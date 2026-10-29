package io.ytong.authserver.authentication;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class LoginRateLimiter {

    private static final long WINDOW_NANOS = Duration.ofSeconds(60).toNanos();
    private static final long SWEEP_INTERVAL_NANOS = Duration.ofSeconds(1).toNanos();
    private static final int MAX_KEYS = 10_000;
    private static final int STRIPE_COUNT = 64;
    private static final class Stripe {
        final Map<String, Deque<Long>> attempts = new HashMap<>();
    }

    private final Stripe[] stripes = new Stripe[STRIPE_COUNT];
    private final AtomicInteger keyCount = new AtomicInteger();
    private final ReentrantLock sweepLock = new ReentrantLock();
    private final LongSupplier ticker;
    // Accessed only while holding sweepLock.
    private long lastSweep;

    @Autowired
    public LoginRateLimiter() {
        this(System::nanoTime);
    }

    LoginRateLimiter(LongSupplier ticker) {
        this.ticker = ticker;
        lastSweep = ticker.getAsLong() - SWEEP_INTERVAL_NANOS;
        for (int i = 0; i < stripes.length; i++) {
            stripes[i] = new Stripe();
        }
    }

    public void check(String address, String username) {
        String sourceKey = "ip:" + address;
        String accountKey = "user:" + username;
        if (!checkWithLocks(sourceKey, accountKey)) {
            // Never sweep while holding request locks. Only one caller sweeps,
            // at most once per second, and other callers do not wait for it.
            sweepExpired();
            if (!checkWithLocks(sourceKey, accountKey)) {
                throw rateLimited();
            }
        }
    }

    private boolean checkWithLocks(String sourceKey, String accountKey) {
        int sourceIndex = stripeIndex(sourceKey);
        int accountIndex = stripeIndex(accountKey);
        // Stable lock ordering prevents deadlocks, including reversed key pairs.
        synchronized (stripes[Math.min(sourceIndex, accountIndex)]) {
            synchronized (stripes[Math.max(sourceIndex, accountIndex)]) {
                Map<String, Deque<Long>> sources = stripes[sourceIndex].attempts;
                Map<String, Deque<Long>> accounts = stripes[accountIndex].attempts;
                int needed = (sources.containsKey(sourceKey) ? 0 : 1)
                        + (accounts.containsKey(accountKey) ? 0 : 1);
                if (!reserveKeys(needed)) {
                    return false;
                }
                // Read time after acquiring locks so timestamps remain ordered.
                long now = ticker.getAsLong();
                boolean source = recordAttempt(sources, sourceKey, 60, now);
                boolean account = recordAttempt(accounts, accountKey, 10, now);
                if (!source || !account) {
                    throw rateLimited();
                }
                return true;
            }
        }
    }

    private static int stripeIndex(String key) {
        int hash = key.hashCode();
        return (hash ^ (hash >>> 16)) & (STRIPE_COUNT - 1);
    }

    private boolean reserveKeys(int needed) {
        if (needed == 0) {
            return true;
        }
        int current;
        do {
            current = keyCount.get();
            if (current + needed > MAX_KEYS) {
                return false;
            }
        } while (!keyCount.compareAndSet(current, current + needed));
        return true;
    }

    private static void prune(Deque<Long> queue, long now) {
        while (!queue.isEmpty() && now - queue.peekFirst() >= WINDOW_NANOS) {
            queue.removeFirst();
        }
    }

    private static boolean recordAttempt(Map<String, Deque<Long>> attempts, String key, int limit, long now) {
        Deque<Long> queue = attempts.computeIfAbsent(key, ignored -> new ArrayDeque<>());
        prune(queue, now);
        // Both dimensions are checked; a saturated key neither grows nor extends its lockout.
        if (queue.size() >= limit) {
            return false;
        }
        queue.addLast(now);
        return true;
    }

    private void sweepExpired() {
        if (!sweepLock.tryLock()) {
            return;
        }
        try {
            long now = ticker.getAsLong();
            if (now - lastSweep < SWEEP_INTERVAL_NANOS) {
                return;
            }
            lastSweep = now;
            for (Stripe stripe : stripes) {
                synchronized (stripe) {
                    var entries = stripe.attempts.values().iterator();
                    while (entries.hasNext()) {
                        Deque<Long> queue = entries.next();
                        prune(queue, now);
                        if (queue.isEmpty()) {
                            entries.remove();
                            keyCount.decrementAndGet();
                        }
                    }
                }
            }
        } finally {
            sweepLock.unlock();
        }
    }

    private static ApiError rateLimited() {
        return new ApiError(HttpStatus.TOO_MANY_REQUESTS, "rate_limited");
    }
}
