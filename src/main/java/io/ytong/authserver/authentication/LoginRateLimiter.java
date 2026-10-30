package io.ytong.authserver.authentication;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class LoginRateLimiter {

    private static final long WINDOW_NANOS = Duration.ofSeconds(60).toNanos();
    private static final long SWEEP_INTERVAL_NANOS = Duration.ofSeconds(1).toNanos();
    private static final int MAX_KEYS = 10_000;
    private enum Decision { ACCEPTED, LIMITED, CAPACITY }

    private final ConcurrentHashMap<String, Deque<Long>> attempts = new ConcurrentHashMap<>();
    private final Semaphore slots = new Semaphore(MAX_KEYS);
    private final AtomicBoolean sweeping = new AtomicBoolean();
    private final LongSupplier ticker;
    // Accessed only by the caller owning the sweeping flag.
    private long lastSweep;

    @Autowired
    public LoginRateLimiter() {
        this(System::nanoTime);
    }

    LoginRateLimiter(LongSupplier ticker) {
        this.ticker = ticker;
        lastSweep = ticker.getAsLong() - SWEEP_INTERVAL_NANOS;
    }

    public void check(String address, String username) {
        // Independent budgets: never hold one key's compute while updating another.
        // Check both dimensions even if the first one rejects the request.
        Decision source = recordWithCleanup("ip:" + address, 60);
        Decision account = recordWithCleanup("user:" + username, 10);
        if (source != Decision.ACCEPTED || account != Decision.ACCEPTED) {
            throw new ApiError(HttpStatus.TOO_MANY_REQUESTS, "rate_limited");
        }
    }

    private Decision recordWithCleanup(String key, int limit) {
        Decision decision = recordAttempt(key, limit);
        if (decision == Decision.CAPACITY) {
            sweepExpired();
            decision = recordAttempt(key, limit);
        }
        return decision;
    }

    private Decision recordAttempt(String key, int limit) {
        var decision = new AtomicReference<>(Decision.CAPACITY);
        attempts.compute(key, (ignored, queue) -> {
            if (queue == null) {
                if (!slots.tryAcquire()) {
                    return null;
                }
                queue = new ArrayDeque<>();
            }
            // Sample inside compute so timestamps for this key stay ordered.
            long now = ticker.getAsLong();
            prune(queue, now);
            if (queue.size() >= limit) {
                decision.set(Decision.LIMITED);
            } else {
                queue.addLast(now);
                decision.set(Decision.ACCEPTED);
            }
            return queue;
        });
        return decision.get();
    }

    private static void prune(Deque<Long> queue, long now) {
        while (!queue.isEmpty() && now - queue.peekFirst() >= WINDOW_NANOS) {
            queue.removeFirst();
        }
    }

    private void sweepExpired() {
        // Capacity pressure may trigger one sweep per second. Other callers skip it.
        if (!sweeping.compareAndSet(false, true)) {
            return;
        }
        try {
            long now = ticker.getAsLong();
            if (now - lastSweep < SWEEP_INTERVAL_NANOS) {
                return;
            }
            lastSweep = now;
            attempts.forEach((key, ignored) -> {
                // Use the same per-key atomic operation as writers to avoid
                // removing a queue that another request has just refreshed.
                Deque<Long> remaining = attempts.computeIfPresent(key, (name, queue) -> {
                    prune(queue, ticker.getAsLong());
                    return queue.isEmpty() ? null : queue;
                });
                // Only this sweeper removes entries, so each removed key releases
                // exactly one slot, after removal has completed.
                if (remaining == null) {
                    slots.release();
                }
            });
        } finally {
            sweeping.set(false);
        }
    }
}
