package io.ytong.authserver.authentication;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class LoginRateLimiter {

    private record Window(long start, int count) {}
    private final Map<String, Window> windows = new HashMap<>();

    public synchronized void check(String address, String username) {
        long now = Instant.now().getEpochSecond();
        windows.entrySet().removeIf(e -> e.getValue().start() + 60 <= now);
        if (windows.size() >= 10_000) {
            throw new ApiError(HttpStatus.TOO_MANY_REQUESTS, "rate_limited");
        }
        boolean source = increment("ip:" + address, 60, now);
        boolean account = increment("user:" + username, 10, now);
        if (!source || !account) {
            throw new ApiError(HttpStatus.TOO_MANY_REQUESTS, "rate_limited");
        }
    }

    private boolean increment(String key, int limit, long now) {
        Window old = windows.getOrDefault(key, new Window(now, 0));
        windows.put(key, new Window(old.start(), old.count() + 1));
        return old.count() < limit;
    }
}
