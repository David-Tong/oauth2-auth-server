package io.ytong.authserver.authentication;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.IntConsumer;

class LoginRateLimiterTests {

    @Test
    void concurrentAttemptsCannotExceedAccountOrSourceLimits() throws Exception {
        var accounts = new LoginRateLimiter(() -> 0L);
        assertThat(concurrentChecks(200, i -> accounts.check("source-" + i, "alice"))).isEqualTo(10);
        var sources = new LoginRateLimiter(() -> 0L);
        assertThat(concurrentChecks(200, i -> sources.check("source", "user-" + i))).isEqualTo(60);
    }

    @Test
    void unrelatedConcurrentRequestsRespectCapacityAndCanRecover() throws Exception {
        var now = new AtomicLong();
        var limiter = new LoginRateLimiter(now::get);
        assertThat(concurrentChecks(5_100, i -> limiter.check("source-" + i, "user-" + i)))
                .isEqualTo(5_000);
        now.set(Duration.ofSeconds(60).toNanos());
        assertThatCode(() -> limiter.check("fresh-source", "fresh-user")).doesNotThrowAnyException();
    }

    private int concurrentChecks(int count, IntConsumer check) throws Exception {
        var executor = Executors.newFixedThreadPool(16);
        var start = new CountDownLatch(1);
        var results = new ArrayList<Future<Boolean>>();
        try {
            for (int i = 0; i < count; i++) {
                int index = i;
                results.add(executor.submit(() -> {
                    start.await();
                    try {
                        check.accept(index);
                        return true;
                    } catch (ApiError error) {
                        assertThat(error.status().value()).isEqualTo(429);
                        return false;
                    }
                }));
            }
            start.countDown();
            int allowed = 0;
            for (var result : results) {
                if (result.get(10, TimeUnit.SECONDS)) {
                    allowed++;
                }
            }
            return allowed;
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void accountWindowSlidesInsteadOfResettingAllAttempts() {
        var now = new AtomicLong();
        var limiter = new LoginRateLimiter(now::get);
        limiter.check("source", "alice");
        now.set(Duration.ofSeconds(59).toNanos());
        for (int i = 0; i < 9; i++) {
            limiter.check("source", "alice");
        }
        now.set(Duration.ofSeconds(60).toNanos() - 1);
        assertThatThrownBy(() -> limiter.check("source", "alice")).isInstanceOf(ApiError.class);
        now.incrementAndGet();
        assertThatCode(() -> limiter.check("source", "alice")).doesNotThrowAnyException();
        assertThatThrownBy(() -> limiter.check("source", "alice")).isInstanceOf(ApiError.class);
        now.set(Duration.ofSeconds(119).toNanos());
        for (int i = 0; i < 9; i++) {
            limiter.check("source", "alice");
        }
        assertThatThrownBy(() -> limiter.check("source", "alice")).isInstanceOf(ApiError.class);
    }

    @Test
    void sourceWindowSlidesAcrossAccounts() {
        var now = new AtomicLong();
        var limiter = new LoginRateLimiter(now::get);
        limiter.check("source", "first");
        now.set(Duration.ofSeconds(59).toNanos());
        for (int i = 0; i < 59; i++) {
            limiter.check("source", "user-" + i);
        }
        now.set(Duration.ofSeconds(60).toNanos());
        assertThatCode(() -> limiter.check("source", "next")).doesNotThrowAnyException();
        assertThatThrownBy(() -> limiter.check("source", "another")).isInstanceOf(ApiError.class);
    }

    @Test
    void capacityDoesNotBlockExistingKeysAndExpires() {
        var now = new AtomicLong();
        var limiter = new LoginRateLimiter(now::get);
        for (int i = 0; i < 5_000; i++) {
            limiter.check("source-" + i, "user-" + i);
        }
        assertThatCode(() -> limiter.check("source-0", "user-0")).doesNotThrowAnyException();
        assertThatThrownBy(() -> limiter.check("new-source", "new-user")).isInstanceOf(ApiError.class);
        now.set(Duration.ofSeconds(60).toNanos());
        assertThatCode(() -> limiter.check("new-source", "new-user")).doesNotThrowAnyException();
    }

    @Test
    void limitsAccountsAcrossSources() {
        var limiter = new LoginRateLimiter();
        for (int i = 0; i < 10; i++) {
            limiter.check("source-" + i, "alice");
        }
        assertThatThrownBy(() -> limiter.check("another-source", "alice")).isInstanceOf(ApiError.class);
        assertThatCode(() -> limiter.check("another-source", "bob")).doesNotThrowAnyException();
    }

    @Test
    void limitsSourcesAcrossAccounts() {
        var limiter = new LoginRateLimiter();
        for (int i = 0; i < 60; i++) {
            limiter.check("source", "user-" + i);
        }
        assertThatThrownBy(() -> limiter.check("source", "another-user")).isInstanceOf(ApiError.class);
    }
}
