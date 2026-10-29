package io.ytong.authserver.authentication;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class LoginRateLimiterTests {
    @Test void limitsAccountsAcrossSources() {
        var limiter = new LoginRateLimiter();
        for (int i = 0; i < 10; i++) limiter.check("source-" + i, "alice");
        assertThatThrownBy(() -> limiter.check("another-source", "alice")).isInstanceOf(ApiError.class);
        assertThatCode(() -> limiter.check("another-source", "bob")).doesNotThrowAnyException();
    }
    @Test void limitsSourcesAcrossAccounts() {
        var limiter = new LoginRateLimiter();
        for (int i = 0; i < 60; i++) limiter.check("source", "user-" + i);
        assertThatThrownBy(() -> limiter.check("source", "another-user")).isInstanceOf(ApiError.class);
    }
}
