package io.ytong.authserver.authentication;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class PendingAuthorizationTests {

    @Test
    void bindsContinuationToSessionAndRejectsExpiredOrReplacedFlows() {
        class MutableClock extends Clock {

            Instant now = Instant.parse("2026-01-01T00:00:00Z");

            public ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            public Clock withZone(ZoneId zone) {
                return this;
            }

            public Instant instant() {
                return now;
            }
        }
        var clock = new MutableClock();
        var pending = new PendingAuthorization(clock);
        var request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        request.setQueryString("client_id=webapp");
        pending.save(request);
        String original = pending.continueUrl(request).split("id=")[1];
        assertThatThrownBy(() -> pending.consume(new MockHttpServletRequest(), original)).isInstanceOf(ApiError.class);
        pending.save(request);
        assertThatThrownBy(() -> pending.consume(request, original)).isInstanceOf(ApiError.class);
        String current = pending.continueUrl(request).split("id=")[1];
        clock.now = clock.now.plusSeconds(300);
        assertThatThrownBy(() -> pending.consume(request, current)).isInstanceOf(ApiError.class);
        assertThat(pending.continueUrl(request)).isNull();
    }
}
