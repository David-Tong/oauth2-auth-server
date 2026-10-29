package io.ytong.authserver.authentication;

import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class PendingAuthorization {

    private static final String KEY = PendingAuthorization.class.getName();
    private final java.time.Clock clock;

    @org.springframework.beans.factory.annotation.Autowired
    public PendingAuthorization() {
        this(java.time.Clock.systemUTC());
    }

    PendingAuthorization(java.time.Clock clock) {
        this.clock = clock;
    }

    private record Pending(String id, String target, Instant expires) implements Serializable {}

    public void save(HttpServletRequest request) {
        String query = request.getQueryString();
        if (!"GET".equals(request.getMethod()) || !"/oauth2/authorize".equals(request.getRequestURI())
                || query == null || query.length() > 8192) {
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_request");
        }
        request.getSession().setAttribute(KEY, new Pending(UUID.randomUUID().toString(),
                "/oauth2/authorize?" + query, clock.instant().plusSeconds(300)));
    }

    private Pending current(HttpServletRequest request) {
        var session = request.getSession(false);
        if (session == null) {
            return null;
        }
        var pending = (Pending) session.getAttribute(KEY);
        if (pending != null && !pending.expires().isAfter(clock.instant())) {
            session.removeAttribute(KEY);
            return null;
        }
        return pending;
    }

    public String continueUrl(HttpServletRequest request) {
        Pending pending = current(request);
        return pending == null ? null : "/api/auth/continue?id=" + pending.id();
    }

    public String consume(HttpServletRequest request, String id) {
        var session = request.getSession(false);
        if (session == null) {
            throw new ApiError(HttpStatus.BAD_REQUEST, "authorization_expired");
        }
        synchronized (session) {
            Pending pending = current(request);
            if (pending == null || !pending.id().equals(id)) {
                throw new ApiError(HttpStatus.BAD_REQUEST, "authorization_expired");
            }
            session.removeAttribute(KEY);
            return pending.target();
        }
    }
}
