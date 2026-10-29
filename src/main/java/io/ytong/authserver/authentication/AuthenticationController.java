package io.ytong.authserver.authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.ytong.authserver.user.JsonUserDetailsService;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.web.bind.annotation.*;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {
    private final AuthenticationManager manager;
    private final SessionAuthenticationStrategy sessions;
    private final SecurityContextRepository contexts;
    private final JsonUserDetailsService users;
    private final PendingAuthorization pending;
    private final LoginRateLimiter limiter;
    private final JsonMapper mapper = JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(tools.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();
    public AuthenticationController(AuthenticationManager manager, SessionAuthenticationStrategy sessions,
            SecurityContextRepository contexts, JsonUserDetailsService users, PendingAuthorization pending,
            LoginRateLimiter limiter) {
        this.manager = manager; this.sessions = sessions; this.contexts = contexts;
        this.users = users; this.pending = pending; this.limiter = limiter;
    }
    public record Identity(String id, String username) {}
    public record LoginResponse(Identity user, String continueUrl) {}
    @GetMapping("/csrf")
    public Map<String, String> csrf(CsrfToken token) {
        return Map.of("token", token.getToken(), "headerName", token.getHeaderName());
    }
    @PostMapping(value = "/login", consumes = "application/json")
    public LoginResponse login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        byte[] body = request.getInputStream().readNBytes(4097);
        if (body.length > 4096) throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_request");
        JsonNode node;
        try { node = mapper.readTree(body); }
        catch (Exception ex) { throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_request"); }
        if (node == null || !node.isObject() || node.size() != 2 || !node.path("username").isString()
                || !node.path("password").isString()) throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_request");
        String username = node.path("username").stringValue();
        String password = node.path("password").stringValue();
        if (!username.matches("[A-Za-z0-9._@-]{1,128}") || password.isEmpty()
                || password.indexOf(0) >= 0 || password.getBytes(StandardCharsets.UTF_8).length > 72)
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_request");
        limiter.check(request.getRemoteAddr(), username);
        try {
            Authentication authenticated = manager.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(username, password));
            sessions.onAuthentication(authenticated, request, response);
            var context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authenticated);
            SecurityContextHolder.setContext(context);
            contexts.saveContext(context, request, response);
            return new LoginResponse(identity(authenticated), pending.continueUrl(request));
        } catch (AuthenticationException ex) {
            throw new ApiError(HttpStatus.UNAUTHORIZED, "invalid_credentials");
        }
    }
    @GetMapping("/session")
    public Identity session(Authentication authentication) { return identity(authentication); }
    @GetMapping("/continue")
    public void resume(@RequestParam String id, HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.sendRedirect(pending.consume(request, id));
    }
    private Identity identity(Authentication authentication) {
        var entry = users.entry(authentication.getName());
        return new Identity(entry.id(), entry.username());
    }
    @ExceptionHandler(ApiError.class)
    public void error(ApiError error, HttpServletResponse response) throws IOException {
        if (error.status() == HttpStatus.TOO_MANY_REQUESTS) response.setHeader("Retry-After", "60");
        ApiError.write(response, error.status().value(), error.code());
    }
}
