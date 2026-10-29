package io.ytong.authserver.config;

import java.net.URI;
import java.time.Duration;
import java.util.*;
import java.util.function.Consumer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import java.io.IOException;
import io.ytong.authserver.authentication.*;
import io.ytong.authserver.user.JsonUserDetailsService;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.*;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.session.*;
import org.springframework.security.web.context.*;
import org.springframework.security.web.csrf.*;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
public class SecurityConfiguration {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new DelegatingPasswordEncoder("bcrypt", Map.of("bcrypt", new BCryptPasswordEncoder(12)));
    }
    @Bean
    public AuthenticationManager authenticationManager(JsonUserDetailsService users, PasswordEncoder encoder) {
        var provider = new DaoAuthenticationProvider(users);
        provider.setPasswordEncoder(encoder);
        // Verify the password before checking enabled status, including for disabled accounts.
        provider.setPreAuthenticationChecks(user -> {});
        provider.setPostAuthenticationChecks(user -> {
            if (!user.isEnabled()) throw new DisabledException("Invalid credentials");
        });
        return new ProviderManager(provider);
    }
    @Bean
    public SecurityContextRepository securityContextRepository() { return new HttpSessionSecurityContextRepository(); }
    @Bean
    public HttpSessionCsrfTokenRepository csrfTokenRepository() { return new HttpSessionCsrfTokenRepository(); }
    @Bean
    public SessionAuthenticationStrategy sessionAuthenticationStrategy(HttpSessionCsrfTokenRepository csrf) {
        return new CompositeSessionAuthenticationStrategy(List.of(new ChangeSessionIdAuthenticationStrategy(),
                new CsrfAuthenticationStrategy(csrf)));
    }
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(AuthProperties properties) {
        validateUrl(properties.issuer());
        if (!properties.loginUrl().startsWith("/") || properties.loginUrl().startsWith("//")
                || properties.loginUrl().contains("\\") || properties.loginUrl().contains("\r")
                || properties.loginUrl().contains("\n") || !properties.loginUrl().startsWith("/app/"))
            throw new IllegalStateException("Login URL must be a local /app/ path served by the webapp proxy");
        if (properties.audience() == null || properties.audience().isBlank())
            throw new IllegalStateException("Configure an API audience");
        return AuthorizationServerSettings.builder().issuer(properties.issuer()).build();
    }
    private static void validateUrl(String value) {
        URI uri = URI.create(value);
        boolean loopback = Set.of("localhost", "127.0.0.1", "[::1]").contains(String.valueOf(uri.getHost()));
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null
                || uri.getQuery() != null || !("https".equals(uri.getScheme()) || (loopback && "http".equals(uri.getScheme()))))
            throw new IllegalStateException("URLs must use HTTPS (HTTP is allowed only on loopback)");
    }
    @Bean
    public RegisteredClientRepository registeredClientRepository(AuthProperties properties) {
        List<RegisteredClient> clients = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        Set<String> knownScopes = new HashSet<>();
        properties.roleScopes().forEach((role, scopes) -> {
            if (!role.matches("[A-Z][A-Z0-9_]{0,31}") || scopes == null) throw new IllegalStateException("Invalid role-scope policy");
            knownScopes.addAll(scopes);
        });
        for (var client : properties.clients()) {
            if (client.id() == null || client.id().isBlank() || !ids.add(client.id())
                    || client.redirectUris() == null || client.redirectUris().isEmpty()
                    || client.scopes() == null || client.scopes().isEmpty() || !knownScopes.containsAll(client.scopes()))
                throw new IllegalStateException("Invalid client registration");
            var builder = RegisteredClient.withId(client.id()).clientId(client.id())
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                    .tokenSettings(TokenSettings.builder().authorizationCodeTimeToLive(Duration.ofSeconds(60))
                            .accessTokenTimeToLive(Duration.ofMinutes(5)).accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                            .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256).build());
            if (client.secretHash() == null || client.secretHash().isBlank()) {
                builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
            } else {
                if (!client.secretHash().matches("\\{bcrypt\\}\\$2[aby]\\$1[0-6]\\$[./A-Za-z0-9]{53}"))
                    throw new IllegalStateException("Client secrets require a bcrypt hash with cost 10-16");
                builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).clientSecret(client.secretHash());
            }
            for (String redirect : client.redirectUris()) {
                validateUrl(redirect);
                if (redirect.contains("*")) throw new IllegalStateException("Wildcard redirects are prohibited");
                builder.redirectUri(redirect);
            }
            client.scopes().forEach(builder::scope);
            clients.add(builder.build());
        }
        if (clients.isEmpty()) throw new IllegalStateException("At least one client is required");
        return new InMemoryRegisteredClientRepository(clients);
    }
    @Bean
    public OAuth2AuthorizationService authorizationService() { return new InMemoryOAuth2AuthorizationService(); }
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(AuthProperties properties, JsonUserDetailsService users,
            com.nimbusds.jose.jwk.source.JWKSource<com.nimbusds.jose.proc.SecurityContext> source) throws Exception {
        String keyId = source.get(new com.nimbusds.jose.jwk.JWKSelector(
                new com.nimbusds.jose.jwk.JWKMatcher.Builder().privateOnly(true).build()), null).get(0).getKeyID();
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getJwsHeader().algorithm(SignatureAlgorithm.RS256).type("at+jwt").keyId(keyId);
                context.getClaims().subject(users.entry(context.getPrincipal().getName()).id())
                        .audience(List.of(properties.audience())).claim("client_id", context.getRegisteredClient().getClientId());
            }
        };
    }
    @Bean @Order(1)
    public SecurityFilterChain authorizationChain(HttpSecurity http, AuthProperties properties,
            PendingAuthorization pending, SecurityContextRepository contexts, JsonUserDetailsService users) throws Exception {
        var server = new OAuth2AuthorizationServerConfigurer();
        http.securityMatcher(server.getEndpointsMatcher()).with(server, config -> config
                .authorizationEndpoint(endpoint -> endpoint
                        .authenticationProviders(providers -> providers.forEach(provider -> {
                            if (provider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider codeProvider)
                                codeProvider.setAuthenticationValidator(validator(properties, users));
                        }))
                        .errorResponseHandler((request, response, exception) -> {
                            String error = exception instanceof OAuth2AuthenticationException oauth ? oauth.getError().getErrorCode() : "invalid_request";
                            ApiError.write(response, 400, error);
                        })));
        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .formLogin(org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer::disable)
                .httpBasic(org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer::disable)
                .securityContext(context -> context.securityContextRepository(contexts))
                .requestCache(cache -> cache.requestCache(new NullRequestCache()))
                .exceptionHandling(errors -> errors.authenticationEntryPoint((request, response, exception) -> {
                    if ("GET".equals(request.getMethod()) && "/oauth2/authorize".equals(request.getRequestURI())) {
                        try { pending.save(request); response.sendRedirect(properties.loginUrl()); }
                        catch (ApiError ex) { ApiError.write(response, ex.status().value(), ex.code()); }
                    } else ApiError.write(response, 401, "unauthorized");
                }));
        // Serialize code exchanges in this single-instance server to prevent concurrent code reuse.
        http.addFilterBefore(new TokenExchangeLock(), org.springframework.security.web.context.SecurityContextHolderFilter.class);
        return http.build();
    }
    private Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> validator(AuthProperties properties, JsonUserDetailsService users) {
        return context -> {
            OAuth2AuthorizationCodeRequestAuthenticationToken token = context.getAuthentication();
            if (token.getRedirectUri() == null || !context.getRegisteredClient().getRedirectUris().contains(token.getRedirectUri()))
                fail("invalid_request", token);
            OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR.accept(context);
            var parameters = token.getAdditionalParameters();
            if (!"S256".equals(parameters.get("code_challenge_method"))
                    || !(parameters.get("code_challenge") instanceof String challenge)
                    || !challenge.matches("[A-Za-z0-9_-]{43}")) fail("invalid_request", token);
            if (token.getScopes().isEmpty()) fail("invalid_scope", token);
            Authentication principal = (Authentication) token.getPrincipal();
            if (principal.isAuthenticated() && !(principal instanceof AnonymousAuthenticationToken)) {
                var entry = users.entry(principal.getName());
                Set<String> allowed = new HashSet<>();
                entry.roles().forEach(role -> allowed.addAll(properties.roleScopes().getOrDefault(role, List.of())));
                if (!entry.enabled() || !allowed.containsAll(token.getScopes())) fail("invalid_scope", token);
            }
        };
    }
    private static void fail(String code, OAuth2AuthorizationCodeRequestAuthenticationToken token) {
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error(code), token);
    }
    @Bean @Order(2)
    public SecurityFilterChain applicationChain(HttpSecurity http, SecurityContextRepository contexts,
            HttpSessionCsrfTokenRepository csrf) throws Exception {
        var handler = new CsrfTokenRequestAttributeHandler();
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/csrf", "/api/auth/login").permitAll()
                        .requestMatchers("/api/auth/session", "/api/auth/continue", "/api/auth/logout").authenticated()
                        .anyRequest().denyAll())
                .formLogin(org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer::disable)
                .httpBasic(org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer::disable)
                .securityContext(context -> context.securityContextRepository(contexts))
                .requestCache(cache -> cache.requestCache(new NullRequestCache()))
                .csrf(config -> config.csrfTokenRepository(csrf).csrfTokenRequestHandler(handler))
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint((req, res, ex) -> ApiError.write(res, 401, "unauthorized"))
                        .accessDeniedHandler((req, res, ex) -> ApiError.write(res, 403, "forbidden")))
                .logout(logout -> logout.logoutUrl("/api/auth/logout").deleteCookies("JSESSIONID")
                        .logoutSuccessHandler((req, res, auth) -> { res.setHeader("Cache-Control", "no-store"); res.setStatus(204); }));
        return http.build();
    }
    private static class TokenExchangeLock extends OncePerRequestFilter {
        private final Object lock = new Object();
        @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            if ("/oauth2/token".equals(request.getRequestURI())) {
                synchronized (lock) { chain.doFilter(request, response); }
            } else chain.doFilter(request, response);
        }
    }
}
