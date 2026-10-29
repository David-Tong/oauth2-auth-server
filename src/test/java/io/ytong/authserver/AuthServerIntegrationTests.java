package io.ytong.authserver;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

@SpringBootTest
@AutoConfigureMockMvc
class AuthServerIntegrationTests {

    static final JsonMapper JSON = JsonMapper.builder().build();
    static final String PASSWORD = "test-password";
    static final String HASH = "{bcrypt}" + new BCryptPasswordEncoder(10).encode(PASSWORD);
    static final String VERIFIER = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    static final Path DIRECTORY = directory();

    static Path directory() {
        try {
            Path path = Files.createTempFile("auth-test-users", ".json");
            Files.writeString(path, "{\"schemaVersion\":1,\"users\":["
                    + user("user-001", "alice", true, "USER") + ","
                    + user("user-002", "disabled", false, "USER") + ","
                    + user("user-003", "restricted", true, "") + "]}");
            path.toFile().deleteOnExit();
            return path;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    static String user(String id, String name, boolean enabled, String role) {
        return "{\"id\":\"" + id + "\",\"username\":\"" + name + "\",\"passwordHash\":\"" + HASH
                + "\",\"enabled\":" + enabled + ",\"roles\":" + (role.isEmpty() ? "[]" : "[\"" + role + "\"]") + "}";
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry properties) {
        properties.add("auth.users.path", DIRECTORY::toString);
        properties.add("auth.keys.ephemeral", () -> true);
        properties.add("auth.clients[0].id", () -> "webapp");
        properties.add("auth.clients[0].redirect-uris[0]", () -> "http://localhost:9000/app/callback");
        properties.add("auth.clients[0].scopes[0]", () -> "demo.read");
        properties.add("auth.clients[1].id", () -> "backend");
        properties.add("auth.clients[1].secret-hash", () -> HASH);
        properties.add("auth.clients[1].redirect-uris[0]", () -> "http://localhost:9000/app/backend-callback");
        properties.add("auth.clients[1].scopes[0]", () -> "demo.read");
    }
    @Autowired
    MockMvc mvc;

    JsonNode json(MvcResult result) throws Exception {
        return JSON.readTree(result.getResponse().getContentAsString());
    }

    record Browser(MockHttpSession session, String header, String csrf) {}

    Browser browser() throws Exception {
        MvcResult result = mvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        JsonNode body = json(result);
        return new Browser((MockHttpSession) result.getRequest().getSession(), body.path("headerName").stringValue(), body.path("token").stringValue());
    }

    MvcResult login(Browser browser, String username, String password) throws Exception {
        return mvc.perform(post("/api/auth/login").session(browser.session()).header(browser.header(), browser.csrf())
                .with(request -> {
                    request.setRequestedSessionId(browser.session().getId());
                    request.setRequestedSessionIdValid(true);
                    return request;
                })
                .contentType("application/json").content(JSON.writeValueAsString(Map.of("username", username, "password", password))))
                .andReturn();
    }

    String challenge() throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(VERIFIER.getBytes(StandardCharsets.US_ASCII)));
    }

    org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder authorize() throws Exception {
        return authorize("demo.read", "S256", "http://localhost:9000/app/callback");
    }

    org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder authorize(String scope, String method, String redirect) throws Exception {
        return get("/oauth2/authorize").queryParam("response_type", "code").queryParam("client_id", "webapp")
                .queryParam("redirect_uri", redirect).queryParam("scope", scope)
                .queryParam("state", "random-client-state").queryParam("code_challenge", challenge()).queryParam("code_challenge_method", method);
    }

    String code(MockHttpSession session) throws Exception {
        String callback = mvc.perform(authorize().session(session)).andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        assertThat(callback).startsWith("http://localhost:9000/app/callback?").contains("state=random-client-state");
        return org.springframework.web.util.UriComponentsBuilder.fromUriString(callback).build().getQueryParams().getFirst("code");
    }

    ResultActions exchange(String code, String verifier) throws Exception {
        return mvc.perform(post("/oauth2/token").param("grant_type", "authorization_code").param("client_id", "webapp")
                .param("redirect_uri", "http://localhost:9000/app/callback").param("code", code).param("code_verifier", verifier));
    }

    @Test
    void loginPersistsSessionRotatesIdAndLogsOut() throws Exception {
        Browser browser = browser();
        String original = browser.session().getId();
        MvcResult result = login(browser, "alice", PASSWORD);
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(json(result).path("user").path("id").stringValue()).isEqualTo("user-001");
        assertThat(json(result).path("continueUrl").isNull()).isTrue();
        assertThat(browser.session().getId()).isNotEqualTo(original);
        mvc.perform(get("/api/auth/session").session(browser.session())).andExpect(status().isOk()).andExpect(jsonPath("$.username").value("alice"));
        mvc.perform(post("/api/auth/logout").session(browser.session())).andExpect(status().isForbidden());
        MvcResult csrf = mvc.perform(get("/api/auth/csrf").session(browser.session())).andReturn();
        mvc.perform(post("/api/auth/logout").session(browser.session()).header(browser.header(), json(csrf).path("token").stringValue()))
                .andExpect(status().isNoContent());
        assertThat(browser.session().isInvalid()).isTrue();
    }

    @Test
    void loginErrorsAreGenericAndSessionApisRequireAuthentication() throws Exception {
        for (String username : List.of("alice", "missing", "disabled")) {
            MvcResult result = login(browser(), username, "incorrect");
            assertThat(result.getResponse().getStatus()).isEqualTo(401);
            assertThat(json(result).path("error").stringValue()).isEqualTo("invalid_credentials");
        }
        assertThat(login(browser(), "disabled", PASSWORD).getResponse().getStatus()).isEqualTo(401);
        mvc.perform(get("/api/auth/session")).andExpect(status().isUnauthorized());
        mvc.perform(get("/login")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/auth/login").contentType("application/json").content("{}"))
                .andExpect(status().isForbidden());
        Browser b = browser();
        for (String input : List.of("{", "{}", "{\"username\":\"alice\",\"password\":true}", "x".repeat(4097))) {
            mvc.perform(post("/api/auth/login").session(b.session()).header(b.header(), b.csrf())
                    .contentType("application/json").content(input)).andExpect(status().isBadRequest());
        }
    }

    @Test
    void fullWebappFlowProducesSignedJwtAndRejectsCodeReplay() throws Exception {
        Browser browser = browser();
        mvc.perform(get("/oauth2/authorize?response_type=code&client_id=webapp&redirect_uri=http://localhost:9000/app/callback&scope=demo.read&state=random-client-state&code_challenge=" + challenge() + "&code_challenge_method=S256")
                .session(browser.session())).andExpect(redirectedUrl("/app/login"));
        MvcResult login = login(browser, "alice", PASSWORD);
        assertThat(login.getResponse().getStatus()).isEqualTo(200);
        String continuation = json(login).path("continueUrl").stringValue();
        assertThat(continuation).startsWith("/api/auth/continue?id=");
        String resume = mvc.perform(get(continuation).session(browser.session())).andExpect(status().is3xxRedirection())
                .andReturn().getResponse().getRedirectedUrl();
        assertThat(resume).startsWith("/oauth2/authorize?");
        mvc.perform(get(continuation).session(browser.session())).andExpect(status().isBadRequest());
        String callback = mvc.perform(get(resume).session(browser.session())).andExpect(status().is3xxRedirection())
                .andReturn().getResponse().getRedirectedUrl();
        String code = org.springframework.web.util.UriComponentsBuilder.fromUriString(callback).build().getQueryParams().getFirst("code");
        MvcResult issued = exchange(code, VERIFIER).andExpect(status().isOk()).andReturn();
        JsonNode tokenResponse = json(issued);
        assertThat(tokenResponse.has("refresh_token")).isFalse();
        SignedJWT jwt = SignedJWT.parse(tokenResponse.path("access_token").stringValue());
        var claims = jwt.getJWTClaimsSet();
        assertThat(jwt.getHeader().getType().toString()).isEqualTo("at+jwt");
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
        assertThat(claims.getSubject()).isEqualTo("user-001");
        assertThat(claims.getIssuer()).isEqualTo("http://localhost:9000");
        assertThat(claims.getAudience()).containsExactly("demo-api");
        assertThat(claims.getStringClaim("client_id")).isEqualTo("webapp");
        assertThat(claims.getJWTID()).isNotBlank();
        assertThat(claims.getExpirationTime().toInstant()).isAfter(java.time.Instant.now());
        JsonNode jwks = json(mvc.perform(get("/oauth2/jwks")).andExpect(status().isOk()).andReturn());
        RSAKey key = (RSAKey) JWKSet.parse(jwks.toString()).getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(key.isPrivate()).isFalse();
        assertThat(jwt.verify(new RSASSAVerifier(key))).isTrue();
        exchange(code, VERIFIER).andExpect(status().isBadRequest());
    }

    @Test
    void rejectsInvalidAuthorizationAndScopePolicy() throws Exception {
        mvc.perform(authorize("demo.read", "S256", "https://attacker.example/callback"))
                .andExpect(status().isBadRequest()).andExpect(header().doesNotExist("Location"));
        mvc.perform(get("/oauth2/authorize").queryParam("response_type", "code").queryParam("client_id", "webapp")
                .queryParam("redirect_uri", "http://localhost:9000/app/callback").queryParam("scope", "demo.read"))
                .andExpect(status().isBadRequest());
        mvc.perform(authorize("demo.read", "plain", "http://localhost:9000/app/callback")).andExpect(status().isBadRequest());
        mvc.perform(authorize("admin", "S256", "http://localhost:9000/app/callback")).andExpect(status().isBadRequest());
        Browser restricted = browser();
        assertThat(login(restricted, "restricted", PASSWORD).getResponse().getStatus()).isEqualTo(200);
        mvc.perform(authorize().session(restricted.session())).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_scope"));
    }

    @Test
    void rejectsWrongVerifierAndUnsupportedGrant() throws Exception {
        Browser b = browser();
        assertThat(login(b, "alice", PASSWORD).getResponse().getStatus()).isEqualTo(200);
        exchange(code(b.session()), "a".repeat(43)).andExpect(status().isBadRequest());
        mvc.perform(post("/oauth2/token").param("grant_type", "password").param("client_id", "webapp"))
                .andExpect(status().is4xxClientError());
        mvc.perform(post("/oauth2/introspect").param("token", "fake")).andExpect(status().isUnauthorized());
    }

    @Test
    void discoveryAdvertisesOnlyImplementedProtocol() throws Exception {
        JsonNode metadata = json(mvc.perform(get("/.well-known/oauth-authorization-server")).andExpect(status().isOk()).andReturn());
        assertThat(metadata.path("issuer").stringValue()).isEqualTo("http://localhost:9000");
        assertThat(metadata.path("code_challenge_methods_supported").toString()).contains("S256").doesNotContain("plain");
        mvc.perform(get("/.well-known/openid-configuration")).andExpect(status().isUnauthorized());
    }

    @Test
    void confidentialClientAuthenticatesAndCanIntrospectAndRevoke() throws Exception {
        Browser b = browser();
        assertThat(login(b, "alice", PASSWORD).getResponse().getStatus()).isEqualTo(200);
        String callback = mvc.perform(get("/oauth2/authorize").session(b.session())
                .queryParam("response_type", "code").queryParam("client_id", "backend")
                .queryParam("redirect_uri", "http://localhost:9000/app/backend-callback")
                .queryParam("scope", "demo.read").queryParam("code_challenge", challenge()).queryParam("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        String code = org.springframework.web.util.UriComponentsBuilder.fromUriString(callback).build().getQueryParams().getFirst("code");
        mvc.perform(post("/oauth2/token").with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic("backend", "wrong"))
                .param("grant_type", "authorization_code").param("code", code).param("code_verifier", VERIFIER)
                .param("redirect_uri", "http://localhost:9000/app/backend-callback")).andExpect(status().isUnauthorized());
        MvcResult issued = mvc.perform(post("/oauth2/token")
                .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic("backend", PASSWORD))
                .param("grant_type", "authorization_code").param("code", code).param("code_verifier", VERIFIER)
                .param("redirect_uri", "http://localhost:9000/app/backend-callback"))
                .andExpect(status().isOk()).andReturn();
        String token = json(issued).path("access_token").stringValue();
        mvc.perform(post("/oauth2/introspect")
                .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic("backend", PASSWORD))
                .param("token", token)).andExpect(status().isOk()).andExpect(jsonPath("$.active").value(true));
        mvc.perform(post("/oauth2/revoke")
                .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic("backend", PASSWORD))
                .param("token", token)).andExpect(status().isOk());
        mvc.perform(post("/oauth2/introspect")
                .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic("backend", PASSWORD))
                .param("token", token)).andExpect(status().isOk()).andExpect(jsonPath("$.active").value(false));
        // Revocation changes server state, but the signed JWT is still cryptographically valid.
        assertThat(SignedJWT.parse(token).getJWTClaimsSet().getExpirationTime().toInstant()).isAfter(java.time.Instant.now());
    }
    @Autowired
    org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizations;

    @Test
    void rejectsExpiredCodesAndConcurrentReuse() throws Exception {
        Browser b = browser();
        assertThat(login(b, "alice", PASSWORD).getResponse().getStatus()).isEqualTo(200);
        String expired = code(b.session());
        var authorization = authorizations.findByToken(expired, new org.springframework.security.oauth2.server.authorization.OAuth2TokenType("code"));
        authorizations.save(org.springframework.security.oauth2.server.authorization.OAuth2Authorization.from(authorization)
                .token(new org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode(expired,
                        java.time.Instant.now().minusSeconds(120), java.time.Instant.now().minusSeconds(60))).build());
        exchange(expired, VERIFIER).andExpect(status().isBadRequest());
        String fresh = code(b.session());
        var executor = java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            var start = new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.Callable<Integer> exchange = () -> {
                start.await();
                return exchange(fresh, VERIFIER).andReturn().getResponse().getStatus();
            };
            var first = executor.submit(exchange);
            var second = executor.submit(exchange);
            start.countDown();
            assertThat(List.of(first.get(10, java.util.concurrent.TimeUnit.SECONDS), second.get(10, java.util.concurrent.TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(200, 400);
        } finally {
            executor.shutdownNow();
        }
    }
}
