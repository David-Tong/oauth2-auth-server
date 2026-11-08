package io.ytong.authserver;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RelativeRedirectTests {

    @LocalServerPort
    int port;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry properties) {
        AuthServerIntegrationTests.properties(properties);
    }

    @Test
    void loginRedirectPreservesTheBrowserOriginThroughTheProxy() throws Exception {
        URI authorize = URI.create("http://localhost:" + port
                + "/oauth2/authorize?response_type=code&client_id=webapp"
                + "&redirect_uri=http%3A%2F%2Flocalhost%3A9001%2Fapp%2Fcallback"
                + "&scope=demo.read&state=test-state"
                + "&code_challenge=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ&code_challenge_method=S256");
        HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        HttpResponse<Void> response = client.send(HttpRequest.newBuilder(authorize).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        assertThat(response.statusCode()).isEqualTo(302);
        assertThat(response.headers().firstValue("Location")).contains("/app/login");
    }
}
