package io.ytong.authserver.config;

import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("auth")
public record AuthProperties(String issuer, String loginUrl, String audience, Users users,
                             Keys keys, List<Client> clients, Map<String, List<String>> roleScopes) {
    public record Users(String path) {}
    public record Keys(boolean ephemeral, String path, String password, String alias) {}
    public record Client(String id, String secretHash, List<String> redirectUris, List<String> scopes) {}
}
