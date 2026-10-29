package io.ytong.authserver.user;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import io.ytong.authserver.config.AuthProperties;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

@Service
public class JsonUserDetailsService implements UserDetailsService {
    private static final int MAX_BYTES = 1_048_576;
    private final Map<String, Entry> users;

    public record Entry(String id, String username, String passwordHash, boolean enabled, Set<String> roles) {
    }

    @org.springframework.beans.factory.annotation.Autowired
    public JsonUserDetailsService(AuthProperties properties) {
        this(Path.of(properties.users().path()), properties.roleScopes().keySet());
    }

    public JsonUserDetailsService(Path path, Set<String> allowedRoles) {
        try (InputStream input = Files.newInputStream(path)) {
            byte[] bytes = input.readNBytes(MAX_BYTES + 1);
            require(bytes.length <= MAX_BYTES);
            var mapper = JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .enable(tools.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();
            JsonNode root = mapper.readTree(bytes);
            fields(root, Set.of("schemaVersion", "users"));
            require(root.path("schemaVersion").isInt() && root.path("schemaVersion").intValue() == 1);
            JsonNode records = root.path("users");
            require(records.isArray() && !records.isEmpty() && records.size() <= 10_000);
            Map<String, Entry> snapshot = new HashMap<>();
            Set<String> ids = new HashSet<>();
            for (JsonNode record : records) {
                fields(record, Set.of("id", "username", "passwordHash", "enabled", "roles"));
                String id = text(record, "id");
                String username = text(record, "username");
                String hash = text(record, "passwordHash");
                require(id.matches("[A-Za-z0-9._-]{1,128}") && ids.add(id));
                require(username.matches("[A-Za-z0-9._@-]{1,128}"));
                require(hash.matches("\\{bcrypt\\}\\$2[aby]\\$(1[0-6])\\$[./A-Za-z0-9]{53}"));
                require(record.path("enabled").isBoolean());
                JsonNode roleNodes = record.path("roles");
                require(roleNodes.isArray() && roleNodes.size() <= 32);
                Set<String> roles = new HashSet<>();
                for (JsonNode role : roleNodes) {
                    require(role.isString() && allowedRoles.contains(role.stringValue())
                            && roles.add(role.stringValue()));
                }
                var entry = new Entry(id, username, hash, record.path("enabled").booleanValue(), Set.copyOf(roles));
                require(snapshot.putIfAbsent(username, entry) == null);
            }
            users = Map.copyOf(snapshot);
        } catch (Exception ex) {
            // Do not attach parser exceptions: their messages can include credential data.
            throw new IllegalStateException(
                    "User directory missing or invalid. Check schema, IDs, usernames, bcrypt hashes and roles.");
        }
    }

    private static void fields(JsonNode node, Set<String> fields) {
        require(node != null && node.isObject() && node.size() == fields.size());
        node.propertyNames().forEach(name -> require(fields.contains(name)));
    }

    private static String text(JsonNode node, String key) {
        require(node.path(key).isString());
        return node.path(key).stringValue();
    }

    private static void require(boolean valid) {
        if (!valid)
            throw new IllegalArgumentException("Invalid directory");
    }

    public Entry entry(String username) {
        Entry entry = users.get(username);
        if (entry == null)
            throw new UsernameNotFoundException("Invalid credentials");
        return entry;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        Entry entry = entry(username);
        return User.withUsername(entry.username()).password(entry.passwordHash())
                .disabled(!entry.enabled()).roles(entry.roles().toArray(String[]::new)).build();
    }
}
