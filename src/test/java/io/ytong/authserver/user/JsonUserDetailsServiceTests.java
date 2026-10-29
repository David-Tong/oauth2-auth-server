package io.ytong.authserver.user;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class JsonUserDetailsServiceTests {

    @TempDir
    Path directory;
    static final String HASH = "{bcrypt}" + new BCryptPasswordEncoder(10).encode("test-password");

    String record(String id, String username) {
        return "{\"id\":\"" + id + "\",\"username\":\"" + username + "\",\"passwordHash\":\"" + HASH
                + "\",\"enabled\":true,\"roles\":[\"USER\"]}";
    }

    String document(String... users) {
        return "{\"schemaVersion\":1,\"users\":[" + String.join(",", users) + "]}";
    }

    @Test
    void rejectsInvalidDirectoriesWithoutLeakingCredentials() throws Exception {
        Path file = directory.resolve("users.json");
        String valid = record("user-001", "alice");
        for (String invalid : java.util.List.of(
                document(valid, valid), document(valid, record("user-002", "alice")),
                document(valid, record("user-001", "bob")), document(valid.replace("{bcrypt}", "{noop}")),
                document(valid.replace("USER", "UNKNOWN")), document(), "not-json",
                document(valid).replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
                document(valid).replace("\"enabled\":true", "\"enabled\":\"true\""),
                document(valid).replace("\"enabled\":true", "\"enabled\":true,\"enabled\":false"),
                document(valid).replace("\"enabled\":true", "\"enabled\":true,\"unexpected\":1"),
                document(valid) + " {}", " ".repeat(1_048_577))) {
            Files.writeString(file, invalid);
            assertThatThrownBy(() -> new JsonUserDetailsService(file, Set.of("USER")))
                    .isInstanceOf(IllegalStateException.class).hasMessageNotContaining(HASH).hasCause(null);
        }
        assertThatThrownBy(() -> new JsonUserDetailsService(directory.resolve("missing"), Set.of("USER")))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void loadsAnImmutableSnapshotAndReplacesItOnRestart() throws Exception {
        Path file = directory.resolve("users.json");
        Files.writeString(file, document(record("user-001", "alice")));
        var first = new JsonUserDetailsService(file, Set.of("USER"));
        assertThat(first.loadUserByUsername("alice").getAuthorities()).extracting("authority").containsExactly("ROLE_USER");
        Files.writeString(file, document(record("user-002", "bob")));
        assertThat(first.entry("alice").id()).isEqualTo("user-001");
        var restarted = new JsonUserDetailsService(file, Set.of("USER"));
        assertThat(restarted.entry("bob").id()).isEqualTo("user-002");
        assertThatThrownBy(() -> restarted.entry("alice")).isInstanceOf(org.springframework.security.core.userdetails.UsernameNotFoundException.class);
    }
}
