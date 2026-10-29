package io.ytong.authserver.tools;

import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Offline utility. Never accepts passwords as command-line arguments.
 */
public final class PasswordHash {

    private PasswordHash() {
    }

    public static void main(String[] args) {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("Run this utility from an interactive terminal");
        }
        char[] password = console.readPassword("Password: ");
        char[] confirmation = console.readPassword("Confirm password: ");
        try {
            if (password == null || confirmation == null || !Arrays.equals(password, confirmation)) {
                throw new IllegalArgumentException("Passwords must match");
            }
            String value = new String(password);
            if (value.isEmpty() || value.indexOf(0) >= 0 || value.getBytes(StandardCharsets.UTF_8).length > 72) {
                throw new IllegalArgumentException("Use a password between 1 and 72 UTF-8 bytes without NUL characters");
            }
            console.printf("{bcrypt}%s%n", new BCryptPasswordEncoder(12).encode(value));
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
            if (confirmation != null) {
                Arrays.fill(confirmation, '\0');
            }
        }
    }
}
