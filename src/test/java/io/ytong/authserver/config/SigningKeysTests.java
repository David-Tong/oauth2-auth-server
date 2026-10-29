package io.ytong.authserver.config;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;

class SigningKeysTests {

    @TempDir
    Path directory;

    @Test
    void loadsPersistentKeysAndPublishesRetiredPublicKeys() throws Exception {
        Path store = directory.resolve("signing.p12");
        Path keytool = Path.of(System.getProperty("java.home"), "bin", System.getProperty("os.name").startsWith("Windows") ? "keytool.exe" : "keytool");
        var process = new ProcessBuilder(keytool.toString(), "-genkeypair", "-alias", "signing-v1", "-keyalg", "RSA",
                "-keysize", "2048", "-storetype", "PKCS12", "-keystore", store.toString(), "-storepass", "test-store-password",
                "-dname", "CN=Test", "-validity", "2", "-noprompt").redirectErrorStream(true).start();
        String diagnostic = new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        assertThat(process.waitFor()).as(diagnostic).isZero();
        var config = new AuthProperties(null, null, null, null,
                new AuthProperties.Keys(false, store.toString(), "test-store-password", "signing-v1"), null, null);
        var factory = new SigningKeys();
        var selector = new JWKSelector(new JWKMatcher.Builder().privateOnly(true).build());
        RSAKey first = (RSAKey) factory.jwkSource(config).get(selector, null).get(0);
        RSAKey restarted = (RSAKey) factory.jwkSource(config).get(selector, null).get(0);
        assertThat(first.computeThumbprint()).isEqualTo(restarted.computeThumbprint());
        assertThat(first.toRSAPublicKey().getEncoded()).isEqualTo(restarted.toRSAPublicKey().getEncoded());
        // A certificate-only entry represents a previously retired verification key.
        var keystore = java.security.KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(store)) {
            keystore.load(input, "test-store-password".toCharArray());
        }
        keystore.setCertificateEntry("retired-key", keystore.getCertificate("signing-v1"));
        try (var output = Files.newOutputStream(store)) {
            keystore.store(output, "test-store-password".toCharArray());
        }
        var keys = factory.jwkSource(config).get(new JWKSelector(new JWKMatcher.Builder().build()), null);
        assertThat(keys).hasSize(2);
        assertThat(keys.stream().filter(JWK::isPrivate)).hasSize(1);
    }

    @Test
    void rejectsMissingProductionKeyMaterial() {
        var config = new AuthProperties(null, null, null, null,
                new AuthProperties.Keys(false, directory.resolve("missing.p12").toString(), "", "signing"), null, null);
        assertThatThrownBy(() -> new SigningKeys().jwkSource(config)).isInstanceOf(IllegalStateException.class);
    }
}
