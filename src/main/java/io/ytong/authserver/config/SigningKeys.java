package io.ytong.authserver.config;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.*;

@Configuration
public class SigningKeys {
    @Bean
    public JWKSource<SecurityContext> jwkSource(AuthProperties properties) throws Exception {
        AuthProperties.Keys config = properties.keys();
        List<JWK> keys = new ArrayList<>();
        if (config.ephemeral()) {
            LoggerFactory.getLogger(SigningKeys.class).warn("Ephemeral development signing key enabled. Tokens will not survive a restart.");
            keys.add(new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate());
        } else {
            if (config.password() == null || config.password().isBlank())
                throw new IllegalStateException("Configure AUTH_KEYSTORE_PASSWORD for the signing keystore");
            KeyStore store = KeyStore.getInstance("PKCS12");
            char[] password = config.password().toCharArray();
            try (var input = Files.newInputStream(Path.of(config.path()))) {
                store.load(input, password);
                RSAKey active = RSAKey.load(store, config.alias(), password);
                if (active == null || !active.isPrivate() || active.size() < 2048)
                    throw new IllegalStateException("A private RSA signing key of at least 2048 bits is required");
                keys.add(new RSAKey.Builder(active).keyID(config.alias()).build());
                // Retired keys must be certificate-only entries so they are published but never used to sign.
                for (String alias : Collections.list(store.aliases())) {
                    if (!alias.equals(config.alias()) && store.isCertificateEntry(alias)) {
                        if (store.getCertificate(alias).getPublicKey() instanceof RSAPublicKey rsa)
                            keys.add(new RSAKey.Builder(rsa).keyID(alias).build());
                    }
                }
            } finally { Arrays.fill(password, '\0'); }
        }
        JWKSet set = new JWKSet(keys);
        return (selector, context) -> selector.select(set);
    }
}
