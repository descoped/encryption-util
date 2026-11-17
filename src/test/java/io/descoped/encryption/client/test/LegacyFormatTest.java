package io.descoped.encryption.client.test;

import io.descoped.encryption.client.Algorithm;
import io.descoped.encryption.client.DecryptionException;
import io.descoped.encryption.client.EncryptionClient;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Known answers produced by the released 2.0.0 code (format 1, AES-CBC with HMAC-SHA256) and 2.0.1 code (format 1,
 * AES-GCM), both with PBKDF2 at 65,536 iterations, so data written by 2.0.x stays readable. Never change these fixtures
 * to make a test pass.
 */
class LegacyFormatTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final char[] PASSWORD = "correct horse battery staple".toCharArray();
    private static final byte[] SALT = HEX.parseHex("000102030405060708090a0b0c0d0e0f");
    private static final String PLAINTEXT = "Hello from encryption-util 2.0.1";

    @ParameterizedTest
    @CsvSource({
            "AES128, 8b55bc2b228eb8dc0f0cea8e0a66c414, 01da9ebd9e94847bcb9b7fc6edaccf7ca33f26450b9337d4bffefdfa3c2c19ce0afc2cedf37b188d900b272cf1446f6bce6f929cfeda97d9c2751a62a5",
            "AES256, 8b55bc2b228eb8dc0f0cea8e0a66c41465cd0058030e6ef63b23c647492e540d, 01a4b82ea9d67fd885b60d02af6900362ea35e6dbf3add0a4e8aba86a8506f39e7b007422b6a1b147f3c27d0dcf050ae2098d78fd374d1fa798c67fc56"
    })
    void decryptsFormatOneWithLegacyDerivedKey(Algorithm algorithm, String keyHex, String ciphertextHex) {
        EncryptionClient client = new EncryptionClient(algorithm);

        SecretKey key = client.deriveKey(PASSWORD, SALT, EncryptionClient.LEGACY_PBKDF2_ITERATIONS);

        assertEquals(keyHex, HEX.formatHex(key.getEncoded()));
        byte[] plaintext = client.decrypt(key, HEX.parseHex(ciphertextHex));
        assertEquals(PLAINTEXT, new String(plaintext, StandardCharsets.UTF_8));
        assertArrayEquals(plaintext, client.decrypt(client.importKey(HEX.parseHex(keyHex)), HEX.parseHex(ciphertextHex)));
    }

    @ParameterizedTest
    @CsvSource({
            "AES256, 8b55bc2b228eb8dc0f0cea8e0a66c41465cd0058030e6ef63b23c647492e540d, 01a4b82ea9d67fd885b60d02af6900362ea35e6dbf3add0a4e8aba86a8506f39e7b007422b6a1b147f3c27d0dcf050ae2098d78fd374d1fa798c67fc56"
    })
    void formatOneIsStillAuthenticated(Algorithm algorithm, String keyHex, String ciphertextHex) {
        EncryptionClient client = new EncryptionClient(algorithm);
        SecretKey key = client.importKey(HEX.parseHex(keyHex));
        byte[] ciphertext = HEX.parseHex(ciphertextHex);

        byte[] changed = ciphertext.clone();
        changed[changed.length - 1] ^= 0x01;
        assertThrows(DecryptionException.class, () -> client.decrypt(key, changed));
        assertThrows(DecryptionException.class,
                () -> client.decrypt(key, ciphertext, "context".getBytes(StandardCharsets.UTF_8)));
    }

    @ParameterizedTest
    @CsvSource({
            "AES128, 8b55bc2b228eb8dc0f0cea8e0a66c414, Hello from encryption-util 2.0.0, 01f0e1d2c3b4a5968778695a4b3c2d1e0fd388e84780e3003cbf5f9a2ec386a9ac2fdf195e55f95f0899e320b327682a53f21912fce0ba5d36de139343904e43feb331c072e87fbaa2c9ed461b89c7d7c7be9c224a8c244d7c4de1c4e583390799",
            "AES128, 8b55bc2b228eb8dc0f0cea8e0a66c414, x, 01f0e1d2c3b4a5968778695a4b3c2d1e0f0a69497bfc264c53f0d0c203146187e769daf4ddd44d58b3200c6428aa69bfa8bfe8c36d16f9c9c359294969b92579d1",
            "AES256, 8b55bc2b228eb8dc0f0cea8e0a66c41465cd0058030e6ef63b23c647492e540d, Hello from encryption-util 2.0.0, 01f0e1d2c3b4a5968778695a4b3c2d1e0f3f5be82a7340c627b944703ac450e20f21458b4b8a426e9694a0a73f07a72238e5b045591d58082f20df75e886f36859758c7759e89c4d32cccf4d2999705c2e95e858f66aa65b7925f025f2f41637b8",
            "AES256, 8b55bc2b228eb8dc0f0cea8e0a66c41465cd0058030e6ef63b23c647492e540d, x, 01f0e1d2c3b4a5968778695a4b3c2d1e0f606a93066ca66a9db5adda99cdb6fa9cf62b9a57962f66d4ce7f3c60fef72852fdc53263f53b47ec59855e714726785d"
    })
    void decryptsTheCbcLayoutOf200(Algorithm algorithm, String keyHex, String plaintext, String ciphertextHex) {
        EncryptionClient client = new EncryptionClient(algorithm);
        SecretKey key = client.deriveKey(PASSWORD, SALT, EncryptionClient.LEGACY_PBKDF2_ITERATIONS);
        assertEquals(keyHex, HEX.formatHex(key.getEncoded()));
        byte[] ciphertext = HEX.parseHex(ciphertextHex);

        assertEquals(plaintext, new String(client.decrypt(key, ciphertext), StandardCharsets.UTF_8));

        for (int i = 1; i < ciphertext.length; i++) {
            byte[] changed = ciphertext.clone();
            changed[i] ^= 0x01;
            assertThrows(DecryptionException.class, () -> client.decrypt(key, changed), "byte " + i);
        }
        assertThrows(DecryptionException.class,
                () -> client.decrypt(key, ciphertext, "context".getBytes(StandardCharsets.UTF_8)));
        SecretKey otherKey = client.generateKey();
        assertThrows(DecryptionException.class, () -> client.decrypt(otherKey, ciphertext));
    }

    /**
     * A 2.0.1 GCM ciphertext whose length also fits the 2.0.0 CBC layout (36-byte plaintext: 65 bytes) is told apart
     * by the HMAC and decrypted as GCM.
     */
    @ParameterizedTest
    @CsvSource({"AES128", "AES256"})
    void gcmOf201WithTheLengthOfTheCbcLayout(Algorithm algorithm) throws Exception {
        EncryptionClient client = new EncryptionClient(algorithm);
        SecretKey key = client.generateKey();
        byte[] plaintext = new byte[36];
        byte[] ciphertext = new byte[1 + 12 + plaintext.length + 16];
        ciphertext[0] = 1;
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, ciphertext, 1, 12));
        cipher.doFinal(plaintext, 0, plaintext.length, ciphertext, 13);
        assertEquals(65, ciphertext.length);

        assertArrayEquals(plaintext, client.decrypt(key, ciphertext));
    }
}
