package io.descoped.encryption.client;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Known answers produced by the released 2.0.1 code (format 1, PBKDF2 with 65,536 iterations), so data written by
 * 2.0.x stays readable.
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
}
