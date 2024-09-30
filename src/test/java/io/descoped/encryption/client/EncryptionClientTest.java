package io.descoped.encryption.client;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class EncryptionClientTest {

    private static final String PASSWORD = "SECURE_KMS_TOKEN";
    private static final String PAYLOAD = "{\"data\" : \"somevalue\"}";

    @DataProvider(name = "algorithms")
    public static Object[][] algorithms() {
        return new Object[][]{
                {Algorithm.AES128},
                {Algorithm.AES256}
        };
    }

    @Test(dataProvider = "algorithms")
    public void testEncryptionAndDecryption(Algorithm algorithm) throws Exception {
        EncryptionClient client = new EncryptionClient(algorithm);
        byte[] salt = client.generateSalt();
        SecretKey secretKey = client.deriveKey(PASSWORD.toCharArray(), salt);

        byte[] encrypted = client.encrypt(secretKey.getEncoded(), PAYLOAD.getBytes(StandardCharsets.UTF_8));
        byte[] decrypted = client.decrypt(secretKey.getEncoded(), encrypted);

        assertEquals(new String(decrypted, StandardCharsets.UTF_8), PAYLOAD);
    }

    @DataProvider(name = "Plaintext-Length-Variations")
    public static Object[][] plaintextVariations() {
        String base = "1234567890abcdefghijklmnopqrstuvwxyz";
        Object[][] objects = new Object[72][]; // 36 lengths (including empty string) * 2 algorithms
        objects[0] = new Object[]{"", Algorithm.AES128};
        objects[1] = new Object[]{"", Algorithm.AES256};
        for (int i = 1; i <= 35; i++) {
            objects[i * 2] = new Object[]{base.substring(0, i), Algorithm.AES128};
            objects[i * 2 + 1] = new Object[]{base.substring(0, i), Algorithm.AES256};
        }
        return objects;
    }

    @Test(dataProvider = "Plaintext-Length-Variations")
    public void testEncryptionAndDecryptionWithVariousLengths(String plaintext, Algorithm algorithm) throws Exception {
        EncryptionClient client = new EncryptionClient(algorithm);
        byte[] salt = client.generateSalt();
        SecretKey secretKey = client.deriveKey(PASSWORD.toCharArray(), salt);

        if (plaintext.isEmpty()) {
            // Test that empty plaintext is handled correctly
            try {
                client.encrypt(secretKey.getEncoded(), plaintext.getBytes(StandardCharsets.UTF_8));
            } catch (IllegalArgumentException e) {
                // Expected behavior for empty input
                return;
            }
            throw new AssertionError("Expected IllegalArgumentException for empty input");
        }

        byte[] encrypted = client.encrypt(secretKey.getEncoded(), plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] decrypted = client.decrypt(secretKey.getEncoded(), encrypted);

        assertEquals(new String(decrypted, StandardCharsets.UTF_8), plaintext);
    }

    @Test(dataProvider = "algorithms")
    public void testEncryptionWithReusedKey(Algorithm algorithm) throws Exception {
        EncryptionClient client = new EncryptionClient(algorithm);
        byte[] salt = client.generateSalt();
        SecretKey secretKey = client.deriveKey(PASSWORD.toCharArray(), salt);

        // First encryption
        byte[] encrypted1 = client.encrypt(secretKey.getEncoded(), PAYLOAD.getBytes(StandardCharsets.UTF_8));

        // Second encryption
        byte[] encrypted2 = client.encrypt(secretKey.getEncoded(), PAYLOAD.getBytes(StandardCharsets.UTF_8));

        // Decrypt both
        byte[] decrypted1 = client.decrypt(secretKey.getEncoded(), encrypted1);
        byte[] decrypted2 = client.decrypt(secretKey.getEncoded(), encrypted2);

        assertEquals(new String(decrypted1, StandardCharsets.UTF_8), PAYLOAD);
        assertEquals(new String(decrypted2, StandardCharsets.UTF_8), PAYLOAD);
        assertNotEquals(encrypted1, encrypted2);
    }

    @Test(dataProvider = "algorithms")
    public void testDeriveKey(Algorithm algorithm) {
        EncryptionClient client = new EncryptionClient(algorithm);
        byte[] salt = new byte[16]; // Use a fixed salt for this test
        Arrays.fill(salt, (byte) 0x00);

        SecretKey key = client.deriveKey(PASSWORD.toCharArray(), salt);

        assertNotNull(key, "Derived key should not be null");
        assertEquals(key.getAlgorithm(), "AES", "Key algorithm should be AES");
        assertEquals(key.getEncoded().length * 8, algorithm.getKeySize(), "Key size should match the algorithm specification");
    }

    @Test(dataProvider = "algorithms")
    public void testDeriveKeyConsistency(Algorithm algorithm) {
        EncryptionClient client = new EncryptionClient(algorithm);
        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 0x00);

        SecretKey key1 = client.deriveKey(PASSWORD.toCharArray(), salt);
        SecretKey key2 = client.deriveKey(PASSWORD.toCharArray(), salt);

        assertTrue(Arrays.equals(key1.getEncoded(), key2.getEncoded()), "Derived keys should be consistent for the same password and salt");
    }

    @Test(dataProvider = "algorithms")
    public void testDeriveKeyWithDifferentSalts(Algorithm algorithm) {
        EncryptionClient client = new EncryptionClient(algorithm);
        byte[] salt1 = new byte[16];
        byte[] salt2 = new byte[16];
        Arrays.fill(salt1, (byte) 0x00);
        Arrays.fill(salt2, (byte) 0x01);

        SecretKey key1 = client.deriveKey(PASSWORD.toCharArray(), salt1);
        SecretKey key2 = client.deriveKey(PASSWORD.toCharArray(), salt2);

        assertFalse(Arrays.equals(key1.getEncoded(), key2.getEncoded()), "Derived keys should be different for different salts");
    }

    @Test(dataProvider = "algorithms", expectedExceptions = IllegalArgumentException.class)
    public void testDeriveKeyWithNullPassword(Algorithm algorithm) {
        EncryptionClient client = new EncryptionClient(algorithm);
        byte[] salt = new byte[16];
        client.deriveKey(null, salt);
    }

    @Test(dataProvider = "algorithms", expectedExceptions = IllegalArgumentException.class)
    public void testDeriveKeyWithEmptyPassword(Algorithm algorithm) {
        EncryptionClient client = new EncryptionClient(algorithm);
        byte[] salt = new byte[16];
        client.deriveKey(new char[0], salt);
    }

    @Test(dataProvider = "algorithms")
    public void testGenerateSalt(Algorithm algorithm) {
        EncryptionClient client = new EncryptionClient(algorithm);
        byte[] salt1 = client.generateSalt();
        byte[] salt2 = client.generateSalt();

        assertNotNull(salt1, "Generated salt should not be null");
        assertNotNull(salt2, "Generated salt should not be null");
        assertEquals(salt1.length, 16, "Salt length should be 16 bytes");
        assertEquals(salt2.length, 16, "Salt length should be 16 bytes");
        assertFalse(Arrays.equals(salt1, salt2), "Generated salts should be unique");
    }

    @Test(dataProvider = "algorithms", expectedExceptions = DecryptionException.class)
    public void testDecryptionWithWrongKey(Algorithm algorithm) throws Exception {
        EncryptionClient client = new EncryptionClient(algorithm);
        byte[] salt = client.generateSalt();
        SecretKey secretKey = client.deriveKey(PASSWORD.toCharArray(), salt);

        byte[] encrypted = client.encrypt(secretKey.getEncoded(), PAYLOAD.getBytes(StandardCharsets.UTF_8));

        // Generate a different key
        SecretKey wrongKey = client.deriveKey("WRONG_PASSWORD".toCharArray(), salt);

        client.decrypt(wrongKey.getEncoded(), encrypted);
    }

    @Test(dataProvider = "algorithms")
    public void testLongPayloadEncryptionAndDecryption(Algorithm algorithm) throws Exception {
        String longPayload = "This is a long client that exceeds the block size of AES to ensure that multi-block encryption and decryption work correctly. " +
                "It should be long enough to span multiple blocks and test the GCM mode of operation effectively.".repeat(10);
        EncryptionClient client = new EncryptionClient(algorithm);
        byte[] salt = client.generateSalt();
        SecretKey secretKey = client.deriveKey(PASSWORD.toCharArray(), salt);

        byte[] encrypted = client.encrypt(secretKey.getEncoded(), longPayload.getBytes(StandardCharsets.UTF_8));
        byte[] decrypted = client.decrypt(secretKey.getEncoded(), encrypted);

        assertEquals(new String(decrypted, StandardCharsets.UTF_8), longPayload);
    }
}