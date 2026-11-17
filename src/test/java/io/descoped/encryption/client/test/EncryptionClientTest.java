package io.descoped.encryption.client.test;

import io.descoped.encryption.client.Algorithm;
import io.descoped.encryption.client.DecryptionException;
import io.descoped.encryption.client.EncryptionClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EncryptionClientTest {

    // The ciphertext layout, written out here rather than read from the library, so a change to the format fails a
    // test: format byte | nonce (12) | ciphertext | tag (16).
    private static final byte FORMAT_1 = 1;
    private static final byte FORMAT_2 = 2;
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH = 16;
    private static final int HEADER_LENGTH = 1 + NONCE_LENGTH;

    private static final byte[] PAYLOAD = "{\"data\" : \"somevalue\"}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CONTEXT = "record-42".getBytes(StandardCharsets.UTF_8);

    @ParameterizedTest
    @EnumSource(Algorithm.class)
    void roundTripWithGeneratedKey(Algorithm algorithm) {
        EncryptionClient client = new EncryptionClient(algorithm);
        SecretKey key = client.generateKey();

        byte[] ciphertext = client.encrypt(key, PAYLOAD);

        assertArrayEquals(PAYLOAD, client.decrypt(key, ciphertext));
    }

    @ParameterizedTest
    @EnumSource(Algorithm.class)
    void roundTripForEveryLengthAcrossBlocks(Algorithm algorithm) {
        EncryptionClient client = new EncryptionClient(algorithm);
        SecretKey key = client.generateKey();
        for (int length = 0; length <= 100; length++) {
            byte[] plaintext = new byte[length];
            Arrays.fill(plaintext, (byte) length);

            byte[] ciphertext = client.encrypt(key, plaintext);

            assertEquals(length + 29, ciphertext.length);
            assertArrayEquals(plaintext, client.decrypt(key, ciphertext), "length " + length);
        }
    }

    @Test
    void formatTwoLayout() {
        EncryptionClient client = new EncryptionClient(Algorithm.AES256);

        byte[] ciphertext = client.encrypt(client.generateKey(), PAYLOAD);

        assertEquals(FORMAT_2, ciphertext[0]);
        assertEquals(HEADER_LENGTH + PAYLOAD.length + TAG_LENGTH, ciphertext.length);
    }

    @Test
    void everyEncryptionUsesAFreshNonce() {
        EncryptionClient client = new EncryptionClient(Algorithm.AES256);
        SecretKey key = client.generateKey();
        Set<String> nonces = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            byte[] ciphertext = client.encrypt(key, PAYLOAD);
            nonces.add(Arrays.toString(Arrays.copyOfRange(ciphertext, 1, 1 + NONCE_LENGTH)));
        }
        assertEquals(1000, nonces.size());
    }

    @Test
    void associatedDataRoundTrip() {
        EncryptionClient client = new EncryptionClient(Algorithm.AES256);
        SecretKey key = client.generateKey();

        byte[] ciphertext = client.encrypt(key, PAYLOAD, CONTEXT);

        assertArrayEquals(PAYLOAD, client.decrypt(key, ciphertext, CONTEXT));
    }

    @Test
    void wrongOrMissingAssociatedDataFails() {
        EncryptionClient client = new EncryptionClient(Algorithm.AES256);
        SecretKey key = client.generateKey();
        byte[] ciphertext = client.encrypt(key, PAYLOAD, CONTEXT);

        assertThrows(DecryptionException.class,
                () -> client.decrypt(key, ciphertext, "record-43".getBytes(StandardCharsets.UTF_8)));
        assertThrows(DecryptionException.class, () -> client.decrypt(key, ciphertext));
        byte[] withoutContext = client.encrypt(key, PAYLOAD);
        assertThrows(DecryptionException.class, () -> client.decrypt(key, withoutContext, CONTEXT));
    }

    @Test
    void changingAnyByteFails() {
        EncryptionClient client = new EncryptionClient(Algorithm.AES256);
        SecretKey key = client.generateKey();
        byte[] ciphertext = client.encrypt(key, PAYLOAD);
        for (int i = 0; i < ciphertext.length; i++) {
            byte[] changed = ciphertext.clone();
            changed[i] ^= 0x01;
            assertThrows(DecryptionException.class, () -> client.decrypt(key, changed), "byte " + i);
        }
    }

    @Test
    void downgradeToFormatOneFails() {
        EncryptionClient client = new EncryptionClient(Algorithm.AES256);
        SecretKey key = client.generateKey();
        byte[] ciphertext = client.encrypt(key, PAYLOAD);
        ciphertext[0] = FORMAT_1;

        assertThrows(DecryptionException.class, () -> client.decrypt(key, ciphertext));
    }

    @Test
    void truncatedOrUnknownCiphertextFails() {
        EncryptionClient client = new EncryptionClient(Algorithm.AES256);
        SecretKey key = client.generateKey();
        byte[] ciphertext = client.encrypt(key, PAYLOAD);

        assertThrows(DecryptionException.class, () -> client.decrypt(key, new byte[0]));
        assertThrows(DecryptionException.class, () -> client.decrypt(key, Arrays.copyOf(ciphertext, 28)));
        assertThrows(DecryptionException.class,
                () -> client.decrypt(key, Arrays.copyOf(ciphertext, ciphertext.length - 1)));
        byte[] unknown = ciphertext.clone();
        unknown[0] = 3;
        DecryptionException e = assertThrows(DecryptionException.class, () -> client.decrypt(key, unknown));
        assertEquals("Unsupported ciphertext format: 3", e.getMessage());
    }

    @ParameterizedTest
    @EnumSource(Algorithm.class)
    void wrongKeyFails(Algorithm algorithm) {
        EncryptionClient client = new EncryptionClient(algorithm);
        byte[] ciphertext = client.encrypt(client.generateKey(), PAYLOAD);

        assertThrows(DecryptionException.class, () -> client.decrypt(client.generateKey(), ciphertext));
    }

    @Test
    void keyOfAnotherSizeOrAlgorithmIsRejected() {
        EncryptionClient aes256 = new EncryptionClient(Algorithm.AES256);
        SecretKey key128 = new EncryptionClient(Algorithm.AES128).generateKey();
        SecretKey hmacKey = new SecretKeySpec(new byte[32], "HmacSHA256");

        assertThrows(IllegalArgumentException.class, () -> aes256.encrypt(key128, PAYLOAD));
        assertThrows(IllegalArgumentException.class, () -> aes256.encrypt(hmacKey, PAYLOAD));
        assertThrows(IllegalArgumentException.class, () -> aes256.importKey(new byte[16]));
        assertThrows(NullPointerException.class, () -> aes256.encrypt(null, PAYLOAD));
        assertThrows(NullPointerException.class, () -> aes256.encrypt(aes256.generateKey(), null));
    }

    @ParameterizedTest
    @EnumSource(Algorithm.class)
    void generatedAndImportedKeys(Algorithm algorithm) {
        EncryptionClient client = new EncryptionClient(algorithm);
        SecretKey key = client.generateKey();

        assertEquals("AES", key.getAlgorithm());
        assertEquals(algorithm.getKeySize(), key.getEncoded().length * 8);
        assertFalse(Arrays.equals(key.getEncoded(), client.generateKey().getEncoded()));

        byte[] raw = key.getEncoded();
        SecretKey imported = client.importKey(raw);
        Arrays.fill(raw, (byte) 0);
        assertArrayEquals(PAYLOAD, client.decrypt(imported, client.encrypt(key, PAYLOAD)));
    }

    @ParameterizedTest
    @EnumSource(Algorithm.class)
    void derivedKeys(Algorithm algorithm) {
        EncryptionClient client = new EncryptionClient(algorithm);
        char[] password = "SECURE_KMS_TOKEN".toCharArray();
        byte[] salt = client.generateSalt();

        SecretKey key1 = client.deriveKey(password, salt);
        SecretKey key2 = client.deriveKey(password, salt);
        SecretKey otherSalt = client.deriveKey(password, client.generateSalt());

        assertEquals("AES", key1.getAlgorithm());
        assertEquals(algorithm.getKeySize(), key1.getEncoded().length * 8);
        assertArrayEquals(key1.getEncoded(), key2.getEncoded());
        assertFalse(Arrays.equals(key1.getEncoded(), otherSalt.getEncoded()));
        assertArrayEquals("SECURE_KMS_TOKEN".toCharArray(), password, "the caller's password is not changed");
        assertArrayEquals(PAYLOAD, client.decrypt(key2, client.encrypt(key1, PAYLOAD)));
    }

    @Test
    void currentAndLegacyIterationsGiveDifferentKeys() {
        EncryptionClient client = new EncryptionClient(Algorithm.AES256);
        char[] password = "SECURE_KMS_TOKEN".toCharArray();
        byte[] salt = client.generateSalt();

        assertFalse(Arrays.equals(client.deriveKey(password, salt).getEncoded(),
                client.deriveKey(password, salt, EncryptionClient.LEGACY_PBKDF2_ITERATIONS).getEncoded()));
    }

    @Test
    void weakKeyDerivationInputIsRejected() {
        EncryptionClient client = new EncryptionClient(Algorithm.AES256);
        char[] password = "SECURE_KMS_TOKEN".toCharArray();
        byte[] salt = client.generateSalt();

        assertThrows(IllegalArgumentException.class, () -> client.deriveKey(new char[0], salt));
        assertThrows(IllegalArgumentException.class, () -> client.deriveKey(password, new byte[15]));
        assertThrows(IllegalArgumentException.class,
                () -> client.deriveKey(password, salt, EncryptionClient.LEGACY_PBKDF2_ITERATIONS - 1));
        assertThrows(NullPointerException.class, () -> client.deriveKey(null, salt));
        assertThrows(NullPointerException.class, () -> client.deriveKey(password, null));
    }

    @Test
    void salts() {
        EncryptionClient client = new EncryptionClient(Algorithm.AES256);

        assertEquals(EncryptionClient.SALT_LENGTH, client.generateSalt().length);
        assertFalse(Arrays.equals(client.generateSalt(), client.generateSalt()));
    }

    @Test
    void algorithm() {
        assertSame(Algorithm.AES128, new EncryptionClient(Algorithm.AES128).algorithm());
        assertThrows(NullPointerException.class, () -> new EncryptionClient(null));
    }

    @Test
    void oneClientAndKeyFromManyThreads() throws Exception {
        EncryptionClient client = new EncryptionClient(Algorithm.AES256);
        SecretKey key = client.generateKey();
        // ExecutorService is AutoCloseable only from Java 19; the baseline is 17.
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < 64; i++) {
                byte[] plaintext = ("message " + i).getBytes(StandardCharsets.UTF_8);
                results.add(executor.submit(() -> {
                    for (int j = 0; j < 50; j++) {
                        if (!Arrays.equals(plaintext, client.decrypt(key, client.encrypt(key, plaintext)))) {
                            return false;
                        }
                    }
                    return true;
                }));
            }
            for (Future<Boolean> result : results) {
                assertTrue(result.get());
            }
        } finally {
            executor.shutdownNow();
        }
    }
}
