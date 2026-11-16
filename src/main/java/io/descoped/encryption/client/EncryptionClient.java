package io.descoped.encryption.client;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Authenticated encryption with AES-GCM, and password-based key derivation with PBKDF2-HMAC-SHA256.
 *
 * <p>Every call to {@link #encrypt(SecretKey, byte[], byte[])} uses a fresh random 96-bit nonce and produces a
 * self-describing ciphertext in format 2:
 *
 * <pre>
 * +---------+------------------+----------------------+-------------------+
 * | 0x02    | nonce (12 bytes) | encrypted data       | GCM tag (16 bytes)|
 * +---------+------------------+----------------------+-------------------+
 * </pre>
 *
 * <p>The 13-byte header (format byte and nonce) is authenticated together with the caller's optional associated
 * data, so the format byte cannot be changed without decryption failing.
 *
 * <p>Format 1 is still decrypted, never written. It has two layouts behind the same format byte: 2.0.0 wrote
 * AES-CBC/PKCS5Padding with an HMAC-SHA256 over IV and data (encrypt-then-MAC, keyed with the AES key), and 2.0.1
 * wrote AES-GCM like format 2 but without associated data. The HMAC is checked before CBC decryption.
 *
 * <p>Instances are immutable and thread-safe. A {@code Cipher} and a {@code SecretKeyFactory} are created per call,
 * because neither is safe for concurrent use.
 *
 * <p>With random nonces, a single key should encrypt no more than 2<sup>32</sup> messages (NIST SP 800-38D, section
 * 8.3). Rotate the key long before that.
 */
public final class EncryptionClient {

    /**
     * PBKDF2-HMAC-SHA256 iterations used by {@link #deriveKey(char[], byte[])}: the OWASP Password Storage Cheat
     * Sheet recommendation.
     */
    public static final int PBKDF2_ITERATIONS = 600_000;

    /**
     * PBKDF2 iterations used by 2.0.0 and 2.0.1. Pass it to {@link #deriveKey(char[], byte[], int)} to derive the keys
     * that existing 2.x data was encrypted with. It is also the lowest iteration count accepted.
     */
    public static final int LEGACY_PBKDF2_ITERATIONS = 65_536;

    /**
     * Shortest accepted salt, in bytes (128 bits, NIST SP 800-132). {@link #generateSalt()} returns salts of this
     * length.
     */
    public static final int SALT_LENGTH = 16;

    static final byte FORMAT_1 = 1;
    static final byte FORMAT_2 = 2;
    static final int NONCE_LENGTH = 12;
    static final int TAG_LENGTH = 16;
    static final int HEADER_LENGTH = 1 + NONCE_LENGTH;

    private static final String LEGACY_CIPHER = "AES/CBC/PKCS5Padding";
    private static final String LEGACY_HMAC = "HmacSHA256";
    private static final int LEGACY_IV_LENGTH = 16;
    private static final int LEGACY_HMAC_LENGTH = 32;

    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final String KDF = "PBKDF2WithHmacSHA256";
    private static final byte[] NO_DATA = new byte[0];
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Algorithm algorithm;

    /**
     * Creates a client for the given key size.
     *
     * @param algorithm the AES key size of the keys this client generates, derives and accepts
     */
    public EncryptionClient(Algorithm algorithm) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
    }

    /**
     * Returns the AES key size of this client.
     *
     * @return the algorithm given to the constructor
     */
    public Algorithm algorithm() {
        return algorithm;
    }

    /**
     * Generates a random AES key. Prefer a random key, kept in a key management system, to a key derived from a
     * password.
     *
     * @return a new key of this client's size
     * @throws IllegalStateException if the platform has no AES key generator
     */
    public SecretKey generateKey() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(algorithm.getKeySize(), RANDOM);
            return generator.generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES key generation is not available", e);
        }
    }

    /**
     * Generates a random salt for {@link #deriveKey(char[], byte[])}. The salt is not secret; store it next to the
     * ciphertext.
     *
     * @return {@value #SALT_LENGTH} random bytes
     */
    public byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Derives a key from a password with PBKDF2-HMAC-SHA256 and {@value #PBKDF2_ITERATIONS} iterations. The same
     * password and salt always give the same key.
     *
     * @param password the password; not modified, the caller should clear it after use
     * @param salt     at least {@value #SALT_LENGTH} bytes, unique per password
     * @return the derived key
     * @throws IllegalArgumentException if the password is empty or the salt is too short
     * @throws IllegalStateException    if the platform has no PBKDF2-HMAC-SHA256
     */
    public SecretKey deriveKey(char[] password, byte[] salt) {
        return deriveKey(password, salt, PBKDF2_ITERATIONS);
    }

    /**
     * Derives a key from a password with PBKDF2-HMAC-SHA256 and the given number of iterations. Use
     * {@link #LEGACY_PBKDF2_ITERATIONS} to derive keys made by 2.0.x.
     *
     * @param password   the password; not modified, the caller should clear it after use
     * @param salt       at least {@value #SALT_LENGTH} bytes, unique per password
     * @param iterations at least {@value #LEGACY_PBKDF2_ITERATIONS}
     * @return the derived key
     * @throws IllegalArgumentException if the password is empty, the salt is too short or the iteration count is
     *                                  too low
     * @throws IllegalStateException    if the platform has no PBKDF2-HMAC-SHA256
     */
    public SecretKey deriveKey(char[] password, byte[] salt, int iterations) {
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(salt, "salt");
        if (password.length == 0) {
            throw new IllegalArgumentException("Password cannot be empty");
        }
        if (salt.length < SALT_LENGTH) {
            throw new IllegalArgumentException("Salt must be at least " + SALT_LENGTH + " bytes, was " + salt.length);
        }
        if (iterations < LEGACY_PBKDF2_ITERATIONS) {
            throw new IllegalArgumentException("Iterations must be at least " + LEGACY_PBKDF2_ITERATIONS + ", was " + iterations);
        }
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, algorithm.getKeySize());
        SecretKey derived = null;
        byte[] encoded = null;
        try {
            derived = SecretKeyFactory.getInstance(KDF).generateSecret(spec);
            encoded = derived.getEncoded();
            return new SecretKeySpec(encoded, "AES");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(KDF + " is not available", e);
        } finally {
            spec.clearPassword();
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
            destroy(derived);
        }
    }

    /**
     * Wraps raw key bytes, for example a key read from a key management system, as an AES key.
     *
     * @param encoded the key, {@code algorithm().getKeySize() / 8} bytes; copied, so the caller may clear it
     * @return the key
     * @throws IllegalArgumentException if the length does not match this client's key size
     */
    public SecretKey importKey(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length * 8 != algorithm.getKeySize()) {
            throw new IllegalArgumentException("Key must be " + algorithm.getKeySize() / 8 + " bytes for " + algorithm
                    + ", was " + encoded.length);
        }
        return new SecretKeySpec(encoded, "AES");
    }

    /**
     * Encrypts and authenticates data. Same as {@link #encrypt(SecretKey, byte[], byte[])} without associated data.
     *
     * @param key       an AES key of this client's size
     * @param plaintext the data to encrypt; may be empty
     * @return the ciphertext in format 2, {@code plaintext.length + 29} bytes
     * @throws IllegalArgumentException if the key is not an AES key of this client's size
     * @throws EncryptionException      if the platform cannot encrypt
     */
    public byte[] encrypt(SecretKey key, byte[] plaintext) {
        return encrypt(key, plaintext, NO_DATA);
    }

    /**
     * Encrypts and authenticates data, and binds it to associated data. The associated data is not encrypted and
     * not part of the result, but the same bytes must be given to {@link #decrypt(SecretKey, byte[], byte[])}. Use
     * it for context the ciphertext belongs to, such as a record id or a tenant, so a ciphertext cannot be moved to
     * another record unnoticed.
     *
     * @param key            an AES key of this client's size
     * @param plaintext      the data to encrypt; may be empty
     * @param associatedData data to authenticate but not encrypt; may be empty
     * @return the ciphertext in format 2, {@code plaintext.length + 29} bytes
     * @throws IllegalArgumentException if the key is not an AES key of this client's size
     * @throws EncryptionException      if the platform cannot encrypt
     */
    public byte[] encrypt(SecretKey key, byte[] plaintext, byte[] associatedData) {
        checkKey(key);
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(associatedData, "associatedData");
        byte[] out = new byte[HEADER_LENGTH + plaintext.length + TAG_LENGTH];
        out[0] = FORMAT_2;
        byte[] nonce = new byte[NONCE_LENGTH];
        RANDOM.nextBytes(nonce);
        System.arraycopy(nonce, 0, out, 1, NONCE_LENGTH);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH * 8, nonce));
            cipher.updateAAD(out, 0, HEADER_LENGTH);
            if (associatedData.length > 0) {
                cipher.updateAAD(associatedData);
            }
            cipher.doFinal(plaintext, 0, plaintext.length, out, HEADER_LENGTH);
            return out;
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Encryption failed", e);
        }
    }

    /**
     * Verifies and decrypts a ciphertext made by {@link #encrypt(SecretKey, byte[])}, or by 2.0.0 or 2.0.1.
     *
     * @param key        the key the data was encrypted with
     * @param ciphertext a ciphertext in format 2, or in format 1 from 2.0.0 or 2.0.1
     * @return the plaintext
     * @throws IllegalArgumentException if the key is not an AES key of this client's size
     * @throws DecryptionException      if the ciphertext is malformed, was encrypted with another key or associated
     *                                  data, or has been changed
     */
    public byte[] decrypt(SecretKey key, byte[] ciphertext) {
        return decrypt(key, ciphertext, NO_DATA);
    }

    /**
     * Verifies and decrypts a ciphertext made by {@link #encrypt(SecretKey, byte[], byte[])}. Nothing is returned
     * unless the whole ciphertext and the associated data are authentic.
     *
     * @param key            the key the data was encrypted with
     * @param ciphertext     a ciphertext in format 2, or in format 1 from 2.0.0 or 2.0.1 (which only accepts empty
     *                       associated data)
     * @param associatedData the associated data given to encrypt; may be empty
     * @return the plaintext
     * @throws IllegalArgumentException if the key is not an AES key of this client's size
     * @throws DecryptionException      if the ciphertext is malformed, was encrypted with another key or associated
     *                                  data, or has been changed
     */
    public byte[] decrypt(SecretKey key, byte[] ciphertext, byte[] associatedData) {
        checkKey(key);
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(associatedData, "associatedData");
        if (ciphertext.length < HEADER_LENGTH + TAG_LENGTH) {
            throw new DecryptionException("Ciphertext is too short: " + ciphertext.length + " bytes");
        }
        byte format = ciphertext[0];
        if (format != FORMAT_1 && format != FORMAT_2) {
            throw new DecryptionException("Unsupported ciphertext format: " + format);
        }
        if (format == FORMAT_1 && associatedData.length > 0) {
            throw new DecryptionException("Ciphertext format 1 cannot carry associated data");
        }
        if (format == FORMAT_1 && isLegacyCbcLayout(ciphertext)) {
            byte[] plaintext = decryptLegacyCbc(key, ciphertext);
            if (plaintext != null) {
                return plaintext;
            }
            // The HMAC did not match: a 2.0.1 GCM ciphertext of the same length, or a failure reported below.
        }
        try {
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH * 8, ciphertext, 1, NONCE_LENGTH));
            if (format == FORMAT_2) {
                cipher.updateAAD(ciphertext, 0, HEADER_LENGTH);
                if (associatedData.length > 0) {
                    cipher.updateAAD(associatedData);
                }
            }
            return cipher.doFinal(ciphertext, HEADER_LENGTH, ciphertext.length - HEADER_LENGTH);
        } catch (AEADBadTagException e) {
            throw new DecryptionException("Authentication failed: wrong key or associated data, or the ciphertext was changed", e);
        } catch (GeneralSecurityException e) {
            throw new DecryptionException("Decryption failed", e);
        }
    }

    /**
     * Whether a format-1 ciphertext has the length of the 2.0.0 layout: format byte, 16-byte IV, a whole number of
     * (at least one) AES-CBC blocks, 32-byte HMAC-SHA256. A 2.0.1 GCM ciphertext can have the same length; the HMAC
     * tells them apart.
     */
    private static boolean isLegacyCbcLayout(byte[] ciphertext) {
        int blocks = ciphertext.length - 1 - LEGACY_IV_LENGTH - LEGACY_HMAC_LENGTH;
        return blocks >= LEGACY_IV_LENGTH && blocks % LEGACY_IV_LENGTH == 0;
    }

    /**
     * Decrypts the 2.0.0 layout (encrypt-then-MAC: AES-CBC/PKCS5Padding, then HMAC-SHA256 keyed with the AES key over
     * IV and encrypted data). The HMAC is checked in constant time before anything is decrypted, so the padding is
     * never examined for unauthenticated data. Read only: this layout is never written.
     *
     * @return the plaintext, or {@code null} if the HMAC does not match
     */
    private static byte[] decryptLegacyCbc(SecretKey key, byte[] ciphertext) {
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            return null;
        }
        int dataLength = ciphertext.length - 1 - LEGACY_IV_LENGTH - LEGACY_HMAC_LENGTH;
        try {
            Mac mac = Mac.getInstance(LEGACY_HMAC);
            mac.init(new SecretKeySpec(encoded, LEGACY_HMAC));
            mac.update(ciphertext, 1, LEGACY_IV_LENGTH + dataLength);
            byte[] expected = Arrays.copyOfRange(ciphertext, ciphertext.length - LEGACY_HMAC_LENGTH, ciphertext.length);
            if (!MessageDigest.isEqual(mac.doFinal(), expected)) {
                return null;
            }
            Cipher cipher = Cipher.getInstance(LEGACY_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ciphertext, 1, LEGACY_IV_LENGTH));
            return cipher.doFinal(ciphertext, 1 + LEGACY_IV_LENGTH, dataLength);
        } catch (GeneralSecurityException e) {
            throw new DecryptionException("Decryption failed", e);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Clears the provider's intermediate key now rather than when it is garbage collected. A provider whose keys
     * cannot be destroyed leaves it to the collector.
     */
    private static void destroy(SecretKey key) {
        if (key == null || key.isDestroyed()) {
            return;
        }
        try {
            key.destroy();
        } catch (DestroyFailedException e) {
            // Not supported by this provider: the key is cleared when it is collected.
        }
    }

    private void checkKey(SecretKey key) {
        Objects.requireNonNull(key, "key");
        if (!"AES".equalsIgnoreCase(key.getAlgorithm())) {
            throw new IllegalArgumentException("Key must be an AES key, was " + key.getAlgorithm());
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            // A key that cannot be exported, such as one held in a hardware token: the provider checks it.
            return;
        }
        int bits = encoded.length * 8;
        Arrays.fill(encoded, (byte) 0);
        if (bits != algorithm.getKeySize()) {
            throw new IllegalArgumentException("Key must be " + algorithm.getKeySize() + " bits for " + algorithm
                    + ", was " + bits);
        }
    }
}
