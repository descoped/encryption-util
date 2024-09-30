package io.descoped.encryption.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class EncryptionClient {

    private static final Logger logger = LoggerFactory.getLogger(EncryptionClient.class);

    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_NONCE_LENGTH = 12; // GCM nonce length
    private static final int GCM_TAG_LENGTH = 128; // GCM authentication tag length in bits
    private static final int SALT_LENGTH = 16;
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int VERSION = 1; // For future versioning of the encryption scheme
    private static final SecretKeyFactory secretKeyFactory = getSecretKeyFactory();

    private static final ThreadLocal<SecureRandom> secureRandom = ThreadLocal.withInitial(SecureRandom::new);

    private final Algorithm algorithm;

    public EncryptionClient(Algorithm algorithm) {
        this.algorithm = algorithm;
    }

    private static SecretKeyFactory getSecretKeyFactory() {
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to initialize SecretKeyFactory", e);
        }
    }

    public SecretKey generateSecretKey(char[] password, byte[] salt) {
        if (password == null || password.length == 0 || salt == null || salt.length == 0) {
            throw new IllegalArgumentException("Password and salt cannot be null or empty");
        }
        try {
            KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, algorithm.getKeySize());
            SecretKey tmp = secretKeyFactory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), "AES");
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Failed to generate secret key", e);
        }
    }

    public SecretKey deriveKey(char[] password, byte[] salt) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        try {
            KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, algorithm.getKeySize());
            SecretKey tmp = secretKeyFactory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), "AES");
        } catch (InvalidKeySpecException e) {
            logger.error("Failed to derive key", e);
            throw new RuntimeException("Failed to derive key", e);
        }
    }

    public byte[] generateNonce() {
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        secureRandom.get().nextBytes(nonce);
        return nonce;
    }

    public byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.get().nextBytes(salt);
        return salt;
    }

    public byte[] encrypt(byte[] secretKey, byte[] data) throws EncryptionException {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to encrypt cannot be null or empty");
        }
        try {
            SecretKey key = new SecretKeySpec(secretKey, "AES");
            byte[] nonce = generateNonce();
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            byte[] encryptedData = cipher.doFinal(data);

            ByteBuffer buffer = ByteBuffer.allocate(1 + GCM_NONCE_LENGTH + encryptedData.length);
            buffer.put((byte) VERSION);
            buffer.put(nonce);
            buffer.put(encryptedData);

            return buffer.array();
        } catch (Exception e) {
            throw new EncryptionException("Failed to encrypt data", e);
        }
    }

    public byte[] decrypt(byte[] secretKey, byte[] encryptedData) throws DecryptionException {
        if (encryptedData == null || encryptedData.length == 0) {
            throw new IllegalArgumentException("Encrypted data cannot be null or empty");
        }
        try {
            ByteBuffer buffer = ByteBuffer.wrap(encryptedData);

            byte version = buffer.get();
            if (version != VERSION) {
                throw new DecryptionException("Unsupported version: " + version);
            }

            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            buffer.get(nonce);

            int ciphertextLength = encryptedData.length - 1 - GCM_NONCE_LENGTH;
            byte[] ciphertext = new byte[ciphertextLength];
            buffer.get(ciphertext);

            SecretKey key = new SecretKeySpec(secretKey, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new DecryptionException("Failed to decrypt data", e);
        }
    }
}