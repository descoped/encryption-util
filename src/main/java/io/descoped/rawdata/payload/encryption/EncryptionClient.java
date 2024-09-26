package io.descoped.rawdata.payload.encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class EncryptionClient {

    private static final Logger logger = LoggerFactory.getLogger(EncryptionClient.class);

    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int IV_LENGTH = 16; // AES block size
    private static final int SALT_LENGTH = 16;
    private static final int HMAC_LENGTH = 32; // SHA256 output size
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

    public byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.get().nextBytes(iv);
        return iv;
    }

    public byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.get().nextBytes(salt);
        return salt;
    }

    public byte[] encrypt(byte[] secretKey, byte[] iv, byte[] data) throws EncryptionException {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to encrypt cannot be null or empty");
        }
        try {
            SecretKey key = new SecretKeySpec(secretKey, "AES");
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] encryptedData = cipher.doFinal(data);

            byte[] hmac = calculateHMAC(key, iv, encryptedData);

            ByteBuffer buffer = ByteBuffer.allocate(1 + IV_LENGTH + encryptedData.length + HMAC_LENGTH);
            buffer.put((byte) VERSION);
            buffer.put(iv);
            buffer.put(encryptedData);
            buffer.put(hmac);

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

            byte[] iv = new byte[IV_LENGTH];
            buffer.get(iv);

            int encryptedLength = encryptedData.length - 1 - IV_LENGTH - HMAC_LENGTH;
            byte[] ciphertext = new byte[encryptedLength];
            buffer.get(ciphertext);

            byte[] hmac = new byte[HMAC_LENGTH];
            buffer.get(hmac);

            SecretKey key = new SecretKeySpec(secretKey, "AES");

            // Verify HMAC
            byte[] calculatedHMAC = calculateHMAC(key, iv, ciphertext);
            if (!MessageDigest.isEqual(hmac, calculatedHMAC)) {
                throw new DecryptionException("HMAC verification failed");
            }

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);
        } catch (DecryptionException e) {
            throw e;
        } catch (Exception e) {
            throw new DecryptionException("Failed to decrypt data", e);
        }
    }

    private byte[] calculateHMAC(SecretKey secretKey, byte[] iv, byte[] ciphertext) throws Exception {
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        hmac.init(new SecretKeySpec(secretKey.getEncoded(), HMAC_ALGORITHM));
        hmac.update(iv);
        return hmac.doFinal(ciphertext);
    }
}
