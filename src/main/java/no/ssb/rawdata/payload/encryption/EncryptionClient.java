package no.ssb.rawdata.payload.encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class EncryptionClient {

    static final SecretKeyFactory secretKeyFactory = getSecretKeyFactory();

    final Algorithm algorithm;
    final int gcmTagLength;
    final int gcpIvLength;

    public EncryptionClient() {
        this(Algorithm.AES128);
    }

    public EncryptionClient(Algorithm algorithm) {
        this.algorithm = algorithm;
        this.gcmTagLength = 16;
        this.gcpIvLength = 12;
    }

    static SecretKeyFactory getSecretKeyFactory() {
        try {
            return SecretKeyFactory.getInstance(/*"PBKDF2WithHmacSHA3-512"*/"PBKDF2WithHmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    static String bytesToHex(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Generate an initial secret key
     *
     * @return AES GCM SecretKey
     */
    SecretKey generateInitialSecretKey() {
        byte[] key = new byte[gcmTagLength];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        return secretKey;
    }

    /**
     * @param key  provided encryption key
     * @param salt provided salt
     * @return AES GCM SecretKey
     * @throws InvalidKeySpecException
     */
    SecretKeySpec generateSecretKey(char[] key, byte[] salt) throws InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(key, salt, 65536, algorithm.aesKeySize());
        SecretKey tmp = secretKeyFactory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    /**
     * Generate a default IV (12 bytes)
     *
     * @return IV
     */
    byte[] generateIV() {
        return generateIV(gcpIvLength);
    }

    /**
     * Generate an IV with a given length
     *
     * @param ivLength
     * @return IV
     */
    byte[] generateIV(int ivLength) {
        byte[] iv = new byte[ivLength];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Encrypt payload with AES GCM transformation
     *
     * @param secretKey secretKey
     * @param iv        initialization vector
     * @param plaintext payload to encrypt
     * @return byte-array with the segments: iv-length, iv and ciphertext
     */
    byte[] encrypt(final byte[] secretKey, final byte[] iv, final byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(algorithm.aesKeySize(), iv);
            SecretKeySpec keySpec = new SecretKeySpec(secretKey, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

            ByteBuffer cipherBuffer = ByteBuffer.allocate(4 + iv.length + cipher.getBlockSize() + plaintext.length);
            cipherBuffer.putInt(iv.length);
            cipherBuffer.put(iv);
            cipher.doFinal(ByteBuffer.wrap(plaintext), cipherBuffer);
            return cipherBuffer.array();

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | ShortBufferException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypt payload with AES GCM transformation
     *
     * @param secretKey     secretKey
     * @param cipherMessage byte-array with the segments: iv-length, iv and ciphertext
     * @return decrypted plaintext
     */
    byte[] decrypt(final byte[] secretKey, final byte[] cipherMessage) {
        try {
            ByteBuffer cipherBuffer = ByteBuffer.wrap(cipherMessage);
            int ivLength = cipherBuffer.getInt();
            if (ivLength < gcpIvLength || ivLength >= gcmTagLength) {
                throw new IllegalArgumentException("Invalid IV length!");
            }
            byte[] iv = new byte[ivLength];
            cipherBuffer.get(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(secretKey, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(algorithm.aesKeySize(), iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
            ByteBuffer plaintextBuffer = ByteBuffer.allocate(cipherBuffer.remaining() - (4 + ivLength));
            cipher.doFinal(cipherBuffer, plaintextBuffer);
            return plaintextBuffer.array();

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | ShortBufferException e) {
            throw new RuntimeException(e);
        }
    }

}
