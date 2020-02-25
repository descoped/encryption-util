package no.ssb.rawdata.payload.encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
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

    static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    static final String ALGORITHM = "AES";
    static final String DEFAULT_CONTENT_ENCODING = "gzip";
    static final int AES_KEY_SIZE = 128;
    static final int GCM_TAG_LENGTH = AES_KEY_SIZE / 8; // default: 16
    static final int GCM_IV_LENGTH = (GCM_TAG_LENGTH / 4) * 3; // default: 12
    static final SecretKeyFactory secretKeyFactory = getSecretKeyFactory();

    private static SecretKeyFactory getSecretKeyFactory() {
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

    SecretKeySpec generateSecretKey(char[] privateKey, byte[] salt) throws InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(privateKey, salt, 65536, AES_KEY_SIZE);
        SecretKey tmp = secretKeyFactory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
    }

    byte[] generateInitialSecretKey() {
        byte[] key = new byte[GCM_TAG_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);
        return secretKey.getEncoded();
    }

    byte[] generateSalt() {
        byte[] iv = new byte[AES_KEY_SIZE / 8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    byte[] generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Encrypt payload with AES GCM transformation
     *
     * @param key secretKey
     * @param iv initialization vector
     * @param plaintext payload to encrypt
     * @return byte-array with the segments: iv-length, iv and ciphertext
     */
    byte[] encrypt(final byte[] key, final byte[] iv, final byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(AES_KEY_SIZE, iv);
            SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
            byte[] cipherText = cipher.doFinal(plaintext);

            ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + cipherText.length);
            byteBuffer.putInt(iv.length);
            byteBuffer.put(iv);
            byteBuffer.put(cipherText);
            return byteBuffer.array();

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypt payload with AES GCM transformation
     *
     * @param key secretKey
     * @param cipherMessage byte-array with the segments: iv-length, iv and ciphertext
     * @return decrypted plaintext
     */
    byte[] decrypt(final byte[] key, final byte[] cipherMessage) {
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(cipherMessage);
            int ivLength = byteBuffer.getInt();
            if (ivLength < GCM_IV_LENGTH || ivLength >= GCM_TAG_LENGTH) { // check input parameter
                throw new IllegalArgumentException("invalid iv length");
            }
            byte[] iv = new byte[ivLength];
            byteBuffer.get(iv);
            byte[] ciphertext = new byte[byteBuffer.remaining()];
            byteBuffer.get(ciphertext);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(AES_KEY_SIZE, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
            return cipher.doFinal(ciphertext);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

}
