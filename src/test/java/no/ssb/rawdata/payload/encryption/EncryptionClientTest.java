package no.ssb.rawdata.payload.encryption;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;

public class EncryptionClientTest {

    static final String PRIVATE_KEY = "SECURE_KMS_TOKEN";
    static final String PAYLOAD = "{\"data\" : \"somevalue\"}";

    final List<byte[]> cipherMessages = new ArrayList<>();

    @Test
    public void testEncryption() throws InvalidKeySpecException {
        EncryptionClient client = new EncryptionClient();
        SecretKeySpec secretKey = client.generateSecretKey(PRIVATE_KEY.toCharArray(), "SALT".getBytes());
        byte[] iv = client.generateIV();
        byte[] cipherMessage = client.encrypt(secretKey.getEncoded(), iv, PAYLOAD.getBytes());
        cipherMessages.add(cipherMessage);
        System.out.printf("base64 encrypted: %s%n", Base64.getEncoder().encodeToString(cipherMessage));
    }

    @Test(dependsOnMethods = {"testEncryption"})
    public void testDecryption() throws InvalidKeySpecException {
        assertFalse(cipherMessages.isEmpty(), "Encryption must be executed before decryption");
        EncryptionClient client = new EncryptionClient();
        byte[] secretKey = client.generateSecretKey(PRIVATE_KEY.toCharArray(), "SALT".getBytes()).getEncoded();
        byte[] plaintext = client.decrypt(secretKey, cipherMessages.get(0));
        assertEquals(plaintext, PAYLOAD.getBytes());
    }

    @DataProvider(name = "Plaintext-Length-Variations")
    public static Object[][] credentials() {
        String base = "1234567890abcdefghijklmnopqrstuvwxyz";
        Object[][] objects = new Object[35][];
        for (int i = 0; i < 35; i++) {
            objects[i] = new Object[]{base.substring(0, i)};
        }
        return objects;
    }

    @Test(dataProvider = "Plaintext-Length-Variations")
    public void testEncryptionAndDecryption(String plaintext) throws InvalidKeySpecException {
        EncryptionClient client = new EncryptionClient();
        SecretKeySpec secretKey = client.generateSecretKey(PRIVATE_KEY.toCharArray(), "SALT".getBytes());

        byte[] iv = client.generateIV();

        byte[] cipherMessage = client.encrypt(secretKey.getEncoded(), iv, plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] plaintextBytes = client.decrypt(secretKey.getEncoded(), cipherMessage);

        assertEquals(new String(plaintextBytes, StandardCharsets.UTF_8), plaintext);
    }

    @Test
    public void testSpecificEncryptionAndDecryption() throws InvalidKeySpecException {
        testEncryptionAndDecryption("hello crypto");
    }
}
