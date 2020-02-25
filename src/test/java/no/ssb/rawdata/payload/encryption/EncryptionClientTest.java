package no.ssb.rawdata.payload.encryption;

import org.testng.annotations.Test;

import javax.crypto.spec.SecretKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;

// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
// https://www.novixys.com/blog/java-aes-example/
// https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
// https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-and-android-part-2-b3b80e99ad36
// https://devops.datenkollektiv.de/using-aes-with-openssl-to-encrypt-files.html
// https://codereview.stackexchange.com/questions/234727/java-rsa-aes-gcm-encryption-utility
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
}
