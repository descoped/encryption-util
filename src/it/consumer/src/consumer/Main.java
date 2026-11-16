package consumer;

import io.descoped.encryption.client.Algorithm;
import io.descoped.encryption.client.DecryptionException;
import io.descoped.encryption.client.EncryptionClient;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Uses the library as an application would: random key, derived key, associated data, tamper detection.
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        String mode = args.length > 0 ? args[0] : "?";
        EncryptionClient client = new EncryptionClient(Algorithm.AES256);
        byte[] plaintext = "smoke test".getBytes(StandardCharsets.UTF_8);
        byte[] context = "record-1".getBytes(StandardCharsets.UTF_8);

        SecretKey random = client.generateKey();
        check(Arrays.equals(plaintext, client.decrypt(random, client.encrypt(random, plaintext, context), context)),
                "random key round trip");

        SecretKey derived = client.deriveKey("password".toCharArray(), client.generateSalt());
        byte[] ciphertext = client.encrypt(derived, plaintext);
        check(Arrays.equals(plaintext, client.decrypt(derived, ciphertext)), "derived key round trip");

        ciphertext[ciphertext.length - 1] ^= 1;
        try {
            client.decrypt(derived, ciphertext);
            check(false, "tampered ciphertext rejected");
        } catch (DecryptionException expected) {
            // rejected, as it must be
        }

        Module module = EncryptionClient.class.getModule();
        System.out.println("OK (" + mode + "): " + (module.isNamed() ? "module " + module.getName() : "class path"));
    }

    private static void check(boolean condition, String what) {
        if (!condition) {
            throw new AssertionError(what);
        }
    }
}
