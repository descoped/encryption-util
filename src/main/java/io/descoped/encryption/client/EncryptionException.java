package io.descoped.encryption.client;

import java.io.Serial;

/**
 * Thrown when the platform cannot encrypt, for example when AES-GCM is not available.
 */
public class EncryptionException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message what was wrong
     * @param cause   the underlying failure
     */
    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
