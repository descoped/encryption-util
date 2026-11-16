package io.descoped.encryption.client;

import java.io.Serial;

/**
 * Thrown when a ciphertext cannot be decrypted: it is malformed, in an unknown format, was encrypted with another key
 * or associated data, or has been changed. No part of the plaintext is ever returned in that case.
 */
public class DecryptionException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message what was wrong
     */
    public DecryptionException(String message) {
        super(message);
    }

    /**
     * Creates the exception.
     *
     * @param message what was wrong
     * @param cause   the underlying failure
     */
    public DecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
