package io.descoped.encryption.client;

/**
 * AES key size used by an {@link EncryptionClient}. Both sizes use AES-GCM with a 128-bit tag; prefer
 * {@link #AES256}.
 */
public enum Algorithm {

    /** AES with a 128-bit key. */
    AES128(128),

    /** AES with a 256-bit key. */
    AES256(256);

    private final int keySize;

    Algorithm(int keySize) {
        this.keySize = keySize;
    }

    /**
     * Returns the key size.
     *
     * @return the key size in bits
     */
    public int getKeySize() {
        return keySize;
    }
}
