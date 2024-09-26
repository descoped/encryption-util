package io.descoped.encryption.client;

public enum Algorithm {
    AES128(128), AES256(256);

    private final int keySize;

    Algorithm(int keySize) {
        this.keySize = keySize;
    }

    public int getKeySize() {
        return keySize;
    }
}
