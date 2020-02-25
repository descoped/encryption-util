package no.ssb.rawdata.payload.encryption;

public enum Algorithm {
    AES128(128),
    AES256(256);

    private final int bitLength;

    Algorithm(int bitLength) {
        this.bitLength = bitLength;
    }

    public int aesKeySize() {
        return bitLength;
    }
}
