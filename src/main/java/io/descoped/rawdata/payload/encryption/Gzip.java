package io.descoped.rawdata.payload.encryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * GZIP compression utilities.
 */
final class Gzip {
    private static final int BUFFER_SIZE = 8192; // Increased buffer size for better performance

    static byte[] compress(final byte[] payload) throws IOException {
        if ((payload == null) || (payload.length == 0)) {
            return new byte[0];
        }

        try (ByteArrayOutputStream buffer = new ByteArrayOutputStream(payload.length);
             GZIPOutputStream gzip = new GZIPOutputStream(buffer)) {
            gzip.write(payload);
            gzip.finish(); // Ensure all data is written
            return buffer.toByteArray();
        }
    }

    static byte[] decompress(final byte[] payload) throws IOException {
        if ((payload == null) || (payload.length == 0)) {
            return null;
        }

        if (!isCompressed(payload)) {
            return payload;
        }

        try (ByteArrayInputStream bis = new ByteArrayInputStream(payload);
             GZIPInputStream gzip = new GZIPInputStream(bis);
             ByteArrayOutputStream buffer = new ByteArrayOutputStream(payload.length)) {

            byte[] bytes = new byte[BUFFER_SIZE];
            int length;

            while ((length = gzip.read(bytes)) > 0) {
                buffer.write(bytes, 0, length);
            }
            return buffer.toByteArray();
        }
    }

    private static boolean isCompressed(final byte[] compressed) {
        return compressed.length >= 2
                && compressed[0] == (byte) (GZIPInputStream.GZIP_MAGIC)
                && compressed[1] == (byte) (GZIPInputStream.GZIP_MAGIC >> 8);
    }
}