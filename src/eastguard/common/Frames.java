package eastguard.common;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/** Small helpers for reading fixed-size frames from blocking streams. */
final class Frames {
    private Frames() {
    }

    /** Reads exactly {@code n} bytes; a premature EOF is a {@link CodecException} (truncated frame). */
    static byte[] readExactly(InputStream in, int n) throws IOException, CodecException {
        byte[] b = in.readNBytes(n);
        if (b.length != n) {
            throw new CodecException("truncated");
        }
        return b;
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
