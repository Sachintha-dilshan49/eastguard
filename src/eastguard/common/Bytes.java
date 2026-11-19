package eastguard.common;

import java.io.Serial;
import java.io.Serializable;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Immutable byte string with value equality. Use it for fixed-size binary fields (fingerprints, jti, nonces,
 * public keys) so records can hold them without exposing a mutable array.
 *
 * <p>{@link #toString()} prints only the length so that key material is never logged by accident;
 * call {@link #hex()} explicitly where a hex rendering is safe.
 */
public final class Bytes implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
    private static final HexFormat HEX = HexFormat.of();

    private final byte[] data;

    private Bytes(byte[] owned) {
        this.data = owned;
    }

    public static Bytes copyOf(byte[] src) {
        return new Bytes(src.clone());
    }

    public static Bytes copyOf(byte[] src, int offset, int length) {
        return new Bytes(Arrays.copyOfRange(src, offset, Math.addExact(offset, length)));
    }

    public static Bytes fromHex(String hex) {
        return new Bytes(HEX.parseHex(hex));
    }

    public int length() {
        return data.length;
    }

    public byte get(int index) {
        return data[index];
    }

    /** Returns a fresh copy. */
    public byte[] toArray() {
        return data.clone();
    }

    public String hex() {
        return HEX.formatHex(data);
    }

    /** Throws {@link IllegalArgumentException} unless this has exactly {@code expected} bytes. */
    public Bytes requireLength(int expected, String field) {
        if (data.length != expected) {
            throw new IllegalArgumentException(field + " must be " + expected + " bytes");
        }
        return this;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Bytes other && Arrays.equals(data, other.data);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }

    @Override
    public String toString() {
        return "Bytes[" + data.length + "]";
    }

    /** Never share the deserialized array with anything else in the object graph. */
    @Serial
    private Object readResolve() {
        return new Bytes(data.clone());
    }
}
