package eastguard.common;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Big-endian encoder for the spec §5 primitives. Invalid values are programming errors and throw
 * {@link IllegalArgumentException}; encoders never emit something the matching reader would reject.
 */
public final class WireWriter {
    private final ByteArrayOutputStream out;

    public WireWriter() {
        this(256);
    }

    public WireWriter(int initialCapacity) {
        this.out = new ByteArrayOutputStream(initialCapacity);
    }

    public WireWriter u8(int v) {
        if (v < 0 || v > 0xFF) {
            throw new IllegalArgumentException("u8 out of range");
        }
        out.write(v);
        return this;
    }

    public WireWriter u16(int v) {
        if (v < 0 || v > 0xFFFF) {
            throw new IllegalArgumentException("u16 out of range");
        }
        out.write(v >>> 8);
        out.write(v);
        return this;
    }

    public WireWriter i64(long v) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.write((int) (v >>> shift));
        }
        return this;
    }

    /** Revisions, sequences and timestamps are nonnegative on the wire. */
    public WireWriter nonNegative(long v, String field) {
        if (v < 0) {
            throw new IllegalArgumentException(field + " must be nonnegative");
        }
        return i64(v);
    }

    public WireWriter ascii(String magic) {
        out.writeBytes(magic.getBytes(StandardCharsets.US_ASCII));
        return this;
    }

    public WireWriter raw(byte[] b) {
        out.writeBytes(b);
        return this;
    }

    public WireWriter fixed(Bytes b, int expectedLength, String field) {
        out.writeBytes(b.requireLength(expectedLength, field).toArray());
        return this;
    }

    public WireWriter id(String id) {
        Ids.require(id, "id");
        u8(id.length());
        return ascii(id);
    }

    /** {@code null} is written as a zero-length id. */
    public WireWriter optId(String id) {
        if (id == null) {
            return u8(0);
        }
        return id(id);
    }

    public WireWriter ip(IpAddress ip) {
        byte[] b = ip.toBytes();
        u8(b.length);
        return raw(b);
    }

    public int size() {
        return out.size();
    }

    public byte[] toByteArray() {
        return out.toByteArray();
    }
}
