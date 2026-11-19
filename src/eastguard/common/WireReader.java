package eastguard.common;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Bounded big-endian decoder for untrusted input. Every read checks the remaining length first, so a
 * truncated frame fails with {@link CodecException} instead of an index exception. Call {@link #end()} after
 * the last field to reject trailing bytes.
 */
public final class WireReader {
    private final byte[] buf;
    private final int end;
    private int pos;

    public WireReader(byte[] buf) {
        this(buf, 0, buf.length);
    }

    public WireReader(byte[] buf, int offset, int length) {
        Objects.checkFromIndexSize(offset, length, buf.length);
        this.buf = buf;
        this.pos = offset;
        this.end = offset + length;
    }

    private void need(int n) throws CodecException {
        if (n > end - pos) {
            throw new CodecException("truncated");
        }
    }

    public int position() {
        return pos;
    }

    public int remaining() {
        return end - pos;
    }

    public int u8() throws CodecException {
        need(1);
        return buf[pos++] & 0xFF;
    }

    public int u16() throws CodecException {
        need(2);
        int v = ((buf[pos] & 0xFF) << 8) | (buf[pos + 1] & 0xFF);
        pos += 2;
        return v;
    }

    public long i64() throws CodecException {
        need(8);
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (buf[pos + i] & 0xFFL);
        }
        pos += 8;
        return v;
    }

    /** Revisions, sequences and timestamps must be nonnegative. */
    public long nonNegative(String field) throws CodecException {
        long v = i64();
        if (v < 0) {
            throw new CodecException(field + " negative");
        }
        return v;
    }

    public byte[] raw(int n) throws CodecException {
        need(n);
        byte[] out = new byte[n];
        System.arraycopy(buf, pos, out, 0, n);
        pos += n;
        return out;
    }

    public Bytes fixed(int n) throws CodecException {
        need(n);
        Bytes b = Bytes.copyOf(buf, pos, n);
        pos += n;
        return b;
    }

    public void magic(String ascii) throws CodecException {
        byte[] expected = ascii.getBytes(StandardCharsets.US_ASCII);
        need(expected.length);
        for (int i = 0; i < expected.length; i++) {
            if (buf[pos + i] != expected[i]) {
                throw new CodecException("bad magic or unsupported version");
            }
        }
        pos += expected.length;
    }

    public String id() throws CodecException {
        String s = optId();
        if (s == null) {
            throw new CodecException("empty id");
        }
        return s;
    }

    /** Returns {@code null} for a zero-length id. */
    public String optId() throws CodecException {
        int len = u8();
        if (len == 0) {
            return null;
        }
        if (len > Ids.MAX_LENGTH) {
            throw new CodecException("id too long");
        }
        need(len);
        for (int i = 0; i < len; i++) {
            if (!Ids.isIdChar(buf[pos + i] & 0xFF, i == 0)) {
                throw new CodecException("invalid id");
            }
        }
        String s = new String(buf, pos, len, StandardCharsets.US_ASCII);
        pos += len;
        return s;
    }

    /** Requires length 4 or 16 and rejects the non-canonical IPv4-mapped IPv6 form. */
    public IpAddress ip() throws CodecException {
        int len = u8();
        if (len != 4 && len != 16) {
            throw new CodecException("invalid ip length");
        }
        byte[] b = raw(len);
        if (IpAddress.isIpv4Mapped(b)) {
            throw new CodecException("non-canonical ip");
        }
        return IpAddress.of(b);
    }

    public void end() throws CodecException {
        if (pos != end) {
            throw new CodecException("trailing bytes");
        }
    }
}
