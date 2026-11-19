package eastguard.common;

import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * Gateway preamble sent inside mTLS before any application byte (spec §5.1):
 *
 * <pre>
 * request: magic:u16 = 0x455A | version:u8 = 1 | tokenLength:u16 | tokenBytes   (token 1..2048)
 * reply:   status:u8
 * </pre>
 */
public record Preamble(Bytes token) {
    public static final int MAGIC = 0x455A;
    public static final int VERSION = 1;
    public static final int HEADER_LENGTH = 5;
    public static final int MAX_LENGTH = HEADER_LENGTH + LeaseCodec.MAX_TOKEN_LENGTH;

    public Preamble {
        Objects.requireNonNull(token, "token");
        if (token.length() < 1 || token.length() > LeaseCodec.MAX_TOKEN_LENGTH) {
            throw new IllegalArgumentException("token must be 1..2048 bytes");
        }
    }

    public static Preamble of(byte[] token) {
        return new Preamble(Bytes.copyOf(token));
    }

    public byte[] encode() {
        return new WireWriter(HEADER_LENGTH + token.length())
                .u16(MAGIC).u8(VERSION).u16(token.length()).raw(token.toArray()).toByteArray();
    }

    /** Decodes one complete frame; rejects truncation and trailing bytes. */
    public static Preamble decode(byte[] frame) throws CodecException {
        ByteBuffer buf = ByteBuffer.wrap(frame);
        Preamble p = tryDecode(buf);
        if (p == null) {
            throw new CodecException("truncated");
        }
        if (buf.hasRemaining()) {
            throw new CodecException("trailing bytes");
        }
        return p;
    }

    /**
     * Incremental decode for a non-blocking reader. {@code buf} is in read mode.
     *
     * <ul>
     *   <li>Complete frame: consumes exactly the frame and returns it. Bytes after it stay in {@code buf}; the
     *       gateway must treat them as a protocol violation because clients wait for the reply.</li>
     *   <li>Incomplete but plausible so far: returns {@code null} and leaves {@code buf} untouched.</li>
     *   <li>Invalid: throws as soon as the offending header bytes have arrived, so an oversize length is
     *       rejected without waiting for (or buffering) the claimed token.</li>
     * </ul>
     */
    public static Preamble tryDecode(ByteBuffer buf) throws CodecException {
        int start = buf.position();
        int avail = buf.remaining();
        if (avail >= 1 && (buf.get(start) & 0xFF) != MAGIC >>> 8
                || avail >= 2 && (buf.get(start + 1) & 0xFF) != (MAGIC & 0xFF)) {
            throw new CodecException("bad magic");
        }
        if (avail >= 3 && (buf.get(start + 2) & 0xFF) != VERSION) {
            throw new CodecException("unsupported version");
        }
        if (avail < HEADER_LENGTH) {
            return null;
        }
        int len = ((buf.get(start + 3) & 0xFF) << 8) | (buf.get(start + 4) & 0xFF);
        if (len < 1 || len > LeaseCodec.MAX_TOKEN_LENGTH) {
            throw new CodecException("invalid token length");
        }
        if (avail < HEADER_LENGTH + len) {
            return null;
        }
        byte[] token = new byte[len];
        buf.get(start + HEADER_LENGTH, token);
        buf.position(start + HEADER_LENGTH + len);
        return new Preamble(Bytes.copyOf(token));
    }

    public static byte[] encodeReply(ReplyStatus status) {
        return new byte[] {(byte) status.code()};
    }

    public static ReplyStatus decodeReply(int statusByte) throws CodecException {
        return ReplyStatus.fromCode(statusByte & 0xFF);
    }
}
