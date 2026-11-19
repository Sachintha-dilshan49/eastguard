package eastguard.common;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * Token service reply (spec §5.1): {@code status:u8 | tokenLength:u16 | tokenBytes}. Token length is 1..2048
 * on success and exactly zero otherwise.
 */
public record IssuerReply(ReplyStatus status, Bytes token) {
    public static final int MAX_LENGTH = 3 + LeaseCodec.MAX_TOKEN_LENGTH;

    public IssuerReply {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(token, "token");
        if (status == ReplyStatus.SUCCESS) {
            if (token.length() < 1 || token.length() > LeaseCodec.MAX_TOKEN_LENGTH) {
                throw new IllegalArgumentException("success needs a 1..2048 byte token");
            }
        } else if (token.length() != 0) {
            throw new IllegalArgumentException("unsuccessful reply must not carry a token");
        }
    }

    public static IssuerReply success(byte[] token) {
        return new IssuerReply(ReplyStatus.SUCCESS, Bytes.copyOf(token));
    }

    public static IssuerReply failure(ReplyStatus status) {
        return new IssuerReply(status, Bytes.copyOf(new byte[0]));
    }

    public byte[] encode() {
        return new WireWriter(3 + token.length()).u8(status.code()).u16(token.length()).raw(token.toArray())
                .toByteArray();
    }

    public static IssuerReply decode(byte[] frame) throws CodecException {
        WireReader r = new WireReader(frame);
        ReplyStatus status = ReplyStatus.fromCode(r.u8());
        int len = r.u16();
        checkLength(status, len);
        byte[] token = r.raw(len);
        r.end();
        return new IssuerReply(status, Bytes.copyOf(token));
    }

    /** Reads exactly one reply frame. Rejects an invalid length before reading the token bytes. */
    public static IssuerReply read(InputStream in) throws IOException, CodecException {
        byte[] head = Frames.readExactly(in, 3);
        ReplyStatus status = ReplyStatus.fromCode(head[0] & 0xFF);
        int len = ((head[1] & 0xFF) << 8) | (head[2] & 0xFF);
        checkLength(status, len);
        return new IssuerReply(status, Bytes.copyOf(Frames.readExactly(in, len)));
    }

    private static void checkLength(ReplyStatus status, int len) throws CodecException {
        boolean ok = status == ReplyStatus.SUCCESS ? len >= 1 && len <= LeaseCodec.MAX_TOKEN_LENGTH : len == 0;
        if (!ok) {
            throw new CodecException("invalid token length");
        }
    }
}
