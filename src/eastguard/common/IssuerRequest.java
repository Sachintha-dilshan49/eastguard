package eastguard.common;

import java.io.IOException;
import java.io.InputStream;

/**
 * Token request sent inside mTLS to the token service (spec §5.1): {@code "EGI1" | targetService:id}.
 * The requester's identity comes from the TLS peer certificate, never from this frame.
 */
public record IssuerRequest(String targetService) {
    public static final String MAGIC = "EGI1";
    /** 4 magic + 1 length + 64 id bytes. */
    public static final int MAX_LENGTH = 4 + 1 + Ids.MAX_LENGTH;

    public IssuerRequest {
        Ids.require(targetService, "targetService");
    }

    public byte[] encode() {
        return new WireWriter(MAX_LENGTH).ascii(MAGIC).id(targetService).toByteArray();
    }

    public static IssuerRequest decode(byte[] frame) throws CodecException {
        if (frame.length > MAX_LENGTH) {
            throw new CodecException("request too long");
        }
        WireReader r = new WireReader(frame);
        r.magic(MAGIC);
        String target = r.id();
        r.end();
        return new IssuerRequest(target);
    }

    /**
     * Reads exactly one request frame from a blocking stream and never reads past it. The caller bounds the
     * total time with a socket timeout.
     */
    public static IssuerRequest read(InputStream in) throws IOException, CodecException {
        byte[] head = Frames.readExactly(in, 5);
        new WireReader(head, 0, 4).magic(MAGIC);
        int idLen = head[4] & 0xFF;
        if (idLen == 0 || idLen > Ids.MAX_LENGTH) {
            throw new CodecException("invalid id length");
        }
        return decode(Frames.concat(head, Frames.readExactly(in, idLen)));
    }
}
