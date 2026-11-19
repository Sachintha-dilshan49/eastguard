package eastguard.common;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * Multicast control notice (spec §5.4):
 *
 * <pre>
 * "EGC1" | cluster:id | keyId:id | revision:i64 | sentAt:i64 | nonce:16 | operation:u8 | expiresAt:i64
 *        | selectorCount:u8 | selectors... | reason:u8 | signature:64     // Ed25519 over all preceding bytes
 * selector = type:u8 | identity:id OR ip:ip
 * </pre>
 *
 * Authenticated, not encrypted. Datagrams are capped like telemetry; receive into
 * {@link TelemetryCodec#RECEIVE_BUFFER}-sized buffers to detect oversize input.
 */
public final class NoticeCodec {
    public static final String MAGIC = "EGC1";
    public static final int MAX_DATAGRAM = TelemetryCodec.MAX_DATAGRAM;
    public static final long MAX_CLOCK_SKEW_MS = 30_000;

    private NoticeCodec() {
    }

    public static byte[] encode(Notice n, PrivateKey controlKey) {
        WireWriter w = new WireWriter(512)
                .ascii(MAGIC).id(n.cluster()).id(n.keyId())
                .nonNegative(n.revision(), "revision").nonNegative(n.sentAtMs(), "sentAt")
                .fixed(n.nonce(), Notice.NONCE_LENGTH, "nonce")
                .u8(n.operation().code()).i64(n.expiresAtMs())
                .u8(n.selectors().size());
        for (Selector s : n.selectors()) {
            w.u8(s.type().code());
            switch (s.type()) {
                case IDENTITY -> w.id(s.identity());
                case IP -> w.ip(s.ip());
            }
        }
        w.u8(n.reason().code());
        byte[] out = w.raw(Ed25519.sign(controlKey, w.toByteArray())).toByteArray();
        if (out.length > MAX_DATAGRAM) {
            throw new IllegalStateException("notice exceeds datagram cap"); // unreachable: max is ~770 bytes
        }
        return out;
    }

    /**
     * Decodes and authenticates one notice.
     *
     * @param controlKeys trusted control-plane verification key for a key ID, or {@code null} if untrusted
     * @param clock       wall clock; {@code sentAt} must be within ±30 s of it
     */
    public static Notice decode(byte[] buf, int offset, int length, String expectedCluster,
            Function<String, PublicKey> controlKeys, Clock clock) throws CodecException {
        if (length > MAX_DATAGRAM) {
            throw new CodecException("oversize datagram");
        }
        if (length < Ed25519.SIGNATURE_LENGTH) {
            throw new CodecException("truncated");
        }
        int bodyLength = length - Ed25519.SIGNATURE_LENGTH;
        WireReader r = new WireReader(buf, offset, bodyLength);
        r.magic(MAGIC);
        String cluster = r.id();
        String keyId = r.id();
        long revision = r.nonNegative("revision");
        long sentAt = r.nonNegative("sentAt");
        Bytes nonce = r.fixed(Notice.NONCE_LENGTH);
        int opCode = r.u8();
        long expiresAt = r.i64();
        int count = r.u8();
        if (count < 1 || count > Notice.MAX_SELECTORS) {
            throw new CodecException("selector count out of range");
        }
        List<Selector> selectors = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            SelectorType type = SelectorType.fromCode(r.u8());
            selectors.add(switch (type) {
                case IDENTITY -> Selector.identity(r.id());
                case IP -> Selector.ip(r.ip());
            });
        }
        int reasonCode = r.u8();
        r.end();

        if (!cluster.equals(expectedCluster)) {
            throw new CodecException("wrong cluster");
        }
        PublicKey key = controlKeys.apply(keyId);
        if (key == null) {
            throw new CodecException("untrusted control key");
        }
        byte[] body = new byte[bodyLength];
        System.arraycopy(buf, offset, body, 0, bodyLength);
        byte[] sig = new byte[Ed25519.SIGNATURE_LENGTH];
        System.arraycopy(buf, offset + bodyLength, sig, 0, sig.length);
        if (!Ed25519.verify(key, body, sig)) {
            throw new CodecException("bad signature");
        }
        // sentAt is nonnegative and so is now, so the subtraction cannot overflow.
        if (Math.abs(clock.millis() - sentAt) > MAX_CLOCK_SKEW_MS) {
            throw new CodecException("notice timestamp outside skew window");
        }
        NoticeOperation op = NoticeOperation.fromCode(opCode);
        ReasonCode reason = ReasonCode.fromCode(reasonCode);
        try {
            return new Notice(cluster, keyId, revision, sentAt, nonce, op, expiresAt, selectors, reason);
        } catch (IllegalArgumentException e) {
            throw new CodecException("invalid notice: " + e.getMessage());
        }
    }

    public static Notice decode(byte[] datagram, String expectedCluster, Function<String, PublicKey> controlKeys,
            Clock clock) throws CodecException {
        return decode(datagram, 0, datagram.length, expectedCluster, controlKeys, clock);
    }
}
