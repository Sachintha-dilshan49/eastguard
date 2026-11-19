package eastguard.common;

import java.util.function.BiFunction;

/**
 * Flow telemetry datagram (spec §5.3):
 *
 * <pre>
 * "EGF1" | cluster:id | producerId:id | keyId:id | bootId:16 | seq:i64 | eventAt:i64 | policyRevision:i64
 *        | sourceIdentity:optId | sourceIp:ip | service:id | dstIp:ip | dstPort:u16
 *        | verdict:u8 | reason:u8 | flags:u8 | mac:32          // HMAC-SHA256 over all preceding bytes
 * </pre>
 *
 * The whole datagram is capped at {@value #MAX_DATAGRAM} bytes. Receive into a buffer of
 * {@link #RECEIVE_BUFFER} bytes so an oversize packet is detected as too long rather than silently truncated
 * by {@code DatagramSocket} into something parseable.
 */
public final class TelemetryCodec {
    public static final String MAGIC = "EGF1";
    public static final int MAX_DATAGRAM = 1200;
    public static final int RECEIVE_BUFFER = MAX_DATAGRAM + 1;
    private static final int FLAG_OUTSIDE_APPROVED_GRAPH = 0x01;

    private TelemetryCodec() {
    }

    public static byte[] encode(Telemetry t, byte[] macKey) {
        WireWriter w = new WireWriter(512)
                .ascii(MAGIC).id(t.cluster()).id(t.producerId()).id(t.keyId())
                .fixed(t.bootId(), Telemetry.BOOT_ID_LENGTH, "bootId")
                .nonNegative(t.seq(), "seq").nonNegative(t.eventAtMs(), "eventAt")
                .nonNegative(t.policyRevision(), "policyRevision")
                .optId(t.sourceIdentity()).ip(t.sourceIp())
                .id(t.service()).ip(t.dstIp()).u16(t.dstPort())
                .u8(t.verdict().code()).u8(t.reason().code())
                .u8(t.outsideApprovedGraph() ? FLAG_OUTSIDE_APPROVED_GRAPH : 0);
        byte[] body = w.toByteArray();
        byte[] out = w.raw(Hmac.sha256(macKey, body)).toByteArray();
        if (out.length > MAX_DATAGRAM) {
            throw new IllegalStateException("telemetry exceeds datagram cap"); // unreachable with id <= 64
        }
        return out;
    }

    /**
     * Decodes and authenticates one datagram.
     *
     * @param macKeys returns the MAC key for {@code (producerId, keyId)}, or {@code null} if that producer/key is
     *                not in the trusted inventory
     * @throws CodecException on oversize or malformed input, wrong cluster, unknown key, bad MAC, reserved flag
     *                        bits, or inconsistent fields
     */
    public static Telemetry decode(byte[] buf, int offset, int length, String expectedCluster,
            BiFunction<String, String, byte[]> macKeys) throws CodecException {
        if (length > MAX_DATAGRAM) {
            throw new CodecException("oversize datagram");
        }
        if (length < Hmac.MAC_LENGTH) {
            throw new CodecException("truncated");
        }
        int bodyLength = length - Hmac.MAC_LENGTH;
        WireReader r = new WireReader(buf, offset, bodyLength);
        r.magic(MAGIC);
        String cluster = r.id();
        String producer = r.id();
        String keyId = r.id();
        Bytes bootId = r.fixed(Telemetry.BOOT_ID_LENGTH);
        long seq = r.nonNegative("seq");
        long eventAt = r.nonNegative("eventAt");
        long policyRevision = r.nonNegative("policyRevision");
        String sourceIdentity = r.optId();
        IpAddress sourceIp = r.ip();
        String service = r.id();
        IpAddress dstIp = r.ip();
        int dstPort = r.u16();
        int verdictCode = r.u8();
        int reasonCode = r.u8();
        int flags = r.u8();
        r.end();

        if (!cluster.equals(expectedCluster)) {
            throw new CodecException("wrong cluster");
        }
        byte[] key = macKeys.apply(producer, keyId);
        if (key == null) {
            throw new CodecException("unknown producer key");
        }
        byte[] mac = new byte[Hmac.MAC_LENGTH];
        System.arraycopy(buf, offset + bodyLength, mac, 0, Hmac.MAC_LENGTH);
        if (!Hmac.verify(key, buf, offset, bodyLength, mac)) {
            throw new CodecException("bad mac");
        }
        // Only now, with an authenticated datagram, interpret enum values and flags.
        if ((flags & ~FLAG_OUTSIDE_APPROVED_GRAPH) != 0) {
            throw new CodecException("reserved flag bits set");
        }
        Verdict verdict = Verdict.fromCode(verdictCode);
        ReasonCode reason = ReasonCode.fromCode(reasonCode);
        try {
            return new Telemetry(cluster, producer, keyId, bootId, seq, eventAt, policyRevision, sourceIdentity,
                    sourceIp, service, dstIp, dstPort, verdict, reason, (flags & FLAG_OUTSIDE_APPROVED_GRAPH) != 0);
        } catch (IllegalArgumentException e) {
            throw new CodecException("invalid telemetry: " + e.getMessage());
        }
    }

    public static Telemetry decode(byte[] datagram, String expectedCluster,
            BiFunction<String, String, byte[]> macKeys) throws CodecException {
        return decode(datagram, 0, datagram.length, expectedCluster, macKeys);
    }
}
