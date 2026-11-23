package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Bytes;
import eastguard.common.Cidr;
import eastguard.common.CodecException;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.IpAddress;
import eastguard.common.LeaseReduction;
import eastguard.common.PilotScope;
import eastguard.common.Policy;
import eastguard.common.PolicyMode;
import eastguard.common.ReasonCode;
import eastguard.common.Restriction;
import eastguard.common.Selector;
import eastguard.common.Service;
import eastguard.common.SnapshotCodec;
import eastguard.common.WireWriter;
import eastguard.common.Workload;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Unit tests for {@link SnapshotCodec}:
 * full round-trip verification, deterministic byte encoding, corrupt magic,
 * truncation, trailing garbage, oversize limits, duplicate validation, and policy mode helpers.
 */
public final class SnapshotCodecTest {
    private static final IpAddress LOOPBACK = IpAddress.parse("127.0.0.1");

    private static EnforcementSnapshot buildFullSnapshot() {
        Workload wl1 = new Workload("web-01", true, Set.of(Bytes.copyOf(new byte[32])), Cidr.of(LOOPBACK, 32));
        Workload wl2 = new Workload("api-01", false, Set.of(), null);

        Service s1 = new Service("app-02", "gw-app-02", new Endpoint(LOOPBACK, 9002), "gateway-app-02",
                new Endpoint(LOOPBACK, 7002));

        Policy policy = new Policy(PolicyMode.ENFORCE, Set.of(new Edge("web-01", "app-02")),
                new PilotScope(Set.of("web-01"), Set.of("app-02")), 10, Duration.ofSeconds(60));

        Restriction r1 = new Restriction(Selector.identity("web-01"), ReasonCode.RISK_SCORE, "detector",
                Instant.ofEpochMilli(1_000_000), Instant.ofEpochMilli(2_000_000), 5);
        Restriction r2 = new Restriction(Selector.ip(LOOPBACK), ReasonCode.OPERATOR_ACTION, "admin",
                Instant.ofEpochMilli(1_100_000), Instant.ofEpochMilli(2_100_000), 6);

        LeaseReduction red = new LeaseReduction(Selector.identity("api-01"), Duration.ofSeconds(15),
                Instant.ofEpochMilli(3_000_000), 7);

        return new EnforcementSnapshot("eg-cluster-1", 42, policy,
                Map.of("web-01", wl1, "api-01", wl2),
                Map.of("app-02", s1),
                List.of(r1, r2),
                List.of(red),
                Map.of(Selector.identity("web-01"), 8L),
                Map.of("lease-k1", TestPki.leaseVerifyKey()),
                Set.of("old-key-revoked"));
    }

    public void testRoundTripCompleteSnapshot() throws Exception {
        EnforcementSnapshot original = buildFullSnapshot();
        byte[] encoded = SnapshotCodec.encode(original);

        assertTrue(encoded != null, "encoded not null");
        assertTrue(encoded.length > 0, "encoded length > 0");

        EnforcementSnapshot decoded = SnapshotCodec.decode(encoded);

        assertEquals(original.clusterId(), decoded.clusterId());
        assertEquals(original.revision(), decoded.revision());
        assertEquals(original.policy().mode(), decoded.policy().mode());
        assertEquals(original.policy().revision(), decoded.policy().revision());
        assertEquals(original.policy().defaultLeaseLength(), decoded.policy().defaultLeaseLength());
        assertEquals(original.policy().approvedEdges(), decoded.policy().approvedEdges());
        assertEquals(original.policy().pilotScope().sourceIdentities(), decoded.policy().pilotScope().sourceIdentities());
        assertEquals(original.policy().pilotScope().serviceIds(), decoded.policy().pilotScope().serviceIds());

        assertEquals(original.workloads().keySet(), decoded.workloads().keySet());
        Workload origWl = original.workloads().get("web-01");
        Workload decWl = decoded.workloads().get("web-01");
        assertEquals(origWl.enabled(), decWl.enabled());
        assertEquals(origWl.ipZone(), decWl.ipZone());
        assertEquals(origWl.revokedCertificates(), decWl.revokedCertificates());

        assertEquals(original.services().keySet(), decoded.services().keySet());
        assertEquals(original.restrictions().size(), decoded.restrictions().size());
        assertEquals(original.leaseReductions().size(), decoded.leaseReductions().size());
        assertEquals(original.releaseWatermarks(), decoded.releaseWatermarks());
        assertEquals(original.tokenKeys().keySet(), decoded.tokenKeys().keySet());
        assertEquals(original.revokedKeyIds(), decoded.revokedKeyIds());
        assertEquals(original.controlKeys().keySet(), decoded.controlKeys().keySet());

        // Deterministic re-encoding must produce the identical byte array
        byte[] reEncoded = SnapshotCodec.encode(decoded);
        assertArrayEquals(encoded, reEncoded);
    }

    public void testRejectsInvalidMagic() {
        byte[] encoded = SnapshotCodec.encode(buildFullSnapshot());
        byte[] badMagic = encoded.clone();
        badMagic[0] = 'X';
        badMagic[1] = 'Y';
        badMagic[2] = 'Z';
        badMagic[3] = '1';
        assertThrows(CodecException.class, () -> SnapshotCodec.decode(badMagic));
    }

    public void testRejectsTruncatedData() {
        byte[] encoded = SnapshotCodec.encode(buildFullSnapshot());
        assertThrows(CodecException.class, () -> SnapshotCodec.decode(Arrays.copyOf(encoded, 10)));
        assertThrows(CodecException.class, () -> SnapshotCodec.decode(Arrays.copyOf(encoded, encoded.length - 1)));
    }

    public void testRejectsTrailingGarbage() {
        byte[] encoded = SnapshotCodec.encode(buildFullSnapshot());
        byte[] trailing = Arrays.copyOf(encoded, encoded.length + 1);
        trailing[encoded.length] = (byte) 0xFF;
        assertThrows(CodecException.class, () -> SnapshotCodec.decode(trailing));
    }

    public void testRejectsOversizeSnapshot() {
        byte[] oversize = new byte[SnapshotCodec.MAX_SIZE + 1];
        assertThrows(CodecException.class, () -> SnapshotCodec.decode(oversize));
    }

    public void testRejectsDuplicateEdgeInPolicy() {
        WireWriter w = new WireWriter(1024)
                .ascii(SnapshotCodec.MAGIC)
                .id("cluster-1")
                .nonNegative(1, "rev")
                .u8(1) // ENFORCE
                .nonNegative(1, "policyRev")
                .i64(60_000)
                .u16(2) // 2 edges with same source and destination
                .id("web-01").id("app-02")
                .id("web-01").id("app-02")
                .u16(0) // pilot sources
                .u16(0) // pilot services
                .u16(0) // workloads
                .u16(0) // services
                .u16(0) // restrictions
                .u16(0) // reductions
                .u16(0) // watermarks
                .u16(0) // token keys
                .u16(0) // revoked key IDs
                .u16(0); // control keys

        assertThrows(CodecException.class, () -> SnapshotCodec.decode(w.toByteArray()));
    }

    public void testPolicyModeHelpers() throws Exception {
        assertEquals(1, SnapshotCodec.modeCode(PolicyMode.ENFORCE));
        assertEquals(2, SnapshotCodec.modeCode(PolicyMode.LEARN));

        assertEquals(PolicyMode.ENFORCE, SnapshotCodec.mode(1));
        assertEquals(PolicyMode.LEARN, SnapshotCodec.mode(2));

        assertThrows(CodecException.class, () -> SnapshotCodec.mode(0));
        assertThrows(CodecException.class, () -> SnapshotCodec.mode(3));
    }
}
