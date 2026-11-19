package eastguard.test;

import static eastguard.test.Assert.*;
import static eastguard.test.Fixtures.*;

import eastguard.common.Bytes;
import eastguard.common.Cidr;
import eastguard.common.Edge;
import eastguard.common.Ed25519;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
import eastguard.common.IpAddress;
import eastguard.common.Lease;
import eastguard.common.LeaseCodec;
import eastguard.common.LeaseReduction;
import eastguard.common.Peer;
import eastguard.common.PilotScope;
import eastguard.common.Policy;
import eastguard.common.PolicyEvaluator;
import eastguard.common.PolicyEvaluator.Decision;
import eastguard.common.PolicyMode;
import eastguard.common.ReasonCode;
import eastguard.common.ReplyStatus;
import eastguard.common.Restriction;
import eastguard.common.Selector;
import eastguard.common.Service;
import eastguard.common.Verdict;
import eastguard.common.Workload;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class PolicyEvaluatorTest {
    private static final long REVISION = 10;
    private static final String PILOT_CLIENT = "batch-01";
    private static final Peer PEER = new Peer(CLIENT, LEAF, CLIENT_IP);
    private static final Endpoint EP = Endpoint.parse("127.0.0.1:9443");

    private final PolicyEvaluator evaluator = new PolicyEvaluator(CLOCK);

    // ---- fixture builder: mutable knobs, immutable snapshot ----

    private PolicyMode mode = PolicyMode.ENFORCE;
    private final Map<String, Workload> workloads = new HashMap<>(Map.of(
            CLIENT, Workload.enabled(CLIENT), PILOT_CLIENT, Workload.enabled(PILOT_CLIENT)));
    private final List<Restriction> restrictions = new ArrayList<>();
    private final List<LeaseReduction> reductions = new ArrayList<>();
    private final Map<Selector, Long> watermarks = new HashMap<>();
    private final Map<String, PublicKey> keys = new HashMap<>(Map.of(KEY_ID, LEASE_KEYS.getPublic()));
    private Set<String> revokedKeys = Set.of();

    private EnforcementSnapshot snapshot() {
        Policy policy = new Policy(mode, Set.of(new Edge(CLIENT, SERVICE)),
                new PilotScope(Set.of(PILOT_CLIENT), Set.of(SERVICE)), 3, Duration.ofSeconds(60));
        Map<String, Service> services = Map.of(
                SERVICE, new Service(SERVICE, "gw-1", EP, "gw1.eastguard.test", EP),
                "db-01", new Service("db-01", "gw-2", EP, "gw2.eastguard.test", EP));
        return new EnforcementSnapshot(CLUSTER, REVISION, policy, workloads, services, restrictions, reductions,
                watermarks, keys, revokedKeys);
    }

    private EnforcementView view() {
        return EnforcementView.fresh(snapshot());
    }

    private static byte[] token(Lease l) {
        return LeaseCodec.issue(l, LEASE_KEYS.getPrivate());
    }

    private Decision admit(Lease l) {
        return evaluator.admit(view(), PEER, SERVICE, token(l));
    }

    private static Restriction quarantine(Selector s) {
        return new Restriction(s, ReasonCode.DECOY_TOUCH, "detector", NOW, NOW.plusSeconds(600), 8);
    }

    // ---- admission: the happy path ----

    public void testAdmitApprovedEdge() {
        Decision d = admit(lease());
        assertEquals(ReasonCode.OK, d.reason());
        assertTrue(d.allowed(), "allowed");
        assertFalse(d.outsideApprovedGraph(), "approved edge");
        assertEquals(lease(), d.lease());
        assertEquals(Verdict.ALLOW, d.verdict());
        assertEquals(ReplyStatus.SUCCESS, d.replyStatus());
    }

    public void testAdmitMappedPeerAddress() {
        Peer mapped = new Peer(CLIENT, LEAF, IpAddress.parse("::ffff:10.0.1.10"));
        assertEquals(ReasonCode.OK, evaluator.admit(view(), mapped, SERVICE, token(lease())).reason());
    }

    // ---- fail closed on state ----

    public void testNotReadyWithoutFreshState() {
        assertEquals(ReasonCode.NOT_READY, evaluator.admit(EnforcementView.NOT_READY, PEER, SERVICE,
                token(lease())).reason());
        EnforcementView stale = new EnforcementView(snapshot(), false, REVISION, Set.of());
        assertEquals(ReasonCode.NOT_READY, evaluator.admit(stale, PEER, SERVICE, token(lease())).reason());
        assertEquals(ReasonCode.NOT_READY, evaluator.issue(stale, PEER, SERVICE).reason());
        assertEquals(ReplyStatus.UNAVAILABLE, evaluator.issue(stale, PEER, SERVICE).replyStatus());
    }

    public void testPausedWhileCatchingUpButQuarantineStillWins() {
        EnforcementView behind = new EnforcementView(snapshot(), true, REVISION + 1, Set.of());
        assertEquals(ReasonCode.NOT_READY, evaluator.admit(behind, PEER, SERVICE, token(lease())).reason());
        assertEquals(ReasonCode.NOT_READY, evaluator.issue(behind, PEER, SERVICE).reason());
        EnforcementView overlay = new EnforcementView(snapshot(), true, REVISION + 1, Set.of(Selector.ip(CLIENT_IP)));
        assertEquals(ReasonCode.QUARANTINED, evaluator.admit(overlay, PEER, SERVICE, token(lease())).reason());
    }

    public void testLeaseNewerThanInstalledStateIsNotReady() {
        assertEquals(ReasonCode.NOT_READY, admit(lease(NOW_MS, NOW_MS + 60_000, REVISION + 1)).reason());
        assertEquals(ReasonCode.OK, admit(lease(NOW_MS, NOW_MS + 60_000, REVISION)).reason());
    }

    // ---- token authenticity ----

    public void testRejectsGarbageAndForgedTokens() {
        assertEquals(ReasonCode.INVALID_TOKEN, evaluator.admit(view(), PEER, SERVICE, new byte[] {'x'}).reason());
        KeyPair attacker = Ed25519.generate();
        byte[] forged = LeaseCodec.issue(lease(), attacker.getPrivate());
        Decision d = evaluator.admit(view(), PEER, SERVICE, forged);
        assertEquals(ReasonCode.INVALID_TOKEN, d.reason());
        assertNull(d.lease()); // unverified claims are never reported
    }

    public void testRejectsWrongClusterAndUnknownKey() {
        Lease otherCluster = new Lease("other", KEY_ID, CLIENT, SERVICE, CLIENT_IP, LEAF, NOW_MS, NOW_MS + 1000, JTI, 5);
        assertEquals(ReasonCode.INVALID_TOKEN, admit(otherCluster).reason());
        Lease unknownKey = new Lease(CLUSTER, "lease-k9", CLIENT, SERVICE, CLIENT_IP, LEAF, NOW_MS, NOW_MS + 1000, JTI, 5);
        assertEquals(ReasonCode.INVALID_TOKEN, admit(unknownKey).reason());
    }

    public void testRevokedSigningKey() {
        revokedKeys = Set.of(KEY_ID);
        assertEquals(ReasonCode.REVOKED, admit(lease()).reason());
    }

    public void testKeyRotationOverlap() {
        KeyPair next = Ed25519.generate();
        keys.put("lease-k2", next.getPublic());
        Lease l2 = new Lease(CLUSTER, "lease-k2", CLIENT, SERVICE, CLIENT_IP, LEAF, NOW_MS, NOW_MS + 1000, JTI, 5);
        assertEquals(ReasonCode.OK, evaluator.admit(view(), PEER, SERVICE,
                LeaseCodec.issue(l2, next.getPrivate())).reason());
        assertEquals(ReasonCode.OK, admit(lease()).reason()); // old key still valid during overlap
    }

    // ---- audience and time ----

    public void testWrongAudience() {
        Decision d = evaluator.admit(view(), PEER, "db-01", token(lease()));
        assertEquals(ReasonCode.WRONG_AUDIENCE, d.reason());
        assertEquals(ReplyStatus.DENY, d.replyStatus());
    }

    public void testExpiryBoundary() {
        assertEquals(ReasonCode.OK, admit(lease(NOW_MS - 59_999, NOW_MS + 1, 5)).reason());
        assertEquals(ReasonCode.EXPIRED, admit(lease(NOW_MS - 60_000, NOW_MS, 5)).reason()); // now >= exp
        assertEquals(ReasonCode.EXPIRED, admit(lease(NOW_MS - 30_000, NOW_MS - 1, 5)).reason());
    }

    public void testFutureIssueSkew() {
        assertEquals(ReasonCode.OK, admit(lease(NOW_MS + 2_000, NOW_MS + 10_000, 5)).reason());
        assertEquals(ReasonCode.INVALID_TOKEN, admit(lease(NOW_MS + 2_001, NOW_MS + 10_000, 5)).reason());
    }

    // ---- binding to TLS peer and socket address ----

    public void testIdentityAndCertificateBinding() {
        Peer other = new Peer("web-02", LEAF, CLIENT_IP);
        workloads.put("web-02", Workload.enabled("web-02"));
        assertEquals(ReasonCode.IDENTITY_MISMATCH, evaluator.admit(view(), other, SERVICE, token(lease())).reason());
        Peer renewedCert = new Peer(CLIENT, Bytes.fromHex("22".repeat(32)), CLIENT_IP);
        assertEquals(ReasonCode.IDENTITY_MISMATCH,
                evaluator.admit(view(), renewedCert, SERVICE, token(lease())).reason());
    }

    public void testIpBinding() {
        for (String ip : new String[] {"10.0.1.11", "2001:db8::10", "::ffff:10.0.1.11"}) {
            Peer moved = new Peer(CLIENT, LEAF, IpAddress.parse(ip));
            assertEquals(ReasonCode.IP_MISMATCH, evaluator.admit(view(), moved, SERVICE, token(lease())).reason());
        }
    }

    // ---- workload status and credentials ----

    public void testDisabledOrUnknownWorkload() {
        workloads.put(CLIENT, new Workload(CLIENT, false, Set.of(), null));
        assertEquals(ReasonCode.IDENTITY_DISABLED, admit(lease()).reason());
        assertEquals(ReasonCode.IDENTITY_DISABLED, evaluator.issue(view(), PEER, SERVICE).reason());
        workloads.remove(CLIENT);
        assertEquals(ReasonCode.IDENTITY_DISABLED, admit(lease()).reason());
    }

    public void testRevokedCertificate() {
        workloads.put(CLIENT, new Workload(CLIENT, true, Set.of(LEAF), null));
        assertEquals(ReasonCode.REVOKED, admit(lease()).reason());
        assertEquals(ReasonCode.REVOKED, evaluator.issue(view(), PEER, SERVICE).reason());
    }

    public void testManagedIpZone() {
        workloads.put(CLIENT, new Workload(CLIENT, true, Set.of(), Cidr.parse("10.0.1.0/24")));
        assertEquals(ReasonCode.OK, admit(lease()).reason());
        workloads.put(CLIENT, new Workload(CLIENT, true, Set.of(), Cidr.parse("10.0.2.0/24")));
        assertEquals(ReasonCode.IP_MISMATCH, admit(lease()).reason());
    }

    // ---- quarantine and release ----

    public void testQuarantineByIdentityOrIp() {
        restrictions.add(quarantine(Selector.identity(CLIENT)));
        Decision d = admit(lease());
        assertEquals(ReasonCode.QUARANTINED, d.reason());
        assertEquals(ReplyStatus.QUARANTINED, d.replyStatus());
        assertEquals(ReasonCode.QUARANTINED, evaluator.issue(view(), PEER, SERVICE).reason());
        restrictions.clear();
        restrictions.add(quarantine(Selector.ip(CLIENT_IP)));
        assertEquals(ReasonCode.QUARANTINED, admit(lease()).reason());
        restrictions.clear();
        restrictions.add(quarantine(Selector.ip(IpAddress.parse("10.9.9.9"))));
        assertEquals(ReasonCode.OK, admit(lease()).reason()); // unrelated selector
    }

    public void testReleaseOfOneSelectorKeepsTheOther() {
        restrictions.add(quarantine(Selector.identity(CLIENT)));
        restrictions.add(quarantine(Selector.ip(CLIENT_IP)));
        restrictions.remove(0); // identity released
        watermarks.put(Selector.identity(CLIENT), REVISION);
        assertEquals(ReasonCode.QUARANTINED, admit(lease(NOW_MS, NOW_MS + 1000, REVISION)).reason());
    }

    public void testRestrictionNotLiftedByLocalClock() {
        // Restriction "expired" an hour ago by wall clock, but the snapshot still carries it: still blocked.
        restrictions.add(new Restriction(Selector.identity(CLIENT), ReasonCode.DECOY_TOUCH, "detector",
                NOW.minusSeconds(7200), NOW.minusSeconds(3600), 8));
        assertEquals(ReasonCode.QUARANTINED, admit(lease()).reason());
    }

    public void testReleaseWatermarkRejectsOldLease() {
        watermarks.put(Selector.identity(CLIENT), 9L);
        assertEquals(ReasonCode.LEASE_SUPERSEDED, admit(lease(NOW_MS, NOW_MS + 1000, 8)).reason());
        assertEquals(ReasonCode.OK, admit(lease(NOW_MS, NOW_MS + 1000, 9)).reason()); // freshly issued lease
        watermarks.clear();
        watermarks.put(Selector.ip(CLIENT_IP), 10L);
        assertEquals(ReasonCode.LEASE_SUPERSEDED, admit(lease(NOW_MS, NOW_MS + 1000, 9)).reason());
    }

    // ---- policy modes ----

    public void testUnapprovedEdgeDeniedInEnforce() {
        Peer pilot = new Peer(PILOT_CLIENT, LEAF, CLIENT_IP);
        Decision d = evaluator.issue(view(), pilot, SERVICE);
        assertEquals(ReasonCode.POLICY_DENY, d.reason());
        assertTrue(d.outsideApprovedGraph(), "denied edge is outside the graph");
        assertEquals(ReasonCode.POLICY_DENY, evaluator.issue(view(), PEER, "db-01").reason());
        assertEquals(ReasonCode.POLICY_DENY, evaluator.issue(view(), PEER, "no-such-svc").reason());
    }

    public void testLearnModeAdmitsOnlyPilotScope() {
        mode = PolicyMode.LEARN;
        Peer pilot = new Peer(PILOT_CLIENT, LEAF, CLIENT_IP);
        Decision issued = evaluator.issue(view(), pilot, SERVICE);
        assertEquals(ReasonCode.OK, issued.reason());
        assertTrue(issued.outsideApprovedGraph(), "pilot admission is a learning observation");

        Lease pl = new Lease(CLUSTER, KEY_ID, PILOT_CLIENT, SERVICE, CLIENT_IP, LEAF, NOW_MS, NOW_MS + 1000, JTI, 5);
        Decision admitted = evaluator.admit(view(), pilot, SERVICE, token(pl));
        assertEquals(ReasonCode.OK, admitted.reason());
        assertTrue(admitted.outsideApprovedGraph(), "flag carried to telemetry");

        assertEquals(ReasonCode.POLICY_DENY, evaluator.issue(view(), pilot, "db-01").reason()); // unscoped
        assertFalse(evaluator.issue(view(), PEER, SERVICE).outsideApprovedGraph(), "approved edge in LEARN");
        // LEARN keeps every other check: quarantine still wins.
        restrictions.add(quarantine(Selector.identity(PILOT_CLIENT)));
        assertEquals(ReasonCode.QUARANTINED, evaluator.issue(view(), pilot, SERVICE).reason());
    }

    // ---- issuance lease length ----

    public void testIssueLeaseLengthAndStepUp() {
        assertEquals(Duration.ofSeconds(60), evaluator.issue(view(), PEER, SERVICE).leaseLength());
        reductions.add(new LeaseReduction(Selector.ip(CLIENT_IP), Duration.ofSeconds(10), NOW.plusSeconds(300), 9));
        reductions.add(new LeaseReduction(Selector.identity(CLIENT), Duration.ofSeconds(30), NOW.plusSeconds(300), 9));
        reductions.add(new LeaseReduction(Selector.identity("other"), Duration.ofSeconds(1), NOW.plusSeconds(300), 9));
        assertEquals(Duration.ofSeconds(10), evaluator.issue(view(), PEER, SERVICE).leaseLength());
    }

    public void testStepUpDoesNotAffectExistingLease() {
        reductions.add(new LeaseReduction(Selector.identity(CLIENT), Duration.ofSeconds(10), NOW.plusSeconds(300), 9));
        assertEquals(ReasonCode.OK, admit(lease()).reason()); // the 60 s lease issued earlier still admits
    }

    // ---- live sessions ----

    public void testContinueSession() {
        Lease expired = lease(NOW_MS - 120_000, NOW_MS - 60_000, 5);
        assertEquals(ReasonCode.OK, evaluator.continueSession(view(), PEER, SERVICE, expired).reason());

        EnforcementView behind = new EnforcementView(snapshot(), true, REVISION + 1, Set.of());
        assertEquals(ReasonCode.OK, evaluator.continueSession(behind, PEER, SERVICE, lease()).reason());

        EnforcementView stale = new EnforcementView(snapshot(), false, REVISION, Set.of());
        assertEquals(ReasonCode.NOT_READY, evaluator.continueSession(stale, PEER, SERVICE, lease()).reason());

        EnforcementView overlay = new EnforcementView(snapshot(), true, REVISION + 1, Set.of(Selector.identity(CLIENT)));
        assertEquals(ReasonCode.QUARANTINED, evaluator.continueSession(overlay, PEER, SERVICE, lease()).reason());

        revokedKeys = Set.of(KEY_ID);
        assertEquals(ReasonCode.REVOKED, evaluator.continueSession(view(), PEER, SERVICE, lease()).reason());
    }

    public void testContinueSessionClosesOnPolicyRemoval() {
        mode = PolicyMode.LEARN;
        Peer pilot = new Peer(PILOT_CLIENT, LEAF, CLIENT_IP);
        assertEquals(ReasonCode.OK, evaluator.continueSession(view(), pilot, SERVICE, lease()).reason());
        mode = PolicyMode.ENFORCE; // freeze without this edge
        assertEquals(ReasonCode.POLICY_DENY, evaluator.continueSession(view(), pilot, SERVICE, lease()).reason());
    }

    public void testEvaluatorUsesInjectedClock() {
        PolicyEvaluator later = new PolicyEvaluator(Clock.fixed(NOW.plusSeconds(61), ZoneOffset.UTC));
        assertEquals(ReasonCode.EXPIRED, later.admit(view(), PEER, SERVICE, token(lease())).reason());
    }
}
