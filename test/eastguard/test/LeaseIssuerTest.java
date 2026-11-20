package eastguard.test;

import static eastguard.test.Assert.*;
import static eastguard.test.Fixtures.*;

import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
import eastguard.common.Lease;
import eastguard.common.LeaseCodec;
import eastguard.common.LeaseReduction;
import eastguard.common.Peer;
import eastguard.common.PilotScope;
import eastguard.common.Policy;
import eastguard.common.PolicyEvaluator;
import eastguard.common.PolicyMode;
import eastguard.common.ReasonCode;
import eastguard.common.ReplyStatus;
import eastguard.common.Restriction;
import eastguard.common.Selector;
import eastguard.common.Service;
import eastguard.common.SignedLease;
import eastguard.common.Workload;
import eastguard.tokensvc.IssueLimiter;
import eastguard.tokensvc.LeaseIssuer;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/** {@link LeaseIssuer} and {@link IssueLimiter} with a fixed clock and the deterministic test signing key. */
public final class LeaseIssuerTest {
    private static final long REVISION = 7;
    private static final Peer PEER = new Peer(CLIENT, LEAF, CLIENT_IP);

    private final AtomicLong nanos = new AtomicLong(1_000);
    private final PolicyEvaluator evaluator = new PolicyEvaluator(CLOCK);

    private LeaseIssuer issuer(int perSecond) {
        return new LeaseIssuer(evaluator, KEY_ID, LEASE_KEYS.getPrivate(), LEASE_KEYS.getPublic(), new IssueLimiter(perSecond, nanos::get),
                CLOCK, new SecureRandom());
    }

    private static EnforcementSnapshot snapshot(List<Restriction> restrictions, List<LeaseReduction> reductions,
            Map<String, PublicKey> keys, Set<String> revokedKeys) {
        Service app = new Service(SERVICE, SERVICE, Endpoint.parse("127.0.0.1:9002"), "127.0.0.1",
                Endpoint.parse("127.0.0.1:7002"));
        Policy policy = new Policy(PolicyMode.ENFORCE, Set.of(new Edge(CLIENT, SERVICE)), PilotScope.NONE, 3,
                Duration.ofSeconds(60));
        return new EnforcementSnapshot(CLUSTER, REVISION, policy,
                Map.of(CLIENT, Workload.enabled(CLIENT), "api-01", Workload.enabled("api-01")),
                Map.of(SERVICE, app), restrictions, reductions, Map.of(), keys, revokedKeys);
    }

    private static EnforcementView view() {
        return EnforcementView.fresh(snapshot(List.of(), List.of(), Map.of(KEY_ID, LEASE_KEYS.getPublic()), Set.of()));
    }

    public void testIssuesSignedLeaseBoundToPeer() throws Exception {
        LeaseIssuer.Outcome o = issuer(10).issue(view(), PEER, SERVICE);
        assertTrue(o.issued(), "should issue: " + o.reason());
        assertEquals(ReplyStatus.SUCCESS, o.reply().status());
        SignedLease signed = LeaseCodec.parse(o.reply().token().toArray());
        assertTrue(signed.verify(LEASE_KEYS.getPublic()), "signature verifies");
        Lease l = signed.lease();
        assertEquals(CLUSTER, l.cluster());
        assertEquals(KEY_ID, l.keyId());
        assertEquals(CLIENT, l.subject());
        assertEquals(SERVICE, l.audience());
        assertEquals(CLIENT_IP, l.sourceIp());
        assertEquals(LEAF, l.leafSha256());
        assertEquals(NOW_MS, l.issuedAtMs());
        assertEquals(NOW_MS + 60_000, l.expiresAtMs());
        assertEquals(REVISION, l.issuedAtRevision());
        assertEquals(l, o.lease());
        // The gateway's evaluator accepts what the issuer signed.
        assertTrue(evaluator.admit(view(), PEER, SERVICE, o.reply().token().toArray()).allowed(), "admitted");
    }

    public void testNoLeaseUnlessTheStatePublishesOurOwnKey() {
        // Same key ID, different key: gateways would reject every lease, so the issuer refuses to sign.
        LeaseIssuer mismatched = new LeaseIssuer(evaluator, KEY_ID, LEASE_KEYS.getPrivate(),
                eastguard.common.Ed25519.generate().getPublic(), new IssueLimiter(10, nanos::get), CLOCK,
                new SecureRandom());
        assertEquals(ReasonCode.NOT_READY, mismatched.issue(view(), PEER, SERVICE).reason());
        // Our key not published at all.
        EnforcementView unpublished = EnforcementView.fresh(snapshot(List.of(), List.of(), Map.of(), Set.of()));
        assertEquals(ReasonCode.NOT_READY, issuer(10).issue(unpublished, PEER, SERVICE).reason());
        assertEquals(ReasonCode.OK, issuer(10).issue(view(), PEER, SERVICE).reason());
    }

    public void testJtiIsRandomPerLease() throws Exception {
        LeaseIssuer is = issuer(10);
        Lease a = is.issue(view(), PEER, SERVICE).lease();
        Lease b = is.issue(view(), PEER, SERVICE).lease();
        assertFalse(a.jti().equals(b.jti()), "jti must differ");
    }

    public void testDenialsCarryNoToken() {
        LeaseIssuer.Outcome unknownService = issuer(10).issue(view(), PEER, "db-09");
        assertEquals(ReasonCode.POLICY_DENY, unknownService.reason());
        assertEquals(ReplyStatus.DENY, unknownService.reply().status());
        assertEquals(0, unknownService.reply().token().length());
        assertNull(unknownService.lease());

        LeaseIssuer.Outcome noEdge = issuer(10).issue(view(), new Peer("api-01", LEAF, CLIENT_IP), SERVICE);
        assertEquals(ReasonCode.POLICY_DENY, noEdge.reason());
    }

    public void testQuarantineAndStaleState() {
        Restriction q = new Restriction(Selector.identity(CLIENT), ReasonCode.OPERATOR_ACTION, "operator", NOW,
                NOW.plusSeconds(300), REVISION);
        var quarantined = EnforcementView.fresh(snapshot(List.of(q), List.of(), Map.of(KEY_ID, LEASE_KEYS.getPublic()),
                Set.of()));
        assertEquals(ReplyStatus.QUARANTINED, issuer(10).issue(quarantined, PEER, SERVICE).reply().status());
        assertEquals(ReplyStatus.UNAVAILABLE, issuer(10).issue(EnforcementView.NOT_READY, PEER, SERVICE).reply().status());
        var stale = new EnforcementView(view().snapshot(), false, REVISION, Set.of());
        assertEquals(ReasonCode.NOT_READY, issuer(10).issue(stale, PEER, SERVICE).reason());
    }

    public void testLeaseReductionShortensNewLeases() {
        var reduced = EnforcementView.fresh(snapshot(List.of(),
                List.of(new LeaseReduction(Selector.identity(CLIENT), Duration.ofSeconds(10), NOW.plusSeconds(300), 6)),
                Map.of(KEY_ID, LEASE_KEYS.getPublic()), Set.of()));
        Lease l = issuer(10).issue(reduced, PEER, SERVICE).lease();
        assertEquals(10_000, l.expiresAtMs() - l.issuedAtMs());
    }

    public void testUnpublishedOrRevokedSigningKeyRefusesToIssue() {
        var unpublished = EnforcementView.fresh(snapshot(List.of(), List.of(), Map.of(), Set.of()));
        LeaseIssuer.Outcome o = issuer(10).issue(unpublished, PEER, SERVICE);
        assertEquals(ReasonCode.NOT_READY, o.reason());
        assertEquals(ReplyStatus.UNAVAILABLE, o.reply().status());
        var revoked = EnforcementView.fresh(snapshot(List.of(), List.of(), Map.of(KEY_ID, LEASE_KEYS.getPublic()),
                Set.of(KEY_ID)));
        assertEquals(ReasonCode.NOT_READY, issuer(10).issue(revoked, PEER, SERVICE).reason());
    }

    public void testPerIdentityLimit() {
        LeaseIssuer is = issuer(2);
        assertTrue(is.issue(view(), PEER, SERVICE).issued(), "1st");
        assertTrue(is.issue(view(), PEER, SERVICE).issued(), "2nd");
        LeaseIssuer.Outcome third = is.issue(view(), PEER, SERVICE);
        assertEquals(ReasonCode.THROTTLED, third.reason());
        assertEquals(ReplyStatus.UNAVAILABLE, third.reply().status());
        // Another identity has its own budget (denied by policy, but not throttled).
        assertEquals(ReasonCode.POLICY_DENY, is.issue(view(), new Peer("api-01", LEAF, CLIENT_IP), SERVICE).reason());
        nanos.addAndGet(1_000_000_000L);
        assertTrue(is.issue(view(), PEER, SERVICE).issued(), "new window");
    }

    public void testLimiterRejectsInsteadOfGrowingUnbounded() {
        IssueLimiter limiter = new IssueLimiter(1, nanos::get);
        for (int i = 0; i < 10_000; i++) {
            assertTrue(limiter.tryAcquire("w" + i), "within cap");
        }
        assertFalse(limiter.tryAcquire("one-too-many"), "cap reached inside the window");
        nanos.addAndGet(1_000_000_000L);
        assertTrue(limiter.tryAcquire("one-too-many"), "stale windows evicted");
    }
}
