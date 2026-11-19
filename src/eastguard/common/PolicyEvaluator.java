package eastguard.common;

import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/**
 * The one authorization function shared by the token service and every gateway (spec §3.2, §4.2, §6).
 * Pure apart from the injected {@link Clock}: no I/O, no logging, no mutable state. Default deny; any
 * missing, stale, or inconsistent input denies.
 *
 * <p>The issuer's decision never substitutes for the gateway's: {@link #admit} re-evaluates everything.
 */
public final class PolicyEvaluator {
    /** Maximum allowed future skew of a lease's issue time (spec §5.2). */
    public static final long MAX_ISSUE_SKEW_MS = 2_000;

    /**
     * @param outsideApprovedGraph the edge is not approved (telemetry flag bit 0); true for pilot admissions
     *                             and for policy denials
     * @param leaseLength          for a successful {@link #issue} only: the lifetime to sign
     * @param lease                for {@link #admit}: the verified lease, when verification got that far
     */
    public record Decision(ReasonCode reason, boolean outsideApprovedGraph, Duration leaseLength, Lease lease) {
        public Decision {
            Objects.requireNonNull(reason, "reason");
        }

        static Decision deny(ReasonCode reason) {
            return new Decision(reason, false, null, null);
        }

        public boolean allowed() {
            return reason == ReasonCode.OK;
        }

        public Verdict verdict() {
            return allowed() ? Verdict.ALLOW : Verdict.DENY;
        }

        public ReplyStatus replyStatus() {
            return ReplyStatus.forReason(reason);
        }

        Decision withLease(Lease l) {
            return new Decision(reason, outsideApprovedGraph, leaseLength, l);
        }
    }

    private final Clock clock;

    public PolicyEvaluator(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Token service: may {@code peer} get a new lease for {@code serviceId}, and for how long? */
    public Decision issue(EnforcementView view, Peer peer, String serviceId) {
        if (!view.usable()) {
            return Decision.deny(ReasonCode.NOT_READY);
        }
        Decision d = authorize(view, peer, serviceId, true);
        if (!d.allowed()) {
            return d;
        }
        EnforcementSnapshot s = view.snapshot();
        Duration length = s.policy().defaultLeaseLength();
        for (LeaseReduction r : s.leaseReductions()) {
            if (r.selector().matches(peer.identity(), peer.ip()) && r.maxLease().compareTo(length) < 0) {
                length = r.maxLease();
            }
        }
        return new Decision(ReasonCode.OK, d.outsideApprovedGraph(), length, null);
    }

    /** Gateway: admit a new connection presenting {@code token}. Also used for the recheck on finishConnect. */
    public Decision admit(EnforcementView view, Peer peer, String serviceId, byte[] token) {
        if (!view.usable()) {
            return Decision.deny(ReasonCode.NOT_READY);
        }
        SignedLease signed;
        try {
            signed = LeaseCodec.parse(token);
        } catch (CodecException e) {
            return Decision.deny(ReasonCode.INVALID_TOKEN);
        }
        return admit(view, peer, serviceId, signed);
    }

    /** As {@link #admit(EnforcementView, Peer, String, byte[])} for an already parsed (unverified) token. */
    public Decision admit(EnforcementView view, Peer peer, String serviceId, SignedLease signed) {
        if (!view.usable()) {
            return Decision.deny(ReasonCode.NOT_READY);
        }
        EnforcementSnapshot s = view.snapshot();
        Lease l = signed.lease();

        // 1. Authenticity: cluster, trusted key, signature.
        if (!l.cluster().equals(s.clusterId())) {
            return Decision.deny(ReasonCode.INVALID_TOKEN);
        }
        if (s.revokedKeyIds().contains(l.keyId())) {
            return Decision.deny(ReasonCode.REVOKED);
        }
        PublicKey key = s.verificationKey(l.keyId());
        if (key == null || !signed.verify(key)) {
            return Decision.deny(ReasonCode.INVALID_TOKEN);
        }
        // From here on the claims are trusted, so the lease can be reported with the decision.

        // 2. Audience and time.
        if (!l.audience().equals(serviceId)) {
            return Decision.deny(ReasonCode.WRONG_AUDIENCE).withLease(l);
        }
        long now = clock.millis();
        if (l.issuedAtMs() - MAX_ISSUE_SKEW_MS > now) { // iat >= 0, so this cannot overflow
            return Decision.deny(ReasonCode.INVALID_TOKEN).withLease(l);
        }
        if (now >= l.expiresAtMs()) {
            return Decision.deny(ReasonCode.EXPIRED).withLease(l);
        }

        // 3. Binding to the TLS peer and the socket address.
        if (!l.subject().equals(peer.identity()) || !l.leafSha256().equals(peer.leafSha256())) {
            return Decision.deny(ReasonCode.IDENTITY_MISMATCH).withLease(l);
        }
        if (!l.sourceIp().equals(peer.ip())) {
            return Decision.deny(ReasonCode.IP_MISMATCH).withLease(l);
        }

        // 4. Never grant on state older than the lease.
        if (l.issuedAtRevision() > s.revision()) {
            return Decision.deny(ReasonCode.NOT_READY).withLease(l);
        }

        // 5. Current authorization, then the release watermark.
        Decision d = authorize(view, peer, serviceId, true);
        if (!d.allowed()) {
            return d.withLease(l);
        }
        if (l.issuedAtRevision() < watermark(s, peer)) {
            return Decision.deny(ReasonCode.LEASE_SUPERSEDED).withLease(l);
        }
        return d.withLease(l);
    }

    /**
     * Gateway sweep of a live, already admitted session. Lease expiry does not end a session (sessions have
     * their own idle/absolute limits), but stale state, key revocation, quarantine, disablement, and policy
     * removal do. Catching up to a newer notice does not by itself close an unrelated session (spec §6.2).
     */
    public Decision continueSession(EnforcementView view, Peer peer, String serviceId, Lease lease) {
        if (!view.usable()) {
            return Decision.deny(ReasonCode.NOT_READY);
        }
        if (view.snapshot().revokedKeyIds().contains(lease.keyId())) {
            return Decision.deny(ReasonCode.REVOKED).withLease(lease);
        }
        return authorize(view, peer, serviceId, false).withLease(lease);
    }

    /** Shared checks for issuance, admission, and live sessions. Caller has checked {@code view.usable()}. */
    private static Decision authorize(EnforcementView view, Peer peer, String serviceId,
            boolean pauseWhileCatchingUp) {
        EnforcementSnapshot s = view.snapshot();

        Workload w = s.workloads().get(peer.identity());
        if (w == null || !w.enabled()) {
            return Decision.deny(ReasonCode.IDENTITY_DISABLED);
        }
        if (w.isCertificateRevoked(peer.leafSha256())) {
            return Decision.deny(ReasonCode.REVOKED);
        }
        if (!w.allowsIp(peer.ip())) {
            return Decision.deny(ReasonCode.IP_MISMATCH);
        }

        // Any matching active selector denies; identity and IP are independent.
        for (Selector sel : view.overlay()) {
            if (sel.matches(peer.identity(), peer.ip())) {
                return Decision.deny(ReasonCode.QUARANTINED);
            }
        }
        for (Restriction r : s.restrictions()) {
            if (r.selector().matches(peer.identity(), peer.ip())) {
                return Decision.deny(ReasonCode.QUARANTINED);
            }
        }
        if (pauseWhileCatchingUp && view.catchingUp()) {
            return Decision.deny(ReasonCode.NOT_READY);
        }

        if (!s.services().containsKey(serviceId)) {
            return Decision.deny(ReasonCode.POLICY_DENY);
        }
        Edge edge = new Edge(peer.identity(), serviceId);
        Policy p = s.policy();
        if (p.isApproved(edge)) {
            return new Decision(ReasonCode.OK, false, null, null);
        }
        if (p.isPilotEdge(edge)) {
            return new Decision(ReasonCode.OK, true, null, null);
        }
        return new Decision(ReasonCode.POLICY_DENY, true, null, null);
    }

    /** Highest release watermark of any selector matching the peer; 0 if none. */
    private static long watermark(EnforcementSnapshot s, Peer peer) {
        long max = 0;
        for (var e : s.releaseWatermarks().entrySet()) {
            if (e.getKey().matches(peer.identity(), peer.ip()) && e.getValue() > max) {
                max = e.getValue();
            }
        }
        return max;
    }
}
