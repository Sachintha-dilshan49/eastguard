package eastguard.tokensvc;

import eastguard.common.Bytes;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
import eastguard.common.Ids;
import eastguard.common.IpAddress;
import eastguard.common.IssuerReply;
import eastguard.common.Lease;
import eastguard.common.LeaseCodec;
import eastguard.common.Peer;
import eastguard.common.PolicyEvaluator;
import eastguard.common.ReasonCode;
import eastguard.common.ReplyStatus;
import eastguard.common.WorkloadIdentity;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Objects;
import javax.net.ssl.SSLSession;

/**
 * Decides and signs one lease request (spec §4.2 step 1). Socket-free so it can be tested directly.
 *
 * <p>Order: usable state, certificate-to-identity binding, per-identity limit, the shared
 * {@link PolicyEvaluator#issue} decision (disablement, revocation, IP zone, quarantine, policy, lease
 * reductions), and finally a check that the signing key is published and not revoked in the installed state — a
 * lease the gateways cannot verify is never handed out.
 */
public final class LeaseIssuer {
    /**
     * @param peer  authenticated peer, when identity resolution got that far (for logging)
     * @param lease the signed claims on success (for logging; never log the token itself)
     */
    public record Outcome(ReasonCode reason, IssuerReply reply, Peer peer, Lease lease) {
        public Outcome {
            Objects.requireNonNull(reason, "reason");
            Objects.requireNonNull(reply, "reply");
        }

        static Outcome deny(ReasonCode reason, Peer peer) {
            return new Outcome(reason, IssuerReply.failure(ReplyStatus.forReason(reason)), peer, null);
        }

        public boolean issued() {
            return reason == ReasonCode.OK;
        }
    }

    private final PolicyEvaluator evaluator;
    private final String keyId;
    private final PrivateKey signingKey;
    private final IssueLimiter limiter;
    private final Clock clock;
    private final SecureRandom random;

    public LeaseIssuer(PolicyEvaluator evaluator, String keyId, PrivateKey signingKey, IssueLimiter limiter,
            Clock clock, SecureRandom random) {
        this.evaluator = Objects.requireNonNull(evaluator, "evaluator");
        this.keyId = Ids.require(keyId, "keyId");
        this.signingKey = Objects.requireNonNull(signingKey, "signingKey");
        this.limiter = Objects.requireNonNull(limiter, "limiter");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
    }

    /** Request over an established mTLS session; {@code socketIp} comes from the accepted socket. */
    public Outcome issue(EnforcementView view, SSLSession session, IpAddress socketIp, String serviceId) {
        if (!view.usable()) {
            return Outcome.deny(ReasonCode.NOT_READY, null);
        }
        WorkloadIdentity.Result id = WorkloadIdentity.authenticate(session, socketIp, view.snapshot().workloads(), clock);
        if (!id.ok()) {
            return Outcome.deny(id.reason(), null);
        }
        return issue(view, id.peer(), serviceId);
    }

    /** Request from an already authenticated peer. */
    public Outcome issue(EnforcementView view, Peer peer, String serviceId) {
        if (!limiter.tryAcquire(peer.identity())) {
            return Outcome.deny(ReasonCode.THROTTLED, peer);
        }
        PolicyEvaluator.Decision d = evaluator.issue(view, peer, serviceId);
        if (!d.allowed()) {
            return Outcome.deny(d.reason(), peer);
        }
        EnforcementSnapshot s = view.snapshot();
        if (s.verificationKey(keyId) == null) {
            return Outcome.deny(ReasonCode.NOT_READY, peer);
        }
        long iat = clock.millis();
        long exp = Math.addExact(iat, d.leaseLength().toMillis());
        byte[] jti = new byte[Lease.JTI_LENGTH];
        random.nextBytes(jti);
        Lease lease = new Lease(s.clusterId(), keyId, peer.identity(), serviceId, peer.ip(), peer.leafSha256(),
                iat, exp, Bytes.copyOf(jti), s.revision());
        return new Outcome(ReasonCode.OK, IssuerReply.success(LeaseCodec.issue(lease, signingKey)), peer, lease);
    }
}
