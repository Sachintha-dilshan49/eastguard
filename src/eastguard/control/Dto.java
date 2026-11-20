package eastguard.control;

import eastguard.common.Bytes;
import eastguard.common.Edge;
import eastguard.common.PolicyMode;
import eastguard.common.Selector;
import java.io.Serializable;
import java.util.List;

/**
 * Typed RMI request and response objects (spec §7.1). Only these records, the few {@code eastguard.common} value
 * types they hold, and immutable JDK lists pass the control plane's deserialization filter ({@link RmiFilter}).
 *
 * <p>Constructors only normalise structure (null lists become empty, lists are copied). They do not reject bad
 * values, because a constructor failure during deserialization would surface as a transport error; the control
 * plane validates every field instead and answers {@link ErrorCode#INVALID}. Credentials never appear in
 * {@code toString()}.
 *
 * <p>The enforcement snapshot travels as {@link eastguard.common.SnapshotCodec} bytes, not as an object graph.
 */
public final class Dto {
    private Dto() {
    }

    /** Explicit error codes; {@code null} in a response means success. */
    public enum ErrorCode { INVALID, UNAUTHORIZED, CONFLICT, UNAVAILABLE }

    /** Per-principal API credential, sent over mTLS on every call. The secret is high-entropy random bytes. */
    public record Credential(String principal, Bytes secret) implements Serializable {
        @Override
        public String toString() {
            return "Credential[" + principal + "]";
        }
    }

    // ---- sync ----

    public record SyncRequest(Credential credential, long knownRevision) implements Serializable {
    }

    /**
     * Either the complete state ({@code snapshot} set) or, when {@code unchanged}, an exact acknowledgement that
     * {@code revision} equals the caller's {@code knownRevision}. Never a partial snapshot.
     */
    public record SyncResponse(ErrorCode error, String message, long revision, boolean unchanged, Bytes snapshot)
            implements Serializable {
        public static SyncResponse failure(ErrorCode code, String message) {
            return new SyncResponse(code, message, -1, false, null);
        }

        public boolean ok() {
            return error == null;
        }
    }

    // ---- mutations ----

    /**
     * @param revision       enforcement revision committed by this request (or by the original, on a replayed
     *                       retry); on failure the current revision, or -1 if unknown
     * @param policyRevision current policy revision, so a CONFLICT tells the caller what to reload
     * @param replayed       an identical retry of an already committed request: nothing new was committed
     */
    public record MutationResult(ErrorCode error, String message, long revision, long policyRevision, boolean replayed)
            implements Serializable {
        public boolean ok() {
            return error == null;
        }
    }

    /** Quarantine (spec §6.2): any matching selector denies. {@code ttlMillis} sets the committed expiry. */
    public record QuarantineRequest(Credential credential, String requestId, List<Selector> selectors, long ttlMillis,
            String reason) implements Serializable {
        public QuarantineRequest {
            selectors = copy(selectors);
        }
    }

    /** Release: removes the restrictions and writes {@code minTokenRevision} watermarks (spec §6.3). */
    public record ReleaseRequest(Credential credential, String requestId, List<Selector> selectors, String reason)
            implements Serializable {
        public ReleaseRequest {
            selectors = copy(selectors);
        }
    }

    /** Replaces the approved edge set, only if the policy is still at {@code expectedPolicyRevision}. */
    public record ReplacePolicyRequest(Credential credential, String requestId, long expectedPolicyRevision,
            List<Edge> edges, String reason) implements Serializable {
        public ReplacePolicyRequest {
            edges = copy(edges);
        }
    }

    public record SetModeRequest(Credential credential, String requestId, long expectedPolicyRevision, PolicyMode mode,
            List<String> pilotSources, List<String> pilotServices, String reason) implements Serializable {
        public SetModeRequest {
            pilotSources = copy(pilotSources);
            pilotServices = copy(pilotServices);
        }
    }

    /** Default length of <em>newly issued</em> leases (spec §3.2). */
    public record SetLeaseDefaultsRequest(Credential credential, String requestId, long expectedPolicyRevision,
            long defaultLeaseMillis, String reason) implements Serializable {
    }

    // ---- reads ----

    /** {@code cursor} 0 means newest; otherwise entries strictly older than that revision. */
    public record DashboardRequest(Credential credential, long cursor, int limit) implements Serializable {
    }

    /** Audit fields of spec §7.2. Never contains credentials, tokens or keys. */
    public record AuditEntry(long revision, long atMillis, String actor, String role, String operation,
            String requestId, String detail, String reason, String outcome) implements Serializable {
    }

    public record RestrictionView(Selector selector, String reason, String actor, long startMillis, long expiryMillis,
            long revision) implements Serializable {
    }

    /** @param nextCursor pass as {@code cursor} for the next (older) page; 0 when there is none */
    public record DashboardView(ErrorCode error, String message, long revision, long policyRevision, PolicyMode mode,
            List<RestrictionView> restrictions, List<AuditEntry> audit, long nextCursor, List<AlertView> alerts)
            implements Serializable {
        public DashboardView {
            restrictions = copy(restrictions);
            audit = copy(audit);
            alerts = copy(alerts);
        }

        public static DashboardView failure(ErrorCode code, String message) {
            return new DashboardView(code, message, -1, -1, null, List.of(), List.of(), 0, List.of());
        }

        public boolean ok() {
            return error == null;
        }
    }

    /** {@code serviceId} null means every service. */
    public record PolicyRequest(Credential credential, String serviceId) implements Serializable {
    }

    /**
     * @param draftVersion learning-draft version, independent of the enforcement revision (spec §3.1)
     * @param candidates   the learning draft: candidate edges with first/last seen and count (in-memory, may be
     *                     incomplete: UDP loss and control-plane restarts omit observations)
     */
    public record PolicyView(ErrorCode error, String message, long revision, long policyRevision, long draftVersion,
            PolicyMode mode, long defaultLeaseMillis, List<Edge> edges, List<String> pilotSources,
            List<String> pilotServices, List<Observation> candidates) implements Serializable {
        public PolicyView {
            edges = copy(edges);
            pilotSources = copy(pilotSources);
            pilotServices = copy(pilotServices);
            candidates = copy(candidates);
        }

        public static PolicyView failure(ErrorCode code, String message) {
            return new PolicyView(code, message, -1, -1, -1, null, 0, List.of(), List.of(), List.of(), List.of());
        }

        public boolean ok() {
            return error == null;
        }
    }

    // ---- detector (Task 7) and freeze (Task 9) ----

    /**
     * One learning observation: a successful pilot admission outside the approved graph (spec §3.2). Times are
     * the producers' event times. The control plane rechecks pilot scope; an observation never grants anything.
     */
    public record Observation(Edge edge, long firstSeenMillis, long lastSeenMillis, long count) implements Serializable {
    }

    /** Bounded batch of distinct candidate edges ({@link #MAX_OBSERVATIONS} at most). */
    public record ObservationBatch(Credential credential, String requestId, List<Observation> observations)
            implements Serializable {
        public static final int MAX_OBSERVATIONS = 500;

        public ObservationBatch {
            observations = copy(observations);
        }
    }

    /** Automated actions a detector may propose (spec §6.1). Never release. */
    public enum ActionType { LEASE_REDUCTION, QUARANTINE }

    /**
     * A detector proposal (spec §6.2): evidence references, a bounded expiry ({@code ttlMillis}) and an idempotency
     * ID ({@code requestId}, the detector's alert ID). The control plane rechecks the automation rules and limits,
     * then commits the action and records the alert, or refuses. The detector never signs or broadcasts anything.
     *
     * @param signals  contributing signal names, e.g. {@code DECOY}, {@code POLICY_DENY}
     * @param evidence telemetry references ({@code producer/boot/seq}), never payload
     */
    public record ActionProposal(Credential credential, String requestId, ActionType action, List<Selector> selectors,
            long ttlMillis, int score, List<String> signals, List<String> evidence) implements Serializable {
        public ActionProposal {
            selectors = copy(selectors);
            signals = copy(signals);
            evidence = copy(evidence);
        }
    }

    /** A committed detector action with its alert (spec §3.1 Alert, §7.3). */
    public record AlertView(String id, String actor, ActionType action, List<Selector> selectors, int score,
            List<String> signals, List<String> evidence, long atMillis, long expiresAtMillis, long revision)
            implements Serializable {
        public AlertView {
            selectors = copy(selectors);
            signals = copy(signals);
            evidence = copy(evidence);
        }
    }

    public record FreezeRequest(Credential credential, String requestId, long expectedPolicyRevision,
            long expectedDraftVersion, List<Edge> reviewedEdges, String reason) implements Serializable {
        public FreezeRequest {
            reviewedEdges = copy(reviewedEdges);
        }
    }

    private static <T> List<T> copy(List<T> list) {
        return list == null ? List.of() : List.copyOf(list);
    }
}
