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

    /**
     * @param nextCursor pass as {@code cursor} for the next (older) page; 0 when there is none
     * @param alerts     committed detector actions and refused detector proposals, oldest first
     * @param role       the caller's own role, so a console can disable what it may not do (the server still
     *                   authorizes every call)
     * @param workloads  known workload identities, sorted (topology)
     * @param services   known service IDs, sorted (topology)
     */
    public record DashboardView(ErrorCode error, String message, long revision, long policyRevision, PolicyMode mode,
            List<RestrictionView> restrictions, List<AuditEntry> audit, long nextCursor, List<AlertView> alerts,
            Role role, List<String> workloads, List<String> services) implements Serializable {
        public DashboardView {
            restrictions = copy(restrictions);
            audit = copy(audit);
            alerts = copy(alerts);
            workloads = copy(workloads);
            services = copy(services);
        }

        public static DashboardView failure(ErrorCode code, String message) {
            return new DashboardView(code, message, -1, -1, null, List.of(), List.of(), 0, List.of(), null, List.of(),
                    List.of());
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

    /**
     * A detector alert as the control plane saw it (spec §3.1 Alert, §7.3): either a committed action
     * ({@link #COMMITTED}, with its commit {@code revision} and expiry) or a proposal the control plane refused
     * ({@code outcome} starts with {@link #REFUSED}; {@code revision} -1, {@code expiresAtMillis} 0).
     */
    public record AlertView(String id, String actor, ActionType action, List<Selector> selectors, int score,
            List<String> signals, List<String> evidence, long atMillis, long expiresAtMillis, long revision,
            String outcome) implements Serializable {
        public static final String COMMITTED = "COMMITTED";
        public static final String REFUSED = "REFUSED";

        public AlertView {
            selectors = copy(selectors);
            signals = copy(signals);
            evidence = copy(evidence);
        }

        public boolean committed() {
            return COMMITTED.equals(outcome);
        }
    }

    /**
     * Commit a reviewed learning draft (spec §3.2). {@code reviewedEdges} is the <em>complete</em> new allow-list.
     * Every edge must already be approved or be a candidate of the draft at {@code expectedDraftVersion}, and the
     * policy must still be at {@code expectedPolicyRevision}. One journaled mutation sets exactly these edges
     * and switches to ENFORCE; a stale version returns CONFLICT.
     */
    public record FreezeRequest(Credential credential, String requestId, long expectedPolicyRevision,
            long expectedDraftVersion, List<Edge> reviewedEdges, String reason) implements Serializable {
        public FreezeRequest {
            reviewedEdges = copy(reviewedEdges);
        }
    }

    public record LearningDraftRequest(Credential credential) implements Serializable {
    }

    /**
     * The learning draft for review (spec §3.2). Candidates are observations, not permissions, and the draft may
     * be incomplete: UDP loss and restarts omit observations ({@link #INCOMPLETE}).
     *
     * @param approved          the current allow-list
     * @param candidates        observed pilot admissions outside it
     * @param draftSinceMillis  when this draft started collecting (control-plane start or the last freeze)
     * @param droppedCandidates distinct candidates dropped because the draft was full
     * @param outOfScope        observations ignored because they were not pilot edges when they arrived
     */
    public record LearningDraftView(ErrorCode error, String message, long revision, long policyRevision,
            long draftVersion, PolicyMode mode, List<String> pilotSources, List<String> pilotServices,
            List<Edge> approved, List<Observation> candidates, long draftSinceMillis, long droppedCandidates,
            long outOfScope) implements Serializable {
        public static final String INCOMPLETE = "Observations may be incomplete: UDP loss, detector or control-plane"
                + " restarts and the draft size limit omit candidates. A missing edge is not evidence of no traffic.";

        public LearningDraftView {
            pilotSources = copy(pilotSources);
            pilotServices = copy(pilotServices);
            approved = copy(approved);
            candidates = copy(candidates);
        }

        public static LearningDraftView failure(ErrorCode code, String message) {
            return new LearningDraftView(code, message, -1, -1, -1, null, List.of(), List.of(), List.of(), List.of(),
                    0, 0, 0);
        }

        public boolean ok() {
            return error == null;
        }

        /** Approved edges plus every candidate: the default reviewed set, before an administrator deselects. */
        public List<Edge> proposedBaseline() {
            java.util.Set<Edge> s = new java.util.HashSet<>(approved);
            candidates.forEach(o -> s.add(o.edge()));
            return s.stream().sorted(EDGE_ORDER).toList();
        }
    }

    /** Stable display and digest order of edges. */
    public static final java.util.Comparator<Edge> EDGE_ORDER = java.util.Comparator.comparing(Edge::toString);

    private static <T> List<T> copy(List<T> list) {
        return list == null ? List.of() : List.copyOf(list);
    }
}
