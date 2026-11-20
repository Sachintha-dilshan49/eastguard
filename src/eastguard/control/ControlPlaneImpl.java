package eastguard.control;

import eastguard.common.Bytes;
import eastguard.common.Cidr;
import eastguard.common.CodecException;
import eastguard.common.Edge;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.Ids;
import eastguard.common.PilotScope;
import eastguard.common.Policy;
import eastguard.common.PolicyMode;
import eastguard.common.ReasonCode;
import eastguard.common.Restriction;
import eastguard.common.Selector;
import eastguard.common.Sha256;
import eastguard.common.SnapshotCodec;
import eastguard.common.WireWriter;
import eastguard.control.Dto.ActionProposal;
import eastguard.control.Dto.AuditEntry;
import eastguard.control.Dto.Credential;
import eastguard.control.Dto.DashboardRequest;
import eastguard.control.Dto.DashboardView;
import eastguard.control.Dto.ErrorCode;
import eastguard.control.Dto.FreezeRequest;
import eastguard.control.Dto.MutationResult;
import eastguard.control.Dto.ObservationBatch;
import eastguard.control.Dto.PolicyRequest;
import eastguard.control.Dto.PolicyView;
import eastguard.control.Dto.QuarantineRequest;
import eastguard.control.Dto.ReleaseRequest;
import eastguard.control.Dto.ReplacePolicyRequest;
import eastguard.control.Dto.RestrictionView;
import eastguard.control.Dto.SetLeaseDefaultsRequest;
import eastguard.control.Dto.SetModeRequest;
import eastguard.control.Dto.SyncRequest;
import eastguard.control.Dto.SyncResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The control plane (spec §6.2, §7.1, §7.2): the only component that commits enforcement state.
 *
 * <h2>Single writer</h2>
 * Every mutation runs under one lock: authenticate, validate, check idempotency and the expected version, build
 * the {@link Mutation}, append it to the {@link Journal} and force it, and only then publish the next immutable
 * {@link EnforcementSnapshot} with a new enforcement revision. Readers ({@link #sync}, dashboards) never take the
 * lock for state; they read the published snapshot. A journal write or force failure fences the control plane:
 * no further mutation is acknowledged and {@link #sync} answers UNAVAILABLE, so enforcement points fail closed
 * when their freshness runs out instead of trusting uncertain state.
 *
 * <h2>Idempotency</h2>
 * A request ID is scoped to the calling principal. The journal record keeps the request's digest, so after a
 * restart an identical retry still returns the original result, and reuse of the ID for a different request is
 * rejected. Rejected requests (INVALID, CONFLICT, UNAUTHORIZED) are not journaled.
 *
 * <h2>Versions</h2>
 * The enforcement revision increments on every commit. Policy edits carry the expected <em>policy</em>
 * revision, so an unrelated quarantine does not invalidate an operator's policy review; a stale expectation
 * returns CONFLICT and never overwrites. The learning-draft version is separate from both (Task 9).
 *
 * <h2>Expiry and release</h2>
 * Quarantine TTL expiry is a committed transition ({@link #expireDue}), not a timer on receivers. Release and
 * expiry write {@code minTokenRevision} watermarks, which are part of the replayed state and survive restarts.
 */
public final class ControlPlaneImpl implements ControlPlane {
    private static final Logger LOG = Logger.getLogger(ControlPlaneImpl.class.getName());
    public static final String SYSTEM_ACTOR = "control-plane";
    private static final int MAX_REASON_CHARS = 200;

    private static final Set<Role> SYNC = EnumSet.of(Role.GATEWAY, Role.ISSUER);
    private static final Set<Role> READ = EnumSet.of(Role.VIEWER, Role.OPERATOR, Role.ADMIN);
    private static final Set<Role> OPERATE = EnumSet.of(Role.OPERATOR, Role.ADMIN);
    private static final Set<Role> ADMINISTER = EnumSet.of(Role.ADMIN);
    private static final Set<Role> DETECT = EnumSet.of(Role.DETECTOR);

    /**
     * @param maxQuarantineTtl   longest TTL an operator may set
     * @param auditRetained      audit entries (and alerts) kept in memory for dashboards (the journal keeps all)
     * @param automation         rules for detector proposals
     * @param maxDraftCandidates learning-draft size; further distinct candidates are dropped and counted
     */
    public record Settings(Duration maxQuarantineTtl, int auditRetained, Automation automation, int maxDraftCandidates) {
        public Settings {
            if (maxQuarantineTtl.compareTo(Duration.ofSeconds(1)) < 0 || auditRetained < 1 || maxDraftCandidates < 1) {
                throw new IllegalArgumentException("settings out of range");
            }
            Objects.requireNonNull(automation, "automation");
        }

        public Settings(Duration maxQuarantineTtl, int auditRetained) {
            this(maxQuarantineTtl, auditRetained, Automation.disabled(), 10_000);
        }

        public static Settings defaults() {
            return new Settings(Duration.ofHours(24), 10_000);
        }

        public Settings withAutomation(Automation a) {
            return new Settings(maxQuarantineTtl, auditRetained, a, maxDraftCandidates);
        }
    }

    /**
     * Control-plane rules for detector proposals (spec §6.1 "enable automatic quarantine only for approved scopes",
     * "control-plane limits on automated action count and duration"). Both switches start off: alert-only.
     *
     * @param stepUpLease          length of newly issued leases under a lease reduction ({@code lease.stepUpSeconds})
     * @param maxActionTtl         longest expiry of an automated action
     * @param maxActionsPerHour    committed automated actions per rolling hour, across all selectors
     * @param protectedIdentities  infrastructure identities never acted on automatically
     * @param eligibleCidrs        an IP selector must be inside one of these (the approved scope) ...
     * @param excludedCidrs        ... and outside all of these (shared/NAT addresses, protected infrastructure)
     */
    public record Automation(boolean leaseReduction, boolean quarantine, Duration stepUpLease, Duration maxActionTtl,
            int maxActionsPerHour, Set<String> protectedIdentities, List<Cidr> eligibleCidrs, List<Cidr> excludedCidrs) {
        public Automation {
            Objects.requireNonNull(stepUpLease, "stepUpLease");
            Objects.requireNonNull(maxActionTtl, "maxActionTtl");
            if (stepUpLease.compareTo(Duration.ofSeconds(1)) < 0 || stepUpLease.compareTo(Policy.MAX_LEASE) > 0
                    || maxActionTtl.compareTo(Duration.ofSeconds(1)) < 0 || maxActionTtl.compareTo(Duration.ofHours(24)) > 0
                    || maxActionsPerHour < 1 || maxActionsPerHour > 10_000) {
                throw new IllegalArgumentException("automation settings out of range");
            }
            protectedIdentities = Set.copyOf(protectedIdentities);
            protectedIdentities.forEach(id -> Ids.require(id, "protected identity"));
            eligibleCidrs = List.copyOf(eligibleCidrs);
            excludedCidrs = List.copyOf(excludedCidrs);
        }

        public static Automation disabled() {
            return new Automation(false, false, Duration.ofSeconds(10), Duration.ofMinutes(5), 20, Set.of(), List.of(),
                    List.of());
        }

        boolean enabled(Dto.ActionType a) {
            return a == Dto.ActionType.QUARANTINE ? quarantine : leaseReduction;
        }

        /** Why {@code s} may not be acted on automatically, or {@code null} if it may. */
        String ineligible(Selector s, EnforcementSnapshot state) {
            if (s.type() == eastguard.common.SelectorType.IDENTITY) {
                if (!state.workloads().containsKey(s.identity())) {
                    return "unknown workload " + s.identity();
                }
                return protectedIdentities.contains(s.identity()) ? s + " is protected infrastructure" : null;
            }
            for (Cidr c : excludedCidrs) {
                if (c.contains(s.ip())) {
                    return s + " is shared or protected (" + c + ")";
                }
            }
            for (Cidr c : eligibleCidrs) {
                if (c.contains(s.ip())) {
                    return null;
                }
            }
            return s + " is outside the approved automation scope";
        }
    }

    private record Outcome(Bytes digest, long revision) {
    }

    private record Caller(String principal, Role role) {
    }

    private record Encoded(long revision, Bytes bytes) {
    }

    /** A request that is well-formed but not applicable to the current state. */
    private static final class Invalid extends Exception {
        private static final long serialVersionUID = 1L;
        final ErrorCode code;

        Invalid(String message) {
            this(ErrorCode.INVALID, message);
        }

        Invalid(ErrorCode code, String message) {
            super(message, null, false, false);
            this.code = code;
        }
    }

    @FunctionalInterface
    private interface Plan {
        Mutation plan(EnforcementSnapshot current, long now) throws Invalid;
    }

    private final Journal journal;
    private final Clock clock;
    private final Settings settings;
    private final AtomicReference<Credentials> credentials;
    private final Object writeLock = new Object();
    private final Map<String, Outcome> outcomes = new HashMap<>(); // guarded by writeLock
    private final ArrayDeque<AuditEntry> audit = new ArrayDeque<>(); // guarded by writeLock
    private final ArrayDeque<Dto.AlertView> alerts = new ArrayDeque<>(); // guarded by writeLock
    private final ArrayDeque<Long> automatedAt = new ArrayDeque<>(); // commit times of detector actions; writeLock
    private final AtomicLong unauthorized = new AtomicLong();

    // Learning draft (spec §3.1, §3.2): in memory, versioned separately from the enforcement revision, and not
    // journaled per observation. Guarded by draftLock, never by writeLock.
    private final Object draftLock = new Object();
    private final Map<Edge, Dto.Observation> draft = new java.util.LinkedHashMap<>();
    private final java.util.LinkedHashMap<String, Bytes> observationRequests = new java.util.LinkedHashMap<>(16, 0.75f,
            false) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Bytes> eldest) {
            return size() > 1_024;
        }
    };
    private long draftVersion;
    private long draftDropped;
    private long observationsOutOfScope;
    private volatile EnforcementSnapshot state;
    private volatile Encoded encoded;
    private volatile boolean failed;

    private ControlPlaneImpl(Journal journal, Clock clock, Credentials credentials, Settings settings) {
        this.journal = Objects.requireNonNull(journal, "journal");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.credentials = new AtomicReference<>(Objects.requireNonNull(credentials, "credentials"));
        this.settings = Objects.requireNonNull(settings, "settings");
    }

    /**
     * Rebuilds state and request outcomes from the journal. A record that does not decode or apply, or a
     * revision that is not exactly one more than the previous record's, fails readiness.
     */
    public static ControlPlaneImpl open(Journal journal, Clock clock, Credentials credentials, Settings settings)
            throws Journal.CorruptJournalException {
        ControlPlaneImpl cp = new ControlPlaneImpl(journal, clock, credentials, settings);
        cp.replay();
        return cp;
    }

    private void replay() throws Journal.CorruptJournalException {
        EnforcementSnapshot s = null;
        int i = 0;
        synchronized (writeLock) {
            for (byte[] payload : journal.replayed()) {
                JournalRecord r;
                try {
                    r = JournalRecord.decode(payload);
                } catch (CodecException e) {
                    throw new Journal.CorruptJournalException("journal record " + i + " cannot be decoded: " + e.getMessage());
                }
                long expected = s == null ? 1 : s.revision() + 1;
                if (r.revision() != expected) {
                    throw new Journal.CorruptJournalException("journal record " + i + " has revision " + r.revision()
                            + " but " + expected + " was expected");
                }
                EnforcementSnapshot before = s;
                try {
                    s = r.mutation().apply(before, r);
                } catch (RuntimeException e) {
                    throw new Journal.CorruptJournalException("journal record " + i + " cannot be applied: " + e.getMessage());
                }
                remember(r, before);
                i++;
            }
        }
        state = s;
        int n = i;
        EnforcementSnapshot last = s;
        LOG.info(() -> "control plane replayed " + n + " journal records" + (last == null ? "; not bootstrapped"
                : "; enforcement revision " + last.revision()));
    }

    // ---- local administration (not exposed over RMI) ----

    /** Ready to serve: bootstrapped, and the journal has not failed. */
    public boolean ready() {
        return state != null && !failed && !journal.failed();
    }

    /** The current published snapshot, or {@code null} before bootstrap. */
    public EnforcementSnapshot snapshot() {
        return state;
    }

    public long unauthorizedCalls() {
        return unauthorized.get();
    }

    public void setCredentials(Credentials c) {
        credentials.set(Objects.requireNonNull(c, "credentials"));
    }

    /**
     * Writes the initial state as revision 1 of an empty journal (spec §9.1 explicit administrator bootstrap).
     * Refuses if the journal already holds state.
     */
    public MutationResult bootstrap(EnforcementSnapshot initial, String actor, String reason) {
        Ids.require(actor, "actor");
        String bad = checkReason(reason);
        if (bad != null) {
            return failure(ErrorCode.INVALID, bad);
        }
        if (initial.revision() != 1 || initial.policy().revision() > 1) {
            return failure(ErrorCode.INVALID, "the bootstrap state must be at revision 1");
        }
        synchronized (writeLock) {
            if (state != null) {
                return failure(ErrorCode.CONFLICT, "already bootstrapped at revision " + state.revision());
            }
            if (failed || journal.failed()) {
                return failure(ErrorCode.UNAVAILABLE, "journal failed");
            }
            return commitLocked(new Caller(actor, Role.ADMIN), null, Sha256.digest(SnapshotCodec.encode(initial)),
                    reason, new Mutation.Bootstrap(initial), clock.millis());
        }
    }

    /**
     * Commits the expiry of every quarantine and lease reduction whose expiry has passed (spec §6.2 step 5), at most
     * {@link Mutation#MAX_SELECTORS} selectors per record. Returns how many entries expired. The server calls
     * this about once per second.
     */
    public int expireDue() {
        synchronized (writeLock) {
            if (!ready()) {
                return 0;
            }
            long now = clock.millis();
            List<Selector> due = new ArrayList<>();
            for (Restriction r : state.restrictions()) {
                if (r.expiry().toEpochMilli() <= now) {
                    due.add(r.selector());
                }
            }
            due.sort(Comparator.comparing(Selector::toString));
            for (int i = 0; i < due.size(); i += Mutation.MAX_SELECTORS) {
                List<Selector> chunk = due.subList(i, Math.min(due.size(), i + Mutation.MAX_SELECTORS));
                MutationResult r = commitLocked(new Caller(SYSTEM_ACTOR, Role.SYSTEM), null,
                        Sha256.digest(new byte[0]), "quarantine TTL expired", new Mutation.Release(chunk, true), now);
                if (!r.ok()) {
                    return i;
                }
            }
            List<Selector> reduced = new ArrayList<>();
            for (eastguard.common.LeaseReduction r : state.leaseReductions()) {
                if (r.expiry().toEpochMilli() <= now) {
                    reduced.add(r.selector());
                }
            }
            reduced.sort(Comparator.comparing(Selector::toString));
            for (int i = 0; i < reduced.size(); i += Mutation.MAX_SELECTORS) {
                List<Selector> chunk = reduced.subList(i, Math.min(reduced.size(), i + Mutation.MAX_SELECTORS));
                MutationResult r = commitLocked(new Caller(SYSTEM_ACTOR, Role.SYSTEM), null,
                        Sha256.digest(new byte[0]), "lease reduction expired", new Mutation.ExpireReductions(chunk), now);
                if (!r.ok()) {
                    break;
                }
            }
            return due.size() + reduced.size();
        }
    }

    // ---- RMI: reads ----

    @Override
    public SyncResponse sync(SyncRequest request) {
        return guard(() -> {
            if (authorize(request == null ? null : request.credential(), SYNC, "sync") == null) {
                return SyncResponse.failure(ErrorCode.UNAUTHORIZED, "not authorized");
            }
            EnforcementSnapshot s = state;
            if (!ready()) {
                return SyncResponse.failure(ErrorCode.UNAVAILABLE, "control plane not ready");
            }
            if (request.knownRevision() == s.revision()) {
                return new SyncResponse(null, null, s.revision(), true, null);
            }
            return new SyncResponse(null, null, s.revision(), false, encode(s));
        }, m -> SyncResponse.failure(ErrorCode.UNAVAILABLE, m));
    }

    private Bytes encode(EnforcementSnapshot s) {
        Encoded e = encoded;
        if (e == null || e.revision() != s.revision()) {
            e = new Encoded(s.revision(), Bytes.copyOf(SnapshotCodec.encode(s)));
            encoded = e;
        }
        return e.bytes();
    }

    @Override
    public DashboardView getDashboard(DashboardRequest request) {
        return guard(() -> {
            if (authorize(request == null ? null : request.credential(), READ, "getDashboard") == null) {
                return DashboardView.failure(ErrorCode.UNAUTHORIZED, "not authorized");
            }
            if (request.limit() < 1 || request.limit() > 200 || request.cursor() < 0) {
                return DashboardView.failure(ErrorCode.INVALID, "limit must be 1..200 and cursor nonnegative");
            }
            if (!ready()) {
                return DashboardView.failure(ErrorCode.UNAVAILABLE, "control plane not ready");
            }
            List<AuditEntry> page = new ArrayList<>();
            long next = 0;
            synchronized (writeLock) {
                Iterator<AuditEntry> it = audit.descendingIterator();
                while (it.hasNext()) {
                    AuditEntry e = it.next();
                    if (request.cursor() != 0 && e.revision() >= request.cursor()) {
                        continue;
                    }
                    if (page.size() == request.limit()) {
                        next = page.get(page.size() - 1).revision();
                        break;
                    }
                    page.add(e);
                }
            }
            EnforcementSnapshot s = state;
            List<RestrictionView> restrictions = new ArrayList<>();
            for (Restriction r : s.restrictions()) {
                restrictions.add(new RestrictionView(r.selector(), r.reason().name(), r.actor(),
                        r.start().toEpochMilli(), r.expiry().toEpochMilli(), r.revision()));
            }
            restrictions.sort(Comparator.comparing(v -> v.selector().toString()));
            List<Dto.AlertView> recentAlerts;
            synchronized (writeLock) {
                recentAlerts = new ArrayList<>(alerts);
            }
            if (recentAlerts.size() > request.limit()) {
                recentAlerts = recentAlerts.subList(recentAlerts.size() - request.limit(), recentAlerts.size());
            }
            return new DashboardView(null, null, s.revision(), s.policy().revision(), s.policy().mode(), restrictions,
                    page, next, recentAlerts);
        }, m -> DashboardView.failure(ErrorCode.UNAVAILABLE, m));
    }

    @Override
    public PolicyView getPolicy(PolicyRequest request) {
        return guard(() -> {
            if (authorize(request == null ? null : request.credential(), READ, "getPolicy") == null) {
                return PolicyView.failure(ErrorCode.UNAUTHORIZED, "not authorized");
            }
            if (!ready()) {
                return PolicyView.failure(ErrorCode.UNAVAILABLE, "control plane not ready");
            }
            EnforcementSnapshot s = state;
            String service = request.serviceId();
            if (service != null && (!Ids.isValid(service) || !s.services().containsKey(service))) {
                return PolicyView.failure(ErrorCode.INVALID, "unknown service");
            }
            Policy p = s.policy();
            List<Edge> edges = new ArrayList<>();
            for (Edge e : p.approvedEdges()) {
                if (service == null || e.serviceId().equals(service)) {
                    edges.add(e);
                }
            }
            edges.sort(Comparator.comparing(Edge::toString));
            List<Dto.Observation> candidates = new ArrayList<>();
            long version;
            synchronized (draftLock) {
                version = draftVersion;
                for (Dto.Observation o : draft.values()) {
                    if (service == null || o.edge().serviceId().equals(service)) {
                        candidates.add(o);
                    }
                }
            }
            candidates.sort(Comparator.comparing(o -> o.edge().toString()));
            return new PolicyView(null, null, s.revision(), p.revision(), version, p.mode(), p.defaultLeaseLength().toMillis(),
                    edges, sorted(p.pilotScope().sourceIdentities()), sorted(p.pilotScope().serviceIds()), candidates);
        }, m -> PolicyView.failure(ErrorCode.UNAVAILABLE, m));
    }

    // ---- RMI: mutations ----

    @Override
    public MutationResult quarantine(QuarantineRequest q) {
        return guard(() -> {
            if (q == null) {
                return failure(ErrorCode.INVALID, "missing request");
            }
            return mutate(q.credential(), OPERATE, "quarantine", q.requestId(), q.reason(), -1, w -> {
                w.u8(q.selectors().size());
                q.selectors().forEach(w::selector);
                w.i64(q.ttlMillis());
            }, (s, now) -> {
                List<Selector> sel = checkSelectors(q.selectors());
                if (q.ttlMillis() < 1_000 || q.ttlMillis() > settings.maxQuarantineTtl().toMillis()) {
                    throw new Invalid("ttl must be 1 s .. " + settings.maxQuarantineTtl().toSeconds() + " s");
                }
                return new Mutation.Quarantine(sel, ReasonCode.OPERATOR_ACTION, Math.addExact(now, q.ttlMillis()));
            });
        }, m -> failure(ErrorCode.UNAVAILABLE, m));
    }

    @Override
    public MutationResult release(ReleaseRequest q) {
        return guard(() -> {
            if (q == null) {
                return failure(ErrorCode.INVALID, "missing request");
            }
            return mutate(q.credential(), OPERATE, "release", q.requestId(), q.reason(), -1, w -> {
                w.u8(q.selectors().size());
                q.selectors().forEach(w::selector);
            }, (s, now) -> {
                List<Selector> sel = checkSelectors(q.selectors());
                Set<Selector> active = new HashSet<>();
                s.restrictions().forEach(r -> active.add(r.selector()));
                for (Selector x : sel) {
                    if (!active.contains(x)) {
                        throw new Invalid(x + " is not quarantined");
                    }
                }
                return new Mutation.Release(sel, false);
            });
        }, m -> failure(ErrorCode.UNAVAILABLE, m));
    }

    @Override
    public MutationResult replacePolicy(ReplacePolicyRequest q) {
        return guard(() -> {
            if (q == null) {
                return failure(ErrorCode.INVALID, "missing request");
            }
            List<Edge> sorted = new ArrayList<>(q.edges());
            sorted.sort(Comparator.comparing(Edge::toString));
            return mutate(q.credential(), ADMINISTER, "replacePolicy", q.requestId(), q.reason(),
                    q.expectedPolicyRevision(), w -> {
                        w.u16(Math.min(sorted.size(), 65_535));
                        sorted.forEach(e -> w.id(e.sourceIdentity()).id(e.serviceId()));
                    }, (s, now) -> {
                        if (q.edges().size() > Mutation.MAX_EDGES) {
                            throw new Invalid("at most " + Mutation.MAX_EDGES + " edges");
                        }
                        Set<Edge> edges = new HashSet<>(q.edges());
                        if (edges.size() != q.edges().size()) {
                            throw new Invalid("duplicate edge");
                        }
                        for (Edge e : edges) {
                            requireKnown(s, e.sourceIdentity(), e.serviceId());
                        }
                        return new Mutation.ReplacePolicy(edges);
                    });
        }, m -> failure(ErrorCode.UNAVAILABLE, m));
    }

    @Override
    public MutationResult setMode(SetModeRequest q) {
        return guard(() -> {
            if (q == null || q.mode() == null) {
                return failure(ErrorCode.INVALID, "missing request or mode");
            }
            List<String> sources = sorted(new HashSet<>(q.pilotSources()));
            List<String> services = sorted(new HashSet<>(q.pilotServices()));
            return mutate(q.credential(), ADMINISTER, "setMode", q.requestId(), q.reason(), q.expectedPolicyRevision(),
                    w -> {
                        w.u8(SnapshotCodec.modeCode(q.mode())).u16(sources.size());
                        sources.forEach(w::text);
                        w.u16(services.size());
                        services.forEach(w::text);
                    }, (s, now) -> {
                        for (String id : sources) {
                            requireKnown(s, id, null);
                        }
                        for (String id : services) {
                            requireKnown(s, null, id);
                        }
                        return new Mutation.SetMode(q.mode(), new PilotScope(Set.copyOf(sources), Set.copyOf(services)));
                    });
        }, m -> failure(ErrorCode.UNAVAILABLE, m));
    }

    @Override
    public MutationResult setLeaseDefaults(SetLeaseDefaultsRequest q) {
        return guard(() -> {
            if (q == null) {
                return failure(ErrorCode.INVALID, "missing request");
            }
            return mutate(q.credential(), ADMINISTER, "setLeaseDefaults", q.requestId(), q.reason(),
                    q.expectedPolicyRevision(), w -> w.i64(q.defaultLeaseMillis()), (s, now) -> {
                        if (q.defaultLeaseMillis() < 1_000 || q.defaultLeaseMillis() > Policy.MAX_LEASE.toMillis()) {
                            throw new Invalid("default lease must be 1..60 s");
                        }
                        return new Mutation.SetLeaseDefaults(Duration.ofMillis(q.defaultLeaseMillis()));
                    });
        }, m -> failure(ErrorCode.UNAVAILABLE, m));
    }

    /**
     * Merges a batch of learning observations into the draft (spec §3.2, §7.1). Each candidate's pilot scope is
     * rechecked against the current policy: only an unapproved edge inside the explicit pilot scope, in LEARN mode,
     * becomes a candidate; anything else is ignored and counted. The draft is not journaled per observation (spec
     * §7.2); an identical retry of a recent request ID is not counted twice. Nothing here changes enforcement.
     */
    @Override
    public MutationResult recordObservations(ObservationBatch q) {
        return guard(() -> {
            Caller caller = authorize(q == null ? null : q.credential(), DETECT, "recordObservations");
            if (caller == null) {
                return failure(ErrorCode.UNAUTHORIZED, "not authorized");
            }
            if (!Ids.isValid(q.requestId())) {
                return failure(ErrorCode.INVALID, "requestId must match [a-z0-9][a-z0-9._-]{0,63}");
            }
            List<Dto.Observation> obs = q.observations();
            if (obs.isEmpty() || obs.size() > ObservationBatch.MAX_OBSERVATIONS) {
                return failure(ErrorCode.INVALID, "1.." + ObservationBatch.MAX_OBSERVATIONS + " observations required");
            }
            long now = clock.millis();
            WireWriter w = new WireWriter().ascii("recordObservations").u16(obs.size());
            Set<Edge> seen = new HashSet<>();
            for (Dto.Observation o : obs) {
                if (o == null || o.edge() == null || o.count() < 1 || o.firstSeenMillis() < 0
                        || o.lastSeenMillis() < o.firstSeenMillis() || o.lastSeenMillis() > now + 60_000) {
                    return failure(ErrorCode.INVALID, "malformed observation");
                }
                if (!seen.add(o.edge())) {
                    return failure(ErrorCode.INVALID, "duplicate edge in batch");
                }
                w.id(o.edge().sourceIdentity()).id(o.edge().serviceId()).i64(o.firstSeenMillis())
                        .i64(o.lastSeenMillis()).i64(o.count());
            }
            Bytes digest = Sha256.digest(w.toByteArray());
            EnforcementSnapshot s = state;
            if (!ready()) {
                return failure(ErrorCode.UNAVAILABLE, "control plane not ready");
            }
            Policy p = s.policy();
            int added = 0;
            int ignored = 0;
            synchronized (draftLock) {
                String key = caller.principal() + "/" + q.requestId();
                Bytes prior = observationRequests.get(key);
                if (prior != null) {
                    return prior.equals(digest)
                            ? new MutationResult(null, "identical retry; already recorded", s.revision(), p.revision(), true)
                            : failure(ErrorCode.INVALID, "request ID " + q.requestId() + " was already used");
                }
                observationRequests.put(key, digest);
                for (Dto.Observation o : obs) {
                    if (!p.isPilotEdge(o.edge())) {
                        ignored++; // approved already, outside the pilot scope, or not in LEARN mode
                        continue;
                    }
                    Dto.Observation old = draft.get(o.edge());
                    if (old == null && draft.size() >= settings.maxDraftCandidates()) {
                        draftDropped++;
                        continue;
                    }
                    draft.put(o.edge(), old == null ? o : new Dto.Observation(o.edge(),
                            Math.min(old.firstSeenMillis(), o.firstSeenMillis()),
                            Math.max(old.lastSeenMillis(), o.lastSeenMillis()), saturatedAdd(old.count(), o.count())));
                    added++;
                }
                observationsOutOfScope += ignored;
                if (added > 0) {
                    draftVersion++;
                }
            }
            int a = added;
            int n = ignored;
            LOG.fine(() -> "observations from " + caller.principal() + ": merged=" + a + " outOfScope=" + n);
            return new MutationResult(null, "merged=" + added + " outOfScope=" + ignored, s.revision(), p.revision(), false);
        }, m -> failure(ErrorCode.UNAVAILABLE, m));
    }

    private static long saturatedAdd(long a, long b) {
        long r = a + b;
        return r < 0 ? Long.MAX_VALUE : r;
    }

    /**
     * Commits a detector proposal if the automation rules allow it (spec §6.1, §6.2): the action type is enabled,
     * the expiry is bounded, the score reaches the action's threshold, every selector is eligible (a known,
     * unprotected identity, or an IP inside the approved scope and not shared or protected), the selector is not
     * already under that action (an existing quarantine or reduction is not extended by repeated evidence), and
     * the hourly action limit is not reached. A retry with the same request ID returns the original result. The
     * committed record carries the alert: score, signals and evidence references.
     */
    @Override
    public MutationResult proposeAction(ActionProposal q) {
        return guard(() -> {
            if (q == null) {
                return failure(ErrorCode.INVALID, "missing request");
            }
            String reason = "detector " + q.action() + " score=" + q.score();
            return mutate(q.credential(), DETECT, "proposeAction", q.requestId(), reason, -1, w -> {
                w.u8(q.action().ordinal()).u8(q.selectors().size());
                q.selectors().forEach(w::selector);
                w.i64(q.ttlMillis()).i64(q.score()).u8(Math.min(q.signals().size(), 255));
                q.signals().forEach(w::text);
                w.u8(Math.min(q.evidence().size(), 255));
                q.evidence().forEach(w::text);
            }, (s, now) -> planDetectorAction(q, s, now));
        }, m -> failure(ErrorCode.UNAVAILABLE, m));
    }

    private Mutation planDetectorAction(ActionProposal q, EnforcementSnapshot s, long now) throws Invalid {
        Automation a = settings.automation();
        if (!a.enabled(q.action())) {
            throw new Invalid(ErrorCode.UNAVAILABLE, "automatic " + q.action() + " is disabled (alert-only)");
        }
        List<Selector> sel = checkSelectors(q.selectors());
        if (q.ttlMillis() < 1_000 || q.ttlMillis() > a.maxActionTtl().toMillis()) {
            throw new Invalid("ttl must be 1 s .. " + a.maxActionTtl().toSeconds() + " s");
        }
        int threshold = q.action() == Dto.ActionType.QUARANTINE ? 100 : 50;
        if (q.score() < threshold || q.score() > 1_000_000) {
            throw new Invalid(q.action() + " needs a score of at least " + threshold);
        }
        if (q.signals().isEmpty() || q.signals().size() > Mutation.DetectorAction.MAX_SIGNALS
                || q.evidence().isEmpty() || q.evidence().size() > Mutation.DetectorAction.MAX_EVIDENCE) {
            throw new Invalid("1.." + Mutation.DetectorAction.MAX_SIGNALS + " signals and 1.."
                    + Mutation.DetectorAction.MAX_EVIDENCE + " evidence references required");
        }
        for (String x : q.signals()) {
            if (!x.matches("[A-Z_]{1,32}")) {
                throw new Invalid("signals must be 1..32 characters [A-Z_]");
            }
        }
        for (String x : q.evidence()) {
            if (x.length() > Mutation.DetectorAction.MAX_REF || checkReason(x) != null) {
                throw new Invalid("evidence references must be 1..100 printable ASCII characters");
            }
        }
        for (Selector x : sel) {
            String why = a.ineligible(x, s);
            if (why != null) {
                throw new Invalid("not eligible for automation: " + why);
            }
        }
        for (Selector x : sel) {
            for (Restriction r : s.restrictions()) {
                if (r.selector().equals(x)) {
                    throw new Invalid(ErrorCode.CONFLICT, x + " is already quarantined until " + r.expiry()
                            + "; not extended");
                }
            }
            if (q.action() == Dto.ActionType.LEASE_REDUCTION) {
                for (eastguard.common.LeaseReduction r : s.leaseReductions()) {
                    if (r.selector().equals(x) && r.expiry().toEpochMilli() > now) {
                        throw new Invalid(ErrorCode.CONFLICT, x + " already has a lease reduction until " + r.expiry()
                                + "; not extended");
                    }
                }
            }
        }
        while (!automatedAt.isEmpty() && automatedAt.peekFirst() <= now - 3_600_000L) {
            automatedAt.removeFirst();
        }
        if (automatedAt.size() >= a.maxActionsPerHour()) {
            throw new Invalid(ErrorCode.UNAVAILABLE, "automated action limit reached (" + a.maxActionsPerHour()
                    + " per hour)");
        }
        long expires = Math.addExact(now, q.ttlMillis());
        return new Mutation.DetectorAction(q.action(), sel, expires,
                q.action() == Dto.ActionType.LEASE_REDUCTION ? a.stepUpLease().toMillis() : 0, q.score(), q.signals(),
                q.evidence());
    }

    /** Learning-draft counters for health and tests. */
    public record DraftStats(long version, int candidates, long dropped, long outOfScope) {
    }

    public DraftStats draftStats() {
        synchronized (draftLock) {
            return new DraftStats(draftVersion, draft.size(), draftDropped, observationsOutOfScope);
        }
    }

    /** The learning draft, sorted by edge. */
    public List<Dto.Observation> draft() {
        synchronized (draftLock) {
            List<Dto.Observation> l = new ArrayList<>(draft.values());
            l.sort(Comparator.comparing(o -> o.edge().toString()));
            return List.copyOf(l);
        }
    }

    /** Committed detector alerts, newest last. */
    public List<Dto.AlertView> alerts() {
        synchronized (writeLock) {
            return List.copyOf(alerts);
        }
    }

    @Override
    public MutationResult freezeBaseline(FreezeRequest q) {
        return notYet(q == null ? null : q.credential(), ADMINISTER, "freezeBaseline", "Task 9");
    }

    private MutationResult notYet(Credential c, Set<Role> roles, String op, String task) {
        return guard(() -> authorize(c, roles, op) == null ? failure(ErrorCode.UNAUTHORIZED, "not authorized")
                : failure(ErrorCode.UNAVAILABLE, op + " is not implemented yet (" + task + ")"),
                m -> failure(ErrorCode.UNAVAILABLE, m));
    }

    // ---- the write path ----

    private MutationResult mutate(Credential credential, Set<Role> roles, String op, String requestId, String reason,
            long expectedPolicyRevision, Consumer<WireWriter> payload, Plan plan) {
        Caller caller = authorize(credential, roles, op);
        if (caller == null) {
            return failure(ErrorCode.UNAUTHORIZED, "not authorized");
        }
        if (!Ids.isValid(requestId)) {
            return failure(ErrorCode.INVALID, "requestId must match [a-z0-9][a-z0-9._-]{0,63}");
        }
        String bad = checkReason(reason);
        if (bad != null) {
            return failure(ErrorCode.INVALID, bad);
        }
        Bytes digest;
        try {
            WireWriter w = new WireWriter().ascii(op).i64(expectedPolicyRevision).text(reason);
            payload.accept(w);
            digest = Sha256.digest(w.toByteArray());
        } catch (IllegalArgumentException | NullPointerException e) {
            return failure(ErrorCode.INVALID, "malformed request");
        }
        synchronized (writeLock) {
            if (!ready()) {
                return failure(ErrorCode.UNAVAILABLE, failed ? "journal failed; mutations stopped" : "not bootstrapped");
            }
            EnforcementSnapshot s = state;
            Outcome prior = outcomes.get(caller.principal() + "/" + requestId);
            if (prior != null) {
                if (prior.digest().equals(digest)) {
                    return new MutationResult(null, "identical retry; already committed", prior.revision(),
                            s.policy().revision(), true);
                }
                return failure(ErrorCode.INVALID, "request ID " + requestId + " was already used for a different request");
            }
            if (expectedPolicyRevision >= 0 && expectedPolicyRevision != s.policy().revision()) {
                return new MutationResult(ErrorCode.CONFLICT, "policy is at revision " + s.policy().revision()
                        + ", not " + expectedPolicyRevision + "; reload and review", s.revision(), s.policy().revision(), false);
            }
            long now = clock.millis();
            Mutation m;
            try {
                m = plan.plan(s, now);
            } catch (Invalid e) {
                LOG.info(() -> op + " by " + caller.principal() + " refused: " + e.code + " " + e.getMessage());
                return new MutationResult(e.code, e.getMessage(), s.revision(), s.policy().revision(), false);
            }
            return commitLocked(caller, requestId, digest, reason, m, now);
        }
    }

    /** Journal first (forced), then publish. Caller holds {@code writeLock}. */
    private MutationResult commitLocked(Caller c, String requestId, Bytes digest, String reason, Mutation m, long now) {
        EnforcementSnapshot before = state;
        long revision = before == null ? 1 : before.revision() + 1;
        JournalRecord r = new JournalRecord(revision, now, c.principal(), c.role(), requestId, digest, reason, m);
        EnforcementSnapshot next;
        try {
            next = m.apply(before, r);
        } catch (RuntimeException e) {
            return failure(ErrorCode.INVALID, "mutation not applicable: " + e.getMessage());
        }
        try {
            journal.append(r.encode());
        } catch (IOException | RuntimeException e) {
            failed = true;
            LOG.log(Level.SEVERE, "journal write failed: no further mutations are acknowledged and sync is "
                    + "unavailable until the control plane is restarted", e);
            return failure(ErrorCode.UNAVAILABLE, "journal write failed");
        }
        state = next;
        AuditEntry entry = remember(r, before);
        LOG.info(() -> "committed revision=" + revision + " op=" + entry.operation() + " actor=" + entry.actor()
                + " role=" + entry.role() + " requestId=" + entry.requestId() + " " + entry.detail());
        return new MutationResult(null, null, revision, next.policy().revision(), false);
    }

    /** Records the idempotency outcome and the audit entry of a committed record. Caller holds {@code writeLock}. */
    private AuditEntry remember(JournalRecord r, EnforcementSnapshot before) {
        if (r.requestId() != null) {
            outcomes.put(r.actor() + "/" + r.requestId(), new Outcome(r.requestDigest(), r.revision()));
        }
        AuditEntry e = new AuditEntry(r.revision(), r.atMillis(), r.actor(), r.role().name(),
                r.mutation().operation(), r.requestId(), describe(r.mutation(), before), r.reason(), "COMMITTED");
        audit.addLast(e);
        while (audit.size() > settings.auditRetained()) {
            audit.removeFirst();
        }
        if (r.mutation() instanceof Mutation.DetectorAction d) {
            automatedAt.addLast(r.atMillis());
            alerts.addLast(new Dto.AlertView(r.requestId(), r.actor(), d.action(), d.selectors(), d.score(), d.signals(),
                    d.evidence(), r.atMillis(), d.expiresAtMillis(), r.revision()));
            while (alerts.size() > settings.auditRetained()) {
                alerts.removeFirst();
            }
        }
        return e;
    }

    private static String describe(Mutation m, EnforcementSnapshot before) {
        String text = switch (m) {
            case Mutation.Bootstrap b -> "workloads=" + b.initial().workloads().size() + " services="
                    + b.initial().services().size() + " edges=" + b.initial().policy().approvedEdges().size()
                    + " mode=" + b.initial().policy().mode();
            case Mutation.Quarantine q -> "selectors=" + q.selectors() + " expiresAt="
                    + Instant.ofEpochMilli(q.expiresAtMillis());
            case Mutation.Release r -> "selectors=" + r.selectors();
            case Mutation.ReplacePolicy p -> {
                Set<Edge> old = before.policy().approvedEdges();
                List<String> diff = new ArrayList<>();
                p.edges().stream().filter(e -> !old.contains(e)).map(e -> "+" + e).sorted().forEach(diff::add);
                old.stream().filter(e -> !p.edges().contains(e)).map(e -> "-" + e).sorted().forEach(diff::add);
                yield "edges=" + p.edges().size() + " diff=" + diff;
            }
            case Mutation.SetMode s -> "mode=" + s.mode() + " pilotSources=" + sorted(s.pilot().sourceIdentities())
                    + " pilotServices=" + sorted(s.pilot().serviceIds());
            case Mutation.SetLeaseDefaults l -> "defaultLeaseMs=" + l.defaultLease().toMillis();
            case Mutation.DetectorAction d -> "selectors=" + d.selectors() + " score=" + d.score() + " signals="
                    + d.signals() + " expiresAt=" + Instant.ofEpochMilli(d.expiresAtMillis())
                    + (d.action() == Dto.ActionType.LEASE_REDUCTION ? " maxLeaseMs=" + d.maxLeaseMillis() : "")
                    + " evidence=" + d.evidence();
            case Mutation.ExpireReductions x -> "selectors=" + x.selectors();
        };
        return text.length() <= 500 ? text : text.substring(0, 497) + "...";
    }

    // ---- validation and helpers ----

    private Caller authorize(Credential credential, Set<Role> allowed, String op) {
        Role role = credentials.get().authenticate(credential);
        if (role == null || !allowed.contains(role)) {
            unauthorized.incrementAndGet();
            String who = credential != null && Ids.isValid(credential.principal()) ? credential.principal() : "<invalid>";
            LOG.warning(() -> "unauthorized " + op + " by principal " + who + (role == null ? " (bad credential)"
                    : " (role " + role + ")"));
            return null;
        }
        return new Caller(credential.principal(), role);
    }

    private static List<Selector> checkSelectors(List<Selector> selectors) throws Invalid {
        if (selectors.isEmpty() || selectors.size() > Mutation.MAX_SELECTORS) {
            throw new Invalid("1.." + Mutation.MAX_SELECTORS + " selectors required");
        }
        Set<Selector> unique = new LinkedHashSet<>(selectors);
        if (unique.size() != selectors.size()) {
            throw new Invalid("duplicate selector");
        }
        return List.copyOf(unique);
    }

    private static void requireKnown(EnforcementSnapshot s, String workload, String service) throws Invalid {
        if (workload != null && (!Ids.isValid(workload) || !s.workloads().containsKey(workload))) {
            throw new Invalid("unknown workload " + (Ids.isValid(workload) ? workload : "<invalid>"));
        }
        if (service != null && (!Ids.isValid(service) || !s.services().containsKey(service))) {
            throw new Invalid("unknown service " + (Ids.isValid(service) ? service : "<invalid>"));
        }
    }

    /** Audit reasons: 1..200 printable ASCII characters, so they are safe in logs. */
    static String checkReason(String reason) {
        if (reason == null || reason.isBlank() || reason.length() > MAX_REASON_CHARS) {
            return "reason must be 1.." + MAX_REASON_CHARS + " characters";
        }
        for (int i = 0; i < reason.length(); i++) {
            char c = reason.charAt(i);
            if (c < 0x20 || c > 0x7e) {
                return "reason must be printable ASCII";
            }
        }
        return null;
    }

    private static List<String> sorted(Set<String> ids) {
        List<String> l = new ArrayList<>(ids);
        l.sort(null);
        return List.copyOf(l);
    }

    private static MutationResult failure(ErrorCode code, String message) {
        return new MutationResult(code, message, -1, -1, false);
    }

    // ---- command line ----

    /**
     * <pre>
     * java -cp out eastguard.control.ControlPlaneImpl --config config/control.properties
     * java -cp out eastguard.control.ControlPlaneImpl bootstrap --config config/control.properties
     *      --state config/bootstrap.properties [--actor admin] --reason "initial deny-by-default policy"
     * </pre>
     * Serving requires a bootstrapped journal; a corrupt journal or revision gap refuses to start (exit 1).
     * Bootstrap takes the same exclusive journal lock, so it cannot run against a live control plane.
     */
    public static void main(String[] args) throws Exception {
        Map<String, String> opts = new HashMap<>();
        boolean bootstrap = args.length > 0 && args[0].equals("bootstrap");
        for (int i = bootstrap ? 1 : 0; i + 1 < args.length; i += 2) {
            if (!args[i].startsWith("--")) {
                usage();
            }
            opts.put(args[i].substring(2), args[i + 1]);
        }
        if (!opts.containsKey("config") || (bootstrap && (!opts.containsKey("state") || !opts.containsKey("reason")))) {
            usage();
        }
        ControlConfig cfg = ControlConfig.load(java.nio.file.Path.of(opts.get("config")));
        if (bootstrap) {
            EnforcementSnapshot initial = eastguard.common.BootstrapState.snapshot(
                    eastguard.common.Config.load(java.nio.file.Path.of(opts.get("state"))));
            if (!initial.clusterId().equals(cfg.clusterId())) {
                System.err.println("bootstrap state is for cluster " + initial.clusterId() + ", not " + cfg.clusterId());
                System.exit(1);
            }
            try (Journal j = Journal.open(cfg.journalFile())) {
                ControlPlaneImpl cp = open(j, Clock.systemUTC(), Credentials.of(List.of()), cfg.settings());
                MutationResult r = cp.bootstrap(initial, opts.getOrDefault("actor", "admin"), opts.get("reason"));
                System.out.println(r.ok() ? "bootstrapped " + cfg.journalFile() + " at revision " + r.revision()
                        : "bootstrap refused: " + r.error() + " " + r.message());
                System.exit(r.ok() ? 0 : 1);
            }
        }
        RmiSupport.configureJvm(cfg.rmiHost()); // before any RMI class is used
        Journal journal = Journal.open(cfg.journalFile());
        ControlPlaneImpl cp;
        try {
            cp = open(journal, Clock.systemUTC(), Credentials.load(cfg.credentialsFile()), cfg.settings());
        } catch (Journal.CorruptJournalException e) {
            System.err.println("NOT READY: " + e.getMessage() + ". Restore a verified backup or fence and re-bootstrap.");
            System.exit(1);
            return;
        }
        if (!cp.ready()) {
            System.err.println("journal " + cfg.journalFile() + " is empty: run the bootstrap command first");
            System.exit(2);
        }
        if (!cp.snapshot().clusterId().equals(cfg.clusterId())) {
            System.err.println("journal belongs to cluster " + cp.snapshot().clusterId());
            System.exit(1);
        }
        ControlServer server = ControlServer.start(cp, eastguard.tokensvc.TlsContextFactory.create(cfg.tls()),
                cfg.rmiHost(), cfg.registryPort(), cfg.objectPort(), cfg.credentialsFile());
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.close();
            try {
                journal.close();
            } catch (IOException ignored) {
                // exiting
            }
        }, "control-shutdown"));
    }

    private static void usage() {
        System.err.println("usage: ControlPlaneImpl --config <control.properties>");
        System.err.println("       ControlPlaneImpl bootstrap --config <control.properties> --state <bootstrap.properties>"
                + " [--actor admin] --reason <text>");
        System.exit(2);
    }

    /** No exception ever crosses RMI from here: unexpected failures become UNAVAILABLE. */
    private static <T> T guard(Supplier<T> body, java.util.function.Function<String, T> onError) {
        try {
            return body.get();
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "control-plane call failed", e);
            return onError.apply("internal error");
        }
    }
}
