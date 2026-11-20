package eastguard.control;

import eastguard.common.CodecException;
import eastguard.common.Edge;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.LeaseReduction;
import eastguard.common.PilotScope;
import eastguard.common.Policy;
import eastguard.common.PolicyMode;
import eastguard.common.ReasonCode;
import eastguard.common.Restriction;
import eastguard.common.Selector;
import eastguard.common.SnapshotCodec;
import eastguard.common.WireReader;
import eastguard.common.WireWriter;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * One enforcement state change (spec §6.2, §6.3, §7.1). {@link #apply} is a pure function from the previous
 * snapshot and the committing record to the next snapshot, used both when committing and when replaying the
 * journal, so replay reproduces exactly the state that was acknowledged. Time comes from the record, never
 * from a clock.
 */
public sealed interface Mutation {
    int MAX_SELECTORS = 8;
    int MAX_EDGES = 10_000;

    /** Stable journal code. */
    int code();

    /** Operation name for audit. */
    String operation();

    void writeBody(WireWriter w);

    /** The next snapshot, at {@code r.revision()}. */
    EnforcementSnapshot apply(EnforcementSnapshot s, JournalRecord r);

    /** Revision 1: the administrator's initial deny-by-default state. */
    record Bootstrap(EnforcementSnapshot initial) implements Mutation {
        public Bootstrap {
            Objects.requireNonNull(initial, "initial");
        }

        public int code() {
            return 1;
        }

        public String operation() {
            return "BOOTSTRAP";
        }

        public void writeBody(WireWriter w) {
            byte[] b = SnapshotCodec.encode(initial);
            w.i64(b.length).raw(b);
        }

        public EnforcementSnapshot apply(EnforcementSnapshot s, JournalRecord r) {
            if (s != null || r.revision() != 1 || initial.revision() != 1) {
                throw new IllegalStateException("bootstrap must be revision 1 of an empty journal");
            }
            return initial;
        }
    }

    /** Adds or replaces a restriction per selector, with a committed expiry. */
    record Quarantine(List<Selector> selectors, ReasonCode reason, long expiresAtMillis) implements Mutation {
        public Quarantine {
            selectors = List.copyOf(selectors);
            Objects.requireNonNull(reason, "reason");
        }

        public int code() {
            return 2;
        }

        public String operation() {
            return "QUARANTINE";
        }

        public void writeBody(WireWriter w) {
            writeSelectors(w, selectors);
            w.u8(reason.code()).nonNegative(expiresAtMillis, "expiresAt");
        }

        public EnforcementSnapshot apply(EnforcementSnapshot s, JournalRecord r) {
            Map<Selector, Restriction> active = byselector(s.restrictions());
            for (Selector sel : selectors) {
                active.put(sel, new Restriction(sel, reason, r.actor(), Instant.ofEpochMilli(r.atMillis()),
                        Instant.ofEpochMilli(expiresAtMillis), r.revision()));
            }
            return with(s, r.revision(), s.policy(), new ArrayList<>(active.values()), s.releaseWatermarks());
        }
    }

    /**
     * Removes restrictions and records {@code minTokenRevision = revision} for each selector (spec §6.3): a
     * lease issued before this commit no longer admits a matching peer. {@code expired} marks the control
     * plane's own TTL transition; the effect is the same.
     */
    record Release(List<Selector> selectors, boolean expired) implements Mutation {
        public Release {
            selectors = List.copyOf(selectors);
        }

        public int code() {
            return expired ? 4 : 3;
        }

        public String operation() {
            return expired ? "EXPIRE" : "RELEASE";
        }

        public void writeBody(WireWriter w) {
            writeSelectors(w, selectors);
        }

        public EnforcementSnapshot apply(EnforcementSnapshot s, JournalRecord r) {
            Map<Selector, Restriction> active = byselector(s.restrictions());
            Map<Selector, Long> marks = new HashMap<>(s.releaseWatermarks());
            for (Selector sel : selectors) {
                active.remove(sel);
                marks.put(sel, r.revision());
            }
            return with(s, r.revision(), s.policy(), new ArrayList<>(active.values()), marks);
        }
    }

    record ReplacePolicy(Set<Edge> edges) implements Mutation {
        public ReplacePolicy {
            edges = Set.copyOf(edges);
        }

        public int code() {
            return 5;
        }

        public String operation() {
            return "REPLACE_POLICY";
        }

        public void writeBody(WireWriter w) {
            List<Edge> sorted = new ArrayList<>(edges);
            sorted.sort(Comparator.comparing(Edge::toString));
            w.u16(sorted.size());
            sorted.forEach(e -> w.id(e.sourceIdentity()).id(e.serviceId()));
        }

        public EnforcementSnapshot apply(EnforcementSnapshot s, JournalRecord r) {
            Policy p = s.policy();
            return withPolicy(s, r, new Policy(p.mode(), edges, p.pilotScope(), r.revision(), p.defaultLeaseLength()));
        }
    }

    record SetMode(PolicyMode mode, PilotScope pilot) implements Mutation {
        public SetMode {
            Objects.requireNonNull(mode, "mode");
            Objects.requireNonNull(pilot, "pilot");
        }

        public int code() {
            return 6;
        }

        public String operation() {
            return "SET_MODE";
        }

        public void writeBody(WireWriter w) {
            w.u8(SnapshotCodec.modeCode(mode));
            writeIds(w, pilot.sourceIdentities());
            writeIds(w, pilot.serviceIds());
        }

        public EnforcementSnapshot apply(EnforcementSnapshot s, JournalRecord r) {
            Policy p = s.policy();
            return withPolicy(s, r, new Policy(mode, p.approvedEdges(), pilot, r.revision(), p.defaultLeaseLength()));
        }
    }

    record SetLeaseDefaults(Duration defaultLease) implements Mutation {
        public SetLeaseDefaults {
            Objects.requireNonNull(defaultLease, "defaultLease");
        }

        public int code() {
            return 7;
        }

        public String operation() {
            return "SET_LEASE_DEFAULTS";
        }

        public void writeBody(WireWriter w) {
            w.i64(defaultLease.toMillis());
        }

        public EnforcementSnapshot apply(EnforcementSnapshot s, JournalRecord r) {
            Policy p = s.policy();
            return withPolicy(s, r, new Policy(p.mode(), p.approvedEdges(), p.pilotScope(), r.revision(), defaultLease));
        }
    }

    /**
     * A detector proposal the control plane accepted (spec §6.1, §6.2): a quarantine with reason RISK_SCORE, or a
     * lease reduction capping newly issued leases at {@code maxLeaseMillis}. Both carry a committed expiry. The
     * alert (score, signals, evidence references) is part of the same record, so it is audited and replayed with
     * the action it caused.
     */
    record DetectorAction(Dto.ActionType action, List<Selector> selectors, long expiresAtMillis, long maxLeaseMillis,
            int score, List<String> signals, List<String> evidence) implements Mutation {
        static final int MAX_SIGNALS = 8;
        static final int MAX_EVIDENCE = 32;
        static final int MAX_REF = 100;

        public DetectorAction {
            Objects.requireNonNull(action, "action");
            selectors = List.copyOf(selectors);
            signals = List.copyOf(signals);
            evidence = List.copyOf(evidence);
            if (action == Dto.ActionType.LEASE_REDUCTION) {
                if (maxLeaseMillis < 1 || maxLeaseMillis > Policy.MAX_LEASE.toMillis()) {
                    throw new IllegalArgumentException("lease reduction must be in (0, 60s]");
                }
            }
        }

        public int code() {
            return 8;
        }

        public String operation() {
            return action == Dto.ActionType.QUARANTINE ? "AUTO_QUARANTINE" : "AUTO_LEASE_REDUCTION";
        }

        public void writeBody(WireWriter w) {
            w.u8(action.ordinal());
            writeSelectors(w, selectors);
            w.nonNegative(expiresAtMillis, "expiresAt").nonNegative(maxLeaseMillis, "maxLease").nonNegative(score, "score");
            w.u8(signals.size());
            signals.forEach(w::text);
            w.u8(evidence.size());
            evidence.forEach(w::text);
        }

        public EnforcementSnapshot apply(EnforcementSnapshot s, JournalRecord r) {
            Instant start = Instant.ofEpochMilli(r.atMillis());
            Instant expiry = Instant.ofEpochMilli(expiresAtMillis);
            if (action == Dto.ActionType.QUARANTINE) {
                Map<Selector, Restriction> active = byselector(s.restrictions());
                for (Selector sel : selectors) {
                    active.put(sel, new Restriction(sel, ReasonCode.RISK_SCORE, r.actor(), start, expiry, r.revision()));
                }
                return with(s, r.revision(), s.policy(), new ArrayList<>(active.values()), s.leaseReductions(),
                        s.releaseWatermarks());
            }
            Map<Selector, LeaseReduction> reductions = new HashMap<>();
            s.leaseReductions().forEach(x -> reductions.put(x.selector(), x));
            for (Selector sel : selectors) {
                reductions.put(sel, new LeaseReduction(sel, Duration.ofMillis(maxLeaseMillis), expiry, r.revision()));
            }
            return with(s, r.revision(), s.policy(), s.restrictions(), new ArrayList<>(reductions.values()),
                    s.releaseWatermarks());
        }
    }

    /** The control plane's own transition removing lease reductions whose expiry has passed. */
    record ExpireReductions(List<Selector> selectors) implements Mutation {
        public ExpireReductions {
            selectors = List.copyOf(selectors);
        }

        public int code() {
            return 9;
        }

        public String operation() {
            return "EXPIRE_LEASE_REDUCTION";
        }

        public void writeBody(WireWriter w) {
            writeSelectors(w, selectors);
        }

        public EnforcementSnapshot apply(EnforcementSnapshot s, JournalRecord r) {
            Set<Selector> gone = new HashSet<>(selectors);
            List<LeaseReduction> kept = new ArrayList<>();
            for (LeaseReduction x : s.leaseReductions()) {
                if (!gone.contains(x.selector())) {
                    kept.add(x);
                }
            }
            return with(s, r.revision(), s.policy(), s.restrictions(), kept, s.releaseWatermarks());
        }
    }

    static Mutation readBody(int code, WireReader r) throws CodecException {
        return switch (code) {
            case 1 -> {
                long len = r.i64();
                if (len < 1 || len > SnapshotCodec.MAX_SIZE) {
                    throw new CodecException("bootstrap snapshot length out of range");
                }
                yield new Bootstrap(SnapshotCodec.decode(r.raw((int) len)));
            }
            case 2 -> {
                List<Selector> sel = readSelectors(r);
                yield new Quarantine(sel, ReasonCode.fromCode(r.u8()), r.nonNegative("expiresAt"));
            }
            case 3, 4 -> new Release(readSelectors(r), code == 4);
            case 5 -> {
                Set<Edge> edges = new HashSet<>();
                for (int i = r.count(MAX_EDGES); i > 0; i--) {
                    if (!edges.add(new Edge(r.id(), r.id()))) {
                        throw new CodecException("duplicate edge");
                    }
                }
                yield new ReplacePolicy(edges);
            }
            case 6 -> new SetMode(SnapshotCodec.mode(r.u8()), new PilotScope(readIds(r), readIds(r)));
            case 7 -> new SetLeaseDefaults(Duration.ofMillis(r.i64()));
            case 8 -> {
                int a = r.u8();
                if (a >= Dto.ActionType.values().length) {
                    throw new CodecException("unknown action");
                }
                List<Selector> sel = readSelectors(r);
                long expires = r.nonNegative("expiresAt");
                long maxLease = r.nonNegative("maxLease");
                long score = r.nonNegative("score");
                if (score > Integer.MAX_VALUE) {
                    throw new CodecException("score out of range");
                }
                List<String> signals = readTexts(r, DetectorAction.MAX_SIGNALS);
                List<String> evidence = readTexts(r, DetectorAction.MAX_EVIDENCE);
                try {
                    yield new DetectorAction(Dto.ActionType.values()[a], sel, expires, maxLease, (int) score, signals,
                            evidence);
                } catch (IllegalArgumentException e) {
                    throw new CodecException("invalid detector action");
                }
            }
            case 9 -> new ExpireReductions(readSelectors(r));
            default -> throw new CodecException("unknown mutation");
        };
    }

    private static void writeSelectors(WireWriter w, List<Selector> selectors) {
        w.u8(selectors.size());
        selectors.forEach(w::selector);
    }

    private static List<Selector> readSelectors(WireReader r) throws CodecException {
        int n = r.u8();
        if (n < 1 || n > MAX_SELECTORS) {
            throw new CodecException("selector count out of range");
        }
        Set<Selector> out = new LinkedHashSet<>();
        for (int i = 0; i < n; i++) {
            if (!out.add(r.selector())) {
                throw new CodecException("duplicate selector");
            }
        }
        return List.copyOf(out);
    }

    private static List<String> readTexts(WireReader r, int max) throws CodecException {
        int n = r.u8();
        if (n > max) {
            throw new CodecException("too many entries");
        }
        List<String> out = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            out.add(r.text(DetectorAction.MAX_REF));
        }
        return List.copyOf(out);
    }

    private static void writeIds(WireWriter w, Set<String> ids) {
        List<String> sorted = new ArrayList<>(ids);
        sorted.sort(null);
        w.u16(sorted.size());
        sorted.forEach(w::id);
    }

    private static Set<String> readIds(WireReader r) throws CodecException {
        Set<String> out = new HashSet<>();
        for (int i = r.count(MAX_EDGES); i > 0; i--) {
            if (!out.add(r.id())) {
                throw new CodecException("duplicate id");
            }
        }
        return out;
    }

    private static Map<Selector, Restriction> byselector(List<Restriction> list) {
        Map<Selector, Restriction> m = new HashMap<>();
        list.forEach(x -> m.put(x.selector(), x));
        return m;
    }

    private static EnforcementSnapshot withPolicy(EnforcementSnapshot s, JournalRecord r, Policy p) {
        return with(s, r.revision(), p, s.restrictions(), s.releaseWatermarks());
    }

    private static EnforcementSnapshot with(EnforcementSnapshot s, long revision, Policy p, List<Restriction> restrictions,
            Map<Selector, Long> watermarks) {
        return with(s, revision, p, restrictions, s.leaseReductions(), watermarks);
    }

    private static EnforcementSnapshot with(EnforcementSnapshot s, long revision, Policy p, List<Restriction> restrictions,
            List<LeaseReduction> reductions, Map<Selector, Long> watermarks) {
        return new EnforcementSnapshot(s.clusterId(), revision, p, s.workloads(), s.services(), restrictions,
                reductions, watermarks, s.tokenKeys(), s.revokedKeyIds());
    }
}
