package eastguard.detector;

import eastguard.common.Alert;
import eastguard.common.AlertStatus;
import eastguard.common.Endpoint;
import eastguard.common.IpAddress;
import eastguard.common.ReasonCode;
import eastguard.common.Selector;
import eastguard.common.Telemetry;
import eastguard.common.Verdict;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.LongPredicate;

/**
 * Scores verified telemetry per actor over a 10-second sliding window on monotonic receipt time (spec §6.1) and
 * decides alerts and proposals. Pure apart from injected time: no I/O. Single-threaded (the receive thread).
 *
 * <h2>Actors</h2>
 * An event is attributed to its TLS-established identity when it has one, otherwise to its canonical source IP.
 *
 * <h2>Signals</h2>
 * Each event contributes to at most one per-event signal, and separately (gateway events only) to the scan
 * signal, so it is counted once per signal:
 * <pre>
 * POLICY_DENY    +30   authenticated DENY/POLICY_DENY (gateway, or issuer for a known service)
 * SECURITY_DENY  +10   DENY for INVALID_TOKEN, WRONG_AUDIENCE, IDENTITY_MISMATCH, QUARANTINED, REVOKED,
 *                      LEASE_SUPERSEDED, IDENTITY_DISABLED or BAD_IDENTITY
 * IP_MISMATCH    +60   authenticated DENY/IP_MISMATCH (verified lease, wrong source IP)
 * DECOY          +100  connection accepted on a decoy listener
 * SCAN           +50   once while more than 10 distinct gateway endpoints were hit in the last 5 s
 * not scored           ALLOW (healthy or pilot traffic), EXPIRED, NOT_READY, BACKEND_UNAVAILABLE, THROTTLED
 * </pre>
 * Only scored gateway events (denials and decoy hits) count towards the scan signal; issuer events never do.
 *
 * <h2>Levels and actions</h2>
 * 50..99 is ALERT: propose a temporary lease reduction (if enabled). 100+ is CRITICAL: propose quarantine (if
 * enabled; otherwise a lease reduction, if that is enabled). An alert is raised when an actor's level rises.
 * A proposal is suppressed, and the alert says why, when: automation is off; the detector is still inside its
 * restart guard; input is degraded or the actor table overflowed in the last 10 s; the same action for the same
 * selector is cooling down; or the selector is not eligible (a protected identity, or an IP that is not in a
 * managed, unshared, unprotected range).
 */
public final class RiskEngine {
    public static final long WINDOW_NANOS = 10_000_000_000L;
    public static final long SCAN_WINDOW_NANOS = 5_000_000_000L;
    public static final int SCAN_ENDPOINTS = 10;
    public static final int ALERT_SCORE = 50;
    public static final int CRITICAL_SCORE = 100;
    private static final int MAX_EVIDENCE = 16;

    public enum Signal {
        POLICY_DENY(30), SECURITY_DENY(10), SCAN(50), IP_MISMATCH(60), DECOY(100);

        private final int points;

        Signal(int points) {
            this.points = points;
        }

        public int points() {
            return points;
        }
    }

    public enum Level { CLEAN, ALERT, CRITICAL }

    public enum ActionType { LEASE_REDUCTION, QUARANTINE }

    private static final Set<ReasonCode> SECURITY_DENIALS = EnumSet.of(ReasonCode.INVALID_TOKEN,
            ReasonCode.WRONG_AUDIENCE, ReasonCode.IDENTITY_MISMATCH, ReasonCode.QUARANTINED, ReasonCode.REVOKED,
            ReasonCode.LEASE_SUPERSEDED, ReasonCode.IDENTITY_DISABLED, ReasonCode.BAD_IDENTITY);

    /**
     * @param maxActors          tracked actors; beyond this new actors are dropped and automation pauses
     * @param maxEventsPerActor  scored entries kept per actor
     * @param cooldownMillis     minimum time between two proposals of the same action for the same selector
     * @param proposeLeaseReduction / proposeQuarantine   automation switches; both off is alert-only
     * @param warmupMillis       restart guard: no proposals this long after start (the acceptance window)
     * @param protectedIdentities identities never proposed for automatic action
     * @param maxAlerts          alert history kept in memory
     */
    public record Settings(int maxActors, int maxEventsPerActor, long cooldownMillis, boolean proposeLeaseReduction,
            boolean proposeQuarantine, long warmupMillis, Set<String> protectedIdentities, int maxAlerts) {
        public Settings {
            if (maxActors < 1 || maxEventsPerActor < 1 || cooldownMillis < 0 || warmupMillis < 0 || maxAlerts < 1) {
                throw new IllegalArgumentException("risk settings out of range");
            }
            protectedIdentities = Set.copyOf(protectedIdentities);
        }

        /** Alert-only defaults (spec §6.1 "start in alert-only mode"). */
        public static Settings alertOnly() {
            return new Settings(10_000, 256, 60_000, false, false, 30_000, Set.of(), 200);
        }
    }

    /** What the detector asks the control plane to commit. The control plane rechecks everything. */
    public record Proposal(ActionType type, Selector selector, int score, List<String> signals, List<String> evidence) {
        public Proposal {
            Objects.requireNonNull(type, "type");
            Objects.requireNonNull(selector, "selector");
            signals = List.copyOf(signals);
            evidence = List.copyOf(evidence);
        }
    }

    /**
     * One raised alert. {@code proposal} is null when no action is proposed; then {@code note} says why
     * (e.g. {@code alert-only}, {@code cooldown}, {@code ineligible: shared ip}).
     */
    public record Detection(Alert alert, Selector actor, Level level, CidrClassifier.Zone zone, Proposal proposal,
            String note) {
    }

    private record Scored(Signal signal, String ref) {
    }

    private record Hit(Endpoint endpoint, String ref) {
    }

    private final class ActorState {
        final SlidingWindow<Scored> scored = new SlidingWindow<>(WINDOW_NANOS, settings.maxEventsPerActor());
        final SlidingWindow<Hit> hits = new SlidingWindow<>(SCAN_WINDOW_NANOS, settings.maxEventsPerActor());
        long scanAtNanos = Long.MIN_VALUE; // last time the scan condition held
        boolean scanHolding;
        Level level = Level.CLEAN;
        String identity;
        IpAddress ip;

        boolean scanCounts(long now) {
            return scanAtNanos != Long.MIN_VALUE && now - scanAtNanos < WINDOW_NANOS;
        }

        int score(long now) {
            int s = 0;
            for (Scored e : scored.values(now)) {
                s += e.signal().points();
            }
            return scanCounts(now) ? s + Signal.SCAN.points() : s;
        }

        boolean idle(long now) {
            return scored.isEmpty(now) && hits.isEmpty(now) && !scanCounts(now);
        }
    }

    private final Settings settings;
    private final CidrClassifier cidrs;
    private final LongPredicate inputDegraded;
    private final Clock clock;
    private final long startNanos;
    private final String alertPrefix;
    private final Map<Selector, ActorState> actors = new HashMap<>();
    private final Map<String, Long> lastProposal = new HashMap<>(); // "TYPE selector" -> nanos
    private final ArrayDeque<Detection> history = new ArrayDeque<>();
    private long alertCounter;
    private long overloadedAtNanos = Long.MIN_VALUE;
    private long droppedActors;

    /**
     * @param inputDegraded is input quality degraded at this monotonic time (see {@link TelemetryVerifier#degraded})
     * @param startNanos    monotonic start time, for the restart guard
     */
    public RiskEngine(Settings settings, CidrClassifier cidrs, LongPredicate inputDegraded, Clock clock, long startNanos,
            SecureRandom random) {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.cidrs = Objects.requireNonNull(cidrs, "cidrs");
        this.inputDegraded = Objects.requireNonNull(inputDegraded, "inputDegraded");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.startNanos = startNanos;
        byte[] b = new byte[6];
        random.nextBytes(b);
        this.alertPrefix = "det-" + java.util.HexFormat.of().formatHex(b) + "-";
    }

    /** The per-event signal of a verified event, or {@code null} when it is not scored. */
    public static Signal signalOf(Telemetry t) {
        return switch (t.verdict()) {
            case ALLOW -> null;
            case DECOY -> Signal.DECOY;
            case DENY -> {
                if (t.reason() == ReasonCode.POLICY_DENY && t.sourceIdentity() != null) {
                    yield Signal.POLICY_DENY;
                }
                if (t.reason() == ReasonCode.IP_MISMATCH && t.sourceIdentity() != null) {
                    yield Signal.IP_MISMATCH;
                }
                yield SECURITY_DENIALS.contains(t.reason()) ? Signal.SECURITY_DENY : null;
            }
        };
    }

    public static Selector actorOf(Telemetry t) {
        return t.sourceIdentity() != null ? Selector.identity(t.sourceIdentity()) : Selector.ip(t.sourceIp());
    }

    /** Scores one verified event; returns the alert it raised, or {@code null}. */
    public Detection accept(TelemetryVerifier.Verified v) {
        Telemetry t = v.event();
        Signal signal = signalOf(t);
        if (signal == null) {
            return null;
        }
        long now = v.receivedNanos();
        Selector key = actorOf(t);
        ActorState a = actors.get(key);
        if (a == null) {
            if (actors.size() >= settings.maxActors()) {
                evictIdle(now);
            }
            if (actors.size() >= settings.maxActors()) {
                droppedActors++;
                overloadedAtNanos = now;
                return null;
            }
            a = new ActorState();
            actors.put(key, a);
        }
        a.identity = t.sourceIdentity();
        a.ip = t.sourceIp();
        String ref = v.ref();
        a.scored.add(now, new Scored(signal, ref));
        if (v.producerKind() == ProducerInventory.Kind.GATEWAY) {
            a.hits.add(now, new Hit(new Endpoint(t.dstIp(), t.dstPort()), ref));
            Set<Endpoint> distinct = new HashSet<>();
            a.hits.values(now).forEach(h -> distinct.add(h.endpoint()));
            if (distinct.size() > SCAN_ENDPOINTS) {
                a.scanHolding = true;
                a.scanAtNanos = now; // one +50 while the condition holds, aging out 10 s after it stops
            } else {
                a.scanHolding = false;
            }
        }
        int score = a.score(now);
        Level level = levelOf(score);
        if (level.compareTo(a.level) <= 0) {
            a.level = level;
            return null;
        }
        a.level = level;
        return raise(key, a, score, level, now);
    }

    private static Level levelOf(int score) {
        return score >= CRITICAL_SCORE ? Level.CRITICAL : score >= ALERT_SCORE ? Level.ALERT : Level.CLEAN;
    }

    private Detection raise(Selector key, ActorState a, int score, Level level, long now) {
        Set<String> signals = new LinkedHashSet<>();
        List<String> refs = new ArrayList<>();
        for (Scored e : a.scored.values(now)) {
            signals.add(e.signal().name());
            refs.add(e.ref());
        }
        if (a.scanCounts(now)) {
            signals.add(Signal.SCAN.name());
        }
        if (refs.size() > MAX_EVIDENCE) {
            refs = refs.subList(refs.size() - MAX_EVIDENCE, refs.size());
        }
        CidrClassifier.Zone zone = cidrs.classify(a.ip);
        ActionType wanted = level == Level.CRITICAL && settings.proposeQuarantine() ? ActionType.QUARANTINE
                : settings.proposeLeaseReduction() ? ActionType.LEASE_REDUCTION : null;
        String note = null;
        Proposal proposal = null;
        if (wanted == null) {
            note = "alert-only";
        } else if (now - startNanos < settings.warmupMillis() * 1_000_000L) {
            note = "suppressed: restart guard";
        } else if (inputDegraded.test(now)) {
            note = "suppressed: input degraded";
        } else if (overloadedAtNanos != Long.MIN_VALUE && now - overloadedAtNanos < WINDOW_NANOS) {
            note = "suppressed: detector overloaded";
        } else if (key.type() == eastguard.common.SelectorType.IDENTITY
                && settings.protectedIdentities().contains(key.identity())) {
            note = "ineligible: protected identity";
        } else if (key.type() == eastguard.common.SelectorType.IP && zone != CidrClassifier.Zone.MANAGED) {
            note = "ineligible: " + zone.name().toLowerCase(java.util.Locale.ROOT) + " ip";
        } else {
            String cooldownKey = wanted + " " + key;
            Long last = lastProposal.get(cooldownKey);
            if (last != null && now - last < settings.cooldownMillis() * 1_000_000L) {
                note = "suppressed: cooldown";
            } else {
                lastProposal.put(cooldownKey, now);
                proposal = new Proposal(wanted, key, score, List.copyOf(signals), refs);
            }
        }
        Alert alert = new Alert(alertPrefix + (++alertCounter), a.identity, a.ip, List.copyOf(signals), score,
                proposal == null ? AlertStatus.OPEN : AlertStatus.PROPOSED, refs, clock.instant());
        Detection d = new Detection(alert, key, level, zone, proposal, note);
        history.addLast(d);
        while (history.size() > settings.maxAlerts()) {
            history.removeFirst();
        }
        return d;
    }

    /** Current score of an actor (0 if unknown). */
    public int score(Selector actor, long nowNanos) {
        ActorState a = actors.get(actor);
        return a == null ? 0 : a.score(nowNanos);
    }

    public Level level(Selector actor, long nowNanos) {
        ActorState a = actors.get(actor);
        if (a == null) {
            return Level.CLEAN;
        }
        Level l = levelOf(a.score(nowNanos));
        if (l.compareTo(a.level) < 0) {
            a.level = l;
        }
        return a.level;
    }

    /** Housekeeping: lowers levels of actors whose evidence aged out, forgets idle actors and old cooldowns. */
    public void tick(long nowNanos) {
        evictIdle(nowNanos);
        for (ActorState a : actors.values()) {
            Level l = levelOf(a.score(nowNanos));
            if (l.compareTo(a.level) < 0) {
                a.level = l;
            }
        }
        lastProposal.values().removeIf(t -> nowNanos - t >= settings.cooldownMillis() * 1_000_000L);
    }

    private void evictIdle(long now) {
        for (Iterator<ActorState> it = actors.values().iterator(); it.hasNext();) {
            if (it.next().idle(now)) {
                it.remove();
            }
        }
    }

    public int actorCount() {
        return actors.size();
    }

    public long droppedActors() {
        return droppedActors;
    }

    /** Most recent alerts, oldest first. */
    public List<Detection> history() {
        return List.copyOf(history);
    }
}
