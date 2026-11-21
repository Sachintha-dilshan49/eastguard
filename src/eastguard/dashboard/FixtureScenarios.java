package eastguard.dashboard;

import eastguard.common.Edge;
import eastguard.common.IpAddress;
import eastguard.common.PolicyMode;
import eastguard.common.Selector;
import eastguard.control.Dto;
import eastguard.control.Role;
import java.time.Clock;
import java.util.List;
import java.util.Objects;

/**
 * Demo profile data (spec §7.3 "demo controls"): a fixed set of <b>labeled fixture scenarios</b>, served through
 * the same {@link ConsoleApi} as live data so every view is exercised. Each one is shown with a "DEMO FIXTURE"
 * banner. There are no attack actions and no ingestion endpoint: fixtures are compiled in, read-only, and every
 * mutation answers UNAVAILABLE. The console reports the VIEWER role in this profile.
 */
public final class FixtureScenarios {
    public record Scenario(String label, Dto.DashboardView dashboard, Dto.LearningDraftView draft, List<Edge> denied) {
        public Scenario {
            denied = List.copyOf(denied);
        }

        @Override
        public String toString() {
            return label;
        }
    }

    static final Edge WEB_APP02 = new Edge("web-01", "app-02");
    static final Edge API_APP02 = new Edge("api-01", "app-02");
    static final Edge WEB_APP03 = new Edge("web-01", "app-03");
    static final Edge BATCH_APP03 = new Edge("batch-07", "app-03");
    static final Edge API_DB = new Edge("api-01", "db-01");

    private FixtureScenarios() {
    }

    /** The fixed scenarios, in demo order. Times are relative to {@code clock}. */
    public static List<Scenario> all(Clock clock) {
        long t = clock.millis();
        List<String> workloads = List.of("api-01", "batch-07", "web-01");
        List<String> services = List.of("app-02", "app-03", "db-01");
        Dto.LearningDraftView enforce = draft(t, 5, 0, PolicyMode.ENFORCE, List.of(WEB_APP02, WEB_APP03), List.of());

        Scenario approved = new Scenario("Fixture A: approved flow and an unapproved (denied) flow",
                dash(12, 5, PolicyMode.ENFORCE, List.of(), List.of(alert("alert-a1", t - 40_000, Dto.ActionType.QUARANTINE,
                        Selector.identity("api-01"), 30, List.of("POLICY_DENY"),
                        "REFUSED UNAVAILABLE: automatic QUARANTINE is disabled (alert-only)")), workloads, services),
                enforce, List.of(API_DB));

        Scenario learning = new Scenario("Fixture B: learning draft ready for review",
                dash(20, 9, PolicyMode.LEARN, List.of(), List.of(), workloads, services),
                draft(t, 9, 4, PolicyMode.LEARN, List.of(WEB_APP02), List.of(
                        new Dto.Observation(API_APP02, t - 3_600_000, t - 60_000, 412),
                        new Dto.Observation(WEB_APP03, t - 3_000_000, t - 5_000, 37),
                        new Dto.Observation(BATCH_APP03, t - 900_000, t - 900_000, 1))),
                List.of());

        Dto.RestrictionView q = new Dto.RestrictionView(Selector.identity("web-01"), "RISK_SCORE", "detector", t - 20_000,
                t + 280_000, 31);
        Dto.RestrictionView qip = new Dto.RestrictionView(Selector.ip(IpAddress.parse("10.0.4.17")), "OPERATOR_ACTION",
                "operator", t - 15_000, t + 3_585_000, 32);
        Scenario contained = new Scenario("Fixture C: decoy hit, web-01 quarantined (detector) and an IP (operator)",
                dash(32, 5, PolicyMode.ENFORCE, List.of(q, qip), List.of(
                        alert("alert-c0", t - 60_000, Dto.ActionType.LEASE_REDUCTION, Selector.identity("web-01"), 60,
                                List.of("POLICY_DENY", "IP_MISMATCH"), "REFUSED CONFLICT: already has a lease reduction"),
                        committed("alert-c1", t - 20_000, Selector.identity("web-01"), 130, List.of("DECOY", "POLICY_DENY"),
                                t + 280_000, 31)), workloads, services),
                enforce, List.of(new Edge("web-01", "db-01")));
        return List.of(approved, learning, contained);
    }

    /** A {@link ConsoleApi} serving the scenario {@code current} selects; read-only. */
    public static ConsoleApi api(java.util.function.Supplier<Scenario> current) {
        Objects.requireNonNull(current, "current");
        Dto.MutationResult readOnly = new Dto.MutationResult(Dto.ErrorCode.UNAVAILABLE,
                "demo profile: fixtures are read-only", -1, -1, false);
        return new ConsoleApi() {
            public Dto.DashboardView dashboard(int limit) {
                return current.get().dashboard();
            }

            public Dto.LearningDraftView learningDraft() {
                return current.get().draft();
            }

            public String fixtureLabel() {
                return "DEMO FIXTURE, not live data: " + current.get().label();
            }

            public List<Edge> deniedEdges() {
                return current.get().denied();
            }

            public Dto.MutationResult quarantine(String id, List<Selector> s, java.time.Duration ttl, String reason) {
                return readOnly;
            }

            public Dto.MutationResult release(String id, List<Selector> s, String reason) {
                return readOnly;
            }

            public Dto.MutationResult freeze(String id, long p, long d, List<Edge> e, String reason) {
                return readOnly;
            }
        };
    }

    private static Dto.DashboardView dash(long revision, long policyRevision, PolicyMode mode,
            List<Dto.RestrictionView> restrictions, List<Dto.AlertView> alerts, List<String> workloads,
            List<String> services) {
        Dto.AuditEntry e = new Dto.AuditEntry(revision, 0, "fixture", "SYSTEM", "FIXTURE", null,
                "labeled demo fixture, not live data", "demo profile", "FIXTURE");
        return new Dto.DashboardView(null, null, revision, policyRevision, mode, restrictions, List.of(e), 0, alerts,
                Role.VIEWER, workloads, services);
    }

    /** A draft that started collecting two hours before {@code now}. */
    private static Dto.LearningDraftView draft(long now, long policyRevision, long version, PolicyMode mode,
            List<Edge> approved, List<Dto.Observation> candidates) {
        boolean learn = mode == PolicyMode.LEARN;
        return new Dto.LearningDraftView(null, null, policyRevision, policyRevision, version, mode,
                learn ? List.of("api-01", "batch-07", "web-01") : List.of(), learn ? List.of("app-02", "app-03") : List.of(),
                approved, candidates, now - 7_200_000, 0, 3);
    }

    private static Dto.AlertView alert(String id, long at, Dto.ActionType action, Selector s, int score,
            List<String> signals, String outcome) {
        return new Dto.AlertView(id, "detector", action, List.of(s), score, signals, List.of("fixture/00000000/1"), at,
                0, -1, outcome);
    }

    private static Dto.AlertView committed(String id, long at, Selector s, int score, List<String> signals,
            long expires, long revision) {
        return new Dto.AlertView(id, "detector", Dto.ActionType.QUARANTINE, List.of(s), score, signals,
                List.of("fixture/00000000/2"), at, expires, revision, Dto.AlertView.COMMITTED);
    }
}
