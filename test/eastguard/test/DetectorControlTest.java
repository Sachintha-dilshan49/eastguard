package eastguard.test;

import static eastguard.test.Assert.assertEquals;
import static eastguard.test.Assert.assertFalse;
import static eastguard.test.Assert.assertNull;
import static eastguard.test.Assert.assertTrue;

import eastguard.common.Bytes;
import eastguard.common.Cidr;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
import eastguard.common.IpAddress;
import eastguard.common.LeaseReduction;
import eastguard.common.Peer;
import eastguard.common.PilotScope;
import eastguard.common.Policy;
import eastguard.common.PolicyEvaluator;
import eastguard.common.PolicyMode;
import eastguard.common.ReasonCode;
import eastguard.common.Restriction;
import eastguard.common.Selector;
import eastguard.common.Service;
import eastguard.common.Workload;
import eastguard.control.ControlPlaneImpl;
import eastguard.control.Dto;
import eastguard.control.Dto.ActionType;
import eastguard.control.Dto.ErrorCode;
import eastguard.control.Dto.MutationResult;
import eastguard.control.Journal;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Control-plane side of the detector (spec §3.2, §6.1, §6.2, §7.1): learning observations and proposals. */
public final class DetectorControlTest {
    private static final java.util.logging.Logger QUIET = java.util.logging.Logger.getLogger("eastguard.control");
    static final Selector WEB = Selector.identity("web-01");
    static final Selector API = Selector.identity("api-01");
    static final Edge API_APP02 = new Edge("api-01", "app-02");
    static final Edge API_APP03 = new Edge("api-01", "app-03");
    static final Edge WEB_APP02 = new Edge("web-01", "app-02");
    static final Edge WEB_APP03 = new Edge("web-01", "app-03");

    private final ControlFixtures fx = new ControlFixtures();
    private final Path file;

    public DetectorControlTest() throws Exception {
        QUIET.setLevel(java.util.logging.Level.SEVERE);
        file = ControlFixtures.freshJournal();
    }

    static ControlPlaneImpl.Automation automation(int perHour) {
        return new ControlPlaneImpl.Automation(true, true, Duration.ofSeconds(10), Duration.ofMinutes(5), perHour,
                Set.of("gw-infra"), List.of(Cidr.parse("10.0.0.0/8")), List.of(Cidr.parse("10.0.99.0/24")));
    }

    /** LEARN mode: pilot covers api-01 -> app-02 only; web-01 -> app-02 is approved; app-03 is outside the pilot. */
    static EnforcementSnapshot learning() {
        Service app02 = new Service("app-02", "app-02", Endpoint.parse("127.0.0.1:9002"), "127.0.0.1",
                Endpoint.parse("127.0.0.1:7002"));
        Service app03 = new Service("app-03", "app-03", Endpoint.parse("127.0.0.1:9004"), "127.0.0.1",
                Endpoint.parse("127.0.0.1:7004"));
        Policy policy = new Policy(PolicyMode.LEARN, Set.of(WEB_APP02), new PilotScope(Set.of("api-01"),
                Set.of("app-02")), 1, Duration.ofSeconds(60));
        return new EnforcementSnapshot("eg-test", 1, policy, Map.of("web-01", Workload.enabled("web-01"), "api-01",
                Workload.enabled("api-01"), "gw-infra", Workload.enabled("gw-infra")),
                Map.of("app-02", app02, "app-03", app03), List.of(), List.of(), Map.of(),
                Map.of("lease-k1", Fixtures.LEASE_KEYS.getPublic()), Set.of());
    }

    private ControlPlaneImpl open(Journal j, ControlPlaneImpl.Automation a) throws Exception {
        return ControlPlaneImpl.open(j, fx.clock, fx.credentials, ControlPlaneImpl.Settings.defaults().withAutomation(a));
    }

    private ControlPlaneImpl bootstrapped(Journal j, ControlPlaneImpl.Automation a) throws Exception {
        ControlPlaneImpl cp = open(j, a);
        assertTrue(cp.bootstrap(learning(), "admin", "test state").ok(), "bootstrap");
        return cp;
    }

    private Dto.ActionProposal propose(String id, ActionType type, long ttl, int score, Selector... sel) {
        return new Dto.ActionProposal(fx.cred("detector"), id, type, List.of(sel), ttl, score,
                List.of("POLICY_DENY", "IP_MISMATCH"), List.of("gw-app-02/00112233/4", "gw-app-02/00112233/7"));
    }

    private Dto.ObservationBatch batch(String id, Dto.Observation... obs) {
        return new Dto.ObservationBatch(fx.cred("detector"), id, List.of(obs));
    }

    private static Dto.Observation obs(Edge e, long first, long last, long count) {
        return new Dto.Observation(e, first, last, count);
    }

    // ---- learning ----

    public void testPilotObservationsBecomeCandidatesUnscopedOnesDoNot() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = bootstrapped(j, ControlPlaneImpl.Automation.disabled());
            long t = fx.clock.millis();
            MutationResult r = cp.recordObservations(batch("b1", obs(API_APP02, t - 5_000, t - 1_000, 2),
                    obs(API_APP03, t - 5_000, t, 1), obs(WEB_APP03, t, t, 1), obs(WEB_APP02, t, t, 9)));
            assertTrue(r.ok(), "accepted: " + r.message());
            assertEquals("merged=1 outOfScope=3", r.message());
            assertEquals(List.of(obs(API_APP02, t - 5_000, t - 1_000, 2)), cp.draft());
            // Merge: first = min, last = max, counts add up; the draft version moves, the enforcement revision not.
            assertTrue(cp.recordObservations(batch("b2", obs(API_APP02, t - 9_000, t, 3))).ok(), "second batch");
            assertEquals(List.of(obs(API_APP02, t - 9_000, t, 5)), cp.draft());
            ControlPlaneImpl.DraftStats st = cp.draftStats();
            assertEquals(2, st.version());
            assertEquals(3, st.outOfScope());
            assertEquals(1, cp.snapshot().revision());
            Dto.PolicyView view = cp.getPolicy(new Dto.PolicyRequest(fx.cred("viewer"), "app-02"));
            assertEquals(2, view.draftVersion());
            assertEquals(List.of(obs(API_APP02, t - 9_000, t, 5)), view.candidates());
            assertTrue(cp.getPolicy(new Dto.PolicyRequest(fx.cred("viewer"), "app-03")).candidates().isEmpty(),
                    "unscoped edge never became a candidate");
            // A candidate grants nothing: api-01 -> app-02 is still not an approved edge.
            assertFalse(cp.snapshot().policy().isApproved(API_APP02), "observations never create permissions");
        }
    }

    public void testObservationRetryIsNotCountedTwice() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = bootstrapped(j, ControlPlaneImpl.Automation.disabled());
            long t = fx.clock.millis();
            assertTrue(cp.recordObservations(batch("b1", obs(API_APP02, t, t, 2))).ok(), "first");
            MutationResult retry = cp.recordObservations(batch("b1", obs(API_APP02, t, t, 2)));
            assertTrue(retry.ok() && retry.replayed(), "identical retry");
            assertEquals(2, cp.draft().get(0).count());
            assertEquals(ErrorCode.INVALID, cp.recordObservations(batch("b1", obs(API_APP02, t, t, 3))).error());
        }
    }

    public void testObservationsIgnoredOutsideLearnModeAndValidated() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = bootstrapped(j, ControlPlaneImpl.Automation.disabled());
            assertTrue(cp.setMode(new Dto.SetModeRequest(fx.cred("admin"), "m1", 1, PolicyMode.ENFORCE, List.of("api-01"),
                    List.of("app-02"), "enforce")).ok(), "enforce");
            long t = fx.clock.millis();
            assertEquals("merged=0 outOfScope=1", cp.recordObservations(batch("b1", obs(API_APP02, t, t, 1))).message());
            assertTrue(cp.draft().isEmpty(), "no candidates in ENFORCE");
            assertEquals(ErrorCode.UNAUTHORIZED, cp.recordObservations(new Dto.ObservationBatch(fx.cred("operator"), "b2",
                    List.of(obs(API_APP02, t, t, 1)))).error());
            assertEquals(ErrorCode.INVALID, cp.recordObservations(batch("b3")).error()); // empty
            assertEquals(ErrorCode.INVALID, cp.recordObservations(batch("b4", obs(API_APP02, t, t - 1, 1))).error());
            assertEquals(ErrorCode.INVALID, cp.recordObservations(batch("b5", obs(API_APP02, t, t, 0))).error());
            assertEquals(ErrorCode.INVALID, cp.recordObservations(batch("b6", obs(API_APP02, t, t, 1),
                    obs(API_APP02, t, t, 1))).error());
            List<Dto.Observation> many = new ArrayList<>();
            for (int i = 0; i < 501; i++) {
                many.add(obs(new Edge("w" + i, "app-02"), t, t, 1));
            }
            assertEquals(ErrorCode.INVALID, cp.recordObservations(new Dto.ObservationBatch(fx.cred("detector"), "b7",
                    many)).error());
        }
    }

    // ---- proposals ----

    public void testLeaseReductionShortensOnlyNewIssuance() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = bootstrapped(j, automation(20));
            Peer web = new Peer("web-01", Bytes.fromHex("11".repeat(32)), IpAddress.parse("10.0.1.10"));
            PolicyEvaluator ev = new PolicyEvaluator(fx.clock);
            assertEquals(Duration.ofSeconds(60), ev.issue(EnforcementView.fresh(cp.snapshot()), web, "app-02").leaseLength());

            MutationResult r = cp.proposeAction(propose("det-a-1", ActionType.LEASE_REDUCTION, 60_000, 60, WEB));
            assertTrue(r.ok(), "committed: " + r.message());
            EnforcementSnapshot s = cp.snapshot();
            assertEquals(2, s.revision());
            assertEquals(List.of(new LeaseReduction(WEB, Duration.ofSeconds(10), fx.clock.instant().plusSeconds(60), 2)),
                    s.leaseReductions());
            assertEquals(Duration.ofSeconds(10), ev.issue(EnforcementView.fresh(s), web, "app-02").leaseLength());
            Peer api = new Peer("api-01", Bytes.fromHex("22".repeat(32)), IpAddress.parse("10.0.1.11"));
            assertEquals(Duration.ofSeconds(60), ev.issue(EnforcementView.fresh(s), api, "app-02").leaseLength());
            assertTrue(s.restrictions().isEmpty(), "a lease reduction is not a quarantine");

            Dto.AlertView alert = cp.alerts().get(0);
            assertEquals("det-a-1", alert.id());
            assertEquals("detector", alert.actor());
            assertEquals(60, alert.score());
            assertEquals(List.of("gw-app-02/00112233/4", "gw-app-02/00112233/7"), alert.evidence());
            Dto.AuditEntry audit = cp.getDashboard(new Dto.DashboardRequest(fx.cred("viewer"), 0, 1)).audit().get(0);
            assertEquals("AUTO_LEASE_REDUCTION", audit.operation());
            assertEquals("DETECTOR", audit.role());
            assertEquals(1, cp.getDashboard(new Dto.DashboardRequest(fx.cred("viewer"), 0, 10)).alerts().size());

            // Not extended by repeated evidence; expires as a committed transition.
            assertEquals(ErrorCode.CONFLICT, cp.proposeAction(propose("det-a-2", ActionType.LEASE_REDUCTION, 60_000, 70,
                    WEB)).error());
            fx.clock.advance(Duration.ofSeconds(61));
            assertEquals(1, cp.expireDue());
            assertTrue(cp.snapshot().leaseReductions().isEmpty(), "expired");
            assertEquals(Duration.ofSeconds(60), ev.issue(EnforcementView.fresh(cp.snapshot()), web, "app-02").leaseLength());
        }
    }

    /** A lost reply: the detector retries with the same idempotency ID and gets the original commit back. */
    public void testProposalIdempotentRetry() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = bootstrapped(j, automation(20));
            MutationResult first = cp.proposeAction(propose("det-b-1", ActionType.QUARANTINE, 60_000, 120, WEB));
            assertTrue(first.ok() && !first.replayed(), "committed");
            MutationResult retry = cp.proposeAction(propose("det-b-1", ActionType.QUARANTINE, 60_000, 120, WEB));
            assertTrue(retry.ok() && retry.replayed(), "replayed, not refused as already quarantined");
            assertEquals(first.revision(), retry.revision());
            assertEquals(2, cp.snapshot().revision());
            assertEquals(1, cp.alerts().size());
            assertEquals(ErrorCode.INVALID, cp.proposeAction(propose("det-b-1", ActionType.QUARANTINE, 30_000, 120,
                    WEB)).error()); // same ID, different payload
        }
        // After a restart the retry is still recognised, and the alert is rebuilt from the journal.
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = open(j, automation(20));
            assertTrue(cp.proposeAction(propose("det-b-1", ActionType.QUARANTINE, 60_000, 120, WEB)).replayed(),
                    "replayed after restart");
            assertEquals(1, cp.alerts().size());
            Restriction r = cp.snapshot().restrictions().get(0);
            assertEquals(ReasonCode.RISK_SCORE, r.reason());
            assertEquals("detector", r.actor());
        }
    }

    public void testQuarantineRulesAndScopes() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = bootstrapped(j, automation(20));
            assertEquals(ErrorCode.INVALID, cp.proposeAction(propose("p1", ActionType.QUARANTINE, 60_000, 99, WEB)).error());
            assertEquals(ErrorCode.INVALID, cp.proposeAction(propose("p2", ActionType.QUARANTINE,
                    Duration.ofMinutes(6).toMillis(), 120, WEB)).error()); // longer than the automation maximum
            assertEquals(ErrorCode.INVALID, cp.proposeAction(propose("p3", ActionType.QUARANTINE, 500, 120, WEB)).error());
            // Shared or ambiguous IPs and protected infrastructure are never quarantined automatically.
            assertEquals(ErrorCode.INVALID, cp.proposeAction(propose("p4", ActionType.QUARANTINE, 60_000, 150,
                    Selector.ip(IpAddress.parse("10.0.99.7")))).error());
            assertEquals(ErrorCode.INVALID, cp.proposeAction(propose("p5", ActionType.QUARANTINE, 60_000, 150,
                    Selector.ip(IpAddress.parse("192.168.1.1")))).error());
            assertEquals(ErrorCode.INVALID, cp.proposeAction(propose("p6", ActionType.QUARANTINE, 60_000, 150,
                    Selector.identity("gw-infra"))).error());
            assertEquals(ErrorCode.INVALID, cp.proposeAction(propose("p7", ActionType.QUARANTINE, 60_000, 150,
                    Selector.identity("ghost"))).error());
            assertEquals(ErrorCode.INVALID, cp.proposeAction(new Dto.ActionProposal(fx.cred("detector"), "p8",
                    ActionType.QUARANTINE, List.of(WEB), 60_000, 150, List.of("decoy hit"), List.of("x/y/1"))).error());
            assertEquals(1, cp.snapshot().revision());

            assertTrue(cp.proposeAction(propose("p9", ActionType.QUARANTINE, 60_000, 150,
                    Selector.ip(IpAddress.parse("10.0.1.20")))).ok(), "managed IP in the approved scope");
            assertTrue(cp.proposeAction(propose("p10", ActionType.QUARANTINE, 60_000, 120, WEB)).ok(), "identity");
            assertEquals(ErrorCode.CONFLICT, cp.proposeAction(propose("p11", ActionType.QUARANTINE, 60_000, 200,
                    WEB)).error()); // an existing quarantine is not extended
            assertEquals(ErrorCode.CONFLICT, cp.proposeAction(propose("p12", ActionType.LEASE_REDUCTION, 60_000, 60,
                    WEB)).error());
            // The detector has no release permission.
            assertEquals(ErrorCode.UNAUTHORIZED, cp.release(new Dto.ReleaseRequest(fx.cred("detector"), "r1",
                    List.of(WEB), "x")).error());
        }
    }

    public void testHourlyActionLimit() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = bootstrapped(j, automation(2));
            assertTrue(cp.proposeAction(propose("l1", ActionType.LEASE_REDUCTION, 60_000, 60, WEB)).ok(), "1");
            assertTrue(cp.proposeAction(propose("l2", ActionType.QUARANTINE, 60_000, 120, API)).ok(), "2");
            MutationResult third = cp.proposeAction(propose("l3", ActionType.QUARANTINE, 60_000, 120,
                    Selector.ip(IpAddress.parse("10.0.1.30"))));
            assertEquals(ErrorCode.UNAVAILABLE, third.error());
            assertTrue(third.message().contains("limit"), third.message());
            fx.clock.advance(Duration.ofMinutes(61));
            assertTrue(cp.proposeAction(propose("l3", ActionType.QUARANTINE, 60_000, 120,
                    Selector.ip(IpAddress.parse("10.0.1.30")))).ok(), "the window moved on; a refused ID can be retried");
        }
    }

    public void testDisabledAutomationTypeIsRefused() throws Exception {
        ControlPlaneImpl.Automation reduceOnly = new ControlPlaneImpl.Automation(true, false, Duration.ofSeconds(10),
                Duration.ofMinutes(5), 20, Set.of(), List.of(Cidr.parse("10.0.0.0/8")), List.of());
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = bootstrapped(j, reduceOnly);
            MutationResult q = cp.proposeAction(propose("d1", ActionType.QUARANTINE, 60_000, 120, WEB));
            assertEquals(ErrorCode.UNAVAILABLE, q.error());
            assertTrue(cp.proposeAction(propose("d2", ActionType.LEASE_REDUCTION, 60_000, 120, WEB)).ok(), "reduce");
            assertNull(cp.snapshot().restrictions().isEmpty() ? null : "quarantined");
        }
    }
}
