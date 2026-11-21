package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.PilotScope;
import eastguard.common.Policy;
import eastguard.common.PolicyMode;
import eastguard.common.Selector;
import eastguard.common.Service;
import eastguard.common.Workload;
import eastguard.control.ControlPlaneImpl;
import eastguard.control.Dto;
import eastguard.control.Dto.ErrorCode;
import eastguard.control.Dto.MutationResult;
import eastguard.control.EdgeDiff;
import eastguard.control.Journal;
import eastguard.control.Role;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Reviewed learning freeze (spec §3.2, §7.1, §10 "freeze applies only the reviewed set", "concurrent edit"). */
public final class LearningFreezeTest {
    private static final java.util.logging.Logger QUIET = java.util.logging.Logger.getLogger("eastguard.control");
    static final Edge WEB_APP02 = new Edge("web-01", "app-02");
    static final Edge API_APP02 = new Edge("api-01", "app-02");
    static final Edge API_APP03 = new Edge("api-01", "app-03");
    static final Edge WEB_APP03 = new Edge("web-01", "app-03");

    private final ControlFixtures fx = new ControlFixtures();
    private final Path file;

    public LearningFreezeTest() throws Exception {
        QUIET.setLevel(java.util.logging.Level.OFF);
        file = ControlFixtures.freshJournal();
    }

    /** LEARN: web-01 -> app-02 approved; the pilot covers web-01 and api-01 to app-02 and app-03. */
    static EnforcementSnapshot learning() {
        Service app02 = new Service("app-02", "app-02", Endpoint.parse("127.0.0.1:9002"), "127.0.0.1",
                Endpoint.parse("127.0.0.1:7002"));
        Service app03 = new Service("app-03", "app-03", Endpoint.parse("127.0.0.1:9004"), "127.0.0.1",
                Endpoint.parse("127.0.0.1:7004"));
        Policy policy = new Policy(PolicyMode.LEARN, Set.of(WEB_APP02), new PilotScope(Set.of("web-01", "api-01"),
                Set.of("app-02", "app-03")), 1, Duration.ofSeconds(60));
        return new EnforcementSnapshot("eg-test", 1, policy, Map.of("web-01", Workload.enabled("web-01"), "api-01",
                Workload.enabled("api-01")), Map.of("app-02", app02, "app-03", app03), List.of(), List.of(), Map.of(),
                Map.of("lease-k1", Fixtures.LEASE_KEYS.getPublic()), Set.of());
    }

    private ControlPlaneImpl open(Journal j) throws Exception {
        return ControlPlaneImpl.open(j, fx.clock, fx.credentials, ControlPlaneImpl.Settings.defaults());
    }

    /** Bootstrapped in LEARN with candidates api-01 -> app-02 and web-01 -> app-03. */
    private ControlPlaneImpl withDraft(Journal j) throws Exception {
        ControlPlaneImpl cp = open(j);
        assertTrue(cp.bootstrap(learning(), "admin", "test state").ok(), "bootstrap");
        observe(cp, "b1", API_APP02, WEB_APP03);
        return cp;
    }

    private void observe(ControlPlaneImpl cp, String id, Edge... edges) {
        long t = fx.clock.millis();
        List<Dto.Observation> obs = java.util.Arrays.stream(edges).map(e -> new Dto.Observation(e, t, t, 1)).toList();
        MutationResult r = cp.recordObservations(new Dto.ObservationBatch(fx.cred("detector"), id, obs));
        assertTrue(r.ok(), "observations: " + r);
    }

    private Dto.LearningDraftView draft(ControlPlaneImpl cp, String who) {
        return cp.getLearningDraft(new Dto.LearningDraftRequest(fx.cred(who)));
    }

    private Dto.FreezeRequest freeze(String id, Dto.LearningDraftView v, Edge... reviewed) {
        return new Dto.FreezeRequest(fx.cred("admin"), id, v.policyRevision(), v.draftVersion(), List.of(reviewed),
                "CHG-7 reviewed pilot baseline");
    }

    public void testFreezeAppliesOnlyTheReviewedSet() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = withDraft(j);
            Dto.LearningDraftView v = draft(cp, "admin");
            assertEquals(List.of(API_APP02, WEB_APP02, WEB_APP03), v.proposedBaseline());
            // The administrator accepts api-01 -> app-02 but not web-01 -> app-03.
            MutationResult r = cp.freezeBaseline(freeze("f-1", v, WEB_APP02, API_APP02));
            assertTrue(r.ok(), "freeze committed: " + r);
            Policy p = cp.snapshot().policy();
            assertEquals(PolicyMode.ENFORCE, p.mode());
            assertEquals(Set.of(WEB_APP02, API_APP02), p.approvedEdges());
            assertEquals(PilotScope.NONE, p.pilotScope());
            assertEquals(r.revision(), p.revision());
            assertFalse(p.isApproved(WEB_APP03), "the unreviewed candidate grants nothing");

            Dto.AuditEntry a = cp.auditPage(0, 1).entries().get(0);
            assertEquals("FREEZE_BASELINE", a.operation());
            assertTrue(a.detail().contains("diff=[+api-01->app-02]") && a.detail().contains("mode=ENFORCE")
                    && a.detail().contains("draftVersion=" + v.draftVersion()), a.detail());
            assertEquals("ADMIN", a.role());

            Dto.LearningDraftView after = draft(cp, "viewer");
            assertEquals(v.draftVersion() + 1, after.draftVersion());
            assertEquals(List.of(WEB_APP03), after.candidates().stream().map(Dto.Observation::edge).toList());
            // ENFORCE now: further pilot observations are out of scope.
            observe(cp, "b2", WEB_APP03);
            assertEquals(after.draftVersion(), draft(cp, "viewer").draftVersion());
        }
        try (Journal j = Journal.open(file)) { // one journaled mutation: replay reproduces it
            Policy p = open(j).snapshot().policy();
            assertEquals(PolicyMode.ENFORCE, p.mode());
            assertEquals(Set.of(WEB_APP02, API_APP02), p.approvedEdges());
        }
    }

    public void testFreezeWithStaleDraftVersionConflicts() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = withDraft(j);
            Dto.LearningDraftView reviewed = draft(cp, "admin");
            observe(cp, "b2", API_APP03); // a new candidate arrives while the administrator reviews
            long revision = cp.snapshot().revision();
            MutationResult r = cp.freezeBaseline(freeze("f-1", reviewed, WEB_APP02, API_APP02));
            assertEquals(ErrorCode.CONFLICT, r.error());
            assertTrue(r.message().contains("reload and review"), r.message());
            assertEquals(revision, cp.snapshot().revision());
            assertEquals(PolicyMode.LEARN, cp.snapshot().policy().mode());
            // Reload and review again: the new version commits.
            Dto.LearningDraftView reloaded = draft(cp, "admin");
            assertEquals(reviewed.draftVersion() + 1, reloaded.draftVersion());
            assertTrue(cp.freezeBaseline(freeze("f-2", reloaded, WEB_APP02, API_APP02)).ok(), "after reload");
        }
    }

    public void testFreezeWithStalePolicyRevisionConflicts() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = withDraft(j);
            Dto.LearningDraftView reviewed = draft(cp, "admin");
            assertTrue(cp.replacePolicy(new Dto.ReplacePolicyRequest(fx.cred("admin-2"), "e-1",
                    reviewed.policyRevision(), List.of(), "remove everything")).ok(), "concurrent edit");
            MutationResult r = cp.freezeBaseline(freeze("f-1", reviewed, WEB_APP02, API_APP02));
            assertEquals(ErrorCode.CONFLICT, r.error());
            assertEquals(Set.of(), cp.snapshot().policy().approvedEdges()); // the newer edit was not overwritten
        }
    }

    public void testConcurrentEditAndFreezeOneCommits() throws Exception {
        for (int round = 0; round < 20; round++) {
            try (Journal j = Journal.open(ControlFixtures.freshJournal())) {
                ControlPlaneImpl cp = withDraft(j);
                Dto.LearningDraftView v = draft(cp, "admin");
                CountDownLatch go = new CountDownLatch(1);
                ExecutorService pool = Executors.newFixedThreadPool(2);
                try {
                    Future<MutationResult> edit = pool.submit(() -> {
                        go.await();
                        return cp.replacePolicy(new Dto.ReplacePolicyRequest(fx.cred("admin-2"), "e-1",
                                v.policyRevision(), List.of(WEB_APP02, WEB_APP03), "manual edit"));
                    });
                    Future<MutationResult> frz = pool.submit(() -> {
                        go.await();
                        return cp.freezeBaseline(freeze("f-1", v, WEB_APP02, API_APP02));
                    });
                    go.countDown();
                    MutationResult a = edit.get();
                    MutationResult b = frz.get();
                    assertTrue(a.ok() ^ b.ok(), "exactly one commits: " + a + " / " + b);
                    assertEquals(ErrorCode.CONFLICT, (a.ok() ? b : a).error());
                    assertEquals(v.revision() + 1, cp.snapshot().revision()); // one commit, not two
                } finally {
                    pool.shutdownNow();
                }
            }
        }
    }

    public void testFreezeRefusesEdgesNobodyReviewed() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = withDraft(j);
            Dto.LearningDraftView v = draft(cp, "admin");
            MutationResult notCandidate = cp.freezeBaseline(freeze("f-1", v, WEB_APP02, API_APP03));
            assertEquals(ErrorCode.INVALID, notCandidate.error());
            assertTrue(notCandidate.message().contains("neither approved nor a candidate"), notCandidate.message());
            assertEquals(ErrorCode.INVALID, cp.freezeBaseline(freeze("f-2", v, new Edge("db-09", "app-02"))).error());
            assertEquals(ErrorCode.INVALID, cp.freezeBaseline(freeze("f-3", v, WEB_APP02, WEB_APP02)).error());
            assertEquals(ErrorCode.INVALID, cp.freezeBaseline(new Dto.FreezeRequest(fx.cred("admin"), "f-4", -1,
                    v.draftVersion(), List.of(WEB_APP02), "no expectation")).error());
            assertEquals(PolicyMode.LEARN, cp.snapshot().policy().mode());
        }
    }

    public void testFreezeCanRemoveAnApprovedEdge() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = withDraft(j);
            Dto.LearningDraftView v = draft(cp, "admin");
            EdgeDiff preview = EdgeDiff.of(v.approved(), List.of(API_APP02));
            assertEquals(List.of(API_APP02), preview.additions());
            assertEquals(List.of(WEB_APP02), preview.removals());
            assertTrue(cp.freezeBaseline(freeze("f-1", v, API_APP02)).ok(), "freeze");
            assertEquals(Set.of(API_APP02), cp.snapshot().policy().approvedEdges());
            assertTrue(cp.auditPage(0, 1).entries().get(0).detail().contains("diff=" + preview), "audit matches preview");
        }
    }

    public void testFreezeIsAdminOnlyAndIdempotent() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = withDraft(j);
            Dto.LearningDraftView v = draft(cp, "admin");
            assertEquals(ErrorCode.UNAUTHORIZED, cp.freezeBaseline(new Dto.FreezeRequest(fx.cred("operator"), "f-1",
                    v.policyRevision(), v.draftVersion(), List.of(WEB_APP02), "x")).error());
            MutationResult first = cp.freezeBaseline(freeze("f-1", v, WEB_APP02, API_APP02));
            long version = draft(cp, "admin").draftVersion();
            MutationResult retry = cp.freezeBaseline(freeze("f-1", v, WEB_APP02, API_APP02));
            assertTrue(retry.ok() && retry.replayed() && retry.revision() == first.revision(), "replayed: " + retry);
            assertEquals(version, draft(cp, "admin").draftVersion());
        }
    }

    public void testLearningDraftViewIsReadOnlyAndMarkedIncomplete() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = withDraft(j);
            Dto.LearningDraftView v = draft(cp, "viewer");
            assertTrue(v.ok(), "viewer may read the draft");
            assertEquals(PolicyMode.LEARN, v.mode());
            assertEquals(List.of(WEB_APP02), v.approved());
            assertEquals(List.of("api-01", "web-01"), v.pilotSources());
            assertEquals(2, v.candidates().size());
            assertTrue(Dto.LearningDraftView.INCOMPLETE.contains("may be incomplete"), "completeness note");
            assertEquals(ErrorCode.UNAUTHORIZED, draft(cp, "gw-app-02").error());
            assertEquals(ErrorCode.UNAUTHORIZED, draft(cp, "detector").error());
        }
    }

    public void testDashboardShowsRoleAndRefusedProposals() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = withDraft(j); // automation disabled: every proposal is refused (alert-only)
            MutationResult r = cp.proposeAction(new Dto.ActionProposal(fx.cred("detector"), "alert-1",
                    Dto.ActionType.QUARANTINE, List.of(Selector.identity("web-01")), 60_000, 130, List.of("DECOY"),
                    List.of("gw-app-02/0a0b0c0d/3")));
            assertEquals(ErrorCode.UNAVAILABLE, r.error());
            Dto.DashboardView d = cp.getDashboard(new Dto.DashboardRequest(fx.cred("viewer"), 0, 10));
            assertEquals(Role.VIEWER, d.role());
            assertEquals(1, d.alerts().size());
            Dto.AlertView a = d.alerts().get(0);
            assertFalse(a.committed(), "a refused proposal is not shown as committed");
            assertTrue(a.outcome().startsWith("REFUSED UNAVAILABLE"), a.outcome());
            assertEquals(-1, a.revision());
            assertEquals(Role.OPERATOR, cp.getDashboard(new Dto.DashboardRequest(fx.cred("operator"), 0, 10)).role());
            assertTrue(cp.alerts().isEmpty(), "nothing committed");
        }
    }

    public void testEdgeDiff() {
        EdgeDiff d = EdgeDiff.of(List.of(WEB_APP02, API_APP03), List.of(API_APP02, WEB_APP02));
        assertEquals(List.of(API_APP02), d.additions());
        assertEquals(List.of(API_APP03), d.removals());
        assertEquals(List.of(WEB_APP02), d.kept());
        assertEquals("[+api-01->app-02, -api-01->app-03]", d.toString());
        assertTrue(EdgeDiff.of(List.of(WEB_APP02), Set.of(WEB_APP02)).empty(), "no change");
    }
}
