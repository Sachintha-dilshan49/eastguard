package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Bytes;
import eastguard.common.Edge;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
import eastguard.common.IpAddress;
import eastguard.common.Lease;
import eastguard.common.LeaseCodec;
import eastguard.common.Peer;
import eastguard.common.PolicyEvaluator;
import eastguard.common.PolicyMode;
import eastguard.common.ReasonCode;
import eastguard.common.Selector;
import eastguard.common.SnapshotCodec;
import eastguard.control.ControlPlaneImpl;
import eastguard.control.Dto;
import eastguard.control.Dto.ErrorCode;
import eastguard.control.Dto.MutationResult;
import eastguard.control.Journal;
import eastguard.control.JournalRecord;
import eastguard.control.Mutation;
import eastguard.control.Role;
import eastguard.common.Sha256;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Control-plane core without RMI: single writer, journal replay, idempotency, versions, expiry, watermarks. */
public final class ControlPlaneImplTest {
    /** Unauthorized calls and journal failures log WARNING/SEVERE on purpose here. */
    private static final java.util.logging.Logger QUIET = java.util.logging.Logger.getLogger("eastguard.control");
    private static final Selector WEB = Selector.identity("web-01");
    private final ControlFixtures fx = new ControlFixtures();
    private final Path file;

    public ControlPlaneImplTest() throws Exception {
        file = ControlFixtures.freshJournal();
        QUIET.setLevel(java.util.logging.Level.OFF);
    }

    private Dto.ReplacePolicyRequest replace(String who, String requestId, long expected, Edge... edges) {
        return new Dto.ReplacePolicyRequest(fx.cred(who), requestId, expected, List.of(edges), "review ticket 42");
    }

    private Dto.QuarantineRequest quarantine(String requestId, long ttlMillis, Selector... sel) {
        return new Dto.QuarantineRequest(fx.cred("operator"), requestId, List.of(sel), ttlMillis, "suspicious scan");
    }

    private Dto.ReleaseRequest release(String requestId, Selector... sel) {
        return new Dto.ReleaseRequest(fx.cred("operator"), requestId, List.of(sel), "remediated");
    }

    private static final Edge WEB_APP = new Edge("web-01", "app-02");
    private static final Edge API_APP = new Edge("api-01", "app-02");

    // ---- bootstrap and replay ----

    public void testBootstrapIsRevisionOneAndReplays() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = fx.open(j);
            assertFalse(cp.ready(), "not ready before bootstrap");
            assertEquals(ErrorCode.UNAVAILABLE, cp.sync(new Dto.SyncRequest(fx.cred("gw-app-02"), 0)).error());
            assertEquals(ErrorCode.UNAVAILABLE, cp.quarantine(quarantine("q1", 60_000, WEB)).error());
            assertTrue(cp.bootstrap(ControlFixtures.initial(Fixtures.LEASE_KEYS.getPublic()), "admin", "first").ok(), "bootstrapped");
            assertEquals(ErrorCode.CONFLICT, cp.bootstrap(ControlFixtures.initial(Fixtures.LEASE_KEYS.getPublic()), "admin",
                    "again").error());
            assertTrue(cp.ready(), "ready");
        }
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = fx.open(j);
            assertEquals(1, cp.snapshot().revision());
            assertEquals(Set.of(WEB_APP), cp.snapshot().policy().approvedEdges());
            assertEquals(1, j.replayed().size());
        }
    }

    // ---- versions, audit, conflicts ----

    public void testAuditedPolicyEditAndVersionConflict() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = fx.bootstrapped(j);
            Dto.PolicyView before = cp.getPolicy(new Dto.PolicyRequest(fx.cred("admin"), "app-02"));
            assertEquals(1, before.policyRevision());
            MutationResult r = cp.replacePolicy(replace("admin", "edit-1", before.policyRevision(), WEB_APP, API_APP));
            assertTrue(r.ok(), "committed: " + r);
            assertEquals(2, r.revision());
            assertEquals(2, r.policyRevision());

            MutationResult stale = cp.replacePolicy(replace("admin-2", "edit-9", before.policyRevision(), WEB_APP));
            assertEquals(ErrorCode.CONFLICT, stale.error());
            assertEquals(2, stale.policyRevision());
            assertEquals(Set.of(WEB_APP, API_APP), cp.snapshot().policy().approvedEdges()); // never overwritten

            Dto.DashboardView d = cp.getDashboard(new Dto.DashboardRequest(fx.cred("viewer"), 0, 10));
            assertTrue(d.ok(), "dashboard");
            Dto.AuditEntry top = d.audit().get(0);
            assertEquals(2, top.revision());
            assertEquals("admin", top.actor());
            assertEquals("ADMIN", top.role());
            assertEquals("REPLACE_POLICY", top.operation());
            assertEquals("edit-1", top.requestId());
            assertEquals("review ticket 42", top.reason());
            assertEquals("COMMITTED", top.outcome());
            assertTrue(top.detail().contains("+api-01->app-02"), "diff in audit: " + top.detail());
            assertEquals(2, d.audit().size()); // the conflict was not committed
        }
    }

    public void testConcurrentEditsOneCommitsOthersConflict() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = fx.bootstrapped(j);
            int n = 8;
            CountDownLatch go = new CountDownLatch(1);
            List<Future<MutationResult>> results = new ArrayList<>();
            try (ExecutorService ex = Executors.newFixedThreadPool(n)) {
                for (int i = 0; i < n; i++) {
                    String id = "edit-" + i;
                    results.add(ex.submit(() -> {
                        go.await();
                        return cp.replacePolicy(replace("admin", id, 1, WEB_APP, API_APP));
                    }));
                }
                go.countDown();
                int ok = 0;
                int conflict = 0;
                for (Future<MutationResult> f : results) {
                    MutationResult r = f.get();
                    if (r.ok()) {
                        ok++;
                    } else if (r.error() == ErrorCode.CONFLICT) {
                        conflict++;
                    }
                }
                assertEquals(1, ok);
                assertEquals(n - 1, conflict);
            }
            assertEquals(2, cp.snapshot().revision());
        }
    }

    // ---- idempotency ----

    public void testLostReplyRetryDoesNotCommitTwice() throws Exception {
        MutationResult first;
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = fx.bootstrapped(j);
            first = cp.replacePolicy(replace("admin", "edit-1", 1, WEB_APP, API_APP));
            assertTrue(first.ok(), "committed");
            // The reply is "lost"; the client retries the identical request.
            MutationResult retry = cp.replacePolicy(replace("admin", "edit-1", 1, WEB_APP, API_APP));
            assertTrue(retry.ok() && retry.replayed(), "identical retry returns the prior result");
            assertEquals(first.revision(), retry.revision());
            assertEquals(ErrorCode.INVALID, cp.replacePolicy(replace("admin", "edit-1", 1, WEB_APP)).error());
            // Request IDs are scoped to the caller: another admin may use the same ID.
            assertEquals(ErrorCode.CONFLICT, cp.replacePolicy(replace("admin-2", "edit-1", 1, WEB_APP)).error());
        }
        try (Journal j = Journal.open(file)) {
            assertEquals(2, j.replayed().size()); // bootstrap + exactly one edit
            ControlPlaneImpl cp = fx.open(j);
            MutationResult afterRestart = cp.replacePolicy(replace("admin", "edit-1", 1, WEB_APP, API_APP));
            assertTrue(afterRestart.replayed(), "still recognised after a restart");
            assertEquals(first.revision(), afterRestart.revision());
            assertEquals(ErrorCode.INVALID, cp.replacePolicy(replace("admin", "edit-1", 1, API_APP)).error());
        }
    }

    public void testQuarantineRetryKeepsOriginalExpiry() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = fx.bootstrapped(j);
            assertTrue(cp.quarantine(quarantine("q-1", 60_000, WEB)).ok(), "committed");
            long expiry = cp.snapshot().restrictions().get(0).expiry().toEpochMilli();
            fx.clock.advance(Duration.ofSeconds(10));
            MutationResult retry = cp.quarantine(quarantine("q-1", 60_000, WEB));
            assertTrue(retry.replayed(), "the retry is recognised although 'now' moved");
            assertEquals(expiry, cp.snapshot().restrictions().get(0).expiry().toEpochMilli());
        }
    }

    // ---- authorization ----

    public void testRolesAreEnforcedOnEveryCall() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = fx.bootstrapped(j);
            Dto.Credential viewer = fx.cred("viewer");
            assertEquals(ErrorCode.UNAUTHORIZED, cp.quarantine(new Dto.QuarantineRequest(viewer, "q1", List.of(WEB),
                    60_000, "x")).error());
            assertEquals(ErrorCode.UNAUTHORIZED, cp.replacePolicy(replace("operator", "e1", 1, WEB_APP)).error());
            assertEquals(ErrorCode.UNAUTHORIZED, cp.getDashboard(new Dto.DashboardRequest(fx.cred("gw-app-02"), 0, 5)).error());
            assertEquals(ErrorCode.UNAUTHORIZED, cp.sync(new Dto.SyncRequest(fx.cred("admin"), 0)).error());
            assertEquals(ErrorCode.UNAUTHORIZED, cp.proposeAction(new Dto.ActionProposal(fx.cred("operator"), "p1",
                    Dto.ActionType.QUARANTINE, List.of(WEB), 60_000, 120, List.of("DECOY"), List.of("gw/1/2"))).error());
            // Wrong secret, unknown principal, revoked principal, no credential at all.
            Dto.Credential forged = new Dto.Credential("admin", ControlFixtures.secret());
            assertEquals(ErrorCode.UNAUTHORIZED, cp.replacePolicy(new Dto.ReplacePolicyRequest(forged, "e2", 1,
                    List.of(WEB_APP), "x")).error());
            assertEquals(ErrorCode.UNAUTHORIZED, cp.sync(new Dto.SyncRequest(new Dto.Credential("ghost",
                    ControlFixtures.secret()), 0)).error());
            assertEquals(ErrorCode.UNAUTHORIZED, cp.quarantine(new Dto.QuarantineRequest(fx.cred("revoked-op"), "q2",
                    List.of(WEB), 60_000, "x")).error());
            assertEquals(ErrorCode.UNAUTHORIZED, cp.sync(new Dto.SyncRequest(null, 0)).error());
            assertEquals(9, cp.unauthorizedCalls());
            assertEquals(1, cp.snapshot().revision()); // nothing committed
            // The right roles work.
            assertTrue(cp.sync(new Dto.SyncRequest(fx.cred("tokensvc"), 0)).ok(), "issuer may sync");
            assertEquals(ErrorCode.UNAVAILABLE, cp.proposeAction(new Dto.ActionProposal(fx.cred("detector"), "p1",
                    Dto.ActionType.QUARANTINE, List.of(WEB), 60_000, 120, List.of("DECOY"), List.of("gw/1/2"))).error());
            // authorized, but automation is off by default (alert-only)
        }
    }

    public void testInvalidRequestsRejected() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = fx.bootstrapped(j);
            assertEquals(ErrorCode.INVALID, cp.quarantine(quarantine("q1", 500, WEB)).error()); // TTL < 1 s
            assertEquals(ErrorCode.INVALID, cp.quarantine(quarantine("q2", Duration.ofDays(2).toMillis(), WEB)).error());
            assertEquals(ErrorCode.INVALID, cp.quarantine(quarantine("Bad ID", 60_000, WEB)).error());
            assertEquals(ErrorCode.INVALID, cp.quarantine(new Dto.QuarantineRequest(fx.cred("operator"), "q3",
                    List.of(WEB), 60_000, "")).error()); // a reason is required
            Selector[] nine = new Selector[9];
            for (int i = 0; i < 9; i++) {
                nine[i] = Selector.ip(IpAddress.parse("10.0.0." + (i + 1)));
            }
            assertEquals(ErrorCode.INVALID, cp.quarantine(quarantine("q4", 60_000, nine)).error());
            assertEquals(ErrorCode.INVALID, cp.replacePolicy(replace("admin", "e1", 1, new Edge("ghost", "app-02"))).error());
            assertEquals(ErrorCode.INVALID, cp.release(release("r1", WEB)).error()); // not quarantined
            assertEquals(ErrorCode.INVALID, cp.setLeaseDefaults(new Dto.SetLeaseDefaultsRequest(fx.cred("admin"), "l1", 1,
                    61_000, "x")).error());
            assertEquals(1, cp.snapshot().revision());
        }
    }

    // ---- quarantine, release, watermarks, expiry ----

    public void testReleaseWritesWatermarkThatSurvivesRestart() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = fx.bootstrapped(j);
            assertEquals(2, cp.quarantine(quarantine("q-1", 300_000, WEB)).revision());
            assertEquals(1, cp.snapshot().restrictions().size());
            assertEquals(3, cp.release(release("r-1", WEB)).revision());
        }
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = fx.open(j);
            EnforcementSnapshot s = cp.snapshot();
            assertEquals(0, s.restrictions().size());
            assertEquals(Long.valueOf(3), s.releaseWatermarks().get(WEB));

            // A lease issued at revision 2 (before the release) no longer admits web-01; one from revision 3 does.
            PolicyEvaluator ev = new PolicyEvaluator(fx.clock);
            Peer peer = new Peer("web-01", Fixtures.LEAF, Fixtures.CLIENT_IP);
            assertEquals(ReasonCode.LEASE_SUPERSEDED, ev.admit(EnforcementView.fresh(s), peer, "app-02", lease(2)).reason());
            assertEquals(ReasonCode.OK, ev.admit(EnforcementView.fresh(s), peer, "app-02", lease(3)).reason());
        }
    }

    private byte[] lease(long revision) {
        long now = fx.clock.millis();
        Lease l = new Lease("eg-test", "lease-k1", "web-01", "app-02", Fixtures.CLIENT_IP, Fixtures.LEAF, now,
                now + 60_000, Fixtures.JTI, revision);
        return LeaseCodec.issue(l, Fixtures.LEASE_KEYS.getPrivate());
    }

    public void testTtlExpiryIsACommittedTransition() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = fx.bootstrapped(j);
            cp.quarantine(quarantine("q-1", 5_000, WEB, Selector.ip(Fixtures.CLIENT_IP)));
            fx.clock.advance(Duration.ofSeconds(4));
            assertEquals(0, cp.expireDue());
            assertEquals(2, cp.snapshot().restrictions().size()); // receivers never unblock on their own
            fx.clock.advance(Duration.ofSeconds(2));
            assertEquals(2, cp.expireDue());
            EnforcementSnapshot s = cp.snapshot();
            assertEquals(3, s.revision());
            assertEquals(0, s.restrictions().size());
            assertEquals(Long.valueOf(3), s.releaseWatermarks().get(WEB));
            Dto.AuditEntry top = cp.getDashboard(new Dto.DashboardRequest(fx.cred("viewer"), 0, 1)).audit().get(0);
            assertEquals("EXPIRE", top.operation());
            assertEquals(ControlPlaneImpl.SYSTEM_ACTOR, top.actor());
            assertEquals("SYSTEM", top.role());
        }
        try (Journal j = Journal.open(file)) {
            assertEquals(Long.valueOf(3), fx.open(j).snapshot().releaseWatermarks().get(WEB));
        }
    }

    public void testModeAndLeaseDefaultsUseThePolicyRevision() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = fx.bootstrapped(j);
            cp.quarantine(quarantine("q-1", 60_000, WEB)); // enforcement revision 2, policy revision still 1
            MutationResult mode = cp.setMode(new Dto.SetModeRequest(fx.cred("admin"), "m1", 1, PolicyMode.LEARN,
                    List.of("api-01"), List.of("app-02"), "start pilot"));
            assertTrue(mode.ok(), "an unrelated quarantine does not conflict with a policy edit: " + mode);
            assertEquals(3, mode.policyRevision());
            assertTrue(cp.snapshot().policy().isPilotEdge(API_APP), "pilot edge");
            assertEquals(ErrorCode.CONFLICT, cp.setLeaseDefaults(new Dto.SetLeaseDefaultsRequest(fx.cred("admin"), "l1",
                    1, 30_000, "shorter")).error());
            assertTrue(cp.setLeaseDefaults(new Dto.SetLeaseDefaultsRequest(fx.cred("admin"), "l2", 3, 30_000,
                    "shorter")).ok(), "with the current version");
            assertEquals(Duration.ofSeconds(30), cp.snapshot().policy().defaultLeaseLength());
        }
    }

    // ---- sync ----

    public void testSyncIsFullOrAnExactAcknowledgement() throws Exception {
        try (Journal j = Journal.open(file)) {
            ControlPlaneImpl cp = fx.bootstrapped(j);
            Dto.SyncResponse full = cp.sync(new Dto.SyncRequest(fx.cred("gw-app-02"), 0));
            assertTrue(full.ok() && !full.unchanged(), "full snapshot");
            EnforcementSnapshot decoded = SnapshotCodec.decode(full.snapshot().toArray());
            assertEquals(1, decoded.revision());
            assertArrayEquals(SnapshotCodec.encode(cp.snapshot()), full.snapshot().toArray());
            Dto.SyncResponse same = cp.sync(new Dto.SyncRequest(fx.cred("gw-app-02"), 1));
            assertTrue(same.ok() && same.unchanged() && same.snapshot() == null, "exact acknowledgement");
            assertEquals(1, same.revision());
            Dto.SyncResponse ahead = cp.sync(new Dto.SyncRequest(fx.cred("gw-app-02"), 7));
            assertFalse(ahead.unchanged(), "a caller claiming a newer revision gets the full current state");
        }
    }

    // ---- durability failures ----

    public void testJournalFailureFencesMutationsAndSync() throws Exception {
        Journal j = Journal.open(file);
        ControlPlaneImpl cp = fx.bootstrapped(j);
        j.close(); // the disk "disappears"
        assertEquals(ErrorCode.UNAVAILABLE, cp.quarantine(quarantine("q-1", 60_000, WEB)).error());
        assertFalse(cp.ready(), "not ready");
        assertEquals(1, cp.snapshot().revision()); // the failed mutation was not published
        assertEquals(ErrorCode.UNAVAILABLE, cp.sync(new Dto.SyncRequest(fx.cred("gw-app-02"), 0)).error());
        try (Journal again = Journal.open(file)) {
            assertEquals(1, fx.open(again).snapshot().revision()); // nothing undurable was acknowledged
        }
    }

    public void testRevisionGapFailsReadiness() throws Exception {
        EnforcementSnapshot init = ControlFixtures.initial(Fixtures.LEASE_KEYS.getPublic());
        Bytes digest = Sha256.digest(new byte[0]);
        try (Journal j = Journal.open(file)) {
            j.append(new JournalRecord(1, 1, "admin", Role.ADMIN, null, digest, "init", new Mutation.Bootstrap(init)).encode());
            j.append(new JournalRecord(3, 2, "operator", Role.OPERATOR, "q-1", digest, "skip",
                    new Mutation.Quarantine(List.of(WEB), ReasonCode.OPERATOR_ACTION, 100_000)).encode());
        }
        try (Journal j = Journal.open(file)) {
            Journal.CorruptJournalException e = assertThrows(Journal.CorruptJournalException.class, () -> fx.open(j));
            assertTrue(e.getMessage().contains("revision 3"), e.getMessage());
        }
    }

    public void testUndecodableRecordFailsReadiness() throws Exception {
        try (Journal j = Journal.open(file)) {
            j.append("not a journal record".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        }
        try (Journal j = Journal.open(file)) {
            assertThrows(Journal.CorruptJournalException.class, () -> fx.open(j));
        }
    }
}
