package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Edge;
import eastguard.common.PolicyMode;
import eastguard.common.Selector;
import eastguard.common.SelectorType;
import eastguard.control.Dto;
import eastguard.control.Role;
import eastguard.dashboard.AlertRows;
import eastguard.dashboard.ConsoleApi;
import eastguard.dashboard.ConsoleModel;
import eastguard.dashboard.ConsoleSnapshot;
import eastguard.dashboard.ConsoleWorker;
import eastguard.dashboard.DashboardController;
import eastguard.dashboard.FixtureScenarios;
import eastguard.dashboard.TopologyModel;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Dashboard model and controller (spec §7.3 threading, §10 "slow or unavailable RMI from Swing"): tested without
 * pixels. A dedicated thread plays the EDT; a settable monotonic clock drives polling and staleness.
 */
public final class DashboardControllerTest {
    private static final Edge WEB_APP02 = new Edge("web-01", "app-02");
    private static final Edge API_APP02 = new Edge("api-01", "app-02");
    private static final Edge WEB_APP03 = new Edge("web-01", "app-03");
    private static final DashboardController.Timing TIMING = new DashboardController.Timing(Duration.ofSeconds(1),
            Duration.ofSeconds(3));

    private final ExecutorService edt = Executors.newSingleThreadExecutor(r -> new Thread(r, "fake-edt"));
    private final AtomicLong nanos = new AtomicLong(1_000_000_000L);
    private final FakeApi api = new FakeApi();
    private final ConsoleModel model = new ConsoleModel(() -> Thread.currentThread().getName().equals("fake-edt"));
    private final ConsoleWorker worker = new ConsoleWorker(edt);
    private final DashboardController c = new DashboardController(model, api, worker, ControlFixtures.fixedClock(),
            nanos::get, TIMING);

    /** Scriptable control plane: normal, slow (blocks until released) or failing. */
    static final class FakeApi implements ConsoleApi {
        volatile Role role = Role.OPERATOR;
        volatile CountDownLatch block;          // non-null: every read blocks on it
        volatile boolean fail;
        volatile long draftVersion = 3;
        volatile Dto.MutationResult freezeResult = new Dto.MutationResult(null, null, 9, 9, false);
        volatile int quarantineFailures;
        final AtomicInteger reads = new AtomicInteger();
        final AtomicInteger mutations = new AtomicInteger();
        final List<String> requestIds = Collections.synchronizedList(new ArrayList<>());
        final AtomicReference<List<Edge>> frozen = new AtomicReference<>();
        final AtomicReference<long[]> frozenVersions = new AtomicReference<>();

        private void read() throws IOException {
            reads.incrementAndGet();
            CountDownLatch b = block;
            if (b != null) {
                try {
                    b.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted");
                }
            }
            if (fail) {
                throw new java.rmi.ConnectException("Connection refused to host: 127.0.0.1");
            }
        }

        public Dto.DashboardView dashboard(int limit) throws IOException {
            read();
            return new Dto.DashboardView(null, null, 8, 5, PolicyMode.LEARN, List.of(), List.of(), 0, List.of(), role,
                    List.of("api-01", "web-01"), List.of("app-02", "app-03"));
        }

        public Dto.LearningDraftView learningDraft() {
            return new Dto.LearningDraftView(null, null, 8, 5, draftVersion, PolicyMode.LEARN, List.of("api-01", "web-01"),
                    List.of("app-02", "app-03"), List.of(WEB_APP02), List.of(new Dto.Observation(API_APP02, 1, 2, 3),
                            new Dto.Observation(WEB_APP03, 1, 2, 1)), 0, 0, 0);
        }

        public Dto.MutationResult quarantine(String id, List<Selector> s, Duration ttl, String reason) throws IOException {
            mutations.incrementAndGet();
            requestIds.add(id);
            if (quarantineFailures > 0) {
                quarantineFailures--;
                throw new java.rmi.UnmarshalException("reply lost");
            }
            return new Dto.MutationResult(null, null, 9, 5, requestIds.size() > 1);
        }

        public Dto.MutationResult release(String id, List<Selector> s, String reason) {
            mutations.incrementAndGet();
            return new Dto.MutationResult(null, null, 10, 5, false);
        }

        public Dto.MutationResult freeze(String id, long p, long d, List<Edge> e, String reason) {
            mutations.incrementAndGet();
            frozen.set(List.copyOf(e));
            frozenVersions.set(new long[] {p, d});
            return freezeResult;
        }
    }

    /** Runs on the fake EDT and waits, like a Swing timer callback. */
    private void onEdt(Runnable r) throws Exception {
        edt.submit(r).get(5, TimeUnit.SECONDS);
    }

    private <T> T read(java.util.concurrent.Callable<T> r) throws Exception {
        return edt.submit(r).get(5, TimeUnit.SECONDS);
    }

    /** Ticks until {@code done} holds on the EDT (the worker delivers results there). */
    private void tickUntil(java.util.function.BooleanSupplier done, String what) throws Exception {
        long end = System.nanoTime() + 5_000_000_000L;
        while (!read(done::getAsBoolean)) {
            if (System.nanoTime() > end) {
                fail("timed out waiting for: " + what);
            }
            onEdt(c::tick);
            Thread.sleep(5);
        }
    }

    private void connect() throws Exception {
        tickUntil(() -> model.connection() == ConsoleModel.Connection.CONNECTED, "first poll");
    }

    private void close() {
        CountDownLatch b = api.block;
        if (b != null) {
            b.countDown();
        }
        worker.close();
        edt.shutdownNow();
    }

    public void testSlowRmiKeepsTheUiResponsiveMarksStaleAndDisablesEdits() throws Exception {
        try {
            connect();
            assertTrue(read(model::canOperate), "operator may act while connected");
            int readsBefore = api.reads.get();
            api.block = new CountDownLatch(1); // the control plane stops answering
            nanos.addAndGet(Duration.ofSeconds(1).toNanos());
            long worst = 0;
            for (int i = 0; i < 60; i++) { // 60 timer ticks, 100 ms of monotonic time apart
                long t0 = System.nanoTime();
                onEdt(c::tick);
                worst = Math.max(worst, System.nanoTime() - t0);
                nanos.addAndGet(Duration.ofMillis(100).toNanos());
            }
            assertTrue(worst < 200_000_000L, "a tick never blocks on RMI (worst " + worst / 1_000_000 + " ms)");
            assertEquals(readsBefore + 1, api.reads.get()); // exactly one poll in flight, none queued behind it
            assertTrue(worker.pollOutstanding(), "the hanging poll is still outstanding");
            assertEquals(ConsoleModel.Connection.STALE, read(model::connection));
            assertTrue(read(model::stale), "marked stale");
            assertTrue(read(model::connectionDetail).contains("slow"), read(model::connectionDetail));
            assertFalse(read(model::canOperate), "edits disabled while stale");
            assertTrue(read(model::data) != null, "the last good data stays visible, marked stale");

            String refused = read(() -> c.quarantine(Selector.identity("web-01"), Duration.ofMinutes(5), "scan"));
            assertTrue(refused != null && refused.contains("stale"), "controller refuses too: " + refused);
            assertEquals(0, api.mutations.get());

            api.block.countDown(); // it answers again
            api.block = null;
            tickUntil(() -> model.connection() == ConsoleModel.Connection.CONNECTED, "recovery");
            assertTrue(read(model::canOperate), "edits enabled again");
        } finally {
            close();
        }
    }

    public void testFirstPollHangingIsStaleWithNoData() throws Exception {
        try {
            api.block = new CountDownLatch(1);
            onEdt(c::tick);
            nanos.addAndGet(Duration.ofSeconds(4).toNanos());
            onEdt(c::tick);
            assertEquals(ConsoleModel.Connection.STALE, read(model::connection));
            assertNull(read(model::data));
            assertFalse(read(model::canOperate), "nothing is editable before the first answer");
        } finally {
            close();
        }
    }

    public void testUnavailableRmiDisconnectsAndKeepsEditsDisabled() throws Exception {
        try {
            connect();
            api.fail = true;
            nanos.addAndGet(Duration.ofSeconds(1).toNanos());
            tickUntil(() -> model.connection() == ConsoleModel.Connection.DISCONNECTED, "failure");
            assertTrue(read(model::connectionDetail).contains("unavailable"), read(model::connectionDetail));
            assertFalse(read(model::canOperate), "disabled when disconnected");
            assertTrue(read(model::data) != null, "old data kept, marked stale");
            assertTrue(read(model::stale), "stale");
            // Old data ages: still disconnected, never "connected" from cache.
            nanos.addAndGet(Duration.ofSeconds(10).toNanos());
            onEdt(c::tick);
            assertTrue(read(model::stale), "stays stale");
            api.fail = false;
            nanos.addAndGet(Duration.ofSeconds(1).toNanos());
            tickUntil(() -> model.connection() == ConsoleModel.Connection.CONNECTED, "recovery");
        } finally {
            close();
        }
    }

    public void testRoleGatesMutationsAndAReasonIsRequired() throws Exception {
        try {
            api.role = Role.VIEWER;
            connect();
            assertTrue(read(model::whyNotOperate).contains("VIEWER"), read(model::whyNotOperate));
            assertTrue(read(() -> c.quarantine(Selector.identity("web-01"), Duration.ofMinutes(1), "x")) != null,
                    "viewer refused");
            assertEquals(0, api.mutations.get());
            api.role = Role.OPERATOR;
            onEdt(c::refresh);
            tickUntil(() -> model.role() == Role.OPERATOR, "role update");
            assertEquals("a reason is required", read(() -> c.quarantine(Selector.identity("web-01"),
                    Duration.ofMinutes(1), "   ")));
            assertTrue(read(() -> c.freeze("reviewed")).contains("ADMIN"), "operator may not freeze");
            assertEquals(0, api.mutations.get());
            assertNull(read(() -> c.quarantine(Selector.identity("web-01"), Duration.ofMinutes(1), "decoy touch")));
            tickUntil(() -> !model.mutationInFlight(), "quarantine done");
            assertEquals(1, api.mutations.get());
            assertTrue(read(model::lastAction).contains("committed at revision 9"), read(model::lastAction));
        } finally {
            close();
        }
    }

    public void testLostReplyIsRetriedOnceWithTheSameRequestId() throws Exception {
        try {
            connect();
            api.quarantineFailures = 1;
            assertNull(read(() -> c.quarantine(Selector.identity("web-01"), Duration.ofMinutes(1), "decoy touch")));
            tickUntil(() -> !model.mutationInFlight(), "quarantine done");
            assertEquals(2, api.requestIds.size());
            assertEquals(api.requestIds.get(0), api.requestIds.get(1));
            assertTrue(api.requestIds.get(0).matches("console-[0-9a-f]{16}"), api.requestIds.get(0));
            assertTrue(read(model::lastAction).contains("(retry)"), read(model::lastAction));
        } finally {
            close();
        }
    }

    public void testFreezeSendsExactlyTheReviewedSetAtTheReviewedVersions() throws Exception {
        try {
            api.role = Role.ADMIN;
            connect();
            onEdt(c::startReview);
            assertEquals(List.of(API_APP02, WEB_APP02, WEB_APP03), read(model::reviewChoices));
            onEdt(() -> c.setReviewed(WEB_APP03, false)); // the administrator rejects one candidate
            onEdt(() -> c.setReviewed(new Edge("db-09", "app-02"), true)); // not in the draft: ignored
            ConsoleModel.Review r = read(model::review);
            assertEquals(List.of(API_APP02), r.diff().additions());
            assertEquals(List.of(), r.diff().removals());
            assertTrue(read(model::canFreeze), "admin may freeze a current review");
            assertNull(read(() -> c.freeze("CHG-7 reviewed baseline")));
            tickUntil(() -> !model.mutationInFlight(), "freeze done");
            assertEquals(List.of(API_APP02, WEB_APP02), api.frozen.get());
            assertEquals(5, api.frozenVersions.get()[0]);
            assertEquals(3, api.frozenVersions.get()[1]);
            assertNull(read(model::review)); // committed: review closed
        } finally {
            close();
        }
    }

    public void testFreezeConflictClearsTheReviewAndReloads() throws Exception {
        try {
            api.role = Role.ADMIN;
            connect();
            onEdt(c::startReview);
            api.freezeResult = new Dto.MutationResult(Dto.ErrorCode.CONFLICT,
                    "learning draft is at version 4, not 3; reload and review", 9, 5, false);
            int readsBefore = api.reads.get();
            assertNull(read(() -> c.freeze("CHG-7 reviewed baseline")));
            tickUntil(() -> !model.mutationInFlight() && api.reads.get() > readsBefore, "conflict and reload");
            assertNull(read(model::review));
            assertTrue(read(model::lastAction).contains("CONFLICT") && read(model::lastAction).contains("Reloaded"),
                    read(model::lastAction));
            assertTrue(read(model::whyNotFreeze).contains("review"), "a new review is required");
        } finally {
            close();
        }
    }

    public void testANewerDraftOutdatesTheReview() throws Exception {
        try {
            api.role = Role.ADMIN;
            connect();
            onEdt(c::startReview);
            api.draftVersion = 4; // a new observation batch arrived
            int readsBefore = api.reads.get();
            onEdt(c::refresh);
            tickUntil(() -> api.reads.get() > readsBefore && model.reviewOutdated(), "outdated review");
            assertFalse(read(model::canFreeze), "an outdated review cannot be frozen");
            assertTrue(read(model::whyNotFreeze).contains("reload and review"), read(model::whyNotFreeze));
        } finally {
            close();
        }
    }

    public void testModelChangesOnlyOnTheUiThread() throws Exception {
        try {
            connect();
            assertThrows(IllegalStateException.class, () -> c.startReview()); // test thread, not the EDT
        } finally {
            close();
        }
    }

    public void testWorkerQueueIsBounded() throws Exception {
        CountDownLatch hold = new CountDownLatch(1);
        try (ConsoleWorker w = new ConsoleWorker(Runnable::run)) {
            int accepted = 0;
            for (int i = 0; i < 20; i++) {
                if (w.submit(() -> {
                    hold.await();
                    return 1;
                }, x -> { }, e -> { })) {
                    accepted++;
                }
            }
            assertEquals(1 + ConsoleWorker.QUEUE, accepted); // one running, QUEUE waiting, the rest refused
            assertFalse(w.poll(() -> 1, x -> { }, e -> { }), "no poll when the queue is full");
            hold.countDown();
        } finally {
            close();
        }
    }

    public void testTopologyLabelsQuarantineAndBlastRadius() {
        List<FixtureScenarios.Scenario> all = FixtureScenarios.all(ControlFixtures.fixedClock());
        FixtureScenarios.Scenario contained = all.get(2);
        TopologyModel t = TopologyModel.of(new ConsoleSnapshot(contained.dashboard(), contained.draft(), contained.label(),
                contained.denied(), 0));
        TopologyModel.Node web = t.workloads().stream().filter(n -> n.id().equals("web-01")).findFirst().orElseThrow();
        assertTrue(web.quarantined() && web.markers().contains(TopologyModel.QUARANTINED), "quarantine overlay label");
        assertTrue(web.markers().contains(TopologyModel.DENIALS), "denial marker from the alert");
        List<TopologyModel.Link> blast = t.links().stream().filter(l -> l.kind() == TopologyModel.LinkKind.BLAST_RADIUS)
                .toList();
        assertEquals(List.of(WEB_APP02, WEB_APP03), blast.stream().map(TopologyModel.Link::edge).toList());
        assertTrue(TopologyModel.LinkKind.BLAST_RADIUS.label.contains("potential blast radius")
                && TopologyModel.LinkKind.BLAST_RADIUS.label.contains("not observed compromise"), "honest label");
        assertEquals(List.of("app-02", "app-03"), TopologyModel.blastRadius("web-01", contained.draft().approved()));
        assertTrue(t.links().stream().anyMatch(l -> l.kind() == TopologyModel.LinkKind.DENIED
                && l.edge().equals(new Edge("web-01", "db-01"))), "denied flow drawn");
        assertEquals(1, t.ipRestrictions().size());
        for (TopologyModel.LinkKind k : TopologyModel.LinkKind.values()) {
            assertFalse(k.symbol.isBlank() || k.label.isBlank(), "every kind has a symbol and a label: " + k);
        }

        FixtureScenarios.Scenario learning = all.get(1);
        TopologyModel lt = TopologyModel.of(new ConsoleSnapshot(learning.dashboard(), learning.draft(), learning.label(),
                List.of(), 0));
        assertEquals(3, lt.links().stream().filter(l -> l.kind() == TopologyModel.LinkKind.CANDIDATE).count());
        assertEquals(1, lt.links().stream().filter(l -> l.kind() == TopologyModel.LinkKind.APPROVED).count());
    }

    public void testAlertRowsTellProposedFromCommitted() {
        FixtureScenarios.Scenario contained = FixtureScenarios.all(ControlFixtures.fixedClock()).get(2);
        List<AlertRows.Row> rows = AlertRows.of(contained.dashboard());
        assertEquals(2, rows.size());
        AlertRows.Row newest = rows.get(0);
        assertEquals(AlertRows.COMMITTED, newest.stage());
        assertEquals("identity web-01", newest.target());
        assertEquals(130, newest.score());
        assertTrue(newest.signals().contains("DECOY") && newest.outcome().contains("revision 31"), newest.toString());
        assertEquals(AlertRows.PROPOSED, rows.get(1).stage());
        assertTrue(rows.get(1).outcome().startsWith("REFUSED"), rows.get(1).outcome());
    }

    public void testExampleConfigsLoad() throws Exception {
        try {
            eastguard.dashboard.DashboardConfig d = eastguard.dashboard.DashboardConfig.load(
                    java.nio.file.Path.of("config", "dashboard.properties.example"));
            assertEquals(eastguard.dashboard.DashboardConfig.Profile.LIVE, d.profile());
            assertEquals("console-operator", d.control().principal());
            eastguard.control.ControlConfig cc = eastguard.control.ControlConfig.load(
                    java.nio.file.Path.of("config", "control.properties.example"));
            assertEquals(9443, cc.audit().listen().port());
            assertEquals(java.util.Set.of(eastguard.control.AuditHttpServer.CONSOLE_IDENTITY), cc.audit().allowedClients());
        } finally {
            close();
        }
    }

    public void testDemoProfileIsLabeledAndReadOnly() throws Exception {
        List<FixtureScenarios.Scenario> all = FixtureScenarios.all(ControlFixtures.fixedClock());
        ConsoleModel m = new ConsoleModel(() -> Thread.currentThread().getName().equals("fake-edt"));
        DashboardController demo = new DashboardController(m, FixtureScenarios.api(() -> all.get(2)), worker,
                ControlFixtures.fixedClock(), nanos::get, TIMING);
        try {
            long end = System.nanoTime() + 5_000_000_000L;
            while (read(m::connection) != ConsoleModel.Connection.CONNECTED && System.nanoTime() < end) {
                onEdt(demo::tick);
                Thread.sleep(5);
            }
            assertTrue(read(m::demo), "demo data");
            assertTrue(read(m::connectionDetail).contains("DEMO FIXTURE"), read(m::connectionDetail));
            assertFalse(read(m::canOperate), "fixtures are read-only");
            assertTrue(read(() -> demo.quarantine(Selector.identity("web-01"), Duration.ofMinutes(1), "x")) != null,
                    "no live action from the demo profile");
            assertEquals(SelectorType.IDENTITY, DashboardController.selector(SelectorType.IDENTITY, " web-01 ").type());
            assertThrows(IllegalArgumentException.class, () -> DashboardController.selector(SelectorType.IP, "web-01"));
        } finally {
            close();
        }
    }
}
