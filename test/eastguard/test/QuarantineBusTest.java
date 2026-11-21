package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.bus.MemoryTransport;
import eastguard.bus.MulticastSettings;
import eastguard.bus.MulticastTransport;
import eastguard.bus.NoticeTransport;
import eastguard.bus.QuarantineListener;
import eastguard.bus.QuarantineSender;
import eastguard.common.Bytes;
import eastguard.common.Ed25519;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
import eastguard.common.IpAddress;
import eastguard.common.Lease;
import eastguard.common.LeaseCodec;
import eastguard.common.Notice;
import eastguard.common.NoticeCodec;
import eastguard.common.NoticeOperation;
import eastguard.common.Peer;
import eastguard.common.PolicyEvaluator;
import eastguard.common.ReasonCode;
import eastguard.common.Selector;
import eastguard.common.SnapshotCodec;
import eastguard.common.WireWriter;
import eastguard.control.ControlPlaneImpl;
import eastguard.control.Dto;
import eastguard.control.Dto.SyncResponse;
import eastguard.control.Journal;
import eastguard.control.StateSync;
import java.io.IOException;
import java.net.DatagramSocket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The multicast quarantine bus (spec §5.4, §6.2, §6.3, §10 "duplicate notice, out-of-order notice, lost multicast,
 * receiver restart"): a real control plane and journal, the real sender and listener, and the in-memory transport
 * with fault injection. The receiver's monotonic clock is fake and syncs are triggered by the test, so every
 * scenario is deterministic; only notice delivery crosses threads (awaited with a bounded wait).
 */
public final class QuarantineBusTest {
    private static final Logger QUIET = Logger.getLogger("eastguard");
    private static final long SEC = 1_000_000_000L;
    private static final String KEY_ID = "control-k1";
    private static final KeyPair CONTROL = Ed25519.generate();
    private static final Selector WEB = Selector.identity("web-01");
    private static final Selector API = Selector.identity("api-01");
    private static final IpAddress WEB_IP = IpAddress.parse("10.0.1.10");
    private static final IpAddress OTHER_IP = IpAddress.parse("10.0.1.77");
    private static final Selector WEB_IP_SEL = Selector.ip(WEB_IP);
    private static final Peer WEB_PEER = new Peer("web-01", Fixtures.LEAF, WEB_IP);
    private static final Bytes API_LEAF = Bytes.fromHex("22".repeat(32));

    private final ControlFixtures fx = new ControlFixtures();
    private final Journal journal;
    private final ControlPlaneImpl cp;
    private final MemoryTransport transport = new MemoryTransport();
    private final QuarantineSender sender;
    private final PolicyEvaluator evaluator;
    private final AtomicLong nanos = new AtomicLong(1_000 * SEC);
    /** When set, the receiver's sync returns this instead of asking the control plane (an old or stale reply). */
    private final AtomicReference<SyncResponse> frozen = new AtomicReference<>();
    private final List<AutoCloseable> closeables = new ArrayList<>();
    private int requestIds;

    public QuarantineBusTest() throws Exception {
        QUIET.setLevel(Level.OFF); // rejected notices and replies log on purpose
        journal = Journal.open(ControlFixtures.freshJournal());
        cp = fx.open(journal);
        EnforcementSnapshot initial = ControlFixtures.initial(Fixtures.LEASE_KEYS.getPublic())
                .withControlKeys(Map.of(KEY_ID, CONTROL.getPublic()));
        assertTrue(cp.bootstrap(initial, "admin", "initial state").ok(), "bootstrapped");
        sender = new QuarantineSender("eg-test", KEY_ID, CONTROL.getPrivate(), transport, fx.clock, new SecureRandom(),
                Duration.ZERO).start();
        cp.onContainment(sender::committed);
        evaluator = new PolicyEvaluator(fx.clock);
    }

    /** One enforcement point: its own sync (driven by the test) and its own listener on the shared transport. */
    private final class Receiver implements AutoCloseable {
        final StateSync sync;
        final QuarantineListener listener;
        final List<Set<Selector>> newlyBlocked = new CopyOnWriteArrayList<>();

        Receiver(String name) throws IOException {
            sync = new StateSync(name, known -> {
                SyncResponse f = frozen.get();
                return f != null ? f : cp.sync(new Dto.SyncRequest(fx.cred("gw-app-02"), known));
            }, new StateSync.Settings("eg-test", Duration.ofSeconds(1), Duration.ofSeconds(5)), nanos::get);
            sync.addOverlayListener(newlyBlocked::add);
            listener = QuarantineListener.forSync(name, transport, sync, fx.clock); // joined before the first sync
            closeables.add(this);
        }

        EnforcementView view() {
            return sync.get();
        }

        ReasonCode issue(Peer p) {
            return evaluator.issue(view(), p, "app-02").reason();
        }

        @Override
        public void close() {
            listener.close();
            sync.close();
        }
    }

    private Receiver synced(String name) throws IOException {
        Receiver r = new Receiver(name);
        assertTrue(r.sync.syncOnce(), "first sync");
        return r;
    }

    private void cleanup() throws Exception {
        for (AutoCloseable c : closeables) {
            c.close();
        }
        sender.close();
        transport.close();
        journal.close();
    }

    private static void await(BooleanSupplier condition, String what) {
        long end = System.nanoTime() + 3 * SEC;
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > end) {
                fail("timed out waiting for " + what);
            }
            Thread.onSpinWait();
        }
    }

    private long quarantine(Selector... sel) {
        Dto.MutationResult r = cp.quarantine(new Dto.QuarantineRequest(fx.cred("operator"), "q" + (++requestIds),
                List.of(sel), 60_000, "suspicious scan"));
        assertTrue(r.ok(), "quarantine committed: " + r);
        return r.revision();
    }

    private long release(Selector... sel) {
        Dto.MutationResult r = cp.release(new Dto.ReleaseRequest(fx.cred("operator"), "r" + (++requestIds),
                List.of(sel), "remediated"));
        assertTrue(r.ok(), "release committed: " + r);
        return r.revision();
    }

    private Notice notice(long revision, NoticeOperation op, long sentAt, List<Selector> sel) {
        byte[] nonce = new byte[Notice.NONCE_LENGTH];
        new SecureRandom().nextBytes(nonce);
        return new Notice("eg-test", KEY_ID, revision, sentAt, Bytes.copyOf(nonce), op,
                op == NoticeOperation.QUARANTINE ? sentAt + 60_000 : 0, sel, ReasonCode.OPERATOR_ACTION);
    }

    private void inject(byte[] datagram) throws IOException {
        transport.send(datagram);
    }

    // ---- sending ----

    public void testCommittedQuarantineIsSentThreeTimesAndAppliedOnce() throws Exception {
        try {
            Receiver r = synced("rx");
            assertEquals(ReasonCode.OK, r.issue(WEB_PEER));
            long rev = quarantine(WEB);
            await(() -> r.listener.accepted() == QuarantineSender.COPIES, "three verified copies");
            assertEquals(3, transport.sent());
            StateSync.NoticeStats s = r.sync.noticeStats();
            assertEquals(1, s.accepted());
            assertEquals(2, s.duplicates()); // coalesced
            assertEquals(rev, s.newest());
            assertEquals(List.of(Set.of(WEB)), r.newlyBlocked); // sessions closed once, not three times
            assertEquals(ReasonCode.QUARANTINED, r.issue(WEB_PEER)); // overlay, before any sync
            assertTrue(r.view().overlay().contains(WEB), "overlay");
            assertTrue(r.view().usable(), "still fresh: a notice never renews, but does not expire state either");
        } finally {
            cleanup();
        }
    }

    public void testSendFailureNeverUndoesTheCommit() throws Exception {
        NoticeTransport broken = new NoticeTransport() {
            @Override
            public void send(byte[] datagram) throws IOException {
                throw new IOException("network unreachable");
            }

            @Override
            public Receiver join() {
                throw new UnsupportedOperationException();
            }
        };
        QuarantineSender bad = new QuarantineSender("eg-test", KEY_ID, CONTROL.getPrivate(), broken, fx.clock,
                new SecureRandom(), Duration.ZERO).start();
        try {
            cp.onContainment(bad::committed);
            long rev = quarantine(WEB);
            await(() -> bad.stats().sendFailures() == QuarantineSender.COPIES, "three failed sends");
            assertEquals(rev, cp.snapshot().revision());
            assertEquals(1, cp.snapshot().restrictions().size()); // committed and durable regardless
            assertEquals(0, bad.stats().datagrams());
        } finally {
            bad.close();
            cleanup();
        }
    }

    public void testSenderSplitsLargeSelectorSetsIntoNoticesOfAtMostEight() throws Exception {
        try {
            Receiver r = synced("rx");
            List<Selector> nine = new ArrayList<>();
            for (int i = 1; i <= 9; i++) {
                nine.add(Selector.ip(IpAddress.parse("10.0.2." + i)));
            }
            sender.committed(new ControlPlaneImpl.Containment(NoticeOperation.QUARANTINE, 7, fx.clock.millis(), nine,
                    fx.clock.millis() + 60_000, ReasonCode.OPERATOR_ACTION));
            await(() -> r.listener.accepted() == 6, "two notices, three copies each");
            assertEquals(2, sender.stats().notices());
            assertEquals(9, r.view().overlay().size());
        } finally {
            cleanup();
        }
    }

    // ---- verification ----

    public void testInvalidSignatureIsRejected() throws Exception {
        try {
            Receiver r = synced("rx");
            byte[] good = NoticeCodec.encode(notice(9, NoticeOperation.QUARANTINE, fx.clock.millis(), List.of(WEB)),
                    CONTROL.getPrivate());
            byte[] flipped = good.clone();
            flipped[flipped.length - 1] ^= 1;
            inject(flipped);
            byte[] body = good.clone();
            body[30] ^= 1; // a changed signed byte (inside the key ID / revision area)
            inject(body);
            KeyPair impostor = Ed25519.generate(); // right key ID, wrong key
            inject(NoticeCodec.encode(notice(9, NoticeOperation.QUARANTINE, fx.clock.millis(), List.of(WEB)),
                    impostor.getPrivate()));
            await(() -> r.listener.rejectedTotal() == 3, "three datagrams rejected");
            assertTrue(r.listener.rejected("bad signature") >= 2, "signature failures: " + r.listener.rejected());
            assertEquals(0, r.listener.accepted());
            assertEquals(ReasonCode.OK, r.issue(WEB_PEER));
            assertEquals(0, r.sync.noticeStats().newest());
        } finally {
            cleanup();
        }
    }

    public void testWrongClusterIsRejected() throws Exception {
        try {
            Receiver r = synced("rx");
            Notice n = notice(9, NoticeOperation.QUARANTINE, fx.clock.millis(), List.of(WEB));
            inject(NoticeCodec.encode(new Notice("eg-other", KEY_ID, 9, n.sentAtMs(), n.nonce(), n.operation(),
                    n.expiresAtMs(), n.selectors(), n.reason()), CONTROL.getPrivate()));
            await(() -> r.listener.rejectedTotal() == 1, "one datagram rejected");
            assertEquals(1, r.listener.rejected("wrong cluster"));
            assertEquals(ReasonCode.OK, r.issue(WEB_PEER));
        } finally {
            cleanup();
        }
    }

    public void testUntrustedKeyIsRejectedIncludingTheLeaseKey() throws Exception {
        try {
            Receiver r = synced("rx");
            KeyPair other = Ed25519.generate();
            Notice n = notice(9, NoticeOperation.QUARANTINE, fx.clock.millis(), List.of(WEB));
            inject(NoticeCodec.encode(new Notice("eg-test", "control-k9", 9, n.sentAtMs(), n.nonce(), n.operation(),
                    n.expiresAtMs(), n.selectors(), n.reason()), other.getPrivate()));
            // The lease signer is published in the snapshot, but only as a lease key: it can never sign notices.
            inject(NoticeCodec.encode(new Notice("eg-test", "lease-k1", 9, n.sentAtMs(), n.nonce(), n.operation(),
                    n.expiresAtMs(), n.selectors(), n.reason()), Fixtures.LEASE_KEYS.getPrivate()));
            await(() -> r.listener.rejectedTotal() == 2, "two datagrams rejected");
            assertEquals(2, r.listener.rejected("untrusted control key"));
            assertEquals(ReasonCode.OK, r.issue(WEB_PEER));
            assertThrows(IllegalArgumentException.class, () -> cp.snapshot().withControlKeys(
                    Map.of("control-k2", Fixtures.LEASE_KEYS.getPublic()))); // and cannot be published as one
        } finally {
            cleanup();
        }
    }

    public void testTimestampOutsideThirtySecondsIsRejected() throws Exception {
        try {
            Receiver r = synced("rx");
            long now = fx.clock.millis();
            inject(NoticeCodec.encode(notice(9, NoticeOperation.QUARANTINE, now - 30_001, List.of(WEB)), CONTROL.getPrivate()));
            inject(NoticeCodec.encode(notice(9, NoticeOperation.QUARANTINE, now + 30_001, List.of(WEB)), CONTROL.getPrivate()));
            await(() -> r.listener.rejectedTotal() == 2, "two datagrams rejected");
            assertEquals(2, r.listener.rejected("notice timestamp outside skew window"));
            assertEquals(ReasonCode.OK, r.issue(WEB_PEER));
            inject(NoticeCodec.encode(notice(9, NoticeOperation.QUARANTINE, now - 29_000, List.of(WEB)), CONTROL.getPrivate()));
            await(() -> r.listener.accepted() == 1, "inside the window");
            assertEquals(ReasonCode.QUARANTINED, r.issue(WEB_PEER));
        } finally {
            cleanup();
        }
    }

    /** A correctly signed notice with an arbitrary selector count, which {@link Notice} itself would refuse. */
    private static byte[] rawNotice(int selectors, PrivateKey key, long now) {
        WireWriter w = new WireWriter(1_024).ascii(NoticeCodec.MAGIC).id("eg-test").id(KEY_ID).i64(9).i64(now)
                .raw(new byte[Notice.NONCE_LENGTH]).u8(NoticeOperation.QUARANTINE.code()).i64(now + 60_000)
                .u8(selectors);
        for (int i = 0; i < selectors; i++) {
            w.u8(eastguard.common.SelectorType.IP.code()).ip(IpAddress.parse("10.0.3." + (i + 1)));
        }
        w.u8(ReasonCode.OPERATOR_ACTION.code());
        return w.raw(Ed25519.sign(key, w.toByteArray())).toByteArray();
    }

    public void testSelectorCountOutsideOneToEightIsRejected() throws Exception {
        try {
            Receiver r = synced("rx");
            long now = fx.clock.millis();
            inject(rawNotice(9, CONTROL.getPrivate(), now));
            inject(rawNotice(0, CONTROL.getPrivate(), now));
            await(() -> r.listener.rejectedTotal() == 2, "two datagrams rejected");
            assertEquals(2, r.listener.rejected("selector count out of range"));
            assertTrue(r.view().overlay().isEmpty(), "nothing applied");
            inject(rawNotice(8, CONTROL.getPrivate(), now)); // the upper bound itself is fine
            await(() -> r.listener.accepted() == 1, "eight selectors accepted");
            assertEquals(8, r.view().overlay().size());
        } finally {
            cleanup();
        }
    }

    // ---- delivery faults ----

    public void testOutOfOrderNoticesForDifferentSelectorsAreBothKept() throws Exception {
        try {
            Receiver r = synced("rx");
            transport.hold();
            long a = quarantine(WEB);
            long b = quarantine(API);
            await(() -> sender.stats().datagrams() == 6, "both notices sent");
            assertEquals(6, transport.releaseHeld(true)); // newest first: B's copies arrive before A's
            await(() -> r.listener.accepted() == 6, "all copies verified");
            assertEquals(Set.of(WEB, API), r.view().overlay());
            assertEquals(b, r.view().newestKnownRevision());
            assertTrue(a < b, "A is older");
            assertEquals(ReasonCode.QUARANTINED, r.issue(WEB_PEER)); // A was not discarded because B came first
        } finally {
            cleanup();
        }
    }

    public void testOldNoticeArrivingLateDoesNotRollStateBack() throws Exception {
        try {
            Receiver r = synced("rx");
            long q = quarantine(WEB);
            long rel = release(WEB);
            await(() -> r.listener.accepted() == 6, "both notices delivered");
            assertTrue(r.sync.syncOnce(), "caught up");
            assertEquals(rel, r.view().snapshot().revision());
            assertEquals(ReasonCode.OK, r.issue(WEB_PEER));
            // ...then replay the old QUARANTINE (a late copy or a capture inside the 30 s window).
            Notice old = notice(q, NoticeOperation.QUARANTINE, fx.clock.millis(), List.of(WEB));
            inject(NoticeCodec.encode(old, CONTROL.getPrivate()));
            await(() -> r.listener.accepted() == 7, "replay verified");
            assertTrue(r.sync.noticeStats().stale() >= 1, "ignored as old news");
            assertTrue(r.view().overlay().isEmpty(), "no overlay from an old notice");
            assertEquals(ReasonCode.OK, r.issue(WEB_PEER));
        } finally {
            cleanup();
        }
    }

    public void testLostNoticeConvergesThroughSync() throws Exception {
        try {
            Receiver r = synced("rx");
            transport.dropNext(QuarantineSender.COPIES); // the whole notice is lost
            long rev = quarantine(WEB);
            await(() -> sender.stats().datagrams() == 3, "sent");
            assertEquals(3, transport.dropped());
            assertEquals(0, r.listener.received());
            assertEquals(ReasonCode.OK, r.issue(WEB_PEER)); // unknown until the next poll ...
            assertTrue(r.sync.syncOnce(), "poll");
            assertEquals(rev, r.view().snapshot().revision());
            assertEquals(ReasonCode.QUARANTINED, r.issue(WEB_PEER)); // ... which converges
            nanos.addAndGet(6 * SEC); // and if the control plane were unreachable, state would go stale instead
            assertFalse(r.view().usable(), "fail closed after maxAge");
        } finally {
            cleanup();
        }
    }

    public void testDuplicatesAndDelaysAcrossThreeReceiversConverge() throws Exception {
        try {
            Receiver[] rx = {synced("rx-1"), synced("rx-2"), synced("rx-3")};
            transport.duplicate(2); // 6 datagrams per receiver for one notice
            transport.delay(Duration.ofMillis(30));
            quarantine(WEB);
            for (Receiver r : rx) {
                await(() -> r.listener.accepted() == 6, "six copies at " + r.sync);
                assertEquals(1, r.sync.noticeStats().accepted());
                assertEquals(5, r.sync.noticeStats().duplicates());
                assertEquals(List.of(Set.of(WEB)), r.newlyBlocked);
                assertEquals(ReasonCode.QUARANTINED, r.issue(WEB_PEER));
            }
        } finally {
            cleanup();
        }
    }

    public void testReceiverRestartConvergesAndIgnoresReplayedNotices() throws Exception {
        try {
            Receiver r = synced("rx");
            long rev = quarantine(WEB);
            await(() -> r.listener.accepted() == 3, "applied");
            r.close(); // restart: all local state, including the overlay, is gone

            Receiver again = new Receiver("rx-restarted");
            assertFalse(again.view().usable(), "no admissions before the first sync");
            // A copy of the old notice arrives before the first sync: no key is trusted yet, so it is held.
            inject(NoticeCodec.encode(notice(rev, NoticeOperation.QUARANTINE, fx.clock.millis(), List.of(WEB)),
                    CONTROL.getPrivate()));
            await(() -> again.listener.rejected("untrusted control key") == 1, "held until keys are known");
            assertTrue(again.sync.syncOnce(), "first sync after restart");
            assertEquals(ReasonCode.QUARANTINED, again.issue(WEB_PEER)); // from the snapshot
            await(() -> again.listener.accepted() == 1, "held notice re-verified with the synced key");
            assertEquals(1, again.sync.noticeStats().stale()); // covered by the snapshot: no overlay
            assertTrue(again.view().overlay().isEmpty(), "overlay empty");
        } finally {
            cleanup();
        }
    }

    // ---- reconciliation ----

    public void testReleaseNeverClearsABlockWithoutACoveringSnapshot() throws Exception {
        try {
            Receiver r = synced("rx");
            long q = quarantine(WEB);
            await(() -> r.listener.accepted() == 3, "quarantine applied");
            SyncResponse beforeRelease = cp.sync(new Dto.SyncRequest(fx.cred("gw-app-02"), 0)); // revision q
            long rel = release(WEB);
            await(() -> r.listener.accepted() == 6, "release verified");
            assertEquals(rel, r.sync.noticeStats().newest());
            assertEquals(ReasonCode.QUARANTINED, r.issue(WEB_PEER)); // the RELEASE alone cleared nothing

            frozen.set(beforeRelease); // a slow or lagging reply: newer than installed, older than the notice
            nanos.addAndGet(4 * SEC);
            assertFalse(r.sync.syncOnce(), "older than the newest notice: not renewing");
            assertEquals(q, r.view().snapshot().revision()); // installed (authoritative for its revision) ...
            assertTrue(r.view().overlay().isEmpty(), "... and it covers the quarantine overlay");
            assertEquals(ReasonCode.QUARANTINED, r.issue(WEB_PEER)); // still blocked, now by the snapshot
            assertEquals(1, r.sync.noticeStats().behindNotice());
            nanos.addAndGet((long) (1.5 * SEC));
            assertFalse(r.view().usable(), "freshness was not renewed by the old reply");

            frozen.set(null);
            assertTrue(r.sync.syncOnce(), "covering snapshot");
            assertEquals(rel, r.view().snapshot().revision());
            assertEquals(ReasonCode.OK, r.issue(WEB_PEER)); // cleared by authoritative state only
        } finally {
            cleanup();
        }
    }

    public void testUnchangedReplyBelowTheNewestNoticeDoesNotRenew() throws Exception {
        try {
            Receiver r = synced("rx");
            long installed = r.view().snapshot().revision();
            frozen.set(new SyncResponse(null, null, installed, true, null)); // "nothing changed" from a lagging source
            quarantine(API);
            await(() -> r.listener.accepted() == 3, "notice applied");
            nanos.addAndGet(4 * SEC);
            assertFalse(r.sync.syncOnce(), "ack older than the notice");
            nanos.addAndGet(SEC + 1);
            assertFalse(r.view().usable(), "stale: the ack did not renew");
        } finally {
            cleanup();
        }
    }

    public void testCatchingUpPausesNewIssuanceButNotUnrelatedSessions() throws Exception {
        try {
            Receiver r = synced("rx");
            Lease l = lease(1);
            quarantine(API); // unrelated to web-01
            await(() -> r.listener.accepted() == 3, "notice applied");
            assertTrue(r.view().catchingUp(), "a newer revision is known");
            assertEquals(ReasonCode.NOT_READY, r.issue(WEB_PEER)); // paused, not denied by policy
            assertEquals(ReasonCode.NOT_READY, evaluator.admit(r.view(), WEB_PEER, "app-02",
                    LeaseCodec.issue(l, Fixtures.LEASE_KEYS.getPrivate())).reason());
            assertEquals(ReasonCode.OK, evaluator.continueSession(r.view(), WEB_PEER, "app-02", l).reason());
            Peer api = new Peer("api-01", API_LEAF, OTHER_IP);
            assertEquals(ReasonCode.QUARANTINED, evaluator.continueSession(r.view(), api, "app-02", l).reason());
            assertTrue(r.sync.syncOnce(), "caught up");
            assertFalse(r.view().catchingUp(), "caught up");
            assertEquals(ReasonCode.OK, r.issue(WEB_PEER));
        } finally {
            cleanup();
        }
    }

    public void testIdentityAndIpSelectorsAreIndependent() throws Exception {
        try {
            Receiver r = synced("rx");
            quarantine(WEB);
            quarantine(WEB_IP_SEL);
            await(() -> r.listener.accepted() == 6, "both applied");
            Peer webElsewhere = new Peer("web-01", Fixtures.LEAF, OTHER_IP);
            Peer apiAtWebIp = new Peer("api-01", API_LEAF, WEB_IP);
            Peer apiElsewhere = new Peer("api-01", API_LEAF, OTHER_IP);
            assertEquals(ReasonCode.QUARANTINED, r.issue(webElsewhere)); // identity selector
            assertEquals(ReasonCode.QUARANTINED, r.issue(apiAtWebIp)); // IP selector
            assertTrue(r.sync.syncOnce(), "sync");
            assertEquals(ReasonCode.POLICY_DENY, r.issue(apiElsewhere)); // neither selector: ordinary policy

            release(WEB); // releasing the identity does not cancel the IP restriction
            await(() -> r.listener.accepted() == 9, "release verified");
            assertTrue(r.sync.syncOnce(), "covering snapshot");
            assertEquals(ReasonCode.OK, r.issue(webElsewhere));
            assertEquals(ReasonCode.QUARANTINED, r.issue(WEB_PEER)); // still at the quarantined IP
            assertEquals(ReasonCode.QUARANTINED, r.issue(apiAtWebIp));
        } finally {
            cleanup();
        }
    }

    private Lease lease(long issuedAtRevision) {
        long now = fx.clock.millis();
        return new Lease("eg-test", "lease-k1", "web-01", "app-02", WEB_IP, Fixtures.LEAF, now, now + 60_000,
                Fixtures.JTI, issuedAtRevision);
    }

    public void testReleasedWorkloadsOldLeaseIsRejectedByTheWatermarkAndANewLeaseWorks() throws Exception {
        try {
            Receiver r = synced("rx");
            byte[] old = LeaseCodec.issue(lease(r.view().snapshot().revision()), Fixtures.LEASE_KEYS.getPrivate());
            assertEquals(ReasonCode.OK, evaluator.admit(r.view(), WEB_PEER, "app-02", old).reason());
            quarantine(WEB);
            long rel = release(WEB);
            await(() -> r.listener.accepted() == 6, "both notices");
            assertTrue(r.sync.syncOnce(), "covering snapshot");
            assertEquals(rel, (long) r.view().snapshot().releaseWatermarks().get(WEB));
            assertEquals(ReasonCode.LEASE_SUPERSEDED, evaluator.admit(r.view(), WEB_PEER, "app-02", old).reason());
            byte[] fresh = LeaseCodec.issue(lease(rel), Fixtures.LEASE_KEYS.getPrivate());
            assertEquals(ReasonCode.OK, evaluator.admit(r.view(), WEB_PEER, "app-02", fresh).reason());
        } finally {
            cleanup();
        }
    }

    public void testSnapshotPublishesControlKeysSeparatelyFromLeaseKeys() throws Exception {
        try {
            EnforcementSnapshot s = SnapshotCodec.decode(SnapshotCodec.encode(cp.snapshot()));
            assertEquals(Set.of(KEY_ID), s.controlKeys().keySet());
            assertEquals(Set.of("lease-k1"), s.tokenKeys().keySet());
            assertNull(s.controlKey("lease-k1"));
            assertNull(s.verificationKey(KEY_ID));
            assertArrayEquals(Ed25519.rawPublicKey(CONTROL.getPublic()), Ed25519.rawPublicKey(s.controlKey(KEY_ID)));
        } finally {
            cleanup();
        }
    }

    public void testMulticastSettingsRequireAGroupAndAnExplicitInterface() throws Exception {
        try {
            java.util.Properties p = new java.util.Properties();
            assertNull(MulticastSettings.from(eastguard.common.Config.of(p, "test"))); // off: polling only
            p.setProperty("multicast.group", "239.20.20.20");
            assertThrows(IllegalArgumentException.class, () -> MulticastSettings.from(eastguard.common.Config.of(p, "t")));
            p.setProperty("multicast.interface", "127.0.0.1");
            MulticastSettings ms = MulticastSettings.from(eastguard.common.Config.of(p, "test"));
            assertEquals(4446, ms.port());
            assertEquals(1, ms.ttl());
            p.setProperty("multicast.group", "10.0.0.1");
            assertThrows(IllegalArgumentException.class, () -> MulticastSettings.from(eastguard.common.Config.of(p, "t")));
            MulticastSettings nowhere = new MulticastSettings(IpAddress.parse("239.20.20.20"), 4446, "192.0.2.123", 1);
            assertThrows(IOException.class, nowhere::resolveInterface); // TEST-NET address on no interface
        } finally {
            cleanup();
        }
    }

    // ---- real multicast qualification (spec §9.1 "verify interface support and multi-receiver binding") ----

    /**
     * Three receivers on one host through {@link MulticastTransport} on the loopback interface. Prints SKIP rather
     * than failing where the OS or a firewall gives no local multicast; the in-memory tests above still cover loss
     * and reordering. Uses a free port, not 4446, so it cannot disturb a running demo.
     */
    public void testRealMulticastLoopbackQualification() throws Exception {
        try {
            int port;
            try (DatagramSocket probe = new DatagramSocket(0)) {
                port = probe.getLocalPort();
            }
            MulticastSettings ms = new MulticastSettings(IpAddress.parse(MulticastSettings.DEFAULT_GROUP), port,
                    "127.0.0.1", 1);
            MulticastTransport mt;
            List<NoticeTransport.Receiver> rx = new ArrayList<>();
            try {
                mt = new MulticastTransport(ms);
                for (int i = 0; i < 3; i++) {
                    rx.add(mt.join());
                }
            } catch (IOException e) {
                System.out.println("SKIP QuarantineBusTest.testRealMulticastLoopbackQualification: " + e.getMessage());
                rx.forEach(NoticeTransport.Receiver::close);
                return;
            }
            try {
                byte[] d = NoticeCodec.encode(notice(9, NoticeOperation.QUARANTINE, fx.clock.millis(), List.of(WEB)),
                        CONTROL.getPrivate());
                mt.send(d);
                byte[] buf = new byte[NoticeTransport.MAX_DATAGRAM + 1];
                int got = 0;
                for (NoticeTransport.Receiver r : rx) {
                    int n = r.receive(buf, 2_000);
                    if (n == d.length) {
                        Notice decoded = NoticeCodec.decode(buf, 0, n, "eg-test", k -> CONTROL.getPublic(), fx.clock);
                        assertEquals(List.of(WEB), decoded.selectors());
                        got++;
                    }
                }
                if (got == 0) {
                    System.out.println("SKIP QuarantineBusTest.testRealMulticastLoopbackQualification: no loopback "
                            + "multicast delivery on " + mt.networkInterface().getName());
                    return;
                }
                assertEquals(3, got); // all receivers or none: a partial delivery is a real failure
            } finally {
                rx.forEach(NoticeTransport.Receiver::close);
                mt.close();
            }
        } finally {
            cleanup();
        }
    }
}
