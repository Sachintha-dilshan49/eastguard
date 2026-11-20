package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Bytes;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.Policy;
import eastguard.common.SnapshotCodec;
import eastguard.control.Dto;
import eastguard.control.Dto.ErrorCode;
import eastguard.control.Dto.SyncResponse;
import eastguard.control.StateSync;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Freshness rules of the enforcement-side sync, with a scripted control plane and a fake monotonic clock. */
public final class StateSyncTest {
    private static final Logger QUIET = Logger.getLogger("eastguard.control");
    private static final long SEC = 1_000_000_000L;

    private final AtomicLong now = new AtomicLong(1_000 * SEC);
    private final Deque<Object> replies = new ArrayDeque<>(); // SyncResponse or IOException
    private final AtomicLong callDurationNanos = new AtomicLong();
    private final AtomicLong lastKnown = new AtomicLong(-1);
    private final StateSync sync;

    public StateSyncTest() {
        QUIET.setLevel(Level.OFF); // rejected replies log WARNING on purpose
        StateSync.Source source = known -> {
            lastKnown.set(known);
            now.addAndGet(callDurationNanos.get()); // the call takes this long
            Object r = replies.removeFirst();
            if (r instanceof IOException e) {
                throw e;
            }
            return (SyncResponse) r;
        };
        sync = new StateSync("test", source, new StateSync.Settings("eg-test", Duration.ofSeconds(1),
                Duration.ofSeconds(5)), now::get);
    }

    private static EnforcementSnapshot snapshot(long revision, String cluster) {
        EnforcementSnapshot b = ControlFixtures.initial(Fixtures.LEASE_KEYS.getPublic());
        Policy p = b.policy();
        return new EnforcementSnapshot(cluster, revision, p, b.workloads(), b.services(), b.restrictions(),
                b.leaseReductions(), b.releaseWatermarks(), b.tokenKeys(), b.revokedKeyIds());
    }

    private static SyncResponse full(long revision) {
        return new SyncResponse(null, null, revision, false, Bytes.copyOf(SnapshotCodec.encode(snapshot(revision, "eg-test"))));
    }

    private static SyncResponse ack(long revision) {
        return new SyncResponse(null, null, revision, true, null);
    }

    private void advance(double seconds) {
        now.addAndGet((long) (seconds * SEC));
    }

    private boolean usable() {
        return sync.get().usable();
    }

    public void testNoAdmissionsBeforeTheFirstValidSync() {
        assertFalse(usable(), "not ready before any sync");
        replies.add(new IOException("control plane down"));
        assertFalse(sync.syncOnce(), "failure");
        assertFalse(usable(), "still not ready");
        replies.add(full(3));
        assertTrue(sync.syncOnce(), "first sync");
        assertTrue(usable(), "ready");
        assertEquals(0, lastKnown.get()); // the first request asks for a full snapshot
    }

    public void testFreshnessRunsFromRequestStartNotFromTheReply() {
        callDurationNanos.set(2 * SEC); // a slow reply
        replies.add(full(3));
        long start = now.get();
        sync.syncOnce();
        assertEquals(start + 2 * SEC, now.get());
        advance(2.9); // 4.9 s after the request started
        assertTrue(usable(), "fresh within 5 s of the request start");
        advance(0.1);
        assertFalse(usable(), "stale exactly 5 s after the request start, although the reply came at 2 s");
    }

    public void testOnlyAnExactAcknowledgementRenews() {
        replies.add(full(3));
        sync.syncOnce();
        advance(4);
        replies.add(ack(3));
        assertTrue(sync.syncOnce(), "ack of the installed revision renews");
        assertEquals(3, lastKnown.get());
        advance(4.5);
        assertTrue(usable(), "renewed");
        replies.add(ack(2)); // a stale or replayed acknowledgement
        assertFalse(sync.syncOnce(), "mismatched ack rejected");
        advance(1);
        assertFalse(usable(), "not renewed by the stale acknowledgement");
    }

    public void testOlderSnapshotIsNeitherInstalledNorRenewing() {
        replies.add(full(5));
        sync.syncOnce();
        advance(4);
        replies.add(full(4)); // e.g. a control plane restored from an old backup
        assertFalse(sync.syncOnce(), "older snapshot rejected");
        assertEquals(5, sync.get().snapshot().revision());
        advance(1);
        assertFalse(usable(), "and it did not renew freshness");
    }

    public void testErrorsAndForeignOrCorruptSnapshotsDoNotRenew() {
        replies.add(full(3));
        sync.syncOnce();
        replies.add(SyncResponse.failure(ErrorCode.UNAVAILABLE, "journal failed"));
        replies.add(new SyncResponse(null, null, 4, false, Bytes.copyOf(SnapshotCodec.encode(snapshot(4, "other")))));
        replies.add(new SyncResponse(null, null, 4, false, Bytes.copyOf(new byte[] {1, 2, 3})));
        replies.add(new SyncResponse(null, null, 9, false, full(4).snapshot())); // revision disagrees
        replies.add(new IOException("timeout"));
        for (int i = 0; i < 5; i++) {
            assertFalse(sync.syncOnce(), "reply " + i + " must not renew");
        }
        assertEquals(3, sync.get().snapshot().revision());
        advance(5);
        assertFalse(usable(), "stale after 5 s of failures");
        assertEquals(3, sync.stats().rejected());
        assertEquals(2, sync.stats().failed());
    }

    public void testListenersRunOnlyForANewRevision() {
        AtomicInteger calls = new AtomicInteger();
        sync.addListener(calls::incrementAndGet);
        replies.add(full(3));
        replies.add(ack(3));
        replies.add(full(3));
        replies.add(full(4));
        for (int i = 0; i < 4; i++) {
            sync.syncOnce();
        }
        assertEquals(2, calls.get()); // revision 3 installed, then revision 4
        assertEquals(4, sync.get().snapshot().revision());
    }

    public void testBackgroundThreadPollsAndStops() throws Exception {
        StateSync live = new StateSync("live", known -> full(7), new StateSync.Settings("eg-test",
                Duration.ofMillis(20), Duration.ofSeconds(5)), System::nanoTime).start();
        try {
            long end = System.nanoTime() + 5 * SEC;
            while (live.stats().ok() < 3 && System.nanoTime() < end) {
                Thread.sleep(5);
            }
            assertTrue(live.stats().ok() >= 3, "polled repeatedly");
            assertTrue(live.get().usable(), "fresh");
        } finally {
            live.close();
        }
        assertEquals(Dto.ErrorCode.values().length, 4); // INVALID, UNAUTHORIZED, CONFLICT, UNAVAILABLE
    }
}
