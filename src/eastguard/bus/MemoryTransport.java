package eastguard.bus;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-process notice transport for tests and demos, with fault injection: drop, duplicate, delay, and hold-then-
 * release (optionally newest first, i.e. reordered). Faults apply per <em>datagram</em>; the
 * {@link QuarantineSender} sends each notice {@link QuarantineSender#COPIES} times, so losing a whole notice means
 * dropping that many datagrams. Thread-safe.
 */
public final class MemoryTransport implements NoticeTransport, AutoCloseable {
    private static final byte[] CLOSED = new byte[0];
    private static final int QUEUE = 1_024;

    private final List<Endpoint> endpoints = new CopyOnWriteArrayList<>();
    private final Object lock = new Object();
    private final List<byte[]> held = new ArrayList<>(); // guarded by lock
    private final AtomicLong sent = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private int dropNext; // guarded by lock
    private int copies = 1; // guarded by lock
    private boolean holding; // guarded by lock
    private long delayMillis; // guarded by lock
    private ScheduledExecutorService timer; // guarded by lock

    /** Drops the next {@code n} datagrams sent, for every receiver. */
    public void dropNext(int n) {
        synchronized (lock) {
            dropNext = Math.max(0, n);
        }
    }

    /** Delivers every datagram {@code n} times (1 = normal). */
    public void duplicate(int n) {
        if (n < 1 || n > 16) {
            throw new IllegalArgumentException("copies 1..16");
        }
        synchronized (lock) {
            copies = n;
        }
    }

    /** Delays every delivery by {@code d} (zero = immediate). */
    public void delay(Duration d) {
        synchronized (lock) {
            delayMillis = Math.max(0, d.toMillis());
        }
    }

    /** Buffers datagrams instead of delivering them until {@link #releaseHeld}. */
    public void hold() {
        synchronized (lock) {
            holding = true;
        }
    }

    /** Stops holding and delivers what was held, newest first if {@code reverse}. Returns how many. */
    public int releaseHeld(boolean reverse) {
        List<byte[]> out;
        synchronized (lock) {
            holding = false;
            out = new ArrayList<>(held);
            held.clear();
        }
        if (reverse) {
            Collections.reverse(out);
        }
        out.forEach(this::deliver);
        return out.size();
    }

    public long sent() {
        return sent.get();
    }

    public long dropped() {
        return dropped.get();
    }

    @Override
    public void send(byte[] datagram) throws IOException {
        if (datagram.length > MAX_DATAGRAM) {
            throw new IOException("datagram over " + MAX_DATAGRAM + " bytes");
        }
        byte[] copy = datagram.clone();
        sent.incrementAndGet();
        synchronized (lock) {
            if (dropNext > 0) {
                dropNext--;
                dropped.incrementAndGet();
                return;
            }
            if (holding) {
                held.add(copy);
                return;
            }
        }
        deliver(copy);
    }

    private void deliver(byte[] datagram) {
        int n;
        long delay;
        ScheduledExecutorService t = null;
        synchronized (lock) {
            n = copies;
            delay = delayMillis;
            if (delay > 0) {
                if (timer == null) {
                    ScheduledThreadPoolExecutor e = new ScheduledThreadPoolExecutor(1, r -> {
                        Thread th = new Thread(r, "memory-transport-delay");
                        th.setDaemon(true);
                        return th;
                    });
                    timer = e;
                }
                t = timer;
            }
        }
        for (int i = 0; i < n; i++) {
            for (Endpoint e : endpoints) {
                if (t != null) {
                    t.schedule(() -> e.offer(datagram), delay, TimeUnit.MILLISECONDS);
                } else {
                    e.offer(datagram);
                }
            }
        }
    }

    @Override
    public Endpoint join() {
        Endpoint e = new Endpoint();
        endpoints.add(e);
        return e;
    }

    @Override
    public void close() {
        synchronized (lock) {
            if (timer != null) {
                timer.shutdownNow();
                timer = null;
            }
        }
        endpoints.forEach(Endpoint::close);
    }

    /** One joined receiver; can also lose datagrams on its own. */
    public final class Endpoint implements Receiver {
        private final LinkedBlockingQueue<byte[]> queue = new LinkedBlockingQueue<>(QUEUE);
        private final AtomicInteger dropNext = new AtomicInteger();
        private volatile boolean closed;

        /** Drops the next {@code n} datagrams for this receiver only. */
        public void dropNext(int n) {
            dropNext.set(Math.max(0, n));
        }

        void offer(byte[] d) {
            if (closed) {
                return;
            }
            if (dropNext.getAndUpdate(v -> v > 0 ? v - 1 : 0) > 0 || !queue.offer(d)) {
                dropped.incrementAndGet();
            }
        }

        @Override
        public int receive(byte[] buf, int timeoutMillis) throws IOException {
            if (closed) {
                return -1;
            }
            byte[] d;
            try {
                d = queue.poll(Math.max(1, timeoutMillis), TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return -1;
            }
            if (d == null) {
                return 0;
            }
            if (d == CLOSED || closed) {
                return -1;
            }
            System.arraycopy(d, 0, buf, 0, Math.min(d.length, buf.length));
            return d.length;
        }

        @Override
        public void close() {
            closed = true;
            endpoints.remove(this);
            queue.clear();
            queue.offer(CLOSED);
        }
    }
}
