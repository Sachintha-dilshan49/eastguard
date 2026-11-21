package eastguard.bus;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Sender-side fault injection over any {@link NoticeTransport}, including real multicast: drop the next datagrams,
 * send each datagram several times, or hold datagrams and release them later, optionally newest first. Receivers
 * join the underlying transport unchanged. Used by {@code DemoM4_Multicast}; {@link MemoryTransport} has the same
 * faults built in (plus delay and per-receiver loss) for unit tests.
 */
public final class FaultyTransport implements NoticeTransport {
    private final NoticeTransport delegate;
    private final List<byte[]> held = new ArrayList<>(); // guarded by this
    private int dropNext; // guarded by this
    private int copies = 1; // guarded by this
    private boolean holding; // guarded by this
    private long dropped; // guarded by this

    public FaultyTransport(NoticeTransport delegate) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
    }

    public synchronized void dropNext(int datagrams) {
        dropNext = Math.max(0, datagrams);
    }

    public synchronized void duplicate(int n) {
        if (n < 1 || n > 16) {
            throw new IllegalArgumentException("copies 1..16");
        }
        copies = n;
    }

    public synchronized void hold() {
        holding = true;
    }

    public synchronized long dropped() {
        return dropped;
    }

    /** Stops holding and sends what was held, newest first if {@code reverse}. Returns how many datagrams. */
    public int releaseHeld(boolean reverse) throws IOException {
        List<byte[]> out;
        synchronized (this) {
            holding = false;
            out = new ArrayList<>(held);
            held.clear();
        }
        if (reverse) {
            Collections.reverse(out);
        }
        for (byte[] d : out) {
            delegate.send(d);
        }
        return out.size();
    }

    @Override
    public void send(byte[] datagram) throws IOException {
        int n;
        synchronized (this) {
            if (dropNext > 0) {
                dropNext--;
                dropped++;
                return;
            }
            if (holding) {
                held.add(datagram.clone());
                return;
            }
            n = copies;
        }
        for (int i = 0; i < n; i++) {
            delegate.send(datagram);
        }
    }

    @Override
    public Receiver join() throws IOException {
        return delegate.join();
    }
}
