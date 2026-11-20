package eastguard.detector;

import eastguard.common.TelemetryCodec;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * UDP telemetry listener (spec §5.3, §6.1). One platform thread receives into a buffer of
 * {@value TelemetryCodec#RECEIVE_BUFFER} bytes, so a datagram longer than {@value TelemetryCodec#MAX_DATAGRAM}
 * bytes fills the buffer and is rejected as oversize instead of being parsed truncated. Each datagram goes
 * through the {@link TelemetryVerifier}; only verified events reach {@code sink}, on this same thread, so the
 * verifier, the risk engine and the learning collector need no locking. {@code tick} runs on this thread too,
 * at least every 200 ms, for housekeeping (aging windows, flushing learning batches).
 */
public final class FlowReceiver implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(FlowReceiver.class.getName());
    private static final int TICK_MILLIS = 200;

    private final InetSocketAddress bind;
    private final TelemetryVerifier verifier;
    private final Consumer<TelemetryVerifier.Verified> sink;
    private final Runnable tick;
    private final LongSupplier nanos;
    private volatile DatagramSocket socket;
    private volatile boolean running;
    private Thread thread;

    public FlowReceiver(InetSocketAddress bind, TelemetryVerifier verifier, Consumer<TelemetryVerifier.Verified> sink,
            Runnable tick, LongSupplier nanos) {
        this.bind = Objects.requireNonNull(bind, "bind");
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.sink = Objects.requireNonNull(sink, "sink");
        this.tick = Objects.requireNonNull(tick, "tick");
        this.nanos = Objects.requireNonNull(nanos, "nanos");
    }

    public synchronized void start() throws IOException {
        if (thread != null) {
            throw new IllegalStateException("already started");
        }
        DatagramSocket s = new DatagramSocket(bind);
        s.setSoTimeout(TICK_MILLIS);
        socket = s;
        running = true;
        thread = Thread.ofPlatform().name("detector-udp").start(this::loop);
        LOG.info(() -> "telemetry receiver listening on udp " + s.getLocalSocketAddress());
    }

    public int port() {
        return socket.getLocalPort();
    }

    private void loop() {
        byte[] buf = new byte[TelemetryCodec.RECEIVE_BUFFER];
        DatagramPacket p = new DatagramPacket(buf, buf.length);
        long lastTick = nanos.getAsLong();
        while (running) {
            try {
                p.setLength(buf.length);
                socket.receive(p);
                handle(buf, p.getLength());
            } catch (SocketTimeoutException e) {
                // fall through to the tick
            } catch (IOException e) {
                if (running) {
                    LOG.log(Level.FINE, "receive failed", e);
                }
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "telemetry handling failed", e);
            }
            long now = nanos.getAsLong();
            if (now - lastTick >= TICK_MILLIS * 1_000_000L) {
                lastTick = now;
                try {
                    tick.run();
                } catch (RuntimeException e) {
                    LOG.log(Level.WARNING, "detector tick failed", e);
                }
            }
        }
    }

    /** Verifies one datagram and hands an accepted event to the sink. Package-private for direct tests. */
    void handle(byte[] buf, int length) {
        TelemetryVerifier.Outcome o = verifier.verify(buf, length, nanos.getAsLong());
        if (o.accepted()) {
            sink.accept(o.verified());
        } else {
            LOG.fine(() -> "telemetry datagram rejected: " + o.result());
        }
    }

    @Override
    public void close() {
        Thread t;
        synchronized (this) {
            running = false;
            t = thread;
        }
        DatagramSocket s = socket;
        if (s != null) {
            s.close();
        }
        if (t != null) {
            try {
                t.join(2_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
