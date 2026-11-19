package eastguard.gateway;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

/**
 * An {@link SSLEngine} over a non-blocking {@link SocketChannel} (spec §4.3).
 *
 * <p><b>Threading.</b> Confined to the gateway selector thread. The one exception is
 * {@link #takeDelegatedTasks()}: the returned batch runs on the bounded TLS task executor, and the caller must
 * not call any other method of this object until the selector has been told that the batch finished. That keeps
 * the engine from ever being driven by two threads at once.
 *
 * <p><b>Buffers</b> are allocated once, bounded, and kept in write mode (data in {@code [0, position)}):
 * <ul>
 *   <li>{@code netIn}: ciphertext read from the socket, one maximum-size record;</li>
 *   <li>{@code netOut}: ciphertext waiting for the socket, one maximum-size record;</li>
 *   <li>{@code appIn}: plaintext unwrapped from the peer, at least one maximum-size record.</li>
 * </ul>
 *
 * <p><b>Closure.</b> The peer's {@code close_notify} sets {@link #inboundDone()}. A TCP end of stream without
 * one is truncation and {@link #unwrap()} throws once no complete record is left. {@link #closeOutbound()}
 * queues our {@code close_notify} (TLS 1.3 half-close: inbound stays readable).
 */
final class TlsChannel {
    /** What the handshake needs next. {@code WAIT}: socket I/O (read, and write if output is pending). */
    enum Handshake { DONE, WAIT, TASK }

    /** The peer's TCP stream ended without {@code close_notify}: an error, never a clean end of stream. */
    static final class TruncatedException extends SSLException {
        private static final long serialVersionUID = 1L;

        TruncatedException() {
            super("connection closed without close_notify (truncated)");
        }
    }

    private static final ByteBuffer EMPTY = ByteBuffer.allocate(0);
    /** Upper bound on engine steps per {@link #handshake()} call: limits work per selected key. */
    private static final int MAX_HANDSHAKE_STEPS = 32;

    private final SocketChannel ch;
    private final SSLEngine engine;
    private final int packetSize;
    private final ByteBuffer netIn;
    private final ByteBuffer netOut;
    private final ByteBuffer appIn;
    private boolean netEof;
    private boolean inboundDone;

    /**
     * @param appCapacity plaintext buffer size; raised to the session's application buffer size if smaller
     */
    TlsChannel(SocketChannel ch, SSLEngine engine, int appCapacity) throws SSLException {
        this.ch = Objects.requireNonNull(ch, "ch");
        this.engine = Objects.requireNonNull(engine, "engine");
        SSLSession s = engine.getSession();
        this.packetSize = s.getPacketBufferSize();
        this.netIn = ByteBuffer.allocate(packetSize);
        this.netOut = ByteBuffer.allocate(packetSize);
        this.appIn = ByteBuffer.allocate(Math.max(appCapacity, s.getApplicationBufferSize()));
        engine.beginHandshake();
    }

    /** Bytes of heap this channel holds in buffers, for the gateway's buffer budget. */
    static long bufferBytes(SSLEngine probe, int appCapacity) {
        SSLSession s = probe.getSession();
        return 2L * s.getPacketBufferSize() + Math.max(appCapacity, s.getApplicationBufferSize());
    }

    SSLSession session() {
        return engine.getSession();
    }

    SocketChannel channel() {
        return ch;
    }

    /** Plaintext received from the peer, in write mode. The caller consumes it with flip()/compact(). */
    ByteBuffer appIn() {
        return appIn;
    }

    boolean inboundDone() {
        return inboundDone;
    }

    boolean outboundDone() {
        return engine.isOutboundDone();
    }

    /** The socket reached end of stream. Before {@link #inboundDone()} this is truncation. */
    boolean netEof() {
        return netEof;
    }

    boolean canReadNet() {
        return !netEof && !inboundDone && netIn.hasRemaining();
    }

    boolean hasPendingOutput() {
        return netOut.position() > 0;
    }

    int pendingOutput() {
        return netOut.position();
    }

    /** True if the engine wants to send something by itself (e.g. a KeyUpdate response). */
    boolean wantsWrap() {
        return engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP;
    }

    boolean wantsTask() {
        return engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK;
    }

    /**
     * Drives the handshake as far as possible without blocking. Reads from the socket when the engine needs
     * input, writes handshake output as it is produced. Throws on any TLS failure or on end of stream.
     */
    Handshake handshake() throws IOException {
        for (int step = 0; step < MAX_HANDSHAKE_STEPS; step++) {
            switch (engine.getHandshakeStatus()) {
                case NOT_HANDSHAKING, FINISHED -> {
                    return Handshake.DONE;
                }
                case NEED_TASK -> {
                    return Handshake.TASK;
                }
                case NEED_WRAP -> {
                    if (netOut.remaining() < packetSize) {
                        flush();
                        if (netOut.remaining() < packetSize) {
                            return Handshake.WAIT;
                        }
                    }
                    SSLEngineResult r = engine.wrap(EMPTY, netOut);
                    if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                        flush(); // best effort: send the alert the engine just produced
                        throw new SSLException("TLS handshake aborted");
                    }
                    if (r.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        return Handshake.WAIT;
                    }
                    flush();
                }
                case NEED_UNWRAP, NEED_UNWRAP_AGAIN -> {
                    SSLEngineResult r = unwrapOnce();
                    switch (r.getStatus()) {
                        case OK -> {
                            // loop: the engine's status tells us what comes next
                        }
                        case BUFFER_UNDERFLOW -> {
                            if (!netIn.hasRemaining()) {
                                throw new SSLException("TLS record larger than the receive buffer");
                            }
                            int n = readNet();
                            if (n < 0) {
                                throw new EOFException("connection closed during the TLS handshake");
                            }
                            if (n == 0) {
                                return Handshake.WAIT;
                            }
                        }
                        case CLOSED -> throw new SSLException("peer closed the connection during the TLS handshake");
                        case BUFFER_OVERFLOW -> throw new SSLException("unexpected application data during the handshake");
                    }
                }
            }
        }
        return Handshake.WAIT; // work limit reached; the caller re-arms interest and comes back
    }

    /**
     * Removes the engine's pending delegated tasks as one batch for the TLS task executor. See the class comment:
     * no other method may be called until the batch has completed.
     */
    Runnable takeDelegatedTasks() {
        List<Runnable> tasks = new ArrayList<>(2);
        Runnable t;
        while ((t = engine.getDelegatedTask()) != null) {
            tasks.add(t);
        }
        return () -> {
            for (Runnable task : tasks) {
                task.run();
            }
        };
    }

    /** One socket read into {@code netIn}, if there is room. Returns bytes read, 0, or -1 at end of stream. */
    int readNet() throws IOException {
        if (netEof || !netIn.hasRemaining()) {
            return netEof ? -1 : 0;
        }
        int n = ch.read(netIn);
        if (n < 0) {
            netEof = true;
        }
        return n;
    }

    /**
     * Unwraps buffered records into {@code appIn} until input runs out, {@code appIn} is full, the peer's
     * {@code close_notify} arrives, or the engine needs a task or a wrap. Returns true if anything was consumed.
     *
     * @throws SSLException on a protocol error, or on truncation (end of stream without {@code close_notify})
     */
    boolean unwrap() throws SSLException {
        boolean progress = false;
        while (!inboundDone) {
            SSLEngineResult r = unwrapOnce();
            switch (r.getStatus()) {
                case CLOSED -> {
                    inboundDone = true;
                    return true;
                }
                case BUFFER_OVERFLOW -> {
                    return progress; // appIn full: the consumer must drain it first
                }
                case BUFFER_UNDERFLOW -> {
                    if (!netIn.hasRemaining()) {
                        throw new SSLException("TLS record larger than the receive buffer");
                    }
                    if (netEof) {
                        throw new TruncatedException();
                    }
                    return progress;
                }
                case OK -> {
                    if (r.bytesConsumed() == 0 && r.bytesProduced() == 0) {
                        return progress;
                    }
                    progress = true;
                }
            }
            SSLEngineResult.HandshakeStatus hs = r.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK || hs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                return progress;
            }
        }
        return progress;
    }

    private SSLEngineResult unwrapOnce() throws SSLException {
        netIn.flip();
        try {
            return engine.unwrap(netIn, appIn);
        } finally {
            netIn.compact();
        }
    }

    /**
     * Encrypts plaintext from {@code src} (read mode) into {@code netOut} while a whole record fits. With an
     * empty {@code src} this produces whatever the engine wants to send on its own. Returns bytes consumed.
     *
     * <p>Once the outbound side is closed nothing more is consumed; the engine may still emit its own
     * {@code close_notify}. That happens after {@link #closeOutbound()}, and also when the peer closes both
     * directions: a JDK TLS 1.3 client's {@code close()} sends {@code user_canceled} then {@code close_notify},
     * and the engine answers by closing its outbound side. Callers check {@link #outboundDone()}.
     */
    int wrap(ByteBuffer src) throws SSLException {
        int consumed = 0;
        while (netOut.remaining() >= packetSize && (src.hasRemaining() || wantsWrap())) {
            SSLEngineResult r = engine.wrap(src, netOut);
            consumed += r.bytesConsumed();
            if (r.getStatus() != SSLEngineResult.Status.OK
                    || (r.bytesConsumed() == 0 && r.bytesProduced() == 0)) {
                break; // CLOSED, BUFFER_OVERFLOW, or nothing to do
            }
        }
        return consumed;
    }

    /** Writes pending ciphertext without blocking. Returns bytes written. */
    int flush() throws IOException {
        if (netOut.position() == 0) {
            return 0;
        }
        netOut.flip();
        try {
            return ch.write(netOut);
        } finally {
            netOut.compact();
        }
    }

    /**
     * Queues our {@code close_notify} after any pending output and tries to write it. Returns true once it has
     * been fully written. Safe to call repeatedly.
     */
    boolean closeOutbound() throws IOException {
        if (!engine.isOutboundDone()) {
            engine.closeOutbound();
        }
        while (!engine.isOutboundDone()) {
            if (netOut.remaining() < packetSize) {
                flush();
                if (netOut.remaining() < packetSize) {
                    return false;
                }
            }
            SSLEngineResult r = engine.wrap(EMPTY, netOut);
            if (r.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                return false;
            }
            if (r.bytesProduced() == 0 && !engine.isOutboundDone()) {
                break; // nothing more to produce (should not happen); do not spin
            }
        }
        flush();
        return !hasPendingOutput();
    }

    /**
     * Best effort after a handshake failure: let the engine emit its alert and write it once. Never throws. Must
     * not be called while delegated tasks are running.
     */
    void sendAlertQuietly() {
        try {
            engine.closeOutbound();
            if (netOut.remaining() >= packetSize) {
                engine.wrap(EMPTY, netOut);
            }
            flush();
        } catch (IOException | RuntimeException ignored) {
            // the connection is being torn down anyway
        }
    }
}
