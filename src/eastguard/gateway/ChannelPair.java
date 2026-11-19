package eastguard.gateway;

import eastguard.common.IpAddress;
import eastguard.common.Lease;
import eastguard.common.Peer;
import eastguard.common.SignedLease;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

/**
 * One client connection and, once admitted, its backend leg (spec §4.3). Confined to the selector thread; plain
 * fields, no locking.
 *
 * <pre>
 * ACCEPT -> TLS_HANDSHAKE -> READ_PREAMBLE -> AUTHORIZE -> CONNECT_BACKEND -> WRITE_REPLY -> RELAY -> CLOSED
 *                                                  \______________ REPLY_THEN_CLOSE (deny) ___/
 * </pre>
 *
 * <p>Relay buffers, in write mode:
 * <pre>
 * client --TLS--> netIn --unwrap--> appIn --write--> backend          (toBackend queue: appIn)
 * client <--TLS-- netOut <--wrap--  toClient <--read-- backend        (toClient queue: toClient + netOut)
 * </pre>
 * Reading a source pauses when its queue reaches the high-water mark and resumes at the low-water mark; a full
 * buffer also stops reads. {@code OP_WRITE} is set only while bytes wait for a destination.
 */
final class ChannelPair {
    enum State { TLS_HANDSHAKE, READ_PREAMBLE, AUTHORIZE, CONNECT_BACKEND, WRITE_REPLY, RELAY, REPLY_THEN_CLOSE, CLOSED }

    final TlsChannel tls;
    final SelectionKey clientKey;
    final IpAddress peerIp;
    final long reservedBytes;

    State state;
    /** {@code System.nanoTime()} deadline for the current pre-relay state. */
    long deadline;
    boolean taskRunning;
    long preambleAt;

    // Set at AUTHORIZE, used by the recheck and by session index commands.
    Peer peer;
    SignedLease signed;
    Lease lease;
    boolean outsideApprovedGraph;
    boolean indexed;

    SocketChannel backend;
    SelectionKey backendKey;
    ByteBuffer reply;

    // Relay.
    ByteBuffer toClient;
    long lastActivity;
    long sessionDeadline;
    boolean clientPaused;
    boolean backendPaused;
    boolean backendEof;
    boolean backendOutputShut;

    ChannelPair(TlsChannel tls, SelectionKey clientKey, IpAddress peerIp, long reservedBytes) {
        this.tls = tls;
        this.clientKey = clientKey;
        this.peerIp = peerIp;
        this.reservedBytes = reservedBytes;
    }

    void startRelay(int relayBufferBytes, long now, long maxSessionNanos) {
        toClient = ByteBuffer.allocate(relayBufferBytes);
        lastActivity = now;
        sessionDeadline = now + maxSessionNanos;
    }

    /** One socket read from the client, if there is room. */
    void readClient(long now) throws IOException {
        if (tls.readNet() > 0) {
            lastActivity = now;
        }
    }

    /** One socket read from the backend, if there is room. */
    void readBackend(long now) throws IOException {
        if (backendEof || !toClient.hasRemaining()) {
            return;
        }
        int n = backend.read(toClient);
        if (n < 0) {
            backendEof = true;
        } else if (n > 0) {
            lastActivity = now;
        }
    }

    /**
     * Moves buffered bytes in both directions as far as the buffers and sockets allow, without reading either
     * socket. Bounded by the buffer sizes. Returns true if anything moved.
     */
    boolean pump(long now) throws IOException {
        boolean moved = false;
        for (int round = 0; round < 4; round++) {
            boolean a = pumpToBackend();
            boolean b = pumpToClient();
            if (!a && !b) {
                break;
            }
            moved = true;
        }
        if (moved) {
            lastActivity = now;
        }
        return moved;
    }

    private boolean pumpToBackend() throws IOException {
        boolean moved = !tls.inboundDone() && tls.unwrap();
        ByteBuffer plain = tls.appIn();
        if (plain.position() > 0 && !backendOutputShut) {
            plain.flip();
            try {
                moved |= backend.write(plain) > 0;
            } finally {
                plain.compact();
            }
        }
        if (tls.inboundDone() && plain.position() == 0 && !backendOutputShut) {
            // Client sent close_notify and everything it sent has been delivered: propagate the half-close.
            backend.shutdownOutput();
            backendOutputShut = true;
            moved = true;
        }
        return moved;
    }

    private boolean pumpToClient() throws IOException {
        boolean moved = tls.flush() > 0;
        if (!tls.outboundDone() && (toClient.position() > 0 || tls.wantsWrap())) {
            toClient.flip();
            try {
                moved |= tls.wrap(toClient) > 0;
            } finally {
                toClient.compact();
            }
            moved |= tls.flush() > 0;
        }
        if (backendEof && toClient.position() == 0 && !tls.outboundDone()) {
            // Backend finished and everything it sent is queued: send close_notify (TLS 1.3 half-close).
            tls.closeOutbound();
            moved |= tls.outboundDone();
        }
        return moved;
    }

    /**
     * The session has ended cleanly: everything the client sent before its {@code close_notify} reached the
     * backend, and our own {@code close_notify} has been written. Normally that is after the backend's end of
     * stream (a half-close in each direction). If the client closed both directions, its engine closed our
     * outbound side too; whatever the backend still sends then has nowhere to go and is dropped.
     */
    boolean relayFinished() {
        return tls.inboundDone() && backendOutputShut && tls.outboundDone() && !tls.hasPendingOutput();
    }

    int toBackendQueued() {
        return tls.appIn().position();
    }

    int toClientQueued() {
        return (toClient == null ? 0 : toClient.position()) + tls.pendingOutput();
    }

    long queuedBytes() {
        return toBackendQueued() + (long) toClientQueued();
    }

    /**
     * Applies the water marks and sets both interest sets for the relay. Returns how many reads were newly paused.
     */
    int updateRelayInterest(int highWater, int lowWater) {
        int paused = 0;
        int up = toBackendQueued();
        if (!clientPaused && up >= highWater) {
            clientPaused = true;
            paused++;
        } else if (clientPaused && up <= lowWater) {
            clientPaused = false;
        }
        int down = toClientQueued();
        if (!backendPaused && down >= highWater) {
            backendPaused = true;
            paused++;
        } else if (backendPaused && down <= lowWater) {
            backendPaused = false;
        }

        int c = 0;
        if (!clientPaused && tls.canReadNet()) {
            c |= SelectionKey.OP_READ;
        }
        if (tls.hasPendingOutput()) {
            c |= SelectionKey.OP_WRITE;
        }
        int b = 0;
        if (!backendPaused && !backendEof && toClient.hasRemaining()) {
            b |= SelectionKey.OP_READ;
        }
        if (up > 0 && !backendOutputShut) {
            b |= SelectionKey.OP_WRITE;
        }
        setInterest(clientKey, c);
        setInterest(backendKey, b);
        return paused;
    }

    void setClientInterest(int ops) {
        setInterest(clientKey, ops);
    }

    void setBackendInterest(int ops) {
        setInterest(backendKey, ops);
    }

    private static void setInterest(SelectionKey key, int ops) {
        if (key != null && key.isValid() && key.interestOps() != ops) {
            key.interestOps(ops);
        }
    }
}
