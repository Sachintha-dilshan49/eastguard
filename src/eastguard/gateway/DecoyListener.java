package eastguard.gateway;

import eastguard.common.Endpoint;
import eastguard.common.Ids;
import eastguard.common.IpAddress;
import eastguard.common.ReasonCode;
import eastguard.common.Verdict;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.time.Clock;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import java.util.logging.Logger;

/**
 * Decoy listener (spec §6.1): an extra port that nothing legitimate uses. It accepts a TCP connection and closes
 * it at once: no TLS, no backend, no fake credentials, and not a single payload byte read. Each accepted
 * connection produces exactly one {@link Verdict#DECOY} decision carrying only the socket peer IP, because no
 * identity was authenticated. A hit is high-confidence evidence, not proof of compromise.
 *
 * <p>Runs on the gateway's selector thread (no thread of its own). Accepts per wake-up are bounded, so a flood
 * of decoy connections cannot starve the real listener; the kernel backlog absorbs or refuses the rest.
 */
public final class DecoyListener {
    private static final Logger LOG = Logger.getLogger(DecoyListener.class.getName());

    private final String id;
    private final InetSocketAddress bind;
    private final int backlog;
    private final DecisionSink sink;
    private final Clock clock;
    private final LongSupplier policyRevision;
    private final AtomicLong hits = new AtomicLong();
    private ServerSocketChannel server;
    private Endpoint local;

    /**
     * @param id             reported as the telemetry service ID for decoy hits
     * @param policyRevision current installed revision, for the event; must not block
     */
    public DecoyListener(String id, InetSocketAddress bind, int backlog, DecisionSink sink, Clock clock,
            LongSupplier policyRevision) {
        this.id = Ids.require(id, "decoy id");
        this.bind = Objects.requireNonNull(bind, "bind");
        this.backlog = backlog;
        this.sink = Objects.requireNonNull(sink, "sink");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.policyRevision = Objects.requireNonNull(policyRevision, "policyRevision");
    }

    /** Binds and registers for accepts on {@code selector}, with this object as the key attachment. */
    void open(Selector selector) throws IOException {
        ServerSocketChannel ss = ServerSocketChannel.open();
        try {
            ss.bind(bind, backlog);
            ss.configureBlocking(false);
            ss.register(selector, SelectionKey.OP_ACCEPT, this);
            InetSocketAddress a = (InetSocketAddress) ss.getLocalAddress();
            local = new Endpoint(IpAddress.of(a.getAddress()), a.getPort());
        } catch (IOException | RuntimeException e) {
            ss.close();
            throw e;
        }
        server = ss;
        LOG.info(() -> "decoy " + id + " listening on " + local);
    }

    /** Accept-and-close up to {@code max} pending connections. Selector thread only. */
    void onAcceptable(int max) {
        for (int i = 0; i < max; i++) {
            SocketChannel ch;
            try {
                ch = server.accept();
            } catch (IOException e) {
                return;
            }
            if (ch == null) {
                return;
            }
            IpAddress ip = null;
            try {
                ip = IpAddress.of(((InetSocketAddress) ch.getRemoteAddress()).getAddress());
            } catch (IOException | RuntimeException e) {
                // the peer is already gone; still nothing to read
            } finally {
                closeQuietly(ch);
            }
            if (ip != null) {
                hits.incrementAndGet();
                IpAddress peer = ip;
                LOG.info(() -> "decoy " + id + " touched by " + peer);
                try {
                    sink.record(new GatewayDecision(clock.millis(), null, ip, id, local, Verdict.DECOY,
                            ReasonCode.DECOY_TOUCH, false, policyRevision.getAsLong()));
                } catch (RuntimeException e) {
                    LOG.fine(() -> "decision sink failed: " + e);
                }
            }
        }
    }

    public String id() {
        return id;
    }

    public int port() {
        return local.port();
    }

    public long hits() {
        return hits.get();
    }

    void close() {
        if (server != null) {
            closeQuietly(server);
        }
    }

    private static void closeQuietly(AutoCloseable c) {
        try {
            c.close();
        } catch (Exception ignored) {
            // best effort
        }
    }
}
