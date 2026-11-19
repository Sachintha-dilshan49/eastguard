package eastguard.gateway;

import eastguard.common.Bytes;
import eastguard.common.CodecException;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementView;
import eastguard.common.Ids;
import eastguard.common.IpAddress;
import eastguard.common.LeaseCodec;
import eastguard.common.Peer;
import eastguard.common.PolicyEvaluator;
import eastguard.common.Preamble;
import eastguard.common.ReasonCode;
import eastguard.common.ReplyStatus;
import eastguard.common.Selector;
import eastguard.common.SignedLease;
import eastguard.common.Verdict;
import eastguard.common.WorkloadIdentity;
import eastguard.gateway.ChannelPair.State;
import eastguard.tokensvc.TlsContextFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;

/**
 * The NIO gateway (spec §4.2, §4.3): mTLS in front of one fixed backend, relaying only after authorization.
 *
 * <h2>Threads</h2>
 * One selector thread owns every channel, interest set, buffer, the {@link SessionIndex}, the per-peer counts
 * and the buffer budget. Delegated TLS tasks run on a small bounded executor and hand the connection back
 * through a queue plus {@code selector.wakeup()}. Other threads only post bounded commands
 * ({@link #closeMatching}, {@link #closeSigningKey}, {@link #closeCertificate}, {@link #closeAll},
 * {@link #reevaluate}) the same way. Nothing on the selector thread blocks: no DNS (numeric addresses only), no
 * RMI, no disk, no blocking sockets. The state supplier and decision sink must not block either.
 *
 * <h2>Admission</h2>
 * After the handshake the gateway reads exactly one preamble ({@link Preamble#tryDecode}, so fragments are
 * fine and an oversize length is rejected from the header). It maps the certificate to a workload
 * ({@link WorkloadIdentity}) and runs {@link PolicyEvaluator#admit}: signature, audience = this service, time,
 * identity + leaf fingerprint = TLS peer, lease IP = socket IP, revocation, quarantine, policy. On success it
 * indexes the session and starts a non-blocking backend connect; on {@code finishConnect()} it runs the full
 * admission check again and only then queues {@code ALLOW}. Client bytes are not read between the preamble and
 * the flushed reply, backend bytes are not read until the reply is flushed, and plaintext arriving in the same
 * read as the preamble is a protocol violation (a conforming client waits for the reply).
 *
 * <h2>Termination</h2>
 * Malformed preambles and TLS failures are closed without an application reply. Denials get the coarse status
 * byte, then {@code close_notify}. A clean end of stream on either side is drained and propagated as a
 * half-close; truncation is an error. Quarantine, revocation and stale state cancel a live session at once
 * without draining. A connection closed by a command while its backend connect is pending gets the matching
 * status (e.g. {@code QUARANTINED}) instead of {@code ALLOW}.
 */
public final class NioGateway implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(NioGateway.class.getName());
    private static final long SWEEP_NANOS = TimeUnit.MILLISECONDS.toNanos(50);
    private static final Object LISTENER = new Object();

    /** Counters and gauges. Gauges are sampled by the selector thread; queued bytes every sweep (50 ms). */
    public record Stats(
            int connections, int handshaking, int pending, int sessions,
            long accepted, long rejectedLimit, long rejectedBudget, long allowed, long denied,
            long malformed, long tlsFailures, long truncated, long ioErrors,
            long handshakeTimeouts, long preambleTimeouts, long connectTimeouts, long idleTimeouts,
            long sessionLimitCloses, long closedByCommand, long completed, long readPauses,
            long reservedBufferBytes, long peakReservedBufferBytes, long queuedBytes, long peakQueuedBytes) {
    }

    /** Admission latency from complete preamble to flushed {@code ALLOW}, in microseconds. */
    public record Latency(int samples, long p50Micros, long p95Micros, long p99Micros, long maxMicros) {
    }

    private sealed interface Command permits CloseMatching, CloseKeyId, CloseCertificate, CloseAll {
    }

    private record CloseMatching(List<Selector> selectors, ReasonCode reason) implements Command {
    }

    private record CloseKeyId(String keyId) implements Command {
    }

    private record CloseCertificate(Bytes certSha256) implements Command {
    }

    private record CloseAll(ReasonCode reason) implements Command {
    }

    private final String serviceId;
    private final SSLContext ctx;
    private final InetSocketAddress listen;
    private final InetSocketAddress backendAddress;
    private final Supplier<EnforcementView> state;
    private final PolicyEvaluator evaluator;
    private final Clock clock;
    private final GatewayLimits limits;
    private final DecisionSink sink;
    private final BackendConnector connector;
    private final int relayBufferBytes;
    private final long connectionCost;
    private final ThreadPoolExecutor tlsTasks;
    private final BlockingQueue<Command> commands;
    private final ConcurrentLinkedQueue<ChannelPair> tasksDone = new ConcurrentLinkedQueue<>();
    private final AtomicBoolean reevaluateRequested = new AtomicBoolean();
    private DecoyListener decoy;

    // Selector-thread state.
    private java.nio.channels.Selector selector;
    private ServerSocketChannel server;
    private SelectionKey serverKey;
    private Endpoint localEndpoint;
    private final Set<ChannelPair> pairs = Collections.newSetFromMap(new IdentityHashMap<>());
    private final Map<IpAddress, Integer> perPeer = new HashMap<>();
    private final SessionIndex<ChannelPair> index = new SessionIndex<>();
    private long lastSweep;

    // Published counters (written by the selector thread, read by anyone).
    private final AtomicInteger connections = new AtomicInteger();
    private final AtomicInteger handshaking = new AtomicInteger();
    private final AtomicInteger pending = new AtomicInteger();
    private final AtomicInteger sessions = new AtomicInteger();
    private final AtomicLong reserved = new AtomicLong();
    private final AtomicLong peakReserved = new AtomicLong();
    private final AtomicLong queued = new AtomicLong();
    private final AtomicLong peakQueued = new AtomicLong();
    private final AtomicLong accepted = new AtomicLong();
    private final AtomicLong rejectedLimit = new AtomicLong();
    private final AtomicLong rejectedBudget = new AtomicLong();
    private final AtomicLong allowed = new AtomicLong();
    private final AtomicLong denied = new AtomicLong();
    private final AtomicLong malformed = new AtomicLong();
    private final AtomicLong tlsFailures = new AtomicLong();
    private final AtomicLong truncated = new AtomicLong();
    private final AtomicLong ioErrors = new AtomicLong();
    private final AtomicLong handshakeTimeouts = new AtomicLong();
    private final AtomicLong preambleTimeouts = new AtomicLong();
    private final AtomicLong connectTimeouts = new AtomicLong();
    private final AtomicLong idleTimeouts = new AtomicLong();
    private final AtomicLong sessionLimitCloses = new AtomicLong();
    private final AtomicLong closedByCommand = new AtomicLong();
    private final AtomicLong completed = new AtomicLong();
    private final AtomicLong readPauses = new AtomicLong();
    private final long[] latencyRing = new long[4_096];
    private int latencyCount;

    private volatile boolean running;
    private Thread thread;

    /**
     * @param serviceId this gateway's service: the required lease audience
     * @param backend   the fixed private backend; numeric, never resolved
     * @param state     current enforcement view; called on the selector thread and must not block
     */
    public NioGateway(String serviceId, SSLContext ctx, InetSocketAddress listen, InetSocketAddress backend,
            Supplier<EnforcementView> state, Clock clock, GatewayLimits limits, DecisionSink sink,
            BackendConnector connector) {
        this.serviceId = Ids.require(serviceId, "serviceId");
        this.ctx = Objects.requireNonNull(ctx, "ctx");
        this.listen = Objects.requireNonNull(listen, "listen");
        this.backendAddress = Objects.requireNonNull(backend, "backend");
        if (backend.isUnresolved()) {
            throw new IllegalArgumentException("backend must be a numeric address");
        }
        this.state = Objects.requireNonNull(state, "state");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.evaluator = new PolicyEvaluator(clock);
        this.limits = Objects.requireNonNull(limits, "limits");
        this.sink = Objects.requireNonNull(sink, "sink");
        this.connector = Objects.requireNonNull(connector, "connector");

        SSLEngine probe = TlsContextFactory.serverEngine(ctx);
        int appSize = probe.getSession().getApplicationBufferSize();
        this.relayBufferBytes = Math.max(limits.relayBufferBytes(), appSize);
        this.connectionCost = TlsChannel.bufferBytes(probe, relayBufferBytes) + relayBufferBytes;
        if (connectionCost > limits.bufferBudgetBytes()) {
            throw new IllegalArgumentException("buffer budget smaller than one connection (" + connectionCost + " bytes)");
        }

        AtomicInteger n = new AtomicInteger();
        this.tlsTasks = new ThreadPoolExecutor(limits.tlsTaskThreads(), limits.tlsTaskThreads(), 0, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(limits.maxHandshakes()), r -> {
                    Thread t = new Thread(r, "gateway-" + serviceId + "-tls-" + n.incrementAndGet());
                    t.setDaemon(true);
                    return t;
                }, new ThreadPoolExecutor.AbortPolicy());
        this.commands = new ArrayBlockingQueue<>(limits.commandQueue());
    }

    /** Builds a gateway from configuration, with its own TLS context and the bootstrap state (Task 6 replaces it). */
    public static NioGateway create(GatewayConfig cfg, Clock clock, DecisionSink sink) {
        SSLContext ctx = TlsContextFactory.create(cfg.tls());
        EnforcementView view = EnforcementView.fresh(cfg.bootstrap());
        NioGateway g = new NioGateway(cfg.serviceId(), ctx, cfg.listen().toSocketAddress(),
                cfg.backend().toSocketAddress(), () -> view, clock, cfg.limits(), sink, BackendConnector.DIRECT);
        if (cfg.decoyListen() != null) {
            g.enableDecoy(cfg.decoyId(), cfg.decoyListen().toSocketAddress());
        }
        return g;
    }

    /** Adds an accept-and-close decoy listener served by the same selector. Call before {@link #start()}. */
    public synchronized void enableDecoy(String decoyId, InetSocketAddress bind) {
        if (thread != null) {
            throw new IllegalStateException("already started");
        }
        decoy = new DecoyListener(decoyId, bind, limits.backlog(), sink, clock, this::currentRevision);
    }

    public synchronized void start() throws IOException {
        if (thread != null) {
            throw new IllegalStateException("already started");
        }
        selector = java.nio.channels.Selector.open();
        try {
            server = ServerSocketChannel.open();
            server.bind(listen, limits.backlog());
            server.configureBlocking(false);
            serverKey = server.register(selector, SelectionKey.OP_ACCEPT, LISTENER);
            InetSocketAddress a = (InetSocketAddress) server.getLocalAddress();
            localEndpoint = new Endpoint(IpAddress.of(a.getAddress()), a.getPort());
            if (decoy != null) {
                decoy.open(selector);
            }
        } catch (IOException | RuntimeException e) {
            closeQuietly(server);
            closeQuietly(selector);
            throw e;
        }
        running = true;
        lastSweep = System.nanoTime();
        thread = Thread.ofPlatform().name("gateway-" + serviceId + "-selector").start(this::run);
        LOG.info(() -> "gateway " + serviceId + " listening on " + localEndpoint + ", backend " + backendAddress);
    }

    public int port() {
        return localEndpoint.port();
    }

    /** Decoy port, or -1 when no decoy is configured. */
    public int decoyPort() {
        return decoy == null ? -1 : decoy.port();
    }

    public long decoyHits() {
        return decoy == null ? 0 : decoy.hits();
    }

    public String serviceId() {
        return serviceId;
    }

    public Stats stats() {
        return new Stats(connections.get(), handshaking.get(), pending.get(), sessions.get(),
                accepted.get(), rejectedLimit.get(), rejectedBudget.get(), allowed.get(), denied.get(),
                malformed.get(), tlsFailures.get(), truncated.get(), ioErrors.get(),
                handshakeTimeouts.get(), preambleTimeouts.get(), connectTimeouts.get(), idleTimeouts.get(),
                sessionLimitCloses.get(), closedByCommand.get(), completed.get(), readPauses.get(),
                reserved.get(), peakReserved.get(), queued.get(), peakQueued.get());
    }

    /** Heap reserved per connection (TLS buffers + both relay buffers); the unit of the buffer budget. */
    public long connectionCost() {
        return connectionCost;
    }

    public Latency admissionLatency() {
        long[] copy;
        synchronized (latencyRing) {
            int n = Math.min(latencyCount, latencyRing.length);
            copy = Arrays.copyOf(latencyRing, n);
        }
        if (copy.length == 0) {
            return new Latency(0, 0, 0, 0, 0);
        }
        Arrays.sort(copy);
        return new Latency(copy.length, pct(copy, 50), pct(copy, 95), pct(copy, 99), copy[copy.length - 1] / 1_000);
    }

    /** Starts a new admission latency measurement window. */
    public void resetAdmissionLatency() {
        synchronized (latencyRing) {
            latencyCount = 0;
        }
    }

    private static long pct(long[] sorted, int p) {
        int i = (int) Math.ceil(p / 100.0 * sorted.length) - 1;
        return sorted[Math.max(0, i)] / 1_000;
    }

    // ---- commands from other threads ----

    /**
     * Closes every live or pending session matching any selector (quarantine, spec §6.2 step 2). Install the
     * restrictive state first: this only acts on sessions that already passed AUTHORIZE; new admissions are
     * stopped by the state. Returns false if the command queue is full; a full re-evaluation against the current
     * state is then scheduled instead, so the effect is never lost.
     */
    public boolean closeMatching(Collection<Selector> selectors, ReasonCode reason) {
        Objects.requireNonNull(reason, "reason");
        return post(new CloseMatching(List.copyOf(selectors), reason));
    }

    /** Emergency key revocation: closes sessions admitted with a lease signed by {@code keyId}. */
    public boolean closeSigningKey(String keyId) {
        return post(new CloseKeyId(Ids.require(keyId, "keyId")));
    }

    /** Certificate revocation: closes sessions whose TLS peer presented this leaf certificate. */
    public boolean closeCertificate(Bytes certSha256) {
        return post(new CloseCertificate(Objects.requireNonNull(certSha256, "certSha256")));
    }

    /** Closes every live and pending session, e.g. when state freshness expires. */
    public boolean closeAll(ReasonCode reason) {
        return post(new CloseAll(Objects.requireNonNull(reason, "reason")));
    }

    /**
     * Re-checks every live and pending session against the current state with
     * {@link PolicyEvaluator#continueSession} and closes those no longer allowed. Coalesced; never dropped.
     */
    public void reevaluate() {
        reevaluateRequested.set(true);
        wakeup();
    }

    private boolean post(Command c) {
        boolean ok = commands.offer(c);
        if (!ok) {
            reevaluateRequested.set(true);
        }
        wakeup();
        return ok;
    }

    private void wakeup() {
        java.nio.channels.Selector s = selector;
        if (s != null) {
            s.wakeup();
        }
    }

    // ---- selector loop ----

    private void run() {
        try {
            while (running) {
                selector.select(TimeUnit.NANOSECONDS.toMillis(SWEEP_NANOS));
                if (!running) {
                    break;
                }
                drainTasksDone();
                drainCommands();
                Iterator<SelectionKey> it = selector.selectedKeys().iterator();
                while (it.hasNext()) {
                    SelectionKey key = it.next();
                    it.remove();
                    dispatch(key);
                }
                long now = System.nanoTime();
                if (now - lastSweep >= SWEEP_NANOS) {
                    lastSweep = now;
                    sweep(now);
                }
                updateAcceptInterest();
            }
        } catch (IOException | RuntimeException e) {
            LOG.log(Level.SEVERE, "gateway selector loop failed; closing all connections", e);
        } finally {
            for (ChannelPair p : new ArrayList<>(pairs)) {
                close(p);
            }
            closeQuietly(server);
            if (decoy != null) {
                decoy.close();
            }
            closeQuietly(selector);
        }
    }

    private void dispatch(SelectionKey key) {
        if (!key.isValid()) {
            return;
        }
        Object att = key.attachment();
        if (att == LISTENER) {
            accept();
        } else if (att instanceof DecoyListener d) {
            d.onAcceptable(limits.maxAcceptsPerEvent());
        } else if (att instanceof ChannelPair p && p.state != State.CLOSED && !p.taskRunning) {
            long now = System.nanoTime();
            try {
                if (key == p.backendKey) {
                    onBackend(p, key.readyOps(), now);
                } else {
                    onClient(p, key.readyOps(), now);
                }
            } catch (IOException | RuntimeException e) {
                fail(p, e);
            }
        }
    }

    private void accept() {
        for (int i = 0; i < limits.maxAcceptsPerEvent() && handshaking.get() < limits.maxHandshakes(); i++) {
            SocketChannel ch;
            try {
                ch = server.accept();
            } catch (IOException e) {
                LOG.log(Level.FINE, "accept failed", e);
                return;
            }
            if (ch == null) {
                return;
            }
            accepted.incrementAndGet();
            IpAddress ip;
            try {
                ip = IpAddress.of(((InetSocketAddress) ch.getRemoteAddress()).getAddress());
            } catch (IOException | RuntimeException e) {
                closeQuietly(ch);
                continue;
            }
            if (pairs.size() >= limits.maxConnections() || perPeer.getOrDefault(ip, 0) >= limits.maxConnectionsPerPeer()) {
                rejectedLimit.incrementAndGet();
                closeQuietly(ch);
                continue;
            }
            if (reserved.get() + connectionCost > limits.bufferBudgetBytes()) {
                rejectedBudget.incrementAndGet();
                closeQuietly(ch);
                continue;
            }
            try {
                ch.configureBlocking(false);
                ch.setOption(StandardSocketOptions.TCP_NODELAY, true);
                TlsChannel tls = new TlsChannel(ch, TlsContextFactory.serverEngine(ctx), relayBufferBytes);
                SelectionKey key = ch.register(selector, 0);
                ChannelPair p = new ChannelPair(tls, key, ip, connectionCost);
                key.attach(p);
                pairs.add(p);
                connections.incrementAndGet();
                perPeer.merge(ip, 1, Integer::sum);
                peakReserved.accumulateAndGet(reserved.addAndGet(connectionCost), Math::max);
                setState(p, State.TLS_HANDSHAKE);
                p.deadline = System.nanoTime() + limits.handshakeTimeout().toNanos();
                p.setClientInterest(SelectionKey.OP_READ); // the client speaks first
            } catch (IOException | RuntimeException e) {
                LOG.log(Level.FINE, "cannot set up accepted connection", e);
                closeQuietly(ch);
            }
        }
    }

    private void updateAcceptInterest() {
        if (serverKey == null || !serverKey.isValid()) {
            return;
        }
        int want = handshaking.get() < limits.maxHandshakes() ? SelectionKey.OP_ACCEPT : 0;
        if (serverKey.interestOps() != want) {
            serverKey.interestOps(want); // at the limit, new connections wait in the kernel backlog
        }
    }

    private void onClient(ChannelPair p, int ops, long now) throws IOException {
        switch (p.state) {
            case TLS_HANDSHAKE -> stepHandshake(p);
            case READ_PREAMBLE -> readPreamble(p, now);
            case CONNECT_BACKEND -> {
                p.tls.flush(); // post-handshake output such as session tickets; client input is not read here
                p.setClientInterest(p.tls.hasPendingOutput() ? SelectionKey.OP_WRITE : 0);
            }
            case WRITE_REPLY, REPLY_THEN_CLOSE -> continueReply(p, now);
            case RELAY -> {
                if ((ops & SelectionKey.OP_READ) != 0) {
                    p.readClient(now);
                }
                relay(p, now);
            }
            default -> {
                // AUTHORIZE is synchronous; CLOSED is filtered out
            }
        }
    }

    private void onBackend(ChannelPair p, int ops, long now) throws IOException {
        switch (p.state) {
            case CONNECT_BACKEND -> {
                if ((ops & SelectionKey.OP_CONNECT) != 0) {
                    boolean connected;
                    try {
                        connected = p.backend.finishConnect();
                    } catch (IOException e) {
                        LOG.fine(() -> "backend connect failed: " + e.getMessage());
                        denyAndClose(p, ReasonCode.BACKEND_UNAVAILABLE);
                        return;
                    }
                    if (connected) {
                        backendConnected(p, now);
                    }
                }
            }
            case RELAY -> {
                if ((ops & SelectionKey.OP_READ) != 0) {
                    p.readBackend(now);
                }
                relay(p, now);
            }
            default -> p.setBackendInterest(0);
        }
    }

    // ---- TLS handshake and delegated tasks ----

    private void stepHandshake(ChannelPair p) throws IOException {
        switch (p.tls.handshake()) {
            case TASK -> runTasks(p);
            case WAIT -> p.setClientInterest(SelectionKey.OP_READ
                    | (p.tls.hasPendingOutput() ? SelectionKey.OP_WRITE : 0));
            case DONE -> {
                setState(p, State.READ_PREAMBLE);
                p.deadline = System.nanoTime() + limits.preambleTimeout().toNanos();
                readPreamble(p, System.nanoTime());
            }
        }
    }

    private void runTasks(ChannelPair p) {
        p.taskRunning = true;
        p.setClientInterest(0);
        p.setBackendInterest(0);
        Runnable batch = p.tls.takeDelegatedTasks();
        try {
            tlsTasks.execute(() -> {
                try {
                    batch.run();
                } catch (RuntimeException e) {
                    // The engine keeps the failure and reports it on its next wrap/unwrap.
                    LOG.log(Level.FINE, "delegated TLS task failed", e);
                } finally {
                    tasksDone.add(p);
                    wakeup();
                }
            });
        } catch (RejectedExecutionException e) {
            p.taskRunning = false;
            rejectedLimit.incrementAndGet();
            LOG.fine("TLS task executor saturated; closing connection");
            close(p);
        }
    }

    private void drainTasksDone() {
        ChannelPair p;
        while ((p = tasksDone.poll()) != null) {
            p.taskRunning = false;
            if (p.state == State.CLOSED) {
                continue;
            }
            long now = System.nanoTime();
            try {
                switch (p.state) {
                    case TLS_HANDSHAKE -> stepHandshake(p);
                    case READ_PREAMBLE -> readPreamble(p, now);
                    case RELAY -> relay(p, now);
                    default -> {
                        // no task can start in other states
                    }
                }
            } catch (IOException | RuntimeException e) {
                fail(p, e);
            }
        }
    }

    // ---- preamble and admission ----

    private void readPreamble(ChannelPair p, long now) throws IOException {
        TlsChannel t = p.tls;
        t.flush();
        t.readNet();
        t.unwrap(); // throws on truncation
        if (t.wantsTask()) {
            runTasks(p);
            return;
        }
        if (t.wantsWrap()) {
            t.wrap(ByteBuffer.allocate(0));
            t.flush();
        }
        if (t.inboundDone()) {
            LOG.fine("client closed before sending a preamble");
            close(p);
            return;
        }
        ByteBuffer plain = t.appIn();
        plain.flip();
        Preamble pre;
        try {
            pre = Preamble.tryDecode(plain);
        } catch (CodecException e) {
            plain.compact();
            rejectMalformed(p, e.getMessage());
            return;
        }
        boolean trailing = pre != null && plain.hasRemaining();
        plain.compact();
        if (pre == null) {
            p.setClientInterest(SelectionKey.OP_READ | (t.hasPendingOutput() ? SelectionKey.OP_WRITE : 0));
            return;
        }
        if (trailing) {
            rejectMalformed(p, "data after the preamble before the reply");
            return;
        }
        p.preambleAt = now;
        authorize(p, pre, now);
    }

    private void rejectMalformed(ChannelPair p, String why) {
        malformed.incrementAndGet();
        EnforcementView view = state.get();
        Peer peer = view.usable() ? authenticate(p, view) : null;
        LOG.info(() -> "malformed preamble from " + p.peerIp + ": " + why);
        record(peer, p.peerIp, Verdict.DENY, ReasonCode.INVALID_TOKEN, false, revision(view));
        denied.incrementAndGet();
        close(p); // no application reply to a malformed frame
    }

    private Peer authenticate(ChannelPair p, EnforcementView view) {
        WorkloadIdentity.Result id = WorkloadIdentity.authenticate(p.tls.session(), p.peerIp,
                view.snapshot().workloads(), clock);
        return id.ok() ? id.peer() : null;
    }

    private void authorize(ChannelPair p, Preamble pre, long now) throws IOException {
        setState(p, State.AUTHORIZE);
        p.setClientInterest(0); // nothing more is read from the client until it has been admitted
        EnforcementView view = state.get();
        if (!view.usable()) {
            denyAndClose(p, ReasonCode.NOT_READY);
            return;
        }
        WorkloadIdentity.Result id = WorkloadIdentity.authenticate(p.tls.session(), p.peerIp,
                view.snapshot().workloads(), clock);
        if (!id.ok()) {
            denyAndClose(p, id.reason());
            return;
        }
        p.peer = id.peer();
        SignedLease signed;
        try {
            signed = LeaseCodec.parse(pre.token().toArray());
        } catch (CodecException e) {
            denyAndClose(p, ReasonCode.INVALID_TOKEN);
            return;
        }
        PolicyEvaluator.Decision d = evaluator.admit(view, p.peer, serviceId, signed);
        p.outsideApprovedGraph = d.outsideApprovedGraph();
        if (!d.allowed()) {
            denyAndClose(p, d.reason());
            return;
        }
        p.signed = signed;
        p.lease = d.lease();
        index.add(new SessionIndex.Entry<>(p, p.peer.identity(), p.peer.ip(), p.lease.keyId(), p.peer.leafSha256()));
        p.indexed = true;
        setState(p, State.CONNECT_BACKEND);
        p.deadline = now + limits.backendConnectTimeout().toNanos();
        p.setClientInterest(p.tls.hasPendingOutput() ? SelectionKey.OP_WRITE : 0);

        SocketChannel ch;
        try {
            ch = connector.open(backendAddress);
            ch.configureBlocking(false);
        } catch (IOException e) {
            LOG.fine(() -> "backend connect failed: " + e.getMessage());
            denyAndClose(p, ReasonCode.BACKEND_UNAVAILABLE);
            return;
        }
        p.backend = ch;
        p.backendKey = ch.register(selector, 0, p);
        if (ch.isConnected()) {
            backendConnected(p, now);
        } else {
            p.setBackendInterest(SelectionKey.OP_CONNECT);
        }
    }

    /** Spec §4.2 step 4: recheck everything now that the backend is there, then (and only then) ALLOW. */
    private void backendConnected(ChannelPair p, long now) throws IOException {
        p.setBackendInterest(0); // no backend bytes until the reply has been flushed
        EnforcementView view = state.get();
        PolicyEvaluator.Decision d = evaluator.admit(view, p.peer, serviceId, p.signed);
        if (!d.allowed()) {
            denyAndClose(p, d.reason());
            return;
        }
        p.outsideApprovedGraph = d.outsideApprovedGraph();
        p.reply = ByteBuffer.wrap(Preamble.encodeReply(ReplyStatus.SUCCESS));
        setState(p, State.WRITE_REPLY);
        p.deadline = now + limits.preambleTimeout().toNanos();
        continueReply(p, now);
    }

    /** Records a denial and sends its status byte, then {@code close_notify}. */
    private void denyAndClose(ChannelPair p, ReasonCode reason) throws IOException {
        EnforcementView view = state.get();
        record(p.peer, p.peerIp, Verdict.DENY, reason, p.outsideApprovedGraph, revision(view));
        denied.incrementAndGet();
        String who = p.peer == null ? "unauthenticated" : p.peer.identity();
        LOG.info(() -> "gateway " + serviceId + " deny sub=" + who + " ip=" + p.peerIp + " reason=" + reason);
        closeBackend(p);
        unindex(p);
        if (p.taskRunning) {
            close(p); // the engine belongs to a task right now; no reply
            return;
        }
        p.reply = ByteBuffer.wrap(Preamble.encodeReply(ReplyStatus.forReason(reason)));
        setState(p, State.REPLY_THEN_CLOSE);
        p.deadline = System.nanoTime() + limits.preambleTimeout().toNanos();
        continueReply(p, System.nanoTime());
    }

    private void continueReply(ChannelPair p, long now) throws IOException {
        TlsChannel t = p.tls;
        t.flush();
        if (p.reply.hasRemaining()) {
            t.wrap(p.reply);
            t.flush();
        }
        if (p.reply.hasRemaining() && t.outboundDone()) {
            close(p); // the client already closed the connection; nobody to tell
            return;
        }
        if (p.reply.hasRemaining() || t.hasPendingOutput()) {
            p.setClientInterest(SelectionKey.OP_WRITE);
            return;
        }
        if (p.state == State.WRITE_REPLY) {
            enterRelay(p, now);
        } else if (t.closeOutbound()) {
            close(p);
        } else {
            p.setClientInterest(SelectionKey.OP_WRITE);
        }
    }

    private void enterRelay(ChannelPair p, long now) throws IOException {
        setState(p, State.RELAY);
        p.startRelay(relayBufferBytes, now, limits.maxSessionDuration().toNanos());
        allowed.incrementAndGet();
        recordLatency(now - p.preambleAt);
        record(p.peer, p.peerIp, Verdict.ALLOW, ReasonCode.OK, p.outsideApprovedGraph, currentRevision());
        LOG.fine(() -> "gateway " + serviceId + " allow sub=" + p.peer.identity() + " ip=" + p.peerIp
                + " keyId=" + p.lease.keyId());
        relay(p, now);
    }

    // ---- relay ----

    private void relay(ChannelPair p, long now) throws IOException {
        p.pump(now);
        if (p.tls.wantsTask()) {
            runTasks(p);
            return;
        }
        if (p.relayFinished()) {
            completed.incrementAndGet();
            close(p);
            return;
        }
        readPauses.addAndGet(p.updateRelayInterest(limits.highWaterBytes(), limits.lowWaterBytes()));
    }

    // ---- commands, deadlines, freshness ----

    private void drainCommands() {
        Command c;
        while ((c = commands.poll()) != null) {
            switch (c) {
                case CloseMatching m -> terminateAll(index.matching(m.selectors()), m.reason());
                case CloseKeyId k -> terminateAll(index.withKeyId(k.keyId()), ReasonCode.REVOKED);
                case CloseCertificate cc -> terminateAll(index.withCertificate(cc.certSha256()), ReasonCode.REVOKED);
                case CloseAll a -> terminateAll(index.all(), a.reason());
            }
        }
        if (reevaluateRequested.getAndSet(false)) {
            EnforcementView view = state.get();
            for (ChannelPair p : index.all()) {
                PolicyEvaluator.Decision d = evaluator.continueSession(view, p.peer, serviceId, p.lease);
                if (!d.allowed()) {
                    terminate(p, d.reason());
                }
            }
        }
    }

    private void terminateAll(List<ChannelPair> matched, ReasonCode reason) {
        for (ChannelPair p : matched) {
            terminate(p, reason);
        }
    }

    /**
     * Ends an indexed session for a containment reason. Pending: no ALLOW; the client gets the status instead.
     * Live: both legs cancelled at once, queued payload discarded (spec §4.3).
     */
    private void terminate(ChannelPair p, ReasonCode reason) {
        if (p.state == State.CLOSED) {
            return;
        }
        closedByCommand.incrementAndGet();
        String who = p.peer.identity();
        LOG.info(() -> "gateway " + serviceId + " closing " + p.state + " session sub=" + who + " ip=" + p.peerIp
                + " reason=" + reason);
        if (p.state == State.CONNECT_BACKEND) {
            try {
                denyAndClose(p, reason);
            } catch (IOException | RuntimeException e) {
                close(p);
            }
        } else {
            close(p);
        }
    }

    private void sweep(long now) {
        EnforcementView view = state.get();
        boolean usable = view.usable();
        long q = 0;
        for (ChannelPair p : new ArrayList<>(pairs)) {
            if (p.state == State.CLOSED) {
                continue;
            }
            q += p.queuedBytes();
            if (!usable && p.indexed) {
                terminate(p, ReasonCode.NOT_READY); // fail closed: stale state ends live sessions (spec §6.2)
                continue;
            }
            switch (p.state) {
                case TLS_HANDSHAKE -> expire(p, now - p.deadline >= 0, handshakeTimeouts);
                case READ_PREAMBLE -> expire(p, now - p.deadline >= 0, preambleTimeouts);
                case CONNECT_BACKEND -> {
                    if (now - p.deadline >= 0) {
                        connectTimeouts.incrementAndGet();
                        try {
                            denyAndClose(p, ReasonCode.BACKEND_UNAVAILABLE);
                        } catch (IOException | RuntimeException e) {
                            close(p);
                        }
                    }
                }
                case WRITE_REPLY, REPLY_THEN_CLOSE -> expire(p, now - p.deadline >= 0, ioErrors);
                case RELAY -> {
                    if (now - p.sessionDeadline >= 0) {
                        sessionLimitCloses.incrementAndGet();
                        close(p);
                    } else if (now - p.lastActivity >= limits.idleTimeout().toNanos()) {
                        idleTimeouts.incrementAndGet();
                        close(p);
                    }
                }
                default -> {
                    // AUTHORIZE is synchronous
                }
            }
        }
        queued.set(q);
        peakQueued.accumulateAndGet(q, Math::max);
    }

    private void expire(ChannelPair p, boolean due, AtomicLong counter) {
        if (due) {
            counter.incrementAndGet();
            close(p); // no reply: these states have nothing to say, or are already saying it
        }
    }

    // ---- bookkeeping ----

    private void setState(ChannelPair p, State next) {
        gauge(p.state, -1);
        p.state = next;
        gauge(next, +1);
    }

    private void gauge(State s, int delta) {
        if (s == null) {
            return;
        }
        switch (s) {
            case TLS_HANDSHAKE, READ_PREAMBLE -> handshaking.addAndGet(delta);
            case AUTHORIZE, CONNECT_BACKEND, WRITE_REPLY -> pending.addAndGet(delta);
            case RELAY -> sessions.addAndGet(delta);
            default -> {
                // REPLY_THEN_CLOSE and CLOSED are not counted
            }
        }
    }

    private void fail(ChannelPair p, Exception e) {
        if (p.state == State.TLS_HANDSHAKE) {
            tlsFailures.incrementAndGet();
            if (!p.taskRunning) {
                p.tls.sendAlertQuietly();
            }
        } else if (e instanceof TlsChannel.TruncatedException) {
            truncated.incrementAndGet();
        } else if (e instanceof SSLException) {
            tlsFailures.incrementAndGet();
        } else {
            ioErrors.incrementAndGet();
        }
        if (e instanceof RuntimeException) {
            LOG.log(Level.WARNING, "unexpected error on a gateway connection", e);
        } else {
            LOG.fine(() -> "connection from " + p.peerIp + " failed in " + p.state + ": " + e);
        }
        close(p);
    }

    /** Immediate close of both legs. Idempotent. Never touches the TLS engine. */
    private void close(ChannelPair p) {
        if (p.state == State.CLOSED) {
            return;
        }
        setState(p, State.CLOSED);
        unindex(p);
        closeBackend(p);
        p.clientKey.cancel();
        closeQuietly(p.tls.channel());
        if (pairs.remove(p)) {
            connections.decrementAndGet();
            perPeer.computeIfPresent(p.peerIp, (k, v) -> v > 1 ? v - 1 : null);
            reserved.addAndGet(-p.reservedBytes);
        }
    }

    private void closeBackend(ChannelPair p) {
        if (p.backendKey != null) {
            p.backendKey.cancel();
        }
        if (p.backend != null) {
            closeQuietly(p.backend);
        }
    }

    private void unindex(ChannelPair p) {
        if (p.indexed) {
            index.remove(p);
            p.indexed = false;
        }
    }

    private void record(Peer peer, IpAddress ip, Verdict v, ReasonCode reason, boolean outside, long revision) {
        try {
            sink.record(new GatewayDecision(clock.millis(), peer == null ? null : peer.identity(), ip, serviceId,
                    localEndpoint, v, reason, outside, revision));
        } catch (RuntimeException e) {
            LOG.fine(() -> "decision sink failed: " + e);
        }
    }

    private void recordLatency(long nanos) {
        synchronized (latencyRing) {
            latencyRing[latencyCount % latencyRing.length] = nanos;
            latencyCount++;
        }
    }

    private long currentRevision() {
        return revision(state.get());
    }

    private static long revision(EnforcementView view) {
        return view.snapshot() == null ? 0 : view.snapshot().revision();
    }

    /** Stops accepting, cancels every connection, and stops the TLS task threads. */
    @Override
    public void close() {
        Thread t;
        synchronized (this) {
            t = thread;
            running = false;
        }
        wakeup();
        if (t != null) {
            try {
                t.join(5_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        tlsTasks.shutdownNow();
    }

    private static void closeQuietly(AutoCloseable c) {
        if (c == null) {
            return;
        }
        try {
            c.close();
        } catch (Exception ignored) {
            // best effort
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !"--config".equals(args[0])) {
            System.err.println("usage: java -cp out eastguard.gateway.NioGateway --config config/gateway-app-02.properties");
            System.exit(2);
        }
        CountingDecisionSink sink = new CountingDecisionSink();
        NioGateway g = create(GatewayConfig.load(Path.of(args[1])), Clock.systemUTC(), sink);
        Runtime.getRuntime().addShutdownHook(new Thread(g::close, "gateway-shutdown"));
        g.start();
    }
}
