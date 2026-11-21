package eastguard.tokensvc;

import eastguard.common.Ed25519;
import eastguard.common.EnforcementView;
import eastguard.common.IpAddress;
import eastguard.common.IssuerRequest;
import eastguard.common.CodecException;
import eastguard.common.KeyStores;
import eastguard.common.PolicyEvaluator;
import eastguard.common.ReasonCode;
import eastguard.common.TelemetrySender;
import eastguard.common.Verdict;
import eastguard.common.Endpoint;
import eastguard.control.ControlClient;
import eastguard.control.StateSync;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * Token service (spec §4.2, §4.3 last paragraph): blocking {@link SSLServerSocket} with mTLS, one virtual thread
 * per connection, one framed {@code EGI1} request per connection.
 *
 * <ul>
 *   <li>A semaphore bounds concurrent handshakes and requests; a connection over the limit is closed at once
 *       (reject excess, no unbounded queue).</li>
 *   <li>Each connection has one total deadline covering handshake, request, decision, and reply. A watchdog
 *       closes the socket when it passes, so a client dribbling bytes cannot hold a permit longer.</li>
 *   <li>The peer IP comes from the accepted socket. The identity comes from the verified certificate.</li>
 *   <li>Malformed requests and TLS failures get no application reply. Tokens are never logged.</li>
 *   <li>Selected denials go to the UDP telemetry producer, if one is attached ({@link #reportable}).</li>
 * </ul>
 *
 * Run: {@code java -cp out eastguard.tokensvc.TokenServer --config config/token.properties}
 */
public final class TokenServer implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(TokenServer.class.getName());

    /** @param maxConcurrent concurrent connections between accept and close */
    public record Limits(int maxConcurrent, Duration deadline, int backlog) {
        public Limits {
            if (maxConcurrent < 1 || backlog < 1) {
                throw new IllegalArgumentException("limits must be positive");
            }
            if (deadline.toMillis() < 1 || deadline.toMillis() > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("deadline out of range");
            }
        }
    }

    /** Monotonic counters for health reporting and tests. */
    public record Stats(long issued, long denied, long handshakeFailures, long malformed, long rejectedBusy,
            long timedOut) {
    }

    private final SSLContext ctx;
    private final InetSocketAddress bind;
    private final Supplier<EnforcementView> state;
    private final LeaseIssuer issuer;
    private final Limits limits;
    private final Semaphore permits;
    private final ScheduledThreadPoolExecutor watchdog;
    private final ExecutorService workers;

    private final AtomicLong issued = new AtomicLong();
    private final AtomicLong denied = new AtomicLong();
    private final AtomicLong handshakeFailures = new AtomicLong();
    private final AtomicLong malformed = new AtomicLong();
    private final AtomicLong rejectedBusy = new AtomicLong();
    private final AtomicLong timedOut = new AtomicLong();

    private volatile SSLServerSocket server;
    private final java.util.List<AutoCloseable> owned = new java.util.concurrent.CopyOnWriteArrayList<>();
    private volatile StateSync sync; // set by create()
    private volatile TelemetrySender telemetry;
    private volatile Clock reportClock = Clock.systemUTC();
    private Thread acceptor;

    /**
     * @param state current enforcement view; must not block (Task 6 replaces the bootstrap view with synced state)
     */
    public TokenServer(SSLContext ctx, InetSocketAddress bind, Supplier<EnforcementView> state, LeaseIssuer issuer,
            Limits limits) {
        this.ctx = Objects.requireNonNull(ctx, "ctx");
        this.bind = Objects.requireNonNull(bind, "bind");
        this.state = Objects.requireNonNull(state, "state");
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.limits = Objects.requireNonNull(limits, "limits");
        this.permits = new Semaphore(limits.maxConcurrent());
        this.watchdog = new ScheduledThreadPoolExecutor(1, r -> {
            Thread t = new Thread(r, "tokensvc-deadline");
            t.setDaemon(true);
            return t;
        });
        this.watchdog.setRemoveOnCancelPolicy(true);
        this.workers = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name("tokensvc-conn-", 0).factory());
    }

    /**
     * Wires a server from configuration with authoritative state from the control plane: a {@link StateSync}
     * polls over RMI on its own thread (started here), and issuance is refused until the first valid sync and
     * whenever freshness has expired. The token service's TLS certificate is also its RMI client identity. With
     * {@code multicast.*} set, a quarantine notice stops matching issuance at once.
     */
    public static TokenServer create(TokenConfig cfg, Clock clock, InetSocketAddress bind) {
        SSLContext ctx = TlsContextFactory.create(cfg.tls());
        eastguard.bus.NoticeTransport notices = null;
        if (cfg.multicast() != null) {
            try {
                notices = new eastguard.bus.MulticastTransport(cfg.multicast());
            } catch (IOException e) {
                throw new java.io.UncheckedIOException("multicast interface " + cfg.multicast().networkInterface(), e);
            }
        }
        return create(cfg, ctx, clock, bind, new ControlClient(cfg.control(), ctx)::sync, notices);
    }

    /**
     * The same wiring with a caller-supplied sync source and notice transport (demos run the control plane
     * in-process and may inject transport faults). {@code notices == null}: polling only.
     */
    public static TokenServer create(TokenConfig cfg, SSLContext ctx, Clock clock, InetSocketAddress bind,
            StateSync.Source source, eastguard.bus.NoticeTransport notices) {
        StateSync sync = new StateSync("tokensvc", source, cfg.sync(), System::nanoTime);
        TokenServer server = create(cfg, clock, bind, ctx, sync);
        server.owned.add(sync);
        server.sync = sync;
        if (cfg.telemetry() != null) {
            server.reportTo(TelemetrySender.create(cfg.sync().clusterId(), cfg.telemetry()), clock);
        }
        if (notices != null) {
            try { // joined before the first sync
                server.owned.add(eastguard.bus.QuarantineListener.forSync("tokensvc", notices, sync, clock));
            } catch (IOException e) {
                server.close();
                throw new java.io.UncheckedIOException("cannot join the quarantine notice group", e);
            }
        } else {
            LOG.warning("multicast.group is not configured: quarantine reaches the token service by polling only");
        }
        sync.start();
        return server;
    }

    /** The state sync wired by {@link #create}, or {@code null} for a server built with a fixed state. */
    public StateSync stateSync() {
        return sync;
    }

    public static TokenServer create(TokenConfig cfg, Clock clock) {
        return create(cfg, clock, cfg.listen().toSocketAddress());
    }

    /** As configured, but with a caller-supplied state (demos with a fixed fixture; tests). */
    public static TokenServer create(TokenConfig cfg, Clock clock, InetSocketAddress bind,
            Supplier<EnforcementView> state) {
        return create(cfg, clock, bind, TlsContextFactory.create(cfg.tls()), state);
    }

    private static TokenServer create(TokenConfig cfg, Clock clock, InetSocketAddress bind, SSLContext ctx,
            Supplier<EnforcementView> state) {
        KeyPair signer = loadSigningKey(cfg);
        LeaseIssuer issuer = new LeaseIssuer(new PolicyEvaluator(clock), cfg.keyId(), signer.getPrivate(),
                signer.getPublic(), new IssueLimiter(cfg.issuePerIdentityPerSecond(), System::nanoTime), clock,
                new SecureRandom());
        return new TokenServer(ctx, bind, state, issuer, cfg.limits());
    }

    /** The signing key and the public key from its certificate (checked against the published key per lease). */
    static KeyPair loadSigningKey(TokenConfig cfg) {
        Path file = cfg.signerStore();
        char[] pw = cfg.signerPassword().read();
        try {
            KeyStore ks = KeyStores.load(file, pw);
            PrivateKey key = KeyStores.privateKey(ks, cfg.signerAlias(), pw, file);
            PublicKey own = KeyStores.certificate(ks, cfg.signerAlias(), file).getPublicKey();
            Ed25519.rawPublicKey(own); // must be Ed25519
            return new KeyPair(own, key);
        } finally {
            Arrays.fill(pw, '\0');
        }
    }

    public synchronized void start() throws IOException {
        if (server != null) {
            throw new IllegalStateException("already started");
        }
        TelemetrySender t = telemetry;
        if (t != null) {
            t.start();
        }
        server = TlsContextFactory.serverSocket(ctx, bind, limits.backlog());
        acceptor = Thread.ofPlatform().name("tokensvc-accept").start(this::acceptLoop);
        LOG.info(() -> "token service listening on " + server.getLocalSocketAddress());
    }

    public int port() {
        return server.getLocalPort();
    }

    /** Connections currently holding a permit. */
    public int active() {
        return limits.maxConcurrent() - permits.availablePermits();
    }

    public Stats stats() {
        return new Stats(issued.get(), denied.get(), handshakeFailures.get(), malformed.get(), rejectedBusy.get(),
                timedOut.get());
    }

    private void acceptLoop() {
        SSLServerSocket ss = server;
        while (!ss.isClosed()) {
            Socket s;
            try {
                s = ss.accept();
            } catch (IOException e) {
                if (!ss.isClosed()) {
                    LOG.log(Level.WARNING, "accept failed", e);
                }
                continue;
            }
            if (!permits.tryAcquire()) {
                rejectedBusy.incrementAndGet();
                closeQuietly(s);
                continue;
            }
            try {
                workers.execute(() -> handle((SSLSocket) s));
            } catch (RejectedExecutionException e) {
                permits.release();
                closeQuietly(s);
            }
        }
    }

    private void handle(SSLSocket s) {
        AtomicBoolean expired = new AtomicBoolean();
        ScheduledFuture<?> guard = watchdog.schedule(() -> {
            expired.set(true);
            closeQuietly(s);
        }, limits.deadline().toMillis(), TimeUnit.MILLISECONDS);
        try (s) {
            s.setSoTimeout((int) limits.deadline().toMillis());
            s.setTcpNoDelay(true);
            s.startHandshake();
            IpAddress ip = IpAddress.of(s.getInetAddress());
            IssuerRequest request;
            try {
                request = IssuerRequest.read(s.getInputStream());
            } catch (CodecException e) {
                // A watchdog close can surface as EOF, i.e. a truncated frame: that is a timeout, not bad input.
                if (expired.get()) {
                    timedOut.incrementAndGet();
                } else {
                    malformed.incrementAndGet();
                    LOG.fine(() -> "malformed request from " + ip + ": " + e.getMessage());
                }
                return;
            }
            EnforcementView view = state.get();
            LeaseIssuer.Outcome o = issuer.issue(view, s.getSession(), ip, request.targetService());
            OutputStream out = s.getOutputStream();
            out.write(o.reply().encode());
            out.flush();
            String who = o.peer() == null ? "unauthenticated" : o.peer().identity();
            if (o.issued()) {
                issued.incrementAndGet();
                LOG.info(() -> "lease issued sub=" + who + " aud=" + request.targetService() + " ip=" + ip
                        + " keyId=" + o.lease().keyId() + " ttlMs=" + (o.lease().expiresAtMs() - o.lease().issuedAtMs())
                        + " rev=" + o.lease().issuedAtRevision());
            } else {
                denied.incrementAndGet();
                LOG.info(() -> "lease denied sub=" + who + " aud=" + request.targetService() + " ip=" + ip
                        + " reason=" + o.reason());
                report(o, view, request.targetService(), s);
            }
        } catch (IOException e) {
            // The read timeout and the watchdog are both set to the deadline; whichever fires first, it is a timeout.
            if (expired.get() || e instanceof SocketTimeoutException) {
                timedOut.incrementAndGet();
                LOG.fine(() -> "connection deadline passed: " + s.getInetAddress().getHostAddress());
            } else if (e instanceof SSLException) {
                handshakeFailures.incrementAndGet();
                LOG.fine(() -> "TLS failure: " + e);
            } else {
                LOG.fine(() -> "connection I/O error: " + e);
            }
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "unexpected error handling a lease request", e);
        } finally {
            guard.cancel(false);
            permits.release();
        }
    }

    /**
     * Sends selected denials to {@code sender} from now on (spec §1 "selected token-service denials"). Call before
     * {@link #start()}. The sender is closed with this server.
     */
    public void reportTo(TelemetrySender sender, Clock clock) {
        this.reportClock = Objects.requireNonNull(clock, "clock");
        this.telemetry = Objects.requireNonNull(sender, "sender");
        owned.add(sender);
    }

    /**
     * Which issuer denials are worth a telemetry event (spec §6.1): only for a peer whose identity TLS
     * established, and only a policy denial for a <em>known</em> service, or a quarantine. Everything else
     * (bad certificates, throttling, NOT_READY, unknown services) stays in the local log and counters.
     */
    public static boolean reportable(LeaseIssuer.Outcome o, EnforcementView view, String service) {
        if (o.issued() || o.peer() == null) {
            return false;
        }
        return switch (o.reason()) {
            case QUARANTINED -> true;
            case POLICY_DENY -> view.snapshot() != null && view.snapshot().services().containsKey(service);
            default -> false;
        };
    }

    private void report(LeaseIssuer.Outcome o, EnforcementView view, String service, SSLSocket s) {
        TelemetrySender t = telemetry;
        if (t == null || !reportable(o, view, service)) {
            return;
        }
        Endpoint listener = new Endpoint(IpAddress.of(s.getLocalAddress()), s.getLocalPort());
        t.offer(reportClock.millis(), o.peer().identity(), o.peer().ip(), service, listener, Verdict.DENY, o.reason(),
                o.reason() == ReasonCode.POLICY_DENY, view.snapshot() == null ? 0 : view.snapshot().revision());
    }

    /** Stops accepting, waits up to one deadline for in-flight requests, then aborts the rest. */
    @Override
    public void close() {
        SSLServerSocket ss = server;
        if (ss != null) {
            closeQuietly(ss);
        }
        workers.shutdown();
        try {
            if (acceptor != null) {
                acceptor.join(limits.deadline().toMillis());
            }
            if (!workers.awaitTermination(limits.deadline().toMillis() + 1_000, TimeUnit.MILLISECONDS)) {
                workers.shutdownNow();
            }
        } catch (InterruptedException e) {
            workers.shutdownNow();
            Thread.currentThread().interrupt();
        }
        watchdog.shutdownNow();
        for (AutoCloseable c : owned) {
            closeQuietly(c);
        }
    }

    private static void closeQuietly(AutoCloseable c) {
        try {
            c.close();
        } catch (Exception ignored) {
            // closing on a failure or deadline path; nothing else to do
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !"--config".equals(args[0])) {
            System.err.println("usage: java -cp out eastguard.tokensvc.TokenServer --config config/token.properties");
            System.exit(2);
        }
        TokenServer server = create(TokenConfig.load(Path.of(args[1])), Clock.systemUTC());
        Runtime.getRuntime().addShutdownHook(new Thread(server::close, "tokensvc-shutdown"));
        server.start();
    }
}
