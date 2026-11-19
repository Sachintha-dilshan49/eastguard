package eastguard.tokensvc;

import eastguard.common.Ed25519;
import eastguard.common.EnforcementView;
import eastguard.common.IpAddress;
import eastguard.common.IssuerRequest;
import eastguard.common.CodecException;
import eastguard.common.KeyStores;
import eastguard.common.PolicyEvaluator;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Path;
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
     * Wires a server from configuration: its own TLS context, the signing key (which must match the published
     * verification key for {@code lease.keyId}), and a fixed bootstrap view.
     */
    public static TokenServer create(TokenConfig cfg, Clock clock, InetSocketAddress bind) {
        SSLContext ctx = TlsContextFactory.create(cfg.tls());
        PrivateKey signingKey = loadSigningKey(cfg);
        EnforcementView view = EnforcementView.fresh(cfg.bootstrap());
        LeaseIssuer issuer = new LeaseIssuer(new PolicyEvaluator(clock), cfg.keyId(), signingKey,
                new IssueLimiter(cfg.issuePerIdentityPerSecond(), System::nanoTime), clock, new SecureRandom());
        return new TokenServer(ctx, bind, () -> view, issuer, cfg.limits());
    }

    public static TokenServer create(TokenConfig cfg, Clock clock) {
        return create(cfg, clock, cfg.listen().toSocketAddress());
    }

    static PrivateKey loadSigningKey(TokenConfig cfg) {
        Path file = cfg.signerStore();
        char[] pw = cfg.signerPassword().read();
        try {
            KeyStore ks = KeyStores.load(file, pw);
            PrivateKey key = KeyStores.privateKey(ks, cfg.signerAlias(), pw, file);
            PublicKey own = KeyStores.certificate(ks, cfg.signerAlias(), file).getPublicKey();
            PublicKey published = cfg.bootstrap().tokenKeys().get(cfg.keyId());
            if (published == null
                    || !Arrays.equals(Ed25519.rawPublicKey(own), Ed25519.rawPublicKey(published))) {
                throw new IllegalStateException("lease signing key " + cfg.keyId()
                        + " does not match the published verification key; gateways would reject every lease");
            }
            return key;
        } finally {
            Arrays.fill(pw, '\0');
        }
    }

    public synchronized void start() throws IOException {
        if (server != null) {
            throw new IllegalStateException("already started");
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
            LeaseIssuer.Outcome o = issuer.issue(state.get(), s.getSession(), ip, request.targetService());
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
