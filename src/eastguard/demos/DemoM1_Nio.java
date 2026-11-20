package eastguard.demos;

import eastguard.client.EastGuardClient;
import eastguard.client.GatewaySession;
import eastguard.common.Bytes;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
import eastguard.common.IpAddress;
import eastguard.common.IssuerReply;
import eastguard.common.KeyStores;
import eastguard.common.Lease;
import eastguard.common.LeaseCodec;
import eastguard.common.ReasonCode;
import eastguard.common.ReplyStatus;
import eastguard.common.SecretSource;
import eastguard.common.Verdict;
import eastguard.common.WorkloadIdentity;
import eastguard.gateway.BackendConnector;
import eastguard.gateway.CountingDecisionSink;
import eastguard.gateway.GatewayConfig;
import eastguard.gateway.NioGateway;
import eastguard.tokensvc.TlsContextFactory;
import eastguard.tokensvc.TokenConfig;
import eastguard.tokensvc.TokenServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import javax.net.ssl.SSLContext;

/**
 * M1 demo (spec §11): one selector thread relays 500+ concurrent legitimate mTLS sessions, denies an unapproved
 * flow, applies controlled backpressure to a slow reader, and records a decoy touch.
 *
 * <pre>
 * .\scripts\gen-certs.ps1                       # once
 * java -cp out eastguard.demos.DemoM1_Nio       # optional arg: number of sessions (default 500)
 * </pre>
 *
 * Starts the echo backend on its fixed port ({@code backend} in the gateway config, 127.0.0.1:7002), a token
 * service and the gateway (both on ephemeral loopback ports). Exit code 0 when every check holds.
 */
public final class DemoM1_Nio {
    private static final Duration TIMEOUT = Duration.ofSeconds(15);
    private static final String GATEWAY_THREAD_PREFIX = "gateway-";
    private static int failures;

    private DemoM1_Nio() {
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("java.util.logging.SimpleFormatter.format", "        [log %4$s] %5$s%6$s%n");
        int sessionCount = args.length > 0 ? Integer.parseInt(args[0]) : 500;
        if (!Files.isRegularFile(Path.of("keys", "truststore.p12"))) {
            System.err.println("keys\\ not found. Run .\\scripts\\gen-certs.ps1 from the project root first.");
            System.exit(2);
        }
        TokenConfig tcfg = TokenConfig.load(Path.of("config/token.properties.example"));
        GatewayConfig gcfg = GatewayConfig.load(Path.of("config/gateway-app-02.properties.example"));
        Clock clock = Clock.systemUTC();
        InetAddress lo = InetAddress.getLoopbackAddress();
        IpAddress loopback = IpAddress.parse("127.0.0.1");
        Path trust = tcfg.tls().trustStore();
        SecretSource storePass = tcfg.tls().password();
        CountingDecisionSink sink = new CountingDecisionSink();
        int platformThreadsBefore = platformThreads();

        EnforcementSnapshot boot = eastguard.common.BootstrapState.snapshot(eastguard.common.Config.load(Path.of("config/bootstrap.properties.example")));
        try (EchoBackend echo = new EchoBackend(gcfg.backend().toSocketAddress(), 4_096).start();
                TokenServer issuerServer = TokenServer.create(tcfg, clock, new InetSocketAddress(lo, 0),
                        () -> EnforcementView.fresh(boot))) {
            issuerServer.start();

            NioGateway gw = new NioGateway(gcfg.serviceId(), TlsContextFactory.create(gcfg.tls()),
                    new InetSocketAddress(lo, 0), gcfg.backend().toSocketAddress(), () -> EnforcementView.fresh(boot),
                    clock, gcfg.limits(), sink, BackendConnector.DIRECT);
            gw.enableDecoy(gcfg.decoyId(), new InetSocketAddress(lo, 0));
            gw.start();
            try (gw) {
                Endpoint issuer = new Endpoint(loopback, issuerServer.port());
                Endpoint gateway = new Endpoint(loopback, gw.port());
                title("Echo backend on " + gcfg.backend() + " (fixed, private), token service on " + issuer
                        + ", gateway " + gw.serviceId() + " on " + gateway + ", decoy " + gcfg.decoyId() + " on port "
                        + gw.decoyPort());
                say("gateway-owned threads: " + gatewayThreads());

                // 1. Many concurrent legitimate sessions.
                title("1. " + sessionCount + " concurrent web-01 sessions through one selector thread");
                EastGuardClient web = client(Path.of("keys", "workload-web-01.p12"), trust, storePass, issuer);
                IssuerReply lease = web.requestLease("app-02");
                check(lease.status() == ReplyStatus.SUCCESS, "web-01 obtained one lease (reused: same cert and IP, 60 s)");
                List<GatewaySession> sessions = openSessions(web, gateway, lease.token(), sessionCount);
                check(sessions.size() == sessionCount, sessions.size() + " sessions admitted and echoed once each");
                check(awaitTrue(() -> gw.stats().sessions() == sessionCount),
                        "gateway reports " + gw.stats().sessions() + " live relay sessions");
                int owned = gatewayThreads().size();
                say("gateway-owned platform threads: " + owned + " " + gatewayThreads());
                say("JVM platform threads in total: " + platformThreads() + " (before the demo: " + platformThreadsBefore
                        + "; clients and echo backend use virtual threads)");
                check(owned < 10, "fewer than 10 gateway-owned threads for " + sessionCount + " sessions");
                long ok = roundTripAll(sessions, "second round");
                check(ok == sessionCount, "all " + ok + " sessions still live: second round trip at the same time");
                say("admission latency during the burst " + latency(gw.admissionLatency())
                        + " (queued behind 64 concurrent handshakes, client crypto in the same JVM)");
                gw.resetAdmissionLatency();
                for (int i = 0; i < 200; i++) {
                    try (GatewaySession s = web.connect(gateway, "127.0.0.1", lease.token())) {
                        echoOnce(s, "warm");
                    }
                }
                NioGateway.Latency warm = gw.admissionLatency();
                say("admission latency, warmed, one at a time " + latency(warm) + "; spec target p95 < 5000 us: "
                        + (warm.p95Micros() < 5_000 ? "met" : "NOT met") + " on this machine");
                say("buffers reserved: " + mib(gw.stats().reservedBufferBytes()) + " of " + mib(gcfg.limits().bufferBudgetBytes())
                        + " budget (" + gw.connectionCost() / 1024 + " KiB per connection)");
                for (GatewaySession s : sessions) {
                    s.close();
                }
                check(awaitTrue(() -> gw.stats().connections() == 0), "all sessions closed and released");

                // 2. Denied flows.
                title("2. api-01 has no approved edge to app-02");
                long backendAccepts = echo.accepted();
                Path apiStore = Path.of("keys", "workload-api-01.p12");
                EastGuardClient api = client(apiStore, trust, storePass, issuer);
                IssuerReply apiLease = api.requestLease("app-02");
                check(apiLease.status() == ReplyStatus.DENY, "token service refuses api-01 a lease (" + apiLease.status() + ")");
                Bytes fixture = signedFixture(tcfg, boot, "api-01", fingerprint(apiStore, storePass), loopback);
                long policyDenies = sink.count(ReasonCode.POLICY_DENY);
                try (GatewaySession s = api.connect(gateway, "127.0.0.1", fixture)) {
                    check(s.status() == ReplyStatus.DENY && sink.count(ReasonCode.POLICY_DENY) == policyDenies + 1,
                            "a validly signed api-01 lease (as if issued under an older policy) is denied by the gateway: "
                                    + s.status() + ", reason POLICY_DENY");
                }
                try (GatewaySession s = api.connect(gateway, "127.0.0.1", lease.token())) {
                    check(s.status() == ReplyStatus.DENY && sink.count(ReasonCode.IDENTITY_MISMATCH) == 1,
                            "api-01 replaying web-01's lease is denied: " + s.status() + ", reason IDENTITY_MISMATCH");
                }
                check(echo.accepted() == backendAccepts, "the backend never saw a denied connection");

                // 3. Backpressure.
                title("3. Slow reader: web-01 sends 16 MiB through the echo backend and reads slowly");
                backpressure(gw, web, gateway, lease.token());

                // 4. Decoy.
                title("4. A connection to the decoy port");
                try (Socket probe = new Socket()) {
                    probe.connect(new InetSocketAddress(lo, gw.decoyPort()), 2_000);
                    probe.setSoTimeout(5_000);
                    check(probe.getInputStream().read() == -1, "decoy accepted and closed at once, read nothing, sent nothing");
                } catch (IOException e) {
                    check(true, "decoy accepted and closed at once (" + e.getClass().getSimpleName() + ")");
                }
                check(awaitTrue(() -> sink.count(Verdict.DECOY) == 1), "exactly one DECOY event recorded (IP-only evidence)");

                NioGateway.Stats st = gw.stats();
                title("Gateway counters: accepted=" + st.accepted() + " allowed=" + st.allowed() + " denied=" + st.denied()
                        + " completed=" + st.completed() + " readPauses=" + st.readPauses() + " tlsFailures="
                        + st.tlsFailures() + " truncated=" + st.truncated());
                say("decisions by reason: " + sink);
                check(awaitTrue(() -> gw.stats().reservedBufferBytes() == 0), "every buffer reservation released");
            }
        }
        System.out.println();
        System.out.println(failures == 0 ? "DemoM1_Nio: all checks passed" : "DemoM1_Nio: " + failures + " check(s) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    /** Opens {@code n} sessions with bounded client-side concurrency; each echoes one message. */
    private static List<GatewaySession> openSessions(EastGuardClient web, Endpoint gateway, Bytes token, int n)
            throws Exception {
        Semaphore inFlight = new Semaphore(64);
        long t0 = System.nanoTime();
        List<GatewaySession> open = new ArrayList<>();
        try (ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<GatewaySession>> futures = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                int id = i;
                futures.add(ex.submit(() -> {
                    inFlight.acquire();
                    try {
                        GatewaySession s = web.connect(gateway, "127.0.0.1", token);
                        if (!s.allowed()) {
                            throw new IOException("denied: " + s.status());
                        }
                        echoOnce(s, "session " + id);
                        return s;
                    } finally {
                        inFlight.release();
                    }
                }));
            }
            for (Future<GatewaySession> f : futures) {
                try {
                    open.add(f.get());
                } catch (Exception e) {
                    say("session failed: " + e.getCause());
                }
            }
        }
        say("opened in " + (System.nanoTime() - t0) / 1_000_000 + " ms (client side: 64 concurrent connects)");
        return open;
    }

    private static long roundTripAll(List<GatewaySession> sessions, String text) throws InterruptedException {
        AtomicLong ok = new AtomicLong();
        try (ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor()) {
            for (GatewaySession s : sessions) {
                ex.submit(() -> {
                    try {
                        echoOnce(s, text);
                        ok.incrementAndGet();
                    } catch (IOException e) {
                        say("round trip failed: " + e);
                    }
                });
            }
        }
        return ok.get();
    }

    private static void echoOnce(GatewaySession s, String text) throws IOException {
        byte[] msg = text.getBytes(StandardCharsets.UTF_8);
        s.output().write(msg);
        s.output().flush();
        s.setReadTimeout(TIMEOUT);
        if (!Arrays.equals(msg, s.input().readNBytes(msg.length))) {
            throw new IOException("echo mismatch");
        }
    }

    private static void backpressure(NioGateway gw, EastGuardClient web, Endpoint gateway, Bytes token) throws Exception {
        final int total = 16 << 20;
        long pausesBefore = gw.stats().readPauses();
        try (GatewaySession s = web.connect(gateway, "127.0.0.1", token)) {
            AtomicLong written = new AtomicLong();
            Thread writer = Thread.ofVirtual().start(() -> {
                byte[] chunk = new byte[16 * 1024];
                try {
                    OutputStream out = s.output();
                    for (int off = 0; off < total; off += chunk.length) {
                        for (int i = 0; i < chunk.length; i++) {
                            chunk[i] = (byte) ((off + i) * 31);
                        }
                        out.write(chunk);
                        written.addAndGet(chunk.length);
                    }
                    out.flush();
                } catch (IOException e) {
                    say("writer stopped: " + e);
                }
            });
            s.setReadTimeout(TIMEOUT);
            InputStream in = s.input();
            byte[] buf = new byte[64 * 1024];
            long read = 0;
            long maxInFlight = 0;
            say(String.format("%8s %12s %12s %12s %16s %12s", "t(ms)", "written", "read", "in flight", "gateway queued", "readPauses"));
            long t0 = System.nanoTime();
            // Phase 1 (0-1.5 s): no reads at all. Phase 2 (1.5-3 s): 4 KiB every 5 ms (~800 KiB/s).
            for (int tick = 0; tick < 12; tick++) {
                long until = System.nanoTime() + 250_000_000L;
                while (tick >= 6 && System.nanoTime() < until) {
                    int n = in.read(buf, 0, 4_096);
                    read += verify(buf, n, read);
                    Thread.sleep(5);
                }
                if (tick < 6) {
                    Thread.sleep(250);
                }
                long inFlight = written.get() - read;
                maxInFlight = Math.max(maxInFlight, inFlight);
                NioGateway.Stats st = gw.stats();
                say(String.format("%8d %12s %12s %12s %16s %12d", (System.nanoTime() - t0) / 1_000_000, kib(written.get()),
                        kib(read), kib(inFlight), kib(st.queuedBytes()), st.readPauses() - pausesBefore));
            }
            // Phase 3: read the rest at full speed and check every byte.
            while (read < total) {
                int n = in.read(buf);
                if (n < 0) {
                    break;
                }
                read += verify(buf, n, read);
            }
            writer.join();
            NioGateway.Stats st = gw.stats();
            check(written.get() == total && read == total, "all " + mib(total) + " delivered intact after the reader caught up");
            check(maxInFlight < total / 2, "the writer was held back: at most " + kib(maxInFlight)
                    + " in flight (kernel socket buffers + gateway) while the reader was slow");
            check(st.peakQueuedBytes() <= gw.connectionCost(), "gateway queue peaked at " + kib(st.peakQueuedBytes())
                    + ", within its fixed per-connection buffers (" + kib(gw.connectionCost()) + ")");
            check(st.readPauses() > pausesBefore, "reads paused at the high-water mark " + (st.readPauses() - pausesBefore)
                    + " times and resumed at the low-water mark");
        }
    }

    private static int verify(byte[] buf, int n, long offset) throws IOException {
        if (n < 0) {
            throw new IOException("stream ended early at " + offset);
        }
        for (int i = 0; i < n; i++) {
            if (buf[i] != (byte) ((offset + i) * 31)) {
                throw new IOException("corrupted byte at " + (offset + i));
            }
        }
        return n;
    }

    /** A lease signed with the real lease key: what an issuer with an outdated policy might have handed out. */
    private static Bytes signedFixture(TokenConfig tcfg, EnforcementSnapshot boot, String sub, Bytes leaf, IpAddress ip) {
        char[] pw = tcfg.signerPassword().read();
        try {
            KeyStore ks = KeyStores.load(tcfg.signerStore(), pw);
            PrivateKey key = KeyStores.privateKey(ks, tcfg.signerAlias(), pw, tcfg.signerStore());
            long now = System.currentTimeMillis();
            byte[] jti = new byte[Lease.JTI_LENGTH];
            new SecureRandom().nextBytes(jti);
            Lease l = new Lease(boot.clusterId(), tcfg.keyId(), sub, "app-02", ip, leaf, now, now + 60_000,
                    Bytes.copyOf(jti), boot.revision());
            return Bytes.copyOf(LeaseCodec.issue(l, key));
        } finally {
            Arrays.fill(pw, '\0');
        }
    }

    private static EastGuardClient client(Path store, Path trust, SecretSource pass, Endpoint issuer) {
        SSLContext ctx = TlsContextFactory.create(new TlsContextFactory.Material(store, trust, pass));
        return new EastGuardClient(ctx, issuer, "127.0.0.1", TIMEOUT);
    }

    private static Bytes fingerprint(Path store, SecretSource pass) throws Exception {
        char[] pw = pass.read();
        try {
            KeyStore ks = KeyStores.load(store, pw);
            X509Certificate leaf = KeyStores.certificate(ks, KeyStores.singleKeyAlias(ks, store), store);
            return WorkloadIdentity.fingerprint(leaf);
        } finally {
            Arrays.fill(pw, '\0');
        }
    }

    private static List<String> gatewayThreads() {
        return Thread.getAllStackTraces().keySet().stream().map(Thread::getName)
                .filter(n -> n.startsWith(GATEWAY_THREAD_PREFIX)).sorted().toList();
    }

    private static int platformThreads() {
        return Thread.getAllStackTraces().size();
    }

    private static boolean awaitTrue(BooleanSupplier condition) throws InterruptedException {
        long end = System.nanoTime() + TIMEOUT.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > end) {
                return false;
            }
            Thread.sleep(10);
        }
        return true;
    }

    /** Complete preamble -> flushed ALLOW, measured by the gateway. */
    private static String latency(NioGateway.Latency l) {
        return "(" + l.samples() + " samples, preamble -> flushed ALLOW): p50=" + l.p50Micros() + " us, p95="
                + l.p95Micros() + " us, p99=" + l.p99Micros() + " us";
    }

    private static String kib(long bytes) {
        return bytes / 1024 + " KiB";
    }

    private static String mib(long bytes) {
        return String.format("%.1f MiB", bytes / 1048576.0);
    }

    private static void title(String s) {
        System.out.println();
        System.out.println(s);
    }

    private static void say(String s) {
        System.out.println("    " + s);
    }

    private static void check(boolean ok, String what) {
        if (!ok) {
            failures++;
        }
        System.out.println("  " + (ok ? "[ok]   " : "[FAIL] ") + what);
    }
}
