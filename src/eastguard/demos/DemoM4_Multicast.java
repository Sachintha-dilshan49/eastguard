package eastguard.demos;

import eastguard.bus.FaultyTransport;
import eastguard.bus.MemoryTransport;
import eastguard.bus.MulticastTransport;
import eastguard.bus.NoticeTransport;
import eastguard.bus.QuarantineSender;
import eastguard.client.EastGuardClient;
import eastguard.client.GatewaySession;
import eastguard.common.BootstrapState;
import eastguard.common.Bytes;
import eastguard.common.Config;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.IpAddress;
import eastguard.common.IssuerReply;
import eastguard.common.NoticeOperation;
import eastguard.common.ReasonCode;
import eastguard.common.ReplyStatus;
import eastguard.common.Selector;
import eastguard.control.ControlConfig;
import eastguard.control.ControlPlaneImpl;
import eastguard.control.Credentials;
import eastguard.control.Dto;
import eastguard.control.Journal;
import eastguard.control.Role;
import eastguard.control.StateSync;
import eastguard.gateway.CountingDecisionSink;
import eastguard.gateway.GatewayConfig;
import eastguard.gateway.NioGateway;
import eastguard.tokensvc.TlsContextFactory;
import eastguard.tokensvc.TokenConfig;
import eastguard.tokensvc.TokenServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;

/**
 * M4 demo (spec §11): the multicast quarantine bus. Three NIO gateways for app-02 and the token service are the
 * receivers; each has its own {@link StateSync} and notice listener, wired exactly as in production
 * ({@link NioGateway#create}, {@link TokenServer#create}). The control plane commits, forces the journal, and then
 * multicasts the same signed EGC1 notice three times with the real control-plane signer.
 *
 * <ol>
 *   <li>Containment latency: repeated quarantines of web-01 while it has a live session at every gateway; time from
 *       the durable commit to the client seeing its session closed (spec target p95 &lt; 100 ms).</li>
 *   <li>Duplicated notices are applied once.</li>
 *   <li>A notice deliberately dropped: state still converges through the next sync.</li>
 *   <li>An out-of-order old notice does not roll state back.</li>
 *   <li>A RELEASE clears nothing until a covering snapshot arrives.</li>
 *   <li>The released workload's old lease is rejected by the watermark; a new lease works.</li>
 * </ol>
 *
 * <pre>
 * .\scripts\gen-certs.ps1                     # once (or -AddControlSigner on an older key set)
 * java -cp out eastguard.demos.DemoM4_Multicast            # real multicast on 127.0.0.1, 239.20.20.20:4446
 * java -cp out eastguard.demos.DemoM4_Multicast --memory   # in-memory transport instead
 * </pre>
 *
 * The control plane runs in this JVM; enforcement points call its {@code sync} directly (credential and role still
 * checked) instead of over RMI, which {@code DemoM5_Rmi} covers. API credentials are generated in memory. Faults
 * are injected on the sending side ({@link FaultyTransport}), so they apply to real multicast too. Exit code 0 when
 * every check holds.
 */
public final class DemoM4_Multicast {
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final Selector WEB = Selector.identity("web-01");
    private static final int TRIALS = 20;
    private static final int GATEWAYS = 3;
    private static int failures;
    private static int requestIds;

    private static ControlPlaneImpl cp;
    private static final Map<String, Bytes> SECRETS = new HashMap<>();

    private DemoM4_Multicast() {
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("java.util.logging.SimpleFormatter.format", "        [log %4$s] %5$s%6$s%n");
        java.util.logging.Logger.getLogger("eastguard").setLevel(java.util.logging.Level.WARNING);
        for (String f : new String[] {"keys/truststore.p12", "keys/control-signer.p12", "keys/control-k1.cer"}) {
            if (!Files.isRegularFile(Path.of(f))) {
                System.err.println(f + " not found. Run .\\scripts\\gen-certs.ps1 (or .\\scripts\\gen-certs.ps1"
                        + " -AddControlSigner on an existing key set) first.");
                System.exit(2);
            }
        }
        boolean memory = Arrays.asList(args).contains("--memory");
        ControlConfig ccfg = ControlConfig.load(Path.of("config/control.properties.example"));
        TokenConfig tcfg = TokenConfig.load(Path.of("config/token.properties.example"));
        GatewayConfig gcfg = GatewayConfig.load(Path.of("config/gateway-app-02.properties.example"));
        Clock clock = Clock.systemUTC();
        IpAddress loopback = IpAddress.parse("127.0.0.1");

        // ---- transport: real multicast if this host delivers it on the configured interface ----
        NoticeTransport base = memory ? null : multicastOrNull(ccfg);
        String transportName;
        if (base == null) {
            base = new MemoryTransport();
            transportName = "in-memory transport" + (memory ? " (--memory)" : " (no local multicast delivery here)");
        } else {
            transportName = "multicast " + ccfg.multicast().group() + ":" + ccfg.multicast().port() + " on "
                    + ((MulticastTransport) base).networkInterface().getName() + ", TTL " + ccfg.multicast().ttl();
        }
        FaultyTransport net = new FaultyTransport(base);

        // ---- control plane: fresh journal, in-memory credentials, the real notice signer ----
        List<Credentials.Principal> principals = new ArrayList<>();
        for (String[] p : new String[][] {{"admin", "ADMIN"}, {"operator", "OPERATOR"}, {"tokensvc", "ISSUER"},
                {"gw-1", "GATEWAY"}, {"gw-2", "GATEWAY"}, {"gw-3", "GATEWAY"}}) {
            byte[] s = new byte[32];
            new SecureRandom().nextBytes(s);
            SECRETS.put(p[0], Bytes.copyOf(s));
            principals.add(Credentials.Principal.withSecret(p[0], Role.valueOf(p[1]), Bytes.copyOf(s)));
        }
        Path journalFile = Path.of("out", "demo-m4", "control.journal");
        Files.createDirectories(journalFile.getParent());
        Files.deleteIfExists(journalFile);
        EnforcementSnapshot initial = BootstrapState.snapshot(Config.load(Path.of("config/bootstrap.properties.example")));
        Journal journal = Journal.open(journalFile);
        cp = ControlPlaneImpl.open(journal, clock, Credentials.of(principals), ccfg.settings());
        require(cp.bootstrap(initial, "admin", "initial deny-by-default policy").ok(), "bootstrap");
        require(cp.replacePolicy(new Dto.ReplacePolicyRequest(cred("admin"), "m4-edit", 1,
                List.of(new Edge("web-01", "app-02"), new Edge("api-01", "app-02")), "demo: api-01 is the bystander"))
                .ok(), "policy edit");
        AtomicLong committedAt = new AtomicLong(); // monotonic time of the last durable quarantine commit
        cp.onContainment(c -> {
            if (c.operation() == NoticeOperation.QUARANTINE) {
                committedAt.set(System.nanoTime());
            }
        });
        QuarantineSender sender = QuarantineSender.fromConfig(ccfg.notices(), cp.snapshot(), net, clock).start();
        cp.onContainment(sender::committed);
        title("Control plane at revision " + cp.snapshot().revision() + "; notices signed by "
                + ccfg.notices().keyId() + " (published in the snapshot, separate from the lease key) over " + transportName);

        // ---- receivers: three gateways and the token service, joined before their first sync ----
        AtomicBoolean partitioned = new AtomicBoolean(); // cuts sync (RMI) only; multicast keeps flowing
        CountingDecisionSink sink = new CountingDecisionSink();
        SSLContext gwCtx = TlsContextFactory.create(gcfg.tls());
        List<NioGateway> gws = new ArrayList<>();
        try (EchoBackend echo = new EchoBackend(gcfg.backend().toSocketAddress(), 64).start();
                TokenServer ts = TokenServer.create(noTelemetry(tcfg), TlsContextFactory.create(tcfg.tls()), clock,
                        new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), source("tokensvc", partitioned), net)) {
            for (int i = 1; i <= GATEWAYS; i++) {
                NioGateway g = NioGateway.create(noDecoy(gcfg), new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), gwCtx,
                        clock, sink, source("gw-" + i, partitioned), net, "gw-" + i);
                gws.add(g);
                g.start();
            }
            ts.start();
            List<StateSync> receivers = new ArrayList<>();
            gws.forEach(g -> receivers.add(g.stateSync()));
            receivers.add(ts.stateSync());
            Endpoint issuer = new Endpoint(loopback, ts.port());
            List<Endpoint> gateways = new ArrayList<>();
            gws.forEach(g -> gateways.add(new Endpoint(loopback, g.port())));
            say("gateways app-02 on " + gateways + ", token service on " + issuer + ", backend " + gcfg.backend());
            EastGuardClient web = workload("keys/workload-web-01.p12", tcfg, issuer);
            EastGuardClient api = workload("keys/workload-api-01.p12", tcfg, issuer);
            check(await(() -> lease(web).status() == ReplyStatus.SUCCESS, 8_000), "all receivers synced");

            // Bystander: api-01 keeps one session at every gateway for the whole demo.
            Bytes apiLease = lease(api).token();
            List<GatewaySession> bystanders = new ArrayList<>();
            for (Endpoint g : gateways) {
                bystanders.add(attempt(() -> open(api, g, apiLease), 3_000));
            }
            check(bystanders.stream().allMatch(s -> s != null && echo(s, "hi")), "api-01 has a live session at each gateway");

            // ---- 1. containment latency ----
            title("1. Quarantine web-01 " + TRIALS + " times while it has a live session at each of the " + GATEWAYS
                    + " gateways; commit -> session closed");
            List<Long> micros = new ArrayList<>();
            int closedAll = 0;
            for (int t = 0; t < TRIALS; t++) {
                IssuerReply l = attempt(() -> success(lease(web)), 3_000);
                List<GatewaySession> sessions = new ArrayList<>();
                for (Endpoint g : gateways) {
                    sessions.add(l == null ? null : attempt(() -> open(web, g, l.token()), 3_000));
                }
                if (sessions.contains(null) || !sessions.stream().allMatch(s -> echo(s, "ping"))) {
                    check(false, "trial " + t + ": web-01 sessions open");
                    continue;
                }
                long[] closedAt = new long[GATEWAYS];
                List<Thread> readers = new ArrayList<>();
                for (int i = 0; i < GATEWAYS; i++) {
                    int k = i;
                    readers.add(Thread.ofVirtual().start(() -> closedAt[k] = closed(sessions.get(k)) ? System.nanoTime() : 0));
                }
                quarantine(WEB);
                for (Thread r : readers) {
                    r.join(5_000);
                }
                long c = committedAt.get();
                boolean all = true;
                for (long at : closedAt) {
                    if (at == 0) {
                        all = false;
                    } else {
                        micros.add((at - c) / 1_000);
                    }
                }
                closedAll += all ? 1 : 0;
                release(WEB);
            }
            micros.sort(null);
            check(closedAll == TRIALS, "every trial closed web-01's session at all " + GATEWAYS + " gateways ("
                    + micros.size() + " samples)");
            if (!micros.isEmpty()) {
                long p50 = pct(micros, 50);
                long p95 = pct(micros, 95);
                say(String.format("commit -> closed: p50 %.1f ms, p95 %.1f ms, max %.1f ms", p50 / 1e3, p95 / 1e3,
                        micros.get(micros.size() - 1) / 1e3));
                check(p95 < 100_000, "spec target p95 < 100 ms on a healthy single segment (measured, not a guarantee)");
            }
            check(bystanders.stream().allMatch(s -> echo(s, "still here")),
                    "api-01's unrelated sessions survived all " + TRIALS + " targeted quarantines");

            // ---- 2. duplicates ----
            title("2. Every notice datagram sent 4 times (12 copies of one notice per receiver)");
            quiet(sender);
            settle(receivers);
            List<long[]> before = noticeCounts(receivers);
            net.duplicate(4);
            long dupRev = quarantine(Selector.ip(IpAddress.parse("10.0.9.9")));
            quiet(sender);
            net.duplicate(1);
            check(await(() -> seen(receivers, before) == 12L * receivers.size(), 3_000), "all copies verified");
            boolean once = true;
            for (int i = 0; i < receivers.size(); i++) {
                StateSync.NoticeStats s = receivers.get(i).noticeStats();
                long applied = s.accepted() - before.get(i)[0];
                long ignored = s.duplicates() + s.stale() - before.get(i)[1];
                say(receivers.get(i).stats().revision() >= dupRev ? name(i) + ": applied " + applied + ", ignored "
                        + ignored + " (duplicate, or already covered by the immediate sync)" : name(i) + ": not synced");
                once &= applied == 1 && ignored == 11;
            }
            check(once, "each receiver applied the notice exactly once");
            release(Selector.ip(IpAddress.parse("10.0.9.9")));

            // ---- 3. a lost notice ----
            title("3. All three copies of the next notice are dropped");
            IssuerReply l3 = attempt(() -> success(lease(web)), 3_000);
            List<GatewaySession> s3 = new ArrayList<>();
            for (Endpoint g : gateways) {
                s3.add(l3 == null ? null : attempt(() -> open(web, g, l3.token()), 3_000));
            }
            check(!s3.contains(null), "web-01 has a live session at each gateway");
            long[] newestBefore = newest(receivers);
            quiet(sender);
            net.dropNext(QuarantineSender.COPIES);
            long t3 = System.nanoTime();
            long lostRev = quarantine(WEB);
            boolean allClosed = true;
            for (GatewaySession s : s3) {
                allClosed &= s != null && closed(s);
            }
            long ms3 = (System.nanoTime() - t3) / 1_000_000;
            check(net.dropped() >= QuarantineSender.COPIES, "the notice for revision " + lostRev + " never left the sender");
            check(allClosed, "the sessions still closed, " + ms3 + " ms after the commit: the next poll (1 s +-20 %)"
                    + " installed the snapshot");
            check(Arrays.equals(newestBefore, newest(receivers)),
                    "no receiver saw the notice; convergence came from authoritative state");
            check(attempt(() -> lease(web).status() == ReplyStatus.QUARANTINED ? Boolean.TRUE : null, 3_000) != null,
                    "token service refuses web-01: QUARANTINED");
            release(WEB);

            // ---- 4. an out-of-order old notice ----
            title("4. Notices held back, then delivered late and newest first");
            quiet(sender);
            net.hold();
            long oldQ = quarantine(WEB);
            long oldR = release(WEB);
            check(await(() -> minRevision(receivers) >= oldR, 4_000), "receivers learned revisions " + oldQ + " and "
                    + oldR + " by polling");
            IssuerReply l4 = attempt(() -> success(lease(web)), 3_000);
            GatewaySession s4 = l4 == null ? null : attempt(() -> open(web, gateways.get(0), l4.token()), 3_000);
            check(s4 != null && echo(s4, "after release"), "web-01 is admitted again");
            settle(receivers);
            List<long[]> before4 = noticeCounts(receivers);
            quiet(sender);
            int late = net.releaseHeld(true); // RELEASE copies first, then the old QUARANTINE
            check(await(() -> seen(receivers, before4) == (long) late * receivers.size(), 3_000),
                    late + " late datagrams verified at every receiver");
            long staleDelta = 0;
            for (int i = 0; i < receivers.size(); i++) {
                staleDelta += receivers.get(i).noticeStats().stale() - before4.get(i)[1];
            }
            check(staleDelta == (long) late * receivers.size(), "all ignored as old news (revision <= installed)");
            check(receivers.stream().allMatch(r -> r.get().overlay().isEmpty()), "no overlay was created");
            check(s4 != null && echo(s4, "still allowed"), "web-01's session was not cut by the old QUARANTINE");
            check(success(lease(web)) != null, "and web-01 can still get a lease: no rollback");
            closeQuietly(s4);

            // ---- 5 and 6. release needs a covering snapshot; then the watermark ----
            title("5. Release while enforcement points cannot sync (multicast still delivers)");
            IssuerReply old = attempt(() -> success(lease(web)), 3_000);
            check(old != null, "web-01 holds a lease issued at revision " + cp.snapshot().revision());
            quarantine(WEB);
            check(await(() -> minRevision(receivers) == cp.snapshot().revision(), 3_000), "quarantine installed everywhere");
            partitioned.set(true);
            long rel = release(WEB);
            check(await(() -> receivers.stream().allMatch(r -> r.get().newestKnownRevision() >= rel), 3_000),
                    "every receiver verified the RELEASE notice for revision " + rel);
            check(lease(web).status() == ReplyStatus.QUARANTINED, "token service still refuses web-01: QUARANTINED");
            check(status(web, gateways.get(1), old.token()) == ReplyStatus.QUARANTINED,
                    "gateway still refuses web-01: QUARANTINED (the RELEASE cleared nothing)");
            check(lease(api).status() == ReplyStatus.UNAVAILABLE,
                    "new issuance is paused while catching up to revision " + rel + ": api-01 gets UNAVAILABLE (NOT_READY)");
            check(echo(bystanders.get(0), "bystander"), "existing unrelated sessions continue within the freshness window");
            partitioned.set(false);
            check(await(() -> minRevision(receivers) >= rel, 3_000), "sync restored: snapshot " + rel + " installed");

            title("6. The released workload's leases");
            long superseded = sink.count(ReasonCode.LEASE_SUPERSEDED);
            check(status(web, gateways.get(2), old.token()) == ReplyStatus.DENY
                    && sink.count(ReasonCode.LEASE_SUPERSEDED) == superseded + 1,
                    "the old lease is denied by the watermark minTokenRevision=" + rel + ": LEASE_SUPERSEDED");
            IssuerReply fresh = attempt(() -> success(lease(web)), 3_000);
            boolean works = fresh != null;
            for (Endpoint g : gateways) {
                GatewaySession s = works ? open(web, g, fresh.token()) : null;
                works &= s != null && echo(s, "back");
                closeQuietly(s);
            }
            check(works, "a newly issued lease is admitted at every gateway");

            title("Notice statistics per receiver");
            for (int i = 0; i < receivers.size(); i++) {
                say(name(i) + ": " + receivers.get(i).noticeStats());
            }
            say("sender: " + sender.stats());
            say("gateway decisions: " + sink + "; backend connections " + echo.accepted());
            bystanders.forEach(DemoM4_Multicast::closeQuietly);
        } finally {
            gws.forEach(NioGateway::close);
            sender.close();
            if (base instanceof AutoCloseable c) {
                c.close();
            }
            journal.close();
        }
        System.out.println();
        System.out.println(failures == 0 ? "DemoM4_Multicast: all checks passed"
                : "DemoM4_Multicast: " + failures + " check(s) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    // ---- control plane ----

    /** The example gateway config without its decoy listener: three gateways cannot share its port. */
    private static GatewayConfig noDecoy(GatewayConfig c) {
        return new GatewayConfig(c.serviceId(), c.listen(), c.backend(), null, c.decoyId(), c.tls(), c.limits(),
                c.control(), c.sync(), null, c.multicast());
    }

    /** The example token config without its telemetry producer (this demo runs no detector). */
    private static TokenConfig noTelemetry(TokenConfig c) {
        return new TokenConfig(c.listen(), c.tls(), c.signerStore(), c.signerAlias(), c.keyId(), c.signerPassword(),
                c.limits(), c.issuePerIdentityPerSecond(), c.control(), c.sync(), null, c.multicast());
    }

    /** Waits until the sender has handled every committed containment, so a fault toggled next hits the next one. */
    private static void quiet(QuarantineSender sender) throws InterruptedException {
        require(await(() -> {
            QuarantineSender.Stats s = sender.stats();
            return s.committed() == s.notices() + s.skipped() + s.dropped()
                    && s.datagrams() + s.sendFailures() == s.notices() * QuarantineSender.COPIES;
        }, 3_000), "sender idle");
    }

    private static Dto.Credential cred(String principal) {
        return new Dto.Credential(principal, SECRETS.get(principal));
    }

    private static StateSync.Source source(String principal, AtomicBoolean partitioned) {
        return known -> {
            if (partitioned.get()) {
                throw new IOException("control plane unreachable (demo partition)");
            }
            return cp.sync(new Dto.SyncRequest(cred(principal), known));
        };
    }

    private static long quarantine(Selector s) {
        Dto.MutationResult r = cp.quarantine(new Dto.QuarantineRequest(cred("operator"), "m4-q-" + (++requestIds),
                List.of(s), Duration.ofMinutes(5).toMillis(), "demo containment"));
        require(r.ok(), "quarantine " + r);
        return r.revision();
    }

    private static long release(Selector s) {
        Dto.MutationResult r = cp.release(new Dto.ReleaseRequest(cred("operator"), "m4-r-" + (++requestIds),
                List.of(s), "demo remediation verified"));
        require(r.ok(), "release " + r);
        return r.revision();
    }

    /** A multicast transport that delivered a probe to a joined receiver on this host, or {@code null}. */
    private static NoticeTransport multicastOrNull(ControlConfig ccfg) {
        try {
            MulticastTransport mt = new MulticastTransport(ccfg.multicast());
            try (NoticeTransport.Receiver r = mt.join()) {
                mt.send(new byte[] {'p', 'r', 'o', 'b', 'e'});
                byte[] buf = new byte[NoticeTransport.MAX_DATAGRAM + 1];
                long end = System.nanoTime() + 1_000_000_000L;
                while (System.nanoTime() < end) {
                    if (r.receive(buf, 200) == 5) {
                        return mt;
                    }
                }
            }
            mt.close();
        } catch (IOException e) {
            System.out.println("    multicast unavailable: " + e.getMessage());
        }
        return null;
    }

    // ---- receivers ----

    private static String name(int i) {
        return i < GATEWAYS ? "gw-" + (i + 1) : "tokensvc";
    }

    /** Per receiver: {accepted, duplicates + stale}. */
    private static List<long[]> noticeCounts(List<StateSync> rs) {
        List<long[]> out = new ArrayList<>();
        for (StateSync r : rs) {
            StateSync.NoticeStats s = r.noticeStats();
            out.add(new long[] {s.accepted(), s.duplicates() + s.stale()});
        }
        return out;
    }

    /** Waits until in-flight copies of earlier notices have been processed everywhere (counts stop moving). */
    private static void settle(List<StateSync> rs) throws InterruptedException {
        long end = System.nanoTime() + 3_000_000_000L;
        List<long[]> last = noticeCounts(rs);
        while (System.nanoTime() < end) {
            Thread.sleep(150);
            if (seen(rs, last) == 0) {
                return;
            }
            last = noticeCounts(rs);
        }
    }

    /** Notices processed by all receivers since {@code before}. */
    private static long seen(List<StateSync> rs, List<long[]> before) {
        long n = 0;
        List<long[]> now = noticeCounts(rs);
        for (int i = 0; i < rs.size(); i++) {
            n += now.get(i)[0] + now.get(i)[1] - before.get(i)[0] - before.get(i)[1];
        }
        return n;
    }

    private static long[] newest(List<StateSync> rs) {
        return rs.stream().mapToLong(r -> r.noticeStats().newest()).toArray();
    }

    private static long minRevision(List<StateSync> rs) {
        return rs.stream().mapToLong(r -> r.stats().revision()).min().orElse(0);
    }

    // ---- clients ----

    private static EastGuardClient workload(String store, TokenConfig tcfg, Endpoint issuer) {
        SSLContext ctx = TlsContextFactory.create(new TlsContextFactory.Material(Path.of(store),
                tcfg.tls().trustStore(), tcfg.tls().password()));
        return new EastGuardClient(ctx, issuer, "127.0.0.1", TIMEOUT);
    }

    private static IssuerReply lease(EastGuardClient c) {
        try {
            return c.requestLease("app-02");
        } catch (IOException e) {
            return IssuerReply.failure(ReplyStatus.UNAVAILABLE);
        }
    }

    private static IssuerReply success(IssuerReply r) {
        return r.status() == ReplyStatus.SUCCESS ? r : null;
    }

    private static GatewaySession open(EastGuardClient c, Endpoint gateway, Bytes token) {
        try {
            GatewaySession s = c.connect(gateway, "127.0.0.1", token);
            if (s.allowed()) {
                return s;
            }
            s.close();
        } catch (IOException e) {
            // retried by the caller
        }
        return null;
    }

    private static ReplyStatus status(EastGuardClient c, Endpoint gateway, Bytes token) {
        try (GatewaySession s = c.connect(gateway, "127.0.0.1", token)) {
            return s.status();
        } catch (IOException e) {
            return null;
        }
    }

    private static boolean echo(GatewaySession s, String text) {
        try {
            byte[] msg = text.getBytes(StandardCharsets.UTF_8);
            s.output().write(msg);
            s.output().flush();
            s.setReadTimeout(TIMEOUT);
            return Arrays.equals(msg, s.input().readNBytes(msg.length));
        } catch (IOException e) {
            return false;
        }
    }

    private static boolean closed(GatewaySession s) {
        try {
            s.setReadTimeout(TIMEOUT);
            return s.input().read() == -1;
        } catch (IOException e) {
            return !(e instanceof java.net.SocketTimeoutException);
        }
    }

    private static void closeQuietly(GatewaySession s) {
        if (s != null) {
            try {
                s.close();
            } catch (IOException ignored) {
                // demo cleanup
            }
        }
    }

    // ---- helpers ----

    private static long pct(List<Long> sorted, int p) {
        int i = (int) Math.ceil(p / 100.0 * sorted.size()) - 1;
        return sorted.get(Math.max(0, Math.min(sorted.size() - 1, i)));
    }

    private static boolean await(Supplier<Boolean> condition, long millis) throws InterruptedException {
        long end = System.nanoTime() + millis * 1_000_000;
        while (!condition.get()) {
            if (System.nanoTime() > end) {
                return false;
            }
            Thread.sleep(20);
        }
        return true;
    }

    private static <T> T attempt(Supplier<T> attempt, long millis) throws InterruptedException {
        long end = System.nanoTime() + millis * 1_000_000;
        T v;
        while ((v = attempt.get()) == null && System.nanoTime() < end) {
            Thread.sleep(20);
        }
        return v;
    }

    private static void require(boolean ok, String what) {
        if (!ok) {
            throw new IllegalStateException("demo setup failed: " + what);
        }
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
