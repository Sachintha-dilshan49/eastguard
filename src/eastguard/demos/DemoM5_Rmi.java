package eastguard.demos;

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
import eastguard.common.ReasonCode;
import eastguard.common.ReplyStatus;
import eastguard.common.SecretSource;
import eastguard.common.Selector;
import eastguard.common.PolicyMode;
import eastguard.control.AuditClient;
import eastguard.control.AuditHttpServer;
import eastguard.control.ControlClient;
import eastguard.handlers.PolicyView;
import eastguard.handlers.ZtpUrlHandler;
import java.net.URI;
import java.net.URL;
import eastguard.control.ControlConfig;
import eastguard.control.ControlPlaneImpl;
import eastguard.control.ControlServer;
import eastguard.control.Credentials;
import eastguard.control.Dto;
import eastguard.control.Journal;
import eastguard.control.RmiSupport;
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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;

/**
 * M5 demo (spec §11): the control plane over secured RMI. An audited policy edit, a version conflict, an
 * idempotent retry, a quarantine that closes a live gateway session through the sync path, a release after which
 * the old lease fails on its watermark and a new lease works, a typed {@code ztp://policy/app-02} read through
 * the explicit URL handler, the paginated HTTPS audit export read with {@code HttpsURLConnection} and the console
 * certificate, and fail-closed behaviour when the control plane goes away.
 *
 * <pre>
 * .\scripts\gen-certs.ps1          # once
 * .\scripts\gen-credentials.ps1    # once
 * java -cp out eastguard.demos.DemoM5_Rmi
 * </pre>
 *
 * Runs every component in this JVM with the production wiring and the example configs: control plane on
 * 127.0.0.1:1099/1100 (journal under {@code out\demo-m5}, recreated each run), token service and gateway
 * synchronising over RMI, echo backend on 127.0.0.1:7002. Exit code 0 when every check holds.
 */
public final class DemoM5_Rmi {
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final Selector WEB = Selector.identity("web-01");
    private static int failures;

    private DemoM5_Rmi() {
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("java.util.logging.SimpleFormatter.format", "        [log %4$s] %5$s%6$s%n");
        for (String f : new String[] {"keys/truststore.p12", "keys/control-credentials.properties",
                "keys/telemetry/tokensvc.key", "keys/console.p12"}) {
            if (!Files.isRegularFile(Path.of(f))) {
                System.err.println(f + " not found. Run .\\scripts\\gen-certs.ps1 and .\\scripts\\gen-credentials.ps1"
                        + " (or gen-credentials.ps1 -TelemetryKeys, gen-certs.ps1 -AddConsole) first.");
                System.exit(2);
            }
        }
        ControlConfig ccfg = ControlConfig.load(Path.of("config/control.properties.example"));
        TokenConfig tcfg = TokenConfig.load(Path.of("config/token.properties.example"));
        GatewayConfig gcfg = GatewayConfig.load(Path.of("config/gateway-app-02.properties.example"));
        RmiSupport.configureJvm(ccfg.rmiHost()); // before any RMI class is used
        Clock clock = Clock.systemUTC();
        IpAddress loopback = IpAddress.parse("127.0.0.1");

        // ---- the control plane: explicit bootstrap of a fresh demo journal, then serve ----
        Path journalFile = Path.of("out", "demo-m5", "control.journal");
        Files.deleteIfExists(journalFile);
        EnforcementSnapshot initial = BootstrapState.snapshot(Config.load(Path.of("config/bootstrap.properties.example")));
        Journal journal = Journal.open(journalFile);
        ControlPlaneImpl cp = ControlPlaneImpl.open(journal, clock, Credentials.load(ccfg.credentialsFile()),
                ccfg.settings());
        Dto.MutationResult b = cp.bootstrap(initial, "admin", "initial deny-by-default policy");
        title("Control plane: bootstrapped " + journalFile + " at revision " + b.revision() + " (approved: "
                + initial.policy().approvedEdges() + ")");
        SSLContext controlTls = TlsContextFactory.create(ccfg.tls());
        ControlServer server = ControlServer.start(cp, controlTls, ccfg.rmiHost(), ccfg.registryPort(),
                ccfg.objectPort(), ccfg.credentialsFile());
        AuditHttpServer audit = AuditHttpServer.start(cp, controlTls, ccfg.audit());
        say("RMI registry " + ccfg.rmiHost() + ":" + ccfg.registryPort() + ", object port " + ccfg.objectPort()
                + ", TLS 1.3 with client certificates on both, per-call API credentials; HTTPS audit export on "
                + ccfg.audit().listen() + " for " + ccfg.audit().allowedClients());

        CountingDecisionSink sink = new CountingDecisionSink();
        try (EchoBackend echo = new EchoBackend(gcfg.backend().toSocketAddress(), 64).start();
                NioGateway gw = NioGateway.create(gcfg, clock, sink);
                TokenServer issuerServer = TokenServer.create(tcfg, clock,
                        new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))) {
            gw.start();
            issuerServer.start();
            Endpoint issuer = new Endpoint(loopback, issuerServer.port());
            Endpoint gateway = new Endpoint(loopback, gw.port());
            say("gateway " + gw.serviceId() + " on " + gateway + " and token service on " + issuer
                    + " poll the control plane once a second (no admissions until the first sync)");

            SSLContext anyCtx = TlsContextFactory.create(tcfg.tls()); // RMI client TLS identity: one per process
            ControlClient admin = control(ccfg, "admin", anyCtx);
            ControlClient admin2 = admin; // a second console of the same administrator
            ControlClient operator = control(ccfg, "operator", anyCtx);
            ControlClient viewer = control(ccfg, "viewer", anyCtx);
            Path trust = tcfg.tls().trustStore();
            SecretSource pass = tcfg.tls().password();
            EastGuardClient web = workload("keys/workload-web-01.p12", trust, pass, issuer);
            EastGuardClient api = workload("keys/workload-api-01.p12", trust, pass, issuer);

            check(await(() -> lease(web).status() == ReplyStatus.SUCCESS, 8_000), "token service synced: web-01 gets a lease");

            // 1. Audited policy edit.
            title("1. Audited policy edit: allow api-01 -> app-02");
            Dto.PolicyView before = admin.getPolicy("app-02");
            say("policy revision " + before.policyRevision() + ", mode " + before.mode() + ", edges " + before.edges());
            check(lease(api).status() == ReplyStatus.DENY, "api-01 is refused a lease before the edit (default deny)");
            List<Edge> edited = new ArrayList<>(before.edges());
            edited.add(new Edge("api-01", "app-02"));
            Dto.MutationResult edit = admin.replacePolicy("m5-edit-1", before.policyRevision(), edited,
                    "CHG-1042 api-01 reads app-02");
            check(edit.ok(), "committed at enforcement revision " + edit.revision() + " (journaled and forced first)");
            Dto.AuditEntry top = viewer.getDashboard(0, 1).audit().get(0);
            say("audit: rev=" + top.revision() + " " + Instant.ofEpochMilli(top.atMillis()) + " actor=" + top.actor()
                    + " role=" + top.role() + " op=" + top.operation() + " requestId=" + top.requestId()
                    + " " + top.detail() + " reason=\"" + top.reason() + "\" outcome=" + top.outcome());
            check(await(() -> lease(api).status() == ReplyStatus.SUCCESS, 5_000),
                    "after the next sync, api-01 gets a lease");

            // 2. Version conflict.
            title("2. A second console edits from the stale policy revision " + before.policyRevision());
            Dto.MutationResult stale = admin2.replacePolicy("m5-edit-2", before.policyRevision(), before.edges(),
                    "remove api-01 again");
            check(stale.error() == Dto.ErrorCode.CONFLICT, "CONFLICT: " + stale.message());
            check(admin.getPolicy("app-02").edges().size() == 2, "the newer policy was not overwritten");

            // 3. Idempotent retry.
            title("3. The reply to m5-edit-1 was 'lost': the console retries");
            long auditBefore = viewer.getDashboard(0, 200).audit().size();
            Dto.MutationResult retry = admin.replacePolicy("m5-edit-1", before.policyRevision(), edited,
                    "CHG-1042 api-01 reads app-02");
            check(retry.ok() && retry.replayed() && retry.revision() == edit.revision(),
                    "identical retry returns the original result (revision " + retry.revision() + "), nothing new committed");
            Dto.MutationResult reuse = admin.replacePolicy("m5-edit-1", edit.policyRevision(), before.edges(),
                    "different change, same ID");
            check(reuse.error() == Dto.ErrorCode.INVALID, "same request ID with a different payload: " + reuse.message());
            check(viewer.getDashboard(0, 200).audit().size() == auditBefore, "audit unchanged: no duplicate commit");

            // 4. Quarantine through the sync path.
            title("4. Operator quarantines web-01 while it has a live session");
            Bytes oldLease = lease(web).token();
            GatewaySession webSession = attempt(() -> open(web, gateway, oldLease), 5_000);
            GatewaySession apiSession = open(api, gateway, lease(api).token());
            check(webSession != null && apiSession != null && echo(webSession, "hi") && echo(apiSession, "hi"),
                    "web-01 and api-01 sessions relay through the gateway");
            long t0 = System.nanoTime();
            Dto.MutationResult q = operator.quarantine("m5-q-1", List.of(WEB), Duration.ofMinutes(5), "decoy touch from web-01");
            check(q.ok(), "quarantine committed at revision " + q.revision());
            webSession.setReadTimeout(Duration.ofSeconds(8));
            boolean closed = closed(webSession);
            check(closed, "web-01's live session closed " + (System.nanoTime() - t0) / 1_000_000
                    + " ms after the commit (sync -> new snapshot -> SessionIndex re-evaluation)");
            check(echo(apiSession, "still here"), "api-01's unrelated session is untouched");
            // The token service polls independently of the gateway (1 s +-20 %): allow it one poll to catch up.
            check(attempt(() -> lease(web).status() == ReplyStatus.QUARANTINED ? Boolean.TRUE : null, 3_000) != null,
                    "token service refuses web-01 a new lease: QUARANTINED");
            check(status(web, gateway, oldLease) == ReplyStatus.QUARANTINED, "gateway refuses web-01's old lease: QUARANTINED");

            // 5. Release and the watermark.
            title("5. Operator releases web-01");
            Dto.MutationResult r = operator.release("m5-r-1", List.of(WEB), "host reimaged, credentials rotated");
            check(r.ok(), "release committed at revision " + r.revision() + ": watermark minTokenRevision=" + r.revision());
            long superseded = sink.count(ReasonCode.LEASE_SUPERSEDED);
            check(await(() -> status(web, gateway, oldLease) == ReplyStatus.DENY, 5_000)
                    && sink.count(ReasonCode.LEASE_SUPERSEDED) > superseded,
                    "the old lease (issued at an earlier revision) is denied: LEASE_SUPERSEDED");
            // The gateway has the release; the token service may need one more poll before it issues again.
            IssuerReply fresh = attempt(() -> {
                IssuerReply x = lease(web);
                return x.status() == ReplyStatus.SUCCESS ? x : null;
            }, 3_000);
            GatewaySession again = fresh != null ? open(web, gateway, fresh.token()) : null;
            check(again != null && echo(again, "back"), "a newly issued lease is admitted and relays");

            // 6. Typed ztp:// policy read.
            title("6. Typed policy read: URL.of(URI.create(\"ztp://policy/app-02\"), handler)");
            ZtpUrlHandler ztp = new ZtpUrlHandler(viewer::getPolicy); // the configured client; the URL picks no endpoint
            Object content = URL.of(URI.create("ztp://policy/app-02"), ztp).getContent();
            PolicyView pv = content instanceof PolicyView p ? p : null;
            check(pv != null, "getContent() returned a typed " + PolicyView.class.getSimpleName() + ": " + pv);
            check(pv != null && pv.allowedSources().equals(List.of("api-01", "web-01")) && pv.mode() == PolicyMode.ENFORCE,
                    "app-02 allows " + (pv == null ? "?" : pv.allowedSources()) + " in ENFORCE mode");
            for (String bad : new String[] {"ztp://10.0.0.9/app-02", "ztp://policy:1099/app-02",
                    "ztp://policy/app-02?host=10.0.0.9", "ztp://policy/../keys"}) {
                check(rejected(bad, ztp), bad + " rejected: only the fixed authority and one service ID");
            }

            // 7. HTTPS audit export.
            title("7. HTTPS audit export on https://127.0.0.1:" + audit.port() + " (client certificate required)");
            AuditClient console = new AuditClient(TlsContextFactory.create(new TlsContextFactory.Material(
                    Path.of("keys/console.p12"), trust, pass)), TIMEOUT);
            AuditClient.Response page = console.get(URI.create("https://127.0.0.1:" + audit.port() + "/audit?limit=3"));
            check(page.status() == 200, "console certificate: GET /audit?limit=3 -> " + page.status() + " "
                    + page.contentType() + " (HttpsURLConnection, normal hostname verification against the IP SAN)");
            say(page.body().length() > 400 ? page.body().substring(0, 400) + "..." : page.body());
            java.util.regex.Matcher next = java.util.regex.Pattern.compile("\"nextCursor\":(\\d+)").matcher(page.body());
            if (next.find()) {
                AuditClient.Response older = console.get(URI.create("https://127.0.0.1:" + audit.port()
                        + "/audit?limit=3&cursor=" + next.group(1)));
                check(older.status() == 200, "next page with cursor=" + next.group(1) + " -> " + older.status());
            }
            check(console.get(URI.create("https://127.0.0.1:" + audit.port() + "/health/ready")).status() == 200,
                    "/health/ready -> 200 (journal open, bootstrapped)");
            AuditClient wrongCert = new AuditClient(TlsContextFactory.create(new TlsContextFactory.Material(
                    Path.of("keys/workload-web-01.p12"), trust, pass)), TIMEOUT);
            int forbidden = wrongCert.get(URI.create("https://127.0.0.1:" + audit.port() + "/audit")).status();
            check(forbidden == 403, "a trusted but unauthorized certificate (workload web-01) -> " + forbidden);

            // 8. Fail closed.
            title("8. The control plane goes away");
            server.close();
            long t1 = System.nanoTime();
            again.setReadTimeout(Duration.ofSeconds(15));
            apiSession.setReadTimeout(Duration.ofSeconds(15));
            boolean bothClosed = closed(again) & closed(apiSession);
            check(bothClosed, "live sessions closed " + (System.nanoTime() - t1) / 1_000_000
                    + " ms later, when the 5 s freshness from the last successful sync ran out");
            // The token service's last sync may have started up to one poll after the gateway's, so its 5 s
            // freshness can run out a little later.
            check(attempt(() -> lease(web).status() == ReplyStatus.UNAVAILABLE
                    && lease(api).status() == ReplyStatus.UNAVAILABLE ? Boolean.TRUE : null, 3_000) != null,
                    "issuance stops: UNAVAILABLE");
            check(status(api, gateway, Bytes.copyOf(new byte[] {'x'})) == ReplyStatus.UNAVAILABLE,
                    "admissions stop: UNAVAILABLE");

            title("Gateway decisions by reason: " + sink + "; the backend accepted " + echo.accepted()
                    + " connections, all after ALLOW");
        } finally {
            audit.close();
            server.close();
            journal.close();
        }
        try (Journal j = Journal.open(journalFile)) {
            title("Journal after restart: " + j.replayed().size() + " records, replays to revision "
                    + ControlPlaneImpl.open(j, clock, Credentials.of(List.of()), ccfg.settings()).snapshot().revision());
        }
        System.out.println();
        System.out.println(failures == 0 ? "DemoM5_Rmi: all checks passed" : "DemoM5_Rmi: " + failures + " check(s) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    private static ControlClient control(ControlConfig ccfg, String principal, SSLContext ctx) {
        SecretSource secret = new SecretSource("EASTGUARD_API_SECRET_" + principal.toUpperCase().replace('-', '_'),
                Path.of("keys", "api", principal + ".secret"));
        return new ControlClient(new ControlClient.Settings(new Endpoint(IpAddress.parse(ccfg.rmiHost()),
                ccfg.registryPort()), ccfg.objectPort(), principal, secret), ctx);
    }

    private static EastGuardClient workload(String store, Path trust, SecretSource pass, Endpoint issuer) {
        SSLContext ctx = TlsContextFactory.create(new TlsContextFactory.Material(Path.of(store), trust, pass));
        return new EastGuardClient(ctx, issuer, "127.0.0.1", TIMEOUT);
    }

    private static IssuerReply lease(EastGuardClient c) {
        try {
            return c.requestLease("app-02");
        } catch (IOException e) {
            return IssuerReply.failure(ReplyStatus.UNAVAILABLE);
        }
    }

    private static GatewaySession open(EastGuardClient c, Endpoint gateway, Bytes token) {
        try {
            GatewaySession s = c.connect(gateway, "127.0.0.1", token);
            return s.allowed() ? s : null;
        } catch (IOException e) {
            return null;
        }
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

    private static boolean rejected(String uri, ZtpUrlHandler h) {
        try {
            URL.of(URI.create(uri), h).getContent();
            return false;
        } catch (IOException e) { // MalformedURLException from URL.of
            return true;
        }
    }

    private static boolean closed(GatewaySession s) {
        try {
            return s.input().read() == -1;
        } catch (IOException e) {
            return !(e instanceof java.net.SocketTimeoutException);
        }
    }

    private static boolean await(Supplier<Boolean> condition, long millis) throws InterruptedException {
        long end = System.nanoTime() + millis * 1_000_000;
        while (!condition.get()) {
            if (System.nanoTime() > end) {
                return false;
            }
            Thread.sleep(100);
        }
        return true;
    }

    private static <T> T attempt(Supplier<T> attempt, long millis) throws InterruptedException {
        long end = System.nanoTime() + millis * 1_000_000;
        T v;
        while ((v = attempt.get()) == null && System.nanoTime() < end) {
            Thread.sleep(100);
        }
        return v;
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
