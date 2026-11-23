package eastguard.demos;

import eastguard.client.EastGuardClient;
import eastguard.client.GatewaySession;
import eastguard.common.Bytes;
import eastguard.common.CodecException;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.IpAddress;
import eastguard.common.IssuerReply;
import eastguard.common.Lease;
import eastguard.common.LeaseCodec;
import eastguard.common.PolicyMode;
import eastguard.common.ReplyStatus;
import eastguard.common.SecretSource;
import eastguard.common.Selector;
import eastguard.control.ControlClient;
import eastguard.control.ControlConfig;
import eastguard.control.Dto;
import eastguard.control.EdgeDiff;
import eastguard.control.RmiSupport;
import eastguard.gateway.GatewayConfig;
import eastguard.tokensvc.TlsContextFactory;
import eastguard.tokensvc.TokenConfig;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;

/**
 * The spec §11 final demo, as a scripted client of the separate processes that {@code scripts\run-demo.ps1}
 * starts (control plane, threat detector, token service, two echo backends, gateways {@code app-02} and
 * {@code app-03}). It starts nothing itself and touches only owned local services and fixtures:
 *
 * <ol>
 *   <li>approved flow {@code web-01 -> app-02} (and {@code -> app-03}) is admitted and relays;</li>
 *   <li>unapproved flow {@code api-01 -> app-02} is denied by the token service and by the gateway;</li>
 *   <li>a learning pilot admits {@code api-01 -> app-02}, the detector reports it as a candidate, the reviewed
 *       draft diff is shown and frozen, and the edge is then allowed in ENFORCE (unscoped edges stay denied);</li>
 *   <li>the labelled decoy fixture (one TCP connect to the owned decoy listener) gives a CRITICAL alert, the
 *       detector proposes, the control plane commits a quarantine, and the multicast notice closes live
 *       sessions at <em>both</em> gateways;</li>
 *   <li>release: the old lease is rejected by the release watermark, a freshly issued lease reconnects.</li>
 * </ol>
 *
 * With {@code --measure N} it then repeats an operator quarantine/release N times across the two gateway
 * processes to measure commit to session closure, and times client connects (TLS + admission).
 *
 * <pre>
 * .\scripts\run-demo.ps1                          # in one terminal; wait for "demo is ready"
 * java -cp out eastguard.demos.DemoFinal          # in another
 * java -cp out eastguard.demos.DemoFinal --measure 20
 * </pre>
 *
 * Needs a fresh demo state ({@code .\scripts\run-demo.ps1 -Reset}). Exit code 0 when every check holds, 1 when a
 * check failed, 2 when the demo processes are not reachable or the state is not fresh.
 */
public final class DemoFinal {
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    /** How long a live session is watched for closure. */
    private static final Duration WATCH = Duration.ofSeconds(15);
    /** One state poll (state.pollMillis 1 s + 20 % jitter) plus the RMI round trip. */
    private static final long POLL_WAIT_MILLIS = 1_400;
    private static final String HOST = "127.0.0.1";
    private static final Edge PILOT_EDGE = new Edge("api-01", "app-02");
    private static final Set<Edge> BOOTSTRAP_EDGES = Set.of(new Edge("web-01", "app-02"), new Edge("web-01", "app-03"));
    /** Strong reference: java.util.logging only holds loggers weakly. */
    private static final Logger QUIET = Logger.getLogger("eastguard");
    private static int failures;
    private static Path logs = Path.of("logs");

    private DemoFinal() {
    }

    public static void main(String[] args) throws Exception {
        int measure = 0;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--measure") && i + 1 < args.length) {
                measure = Integer.parseInt(args[++i]);
            } else if (args[i].equals("--logs") && i + 1 < args.length) {
                logs = Path.of(args[++i]);
            } else {
                System.err.println("usage: java -cp out eastguard.demos.DemoFinal [--measure <rounds>] [--logs <dir>]");
                System.exit(2);
            }
        }
        QUIET.setLevel(Level.WARNING); // this process is a client; the servers' logs are in logs\
        ControlConfig ccfg = ControlConfig.load(Path.of("config/demo-control.properties.example"));
        TokenConfig tcfg = TokenConfig.load(Path.of("config/token.properties.example"));
        GatewayConfig g2 = GatewayConfig.load(Path.of("config/gateway-app-02.properties.example"));
        GatewayConfig g3 = GatewayConfig.load(Path.of("config/gateway-app-03.properties.example"));
        Endpoint issuer = tcfg.listen();
        Endpoint gw2 = g2.listen();
        Endpoint gw3 = g3.listen();
        Endpoint decoy = g2.decoyListen();
        Path trust = tcfg.tls().trustStore();
        SecretSource pass = tcfg.tls().password();

        RmiSupport.configureJvm(null);
        // One RMI client TLS identity per process (DEVIATIONS 6.6): the operator console's certificate. Each call
        // still carries its own principal's API credential and is authorized by role.
        SSLContext consoleTls = TlsContextFactory.create(new TlsContextFactory.Material(Path.of("keys/console.p12"),
                trust, pass));
        ControlClient admin = control(ccfg, "admin", consoleTls);
        ControlClient operator = control(ccfg, "operator", consoleTls);
        ControlClient viewer = control(ccfg, "viewer", consoleTls);
        EastGuardClient web = workload("keys/workload-web-01.p12", trust, pass, issuer);
        EastGuardClient api = workload("keys/workload-api-01.p12", trust, pass, issuer);

        System.out.println("EastGuard final demo (spec section 11) against the processes started by scripts\\run-demo.ps1");
        System.out.println("  control plane rmi " + ccfg.rmiHost() + ":" + ccfg.registryPort() + "  token service " + issuer
                + "  gateway app-02 " + gw2 + " (decoy " + decoy + ")  gateway app-03 " + gw3);
        preflight(viewer, admin);

        // 1. Approved flow.
        title("1. Approved flow: web-01 -> app-02 (and web-01 -> app-03 through the second gateway)");
        IssuerReply webLease = lease(web, "app-02");
        check(webLease.status() == ReplyStatus.SUCCESS, "token service issued web-01 a lease for app-02 over mTLS");
        say(describe(webLease.token()));
        GatewaySession s1 = open(web, gw2, webLease.token());
        check(s1 != null && echo(s1, "hello app-02"), "gateway app-02 verified the lease, connected the backend, sent ALLOW;"
                + " bytes relay to the private echo backend");
        GatewaySession s1b = connectFresh(web, "app-03", gw3);
        check(s1b != null && echo(s1b, "hello app-03"), "the same workload reaches app-03 through gateway app-03");
        closeQuietly(s1);
        closeQuietly(s1b);

        // 2. Unapproved flow.
        title("2. Unapproved flow: api-01 -> app-02 (no approved edge; default deny)");
        LogTail tokLog = new LogTail("tokensvc");
        LogTail gw2Log = new LogTail("gateway-app-02");
        IssuerReply apiDenied = lease(api, "app-02");
        check(apiDenied.status() == ReplyStatus.DENY && apiDenied.token().length() == 0,
                "token service refuses api-01 a lease for app-02: " + apiDenied.status() + ", no token");
        evidence(tokLog, "lease denied sub=api-01 aud=app-02 .*reason=\\w+");
        ReplyStatus replay = status(api, gw2, webLease.token());
        check(replay == ReplyStatus.DENY, "api-01 replaying web-01's lease at gateway app-02: " + replay
                + " before any byte reaches the backend");
        evidence(gw2Log, "gateway app-02 deny sub=api-01 .*reason=\\w+");

        // 3. Learning pilot, review, freeze.
        title("3. Learning pilot: observe api-01 -> app-02, review the draft diff, freeze, then ENFORCE");
        Dto.PolicyView before = admin.getPolicy(null);
        Dto.MutationResult learn = admin.setMode("final-learn-" + System.currentTimeMillis(), before.policyRevision(),
                PolicyMode.LEARN, List.of("api-01"), List.of("app-02"), "pilot: discover api-01 dependencies on app-02");
        check(learn.ok(), "admin switched to LEARN with pilot scope sources=[api-01] services=[app-02] (revision "
                + learn.revision() + ")");
        // Mode and policy edits reach the token service and gateways by polling (1 s +-20 %), not by multicast.
        // Wait one poll instead of retrying fast: every refused request is an authenticated POLICY_DENY (+30)
        // for api-01, and a retry storm would correctly drive it to CRITICAL and an automatic quarantine.
        say("waiting one state poll (policy edits are polled, not multicast) before using the pilot edge");
        IssuerReply pilotLease = afterPoll(() -> {
            IssuerReply r = lease(api, "app-02");
            return r.status() == ReplyStatus.SUCCESS ? r : null;
        });
        GatewaySession pilot = pilotLease == null ? null : open(api, gw2, pilotLease.token());
        check(pilot != null && echo(pilot, "pilot traffic"),
                "the pilot edge api-01 -> app-02 is admitted in LEARN mode (gateway reports it as a candidate)");
        closeQuietly(pilot);
        IssuerReply unscoped = lease(api, "app-03");
        check(unscoped.status() == ReplyStatus.DENY, "unscoped edge api-01 -> app-03 stays denied: " + unscoped.status());

        Dto.LearningDraftView draft = attempt(() -> {
            Dto.LearningDraftView d = call(admin::getLearningDraft);
            return d != null && d.ok() && d.candidates().stream().anyMatch(o -> o.edge().equals(PILOT_EDGE)) ? d : null;
        }, 15_000);
        check(draft != null, "the detector forwarded the observation; the learning draft holds the candidate");
        if (draft == null) {
            finish();
        }
        say("draft version " + draft.draftVersion() + ", mode " + draft.mode() + ", approved " + draft.approved());
        for (Dto.Observation o : draft.candidates()) {
            say("candidate " + o.edge() + "  count=" + o.count() + "  first=" + Instant.ofEpochMilli(o.firstSeenMillis())
                    + "  last=" + Instant.ofEpochMilli(o.lastSeenMillis()));
        }
        say("note: " + Dto.LearningDraftView.INCOMPLETE);
        List<Edge> reviewed = new ArrayList<>(draft.approved());
        reviewed.add(PILOT_EDGE); // the reviewer accepts exactly this candidate; anything else stays unreviewed
        EdgeDiff diff = EdgeDiff.of(draft.approved(), reviewed);
        say("reviewed diff (exactly what the freeze commits): " + diff + "  additions=" + diff.additions()
                + " removals=" + diff.removals());
        Dto.MutationResult freeze = admin.freezeBaseline("final-freeze-" + System.currentTimeMillis(),
                draft.policyRevision(), draft.draftVersion(), reviewed, "reviewed pilot: api-01 reads app-02");
        check(freeze.ok(), "freeze committed at revision " + freeze.revision() + ": reviewed set applied, mode ENFORCE");
        Dto.PolicyView after = admin.getPolicy(null);
        check(after.mode() == PolicyMode.ENFORCE && after.edges().contains(PILOT_EDGE)
                && after.edges().size() == BOOTSTRAP_EDGES.size() + 1,
                "policy is ENFORCE with edges " + after.edges());
        IssuerReply enforced = afterPoll(() -> {
            IssuerReply r = lease(api, "app-02");
            return r.status() == ReplyStatus.SUCCESS ? r : null;
        });
        GatewaySession apiNow = enforced == null ? null : open(api, gw2, enforced.token());
        check(apiNow != null && echo(apiNow, "approved now"), "api-01 -> app-02 is allowed in ENFORCE");
        closeQuietly(apiNow);
        // Checked on the policy, not with another denied request: each authenticated policy denial scores +30 for
        // api-01 within the detector's 10 s window, and the demo must not push the workload to CRITICAL itself.
        check(!after.edges().contains(new Edge("api-01", "app-03")),
                "api-01 -> app-03 was never reviewed and stays outside the allow-list (denied by default)");

        // 4. Labelled decoy fixture -> critical alert -> committed quarantine at both gateways.
        title("4. Labelled detector fixture: decoy hit -> CRITICAL alert -> committed quarantine at both gateways");
        IssuerReply oldLease = lease(web, "app-02");
        GatewaySession live2 = open(web, gw2, oldLease.token());
        GatewaySession live3 = connectFresh(web, "app-03", gw3);
        GatewaySession liveApi = enforced == null ? null : open(api, gw2, lease(api, "app-02").token());
        check(live2 != null && live3 != null && liveApi != null && echo(live2, "a") && echo(live3, "b") && echo(liveApi, "c"),
                "live sessions: web-01@app-02, web-01@app-03, api-01@app-02");
        int alertsBefore = viewer.getDashboard(0, 1).alerts().size();
        LogTail detLog = new LogTail("detector");
        LogTail gw2Close = new LogTail("gateway-app-02");
        LogTail gw3Close = new LogTail("gateway-app-03");
        say("FIXTURE decoy-hit (labelled, owned): one TCP connection from 127.0.0.1 to decoy listener decoy-9003 at " + decoy);
        say("expected: DECOY +100 -> CRITICAL -> detector proposes QUARANTINE ip:127.0.0.1 -> control plane rechecks its"
                + " automation rules, journals, multicasts -> both gateways close matching sessions");
        Map<String, CompletableFuture<Long>> closures = new LinkedHashMap<>();
        closures.put("web-01@app-02", watchClose(live2));
        closures.put("web-01@app-03", watchClose(live3));
        closures.put("api-01@app-02", watchClose(liveApi));
        long t0 = System.nanoTime();
        touchDecoy(decoy);
        boolean allClosed = true;
        for (var e : closures.entrySet()) {
            long at = closedAt(e.getValue());
            boolean ok = at > 0;
            allClosed &= ok;
            check(ok, e.getKey() + (ok ? " closed " + ms(at - t0) + " ms after the decoy hit" : " was NOT closed"));
        }
        if (!allClosed) {
            String why = detLog.find(Pattern.compile("suppressed: [^\\r\\n]*"), 0);
            say("the detector " + (why != null ? "reported '" + why + "'" : "did not commit an action") + ". Proposals are"
                    + " suppressed for telemetry.acceptanceMillis after the detector starts and for"
                    + " detector.cooldownMillis after a proposal; see logs\\detector.log");
        }
        evidence(detLog, "CRITICAL alert .*signals=\\[DECOY\\].*");
        evidence(gw2Close, "gateway app-02 closing RELAY session .*reason=QUARANTINED");
        evidence(gw3Close, "gateway app-03 closing RELAY session .*reason=QUARANTINED");
        Dto.DashboardView dash = viewer.getDashboard(0, 5);
        Dto.AlertView alert = dash.alerts().size() > alertsBefore ? dash.alerts().get(dash.alerts().size() - 1) : null;
        check(alert != null && alert.committed() && alert.signals().contains("DECOY"),
                "control plane recorded the committed detector action"
                        + (alert == null ? "" : ": " + alert.action() + " " + alert.selectors() + " score=" + alert.score()
                        + " signals=" + alert.signals() + " evidence=" + alert.evidence() + " revision=" + alert.revision()
                        + " expires=" + Instant.ofEpochMilli(alert.expiresAtMillis())));
        Selector quarantined = alert != null && !alert.selectors().isEmpty() ? alert.selectors().get(0)
                : Selector.ip(IpAddress.parse(HOST));
        check(dash.restrictions().stream().anyMatch(r -> r.selector().equals(quarantined)),
                "active restriction: " + quarantined + " (journaled, audited as actor " + (alert == null ? "?" : alert.actor()) + ")");
        check(afterPoll(() -> lease(web, "app-02").status() == ReplyStatus.QUARANTINED ? Boolean.TRUE : null) != null,
                "token service refuses new leases: QUARANTINED");
        check(status(web, gw2, oldLease.token()) == ReplyStatus.QUARANTINED,
                "gateway app-02 refuses the still-valid old lease: QUARANTINED");

        // 5. Release, watermark, fresh lease.
        title("5. Release -> the old lease is rejected by the watermark -> a fresh lease reconnects");
        LogTail gw2Deny = new LogTail("gateway-app-02");
        Dto.MutationResult rel = operator.release("final-release-" + System.currentTimeMillis(), List.of(quarantined),
                "decoy fixture reviewed: owned demo traffic");
        check(rel.ok(), "operator released " + quarantined + " at revision " + rel.revision()
                + "; watermark minTokenRevision=" + rel.revision() + " for that selector");
        Lease old = claims(oldLease.token());
        say("old lease: issued at revision " + (old == null ? "?" : old.issuedAtRevision()) + " < watermark " + rel.revision()
                + ", still inside its lifetime (expires " + (old == null ? "?" : Instant.ofEpochMilli(old.expiresAtMs())) + ")");
        check(afterPoll(() -> status(web, gw2, oldLease.token()) == ReplyStatus.DENY ? Boolean.TRUE : null) != null,
                "gateway app-02 rejects the old lease after the release: DENY");
        evidence(gw2Deny, "gateway app-02 deny sub=web-01 .*reason=LEASE_SUPERSEDED");
        IssuerReply fresh = attempt(() -> {
            IssuerReply r = lease(web, "app-02");
            return r.status() == ReplyStatus.SUCCESS ? r : null;
        }, 5_000);
        Lease freshClaims = fresh == null ? null : claims(fresh.token());
        GatewaySession back = fresh == null ? null : open(web, gw2, fresh.token());
        check(back != null && echo(back, "back again"), "a freshly issued lease (revision "
                + (freshClaims == null ? "?" : freshClaims.issuedAtRevision()) + ") reconnects to app-02 and relays");
        GatewaySession back3 = connectFresh(web, "app-03", gw3);
        check(back3 != null && echo(back3, "back again"), "and to app-03 through the second gateway");
        closeQuietly(back);
        closeQuietly(back3);

        if (measure > 0) {
            measure(measure, operator, viewer, web, api, gw2, gw3);
        }
        finish();
    }

    // ---- measurements (--measure N) ----

    private static void measure(int rounds, ControlClient operator, ControlClient viewer, EastGuardClient web,
            EastGuardClient api, Endpoint gw2, Endpoint gw3) throws Exception {
        title("M. Measurements across the separate processes (" + rounds + " rounds)");
        // Client-observed connect: TCP + TLS 1.3 handshake + preamble + gateway admission + ALLOW, one lease reused.
        IssuerReply l = lease(web, "app-02");
        List<Long> connect = new ArrayList<>();
        for (int i = 0; i < 220; i++) {
            long t = System.nanoTime();
            ReplyStatus s = status(web, gw2, l.token());
            if (i >= 20 && s == ReplyStatus.SUCCESS) { // first 20 are warm-up
                connect.add(System.nanoTime() - t);
            }
        }
        say("client connect incl. TLS handshake, sequential, warmed (n=" + connect.size() + "): " + stats(connect));

        // Operator quarantine of identity web-01: commit -> multicast -> closure at both gateway processes, while an
        // unrelated api-01 session stays up.
        GatewaySession bystander = open(api, gw2, lease(api, "app-02").token());
        int alertsBefore = viewer.getDashboard(0, 1).alerts().size();
        List<Long> commitToClose = new ArrayList<>();
        List<Long> callToClose = new ArrayList<>();
        Selector webSel = Selector.identity("web-01");
        for (int i = 0; i < rounds; i++) {
            GatewaySession a = connectFresh(web, "app-02", gw2);
            GatewaySession b = connectFresh(web, "app-03", gw3);
            if (a == null || b == null) {
                check(false, "round " + i + ": web-01 could not reconnect");
                return;
            }
            CompletableFuture<Long> ca = watchClose(a);
            CompletableFuture<Long> cb = watchClose(b);
            long t0 = System.nanoTime();
            Dto.MutationResult q = operator.quarantine("final-m-q-" + System.nanoTime(), List.of(webSel),
                    Duration.ofMinutes(1), "containment measurement round " + i);
            long acked = System.nanoTime();
            long xa = closedAt(ca);
            long xb = closedAt(cb);
            if (!q.ok() || xa < 0 || xb < 0) {
                check(false, "round " + i + ": quarantine " + q.error() + ", closed " + (xa > 0) + "/" + (xb > 0));
                return;
            }
            for (long x : new long[] {xa, xb}) {
                callToClose.add(x - t0);
                commitToClose.add(Math.max(0, x - acked));
            }
            operator.release("final-m-r-" + System.nanoTime(), List.of(webSel), "measurement round " + i);
            Thread.sleep(300); // let the release notice and sync land before the next lease request
        }
        say("operator quarantine call start -> session EOF (includes RMI call + journal force + multicast), n="
                + callToClose.size() + ": " + stats(callToClose));
        say("commit acknowledged -> session EOF (0 when the session closed before the RMI reply arrived), n="
                + commitToClose.size() + ": " + stats(commitToClose));
        check(bystander != null && echo(bystander, "still here"),
                "the unrelated api-01 session survived all " + rounds + " targeted web-01 quarantines");
        closeQuietly(bystander);
        check(viewer.getDashboard(0, 1).alerts().size() == alertsBefore,
                "no automatic action was triggered by the measurement traffic");
    }

    private static String stats(List<Long> nanos) {
        long[] v = nanos.stream().mapToLong(Long::longValue).sorted().toArray();
        if (v.length == 0) {
            return "no samples";
        }
        return String.format("p50 %.2f ms, p95 %.2f ms, p99 %.2f ms, max %.2f ms", pct(v, 50), pct(v, 95), pct(v, 99),
                v[v.length - 1] / 1e6);
    }

    private static double pct(long[] sorted, int p) {
        int i = (int) Math.ceil(p / 100.0 * sorted.length) - 1;
        return sorted[Math.max(0, Math.min(sorted.length - 1, i))] / 1e6;
    }

    // ---- preflight ----

    private static void preflight(ControlClient viewer, ControlClient admin) {
        Dto.DashboardView d;
        Dto.PolicyView p;
        try {
            d = viewer.getDashboard(0, 1);
            p = admin.getPolicy(null);
        } catch (IOException e) {
            System.err.println("control plane not reachable (" + e.getClass().getSimpleName() + "): start the demo first"
                    + " with .\\scripts\\run-demo.ps1 and wait for 'demo is ready'");
            System.exit(2);
            return;
        }
        if (!d.ok() || !p.ok()) {
            System.err.println("control plane refused the demo principals: " + d.error() + " " + p.error()
                    + " (run .\\scripts\\gen-credentials.ps1)");
            System.exit(2);
        }
        say("control plane revision " + d.revision() + ", mode " + p.mode() + ", approved " + p.edges()
                + ", active restrictions " + d.restrictions().size());
        if (p.mode() != PolicyMode.ENFORCE || !Set.copyOf(p.edges()).equals(BOOTSTRAP_EDGES) || !d.restrictions().isEmpty()) {
            System.err.println("the demo state is not fresh (a previous run froze or restricted something)."
                    + " Stop run-demo (Ctrl+C) and start it again with: .\\scripts\\run-demo.ps1 -Reset");
            System.exit(2);
        }
    }

    // ---- clients ----

    private static ControlClient control(ControlConfig ccfg, String principal, SSLContext ctx) {
        SecretSource secret = new SecretSource("EASTGUARD_API_SECRET_" + principal.toUpperCase().replace('-', '_'),
                Path.of("keys", "api", principal + ".secret"));
        return new ControlClient(new ControlClient.Settings(new Endpoint(IpAddress.parse(ccfg.rmiHost()),
                ccfg.registryPort()), ccfg.objectPort(), principal, secret), ctx);
    }

    private static EastGuardClient workload(String store, Path trust, SecretSource pass, Endpoint issuer) {
        SSLContext ctx = TlsContextFactory.create(new TlsContextFactory.Material(Path.of(store), trust, pass));
        return new EastGuardClient(ctx, issuer, HOST, TIMEOUT);
    }

    private static IssuerReply lease(EastGuardClient c, String service) {
        try {
            return c.requestLease(service);
        } catch (IOException e) {
            return IssuerReply.failure(ReplyStatus.UNAVAILABLE);
        }
    }

    /** A new lease for {@code service} and a session on it, retried briefly while the token service catches up. */
    private static GatewaySession connectFresh(EastGuardClient c, String service, Endpoint gateway)
            throws InterruptedException {
        return attempt(() -> {
            IssuerReply r = lease(c, service);
            return r.status() == ReplyStatus.SUCCESS ? open(c, gateway, r.token()) : null;
        }, 5_000);
    }

    /**
     * Presents a lease and returns the admitted session, or null. UNAVAILABLE is retried for up to 5 s: right after
     * a policy commit the token service may already issue at the new revision while the gateway, which polls
     * independently, still has the previous one and fails closed with NOT_READY until its next sync.
     */
    private static GatewaySession open(EastGuardClient c, Endpoint gateway, Bytes token) {
        if (token == null || token.length() == 0) {
            return null;
        }
        long end = System.nanoTime() + TIMEOUT.toNanos();
        while (true) {
            try {
                GatewaySession s = c.connect(gateway, HOST, token);
                if (s.allowed() || s.status() != ReplyStatus.UNAVAILABLE) {
                    return s.allowed() ? s : null;
                }
            } catch (IOException e) {
                // retried below
            }
            if (System.nanoTime() > end) {
                return null;
            }
            try {
                Thread.sleep(150);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
    }

    private static ReplyStatus status(EastGuardClient c, Endpoint gateway, Bytes token) {
        if (token == null || token.length() == 0) {
            return null;
        }
        try (GatewaySession s = c.connect(gateway, HOST, token)) {
            return s.status();
        } catch (IOException e) {
            return null;
        }
    }

    private static boolean echo(GatewaySession s, String text) {
        if (s == null) {
            return false;
        }
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

    /** The closure time of a watched session, or -1 if it was not closed (or the watch failed). */
    private static long closedAt(CompletableFuture<Long> f) throws InterruptedException {
        try {
            return f.get(WATCH.toMillis() + 2_000, TimeUnit.MILLISECONDS);
        } catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException e) {
            return -1;
        }
    }

    /** Completes with the {@link System#nanoTime()} at which the session ended, or -1 if it did not in time. */
    private static CompletableFuture<Long> watchClose(GatewaySession s) {
        CompletableFuture<Long> f = new CompletableFuture<>();
        if (s == null) {
            f.complete(-1L);
            return f;
        }
        Thread.ofVirtual().start(() -> {
            try {
                s.setReadTimeout(WATCH);
                int r = s.input().read();
                f.complete(r == -1 ? System.nanoTime() : -1L);
            } catch (SocketTimeoutException e) {
                f.complete(-1L);
            } catch (IOException e) { // reset or TLS failure: the gateway cut the connection
                f.complete(System.nanoTime());
            }
        });
        return f;
    }

    /** The decoy listener accepts and closes; nothing is sent. */
    private static void touchDecoy(Endpoint decoy) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(decoy.ip().toInetAddress(), decoy.port()), 2_000);
            s.setSoTimeout(2_000);
            InputStream in = s.getInputStream();
            in.read();
        } catch (IOException e) {
            // closed by the decoy: expected
        }
    }

    private static Lease claims(Bytes token) {
        try {
            return LeaseCodec.parse(token.toArray()).lease();
        } catch (CodecException | RuntimeException e) {
            return null;
        }
    }

    /** Lease claims for the audience, never the token itself. */
    private static String describe(Bytes token) {
        Lease l = claims(token);
        if (l == null) {
            return "lease: (not decodable)";
        }
        return "lease claims: sub=" + l.subject() + " aud=" + l.audience() + " ip=" + l.sourceIp() + " keyId=" + l.keyId()
                + " ttl=" + (l.expiresAtMs() - l.issuedAtMs()) / 1000 + "s issuedAtRevision=" + l.issuedAtRevision()
                + " (Ed25519-signed, bound to the client certificate's SHA-256)";
    }

    private static <T> T call(IoSupplier<T> body) {
        try {
            return body.get();
        } catch (IOException e) {
            return null;
        }
    }

    private interface IoSupplier<T> {
        T get() throws IOException;
    }

    // ---- server log evidence (logs\<component>.log, written by run-demo.ps1) ----

    /** Remembers the current end of a component log; {@link #find} searches only what was written after it. */
    private static final class LogTail {
        private final Path file;
        private final long mark;

        LogTail(String component) {
            this.file = logs.resolve(component + ".log");
            long m;
            try {
                m = Files.size(file);
            } catch (IOException e) {
                m = -1;
            }
            this.mark = m;
        }

        String find(Pattern p, long waitMillis) throws InterruptedException {
            if (mark < 0) {
                return null;
            }
            long end = System.nanoTime() + waitMillis * 1_000_000;
            do {
                try {
                    byte[] all = Files.readAllBytes(file);
                    if (all.length > mark) {
                        String text = new String(all, (int) mark, all.length - (int) mark, StandardCharsets.ISO_8859_1);
                        Matcher m = p.matcher(text);
                        if (m.find()) {
                            return m.group();
                        }
                    }
                } catch (IOException e) {
                    return null;
                }
                Thread.sleep(100);
            } while (System.nanoTime() < end);
            return null;
        }
    }

    private static void evidence(LogTail log, String regex) throws InterruptedException {
        String line = log.find(Pattern.compile(regex), 3_000);
        if (log.mark < 0) {
            say("(server log " + log.file + " not found: skipped the log cross-check)");
        } else {
            check(line != null, "server log " + log.file.getFileName() + ": " + (line == null ? "no line matching /" + regex + "/" : line.trim()));
        }
    }

    // ---- helpers ----

    private static long ms(long nanos) {
        return Math.round(nanos / 1e6);
    }

    private static void closeQuietly(GatewaySession s) {
        if (s != null) {
            try {
                s.close();
            } catch (IOException ignored) {
                // closing
            }
        }
    }

    private static boolean await(Supplier<Boolean> condition, long millis) throws InterruptedException {
        long end = System.nanoTime() + millis * 1_000_000;
        while (!Boolean.TRUE.equals(condition.get())) {
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
            Thread.sleep(150);
        }
        return v;
    }

    /**
     * For a request that is refused (and scored by the detector) until a polled policy change arrives: wait one
     * poll interval, then try at most three times, one poll apart.
     */
    private static <T> T afterPoll(Supplier<T> attempt) throws InterruptedException {
        for (int i = 0; i < 3; i++) {
            Thread.sleep(POLL_WAIT_MILLIS);
            T v = attempt.get();
            if (v != null) {
                return v;
            }
        }
        return null;
    }

    private static void title(String s) {
        System.out.println();
        System.out.println("== " + s);
    }

    private static void say(String s) {
        System.out.println("     " + s);
    }

    private static void check(boolean ok, String what) {
        if (!ok) {
            failures++;
        }
        System.out.println("  " + (ok ? "[ok]   " : "[FAIL] ") + what);
    }

    private static void finish() {
        System.out.println();
        System.out.println(failures == 0 ? "DemoFinal: all checks passed" : "DemoFinal: " + failures + " check(s) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
