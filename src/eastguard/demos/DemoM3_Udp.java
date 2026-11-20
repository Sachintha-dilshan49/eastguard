package eastguard.demos;

import eastguard.common.Bytes;
import eastguard.common.Cidr;
import eastguard.common.Ed25519;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.EnforcementView;
import eastguard.common.IpAddress;
import eastguard.common.Lease;
import eastguard.common.Peer;
import eastguard.common.PilotScope;
import eastguard.common.Policy;
import eastguard.common.PolicyEvaluator;
import eastguard.common.PolicyMode;
import eastguard.common.ReasonCode;
import eastguard.common.Restriction;
import eastguard.common.Selector;
import eastguard.common.Service;
import eastguard.common.Telemetry;
import eastguard.common.TelemetryCodec;
import eastguard.common.TelemetrySender;
import eastguard.common.Verdict;
import eastguard.common.Workload;
import eastguard.control.ControlPlaneImpl;
import eastguard.control.Credentials;
import eastguard.control.Dto;
import eastguard.control.Journal;
import eastguard.control.Role;
import eastguard.detector.CidrClassifier;
import eastguard.detector.DetectorControl;
import eastguard.detector.ProducerInventory;
import eastguard.detector.ProducerInventory.Kind;
import eastguard.detector.ProducerInventory.Producer;
import eastguard.detector.RiskEngine;
import eastguard.detector.TelemetryVerifier;
import eastguard.detector.TelemetryVerifier.Result;
import eastguard.detector.ThreatDetector;
import eastguard.tokensvc.IssueLimiter;
import eastguard.tokensvc.LeaseIssuer;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * M3 demo (spec §11): authenticated UDP telemetry, CIDR classification, detector scoring and learning
 * observations. A bounded, labelled fixture stream of telemetry datagrams (no scanner, no attack tool) goes over
 * real UDP to a {@link ThreatDetector}, which verifies, deduplicates and scores it and sends proposals and
 * observation batches to a control plane in this JVM (role DETECTOR; the same calls run over secured RMI in
 * production, see {@code RmiTest}). Shown, and checked:
 *
 * <ol>
 *   <li>CIDR classification of the fixture source addresses.</li>
 *   <li>Restart guard: right after start a decoy hit raises a critical alert but no action.</li>
 *   <li>Learning: pilot admissions become candidate edges; an unscoped one is dropped by the control plane.</li>
 *   <li>Risk transitions for web-01: clean 30, 40 (infrastructure failures not scored), alert at 50 with a
 *       committed lease reduction that shortens only <em>newly issued</em> leases to 10 s.</li>
 *   <li>Forged, duplicate, replayed, out-of-scope and oversized datagrams do not change any score.</li>
 *   <li>Critical at 110: quarantine committed.</li>
 *   <li>Decoy hits: a managed IP is quarantined; a shared (NAT) IP and protected infrastructure only alert.</li>
 * </ol>
 *
 * <pre>java -cp out eastguard.demos.DemoM3_Udp</pre>
 *
 * Needs no key files: keys and credentials are generated in memory. The journal lives under {@code out\demo-m3}
 * and is recreated each run. Exit code 0 when every check holds.
 */
public final class DemoM3_Udp {
    private static final String CLUSTER = "eg-demo";
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final long WARMUP_MILLIS = 2_000;
    private static final Endpoint GW = Endpoint.parse("127.0.0.1:9002");
    private static final Endpoint DECOY = Endpoint.parse("127.0.0.1:9003");
    private static final Endpoint OTHER_GW = Endpoint.parse("127.0.0.1:9005");
    private static final Endpoint ISSUER = Endpoint.parse("127.0.0.1:8443");
    private static final IpAddress WEB_IP = IpAddress.parse("10.0.1.10");
    private static final IpAddress API_IP = IpAddress.parse("10.0.1.11");
    private static final IpAddress DB_IP = IpAddress.parse("10.0.1.12");
    private static final IpAddress EARLY_IP = IpAddress.parse("10.0.1.66");
    private static final IpAddress INTRUDER_IP = IpAddress.parse("10.0.1.77");
    private static final IpAddress NAT_IP = IpAddress.parse("10.0.99.7");
    private static final IpAddress INFRA_IP = IpAddress.parse("10.0.0.5");
    private static final IpAddress OUTSIDE_IP = IpAddress.parse("192.168.50.9");
    private static final Selector WEB = Selector.identity("web-01");
    private static final List<Cidr> MANAGED = List.of(Cidr.parse("10.0.0.0/8"));
    private static final List<Cidr> SHARED = List.of(Cidr.parse("10.0.99.0/24"));
    private static final List<Cidr> PROTECTED = List.of(Cidr.parse("10.0.0.0/28"));

    private static int failures;
    private static final SecureRandom RANDOM = new SecureRandom();

    private DemoM3_Udp() {
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("java.util.logging.SimpleFormatter.format", "        [log %4$s] %5$s%6$s%n");
        java.util.logging.Logger.getLogger("eastguard").setLevel(java.util.logging.Level.SEVERE);
        Path dir = Path.of("out", "demo-m3");
        deleteTree(dir);
        Files.createDirectories(dir);

        // ---- control plane (in this JVM), automation enabled for the demo scope ----
        KeyPair leaseKeys = Ed25519.generate();
        Bytes detectorSecret = randomBytes(32);
        Credentials creds = Credentials.of(List.of(Credentials.Principal.withSecret("detector", Role.DETECTOR,
                detectorSecret)));
        ControlPlaneImpl.Automation automation = new ControlPlaneImpl.Automation(true, true, Duration.ofSeconds(10),
                Duration.ofMinutes(5), 20, Set.of(), MANAGED, concat(SHARED, PROTECTED));
        Journal journal = Journal.open(dir.resolve("control.journal"));
        ControlPlaneImpl cp = ControlPlaneImpl.open(journal, Clock.systemUTC(), creds,
                ControlPlaneImpl.Settings.defaults().withAutomation(automation));
        require(cp.bootstrap(initial(leaseKeys), "admin", "demo-m3 fixture state").ok(), "control plane bootstrapped");

        // ---- detector on an ephemeral UDP port, with a short restart guard for the demo ----
        byte[] gwKey = randomBytes(32).toArray();
        byte[] issuerKey = randomBytes(32).toArray();
        ProducerInventory inventory = ProducerInventory.of(List.of(
                new Producer("gw-app-02", Kind.GATEWAY, "tk1", Map.of(GW, "app-02"), Map.of(DECOY, "decoy-9003")),
                new Producer("gw-app-05", Kind.GATEWAY, "tk1", Map.of(OTHER_GW, "app-05"), Map.of()),
                new Producer("tokensvc", Kind.ISSUER, "tk1", Map.of(ISSUER, ProducerInventory.ANY_SERVICE), Map.of())),
                Map.of("gw-app-02", gwKey, "gw-app-05", randomBytes(32).toArray(), "tokensvc", issuerKey));
        CidrClassifier cidrs = new CidrClassifier(MANAGED, SHARED, PROTECTED);
        ThreatDetector.Settings ds = new ThreatDetector.Settings(CLUSTER,
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0),
                new TelemetryVerifier.Settings(WARMUP_MILLIS, 5_000, 1_024, 8),
                new RiskEngine.Settings(1_000, 256, 60_000, true, true, WARMUP_MILLIS, Set.of(), 100),
                cidrs, Duration.ofMinutes(5), 100, 60_000, 1_000);
        ThreatDetector detector = new ThreatDetector(ds, inventory, DetectorControl.direct(cp,
                new Dto.Credential("detector", detectorSecret)), Clock.systemUTC(), System::nanoTime);
        List<RiskEngine.Detection> alerts = new CopyOnWriteArrayList<>();
        detector.onDetection(alerts::add);
        detector.start();
        InetSocketAddress to = new InetSocketAddress(InetAddress.getLoopbackAddress(), detector.port());

        try (DatagramSocket udp = new DatagramSocket();
                TelemetrySender gwSender = new TelemetrySender(CLUSTER, "gw-app-02", "tk1", gwKey, to, 256, RANDOM)) {
            Fixture fx = new Fixture(udp, to, gwKey, issuerKey);

            // 2 first, while the restart guard is still on.
            section("Restart guard (spec 6.1): no automatic action until pre-restart datagrams have aged out");
            fx.send(fx.gw(null, EARLY_IP, DECOY, "decoy-9003", Verdict.DECOY, ReasonCode.DECOY_TOUCH, false));
            RiskEngine.Detection early = awaitAlert(alerts, Selector.ip(EARLY_IP));
            show("decoy hit from " + EARLY_IP + " at start", early);
            require(early != null && early.level() == RiskEngine.Level.CRITICAL && early.proposal() == null
                    && "suppressed: restart guard".equals(early.note()), "critical alert, action suppressed");

            section("CIDR classification of fixture source addresses");
            for (IpAddress ip : List.of(WEB_IP, INTRUDER_IP, NAT_IP, INFRA_IP, OUTSIDE_IP)) {
                CidrClassifier.Zone z = cidrs.classify(ip);
                System.out.printf("    %-14s %-10s automatic IP action %s%n", ip, z,
                        cidrs.eligibleForAutomation(ip) ? "allowed" : "never");
            }
            require(cidrs.classify(NAT_IP) == CidrClassifier.Zone.SHARED
                    && cidrs.classify(INFRA_IP) == CidrClassifier.Zone.PROTECTED
                    && cidrs.classify(WEB_IP) == CidrClassifier.Zone.MANAGED
                    && cidrs.classify(OUTSIDE_IP) == CidrClassifier.Zone.UNMANAGED, "classification as configured");
            Thread.sleep(WARMUP_MILLIS + 200);
            System.out.println("    (waited " + WARMUP_MILLIS + " ms: the restart guard is over)");

            // 3. Learning observations through the real non-blocking UDP producer.
            section("Learning (spec 3.2): pilot admissions become candidates; observations never grant access");
            gwSender.start();
            for (int i = 0; i < 3; i++) {
                gwSender.offer(System.currentTimeMillis(), "api-01", API_IP, "app-02", GW, Verdict.ALLOW, ReasonCode.OK,
                        true, 1);
            }
            gwSender.offer(System.currentTimeMillis(), "web-01", WEB_IP, "app-02", GW, Verdict.ALLOW, ReasonCode.OK,
                    false, 1);
            // A producer claiming an ALLOW outside the pilot scope: the control plane's recheck drops it.
            gwSender.offer(System.currentTimeMillis(), "db-01", DB_IP, "app-02", GW, Verdict.ALLOW, ReasonCode.OK,
                    true, 1);
            awaitTrue(() -> detector.eventsProcessed() >= 6, "learning events received");
            detector.flushLearning();
            detector.dispatcher().awaitIdle(TIMEOUT);
            List<Dto.Observation> draft = cp.draft();
            for (Dto.Observation o : draft) {
                System.out.println("    candidate " + o.edge() + " count=" + o.count());
            }
            System.out.println("    control plane: " + cp.draftStats());
            require(draft.size() == 1 && draft.get(0).edge().equals(new Edge("api-01", "app-02"))
                    && draft.get(0).count() == 3, "api-01->app-02 is a candidate with 3 observations");
            require(cp.draftStats().outOfScope() == 1, "db-01->app-02 (outside the pilot) was dropped");
            require(!cp.snapshot().policy().isApproved(new Edge("api-01", "app-02")), "a candidate grants nothing");
            require(detector.score(Selector.identity("api-01")) == 0, "healthy pilot discovery is not scored");

            // 4. Risk transitions for web-01.
            section("Risk transitions for web-01 (10 s window; 50 alert, 100 critical)");
            LeaseIssuer issuer = new LeaseIssuer(new PolicyEvaluator(Clock.systemUTC()), "lease-k1", leaseKeys.getPrivate(),
                    leaseKeys.getPublic(), new IssueLimiter(100, System::nanoTime), Clock.systemUTC(), RANDOM);
            Peer web = new Peer("web-01", Bytes.fromHex("11".repeat(32)), WEB_IP);
            Peer api = new Peer("api-01", Bytes.fromHex("22".repeat(32)), API_IP);
            Lease before = issuer.issue(EnforcementView.fresh(cp.snapshot()), web, "app-02").lease();
            System.out.println("    lease issued to web-01 before any alert: " + seconds(before) + " s");

            fx.step("issuer: POLICY_DENY web-01 -> app-05", fx.issuerDeny("web-01", WEB_IP, "app-05",
                    ReasonCode.POLICY_DENY), detector, 30);
            fx.step("gateway: INVALID_TOKEN", fx.gw("web-01", WEB_IP, GW, "app-02", Verdict.DENY,
                    ReasonCode.INVALID_TOKEN, false), detector, 40);
            fx.step("gateway: EXPIRED (ordinary expiry, not scored)", fx.gw("web-01", WEB_IP, GW, "app-02", Verdict.DENY,
                    ReasonCode.EXPIRED, false), detector, 40);
            fx.step("gateway: BACKEND_UNAVAILABLE (infrastructure, not scored)", fx.gw("web-01", WEB_IP, GW, "app-02",
                    Verdict.DENY, ReasonCode.BACKEND_UNAVAILABLE, false), detector, 40);
            byte[] wrongAudience = fx.gw("web-01", WEB_IP, GW, "app-02", Verdict.DENY, ReasonCode.WRONG_AUDIENCE, false);
            fx.step("gateway: WRONG_AUDIENCE", wrongAudience, detector, 50);
            RiskEngine.Detection alert = awaitAlert(alerts, WEB);
            show("web-01", alert);
            require(alert != null && alert.level() == RiskEngine.Level.ALERT && alert.alert().score() == 50
                    && alert.proposal() != null && alert.proposal().type() == RiskEngine.ActionType.LEASE_REDUCTION,
                    "ALERT at 50 proposes a lease reduction");
            detector.dispatcher().awaitIdle(TIMEOUT);
            EnforcementSnapshot s = cp.snapshot();
            require(s.leaseReductions().size() == 1 && s.leaseReductions().get(0).selector().equals(WEB),
                    "control plane committed the lease reduction for web-01 (revision " + s.revision() + ")");
            Lease after = issuer.issue(EnforcementView.fresh(s), web, "app-02").lease();
            Lease other = issuer.issue(EnforcementView.fresh(s), api, "app-02").lease();
            PolicyEvaluator gateway = new PolicyEvaluator(Clock.systemUTC());
            PolicyEvaluator.Decision old = gateway.admit(EnforcementView.fresh(s), web, "app-02",
                    eastguard.common.LeaseCodec.issue(before, leaseKeys.getPrivate()));
            System.out.println("    new lease for web-01: " + seconds(after) + " s; for api-01: " + seconds(other)
                    + " s; the earlier 60 s lease at the gateway: " + old.reason());
            require(seconds(before) == 60 && seconds(after) == 10, "step-up shortens newly issued web-01 leases to 10 s");
            require(seconds(other) == 60, "other workloads keep the default lease length");
            require(old.allowed(), "an already issued lease is not shortened (new issuance only)");

            // 5. Untrusted or repeated input does not inflate scores.
            section("Forged, duplicate, replayed, out-of-scope and oversized datagrams (spec 5.3)");
            TelemetryVerifier.Stats st0 = detector.telemetryStats();
            fx.send(wrongAudience);
            fx.send(wrongAudience);
            byte[] forged = TelemetryCodec.encode(fx.telemetry("gw-app-02", fx.gwBoot, 999, "web-01", WEB_IP, GW,
                    "app-02", Verdict.DENY, ReasonCode.IP_MISMATCH, false), randomBytes(32).toArray());
            fx.send(forged);
            fx.send(fx.gw("web-01", WEB_IP, OTHER_GW, "app-05", Verdict.DENY, ReasonCode.IP_MISMATCH, false));
            byte[] oversized = new byte[1_300];
            byte[] valid = fx.gw("web-01", WEB_IP, GW, "app-02", Verdict.DENY, ReasonCode.IP_MISMATCH, false);
            System.arraycopy(valid, 0, oversized, 0, valid.length);
            fx.send(oversized);
            awaitTrue(() -> {
                TelemetryVerifier.Stats st = detector.telemetryStats();
                return st.count(Result.DUPLICATE) - st0.count(Result.DUPLICATE) == 2
                        && st.count(Result.UNAUTHENTICATED) - st0.count(Result.UNAUTHENTICATED) == 1
                        && st.count(Result.OUT_OF_SCOPE) - st0.count(Result.OUT_OF_SCOPE) == 1
                        && st.count(Result.OVERSIZE) - st0.count(Result.OVERSIZE) == 1;
            }, "all five rejected");
            TelemetryVerifier.Stats st1 = detector.telemetryStats();
            System.out.println("    rejected: duplicate=" + (st1.count(Result.DUPLICATE) - st0.count(Result.DUPLICATE))
                    + " unauthenticated=" + (st1.count(Result.UNAUTHENTICATED) - st0.count(Result.UNAUTHENTICATED))
                    + " out-of-scope=" + (st1.count(Result.OUT_OF_SCOPE) - st0.count(Result.OUT_OF_SCOPE))
                    + " oversize=" + (st1.count(Result.OVERSIZE) - st0.count(Result.OVERSIZE)));
            require(detector.score(WEB) == 50, "web-01 still scores 50");

            // 6. Critical.
            section("Critical at 100+ (spec 6.1): quarantine proposed and committed");
            fx.step("gateway: IP_MISMATCH on a verified lease", fx.gw("web-01", WEB_IP, GW, "app-02", Verdict.DENY,
                    ReasonCode.IP_MISMATCH, false), detector, 110);
            RiskEngine.Detection critical = awaitAlert(alerts, WEB, RiskEngine.Level.CRITICAL);
            show("web-01", critical);
            detector.dispatcher().awaitIdle(TIMEOUT);
            require(critical != null && critical.proposal() != null
                    && critical.proposal().type() == RiskEngine.ActionType.QUARANTINE, "CRITICAL proposes quarantine");
            require(restricted(cp, WEB), "control plane committed the quarantine of web-01");

            // 7. Decoys.
            section("Decoy hits (spec 6.1): +100 immediately; automation only for eligible selectors");
            for (IpAddress ip : List.of(INTRUDER_IP, NAT_IP, INFRA_IP)) {
                fx.send(fx.gw(null, ip, DECOY, "decoy-9003", Verdict.DECOY, ReasonCode.DECOY_TOUCH, false));
                show("decoy hit from " + ip, awaitAlert(alerts, Selector.ip(ip)));
            }
            detector.dispatcher().awaitIdle(TIMEOUT);
            require(score(alerts, INTRUDER_IP) == 100 && score(alerts, NAT_IP) == 100 && score(alerts, INFRA_IP) == 100,
                    "each decoy hit is a critical alert at 100");
            require(restricted(cp, Selector.ip(INTRUDER_IP)), "managed IP " + INTRUDER_IP + " quarantined");
            require(!restricted(cp, Selector.ip(NAT_IP)), "shared NAT address " + NAT_IP + " not quarantined");
            require(!restricted(cp, Selector.ip(INFRA_IP)), "protected infrastructure " + INFRA_IP + " not quarantined");

            section("Control plane: committed state and alerts (the detector never signs or broadcasts)");
            for (Restriction r : cp.snapshot().restrictions().stream()
                    .sorted(Comparator.comparing(r -> r.selector().toString())).toList()) {
                System.out.println("    quarantine " + r.selector() + " reason=" + r.reason() + " actor=" + r.actor()
                        + " revision=" + r.revision());
            }
            for (Dto.AlertView a : cp.alerts()) {
                System.out.println("    alert " + a.id() + " " + a.action() + " " + a.selectors() + " score=" + a.score()
                        + " signals=" + a.signals() + " evidence=" + a.evidence().size() + " refs");
            }
            TelemetryVerifier.Stats st = detector.telemetryStats();
            System.out.println("    telemetry: accepted=" + st.count(Result.ACCEPTED) + " duplicate="
                    + st.count(Result.DUPLICATE) + " unauthenticated=" + st.count(Result.UNAUTHENTICATED)
                    + " out-of-scope=" + st.count(Result.OUT_OF_SCOPE) + " oversize=" + st.count(Result.OVERSIZE)
                    + " missing=" + st.missing() + "; producer " + gwSender.stats());
            require(cp.alerts().size() == 3, "three committed actions, each with its alert");
        } finally {
            detector.close();
            journal.close();
        }
        System.out.println();
        System.out.println(failures == 0 ? "DemoM3_Udp: all checks passed" : "DemoM3_Udp: " + failures + " check(s) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    /** Hand-built datagrams from a fixed producer boot, so the demo can replay exactly the same bytes. */
    private static final class Fixture {
        final DatagramSocket udp;
        final InetSocketAddress to;
        final byte[] gwKey;
        final byte[] issuerKey;
        final Bytes gwBoot = randomBytes(16);
        final Bytes issuerBoot = randomBytes(16);
        long gwSeq;
        long issuerSeq;

        Fixture(DatagramSocket udp, InetSocketAddress to, byte[] gwKey, byte[] issuerKey) {
            this.udp = udp;
            this.to = to;
            this.gwKey = gwKey;
            this.issuerKey = issuerKey;
        }

        Telemetry telemetry(String producer, Bytes boot, long seq, String identity, IpAddress ip, Endpoint dst,
                String service, Verdict v, ReasonCode r, boolean outside) {
            return new Telemetry(CLUSTER, producer, "tk1", boot, seq, System.currentTimeMillis(), 1, identity, ip, service,
                    dst.ip(), dst.port(), v, r, outside);
        }

        byte[] gw(String identity, IpAddress ip, Endpoint dst, String service, Verdict v, ReasonCode r, boolean outside) {
            return TelemetryCodec.encode(telemetry("gw-app-02", gwBoot, gwSeq++, identity, ip, dst, service, v, r,
                    outside), gwKey);
        }

        byte[] issuerDeny(String identity, IpAddress ip, String service, ReasonCode r) {
            return TelemetryCodec.encode(telemetry("tokensvc", issuerBoot, issuerSeq++, identity, ip, ISSUER, service,
                    Verdict.DENY, r, r == ReasonCode.POLICY_DENY), issuerKey);
        }

        void send(byte[] d) throws Exception {
            udp.send(new DatagramPacket(d, d.length, to));
        }

        void step(String label, byte[] d, ThreatDetector detector, int expected) throws Exception {
            long processed = detector.eventsProcessed();
            send(d);
            awaitTrue(() -> detector.eventsProcessed() > processed, "event scored");
            int score = detector.score(WEB);
            System.out.printf("    %-58s score %3d  %s%n", label, score, level(score));
            require(score == expected, "web-01 scores " + expected);
        }
    }

    private static String level(int score) {
        return score >= RiskEngine.CRITICAL_SCORE ? "CRITICAL" : score >= RiskEngine.ALERT_SCORE ? "ALERT" : "clean";
    }

    /** LEARN mode: web-01 -> app-02 approved; pilot api-01 -> app-02; app-05 exists but web-01 may not use it. */
    private static EnforcementSnapshot initial(KeyPair leaseKeys) {
        Service app02 = new Service("app-02", "app-02", GW, "127.0.0.1", Endpoint.parse("127.0.0.1:7002"));
        Service app05 = new Service("app-05", "app-05", OTHER_GW, "127.0.0.1", Endpoint.parse("127.0.0.1:7005"));
        Policy policy = new Policy(PolicyMode.LEARN, Set.of(new Edge("web-01", "app-02")),
                new PilotScope(Set.of("api-01"), Set.of("app-02")), 1, Duration.ofSeconds(60));
        return new EnforcementSnapshot(CLUSTER, 1, policy, Map.of("web-01", Workload.enabled("web-01"), "api-01",
                Workload.enabled("api-01"), "db-01", Workload.enabled("db-01")), Map.of("app-02", app02, "app-05", app05),
                List.of(), List.of(), Map.of(), Map.of("lease-k1", leaseKeys.getPublic()), Set.of());
    }

    private static RiskEngine.Detection awaitAlert(List<RiskEngine.Detection> alerts, Selector actor) throws Exception {
        return awaitAlert(alerts, actor, null);
    }

    private static RiskEngine.Detection awaitAlert(List<RiskEngine.Detection> alerts, Selector actor,
            RiskEngine.Level level) throws Exception {
        long deadline = System.nanoTime() + TIMEOUT.toNanos();
        while (System.nanoTime() < deadline) {
            for (RiskEngine.Detection d : alerts) {
                if (d.actor().equals(actor) && (level == null || d.level() == level)) {
                    return d;
                }
            }
            Thread.sleep(5);
        }
        return null;
    }

    private static int score(List<RiskEngine.Detection> alerts, IpAddress ip) {
        for (RiskEngine.Detection d : alerts) {
            if (d.actor().equals(Selector.ip(ip))) {
                return d.alert().score();
            }
        }
        return -1;
    }

    private static boolean restricted(ControlPlaneImpl cp, Selector s) {
        return cp.snapshot().restrictions().stream().anyMatch(r -> r.selector().equals(s));
    }

    private static void show(String who, RiskEngine.Detection d) {
        if (d == null) {
            System.out.println("    " + who + ": no alert");
            return;
        }
        System.out.println("    " + d.level() + " alert " + who + " score=" + d.alert().score() + " zone=" + d.zone()
                + " signals=" + d.alert().signals() + " -> " + (d.proposal() != null ? "propose "
                + d.proposal().type() + " " + d.proposal().selector() : d.note()));
    }

    private static long seconds(Lease l) {
        return (l.expiresAtMs() - l.issuedAtMs()) / 1_000;
    }

    private static void awaitTrue(java.util.function.BooleanSupplier c, String what) throws InterruptedException {
        long deadline = System.nanoTime() + TIMEOUT.toNanos();
        while (!c.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                require(false, "timed out waiting: " + what);
                return;
            }
            Thread.sleep(5);
        }
    }

    private static void section(String title) {
        System.out.println();
        System.out.println("== " + title);
    }

    private static void require(boolean ok, String what) {
        System.out.println("  " + (ok ? "[ok]  " : "[FAIL]") + " " + what);
        if (!ok) {
            failures++;
        }
    }

    private static Bytes randomBytes(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return Bytes.copyOf(b);
    }

    private static <T> List<T> concat(List<T> a, List<T> b) {
        List<T> out = new ArrayList<>(a);
        out.addAll(b);
        return out;
    }

    private static void deleteTree(Path dir) throws java.io.IOException {
        if (!Files.exists(dir)) {
            return;
        }
        try (var paths = Files.walk(dir)) {
            for (Path p : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(p);
            }
        }
    }
}
