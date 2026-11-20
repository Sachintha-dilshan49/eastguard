package eastguard.test;

import static eastguard.test.Assert.assertEquals;
import static eastguard.test.Assert.assertNull;
import static eastguard.test.Assert.assertTrue;

import eastguard.common.AlertStatus;
import eastguard.common.Bytes;
import eastguard.common.Cidr;
import eastguard.common.Endpoint;
import eastguard.common.IpAddress;
import eastguard.common.ReasonCode;
import eastguard.common.Selector;
import eastguard.common.Telemetry;
import eastguard.common.Verdict;
import eastguard.detector.CidrClassifier;
import eastguard.detector.ProducerInventory.Kind;
import eastguard.detector.RiskEngine;
import eastguard.detector.RiskEngine.ActionType;
import eastguard.detector.RiskEngine.Detection;
import eastguard.detector.RiskEngine.Level;
import eastguard.detector.RiskEngine.Settings;
import eastguard.detector.SlidingWindow;
import eastguard.detector.TelemetryVerifier.Verified;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;

/** Detector scoring (spec §6.1): exact fixture scores, age-out, scan signal, levels, and automation guards. */
public final class RiskEngineTest {
    static final long S = 1_000_000_000L;
    static final Endpoint GW = Endpoint.parse("127.0.0.1:9002");
    static final Endpoint DECOY = Endpoint.parse("127.0.0.1:9003");
    static final Endpoint ISSUER = Endpoint.parse("127.0.0.1:8443");
    static final IpAddress WEB_IP = IpAddress.parse("10.0.1.10");
    static final IpAddress SHARED_IP = IpAddress.parse("10.0.99.7");
    static final IpAddress INFRA_IP = IpAddress.parse("10.0.0.5");
    static final IpAddress OUTSIDE_IP = IpAddress.parse("192.168.5.5");
    static final Selector WEB = Selector.identity("web-01");
    static final CidrClassifier CIDRS = new CidrClassifier(List.of(Cidr.parse("10.0.0.0/8")),
            List.of(Cidr.parse("10.0.99.0/24")), List.of(Cidr.parse("10.0.0.0/28")));
    static final Bytes BOOT = Bytes.fromHex("00112233445566778899aabbccddeeff");

    private long seq;

    static Settings automated(long cooldownMillis, long warmupMillis) {
        return new Settings(100, 256, cooldownMillis, true, true, warmupMillis, Set.of("gw-infra"), 50);
    }

    static RiskEngine engine(Settings s) {
        return new RiskEngine(s, CIDRS, now -> false, Fixtures.CLOCK, 0, new SecureRandom());
    }

    Verified ev(long at, Kind kind, String identity, IpAddress ip, Endpoint dst, Verdict v, ReasonCode r) {
        String service = kind == Kind.ISSUER ? "app-02" : dst.equals(DECOY) ? "decoy-9003" : "app-" + dst.port();
        Telemetry t = new Telemetry("eg-demo", kind == Kind.ISSUER ? "tokensvc" : "gw-app-02", "tk1", BOOT, seq++,
                Fixtures.NOW_MS, 1, identity, ip, service, dst.ip(), dst.port(), v, r, r == ReasonCode.POLICY_DENY);
        return new Verified(t, kind, at);
    }

    Verified deny(long at, ReasonCode r) {
        return ev(at, Kind.GATEWAY, "web-01", WEB_IP, GW, Verdict.DENY, r);
    }

    Verified decoy(long at, IpAddress ip) {
        return ev(at, Kind.GATEWAY, null, ip, DECOY, Verdict.DECOY, ReasonCode.DECOY_TOUCH);
    }

    public void testSignalTable() {
        assertEquals(RiskEngine.Signal.POLICY_DENY, RiskEngine.signalOf(deny(0, ReasonCode.POLICY_DENY).event()));
        assertEquals(RiskEngine.Signal.IP_MISMATCH, RiskEngine.signalOf(deny(0, ReasonCode.IP_MISMATCH).event()));
        assertEquals(RiskEngine.Signal.DECOY, RiskEngine.signalOf(decoy(0, WEB_IP).event()));
        for (ReasonCode r : List.of(ReasonCode.INVALID_TOKEN, ReasonCode.WRONG_AUDIENCE, ReasonCode.IDENTITY_MISMATCH,
                ReasonCode.QUARANTINED, ReasonCode.REVOKED, ReasonCode.LEASE_SUPERSEDED, ReasonCode.IDENTITY_DISABLED,
                ReasonCode.BAD_IDENTITY)) {
            assertEquals(RiskEngine.Signal.SECURITY_DENY, RiskEngine.signalOf(deny(0, r).event()));
        }
        // Infrastructure failures, throttling, ordinary expiry and healthy or pilot traffic are not scored.
        for (ReasonCode r : List.of(ReasonCode.EXPIRED, ReasonCode.NOT_READY, ReasonCode.BACKEND_UNAVAILABLE,
                ReasonCode.THROTTLED)) {
            assertNull(RiskEngine.signalOf(deny(0, r).event()));
        }
        assertNull(RiskEngine.signalOf(ev(0, Kind.GATEWAY, "web-01", WEB_IP, GW, Verdict.ALLOW, ReasonCode.OK).event()));
        assertEquals(30 + 10 + 50 + 60 + 100, java.util.Arrays.stream(RiskEngine.Signal.values())
                .mapToInt(RiskEngine.Signal::points).sum());
    }

    /** The fixture stream of DemoM3: clean, alert at 50, critical at 110, then exact age-out. */
    public void testFixtureScoresTransitionsAndAgeOut() {
        RiskEngine e = engine(automated(60_000, 0));
        assertNull(e.accept(deny(0, ReasonCode.POLICY_DENY)));
        assertEquals(30, e.score(WEB, 0));
        assertNull(e.accept(deny(1 * S, ReasonCode.INVALID_TOKEN)));
        assertEquals(40, e.score(WEB, S));
        assertNull(e.accept(deny(S + 1, ReasonCode.EXPIRED))); // not scored
        assertNull(e.accept(deny(S + 2, ReasonCode.THROTTLED))); // not scored
        Detection alert = e.accept(deny(2 * S, ReasonCode.WRONG_AUDIENCE));
        assertEquals(50, alert.alert().score());
        assertEquals(Level.ALERT, alert.level());
        assertEquals(ActionType.LEASE_REDUCTION, alert.proposal().type());
        assertEquals(WEB, alert.proposal().selector());
        assertEquals(List.of("POLICY_DENY", "SECURITY_DENY"), alert.alert().signals());
        assertEquals(3, alert.alert().evidenceRefs().size());
        assertEquals(AlertStatus.PROPOSED, alert.alert().status());
        Detection critical = e.accept(deny(3 * S, ReasonCode.IP_MISMATCH));
        assertEquals(110, critical.alert().score());
        assertEquals(Level.CRITICAL, critical.level());
        assertEquals(ActionType.QUARANTINE, critical.proposal().type());

        assertEquals(110, e.score(WEB, 10 * S - 1));
        assertEquals(80, e.score(WEB, 10 * S)); // the event at t=0 aged out after exactly 10 s
        e.tick(10 * S);
        assertEquals(Level.ALERT, e.level(WEB, 10 * S));
        assertEquals(60, e.score(WEB, 12 * S));
        assertEquals(0, e.score(WEB, 13 * S));
        e.tick(13 * S);
        assertEquals(0, e.actorCount());
    }

    public void testScanSignalAddsFiftyOnceAndOnlyForGatewayEvents() {
        RiskEngine e = engine(Settings.alertOnly());
        Selector ip = Selector.ip(OUTSIDE_IP);
        for (int i = 0; i < 11; i++) {
            e.accept(ev(i * 100_000_000L, Kind.GATEWAY, null, OUTSIDE_IP, new Endpoint(GW.ip(), 9100 + i), Verdict.DENY,
                    ReasonCode.INVALID_TOKEN));
        }
        assertEquals(11 * 10 + 50, e.score(ip, S + 100_000_000L));
        e.accept(ev(1_200_000_000L, Kind.GATEWAY, null, OUTSIDE_IP, new Endpoint(GW.ip(), 9200), Verdict.DENY,
                ReasonCode.INVALID_TOKEN));
        assertEquals(12 * 10 + 50, e.score(ip, 1_200_000_000L)); // +50 once while the condition holds
        // The same endpoint again does not add distinct endpoints.
        RiskEngine same = engine(Settings.alertOnly());
        for (int i = 0; i < 12; i++) {
            same.accept(ev(i, Kind.GATEWAY, null, OUTSIDE_IP, GW, Verdict.DENY, ReasonCode.INVALID_TOKEN));
        }
        assertEquals(120, same.score(ip, 12));
        // Issuer denials never count towards the scan signal.
        RiskEngine issuer = engine(Settings.alertOnly());
        for (int i = 0; i < 11; i++) {
            issuer.accept(ev(i, Kind.ISSUER, "web-01", WEB_IP, new Endpoint(ISSUER.ip(), 8400 + i), Verdict.DENY,
                    ReasonCode.POLICY_DENY));
        }
        assertEquals(330, issuer.score(WEB, 11));
    }

    public void testDecoyHitIsCriticalImmediatelyAndIpOnly() {
        RiskEngine e = engine(automated(60_000, 0));
        Detection d = e.accept(decoy(0, WEB_IP));
        assertEquals(100, d.alert().score());
        assertEquals(Level.CRITICAL, d.level());
        assertEquals(Selector.ip(WEB_IP), d.actor());
        assertNull(d.alert().sourceIdentity());
        assertEquals(CidrClassifier.Zone.MANAGED, d.zone());
        assertEquals(ActionType.QUARANTINE, d.proposal().type());
        assertEquals(Selector.ip(WEB_IP), d.proposal().selector());
    }

    public void testNoAutomaticActionForSharedProtectedOrUnmanagedIps() {
        RiskEngine e = engine(automated(60_000, 0));
        Detection shared = e.accept(decoy(0, SHARED_IP));
        assertEquals(Level.CRITICAL, shared.level());
        assertNull(shared.proposal());
        assertEquals("ineligible: shared ip", shared.note());
        assertEquals(AlertStatus.OPEN, shared.alert().status());
        assertEquals("ineligible: protected ip", e.accept(decoy(1, INFRA_IP)).note());
        assertEquals("ineligible: unmanaged ip", e.accept(decoy(2, OUTSIDE_IP)).note());
        // A protected infrastructure identity is never proposed either.
        Detection infra = e.accept(ev(3, Kind.GATEWAY, "gw-infra", WEB_IP, GW, Verdict.DENY, ReasonCode.IP_MISMATCH));
        Detection infra2 = e.accept(ev(4, Kind.GATEWAY, "gw-infra", WEB_IP, GW, Verdict.DENY, ReasonCode.IP_MISMATCH));
        assertEquals("ineligible: protected identity", infra.note());
        assertEquals(Level.CRITICAL, infra2.level());
        assertNull(infra2.proposal());
    }

    public void testCooldownPerSelectorAndAction() {
        RiskEngine e = engine(automated(60_000, 0));
        assertEquals(ActionType.QUARANTINE, e.accept(decoy(0, WEB_IP)).proposal().type());
        e.tick(11 * S); // evidence aged out: level back to clean
        Detection again = e.accept(decoy(15 * S, WEB_IP));
        assertEquals(Level.CRITICAL, again.level());
        assertNull(again.proposal());
        assertEquals("suppressed: cooldown", again.note());
        // A different selector is not affected by that cooldown.
        assertEquals(ActionType.QUARANTINE, e.accept(decoy(15 * S, IpAddress.parse("10.0.1.11"))).proposal().type());
        e.tick(30 * S);
        assertEquals(ActionType.QUARANTINE, e.accept(decoy(61 * S, WEB_IP)).proposal().type());
    }

    public void testRestartGuardSuppressesActionsButNotAlerts() {
        RiskEngine e = engine(automated(0, 30_000));
        Detection early = e.accept(decoy(29 * S, WEB_IP));
        assertEquals(Level.CRITICAL, early.level());
        assertNull(early.proposal());
        assertEquals("suppressed: restart guard", early.note());
        e.tick(40 * S);
        assertEquals(ActionType.QUARANTINE, e.accept(decoy(40 * S, WEB_IP)).proposal().type());
    }

    public void testDegradedInputSuspendsAutomation() {
        RiskEngine e = new RiskEngine(automated(0, 0), CIDRS, now -> true, Fixtures.CLOCK, 0, new SecureRandom());
        assertEquals("suppressed: input degraded", e.accept(decoy(0, WEB_IP)).note());
    }

    public void testAlertOnlyByDefault() {
        RiskEngine e = engine(Settings.alertOnly());
        Detection d = e.accept(decoy(31 * S, WEB_IP));
        assertEquals(Level.CRITICAL, d.level());
        assertNull(d.proposal());
        assertEquals("alert-only", d.note());
        assertEquals(1, e.history().size());
    }

    public void testActorTableIsBoundedAndOverflowPausesAutomation() {
        RiskEngine e = engine(new Settings(2, 256, 0, true, true, 0, Set.of(), 50));
        e.accept(deny(0, ReasonCode.POLICY_DENY));
        e.accept(decoy(1, IpAddress.parse("10.0.1.20")));
        assertNull(e.accept(decoy(2, IpAddress.parse("10.0.1.21")))); // third actor dropped
        assertEquals(1, e.droppedActors());
        assertEquals(2, e.actorCount());
        Detection d = e.accept(deny(3, ReasonCode.IP_MISMATCH)); // web-01: 30 + 60 = 90
        assertEquals("suppressed: detector overloaded", d.note());
    }

    public void testSlidingWindowBounds() {
        SlidingWindow<Integer> w = new SlidingWindow<>(10, 3);
        assertTrue(w.add(0, 1), "room");
        w.add(1, 2);
        w.add(2, 3);
        assertTrue(!w.add(3, 4), "evicted the oldest");
        assertEquals(List.of(2, 3, 4), w.values(3));
        assertEquals(List.of(4), w.values(12));
        assertEquals(1, w.evicted());
    }
}
