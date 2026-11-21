package eastguard.test;

import eastguard.common.Bytes;
import eastguard.common.Edge;
import eastguard.common.Endpoint;
import eastguard.common.EnforcementSnapshot;
import eastguard.common.PilotScope;
import eastguard.common.Policy;
import eastguard.common.PolicyMode;
import eastguard.common.Service;
import eastguard.common.Workload;
import eastguard.control.ControlPlaneImpl;
import eastguard.control.Credentials;
import eastguard.control.Dto;
import eastguard.control.Journal;
import eastguard.control.Role;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Shared control-plane fixtures: bootstrap state, principals, a settable clock. Not a test class. */
final class ControlFixtures {
    static final String[][] PRINCIPALS = {
            {"admin", "ADMIN"}, {"operator", "OPERATOR"}, {"viewer", "VIEWER"}, {"gw-app-02", "GATEWAY"},
            {"tokensvc", "ISSUER"}, {"detector", "DETECTOR"}, {"admin-2", "ADMIN"}};
    private static final SecureRandom RANDOM = new SecureRandom();

    /** One secret per principal, plus a disabled operator. */
    final Map<String, Bytes> secrets = new HashMap<>();
    final Credentials credentials;
    final MutableClock clock = new MutableClock(Instant.parse("2026-11-19T10:00:00Z"));

    ControlFixtures() {
        List<Credentials.Principal> list = new ArrayList<>();
        for (String[] p : PRINCIPALS) {
            Bytes s = secret();
            secrets.put(p[0], s);
            list.add(Credentials.Principal.withSecret(p[0], Role.valueOf(p[1]), s));
        }
        Bytes revoked = secret();
        secrets.put("revoked-op", revoked);
        list.add(new Credentials.Principal("revoked-op", Role.OPERATOR,
                Credentials.Principal.withSecret("revoked-op", Role.OPERATOR, revoked).digests(), false));
        credentials = Credentials.of(list);
    }

    static Clock fixedClock() {
        return Clock.fixed(Instant.parse("2026-11-19T10:00:00Z"), ZoneOffset.UTC);
    }

    static Bytes secret() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return Bytes.copyOf(b);
    }

    Dto.Credential cred(String principal) {
        return new Dto.Credential(principal, secrets.get(principal));
    }

    /** Revision-1 state: web-01 and api-01, service app-02, only web-01 -> app-02 approved. */
    static EnforcementSnapshot initial(PublicKey leaseKey) {
        Service app = new Service("app-02", "app-02", Endpoint.parse("127.0.0.1:9002"), "127.0.0.1",
                Endpoint.parse("127.0.0.1:7002"));
        Policy policy = new Policy(PolicyMode.ENFORCE, Set.of(new Edge("web-01", "app-02")), PilotScope.NONE, 1,
                Duration.ofSeconds(60));
        return new EnforcementSnapshot("eg-test", 1, policy,
                Map.of("web-01", Workload.enabled("web-01"), "api-01", Workload.enabled("api-01")),
                Map.of("app-02", app), List.of(), List.of(), Map.of(), Map.of("lease-k1", leaseKey), Set.of());
    }

    static Path freshJournal() throws IOException {
        Path dir = Files.createDirectories(Path.of("out", "test-control"));
        return Files.createTempDirectory(dir, "cp").resolve("control.journal");
    }

    /** Opens the journal at {@code file} and a control plane over it. Close the journal when done. */
    ControlPlaneImpl open(Journal journal) throws IOException {
        return ControlPlaneImpl.open(journal, clock, credentials, ControlPlaneImpl.Settings.defaults());
    }

    /** A bootstrapped control plane on a new journal. */
    ControlPlaneImpl bootstrapped(Journal journal) throws IOException {
        ControlPlaneImpl cp = open(journal);
        Dto.MutationResult r = cp.bootstrap(initial(Fixtures.LEASE_KEYS.getPublic()), "admin", "initial state");
        if (!r.ok()) {
            throw new IllegalStateException("bootstrap failed: " + r);
        }
        return cp;
    }

    static final class MutableClock extends Clock {
        private volatile Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
