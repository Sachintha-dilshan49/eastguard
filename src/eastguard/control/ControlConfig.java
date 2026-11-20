package eastguard.control;

import eastguard.common.Config;
import eastguard.common.Ids;
import eastguard.common.IpAddress;
import eastguard.common.SecretSource;
import eastguard.tokensvc.TlsContextFactory;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;

/** Control-plane configuration, see {@code config/control.properties.example}. */
public record ControlConfig(String clusterId, String rmiHost, int registryPort, int objectPort,
        TlsContextFactory.Material tls, Path journalFile, Path credentialsFile, ControlPlaneImpl.Settings settings) {

    public ControlConfig {
        Ids.require(clusterId, "clusterId");
        IpAddress.parse(rmiHost);
        if (registryPort == objectPort) {
            throw new IllegalArgumentException("registry and object ports must differ");
        }
        Objects.requireNonNull(tls, "tls");
        Objects.requireNonNull(journalFile, "journalFile");
        Objects.requireNonNull(credentialsFile, "credentialsFile");
        Objects.requireNonNull(settings, "settings");
    }

    public static ControlConfig load(Path file) {
        Config c = Config.load(file);
        String host = c.string("rmi.host");
        try {
            IpAddress.parse(host);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("config " + c.source() + ": rmi.host must be a numeric address");
        }
        ControlConfig cfg = new ControlConfig(c.id("cluster.id"), host,
                c.intIn("rmi.registryPort", 1099, 1, 65_535), c.intIn("rmi.objectPort", 1100, 1, 65_535),
                new TlsContextFactory.Material(c.path("tls.keyStore"), c.path("tls.trustStore"),
                        new SecretSource(c.string("tls.passwordEnv", "EASTGUARD_STORE_PASS"),
                                c.path("tls.passwordFile", "keys/store.pass"))),
                c.path("journal.file"), c.path("credentials.file"),
                new ControlPlaneImpl.Settings(Duration.ofSeconds(c.longIn("quarantine.maxTtlSeconds", 86_400, 1, 604_800)),
                        c.intIn("audit.retainedEntries", 10_000, 1, 1_000_000), automation(c),
                        c.intIn("learning.maxCandidates", 10_000, 1, 1_000_000)));
        c.requireNoUnknownKeys();
        return cfg;
    }

    /** {@code automation.*} and {@code lease.stepUpSeconds}; everything off by default (alert-only). */
    static ControlPlaneImpl.Automation automation(Config c) {
        return new ControlPlaneImpl.Automation(c.bool("automation.leaseReduction", false),
                c.bool("automation.quarantine", false), Duration.ofSeconds(c.longIn("lease.stepUpSeconds", 10, 1, 60)),
                Duration.ofSeconds(c.longIn("automation.maxActionTtlSeconds", 300, 1, 86_400)),
                c.intIn("automation.maxActionsPerHour", 20, 1, 10_000),
                new java.util.HashSet<>(c.idList("automation.protectedIdentities")),
                c.cidrList("automation.eligibleCidrs"), c.cidrList("automation.excludedCidrs"));
    }
}
