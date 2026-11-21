package eastguard.control;

import eastguard.bus.MulticastSettings;
import eastguard.common.Config;
import eastguard.common.Ids;
import eastguard.common.IpAddress;
import eastguard.common.SecretSource;
import eastguard.tokensvc.TlsContextFactory;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;

/**
 * Control-plane configuration, see {@code config/control.properties.example}.
 *
 * @param multicast optional notice channel ({@code multicast.*}); {@code null}: no notices, enforcement points
 *                  converge by polling only
 * @param notices   the control-plane notice signer, required with {@code multicast}
 * @param audit     optional HTTPS audit export ({@code audit.*}); {@code null}: not served
 */
public record ControlConfig(String clusterId, String rmiHost, int registryPort, int objectPort,
        TlsContextFactory.Material tls, Path journalFile, Path credentialsFile, ControlPlaneImpl.Settings settings,
        MulticastSettings multicast, NoticeSigner notices, AuditHttpServer.Settings audit) {

    /**
     * The Ed25519 control-plane signer for multicast notices (spec §5.4). Never the lease key: a separate store,
     * alias and password ({@code scripts/gen-certs.ps1 -AddControlSigner}).
     *
     * <pre>
     * notice.keyStore=keys/control-signer.p12   notice.keyAlias=control-k1   notice.keyId=control-k1
     * notice.passwordEnv=EASTGUARD_CONTROL_SIGNER_PASS   notice.passwordFile=keys/control-signer.pass
     * notice.repeatGapMillis=10                 pause between the three copies of a notice
     * </pre>
     */
    public record NoticeSigner(Path keyStore, String alias, String keyId, SecretSource password, Duration repeatGap) {
        public NoticeSigner {
            Objects.requireNonNull(keyStore, "keyStore");
            Objects.requireNonNull(alias, "alias");
            Ids.require(keyId, "keyId");
            Objects.requireNonNull(password, "password");
            Objects.requireNonNull(repeatGap, "repeatGap");
        }
    }

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
        if (multicast != null && notices == null) {
            throw new IllegalArgumentException("multicast notices need a notice signer (notice.*)");
        }
    }

    public static ControlConfig load(Path file) {
        Config c = Config.load(file);
        String host = c.string("rmi.host");
        try {
            IpAddress.parse(host);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("config " + c.source() + ": rmi.host must be a numeric address");
        }
        MulticastSettings multicast = MulticastSettings.from(c);
        NoticeSigner signer = multicast == null && c.optional("notice.keyStore") == null ? null
                : new NoticeSigner(c.path("notice.keyStore"), c.string("notice.keyAlias", "control-k1"),
                        c.id("notice.keyId"), new SecretSource(c.string("notice.passwordEnv", "EASTGUARD_CONTROL_SIGNER_PASS"),
                                c.path("notice.passwordFile", "keys/control-signer.pass")),
                        c.millis("notice.repeatGapMillis", 10, 0, 1_000));
        ControlConfig cfg = new ControlConfig(c.id("cluster.id"), host,
                c.intIn("rmi.registryPort", 1099, 1, 65_535), c.intIn("rmi.objectPort", 1100, 1, 65_535),
                new TlsContextFactory.Material(c.path("tls.keyStore"), c.path("tls.trustStore"),
                        new SecretSource(c.string("tls.passwordEnv", "EASTGUARD_STORE_PASS"),
                                c.path("tls.passwordFile", "keys/store.pass"))),
                c.path("journal.file"), c.path("credentials.file"),
                new ControlPlaneImpl.Settings(Duration.ofSeconds(c.longIn("quarantine.maxTtlSeconds", 86_400, 1, 604_800)),
                        c.intIn("audit.retainedEntries", 10_000, 1, 1_000_000), automation(c),
                        c.intIn("learning.maxCandidates", 10_000, 1, 1_000_000)),
                multicast, signer, AuditHttpServer.from(c));
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
