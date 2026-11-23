package eastguard.simulator;

import eastguard.client.EastGuardClient;
import eastguard.client.GatewaySession;
import eastguard.common.Bytes;
import eastguard.common.Endpoint;
import eastguard.common.IssuerReply;
import eastguard.common.ReplyStatus;
import eastguard.common.SecretSource;
import eastguard.tokensvc.TlsContextFactory;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;

/**
 * Token theft and replay attack simulator (idea §7, §10): simulates a compromised node attempting
 * lateral movement by replaying a stolen identity lease.
 *
 * <ol>
 *   <li>The attacker captures a valid, unexpired lease token legitimately issued to workload A (e.g. {@code web-01});</li>
 *   <li>The attacker connects to the target service's gateway from workload B's credentials (e.g. {@code api-01});</li>
 *   <li>The gateway checks the token's embedded leaf certificate fingerprint against the mTLS peer certificate;</li>
 *   <li>The gateway rejects the replayed token with {@code 0x01 DENY} (reason {@code IDENTITY_MISMATCH})
 *       and scores +60 risk points in the Threat Detector without opening a backend connection.</li>
 * </ol>
 */
public final class TokenReplayAttack {
    private static final Logger LOG = Logger.getLogger(TokenReplayAttack.class.getName());

    public record AttackResult(
            boolean attackBlocked,
            ReplyStatus gatewayReply,
            String reasonExplanation,
            Duration duration) {}

    private final EastGuardClient victimClient;
    private final EastGuardClient attackerClient;
    private final Endpoint gateway;
    private final String gatewayServerName;
    private final String targetService;

    public TokenReplayAttack(
            SSLContext victimCtx,
            SSLContext attackerCtx,
            Endpoint issuer,
            String issuerServerName,
            Endpoint gateway,
            String gatewayServerName,
            String targetService,
            Duration timeout) {

        this.victimClient = new EastGuardClient(victimCtx, issuer, issuerServerName, timeout);
        this.attackerClient = new EastGuardClient(attackerCtx, issuer, issuerServerName, timeout);
        this.gateway = Objects.requireNonNull(gateway, "gateway");
        this.gatewayServerName = Objects.requireNonNull(gatewayServerName, "gatewayServerName");
        this.targetService = Objects.requireNonNull(targetService, "targetService");
    }

    /**
     * Executes the token replay attack:
     * 1. Obtains a valid token using victim's TLS certificate.
     * 2. Presents that token to the gateway using attacker's TLS certificate.
     */
    public AttackResult execute() throws IOException {
        long t0 = System.nanoTime();
        // 1. Legitimately obtain a token for victim (web-01) -> target (app-02)
        IssuerReply victimReply = victimClient.requestLease(targetService);
        if (victimReply.status() != ReplyStatus.SUCCESS) {
            long ms = (System.nanoTime() - t0) / 1_000_000;
            return new AttackResult(false, victimReply.status(),
                    "Could not obtain initial victim token: " + victimReply.status(), Duration.ofMillis(ms));
        }
        Bytes stolenToken = victimReply.token();

        // 2. Attacker (api-01) attempts to present victim's token to gateway (app-02)
        try (GatewaySession session = attackerClient.connect(gateway, gatewayServerName, stolenToken)) {
            long ms = (System.nanoTime() - t0) / 1_000_000;
            if (session.status() == ReplyStatus.SUCCESS) {
                // Security failure: token replay succeeded (should not happen)
                return new AttackResult(false, ReplyStatus.SUCCESS,
                        "CRITICAL: Gateway erroneously admitted a replayed token!", Duration.ofMillis(ms));
            } else {
                // Expected security defense: gateway rejected the replayed token
                return new AttackResult(true, session.status(),
                        "Gateway successfully rejected replayed token with status " + session.status()
                                + " (IDENTITY_MISMATCH: certificate fingerprint mismatch)", Duration.ofMillis(ms));
            }
        }
    }

    public static void main(String[] args) throws Exception {
        Path keysDir = Path.of(args.length > 0 ? args[0] : "keys");
        SecretSource pass = new SecretSource("EASTGUARD_STORE_PASS", keysDir.resolve("store.pass"));
        Path ts = keysDir.resolve("truststore.p12");

        Path webP12 = keysDir.resolve("workload-web-01.p12");
        Path apiP12 = keysDir.resolve("workload-api-01.p12");

        SSLContext victimCtx = TlsContextFactory.create(new TlsContextFactory.Material(webP12, ts, pass));
        SSLContext attackerCtx = TlsContextFactory.create(new TlsContextFactory.Material(apiP12, ts, pass));

        Endpoint issuer = new Endpoint(eastguard.common.IpAddress.parse("127.0.0.1"), 8443);
        Endpoint gateway = new Endpoint(eastguard.common.IpAddress.parse("127.0.0.1"), 9002);

        TokenReplayAttack attack = new TokenReplayAttack(victimCtx, attackerCtx,
                issuer, "localhost", gateway, "localhost", "app-02", Duration.ofSeconds(5));

        System.out.println("Launching Token Replay Attack (simulating stolen web-01 token replayed by api-01)...");
        AttackResult res = attack.execute();
        System.out.println("Attack blocked: " + res.attackBlocked());
        System.out.println("Gateway reply:  " + res.gatewayReply());
        System.out.println("Explanation:    " + res.reasonExplanation());
        System.out.println("Elapsed:        " + res.duration().toMillis() + " ms");
        if (!res.attackBlocked()) {
            System.exit(1);
        }
    }
}
