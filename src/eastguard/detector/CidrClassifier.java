package eastguard.detector;

import eastguard.common.Cidr;
import eastguard.common.IpAddress;
import java.util.List;
import java.util.Objects;

/**
 * Classifies a source address against configured prefixes (spec §6.1 "do not automatically quarantine shared or
 * ambiguous IPs or protected infrastructure"). The first match wins, most restrictive first:
 *
 * <ol>
 *   <li>{@link Zone#PROTECTED}: infrastructure (gateways, control plane, DNS...). Never auto-quarantined.</li>
 *   <li>{@link Zone#SHARED}: NAT, proxies, shared hosts; one address stands for several workloads.</li>
 *   <li>{@link Zone#MANAGED}: workload addresses EastGuard manages; eligible for automatic IP actions.</li>
 *   <li>{@link Zone#UNMANAGED}: anything else; ambiguous, alert only.</li>
 * </ol>
 */
public final class CidrClassifier {
    public enum Zone { PROTECTED, SHARED, MANAGED, UNMANAGED }

    private final List<Cidr> managed;
    private final List<Cidr> shared;
    private final List<Cidr> protectedInfra;

    public CidrClassifier(List<Cidr> managed, List<Cidr> shared, List<Cidr> protectedInfra) {
        this.managed = List.copyOf(Objects.requireNonNull(managed, "managed"));
        this.shared = List.copyOf(Objects.requireNonNull(shared, "shared"));
        this.protectedInfra = List.copyOf(Objects.requireNonNull(protectedInfra, "protected"));
    }

    public static final CidrClassifier NONE = new CidrClassifier(List.of(), List.of(), List.of());

    public Zone classify(IpAddress ip) {
        if (matches(protectedInfra, ip)) {
            return Zone.PROTECTED;
        }
        if (matches(shared, ip)) {
            return Zone.SHARED;
        }
        return matches(managed, ip) ? Zone.MANAGED : Zone.UNMANAGED;
    }

    /** Only a managed, unshared, unprotected address may be the target of an automatic IP action. */
    public boolean eligibleForAutomation(IpAddress ip) {
        return classify(ip) == Zone.MANAGED;
    }

    private static boolean matches(List<Cidr> list, IpAddress ip) {
        for (Cidr c : list) {
            if (c.contains(ip)) {
                return true;
            }
        }
        return false;
    }
}
