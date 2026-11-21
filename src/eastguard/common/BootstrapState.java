package eastguard.common;

import java.security.PublicKey;
import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Builds an {@link EnforcementSnapshot} from {@code bootstrap.*} configuration keys. Used by the token service
 * (and later the gateway) until control-plane sync exists (Task 6); afterwards it only seeds the control plane.
 *
 * <pre>
 * cluster.id=eg-demo
 * lease.defaultSeconds=60                       1..60
 * bootstrap.revision=1
 * bootstrap.mode=ENFORCE                        ENFORCE | LEARN
 * bootstrap.workloads=web-01,api-01
 * bootstrap.workload.web-01.enabled=true        optional, default true
 * bootstrap.workload.web-01.ipZone=10.0.1.0/24  optional
 * bootstrap.services=app-02
 * bootstrap.service.app-02.gateway=app-02
 * bootstrap.service.app-02.listener=127.0.0.1:9002
 * bootstrap.service.app-02.serverName=127.0.0.1
 * bootstrap.service.app-02.backend=127.0.0.1:7002
 * bootstrap.edges=web-01>app-02                 source>service, comma-separated
 * bootstrap.pilot.sources=                      LEARN pilot scope, optional
 * bootstrap.pilot.services=
 * bootstrap.tokenKeys=lease-k1
 * bootstrap.tokenKey.lease-k1.cert=keys/lease-k1.cer
 * bootstrap.controlKeys=control-k1              multicast notice keys (spec §5.4); optional, separate from
 * bootstrap.controlKey.control-k1.cert=keys/control-k1.cer   the lease keys
 * </pre>
 *
 * Edges and pilot entries must reference listed workloads and services. Deny by default: an empty edge list
 * admits nothing.
 */
public final class BootstrapState {
    private BootstrapState() {
    }

    public static EnforcementSnapshot snapshot(Config c) {
        String cluster = c.id("cluster.id");
        long revision = c.longIn("bootstrap.revision", 1, 0, Long.MAX_VALUE);
        PolicyMode mode = c.enumValue("bootstrap.mode", PolicyMode.class, PolicyMode.ENFORCE);
        Duration lease = Duration.ofSeconds(c.longIn("lease.defaultSeconds", 60, 1, 60));

        Map<String, Workload> workloads = new HashMap<>();
        for (String id : c.idList("bootstrap.workloads")) {
            String p = "bootstrap.workload." + id + ".";
            workloads.put(id, new Workload(id, c.bool(p + "enabled", true), Set.of(), c.cidr(p + "ipZone")));
        }

        Map<String, Service> services = new HashMap<>();
        for (String id : c.idList("bootstrap.services")) {
            String p = "bootstrap.service." + id + ".";
            String serverName = c.string(p + "serverName");
            try {
                services.put(id, new Service(id, c.id(p + "gateway"), c.endpoint(p + "listener"), serverName,
                        c.endpoint(p + "backend")));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("config " + c.source() + ": service " + id + ": " + e.getMessage());
            }
        }

        Set<Edge> edges = new HashSet<>();
        String edgeList = c.optional("bootstrap.edges");
        if (edgeList != null) {
            for (String part : edgeList.split(",", -1)) {
                String[] sides = part.strip().split(">", -1);
                if (sides.length != 2 || !Ids.isValid(sides[0].strip()) || !Ids.isValid(sides[1].strip())) {
                    throw new IllegalArgumentException("config " + c.source() + ": bootstrap.edges entries must be source>service");
                }
                Edge e = new Edge(sides[0].strip(), sides[1].strip());
                requireKnown(c, workloads.keySet(), e.sourceIdentity(), "bootstrap.edges");
                requireKnown(c, services.keySet(), e.serviceId(), "bootstrap.edges");
                if (!edges.add(e)) {
                    throw new IllegalArgumentException("config " + c.source() + ": bootstrap.edges lists " + e + " twice");
                }
            }
        }

        List<String> pilotSources = c.idList("bootstrap.pilot.sources");
        List<String> pilotServices = c.idList("bootstrap.pilot.services");
        pilotSources.forEach(id -> requireKnown(c, workloads.keySet(), id, "bootstrap.pilot.sources"));
        pilotServices.forEach(id -> requireKnown(c, services.keySet(), id, "bootstrap.pilot.services"));
        PilotScope pilot = new PilotScope(Set.copyOf(pilotSources), Set.copyOf(pilotServices));

        Map<String, PublicKey> keys = new HashMap<>();
        for (String keyId : c.idList("bootstrap.tokenKeys")) {
            keys.put(keyId, KeyStores.ed25519PublicKey(c.path("bootstrap.tokenKey." + keyId + ".cert")));
        }

        Map<String, PublicKey> controlKeys = new HashMap<>();
        for (String keyId : c.idList("bootstrap.controlKeys")) {
            controlKeys.put(keyId, KeyStores.ed25519PublicKey(c.path("bootstrap.controlKey." + keyId + ".cert")));
        }

        Policy policy = new Policy(mode, edges, pilot, revision, lease);
        return new EnforcementSnapshot(cluster, revision, policy, workloads, services, List.of(), List.of(),
                Map.of(), keys, Set.of(), controlKeys);
    }

    private static void requireKnown(Config c, Set<String> known, String id, String key) {
        if (!known.contains(id)) {
            throw new IllegalArgumentException("config " + c.source() + ": " + key + " references unknown '" + id + "'");
        }
    }
}
