package eastguard.detector;

import eastguard.common.Config;
import eastguard.common.Endpoint;
import eastguard.common.Ids;
import eastguard.common.ReasonCode;
import eastguard.common.SecretSource;
import eastguard.common.Telemetry;
import eastguard.common.TelemetrySender;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Trusted telemetry producers (spec §5.3): each one's HMAC key and the listeners it may report on. A datagram is
 * scored only if its MAC verifies with its producer's own key <em>and</em> the producer is in scope for the event:
 *
 * <ul>
 *   <li>A {@link Kind#GATEWAY} reports ALLOW/DENY only for its own service on its own listener, and DECOY only
 *       for one of its own decoy listeners.</li>
 *   <li>The {@link Kind#ISSUER} reports DENY only, only with reason POLICY_DENY or QUARANTINED, and only on the
 *       token-service listener. Its {@code service} is the requested service ({@code *} in the inventory).</li>
 * </ul>
 *
 * A compromised producer key can therefore not attribute events to another producer's listeners.
 *
 * <pre>
 * producers=gw-app-02,tokensvc
 * producer.gw-app-02.kind=GATEWAY
 * producer.gw-app-02.keyId=tk1
 * producer.gw-app-02.keyFile=keys/telemetry/gw-app-02.key    (or keyEnv; default EASTGUARD_TELEMETRY_KEY_GW_APP_02)
 * producer.gw-app-02.listeners=app-02@127.0.0.1:9002
 * producer.gw-app-02.decoys=decoy-9003@127.0.0.1:9003
 * producer.tokensvc.kind=ISSUER
 * producer.tokensvc.listeners=*@127.0.0.1:8443
 * </pre>
 */
public final class ProducerInventory {
    public enum Kind { GATEWAY, ISSUER }

    /** Wildcard service for the issuer's listener. */
    public static final String ANY_SERVICE = "*";

    /**
     * @param listeners listener endpoint to the only service ID reported on it
     * @param decoys    decoy endpoint to its decoy ID (gateways only)
     */
    public record Producer(String id, Kind kind, String keyId, Map<Endpoint, String> listeners,
            Map<Endpoint, String> decoys) {
        public Producer {
            Ids.require(id, "producer id");
            Objects.requireNonNull(kind, "kind");
            Ids.require(keyId, "keyId");
            listeners = Map.copyOf(listeners);
            decoys = Map.copyOf(decoys);
            if (listeners.isEmpty()) {
                throw new IllegalArgumentException("producer " + id + " has no listeners");
            }
            if (kind == Kind.ISSUER && !decoys.isEmpty()) {
                throw new IllegalArgumentException("issuer " + id + " cannot have decoys");
            }
            listeners.values().forEach(s -> {
                if (!(kind == Kind.ISSUER && ANY_SERVICE.equals(s))) {
                    Ids.require(s, "listener service");
                }
            });
            decoys.values().forEach(s -> Ids.require(s, "decoy id"));
            for (Endpoint e : decoys.keySet()) {
                if (listeners.containsKey(e)) {
                    throw new IllegalArgumentException("producer " + id + ": " + e + " is both listener and decoy");
                }
            }
        }
    }

    private final Map<String, Producer> producers;
    private final Map<String, byte[]> keys; // producerId -> key; never exposed

    private ProducerInventory(Map<String, Producer> producers, Map<String, byte[]> keys) {
        this.producers = Map.copyOf(producers);
        this.keys = Map.copyOf(keys);
    }

    /** Builds an inventory; keys are copied. Rejects one endpoint claimed by two producers. */
    public static ProducerInventory of(List<Producer> list, Map<String, byte[]> keys) {
        Map<String, Producer> byId = new LinkedHashMap<>();
        Map<String, byte[]> k = new HashMap<>();
        Map<Endpoint, String> owner = new HashMap<>();
        for (Producer p : list) {
            if (byId.put(p.id(), p) != null) {
                throw new IllegalArgumentException("producer " + p.id() + " listed twice");
            }
            byte[] key = keys.get(p.id());
            if (key == null || key.length < 32) {
                throw new IllegalArgumentException("producer " + p.id() + " needs a key of at least 32 bytes");
            }
            k.put(p.id(), key.clone());
            k.put(p.id() + "/" + p.keyId(), key.clone());
            for (Endpoint e : concat(p.listeners(), p.decoys())) {
                String prev = owner.put(e, p.id());
                if (prev != null) {
                    throw new IllegalArgumentException(e + " is claimed by producers " + prev + " and " + p.id());
                }
            }
        }
        for (Map.Entry<String, byte[]> entry : keys.entrySet()) {
            if (entry.getKey().contains("/")) {
                k.put(entry.getKey(), entry.getValue().clone());
            }
        }
        return new ProducerInventory(byId, k);
    }

    private static List<Endpoint> concat(Map<Endpoint, String> a, Map<Endpoint, String> b) {
        List<Endpoint> out = new java.util.ArrayList<>(a.keySet());
        out.addAll(b.keySet());
        return out;
    }

    /** A configured producer and where its key comes from. */
    public record Spec(Producer producer, SecretSource key) {
        public Spec {
            Objects.requireNonNull(producer, "producer");
            Objects.requireNonNull(key, "key");
        }
    }

    /** Parses {@code producers} and {@code producer.<id>.*} without reading any key. */
    public static List<Spec> specs(Config c) {
        List<String> ids = c.idList("producers");
        if (ids.isEmpty()) {
            throw new IllegalArgumentException("config " + c.source() + ": producers is required");
        }
        List<Spec> out = new java.util.ArrayList<>();
        for (String id : ids) {
            String pre = "producer." + id + ".";
            Kind kind = c.enumValue(pre + "kind", Kind.class, null);
            if (kind == null) {
                throw new IllegalArgumentException("config " + c.source() + ": " + pre + "kind is required");
            }
            String keyId = c.id(pre + "keyId");
            SecretSource src = new SecretSource(c.string(pre + "keyEnv", defaultKeyEnv(id)),
                    Path.of(c.string(pre + "keyFile")));
            out.add(new Spec(new Producer(id, kind, keyId, endpoints(c, pre + "listeners", kind == Kind.ISSUER),
                    endpoints(c, pre + "decoys", false)), src));
        }
        return List.copyOf(out);
    }

    /** Reads every producer's key and builds the inventory. */
    public static ProducerInventory load(List<Spec> specs) {
        Map<String, byte[]> keys = new HashMap<>();
        try {
            for (Spec s : specs) {
                keys.put(s.producer().id(), TelemetrySender.readKey(s.key()));
            }
            return of(specs.stream().map(Spec::producer).toList(), keys);
        } finally {
            keys.values().forEach(k -> Arrays.fill(k, (byte) 0));
        }
    }

    static String defaultKeyEnv(String producerId) {
        return "EASTGUARD_TELEMETRY_KEY_" + producerId.toUpperCase(Locale.ROOT).replace('-', '_').replace('.', '_');
    }

    /** {@code service@ip:port} entries, comma-separated. */
    private static Map<Endpoint, String> endpoints(Config c, String key, boolean wildcardAllowed) {
        Map<Endpoint, String> out = new LinkedHashMap<>();
        String v = c.optional(key);
        if (v == null) {
            return out;
        }
        for (String part : v.split(",", -1)) {
            String entry = part.strip();
            int at = entry.indexOf('@');
            if (at < 1) {
                throw new IllegalArgumentException("config " + c.source() + ": " + key + " entries are service@ip:port");
            }
            String service = entry.substring(0, at);
            if (!(wildcardAllowed && ANY_SERVICE.equals(service)) && !Ids.isValid(service)) {
                throw new IllegalArgumentException("config " + c.source() + ": " + key + " has an invalid service id");
            }
            Endpoint e;
            try {
                e = Endpoint.parse(entry.substring(at + 1));
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("config " + c.source() + ": " + key + " needs numeric ip:port");
            }
            if (out.put(e, service) != null) {
                throw new IllegalArgumentException("config " + c.source() + ": " + key + " lists " + e + " twice");
            }
        }
        return out;
    }

    /** MAC key for {@code (producerId, keyId)}, or {@code null} when not trusted. The array must not be modified. */
    byte[] key(String producerId, String keyId) {
        Producer p = producers.get(producerId);
        if (p == null) {
            return null;
        }
        byte[] compound = keys.get(producerId + "/" + keyId);
        if (compound != null) {
            return compound;
        }
        return p.keyId().equals(keyId) ? keys.get(producerId) : null;
    }

    /**
     * Returns an inventory that also trusts {@code (producerId, keyId)} with {@code rawKey},
     * enabling hitless telemetry key rotation without restarting.
     */
    public ProducerInventory withKey(String producerId, String keyId, byte[] rawKey) {
        Ids.require(producerId, "producer id");
        Ids.require(keyId, "keyId");
        if (!producers.containsKey(producerId)) {
            throw new IllegalArgumentException("unknown producer " + producerId);
        }
        if (rawKey == null || rawKey.length < 32) {
            throw new IllegalArgumentException("key must be at least 32 bytes");
        }
        Map<String, byte[]> newKeys = new HashMap<>(keys);
        newKeys.put(producerId + "/" + keyId, rawKey.clone());
        return new ProducerInventory(producers, newKeys);
    }

    public Producer producer(String id) {
        return producers.get(id);
    }

    public int size() {
        return producers.size();
    }

    /** Producer-to-listener scope for an authenticated event (see the class comment). */
    public boolean inScope(Telemetry t) {
        Producer p = producers.get(t.producerId());
        if (p == null) {
            return false;
        }
        Endpoint dst = new Endpoint(t.dstIp(), t.dstPort());
        return switch (p.kind()) {
            case GATEWAY -> switch (t.verdict()) {
                case DECOY -> t.service().equals(p.decoys().get(dst)) && t.sourceIdentity() == null;
                case ALLOW -> t.sourceIdentity() != null && t.service().equals(p.listeners().get(dst));
                case DENY -> t.service().equals(p.listeners().get(dst));
            };
            case ISSUER -> {
                String s = p.listeners().get(dst);
                yield t.verdict() == eastguard.common.Verdict.DENY
                        && (t.reason() == ReasonCode.POLICY_DENY || t.reason() == ReasonCode.QUARANTINED)
                        && t.sourceIdentity() != null
                        && (ANY_SERVICE.equals(s) || t.service().equals(s));
            }
        };
    }
}
