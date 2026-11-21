package eastguard.common;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Binary form of an {@link EnforcementSnapshot}: what a control-plane sync carries and what the journal's
 * bootstrap record stores. Big-endian, spec §5 primitives, no Java serialization. Collections are written in a
 * fixed order so equal snapshots encode to equal bytes. Decoding validates every value through the domain
 * constructors and rejects trailing bytes, so a decoded snapshot is as trustworthy as one built in-process.
 *
 * <pre>
 * "EGS2" | cluster:id | revision:i64
 * | mode:u8 | policyRevision:i64 | defaultLeaseMs:i64 | n:u16 (source:id service:id)*
 * | n:u16 pilotSource:id* | n:u16 pilotService:id*
 * | n:u16 (id enabled:u8 hasZone:u8 [ip prefix:u8] n:u16 revokedLeaf:32*)*            workloads
 * | n:u16 (id gateway:id listenIp:ip port:u16 serverName:text backendIp:ip port:u16)*   services
 * | n:u16 (selector reason:u8 actor:id startMs:i64 expiryMs:i64 revision:i64)*          restrictions
 * | n:u16 (selector maxLeaseMs:i64 expiryMs:i64 revision:i64)*                           lease reductions
 * | n:u16 (selector minTokenRevision:i64)*                                               release watermarks
 * | n:u16 (keyId:id ed25519:32)*                                                         token keys
 * | n:u16 keyId:id*                                                                      revoked key IDs
 * | n:u16 (keyId:id ed25519:32)*                                                         control (notice) keys
 * </pre>
 */
public final class SnapshotCodec {
    /** "EGS2" since Task 8 added the control keys; an "EGS1" (older) journal must be re-bootstrapped. */
    public static final String MAGIC = "EGS2";
    public static final int MAX_SIZE = 1 << 20;
    private static final int MAX_COUNT = 65_535;
    private static final Comparator<Selector> BY_SELECTOR = Comparator.comparing(Selector::toString);

    private SnapshotCodec() {
    }

    public static byte[] encode(EnforcementSnapshot s) {
        WireWriter w = new WireWriter(1_024).ascii(MAGIC).id(s.clusterId()).nonNegative(s.revision(), "revision");
        Policy p = s.policy();
        w.u8(modeCode(p.mode())).nonNegative(p.revision(), "policyRevision").i64(p.defaultLeaseLength().toMillis());
        List<Edge> edges = new ArrayList<>(p.approvedEdges());
        edges.sort(Comparator.comparing(Edge::toString));
        w.u16(edges.size());
        for (Edge e : edges) {
            w.id(e.sourceIdentity()).id(e.serviceId());
        }
        ids(w, p.pilotScope().sourceIdentities());
        ids(w, p.pilotScope().serviceIds());

        w.u16(s.workloads().size());
        for (Workload wl : sorted(s.workloads())) {
            w.id(wl.id()).bool(wl.enabled()).bool(wl.ipZone() != null);
            if (wl.ipZone() != null) {
                w.ip(wl.ipZone().network()).u8(wl.ipZone().prefixLength());
            }
            List<Bytes> revoked = new ArrayList<>(wl.revokedCertificates());
            revoked.sort(Comparator.comparing(Bytes::hex));
            w.u16(revoked.size());
            revoked.forEach(b -> w.fixed(b, Sha256.LENGTH, "revoked leaf"));
        }

        w.u16(s.services().size());
        for (Service sv : sorted(s.services())) {
            w.id(sv.id()).id(sv.gatewayId()).ip(sv.listener().ip()).u16(sv.listener().port()).text(sv.tlsServerName())
                    .ip(sv.backend().ip()).u16(sv.backend().port());
        }

        List<Restriction> restrictions = new ArrayList<>(s.restrictions());
        restrictions.sort(Comparator.comparing(Restriction::selector, BY_SELECTOR));
        w.u16(restrictions.size());
        for (Restriction r : restrictions) {
            w.selector(r.selector()).u8(r.reason().code()).id(r.actor()).nonNegative(r.start().toEpochMilli(), "start")
                    .nonNegative(r.expiry().toEpochMilli(), "expiry").nonNegative(r.revision(), "revision");
        }

        List<LeaseReduction> reductions = new ArrayList<>(s.leaseReductions());
        reductions.sort(Comparator.comparing(LeaseReduction::selector, BY_SELECTOR));
        w.u16(reductions.size());
        for (LeaseReduction r : reductions) {
            w.selector(r.selector()).i64(r.maxLease().toMillis()).nonNegative(r.expiry().toEpochMilli(), "expiry")
                    .nonNegative(r.revision(), "revision");
        }

        List<Selector> marked = new ArrayList<>(s.releaseWatermarks().keySet());
        marked.sort(BY_SELECTOR);
        w.u16(marked.size());
        for (Selector sel : marked) {
            w.selector(sel).nonNegative(s.releaseWatermarks().get(sel), "watermark");
        }

        List<String> keyIds = new ArrayList<>(s.tokenKeys().keySet());
        keyIds.sort(null);
        w.u16(keyIds.size());
        for (String k : keyIds) {
            w.id(k).raw(Ed25519.rawPublicKey(s.tokenKeys().get(k)));
        }
        ids(w, s.revokedKeyIds());
        List<String> controlIds = new ArrayList<>(s.controlKeys().keySet());
        controlIds.sort(null);
        w.u16(controlIds.size());
        for (String k : controlIds) {
            w.id(k).raw(Ed25519.rawPublicKey(s.controlKeys().get(k)));
        }
        if (w.size() > MAX_SIZE) {
            throw new IllegalArgumentException("snapshot exceeds " + MAX_SIZE + " bytes");
        }
        return w.toByteArray();
    }

    public static EnforcementSnapshot decode(byte[] bytes) throws CodecException {
        if (bytes.length > MAX_SIZE) {
            throw new CodecException("snapshot too large");
        }
        WireReader r = new WireReader(bytes);
        try {
            r.magic(MAGIC);
            String cluster = r.id();
            long revision = r.nonNegative("revision");
            PolicyMode mode = mode(r.u8());
            long policyRevision = r.nonNegative("policyRevision");
            Duration lease = Duration.ofMillis(r.i64());
            Set<Edge> edges = new HashSet<>();
            for (int i = r.count(MAX_COUNT); i > 0; i--) {
                if (!edges.add(new Edge(r.id(), r.id()))) {
                    throw new CodecException("duplicate edge");
                }
            }
            PilotScope pilot = new PilotScope(readIds(r), readIds(r));
            Policy policy = new Policy(mode, edges, pilot, policyRevision, lease);

            Map<String, Workload> workloads = new HashMap<>();
            for (int i = r.count(MAX_COUNT); i > 0; i--) {
                String id = r.id();
                boolean enabled = r.bool();
                Cidr zone = r.bool() ? Cidr.of(r.ip(), r.u8()) : null;
                Set<Bytes> revoked = new HashSet<>();
                for (int j = r.count(MAX_COUNT); j > 0; j--) {
                    revoked.add(r.fixed(Sha256.LENGTH));
                }
                put(workloads, id, new Workload(id, enabled, revoked, zone));
            }

            Map<String, Service> services = new HashMap<>();
            for (int i = r.count(MAX_COUNT); i > 0; i--) {
                String id = r.id();
                String gw = r.id();
                Endpoint listener = new Endpoint(r.ip(), r.u16());
                String serverName = r.text(253);
                Endpoint backend = new Endpoint(r.ip(), r.u16());
                put(services, id, new Service(id, gw, listener, serverName, backend));
            }

            List<Restriction> restrictions = new ArrayList<>();
            for (int i = r.count(MAX_COUNT); i > 0; i--) {
                restrictions.add(new Restriction(r.selector(), ReasonCode.fromCode(r.u8()), r.id(),
                        Instant.ofEpochMilli(r.nonNegative("start")), Instant.ofEpochMilli(r.nonNegative("expiry")),
                        r.nonNegative("revision")));
            }
            List<LeaseReduction> reductions = new ArrayList<>();
            for (int i = r.count(MAX_COUNT); i > 0; i--) {
                reductions.add(new LeaseReduction(r.selector(), Duration.ofMillis(r.i64()),
                        Instant.ofEpochMilli(r.nonNegative("expiry")), r.nonNegative("revision")));
            }
            Map<Selector, Long> watermarks = new HashMap<>();
            for (int i = r.count(MAX_COUNT); i > 0; i--) {
                if (watermarks.put(r.selector(), r.nonNegative("watermark")) != null) {
                    throw new CodecException("duplicate watermark");
                }
            }
            Map<String, PublicKey> keys = new HashMap<>();
            for (int i = r.count(MAX_COUNT); i > 0; i--) {
                put(keys, r.id(), Ed25519.publicKeyFromRaw(r.raw(Ed25519.KEY_LENGTH)));
            }
            Set<String> revokedKeys = readIds(r);
            Map<String, PublicKey> controlKeys = new HashMap<>();
            for (int i = r.count(MAX_COUNT); i > 0; i--) {
                put(controlKeys, r.id(), Ed25519.publicKeyFromRaw(r.raw(Ed25519.KEY_LENGTH)));
            }
            r.end();
            return new EnforcementSnapshot(cluster, revision, policy, workloads, services, restrictions, reductions,
                    watermarks, keys, revokedKeys, controlKeys);
        } catch (IllegalArgumentException | ArithmeticException e) {
            throw new CodecException("invalid snapshot: " + e.getMessage());
        }
    }

    private static void ids(WireWriter w, Set<String> ids) {
        List<String> list = new ArrayList<>(ids);
        list.sort(null);
        w.u16(list.size());
        list.forEach(w::id);
    }

    private static Set<String> readIds(WireReader r) throws CodecException {
        Set<String> out = new HashSet<>();
        for (int i = r.count(MAX_COUNT); i > 0; i--) {
            if (!out.add(r.id())) {
                throw new CodecException("duplicate id");
            }
        }
        return out;
    }

    private static <V> List<V> sorted(Map<String, V> m) {
        List<String> keys = new ArrayList<>(m.keySet());
        keys.sort(null);
        List<V> out = new ArrayList<>(keys.size());
        keys.forEach(k -> out.add(m.get(k)));
        return out;
    }

    private static <V> void put(Map<String, V> m, String key, V value) throws CodecException {
        if (m.put(key, value) != null) {
            throw new CodecException("duplicate entry");
        }
    }

    public static int modeCode(PolicyMode m) {
        return switch (m) {
            case ENFORCE -> 1;
            case LEARN -> 2;
        };
    }

    public static PolicyMode mode(int code) throws CodecException {
        return switch (code) {
            case 1 -> PolicyMode.ENFORCE;
            case 2 -> PolicyMode.LEARN;
            default -> throw new CodecException("unknown policy mode");
        };
    }
}
