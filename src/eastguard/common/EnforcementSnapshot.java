package eastguard.common;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable authoritative state installed by the token service and gateways (spec §3.1, §6.2). Everything an
 * enforcement decision needs is in here, so {@link PolicyEvaluator} stays a pure function of it.
 *
 * @param revision          enforcement revision; separate from the learning-draft version
 * @param restrictions      active quarantines; removed only by a newer snapshot
 * @param releaseWatermarks per released selector: leases with {@code issuedAtRevision} below this are rejected
 * @param tokenKeys         lease verification keys by key ID (public keys only)
 * @param revokedKeyIds     signing keys revoked in an emergency; leases signed by them are rejected
 */
public record EnforcementSnapshot(
        String clusterId,
        long revision,
        Policy policy,
        Map<String, Workload> workloads,
        Map<String, Service> services,
        List<Restriction> restrictions,
        List<LeaseReduction> leaseReductions,
        Map<Selector, Long> releaseWatermarks,
        Map<String, PublicKey> tokenKeys,
        Set<String> revokedKeyIds) {

    public EnforcementSnapshot {
        Ids.require(clusterId, "clusterId");
        if (revision < 0) {
            throw new IllegalArgumentException("revision negative");
        }
        Objects.requireNonNull(policy, "policy");
        workloads = Map.copyOf(Objects.requireNonNull(workloads, "workloads"));
        services = Map.copyOf(Objects.requireNonNull(services, "services"));
        restrictions = List.copyOf(Objects.requireNonNull(restrictions, "restrictions"));
        leaseReductions = List.copyOf(Objects.requireNonNull(leaseReductions, "leaseReductions"));
        releaseWatermarks = Map.copyOf(Objects.requireNonNull(releaseWatermarks, "releaseWatermarks"));
        tokenKeys = Map.copyOf(Objects.requireNonNull(tokenKeys, "tokenKeys"));
        revokedKeyIds = Set.copyOf(Objects.requireNonNull(revokedKeyIds, "revokedKeyIds"));

        if (policy.revision() > revision) {
            throw new IllegalArgumentException("policy newer than snapshot");
        }
        workloads.forEach((k, w) -> requireKey(k, w.id(), "workload"));
        services.forEach((k, s) -> requireKey(k, s.id(), "service"));
        for (Restriction r : restrictions) {
            requireNotNewer(r.revision(), revision, "restriction");
        }
        for (LeaseReduction r : leaseReductions) {
            requireNotNewer(r.revision(), revision, "lease reduction");
        }
        releaseWatermarks.forEach((sel, wm) -> {
            if (wm < 0) {
                throw new IllegalArgumentException("watermark negative");
            }
            requireNotNewer(wm, revision, "watermark");
        });
        tokenKeys.forEach((id, key) -> {
            Ids.require(id, "key id");
            if (!Ed25519.ALGORITHM.equals(key.getAlgorithm()) && !"EdDSA".equals(key.getAlgorithm())) {
                throw new IllegalArgumentException("token key is not Ed25519");
            }
        });
        revokedKeyIds.forEach(id -> Ids.require(id, "revoked key id"));
    }

    private static void requireKey(String key, String id, String what) {
        if (!key.equals(id)) {
            throw new IllegalArgumentException(what + " map key does not match id");
        }
    }

    private static void requireNotNewer(long rev, long snapshotRevision, String what) {
        if (rev > snapshotRevision) {
            throw new IllegalArgumentException(what + " revision newer than snapshot");
        }
    }

    /** Usable verification key, or {@code null} if the key ID is unknown or revoked. */
    public PublicKey verificationKey(String keyId) {
        return revokedKeyIds.contains(keyId) ? null : tokenKeys.get(keyId);
    }
}
