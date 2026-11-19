package eastguard.gateway;

import eastguard.common.Bytes;
import eastguard.common.Ids;
import eastguard.common.IpAddress;
import eastguard.common.Selector;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Collection;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Gateway sessions indexed for containment (spec §4.3 last bullet, §6.2): by verified identity and by peer IP,
 * keeping the lease signing key ID and the leaf-certificate fingerprint for revocation.
 *
 * <p>A session is added as soon as it passes AUTHORIZE, i.e. while its backend connect is still pending, so a
 * slow connect cannot race past a quarantine; it stays until the connection closes.
 *
 * <p><b>Not thread-safe.</b> Owned by the gateway selector thread. Other threads never touch it: they post a
 * command to {@link NioGateway} (for example {@link NioGateway#closeMatching}), which looks sessions up here on
 * the selector thread. Sessions are compared by identity, so {@code S} need not implement {@code equals}.
 *
 * @param <S> the session handle (the gateway uses its per-connection object; tests can use any object)
 */
public final class SessionIndex<S> {
    /** What the index knows about one session. All values come from TLS and the verified lease. */
    public record Entry<S>(S session, String identity, IpAddress ip, String keyId, Bytes certSha256) {
        public Entry {
            Objects.requireNonNull(session, "session");
            Ids.require(identity, "identity");
            Objects.requireNonNull(ip, "ip");
            Ids.require(keyId, "keyId");
            Objects.requireNonNull(certSha256, "certSha256");
        }
    }

    private final Map<S, Entry<S>> entries = new IdentityHashMap<>();
    private final Map<String, Set<S>> byIdentity = new HashMap<>();
    private final Map<IpAddress, Set<S>> byIp = new HashMap<>();

    public void add(Entry<S> e) {
        if (entries.putIfAbsent(e.session(), e) != null) {
            throw new IllegalStateException("session already indexed");
        }
        byIdentity.computeIfAbsent(e.identity(), k -> newSet()).add(e.session());
        byIp.computeIfAbsent(e.ip(), k -> newSet()).add(e.session());
    }

    /** Removes the session if present; returns whether it was. */
    public boolean remove(S session) {
        Entry<S> e = entries.remove(session);
        if (e == null) {
            return false;
        }
        removeFrom(byIdentity, e.identity(), session);
        removeFrom(byIp, e.ip(), session);
        return true;
    }

    public int size() {
        return entries.size();
    }

    public boolean contains(S session) {
        return entries.containsKey(session);
    }

    /** Sessions matched by any of the selectors (identity and IP selectors are independent), each once. */
    public List<S> matching(Collection<Selector> selectors) {
        Set<S> out = newSet();
        for (Selector sel : selectors) {
            Set<S> hit = switch (sel.type()) {
                case IDENTITY -> byIdentity.get(sel.identity());
                case IP -> byIp.get(sel.ip());
            };
            if (hit != null) {
                out.addAll(hit);
            }
        }
        return new ArrayList<>(out);
    }

    /** Sessions admitted with a lease signed by {@code keyId}. Linear: revocation is rare. */
    public List<S> withKeyId(String keyId) {
        List<S> out = new ArrayList<>();
        for (Entry<S> e : entries.values()) {
            if (e.keyId().equals(keyId)) {
                out.add(e.session());
            }
        }
        return out;
    }

    /** Sessions whose TLS peer presented the leaf certificate with this SHA-256. Linear: revocation is rare. */
    public List<S> withCertificate(Bytes certSha256) {
        List<S> out = new ArrayList<>();
        for (Entry<S> e : entries.values()) {
            if (e.certSha256().equals(certSha256)) {
                out.add(e.session());
            }
        }
        return out;
    }

    public List<S> all() {
        return new ArrayList<>(entries.keySet());
    }

    private static <S> Set<S> newSet() {
        return Collections.newSetFromMap(new IdentityHashMap<>());
    }

    private static <K, S> void removeFrom(Map<K, Set<S>> map, K key, S session) {
        Set<S> set = map.get(key);
        if (set != null) {
            set.remove(session);
            if (set.isEmpty()) {
                map.remove(key);
            }
        }
    }
}
