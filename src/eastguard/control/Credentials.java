package eastguard.control;

import eastguard.common.Bytes;
import eastguard.common.Config;
import eastguard.common.Ids;
import eastguard.common.Sha256;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Per-principal API credentials (spec §7.1), stored as SHA-256 digests of high-entropy random secrets.
 * Provisioned by {@code scripts/gen-credentials.ps1} into a git-ignored file:
 *
 * <pre>
 * principals=admin,operator,gw-app-02
 * principal.admin.role=ADMIN
 * principal.admin.sha256=&lt;hex&gt;[,&lt;hex&gt;]       several digests during a rotation overlap
 * principal.admin.enabled=true                 false revokes the principal
 * </pre>
 *
 * A plain hash suffices because the secrets are 32 random bytes, not passwords. Comparison is constant-time.
 * Neither secrets nor digests are ever logged.
 */
public final class Credentials {
    public static final int MIN_SECRET = 16;
    public static final int MAX_SECRET = 64;

    public record Principal(String id, Role role, List<Bytes> digests, boolean enabled) {
        public Principal {
            Ids.require(id, "principal");
            Objects.requireNonNull(role, "role");
            if (role == Role.SYSTEM) {
                throw new IllegalArgumentException("SYSTEM cannot be assigned to a credential");
            }
            digests = List.copyOf(digests);
            if (digests.isEmpty()) {
                throw new IllegalArgumentException("principal " + id + " has no credential digest");
            }
            digests.forEach(d -> d.requireLength(Sha256.LENGTH, "credential digest"));
        }

        /** A principal whose single credential is {@code secret} (for provisioning and tests). */
        public static Principal withSecret(String id, Role role, Bytes secret) {
            return new Principal(id, role, List.of(Sha256.digest(secret.toArray())), true);
        }
    }

    private final Map<String, Principal> principals;

    private Credentials(Map<String, Principal> principals) {
        this.principals = Map.copyOf(principals);
    }

    public static Credentials of(List<Principal> list) {
        Map<String, Principal> m = new java.util.HashMap<>();
        for (Principal p : list) {
            if (m.put(p.id(), p) != null) {
                throw new IllegalArgumentException("principal " + p.id() + " listed twice");
            }
        }
        return new Credentials(m);
    }

    public static Credentials load(Path file) {
        Config c = Config.load(file);
        List<Principal> list = new ArrayList<>();
        for (String id : c.idList("principals")) {
            String p = "principal." + id + ".";
            Role role = c.enumValue(p + "role", Role.class, null);
            if (role == null) {
                throw new IllegalArgumentException("config " + c.source() + ": " + p + "role is required");
            }
            List<Bytes> digests = new ArrayList<>();
            for (String hex : c.string(p + "sha256").split(",", -1)) {
                try {
                    digests.add(Bytes.copyOf(HexFormat.of().parseHex(hex.strip())));
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("config " + c.source() + ": " + p + "sha256 must be hex");
                }
            }
            list.add(new Principal(id, role, digests, c.bool(p + "enabled", true)));
        }
        c.requireNoUnknownKeys();
        return of(list);
    }

    /** The caller's role if the credential is valid and enabled, else {@code null}. */
    public Role authenticate(Dto.Credential credential) {
        if (credential == null || credential.secret() == null || !Ids.isValid(credential.principal())
                || credential.secret().length() < MIN_SECRET || credential.secret().length() > MAX_SECRET) {
            return null;
        }
        Bytes presented = Sha256.digest(credential.secret().toArray());
        Principal p = principals.get(credential.principal());
        if (p == null) {
            return null;
        }
        boolean match = false;
        for (Bytes d : p.digests()) {
            match |= MessageDigest.isEqual(d.toArray(), presented.toArray());
        }
        return match && p.enabled() ? p.role() : null;
    }

    public int size() {
        return principals.size();
    }
}
