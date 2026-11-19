package eastguard.common;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/**
 * Signed control notice (spec §5.4). Times are Unix milliseconds as on the wire.
 *
 * @param expiresAtMs absolute quarantine deadline (after {@code sentAtMs}) for QUARANTINE; exactly zero for
 *                    RELEASE. Informational for receivers: only an authoritative snapshot ever unblocks.
 * @param selectors   1..8 distinct selectors
 */
public record Notice(String cluster, String keyId, long revision, long sentAtMs, Bytes nonce,
        NoticeOperation operation, long expiresAtMs, List<Selector> selectors, ReasonCode reason) {

    public static final int NONCE_LENGTH = 16;
    public static final int MAX_SELECTORS = 8;

    public Notice {
        Ids.require(cluster, "cluster");
        Ids.require(keyId, "keyId");
        if (revision < 0 || sentAtMs < 0) {
            throw new IllegalArgumentException("revision and sentAt must be nonnegative");
        }
        Objects.requireNonNull(nonce, "nonce").requireLength(NONCE_LENGTH, "nonce");
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(reason, "reason");
        selectors = List.copyOf(Objects.requireNonNull(selectors, "selectors"));
        if (selectors.isEmpty() || selectors.size() > MAX_SELECTORS) {
            throw new IllegalArgumentException("notice needs 1..8 selectors");
        }
        if (new HashSet<>(selectors).size() != selectors.size()) {
            throw new IllegalArgumentException("duplicate selector");
        }
        switch (operation) {
            case QUARANTINE -> {
                if (expiresAtMs <= sentAtMs) {
                    throw new IllegalArgumentException("quarantine must expire after it was sent");
                }
            }
            case RELEASE -> {
                if (expiresAtMs != 0) {
                    throw new IllegalArgumentException("release must have expiresAt = 0");
                }
            }
        }
    }
}
