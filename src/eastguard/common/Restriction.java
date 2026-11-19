package eastguard.common;

import java.time.Instant;
import java.util.Objects;

/**
 * Committed quarantine (spec §3.1). It stays active until the control plane commits its removal or expiry;
 * receivers never unblock on a local wall-clock timer (spec §6.2), so {@code expiry} is informational here.
 */
public record Restriction(Selector selector, ReasonCode reason, String actor, Instant start, Instant expiry,
        long revision) {
    public Restriction {
        Objects.requireNonNull(selector, "selector");
        Objects.requireNonNull(reason, "reason");
        Ids.require(actor, "actor");
        Objects.requireNonNull(start, "start");
        Objects.requireNonNull(expiry, "expiry");
        if (!expiry.isAfter(start)) {
            throw new IllegalArgumentException("expiry must be after start");
        }
        if (revision < 0) {
            throw new IllegalArgumentException("revision negative");
        }
    }
}
