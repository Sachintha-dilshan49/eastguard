package eastguard.common;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Risk step-up: caps the length of <em>newly issued</em> leases for a selector (spec §4.2). It does not affect
 * established sessions. Like restrictions, it is removed only by an authoritative snapshot.
 */
public record LeaseReduction(Selector selector, Duration maxLease, Instant expiry, long revision) {
    public LeaseReduction {
        Objects.requireNonNull(selector, "selector");
        Objects.requireNonNull(maxLease, "maxLease");
        Objects.requireNonNull(expiry, "expiry");
        Policy.requireLeaseLength(maxLease);
        if (revision < 0) {
            throw new IllegalArgumentException("revision negative");
        }
    }
}
