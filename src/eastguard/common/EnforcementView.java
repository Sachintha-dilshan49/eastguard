package eastguard.common;

import java.util.Objects;
import java.util.Set;

/**
 * What an enforcement point currently knows, as handed to {@link PolicyEvaluator} (spec §6.2).
 *
 * @param snapshot            last authoritative snapshot, or {@code null} before the first successful sync
 * @param fresh               true only while the freshness deadline (computed by the caller with monotonic
 *                            time, at most 5 s from the start of the last successful sync) has not passed
 * @param newestKnownRevision highest revision seen in a verified notice; above the snapshot means "catching up"
 * @param overlay             selectors quarantined by verified notices not yet covered by the snapshot
 */
public record EnforcementView(EnforcementSnapshot snapshot, boolean fresh, long newestKnownRevision,
        Set<Selector> overlay) {

    public static final EnforcementView NOT_READY = new EnforcementView(null, false, 0, Set.of());

    public EnforcementView {
        overlay = Set.copyOf(Objects.requireNonNull(overlay, "overlay"));
        if (newestKnownRevision < 0) {
            throw new IllegalArgumentException("revision negative");
        }
    }

    /** A fresh view of {@code snapshot} with no pending notices. */
    public static EnforcementView fresh(EnforcementSnapshot snapshot) {
        return new EnforcementView(Objects.requireNonNull(snapshot), true, snapshot.revision(), Set.of());
    }

    /** Usable means: synced at least once and still inside the freshness window. */
    public boolean usable() {
        return snapshot != null && fresh;
    }

    public boolean catchingUp() {
        return snapshot != null && newestKnownRevision > snapshot.revision();
    }
}
