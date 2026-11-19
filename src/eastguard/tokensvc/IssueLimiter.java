package eastguard.tokensvc;

import java.util.HashMap;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * Per-client issuance limit (spec §4.2): at most {@code perSecond} lease requests per authenticated workload
 * identity in each one-second window (fixed window, monotonic time). Only identities that passed
 * {@link eastguard.common.WorkloadIdentity} reach this, so the map is bounded by the registry size; a hard cap
 * guards against a huge registry anyway.
 */
public final class IssueLimiter {
    static final int MAX_TRACKED = 10_000;
    private static final long WINDOW_NANOS = 1_000_000_000L;

    private final int perSecond;
    private final LongSupplier nanoTime;
    /** identity -> {windowStartNanos, count}. Guarded by this. */
    private final Map<String, long[]> windows = new HashMap<>();

    public IssueLimiter(int perSecond, LongSupplier nanoTime) {
        if (perSecond < 1) {
            throw new IllegalArgumentException("perSecond must be positive");
        }
        this.perSecond = perSecond;
        this.nanoTime = nanoTime;
    }

    public synchronized boolean tryAcquire(String identity) {
        long now = nanoTime.getAsLong();
        long[] w = windows.get(identity);
        if (w != null && now - w[0] < WINDOW_NANOS) {
            if (w[1] >= perSecond) {
                return false;
            }
            w[1]++;
            return true;
        }
        if (w == null && windows.size() >= MAX_TRACKED) {
            windows.values().removeIf(x -> now - x[0] >= WINDOW_NANOS);
            if (windows.size() >= MAX_TRACKED) {
                return false; // fail closed rather than grow without bound
            }
        }
        windows.put(identity, new long[] {now, 1});
        return true;
    }
}
