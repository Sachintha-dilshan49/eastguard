package eastguard.dashboard;

import eastguard.common.IpAddress;
import eastguard.common.Ids;
import eastguard.common.Selector;
import eastguard.control.Dto;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.function.LongSupplier;
import java.util.logging.Logger;

/**
 * Dashboard actions (the C of spec §8 MVC). Runs on the UI thread; every network call goes through the one
 * {@link ConsoleWorker}, and every result comes back to the UI thread before it touches the {@link ConsoleModel}.
 *
 * <ul>
 *   <li>{@link #tick} (a Swing timer, every few hundred ms) starts a poll when one is due and none is outstanding,
 *       and marks the view STALE when the last success is older than {@code staleAfter} or the outstanding poll
 *       has run longer than that. It never blocks.</li>
 *   <li>Mutations are refused here unless the model allows them (disabled buttons are not the only guard). Each
 *       needs a reason; the view confirms it with the operator first. A transport failure is retried once with
 *       the same request ID, which the control plane answers idempotently.</li>
 *   <li>A freeze CONFLICT clears the review and reloads, so the administrator reviews the newer draft.</li>
 * </ul>
 */
public final class DashboardController {
    private static final Logger LOG = Logger.getLogger(DashboardController.class.getName());
    private static final SecureRandom RANDOM = new SecureRandom();
    static final int DASHBOARD_LIMIT = 100;

    /**
     * @param pollEvery  time between polls
     * @param staleAfter data older than this (or a poll running longer) is marked stale
     */
    public record Timing(Duration pollEvery, Duration staleAfter) {
        public Timing {
            if (pollEvery.toMillis() < 100 || staleAfter.compareTo(pollEvery) <= 0) {
                throw new IllegalArgumentException("pollEvery >= 100 ms and staleAfter > pollEvery required");
            }
        }
    }

    private final ConsoleModel model;
    private final ConsoleApi api;
    private final ConsoleWorker worker;
    private final Clock clock;
    private final LongSupplier nanos;
    private final long pollEveryNanos;
    private final long staleAfterNanos;
    private long lastPollStart = Long.MIN_VALUE;
    private long lastSuccess = Long.MIN_VALUE;
    private boolean pollDue = true;

    public DashboardController(ConsoleModel model, ConsoleApi api, ConsoleWorker worker, Clock clock,
            LongSupplier nanos, Timing timing) {
        this.model = Objects.requireNonNull(model, "model");
        this.api = Objects.requireNonNull(api, "api");
        this.worker = Objects.requireNonNull(worker, "worker");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.nanos = Objects.requireNonNull(nanos, "nanos");
        this.pollEveryNanos = timing.pollEvery().toNanos();
        this.staleAfterNanos = timing.staleAfter().toNanos();
    }

    public ConsoleModel model() {
        return model;
    }

    // ---- polling ----

    /** Called periodically on the UI thread. Never blocks. */
    public void tick() {
        long now = nanos.getAsLong();
        if (worker.pollOutstanding()) {
            if (now - lastPollStart > staleAfterNanos) {
                model.stale("control plane slow: no answer for " + seconds(now - lastPollStart) + " s");
            }
        } else if (lastSuccess != Long.MIN_VALUE && now - lastSuccess > staleAfterNanos) {
            model.stale("no successful poll for " + seconds(now - lastSuccess) + " s");
        }
        if (pollDue || lastPollStart == Long.MIN_VALUE || now - lastPollStart >= pollEveryNanos) {
            startPoll(now);
        }
    }

    /** Reload as soon as possible (after a mutation or a conflict, or on request). */
    public void refresh() {
        pollDue = true;
        tick();
    }

    private void startPoll(long now) {
        boolean started = worker.poll(() -> new ConsoleSnapshot(api.dashboard(DASHBOARD_LIMIT), api.learningDraft(),
                api.fixtureLabel(), api.deniedEdges(), clock.millis()), this::pollSucceeded, this::pollFailed);
        if (started) {
            lastPollStart = now;
            pollDue = false;
        }
    }

    private void pollSucceeded(ConsoleSnapshot s) {
        if (!s.dashboard().ok()) {
            pollFailed(new IOException(s.dashboard().error() + " " + s.dashboard().message()));
            return;
        }
        if (!s.draft().ok()) {
            pollFailed(new IOException(s.draft().error() + " " + s.draft().message()));
            return;
        }
        lastSuccess = nanos.getAsLong();
        model.connected(s);
    }

    private void pollFailed(Exception e) {
        model.disconnected("control plane unavailable: " + describe(e));
    }

    // ---- mutations ----

    /**
     * Quarantine one selector. The view has already confirmed it with the operator.
     *
     * @return {@code null} if submitted, else why not
     */
    public String quarantine(Selector selector, Duration ttl, String reason) {
        String why = model.whyNotOperate();
        if (why == null) {
            why = checkReason(reason);
        }
        if (why == null && (selector == null || ttl == null || ttl.toMillis() < 1_000)) {
            why = "a selector and a TTL of at least 1 s are required";
        }
        if (why != null) {
            return refuse(why);
        }
        String id = requestId();
        return mutate("quarantine " + selector, () -> retryOnce(() -> api.quarantine(id, List.of(selector), ttl, reason)));
    }

    /** Release one selector (confirmed by the view). */
    public String release(Selector selector, String reason) {
        String why = model.whyNotOperate();
        if (why == null) {
            why = checkReason(reason);
        }
        if (why == null && selector == null) {
            why = "select a restriction to release";
        }
        if (why != null) {
            return refuse(why);
        }
        String id = requestId();
        return mutate("release " + selector, () -> retryOnce(() -> api.release(id, List.of(selector), reason)));
    }

    /** Freeze exactly the reviewed edge set at the review's versions (confirmed by the view with the diff). */
    public String freeze(String reason) {
        String why = model.whyNotFreeze();
        if (why == null) {
            why = checkReason(reason);
        }
        if (why != null) {
            return refuse(why);
        }
        ConsoleModel.Review r = model.review();
        String id = requestId();
        return mutate("freeze " + r.diff(), () -> retryOnce(() -> api.freeze(id, r.base().policyRevision(),
                r.base().draftVersion(), r.edges(), reason)));
    }

    public void startReview() {
        model.startReview();
    }

    public void setReviewed(eastguard.common.Edge e, boolean included) {
        model.setReviewed(e, included);
    }

    private String mutate(String what, Callable<Dto.MutationResult> call) {
        model.mutationStarted(what);
        boolean queued = worker.submit(call, r -> finished(what, r), e -> {
            model.mutationFinished(what + ": no reply (" + describe(e) + "). It may have committed: check the audit.");
            refresh();
        });
        if (!queued) {
            model.mutationFinished(what + ": not sent, the console is busy");
            return "busy";
        }
        return null;
    }

    private void finished(String what, Dto.MutationResult r) {
        if (r.ok()) {
            model.mutationFinished(what + ": committed at revision " + r.revision() + (r.replayed() ? " (retry)" : ""));
            if (what.startsWith("freeze")) {
                model.clearReview();
            }
        } else if (r.error() == Dto.ErrorCode.CONFLICT && what.startsWith("freeze")) {
            model.clearReview();
            model.mutationFinished(what + ": CONFLICT, " + r.message() + ". Reloaded: review the new draft.");
        } else {
            model.mutationFinished(what + ": " + r.error() + " " + r.message());
        }
        refresh();
    }

    /** One retry after a transport failure, with the same request ID (the control plane deduplicates it). */
    private static Dto.MutationResult retryOnce(Callable<Dto.MutationResult> call) throws Exception {
        try {
            return call.call();
        } catch (IOException first) {
            LOG.fine("mutation reply lost; retrying once with the same request ID");
            return call.call();
        }
    }

    private String refuse(String why) {
        model.message("not sent: " + why);
        return why;
    }

    // ---- validation helpers (shared with the views) ----

    /** {@code null} if the reason is acceptable to the control plane (1..200 printable ASCII). */
    public static String checkReason(String reason) {
        if (reason == null || reason.isBlank()) {
            return "a reason is required";
        }
        if (reason.length() > 200) {
            return "the reason must be at most 200 characters";
        }
        for (int i = 0; i < reason.length(); i++) {
            char c = reason.charAt(i);
            if (c < 0x20 || c > 0x7e) {
                return "the reason must be printable ASCII";
            }
        }
        return null;
    }

    /** Parses a typed selector from the quarantine form, or throws {@link IllegalArgumentException}. */
    public static Selector selector(eastguard.common.SelectorType type, String value) {
        String v = value == null ? "" : value.strip();
        return switch (type) {
            case IDENTITY -> {
                if (!Ids.isValid(v)) {
                    throw new IllegalArgumentException("not a valid workload identity");
                }
                yield Selector.identity(v);
            }
            case IP -> Selector.ip(IpAddress.parse(v));
        };
    }

    private static String requestId() {
        byte[] b = new byte[8];
        RANDOM.nextBytes(b);
        return "console-" + HexFormat.of().formatHex(b);
    }

    private static long seconds(long nanos) {
        return Math.max(0, nanos / 1_000_000_000L);
    }

    private static String describe(Exception e) {
        String m = e.getMessage();
        return e.getClass().getSimpleName() + (m == null ? "" : ": " + (m.length() > 120 ? m.substring(0, 120) : m));
    }
}
