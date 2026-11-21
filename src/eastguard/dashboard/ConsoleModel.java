package eastguard.dashboard;

import eastguard.common.Edge;
import eastguard.control.Dto;
import eastguard.control.EdgeDiff;
import eastguard.control.Role;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BooleanSupplier;

/**
 * Dashboard state (the M of spec §8 MVC). Changed only on the UI thread (checked on every change: in the
 * application that is the EDT), so views read it without locks. Views observe it through {@link #onChange}.
 *
 * <ul>
 *   <li><b>Connection</b>: {@link Connection#CONNECTED} only after a successful poll and until the controller
 *       decides the data is too old or a poll is too slow ({@link Connection#STALE}), or a poll fails
 *       ({@link Connection#DISCONNECTED}). The last good data stays visible in both cases, explicitly marked.</li>
 *   <li><b>Permissions</b>: mutations are enabled only while CONNECTED, with no other mutation in flight, and for
 *       the role the control plane reported for this console's credential. The server authorizes anyway.</li>
 *   <li><b>Review</b>: the freeze preview works on a copy of the draft taken at one policy revision and draft
 *       version. A newer draft marks the review outdated; a CONFLICT clears it.</li>
 * </ul>
 */
public final class ConsoleModel {
    public enum Connection { CONNECTING, CONNECTED, STALE, DISCONNECTED }

    /**
     * The edge set an administrator is reviewing, pinned to the versions it was taken from.
     *
     * @param base     the draft the review started from
     * @param reviewed the edges currently included (the complete proposed allow-list)
     */
    public record Review(Dto.LearningDraftView base, Set<Edge> reviewed) {
        public Review {
            Objects.requireNonNull(base, "base");
            reviewed = Set.copyOf(reviewed);
        }

        public EdgeDiff diff() {
            return EdgeDiff.of(base.approved(), reviewed);
        }

        /** The reviewed edges in submission order. */
        public List<Edge> edges() {
            return reviewed.stream().sorted(Dto.EDGE_ORDER).toList();
        }
    }

    private final BooleanSupplier onUiThread;
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private Connection connection = Connection.CONNECTING;
    private String connectionDetail = "connecting to the control plane";
    private ConsoleSnapshot data;
    private boolean mutationInFlight;
    private String lastAction = "";
    private Review review;
    private boolean reviewOutdated;

    /** @param onUiThread true on the thread allowed to change the model ({@code SwingUtilities::isEventDispatchThread}) */
    public ConsoleModel(BooleanSupplier onUiThread) {
        this.onUiThread = Objects.requireNonNull(onUiThread, "onUiThread");
    }

    public void onChange(Runnable listener) {
        listeners.add(Objects.requireNonNull(listener, "listener"));
    }

    private void changed() {
        listeners.forEach(Runnable::run);
    }

    private void requireUi() {
        if (!onUiThread.getAsBoolean()) {
            throw new IllegalStateException("the console model is changed only on the UI thread");
        }
    }

    // ---- reads (UI thread) ----

    public Connection connection() {
        return connection;
    }

    public String connectionDetail() {
        return connectionDetail;
    }

    /** The last good data, or {@code null} before the first successful poll. */
    public ConsoleSnapshot data() {
        return data;
    }

    /** True whenever what is shown may not be current: anything but CONNECTED. */
    public boolean stale() {
        return connection != Connection.CONNECTED;
    }

    public boolean mutationInFlight() {
        return mutationInFlight;
    }

    public String lastAction() {
        return lastAction;
    }

    public Review review() {
        return review;
    }

    public boolean reviewOutdated() {
        return reviewOutdated;
    }

    /** The role the control plane reported, or {@code null} before the first poll. */
    public Role role() {
        return data == null ? null : data.dashboard().role();
    }

    public boolean demo() {
        return data != null && data.fixture() != null;
    }

    /** Quarantine and release: OPERATOR or ADMIN, live and connected, nothing else in flight. */
    public boolean canOperate() {
        return whyNotOperate() == null;
    }

    /** Freeze: ADMIN, live and connected, nothing else in flight, a current review. */
    public boolean canFreeze() {
        return whyNotFreeze() == null;
    }

    /** Why quarantine/release are disabled, or {@code null}. */
    public String whyNotOperate() {
        String common = whyNotMutate();
        if (common != null) {
            return common;
        }
        Role r = role();
        return r == Role.OPERATOR || r == Role.ADMIN ? null : "role " + r + " may not quarantine or release";
    }

    /** Why freeze is disabled, or {@code null}. */
    public String whyNotFreeze() {
        String common = whyNotMutate();
        if (common != null) {
            return common;
        }
        if (role() != Role.ADMIN) {
            return "role " + role() + " may not freeze a baseline (ADMIN only)";
        }
        if (review == null) {
            return "start a review first";
        }
        return reviewOutdated ? "the draft or policy changed since this review: reload and review again" : null;
    }

    private String whyNotMutate() {
        if (connection != Connection.CONNECTED) {
            return "disconnected or stale: edits are disabled";
        }
        if (demo()) {
            return "demo fixtures are read-only";
        }
        return mutationInFlight ? "another change is in flight" : null;
    }

    // ---- changes (UI thread) ----

    void connected(ConsoleSnapshot snapshot) {
        requireUi();
        data = Objects.requireNonNull(snapshot, "snapshot");
        connection = Connection.CONNECTED;
        connectionDetail = snapshot.fixture() != null ? "demo fixture: " + snapshot.fixture()
                : "connected; revision " + snapshot.dashboard().revision();
        if (review != null && !reviewOutdated && (snapshot.draft().draftVersion() != review.base().draftVersion()
                || snapshot.draft().policyRevision() != review.base().policyRevision())) {
            reviewOutdated = true;
        }
        changed();
    }

    void stale(String why) {
        requireUi();
        if (connection == Connection.CONNECTED || connection == Connection.CONNECTING) {
            connection = Connection.STALE;
            connectionDetail = why;
            changed();
        }
    }

    void disconnected(String why) {
        requireUi();
        connection = Connection.DISCONNECTED;
        connectionDetail = why;
        changed();
    }

    void mutationStarted(String what) {
        requireUi();
        mutationInFlight = true;
        lastAction = what + " ...";
        changed();
    }

    void mutationFinished(String outcome) {
        requireUi();
        mutationInFlight = false;
        lastAction = outcome;
        changed();
    }

    void message(String text) {
        requireUi();
        lastAction = text;
        changed();
    }

    /** Starts a review of the current draft with every candidate included. */
    void startReview() {
        requireUi();
        if (data == null) {
            return;
        }
        review = new Review(data.draft(), new LinkedHashSet<>(data.draft().proposedBaseline()));
        reviewOutdated = false;
        changed();
    }

    /** Includes or excludes one edge of the review (an approved edge or a candidate of the review's draft). */
    void setReviewed(Edge e, boolean included) {
        requireUi();
        if (review == null) {
            return;
        }
        Set<Edge> next = new LinkedHashSet<>(review.reviewed());
        if (included && review.base().proposedBaseline().contains(e)) {
            next.add(e);
        } else if (!included) {
            next.remove(e);
        }
        review = new Review(review.base(), next);
        changed();
    }

    void clearReview() {
        requireUi();
        review = null;
        reviewOutdated = false;
        changed();
    }

    /** Edges of the review's draft in display order, for the editor's check list. */
    public List<Edge> reviewChoices() {
        return review == null ? List.of() : new ArrayList<>(review.base().proposedBaseline());
    }
}
