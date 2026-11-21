package eastguard.dashboard;

import eastguard.common.Selector;
import eastguard.control.Dto;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Rows of the alert table (spec §7.3 alerts): signal, score, trusted identity or IP, action outcome and time,
 * with committed actions and refused proposals told apart in the {@code stage} column.
 */
public final class AlertRows {
    public static final String COMMITTED = "✔ COMMITTED";
    public static final String PROPOSED = "… PROPOSED (refused)";

    /** One row; {@code target} is the trusted attribution (workload identity or IP), never a claimed name. */
    public record Row(String time, String stage, String action, String target, int score, String signals,
            String outcome) {
    }

    private AlertRows() {
    }

    /** Newest first. */
    public static List<Row> of(Dto.DashboardView d) {
        return d.alerts().stream().sorted(Comparator.comparingLong(Dto.AlertView::atMillis).reversed()).map(a -> new Row(
                Instant.ofEpochMilli(a.atMillis()).toString(),
                a.committed() ? COMMITTED : PROPOSED,
                a.action().name(),
                a.selectors().stream().map(AlertRows::target).collect(Collectors.joining(", ")),
                a.score(),
                String.join(", ", a.signals()),
                a.committed() ? "committed at revision " + a.revision() + ", expires "
                        + Instant.ofEpochMilli(a.expiresAtMillis()) : a.outcome())).toList();
    }

    static String target(Selector s) {
        return switch (s.type()) {
            case IDENTITY -> "identity " + s.identity();
            case IP -> "IP " + s.ip();
        };
    }
}
