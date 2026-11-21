package eastguard.dashboard;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * Alert view (spec §7.3): signal, score, trusted identity or IP, action outcome and time. The Stage column says
 * in words whether the control plane <b>committed</b> the action or <b>refused</b> the detector's proposal; a
 * committed row is also bold, so colour is not the only cue.
 */
final class AlertTable extends JPanel {
    private static final long serialVersionUID = 1L;
    private final transient ConsoleModel model;
    private final RowTableModel<AlertRows.Row> rows = new RowTableModel<>(new String[] {"Time (UTC)", "Stage", "Action",
            "Trusted identity / IP", "Score", "Signals", "Outcome"}, (r, c) -> switch (c) {
                case 0 -> r.time();
                case 1 -> r.stage();
                case 2 -> r.action();
                case 3 -> r.target();
                case 4 -> r.score();
                case 5 -> r.signals();
                default -> r.outcome();
            });
    private final JLabel note = new JLabel();

    AlertTable(ConsoleModel model) {
        super(new BorderLayout());
        this.model = model;
        JTable table = new JTable(rows);
        table.setAutoCreateRowSorter(true);
        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            private static final long serialVersionUID = 1L;

            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, v, sel, focus, row, col);
                AlertRows.Row r = rows.row(t.convertRowIndexToModel(row));
                boolean committed = r != null && AlertRows.COMMITTED.equals(r.stage());
                c.setFont(c.getFont().deriveFont(committed ? Font.BOLD : Font.PLAIN));
                if (!sel) {
                    c.setBackground(committed ? new Color(0xfff3e0) : Color.WHITE);
                }
                return c;
            }
        });
        note.setText("Committed: the control plane journaled the action. Proposed (refused): the detector asked and the"
                + " control plane said no (alert-only, ineligible, conflicting or over the limit).");
        add(note, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
        model.onChange(this::refresh);
    }

    private void refresh() {
        ConsoleSnapshot d = model.data();
        rows.setRows(d == null ? java.util.List.of() : AlertRows.of(d.dashboard()));
    }
}
