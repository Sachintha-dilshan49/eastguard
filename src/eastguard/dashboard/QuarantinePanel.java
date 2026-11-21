package eastguard.dashboard;

import eastguard.common.Selector;
import eastguard.common.SelectorType;
import eastguard.control.Dto;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SpinnerNumberModel;

/**
 * Quarantine panel (spec §7.3): active restrictions with selector type, reason, expiry and overlapping
 * restrictions (others committed by the same action); a form to quarantine one typed selector and a release of
 * the selected one. Both need a reason and a confirmation. For a quarantined identity it lists the services the
 * <em>policy</em> allows it to reach, labeled as its potential blast radius, never as observed compromise.
 */
final class QuarantinePanel extends JPanel {
    private static final long serialVersionUID = 1L;
    private final transient ConsoleModel model;
    private final transient DashboardController controller;
    private final RowTableModel<Dto.RestrictionView> rows;
    private final JTable table;
    private final JComboBox<SelectorType> type = new JComboBox<>(SelectorType.values());
    private final JTextField value = new JTextField(16);
    private final JSpinner ttlMinutes = new JSpinner(new SpinnerNumberModel(5, 1, 24 * 60, 1));
    private final JTextField reason = new JTextField(30);
    private final JButton quarantine = new JButton("Quarantine...");
    private final JButton release = new JButton("Release selected...");
    private final JLabel why = new JLabel();
    private final JTextArea blast = new JTextArea(5, 60);
    private transient List<Dto.RestrictionView> current = List.of();

    QuarantinePanel(ConsoleModel model, DashboardController controller) {
        super(new BorderLayout(6, 6));
        this.model = model;
        this.controller = controller;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        rows = new RowTableModel<>(new String[] {"Selector type", "Selector", "Reason", "Actor", "Started (UTC)",
                "Expires (UTC)", "Revision", "Overlapping restrictions"}, (r, c) -> switch (c) {
                    case 0 -> r.selector().type().name();
                    case 1 -> r.selector().type() == SelectorType.IDENTITY ? r.selector().identity() : r.selector().ip().toString();
                    case 2 -> r.reason();
                    case 3 -> r.actor();
                    case 4 -> Instant.ofEpochMilli(r.startMillis()).toString();
                    case 5 -> Instant.ofEpochMilli(r.expiryMillis()).toString();
                    case 6 -> r.revision();
                    default -> overlaps(r);
                });
        table = new JTable(rows);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> showBlastRadius());
        add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel form = new JPanel(new GridLayout(0, 1));
        JPanel line1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        line1.add(new JLabel("Selector type"));
        line1.add(type);
        line1.add(new JLabel("identity or IP"));
        line1.add(value);
        line1.add(new JLabel("TTL (minutes)"));
        line1.add(ttlMinutes);
        JPanel line2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        line2.add(new JLabel("Reason (required)"));
        line2.add(reason);
        line2.add(quarantine);
        line2.add(release);
        line2.add(why);
        form.add(line1);
        form.add(line2);
        blast.setEditable(false);
        blast.setLineWrap(true);
        blast.setWrapStyleWord(true);
        JPanel south = new JPanel(new BorderLayout());
        south.add(form, BorderLayout.NORTH);
        south.add(new JScrollPane(blast), BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);

        quarantine.addActionListener(e -> confirmQuarantine());
        release.addActionListener(e -> confirmRelease());
        model.onChange(this::refresh);
        refresh();
    }

    private String overlaps(Dto.RestrictionView r) {
        return current.stream().filter(o -> o != r && o.revision() == r.revision()).map(o -> o.selector().toString())
                .collect(Collectors.joining(", "));
    }

    private void confirmQuarantine() {
        Selector s;
        try {
            s = DashboardController.selector((SelectorType) type.getSelectedItem(), value.getText());
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Quarantine", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String bad = DashboardController.checkReason(reason.getText());
        if (bad != null) {
            JOptionPane.showMessageDialog(this, bad, "Quarantine", JOptionPane.WARNING_MESSAGE);
            return;
        }
        Duration ttl = Duration.ofMinutes(((Number) ttlMinutes.getValue()).longValue());
        if (JOptionPane.showConfirmDialog(this, "Quarantine " + s + " for " + ttl.toMinutes() + " min?\nReason: "
                + reason.getText() + "\nEvery gateway closes its matching sessions.", "Confirm quarantine",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.OK_OPTION) {
            controller.quarantine(s, ttl, reason.getText());
        }
    }

    private void confirmRelease() {
        Dto.RestrictionView r = rows.row(table.getSelectedRow());
        if (r == null) {
            JOptionPane.showMessageDialog(this, "Select a restriction first.", "Release", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String bad = DashboardController.checkReason(reason.getText());
        if (bad != null) {
            JOptionPane.showMessageDialog(this, bad, "Release", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String extra = overlaps(r).isEmpty() ? "" : "\nStill active after this release: " + overlaps(r);
        if (JOptionPane.showConfirmDialog(this, "Release " + r.selector() + "?\nReason: " + reason.getText()
                + "\nLeases issued before the release stay invalid; the workload needs a fresh lease." + extra,
                "Confirm release", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.OK_OPTION) {
            controller.release(r.selector(), reason.getText());
        }
    }

    private void showBlastRadius() {
        ConsoleSnapshot d = model.data();
        Dto.RestrictionView r = rows.row(table.getSelectedRow());
        if (d == null || r == null) {
            blast.setText("Select a quarantined identity to see its " + TopologyModel.BLAST_RADIUS_LABEL + ".");
            return;
        }
        if (r.selector().type() != SelectorType.IDENTITY) {
            blast.setText(r.selector() + " is an IP selector: the policy is written per identity, so no policy-allowed"
                    + " destinations can be derived for it.");
            return;
        }
        List<String> services = TopologyModel.blastRadius(r.selector().identity(), d.draft().approved());
        blast.setText("⚠ " + r.selector().identity() + ": " + TopologyModel.BLAST_RADIUS_LABEL + ":\n  "
                + (services.isEmpty() ? "(no approved destinations)" : String.join(", ", services))
                + "\nThese are destinations the policy allows. They are not evidence of compromise.");
    }

    private void refresh() {
        ConsoleSnapshot d = model.data();
        current = d == null ? List.of() : d.dashboard().restrictions();
        int selected = table.getSelectedRow();
        rows.setRows(current);
        if (selected >= 0 && selected < current.size()) {
            table.setRowSelectionInterval(selected, selected);
        }
        boolean ok = model.canOperate();
        quarantine.setEnabled(ok);
        release.setEnabled(ok);
        String w = model.whyNotOperate();
        why.setText(w == null ? model.lastAction() : "(" + w + ")");
        quarantine.setToolTipText(w);
        release.setToolTipText(w);
        showBlastRadius();
    }
}
