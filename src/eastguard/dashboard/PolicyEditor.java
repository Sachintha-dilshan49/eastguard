package eastguard.dashboard;

import eastguard.common.Edge;
import eastguard.control.Dto;
import eastguard.control.EdgeDiff;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.table.AbstractTableModel;

/**
 * Policy editor (spec §3.2, §7.3): shows the active mode and revisions, the learning draft with a completeness
 * warning, and a review where the administrator includes or excludes each approved edge and candidate. The
 * preview is the <b>exact</b> {@link EdgeDiff} a freeze would commit (the same function the control plane audits).
 * Freeze asks for a reason and a confirmation that repeats the diff and the versions. After a CONFLICT the
 * controller reloads and the review must be started again.
 */
final class PolicyEditor extends JPanel {
    private static final long serialVersionUID = 1L;
    private final transient ConsoleModel model;
    private final transient DashboardController controller;
    private final JLabel header = new JLabel();
    private final JLabel warning = new JLabel();
    private final JTextArea preview = new JTextArea(10, 40);
    private final JTextField reason = new JTextField(40);
    private final JButton startReview = new JButton("Start review of the current draft");
    private final JButton freeze = new JButton("Freeze baseline and switch to ENFORCE...");
    private final JLabel freezeWhy = new JLabel();
    private final ReviewTable reviewTable = new ReviewTable();

    PolicyEditor(ConsoleModel model, DashboardController controller) {
        super(new BorderLayout(6, 6));
        this.model = model;
        this.controller = controller;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        header.setFont(header.getFont().deriveFont(Font.BOLD));
        JPanel top = new JPanel(new GridLayout(0, 1));
        top.add(header);
        JLabel incomplete = new JLabel("⚠ " + Dto.LearningDraftView.INCOMPLETE);
        top.add(incomplete);
        top.add(warning);
        add(top, BorderLayout.NORTH);

        preview.setEditable(false);
        preview.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(new JTable(reviewTable)),
                new JScrollPane(preview));
        split.setResizeWeight(0.6);
        add(split, BorderLayout.CENTER);

        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bottom.add(startReview);
        bottom.add(new JLabel("Reason (required):"));
        bottom.add(reason);
        bottom.add(freeze);
        bottom.add(freezeWhy);
        add(bottom, BorderLayout.SOUTH);

        startReview.addActionListener(e -> controller.startReview());
        freeze.addActionListener(e -> confirmFreeze());
        model.onChange(this::refresh);
        refresh();
    }

    private void confirmFreeze() {
        ConsoleModel.Review r = model.review();
        if (r == null) {
            return;
        }
        String why = DashboardController.checkReason(reason.getText());
        if (why != null) {
            JOptionPane.showMessageDialog(this, why, "Freeze baseline", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String text = "Commit exactly this allow-list and switch to ENFORCE?\n\n" + diffText(r)
                + "\nExpected policy revision " + r.base().policyRevision() + ", draft version "
                + r.base().draftVersion() + ".\nUnreviewed candidates stay denied.";
        if (JOptionPane.showConfirmDialog(this, text, "Confirm freeze", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE) == JOptionPane.OK_OPTION) {
            controller.freeze(reason.getText());
        }
    }

    private void refresh() {
        ConsoleSnapshot d = model.data();
        if (d == null) {
            header.setText("Policy: no data yet");
        } else {
            Dto.LearningDraftView v = d.draft();
            header.setText("Mode " + v.mode() + "  |  policy revision " + v.policyRevision() + "  |  enforcement revision "
                    + v.revision() + "  |  draft version " + v.draftVersion() + "  |  pilot sources " + v.pilotSources()
                    + ", services " + v.pilotServices() + "  |  " + v.candidates().size() + " candidate(s), "
                    + v.droppedCandidates() + " dropped, draft since " + Instant.ofEpochMilli(v.draftSinceMillis())
                    + (model.stale() ? "  |  ⚠ STALE" : ""));
        }
        ConsoleModel.Review r = model.review();
        warning.setText(model.reviewOutdated() ? "⚠ The draft or policy changed since this review started: start the"
                + " review again." : r == null ? "No review in progress." : "Reviewing draft version "
                + r.base().draftVersion() + " at policy revision " + r.base().policyRevision() + ".");
        reviewTable.update(r);
        preview.setText(r == null ? "" : diffText(r));
        startReview.setEnabled(d != null && !model.demo());
        freeze.setEnabled(model.canFreeze());
        String why = model.whyNotFreeze();
        freezeWhy.setText(why == null ? "" : "(" + why + ")");
        freeze.setToolTipText(why);
    }

    static String diffText(ConsoleModel.Review r) {
        EdgeDiff diff = r.diff();
        StringBuilder b = new StringBuilder("Exact change (" + diff.additions().size() + " added, "
                + diff.removals().size() + " removed, " + diff.kept().size() + " unchanged):\n");
        diff.additions().forEach(e -> b.append("  + ").append(e).append('\n'));
        diff.removals().forEach(e -> b.append("  - ").append(e).append('\n'));
        diff.kept().forEach(e -> b.append("    ").append(e).append('\n'));
        return b.toString();
    }

    /** Include check box per approved edge and candidate of the review's draft. */
    private final class ReviewTable extends AbstractTableModel {
        private static final long serialVersionUID = 1L;
        private transient List<Edge> edges = List.of();
        private transient Map<Edge, Dto.Observation> obs = new HashMap<>();
        private transient ConsoleModel.Review review;

        void update(ConsoleModel.Review r) {
            review = r;
            edges = r == null ? List.of() : model.reviewChoices();
            obs = new HashMap<>();
            if (r != null) {
                r.base().candidates().forEach(o -> obs.put(o.edge(), o));
            }
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return edges.size();
        }

        @Override
        public int getColumnCount() {
            return 5;
        }

        @Override
        public String getColumnName(int c) {
            return new String[] {"Include", "Edge", "Status", "Observations", "Last seen (UTC)"}[c];
        }

        @Override
        public Class<?> getColumnClass(int c) {
            return c == 0 ? Boolean.class : String.class;
        }

        @Override
        public boolean isCellEditable(int r, int c) {
            return c == 0 && !model.reviewOutdated() && !model.stale();
        }

        @Override
        public Object getValueAt(int r, int c) {
            Edge e = edges.get(r);
            Dto.Observation o = obs.get(e);
            boolean approved = review.base().approved().contains(e);
            return switch (c) {
                case 0 -> review.reviewed().contains(e);
                case 1 -> e.toString();
                case 2 -> approved ? "✔ approved now" : "? candidate";
                case 3 -> o == null ? "" : Long.toString(o.count());
                default -> o == null ? "" : Instant.ofEpochMilli(o.lastSeenMillis()).toString();
            };
        }

        @Override
        public void setValueAt(Object v, int r, int c) {
            if (c == 0 && v instanceof Boolean b) {
                controller.setReviewed(edges.get(r), b);
            }
        }
    }
}
