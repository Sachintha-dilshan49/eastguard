package eastguard.dashboard;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Stroke;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JPanel;

/**
 * Topology view (spec §7.3): workloads on the left, services on the right, one line per approved edge,
 * candidate, denied flow and blast-radius edge. Each kind has a <b>line style, a symbol and a text label</b>
 * (shown in the legend and on the line), so colour is never the only cue. Quarantined nodes carry a text marker.
 * Paints only what {@link TopologyModel} derived from the model; stale data is overlaid with a STALE notice.
 */
final class TopologyPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    private static final Color APPROVED = new Color(0x2e7d32);
    private static final Color CANDIDATE = new Color(0x1565c0);
    private static final Color DENIED = new Color(0xc62828);
    private static final Color BLAST = new Color(0xef6c00);
    private final transient ConsoleModel model;

    TopologyPanel(ConsoleModel model) {
        this.model = model;
        setPreferredSize(new Dimension(900, 520));
        setBackground(Color.WHITE);
        model.onChange(this::repaint);
    }

    @Override
    protected void paintComponent(Graphics g0) {
        super.paintComponent(g0);
        Graphics2D g = (Graphics2D) g0.create();
        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            ConsoleSnapshot data = model.data();
            if (data == null) {
                g.setColor(Color.DARK_GRAY);
                g.drawString("No data yet: " + model.connectionDetail(), 20, 30);
                return;
            }
            paintGraph(g, TopologyModel.of(data));
            if (model.stale()) {
                g.setColor(new Color(128, 128, 128, 110));
                g.fillRect(0, 0, getWidth(), getHeight());
                g.setColor(Color.BLACK);
                g.setFont(getFont().deriveFont(Font.BOLD, 18f));
                g.drawString("⚠ STALE: " + model.connectionDetail(), 20, getHeight() / 2);
            }
        } finally {
            g.dispose();
        }
    }

    private void paintGraph(Graphics2D g, TopologyModel t) {
        int w = getWidth();
        int legendTop = getHeight() - 110;
        int leftX = 40;
        int rightX = Math.max(leftX + 380, w - 260);
        int boxW = 220;
        Map<String, int[]> left = layout(t.workloads(), leftX, legendTop);
        Map<String, int[]> right = layout(t.services(), rightX, legendTop);
        g.setFont(getFont().deriveFont(12f));

        Map<String, Integer> perPair = new HashMap<>();
        for (TopologyModel.Link l : t.links()) {
            int[] a = left.get(l.edge().sourceIdentity());
            int[] b = right.get(l.edge().serviceId());
            if (a == null || b == null) {
                continue;
            }
            String pair = l.edge().toString();
            int offset = perPair.merge(pair, 1, Integer::sum) * 6 - 6;
            int x1 = a[0] + boxW;
            int y1 = a[1] + 18 + offset;
            int x2 = b[0];
            int y2 = b[1] + 18 + offset;
            g.setColor(colour(l.kind()));
            g.setStroke(stroke(l.kind()));
            g.drawLine(x1, y1, x2, y2);
            g.setStroke(new BasicStroke(1f));
            String tag = l.kind().symbol + " " + shortLabel(l.kind());
            g.drawString(tag, (x1 + x2) / 2 - g.getFontMetrics().stringWidth(tag) / 2, (y1 + y2) / 2 - 3);
        }
        for (TopologyModel.Node n : t.workloads()) {
            node(g, n, left.get(n.id()), boxW, "workload");
        }
        for (TopologyModel.Node n : t.services()) {
            node(g, n, right.get(n.id()), boxW, "service");
        }
        int y = 20;
        g.setColor(Color.BLACK);
        for (String ip : t.ipRestrictions()) {
            g.drawString("IP " + ip, w / 2 - 80, y);
            y += 16;
        }
        legend(g, legendTop + 10);
    }

    private static Map<String, int[]> layout(List<TopologyModel.Node> nodes, int x, int bottom) {
        Map<String, int[]> m = new HashMap<>();
        int gap = Math.max(60, Math.min(90, (bottom - 40) / Math.max(1, nodes.size())));
        int y = 40;
        for (TopologyModel.Node n : nodes) {
            m.put(n.id(), new int[] {x, y});
            y += gap;
        }
        return m;
    }

    private static void node(Graphics2D g, TopologyModel.Node n, int[] at, int w, String kind) {
        int h = 36 + 14 * n.markers().size();
        g.setColor(n.quarantined() ? new Color(0xffebee) : new Color(0xf5f5f5));
        g.fillRoundRect(at[0], at[1], w, h, 10, 10);
        g.setColor(n.quarantined() ? DENIED : Color.GRAY);
        g.setStroke(new BasicStroke(n.quarantined() ? 3f : 1f));
        g.drawRoundRect(at[0], at[1], w, h, 10, 10);
        g.setStroke(new BasicStroke(1f));
        g.setColor(Color.BLACK);
        g.drawString(kind + ": " + n.id(), at[0] + 8, at[1] + 22);
        int y = at[1] + 36;
        for (String mark : n.markers()) {
            g.drawString(mark, at[0] + 8, y);
            y += 14;
        }
    }

    private void legend(Graphics2D g, int y) {
        FontMetrics fm = g.getFontMetrics();
        int x = 20;
        for (TopologyModel.LinkKind k : TopologyModel.LinkKind.values()) {
            g.setColor(colour(k));
            g.setStroke(stroke(k));
            g.drawLine(x, y + 5, x + 40, y + 5);
            g.setStroke(new BasicStroke(1f));
            g.setColor(Color.BLACK);
            g.drawString(k.symbol + " " + k.label, x + 48, y + 10);
            y += fm.getHeight() + 4;
        }
        g.drawString(TopologyModel.QUARANTINED + " / " + TopologyModel.DENIALS + ": node markers", x, y + 10);
    }

    private static String shortLabel(TopologyModel.LinkKind k) {
        return switch (k) {
            case APPROVED -> "approved";
            case CANDIDATE -> "candidate";
            case DENIED -> "denied";
            case BLAST_RADIUS -> "potential blast radius";
        };
    }

    private static Color colour(TopologyModel.LinkKind k) {
        return switch (k) {
            case APPROVED -> APPROVED;
            case CANDIDATE -> CANDIDATE;
            case DENIED -> DENIED;
            case BLAST_RADIUS -> BLAST;
        };
    }

    private static Stroke stroke(TopologyModel.LinkKind k) {
        return switch (k) {
            case APPROVED -> new BasicStroke(2f);
            case CANDIDATE -> new BasicStroke(2f, BasicStroke.CAP_BUTT, BasicStroke.JOIN_MITER, 10f, new float[] {8f, 6f}, 0f);
            case DENIED -> new BasicStroke(2f, BasicStroke.CAP_BUTT, BasicStroke.JOIN_MITER, 10f, new float[] {2f, 4f}, 0f);
            case BLAST_RADIUS -> new BasicStroke(4f);
        };
    }
}
