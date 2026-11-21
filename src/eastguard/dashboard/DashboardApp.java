package eastguard.dashboard;

import eastguard.control.ControlClient;
import eastguard.control.Dto;
import eastguard.control.RmiSupport;
import eastguard.tokensvc.TlsContextFactory;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.BorderFactory;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.WindowConstants;

/**
 * EastGuard operator console (spec §7.3), a Swing MVC application: {@link ConsoleModel} (state),
 * {@link DashboardController} (actions, polling), and the views {@link TopologyPanel}, {@link AlertTable},
 * {@link PolicyEditor}, {@link QuarantinePanel} and an audit table.
 *
 * <pre>
 * java -cp out eastguard.dashboard.DashboardApp --config config/dashboard.properties.example
 * java -cp out eastguard.dashboard.DashboardApp --demo        # labeled fixtures only, no network
 * </pre>
 *
 * Threading: all RMI runs on the one {@link ConsoleWorker} thread with one poll outstanding at most; results are
 * applied on the EDT ({@code SwingUtilities.invokeLater}); a Swing {@link Timer} drives {@link DashboardController#tick}.
 * The window never waits for the network. When the data is stale or the control plane is unreachable, a banner
 * says so and every edit is disabled; the role reported by the control plane disables what this console's
 * credential may not do.
 */
public final class DashboardApp {
    private DashboardApp() {
    }

    public static void main(String[] args) throws Exception {
        boolean demo = args.length == 1 && args[0].equals("--demo");
        if (!demo && (args.length != 2 || !args[0].equals("--config"))) {
            System.err.println("usage: DashboardApp --config <dashboard.properties> | --demo");
            System.exit(2);
        }
        DashboardConfig cfg = demo ? new DashboardConfig(DashboardConfig.Profile.DEMO,
                new DashboardController.Timing(java.time.Duration.ofSeconds(1), java.time.Duration.ofSeconds(4)), null, null)
                : DashboardConfig.load(Path.of(args[1]));
        Clock clock = Clock.systemUTC();
        AtomicReference<FixtureScenarios.Scenario> scenario = new AtomicReference<>();
        List<FixtureScenarios.Scenario> scenarios = FixtureScenarios.all(clock);
        ConsoleApi api;
        if (cfg.profile() == DashboardConfig.Profile.DEMO) {
            scenario.set(scenarios.get(0));
            api = FixtureScenarios.api(scenario::get);
        } else {
            RmiSupport.configureJvm(null);
            api = ConsoleApi.rmi(new ControlClient(cfg.control(), TlsContextFactory.create(cfg.tls())));
        }
        SwingUtilities.invokeLater(() -> show(cfg, api, clock, scenarios, scenario));
    }

    private static void show(DashboardConfig cfg, ConsoleApi api, Clock clock, List<FixtureScenarios.Scenario> scenarios,
            AtomicReference<FixtureScenarios.Scenario> scenario) {
        ConsoleModel model = new ConsoleModel(SwingUtilities::isEventDispatchThread);
        ConsoleWorker worker = new ConsoleWorker(SwingUtilities::invokeLater);
        DashboardController controller = new DashboardController(model, api, worker, clock, System::nanoTime,
                cfg.timing());

        JFrame frame = new JFrame("EastGuard console" + (cfg.profile() == DashboardConfig.Profile.DEMO
                ? " (DEMO FIXTURES)" : " (" + cfg.control().principal() + ")"));
        frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        JPanel top = new JPanel(new BorderLayout());
        top.add(banner(model), BorderLayout.CENTER);
        if (cfg.profile() == DashboardConfig.Profile.DEMO) {
            JPanel pick = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JComboBox<FixtureScenarios.Scenario> box = new JComboBox<>(scenarios.toArray(new FixtureScenarios.Scenario[0]));
            box.addActionListener(e -> {
                scenario.set((FixtureScenarios.Scenario) box.getSelectedItem());
                controller.refresh();
            });
            pick.add(new JLabel("Labeled fixture scenario:"));
            pick.add(box);
            top.add(pick, BorderLayout.SOUTH);
        }
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Topology", new JScrollPane(new TopologyPanel(model)));
        tabs.addTab("Alerts", new AlertTable(model));
        tabs.addTab("Policy and learning", new PolicyEditor(model, controller));
        tabs.addTab("Quarantine", new QuarantinePanel(model, controller));
        tabs.addTab("Audit", audit(model));
        frame.getContentPane().add(top, BorderLayout.NORTH);
        frame.getContentPane().add(tabs, BorderLayout.CENTER);
        frame.setSize(1200, 780);
        frame.setLocationByPlatform(true);

        Timer timer = new Timer(250, e -> controller.tick());
        frame.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosed(java.awt.event.WindowEvent e) {
                timer.stop();
                worker.close();
            }
        });
        timer.start();
        controller.tick();
        frame.setVisible(true);
    }

    /** Connection, staleness, role and the last action, in words and symbols as well as colour. */
    private static JLabel banner(ConsoleModel model) {
        JLabel l = new JLabel();
        l.setOpaque(true);
        l.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 10));
        l.setFont(l.getFont().deriveFont(Font.BOLD, 14f));
        Runnable update = () -> {
            ConsoleSnapshot d = model.data();
            String when = d == null ? "never" : Instant.ofEpochMilli(d.fetchedAtMillis()).toString();
            String state = switch (model.connection()) {
                case CONNECTED -> "● CONNECTED";
                case CONNECTING -> "… CONNECTING";
                case STALE -> "⚠ STALE: data from " + when + "; edits disabled";
                case DISCONNECTED -> "✖ DISCONNECTED: data from " + when + "; edits disabled";
            };
            l.setText(state + "  |  " + model.connectionDetail() + "  |  role " + model.role()
                    + (model.lastAction().isEmpty() ? "" : "  |  " + model.lastAction()));
            l.setBackground(model.demo() ? new Color(0xe1f5fe) : switch (model.connection()) {
                case CONNECTED -> new Color(0xe8f5e9);
                case CONNECTING -> new Color(0xeeeeee);
                case STALE -> new Color(0xfff8e1);
                case DISCONNECTED -> new Color(0xffebee);
            });
        };
        model.onChange(update);
        update.run();
        return l;
    }

    private static JScrollPane audit(ConsoleModel model) {
        RowTableModel<Dto.AuditEntry> rows = new RowTableModel<>(new String[] {"Revision", "Time (UTC)", "Actor", "Role",
                "Operation", "Request ID", "Detail", "Reason", "Outcome"}, (e, c) -> switch (c) {
                    case 0 -> e.revision();
                    case 1 -> Instant.ofEpochMilli(e.atMillis()).toString();
                    case 2 -> e.actor();
                    case 3 -> e.role();
                    case 4 -> e.operation();
                    case 5 -> e.requestId();
                    case 6 -> e.detail();
                    case 7 -> e.reason();
                    default -> e.outcome();
                });
        model.onChange(() -> rows.setRows(model.data() == null ? List.of() : model.data().dashboard().audit()));
        return new JScrollPane(new JTable(rows));
    }
}
