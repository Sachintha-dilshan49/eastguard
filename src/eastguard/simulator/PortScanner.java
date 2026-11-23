package eastguard.simulator;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Port scanning attack simulator (idea §7, §10): sweeps a target IP across a port range to simulate
 * network reconnaissance. Demonstrates:
 * <ol>
 *   <li>Reconnaissance detection: scanning &gt; 10 managed endpoints in 5 s triggers the Threat Detector's
 *       scan signal (+50 risk points);</li>
 *   <li>Honeypot trap: touching a gateway's decoy listener generates an instant CRITICAL alert (+100 risk points)
 *       and initiates immediate quarantine.</li>
 * </ol>
 */
public final class PortScanner {
    private static final Logger LOG = Logger.getLogger(PortScanner.class.getName());

    public enum PortState { OPEN, CLOSED, FILTERED, DECOY_HIT }

    public record PortResult(int port, PortState state, Duration latency) {}

    public record ScanReport(
            InetAddress target,
            int totalScanned,
            List<PortResult> results,
            int openCount,
            int closedCount,
            int decoyCount,
            Duration totalDuration) {

        public ScanReport {
            results = List.copyOf(results);
        }
    }

    private final InetAddress target;
    private final Duration connectTimeout;

    public PortScanner(InetAddress target, Duration connectTimeout) {
        this.target = Objects.requireNonNull(target, "target");
        this.connectTimeout = Objects.requireNonNull(connectTimeout, "connectTimeout");
    }

    /** Probes a single TCP port and classifies its response. */
    public PortResult probe(int port) {
        long t0 = System.nanoTime();
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(target, port), (int) connectTimeout.toMillis());
            long ms = (System.nanoTime() - t0) / 1_000_000;
            // Check if connection was closed immediately by server (typical decoy / honeypot behavior)
            s.setSoTimeout(100);
            try {
                int read = s.getInputStream().read();
                if (read == -1) {
                    return new PortResult(port, PortState.DECOY_HIT, Duration.ofMillis(ms));
                }
            } catch (java.net.SocketTimeoutException ignored) {
                // Connection stayed open and timed out waiting for input: real open service
                return new PortResult(port, PortState.OPEN, Duration.ofMillis(ms));
            }
            return new PortResult(port, PortState.OPEN, Duration.ofMillis(ms));
        } catch (java.net.ConnectException e) {
            long ms = (System.nanoTime() - t0) / 1_000_000;
            return new PortResult(port, PortState.CLOSED, Duration.ofMillis(ms));
        } catch (java.net.SocketTimeoutException e) {
            long ms = (System.nanoTime() - t0) / 1_000_000;
            return new PortResult(port, PortState.FILTERED, Duration.ofMillis(ms));
        } catch (IOException e) {
            long ms = (System.nanoTime() - t0) / 1_000_000;
            return new PortResult(port, PortState.CLOSED, Duration.ofMillis(ms));
        }
    }

    /** Scans an inclusive range of ports sequentially or with bounded concurrency. */
    public ScanReport scan(int startPort, int endPort) {
        if (startPort < 1 || endPort > 65_535 || startPort > endPort) {
            throw new IllegalArgumentException("invalid port range: " + startPort + " to " + endPort);
        }
        long t0 = System.nanoTime();
        List<PortResult> results = new ArrayList<>();
        int open = 0;
        int closed = 0;
        int decoy = 0;

        for (int p = startPort; p <= endPort; p++) {
            PortResult res = probe(p);
            results.add(res);
            switch (res.state()) {
                case OPEN -> open++;
                case CLOSED, FILTERED -> closed++;
                case DECOY_HIT -> decoy++;
            }
        }
        long totalMs = (System.nanoTime() - t0) / 1_000_000;
        return new ScanReport(target, results.size(), results, open, closed, decoy, Duration.ofMillis(totalMs));
    }

    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "127.0.0.1";
        int start = args.length > 1 ? Integer.parseInt(args[1]) : 9000;
        int end = args.length > 2 ? Integer.parseInt(args[2]) : 9015;

        InetAddress addr = InetAddress.getByName(host);
        PortScanner scanner = new PortScanner(addr, Duration.ofMillis(200));
        System.out.println("Scanning " + addr + " ports " + start + ".." + end + "...");
        ScanReport report = scanner.scan(start, end);

        System.out.println("Scan complete in " + report.totalDuration().toMillis() + " ms.");
        System.out.println("Total: " + report.totalScanned() + " | Open: " + report.openCount()
                + " | Decoys hit: " + report.decoyCount() + " | Closed/Filtered: " + report.closedCount());
        for (PortResult r : report.results()) {
            if (r.state() == PortState.OPEN || r.state() == PortState.DECOY_HIT) {
                System.out.println("  Port " + r.port() + ": " + r.state() + " (" + r.latency().toMillis() + " ms)");
            }
        }
    }
}
