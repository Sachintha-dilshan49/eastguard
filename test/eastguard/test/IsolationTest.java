package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.Endpoint;
import eastguard.common.Lease;
import eastguard.common.Preamble;
import eastguard.demos.EchoBackend;
import java.net.ConnectException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Spec §10 "deployment isolation: an unauthorized workload cannot reach the protected backend except through its
 * gateway", as far as one host can show it. Real isolation is a property of the deployment (separate hosts, host
 * firewall, network segmentation) and is not testable on a single machine; see docs/TEST-COVERAGE.md. What can be
 * checked locally:
 * <ul>
 *   <li>the demo backend fixture is bound to loopback only: it refuses connections on every other local address;</li>
 *   <li>every configured backend is a loopback endpoint that no other component listens on or sends to;</li>
 *   <li>the client cannot choose a destination: neither the preamble nor the lease names a host or port.</li>
 * </ul>
 */
public final class IsolationTest {

    public void testBackendFixtureRefusesEveryNonLoopbackAddress() throws Exception {
        List<InetAddress> others = new ArrayList<>();
        for (NetworkInterface nif : NetworkInterface.networkInterfaces().toList()) {
            if (nif.isUp() && !nif.isLoopback()) {
                nif.inetAddresses().filter(a -> a instanceof Inet4Address && !a.isLinkLocalAddress()).forEach(others::add);
            }
        }
        try (EchoBackend echo = new EchoBackend(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 8).start()) {
            int port = echo.port();
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 2_000);
            }
            if (others.isEmpty()) {
                System.out.println("    SKIP part of IsolationTest: no non-loopback IPv4 address on this host");
                return;
            }
            for (InetAddress a : others) {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(a, port), 2_000);
                    fail("backend reachable on " + a.getHostAddress() + ":" + port);
                } catch (ConnectException | SocketTimeoutException expected) {
                    // refused (or filtered): only loopback reaches it
                }
            }
        }
    }

    /** Backends are loopback-only and nothing else in the demo listens on, or sends to, a backend port. */
    public void testConfiguredBackendsAreLoopbackAndOnlyTheirGatewayUsesThem() throws Exception {
        List<String> gateways = List.of("gateway-app-02.properties.example", "gateway-app-03.properties.example");
        Set<Endpoint> backends = new java.util.HashSet<>();
        Set<Endpoint> others = new java.util.HashSet<>();
        for (String g : gateways) {
            Properties p = DemoConfigTest.raw(g);
            Endpoint backend = Endpoint.parse(p.getProperty("backend"));
            assertTrue(backend.ip().toInetAddress().isLoopbackAddress(), g + ": backend " + backend + " is loopback");
            assertTrue(backends.add(backend), g + ": backend " + backend + " is not shared with another gateway");
            others.add(Endpoint.parse(p.getProperty("listen")));
            others.add(Endpoint.parse(p.getProperty("telemetry.collector")));
            if (p.getProperty("decoy.listen") != null) {
                others.add(Endpoint.parse(p.getProperty("decoy.listen")));
            }
        }
        for (String c : List.of("token.properties.example", "demo-detector.properties.example")) {
            others.add(Endpoint.parse(DemoConfigTest.raw(c).getProperty("listen")));
        }
        Properties control = DemoConfigTest.raw("demo-control.properties.example");
        others.add(Endpoint.parse(control.getProperty("audit.listen")));
        Set<Integer> otherPorts = others.stream().map(Endpoint::port).collect(Collectors.toSet());
        otherPorts.add(Integer.parseInt(control.getProperty("rmi.registryPort")));
        otherPorts.add(Integer.parseInt(control.getProperty("rmi.objectPort")));
        for (Endpoint b : backends) {
            assertFalse(otherPorts.contains(b.port()), "backend port " + b.port() + " is used by no other component");
        }
    }

    /** The gateway connects only to its configured backend: no client-supplied field names a destination. */
    public void testClientCannotChooseTheBackend() {
        assertEquals(List.of("token"), Arrays.stream(Preamble.class.getRecordComponents()).map(c -> c.getName()).toList());
        Set<String> leaseFields = Arrays.stream(Lease.class.getRecordComponents()).map(c -> c.getName())
                .collect(Collectors.toSet());
        for (String f : leaseFields) {
            String lower = f.toLowerCase();
            assertFalse(lower.contains("host") || lower.contains("port") || lower.contains("backend")
                    || lower.contains("destination"), "lease field " + f + " names no destination");
        }
        assertTrue(leaseFields.contains("audience"), "the lease names only a service, checked against the gateway's own");
    }
}
