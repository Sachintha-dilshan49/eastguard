package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.demos.EchoBackend;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Tests for demo utilities: {@link EchoBackend}.
 */
public final class DemoComponentsTest {

    public void testEchoBackendBasicEchoAndShutdown() throws Exception {
        try (EchoBackend backend = new EchoBackend(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 5).start()) {
            int port = backend.port();
            assertTrue(port > 0, "port > 0");

            try (Socket s = new Socket(InetAddress.getLoopbackAddress(), port)) {
                OutputStream out = s.getOutputStream();
                InputStream in = s.getInputStream();

                byte[] data = "Hello EastGuard Echo!".getBytes();
                out.write(data);
                out.flush();
                s.shutdownOutput();

                byte[] received = in.readAllBytes();
                assertArrayEquals(data, received);
            }

            // Wait a brief moment for worker to update counters
            long deadline = System.currentTimeMillis() + 1000;
            while (backend.bytesEchoed() == 0 && System.currentTimeMillis() < deadline) {
                Thread.onSpinWait();
            }

            assertEquals(1L, backend.accepted());
            assertEquals("Hello EastGuard Echo!".length(), backend.bytesEchoed());
            assertEquals(0L, backend.rejected());
        }
    }

    public void testEchoBackendRejectsExcessConnections() throws Exception {
        // Backend with maxConnections = 1
        try (EchoBackend backend = new EchoBackend(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 1).start()) {
            int port = backend.port();

            // First connection takes the single permit
            try (Socket s1 = new Socket(InetAddress.getLoopbackAddress(), port)) {
                // Keep s1 open without writing so permit stays held
                s1.getOutputStream().write(1);

                // Second connection should be rejected immediately
                try (Socket s2 = new Socket(InetAddress.getLoopbackAddress(), port)) {
                    // Expect s2 to be closed by server immediately (EOF on read)
                    int b = s2.getInputStream().read();
                    assertEquals(-1, b);
                }
            }

            long deadline = System.currentTimeMillis() + 1000;
            while (backend.rejected() == 0 && System.currentTimeMillis() < deadline) {
                Thread.onSpinWait();
            }

            assertEquals(1L, backend.rejected());
        }
    }
}
