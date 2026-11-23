package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.bus.FaultyTransport;
import eastguard.bus.MulticastSettings;
import eastguard.bus.NoticeTransport;
import eastguard.common.Config;
import eastguard.common.IpAddress;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Tests for {@link FaultyTransport} and {@link MulticastSettings}:
 * fault injection (packet dropping, duplication, hold and release in FIFO/LIFO orders),
 * and multicast settings validation and interface resolution.
 */
public final class BusMoreTest {

    static final class MockTransport implements NoticeTransport {
        final List<byte[]> received = new ArrayList<>();
        boolean joined;

        @Override
        public void send(byte[] datagram) {
            received.add(datagram.clone());
        }

        @Override
        public Receiver join() {
            joined = true;
            return new Receiver() {
                @Override
                public int receive(byte[] buf, int timeoutMillis) {
                    return 0;
                }

                @Override
                public void close() {
                }
            };
        }
    }

    public void testFaultyTransportDropNext() throws IOException {
        MockTransport mock = new MockTransport();
        FaultyTransport faulty = new FaultyTransport(mock);

        faulty.dropNext(2);
        assertEquals(0L, faulty.dropped());

        byte[] p1 = new byte[] {1};
        byte[] p2 = new byte[] {2};
        byte[] p3 = new byte[] {3};

        faulty.send(p1);
        faulty.send(p2);
        assertEquals(2L, faulty.dropped());
        assertTrue(mock.received.isEmpty(), "mock received is empty");

        // Third packet passes through
        faulty.send(p3);
        assertEquals(2L, faulty.dropped());
        assertEquals(1, mock.received.size());
        assertArrayEquals(p3, mock.received.get(0));
    }

    public void testFaultyTransportDuplication() throws IOException {
        MockTransport mock = new MockTransport();
        FaultyTransport faulty = new FaultyTransport(mock);

        assertThrows(IllegalArgumentException.class, () -> faulty.duplicate(0));
        assertThrows(IllegalArgumentException.class, () -> faulty.duplicate(17));

        faulty.duplicate(3);
        byte[] p = new byte[] {1, 2, 3};
        faulty.send(p);

        assertEquals(3, mock.received.size());
        assertArrayEquals(p, mock.received.get(0));
        assertArrayEquals(p, mock.received.get(1));
        assertArrayEquals(p, mock.received.get(2));
    }

    public void testFaultyTransportHoldAndRelease() throws IOException {
        MockTransport mock = new MockTransport();
        FaultyTransport faulty = new FaultyTransport(mock);

        faulty.hold();

        byte[] p1 = new byte[] {1};
        byte[] p2 = new byte[] {2};
        faulty.send(p1);
        faulty.send(p2);

        assertTrue(mock.received.isEmpty(), "held datagrams not sent yet");

        // Release in normal order (reverse = false)
        int released = faulty.releaseHeld(false);
        assertEquals(2, released);
        assertEquals(2, mock.received.size());
        assertArrayEquals(p1, mock.received.get(0));
        assertArrayEquals(p2, mock.received.get(1));

        // Hold and release in reverse order (reverse = true)
        mock.received.clear();
        faulty.hold();
        faulty.send(p1);
        faulty.send(p2);

        released = faulty.releaseHeld(true);
        assertEquals(2, released);
        assertEquals(2, mock.received.size());
        assertArrayEquals(p2, mock.received.get(0));
        assertArrayEquals(p1, mock.received.get(1));

        // Join delegates
        assertFalse(mock.joined, "not joined yet");
        faulty.join();
        assertTrue(mock.joined, "joined");
    }

    public void testMulticastSettingsValidation() {
        assertThrows(NullPointerException.class, () -> new MulticastSettings(null, 4446, "127.0.0.1", 1));
        // Non-multicast IP
        assertThrows(IllegalArgumentException.class, () -> new MulticastSettings(IpAddress.parse("127.0.0.1"), 4446, "127.0.0.1", 1));
        // Invalid ports / ttls
        assertThrows(IllegalArgumentException.class, () -> new MulticastSettings(IpAddress.parse("239.20.20.20"), 0, "127.0.0.1", 1));
        assertThrows(IllegalArgumentException.class, () -> new MulticastSettings(IpAddress.parse("239.20.20.20"), 4446, "127.0.0.1", -1));
        assertThrows(IllegalArgumentException.class, () -> new MulticastSettings(IpAddress.parse("239.20.20.20"), 4446, "127.0.0.1", 256));
        // Blank interface
        assertThrows(IllegalArgumentException.class, () -> new MulticastSettings(IpAddress.parse("239.20.20.20"), 4446, "  ", 1));

        Properties props = new Properties();
        assertNull(MulticastSettings.from(Config.of(props, "test")));

        props.setProperty("multicast.group", "239.20.20.20");
        props.setProperty("multicast.interface", "127.0.0.1");
        MulticastSettings settings = MulticastSettings.from(Config.of(props, "test"));
        assertTrue(settings != null, "settings loaded");
        assertEquals(IpAddress.parse("239.20.20.20"), settings.group());
        assertEquals("127.0.0.1", settings.networkInterface());
        assertEquals(4446, settings.port());
        assertEquals(1, settings.ttl());
    }
}
