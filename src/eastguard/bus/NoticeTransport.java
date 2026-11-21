package eastguard.bus;

import java.io.IOException;

/**
 * Adapter for the datagram channel that carries signed control notices (spec §5.4, §8 "Adapter"). The production
 * implementation is {@link MulticastTransport}; tests and demos use {@link MemoryTransport}, which can drop,
 * duplicate, delay and reorder.
 *
 * <p>Delivery is best effort and unordered; nothing on top of it may assume otherwise. Correctness comes from
 * signed revisions plus the authoritative sync, never from the transport.
 */
public interface NoticeTransport {
    /** Maximum datagram size handed to or accepted from a transport (the notice codec's cap). */
    int MAX_DATAGRAM = eastguard.common.NoticeCodec.MAX_DATAGRAM;

    /** Sends one datagram to every joined receiver. May block briefly; never called on a gateway selector. */
    void send(byte[] datagram) throws IOException;

    /**
     * Joins the group. Returns only once the membership is in place, so a caller that joins before its first sync
     * cannot miss a notice committed after that sync started.
     */
    Receiver join() throws IOException;

    /** One joined receiver. Owned by a single listener thread. */
    interface Receiver extends AutoCloseable {
        /**
         * Waits up to {@code timeoutMillis} for a datagram and copies it into {@code buf}.
         *
         * @return the datagram length; 0 on timeout; -1 once closed. A length above {@code buf.length} means the
         *         datagram was oversize (only its first {@code buf.length} bytes were copied) and must be rejected.
         */
        int receive(byte[] buf, int timeoutMillis) throws IOException;

        @Override
        void close();
    }
}
