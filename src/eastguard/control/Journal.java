package eastguard.control;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.zip.CRC32C;

/**
 * Append-only, length-framed control-plane journal (spec §7.2).
 *
 * <pre>
 * frame = length:u32 | ~length:u32 | crc32c(payload):u32 | payload[length]      (big-endian, 1 &lt;= length &lt;= 1 MiB)
 * </pre>
 *
 * <ul>
 *   <li><b>Exclusive.</b> {@link #open} takes an exclusive lock on the file for the life of the object; a second
 *       opener (another process, or the same JVM) fails.</li>
 *   <li><b>Durable.</b> {@link #append} returns only after the whole frame is written and
 *       {@code force(true)} (data and the new file length) succeeded. Any write or force failure leaves the
 *       journal <em>failed</em>: every later append throws, so the caller stops acknowledging mutations.</li>
 *   <li><b>Replay.</b> {@link #open} reads every frame. An <em>incomplete trailing frame</em> (the file ends
 *       inside a header or payload: a write interrupted by a crash, never acknowledged) is cut off and the file
 *       truncated to the last complete frame. A <em>complete</em> frame with a bad checksum, or a length that
 *       disagrees with its complement or is out of range, is corruption: {@link CorruptJournalException}, and
 *       the control plane must not become ready. The complemented length keeps a corrupted length field in the
 *       middle of the file from looking like a torn tail and silently discarding later records.</li>
 * </ul>
 *
 * The checksum detects corruption, not deliberate rewriting (spec §7.2).
 */
public final class Journal implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(Journal.class.getName());
    public static final int MAX_FRAME = 1 << 20;
    static final int HEADER = 12;

    /** A complete frame that fails its checks: fail readiness, never repair automatically. */
    public static final class CorruptJournalException extends IOException {
        private static final long serialVersionUID = 1L;

        CorruptJournalException(String message) {
            super(message);
        }
    }

    private final Path file;
    private final FileChannel ch;
    private final FileLock lock;
    private final List<byte[]> replayed;
    private final long discardedTailBytes;
    private long end;
    private volatile boolean failed;

    private Journal(Path file, FileChannel ch, FileLock lock, List<byte[]> replayed, long end, long discarded) {
        this.file = file;
        this.ch = ch;
        this.lock = lock;
        this.replayed = replayed;
        this.end = end;
        this.discardedTailBytes = discarded;
    }

    /** Opens (creating the file and its directory if needed), locks, and replays the journal. */
    public static Journal open(Path file) throws IOException {
        Path dir = file.toAbsolutePath().getParent();
        if (dir != null) {
            Files.createDirectories(dir);
        }
        FileChannel ch = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.READ,
                StandardOpenOption.WRITE);
        try {
            FileLock lock;
            try {
                lock = ch.tryLock();
            } catch (OverlappingFileLockException e) {
                lock = null;
            }
            if (lock == null) {
                throw new IOException("journal " + file + " is locked by another control plane");
            }
            List<byte[]> records = new ArrayList<>();
            long size = ch.size();
            long pos = scan(ch, size, records);
            long discarded = size - pos;
            if (discarded > 0) {
                LOG.warning(() -> "journal " + file + ": discarding an incomplete trailing frame of " + discarded
                        + " bytes at offset " + pos + " (an unacknowledged write interrupted by a crash)");
                ch.truncate(pos);
                ch.force(true);
            }
            return new Journal(file, ch, lock, records, pos, discarded);
        } catch (IOException | RuntimeException e) {
            ch.close();
            throw e;
        }
    }

    /** Reads complete frames into {@code out}; returns the offset just after the last complete frame. */
    private static long scan(FileChannel ch, long size, List<byte[]> out) throws IOException {
        ByteBuffer hdr = ByteBuffer.allocate(HEADER);
        long pos = 0;
        while (size - pos >= HEADER) {
            readFully(ch, hdr.clear(), pos);
            hdr.flip();
            int len = hdr.getInt();
            int check = hdr.getInt();
            int crc = hdr.getInt();
            if (check != ~len || len < 1 || len > MAX_FRAME) {
                throw new CorruptJournalException("invalid frame header at offset " + pos);
            }
            if (size - pos - HEADER < len) {
                break; // trailing frame cut short
            }
            byte[] payload = new byte[len];
            readFully(ch, ByteBuffer.wrap(payload), pos + HEADER);
            if (crc32c(payload) != crc) {
                throw new CorruptJournalException("checksum mismatch in the record at offset " + pos);
            }
            out.add(payload);
            pos += HEADER + len;
        }
        return pos;
    }

    private static void readFully(FileChannel ch, ByteBuffer dst, long position) throws IOException {
        while (dst.hasRemaining()) {
            int n = ch.read(dst, position + dst.position());
            if (n < 0) {
                throw new IOException("unexpected end of journal");
            }
        }
    }

    static int crc32c(byte[] payload) {
        CRC32C c = new CRC32C();
        c.update(payload);
        return (int) c.getValue();
    }

    /** Payloads replayed at open, in order. */
    public List<byte[]> replayed() {
        return replayed;
    }

    /** Bytes of an incomplete trailing frame removed at open; 0 if the file ended cleanly. */
    public long discardedTailBytes() {
        return discardedTailBytes;
    }

    public boolean failed() {
        return failed;
    }

    public Path file() {
        return file;
    }

    /**
     * Appends one record and forces it to storage. Returns only when the record is durable. On any failure the
     * journal is marked failed (the record may or may not have reached the disk) and every later call throws.
     */
    public synchronized void append(byte[] payload) throws IOException {
        if (failed) {
            throw new IOException("journal failed earlier; restart the control plane to recover");
        }
        if (payload.length < 1 || payload.length > MAX_FRAME) {
            throw new IllegalArgumentException("record size out of range");
        }
        ByteBuffer frame = ByteBuffer.allocate(HEADER + payload.length)
                .putInt(payload.length).putInt(~payload.length).putInt(crc32c(payload)).put(payload).flip();
        try {
            long at = end;
            while (frame.hasRemaining()) {
                at += ch.write(frame, at);
            }
            ch.force(true); // data and the new file length
            end = at;
        } catch (IOException | RuntimeException e) {
            failed = true;
            throw e instanceof IOException io ? io : new IOException(e);
        }
    }

    @Override
    public synchronized void close() throws IOException {
        failed = true; // no appends after close
        try {
            if (lock.isValid()) {
                lock.release();
            }
        } finally {
            ch.close();
        }
    }
}
