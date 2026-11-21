package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.control.Journal;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Framing, locking, durability failure and crash recovery of the control-plane journal. */
public final class JournalTest {
    private static final Logger QUIET = Logger.getLogger(Journal.class.getName());
    private final Path file;

    public JournalTest() throws IOException {
        Path dir = Files.createDirectories(Path.of("out", "test-journal"));
        file = Files.createTempFile(dir, "journal", ".bin");
        Files.delete(file); // let Journal create it
    }

    private static byte[] rec(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private void write(String... records) throws IOException {
        try (Journal j = Journal.open(file)) {
            for (String r : records) {
                j.append(rec(r));
            }
        }
    }

    private static List<String> texts(Journal j) {
        return j.replayed().stream().map(b -> new String(b, StandardCharsets.US_ASCII)).toList();
    }

    public void testAppendAndReplayInOrder() throws Exception {
        write("one", "two", "three");
        try (Journal j = Journal.open(file)) {
            assertEquals(List.of("one", "two", "three"), texts(j));
            assertEquals(0, j.discardedTailBytes());
            j.append(rec("four"));
        }
        try (Journal j = Journal.open(file)) {
            assertEquals(List.of("one", "two", "three", "four"), texts(j));
        }
    }

    public void testTornTrailingFrameIsRecovered() throws Exception {
        QUIET.setLevel(Level.SEVERE); // the recovery WARNING is expected here
        write("one", "two", "three");
        long full = Files.size(file);
        for (int cut = 1; cut < 5 + 12; cut++) { // a crash after every byte of the header and payload of "three"
            write(); // reopen once so the file is consistent
            try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE)) {
                ch.truncate(full - (5 + 12) + Math.min(cut, 5 + 12 - 1)); // keep "one","two" + a prefix of "three"
            }
            try (Journal j = Journal.open(file)) {
                assertEquals(List.of("one", "two"), texts(j));
                assertTrue(j.discardedTailBytes() > 0, "tail discarded");
                j.append(rec("three")); // the next append continues cleanly after the cut
            }
            try (Journal j = Journal.open(file)) {
                assertEquals(List.of("one", "two", "three"), texts(j));
                assertEquals(0, j.discardedTailBytes());
            }
        }
    }

    public void testCorruptCompleteRecordFailsOpen() throws Exception {
        write("one", "two", "three");
        byte[] all = Files.readAllBytes(file);
        int payloadOfTwo = (12 + 3) + 12; // after frame "one" and the header of "two"
        all[payloadOfTwo] ^= 0x40;
        Files.write(file, all);
        assertThrows(Journal.CorruptJournalException.class, () -> Journal.open(file));
    }

    public void testCorruptLengthInTheMiddleIsNotMistakenForATornTail() throws Exception {
        write("one", "two", "three");
        byte[] all = Files.readAllBytes(file);
        ByteBuffer.wrap(all).putInt(15, 4_000); // frame "two" claims 4000 bytes, beyond the end of the file
        Files.write(file, all);
        assertThrows(Journal.CorruptJournalException.class, () -> Journal.open(file));
    }

    public void testExclusiveLock() throws Exception {
        try (Journal j = Journal.open(file)) {
            assertFalse(j.failed(), "the holder is healthy");
            IOException e = assertThrows(IOException.class, () -> Journal.open(file));
            assertTrue(e.getMessage().contains("locked"), "says it is locked");
        }
        Journal.open(file).close(); // released on close
    }

    public void testFailedWriteFencesFurtherAppends() throws Exception {
        Journal j = Journal.open(file);
        j.append(rec("one"));
        j.close(); // the channel is gone: the next write fails like a dead disk would
        assertThrows(IOException.class, () -> j.append(rec("two")));
        assertTrue(j.failed(), "failed");
        try (Journal again = Journal.open(file)) {
            assertEquals(List.of("one"), texts(again));
        }
    }

    public void testRecordSizeBounds() throws Exception {
        try (Journal j = Journal.open(file)) {
            assertThrows(IllegalArgumentException.class, () -> j.append(new byte[0]));
            assertThrows(IllegalArgumentException.class, () -> j.append(new byte[Journal.MAX_FRAME + 1]));
            j.append(new byte[Journal.MAX_FRAME]);
        }
        try (Journal j = Journal.open(file)) {
            assertEquals(1, j.replayed().size());
        }
    }
}
