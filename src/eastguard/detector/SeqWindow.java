package eastguard.detector;

/**
 * Replay window for one {@code (producerId, bootId)} stream (spec §6.1): remembers which of the last {@code size}
 * sequence numbers below the highest one have been seen. A new highest sequence slides the window; a sequence
 * inside the window is accepted once (limited reordering); anything at or below {@code highest - size} is too
 * old to tell apart from a replay and is rejected. Not thread-safe.
 */
final class SeqWindow {
    enum Mark { NEW, DUPLICATE, TOO_OLD }

    private final int size;
    private final long[] bits;
    private long highest = -1;
    private long skipped;  // sequence numbers jumped over when the window advanced
    private long filled;   // of those, how many arrived late (reordered) inside the window

    SeqWindow(int size) {
        if (size < 64 || size > 65_536 || Integer.bitCount(size) != 1) {
            throw new IllegalArgumentException("window size must be a power of two in [64, 65536]");
        }
        this.size = size;
        this.bits = new long[size / 64];
    }

    Mark mark(long seq) {
        if (seq < 0) {
            return Mark.TOO_OLD;
        }
        if (highest < 0) {
            // First datagram of this stream as far as we know (producer or detector may have restarted).
            highest = seq;
            set(seq);
            return Mark.NEW;
        }
        if (seq > highest) {
            long advance = seq - highest;
            skipped += advance - 1;
            if (advance >= size) {
                java.util.Arrays.fill(bits, 0);
            } else {
                for (long s = highest + 1; s < seq; s++) {
                    clear(s);
                }
            }
            highest = seq;
            set(seq);
            return Mark.NEW;
        }
        if (seq <= highest - size) {
            return Mark.TOO_OLD;
        }
        if (get(seq)) {
            return Mark.DUPLICATE;
        }
        set(seq);
        filled++;
        return Mark.NEW;
    }

    /** Sequence numbers skipped and never received (so far). */
    long missing() {
        return skipped - filled;
    }

    long reordered() {
        return filled;
    }

    long highest() {
        return highest;
    }

    private int index(long seq) {
        return (int) (seq & (size - 1));
    }

    private boolean get(long seq) {
        int i = index(seq);
        return (bits[i >>> 6] & (1L << (i & 63))) != 0;
    }

    private void set(long seq) {
        int i = index(seq);
        bits[i >>> 6] |= 1L << (i & 63);
    }

    private void clear(long seq) {
        int i = index(seq);
        bits[i >>> 6] &= ~(1L << (i & 63));
    }
}
