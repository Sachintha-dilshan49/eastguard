package eastguard.detector;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Bounded time window over monotonic timestamps (spec §6.1). Items older than {@code span} are pruned; at most
 * {@code capacity} items are kept, the oldest being evicted (and counted) first. Timestamps must be added in
 * non-decreasing order. Not thread-safe.
 */
public final class SlidingWindow<T> {
    private record Item<T>(long atNanos, T value) {
    }

    private final long spanNanos;
    private final int capacity;
    private final ArrayDeque<Item<T>> items = new ArrayDeque<>();
    private long evicted;

    public SlidingWindow(long spanNanos, int capacity) {
        if (spanNanos <= 0 || capacity < 1) {
            throw new IllegalArgumentException("span and capacity must be positive");
        }
        this.spanNanos = spanNanos;
        this.capacity = capacity;
    }

    /** Adds {@code value} at {@code atNanos}; returns false if an older item had to be evicted to make room. */
    public boolean add(long atNanos, T value) {
        prune(atNanos);
        boolean room = items.size() < capacity;
        if (!room) {
            items.removeFirst();
            evicted++;
        }
        items.addLast(new Item<>(atNanos, value));
        return room;
    }

    /** Drops items at or before {@code nowNanos - span}: an item is in the window for exactly {@code span}. */
    public void prune(long nowNanos) {
        while (!items.isEmpty() && nowNanos - items.peekFirst().atNanos() >= spanNanos) {
            items.removeFirst();
        }
    }

    /** Values still in the window at {@code nowNanos}, oldest first. */
    public List<T> values(long nowNanos) {
        prune(nowNanos);
        List<T> out = new ArrayList<>(items.size());
        for (Iterator<Item<T>> it = items.iterator(); it.hasNext();) {
            out.add(it.next().value());
        }
        return out;
    }

    public boolean isEmpty(long nowNanos) {
        prune(nowNanos);
        return items.isEmpty();
    }

    public int size() {
        return items.size();
    }

    public long evicted() {
        return evicted;
    }
}
