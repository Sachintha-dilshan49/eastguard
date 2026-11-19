package eastguard.test;

import java.util.Arrays;
import java.util.Objects;

/** Minimal JDK-only assertions. Failures throw {@link AssertionError}. */
public final class Assert {
    private Assert() {
    }

    @FunctionalInterface
    public interface ThrowingRunnable {
        void run() throws Throwable;
    }

    public static void fail(String message) {
        throw new AssertionError(message);
    }

    public static void assertTrue(boolean condition, String message) {
        if (!condition) {
            fail(message);
        }
    }

    public static void assertFalse(boolean condition, String message) {
        assertTrue(!condition, message);
    }

    public static void assertEquals(Object expected, Object actual) {
        if (!Objects.equals(expected, actual)) {
            fail("expected <" + expected + "> but was <" + actual + ">");
        }
    }

    public static void assertEquals(long expected, long actual) {
        if (expected != actual) {
            fail("expected <" + expected + "> but was <" + actual + ">");
        }
    }

    public static void assertNull(Object actual) {
        if (actual != null) {
            fail("expected null but was <" + actual + ">");
        }
    }

    public static void assertArrayEquals(byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            fail("byte arrays differ: expected " + Arrays.toString(expected) + " but was " + Arrays.toString(actual));
        }
    }

    /** Runs {@code body}, requires it to throw {@code type}, and returns the exception. */
    public static <T extends Throwable> T assertThrows(Class<T> type, ThrowingRunnable body) {
        try {
            body.run();
        } catch (Throwable t) {
            if (type.isInstance(t)) {
                return type.cast(t);
            }
            AssertionError e = new AssertionError("expected " + type.getSimpleName() + " but got " + t);
            e.initCause(t);
            throw e;
        }
        throw new AssertionError("expected " + type.getSimpleName() + " but nothing was thrown");
    }
}
