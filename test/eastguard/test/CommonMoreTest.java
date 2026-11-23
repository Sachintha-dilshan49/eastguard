package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.CodecException;
import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * Tests for common package internal utilities: {@link eastguard.common.Frames}.
 */
public final class CommonMoreTest {

    public void testFramesReadExactly() throws Exception {
        byte[] data = new byte[] {1, 2, 3, 4, 5};
        ByteArrayInputStream in = new ByteArrayInputStream(data);

        // Access package-private Frames via reflection
        Class<?> cls = Class.forName("eastguard.common.Frames");
        var readExactly = cls.getDeclaredMethod("readExactly", java.io.InputStream.class, int.class);
        readExactly.setAccessible(true);

        byte[] read = (byte[]) readExactly.invoke(null, in, 3);
        assertArrayEquals(new byte[] {1, 2, 3}, read);

        // Attempting to read 5 more bytes from stream with only 2 left throws CodecException
        try {
            readExactly.invoke(null, in, 5);
            fail("expected CodecException on truncated read");
        } catch (java.lang.reflect.InvocationTargetException e) {
            assertTrue(e.getCause() instanceof CodecException, e.getCause().getClass().getName());
        }
    }

    public void testFramesConcat() throws Exception {
        Class<?> cls = Class.forName("eastguard.common.Frames");
        var concat = cls.getDeclaredMethod("concat", byte[].class, byte[].class);
        concat.setAccessible(true);

        byte[] a = new byte[] {1, 2};
        byte[] b = new byte[] {3, 4, 5};
        byte[] combined = (byte[]) concat.invoke(null, a, b);

        assertArrayEquals(new byte[] {1, 2, 3, 4, 5}, combined);
    }
}

