package eastguard.test;

import static eastguard.test.Assert.*;

/** Trivial sample test: proves the runner discovers tests and that the assert helpers really fail. */
public final class SmokeTest {

    public void testArithmetic() {
        assertEquals(4, 2 + 2);
        assertTrue("east".concat("guard").equals("eastguard"), "string concat");
    }

    public void testAssertEqualsDetectsMismatch() {
        AssertionError e = assertThrows(AssertionError.class, () -> assertEquals(1, 2));
        assertEquals("expected <1> but was <2>", e.getMessage());
    }

    public void testAssertThrowsFailsWhenNothingThrown() {
        assertThrows(AssertionError.class, () -> assertThrows(IllegalStateException.class, () -> { }));
    }
}
