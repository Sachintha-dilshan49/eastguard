package eastguard.test;

import static eastguard.test.Assert.*;

import eastguard.common.CodecException;
import eastguard.common.NoticeOperation;
import eastguard.common.ReasonCode;
import eastguard.common.ReplyStatus;
import eastguard.common.SelectorType;
import eastguard.common.Verdict;
import java.util.HashSet;
import java.util.Set;

public final class CodesTest {

    public void testReasonCodesAreStable() {
        // These numbers are on the wire; changing one breaks every deployed detector.
        assertEquals(0, ReasonCode.OK.code());
        assertEquals(1, ReasonCode.INVALID_TOKEN.code());
        assertEquals(2, ReasonCode.EXPIRED.code());
        assertEquals(3, ReasonCode.WRONG_AUDIENCE.code());
        assertEquals(4, ReasonCode.IDENTITY_MISMATCH.code());
        assertEquals(5, ReasonCode.IP_MISMATCH.code());
        assertEquals(6, ReasonCode.POLICY_DENY.code());
        assertEquals(7, ReasonCode.QUARANTINED.code());
        assertEquals(8, ReasonCode.NOT_READY.code());
        assertEquals(9, ReasonCode.BACKEND_UNAVAILABLE.code());
        assertEquals(10, ReasonCode.THROTTLED.code());
        assertEquals(11, ReasonCode.DECOY_TOUCH.code());
        assertEquals(18, ReasonCode.BAD_IDENTITY.code());
    }

    public void testReasonCodesRoundTripAndAreUnique() throws Exception {
        Set<Integer> seen = new HashSet<>();
        for (ReasonCode r : ReasonCode.values()) {
            assertTrue(seen.add(r.code()), "duplicate code " + r.code());
            assertEquals(r, ReasonCode.fromCode(r.code()));
        }
    }

    public void testUnknownCodesRejected() {
        for (int bad : new int[] {-1, 19, 255, 256}) {
            assertThrows(CodecException.class, () -> ReasonCode.fromCode(bad));
        }
        assertThrows(CodecException.class, () -> Verdict.fromCode(3));
        assertThrows(CodecException.class, () -> ReplyStatus.fromCode(4));
        assertThrows(CodecException.class, () -> NoticeOperation.fromCode(0));
        assertThrows(CodecException.class, () -> NoticeOperation.fromCode(3));
        assertThrows(CodecException.class, () -> SelectorType.fromCode(0));
        assertThrows(CodecException.class, () -> SelectorType.fromCode(3));
    }

    public void testSmallEnumsMatchSpec() throws Exception {
        assertEquals(Verdict.DECOY, Verdict.fromCode(2));
        assertEquals(ReplyStatus.UNAVAILABLE, ReplyStatus.fromCode(3));
        assertEquals(NoticeOperation.RELEASE, NoticeOperation.fromCode(2));
        assertEquals(SelectorType.IP, SelectorType.fromCode(2));
    }

    public void testReplyStatusForReason() {
        assertEquals(ReplyStatus.SUCCESS, ReplyStatus.forReason(ReasonCode.OK));
        assertEquals(ReplyStatus.QUARANTINED, ReplyStatus.forReason(ReasonCode.QUARANTINED));
        assertEquals(ReplyStatus.UNAVAILABLE, ReplyStatus.forReason(ReasonCode.NOT_READY));
        assertEquals(ReplyStatus.UNAVAILABLE, ReplyStatus.forReason(ReasonCode.BACKEND_UNAVAILABLE));
        assertEquals(ReplyStatus.DENY, ReplyStatus.forReason(ReasonCode.INVALID_TOKEN));
        assertEquals(ReplyStatus.DENY, ReplyStatus.forReason(ReasonCode.LEASE_SUPERSEDED));
    }
}
