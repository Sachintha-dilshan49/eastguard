package eastguard.control;

import eastguard.common.Bytes;
import eastguard.common.CodecException;
import eastguard.common.Ids;
import eastguard.common.Sha256;
import eastguard.common.WireReader;
import eastguard.common.WireWriter;
import java.util.Objects;

/**
 * One committed enforcement mutation as stored in the journal: the state change and its audit metadata in the
 * same record (spec §7.2). Only committed mutations are journaled.
 *
 * <pre>
 * "EGJ1" | revision:i64 | atMs:i64 | actor:id | role:u8 | requestId:optId | requestDigest:32 | reason:text
 *        | op:u8 | body (see {@link Mutation})
 * </pre>
 *
 * @param requestId     caller-scoped idempotency key; null for the control plane's own transitions
 * @param requestDigest SHA-256 of the request's canonical payload, to tell an identical retry from ID reuse
 */
public record JournalRecord(long revision, long atMillis, String actor, Role role, String requestId,
        Bytes requestDigest, String reason, Mutation mutation) {
    public static final String MAGIC = "EGJ1";
    public static final int MAX_REASON_BYTES = 512;

    public JournalRecord {
        if (revision < 1 || atMillis < 0) {
            throw new IllegalArgumentException("revision and time must be positive");
        }
        Ids.require(actor, "actor");
        Objects.requireNonNull(role, "role");
        Ids.requireOptional(requestId, "requestId");
        Objects.requireNonNull(requestDigest, "requestDigest").requireLength(Sha256.LENGTH, "requestDigest");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(mutation, "mutation");
    }

    public byte[] encode() {
        WireWriter w = new WireWriter().ascii(MAGIC).nonNegative(revision, "revision").nonNegative(atMillis, "at")
                .id(actor).u8(role.code()).optId(requestId).fixed(requestDigest, Sha256.LENGTH, "requestDigest")
                .text(reason).u8(mutation.code());
        mutation.writeBody(w);
        return w.toByteArray();
    }

    public static JournalRecord decode(byte[] payload) throws CodecException {
        WireReader r = new WireReader(payload);
        try {
            r.magic(MAGIC);
            long revision = r.nonNegative("revision");
            long at = r.nonNegative("at");
            String actor = r.id();
            Role role = Role.fromCode(r.u8());
            String requestId = r.optId();
            Bytes digest = r.fixed(Sha256.LENGTH);
            String reason = r.text(MAX_REASON_BYTES);
            Mutation m = Mutation.readBody(r.u8(), r);
            r.end();
            return new JournalRecord(revision, at, actor, role, requestId, digest, reason, m);
        } catch (IllegalArgumentException e) {
            throw new CodecException("invalid journal record: " + e.getMessage());
        }
    }
}
