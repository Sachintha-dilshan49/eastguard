package eastguard.common;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;

/**
 * Where a secret (keystore password, MAC key) comes from: an environment variable, else a protected file
 * (spec §9.1: never in sample files or command-line arguments). Only the variable name and file path appear in
 * {@link #toString()} and error messages, never the value.
 *
 * @param envVar environment variable consulted first; ignored when unset or empty
 * @param file   fallback file holding the secret as UTF-8, trailing whitespace ignored; may be {@code null}
 */
public record SecretSource(String envVar, Path file) {
    public SecretSource {
        Objects.requireNonNull(envVar, "envVar");
        if (envVar.isEmpty()) {
            throw new IllegalArgumentException("envVar empty");
        }
    }

    /** Returns a fresh array the caller should clear when done. */
    public char[] read() {
        String env = System.getenv(envVar);
        if (env != null && !env.isEmpty()) {
            return env.toCharArray();
        }
        if (file == null || !Files.isRegularFile(file)) {
            throw new IllegalStateException("secret not configured: set " + envVar
                    + (file == null ? "" : " or create " + file));
        }
        byte[] raw = null;
        CharBuffer chars = null;
        try {
            raw = Files.readAllBytes(file);
            chars = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw));
            int end = chars.limit();
            while (end > 0 && Character.isWhitespace(chars.get(end - 1))) {
                end--;
            }
            if (end == 0) {
                throw new IllegalStateException("secret file is empty: " + file);
            }
            char[] out = new char[end];
            chars.get(0, out);
            return out;
        } catch (CharacterCodingException e) {
            throw new IllegalStateException("secret file is not UTF-8: " + file);
        } catch (IOException e) {
            throw new IllegalStateException("cannot read secret file: " + file, e);
        } finally {
            if (raw != null) {
                Arrays.fill(raw, (byte) 0);
            }
            if (chars != null && chars.hasArray()) {
                Arrays.fill(chars.array(), '\0');
            }
        }
    }
}
