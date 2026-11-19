package eastguard.client;

import eastguard.common.CodecException;
import eastguard.common.Endpoint;
import eastguard.common.IssuerReply;
import eastguard.common.IssuerRequest;
import eastguard.tokensvc.TlsContextFactory;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ProtocolException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * Java workload client (spec §4.2). This part obtains leases from the token service over mTLS; the gateway
 * connection that presents them is added with the NIO gateway (Task 5).
 *
 * <p>The client's identity is whatever its certificate says; the request only names the target service. Each
 * call opens one connection, sends one {@code EGI1} frame, and reads one reply within a total deadline. There is
 * no automatic retry.
 */
public final class EastGuardClient {
    private final SSLContext ctx;
    private final Endpoint issuer;
    private final String issuerServerName;
    private final Duration timeout;

    /**
     * @param ctx              this workload's own TLS context (its certificate and the EastGuard trust store)
     * @param issuer           numeric token service endpoint
     * @param issuerServerName DNS name or IP literal the token service certificate must match
     * @param timeout          total deadline per request: connect, handshake, request, and reply
     */
    public EastGuardClient(SSLContext ctx, Endpoint issuer, String issuerServerName, Duration timeout) {
        this.ctx = Objects.requireNonNull(ctx, "ctx");
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.issuerServerName = Objects.requireNonNull(issuerServerName, "issuerServerName");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        if (timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("timeout must be positive");
        }
    }

    /**
     * Requests a lease for {@code serviceId}. Returns the issuer's reply (success with token, or a coarse
     * denial status). TLS failures, timeouts, and malformed replies throw {@link IOException}. With TLS 1.3 the
     * server rejects a client certificate after the client's side of the handshake is complete, so that case
     * surfaces on the first read, as an {@link javax.net.ssl.SSLException} or, if a TCP reset discards the
     * alert, a {@link java.net.SocketException}.
     *
     * @throws IllegalArgumentException if {@code serviceId} is not a valid id
     */
    public IssuerReply requestLease(String serviceId) throws IOException {
        byte[] frame = new IssuerRequest(serviceId).encode();
        AtomicReference<SSLSocket> open = new AtomicReference<>();
        // Total deadline: close whatever socket is open when it passes, wherever the call is blocked.
        CompletableFuture<Void> deadline = CompletableFuture.runAsync(() -> {
            SSLSocket s = open.get();
            if (s != null) {
                try {
                    s.close();
                } catch (IOException ignored) {
                    // already failing
                }
            }
        }, CompletableFuture.delayedExecutor(timeout.toMillis(), TimeUnit.MILLISECONDS));
        try (SSLSocket s = TlsContextFactory.connect(ctx, issuer, issuerServerName, timeout)) {
            open.set(s);
            if (deadline.isDone()) {
                throw new IOException("token request deadline passed");
            }
            OutputStream out = s.getOutputStream();
            out.write(frame);
            out.flush();
            try {
                return IssuerReply.read(s.getInputStream());
            } catch (CodecException e) {
                throw new ProtocolException("malformed token service reply: " + e.getMessage());
            }
        } finally {
            deadline.cancel(false);
        }
    }
}
