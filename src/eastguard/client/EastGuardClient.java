package eastguard.client;

import eastguard.common.Bytes;
import eastguard.common.CodecException;
import eastguard.common.Endpoint;
import eastguard.common.IssuerReply;
import eastguard.common.IssuerRequest;
import eastguard.common.Preamble;
import eastguard.common.ReplyStatus;
import eastguard.tokensvc.TlsContextFactory;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ProtocolException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * Java workload client (spec §4.2): obtains leases from the token service and presents them to gateways, both
 * over mTLS with this workload's own certificate.
 *
 * <p>The client's identity is whatever its certificate says; requests only name the target service. Every call
 * opens one connection and completes its exchange (connect, handshake, request, reply) within one total
 * deadline. There is no automatic retry, and no application byte is sent to a gateway before its reply.
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
     * @param timeout          total deadline per exchange: connect, handshake, request, and reply
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
        return exchange(issuer, issuerServerName, s -> {
            try (s) {
                OutputStream out = s.getOutputStream();
                out.write(frame);
                out.flush();
                try {
                    return IssuerReply.read(s.getInputStream());
                } catch (CodecException e) {
                    throw new ProtocolException("malformed token service reply: " + e.getMessage());
                }
            }
        });
    }

    /**
     * Opens an mTLS connection to a gateway, sends the lease preamble, and waits for the one-byte reply
     * (spec §4.2 step 2, §5.1). The returned session exposes the application streams only after {@code ALLOW};
     * for a denial it carries the status and the connection is already closed.
     *
     * @param gateway           numeric gateway endpoint
     * @param gatewayServerName DNS name or IP literal the gateway certificate must match
     * @param token             lease from {@link #requestLease}; reusable within its lifetime from this
     *                          certificate and source IP
     * @throws IOException on TLS failure, timeout, or a connection closed without a reply (e.g. a malformed
     *                     preamble, or a gateway at its connection limit)
     */
    public GatewaySession connect(Endpoint gateway, String gatewayServerName, Bytes token) throws IOException {
        Objects.requireNonNull(gateway, "gateway");
        byte[] preamble = new Preamble(Objects.requireNonNull(token, "token")).encode();
        return exchange(gateway, gatewayServerName, s -> {
            boolean keep = false;
            try {
                OutputStream out = s.getOutputStream();
                out.write(preamble);
                out.flush();
                int b = s.getInputStream().read();
                if (b < 0) {
                    throw new EOFException("gateway closed the connection without a reply");
                }
                ReplyStatus status;
                try {
                    status = Preamble.decodeReply(b);
                } catch (CodecException e) {
                    throw new ProtocolException("malformed gateway reply");
                }
                if (status != ReplyStatus.SUCCESS) {
                    return new GatewaySession(status, null);
                }
                s.setSoTimeout(0); // admitted: the application chooses its own read timeout
                keep = true;
                return new GatewaySession(status, s);
            } finally {
                if (!keep) {
                    s.close();
                }
            }
        });
    }

    /** Requests a lease for {@code serviceId} and presents it to that service's gateway. */
    public GatewaySession connect(String serviceId, Endpoint gateway, String gatewayServerName) throws IOException {
        IssuerReply lease = requestLease(serviceId);
        if (lease.status() != ReplyStatus.SUCCESS) {
            return new GatewaySession(lease.status(), null);
        }
        return connect(gateway, gatewayServerName, lease.token());
    }

    @FunctionalInterface
    private interface Exchange<T> {
        /** Runs on a connected, handshaken socket. Closes it, unless it hands it over in the result. */
        T run(SSLSocket s) throws IOException;
    }

    /**
     * Runs one exchange under the total deadline: a watchdog closes whatever socket is open when it passes,
     * wherever the call is blocked. A deadline that passes after the exchange finished still fails the call,
     * because the socket may have been closed under the result.
     */
    private <T> T exchange(Endpoint target, String serverName, Exchange<T> body) throws IOException {
        AtomicReference<SSLSocket> open = new AtomicReference<>();
        AtomicBoolean expired = new AtomicBoolean();
        CompletableFuture<Void> deadline = CompletableFuture.runAsync(() -> {
            expired.set(true);
            SSLSocket s = open.get();
            if (s != null) {
                try {
                    s.close();
                } catch (IOException ignored) {
                    // already failing
                }
            }
        }, CompletableFuture.delayedExecutor(timeout.toMillis(), TimeUnit.MILLISECONDS));
        SSLSocket s = null;
        try {
            s = TlsContextFactory.connect(ctx, target, serverName, timeout);
            open.set(s);
            if (expired.get()) {
                throw new IOException("deadline passed");
            }
            T result = body.run(s);
            deadline.cancel(false);
            if (expired.get()) {
                throw new IOException("deadline passed");
            }
            return result;
        } catch (IOException | RuntimeException e) {
            if (s != null) {
                s.close();
            }
            if (expired.get()) {
                throw new IOException("deadline of " + timeout.toMillis() + " ms passed", e);
            }
            throw e;
        } finally {
            deadline.cancel(false);
        }
    }
}
