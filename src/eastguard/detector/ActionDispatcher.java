package eastguard.detector;

import eastguard.control.Dto;
import eastguard.control.Dto.MutationResult;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * Sends proposals and observation batches to the control plane off the receive thread (RMI calls block). One
 * worker thread and a bounded queue: when it is full, the task is dropped and counted rather than queued without
 * limit. A transport failure is retried a few times with the <em>same</em> request ID, so a commit whose reply was
 * lost is returned as a replay instead of being committed twice (spec §7.1).
 */
public final class ActionDispatcher implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(ActionDispatcher.class.getName());

    /** One completed call: {@code result} on an answer, {@code error} when every attempt failed in transport. */
    public record Outcome(String requestId, String what, MutationResult result, String error) {
        public boolean committed() {
            return result != null && result.ok();
        }
    }

    @FunctionalInterface
    private interface Call {
        MutationResult run() throws IOException;
    }

    private final DetectorControl control;
    private final int attempts;
    private final long backoffMillis;
    private final ThreadPoolExecutor worker;
    private final AtomicLong submitted = new AtomicLong();
    private final AtomicLong completed = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final ArrayDeque<Outcome> recent = new ArrayDeque<>();

    public ActionDispatcher(DetectorControl control, int queueCapacity, int attempts, long backoffMillis) {
        this.control = Objects.requireNonNull(control, "control");
        if (queueCapacity < 1 || attempts < 1 || backoffMillis < 0) {
            throw new IllegalArgumentException("dispatcher settings out of range");
        }
        this.attempts = attempts;
        this.backoffMillis = backoffMillis;
        this.worker = new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(queueCapacity), r -> {
            Thread t = new Thread(r, "detector-control");
            t.setDaemon(true);
            return t;
        }, new ThreadPoolExecutor.AbortPolicy());
    }

    public boolean propose(String requestId, RiskEngine.Proposal p, Duration ttl) {
        Dto.ActionType type = p.type() == RiskEngine.ActionType.QUARANTINE ? Dto.ActionType.QUARANTINE
                : Dto.ActionType.LEASE_REDUCTION;
        return submit(requestId, type + " " + p.selector(), () -> control.proposeAction(requestId, type,
                List.of(p.selector()), ttl, p.score(), p.signals(), p.evidence()));
    }

    public boolean observe(String requestId, List<Dto.Observation> batch) {
        return submit(requestId, "observations x" + batch.size(), () -> control.recordObservations(requestId, batch));
    }

    private boolean submit(String requestId, String what, Call call) {
        submitted.incrementAndGet();
        try {
            worker.execute(() -> run(requestId, what, call));
            return true;
        } catch (RejectedExecutionException e) {
            submitted.decrementAndGet();
            dropped.incrementAndGet();
            LOG.warning(() -> "control-plane queue full: dropped " + what + " (" + requestId + ")");
            return false;
        }
    }

    private void run(String requestId, String what, Call call) {
        Outcome o = null;
        try {
            for (int i = 1; i <= attempts && o == null; i++) {
                try {
                    MutationResult r = call.run();
                    o = new Outcome(requestId, what, r, null);
                } catch (IOException e) {
                    if (i == attempts) {
                        o = new Outcome(requestId, what, null, e.getClass().getSimpleName());
                    } else {
                        Thread.sleep(backoffMillis * i);
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            o = new Outcome(requestId, what, null, "interrupted");
        } catch (RuntimeException e) {
            o = new Outcome(requestId, what, null, e.getClass().getSimpleName());
        }
        Outcome done = o;
        LOG.info(() -> "control plane " + what + " (" + requestId + "): " + (done.result() == null ? "failed: " + done.error()
                : done.result().ok() ? (done.result().replayed() ? "replayed" : "ok") + " rev=" + done.result().revision()
                : done.result().error() + " " + done.result().message()));
        synchronized (recent) {
            recent.addLast(done);
            while (recent.size() > 200) {
                recent.removeFirst();
            }
        }
        completed.incrementAndGet();
    }

    /** Waits until everything submitted so far has completed, or the timeout passes. */
    public boolean awaitIdle(Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (completed.get() < submitted.get()) {
            if (System.nanoTime() >= deadline) {
                return false;
            }
            Thread.sleep(5);
        }
        return true;
    }

    public List<Outcome> recent() {
        synchronized (recent) {
            return List.copyOf(recent);
        }
    }

    public long dropped() {
        return dropped.get();
    }

    @Override
    public void close() {
        worker.shutdown();
        try {
            if (!worker.awaitTermination(5, TimeUnit.SECONDS)) {
                worker.shutdownNow();
            }
        } catch (InterruptedException e) {
            worker.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
