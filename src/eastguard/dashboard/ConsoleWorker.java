package eastguard.dashboard;

import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * The dashboard's only path to the network (spec §7.3 threading): <b>one</b> background thread with a queue of
 * {@link #QUEUE} tasks. At most one poll is outstanding at a time; a poll requested while one is queued or
 * running is refused, not queued. Results and failures are handed to the UI executor (the EDT in the
 * application), so components are only ever touched there. A call that hangs ties up only this thread: the UI
 * keeps running, and the controller marks the view stale.
 */
public final class ConsoleWorker implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(ConsoleWorker.class.getName());
    public static final int QUEUE = 4;

    private final ThreadPoolExecutor executor;
    private final Executor ui;
    private final AtomicBoolean pollOutstanding = new AtomicBoolean();

    /** @param ui runs result callbacks: {@code SwingUtilities::invokeLater} in the application */
    public ConsoleWorker(Executor ui) {
        this.ui = Objects.requireNonNull(ui, "ui");
        this.executor = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(QUEUE), r -> {
            Thread t = new Thread(r, "console-rmi");
            t.setDaemon(true);
            return t;
        }, new ThreadPoolExecutor.AbortPolicy());
    }

    /** True while a poll is queued or running. */
    public boolean pollOutstanding() {
        return pollOutstanding.get();
    }

    /**
     * Starts a poll unless one is outstanding or the queue is full.
     *
     * @return {@code false} if nothing was started
     */
    public <T> boolean poll(Callable<T> call, Consumer<T> onResult, Consumer<Exception> onFailure) {
        if (!pollOutstanding.compareAndSet(false, true)) {
            return false;
        }
        if (!run(call, onResult, onFailure, () -> pollOutstanding.set(false))) {
            pollOutstanding.set(false);
            return false;
        }
        return true;
    }

    /**
     * Queues a one-off task (a mutation).
     *
     * @return {@code false} if the queue is full or the worker is closed
     */
    public <T> boolean submit(Callable<T> call, Consumer<T> onResult, Consumer<Exception> onFailure) {
        return run(call, onResult, onFailure, () -> { });
    }

    private <T> boolean run(Callable<T> call, Consumer<T> onResult, Consumer<Exception> onFailure, Runnable done) {
        try {
            executor.execute(() -> {
                T result;
                try {
                    result = call.call();
                } catch (Exception e) {
                    done.run();
                    deliver(() -> onFailure.accept(e));
                    return;
                } catch (Error e) {
                    done.run();
                    throw e;
                }
                done.run();
                deliver(() -> onResult.accept(result));
            });
            return true;
        } catch (RejectedExecutionException e) {
            LOG.fine("console worker busy or closed; task refused");
            return false;
        }
    }

    private void deliver(Runnable r) {
        try {
            ui.execute(r);
        } catch (RejectedExecutionException e) {
            LOG.fine("UI closed; result dropped"); // the window is gone
        }
    }

    /** Interrupts a hanging call and stops the thread. */
    @Override
    public void close() {
        executor.shutdownNow();
    }
}
