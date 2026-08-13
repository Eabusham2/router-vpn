package com.eabusham.routervpn;

import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/** Starts a prepared multihop graph and accepts Connected only after exit-node private path proof. */
final class AndroidMultihopRuntime implements AutoCloseable {
    interface Callback {
        void progress(String message);
        void finished(boolean ok, String message);
    }

    private static final long START_TIMEOUT_MS = 20000L;
    private static final int PROBE_TIMEOUT_MS = 5000;
    private final NativeSingBoxController singBox;
    private final AndroidMultihopController builder;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private Future<?> active;

    AndroidMultihopRuntime(android.content.Context context, NativeSingBoxController singBox) {
        this.singBox = singBox;
        this.builder = new AndroidMultihopController(context, singBox);
    }

    java.util.List<NativeSingBoxController.ModeInfo> listSupportedExitModes(File exitBundle) throws Exception {
        return builder.listSupportedExitModes(exitBundle);
    }

    synchronized void connect(File entryBundle, File exitBundle, String exitMode, Callback callback) {
        if (closed.get()) { callback.finished(false, "Android multihop runtime is closed."); return; }
        if (active != null && !active.isDone()) { callback.finished(false, "Another Android multihop attempt is already running."); return; }
        active = executor.submit(() -> run(entryBundle, exitBundle, exitMode, callback));
    }

    private void run(File entryBundle, File exitBundle, String exitMode, Callback callback) {
        boolean started = false;
        try {
            String before = singBox.getState();
            if ("UP".equals(before) || "STARTING".equals(before) || "STOPPING".equals(before)) throw new IllegalStateException("Disconnect the current embedded VPN before starting multihop.");
            callback.progress("Preparing WireGuard entry → " + exitMode + " exit…");
            AndroidMultihopController.Prepared prepared = builder.prepare(entryBundle, exitBundle, exitMode);
            if (Thread.currentThread().isInterrupted() || closed.get()) throw new InterruptedException("Multihop start cancelled.");
            callback.progress("Starting one Android VpnService multihop graph…");
            singBox.start(prepared.session);
            started = true;
            long deadline = System.currentTimeMillis() + START_TIMEOUT_MS;
            while (System.currentTimeMillis() < deadline) {
                if (Thread.currentThread().isInterrupted() || closed.get()) throw new InterruptedException("Multihop start cancelled.");
                String state = singBox.getState();
                if ("UP".equals(state)) break;
                if ("ERROR".equals(state)) throw new IllegalStateException(nonEmpty(singBox.getError(), "Embedded multihop engine failed."));
                if ("DOWN".equals(state) && System.currentTimeMillis() + 500L < deadline) { Thread.sleep(250L); continue; }
                Thread.sleep(250L);
            }
            if (!"UP".equals(singBox.getState())) throw new IllegalStateException("Embedded multihop engine did not reach UP before timeout.");
            callback.progress("Tunnel is UP; proving the selected exit node before Connected…");
            if (!AndroidPathProbe.prove(prepared.exitBundle, PROBE_TIMEOUT_MS)) throw new IllegalStateException("Exit-node private path proof failed; multihop was disconnected.");
            callback.finished(true, "Connected: WireGuard entry → " + prepared.exitMode + " exit. Exit-node private path proof passed. Expect higher latency than single-hop.");
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            if (started) singBox.stop();
            callback.finished(false, "Android multihop cancelled and disconnected.");
        } catch (Exception error) {
            if (started) singBox.stop();
            callback.finished(false, nonEmpty(error.getMessage(), "Android multihop failed closed."));
        }
    }

    synchronized void disconnect() {
        if (active != null && !active.isDone()) active.cancel(true);
        singBox.stop();
    }

    @Override public synchronized void close() {
        if (!closed.compareAndSet(false, true)) return;
        if (active != null && !active.isDone()) active.cancel(true);
        executor.shutdownNow();
    }

    private static String nonEmpty(String value, String fallback) { return value == null || value.trim().isEmpty() ? fallback : value.trim(); }
}
