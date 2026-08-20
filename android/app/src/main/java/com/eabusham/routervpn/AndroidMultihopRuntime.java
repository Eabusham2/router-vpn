package com.eabusham.routervpn;

import android.content.Context;

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
    private final Context context;
    private final NativeSingBoxController singBox;
    private final AndroidMultihopController builder;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private Future<?> active;
    private boolean transitioning;
    private boolean connected;
    private boolean disconnectRequested;
    private String activeEntryId = "";
    private String activeExitId = "";
    private String activeExitMode = "";

    AndroidMultihopRuntime(Context context, NativeSingBoxController singBox) {
        this.context = context.getApplicationContext();
        this.singBox = singBox;
        this.builder = new AndroidMultihopController(context, singBox);
        restoreFromPersistedState();
    }

    java.util.List<NativeSingBoxController.ModeInfo> listSupportedExitModes(File exitBundle) throws Exception {
        return builder.listSupportedExitModes(exitBundle);
    }

    synchronized boolean isActiveOrTransitioning() {
        reconcileRuntimeLocked();
        return transitioning || connected;
    }

    synchronized boolean isConnected() {
        reconcileRuntimeLocked();
        return connected;
    }

    synchronized String activeEntryId() {
        reconcileRuntimeLocked();
        return connected ? activeEntryId : "";
    }

    synchronized String activeExitId() {
        reconcileRuntimeLocked();
        return connected ? activeExitId : "";
    }

    synchronized String activeExitMode() {
        reconcileRuntimeLocked();
        return connected ? activeExitMode : "";
    }

    synchronized void connect(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, String exitMode, Callback callback) {
        if (closed.get()) { callback.finished(false, "Android multihop runtime is closed."); return; }
        reconcileRuntimeLocked();
        if (transitioning || connected || (active != null && !active.isDone())) { callback.finished(false, "Another Android multihop session is already active or starting."); return; }
        if (entry == null || exit == null || entry.id.equals(exit.id)) { callback.finished(false, "Multihop requires two different stored nodes."); return; }
        if (exitMode == null || exitMode.trim().isEmpty()) { callback.finished(false, "Choose a supported multihop exit transport."); return; }
        transitioning = true;
        disconnectRequested = false;
        clearActiveGraphLocked();
        AndroidHomeStateStore.beginMultihop(context, entry.id, exit.id, exitMode.trim());
        try {
            active = executor.submit(() -> run(entry, exit, exitMode.trim(), callback));
        } catch (RuntimeException error) {
            transitioning = false;
            AndroidHomeStateStore.failed(context, nonEmpty(error.getMessage(), "Could not start Android multihop worker."));
            callback.finished(false, nonEmpty(error.getMessage(), "Could not start Android multihop worker."));
        }
    }

    private void run(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, String exitMode, Callback callback) {
        boolean started = false;
        try {
            String before = singBox.getState();
            if ("UP".equals(before) || "STARTING".equals(before) || "STOPPING".equals(before)) throw new IllegalStateException("Disconnect the current embedded VPN before starting multihop.");
            callback.progress("Preparing WireGuard entry → " + exitMode + " exit…");
            AndroidMultihopController.Prepared prepared = builder.prepare(entry.file, exit.file, exitMode);
            if (Thread.currentThread().isInterrupted() || closed.get()) throw new InterruptedException("Multihop start cancelled.");
            callback.progress("Starting one Android VpnService multihop graph…");
            singBox.start(prepared.session);
            started = true;
            long deadline = System.currentTimeMillis() + START_TIMEOUT_MS;
            while (System.currentTimeMillis() < deadline) {
                if (Thread.currentThread().isInterrupted() || closed.get()) throw new InterruptedException("Multihop start cancelled.");
                String state = singBox.getState();
                if ("UP".equals(state)) break;
                if ("FAILED".equals(state) || "REVOKED".equals(state)) {
                    throw new IllegalStateException(nonEmpty(singBox.getError(), "Embedded multihop engine entered terminal state " + state + "."));
                }
                Thread.sleep(250L);
            }
            if (!"UP".equals(singBox.getState())) throw new IllegalStateException("Embedded multihop engine did not reach UP before timeout.");
            callback.progress("Tunnel is UP; proving the selected exit node before Connected…");
            if (!AndroidPathProbe.prove(prepared.exitBundle, PROBE_TIMEOUT_MS)) throw new IllegalStateException("Exit-node private path proof failed; multihop was disconnected.");
            synchronized (this) {
                if (disconnectRequested || closed.get() || Thread.currentThread().isInterrupted()) throw new InterruptedException("Multihop start cancelled.");
                transitioning = false;
                connected = true;
                activeEntryId = entry.id;
                activeExitId = exit.id;
                activeExitMode = prepared.exitMode;
            }
            AndroidHomeStateStore.connectedMultihop(context, entry.id, exit.id, prepared.exitMode);
            callback.finished(true, "Connected: " + entry.name + " → " + exit.name + " via WireGuard entry + " + prepared.exitMode + " exit. Exit-node private path proof passed.");
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            if (started) singBox.stop();
            boolean userCancelled;
            synchronized (this) {
                userCancelled = disconnectRequested || closed.get();
                transitioning = false;
                connected = false;
                clearActiveGraphLocked();
            }
            if (userCancelled) AndroidHomeStateStore.disconnected(context);
            else AndroidHomeStateStore.failed(context, "Android multihop start was interrupted and disconnected.");
            callback.finished(false, userCancelled ? "Android multihop cancelled and disconnected." : "Android multihop start was interrupted and disconnected.");
        } catch (Exception error) {
            if (started) singBox.stop();
            synchronized (this) {
                transitioning = false;
                connected = false;
                clearActiveGraphLocked();
            }
            String message = nonEmpty(error.getMessage(), "Android multihop failed closed.");
            AndroidHomeStateStore.failed(context, message);
            callback.finished(false, message);
        }
    }

    synchronized void disconnect() {
        disconnectRequested = true;
        transitioning = false;
        connected = false;
        clearActiveGraphLocked();
        if (active != null && !active.isDone()) active.cancel(true);
        singBox.stop();
        AndroidHomeStateStore.disconnected(context);
    }

    @Override public synchronized void close() {
        if (!closed.compareAndSet(false, true)) return;
        disconnectRequested = true;
        transitioning = false;
        connected = false;
        clearActiveGraphLocked();
        if (active != null && !active.isDone()) active.cancel(true);
        executor.shutdownNow();
    }

    private synchronized void restoreFromPersistedState() {
        AndroidHomeStateStore.Snapshot state = AndroidHomeStateStore.snapshot(context);
        if (state.connected && "multihop".equals(state.logicalMode) && !state.activeEntryId.isEmpty() && !state.activeExitId.isEmpty() && "UP".equals(singBox.getState())) {
            connected = true;
            transitioning = false;
            activeEntryId = state.activeEntryId;
            activeExitId = state.activeExitId;
            activeExitMode = state.runtimeMode;
        } else if (state.connected && "multihop".equals(state.logicalMode)) {
            AndroidHomeStateStore.failed(context, "Stored multihop state did not match an active embedded VPN engine; stale Connected state was cleared.");
        }
    }

    private void reconcileRuntimeLocked() {
        if (connected && !"UP".equals(singBox.getState())) {
            connected = false;
            transitioning = false;
            clearActiveGraphLocked();
            AndroidHomeStateStore.failed(context, "Android multihop engine is no longer UP; Connected state was cleared.");
        }
    }

    private void clearActiveGraphLocked() {
        activeEntryId = "";
        activeExitId = "";
        activeExitMode = "";
    }

    private static String nonEmpty(String value, String fallback) { return value == null || value.trim().isEmpty() ? fallback : value.trim(); }
}
