package com.eabusham.routervpn;

import android.content.Context;
import android.os.SystemClock;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Process owner for one ordered native graph, including its retryable drain.
 * Home state and private files are receipts, never permission to reconstruct a
 * native owner after process death. */
final class AndroidNodeChainRuntime implements AutoCloseable {
    interface Callback {
        void progress(String message);
        void finished(boolean ok, String message);
        default void owned(String homeSession) {}
    }
    private static final Callback SILENT = new Callback() {
        public void progress(String ignored) {}
        public void finished(boolean ok, String ignored) {}
    };
    private final Context context;
    private final NativeSingBoxController singBox;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private AndroidNodeChainSession owner;
    private boolean transitioning, connected, stopping, closed, submitted;
    private long operation;

    AndroidNodeChainRuntime(Context context, NativeSingBoxController singBox) {
        this.context = context.getApplicationContext(); this.singBox = singBox;
    }

    private void reconcile() {
        if (owner != null && owner.released()) { owner = null; connected = false; submitted = false; }
    }
    synchronized boolean isActiveOrTransitioning() { reconcile(); return transitioning || owner != null; }
    private AndroidNodeChainSession connectedOwner() {
        AndroidNodeChainSession captured;
        synchronized (this) { reconcile(); captured = connected && !stopping ? owner : null; }
        // Never hold the runtime monitor across source-store or native reads.
        // Store mutation admission also consults the runtime's busy state.
        if (captured == null || !LayeredVpnService.nodeChainReady(captured)) return null;
        synchronized (this) { return owner == captured && connected && !stopping ? captured : null; }
    }
    boolean isConnected() { return connectedOwner() != null; }
    static final class ActiveCapture {
        final String homeSession;
        final long pathGeneration;
        final String progressJSON;
        final List<AndroidNodeStore.ChainSource> sources;
        final List<String> modes;
        private ActiveCapture(AndroidNodeChainSession owner,String progress) { homeSession=owner.home.sessionId;pathGeneration=owner.home.pathGeneration;progressJSON=progress;sources=owner.source.members;modes=owner.source.modes; }
    }
    ActiveCapture captureActive() {
        AndroidNodeChainSession captured=connectedOwner();
        if(captured==null)return null;
        try {
            String progress=captured.progressJSON();
            if(progress==null||progress.length()>65536||connectedOwner()!=captured)return null;
            return new ActiveCapture(captured,progress);
        } catch(Exception retired) { return null; }
    }
    List<AndroidNodeStore.ChainSource> activeSources() {
        AndroidNodeChainSession captured = connectedOwner();
        return captured == null ? Collections.emptyList() : captured.source.members;
    }
    List<String> activeModes() {
        AndroidNodeChainSession captured = connectedOwner();
        return captured == null ? Collections.emptyList() : captured.source.modes;
    }

    void connect(AndroidNodeStore.ChainCapture capture, Callback callback) { connect(capture, AndroidHomeStateStore.snapshot(context), callback); }
    synchronized void connect(AndroidNodeStore.ChainCapture capture, AndroidHomeStateStore.Snapshot idle, Callback callback) {
        reconcile();
        if (closed || transitioning || owner != null || !terminal(singBox.getState())) {
            callback.finished(false, "The previous native owner must finish cleanup before an ordered path can start."); return;
        }
        transitioning = true; stopping = false; submitted = false;
        long selectedOperation=++operation;
        executor.execute(() -> launch(capture, idle, selectedOperation, callback));
    }

    private void launch(AndroidNodeStore.ChainCapture source, AndroidHomeStateStore.Snapshot idle, long selectedOperation, Callback callback) {
        AndroidHomeStateStore.Snapshot home = null;
        AndroidNodeChainSession session = null;
        try {
            if (source == null) throw new IllegalStateException("The original ordered selection is missing.");
            source.requireCurrent(); requireStarting(selectedOperation);
            synchronized (AndroidHomeStateStore.class) {
                AndroidHomeStateStore.Snapshot now = AndroidHomeStateStore.snapshot(context);
                if (idle == null || now.connected || AndroidHomeStateStore.emergencyDisconnectPending(context)
                        || !idle.sessionId.equals(now.sessionId) || idle.pathGeneration != now.pathGeneration
                        || !idle.phase.equals(now.phase) || !("off".equals(now.phase) || "disconnected".equals(now.phase) || "failed".equals(now.phase))) {
                    throw new IllegalStateException("The captured idle Home owner changed before ordered startup.");
                }
                home = AndroidHomeStateStore.beginNodeChain(context, source);
            }
            callback.owned(home.sessionId);
            callback.progress("Preparing every original ordered node and authenticated layer…");
            session = new AndroidNodeChainSession(context, source, home);
            synchronized (this) { requireStarting(selectedOperation); owner = session; }
            requireStarting(selectedOperation); session.stage(); requireStarting(selectedOperation);
            synchronized (this) { requireStarting(selectedOperation); submitted = true; }
            singBox.startNodeChain(session.request, home.sessionId);
            long deadline = SystemClock.elapsedRealtime() + 30000L + 30000L * source.members.size();
            while (SystemClock.elapsedRealtime() < deadline) {
                requireStarting(selectedOperation); session.requireSource();
                if (LayeredVpnService.nodeChainReady(session)) break;
                if (session.released() || session.claimed() && ("FAILED".equals(singBox.getState()) || "REVOKED".equals(singBox.getState())))
                    throw new IllegalStateException("The native ordered path failed: " + singBox.getError());
                Thread.sleep(50);
            }
            requireStarting(selectedOperation); session.requireSource();
            if (!LayeredVpnService.nodeChainReady(session)) throw new IllegalStateException("The complete ordered path did not finish its native proof before timeout.");
            if (!AndroidHomeStateStore.connectedNodeChain(context, home)) throw new IllegalStateException("The original ordered Home selection changed during proof.");
            if (!LayeredVpnService.nodeChainReady(session)) throw new IllegalStateException("The complete native proof expired before Connected delivery.");
            synchronized (this) {
                requireStarting(selectedOperation); connected = true; transitioning = false;
            }
            LayeredVpnService.startNodeChainAutomaticMTU(session);
            callback.finished(true, "Every ordered node and selected DNS passed the original native path proof.");
        } catch (Throwable failure) {
            String message = safe(failure);
            AndroidHomeStateStore.failedNodeChain(context, home, message, false);
            boolean clean = stopOwned(session);
            AndroidHomeStateStore.failedNodeChain(context, home, message, clean);
            synchronized (this) { if(operation==selectedOperation){connected = false; transitioning = false; reconcile();} }
            callback.finished(false, clean ? message : message + " Native cleanup remains pending; retry Disconnect.");
        }
    }

    private synchronized void requireStarting(long selectedOperation) {
        if (operation != selectedOperation || closed || stopping || !transitioning) throw new IllegalStateException("The ordered connection was cancelled.");
    }

    void disconnect() { disconnect(SILENT); }
    void disconnect(Callback callback) {
        final long selectedOperation;
        synchronized (this) { selectedOperation=operation;stopping = true; connected = false; if (owner != null) owner.cancel(); }
        executor.execute(() -> {
            boolean clean = stopOperation(selectedOperation);
            callback.finished(clean, clean ? "Ordered path disconnected." : "Ordered native cleanup is still pending; its original owner is retained.");
        });
    }

    /** Background callers only. A failed join keeps the exact owner for retry. */
    boolean stopAndProve() {
        final long selectedOperation;
        synchronized(this){selectedOperation=operation;}
        return stopOperation(selectedOperation);
    }
    private boolean stopOperation(long selectedOperation) {
        AndroidNodeChainSession captured;
        synchronized (this) {
            if(operation!=selectedOperation)return true; // A newer admission required the old owner to release first.
            stopping = true; connected = false; captured = owner; if (captured != null) captured.cancel(); else if (transitioning) return false;
        }
        boolean clean = stopOwned(captured);
        synchronized (this) { if (clean && operation==selectedOperation) { transitioning = false; reconcile(); } }
        synchronized(this){if (clean && captured != null && operation==selectedOperation) AndroidHomeStateStore.disconnectedNodeChain(context, captured.home);}
        return clean;
    }

    private boolean stopOwned(AndroidNodeChainSession captured) {
        if (captured == null) return true;
        captured.cancel();
        if (captured.released()) return true;
        try {
            boolean delivered;
            synchronized (this) { delivered = owner == captured && submitted; }
            if (delivered || captured.claimed()) singBox.stopNodeChain(captured.sessionId);
            else captured.discardUnstarted();
            long deadline = SystemClock.elapsedRealtime() + 12000L;
            while (!captured.released() && SystemClock.elapsedRealtime() < deadline) Thread.sleep(25);
            return captured.released();
        } catch (Exception pending) { return false; }
    }

    void networkChanged(AndroidHomeStateStore.Snapshot home) {
        AndroidNodeChainSession captured;
        final long selectedOperation;
        synchronized (this) {
            captured = owner;
            if (captured == null || !captured.home.sessionId.equals(home.sessionId)) return;
            selectedOperation=operation;
            stopping = true; connected = false; captured.cancel();
        }
        AndroidHomeStateStore.failedNodeChain(context, captured.home,
                "The physical network changed; reconnect to prove the complete original ordered path.", false);
        executor.execute(() -> {
            boolean clean = stopOwned(captured);
            AndroidHomeStateStore.failedNodeChain(context, captured.home,
                    "The physical network changed; reconnect to prove every ordered member and selected DNS.", clean);
            synchronized (this) { if(operation==selectedOperation){transitioning = false; reconcile();} }
        });
    }

    static final class RestoreCapture {
        final AndroidNodeStore.ChainCapture source;
        private final AndroidNodeChainSession original;
        private RestoreCapture(AndroidNodeChainSession owner) { original = owner; source = owner.source; }
    }
    RestoreCapture captureRestore() throws Exception {
        AndroidNodeChainSession captured = connectedOwner();
        if (captured == null) throw new IllegalStateException("The original proved ordered owner is unavailable.");
        captured.requireCurrent();
        RestoreCapture value = new RestoreCapture(captured);
        if (!captureCurrent(value)) throw new IllegalStateException("The ordered source changed during restore capture.");
        return value;
    }
    boolean captureCurrent(RestoreCapture capture) {
        try {
            if (capture == null || connectedOwner() != capture.original) return false;
            capture.source.requireCurrent(); return connectedOwner() == capture.original;
        } catch (Exception stale) { return false; }
    }
    void restore(RestoreCapture capture, AndroidHomeStateStore.Snapshot idle, Callback callback) {
        try {
            if (capture == null || idle == null || !capture.original.released()) throw new IllegalStateException("The original ordered native owner has not completed its drain.");
            capture.source.requireCurrent();
            connect(capture.source, idle, callback);
        } catch (Exception stale) { callback.finished(false, safe(stale)); }
    }
    @Override public void close() { synchronized (this) { closed = true; } disconnect(); }
    private static boolean terminal(String state) { return "DOWN".equals(state) || "FAILED".equals(state) || "REVOKED".equals(state); }
    private static String safe(Throwable failure) {
        String value = failure.getMessage();
        return value == null || value.trim().isEmpty() ? "The original ordered path could not be proved." : value.replace('\n', ' ').replace('\r', ' ').trim();
    }
}
