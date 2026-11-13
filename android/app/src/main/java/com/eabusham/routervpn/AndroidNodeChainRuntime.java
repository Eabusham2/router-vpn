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
        default void validate() throws Exception {}
    }
    /** The preparation owner retains its physical cohort and measurement lease.
     * Draining that owner must finish before its original graph can be stopped. */
    interface TemporaryGuard {
        void requireCurrent() throws Exception;
        void cancel();
        boolean drain();
    }
    private static final Callback SILENT = new Callback() {
        public void progress(String ignored) {}
        public void finished(boolean ok, String ignored) {}
    };
    private final Context context;
    private final NativeSingBoxController singBox;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private AndroidNodeChainSession owner;
    private Temporary temporary;
    private AndroidNodeChainSession capturedDrain;
    private long capturedDrainOperation, capturedDrainGeneration;
    private boolean capturedDrainRestoreAuthorized;
    private boolean transitioning, connected, stopping, closed, submitted;
    private long operation;

    AndroidNodeChainRuntime(Context context, NativeSingBoxController singBox) {
        this.context = context.getApplicationContext(); this.singBox = singBox;
    }

    private void reconcile() {
        if (owner != null && owner.released() && owner != capturedDrain) { owner = null; connected = false; submitted = false; }
    }
    synchronized boolean isActiveOrTransitioning() { reconcile(); return transitioning || owner != null || temporary != null; }

    /** Opaque authority for one initially idle, complete saved Local graph.
     * This does not prepare a prefix independently of the saved final node. */
    final class Temporary {
        private final AndroidNodeStore.ChainCapture source;
        private final AndroidHomeStateStore.Snapshot idle;
        private final String selected;
        private final long selectedOperation;
        private final TemporaryGuard guard;
        private final Callback observer;
        private boolean started, finished, cancelled;
        private Temporary(AndroidNodeStore.ChainCapture source, AndroidHomeStateStore.Snapshot idle,
                          String selected, long selectedOperation, TemporaryGuard guard, Callback observer) {
            this.source=source;this.idle=idle;this.selected=selected;this.selectedOperation=selectedOperation;
            this.guard=guard;this.observer=observer;
        }
        // Reserve before starting so even an immediate failure cannot run a
        // completion callback before the caller retains its cleanup authority.
        void start() {
            synchronized(AndroidNodeChainRuntime.this) {
                if(temporary!=this||operation!=selectedOperation||started||cancelled||closed)
                    throw new IllegalStateException("The original temporary ordered reservation is unavailable.");
                started=true;
                executor.execute(() -> launch(source,idle,selected,selectedOperation,false,null,new Callback() {
                    public void validate() throws Exception { requireCurrent(); }
                    public void owned(String home) { try{observer.owned(home);}catch(Throwable ignored){} }
                    public void progress(String message) { try{observer.progress(message);}catch(Throwable ignored){} }
                    public void finished(boolean ok,String message) {
                        synchronized(AndroidNodeChainRuntime.this){finished=true;}
                        try{observer.finished(ok,message);}catch(Throwable ignored){}
                    }
                }));
            }
        }
        void requireCurrent() throws Exception {
            synchronized(AndroidNodeChainRuntime.this) {
                if(temporary!=this||operation!=selectedOperation||cancelled||closed)
                    throw new IllegalStateException("The original temporary ordered test was cancelled.");
            }
            guard.requireCurrent();
        }
        AndroidNodeChainSession session() throws Exception {
            requireCurrent();
            AndroidNodeChainSession captured;
            synchronized(AndroidNodeChainRuntime.this) {
                captured=owner;
                if(temporary!=this||operation!=selectedOperation||!finished||cancelled||!connected||stopping||captured==null)
                    throw new IllegalStateException("The complete temporary ordered graph has not proved its original owner.");
            }
            if(!LayeredVpnService.nodeChainReady(captured))throw new IllegalStateException("The complete temporary native proof is unavailable.");
            requireCurrent();return captured;
        }
        void cancel() {
            synchronized(AndroidNodeChainRuntime.this) {
                cancelled=true;
                if(temporary!=this||operation!=selectedOperation)return;
                stopping=true;connected=false;
            }
            try{guard.cancel();}catch(Throwable ignored){ /* Retain drain authority for retry. */ }
        }
        /** Background callers only. False retains this handle and both owners. */
        boolean drain() {
            synchronized(AndroidNodeChainRuntime.this) {
                if(temporary!=this||operation!=selectedOperation)return true; // Already joined; never touch a replacement.
            }
            cancel();
            try{if(!guard.drain())return false;}catch(Throwable pending){return false;}
            synchronized(AndroidNodeChainRuntime.this) {
                if(temporary!=this||operation!=selectedOperation)return true;
                if(started&&!finished)return false;
                if(!started)transitioning=false;
            }
            if(!stopNativeOperation(selectedOperation))return false;
            synchronized(AndroidNodeChainRuntime.this) {
                if(temporary==this&&operation==selectedOperation){temporary=null;transitioning=false;}
            }
            return true;
        }
    }
    Temporary reserveTemporary(AndroidNodeStore.ChainCapture source, AndroidHomeStateStore.Snapshot idle,
                               String selected, TemporaryGuard guard, Callback callback) throws Exception {
        if(source==null||guard==null||callback==null)throw new IllegalArgumentException("The original temporary capture is incomplete.");
        if(!"local".equals(source.execution))throw new IllegalStateException("Temporary candidate preparation requires the saved Local execution.");
        source.requireCurrent();AndroidNodeChainSession.requireSelection(context,source,selected);guard.requireCurrent();
        synchronized(this) {
            reconcile();
            if(closed||temporary!=null||transitioning||owner!=null||!terminal(singBox.getState()))
                throw new IllegalStateException("Finish the original native owner before testing a saved ordered path.");
            AndroidHomeStateStore.Snapshot now=AndroidHomeStateStore.snapshot(context);
            if(idle==null||now.connected||AndroidHomeStateStore.emergencyDisconnectPending(context)
                    ||!idle.sessionId.equals(now.sessionId)||idle.pathGeneration!=now.pathGeneration||!idle.phase.equals(now.phase)
                    ||!("off".equals(now.phase)||"disconnected".equals(now.phase)||"failed".equals(now.phase)))
                throw new IllegalStateException("The captured idle Home owner changed before temporary reservation.");
            transitioning=true;stopping=false;submitted=false;
            temporary=new Temporary(source,idle,selected,++operation,guard,callback);return temporary;
        }
    }
    synchronized boolean retainsCapturedOwner(String homeSession) {
        reconcile();
        return homeSession != null && owner != null && homeSession.equals(owner.home.sessionId)
                && (!owner.released() || capturedDrain == owner && capturedDrainOperation == operation);
    }
    private AndroidNodeChainSession connectedOwner() {
        AndroidNodeChainSession captured;
        synchronized (this) { reconcile(); captured = connected && !stopping && temporary == null ? owner : null; }
        // Never hold the runtime monitor across source-store or native reads.
        // Store mutation admission also consults the runtime's busy state.
        if (captured == null || !LayeredVpnService.nodeChainReady(captured)) return null;
        synchronized (this) { return owner == captured && connected && !stopping && temporary == null ? captured : null; }
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
    void connect(AndroidNodeStore.ChainCapture capture, AndroidHomeStateStore.Snapshot idle, Callback callback) { connectSelected(capture,idle,true,callback); }
    void connectLast(AndroidNodeStore.ChainCapture capture, AndroidHomeStateStore.Snapshot idle, Callback callback) { connectSelected(capture,idle,false,callback); }
    private void connectSelected(AndroidNodeStore.ChainCapture capture, AndroidHomeStateStore.Snapshot idle, boolean remember, Callback callback) {
        try { connect(capture,idle,AndroidNodeChainSession.selection(context,capture),remember,callback); }
        catch(Exception invalid){callback.finished(false,safe(invalid));}
    }
    void connect(AndroidNodeStore.ChainCapture capture, AndroidHomeStateStore.Snapshot idle, String selected, Callback callback) { connect(capture,idle,selected,true,callback); }
    void connectLast(AndroidNodeStore.ChainCapture capture, AndroidHomeStateStore.Snapshot idle, String selected, Callback callback) { connect(capture,idle,selected,false,callback); }
    private synchronized void connect(AndroidNodeStore.ChainCapture capture, AndroidHomeStateStore.Snapshot idle, String selected, boolean remember, Callback callback) {
        connect(capture, idle, selected, remember, null, callback);
    }
    private synchronized void connect(AndroidNodeStore.ChainCapture capture, AndroidHomeStateStore.Snapshot idle, String selected,
                                      boolean remember, AndroidNodeChainExecutionCapture.RestoreCapture restore, Callback callback) {
        reconcile();
        if (closed || temporary != null || transitioning || owner != null || !terminal(singBox.getState())) {
            callback.finished(false, "The previous native owner must finish cleanup before an ordered path can start."); return;
        }
        transitioning = true; stopping = false; submitted = false;
        long selectedOperation=++operation;
        executor.execute(() -> launch(capture, idle, selected, selectedOperation, remember, restore, callback));
    }

    private void launch(AndroidNodeStore.ChainCapture source, AndroidHomeStateStore.Snapshot idle, String selected, long selectedOperation, boolean remember,
                        AndroidNodeChainExecutionCapture.RestoreCapture restore, Callback callback) {
        AndroidHomeStateStore.Snapshot home = null;
        AndroidNodeChainSession session = null;
        try {
            if (source == null) throw new IllegalStateException("The original ordered selection is missing.");
            source.requireCurrent(); callback.validate(); requireStarting(selectedOperation);
            AndroidStartupPolicy.OrderedLast history = remember ? AndroidStartupPolicy.prepareOrderedExecution(context, source) : null;
            synchronized (context.getSharedPreferences("router-vpn-unified",Context.MODE_PRIVATE)) {
            AndroidNodeChainSession.requireSelection(context,source,selected);
            synchronized (AndroidHomeStateStore.class) {
                AndroidHomeStateStore.Snapshot now = AndroidHomeStateStore.snapshot(context);
                if (idle == null || now.connected || AndroidHomeStateStore.emergencyDisconnectPending(context)
                        || !idle.sessionId.equals(now.sessionId) || idle.pathGeneration != now.pathGeneration
                        || !idle.phase.equals(now.phase) || !("off".equals(now.phase) || "disconnected".equals(now.phase) || "failed".equals(now.phase))) {
                    throw new IllegalStateException("The captured idle Home owner changed before ordered startup.");
                }
                home = AndroidHomeStateStore.beginNodeChain(context, source);
            }
            }
            callback.owned(home.sessionId);
            callback.progress("Preparing every original ordered node and authenticated layer…");
            session = new AndroidNodeChainSession(context, source, home, selected, restore);
            synchronized (this) { requireStarting(selectedOperation); owner = session; }
            requireStarting(selectedOperation); session.stage(); callback.validate(); requireStarting(selectedOperation);
            synchronized (this) { requireStarting(selectedOperation); submitted = true; }
            singBox.startNodeChain(session.request, home.sessionId);
            long deadline = SystemClock.elapsedRealtime() + 30000L + 30000L * source.members.size();
            while (SystemClock.elapsedRealtime() < deadline) {
                requireStarting(selectedOperation); session.requireSource(); callback.validate();
                if (LayeredVpnService.nodeChainReady(session)) break;
                if (session.released() || session.claimed() && ("FAILED".equals(singBox.getState()) || "REVOKED".equals(singBox.getState())))
                    throw new IllegalStateException("The native ordered path failed: " + singBox.getError());
                Thread.sleep(50);
            }
            requireStarting(selectedOperation); session.requireSource(); callback.validate();
            if (!LayeredVpnService.nodeChainReady(session)) throw new IllegalStateException("The complete ordered path did not finish its native proof before timeout.");
            synchronized(context.getSharedPreferences("router-vpn-unified",Context.MODE_PRIVATE)) {
                AndroidNodeChainSession.requireSelection(context,source,selected);
                if (!AndroidHomeStateStore.connectedNodeChain(context, home)) throw new IllegalStateException("The original ordered Home selection changed during proof.");
            }
            if (!LayeredVpnService.nodeChainReady(session)) throw new IllegalStateException("The complete native proof expired before Connected delivery.");
            synchronized (this) {
                requireStarting(selectedOperation); connected = true; transitioning = false;
            }
            LayeredVpnService.startNodeChainAutomaticMTU(session);
            synchronized (this) {
                if (operation == selectedOperation && owner == session && connected && !stopping)
                    AndroidStartupPolicy.recordOrderedExecution(context, history, AndroidHomeStateStore.snapshot(context));
            }
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
        final Temporary preparation;
        synchronized (this) { selectedOperation=operation;preparation=temporary;stopping = true; connected = false; if (preparation==null&&owner != null) owner.cancel(); }
        if(preparation!=null)preparation.cancel();
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
    /** Speed Lab stops only its original proved owner. Invalidate that proof
     * before native teardown; an unrelated or queued replacement is untouched. */
    boolean disconnectAndDrainCaptured(String homeSession) {
        final long selectedOperation;
        final boolean restoreAuthorized;
        synchronized (this) {
            reconcile();
            AndroidNodeChainSession captured = owner;
            boolean retry = captured != null && capturedDrain == captured && capturedDrainOperation == operation;
            if (temporary != null || homeSession == null || homeSession.isEmpty() || captured == null || transitioning
                    || !homeSession.equals(captured.home.sessionId)) return false;
            synchronized (AndroidHomeStateStore.class) {
                AndroidHomeStateStore.Snapshot now = AndroidHomeStateStore.snapshot(context);
                boolean identity = captured.home.activeNodeId.equals(now.activeNodeId) && captured.home.activeChain.equals(now.activeChain);
                boolean releasedReceipt = retry && captured.released() && now.activeNodeId.isEmpty() && now.activeChain.isEmpty()
                        && "failed".equals(now.phase) && "failed".equals(now.pathProof);
                if (!homeSession.equals(now.sessionId) || !captured.home.logicalMode.equals(now.logicalMode)
                        || !captured.home.runtimeMode.equals(now.runtimeMode) || !(identity || releasedReceipt) || !now.activeEntryId.isEmpty()
                        || !now.activeExitId.isEmpty() || !now.activeExternalId.isEmpty()
                        || AndroidHomeStateStore.emergencyDisconnectPending(context)) return false;
                if (retry) {
                    if (now.pathGeneration != capturedDrainGeneration || now.connected
                            || !("connecting".equals(now.phase) || "failed".equals(now.phase))) return false;
                } else {
                    boolean failedOwner = !now.connected && "failed".equals(now.phase) && "failed".equals(now.pathProof)
                            && now.pathGeneration == captured.home.pathGeneration;
                    if (!failedOwner) {
                        if (!connected || stopping || !AndroidHomeStateStore.ownsNodeChain(context, captured.home) || !now.connected || !"connected".equals(now.phase)) return false;
                        if (AndroidHomeStateStore.beginPathRevalidation(context, "The original ordered path is stopping for a captured temporary measurement.") == null) return false;
                    }
                    capturedDrain = captured; capturedDrainOperation = operation;
                    capturedDrainGeneration = failedOwner ? now.pathGeneration : now.pathGeneration + 1;
                    capturedDrainRestoreAuthorized = !failedOwner;
                }
            }
            selectedOperation = operation; restoreAuthorized = capturedDrainRestoreAuthorized; stopping = true; connected = false; captured.cancel();
        }
        // An already failed original proof can still own retryable cleanup.
        // Its drain never authorizes the temporary transaction to restore it.
        return stopOperation(selectedOperation) && restoreAuthorized;
    }
    private boolean stopOperation(long selectedOperation) {
        Temporary preparation;
        synchronized(this){preparation=operation==selectedOperation?temporary:null;}
        return preparation==null?stopNativeOperation(selectedOperation):preparation.drain();
    }
    private boolean stopNativeOperation(long selectedOperation) {
        AndroidNodeChainSession captured;
        synchronized (this) {
            if(operation!=selectedOperation)return true; // A newer admission required the old owner to release first.
            stopping = true; connected = false; captured = owner; if (captured != null) captured.cancel(); else if (transitioning) return false;
        }
        boolean clean = stopOwned(captured);
        synchronized (this) { if (clean && operation==selectedOperation) { if(capturedDrain==captured)capturedDrain=null; transitioning = false; reconcile(); } }
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
        final Temporary preparation;
        final long selectedOperation;
        synchronized (this) {
            captured = owner;
            if (captured == null || !captured.home.sessionId.equals(home.sessionId)) return;
            selectedOperation=operation;preparation=temporary;
            stopping = true; connected = false;
            if(preparation==null)captured.cancel();
        }
        if(preparation!=null) {
            preparation.cancel();
            // Invalidate use immediately, while retaining the exact native graph
            // until candidate callbacks have joined. A failed drain is retryable.
            executor.execute(preparation::drain);return;
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
        final String selection;
        private final AndroidNodeChainSession original;
        private final AndroidNodeChainExecutionCapture.RestoreCapture execution;
        private RestoreCapture(AndroidNodeChainSession owner) throws Exception {
            original = owner; source = owner.source; selection = owner.selectionDigest;
            execution = owner.execution == null ? null : owner.execution.captureRestore();
        }
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
            capture.source.requireCurrent(); AndroidNodeChainSession.requireSelection(context,capture.source,capture.selection); return connectedOwner() == capture.original;
        } catch (Exception stale) { return false; }
    }
    boolean restoredMatches(RestoreCapture capture) {
        try {
            if (capture == null || !capture.original.released()) return false;
            AndroidNodeChainSession current = connectedOwner();
            if (current == null || current == capture.original || current.source != capture.source) return false;
            if (capture.execution == null ? current.execution != null
                    : current.execution == null || !current.execution.restoredMatches(capture.execution)) return false;
            capture.source.requireCurrent(); AndroidNodeChainSession.requireSelection(context,capture.source,capture.selection); current.requireCurrent();
            return connectedOwner() == current;
        } catch (Exception stale) { return false; }
    }
    void restore(RestoreCapture capture, AndroidHomeStateStore.Snapshot idle, Callback callback) {
        try {
            if (capture == null || idle == null || !capture.original.released()) throw new IllegalStateException("The original ordered native owner has not completed its drain.");
            capture.source.requireCurrent();
            AndroidNodeChainSession.requireSelection(context,capture.source,capture.selection);
            connect(capture.source, idle, capture.selection, false, capture.execution, callback);
        } catch (Exception stale) { callback.finished(false, safe(stale)); }
    }
    @Override public void close() { synchronized (this) { closed = true; } disconnect(); }
    private static boolean terminal(String state) { return "DOWN".equals(state) || "FAILED".equals(state) || "REVOKED".equals(state); }
    private static String safe(Throwable failure) {
        String value = failure.getMessage();
        return value == null || value.trim().isEmpty() ? "The original ordered path could not be proved." : value.replace('\n', ' ').replace('\r', ' ').trim();
    }
}
