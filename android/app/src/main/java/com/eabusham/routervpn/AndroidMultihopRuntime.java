package com.eabusham.routervpn;

import android.content.Context;

import java.io.File;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/** Starts a prepared multihop graph and accepts Connected only after exit-node private path proof. */
final class AndroidMultihopRuntime implements AutoCloseable {
    interface Callback {
        void progress(String message);
        void finished(boolean ok, String message);
        default void owned(String homeSession) {}
    }

    private static final long START_TIMEOUT_MS = 20000L;
    private static final long STOP_TIMEOUT_MS = 8000L;
    private static final int PROBE_TIMEOUT_MS = 5000;
    private final Context context;
    private final NativeSingBoxController singBox;
    private final AndroidMultihopController builder;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private Future<?> active;
    private Thread workerThread;
    private boolean transitioning;
    private boolean connected;
    private boolean disconnectRequested;
    private boolean revalidationTeardown;
    private String activeEntryId = "";
    private String activeEntryMode = "";
    private String activeExitId = "";
    private String activeExitMode = "";
    private String activeExecution = "";
    private String activeHomeSession = "";
    private AndroidMultihopController.Source activeEntrySource, activeExitSource;

    /** Never persisted or rebuilt from selected labels: one proved owner plus its exact sources. */
    static final class RestoreCapture {
        final String policy, selected;
        final LayeredVpnService.CapturedMultihop owner;
        final AndroidMultihopController.Source entrySource, exitSource;
        private RestoreCapture(String policy, LayeredVpnService.CapturedMultihop owner,
                               AndroidMultihopController.Source entrySource, AndroidMultihopController.Source exitSource) {
            this.policy=policy;this.selected=owner.execution;this.owner=owner;this.entrySource=entrySource;this.exitSource=exitSource;
        }
        void require(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit) throws Exception {
            if (entry==null||exit==null||entry.id.equals(exit.id)||!owner.entryId.equals(entry.id)||!owner.exitId.equals(exit.id)
                    ||!java.util.Arrays.asList("local","server","auto").contains(policy)
                    ||!java.util.Arrays.asList("local","server").contains(selected)||!"auto".equals(policy)&&!policy.equals(selected)
                    ||entrySource==null||exitSource==null) throw new IllegalStateException("The original multihop capture lost its bound nodes or winner.");
            entrySource.require(entry.file);exitSource.require(exit.file);
            AndroidMultihopController.validatedServerIdentityPins(selected,owner.exitMode,owner.serverIdentityPins);
        }
    }

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
        if (transitioning || connected || (active != null && !active.isDone())) return true;
        AndroidHomeStateStore.Snapshot home = AndroidHomeStateStore.snapshot(context);
        return "multihop".equals(home.logicalMode) && runtimeBusy(singBox.getState());
    }

    synchronized boolean isConnected() {
        reconcileRuntimeLocked();
        return connected;
    }

    synchronized String activeExecution() { reconcileRuntimeLocked(); return connected ? activeExecution : ""; }
    synchronized String activeSelectedExecution() throws Exception {
        reconcileRuntimeLocked();
        if(!connected||disconnectRequested||closed.get())throw new IllegalStateException("The original multihop owner is unavailable.");
        return LayeredVpnService.capturedMultihopExecution(AndroidHomeStateStore.snapshot(context).sessionId);
    }

    synchronized RestoreCapture captureRestore(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, AndroidHomeStateStore.Snapshot home) throws Exception {
        reconcileRuntimeLocked();
        if(!connected||disconnectRequested||closed.get()||home==null||!activeHomeSession.equals(home.sessionId)
                ||!activeEntryId.equals(home.activeEntryId)||!activeExitId.equals(home.activeExitId)
                ||!activeEntryMode.equals(home.activeEntryMode)||!activeExitMode.equals(home.runtimeMode)) throw new IllegalStateException("The original multihop source owner is unavailable.");
        LayeredVpnService.CapturedMultihop owner=LayeredVpnService.capturedMultihop(home.sessionId);
        if(!owner.matchesHome(home))throw new IllegalStateException("The original multihop home session changed during capture.");
        RestoreCapture result=new RestoreCapture(activeExecution,owner,activeEntrySource,activeExitSource);
        result.require(entry,exit);
        if(!captureCurrent(result))throw new IllegalStateException("The original multihop owner changed during source capture.");
        return result;
    }

    synchronized boolean captureCurrent(RestoreCapture capture) {
        try {
            reconcileRuntimeLocked();
            if(capture==null||!connected||disconnectRequested||closed.get()||!activeHomeSession.equals(capture.owner.homeSession)
                    ||!activeExecution.equals(capture.policy)||!capture.entrySource.same(activeEntrySource)||!capture.exitSource.same(activeExitSource))return false;
            capture.entrySource.require(capture.entrySource.file);capture.exitSource.require(capture.exitSource.file);
            return capture.owner.sameOwner(LayeredVpnService.capturedMultihop(activeHomeSession));
        } catch(Exception changed) { return false; }
    }

    synchronized boolean restoredMatches(RestoreCapture original, AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, AndroidHomeStateStore.Snapshot home) {
        try {
            RestoreCapture actual=captureRestore(entry,exit,home);
            return original!=null&&original.policy.equals(actual.policy)&&original.selected.equals(actual.selected)
                    &&original.owner.entryId.equals(actual.owner.entryId)&&original.owner.exitId.equals(actual.owner.exitId)
                    &&original.owner.entryMode.equals(actual.owner.entryMode)&&original.owner.exitMode.equals(actual.owner.exitMode)
                    &&original.entrySource.same(actual.entrySource)&&original.exitSource.same(actual.exitSource)
                    &&original.owner.serverIdentityPins.equals(actual.owner.serverIdentityPins);
        } catch(Exception changed) { return false; }
    }

    synchronized String activeEntryMode() { reconcileRuntimeLocked(); return connected ? activeEntryMode : ""; }

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
        connect(entry, exit, exitMode, "local", callback);
    }
    synchronized void connect(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, String exitMode, String execution, Callback callback) {
        connect(entry,exit,exitMode,execution,"wg",callback);
    }
    synchronized void connect(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, String exitMode, String execution, String entryMode, Callback callback) {
        connectCaptured(entry,exit,exitMode,execution,execution,entryMode,null,null,callback);
    }
    /** Runtime-only winner override; the saved Compare preference remains unchanged. */
    synchronized void restoreCaptured(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,RestoreCapture capture,AndroidHomeStateStore.Snapshot idle,Callback callback){
        try{if(capture==null||idle==null)throw new IllegalStateException("The original multihop capture or idle owner is missing.");capture.require(entry,exit);}
        catch(Exception changed){callback.finished(false,nonEmpty(changed.getMessage(),"The original multihop capture changed."));return;}
        connectCaptured(entry,exit,capture.owner.exitMode,capture.selected,capture.policy,capture.owner.entryMode,capture,idle,callback);
    }
    private synchronized void connectCaptured(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, String exitMode, String execution, String policy, String entryMode, RestoreCapture capture, AndroidHomeStateStore.Snapshot expectedIdle, Callback callback) {
        if (!NativeSingBoxController.nativeMultihopEntry(entryMode)) { callback.finished(false,"Choose an exact native entry transport.");return; }
        if(!java.util.Arrays.asList("local","server","auto").contains(execution)){callback.finished(false,"Invalid multihop execution.");return;}
        if (closed.get()) { callback.finished(false, "Android multihop runtime is closed."); return; }
        reconcileRuntimeLocked();
        if (transitioning || connected || (active != null && !active.isDone())) { callback.finished(false, "Another Android multihop session is already active or starting."); return; }
        if (entry == null || exit == null || entry.id.equals(exit.id)) { callback.finished(false, "Multihop requires two different stored nodes."); return; }
        if (exitMode == null || exitMode.trim().isEmpty()) { callback.finished(false, "Choose a supported multihop exit transport."); return; }
        if (runtimeBusy(singBox.getState())) { callback.finished(false, "The embedded VPN must prove a terminal state before multihop can start."); return; }
        final String homeSession;
        synchronized(AndroidHomeStateStore.class) {
            AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
            if(expectedIdle!=null&&(expectedIdle.connected||home.connected||!expectedIdle.sessionId.equals(home.sessionId)
                    ||expectedIdle.pathGeneration!=home.pathGeneration||!expectedIdle.phase.equals(home.phase)
                    ||!java.util.Arrays.asList("off","disconnected","failed").contains(home.phase)
                    ||AndroidHomeStateStore.emergencyDisconnectPending(context))) {
                callback.finished(false,"A newer Home decision prevents automatic multihop restoration.");return;
            }
            transitioning = true;
            disconnectRequested = false;
            revalidationTeardown = false;
            clearActiveGraphLocked();
            homeSession=AndroidHomeStateStore.beginMultihop(context, entry.id, exit.id, exitMode.trim(), entryMode);
        }
        try {
            active = executor.submit(() -> run(entry, exit, exitMode.trim(), execution, policy, entryMode, homeSession, capture, callback));
        } catch (RuntimeException error) {
            transitioning = false;
            AndroidHomeStateStore.failed(context, nonEmpty(error.getMessage(), "Could not start Android multihop worker."));
            callback.finished(false, nonEmpty(error.getMessage(), "Could not start Android multihop worker."));
        }
    }

    private void run(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, String exitMode, String execution, String policy, String entryMode, String homeSession, RestoreCapture capture, Callback callback) {
        boolean started = false;
        synchronized (this) { workerThread = Thread.currentThread(); }
        try {
            callback.owned(homeSession);
            synchronized (this) {
                if (disconnectRequested || closed.get() || Thread.currentThread().isInterrupted() || !homeSession.equals(AndroidHomeStateStore.snapshot(context).sessionId)) throw new InterruptedException("Multihop start cancelled.");
            }
            String before = singBox.getState();
            if (!terminal(before)) throw new IllegalStateException("Disconnect the current embedded VPN before starting multihop.");
            callback.progress("Preparing " + entryMode + " entry → " + exitMode + " exit…");
            AndroidMultihopController.Prepared prepared = capture==null ? builder.prepare(entry.file, exit.file, exitMode, execution, entryMode)
                    : builder.prepare(entry.file, exit.file, exitMode, execution, entryMode,capture.entrySource,capture.exitSource,capture.owner.serverIdentityPins);
            if (Thread.currentThread().isInterrupted() || closed.get()) throw new InterruptedException("Multihop start cancelled.");
            callback.progress("Starting one Android VpnService multihop graph…");
            synchronized (this) {
                if (disconnectRequested || closed.get() || Thread.currentThread().isInterrupted() || !homeSession.equals(AndroidHomeStateStore.snapshot(context).sessionId)) throw new InterruptedException("Multihop start cancelled before engine launch.");
                // A launch may publish ownership and then throw. Such a partial
                // start still requires confirmed teardown.
                started = true;
                singBox.start(prepared.session);
            }
            long deadline = System.currentTimeMillis() + ("local".equals(execution) ? START_TIMEOUT_MS : 120000L);
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
            prepared.entrySource.require(entry.file);prepared.exitSource.require(exit.file);
            synchronized (this) {
                if (disconnectRequested || closed.get() || Thread.currentThread().isInterrupted() || !homeSession.equals(AndroidHomeStateStore.snapshot(context).sessionId)) throw new InterruptedException("Multihop start cancelled.");
                transitioning = false;
                connected = true;
                activeEntryId = entry.id;
                activeEntryMode = entryMode;
                activeExitId = exit.id;
                activeExitMode = prepared.exitMode;
                activeExecution = policy;
                activeHomeSession = homeSession;
                activeEntrySource = prepared.entrySource; activeExitSource = prepared.exitSource;
                AndroidHomeStateStore.connectedMultihop(context, entry.id, exit.id, prepared.exitMode, entryMode);
                // The captured graph's post-proof activation and completion are
                // part of the same adoption as its state. Disconnect must not
                // invalidate that owner and then let this worker start MTU or
                // deliver a stale Connected callback. UI callbacks only enqueue.
                LayeredVpnService.startAutomaticMTU();
                callback.finished(true, "Connected: " + entry.name + " → " + exit.name + " via " + entryMode + " entry + " + prepared.exitMode + " exit. Exit-node private path proof passed.");
            }
        } catch (InterruptedException interrupted) {
            boolean stopped = !started || stopEmbeddedAndProve();
            Thread.currentThread().interrupt();
            boolean userCancelled;
            boolean suppressHome;
            synchronized (this) {
                userCancelled = disconnectRequested || closed.get();
                suppressHome = revalidationTeardown || !homeSession.equals(AndroidHomeStateStore.snapshot(context).sessionId);
                transitioning = !stopped;
                if (stopped) {
                    connected = false;
                    clearActiveGraphLocked();
                }
            }
            boolean emergency = AndroidHomeStateStore.emergencyDisconnectPending(context);
            if (!stopped) {
                if (!suppressHome) AndroidHomeStateStore.warning(context, emergency
                        ? "Emergency Disconnect requested; Android multihop teardown was not proved; graph ownership retained."
                        : "Android multihop cancellation could not prove embedded engine teardown; runtime ownership retained.");
                callback.finished(false, "Android multihop cancellation incomplete; embedded engine did not prove teardown.");
            } else {
                if (!suppressHome) {
                    if (emergency) AndroidHomeStateStore.warning(context, "Emergency Disconnect requested; Android multihop graph stopped; awaiting remaining runtime teardown.");
                    else if (userCancelled) AndroidHomeStateStore.disconnected(context);
                    else AndroidHomeStateStore.failed(context, "Android multihop start was interrupted and disconnected.");
                }
                callback.finished(false, userCancelled ? "Android multihop cancelled and disconnected." : "Android multihop start was interrupted and disconnected.");
            }
        } catch (Exception error) {
            boolean stopped = !started || stopEmbeddedAndProve();
            boolean suppressHome;
            synchronized (this) {
                suppressHome = revalidationTeardown || !homeSession.equals(AndroidHomeStateStore.snapshot(context).sessionId);
                transitioning = !stopped;
                if (stopped) {
                    connected = false;
                    clearActiveGraphLocked();
                }
            }
            String message = nonEmpty(error.getMessage(), "Android multihop failed closed.");
            if (!stopped) message += " Embedded engine teardown was not proved; runtime ownership retained.";
            if (!suppressHome) {
                boolean emergency = AndroidHomeStateStore.emergencyDisconnectPending(context);
                if (emergency) AndroidHomeStateStore.warning(context, "Emergency Disconnect requested; " + message);
                else if (stopped) AndroidHomeStateStore.failed(context, message);
                else AndroidHomeStateStore.warning(context, message);
            }
            callback.finished(false, message);
        } finally {
            synchronized (this) { workerThread = null; }
        }
    }

    void disconnect() { disconnectCaptured("",false); }
    boolean disconnectCaptured(String session) { return disconnectCaptured(session,false); }
    boolean disconnectAndDrainCaptured(String session) { return disconnectCaptured(session,true); }
    private boolean disconnectCaptured(String requiredSession,boolean drain) {
        boolean emergency = AndroidHomeStateStore.emergencyDisconnectPending(context);
        final String ownedSession;final Future<?> task;
        synchronized (this) {
            AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
            if(!requiredSession.isEmpty()&&!requiredSession.equals(home.sessionId))return false;
            if(!requiredSession.isEmpty()&&!"multihop".equals(home.logicalMode))return false;
            ownedSession=home.sessionId;task=active;
            if (!emergency) AndroidHomeStateStore.beginPathRevalidation(context, "Android multihop disconnect requested; retaining graph ownership until embedded teardown is proved.");
            disconnectRequested = true;
            revalidationTeardown = drain;
            transitioning = true;
            if (workerThread != null) workerThread.interrupt();
        }
        boolean stopped = stopEmbeddedAndProve();
        if(stopped&&drain)stopped=drainWorker(task);
        synchronized (this) {
            transitioning = !stopped;
            if (stopped) { connected = false; clearActiveGraphLocked(); }
        }
        synchronized(AndroidHomeStateStore.class){
            if(ownedSession.equals(AndroidHomeStateStore.snapshot(context).sessionId)){
                if(!stopped)AndroidHomeStateStore.warning(context,"Android multihop teardown or worker drain remains unproved; graph ownership is retained.");
                else if(emergency)AndroidHomeStateStore.warning(context,"Emergency Disconnect requested; Android multihop graph stopped; awaiting remaining runtime teardown.");
                else AndroidHomeStateStore.disconnected(context);
            }
        }
        if(!stopped)throw new IllegalStateException("Android multihop teardown or worker drain is still pending.");
        return true;
    }
    private static boolean drainWorker(Future<?> task){
        if(task==null)return true;boolean interrupted=Thread.interrupted();long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(8);
        try{while(true){try{task.get(Math.max(1,deadline-System.nanoTime()),java.util.concurrent.TimeUnit.NANOSECONDS);return true;}
            catch(InterruptedException ignored){interrupted=true;if(System.nanoTime()>=deadline)return task.isDone();}
            catch(java.util.concurrent.ExecutionException complete){return true;}
            catch(java.util.concurrent.TimeoutException pending){return false;}}}
        finally{if(interrupted)Thread.currentThread().interrupt();}
    }

    /** Tear down this owner's runtime without changing Home state; the revalidation transaction owns the final state write. */
    void failClosedForRevalidation() {
        synchronized (this) {
            disconnectRequested = true;
            revalidationTeardown = true;
            transitioning = true;
            if (workerThread != null) workerThread.interrupt();
        }
        boolean stopped = stopEmbeddedAndProve();
        synchronized (this) {
            transitioning = !stopped;
            if (stopped) {
                connected = false;
                clearActiveGraphLocked();
            }
        }
        if (!stopped) throw new IllegalStateException("Android multihop revalidation teardown did not reach a terminal state.");
    }

    @Override public void close() {
        synchronized (this) {
            if (!closed.compareAndSet(false, true)) return;
            disconnectRequested = true;
            revalidationTeardown = true;
            transitioning = true;
            if (workerThread != null) workerThread.interrupt();
        }
        if (runtimeBusy(singBox.getState())) stopEmbeddedAndProve();
        synchronized (this) {
            transitioning = runtimeBusy(singBox.getState());
            if (!transitioning) {
                connected = false;
                clearActiveGraphLocked();
            }
        }
        // Let a queued task observe closed/disconnectRequested and complete its
        // Future normally; cancellation marks a Future done before its worker exits.
        executor.shutdown();
    }

    private synchronized void restoreFromPersistedState() {
        AndroidHomeStateStore.Snapshot state = AndroidHomeStateStore.snapshot(context);
        if (state.connected && "multihop".equals(state.logicalMode) && !state.activeEntryId.isEmpty() && !state.activeExitId.isEmpty() && NativeSingBoxController.nativeMultihopEntry(state.activeEntryMode) && "UP".equals(singBox.getState())) {
            connected = true;
            transitioning = false;
            activeEntryId = state.activeEntryId;
            activeEntryMode = state.activeEntryMode;
            activeExitId = state.activeExitId;
            activeExitMode = state.runtimeMode;
        } else if (state.connected && "multihop".equals(state.logicalMode)) {
            AndroidHomeStateStore.failed(context, "Stored multihop state did not match an active embedded VPN engine; stale Connected state was cleared.");
        }
    }

    private void reconcileRuntimeLocked() {
        String state = singBox.getState();
        if (connected && terminal(state)) {
            connected = false;
            transitioning = false;
            clearActiveGraphLocked();
            AndroidHomeStateStore.failed(context, "Android multihop engine is no longer UP; Connected state was cleared.");
        }
    }

    private boolean stopEmbeddedAndProve() {
        boolean interrupted = Thread.interrupted();
        try {
            singBox.stop();
            long deadline = System.currentTimeMillis() + STOP_TIMEOUT_MS;
            while (System.currentTimeMillis() < deadline) {
                if (terminal(singBox.getState())) return true;
                try { Thread.sleep(150L); }
                catch (InterruptedException error) { interrupted = true; }
            }
            return terminal(singBox.getState());
        } catch (RuntimeException error) {
            // A failed stop request or state read is not teardown proof. Keep
            // ownership and let the caller report an incomplete disconnect.
            return false;
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    private static boolean terminal(String state) {
        if (state == null) return false;
        String normalized = state.trim().toUpperCase(Locale.ROOT);
        return "DOWN".equals(normalized) || "FAILED".equals(normalized) || "REVOKED".equals(normalized);
    }

    private static boolean runtimeBusy(String state) { return !terminal(state); }

    private void clearActiveGraphLocked() {
        activeEntryId = "";
        activeEntryMode = "";
        activeExitId = "";
        activeExitMode = "";
        activeExecution = "";
        activeHomeSession = "";
        activeEntrySource = null; activeExitSource = null;
    }

    private static String nonEmpty(String value, String fallback) { return value == null || value.trim().isEmpty() ? fallback : value.trim(); }
}
