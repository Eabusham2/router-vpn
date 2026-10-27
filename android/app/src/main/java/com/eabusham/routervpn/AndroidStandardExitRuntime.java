package com.eabusham.routervpn;

import android.content.Context;

import java.io.File;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/** Owns one custom-exit graph, its exact proof and cancellation through real teardown. */
final class AndroidStandardExitRuntime implements AutoCloseable {
    interface Callback{void progress(String message);void finished(boolean ok,String message);default void owned(String homeSession){}}
    private static final long TOR_START_TIMEOUT_MS=200000L;
    private static final long POLICY_START_TIMEOUT_MS=90000L;
    // Shared execution may consume 100s before the separate 45s final proof.
    // Retain 35s for native service startup and delivery without shortening either phase.
    private static final long EXECUTION_START_TIMEOUT_MS=180000L;
    private static final long STOP_TIMEOUT_MS=8000L;
    private final Context context;
    private final NativeSingBoxController singBox;
    private final AndroidStandardExitController builder;
    private final AndroidDirectStandardExitController directBuilder;
    private final ExecutorService executor=Executors.newSingleThreadExecutor();
    private final AtomicBoolean closed=new AtomicBoolean(false);
    private Future<?> active;
    private Thread workerThread;
    private boolean disconnectRequested;
    private boolean revalidationTeardown;
    private boolean teardownInProgress;
    private String torNativeSession="",torHomeSession="",torExternalID="";
    private String externalNativeSession="",externalHomeSession="",externalID="";
    private String requestedExecution="local";

    AndroidStandardExitRuntime(Context context,NativeSingBoxController singBox){
        this.context=context.getApplicationContext();
        this.singBox=singBox;
        this.builder=new AndroidStandardExitController(this.context);
        this.directBuilder=new AndroidDirectStandardExitController(this.context);
    }

    synchronized void connect(File entryBundle,AndroidStandardExitStore.Entry exit,Callback cb){ submit(entryBundle,exit,false,"wg",cb); }
    synchronized void connect(File entryBundle,AndroidStandardExitStore.Entry exit,String entryMode,Callback cb){ submit(entryBundle,exit,false,entryMode,cb); }
    synchronized void connectDirect(AndroidStandardExitStore.Entry exit,Callback cb){ submit(null,exit,true,"external",cb); }

    synchronized void connect(File entryBundle,AndroidStandardExitStore.Entry exit,String entryMode,String execution,Callback cb){submit(entryBundle,exit,false,entryMode,execution,"",cb);}
    synchronized void restoreCaptured(File entryBundle,AndroidStandardExitStore.Entry exit,String entryMode,String execution,String selected,Callback cb){
        if(entryBundle==null||!java.util.Arrays.asList("local","server").contains(selected)||!"auto".equals(execution)&&!execution.equals(selected)){cb.finished(false,"The original external execution receipt is invalid.");return;}
        submit(entryBundle,exit,false,entryMode,execution,"local".equals(execution)?"":selected,cb);
    }

    private void submit(File entryBundle,AndroidStandardExitStore.Entry exit,boolean direct,String entryMode,Callback cb){submit(entryBundle,exit,direct,entryMode,"local","",cb);}

    private void submit(File entryBundle,AndroidStandardExitStore.Entry exit,boolean direct,String entryMode,String execution,String restoredExecution,Callback cb){
        if(closed.get()){cb.finished(false,"Android custom-exit runtime is closed.");return;}
        if(teardownInProgress||(active!=null&&!active.isDone())){cb.finished(false,"Another Android custom-exit attempt or teardown is running.");return;}
        String blocked=startBlockedReason();if(!blocked.isEmpty()){cb.finished(false,blocked);return;}
        final AndroidStandardExitStore.Entry captured;
        final String capturedEntry;
        try { captured=AndroidStandardExitStore.copy(exit); AndroidStandardExitStore.validate(captured); AndroidStandardExitStore.validateExecution(captured,!direct,execution);
            capturedEntry=!direct?AndroidExternalPolicy.entryDigest(entryBundle):"";
        }
        catch(Exception invalid){cb.finished(false,"The saved custom-exit profile is invalid; review its settings before connecting.");return;}
        disconnectRequested=false;revalidationTeardown=false;teardownInProgress=false;
        torNativeSession="";torHomeSession="";torExternalID="";
        externalNativeSession="";externalHomeSession="";externalID="";requestedExecution=execution;
        AndroidHomeStateStore.Snapshot initialHome=AndroidHomeStateStore.snapshot(context);
        active=executor.submit(()->run(entryBundle,captured,direct,entryMode,execution,restoredExecution,capturedEntry,initialHome,cb));
    }

    private void run(File entry,AndroidStandardExitStore.Entry exit,boolean direct,String entryMode,String execution,String restoredExecution,String capturedEntry,AndroidHomeStateStore.Snapshot initialHome,Callback cb){
        boolean started=false,sessionStarted=false,releasePrepared=true;
        NativeSingBoxController.SessionInfo preparedSession=null;
        boolean tor=AndroidTorProfile.isTor(exit.protocol);
        boolean policy=AndroidExternalPolicy.supports(exit.protocol);
        AndroidHomeStateStore.Snapshot capturedHome=null;
        synchronized(this){workerThread=Thread.currentThread();}
        try{
            synchronized(this){if(disconnectRequested||closed.get()||Thread.currentThread().isInterrupted())throw new InterruptedException("Custom exit cancelled.");}
            if(!tor&&!policy)throw new IllegalArgumentException("The selected external protocol has no captured native policy owner.");
            String blocked=startBlockedReason();if(!blocked.isEmpty())throw new IllegalStateException(blocked);
            String before=singBox.getState();
            if(!terminal(before))throw new IllegalStateException("Disconnect the current embedded VPN before custom exit.");
            if(!direct&&!capturedEntry.equals(AndroidExternalPolicy.entryDigest(entry)))throw new IllegalStateException("The selected external entry changed while its request was queued.");
            synchronized(AndroidHomeStateStore.class){
                AndroidHomeStateStore.Snapshot now=AndroidHomeStateStore.snapshot(context);
                if(!initialHome.sessionId.equals(now.sessionId)||initialHome.pathGeneration!=now.pathGeneration||initialHome.connected!=now.connected||!initialHome.phase.equals(now.phase))
                    throw new InterruptedException("A newer connection or Disconnect cancelled the queued external path.");
                if(tor) AndroidHomeStateStore.beginTorExternal(context,exit.id,exit.name,exit.protocol,direct?"":entryID(entry),entryMode);
                else AndroidHomeStateStore.beginPolicyExternal(context,exit.id,exit.name,exit.protocol,exit.expectedPublicIp,direct?"":entryID(entry),entryMode);
                sessionStarted=true;
                capturedHome=AndroidHomeStateStore.snapshot(context);
            }
            cb.owned(capturedHome.sessionId);
            cb.progress(direct?"Preparing direct "+exit.protocol+" custom exit with its captured protection policy…":"Preparing "+entryMode+" entry → "+exit.protocol+" custom exit…");
            NativeSingBoxController.SessionInfo session=direct?directBuilder.prepare(exit):builder.prepare(entry,exit,entryMode,execution,restoredExecution);
            preparedSession=session;
            if(Thread.currentThread().isInterrupted()||closed.get())throw new InterruptedException("Custom exit cancelled.");
            cb.progress("Starting one Android VpnService custom-exit graph…");
            synchronized(this){
                if(disconnectRequested||closed.get()||Thread.currentThread().isInterrupted())throw new InterruptedException("Custom exit cancelled before engine launch.");
                // A partially published start still owns cleanup when launch throws.
                if(tor){torNativeSession=session.sessionId;torHomeSession=capturedHome.sessionId;torExternalID=exit.id;}
                if(policy){externalNativeSession=session.sessionId;externalHomeSession=capturedHome.sessionId;externalID=exit.id;}
                started=true;releasePrepared=false;
                if(policy)singBox.startExternal(session,capturedHome.sessionId);else singBox.start(session);
            }
            long deadline=System.currentTimeMillis()+startTimeoutMillis(tor,execution);
            while(System.currentTimeMillis()<deadline){
                if(Thread.currentThread().isInterrupted()||closed.get())throw new InterruptedException("Custom exit cancelled.");
                String state=singBox.getState();
                if("UP".equals(state))break;
                if("FAILED".equals(state)||"REVOKED".equals(state))throw new IllegalStateException(nonEmpty(singBox.getError(),"Embedded custom-exit engine entered "+state+"."));
                Thread.sleep(250L);
            }
            if(!"UP".equals(singBox.getState()))throw new IllegalStateException("Embedded custom-exit engine did not reach UP before timeout.");
            cb.progress(tor?"The captured Tor circuit, entry and selected DNS passed; checking current ownership…":"Captured entry, selected DNS and public exit passed; checking current ownership…");
            String observed=tor?capturedTorExit(capturedHome):capturedExternalExit(capturedHome);
            String selectedExecution=capturedExternalExecution(capturedHome);
            synchronized(this){
                if(disconnectRequested||closed.get()||Thread.currentThread().isInterrupted())throw new InterruptedException("Custom exit cancelled before Connected adoption.");
                if(!selectedExecution.equals(capturedExternalExecution(capturedHome)))throw new IllegalStateException("The proved execution changed before Connected adoption.");
                if(tor){
                    capturedTorExit(capturedHome);
                    if(!AndroidHomeStateStore.connectedTorExternal(context,capturedHome,observed))throw new IllegalStateException("The captured Tor session changed before Connected adoption.");
                    LayeredVpnService.startTorAutomaticMTU(torNativeSession,torExternalID,capturedHome.sessionId);
                }else{
                    capturedExternalExit(capturedHome);
                    if(!AndroidHomeStateStore.connectedPolicyExternal(context,capturedHome,observed))throw new IllegalStateException("The captured external session changed before Connected adoption.");
                    LayeredVpnService.startExternalAutomaticMTU(externalNativeSession,externalID,capturedHome.sessionId);
                }
            }
            cb.finished(true,tor?"Connected: "+(direct?"direct Tor":entryMode+" entry → Tor ["+selectedExecution+"]")+". Captured circuit and DNS proof passed; current exit "+observed
                    :"Connected: "+(direct?"direct ":entryMode+" entry → ")+exit.protocol+(direct?"":" ["+selectedExecution+"]")+". Captured entry, selected DNS and public exit proof passed: "+observed);
        } catch(InterruptedException error){
            boolean stopped=!started||stopEmbeddedAndProve();
            releasePrepared=stopped;
            Thread.currentThread().interrupt();
            boolean suppressHome;
            synchronized(this){suppressHome=revalidationTeardown;teardownInProgress=!stopped;}
            boolean emergency=AndroidHomeStateStore.emergencyDisconnectPending(context);
            if(sessionStarted&&!suppressHome&&sameHomeOwner(tor,capturedHome)){
                if(emergency){
                    AndroidHomeStateStore.warning(context,stopped
                            ?"Emergency Disconnect requested; Android custom-exit graph stopped; awaiting remaining runtime teardown."
                            :"Emergency Disconnect requested; Android custom-exit teardown was not proved; runtime ownership retained.");
                }else if(stopped){
                    AndroidHomeStateStore.disconnected(context);
                }else{
                    AndroidHomeStateStore.warning(context,"Android custom-exit cancellation could not prove embedded engine teardown; runtime ownership retained.");
                }
            }
            cb.finished(false,stopped?"Android custom exit cancelled and disconnected.":"Android custom exit cancellation incomplete; embedded engine did not prove teardown.");
        } catch(Exception error){
            boolean stopped=!started||stopEmbeddedAndProve();
            releasePrepared=stopped;
            boolean suppressHome;
            synchronized(this){suppressHome=revalidationTeardown;teardownInProgress=!stopped;}
            String message=tor?"The captured Tor circuit, entry or DNS proof failed. Check the saved bridge and DNS settings, then reconnect.":nonEmpty(error.getMessage(),"Android custom exit failed closed.");
            if(!stopped)message+=" Embedded engine teardown was not proved; runtime ownership retained.";
            if(sessionStarted&&!suppressHome&&sameHomeOwner(tor,capturedHome)){
                boolean emergency=AndroidHomeStateStore.emergencyDisconnectPending(context);
                if(emergency) AndroidHomeStateStore.warning(context,"Emergency Disconnect requested; "+message);
                else if(stopped) AndroidHomeStateStore.failed(context,message);
                else AndroidHomeStateStore.warning(context,message);
            }
            cb.finished(false,message);
        }finally{
            try{
                if((policy||tor)&&releasePrepared&&preparedSession!=null){
                    if(preparedSession.maxPreparation!=null)preparedSession.maxPreparation.close();
                    LayeredVpnService.discardPreparedSession(context,preparedSession.sessionId);
                }
            }finally{synchronized(this){workerThread=null;}}
        }
    }

    private boolean sameHomeOwner(boolean tor,AndroidHomeStateStore.Snapshot captured){
        return captured!=null&&captured.sessionId.equals(AndroidHomeStateStore.snapshot(context).sessionId);
    }

    static long startTimeoutMillis(boolean tor,String execution){
        return tor?TOR_START_TIMEOUT_MS:"local".equals(execution)?POLICY_START_TIMEOUT_MS:EXECUTION_START_TIMEOUT_MS;
    }

    synchronized String capturedTorExit(AndroidHomeStateStore.Snapshot owner)throws Exception{
        AndroidHomeStateStore.Snapshot current=AndroidHomeStateStore.snapshot(context);
        if(disconnectRequested||closed.get()||owner==null||!AndroidTorProfile.isTor(owner.activeExternalProtocol)
                ||torNativeSession.isEmpty()||!torHomeSession.equals(owner.sessionId)||!torHomeSession.equals(current.sessionId)
                ||!torExternalID.equals(owner.activeExternalId)||!torExternalID.equals(current.activeExternalId)
                ||owner.pathGeneration!=current.pathGeneration||!owner.activeExternalProtocol.equals(current.activeExternalProtocol)
                ||!owner.activeEntryId.equals(current.activeEntryId)||!owner.activeEntryMode.equals(current.activeEntryMode)
                ||!"UP".equals(singBox.getState()))throw new IllegalStateException("The captured Tor runtime is unavailable; reconnect to prove its path.");
        return LayeredVpnService.torExitIP(torNativeSession,torExternalID);
    }

    synchronized String capturedExternalExit(AndroidHomeStateStore.Snapshot owner)throws Exception{
        AndroidHomeStateStore.Snapshot current=AndroidHomeStateStore.snapshot(context);
        if(disconnectRequested||closed.get()||owner==null||!AndroidExternalPolicy.supports(owner.activeExternalProtocol)
                ||externalNativeSession.isEmpty()||!externalHomeSession.equals(owner.sessionId)||!externalHomeSession.equals(current.sessionId)
                ||owner.pathGeneration!=current.pathGeneration||!externalID.equals(owner.activeExternalId)||!externalID.equals(current.activeExternalId)
                ||!owner.activeEntryId.equals(current.activeEntryId)||!owner.activeEntryMode.equals(current.activeEntryMode)
                ||!owner.expectedExternalIp.equals(current.expectedExternalIp)||!"UP".equals(singBox.getState())) throw new IllegalStateException("The captured external runtime is unavailable; reconnect to prove its path.");
        return LayeredVpnService.externalExitIP(externalNativeSession,externalID);
    }

    synchronized String capturedRequestedExecution(AndroidHomeStateStore.Snapshot owner)throws Exception {
        if(owner!=null&&AndroidTorProfile.isTor(owner.activeExternalProtocol))capturedTorExit(owner);else capturedExternalExit(owner);
        return requestedExecution;
    }

    synchronized String capturedExternalExecution(AndroidHomeStateStore.Snapshot owner)throws Exception {
        final String selected;
        if(owner!=null&&AndroidTorProfile.isTor(owner.activeExternalProtocol)){
            capturedTorExit(owner);selected=LayeredVpnService.torExecution(torNativeSession,torExternalID);
        }else{
            capturedExternalExit(owner);selected=LayeredVpnService.externalExecution(externalNativeSession,externalID);
        }
        if(!java.util.Arrays.asList("local","server").contains(selected)||!"auto".equals(requestedExecution)&&!requestedExecution.equals(selected))throw new IllegalStateException("The external execution receipt differs from its captured selection.");
        return selected;
    }

    private static String entryID(File file){
        if(file==null||!file.getName().matches("[0-9a-f]{32}\\.json"))throw new IllegalArgumentException("Select a saved Router VPN entry node.");
        return file.getName().substring(0,32);
    }

    private String startBlockedReason(){
        AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
        if(home.connected)return "Disconnect the current Router VPN or custom-exit session before starting another custom exit.";
        AndroidRuntimeRegistry engines=AndroidRuntimeRegistry.get(context);
        boolean failedMarkerOnly=AndroidVpnMutationGuard.failedSessionHasNoLiveEngine(context,engines);
        if(engines.orchestrator.isRunning()||(!failedMarkerOnly&&engines.orchestrator.isActive())||engines.multihop.isActiveOrTransitioning()
                ||engines.wireGuard.getState()!=com.wireguard.android.backend.Tunnel.State.DOWN
                ||engines.amneziaWG.getState()!=org.amnezia.awg.backend.Tunnel.State.DOWN
                ||runtimeBusy(engines.xray.getState()))return "Wait for the current Router VPN transition to finish or disconnect before starting a custom exit.";
        return "";
    }

    synchronized boolean isActiveOrTransitioning(){
        if(teardownInProgress)return true;
        Future<?> task=active;
        if(task!=null&&!task.isDone())return true;
        String state=singBox.getState();
        if(state==null)return true;
        String normalized=state.trim().toUpperCase(Locale.ROOT);
        if(!terminal(normalized))return true;
        AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
        if(!"external".equals(home.logicalMode))return false;
        String phase=home.phase==null?"":home.phase.trim().toLowerCase(Locale.ROOT);
        return home.connected||!("off".equals(phase)||"disconnected".equals(phase)||"failed".equals(phase));
    }

    void disconnect(){ disconnectCaptured(""); }

    boolean disconnectCaptured(String requiredSession){ return disconnectCaptured(requiredSession,false); }
    boolean disconnectAndDrainCaptured(String requiredSession){ return disconnectCaptured(requiredSession,true); }
    private boolean disconnectCaptured(String requiredSession,boolean drain){
        boolean emergency=AndroidHomeStateStore.emergencyDisconnectPending(context);
        final String ownedSession;final Future<?> task;
        synchronized(this){
            AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
            if(!requiredSession.isEmpty()&&!requiredSession.equals(home.sessionId))return false;
            boolean owns=(active!=null&&!active.isDone())||"external".equals(home.logicalMode)||singBox.getMode().startsWith("standard-");
            if(!owns)return false;
            ownedSession=home.sessionId;task=active;
            if(!emergency)AndroidHomeStateStore.beginPathRevalidation(context,"Android custom-exit disconnect requested; retaining runtime ownership until embedded teardown is proved.");
            disconnectRequested=true;revalidationTeardown=drain;teardownInProgress=true;
            if(workerThread!=null)workerThread.interrupt();
        }
        boolean stopped=stopEmbeddedAndProve();
        if(stopped&&drain)stopped=drainWorker(task);
        synchronized(this){teardownInProgress=!stopped;}
        if(!stopped){
            synchronized(AndroidHomeStateStore.class){
                if(ownedSession.equals(AndroidHomeStateStore.snapshot(context).sessionId))AndroidHomeStateStore.warning(context,emergency
                        ?"Emergency Disconnect requested; Android custom-exit teardown was not proved; runtime ownership retained."
                        :"Android custom-exit disconnect did not prove embedded engine teardown; runtime ownership retained.");
            }
            throw new IllegalStateException("Android custom-exit teardown did not reach DOWN/FAILED/REVOKED before timeout.");
        }
        synchronized(AndroidHomeStateStore.class){
            if(ownedSession.equals(AndroidHomeStateStore.snapshot(context).sessionId)){
                if(emergency)AndroidHomeStateStore.warning(context,"Emergency Disconnect requested; Android custom-exit graph stopped; awaiting remaining runtime teardown.");
                else AndroidHomeStateStore.disconnected(context);
            }
        }
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

    /** Tear down this owner's runtime without changing Home state; revalidation owns the failed-state adoption. */
    void failClosedForRevalidation(){
        synchronized(this){disconnectRequested=true;revalidationTeardown=true;teardownInProgress=true;if(workerThread!=null)workerThread.interrupt();}
        boolean stopped=stopEmbeddedAndProve();
        synchronized(this){teardownInProgress=!stopped;}
        if(!stopped)throw new IllegalStateException("Android custom-exit revalidation teardown did not reach a terminal state.");
    }

    @Override public void close(){
        boolean owns;
        synchronized(this){
            if(!closed.compareAndSet(false,true))return;
            disconnectRequested=true;revalidationTeardown=true;teardownInProgress=true;
            if(workerThread!=null)workerThread.interrupt();
            AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
            owns="external".equals(home.logicalMode)||singBox.getMode().startsWith("standard-");
        }
        if(owns&&runtimeBusy(singBox.getState()))stopEmbeddedAndProve();
        synchronized(this){teardownInProgress=owns&&runtimeBusy(singBox.getState());}
        // Queued attempts must observe closed and complete normally; cancelling
        // their Future would claim completion before worker cleanup finished.
        executor.shutdown();
    }

    private boolean stopEmbeddedAndProve(){
        boolean interrupted=Thread.interrupted();
        try{
            singBox.stop();
            long deadline=System.currentTimeMillis()+STOP_TIMEOUT_MS;
            while(System.currentTimeMillis()<deadline){
                if(terminal(singBox.getState()))return true;
                try{Thread.sleep(150L);}catch(InterruptedException error){interrupted=true;}
            }
            return terminal(singBox.getState());
        }catch(RuntimeException error){
            // Neither a failed stop request nor a failed state read proves DOWN.
            return false;
        }finally{if(interrupted)Thread.currentThread().interrupt();}
    }

    private static boolean terminal(String state){
        if(state==null)return false;
        String normalized=state.trim().toUpperCase(Locale.ROOT);
        return "DOWN".equals(normalized)||"FAILED".equals(normalized)||"REVOKED".equals(normalized);
    }
    private static boolean runtimeBusy(String state){return !terminal(state);}
    private static String nonEmpty(String value,String fallback){return value==null||value.trim().isEmpty()?fallback:value.trim();}
}
