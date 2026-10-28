package com.eabusham.routervpn;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/** Activity-owned UI bridge over app-process-owned VPN engines. */
final class AndroidUnifiedConnectionController implements AutoCloseable {
    interface Callback { void progress(String message); void finished(boolean ok, String message); default void owned(String homeSession) {} default void superseded() {} default void validate() throws Exception {} }
    // Activity request codes use only the lower 16 bits. This reserved range is
    // disjoint from import/via-entry and legacy native screens. Never reuse a
    // code in this process: a cancelled prompt may return after its successor.
    static final int PREPARE_UNIFIED = 0x4000;
    private static int nextPermissionCode=PREPARE_UNIFIED;
    private static final String STATE_PENDING="routervpn.pending",STATE_MODE="routervpn.pending.mode",STATE_LAYERS="routervpn.pending.layers",STATE_NODE="routervpn.pending.node",STATE_ENTRY="routervpn.pending.entry",STATE_EXIT="routervpn.pending.exit",STATE_EXIT_MODE="routervpn.pending.exit_mode",STATE_STANDARD_EXIT="routervpn.pending.standard_exit",STATE_EXTERNAL_DIRECT="routervpn.pending.external_direct";
    private static final String STATE_STARTUP="routervpn.pending.startup_nonce";
    private static final String STATE_ORDINARY_ENTRY="routervpn.pending.ordinary_entry";
    private static final String STATE_PERMISSION="routervpn.pending.permission_nonce",STATE_SELECTION="routervpn.pending.selection_digest";

    /** Process-owned receipt; Bundle carries only its nonce and choice digest. */
    private static final class PermissionOwner {
        final String nonce=java.util.UUID.randomUUID().toString().replace("-","");
        final String selection,request;
        final int requestCode;
        Object attachment;
        PermissionOwner(String selection,String request,int requestCode,Object attachment){this.selection=selection;this.request=request;this.requestCode=requestCode;this.attachment=attachment;}
    }
    private static PermissionOwner permissionOwner;

    private final Activity activity;
    private final AndroidNodeStore nodeStore;
    private final AndroidStandardExitStore exitStore;
    private final AndroidRuntimeRegistry runtime;
    private final NativeWireGuardController wireGuard;
    private final NativeAmneziaWGController amneziaWG;
    private final NativeSingBoxController singBox;
    private final NativeXrayController xray;
    private final AndroidModeOrchestrator orchestrator;
    private final AndroidMultihopRuntime multihop;
    private final AtomicBoolean disconnecting = new AtomicBoolean(false);

    private String pendingMode = "";
    private List<String> pendingLayers = Collections.emptyList();
    private AndroidNodeStore.Node pendingNode, pendingEntry, pendingExit;
    private AndroidStandardExitStore.Entry pendingStandardExit;
    private AndroidStandardExitStore.Entry pendingOrdinaryEntry;
    private boolean pendingExternalDirect;
    private String pendingExitMode = "";
    private String pendingExecution = "local";
    private String pendingEntryMode = "wg";
    private String pendingExternalDigest = "", pendingEntryDigest = "", pendingExternalRequestDigest = "";
    private Callback pendingCallback;
    private AndroidStartupPolicy.Attempt pendingStartup;
    private final Object permissionAttachment=new Object();
    private PermissionOwner pendingPermission;
    private boolean pendingSaved;

    AndroidUnifiedConnectionController(Activity activity, AndroidNodeStore nodeStore) {
        this.activity = activity;
        this.nodeStore = nodeStore;
        this.exitStore = new AndroidStandardExitStore(activity);
        runtime = AndroidRuntimeRegistry.get(activity);
        wireGuard = runtime.wireGuard;
        amneziaWG = runtime.amneziaWG;
        singBox = runtime.singBox;
        xray = runtime.xray;
        orchestrator = runtime.orchestrator;
        multihop = runtime.multihop;
    }

    boolean isActiveOrTransitioning() { return pendingCallback!=null || disconnecting.get() || AndroidVpnMutationGuard.isBusy(activity); }
    boolean isConnected() { return AndroidHomeStateStore.snapshot(activity).connected; }
    boolean isMultihopConnected() { return multihop.isConnected(); }
    String activeMultihopEntryId() { return multihop.activeEntryId(); }
    String activeMultihopExitId() { return multihop.activeExitId(); }
    String activeMultihopEntryMode() { return multihop.activeEntryMode(); }
    String activeMultihopExitMode() { return multihop.activeExitMode(); }
    List<AndroidStandardExitStore.Entry> standardExits() throws Exception { return exitStore.list(); }

    String capturedExternalExecution(AndroidHomeStateStore.Snapshot owner,String requested)throws Exception{
        if(owner==null||!owner.connected||!"connected".equals(owner.phase)||!"passed".equals(owner.pathProof)||!"external".equals(owner.logicalMode)
                ||!samePath(owner,AndroidHomeStateStore.snapshot(activity)))throw new IllegalStateException("The temporary external path lost its captured owner.");
        if(!requested.equals(runtime.standardExit.capturedRequestedExecution(owner)))throw new IllegalStateException("The external execution changed during the temporary test.");
        final String selected=runtime.standardExit.capturedExternalExecution(owner);
        if(!samePath(owner,AndroidHomeStateStore.snapshot(activity)))throw new IllegalStateException("The temporary external owner changed while reading its execution receipt.");
        return selected;
    }

    boolean capturedOrdinaryEntryMatches(AndroidHomeStateStore.Snapshot owner,AndroidStandardExitStore.Entry expected)throws Exception{
        if(!samePath(owner,AndroidHomeStateStore.snapshot(activity)))return false;
        AndroidStandardExitStore.Entry captured=runtime.standardExit.capturedOrdinaryEntry(owner);
        return (expected==null?captured==null:captured!=null&&externalDigest(expected).equals(externalDigest(captured)))
                &&samePath(owner,AndroidHomeStateStore.snapshot(activity));
    }

    boolean isStartupPending(){return pendingStartup!=null&&pendingCallback!=null;}
    boolean isPermissionPending(){return pendingCallback!=null;}
    boolean cancelPermissionPending(){return cancelPending(pendingCallback);}
    boolean cancelStartupPending(){
        if(!isStartupPending())return false;
        AndroidStartupPolicy.Attempt captured=pendingStartup;Callback callback=pendingCallback;
        clearPending();captured.cancel();callback.finished(false,"Automatic startup was cancelled; Connect remains a separate choice.");return true;
    }

    void connectStartup(AndroidStartupPolicy.Attempt capture,Callback callback){
        if(pendingCallback!=null){callback.finished(false,"Finish or cancel the current Android permission request first.");return;}
        try{String selection=AndroidConnectionSelection.digest(activity,nodeStore);prepareStartup(capture,callback);requestPermission(capture.external()?"saved external startup path":capture.multihop()?"saved startup multihop":"startup "+displayMode(capture.mode),selection);}
        catch(Exception rejected){clearPending();if(capture!=null)capture.cancel();callback.finished(false,safe(rejected));}
    }

    private void prepareStartup(AndroidStartupPolicy.Attempt capture,Callback callback)throws Exception{
        if(capture==null||pendingCallback!=null)throw new IllegalStateException("The startup permission request is unavailable or another request is pending.");
        capture.requireCurrent(activity,nodeStore,this);
        pendingStartup=capture;pendingCallback=callback;pendingNode=capture.node;
        pendingMode=capture.external()?"external":capture.multihop()?"multihop":capture.mode;pendingLayers=Collections.emptyList();
        pendingEntry=capture.entry;pendingExit=capture.exit;pendingEntryMode=capture.entryMode;
        pendingExitMode=capture.exitMode;pendingExecution=capture.execution;
        pendingStandardExit=null;pendingOrdinaryEntry=null;pendingExternalDirect=false;
        if(capture.external()){
            pendingStandardExit=AndroidStandardExitStore.copy(capture.external);pendingOrdinaryEntry=capture.ordinaryEntry==null?null:AndroidStandardExitStore.copy(capture.ordinaryEntry);pendingExternalDirect=capture.entry==null&&pendingOrdinaryEntry==null;
            pendingExternalDigest=externalDigest(pendingStandardExit);pendingEntryDigest=pendingOrdinaryEntry!=null?externalDigest(pendingOrdinaryEntry):pendingExternalDirect?"":entryDigest(capture.entry);
            pendingExternalRequestDigest=pendingOrdinaryEntry!=null?ordinaryRequestDigest(pendingEntryMode,pendingEntryDigest,pendingExternalDigest,pendingExecution):externalRequestDigest(pendingExternalDirect,pendingEntryMode,pendingEntryDigest,pendingExternalDigest,pendingExecution);
        }
    }


    /** Frozen references to the proved pre-test connection, never a new saved profile. */
    static final class RestorePoint {
        final AndroidHomeStateStore.Snapshot home;
        final String topology, execution, selectedExecution, source;
        final AndroidNodeStore.Node node, entry, exit;
        final AndroidStandardExitStore.Entry external;
        final AndroidStandardExitStore.Entry ordinaryEntry;
        final java.util.Map<File,String> files;
        final String externalDigest;
        final String ordinaryEntryDigest;
        final AndroidMultihopRuntime.RestoreCapture multihopCapture;
        RestorePoint(AndroidHomeStateStore.Snapshot home,String topology,AndroidNodeStore.Node node,
                     AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,AndroidStandardExitStore.Entry external,
                     String execution,String selectedExecution,String source,java.util.Map<File,String> files,String externalDigest,AndroidMultihopRuntime.RestoreCapture multihopCapture){
            this(home,topology,node,entry,exit,external,null,execution,selectedExecution,source,files,externalDigest,"",multihopCapture);
        }
        RestorePoint(AndroidHomeStateStore.Snapshot home,String topology,AndroidNodeStore.Node node,
                     AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,AndroidStandardExitStore.Entry external,AndroidStandardExitStore.Entry ordinaryEntry,
                     String execution,String selectedExecution,String source,java.util.Map<File,String> files,String externalDigest,String ordinaryEntryDigest,AndroidMultihopRuntime.RestoreCapture multihopCapture){
            this.home=home;this.topology=topology;this.node=node;this.entry=entry;this.exit=exit;this.external=external;
            this.ordinaryEntry=ordinaryEntry;this.ordinaryEntryDigest=ordinaryEntryDigest;
            this.execution=execution;this.selectedExecution=selectedExecution;this.source=source;this.files=Collections.unmodifiableMap(new java.util.LinkedHashMap<>(files));this.externalDigest=externalDigest;
            this.multihopCapture=multihopCapture;
        }
        boolean connected(){return home.connected;}
    }

    RestorePoint captureRestorePoint() throws Exception {
        AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(activity);
        if(pendingCallback!=null||disconnecting.get())throw new IllegalStateException("Finish the current VPN transition before a temporary test.");
        if(!home.connected){
            if(isActiveOrTransitioning())throw new IllegalStateException("The current native VPN owner has not drained.");
            return new RestorePoint(home,"off",null,null,null,null,"","","",Collections.emptyMap(),"",null);
        }
        if(!"connected".equals(home.phase)||!"passed".equals(home.pathProof)||home.sessionId.isEmpty())throw new IllegalStateException("The original path requires fresh connection proof before testing another path.");
        String topology="router",execution="",selectedExecution="",source="",savedExternal="",savedOrdinary="";
        AndroidNodeStore.Node node=null,entry=null,exit=null;AndroidStandardExitStore.Entry external=null,ordinaryEntry=null;
        AndroidMultihopRuntime.RestoreCapture multihopCapture=null;
        java.util.Map<File,String> files=new java.util.LinkedHashMap<>();
        if("multihop".equals(home.logicalMode)){
            topology="multihop";entry=requiredNode(home.activeEntryId);exit=requiredNode(home.activeExitId);
            multihopCapture=multihop.captureRestore(entry,exit,home);
            execution=multihopCapture.policy;
            selectedExecution=multihopCapture.selected;
            if(!multihop.isConnected()||!home.activeEntryId.equals(multihop.activeEntryId())||!home.activeExitId.equals(multihop.activeExitId())
                    ||!home.activeEntryMode.equals(multihop.activeEntryMode())||!home.runtimeMode.equals(multihop.activeExitMode())
                    ||!java.util.Arrays.asList("local","server","auto").contains(execution)||!java.util.Arrays.asList("local","server").contains(selectedExecution)
                    ||!"auto".equals(execution)&&!execution.equals(selectedExecution))throw new IllegalStateException("The live multihop graph or its execution choice could not be captured.");
            files.put(entry.file,multihopCapture.entrySource.digest);files.put(exit.file,multihopCapture.exitSource.digest);
        }else if("external".equals(home.logicalMode)){
            topology="external";
            execution=runtime.standardExit.capturedRequestedExecution(home);selectedExecution=runtime.standardExit.capturedExternalExecution(home);
            external=AndroidStandardExitStore.copy(exitStore.get(home.activeExternalId));AndroidStandardExitStore.validate(external);
            if(!home.activeExternalProtocol.equals(external.protocol))throw new IllegalStateException("The active external protocol changed.");
            savedExternal=externalDigest(external);
            ordinaryEntry=runtime.standardExit.capturedOrdinaryEntry(home);
            if(ordinaryEntry!=null){
                savedOrdinary=externalDigest(ordinaryEntry);
                if(!"local".equals(execution)||!"local".equals(selectedExecution)||!home.activeEntryId.equals(ordinaryEntry.id)
                        ||!savedOrdinary.equals(externalDigest(exitStore.get(ordinaryEntry.id))))throw new IllegalStateException("The original ordinary entry changed before capture.");
            }else if(!home.activeEntryId.isEmpty()){entry=requiredNode(home.activeEntryId);files.put(entry.file,entryDigest(entry));}
        }else{
            node=requiredNode(home.activeNodeId);source=orchestrator.captureSource(node.file,home.sessionId,home.runtimeMode);files.put(node.file,entryDigest(node));
        }
        if(!samePath(home,AndroidHomeStateStore.snapshot(activity))||multihopCapture!=null&&!multihop.captureCurrent(multihopCapture))throw new IllegalStateException("The original connection changed while its restoration state was captured.");
        return new RestorePoint(home,topology,node,entry,exit,external,ordinaryEntry,execution,selectedExecution,source,files,savedExternal,savedOrdinary,multihopCapture);
    }

    boolean restorePointCurrent(RestorePoint point){
        return point!=null&&(point.connected()?samePath(point.home,AndroidHomeStateStore.snapshot(activity))
                &&(!"multihop".equals(point.topology)||multihop.captureCurrent(point.multihopCapture)):idleCurrent(point.home));
    }
    AndroidHomeStateStore.Snapshot captureIdle() throws Exception {
        AndroidHomeStateStore.Snapshot idle=AndroidHomeStateStore.snapshot(activity);
        if(!idleCurrent(idle))throw new IllegalStateException("A new connection or undrained runtime owns the path.");
        return idle;
    }
    boolean idleCurrent(AndroidHomeStateStore.Snapshot idle){
        if(idle==null||pendingCallback!=null||disconnecting.get()||isActiveOrTransitioning())return false;
        AndroidHomeStateStore.Snapshot now=AndroidHomeStateStore.snapshot(activity);
        return !idle.connected&&!now.connected&&idle.sessionId.equals(now.sessionId)&&idle.pathGeneration==now.pathGeneration
                &&idle.phase.equals(now.phase)&&java.util.Arrays.asList("off","disconnected","failed").contains(now.phase);
    }
    private static boolean samePath(AndroidHomeStateStore.Snapshot a,AndroidHomeStateStore.Snapshot b){
        return a!=null&&b!=null&&a.connected==b.connected&&a.sessionId.equals(b.sessionId)&&a.pathGeneration==b.pathGeneration
                &&a.phase.equals(b.phase)&&a.pathProof.equals(b.pathProof)&&a.logicalMode.equals(b.logicalMode)&&a.runtimeMode.equals(b.runtimeMode)
                &&a.activeNodeId.equals(b.activeNodeId)&&a.activeEntryId.equals(b.activeEntryId)&&a.activeExitId.equals(b.activeExitId)
                &&a.activeEntryMode.equals(b.activeEntryMode)&&a.activeExternalId.equals(b.activeExternalId)&&a.activeExternalProtocol.equals(b.activeExternalProtocol);
    }
    private AndroidNodeStore.Node requiredNode(String id)throws Exception{
        AndroidNodeStore.Node node=findNode(id);if(node==null||node.file==null||!node.file.isFile())throw new IllegalStateException("An original connection node disappeared.");return node;
    }
    private void validateRestorePoint(RestorePoint point)throws Exception{
        if("multihop".equals(point.topology)){
            if(point.multihopCapture==null||!point.multihopCapture.owner.matchesHome(point.home))throw new IllegalStateException("The original multihop home capture changed.");
            point.multihopCapture.require(point.entry,point.exit);
        }
        for(java.util.Map.Entry<File,String> file:point.files.entrySet())if(!file.getValue().equals(AndroidTorProfile.digest(AndroidPrivateFileStore.read(file.getKey(),AndroidNodeStore.MAX_BUNDLE))))throw new IllegalStateException("An original node changed; automatic restoration was cancelled.");
        if(point.external!=null&&!point.externalDigest.equals(externalDigest(exitStore.get(point.external.id))))throw new IllegalStateException("The original external profile changed; automatic restoration was cancelled.");
        if(point.ordinaryEntry!=null){
            if(point.entry!=null||!"local".equals(point.execution)||!"local".equals(point.selectedExecution))throw new IllegalStateException("The original ordinary Tor execution changed.");
            requireOrdinaryCapture(point.ordinaryEntry,point.external,point.home.activeEntryMode,point.execution,point.ordinaryEntryDigest,point.externalDigest);
        }
    }
    void restoreCaptured(RestorePoint point,AndroidHomeStateStore.Snapshot idle,Callback callback){
        try{if(point==null||!point.connected()||!idleCurrent(idle))throw new IllegalStateException("A newer connection decision prevents automatic restoration.");validateRestorePoint(point);}
        catch(Exception changed){callback.finished(false,safe(changed));return;}
        callback.progress("Restoring the original captured connection and checking its real path again…");
        Callback guarded=new Callback(){
            public void validate()throws Exception{if(!idleCurrent(idle))throw new IllegalStateException("A newer decision cancelled the pending original connection.");validateRestorePoint(point);callback.validate();}
            public void owned(String session){callback.owned(session);}public void progress(String message){callback.progress(message);}public void finished(boolean ok,String message){callback.finished(ok,message);}
        };
        if("multihop".equals(point.topology)){
            if(VpnService.prepare(activity)!=null){callback.finished(false,"Android VPN permission changed; grant permission before restoring the original multihop connection.");return;}
            try{guarded.validate();}catch(Exception changed){callback.finished(false,safe(changed));return;}
            multihop.restoreCaptured(point.entry,point.exit,point.multihopCapture,idle,new AndroidMultihopRuntime.Callback(){
                public void owned(String id){activity.runOnUiThread(()->callback.owned(id));}
                public void progress(String message){activity.runOnUiThread(()->callback.progress(message));}
                public void finished(boolean ok,String message){activity.runOnUiThread(()->callback.finished(ok,message));}
            });return;
        }
        if("external".equals(point.topology)){
            if(point.ordinaryEntry!=null){connectOrdinaryTor(point.ordinaryEntry,point.external,point.execution,guarded);return;}
            if(point.entry==null||point.execution.isEmpty()||"local".equals(point.execution)){connectExternal(point.entry,point.external,point.entry==null,point.home.activeEntryMode,guarded);return;}
            if(VpnService.prepare(activity)!=null){callback.finished(false,"Android VPN permission changed; grant permission before restoring the original external path.");return;}
            try{guarded.validate();}catch(Exception changed){callback.finished(false,safe(changed));return;}
            runtime.standardExit.restoreCaptured(point.entry.file,point.external,point.home.activeEntryMode,point.execution,point.selectedExecution,new AndroidStandardExitRuntime.Callback(){
                public void owned(String id){activity.runOnUiThread(()->callback.owned(id));}public void progress(String message){activity.runOnUiThread(()->callback.progress(message));}public void finished(boolean ok,String message){activity.runOnUiThread(()->callback.finished(ok,message));}
            });return;
        }
        if(VpnService.prepare(activity)!=null){callback.finished(false,"Android VPN permission changed; grant permission before restoring the original connection.");return;}
        orchestrator.restoreCaptured(point.node.file,point.home.runtimeMode,point.home.logicalMode,point.home.fallback,point.source,new AndroidModeOrchestrator.Callback(){
            public void owned(String id){activity.runOnUiThread(()->callback.owned(id));}
            public void progress(String message){activity.runOnUiThread(()->callback.progress(message));}
            public void finished(boolean ok,String mode,String message){activity.runOnUiThread(()->callback.finished(ok,message));}
        });
    }

    boolean restoredCurrent(RestorePoint point,String session){
        AndroidHomeStateStore.Snapshot now=AndroidHomeStateStore.snapshot(activity);
        if(point==null||session==null||session.isEmpty()||!session.equals(now.sessionId)||!now.connected||!"connected".equals(now.phase)||!"passed".equals(now.pathProof))return false;
        if("router".equals(point.topology))return point.home.logicalMode.equals(now.logicalMode)&&point.home.runtimeMode.equals(now.runtimeMode)&&point.home.activeNodeId.equals(now.activeNodeId);
        if("multihop".equals(point.topology))return "multihop".equals(now.logicalMode)&&point.home.runtimeMode.equals(now.runtimeMode)&&point.home.activeEntryId.equals(now.activeEntryId)&&point.home.activeExitId.equals(now.activeExitId)&&point.home.activeEntryMode.equals(now.activeEntryMode)&&multihop.restoredMatches(point.multihopCapture,point.entry,point.exit,now);
        boolean same="external".equals(now.logicalMode)&&point.home.activeExternalId.equals(now.activeExternalId)&&point.home.activeExternalProtocol.equals(now.activeExternalProtocol)&&point.home.activeEntryId.equals(now.activeEntryId)&&point.home.activeEntryMode.equals(now.activeEntryMode);
        if(!same)return false;
        try{AndroidStandardExitStore.Entry restored=runtime.standardExit.capturedOrdinaryEntry(now);
            if(point.ordinaryEntry==null?restored!=null:restored==null||!point.ordinaryEntryDigest.equals(externalDigest(restored)))return false;
        }catch(Exception stale){return false;}
        if(!point.execution.isEmpty())try{return point.execution.equals(runtime.standardExit.capturedRequestedExecution(now))&&point.selectedExecution.equals(runtime.standardExit.capturedExternalExecution(now));}catch(Exception stale){return false;}
        return true;
    }

    /** Cleanup can retire only the captured session and must join its real worker. */
    void stopCaptured(String session,String topology,Callback callback){
        AndroidHomeStateStore.Snapshot before=AndroidHomeStateStore.snapshot(activity);
        if(session==null||session.isEmpty()||!session.equals(before.sessionId)||!disconnecting.compareAndSet(false,true)){
            callback.finished(false,"The captured path was replaced or another stop owns cleanup; automatic restoration was cancelled.");return;
        }
        final long stoppedGeneration=before.pathGeneration+(before.connected?1L:0L)+1L;
        Callback done=new Callback(){public void progress(String message){activity.runOnUiThread(()->callback.progress(message));}
            public void finished(boolean ok,String message){
                disconnecting.set(false);activity.runOnUiThread(()->{
                    AndroidHomeStateStore.Snapshot now=AndroidHomeStateStore.snapshot(activity);
                    long expected=ok?stoppedGeneration:before.pathGeneration+(before.connected?1L:0L);
                    if(now.pathGeneration!=expected||!ok&&!session.equals(now.sessionId))callback.superseded();
                    boolean unchanged=ok&&!now.connected&&"off".equals(now.phase)&&now.pathGeneration==stoppedGeneration;
                    callback.finished(unchanged,unchanged?message:"Cleanup completed or remains owned, but a newer path decision prevents restoration: "+message);
                });
            }};
        if("router".equals(topology)){
            orchestrator.disconnectCaptured(session,new AndroidModeOrchestrator.Callback(){public void progress(String message){done.progress(message);}public void finished(boolean ok,String mode,String message){done.finished(ok,message);}});return;
        }
        new Thread(()->{
            try{
                boolean stopped="multihop".equals(topology)?multihop.disconnectAndDrainCaptured(session):"external".equals(topology)&&runtime.standardExit.disconnectAndDrainCaptured(session);
                done.finished(stopped,stopped?"The captured native path and its connection worker have drained.":"The captured native owner changed.");
            }catch(Throwable error){done.finished(false,"Captured native cleanup remains pending: "+safe(error));}
        },"routervpn-captured-path-drain").start();
    }
    boolean cancelPending(Callback owner){
        if(owner==null||pendingCallback!=owner)return false;
        if(pendingStartup!=null)pendingStartup.cancel();
        clearPending();owner.finished(false,"The captured Android permission request was cancelled.");return true;
    }

    void connect(String mode, List<String> layers, Callback callback) {
        if(pendingCallback!=null){callback.finished(false,"Finish or cancel the current Android permission request first.");return;}
        if (isActiveOrTransitioning()) { callback.finished(false, "Disconnect the current Router VPN session or let its transition finish first."); return; }
        final String selection;
        try { selection=AndroidConnectionSelection.digest(activity,nodeStore);activeBundle(); } catch (Exception error) { callback.finished(false, safe(error)); return; }
        pendingNode = null; prepareSingleNode(mode,layers,callback,selection);
    }

    /** Explicit/test-only node connection that never mutates AndroidNodeStore.activeId(). */
    void connectNode(AndroidNodeStore.Node node, String mode, List<String> layers, Callback callback) {
        if(pendingCallback!=null){callback.finished(false,"Finish or cancel the current Android permission request first.");return;}
        if(node==null||node.file==null||!node.file.isFile()||node.file.length()<=0){callback.finished(false,"Choose a valid stored Router VPN node first.");return;}
        if (isActiveOrTransitioning()) { callback.finished(false, "Disconnect the current Router VPN session or let its transition finish first."); return; }
        final String selection;
        try{selection=AndroidConnectionSelection.digest(activity,nodeStore);}catch(Exception error){callback.finished(false,safe(error));return;}
        pendingNode=node; prepareSingleNode(mode,layers,callback,selection);
    }

    private void prepareSingleNode(String mode,List<String>layers,Callback callback,String selection){
        if(pendingCallback!=null){callback.finished(false,"Finish or cancel the current Android permission request first.");return;}
        pendingMode = mode == null || mode.trim().isEmpty() ? "smart-auto" : mode.trim().toLowerCase();
        pendingLayers = layers == null ? Collections.emptyList() : new ArrayList<>(layers);
        pendingEntry = null; pendingExit = null; pendingStandardExit=null; pendingOrdinaryEntry=null; pendingExternalDirect=false; pendingExitMode = ""; pendingCallback = callback;
        requestPermission("Router VPN " + displayMode(pendingMode),selection);
    }

    void connectMultihop(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, String exitMode, Callback callback) {
        connectMultihop(entry, exit, exitMode, "local", callback);
    }
    void connectMultihop(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, String exitMode, String execution, Callback callback) {
        connectMultihop(entry,exit,exitMode,execution,"wg",callback);
    }
    void connectMultihop(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, String exitMode, String execution, String entryMode, Callback callback) {
        if(pendingCallback!=null){callback.finished(false,"Finish or cancel the current Android permission request first.");return;}
        if (!NativeSingBoxController.nativeMultihopEntry(entryMode)) { callback.finished(false,"Choose an exact native entry transport.");return; }
        if(!java.util.Arrays.asList("local","server","auto").contains(execution)){callback.finished(false,"Choose Local, Server, or Compare both.");return;}
        if (entry == null || exit == null || entry.id.equals(exit.id)) { callback.finished(false, "Multihop requires two different stored nodes."); return; }
        if (exitMode == null || exitMode.trim().isEmpty()) { callback.finished(false, "Choose a supported multihop exit transport."); return; }
        if (isActiveOrTransitioning()) { callback.finished(false, "Disconnect the current Router VPN session before multihop."); return; }
        final String selection;
        try{selection=AndroidConnectionSelection.digest(activity,nodeStore);}catch(Exception error){callback.finished(false,safe(error));return;}
        pendingNode=null;pendingStandardExit=null;pendingOrdinaryEntry=null;pendingExternalDirect=false;pendingMode="multihop";pendingLayers=Collections.emptyList();pendingEntry=entry;pendingExit=exit;pendingExitMode=exitMode.trim();pendingExecution=execution;pendingEntryMode=entryMode;pendingCallback=callback;
        requestPermission("Router VPN multihop",selection);
    }

    /** Uses the existing proven Android custom-exit runtime under the same VPN-permission owner. */
    void connectExternal(AndroidConnectionProfileStore.ExternalSelection path,Callback callback){
        if(path==null){callback.finished(false,"Choose a stored external path first.");return;}
        if(path.ordinaryEntry!=null)connectOrdinaryTor(path.ordinaryEntry,path.exit,path.execution,callback);
        else connectExternal(path.entry,path.exit,path.direct(),path.entryMode,path.execution,callback);
    }

    void connectOrdinaryTor(AndroidStandardExitStore.Entry entry,AndroidStandardExitStore.Entry exit,String execution,Callback callback){
        if(isActiveOrTransitioning()){callback.finished(false,"Disconnect the current VPN before selecting an ordinary Tor path.");return;}
        if(pendingCallback!=null){callback.finished(false,"Finish or cancel the current Android VPN permission request first.");return;}
        try{
            String selection=AndroidConnectionSelection.digest(activity,nodeStore);
            AndroidStandardExitStore.Entry capturedEntry=AndroidStandardExitStore.copy(entry),capturedExit=AndroidStandardExitStore.copy(exit);
            String mode=AndroidExternalPolicy.protocol(capturedEntry.protocol),entryDigest=externalDigest(capturedEntry),exitDigest=externalDigest(capturedExit);
            requireOrdinaryCapture(capturedEntry,capturedExit,mode,execution,entryDigest,exitDigest);
            AndroidTorProfile.compileOrdinary(capturedEntry,capturedExit,"permission-validation",execution);
            pendingNode=null;pendingMode="external";pendingLayers=Collections.emptyList();pendingEntry=null;pendingExit=null;pendingExitMode="";
            pendingOrdinaryEntry=capturedEntry;pendingStandardExit=capturedExit;pendingExternalDirect=false;pendingEntryMode=mode;
            pendingExternalDigest=exitDigest;pendingEntryDigest=entryDigest;pendingExternalRequestDigest=ordinaryRequestDigest(mode,entryDigest,exitDigest,execution);
            pendingExecution=execution;pendingCallback=callback;
            requestPermission(capturedEntry.name+" → "+capturedExit.name+" via Local Tor",selection);
        }catch(Exception invalid){clearPending();callback.finished(false,"The saved ordinary Tor path changed or could not be captured: "+safe(invalid));}
    }

    void connectExternal(AndroidNodeStore.Node entry, AndroidStandardExitStore.Entry exit, boolean direct, Callback callback) {
        connectExternal(entry,exit,direct,"wg",callback);
    }

    void connectExternal(AndroidNodeStore.Node entry, AndroidStandardExitStore.Entry exit, boolean direct, String entryMode, Callback callback) {
        connectExternal(entry,exit,direct,entryMode,"local",callback);
    }

    void connectExternal(AndroidNodeStore.Node entry, AndroidStandardExitStore.Entry exit, boolean direct, String entryMode, String execution, Callback callback) {
        if(exit==null){callback.finished(false,"Choose a stored custom exit first.");return;}
        if(!direct&&(entry==null||entry.file==null||!entry.file.isFile())){callback.finished(false,"Choose a valid Router VPN entry node for the hopped external test.");return;}
        if(!direct&&!NativeSingBoxController.nativeMultihopEntry(entryMode)){callback.finished(false,"Choose the exact saved native Router VPN entry mode.");return;}
        if(isActiveOrTransitioning()){callback.finished(false,"Disconnect the current Router VPN session before a custom-exit test.");return;}
        if(pendingCallback!=null){callback.finished(false,"Finish or cancel the current Android VPN permission request first.");return;}
        final AndroidStandardExitStore.Entry captured;final String exitDigest,entryDigest,requestDigest,selection;
        try{
            selection=AndroidConnectionSelection.digest(activity,nodeStore);
            captured=AndroidStandardExitStore.copy(exit);AndroidStandardExitStore.validate(captured);AndroidStandardExitStore.validateExecution(captured,!direct,execution);
            exitDigest=externalDigest(captured);entryDigest=direct?"":entryDigest(entry);
            requireExternalCapture(entry,captured,direct,entryDigest,exitDigest);
            requestDigest=externalRequestDigest(direct,direct?"wg":entryMode,entryDigest,exitDigest,execution);
        }catch(Exception invalid){callback.finished(false,"The saved external selection changed or could not be captured; select the path again.");return;}
        pendingNode=null;pendingMode="external";pendingLayers=Collections.emptyList();pendingEntry=direct?null:entry;pendingOrdinaryEntry=null;pendingExit=null;pendingExitMode="";pendingStandardExit=captured;pendingExternalDirect=direct;pendingEntryMode=direct?"wg":entryMode;pendingExternalDigest=exitDigest;pendingEntryDigest=entryDigest;pendingExternalRequestDigest=requestDigest;pendingExecution=execution;pendingCallback=callback;
        requestPermission(direct?"direct "+exit.protocol+" custom exit":"Router VPN entry → "+exit.protocol+" custom exit",selection);
    }

    List<NativeSingBoxController.ModeInfo> supportedNativeEntryModes(AndroidNodeStore.Node entry)throws Exception{
        if(entry==null)return Collections.emptyList();
        JSONObject bundle=new JSONObject(AndroidTorProfile.strictText(AndroidPrivateFileStore.read(entry.file,AndroidNodeStore.MAX_BUNDLE)));AndroidNodeStore.validateBundle(bundle);
        JSONObject profiles=bundle.getJSONObject("profiles");JSONArray modes=bundle.getJSONArray("modes");
        List<NativeSingBoxController.ModeInfo> result=new ArrayList<>();java.util.HashSet<String> seen=new java.util.HashSet<>();
        for(int i=0;i<modes.length();i++){JSONObject mode=modes.getJSONObject(i);String id=mode.optString("id","");
            if(NativeSingBoxController.nativeMultihopEntry(id)&&profiles.optJSONObject(id)!=null&&seen.add(id))result.add(new NativeSingBoxController.ModeInfo(id,mode.optString("name",id)+" ["+id+"]"));}
        return result;
    }

    private static String externalDigest(AndroidStandardExitStore.Entry exit)throws Exception{return AndroidTorProfile.digest(AndroidStandardExitStore.snapshot(exit).getBytes(StandardCharsets.UTF_8));}
    private static String entryDigest(AndroidNodeStore.Node entry)throws Exception{if(entry==null||entry.file==null)throw new IllegalArgumentException("A captured entry is required.");return AndroidTorProfile.digest(AndroidPrivateFileStore.read(entry.file,AndroidNodeStore.MAX_BUNDLE));}
    private static String externalRequestDigest(boolean direct,String mode,String entry,String exit,String execution)throws Exception{return AndroidTorProfile.digest(("routervpn-external-permission-v2\n"+direct+"\n"+mode+"\n"+entry+"\n"+exit+"\n"+execution).getBytes(StandardCharsets.UTF_8));}
    private static String ordinaryRequestDigest(String mode,String entry,String exit,String execution)throws Exception{return AndroidTorProfile.digest(("routervpn-external-permission-v3\nexternal\n"+mode+"\n"+entry+"\n"+exit+"\n"+execution).getBytes(StandardCharsets.UTF_8));}
    private void requireOrdinaryCapture(AndroidStandardExitStore.Entry entry,AndroidStandardExitStore.Entry exit,String mode,String execution,String entryDigest,String exitDigest)throws Exception{
        AndroidStandardExitStore.validate(entry);AndroidStandardExitStore.validate(exit);
        if(!AndroidExternalPolicy.supports(entry.protocol)||!AndroidTorProfile.isTor(exit.protocol)||entry.id.equals(exit.id)
                ||!mode.equals(AndroidExternalPolicy.protocol(entry.protocol))||!"local".equals(execution))throw new IllegalStateException("The ordinary Tor path lost its selected entry, exit or Local execution.");
        if(!entryDigest.matches("[0-9a-f]{64}")||!entryDigest.equals(externalDigest(entry))||!entryDigest.equals(externalDigest(exitStore.get(entry.id)))
                ||!exitDigest.matches("[0-9a-f]{64}")||!exitDigest.equals(externalDigest(exit))||!exitDigest.equals(externalDigest(exitStore.get(exit.id))))throw new IllegalStateException("The captured ordinary Tor node changed.");
    }
    private void requireExternalCapture(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,boolean direct,String nodeDigest,String exitDigest)throws Exception{
        if(exit==null||!exitDigest.matches("[0-9a-f]{64}")||!exitDigest.equals(externalDigest(exit))||!exitDigest.equals(externalDigest(exitStore.get(exit.id))))throw new IllegalStateException("The captured external profile changed.");
        if(direct){if(!nodeDigest.isEmpty())throw new IllegalStateException("A direct external path acquired another entry.");}
        else if(!nodeDigest.matches("[0-9a-f]{64}")||!nodeDigest.equals(entryDigest(entry)))throw new IllegalStateException("The captured Router VPN entry changed.");
    }

    List<NativeSingBoxController.ModeInfo> supportedMultihopExitModes(AndroidNodeStore.Node exit) throws Exception {
        if (exit == null) return Collections.emptyList();
        return multihop.listSupportedExitModes(exit.file);
    }

    void savePending(Bundle out) {
        if (out == null || pendingCallback == null || pendingMode.isEmpty() || !ownsPermission(pendingPermission,permissionAttachment)) return;
        out.putString(STATE_PERMISSION,pendingPermission.nonce);out.putString(STATE_SELECTION,pendingPermission.selection);pendingSaved=true;
        out.putBoolean(STATE_PENDING,true);out.putString(STATE_MODE,pendingMode);out.putStringArrayList(STATE_LAYERS,new ArrayList<>(pendingLayers));
        if(pendingStartup!=null)out.putString(STATE_STARTUP,pendingStartup.nonce);
        if(pendingNode!=null)out.putString(STATE_NODE,pendingNode.id);if(pendingEntry!=null)out.putString(STATE_ENTRY,pendingEntry.id);if(pendingExit!=null)out.putString(STATE_EXIT,pendingExit.id);out.putString(STATE_EXIT_MODE,pendingExitMode);out.putString("multihop_execution_pending",pendingExecution);out.putString("multihop_entry_mode_pending",pendingEntryMode);
        if(pendingStandardExit!=null)out.putString(STATE_STANDARD_EXIT,pendingStandardExit.id);out.putBoolean(STATE_EXTERNAL_DIRECT,pendingExternalDirect);
        if(pendingOrdinaryEntry!=null)out.putString(STATE_ORDINARY_ENTRY,pendingOrdinaryEntry.id);
        if("external".equals(pendingMode)){out.putString("external_profile_digest_pending",pendingExternalDigest);out.putString("external_entry_digest_pending",pendingEntryDigest);out.putString("external_request_digest_pending",pendingExternalRequestDigest);}
    }

    void restorePending(Bundle in, Callback callback) {
        if(pendingCallback!=null){callback.finished(false,"Another Android permission request already owns this screen.");return;}
        if(in==null||!in.getBoolean(STATE_PENDING,false))return;
        try{
            pendingPermission=restorePermission(in.getString(STATE_PERMISSION,""),in.getString(STATE_SELECTION,""),permissionAttachment);
            AndroidConnectionSelection.requireCurrent(activity,nodeStore,pendingPermission.selection);
        }catch(Exception stale){clearPending();callback.finished(false,"The saved Android permission owner is no longer current: "+safe(stale));return;}
        if(in!=null&&in.containsKey(STATE_STARTUP)){
            AndroidStartupPolicy.Attempt captured=AndroidStartupPolicy.restore(in.getString(STATE_STARTUP,""));
            try{prepareStartup(captured,callback);requirePendingIdentity();callback.progress("Waiting for Android VPN permission for the exact captured startup path…");}
            catch(Exception stale){clearPending();if(captured!=null)captured.cancel();callback.finished(false,"Automatic startup was not restored: "+safe(stale));}
            return;
        }
        String mode=in.getString(STATE_MODE,"");if(mode==null||mode.trim().isEmpty()){clearPending();callback.finished(false,"The pending Android connection mode is missing.");return;}pendingMode=mode.trim();
        ArrayList<String>layers=in.getStringArrayList(STATE_LAYERS);pendingLayers=layers==null?Collections.emptyList():new ArrayList<>(layers);
        pendingNode=findNode(in.getString(STATE_NODE,""));pendingEntry=findNode(in.getString(STATE_ENTRY,""));pendingExit=findNode(in.getString(STATE_EXIT,""));
        pendingOrdinaryEntry=findStandardExit(in.getString(STATE_ORDINARY_ENTRY,""));pendingEntryMode=in.getString("multihop_entry_mode_pending","wg");
        if(in.containsKey(STATE_ORDINARY_ENTRY)&&(!"external".equals(pendingMode)||pendingOrdinaryEntry==null||pendingEntry!=null)
                ||pendingOrdinaryEntry==null&&!NativeSingBoxController.nativeMultihopEntry(pendingEntryMode)){clearPending();callback.finished(false,"Pending entry mode or kind is invalid.");return;}
        pendingExecution=in.getString("multihop_execution_pending","local");if(!java.util.Arrays.asList("local","server","auto").contains(pendingExecution)){clearPending();callback.finished(false,"Pending multihop execution is invalid.");return;}
        pendingExitMode=in.getString(STATE_EXIT_MODE,"");if(pendingExitMode==null)pendingExitMode="";
        pendingStandardExit=findStandardExit(in.getString(STATE_STANDARD_EXIT,""));pendingExternalDirect=in.getBoolean(STATE_EXTERNAL_DIRECT,false);
        if("multihop".equals(pendingMode)&&(pendingEntry==null||pendingExit==null||pendingEntry.id.equals(pendingExit.id)||pendingExitMode.isEmpty())){clearPending();callback.finished(false,"Pending multihop permission state could not be restored safely; choose the hops again.");return;}
        if("external".equals(pendingMode)&&(pendingStandardExit==null||(!pendingExternalDirect&&pendingEntry==null&&pendingOrdinaryEntry==null)||pendingExternalDirect&&pendingOrdinaryEntry!=null)){clearPending();callback.finished(false,"Pending external Speed Lab path disappeared before Android VPN permission completed.");return;}
        if("external".equals(pendingMode)){
            pendingExternalDigest=in.getString("external_profile_digest_pending","");pendingEntryDigest=in.getString("external_entry_digest_pending","");pendingExternalRequestDigest=in.getString("external_request_digest_pending","");
            try{
                final String expected;
                if(pendingOrdinaryEntry!=null){
                    requireOrdinaryCapture(pendingOrdinaryEntry,pendingStandardExit,pendingEntryMode,pendingExecution,pendingEntryDigest,pendingExternalDigest);
                    expected=ordinaryRequestDigest(pendingEntryMode,pendingEntryDigest,pendingExternalDigest,pendingExecution);
                    pendingOrdinaryEntry=AndroidStandardExitStore.copy(pendingOrdinaryEntry);
                }else{
                    requireExternalCapture(pendingEntry,pendingStandardExit,pendingExternalDirect,pendingEntryDigest,pendingExternalDigest);
                    AndroidStandardExitStore.validateExecution(pendingStandardExit,!pendingExternalDirect,pendingExecution);
                    expected=externalRequestDigest(pendingExternalDirect,pendingEntryMode,pendingEntryDigest,pendingExternalDigest,pendingExecution);
                }
                if(!pendingExternalRequestDigest.equals(expected))throw new IllegalStateException("The external request identity changed.");pendingStandardExit=AndroidStandardExitStore.copy(pendingStandardExit);
            }
            catch(Exception changed){clearPending();callback.finished(false,"The captured external permission request changed; select the path again.");return;}
        }
        if(!"multihop".equals(pendingMode)&&!"external".equals(pendingMode)&&in.containsKey(STATE_NODE)&&pendingNode==null){clearPending();callback.finished(false,"Pending test node disappeared before Android VPN permission completed.");return;}
        try{requirePendingIdentity();}catch(Exception stale){clearPending();callback.finished(false,"The captured Android permission request changed: "+safe(stale));return;}
        pendingCallback=callback;callback.progress("Waiting for Android VPN permission for restored "+displayMode(pendingMode)+" request…");
    }

    /** Returning from a permission screen never rearms startup or rereads a new
     * requested path. A changed saved choice retires only this pending owner. */
    void resumePending(){
        Callback callback=pendingCallback;if(callback==null)return;
        try{requirePendingIdentity();AndroidConnectionSelection.requireCurrent(activity,nodeStore,pendingPermission.selection);}
        catch(Exception stale){if(pendingCallback!=callback)return;if(pendingStartup!=null)pendingStartup.cancel();clearPending();callback.finished(false,safe(stale));}
    }

    void disconnect(Callback callback) {
        AndroidStartupPolicy.cancelPending();
        AndroidHomeStateStore.advancePathGeneration(activity);
        Callback abandoned=pendingCallback;clearPending();
        if(abandoned!=null)abandoned.finished(false,"Disconnect cancelled the pending Android permission request.");
        if(!disconnecting.compareAndSet(false,true)){callback.finished(false,"A Router VPN disconnect is already being verified.");return;}
        final boolean wasMultihop=multihop.isActiveOrTransitioning();
        final boolean wasExternal=runtime.standardExit.isActiveOrTransitioning();
        activity.runOnUiThread(()->callback.progress("Disconnecting and proving owned Android VPN transports stop…"));
        new Thread(()->{
            try{
                if(wasMultihop)multihop.disconnect();
                if(wasExternal)runtime.standardExit.disconnect();
            }catch(Throwable error){
                disconnecting.set(false);
                activity.runOnUiThread(()->callback.finished(false,"Disconnect incomplete: "+safe(error)));
                return;
            }
            orchestrator.disconnect(new AndroidModeOrchestrator.Callback(){
                @Override public void progress(String message){activity.runOnUiThread(()->callback.progress(message));}
                @Override public void finished(boolean success,String modeId,String message){
                    disconnecting.set(false);
                    activity.runOnUiThread(()->callback.finished(success,wasMultihop&&success?"Disconnected Android multihop and native Router VPN transports.":wasExternal&&success?"Disconnected Android custom exit and native Router VPN transports.":message));
                }
            });
        },"routervpn-unified-disconnect").start();
    }

    /** A temporary external test may stop only the Home session it started. */
    void disconnectExternal(String homeSession, Callback callback) {
        if(homeSession==null||homeSession.isEmpty()){callback.finished(true,"No temporary external runtime was started.");return;}
        new Thread(()->{
            try{boolean stopped=runtime.standardExit.disconnectCaptured(homeSession);activity.runOnUiThread(()->callback.finished(true,stopped?"The captured temporary external path stopped.":"The temporary path was already replaced; its replacement is unchanged."));}
            catch(Throwable failure){activity.runOnUiThread(()->callback.finished(false,"Temporary external cleanup remains pending: "+safe(failure)));}
        },"routervpn-external-test-disconnect").start();
    }

    boolean onActivityResult(int requestCode, int resultCode) {
        if(requestCode<PREPARE_UNIFIED||requestCode>0xffff)return false;
        if(!ownsPermission(pendingPermission,permissionAttachment)||pendingCallback==null||requestCode!=pendingPermission.requestCode)return true;
        Callback callback=pendingCallback;
        if(resultCode!=Activity.RESULT_OK){if(pendingStartup!=null)pendingStartup.cancel();clearPending();callback.finished(false,"Android VPN permission was not granted; Router VPN stayed disconnected.");return true;}
        startPending();return true;
    }

    private void requestPermission(String label,String selection) {
        Callback callback=pendingCallback;if(callback==null)return;
        try{
            AndroidConnectionSelection.requireCurrent(activity,nodeStore,selection);
            Intent permission=VpnService.prepare(activity);
            pendingPermission=createPermission(selection,pendingIdentity(),permission!=null,permissionAttachment);
            if(permission==null){startPending();return;}
            callback.progress("Waiting for Android VPN permission for "+label+"…");
            if(pendingCallback==callback&&ownsPermission(pendingPermission,permissionAttachment))activity.startActivityForResult(permission,pendingPermission.requestCode);
        }catch(Exception rejected){if(pendingCallback!=callback)return;if(pendingStartup!=null)pendingStartup.cancel();clearPending();callback.finished(false,safe(rejected));}
    }

    private void startPending() {
        final String mode=pendingMode;final List<String>layers=new ArrayList<>(pendingLayers);final AndroidNodeStore.Node node=pendingNode,entry=pendingEntry,exit=pendingExit;final AndroidStandardExitStore.Entry standardExit=pendingStandardExit,ordinaryEntry=pendingOrdinaryEntry;final boolean externalDirect=pendingExternalDirect;final String entryMode=pendingEntryMode;final String execution=pendingExecution;final String exitMode=pendingExitMode;final String externalDigest=pendingExternalDigest,entryDigest=pendingEntryDigest;final Callback callback=pendingCallback;final AndroidStartupPolicy.Attempt startup=pendingStartup;final PermissionOwner permission=pendingPermission;
        Exception invalid=null;try{requirePendingIdentity();}catch(Exception stale){invalid=stale;}
        clearPending();if(callback==null)return;
        try{if(invalid!=null)throw invalid;AndroidConnectionSelection.requireCurrent(activity,nodeStore,permission.selection);if(isActiveOrTransitioning())throw new IllegalStateException("Another path owns the pending connection.");callback.validate();if(startup!=null){startup.requireCurrent(activity,nodeStore,this);startup.dispatched();}}catch(Exception stale){if(startup!=null)startup.cancel();callback.finished(false,safe(stale));return;}
        if("multihop".equals(mode)){if(entry==null||exit==null||entry.id.equals(exit.id)||exitMode.isEmpty()){callback.finished(false,"Multihop selection expired; choose entry and exit again.");return;}multihop.connect(entry,exit,exitMode,execution,entryMode,new AndroidMultihopRuntime.Callback(){@Override public void owned(String session){activity.runOnUiThread(()->callback.owned(session));}@Override public void progress(String message){activity.runOnUiThread(()->callback.progress(message));}@Override public void finished(boolean ok,String message){activity.runOnUiThread(()->callback.finished(ok,message));}});return;}
        if("external".equals(mode)){
            try{if(isActiveOrTransitioning())throw new IllegalStateException("Another VPN owns the current path.");
                if(ordinaryEntry!=null){if(externalDirect||entry!=null)throw new IllegalStateException("The captured ordinary entry kind changed.");requireOrdinaryCapture(ordinaryEntry,standardExit,entryMode,execution,entryDigest,externalDigest);}
                else{requireExternalCapture(entry,standardExit,externalDirect,entryDigest,externalDigest);if(!externalDirect&&!NativeSingBoxController.nativeMultihopEntry(entryMode))throw new IllegalArgumentException("The captured entry mode changed.");}
            }
            catch(Exception changed){callback.finished(false,"The captured external path changed during Android permission; select it again.");return;}
            AndroidStandardExitRuntime.Callback bridge=new AndroidStandardExitRuntime.Callback(){@Override public void owned(String homeSession){activity.runOnUiThread(()->callback.owned(homeSession));}@Override public void progress(String message){activity.runOnUiThread(()->callback.progress(message));}@Override public void finished(boolean ok,String message){activity.runOnUiThread(()->callback.finished(ok,message));}};
            if(ordinaryEntry!=null)runtime.standardExit.connectOrdinary(ordinaryEntry,standardExit,execution,bridge);else if(externalDirect)runtime.standardExit.connectDirect(standardExit,bridge);else runtime.standardExit.connect(entry.file,standardExit,entryMode,execution,bridge);return;
        }
        final File bundle;try{bundle=node!=null?node.file:activeBundle();if(bundle==null||!bundle.isFile()||bundle.length()<=0)throw new IllegalStateException("Requested Router VPN node bundle is missing.");}catch(Exception error){callback.finished(false,safe(error));return;}
        AndroidModeOrchestrator.Callback bridge=new AndroidModeOrchestrator.Callback(){@Override public void owned(String session){activity.runOnUiThread(()->callback.owned(session));}@Override public void proved(String session,String raw,String source){if(node==null||startup!=null)AndroidStartupPolicy.recordProven(activity,nodeStore,bundle,session,raw,source);}@Override public void progress(String message){activity.runOnUiThread(()->callback.progress(message));}@Override public void finished(boolean ok,String modeId,String message){activity.runOnUiThread(()->callback.finished(ok,message));}};
        if(startup!=null)orchestrator.startup(bundle,startup.mode,startup.lastRaw,startup.source,bridge);else if("smart-auto".equals(mode))orchestrator.auto(bundle,true,bridge);else if("auto".equals(mode))orchestrator.auto(bundle,false,bridge);else if("all".equals(mode))orchestrator.all(bundle,bridge);else if(mode.startsWith("custom:")){if(layers.isEmpty())callback.finished(false,"CUSTOM requires at least one saved layer.");else orchestrator.custom(bundle,layers,bridge);}else orchestrator.logical(bundle,mode,bridge);
    }

    private AndroidNodeStore.Node findNode(String id){if(id==null||id.isEmpty())return null;try{for(AndroidNodeStore.Node node:nodeStore.list())if(id.equals(node.id))return node;}catch(Exception ignored){}return null;}
    private AndroidStandardExitStore.Entry findStandardExit(String id){if(id==null||id.isEmpty())return null;try{return exitStore.get(id);}catch(Exception ignored){return null;}}
    private File activeBundle() throws Exception {String id=nodeStore.activeId();if(id==null||id.trim().isEmpty())throw new IllegalStateException("Pair/import and select a Router VPN node first.");File file=nodeStore.file(id);if(file==null||!file.isFile()||file.length()<=0)throw new IllegalStateException("Selected Router VPN node bundle is missing.");return file;}
    private String pendingIdentity()throws Exception{
        JSONObject captured=new JSONObject().put("mode",pendingMode).put("layers",new JSONArray(pendingLayers))
                .put("node",pendingNode==null?"":pendingNode.id).put("entry",pendingEntry==null?"":pendingEntry.id).put("exit",pendingExit==null?"":pendingExit.id)
                .put("ordinary_entry",pendingOrdinaryEntry==null?"":pendingOrdinaryEntry.id).put("external_exit",pendingStandardExit==null?"":pendingStandardExit.id)
                .put("direct",pendingExternalDirect).put("entry_mode",pendingEntryMode).put("exit_mode",pendingExitMode).put("execution",pendingExecution)
                .put("external_request",pendingExternalRequestDigest).put("startup",pendingStartup==null?"":pendingStartup.nonce);
        return AndroidTorProfile.digest(captured.toString().getBytes(StandardCharsets.UTF_8));
    }
    private void requirePendingIdentity()throws Exception{
        if(!ownsPermission(pendingPermission,permissionAttachment)||!pendingPermission.request.equals(pendingIdentity()))
            throw new IllegalStateException("The captured Android permission owner was cancelled, consumed or changed.");
    }
    private static synchronized PermissionOwner createPermission(String selection,String request,boolean prompt,Object attachment){
        if(permissionOwner!=null&&permissionOwner.attachment!=null)throw new IllegalStateException("Another screen owns Android VPN permission. Finish or cancel it first.");
        if(prompt&&nextPermissionCode>0xffff)throw new IllegalStateException("Android permission request identities are exhausted. Reopen the app in a new process before connecting.");
        return permissionOwner=new PermissionOwner(selection,request,prompt?nextPermissionCode++:0,attachment);
    }
    private static synchronized PermissionOwner restorePermission(String nonce,String selection,Object attachment){
        if(permissionOwner==null||permissionOwner.attachment!=null||!permissionOwner.nonce.equals(nonce)||!permissionOwner.selection.equals(selection))
            throw new IllegalStateException("The saved Android permission request cannot replace its current owner.");
        permissionOwner.attachment=attachment;return permissionOwner;
    }
    private static synchronized boolean ownsPermission(PermissionOwner captured,Object attachment){return captured!=null&&permissionOwner==captured&&captured.attachment==attachment;}
    private static synchronized void releasePermission(PermissionOwner captured,Object attachment,boolean transfer){
        if(!ownsPermission(captured,attachment))return;
        if(transfer)captured.attachment=null;else permissionOwner=null;
    }
    private void clearPending(){releasePermission(pendingPermission,permissionAttachment,false);pendingPermission=null;pendingSaved=false;pendingStartup=null;pendingEntryMode="wg";pendingExecution="local";pendingMode="";pendingLayers=Collections.emptyList();pendingNode=null;pendingEntry=null;pendingExit=null;pendingStandardExit=null;pendingOrdinaryEntry=null;pendingExternalDirect=false;pendingExitMode="";pendingExternalDigest="";pendingEntryDigest="";pendingExternalRequestDigest="";pendingCallback=null;}
    private static String displayMode(String mode){if("smart-auto".equals(mode))return"SMART AUTO";if("auto".equals(mode))return"AUTO";if("multihop".equals(mode))return"multihop";if("external".equals(mode))return"external exit";if(mode.startsWith("custom:"))return"CUSTOM";return mode.toUpperCase();}
    private static String safe(Throwable error){String value=error==null?"":error.getMessage();return value==null||value.trim().isEmpty()?"Router VPN connection error":value.trim();}
    @Override public void close(){
        if(pendingSaved&&!activity.isFinishing()){releasePermission(pendingPermission,permissionAttachment,true);pendingPermission=null;}
        else if(pendingStartup!=null)pendingStartup.cancel();
        clearPending();
    }
}
