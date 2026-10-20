package com.eabusham.routervpn;

import android.app.Activity;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/** Captured connect-test-restore transaction; every traffic owner drains before reuse. */
final class AndroidSpeedLabController {
    interface Callback { void progress(String message); void finished(AndroidSpeedLab.Result result, Throwable error); }

    static final class Request {
        String entryMode="wg", execution="local";
        String scope="current", topology="router", mode="smart-auto", exitMode="shadowsocks", durationMode="auto";
        AndroidNodeStore.Node node,entry,exit;
        AndroidStandardExitStore.Entry standardExit;
        List<String> customLayers=Collections.emptyList();
        double minSeconds=4,maxSeconds=12;
        boolean externalDirect=true;
    }

    private final Activity activity;
    private final AndroidUnifiedConnectionController connection;
    private final AndroidSpeedLab meter;
    private final AndroidNativeHopMeasurement nativeHopMeter=new AndroidNativeHopMeasurement();
    private volatile String nativeHopStatus="";
    private final AtomicBoolean running=new AtomicBoolean(false);
    private volatile List<AndroidSpeedLabHopMeter.Hop> lastHops=Collections.emptyList();
    private volatile String lastHopError="";
    private Object mtuLease;
    private volatile Callback activeCallback;
    private long generation;
    private String temporaryHome="",phase="idle";
    private boolean externalTemporary, completionStarted, originalSuspended;
    private volatile boolean cancelled, pathDecisionChanged;
    private AndroidUnifiedConnectionController.RestorePoint original;
    private AndroidHomeStateStore.Snapshot idle;
    private AndroidUnifiedConnectionController.Callback connectingCallback;
    private Request activeRequest;
    private Map<File,String> capturedFiles=Collections.emptyMap();

    private static Request capture(Request input)throws Exception{
        Request q=new Request();q.scope=normalize(input.scope,"current");q.topology=normalize(input.topology,"router");q.mode=normalize(input.mode,"smart-auto");q.entryMode=normalize(input.entryMode,"");q.exitMode=normalize(input.exitMode,"shadowsocks");q.execution=normalize(input.execution,"local");q.externalDirect=input.externalDirect;
        if(!java.util.Arrays.asList("current","temporary").contains(q.scope))throw new IllegalArgumentException("Choose Current path or Temporary config.");
        if("temporary".equals(q.scope)&&!java.util.Arrays.asList("router","multihop","external","system-direct").contains(q.topology))throw new IllegalArgumentException("Choose a supported temporary topology.");
        if("multihop".equals(q.topology)&&!java.util.Arrays.asList("local","server","auto").contains(q.execution))throw new IllegalArgumentException("Choose an exact multihop execution.");
        q.node=input.node;q.entry=input.entry;q.exit=input.exit;q.standardExit=input.standardExit==null?null:AndroidStandardExitStore.copy(input.standardExit);
        q.customLayers=input.customLayers==null?Collections.emptyList():Collections.unmodifiableList(new ArrayList<>(input.customLayers));
        AndroidSpeedLab.DurationPolicy time=AndroidSpeedLab.DurationPolicy.normalize(input.durationMode,input.minSeconds,input.maxSeconds);q.durationMode=time.mode;q.minSeconds=time.minSeconds;q.maxSeconds=time.maxSeconds;
        if("temporary".equals(q.scope)&&("multihop".equals(q.topology)||"external".equals(q.topology)&&!q.externalDirect)&&!NativeSingBoxController.nativeMultihopEntry(q.entryMode))throw new IllegalArgumentException("Choose the exact saved native entry mode.");
        return q;
    }
    private static String digest(File file)throws Exception{return AndroidTorProfile.digest(AndroidPrivateFileStore.read(file,AndroidNodeStore.MAX_BUNDLE));}
    private static void captureNode(Map<File,String> values,AndroidNodeStore.Node node)throws Exception{if(node==null||node.file==null)throw new IllegalArgumentException("Choose a valid saved Router VPN node.");values.put(node.file,digest(node.file));}
    private synchronized boolean current(long owner){return running.get()&&generation==owner;}


    AndroidSpeedLabController(Activity activity,AndroidUnifiedConnectionController connection){this.activity=activity;this.connection=connection;this.meter=new AndroidSpeedLab(activity);}
    boolean isRunning(){return running.get();}
    List<AndroidSpeedLabHopMeter.Hop> hops(){return new ArrayList<>(lastHops);}
    String hopError(){return lastHopError;}
    String nativeHops(){return nativeHopStatus;}

    void run(Request request,Callback callback){
        if(request==null){callback.finished(null,new IllegalArgumentException("Speed Lab request is required."));return;}
        final long owner;final Request captured;final Map<File,String> sources=new LinkedHashMap<>();final Object lease;
        synchronized(this){
            if(!running.compareAndSet(false,true)){callback.finished(null,new IllegalStateException("Another Speed Lab test is already running."));return;}
            owner=++generation;temporaryHome="";externalTemporary=false;completionStarted=false;originalSuspended=false;cancelled=false;pathDecisionChanged=false;original=null;idle=null;connectingCallback=null;phase="quiescing";
            try{
                captured=capture(request);
                if("temporary".equals(captured.scope)){
                    if("router".equals(captured.topology))captureNode(sources,captured.node);
                    if("multihop".equals(captured.topology)){captureNode(sources,captured.entry);captureNode(sources,captured.exit);if(captured.entry.id.equals(captured.exit.id))throw new IllegalArgumentException("Choose different entry and exit nodes.");}
                    if("external".equals(captured.topology)){
                        if(captured.standardExit==null)throw new IllegalArgumentException("Choose a stored custom exit.");
                        AndroidStandardExitStore.validate(captured.standardExit);
                        if(!captured.externalDirect)captureNode(sources,captured.entry);
                    }
                }
                if("temporary".equals(captured.scope))original=connection.captureRestorePoint();
                activeRequest=captured;capturedFiles=Collections.unmodifiableMap(new LinkedHashMap<>(sources));
                lease=AndroidMTUMeasurementGate.acquire();mtuLease=lease;
            }catch(Throwable error){running.set(false);callback.finished(null,error);return;}
        }
        Callback ownedCallback=new Callback(){
            public void progress(String message){if(current(owner))callback.progress(message);}
            public void finished(AndroidSpeedLab.Result result,Throwable error){if(generation==owner)callback.finished(result,error);}
        };
        activeCallback=ownedCallback;final AtomicBoolean quiesced=new AtomicBoolean();
        LayeredVpnService.quiesceMTUForSpeedLab(error->activity.runOnUiThread(()->{
            if(!current(owner)||mtuLease!=lease||!quiesced.compareAndSet(false,true))return;
            if(error!=null){finish(ownedCallback,null,error);return;}
            try{for(Map.Entry<File,String> source:sources.entrySet())if(!source.getValue().equals(digest(source.getKey())))throw new IllegalStateException("The captured Speed Lab node changed while MTU work was draining.");}
            catch(Throwable changed){finish(ownedCallback,null,changed);return;}
            runOwned(captured,ownedCallback,owner);
        }));
    }

    private void runOwned(Request request,Callback callback,long owner){
        lastHops=Collections.emptyList();lastHopError="";nativeHopStatus="";
        if(cancelled){complete(callback,null,cancelled());return;}
        if("current".equals(request.scope)){callback.progress("Testing the actual current Android path…");measure(request,callback);return;}
        if(!"temporary".equals(request.scope)){complete(callback,null,new IllegalArgumentException("Speed Lab scope must be current or temporary."));return;}
        try{
            if(!connection.restorePointCurrent(original))throw new IllegalStateException("The original connection changed before the temporary test could start.");
            if(!original.connected()){idle=connection.captureIdle();startTemporary(request,callback,owner);return;}
            phase="suspending";callback.progress("Saving the exact running connection and draining its native path…");
            stopAndDrain(original.home.sessionId,original.topology,owner,new AndroidUnifiedConnectionController.Callback(){
                public void progress(String message){callback.progress(message);}
                public void finished(boolean ok,String message){
                    if(!current(owner))return;
                    if(!ok||pathDecisionChanged){finish(callback,null,new IllegalStateException(message));return;}
                    originalSuspended=true;
                    try{idle=connection.captureIdle();}catch(Exception changed){finish(callback,null,changed);return;}
                    if(cancelled){complete(callback,null,cancelled());return;}
                    startTemporary(request,callback,owner);
                }
            });
        }catch(Throwable error){complete(callback,null,error);}
    }

    private void startTemporary(Request request,Callback callback,long owner){
        try{
            if(!connection.idleCurrent(idle))throw new IllegalStateException("A newer connection decision cancelled this temporary test.");
            for(Map.Entry<File,String> source:capturedFiles.entrySet())if(!source.getValue().equals(digest(source.getKey())))throw new IllegalStateException("A captured test node changed before startup.");
            if(cancelled){complete(callback,null,cancelled());return;}
            if("system-direct".equals(request.topology)){callback.progress("Testing raw Android system Internet; the captured original path will be restored…");measure(request,callback);return;}
            phase="connecting";externalTemporary="external".equals(request.topology);
            final AtomicBoolean connectedCallback=new AtomicBoolean();
            AndroidUnifiedConnectionController.Callback bridge=new AndroidUnifiedConnectionController.Callback(){
                public void validate()throws Exception{
                    if(!current(owner)||cancelled||completionStarted||!connection.idleCurrent(idle))throw new IllegalStateException("The captured temporary permission request was cancelled or replaced.");
                    for(Map.Entry<File,String> source:capturedFiles.entrySet())if(!source.getValue().equals(digest(source.getKey())))throw new IllegalStateException("The captured test node changed while Android permission was pending.");
                }
                public void owned(String homeSession){
                    if(!current(owner)||completionStarted)return;
                    if(homeSession==null||homeSession.isEmpty()||(!temporaryHome.isEmpty()&&!temporaryHome.equals(homeSession))){complete(callback,null,new IllegalStateException("Temporary path ownership changed."));return;}
                    temporaryHome=homeSession;
                    if(cancelled)complete(callback,null,cancelled());
                }
                public void progress(String message){if(current(owner)&&!completionStarted)callback.progress(message);}
                public void finished(boolean ok,String message){
                    if(!current(owner)||completionStarted||!connectedCallback.compareAndSet(false,true))return;
                    connectingCallback=null;
                    if(cancelled){complete(callback,null,cancelled());return;}
                    if(!ok){complete(callback,null,new IllegalStateException(message));return;}
                    if(!temporaryCurrent(request)){complete(callback,null,new IllegalStateException("The temporary path changed before measurement."));return;}
                    callback.progress("Temporary path is proven. Running Speed Lab without changing saved profiles…");measure(request,callback);
                }
            };
            connectingCallback=bridge;
            switch(request.topology){
                case "router":String mode=request.mode;if("custom".equals(mode))mode="custom:speed-lab";connection.connectNode(request.node,mode,request.customLayers,bridge);break;
                case "multihop":connection.connectMultihop(request.entry,request.exit,request.exitMode,request.execution,request.entryMode,bridge);break;
                case "external":connection.connectExternal(request.entry,request.standardExit,request.externalDirect,request.entryMode,bridge);break;
                default:throw new IllegalArgumentException("Unsupported Android Speed Lab topology: "+request.topology);
            }
        }catch(Throwable error){complete(callback,null,error);}
    }

    void cancel(){
        final Callback callback;final long owner;
        synchronized(this){if(!running.get())return;cancelled=true;callback=activeCallback;owner=generation;}
        if(callback==null)return;
        callback.progress("Cancelling test traffic; keeping connection ownership until cleanup and restoration finish…");
        activity.runOnUiThread(()->{
            if(!current(owner))return;
            String stage=phase;
            if("measuring".equals(stage)){meter.cancel();return;}
            if("hops".equals(stage)){nativeHopMeter.cancel();return;}
            if("connecting".equals(stage)){
                if(connection.cancelPending(connectingCallback))return;
                if(!temporaryHome.isEmpty())complete(callback,null,cancelled());
            }
            // Quiescence, native stop and restoration each own their completion.
            // Their callback observes cancelled and retains the MTU lease until joined.
        });
    }
    private static Throwable cancelled(){return new java.util.concurrent.CancellationException("Speed Lab was cancelled; any captured original connection is restored only while its owner remains current.");}

    private void measure(Request request,Callback callback){
        final long owner=generation;phase="measuring";
        if(cancelled){complete(callback,null,cancelled());return;}
        meter.run(request.durationMode,request.minSeconds,request.maxSeconds,(result,error)->activity.runOnUiThread(()->{
            if(!current(owner)||completionStarted)return;
            if(cancelled){complete(callback,null,cancelled());return;}
            if(error!=null){complete(callback,null,error);return;}
            if("temporary".equals(request.scope)&&!temporaryCurrent(request)){complete(callback,null,new IllegalStateException("The temporary path changed during measurement."));return;}
            AndroidHomeStateStore.Snapshot runtime=AndroidHomeStateStore.snapshot(activity);
            if(!runtime.connected||!("external".equals(runtime.logicalMode)||"multihop".equals(runtime.logicalMode))){complete(callback,result,null);return;}
            phase="hops";callback.progress("Measuring the captured native entry and exit paths…");
            nativeHopMeter.run(mtuLease,new AndroidNativeHopMeasurement.Callback(){
                public void progress(String status){if(current(owner))callback.progress("Measuring captured native paths; MTU remains held until cleanup drains…");}
                public void finished(String status,Throwable hopError){activity.runOnUiThread(()->{
                    if(!current(owner)||completionStarted)return;
                    if(cancelled){complete(callback,null,cancelled());return;}
                    if(hopError!=null){complete(callback,null,hopError);return;}
                    if("temporary".equals(request.scope)&&!temporaryCurrent(request)){complete(callback,null,new IllegalStateException("The temporary path changed during native measurement."));return;}
                    try{nativeHopStatus=AndroidHopMeasurementDialog.renderStatus(status);}catch(Exception invalid){complete(callback,null,invalid);return;}
                    complete(callback,result,null);
                });}
            });
        }));
    }

    private void complete(Callback callback,AndroidSpeedLab.Result result,Throwable error){
        final long owner;
        synchronized(this){if(callback!=activeCallback||completionStarted||!running.get())return;completionStarted=true;owner=generation;}
        if(!"temporary".equals(activeRequest.scope)){finish(callback,result,error);return;}
        phase="cleanup";
        if(temporaryHome.isEmpty()){restoreOriginal(callback,owner,result,error);return;}
        callback.progress("Test traffic has drained. Stopping the captured temporary native path…");
        stopAndDrain(temporaryHome,activeRequest.topology,owner,new AndroidUnifiedConnectionController.Callback(){
            public void progress(String message){callback.progress(message);}
            public void finished(boolean ok,String message){
                if(!current(owner))return;
                if(!ok){finish(callback,null,withCause("A newer path decision cancelled restoration, or cleanup could not retire the captured owner: "+message,error));return;}
                try{idle=connection.captureIdle();}catch(Throwable changed){finish(callback,null,withCause("The idle restoration owner changed.",changed));return;}
                restoreOriginal(callback,owner,result,error);
            }
        });
    }

    private void stopAndDrain(String home,String topology,long owner,AndroidUnifiedConnectionController.Callback callback){
        connection.stopCaptured(home,topology,new AndroidUnifiedConnectionController.Callback(){
            public void progress(String message){if(current(owner))callback.progress(message);}
            public void superseded(){pathDecisionChanged=true;}
            public void finished(boolean ok,String message){
                if(!current(owner))return;
                if(!ok&&home.equals(AndroidHomeStateStore.snapshot(activity).sessionId)){
                    callback.progress("The captured native owner is still draining; its MTU hold is retained…");
                    new Thread(()->{try{Thread.sleep(250L);}catch(InterruptedException ignored){}activity.runOnUiThread(()->{if(current(owner))stopAndDrain(home,topology,owner,callback);});},"routervpn-speedlab-cleanup-retry").start();
                    return;
                }
                callback.finished(ok,message);
            }
        });
    }

    private void restoreOriginal(Callback callback,long owner,AndroidSpeedLab.Result result,Throwable error){
        if(pathDecisionChanged||!connection.idleCurrent(idle)){finish(callback,null,withCause("A newer connection or Disconnect cancelled automatic restoration.",error));return;}
        if(!originalSuspended||original==null||!original.connected()){finish(callback,result,error);return;}
        phase="restoring";callback.progress("Restoring the exact original connection and obtaining fresh path proof…");
        final String[] restoredOwner={""};
        connection.restoreCaptured(original,idle,new AndroidUnifiedConnectionController.Callback(){
            public void owned(String session){if(current(owner)&&restoredOwner[0].isEmpty())restoredOwner[0]=session;}
            public void progress(String message){if(current(owner))callback.progress(message);}
            public void finished(boolean ok,String message){
                if(!current(owner))return;
                if(!ok||!connection.restoredCurrent(original,restoredOwner[0])){finish(callback,null,withCause("The original captured connection could not be restored or its fresh proof was superseded: "+message,error));return;}
                callback.progress("Original connection restored and proved. All temporary test owners have drained.");
                finish(callback,cancelled?null:result,cancelled?cancelled():error);
            }
        });
    }
    private static Throwable withCause(String message,Throwable cause){IllegalStateException failure=new IllegalStateException(message);if(cause!=null)failure.addSuppressed(cause);return failure;}

    private boolean temporaryCurrent(Request q){
        if("system-direct".equals(q.topology))return connection.idleCurrent(idle);
        AndroidHomeStateStore.Snapshot state=AndroidHomeStateStore.snapshot(activity);
        if(temporaryHome.isEmpty()||!temporaryHome.equals(state.sessionId)||!state.connected||!"connected".equals(state.phase)||!"passed".equals(state.pathProof))return false;
        if("router".equals(q.topology))return q.node.id.equals(state.activeNodeId)&&!"multihop".equals(state.logicalMode)&&!"external".equals(state.logicalMode);
        if("multihop".equals(q.topology))return "multihop".equals(state.logicalMode)&&q.entry.id.equals(state.activeEntryId)&&q.exit.id.equals(state.activeExitId)&&q.exitMode.equals(state.runtimeMode)&&q.entryMode.equals(state.activeEntryMode);
        return "external".equals(state.logicalMode)&&q.standardExit.id.equals(state.activeExternalId)&&q.standardExit.protocol.equals(state.activeExternalProtocol)
                &&(q.externalDirect?state.activeEntryId.isEmpty():q.entry.id.equals(state.activeEntryId)&&q.entryMode.equals(state.activeEntryMode));
    }

    private static AndroidNodeStore.Node find(List<AndroidNodeStore.Node>nodes,String id){if(nodes==null||id==null)return null;for(AndroidNodeStore.Node node:nodes)if(node!=null&&id.equals(node.id))return node;return null;}
    private void finish(Callback callback,AndroidSpeedLab.Result result,Throwable error){
        final Object lease;
        synchronized(this){if(callback!=activeCallback||!running.get())return;lease=mtuLease;mtuLease=null;activeCallback=null;running.set(false);}
        phase="idle";AndroidMTUMeasurementGate.release(lease);
        try{LayeredVpnService.startAutomaticMTU();}catch(RuntimeException unavailable){if(error==null)error=unavailable;else error.addSuppressed(unavailable);}
        callback.finished(cancelled?null:result,cancelled&&error==null?cancelled():error);
    }
    private static String normalize(String value,String fallback){String out=value==null?"":value.trim().toLowerCase(Locale.US);return out.isEmpty()?fallback:out;}
}
