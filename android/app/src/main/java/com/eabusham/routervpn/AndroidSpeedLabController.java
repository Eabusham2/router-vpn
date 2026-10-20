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

/** Connect-test-disconnect transaction for the native Android Speed Lab. */
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
    private final AndroidSpeedLabHopMeter hopMeter;
    private final AtomicBoolean running=new AtomicBoolean(false);
    private volatile List<AndroidSpeedLabHopMeter.Hop> lastHops=Collections.emptyList();
    private volatile String lastHopError="";
    private Object mtuLease;
    private volatile Callback activeCallback;
    private long generation;
    private String externalHome="";
    private boolean externalTemporary, completionStarted;

    private static Request capture(Request input)throws Exception{
        Request q=new Request();q.scope=normalize(input.scope,"current");q.topology=normalize(input.topology,"router");q.mode=normalize(input.mode,"smart-auto");q.entryMode=normalize(input.entryMode,"");q.exitMode=normalize(input.exitMode,"shadowsocks");q.execution=normalize(input.execution,"local");q.externalDirect=input.externalDirect;
        q.node=input.node;q.entry=input.entry;q.exit=input.exit;q.standardExit=input.standardExit==null?null:AndroidStandardExitStore.copy(input.standardExit);
        q.customLayers=input.customLayers==null?Collections.emptyList():Collections.unmodifiableList(new ArrayList<>(input.customLayers));
        AndroidSpeedLab.DurationPolicy time=AndroidSpeedLab.DurationPolicy.normalize(input.durationMode,input.minSeconds,input.maxSeconds);q.durationMode=time.mode;q.minSeconds=time.minSeconds;q.maxSeconds=time.maxSeconds;
        if("temporary".equals(q.scope)&&("multihop".equals(q.topology)||"external".equals(q.topology)&&!q.externalDirect)&&!NativeSingBoxController.nativeMultihopEntry(q.entryMode))throw new IllegalArgumentException("Choose the exact saved native entry mode.");
        return q;
    }
    private static String digest(File file)throws Exception{return AndroidTorProfile.digest(AndroidPrivateFileStore.read(file,AndroidNodeStore.MAX_BUNDLE));}
    private static void captureNode(Map<File,String> values,AndroidNodeStore.Node node)throws Exception{if(node==null||node.file==null)throw new IllegalArgumentException("Choose a valid saved Router VPN node.");values.put(node.file,digest(node.file));}
    private synchronized boolean current(long owner){return running.get()&&generation==owner;}


    AndroidSpeedLabController(Activity activity,AndroidUnifiedConnectionController connection){this.activity=activity;this.connection=connection;this.meter=new AndroidSpeedLab(activity);this.hopMeter=new AndroidSpeedLabHopMeter(activity);}
    boolean isRunning(){return running.get();}
    List<AndroidSpeedLabHopMeter.Hop> hops(){return new ArrayList<>(lastHops);}
    String hopError(){return lastHopError;}

    void run(Request request,Callback callback){
        if(request==null){callback.finished(null,new IllegalArgumentException("Speed Lab request is required."));return;}
        final long owner;final Request captured;final Map<File,String> sources=new LinkedHashMap<>();final Object lease;
        synchronized(this){
            if(!running.compareAndSet(false,true)){callback.finished(null,new IllegalStateException("Another Speed Lab test is already running."));return;}
            owner=++generation;externalHome="";externalTemporary=false;completionStarted=false;
            try{
                captured=capture(request);
                if("temporary".equals(captured.scope)){
                    if("router".equals(captured.topology))captureNode(sources,captured.node);
                    if("multihop".equals(captured.topology)){captureNode(sources,captured.entry);captureNode(sources,captured.exit);}
                    if("external".equals(captured.topology)){
                        if(captured.standardExit==null)throw new IllegalArgumentException("Choose a stored custom exit.");
                        AndroidStandardExitStore.validate(captured.standardExit);
                        if(!captured.externalDirect)captureNode(sources,captured.entry);
                    }
                }
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
        lastHops=Collections.emptyList();lastHopError="";
        boolean temporaryRuntimeRequested=false;
        try{
            String scope=normalize(request.scope,"current");
            if("current".equals(scope)){callback.progress("Testing the actual current Android path…");measure(request,callback,false);return;}
            if(!"temporary".equals(scope)){finish(callback,null,new IllegalArgumentException("Speed Lab scope must be current or temporary."));return;}
            if(connection.isActiveOrTransitioning()){finish(callback,null,new IllegalStateException("Disconnect Router VPN before a temporary Android Speed Lab configuration."));return;}
            String topology=normalize(request.topology,"router");
            if("system-direct".equals(topology)){callback.progress("Testing raw Android system Internet with Router VPN disconnected…");measure(request,callback,false);return;}
            temporaryRuntimeRequested=true;externalTemporary="external".equals(topology);
            final AtomicBoolean connectedCallback=new AtomicBoolean();
            AndroidUnifiedConnectionController.Callback bridge=new AndroidUnifiedConnectionController.Callback(){
                @Override public void owned(String homeSession){if(current(owner)&&!completionStarted){if(externalHome.isEmpty())externalHome=homeSession;else if(!externalHome.equals(homeSession))complete(callback,true,null,new IllegalStateException("Temporary external ownership changed."));}}
                @Override public void progress(String message){if(current(owner))callback.progress(message);}
                @Override public void finished(boolean ok,String message){
                    if(!current(owner)||completionStarted||!connectedCallback.compareAndSet(false,true))return;
                    if(!ok){complete(callback,true,null,new IllegalStateException(message));return;}
                    if(externalTemporary&&!externalCurrent(request)){complete(callback,true,null,new IllegalStateException("The temporary external path changed before measurement."));return;}
                    callback.progress("Temporary path is proven. Running Speed Lab without saving this graph…");
                    measure(request,callback,true);
                }
            };
            switch(topology){
                case "router":
                    if(request.node==null){finish(callback,null,new IllegalArgumentException("Choose a Router VPN node."));return;}
                    String mode=normalize(request.mode,"smart-auto");List<String>layers=request.customLayers==null?Collections.emptyList():new ArrayList<>(request.customLayers);if("custom".equals(mode))mode="custom:speed-lab";
                    connection.connectNode(request.node,mode,layers,bridge);break;
                case "multihop":
                    if(request.entry==null||request.exit==null||request.entry.id.equals(request.exit.id)){finish(callback,null,new IllegalArgumentException("Choose different Router VPN entry and exit nodes."));return;}
                    connection.connectMultihop(request.entry,request.exit,normalize(request.exitMode,"shadowsocks"),normalize(request.execution,"local"),normalize(request.entryMode,"wg"),bridge);break;
                case "external":
                    if(request.standardExit==null){finish(callback,null,new IllegalArgumentException("Choose a stored custom exit."));return;}
                    connection.connectExternal(request.entry,request.standardExit,request.externalDirect,request.entryMode,bridge);break;
                default: temporaryRuntimeRequested=false;finish(callback,null,new IllegalArgumentException("Unsupported Android Speed Lab topology: "+topology));
            }
        }catch(Throwable error){if(temporaryRuntimeRequested)complete(callback,true,null,error);else finish(callback,null,error);}
    }

    private void measure(Request request,Callback callback,boolean cleanup){
        final long owner=generation;
        meter.run(request.durationMode,request.minSeconds,request.maxSeconds,(result,error)->activity.runOnUiThread(()->{
            if(!current(owner)||completionStarted)return;
            if(error!=null){complete(callback,cleanup,result,error);return;}
            if(externalTemporary&&!externalCurrent(request)){complete(callback,cleanup,null,new IllegalStateException("The temporary external path changed during measurement."));return;}
            AndroidHomeStateStore.Snapshot runtime=AndroidHomeStateStore.snapshot(activity);
            if(!runtime.connected||!"multihop".equals(runtime.logicalMode)){complete(callback,cleanup,result,null);return;}
            try{
                AndroidNodeStore store=new AndroidNodeStore(activity);AndroidNodeStore.Node entry=find(store.list(),runtime.activeEntryId),exit=find(store.list(),runtime.activeExitId);
                if(entry==null||exit==null)throw new IllegalStateException("Active Android multihop nodes disappeared before Speed Lab hop measurement.");
                callback.progress("End-to-end test complete. Measuring entry and exit hops on the same graph…");
                hopMeter.measure(entry,exit,(hops,hopError)->activity.runOnUiThread(()->{
                    if(!current(owner)||completionStarted)return;
                    if(hopError==null&&hops!=null){lastHops=Collections.unmodifiableList(new ArrayList<>(hops));lastHopError="";}else{lastHops=Collections.emptyList();lastHopError=hopError==null?"Per-hop Speed Lab metrics were unavailable.":hopError.getMessage();}
                    complete(callback,cleanup,result,null);
                }));
            }catch(Throwable hopSetupError){lastHopError=hopSetupError.getMessage();complete(callback,cleanup,result,null);}
        }));
    }

    private void complete(Callback callback,boolean cleanup,AndroidSpeedLab.Result result,Throwable error){
        final long owner;
        synchronized(this){if(callback!=activeCallback||completionStarted||!running.get())return;completionStarted=true;owner=generation;}
        if(!cleanup){finish(callback,result,error);return;}
        callback.progress(error==null?"Measurement complete. Tearing down temporary path…":"Temporary setup/measurement failed. Restoring the disconnected state…");
        AndroidUnifiedConnectionController.Callback completed=new AndroidUnifiedConnectionController.Callback(){
            @Override public void progress(String message){callback.progress(message);}
            @Override public void finished(boolean ok,String message){
                if(!current(owner))return;
                Throwable finalError=error;
                if(!ok){IllegalStateException cleanupError=new IllegalStateException("Temporary Android path cleanup failed: "+message);if(finalError!=null)cleanupError.addSuppressed(finalError);finalError=cleanupError;}
                finish(callback,result,finalError);
            }
        };
        if(externalTemporary)connection.disconnectExternal(externalHome,completed);else connection.disconnect(completed);
    }

    private boolean externalCurrent(Request q){
        AndroidHomeStateStore.Snapshot state=AndroidHomeStateStore.snapshot(activity);
        return !externalHome.isEmpty()&&externalHome.equals(state.sessionId)&&state.connected&&"connected".equals(state.phase)&&"passed".equals(state.pathProof)
                &&"external".equals(state.logicalMode)&&q.standardExit.id.equals(state.activeExternalId)&&q.standardExit.protocol.equals(state.activeExternalProtocol)
                &&(q.externalDirect?state.activeEntryId.isEmpty():q.entry.id.equals(state.activeEntryId)&&q.entryMode.equals(state.activeEntryMode));
    }

    private static AndroidNodeStore.Node find(List<AndroidNodeStore.Node>nodes,String id){if(nodes==null||id==null)return null;for(AndroidNodeStore.Node node:nodes)if(node!=null&&id.equals(node.id))return node;return null;}
    private void finish(Callback callback,AndroidSpeedLab.Result result,Throwable error){
        final Object lease;
        synchronized(this){if(callback!=activeCallback||!running.get())return;lease=mtuLease;mtuLease=null;activeCallback=null;running.set(false);}
        AndroidMTUMeasurementGate.release(lease);callback.finished(result,error);
    }
    private static String normalize(String value,String fallback){String out=value==null?"":value.trim().toLowerCase(Locale.US);return out.isEmpty()?fallback:out;}
}
