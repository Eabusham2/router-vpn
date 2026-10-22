package com.eabusham.routervpn;

import android.content.Context;
import org.json.JSONObject;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Real direct-node statistics and bounded, captured current Router telemetry. */
final class AndroidTelemetry {
    interface Callback<T> { void finished(T value, Throwable error); }
    static final class Result {
        final String id,name; final double minMs,medianMs,averageMs,trimmedMeanMs,p90Ms,maxMs; final int samples,failed;
        AndroidTelemetryNetwork route; AndroidNodeStore.Node node; String source;
        Result(String id,String name,double min,double median,double average,double p90,double max,int samples,int failed){this(id,name,min,median,average,Double.NaN,p90,max,samples,failed);}
        Result(String id,String name,double min,double median,double average,double trimmedMean,double p90,double max,int samples,int failed){this.id=id;this.name=name;this.minMs=min;this.medianMs=median;this.averageMs=average;this.trimmedMeanMs=trimmedMean;this.p90Ms=p90;this.maxMs=max;this.samples=samples;this.failed=failed;}
        void requireCurrent()throws Exception{if(route!=null)route.check();if(node!=null&&!source.equals(AndroidNodeStatistics.source(node)))throw new IllegalStateException("The measured node changed; retest before selecting it.");}
        String shortLabel(){return String.format(Locale.US,"%.1f ms",medianMs);}
        String detail(){return String.format(Locale.US,"%s — direct TCP median %.1f ms • min %.1f • avg %.1f%s • p90 %.1f • max %.1f • %d ok / %d failed",name,medianMs,minMs,averageMs,Double.isFinite(trimmedMeanMs)?String.format(Locale.US," • 10%% trimmed mean %.1f",trimmedMeanMs):"",p90Ms,maxMs,samples,failed);}
    }
    static final class PathResult {
        final double medianMs; final int samples,failed; final String proof; AndroidTelemetryCapture capture;
        PathResult(double median,int samples,int failed,String proof){this.medianMs=median;this.samples=samples;this.failed=failed;this.proof=proof;}
        void requireCurrent()throws Exception{if(capture==null)throw new IllegalStateException("Current RTT has no retained path capture.");capture.requireCurrent();}
    }
    static final class SpeedResult {
        final double downloadMbps,uploadMbps,downloadMs,uploadMs,serverReceiveMs; final int bytes; AndroidTelemetryCapture capture;
        SpeedResult(double down,double up,double downMs,double upMs,double serverMs,int bytes){this.downloadMbps=down;this.uploadMbps=up;this.downloadMs=downMs;this.uploadMs=upMs;this.serverReceiveMs=serverMs;this.bytes=bytes;}
        void requireCurrent()throws Exception{if(capture==null)throw new IllegalStateException("Current speed has no retained path capture.");capture.requireCurrent();}
        String detail(){return String.format(Locale.US,"Download %.1f Mbps • Upload %.1f Mbps\n%d MiB each way • %.0f ms down • %.0f ms up%s",downloadMbps,uploadMbps,bytes/(1<<20),downloadMs,uploadMs,serverReceiveMs>0?String.format(Locale.US," • server receive %.0f ms",serverReceiveMs):"");}
    }
    private static final String PREFS="router-vpn-telemetry-quick-v2";
    private static final int[] PORTS={443,8388,10443,11443,12443,13443,14443,15443,51820,51822};
    private static final int SPEED_DEFAULT_BYTES=8<<20,SPEED_MIN_BYTES=1<<20,SPEED_MAX_BYTES=16<<20;
    private static final AtomicBoolean PATH_RUNNING=new AtomicBoolean();
    private static volatile AndroidTelemetryIO processPathIO;
    private final Context context; private final AndroidNodeStore store;
    private volatile AndroidTelemetryIO pathIO; private volatile SpeedWork speedWork;
    private final List<AndroidTelemetryIO> nodeWork=new ArrayList<>();
    private volatile boolean closed;
    private static final class SpeedWork { volatile boolean cancelled; volatile AndroidTelemetryIO io; volatile Thread worker; void cancel(){cancelled=true;AndroidTelemetryIO owned=io;if(owned!=null)owned.cancel();Thread root=worker;if(root!=null)root.interrupt();} }

    AndroidTelemetry(Context context,AndroidNodeStore store){this.context=context.getApplicationContext();this.store=store;}
    double cachedMedian(String id){
        try{
            JSONObject value=new JSONObject(context.getSharedPreferences(PREFS,Context.MODE_PRIVATE).getString(id,"{}"));
            long age=System.currentTimeMillis()-value.optLong("at",0);if(age<0||age>120000)return 0;
            AndroidNodeStore.Node node=storedNode(id);if(node==null||!AndroidNodeStatistics.source(node).equals(value.optString("source")))return 0;
            double ms=value.optDouble("median",0);return Double.isFinite(ms)&&ms>0?ms:0;
        }catch(Exception ignored){return 0;}
    }
    private void cache(Result result)throws Exception{
        result.requireCurrent();JSONObject value=new JSONObject().put("median",result.medianMs).put("at",System.currentTimeMillis()).put("source",result.source);
        context.getSharedPreferences(PREFS,Context.MODE_PRIVATE).edit().putString(result.id,value.toString()).apply();
    }
    AndroidNodeStatistics.Record savedStatistics(AndroidNodeStore.Node node){return AndroidNodeStatistics.load(node);}
    void cancelCurrent(){AndroidTelemetryIO owned=pathIO;if(owned!=null)owned.cancel();SpeedWork speed=speedWork;if(speed!=null)speed.cancel();}
    void close(){closed=true;cancelCurrent();synchronized(nodeWork){for(AndroidTelemetryIO owned:nodeWork)owned.cancel();}}

    void measureNode(AndroidNodeStore.Node node,int samples,Callback<Result> callback){
        new Thread(()->{try{Result result=probeNode(node,clamp(samples,3,50));result.requireCurrent();
            if(samples==50){if(result.samples==50&&result.failed==0)AndroidNodeStatistics.save(node,new AndroidNodeStatistics.Record(node.id,result.source,node.endpoint,result.route.pathIdentity(),System.currentTimeMillis(),result.minMs,result.medianMs,result.averageMs,result.trimmedMeanMs,result.p90Ms,result.maxMs,result.samples,result.failed));}
            else cache(result);
            callback.finished(result,null);
        }catch(Throwable error){callback.finished(null,error);}},"routervpn-node-rtt").start();
    }
    void measureAll(int samples,Callback<List<Result>> callback){
        new Thread(()->{try{List<Result> out=new ArrayList<>();for(AndroidNodeStore.Node node:store.list()){
            if(closed)throw new IllegalStateException("The node chooser was closed.");
            try{Result result=probeNode(node,clamp(samples,3,10));cache(result);out.add(result);}catch(Exception failure){if(closed||AndroidVpnMutationGuard.isBusy(context))throw failure;}
        }
        if(out.isEmpty())throw new IllegalStateException("No Router node returned direct latency. Disconnect before testing; failed nodes remain unavailable.");
        for(Result result:out)result.requireCurrent();Collections.sort(out,Comparator.comparingDouble(result->result.medianMs));callback.finished(out,null);
        }catch(Throwable error){callback.finished(null,error);}},"routervpn-fastest-rtt").start();
    }
    // The shipping entry chooser uses AndroidViaEntryPathMeter's retained child
    // and complete drain. Keep the old source-compatible API fail-closed.
    void measureNodesViaCurrentPath(String entry,List<AndroidNodeStore.Node> nodes,int samples,Callback<List<Result>> callback){callback.finished(null,new IllegalStateException("Use the captured via-entry candidate operation; ambient Home state does not own a temporary tunnel."));}

    private Result probeNode(AndroidNodeStore.Node node,int samples)throws Exception{
        if(closed||node==null||node.endpoint==null||node.endpoint.trim().isEmpty())throw new IllegalArgumentException("A stored node with a public endpoint is required.");
        if(AndroidMTUMeasurementGate.held())throw new IllegalStateException("Finish the owned measurement before probing node latency.");
        String source=AndroidNodeStatistics.source(node);AndroidTelemetryNetwork route=AndroidTelemetryNetwork.direct(context);
        AndroidTelemetryIO io=new AndroidTelemetryIO(route.network.getSocketFactory(),()->{if(closed||AndroidMTUMeasurementGate.held())throw new IllegalStateException("Node latency yielded to an owned measurement.");route.check();},65000);
        synchronized(nodeWork){nodeWork.add(io);}io.attach();Result result=null;Throwable failure=null;
        try{
            String host=endpointHost(node.endpoint);InetAddress[] addresses=route.network.getAllByName(host);io.check();
            if(addresses==null||addresses.length==0||addresses.length>16)throw new IllegalStateException("The captured network returned no bounded node addresses.");
            InetSocketAddress target=null;
            outer:for(int port:PORTS)for(InetAddress address:addresses){io.check();Socket socket=io.open();try{socket.connect(new InetSocketAddress(address,port),450);target=new InetSocketAddress(address,port);break outer;}catch(Exception ignored){io.check();}finally{io.release(socket);}}
            if(target==null)throw new IllegalStateException("No live TCP probe port answered for the selected node.");
            List<Double> values=new ArrayList<>();int failed=0;
            for(int i=0;i<samples;i++){io.check();Socket socket=io.open();try{long start=System.nanoTime();socket.connect(target,900);double elapsed=(System.nanoTime()-start)/1000000d;io.check();values.add(elapsed);}catch(Exception error){io.check();failed++;}finally{io.release(socket);}if(i+1<samples)Thread.sleep(20);}
            if(values.isEmpty())throw new IllegalStateException("All direct node latency probes failed.");
            Collections.sort(values);result=new Result(node.id,node.name,round(values.get(0)),round(percentile(values,.5)),round(average(values)),round(trimmedMean(values)),round(percentile(values,.9)),round(values.get(values.size()-1)),values.size(),failed);
            result.route=route;result.node=node;result.source=source;result.requireCurrent();
        }catch(Throwable error){failure=error;}finally{io.drain();synchronized(nodeWork){nodeWork.remove(io);}}
        if(failure!=null)throw exception(failure);if(io.failure()!=null)throw exception(io.failure());result.requireCurrent();return result;
    }

    void currentPath(int samples,Callback<PathResult> callback){
        if(closed||AndroidMTUMeasurementGate.held()||!PATH_RUNNING.compareAndSet(false,true)){callback.finished(null,new IllegalStateException("Current RTT yields while another measurement is active."));return;}
        new Thread(()->{
            AndroidTelemetryIO io=null;PathResult result=null;Throwable failure=null;
            try{
                AndroidTelemetryCapture captured=AndroidTelemetryCapture.current(context,store);
                io=new AndroidTelemetryIO(captured.route.network.getSocketFactory(),()->{if(closed||AndroidMTUMeasurementGate.held())throw new IllegalStateException("Current RTT yielded to an owned measurement.");captured.check();},45000);
                pathIO=io;processPathIO=io;io.attach();AndroidTelemetryHttp http=new AndroidTelemetryHttp(io,captured.api,"",captured.proofId);
                List<Double> values=new ArrayList<>();int failed=0,count=clamp(samples,2,5);
                for(int i=0;i<count;i++){io.check();try{values.add(http.health());}catch(Exception error){io.check();failed++;}if(i+1<count)Thread.sleep(35);}
                if(values.isEmpty())throw new IllegalStateException("The exact Router node did not prove its private health endpoint on this captured VPN path.");
                Collections.sort(values);captured.requireCurrent();result=new PathResult(round(percentile(values,.5)),values.size(),failed,"Private HTTP health response time, including connection setup, through the captured native VPN network; exact Router node identity verified.");result.capture=captured;
            }catch(Throwable error){failure=error;}finally{if(io!=null){io.drain();if(failure==null)failure=io.failure();}pathIO=null;processPathIO=null;PATH_RUNNING.set(false);}
            try{if(failure==null)result.requireCurrent();}catch(Throwable stale){failure=stale;}
            callback.finished(failure==null?result:null,failure);
        },"routervpn-current-rtt").start();
    }
    synchronized void speedTest(int bytes,Callback<SpeedResult> callback){
        if(closed||speedWork!=null){callback.finished(null,new IllegalStateException("Finish or cancel the current private speed test first."));return;}
        final Object lease;try{lease=AndroidMTUMeasurementGate.acquire();}catch(Throwable busy){callback.finished(null,busy);return;}
        SpeedWork work=new SpeedWork();speedWork=work;
        new Thread(()->{
            work.worker=Thread.currentThread();SpeedResult result=null;Throwable failure=null;AndroidTelemetryIO io=null;
            try{
                AndroidTelemetryCapture captured=AndroidTelemetryCapture.current(context,store);
                AndroidTelemetryIO prior=processPathIO;if(prior!=null)prior.cancel();
                while(PATH_RUNNING.get())try{Thread.sleep(25);}catch(InterruptedException ignored){}
                CountDownLatch drained=new CountDownLatch(1);AtomicReference<Throwable> mtuFailure=new AtomicReference<>();
                LayeredVpnService.quiesceMTUForSpeedLab(error->{mtuFailure.set(error);drained.countDown();});
                boolean waiting=true;while(waiting)try{drained.await();waiting=false;}catch(InterruptedException ignored){}
                if(mtuFailure.get()!=null)throw exception(mtuFailure.get());
                if(work.cancelled||closed)throw new IllegalStateException("Private speed test cancelled after MTU work drained.");
                captured.requireCurrent();
                io=new AndroidTelemetryIO(captured.route.network.getSocketFactory(),()->{if(work.cancelled||closed||!AndroidMTUMeasurementGate.owns(lease))throw new IllegalStateException("Private speed test no longer owns the measurement lease.");captured.check();},90000);
                work.io=io;io.attach();captured.requireCurrent();
                result=new AndroidTelemetryHttp(io,captured.api,captured.token,captured.proofId,captured::requireCurrent).speed(Math.max(SPEED_MIN_BYTES,Math.min(SPEED_MAX_BYTES,bytes<=0?SPEED_DEFAULT_BYTES:bytes)));
                captured.requireCurrent();result.capture=captured;
            }catch(Throwable error){failure=error;}finally{
                if(io!=null){io.drain();if(failure==null)failure=io.failure();}
                // Only the real worker may release, after every socket and the
                // MTU quiesce callback have actually returned, including Cancel.
                AndroidMTUMeasurementGate.release(lease);synchronized(AndroidTelemetry.this){if(speedWork==work)speedWork=null;}
            }
            try{if(failure==null){if(work.cancelled||closed)throw new IllegalStateException("Private speed test cancelled.");result.requireCurrent();}}catch(Throwable stale){failure=stale;}
            callback.finished(failure==null?result:null,failure);
        },"routervpn-current-speed").start();
    }
    private static Exception exception(Throwable error){return error instanceof Exception?(Exception)error:new IllegalStateException("Captured telemetry failed.",error);}
    void speedTest(AndroidNodeStore.Node node,int bytes,Callback<SpeedResult> callback){
        try{
            if(node==null)throw new IllegalArgumentException("Choose a Router VPN hop first.");
            validateRoutedHopIdentity(node);
            AndroidHomeStateStore.Snapshot state=AndroidHomeStateStore.snapshot(context);
            AndroidNodeStore.Node entry=storedNode(state.activeEntryId),exit=storedNode(state.activeExitId);
            if(entry==null||exit==null||entry.id.equals(exit.id))throw new IllegalStateException("Active multihop entry/exit records are unavailable; refusing ambiguous hop speed.");
            int requested=bytes<=0?SPEED_DEFAULT_BYTES:Math.max(SPEED_MIN_BYTES,Math.min(SPEED_MAX_BYTES,bytes));
            new AndroidSpeedLabHopMeter(context).measure(entry,exit,requested,(hops,error)->{
                if(error!=null){callback.finished(null,error);return;}
                AndroidSpeedLabHopMeter.Hop match=null;
                if(hops!=null)for(AndroidSpeedLabHopMeter.Hop hop:hops)if(node.id.equals(hop.id)){match=hop;break;}
                if(match==null){callback.finished(null,new IllegalStateException("Exact multihop proof lanes returned no result for the requested hop."));return;}
                double downMs=transferDurationMs(match.bytes,match.downloadMbps),upMs=transferDurationMs(match.bytes,match.uploadMbps);
                callback.finished(new SpeedResult(match.downloadMbps,match.uploadMbps,downMs,upMs,0,match.bytes),null);
            });
        }catch(Throwable e){callback.finished(null,e);}
    }

    private AndroidNodeStore.Node storedNode(String id)throws Exception{if(id==null||id.isEmpty())return null;for(AndroidNodeStore.Node node:store.list())if(id.equals(node.id))return node;return null;}
    private void validateRoutedHopIdentity(AndroidNodeStore.Node node){AndroidHomeStateStore.Snapshot state=AndroidHomeStateStore.snapshot(context);if(!state.connected||!"connected".equals(state.phase)||!"passed".equals(state.pathProof)||!"multihop".equals(state.logicalMode))throw new IllegalStateException("Connect the actual proved Android multihop graph before testing routed hop speed.");requireMultihopEngineUp();if(state.activeEntryId==null||state.activeEntryId.isEmpty()||state.activeExitId==null||state.activeExitId.isEmpty())throw new IllegalStateException("Active multihop graph identity is unavailable; refusing to label a hop speed.");if(!node.id.equals(state.activeEntryId)&&!node.id.equals(state.activeExitId))throw new IllegalStateException("Requested hop is not part of the active Android multihop graph.");}
    private void requireMultihopEngineUp(){String state=context.getSharedPreferences(NativeSingBoxController.PREFS,Context.MODE_PRIVATE).getString(NativeSingBoxController.STATE_KEY,"DOWN");if(!"UP".equals(state))throw new IllegalStateException("Android multihop engine is not UP; refusing routed telemetry.");}
    private static double transferDurationMs(int bytes,double mbps){if(bytes<=0||mbps<=0)return 0;return round((bytes*8d/1_000_000d)/mbps*1000d);}
    private static String endpointHost(String value){String raw=value.trim();try{URI uri=raw.contains("://")?URI.create(raw):URI.create("tcp://"+raw);if(uri.getHost()!=null&&!uri.getHost().isEmpty())return uri.getHost();}catch(Exception ignored){}if(raw.startsWith("[")&&raw.contains("]"))return raw.substring(1,raw.indexOf(']'));int colon=raw.lastIndexOf(':');if(colon>0&&raw.indexOf(':')==colon)return raw.substring(0,colon);return raw;}
    private static int clamp(int v,int fallback,int max){if(v<=0)v=fallback;return Math.max(1,Math.min(max,v));}
    private static double average(List<Double>v){double s=0;for(double x:v)s+=x;return s/v.size();}
    static double trimmedMean(List<Double> sorted){int trim=sorted.size()/10;double sum=0;for(int i=trim;i<sorted.size()-trim;i++)sum+=sorted.get(i);return sum/(sorted.size()-2*trim);}
    private static double percentile(List<Double>v,double p){if(v.size()==1)return v.get(0);double index=p*(v.size()-1),floor=Math.floor(index),ceil=Math.ceil(index);if(floor==ceil)return v.get((int)floor);return v.get((int)floor)*(ceil-index)+v.get((int)ceil)*(index-floor);}
    private static double round(double v){return Math.round(v*1000d)/1000d;}
}
