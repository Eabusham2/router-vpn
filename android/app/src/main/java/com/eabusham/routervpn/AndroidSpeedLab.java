package com.eabusham.routervpn;

import android.content.Context;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Native Android Speed Lab. Throughput and loaded latency are measured independently. */
final class AndroidSpeedLab {
    interface Callback { void finished(Result value, Throwable error); }

    private static final class StalePathException extends IllegalStateException {
        StalePathException(String message){super(message);}
    }

    private static final class ParallelRound {
        final long bytes,nanos;
        ParallelRound(long bytes,long nanos){this.bytes=bytes;this.nanos=nanos;}
    }

    static final class DurationPolicy {
        final String mode; final double minSeconds,maxSeconds;
        DurationPolicy(String mode,double minSeconds,double maxSeconds){this.mode=mode;this.minSeconds=minSeconds;this.maxSeconds=maxSeconds;}
        static DurationPolicy normalize(String mode,double min,double max){
            String value=mode==null?"auto":mode.trim().toLowerCase(Locale.US);
            if(value.isEmpty()||"default".equals(value)||"auto".equals(value))return new DurationPolicy("auto",4,12);
            if(!"custom".equals(value))throw new IllegalArgumentException("Speed Lab timing must be Auto or Custom.");
            if(Double.isNaN(min)||Double.isNaN(max)||Double.isInfinite(min)||Double.isInfinite(max)||min<1||max>60||max<min)throw new IllegalArgumentException("Custom Speed Lab time must satisfy 1s <= min <= max <= 60s.");
            return new DurationPolicy("custom",round(min),round(max));
        }
    }

    static final class Latency {
        final int samples,failed; final double minMs,medianMs,averageMs,p90Ms,maxMs,jitterMs;
        Latency(int samples,int failed,double min,double median,double average,double p90,double max,double jitter){this.samples=samples;this.failed=failed;this.minMs=min;this.medianMs=median;this.averageMs=average;this.p90Ms=p90;this.maxMs=max;this.jitterMs=jitter;}
        String detail(){return String.format(Locale.US,"median %.1f ms • p90 %.1f • max %.1f • jitter %.1f",medianMs,p90Ms,maxMs,jitterMs);}
    }

    static final class Direction {
        final String direction; final double mbps,seconds,bufferbloatMs; final long bytes; final int rounds; final Latency loadedLatency; final boolean stoppedStable;
        Direction(String direction,double mbps,long bytes,double seconds,int rounds,Latency loaded,double bloat,boolean stable){this.direction=direction;this.mbps=mbps;this.bytes=bytes;this.seconds=seconds;this.rounds=rounds;this.loadedLatency=loaded;this.bufferbloatMs=bloat;this.stoppedStable=stable;}
    }

    static final class Result {
        final DurationPolicy timing; final Latency idle; final Direction download,upload; final long startedAt,finishedAt; final String pathIdentity;
        Result(DurationPolicy timing,Latency idle,Direction download,Direction upload,long started,long finished,String pathIdentity){this.timing=timing;this.idle=idle;this.download=download;this.upload=upload;this.startedAt=started;this.finishedAt=finished;this.pathIdentity=pathIdentity;}
        String summary(){return String.format(Locale.US,"↓ %.1f Mbps • ↑ %.1f Mbps\nIdle %.1f ms • ↓ loaded %.1f ms (+%.1f) • ↑ loaded %.1f ms (+%.1f)",download.mbps,upload.mbps,idle.medianMs,download.loadedLatency.medianMs,download.bufferbloatMs,upload.loadedLatency.medianMs,upload.bufferbloatMs);}
        JSONObject json()throws Exception{
            JSONObject root=new JSONObject();root.put("provider","Cloudflare Speed Test edge (built-in Router VPN Speed Lab)");root.put("path_identity",pathIdentity);root.put("started_at",startedAt);root.put("finished_at",finishedAt);root.put("timing",new JSONObject().put("mode",timing.mode).put("min_seconds",timing.minSeconds).put("max_seconds",timing.maxSeconds));root.put("idle_latency",latencyJson(idle));root.put("download",directionJson(download));root.put("upload",directionJson(upload));return root;
        }
        private static JSONObject latencyJson(Latency v)throws Exception{return new JSONObject().put("samples",v.samples).put("failed",v.failed).put("min_ms",v.minMs).put("median_ms",v.medianMs).put("average_ms",v.averageMs).put("p90_ms",v.p90Ms).put("max_ms",v.maxMs).put("jitter_ms",v.jitterMs);}
        private static JSONObject directionJson(Direction v)throws Exception{return new JSONObject().put("direction",v.direction).put("mbps",v.mbps).put("bytes",v.bytes).put("seconds",v.seconds).put("rounds",v.rounds).put("loaded_latency",latencyJson(v.loadedLatency)).put("bufferbloat_ms",v.bufferbloatMs).put("stopped_stable",v.stoppedStable);}
    }

    private static final String DOWN="https://speed.cloudflare.com/__down";
    private static final String UP="https://speed.cloudflare.com/__up";
    private static final ThreadLocal<SecureRandom> RANDOM=ThreadLocal.withInitial(SecureRandom::new);
    private final Context context;

    AndroidSpeedLab(Context context){this.context=context.getApplicationContext();}

    void run(String durationMode,double minSeconds,double maxSeconds,Callback callback){
        final DurationPolicy policy;
        try{policy=DurationPolicy.normalize(durationMode,minSeconds,maxSeconds);}catch(Throwable error){callback.finished(null,error);return;}
        new Thread(()->{try{AndroidHomeStateStore.Snapshot before=AndroidHomeStateStore.snapshot(context);requireFresh(before);String identity=identity(before);long started=System.currentTimeMillis();Latency idle=idleLatency(before);requireFresh(before);Direction down=direction("download",policy,idle.medianMs,before);requireFresh(before);Direction up=direction("upload",policy,idle.medianMs,before);requireFresh(before);callback.finished(new Result(policy,idle,down,up,started,System.currentTimeMillis(),identity),null);}catch(Throwable error){callback.finished(null,error);}},"routervpn-speed-lab").start();
    }

    private Latency idleLatency(AndroidHomeStateStore.Snapshot snapshot)throws Exception{
        List<Double> values=new ArrayList<>();int failed=0;
        for(int i=0;i<10;i++){requireFresh(snapshot);try{values.add(probe());}catch(StalePathException stale){throw stale;}catch(Throwable ignored){failed++;}requireFresh(snapshot);if(i!=9)Thread.sleep(60);}
        if(values.size()<3)throw new IllegalStateException("Too few idle latency samples succeeded.");return stats(values,failed);
    }

    private Direction direction(String direction,DurationPolicy policy,double idleMedian,AndroidHomeStateStore.Snapshot snapshot)throws Exception{
        long started=System.nanoTime(),totalBytes=0,totalWallNs=0;List<Double>rates=new ArrayList<>();AtomicBoolean loading=new AtomicBoolean(true);List<Double>loadedValues=Collections.synchronizedList(new ArrayList<>());int[] loadedFailed={0};AtomicReference<Throwable> loadedFatal=new AtomicReference<>();
        Thread latency=new Thread(()->{while(loading.get()){try{requireFresh(snapshot);loadedValues.add(probe());requireFresh(snapshot);}catch(StalePathException stale){loadedFatal.compareAndSet(null,stale);loading.set(false);break;}catch(Throwable error){loadedFailed[0]++;}try{Thread.sleep(110);}catch(InterruptedException ignored){Thread.currentThread().interrupt();break;}}},"routervpn-speed-lab-loaded-"+direction);latency.start();
        boolean stable=false;
        try{
            while((System.nanoTime()-started)/1_000_000_000d<policy.maxSeconds){requireFresh(snapshot);Throwable fatal=loadedFatal.get();if(fatal!=null)throw fatal;double previous=rates.isEmpty()?0:rates.get(rates.size()-1);int bytes=roundBytes(previous),streams=streamCount(previous);ParallelRound round=parallelRound(direction,bytes,streams);requireFresh(snapshot);fatal=loadedFatal.get();if(fatal!=null)throw fatal;if(round.bytes<=0||round.nanos<=0)throw new IllegalStateException("Speed Lab produced no measurable "+direction+" transfer.");double rate=round.bytes*8d/1_000_000d/(round.nanos/1_000_000_000d);rates.add(rate);totalBytes+=round.bytes;totalWallNs+=round.nanos;if((System.nanoTime()-started)/1_000_000_000d>=policy.minSeconds&&stable(rates)){stable=true;break;}}
        }finally{loading.set(false);latency.interrupt();latency.join(3000);}
        Throwable fatal=loadedFatal.get();if(fatal!=null){if(fatal instanceof Exception)throw(Exception)fatal;throw new IllegalStateException("Loaded-latency path validation failed.",fatal);}requireFresh(snapshot);
        if(totalBytes<=0||totalWallNs<=0)throw new IllegalStateException("Speed Lab completed without "+direction+" bytes.");List<Double>copy; synchronized(loadedValues){copy=new ArrayList<>(loadedValues);}if(copy.size()<2)throw new IllegalStateException("Too few "+direction+"-loaded latency samples succeeded.");Latency loaded=stats(copy,loadedFailed[0]);double seconds=totalWallNs/1_000_000_000d;double mbps=totalBytes*8d/1_000_000d/seconds;return new Direction(direction,round(mbps),totalBytes,round((System.nanoTime()-started)/1_000_000_000d),rates.size(),loaded,round(Math.max(0,loaded.medianMs-idleMedian)),stable);
    }

    private ParallelRound parallelRound(String direction,int bytes,int streams)throws Exception{
        streams=Math.max(1,Math.min(4,streams));bytes=Math.max(bytes,streams);final int streamCount=streams;baseBytesGuard(bytes);
        final int base=bytes/streamCount,remainder=bytes%streamCount;AtomicLong total=new AtomicLong();AtomicReference<Throwable> failure=new AtomicReference<>();Thread[]workers=new Thread[streamCount];long started=System.nanoTime();
        for(int i=0;i<streamCount;i++){final int part=base+(i<remainder?1:0),index=i;workers[i]=new Thread(()->{try{long done="download".equals(direction)?download(part):upload(part);total.addAndGet(done);}catch(Throwable error){failure.compareAndSet(null,error);}},"routervpn-speed-lab-"+direction+"-stream-"+index);workers[i].start();}
        for(Thread worker:workers){try{worker.join(35000);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw interrupted;}if(worker.isAlive()){for(Thread other:workers)other.interrupt();throw new IllegalStateException("Speed Lab "+direction+" stream exceeded its bounded round timeout.");}}
        Throwable error=failure.get();if(error!=null){if(error instanceof Exception)throw(Exception)error;throw new IllegalStateException("Speed Lab "+direction+" stream failed.",error);}long elapsed=System.nanoTime()-started,done=total.get();if(done!=bytes)throw new IllegalStateException("Parallel "+direction+" transferred "+done+" bytes, expected "+bytes+".");return new ParallelRound(done,elapsed);
    }

    private static void baseBytesGuard(int bytes){if(bytes<1||bytes>(32<<20))throw new IllegalArgumentException("Android Speed Lab round size is outside the bounded 1–32 MiB range.");}

    private double probe()throws Exception{
        HttpURLConnection c=(HttpURLConnection)new URL(DOWN+"?bytes=1&r="+System.nanoTime()).openConnection();c.setConnectTimeout(2500);c.setReadTimeout(2500);c.setInstanceFollowRedirects(false);c.setUseCaches(false);c.setRequestProperty("Accept-Encoding","identity");c.setRequestProperty("Cache-Control","no-store");c.setRequestProperty("User-Agent","RouterVPN-SpeedLab/1");long start=System.nanoTime();int code=c.getResponseCode();if(code<200||code>=300)throw new IllegalStateException("Latency probe returned HTTP "+code);int count=0;try(InputStream in=c.getInputStream()){while(in.read()!=-1){count++;if(count>1)break;}}finally{c.disconnect();}if(count!=1)throw new IllegalStateException("Latency probe did not return exactly one byte.");return round((System.nanoTime()-start)/1_000_000d);
    }

    private long download(int bytes)throws Exception{
        HttpURLConnection c=(HttpURLConnection)new URL(DOWN+"?bytes="+bytes+"&r="+System.nanoTime()).openConnection();c.setConnectTimeout(3500);c.setReadTimeout(30000);c.setInstanceFollowRedirects(false);c.setUseCaches(false);c.setRequestProperty("Accept-Encoding","identity");c.setRequestProperty("Cache-Control","no-store");c.setRequestProperty("User-Agent","RouterVPN-SpeedLab/1");int code=c.getResponseCode();if(code<200||code>=300)throw new IllegalStateException("Download load returned HTTP "+code);long total=0;try(InputStream in=c.getInputStream()){byte[]buf=new byte[64<<10];for(int n;(n=in.read(buf))!=-1;){total+=n;if(total>bytes)throw new IllegalStateException("Download exceeded requested size.");}}finally{c.disconnect();}if(total!=bytes)throw new IllegalStateException("Download returned "+total+" bytes, expected "+bytes+".");return total;
    }

    private long upload(int bytes)throws Exception{
        HttpURLConnection c=(HttpURLConnection)new URL(UP).openConnection();c.setConnectTimeout(3500);c.setReadTimeout(30000);c.setInstanceFollowRedirects(false);c.setUseCaches(false);c.setDoOutput(true);c.setRequestMethod("POST");c.setFixedLengthStreamingMode(bytes);c.setRequestProperty("Content-Type","application/octet-stream");c.setRequestProperty("Cache-Control","no-store");c.setRequestProperty("User-Agent","RouterVPN-SpeedLab/1");byte[]chunk=new byte[64<<10];int remaining=bytes;SecureRandom random=RANDOM.get();try(OutputStream out=c.getOutputStream()){while(remaining>0){int n=Math.min(chunk.length,remaining);random.nextBytes(chunk);out.write(chunk,0,n);remaining-=n;}out.flush();}int code=c.getResponseCode();if(code<200||code>=300)throw new IllegalStateException("Upload load returned HTTP "+code);try(InputStream in=c.getInputStream();ByteArrayOutputStream sink=new ByteArrayOutputStream()){byte[]buf=new byte[4096];for(int n,total=0;(n=in.read(buf))!=-1;){total+=n;if(total>65536)throw new IllegalStateException("Upload response exceeded limit.");sink.write(buf,0,n);}}finally{c.disconnect();}return bytes;
    }

    private void requireFresh(AndroidHomeStateStore.Snapshot before){AndroidHomeStateStore.Snapshot now=AndroidHomeStateStore.snapshot(context);if(before.connected!=now.connected||!same(before.sessionId,now.sessionId)||before.pathGeneration!=now.pathGeneration||!same(before.phase,now.phase)||!same(before.pathProof,now.pathProof)||!same(before.activeNodeId,now.activeNodeId)||!same(before.activeEntryId,now.activeEntryId)||!same(before.activeExitId,now.activeExitId)||!same(before.activeExternalId,now.activeExternalId)||!same(before.activeExternalProtocol,now.activeExternalProtocol)||!same(before.expectedExternalIp,now.expectedExternalIp)||!same(before.runtimeMode,now.runtimeMode)||!same(before.actualBase,now.actualBase)||!same(before.logicalMode,now.logicalMode))throw new StalePathException("Speed Lab result became stale because the Android VPN path changed during measurement.");if(now.connected&&(!"connected".equals(now.phase)||!"passed".equals(now.pathProof)))throw new StalePathException("Android current path is connected but not path-proved; Speed Lab refuses to label it.");if(!now.connected&&!"off".equals(now.phase))throw new StalePathException("Android disconnected path entered a transition during Speed Lab measurement.");}
    private static String identity(AndroidHomeStateStore.Snapshot s){if(!s.connected)return"system-direct:g"+s.pathGeneration;if(!"connected".equals(s.phase)||!"passed".equals(s.pathProof))throw new StalePathException("Android current VPN path is not proven.");if("multihop".equals(s.logicalMode))return"multihop:"+safe(s.activeEntryId)+"->"+safe(s.activeExitId)+":"+safe(s.runtimeMode)+":"+safe(s.actualBase)+":g"+s.pathGeneration;if("external".equals(s.logicalMode))return"external:"+safe(s.activeExternalId)+":"+safe(s.activeExternalProtocol)+":"+safe(s.actualBase)+":g"+s.pathGeneration;return"vpn:"+safe(s.activeNodeId)+":"+safe(s.runtimeMode)+":"+safe(s.actualBase)+":g"+s.pathGeneration;}
    private static int roundBytes(double previousMbps){if(previousMbps<=0)return 8<<20;long v=(long)(previousMbps*1_000_000d/8d*.70);return(int)Math.max(1<<20,Math.min(32<<20,v));}
    private static int streamCount(double previousMbps){if(previousMbps>=250)return 4;if(previousMbps>=80)return 2;return 1;}
    private static boolean stable(List<Double>rates){if(rates.size()<3)return false;int n=rates.size();double a=rates.get(n-3),b=rates.get(n-2),c=rates.get(n-1),min=Math.min(a,Math.min(b,c)),max=Math.max(a,Math.max(b,c)),mean=(a+b+c)/3d;return mean>0&&(max-min)/mean<=.04;}
    private static Latency stats(List<Double>values,int failed){if(values.isEmpty())throw new IllegalStateException("No latency samples succeeded.");List<Double>v=new ArrayList<>(values);Collections.sort(v);double sum=0;for(double x:v)sum+=x;double mean=sum/v.size(),variance=0;for(double x:v){double d=x-mean;variance+=d*d;}variance/=v.size();return new Latency(v.size(),failed,round(v.get(0)),round(percentile(v,.5)),round(mean),round(percentile(v,.9)),round(v.get(v.size()-1)),round(Math.sqrt(variance)));}
    private static double percentile(List<Double>v,double p){if(v.size()==1)return v.get(0);double pos=(v.size()-1)*p;int lo=(int)Math.floor(pos),hi=(int)Math.ceil(pos);if(lo==hi)return v.get(lo);return v.get(lo)+(v.get(hi)-v.get(lo))*(pos-lo);}
    private static boolean same(String a,String b){return safe(a).equals(safe(b));}
    private static String safe(String v){return v==null?"":v;}
    private static double round(double v){return Math.round(v*1000d)/1000d;}
}
