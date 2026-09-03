package com.eabusham.routervpn;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Independent per-hop RTT/Mbps for Speed Lab on one unchanged proven Android multihop graph. */
final class AndroidSpeedLabHopMeter {
    interface Callback { void finished(List<Hop> value, Throwable error); }

    static final class Hop {
        final String role,id,name;
        final double medianMs,downloadMbps,uploadMbps;
        final int latencySamples,latencyFailed,bytes;
        Hop(String role,String id,String name,double medianMs,double downloadMbps,double uploadMbps,int latencySamples,int latencyFailed,int bytes){
            this.role=role;this.id=id;this.name=name;this.medianMs=medianMs;this.downloadMbps=downloadMbps;this.uploadMbps=uploadMbps;this.latencySamples=latencySamples;this.latencyFailed=latencyFailed;this.bytes=bytes;
        }
        String summary(){return String.format(Locale.US,"%s • %s • %.1f ms • ↓ %.1f / ↑ %.1f Mbps",role.toUpperCase(Locale.US),name==null||name.isEmpty()?id:name,medianMs,downloadMbps,uploadMbps);}
    }

    private static final int BYTES=8<<20;
    private final Context context;

    AndroidSpeedLabHopMeter(Context context){this.context=context.getApplicationContext();}

    void measure(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,Callback callback){
        new Thread(()->{
            try{
                if(entry==null||exit==null||entry.id.equals(exit.id))throw new IllegalArgumentException("Choose different Router VPN entry and exit nodes for per-hop Speed Lab metrics.");
                AndroidHomeStateStore.Snapshot identity=requireGraph(entry.id,exit.id,null);
                List<Hop>out=new ArrayList<>(2);
                out.add(measureHop("entry",entry,identity));
                requireGraph(entry.id,exit.id,identity);
                out.add(measureHop("exit",exit,identity));
                requireGraph(entry.id,exit.id,identity);
                callback.finished(out,null);
            }catch(Throwable error){callback.finished(null,error);}
        },"routervpn-speedlab-hops").start();
    }

    private Hop measureHop(String role,AndroidNodeStore.Node node,AndroidHomeStateStore.Snapshot identity)throws Exception{
        PrivateNode privateNode=privateNode(node);
        List<Double>latencies=new ArrayList<>();int failed=0;
        for(int i=0;i<4;i++){
            requireGraph(identity.activeEntryId,identity.activeExitId,identity);
            long started=System.nanoTime();
            HttpURLConnection health=null;
            try{
                health=open(privateNode.base+"/health",privateNode.token,"GET",2500);
                int code=health.getResponseCode();
                try(InputStream in=code>=200&&code<300?health.getInputStream():health.getErrorStream()){if(in!=null){byte[]b=new byte[512];while(in.read(b)!=-1){}}}
                if(code<200||code>=300)throw new IllegalStateException("Private hop health returned HTTP "+code);
                latencies.add((System.nanoTime()-started)/1_000_000d);
            }catch(Exception error){failed++;}
            finally{if(health!=null)health.disconnect();}
            if(i!=3)Thread.sleep(35);
        }
        if(latencies.isEmpty())throw new IllegalStateException(role+" hop private RTT produced no successful samples.");
        Collections.sort(latencies);
        requireGraph(identity.activeEntryId,identity.activeExitId,identity);
        double median=percentile(latencies,.5);

        double down=download(privateNode);
        requireGraph(identity.activeEntryId,identity.activeExitId,identity);
        double up=upload(privateNode);
        requireGraph(identity.activeEntryId,identity.activeExitId,identity);
        return new Hop(role,node.id,node.name,round(median),round(down),round(up),latencies.size(),failed,BYTES);
    }

    private double download(PrivateNode node)throws Exception{
        HttpURLConnection c=open(node.base+"/api/benchmark/download?bytes="+BYTES,node.token,"GET",30000);c.setRequestProperty("Accept-Encoding","identity");long started=System.nanoTime();long total=0;
        try{int code=c.getResponseCode();if(code<200||code>=300)throw new IllegalStateException("Hop download benchmark returned HTTP "+code);try(InputStream in=c.getInputStream()){byte[]b=new byte[64<<10];for(int n;(n=in.read(b))!=-1;){total+=n;if(total>BYTES)throw new IllegalStateException("Hop download exceeded requested size.");}}}finally{c.disconnect();}
        if(total!=BYTES)throw new IllegalStateException("Hop download returned "+total+" bytes, expected "+BYTES+".");double seconds=(System.nanoTime()-started)/1_000_000_000d;return BYTES*8d/1_000_000d/Math.max(seconds,.000001);
    }

    private double upload(PrivateNode node)throws Exception{
        HttpURLConnection c=open(node.base+"/api/benchmark/upload",node.token,"POST",30000);c.setDoOutput(true);c.setFixedLengthStreamingMode(BYTES);c.setRequestProperty("Content-Type","application/octet-stream");SecureRandom random=new SecureRandom();byte[]chunk=new byte[64<<10];int remaining=BYTES;long started=System.nanoTime();
        try{try(OutputStream out=c.getOutputStream()){while(remaining>0){int n=Math.min(chunk.length,remaining);random.nextBytes(chunk);out.write(chunk,0,n);remaining-=n;}out.flush();}int code=c.getResponseCode();if(code<200||code>=300)throw new IllegalStateException("Hop upload benchmark returned HTTP "+code);byte[]reply;try(InputStream in=c.getInputStream();ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]b=new byte[4096];for(int n,total=0;(n=in.read(b))!=-1;){total+=n;if(total>65536)throw new IllegalStateException("Hop upload proof is too large.");out.write(b,0,n);}reply=out.toByteArray();}JSONObject ack=new JSONObject(new String(reply,StandardCharsets.UTF_8));if(ack.optLong("bytes",-1)!=BYTES)throw new IllegalStateException("Hop upload byte proof mismatch.");}finally{c.disconnect();}
        double seconds=(System.nanoTime()-started)/1_000_000_000d;return BYTES*8d/1_000_000d/Math.max(seconds,.000001);
    }

    private HttpURLConnection open(String value,String token,String method,int timeout)throws Exception{
        HttpURLConnection c=(HttpURLConnection)new URL(value).openConnection();c.setConnectTimeout(3000);c.setReadTimeout(timeout);c.setUseCaches(false);c.setRequestMethod(method);c.setRequestProperty("Authorization","Bearer "+token);c.setRequestProperty("Cache-Control","no-store");return c;
    }

    private PrivateNode privateNode(AndroidNodeStore.Node node)throws Exception{
        JSONObject bundle=readBundle(node);JSONObject profile=selectedProfile(bundle);String api=profile==null?"":profile.optString("router_api","").trim();if(api.isEmpty())api=bundle.optString("routerAPI","").trim();String token=profile==null?"":profile.optString("api_token","").trim();if(token.isEmpty())token=bundle.optString("apiToken","").trim();if(api.isEmpty()||token.isEmpty())throw new IllegalStateException("Router VPN "+node.name+" has no private benchmark API/token.");while(api.endsWith("/"))api=api.substring(0,api.length()-1);return new PrivateNode(api,token);
    }

    private JSONObject readBundle(AndroidNodeStore.Node node)throws Exception{
        if(node.file==null||!node.file.isFile()||node.file.length()<=0||node.file.length()>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Stored hop bundle size is invalid.");try(FileInputStream in=new FileInputStream(node.file);ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]b=new byte[8192];int n,total=0;while((n=in.read(b))!=-1){total+=n;if(total>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Stored hop bundle exceeds safety limit.");out.write(b,0,n);}return new JSONObject(new String(out.toByteArray(),StandardCharsets.UTF_8));}
    }

    private static JSONObject selectedProfile(JSONObject bundle){JSONArray rows=bundle.optJSONArray("routerProfiles");String selected=bundle.optString("selectedRouterID","");if(rows==null)return null;for(int i=0;i<rows.length();i++){JSONObject p=rows.optJSONObject(i);if(p!=null&&selected.equals(p.optString("id","")))return p;}return rows.length()>0?rows.optJSONObject(0):null;}

    private AndroidHomeStateStore.Snapshot requireGraph(String entry,String exit,AndroidHomeStateStore.Snapshot expected){AndroidHomeStateStore.Snapshot s=AndroidHomeStateStore.snapshot(context);if(!s.connected||!"connected".equals(s.phase)||!"passed".equals(s.pathProof)||!"multihop".equals(s.logicalMode)||!entry.equals(s.activeEntryId)||!exit.equals(s.activeExitId))throw new IllegalStateException("Android multihop graph changed while Speed Lab hop metrics were running; stale results were discarded.");if(expected!=null&&(!expected.sessionId.equals(s.sessionId)||expected.pathGeneration!=s.pathGeneration||!expected.runtimeMode.equals(s.runtimeMode)||!expected.actualBase.equals(s.actualBase)))throw new IllegalStateException("Android multihop session identity changed while Speed Lab hop metrics were running; stale results were discarded.");return s;}

    private static double percentile(List<Double>v,double p){if(v.size()==1)return v.get(0);double x=p*(v.size()-1),lo=Math.floor(x),hi=Math.ceil(x);if(lo==hi)return v.get((int)lo);return v.get((int)lo)*(hi-x)+v.get((int)hi)*(x-lo);}
    private static double round(double value){return Math.round(value*1000d)/1000d;}
    private static final class PrivateNode{final String base,token;PrivateNode(String base,String token){this.base=base;this.token=token;}}
}
