package com.eabusham.routervpn;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
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
    interface SingleCallback { void finished(Hop value, Throwable error); }

    static final class Hop {
        final String role,id,name;
        final double medianMs,downloadMbps,uploadMbps;
        final int latencySamples,latencyFailed,bytes;
        Hop(String role,String id,String name,double medianMs,double downloadMbps,double uploadMbps,int latencySamples,int latencyFailed,int bytes){
            this.role=role;this.id=id;this.name=name;this.medianMs=medianMs;this.downloadMbps=downloadMbps;this.uploadMbps=uploadMbps;this.latencySamples=latencySamples;this.latencyFailed=latencyFailed;this.bytes=bytes;
        }
        String summary(){return String.format(Locale.US,"%s • %s • %.1f ms • ↓ %.1f / ↑ %.1f Mbps",role.toUpperCase(Locale.US),name==null||name.isEmpty()?id:name,medianMs,downloadMbps,uploadMbps);}
    }

    private static final int DEFAULT_BYTES=8<<20,MIN_BYTES=1<<20,MAX_BYTES=16<<20;
    private static final int ENTRY_PROOF_PORT=1098;
    private static final int EXIT_PROOF_PORT=1099;
    private static final int MAX_PROOF=16<<10;
    private static final String PROOF_KIND="router-vpn-private-agent-v1";
    private final Context context;

    AndroidSpeedLabHopMeter(Context context){this.context=context.getApplicationContext();}

    void measure(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,Callback callback){measure(entry,exit,DEFAULT_BYTES,callback);}

    void measure(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,int requestedBytes,Callback callback){
        final int bytes=boundedBytes(requestedBytes);
        new Thread(()->{
            try{
                if(entry==null||exit==null||entry.id.equals(exit.id))throw new IllegalArgumentException("Choose different Router VPN entry and exit nodes for per-hop Speed Lab metrics.");
                AndroidHomeStateStore.Snapshot identity=requireGraph(entry.id,exit.id,null);
                List<Hop>out=new ArrayList<>(2);
                out.add(measureHop("entry",entry,identity,ENTRY_PROOF_PORT,bytes));
                requireGraph(entry.id,exit.id,identity);
                out.add(measureHop("exit",exit,identity,EXIT_PROOF_PORT,bytes));
                requireGraph(entry.id,exit.id,identity);
                callback.finished(out,null);
            }catch(Throwable error){callback.finished(null,error);}
        },"routervpn-speedlab-hops").start();
    }

    void measureOne(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,AndroidNodeStore.Node requested,int requestedBytes,SingleCallback callback){
        final int bytes=boundedBytes(requestedBytes);
        new Thread(()->{
            try{
                if(entry==null||exit==null||requested==null||entry.id.equals(exit.id))throw new IllegalArgumentException("Active Router VPN entry/exit nodes are required for routed hop metrics.");
                final String role;
                final int proofPort;
                if(requested.id.equals(entry.id)){role="entry";proofPort=ENTRY_PROOF_PORT;}
                else if(requested.id.equals(exit.id)){role="exit";proofPort=EXIT_PROOF_PORT;}
                else throw new IllegalArgumentException("Requested hop is not part of the active Android multihop graph.");
                AndroidHomeStateStore.Snapshot identity=requireGraph(entry.id,exit.id,null);
                Hop value=measureHop(role,requested,identity,proofPort,bytes);
                requireGraph(entry.id,exit.id,identity);
                callback.finished(value,null);
            }catch(Throwable error){callback.finished(null,error);}
        },"routervpn-one-hop-speed").start();
    }

    private static int boundedBytes(int requestedBytes){return Math.max(MIN_BYTES,Math.min(MAX_BYTES,requestedBytes<=0?DEFAULT_BYTES:requestedBytes));}

    private Hop measureHop(String role,AndroidNodeStore.Node node,AndroidHomeStateStore.Snapshot identity,int proofPort,int bytes)throws Exception{
        PrivateNode privateNode=privateNode(node);
        prove(privateNode,proofPort);
        requireGraph(identity.activeEntryId,identity.activeExitId,identity);
        List<Double>latencies=new ArrayList<>();int failed=0;
        for(int i=0;i<4;i++){
            requireGraph(identity.activeEntryId,identity.activeExitId,identity);
            long started=System.nanoTime();
            try{
                prove(privateNode,proofPort);
                latencies.add((System.nanoTime()-started)/1_000_000d);
            }catch(Exception error){failed++;}
            if(i!=3)Thread.sleep(35);
        }
        if(latencies.isEmpty())throw new IllegalStateException(role+" hop exact node-proof lane produced no successful RTT samples.");
        Collections.sort(latencies);
        requireGraph(identity.activeEntryId,identity.activeExitId,identity);
        double median=percentile(latencies,.5);

        double down=download(privateNode,proofPort,bytes);
        requireGraph(identity.activeEntryId,identity.activeExitId,identity);
        double up=upload(privateNode,proofPort,bytes);
        requireGraph(identity.activeEntryId,identity.activeExitId,identity);
        prove(privateNode,proofPort);
        requireGraph(identity.activeEntryId,identity.activeExitId,identity);
        return new Hop(role,node.id,node.name,round(median),round(down),round(up),latencies.size(),failed,bytes);
    }

    private void prove(PrivateNode node,int proofPort)throws Exception{
        HttpURLConnection c=open(node.base+"/health",node.token,"GET",2500,proofPort);
        try{
            int code=c.getResponseCode();
            if(code<200||code>=300)throw new IllegalStateException("Hop node proof returned HTTP "+code);
            byte[]reply=readLimited(c.getInputStream(),MAX_PROOF,"Hop node proof is too large.");
            JSONObject body=new JSONObject(new String(reply,StandardCharsets.UTF_8));
            if(!body.optBoolean("ok",false)||!node.expectedNode.equals(body.optString("node_id","").trim())||!PROOF_KIND.equals(body.optString("proof","").trim()))throw new IllegalStateException("Hop proof lane reached the wrong Router VPN node identity.");
        }finally{c.disconnect();}
    }

    private double download(PrivateNode node,int proofPort,int bytes)throws Exception{
        HttpURLConnection c=open(node.base+"/api/benchmark/download?bytes="+bytes,node.token,"GET",30000,proofPort);c.setRequestProperty("Accept-Encoding","identity");long started=System.nanoTime();long total=0;
        try{int code=c.getResponseCode();if(code<200||code>=300)throw new IllegalStateException("Hop download benchmark returned HTTP "+code);try(InputStream in=c.getInputStream()){byte[]b=new byte[64<<10];for(int n;(n=in.read(b))!=-1;){total+=n;if(total>bytes)throw new IllegalStateException("Hop download exceeded requested size.");}}}finally{c.disconnect();}
        if(total!=bytes)throw new IllegalStateException("Hop download returned "+total+" bytes, expected "+bytes+".");double seconds=(System.nanoTime()-started)/1_000_000_000d;return bytes*8d/1_000_000d/Math.max(seconds,.000001);
    }

    private double upload(PrivateNode node,int proofPort,int bytes)throws Exception{
        HttpURLConnection c=open(node.base+"/api/benchmark/upload",node.token,"POST",30000,proofPort);c.setDoOutput(true);c.setFixedLengthStreamingMode(bytes);c.setRequestProperty("Content-Type","application/octet-stream");SecureRandom random=new SecureRandom();byte[]chunk=new byte[64<<10];int remaining=bytes;long started=System.nanoTime();
        try{try(OutputStream out=c.getOutputStream()){while(remaining>0){int n=Math.min(chunk.length,remaining);random.nextBytes(chunk);out.write(chunk,0,n);remaining-=n;}out.flush();}int code=c.getResponseCode();if(code<200||code>=300)throw new IllegalStateException("Hop upload benchmark returned HTTP "+code);byte[]reply=readLimited(c.getInputStream(),65536,"Hop upload proof is too large.");JSONObject ack=new JSONObject(new String(reply,StandardCharsets.UTF_8));if(ack.optLong("bytes",-1)!=bytes)throw new IllegalStateException("Hop upload byte proof mismatch.");}finally{c.disconnect();}
        double seconds=(System.nanoTime()-started)/1_000_000_000d;return bytes*8d/1_000_000d/Math.max(seconds,.000001);
    }

    private HttpURLConnection open(String value,String token,String method,int timeout,int proofPort)throws Exception{
        if(proofPort!=ENTRY_PROOF_PORT&&proofPort!=EXIT_PROOF_PORT)throw new IllegalArgumentException("Speed Lab requires a reserved multihop proof lane.");
        Proxy proxy=new Proxy(Proxy.Type.HTTP,new InetSocketAddress("127.0.0.1",proofPort));
        HttpURLConnection c=(HttpURLConnection)new URL(value).openConnection(proxy);c.setConnectTimeout(3000);c.setReadTimeout(timeout);c.setUseCaches(false);c.setRequestMethod(method);c.setRequestProperty("Authorization","Bearer "+token);c.setRequestProperty("Cache-Control","no-store");return c;
    }

    private PrivateNode privateNode(AndroidNodeStore.Node node)throws Exception{
        JSONObject bundle=readBundle(node);AndroidNodeStore.validateBundle(bundle);JSONObject profile=selectedProfile(bundle);String api=profile==null?"":profile.optString("router_api","").trim();if(api.isEmpty())api=bundle.optString("routerAPI","").trim();String token=profile==null?"":profile.optString("api_token","").trim();if(token.isEmpty())token=bundle.optString("apiToken","").trim();String expected=AndroidNodeStore.stableNodeIdentity(bundle);if(api.isEmpty()||token.isEmpty())throw new IllegalStateException("Router VPN "+node.name+" has no private benchmark API/token.");if(!expected.matches("[0-9a-f]{64}"))throw new IllegalStateException("Router VPN "+node.name+" has no valid stable node proof identity.");while(api.endsWith("/"))api=api.substring(0,api.length()-1);if(!api.startsWith("http://"))throw new IllegalStateException("Per-hop Speed Lab requires the private Router VPN HTTP API.");return new PrivateNode(api,token,expected);
    }

    private JSONObject readBundle(AndroidNodeStore.Node node)throws Exception{
        if(node.file==null||!node.file.isFile()||node.file.length()<=0||node.file.length()>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Stored hop bundle size is invalid.");try(FileInputStream in=new FileInputStream(node.file);ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]b=new byte[8192];int n,total=0;while((n=in.read(b))!=-1){total+=n;if(total>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Stored hop bundle exceeds safety limit.");out.write(b,0,n);}return new JSONObject(new String(out.toByteArray(),StandardCharsets.UTF_8));}
    }

    private static byte[] readLimited(InputStream in,int max,String error)throws Exception{try(InputStream input=in;ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]b=new byte[4096];for(int n,total=0;(n=input.read(b))!=-1;){total+=n;if(total>max)throw new IllegalStateException(error);out.write(b,0,n);}return out.toByteArray();}}

    private static JSONObject selectedProfile(JSONObject bundle){JSONArray rows=bundle.optJSONArray("routerProfiles");String selected=bundle.optString("selectedRouterID","");if(rows==null)return null;for(int i=0;i<rows.length();i++){JSONObject p=rows.optJSONObject(i);if(p!=null&&selected.equals(p.optString("id","")))return p;}return rows.length()>0?rows.optJSONObject(0):null;}

    private AndroidHomeStateStore.Snapshot requireGraph(String entry,String exit,AndroidHomeStateStore.Snapshot expected){AndroidHomeStateStore.Snapshot s=AndroidHomeStateStore.snapshot(context);if(!s.connected||!"connected".equals(s.phase)||!"passed".equals(s.pathProof)||!"multihop".equals(s.logicalMode)||!entry.equals(s.activeEntryId)||!exit.equals(s.activeExitId))throw new IllegalStateException("Android multihop graph changed while Speed Lab hop metrics were running; stale results were discarded.");if(expected!=null&&(!expected.sessionId.equals(s.sessionId)||expected.pathGeneration!=s.pathGeneration||!expected.runtimeMode.equals(s.runtimeMode)||!expected.actualBase.equals(s.actualBase)))throw new IllegalStateException("Android multihop session identity changed while Speed Lab hop metrics were running; stale results were discarded.");return s;}

    private static double percentile(List<Double>v,double p){if(v.size()==1)return v.get(0);double x=p*(v.size()-1),lo=Math.floor(x),hi=Math.ceil(x);if(lo==hi)return v.get((int)lo);return v.get((int)lo)*(hi-x)+v.get((int)hi)*(x-lo);}
    private static double round(double value){return Math.round(value*1000d)/1000d;}
    private static final class PrivateNode{final String base,token,expectedNode;PrivateNode(String base,String token,String expectedNode){this.base=base;this.token=token;this.expectedNode=expectedNode;}}
}