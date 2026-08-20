package com.eabusham.routervpn;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.SSLSocketFactory;

/** Bounded native Android telemetry. It never invents hop RTT or speed from arithmetic. */
final class AndroidTelemetry {
    interface Callback<T> { void finished(T value, Throwable error); }
    static final class Result {
        final String id,name; final double minMs,medianMs,averageMs,p90Ms,maxMs; final int samples,failed;
        Result(String id,String name,double min,double median,double average,double p90,double max,int samples,int failed){this.id=id;this.name=name;this.minMs=min;this.medianMs=median;this.averageMs=average;this.p90Ms=p90;this.maxMs=max;this.samples=samples;this.failed=failed;}
        String shortLabel(){return String.format(Locale.US,"%.1f ms",medianMs);}
        String detail(){return String.format(Locale.US,"%s — median %.1f ms • min %.1f • avg %.1f • p90 %.1f • max %.1f • %d ok / %d failed",name,medianMs,minMs,averageMs,p90Ms,maxMs,samples,failed);}
    }
    static final class PathResult {
        final double medianMs; final int samples,failed; final String proof;
        PathResult(double median,int samples,int failed,String proof){this.medianMs=median;this.samples=samples;this.failed=failed;this.proof=proof;}
    }
    static final class SpeedResult {
        final double downloadMbps,uploadMbps,downloadMs,uploadMs,serverReceiveMs;
        final int bytes;
        SpeedResult(double down,double up,double downMs,double upMs,double serverMs,int bytes){this.downloadMbps=down;this.uploadMbps=up;this.downloadMs=downMs;this.uploadMs=upMs;this.serverReceiveMs=serverMs;this.bytes=bytes;}
        String detail(){return String.format(Locale.US,"Download %.1f Mbps • Upload %.1f Mbps\n%d MiB each way • %.0f ms down • %.0f ms up%s",downloadMbps,uploadMbps,bytes/(1<<20),downloadMs,uploadMs,serverReceiveMs>0?String.format(Locale.US," • server receive %.0f ms",serverReceiveMs):"");}
    }

    private static final String PREFS="router-vpn-telemetry-v1";
    private static final int[] PORTS={443,8388,10443,11443,12443,13443,14443,15443,51820,51822};
    private static final int SPEED_DEFAULT_BYTES=8<<20,SPEED_MIN_BYTES=1<<20,SPEED_MAX_BYTES=16<<20;
    private final Context context;
    private final AndroidNodeStore store;

    AndroidTelemetry(Context context,AndroidNodeStore store){this.context=context.getApplicationContext();this.store=store;}

    double cachedMedian(String id){return context.getSharedPreferences(PREFS,Context.MODE_PRIVATE).getFloat("ms_"+id,0f);}
    private void cache(Result r){context.getSharedPreferences(PREFS,Context.MODE_PRIVATE).edit().putFloat("ms_"+r.id,(float)r.medianMs).putLong("at_"+r.id,System.currentTimeMillis()).apply();}

    void measureNode(AndroidNodeStore.Node node,int samples,Callback<Result> callback){new Thread(()->{try{Result r=probeNode(node,clamp(samples,3,50));cache(r);callback.finished(r,null);}catch(Throwable e){callback.finished(null,e);}},"routervpn-node-rtt").start();}

    void measureAll(int samples,Callback<List<Result>> callback){new Thread(()->{try{List<Result>out=new ArrayList<>();for(AndroidNodeStore.Node n:store.list()){try{Result r=probeNode(n,clamp(samples,3,10));cache(r);out.add(r);}catch(Throwable ignored){}}if(out.isEmpty())throw new IllegalStateException("No Router VPN node returned a live latency result.");Collections.sort(out,Comparator.comparingDouble(r->r.medianMs));callback.finished(out,null);}catch(Throwable e){callback.finished(null,e);}},"routervpn-fastest-rtt").start();}

    void currentPath(int samples,Callback<PathResult> callback){new Thread(()->{try{callback.finished(probePrivatePath(clamp(samples,2,10)),null);}catch(Throwable e){callback.finished(null,e);}},"routervpn-private-rtt").start();}

    void speedTest(int bytes,Callback<SpeedResult> callback){new Thread(()->{try{callback.finished(probeSpeed(activeBundle(),bytes<=0?SPEED_DEFAULT_BYTES:bytes),null);}catch(Throwable e){callback.finished(null,e);}},"routervpn-private-speed").start();}

    void speedTest(AndroidNodeStore.Node node,int bytes,Callback<SpeedResult> callback){new Thread(()->{try{if(node==null)throw new IllegalArgumentException("Choose a Router VPN hop first.");callback.finished(probeSpeed(readBundle(node.file),bytes<=0?SPEED_DEFAULT_BYTES:bytes),null);}catch(Throwable e){callback.finished(null,e);}},"routervpn-hop-speed").start();}

    private Result probeNode(AndroidNodeStore.Node node,int samples)throws Exception{
        if(node==null||node.endpoint==null||node.endpoint.trim().isEmpty())throw new IllegalArgumentException("Node has no public endpoint.");String host=endpointHost(node.endpoint);int port=discoverPort(host);List<Double>values=new ArrayList<>();int failed=0;
        for(int i=0;i<samples;i++){long start=System.nanoTime();try(Socket socket=new Socket()){socket.connect(new InetSocketAddress(host,port),900);values.add((System.nanoTime()-start)/1_000_000d);}catch(Exception e){failed++;}if(i+1<samples)try{Thread.sleep(20);}catch(InterruptedException ignored){Thread.currentThread().interrupt();}}
        if(values.isEmpty())throw new IllegalStateException("All live node latency probes failed.");Collections.sort(values);return new Result(node.id,node.name,round(values.get(0)),round(percentile(values,.5)),round(average(values)),round(percentile(values,.9)),round(values.get(values.size()-1)),values.size(),failed);
    }

    private int discoverPort(String host)throws Exception{Exception last=null;for(int port:PORTS){try(Socket s=new Socket()){s.connect(new InetSocketAddress(host,port),450);return port;}catch(Exception e){last=e;}}throw new IllegalStateException("No safe live probe port answered for "+host,last);}

    private PathResult probePrivatePath(int samples)throws Exception{
        JSONObject bundle=activeBundle();JSONObject profile=selectedProfile(bundle);String api=profile==null?"":profile.optString("router_api","").trim();if(api.isEmpty())api=bundle.optString("routerAPI","").trim();if(api.isEmpty())throw new IllegalStateException("Selected Router VPN node has no private Router API.");String token=profile==null?"":profile.optString("api_token","").trim();if(token.isEmpty())token=bundle.optString("apiToken","").trim();URI uri=URI.create(api);String host=uri.getHost();if(host==null||host.isEmpty())throw new IllegalStateException("Private Router API host is invalid.");int port=uri.getPort()>0?uri.getPort():("https".equalsIgnoreCase(uri.getScheme())?443:80);List<Double>values=new ArrayList<>();int failed=0;
        for(int i=0;i<samples;i++){long started=System.nanoTime();try{Socket socket="https".equalsIgnoreCase(uri.getScheme())?SSLSocketFactory.getDefault().createSocket():new Socket();socket.connect(new InetSocketAddress(host,port),1200);socket.setSoTimeout(1500);OutputStream out=socket.getOutputStream();String request="GET /health HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n"+(token.isEmpty()?"":"Authorization: Bearer "+token+"\r\n")+"\r\n";out.write(request.getBytes(StandardCharsets.US_ASCII));out.flush();InputStream in=socket.getInputStream();byte[]head=new byte[256];int n=in.read(head);socket.close();if(n<=0||!new String(head,0,n,StandardCharsets.US_ASCII).startsWith("HTTP/1.1 2"))throw new IllegalStateException("Private path health did not return 2xx");values.add((System.nanoTime()-started)/1_000_000d);}catch(Exception e){failed++;}if(i+1<samples)try{Thread.sleep(35);}catch(InterruptedException ignored){Thread.currentThread().interrupt();}}
        if(values.isEmpty())throw new IllegalStateException("Current private tunnel path did not answer.");Collections.sort(values);return new PathResult(round(percentile(values,.5)),values.size(),failed,"HTTP RTT to selected node private Router API through Android's current VPN path");
    }

    private SpeedResult probeSpeed(JSONObject bundle,int requestedBytes)throws Exception{
        int bytes=Math.max(SPEED_MIN_BYTES,Math.min(SPEED_MAX_BYTES,requestedBytes));
        JSONObject profile=selectedProfile(bundle);String api=profile==null?"":profile.optString("router_api","").trim();if(api.isEmpty())api=bundle.optString("routerAPI","").trim();String token=profile==null?"":profile.optString("api_token","").trim();if(token.isEmpty())token=bundle.optString("apiToken","").trim();if(api.isEmpty()||token.isEmpty())throw new IllegalStateException("Router VPN hop has no private benchmark API/token.");String base=api.endsWith("/")?api.substring(0,api.length()-1):api;

        HttpURLConnection down=(HttpURLConnection)new URL(base+"/api/benchmark/download?bytes="+bytes).openConnection();down.setConnectTimeout(3000);down.setReadTimeout(30000);down.setUseCaches(false);down.setRequestProperty("Authorization","Bearer "+token);down.setRequestProperty("Cache-Control","no-store");down.setRequestProperty("Accept-Encoding","identity");long downStart=System.nanoTime();int downCode=down.getResponseCode();if(downCode<200||downCode>=300)throw new IllegalStateException("Download benchmark returned HTTP "+downCode);long downloaded=0;try(InputStream in=down.getInputStream()){byte[]buf=new byte[64<<10];for(int n;(n=in.read(buf))!=-1;){downloaded+=n;if(downloaded>bytes)throw new IllegalStateException("Download benchmark exceeded requested size.");}}finally{down.disconnect();}double downSeconds=(System.nanoTime()-downStart)/1_000_000_000d;if(downloaded!=bytes)throw new IllegalStateException("Download benchmark returned "+downloaded+" bytes, expected "+bytes+".");

        HttpURLConnection up=(HttpURLConnection)new URL(base+"/api/benchmark/upload").openConnection();up.setConnectTimeout(3000);up.setReadTimeout(30000);up.setUseCaches(false);up.setDoOutput(true);up.setRequestMethod("POST");up.setFixedLengthStreamingMode(bytes);up.setRequestProperty("Authorization","Bearer "+token);up.setRequestProperty("Cache-Control","no-store");up.setRequestProperty("Content-Type","application/octet-stream");SecureRandom random=new SecureRandom();byte[]chunk=new byte[64<<10];int remaining=bytes;long upStart=System.nanoTime();try(OutputStream out=up.getOutputStream()){while(remaining>0){int n=Math.min(chunk.length,remaining);random.nextBytes(chunk);out.write(chunk,0,n);remaining-=n;}out.flush();}int upCode=up.getResponseCode();if(upCode<200||upCode>=300)throw new IllegalStateException("Upload benchmark returned HTTP "+upCode);byte[]replyBytes;try(InputStream in=up.getInputStream();ByteArrayOutputStream reply=new ByteArrayOutputStream()){byte[]buf=new byte[4096];for(int n,total=0;(n=in.read(buf))!=-1;){total+=n;if(total>65536)throw new IllegalStateException("Upload benchmark response is too large.");reply.write(buf,0,n);}replyBytes=reply.toByteArray();}finally{up.disconnect();}double upSeconds=(System.nanoTime()-upStart)/1_000_000_000d;JSONObject reply=new JSONObject(new String(replyBytes,StandardCharsets.UTF_8));if(reply.optLong("bytes",-1)!=bytes)throw new IllegalStateException("Upload benchmark byte proof mismatch.");double mbits=bytes*8d/1_000_000d;return new SpeedResult(round(mbits/Math.max(downSeconds,.000001)),round(mbits/Math.max(upSeconds,.000001)),round(downSeconds*1000),round(upSeconds*1000),round(reply.optDouble("server_receive_ms",0)),bytes);
    }

    private JSONObject activeBundle()throws Exception{String id=store.activeId();if(id==null||id.isEmpty())throw new IllegalStateException("Select a Router VPN node first.");return readBundle(store.file(id));}
    private static JSONObject readBundle(File file)throws Exception{if(file==null||!file.isFile()||file.length()<=0||file.length()>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Stored node bundle size is invalid.");try(FileInputStream in=new FileInputStream(file);ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]b=new byte[8192];int n,total=0;while((n=in.read(b))!=-1){total+=n;if(total>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Bundle exceeds safety limit.");out.write(b,0,n);}return new JSONObject(new String(out.toByteArray(),StandardCharsets.UTF_8));}}
    private static JSONObject selectedProfile(JSONObject bundle){JSONArray a=bundle.optJSONArray("routerProfiles");String id=bundle.optString("selectedRouterID","");if(a==null)return null;for(int i=0;i<a.length();i++){JSONObject p=a.optJSONObject(i);if(p!=null&&id.equals(p.optString("id","")))return p;}return a.length()>0?a.optJSONObject(0):null;}
    private static String endpointHost(String value){String raw=value.trim();try{URI uri=raw.contains("://")?URI.create(raw):URI.create("tcp://"+raw);if(uri.getHost()!=null&&!uri.getHost().isEmpty())return uri.getHost();}catch(Exception ignored){}if(raw.startsWith("[")&&raw.contains("]"))return raw.substring(1,raw.indexOf(']'));int colon=raw.lastIndexOf(':');if(colon>0&&raw.indexOf(':')==colon)return raw.substring(0,colon);return raw;}
    private static int clamp(int v,int fallback,int max){if(v<=0)v=fallback;return Math.max(1,Math.min(max,v));}
    private static double average(List<Double>v){double s=0;for(double x:v)s+=x;return s/v.size();}
    private static double percentile(List<Double>v,double p){if(v.size()==1)return v.get(0);double index=p*(v.size()-1),floor=Math.floor(index),ceil=Math.ceil(index);if(floor==ceil)return v.get((int)floor);return v.get((int)floor)*(ceil-index)+v.get((int)ceil)*(index-floor);}
    private static double round(double v){return Math.round(v*1000d)/1000d;}
}
