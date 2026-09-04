package com.eabusham.routervpn;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Process;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/** Real forwarding-master state through the active Router VPN private path. */
final class AndroidForwardingMaster {
    interface Callback { void finished(Boolean enabled, Throwable error); }
    private static final int MAX_REPLY=64*1024;
    private final Context context;
    private final AndroidNodeStore store;

    AndroidForwardingMaster(Context context,AndroidNodeStore store){this.context=context.getApplicationContext();this.store=store;}

    void get(Callback callback){run(null,callback);}
    void set(boolean enabled,Callback callback){run(enabled,callback);}

    private void run(Boolean requested,Callback callback){new Thread(()->{try{callback.finished(request(requested),null);}catch(Throwable error){callback.finished(null,error);}},"routervpn-forwarding-master").start();}

    private boolean request(Boolean requested)throws Exception{
        AndroidHomeStateStore.Snapshot state=AndroidHomeStateStore.snapshot(context);
        if(!state.connected)throw new IllegalStateException("Connect Router VPN before changing the server forwarding master.");
        if("external".equals(state.logicalMode))throw new IllegalStateException("Forwarding master belongs to a Router VPN home node; a direct external-exit session cannot control it.");
        String nodeId="multihop".equals(state.logicalMode)?state.activeExitId:state.activeNodeId;
        if(nodeId==null||nodeId.isEmpty())throw new IllegalStateException("Active Router VPN session node identity is unavailable.");
        JSONObject bundle=readBundle(store.file(nodeId));
        JSONObject profile=selectedProfile(bundle);
        String api=profile==null?"":profile.optString("router_api","").trim();
        if(api.isEmpty())api=bundle.optString("routerAPI","").trim();
        String token=profile==null?"":profile.optString("api_token","").trim();
        if(token.isEmpty())token=bundle.optString("apiToken","").trim();
        if(api.isEmpty()||token.isEmpty())throw new IllegalStateException("Active Router VPN node has no authenticated private Router API.");
        URI uri=URI.create(api);
        String host=uri.getHost();
        if(host==null||host.isEmpty()||!("http".equalsIgnoreCase(uri.getScheme())||"https".equalsIgnoreCase(uri.getScheme())))throw new IllegalStateException("Private Router API URL is invalid.");
        // Parse the literal address locally on every supported Android API level.
        // AndroidNumericAddress never invokes DNS, unlike hostname resolution,
        // and avoids the API-29-only android.net.InetAddresses dependency.
        InetAddress address;
        try{address=AndroidNumericAddress.parse(host);}catch(Exception e){throw new IllegalStateException("Forwarding master requires a literal private Router API address; hostnames are refused before any DNS lookup.",e);}
        if(!isPrivate(address))throw new IllegalStateException("Forwarding master refuses to send the node token to a non-private Router API host.");
        String base=api.endsWith("/")?api.substring(0,api.length()-1):api;
        Network vpn=ownedVpnNetwork();
        if(vpn==null)throw new IllegalStateException("Android has no active VPN network owned by Router VPN.");
        HttpURLConnection c=(HttpURLConnection)vpn.openConnection(new URL(base+"/api/forwarding/master"));
        c.setConnectTimeout(3000);c.setReadTimeout(5000);c.setUseCaches(false);c.setInstanceFollowRedirects(false);
        c.setRequestProperty("Authorization","Bearer "+token);c.setRequestProperty("Accept","application/json");c.setRequestProperty("Cache-Control","no-store");
        if(requested!=null){byte[]body=(new JSONObject().put("enabled",requested.booleanValue()).toString()+"\n").getBytes(StandardCharsets.UTF_8);c.setRequestMethod("PUT");c.setDoOutput(true);c.setFixedLengthStreamingMode(body.length);c.setRequestProperty("Content-Type","application/json");try(OutputStream out=c.getOutputStream()){out.write(body);out.flush();}}
        else c.setRequestMethod("GET");
        int code=c.getResponseCode();if(code<200||code>=300){c.disconnect();throw new IllegalStateException("Forwarding master returned HTTP "+code+".");}
        byte[]raw;try(InputStream in=c.getInputStream();ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]buf=new byte[4096];for(int n,total=0;(n=in.read(buf))!=-1;){total+=n;if(total>MAX_REPLY)throw new IllegalStateException("Forwarding-master response is too large.");out.write(buf,0,n);}raw=out.toByteArray();}finally{c.disconnect();}
        JSONObject reply=new JSONObject(new String(raw,StandardCharsets.UTF_8));if(!reply.optBoolean("ok",false)||!reply.has("enabled"))throw new IllegalStateException("Forwarding-master response could not be verified.");boolean enabled=reply.getBoolean("enabled");if(requested!=null&&enabled!=requested.booleanValue())throw new IllegalStateException("Forwarding master did not reach the requested state.");
        AndroidHomeStateStore.Snapshot after=AndroidHomeStateStore.snapshot(context);if(!after.connected||!state.sessionId.equals(after.sessionId)||after.pathGeneration!=state.pathGeneration)throw new IllegalStateException("VPN session/path changed while updating forwarding master; result discarded.");
        return enabled;
    }

    private Network ownedVpnNetwork(){ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);if(cm==null)return null;Network n=cm.getActiveNetwork();if(n==null)return null;NetworkCapabilities caps=cm.getNetworkCapabilities(n);if(caps==null||!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))return null;if(Build.VERSION.SDK_INT<Build.VERSION_CODES.Q)return null;return caps.getOwnerUid()==Process.myUid()?n:null;}
    private static boolean isPrivate(InetAddress a){if(a.isAnyLocalAddress())return false;if(a.isLoopbackAddress()||a.isLinkLocalAddress()||a.isSiteLocalAddress())return true;byte[]b=a.getAddress();return b.length==16&&(b[0]&0xfe)==0xfc;}
    private static JSONObject readBundle(File file)throws Exception{if(file==null||!file.isFile()||file.length()<=0||file.length()>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Active node bundle is invalid.");try(FileInputStream in=new FileInputStream(file);ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]buf=new byte[8192];int total=0,n;while((n=in.read(buf))!=-1){total+=n;if(total>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Active node bundle exceeds safety limit.");out.write(buf,0,n);}return new JSONObject(new String(out.toByteArray(),StandardCharsets.UTF_8));}}
    private static JSONObject selectedProfile(JSONObject bundle){JSONArray a=bundle.optJSONArray("routerProfiles");String id=bundle.optString("selectedRouterID","");if(a==null)return null;for(int i=0;i<a.length();i++){JSONObject p=a.optJSONObject(i);if(p!=null&&id.equals(p.optString("id","")))return p;}return a.length()>0?a.optJSONObject(0):null;}
}
