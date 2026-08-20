package com.eabusham.routervpn;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Process;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Truthful Android Home state. Cached profile public_ip is never treated as a live exit proof. */
final class AndroidHomeSummary {
    interface Callback { void done(String message, Throwable error); }
    private static volatile String provedSignature = "";
    private static volatile String provedExit = "";

    private static final class RuntimeState {
        String phase="off", logical="", runtime="", base="", fallback="", warning="", activeEntryId="", activeExitId="";
        boolean connected;
    }

    static String format(Activity activity, AndroidNodeStore nodeStore) {
        try {
            RuntimeState runtime = runtimeState(activity);
            JSONObject profile = proofProfile(nodeStore, runtime);
            Network vpn = ownedVpnNetwork(activity);
            String signature = signature(vpn, runtime);
            boolean osConnected = vpn != null;
            boolean connected = runtime.connected && osConnected;
            if (!signature.equals(provedSignature)) { provedSignature = ""; provedExit = ""; }
            String exit = connected ? (!provedExit.isEmpty() ? provedExit : "Unproven — tap Prove actual exit") : "Not connected";
            List<String> warnings = new ArrayList<>();
            if (runtime.connected && !osConnected) warnings.add("Stored runtime says connected but Android has no Router VPN-owned VPN network");
            if (connected && provedExit.isEmpty()) warnings.add("Actual public exit is not proven for this live Android VPN network");
            if ("multihop".equals(runtime.logical) && (runtime.activeEntryId.isEmpty() || runtime.activeExitId.isEmpty())) warnings.add("Multihop runtime identity is incomplete; exit proof is unavailable until the exact active graph is known");
            if (!runtime.warning.isEmpty()) warnings.add(runtime.warning);
            warnings.add("DNS RTT is a home-node A/AAAA query measurement; active Android tunnel DNS still needs runtime/device proof");

            String dnsHost = profile.optString("dns_host", profile.optString("adguard_ipv4", ""));
            String dnsMode = profile.optString("dns_mode", "home");
            double dnsRtt = measuredDnsRtt(profile, dnsHost);
            int samples = profile.optInt("latency_samples", 0);
            double latency = profile.optDouble("latency_median_ms", 0);
            int mtu = profile.optInt("effective_mtu", 0);
            String mtuText = mtu > 0 ? mtu + " • " + profile.optString("effective_mtu_source", "measured") : profile.optString("mtu_policy", "default");
            String location = profile.optString("location", "").trim();
            if (location.isEmpty()) location = "Location not labeled";
            String logical = runtime.logical.isEmpty() ? runtime.runtime : runtime.logical;
            String base = runtime.base.isEmpty() ? inferredBase(runtime.runtime) : runtime.base;
            String fallback = runtime.fallback.isEmpty() ? "None" : runtime.fallback;
            String nodeLabel = profile.optString("name", profile.optString("id", "Router VPN"));
            String graphLabel = "multihop".equals(runtime.logical) && !runtime.activeEntryId.isEmpty() && !runtime.activeExitId.isEmpty()
                    ? nodeName(nodeStore, runtime.activeEntryId) + " → " + nodeName(nodeStore, runtime.activeExitId)
                    : nodeLabel;
            String proofLabel = "multihop".equals(runtime.logical) ? "active exit-node path proof" : "selected-node path proof";

            return "Node/path: " + graphLabel + " • " + location +
                    "\nPublic endpoint: " + profile.optString("endpoint", "—") +
                    "\nActual public VPN exit: " + exit +
                    "\nConnection: " + (connected ? "connected • " + proofLabel + " passed by the active engine" : runtime.phase) +
                    "\nLogical/runtime/base: " + empty(logical) + " • " + empty(runtime.runtime) + " • " + empty(base) +
                    "\nFallback: " + fallback +
                    "\nDNS: " + dnsMode + " • " + empty(dnsHost) + (dnsRtt > 0 ? String.format(Locale.US," • home query RTT %.2f ms",dnsRtt) : " • query RTT not measured") +
                    "\nNode latency: " + (samples > 0 ? String.format(Locale.US,"%.2f ms / %d samples",latency,samples) : "Not measured") +
                    "\nLAN access: " + (profile.optBoolean("home_lan_access", true) ? "On" : "Off") + " • Kill switch: " + killSwitch(profile) +
                    "\nEffective MTU: " + mtuText + " • IPv6: " + profile.optString("ipv6_mode", "default") +
                    "\nWarnings: " + (warnings.isEmpty() ? "None" : String.join(" | ", warnings));
        } catch (Throwable error) {
            return "Home state unavailable: " + safe(error);
        }
    }

    static void proveActualExit(Activity activity, AndroidNodeStore nodeStore, Callback callback) {
        new Thread(() -> {
            try {
                FileProof proof = proofInputs(activity, nodeStore);
                if (!AndroidPathProbe.prove(proof.bundle, 8000)) throw new IllegalStateException(proof.multihop ? "Active multihop exit-node private path proof failed before public-exit test." : "Selected-node private path proof failed before public-exit test.");
                String ip = fetchIP(proof.network);
                FileProof after = proofInputs(activity, nodeStore);
                if (!proof.signature.equals(after.signature)) throw new IllegalStateException("Android VPN network/runtime or active node graph changed while proving public exit; result discarded.");
                if (!AndroidPathProbe.prove(after.bundle, 8000)) throw new IllegalStateException(after.multihop ? "Active multihop exit-node private path proof failed after public-exit test." : "Selected-node private path proof failed after public-exit test.");
                provedSignature = after.signature;
                provedExit = ip;
                AndroidHomeStateStore.saveActualExit(activity, AndroidHomeStateStore.snapshot(activity).sessionId, ip);
                callback.done("Actual public VPN exit proved for this live Router VPN network: " + ip, null);
            } catch (Throwable error) { provedSignature=""; provedExit=""; callback.done("Actual exit proof failed: " + safe(error), error); }
        }, "routervpn-home-exit-proof").start();
    }

    static void emergencyDisconnect(Activity activity, Callback callback) {
        AndroidHomeStateStore.warning(activity, "Emergency Disconnect requested; verifying Router VPN transports stop.");
        try { activity.startService(new Intent(activity, LayeredVpnService.class).setAction(LayeredVpnService.ACTION_STOP)); } catch (Throwable ignored) {}
        try { activity.startService(new Intent(activity, XrayVpnService.class).setAction(XrayVpnService.ACTION_STOP)); } catch (Throwable ignored) {}
        NativeWireGuardController wg = new NativeWireGuardController(activity);
        NativeAmneziaWGController awg = new NativeAmneziaWGController(activity);
        wg.disconnect((state,message,error) -> wg.close());
        awg.disconnect((state,message,error) -> awg.close());
        provedSignature=""; provedExit="";
        new Thread(() -> {
            try {
                Thread.sleep(1200);
                if (ownedVpnNetwork(activity) != null) throw new IllegalStateException("A Router VPN-owned Android VPN network is still active after emergency-stop requests.");
                AndroidHomeStateStore.disconnected(activity);
                callback.done("Emergency Disconnect completed; no Router VPN-owned VPN network remains.", null);
            } catch(Throwable error) { AndroidHomeStateStore.failed(activity, safe(error)); callback.done("Emergency Disconnect incomplete: "+safe(error), error); }
        }, "routervpn-emergency-verify").start();
    }

    private static final class FileProof {
        final java.io.File bundle; final Network network; final String signature; final boolean multihop;
        FileProof(java.io.File bundle,Network network,String signature,boolean multihop){this.bundle=bundle;this.network=network;this.signature=signature;this.multihop=multihop;}
    }
    private static FileProof proofInputs(Activity activity,AndroidNodeStore store)throws Exception{
        RuntimeState runtime=runtimeState(activity); if(!runtime.connected)throw new IllegalStateException("Router VPN runtime is not in a proven connected state.");
        boolean multihop="multihop".equals(runtime.logical);
        String id=multihop?runtime.activeExitId:store.activeId();
        if(id==null||id.isEmpty())throw new IllegalStateException(multihop?"Active multihop exit identity is unavailable.":"Select a Router VPN node first.");
        java.io.File bundle=store.file(id); if(!bundle.isFile())throw new IllegalStateException(multihop?"Active multihop exit bundle is missing.":"Selected private node bundle is missing.");
        Network network=ownedVpnNetwork(activity); if(network==null)throw new IllegalStateException("No active Android VPN network owned by Router VPN.");
        return new FileProof(bundle,network,signature(network,runtime),multihop);
    }

    private static Network ownedVpnNetwork(Context context) {
        ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE); if(cm==null)return null;
        Network network=cm.getActiveNetwork(); if(network==null)return null;
        NetworkCapabilities caps=cm.getNetworkCapabilities(network); if(caps==null||!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))return null;
        if(Build.VERSION.SDK_INT<Build.VERSION_CODES.Q)return null;
        return caps.getOwnerUid()==Process.myUid()?network:null;
    }

    private static RuntimeState runtimeState(Context context){
        RuntimeState out=new RuntimeState(); AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
        out.activeEntryId=home.activeEntryId;out.activeExitId=home.activeExitId;
        if(home.connected){out.connected=true;out.phase=home.phase;out.logical=home.logicalMode;out.runtime=home.runtimeMode;out.base=home.actualBase;out.fallback=home.fallback;out.warning=home.warning;return out;}
        SharedPreferences p=context.getSharedPreferences("router-vpn",Context.MODE_PRIVATE);
        String layered=p.getString(NativeSingBoxController.STATE_KEY,"DOWN");
        if("UP".equals(layered)){out.connected=true;out.phase="connected";out.runtime=p.getString(NativeSingBoxController.MODE_KEY,"");out.logical=out.runtime;out.base="libbox";out.warning=p.getString(NativeSingBoxController.ERROR_KEY,"");return out;}
        String xray=p.getString(NativeXrayController.STATE_KEY,"DOWN");
        if("UP".equals(xray)){out.connected=true;out.phase="connected";out.runtime=p.getString(NativeXrayController.MODE_KEY,"");out.logical=out.runtime;out.base="xray";out.warning=p.getString(NativeXrayController.ERROR_KEY,"");return out;}
        out.phase=home.phase;out.warning=home.warning;return out;
    }

    private static String signature(Network network,RuntimeState runtime){return network==null?"":network.getNetworkHandle()+"|"+runtime.logical+"|"+runtime.runtime+"|"+runtime.base+"|"+runtime.activeEntryId+"|"+runtime.activeExitId;}
    private static String fetchIP(Network network)throws Exception{
        for(String raw:new String[]{"https://api64.ipify.org","https://api.ipify.org"}){
            HttpURLConnection c=null;try{c=(HttpURLConnection)network.openConnection(new URL(raw));c.setConnectTimeout(6000);c.setReadTimeout(6000);c.setUseCaches(false);if(c.getResponseCode()/100!=2)continue;byte[]data=readLimited(c.getInputStream(),128);String value=new String(data,StandardCharsets.UTF_8).trim();if(value.matches("[0-9A-Fa-f:.]+")){InetAddress.getByName(value);return value;}}catch(Throwable ignored){}finally{if(c!=null)c.disconnect();}
        }throw new IllegalStateException("Could not determine public VPN exit through the active Router VPN network.");
    }
    private static JSONObject proofProfile(AndroidNodeStore store,RuntimeState runtime)throws Exception{String id="multihop".equals(runtime.logical)&&!runtime.activeExitId.isEmpty()?runtime.activeExitId:store.activeId();if(id==null||id.isEmpty())throw new IllegalStateException("Pair/import and select a Router VPN node first.");return AndroidUnifiedNodeCatalog.selectedProfile(store.file(id));}
    private static String nodeName(AndroidNodeStore store,String id){try{JSONObject p=AndroidUnifiedNodeCatalog.selectedProfile(store.file(id));String name=p.optString("name",id).trim();return name.isEmpty()?id:name;}catch(Throwable ignored){return id==null||id.isEmpty()?"unknown":id;}}
    private static double measuredDnsRtt(JSONObject p,String host){JSONArray a=p.optJSONArray("dns_results");if(a!=null)for(int i=0;i<a.length();i++){JSONObject r=a.optJSONObject(i);if(r!=null&&r.optBoolean("working")&&host.equals(r.optString("address")))return r.optDouble("latency_ms",0);}return p.optDouble("fastest_dns_latency_ms",0);}
    private static String killSwitch(JSONObject p){String value=p.optString("kill_switch_policy","").trim();if(!value.isEmpty())return value;return p.optBoolean("kill_switch",false)?"strict":"off";}
    private static String inferredBase(String runtime){if(runtime==null)return"";if(runtime.startsWith("awg"))return"awg";if("wg".equals(runtime)||runtime.contains("-wg"))return"wg";if(!runtime.isEmpty())return"embedded";return"";}
    private static String empty(String value){return value==null||value.isEmpty()?"—":value;}
    private static byte[] readLimited(InputStream input,int max)throws Exception{try(InputStream in=input;ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]b=new byte[128];int n,total=0;while((n=in.read(b))!=-1){total+=n;if(total>max)throw new IllegalStateException("Public-exit response exceeded safety limit.");out.write(b,0,n);}return out.toByteArray();}}
    private static String safe(Throwable e){String v=e==null?"":e.getMessage();return v==null||v.trim().isEmpty()?"Router VPN error":v.replace('\n',' ').replace('\r',' ').trim();}
    private AndroidHomeSummary(){}
}
