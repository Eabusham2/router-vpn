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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Truthful Android Home state. Cached profile public_ip is never treated as a live exit proof. */
final class AndroidHomeSummary {
    interface Callback { void done(String message, Throwable error); }
    private static volatile String provedSignature = "";
    private static volatile String provedExit = "";

    private static final class RuntimeState {
        String sessionId="",phase="off", logical="", runtime="", base="", fallback="", warning="", activeNodeId="", activeEntryId="", activeExitId="";
        String activeExternalId="",activeExternalName="",activeExternalProtocol="",expectedExternalIp="";
        long pathGeneration;
        boolean connected;
    }

    static String format(Activity activity, AndroidNodeStore nodeStore) {
        try {
            RuntimeState runtime = runtimeState(activity);
            Network vpn = ownedVpnNetwork(activity);
            String signature = signature(vpn, runtime);
            boolean osConnected = vpn != null;
            boolean connected = runtime.connected && osConnected;
            if (!signature.equals(provedSignature)) { provedSignature = ""; provedExit = ""; }
            if ("external".equals(runtime.logical)) return formatExternal(activity,runtime,connected,osConnected);
            if (runtime.logical.startsWith("external-untracked")) return "Node/path: Untracked custom external runtime\nActual public VPN exit: Unproven\nConnection: "+(connected?"VPN engine is UP but unified external-session identity is missing":"not connected")+"\nWarnings: Reconnect this custom exit from the Router VPN Custom Exits screen before trusting identity/proof.";

            JSONObject profile = proofProfile(nodeStore, runtime);
            String exit = connected ? (!provedExit.isEmpty() ? provedExit : "Unproven — tap Prove actual exit") : "Not connected";
            List<String> warnings = new ArrayList<>();
            if (runtime.connected && !osConnected) warnings.add("Stored runtime says connected but Android has no Router VPN-owned VPN network");
            if (connected && provedExit.isEmpty()) warnings.add("Actual public exit is not proven for this live Android VPN network");
            if (runtime.connected && !"multihop".equals(runtime.logical) && runtime.activeNodeId.isEmpty()) warnings.add("Connected session node identity is unavailable; reconnect before trusting node-specific proof");
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
            String proofLabel = "multihop".equals(runtime.logical) ? "active exit-node path proof" : "session node path proof";

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
        } catch (Throwable error) { return "Home state unavailable: " + safe(error); }
    }

    private static String formatExternal(Activity activity,RuntimeState runtime,boolean connected,boolean osConnected){
        String stored=AndroidHomeStateStore.actualExitForCurrentSession(activity);
        String actual=!provedExit.isEmpty()?provedExit:stored;
        List<String>warnings=new ArrayList<>();
        if(runtime.connected&&!osConnected)warnings.add("Stored external session says connected but Android has no Router VPN-owned VPN network");
        if(runtime.expectedExternalIp.isEmpty())warnings.add("Expected custom-exit public IP is missing; reconnect before trusting proof");
        if(connected&&actual.isEmpty())warnings.add("Current external-session public exit is unproven");
        if(!runtime.warning.isEmpty())warnings.add(runtime.warning);
        return "Node/path: Custom external • "+empty(runtime.activeExternalName)+
                "\nProtocol: "+empty(runtime.activeExternalProtocol)+" • path base: "+empty(runtime.base)+
                "\nExpected public VPN exit: "+empty(runtime.expectedExternalIp)+
                "\nActual public VPN exit: "+(connected?(actual.isEmpty()?"Unproven — tap Prove actual exit":actual):"Not connected")+
                "\nConnection: "+(connected?"connected • expected-exit proof passed before Connected":runtime.phase)+
                "\nWarnings: "+(warnings.isEmpty()?"None":String.join(" | ",warnings));
    }

    static void proveActualExit(Activity activity, AndroidNodeStore nodeStore, Callback callback) {
        new Thread(() -> {
            try {
                RuntimeState runtime=runtimeState(activity);
                if("external".equals(runtime.logical)){proveExternalExit(activity,runtime,callback);return;}
                FileProof proof = proofInputs(activity, nodeStore);
                if (!AndroidPathProbe.prove(proof.bundle, 8000)) throw new IllegalStateException(proof.multihop ? "Active multihop exit-node private path proof failed before public-exit test." : "Active session node private path proof failed before public-exit test.");
                String ip = fetchIP(proof.network);
                FileProof after = proofInputs(activity, nodeStore);
                if (!proof.signature.equals(after.signature)) throw new IllegalStateException("Android VPN network/session/runtime or underlying path generation changed while proving public exit; result discarded.");
                if (!AndroidPathProbe.prove(after.bundle, 8000)) throw new IllegalStateException(after.multihop ? "Active multihop exit-node private path proof failed after public-exit test." : "Active session node private path proof failed after public-exit test.");
                provedSignature = after.signature; provedExit = ip;
                AndroidHomeStateStore.saveActualExit(activity, AndroidHomeStateStore.snapshot(activity).sessionId, ip);
                callback.done("Actual public VPN exit proved for this live Router VPN network: " + ip, null);
            } catch (Throwable error) { provedSignature=""; provedExit=""; callback.done("Actual exit proof failed: " + safe(error), error); }
        }, "routervpn-home-exit-proof").start();
    }

    private static void proveExternalExit(Activity activity,RuntimeState before,Callback callback)throws Exception{
        if(!before.connected)throw new IllegalStateException("Custom external exit is not in a proven connected state.");
        if(before.expectedExternalIp.isEmpty())throw new IllegalStateException("Custom external exit has no expected public IP proof target.");
        Network network=ownedVpnNetwork(activity);if(network==null)throw new IllegalStateException("No active Android VPN network owned by Router VPN.");
        String beforeSignature=signature(network,before);String ip=fetchIP(network);
        if(!InetAddress.getByName(ip).equals(InetAddress.getByName(before.expectedExternalIp)))throw new IllegalStateException("Custom exit reached "+ip+", expected "+before.expectedExternalIp+".");
        RuntimeState after=runtimeState(activity);Network afterNetwork=ownedVpnNetwork(activity);if(afterNetwork==null||!beforeSignature.equals(signature(afterNetwork,after)))throw new IllegalStateException("External VPN network/session/path generation changed while proving public exit; result discarded.");
        provedSignature=beforeSignature;provedExit=ip;AndroidHomeStateStore.saveActualExit(activity,AndroidHomeStateStore.snapshot(activity).sessionId,ip);callback.done("Actual custom public VPN exit re-proved for this live session: "+ip,null);
    }

    static void emergencyDisconnect(Activity activity, Callback callback) {
        AndroidHomeStateStore.warning(activity, "Emergency Disconnect requested; verifying every Router VPN transport stops.");
        AndroidRuntimeRegistry runtime=AndroidRuntimeRegistry.get(activity);
        try{runtime.multihop.disconnect();}catch(Throwable ignored){}
        try{runtime.standardExit.disconnect();}catch(Throwable ignored){}
        try{runtime.singBox.stop();}catch(Throwable ignored){}
        try{runtime.xray.stop();}catch(Throwable ignored){}
        try { activity.startService(new Intent(activity, LayeredVpnService.class).setAction(LayeredVpnService.ACTION_STOP)); } catch (Throwable ignored) {}
        try { activity.startService(new Intent(activity, XrayVpnService.class).setAction(XrayVpnService.ACTION_STOP)); } catch (Throwable ignored) {}
        CountDownLatch rawStops=new CountDownLatch(2);
        AtomicBoolean wgDown=new AtomicBoolean(false),awgDown=new AtomicBoolean(false);
        AtomicReference<String> rawFailure=new AtomicReference<>("");
        runtime.wireGuard.disconnect((state,message,error)->{if(error==null&&state==com.wireguard.android.backend.Tunnel.State.DOWN)wgDown.set(true);else rawFailure.compareAndSet("","WireGuard: "+(error==null?message:safe(error)));rawStops.countDown();});
        runtime.amneziaWG.disconnect((state,message,error)->{if(error==null&&state==org.amnezia.awg.backend.Tunnel.State.DOWN)awgDown.set(true);else rawFailure.compareAndSet("","AmneziaWG: "+(error==null?message:safe(error)));rawStops.countDown();});
        provedSignature=""; provedExit="";
        new Thread(() -> {
            try {
                if(!rawStops.await(4, TimeUnit.SECONDS))throw new IllegalStateException("Raw WireGuard/AmneziaWG teardown timed out; session ownership retained.");
                if(!rawFailure.get().isEmpty())throw new IllegalStateException("Raw tunnel teardown failed: "+rawFailure.get());
                if(!wgDown.get()||runtime.wireGuard.getState()!=com.wireguard.android.backend.Tunnel.State.DOWN)throw new IllegalStateException("WireGuard did not prove DOWN during Emergency Disconnect.");
                if(!awgDown.get()||runtime.amneziaWG.getState()!=org.amnezia.awg.backend.Tunnel.State.DOWN)throw new IllegalStateException("AmneziaWG did not prove DOWN during Emergency Disconnect.");
                long deadline=System.currentTimeMillis()+5000L;
                while(System.currentTimeMillis()<deadline){
                    boolean clean=ownedVpnNetwork(activity)==null&&terminalEngineState(runtime.singBox.getState())&&terminalEngineState(runtime.xray.getState())&&!runtime.multihop.isActiveOrTransitioning()&&!runtime.standardExit.isActiveOrTransitioning();
                    if(clean)break;
                    Thread.sleep(150L);
                }
                if(ownedVpnNetwork(activity)!=null)throw new IllegalStateException("A Router VPN-owned Android VPN network is still active after emergency-stop requests.");
                if(!terminalEngineState(runtime.singBox.getState()))throw new IllegalStateException("Libbox did not reach DOWN/FAILED/REVOKED during Emergency Disconnect.");
                if(!terminalEngineState(runtime.xray.getState()))throw new IllegalStateException("Xray did not reach DOWN/FAILED/REVOKED during Emergency Disconnect.");
                if(runtime.multihop.isActiveOrTransitioning())throw new IllegalStateException("Multihop runtime still owns an active/transitioning graph after Emergency Disconnect.");
                if(runtime.standardExit.isActiveOrTransitioning())throw new IllegalStateException("Custom-exit runtime still owns an active/transitioning graph after Emergency Disconnect.");
                AndroidHomeStateStore.disconnected(activity);
                callback.done("Emergency Disconnect completed; all Router VPN engines proved terminal and no Router VPN-owned VPN network remains.", null);
            } catch(Throwable error) { AndroidHomeStateStore.failed(activity, safe(error)); callback.done("Emergency Disconnect incomplete: "+safe(error), error); }
        }, "routervpn-emergency-verify").start();
    }

    private static final class FileProof { final java.io.File bundle; final Network network; final String signature; final boolean multihop; FileProof(java.io.File bundle,Network network,String signature,boolean multihop){this.bundle=bundle;this.network=network;this.signature=signature;this.multihop=multihop;} }
    private static FileProof proofInputs(Activity activity,AndroidNodeStore store)throws Exception{
        RuntimeState runtime=runtimeState(activity); if(!runtime.connected)throw new IllegalStateException("Router VPN runtime is not in a proven connected state.");
        boolean multihop="multihop".equals(runtime.logical);String id=multihop?runtime.activeExitId:runtime.activeNodeId;
        if(id==null||id.isEmpty())throw new IllegalStateException(multihop?"Active multihop exit identity is unavailable.":"Active Router VPN session node identity is unavailable; reconnect before proving exit.");
        java.io.File bundle=store.file(id); if(!bundle.isFile())throw new IllegalStateException(multihop?"Active multihop exit bundle is missing.":"Active session node bundle is missing.");
        Network network=ownedVpnNetwork(activity); if(network==null)throw new IllegalStateException("No active Android VPN network owned by Router VPN.");
        return new FileProof(bundle,network,signature(network,runtime),multihop);
    }

    private static Network ownedVpnNetwork(Context context) {
        ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE); if(cm==null)return null;Network network=cm.getActiveNetwork();if(network==null)return null;NetworkCapabilities caps=cm.getNetworkCapabilities(network);if(caps==null||!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))return null;if(Build.VERSION.SDK_INT<Build.VERSION_CODES.Q)return null;return caps.getOwnerUid()==Process.myUid()?network:null;
    }

    private static RuntimeState runtimeState(Context context){
        RuntimeState out=new RuntimeState();AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
        out.sessionId=home.sessionId;out.activeNodeId=home.activeNodeId;out.activeEntryId=home.activeEntryId;out.activeExitId=home.activeExitId;out.activeExternalId=home.activeExternalId;out.activeExternalName=home.activeExternalName;out.activeExternalProtocol=home.activeExternalProtocol;out.expectedExternalIp=home.expectedExternalIp;out.pathGeneration=home.pathGeneration;
        if(home.connected&&"passed".equals(home.pathProof)){out.connected=true;out.phase=home.phase;out.logical=home.logicalMode;out.runtime=home.runtimeMode;out.base=home.actualBase;out.fallback=home.fallback;out.warning=home.warning;return out;}
        SharedPreferences p=context.getSharedPreferences("router-vpn",Context.MODE_PRIVATE);String layered=p.getString(NativeSingBoxController.STATE_KEY,"DOWN");
        if("UP".equals(layered)){out.connected=false;out.phase="engine-up-unproven";out.logical=home.logicalMode.isEmpty()?p.getString(NativeSingBoxController.MODE_KEY,""):home.logicalMode;out.runtime=p.getString(NativeSingBoxController.MODE_KEY,"");out.base="libbox";out.fallback=home.fallback;out.warning=combineWarnings(home.warning,p.getString(NativeSingBoxController.ERROR_KEY,""),"Libbox engine is UP but no current selected-path proof is passed; Router VPN refuses to call this Connected.");return out;}
        String xray=p.getString(NativeXrayController.STATE_KEY,"DOWN");if("UP".equals(xray)){out.connected=false;out.phase="engine-up-unproven";out.logical=home.logicalMode.isEmpty()?p.getString(NativeXrayController.MODE_KEY,""):home.logicalMode;out.runtime=p.getString(NativeXrayController.MODE_KEY,"");out.base="xray";out.fallback=home.fallback;out.warning=combineWarnings(home.warning,p.getString(NativeXrayController.ERROR_KEY,""),"Xray engine is UP but no current selected-path proof is passed; Router VPN refuses to call this Connected.");return out;}out.phase=home.phase;out.logical=home.logicalMode;out.runtime=home.runtimeMode;out.base=home.actualBase;out.fallback=home.fallback;out.warning=home.connected?combineWarnings(home.warning,"Stored Connected state has no current passed path proof; Router VPN refuses to adopt it."):home.warning;return out;
    }

    private static boolean terminalEngineState(String state){if(state==null)return false;String normalized=state.trim().toUpperCase(Locale.ROOT);return "DOWN".equals(normalized)||"FAILED".equals(normalized)||"REVOKED".equals(normalized);}
    private static String combineWarnings(String... values){List<String>parts=new ArrayList<>();if(values!=null)for(String value:values){String cleaned=value==null?"":value.replace('\n',' ').replace('\r',' ').trim();if(!cleaned.isEmpty())parts.add(cleaned);}return String.join(" | ",parts);}
    private static String signature(Network network,RuntimeState runtime){return network==null?"":network.getNetworkHandle()+"|session="+runtime.sessionId+"|"+runtime.logical+"|"+runtime.runtime+"|"+runtime.base+"|"+runtime.activeNodeId+"|"+runtime.activeEntryId+"|"+runtime.activeExitId+"|"+runtime.activeExternalId+"|"+runtime.expectedExternalIp+"|path="+runtime.pathGeneration;}
    private static String fetchIP(Network network)throws Exception{for(String raw:new String[]{"https://api64.ipify.org","https://api.ipify.org"}){HttpURLConnection c=null;try{c=(HttpURLConnection)network.openConnection(new URL(raw));c.setConnectTimeout(6000);c.setReadTimeout(6000);c.setUseCaches(false);if(c.getResponseCode()/100!=2)continue;byte[]data=readLimited(c.getInputStream(),128);String value=new String(data,StandardCharsets.UTF_8).trim();if(value.matches("[0-9A-Fa-f:.]+")){InetAddress.getByName(value);return value;}}catch(Throwable ignored){}finally{if(c!=null)c.disconnect();}}throw new IllegalStateException("Could not determine public VPN exit through the active Router VPN network.");}
    private static JSONObject proofProfile(AndroidNodeStore store,RuntimeState runtime)throws Exception{String id;if(runtime.connected){id="multihop".equals(runtime.logical)?runtime.activeExitId:runtime.activeNodeId;}else{id=store.activeId();}if(id==null||id.isEmpty())throw new IllegalStateException(runtime.connected?"Active session node identity is unavailable.":"Pair/import and select a Router VPN node first.");return AndroidUnifiedNodeCatalog.selectedProfile(store.file(id));}
    private static String nodeName(AndroidNodeStore store,String id){try{JSONObject p=AndroidUnifiedNodeCatalog.selectedProfile(store.file(id));String name=p.optString("name",id).trim();return name.isEmpty()?id:name;}catch(Throwable ignored){return id==null||id.isEmpty()?"unknown":id;}}
    private static double measuredDnsRtt(JSONObject p,String host){JSONArray a=p.optJSONArray("dns_results");if(a!=null)for(int i=0;i<a.length();i++){JSONObject r=a.optJSONObject(i);if(r!=null&&r.optBoolean("working")&&host.equals(r.optString("address")))return r.optDouble("latency_ms",0);}return p.optDouble("fastest_dns_latency_ms",0);}
    private static String killSwitch(JSONObject p){String value=p.optString("kill_switch_policy","").trim();if(!value.isEmpty())return value;return p.optBoolean("kill_switch",false)?"strict":"off";}
    private static String inferredBase(String runtime){if(runtime==null)return"";if(runtime.startsWith("awg"))return"awg";if("wg".equals(runtime)||runtime.contains("-wg"))return"wg";if(!runtime.isEmpty())return"embedded";return"";}
    private static String empty(String value){return value==null||value.isEmpty()?"—":value;}
    private static byte[] readLimited(InputStream input,int max)throws Exception{try(InputStream in=input;ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]b=new byte[128];int n,total=0;while((n=input.read(b))!=-1){total+=n;if(total>max)throw new IllegalStateException("Public-exit response exceeded safety limit.");out.write(b,0,n);}return out.toByteArray();}}
    private static String safe(Throwable e){String v=e==null?"":e.getMessage();return v==null||v.trim().isEmpty()?"Router VPN error":v.replace('\n',' ').replace('\r',' ').trim();}
    private AndroidHomeSummary(){}
}
