package com.eabusham.routervpn;

import android.content.Context;
import org.json.JSONObject;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

/** Immutable current Router path, complete private sources, native owner and OS route. */
final class AndroidTelemetryCapture {
    final AndroidTelemetryNetwork route;
    final JSONObject bundle,profile;
    final String nodeId,proofId,api,token,signature;
    private final Context context;
    private final AndroidNodeStore store;
    private final Map<String,String> sources=new LinkedHashMap<>();
    private final Map<String,File> files=new LinkedHashMap<>();

    private AndroidTelemetryCapture(Context context,AndroidNodeStore store)throws Exception{
        this.context=context.getApplicationContext();this.store=store;
        AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);requireProved(home);
        signature=signature(home);nodeId="multihop".equals(home.logicalMode)?home.activeExitId:home.activeNodeId;
        if(nodeId.isEmpty())throw new IllegalStateException("The current Router VPN node identity is unavailable.");
        byte[] raw=capture(nodeId);if(!home.activeEntryId.isEmpty()&&!home.activeEntryId.equals(nodeId))capture(home.activeEntryId);
        bundle=new JSONObject(new String(raw,StandardCharsets.UTF_8));profile=AndroidProfileSelection.selectedRouterProfile(bundle);
        if(profile==null)throw new IllegalStateException("The captured Router profile is unavailable.");
        proofId=AndroidNodeStore.stableNodeIdentity(bundle);
        api=profile.optString("router_api",bundle.optString("routerAPI","")).trim();
        token=profile.optString("api_token",bundle.optString("apiToken","")).trim();
        AndroidRuntimeRegistry engines=AndroidRuntimeRegistry.get(context);
        ArrayList<AndroidTelemetryNetwork> candidates=new ArrayList<>();
        if("UP".equals(engines.singBox.getState()))candidates.add(LayeredVpnService.captureTelemetryNetwork());
        if("UP".equals(engines.xray.getState()))candidates.add(XrayVpnService.captureTelemetryNetwork());
        if(engines.wireGuard.getState()==com.wireguard.android.backend.Tunnel.State.UP)candidates.add(engines.wireGuard.captureTelemetryNetwork());
        if(engines.amneziaWG.getState()==org.amnezia.awg.backend.Tunnel.State.UP)candidates.add(engines.amneziaWG.captureTelemetryNetwork());
        if(candidates.size()!=1||candidates.get(0)==null)throw new IllegalStateException("The current path does not have one unambiguous retained native VPN owner.");
        route=candidates.get(0);requireCurrent();
    }
    static AndroidTelemetryCapture current(Context context,AndroidNodeStore store)throws Exception{return new AndroidTelemetryCapture(context,store);}
    private byte[] capture(String id)throws Exception{
        File file=store.file(id).getCanonicalFile();byte[] raw=AndroidPrivateFileStore.read(file,AndroidNodeStore.MAX_BUNDLE);
        files.put(id,file);sources.put(id,AndroidTelemetryNetwork.digest(raw));return raw;
    }
    void check()throws Exception{
        AndroidHomeStateStore.Snapshot now=AndroidHomeStateStore.snapshot(context);requireProved(now);
        if(!signature.equals(signature(now)))throw new IllegalStateException("The Router VPN session or path generation changed; telemetry was discarded.");
        route.check();
    }
    void requireCurrent()throws Exception{
        check();
        for(Map.Entry<String,String> captured:sources.entrySet()){
            File current=store.file(captured.getKey()).getCanonicalFile();
            if(!files.get(captured.getKey()).equals(current)||!captured.getValue().equals(AndroidTelemetryNetwork.digest(AndroidPrivateFileStore.read(current,AndroidNodeStore.MAX_BUNDLE))))
                throw new IllegalStateException("A complete captured Router source changed; telemetry was discarded.");
        }
        check();
    }
    private static void requireProved(AndroidHomeStateStore.Snapshot home){
        if(!home.connected||!"connected".equals(home.phase)||!"passed".equals(home.pathProof)||home.sessionId.isEmpty()||"external".equals(home.logicalMode)||!home.activeExternalId.isEmpty())
            throw new IllegalStateException("Connect a proved Router VPN path before measuring its private RTT or speed.");
    }
    private static String signature(AndroidHomeStateStore.Snapshot home){return home.sessionId+"|"+home.pathGeneration+"|"+home.logicalMode+"|"+home.runtimeMode+"|"+home.actualBase+"|"+home.activeNodeId+"|"+home.activeEntryId+"|"+home.activeEntryMode+"|"+home.activeExitId+"|"+home.activeExternalId;}
}
