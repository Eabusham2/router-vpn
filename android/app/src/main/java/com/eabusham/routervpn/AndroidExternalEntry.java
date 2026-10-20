package com.eabusham.routervpn;

import android.content.Context;
import io.nekohasekai.libbox.Libbox;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;

/** Captures a complete native Router VPN entry and its owned helper lifecycle. */
final class AndroidExternalEntry implements AutoCloseable {
    final JSONObject profile;
    final String config;
    final AndroidStartLayer.RelayPlan relay;
    final AndroidMAXProfilePreparation maxPreparation;
    private boolean staged;

    private AndroidExternalEntry(JSONObject profile, String config, AndroidStartLayer.RelayPlan relay,
            AndroidMAXProfilePreparation maxPreparation) {
        this.profile=profile;this.config=config;this.relay=relay;this.maxPreparation=maxPreparation;
    }

    static AndroidExternalEntry prepare(Context context, File sourceFile, JSONObject bundle, String mode) throws Exception {
        if(!NativeSingBoxController.nativeMultihopEntry(mode))throw new IllegalArgumentException("Choose the exact native Router VPN entry mode.");
        AndroidNodeStore.validateBundle(bundle);
        if(bundle.optString("selectedRouterID",bundle.optString("selected_id","")).trim().isEmpty())throw new IllegalArgumentException("Select the exact Router VPN entry profile.");
        JSONObject profile=new JSONObject(AndroidProfileSelection.selectedRouterProfile(bundle).toString());
        String node=AndroidNodeStore.stableNodeIdentity(bundle);
        if(!node.matches("[0-9a-f]{64}")||!node.equals(profile.optString("node_proof_id"))||!"router-vpn".equals(profile.optString("node_kind")))throw new IllegalArgumentException("The captured entry lost its Router VPN node identity.");
        JSONObject assets=bundle.getJSONObject("profiles").getJSONObject(mode);
        AndroidMAXProfilePreparation max=null;
        AndroidStartLayer.RelayPlan relay=null;
        try{
            JSONObject graph;
            if(AndroidNativeMAXProfile.isMode(mode)){
                AndroidMAXProfilePreparation.Source source=new AndroidMAXProfilePreparation.Source(sourceFile,bundle,mode);
                max=AndroidMAXProfilePreparation.begin(context,source);
                graph=new JSONObject(max==null?AndroidNativeMAXProfile.compile(bundle,assets,mode):max.compile(source));
            }else if(AndroidNativeCompositeProfile.isMode(mode)){
                graph=new JSONObject(AndroidNativeCompositeProfile.compile(bundle,assets,mode));
            }else{
                graph=new JSONObject(AndroidStartLayer.nativeXray(mode)?AndroidXrayLibboxPolicy.resolve(bundle,assets,mode)
                        :NativeSingBoxController.compileStandaloneProfile(bundle,assets,mode));
            }
            if("hysteria2".equals(mode)||"shadowsocks".equals(mode)){
                JSONObject inline=new JSONObject(Libbox.routerCompileProxyEntry(assets.toString(),mode));
                if(!mode.equals(inline.getString("type"))||inline.has("detour"))throw new IllegalStateException("The entry lost its exact proxy transport.");
                JSONArray outputs=graph.getJSONArray("outbounds");int found=0;
                for(int i=0;i<outputs.length();i++)if("proxy".equals(outputs.getJSONObject(i).optString("tag"))){outputs.put(i,inline.put("tag","proxy"));found++;}
                if(found!=1)throw new IllegalStateException("The entry requires one captured proxy owner.");
            }
            NativeSingBoxController.applySelectedDns(bundle,graph);
            if(AndroidStartLayer.nativeXray(mode)&&!AndroidNativeCompositeProfile.isMode(mode))AndroidXrayLibboxPolicy.normalizeDnsRoutes(graph);
            if(!AndroidNativeMAXProfile.isMode(mode)&&!AndroidNativeCompositeProfile.isMode(mode))relay=AndroidStartLayer.apply(bundle,graph,mode);
            if(relay!=null){
                // The pinned native AES+XOR engine owns this same authenticated
                // transport directly; the imported graph needs no local relay.
                JSONArray outputs=graph.getJSONArray("outbounds");int replaced=0;
                for(int i=0;i<outputs.length();i++){
                    JSONObject output=outputs.getJSONObject(i);
                    if("shadowsocks".equals(output.optString("type"))&&"127.0.0.1".equals(output.optString("server"))
                            &&output.optInt("server_port",0)==AndroidStartLayerRelay.LISTEN_PORT){
                        if(output.has("detour")||!AndroidStartLayer.AES_METHOD.equals(output.getString("method")))throw new IllegalStateException("The Start Layer relay lost its exact AES owner.");
                        output.put("type","routervpn-aes-xor").put("server",relay.targetHost).put("server_port",AndroidStartLayerRelay.SERVER_PORT);replaced++;
                    }
                }
                if(replaced!=1)throw new IllegalStateException("The captured Start Layer requires one native AES+XOR owner.");
                relay.clear();relay=null;
            }
            graph=NativeSingBoxController.applyPerformance(bundle,graph);
            if(max!=null)max.verify();
            return new AndroidExternalEntry(profile,graph.toString(),relay,max);
        }catch(Throwable failure){
            if(relay!=null)relay.clear();
            if(max!=null)max.close();
            throw failure;
        }
    }

    void stage(File folder,String session,String mode,String graph)throws Exception{
        if(relay!=null)AndroidPrivateFileStore.write(new File(folder,AndroidStartLayerRelay.SESSION_FILE),relay.metadata().toString().getBytes(java.nio.charset.StandardCharsets.UTF_8),16384);
        if(maxPreparation!=null)maxPreparation.stage(folder,session,mode,graph);
        staged=true;
    }

    @Override public void close(){
        if(relay!=null)relay.clear();
        if(maxPreparation!=null&&!staged)maxPreparation.close();
    }
}
