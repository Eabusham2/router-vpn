package com.eabusham.routervpn;

import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterNodeChainCandidatePreparation;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/** One immutable packet-prefix purpose. Configured MTU bounds are not measured
 * MTU, and private prefix proofs never authorize Connected or application DNS. */
final class AndroidNodeCandidatePrefixCapture implements AutoCloseable {
    final RouterNodeChainCandidatePreparation plan;
    final AndroidNodeChainCapture original;
    final String launchInput, config, metadata, inventory;
    final String sourceSHA256, configSHA256, captureSHA256;
    final int prefix, originalMTU, ceilingMTU;
    final String tunTag;

    static AndroidNodeCandidatePrefixCapture compile(AndroidNodeChainCapture original,int prefix,String inventory)throws Exception {
        requireSource(original,prefix,inventory);
        RouterNodeChainCandidatePreparation plan=Libbox.newRouterNodeChainCandidatePreparation(original.sourceInput,prefix,inventory);
        try{return new AndroidNodeCandidatePrefixCapture(original,prefix,inventory,plan);}
        catch(Exception failed){if(plan!=null)try{plan.close();}catch(Exception cleanup){failed.addSuppressed(cleanup);}throw failed;}
    }

    /** Reopening uses the strict native parser. No receipt is stripped into a
     * different constructor input, and the saved full source stays independent. */
    static AndroidNodeCandidatePrefixCapture reopen(String input,AndroidNodeChainCapture original,int prefix,String inventory)throws Exception {
        requireSource(original,prefix,inventory);bounded(input,AndroidNodeChainCapture.MAX_INPUT);
        RouterNodeChainCandidatePreparation plan=Libbox.routerNodeChainCandidatePreparationLaunch(input);
        try{
            AndroidNodeCandidatePrefixCapture capture=new AndroidNodeCandidatePrefixCapture(original,prefix,inventory,plan);
            if(!input.equals(capture.launchInput))throw invalid();
            return capture;
        }catch(Exception failed){if(plan!=null)try{plan.close();}catch(Exception cleanup){failed.addSuppressed(cleanup);}throw failed;}
    }

    private static void requireSource(AndroidNodeChainCapture original,int prefix,String inventory)throws Exception {
        if(original==null||original.socks!=null||!"local".equals(original.selectionExecution)||prefix<0||prefix>=original.memberInputs.size()-1)throw invalid();
        original.requireCurrent();bounded(inventory,AndroidNodeChainCapture.MAX_INPUT);
        for(int i=0;i<=prefix;i++)if(!packetMode(new JSONObject(original.memberInputs.get(i)).getString("mode")))throw invalid();
    }

    private AndroidNodeCandidatePrefixCapture(AndroidNodeChainCapture original,int prefix,String inventory,RouterNodeChainCandidatePreparation plan)throws Exception {
        requireSource(original,prefix,inventory);if(plan==null)throw invalid();
        this.original=original;this.prefix=prefix;this.inventory=inventory;this.plan=plan;
        launchInput=bounded(plan.launchInput(),AndroidNodeChainCapture.MAX_INPUT);
        config=bounded(plan.config(),4*1024*1024);metadata=bounded(plan.metadata(),64*1024);
        sourceSHA256=plan.sourceSHA256();configSHA256=plan.configSHA256();captureSHA256=plan.captureSHA256();
        JSONObject source=new JSONObject(launchInput),meta=new JSONObject(metadata),graph=new JSONObject(config);
        if(!"routervpn-node-chain-candidate-preparation".equals(source.getString("kind"))||integer(source,"schema")!=1
                ||integer(source,"prefix_position")!=prefix||!inventory.equals(source.getString("inventory"))
                ||integer(meta,"schema")!=1||integer(meta,"prefix_position")!=prefix
                ||!sourceSHA256.equals(meta.getString("source_sha256"))||!configSHA256.equals(meta.getString("config_sha256"))
                ||!captureSHA256.equals(meta.getString("capture_sha256"))||!digest(sourceSHA256)||!digest(configSHA256)||!digest(captureSHA256)
                ||!configSHA256.equals(AndroidTorProfile.digest(config.getBytes(StandardCharsets.UTF_8)))
                ||!original.sourceSHA256.equals(plan.originalSourceSHA256())||!original.sourceSHA256.equals(meta.getString("original_source_sha256"))
                ||!Boolean.FALSE.equals(meta.get("application_open"))||!Boolean.FALSE.equals(meta.get("dns_open"))||!Boolean.FALSE.equals(meta.get("ready"))
                ||!"pending-prefix-proof".equals(meta.getString("stage"))||!"configured-bounds-only".equals(meta.getString("mtu_measurement")))throw invalid();
        JSONArray proofs=meta.getJSONArray("prefixes"),targets=meta.getJSONArray("targets");
        if(proofs.length()!=prefix+1||targets.length()<1||targets.length()>64)throw invalid();
        Set<String> ids=new HashSet<>();
        for(int i=0;i<targets.length();i++){
            JSONObject target=targets.getJSONObject(i);String id=target.getString("id");
            if(id.isEmpty()||id.length()>128||!ids.add(id)||!digest(target.getString("source_sha256")))throw invalid();
        }
        for(int i=0;i<proofs.length();i++){
            JSONObject proof=proofs.getJSONObject(i),member=new JSONObject(original.memberInputs.get(i));
            JSONObject profile=new JSONObject(member.getString("profile_json"));String layer=profile.optString("start_layer","off");if(layer.isEmpty())layer="off";
            if(integer(proof,"position")!=i||!profile.getString("id").equals(proof.getString("profile_id"))
                    ||!profile.getString("node_proof_id").equals(proof.getString("node_id"))||!member.getString("mode").equals(proof.getString("mode"))
                    ||!layer.equals(proof.getString("start_layer"))||!member.getString("source_sha256").equals(proof.getString("source_sha256"))
                    ||proof.getString("tag").isEmpty())throw invalid();
        }
        if(!proofs.getJSONObject(prefix).getString("profile_id").equals(meta.getString("prefix_id")))throw invalid();
        JSONObject mtu=meta.getJSONObject("mtu");originalMTU=integer(mtu,"original");ceilingMTU=integer(mtu,"ceiling");tunTag=mtu.getString("tun_tag");
        JSONArray inbounds=graph.getJSONArray("inbounds"),bounds=mtu.getJSONArray("prefixes");
        if(originalMTU<1280||originalMTU>9000||ceilingMTU<originalMTU||ceilingMTU>9000||tunTag.isEmpty()
                ||inbounds.length()!=1||bounds.length()!=proofs.length())throw invalid();
        JSONObject tun=inbounds.getJSONObject(0);
        if(!"tun".equals(tun.getString("type"))||!tunTag.equals(tun.getString("tag"))||integer(tun,"mtu")!=originalMTU)throw invalid();
        int minimum=9000;
        for(int i=0;i<bounds.length();i++){
            JSONObject bound=bounds.getJSONObject(i);int ceiling=integer(bound,"ceiling");
            if(integer(bound,"position")!=i||!proofs.getJSONObject(i).getString("tag").equals(bound.getString("tag"))||ceiling<originalMTU||ceiling>9000)throw invalid();
            minimum=Math.min(minimum,ceiling);
        }
        if(ceilingMTU!=minimum)throw invalid();
        original.requireCurrent();
    }

    void requireCurrent()throws Exception {original.requireCurrent();}
    @Override public void close()throws Exception {plan.close();}
    private static boolean packetMode(String mode){return "wg".equals(mode)||"awg2-fast".equals(mode)||"awg2-strong".equals(mode);}
    private static boolean digest(String value){return value!=null&&value.matches("[0-9a-f]{64}");}
    private static int integer(JSONObject value,String key)throws Exception {
        Object raw=value.get(key);if(!(raw instanceof Number))throw invalid();
        double number=((Number)raw).doubleValue();int exact=((Number)raw).intValue();
        if(!Double.isFinite(number)||number!=exact||exact<0||exact>9000)throw invalid();return exact;
    }
    private static String bounded(String value,int limit){if(value==null||value.isEmpty()||value.getBytes(StandardCharsets.UTF_8).length>limit)throw invalid();return value;}
    private static IllegalStateException invalid(){return new IllegalStateException("The original saved source, selected packet prefix or closed test policy could not be reproduced.");}
}
