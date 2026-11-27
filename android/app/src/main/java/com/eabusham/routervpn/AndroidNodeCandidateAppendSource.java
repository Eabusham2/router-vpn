package com.eabusham.routervpn;

import android.content.Context;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterNodeChainCandidateAppendSource;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Source-only capture of a real unfinished prefix. The separately selected
 * control supplies device policy, never a fabricated route member or final. */
final class AndroidNodeCandidateAppendSource {
    final RouterNodeChainCandidateAppendSource plan;
    final AndroidNodeStore.ChainCapture original;
    final AndroidDeviceMTU deviceMTU;
    final String source,config,metadata,sourceSHA256,configSHA256;
    final List<String> memberInputs,identityInputs;
    final boolean strict,homeLANAccess;
    private final Context context;

    AndroidNodeCandidateAppendSource(Context context,AndroidNodeStore.ChainCapture original)throws Exception {
        if(original==null||!original.appendDraft()||!"local".equals(original.execution))
            throw invalid();
        this.context=context.getApplicationContext();this.original=original;
        original.requireCurrent();deviceMTU=AndroidDeviceMTU.capture(this.context);
        List<String> inputs=new ArrayList<>(),identities=new ArrayList<>();
        boolean protect=false,lan=true;
        List<AndroidNodeStore.ChainSource> policySources=new ArrayList<>();policySources.add(original.control);policySources.addAll(original.members);
        for(AndroidNodeStore.ChainSource member:policySources) {
            JSONObject profile=member.profile();
            String policy=profile.optString("kill_switch_policy",profile.optBoolean("kill_switch",false)?"on-connect":"off");
            if(!List.of("off","on-connect","always").contains(policy))throw invalid();
            protect|=!"off".equals(policy)||profile.optBoolean("kill_switch",false);
            lan&=profile.optBoolean("home_lan_access",true);
        }
        int sourceSchema=1;
        for(int i=0;i<original.members.size();i++) {
            AndroidNodeStore.ChainSource member=original.members.get(i);String mode=original.modes.get(i);
            requirePrefixMember(member,mode,i);
            if(member.imported||"shadowsocks".equals(mode))sourceSchema=2;
            inputs.add(AndroidNodeChainCapture.memberInput(member,mode,member.profile()));
            identities.add(AndroidNodeChainCapture.identityInput(member));
        }
        // The original control's standard device source is captured separately.
        // Its WireGuard transport and credentials are never inserted or dialled.
        String device=AndroidNodeChainCapture.memberInput(original.control,"wg",original.control.profile());
        JSONObject input=new JSONObject().put("kind","routervpn-node-chain-candidate-append-source").put("schema",sourceSchema)
                .put("execution","local").put("draft_revision",original.appendRevision)
                .put("device_revision",original.deviceRevision()).put("device_source",device)
                .put("next_mode",original.appendMode).put("append_position",inputs.size())
                .put("nodes",new JSONArray(inputs)).put("identity_sources",new JSONArray(identities));
        if(!deviceMTU.revision.isEmpty())input.put("device_mtu_revision",deviceMTU.revision);
        if(deviceMTU.value!=0)input.put("device_fixed_mtu",deviceMTU.value);
        String request=input.toString();
        if(request.getBytes(StandardCharsets.UTF_8).length>AndroidNodeChainCapture.MAX_INPUT)throw invalid();
        plan=Libbox.newRouterNodeChainCandidateAppendSource(request);
        if(plan==null)throw invalid();
        source=bounded(plan.source(),AndroidNodeChainCapture.MAX_INPUT);
        config=bounded(plan.config(),4*1024*1024);metadata=bounded(plan.metadata(),256*1024);
        sourceSHA256=plan.sourceSHA256();configSHA256=plan.configSHA256();
        JSONObject returned=new JSONObject(source),meta=new JSONObject(metadata),deviceRecord=new JSONObject(device);
        if(!"routervpn-node-chain-candidate-append-source".equals(returned.getString("kind"))
                ||returned.getInt("schema")!=sourceSchema||!"local".equals(returned.getString("execution"))
                ||!original.appendRevision.equals(returned.getString("draft_revision"))
                ||!original.deviceRevision().equals(returned.getString("device_revision"))
                ||!device.equals(returned.getString("device_source"))
                ||!original.appendMode.equals(returned.getString("next_mode"))
                ||returned.getInt("append_position")!=inputs.size()
                ||!new JSONArray(inputs).toString().equals(returned.getJSONArray("nodes").toString())
                ||!new JSONArray(identities).toString().equals(returned.getJSONArray("identity_sources").toString())
                ||!deviceMTU.revision.equals(returned.optString("device_mtu_revision",""))
                ||deviceMTU.value!=returned.optInt("device_fixed_mtu",0)
                ||!original.appendMode.equals(plan.candidateMode())||plan.appendPosition()!=inputs.size()
                ||!sourceSHA256.matches("[0-9a-f]{64}")||!configSHA256.equals(digest(config))
                ||!"draft-prefix-append".equals(meta.getString("purpose"))||meta.getInt("schema")!=1
                ||!sourceSHA256.equals(meta.getString("source_sha256"))||!configSHA256.equals(meta.getString("config_sha256"))
                ||!deviceRecord.getString("source_sha256").equals(meta.getString("device_source_sha256"))
                ||!original.appendRevision.equals(meta.getString("draft_revision"))
                ||!original.deviceRevision().equals(meta.getString("device_revision"))
                ||!deviceMTU.revision.equals(meta.getString("device_mtu_revision"))
                ||!original.appendMode.equals(meta.getString("candidate_mode"))
                ||meta.getInt("append_position")!=inputs.size()||meta.getInt("prefix_position")!=inputs.size()-1
                ||!Boolean.FALSE.equals(meta.get("application_open"))||!Boolean.FALSE.equals(meta.get("dns_open"))
                ||!Boolean.FALSE.equals(meta.get("ready")))throw invalid();
        memberInputs=Collections.unmodifiableList(inputs);identityInputs=Collections.unmodifiableList(identities);
        strict=protect;homeLANAccess=lan;requireCurrent();
    }

    // Eligibility is specific to an unfinished append source. The shared
    // constructor remains the authority for whole-prefix closures and keys.
    static boolean permitsPrefixMember(AndroidNodeStore.ChainSource member,String mode,int position) {
        try {
            if(member==null||position<0)return false;
            boolean packet=List.of("wg","awg2-fast","awg2-strong").contains(mode);
            if(position==0&&(member.imported||!packet))return false;
            if(member.imported) {
                if(!"shadowsocks".equals(mode))return false;
                AndroidNodeChainCapture.requireLiteralImportedSS(member);
                return true;
            }
            if(!packet&&!"shadowsocks".equals(mode))return false;
            member.requirePairedIdentity();
            if("shadowsocks".equals(mode)&&!List.of("","off").contains(member.profile().optString("start_layer","off")))return false;
            JSONObject asset=member.bundle().getJSONObject("profiles").optJSONObject(mode);
            return asset!=null&&asset.length()>0;
        } catch(Exception unavailable) {return false;}
    }
    static void requirePrefixMember(AndroidNodeStore.ChainSource member,String mode,int position)throws Exception {
        if(!permitsPrefixMember(member,mode,position))throw new IllegalStateException(
                "Keep the original paired packet entry and supported packet or literal Shadowsocks 2022 prefix members.");
        // Imported sources use their original external capture and empty paired
        // identity companion; they never acquire a Router pairing identity.
        AndroidNodeChainCapture.memberInput(member,mode,member.profile());
    }

    void requireCurrent()throws Exception {
        original.requireCurrent();deviceMTU.requireCurrent(context);
        if(!source.equals(plan.source())||!sourceSHA256.equals(plan.sourceSHA256())
                ||!configSHA256.equals(plan.configSHA256())||!metadata.equals(plan.metadata()))throw invalid();
    }
    boolean fits(String input)throws Exception {requireCurrent();return Libbox.routerNodeChainCandidateAppendInputFitsSource(plan,input);}
    private static String bounded(String value,int max)throws Exception {
        if(value==null||value.isEmpty()||value.getBytes(StandardCharsets.UTF_8).length>max)throw invalid();
        Libbox.routerValidatePrivateNodeJSON(value);return value;
    }
    private static String digest(String value)throws Exception {return AndroidTorProfile.digest(value.getBytes(StandardCharsets.UTF_8));}
    private static IllegalStateException invalid(){return new IllegalStateException("The unfinished prefix lost its original draft or independent device policy.");}
}
