package com.eabusham.routervpn;

import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterNodeChainCandidatePreparation;
import io.nekohasekai.libbox.RouterNodeChainCandidateAppendExecutionPreparation;
import io.nekohasekai.libbox.RouterNodeChainCandidateAppendExecutionSource;
import io.nekohasekai.libbox.RouterNodeChainCandidateCatalog;
import io.nekohasekai.libbox.CommandServer;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/** One immutable packet-prefix purpose. Configured MTU bounds are not measured
 * MTU, and private prefix proofs never authorize Connected or application DNS. */
final class AndroidNodeCandidatePrefixCapture implements AutoCloseable {
    /** Exactly one native purpose owns the original CommandServer. Neither
     * alternative can borrow a complete selected-route preparation. */
    static final class NativePlan {
        private final RouterNodeChainCandidatePreparation local;
        private final RouterNodeChainCandidateAppendExecutionPreparation execution;
        private final RouterNodeChainCandidateAppendExecutionSource executionSource;
        private final String capturedInput;
        private NativePlan(RouterNodeChainCandidatePreparation value) {
            if(value==null)throw invalid();local=value;execution=null;executionSource=null;capturedInput="";
        }
        private NativePlan(RouterNodeChainCandidateAppendExecutionPreparation value,RouterNodeChainCandidateAppendExecutionSource source) {
            if(value==null||source==null)throw invalid();local=null;execution=value;executionSource=source;capturedInput=source.source();
        }
        static NativePlan execution(AndroidNodeChainCapture original,String inventory,String launch)throws Exception {
            if(original.append==null||!original.append.original.appendExecutionDraft())throw invalid();
            String input=new JSONObject().put("kind","routervpn-node-chain-append-execution-source").put("schema",1)
                    .put("execution",original.append.original.appendExecution).put("local_source",original.append.source).put("inventory",inventory).toString();
            RouterNodeChainCandidateAppendExecutionSource source=Libbox.newRouterNodeChainCandidateAppendExecutionSource(input);
            if(source==null)throw invalid();
            RouterNodeChainCandidateAppendExecutionPreparation value=launch==null
                    ?Libbox.newRouterNodeChainCandidateAppendExecutionPreparation(source.source())
                    :Libbox.routerNodeChainCandidateAppendExecutionPreparationLaunch(launch);
            // Retain the original returned preparation before any readback can fail.
            try {NativePlan result=new NativePlan(value,source);result.requireSource(original,inventory);return result;}
            catch(Exception failure){if(value!=null)try{value.close();}catch(Exception cleanup){failure.addSuppressed(cleanup);}throw failure;}
        }
        boolean executionPurpose(){return execution!=null;}
        String requestedExecution(){return execution==null?"local":execution.execution();}
        String config(){return execution==null?local.config():execution.config();}
        String launchInput(){return execution==null?local.launchInput():execution.launchInput();}
        String sourceSHA256(){return execution==null?local.sourceSHA256():execution.sourceSHA256();}
        String originalSourceSHA256(){return execution==null?local.originalSourceSHA256():execution.originalSourceSHA256();}
        String configSHA256(){return execution==null?local.configSHA256():execution.configSHA256();}
        String captureSHA256(){return execution==null?local.captureSHA256():execution.captureSHA256();}
        String metadata(){return execution==null?local.metadata():execution.metadata();}
        String metadataPage(int offset){return execution==null?local.metadataPage(offset):execution.metadataPage(offset);}
        String appendSourceMetadata(){return execution==null?local.appendSourceMetadata():execution.appendSourceMetadata();}
        boolean isAppend(){return execution!=null||local.isAppend();}
        long appendPosition(){return execution==null?local.appendPosition():execution.appendPosition();}
        String candidateMode(){return execution==null?local.candidateMode():execution.candidateMode();}
        String candidateKind(){return execution==null?local.candidateKind():execution.candidateKind();}
        String candidateMeasurement(){return execution==null?local.candidateMeasurement():execution.candidateMeasurement();}
        void bindNative(CommandServer server)throws Exception{if(execution==null)local.bindNative(server);else execution.bindNative(server);}
        void run(CommandServer server,RouterNodeChainCandidateCatalog catalog)throws Exception{if(execution==null)local.run(server,catalog);else execution.run(server,catalog);}
        boolean healthy(){
            if(execution==null)return local.healthy();
            try {if(!execution.healthy())return false;requireProgress(execution.progressJSON(),true);return true;}
            catch(Exception unavailable){return false;}
        }
        String progressJSON()throws Exception {
            if(execution==null)return local.progressJSON();
            String raw=execution.progressJSON();requireProgress(raw,false);return raw;
        }
        private void requireProgress(String raw,boolean prepared)throws Exception {
            JSONObject state=new JSONObject(bounded(raw,32*1024));
            exactKeys(state,"stage","purpose","requested_execution","prepared","prefixes","application_open","dns_open","execution_source_sha256","execution_capture_sha256");
            String capture=state.getString("execution_capture_sha256"), stage=state.getString("stage");
            if(!Set.of("pending-prefix-proof","pending-prefix-discovery","append-execution-prepared","append-execution-failed","append-execution-retired").contains(stage)
                    ||Boolean.TRUE.equals(state.get("prepared"))!="append-execution-prepared".equals(stage)
                    ||!"draft-prefix-append-execution".equals(state.getString("purpose"))||!requestedExecution().equals(state.getString("requested_execution"))
                    ||!sourceSHA256().equals(state.getString("execution_source_sha256"))||!captureSHA256().equals(capture)
                    ||!capture.isEmpty()&&!digest(capture)||!(state.get("prepared") instanceof Boolean)
                    ||prepared&&!Boolean.TRUE.equals(state.get("prepared"))||state.getBoolean("prepared")&&!digest(capture)
                    ||!Boolean.FALSE.equals(state.get("application_open"))||!Boolean.FALSE.equals(state.get("dns_open"))
                    ||state.getJSONArray("prefixes").length()>appendPosition())throw invalid();
        }
        void start(String request,String candidate)throws Exception{if(execution==null)local.start(request,candidate);else execution.start(request,candidate);}
        void cancel(String request){if(execution==null)local.cancel(request);else execution.cancel(request);}
        void drain(String request)throws Exception{if(execution==null)local.drain(request);else execution.drain(request);}
        String statusJSON(){return execution==null?local.statusJSON():execution.statusJSON();}
        String selectionJSON(){return execution==null?"":execution.selectionJSON();}
        void networkChanged(){if(execution==null)local.networkChanged();else execution.networkChanged();}
        boolean nativeClosed(){return execution==null?local.nativeClosed():execution.nativeClosed();}
        void close()throws Exception{if(execution==null)local.close();else execution.close();}
        boolean fitsExecutionSource(String input)throws Exception {
            return execution!=null&&Libbox.routerNodeChainCandidateAppendExecutionInputFitsSource(executionSource,input);
        }
        void requireSource(AndroidNodeChainCapture original,String inventory)throws Exception {
            if(execution==null)return;
            AndroidNodeCandidateAppendSource append=original.append;
            if(local!=null||append==null||!append.original.appendExecutionDraft()
                    ||!AndroidNodeCandidateAppendSource.permitsExecution(append.original.members,append.original.modes,append.kind,append.original.appendMode,append.original.appendExecution))throw invalid();
            JSONObject input=new JSONObject(capturedInput);
            exactKeys(input,"kind","schema","execution","local_source","inventory");
            if(!"routervpn-node-chain-append-execution-source".equals(input.getString("kind"))||integer(input,"schema")!=1
                    ||!append.original.appendExecution.equals(input.getString("execution"))||!append.source.equals(input.getString("local_source"))
                    ||!inventory.equals(input.getString("inventory"))||!capturedInput.equals(executionSource.source())||!capturedInput.equals(launchInput())
                    ||!append.source.equals(executionSource.localSource())||!sourceSHA256().equals(executionSource.sourceSHA256())
                    ||!append.sourceSHA256.equals(originalSourceSHA256())||!originalSourceSHA256().equals(executionSource.originalSourceSHA256())
                    ||!config().equals(executionSource.config())||!configSHA256().equals(executionSource.configSHA256())
                    ||!append.metadata.equals(appendSourceMetadata())||!append.metadata.equals(executionSource.appendSourceMetadata())
                    ||!metadata().equals(executionSource.metadata())
                    ||!append.original.appendExecution.equals(requestedExecution())||!requestedExecution().equals(executionSource.execution())
                    ||!append.original.appendMode.equals(candidateMode())||!candidateMode().equals(executionSource.candidateMode())
                    ||!"router-vpn".equals(candidateKind())||!candidateKind().equals(executionSource.candidateKind())
                    ||!"routed-candidate-response".equals(candidateMeasurement())||!candidateMeasurement().equals(executionSource.candidateMeasurement())
                    ||appendPosition()!=append.memberInputs.size()||appendPosition()!=executionSource.appendPosition())throw invalid();
        }
    }
    final NativePlan plan;
    final AndroidNodeChainCapture original;
    final String launchInput, config, metadata, nativeMetadata, inventory, responseMode;
    final String sourceSHA256, configSHA256, captureSHA256;
    final int prefix, originalMTU, ceilingMTU;
    final String tunTag;

    static AndroidNodeCandidatePrefixCapture compile(AndroidNodeChainCapture original,int prefix,String inventory)throws Exception {
        requireSource(original,prefix,inventory);
        NativePlan plan=original.append!=null&&original.append.original.appendExecutionDraft()
                ?NativePlan.execution(original,inventory,null):new NativePlan(original.append!=null
                ?Libbox.newRouterNodeChainCandidateAppendPreparation(original.append.source,inventory)
                :original.connect!=null
                ?Libbox.newRouterNodeChainCONNECTCandidatePreparation(original.connect.source,prefix,inventory)
                :original.socks!=null?Libbox.newRouterNodeChainSOCKSCandidatePreparation(original.socks.source,prefix,inventory)
                :Libbox.newRouterNodeChainCandidatePreparation(original.sourceInput,prefix,inventory));
        try{return new AndroidNodeCandidatePrefixCapture(original,prefix,inventory,plan);}
        catch(Exception failed){if(plan!=null)try{plan.close();}catch(Exception cleanup){failed.addSuppressed(cleanup);}throw failed;}
    }

    /** Reopening uses the strict native parser. No receipt is stripped into a
     * different constructor input, and the saved full source stays independent. */
    static AndroidNodeCandidatePrefixCapture reopen(String input,AndroidNodeChainCapture original,int prefix,String inventory)throws Exception {
        requireSource(original,prefix,inventory);bounded(input,AndroidNodeChainCapture.MAX_INPUT);
        NativePlan plan=original.append!=null&&original.append.original.appendExecutionDraft()
                ?NativePlan.execution(original,inventory,input):new NativePlan(Libbox.routerNodeChainCandidatePreparationLaunch(input));
        try{
            AndroidNodeCandidatePrefixCapture capture=new AndroidNodeCandidatePrefixCapture(original,prefix,inventory,plan);
            if(!input.equals(capture.launchInput))throw invalid();
            return capture;
        }catch(Exception failed){if(plan!=null)try{plan.close();}catch(Exception cleanup){failed.addSuppressed(cleanup);}throw failed;}
    }

    private static void requireSource(AndroidNodeChainCapture original,int prefix,String inventory)throws Exception {
        if(original==null||original.socks!=null&&original.connect!=null||!"local".equals(original.selectionExecution)||prefix<0||prefix>=(original.append!=null?original.memberInputs.size():original.memberInputs.size()-1))throw invalid();
        original.requireCurrent();bounded(inventory,AndroidNodeChainCapture.MAX_INPUT);
        JSONObject offered=new JSONObject(inventory);
        if(original.append!=null) {
            if(prefix!=original.memberInputs.size()-1||!offered.has("response_mode")
                    ||!original.append.plan.candidateMode().equals(offered.getString("response_mode")))throw invalid();
            return;
        }
        if(offered.has("response_mode")) {
            String mode=offered.getString("response_mode");
            if(mode.isEmpty()||original.plan==null||!mode.equals(Libbox.routerNodeChainPreparedCandidateResponseMode(original.plan,prefix)))throw invalid();
            return;
        }
        JSONObject selected=new JSONObject(original.memberInputs.get(prefix));
        boolean stream="routervpn-node-chain-imported-member".equals(selected.optString("kind"))||"shadowsocks".equals(selected.optString("mode"));
        if(stream){
            if(original.plan!=null) {
                String metric=Libbox.routerNodeChainCandidatePrefixMeasurement(original.plan,prefix);
                JSONObject last=new JSONObject(original.memberInputs.get(original.memberInputs.size()-1));
                String expected="routervpn-node-chain-external-final".equals(last.optString("kind"))?"routed-public-candidate-response":"routed-candidate-response";
                if(expected.equals(metric))return;
            }
            throw invalid();
        }
        if(original.multipleImported && packetMode(selected.optString("mode")) && original.plan!=null
                && "routed-tcp-connect".equals(Libbox.routerNodeChainCandidatePrefixMeasurement(original.plan,prefix)))return;
        for(int i=0;i<=prefix;i++)if(!packetMode(new JSONObject(original.memberInputs.get(i)).optString("mode")))throw invalid();
    }

    private AndroidNodeCandidatePrefixCapture(AndroidNodeChainCapture original,int prefix,String inventory,NativePlan plan)throws Exception {
        requireSource(original,prefix,inventory);if(plan==null)throw invalid();
        this.original=original;this.prefix=prefix;this.inventory=inventory;this.plan=plan;
        launchInput=bounded(plan.launchInput(),AndroidNodeChainCapture.MAX_INPUT);
        config=bounded(plan.config(),4*1024*1024);
        JSONObject offered=new JSONObject(inventory);
        responseMode=offered.has("response_mode")?offered.getString("response_mode"):"";
        JSONArray inputs=offered.getJSONArray("inputs");int originalCount=inputs.length();
        long observationDeadline=AndroidNodeCandidateMetadata.observationDeadline();String first=plan.metadata();nativeMetadata=first;
        JSONObject meta=AndroidNodeCandidateMetadata.read(first,plan::metadataPage,originalCount,observationDeadline);
        boolean paged=new JSONObject(first).getInt("schema")==2;
        boolean execution=plan.executionPurpose();
        if(execution) {
            plan.requireSource(original,inventory);
            exactKeys(meta,"schema","purpose","capture_sha256","source_sha256","config_sha256","prefix_position","prefix_id","append_position","targets","measurement","candidate_mode",
                    "draft_revision","device_revision","device_source_sha256","device_mtu_revision","original_source_sha256","prefix_count","prefixes_sha256","mtu_sha256","append_source_metadata_sha256",
                    "application_open","dns_open","ready","stage","mtu_measurement","execution_source_sha256","requested_execution","execution_capture_sha256","original_preparation_source_sha256","original_preparation_capture_sha256");
            if(paged||originalCount<1||originalCount>50||!meta.getString("capture_sha256").isEmpty()||!meta.getString("execution_capture_sha256").isEmpty()
                    ||!plan.captureSHA256().isEmpty()||!plan.sourceSHA256().equals(meta.getString("execution_source_sha256"))
                    ||!plan.requestedExecution().equals(meta.getString("requested_execution"))
                    ||!digest(meta.getString("original_preparation_source_sha256"))||!digest(meta.getString("original_preparation_capture_sha256")))throw invalid();
        } else if(original.append!=null&&original.append.original.appendExecutionDraft())throw invalid();
        if(original.append==null&&!responseMode.isEmpty()&&(original.plan==null
                ||!responseMode.equals(Libbox.routerNodeChainPreparedCandidateResponseMode(original.plan,prefix))))throw invalid();
        if(original.append!=null) {
            String originalMetadata=bounded(plan.appendSourceMetadata(),256*1024);
            if(!plan.isAppend()||plan.appendPosition()!=original.memberInputs.size()
                    ||!original.append.metadata.equals(originalMetadata)
                    ||!AndroidTorProfile.digest(originalMetadata.getBytes(StandardCharsets.UTF_8)).equals(meta.getString("append_source_metadata_sha256"))
                    ||integer(meta,"prefix_count")!=original.memberInputs.size()
                    ||!(execution?"draft-prefix-append-execution":"draft-prefix-append").equals(meta.getString("purpose"))
                    ||integer(meta,"append_position")!=original.memberInputs.size()
                    ||!original.append.kind.equals(plan.candidateKind())||!original.append.measurement.equals(plan.candidateMeasurement())
                    ||!original.append.measurement.equals(meta.getString("measurement"))
                    ||("external".equals(original.append.kind)?!"external".equals(meta.optString("candidate_kind","")):meta.has("candidate_kind")))throw invalid();
            JSONObject retained=new JSONObject(originalMetadata);
            for(String key:new String[]{"draft_revision","device_revision","device_source_sha256","device_mtu_revision","candidate_mode"})
                if(!retained.get(key).equals(meta.get(key)))throw invalid();
            meta.put("prefixes",retained.getJSONArray("prefixes")).put("mtu",retained.getJSONObject("mtu"));
        } else if(plan.isAppend()||meta.has("purpose")||meta.has("candidate_kind"))throw invalid();
        metadata=meta.toString();
        sourceSHA256=plan.sourceSHA256();configSHA256=plan.configSHA256();captureSHA256=plan.captureSHA256();
        JSONObject source=new JSONObject(launchInput),graph=new JSONObject(config);
        if(!purposeKind(original).equals(source.getString("kind"))||integer(source,"schema")!=1
                ||original.append!=null&&!execution&&(!original.append.source.equals(source.getString("prefix_source"))
                    ||integer(source,"append_position")!=original.memberInputs.size())
                ||original.connect!=null&&!original.connect.source.equals(source.getString("original_source"))
                ||original.socks!=null&&!original.socks.source.equals(source.getString("original_source"))
                ||!responseMode.equals(plan.candidateMode())
                ||(responseMode.isEmpty()?meta.has("candidate_mode"):!responseMode.equals(meta.optString("candidate_mode"))
                    ||!(original.append==null?"routed-candidate-response":original.append.measurement).equals(meta.optString("measurement")))
                ||!execution&&integer(source,"prefix_position")!=prefix||!inventory.equals(source.getString("inventory"))
                ||integer(meta,"schema")!=1||integer(meta,"prefix_position")!=prefix
                ||!sourceSHA256.equals(meta.getString("source_sha256"))||!configSHA256.equals(meta.getString("config_sha256"))
                ||!captureSHA256.equals(meta.getString("capture_sha256"))||!digest(sourceSHA256)||!digest(configSHA256)||(execution?!captureSHA256.isEmpty():!digest(captureSHA256))
                ||!configSHA256.equals(AndroidTorProfile.digest(config.getBytes(StandardCharsets.UTF_8)))
                ||!original.sourceSHA256.equals(plan.originalSourceSHA256())||!original.sourceSHA256.equals(meta.getString("original_source_sha256"))
                ||!Boolean.FALSE.equals(meta.get("application_open"))||!Boolean.FALSE.equals(meta.get("dns_open"))||!Boolean.FALSE.equals(meta.get("ready"))
                ||!"pending-prefix-proof".equals(meta.getString("stage"))||!"configured-bounds-only".equals(meta.getString("mtu_measurement")))throw invalid();
        JSONArray proofs=meta.getJSONArray("prefixes"),targets=meta.getJSONArray("targets");
        if(proofs.length()!=prefix+1||targets.length()<1||execution&&targets.length()!=originalCount)throw invalid();
        Set<String> ids=new HashSet<>();
        for(int i=0;i<targets.length();i++){
            JSONObject target=targets.getJSONObject(i);String id=target.getString("id");
            if(id.isEmpty()||id.length()>128||!ids.add(id)||!digest(target.getString("source_sha256")))throw invalid();
            if(paged||execution){
                JSONObject input=new JSONObject(inputs.getString(i));
                String originalID=input.has("profile_json")?new JSONObject(input.getString("profile_json")).getString("id")
                        :new JSONObject(input.getString("capture")).getString("exit_id");
                if(!id.equals(originalID))throw invalid();
            }
        }
        for(int i=0;i<proofs.length();i++){
            JSONObject proof=proofs.getJSONObject(i),member=new JSONObject(original.memberInputs.get(i));
            if ("routervpn-node-chain-imported-member".equals(member.optString("kind"))) {
                JSONObject retained;
                if(original.append!=null) {
                    original.append.requireCurrent();
                    if(original.plan!=null||!plan.isAppend()||!"draft-prefix-append".equals(meta.getString("purpose"))
                            ||!original.append.metadata.equals(plan.appendSourceMetadata()))throw invalid();
                    retained=new JSONObject(original.append.metadata).getJSONArray("prefixes").getJSONObject(i);
                } else {
                    if(original.plan==null || (responseMode.isEmpty()
                            ?!Libbox.routerNodeChainCandidatePrefixMeasurement(original.plan,prefix).equals(meta.optString("measurement","routed-tcp-connect"))
                            :!responseMode.equals(Libbox.routerNodeChainPreparedCandidateResponseMode(original.plan,prefix))))throw invalid();
                    retained=new JSONObject(Libbox.routerNodeChainCandidatePrefixProof(original.plan,i));
                }
                for(String key:new String[]{"position","profile_id","node_id","source_sha256","tag","kind","node_kind","mode","start_layer"})
                    if(!retained.get(key).equals(proof.get(key)))throw invalid();
                if(!"public-path".equals(proof.getString("kind"))||!"external".equals(proof.getString("node_kind"))||!proof.getString("node_id").isEmpty())throw invalid();
                continue;
            }
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
        original.requireCurrent();if(paged)AndroidNodeCandidateMetadata.requireBefore(observationDeadline);
    }

    boolean appendExecution(){return plan.executionPurpose();}
    String requestedExecution(){return plan.requestedExecution();}
    void requireCurrent()throws Exception {
        original.requireCurrent();
        if(appendExecution()){plan.requireSource(original,inventory);if(!nativeMetadata.equals(plan.metadata()))throw invalid();}
    }
    @Override public void close()throws Exception {plan.close();}
    private static String purposeKind(AndroidNodeChainCapture original) {
        if(original.append!=null)return original.append.original.appendExecutionDraft()?"routervpn-node-chain-append-execution-source":"routervpn-node-chain-candidate-append-preparation";
        if (original.externalFinal || original.multipleImported)
            return "routervpn-node-chain-multiple-imported-candidate-preparation";
        return original.connect!=null?"routervpn-node-chain-connect-candidate-preparation"
                :original.socks!=null?"routervpn-node-chain-socks-candidate-preparation"
                :"routervpn-node-chain-candidate-preparation";
    }
    private static void exactKeys(JSONObject value,String... names)throws Exception {
        if(value.length()!=names.length)throw invalid();
        for(String name:names)if(!value.has(name))throw invalid();
    }
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
