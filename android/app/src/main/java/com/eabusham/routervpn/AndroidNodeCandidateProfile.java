package com.eabusham.routervpn;

import android.content.Context;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterNodeChain;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** An explicit future connection, compiled from the measured original sources.
 * Saving never edits a node, active selection, native session or receipt. */
final class AndroidNodeCandidateProfile {
    /** Only a known complete-path incompatibility may keep a measured row without
     * Save. Source, owner, result and native compiler failures retain their
     * original exception type and invalidate the batch. */
    static final class ProposalUnavailable extends Exception {
        private ProposalUnavailable(String reason){super(reason);}
    }
    /** The preparation seals this authority only after its complete temporary
     * native graph has drained. It checks the original result, sources, idle
     * selection and physical cohort without retaining live measurement power. */
    interface SavedResultAuthority {void requireCurrent(AndroidNodeCandidateResult result)throws Exception;}
    private final AndroidNodeCandidateMeasurement operation;
    private final AndroidNodeCandidateResult result;
    private final SavedResultAuthority savedAuthority;
    private final List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();
    private final List<String> modes=new ArrayList<>();
    private final String execution;
    final String description;
    AndroidNodeCandidateProfile(AndroidNodeCandidateMeasurement operation,AndroidNodeCandidateResult result)throws Exception {
        this(operation,result,null);
    }
    static AndroidNodeCandidateProfile captureTemporary(AndroidNodeCandidateMeasurement operation,AndroidNodeCandidateResult result,SavedResultAuthority authority)throws Exception {
        if(authority==null)throw new IllegalArgumentException("The original temporary preparation authority is required.");
        return new AndroidNodeCandidateProfile(operation,result,authority);
    }
    private AndroidNodeCandidateProfile(AndroidNodeCandidateMeasurement operation,AndroidNodeCandidateResult result,SavedResultAuthority authority)throws Exception {
        if(operation==null||result==null)throw new IllegalArgumentException("The original measured candidate is required.");
        this.operation=operation;this.result=result;this.savedAuthority=authority;requireCurrent();
        AndroidNodeCandidateCatalog catalog=operation.catalog;
        boolean response="routed-candidate-response".equals(catalog.measurement);
        if(catalog.originalSource.measurementOnly()&&!response)throw new ProposalUnavailable("This measurement belongs to an unsaved ordered draft. Save the edited path separately.");
        AndroidNodeCandidateCatalog.Row selected=null;
        for(AndroidNodeCandidateCatalog.Row row:catalog.rows)if(row.id.equals(result.id)&&!row.input.isEmpty()){if(selected!=null)throw new IllegalStateException("Duplicate candidate identity");selected=row;}
        if(selected==null)throw new IllegalStateException("The measured original source is missing.");
        AndroidNodeStore.ChainSource candidate=catalog.source(selected.localID);
        String candidateMode=AndroidNodeCandidateCatalog.candidateMode(candidate);
        String actual=AndroidNodeChainCapture.memberInput(candidate,candidateMode,candidate.profile());
        if(!selected.input.equals(actual))throw new IllegalStateException("The measured source changed before proposal.");
        AndroidNodeStore.ChainCapture original=catalog.originalSource;
        int replacement=catalog.prefix+1;
        if(original==null||replacement<1||replacement>=original.members.size()||original.members.size()!=original.modes.size())
            throw new IllegalStateException("The measured prefix has no original next-hop position.");
        execution=original.execution;
        boolean insert=response&&replacement<original.members.size()-1;
        if(response){
            if(candidate.imported||!"shadowsocks".equals(candidateMode)
                    ||!AndroidNodeChainCapture.responsePrefix(original.members,original.modes,catalog.prefix,execution))
                throw new IllegalStateException("The authenticated response lost its original stream or paired candidate.");
            if(insert){
                for(int i=1;i<original.members.size()-1;i++)
                    if(!original.members.get(i).imported&&"shadowsocks".equals(original.modes.get(i)))
                        throw unavailable("This path already has a paired Shadowsocks intermediate. A second one cannot be saved.");
            }
            if(insert&&(original.members.size()>=8||!original.members.get(replacement).imported))
                throw unavailable("Saving this intermediate needs two adjacent imported streams and a path of at most eight nodes.");
        }else if(!"routed-tcp-connect".equals(catalog.measurement)
                ||!java.util.Arrays.asList("wg","awg2-fast","awg2-strong").contains(original.modes.get(catalog.prefix))){
            throw new IllegalStateException("The measured packet prefix lost its original transport.");
        }
        if(!java.util.Arrays.asList("local","server","auto").contains(execution))
            throw new IllegalStateException("The measured original path lost its requested execution.");
        // A score belongs to the next hop reached through this exact prefix.
        // Keep every other saved member and policy; incompatible replacements
        // must fail the complete compiler rather than silently truncate a tail.
        sources.addAll(original.members);modes.addAll(original.modes);
        if(insert){
            sources.add(replacement,candidate);modes.add(replacement,candidateMode);
            if(!AndroidNodeChainCapture.pairedStreamInterior(sources,modes,execution,replacement))
                throw unavailable("Saving this intermediate needs a Local packet prefix followed by literal Shadowsocks streams with Start Layer off.");
        }else{
            sources.set(replacement,candidate);modes.set(replacement,candidateMode);
        }
        JSONArray references=new JSONArray(),inputs=new JSONArray(),identities=new JSONArray();
        List<String> capturedInputs=new ArrayList<>(),capturedIdentities=new ArrayList<>();
        StringBuilder preview=new StringBuilder();long bytes=0;
        java.util.Set<String> ids=new java.util.HashSet<>(),proofs=new java.util.HashSet<>();
        for(int i=0;i<sources.size();i++){
            AndroidNodeStore.ChainSource source=sources.get(i);bytes+=source.bytes().length;
            if(!ids.add(source.profileId)||!source.proofId.isEmpty()&&!proofs.add(source.proofId))
                throw unavailable("This replacement duplicates a node retained in the saved path.");
            references.put(new JSONObject().put("id",source.profileId).put("mode",modes.get(i)));
            if(i>0)preview.append(" → ");preview.append(source.profileId).append(" (").append(modes.get(i)).append(")");
        }
        if(bytes>AndroidNodeStore.MAX_CHAIN_SOURCE)throw new IllegalStateException("The proposed original sources exceed their bound.");
        // The catalog measured the candidate's captured transport. It does
        // not grant a different packet mode or permission to remove a suffix.
        if(candidate.imported){
            boolean shadowsocks = "shadowsocks".equals(candidateMode);
            if (replacement == sources.size()-1 || (!shadowsocks && replacement != sources.size()-2))
                throw unavailable("This imported transport cannot occupy that position before the saved paired final.");
            for (int i=0; i<sources.size(); i++) {
                if (i != replacement && sources.get(i).imported && (!shadowsocks || !"shadowsocks".equals(modes.get(i))))
                    throw unavailable("These imported transports cannot share the saved intermediate positions.");
            }
            if(!"shadowsocks".equals(modes.get(modes.size()-1)))
                throw unavailable("This imported intermediate transport requires a paired Shadowsocks final; the saved final mode is "+modes.get(modes.size()-1)+".");
        }else if(!insert&&replacement<sources.size()-1&&!java.util.Arrays.asList("wg","awg2-fast","awg2-strong").contains(candidateMode)){
            throw unavailable("The measured transport cannot replace a WireGuard or AmneziaWG intermediate hop.");
        }
        for(int i=0;i<sources.size();i++){
            AndroidNodeStore.ChainSource source=sources.get(i);JSONObject policy=source.profile();
            if(i==sources.size()-1){policy.put("multihop_enabled",true).put("multihop_execution",execution).put("multihop_nodes",references);for(String key:new String[]{"multihop_entry_id","multihop_entry_mode","multihop_exit_id","multihop_exit_mode"})policy.remove(key);AndroidNodeStore.orderedSelection(policy);}
            String member=AndroidNodeChainCapture.memberInput(source,modes.get(i),"local".equals(execution)?policy:AndroidNodeChainCapture.executionProfile(policy)),identity=AndroidNodeChainCapture.identityInput(source);
            inputs.put(member);identities.put(identity);capturedInputs.add(member);capturedIdentities.add(identity);
        }
        AndroidNodeChainCapture.requireCompleteShape(sources,modes,execution);
        int schema=AndroidNodeChainCapture.sourceSchema(sources);
        String input=new JSONObject().put("schema",schema).put("execution","local").put("nodes",inputs).put("identity_sources",identities).toString();
        if(input.getBytes(StandardCharsets.UTF_8).length>AndroidNodeChainCapture.MAX_INPUT)throw new IllegalStateException("The complete proposed source exceeds its bound.");
        if(schema==4){
            try(AndroidNodeChainCONNECTCapture compiled=AndroidNodeChainCONNECTCapture.compile(input,capturedInputs,capturedIdentities)){
                if(!"local".equals(execution))AndroidNodeChainCapture.validateCONNECTExecutionSource(compiled.source,execution);
                requireCurrent();
            }
        }else if(schema==3){
            try(AndroidNodeChainSOCKSCapture compiled=AndroidNodeChainSOCKSCapture.compile(input,capturedInputs,capturedIdentities)){
                if(!"local".equals(execution))AndroidNodeChainCapture.validateSOCKSExecutionSource(compiled.source,execution);
                requireCurrent();
            }
        }else{
        RouterNodeChain compiled;
        try { compiled=Libbox.newRouterNodeChain(input); }
        catch(Exception rejected){
            if(response&&"paired Shadowsocks intermediate requires independent original stream endpoints and credentials".equals(String.valueOf(rejected.getMessage()).trim()))
                throw unavailable("The original stream endpoints and cipher keys must be independent to save this intermediate.");
            throw rejected;
        }
        if(compiled==null)throw new IllegalStateException("The compiler returned no proposed path.");
        try {if(compiled.config()==null||compiled.config().isEmpty())throw new IllegalStateException("The compiler returned no complete proposed graph.");
            JSONObject returned=new JSONObject(compiled.launchInput());
            if(!"routervpn-node-chain-launch-input".equals(returned.getString("kind"))||returned.getInt("schema")!=schema||!"local".equals(returned.getString("execution"))
                    ||!inputs.toString().equals(returned.getJSONArray("nodes").toString())||!identities.toString().equals(returned.getJSONArray("identity_sources").toString()))
                throw new IllegalStateException("The native proposal replaced a captured member or paired identity.");
            if(!"local".equals(execution))AndroidNodeChainCapture.validateExecutionPlan(compiled,execution);
            requireCurrent();}
        finally {compiled.close();}
        }
        description=preview.toString();
    }
    private ProposalUnavailable unavailable(String reason)throws Exception {
        // A recognized graph limitation cannot hide an expired or replaced
        // source/result observed while deciding whether Save is supported.
        requireCurrent();return new ProposalUnavailable(reason);
    }
    private void requireCurrent()throws Exception {operation.requireResult(result);}
    private void requireSavedCurrent()throws Exception {
        if(savedAuthority==null){requireCurrent();return;}
        if(!operation.joined()||!result.current(System.currentTimeMillis()))throw new IllegalStateException("The original temporary measurement must drain and remain fresh before saving.");
        savedAuthority.requireCurrent(result);
    }
    AndroidConnectionProfileStore.Record save(Context context,String name)throws Exception {
        synchronized(operation){
            requireSavedCurrent();AndroidConnectionProfileStore store=new AndroidConnectionProfileStore(context,new AndroidNodeStore(context),new AndroidStandardExitStore(context));
            return store.appendOrderedProposal(name,sources,modes,execution,()->{try{requireSavedCurrent();}catch(Exception stale){throw new IllegalStateException("Retest this original candidate before saving.",stale);}});
        }
    }
}
