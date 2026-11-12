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
    private final AndroidNodeCandidateMeasurement operation;
    private final AndroidNodeCandidateResult result;
    private final List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();
    private final List<String> modes=new ArrayList<>();
    final String description;
    AndroidNodeCandidateProfile(AndroidNodeCandidateMeasurement operation,AndroidNodeCandidateResult result)throws Exception {
        this.operation=operation;this.result=result;requireCurrent();
        AndroidNodeCandidateCatalog catalog=operation.catalog;AndroidNodeCandidateCatalog.Row selected=null;
        for(AndroidNodeCandidateCatalog.Row row:catalog.rows)if(row.id.equals(result.id)&&!row.input.isEmpty()){if(selected!=null)throw new IllegalStateException("Duplicate candidate identity");selected=row;}
        if(selected==null)throw new IllegalStateException("The measured original source is missing.");
        AndroidNodeStore.ChainSource candidate=catalog.source(selected.localID);
        String actual=AndroidNodeChainCapture.memberInput(candidate,"shadowsocks",candidate.profile());
        if(!selected.input.equals(actual))throw new IllegalStateException("The measured source changed before proposal.");
        for(int i=0;i<=catalog.prefix;i++){sources.add(catalog.session.source.members.get(i));modes.add(catalog.session.source.modes.get(i));}
        sources.add(candidate);modes.add("shadowsocks");
        if(candidate.imported){
            if(catalog.prefix!=0)throw new IllegalStateException("A custom candidate currently requires one first packet node and the original paired final node.");
            AndroidNodeStore.ChainSource last=catalog.session.source.control;
            sources.add(last);modes.add("shadowsocks");
        }
        JSONArray references=new JSONArray(),inputs=new JSONArray(),identities=new JSONArray();
        StringBuilder preview=new StringBuilder();long bytes=0;
        for(int i=0;i<sources.size();i++){
            AndroidNodeStore.ChainSource source=sources.get(i);bytes+=source.bytes().length;
            references.put(new JSONObject().put("id",source.profileId).put("mode",modes.get(i)));
            if(i>0)preview.append(" → ");preview.append(source.profileId).append(" (").append(modes.get(i)).append(")");
        }
        if(bytes>AndroidNodeStore.MAX_CHAIN_SOURCE)throw new IllegalStateException("The proposed original sources exceed their bound.");
        for(int i=0;i<sources.size();i++){
            AndroidNodeStore.ChainSource source=sources.get(i);JSONObject policy=source.profile();
            if(i==sources.size()-1){policy.put("multihop_enabled",true).put("multihop_execution","local").put("multihop_nodes",references);for(String key:new String[]{"multihop_entry_id","multihop_entry_mode","multihop_exit_id","multihop_exit_mode"})policy.remove(key);AndroidNodeStore.orderedSelection(policy);}
            inputs.put(AndroidNodeChainCapture.memberInput(source,modes.get(i),policy));identities.put(AndroidNodeChainCapture.identityInput(source));
        }
        String input=new JSONObject().put("schema",AndroidNodeChainCapture.sourceSchema(sources)).put("execution","local").put("nodes",inputs).put("identity_sources",identities).toString();
        if(input.getBytes(StandardCharsets.UTF_8).length>AndroidNodeChainCapture.MAX_INPUT)throw new IllegalStateException("The complete proposed source exceeds its bound.");
        RouterNodeChain compiled=Libbox.newRouterNodeChain(input);
        if(compiled==null)throw new IllegalStateException("The compiler returned no proposed path.");
        try {if(compiled.config()==null||compiled.config().isEmpty())throw new IllegalStateException("The compiler returned no complete proposed graph.");requireCurrent();}
        finally {compiled.close();}
        description=preview.toString();
    }
    private void requireCurrent()throws Exception {operation.requireResult(result);}
    AndroidConnectionProfileStore.Record save(Context context,String name)throws Exception {
        synchronized(operation){
            requireCurrent();AndroidConnectionProfileStore store=new AndroidConnectionProfileStore(context,new AndroidNodeStore(context),new AndroidStandardExitStore(context));
            return store.appendOrderedProposal(name,sources,modes,()->{try{requireCurrent();}catch(Exception stale){throw new IllegalStateException("Retest this original candidate before saving.",stale);}});
        }
    }
}
