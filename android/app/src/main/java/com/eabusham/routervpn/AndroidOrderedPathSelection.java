package com.eabusham.routervpn;

import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterNodeChain;
import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** One cancellable editor draft. It retains original private sources in memory;
 * only an explicit Save publishes references and per-member policy choices. */
final class AndroidOrderedPathSelection {
    private static final List<String> PREFIX_MODES=List.of("wg","awg2-fast","awg2-strong");
    static final class Member {
        final AndroidNodeStore.ChainSource source;
        final String mode;
        Member(AndroidNodeStore.ChainSource source,String mode) { this.source=source;this.mode=mode; }
    }

    final AndroidNodeStore.ChainCatalog catalog;
    private final AndroidConnectionProfileStore profiles;
    private final Map<String,Object> preferences;
    private final List<Member> members=new ArrayList<>();
    private boolean saved;

    AndroidOrderedPathSelection(AndroidNodeStore nodes,AndroidConnectionProfileStore profiles) throws Exception {
        this.profiles=profiles;
        preferences=profiles.orderedEditorPreferences();
        catalog=nodes.captureChainCatalog();
        String selection=(String)preferences.getOrDefault("multihop_nodes","");
        if(!selection.isEmpty()) {
            AndroidNodeStore.ChainCapture captured=profiles.orderedEditorPath();
            for(int i=0;i<captured.members.size();i++)members.add(new Member(catalog.source(captured.members.get(i).id),captured.modes.get(i)));
        } else if(!catalog.selectedId.isEmpty()) {
            AndroidNodeStore.ChainSource selected=catalog.source(catalog.selectedId);
            if(hasMode(selected,"shadowsocks"))members.add(new Member(selected,"shadowsocks"));
        }
        requireCurrent();
    }

    List<Member> members() { return Collections.unmodifiableList(new ArrayList<>(members)); }

    List<AndroidNodeStore.Node> choices(boolean finalNode) throws Exception {
        requireCurrent();
        List<AndroidNodeStore.Node> result=new ArrayList<>();
        for(AndroidNodeStore.Node node:catalog.nodes) {
            boolean used=false;
            for(int i=0;i<members.size();i++)if(members.get(i).source.id.equals(node.id)&&(!finalNode||i!=members.size()-1))used=true;
            if(!used&&(finalNode?hasMode(catalog.source(node.id),"shadowsocks"):!prefixModes(node.id).isEmpty()))result.add(node);
        }
        requireCurrent();return result;
    }

    List<String> prefixModes(String id) throws Exception {
        requireCurrent();AndroidNodeStore.ChainSource source=catalog.source(id);List<String> result=new ArrayList<>();
        for(String mode:PREFIX_MODES)if(hasMode(source,mode))result.add(mode);
        requireCurrent();return Collections.unmodifiableList(result);
    }

    static String prefixModeTitle(String mode) {
        switch(mode) {
            case "wg":return "WireGuard";
            case "awg2-fast":return "AmneziaWG Fast";
            case "awg2-strong":return "AmneziaWG Strong";
            default:throw new IllegalArgumentException("Choose an exact supported intermediate transport.");
        }
    }

    void setFinal(String id) throws Exception {
        requireCurrent();
        AndroidNodeStore.ChainSource source=catalog.source(id);
        if(!hasMode(source,"shadowsocks"))throw new IllegalStateException("The selected final node has no complete Shadowsocks source.");
        for(int i=0;i<members.size()-1;i++)if(members.get(i).source.id.equals(id))throw new IllegalStateException("Choose a different final node.");
        Member previous=members.isEmpty()?null:members.get(members.size()-1),selected=new Member(source,"shadowsocks");
        if(members.isEmpty())members.add(selected);else members.set(members.size()-1,selected);
        try { requireBound(); }
        catch(Exception failure) { if(previous==null)members.clear();else members.set(members.size()-1,previous);throw failure; }
    }

    void addPrefix(String id) throws Exception {
        addPrefix(id,"wg");
    }

    void addPrefix(String id,String mode) throws Exception {
        requireCurrent();
        if(members.isEmpty())throw new IllegalStateException("Choose the final node first.");
        if(members.size()>=8)throw new IllegalStateException("This native ordered path supports at most eight nodes.");
        for(Member member:members)if(member.source.id.equals(id))throw new IllegalStateException("Each ordered position needs a different saved node.");
        AndroidNodeStore.ChainSource source=catalog.source(id);
        requirePrefixMode(source,mode);
        members.add(members.size()-1,new Member(source,mode));
        try { requireBound(); }
        catch(Exception failure) { members.remove(members.size()-2);throw failure; }
    }

    void setPrefixMode(int position,String mode) throws Exception {
        requireCurrent();
        if(position<0||position>=members.size()-1)throw new IllegalStateException("Choose an intermediate node to change its transport.");
        AndroidNodeStore.ChainSource source=members.get(position).source;requirePrefixMode(source,mode);
        members.set(position,new Member(source,mode));
    }

    private static void requirePrefixMode(AndroidNodeStore.ChainSource source,String mode) throws Exception {
        if(!PREFIX_MODES.contains(mode))throw new IllegalStateException("Choose WireGuard, AmneziaWG Fast or AmneziaWG Strong for this intermediate node.");
        if(!hasMode(source,mode))throw new IllegalStateException("The selected intermediate node has no complete "+prefixModeTitle(mode)+" source.");
    }

    void movePrefix(int position,int destination) throws Exception {
        requireCurrent();
        if(position<0||destination<0||position>=members.size()-1||destination>=members.size()-1)
            throw new IllegalStateException("Reorder the intermediate nodes without replacing the final node.");
        Member member=members.remove(position);members.add(destination,member);
    }

    void removePrefix(int position) throws Exception {
        requireCurrent();
        if(position<0||position>=members.size()-1)throw new IllegalStateException("Choose an intermediate node to remove.");
        members.remove(position);
    }

    /** Use the real pure native compiler before publishing any selected node. */
    AndroidNodeStore.ChainCapture save() throws Exception {
        requireCurrent();requireBound();
        if(members.size()<2)throw new IllegalStateException("Add at least one intermediate node before saving.");
        JSONArray references=new JSONArray();
        for(Member member:members)references.put(new JSONObject().put("id",member.source.profileId).put("mode",member.mode));
        JSONArray inputs=new JSONArray();List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();List<String> modes=new ArrayList<>();
        for(int i=0;i<members.size();i++) {
            Member member=members.get(i);JSONObject profile=member.source.profile();
            if(i==members.size()-1) {
                profile.put("multihop_enabled",true).put("multihop_execution","local").put("multihop_nodes",references);
                for(String key:new String[]{"multihop_entry_id","multihop_entry_mode","multihop_exit_id","multihop_exit_mode"})profile.remove(key);
                AndroidNodeStore.orderedSelection(profile);
            }
            inputs.put(AndroidNodeChainCapture.memberInput(member.source,member.mode,profile));
            sources.add(member.source);modes.add(member.mode);
        }
        String source=new JSONObject().put("schema",1).put("execution","local").put("nodes",inputs).toString();
        if(source.getBytes(StandardCharsets.UTF_8).length>AndroidNodeChainCapture.MAX_INPUT)throw new IllegalStateException("The complete ordered path exceeds its private source bound.");
        RouterNodeChain preview=Libbox.newRouterNodeChain(source);
        if(preview==null)throw new IllegalStateException("The native compiler returned no complete ordered path.");
        try {
            if(preview.config()==null||preview.config().isEmpty())throw new IllegalStateException("The native compiler returned no complete ordered graph.");
            requireCurrent();
        } finally { preview.close(); }
        AndroidNodeStore.ChainCapture captured=profiles.selectOrderedPath(catalog,sources,modes,preferences);
        saved=true;return captured;
    }

    void requireCurrent() throws Exception {
        if(saved)throw new IllegalStateException("The ordered draft was already saved; reopen it before editing again.");
        catalog.requireCurrent();
        if(!preferences.equals(profiles.orderedEditorPreferences()))throw new IllegalStateException("The selected connection changed while its ordered editor was open.");
    }

    private void requireBound() throws Exception {
        long size=0;Set<String> proofs=new HashSet<>();
        for(Member member:members) {
            size+=member.source.bytes().length;
            if(!proofs.add(member.source.proofId))throw new IllegalStateException("Ordered members must retain distinct paired node identities.");
        }
        if(size>AndroidNodeStore.MAX_CHAIN_SOURCE)throw new IllegalStateException("The complete ordered path exceeds its private source bound.");
    }

    private static boolean hasMode(AndroidNodeStore.ChainSource source,String mode) throws Exception {
        try { source.requirePairedIdentity(); }
        catch(IllegalStateException unavailable) { return false; }
        JSONObject assets=source.bundle().getJSONObject("profiles").optJSONObject(mode);
        return assets!=null&&assets.length()>0;
    }
}
