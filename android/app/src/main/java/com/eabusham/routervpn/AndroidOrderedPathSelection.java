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
    private volatile long revision;
    private String execution="local";

    AndroidOrderedPathSelection(AndroidNodeStore nodes,AndroidConnectionProfileStore profiles) throws Exception {
        this.profiles=profiles;
        preferences=profiles.orderedEditorPreferences();
        catalog=nodes.captureChainCatalog();
        String selection=(String)preferences.getOrDefault("multihop_nodes","");
        if(!selection.isEmpty()) {
            AndroidNodeStore.ChainCapture captured=profiles.orderedEditorPath();
            execution=captured.execution;
            for(int i=0;i<captured.members.size();i++)members.add(new Member(catalog.source(captured.members.get(i).id),captured.modes.get(i)));
        } else if(!catalog.selectedId.isEmpty()) {
            AndroidNodeStore.ChainSource selected=catalog.source(catalog.selectedId);
            List<String> modes=finalModes(selected.id);
            if(!modes.isEmpty())members.add(new Member(selected,modes.get(0)));
        }
        requireCurrent();
    }

    List<Member> members() { return Collections.unmodifiableList(new ArrayList<>(members)); }
    String execution() { return execution; }
    long revision(){return revision;}
    static String executionTitle(String value) {
        switch(value) {
            case "local":return "Local";
            case "server":return "Server";
            case "auto":return "Compare both";
            default:throw new IllegalArgumentException("Choose Local, Server or Compare both.");
        }
    }
    void setExecution(String value) throws Exception {
        requireCurrent();executionTitle(value);String previous=execution;execution=value;
        try { requireBound(); } catch(Exception invalid) { execution=previous;throw invalid; }
        revision++;
    }

    AndroidNodeStore.ChainCapture matchingSavedPath() throws Exception {
        requireCurrent();
        if(!Boolean.TRUE.equals(preferences.get("multihop_on")) || "".equals(preferences.getOrDefault("multihop_nodes","")))return null;
        AndroidNodeStore.ChainCapture source=profiles.orderedEditorPath();
        if(!execution.equals(source.execution)||members.size()!=source.members.size())return null;
        for(int i=0;i<members.size();i++) {
            Member member=members.get(i);
            if(!member.mode.equals(source.modes.get(i))||!member.source.id.equals(source.members.get(i).id)
                    ||!java.util.Arrays.equals(member.source.bytes(),source.members.get(i).bytes()))return null;
        }
        source.requireCurrent();return source;
    }

    java.util.concurrent.Callable<AndroidNodeStore.ChainCapture> candidateDraftCapture(int prefix) throws Exception {
        long capturedRevision=revision;
        requireCurrent();requireBound();
        if(!"local".equals(execution))throw new IllegalStateException("Draft candidate timing requires Local execution.");
        List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();List<String> modes=new ArrayList<>();
        for(Member member:members){sources.add(member.source);modes.add(member.mode);}
        return ()->catalog.captureCandidateDraft(sources,modes,prefix,()->revision==capturedRevision);
    }

    List<AndroidNodeStore.Node> choices(boolean finalNode) throws Exception {
        requireCurrent();
        List<AndroidNodeStore.Node> result=new ArrayList<>();
        for(AndroidNodeStore.Node node:catalog.nodes) {
            boolean used=false;
            for(int i=0;i<members.size();i++)if(members.get(i).source.id.equals(node.id)&&(!finalNode||i!=members.size()-1))used=true;
            if(!used&&(finalNode?!finalModes(node.id).isEmpty():!prefixModes(node.id).isEmpty()))result.add(node);
        }
        requireCurrent();return result;
    }

    List<String> prefixModes(String id) throws Exception {
        requireCurrent();AndroidNodeStore.ChainSource source=catalog.source(id);List<String> result=new ArrayList<>();
        if(source.imported){
            String mode=AndroidExternalPolicy.protocol(source.external().protocol);boolean variablePrefix="shadowsocks".equals(mode)||"socks5".equals(mode)||"http-connect".equals(mode)||"https-connect".equals(mode)||"openvpn".equals(mode);
            boolean paired=true;for(Member member:members)paired&=!member.source.imported;
            boolean independent="local".equals(execution)&&"shadowsocks".equals(mode)&&literalSS(source);
            for(Member member:members)if(member.source.imported)independent&=literalSS(member.source);
            if(members.size()>=2&&members.size()<8&&(variablePrefix||members.size()==2)&&(paired||independent)&&"shadowsocks".equals(members.get(members.size()-1).mode))result.add(mode);
        }
        else for(String mode:PREFIX_MODES)if(hasMode(source,mode))result.add(mode);
        requireCurrent();return Collections.unmodifiableList(result);
    }

    static String prefixModeTitle(String mode) {
        switch(mode) {
            case "shadowsocks":return "Custom Shadowsocks 2022";
            case "socks5":return "Custom SOCKS5";
            case "http-connect":return "Custom HTTP CONNECT";
            case "https-connect":return "Custom HTTPS CONNECT";
            case "openvpn":return "Custom OpenVPN";
            case "wg":return "WireGuard";
            case "awg2-fast":return "AmneziaWG Fast";
            case "awg2-strong":return "AmneziaWG Strong";
            default:throw new IllegalArgumentException("Choose an exact supported intermediate transport.");
        }
    }

    List<String> finalModes(String id) throws Exception {
        requireCurrent();AndroidNodeStore.ChainSource source=catalog.source(id);List<String> result=new ArrayList<>();
        if(!source.imported) {
            if(hasMode(source,"shadowsocks"))result.add("shadowsocks");
            boolean imported=false;for(Member member:members)imported|=member.source.imported;
            if(!imported&&hasCapturedHysteriaFinal(source))result.add("hysteria2");
        }
        requireCurrent();return Collections.unmodifiableList(result);
    }

    static String finalModeTitle(String mode) {
        if("shadowsocks".equals(mode))return "Shadowsocks 2022";
        if("hysteria2".equals(mode))return "Hysteria2";
        throw new IllegalArgumentException("Choose an exact supported final transport.");
    }

    void setFinal(String id) throws Exception {
        List<String> modes=finalModes(id);
        if(modes.isEmpty())throw new IllegalStateException("The selected final node has no compatible complete source.");
        setFinal(id,modes.get(0));
    }

    void setFinal(String id,String mode) throws Exception {
        requireCurrent();
        AndroidNodeStore.ChainSource source=catalog.source(id);
        if(!finalModes(id).contains(mode))throw new IllegalStateException("The selected final node has no compatible complete source for this exact transport.");
        for(int i=0;i<members.size()-1;i++)if(members.get(i).source.id.equals(id))throw new IllegalStateException("Choose a different final node.");
        Member previous=members.isEmpty()?null:members.get(members.size()-1),selected=new Member(source,mode);
        if(members.isEmpty())members.add(selected);else members.set(members.size()-1,selected);
        try { requireBound(); }
        catch(Exception failure) { if(previous==null)members.clear();else members.set(members.size()-1,previous);throw failure; }
        revision++;
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
        if(source.imported&&!"shadowsocks".equals(members.get(members.size()-1).mode))throw new IllegalStateException("An imported middle requires its paired Shadowsocks 2022 final.");
        requirePrefixMode(source,mode);
        int position=members.size()-1;
        if(!source.imported&&members.size()>=3&&members.get(members.size()-2).source.imported&&!("local".equals(execution)&&literalSS(members.get(members.size()-2).source)))position--;
        members.add(position,new Member(source,mode));
        try { requireBound(); }
        catch(Exception failure) { members.remove(position);throw failure; }
        revision++;
    }

    void setPrefixMode(int position,String mode) throws Exception {
        requireCurrent();
        if(position<0||position>=members.size()-1)throw new IllegalStateException("Choose an intermediate node to change its transport.");
        AndroidNodeStore.ChainSource source=members.get(position).source;requirePrefixMode(source,mode);
        members.set(position,new Member(source,mode));
        revision++;
    }

    private static void requirePrefixMode(AndroidNodeStore.ChainSource source,String mode) throws Exception {
        if(source.imported){AndroidNodeStore.ChainSource.requireImported(source.external());if(!mode.equals(AndroidExternalPolicy.protocol(source.external().protocol)))throw new IllegalStateException("Keep the original imported transport.");return;}
        if(!PREFIX_MODES.contains(mode))throw new IllegalStateException("Choose WireGuard, AmneziaWG Fast or AmneziaWG Strong for this intermediate node.");
        if(!hasMode(source,mode))throw new IllegalStateException("The selected intermediate node has no complete "+prefixModeTitle(mode)+" source.");
    }

    void movePrefix(int position,int destination) throws Exception {
        requireCurrent();
        if(position<0||destination<0||position>=members.size()-1||destination>=members.size()-1)
            throw new IllegalStateException("Reorder the intermediate nodes without replacing the final node.");
        Member member=members.remove(position);members.add(destination,member);
        try{requireBound();}catch(Exception failure){members.remove(destination);members.add(position,member);throw failure;}
        revision++;
    }

    void removePrefix(int position) throws Exception {
        requireCurrent();
        if(position<0||position>=members.size()-1)throw new IllegalStateException("Choose an intermediate node to remove.");
        Member old=members.remove(position);
        try{requireBound();}catch(Exception failure){members.add(position,old);throw failure;}
        revision++;
    }

    /** Use the real pure native compiler before publishing any selected node. */
    AndroidNodeStore.ChainCapture save() throws Exception {
        requireCurrent();requireBound();
        if(members.size()<2)throw new IllegalStateException("Add at least one intermediate node before saving.");
        JSONArray references=new JSONArray();
        for(Member member:members)references.put(new JSONObject().put("id",member.source.profileId).put("mode",member.mode));
        JSONArray inputs=new JSONArray(),identities=new JSONArray();List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();List<String> modes=new ArrayList<>();
        for(int i=0;i<members.size();i++) {
            Member member=members.get(i);JSONObject profile=member.source.profile();
            if(i==members.size()-1) {
                profile.put("multihop_enabled",true).put("multihop_execution",execution).put("multihop_nodes",references);
                for(String key:new String[]{"multihop_entry_id","multihop_entry_mode","multihop_exit_id","multihop_exit_mode"})profile.remove(key);
                AndroidNodeStore.orderedSelection(profile);
            }
            inputs.put(AndroidNodeChainCapture.memberInput(member.source,member.mode,"local".equals(execution)?profile:AndroidNodeChainCapture.executionProfile(profile)));
            identities.put(AndroidNodeChainCapture.identityInput(member.source));
            sources.add(member.source);modes.add(member.mode);
        }
        String source=new JSONObject().put("schema",AndroidNodeChainCapture.sourceSchema(sources)).put("execution","local").put("nodes",inputs).put("identity_sources",identities).toString();
        if(source.getBytes(StandardCharsets.UTF_8).length>AndroidNodeChainCapture.MAX_INPUT)throw new IllegalStateException("The complete ordered path exceeds its private source bound.");
        if(AndroidNodeChainCapture.sourceSchema(sources)==4) {
            AndroidNodeChainCONNECTCapture preview=AndroidNodeChainCONNECTCapture.compile(source,jsonStrings(inputs),jsonStrings(identities));
            try { if(!"local".equals(execution))AndroidNodeChainCapture.validateCONNECTExecutionSource(preview.source,execution);requireCurrent(); } finally { preview.close(); }
        } else if(AndroidNodeChainCapture.sourceSchema(sources)==3) {
            AndroidNodeChainSOCKSCapture preview=AndroidNodeChainSOCKSCapture.compile(source,jsonStrings(inputs),jsonStrings(identities));
            try { if(!"local".equals(execution))AndroidNodeChainCapture.validateSOCKSExecutionSource(preview.source,execution);requireCurrent(); } finally { preview.close(); }
        } else {
            RouterNodeChain preview=Libbox.newRouterNodeChain(source);
            if(preview==null)throw new IllegalStateException("The native compiler returned no complete ordered path.");
            try {
                if(preview.config()==null||preview.config().isEmpty())throw new IllegalStateException("The native compiler returned no complete ordered graph.");
                if(!"local".equals(execution))AndroidNodeChainCapture.validateExecutionPlan(preview,execution);
                requireCurrent();
            } finally { preview.close(); }
        }
        AndroidNodeStore.ChainCapture captured=profiles.selectOrderedPath(catalog,sources,modes,preferences,execution);
        saved=true;revision++;return captured;
    }

    private static List<String> jsonStrings(JSONArray values)throws Exception {
        List<String> result=new ArrayList<>();for(int i=0;i<values.length();i++)result.add(values.getString(i));return result;
    }

    void requireCurrent() throws Exception {
        if(saved)throw new IllegalStateException("The ordered draft was already saved; reopen it before editing again.");
        catalog.requireCurrent();
        if(!preferences.equals(profiles.orderedEditorPreferences()))throw new IllegalStateException("The selected connection changed while its ordered editor was open.");
    }

    private void requireBound() throws Exception {
        if(!members.isEmpty()) {
            Member last=members.get(members.size()-1);
            if(!finalModes(last.source.id).contains(last.mode))throw new IllegalStateException("The ordered final transport is incompatible with its original source or imported middle.");
        }
        long size=0;Set<String> proofs=new HashSet<>();
        for(Member member:members) {
            size+=member.source.bytes().length;
            if(!proofs.add(member.source.identityKey()))throw new IllegalStateException("Ordered members must retain distinct paired node identities.");
        }
        List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();for(Member member:members)sources.add(member.source);
        int schema=AndroidNodeChainCapture.sourceSchema(sources);
        List<String> modes=new ArrayList<>();for(Member member:members)modes.add(member.mode);
        AndroidNodeChainCapture.requireCompleteShape(sources,modes,execution);
        if(!"local".equals(execution)&&!members.isEmpty()) {
            boolean hysteriaFinal=schema==1&&"hysteria2".equals(members.get(members.size()-1).mode);
            if(hysteriaFinal) {
                if(members.size()<2||members.size()>8)throw new IllegalStateException("Paired Hysteria2 execution requires two to eight original nodes.");
                for(int i=0;i<members.size()-1;i++)if(members.get(i).source.imported||!List.of("wg","awg2-fast","awg2-strong").contains(members.get(i).mode))
                    throw new IllegalStateException("Hysteria2 execution requires only original paired packet prefixes.");
            }
            if(schema>5||schema==3&&(members.size()<3||members.size()>8)||schema==4&&(members.size()<3||members.size()>8)||schema==5&&(members.size()<3||members.size()>8)||!hysteriaFinal&&!"shadowsocks".equals(members.get(members.size()-1).mode))
                throw new IllegalStateException("Server and Compare require paired packet prefixes before the Shadowsocks 2022 final or an original paired Hysteria2 final with its own authenticated Start Layer. Imported middle paths retain their Shadowsocks 2022 final; a Shadowsocks hostname requires at least four nodes.");
            for(Member member:members)if(member.source.imported) {
                AndroidStandardExitStore.Entry imported=member.source.external();
                if(AndroidStandardExitStore.importedHostname(imported)) {
                    if(members.size()<4 || schema!=2 || members.get(members.size()-2)!=member || !"shadowsocks".equals(member.mode))
                        throw new IllegalStateException("Hostname Server and Compare require two to six original paired prefixes before the Shadowsocks middle and final.");
                    AndroidStandardExitStore.validateImportedHostnamePolicy(imported);
                } else AndroidNumericAddress.parse(imported.server);
            }
        }
        if(size>AndroidNodeStore.MAX_CHAIN_SOURCE)throw new IllegalStateException("The complete ordered path exceeds its private source bound.");
    }

    private static boolean literalSS(AndroidNodeStore.ChainSource source) {
        try { AndroidNodeChainCapture.requireLiteralImportedSS(source);return true; }
        catch(Exception unavailable) { return false; }
    }

    private static boolean hasCapturedHysteriaFinal(AndroidNodeStore.ChainSource source) throws Exception {
        if(!hasMode(source,"hysteria2"))return false;
        // Preserve the existing Off eligibility; authenticated layers also
        // require this exact node's independently captured outer source.
        String layer=source.profile().optString("start_layer","off");
        if(layer.isEmpty()||"off".equals(layer))return true;
        try {
            // The pure member compiler binds this node's original TLS/password
            // and optional AES/whitening owner. A mode asset alone is not proof.
            AndroidNodeChainCapture.memberInput(source,"hysteria2",AndroidNodeChainCapture.executionProfile(source.profile()));
            return true;
        } catch(Exception unavailable) { return false; }
    }

    private static boolean hasMode(AndroidNodeStore.ChainSource source,String mode) throws Exception {
        try { source.requirePairedIdentity(); }
        catch(IllegalStateException unavailable) { return false; }
        JSONObject assets=source.bundle().getJSONObject("profiles").optJSONObject(mode);
        return assets!=null&&assets.length()>0;
    }
}
