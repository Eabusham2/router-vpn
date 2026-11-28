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
    private boolean unfinished;
    private final String draftIdentity=java.util.UUID.randomUUID().toString();
    private volatile long revision;
    private String execution="local";
    private AndroidNodeCandidateAppendSource.NextChoice appendContinuation;
    private long appendContinuationRevision=-1;

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
    boolean unfinished(){return unfinished;}
    long revision(){return revision;}
    private boolean proxyEntryPrefix(){return (unfinished||members.size()>=2)&&!members.isEmpty()&&!members.get(0).source.imported&&AndroidNodeCandidateAppendSource.proxyEntryMode(members.get(0).mode);}
    List<AndroidNodeCandidateAppendSource.NextChoice> appendNextChoices()throws Exception {
        requireCurrent();requireBound();
        List<AndroidNodeCandidateAppendSource.NextChoice> choices=new ArrayList<>(AndroidNodeCandidateAppendSource.nextChoices(proxyEntryPrefix()));
        List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();List<String> modes=new ArrayList<>();
        for(Member member:members){sources.add(member.source);modes.add(member.mode);}
        if(AndroidNodeCandidateAppendSource.permitsExecution(sources,modes,"router-vpn","shadowsocks","server")) {
            choices.add(new AndroidNodeCandidateAppendSource.NextChoice("router-vpn","shadowsocks","server"));
            choices.add(new AndroidNodeCandidateAppendSource.NextChoice("router-vpn","shadowsocks","auto"));
        }
        return Collections.unmodifiableList(choices);
    }
    static String executionTitle(String value) {
        switch(value) {
            case "local":return "Local";
            case "server":return "Server";
            case "auto":return "Compare both";
            default:throw new IllegalArgumentException("Choose Local, Server or Compare both.");
        }
    }
    void setExecution(String value) throws Exception {
        requireCurrent();executionTitle(value);if(unfinished&&!"local".equals(value))throw new IllegalStateException("Finish this prefix before selecting Server or Compare.");String previous=execution;execution=value;
        try { requireBound(); } catch(Exception invalid) { execution=previous;throw invalid; }
        revision++;
    }

    AndroidNodeStore.ChainCapture matchingSavedPath() throws Exception {
        requireCurrent();
        if(unfinished)return null;
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

    boolean canMeasureThrough(int position) {
        if(unfinished)return false;
        List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();List<String> modes=new ArrayList<>();
        for(Member member:members){sources.add(member.source);modes.add(member.mode);}
        if(AndroidNodeChainCapture.responsePrefix(sources,modes,position,execution))return true;
        if(!"local".equals(execution) || !AndroidNodeChainCapture.localPacketPrefix(sources,modes,position))return false;
        try { AndroidNodeChainCapture.requireCompleteShape(sources,modes,execution);return true; }
        catch(Exception unavailable){return false;}
    }

    java.util.concurrent.Callable<AndroidNodeStore.ChainCapture> candidateDraftCapture(int prefix) throws Exception {
        long capturedRevision=revision;
        requireCurrent();requireBound();
        if(unfinished)throw new IllegalStateException("Choose an explicit next transport for this unfinished prefix.");
        String capturedExecution=execution;
        List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();List<String> modes=new ArrayList<>();
        for(Member member:members){sources.add(member.source);modes.add(member.mode);}
        return ()->"local".equals(capturedExecution)
                ?catalog.captureCandidateDraft(sources,modes,prefix,()->revision==capturedRevision)
                :catalog.captureSelectedCandidateDraft(sources,modes,prefix,capturedExecution,()->revision==capturedRevision);
    }

    java.util.concurrent.Callable<AndroidNodeStore.ChainCapture> candidateAppendCapture(String nextKind,String nextMode,String requestedExecution)throws Exception {
        requireCurrent();requireBound();
        if(!unfinished||!"local".equals(execution)||members.isEmpty()||members.size()>=AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH
                ||!AndroidNodeCandidateAppendSource.supportsNext(nextKind,nextMode,proxyEntryPrefix()))throw new IllegalStateException("Choose the next transport for the original unfinished prefix.");
        long capturedRevision=revision;
        List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();List<String> modes=new ArrayList<>();
        for(Member member:members){sources.add(member.source);modes.add(member.mode);}
        if(!AndroidNodeCandidateAppendSource.permitsExecution(sources,modes,nextKind,nextMode,requestedExecution))
            throw new IllegalStateException("This prefix cannot continue the original Server or Compare request. Choose an explicit Local next-node measurement or finish the draft.");
        String originalRevision=draftIdentity+"-"+capturedRevision;
        return ()->catalog.captureCandidateAppend(sources,modes,nextKind,nextMode,requestedExecution,originalRevision,
                ()->unfinished&&revision==capturedRevision);
    }

    List<AndroidNodeStore.Node> prefixStartChoices()throws Exception {
        requireCurrent();List<AndroidNodeStore.Node> result=new ArrayList<>();
        for(AndroidNodeStore.Node node:catalog.nodes)if(!prefixStartModes(node.id).isEmpty())result.add(node);
        return result;
    }
    List<String> prefixStartModes(String id)throws Exception {
        requireCurrent();AndroidNodeStore.ChainSource source=catalog.source(id);List<String> result=new ArrayList<>();
        for(String mode:AndroidNodeCandidateAppendSource.NEXT_MODES)
            if(AndroidNodeCandidateAppendSource.permitsPrefixMember(source,mode,0,AndroidNodeCandidateAppendSource.proxyEntryMode(mode))&&hasMode(source,mode))result.add(mode);
        return result;
    }
    void beginPrefix(String id,String mode)throws Exception {
        requireCurrent();
        if(!prefixStartModes(id).contains(mode))throw new IllegalStateException("Choose an original paired packet entry or literal Shadowsocks or Hysteria2 entry with Start Layer Off.");
        List<Member> previous=new ArrayList<>(members);boolean wasUnfinished=unfinished;String previousExecution=execution;
        members.clear();members.add(new Member(catalog.source(id),mode));unfinished=true;execution="local";
        try{requireBound();}catch(Exception failed){members.clear();members.addAll(previous);unfinished=wasUnfinished;execution=previousExecution;throw failed;}
        revision++;
    }

    private boolean canExtendOriginalRoute() throws Exception {
        if (!List.of("local","server","auto").contains(execution) || members.size() < 8 || members.size() >= AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH) return false;
        if(proxyEntryPrefix()) {
            List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();List<String> modes=new ArrayList<>();
            for(Member member:members){sources.add(member.source);modes.add(member.mode);}
            return AndroidNodeChainCapture.pairedProxyEntryLocalSource(sources,modes,execution);
        }
        if (members.get(members.size()-1).source.imported) return externalExitPrefix();
        boolean stream=false;
        for(int i=0;i<members.size();i++) {
            Member member=members.get(i);boolean last=i==members.size()-1;
            if(member.source.imported) {
                if(i==0||last||!"shadowsocks".equals(member.mode))return false;
                if(!literalSS(member.source) && (!"local".equals(execution)||!AndroidStandardExitStore.importedHostname(member.source.external())))return false;
                stream=true;
            } else if (!java.util.Arrays.asList("","off").contains(member.source.profile().optString("start_layer","off"))
                    || (last ? !"shadowsocks".equals(member.mode) : !"shadowsocks".equals(member.mode)&&(stream||!PREFIX_MODES.contains(member.mode))))return false;
            else if("shadowsocks".equals(member.mode)){if(!last&&!"local".equals(execution)&&!qualifiesPairedStream(i,member.source,false))return false;stream=true;}
        }
        if(!"local".equals(execution) && (!PREFIX_MODES.contains(members.get(0).mode)||!members.get(1).source.imported))return false;
        return true;
    }

    boolean canAddPrefix() throws Exception {
        if(unfinished)return members.size()<AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH-1&&!choices(false).isEmpty();
        return !members.isEmpty()&&(members.size()<8||canExtendOriginalRoute())&&members.size()<catalog.nodes.size()&&!choices(false).isEmpty();
    }

    List<AndroidNodeStore.Node> choices(boolean finalNode) throws Exception {
        requireCurrent();
        List<AndroidNodeStore.Node> result=new ArrayList<>();
        for(AndroidNodeStore.Node node:catalog.nodes) {
            boolean used=false;
            for(int i=0;i<members.size();i++)if(members.get(i).source.id.equals(node.id)&&(!finalNode||unfinished||i!=members.size()-1))used=true;
            if(!used&&(finalNode?!finalModes(node.id).isEmpty():!prefixModes(node.id).isEmpty()))result.add(node);
        }
        requireCurrent();return result;
    }

    List<String> prefixModes(String id) throws Exception {
        requireCurrent();AndroidNodeStore.ChainSource source=catalog.source(id);List<String> result=new ArrayList<>();
        if(unfinished) {
            int position=members.size();
            for(int i=0;i<members.size();i++)if(members.get(i).source.id.equals(id))position=i;
            for(String mode:AndroidNodeCandidateAppendSource.NEXT_MODES)
                if(AndroidNodeCandidateAppendSource.permitsPrefixMember(source,mode,position,proxyEntryPrefix()))result.add(mode);
            return Collections.unmodifiableList(result);
        }
        if(proxyEntryPrefix()&&"local".equals(execution)) {
            int position=members.size()-1;
            for(int i=0;i<members.size()-1;i++)if(members.get(i).source.id.equals(id))position=i;
            for(String mode:AndroidNodeCandidateAppendSource.NEXT_MODES)
                if(AndroidNodeCandidateAppendSource.permitsPrefixMember(source,mode,position,true))result.add(mode);
            return Collections.unmodifiableList(result);
        }
        if (!members.isEmpty() && members.get(members.size()-1).source.imported) {
            if (externalExitPrefix()) {
                if (members.get(0).source.id.equals(id)) {
                    for (String mode : PREFIX_MODES) if (hasMode(source, mode)) result.add(mode);
                } else if (members.size()<AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH && source.imported && literalSS(source)) {
                    result.add("shadowsocks");
                }
            }
            return Collections.unmodifiableList(result);
        }
        if (members.size() >= 8) {
            if (canExtendOriginalRoute()) {
                if(source.imported && canAppendImportedSS(source) || !source.imported && canAppendPairedStream(source))result.add("shadowsocks");
                boolean allWireGuard=true;
                for(int i=0;i<members.size()-1;i++)allWireGuard &= !members.get(i).source.imported&&"wg".equals(members.get(i).mode);
                if("local".equals(execution)&&allWireGuard && !source.imported && java.util.Arrays.asList("","off").contains(source.profile().optString("start_layer","off")) && hasMode(source,"wg"))result.add("wg");
            }
            requireCurrent();return Collections.unmodifiableList(result);
        }
        if(source.imported){
            String mode=AndroidExternalPolicy.protocol(source.external().protocol);boolean variablePrefix="shadowsocks".equals(mode)||"socks5".equals(mode)||"http-connect".equals(mode)||"https-connect".equals(mode)||"openvpn".equals(mode);
            boolean paired=true;for(Member member:members)paired&=!member.source.imported;
            boolean independent="shadowsocks".equals(mode)&&canAppendImportedSS(source) &&
                    ("local".equals(execution)||!members.isEmpty()&&!members.get(0).source.imported);
            if(members.size()==1 && "local".equals(execution) && independent && "shadowsocks".equals(members.get(0).mode))result.add(mode);
            else if(members.size()>=2&&members.size()<8&&(variablePrefix||members.size()==2)&&(paired||independent)&&"shadowsocks".equals(members.get(members.size()-1).mode))result.add(mode);
        }
        else if(members.isEmpty() || !members.get(0).source.imported) {
            for(String mode:PREFIX_MODES)if(hasMode(source,mode))result.add(mode);
            if (canAppendPairedStream(source)) result.add("shadowsocks");
        }
        if(!members.isEmpty() && members.get(0).source.imported && members.size()>=3)result.clear();
        requireCurrent();return Collections.unmodifiableList(result);
    }

    static String prefixModeTitle(String mode) {
        switch(mode) {
            case "shadowsocks":return "Shadowsocks 2022";
            case "hysteria2":return "Hysteria2";
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

    private boolean externalExitPrefix() throws Exception {
        if (members.isEmpty()) return false;
        Member first=members.get(0);
        if (!catalog.selectedId.equals(first.source.id) || first.source.imported || !hasMode(first.source,"wg")
                || !first.source.supportsExternalExitEntryLayer()) return false;
        if (members.size()==1) return true;
        if (!PREFIX_MODES.contains(first.mode) || !hasMode(first.source, first.mode)) return false;
        for (int i=1;i<members.size()-1;i++) {
            Member middle=members.get(i);
            if (!middle.source.imported || !"shadowsocks".equals(middle.mode) || !literalSS(middle.source)) return false;
        }
        return true;
    }

    List<String> finalModes(String id) throws Exception {
        requireCurrent();AndroidNodeStore.ChainSource source=catalog.source(id);List<String> result=new ArrayList<>();
        if(proxyEntryPrefix()) {
            if("local".equals(execution))for(String mode:List.of("shadowsocks","hysteria2"))
                if(AndroidNodeCandidateAppendSource.permitsPrefixMember(source,mode,1,true))result.add(mode);
            return Collections.unmodifiableList(result);
        }
        if(!source.imported) {
            if(hasMode(source,"shadowsocks"))result.add("shadowsocks");
            boolean imported=false;for(Member member:members)imported|=member.source.imported;
            if(!imported&&hasCapturedHysteriaFinal(source))result.add("hysteria2");
            boolean packetPrefix="local".equals(execution)&&members.size()+(unfinished?1:0)<=8;
            for(int i=0;packetPrefix&&i<members.size()-(unfinished?0:1);i++) {
                Member prefix=members.get(i);
                packetPrefix=AndroidNodeChainCapture.pairedPacketWithoutStartLayer(prefix.source,prefix.mode);
            }
            if(packetPrefix)for(String mode:PREFIX_MODES) {
                if(!AndroidNodeChainCapture.pairedPacketWithoutStartLayer(source,mode)||!hasMode(source,mode))continue;
                try {
                    String input=AndroidNodeChainCapture.memberInput(source,mode,source.profile());
                    if(Libbox.routerNodeChainResponseCandidateInputSupported(input,mode))result.add(mode);
                } catch(Exception unavailable) { /* Another transport may have a valid source. */ }
            }
        } else if (externalExitPrefix() && literalSS(source)) result.add("shadowsocks");
        requireCurrent();return Collections.unmodifiableList(result);
    }

    static String finalModeTitle(String mode) {
        if("shadowsocks".equals(mode))return "Shadowsocks 2022";
        if("hysteria2".equals(mode))return "Hysteria2";
        if(PREFIX_MODES.contains(mode))return prefixModeTitle(mode);
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
        for(int i=0;i<members.size()-(unfinished?0:1);i++)if(members.get(i).source.id.equals(id))throw new IllegalStateException("Choose a different final node.");
        if(unfinished) {
            members.add(new Member(source,mode));unfinished=false;
            try{requireBound();}catch(Exception failed){members.remove(members.size()-1);unfinished=true;throw failed;}
            revision++;return;
        }
        Member previous=members.isEmpty()?null:members.get(members.size()-1),selected=new Member(source,mode);
        boolean retainEntry = source.imported && members.size()==1;
        if (retainEntry) { members.set(0,new Member(previous.source,"wg")); members.add(selected); }
        else if(members.isEmpty())members.add(selected);else members.set(members.size()-1,selected);
        try { requireBound(); }
        catch(Exception failure) { if(previous==null)members.clear();else { if(retainEntry)members.remove(members.size()-1); members.set(members.size()-1,previous); }throw failure; }
        revision++;
    }

    void addPrefix(String id) throws Exception {
        addPrefix(id,"wg");
    }

    void insertMeasured(AndroidNodeStore.ChainCapture original,int prefix,AndroidNodeStore.ChainSource candidate,
            java.util.function.BooleanSupplier fresh) throws Exception {
        requireCurrent();
        boolean externalFinal=original.members.get(original.members.size()-1).imported;
        if (candidate.imported!=externalFinal || prefix < 1 || prefix >= members.size()-1 || members.size() >= AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH)
            throw new IllegalStateException("This measured node cannot be inserted at the original position.");
        AndroidNodeStore.ChainSource linked = catalog.source(candidate.id);
        if (!linked.profileId.equals(candidate.profileId) || !linked.proofId.equals(candidate.proofId)
                || !java.util.Arrays.equals(linked.bytes(),candidate.bytes()))
            throw new IllegalStateException("The measured candidate has changed. Measure it again.");
        original.editDraft(catalog,prefix,()->{
            if (!fresh.getAsBoolean()) throw new IllegalStateException("The measured candidate expired before insertion.");
            members.add(prefix + 1,new Member(linked,"shadowsocks"));
            try {
                requireBound();
                if (!fresh.getAsBoolean()) throw new IllegalStateException("The measured candidate expired before insertion.");
            } catch (Exception failure) { members.remove(prefix + 1); throw failure; }
            revision++;
            return null;
        });
    }

    void replaceMeasured(AndroidNodeStore.ChainCapture original,int prefix,AndroidNodeStore.ChainSource candidate,String mode,
            java.util.function.BooleanSupplier fresh) throws Exception {
        requireCurrent();
        int position=prefix+1;
        if(!"local".equals(execution)||!execution.equals(original.execution)||!original.measurementOnly()||candidate.imported
                ||prefix<0||position>=members.size()-1||members.size()!=original.members.size()
                ||!NativeSingBoxController.nativeWireGuardFamily(mode)||!mode.equals(original.modes.get(position)))
            throw new IllegalStateException("This measured node cannot replace the original packet successor.");
        for(int i=0;i<members.size();i++) {
            Member retained=members.get(i);AndroidNodeStore.ChainSource captured=original.members.get(i);
            if(!retained.mode.equals(original.modes.get(i))||!retained.source.id.equals(captured.id)
                    ||!java.util.Arrays.equals(retained.source.bytes(),captured.bytes()))
                throw new IllegalStateException("The original measured draft or its suffix changed.");
        }
        AndroidNodeStore.ChainSource linked=catalog.source(candidate.id);
        if(!linked.profileId.equals(candidate.profileId)||!linked.proofId.equals(candidate.proofId)
                ||!java.util.Arrays.equals(linked.bytes(),candidate.bytes()))
            throw new IllegalStateException("The measured candidate has changed. Measure it again.");
        original.editDraft(catalog,prefix,()->{
            if(!fresh.getAsBoolean())throw new IllegalStateException("The measured candidate expired before replacement.");
            Member previous=members.set(position,new Member(linked,mode));
            try {
                requireBound();
                if(!fresh.getAsBoolean())throw new IllegalStateException("The measured candidate expired before replacement.");
            } catch(Exception failure){members.set(position,previous);throw failure;}
            revision++;
            return null;
        });
    }

    void appendMeasured(AndroidNodeStore.ChainCapture original,AndroidNodeStore.ChainSource candidate,String mode,
            java.util.function.BooleanSupplier fresh)throws Exception {
        requireCurrent();
        if(!unfinished||!original.appendDraft()||!"local".equals(execution)||!mode.equals(original.appendMode)
                ||!AndroidNodeCandidateAppendSource.supportsNext(original.appendKind,mode,proxyEntryPrefix())||candidate.imported!="external".equals(original.appendKind)
                ||members.size()!=original.members.size()||members.size()>=AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH)
            throw new IllegalStateException("This measured node belongs to a different unfinished prefix.");
        for(int i=0;i<members.size();i++)if(!members.get(i).mode.equals(original.modes.get(i))
                ||!members.get(i).source.id.equals(original.members.get(i).id)
                ||!java.util.Arrays.equals(members.get(i).source.bytes(),original.members.get(i).bytes()))
            throw new IllegalStateException("The original unfinished prefix changed.");
        AndroidNodeCandidateAppendSource.requireCandidate(candidate,original.appendKind,mode);
        AndroidNodeStore.ChainSource linked=catalog.source(candidate.id);
        if(!linked.profileId.equals(candidate.profileId)||!linked.proofId.equals(candidate.proofId)
                ||!java.util.Arrays.equals(linked.bytes(),candidate.bytes()))throw new IllegalStateException("The measured original candidate changed.");
        original.editDraft(catalog,original.members.size()-1,()->{
            if(!fresh.getAsBoolean())throw new IllegalStateException("The measured append expired before adoption.");
            members.add(new Member(linked,mode));
            try{requireBound();if(!fresh.getAsBoolean())throw new IllegalStateException("The measured append expired before adoption.");}
            catch(Exception failed){members.remove(members.size()-1);throw failed;}
            revision++;appendContinuation=new AndroidNodeCandidateAppendSource.NextChoice(original.appendKind,original.appendMode,original.appendExecution);
            appendContinuationRevision=revision;return null;
        });
    }

    AndroidNodeCandidateAppendSource.NextChoice appendContinuation()throws Exception {
        requireCurrent();
        if(!unfinished||appendContinuation==null||appendContinuationRevision!=revision
                ||!AndroidNodeCandidateAppendSource.supportsNext(appendContinuation.kind,appendContinuation.mode,proxyEntryPrefix()))
            throw new IllegalStateException("The original next-node choice changed after adoption.");
        return appendContinuation;
    }

    void addPrefix(String id,String mode) throws Exception {
        requireCurrent();
        if(unfinished) {
            if(members.size()>=AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH-1)throw new IllegalStateException("Choose a final node within the original traversal budget.");
            for(Member member:members)if(member.source.id.equals(id))throw new IllegalStateException("Choose an unused prefix node.");
            AndroidNodeStore.ChainSource original=catalog.source(id);
            AndroidNodeCandidateAppendSource.requirePrefixMember(original,mode,members.size(),proxyEntryPrefix());
            members.add(new Member(original,mode));
            try{requireBound();}catch(Exception failed){members.remove(members.size()-1);throw failed;}
            revision++;return;
        }
        if(members.isEmpty())throw new IllegalStateException("Choose the final node first.");
        if(members.size()>=8 && !canExtendOriginalRoute())throw new IllegalStateException("This route cannot add another node with its current execution and transports.");
        for(Member member:members)if(member.source.id.equals(id))throw new IllegalStateException("Each ordered position needs a different saved node.");
        AndroidNodeStore.ChainSource source=catalog.source(id);
        if(source.imported&&!"shadowsocks".equals(members.get(members.size()-1).mode))throw new IllegalStateException("An imported middle requires its paired Shadowsocks 2022 final.");
        if(proxyEntryPrefix())AndroidNodeCandidateAppendSource.requirePrefixMember(source,mode,members.size()-1,true);
        else if (!"shadowsocks".equals(mode) || source.imported || !canAppendPairedStream(source)) requirePrefixMode(source,mode);
        int position=members.size()-1;
        if(!source.imported&&members.size()>=3&&members.get(members.size()-2).source.imported&&!literalSS(members.get(members.size()-2).source))position--;
        members.add(position,new Member(source,mode));
        try { requireBound(); }
        catch(Exception failure) { members.remove(position);throw failure; }
        revision++;
    }

    void setPrefixMode(int position,String mode) throws Exception {
        requireCurrent();
        if(position<0||position>=members.size()-(unfinished?0:1))throw new IllegalStateException("Choose an intermediate node to change its transport.");
        AndroidNodeStore.ChainSource source=members.get(position).source;
        if(unfinished||proxyEntryPrefix())AndroidNodeCandidateAppendSource.requirePrefixMember(source,mode,position,position==0?AndroidNodeCandidateAppendSource.proxyEntryMode(mode):proxyEntryPrefix());
        else if (!"shadowsocks".equals(mode) || source.imported || !hasMode(source,mode) || !qualifiesPairedStream(position,source,false)) requirePrefixMode(source,mode);
        Member previous = members.set(position,new Member(source,mode));
        try { requireBound(); }
        catch(Exception failure) { members.set(position,previous); throw failure; }
        revision++;
    }

    private static void requirePrefixMode(AndroidNodeStore.ChainSource source,String mode) throws Exception {
        if(source.imported){AndroidNodeStore.ChainSource.requireImported(source.external());if(!mode.equals(AndroidExternalPolicy.protocol(source.external().protocol)))throw new IllegalStateException("Keep the original imported transport.");return;}
        if(!PREFIX_MODES.contains(mode))throw new IllegalStateException("Choose WireGuard, AmneziaWG Fast or AmneziaWG Strong for this intermediate node.");
        if(!hasMode(source,mode))throw new IllegalStateException("The selected intermediate node has no complete "+prefixModeTitle(mode)+" source.");
    }

    void movePrefix(int position,int destination) throws Exception {
        requireCurrent();
        if(position<0||destination<0||position>=members.size()-(unfinished?0:1)||destination>=members.size()-(unfinished?0:1))
            throw new IllegalStateException("Reorder the intermediate nodes without replacing the final node.");
        Member member=members.remove(position);members.add(destination,member);
        try{requireBound();}catch(Exception failure){members.remove(destination);members.add(position,member);throw failure;}
        revision++;
    }

    void removePrefix(int position) throws Exception {
        requireCurrent();
        if(position<0||position>=members.size()-(unfinished?0:1))throw new IllegalStateException("Choose an intermediate node to remove.");
        Member old=members.remove(position);
        try{requireBound();}catch(Exception failure){members.add(position,old);throw failure;}
        revision++;
    }

    /** Use the real pure native compiler before publishing any selected node. */
    AndroidNodeStore.ChainCapture save() throws Exception {
        requireCurrent();requireBound();
        if(unfinished)throw new IllegalStateException("Choose a real final node before saving this unfinished prefix.");
        if(members.size()<2)throw new IllegalStateException("Add at least one intermediate node before saving.");
        if((members.get(0).source.imported || members.get(members.size()-1).source.imported) && members.size()==2)
            throw new IllegalStateException("Choose a second custom Shadowsocks 2022 node before saving this route.");
        compileCompletePath();
        List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();List<String> modes=new ArrayList<>();
        for(Member member:members){sources.add(member.source);modes.add(member.mode);}
        AndroidNodeStore.ChainCapture captured=profiles.selectOrderedPath(catalog,sources,modes,preferences,execution);
        saved=true;revision++;return captured;
    }

    private String compileCompletePath() throws Exception {
        JSONArray references=new JSONArray();
        for(Member member:members)references.put(new JSONObject().put("id",member.source.profileId).put("mode",member.mode));
        JSONArray inputs=new JSONArray(),identities=new JSONArray();List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();List<String> modes=new ArrayList<>();
        for(int i=0;i<members.size();i++) {
            Member member=members.get(i);JSONObject profile=member.source.profile();
            if(i==(members.get(members.size()-1).source.imported ? 0 : members.size()-1)) {
                profile.put("multihop_enabled",true).put("multihop_execution",execution).put("multihop_nodes",references);
                for(String key:new String[]{"multihop_entry_id","multihop_entry_mode","multihop_exit_id","multihop_exit_mode"})profile.remove(key);
                AndroidNodeStore.orderedSelection(profile);
            }
            inputs.put(AndroidNodeChainCapture.memberInput(member.source,member.mode,"local".equals(execution)?profile:AndroidNodeChainCapture.executionProfile(profile)));
            identities.put(AndroidNodeChainCapture.identityInput(member.source));
            sources.add(member.source);modes.add(member.mode);
        }
        int schema = AndroidNodeChainCapture.sourceSchema(sources,modes);
        if (schema == 8) inputs.put(inputs.length()-1,AndroidNodeChainCapture.externalFinalInput(inputs.getString(0),inputs.getString(inputs.length()-1)));
        String source=new JSONObject().put("schema",schema).put("execution","local").put("nodes",inputs).put("identity_sources",identities).toString();
        if(source.getBytes(StandardCharsets.UTF_8).length>AndroidNodeChainCapture.MAX_INPUT)throw new IllegalStateException("The complete ordered path exceeds its private source bound.");
        if(AndroidNodeChainCapture.sourceSchema(sources,modes)==4) {
            AndroidNodeChainCONNECTCapture preview=AndroidNodeChainCONNECTCapture.compile(source,jsonStrings(inputs),jsonStrings(identities));
            try { if(!"local".equals(execution))AndroidNodeChainCapture.validateCONNECTExecutionSource(preview.source,execution);requireCurrent(); } finally { preview.close(); }
        } else if(AndroidNodeChainCapture.sourceSchema(sources,modes)==3) {
            AndroidNodeChainSOCKSCapture preview=AndroidNodeChainSOCKSCapture.compile(source,jsonStrings(inputs),jsonStrings(identities));
            try { if(!"local".equals(execution))AndroidNodeChainCapture.validateSOCKSExecutionSource(preview.source,execution);requireCurrent(); } finally { preview.close(); }
        } else {
            RouterNodeChain preview=Libbox.newRouterNodeChain(source);
            if(preview==null)throw new IllegalStateException("The native compiler returned no complete ordered path.");
            try {
                if(preview.config()==null||preview.config().isEmpty())throw new IllegalStateException("The native compiler returned no complete ordered graph.");
                if((AndroidNodeChainCapture.pairedHysteriaLocalSource(sources,modes,execution)?sources.size():0)!=preview.pairedHysteriaLocalNodeCount())
                    throw new IllegalStateException("The complete preview lost its original paired Local Hysteria2 family.");
                if((AndroidNodeChainCapture.pairedProxyEntryLocalSource(sources,modes,execution)?sources.size():0)!=preview.pairedProxyEntryLocalNodeCount())
                    throw new IllegalStateException("The complete preview lost its original paired proxy entry.");
                if(!"local".equals(execution))AndroidNodeChainCapture.validateExecutionPlan(preview,execution);
                requireCurrent();
            } finally { preview.close(); }
        }
        return source;
    }

    static final class AppendCompletion {
        private final AndroidOrderedPathSelection owner;
        private final long revision;
        private final String source;
        private final List<AndroidNodeStore.ChainSource> sources;
        private final List<String> modes;
        final String description;
        private AppendCompletion(AndroidOrderedPathSelection owner,long revision,String source) {
            this.owner=owner;this.revision=revision;this.source=source;
            List<AndroidNodeStore.ChainSource> originals=new ArrayList<>();List<String> transports=new ArrayList<>();
            StringBuilder text=new StringBuilder();
            for(Member member:owner.members){
                originals.add(member.source);transports.add(member.mode);
                if(text.length()>0)text.append(" → ");
                text.append(member.source.profileId).append(" (").append(member.mode).append(")");
            }
            sources=Collections.unmodifiableList(originals);modes=Collections.unmodifiableList(transports);
            description=text.toString();
        }
    }
    boolean canCompleteAppend() {
        if(!unfinished||!"local".equals(execution)||members.size()<2||members.size()>AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH)return false;
        Member last=members.get(members.size()-1);
        return !last.source.imported&&List.of("shadowsocks","hysteria2").contains(last.mode);
    }
    AppendCompletion prepareAppendCompletion(Runnable current) throws Exception {
        current.run();requireCurrent();requireBound();
        if(!canCompleteAppend())throw new IllegalStateException("Keep the actual last paired Shadowsocks or Hysteria2 node as the final.");
        long expected=revision;String source=compileCompletePath();
        current.run();requireCurrent();
        if(revision!=expected)throw new IllegalStateException("The original prefix changed before completion.");
        return new AppendCompletion(this,expected,source);
    }
    AndroidConnectionProfileStore.Record saveAppendCompletion(AppendCompletion proposal,String name,Runnable current) throws Exception {
        current.run();requireAppendCompletion(proposal);
        if(!proposal.source.equals(compileCompletePath()))throw new IllegalStateException("The complete original source changed before Save.");
        current.run();requireAppendCompletion(proposal);
        return profiles.appendOrderedProposal(name,proposal.sources,proposal.modes,"local",()->{
            current.run();
            try{requireAppendCompletion(proposal);}
            catch(Exception changed){throw new IllegalStateException("The complete draft changed before saving its named profile.",changed);}
        });
    }
    private void requireAppendCompletion(AppendCompletion proposal) throws Exception {
        requireCurrent();requireBound();
        if(proposal==null||proposal.owner!=this||proposal.revision!=revision||!canCompleteAppend())
            throw new IllegalStateException("The complete draft no longer belongs to this original editor.");
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
        if(unfinished) {
            if(!"local".equals(execution)||members.size()>AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH)throw new IllegalStateException("The unfinished prefix exceeded its original traversal scope.");
            long bytes=0;Set<String> ids=new HashSet<>(),proofs=new HashSet<>();
            for(int i=0;i<members.size();i++) {
                Member member=members.get(i);
                AndroidNodeCandidateAppendSource.requirePrefixMember(member.source,member.mode,i,proxyEntryPrefix());
                if(!ids.add(member.source.profileId)||!proofs.add(member.source.identityKey()))
                    throw new IllegalStateException("The unfinished prefix requires distinct original source identities.");
                bytes+=member.source.bytes().length;
            }
            if(bytes>AndroidNodeStore.MAX_CHAIN_SOURCE)throw new IllegalStateException("The unfinished prefix exceeds its private source bound.");
            return;
        }
        if(!members.isEmpty()) {
            Member last=members.get(members.size()-1);
            if(!finalModes(last.source.id).contains(last.mode))throw new IllegalStateException("The ordered final transport is incompatible with its original source or imported middle.");
        }
        long size=0;Set<String> proofs=new HashSet<>();
        for(Member member:members) {
            size+=member.source.bytes().length;
            if(!proofs.add(member.source.identityKey()))throw new IllegalStateException("Ordered members must retain distinct paired node identities.");
        }
        if(size>AndroidNodeStore.MAX_CHAIN_SOURCE)throw new IllegalStateException("The complete ordered path exceeds its private source bound.");
        // The first imported choice can remain a cancellable draft before the
        // second imported source is chosen. Save still requires the full graph.
        if (members.size()==2 && members.get(1).source.imported && externalExitPrefix()) return;
        if(members.size()==2 && members.get(0).source.imported && "local".equals(execution)
                && literalSS(members.get(0).source) && "shadowsocks".equals(members.get(1).mode))return;
        List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();for(Member member:members)sources.add(member.source);
        List<String> modes=new ArrayList<>();for(Member member:members)modes.add(member.mode);
        int schema=AndroidNodeChainCapture.sourceSchema(sources,modes);
        AndroidNodeChainCapture.requireCompleteShape(sources,modes,execution);
        if(!"local".equals(execution)&&!members.isEmpty()) {
            boolean hysteriaFinal=schema==1&&"hysteria2".equals(members.get(members.size()-1).mode);
            if(hysteriaFinal) {
                if(members.size()<2||members.size()>8)throw new IllegalStateException("Paired Hysteria2 execution requires two to eight original nodes.");
                for(int i=0;i<members.size()-1;i++)if(members.get(i).source.imported||!List.of("wg","awg2-fast","awg2-strong").contains(members.get(i).mode))
                    throw new IllegalStateException("Hysteria2 execution requires only original paired packet prefixes.");
            }
            if(schema>6&&schema!=8||schema==3&&(members.size()<3||members.size()>8)||schema==4&&(members.size()<3||members.size()>8)||schema==5&&(members.size()<3||members.size()>8)||!hysteriaFinal&&!"shadowsocks".equals(members.get(members.size()-1).mode))
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
    }

    private boolean canAppendPairedStream(AndroidNodeStore.ChainSource source) throws Exception {
        if (members.isEmpty() || !hasMode(source,"shadowsocks")) return false;
        try { return qualifiesPairedStream(members.size()-1,source,true); }
        catch (Exception unavailable) { return false; }
    }

    private boolean qualifiesPairedStream(int position, AndroidNodeStore.ChainSource source, boolean insert) throws Exception {
        List<AndroidNodeStore.ChainSource> sources = new ArrayList<>();
        List<String> modes = new ArrayList<>();
        for (Member member : members) { sources.add(member.source); modes.add(member.mode); }
        if (insert) {
            sources.add(position, source); modes.add(position, "shadowsocks");
        } else {
            sources.set(position, source); modes.set(position, "shadowsocks");
        }
        return AndroidNodeChainCapture.pairedStreamInterior(sources, modes, execution, position);
    }

    private boolean canAppendImportedSS(AndroidNodeStore.ChainSource source) {
        if(members.isEmpty())return false;
        List<AndroidNodeStore.ChainSource> sources=new ArrayList<>();
        List<String> modes=new ArrayList<>();
        for(Member member:members){sources.add(member.source);modes.add(member.mode);}
        sources.add(members.size()-1,source);modes.add(members.size()-1,"shadowsocks");
        try { return !AndroidNodeChainCapture.requireMixedImports(sources,modes)||"local".equals(execution); }
        catch(Exception unavailable){return false;}
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
