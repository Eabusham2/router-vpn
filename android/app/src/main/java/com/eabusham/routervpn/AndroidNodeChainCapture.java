package com.eabusham.routervpn;

import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterNodeChain;
import io.nekohasekai.libbox.RouterNodeChainExecution;
import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Complete private source for one native ordered graph. Compilation opens no
 * VPN, proves no connection, and never substitutes the final node for control. */
final class AndroidNodeChainCapture implements AutoCloseable {
    static final int MAX_INPUT = 40 * 1024 * 1024;
    static final String SESSION_FILE = "routervpn-node-chain.json";
    final RouterNodeChain plan;
    final AndroidNodeChainSOCKSCapture socks;
    final AndroidNodeChainCONNECTCapture connect;
    final String sourceInput, launchInput, config, sourceSHA256, configSHA256, selectionExecution;
    final List<String> memberInputs, identityInputs;
    final boolean strict, homeLANAccess, openVPN, multipleImported;
    private final AndroidNodeStore.ChainCapture original;

    static boolean selectedResponseWinner(String requested, String winner) {
        return "server".equals(winner) && ("server".equals(requested) || "auto".equals(requested))
                || "local".equals(winner) && "auto".equals(requested);
    }

    // Source-only chooser preview. Only the original native compiler can
    // authorize this response metric or open a closed prefix preparation.
    static boolean responsePrefix(List<AndroidNodeStore.ChainSource> sources,List<String> modes,int prefix,String execution) {
        if (sources.size()!=modes.size()||prefix<1||prefix>=sources.size()-1) return false;
        if ("auto".equals(execution) || "server".equals(execution)) {
            if (sources.size() >= 4) {
                try {
                    List<Boolean> imported = new ArrayList<>();
                    java.util.Set<String> profiles = new java.util.HashSet<>(), proofs = new java.util.HashSet<>();
                    for (AndroidNodeStore.ChainSource member : sources) {
                        imported.add(member.imported);
                        if (!profiles.add(member.profileId)
                                || !java.util.Arrays.asList("", "off").contains(member.profile().optString("start_layer", "off"))) return false;
                        if (member.imported) requireLiteralImportedSS(member);
                        else if (!member.proofId.matches("[0-9a-f]{64}") || !proofs.add(member.proofId)) return false;
                    }
                    return selectedStreamLayout(modes, imported) && (prefix == sources.size()-2
                            || sources.size() < AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH);
                } catch (Exception unavailable) { return false; }
            }
            if (prefix != 1 || modes.size() != 3 || !List.of("wg", "awg2-fast", "awg2-strong").contains(modes.get(0))
                    || !modes.subList(1, 3).stream().allMatch("shadowsocks"::equals)
                    || sources.get(0).imported || !sources.get(1).imported || sources.get(2).imported) return false;
            try {
                requireLiteralImportedSS(sources.get(1));
                for (AndroidNodeStore.ChainSource member : sources) {
                    if (!java.util.Arrays.asList("", "off").contains(member.profile().optString("start_layer", "off"))) return false;
                    if (!member.imported && !member.proofId.matches("[0-9a-f]{64}")) return false;
                }
                return true;
            } catch (Exception unavailable) { return false; }
        }
        if (!"local".equals(execution)) return false;
        try {
            int last=sources.size()-1;
            if (sources.get(last).imported) return sourceSchema(sources,modes)==8;
            if ("shadowsocks".equals(modes.get(prefix))) {
                for(int i=1;i<last;i++) {
                    if(!sources.get(i).imported&&"shadowsocks".equals(modes.get(i)))
                        return pairedStreamInterior(sources,modes,execution,i);
                }
            }
            if (sources.get(0).imported || !sources.get(prefix).imported || sources.get(last).imported
                    || !"shadowsocks".equals(modes.get(last))
                    || !java.util.Arrays.asList("", "off").contains(sources.get(last).profile().optString("start_layer", "off"))) return false;
            int schema=sourceSchema(sources,modes);
            int end = prefix;
            if (schema==6) requireCompleteShape(sources,modes,execution);
            if (sources.size() > 8) {
                if (schema != 6) return false;
                end = last - 1;
            }
            boolean stream = false;
            for (int i = 0; i <= end; i++) {
                AndroidNodeStore.ChainSource source = sources.get(i);
                if (source.imported) {
                    if (!"shadowsocks".equals(modes.get(i))) return false;
                    if (schema==2 && i==prefix || schema==6 && AndroidStandardExitStore.importedHostname(source.external())) {
                        // The native imported-member parser preserves a hostname only
                        // with its original Custom TCP literal transport resolver.
                        memberInput(source, modes.get(i), source.profile());
                    } else {
                        requireLiteralImportedSS(source);
                    }
                    stream = true;
                } else if (stream || !java.util.Arrays.asList("wg", "awg2-fast", "awg2-strong").contains(modes.get(i))
                        || !source.proofId.matches("[0-9a-f]{64}")
                        || !java.util.Arrays.asList("", "off").contains(source.profile().optString("start_layer", "off"))) return false;
            }
            return true;
        } catch(Exception unavailable){return false;}
    }

    boolean ownsSelectedCandidatePrefix(AndroidNodeStore.ChainCapture source, int position) {
        if (!ownsSource(source) || position < 0 || position >= source.members.size() - 1
                || position != 0 && plan == null) return false;
        AndroidNodeStore.ChainSource member = source.members.get(position);
        if (member.imported) {
            return ("auto".equals(source.execution) || "server".equals(source.execution)) && (multipleImported || source.members.size() == 3)
                    && identityInputs.get(position).isEmpty()
                    && responsePrefix(source.members,source.modes,position,source.execution);
        }
        return !member.imported && member.proofId.matches("[0-9a-f]{64}")
                && !identityInputs.get(position).isEmpty()
                && (java.util.Arrays.asList("wg", "awg2-fast", "awg2-strong").contains(source.modes.get(position))
                    || multipleImported && ("auto".equals(source.execution) || "server".equals(source.execution))
                    && responsePrefix(source.members,source.modes,position,source.execution));
    }

    static AndroidNodeChainCapture compile(AndroidNodeStore.ChainCapture original) throws Exception {
        return compile(original,-1);
    }

    static AndroidNodeChainCapture compile(AndroidNodeStore.ChainCapture original,int candidatePrefix) throws Exception {
        return compileInputs(original,memberInputs(original,candidatePrefix));
    }

    private Object selectedCandidatePurpose;
    static AndroidNodeChainCapture compileSelectedCandidateDraft(AndroidNodeStore.ChainCapture original,Object purpose)throws Exception {
        List<String> inputs=memberInputs(original,original.selectedCandidateReferences(purpose));
        AndroidNodeChainCapture captured=compileInputs(original,inputs);
        captured.selectedCandidatePurpose=purpose;
        try { captured.requireCurrent();return captured; }
        catch(Exception failed){try{captured.close();}catch(Exception cleanup){failed.addSuppressed(cleanup);}throw failed;}
    }

    private static AndroidNodeChainCapture compileInputs(AndroidNodeStore.ChainCapture original,List<String> inputs)throws Exception {
        List<String> identities = identityInputs(original);
        String source = sourceInput(original, inputs, identities);
        if ((sourceSchema(original.members,original.modes) == 3 || sourceSchema(original.members,original.modes) == 4)) return new AndroidNodeChainCapture(original, inputs, identities, source);
        RouterNodeChain plan = Libbox.newRouterNodeChain(source);
        try { return new AndroidNodeChainCapture(original, inputs, identities, source, plan); }
        catch (Exception failure) { try { plan.close(); } catch (Exception close) { failure.addSuppressed(close); } throw failure; }
    }

    static AndroidNodeChainCapture reopen(String input, AndroidNodeStore.ChainCapture original) throws Exception {
        List<String> inputs = memberInputs(original,-1);
        List<String> identities = identityInputs(original);
        if ((sourceSchema(original.members,original.modes) == 3 || sourceSchema(original.members,original.modes) == 4)) {
            AndroidNodeChainCapture captured = compile(original);
            if (!input.equals(captured.launchInput)) { captured.close(); throw new IllegalStateException("The typed private source differs from its original complete capture."); }
            return captured;
        }
        RouterNodeChain plan = Libbox.routerNodeChainLaunch(bounded(input, MAX_INPUT));
        try {
            AndroidNodeChainCapture capture = new AndroidNodeChainCapture(original, inputs, identities, sourceInput(original, inputs, identities), plan);
            if (!input.equals(capture.launchInput)) throw new IllegalStateException("The private ordered launch source is not its original canonical capture.");
            return capture;
        } catch (Exception failure) { try { plan.close(); } catch (Exception close) { failure.addSuppressed(close); } throw failure; }
    }

    private static String sourceInput(AndroidNodeStore.ChainCapture original, List<String> inputs, List<String> identities) throws Exception {
        // Reconstruct only from the original captured members, never by removing
        // receipt fields from an unchecked private launch document.
        return bounded(new JSONObject().put("schema", sourceSchema(original.members,original.modes)).put("execution", "local")
                .put("nodes", new JSONArray(inputs)).put("identity_sources",new JSONArray(identities)).toString(), MAX_INPUT);
    }

    private AndroidNodeChainCapture(AndroidNodeStore.ChainCapture original, List<String> inputs, List<String> identities, String source, RouterNodeChain plan) throws Exception {
        if (plan == null) throw new IllegalStateException("The native ordered compiler returned no source owner.");
        this.original = original; this.plan = plan; socks = null; connect = null;
        int schema = sourceSchema(original.members,original.modes);
        openVPN = schema == 5; multipleImported = schema == 6; selectionExecution = original.execution;
        if (inputs.size() != original.members.size()) throw new IllegalStateException("The native input omitted an original ordered member.");
        memberInputs = Collections.unmodifiableList(new ArrayList<>(inputs));
        identityInputs = Collections.unmodifiableList(new ArrayList<>(identities));
        sourceInput = source;
        launchInput = bounded(plan.launchInput(), MAX_INPUT);
        config = bounded(plan.config(), 4 * 1024 * 1024);
        sourceSHA256 = plan.sourceSHA256(); configSHA256 = plan.configSHA256();
        JSONObject record = new JSONObject(launchInput);
        if (!"routervpn-node-chain-launch-input".equals(record.getString("kind")) || record.getInt("schema") != sourceSchema(original.members,original.modes)
                || !"local".equals(record.getString("execution")) || !sourceSHA256.matches("[0-9a-f]{64}")
                || !configSHA256.equals(digest(config)) || !sourceSHA256.equals(record.getString("source_sha256"))
                || !configSHA256.equals(record.getString("config_sha256")) || !configSHA256.equals(record.getString("original_config_sha256"))) {
            throw new IllegalStateException("The ordered native graph differs from its original private source.");
        }
        for (String key : new String[]{"projection_kind", "session_id", "target_os", "restored_mtu"}) {
            if (record.has(key)) throw new IllegalStateException("An Android source cannot borrow another platform's native projection.");
        }
        JSONArray returned = record.getJSONArray("nodes");
        if (returned.length() != memberInputs.size()) throw new IllegalStateException("The native graph omitted an original ordered member.");
        JSONArray returnedIdentities=record.getJSONArray("identity_sources");
        if(returnedIdentities.length()!=identityInputs.size()||identityInputs.size()!=memberInputs.size())throw new IllegalStateException("The native graph omitted an original paired identity source.");
        boolean protect = false, lan = true;
        for (int i = 0; i < returned.length(); i++) {
            if (!memberInputs.get(i).equals(returned.getString(i))) throw new IllegalStateException("The native graph reordered or replaced an original member.");
            if(!identityInputs.get(i).equals(returnedIdentities.getString(i)))throw new IllegalStateException("The native graph reordered or replaced an original paired identity source.");
            JSONObject profile = original.members.get(i).profile();
            String policy = profile.optString("kill_switch_policy", profile.optBoolean("kill_switch", false) ? "on-connect" : "off");
            if (!java.util.Arrays.asList("off", "on-connect", "always").contains(policy)) throw new IllegalStateException("An ordered member has an invalid protection policy.");
            protect |= !"off".equals(policy) || profile.optBoolean("kill_switch", false);
            lan &= profile.optBoolean("home_lan_access", true);
        }
        strict = protect; homeLANAccess = lan;
        original.requireCurrent();
    }

    private AndroidNodeChainCapture(AndroidNodeStore.ChainCapture original, List<String> inputs, List<String> identities, String source) throws Exception {
        this.original=original; plan=null; openVPN=false; multipleImported=false; selectionExecution=original.execution;
        boolean isCONNECT=sourceSchema(original.members,original.modes)==4;
        int count=original.members.size();
        if (!"local".equals(selectionExecution) && !(java.util.Arrays.asList("server","auto").contains(selectionExecution) && count>=3&&count<=8)) throw new IllegalStateException("SOCKS5 and CONNECT Server or Compare require three to eight complete original nodes.");
        socks=isCONNECT?null:AndroidNodeChainSOCKSCapture.compile(source,inputs,identities);
        connect=isCONNECT?AndroidNodeChainCONNECTCapture.compile(source,inputs,identities):null;
        try {
            memberInputs=Collections.unmodifiableList(new ArrayList<>(inputs));
            identityInputs=Collections.unmodifiableList(new ArrayList<>(identities));
            sourceInput=source; launchInput=connect!=null?connect.source:socks.source; config=connect!=null?connect.config:socks.config;
            sourceSHA256=connect!=null?connect.sourceSHA256:socks.sourceSHA256; configSHA256=connect!=null?connect.configSHA256:socks.configSHA256;
            boolean protect=false,lan=true;
            for (AndroidNodeStore.ChainSource member:original.members) {
                JSONObject profile=member.profile();
                String policy=profile.optString("kill_switch_policy",profile.optBoolean("kill_switch",false)?"on-connect":"off");
                if(!java.util.Arrays.asList("off","on-connect","always").contains(policy))throw new IllegalStateException("An ordered member has an invalid protection policy.");
                protect|=!"off".equals(policy)||profile.optBoolean("kill_switch",false);
                lan&=profile.optBoolean("home_lan_access",true);
            }
            strict=protect;homeLANAccess=lan;original.requireCurrent();
        } catch(Exception failure) { try{if(connect!=null)connect.close();else socks.close();}catch(Exception cleanup){failure.addSuppressed(cleanup);}throw failure; }
    }

    private static List<String> identityInputs(AndroidNodeStore.ChainCapture original) throws Exception {
        original.requireCurrent();List<String> result=new ArrayList<>();
        for(AndroidNodeStore.ChainSource member:original.members)result.add(identityInput(member));
        original.requireCurrent();return result;
    }

    static String identityInput(AndroidNodeStore.ChainSource member) throws Exception {
        if(member.imported)return "";
        member.requirePairedIdentity();
        return bounded(member.bundle().getJSONObject("profiles").getJSONObject("wg").toString(),16*1024*1024);
    }

    static String candidateSourceInput(AndroidNodeStore.ChainCapture original,int prefix) throws Exception {
        List<String> inputs=memberInputs(original,original.measurementOnly()?prefix:-1);
        return sourceInput(original,inputs,identityInputs(original));
    }

    private static List<String> memberInputs(AndroidNodeStore.ChainCapture original,int candidatePrefix) throws Exception {
        if (original == null) throw new IllegalStateException("The original selected ordered source is missing.");
        original.requireCurrent();
        return memberInputs(original,original.references(candidatePrefix));
    }
    private static List<String> memberInputs(AndroidNodeStore.ChainCapture original,JSONArray selected)throws Exception {
        original.requireCurrent();
        if (selected.length() != original.members.size() || selected.length() != original.modes.size()) throw new IllegalStateException("The original ordered capture is incomplete.");
        List<String> inputs = new ArrayList<>();
        for (int i = 0; i < selected.length(); i++) {
            AndroidNodeStore.ChainSource member = original.members.get(i);
            JSONObject profile = member.profile(), reference = selected.getJSONObject(i);
            String mode = original.modes.get(i);
            if (!member.profileId.equals(reference.getString("id")) || !mode.equals(reference.getString("mode"))) {
                throw new IllegalStateException("The ordered member changed its original position or exact mode.");
            }
            boolean externalExit = original.members.get(selected.length()-1).imported;
            if((original.selectedCandidateDraft() || original.measurementOnly() && (selected.length()>8 || externalExit))
                    && i==(externalExit ? 0 : selected.length()-1)){
                profile.put("multihop_enabled",true).put("multihop_execution",original.execution).put("multihop_nodes",selected);
                for(String key:new String[]{"multihop_entry_id","multihop_entry_mode","multihop_exit_id","multihop_exit_mode"})profile.remove(key);
                AndroidNodeStore.orderedSelection(profile);
            }
            inputs.add(memberInput(member, mode, "local".equals(original.execution) ? profile : executionProfile(profile)));
        }
        if (sourceSchema(original.members, original.modes) == 8) {
            int last = inputs.size() - 1;
            inputs.set(last, externalFinalInput(inputs.get(0), inputs.get(last)));
        }
        original.requireCurrent();
        return inputs;
    }

    /** Startup controls schedule a connection; they do not change its native
     * execution source. Full original bundle bytes remain owned by ChainCapture. */
    static String externalFinalInput(String entry, String imported) throws Exception {
        return bounded(Libbox.routerNodeChainExternalFinalFromEntry(entry, imported), MAX_INPUT);
    }

    static JSONObject executionProfile(JSONObject profile) throws Exception {
        JSONObject result=new JSONObject(profile.toString());
        result.remove("startup_mode");result.remove("auto_connect");
        return result;
    }

    /** Validate Server/Compare before a saved-profile transaction publishes any
     * node, preference or credential reference. The native preparation stays closed. */
    static void validateExecutionSources(List<AndroidNodeStore.ChainSource> members,List<String> modes,String execution) throws Exception {
        if (!java.util.Arrays.asList("server","auto").contains(execution) || members==null || modes==null
                || members.size()!=modes.size() || members.size()<2)
            throw new IllegalStateException("The ordered execution preview lost its complete original graph.");
        requireCompleteShape(members,modes,execution);
        JSONObject control=members.get(members.size()-1).profile();
        JSONArray selected=AndroidNodeStore.orderedSelection(control);
        if (!execution.equals(control.getString("multihop_execution")) || selected.length()!=members.size())
            throw new IllegalStateException("The staged ordered execution differs from its final source.");
        JSONArray inputs=new JSONArray(),identities=new JSONArray();
        for(int i=0;i<members.size();i++) {
            AndroidNodeStore.ChainSource member=members.get(i);JSONObject reference=selected.getJSONObject(i);
            if(!member.profileId.equals(reference.getString("id")) || !modes.get(i).equals(reference.getString("mode")))
                throw new IllegalStateException("The staged execution reordered or replaced an original member.");
            inputs.put(memberInput(member,modes.get(i),executionProfile(member.profile())));
            identities.put(identityInput(member));
        }
        String input=bounded(new JSONObject().put("schema",sourceSchema(members,modes)).put("execution","local")
                .put("nodes",inputs).put("identity_sources",identities).toString(),MAX_INPUT);
        if (sourceSchema(members,modes)==4) {
            if(members.size()<3||members.size()>8)throw new IllegalStateException("CONNECT Server and Compare require three to eight complete original members.");
            validateCONNECTExecutionSource(input,execution);
            return;
        }
        if (sourceSchema(members,modes)==3) {
            validateSOCKSExecutionSource(input,execution);
            return;
        }
        RouterNodeChain local=Libbox.newRouterNodeChain(input);
        if(local==null)throw new IllegalStateException("The native compiler returned no complete Local source.");
        try { validateExecutionPlan(local,execution); } finally { local.close(); }
    }

    static void validateSOCKSExecutionSource(String input,String execution) throws Exception {
        JSONObject original=new JSONObject(input);
        int count=original.getJSONArray("nodes").length();
        if(original.getInt("schema")!=3||count<3||count>8||!java.util.Arrays.asList("server","auto").contains(execution))
            throw new IllegalStateException("SOCKS5 execution requires three to eight complete original members.");
        RouterNodeChainExecution preview=Libbox.newRouterNodeChainSOCKSExecution(input,execution);
        if(preview==null)throw new IllegalStateException("The native SOCKS5 compiler returned no execution preparation.");
        try {
            JSONObject preparation=new JSONObject(preview.source()),returned=new JSONObject(preparation.getString("local_source"));
            if(preparation.getInt("schema")!=3 || !execution.equals(preview.requestedExecution()) || !execution.equals(preparation.getString("execution"))
                    || returned.getInt("schema")!=3 || !"local".equals(returned.getString("execution"))
                    || !original.getJSONArray("nodes").toString().equals(returned.getJSONArray("nodes").toString())
                    || !original.getJSONArray("identity_sources").toString().equals(returned.getJSONArray("identity_sources").toString())
                    || preview.config()==null || preview.config().isEmpty())
                throw new IllegalStateException("The typed SOCKS5 preview changed its original source.");
        } finally { preview.close(); }
    }

    static void validateCONNECTExecutionSource(String input,String execution) throws Exception {
        JSONObject original=new JSONObject(input);
        int count=original.getJSONArray("nodes").length();
        if(original.getInt("schema")!=4||count<3||count>8||!java.util.Arrays.asList("server","auto").contains(execution))
            throw new IllegalStateException("CONNECT execution requires three to eight complete original members.");
        RouterNodeChainExecution preview=Libbox.newRouterNodeChainCONNECTExecution(input,execution);
        if(preview==null)throw new IllegalStateException("The native CONNECT compiler returned no execution preparation.");
        try {
            JSONObject preparation=new JSONObject(preview.source()),returned=new JSONObject(preparation.getString("local_source"));
            if(preparation.getInt("schema")!=4 || !execution.equals(preview.requestedExecution()) || !execution.equals(preparation.getString("execution"))
                    || returned.getInt("schema")!=4 || !"local".equals(returned.getString("execution"))
                    || !original.getJSONArray("nodes").toString().equals(returned.getJSONArray("nodes").toString())
                    || !original.getJSONArray("identity_sources").toString().equals(returned.getJSONArray("identity_sources").toString())
                    || preview.config()==null || preview.config().isEmpty())
                throw new IllegalStateException("The typed CONNECT preview changed its original source.");
        } finally { preview.close(); }
    }

    static void validateExecutionPlan(RouterNodeChain local,String execution) throws Exception {
        if(local==null || !java.util.Arrays.asList("server","auto").contains(execution))
            throw new IllegalStateException("Choose the original ordered Server or Compare graph.");
        JSONObject original=new JSONObject(local.launchInput());
        int schema=original.getInt("schema");
        RouterNodeChainExecution preview=schema==6
                ? Libbox.routerNodeChainMultipleImportedExecutionFromLaunch(local.launchInput(),execution)
                : schema==5
                ? Libbox.routerNodeChainOpenVPNExecutionFromLaunch(local.launchInput(),execution)
                : Libbox.routerNodeChainExecutionFromLaunch(local.launchInput(),execution);
        if(preview==null)throw new IllegalStateException("The native compiler returned no ordered execution preparation.");
        try {
            int count=original.getJSONArray("nodes").length();
            if(count>8 && (schema!=6 || local.extendedLocalNodeCount()!=count || preview.extendedOriginalNodeCount()!=count))
                throw new IllegalStateException("The execution preview lost the complete sealed extended source.");
            if(!execution.equals(preview.requestedExecution()) || !local.sourceSHA256().equals(preview.localSourceSHA256())
                    || preview.config()==null || preview.config().isEmpty())
                throw new IllegalStateException("The ordered execution preview changed its original Local source.");
            if(schema==5 || schema==6) {
                JSONObject preparation=new JSONObject(preview.source()),returned=new JSONObject(preparation.getString("local_source"));
                if(preparation.length()!=4 || preparation.getInt("schema")!=schema
                        || !execution.equals(preparation.getString("execution"))
                        || !local.launchInput().equals(preparation.getString(schema==6?"multiple_imported_local_launch":"openvpn_local_launch"))
                        || returned.length()!=4 || returned.getInt("schema")!=schema || !"local".equals(returned.getString("execution"))
                        || !original.getJSONArray("nodes").toString().equals(returned.getJSONArray("nodes").toString())
                        || !original.getJSONArray("identity_sources").toString().equals(returned.getJSONArray("identity_sources").toString()))
                    throw new IllegalStateException("The typed execution preview changed its original sealed Local source.");
            }
        } finally { preview.close(); }
    }

    /** Pure compiler input shared by the editor preview and the launch capture. */
    static String memberInput(AndroidNodeStore.ChainSource member, String mode, JSONObject profile) throws Exception {
        if(member.imported) {
            if(!mode.equals(AndroidExternalPolicy.protocol(member.external().protocol))||!member.profileId.equals(profile.getString("id"))||!"external".equals(profile.getString("node_kind"))||profile.has("node_proof_id")||profile.has("router_api")||profile.has("api_token"))throw new IllegalStateException("The imported source cannot borrow a paired Router identity.");
            AndroidExternalPolicy.Captured captured=AndroidExternalPolicy.captureImportedEntry(member.external());
            return bounded("socks5".equals(mode)?Libbox.routerNodeChainImportedSOCKSMemberInput(captured.source,captured.capture)
                    :("http-connect".equals(mode)||"https-connect".equals(mode))?Libbox.routerNodeChainImportedCONNECTMemberInput(captured.source,captured.capture)
                    :"openvpn".equals(mode)?Libbox.routerNodeChainImportedOpenVPNMemberInput(captured.source,captured.capture)
                    :Libbox.routerNodeChainImportedMemberInput(captured.source,captured.capture),MAX_INPUT);
        }
        member.requirePairedIdentity();
        if (!member.profileId.equals(profile.getString("id")) || !member.proofId.equals(profile.getString("node_proof_id"))) {
            throw new IllegalStateException("The ordered compiler input lost its original paired member.");
        }
        JSONObject assets = member.bundle().getJSONObject("profiles");
        String files = bounded(assets.getJSONObject(mode).toString(), 16 * 1024 * 1024);
        String layer = profile.optString("start_layer", "off"), start = "";
        if (layer.isEmpty()) layer = "off";
        if (!java.util.Arrays.asList("off", "aes-256-gcm", "aes-256-gcm+xor-whitening").contains(layer)) throw new IllegalStateException("An ordered member lost its exact authenticated Start Layer.");
        if (!"off".equals(layer) && !"shadowsocks".equals(mode)) start = bounded(assets.getJSONObject("shadowsocks").toString(), 16 * 1024 * 1024);
        String bootstrap = profile.has("dns_bootstrap") ? bounded(profile.getJSONObject("dns_bootstrap").toString(), 16384) : "";
        return bounded(Libbox.routerNodeChainMemberInput(mode, files, bounded(profile.toString(), 256 * 1024), start, bootstrap), MAX_INPUT);
    }

    static int sourceSchema(List<AndroidNodeStore.ChainSource> members,List<String> modes) throws Exception {
        if(members.size()!=modes.size())throw new IllegalStateException("The original route lost a member transport.");
        int count = members.size();
        if (count > 0 && members.get(count - 1).imported) {
            if (count < 3 || count > AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH || members.get(0).imported
                    || !"wg".equals(modes.get(0)) || !List.of("", "off").contains(members.get(0).profile().optString("start_layer", "off")))
                throw new IllegalStateException("An imported final requires its original WireGuard entry and at least one imported intermediate.");
            members.get(0).requirePairedIdentity();
            for (int i = 1; i < count; i++) {
                if (!members.get(i).imported || !"shadowsocks".equals(modes.get(i)))
                    throw new IllegalStateException("Choose literal imported Shadowsocks 2022 nodes after the WireGuard entry.");
                requireLiteralImportedSS(members.get(i));
            }
            return 8;
        }
        int imported=0,middle=-1;boolean privateStream=false;
        for(int i=0;i<members.size();i++){
            if(members.get(i).imported){imported++;middle=i;}
            else if(i>0&&i<members.size()-1&&"shadowsocks".equals(modes.get(i)))privateStream=true;
        }
        if (members.size() > 8) {
            int last=members.size()-1;
            if (members.size()>AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH || members.get(0).imported || members.get(last).imported)
                throw new IllegalStateException("A longer route needs its original paired entry and final.");
            boolean stream=false;
            for (int i=0;i<=last;i++) {
                AndroidNodeStore.ChainSource member=members.get(i);
                if (member.imported) { stream=true; }
                else {
                    if ((stream && !"shadowsocks".equals(modes.get(i))) || !java.util.Arrays.asList("", "off").contains(member.profile().optString("start_layer","off")))
                        throw new IllegalStateException("Retain the original Off packet prefix before every stream.");
                    if("shadowsocks".equals(modes.get(i)))stream=true;
                }
            }
            if(imported>0)requireMixedImports(members,modes);
            return imported==0?1:6;
        }
        if(imported==0)return 1;
        if(members.size()==3 && imported==2 && members.get(0).imported && members.get(1).imported) {
            requireLiteralImportedSS(members.get(0));
            requireLiteralImportedSS(members.get(1));
            return 7;
        }
        if(members.size()<3||members.get(0).imported||members.get(members.size()-1).imported)
            throw new IllegalStateException("An imported interior requires its original paired entry and final node.");
        // Preserve every existing single-penultimate source family. Schema six
        // is a separate Local shape, never a promotion of a typed middle.
        if(imported==1&&!privateStream&&middle==members.size()-2) {
            String protocol=AndroidExternalPolicy.protocol(members.get(middle).external().protocol);
            switch(protocol) {
                case "shadowsocks":return 2;
                case "socks5":return 3;
                case "http-connect":case "https-connect":return 4;
                case "openvpn":return 5;
                default:throw new IllegalStateException("The imported source has no ordered transport owner.");
            }
        }
        requireMixedImports(members,modes);
        return 6;
    }

    // Native compilation binds the hostname and its saved resolver to the
    // same predecessor. A later hostname requires one packet and literal imports.
    static boolean requireMixedImports(List<AndroidNodeStore.ChainSource> members,List<String> modes) throws Exception {
        int hostname=-1,last=members.size()-1;
        for(int i=0;i<=last;i++) {
            AndroidNodeStore.ChainSource member=members.get(i);
            if(!member.imported)continue;
            AndroidStandardExitStore.Entry source=member.external();
            if(!AndroidStandardExitStore.importedHostname(source)) { requireLiteralImportedSS(member);continue; }
            if(hostname>=0 || i==0 || i==last)throw new IllegalStateException("Choose one original interior hostname with its saved resolver.");
            AndroidNodeStore.ChainSource.requireImported(source);
            hostname=i;
        }
        if(hostname<0)return false;
        if(members.get(last).imported)throw new IllegalStateException("Retain the original paired final after the hostname stream.");
        int packets = 0;
        while (packets < last && !members.get(packets).imported &&
                java.util.Arrays.asList("wg","awg2-fast","awg2-strong").contains(modes.get(packets))) packets++;
        if (packets < 1 || hostname!=packets && packets!=1)
            throw new IllegalStateException("A later hostname requires one original packet entry and literal imports.");
        for(int i=0;i<=last;i++) {
            AndroidNodeStore.ChainSource member=members.get(i);
            if (hostname!=packets && i>0 && i<last && !member.imported)
                throw new IllegalStateException("A later hostname requires independently imported stream predecessors.");
            boolean originalMode=i<packets
                    ? !member.imported && java.util.Arrays.asList("wg","awg2-fast","awg2-strong").contains(modes.get(i))
                    : "shadowsocks".equals(modes.get(i));
            if(!originalMode || !member.imported && !java.util.Arrays.asList("","off").contains(member.profile().optString("start_layer","off")))
                throw new IllegalStateException("Keep the original Off packet prefix, first hostname stream and remaining Shadowsocks streams.");
        }
        return true;
    }

    static void requireLiteralImportedSS(AndroidNodeStore.ChainSource member) throws Exception {
        AndroidStandardExitStore.Entry source=member.external();
        AndroidNodeStore.ChainSource.requireImported(source);
        if(!"shadowsocks".equals(AndroidExternalPolicy.protocol(source.protocol)))
            throw new IllegalStateException("Independent Local imports require original Shadowsocks 2022 sources.");
        AndroidNumericAddress.parse(source.server);
    }

    // Only the complete native compiler can check independent peer endpoints
    // and cipher keys. This check binds the private intermediate to its
    // original source role before Save, Load or launch calls that compiler.
    static boolean pairedStreamInterior(List<AndroidNodeStore.ChainSource> members,List<String> modes,String execution,int interior) throws Exception {
        int last=members.size()-1;
        boolean selected = "server".equals(execution) || "auto".equals(execution);
        if(selected) {
            List<Boolean> imported = new ArrayList<>();
            for (AndroidNodeStore.ChainSource member : members) imported.add(member.imported);
            if (!selectedStreamLayout(modes, imported)) return false;
        }
        if((!selected && !"local".equals(execution))||members.size()>AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH||modes.size()!=members.size()
                ||interior<1||interior>=last||members.get(0).imported||members.get(last).imported||members.get(interior).imported
                ||!"shadowsocks".equals(modes.get(interior))||!"shadowsocks".equals(modes.get(last)))return false;
        if (requireMixedImports(members,modes) && selected) return false;
        boolean stream=false,imported=false;
        for(int i=0;i<=last;i++){
            AndroidNodeStore.ChainSource node=members.get(i);String mode=modes.get(i);
            if(node.imported){
                if(!"shadowsocks".equals(mode))return false;
                imported=true;stream=true;
            }else{
                if(!java.util.Arrays.asList("", "off").contains(node.profile().optString("start_layer","off")))return false;
                if("shadowsocks".equals(mode)){if(i==0)return false;stream=true;}
                else if(stream||!java.util.Arrays.asList("wg","awg2-fast","awg2-strong").contains(mode))return false;
            }
        }
        return imported;
    }

    static boolean selectedStreamLayout(List<String> modes, List<Boolean> imported) {
        int last = modes.size() - 1;
        return last >= 3 && last < AndroidNodeStore.PHYSICAL_TRAVERSAL_DEPTH && imported.size() == modes.size()
                && !imported.get(0) && imported.get(1) && !imported.get(last)
                && List.of("wg", "awg2-fast", "awg2-strong").contains(modes.get(0)) && modes.subList(1, modes.size()).stream().allMatch("shadowsocks"::equals);
    }

    static void requireCompleteShape(List<AndroidNodeStore.ChainSource> members,List<String> modes,String execution) throws Exception {
        int schema=sourceSchema(members,modes);
        if (schema == 8 && !"local".equals(execution))
            throw new IllegalStateException("An ordered imported final requires Local execution.");
        if (members.size()>8 && schema==1) {
            if(!"local".equals(execution)||modes.size()!=members.size())throw new IllegalStateException("An extended paired route requires its complete Local source.");
            for(int i=0;i<modes.size();i++)if(!(i==modes.size()-1?"shadowsocks":"wg").equals(modes.get(i)))throw new IllegalStateException("Extended paired Local requires WireGuard at every prefix and a Shadowsocks final.");
        }
        if (members.size()>8 && schema==6 && !"local".equals(execution)
                && (modes.size()!=members.size() || !List.of("wg","awg2-fast","awg2-strong").contains(modes.get(0)) || !members.get(1).imported))
            throw new IllegalStateException("The longer mixed packet and stream route requires Local execution.");
        if(schema!=6 && schema!=7)return;
        boolean selected=schema==6 && java.util.Arrays.asList("server","auto").contains(execution);
        if(!("local".equals(execution)||selected)||members.size()!=modes.size()||!"shadowsocks".equals(modes.get(modes.size()-1)))
            throw new IllegalStateException("The imported route requires its original paired Shadowsocks final. A custom entry requires Local.");
        for(int i=0;i<members.size()-1;i++) {
            if(members.get(i).imported) {
                if(selected&&AndroidStandardExitStore.importedHostname(members.get(i).external()))
                    throw new IllegalStateException("A mixed route with an imported hostname requires Local execution.");
                if(!"shadowsocks".equals(modes.get(i)))throw new IllegalStateException("Keep each imported source's original Shadowsocks transport.");
            } else if(!java.util.Arrays.asList("wg","awg2-fast","awg2-strong").contains(modes.get(i))){
                if(schema==6&&pairedStreamInterior(members,modes,execution,i))return;
                throw new IllegalStateException("This paired intermediate has no supported position in the original route.");
            }
        }
    }

    /** Validate the complete staged Local imported proposal before any store
     * writes. Per-member validation cannot establish ordered graph ownership. */
    static void validateLocalImportedSources(List<AndroidNodeStore.ChainSource> members,List<String> modes) throws Exception {
        requireCompleteShape(members,modes,"local");
        int schema=sourceSchema(members,modes);
        if(schema!=6 && schema!=7 && schema!=8)throw new IllegalStateException("The independent-import preview requires its complete Local imported source.");
        JSONObject control=members.get(schema == 8 ? 0 : members.size()-1).profile();
        JSONArray selected=AndroidNodeStore.orderedSelection(control),inputs=new JSONArray(),identities=new JSONArray();
        if(!"local".equals(control.getString("multihop_execution"))||selected.length()!=members.size())
            throw new IllegalStateException("The staged Local path changed its exact complete selection.");
        for(int i=0;i<members.size();i++) {
            AndroidNodeStore.ChainSource member=members.get(i);JSONObject reference=selected.getJSONObject(i);
            if(!member.profileId.equals(reference.getString("id"))||!modes.get(i).equals(reference.getString("mode")))
                throw new IllegalStateException("The staged Local path reordered or replaced an original member.");
            inputs.put(memberInput(member,modes.get(i),member.profile()));identities.put(identityInput(member));
        }
        if (schema == 8) inputs.put(inputs.length()-1, externalFinalInput(inputs.getString(0), inputs.getString(inputs.length()-1)));
        String source=bounded(new JSONObject().put("schema",schema).put("execution","local").put("nodes",inputs).put("identity_sources",identities).toString(),MAX_INPUT);
        RouterNodeChain preview=Libbox.newRouterNodeChain(source);
        if(preview==null)throw new IllegalStateException("The native compiler returned no complete imported Local graph.");
        try {
            String launch=bounded(preview.launchInput(),MAX_INPUT);
            JSONObject returned=new JSONObject(launch);
            String config=bounded(preview.config(),4*1024*1024);
            String sourceSHA=preview.sourceSHA256(),configSHA=preview.configSHA256();
            // The unprojected native launch carries all four receipt hashes in
            // addition to kind and its complete four-field source. Never trim
            // those seals to make a preview resemble the constructor input.
            if(returned.length()!=9||!"routervpn-node-chain-launch-input".equals(returned.getString("kind"))
                    ||returned.getInt("schema")!=schema||!"local".equals(returned.getString("execution"))
                    ||!inputs.toString().equals(returned.getJSONArray("nodes").toString())
                    ||!identities.toString().equals(returned.getJSONArray("identity_sources").toString())
                    ||sourceSHA==null||!sourceSHA.matches("[0-9a-f]{64}")||!sourceSHA.equals(returned.getString("source_sha256"))
                    ||configSHA==null||!configSHA.equals(digest(config))||!configSHA.equals(returned.getString("config_sha256"))
                    ||!configSHA.equals(returned.getString("original_config_sha256"))
                    ||!returned.getString("metadata_sha256").matches("[0-9a-f]{64}"))
                throw new IllegalStateException("The native Local preview changed its original imported set.");
            // Reopen through the sealed native parser so a well-formed but
            // substituted metadata digest cannot survive the preview boundary.
            RouterNodeChain sealed=Libbox.routerNodeChainLaunch(launch);
            if(sealed==null)throw new IllegalStateException("The native Local preview lost its sealed source.");
            try {
                if(!launch.equals(sealed.launchInput())||!config.equals(sealed.config())
                        ||!sourceSHA.equals(sealed.sourceSHA256())||!configSHA.equals(sealed.configSHA256()))
                    throw new IllegalStateException("The native Local preview could not reopen its original sealed source.");
            } finally { sealed.close(); }
        } finally { preview.close(); }
    }

    JSONObject controlProfile() throws Exception { return original.control.profile(); }
    JSONObject finalProfile() throws Exception { return original.members.get(original.members.size() - 1).profile(); }
    boolean ownsSource(AndroidNodeStore.ChainCapture source) { return original == source; }
    void requireCurrent() throws Exception {
        original.requireCurrent();
        if(selectedCandidatePurpose!=null)original.requireSelectedCandidatePurpose(selectedCandidatePurpose);
    }
    void requireHistoryCurrent(AndroidNodeStore.HistoryReadback readback) throws Exception {
        if (readback == null) throw new IllegalStateException("The original history source readback is missing.");
        readback.require(original);
    }
    @Override public void close() throws Exception { if(connect!=null)connect.close();else if(socks!=null)socks.close();else plan.close(); }

    private static String bounded(String value, int limit) {
        if (value == null || value.isEmpty() || value.getBytes(StandardCharsets.UTF_8).length > limit) throw new IllegalStateException("The complete ordered private source exceeds its bound.");
        return value;
    }
    private static String digest(String value) throws Exception {
        byte[] bytes = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) result.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return result.toString();
    }
}
