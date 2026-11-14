package com.eabusham.routervpn;

import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterNodeChain;
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
    final boolean strict, homeLANAccess;
    private final AndroidNodeStore.ChainCapture original;

    static AndroidNodeChainCapture compile(AndroidNodeStore.ChainCapture original) throws Exception {
        List<String> inputs = memberInputs(original);
        List<String> identities = identityInputs(original);
        String source = sourceInput(original, inputs, identities);
        if (sourceSchema(original.members) >= 3) return new AndroidNodeChainCapture(original, inputs, identities, source);
        RouterNodeChain plan = Libbox.newRouterNodeChain(source);
        try { return new AndroidNodeChainCapture(original, inputs, identities, source, plan); }
        catch (Exception failure) { try { plan.close(); } catch (Exception close) { failure.addSuppressed(close); } throw failure; }
    }

    static AndroidNodeChainCapture reopen(String input, AndroidNodeStore.ChainCapture original) throws Exception {
        List<String> inputs = memberInputs(original);
        List<String> identities = identityInputs(original);
        if (sourceSchema(original.members) >= 3) {
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
        return bounded(new JSONObject().put("schema", sourceSchema(original.members)).put("execution", "local")
                .put("nodes", new JSONArray(inputs)).put("identity_sources",new JSONArray(identities)).toString(), MAX_INPUT);
    }

    private AndroidNodeChainCapture(AndroidNodeStore.ChainCapture original, List<String> inputs, List<String> identities, String source, RouterNodeChain plan) throws Exception {
        if (plan == null) throw new IllegalStateException("The native ordered compiler returned no source owner.");
        this.original = original; this.plan = plan; socks = null; connect = null; selectionExecution = original.execution;
        if (inputs.size() != original.members.size()) throw new IllegalStateException("The native input omitted an original ordered member.");
        memberInputs = Collections.unmodifiableList(new ArrayList<>(inputs));
        identityInputs = Collections.unmodifiableList(new ArrayList<>(identities));
        sourceInput = source;
        launchInput = bounded(plan.launchInput(), MAX_INPUT);
        config = bounded(plan.config(), 4 * 1024 * 1024);
        sourceSHA256 = plan.sourceSHA256(); configSHA256 = plan.configSHA256();
        JSONObject record = new JSONObject(launchInput);
        if (!"routervpn-node-chain-launch-input".equals(record.getString("kind")) || record.getInt("schema") != sourceSchema(original.members)
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
        this.original=original; plan=null; selectionExecution=original.execution;
        if (!"local".equals(selectionExecution)) throw new IllegalStateException("The typed imported source requires its original Local execution.");
        boolean isCONNECT=sourceSchema(original.members)==4;
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

    private static List<String> memberInputs(AndroidNodeStore.ChainCapture original) throws Exception {
        if (original == null) throw new IllegalStateException("The original selected ordered source is missing.");
        original.requireCurrent();
        JSONArray selected = AndroidNodeStore.orderedSelection(original.control.profile());
        if (selected.length() != original.members.size() || selected.length() != original.modes.size()) throw new IllegalStateException("The original ordered capture is incomplete.");
        List<String> inputs = new ArrayList<>();
        for (int i = 0; i < selected.length(); i++) {
            AndroidNodeStore.ChainSource member = original.members.get(i);
            JSONObject profile = member.profile(), reference = selected.getJSONObject(i);
            String mode = original.modes.get(i);
            if (!member.profileId.equals(reference.getString("id")) || !mode.equals(reference.getString("mode"))) {
                throw new IllegalStateException("The ordered member changed its original position or exact mode.");
            }
            inputs.add(memberInput(member, mode, profile));
        }
        original.requireCurrent();
        return inputs;
    }

    /** Pure compiler input shared by the editor preview and the launch capture. */
    static String memberInput(AndroidNodeStore.ChainSource member, String mode, JSONObject profile) throws Exception {
        if(member.imported) {
            if(!mode.equals(AndroidExternalPolicy.protocol(member.external().protocol))||!member.profileId.equals(profile.getString("id"))||!"external".equals(profile.getString("node_kind"))||profile.has("node_proof_id")||profile.has("router_api")||profile.has("api_token"))throw new IllegalStateException("The imported source cannot borrow a paired Router identity.");
            AndroidExternalPolicy.Captured captured=AndroidExternalPolicy.captureImportedEntry(member.external());
            return bounded("socks5".equals(mode)?Libbox.routerNodeChainImportedSOCKSMemberInput(captured.source,captured.capture)
                    :("http-connect".equals(mode)||"https-connect".equals(mode))?Libbox.routerNodeChainImportedCONNECTMemberInput(captured.source,captured.capture)
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

    static int sourceSchema(List<AndroidNodeStore.ChainSource> members) throws Exception {
        int imported=0;for(int i=0;i<members.size();i++)if(members.get(i).imported){imported++;if(members.size()!=3||i!=1)throw new IllegalStateException("A custom node requires one paired first node and one paired final node.");}
        if(imported>1)throw new IllegalStateException("This custom path supports one imported intermediate node.");
        if(imported==0)return 1;
        String protocol=AndroidExternalPolicy.protocol(members.get(1).external().protocol);
        return "socks5".equals(protocol)?3:("http-connect".equals(protocol)||"https-connect".equals(protocol))?4:2;
    }

    JSONObject controlProfile() throws Exception { return original.control.profile(); }
    JSONObject finalProfile() throws Exception { return original.members.get(original.members.size() - 1).profile(); }
    boolean ownsSource(AndroidNodeStore.ChainCapture source) { return original == source; }
    void requireCurrent() throws Exception { original.requireCurrent(); }
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
