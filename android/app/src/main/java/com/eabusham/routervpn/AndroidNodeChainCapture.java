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
    final String launchInput, config, sourceSHA256, configSHA256;
    final List<String> memberInputs;
    final boolean strict, homeLANAccess;
    private final AndroidNodeStore.ChainCapture original;

    static AndroidNodeChainCapture compile(AndroidNodeStore.ChainCapture original) throws Exception {
        List<String> inputs = memberInputs(original);
        String source = bounded(new JSONObject().put("schema", 1).put("execution", "local")
                .put("nodes", new JSONArray(inputs)).toString(), MAX_INPUT);
        RouterNodeChain plan = Libbox.newRouterNodeChain(source);
        try { return new AndroidNodeChainCapture(original, inputs, plan); }
        catch (Exception failure) { try { plan.close(); } catch (Exception close) { failure.addSuppressed(close); } throw failure; }
    }

    static AndroidNodeChainCapture reopen(String input, AndroidNodeStore.ChainCapture original) throws Exception {
        List<String> inputs = memberInputs(original);
        RouterNodeChain plan = Libbox.newRouterNodeChainLaunch(bounded(input, MAX_INPUT));
        try {
            AndroidNodeChainCapture capture = new AndroidNodeChainCapture(original, inputs, plan);
            if (!input.equals(capture.launchInput)) throw new IllegalStateException("The private ordered launch source is not its original canonical capture.");
            return capture;
        } catch (Exception failure) { try { plan.close(); } catch (Exception close) { failure.addSuppressed(close); } throw failure; }
    }

    private AndroidNodeChainCapture(AndroidNodeStore.ChainCapture original, List<String> inputs, RouterNodeChain plan) throws Exception {
        if (plan == null) throw new IllegalStateException("The native ordered compiler returned no source owner.");
        this.original = original; this.plan = plan;
        if (inputs.size() != original.members.size()) throw new IllegalStateException("The native input omitted an original ordered member.");
        memberInputs = Collections.unmodifiableList(new ArrayList<>(inputs));
        launchInput = bounded(plan.launchInput(), MAX_INPUT);
        config = bounded(plan.config(), 4 * 1024 * 1024);
        sourceSHA256 = plan.sourceSHA256(); configSHA256 = plan.configSHA256();
        JSONObject record = new JSONObject(launchInput);
        if (!"routervpn-node-chain-launch-input".equals(record.getString("kind")) || record.getInt("schema") != 1
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
        boolean protect = false, lan = true;
        for (int i = 0; i < returned.length(); i++) {
            if (!memberInputs.get(i).equals(returned.getString(i))) throw new IllegalStateException("The native graph reordered or replaced an original member.");
            JSONObject profile = original.members.get(i).profile();
            String policy = profile.optString("kill_switch_policy", profile.optBoolean("kill_switch", false) ? "on-connect" : "off");
            if (!java.util.Arrays.asList("off", "on-connect", "always").contains(policy)) throw new IllegalStateException("An ordered member has an invalid protection policy.");
            protect |= !"off".equals(policy) || profile.optBoolean("kill_switch", false);
            lan &= profile.optBoolean("home_lan_access", true);
        }
        strict = protect; homeLANAccess = lan;
        original.requireCurrent();
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

    JSONObject controlProfile() throws Exception { return original.control.profile(); }
    JSONObject finalProfile() throws Exception { return original.members.get(original.members.size() - 1).profile(); }
    void requireCurrent() throws Exception { original.requireCurrent(); }
    @Override public void close() throws Exception { plan.close(); }

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
