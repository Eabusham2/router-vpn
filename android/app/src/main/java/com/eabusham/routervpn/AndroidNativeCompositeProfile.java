package com.eabusham.routervpn;

import io.nekohasekai.libbox.Libbox;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Captures both authenticated TCP/UDP lanes before a multihop session exists. */
final class AndroidNativeCompositeProfile {
    private static final int MAX_BYTES = 4 * 1024 * 1024;

    static boolean isMode(String mode) {
        return "ss-v2ray".equals(mode) || "split".equals(mode) || "max".equals(mode);
    }

    static String compile(JSONObject bundle, JSONObject assets, String mode) throws Exception {
        try {
            if (!isMode(mode) || assets == null) throw invalid();
            JSONObject selected = AndroidProfileSelection.selectedRouterProfile(bundle);
            String node = AndroidNodeStore.stableNodeIdentity(bundle);
            String layer = AndroidStartLayer.selectedMode(bundle);
            if (!node.matches("[0-9a-f]{64}") || !"router-vpn".equals(selected.getString("node_kind"))
                    || !node.equals(selected.getString("node_proof_id"))
                    || !Arrays.asList(AndroidStartLayer.OFF, AndroidStartLayer.AES, AndroidStartLayer.AES_XOR).contains(layer)) throw invalid();
            JSONObject metadata = new JSONObject().put("node_id", node).put("node_kind", "router-vpn")
                    .put("router_api", selected.getString("router_api")).put("start_layer", layer);
            String captured = assets.toString();
            String start = AndroidStartLayer.OFF.equals(layer) ? ""
                    : bundle.getJSONObject("profiles").getJSONObject("shadowsocks").toString();
            if (!bounded(captured) || metadata.toString().getBytes(StandardCharsets.UTF_8).length > 16384
                    || !start.isEmpty() && !bounded(start)) throw invalid();
            String compiled = Libbox.routerCompileCompositeProfile(mode, captured, metadata.toString(), start);
            if (!bounded(compiled)) throw invalid();
            // Revalidate the exact captured owner using the shared planner.
            // This construction-only wrapper cannot run without both children.
            base(compiled, mode, node, layer);
            return compiled;
        } catch (Exception rejected) {
            // Raw parser exceptions can contain a profile's credentials.
            throw invalid();
        }
    }

    static JSONObject base(String source, String mode, String node, String layer) throws Exception {
        String compiled = Libbox.routerCompositeMultihopBase(source, mode, node, layer);
        if (!bounded(compiled)) throw invalid();
        JSONObject graph = new JSONObject(compiled);
        JSONArray outputs = graph.getJSONArray("outbounds");
        if (outputs.length() != 1 || !"proxy".equals(graph.getJSONObject("route").getString("final"))) throw invalid();
        JSONObject owner = outputs.getJSONObject(0);
        if (!"routervpn-composite".equals(owner.getString("type")) || !"proxy".equals(owner.getString("tag"))
                || !mode.equals(owner.getString("mode")) || !node.equals(owner.getString("node_id"))
                || owner.has("detour")) throw invalid();
        return graph;
    }

    private static boolean bounded(String value) {
        return value != null && !value.isEmpty() && value.getBytes(StandardCharsets.UTF_8).length <= MAX_BYTES;
    }
    private static IllegalStateException invalid() {
        return new IllegalStateException("The composite profile lost its captured node, encryption, or TCP/UDP transport.");
    }
    private AndroidNativeCompositeProfile() {}
}
