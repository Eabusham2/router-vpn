package com.eabusham.routervpn;

import java.nio.charset.StandardCharsets;
import org.json.JSONObject;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterMultihop;

/** Captured entry policy; no independent VPN, local relay or network lookup. */
final class AndroidMultihopStartLayer {
    static final String SESSION_FILE = "routervpn-entry-start-layer.json";
    static final int MAX_BYTES = 16384;

    static String capture(JSONObject entry) throws Exception {
        String mode = AndroidStartLayer.selectedMode(entry);
        if (AndroidStartLayer.OFF.equals(mode)) return "";
        if (!AndroidStartLayer.AES.equals(mode) && !AndroidStartLayer.AES_XOR.equals(mode)) {
            throw new IllegalArgumentException("Entry Start Layer requires authenticated AES.");
        }
        JSONObject node = AndroidProfileSelection.selectedRouterProfile(entry);
        if (!"router-vpn".equals(node.optString("node_kind", "router-vpn"))) {
            throw new IllegalArgumentException("Entry Start Layer requires the captured home node.");
        }
        JSONObject profile = entry.getJSONObject("profiles").getJSONObject("shadowsocks");
        String captured = new JSONObject().put("mode", mode).put("profile", profile).toString();
        if (captured.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            throw new IllegalArgumentException("Captured entry Start Layer exceeds its bound.");
        }
        return captured;
    }

    static void preflight(String config, String metadata, String captured) throws Exception {
        if (captured.isEmpty()) return;
        String graph = Libbox.routerCompileMultihopEntryStartLayer(config, metadata, captured);
        if (graph == null || graph.isEmpty() || graph.getBytes(StandardCharsets.UTF_8).length > 4*1024*1024) {
            throw new IllegalStateException("Native entry layer did not return a bounded graph.");
        }
        Libbox.checkConfig(graph);
    }

    static RouterMultihop prepareExecution(String config, String metadata, String captured) throws Exception {
        JSONObject selection = new JSONObject(metadata);
        String execution = selection.has("execution") ? selection.getString("execution") : "local";
        if (!java.util.Arrays.asList("local", "server", "auto").contains(execution)) throw new IllegalArgumentException("Unknown multihop execution.");
        String required = selection.has("entry_start_layer") ? selection.getString("entry_start_layer") : "";
        if (captured == null) {
            if (!required.isEmpty()) throw new IllegalStateException("Captured entry layer source is missing.");
            return "local".equals(execution) ? null : Libbox.newRouterMultihop(config, metadata);
        }
        if (required.isEmpty()) throw new IllegalStateException("Unrequested entry layer file.");
        return prepare(config, metadata, captured);
    }

    static RouterMultihop prepare(String config, String metadata, String captured) throws Exception {
        if (captured == null || captured.isEmpty() || captured.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            throw new IllegalStateException("Captured entry layer is missing or oversized.");
        }
        // This path is used even for Local. Omitting comparison does not mean
        // permission to omit a requested authenticated physical entry layer.
        return Libbox.newRouterMultihopWithEntryStartLayer(config, metadata, captured);
    }

    private AndroidMultihopStartLayer() {}
}
