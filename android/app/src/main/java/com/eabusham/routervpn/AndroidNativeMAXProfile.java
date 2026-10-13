package com.eabusham.routervpn;

import android.util.Base64;
import io.nekohasekai.libbox.Libbox;
import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Complete MAX assets are compiled into the owned runtime, never run as scripts. */
final class AndroidNativeMAXProfile {
    private static final int MAX_GRAPH = 4 * 1024 * 1024;
    private static final Set<String> MODES = new HashSet<>(Arrays.asList(
            "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"));

    static boolean isMode(String mode) { return mode != null && MODES.contains(mode); }

    static String compile(JSONObject bundle, JSONObject assets, String mode) throws Exception {
        try {
            return compileCaptured(bundle, assets, mode);
        } catch (Exception rejected) {
            // JSONObject/native parser diagnostics may contain serialized key
            // material. Keep those objects and exception causes out of the UI.
            throw invalid("Complete MAX profile or captured policy failed validation.");
        }
    }

    private static String compileCaptured(JSONObject bundle, JSONObject assets, String mode) throws Exception {
        validateAssets(assets, mode);
        JSONObject profile = AndroidProfileSelection.selectedRouterProfile(bundle);
        String node = AndroidNodeStore.stableNodeIdentity(bundle);
        String layer = AndroidStartLayer.selectedMode(bundle);
        if (!node.matches("[0-9a-f]{64}") || !"router-vpn".equals(text(profile, "node_kind"))
                || !node.equals(text(profile, "node_proof_id"))
                || !Arrays.asList(AndroidStartLayer.OFF, AndroidStartLayer.AES, AndroidStartLayer.AES_XOR).contains(layer)) {
            throw invalid("Complete MAX requires the captured node and authenticated Start Layer policy.");
        }
        JSONObject metadata = new JSONObject().put("node_id", node).put("node_kind", "router-vpn")
                .put("endpoint", text(profile, "endpoint")).put("router_api", text(profile, "router_api"))
                .put("start_layer", layer);
        String input = assets.toString();
        if (input.getBytes(StandardCharsets.UTF_8).length > 16 * 1024 * 1024
                || metadata.toString().getBytes(StandardCharsets.UTF_8).length > 16384) {
            throw invalid("Complete MAX input exceeds its bound.");
        }
        String compiled = Libbox.routerCompileMAXProfile(mode, input, metadata.toString());
        if (compiled == null || compiled.isEmpty() || compiled.getBytes(StandardCharsets.UTF_8).length > MAX_GRAPH) {
            throw invalid("Complete MAX compiler returned no bounded graph.");
        }
        validateGraph(bundle, assets, new JSONObject(compiled), mode);
        return compiled;
    }

    static void validateAssets(JSONObject assets, String mode) throws Exception {
        if (!isMode(mode) || assets == null) throw invalid("Unknown or absent complete MAX profile.");
        boolean awg = mode.endsWith("-awg"), tls = mode.startsWith("max-tls-");
        Set<String> keys = new HashSet<>(Arrays.asList("rosenpass-client-secret", "rosenpass-client-public", "rosenpass-server-public"));
        Set<String> required = new HashSet<>(keys);
        required.addAll(Arrays.asList(awg ? "awg.conf" : "wg.conf", "middle-sing-box.json", "chain.env",
                "rosenpass.env", "rosenpass.toml", tls ? "outer-xray.json" : "cert.pem"));
        Set<String> allowed = new HashSet<>(required);
        allowed.add("stack.json"); allowed.add(awg ? "awg-socks.conf" : "wg-socks.conf");
        for (String name : required) if (!assets.has(name)) throw invalid("Complete MAX is missing a mandatory asset.");
        JSONArray names = assets.names();
        if (names == null || names.length() > allowed.size()) throw invalid("Complete MAX asset map is invalid.");
        int total = 0, ownSize = 0, peerSize = 0;
        for (int i = 0; i < names.length(); i++) {
            String name = names.getString(i);
            if (!allowed.contains(name)) throw invalid("Complete MAX contains an unowned helper or asset.");
            String encoded = text(assets, name);
            if (encoded.isEmpty() || encoded.length() > ((MAX_GRAPH + 2) / 3) * 4) throw invalid("Complete MAX asset exceeds its bound.");
            byte[] raw = Base64.decode(encoded, Base64.DEFAULT);
            try {
                if (raw.length == 0 || raw.length > MAX_GRAPH || !Base64.encodeToString(raw, Base64.NO_WRAP).equals(encoded)) {
                    throw invalid("Complete MAX requires exact generated asset encoding.");
                }
                total += raw.length;
                if (total > 12 * 1024 * 1024) throw invalid("Complete MAX assets exceed their combined bound.");
                if (keys.contains(name)) {
                    int nonzero = 0; for (byte value : raw) nonzero |= value;
                    if (raw.length < 32 || nonzero == 0) throw invalid("Complete MAX lost its PQ key material.");
                    if ("rosenpass-client-public".equals(name)) ownSize = raw.length;
                    if ("rosenpass-server-public".equals(name)) peerSize = raw.length;
                } else {
                    StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw));
                }
            } finally { Arrays.fill(raw, (byte) 0); }
        }
        if (ownSize != peerSize || text(assets, "rosenpass-client-public").equals(text(assets, "rosenpass-server-public"))) {
            throw invalid("Complete MAX needs distinct PQ peer identities.");
        }
    }

    static void validateGraph(JSONObject bundle, JSONObject assets, JSONObject graph, String mode) throws Exception {
        if (!isMode(mode)) throw invalid("Unknown complete MAX graph.");
        String node = AndroidNodeStore.stableNodeIdentity(bundle), layer = AndroidStartLayer.selectedMode(bundle);
        boolean extra = !AndroidStartLayer.OFF.equals(layer);
        JSONArray endpoints = graph.getJSONArray("endpoints"), inbounds = graph.getJSONArray("inbounds"), outs = graph.getJSONArray("outbounds");
        if (endpoints.length() != 1 || inbounds.length() != 1 || outs.length() != (extra ? 3 : 2)) throw invalid("Complete MAX lost its single VPN interface.");
        JSONObject ep = endpoints.getJSONObject(0), tun = inbounds.getJSONObject(0), middle = outs.getJSONObject(0), outer = outs.getJSONObject(1);
        if (!"tun".equals(tun.getString("type")) || !"tun-in".equals(tun.getString("tag"))
                || !Boolean.TRUE.equals(tun.opt("auto_route")) || !Boolean.TRUE.equals(tun.opt("strict_route"))
                || !"proxy".equals(graph.getJSONObject("route").getString("final"))
                || !"routervpn-pq".equals(ep.getString("type")) || !"proxy".equals(ep.getString("tag"))
                || !(mode.endsWith("-awg") ? "awg2-pq" : "wg-pq").equals(ep.getString("mode"))
                || !node.equals(ep.getString("node_id")) || !Boolean.FALSE.equals(ep.opt("system"))
                || !"routervpn-max-ss".equals(ep.getString("detour"))
                || !"shadowsocks".equals(middle.getString("type")) || !"routervpn-max-ss".equals(middle.getString("tag"))
                || !AndroidStartLayer.AES_METHOD.equals(middle.getString("method")) || !"routervpn-max-outer".equals(middle.getString("detour"))
                || !"routervpn-max-outer".equals(outer.getString("tag"))
                || !(mode.startsWith("max-tls-") ? "routervpn-xray" : "hysteria2").equals(outer.getString("type"))
                || (extra ? !"routervpn-max-start-layer".equals(outer.opt("detour")) : outer.has("detour"))) {
            throw invalid("Complete MAX lost its ordered encryption chain.");
        }
        if (extra) {
            JSONObject start = outs.getJSONObject(2);
            if (!"routervpn-max-start-layer".equals(start.getString("tag")) || start.has("detour")
                    || !(AndroidStartLayer.AES.equals(layer) ? "shadowsocks" : "routervpn-aes-xor").equals(start.getString("type"))) {
                throw invalid("Complete MAX lost the captured outermost Start Layer.");
            }
        }
        JSONObject pq = ep.getJSONObject("pq");
        for (String[] pair : new String[][]{{"secret", "rosenpass-client-secret"}, {"public", "rosenpass-client-public"}, {"peer", "rosenpass-server-public"}}) {
            if (!text(assets, pair[1]).equals(text(pq, pair[0]))) throw invalid("Complete MAX changed a captured PQ key.");
        }
    }

    private static String text(JSONObject object, String key) throws Exception {
        Object value = object.opt(key);
        if (!(value instanceof String)) throw invalid("Complete MAX field must be an exact string.");
        return (String) value;
    }
    private static IllegalStateException invalid(String message) { return new IllegalStateException(message); }
    private AndroidNativeMAXProfile() {}
}
