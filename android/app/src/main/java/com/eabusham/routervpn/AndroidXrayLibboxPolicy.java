package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;
import io.nekohasekai.libbox.Libbox;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Compiles one captured Xray graph for the existing LayeredVpnService. */
final class AndroidXrayLibboxPolicy {
    private static final int LIMIT = 4 * 1024 * 1024;

    static String check(JSONObject bundle, JSONObject profile, String mode) throws Exception {
        verifyAssets(profile);
        String raw = AndroidStartLayer.exactNativeAsset(profile, "xray.json");
        String wrapper = profile.has("sing-box.json")
                ? AndroidStartLayer.exactNativeAsset(profile, "sing-box.json") : legacyWrapper(mode, raw);
        JSONObject graph = new JSONObject(bounded(Libbox.routerCheckXrayProfile(mode, wrapper, raw)));
        captureBothFamilies(graph);
        return bounded(graph.toString());
    }

    /** Capture IPv6 even when policy rejects it; omitting its OS route would leak it. */
    private static void captureBothFamilies(JSONObject graph) throws Exception {
        JSONArray inbounds = graph.getJSONArray("inbounds");
        if (inbounds.length() != 1) throw new IllegalStateException("One native Xray TUN is required.");
        JSONObject tun = inbounds.getJSONObject(0);
        if (!"tun".equals(tun.optString("type")) || !Boolean.TRUE.equals(tun.opt("auto_route"))
                || !Boolean.TRUE.equals(tun.opt("strict_route"))) {
            throw new IllegalStateException("Native Xray requires one full-device capture interface.");
        }
        JSONArray addresses;
        if (tun.has("address")) {
            addresses = tun.getJSONArray("address");
            if (addresses.length() == 0 || addresses.length() > 16) throw new IllegalStateException("Invalid native TUN address count.");
        } else addresses = new JSONArray();
        boolean ipv4 = false, ipv6 = false;
        for (int i = 0; i < addresses.length(); i++) {
            Object value = addresses.get(i);
            if (!(value instanceof String)) throw new IllegalStateException("TUN addresses must be numeric prefixes.");
            String[] parts = ((String) value).split("/", -1);
            if (parts.length != 2 || !parts[1].matches("[0-9]{1,3}") || parts[0].contains("%")
                    || AndroidNumericAddress.parse(parts[0]) == null) {
                throw new IllegalStateException("Native TUN address is not an unscoped numeric prefix.");
            }
            boolean v6 = parts[0].contains(":");
            int prefix = Integer.parseInt(parts[1]);
            if (prefix > (v6 ? 128 : 32)) throw new IllegalStateException("Native TUN prefix length is invalid.");
            if (v6) ipv6 = true; else ipv4 = true;
        }
        // Keep every supplied interface address; add only a missing family.
        if (!ipv4) addresses.put("172.19.0.1/30");
        if (!ipv6) addresses.put("fdfe:dcba:9876::1/126");
        tun.put("address", addresses);
        if (!tun.has("tag")) tun.put("tag", "tun-in");
        Object tag = tun.get("tag");
        if (!(tag instanceof String) || !((String) tag).matches("[A-Za-z0-9_.-]{1,128}")) {
            throw new IllegalStateException("Native TUN requires an exact owned route tag.");
        }
        tun.put("mtu", AndroidNativeProfilePolicy.exactInteger(tun, "mtu", 1280, 1280, 9000));
    }

    static String resolve(JSONObject bundle, JSONObject profile, String mode) throws Exception {
        String wrapper = check(bundle, profile, mode);
        String raw = AndroidStartLayer.exactNativeAsset(profile, "xray.json");
        String start = AndroidStartLayer.selectedMode(bundle);
        String response;
        if (AndroidStartLayer.OFF.equals(start)) {
            response = Libbox.routerResolveXrayProfile(mode, wrapper, raw);
        } else {
            JSONObject node = AndroidProfileSelection.selectedRouterProfile(bundle);
            String aes = AndroidStartLayer.exactNativeAsset(bundle.getJSONObject("profiles").getJSONObject("shadowsocks"), "sing-box.json");
            String policy = new JSONObject().put("mode", start).put("raw_mode", mode)
                    .put("node_kind", "router-vpn").put("router_api", node.getString("router_api")).toString();
            response = Libbox.routerResolveXrayStartLayerProfile(mode, wrapper, raw, aes, policy);
        }
        if (response == null || response.isEmpty() || response.length() > 20 * 1024 * 1024) {
            throw new IllegalStateException("Native Xray preparation returned no bounded result.");
        }
        JSONObject files = new JSONObject(response);
        Set<String> keys = new HashSet<>();
        JSONArray names = files.names();
        for (int i = 0; names != null && i < names.length(); i++) keys.add(names.getString(i));
        Set<String> expected = new HashSet<>(Arrays.asList("sing-box.json", "xray.json"));
        if (!AndroidStartLayer.OFF.equals(start)) expected.add("start-layer-source.json");
        if (!keys.equals(expected)) throw new IllegalStateException("Native Xray preparation returned foreign assets.");
        // Fully decode and validate before changing the launch-only bundle.
        // No stored node configuration is rewritten by hostname bootstrap.
        String compiled = AndroidStartLayer.exactNativeAsset(files, "sing-box.json");
        String resolved = AndroidStartLayer.exactNativeAsset(files, "xray.json");
        String aes = files.has("start-layer-source.json") ? AndroidStartLayer.exactNativeAsset(files, "start-layer-source.json") : null;
        bounded(Libbox.routerCompileXrayProfile(mode, compiled, resolved));
        if (Thread.currentThread().isInterrupted()) throw new InterruptedException("Native Xray preparation was cancelled.");
        profile.put("sing-box.json", files.getString("sing-box.json"));
        profile.put("xray.json", files.getString("xray.json"));
        if (aes != null) bundle.getJSONObject("profiles").getJSONObject("shadowsocks").put("sing-box.json", files.getString("start-layer-source.json"));
        return compiled;
    }

    static JSONObject applyDevice(JSONObject bundle, JSONObject graph) throws Exception {
        JSONObject node = AndroidProfileSelection.selectedRouterProfile(bundle);
        JSONArray inbounds = graph.getJSONArray("inbounds");
        if (inbounds.length() != 1) throw new IllegalStateException("Native Xray must retain one system VPN.");
        JSONObject tun = inbounds.getJSONObject(0);
        if (!tun.has("tag")) tun.put("tag", "tun-in");
        if (!tun.has("address")) tun.put("address", new JSONArray().put("172.19.0.1/30").put("fdfe:dcba:9876::1/126"));
        int mtu = AndroidNativeProfilePolicy.selectedMtu(bundle,
                AndroidNativeProfilePolicy.exactInteger(tun, "mtu", 1280, 1280, 9000));
        tun.put("mtu", mtu);
        return new JSONObject(bounded(Libbox.routerApplyNativeXrayDevicePolicy(graph.toString(), node.toString())));
    }

    static void normalizeDnsRoutes(JSONObject graph) throws Exception {
        JSONObject route = graph.getJSONObject("route");
        String tcp = route.getString("final"), udp = tcp;
        JSONArray rules = route.optJSONArray("rules"), outbounds = graph.getJSONArray("outbounds");
        for (int i = 0; rules != null && i < rules.length(); i++) {
            JSONObject rule = rules.getJSONObject(i);
            if (rule.length() == 3 && "udp".equals(rule.optString("network")) && "route".equals(rule.optString("action"))) {
                String tag = rule.getString("outbound");
                for (int j = 0; j < outbounds.length(); j++) {
                    JSONObject out = outbounds.getJSONObject(j);
                    if (tag.equals(out.optString("tag")) && "hysteria2".equals(out.optString("type"))) udp = tag;
                }
            }
        }
        JSONArray servers = graph.getJSONObject("dns").getJSONArray("servers");
        for (int i = 0; i < servers.length(); i++) {
            JSONObject resolver = servers.getJSONObject(i);
            resolver.put("detour", Arrays.asList("udp", "h3", "quic").contains(resolver.getString("type")) ? udp : tcp);
        }
    }

    private static void verifyAssets(JSONObject profile) throws Exception {
        JSONArray names = profile.names();
        if (names == null) throw new IllegalStateException("Missing native Xray profile.");
        for (int i = 0; i < names.length(); i++) {
            if (!Arrays.asList("sing-box.json", "xray.json", "cert.pem", "stack.json").contains(names.getString(i))) {
                throw new IllegalStateException("Native Xray profile contains an unowned helper.");
            }
        }
    }

    private static String legacyWrapper(String mode, String raw) throws Exception {
        if (!"reality-xhttp".equals(mode)) throw new IllegalStateException("Native Xray requires its owned TUN wrapper.");
        JSONArray in = new JSONObject(raw).getJSONArray("inbounds");
        if (in.length() != 1) throw new IllegalStateException("Ambiguous legacy Xray ingress.");
        int port = AndroidNativeProfilePolicy.exactInteger(in.getJSONObject(0), "port", 0, 1, 65535);
        JSONObject tun = new JSONObject().put("type", "tun").put("tag", "tun-in")
                .put("address", new JSONArray().put("172.19.0.1/30").put("fdfe:dcba:9876::1/126"))
                .put("mtu", 1280).put("auto_route", true).put("strict_route", true).put("stack", "gvisor");
        JSONObject out = new JSONObject().put("type", "socks").put("tag", "proxy")
                .put("server", "127.0.0.1").put("server_port", port).put("version", "5");
        return new JSONObject().put("inbounds", new JSONArray().put(tun)).put("outbounds", new JSONArray().put(out))
                .put("route", new JSONObject().put("final", "proxy").put("rules", new JSONArray())).toString();
    }

    private static String bounded(String value) {
        if (value == null || value.isEmpty() || value.getBytes(StandardCharsets.UTF_8).length > LIMIT) {
            throw new IllegalStateException("Native Xray returned no bounded configuration.");
        }
        return value;
    }
    private AndroidXrayLibboxPolicy() {}
}
