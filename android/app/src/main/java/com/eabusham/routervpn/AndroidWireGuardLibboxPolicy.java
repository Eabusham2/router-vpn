package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;
import io.nekohasekai.libbox.Libbox;

/** Applies one frozen node's policy to its native WG endpoint and sole OS TUN. */
final class AndroidWireGuardLibboxPolicy {
    static JSONObject apply(JSONObject bundle, JSONObject config) throws Exception {
        JSONObject profile = AndroidProfileSelection.selectedRouterProfile(bundle);
        for (String key : new String[]{"daita_enabled", "jumbo_tun"}) {
            if (AndroidNativeProfilePolicy.booleanPolicy(profile, key, false)) {
                throw new IllegalStateException("Native WireGuard Libbox does not implement " + key + "; no session was started.");
            }
        }
        JSONArray inbounds = config.getJSONArray("inbounds");
        JSONArray endpoints = config.getJSONArray("endpoints");
        if (inbounds.length() != 1 || endpoints.length() != 1 || config.getJSONArray("outbounds").length() != 0) {
            throw new IllegalStateException("Single-node WireGuard requires one TUN and one owned native endpoint.");
        }
        JSONObject tun = inbounds.getJSONObject(0), endpoint = endpoints.getJSONObject(0);
        if (!"tun".equals(tun.getString("type")) || !"tun-in".equals(tun.getString("tag"))
                || !Boolean.TRUE.equals(tun.opt("auto_route")) || !Boolean.TRUE.equals(tun.opt("strict_route"))
                || !("wireguard".equals(endpoint.getString("type")) || "routervpn-amneziawg".equals(endpoint.getString("type"))) || !"proxy".equals(endpoint.getString("tag"))
                || endpoint.has("detour") || !Boolean.FALSE.equals(endpoint.opt("system"))
                || !"proxy".equals(config.getJSONObject("route").getString("final"))) {
            throw new IllegalStateException("Single-node WireGuard lost its native graph ownership.");
        }
        int nativeMtu = AndroidNativeProfilePolicy.selectedMtu(bundle,
                AndroidNativeProfilePolicy.exactInteger(endpoint, "mtu", 1280, 1280, 9000));
        String policy = AndroidNativeProfilePolicy.stringPolicy(profile, "mtu_policy", "auto");
        boolean fixed = "manual".equals(policy) || "fixed".equals(policy);
        int tunMtu = fixed ? nativeMtu : Math.min(nativeMtu,
                AndroidNativeProfilePolicy.exactInteger(tun, "mtu", 1280, 1280, 9000));
        endpoint.put("mtu", nativeMtu); tun.put("mtu", tunMtu);
        String ipv6 = AndroidNativeProfilePolicy.stringPolicy(profile, "ipv6_mode", "on");
        if (!java.util.Arrays.asList("", "on", "auto", "off").contains(ipv6)) throw new IllegalStateException("Unknown IPv6 policy.");
        if ("off".equals(ipv6)) {
            // Keep IPv6 captured by Android. Removing its route would let it
            // escape via the underlying network instead of rejecting it.
            JSONObject route = config.getJSONObject("route");
            JSONArray rules = route.getJSONArray("rules");
            JSONArray next = new JSONArray().put(new JSONObject().put("inbound", new JSONArray().put("tun-in"))
                    .put("ip_version", 6).put("action", "reject"));
            for (int i = 0; i < rules.length(); i++) next.put(rules.get(i));
            route.put("rules", next);
            config.getJSONObject("dns").put("strategy", "ipv4_only");
        }
        // The existing LAN compiler also works for a single node: both policy
        // inputs name the same frozen profile. Its private proof exception is
        // exact host+port, not a LAN bypass; no extra tunnel is constructed.
        JSONObject policies = new JSONObject().put("entry", profile).put("exit", profile);
        String result = Libbox.routerApplyMultihopLANPolicy(config.toString(), policies.toString());
        if (result == null || result.isEmpty() || result.length() > 4 * 1024 * 1024) {
            throw new IllegalStateException("Native WireGuard policy returned no bounded graph.");
        }
        return new JSONObject(result);
    }
    private AndroidWireGuardLibboxPolicy() {}
}
