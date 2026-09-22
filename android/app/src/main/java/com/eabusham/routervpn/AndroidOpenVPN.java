package com.eabusham.routervpn;

import io.nekohasekai.libbox.Libbox;
import org.json.JSONObject;

/** Private .ovpn compilation uses the same single Go runtime as the live TUN. */
final class AndroidOpenVPN {
    private AndroidOpenVPN() { }

    static JSONObject endpoint(AndroidStandardExitStore.Entry entry, String detour) throws Exception {
        if (entry == null) throw new IllegalArgumentException("OpenVPN exit is required.");
        if (!"1.14.1".equals(Libbox.version().trim())) {
            throw new IllegalStateException("The pinned native OpenVPN core does not match this app.");
        }
        String value = Libbox.routerOpenVPNEndpoint(
                entry.openVPNConfig == null ? "" : entry.openVPNConfig,
                entry.username == null ? "" : entry.username,
                entry.password == null ? "" : entry.password,
                "custom-exit", detour);
        JSONObject result = new JSONObject(value);
        if (!"openvpn-client".equals(result.optString("type")) || result.optBoolean("system", true)
                || !"custom-exit".equals(result.optString("tag"))
                || !detour.equals(result.optString("detour", ""))) {
            throw new IllegalStateException("Native OpenVPN compiler returned an invalid owned endpoint.");
        }
        return result;
    }
}
