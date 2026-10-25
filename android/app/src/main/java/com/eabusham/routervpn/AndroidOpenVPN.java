package com.eabusham.routervpn;

import io.nekohasekai.libbox.Libbox;
import org.json.JSONObject;

/** Private .ovpn compilation uses the same single Go runtime as the live TUN. */
final class AndroidOpenVPN {
    private AndroidOpenVPN() { }

    static JSONObject pairing(AndroidStandardExitStore.Entry entry, String raw) throws Exception {
        if (raw == null || raw.trim().isEmpty()) return null;
        if (entry == null || !"openvpn".equals(entry.protocol) || raw.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 512 * 1024)
            throw new IllegalArgumentException("OpenVPN pairing belongs to its bounded private OpenVPN node.");
        JSONObject profile = new JSONObject().put("config", entry.openVPNConfig).put("username", entry.username).put("password", entry.password);
        // Validate the original editor bytes before JSONObject can collapse
        // duplicate keys. The shared parser rejects server secrets and proves
        // independent provider/client identities and exact remote policy.
        Libbox.routerValidateExternalOpenVPNPairing(profile.toString(), raw);
        return new JSONObject(raw);
    }

    static void validatePairing(AndroidStandardExitStore.Entry entry) throws Exception {
        if (entry.openVPNPairing != null) pairing(entry, entry.openVPNPairing.toString());
    }

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
