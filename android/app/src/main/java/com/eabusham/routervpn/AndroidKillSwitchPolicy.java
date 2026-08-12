package com.eabusham.routervpn;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

/** Shared fail-closed interpretation of the selected router's Android kill-switch policy. */
final class AndroidKillSwitchPolicy {
    static final String SESSION_MARKER = ".strict-lockdown";
    private static final int MAX_BUNDLE = 64 * 1024 * 1024;

    static boolean strictRequested(File bundle) throws Exception {
        if (bundle == null || !bundle.isFile() || bundle.length() <= 0 || bundle.length() > MAX_BUNDLE) {
            throw new IllegalStateException("Private node bundle is missing or invalid.");
        }
        try (FileInputStream input = new FileInputStream(bundle)) {
            return strictRequested(new JSONObject(new String(readLimited(input), StandardCharsets.UTF_8)));
        }
    }

    static boolean strictRequested(JSONObject bundle) {
        JSONObject profile = selectedProfile(bundle);
        if (profile == null) return false;
        String policy = profile.optString("kill_switch_policy", "off").trim().toLowerCase();
        return profile.optBoolean("kill_switch", false)
                || "strict".equals(policy)
                || "always".equals(policy)
                || "lockdown".equals(policy);
    }

    static String requirementMessage() {
        return "Strict kill switch requires Android Always-on VPN plus ‘Block connections without VPN’ for Router VPN. Open Android VPN settings, enable both, then connect an embedded libbox mode. Raw WG/AWG backends are not accepted as strict until Router VPN can prove their lockdown service state.";
    }

    private static JSONObject selectedProfile(JSONObject bundle) {
        JSONArray profiles = bundle.optJSONArray("routerProfiles");
        String wanted = bundle.optString("selectedRouterID", "").trim();
        if (profiles == null) return null;
        for (int i = 0; i < profiles.length(); i++) {
            JSONObject profile = profiles.optJSONObject(i);
            if (profile != null && wanted.equals(profile.optString("id", ""))) return profile;
        }
        return profiles.length() > 0 ? profiles.optJSONObject(0) : null;
    }

    private static byte[] readLimited(FileInputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0, read;
        while ((read = input.read(buffer)) != -1) {
            total += read;
            if (total > MAX_BUNDLE) throw new IllegalStateException("Private node bundle exceeds safety limit.");
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private AndroidKillSwitchPolicy() {}
}
