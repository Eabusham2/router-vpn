package com.eabusham.routervpn;

import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Composes the optional authenticated Router VPN Start Layer into Android's
 * native Libbox raw-mode graph. AES is real Shadowsocks 2022 AES-256-GCM.
 * XOR whitening is not implemented here and must fail closed rather than being
 * treated as encryption or silently ignored.
 */
final class AndroidStartLayer {
    static final String OFF = "off";
    static final String AES = "aes-256-gcm";
    static final String AES_XOR = "aes-256-gcm+xor-whitening";
    static final String AES_METHOD = "2022-blake3-aes-256-gcm";
    static final String AES_TAG = "start-layer-aes";

    private static final Set<String> SUPPORTED = new HashSet<>(Arrays.asList(
            "shadowsocks", "hysteria2", "naive-h2", "naive-h3"));

    static String selectedMode(JSONObject bundle) throws Exception {
        JSONObject profile = selectedRouterProfile(bundle);
        return normalize(profile.optString("start_layer", OFF));
    }

    static boolean supportsRawMode(String modeId) {
        return modeId != null && SUPPORTED.contains(modeId.trim().toLowerCase(Locale.ROOT));
    }

    static String nativeCapabilityReason(JSONObject bundle, String modeId) {
        try {
            String start = selectedMode(bundle);
            if (OFF.equals(start)) return "";
            if (!supportsRawMode(modeId)) return modeId + " has no proved Android Start Layer composition path.";
            if (AES_XOR.equals(start)) {
                return "AES-256-GCM + XOR whitening is not available on Android until the VpnService owns a protected local whitening relay; XOR is never counted as encryption.";
            }
            return "";
        } catch (Exception error) {
            String message = error.getMessage();
            return message == null || message.trim().isEmpty() ? "Invalid Android Start Layer preference." : message.trim();
        }
    }

    static void apply(JSONObject bundle, JSONObject targetConfig, String modeId) throws Exception {
        String start = selectedMode(bundle);
        if (OFF.equals(start)) return;
        String mode = modeId == null ? "" : modeId.trim().toLowerCase(Locale.ROOT);
        if (!SUPPORTED.contains(mode)) {
            throw new IllegalStateException(mode + " does not have a proved Android Start Layer composition path.");
        }
        if (AES_XOR.equals(start)) {
            throw new IllegalStateException("AES-256-GCM + XOR whitening requires a protected Android local whitening relay; this build refuses to silently ignore or downgrade it.");
        }
        if (!AES.equals(start)) throw new IllegalStateException("Unsupported Android Start Layer: " + start);

        JSONArray outbounds = targetConfig.optJSONArray("outbounds");
        if (outbounds == null) throw new IllegalStateException(mode + " has no Libbox outbounds.");
        if ("shadowsocks".equals(mode)) {
            JSONObject ss = exactlyOneType(outbounds, "shadowsocks", "selected Shadowsocks mode");
            requireAESOutbound(ss);
            return;
        }

        JSONObject profiles = bundle.optJSONObject("profiles");
        JSONObject ssProfile = profiles == null ? null : profiles.optJSONObject("shadowsocks");
        if (ssProfile == null) throw new IllegalStateException("Generated Shadowsocks 2022 profile is missing for Android Start Layer.");
        String encoded = ssProfile.optString("sing-box.json", "").trim();
        if (encoded.isEmpty()) throw new IllegalStateException("Generated Shadowsocks 2022 config is missing for Android Start Layer.");
        byte[] raw;
        try { raw = Base64.decode(encoded, Base64.DEFAULT); }
        catch (IllegalArgumentException invalid) { throw new IllegalStateException("Generated Shadowsocks 2022 config is not valid base64.", invalid); }
        if (raw.length == 0 || raw.length > 4 * 1024 * 1024) throw new IllegalStateException("Generated Shadowsocks 2022 config size is invalid.");
        JSONObject ssDoc = new JSONObject(new String(raw, StandardCharsets.UTF_8));
        JSONArray ssOutbounds = ssDoc.optJSONArray("outbounds");
        if (ssOutbounds == null) throw new IllegalStateException("Generated Shadowsocks 2022 config has no outbounds.");
        JSONObject aes = new JSONObject(exactlyOneType(ssOutbounds, "shadowsocks", "generated Shadowsocks profile").toString());
        requireAESOutbound(aes);
        aes.put("tag", AES_TAG);

        JSONObject inner = exactlyOneTag(outbounds, "proxy", mode);
        String detour = inner.optString("detour", "").trim();
        if (!detour.isEmpty()) throw new IllegalStateException(mode + " proxy outbound already owns a detour; Start Layer will not overwrite it.");
        inner.put("server", "127.0.0.1");
        inner.put("detour", AES_TAG);
        outbounds.put(aes);
    }

    private static JSONObject selectedRouterProfile(JSONObject bundle) throws Exception {
        JSONArray profiles = bundle.optJSONArray("routerProfiles");
        String selected = bundle.optString("selectedRouterID", "").trim();
        if (profiles == null || profiles.length() == 0) throw new IllegalStateException("Router VPN bundle has no Router profiles.");
        JSONObject fallback = null;
        for (int i = 0; i < profiles.length(); i++) {
            JSONObject profile = profiles.optJSONObject(i);
            if (profile == null) continue;
            if (fallback == null) fallback = profile;
            if (!selected.isEmpty() && selected.equals(profile.optString("id", ""))) return requireHome(profile);
        }
        if (!selected.isEmpty()) throw new IllegalStateException("Selected Router VPN profile is missing from the Android bundle.");
        return requireHome(fallback);
    }

    private static JSONObject requireHome(JSONObject profile) throws Exception {
        if (profile == null) throw new IllegalStateException("Router VPN profile is missing.");
        String kind = profile.optString("node_kind", "router-vpn").trim().toLowerCase(Locale.ROOT);
        if (kind.isEmpty()) kind = "router-vpn";
        if (!"router-vpn".equals(kind)) throw new IllegalStateException("Start Layer is owned by Router VPN home-node profiles; external nodes keep their own transport security.");
        return profile;
    }

    private static JSONObject exactlyOneType(JSONArray values, String type, String label) throws Exception {
        JSONObject found = null;
        int matches = 0;
        for (int i = 0; i < values.length(); i++) {
            JSONObject value = values.optJSONObject(i);
            if (value != null && type.equalsIgnoreCase(value.optString("type", "").trim())) {
                found = value; matches++;
            }
        }
        if (matches != 1) throw new IllegalStateException(label + " must contain exactly one " + type + " outbound.");
        return found;
    }

    private static JSONObject exactlyOneTag(JSONArray values, String tag, String label) throws Exception {
        JSONObject found = null;
        int matches = 0;
        for (int i = 0; i < values.length(); i++) {
            JSONObject value = values.optJSONObject(i);
            if (value != null && tag.equals(value.optString("tag", "").trim())) { found = value; matches++; }
        }
        if (matches != 1) throw new IllegalStateException(label + " must expose exactly one " + tag + " outbound for Start Layer composition.");
        return found;
    }

    private static void requireAESOutbound(JSONObject outbound) throws Exception {
        String method = outbound.optString("method", "").trim().toLowerCase(Locale.ROOT);
        String password = outbound.optString("password", "");
        if (!AES_METHOD.equals(method) || password.isEmpty()) {
            throw new IllegalStateException("Start Layer requires authenticated Shadowsocks 2022 BLAKE3 AES-256-GCM.");
        }
        String server = outbound.optString("server", "").trim();
        int port = outbound.optInt("server_port", 0);
        if (server.isEmpty() || port < 1 || port > 65535) throw new IllegalStateException("Start Layer AES outbound has an invalid server/port.");
    }

    private static String normalize(String value) {
        String raw = value == null ? "" : value.trim().toLowerCase(Locale.ROOT).replace('_', '-').replace(" ", "");
        if (raw.isEmpty() || "off".equals(raw) || "none".equals(raw) || "disabled".equals(raw)) return OFF;
        if ("aes".equals(raw) || "aes256".equals(raw) || "aes-256".equals(raw) || "aes-gcm".equals(raw) || "aes256-gcm".equals(raw) || AES.equals(raw)) return AES;
        if ("aes+xor".equals(raw) || "xor+aes".equals(raw) || "aes-256-gcm+xor".equals(raw) || "xor+aes-256-gcm".equals(raw) || AES_XOR.equals(raw)) return AES_XOR;
        if ("xor".equals(raw) || "xor-only".equals(raw) || "xor-whitening".equals(raw)) throw new IllegalArgumentException("XOR whitening is obfuscation only and requires authenticated AES-256-GCM.");
        throw new IllegalArgumentException("Unsupported Start Layer " + raw + ".");
    }

    private AndroidStartLayer() {}
}
