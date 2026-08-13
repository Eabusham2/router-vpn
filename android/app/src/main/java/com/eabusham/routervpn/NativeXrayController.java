package com.eabusham.routervpn;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Builds bounded app-private Xray sessions from self-contained generated Router VPN profiles. */
final class NativeXrayController {
    static final String PREFS = "router-vpn";
    static final String STATE_KEY = "xray_state_v1";
    static final String MODE_KEY = "xray_mode_v1";
    static final String ERROR_KEY = "xray_error_v1";
    static final String CONFIG_FILE = "xray.json";
    static final String META_FILE = "session.json";

    private static final int MAX_BUNDLE = 64 * 1024 * 1024;
    private static final int MAX_CONFIG = 4 * 1024 * 1024;
    private static final int MAX_PROFILE_FILE = 8 * 1024 * 1024;
    private static final int MAX_PROFILE_TOTAL = 32 * 1024 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    static final class ModeInfo {
        final String id;
        final String name;
        ModeInfo(String id, String name) { this.id = id; this.name = name; }
        @Override public String toString() { return name; }
    }

    static final class SessionInfo {
        final String sessionId;
        final String modeId;
        SessionInfo(String sessionId, String modeId) { this.sessionId = sessionId; this.modeId = modeId; }
    }

    private final Context context;
    NativeXrayController(Context context) { this.context = context.getApplicationContext(); }

    List<ModeInfo> listDirectXrayModes(File privateBundle) throws Exception {
        JSONObject root = loadBundle(privateBundle);
        JSONObject profiles = root.optJSONObject("profiles");
        JSONArray modes = root.optJSONArray("modes");
        List<ModeInfo> result = new ArrayList<>();
        if (profiles == null || modes == null) return result;
        for (int i = 0; i < modes.length(); i++) {
            JSONObject mode = modes.optJSONObject(i);
            if (mode == null) continue;
            String id = mode.optString("id", "").trim();
            if (!safeToken(id)) continue;
            JSONObject profile = profiles.optJSONObject(id);
            if (profile == null || isCompositeProfile(profile)) continue;
            String encoded = profile.optString(CONFIG_FILE, "").trim();
            if (encoded.isEmpty()) continue;
            byte[] config;
            try { config = Base64.decode(encoded, Base64.DEFAULT); } catch (IllegalArgumentException invalid) { continue; }
            if (config.length <= 0 || config.length > MAX_CONFIG) continue;
            if (!isDirectXrayConfig(new String(config, StandardCharsets.UTF_8))) continue;
            String name = mode.optString("name", id).trim();
            result.add(new ModeInfo(id, name.isEmpty() ? id : name));
        }
        return result;
    }

    SessionInfo prepareSession(File privateBundle, String modeId) throws Exception {
        if (!safeToken(modeId)) throw new IllegalArgumentException("Invalid Xray mode id.");
        JSONObject root = loadBundle(privateBundle);
        JSONObject profiles = root.optJSONObject("profiles");
        JSONObject profile = profiles == null ? null : profiles.optJSONObject(modeId);
        if (profile == null) throw new IllegalStateException("The selected mode has no generated profile.");
        if (isCompositeProfile(profile)) throw new IllegalStateException("The selected mode is a composite/multi-engine profile and cannot be represented truthfully by native Xray alone.");
        String encoded = profile.optString(CONFIG_FILE, "").trim();
        if (encoded.isEmpty()) throw new IllegalStateException("The selected mode has no Xray config.");
        byte[] raw = Base64.decode(encoded, Base64.DEFAULT);
        if (raw.length <= 0 || raw.length > MAX_CONFIG) throw new IllegalStateException("Xray config size is invalid.");
        JSONObject config = new JSONObject(new String(raw, StandardCharsets.UTF_8));
        String proxyTag = validatedProxyTag(config);
        patchForAndroidTun(config, proxyTag, selectedMtu(root));
        byte[] patched = (config.toString(2) + "\n").getBytes(StandardCharsets.UTF_8);
        if (patched.length > MAX_CONFIG) throw new IllegalStateException("Patched Xray config exceeds safety limit.");

        File sessionsRoot = new File(context.getFilesDir(), "xray-sessions");
        if (!sessionsRoot.isDirectory() && !sessionsRoot.mkdirs()) throw new IllegalStateException("Cannot create Xray session directory.");
        cleanupOldSessions(sessionsRoot);
        String sessionId = randomHex(16);
        File session = new File(sessionsRoot, sessionId);
        if (!session.mkdir()) throw new IllegalStateException("Cannot create Xray session.");
        int total = 0;
        try {
            if (AndroidKillSwitchPolicy.strictRequested(root)) writeFile(new File(session, AndroidKillSwitchPolicy.SESSION_MARKER), new byte[]{'1','\n'});
            JSONArray names = profile.names();
            if (names == null) throw new IllegalStateException("Selected Xray profile is empty.");
            for (int i = 0; i < names.length(); i++) {
                String name = names.getString(i);
                if (!safeFileName(name)) throw new IllegalStateException("Unsafe Xray profile filename: " + name);
                byte[] decoded;
                if (CONFIG_FILE.equals(name)) decoded = patched;
                else {
                    String value = profile.optString(name, "").trim();
                    if (value.isEmpty()) continue;
                    decoded = Base64.decode(value, Base64.DEFAULT);
                }
                if (decoded.length > MAX_PROFILE_FILE) throw new IllegalStateException("Xray profile file is too large: " + name);
                total += decoded.length;
                if (total > MAX_PROFILE_TOTAL) throw new IllegalStateException("Selected Xray profile exceeds safety limit.");
                writeFile(new File(session, name), decoded);
            }
            JSONObject meta = new JSONObject()
                    .put("modeId", modeId)
                    .put("dns", selectedPlainDns(root))
                    .put("mtu", selectedMtu(root));
            writeFile(new File(session, META_FILE), (meta.toString() + "\n").getBytes(StandardCharsets.UTF_8));
            return new SessionInfo(sessionId, modeId);
        } catch (Throwable error) {
            deleteTree(session);
            throw error;
        }
    }

    void start(SessionInfo session) {
        Intent intent = new Intent(context, XrayVpnService.class)
                .setAction(XrayVpnService.ACTION_START)
                .putExtra(XrayVpnService.EXTRA_SESSION_ID, session.sessionId)
                .putExtra(XrayVpnService.EXTRA_MODE_ID, session.modeId);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(intent); else context.startService(intent);
    }

    void stop() { context.startService(new Intent(context, XrayVpnService.class).setAction(XrayVpnService.ACTION_STOP)); }
    String getState() { return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(STATE_KEY, "DOWN"); }
    String getMode() { return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(MODE_KEY, ""); }
    String getError() { return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(ERROR_KEY, ""); }

    private static boolean isCompositeProfile(JSONObject profile) {
        // These files are generated only for protocol-split/MAX/multi-engine
        // graphs. Their xray.json is one sidecar, not the semantic whole mode.
        // Native Xray must never silently downgrade such a mode to that sidecar.
        return profile.has("stack.json")
                || profile.has("chain.env")
                || profile.has("middle-sing-box.json")
                || profile.has("outer-xray.json")
                || profile.has("outer-sing-box.json");
    }

    private static boolean isDirectXrayConfig(String text) {
        try { validatedProxyTag(new JSONObject(text)); return true; } catch (Throwable invalid) { return false; }
    }

    private static String validatedProxyTag(JSONObject config) throws Exception {
        JSONArray outbounds = config.optJSONArray("outbounds");
        if (outbounds == null || outbounds.length() == 0) throw new IllegalStateException("Xray config has no outbounds.");
        JSONObject selected = null;
        for (int i = 0; i < outbounds.length(); i++) {
            JSONObject outbound = outbounds.optJSONObject(i);
            if (outbound != null && "proxy".equals(outbound.optString("tag", ""))) { selected = outbound; break; }
        }
        if (selected == null) throw new IllegalStateException("Xray config has no generated proxy outbound.");
        String protocol = selected.optString("protocol", "").trim().toLowerCase(Locale.ROOT);
        if (protocol.isEmpty() || "freedom".equals(protocol) || "direct".equals(protocol) || "blackhole".equals(protocol) || "block".equals(protocol)) {
            throw new IllegalStateException("Xray proxy outbound is not a protected transport.");
        }
        JSONObject settings = selected.optJSONObject("settings");
        if (settings != null) {
            JSONArray vnext = settings.optJSONArray("vnext");
            if (vnext != null && vnext.length() > 0) {
                String address = vnext.optJSONObject(0) == null ? "" : vnext.optJSONObject(0).optString("address", "").trim();
                if (isLoopbackHost(address)) throw new IllegalStateException("Xray proxy outbound depends on a local wrapper.");
            }
            String server = settings.optString("address", settings.optString("server", "")).trim();
            if (isLoopbackHost(server)) throw new IllegalStateException("Xray proxy outbound depends on a local wrapper.");
        }
        String directServer = selected.optString("server", "").trim();
        if (isLoopbackHost(directServer)) throw new IllegalStateException("Xray proxy outbound depends on a local wrapper.");
        String tag = selected.optString("tag", "").trim();
        if (!safeToken(tag)) throw new IllegalStateException("Xray proxy tag is unsafe.");
        return tag;
    }

    private static void patchForAndroidTun(JSONObject config, String proxyTag, int mtu) throws Exception {
        JSONArray inbounds = new JSONArray();
        inbounds.put(new JSONObject()
                .put("tag", "routervpn-tun")
                .put("port", 0)
                .put("protocol", "tun")
                .put("settings", new JSONObject().put("name", "routervpn0").put("MTU", mtu)));
        config.put("inbounds", inbounds);
        JSONObject routing = config.optJSONObject("routing");
        if (routing == null) routing = new JSONObject();
        JSONArray old = routing.optJSONArray("rules");
        JSONArray rules = new JSONArray();
        rules.put(new JSONObject()
                .put("type", "field")
                .put("inboundTag", new JSONArray().put("routervpn-tun"))
                .put("outboundTag", proxyTag));
        if (old != null) for (int i = 0; i < old.length(); i++) rules.put(old.get(i));
        routing.put("rules", rules);
        config.put("routing", routing);
    }

    private static String selectedPlainDns(JSONObject bundle) throws Exception {
        JSONObject p = selectedProfile(bundle);
        if (p == null) return "1.1.1.1";
        String mode = p.optString("dns_mode", "fastest").trim().toLowerCase(Locale.ROOT);
        String protocol = p.optString("dns_protocol", "udp").trim().toLowerCase(Locale.ROOT);
        String host;
        if ("home".equals(mode)) host = p.optString("adguard_ipv4", p.optString("adguard_ipv6", "")).trim();
        else if ("fastest".equals(mode)) host = p.optString("fastest_dns_host", "1.1.1.1").trim();
        else host = p.optString("dns_host", p.optString("fastest_dns_host", "1.1.1.1")).trim();
        if (!("udp".equals(protocol) || "tcp".equals(protocol) || "fastest".equals(mode) || "home".equals(mode))) {
            throw new IllegalStateException("Native Xray currently requires an IP-based plain selected DNS; encrypted selected DNS remains available through embedded libbox modes.");
        }
        if (!isLiteralIp(host)) throw new IllegalStateException("Native Xray selected DNS must be a literal IP address.");
        return host;
    }

    private static int selectedMtu(JSONObject bundle) {
        JSONObject p = selectedProfile(bundle);
        int mtu = p == null ? 1380 : p.optInt("mtu", p.optInt("tun_mtu", 1380));
        if (mtu < 1200 || mtu > 9000) mtu = 1380;
        return mtu;
    }

    private static JSONObject selectedProfile(JSONObject bundle) {
        JSONArray profiles = bundle.optJSONArray("routerProfiles");
        String wanted = bundle.optString("selectedRouterID", "").trim();
        if (profiles == null) return null;
        for (int i = 0; i < profiles.length(); i++) {
            JSONObject p = profiles.optJSONObject(i);
            if (p != null && wanted.equals(p.optString("id", ""))) return p;
        }
        return profiles.length() > 0 ? profiles.optJSONObject(0) : null;
    }

    private static boolean isLiteralIp(String value) {
        if (value == null || value.trim().isEmpty()) return false;
        String v = value.trim();
        try {
            InetAddress parsed = InetAddress.getByName(v);
            if (v.indexOf(':') >= 0) return parsed.getAddress().length == 16;
            return v.matches("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}") && parsed.getAddress().length == 4;
        } catch (Exception invalid) { return false; }
    }

    private static boolean isLoopbackHost(String value) {
        if (value == null) return false;
        String v = value.trim().toLowerCase(Locale.ROOT);
        return "localhost".equals(v) || "127.0.0.1".equals(v) || "::1".equals(v) || v.startsWith("127.");
    }

    private static JSONObject loadBundle(File file) throws Exception {
        if (file == null || !file.isFile() || file.length() <= 0 || file.length() > MAX_BUNDLE) throw new IllegalStateException("Private node bundle is missing or invalid.");
        try (FileInputStream input = new FileInputStream(file)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192]; int total = 0, read;
            while ((read = input.read(buffer)) != -1) {
                total += read; if (total > MAX_BUNDLE) throw new IllegalStateException("Private node bundle exceeds safety limit.");
                output.write(buffer, 0, read);
            }
            JSONObject root = new JSONObject(new String(output.toByteArray(), StandardCharsets.UTF_8));
            AndroidNodeStore.validateBundle(root);
            return root;
        }
    }

    private static boolean safeToken(String value) { return value != null && value.matches("[A-Za-z0-9._-]{1,96}") && !value.equals(".") && !value.equals("..") && !value.contains(".."); }
    private static boolean safeFileName(String value) { return value != null && value.matches("[A-Za-z0-9._-]{1,128}") && !value.equals(".") && !value.equals("..") && !value.contains(".."); }
    private static String randomHex(int bytes) { byte[] raw = new byte[bytes]; RANDOM.nextBytes(raw); StringBuilder out = new StringBuilder(bytes * 2); for (byte b : raw) out.append(String.format(Locale.ROOT, "%02x", b & 0xff)); return out.toString(); }
    private static void writeFile(File file, byte[] bytes) throws Exception { try (FileOutputStream output = new FileOutputStream(file, false)) { output.write(bytes); output.getFD().sync(); } }
    private static void cleanupOldSessions(File root) { File[] children = root.listFiles(); if (children == null) return; long cutoff = System.currentTimeMillis() - 24L * 60L * 60L * 1000L; for (File child : children) if (child.lastModified() < cutoff) deleteTree(child); }
    static void deleteTree(File file) { if (file == null || !file.exists()) return; if (file.isDirectory()) { File[] children = file.listFiles(); if (children != null) for (File child : children) deleteTree(child); } file.delete(); }
}
