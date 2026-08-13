package com.eabusham.routervpn;

import android.content.Context;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Builds one real Android VpnService graph: standard WireGuard entry endpoint ->
 * self-contained Shadowsocks/Hysteria2 exit outbound -> Internet.
 *
 * Pinned sing-box 1.13.12 resolves DialerOptions.detour through OutboundManager,
 * whose Outbound(tag) falls back to EndpointManager.Get(tag); WireGuard endpoints
 * implement adapter.Outbound. Keep other/mixed engine combinations fail-closed.
 */
final class AndroidMultihopController {
    private static final int MAX_BUNDLE = 32 * 1024 * 1024;
    private static final int MAX_CONFIG = 4 * 1024 * 1024;
    private static final int MAX_FILE = 8 * 1024 * 1024;
    private static final int MAX_TOTAL = 32 * 1024 * 1024;
    private static final int MAX_SESSION_DIRS = 32;
    private static final SecureRandom RANDOM = new SecureRandom();
    private final Context context;
    private final NativeSingBoxController singBox;

    static final class Prepared {
        final NativeSingBoxController.SessionInfo session;
        final File exitBundle;
        final String exitMode;
        Prepared(NativeSingBoxController.SessionInfo session, File exitBundle, String exitMode) {
            this.session = session; this.exitBundle = exitBundle; this.exitMode = exitMode;
        }
    }

    AndroidMultihopController(Context context, NativeSingBoxController singBox) {
        this.context = context.getApplicationContext();
        this.singBox = singBox;
    }

    List<NativeSingBoxController.ModeInfo> listSupportedExitModes(File exitBundle) throws Exception {
        List<NativeSingBoxController.ModeInfo> result = new ArrayList<>();
        for (NativeSingBoxController.ModeInfo mode : singBox.listDirectLibboxModes(exitBundle)) {
            if ("shadowsocks".equals(mode.id) || "hysteria2".equals(mode.id)) result.add(mode);
        }
        return result;
    }

    Prepared prepare(File entryBundle, File exitBundle, String exitMode) throws Exception {
        if (entryBundle == null || exitBundle == null) throw new IllegalArgumentException("Choose both an entry and an exit node.");
        if (entryBundle.getCanonicalFile().equals(exitBundle.getCanonicalFile())) throw new IllegalArgumentException("Entry and exit must be different stored nodes.");
        if (!("shadowsocks".equals(exitMode) || "hysteria2".equals(exitMode))) throw new IllegalArgumentException("Android multihop currently supports Shadowsocks or Hysteria2 as the exit transport.");

        JSONObject entry = loadBundle(entryBundle);
        JSONObject exit = loadBundle(exitBundle);
        String entryIdentity = AndroidNodeStore.stableNodeIdentity(entry);
        String exitIdentity = AndroidNodeStore.stableNodeIdentity(exit);
        if (!entryIdentity.isEmpty() && entryIdentity.equals(exitIdentity)) throw new IllegalArgumentException("Entry and exit resolve to the same Router VPN node identity.");
        WgConfig wg = parseWireGuard(entry);
        JSONObject exitProfile = requiredProfile(exit, exitMode);
        String encodedConfig = exitProfile.optString("sing-box.json", "").trim();
        if (encodedConfig.isEmpty()) throw new IllegalStateException("Exit mode has no embedded sing-box config.");
        byte[] rawConfig = Base64.decode(encodedConfig, Base64.DEFAULT);
        if (rawConfig.length == 0 || rawConfig.length > MAX_CONFIG) throw new IllegalStateException("Exit sing-box config size is invalid.");
        JSONObject config = new JSONObject(new String(rawConfig, StandardCharsets.UTF_8));
        makeMultihopConfig(config, wg, exitMode);
        byte[] patched = (config.toString(2) + "\n").getBytes(StandardCharsets.UTF_8);
        if (patched.length > MAX_CONFIG) throw new IllegalStateException("Multihop sing-box config exceeds safety limit.");

        File root = new File(context.getFilesDir(), "layered-sessions");
        if (!root.isDirectory() && !root.mkdirs()) throw new IllegalStateException("Cannot create layered session directory.");
        File[] dirs = root.listFiles(File::isDirectory);
        if (dirs != null && dirs.length >= MAX_SESSION_DIRS) throw new IllegalStateException("Too many private layered sessions exist; disconnect the current VPN before retrying.");
        String sessionId = randomHex(16);
        File session = new File(root, sessionId);
        if (!session.mkdir()) throw new IllegalStateException("Cannot create multihop session.");
        int total = 0;
        try {
            if (AndroidKillSwitchPolicy.strictRequested(entry) || AndroidKillSwitchPolicy.strictRequested(exit)) writeFile(new File(session, AndroidKillSwitchPolicy.SESSION_MARKER), new byte[]{'1','\n'});
            JSONArray names = exitProfile.names();
            if (names == null) throw new IllegalStateException("Exit profile is empty.");
            for (int i = 0; i < names.length(); i++) {
                String name = names.getString(i);
                if (!safeFileName(name)) throw new IllegalStateException("Unsafe exit profile filename: " + name);
                byte[] data;
                if ("sing-box.json".equals(name)) data = patched;
                else {
                    String encoded = exitProfile.optString(name, "").trim();
                    if (encoded.isEmpty()) continue;
                    data = Base64.decode(encoded, Base64.DEFAULT);
                }
                if (data.length > MAX_FILE) throw new IllegalStateException("Exit profile file is too large: " + name);
                total += data.length;
                if (total > MAX_TOTAL) throw new IllegalStateException("Multihop session exceeds private staging limit.");
                writeFile(new File(session, name), data);
            }
            File configFile = new File(session, "sing-box.json");
            if (!configFile.isFile() || configFile.length() == 0) throw new IllegalStateException("Multihop session is missing sing-box.json.");
            return new Prepared(new NativeSingBoxController.SessionInfo(sessionId, "multihop-" + exitMode), exitBundle, exitMode);
        } catch (Throwable error) {
            deleteTree(session);
            throw error;
        }
    }

    private static void makeMultihopConfig(JSONObject config, WgConfig wg, String exitMode) throws Exception {
        JSONArray existingEndpoints = config.optJSONArray("endpoints");
        if (existingEndpoints != null && existingEndpoints.length() != 0) throw new IllegalStateException("Exit config already contains endpoints; mixed endpoint graphs are not accepted for Android multihop.");
        JSONArray inbounds = config.optJSONArray("inbounds");
        boolean fullDeviceTun = false;
        if (inbounds != null) for (int i = 0; i < inbounds.length(); i++) {
            JSONObject inbound = inbounds.optJSONObject(i);
            if (inbound != null && "tun".equals(inbound.optString("type")) && inbound.optBoolean("auto_route", false)) fullDeviceTun = true;
        }
        if (!fullDeviceTun) throw new IllegalStateException("Exit mode is not a full-device libbox profile.");

        JSONObject route = config.optJSONObject("route");
        String finalTag = route == null ? "" : route.optString("final", "").trim();
        if (!"proxy".equals(finalTag)) throw new IllegalStateException("Exit profile final route is not the expected proxy outbound.");
        JSONArray outbounds = config.optJSONArray("outbounds");
        if (outbounds == null) throw new IllegalStateException("Exit profile has no outbounds.");
        JSONObject proxy = null;
        for (int i = 0; i < outbounds.length(); i++) {
            JSONObject outbound = outbounds.optJSONObject(i);
            if (outbound != null && "proxy".equals(outbound.optString("tag", ""))) { proxy = outbound; break; }
        }
        if (proxy == null) throw new IllegalStateException("Exit profile has no proxy outbound.");
        String type = proxy.optString("type", "").toLowerCase(Locale.ROOT);
        String expected = "shadowsocks".equals(exitMode) ? "shadowsocks" : "hysteria2";
        if (!expected.equals(type)) throw new IllegalStateException("Exit mode engine does not match its generated profile.");
        if (proxy.has("detour") && !proxy.optString("detour", "").trim().isEmpty()) throw new IllegalStateException("Exit proxy already has a detour; nested/mixed multihop is not accepted.");
        proxy.put("detour", "entry-wg");
        config.put("endpoints", new JSONArray().put(wg.toEndpointJson()));
    }

    private static JSONObject requiredProfile(JSONObject bundle, String mode) {
        JSONObject profiles = bundle.optJSONObject("profiles");
        JSONObject profile = profiles == null ? null : profiles.optJSONObject(mode);
        if (profile == null) throw new IllegalStateException("Exit node does not contain " + mode + ".");
        return profile;
    }

    private static WgConfig parseWireGuard(JSONObject bundle) throws Exception {
        JSONObject profiles = bundle.optJSONObject("profiles");
        JSONObject wgProfile = profiles == null ? null : profiles.optJSONObject("wg");
        String encoded = wgProfile == null ? "" : wgProfile.optString("wg.conf", "").trim();
        if (encoded.isEmpty()) throw new IllegalStateException("Entry node has no standard WireGuard profile.");
        byte[] raw = Base64.decode(encoded, Base64.DEFAULT);
        if (raw.length == 0 || raw.length > 1024 * 1024) throw new IllegalStateException("Entry WireGuard profile size is invalid.");
        String config = new String(raw, StandardCharsets.UTF_8);
        Map<String,String> iface = new LinkedHashMap<>(), peer = new LinkedHashMap<>();
        Map<String,String> current = null; int peers = 0;
        for (String rawLine : config.split("\\r?\\n")) {
            String line = rawLine.trim();
            int comment = line.indexOf('#'); if (comment >= 0) line = line.substring(0, comment).trim();
            if (line.isEmpty()) continue;
            if ("[Interface]".equalsIgnoreCase(line)) { current = iface; continue; }
            if ("[Peer]".equalsIgnoreCase(line)) { peers++; if (peers > 1) throw new IllegalStateException("Android multihop entry requires exactly one WireGuard peer."); current = peer; continue; }
            int eq = line.indexOf('=');
            if (current != null && eq > 0) current.put(line.substring(0, eq).trim().toLowerCase(Locale.ROOT), line.substring(eq + 1).trim());
        }
        if (peers != 1) throw new IllegalStateException("Android multihop entry requires exactly one WireGuard peer.");
        WgConfig result = new WgConfig();
        result.privateKey = required(iface, "privatekey", "Entry WireGuard private key is missing.");
        result.addresses = splitCsv(required(iface, "address", "Entry WireGuard address is missing."));
        result.publicKey = required(peer, "publickey", "Entry WireGuard peer public key is missing.");
        result.preSharedKey = peer.getOrDefault("presharedkey", "").trim();
        result.allowedIps = splitCsv(required(peer, "allowedips", "Entry WireGuard AllowedIPs are missing."));
        String endpoint = required(peer, "endpoint", "Entry WireGuard endpoint is missing.");
        HostPort hp = parseEndpoint(endpoint); result.host = hp.host; result.port = hp.port;
        String mtu = iface.getOrDefault("mtu", "").trim();
        if (!mtu.isEmpty()) { try { result.mtu = Integer.parseInt(mtu); } catch (NumberFormatException e) { throw new IllegalStateException("Entry WireGuard MTU is invalid."); } }
        if (result.mtu != 0 && (result.mtu < 1280 || result.mtu > 9000)) throw new IllegalStateException("Entry WireGuard MTU is outside the safe range.");
        return result;
    }

    private static final class WgConfig {
        String privateKey, publicKey, preSharedKey, host; List<String> addresses, allowedIps; int port, mtu;
        JSONObject toEndpointJson() throws Exception {
            JSONObject endpoint = new JSONObject().put("type", "wireguard").put("tag", "entry-wg").put("address", new JSONArray(addresses)).put("private_key", privateKey);
            if (mtu != 0) endpoint.put("mtu", mtu);
            JSONObject peer = new JSONObject().put("address", host).put("port", port).put("public_key", publicKey).put("allowed_ips", new JSONArray(allowedIps));
            if (!preSharedKey.isEmpty()) peer.put("pre_shared_key", preSharedKey);
            endpoint.put("peers", new JSONArray().put(peer));
            return endpoint;
        }
    }

    private static final class HostPort { final String host; final int port; HostPort(String host, int port) { this.host = host; this.port = port; } }
    private static HostPort parseEndpoint(String value) {
        String host; String portText;
        if (value.startsWith("[")) {
            int close = value.indexOf(']'); if (close < 1 || close + 2 > value.length() || value.charAt(close + 1) != ':') throw new IllegalStateException("Entry WireGuard endpoint is invalid.");
            host = value.substring(1, close).trim(); portText = value.substring(close + 2).trim();
        } else {
            int colon = value.lastIndexOf(':'); if (colon < 1 || colon == value.length() - 1) throw new IllegalStateException("Entry WireGuard endpoint is invalid.");
            host = value.substring(0, colon).trim(); portText = value.substring(colon + 1).trim();
        }
        if (host.isEmpty()) throw new IllegalStateException("Entry WireGuard endpoint host is empty.");
        int port; try { port = Integer.parseInt(portText); } catch (NumberFormatException e) { throw new IllegalStateException("Entry WireGuard endpoint port is invalid."); }
        if (port < 1 || port > 65535) throw new IllegalStateException("Entry WireGuard endpoint port is invalid.");
        return new HostPort(host, port);
    }

    private static String required(Map<String,String> map, String key, String message) { String value = map.getOrDefault(key, "").trim(); if (value.isEmpty()) throw new IllegalStateException(message); return value; }
    private static List<String> splitCsv(String value) { List<String> out = new ArrayList<>(); for (String part : value.split(",")) { String item = part.trim(); if (!item.isEmpty()) out.add(item); } if (out.isEmpty()) throw new IllegalStateException("WireGuard list value is empty."); return out; }
    private static JSONObject loadBundle(File file) throws Exception {
        if (file == null || !file.isFile() || file.length() <= 0 || file.length() > MAX_BUNDLE) throw new IllegalStateException("Private node bundle is missing or invalid.");
        try (FileInputStream in = new FileInputStream(file); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] b = new byte[8192]; int total = 0, n; while ((n = in.read(b)) != -1) { total += n; if (total > MAX_BUNDLE) throw new IllegalStateException("Private node bundle exceeds safety limit."); out.write(b, 0, n); }
            JSONObject root = new JSONObject(new String(out.toByteArray(), StandardCharsets.UTF_8)); AndroidNodeStore.validateBundle(root); return root;
        }
    }
    private static void writeFile(File file, byte[] data) throws Exception { try (FileOutputStream out = new FileOutputStream(file, false)) { out.write(data); out.flush(); out.getFD().sync(); } }
    private static boolean safeFileName(String value) { return value != null && value.matches("[A-Za-z0-9._-]{1,128}") && !value.equals(".") && !value.equals("..") && !value.contains(".."); }
    private static String randomHex(int bytes) { byte[] value = new byte[bytes]; RANDOM.nextBytes(value); StringBuilder out = new StringBuilder(bytes * 2); for (byte b : value) out.append(String.format("%02x", b & 0xff)); return out.toString(); }
    private static void deleteTree(File file) { if (file == null || !file.exists()) return; File[] children = file.listFiles(); if (children != null) for (File child : children) deleteTree(child); file.delete(); }
}
