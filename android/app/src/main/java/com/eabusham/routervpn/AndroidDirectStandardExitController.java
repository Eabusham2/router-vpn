package com.eabusham.routervpn;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Locale;

/** Builds a direct non-Router-VPN external exit on Android. */
final class AndroidDirectStandardExitController {
    private static final int MAX_CONFIG = 4 * 1024 * 1024;
    private static final int MAX_SESSION_DIRS = 32;
    private static final SecureRandom RANDOM = new SecureRandom();
    private final Context context;

    AndroidDirectStandardExitController(Context context) { this.context = context.getApplicationContext(); }

    NativeSingBoxController.SessionInfo prepare(AndroidStandardExitStore.Entry exit) throws Exception {
        AndroidStandardExitStore.validate(exit);
        if ("openvpn".equals(exit.protocol)) throw new IllegalArgumentException("OpenVPN direct exit is unavailable on Android until a native OpenVPN dataplane is pinned and validated.");

        JSONObject custom = customExitJson(exit);
        JSONArray endpoints = new JSONArray();
        JSONArray outbounds = new JSONArray();
        if ("wireguard".equals(exit.protocol)) endpoints.put(custom); else outbounds.put(custom);

        JSONObject tun = new JSONObject()
                .put("type", "tun").put("tag", "tun-in")
                .put("address", new JSONArray().put("172.29.93.1/30").put("fd29:93::1/126"))
                .put("mtu", exit.wgMtu >= 1280 && exit.wgMtu <= 9000 ? exit.wgMtu : 1280)
                .put("auto_route", true).put("strict_route", true).put("stack", "system");
        JSONObject proof = new JSONObject().put("type", "mixed").put("tag", "standard-exit-proof").put("listen", "127.0.0.1").put("listen_port", 1099);
        JSONObject dns = new JSONObject()
                .put("type", "https").put("tag", "selected-dns")
                .put("server", "1.1.1.1").put("server_port", 443)
                .put("path", "/dns-query").put("detour", "custom-exit")
                .put("tls", new JSONObject().put("enabled", true).put("server_name", "cloudflare-dns.com"));
        JSONObject route = new JSONObject()
                .put("rules", new JSONArray().put(new JSONObject().put("protocol", "dns").put("action", "hijack-dns")))
                .put("final", "custom-exit").put("auto_detect_interface", true);
        JSONObject config = new JSONObject()
                .put("log", new JSONObject().put("level", "warn").put("timestamp", true))
                .put("dns", new JSONObject().put("servers", new JSONArray().put(dns)).put("final", "selected-dns"))
                .put("inbounds", new JSONArray().put(tun).put(proof))
                .put("endpoints", endpoints).put("outbounds", outbounds).put("route", route);
        byte[] raw = (config.toString(2) + "\n").getBytes(StandardCharsets.UTF_8);
        if (raw.length <= 0 || raw.length > MAX_CONFIG) throw new IllegalStateException("Android direct custom-exit config exceeds safety limit.");

        File root = new File(context.getFilesDir(), "layered-sessions");
        if (!root.isDirectory() && !root.mkdirs()) throw new IllegalStateException("Cannot create layered session directory.");
        File[] dirs = root.listFiles(File::isDirectory);
        if (dirs != null && dirs.length >= MAX_SESSION_DIRS) throw new IllegalStateException("Too many private layered sessions exist; disconnect before retrying.");
        String id = randomHex(16);
        File session = new File(root, id);
        if (!session.mkdir()) throw new IllegalStateException("Cannot create direct custom-exit session.");
        try {
            writeFile(new File(session, AndroidKillSwitchPolicy.SESSION_MARKER), new byte[]{'1','\n'});
            writeFile(new File(session, "sing-box.json"), raw);
            return new NativeSingBoxController.SessionInfo(id, "standard-direct-" + exit.protocol);
        } catch (Throwable error) {
            deleteTree(session);
            throw error;
        }
    }

    private static JSONObject customExitJson(AndroidStandardExitStore.Entry e) throws Exception {
        if ("wireguard".equals(e.protocol)) {
            JSONObject peer = new JSONObject().put("address", e.server).put("port", e.serverPort)
                    .put("public_key", e.wgPeerPublicKey).put("allowed_ips", new JSONArray(e.wgAllowedIps));
            if (!e.wgPreSharedKey.isEmpty()) peer.put("pre_shared_key", e.wgPreSharedKey);
            JSONObject endpoint = new JSONObject().put("type", "wireguard").put("tag", "custom-exit")
                    .put("address", new JSONArray(e.wgAddresses)).put("private_key", e.wgPrivateKey)
                    .put("peers", new JSONArray().put(peer));
            if (e.wgMtu != 0) endpoint.put("mtu", e.wgMtu);
            return endpoint;
        }
        JSONObject out = new JSONObject().put("tag", "custom-exit").put("server", e.server).put("server_port", e.serverPort);
        if ("socks5".equals(e.protocol)) {
            out.put("type", "socks").put("version", "5");
            if (!e.username.isEmpty()) out.put("username", e.username).put("password", e.password);
        } else if ("http".equals(e.protocol) || "https".equals(e.protocol)) {
            out.put("type", "http");
            if (!e.username.isEmpty()) out.put("username", e.username).put("password", e.password);
            if ("https".equals(e.protocol)) out.put("tls", new JSONObject().put("enabled", true).put("server_name", e.tlsServerName));
        } else if ("shadowsocks".equals(e.protocol)) {
            out.put("type", "shadowsocks").put("method", e.method).put("password", e.secret);
        } else if ("hysteria2".equals(e.protocol)) {
            out.put("type", "hysteria2").put("password", e.secret)
                    .put("tls", new JSONObject().put("enabled", true).put("server_name", e.tlsServerName));
        } else {
            throw new IllegalArgumentException("Unsupported direct Android custom exit protocol: " + e.protocol);
        }
        return out;
    }

    private static void writeFile(File file, byte[] data) throws Exception {
        try (FileOutputStream out = new FileOutputStream(file, false)) { out.write(data); out.flush(); out.getFD().sync(); }
    }
    private static String randomHex(int bytes) {
        byte[] value = new byte[bytes]; RANDOM.nextBytes(value); StringBuilder out = new StringBuilder();
        for (byte b : value) out.append(String.format(Locale.ROOT, "%02x", b & 255)); return out.toString();
    }
    private static void deleteTree(File file) { if (file == null || !file.exists()) return; File[] children=file.listFiles(); if(children!=null)for(File child:children)deleteTree(child); file.delete(); }
}
