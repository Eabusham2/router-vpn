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
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/** Prepares bounded app-private libbox sessions; no large configs cross Binder. */
final class NativeSingBoxController {
    static final String PREFS = "router-vpn";
    static final String STATE_KEY = "layered_state_v1";
    static final String MODE_KEY = "layered_mode_v1";
    static final String ERROR_KEY = "layered_error_v1";

    private static final long MAX_BUNDLE = 64L * 1024L * 1024L;
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

    NativeSingBoxController(Context context) {
        this.context = context.getApplicationContext();
    }

    List<ModeInfo> listDirectLibboxModes(File privateBundle) throws Exception {
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
            if (profile == null) continue;
            String encoded = profile.optString("sing-box.json", "").trim();
            if (encoded.isEmpty()) continue;
            byte[] config;
            try { config = Base64.decode(encoded, Base64.DEFAULT); }
            catch (IllegalArgumentException invalid) { continue; }
            if (config.length == 0 || config.length > MAX_CONFIG) continue;
            if (!isDirectFullDeviceConfig(new String(config, StandardCharsets.UTF_8))) continue;
            String name = mode.optString("name", id).trim();
            result.add(new ModeInfo(id, name.isEmpty() ? id : name));
        }
        return result;
    }

    SessionInfo prepareSession(File privateBundle, String modeId) throws Exception {
        if (!safeToken(modeId)) throw new IllegalArgumentException("Invalid mode id.");
        JSONObject root = loadBundle(privateBundle);
        JSONObject profiles = root.optJSONObject("profiles");
        JSONObject profile = profiles == null ? null : profiles.optJSONObject(modeId);
        if (profile == null) throw new IllegalStateException("The selected mode has no generated profile.");
        String configEncoded = profile.optString("sing-box.json", "").trim();
        if (configEncoded.isEmpty()) throw new IllegalStateException("The selected mode has no sing-box config.");
        byte[] config = Base64.decode(configEncoded, Base64.DEFAULT);
        if (config.length == 0 || config.length > MAX_CONFIG) throw new IllegalStateException("sing-box config size is invalid.");
        if (!isDirectFullDeviceConfig(new String(config, StandardCharsets.UTF_8))) {
            throw new IllegalStateException("This mode still depends on another local engine and is not a direct embedded libbox mode.");
        }

        File rootDir = new File(context.getFilesDir(), "layered-sessions");
        if (!rootDir.isDirectory() && !rootDir.mkdirs()) throw new IllegalStateException("Cannot create layered session directory.");
        cleanupOldSessions(rootDir);
        String sessionId = randomHex(16);
        File session = new File(rootDir, sessionId);
        if (!session.mkdir()) throw new IllegalStateException("Cannot create layered session.");
        int total = 0;
        try {
            JSONArray names = profile.names();
            if (names == null) throw new IllegalStateException("Selected mode profile is empty.");
            for (int i = 0; i < names.length(); i++) {
                String name = names.getString(i);
                if (!safeFileName(name)) throw new IllegalStateException("Unsafe profile filename: " + name);
                String encoded = profile.optString(name, "").trim();
                if (encoded.isEmpty()) continue;
                byte[] decoded = Base64.decode(encoded, Base64.DEFAULT);
                if (decoded.length > MAX_PROFILE_FILE) throw new IllegalStateException("Profile file is too large: " + name);
                total += decoded.length;
                if (total > MAX_PROFILE_TOTAL) throw new IllegalStateException("Selected mode profile exceeds safety limit.");
                writeFile(new File(session, name), decoded);
            }
            File configFile = new File(session, "sing-box.json");
            if (!configFile.isFile() || configFile.length() == 0) throw new IllegalStateException("Session is missing sing-box.json.");
            return new SessionInfo(sessionId, modeId);
        } catch (Throwable error) {
            deleteTree(session);
            throw error;
        }
    }

    void start(SessionInfo session) {
        Intent intent = new Intent(context, LayeredVpnService.class)
                .setAction(LayeredVpnService.ACTION_START)
                .putExtra(LayeredVpnService.EXTRA_SESSION_ID, session.sessionId)
                .putExtra(LayeredVpnService.EXTRA_MODE_ID, session.modeId);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(intent);
        else context.startService(intent);
    }

    void stop() {
        Intent intent = new Intent(context, LayeredVpnService.class).setAction(LayeredVpnService.ACTION_STOP);
        context.startService(intent);
    }

    String getState() { return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(STATE_KEY, "DOWN"); }
    String getMode() { return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(MODE_KEY, ""); }
    String getError() { return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(ERROR_KEY, ""); }

    private static JSONObject loadBundle(File file) throws Exception {
        if (file == null || !file.isFile()) throw new IllegalStateException("Import/link a Router VPN node first.");
        if (file.length() <= 0 || file.length() > MAX_BUNDLE) throw new IllegalStateException("Private node bundle size is invalid.");
        return new JSONObject(new String(readLimited(file, (int) MAX_BUNDLE), StandardCharsets.UTF_8));
    }

    private static boolean isDirectFullDeviceConfig(String content) {
        try {
            JSONObject root = new JSONObject(content);
            JSONArray inbounds = root.optJSONArray("inbounds");
            boolean tun = false;
            if (inbounds != null) {
                for (int i = 0; i < inbounds.length(); i++) {
                    JSONObject inbound = inbounds.optJSONObject(i);
                    if (inbound != null && "tun".equals(inbound.optString("type")) && inbound.optBoolean("auto_route", false)) tun = true;
                }
            }
            if (!tun) return false;
            JSONArray outbounds = root.optJSONArray("outbounds");
            if (outbounds != null) {
                for (int i = 0; i < outbounds.length(); i++) {
                    JSONObject outbound = outbounds.optJSONObject(i);
                    if (outbound == null) continue;
                    String server = outbound.optString("server", "").trim().toLowerCase();
                    if ("127.0.0.1".equals(server) || "::1".equals(server) || "localhost".equals(server)) return false;
                }
            }
            return true;
        } catch (Exception invalid) { return false; }
    }

    private static boolean safeToken(String value) {
        return value != null && value.matches("[A-Za-z0-9._-]{1,96}") && !value.equals(".") && !value.equals("..") && !value.contains("..");
    }
    private static boolean safeFileName(String value) {
        return value != null && value.matches("[A-Za-z0-9._-]{1,128}") && !value.equals(".") && !value.equals("..") && !value.contains("..");
    }

    private static byte[] readLimited(File file, int max) throws Exception {
        try (FileInputStream input = new FileInputStream(file); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192]; int total = 0, read;
            while ((read = input.read(buffer)) != -1) {
                total += read; if (total > max) throw new IllegalStateException("File exceeds safety limit.");
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }

    private static void writeFile(File file, byte[] data) throws Exception {
        try (FileOutputStream output = new FileOutputStream(file, false)) { output.write(data); output.getFD().sync(); }
    }

    private static String randomHex(int bytes) {
        byte[] raw = new byte[bytes]; RANDOM.nextBytes(raw); StringBuilder out = new StringBuilder(bytes * 2);
        for (byte b : raw) out.append(String.format("%02x", b & 0xff)); return out.toString();
    }

    private static void cleanupOldSessions(File root) {
        File[] children = root.listFiles(); if (children == null) return;
        long cutoff = System.currentTimeMillis() - 24L * 60L * 60L * 1000L;
        for (File child : children) if (child.isDirectory() && child.lastModified() < cutoff) deleteTree(child);
    }

    static void deleteTree(File file) {
        if (file == null) return; File[] children = file.listFiles(); if (children != null) for (File child : children) deleteTree(child); file.delete();
    }
}
