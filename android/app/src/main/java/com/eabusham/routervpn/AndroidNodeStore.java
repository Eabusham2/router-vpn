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
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/** App-private bounded Router VPN node store. IDs are locally derived, never trusted path input. */
final class AndroidNodeStore {
    static final int MAX_NODES = 24;
    static final int MAX_BUNDLE = 32 * 1024 * 1024;
    static final int MAX_PROFILE_SCHEMA = 4;
    static final String ACTIVE_BUNDLE = "router-vpn-bundle.json";
    private static final String PREFS = "router-vpn";
    private static final String ACTIVE_ID = "active_node_id_v1";
    private static final String STORE_DIR = "router-nodes-v1";
    private static final String NODE_PROOF_DOMAIN = "router-vpn-node-proof-v1\n";

    static final class Node {
        final String id;
        final String name;
        final String endpoint;
        final File file;
        Node(String id, String name, String endpoint, File file) {
            this.id = id; this.name = name; this.endpoint = endpoint; this.file = file;
        }
        @Override public String toString() { return name + (endpoint.isEmpty() ? "" : " — " + endpoint); }
    }

    private final Context context;
    private final File root;

    AndroidNodeStore(Context context) {
        this.context = context.getApplicationContext();
        this.root = new File(this.context.getFilesDir(), STORE_DIR);
    }

    synchronized Node importBundle(byte[] bytes) throws Exception {
        requireMutable("importing or replacing a Router VPN node");
        if (bytes == null || bytes.length == 0 || bytes.length > MAX_BUNDLE) throw new IllegalArgumentException("Router bundle size is invalid.");
        JSONObject bundle = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        validateBundle(bundle);
        ensureRoot();
        String id = deriveId(bundle, bytes);
        File target = nodeFile(id);
        File[] existing = root.listFiles((dir, name) -> name.matches("[0-9a-f]{32}\\.json"));
        int count = existing == null ? 0 : existing.length;
        if (!target.isFile() && count >= MAX_NODES) throw new IllegalStateException("Android node store is full (max " + MAX_NODES + "). Remove a node before importing another.");
        atomicWrite(target, bytes);
        selectInternal(id);
        return describe(id, bundle, target);
    }

    synchronized List<Node> list() throws Exception {
        ensureRoot();
        File[] files = root.listFiles((dir, name) -> name.matches("[0-9a-f]{32}\\.json"));
        List<Node> result = new ArrayList<>();
        if (files != null) for (File file : files) {
            try {
                JSONObject bundle = load(file);
                validateBundle(bundle);
                String id = file.getName().substring(0, 32);
                if (!id.equals(deriveId(bundle, readLimited(file, MAX_BUNDLE)))) continue;
                result.add(describe(id, bundle, file));
            } catch (Exception ignored) { /* Corrupt/untrusted entries are not surfaced. */ }
        }
        Collections.sort(result, Comparator.comparing((Node n) -> n.name).thenComparing(n -> n.id));
        return result;
    }

    synchronized void select(String id) throws Exception {
        requireSelectable(id);
        selectInternal(id);
    }

    synchronized void remove(String id) throws Exception {
        requireMutable("deleting a Router VPN node");
        if (!safeId(id)) throw new IllegalArgumentException("Invalid local node id.");
        File file = nodeFile(id);
        if (file.exists() && !file.delete()) throw new IllegalStateException("Could not remove stored node.");
        String active = activeId();
        if (id.equals(active)) context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(ACTIVE_ID).apply();
    }

    String activeId() { return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(ACTIVE_ID, ""); }

    File file(String id) {
        if (!safeId(id)) throw new IllegalArgumentException("Invalid local node id.");
        File file = nodeFile(id);
        if (!file.isFile()) throw new IllegalStateException("Stored node is missing.");
        return file;
    }

    private void requireSelectable(String id) {
        if (!safeId(id)) throw new IllegalArgumentException("Invalid local node id.");
        AndroidHomeStateStore.Snapshot runtime = AndroidHomeStateStore.snapshot(context);
        AndroidRuntimeRegistry engines = AndroidRuntimeRegistry.get(context);
        boolean transitioning = "connecting".equals(runtime.phase) || engines.orchestrator.isRunning() || engines.multihop.isActiveOrTransitioning()
                || "STARTING".equals(engines.singBox.getState()) || "STOPPING".equals(engines.singBox.getState())
                || "STARTING".equals(engines.xray.getState()) || "STOPPING".equals(engines.xray.getState());
        if (transitioning) throw new IllegalStateException("Wait for the current Router VPN transition to finish or disconnect before selecting a node.");
        if (runtime.connected) {
            String live = "multihop".equals(runtime.logicalMode) ? runtime.activeExitId : runtime.activeNodeId;
            if (live == null || live.isEmpty() || !id.equals(live)) throw new IllegalStateException("Disconnect Router VPN before selecting a different node; the live session identity is frozen until disconnect.");
        }
    }

    private void requireMutable(String action) {
        AndroidHomeStateStore.Snapshot runtime = AndroidHomeStateStore.snapshot(context);
        AndroidRuntimeRegistry engines = AndroidRuntimeRegistry.get(context);
        boolean activeOrTransitioning = runtime.connected || "connecting".equals(runtime.phase)
                || engines.orchestrator.isRunning() || engines.multihop.isActiveOrTransitioning()
                || "UP".equals(engines.singBox.getState()) || "STARTING".equals(engines.singBox.getState()) || "STOPPING".equals(engines.singBox.getState())
                || "UP".equals(engines.xray.getState()) || "STARTING".equals(engines.xray.getState()) || "STOPPING".equals(engines.xray.getState());
        if (activeOrTransitioning) throw new IllegalStateException("Disconnect Router VPN before " + action + "; live node identity and proof must remain immutable for the session.");
    }

    private void selectInternal(String id) throws Exception {
        if (!safeId(id)) throw new IllegalArgumentException("Invalid local node id.");
        File source = nodeFile(id);
        if (!source.isFile()) throw new IllegalStateException("Selected node is not stored.");
        byte[] bytes = readLimited(source, MAX_BUNDLE);
        JSONObject bundle = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        validateBundle(bundle);
        if (!id.equals(deriveId(bundle, bytes))) throw new IllegalStateException("Stored node identity check failed.");
        atomicWrite(new File(context.getFilesDir(), ACTIVE_BUNDLE), bytes);
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(ACTIVE_ID, id).apply();
    }

    private void ensureRoot() throws Exception {
        if (!root.isDirectory() && !root.mkdirs()) throw new IllegalStateException("Cannot create private node store.");
    }

    private File nodeFile(String id) {
        if (!safeId(id)) throw new IllegalArgumentException("Invalid local node id.");
        return new File(root, id + ".json");
    }

    private static Node describe(String id, JSONObject bundle, File file) {
        JSONObject profile = selectedProfile(bundle);
        String name = profile == null ? "Router VPN node" : profile.optString("name", "Router VPN node").trim();
        if (name.isEmpty()) name = "Router VPN node";
        String endpoint = profile == null ? bundle.optString("endpoint", "").trim() : profile.optString("endpoint", bundle.optString("endpoint", "")).trim();
        return new Node(id, name, endpoint, file);
    }

    /** Stable public identity shared with router-agent. */
    static String stableNodeIdentity(JSONObject bundle) throws Exception {
        JSONObject profile = selectedProfile(bundle);
        String top = bundle.optString("nodeProofId", "").trim();
        String nested = profile == null ? "" : profile.optString("node_proof_id", "").trim();
        if (!top.isEmpty() && !top.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Router bundle nodeProofId is invalid.");
        if (!nested.isEmpty() && !nested.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Router profile node proof id is invalid.");
        if (!top.isEmpty() && !nested.isEmpty() && !top.equals(nested)) throw new IllegalArgumentException("Router bundle node proof ids disagree.");
        String supplied = !top.isEmpty() ? top : nested;
        String peerKey = wireGuardPeerPublicKey(bundle);
        if (!peerKey.isEmpty()) {
            String derived = hex(MessageDigest.getInstance("SHA-256").digest((NODE_PROOF_DOMAIN + peerKey).getBytes(StandardCharsets.UTF_8)));
            if (!supplied.isEmpty() && !supplied.equals(derived)) throw new IllegalArgumentException("Router bundle node proof does not match its WireGuard server public key.");
            return derived;
        }
        return supplied;
    }

    static String deriveId(JSONObject bundle, byte[] raw) throws Exception {
        String stable = stableNodeIdentity(bundle);
        if (!stable.isEmpty()) return stable.substring(0, 32);
        String endpoint = bundle.optString("endpoint", "").trim().toLowerCase();
        String routerApi = bundle.optString("routerAPI", "").trim().toLowerCase();
        String fallback = "router-vpn-node-v1-fallback\n" + endpoint + "\n" + routerApi + "\n" + hex(MessageDigest.getInstance("SHA-256").digest(raw));
        return hex(MessageDigest.getInstance("SHA-256").digest(fallback.getBytes(StandardCharsets.UTF_8))).substring(0, 32);
    }

    private static String wireGuardPeerPublicKey(JSONObject bundle) {
        try {
            JSONObject profiles = bundle.optJSONObject("profiles");
            JSONObject wg = profiles == null ? null : profiles.optJSONObject("wg");
            String encoded = wg == null ? "" : wg.optString("wg.conf", "").trim();
            if (encoded.isEmpty()) return "";
            String conf = new String(Base64.decode(encoded, Base64.DEFAULT), StandardCharsets.UTF_8);
            boolean peer = false;
            for (String rawLine : conf.split("\\r?\\n")) {
                String line = rawLine.trim();
                if (line.startsWith("[") && line.endsWith("]")) { peer = "[Peer]".equalsIgnoreCase(line); continue; }
                if (peer && line.regionMatches(true, 0, "PublicKey", 0, 9)) {
                    int eq = line.indexOf('=');
                    if (eq > 0) return line.substring(eq + 1).trim();
                }
            }
        } catch (Exception ignored) { }
        return "";
    }

    static void validateBundle(JSONObject bundle) {
        if (bundle == null || !bundle.has("profiles") || !bundle.has("modes") || !bundle.has("routerProfiles")) throw new IllegalArgumentException("This is not a complete Router VPN node bundle.");
        int profileSchema = bundle.optInt("profileSchemaVersion", 1);
        if (profileSchema < 1 || profileSchema > MAX_PROFILE_SCHEMA) throw new IllegalArgumentException("Router profile schema is newer than this Android app supports.");
        JSONArray routerProfiles = bundle.optJSONArray("routerProfiles");
        if (routerProfiles == null || routerProfiles.length() == 0) throw new IllegalArgumentException("Router VPN node bundle has no router profiles.");
        for (int i = 0; i < routerProfiles.length(); i++) {
            JSONObject profile = routerProfiles.optJSONObject(i);
            if (profile == null) throw new IllegalArgumentException("Router VPN node bundle contains an invalid router profile.");
            int nestedSchema = profile.optInt("schema_version", profileSchema);
            if (nestedSchema < 1 || nestedSchema > MAX_PROFILE_SCHEMA) throw new IllegalArgumentException("Router profile schema is newer than this Android app supports.");
        }
        JSONObject profiles = bundle.optJSONObject("profiles");
        if (profiles == null || profiles.length() == 0) throw new IllegalArgumentException("Router VPN node bundle has no generated profiles.");
        try { stableNodeIdentity(bundle); }
        catch (RuntimeException error) { throw error; }
        catch (Exception error) { throw new IllegalArgumentException("Router VPN node identity validation failed.", error); }
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

    private static JSONObject load(File file) throws Exception { return new JSONObject(new String(readLimited(file, MAX_BUNDLE), StandardCharsets.UTF_8)); }

    private static byte[] readLimited(File file, int max) throws Exception {
        if (file == null || !file.isFile() || file.length() <= 0 || file.length() > max) throw new IllegalStateException("Stored node bundle size is invalid.");
        try (FileInputStream in = new FileInputStream(file); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192]; int total = 0, n;
            while ((n = in.read(buffer)) != -1) { total += n; if (total > max) throw new IllegalStateException("Stored node bundle exceeds safety limit."); out.write(buffer, 0, n); }
            return out.toByteArray();
        }
    }

    private static void atomicWrite(File target, byte[] bytes) throws Exception {
        File parent = target.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) throw new IllegalStateException("Cannot create private storage directory.");
        File temp = new File(parent, "." + target.getName() + ".tmp");
        try {
            try (FileOutputStream out = new FileOutputStream(temp, false)) { out.write(bytes); out.flush(); out.getFD().sync(); }
            if (target.exists() && !target.delete()) throw new IllegalStateException("Cannot replace stored node.");
            if (!temp.renameTo(target)) throw new IllegalStateException("Cannot commit stored node.");
        } finally { if (temp.exists()) temp.delete(); }
    }

    private static boolean safeId(String value) { return value != null && value.matches("[0-9a-f]{32}"); }
    private static String hex(byte[] data) { StringBuilder out = new StringBuilder(data.length * 2); for (byte b : data) out.append(String.format("%02x", b & 0xff)); return out.toString(); }
}