package com.eabusham.routervpn;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/** App-private bounded Router VPN node store. IDs are locally derived, never trusted path input. */
final class AndroidNodeStore {
    private static final Object STORE_LOCK = new Object();
    // Process-local publication epoch: advance before writes/rollback so an
    // old measurement cannot revive after change-away/back or a failed restore.
    // All access used for DNS authority is under the shared writer lock.
    private static long selectionGeneration;
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

    /** Exact active-node identity/source for rollback and owned DNS result adoption. */
    static final class SelectionSnapshot {
        final String id;
        final byte[] activeBundle;
        final long generation;
        SelectionSnapshot(String id, byte[] activeBundle) {
            this.generation = selectionGeneration;
            this.id = id == null ? "" : id;
            this.activeBundle = activeBundle == null ? null : activeBundle.clone();
        }
    }

    private final Context context;
    private final File root;

    AndroidNodeStore(Context context) {
        this.context = context.getApplicationContext();
        this.root = new File(this.context.getFilesDir(), STORE_DIR);
    }

    synchronized Node importBundle(byte[] bytes) throws Exception { synchronized (STORE_LOCK) {
        requireMutable("importing or replacing a Router VPN node");
        if (bytes == null || bytes.length == 0 || bytes.length > MAX_BUNDLE) throw new IllegalArgumentException("Router bundle size is invalid.");
        // Validate original bytes before JSONObject can collapse duplicate
        // credential or node-identity fields into one apparently valid value.
        String source = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(bytes)).toString();
        io.nekohasekai.libbox.Libbox.routerValidatePrivateNodeJSON(source);
        JSONObject bundle = new JSONObject(source);
        validateBundle(bundle);
        ensureRoot();
        String id = deriveId(bundle, bytes);
        File target = nodeFile(id);
        File[] existing = root.listFiles((dir, name) -> name.matches("[0-9a-f]{32}\\.json"));
        int count = existing == null ? 0 : existing.length;
        if (!target.isFile() && count >= MAX_NODES) throw new IllegalStateException("Android node store is full (max " + MAX_NODES + "). Remove a node before importing another.");

        byte[] previousNode = snapshotOptional(target);
        boolean nodeAdopted = false;
        try {
            selectionGeneration++;
            atomicWrite(target, bytes);
            nodeAdopted = true;
            selectInternal(id);
        } catch (Exception failure) {
            if (nodeAdopted) {
                try { restoreFile(target, previousNode); }
                catch (Exception rollback) { throw incompleteRollback("Router node import", failure, rollback); }
            }
            throw failure;
        }
        return describe(id, bundle, target);
        }
    }

    /** Apply profile policy only to the exact node source captured by that load. */
    synchronized Node applyProfileBundle(String id, byte[] original, byte[] updated) throws Exception { synchronized (STORE_LOCK) {
        requireMutable("applying a connection profile's Router node");
        if (!safeId(id) || original == null || updated == null || original.length == 0
                || original.length > MAX_BUNDLE || updated.length == 0 || updated.length > MAX_BUNDLE) {
            throw new IllegalArgumentException("Profile apply lost its bounded original node source.");
        }
        if (!java.util.Arrays.equals(snapshotOptional(nodeFile(id)), original)) {
            throw new IllegalStateException("A linked Router node changed before profile apply; its newer source was preserved.");
        }
        if (!id.equals(deriveId(new JSONObject(new String(updated, StandardCharsets.UTF_8)), updated))) {
            throw new IllegalStateException("Profile apply changed the captured Router node identity.");
        }
        // Reentrant on this instance and the shared writer lock; import keeps
        // its original strict decoder, validation and partial-write rollback.
        return importBundle(updated);
    } }

    /** DNS result adoption must retain the same active node and exact private source. */
    synchronized void requireDNSBenchmarkSource(SelectionSnapshot source) throws Exception { synchronized (STORE_LOCK) {
        if (source == null || source.generation != selectionGeneration || !safeId(source.id) || source.activeBundle == null
                || !source.id.equals(activeId())
                || !java.util.Arrays.equals(snapshotOptional(activeBundleFile()), source.activeBundle)
                || !java.util.Arrays.equals(snapshotOptional(nodeFile(source.id)), source.activeBundle)) {
            throw new IllegalStateException("Selected Router VPN node or source changed during DNS Retest; measurement was not persisted.");
        }
    } }

    synchronized SelectionSnapshot applyDNSBenchmark(SelectionSnapshot source, byte[] updated) throws Exception { synchronized (STORE_LOCK) {
        requireDNSBenchmarkSource(source);
        // Shared writer lock spans identity/source validation and the existing
        // strict import/selection transaction, including its rollback handling.
        applyProfileBundle(source.id, source.activeBundle, updated);
        return snapshotSelection();
    } }

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

    synchronized void select(String id) throws Exception { synchronized (STORE_LOCK) {
        requireSelectable(id);
        selectInternal(id);
        }
    }

    synchronized void remove(String id) throws Exception { synchronized (STORE_LOCK) {
        requireMutable("deleting a Router VPN node");
        if (!safeId(id)) throw new IllegalArgumentException("Invalid local node id.");
        File nodeFile = nodeFile(id);
        byte[] previousNode = snapshotOptional(nodeFile);
        String previousId = activeId();
        boolean active = id.equals(previousId);
        File activeBundle = activeBundleFile();
        byte[] previousActiveBundle = active ? snapshotOptional(activeBundle) : null;
        boolean mutated = false;
        selectionGeneration++;
        try {
            if (previousNode != null) {
                AndroidPrivateFileStore.remove(nodeFile, MAX_BUNDLE);
                mutated = true;
            }
            if (active) {
                if (previousActiveBundle != null) AndroidPrivateFileStore.remove(activeBundle, MAX_BUNDLE);
                mutated = true;
                if (!preferences().edit().remove(ACTIVE_ID).commit()) {
                    throw new IllegalStateException("Could not persist removal of the selected Router VPN node.");
                }
            }
        } catch (Exception failure) {
            if (mutated) {
                try {
                    restoreFile(nodeFile, previousNode);
                    if (active) rollbackSelection(activeBundle, previousActiveBundle, previousId);
                } catch (Exception rollback) {
                    throw incompleteRollback("Router node delete", failure, rollback);
                }
            }
            throw failure;
        }
        }
    }

    String activeId() { return preferences().getString(ACTIVE_ID, ""); }

    File usageFile() { return new File(context.getFilesDir(), "node-usage-v1.json"); }

    synchronized SelectionSnapshot snapshotSelection() throws Exception { synchronized (STORE_LOCK) {
        return new SelectionSnapshot(activeId(), snapshotOptional(activeBundleFile()));
        }
    }

    synchronized void restoreSelection(SelectionSnapshot snapshot) throws Exception { synchronized (STORE_LOCK) {
        if (snapshot == null) throw new IllegalArgumentException("Node selection rollback snapshot is missing.");
        rollbackSelection(activeBundleFile(), snapshot.activeBundle, snapshot.id);
        }
    }

    /** Restore only bytes published by this transaction; a newer source stays owned. */
    synchronized void restoreProfileBundle(String id, byte[] original, byte[] published) throws Exception { synchronized (STORE_LOCK) {
        requireMutable("restoring a connection profile's Router node");
        if (!safeId(id) || original == null || published == null || original.length == 0
                || original.length > MAX_BUNDLE || published.length == 0 || published.length > MAX_BUNDLE) {
            throw new IllegalArgumentException("Profile rollback lost its bounded original node source.");
        }
        File target = nodeFile(id);
        byte[] current = snapshotOptional(target);
        if (java.util.Arrays.equals(current, original)) return;
        if (!java.util.Arrays.equals(current, published)) {
            throw new IllegalStateException("A concurrent Router-node update prevents safe rollback; its source was preserved.");
        }
        JSONObject bundle = new JSONObject(new String(original, StandardCharsets.UTF_8));
        validateBundle(bundle);
        if (!id.equals(deriveId(bundle, original))) throw new IllegalStateException("Profile rollback changed the original Router identity.");
        // Selection is a separate retained publication. Re-importing here would
        // select this node and overwrite an independently adopted active source.
        selectionGeneration++;
        atomicWrite(target, original);
    } }

    synchronized void restoreProfileSelection(SelectionSnapshot original, List<SelectionSnapshot> attempted) throws Exception { synchronized (STORE_LOCK) {
        if (original == null || attempted == null) throw new IllegalArgumentException("Profile rollback lost its original selection.");
        SelectionSnapshot current = snapshotSelection();
        if (sameSelection(current, original)) return;
        boolean owned = false;
        for (SelectionSnapshot candidate : attempted) if (sameSelection(current, candidate)) { owned = true; break; }
        if (!owned) throw new IllegalStateException("A concurrent Router selection prevents safe rollback; its active source was preserved.");
        rollbackSelection(activeBundleFile(), original.activeBundle, original.id);
    } }

    private static boolean sameSelection(SelectionSnapshot left, SelectionSnapshot right) {
        return right != null && left.id.equals(right.id) && java.util.Arrays.equals(left.activeBundle, right.activeBundle);
    }

    File file(String id) {
        if (!safeId(id)) throw new IllegalArgumentException("Invalid local node id.");
        File file = nodeFile(id);
        if (!file.isFile()) throw new IllegalStateException("Stored node is missing.");
        try {
            byte[] bytes = readLimited(file, MAX_BUNDLE);
            JSONObject bundle = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
            validateBundle(bundle);
            if (!id.equals(deriveId(bundle, bytes))) throw new IllegalStateException("Stored node identity check failed.");
            return file;
        } catch (RuntimeException error) {
            throw error;
        } catch (Exception error) {
            throw new IllegalStateException("Stored Router VPN node failed validation.", error);
        }
    }

    private void requireSelectable(String id) {
        if (!safeId(id)) throw new IllegalArgumentException("Invalid local node id.");
        if (AndroidVpnMutationGuard.isBusy(context)) {
            throw new IllegalStateException("Disconnect Router VPN or let the active transition/temporary VPN operation finish before selecting another node; live session identity is frozen until disconnect, while temporary path ownership remains frozen until that operation finishes.");
        }
    }

    private void requireMutable(String action) {
        if (AndroidVpnMutationGuard.isBusy(context)) {
            throw new IllegalStateException("Disconnect Router VPN or let the active transition/temporary VPN operation finish before " + action + "; live node identity and proof must remain immutable for the session.");
        }
    }

    private void selectInternal(String id) throws Exception {
        if (!safeId(id)) throw new IllegalArgumentException("Invalid local node id.");
        File source = nodeFile(id);
        byte[] bytes = readLimited(source, MAX_BUNDLE);
        JSONObject bundle = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        validateBundle(bundle);
        if (!id.equals(deriveId(bundle, bytes))) throw new IllegalStateException("Stored node identity check failed.");

        File activeBundle = activeBundleFile();
        byte[] previousActiveBundle = snapshotOptional(activeBundle);
        String previousId = activeId();
        boolean bundleAdopted = false;
        try {
            selectionGeneration++;
            atomicWrite(activeBundle, bytes);
            bundleAdopted = true;
            if (!preferences().edit().putString(ACTIVE_ID, id).commit()) {
                throw new IllegalStateException("Could not persist the selected Router VPN node.");
            }
        } catch (Exception failure) {
            if (bundleAdopted) {
                try { rollbackSelection(activeBundle, previousActiveBundle, previousId); }
                catch (Exception rollback) { throw incompleteRollback("Router node selection", failure, rollback); }
            }
            throw failure;
        }
    }

    private SharedPreferences preferences() {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private File activeBundleFile() {
        return new File(context.getFilesDir(), ACTIVE_BUNDLE);
    }

    private static byte[] snapshotOptional(File target) throws Exception {
        return target.exists() ? readLimited(target, MAX_BUNDLE) : null;
    }

    private static void restoreFile(File target, byte[] previous) throws Exception {
        if (previous == null) AndroidPrivateFileStore.remove(target, MAX_BUNDLE);
        else atomicWrite(target, previous);
    }

    private void rollbackSelection(File activeBundle, byte[] previousBundle, String previousId) throws Exception {
        selectionGeneration++;
        Exception rollbackFailure = null;
        try { restoreFile(activeBundle, previousBundle); }
        catch (Exception error) { rollbackFailure = error; }
        try {
            SharedPreferences.Editor editor = preferences().edit();
            if (previousId == null || previousId.isEmpty()) editor.remove(ACTIVE_ID);
            else editor.putString(ACTIVE_ID, previousId);
            if (!editor.commit()) throw new IllegalStateException("Could not restore the prior selected node identity.");
        } catch (Exception error) {
            if (rollbackFailure == null) rollbackFailure = error;
            else rollbackFailure.addSuppressed(error);
        }
        if (rollbackFailure != null) throw rollbackFailure;
    }

    private static IllegalStateException incompleteRollback(String action, Exception failure, Exception rollback) {
        IllegalStateException combined = new IllegalStateException(action + " failed and rollback was incomplete: " + rollback.getMessage(), failure);
        combined.addSuppressed(rollback);
        return combined;
    }

    private void ensureRoot() throws Exception {
        AndroidPrivateFileStore.ensurePrivateDirectory(root);
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
        return AndroidProfileSelection.selectedRouterProfile(bundle);
    }

    private static JSONObject load(File file) throws Exception { return new JSONObject(new String(readLimited(file, MAX_BUNDLE), StandardCharsets.UTF_8)); }

    private static byte[] readLimited(File file, int max) throws Exception {
        return AndroidPrivateFileStore.read(file, max);
    }

    private static void atomicWrite(File target, byte[] bytes) throws Exception {
        AndroidPrivateFileStore.write(target, bytes, MAX_BUNDLE);
    }

    private static boolean safeId(String value) { return value != null && value.matches("[0-9a-f]{32}"); }
    private static String hex(byte[] data) { StringBuilder out = new StringBuilder(data.length * 2); for (byte b : data) out.append(String.format("%02x", b & 0xff)); return out.toString(); }
}
