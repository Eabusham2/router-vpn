package com.eabusham.routervpn;

import android.content.Context;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterMultihop;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;

/** One imported entry and one independently paired final node in the owned VPN service. */
final class AndroidImportedRouterPath {
    static final String SESSION_FILE = "routervpn-imported-router.json";
    static final int MAX_INPUT = 24 * 1024 * 1024;
    private static final String[] INPUT_KEYS = {"entry_config", "entry_capture", "exit_mode", "exit_files",
            "exit_profile", "exit_start", "dns_bootstrap", "source_sha256"};

    static void requireEntry(AndroidStandardExitStore.Entry entry) throws Exception {
        if (entry == null || !Arrays.asList("shadowsocks", "hysteria2").contains(entry.protocol)
                || "shadowsocks".equals(entry.protocol) && !Arrays.asList("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305").contains(entry.method)) {
            throw new IllegalArgumentException("This imported entry path requires Shadowsocks 2022 or Hysteria2.");
        }
        AndroidStandardExitStore.validate(entry);
    }

    static AndroidMultihopController.Source captureSource(Context context, AndroidStandardExitStore.Entry entry) throws Exception {
        requireEntry(entry);
        final Context owner = context.getApplicationContext();
        final String id = entry.id, original = AndroidStandardExitStore.snapshot(AndroidStandardExitStore.copy(entry));
        return new AndroidMultihopController.Source(id, entry.name, original.getBytes(StandardCharsets.UTF_8), () -> {
            if (!original.equals(AndroidStandardExitStore.snapshot(AndroidStandardExitStore.capturedEntry(owner,id)))) {
                throw new IllegalStateException("The original imported multihop entry changed.");
            }
        });
    }

    static AndroidStandardExitStore.Entry entry(Context context, AndroidMultihopController.Source source) throws Exception {
        if (source == null || !source.imported()) throw new IllegalStateException("The original imported entry is unavailable.");
        source.require(null);
        AndroidStandardExitStore.Entry result = AndroidStandardExitStore.capturedEntry(context,source.importedId);
        if (!source.digest.equals(AndroidTorProfile.digest(AndroidStandardExitStore.snapshot(result).getBytes(StandardCharsets.UTF_8)))) {
            throw new IllegalStateException("The imported entry changed during source capture.");
        }
        source.require(null);
        return result;
    }

    static JSONObject finalBundle(File file) throws Exception {
        String original=AndroidTorProfile.strictText(AndroidPrivateFileStore.read(file, AndroidNodeStore.MAX_BUNDLE));
        Libbox.routerValidatePrivateNodeJSON(original);
        JSONObject bundle = new JSONObject(original);
        AndroidNodeStore.validateBundle(bundle);
        JSONObject profile = AndroidProfileSelection.selectedRouterProfile(bundle);
        String identity = AndroidNodeStore.stableNodeIdentity(bundle);
        if (!identity.matches("[0-9a-f]{64}") || !pairedKind(profile)
                || !identity.equals(profile.optString("node_proof_id"))) {
            throw new IllegalStateException("The final node lost its independently paired identity.");
        }
        bundle.getJSONObject("profiles").getJSONObject("shadowsocks");
        return bundle;
    }

    private static boolean pairedKind(JSONObject profile)throws Exception{
        if(!profile.has("node_kind"))return true;
        Object kind=profile.get("node_kind");
        return kind instanceof String&&(((String)kind).isEmpty()||"router-vpn".equals(kind));
    }

    static final class Compiled {
        final String input, config, metadata, mtu, source;
        Compiled(JSONObject input) throws Exception {
            RouterMultihop owner = create(input);
            try {
                config = owner.config(); metadata = owner.metadata(); mtu = owner.mtuProfile(); source = owner.sourceSHA256();
                if (config == null || config.isEmpty() || config.getBytes(StandardCharsets.UTF_8).length > 4 * 1024 * 1024
                        || metadata == null || metadata.isEmpty() || metadata.getBytes(StandardCharsets.UTF_8).length > 16384
                        || mtu == null || mtu.isEmpty() || mtu.getBytes(StandardCharsets.UTF_8).length > 256 * 1024
                        || source == null || !source.matches("[0-9a-f]{64}")) {
                    throw new IllegalStateException("The imported-entry compiler returned an incomplete captured path.");
                }
                JSONObject selected = new JSONObject(metadata);
                String entryMode = new JSONObject(input.getString("entry_capture")).getString("protocol");
                if (!Arrays.asList("shadowsocks", "hysteria2").contains(entryMode)
                        || !"external".equals(selected.getString("entry_kind")) || !"local".equals(selected.getString("execution"))
                        || !entryMode.equals(selected.getString("entry_mode")) || !"shadowsocks".equals(selected.getString("exit_mode"))) {
                    throw new IllegalStateException("The imported-entry compiler changed the selected path.");
                }
                this.input = input.put("source_sha256", source).toString();
                if (this.input.getBytes(StandardCharsets.UTF_8).length > MAX_INPUT) throw new IllegalStateException("The captured path exceeds its private staging bound.");
            } finally { owner.close(); }
        }
    }

    static Compiled compile(AndroidStandardExitStore.Entry entry, JSONObject exit, String exitMode, String execution) throws Exception {
        requireEntry(entry);
        if (!"local".equals(execution) || !"shadowsocks".equals(exitMode)) {
            throw new IllegalArgumentException("Choose Local and the paired final node's Shadowsocks transport for this imported entry.");
        }
        AndroidNodeStore.validateBundle(exit);
        JSONObject profile = new JSONObject(AndroidProfileSelection.selectedRouterProfile(exit).toString());
        String identity = AndroidNodeStore.stableNodeIdentity(exit);
        if (!identity.matches("[0-9a-f]{64}") || !identity.equals(profile.optString("node_proof_id"))
                || !pairedKind(profile) || entry.id.equals(profile.getString("id"))) {
            throw new IllegalArgumentException("Choose a distinct independently paired final node.");
        }
        // Android's graph choice lives separately from the imported node's
        // historical UI preferences. Apply that validated choice to this copy;
        // preparation/restoration still retain the complete original node file.
        profile.put("multihop_execution", execution);
        AndroidExternalPolicy.Captured captured = AndroidExternalPolicy.captureImportedEntry(entry);
        JSONObject input = new JSONObject().put("schema", 1).put("entry_config", captured.source).put("entry_capture", captured.capture)
                .put("exit_mode", exitMode).put("exit_files", exit.getJSONObject("profiles").getJSONObject(exitMode).toString())
                // Shadowsocks carries its selected AES/XOR policy in its own
                // original transport. NewNodeProfile rejects an extra layer
                // source that would duplicate that authenticated transport.
                .put("exit_profile", profile.toString()).put("exit_start", "")
                .put("dns_bootstrap", profile.has("dns_bootstrap") ? profile.getJSONObject("dns_bootstrap").toString() : "");
        return new Compiled(input);
    }

    private static RouterMultihop create(JSONObject input) throws Exception {
        return Libbox.newRouterImportedEntryMultihop(input.getString("entry_config"), input.getString("entry_capture"),
                input.getString("exit_mode"), input.getString("exit_files"), input.getString("exit_profile"),
                input.getString("exit_start"), input.getString("dns_bootstrap"));
    }

    /** Recreate from original private inputs; staged labels or graph bytes grant no proof authority. */
    static RouterMultihop prepareExecution(String config, String metadata, String raw) throws Exception {
        if (raw == null || raw.isEmpty() || raw.getBytes(StandardCharsets.UTF_8).length > MAX_INPUT) {
            throw new IllegalStateException("The imported-entry session lost its captured sources.");
        }
        Libbox.routerValidatePrivateNodeJSON(raw);
        JSONObject input = new JSONObject(raw);
        if (input.length() != INPUT_KEYS.length + 1 || !(input.get("schema") instanceof Integer)
                || input.getInt("schema") != 1) throw new IllegalStateException("Invalid captured imported-entry session.");
        for (String key : INPUT_KEYS) if (!(input.get(key) instanceof String)) throw new IllegalStateException("A captured path source changed type.");
        RouterMultihop owner = create(input);
        try {
            if (!config.equals(owner.config()) || !metadata.equals(owner.metadata()) || !input.getString("source_sha256").equals(owner.sourceSHA256())) {
                throw new IllegalStateException("The staged graph differs from its original imported-entry sources.");
            }
            return owner;
        } catch (Throwable failure) { owner.close(); throw failure; }
    }

    static boolean requiresProtection(String raw) throws Exception {
        JSONObject input = new JSONObject(raw);
        JSONObject first = new JSONObject(input.getString("entry_capture")).getJSONObject("profile");
        JSONObject last = new JSONObject(input.getString("exit_profile"));
        return AndroidExternalProtection.entryRequested(first) || AndroidExternalProtection.entryRequested(last);
    }

    static AndroidMultihopController.Prepared prepare(Context context, AndroidMultihopController.Source entrySource,
            File exitFile, String exitMode, String execution, AndroidMultihopController.Source expectedExit) throws Exception {
        if (entrySource == null || !entrySource.imported()) throw new IllegalStateException("The original imported entry source is missing.");
        entrySource.require(null);
        byte[] exitBytes = AndroidPrivateFileStore.read(exitFile, AndroidNodeStore.MAX_BUNDLE);
        AndroidMultihopController.Source exitSource = AndroidMultihopController.captureSource(exitFile, exitBytes);
        if (expectedExit != null && !expectedExit.same(exitSource)) throw new IllegalStateException("The original final node changed before restoration.");
        JSONObject bundle = finalBundle(exitFile);
        AndroidStandardExitStore.Entry ordinary = entry(context, entrySource);
        Compiled compiled = compile(ordinary, bundle, exitMode, execution);
        Libbox.checkConfig(compiled.config);
        entrySource.require(null); exitSource.require(exitFile);
        if (Thread.currentThread().isInterrupted()) throw new InterruptedException("Imported-entry preparation was cancelled.");
        File root = new File(context.getFilesDir(), "layered-sessions");
        if (!root.isDirectory() && !root.mkdirs()) throw new IllegalStateException("Cannot create private session storage.");
        File[] existing = root.listFiles(File::isDirectory);
        if (existing == null || existing.length >= 32) throw new IllegalStateException("Private session storage is full or unavailable.");
        String id = UUID.randomUUID().toString().replace("-", "");
        File folder = new File(root, id);
        if (!folder.mkdir()) throw new IllegalStateException("Cannot create the owned imported-entry session.");
        try {
            AndroidPrivateFileStore.write(new File(folder, "sing-box.json"), compiled.config.getBytes(StandardCharsets.UTF_8), 4 * 1024 * 1024);
            AndroidPrivateFileStore.write(new File(folder, "routervpn-multihop.json"), compiled.metadata.getBytes(StandardCharsets.UTF_8), 16384);
            AndroidPrivateFileStore.write(new File(folder, "routervpn-mtu.json"), compiled.mtu.getBytes(StandardCharsets.UTF_8), 256 * 1024);
            AndroidPrivateFileStore.write(new File(folder, SESSION_FILE), compiled.input.getBytes(StandardCharsets.UTF_8), MAX_INPUT);
            if (AndroidKillSwitchPolicy.strictRequested(bundle) || AndroidExternalProtection.requested(ordinary.policy, true)) {
                AndroidPrivateFileStore.write(new File(folder, AndroidKillSwitchPolicy.SESSION_MARKER), new byte[]{'1', '\n'}, 2);
            }
            entrySource.require(null); exitSource.require(exitFile);
            return new AndroidMultihopController.Prepared(new NativeSingBoxController.SessionInfo(id, "multihop-imported-" + exitMode),
                    exitFile, exitMode, entrySource, exitSource);
        } catch (Throwable failure) {
            cleanupFailedPreparation(folder, failure);
            throw failure;
        }
    }

    /** Retains the exact private workspace when preparation cannot join cleanup. */
    static final class PreparationFailure extends Exception {
        final String sessionId;
        private PreparationFailure(String sessionId, Throwable original, Exception cleanup) {
            super("The original imported-entry preparation still owns private staging cleanup.", original);
            this.sessionId = sessionId;
            addSuppressed(cleanup);
        }
    }

    static void cleanupFailedPreparation(File ownedFolder, Throwable original) throws PreparationFailure {
        try { remove(ownedFolder); }
        catch (Exception cleanup) { throw new PreparationFailure(ownedFolder.getName(), original, cleanup); }
    }

    private static void remove(File file) throws java.io.IOException {
        if (file.isDirectory()) { File[] children = file.listFiles(); if (children != null) for (File child : children) remove(child); }
        if (file.exists() && !file.delete()) throw new java.io.IOException("The owned private imported-entry session still needs cleanup.");
    }
    private AndroidImportedRouterPath() {}
}
