package com.eabusham.routervpn;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Activity-owned UI bridge over app-process-owned VPN engines. Android VPN
 * consent remains system-owned and every success still requires path proof.
 */
final class AndroidUnifiedConnectionController implements AutoCloseable {
    interface Callback { void progress(String message); void finished(boolean ok, String message); }
    static final int PREPARE_UNIFIED = 7605;

    private final Activity activity;
    private final AndroidNodeStore nodeStore;
    private final AndroidRuntimeRegistry runtime;
    private final NativeWireGuardController wireGuard;
    private final NativeAmneziaWGController amneziaWG;
    private final NativeSingBoxController singBox;
    private final NativeXrayController xray;
    private final AndroidModeOrchestrator orchestrator;
    private final AndroidMultihopRuntime multihop;

    private String pendingMode = "";
    private List<String> pendingLayers = Collections.emptyList();
    private AndroidNodeStore.Node pendingEntry, pendingExit;
    private String pendingExitMode = "";
    private Callback pendingCallback;

    AndroidUnifiedConnectionController(Activity activity, AndroidNodeStore nodeStore) {
        this.activity = activity;
        this.nodeStore = nodeStore;
        runtime = AndroidRuntimeRegistry.get(activity);
        wireGuard = runtime.wireGuard;
        amneziaWG = runtime.amneziaWG;
        singBox = runtime.singBox;
        xray = runtime.xray;
        orchestrator = runtime.orchestrator;
        multihop = runtime.multihop;
    }

    boolean isActiveOrTransitioning() { return multihop.isActiveOrTransitioning() || orchestrator.isRunning() || orchestrator.isActive(); }
    boolean isConnected() { return AndroidHomeStateStore.snapshot(activity).connected; }
    boolean isMultihopConnected() { return multihop.isConnected(); }
    String activeMultihopEntryId() { return multihop.activeEntryId(); }
    String activeMultihopExitId() { return multihop.activeExitId(); }
    String activeMultihopExitMode() { return multihop.activeExitMode(); }

    void connect(String mode, List<String> layers, Callback callback) {
        if (isActiveOrTransitioning()) { callback.finished(false, "Disconnect the current Router VPN session or let its transition finish first."); return; }
        try { activeBundle(); }
        catch (Exception error) { callback.finished(false, safe(error)); return; }
        pendingMode = mode == null || mode.trim().isEmpty() ? "smart-auto" : mode.trim().toLowerCase();
        pendingLayers = layers == null ? Collections.emptyList() : new ArrayList<>(layers);
        pendingEntry = null; pendingExit = null; pendingExitMode = ""; pendingCallback = callback;
        requestPermission("Router VPN " + displayMode(pendingMode));
    }

    void connectMultihop(AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, String exitMode, Callback callback) {
        if (entry == null || exit == null || entry.id.equals(exit.id)) { callback.finished(false, "Multihop requires two different stored nodes."); return; }
        if (exitMode == null || exitMode.trim().isEmpty()) { callback.finished(false, "Choose a supported multihop exit transport."); return; }
        if (isActiveOrTransitioning()) { callback.finished(false, "Disconnect the current Router VPN session before multihop."); return; }
        pendingMode = "multihop"; pendingLayers = Collections.emptyList(); pendingEntry = entry; pendingExit = exit; pendingExitMode = exitMode.trim(); pendingCallback = callback;
        requestPermission("Router VPN multihop");
    }

    List<NativeSingBoxController.ModeInfo> supportedMultihopExitModes(AndroidNodeStore.Node exit) throws Exception {
        if (exit == null) return Collections.emptyList();
        return multihop.listSupportedExitModes(exit.file);
    }

    void disconnect(Callback callback) {
        clearPending();
        boolean wasMultihop = multihop.isActiveOrTransitioning();
        try { multihop.disconnect(); } catch (Throwable ignored) {}
        orchestrator.disconnect(new AndroidModeOrchestrator.Callback() {
            @Override public void progress(String message) { activity.runOnUiThread(() -> callback.progress(message)); }
            @Override public void finished(boolean success, String modeId, String message) {
                activity.runOnUiThread(() -> callback.finished(success, wasMultihop && success ? "Disconnected Android multihop and native Router VPN transports." : message));
            }
        });
    }

    boolean onActivityResult(int requestCode, int resultCode) {
        if (requestCode != PREPARE_UNIFIED) return false;
        Callback cb = pendingCallback;
        if (resultCode != Activity.RESULT_OK) {
            clearPending();
            if (cb != null) cb.finished(false, "Android VPN permission was not granted; Router VPN stayed disconnected.");
            return true;
        }
        startPending();
        return true;
    }

    private void requestPermission(String label) {
        Intent permission = VpnService.prepare(activity);
        if (permission == null) { startPending(); return; }
        if (pendingCallback != null) pendingCallback.progress("Waiting for Android VPN permission for " + label + "…");
        activity.startActivityForResult(permission, PREPARE_UNIFIED);
    }

    private void startPending() {
        final String mode = pendingMode;
        final List<String> layers = new ArrayList<>(pendingLayers);
        final AndroidNodeStore.Node entry = pendingEntry, exit = pendingExit;
        final String exitMode = pendingExitMode;
        final Callback callback = pendingCallback;
        clearPending();
        if (callback == null) return;
        if ("multihop".equals(mode)) {
            if (entry == null || exit == null || entry.id.equals(exit.id) || exitMode.isEmpty()) { callback.finished(false, "Multihop selection expired; choose entry and exit again."); return; }
            multihop.connect(entry, exit, exitMode, new AndroidMultihopRuntime.Callback() {
                @Override public void progress(String message) { activity.runOnUiThread(() -> callback.progress(message)); }
                @Override public void finished(boolean ok, String message) { activity.runOnUiThread(() -> callback.finished(ok, message)); }
            });
            return;
        }
        final File bundle;
        try { bundle = activeBundle(); }
        catch (Exception error) { callback.finished(false, safe(error)); return; }
        AndroidModeOrchestrator.Callback bridge = new AndroidModeOrchestrator.Callback() {
            @Override public void progress(String message) { activity.runOnUiThread(() -> callback.progress(message)); }
            @Override public void finished(boolean ok, String modeId, String message) { activity.runOnUiThread(() -> callback.finished(ok, message)); }
        };
        if ("smart-auto".equals(mode)) orchestrator.auto(bundle, true, bridge);
        else if ("auto".equals(mode)) orchestrator.auto(bundle, false, bridge);
        else if ("all".equals(mode)) orchestrator.all(bundle, bridge);
        else if (mode.startsWith("custom:")) {
            if (layers.isEmpty()) callback.finished(false, "CUSTOM requires at least one saved layer.");
            else orchestrator.custom(bundle, layers, bridge);
        } else orchestrator.logical(bundle, mode, bridge);
    }

    private File activeBundle() throws Exception {
        String id = nodeStore.activeId();
        if (id == null || id.trim().isEmpty()) throw new IllegalStateException("Pair/import and select a Router VPN node first.");
        File file = nodeStore.file(id);
        if (file == null || !file.isFile() || file.length() <= 0) throw new IllegalStateException("Selected Router VPN node bundle is missing.");
        return file;
    }

    private void clearPending() { pendingMode=""; pendingLayers=Collections.emptyList(); pendingEntry=null; pendingExit=null; pendingExitMode=""; pendingCallback=null; }
    private static String displayMode(String mode) { if ("smart-auto".equals(mode)) return "SMART AUTO"; if ("auto".equals(mode)) return "AUTO"; if (mode.startsWith("custom:")) return "CUSTOM"; return mode.toUpperCase(); }
    private static String safe(Throwable error) { String value=error==null?"":error.getMessage(); return value==null||value.trim().isEmpty()?"Router VPN connection error":value.trim(); }

    @Override public void close() {
        // Activity destruction must not destroy the app-process VPN engines.
        // They own active GoBackend/libbox/Xray state across rotation/recreation.
        clearPending();
    }
}
