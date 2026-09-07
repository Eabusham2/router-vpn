package com.eabusham.routervpn;

import android.content.Context;
import android.util.Base64;

import org.amnezia.awg.backend.GoBackend;
import org.amnezia.awg.backend.Tunnel;
import org.amnezia.awg.config.Config;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Native Android AmneziaWG 2 runtime using Amnezia's Apache-2.0 GoBackend. */
final class NativeAmneziaWGController implements Tunnel {
    interface Callback { void done(State state, String message, Throwable error); }
    private final Context appContext;
    private final GoBackend backend;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final AndroidUnderlyingNetworkMonitor networkMonitor;
    private volatile State state = State.DOWN;
    private volatile Config activeConfig;
    private volatile File activeBundle;
    private volatile String lastError = "";
    private volatile boolean homeStateOwner;

    NativeAmneziaWGController(Context context) {
        appContext = context.getApplicationContext();
        backend = new GoBackend(appContext);
        networkMonitor = new AndroidUnderlyingNetworkMonitor(appContext);
    }
    @Override public String getName() { return "routervpn-awg"; }
    @Override public void onStateChange(State newState) { state = newState; }
    State getState() { return state; }
    String getError() { return lastError; }

    /** Direct raw-tunnel use owns the shared Home/session state. */
    void connect(File privateBundle, Callback callback) { connectInternal(privateBundle, true, callback); }

    /** AUTO/SMART/CUSTOM child transport: the outer orchestrator owns Home/session state. */
    void connectManaged(File privateBundle, Callback callback) { connectInternal(privateBundle, false, callback); }

    private void connectInternal(File privateBundle, boolean publishHomeState, Callback callback) {
        String activeNodeId = AndroidHomeStateStore.nodeIdFromBundleFile(privateBundle);
        homeStateOwner = publishHomeState;
        if (publishHomeState) AndroidHomeStateStore.begin(appContext, "raw-tunnel", "awg2-fast", "awg", activeNodeId);
        executor.execute(() -> {
            try {
                networkMonitor.stop();
                clearActive();
                if (AndroidKillSwitchPolicy.strictRequested(privateBundle)) throw new IllegalStateException(AndroidKillSwitchPolicy.requirementMessage());
                Config config = loadConfig(privateBundle);
                State result = backend.setState(this, State.UP, config);
                state = result;
                if (result != State.UP) throw new IllegalStateException("AmneziaWG backend did not enter UP state.");
                if (!AndroidPathProbe.prove(privateBundle, 8000)) {
                    State down = backend.setState(this, State.DOWN, null);
                    state = down;
                    if (down != State.DOWN) throw new IllegalStateException("AmneziaWG path proof failed and teardown did not prove DOWN.");
                    throw new IllegalStateException("Native AmneziaWG failed selected-node private path proof.");
                }
                activeConfig = config;
                activeBundle = privateBundle;
                lastError = "";
                if (publishHomeState) AndroidHomeStateStore.connected(appContext, "raw-tunnel", "awg2-fast", "awg", "", activeNodeId);
                networkMonitor.start(() -> executor.execute(this::recoverAfterNetworkChange));
                callback.done(State.UP, "Native Android AmneziaWG 2 is active with selected DNS/MTU and selected-node private path proof.", null);
            } catch (Throwable error) {
                failClosed(error, publishHomeState);
                callback.done(state, "Native AmneziaWG failed: " + lastError, error);
            }
        });
    }

    private void recoverAfterNetworkChange() {
        Config config = activeConfig;
        File bundle = activeBundle;
        if (state != State.UP || config == null || bundle == null) return;
        String reason = "Underlying network changed; AmneziaWG is re-establishing and revalidating the selected node.";
        AndroidHomeStateStore.Snapshot revalidation = AndroidHomeStateStore.beginPathRevalidation(appContext, reason);
        boolean failSharedState = homeStateOwner || revalidation != null;
        try {
            lastError = reason;
            State down = backend.setState(this, State.DOWN, null);
            state = down;
            if (down != State.DOWN) throw new IllegalStateException("AmneziaWG network-transition teardown did not prove DOWN.");
            State result = backend.setState(this, State.UP, config);
            state = result;
            if (result != State.UP || !AndroidPathProbe.prove(bundle, 10000)) {
                throw new IllegalStateException("AmneziaWG did not recover a proven selected-node path after the underlying network changed.");
            }
            if (revalidation != null && !AndroidHomeStateStore.completePathRevalidation(appContext, revalidation)) {
                throw new IllegalStateException("AmneziaWG path proof completed for a stale Android session/generation; refusing to re-adopt Connected.");
            }
            lastError = "";
        } catch (Throwable error) {
            failClosed(new IllegalStateException("AmneziaWG network-transition recovery failed closed: " + safeMessage(error), error), failSharedState);
        }
    }

    /** Normal/raw disconnect owns and clears Home state. */
    void disconnect(Callback callback) { disconnectInternal(true, callback); }

    /** Orchestrator candidate teardown must not clear the outer logical session. */
    void disconnectManaged(Callback callback) { disconnectInternal(false, callback); }

    private void disconnectInternal(boolean publishHomeState, Callback callback) {
        executor.execute(() -> {
            networkMonitor.stop();
            boolean emergency = publishHomeState && AndroidHomeStateStore.emergencyDisconnectPending(appContext);
            if (publishHomeState && !emergency) {
                AndroidHomeStateStore.beginPathRevalidation(appContext, "AmneziaWG disconnect requested; retaining session ownership until DOWN is proved.");
            }
            try {
                State result = backend.setState(this, State.DOWN, null);
                state = result;
                if (result != State.DOWN) throw new IllegalStateException("AmneziaWG teardown did not prove DOWN.");
                clearActive();
                lastError = "";
                if (publishHomeState && !emergency) AndroidHomeStateStore.disconnected(appContext);
                homeStateOwner = false;
                callback.done(State.DOWN, "Native Android AmneziaWG disconnected.", null);
            } catch (Throwable error) {
                lastError = safeMessage(error);
                if (publishHomeState) {
                    if (emergency) {
                        AndroidHomeStateStore.warning(appContext, "Emergency Disconnect requested; AmneziaWG disconnect incomplete: " + lastError);
                    } else {
                        AndroidHomeStateStore.warning(appContext, "AmneziaWG disconnect incomplete; runtime ownership retained: " + lastError);
                    }
                }
                callback.done(state, "AmneziaWG disconnect incomplete: " + lastError, error);
            }
        });
    }

    void close() {
        networkMonitor.stop();
        clearActive();
        homeStateOwner = false;
        executor.shutdown();
    }

    private void failClosed(Throwable error, boolean publishHomeFailure) {
        networkMonitor.stop();
        String primary = safeMessage(error);
        Throwable teardownError = null;
        try {
            State result = backend.setState(this, State.DOWN, null);
            state = result;
            if (result != State.DOWN) teardownError = new IllegalStateException("AmneziaWG teardown did not prove DOWN.");
        } catch (Throwable stopError) {
            teardownError = stopError;
        }
        if (teardownError == null) {
            lastError = primary;
            if (publishHomeFailure) AndroidHomeStateStore.failed(appContext, lastError);
            clearActive();
            homeStateOwner = false;
            return;
        }
        lastError = primary + " Teardown incomplete; runtime ownership retained: " + safeMessage(teardownError);
        if (publishHomeFailure) AndroidHomeStateStore.warning(appContext, lastError);
    }

    private void clearActive() { activeConfig = null; activeBundle = null; }

    private static Config loadConfig(File privateBundle) throws Exception {
        if (!privateBundle.isFile()) throw new IllegalStateException("Import/link a Router VPN node first.");
        if (privateBundle.length() <= 0 || privateBundle.length() > 64L * 1024L * 1024L) throw new IllegalStateException("Private node bundle size is invalid.");
        JSONObject root = new JSONObject(new String(readLimited(privateBundle, 64 * 1024 * 1024), StandardCharsets.UTF_8));
        JSONObject profiles = root.optJSONObject("profiles"); if (profiles == null) throw new IllegalStateException("Node bundle has no generated profiles.");
        JSONObject awg = profiles.optJSONObject("awg2-fast"); int fallbackMtu = 1400;
        if (awg == null) { awg = profiles.optJSONObject("awg2-strong"); fallbackMtu = 1360; }
        if (awg == null) throw new IllegalStateException("Node bundle has no AmneziaWG 2 profile.");
        String encoded = awg.optString("awg.conf", "").trim(); if (encoded.isEmpty()) throw new IllegalStateException("Node bundle has no AmneziaWG awg.conf.");
        byte[] decoded = Base64.decode(encoded, Base64.DEFAULT); if (decoded.length <= 0 || decoded.length > 512 * 1024) throw new IllegalStateException("AmneziaWG profile size is invalid.");
        String patched = AndroidNativeProfilePolicy.patchWireGuardLikeConfig(root, new String(decoded, StandardCharsets.UTF_8), fallbackMtu);
        return Config.parse(new ByteArrayInputStream(patched.getBytes(StandardCharsets.UTF_8)));
    }

    private static byte[] readLimited(File file, int maxBytes) throws Exception {
        try (FileInputStream input = new FileInputStream(file); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192]; int total = 0, read;
            while ((read = input.read(buffer)) != -1) { total += read; if (total > maxBytes) throw new IllegalStateException("Private node bundle exceeds safety limit."); output.write(buffer, 0, read); }
            return output.toByteArray();
        }
    }
    private static String safeMessage(Throwable error) { String value = error == null ? "unknown error" : error.getMessage(); if (value == null || value.trim().isEmpty()) value = error == null ? "unknown error" : error.getClass().getSimpleName(); return value.replace('\n',' ').replace('\r',' ').trim(); }
}
