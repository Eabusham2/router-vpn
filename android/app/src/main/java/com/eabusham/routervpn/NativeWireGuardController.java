package com.eabusham.routervpn;

import android.content.Context;
import android.util.Base64;

import com.wireguard.android.backend.GoBackend;
import com.wireguard.android.backend.Tunnel;
import com.wireguard.config.Config;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Native Android WireGuard runtime using WireGuard's official userspace GoBackend. */
final class NativeWireGuardController implements Tunnel {
    interface Callback { void done(State state, String message, Throwable error); }
    private final Context appContext;
    private final GoBackend backend;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final AndroidUnderlyingNetworkMonitor networkMonitor;
    private volatile State state = State.DOWN;
    private volatile Config activeConfig;
    private volatile File activeBundle;
    private volatile String lastError = "";

    NativeWireGuardController(Context context) {
        appContext = context.getApplicationContext();
        backend = new GoBackend(appContext);
        networkMonitor = new AndroidUnderlyingNetworkMonitor(appContext);
    }
    @Override public String getName() { return "routervpn"; }
    @Override public void onStateChange(State newState) { state = newState; }
    State getState() { return state; }
    String getError() { return lastError; }

    void connect(File privateBundle, Callback callback) {
        AndroidHomeStateStore.begin(appContext, "raw-tunnel", "wg", "wg");
        executor.execute(() -> {
            try {
                networkMonitor.stop();
                clearActive();
                if (AndroidKillSwitchPolicy.strictRequested(privateBundle)) throw new IllegalStateException(AndroidKillSwitchPolicy.requirementMessage());
                Config config = loadWireGuardConfig(privateBundle);
                State result = backend.setState(this, State.UP, config);
                state = result;
                if (result != State.UP) throw new IllegalStateException("WireGuard backend did not enter UP state.");
                if (!AndroidPathProbe.prove(privateBundle, 8000)) {
                    backend.setState(this, State.DOWN, null);
                    state = State.DOWN;
                    throw new IllegalStateException("Native WireGuard failed selected-node private path proof.");
                }
                activeConfig = config;
                activeBundle = privateBundle;
                lastError = "";
                AndroidHomeStateStore.connected(appContext, "raw-tunnel", "wg", "wg", "");
                networkMonitor.start(() -> executor.execute(this::recoverAfterNetworkChange));
                callback.done(State.UP, "Native Android WireGuard is active with selected DNS/MTU and selected-node private path proof.", null);
            } catch (Throwable error) {
                failClosed(error);
                callback.done(State.DOWN, "Native WireGuard failed: " + safeMessage(error), error);
            }
        });
    }

    private void recoverAfterNetworkChange() {
        Config config = activeConfig;
        File bundle = activeBundle;
        if (state != State.UP || config == null || bundle == null) return;
        try {
            lastError = "Underlying network changed; WireGuard is re-establishing and revalidating the selected node.";
            AndroidHomeStateStore.warning(appContext, lastError);
            backend.setState(this, State.DOWN, null);
            State result = backend.setState(this, State.UP, config);
            state = result;
            if (result != State.UP || !AndroidPathProbe.prove(bundle, 10000)) {
                throw new IllegalStateException("WireGuard did not recover a proven selected-node path after the underlying network changed.");
            }
            lastError = "";
            AndroidHomeStateStore.connected(appContext, "raw-tunnel", "wg", "wg", "");
        } catch (Throwable error) {
            failClosed(new IllegalStateException("WireGuard network-transition recovery failed closed: " + safeMessage(error), error));
        }
    }

    void disconnect(Callback callback) {
        executor.execute(() -> {
            networkMonitor.stop();
            clearActive();
            try {
                State result = backend.setState(this, State.DOWN, null);
                state = result;
                lastError = "";
                AndroidHomeStateStore.disconnected(appContext);
                callback.done(result, "Native Android WireGuard disconnected.", null);
            } catch (Throwable error) {
                lastError = safeMessage(error);
                AndroidHomeStateStore.failed(appContext, "WireGuard disconnect failed: " + lastError);
                callback.done(state, "WireGuard disconnect failed: " + lastError, error);
            }
        });
    }

    void close() {
        networkMonitor.stop();
        clearActive();
        executor.shutdown();
    }

    private void failClosed(Throwable error) {
        networkMonitor.stop();
        try { backend.setState(this, State.DOWN, null); } catch (Throwable ignored) { }
        state = State.DOWN;
        lastError = safeMessage(error);
        AndroidHomeStateStore.failed(appContext, lastError);
        clearActive();
    }

    private void clearActive() { activeConfig = null; activeBundle = null; }

    private static Config loadWireGuardConfig(File privateBundle) throws Exception {
        if (!privateBundle.isFile()) throw new IllegalStateException("Import/link a Router VPN node first.");
        if (privateBundle.length() <= 0 || privateBundle.length() > 64L * 1024L * 1024L) throw new IllegalStateException("Private node bundle size is invalid.");
        byte[] bundleBytes = readLimited(privateBundle, 64 * 1024 * 1024);
        JSONObject root = new JSONObject(new String(bundleBytes, StandardCharsets.UTF_8));
        JSONObject profiles = root.optJSONObject("profiles");
        if (profiles == null) throw new IllegalStateException("Node bundle has no generated profiles.");
        JSONObject wg = profiles.optJSONObject("wg");
        if (wg == null) throw new IllegalStateException("Node bundle has no raw WireGuard profile.");
        String encoded = wg.optString("wg.conf", "").trim();
        if (encoded.isEmpty()) throw new IllegalStateException("Node bundle has no WireGuard wg.conf.");
        byte[] decoded = Base64.decode(encoded, Base64.DEFAULT);
        if (decoded.length <= 0 || decoded.length > 512 * 1024) throw new IllegalStateException("WireGuard profile size is invalid.");
        String patched = AndroidNativeProfilePolicy.patchWireGuardLikeConfig(root, new String(decoded, StandardCharsets.UTF_8), 1420);
        return Config.parse(new ByteArrayInputStream(patched.getBytes(StandardCharsets.UTF_8)));
    }

    private static byte[] readLimited(File file, int maxBytes) throws Exception {
        try (FileInputStream input = new FileInputStream(file); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192]; int total = 0, read;
            while ((read = input.read(buffer)) != -1) { total += read; if (total > maxBytes) throw new IllegalStateException("Private node bundle exceeds safety limit."); output.write(buffer, 0, read); }
            return output.toByteArray();
        }
    }

    private static String safeMessage(Throwable error) {
        String value = error == null ? "unknown error" : error.getMessage();
        if (value == null || value.trim().isEmpty()) value = error == null ? "unknown error" : error.getClass().getSimpleName();
        return value.replace('\n', ' ').replace('\r', ' ').trim();
    }
}
