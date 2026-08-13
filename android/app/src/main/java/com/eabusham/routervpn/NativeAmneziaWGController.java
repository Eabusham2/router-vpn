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
    private final GoBackend backend;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final AndroidUnderlyingNetworkMonitor networkMonitor;
    private volatile State state = State.DOWN;
    private volatile Config activeConfig;
    private volatile File activeBundle;
    private volatile String lastError = "";

    NativeAmneziaWGController(Context context) {
        Context app = context.getApplicationContext();
        backend = new GoBackend(app);
        networkMonitor = new AndroidUnderlyingNetworkMonitor(app);
    }
    @Override public String getName() { return "routervpn-awg"; }
    @Override public void onStateChange(State newState) { state = newState; }
    State getState() { return state; }
    String getError() { return lastError; }

    void connect(File privateBundle, Callback callback) {
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
                    backend.setState(this, State.DOWN, null);
                    state = State.DOWN;
                    throw new IllegalStateException("Native AmneziaWG failed selected-node private path proof.");
                }
                activeConfig = config;
                activeBundle = privateBundle;
                lastError = "";
                networkMonitor.start(() -> executor.execute(this::recoverAfterNetworkChange));
                callback.done(State.UP, "Native Android AmneziaWG 2 is active with selected DNS/MTU and selected-node private path proof.", null);
            } catch (Throwable error) {
                failClosed(error);
                callback.done(State.DOWN, "Native AmneziaWG failed: " + safeMessage(error), error);
            }
        });
    }

    private void recoverAfterNetworkChange() {
        Config config = activeConfig;
        File bundle = activeBundle;
        if (state != State.UP || config == null || bundle == null) return;
        try {
            lastError = "Underlying network changed; AmneziaWG is re-establishing and revalidating the selected node.";
            backend.setState(this, State.DOWN, null);
            State result = backend.setState(this, State.UP, config);
            state = result;
            if (result != State.UP || !AndroidPathProbe.prove(bundle, 10000)) {
                throw new IllegalStateException("AmneziaWG did not recover a proven selected-node path after the underlying network changed.");
            }
            lastError = "";
        } catch (Throwable error) {
            failClosed(new IllegalStateException("AmneziaWG network-transition recovery failed closed: " + safeMessage(error), error));
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
                callback.done(result, "Native Android AmneziaWG disconnected.", null);
            } catch (Throwable error) {
                lastError = safeMessage(error);
                callback.done(state, "AmneziaWG disconnect failed: " + lastError, error);
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
        clearActive();
    }

    private void clearActive() {
        activeConfig = null;
        activeBundle = null;
    }

    private static Config loadConfig(File privateBundle) throws Exception {
        if (!privateBundle.isFile()) throw new IllegalStateException("Import/link a Router VPN node first.");
        if (privateBundle.length() <= 0 || privateBundle.length() > 64L * 1024L * 1024L) throw new IllegalStateException("Private node bundle size is invalid.");
        JSONObject root = new JSONObject(new String(readLimited(privateBundle, 64 * 1024 * 1024), StandardCharsets.UTF_8));
        JSONObject profiles = root.optJSONObject("profiles");
        if (profiles == null) throw new IllegalStateException("Node bundle has no generated profiles.");
        JSONObject awg = profiles.optJSONObject("awg2-fast");
        int fallbackMtu = 1400;
        if (awg == null) { awg = profiles.optJSONObject("awg2-strong"); fallbackMtu = 1360; }
        if (awg == null) throw new IllegalStateException("Node bundle has no AmneziaWG 2 profile.");
        String encoded = awg.optString("awg.conf", "").trim();
        if (encoded.isEmpty()) throw new IllegalStateException("Node bundle has no AmneziaWG awg.conf.");
        byte[] decoded = Base64.decode(encoded, Base64.DEFAULT);
        if (decoded.length <= 0 || decoded.length > 512 * 1024) throw new IllegalStateException("AmneziaWG profile size is invalid.");
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

    private static String safeMessage(Throwable error) {
        String value = error == null ? "unknown error" : error.getMessage();
        if (value == null || value.trim().isEmpty()) value = error == null ? "unknown error" : error.getClass().getSimpleName();
        return value.replace('\n', ' ').replace('\r', ' ').trim();
    }
}
