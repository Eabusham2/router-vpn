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
    private final GoBackend backend;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private volatile State state = State.DOWN;

    NativeWireGuardController(Context context) { backend = new GoBackend(context.getApplicationContext()); }
    @Override public String getName() { return "routervpn"; }
    @Override public void onStateChange(State newState) { state = newState; }
    State getState() { return state; }

    void connect(File privateBundle, Callback callback) {
        executor.execute(() -> {
            try {
                if (AndroidKillSwitchPolicy.strictRequested(privateBundle)) throw new IllegalStateException(AndroidKillSwitchPolicy.requirementMessage());
                Config config = loadWireGuardConfig(privateBundle);
                State result = backend.setState(this, State.UP, config);
                state = result;
                callback.done(result, "Native Android WireGuard is active through the official userspace backend with the selected enforceable DNS address and MTU policy.", null);
            } catch (Throwable error) {
                state = State.DOWN;
                callback.done(State.DOWN, "Native WireGuard failed: " + safeMessage(error), error);
            }
        });
    }

    void disconnect(Callback callback) {
        executor.execute(() -> {
            try {
                State result = backend.setState(this, State.DOWN, null);
                state = result;
                callback.done(result, "Native Android WireGuard disconnected.", null);
            } catch (Throwable error) { callback.done(state, "WireGuard disconnect failed: " + safeMessage(error), error); }
        });
    }

    void close() { executor.shutdown(); }

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
