package com.eabusham.routervpn;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.Locale;

/**
 * Invalidates runtime evidence that belongs to a previous Android app process.
 *
 * Router VPN's VpnService engines are process-owned and START_NOT_STICKY. A
 * SharedPreferences value such as connected=true or layered_state_v1=UP is
 * therefore not proof that the new process still owns a live/proven tunnel.
 * Reconnect must create a new session and pass the selected-path proof again.
 */
final class AndroidProcessStateReconciler {
    private static final String RESTART_REASON =
            "Router VPN app process restarted; previous process-owned VPN/path proof was invalidated. Reconnect to establish and prove the selected path again.";

    static void reconcile(Context context) {
        Context app = context.getApplicationContext();
        AndroidHomeStateStore.Snapshot home = AndroidHomeStateStore.snapshot(app);
        String phase = home.phase == null ? "" : home.phase.trim().toLowerCase(Locale.ROOT);
        boolean staleHome = home.connected || "connecting".equals(phase) || "connected".equals(phase) || "stopping".equals(phase);

        SharedPreferences runtime = app.getSharedPreferences(NativeSingBoxController.PREFS, Context.MODE_PRIVATE);
        boolean staleLayered = invalidateEngine(runtime,
                NativeSingBoxController.STATE_KEY,
                NativeSingBoxController.MODE_KEY,
                NativeSingBoxController.ERROR_KEY);
        boolean staleXray = invalidateEngine(runtime,
                NativeXrayController.STATE_KEY,
                NativeXrayController.MODE_KEY,
                NativeXrayController.ERROR_KEY);

        if (staleHome || staleLayered || staleXray) {
            // The path generation is part of async-proof freshness. Increment it
            // before clearing Connected so any in-flight result from old state
            // cannot be adopted by the new process.
            AndroidHomeStateStore.advancePathGeneration(app);
            AndroidHomeStateStore.failed(app, RESTART_REASON);
        }
    }

    private static boolean invalidateEngine(SharedPreferences prefs, String stateKey, String modeKey, String errorKey) {
        String state = prefs.getString(stateKey, "DOWN");
        state = state == null ? "DOWN" : state.trim().toUpperCase(Locale.ROOT);
        if (!"UP".equals(state) && !"STARTING".equals(state) && !"STOPPING".equals(state)) return false;
        prefs.edit()
                .putString(stateKey, "FAILED")
                .putString(modeKey, "")
                .putString(errorKey, RESTART_REASON)
                .apply();
        return true;
    }

    private AndroidProcessStateReconciler() { }
}
