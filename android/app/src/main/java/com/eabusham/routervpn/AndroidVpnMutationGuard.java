package com.eabusham.routervpn;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Process;

/** One fail-closed busy-state source for persistent node/profile mutation UI and stores. */
final class AndroidVpnMutationGuard {
    static boolean isBusy(Context context) {
        if (context == null) return true;
        boolean ownedVpn = hasOwnedVpnTransport(context);
        try {
            AndroidHomeStateStore.Snapshot home = AndroidHomeStateStore.snapshot(context);
            AndroidRuntimeRegistry e = AndroidRuntimeRegistry.get(context);
            String phase = home.phase == null ? "" : home.phase.trim().toLowerCase(java.util.Locale.ROOT);
            // A managed child can fail closed and clear its real engine before the
            // outer orchestrator has had a chance to discard its cached current
            // candidate marker. Do not let that bookkeeping-only marker trap the
            // UI forever. Recovery is allowed only when Home is explicitly failed,
            // no app-owned VPN transport remains, no transition is running, and
            // every actual engine is provably idle/terminal.
            if (!ownedVpn && failedSessionHasNoLiveEngine(home, e)) return false;
            return ownedVpn
                    || phaseBusy(home.connected, phase)
                    || e.orchestrator.isRunning()
                    || e.orchestrator.isActive()
                    || e.multihop.isActiveOrTransitioning()
                    || e.standardExit.isActiveOrTransitioning()
                    || tunnelBusy(e.wireGuard.getState())
                    || tunnelBusy(e.amneziaWG.getState())
                    || runtimeBusy(e.singBox.getState())
                    || runtimeBusy(e.xray.getState());
        } catch (Throwable ignored) {
            return true;
        }
    }

    static boolean failedSessionHasNoLiveEngine(Context context, AndroidRuntimeRegistry e) {
        if (context == null || e == null) return false;
        AndroidHomeStateStore.Snapshot home = AndroidHomeStateStore.snapshot(context);
        return failedSessionHasNoLiveEngine(home, e) && !hasOwnedVpnTransport(context);
    }

    private static boolean failedSessionHasNoLiveEngine(AndroidHomeStateStore.Snapshot home, AndroidRuntimeRegistry e) {
        if (home == null || e == null || home.connected) return false;
        String phase = home.phase == null ? "" : home.phase.trim().toLowerCase(java.util.Locale.ROOT);
        return "failed".equals(phase)
                && !e.orchestrator.isRunning()
                && e.wireGuard.getState() == com.wireguard.android.backend.Tunnel.State.DOWN
                && e.amneziaWG.getState() == org.amnezia.awg.backend.Tunnel.State.DOWN
                && !runtimeBusy(e.singBox.getState())
                && !runtimeBusy(e.xray.getState());
    }

    private static boolean phaseBusy(boolean connected, String phase) {
        if (connected) return true;
        // Mutation is safe only in explicit, stable idle states. Unknown/future
        // phases fail closed instead of silently becoming mutable.
        return !("off".equals(phase) || "disconnected".equals(phase) || "failed".equals(phase));
    }

    private static boolean tunnelBusy(com.wireguard.android.backend.Tunnel.State state) {
        return state != null && state != com.wireguard.android.backend.Tunnel.State.DOWN;
    }

    private static boolean tunnelBusy(org.amnezia.awg.backend.Tunnel.State state) {
        return state != null && state != org.amnezia.awg.backend.Tunnel.State.DOWN;
    }

    private static boolean runtimeBusy(String state) {
        if (state == null) return true;
        String normalized = state.trim().toUpperCase(java.util.Locale.ROOT);
        return !("DOWN".equals(normalized) || "FAILED".equals(normalized) || "REVOKED".equals(normalized));
    }

    private static boolean hasOwnedVpnTransport(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return false;
        Network network = cm.getActiveNetwork();
        if (network == null) return false;
        NetworkCapabilities caps = cm.getNetworkCapabilities(network);
        if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return false;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            int owner = caps.getOwnerUid();
            return owner == Process.myUid() || owner < 0;
        }
        return true;
    }

    private AndroidVpnMutationGuard() {}
}
