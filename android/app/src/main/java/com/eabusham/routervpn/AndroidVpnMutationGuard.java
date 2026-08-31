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
        if (hasOwnedVpnTransport(context)) return true;
        try {
            AndroidHomeStateStore.Snapshot home = AndroidHomeStateStore.snapshot(context);
            AndroidRuntimeRegistry e = AndroidRuntimeRegistry.get(context);
            String phase = home.phase == null ? "" : home.phase.trim().toLowerCase(java.util.Locale.ROOT);
            return phaseBusy(home.connected, phase)
                    || e.orchestrator.isRunning()
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
