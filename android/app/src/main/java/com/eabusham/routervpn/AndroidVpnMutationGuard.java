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
            return home.connected
                    || phase.contains("connecting") || phase.contains("starting") || phase.contains("checking")
                    || phase.contains("trying") || phase.contains("proving") || phase.contains("disconnecting")
                    || phase.contains("stopping") || phase.contains("switching") || phase.contains("reconnecting")
                    || e.orchestrator.isRunning()
                    || e.multihop.isActiveOrTransitioning()
                    || runtimeBusy(e.singBox.getState())
                    || runtimeBusy(e.xray.getState());
        } catch (Throwable ignored) {
            return true;
        }
    }

    private static boolean runtimeBusy(String state) {
        return "UP".equals(state) || "STARTING".equals(state) || "STOPPING".equals(state);
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
