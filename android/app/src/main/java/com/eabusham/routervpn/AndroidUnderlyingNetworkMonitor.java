package com.eabusham.routervpn;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;

/** Small lifecycle-safe watcher for non-VPN Internet network transitions. */
final class AndroidUnderlyingNetworkMonitor {
    interface Listener { void changed(); }

    private final ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback callback;
    private Network current;
    private boolean initialized;

    AndroidUnderlyingNetworkMonitor(Context context) {
        connectivity = (ConnectivityManager) context.getApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    synchronized void start(Listener listener) {
        stop();
        NetworkRequest request = new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build();
        callback = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network network) {
                boolean changed;
                synchronized (AndroidUnderlyingNetworkMonitor.this) {
                    changed = initialized && (current == null || !current.equals(network));
                    current = network;
                    initialized = true;
                }
                if (changed) listener.changed();
            }
            @Override public void onLost(Network network) {
                synchronized (AndroidUnderlyingNetworkMonitor.this) {
                    if (current != null && current.equals(network)) current = null;
                }
            }
        };
        connectivity.registerNetworkCallback(request, callback);
    }

    synchronized void stop() {
        if (callback != null) {
            try { connectivity.unregisterNetworkCallback(callback); } catch (Throwable ignored) { }
            callback = null;
        }
        current = null;
        initialized = false;
    }
}
