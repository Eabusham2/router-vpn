package com.eabusham.routervpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import libXray.DialerController;
import libXray.LibXray;

/** Full-device Xray-core Android VpnService using the exact pinned libXray mobile wrapper. */
public final class XrayVpnService extends VpnService {
    static final String ACTION_START = "com.eabusham.routervpn.XRAY_START";
    static final String ACTION_STOP = "com.eabusham.routervpn.XRAY_STOP";
    static final String EXTRA_SESSION_ID = "session_id";
    static final String EXTRA_MODE_ID = "mode_id";

    private static final String TAG = "RouterVPN-Xray";
    private static final String CHANNEL = "routervpn-xray";
    private static final int NOTIFICATION_ID = 7111;
    private static final int MAX_CONFIG = 4 * 1024 * 1024;
    private static final int MAX_META = 64 * 1024;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Object lock = new Object();
    private ParcelFileDescriptor tun;
    private File activeSession;
    private String activeMode = "";
    private JSONObject activeConfig;
    private volatile String state = "DOWN";
    private volatile boolean explicitStop;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback networkCallback;
    private Network underlyingNetwork;
    private boolean controllerRegistered;

    private final DialerController socketProtector = new DialerController() {
        @Override public boolean protectFd(long fd) {
            if (fd < 0 || fd > Integer.MAX_VALUE) return false;
            return protect((int) fd);
        }
    };

    @Override public void onCreate() {
        super.onCreate();
        connectivity = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        ensureNotificationChannel();
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? "" : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            explicitStop = true;
            executor.execute(() -> shutdown("DOWN", ""));
            return Service.START_NOT_STICKY;
        }
        if (!ACTION_START.equals(action)) return Service.START_NOT_STICKY;
        startForeground(NOTIFICATION_ID, notification("Starting native Xray VPN…"));
        String sessionId = intent.getStringExtra(EXTRA_SESSION_ID);
        String modeId = intent.getStringExtra(EXTRA_MODE_ID);
        explicitStop = false;
        executor.execute(() -> startXray(sessionId, modeId));
        return Service.START_NOT_STICKY;
    }

    private void startXray(String sessionId, String modeId) {
        synchronized (lock) {
            if ("STARTING".equals(state) || "UP".equals(state)) return;
            publish("STARTING", modeId, "");
        }
        try {
            if (VpnService.prepare(this) != null) throw new IllegalStateException("Android VPN permission is missing or was revoked.");
            if (!safeToken(sessionId) || !safeToken(modeId)) throw new IllegalArgumentException("Invalid Xray session metadata.");
            File sessionsRoot = new File(getFilesDir(), "xray-sessions").getCanonicalFile();
            File session = new File(sessionsRoot, sessionId).getCanonicalFile();
            if (!session.getParentFile().equals(sessionsRoot) || !session.isDirectory()) throw new IllegalStateException("Xray session is missing or unsafe.");
            verifyStrictLockdown(session);
            JSONObject config = readJson(new File(session, NativeXrayController.CONFIG_FILE), MAX_CONFIG);
            JSONObject meta = readJson(new File(session, NativeXrayController.META_FILE), MAX_META);
            int mtu = meta.optInt("mtu", 1380);
            if (mtu < 1200 || mtu > 9000) throw new IllegalStateException("Xray session MTU is invalid.");
            String dns = meta.optString("dns", "").trim();
            if (dns.isEmpty()) throw new IllegalStateException("Xray session DNS is missing.");

            Builder builder = new Builder()
                    .setSession("Router VPN — Xray " + modeId)
                    .setMtu(mtu)
                    .addAddress("198.18.0.1", 30)
                    .addAddress("fd00:5256:504e::1", 126)
                    .addRoute("0.0.0.0", 0)
                    .addRoute("::", 0)
                    .addDnsServer(dns);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false);
            ParcelFileDescriptor established = builder.establish();
            if (established == null) throw new IllegalStateException("Android refused to establish the Xray VPN interface.");

            synchronized (lock) {
                closeCoreLocked(false);
                tun = established;
                activeSession = session;
                activeMode = modeId;
                activeConfig = config;
            }
            registerSocketProtection();
            runCoreAndProve();
            registerUnderlyingNetworkMonitor();
            publish("UP", modeId, "");
            updateForeground("Native Xray active: " + modeId);
        } catch (Throwable error) {
            Log.e(TAG, "Native Xray start failed", error);
            shutdown("FAILED", safe(error));
        }
    }

    private void verifyStrictLockdown(File session) throws Exception {
        if (!new File(session, AndroidKillSwitchPolicy.SESSION_MARKER).isFile()) return;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) throw new IllegalStateException("Strict Android kill switch requires Android 10 or newer lockdown APIs.");
        if (!isAlwaysOn() || !isLockdownEnabled()) throw new IllegalStateException(AndroidKillSwitchPolicy.requirementMessage());
    }

    private void registerSocketProtection() throws Exception {
        if (controllerRegistered) return;
        LibXray.registerDialerController(socketProtector);
        LibXray.registerListenerController(socketProtector);
        controllerRegistered = true;
    }

    private void runCoreAndProve() throws Exception {
        JSONObject config;
        ParcelFileDescriptor descriptor;
        synchronized (lock) {
            config = activeConfig == null ? null : new JSONObject(activeConfig.toString());
            descriptor = tun;
        }
        if (config == null || descriptor == null || descriptor.getFileDescriptor() == null || !descriptor.getFileDescriptor().valid()) throw new IllegalStateException("Xray runtime has no valid Android TUN.");
        JSONObject env = config.optJSONObject("env");
        if (env == null) env = new JSONObject();
        env.put("xray.tun.fd", Integer.toString(descriptor.getFd()));
        config.put("env", env);
        JSONObject request = new JSONObject()
                .put("apiVersion", 1)
                .put("method", "runXrayFromJson")
                .put("payload", new JSONObject().put("configJSON", config.toString()));
        requireInvokeSuccess(LibXray.invoke(request.toString()), "start Xray");
        JSONObject stateRequest = new JSONObject().put("apiVersion", 1).put("method", "getXrayState");
        JSONObject stateResponse = requireInvokeSuccess(LibXray.invoke(stateRequest.toString()), "read Xray state");
        JSONObject data = stateResponse.optJSONObject("data");
        if (data == null || !data.optBoolean("running", false)) throw new IllegalStateException("Pinned Xray core did not report a running state.");
        File activeBundle = getFileStreamPath(AndroidNodeStore.ACTIVE_BUNDLE);
        if (!AndroidPathProbe.prove(activeBundle, 8000)) throw new IllegalStateException("Native Xray did not pass selected-node private path proof.");
    }

    private static JSONObject requireInvokeSuccess(String raw, String action) throws Exception {
        if (raw == null || raw.trim().isEmpty()) throw new IllegalStateException("libXray returned no response while attempting to " + action + ".");
        JSONObject response = new JSONObject(raw);
        if (!response.optBoolean("success", false)) throw new IllegalStateException("libXray failed to " + action + ": " + response.optString("error", "unknown error"));
        return response;
    }

    private void registerUnderlyingNetworkMonitor() {
        synchronized (lock) {
            if (networkCallback != null) return;
            NetworkRequest request = new NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build();
            networkCallback = new ConnectivityManager.NetworkCallback() {
                @Override public void onAvailable(Network network) { executor.execute(() -> underlyingAvailable(network)); }
                @Override public void onLost(Network network) { executor.execute(() -> underlyingLost(network)); }
            };
            connectivity.registerNetworkCallback(request, networkCallback);
        }
    }

    private void underlyingAvailable(Network network) {
        if (network == null || explicitStop) return;
        boolean restart;
        synchronized (lock) {
            restart = underlyingNetwork != null && !underlyingNetwork.equals(network) && "UP".equals(state);
            underlyingNetwork = network;
        }
        if (!restart) return;
        restartAfterNetworkChange();
    }

    private void underlyingLost(Network network) {
        synchronized (lock) {
            if (underlyingNetwork != null && underlyingNetwork.equals(network)) underlyingNetwork = null;
        }
    }

    private void restartAfterNetworkChange() {
        String mode;
        synchronized (lock) {
            if (!"UP".equals(state) || tun == null || activeConfig == null) return;
            mode = activeMode;
            publish("STARTING", mode, "Underlying network changed; revalidating Xray path.");
        }
        try {
            stopCoreOnly();
            runCoreAndProve();
            publish("UP", mode, "");
            updateForeground("Native Xray active: " + mode);
        } catch (Throwable error) {
            Log.e(TAG, "Xray reconnect/path proof failed", error);
            shutdown("FAILED", "Underlying network changed and Xray could not re-establish a proven path: " + safe(error));
        }
    }

    private void stopCoreOnly() {
        try {
            JSONObject request = new JSONObject().put("apiVersion", 1).put("method", "stopXray");
            requireInvokeSuccess(LibXray.invoke(request.toString()), "stop Xray");
        } catch (Throwable ignored) { }
    }

    @Override public void onRevoke() {
        explicitStop = false;
        executor.execute(() -> shutdown("REVOKED", "Android revoked VPN permission."));
        super.onRevoke();
    }

    @Override public void onDestroy() {
        String terminal = state;
        String mode = activeMode;
        File session;
        synchronized (lock) {
            session = activeSession;
            activeSession = null;
            closeCoreLocked(true);
        }
        if (!explicitStop && ("UP".equals(terminal) || "STARTING".equals(terminal))) publish("FAILED", mode, "Native Xray VPN service stopped unexpectedly.");
        if (session != null) NativeXrayController.deleteTree(session);
        executor.shutdown();
        super.onDestroy();
    }

    private void shutdown(String terminalState, String error) {
        String mode;
        File session;
        synchronized (lock) {
            mode = activeMode;
            session = activeSession;
            if ("DOWN".equals(terminalState)) publish("STOPPING", mode, "");
            closeCoreLocked(true);
            activeSession = null;
            activeMode = "";
            activeConfig = null;
            publish(terminalState, "DOWN".equals(terminalState) ? "" : mode, error);
        }
        if (session != null) NativeXrayController.deleteTree(session);
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    private void closeCoreLocked(boolean closeTun) {
        stopCoreOnly();
        if (closeTun && tun != null) {
            try { tun.close(); } catch (Throwable ignored) { }
            tun = null;
        }
        if (networkCallback != null) {
            try { connectivity.unregisterNetworkCallback(networkCallback); } catch (Throwable ignored) { }
            networkCallback = null;
        }
        underlyingNetwork = null;
    }

    private void publish(String newState, String mode, String error) {
        state = newState;
        getSharedPreferences(NativeXrayController.PREFS, MODE_PRIVATE).edit()
                .putString(NativeXrayController.STATE_KEY, newState)
                .putString(NativeXrayController.MODE_KEY, mode == null ? "" : mode)
                .putString(NativeXrayController.ERROR_KEY, error == null ? "" : error)
                .apply();
    }

    private void ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL, "Router VPN Xray", NotificationManager.IMPORTANCE_LOW));
    }

    private Notification notification(String text) {
        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O ? new Notification.Builder(this, CHANNEL) : new Notification.Builder(this);
        return builder.setContentTitle("Router VPN").setContentText(text).setSmallIcon(android.R.drawable.stat_sys_warning).setOngoing(true).build();
    }

    private void updateForeground(String text) {
        NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        manager.notify(NOTIFICATION_ID, notification(text));
    }

    private static JSONObject readJson(File file, int max) throws Exception {
        File canonical = file.getCanonicalFile();
        if (!canonical.isFile() || canonical.length() <= 0 || canonical.length() > max) throw new IllegalStateException("Xray session file is missing or invalid: " + file.getName());
        try (FileInputStream input = new FileInputStream(canonical)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192]; int total = 0, read;
            while ((read = input.read(buffer)) != -1) { total += read; if (total > max) throw new IllegalStateException("Xray session file exceeds safety limit."); output.write(buffer, 0, read); }
            return new JSONObject(new String(output.toByteArray(), StandardCharsets.UTF_8));
        }
    }

    private static boolean safeToken(String value) { return value != null && value.matches("[A-Za-z0-9._-]{1,96}") && !value.equals(".") && !value.equals("..") && !value.contains(".."); }
    private static String safe(Throwable error) { String message = error == null ? "unknown error" : error.getMessage(); if (message == null || message.trim().isEmpty()) message = error == null ? "unknown error" : error.getClass().getSimpleName(); return message.replace('\n', ' ').replace('\r', ' ').trim(); }
}
