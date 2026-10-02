package com.eabusham.routervpn;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import io.nekohasekai.libbox.CommandServer;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterMTU;
import io.nekohasekai.libbox.RouterMTUPlatform;
import io.nekohasekai.libbox.RouterMTUState;
import org.json.JSONObject;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.UUID;

/** One service generation. No UI-created VPN, ambient-network measurement,
 * arbitrary target, endpoint replacement, or unverified cache adoption. */
final class AndroidMTUSession implements RouterMTUPlatform {
    interface Failure { void abort(AndroidMTUSession owner); }
    interface InterfaceReader { int mtu(String name) throws Exception; }
    private static final Object CACHE_LOCK = new Object();
    private final ConnectivityManager connectivity;
    private final SharedPreferences preferences;
    private final Failure failure;
    private final InterfaceReader interfaces;
    final String identity = UUID.randomUUID().toString();
    private String path = "", name = "", tun = "";
    private int requestedMTU;
    private volatile boolean invalid, closed;
    private boolean changing, activated;
    private volatile RouterMTU controller;
    private volatile String notice = "Connect a proved Auto-MTU Router VPN path first.";

    AndroidMTUSession(Context context, Failure failure) {
        this(context, failure, name -> {
            NetworkInterface value = NetworkInterface.getByName(name);
            if (value == null || !value.isUp()) throw new IllegalStateException("Owned interface is down.");
            return value.getMTU();
        });
    }
    // Only the OS readback boundary is replaceable by lifecycle tests.
    AndroidMTUSession(Context context, Failure failure, InterfaceReader interfaces) {
        connectivity = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        preferences = context.getSharedPreferences("routervpn-mtu-v3", Context.MODE_PRIVATE);
        this.failure = failure;
        this.interfaces = interfaces;
    }
    private String physicalPath() {
        try {
            ArrayList<String> values = new ArrayList<>();
            for (Network network : connectivity.getAllNetworks()) {
                NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
                LinkProperties links = connectivity.getLinkProperties(network);
                if (caps == null || links == null || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                ArrayList<String> addresses = new ArrayList<>();
                for (Object address : links.getLinkAddresses()) addresses.add(address.toString());
                Collections.sort(addresses);
                values.add(network.getNetworkHandle() + ":" + links.getInterfaceName() + ":" + addresses + ":" + links.getRoutes() + ":" + links.getDnsServers());
            }
            if (values.isEmpty()) return "";
            Network active = connectivity.getActiveNetwork();
            NetworkCapabilities activeCaps = active == null ? null : connectivity.getNetworkCapabilities(active);
            if (activeCaps == null) return "";
            // Do not key the VPN's replaceable handle, but do retain the default
            // physical network or the VPN's currently reported radio transports.
            values.add("default:" + (activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ? "vpn" : active.getNetworkHandle())
                    + ":" + activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                    + ":" + activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                    + ":" + activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET));
            Collections.sort(values);
            byte[] sum = MessageDigest.getInstance("SHA-256").digest(values.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder();
            for (byte value : sum) result.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
            return result.toString();
        } catch (Exception error) { return ""; }
    }
    synchronized void beforeOpen() throws Exception {
        if (closed || invalid || (!tun.isEmpty() && !changing)) throw new IllegalStateException("Unowned or stopped TUN replacement.");
        if (changing && !path.equals(physicalPath())) { invalid = true; throw new IllegalStateException("Physical path changed during MTU replacement."); }
    }
    synchronized void established(int mtu) throws Exception {
        if (closed || invalid || mtu < 1280 || mtu > 9000) throw new IllegalStateException("TUN establishment is stale or invalid.");
        tun = UUID.randomUUID().toString(); requestedMTU = mtu;
    }
    synchronized void registered(String value) {
        if (!closed && !invalid && value != null && value.matches("[A-Za-z0-9_.:-]{1,64}")) name = value;
    }
    synchronized boolean unchangedPhysicalPath() { return !closed && !invalid && !path.isEmpty() && path.equals(physicalPath()); }
    void networkChanged() {
        invalid = true;
        RouterMTU owned = controller; if (owned != null) owned.networkChanged();
    }
    void checkNetwork() {
        boolean changed;
        synchronized (this) { changed = !path.isEmpty() && !path.equals(physicalPath()); }
        if (changed) networkChanged();
    }
    void close() throws Exception {
        closed = true; invalid = true;
        RouterMTU owned = controller;
        if (owned != null) { owned.networkChanged(); owned.close(); }
    }
    private Network vpnNetwork() throws Exception {
        Network found = null;
        for (Network network : connectivity.getAllNetworks()) {
            NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
            LinkProperties links = connectivity.getLinkProperties(network);
            if (caps == null || links == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) || !name.equals(links.getInterfaceName())) continue;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && caps.getOwnerUid() != Process.myUid()) continue;
            if (found != null) throw new IllegalStateException("Ambiguous owned VPN interface.");
            found = network;
        }
        if (found == null) throw new IllegalStateException("Captured system VPN network is unavailable.");
        return found;
    }
    @Override public synchronized RouterMTUState captureMTU() {
        try {
            if (closed || invalid || name.isEmpty() || tun.isEmpty()) return null;
            String current = physicalPath(); if (current.isEmpty()) return null;
            if (path.isEmpty()) path = current;
            if (!path.equals(current)) { invalid = true; return null; }
            vpnNetwork();
            int actual = interfaces.mtu(name);
            if (actual != requestedMTU) return null;
            RouterMTUState result = new RouterMTUState();
            result.setSession(identity); result.setPath(path); result.setInterface(tun); result.setMTU(actual);
            return result;
        } catch (Exception error) { return null; }
    }
    private static boolean same(RouterMTUState a, RouterMTUState b) {
        return a != null && b != null && a.getSession().equals(b.getSession()) && a.getPath().equals(b.getPath())
                && a.getInterface().equals(b.getInterface()) && a.getMTU() == b.getMTU();
    }
    @Override public synchronized void beginMTUChange(RouterMTUState expected) throws Exception {
        if (changing || !same(captureMTU(), expected)) throw new IllegalStateException("MTU mutation lost its captured VPN.");
        changing = true;
    }
    @Override public synchronized void endMTUChange() throws Exception {
        try {
            long end = android.os.SystemClock.elapsedRealtime() + 2500;
            while (!closed && !invalid && captureMTU() == null && android.os.SystemClock.elapsedRealtime() < end) wait(20);
            if (captureMTU() == null) throw new IllegalStateException("OS VPN readback did not confirm the new MTU.");
        } finally { changing = false; }
    }
    @Override public synchronized void bindMTUSocket(RouterMTUState expected, long fd) throws Exception {
        if (fd < 0 || fd > Integer.MAX_VALUE || !same(captureMTU(), expected)) throw new IllegalStateException("MTU socket belongs to a stale VPN.");
        Network owned = vpnNetwork();
        try (ParcelFileDescriptor duplicate = ParcelFileDescriptor.fromFd((int) fd)) { owned.bindSocket(duplicate.getFileDescriptor()); }
        if (!same(captureMTU(), expected) || !owned.equals(vpnNetwork())) throw new IllegalStateException("VPN changed while binding the MTU socket.");
    }
    @Override public String readMTUCache() {
        synchronized (CACHE_LOCK) { try { return preferences.getString("records", ""); } catch (Exception invalid) { return "invalid-cache"; } }
    }
    @Override public boolean compareAndSwapMTUCache(String expected, String replacement) {
        synchronized (CACHE_LOCK) {
            if (expected == null || replacement == null || replacement.length() > 65536) return false;
            try { return expected.equals(preferences.getString("records", "")) && preferences.edit().putString("records", replacement).commit(); }
            catch (Exception error) { return false; }
        }
    }
    @Override public void abortMTU(String reason) { invalid = true; failure.abort(this); }

    // The service executor invokes this after final selection, not each SMART trial.
    void activate(CommandServer core, String config, String metadata) {
        synchronized (this) { if (activated || closed || invalid) return; activated = true; }
        try {
            JSONObject profile = new JSONObject(metadata);
            String policy = profile.optString("mtu_policy", "auto").trim().toLowerCase(java.util.Locale.ROOT);
            if (!(policy.isEmpty() || "auto".equals(policy)) || profile.optBoolean("jumbo_tun", false)) {
                notice = "Fixed, runtime-default and Jumbo modes do not enter Auto-MTU."; return;
            }
            long end = android.os.SystemClock.elapsedRealtime() + 2500;
            while (!closed && !invalid && captureMTU() == null && android.os.SystemClock.elapsedRealtime() < end) Thread.sleep(20);
            if (closed || invalid) return;
            RouterMTU created = Libbox.newRouterMTU(core, this, config, metadata);
            synchronized (this) {
                if (closed || invalid) { created.networkChanged(); created.close(); return; }
                controller = created;
            }
            if (!AndroidMTUMeasurementGate.held()) AndroidMTUMeasurementGate.startMTU(() -> created.start(UUID.randomUUID().toString().replace("-", ""), false));
            notice = "";
        } catch (Exception error) { notice = "Auto-MTU has no verified measurement for this native path; configured MTU is retained."; }
    }
    void drainForMeasurement() throws Exception {
        RouterMTU owned = controller;
        if (owned == null || !owned.running()) return;
        JSONObject progress = new JSONObject(owned.statusJSON());
        String request = progress.optString("request_id", "");
        if (!request.matches("[0-9a-f]{32}")) throw new IllegalStateException("MTU operation identity is unavailable.");
        owned.cancel(request);
        long end = android.os.SystemClock.elapsedRealtime() + 10000;
        while (owned.running() && !closed && android.os.SystemClock.elapsedRealtime() < end) Thread.sleep(20);
        if (closed || invalid || owned.running()) throw new IllegalStateException("MTU cancellation did not retain a verified measurement path.");
        JSONObject result = new JSONObject(owned.statusJSON());
        if (!result.optBoolean("restored", false) && !result.optBoolean("measured", false)
                && result.optInt("original_mtu", 0) != result.optInt("effective_mtu", -1)) {
            throw new IllegalStateException("MTU rollback was not verified before Speed Lab.");
        }
    }
    boolean running() { RouterMTU owned = controller; return owned != null && owned.running(); }
    String request(String operation, String session, String request) throws Exception {
        checkNetwork();
        RouterMTU owned = controller;
        if (!"status".equals(operation)) {
            if (closed || invalid || !identity.equals(session) || owned == null || request == null || !request.matches("[0-9a-f]{32}")) throw new IllegalStateException("MTU request is stale or unavailable.");
            if ("start".equals(operation)) AndroidMTUMeasurementGate.startMTU(() -> owned.start(request, true));
            else if ("cancel".equals(operation)) owned.cancel(request);
            else throw new IllegalArgumentException("Unknown MTU request.");
        }
        String raw = owned == null ? "{}" : owned.statusJSON();
        if (raw == null || raw.length() > 32768) throw new IllegalStateException("MTU status exceeds the IPC bound.");
        JSONObject result = new JSONObject(raw);
        if (owned == null) result.put("phase", "unavailable").put("failure", notice);
        result.put("session_id", identity);
        result.put("measurement_hold", AndroidMTUMeasurementGate.held());
        return result.toString();
    }
}
