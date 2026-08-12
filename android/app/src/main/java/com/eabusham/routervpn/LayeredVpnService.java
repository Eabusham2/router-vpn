package com.eabusham.routervpn;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.IpPrefix;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.system.OsConstants;
import android.util.Base64;
import android.util.Log;

import io.nekohasekai.libbox.CommandServer;
import io.nekohasekai.libbox.CommandServerHandler;
import io.nekohasekai.libbox.ConnectionOwner;
import io.nekohasekai.libbox.InterfaceUpdateListener;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.LocalDNSTransport;
import io.nekohasekai.libbox.NetworkInterfaceIterator;
import io.nekohasekai.libbox.OverrideOptions;
import io.nekohasekai.libbox.PlatformInterface;
import io.nekohasekai.libbox.RoutePrefix;
import io.nekohasekai.libbox.RoutePrefixIterator;
import io.nekohasekai.libbox.SetupOptions;
import io.nekohasekai.libbox.StringBox;
import io.nekohasekai.libbox.StringIterator;
import io.nekohasekai.libbox.SystemProxyStatus;
import io.nekohasekai.libbox.TunOptions;
import io.nekohasekai.libbox.WIFIState;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Embedded sing-box full-device Android tunnel. Mixed local-engine profiles are rejected before this service starts. */
public final class LayeredVpnService extends VpnService implements PlatformInterface, CommandServerHandler {
    static final String ACTION_START = "com.eabusham.routervpn.LAYERED_START";
    static final String ACTION_STOP = "com.eabusham.routervpn.LAYERED_STOP";
    static final String EXTRA_SESSION_ID = "session_id";
    static final String EXTRA_MODE_ID = "mode_id";

    private static final String TAG = "RouterVPN-Libbox";
    private static final String CHANNEL = "routervpn-layered";
    private static final int NOTIFICATION_ID = 7107;
    private static final int MAX_CONFIG = 4 * 1024 * 1024;
    private static final String PREFS = "router-vpn";
    private static final String STATE_KEY = "layered_state_v1";
    private static final String MODE_KEY = "layered_mode_v1";
    private static final String ERROR_KEY = "layered_error_v1";

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Object lock = new Object();
    private CommandServer commandServer;
    private ParcelFileDescriptor tunDescriptor;
    private File activeSession;
    private String activeMode = "";
    private volatile String state = "DOWN";
    private volatile boolean explicitStop;

    private ConnectivityManager connectivity;
    private InterfaceUpdateListener interfaceListener;
    private ConnectivityManager.NetworkCallback interfaceCallback;

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

        startForeground(NOTIFICATION_ID, buildNotification("Starting layered VPN…"));
        final String sessionId = intent.getStringExtra(EXTRA_SESSION_ID);
        final String modeId = intent.getStringExtra(EXTRA_MODE_ID);
        explicitStop = false;
        executor.execute(() -> startLayered(sessionId, modeId));
        return Service.START_NOT_STICKY;
    }

    private void startLayered(String sessionId, String modeId) {
        synchronized (lock) {
            if ("STARTING".equals(state) || "UP".equals(state)) return;
            publish("STARTING", modeId, "");
        }
        try {
            if (VpnService.prepare(this) != null) throw new RevokedException("Android VPN permission is missing or was revoked.");
            if (!safeToken(sessionId) || !safeToken(modeId)) throw new IllegalArgumentException("Invalid layered session metadata.");

            File sessionsRoot = new File(getFilesDir(), "layered-sessions").getCanonicalFile();
            File session = new File(sessionsRoot, sessionId).getCanonicalFile();
            if (!session.getParentFile().equals(sessionsRoot) || !session.isDirectory()) throw new IllegalStateException("Layered session is missing or unsafe.");
            File configFile = new File(session, "sing-box.json").getCanonicalFile();
            if (!configFile.getParentFile().equals(session) || !configFile.isFile()) throw new IllegalStateException("Layered session has no sing-box.json.");
            String config = new String(readLimited(configFile, MAX_CONFIG), java.nio.charset.StandardCharsets.UTF_8);

            File base = new File(getFilesDir(), "libbox-base");
            File temp = new File(getCacheDir(), "libbox-temp");
            if ((!base.isDirectory() && !base.mkdirs()) || (!temp.isDirectory() && !temp.mkdirs())) throw new IllegalStateException("Cannot create libbox runtime directories.");
            SetupOptions setup = new SetupOptions();
            setup.setBasePath(base.getAbsolutePath());
            // Critical: relative cert/config assets such as hysteria2 cert.pem resolve inside this private session.
            setup.setWorkingPath(session.getAbsolutePath());
            setup.setTempPath(temp.getAbsolutePath());
            setup.setFixAndroidStack(true);
            setup.setLogMaxLines(2000);
            setup.setDebug(false);
            Libbox.setup(setup);
            Libbox.checkConfig(config);

            synchronized (lock) {
                closeCoreLocked();
                activeSession = session;
                activeMode = modeId;
                commandServer = new CommandServer(this, this);
                commandServer.start();
                commandServer.startOrReloadService(config, new OverrideOptions());
                if (tunDescriptor == null || tunDescriptor.getFileDescriptor() == null || !tunDescriptor.getFileDescriptor().valid()) {
                    throw new IllegalStateException("sing-box started without establishing an Android VPN TUN.");
                }
                publish("UP", modeId, "");
            }
            updateForeground("Layered VPN active: " + modeId);
        } catch (RevokedException revoked) {
            Log.w(TAG, revoked.getMessage());
            shutdown("REVOKED", revoked.getMessage());
        } catch (Throwable error) {
            Log.e(TAG, "Layered VPN start failed", error);
            shutdown("FAILED", safeMessage(error));
        }
    }

    @Override public void onRevoke() {
        explicitStop = false;
        executor.execute(() -> shutdown("REVOKED", "Android revoked VPN permission."));
        super.onRevoke();
    }

    @Override public void onDestroy() {
        String terminal = state;
        synchronized (lock) { closeCoreLocked(); }
        if (!explicitStop && ("UP".equals(terminal) || "STARTING".equals(terminal))) {
            publish("FAILED", activeMode, "Layered VPN service stopped unexpectedly.");
        }
        executor.shutdown();
        super.onDestroy();
    }

    private void shutdown(String terminalState, String error) {
        String mode;
        File session;
        synchronized (lock) {
            if (!"DOWN".equals(terminalState) && !"FAILED".equals(terminalState) && !"REVOKED".equals(terminalState)) terminalState = "FAILED";
            if ("DOWN".equals(terminalState)) publish("STOPPING", activeMode, "");
            mode = activeMode;
            session = activeSession;
            closeCoreLocked();
            activeSession = null;
            activeMode = "";
            publish(terminalState, "DOWN".equals(terminalState) ? "" : mode, error);
        }
        if (session != null) deleteTree(session);
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    private void closeCoreLocked() {
        if (commandServer != null) {
            try { commandServer.closeService(); } catch (Throwable ignored) { }
            try { commandServer.close(); } catch (Throwable ignored) { }
            commandServer = null;
        }
        if (tunDescriptor != null) {
            try { tunDescriptor.close(); } catch (Throwable ignored) { }
            tunDescriptor = null;
        }
        unregisterInterfaceMonitorLocked();
    }

    private void publish(String newState, String mode, String error) {
        state = newState;
        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putString(STATE_KEY, newState)
                .putString(MODE_KEY, mode == null ? "" : mode)
                .putString(ERROR_KEY, error == null ? "" : error)
                .apply();
    }

    // PlatformInterface: libbox delegates Android TUN creation and socket protection here.
    @Override public LocalDNSTransport localDNSTransport() { return null; }
    @Override public boolean usePlatformAutoDetectInterfaceControl() { return true; }
    @Override public void autoDetectInterfaceControl(int fd) throws Exception {
        if (!protect(fd)) throw new IllegalStateException("Android refused to protect an outbound socket from the VPN loop.");
    }

    @Override public int openTun(TunOptions options) throws Exception {
        if (VpnService.prepare(this) != null) throw new RevokedException("Android VPN permission was revoked before TUN creation.");
        Builder builder = new Builder().setSession("Router VPN — " + (activeMode.isEmpty() ? "layered" : activeMode)).setMtu(options.getMTU());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false);

        RoutePrefixIterator inet4 = options.getInet4Address();
        while (inet4.hasNext()) { RoutePrefix route = inet4.next(); builder.addAddress(route.address(), route.prefix()); }
        RoutePrefixIterator inet6 = options.getInet6Address();
        while (inet6.hasNext()) { RoutePrefix route = inet6.next(); builder.addAddress(route.address(), route.prefix()); }

        if (options.getAutoRoute()) {
            StringBox dns = options.getDNSServerAddress();
            if (dns != null && dns.getValue() != null && !dns.getValue().isEmpty()) builder.addDnsServer(dns.getValue());
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                boolean has4 = addRoutes33(builder, options.getInet4RouteAddress(), false);
                boolean has6 = addRoutes33(builder, options.getInet6RouteAddress(), false);
                if (!has4 && options.getInet4Address().hasNext()) builder.addRoute(new IpPrefix("0.0.0.0/0"));
                if (!has6 && options.getInet6Address().hasNext()) builder.addRoute(new IpPrefix("::/0"));
                addRoutes33(builder, options.getInet4RouteExcludeAddress(), true);
                addRoutes33(builder, options.getInet6RouteExcludeAddress(), true);
            } else {
                addLegacyRoutes(builder, options.getInet4RouteRange());
                addLegacyRoutes(builder, options.getInet6RouteRange());
            }
            applyPackageRules(builder, options.getIncludePackage(), true);
            applyPackageRules(builder, options.getExcludePackage(), false);
        }

        ParcelFileDescriptor pfd = builder.establish();
        if (pfd == null) throw new RevokedException("Android refused to establish the VPN interface.");
        synchronized (lock) {
            if (tunDescriptor != null) try { tunDescriptor.close(); } catch (Throwable ignored) { }
            tunDescriptor = pfd;
        }
        return pfd.getFd();
    }

    private static boolean addRoutes33(Builder builder, RoutePrefixIterator iterator, boolean exclude) {
        boolean any = false;
        while (iterator.hasNext()) {
            RoutePrefix route = iterator.next();
            IpPrefix prefix = new IpPrefix(route.address() + "/" + route.prefix());
            if (exclude) builder.excludeRoute(prefix); else builder.addRoute(prefix);
            any = true;
        }
        return any;
    }

    private static void addLegacyRoutes(Builder builder, RoutePrefixIterator iterator) {
        while (iterator.hasNext()) { RoutePrefix route = iterator.next(); builder.addRoute(route.address(), route.prefix()); }
    }

    private void applyPackageRules(Builder builder, StringIterator iterator, boolean include) {
        while (iterator.hasNext()) {
            String packageName = iterator.next();
            try {
                if (include) builder.addAllowedApplication(packageName); else builder.addDisallowedApplication(packageName);
            } catch (PackageManager.NameNotFoundException missing) {
                Log.w(TAG, "Ignoring missing package rule: " + packageName);
            }
        }
    }

    @Override public boolean useProcFS() { return Build.VERSION.SDK_INT < Build.VERSION_CODES.Q; }

    @Override public ConnectionOwner findConnectionOwner(int ipProtocol, String sourceAddress, int sourcePort, String destinationAddress, int destinationPort) throws Exception {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) throw new IllegalStateException("Connection owner lookup is unavailable before Android 10.");
        int uid = connectivity.getConnectionOwnerUid(ipProtocol, new InetSocketAddress(sourceAddress, sourcePort), new InetSocketAddress(destinationAddress, destinationPort));
        if (uid == Process.INVALID_UID) throw new IllegalStateException("Android connection owner was not found.");
        String[] packages = getPackageManager().getPackagesForUid(uid);
        ConnectionOwner owner = new ConnectionOwner();
        owner.setUserId(uid);
        owner.setUserName(packages != null && packages.length > 0 ? packages[0] : "");
        List<String> packageList = new ArrayList<>();
        if (packages != null) Collections.addAll(packageList, packages);
        owner.setAndroidPackageNames(new Strings(packageList));
        return owner;
    }

    @Override public void startDefaultInterfaceMonitor(InterfaceUpdateListener listener) throws Exception {
        synchronized (lock) {
            interfaceListener = listener;
            if (interfaceCallback == null) {
                interfaceCallback = new ConnectivityManager.NetworkCallback() {
                    @Override public void onAvailable(Network network) { pushDefaultInterface(); }
                    @Override public void onLost(Network network) { pushDefaultInterface(); }
                    @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) { pushDefaultInterface(); }
                    @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) { pushDefaultInterface(); }
                };
                connectivity.registerDefaultNetworkCallback(interfaceCallback);
            }
        }
        pushDefaultInterface();
    }

    @Override public void closeDefaultInterfaceMonitor(InterfaceUpdateListener listener) {
        synchronized (lock) {
            if (interfaceListener == listener) interfaceListener = null;
            unregisterInterfaceMonitorLocked();
        }
    }

    private void unregisterInterfaceMonitorLocked() {
        if (interfaceCallback != null) {
            try { connectivity.unregisterNetworkCallback(interfaceCallback); } catch (Throwable ignored) { }
            interfaceCallback = null;
        }
        interfaceListener = null;
    }

    private void pushDefaultInterface() {
        InterfaceUpdateListener listener = interfaceListener;
        if (listener == null) return;
        try {
            Network network = connectivity.getActiveNetwork();
            if (network == null) return;
            LinkProperties links = connectivity.getLinkProperties(network);
            NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
            if (links == null || links.getInterfaceName() == null) return;
            java.net.NetworkInterface netIf = java.net.NetworkInterface.getByName(links.getInterfaceName());
            int index = netIf == null ? 0 : netIf.getIndex();
            boolean expensive = caps == null || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED);
            boolean constrained = caps != null && !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED);
            listener.updateDefaultInterface(links.getInterfaceName(), index, expensive, constrained);
        } catch (Throwable error) { Log.w(TAG, "Default-interface update failed", error); }
    }

    @Override public NetworkInterfaceIterator getInterfaces() throws Exception {
        Map<String, LinkProperties> linksByName = new HashMap<>();
        Map<String, NetworkCapabilities> capsByName = new HashMap<>();
        for (Network network : connectivity.getAllNetworks()) {
            LinkProperties links = connectivity.getLinkProperties(network);
            if (links == null || links.getInterfaceName() == null) continue;
            linksByName.put(links.getInterfaceName(), links);
            NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
            if (caps != null) capsByName.put(links.getInterfaceName(), caps);
        }

        List<io.nekohasekai.libbox.NetworkInterface> result = new ArrayList<>();
        Enumeration<java.net.NetworkInterface> enumeration = java.net.NetworkInterface.getNetworkInterfaces();
        while (enumeration != null && enumeration.hasMoreElements()) {
            java.net.NetworkInterface netIf = enumeration.nextElement();
            io.nekohasekai.libbox.NetworkInterface box = new io.nekohasekai.libbox.NetworkInterface();
            box.setName(netIf.getName());
            box.setIndex(netIf.getIndex());
            try { box.setMTU(netIf.getMTU()); } catch (Throwable ignored) { box.setMTU(0); }
            List<String> addresses = new ArrayList<>();
            netIf.getInterfaceAddresses().forEach(item -> {
                if (item != null && item.getAddress() != null) addresses.add(interfacePrefix(item));
            });
            box.setAddresses(new Strings(addresses));
            int flags = 0;
            try { if (netIf.isUp()) flags |= OsConstants.IFF_UP | OsConstants.IFF_RUNNING; } catch (Throwable ignored) { }
            try { if (netIf.isLoopback()) flags |= OsConstants.IFF_LOOPBACK; } catch (Throwable ignored) { }
            try { if (netIf.isPointToPoint()) flags |= OsConstants.IFF_POINTOPOINT; } catch (Throwable ignored) { }
            try { if (netIf.supportsMulticast()) flags |= OsConstants.IFF_MULTICAST; } catch (Throwable ignored) { }
            box.setFlags(flags);

            LinkProperties links = linksByName.get(netIf.getName());
            NetworkCapabilities caps = capsByName.get(netIf.getName());
            List<String> dns = new ArrayList<>();
            if (links != null) links.getDnsServers().forEach(server -> { if (server.getHostAddress() != null) dns.add(server.getHostAddress()); });
            box.setDNSServer(new Strings(dns));
            int type = Libbox.InterfaceTypeOther;
            if (caps != null) {
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) type = Libbox.InterfaceTypeWIFI;
                else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) type = Libbox.InterfaceTypeCellular;
                else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) type = Libbox.InterfaceTypeEthernet;
            }
            box.setType(type);
            box.setMetered(caps == null || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED));
            result.add(box);
        }
        return new Interfaces(result);
    }

    @Override public boolean underNetworkExtension() { return false; }
    @Override public boolean includeAllNetworks() { return false; }
    @Override public WIFIState readWIFIState() { return null; }

    @Override public StringIterator systemCertificates() {
        List<String> certs = new ArrayList<>();
        try {
            KeyStore store = KeyStore.getInstance("AndroidCAStore");
            store.load(null, null);
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                Certificate cert = store.getCertificate(aliases.nextElement());
                if (cert == null) continue;
                certs.add("-----BEGIN CERTIFICATE-----\n" + Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP) + "\n-----END CERTIFICATE-----");
            }
        } catch (Throwable error) { Log.w(TAG, "Unable to enumerate Android CA store", error); }
        return new Strings(certs);
    }

    @Override public void clearDNSCache() { }
    @Override public void sendNotification(io.nekohasekai.libbox.Notification notification) { }

    // CommandServerHandler. State callbacks never turn FAILED/REVOKED into a false clean DOWN state.
    @Override public void serviceStop() {
        executor.execute(() -> {
            if ("FAILED".equals(state) || "REVOKED".equals(state)) return;
            shutdown(explicitStop ? "DOWN" : "FAILED", explicitStop ? "" : "sing-box stopped unexpectedly.");
        });
    }

    @Override public void serviceReload() {
        Log.i(TAG, "libbox requested a service reload; the active config remains authoritative for this session.");
    }

    @Override public SystemProxyStatus getSystemProxyStatus() { return null; }
    @Override public void setSystemProxyEnabled(boolean enabled) { }
    @Override public void writeDebugMessage(String message) { Log.d(TAG, message == null ? "" : message); }

    private void ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            manager.createNotificationChannel(new NotificationChannel(CHANNEL, "Router VPN layered tunnel", NotificationManager.IMPORTANCE_LOW));
        }
    }

    private android.app.Notification buildNotification(String text) {
        android.app.Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O ? new android.app.Notification.Builder(this, CHANNEL) : new android.app.Notification.Builder(this);
        return builder.setContentTitle("Router VPN").setContentText(text).setSmallIcon(android.R.drawable.ic_dialog_info).setOngoing(true).build();
    }

    private void updateForeground(String text) { startForeground(NOTIFICATION_ID, buildNotification(text)); }

    private static String interfacePrefix(java.net.InterfaceAddress item) {
        java.net.InetAddress address = item.getAddress();
        String host = address.getHostAddress();
        if (address instanceof Inet6Address) {
            try { host = Inet6Address.getByAddress(address.getAddress()).getHostAddress(); } catch (Throwable ignored) { }
        }
        return host + "/" + item.getNetworkPrefixLength();
    }

    private static boolean safeToken(String value) { return value != null && value.matches("[A-Za-z0-9._-]{1,96}") && !value.contains(".."); }

    private static byte[] readLimited(File file, int max) throws Exception {
        try (FileInputStream input = new FileInputStream(file); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192]; int total = 0, read;
            while ((read = input.read(buffer)) != -1) { total += read; if (total > max) throw new IllegalStateException("Config exceeds safety limit."); output.write(buffer, 0, read); }
            return output.toByteArray();
        }
    }

    private static void deleteTree(File file) {
        if (file == null) return;
        File[] children = file.listFiles();
        if (children != null) for (File child : children) deleteTree(child);
        if (!file.delete() && file.exists()) Log.w(TAG, "Could not delete layered session path: " + file);
    }

    private static String safeMessage(Throwable error) {
        String value = error == null ? "unknown error" : error.getMessage();
        if (value == null || value.trim().isEmpty()) value = error == null ? "unknown error" : error.getClass().getSimpleName();
        return value.replace('\n', ' ').replace('\r', ' ').trim();
    }

    private static final class RevokedException extends Exception { RevokedException(String message) { super(message); } }

    private static final class Strings implements StringIterator {
        private final java.util.Iterator<String> iterator;
        private final int size;
        Strings(List<String> values) { List<String> copy = new ArrayList<>(values); iterator = copy.iterator(); size = copy.size(); }
        @Override public int len() { return size; }
        @Override public boolean hasNext() { return iterator.hasNext(); }
        @Override public String next() { return iterator.next(); }
    }

    private static final class Interfaces implements NetworkInterfaceIterator {
        private final java.util.Iterator<io.nekohasekai.libbox.NetworkInterface> iterator;
        Interfaces(List<io.nekohasekai.libbox.NetworkInterface> values) { iterator = values.iterator(); }
        @Override public boolean hasNext() { return iterator.hasNext(); }
        @Override public io.nekohasekai.libbox.NetworkInterface next() { return iterator.next(); }
    }
}
