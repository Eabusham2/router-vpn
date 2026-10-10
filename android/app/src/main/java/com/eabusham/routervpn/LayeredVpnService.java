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

import org.json.JSONObject;

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
import io.nekohasekai.libbox.StringIterator;
import io.nekohasekai.libbox.SystemProxyStatus;
import io.nekohasekai.libbox.TunOptions;
import io.nekohasekai.libbox.WIFIState;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
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
    private final Object tunAccess = new Object();
    private volatile AndroidMTUSession mtuSession;
    private String mtuMetadata = "";
    static void startAutomaticMTU(){
        LayeredVpnService service=currentService.get();if(service==null)return;
        CommandServer core=service.commandServer;AndroidMTUSession captured=service.mtuSession;
        service.executor.execute(()->{
            if(core==null||captured==null||service.commandServer!=core||service.mtuSession!=captured||service.explicitStop||!"UP".equals(service.state))return;
            if(!service.mtuMetadata.isEmpty())captured.activate(core,service.activeConfig,service.mtuMetadata);
        });
    }
    static void quiesceMTUForSpeedLab(java.util.function.Consumer<Throwable> completion){
        LayeredVpnService service=currentService.get();
        if(service==null){completion.accept(null);return;}
        AndroidMTUSession captured=service.mtuSession;
        try{service.executor.execute(()->{
            try{
                if(captured!=service.mtuSession)throw new IllegalStateException("VPN changed while acquiring the Speed Lab path.");
                if(captured!=null)captured.drainForMeasurement();
                completion.accept(null);
            }catch(Throwable error){completion.accept(error);}
        });}catch(java.util.concurrent.RejectedExecutionException error){completion.accept(error);}
    }
    static String mtuRequest(String operation,String session,String request)throws Exception{
        LayeredVpnService service=currentService.get();if(service==null)throw new IllegalStateException("No live Router VPN session.");
        synchronized(service.lock){
            AndroidMTUSession owned=service.mtuSession;
            if(owned==null||!"UP".equals(service.state)||service.explicitStop)throw new IllegalStateException("Connect a proved Router VPN path first.");
            if("start".equals(operation)&&service.hopMeasurement!=null){
                JSONObject progress=new JSONObject(service.hopMeasurement.statusJSON());
                if(!progress.optBoolean("complete",false)&&!progress.optString("request_id","").isEmpty())throw new IllegalStateException("Finish hop measurement before MTU Retest.");
            }
            return owned.request(operation,session,request);
        }
    }
    private volatile CommandServer commandServer;
    private volatile boolean performanceActive;
    private final Runnable performanceWatch = new Runnable() { public void run() {
        CommandServer owned = commandServer;
        if (!performanceActive || owned == null || !"UP".equals(state)) return;
        String failure = Libbox.routerPerformanceFailure(owned);
        if (failure == null || !failure.isEmpty()) {
            executor.execute(() -> { if (commandServer == owned && performanceActive) shutdown("FAILED", "Requested padding stopped or its private path changed."); });
            return;
        }
        executionHandler.postDelayed(this, 500);
    }};
    private volatile io.nekohasekai.libbox.RouterMultihop executionController;
    private volatile io.nekohasekai.libbox.RouterHopMeasurement hopMeasurement;
    private static volatile java.lang.ref.WeakReference<LayeredVpnService> currentService=new java.lang.ref.WeakReference<>(null);
    private final android.os.Handler executionHandler=new android.os.Handler(android.os.Looper.getMainLooper());
    private volatile String executionNetwork="";
    private volatile boolean executionProved;
    static String multihopProgressJSON(){LayeredVpnService service=currentService.get();io.nekohasekai.libbox.RouterMultihop plan=service==null?null:service.executionController;return plan==null?"":plan.progressJSON();}
    static String hopMeasurementRequest(String operation,String id) throws Exception {
        LayeredVpnService service=currentService.get();
        if(service==null||id==null||!id.matches("[0-9a-f]{32}"))throw new IllegalStateException("No captured hop measurement session.");
        synchronized(service.lock){
            io.nekohasekai.libbox.RouterHopMeasurement probe=service.hopMeasurement;
            if(probe==null||!"UP".equals(service.state))throw new IllegalStateException("The proved multihop runtime is unavailable.");
            if("start".equals(operation)){
                if(service.mtuSession!=null&&service.mtuSession.running())throw new IllegalStateException("Finish MTU Retest before measuring hops.");
                probe.start(id,8388608);
            }
            else if("cancel".equals(operation))probe.cancel(id);
            else if(!"status".equals(operation))throw new IllegalArgumentException("Unknown hop measurement operation.");
            String response=probe.statusJSON();
            if(response==null||response.length()>16384)throw new IllegalStateException("Oversized measurement status.");
            return response;
        }
    }
    private void cancelMultihopComparison(){AndroidMTUSession mtu=mtuSession;if(mtu!=null)mtu.networkChanged();CommandServer owned=commandServer;if(owned!=null)Libbox.routerInvalidatePerformance(owned);io.nekohasekai.libbox.RouterHopMeasurement probe=hopMeasurement;if(probe!=null)probe.networkChanged();io.nekohasekai.libbox.RouterMultihop plan=executionController;if(plan!=null)plan.networkChanged();}
    private String executionNetworkIdentity(){
        java.util.ArrayList<String> values=new java.util.ArrayList<>();
        try{for(Network network:connectivity.getAllNetworks()){
            NetworkCapabilities caps=connectivity.getNetworkCapabilities(network);
            LinkProperties links=connectivity.getLinkProperties(network);
            if(caps==null||caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)||links==null)continue;
            values.add(network.toString()+":"+links.getInterfaceName()+":"+links.getLinkAddresses());
        }}catch(Exception failure){return "";}
        java.util.Collections.sort(values);return values.toString();
    }
    private final Runnable executionWatch=new Runnable(){public void run(){
        io.nekohasekai.libbox.RouterMultihop plan=executionController;if(plan==null&&hopMeasurement==null)return;
        if(!executionNetwork.equals(executionNetworkIdentity())||(executionProved&&plan!=null&&!plan.healthy())){
            cancelMultihopComparison();executor.execute(()->shutdown("FAILED","Multihop network or server lease changed; reconnect to compare again."));return;
        }
        executionHandler.postDelayed(this,500);
    }};
    private volatile ParcelFileDescriptor tunDescriptor;
    private AndroidStartLayerRelay startLayerRelay;
    private File activeSession;
    private String activeMode = "";
    private String activeConfig = "";
    private volatile String state = "DOWN";
    private volatile boolean explicitStop;

    private ConnectivityManager connectivity;
    private InterfaceUpdateListener interfaceListener;
    private ConnectivityManager.NetworkCallback interfaceCallback;

    @Override public void onCreate() {
        super.onCreate();
        connectivity = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        ensureNotificationChannel();
        currentService=new java.lang.ref.WeakReference<>(this);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? "" : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            cancelMultihopComparison();
            explicitStop = true;
            final long command = intent.getLongExtra(AndroidServiceStopConfirmation.EXTRA_COMMAND, 0L);
            executor.execute(() -> {
                shutdown("DOWN", "");
                // Do not acknowledge in finally: failed teardown must remain busy.
                AndroidServiceStopConfirmation.acknowledge(STATE_KEY, command);
            });
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
        AndroidStartLayerRelay pendingRelay = null;
        try {
            if (VpnService.prepare(this) != null) throw new RevokedException("Android VPN permission is missing or was revoked.");
            if (!safeToken(sessionId) || !safeToken(modeId)) throw new IllegalArgumentException("Invalid layered session metadata.");

            File sessionsRoot = new File(getFilesDir(), "layered-sessions").getCanonicalFile();
            File session = new File(sessionsRoot, sessionId).getCanonicalFile();
            if (!session.getParentFile().equals(sessionsRoot) || !session.isDirectory()) throw new IllegalStateException("Layered session is missing or unsafe.");
            if (new File(session, AndroidKillSwitchPolicy.SESSION_MARKER).isFile()) {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                    throw new IllegalStateException("Strict Android kill switch requires Android 10 or newer lockdown APIs.");
                }
                if (!isAlwaysOn() || !isLockdownEnabled()) {
                    throw new IllegalStateException(AndroidKillSwitchPolicy.requirementMessage());
                }
            }
            File configFile = new File(session, "sing-box.json").getCanonicalFile();
            if (!configFile.getParentFile().equals(session) || !configFile.isFile()) throw new IllegalStateException("Layered session has no sing-box.json.");
            String config = new String(readLimited(configFile, MAX_CONFIG), java.nio.charset.StandardCharsets.UTF_8);

            File base = new File(getFilesDir(), "libbox-base");
            File temp = new File(getCacheDir(), "libbox-temp");
            if ((!base.isDirectory() && !base.mkdirs()) || (!temp.isDirectory() && !temp.mkdirs())) throw new IllegalStateException("Cannot create libbox runtime directories.");
            SetupOptions setup = new SetupOptions();
            setup.setBasePath(base.getAbsolutePath());
            setup.setWorkingPath(session.getAbsolutePath());
            setup.setTempPath(temp.getAbsolutePath());
            setup.setFixAndroidStack(true);
            setup.setLogMaxLines(2000);
            setup.setDebug(false);
            Libbox.setup(setup);
            io.nekohasekai.libbox.RouterMultihop preparedExecution=null;
            String hopMetadata=null;
            File executionFile=new File(session,"routervpn-multihop.json").getCanonicalFile();
            File entryLayerFile=new File(session,AndroidMultihopStartLayer.SESSION_FILE).getCanonicalFile();
            if (entryLayerFile.exists() && (!executionFile.isFile() || !entryLayerFile.getParentFile().equals(session))) {
                throw new IllegalStateException("Entry Start Layer has no owned multihop session.");
            }
            if(executionFile.isFile()){
                if(!modeId.startsWith("multihop-")||!executionFile.getParentFile().equals(session))throw new IllegalStateException("Unowned multihop metadata.");
                String metadata=new String(readLimited(executionFile,16384),java.nio.charset.StandardCharsets.UTF_8);
                hopMetadata=metadata;
                String execution=new JSONObject(metadata).optString("execution","local");
                if(!java.util.Arrays.asList("local","server","auto").contains(execution))throw new IllegalArgumentException("Unknown multihop execution.");
                String captured=null;
                if(entryLayerFile.exists()) {
                    if(!entryLayerFile.isFile())throw new IllegalStateException("Captured entry layer is not a private file.");
                    byte[] raw=readLimited(entryLayerFile,AndroidMultihopStartLayer.MAX_BYTES);
                    captured=java.nio.charset.StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                        .decode(java.nio.ByteBuffer.wrap(raw)).toString();
                }
                preparedExecution=AndroidMultihopStartLayer.prepareExecution(config,metadata,captured);
                if(preparedExecution!=null)config=preparedExecution.config();
            }
            String capturedMTU="";
            File mtuFile=new File(session,"routervpn-mtu.json").getCanonicalFile();
            if(mtuFile.isFile()){
                if(!mtuFile.getParentFile().equals(session))throw new IllegalStateException("Unowned MTU profile file.");
                capturedMTU=new String(readLimited(mtuFile,256*1024),java.nio.charset.StandardCharsets.UTF_8);
            }
            Libbox.checkConfig(config);

            pendingRelay = AndroidStartLayerRelay.startIfConfigured(this, session, message -> executor.execute(() -> {
                if (!explicitStop) shutdown("FAILED", message);
            }));
            synchronized (lock) {
                closeCoreLocked();
                startLayerRelay = pendingRelay;
                pendingRelay = null;
                activeSession = session;
                activeMode = modeId;
                activeConfig = config;
                mtuMetadata=capturedMTU;
                mtuSession=new AndroidMTUSession(this,owner->executor.execute(()->{
                    if(mtuSession==owner)shutdown("FAILED","MTU transaction could not retain the verified VPN interface.");
                }));
                executionController=preparedExecution;executionProved=false;
                commandServer = new CommandServer(this, this);
                commandServer.start();
                commandServer.startOrReloadService(config, new OverrideOptions());
                if (tunDescriptor == null || tunDescriptor.getFileDescriptor() == null || !tunDescriptor.getFileDescriptor().valid()) {
                    throw new IllegalStateException("sing-box started without establishing an Android VPN TUN.");
                }
            }
            io.nekohasekai.libbox.RouterMultihop ownedExecution=executionController;
            CommandServer ownedServer=commandServer;
            if(hopMetadata!=null){
                executionNetwork=executionNetworkIdentity();
                if(executionNetwork.isEmpty())throw new IllegalStateException("Underlying network identity is unavailable.");
                executionHandler.post(executionWatch);
                if(ownedExecution!=null)ownedExecution.run(ownedServer);
                synchronized(lock){hopMeasurement=Libbox.newRouterHopMeasurement(ownedServer,hopMetadata);}
                executionHandler.removeCallbacks(executionWatch);executionHandler.post(executionWatch);
            }
            long performanceServices = Libbox.routerStartPerformance(ownedServer);
            synchronized(lock){
                if(explicitStop||commandServer!=ownedServer||executionController!=ownedExecution)throw new IllegalStateException("VPN ownership changed during multihop comparison.");
                performanceActive = performanceServices > 0;
                executionProved=true;publish("UP",modeId,"");
            }
            if (performanceActive) executionHandler.post(performanceWatch);
            updateForeground("Layered VPN active: " + modeId);
        } catch (RevokedException revoked) {
            Log.w(TAG, revoked.getMessage());
            shutdown("REVOKED", revoked.getMessage());
        } catch (Throwable error) {
            Log.e(TAG, "Layered VPN start failed", error);
            shutdown("FAILED", safeMessage(error));
        } finally {
            if (pendingRelay != null) pendingRelay.close();
        }
    }

    @Override public void onRevoke() {
        cancelMultihopComparison();
        explicitStop = false;
        executor.execute(() -> shutdown("REVOKED", "Android revoked VPN permission."));
        super.onRevoke();
    }

    @Override public void onDestroy() {
        cancelMultihopComparison();
        if(currentService.get()==this)currentService.clear();
        String terminal = state;
        String mode = activeMode;
        File session;
        synchronized (lock) {
            session = activeSession;
            activeSession = null;
            closeCoreLocked();
            activeConfig = "";
        }
        if (!explicitStop && ("UP".equals(terminal) || "STARTING".equals(terminal))) {
            publish("FAILED", mode, "Layered VPN service stopped unexpectedly.");
        }
        if (session != null) deleteTree(session);
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
            activeConfig = "";
            publish(terminalState, "DOWN".equals(terminalState) ? "" : mode, error);
        }
        if (session != null) deleteTree(session);
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    private void closeCoreLocked() {
        AndroidMTUSession oldMTU=mtuSession;
        if(oldMTU!=null){
            oldMTU.networkChanged();
            try{oldMTU.close();}catch(Exception error){Log.w(TAG,"MTU controller drain failed before native teardown.");}
        }
        mtuSession=null;mtuMetadata="";
        performanceActive = false;
        executionHandler.removeCallbacks(performanceWatch);
        if (commandServer != null) Libbox.routerInvalidatePerformance(commandServer);
        executionHandler.removeCallbacks(executionWatch);
        if(hopMeasurement!=null){try{hopMeasurement.close();}catch(Exception error){Log.w(TAG,"Hop measurement teardown is pending.");}hopMeasurement=null;}
        if(executionController!=null){
            try{executionController.close();}catch(Exception failure){Log.w(TAG,"Server lease cleanup was not confirmed; bounded server expiry remains in force.");}
            executionController=null;executionProved=false;
        }
        if (commandServer != null) {
            try { commandServer.closeService(); } catch (Throwable ignored) { }
            try { commandServer.close(); } catch (Throwable ignored) { }
            commandServer = null;
        }
        if (startLayerRelay != null) {
            try { startLayerRelay.close(); } catch (Throwable ignored) { }
            startLayerRelay = null;
        }
        synchronized(tunAccess){
            if (tunDescriptor != null) {try { tunDescriptor.close(); } catch (Throwable ignored) { } tunDescriptor=null;}
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

    @Override public LocalDNSTransport localDNSTransport() { return null; }
    @Override public boolean usePlatformAutoDetectInterfaceControl() { return true; }
    @Override public void autoDetectInterfaceControl(int fd) throws Exception {
        if (!protect(fd)) throw new IllegalStateException("Android refused to protect an outbound socket from the VPN loop.");
    }

    @Override public int openTun(TunOptions options) throws Exception {
        if (VpnService.prepare(this) != null) throw new RevokedException("Android VPN permission was revoked before TUN creation.");
        AndroidMTUSession opening=mtuSession;
        if(opening==null||explicitStop)throw new IllegalStateException("TUN owner stopped before establishment.");
        opening.beforeOpen();
        Builder builder = new Builder().setSession("Router VPN — " + (activeMode.isEmpty() ? "layered" : activeMode)).setMtu(options.getMTU());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false);

        RoutePrefixIterator inet4 = options.getInet4Address();
        while (inet4.hasNext()) { RoutePrefix route = inet4.next(); builder.addAddress(route.address(), route.prefix()); }
        RoutePrefixIterator inet6 = options.getInet6Address();
        while (inet6.hasNext()) { RoutePrefix route = inet6.next(); builder.addAddress(route.address(), route.prefix()); }

        if (options.getAutoRoute()) {
            StringIterator dns = options.getDNSServerAddress();
            int dnsCount = 0;
            if (dns == null) throw new IllegalStateException("Libbox did not provide in-tunnel DNS.");
            while (dns.hasNext()) {
                String address = dns.next();
                if (++dnsCount > 16 || address == null || address.trim().isEmpty()) {
                    throw new IllegalStateException("Libbox returned an invalid or oversized in-tunnel DNS list.");
                }
                // Builder accepts numeric addresses; no hostname resolution or
                // system-DNS fallback is introduced by this binding adapter.
                builder.addDnsServer(address.trim());
            }
            if (dnsCount == 0) throw new IllegalStateException("Libbox did not provide in-tunnel DNS.");
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                boolean has4 = addRoutes33(builder, options.getInet4RouteAddress(), false);
                boolean has6 = addRoutes33(builder, options.getInet6RouteAddress(), false);
                if (!has4 && options.getInet4Address().hasNext()) builder.addRoute(new IpPrefix(InetAddress.getByName("0.0.0.0"), 0));
                if (!has6 && options.getInet6Address().hasNext()) builder.addRoute(new IpPrefix(InetAddress.getByName("::"), 0));
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
        synchronized (tunAccess) {
            if(opening!=mtuSession||explicitStop){pfd.close();throw new IllegalStateException("TUN establishment became stale.");}
            try{opening.established(options.getMTU());}catch(Exception error){pfd.close();throw error;}
            ParcelFileDescriptor previous=tunDescriptor;tunDescriptor=pfd;
            if(previous!=null)previous.close();
        }
        return pfd.getFd();
    }

    private static boolean addRoutes33(Builder builder, RoutePrefixIterator iterator, boolean exclude) throws Exception {
        boolean any = false;
        while (iterator.hasNext()) {
            RoutePrefix route = iterator.next();
            IpPrefix prefix = new IpPrefix(InetAddress.getByName(route.address()), route.prefix());
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
        AndroidMTUSession mtu=mtuSession;
        if(mtu!=null){
            // Own VPN replacement is not a physical-interface transition.
            if(mtu.unchangedPhysicalPath())return;
            mtu.checkNetwork();
        }
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
            CommandServer server = commandServer;
            if (server != null) server.resetNetwork();
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

    public StringIterator systemCertificates() {
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

    @Override public void serviceStop() {
        executor.execute(() -> {
            if ("FAILED".equals(state) || "REVOKED".equals(state)) return;
            shutdown(explicitStop ? "DOWN" : "FAILED", explicitStop ? "" : "sing-box stopped unexpectedly.");
        });
    }

    @Override public void serviceReload() {
        executor.execute(() -> {
            synchronized (lock) {
                if (commandServer == null || activeConfig.isEmpty()) return;
                if(executionController!=null||hopMeasurement!=null||mtuSession!=null){cancelMultihopComparison();shutdown("FAILED","Native reload needs fresh path and MTU ownership.");return;}
                try {
                    commandServer.startOrReloadService(activeConfig, new OverrideOptions());
                } catch (Throwable error) {
                    Log.e(TAG, "libbox reload failed", error);
                    publish("FAILED", activeMode, safeMessage(error));
                }
            }
        });
    }

    @Override public SystemProxyStatus getSystemProxyStatus() { return new SystemProxyStatus(); }
    @Override public void setSystemProxyEnabled(boolean enabled) { }
    @Override public void writeDebugMessage(String message) { Log.d(TAG, message == null ? "" : message); }

    @Override public void cancelNotification(String identifier, int typeID) { }
    @Override public void startNeighborMonitor(io.nekohasekai.libbox.NeighborUpdateListener listener) throws Exception { throw unsupportedPlatformService(); }
    @Override public void closeNeighborMonitor(io.nekohasekai.libbox.NeighborUpdateListener listener) { }
    @Override public void registerMyInterface(String name) { AndroidMTUSession owned=mtuSession;if(owned!=null)owned.registered(name); }
    @Override public boolean usePlatformShell() { return false; }
    @Override public void checkPlatformShell() throws Exception { throw unsupportedPlatformService(); }
    @Override public io.nekohasekai.libbox.ShellSession openShellSession(io.nekohasekai.libbox.PlatformUser user, String command, StringIterator environ, String term, int rows, int cols) throws Exception { throw unsupportedPlatformService(); }
    @Override public io.nekohasekai.libbox.PlatformUser lookupUser(String username) throws Exception { throw unsupportedPlatformService(); }
    @Override public String lookupSFTPServer() throws Exception { throw unsupportedPlatformService(); }
    @Override public String readSystemSSHHostKey() throws Exception { throw unsupportedPlatformService(); }
    @Override public String tailscaleHostname() { return "router-vpn"; }
    @Override public boolean usePlatformBridge() { return false; }
    @Override public io.nekohasekai.libbox.BridgeSession createBridge(io.nekohasekai.libbox.BridgeOptions options) throws Exception { throw unsupportedPlatformService(); }
    @Override public void triggerNativeCrash() throws Exception { throw unsupportedPlatformService(); }
    @Override public int connectSSHAgent() throws Exception { throw unsupportedPlatformService(); }
    private static UnsupportedOperationException unsupportedPlatformService() { return new UnsupportedOperationException("Router VPN does not expose shell, SSH, neighbor or platform-bridge services"); }

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

    private static boolean safeToken(String value) { return value != null && value.matches("[A-Za-z0-9._-]{1,96}") && !value.equals(".") && !value.equals("..") && !value.contains(".."); }

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
