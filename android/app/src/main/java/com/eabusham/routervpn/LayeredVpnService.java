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
public final class LayeredVpnService extends VpnService implements PlatformInterface, CommandServerHandler, AndroidStartLayerRelay.SocketProtector {
    static final String ACTION_START = "com.eabusham.routervpn.LAYERED_START";
    static final String ACTION_STOP = "com.eabusham.routervpn.LAYERED_STOP";
    static final String EXTRA_SESSION_ID = "session_id";
    static final String EXTRA_HOME_SESSION_ID = "external_home_session_id";
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
    private volatile AndroidTorSession torSession;
    private volatile AndroidExternalSession externalSession;
    private volatile boolean externalOwner;
    private volatile AndroidHomeStateStore.Snapshot externalHomeOwner;
    private volatile Network externalPhysicalNetwork;
    private volatile AndroidMAXProfilePreparation.Adopted maxSession;
    private volatile boolean torOwner;
    private volatile Network torPhysicalNetwork;
    private final java.util.concurrent.atomic.AtomicLong lifecycle = new java.util.concurrent.atomic.AtomicLong();
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
    static String torProofJSON(String sessionID, String externalID) throws Exception {
        LayeredVpnService service = currentService.get();
        AndroidTorSession captured = service == null ? null : service.torSession;
        if (captured == null || !"UP".equals(service.state) || service.explicitStop) throw new IllegalStateException("The captured Tor VPN proof is unavailable.");
        return captured.result(sessionID, externalID);
    }
    static String torExitIP(String sessionID, String externalID) throws Exception {
        return new JSONObject(torProofJSON(sessionID, externalID)).getString("ip");
    }
    static String externalExitIP(String sessionID, String externalID) throws Exception {
        LayeredVpnService service = currentService.get();
        AndroidExternalSession captured = service == null ? null : service.externalSession;
        if (captured == null || !"UP".equals(service.state) || service.explicitStop) throw new IllegalStateException("The captured external VPN proof is unavailable.");
        return new JSONObject(captured.result(sessionID, externalID)).getString("ip");
    }
    private void cancelMultihopComparison(){AndroidMAXProfilePreparation.Adopted max=maxSession;if(max!=null)max.cancel();AndroidTorSession tor=torSession;if(tor!=null)tor.cancel();AndroidExternalSession external=externalSession;if(external!=null)external.cancel();AndroidMTUSession mtu=mtuSession;if(mtu!=null)mtu.networkChanged();CommandServer owned=commandServer;if(owned!=null)Libbox.routerInvalidatePerformance(owned);io.nekohasekai.libbox.RouterHopMeasurement probe=hopMeasurement;if(probe!=null)probe.networkChanged();io.nekohasekai.libbox.RouterMultihop plan=executionController;if(plan!=null)plan.networkChanged();}
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
        io.nekohasekai.libbox.RouterMultihop plan=executionController;AndroidTorSession tor=torSession;AndroidExternalSession external=externalSession;AndroidMAXProfilePreparation.Adopted max=maxSession;if(plan==null&&hopMeasurement==null&&tor==null&&external==null&&max==null)return;
        if(max!=null&&!max.current(false)||!executionNetwork.equals(executionNetworkIdentity())||(executionProved&&plan!=null&&!plan.healthy())||(executionProved&&tor!=null&&!tor.healthy())||(executionProved&&external!=null&&!external.healthy())){
            if(external!=null)AndroidHomeStateStore.failedPolicyExternal(LayeredVpnService.this,externalHomeOwner,"The captured external exit, entry, DNS or network changed; reconnect to prove the path.",false);
            cancelMultihopComparison();executor.execute(()->{if(tor!=null&&torSession!=tor||external!=null&&externalSession!=external||max!=null&&maxSession!=max)return;shutdown("FAILED",max!=null?"The captured MAX source or physical network changed; reconnect to prove the path.":tor!=null?"The captured Tor network or circuit changed; reconnect to prove the path.":external!=null?"The captured external exit, entry, DNS or network changed; reconnect to prove the path.":"Multihop network or server lease changed; reconnect to compare again.");});return;
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
            lifecycle.incrementAndGet();
            explicitStop = true;
            AndroidMAXProfilePreparation.cancelActive();
            cancelMultihopComparison();
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
        final String maxOwner = intent.getStringExtra(AndroidMAXProfilePreparation.EXTRA_OWNER);
        final String homeSession = intent.getStringExtra(EXTRA_HOME_SESSION_ID);
        final long generation = lifecycle.incrementAndGet();
        explicitStop = false;
        executor.execute(() -> startLayered(sessionId, modeId, generation, maxOwner, homeSession));
        return Service.START_NOT_STICKY;
    }

    private void startLayered(String sessionId, String modeId, long generation, String maxOwner, String homeSession) {
        synchronized (lock) {
            if (generation != lifecycle.get() || explicitStop || "STARTING".equals(state) || "UP".equals(state) || torOwner || externalOwner) {
                AndroidMAXProfilePreparation.discardPrepared(sessionId,maxOwner);
                discardPreparedSession(this,sessionId);
                return;
            }
            publish("STARTING", modeId, "");
        }
        AndroidMAXProfilePreparation.Adopted preparedMAX = null;
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
            File torFile = new File(session, AndroidTorProfile.SESSION_FILE).getCanonicalFile();
            JSONObject torMetadata = null;
            if (torFile.exists()) {
                if (!torFile.isFile() || !torFile.getParentFile().equals(session)) throw new IllegalStateException("Tor metadata has no private session owner.");
                torMetadata = AndroidTorProfile.session(config, AndroidTorProfile.strictText(readLimited(torFile, AndroidTorProfile.MAX_METADATA)), sessionId, modeId);
            } else if ("standard-tor".equals(modeId) || "standard-tor-bridge".equals(modeId)
                    || "standard-direct-tor".equals(modeId) || "standard-direct-tor-bridge".equals(modeId)) {
                throw new IllegalStateException("The requested Tor VPN has no captured proof metadata.");
            }
            File externalFile = new File(session, AndroidExternalPolicy.SESSION_FILE).getCanonicalFile();
            JSONObject externalMetadata = null;
            AndroidHomeStateStore.Snapshot externalHome = null;
            String externalProtocol = modeId.startsWith("standard-direct-") ? modeId.substring("standard-direct-".length())
                    : modeId.startsWith("standard-") ? modeId.substring("standard-".length()) : "";
            if (externalFile.exists()) {
                if (torMetadata != null || !externalFile.isFile() || !externalFile.getParentFile().equals(session)) throw new IllegalStateException("External policy has no exclusive private session owner.");
                externalMetadata = AndroidExternalPolicy.session(config, AndroidTorProfile.strictText(readLimited(externalFile, AndroidExternalPolicy.MAX_METADATA)), sessionId, modeId);
                externalHome = captureExternalHome(externalMetadata, homeSession);
            } else if (AndroidExternalPolicy.supports(externalProtocol)) {
                throw new IllegalStateException("The ordinary external VPN has no captured policy and proof metadata.");
            }
            preparedMAX = AndroidMAXProfilePreparation.claim(this, session, sessionId, modeId, config, maxOwner);

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
            if (torMetadata != null) {
                File noBackup = getNoBackupFilesDir().getCanonicalFile();
                if (!noBackup.isDirectory() && !noBackup.mkdirs()) throw new IllegalStateException("Cannot create private Tor state storage.");
                Libbox.routerTorSetStateDirectory(new File(noBackup, "routervpn-tor").getAbsolutePath());
            }
            // The immutable factory owns no peer or network. Each compiled PQ
            // endpoint creates its own protocol under this service's VPN owner.
            RouterPQNative.install();
            io.nekohasekai.libbox.RouterMultihop preparedExecution=null;
            String hopMetadata=null;
            File executionFile=new File(session,"routervpn-multihop.json").getCanonicalFile();
            File entryLayerFile=new File(session,AndroidMultihopStartLayer.SESSION_FILE).getCanonicalFile();
            File exitLayerFile=new File(session,AndroidMultihopStartLayer.EXIT_SESSION_FILE).getCanonicalFile();
            if(exitLayerFile.exists()&&(!executionFile.isFile()||!exitLayerFile.getParentFile().equals(session)))throw new IllegalStateException("Exit Start Layer has no owned multihop session.");
            if (entryLayerFile.exists() && (!executionFile.isFile() || !entryLayerFile.getParentFile().equals(session))) {
                throw new IllegalStateException("Entry Start Layer has no owned multihop session.");
            }
            if(executionFile.isFile()){
                if (torMetadata != null || externalMetadata != null) throw new IllegalStateException("A captured external path cannot adopt a second multihop execution owner.");
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
                String capturedExit=null;
                if(exitLayerFile.exists()){
                    if(!exitLayerFile.isFile())throw new IllegalStateException("Captured exit layer is not a private file.");
                    byte[] raw=readLimited(exitLayerFile,AndroidMultihopStartLayer.MAX_BYTES);
                    capturedExit=java.nio.charset.StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                        .decode(java.nio.ByteBuffer.wrap(raw)).toString();
                }
                preparedExecution=AndroidMultihopStartLayer.prepareExecution(config,metadata,captured,capturedExit);
                if(preparedExecution!=null)config=preparedExecution.config();
            }
            String capturedMTU="";
            File mtuFile=new File(session,"routervpn-mtu.json").getCanonicalFile();
            if(mtuFile.isFile()){
                if(!mtuFile.getParentFile().equals(session))throw new IllegalStateException("Unowned MTU profile file.");
                capturedMTU=new String(readLimited(mtuFile,256*1024),java.nio.charset.StandardCharsets.UTF_8);
            }
            Libbox.checkConfig(config);
            String torNetwork = torMetadata == null ? "" : executionNetworkIdentity();
            if (torMetadata != null && (torNetwork.isEmpty() || "[]".equals(torNetwork))) throw new IllegalStateException("Tor requires the captured underlying network before startup.");
            Network torPhysical = torMetadata == null ? null : connectivity.getActiveNetwork();
            if (torMetadata != null && (torPhysical == null || connectivity.getNetworkCapabilities(torPhysical) == null
                    || connectivity.getNetworkCapabilities(torPhysical).hasTransport(NetworkCapabilities.TRANSPORT_VPN))) throw new IllegalStateException("Tor requires an owned physical network before the VPN starts.");
            String externalNetwork = externalMetadata == null ? "" : executionNetworkIdentity();
            Network externalPhysical = externalMetadata == null ? null : connectivity.getActiveNetwork();
            if (externalMetadata != null && (externalNetwork.isEmpty() || "[]".equals(externalNetwork) || externalPhysical == null
                    || connectivity.getNetworkCapabilities(externalPhysical) == null
                    || connectivity.getNetworkCapabilities(externalPhysical).hasTransport(NetworkCapabilities.TRANSPORT_VPN))) throw new IllegalStateException("External VPN requires its captured physical network before startup.");
            if (preparedMAX != null && (!preparedMAX.current(true)
                    || torPhysical != null && !preparedMAX.physical.network.equals(torPhysical)
                    || externalPhysical != null && !preparedMAX.physical.network.equals(externalPhysical))) throw new IllegalStateException("Complete MAX lost its captured physical network before native startup.");

            synchronized (lock) {
                if (generation != lifecycle.get() || explicitStop) throw new IllegalStateException("VPN launch was cancelled before native startup.");
                closeCoreLocked();
                if (preparedMAX != null && !preparedMAX.current(true)) throw new IllegalStateException("Complete MAX source changed before native startup.");
                maxSession = preparedMAX;
                activeSession = session;
                activeMode = modeId;
                activeConfig = config;
                mtuMetadata=capturedMTU;
                mtuSession=new AndroidMTUSession(this,owner->executor.execute(()->{
                    if(mtuSession==owner)shutdown("FAILED","MTU transaction could not retain the verified VPN interface.");
                }));
                executionController=preparedExecution;executionProved=false;
                torPhysicalNetwork = torPhysical;
                externalPhysicalNetwork = externalPhysical;
                externalOwner = externalMetadata != null;
                externalHomeOwner = externalHome;
                if(externalHome!=null&&!AndroidHomeStateStore.ownsPolicyExternal(this,externalHome))throw new IllegalStateException("External Home owner changed before native startup.");
                if(torMetadata!=null)executionNetwork=torNetwork;
                else if(externalMetadata!=null)executionNetwork=externalNetwork;
                else if(preparedMAX!=null)executionNetwork=executionNetworkIdentity();
                torOwner = torMetadata != null;
                startLayerRelay = AndroidStartLayerRelay.prepareIfConfigured(this, session, message -> executor.execute(() -> {
                    if (!explicitStop && activeSession == session) shutdown("FAILED", message);
                }));
                if(startLayerRelay!=null)startLayerRelay.start();
                commandServer = new CommandServer(this, this);
                commandServer.start();
                commandServer.startOrReloadService(config, new OverrideOptions());
                if (tunDescriptor == null || tunDescriptor.getFileDescriptor() == null || !tunDescriptor.getFileDescriptor().valid()) {
                    throw new IllegalStateException("sing-box started without establishing an Android VPN TUN.");
                }
            }
            io.nekohasekai.libbox.RouterMultihop ownedExecution=executionController;
            CommandServer ownedServer=commandServer;
            if (preparedMAX != null) executionHandler.post(executionWatch);
            if (torMetadata != null) {
                final CommandServer capturedServer = ownedServer;
                final AndroidTorSession capturedTor = new AndroidTorSession(torMetadata, capturedServer, new AndroidTorSession.Owner() {
                    @Override public boolean current(AndroidTorSession candidate, CommandServer nativeServer) {
                        return torSession == candidate && commandServer == nativeServer && generation == lifecycle.get() && !explicitStop
                                && activeSession != null && sessionId.equals(activeSession.getName());
                    }
                    @Override public String network() { return executionNetworkIdentity(); }
                });
                synchronized (lock) {
                    torSession = capturedTor;
                    if (generation != lifecycle.get() || explicitStop || !torNetwork.equals(executionNetworkIdentity())) { capturedTor.cancel(); throw new IllegalStateException("Tor VPN launch was cancelled or its captured network changed."); }
                }
                executionNetwork = torNetwork;
                executionHandler.post(executionWatch);
                updateForeground("Proving Tor circuit and selected DNS…");
                capturedTor.prove();
            }
            if (externalMetadata != null) {
                final AndroidExternalSession capturedExternal = new AndroidExternalSession(externalMetadata, ownedServer, new AndroidExternalSession.Owner() {
                    @Override public boolean current(AndroidExternalSession candidate, CommandServer nativeServer) {
                        return externalSession == candidate && commandServer == nativeServer && generation == lifecycle.get() && !explicitStop
                                && activeSession != null && sessionId.equals(activeSession.getName())
                                && AndroidHomeStateStore.ownsPolicyExternal(LayeredVpnService.this,externalHomeOwner);
                    }
                    @Override public String network() { return executionNetworkIdentity(); }
                });
                synchronized (lock) {
                    externalSession = capturedExternal;
                    if (generation != lifecycle.get() || explicitStop || !externalNetwork.equals(executionNetworkIdentity())) {
                        capturedExternal.cancel(); throw new IllegalStateException("External launch was cancelled or its captured network changed.");
                    }
                }
                executionNetwork = externalNetwork;
                executionHandler.post(executionWatch);
                updateForeground("Proving captured entry, selected DNS and public exit…");
                capturedExternal.prove();
            }
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
                if(explicitStop||generation!=lifecycle.get()||commandServer!=ownedServer||executionController!=ownedExecution
                        ||torSession!=null&&!torSession.healthy()||externalSession!=null&&!externalSession.healthy()||maxSession!=null&&!maxSession.current(true))throw new IllegalStateException("VPN ownership changed during path proof.");
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
            if (preparedMAX != null && maxSession != preparedMAX) preparedMAX.cancel();
            AndroidMAXProfilePreparation.discardPrepared(sessionId,maxOwner);
            // This requested directory is retained only after actual runtime
            // adoption. Lockdown, permission and network failures happen earlier.
            discardPreparedSession(this,sessionId);
        }
    }

    static boolean discardPreparedSession(android.content.Context context, String sessionId) {
        if(!safeToken(sessionId))return false;
        LayeredVpnService service=currentService.get();
        synchronized(service==null?LayeredVpnService.class:service.lock){
            try{
                File root=new File(context.getFilesDir(),"layered-sessions").getCanonicalFile();
                File folder=new File(root,sessionId).getCanonicalFile();
                if(!folder.getParentFile().equals(root))return false;
                if(service!=null&&service.activeSession!=null&&folder.equals(service.activeSession.getCanonicalFile()))return false;
                removePreparedTree(folder);
                return !folder.exists();
            }catch(Exception cleanup){return false;}
        }
    }

    private static void removePreparedTree(File file) {
        if(!java.nio.file.Files.isSymbolicLink(file.toPath())){
            File[] children=file.listFiles();
            if(children!=null)for(File child:children)removePreparedTree(child);
        }
        file.delete();
    }

    private AndroidHomeStateStore.Snapshot captureExternalHome(JSONObject metadata, String homeSession) throws Exception {
        AndroidHomeStateStore.Snapshot home = AndroidHomeStateStore.snapshot(this);
        JSONObject capture = new JSONObject(metadata.getString("capture_json"));
        boolean entry = capture.optString("entry_tag", "").length() != 0;
        if (homeSession == null || homeSession.isEmpty() || !homeSession.equals(home.sessionId)
                || !metadata.getString("external_id").equals(home.activeExternalId)
                || !metadata.getString("protocol").equals(home.activeExternalProtocol)
                || !capture.getString("expected_public_ip").equals(home.expectedExternalIp)
                || entry != !home.activeEntryId.isEmpty()
                || entry && !metadata.getString("entry_mode").equals(home.activeEntryMode)
                || !"connecting".equals(home.phase) || !"pending".equals(home.pathProof)
                || !AndroidHomeStateStore.ownsPolicyExternal(this,home)) throw new IllegalStateException("External launch does not own the captured Home selection.");
        return home;
    }

    @Override public void onRevoke() {
        lifecycle.incrementAndGet();
        AndroidMAXProfilePreparation.cancelActive();
        cancelMultihopComparison();
        explicitStop = false;
        executor.execute(() -> shutdown("REVOKED", "Android revoked VPN permission."));
        super.onRevoke();
    }

    @Override public void onDestroy() {
        lifecycle.incrementAndGet();
        AndroidMAXProfilePreparation.cancelActive();
        cancelMultihopComparison();
        String terminal = state;
        String mode = activeMode;
        File session;
        AndroidHomeStateStore.Snapshot home = externalHomeOwner;
        AndroidHomeStateStore.failedPolicyExternal(this,home,"The captured external VPN service stopped; its path proof is no longer valid.",false);
        synchronized (lock) {
            session = activeSession;
            try { closeCoreLocked(); }
            catch (RuntimeException pending) {
                publish("STOPPING", mode, "VPN teardown remains unconfirmed; runtime ownership is retained.");
                executor.shutdown();
                super.onDestroy();
                return;
            }
            activeSession = null;
            activeConfig = "";
        }
        if(currentService.get()==this)currentService.clear();
        AndroidHomeStateStore.failedPolicyExternal(this,home,"The captured external VPN service stopped; reconnect to prove the path.",true);
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
        AndroidHomeStateStore.Snapshot home;
        synchronized (lock) {
            if (!"DOWN".equals(terminalState) && !"FAILED".equals(terminalState) && !"REVOKED".equals(terminalState)) terminalState = "FAILED";
            if ("DOWN".equals(terminalState)) publish("STOPPING", activeMode, "");
            mode = activeMode;
            session = activeSession;
            home = externalHomeOwner;
            AndroidHomeStateStore.failedPolicyExternal(this,home,error.isEmpty()?"The captured external VPN is stopping; its path proof is no longer valid.":error,false);
            closeCoreLocked();
            activeSession = null;
            activeMode = "";
            activeConfig = "";
            publish(terminalState, "DOWN".equals(terminalState) ? "" : mode, error);
            AndroidHomeStateStore.failedPolicyExternal(this,home,error.isEmpty()?"The captured external VPN stopped.":error,true);
        }
        if (session != null) deleteTree(session);
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    private void closeCoreLocked() {
        AndroidMAXProfilePreparation.Adopted capturedMAX = maxSession;
        if (capturedMAX != null) capturedMAX.cancel();
        AndroidTorSession capturedTor = torSession;
        if(capturedTor!=null)capturedTor.cancel();
        AndroidExternalSession capturedExternal = externalSession;
        if(capturedExternal!=null)capturedExternal.cancel();
        if(startLayerRelay!=null){
            try{startLayerRelay.close();}
            catch(RuntimeException pending){
                publish("STOPPING",activeMode,"Start Layer teardown remains unconfirmed; runtime ownership is retained.");
                throw new IllegalStateException("Start Layer teardown has not completed.");
            }
        }
        if (torOwner || externalOwner || capturedMAX != null) {
            try {
                // Checked native close keeps the Box owned on timeout. A stop
                // acknowledgment and a new graph must wait for its real drain.
                if (commandServer != null) {
                    Libbox.routerStrategyCloseService(commandServer);
                    commandServer.close();
                }
            } catch (Throwable pending) {
                publish("STOPPING", activeMode, "Native captured-path teardown remains unconfirmed; runtime ownership is retained.");
                throw new IllegalStateException("Native captured-path teardown has not completed.");
            }
            commandServer = null;
            torSession = null;
            torOwner = false;
            torPhysicalNetwork = null;
            externalSession = null;
            externalOwner = false;
            externalPhysicalNetwork = null;
            externalHomeOwner = null;
            maxSession = null;
        }
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
        startLayerRelay = null;
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
        AndroidMAXProfilePreparation.Adopted max = maxSession;
        if (max != null) {
            requireMAXNetwork(max);
            try (ParcelFileDescriptor borrowed = ParcelFileDescriptor.fromFd(fd)) { max.physical.network.bindSocket(borrowed.getFileDescriptor()); }
            requireMAXNetwork(max);
        } else if(torOwner){
            Network captured=torPhysicalNetwork;requireTorNetwork(captured);
            // fromFd duplicates the borrowed descriptor. Closing this wrapper
            // cannot close the sole native socket; binding applies to both FDs.
            try(ParcelFileDescriptor borrowed=ParcelFileDescriptor.fromFd(fd)){captured.bindSocket(borrowed.getFileDescriptor());}
            requireTorNetwork(captured);
        } else if(externalOwner){
            Network capturedExternal=externalPhysicalNetwork;requireExternalNetwork(capturedExternal);
            try(ParcelFileDescriptor borrowed=ParcelFileDescriptor.fromFd(fd)){capturedExternal.bindSocket(borrowed.getFileDescriptor());}
            requireExternalNetwork(capturedExternal);
        }
    }

    @Override public void protectRelaySocket(java.net.Socket socket)throws Exception{
        if(!protect(socket))throw new IllegalStateException("Android refused the protected entry socket.");
        AndroidMAXProfilePreparation.Adopted max=maxSession;
        if(max!=null){requireMAXNetwork(max);max.physical.network.bindSocket(socket);requireMAXNetwork(max);}
        else if(torOwner){Network captured=torPhysicalNetwork;requireTorNetwork(captured);captured.bindSocket(socket);requireTorNetwork(captured);}
        else if(externalOwner){Network captured=externalPhysicalNetwork;requireExternalNetwork(captured);captured.bindSocket(socket);requireExternalNetwork(captured);}
    }
    @Override public void protectRelaySocket(java.net.DatagramSocket socket)throws Exception{
        if(!protect(socket))throw new IllegalStateException("Android refused the protected entry socket.");
        AndroidMAXProfilePreparation.Adopted max=maxSession;
        if(max!=null){requireMAXNetwork(max);max.physical.network.bindSocket(socket);requireMAXNetwork(max);}
        else if(torOwner){Network captured=torPhysicalNetwork;requireTorNetwork(captured);captured.bindSocket(socket);requireTorNetwork(captured);}
        else if(externalOwner){Network captured=externalPhysicalNetwork;requireExternalNetwork(captured);captured.bindSocket(socket);requireExternalNetwork(captured);}
    }
    private void requireMAXNetwork(AndroidMAXProfilePreparation.Adopted captured) {
        if (explicitStop || captured != maxSession || !captured.current(false)) throw new IllegalStateException("The captured MAX physical network changed; reconnect before opening traffic.");
        if (torOwner) requireTorNetwork(torPhysicalNetwork);
        if (externalOwner) requireExternalNetwork(externalPhysicalNetwork);
    }
    private void requireTorNetwork(Network captured){
        NetworkCapabilities caps=captured==null?null:connectivity.getNetworkCapabilities(captured);
        if(explicitStop||!torOwner||captured!=torPhysicalNetwork||caps==null||caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                ||!executionNetwork.equals(executionNetworkIdentity()))throw new IllegalStateException("The captured Tor physical network changed; reconnect before opening traffic.");
    }
    private void requireExternalNetwork(Network captured){
        NetworkCapabilities caps=captured==null?null:connectivity.getNetworkCapabilities(captured);
        if(explicitStop||!externalOwner||captured!=externalPhysicalNetwork||caps==null||caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                ||!executionNetwork.equals(executionNetworkIdentity()))throw new IllegalStateException("The captured external physical network changed; reconnect before opening traffic.");
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
        AndroidTorSession tor=torSession;
        if(tor!=null&&!executionNetwork.equals(executionNetworkIdentity())){
            tor.cancel();executor.execute(()->{if(torSession==tor)shutdown("FAILED","The captured Tor network changed; reconnect to prove the path.");});return;
        }
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
                if(torOwner||executionController!=null||hopMeasurement!=null||mtuSession!=null){cancelMultihopComparison();shutdown("FAILED","Native reload needs fresh path and MTU ownership.");return;}
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
