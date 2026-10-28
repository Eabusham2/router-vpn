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
    static final String EXTRA_TOR_COMPARISON = "tor_comparison_session_id";
    static final String EXTRA_MODE_ID = "mode_id";

    private static final String TAG = "RouterVPN-Libbox";
    private static final String CHANNEL = "routervpn-layered";
    private static final int NOTIFICATION_ID = 7107;
    private static final int MAX_CONFIG = 4 * 1024 * 1024;
    private static final String PREFS = "router-vpn";
    private static final String STATE_KEY = "layered_state_v1";
    private static final String MODE_KEY = "layered_mode_v1";
    private static final String ERROR_KEY = "layered_error_v1";

    /** Null means the app has no live service from which to read the OS setting. */
    static Boolean currentLockdownState() {
        LayeredVpnService service = currentService.get();
        return service == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.Q ? null : service.isLockdownEnabled();
    }

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Object lock = new Object();
    private final Object tunAccess = new Object();
    private volatile AndroidMTUSession mtuSession;
    private String mtuMetadata = "";
    static void startAutomaticMTU(){
        LayeredVpnService service=currentService.get();if(service==null)return;
        service.scheduleAutomaticMTU(service.externalSession,service.torSession);
    }
    /** The completed graph owns this activation; a delayed caller cannot
     * select a replacement service or its TUN through the global reference. */
    static void startMultihopAutomaticMTU(CapturedMultihop owner)throws Exception{
        if(owner==null)throw new IllegalStateException("The proved multihop MTU owner is missing.");
        LayeredVpnService service=owner.service;
        final AndroidMTUSession captured;final String metadata;
        synchronized(service.lock){
            if(!owner.sameOwner(capturedMultihop(service,owner.homeSession)))throw new IllegalStateException("The multihop owner changed before MTU activation.");
            captured=owner.mtu;metadata=owner.mtuMetadata;
            if(captured==null||metadata==null||metadata.isEmpty())return;
            service.executor.execute(()->{
                synchronized(service.lock){
                    try{
                        if(service.mtuSession!=captured||!metadata.equals(service.mtuMetadata)
                                ||!owner.sameOwner(capturedMultihop(service,owner.homeSession)))return;
                    }catch(Exception retired){return;}
                }
                // The service executor serializes native setup/teardown. Even
                // a late stop retains these exact old objects; no replacement
                // core, configuration or MTU session is read after the check.
                captured.activate(owner.server,owner.config,metadata);
            });
        }
    }
    static void startExternalAutomaticMTU(String session,String external,String home){
        LayeredVpnService service=currentService.get();if(service==null)return;
        synchronized(service.lock){
            AndroidExternalSession owned=service.externalSession;
            AndroidHomeStateStore.Snapshot capturedHome=service.externalHomeOwner;
            if(owned==null||capturedHome==null||!owned.sessionID.equals(session)||!owned.externalID.equals(external)
                    ||!capturedHome.sessionId.equals(home))return;
            service.scheduleAutomaticMTU(owned,null);
        }
    }
    static void startTorAutomaticMTU(String session,String external,String home){
        LayeredVpnService service=currentService.get();if(service==null)return;
        synchronized(service.lock){
            AndroidTorSession owned=service.torSession;
            AndroidHomeStateStore.Snapshot captured=AndroidHomeStateStore.snapshot(service);
            if(owned==null||!owned.sessionID.equals(session)||!owned.externalID.equals(external)
                    ||!captured.sessionId.equals(home)||!captured.activeExternalId.equals(external)
                    ||!AndroidTorProfile.isTor(captured.activeExternalProtocol)||!captured.connected
                    ||!"passed".equals(captured.pathProof)||AndroidHomeStateStore.emergencyDisconnectPending(service))return;
            service.torHomeOwner=captured;
            service.scheduleAutomaticMTU(null,owned);
        }
    }
    private boolean ownsTorMTUHome(){
        AndroidHomeStateStore.Snapshot home=torHomeOwner,now=AndroidHomeStateStore.snapshot(this);
        return home!=null&&now.connected&&"passed".equals(now.pathProof)&&!AndroidHomeStateStore.emergencyDisconnectPending(this)
                &&home.sessionId.equals(now.sessionId)&&home.pathGeneration==now.pathGeneration
                &&home.activeExternalId.equals(now.activeExternalId)&&home.activeExternalProtocol.equals(now.activeExternalProtocol)
                &&home.activeEntryId.equals(now.activeEntryId)&&home.activeEntryMode.equals(now.activeEntryMode);
    }
    private void scheduleAutomaticMTU(AndroidExternalSession external,AndroidTorSession tor){
        LayeredVpnService service=this;
        CommandServer core=commandServer;AndroidMTUSession captured=mtuSession;
        long generation=lifecycle.get();
        service.executor.execute(()->{
            if(core==null||captured==null||service.commandServer!=core||service.mtuSession!=captured
                    ||generation!=service.lifecycle.get()||service.explicitStop||!"UP".equals(service.state))return;
            if(external!=null){
                AndroidHomeStateStore.Snapshot home=service.externalHomeOwner;
                AndroidHomeStateStore.Snapshot now=AndroidHomeStateStore.snapshot(service);
                if(service.externalSession!=external||home==null||!now.connected||!"passed".equals(now.pathProof)||!external.healthy()
                        ||!AndroidHomeStateStore.ownsPolicyExternal(service,home))return;
                captured.activateExternal(external);
            }else if(tor!=null){
                if(service.torSession!=tor||!tor.healthy()||!service.ownsTorMTUHome())return;
                captured.activateTor(tor);
            }else if(service.externalSession==null&&service.torSession==null&&!service.mtuMetadata.isEmpty())captured.activate(core,service.activeConfig,service.mtuMetadata);
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
    static AndroidTelemetryNetwork captureTelemetryNetwork() throws Exception {
        LayeredVpnService service=currentService.get();
        if(service==null)throw new IllegalStateException("The native VPN service is not retained.");
        CommandServer core=service.commandServer;AndroidMTUSession tun=service.mtuSession;long generation=service.lifecycle.get();
        if(core==null||tun==null||service.explicitStop||!"UP".equals(service.state))throw new IllegalStateException("The native VPN has no proved running TUN owner.");
        return tun.captureTelemetryNetwork().retaining(()->{
            if(currentService.get()!=service||core!=service.commandServer||tun!=service.mtuSession||generation!=service.lifecycle.get()||service.explicitStop||!"UP".equals(service.state))
                throw new IllegalStateException("The captured native VPN service was stopped or replaced.");
        });
    }
    static String mtuRequest(String operation,String session,String request)throws Exception{
        LayeredVpnService service=currentService.get();if(service==null)throw new IllegalStateException("No live Router VPN session.");
        synchronized(service.lock){
            AndroidMTUSession owned=service.mtuSession;
            if(owned==null||!"UP".equals(service.state)||service.explicitStop)throw new IllegalStateException("Connect a proved Router VPN path first.");
            if("start".equals(operation)&&service.hopMeasurement!=null){
                JSONObject progress=new JSONObject(service.hopMeasurement.statusJSON());
                if(!progress.optBoolean("drained",false)&&!progress.optString("request_id","").isEmpty())throw new IllegalStateException("Finish hop measurement and its native cleanup before MTU Retest.");
            }
            if("start".equals(operation)&&service.dnsMeasurement!=null){
                JSONObject progress=new JSONObject(service.dnsMeasurement.statusJSON());
                if(!progress.optBoolean("drained",false)&&!progress.optString("request_id","").isEmpty())throw new IllegalStateException("Finish DNS comparison and its native cleanup before MTU Retest.");
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
    private volatile io.nekohasekai.libbox.RouterDNSMeasurement dnsMeasurement;
    private volatile AndroidTorSession torSession;
    private volatile TorCompareTrial torCompareTrial;
    private static final Object TOR_COMPARE_LOCK = new Object();
    private static TorCompareTrial reservedTorCompare;
    interface TorCompareCurrent { boolean current(); }

    /** One candidate keeps its exact service/start generation through native
     * shutdown. A late start intent cannot borrow a newer comparison owner. */
    static final class TorCompareTrial {
        final NativeSingBoxController.SessionInfo prepared;
        final String externalID, execution;
        final AndroidMAXDNSOwner.Physical physical;
        final TorCompareCurrent owner;
        private volatile LayeredVpnService service;
        private volatile long generation;
        private volatile boolean submitted, seen, finished, cancelled, closed, kept, stopping;
        private volatile String failure = "";
        private volatile RuntimeException stopFailure;
        private volatile CommandServer provedServer;
        private volatile AndroidTorSession provedTor;
        private final Object closeLock = new Object();
        private final java.util.concurrent.CountDownLatch stopped = new java.util.concurrent.CountDownLatch(1);

        private TorCompareTrial(NativeSingBoxController.SessionInfo prepared, String externalID, String execution,
                                AndroidMAXDNSOwner.Physical physical, TorCompareCurrent owner) {
            this.prepared=prepared;this.externalID=externalID;this.execution=execution;this.physical=physical;this.owner=owner;
        }
        static TorCompareTrial reserve(NativeSingBoxController.SessionInfo prepared, String externalID, String execution,
                                       AndroidMAXDNSOwner.Physical physical, TorCompareCurrent owner) {
            if(prepared==null||externalID==null||externalID.isEmpty()||!java.util.Arrays.asList("local","server").contains(execution)
                    ||physical==null||owner==null||!owner.current())throw new IllegalStateException("Tor comparison lost its captured candidate.");
            synchronized(TOR_COMPARE_LOCK){
                if(reservedTorCompare!=null&&!reservedTorCompare.closed)throw new IllegalStateException("The preceding Tor candidate has not drained.");
                TorCompareTrial result=new TorCompareTrial(prepared,externalID,execution,physical,owner);
                reservedTorCompare=result;return result;
            }
        }
        void submit() {
            synchronized(this){if(cancelled||closed||submitted||!owner.current())throw new IllegalStateException("Tor comparison launch was cancelled.");submitted=true;}
        }
        private boolean bind(LayeredVpnService value){
            synchronized(this){
                if(seen||closed||cancelled||!submitted||!owner.current())return false;
                // A delayed private Intent must not revoke another native
                // owner before the executor gets a chance to reject it.
                if(value.executor.isShutdown()||value.torCompareTrial!=null||value.commandServer!=null||value.activeSession!=null
                        ||value.torOwner||value.externalOwner||"STARTING".equals(value.state)
                        ||"UP".equals(value.state)||"STOPPING".equals(value.state)) {
                    failure="Another native owner replaced the Tor comparison candidate.";
                    cancelled=true;return false;
                }
                service=value;generation=value.lifecycle.incrementAndGet();seen=true;
                value.explicitStop=false;value.torCompareTrial=this;return true;
            }
        }
        private void finished(boolean success,String reason){
            if(success){
                LayeredVpnService captured=service;AndroidTorSession tor=captured==null?null:captured.torSession;
                if(captured==null||tor==null||!prepared.sessionId.equals(tor.sessionID)||!externalID.equals(tor.externalID))reason="Tor comparison did not retain its native proof.";
                else{provedServer=captured.commandServer;provedTor=tor;}
            }
            if(reason!=null&&!reason.isEmpty())failure=reason;
            finished=true;
        }
        String failure(){return failure.isEmpty()&&closed&&!kept?"The Tor candidate has already stopped.":failure;}
        boolean current(){
            AndroidTorSession captured=provedTor;
            return captured!=null&&retainedCurrent()&&captured.comparisonCurrent()&&captured==provedTor&&retainedCurrent();
        }
        private boolean retainedCurrent(){
            LayeredVpnService captured=service;AndroidTorSession tor=provedTor;CommandServer server=provedServer;
            return !cancelled&&!closed&&owner.current()&&captured!=null&&currentService.get()==captured&&tor!=null&&server!=null&&finished
                    &&generation==captured.lifecycle.get()&&!captured.explicitStop&&"UP".equals(captured.state)
                    &&(kept||captured.torCompareTrial==this)&&captured.commandServer==server&&captured.torSession==tor
                    &&captured.activeSession!=null&&prepared.sessionId.equals(captured.activeSession.getName())
                    &&physical.network.equals(captured.torPhysicalNetwork);
        }
        CommandServer server(){return current()?provedServer:null;}
        io.nekohasekai.libbox.RouterTorProofRequest proof(){
            if(!current())return null;try{return provedTor.comparisonProof();}catch(Exception changed){return null;}
        }
        void cancel(){
            synchronized(this){if(kept)return;cancelled=true;}
            LayeredVpnService captured=service;
            if(captured!=null&&captured.torCompareTrial==this){
                captured.lifecycle.compareAndSet(generation,generation+1);
                captured.executionProved=false;
                captured.executionHandler.removeCallbacks(captured.executionWatch);
                captured.executionHandler.removeCallbacks(captured.performanceWatch);
                AndroidTorSession tor=captured.torSession;
                if(tor!=null&&prepared.sessionId.equals(tor.sessionID))tor.cancel();
                AndroidMAXProfilePreparation.Adopted max=captured.maxSession;
                if(max!=null&&captured.activeSession!=null&&prepared.sessionId.equals(captured.activeSession.getName()))max.cancel();
            }
        }
        private void requestStop(){
            final LayeredVpnService captured=service;
            synchronized(this){if(closed||kept||stopping||stopFailure!=null||captured==null)return;stopping=true;}
            try{captured.executor.execute(()->{
                try{captured.closeTorCompareTrial(this,"");}
                catch(RuntimeException pending){stopFailure=pending;}
                finally{stopping=false;}
            });}catch(RuntimeException unavailable){stopFailure=unavailable;stopping=false;}
        }
        void abortUnsubmitted(){
            synchronized(this){if(submitted||seen)return;cancelled=true;finished=true;}
            completeClose();
        }
        void close() throws Exception {
            synchronized(closeLock){closeRetained();}
        }
        private void closeRetained() throws Exception {
            if(kept||closed)return;
            cancel();
            synchronized(this){
                // Revocation precedes removing the registry. Every comparison
                // Intent is explicitly marked, so a late delivery cannot enter
                // the ordinary launch path after this unseen owner is gone.
                if(!seen){finished=true;completeClose();return;}
                if(!stopping)stopFailure=null;
            }
            long deadline=System.nanoTime()+25_000_000_000L;boolean interrupted=Thread.interrupted();
            try{
                while(!closed){
                    requestStop();
                    RuntimeException pending=stopFailure;if(pending!=null)throw pending;
                    long remaining=deadline-System.nanoTime();if(remaining<=0)throw new IllegalStateException("The exact Tor candidate teardown is still pending.");
                    try{stopped.await(Math.min(remaining,100_000_000L),java.util.concurrent.TimeUnit.NANOSECONDS);}
                    catch(InterruptedException ignored){interrupted=true;}
                }
            }finally{if(interrupted)Thread.currentThread().interrupt();}
        }
        void keep() throws Exception {
            if(!retainedCurrent())throw new IllegalStateException("The proved Tor winner changed before adoption.");
            LayeredVpnService captured=service;
            synchronized(captured.lock){
                synchronized(this){
                    if(!retainedCurrent()||captured.torCompareTrial!=this)throw new IllegalStateException("The Tor winner lost its native service.");
                    kept=true;captured.torCompareTrial=null;
                }
            }
            synchronized(TOR_COMPARE_LOCK){if(reservedTorCompare==this)reservedTorCompare=null;}
        }
        private void completeClose(){
            closed=true;provedServer=null;provedTor=null;
            synchronized(TOR_COMPARE_LOCK){if(reservedTorCompare==this)reservedTorCompare=null;}
            stopped.countDown();
        }
    }
    private static final class TorCleanup {
        final AndroidTorSession tor;
        final CommandServer server;
        final AndroidMAXProfilePreparation.Adopted max;
        final Network network;
        final String networkIdentity;
        // The native Close request has the same eight-second maximum.
        final long deadline = System.nanoTime() + 8_000_000_000L;
        TorCleanup(AndroidTorSession tor, CommandServer server, AndroidMAXProfilePreparation.Adopted max,
                   Network network, String networkIdentity) {
            this.tor=tor;this.server=server;this.max=max;this.network=network;this.networkIdentity=networkIdentity;
        }
    }
    private volatile TorCleanup torCleanup;
    private volatile AndroidHomeStateStore.Snapshot torHomeOwner;
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
    private volatile String multihopMetadata;
    private volatile AndroidHomeStateStore.Snapshot multihopHomeOwner;
    static String multihopProgressJSON(){LayeredVpnService service=currentService.get();io.nekohasekai.libbox.RouterMultihop plan=service==null?null:service.executionController;return plan==null?"":plan.progressJSON();}
    /** A runtime-only receipt. Public pins remain bound to this exact proved owner. */
    static final class CapturedMultihop {
        final String homeSession, entryId, exitId, entryMode, exitMode, execution, serverIdentityPins;
        final long pathGeneration;
        private final LayeredVpnService service;
        private final CommandServer server;
        private final io.nekohasekai.libbox.RouterMultihop plan;
        private final AndroidMTUSession mtu;
        private final File session;
        private final long generation;
        private final String config, metadata, mtuMetadata;
        private CapturedMultihop(LayeredVpnService service, AndroidHomeStateStore.Snapshot home, CommandServer server,
                                 io.nekohasekai.libbox.RouterMultihop plan, File session, long generation,
                                 String config, String metadata, AndroidMTUSession mtu, String mtuMetadata, String execution, String serverIdentityPins) {
            this.service=service;this.server=server;this.plan=plan;this.session=session;this.generation=generation;
            this.config=config;this.metadata=metadata;this.execution=execution;this.serverIdentityPins=serverIdentityPins;
            this.mtu=mtu;this.mtuMetadata=mtuMetadata;
            homeSession=home.sessionId;pathGeneration=home.pathGeneration;entryId=home.activeEntryId;exitId=home.activeExitId;
            entryMode=home.activeEntryMode;exitMode=home.runtimeMode;
        }
        boolean matchesHome(AndroidHomeStateStore.Snapshot home) {
            return home!=null&&home.connected&&"connected".equals(home.phase)&&"passed".equals(home.pathProof)
                    &&"multihop".equals(home.logicalMode)&&homeSession.equals(home.sessionId)&&pathGeneration==home.pathGeneration
                    &&entryId.equals(home.activeEntryId)&&exitId.equals(home.activeExitId)
                    &&entryMode.equals(home.activeEntryMode)&&exitMode.equals(home.runtimeMode);
        }
        boolean sameOwner(CapturedMultihop other) {
            return other!=null&&service==other.service&&server==other.server&&plan==other.plan&&session==other.session&&mtu==other.mtu
                    &&generation==other.generation&&config.equals(other.config)&&metadata.equals(other.metadata)
                    &&java.util.Objects.equals(mtuMetadata,other.mtuMetadata)
                    &&homeSession.equals(other.homeSession)&&pathGeneration==other.pathGeneration
                    &&entryId.equals(other.entryId)&&exitId.equals(other.exitId)&&entryMode.equals(other.entryMode)&&exitMode.equals(other.exitMode)
                    &&execution.equals(other.execution)&&serverIdentityPins.equals(other.serverIdentityPins);
        }
    }
    /** A previous score is never reused; this only freezes the live route choice. */
    static String capturedMultihopExecution(String homeSession) throws Exception {
        return capturedMultihop(homeSession).execution;
    }
    static CapturedMultihop capturedMultihop(String homeSession) throws Exception {
        return capturedMultihop(currentService.get(),homeSession);
    }
    private static CapturedMultihop capturedMultihop(LayeredVpnService service,String homeSession) throws Exception {
        if(service==null||homeSession==null||homeSession.isEmpty())throw new IllegalStateException("The original multihop service is unavailable.");
        synchronized(service.lock){
            long generation=service.lifecycle.get();CommandServer server=service.commandServer;
            AndroidMTUSession mtu=service.mtuSession;String mtuMetadata=service.mtuMetadata;
            File nativeSession=service.activeSession;String config=service.activeConfig,metadataSource=service.multihopMetadata;
            AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(service),owner=service.multihopHomeOwner;
            if(owner==null||!homeSession.equals(home.sessionId)||!homeSession.equals(owner.sessionId)||owner.pathGeneration!=home.pathGeneration
                    ||!owner.activeEntryId.equals(home.activeEntryId)||!owner.activeExitId.equals(home.activeExitId)
                    ||!owner.activeEntryMode.equals(home.activeEntryMode)||!owner.runtimeMode.equals(home.runtimeMode)
                    ||!home.connected||!"connected".equals(home.phase)||!"passed".equals(home.pathProof)||!"multihop".equals(home.logicalMode)
                    ||AndroidHomeStateStore.emergencyDisconnectPending(service)||service.explicitStop||!"UP".equals(service.state)
                    ||!service.executionProved||service.commandServer==null||service.activeSession==null||service.hopMeasurement==null
                    ||service.executionNetwork.isEmpty()||"[]".equals(service.executionNetwork)||!service.executionNetwork.equals(service.executionNetworkIdentity())
                    ||config==null||config.isEmpty()||metadataSource==null||metadataSource.length()>16384)throw new IllegalStateException("The original multihop path is no longer proved and owned.");
            JSONObject metadata=new JSONObject(metadataSource);
            String requested=metadata.optString("execution","local");
            if(!home.runtimeMode.equals(metadata.getString("exit_mode"))||!home.activeEntryMode.equals(metadata.optString("entry_mode","wg")))throw new IllegalStateException("The original multihop transport changed.");
            io.nekohasekai.libbox.RouterMultihop plan=service.executionController;
            String selected="local",pins="{}";
            if(plan==null){if(!"local".equals(requested))throw new IllegalStateException("The multihop comparison owner is missing.");}
            else{
                String raw=plan.progressJSON();if(raw==null||raw.length()>65536||!plan.healthy())throw new IllegalStateException("The selected multihop lease or native owner changed.");
                JSONObject progress=new JSONObject(raw);selected=progress.getString("execution");
                if(!progress.optBoolean("complete",false)||!"selected".equals(progress.optString("stage",""))||!progress.optString("failure","").isEmpty()
                        ||!java.util.Arrays.asList("local","server").contains(selected)||!"auto".equals(requested)&&!requested.equals(selected))throw new IllegalStateException("Multihop has no retained valid Local or Server selection.");
                pins=plan.serverIdentityPinsJSON();
            }
            pins=AndroidMultihopController.validatedServerIdentityPins(selected,home.runtimeMode,pins);
            AndroidHomeStateStore.Snapshot after=AndroidHomeStateStore.snapshot(service);
            if(currentService.get()!=service||service.explicitStop||!"UP".equals(service.state)||!service.executionProved||generation!=service.lifecycle.get()
                    ||server!=service.commandServer||owner!=service.multihopHomeOwner||plan!=service.executionController
                    ||mtu!=service.mtuSession||!java.util.Objects.equals(mtuMetadata,service.mtuMetadata)
                    ||nativeSession!=service.activeSession||!config.equals(service.activeConfig)||!metadataSource.equals(service.multihopMetadata)
                    ||!after.connected||!home.sessionId.equals(after.sessionId)||home.pathGeneration!=after.pathGeneration
                    ||!home.activeEntryId.equals(after.activeEntryId)||!home.activeExitId.equals(after.activeExitId)
                    ||!home.activeEntryMode.equals(after.activeEntryMode)||!home.runtimeMode.equals(after.runtimeMode)
                    ||!"connected".equals(after.phase)||!"passed".equals(after.pathProof)||!"multihop".equals(after.logicalMode)
                    ||!service.executionNetwork.equals(service.executionNetworkIdentity())||plan!=null&&!plan.healthy())throw new IllegalStateException("Multihop changed during route capture.");
            return new CapturedMultihop(service,home,server,plan,nativeSession,generation,config,metadataSource,mtu,mtuMetadata,selected,pins);
        }
    }
    static String hopMeasurementRequest(String operation,String id) throws Exception {
        LayeredVpnService service=currentService.get();
        if(service==null||id==null||!id.matches("[0-9a-f]{32}"))throw new IllegalStateException("No captured hop measurement session.");
        synchronized(service.lock){
            io.nekohasekai.libbox.RouterHopMeasurement probe=service.hopMeasurement;
            if(probe==null||!"UP".equals(service.state)||service.explicitStop)throw new IllegalStateException("The proved native path measurement runtime is unavailable.");
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

    /** Retains the old native probe so cancellation can drain it after replacement. */
    static final class HopMeasurementOwner {
        private final LayeredVpnService service;
        private final io.nekohasekai.libbox.RouterHopMeasurement probe;
        private final CommandServer server;
        private final long generation;
        private final String request,network;
        private volatile boolean started;
        private HopMeasurementOwner(LayeredVpnService service,String request){this.service=service;probe=service.hopMeasurement;server=service.commandServer;generation=service.lifecycle.get();network=service.executionNetwork;this.request=request;}
        private void requireCurrent(){
            if(probe==null||server==null||service.hopMeasurement!=probe||service.commandServer!=server||generation!=service.lifecycle.get()
                    ||service.explicitStop||!"UP".equals(service.state)||!network.equals(service.executionNetworkIdentity()))throw new IllegalStateException("The captured path measurement session changed.");
        }
        void start()throws Exception{
            synchronized(service.lock){requireCurrent();if(service.mtuSession!=null&&service.mtuSession.running())throw new IllegalStateException("MTU Retest has not drained.");probe.start(request,8388608);started=true;requireCurrent();}
        }
        boolean started(){return started;}
        String status()throws Exception{
            synchronized(service.lock){requireCurrent();String response=probe.statusJSON();requireCurrent();if(response==null||response.length()>16384)throw new IllegalStateException("Oversized measurement status.");return response;}
        }
        void cancel(){probe.cancel(request);}
        void drain()throws Exception{probe.drain(request);}
    }
    static HopMeasurementOwner captureHopMeasurement(String request)throws Exception{
        LayeredVpnService service=currentService.get();if(service==null||request==null||!request.matches("[0-9a-f]{32}"))throw new IllegalStateException("No captured path measurement session.");
        synchronized(service.lock){HopMeasurementOwner owner=new HopMeasurementOwner(service,request);owner.requireCurrent();return owner;}
    }

    /** The request retains its exact old DNS handle after network/Box replacement.
     * Status/start require the live owner; cancel/drain always reach that handle. */
    static final class DNSMeasurementOwner {
        private final LayeredVpnService service;
        private final io.nekohasekai.libbox.RouterDNSMeasurement probe;
        private final CommandServer server;
        private final AndroidTorSession tor;
        private final AndroidExternalSession external;
        private final long generation;
        final String request,nodeID,sessionID;
        private final String network;
        private volatile boolean attempted;
        private DNSMeasurementOwner(LayeredVpnService service,String request,String nodeID){
            this.service=service;this.request=request;this.nodeID=nodeID;
            probe=service.dnsMeasurement;server=service.commandServer;generation=service.lifecycle.get();network=service.executionNetwork;
            tor=service.torSession;external=service.externalSession;
            sessionID=tor!=null?tor.sessionID:external!=null?external.sessionID:"";
        }
        private void requireCurrent(){
            if(probe==null||server==null||service.dnsMeasurement!=probe||service.commandServer!=server||generation!=service.lifecycle.get()
                    ||service.explicitStop||!"UP".equals(service.state)||network.isEmpty()||"[]".equals(network)||!network.equals(service.executionNetworkIdentity())
                    ||(tor==null)==(external==null)||tor!=service.torSession||external!=service.externalSession
                    ||tor!=null&&(!nodeID.equals(tor.externalID)||!tor.healthy())||external!=null&&(!nodeID.equals(external.externalID)||!external.healthy()))
                throw new IllegalStateException("Connect and prove this external DNS path before comparing resolvers.");
        }
        void start(String transport)throws Exception{
            synchronized(service.lock){
                requireCurrent();
                if(service.mtuSession!=null&&service.mtuSession.running())throw new IllegalStateException("MTU Retest has not drained.");
                attempted=true;probe.start(request,transport);requireCurrent();
            }
        }
        boolean attempted(){return attempted;}
        String status()throws Exception{
            synchronized(service.lock){requireCurrent();String response=probe.statusJSON();requireCurrent();if(response==null||response.length()>65536)throw new IllegalStateException("Oversized native DNS measurement status.");return response;}
        }
        void cancel(){probe.cancel(request);}
        void drain()throws Exception{probe.drain(request);}
    }
    static DNSMeasurementOwner captureDNSMeasurement(String request,String nodeID)throws Exception{
        LayeredVpnService service=currentService.get();
        if(service==null||request==null||!request.matches("[0-9a-f]{32}")||nodeID==null||nodeID.isEmpty())throw new IllegalStateException("No captured external DNS measurement session.");
        synchronized(service.lock){DNSMeasurementOwner owner=new DNSMeasurementOwner(service,request,nodeID);owner.requireCurrent();return owner;}
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
    static String torExecution(String sessionID, String externalID) throws Exception {
        LayeredVpnService service = currentService.get();
        AndroidTorSession captured = service == null ? null : service.torSession;
        if (captured == null || !"UP".equals(service.state) || service.explicitStop) throw new IllegalStateException("The captured Tor execution receipt is unavailable.");
        return captured.execution(sessionID, externalID);
    }
    static String externalExitIP(String sessionID, String externalID) throws Exception {
        LayeredVpnService service = currentService.get();
        AndroidExternalSession captured = service == null ? null : service.externalSession;
        if (captured == null || !"UP".equals(service.state) || service.explicitStop) throw new IllegalStateException("The captured external VPN proof is unavailable.");
        return new JSONObject(captured.result(sessionID, externalID)).getString("ip");
    }
    static String externalExecution(String sessionID,String externalID)throws Exception {
        LayeredVpnService service=currentService.get();AndroidExternalSession captured=service==null?null:service.externalSession;
        if(captured==null||!"UP".equals(service.state)||service.explicitStop)throw new IllegalStateException("The captured external execution receipt is unavailable.");
        return captured.execution(sessionID,externalID);
    }
    private void cancelMultihopComparison(){AndroidMAXProfilePreparation.Adopted max=maxSession;if(max!=null)max.cancel();AndroidTorSession tor=torSession;if(tor!=null)tor.cancel();AndroidExternalSession external=externalSession;if(external!=null)external.cancel();AndroidMTUSession mtu=mtuSession;if(mtu!=null)mtu.networkChanged();CommandServer owned=commandServer;if(owned!=null)Libbox.routerInvalidatePerformance(owned);io.nekohasekai.libbox.RouterHopMeasurement probe=hopMeasurement;if(probe!=null)probe.networkChanged();io.nekohasekai.libbox.RouterDNSMeasurement dns=dnsMeasurement;if(dns!=null)dns.networkChanged();io.nekohasekai.libbox.RouterMultihop plan=executionController;if(plan!=null)plan.networkChanged();}
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
        io.nekohasekai.libbox.RouterMultihop plan=executionController;AndroidTorSession tor=torSession;AndroidExternalSession external=externalSession;AndroidMAXProfilePreparation.Adopted max=maxSession;if(plan==null&&hopMeasurement==null&&dnsMeasurement==null&&tor==null&&external==null&&max==null)return;
        if(max!=null&&!max.current(false)||!executionNetwork.equals(executionNetworkIdentity())||(executionProved&&plan!=null&&!plan.healthy())||(executionProved&&tor!=null&&!tor.healthy())||(executionProved&&external!=null&&!external.healthy())){
            if(external!=null)AndroidHomeStateStore.failedPolicyExternal(LayeredVpnService.this,externalHomeOwner,"The captured external exit, entry, DNS or network changed; reconnect to prove the path.",false);
            cancelMultihopComparison();executor.execute(()->{if(tor!=null&&torSession!=tor||external!=null&&externalSession!=external||max!=null&&maxSession!=max)return;shutdown("FAILED",max!=null?"The captured MAX source or physical network changed; reconnect to prove the path.":tor!=null?"The captured Tor network or circuit changed; reconnect to prove the path.":external!=null?"The captured external exit, entry, DNS or network changed; reconnect to prove the path.":"Multihop network or server lease changed; reconnect to compare again.");});return;
        }
        executionHandler.postDelayed(this,500);
    }};
    private volatile ParcelFileDescriptor tunDescriptor;
    private AndroidStartLayerRelay startLayerRelay;
    private volatile File activeSession;
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

        final String sessionId = intent.getStringExtra(EXTRA_SESSION_ID);
        final String modeId = intent.getStringExtra(EXTRA_MODE_ID);
        final String maxOwner = intent.getStringExtra(AndroidMAXProfilePreparation.EXTRA_OWNER);
        final String homeSession = intent.getStringExtra(EXTRA_HOME_SESSION_ID);
        final String comparisonSession = intent.getStringExtra(EXTRA_TOR_COMPARISON);
        TorCompareTrial trial;
        synchronized(TOR_COMPARE_LOCK){trial=reservedTorCompare!=null&&reservedTorCompare.prepared.sessionId.equals(sessionId)?reservedTorCompare:null;}
        final long generation;
        if(comparisonSession!=null){
            if(!comparisonSession.equals(sessionId)||trial==null||!trial.bind(this)){
                rejectTorComparisonStart(startId);return Service.START_NOT_STICKY;
            }
            generation=trial.generation;
        }else{
            boolean reserved; synchronized(TOR_COMPARE_LOCK){reserved=reservedTorCompare!=null;}
            if(reserved){rejectTorComparisonStart(startId);return Service.START_NOT_STICKY;}
            generation=lifecycle.incrementAndGet();explicitStop=false;
        }
        startForeground(NOTIFICATION_ID, buildNotification("Starting layered VPN…"));
        executor.execute(() -> startLayered(sessionId, modeId, generation, maxOwner, homeSession));
        return Service.START_NOT_STICKY;
    }

    private void rejectTorComparisonStart(int startId){
        // A cancelled startForegroundService delivery still has to satisfy
        // Android's foreground-start contract. Never touch a retained path;
        // stopSelf(startId) also cannot stop a later framework start command.
        if(commandServer==null&&activeSession==null&&torCompareTrial==null
                &&!("UP".equals(state)||"STARTING".equals(state)||"STOPPING".equals(state))){
            startForeground(NOTIFICATION_ID,buildNotification("Cancelled Tor comparison…"));
            stopForeground(STOP_FOREGROUND_REMOVE);stopSelf(startId);
        }
    }

    private void startLayered(String sessionId, String modeId, long generation, String maxOwner, String homeSession) {
        TorCompareTrial comparison=torCompareTrial;
        if(comparison!=null&&!comparison.prepared.sessionId.equals(sessionId))comparison=null;
        final TorCompareTrial capturedComparison=comparison;
        final boolean rejected;
        synchronized (lock) {
            rejected=generation != lifecycle.get() || explicitStop || capturedComparison!=null&&(capturedComparison.cancelled||!capturedComparison.owner.current())
                    || "STARTING".equals(state) || "UP".equals(state) || torOwner || externalOwner;
            if(!rejected)publish("STARTING", modeId, "");
        }
        if(rejected){
            AndroidMAXProfilePreparation.discardPrepared(sessionId,maxOwner);
            discardPreparedSession(this,sessionId);
            if(capturedComparison!=null){capturedComparison.finished(false,"Tor candidate was cancelled before native startup.");closeTorCompareTrial(capturedComparison,"");}
            return;
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
            if (externalMetadata != null || torMetadata != null) {
                boolean required = externalMetadata != null
                        ? AndroidExternalProtection.externalCapture(new JSONObject(externalMetadata.getString("capture_json")))
                        : AndroidExternalProtection.torCapture(torMetadata);
                AndroidExternalProtection.requireSession(new File(session, AndroidKillSwitchPolicy.SESSION_MARKER).isFile(), required,
                        Build.VERSION.SDK_INT, Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && isAlwaysOn(),
                        Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && isLockdownEnabled());
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
            Network torPhysical = torMetadata == null ? null : capturedComparison==null?connectivity.getActiveNetwork():capturedComparison.physical.network;
            if (torMetadata != null && (torPhysical == null || connectivity.getNetworkCapabilities(torPhysical) == null
                    || connectivity.getNetworkCapabilities(torPhysical).hasTransport(NetworkCapabilities.TRANSPORT_VPN))) throw new IllegalStateException("Tor requires an owned physical network before the VPN starts.");
            if(capturedComparison!=null&&(torMetadata==null||!capturedComparison.physical.current(true)||!capturedComparison.owner.current()
                    ||!capturedComparison.execution.equals(AndroidTorProfile.execution(torMetadata))||!capturedComparison.externalID.equals(torMetadata.getString("external_id"))))
                throw new IllegalStateException("Tor comparison candidate differs from its captured source or physical network.");
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
                multihopMetadata=hopMetadata;multihopHomeOwner=hopMetadata==null?null:AndroidHomeStateStore.snapshot(this);
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
                final AndroidTorSession capturedTor = new AndroidTorSession(torMetadata, config, capturedServer, new AndroidTorSession.Owner() {
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
                adoptHopMeasurement(capturedTor.newHopMeasurement(), ownedServer, generation);
                adoptDNSMeasurement(capturedTor.newDNSMeasurement(), ownedServer, generation);
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
                adoptHopMeasurement(capturedExternal.newHopMeasurement(), ownedServer, generation);
                adoptDNSMeasurement(capturedExternal.newDNSMeasurement(), ownedServer, generation);
            }
            if(hopMetadata!=null){
                executionNetwork=executionNetworkIdentity();
                if(executionNetwork.isEmpty())throw new IllegalStateException("Underlying network identity is unavailable.");
                executionHandler.post(executionWatch);
                if(ownedExecution!=null)ownedExecution.run(ownedServer);
                adoptHopMeasurement(Libbox.newRouterHopMeasurement(ownedServer,hopMetadata),ownedServer,generation);
                executionHandler.removeCallbacks(executionWatch);executionHandler.post(executionWatch);
            }
            long performanceServices = Libbox.routerStartPerformance(ownedServer);
            synchronized(lock){
                if(explicitStop||generation!=lifecycle.get()||commandServer!=ownedServer||executionController!=ownedExecution
                        ||torSession!=null&&!torSession.healthy()||externalSession!=null&&!externalSession.healthy()||maxSession!=null&&!maxSession.current(true))throw new IllegalStateException("VPN ownership changed during path proof.");
                performanceActive = performanceServices > 0;
                executionProved=true;publish("UP",modeId,"");
            }
            if(capturedComparison!=null)capturedComparison.finished(true,"");
            if (performanceActive) executionHandler.post(performanceWatch);
            updateForeground("Layered VPN active: " + modeId);
        } catch (RevokedException revoked) {
            Log.w(TAG, revoked.getMessage());
            if(capturedComparison!=null)capturedComparison.finished(false,revoked.getMessage());
            shutdown("REVOKED", revoked.getMessage());
        } catch (Throwable error) {
            Log.e(TAG, "Layered VPN start failed", error);
            if(capturedComparison!=null)capturedComparison.finished(false,safeMessage(error));
            shutdown("FAILED", safeMessage(error));
        } finally {
            if (preparedMAX != null && maxSession != preparedMAX) preparedMAX.cancel();
            AndroidMAXProfilePreparation.discardPrepared(sessionId,maxOwner);
            // This requested directory is retained only after actual runtime
            // adoption. Lockdown, permission and network failures happen earlier.
            discardPreparedSession(this,sessionId);
        }
    }

    private void adoptHopMeasurement(io.nekohasekai.libbox.RouterHopMeasurement measurement, CommandServer server, long generation) throws Exception {
        if (measurement == null) throw new IllegalStateException("The captured path measurement owner is unavailable.");
        synchronized (lock) {
            if (!explicitStop && generation == lifecycle.get() && commandServer == server && hopMeasurement == null
                    && executionNetwork.equals(executionNetworkIdentity())
                    && (torSession == null || torSession.healthy()) && (externalSession == null || externalSession.healthy())) {
                hopMeasurement = measurement;
                return;
            }
        }
        measurement.close();
        throw new IllegalStateException("VPN ownership changed before path measurement adoption.");
    }

    private void adoptDNSMeasurement(io.nekohasekai.libbox.RouterDNSMeasurement measurement, CommandServer server, long generation) throws Exception {
        if(measurement==null)throw new IllegalStateException("The captured DNS measurement owner is unavailable.");
        synchronized(lock){
            if(!explicitStop&&generation==lifecycle.get()&&commandServer==server&&dnsMeasurement==null
                    &&executionNetwork.equals(executionNetworkIdentity())&&(torSession==null)!=(externalSession==null)
                    &&(torSession==null||torSession.healthy())&&(externalSession==null||externalSession.healthy())){
                dnsMeasurement=measurement;return;
            }
        }
        measurement.close();
        throw new IllegalStateException("VPN ownership changed before DNS measurement adoption.");
    }
    private void closeDNSMeasurementLocked(){
        if(dnsMeasurement==null)return;
        try{dnsMeasurement.close();}
        catch(Exception pending){publish("STOPPING",activeMode,"DNS measurement cleanup is still pending; its native owner is retained.");throw new IllegalStateException("DNS measurement teardown has not drained.",pending);}
        dnsMeasurement=null;
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
        AndroidHomeStateStore.Snapshot torHome = torHomeOwner;
        AndroidHomeStateStore.failedPolicyExternal(this,home,"The captured external VPN service stopped; its path proof is no longer valid.",false);
        AndroidHomeStateStore.failedTorExternal(this,torHome,"The captured Tor VPN service stopped; its path proof is no longer valid.",false);
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
            TorCompareTrial trial=torCompareTrial;torCompareTrial=null;
            if(trial!=null&&!trial.kept)trial.completeClose();
        }
        if(currentService.get()==this)currentService.clear();
        AndroidHomeStateStore.failedPolicyExternal(this,home,"The captured external VPN service stopped; reconnect to prove the path.",true);
        AndroidHomeStateStore.failedTorExternal(this,torHome,"The captured Tor VPN service stopped; reconnect to prove the path.",true);
        if (!explicitStop && ("UP".equals(terminal) || "STARTING".equals(terminal))) {
            publish("FAILED", mode, "Layered VPN service stopped unexpectedly.");
        }
        if (session != null) deleteTree(session);
        executor.shutdown();
        super.onDestroy();
    }

    private void shutdown(String terminalState, String error) {
        TorCompareTrial trial=torCompareTrial;
        if(trial!=null&&!trial.kept){closeTorCompareTrial(trial,error);return;}
        String mode;
        File session;
        AndroidHomeStateStore.Snapshot home;
        AndroidHomeStateStore.Snapshot torHome;
        synchronized (lock) {
            if (!"DOWN".equals(terminalState) && !"FAILED".equals(terminalState) && !"REVOKED".equals(terminalState)) terminalState = "FAILED";
            if ("DOWN".equals(terminalState)) publish("STOPPING", activeMode, "");
            mode = activeMode;
            session = activeSession;
            home = externalHomeOwner;
            torHome = torHomeOwner;
            AndroidHomeStateStore.failedPolicyExternal(this,home,error.isEmpty()?"The captured external VPN is stopping; its path proof is no longer valid.":error,false);
            AndroidHomeStateStore.failedTorExternal(this,torHome,error.isEmpty()?"The captured Tor VPN is stopping; its path proof is no longer valid.":error,false);
            closeCoreLocked();
            activeSession = null;
            activeMode = "";
            activeConfig = "";
            publish(terminalState, "DOWN".equals(terminalState) ? "" : mode, error);
            AndroidHomeStateStore.failedPolicyExternal(this,home,error.isEmpty()?"The captured external VPN stopped.":error,true);
            AndroidHomeStateStore.failedTorExternal(this,torHome,error.isEmpty()?"The captured Tor VPN stopped.":error,true);
        }
        if (session != null) deleteTree(session);
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    /** Stop only this round's candidate. Trials keep the same service and
     * pending Home owner; normal Stop/revocation still retires the service. */
    private void closeTorCompareTrial(TorCompareTrial trial,String failure) {
        if(trial.kept||trial.closed)return;
        trial.cancel();
        File session;
        synchronized(lock){
            if(torCompareTrial!=trial){
                if(trial.provedServer==null&&trial.finished){trial.completeClose();return;}
                throw new IllegalStateException("The retained Tor candidate no longer owns its service cleanup.");
            }
            if(activeSession!=null&&!trial.prepared.sessionId.equals(activeSession.getName()))
                throw new IllegalStateException("An old Tor comparison cannot close a replacement session.");
            session=activeSession;
            publish("STOPPING",activeMode,failure==null?"":failure);
            closeCoreLocked();
            activeSession=null;activeMode="";activeConfig="";torCompareTrial=null;
            publish("DOWN","",failure==null?"":failure);
        }
        if(session!=null)deleteTree(session);
        else discardPreparedSession(this,trial.prepared.sessionId);
        trial.completeClose();
        if(explicitStop){stopForeground(STOP_FOREGROUND_REMOVE);stopSelf();}
        else updateForeground("Comparing Tor Local and Server execution…");
    }

    private void closeCoreLocked() {
        AndroidMAXProfilePreparation.Adopted capturedMAX = maxSession;
        if (capturedMAX != null) capturedMAX.cancel();
        AndroidTorSession capturedTor = torSession;
        if(capturedTor!=null){
            // Revoke data first. Only the exact native Server lease can use
            // its retained lower path while this bounded DELETE is running.
            capturedTor.cancel();
            // Native Tor Close waits for retained measurement sockets. Join
            // their retryable owners first, while keeping the entry and TUN.
            closeTorMeasurementsLocked();
            torCleanup=new TorCleanup(capturedTor,commandServer,capturedMAX,torPhysicalNetwork,executionNetwork);
            try{capturedTor.close();}
            catch(Exception pending){publish("STOPPING",activeMode,"Tor server lease cleanup remains pending; the captured native path is retained for retry.");throw new IllegalStateException("Tor execution cleanup has not been acknowledged.",pending);}
            finally{torCleanup=null;}
        }
        AndroidExternalSession capturedExternal = externalSession;
        if(capturedExternal!=null){
            try{capturedExternal.close();}
            catch(Exception pending){publish("STOPPING",activeMode,"External server lease cleanup remains pending; the captured native path is retained for retry.");throw new IllegalStateException("External execution cleanup has not been acknowledged.",pending);}
        }
        if(hopMeasurement!=null)hopMeasurement.networkChanged();
        if(dnsMeasurement!=null)dnsMeasurement.networkChanged();
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
            closeDNSMeasurementLocked();
            commandServer = null;
            torSession = null;
            torOwner = false;
            torPhysicalNetwork = null;
            externalSession = null;
            externalOwner = false;
            externalPhysicalNetwork = null;
            maxSession = null;
        }
        AndroidMTUSession oldMTU=mtuSession;
        if(oldMTU!=null){
            oldMTU.networkChanged();
            try{oldMTU.close();}
            catch(Exception error){publish("STOPPING",activeMode,"MTU cleanup is still pending; its native owner is retained.");throw new IllegalStateException("MTU controller teardown has not drained.");}
        }
        mtuSession=null;mtuMetadata="";
        performanceActive = false;
        executionHandler.removeCallbacks(performanceWatch);
        if (commandServer != null) Libbox.routerInvalidatePerformance(commandServer);
        executionHandler.removeCallbacks(executionWatch);
        closeDNSMeasurementLocked();
        if(hopMeasurement!=null){
            try{hopMeasurement.close();}
            catch(Exception error){publish("STOPPING",activeMode,"Hop measurement cleanup is still pending; its native owner is retained.");throw new IllegalStateException("Hop measurement teardown has not drained.");}
            hopMeasurement=null;
        }
        if(executionController!=null){
            try{executionController.close();}catch(Exception failure){Log.w(TAG,"Server lease cleanup was not confirmed; bounded server expiry remains in force.");}
            executionController=null;executionProved=false;
        }
        multihopMetadata=null;multihopHomeOwner=null;executionProved=false;
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
        externalHomeOwner = null;
        torHomeOwner = null;
    }

    private void closeTorMeasurementsLocked(){
        if(hopMeasurement!=null){
            hopMeasurement.networkChanged();
            try{hopMeasurement.close();}
            catch(Exception pending){publish("STOPPING",activeMode,"Tor hop measurement cleanup is still pending; its native owner is retained.");throw new IllegalStateException("Tor hop measurement teardown has not drained.",pending);}
            hopMeasurement=null;
        }
        if(dnsMeasurement!=null)dnsMeasurement.networkChanged();
        closeDNSMeasurementLocked();
        AndroidMTUSession captured=mtuSession;
        if(captured!=null){
            captured.networkChanged();
            try{captured.close();}
            catch(Exception pending){publish("STOPPING",activeMode,"Tor MTU cleanup is still pending; its native owner is retained.");throw new IllegalStateException("Tor MTU teardown has not drained.",pending);}
            mtuSession=null;mtuMetadata="";
        }
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
        boolean cleanup=torCleanupCurrent();
        if (captured != maxSession || (cleanup ? !captured.cleanupCurrent() : explicitStop || !captured.current(false))) throw new IllegalStateException("The captured MAX physical network changed; reconnect before opening traffic.");
        if (torOwner) requireTorNetwork(torPhysicalNetwork);
        if (externalOwner) requireExternalNetwork(externalPhysicalNetwork);
    }
    private boolean torCleanupCurrent(){
        TorCleanup captured=torCleanup;
        return captured!=null&&System.nanoTime()<captured.deadline&&torOwner
                &&captured.tor==torSession&&captured.server!=null&&captured.server==commandServer
                &&captured.max==maxSession&&captured.network!=null&&captured.network==torPhysicalNetwork
                &&captured.networkIdentity.equals(executionNetwork)&&captured.tor.retainsServerCleanup(captured.server);
    }
    private void requireTorNetwork(Network captured){
        NetworkCapabilities caps=captured==null?null:connectivity.getNetworkCapabilities(captured);
        AndroidTorSession tor=torSession;
        boolean stopped=explicitStop||torCleanup!=null||tor!=null&&tor.dataCancelled();
        if((stopped&&!torCleanupCurrent())||!torOwner||captured!=torPhysicalNetwork||caps==null||caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
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
                if(torOwner||executionController!=null||hopMeasurement!=null||dnsMeasurement!=null||mtuSession!=null){cancelMultihopComparison();shutdown("FAILED","Native reload needs fresh path and MTU ownership.");return;}
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
