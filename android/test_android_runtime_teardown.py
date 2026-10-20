#!/usr/bin/env python3
"""Exercise the actual runtime classes on a JVM with fake Android/engine boundaries.

No source rewriting or real networking is used. This proves controller lifecycle
behavior, not Android VpnService traffic, device permissions, or leak resistance.
"""
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'
TARGETS = sys.argv[2:]
assert all(x in ('multihop', 'external', 'tor') for x in TARGETS), 'unknown runtime test target'
javac, java = shutil.which('javac'), shutil.which('java')
assert javac and java, 'JDK is required for Android runtime lifecycle tests'

STUBS = r'''package com.eabusham.routervpn;
import android.content.Context;
import java.io.File;
import java.util.Collections;
import java.util.List;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

final class NativeSingBoxController {
    // PRODUCTION_TRANSPORT_PREDICATES
    static final class ModeInfo {}
    static final class SessionInfo {final String sessionId="native-session";final Preparation maxPreparation=null;}static final class Preparation{void close(){}}
    volatile String state = "DOWN", mode = "";
    volatile String startState = "UP";
    volatile boolean failStart, failStop;
    final AtomicInteger starts = new AtomicInteger(), stops = new AtomicInteger();
    String getState() { return state; }
    String getMode() { return mode; }
    String getError() { return "injected engine failure"; }
    void start(SessionInfo session) {
        starts.incrementAndGet(); state = startState; mode = "standard-test";
        if (failStart) throw new IllegalStateException("start failed after engine ownership publication");
    }
    void startExternal(SessionInfo session,String homeSession) {
        if(!homeSession.equals(AndroidHomeStateStore.current.sessionId))throw new AssertionError("Native launch lost its exact Home owner");
        start(session);
    }
    void stop() {
        stops.incrementAndGet();
        if (failStop) throw new IllegalStateException("stop request failed");
        state = "DOWN";
    }
}
final class LayeredVpnService {
    static final AtomicInteger discarded=new AtomicInteger();
    static boolean discardPreparedSession(Context context,String session){if(!"native-session".equals(session))throw new AssertionError("Discarded wrong session");discarded.incrementAndGet();return true;}
    static final AtomicInteger externalReads=new AtomicInteger();static volatile boolean externalHealthy=true;
    static String externalExitIP(String session,String exit){externalReads.incrementAndGet();if(!externalHealthy||!"native-session".equals(session)||!"external".equals(exit))throw new IllegalStateException("wrong captured external owner");return "1.1.1.1";}
    static final AtomicInteger torReads=new AtomicInteger();static volatile boolean torHealthy=true;
    static String torExitIP(String session,String exit){torReads.incrementAndGet();if(!torHealthy||!"native-session".equals(session)||!"external".equals(exit))throw new IllegalStateException("wrong captured Tor owner");return "8.8.4.4";}
    static final AtomicInteger mtuStarts = new AtomicInteger();
    static volatile java.util.concurrent.CountDownLatch mtuEntered, mtuRelease;
    static void startAutomaticMTU() {
        if (!AndroidHomeStateStore.current.connected) throw new AssertionError("MTU started before path proof adoption");
        java.util.concurrent.CountDownLatch entered=mtuEntered, release=mtuRelease;
        if(entered!=null){
            entered.countDown(); boolean interrupted=false;
            while(true){try{release.await();break;}catch(InterruptedException e){interrupted=true;}}
            if(interrupted)Thread.currentThread().interrupt();
        }
        if (!AndroidHomeStateStore.current.connected) throw new AssertionError("MTU activation escaped its captured adoption");
        mtuStarts.incrementAndGet();
    }
}
final class AndroidNodeStore {
    static final class Node {
        final String id, name; final File file;
        Node(String id) { this.id=id; name=id; file=new File(id); }
    }
}
final class AndroidMultihopController {
    static final class Prepared {
        final NativeSingBoxController.SessionInfo session = new NativeSingBoxController.SessionInfo();
        final File exitBundle; final String exitMode;
        Prepared(File exit, String mode) { exitBundle=exit; exitMode=mode; }
    }
    AndroidMultihopController(Context c, NativeSingBoxController s) {}
    List<NativeSingBoxController.ModeInfo> listSupportedExitModes(File f) { return Collections.emptyList(); }
    static volatile String lastExecution = "", lastEntryMode = "";
    Prepared prepare(File entry, File exit, String mode) { return prepare(entry,exit,mode,"local","wg"); }
    Prepared prepare(File entry, File exit, String mode, String execution, String entryMode) {
        lastExecution=execution; lastEntryMode=entryMode; return new Prepared(exit,mode);
    }
}
final class AndroidStandardExitStore {
    static final class Entry {
        String id="external", name="external", protocol="socks5", expectedPublicIp="1.1.1.1";
    }
    static Entry copy(Entry entry){Entry e=new Entry();e.id=entry.id;e.name=entry.name;e.protocol=entry.protocol;e.expectedPublicIp=entry.expectedPublicIp;return e;}
    static void validate(Entry entry){}
}
final class AndroidTorProfile {static boolean isTor(String protocol){return "tor".equals(protocol)||"tor-bridge".equals(protocol);}}
final class AndroidExternalPolicy {static volatile String entryVersion="captured-entry";static String entryDigest(File file){return entryVersion;}
    // PRODUCTION_EXTERNAL_PREDICATE
}
final class AndroidStandardExitController {
    static volatile String lastEntryMode="",lastProtocol="";
    AndroidStandardExitController(Context c) {}
    NativeSingBoxController.SessionInfo prepare(File f, AndroidStandardExitStore.Entry e) { return new NativeSingBoxController.SessionInfo(); }
    NativeSingBoxController.SessionInfo prepare(File f, AndroidStandardExitStore.Entry e,String mode) {lastEntryMode=mode;lastProtocol=e.protocol;return prepare(f,e); }
}
final class AndroidDirectStandardExitController {
    static volatile String lastProtocol="";
    AndroidDirectStandardExitController(Context c) {}
    NativeSingBoxController.SessionInfo prepare(AndroidStandardExitStore.Entry e) {lastProtocol=e.protocol;return new NativeSingBoxController.SessionInfo(); }
}
final class AndroidPathProbe {
    static boolean prove(File bundle, int timeout) { return true; }
}
final class AndroidHomeStateStore {
    static final class Snapshot {
        boolean connected;
        long pathGeneration;
        String expectedExternalIp="";
        String logicalMode="", phase="off", activeEntryId="", activeExitId="", activeEntryMode="wg", runtimeMode="",sessionId="home-session",activeExternalId="external",activeExternalProtocol="socks5";
    }
    static volatile Snapshot current = new Snapshot();
    static volatile java.util.concurrent.CountDownLatch connectedEntered, connectedRelease;
    static void reset() { current=new Snapshot(); connectedEntered=null; connectedRelease=null; }
    static void beforeConnectedWrite() {
        if(connectedEntered==null)return;
        connectedEntered.countDown(); boolean interrupted=false;
        while(true){try{connectedRelease.await();break;}catch(InterruptedException e){interrupted=true;}}
        if(interrupted)Thread.currentThread().interrupt();
    }
    static Snapshot snapshot(Context c) { return current; }
    static boolean emergencyDisconnectPending(Context c) { return false; }
    static String beginMultihop(Context c, String entry, String exit, String mode, String entryMode) {
        Snapshot s=new Snapshot(); s.logicalMode="multihop"; s.phase="connecting";
        s.activeEntryId=entry; s.activeEntryMode=entryMode; s.activeExitId=exit; s.runtimeMode=mode; current=s; return "multi-session";
    }
    static void connectedMultihop(Context c, String entry, String exit, String mode, String entryMode) {
        beginMultihop(c,entry,exit,mode,entryMode); beforeConnectedWrite(); current.connected=true; current.phase="connected";
    }
    static void beginExternal(Context c, String id, String name, String protocol, String ip, String base) {
        Snapshot s=new Snapshot();s.logicalMode="external";s.phase="connecting";current=s;
    }
    static String beginTorExternal(Context c,String id,String name,String protocol,String entry,String mode){beginExternal(c,id,name,protocol,"",mode);current.activeExternalProtocol=protocol;current.activeExternalId=id;current.activeEntryId=entry;current.activeEntryMode=mode;return "home-session";}
    static boolean connectedTorExternal(Context c,Snapshot s,String ip){if(!s.sessionId.equals(current.sessionId))return false;beforeConnectedWrite();current.connected=true;current.phase="connected";return true;}
    static String beginPolicyExternal(Context c,String id,String name,String protocol,String expected,String entry,String mode){beginTorExternal(c,id,name,protocol,entry,mode);current.expectedExternalIp=expected;return "home-session";}
    static boolean connectedPolicyExternal(Context c,Snapshot s,String ip){if(!s.sessionId.equals(current.sessionId)||s.pathGeneration!=current.pathGeneration)return false;beforeConnectedWrite();current.connected=true;current.phase="connected";return true;}
    static void connectedExternal(Context c, String id, String name, String protocol, String ip, String base, String observed) {
        beginExternal(c,id,name,protocol,ip,base); beforeConnectedWrite(); current.connected=true; current.phase="connected";
    }
    static void beginPathRevalidation(Context c, String reason) { current.connected=false;current.phase="disconnecting"; }
    static void warning(Context c, String warning) {}
    static void failed(Context c, String reason) { current.connected=false;current.phase="failed"; }
    static void disconnected(Context c) { reset(); }
}
final class AndroidRuntimeRegistry {
    static final AndroidRuntimeRegistry INSTANCE=new AndroidRuntimeRegistry();
    static AndroidRuntimeRegistry get(Context c) { return INSTANCE; }
    final IdleOwner orchestrator=new IdleOwner(), multihop=new IdleOwner();
    final WG wireGuard=new WG(); final AWG amneziaWG=new AWG(); final Xray xray=new Xray();
    static final class IdleOwner { boolean isRunning(){return false;}boolean isActive(){return false;}boolean isActiveOrTransitioning(){return false;} }
    static final class WG { com.wireguard.android.backend.Tunnel.State getState(){return com.wireguard.android.backend.Tunnel.State.DOWN;} }
    static final class AWG { org.amnezia.awg.backend.Tunnel.State getState(){return org.amnezia.awg.backend.Tunnel.State.DOWN;} }
    static final class Xray { String getState(){return "DOWN";} }
}
final class AndroidVpnMutationGuard {
    static boolean failedSessionHasNoLiveEngine(Context c, AndroidRuntimeRegistry e) { return false; }
}
'''

HARNESS = r'''package com.eabusham.routervpn;
import android.content.Context;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public final class RuntimeTeardownHarness {
    static final List<String> failures=new ArrayList<>();
    static final java.util.concurrent.atomic.AtomicInteger publicProofs=new java.util.concurrent.atomic.AtomicInteger();
    static final class Callback implements AndroidMultihopRuntime.Callback, AndroidStandardExitRuntime.Callback {
        final int blockAt; int progressCalls; volatile boolean ok;
        final CountDownLatch entered=new CountDownLatch(1), release=new CountDownLatch(1), done=new CountDownLatch(1);
        Callback(int blockAt) { this.blockAt=blockAt; }
        public void progress(String message) {
            if (++progressCalls!=blockAt) return;
            entered.countDown(); boolean interrupted=false;
            while (true) {
                try { release.await(); break; }
                catch (InterruptedException e) { interrupted=true; }
            }
            if (interrupted) Thread.currentThread().interrupt();
        }
        public void finished(boolean ok, String message) { this.ok=ok; done.countDown(); }
        void awaitEntered() throws Exception { check(entered.await(3,TimeUnit.SECONDS),"worker never reached requested checkpoint"); }
        void awaitDone() throws Exception { check(done.await(3,TimeUnit.SECONDS),"worker failed without delivering a completion callback"); }
    }
    static final class Owner implements AutoCloseable {
        final Context context=new Context(); final NativeSingBoxController engine=new NativeSingBoxController();
        final AndroidMultihopRuntime multihop; final AndroidStandardExitRuntime external;
        final String kind;
        Owner(String kind) {
            this.kind=kind;LayeredVpnService.torReads.set(0);LayeredVpnService.torHealthy=true;publicProofs.set(0);
            LayeredVpnService.externalReads.set(0);LayeredVpnService.externalHealthy=true;
            LayeredVpnService.discarded.set(0);
            AndroidHomeStateStore.reset(); LayeredVpnService.mtuStarts.set(0); LayeredVpnService.mtuEntered=null;LayeredVpnService.mtuRelease=null;
            multihop="multihop".equals(kind)?new AndroidMultihopRuntime(context,engine):null;
            external=multihop==null?new AndroidStandardExitRuntime(context,engine):null;
        }
        Object runtime() { return multihop!=null?multihop:external; }
        void connect(Callback cb) {
            if(multihop!=null)multihop.connect(new AndroidNodeStore.Node("entry"),new AndroidNodeStore.Node("exit"),"shadowsocks",cb);
            else {AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();if(kind.equals("tor")){e.protocol="tor";e.expectedPublicIp="";}external.connectDirect(e,cb);}
        }
        boolean busy() { return multihop!=null?multihop.isActiveOrTransitioning():external.isActiveOrTransitioning(); }
        void disconnect() { if(multihop!=null)multihop.disconnect();else external.disconnect(); }
        public void close() {
            engine.failStop=false; engine.state="DOWN";
            if(multihop!=null)multihop.close();else external.close();
        }
    }
    interface Case { void run() throws Exception; }
    static void check(boolean value, String message) { if(!value)throw new AssertionError(message); }
    static void test(String name, Case body) {
        try { body.run();System.out.println("PASS "+name); }
        catch(Throwable t){failures.add(name+": "+t);System.out.println("FAIL "+name+": "+t);}
    }
    static void awaitIdle(Owner owner) throws Exception {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
        while(owner.busy()&&System.nanoTime()<deadline)Thread.sleep(5);
        check(!owner.busy(),"worker did not release ownership after completion");
    }
    static void tests(String kind) {
        if("tor".equals(kind))torTests();
        if("external".equals(kind))externalTests();
        if ("multihop".equals(kind)) for (String entryMode:new String[]{"wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2"}) for (String execution:new String[]{"local","server","auto"}) {
            test("multihop captured transport/execution "+entryMode+"/"+execution,()->{
                try(Owner owner=new Owner(kind)) {
                    Callback cb=new Callback(0);
                    owner.multihop.connect(new AndroidNodeStore.Node("entry"),new AndroidNodeStore.Node("exit"),"shadowsocks",execution,entryMode,cb);
                    cb.awaitDone();
                    check(cb.ok&&execution.equals(AndroidMultihopController.lastExecution),"execution changed before preparation");
                    check(entryMode.equals(AndroidMultihopController.lastEntryMode),"entry transport changed before preparation");
                    check(entryMode.equals(owner.multihop.activeEntryMode())&&entryMode.equals(AndroidHomeStateStore.current.activeEntryMode),"proved live entry identity changed");
                    check(LayeredVpnService.mtuStarts.get()==1,"MTU did not start exactly once after path proof");
                    owner.disconnect();awaitIdle(owner);
                }
            });
        }
        if ("multihop".equals(kind)) {
            for(String entryMode:new String[]{"wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2"}) {
                test("multihop restore exact entry "+entryMode,()->{
                    try(Owner owner=new Owner(kind)) {
                        owner.engine.state="UP";
                        AndroidHomeStateStore.connectedMultihop(owner.context,"entry","exit","hysteria2",entryMode);
                        try(AndroidMultihopRuntime restored=new AndroidMultihopRuntime(owner.context,owner.engine)) {
                            check(restored.isConnected()&&entryMode.equals(restored.activeEntryMode()),"saved proved entry was dropped or relabelled");
                            check(restored.activeEntryId().equals("entry")&&restored.activeExitId().equals("exit")&&restored.activeExitMode().equals("hysteria2"),"restoration substituted a different graph");
                            check(owner.engine.starts.get()==0&&LayeredVpnService.mtuStarts.get()==0,"restoration started another VPN or measurement");
                            restored.disconnect();
                        }
                    }
                });
            }
            for(String entryMode:new String[]{"socks","http","tor","max-unknown","awg2-pq-unknown","WG","",null}) {
                test("multihop rejects unavailable entry "+entryMode,()->{
                    try(Owner owner=new Owner(kind)) {
                        Callback cb=new Callback(0);
                        owner.multihop.connect(new AndroidNodeStore.Node("entry"),new AndroidNodeStore.Node("exit"),"shadowsocks","auto",entryMode,cb);
                        cb.awaitDone();
                        check(!cb.ok&&owner.engine.starts.get()==0&&LayeredVpnService.mtuStarts.get()==0,"unavailable entry started or reported success");
                        check(!owner.busy()&&!AndroidHomeStateStore.current.connected,"invalid entry retained graph ownership");
                    }
                });
            }
        }
        test(kind+" successful proof",()->{
            try(Owner owner=new Owner(kind)) {
                Callback cb=new Callback(0);owner.connect(cb);cb.awaitDone();
                check(cb.ok&&AndroidHomeStateStore.current.connected,"normal connection never reached proved Connected");
                check(LayeredVpnService.mtuStarts.get()==(owner.multihop!=null?1:0),"MTU must start once, only after selected-router proof");
                if(kind.equals("tor"))check(publicProofs.get()==0&&LayeredVpnService.torReads.get()==2,"Tor used fixed-IP proof or lost final owner readback");
                if(kind.equals("external"))check(publicProofs.get()==0&&LayeredVpnService.externalReads.get()==2,"ordinary external path bypassed captured entry/DNS/native proof");
                if(kind.equals("external"))check(LayeredVpnService.discarded.get()==0,"successful native launch discarded its active session");
                owner.disconnect();awaitIdle(owner);
            }
        });
        test(kind+" terminal state whitelist",()->{
            try(Owner owner=new Owner(kind)) {
                Method m=owner.runtime().getClass().getDeclaredMethod("terminal",String.class);m.setAccessible(true);
                for(String state:new String[]{null,"","UNKNOWN","UP","STARTING","STOPPING"})check(!(Boolean)m.invoke(null,state),"accepted nonterminal state "+state);
                for(String state:new String[]{"DOWN","FAILED","REVOKED"," down "})check((Boolean)m.invoke(null,state),"rejected terminal state "+state);
            }
        });
        test(kind+" cancelled worker retains ownership",()->{
            try(Owner owner=new Owner(kind)) {
                Callback cb=new Callback(1);
                try {
                    owner.connect(cb);cb.awaitEntered();owner.disconnect();
                    check(owner.busy(),"cancelled Future was treated as finished while its worker was still running");
                    Callback replacement=new Callback(0);owner.connect(replacement);replacement.awaitDone();
                    check(!replacement.ok,"accepted a replacement while the cancelled worker was still alive");
                } finally {cb.release.countDown();cb.awaitDone();}
                awaitIdle(owner);
            }
        });
        test(kind+" queued cancellation before worker starts",()->{
            try(Owner owner=new Owner(kind)) {
                java.lang.reflect.Field f=owner.runtime().getClass().getDeclaredField("executor");f.setAccessible(true);
                java.util.concurrent.ExecutorService executor=(java.util.concurrent.ExecutorService)f.get(owner.runtime());
                CountDownLatch occupied=new CountDownLatch(1), release=new CountDownLatch(1);
                executor.submit(()->{occupied.countDown();try{release.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}});
                check(occupied.await(3,TimeUnit.SECONDS),"executor setup stalled");
                Callback cb=new Callback(0);
                try {owner.connect(cb);owner.disconnect();check(owner.busy(),"queued worker ownership was lost");}
                finally {release.countDown();cb.awaitDone();}
                check(!cb.ok&&owner.engine.starts.get()==0,"queued attempt launched after Disconnect");
                check(LayeredVpnService.mtuStarts.get()==0,"cancelled queued attempt launched MTU");awaitIdle(owner);
            }
        });
        test(kind+" Connected adoption cannot overtake Disconnect",()->{
            try(Owner owner=new Owner(kind)) {
                CountDownLatch entered=new CountDownLatch(1), release=new CountDownLatch(1);
                AndroidHomeStateStore.connectedEntered=entered;AndroidHomeStateStore.connectedRelease=release;
                Callback cb=new Callback(0);CountDownLatch finished=new CountDownLatch(1);
                java.util.concurrent.atomic.AtomicReference<Throwable> error=new java.util.concurrent.atomic.AtomicReference<>();
                Thread stop=new Thread(()->{try{owner.disconnect();}catch(Throwable t){error.set(t);}finally{finished.countDown();}});
                try {
                    owner.connect(cb);check(entered.await(3,TimeUnit.SECONDS),"Connected publication never started");
                    stop.start();finished.await(250,TimeUnit.MILLISECONDS);
                } finally {release.countDown();cb.awaitDone();}
                check(finished.await(3,TimeUnit.SECONDS),"disconnect remained blocked after publication completed");
                check(error.get()==null,"disconnect threw: "+error.get());
                check(!AndroidHomeStateStore.current.connected,"stale Connected write overtook completed Disconnect");
                awaitIdle(owner);
            }
        });
        if("multihop".equals(kind)) test("multihop MTU activation cannot escape captured adoption",()->{
            try(Owner owner=new Owner(kind)){
                CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1),stopping=new CountDownLatch(1),finished=new CountDownLatch(1);
                LayeredVpnService.mtuEntered=entered;LayeredVpnService.mtuRelease=release;
                Callback cb=new Callback(0);
                java.util.concurrent.atomic.AtomicReference<Throwable> failure=new java.util.concurrent.atomic.AtomicReference<>();
                Thread stop=new Thread(()->{stopping.countDown();try{owner.disconnect();}catch(Throwable e){failure.set(e);}finally{finished.countDown();}});
                try{
                    owner.connect(cb);check(entered.await(3,TimeUnit.SECONDS),"MTU adoption was never reached");
                    stop.start();check(stopping.await(3,TimeUnit.SECONDS),"disconnect was not attempted");
                    long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
                    while(stop.getState()!=Thread.State.BLOCKED&&finished.getCount()!=0&&System.nanoTime()<deadline)Thread.sleep(2);
                    check(stop.getState()==Thread.State.BLOCKED&&finished.getCount()!=0,"Disconnect completed outside the MTU adoption boundary");
                    check(AndroidHomeStateStore.current.connected,"Disconnect invalidated Home before captured activation completed");
                }finally{
                    release.countDown();
                    check(finished.await(3,TimeUnit.SECONDS),"disconnect did not complete after activation release");
                    cb.awaitDone();
                }
                check(failure.get()==null,"disconnect failed after adoption release");
                check(LayeredVpnService.mtuStarts.get()==1&&!AndroidHomeStateStore.current.connected,"stale activation/Connected survived Disconnect");
                awaitIdle(owner);
            }
        });
        test(kind+" cancellation before engine launch",()->{
            try(Owner owner=new Owner(kind)) {
                Callback cb=new Callback(2);
                try {owner.connect(cb);cb.awaitEntered();owner.disconnect();}
                finally {cb.release.countDown();cb.awaitDone();}
                check(owner.engine.starts.get()==0,"engine launched after Disconnect completed");
                check(!cb.ok,"cancelled attempt reported Connected");check(LayeredVpnService.mtuStarts.get()==0,"cancelled attempt launched MTU");awaitIdle(owner);
                if(kind.equals("external"))check(LayeredVpnService.discarded.get()==1,"cancellation leaked prepared private external files");
            }
        });
        test(kind+" partial start failure tears down",()->{
            try(Owner owner=new Owner(kind)) {
                owner.engine.failStart=true;Callback cb=new Callback(0);owner.connect(cb);cb.awaitDone();
                check(!cb.ok,"failed start reported success");
                check(owner.engine.stops.get()>0&&"DOWN".equals(owner.engine.state),"start threw after publishing engine ownership but cleanup was skipped");
                awaitIdle(owner);
                if(kind.equals("external"))check(LayeredVpnService.discarded.get()==1,"failed dispatched launch leaked its released external preparation");
            }
        });
        test(kind+" failed stop still reports failure",()->{
            try(Owner owner=new Owner(kind)) {
                owner.engine.startState="FAILED";owner.engine.failStop=true;
                Callback cb=new Callback(0);owner.connect(cb);cb.awaitDone();
                check(!cb.ok,"stop exception reported success");check(owner.busy(),"stop exception released unproved ownership");
                if(kind.equals("external"))check(LayeredVpnService.discarded.get()==0,"unconfirmed stop discarded live private session files");
            }
        });
        test(kind+" unknown engine state blocks start",()->{
            try(Owner owner=new Owner(kind)) {
                owner.engine.state="UNKNOWN";Callback cb=new Callback(0);owner.connect(cb);cb.awaitDone();
                check(owner.engine.starts.get()==0&&!cb.ok,"unknown engine state was treated as safe to replace");
            }
        });
    }

    static void externalTests(){
        test("unknown external protocol has no fallback owner",()->{try(Owner owner=new Owner("external")){AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.protocol="unowned";AndroidHomeStateStore.Snapshot before=AndroidHomeStateStore.current;Callback cb=new Callback(0);owner.external.connectDirect(e,cb);cb.awaitDone();check(!cb.ok&&owner.engine.starts.get()==0&&LayeredVpnService.externalReads.get()==0&&publicProofs.get()==0,"unowned protocol reached a fallback graph or proof");check(AndroidHomeStateStore.current==before,"unowned protocol created a pending Home session");awaitIdle(owner);}});
        test("ordinary external requires its native DNS and entry proof",()->{try(Owner owner=new Owner("external")){LayeredVpnService.externalHealthy=false;Callback cb=new Callback(0);owner.connect(cb);cb.awaitDone();check(!cb.ok&&!AndroidHomeStateStore.current.connected&&owner.engine.stops.get()>0&&publicProofs.get()==0,"missing native proof fell back to a public-IP-only check");awaitIdle(owner);}});
        test("ordinary external stale Home response cannot overwrite replacement",()->{try(Owner owner=new Owner("external")){Callback cb=new Callback(3);try{owner.connect(cb);cb.awaitEntered();AndroidHomeStateStore.Snapshot replacement=new AndroidHomeStateStore.Snapshot();replacement.sessionId="new-session";replacement.phase="new-owner";AndroidHomeStateStore.current=replacement;}finally{cb.release.countDown();cb.awaitDone();}check(!cb.ok&&AndroidHomeStateStore.current.sessionId.equals("new-session")&&AndroidHomeStateStore.current.phase.equals("new-owner"),"stale ordinary completion overwrote a replacement owner");}});
        test("ordinary external freezes entry before queued work",()->{try(Owner owner=new Owner("external")){java.lang.reflect.Field f=owner.runtime().getClass().getDeclaredField("executor");f.setAccessible(true);java.util.concurrent.ExecutorService executor=(java.util.concurrent.ExecutorService)f.get(owner.runtime());CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);executor.submit(()->{entered.countDown();try{release.await();}catch(Exception e){throw new AssertionError(e);}});check(entered.await(3,TimeUnit.SECONDS),"queue did not block");AndroidExternalPolicy.entryVersion="original";Callback cb=new Callback(0);owner.external.connect(new java.io.File("a".repeat(32)+".json"),new AndroidStandardExitStore.Entry(),"wg",cb);AndroidExternalPolicy.entryVersion="replacement";release.countDown();cb.awaitDone();check(!cb.ok&&owner.engine.starts.get()==0&&LayeredVpnService.externalReads.get()==0,"queued source replacement started a native graph");awaitIdle(owner);}});
        for(String mode:new String[]{"external","wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","naive-h2","naive-h3","reality-vision","reality-pq-vision","reality-xhttp","ss-v2ray","split","max","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"})for(boolean proof:new boolean[]{false,true})test("OpenVPN captured native policy "+mode+"/"+proof,()->{
            try(Owner owner=new Owner("external")){AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.protocol="openvpn";LayeredVpnService.externalHealthy=proof;Callback cb=new Callback(0);
                if(mode.equals("external"))owner.external.connectDirect(e,cb);else owner.external.connect(new java.io.File("a".repeat(32)+".json"),e,mode,cb);cb.awaitDone();
                check(cb.ok==proof&&AndroidHomeStateStore.current.connected==proof,"OpenVPN ignored its exact captured native proof");check(publicProofs.get()==0&&LayeredVpnService.externalReads.get()>0,"OpenVPN fell back to the retired public-IP-only adapter");
                if(proof){check(AndroidHomeStateStore.current.activeExternalProtocol.equals("openvpn"),"OpenVPN borrowed another external identity");if(!mode.equals("external"))check(mode.equals(AndroidStandardExitController.lastEntryMode)&&mode.equals(AndroidHomeStateStore.current.activeEntryMode),"OpenVPN replaced its selected native entry");owner.disconnect();}else check(owner.engine.stops.get()>0,"failed OpenVPN proof left its native runtime alive");awaitIdle(owner);
            }
        });
        test("OpenVPN cancellation cannot publish a stale proof",()->{try(Owner owner=new Owner("external")){AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.protocol="openvpn";Callback cb=new Callback(3);try{owner.external.connectDirect(e,cb);cb.awaitEntered();owner.disconnect();}finally{cb.release.countDown();cb.awaitDone();}check(!cb.ok&&!AndroidHomeStateStore.current.connected&&publicProofs.get()==0,"cancelled OpenVPN proof was adopted");awaitIdle(owner);}});
    }
    static AndroidStandardExitStore.Entry torEntry(){AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.protocol="tor-bridge";e.expectedPublicIp="";return e;}
    static void torTests(){
        for(String mode:new String[]{"wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","naive-h2","naive-h3","reality-vision","reality-pq-vision","reality-xhttp","ss-v2ray","split","max","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"})test("Tor exact entry "+mode,()->{
            try(Owner owner=new Owner("tor")){Callback cb=new Callback(0);owner.external.connect(new java.io.File("a".repeat(32)+".json"),torEntry(),mode,cb);cb.awaitDone();
                check(cb.ok&&mode.equals(AndroidStandardExitController.lastEntryMode)&&mode.equals(AndroidHomeStateStore.current.activeEntryMode),"Tor entry was replaced with default WG");check(publicProofs.get()==0,"Tor borrowed fixed-IP proof");owner.disconnect();awaitIdle(owner);}
        });
        test("Tor late underlying UP cannot adopt after cancel",()->{
            try(Owner owner=new Owner("tor")){owner.engine.startState="STARTING";Callback cb=new Callback(0);owner.connect(cb);long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);while(owner.engine.starts.get()==0&&System.nanoTime()<deadline)Thread.sleep(2);
                check(owner.engine.starts.get()==1&&!AndroidHomeStateStore.current.connected,"Tor connected before native proof");owner.disconnect();cb.awaitDone();check(!cb.ok&&LayeredVpnService.torReads.get()==0,"cancelled native startup reached Connected");awaitIdle(owner);}
        });
        test("Tor missing native owner fails closed",()->{
            try(Owner owner=new Owner("tor")){LayeredVpnService.torHealthy=false;Callback cb=new Callback(0);owner.connect(cb);cb.awaitDone();check(!cb.ok&&!AndroidHomeStateStore.current.connected&&owner.engine.stops.get()>0,"unproven native Tor owner admitted");check(publicProofs.get()==0,"missing native proof substituted public IP");awaitIdle(owner);}
        });
        test("Tor stale Home completion cannot overwrite replacement",()->{
            try(Owner owner=new Owner("tor")){Callback cb=new Callback(3);try{owner.connect(cb);cb.awaitEntered();AndroidHomeStateStore.Snapshot replacement=new AndroidHomeStateStore.Snapshot();replacement.sessionId="new-session";replacement.phase="new-owner";AndroidHomeStateStore.current=replacement;}finally{cb.release.countDown();cb.awaitDone();}
                check(!cb.ok&&AndroidHomeStateStore.current.sessionId.equals("new-session")&&AndroidHomeStateStore.current.phase.equals("new-owner"),"late Tor failure overwrote a new Home owner");}
        });
        test("Tor request freezes saved exit before queued work",()->{
            try(Owner owner=new Owner("tor")){java.lang.reflect.Field f=owner.runtime().getClass().getDeclaredField("executor");f.setAccessible(true);java.util.concurrent.ExecutorService executor=(java.util.concurrent.ExecutorService)f.get(owner.runtime());CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);executor.submit(()->{entered.countDown();try{release.await();}catch(Exception e){throw new AssertionError(e);}});check(entered.await(3,TimeUnit.SECONDS),"queue did not block");
                AndroidStandardExitStore.Entry original=torEntry();Callback cb=new Callback(0);owner.external.connectDirect(original,cb);original.protocol="socks5";original.expectedPublicIp="1.1.1.1";release.countDown();cb.awaitDone();check(cb.ok&&AndroidDirectStandardExitController.lastProtocol.equals("tor-bridge")&&publicProofs.get()==0,"queued request re-read mutable exit credentials");owner.disconnect();awaitIdle(owner);}
        });
    }
    public static void main(String[] args) {
        // A deterministic fake of the public-exit provider. No real sockets,
        // DNS requests, VPN engines, or external services are used by this test.
        URL.setURLStreamHandlerFactory(protocol -> "https".equals(protocol)?new URLStreamHandler(){
            protected URLConnection openConnection(URL u){return openConnection(u,Proxy.NO_PROXY);}
            protected URLConnection openConnection(URL u,Proxy p){return new HttpURLConnection(u){
                public void connect(){}public void disconnect(){}public boolean usingProxy(){return true;}
                public int getResponseCode(){publicProofs.incrementAndGet();return 200;}
                public InputStream getInputStream(){return new ByteArrayInputStream("1.1.1.1".getBytes(StandardCharsets.US_ASCII));}
            };}
        }:null);
        if(args.length==0){tests("multihop");tests("external");tests("tor");}
        else for(String kind:args)tests(kind);
        if(!failures.isEmpty()){for(String s:failures)System.err.println(s);System.exit(1);}
    }
}
'''

# Engine operations are doubled, but the mode predicates are copied verbatim
# from shipping source so this lifecycle harness cannot drift into a separate
# capability allowlist. Runtime source files themselves are never rewritten.
controller_source = (JAVA / 'NativeSingBoxController.java').read_text()
predicates = []
for name in ('nativeWireGuardFamily', 'nativePQFamily', 'nativeNaiveFamily', 'nativeMultihopEntry'):
    matches = re.findall(r'(?ms)^    static boolean ' + name + r'\(String mode\) \{\n.*?^    \}', controller_source)
    assert len(matches) == 1, 'missing or ambiguous production transport predicate: ' + name
    predicates.append(matches[0])
STUBS = STUBS.replace('    // PRODUCTION_TRANSPORT_PREDICATES', '\n'.join(predicates))
external_source = (JAVA / 'AndroidExternalPolicy.java').read_text()
external_predicate = re.findall(r'(?ms)^    static boolean supports\(String protocol\) \{\n.*?^    \}', external_source)
assert len(external_predicate) == 1, 'missing exact external capability predicate'
STUBS = STUBS.replace('    // PRODUCTION_EXTERNAL_PREDICATE', external_predicate[0])
composite_source = (JAVA / 'AndroidNativeCompositeProfile.java').read_text()
composite_predicate = re.findall(r'(?ms)^    static boolean isMode\(String mode\) \{\n.*?^    \}', composite_source)
assert len(composite_predicate) == 1, 'missing exact composite transport predicate'
STUBS += '\nfinal class AndroidNativeCompositeProfile {\n' + composite_predicate[0] + '\n}\n'

with tempfile.TemporaryDirectory(prefix='routervpn-runtime-teardown-') as tmp:
    base=Path(tmp); pkg=base/'com/eabusham/routervpn';pkg.mkdir(parents=True)
    for name in ('AndroidMultihopRuntime.java','AndroidStandardExitRuntime.java'):
        shutil.copyfile(JAVA/name,pkg/name)
    (pkg/'LifecycleStubs.java').write_text(STUBS,encoding='utf-8')
    (pkg/'RuntimeTeardownHarness.java').write_text(HARNESS,encoding='utf-8')
    context=base/'android/content/Context.java';context.parent.mkdir(parents=True)
    context.write_text('package android.content; public class Context { public Context getApplicationContext() {return this;} }',encoding='utf-8')
    for package in ('com.wireguard.android.backend','org.amnezia.awg.backend'):
        path=base/Path(package.replace('.','/'))/'Tunnel.java';path.parent.mkdir(parents=True)
        path.write_text('package '+package+'; public interface Tunnel { enum State { UP, DOWN, TOGGLE } }',encoding='utf-8')
    classes=base/'classes';classes.mkdir()
    subprocess.run([javac,'-encoding','UTF-8','-d',str(classes),*[str(p) for p in base.rglob('*.java')]],check=True,timeout=30)
    subprocess.run([java,'-cp',str(classes),'com.eabusham.routervpn.RuntimeTeardownHarness',*TARGETS],check=True,timeout=90)
print('Android actual-runtime teardown behavior: PASS')
