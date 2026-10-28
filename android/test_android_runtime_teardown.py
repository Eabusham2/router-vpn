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
    volatile Runnable duringStop;
    final AtomicInteger starts = new AtomicInteger(), stops = new AtomicInteger();
    String getState() { return state; }
    String getMode() { return mode; }
    String getError() { return "injected engine failure"; }
    void start(SessionInfo session) {
        starts.incrementAndGet(); state = startState; mode = "standard-test";
        if (failStart) throw new IllegalStateException("start failed after engine ownership publication");
    }
    void startTorComparison(SessionInfo session){start(session);}
    void startExternal(SessionInfo session,String homeSession) {
        if(!homeSession.equals(AndroidHomeStateStore.current.sessionId))throw new AssertionError("Native launch lost its exact Home owner");
        start(session);
    }
    void stop() {
        stops.incrementAndGet();
        if(duringStop!=null)duringStop.run();
        if (failStop) throw new IllegalStateException("stop request failed");
        state = "DOWN";
    }
}
final class LayeredVpnService {
    static String selectedOverride="",serverPins="{}";static boolean staleCapture;
    static final class CapturedMultihop {
        final String homeSession,entryId,exitId,entryMode,exitMode,execution,serverIdentityPins;final long generation;
        CapturedMultihop(String session){AndroidHomeStateStore.Snapshot h=AndroidHomeStateStore.current;homeSession=session;entryId=h.activeEntryId;exitId=h.activeExitId;entryMode=h.activeEntryMode;exitMode=h.runtimeMode;generation=h.pathGeneration;execution=capturedMultihopExecution(session);serverIdentityPins=serverPins;}
        boolean matchesHome(AndroidHomeStateStore.Snapshot h){return !staleCapture&&h.connected&&homeSession.equals(h.sessionId)&&generation==h.pathGeneration&&entryId.equals(h.activeEntryId)&&exitId.equals(h.activeExitId)&&entryMode.equals(h.activeEntryMode)&&exitMode.equals(h.runtimeMode);}
        boolean sameOwner(CapturedMultihop other){return other!=null&&!staleCapture&&homeSession.equals(other.homeSession)&&generation==other.generation&&execution.equals(other.execution)&&serverIdentityPins.equals(other.serverIdentityPins);}
    }
    static CapturedMultihop capturedMultihop(String session){return new CapturedMultihop(session);}
    static String capturedMultihopExecution(String session){if(!session.equals(AndroidHomeStateStore.current.sessionId))throw new IllegalStateException("stale native graph");return selectedOverride.isEmpty()?(AndroidMultihopController.lastExecution.equals("auto")?"server":AndroidMultihopController.lastExecution):selectedOverride;}
    static final AtomicInteger discarded=new AtomicInteger();
    static boolean discardPreparedSession(Context context,String session){if(!"native-session".equals(session))throw new AssertionError("Discarded wrong session");discarded.incrementAndGet();return true;}
    static final AtomicInteger externalReads=new AtomicInteger();static volatile boolean externalHealthy=true;
    static String externalExecution(String session,String exit){return "local";}
    static final AtomicInteger torExecutionReads=new AtomicInteger();static String torExecutionOverride="";
    static String torExecution(String session,String exit){torExecutionReads.incrementAndGet();if(!torHealthy||!"native-session".equals(session)||!"external".equals(exit))throw new IllegalStateException("wrong captured Tor execution");return torExecutionOverride.isEmpty()?(AndroidStandardExitController.lastExecution.isEmpty()?"local":AndroidStandardExitController.lastExecution):torExecutionOverride;}
    static String externalExitIP(String session,String exit){externalReads.incrementAndGet();if(!externalHealthy||!"native-session".equals(session)||!"external".equals(exit))throw new IllegalStateException("wrong captured external owner");return "1.1.1.1";}
    static final AtomicInteger torReads=new AtomicInteger();static volatile boolean torHealthy=true;
    static String torExitIP(String session,String exit){torReads.incrementAndGet();if(!torHealthy||!"native-session".equals(session)||!"external".equals(exit))throw new IllegalStateException("wrong captured Tor owner");return "8.8.4.4";}
    static final AtomicInteger mtuStarts = new AtomicInteger();
    static void startExternalAutomaticMTU(String session,String exit,String home){
        if(!"native-session".equals(session)||!"external".equals(exit)||!home.equals(AndroidHomeStateStore.current.sessionId))throw new AssertionError("MTU substituted its captured external or Home owner");
        startAutomaticMTU();
    }
    static void startTorAutomaticMTU(String session,String exit,String home){startExternalAutomaticMTU(session,exit,home);}
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
    static java.util.Set<String> changedSources=new java.util.HashSet<>();static String lastPins="";
    static String validatedServerIdentityPins(String execution,String mode,String pins){if(pins==null)throw new IllegalStateException("pins absent");return pins;}
    static final class Source {final File file;final String digest;Source(File file){this.file=file;digest=file.getPath();}void require(File candidate){if(!file.equals(candidate)||changedSources.contains(file.getPath()))throw new IllegalStateException("changed captured node");}boolean same(Source other){return other!=null&&file.equals(other.file)&&digest.equals(other.digest);}}
    static final class Prepared {
        final NativeSingBoxController.SessionInfo session = new NativeSingBoxController.SessionInfo();
        final File exitBundle; final String exitMode;
        final Source entrySource,exitSource;
        Prepared(File entry,File exit, String mode) { exitBundle=exit; exitMode=mode;entrySource=new Source(entry);exitSource=new Source(exit); }
    }
    Prepared prepare(File entry,File exit,String mode,String execution,String entryMode,Source a,Source b,String pins){a.require(entry);b.require(exit);lastPins=pins;return prepare(entry,exit,mode,execution,entryMode);}
    AndroidMultihopController(Context c, NativeSingBoxController s) {}
    List<NativeSingBoxController.ModeInfo> listSupportedExitModes(File f) { return Collections.emptyList(); }
    static volatile String lastExecution = "", lastEntryMode = "";
    Prepared prepare(File entry, File exit, String mode) { return prepare(entry,exit,mode,"local","wg"); }
    Prepared prepare(File entry, File exit, String mode, String execution, String entryMode) {
        lastExecution=execution; lastEntryMode=entryMode; return new Prepared(entry,exit,mode);
    }
}
final class AndroidStandardExitStore {
    static final java.util.Map<String,Entry> saved=new java.util.concurrent.ConcurrentHashMap<>();
    AndroidStandardExitStore(Context c){} Entry get(String id){Entry e=saved.get(id);if(e==null)throw new IllegalArgumentException("missing captured provider");return copy(e);}
    static String snapshot(Entry e){return e.id+"\n"+e.name+"\n"+e.protocol+"\n"+e.expectedPublicIp;}
    static final class Entry {
        String id="external", name="external", protocol="socks5", expectedPublicIp="1.1.1.1";
    }
    static Entry copy(Entry entry){Entry e=new Entry();e.id=entry.id;e.name=entry.name;e.protocol=entry.protocol;e.expectedPublicIp=entry.expectedPublicIp;return e;}
    static void validate(Entry entry){}
    static void validateExecution(Entry entry,boolean hasEntry,String execution){if(!java.util.Arrays.asList("local","server","auto").contains(execution))throw new IllegalArgumentException("execution");}
}
final class AndroidTorProfile {
 static int ordinaryPreparations;static AndroidStandardExitStore.Entry lastOrdinary;static Runnable beforePrepared;
 static boolean isTor(String protocol){return "tor".equals(protocol)||"tor-bridge".equals(protocol);}
 static NativeSingBoxController.SessionInfo prepareOrdinary(Context c,AndroidStandardExitStore.Entry entry,AndroidStandardExitStore.Entry exit,String execution){if(!execution.equals("local")||!isTor(exit.protocol))throw new AssertionError("ordinary boundary acquired private authority");ordinaryPreparations++;lastOrdinary=AndroidStandardExitStore.copy(entry);if(beforePrepared!=null)beforePrepared.run();return new NativeSingBoxController.SessionInfo();}
}
final class AndroidExternalPolicy {static String protocol(String p){return p.equals("http")?"http-connect":p.equals("https")?"https-connect":p;}static volatile String entryVersion="captured-entry";static String entryDigest(File file){return entryVersion;}
    // PRODUCTION_EXTERNAL_PREDICATE
}
final class AndroidStandardExitController {
    static volatile String lastEntryMode="",lastProtocol="",lastExecution="";
    AndroidStandardExitController(Context c) {}
    NativeSingBoxController.SessionInfo prepare(File f, AndroidStandardExitStore.Entry e) { return new NativeSingBoxController.SessionInfo(); }
    NativeSingBoxController.SessionInfo prepare(File f, AndroidStandardExitStore.Entry e,String mode,String execution,String restored){lastExecution=restored.isEmpty()?execution:restored;return prepare(f,e,mode);}
    NativeSingBoxController.SessionInfo prepare(File f, AndroidStandardExitStore.Entry e,String mode) {lastEntryMode=mode;lastProtocol=e.protocol;return prepare(f,e); }
}
// This unrelated runtime suite keeps the coordinator as an explicit boundary.
// Actual Compare host/service lifecycle is executed by test_android_tor_compare.py.
final class AndroidTorCompareRuntime {
 interface Owner{boolean current();void requireSource()throws Exception;void launch(NativeSingBoxController.SessionInfo s)throws Exception;void progress(String s);}
 static int runs,closes,cancels;static boolean failRun,failClose;static String chosen="server";private final Owner owner;
 AndroidTorCompareRuntime(Context c,File f,AndroidStandardExitStore.Entry e,String m,String h,String d,Owner o){owner=o;}
 NativeSingBoxController.SessionInfo run()throws Exception{runs++;owner.requireSource();NativeSingBoxController.SessionInfo s=new NativeSingBoxController.SessionInfo();owner.launch(s);LayeredVpnService.torExecutionOverride=chosen;if(failRun)throw new Exception("comparison probes failed");return s;}
 void cancel(){cancels++;}void close()throws Exception{closes++;if(failClose)throw new Exception("comparison native owner still retained");}
}
final class AndroidDirectStandardExitController {
    static volatile String lastProtocol="";
    AndroidDirectStandardExitController(Context c) {}
    NativeSingBoxController.SessionInfo prepare(AndroidStandardExitStore.Entry e) {lastProtocol=e.protocol;return new NativeSingBoxController.SessionInfo(); }
}
// Actual record serialization and source validation run in the startup suite.
// This boundary checks the shipping runtime's proof/transaction/call ordering.
final class AndroidStartupPolicy {
 static Object runtimeLock;static int prepared,writes;static TorLast last;static Runnable onPrepare;
 static final class TorLast{final String entryMode,requested,selected,digest;TorLast(String m,String r,String s,String d){entryMode=m;requested=r;selected=s;digest=d;}}
 static void reset(Object owner){runtimeLock=owner;prepared=0;writes=0;last=null;onPrepare=null;}
 static TorLast prepareTorExecution(Context c,File file,AndroidStandardExitStore.Entry exit,String mode,String requested,String selected,String digest){
  if(Thread.holdsLock(runtimeLock)||Thread.holdsLock(AndroidHomeStateStore.class))throw new AssertionError("private Last preparation ran under native/Home lock");
  if(file==null||!AndroidTorProfile.isTor(exit.protocol)||!java.util.List.of("local","server").contains(selected)||LayeredVpnService.torReads.get()==0)throw new AssertionError("Last preparation has no captured native proof");
  prepared++;if(onPrepare!=null)onPrepare.run();return new TorLast(mode,requested,selected,digest);
 }
 static boolean recordTorExecution(Context c,TorLast record,AndroidHomeStateStore.Snapshot owner){
  if(record==null)return false;
  if(!Thread.holdsLock(runtimeLock)||owner!=AndroidHomeStateStore.current||!owner.connected||!owner.phase.equals("connected")||!LayeredVpnService.torHealthy)return false;
  writes++;last=record;return true;
 }
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
        s.activeEntryId=entry; s.activeEntryMode=entryMode; s.activeExitId=exit; s.runtimeMode=mode; s.sessionId="multi-session"; current=s; return s.sessionId;
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
import java.io.File;
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
        final int blockAt; int progressCalls; volatile boolean ok;volatile String homeOwner="";int ownerCalls;
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
        public void owned(String session) {homeOwner=session;ownerCalls++;}
        void awaitEntered() throws Exception { check(entered.await(3,TimeUnit.SECONDS),"worker never reached requested checkpoint"); }
        void awaitDone() throws Exception { check(done.await(3,TimeUnit.SECONDS),"worker failed without delivering a completion callback"); }
    }
    static final class Owner implements AutoCloseable {
        final Context context=new Context(); final NativeSingBoxController engine=new NativeSingBoxController();
        final AndroidMultihopRuntime multihop; final AndroidStandardExitRuntime external;
        final String kind;
        Owner(String kind) {
            this.kind=kind;AndroidTorCompareRuntime.runs=0;AndroidTorCompareRuntime.closes=0;AndroidTorCompareRuntime.cancels=0;AndroidTorCompareRuntime.failRun=false;AndroidTorCompareRuntime.failClose=false;AndroidTorCompareRuntime.chosen="server";AndroidStandardExitStore.saved.clear();AndroidTorProfile.ordinaryPreparations=0;AndroidTorProfile.lastOrdinary=null;AndroidTorProfile.beforePrepared=null;LayeredVpnService.selectedOverride="";LayeredVpnService.serverPins="{}";LayeredVpnService.staleCapture=false;AndroidMultihopController.changedSources.clear();AndroidMultihopController.lastPins="";LayeredVpnService.torReads.set(0);LayeredVpnService.torExecutionReads.set(0);LayeredVpnService.torExecutionOverride="";AndroidStandardExitController.lastExecution="";LayeredVpnService.torHealthy=true;publicProofs.set(0);
            LayeredVpnService.externalReads.set(0);LayeredVpnService.externalHealthy=true;
            LayeredVpnService.discarded.set(0);
            AndroidHomeStateStore.reset(); LayeredVpnService.mtuStarts.set(0); LayeredVpnService.mtuEntered=null;LayeredVpnService.mtuRelease=null;
            multihop="multihop".equals(kind)?new AndroidMultihopRuntime(context,engine):null;
            external=multihop==null?new AndroidStandardExitRuntime(context,engine):null;
            AndroidStartupPolicy.reset(external);
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
    static AndroidStandardExitStore.Entry ordinary(String protocol){AndroidStandardExitStore.Entry value=new AndroidStandardExitStore.Entry();value.id="ordinary-entry";value.protocol=protocol;value.name="provider-only source";AndroidStandardExitStore.saved.put(value.id,AndroidStandardExitStore.copy(value));return value;}
    static AndroidStandardExitStore.Entry torExit(){AndroidStandardExitStore.Entry value=new AndroidStandardExitStore.Entry();value.protocol="tor-bridge";value.expectedPublicIp="";AndroidStandardExitStore.saved.put(value.id,AndroidStandardExitStore.copy(value));return value;}
    static void ordinaryTorTests(){
        for(String protocol:new String[]{"wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn"})test("ordinary "+protocol+" → Tor owns native preparation and proof",()->{
            try(Owner owner=new Owner("tor")){AndroidStandardExitStore.Entry entry=ordinary(protocol),exit=torExit();String source=AndroidStandardExitStore.snapshot(entry);Callback cb=new Callback(0);owner.external.connectOrdinary(entry,exit,"local",cb);cb.awaitDone();
                check(cb.ok&&owner.engine.starts.get()==1&&AndroidTorProfile.ordinaryPreparations==1,"ordinary path failed to launch its one captured native graph");
                AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.current;
                check(home.activeEntryId.equals(entry.id)&&home.activeEntryMode.equals(AndroidExternalPolicy.protocol(protocol))&&home.activeExternalId.equals(exit.id),"ordinary native owner changed typed path identity");
                check(LayeredVpnService.torReads.get()>=2&&LayeredVpnService.mtuStarts.get()==1&&publicProofs.get()==0,"ordinary Tor bypassed native proof or MTU ownership");
                AndroidStandardExitStore.Entry captured=owner.external.capturedOrdinaryEntry(home);check(source.equals(AndroidStandardExitStore.snapshot(captured)),"ordinary runtime failed exact source capture");captured.name="caller mutation";check(source.equals(AndroidStandardExitStore.snapshot(owner.external.capturedOrdinaryEntry(home))),"ordinary runtime exposed mutable source authority");
                check(owner.external.capturedExternalExecution(home).equals("local")&&owner.external.capturedRequestedExecution(home).equals("local"),"ordinary runtime borrowed server execution");
                owner.disconnect();awaitIdle(owner);boolean rejected=false;try{owner.external.capturedOrdinaryEntry(home);}catch(Exception expected){rejected=true;}check(rejected,"closed ordinary proof still authorized source capture");
            }
        });
        for(String fault:new String[]{"entry-replaced","entry-removed","exit-replaced","exit-removed","cancel"})test("ordinary Tor preparation rejects "+fault,()->{
            try(Owner owner=new Owner("tor")){AndroidStandardExitStore.Entry entry=ordinary("socks5"),exit=torExit();Callback cb=new Callback(1);owner.external.connectOrdinary(entry,exit,"local",cb);cb.awaitEntered();
                try{if(fault.equals("entry-replaced")){entry.name+=" replacement";AndroidStandardExitStore.saved.put(entry.id,entry);}if(fault.equals("entry-removed"))AndroidStandardExitStore.saved.remove(entry.id);if(fault.equals("exit-replaced")){exit.name+=" replacement";AndroidStandardExitStore.saved.put(exit.id,exit);}if(fault.equals("exit-removed"))AndroidStandardExitStore.saved.remove(exit.id);if(fault.equals("cancel"))owner.disconnect();}finally{cb.release.countDown();}
                cb.awaitDone();check(!cb.ok&&owner.engine.starts.get()==0&&!AndroidHomeStateStore.current.connected,"changed ordinary source or cancelled owner reached engine start");check(LayeredVpnService.discarded.get()==1,"failed ordinary preparation leaked its staged session");awaitIdle(owner);
            }
        });
        for(String fault:new String[]{"source","cancel"})test("ordinary Tor queued request rejects "+fault,()->{
            try(Owner owner=new Owner("tor")){AndroidStandardExitStore.Entry entry=ordinary("socks5"),exit=torExit();java.lang.reflect.Field field=AndroidStandardExitRuntime.class.getDeclaredField("executor");field.setAccessible(true);java.util.concurrent.ExecutorService executor=(java.util.concurrent.ExecutorService)field.get(owner.external);
                CountDownLatch occupied=new CountDownLatch(1),release=new CountDownLatch(1);executor.submit(()->{occupied.countDown();try{release.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}});check(occupied.await(3,TimeUnit.SECONDS),"ordinary queue was not held");
                Callback cb=new Callback(0);try{owner.external.connectOrdinary(entry,exit,"local",cb);if(fault.equals("source")){entry.name+=" replaced";AndroidStandardExitStore.saved.put(entry.id,entry);}else owner.disconnect();}finally{release.countDown();}cb.awaitDone();check(!cb.ok&&AndroidTorProfile.ordinaryPreparations==0&&owner.engine.starts.get()==0,"changed queued source reached native preparation");awaitIdle(owner);
            }
        });
        for(String fault:new String[]{"entry","exit"})test("ordinary Tor late proof rejects changed "+fault,()->{
            try(Owner owner=new Owner("tor")){AndroidStandardExitStore.Entry entry=ordinary("socks5"),exit=torExit();Callback cb=new Callback(3);owner.external.connectOrdinary(entry,exit,"local",cb);cb.awaitEntered();
                try{AndroidStandardExitStore.Entry changed=fault.equals("entry")?entry:exit;changed.name+=" replaced while proving";AndroidStandardExitStore.saved.put(changed.id,changed);}finally{cb.release.countDown();}
                cb.awaitDone();check(!cb.ok&&owner.engine.starts.get()==1&&owner.engine.stops.get()==1&&!AndroidHomeStateStore.current.connected,"late ordinary proof adopted replaced source");check(LayeredVpnService.mtuStarts.get()==0&&LayeredVpnService.discarded.get()==1,"late ordinary source loss retained MTU or staged owner");awaitIdle(owner);
            }
        });
        for(String fault:new String[]{"server","auto","duplicate","wrong-exit","tor-entry"})test("ordinary Tor rejects invalid authority "+fault,()->{
            try(Owner owner=new Owner("tor")){AndroidStandardExitStore.Entry entry=ordinary("socks5"),exit=torExit();if(fault.equals("duplicate"))exit.id=entry.id;if(fault.equals("wrong-exit"))exit.protocol="socks5";if(fault.equals("tor-entry"))entry.protocol="tor";Callback cb=new Callback(0);owner.external.connectOrdinary(entry,exit,fault.equals("server")||fault.equals("auto")?fault:"local",cb);cb.awaitDone();check(!cb.ok&&owner.engine.starts.get()==0&&AndroidTorProfile.ordinaryPreparations==0,"ordinary input acquired unavailable path authority");}
        });
    }
    static void torCompareRuntimeTests(){
        for(String selected:new String[]{"local","server"})test("Tor Compare owns the proved "+selected+" leaf and original auto preference",()->{
            try(Owner owner=new Owner("tor")){AndroidTorCompareRuntime.chosen=selected;AndroidStandardExitStore.Entry exit=torExit();Callback cb=new Callback(0);owner.external.connect(new File("a".repeat(32)+".json"),exit,"max-tls-awg","auto",cb);cb.awaitDone();
                check(cb.ok&&AndroidTorCompareRuntime.runs==1&&owner.engine.starts.get()==1,"Tor auto did not use captured coordinator");check(owner.external.capturedRequestedExecution(AndroidHomeStateStore.current).equals("auto")&&owner.external.capturedExternalExecution(AndroidHomeStateStore.current).equals(selected),"Tor preference/actual execution conflated");check(LayeredVpnService.mtuStarts.get()==1&&cb.ownerCalls==1,"trial or unproved owner adopted Connected/MTU");owner.disconnect();awaitIdle(owner);}
        });
        for(String selected:new String[]{"local","server"})test("Tor auto restoration retains "+selected+" without rerunning selection",()->{
            try(Owner owner=new Owner("tor")){Callback cb=new Callback(0);owner.external.restoreCaptured(new File("a".repeat(32)+".json"),torExit(),"reality-xhttp","auto",selected,cb);cb.awaitDone();check(cb.ok&&AndroidTorCompareRuntime.runs==0&&AndroidStandardExitController.lastExecution.equals(selected),"restoration reran Compare or changed leaf");check(owner.external.capturedRequestedExecution(AndroidHomeStateStore.current).equals("auto"),"restoration discarded original preference");owner.disconnect();awaitIdle(owner);}
        });
        test("Tor Compare partial failure stops and joins its exact owner",()->{
            try(Owner owner=new Owner("tor")){AndroidTorCompareRuntime.failRun=true;Callback cb=new Callback(0);owner.external.connect(new File("a".repeat(32)+".json"),torExit(),"wg","auto",cb);cb.awaitDone();check(!cb.ok&&owner.engine.stops.get()>0&&AndroidTorCompareRuntime.cancels>0&&AndroidTorCompareRuntime.closes>0&&!AndroidHomeStateStore.current.connected,"partial Compare lost native cleanup");awaitIdle(owner);}
        });
        test("Tor Compare unacknowledged drain remains busy until retry",()->{
            try(Owner owner=new Owner("tor")){AndroidTorCompareRuntime.failRun=true;AndroidTorCompareRuntime.failClose=true;Callback cb=new Callback(0);owner.external.connect(new File("a".repeat(32)+".json"),torExit(),"wg","auto",cb);cb.awaitDone();check(!cb.ok&&owner.busy()&&!AndroidHomeStateStore.current.connected,"failed Compare drain released runtime");AndroidTorCompareRuntime.failClose=false;owner.disconnect();awaitIdle(owner);}
        });
    }
    static void torLastRuntimeTests(){
        for(String selected:new String[]{"local","server"})test("Tor Last records only the actual proved "+selected+" winner",()->{
            try(Owner owner=new Owner("tor")){AndroidTorCompareRuntime.chosen=selected;AndroidStandardExitStore.Entry exit=torExit();Callback cb=new Callback(0);owner.external.connect(new File("a".repeat(32)+".json"),exit,"max-tls-awg","auto",cb);cb.awaitDone();
                check(cb.ok&&AndroidStartupPolicy.prepared==1&&AndroidStartupPolicy.writes==1,"successful Tor path did not record exactly one proved Last winner");var record=AndroidStartupPolicy.last;
                check(record.selected.equals(selected)&&record.requested.equals("auto")&&record.entryMode.equals("max-tls-awg")&&record.digest.equals(AndroidExternalPolicy.entryVersion),"Tor Last receipt lost captured policy, source or actual execution");owner.disconnect();awaitIdle(owner);}
        });
        for(String selected:new String[]{"local","server"})test("Tor Last restoration does not replace historical receipt "+selected,()->{
            try(Owner owner=new Owner("tor")){Callback cb=new Callback(0);owner.external.restoreCaptured(new File("a".repeat(32)+".json"),torExit(),"wg","auto",selected,cb);cb.awaitDone();check(cb.ok&&AndroidStartupPolicy.prepared==0&&AndroidStartupPolicy.writes==0&&AndroidTorCompareRuntime.runs==0,"Tor restored path overwrote Last history or reran Compare");owner.disconnect();awaitIdle(owner);}
        });
        test("Tor Last captures temporary transaction before queued startup",()->{
            try(Owner owner=new Owner("tor")){var field=AndroidStandardExitRuntime.class.getDeclaredField("executor");field.setAccessible(true);var executor=(java.util.concurrent.ExecutorService)field.get(owner.external);CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
                executor.submit(()->{entered.countDown();try{release.await();}catch(Exception e){throw new AssertionError(e);}});check(entered.await(3,TimeUnit.SECONDS),"queued temporary owner did not block");Object lease=AndroidMTUMeasurementGate.acquire();Callback cb=new Callback(0);
                try{owner.external.connect(new File("a".repeat(32)+".json"),torExit(),"wg","auto",cb);}finally{AndroidMTUMeasurementGate.release(lease);release.countDown();}cb.awaitDone();
                check(cb.ok&&AndroidStartupPolicy.prepared==0&&AndroidStartupPolicy.writes==0,"late temporary Tor completion entered Last memory after lease release");owner.disconnect();awaitIdle(owner);}
        });
        test("Tor Last source preparation does not block Disconnect or bless its late owner",()->{
            try(Owner owner=new Owner("tor")){CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);AndroidStartupPolicy.onPrepare=()->{entered.countDown();boolean interrupted=false;while(true)try{release.await();break;}catch(InterruptedException e){interrupted=true;}if(interrupted)Thread.currentThread().interrupt();};Callback cb=new Callback(0);
                owner.external.connect(new File("a".repeat(32)+".json"),torExit(),"wg","auto",cb);check(entered.await(3,TimeUnit.SECONDS),"Last source preparation did not enter");try{owner.disconnect();check(!AndroidHomeStateStore.current.connected&&AndroidStartupPolicy.writes==0,"Disconnect did not revoke Last adoption before source preparation returned");}finally{release.countDown();}cb.awaitDone();check(!cb.ok&&AndroidStartupPolicy.writes==0,"retired Tor source preparation blessed a late owner");awaitIdle(owner);}
        });
        for(String fault:new String[]{"proof","partial-compare","direct","ordinary"})test("Tor Last excludes "+fault,()->{
            try(Owner owner=new Owner("tor")){Callback cb=new Callback(0);if(fault.equals("proof"))LayeredVpnService.torHealthy=false;if(fault.equals("partial-compare"))AndroidTorCompareRuntime.failRun=true;
                if(fault.equals("direct"))owner.connect(cb);else if(fault.equals("ordinary"))owner.external.connectOrdinary(ordinary("socks5"),torExit(),"local",cb);else owner.external.connect(new File("a".repeat(32)+".json"),torExit(),"wg","auto",cb);cb.awaitDone();check(AndroidStartupPolicy.prepared==0&&AndroidStartupPolicy.writes==0,"unproved or unrelated Tor path entered Last receipt");if(cb.ok)owner.disconnect();awaitIdle(owner);}
        });
    }
    static void tests(String kind) {
        if("tor".equals(kind)){torTests();ordinaryTorTests();torCompareRuntimeTests();torLastRuntimeTests();}
        if("external".equals(kind))externalTests();
        {
            test(kind+" temporary cleanup retains its exact Home owner",()->{
                try(Owner owner=new Owner(kind)){Callback cb=new Callback(0);owner.connect(cb);cb.awaitDone();check(cb.ok&&cb.ownerCalls==1&&cb.homeOwner.equals(AndroidHomeStateStore.current.sessionId),"runtime did not expose its exact captured Home owner");
                    check(!(owner.multihop!=null?owner.multihop.disconnectCaptured("stale-home"):owner.external.disconnectCaptured("stale-home"))&&owner.engine.stops.get()==0&&AndroidHomeStateStore.current.connected,"stale temporary cleanup stopped the current native engine");
                    check((owner.multihop!=null?owner.multihop.disconnectCaptured(cb.homeOwner):owner.external.disconnectCaptured(cb.homeOwner))&&owner.engine.stops.get()==1&&!AndroidHomeStateStore.current.connected,"captured temporary cleanup did not stop its own native engine");awaitIdle(owner);
                }
            });
            test(kind+" delayed teardown cannot erase a newer Home owner",()->{
                try(Owner owner=new Owner(kind)){Callback cb=new Callback(0);owner.connect(cb);cb.awaitDone();AndroidHomeStateStore.Snapshot replacement=new AndroidHomeStateStore.Snapshot();replacement.sessionId="newer-home";replacement.phase="newer-owner";
                    owner.engine.duringStop=()->AndroidHomeStateStore.current=replacement;check((owner.multihop!=null?owner.multihop.disconnectCaptured(cb.homeOwner):owner.external.disconnectCaptured(cb.homeOwner)),"captured teardown was skipped");
                    check(AndroidHomeStateStore.current==replacement&&replacement.phase.equals("newer-owner"),"old teardown overwrote newer Home state");owner.engine.duringStop=null;
                }
            });
        }
        test(kind+" captured stop joins late preparation before reuse",()->{
            try(Owner owner=new Owner(kind)){
                Callback cb=new Callback(1);owner.connect(cb);cb.awaitEntered();String session=cb.homeOwner;check(!session.isEmpty(),"queued start did not expose its exact Home owner");
                CountDownLatch done=new CountDownLatch(1);java.util.concurrent.atomic.AtomicReference<Throwable> error=new java.util.concurrent.atomic.AtomicReference<>();
                Thread stop=new Thread(()->{try{check(owner.multihop!=null?owner.multihop.disconnectAndDrainCaptured(session):owner.external.disconnectAndDrainCaptured(session),"captured stop lost owner");}catch(Throwable failure){error.set(failure);}finally{done.countDown();}});
                stop.start();try{check(!done.await(100,TimeUnit.MILLISECONDS)&&owner.busy(),"temporary cleanup returned before its preparing worker drained");}
                finally{cb.release.countDown();}
                check(done.await(3,TimeUnit.SECONDS),"captured worker never drained");cb.awaitDone();check(error.get()==null&&!cb.ok&&!AndroidHomeStateStore.current.connected,"late preparation adopted or escaped captured cleanup");check(owner.engine.starts.get()==0,"late preparation started a native engine after cancellation");awaitIdle(owner);
            }
        });
        if ("multihop".equals(kind)) for (String entryMode:new String[]{"wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2"}) for (String execution:new String[]{"local","server","auto"}) {
            test("multihop captured transport/execution "+entryMode+"/"+execution,()->{
                try(Owner owner=new Owner(kind)) {
                    Callback cb=new Callback(0);
                    owner.multihop.connect(new AndroidNodeStore.Node("entry"),new AndroidNodeStore.Node("exit"),"shadowsocks",execution,entryMode,cb);
                    cb.awaitDone();
                    check(cb.ok&&execution.equals(AndroidMultihopController.lastExecution),"execution changed before preparation");
                    check(entryMode.equals(AndroidMultihopController.lastEntryMode),"entry transport changed before preparation");
                    check(execution.equals(owner.multihop.activeExecution()),"runtime lost its selected execution preference");
                    check(entryMode.equals(owner.multihop.activeEntryMode())&&entryMode.equals(AndroidHomeStateStore.current.activeEntryMode),"proved live entry identity changed");
                    check(LayeredVpnService.mtuStarts.get()==1,"MTU did not start exactly once after path proof");
                    owner.disconnect();awaitIdle(owner);
                }
            });
        }
        if ("multihop".equals(kind)) {
            for(String selected:new String[]{"local","server"})test("multihop restore keeps Compare preference and exact "+selected+" winner",()->{
                try(Owner owner=new Owner(kind)){AndroidNodeStore.Node entry=new AndroidNodeStore.Node("entry"),exit=new AndroidNodeStore.Node("exit");LayeredVpnService.selectedOverride=selected;
                    Callback first=new Callback(0);owner.multihop.connect(entry,exit,"shadowsocks","auto","wg-pq",first);first.awaitDone();check(first.ok,"original graph did not prove");
                    AndroidMultihopRuntime.RestoreCapture captured=owner.multihop.captureRestore(entry,exit,AndroidHomeStateStore.current);
                    owner.disconnect();awaitIdle(owner);LayeredVpnService.selectedOverride="";
                    Callback cb=new Callback(0);owner.multihop.restoreCaptured(entry,exit,captured,AndroidHomeStateStore.current,cb);cb.awaitDone();
                    check(cb.ok&&selected.equals(AndroidMultihopController.lastExecution),"restoration reran the chooser or changed the original path");
                    check(owner.multihop.activeExecution().equals("auto")&&owner.multihop.activeSelectedExecution().equals(selected),"runtime override overwrote Compare or lost actual native winner");
                    owner.disconnect();awaitIdle(owner);
                }
            });
            test("multihop restore rejects contradictory winner before launch",()->{
                try(Owner owner=new Owner(kind)){Callback first=new Callback(0);owner.multihop.connect(new AndroidNodeStore.Node("entry"),new AndroidNodeStore.Node("exit"),"shadowsocks","local","wg",first);first.awaitDone();LayeredVpnService.selectedOverride="server";boolean refused=false;try{owner.multihop.captureRestore(new AndroidNodeStore.Node("entry"),new AndroidNodeStore.Node("exit"),AndroidHomeStateStore.current);}catch(Exception expected){refused=true;}check(refused&&owner.engine.starts.get()==1,"incompatible native winner was captured");}
            });
            for(String fault:new String[]{"changed-entry","changed-exit","wrong-entry","wrong-exit","stale-home","changed-pins","stale-idle"})test("multihop runtime-only capture rejects "+fault,()->{
                try(Owner owner=new Owner(kind)){
                    AndroidNodeStore.Node entry=new AndroidNodeStore.Node("entry"),exit=new AndroidNodeStore.Node("exit");Callback first=new Callback(0);
                    LayeredVpnService.serverPins="public-server-identity-original";
                    owner.multihop.connect(entry,exit,"wg-pq","auto","wg",first);first.awaitDone();check(first.ok,"original packet graph not proved");
                    AndroidMultihopRuntime.RestoreCapture captured=owner.multihop.captureRestore(entry,exit,AndroidHomeStateStore.current);
                    if(fault.equals("stale-home")){LayeredVpnService.staleCapture=true;check(!owner.multihop.captureCurrent(captured),"stale home owner authorized temporary stop");return;}
                    if(fault.equals("changed-pins")){LayeredVpnService.serverPins="public-server-identity-replaced";check(!owner.multihop.captureCurrent(captured),"new paired key authorized temporary stop");LayeredVpnService.serverPins="public-server-identity-original";}
                    owner.disconnect();awaitIdle(owner);AndroidHomeStateStore.Snapshot idle=AndroidHomeStateStore.current;
                    if(fault.equals("stale-idle")){AndroidHomeStateStore.Snapshot changed=new AndroidHomeStateStore.Snapshot();changed.sessionId="new-user-decision";AndroidHomeStateStore.current=changed;}
                    if(fault.startsWith("changed-")&&!fault.equals("changed-pins"))AndroidMultihopController.changedSources.add(fault.endsWith("entry")?"entry":"exit");
                    Callback restored=new Callback(0);owner.multihop.restoreCaptured(fault.equals("wrong-entry")?new AndroidNodeStore.Node("different"):entry,fault.equals("wrong-exit")?new AndroidNodeStore.Node("different"):exit,captured,idle,restored);restored.awaitDone();
                    if(fault.equals("changed-pins")){check(restored.ok&&AndroidMultihopController.lastPins.equals("public-server-identity-original"),"restore failed to forward captured pins");LayeredVpnService.serverPins="public-server-identity-replaced";check(!owner.multihop.restoredMatches(captured,entry,exit,AndroidHomeStateStore.current),"replacement pins were accepted after restore");}
                    else check(!restored.ok&&owner.engine.starts.get()==1,"changed source or node launched restoration");
                }
            });
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
                check(LayeredVpnService.mtuStarts.get()==1,"MTU must start once, only after its captured path proof");
                if(kind.equals("tor"))check(publicProofs.get()==0&&LayeredVpnService.torReads.get()>=2&&LayeredVpnService.torExecutionReads.get()==2,"Tor used fixed-IP proof or lost final execution readback");
                if(kind.equals("external"))check(publicProofs.get()==0&&LayeredVpnService.externalReads.get()==4,"ordinary external path bypassed captured entry/DNS/native proof or winner ownership");
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
        test(kind+" MTU activation cannot escape captured adoption",()->{
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
        test("external startup deadline covers shared execution and final proof",()->{
            check(AndroidStandardExitRuntime.startTimeoutMillis(false,"local")==90000L,"ordinary local startup budget changed");
            long minimum=SHARED_EXECUTION_BUDGET_MS+SHARED_FINAL_PROOF_BUDGET_MS+30000L;
            for(String execution:new String[]{"server","auto"}){
                long budget=AndroidStandardExitRuntime.startTimeoutMillis(false,execution);
                check(budget>=minimum&&budget<=200000L,"external execution can time out before its shared comparison and final proof finish");
            }
            check(AndroidStandardExitRuntime.startTimeoutMillis(true,"local")==200000L,"Tor startup budget changed");
        });
        for(String kind:new String[]{"external","tor"})for(String changed:new String[]{"idle-disconnect","replacement","entry"})test(kind+" queued selection rejects "+changed,()->{
            try(Owner owner=new Owner(kind)){
                java.lang.reflect.Field field=owner.runtime().getClass().getDeclaredField("executor");field.setAccessible(true);java.util.concurrent.ExecutorService executor=(java.util.concurrent.ExecutorService)field.get(owner.runtime());
                CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);executor.submit(()->{entered.countDown();try{release.await();}catch(Exception e){throw new AssertionError(e);}});check(entered.await(3,TimeUnit.SECONDS),"queue did not block");
                AndroidStandardExitStore.Entry exit=new AndroidStandardExitStore.Entry();if(kind.equals("tor"))exit.protocol="tor";Callback cb=new Callback(0);AndroidExternalPolicy.entryVersion="queued-original";
                owner.external.connect(new java.io.File("a".repeat(32)+".json"),exit,"wg",cb);
                AndroidHomeStateStore.Snapshot expected=AndroidHomeStateStore.current;
                if(changed.equals("entry"))AndroidExternalPolicy.entryVersion="changed-entry";
                else{expected=new AndroidHomeStateStore.Snapshot();expected.pathGeneration=7;if(changed.equals("replacement")){expected.sessionId="newer-owner";expected.phase="connecting";}AndroidHomeStateStore.current=expected;}
                release.countDown();cb.awaitDone();check(!cb.ok&&owner.engine.starts.get()==0&&AndroidHomeStateStore.current==expected,"queued external/Tor startup replaced a newer decision or source");awaitIdle(owner);
            }
        });
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
        for(String execution:new String[]{"local","server"})for(String mode:new String[]{"wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","naive-h2","naive-h3","reality-vision","reality-pq-vision","reality-xhttp","ss-v2ray","split","max","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"})test("Tor exact entry "+mode+"/"+execution,()->{
            try(Owner owner=new Owner("tor")){Callback cb=new Callback(0);owner.external.connect(new java.io.File("a".repeat(32)+".json"),torEntry(),mode,execution,cb);cb.awaitDone();
                check(cb.ok&&mode.equals(AndroidStandardExitController.lastEntryMode)&&mode.equals(AndroidHomeStateStore.current.activeEntryMode)&&execution.equals(owner.external.capturedExternalExecution(AndroidHomeStateStore.current)),"Tor entry or execution was replaced");check(publicProofs.get()==0,"Tor borrowed fixed-IP proof");owner.disconnect();awaitIdle(owner);}
        });
        test("Tor Server cannot adopt a Local receipt",()->{
            try(Owner owner=new Owner("tor")){LayeredVpnService.torExecutionOverride="local";Callback cb=new Callback(0);owner.external.connect(new java.io.File("a".repeat(32)+".json"),torEntry(),"shadowsocks","server",cb);cb.awaitDone();
                check(!cb.ok&&!AndroidHomeStateStore.current.connected&&LayeredVpnService.mtuStarts.get()==0,"Tor published Connected or MTU before proving its Server receipt");awaitIdle(owner);}
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

# Check the shipping budget against both sequential native phases. This stays
# deterministic without shortening production timers or waiting three minutes.
execution_source = (ROOT / 'internal/mobilemultihop/runtime.go').read_text()
execution_timeout = re.search(r'context.WithTimeout\(parent,\s*(\d+)\s*\*\s*time.Second\)', execution_source)
proof_source = (ROOT / 'internal/mobilemultihop/external_proof.go').read_text()
proof_timeout = re.search(r'context.WithTimeout\(r.ctx,\s*(\d+)\s*\*\s*time.Second\)', proof_source)
assert execution_timeout and proof_timeout, 'shared execution/final proof deadline contract changed'
HARNESS = HARNESS.replace('SHARED_EXECUTION_BUDGET_MS', str(int(execution_timeout[1]) * 1000) + 'L')
HARNESS = HARNESS.replace('SHARED_FINAL_PROOF_BUDGET_MS', str(int(proof_timeout[1]) * 1000) + 'L')
runtime_source = (JAVA / 'AndroidStandardExitRuntime.java').read_text()
assert 'long deadline=System.currentTimeMillis()+startTimeoutMillis(tor,execution);' in runtime_source, 'native startup must use the execution-specific deadline'

with tempfile.TemporaryDirectory(prefix='routervpn-runtime-teardown-') as tmp:
    base=Path(tmp); pkg=base/'com/eabusham/routervpn';pkg.mkdir(parents=True)
    for name in ('AndroidMultihopRuntime.java','AndroidStandardExitRuntime.java','AndroidMTUMeasurementGate.java'):
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
    if not TARGETS or 'tor' in TARGETS:
        target=pkg/'AndroidStandardExitRuntime.java';original=target.read_text()
        controls=(
            ('captured temporary origin','boolean rememberTor=restoredExecution.isEmpty()&&!AndroidMTUMeasurementGate.held();','boolean rememberTor=restoredExecution.isEmpty();','late temporary Tor completion entered Last memory after lease release'),
            ('restored history','boolean rememberTor=restoredExecution.isEmpty()&&!AndroidMTUMeasurementGate.held();','boolean rememberTor=!AndroidMTUMeasurementGate.held();','Tor restored path overwrote Last history or reran Compare'),
            ('proved runtime publication','AndroidStartupPolicy.recordTorExecution(context,last,capturedHome);','/* mutation: actual proved winner not persisted */','successful Tor path did not record exactly one proved Last winner'),
        )
        for label,old,new,expected in controls:
            assert original.count(old)==1,(label,'missing exact mutation anchor')
            target.write_text(original.replace(old,new))
            subprocess.run([javac,'-encoding','UTF-8','-d',str(classes),*[str(p) for p in base.rglob('*.java')]],check=True,timeout=30,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            broken=subprocess.run([java,'-cp',str(classes),'com.eabusham.routervpn.RuntimeTeardownHarness','tor'],timeout=90,capture_output=True,text=True)
            target.write_text(original)
            assert broken.returncode and expected in broken.stdout+broken.stderr,(label,'did not reach intended runtime assertion',broken.stdout,broken.stderr)
            print('Android Tor Last runtime negative control rejected: '+label)
print('Android actual-runtime teardown behavior: PASS')
