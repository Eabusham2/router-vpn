#!/usr/bin/env python3
"""Exercise the actual runtime classes on a JVM with fake Android/engine boundaries.

No source rewriting or real networking is used. This proves controller lifecycle
behavior, not Android VpnService traffic, device permissions, or leak resistance.
"""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'
TARGETS = sys.argv[2:]
assert all(x in ('multihop', 'external') for x in TARGETS), 'unknown runtime test target'
javac, java = shutil.which('javac'), shutil.which('java')
assert javac and java, 'JDK is required for Android runtime lifecycle tests'

STUBS = r'''package com.eabusham.routervpn;
import android.content.Context;
import java.io.File;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

final class NativeSingBoxController {
    static final class ModeInfo {}
    static final class SessionInfo {}
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
    void stop() {
        stops.incrementAndGet();
        if (failStop) throw new IllegalStateException("stop request failed");
        state = "DOWN";
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
    Prepared prepare(File entry, File exit, String mode) { return new Prepared(exit,mode); }
}
final class AndroidStandardExitStore {
    static final class Entry {
        final String id="external", name="external", protocol="socks5", expectedPublicIp="1.1.1.1";
    }
}
final class AndroidStandardExitController {
    AndroidStandardExitController(Context c) {}
    NativeSingBoxController.SessionInfo prepare(File f, AndroidStandardExitStore.Entry e) { return new NativeSingBoxController.SessionInfo(); }
}
final class AndroidDirectStandardExitController {
    AndroidDirectStandardExitController(Context c) {}
    NativeSingBoxController.SessionInfo prepare(AndroidStandardExitStore.Entry e) { return new NativeSingBoxController.SessionInfo(); }
}
final class AndroidPathProbe {
    static boolean prove(File bundle, int timeout) { return true; }
}
final class AndroidHomeStateStore {
    static final class Snapshot {
        boolean connected;
        String logicalMode="", phase="off", activeEntryId="", activeExitId="", runtimeMode="";
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
    static String beginMultihop(Context c, String entry, String exit, String mode) {
        Snapshot s=new Snapshot(); s.logicalMode="multihop"; s.phase="connecting";
        s.activeEntryId=entry; s.activeExitId=exit; s.runtimeMode=mode; current=s; return "multi-session";
    }
    static void connectedMultihop(Context c, String entry, String exit, String mode) {
        beginMultihop(c,entry,exit,mode); beforeConnectedWrite(); current.connected=true; current.phase="connected";
    }
    static void beginExternal(Context c, String id, String name, String protocol, String ip, String base) {
        Snapshot s=new Snapshot();s.logicalMode="external";s.phase="connecting";current=s;
    }
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
        Owner(String kind) {
            AndroidHomeStateStore.reset();
            multihop="multihop".equals(kind)?new AndroidMultihopRuntime(context,engine):null;
            external=multihop==null?new AndroidStandardExitRuntime(context,engine):null;
        }
        Object runtime() { return multihop!=null?multihop:external; }
        void connect(Callback cb) {
            if(multihop!=null)multihop.connect(new AndroidNodeStore.Node("entry"),new AndroidNodeStore.Node("exit"),"shadowsocks",cb);
            else external.connectDirect(new AndroidStandardExitStore.Entry(),cb);
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
        test(kind+" successful proof",()->{
            try(Owner owner=new Owner(kind)) {
                Callback cb=new Callback(0);owner.connect(cb);cb.awaitDone();
                check(cb.ok&&AndroidHomeStateStore.current.connected,"normal connection never reached proved Connected");
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
                check(!cb.ok&&owner.engine.starts.get()==0,"queued attempt launched after Disconnect");awaitIdle(owner);
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
        test(kind+" cancellation before engine launch",()->{
            try(Owner owner=new Owner(kind)) {
                Callback cb=new Callback(2);
                try {owner.connect(cb);cb.awaitEntered();owner.disconnect();}
                finally {cb.release.countDown();cb.awaitDone();}
                check(owner.engine.starts.get()==0,"engine launched after Disconnect completed");
                check(!cb.ok,"cancelled attempt reported Connected");awaitIdle(owner);
            }
        });
        test(kind+" partial start failure tears down",()->{
            try(Owner owner=new Owner(kind)) {
                owner.engine.failStart=true;Callback cb=new Callback(0);owner.connect(cb);cb.awaitDone();
                check(!cb.ok,"failed start reported success");
                check(owner.engine.stops.get()>0&&"DOWN".equals(owner.engine.state),"start threw after publishing engine ownership but cleanup was skipped");
                awaitIdle(owner);
            }
        });
        test(kind+" failed stop still reports failure",()->{
            try(Owner owner=new Owner(kind)) {
                owner.engine.startState="FAILED";owner.engine.failStop=true;
                Callback cb=new Callback(0);owner.connect(cb);cb.awaitDone();
                check(!cb.ok,"stop exception reported success");check(owner.busy(),"stop exception released unproved ownership");
            }
        });
        test(kind+" unknown engine state blocks start",()->{
            try(Owner owner=new Owner(kind)) {
                owner.engine.state="UNKNOWN";Callback cb=new Callback(0);owner.connect(cb);cb.awaitDone();
                check(owner.engine.starts.get()==0&&!cb.ok,"unknown engine state was treated as safe to replace");
            }
        });
    }
    public static void main(String[] args) {
        // A deterministic fake of the public-exit provider. No real sockets,
        // DNS requests, VPN engines, or external services are used by this test.
        URL.setURLStreamHandlerFactory(protocol -> "https".equals(protocol)?new URLStreamHandler(){
            protected URLConnection openConnection(URL u){return openConnection(u,Proxy.NO_PROXY);}
            protected URLConnection openConnection(URL u,Proxy p){return new HttpURLConnection(u){
                public void connect(){}public void disconnect(){}public boolean usingProxy(){return true;}
                public int getResponseCode(){return 200;}
                public InputStream getInputStream(){return new ByteArrayInputStream("1.1.1.1".getBytes(StandardCharsets.US_ASCII));}
            };}
        }:null);
        if(args.length==0){tests("multihop");tests("external");}
        else for(String kind:args)tests(kind);
        if(!failures.isEmpty()){for(String s:failures)System.err.println(s);System.exit(1);}
    }
}
'''

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
