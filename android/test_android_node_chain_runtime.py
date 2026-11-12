#!/usr/bin/env python3
"""Execute the shipping ordered runtime, private session, Home and full service.

The OS, pure-source compiler and native packet/MTU handles are explicit doubles.
The companion ordered-source gate runs the actual shared Go compiler. This gate
checks host lifecycle ownership; APK/native traffic/device acceptance are separate.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


B = load('ordered_service_boundaries', 'android/test_android_layered_service_compile.py')
SOURCES = dict(B.STUBS)
SOURCES.pop('org/json/JSONObject.java')
APP = 'com/eabusham/routervpn/'
NATIVE = 'io/nekohasekai/libbox/'
for name in ('AndroidNodeChainSession', 'AndroidHomeStateStore'):
    SOURCES.pop(APP + name + '.java')

SOURCES['android/content/SharedPreferences.java'] = '''package android.content;
public interface SharedPreferences {String getString(String k,String d);long getLong(String k,long d);boolean getBoolean(String k,boolean d);java.util.Map<String,?> getAll();Editor edit();
 interface Editor {Editor putString(String k,String v);Editor putLong(String k,long v);Editor putBoolean(String k,boolean v);Editor remove(String k);void apply();}}
'''
SOURCES['android/content/Context.java'] = r'''package android.content;
public class Context {
 public static final int MODE_PRIVATE=0;public static final String CONNECTIVITY_SERVICE="c",NOTIFICATION_SERVICE="n";
 public java.io.File files;public android.net.ConnectivityManager network=new android.net.ConnectivityManager();
 public java.util.Map<String,Store> stores=new java.util.HashMap<>();
 public Context getApplicationContext(){return this;}public java.io.File getFilesDir(){return files;}public java.io.File getCacheDir(){return files;}public java.io.File getNoBackupFilesDir(){return files;}
 public Object getSystemService(String n){return CONNECTIVITY_SERVICE.equals(n)?network:new android.app.NotificationManager();}
 public android.content.pm.PackageManager getPackageManager(){return new android.content.pm.PackageManager();}
 public synchronized SharedPreferences getSharedPreferences(String n,int mode){return stores.computeIfAbsent(n,k->new Store());}
 public static class Store implements SharedPreferences {
  final java.util.Map<String,Object> values=new java.util.HashMap<>();
  public volatile Runnable beforeApply;public volatile Thread applyThread;
  public synchronized String getString(String k,String d){return (String)values.getOrDefault(k,d);}public synchronized long getLong(String k,long d){return (Long)values.getOrDefault(k,d);}public synchronized boolean getBoolean(String k,boolean d){return (Boolean)values.getOrDefault(k,d);}
  public synchronized java.util.Map<String,?> getAll(){return new java.util.HashMap<>(values);}
  public Editor edit(){return new Editor(){final java.util.Map<String,Object> stage=new java.util.HashMap<>();
   public Editor putString(String k,String v){stage.put(k,v);return this;}public Editor putLong(String k,long v){stage.put(k,v);return this;}public Editor putBoolean(String k,boolean v){stage.put(k,v);return this;}public Editor remove(String k){stage.put(k,null);return this;}
   public void apply(){Runnable hook=beforeApply;if(hook!=null&&Thread.currentThread()==applyThread)hook.run();synchronized(Store.this){for(var e:stage.entrySet())if(e.getValue()==null)values.remove(e.getKey());else values.put(e.getKey(),e.getValue());}}
  };}
 }
}'''
SOURCES['android/content/Intent.java'] = r'''package android.content;public class Intent {
 private String action="";private final java.util.Map<String,Object> extra=new java.util.HashMap<>();public Intent(){}public Intent(Context c,Class<?> type){}
 public Intent setAction(String a){action=a;return this;}public String getAction(){return action;}public Intent putExtra(String k,String v){extra.put(k,v);return this;}public Intent putExtra(String k,long v){extra.put(k,v);return this;}
 public String getStringExtra(String k){return (String)extra.get(k);}public long getLongExtra(String k,long d){return (Long)extra.getOrDefault(k,d);}}
'''
SOURCES['android/os/SystemClock.java'] = 'package android.os;public class SystemClock{public static long elapsedRealtime(){return System.nanoTime()/1000000;}}'
SOURCES['android/os/Handler.java'] = r'''package android.os;public class Handler {
 public final java.util.List<Runnable> posted=java.util.Collections.synchronizedList(new java.util.ArrayList<>());public Handler(Looper loop){}
 public boolean post(Runnable work){posted.add(work);return true;}public boolean postDelayed(Runnable work,long delay){return true;}public void removeCallbacks(Runnable work){posted.remove(work);}
 public void runPosted(){java.util.List<Runnable> work;synchronized(posted){work=new java.util.ArrayList<>(posted);posted.clear();}for(Runnable value:work)value.run();}
}'''
SOURCES['android/os/ParcelFileDescriptor.java'] = r'''package android.os;public class ParcelFileDescriptor implements java.io.Closeable {
 final java.io.FileInputStream stream;public ParcelFileDescriptor()throws java.io.IOException{stream=new java.io.FileInputStream("/dev/null");}
 public static ParcelFileDescriptor fromFd(int fd)throws java.io.IOException{return new ParcelFileDescriptor();}public java.io.FileDescriptor getFileDescriptor(){try{return stream.getFD();}catch(Exception failure){throw new IllegalStateException(failure);}}
 public int getFd(){return 10;}public void close()throws java.io.IOException{stream.close();}}
'''
SOURCES['android/net/VpnService.java'] = SOURCES['android/net/VpnService.java'].replace('public static android.content.Intent prepare(android.content.Context c){return null;}', 'public static boolean revoked;public static android.content.Intent prepare(android.content.Context c){return revoked?new android.content.Intent():null;}').replace('public android.os.ParcelFileDescriptor establish(){return null;}', 'public android.os.ParcelFileDescriptor establish(){try{return new android.os.ParcelFileDescriptor();}catch(Exception failure){throw new IllegalStateException(failure);}}')
SOURCES['android/net/Network.java'] = SOURCES['android/net/Network.java'].replace('public void bindSocket(java.io.FileDescriptor fd)throws java.io.IOException{}', 'public int bindings;public void bindSocket(java.io.FileDescriptor fd)throws java.io.IOException{bindings++;}')
SOURCES['android/net/ConnectivityManager.java'] = SOURCES['android/net/ConnectivityManager.java'].replace('public Network[] getAllNetworks(){return new Network[0];} public Network getActiveNetwork(){return null;}', 'public Network physical=new Network();public Network[] getAllNetworks(){return new Network[]{physical};} public Network getActiveNetwork(){return physical;}').replace('getNetworkCapabilities(Network n){return null;}', 'getNetworkCapabilities(Network n){return new NetworkCapabilities();}').replace('getLinkProperties(Network n){return null;}', 'getLinkProperties(Network n){return new LinkProperties();}')
SOURCES[NATIVE + 'TunOptions.java'] = SOURCES[NATIVE + 'TunOptions.java'].replace('getAutoRoute(){return true;}', 'getAutoRoute(){return false;}').replace('RoutePrefixIterator getInet4Address(){return null;}', 'RoutePrefixIterator getInet4Address(){return empty();}').replace('RoutePrefixIterator getInet6Address(){return null;}', 'RoutePrefixIterator getInet6Address(){return empty();}')[:-1] + 'private RoutePrefixIterator empty(){return new RoutePrefixIterator(){public boolean hasNext(){return false;}public RoutePrefix next(){return null;}};}}'
SOURCES[NATIVE + 'CommandServer.java'] = r'''package io.nekohasekai.libbox;public class CommandServer {
 public static int created;public final PlatformInterface platform;public boolean closed;public int checkedCloses;public boolean failClose;
 public CommandServer(PlatformInterface p,CommandServerHandler h){platform=p;created++;}public void start(){}
 public void startOrReloadService(String config,OverrideOptions options)throws Exception{platform.autoDetectInterfaceControl(10);platform.openTun(new TunOptions());}
 public void closeService(){throw new AssertionError("Ordered graph used unchecked native shutdown");}public void close(){closed=true;}public void resetNetwork(){}
}'''
SOURCES[NATIVE + 'RouterNodeChain.java'] = r'''package io.nekohasekai.libbox;public class RouterNodeChain {
 public static java.util.function.Consumer<RouterNodeChain> configured;public static volatile RouterNodeChain latest;
 public CommandServer server;public final int count;public volatile boolean cancelled,valid=true;public int runs,closes,failCloses;public volatile int healthCalls;public Runnable afterRun,afterHealth;
 public java.util.concurrent.CountDownLatch entered,release;
 public RouterNodeChain(int count){this.count=count;latest=this;if(configured!=null)configured.accept(this);}
 public void run(CommandServer original)throws Exception{runs++;server=original;if(entered!=null)entered.countDown();if(release!=null&&!release.await(3,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("test proof did not drain");if(afterRun!=null)afterRun.run();if(cancelled||!valid)throw new IllegalStateException("middle member/DNS proof failed");}
 public boolean healthy(){healthCalls++;Runnable hook=afterHealth;afterHealth=null;if(hook!=null)hook.run();return server!=null&&!cancelled&&valid&&!server.closed;}
 public void networkChanged(){cancelled=true;if(release!=null)release.countDown();}public String progressJSON(){return "{}";}
 public void close()throws Exception{closes++;if(failCloses-->0)throw new IllegalStateException("native ordered join pending");cancelled=true;}
}'''
SOURCES[NATIVE + 'RouterHopMeasurement.java'] = r'''package io.nekohasekai.libbox;public class RouterHopMeasurement {
 public int starts,cancels,drains,closes;public String request="";public boolean invalidated;
 public void networkChanged(){invalidated=true;}public void start(String id,long size){if(invalidated)throw new IllegalStateException("retired native measurement");request=id;starts++;}
 public void startLatency(String id,String exit){throw new AssertionError("ordered transfer used external latency");}public void startResponse(String id,String exit){throw new AssertionError("ordered transfer used external response");}
 public void cancel(String id){if(!request.equals(id))throw new AssertionError("cancelled another request");cancels++;}public void drain(String id){if(!request.equals(id))throw new AssertionError("drained another request");drains++;}
 public String statusJSON(){return "{\"results\":[]}";}public void close(){invalidated=true;closes++;}
}'''
SOURCES[NATIVE + 'RouterMTUPlatform.java'] = 'package io.nekohasekai.libbox;public interface RouterMTUPlatform{}'
SOURCES[NATIVE + 'RouterMTU.java'] = 'package io.nekohasekai.libbox;public class RouterMTU{}'
SOURCES[NATIVE + 'Libbox.java'] = SOURCES[NATIVE + 'Libbox.java'].replace('public static void routerStrategyCloseService(CommandServer server)throws Exception{}', 'public static void routerStrategyCloseService(CommandServer server)throws Exception{server.checkedCloses++;if(server.failClose)throw new IllegalStateException("native Box drain pending");server.closed=true;}')[:-1] + r'''
 public static RouterHopMeasurement routerNodeChainNewHopMeasurement(RouterNodeChain plan,CommandServer server)throws Exception{if(plan.server!=server||!plan.healthy())throw new IllegalStateException("unproved ordered measurement");return new RouterHopMeasurement();}
 public static RouterNodeChain mtuPlan;public static CommandServer mtuServer;public static RouterMTUPlatform mtuPlatform;
 public static RouterMTU routerNodeChainNewMTU(RouterNodeChain plan,CommandServer server,RouterMTUPlatform platform)throws Exception{
  if(plan.server!=server||!plan.healthy())throw new IllegalStateException("unproved or replaced ordered MTU");mtuPlan=plan;mtuServer=server;mtuPlatform=platform;return new RouterMTU();}
}'''
SOURCES[APP + 'AndroidNodeStore.java'] = r'''package com.eabusham.routervpn;final class AndroidNodeStore {
 AndroidNodeStore(android.content.Context context){}String activeId(){return "";}
 static final class ChainSource {final String id;ChainSource(String id){this.id=id;}}
 static final class ChainCapture {
  final ChainSource control;final java.util.List<ChainSource> members;final java.util.List<String> modes;volatile boolean valid=true;boolean strict;volatile Runnable beforeCurrent;volatile Thread hookThread;
  ChainCapture(int count){java.util.List<ChainSource> list=new java.util.ArrayList<>();java.util.List<String> selected=new java.util.ArrayList<>();for(int i=0;i<count;i++){list.add(new ChainSource(String.format("%032x",i+1)));selected.add(i==count-1?"shadowsocks":"wg");}members=java.util.List.copyOf(list);modes=java.util.List.copyOf(selected);control=members.get(count-1);}
  void requireCurrent(){Runnable hook=beforeCurrent;if(hook!=null&&Thread.currentThread()==hookThread){beforeCurrent=null;hook.run();}if(!valid)throw new IllegalStateException("original middle source replaced");}
 }
}'''
SOURCES[APP + 'AndroidNodeChainCapture.java'] = r'''package com.eabusham.routervpn;final class AndroidNodeChainCapture {
 static final String SESSION_FILE="routervpn-node-chain.json";final AndroidNodeStore.ChainCapture source;final io.nekohasekai.libbox.RouterNodeChain plan;
 final String config="{\"original\":\"one-complete-TUN\"}",launchInput;final boolean strict;
 private AndroidNodeChainCapture(AndroidNodeStore.ChainCapture source){this.source=source;strict=source.strict;plan=new io.nekohasekai.libbox.RouterNodeChain(source.members.size());launchInput="ordered:"+source.members.size();}
 static AndroidNodeChainCapture compile(AndroidNodeStore.ChainCapture source){source.requireCurrent();return new AndroidNodeChainCapture(source);}
 void requireCurrent(){source.requireCurrent();}void close()throws Exception{plan.close();}
}'''
SOURCES[APP + 'AndroidMTUSession.java'] = SOURCES[APP + 'AndroidMTUSession.java'].replace('public void activateNodeChain(AndroidNodeChainSession source){}', 'public AndroidNodeChainSession activated;public Exception failure;public void activateNodeChain(AndroidNodeChainSession source){try{activated=source;source.newMTU(new io.nekohasekai.libbox.RouterMTUPlatform(){});}catch(Exception stale){failure=stale;}}').replace('public Long proofObservationToken(){return 0L;}', 'public Long token=0L;public Long proofObservationToken(){return token;}').replace('public boolean proofOwnerCurrent(){return true;}', 'public boolean current=true;public boolean proofOwnerCurrent(){return current;}')
SOURCES[APP + 'NativeSingBoxController.java'] = r'''package com.eabusham.routervpn;final class NativeSingBoxController {
 static final class SessionInfo{final String sessionId,modeId;SessionInfo(String id,String mode){sessionId=id;modeId=mode;}}
 LayeredVpnService service;boolean delay;android.content.Intent late;Runnable beforeStart;
 NativeSingBoxController(LayeredVpnService service){this.service=service;}
 void startNodeChain(SessionInfo value,String home){android.content.Intent intent=new android.content.Intent().setAction(LayeredVpnService.ACTION_START).putExtra(LayeredVpnService.EXTRA_SESSION_ID,value.sessionId).putExtra(LayeredVpnService.EXTRA_MODE_ID,value.modeId).putExtra(LayeredVpnService.EXTRA_HOME_SESSION_ID,home);if(beforeStart!=null)beforeStart.run();if(delay)late=intent;else service.onStartCommand(intent,0,1);}
 void stopNodeChain(String id){service.onStartCommand(new android.content.Intent().setAction(LayeredVpnService.ACTION_STOP_NODE_CHAIN).putExtra(LayeredVpnService.EXTRA_SESSION_ID,id),0,2);}
 String getState(){return service.getSharedPreferences("router-vpn",0).getString("layered_state_v1","DOWN");}String getError(){return service.getSharedPreferences("router-vpn",0).getString("layered_error_v1","");}
 static boolean nativeMultihopEntry(String mode){return "wg".equals(mode);}
}'''
SOURCES[APP + 'AndroidImportedRouterPath.java'] = SOURCES[APP + 'AndroidImportedRouterPath.java'][:-1] + 'static boolean supports(String entry,String exit){return false;}}'
SOURCES['com/wireguard/android/backend/Tunnel.java'] = 'package com.wireguard.android.backend;public interface Tunnel{enum State{DOWN,UP}}'
SOURCES['org/amnezia/awg/backend/Tunnel.java'] = 'package org.amnezia.awg.backend;public interface Tunnel{enum State{DOWN,UP}}'
SOURCES[APP + 'AndroidRuntimeRegistry.java'] = '''package com.eabusham.routervpn;final class AndroidRuntimeRegistry{
 static AndroidRuntimeRegistry get(android.content.Context c){return new AndroidRuntimeRegistry();}final WG wireGuard=new WG();final AWG amneziaWG=new AWG();
 static class WG{com.wireguard.android.backend.Tunnel.State getState(){return com.wireguard.android.backend.Tunnel.State.DOWN;}}
 static class AWG{org.amnezia.awg.backend.Tunnel.State getState(){return org.amnezia.awg.backend.Tunnel.State.DOWN;}}
}'''
SOURCES[APP + 'AndroidStartupPolicy.java'] = '''package com.eabusham.routervpn;final class AndroidStartupPolicy {
 static int prepared,recorded;static AndroidNodeStore.ChainCapture source;
 static final class OrderedLast{final AndroidNodeStore.ChainCapture source;OrderedLast(AndroidNodeStore.ChainCapture source){this.source=source;}}
 static OrderedLast prepareOrderedExecution(android.content.Context context,AndroidNodeStore.ChainCapture capture){prepared++;source=capture;return new OrderedLast(capture);}
 static boolean recordOrderedExecution(android.content.Context context,OrderedLast receipt,AndroidHomeStateStore.Snapshot home){if(receipt==null)return false;if(!home.connected||!home.pathProof.equals("passed")||!home.logicalMode.equals("node-chain")||receipt.source!=source)throw new AssertionError("history preceded complete ordered proof");recorded++;return true;}
}'''

HARNESS = r'''package com.eabusham.routervpn;
import android.content.*;import io.nekohasekai.libbox.*;import java.nio.file.*;import java.lang.reflect.*;import java.util.concurrent.*;import java.util.*;
public final class OrderedRuntimeTest {
 static int checks;interface Action{void run()throws Exception;}static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
 static final java.util.concurrent.ConcurrentLinkedQueue<Throwable> uncaught=new java.util.concurrent.ConcurrentLinkedQueue<>();
 static void reject(Action call,String message)throws Exception{try{call.run();}catch(Exception expected){checks++;return;}throw new AssertionError(message);}
 static Object get(Object owner,String name)throws Exception{Field field=owner.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(owner);}
 static void set(Object owner,String name,Object value)throws Exception{Field field=owner.getClass().getDeclaredField(name);field.setAccessible(true);field.set(owner,value);}
 static void await(java.util.function.BooleanSupplier done,String why)throws Exception{long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(4);while(!done.getAsBoolean()&&System.nanoTime()<end)Thread.sleep(5);check(done.getAsBoolean(),why);}
 static final class Result implements AndroidNodeChainRuntime.Callback {final CountDownLatch done=new CountDownLatch(1);volatile boolean ok;volatile Thread worker;String message,home;public void progress(String ignored){worker=Thread.currentThread();}public void owned(String value){home=value;}public void finished(boolean success,String text){ok=success;message=text;done.countDown();}void finished()throws Exception{check(done.await(5,TimeUnit.SECONDS),"ordered callback did not finish");}}
 static final class Fixture implements AutoCloseable {
  final LayeredVpnService service=new LayeredVpnService();final NativeSingBoxController nativeOwner;final AndroidNodeChainRuntime runtime;final AndroidNodeStore.ChainCapture source;final Path files;
  Fixture(int count)throws Exception{files=Files.createTempDirectory("ordered-runtime-");service.files=files.toFile();service.onCreate();nativeOwner=new NativeSingBoxController(service);runtime=new AndroidNodeChainRuntime(service,nativeOwner);source=new AndroidNodeStore.ChainCapture(count);RouterNodeChain.configured=null;android.net.VpnService.revoked=false;}
  AndroidNodeChainSession owner()throws Exception{return (AndroidNodeChainSession)get(runtime,"owner");}
  Result connect()throws Exception{Result result=new Result();runtime.connect(source,result);result.finished();return result;}
  void connected()throws Exception{Result result=connect();check(result.ok,"complete native graph did not connect: "+result.message);check(runtime.isConnected(),"proved graph was not owned");drain();}
  void drain()throws Exception{((ExecutorService)get(service,"executor")).submit(()->{}).get(5,TimeUnit.SECONDS);}
  void stop()throws Exception{check(runtime.stopAndProve(),"native owner did not acknowledge complete cleanup");drain();}
  public void close()throws Exception{RouterNodeChain.configured=null;AndroidNodeChainSession value=owner();if(value!=null){value.capture.plan.failCloses=0;CommandServer core=(CommandServer)get(service,"commandServer");if(core!=null)core.failClose=false;runtime.stopAndProve();}((ExecutorService)get(runtime,"executor")).shutdownNow();((ExecutorService)get(service,"executor")).shutdownNow();((ExecutorService)get(service,"nodeChainObservations")).shutdownNow();try(var all=Files.walk(files)){for(Path path:all.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}}
 }
 static void success()throws Exception {
  for(int count:new int[]{2,3,4,8})try(Fixture f=new Fixture(count)){
   int previousHistory=AndroidStartupPolicy.recorded;f.connected();check(AndroidStartupPolicy.recorded==previousHistory+1,"fresh proved ordered connection did not record its captured Local choice");AndroidNodeChainSession original=f.owner();RouterNodeChain graph=original.capture.plan;CommandServer server=(CommandServer)get(f.service,"commandServer");
   check(graph.runs==1&&graph.count==count&&graph.server==server,"service substituted a pair/final probe or another native Box");
   var home=AndroidHomeStateStore.snapshot(f.service);var ordered=new org.json.JSONArray(home.activeChain);
   check(home.connected&&home.logicalMode.equals("node-chain")&&home.activeEntryId.isEmpty()&&home.activeExitId.isEmpty()&&ordered.length()==count,"Home dropped ordered members or borrowed pair identity");
   for(int i=0;i<count;i++)check(ordered.getJSONObject(i).getString("id").equals(f.source.members.get(i).id)&&ordered.getJSONObject(i).getString("mode").equals(f.source.modes.get(i)),"Home reordered original member choices");
   check(f.runtime.activeSources()==f.source.members&&f.runtime.activeModes()==f.source.modes,"live UI lost immutable original member sources");
   check(Libbox.mtuPlan==graph&&Libbox.mtuServer==server,"MTU constructed from a replacement graph or native server");
   check(f.service.network.physical.bindings==1,"ordered socket was not bound to its captured physical network");
   reject(()->AndroidNodeChainSession.claim(f.service,original.directory,original.sessionId,"node-chain",original.capture.config,home.sessionId),"same private source started twice");
   var restore=f.runtime.captureRestore();check(f.runtime.captureCurrent(restore),"proved original restore capture rejected");
   check(!f.runtime.restoredMatches(restore),"the original proof was mistaken for a fresh restored owner");
   check(!f.runtime.disconnectAndDrainCaptured("different-home")&&f.runtime.isConnected(),"captured disconnect stopped an unrelated Home owner");
   check(f.runtime.disconnectAndDrainCaptured(home.sessionId),"the exact captured ordered owner did not drain");f.drain();
   check(AndroidHomeStateStore.snapshot(f.service).pathGeneration==home.pathGeneration+2,"captured stop did not invalidate proof before terminal Home");
   check(original.released()&&!original.directory.exists()&&server.checkedCloses>0&&!f.runtime.isActiveOrTransitioning(),"Disconnected preceded native join or private-source cleanup");
   int prepared=AndroidStartupPolicy.prepared,recorded=AndroidStartupPolicy.recorded;
   var idle=AndroidHomeStateStore.snapshot(f.service);Result result=new Result();f.runtime.restore(restore,idle,result);result.finished();check(result.ok,"exact original restore did not reprove every member: "+result.message);
   AndroidNodeChainSession restored=f.owner();check(restored!=original&&restored.source==original.source&&restored.capture.plan!=graph&&restored.capture.plan.runs==1,"restore reused proof or reconstructed saved labels");
   check(f.runtime.restoredMatches(restore)&&!f.runtime.captureCurrent(restore),"fresh restored proof did not match its complete original sources");
   check(prepared==AndroidStartupPolicy.prepared&&recorded==AndroidStartupPolicy.recorded,"temporary restoration overwrote ordered Last history");
   f.source.valid=false;check(!f.runtime.restoredMatches(restore),"restored proof borrowed a changed original member");f.source.valid=true;
   check(!f.runtime.disconnectAndDrainCaptured(home.sessionId)&&f.runtime.isConnected(),"an old captured disconnect stopped the fresh restored owner");f.stop();
   Result last=new Result();f.runtime.connectLast(f.source,AndroidHomeStateStore.snapshot(f.service),last);last.finished();check(last.ok&&f.runtime.isConnected()&&f.owner().capture.plan!=restored.capture.plan&&f.owner().capture.plan.runs==1,"Startup Last reused an old ordered native proof");
   check(prepared==AndroidStartupPolicy.prepared&&recorded==AndroidStartupPolicy.recorded,"Startup Last overwrote its original ordered history");f.stop();
  }
 }
 static void staleSources()throws Exception {
  for(String family:List.of("middle","Home","proof","config","metadata","launch"))try(Fixture f=new Fixture(4)){
   final String[] replacement={""};int created=CommandServer.created,beforeHistory=AndroidStartupPolicy.recorded;
   if(family.equals("middle"))RouterNodeChain.configured=plan->plan.afterRun=()->f.source.valid=false;
   if(family.equals("proof"))RouterNodeChain.configured=plan->plan.valid=false;
   if(family.equals("Home"))RouterNodeChain.configured=plan->plan.afterRun=()->{replacement[0]=AndroidHomeStateStore.begin(f.service,"new","new","libbox","replacement");AndroidHomeStateStore.connected(f.service,"new","new","libbox","","replacement");};
   if(family.equals("config")||family.equals("metadata")||family.equals("launch"))f.nativeOwner.beforeStart=()->{try{AndroidNodeChainSession owner=f.owner();Files.writeString(owner.directory.toPath().resolve(family.equals("config")?"sing-box.json":family.equals("launch")?AndroidNodeChainCapture.SESSION_FILE:"routervpn-multihop.json"),"{}");}catch(Exception failure){throw new IllegalStateException(failure);}};
   Result result=f.connect();check(!result.ok&&!f.runtime.isConnected(),"stale ordered source/proof reached Connected: "+family);f.drain();
   check(AndroidStartupPolicy.recorded==beforeHistory,"failed complete ordered proof minted historical Last authority: "+family);
   check(!f.runtime.isActiveOrTransitioning(),"failed native proof lost its cleanup: "+family);
   if(!replacement[0].isEmpty())check(AndroidHomeStateStore.snapshot(f.service).sessionId.equals(replacement[0])&&AndroidHomeStateStore.snapshot(f.service).connected,"old ordered failure overwrote replacement Home");
   if(family.equals("config")||family.equals("metadata")||family.equals("launch"))check(created==CommandServer.created,"tampered or mixed ordered source constructed native service");
  }
 }
 static void pendingCleanup()throws Exception {
  try(Fixture f=new Fixture(4)){f.connected();f.owner().capture.plan.failCloses=1;f.stop();}
  for(boolean graphFailure:new boolean[]{true,false})try(Fixture f=new Fixture(4)){
   f.connected();AndroidNodeChainSession original=f.owner();CommandServer server=(CommandServer)get(f.service,"commandServer");
   if(graphFailure)original.capture.plan.failCloses=2;else server.failClose=true;
   Method stop=LayeredVpnService.class.getDeclaredMethod("shutdown",String.class,String.class);stop.setAccessible(true);
   reject(()->stop.invoke(f.service,"DOWN",""),"unjoined ordered native owner was discarded");
   check(f.runtime.isActiveOrTransitioning()&&!original.released()&&original.directory.exists(),"failed ordered native join lost its source/cleanup ownership");
   check(get(f.service,"nodeChainSession")==original&&get(f.service,"commandServer")==server,"failed native drain discarded or swapped exact handles");
   Result blocked=f.connect();check(!blocked.ok,"replacement ordered graph bypassed retained cleanup");
   original.capture.plan.failCloses=0;server.failClose=false;f.stop();check(original.released(),"retry did not acknowledge the original native owner");
  }
 }
 static void capturedDrainRetry()throws Exception {
  for(boolean releasedBeforeRetry:new boolean[]{false,true})try(Fixture f=new Fixture(4)){
   f.connected();AndroidNodeChainSession original=f.owner();var home=AndroidHomeStateStore.snapshot(f.service);var restore=f.runtime.captureRestore();CommandServer server=(CommandServer)get(f.service,"commandServer");server.failClose=true;
   check(!f.runtime.disconnectAndDrainCaptured(home.sessionId),"failed captured drain acknowledged an open native Box");f.drain();
   check(uncaught.isEmpty(),"native cleanup failure escaped the ordered worker and could terminate Android");
   check(f.runtime.isActiveOrTransitioning()&&f.owner()==original&&!original.released()&&f.runtime.retainsCapturedOwner(home.sessionId),"failed captured drain lost its exact retry authority");
   check(AndroidHomeStateStore.snapshot(f.service).pathGeneration==home.pathGeneration+1,"failed captured drain invalidated its Home more than once");
   server.failClose=false;
   if(releasedBeforeRetry){Method shutdown=LayeredVpnService.class.getDeclaredMethod("shutdown",String.class,String.class);shutdown.setAccessible(true);shutdown.invoke(f.service,"DOWN","");check(original.released()&&AndroidHomeStateStore.snapshot(f.service).activeChain.isEmpty(),"late native release did not clear its retired public identity");check(f.runtime.isActiveOrTransitioning()&&f.owner()==original,"late release lost its pending exact Home receipt");}
   check(!f.runtime.disconnectAndDrainCaptured("unrelated-home"),"failed captured drain adopted another UUID");
   check(f.runtime.disconnectAndDrainCaptured(home.sessionId),"same captured drain could not retry its original native cleanup");
   check(original.released()&&!original.directory.exists()&&AndroidHomeStateStore.snapshot(f.service).pathGeneration==home.pathGeneration+2&&!f.runtime.isActiveOrTransitioning()&&!f.runtime.retainsCapturedOwner(home.sessionId),"captured drain retry did not finish the exact two-generation transition");
   Result replay=new Result();f.runtime.restore(restore,AndroidHomeStateStore.snapshot(f.service),replay);replay.finished();check(replay.ok&&f.runtime.restoredMatches(restore),"original ordered source could not restore after captured cleanup retry");f.stop();
  }
  try(Fixture f=new Fixture(4)){
   f.connected();AndroidNodeChainSession original=f.owner();String home=original.home.sessionId;Method shutdown=LayeredVpnService.class.getDeclaredMethod("shutdown",String.class,String.class);shutdown.setAccessible(true);shutdown.invoke(f.service,"FAILED","native watchdog retired original proof");
   check(original.released()&&!f.runtime.retainsCapturedOwner(home)&&!f.runtime.disconnectAndDrainCaptured(home),"terminal owner before captured stop was reported as retryable native cleanup");
   check(AndroidHomeStateStore.snapshot(f.service).sessionId.equals(home)&&!AndroidHomeStateStore.snapshot(f.service).connected,"terminal captured-stop query replaced the final Home receipt");
  }
  try(Fixture f=new Fixture(4)){
   f.connected();AndroidNodeChainSession original=f.owner();String home=original.home.sessionId;CommandServer server=(CommandServer)get(f.service,"commandServer");server.failClose=true;
   Method shutdown=LayeredVpnService.class.getDeclaredMethod("shutdown",String.class,String.class);shutdown.setAccessible(true);reject(()->shutdown.invoke(f.service,"FAILED","native watchdog retired original proof"),"failed original watchdog cleanup was not retained");
   check(f.runtime.retainsCapturedOwner(home)&&!AndroidHomeStateStore.snapshot(f.service).connected,"failed original watchdog owner lost its cleanup authority");
   check(!f.runtime.disconnectAndDrainCaptured(home)&&f.runtime.retainsCapturedOwner(home),"failed original proof became restoration authority during cleanup");
   check(uncaught.isEmpty(),"native cleanup failure escaped the ordered worker and could terminate Android");
   server.failClose=false;check(!f.runtime.disconnectAndDrainCaptured(home),"retiring a failed original proof authorized temporary restoration");
   check(original.released()&&!f.runtime.retainsCapturedOwner(home)&&!f.runtime.isActiveOrTransitioning(),"failed original watchdog owner did not become terminal after captured cleanup retry");
  }
 }
 static void selectionOwnership()throws Exception {
  for(boolean restoring:new boolean[]{false,true})try(Fixture f=new Fixture(4)){
   var prefs=f.service.getSharedPreferences("router-vpn-unified",0);prefs.edit().putBoolean("multihop_on",true).apply();AndroidNodeChainRuntime.RestoreCapture capture=null;
   if(restoring){f.connected();capture=f.runtime.captureRestore();check(f.runtime.disconnectAndDrainCaptured(AndroidHomeStateStore.snapshot(f.service).sessionId),"selection restore fixture did not stop its original owner");}
   var idle=AndroidHomeStateStore.snapshot(f.service);String selection=AndroidNodeChainSession.selection(f.service,f.source);int created=CommandServer.created;
   CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);((ExecutorService)get(f.runtime,"executor")).submit(()->{entered.countDown();try{release.await(3,TimeUnit.SECONDS);}catch(InterruptedException stopped){Thread.currentThread().interrupt();}});check(entered.await(1,TimeUnit.SECONDS),"queued selection fixture did not hold admission");
   Result result=new Result();if(restoring)f.runtime.restore(capture,idle,result);else f.runtime.connect(f.source,idle,selection,result);prefs.edit().putBoolean("multihop_on",false).apply();release.countDown();result.finished();
   check(!result.ok&&created==CommandServer.created&&!f.runtime.isActiveOrTransitioning(),"queued ordered admission borrowed a newer saved Off choice");
   check(AndroidHomeStateStore.snapshot(f.service).pathGeneration==idle.pathGeneration&&AndroidHomeStateStore.snapshot(f.service).sessionId.equals(idle.sessionId),"stale saved ordered choice changed idle Home before rejection");
  }
  try(Fixture f=new Fixture(4)){
   var prefs=f.service.getSharedPreferences("router-vpn-unified",0);prefs.edit().putBoolean("multihop_on",true).apply();RouterNodeChain.configured=plan->plan.afterRun=()->prefs.edit().putBoolean("multihop_on",false).apply();
   Result result=f.connect();check(!result.ok&&!f.runtime.isConnected()&&!f.runtime.isActiveOrTransitioning(),"saved Off during native proof reached Connected");
  }
  try(Fixture f=new Fixture(4)){
   var prefs=f.service.getSharedPreferences("router-vpn-unified",0);prefs.edit().putBoolean("multihop_on",true).apply();f.connected();var capture=f.runtime.captureRestore();AndroidNodeChainSession original=f.owner();prefs.edit().putBoolean("multihop_on",false).apply();
   check(!LayeredVpnService.nodeChainReady(original),"live ordered native proof ignored a newer saved selection");check(!f.runtime.captureCurrent(capture),"restore capture ignored a newer saved selection");f.stop();
   Result result=new Result();f.runtime.restore(capture,AndroidHomeStateStore.snapshot(f.service),result);result.finished();check(!result.ok&&!f.runtime.isActiveOrTransitioning(),"restore recaptured the new saved choice instead of the original digest");
  }
 }
 static void lateDelivery()throws Exception {
  AndroidNodeChainSession retired;android.content.Intent late;
  try(Fixture f=new Fixture(4)){
   f.nativeOwner.delay=true;Result launch=new Result();f.runtime.connect(f.source,launch);await(()->f.nativeOwner.late!=null,"delayed native start was not staged");retired=f.owner();late=f.nativeOwner.late;
   Result stop=new Result();f.runtime.disconnect(stop);launch.finished();stop.finished();check(!launch.ok&&stop.ok&&retired.released(),"cancelled queued start lost its cleanup acknowledgement");
  }
  try(Fixture replacement=new Fixture(3)){
   replacement.connected();AndroidNodeChainSession original=replacement.owner();long generation=((java.util.concurrent.atomic.AtomicLong)get(replacement.service,"lifecycle")).get();
   replacement.nativeOwner.stopNodeChain(retired.sessionId);replacement.service.onStartCommand(late,0,99);replacement.drain();
   check(replacement.owner()==original&&replacement.runtime.isConnected()&&((java.util.concurrent.atomic.AtomicLong)get(replacement.service,"lifecycle")).get()==generation,"old ordered delivery changed a replacement native generation");replacement.stop();
  }
 }
 static void destroyedHost()throws Exception {
  try(Fixture f=new Fixture(4)){
   f.connected();AndroidNodeChainSession captured=f.owner();CommandServer server=(CommandServer)get(f.service,"commandServer");server.failClose=true;
   f.service.onDestroy();check(!captured.released()&&!((ExecutorService)get(f.service,"executor")).isShutdown(),"destroyed service discarded its retryable native drain authority");
   LayeredVpnService replacement=new LayeredVpnService();replacement.files=f.service.files;replacement.stores=f.service.stores;replacement.network=f.service.network;replacement.onCreate();
   try {
    int before=CommandServer.created;
    replacement.onStartCommand(new Intent().setAction(LayeredVpnService.ACTION_START).putExtra(LayeredVpnService.EXTRA_SESSION_ID,"f".repeat(32)).putExtra(LayeredVpnService.EXTRA_MODE_ID,"wg"),0,9);
    check(before==CommandServer.created,"recreated service replaced an unjoined original graph");
    server.failClose=false;new NativeSingBoxController(replacement).stopNodeChain(captured.sessionId);
    await(captured::released,"recreated service could not retry the original native host drain");
    check(!captured.directory.exists()&&server.checkedCloses>1&&get(replacement,"commandServer")==null,"recreated service used a replacement Box or lost exact private cleanup");
    NativeSingBoxController freshNative=new NativeSingBoxController(replacement);await(()->freshNative.getState().equals("DOWN"),"recreated idle host retained stale STOPPING after exact cleanup receipt");
    AndroidNodeChainRuntime fresh=new AndroidNodeChainRuntime(replacement,freshNative);
    try{Result launch=new Result();fresh.connect(new AndroidNodeStore.ChainCapture(3),launch);launch.finished();check(launch.ok&&fresh.isConnected(),"recreated host could not start after its exact old drain receipt");check(fresh.stopAndProve(),"fresh recreated native graph did not drain");}
    finally{((ExecutorService)get(fresh,"executor")).shutdownNow();}
   }finally{((ExecutorService)get(replacement,"executor")).shutdownNow();((ExecutorService)get(replacement,"nodeChainObservations")).shutdownNow();}
  }
 }
 static void idleEpoch()throws Exception {
  try(Fixture f=new Fixture(4)){
   var original=AndroidHomeStateStore.snapshot(f.service);
   AndroidHomeStateStore.warning(f.service,"Emergency Disconnect requested; waiting for original native owners.");AndroidHomeStateStore.disconnected(f.service);
   var completed=AndroidHomeStateStore.snapshot(f.service);int created=CommandServer.created;
   Result result=new Result();f.runtime.connect(f.source,original,result);result.finished();
   check(!result.ok&&!f.runtime.isActiveOrTransitioning()&&created==CommandServer.created,"completed Emergency epoch revived queued ordered launch");
   check(AndroidHomeStateStore.snapshot(f.service).pathGeneration==completed.pathGeneration,"stale ordered permission changed completed Emergency Home");
  }
 }
 static void watchdog()throws Exception {
  try(Fixture f=new Fixture(4)){
   f.connected();AndroidNodeChainSession captured=f.owner();RouterNodeChain plan=captured.capture.plan;
   android.os.Handler handler=(android.os.Handler)get(f.service,"executionHandler");handler.posted.clear();Runnable watch=(Runnable)get(f.service,"executionWatch");
   CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1),returned=new CountDownLatch(1);int reads=plan.healthCalls;
   plan.afterHealth=()->{entered.countDown();try{release.await(3,TimeUnit.SECONDS);}catch(InterruptedException stopped){Thread.currentThread().interrupt();}};
   Thread ui=new Thread(()->{watch.run();returned.countDown();});ui.start();
   try {
    check(returned.await(1,TimeUnit.SECONDS),"ordered watchdog blocked the main Handler on native proof");check(entered.await(1,TimeUnit.SECONDS),"ordered watchdog did not observe the original native proof");
    for(int i=0;i<5;i++)watch.run();check(plan.healthCalls==reads+1,"ordered watchdog queued overlapping native observations");plan.valid=false;
   }finally{release.countDown();ui.join(4000);}
   await(()->!handler.posted.isEmpty(),"ordered observation did not return its captured verdict");handler.runPosted();
   await(captured::released,"ordered watchdog did not retire the exact failed native owner");check(!AndroidHomeStateStore.snapshot(f.service).connected,"ordered watchdog kept expired Connected proof");
  }
 }
 static void lateDestroyedProof()throws Exception {
  CountDownLatch entered=new CountDownLatch(1),unwind=new CountDownLatch(1);
  try(Fixture old=new Fixture(4)){
   // The native proof returns before the Java source check pauses. Native
   // Close may therefore join honestly while that old host callback is late.
   RouterNodeChain.configured=plan->plan.afterRun=()->{old.source.hookThread=Thread.currentThread();old.source.beforeCurrent=()->{entered.countDown();try{unwind.await(10,TimeUnit.SECONDS);}catch(InterruptedException stopped){Thread.currentThread().interrupt();}};};
   Result launch=new Result();old.runtime.connect(old.source,launch);check(entered.await(3,TimeUnit.SECONDS),"old native proof did not reach its delayed host return");
   AndroidNodeChainSession captured=old.owner();old.service.onDestroy();check(captured.released(),"destroyed old proof did not finish its native join");
   try(Fixture replacement=new Fixture(3)){
    replacement.service.stores=old.service.stores;replacement.connected();String home=AndroidHomeStateStore.snapshot(replacement.service).sessionId;
    unwind.countDown();check(((ExecutorService)get(old.service,"executor")).awaitTermination(4,TimeUnit.SECONDS),"old native proof did not unwind after replacement");launch.finished();
    check(replacement.nativeOwner.getState().equals("UP")&&replacement.runtime.isConnected(),"late destroyed host overwrote replacement service state");
    check(AndroidHomeStateStore.snapshot(replacement.service).sessionId.equals(home)&&AndroidHomeStateStore.snapshot(replacement.service).connected,"late old proof replaced the new Home owner");replacement.stop();
   }
  }finally{unwind.countDown();}
 }
 static void preclaim()throws Exception {
  try(Fixture f=new Fixture(4)){
   f.service.getSharedPreferences("router-vpn",0).edit().putString("layered_state_v1","FAILED").putString("layered_error_v1","old failure").apply();f.nativeOwner.delay=true;
   Result launch=new Result();f.runtime.connect(f.source,launch);await(()->f.nativeOwner.late!=null,"fresh start was not captured before delivery");
   check(!launch.done.await(150,TimeUnit.MILLISECONDS),"old terminal state rejected a fresh unclaimed ordered source");
   f.service.onStartCommand(f.nativeOwner.late,0,1);launch.finished();check(launch.ok&&f.runtime.isConnected(),"fresh ordered source did not survive stale prior FAILED state");f.stop();
  }
  try(Fixture f=new Fixture(4)){
   f.nativeOwner.beforeStart=()->android.net.VpnService.revoked=true;int created=CommandServer.created;Result launch=new Result();f.runtime.connect(f.source,launch);
   check(launch.done.await(4,TimeUnit.SECONDS),"preclaim ordered failure retained its private owner indefinitely");
   check(!launch.ok&&created==CommandServer.created&&!f.runtime.isActiveOrTransitioning()&&AndroidNodeChainSession.retained()==null,"revoked preclaim source started or lost exact cleanup");
  }finally{android.net.VpnService.revoked=false;}
 }
 static void publicationFence()throws Exception {
  CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1),claiming=new CountDownLatch(1),claimed=new CountDownLatch(1);
  try(Fixture old=new Fixture(3)){
   var store=(android.content.Context.Store)old.service.getSharedPreferences("router-vpn",0);
   Method publish=LayeredVpnService.class.getDeclaredMethod("publish",String.class,String.class,String.class);publish.setAccessible(true);
   var failure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
   LayeredVpnService replacement=new LayeredVpnService();replacement.files=old.service.files;replacement.stores=old.service.stores;replacement.network=old.service.network;
   Thread oldWriter=new Thread(()->{try{publish.invoke(old.service,"FAILED","node-chain","old callback");}catch(Throwable error){failure.set(error);}});
   Thread newWriter=new Thread(()->{try{claiming.countDown();replacement.onCreate();claimed.countDown();publish.invoke(replacement,"STARTING","node-chain","");}catch(Throwable error){failure.set(error);}});
   store.applyThread=oldWriter;store.beforeApply=()->{entered.countDown();try{release.await(5,TimeUnit.SECONDS);}catch(InterruptedException stopped){Thread.currentThread().interrupt();}};
   try {
    oldWriter.start();check(entered.await(2,TimeUnit.SECONDS),"old publication did not reach the checked preference write");newWriter.start();check(claiming.await(2,TimeUnit.SECONDS),"replacement did not attempt service ownership");
    check(!claimed.await(200,TimeUnit.MILLISECONDS),"replacement claimed ownership inside an unfinished old state publication");
   }finally{release.countDown();oldWriter.join(3000);newWriter.join(3000);store.beforeApply=null;((ExecutorService)get(replacement,"executor")).shutdownNow();((ExecutorService)get(replacement,"nodeChainObservations")).shutdownNow();}
   check(!oldWriter.isAlive()&&!newWriter.isAlive()&&failure.get()==null,"service publication fence did not finish both owners");
   check(old.nativeOwner.getState().equals("STARTING"),"old checked publication overwrote the replacement state");
  }finally{release.countDown();}
 }
 static void sameRuntimeReplacement()throws Exception {
  CountDownLatch entered=new CountDownLatch(1),unwind=new CountDownLatch(1);
  try(Fixture original=new Fixture(4)){
   Result old=new Result();RouterNodeChain.configured=plan->plan.afterRun=()->{original.source.hookThread=old.worker;original.source.beforeCurrent=()->{entered.countDown();try{unwind.await(10,TimeUnit.SECONDS);}catch(InterruptedException stopped){Thread.currentThread().interrupt();}};};
   original.runtime.connect(original.source,old);check(entered.await(3,TimeUnit.SECONDS),"old runtime did not pause after native proof returned");
   original.stop();original.service.onDestroy();
   LayeredVpnService replacement=new LayeredVpnService();replacement.files=original.service.files;replacement.stores=original.service.stores;replacement.network=original.service.network;replacement.onCreate();original.nativeOwner.service=replacement;RouterNodeChain.configured=null;
   try {
    Result fresh=new Result();original.runtime.connect(new AndroidNodeStore.ChainCapture(3),fresh);check(fresh.done.getCount()==1,"new runtime admission was not queued behind old worker");
    unwind.countDown();old.finished();fresh.finished();check(!old.ok&&fresh.ok&&original.runtime.isConnected(),"old runtime catch cancelled the queued replacement operation");
    check(original.runtime.activeSources().size()==3&&original.runtime.stopAndProve(),"queued replacement lost its exact new source or cleanup");
   }finally{((ExecutorService)get(replacement,"executor")).shutdownNow();((ExecutorService)get(replacement,"nodeChainObservations")).shutdownNow();}
  }finally{unwind.countDown();}
 }
 static void ownedProof()throws Exception {
  try(Fixture f=new Fixture(4)){
   f.connected();AndroidNodeChainSession original=f.owner();AndroidMTUSession mtu=(AndroidMTUSession)get(f.service,"mtuSession");
   original.capture.plan.afterHealth=()->{mtu.token=null;original.capture.plan.valid=false;};
   check(LayeredVpnService.nodeChainReady(original),"owned MTU mutation was mistaken for expired ordered proof");mtu.token=2L;
   check(!LayeredVpnService.nodeChainReady(original),"stable failed ordered proof survived an MTU observation");original.capture.plan.valid=true;
   mtu.current=false;check(!LayeredVpnService.nodeChainReady(original),"retired MTU owner deferred proof forever");mtu.current=true;
   f.service.network.physical=new android.net.Network();check(!LayeredVpnService.nodeChainReady(original),"ordered proof adopted another physical network");
   f.runtime.networkChanged(original.home);await(()->!f.runtime.isActiveOrTransitioning(),"network failure did not retire original complete graph");check(!AndroidHomeStateStore.snapshot(f.service).connected,"network failure retained stale Connected");
  }
  try(Fixture f=new Fixture(4)){
   f.connected();AndroidNodeChainSession original=f.owner();
   AndroidHomeStateStore.begin(f.service,"new","new","libbox","replacement");
   reject(original::requireCurrent,"changed Home still authorized the original native source");
  }
 }
 static void orderedMeasurement()throws Exception {
  for(int count:new int[]{3,8})try(Fixture f=new Fixture(count)){
   f.connected();AndroidNodeChainSession chain=f.owner();RouterHopMeasurement probe=(RouterHopMeasurement)get(f.service,"hopMeasurement");
   check(probe!=null,"proved ordered chain never adopted native measurement");String request="a".repeat(32);
   LayeredVpnService.HopMeasurementOwner owner=LayeredVpnService.captureHopMeasurement(request);owner.start();owner.status();
   check(probe.starts==1&&probe.request.equals(request),"ordered path dispatched another native measurement");
   f.source.valid=false;reject(owner::status,"changed intermediate source published ordered measurements");
   owner.cancel();owner.drain();check(probe.cancels==1&&probe.drains==1,"stale source lost original measurement cleanup");f.source.valid=true;
   chain.capture.plan.valid=false;reject(owner::status,"expired ordered proof published measurements");chain.capture.plan.valid=true;
   f.stop();check(probe.invalidated&&probe.closes>0,"ordered Stop dropped native measurement without close");reject(owner::status,"retired ordered owner published measurements");
  }
 }
 public static void main(String[] args)throws Exception {
  Thread.UncaughtExceptionHandler previous=Thread.getDefaultUncaughtExceptionHandler();Thread.setDefaultUncaughtExceptionHandler((thread,failure)->uncaught.add(failure));
  try {
  String family=args.length==0?"all":args[0];
  if(family.equals("all")||family.equals("measurement"))orderedMeasurement();
  if(family.equals("all")||family.equals("success"))success();if(family.equals("all")||family.equals("source"))staleSources();if(family.equals("all")||family.equals("cleanup"))pendingCleanup();if(family.equals("all")||family.equals("late"))lateDelivery();if(family.equals("all")||family.equals("proof"))ownedProof();if(family.equals("all")||family.equals("destroyed"))destroyedHost();if(family.equals("all")||family.equals("idle"))idleEpoch();if(family.equals("all")||family.equals("watchdog"))watchdog();if(family.equals("all")||family.equals("late-destroyed"))lateDestroyedProof();if(family.equals("all")||family.equals("preclaim"))preclaim();if(family.equals("all")||family.equals("same-runtime"))sameRuntimeReplacement();if(family.equals("all")||family.equals("publication"))publicationFence();if(family.equals("all")||family.equals("captured-drain"))capturedDrainRetry();if(family.equals("all")||family.equals("selection"))selectionOwnership();
  check(uncaught.isEmpty(),"native cleanup failure escaped the ordered worker and could terminate Android");
  System.out.println("Android ordered native host ownership: "+checks+" executable checks passed; OS/native handles doubled.");
  } finally {Thread.setDefaultUncaughtExceptionHandler(previous);}
 }
}'''


def main():
    measurement_only = sys.argv[1:] == ['--measurement-only']
    if sys.argv[1:] and not measurement_only: raise ValueError('Unknown ordered runtime test selection')
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):
        raise RuntimeError('JDK and the actual Android JSON library are required')
    with tempfile.TemporaryDirectory(prefix='routervpn-ordered-runtime-') as directory:
        work = Path(directory)
        src = work / 'src'
        for path, text in SOURCES.items():
            target = src / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        app = src / APP
        names = ('AndroidHomeStateStore', 'AndroidConnectionSelection', 'AndroidNodeChainSession', 'AndroidNodeChainRuntime', 'LayeredVpnService')
        originals = {}
        for name in names:
            originals[name] = (JAVA / (name + '.java')).read_text()
            (app / (name + '.java')).write_text(originals[name])
        (app / 'OrderedRuntimeTest.java').write_text(HARNESS)
        classes = work / 'classes'
        command = ['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', str(jar), '-d', str(classes), *map(str, src.rglob('*.java'))]
        subprocess.run(command, check=True, timeout=60)
        run = ['java', '-cp', os.pathsep.join((str(classes), str(jar))), 'com.eabusham.routervpn.OrderedRuntimeTest']
        subprocess.run(run + (["measurement"] if measurement_only else []), check=True, timeout=120)
        controls = (
            ('LayeredVpnService', '                adoptHopMeasurement(capturedChain.newHopMeasurement(), ownedServer, generation);', '', 'measurement', 'proved ordered chain never adopted native measurement'),
            ('LayeredVpnService', 'if(chain!=service.nodeChainSession || chain!=null&&!chain.healthy())', 'if(false)', 'measurement', 'changed intermediate source published ordered measurements'),
            ('AndroidNodeChainSession', '        value.requireFiles();', '', 'source', 'stale ordered source/proof reached Connected: launch'),
            ('AndroidNodeChainSession', '        capture.requireCurrent();', '', 'source', 'stale ordered source/proof reached Connected: middle'),
            ('AndroidNodeChainSession', '        if (!AndroidHomeStateStore.ownsNodeChain(context, home))', '        if (false)', 'proof', 'changed Home still authorized the original native source'),
            ('LayeredVpnService', '                chain.closePlan();\n                if (mtu != null) mtu.close();', '                if (mtu != null) mtu.close();', 'cleanup', 'native owner did not acknowledge complete cleanup'),
            ('LayeredVpnService', 'if (nodeChainSession == null) executor.shutdown();', 'executor.shutdown();', 'destroyed', 'destroyed service discarded its retryable native drain authority'),
            ('AndroidNodeChainRuntime', 'idle.pathGeneration != now.pathGeneration', 'false', 'idle', 'completed Emergency epoch revived queued ordered launch'),
            ('LayeredVpnService', 'nodeChainObservations.execute(() -> {', '((java.util.concurrent.Executor) Runnable::run).execute(() -> {', 'watchdog', 'ordered watchdog blocked the main Handler on native proof'),
            ('LayeredVpnService', '        if (currentService.get() != this) return;', '', 'late-destroyed', 'late destroyed host overwrote replacement service state'),
            ('AndroidNodeChainRuntime', 'session.claimed() && ("FAILED".equals', 'true && ("FAILED".equals', 'preclaim', 'old terminal state rejected a fresh unclaimed ordered source'),
            ('LayeredVpnService', 'preparedChain == null ? AndroidNodeChainSession.pending(sessionId) : preparedChain', 'preparedChain', 'preclaim', 'preclaim ordered failure retained its private owner indefinitely'),
            ('LayeredVpnService', 'currentService.get() == this && lifecycle.get() == generation && nodeChainSession == null', 'false && lifecycle.get() == generation && nodeChainSession == null', 'destroyed', 'recreated idle host retained stale STOPPING after exact cleanup receipt'),
            ('AndroidNodeChainRuntime', 'if(operation==selectedOperation){connected = false; transitioning = false; reconcile();}', '{connected = false; transitioning = false; reconcile();}', 'same-runtime', 'old runtime catch cancelled the queued replacement operation'),
            ('LayeredVpnService', 'synchronized (PUBLICATION_LOCK) {\n            if (currentService.get() != this) return;', 'synchronized (new Object()) {\n            if (currentService.get() != this) return;', 'publication', 'replacement claimed ownership inside an unfinished old state publication'),
            ('LayeredVpnService', 'synchronized (PUBLICATION_LOCK) {\n            currentService=new java.lang.ref.WeakReference<>(this);', 'synchronized (new Object()) {\n            currentService=new java.lang.ref.WeakReference<>(this);', 'publication', 'replacement claimed ownership inside an unfinished old state publication'),
            ('AndroidNodeChainRuntime', 'connect(capture.source, idle, capture.selection, false, callback);', 'connect(capture.source, idle, capture.selection, true, callback);', 'success', 'temporary restoration overwrote ordered Last history'),
            ('AndroidNodeChainRuntime', 'recordOrderedExecution(context, history,', 'recordOrderedExecution(context, null,', 'success', 'fresh proved ordered connection did not record its captured Local choice'),
            ('AndroidNodeChainRuntime', 'connectSelected(capture,idle,false,callback);', 'connectSelected(capture,idle,true,callback);', 'success', 'Startup Last overwrote its original ordered history'),
            ('AndroidNodeChainRuntime', 'capturedDrain == captured && capturedDrainOperation == operation', 'false', 'captured-drain', 'same captured drain could not retry its original native cleanup'),
            ('AndroidNodeChainRuntime', 'owner.released() && owner != capturedDrain', 'owner.released()', 'captured-drain', 'late release lost its pending exact Home receipt'),
            ('AndroidNodeChainSession', '        requireSelection(context,source,selectionDigest);', '', 'selection', 'live ordered native proof ignored a newer saved selection'),
            ('AndroidNodeChainRuntime', 'boolean failedOwner = !now.connected', 'boolean failedOwner = false && !now.connected', 'captured-drain', 'failed original watchdog owner did not become terminal after captured cleanup retry'),
            ('LayeredVpnService', 'Log.w(TAG,"Native cleanup remains owned for retry",pending);', 'if(pending!=null)throw new IllegalStateException("uncaught native cleanup regression",pending);', 'captured-drain', 'native cleanup failure escaped the ordered worker and could terminate Android'),
        )
        for number, (name, old, new, family, witness) in enumerate(controls):
            if measurement_only and family != "measurement": continue
            source = originals[name]
            if source.count(old) != 1:
                raise AssertionError('Ordered causal control lost its exact seam: ' + name + ':' + old)
            mutant = work / ('mutant-' + str(number)) / (name + '.java')
            mutant.parent.mkdir()
            mutant.write_text(source.replace(old, new))
            out = work / ('negative-' + str(number))
            shutil.copytree(classes, out)
            cp = os.pathsep.join((str(out), str(jar)))
            subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', cp, '-d', str(out), str(mutant)], check=True, timeout=60)
            result = subprocess.run(['java', '-cp', cp, 'com.eabusham.routervpn.OrderedRuntimeTest', family], capture_output=True, text=True, timeout=60)
            if result.returncode == 0 or witness not in result.stderr:
                raise AssertionError('Ordered causal control missed its defect: ' + family + '\n' + result.stdout + '\n' + result.stderr)
            print('Android ordered host causal control rejected: ' + name + '/' + family)


if __name__ == '__main__':
    main()
