#!/usr/bin/env python3
"""Run shipping Speed Lab + unified bridge through captured restore/cancel transactions."""
from pathlib import Path
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'
spec = importlib.util.spec_from_file_location('restore_permissions', ROOT/'android/test_android_external_permission.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

OWNERS = r'''
final class AndroidHomeStateStore {
 static final class Snapshot {boolean connected;long pathGeneration;String sessionId="",phase="off",pathProof="not-run",logicalMode="",runtimeMode="",fallback="",activeNodeId="",activeEntryId="",activeExitId="",activeEntryMode="",activeExternalId="",activeExternalProtocol="";}
 static volatile Snapshot current=new Snapshot();static int serial;
 static Snapshot snapshot(Context c){return current;}
 static Snapshot copy(){Snapshot a=current,b=new Snapshot();b.connected=a.connected;b.pathGeneration=a.pathGeneration;b.sessionId=a.sessionId;b.phase=a.phase;b.pathProof=a.pathProof;b.logicalMode=a.logicalMode;b.runtimeMode=a.runtimeMode;b.fallback=a.fallback;b.activeNodeId=a.activeNodeId;b.activeEntryId=a.activeEntryId;b.activeExitId=a.activeExitId;b.activeEntryMode=a.activeEntryMode;b.activeExternalId=a.activeExternalId;b.activeExternalProtocol=a.activeExternalProtocol;return b;}
 static long advancePathGeneration(Context c){Snapshot s=copy();s.pathGeneration++;current=s;return s.pathGeneration;}
 static Snapshot begin(String topology,String raw,String entry,String exit,String mode,String external){Snapshot s=new Snapshot();s.pathGeneration=current.pathGeneration+1;s.sessionId="native-"+(++serial);s.logicalMode=topology;s.phase="connecting";s.pathProof="pending";s.runtimeMode=raw;s.activeNodeId=exit;s.activeEntryId=entry;s.activeExitId=exit;s.activeEntryMode=mode;s.activeExternalId=external;s.activeExternalProtocol=topology.equals("external")?raw:"";current=s;return s;}
 static void proved(){Snapshot s=copy();s.connected=true;s.phase="connected";s.pathProof="passed";current=s;RuntimeBoundary.proofs++;}
 static void off(){Snapshot s=new Snapshot();s.pathGeneration=current.pathGeneration+1;current=s;}
}
final class RuntimeBoundary {
 static volatile boolean holdConnect,holdRestore,holdStop,stopEntered,stopping;
 static volatile Runnable pendingConnect,pendingRestore,afterRestoredProof,afterOrdinaryProof;static volatile java.util.concurrent.CountDownLatch stopRelease;
 static int starts,stops,restores,proofs;static String restoredPins="",restoredRaw="",restoredLogical="",restoredExecution="",restoredEntry="",restoredExternal="";
 static void reset(){holdConnect=false;holdRestore=false;holdStop=false;stopEntered=false;stopping=false;pendingConnect=null;pendingRestore=null;afterRestoredProof=null;afterOrdinaryProof=null;stopRelease=new java.util.concurrent.CountDownLatch(1);starts=stops=restores=proofs=0;restoredRaw=restoredLogical=restoredExecution=restoredEntry=restoredExternal="";}
 static void ready(Runnable r){if(holdConnect)pendingConnect=r;else r.run();}
 static boolean stop(String id)throws Exception{if(!id.equals(AndroidHomeStateStore.current.sessionId))return false;stops++;stopping=true;AndroidHomeStateStore.Snapshot s=AndroidHomeStateStore.copy();if(s.connected)s.pathGeneration++;s.connected=false;s.phase="connecting";s.pathProof="pending";AndroidHomeStateStore.current=s;stopEntered=true;if(holdStop)stopRelease.await();boolean owned=id.equals(AndroidHomeStateStore.current.sessionId);if(owned)AndroidHomeStateStore.off();stopping=false;return owned;}
}
final class AndroidModeOrchestrator {
 interface Callback{void progress(String message);void finished(boolean ok,String mode,String message);default void owned(String id){}default void proved(String session,String raw,String source){}}
 void startup(File f,String mode,String raw,String source,Callback cb){throw new AssertionError("temporary Speed Lab cannot become startup");}
 String source="";
 String captureSource(File f,String id,String raw)throws Exception{String now=Files.readString(f.toPath());if(!source.equals(now)||!id.equals(AndroidHomeStateStore.current.sessionId))throw new IllegalStateException("active exact source changed");return now;}
 void restoreCaptured(File f,String raw,String logical,String fallback,String expected,Callback cb){try{if(!expected.equals(Files.readString(f.toPath())))throw new IllegalStateException("changed original");RuntimeBoundary.restores++;RuntimeBoundary.restoredRaw=raw;RuntimeBoundary.restoredLogical=logical;source=expected;AndroidHomeStateStore.begin(logical,raw,"",node(f),"","");cb.owned(AndroidHomeStateStore.current.sessionId);Runnable finish=()->{AndroidHomeStateStore.proved();if(RuntimeBoundary.afterRestoredProof!=null)RuntimeBoundary.afterRestoredProof.run();cb.finished(true,raw,"fresh restored proof");};if(RuntimeBoundary.holdRestore)RuntimeBoundary.pendingRestore=finish;else finish.run();}catch(Exception e){cb.finished(false,"",e.toString());}}
 void disconnectCaptured(String id,Callback cb){new Thread(()->{try{cb.finished(RuntimeBoundary.stop(id),"","captured router drain");}catch(Exception e){cb.finished(false,"",e.toString());}}).start();}
 void disconnect(Callback cb){AndroidHomeStateStore.off();cb.finished(true,"","stopped");}
 static String node(File f){return f.getName().replace(".json","");}
 void start(File f,String logical,String raw,Callback cb){RuntimeBoundary.starts++;try{source=Files.readString(f.toPath());}catch(Exception e){cb.finished(false,"",e.toString());return;}AndroidHomeStateStore.begin(logical,raw,"",node(f),"","");cb.owned(AndroidHomeStateStore.current.sessionId);RuntimeBoundary.ready(()->{AndroidHomeStateStore.proved();cb.finished(true,raw,"proved test");});}
 void auto(File f,boolean smart,Callback cb){start(f,smart?"SMART AUTO":"AUTO","wg-pq",cb);}void all(File f,Callback cb){start(f,"ALL","max-quic-awg",cb);}void custom(File f,List<String> layers,Callback cb){start(f,"CUSTOM","reality-vision",cb);}void logical(File f,String mode,Callback cb){start(f,mode,mode,cb);}
}
final class AndroidMultihopRuntime {
 // MULTIHOP_CAPTURE_TYPES
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String id){}}
 String execution="local",selected="local",serverPins="original-public-pins";
 RestoreCapture captureRestore(AndroidNodeStore.Node a,AndroidNodeStore.Node b,AndroidHomeStateStore.Snapshot home)throws Exception{return new RestoreCapture(execution,selected,home,a,b,serverPins);}
 boolean captureCurrent(RestoreCapture capture){return capture!=null&&capture.owner.matchesHome(AndroidHomeStateStore.current)&&capture.owner.pins.equals(serverPins)&&capture.policy.equals(execution)&&capture.selected.equals(selected);}
 boolean restoredMatches(RestoreCapture capture,AndroidNodeStore.Node a,AndroidNodeStore.Node b,AndroidHomeStateStore.Snapshot home){try{capture.require(a,b);return capture.policy.equals(execution)&&capture.selected.equals(selected)&&capture.owner.pins.equals(serverPins)&&capture.owner.entryMode.equals(home.activeEntryMode)&&capture.owner.exitMode.equals(home.runtimeMode);}catch(Exception changed){return false;}}
 boolean isConnected(){return AndroidHomeStateStore.current.connected&&AndroidHomeStateStore.current.logicalMode.equals("multihop");}boolean isActiveOrTransitioning(){return isConnected();}
 String activeEntryId(){return AndroidHomeStateStore.current.activeEntryId;}String activeExitId(){return AndroidHomeStateStore.current.activeExitId;}String activeEntryMode(){return AndroidHomeStateStore.current.activeEntryMode;}String activeExitMode(){return AndroidHomeStateStore.current.runtimeMode;}String activeExecution(){return execution;}String activeSelectedExecution(){return selected;}
 boolean disconnectAndDrainCaptured(String id)throws Exception{return RuntimeBoundary.stop(id);}void disconnect(){}
 void connect(AndroidNodeStore.Node a,AndroidNodeStore.Node b,String mode,String exec,String entry,Callback cb){RuntimeBoundary.starts++;execution=exec;selected=exec.equals("auto")?"server":exec;AndroidHomeStateStore.begin("multihop",mode,a.id,b.id,entry,"");cb.owned(AndroidHomeStateStore.current.sessionId);RuntimeBoundary.ready(()->{AndroidHomeStateStore.proved();cb.finished(true,"proved graph");});}
 void connectLast(AndroidNodeStore.Node a,AndroidNodeStore.Node b,StartupCapture capture,AndroidHomeStateStore.Snapshot idle,Callback cb){throw new AssertionError("temporary restore must use runtime-only capture");}
 void restoreCaptured(AndroidNodeStore.Node a,AndroidNodeStore.Node b,RestoreCapture capture,AndroidHomeStateStore.Snapshot idle,Callback cb){try{capture.require(a,b);}catch(Exception changed){cb.finished(false,changed.toString());return;}String mode=capture.owner.exitMode,policy=capture.policy,winner=capture.selected,entry=capture.owner.entryMode;RuntimeBoundary.restoredPins=capture.owner.pins;RuntimeBoundary.restores++;RuntimeBoundary.restoredExecution=winner;execution=policy;selected=winner;AndroidHomeStateStore.begin("multihop",mode,a.id,b.id,entry,"");cb.owned(AndroidHomeStateStore.current.sessionId);Runnable finish=()->{AndroidHomeStateStore.proved();if(RuntimeBoundary.afterRestoredProof!=null)RuntimeBoundary.afterRestoredProof.run();cb.finished(true,"fresh exact winner proof");};if(RuntimeBoundary.holdRestore)RuntimeBoundary.pendingRestore=finish;else finish.run();}
 List<NativeSingBoxController.ModeInfo> listSupportedExitModes(File f){return Collections.emptyList();}
}
final class AndroidStandardExitRuntime {
 String execution="local",selected="local",restoredResponseMap="";
 AndroidStandardExitStore.Entry ordinaryEntry;
 AndroidStandardExitStore.Entry capturedOrdinaryEntry(AndroidHomeStateStore.Snapshot s){if(ordinaryEntry==null)return null;if(!s.connected||!s.sessionId.equals(AndroidHomeStateStore.current.sessionId)||!s.activeEntryId.equals(ordinaryEntry.id))throw new IllegalStateException("ordinary runtime owner changed");return AndroidStandardExitStore.copy(ordinaryEntry);}
 String capturedRequestedExecution(AndroidHomeStateStore.Snapshot s){return execution;}String capturedExternalExecution(AndroidHomeStateStore.Snapshot s){return selected;}
 void connect(File f,AndroidStandardExitStore.Entry e,String mode,String execution,Callback cb){this.execution=execution;selected=execution.equals("auto")?"server":execution;connect(f,e,mode,cb);}
 void restoreCaptured(File f,AndroidStandardExitStore.Entry e,String mode,String execution,String winner,Callback cb){RuntimeBoundary.restores++;RuntimeBoundary.restoredExecution=winner;this.execution=execution;selected=winner;restoredResponseMap=e.responseMap;connect(f,e,mode,new Callback(){public void owned(String id){cb.owned(id);}public void progress(String message){cb.progress(message);}public void finished(boolean ok,String message){if(ok&&RuntimeBoundary.afterRestoredProof!=null)RuntimeBoundary.afterRestoredProof.run();cb.finished(ok,message);}});}
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String id){}}
 boolean isActiveOrTransitioning(){return AndroidHomeStateStore.current.connected&&AndroidHomeStateStore.current.logicalMode.equals("external");}
 String capturedTorExit(AndroidHomeStateStore.Snapshot s){return "8.8.4.4";}String capturedExternalExit(AndroidHomeStateStore.Snapshot s){return "8.8.4.4";}
 void disconnect(){}boolean disconnectCaptured(String id)throws Exception{return RuntimeBoundary.stop(id);}boolean disconnectAndDrainCaptured(String id)throws Exception{return RuntimeBoundary.stop(id);}
 void connectDirect(AndroidStandardExitStore.Entry e,Callback cb){connect(null,e,"",cb);}void connect(File f,AndroidStandardExitStore.Entry e,String mode,Callback cb){ordinaryEntry=null;RuntimeBoundary.starts++;AndroidHomeStateStore.begin("external",e.protocol,f==null?"":AndroidModeOrchestrator.node(f),"",mode,e.id);cb.owned(AndroidHomeStateStore.current.sessionId);RuntimeBoundary.ready(()->{AndroidHomeStateStore.proved();cb.finished(true,"proved external");});}
 void connectOrdinary(AndroidStandardExitStore.Entry entry,AndroidStandardExitStore.Entry exit,String execution,Callback cb){ordinaryEntry=AndroidStandardExitStore.copy(entry);this.execution=execution;selected=execution;RuntimeBoundary.starts++;AndroidHomeStateStore.begin("external",exit.protocol,entry.id,"",AndroidExternalPolicy.protocol(entry.protocol),exit.id);cb.owned(AndroidHomeStateStore.current.sessionId);RuntimeBoundary.ready(()->{AndroidHomeStateStore.proved();if(RuntimeBoundary.afterOrdinaryProof!=null)RuntimeBoundary.afterOrdinaryProof.run();cb.finished(true,"proved ordinary Tor");});}
}
'''
OWNERS = OWNERS.replace('// MULTIHOP_CAPTURE_TYPES',P.MULTIHOP_CAPTURE_TYPES)

METERS = r'''
// Saved preference/private-store boundary; the real profile store has its own
// executable transactional tests. The actual dialog consumes this exact tuple.
final class AndroidConnectionProfileStore {
 static ExternalSelection saved;
 static final class ExternalSelection {final AndroidNodeStore.Node entry;final AndroidStandardExitStore.Entry ordinaryEntry,exit;final String entryMode,execution;ExternalSelection(AndroidNodeStore.Node e,AndroidStandardExitStore.Entry x,String m,String c){this(e,null,x,m,c);}ExternalSelection(AndroidNodeStore.Node e,AndroidStandardExitStore.Entry ordinary,AndroidStandardExitStore.Entry x,String m,String c){entry=e;ordinaryEntry=ordinary;exit=x;entryMode=m;execution=c;}boolean direct(){return entry==null&&ordinaryEntry==null;}}
 AndroidConnectionProfileStore(Context c,AndroidNodeStore n,AndroidStandardExitStore e){}
 ExternalSelection currentExternalPath(String id){if(saved==null||!saved.exit.id.equals(id))throw new IllegalStateException("stale saved selection");return saved;}
}
final class LayeredVpnService {static java.util.function.Consumer<Throwable> quiesce;static int automatic;static void quiesceMTUForSpeedLab(java.util.function.Consumer<Throwable> cb){quiesce=cb;}static void startAutomaticMTU(){automatic++;}}
final class AndroidSpeedLab {
 interface Callback{void finished(Result result,Throwable error);}static final class Latency{double medianMs,p90Ms;String detail(){return "latency";}}static final class Transfer{double mbps,bufferbloatMs;Latency loadedLatency=new Latency();}static final class Result{Latency idle=new Latency();Transfer download=new Transfer(),upload=new Transfer();String pathIdentity="captured";org.json.JSONObject json(){return new org.json.JSONObject();}String summary(){return "measured";}}
 // PRODUCTION_DURATION
 static double round(double n){return n;}static volatile Callback pending;static int starts,cancels;static boolean active;
 AndroidSpeedLab(android.app.Activity a){}void run(String m,double l,double h,Callback cb){starts++;active=true;pending=cb;}void cancel(){cancels++;}
 static void drained(boolean cancel){active=false;Callback cb=pending;pending=null;cb.finished(cancel?null:new Result(),cancel?new java.util.concurrent.CancellationException("http drained"):null);}
}
final class AndroidNativeHopMeasurement {
 interface Callback{void progress(String status);void finished(String status,Throwable error);}static boolean hold;static volatile Callback pending;static int starts,cancels;
 void run(Object lease,Callback cb){if(!AndroidMTUMeasurementGate.owns(lease))throw new AssertionError("native probe lost outer MTU lease");starts++;pending=cb;if(!hold)drained(false);}void cancel(){cancels++;}
 static void drained(boolean cancel){Callback cb=pending;pending=null;cb.finished(cancel?null:"native results drained",cancel?new java.util.concurrent.CancellationException("native drained"):null);}
}
final class AndroidHopMeasurementDialog{AndroidHopMeasurementDialog(android.app.Activity a,AndroidUnifiedConnectionController c){}void show(){}static String renderStatus(String s){return s;}}
final class AndroidSpeedLabHopMeter{static final class Hop{String summary(){return "hop";}}}
'''
HARNESS = r'''package com.eabusham.routervpn;
import android.app.*;import java.nio.file.*;import java.util.*;import org.json.*;
public final class SpeedLabRestoreTest {
 static int checks;static void check(boolean v,String msg){checks++;if(!v)throw new AssertionError(msg);}
 interface Condition{boolean ready();}static void waitFor(Condition c,String msg)throws Exception{long until=System.nanoTime()+3_000_000_000L;while(!c.ready()&&System.nanoTime()<until)Thread.sleep(2);check(c.ready(),msg);}
 static final class Result implements AndroidSpeedLabController.Callback {volatile int count;volatile Throwable error;volatile AndroidSpeedLab.Result result;public void progress(String s){}public void finished(AndroidSpeedLab.Result r,Throwable e){result=r;error=e;count++;}}
 static final class Fixture {
  final Activity activity=new Activity();final AndroidNodeStore nodes=new AndroidNodeStore(activity);final AndroidUnifiedConnectionController connection;final AndroidSpeedLabController controller;final Result result=new Result();final AndroidSpeedLabController.Request request=new AndroidSpeedLabController.Request();
  final AndroidNodeStore.Node original,first,last;final AndroidStandardExitStore.Entry external=new AndroidStandardExitStore.Entry();AndroidStandardExitStore.Entry originalOrdinary;final String type,raw;String originalSession,originalWinner="server";
  Fixture(Path directory,String type,String topology)throws Exception{check(!AndroidMTUMeasurementGate.held(),"previous case leaked hold");this.type=type;this.raw=type.equals("multihop")?"max-quic-awg":type.startsWith("external")?type.substring(9):"reality-pq-vision";
   RuntimeBoundary.reset();android.content.Context.speedPreferences.clear();AndroidConnectionProfileStore.saved=null;AndroidHomeStateStore.current=new AndroidHomeStateStore.Snapshot();AndroidRuntimeRegistry.instance=new AndroidRuntimeRegistry();AndroidVpnMutationGuard.busy=false;AndroidNodeStore.nodes.clear();AndroidStandardExitStore.saved.clear();android.net.VpnService.needsPermission=false;AndroidSpeedLab.starts=AndroidSpeedLab.cancels=0;AndroidSpeedLab.pending=null;AndroidNativeHopMeasurement.starts=AndroidNativeHopMeasurement.cancels=0;AndroidNativeHopMeasurement.hold=false;AndroidNativeHopMeasurement.pending=null;LayeredVpnService.quiesce=null;LayeredVpnService.automatic=0;
   original=node(directory,"original");first=node(directory,"entry");last=node(directory,"exit");external.protocol=type.startsWith("external")?raw:"tor-bridge";if(type.equals("external-openvpn"))external.responseMap="captured-private-two-host-map";AndroidStandardExitStore.saved.put(external.id,AndroidStandardExitStore.copy(external));
   connection=new AndroidUnifiedConnectionController(activity,nodes);controller=new AndroidSpeedLabController(activity,connection);
   if(type.equals("router")){AndroidHomeStateStore.begin("SMART AUTO",raw,"",original.id,"","");AndroidRuntimeRegistry.instance.orchestrator.source=Files.readString(original.file.toPath());AndroidHomeStateStore.proved();}
   if(type.equals("multihop")){AndroidHomeStateStore.begin("multihop",raw,original.id,last.id,"reality-xhttp","");AndroidRuntimeRegistry.instance.multihop.execution="auto";AndroidRuntimeRegistry.instance.multihop.selected="server";AndroidHomeStateStore.proved();}
   if(type.startsWith("external")){AndroidHomeStateStore.begin("external",raw,original.id,"","max-quic-awg",external.id);AndroidHomeStateStore.proved();}
   originalSession=AndroidHomeStateStore.current.sessionId;
   request.scope="temporary";request.topology=topology;request.node=first;request.entry=first;request.exit=last;request.mode="all";request.entryMode="wg-pq";request.exitMode="shadowsocks";request.execution="external".equals(topology)?"local":"server";request.standardExit=external;request.externalDirect=false;
  }
  AndroidNodeStore.Node node(Path root,String id)throws Exception{Path folder=Files.createTempDirectory(root,id);Path file=folder.resolve(id+".json");Files.writeString(file,"{\"private\":\""+id+"\",\"dns\":\"home-adguard\",\"mtu\":\"auto\"}");AndroidNodeStore.Node n=new AndroidNodeStore.Node(id,file.toFile());AndroidNodeStore.nodes.add(n);return n;}
  void start(){controller.run(request,result);}void quiesce(){LayeredVpnService.quiesce.accept(null);}void measured()throws Exception{waitFor(()->AndroidSpeedLab.pending!=null,"measurement never started");AndroidSpeedLab.drained(false);}
  void complete()throws Exception{waitFor(()->result.count>0,"transaction never completed");check(result.count==1&&!controller.isRunning()&&!AndroidMTUMeasurementGate.held(),"completion did not release its drained lease exactly once");}
  AndroidStandardExitStore.Entry ordinary(String protocol,String id){AndroidStandardExitStore.Entry value=new AndroidStandardExitStore.Entry();value.id=id;value.name="Ordinary "+protocol;value.protocol=protocol;value.secret="ordinary-private-"+id;value.policy="ordinary-policy-"+id;AndroidStandardExitStore.saved.put(id,AndroidStandardExitStore.copy(value));return value;}
  void ordinaryOriginal(String protocol){originalOrdinary=ordinary(protocol,original.id);AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.instance.standardExit;runtime.ordinaryEntry=AndroidStandardExitStore.copy(originalOrdinary);runtime.execution=runtime.selected="local";AndroidHomeStateStore.begin("external",external.protocol,original.id,"",AndroidExternalPolicy.protocol(protocol),external.id);AndroidHomeStateStore.proved();originalSession=AndroidHomeStateStore.current.sessionId;}
  void ordinaryTemporary(String protocol){request.ordinaryEntry=ordinary(protocol,first.id);request.entry=null;request.entryMode=AndroidExternalPolicy.protocol(protocol);request.execution="local";request.externalDirect=false;request.topology="external";}
  void originalRestored()throws Exception{AndroidHomeStateStore.Snapshot s=AndroidHomeStateStore.current;check(s.connected&&s.pathProof.equals("passed")&&!s.sessionId.equals(originalSession),"original lacks fresh proof/session");check(s.runtimeMode.equals(raw),"original raw transport changed");if(type.equals("router"))check(s.logicalMode.equals("SMART AUTO")&&s.activeNodeId.equals(original.id)&&RuntimeBoundary.restoredRaw.equals(raw),"SMART AUTO was reselected or node changed");if(type.equals("multihop"))check(s.activeEntryId.equals(original.id)&&s.activeEntryMode.equals("reality-xhttp")&&s.activeExitId.equals(last.id)&&AndroidRuntimeRegistry.instance.multihop.execution.equals("auto")&&AndroidRuntimeRegistry.instance.multihop.selected.equals(originalWinner)&&RuntimeBoundary.restoredExecution.equals(originalWinner),"original multihop execution/entry changed");if(type.startsWith("external")){if(originalOrdinary==null)check(s.activeExternalId.equals(external.id)&&s.activeEntryMode.equals("max-quic-awg")&&s.activeEntryId.equals(original.id),"external original entry or profile changed");else{AndroidStandardExitStore.Entry actual=AndroidRuntimeRegistry.instance.standardExit.capturedOrdinaryEntry(s);check(actual!=null&&AndroidStandardExitStore.snapshot(actual).equals(AndroidStandardExitStore.snapshot(originalOrdinary))&&s.activeEntryMode.equals(AndroidExternalPolicy.protocol(originalOrdinary.protocol))&&s.activeExternalId.equals(external.id),"ordinary original source/kind/path changed");}}check(nodes.activeId().equals("original"),"temporary path rewrote selected saved node");}
 }
 static void matrix(Path root)throws Exception{
  for(String original:new String[]{"router","multihop","external-openvpn","external-amneziawg","external-tor","external-tor-bridge"})for(String topology:new String[]{"router","multihop","external","system-direct"}){
   Fixture f=new Fixture(root,original,topology);String before=Files.readString(f.original.file.toPath());f.start();check(AndroidHomeStateStore.current.connected&&AndroidSpeedLab.starts==0,"original was stopped before MTU drain");f.quiesce();f.measured();f.complete();check(f.result.error==null&&f.result.result!=null,"valid temporary test failed: "+original+"/"+topology+" "+f.result.error);f.originalRestored();check(Files.readString(f.original.file.toPath()).equals(before),"restoration changed stored policy");check(RuntimeBoundary.stops==(topology.equals("system-direct")?1:2),"wrong graph cleanup count");check(AndroidNativeHopMeasurement.starts==((topology.equals("external")||topology.equals("multihop"))?1:0),"multihop or external bypassed owned native measurement");
  }
 }
 static void exactMultihopWinner(Path root)throws Exception{
  for(String selected:new String[]{"local","server"})for(String topology:new String[]{"router","multihop","external","system-direct"}){
   Fixture f=new Fixture(root,"multihop",topology);f.originalWinner=selected;AndroidRuntimeRegistry.instance.multihop.selected=selected;f.start();f.quiesce();f.measured();f.complete();
   check(f.result.error==null,"exact prior winner restore failed");f.originalRestored();check(RuntimeBoundary.proofs>=(topology.equals("system-direct")?2:3),"winner restore reused an old proof");
  }
 }
 static void exactExternalWinner(Path root)throws Exception{
  for(String kind:new String[]{"external-shadowsocks","external-openvpn","external-tor","external-tor-bridge"})for(String selected:new String[]{"local","server"})for(String topology:new String[]{"router","multihop","external","system-direct"}){
   Fixture f=new Fixture(root,kind,topology);AndroidStandardExitRuntime owner=AndroidRuntimeRegistry.instance.standardExit;owner.execution="auto";owner.selected=selected;
   f.start();f.quiesce();f.measured();f.complete();check(f.result.error==null,"external winner restoration failed");f.originalRestored();
   check(owner.execution.equals("auto")&&owner.selected.equals(selected)&&RuntimeBoundary.restoredExecution.equals(selected)&&owner.restoredResponseMap.equals(f.external.responseMap),"external Compare was rerun instead of restoring its proved winner");
  }
 }
 static void exactTorExecution(Path root)throws Exception{
  for(String kind:new String[]{"external-tor","external-tor-bridge"})for(String selected:new String[]{"local","server"})for(String topology:new String[]{"router","multihop","external","system-direct"}){
   Fixture f=new Fixture(root,kind,topology);AndroidStandardExitRuntime owner=AndroidRuntimeRegistry.instance.standardExit;owner.execution=selected;owner.selected=selected;
   if(topology.equals("external"))f.request.execution=selected;
   f.start();f.quiesce();f.measured();f.complete();check(f.result.error==null,"captured Tor execution restoration failed");f.originalRestored();
   check(owner.execution.equals(selected)&&owner.selected.equals(selected),"Tor Server was replaced by Local during restore");
   if(selected.equals("server"))check(RuntimeBoundary.restoredExecution.equals("server"),"Tor Server did not use captured restoration");
  }
  Fixture replaced=new Fixture(root,"external-tor-bridge","router");AndroidStandardExitRuntime owner=AndroidRuntimeRegistry.instance.standardExit;owner.execution="server";owner.selected="server";
  RuntimeBoundary.afterRestoredProof=()->owner.selected="local";replaced.start();replaced.quiesce();replaced.measured();replaced.complete();
  check(replaced.result.error!=null&&replaced.result.result==null,"Tor retained a score after restoration switched execution");
 }
 static void ordinaryRestoration(Path root)throws Exception{
  for(String protocol:List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn"))for(String topology:List.of("router","multihop","external","ordinary","system-direct")){
   Fixture f=new Fixture(root,"external-tor-bridge",topology.equals("ordinary")?"external":topology);f.ordinaryOriginal(protocol);if(topology.equals("ordinary"))f.ordinaryTemporary(protocol);
   String first=Files.readString(f.original.file.toPath()),source=AndroidStandardExitStore.snapshot(f.originalOrdinary);f.start();check(AndroidHomeStateStore.current.sessionId.equals(f.originalSession)&&AndroidSpeedLab.starts==0,"ordinary original stopped before MTU drain");f.quiesce();f.measured();f.complete();
   check(f.result.error==null&&f.result.result!=null,"ordinary restoration failed: "+protocol+"/"+topology+" "+f.result.error);f.originalRestored();check(source.equals(AndroidStandardExitStore.snapshot(AndroidStandardExitStore.saved.get(f.original.id)))&&first.equals(Files.readString(f.original.file.toPath())),"ordinary restoration rewrote credentials or colliding private Router source");check(AndroidRuntimeRegistry.instance.standardExit.execution.equals("local")&&AndroidRuntimeRegistry.instance.standardExit.selected.equals("local"),"ordinary restore selected Server/Compare");
  }
  Fixture collision=new Fixture(root,"external-tor-bridge","router");collision.ordinaryOriginal("socks5");collision.start();Files.writeString(collision.original.file.toPath(),"unrelated Router credential changed");collision.quiesce();collision.measured();collision.complete();check(collision.result.error==null,"ordinary restoration captured an unrelated Router file with the same ID");collision.originalRestored();
 }
 static void ordinaryRestoreChanges(Path root)throws Exception{
  for(String stage:List.of("cleanup","permission"))for(String source:List.of("entry-key","entry-policy","entry-removed","exit-key","exit-policy","exit-removed")){
   Fixture f=new Fixture(root,"external-tor-bridge","router");f.ordinaryOriginal("https");f.start();f.quiesce();waitFor(()->AndroidSpeedLab.pending!=null,"ordinary original test did not measure");
   if(stage.equals("cleanup")){RuntimeBoundary.holdStop=true;RuntimeBoundary.stopEntered=false;}else android.net.VpnService.needsPermission=true;AndroidSpeedLab.drained(false);
   if(stage.equals("cleanup"))waitFor(()->RuntimeBoundary.stopEntered,"temporary cleanup was not captured");else waitFor(()->f.activity.permissionRequest!=0,"ordinary restoration never requested renewed permission");
   String id=source.startsWith("entry")?f.originalOrdinary.id:f.external.id;if(source.endsWith("removed"))AndroidStandardExitStore.saved.remove(id);else if(source.endsWith("policy"))AndroidStandardExitStore.saved.get(id).policy="changed during original restore";else AndroidStandardExitStore.saved.get(id).secret="replacement original private source";
   if(stage.equals("cleanup")){RuntimeBoundary.holdStop=false;RuntimeBoundary.stopRelease.countDown();}else{android.net.VpnService.needsPermission=false;f.connection.onActivityResult(f.activity.permissionRequest,Activity.RESULT_OK);}f.complete();
   check(f.result.error!=null&&f.result.result==null&&RuntimeBoundary.starts==1&&!AndroidHomeStateStore.current.connected,"changed ordinary original was restored or kept a successful result: "+stage+"/"+source);
  }
  for(String change:List.of("key","policy","kind","execution")){
   Fixture f=new Fixture(root,"external-tor-bridge","router");f.ordinaryOriginal("socks5");AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.instance.standardExit;
   RuntimeBoundary.afterOrdinaryProof=()->{if(change.equals("kind"))runtime.ordinaryEntry=null;else if(change.equals("key"))runtime.ordinaryEntry.secret="substituted proved entry";else if(change.equals("policy"))runtime.ordinaryEntry.policy="substituted proved DNS";else runtime.selected="server";};
   f.start();f.quiesce();f.measured();f.complete();check(f.result.error!=null&&f.result.result==null,"substituted ordinary restored runtime kept a score: "+change);
  }
  Fixture temporary=new Fixture(root,"router","external");temporary.ordinaryTemporary("socks5");RuntimeBoundary.afterOrdinaryProof=()->AndroidRuntimeRegistry.instance.standardExit.ordinaryEntry.secret="substituted temporary native source";temporary.start();temporary.quiesce();temporary.complete();check(temporary.result.error!=null&&temporary.result.result==null&&AndroidSpeedLab.starts==0,"substituted temporary ordinary proof reached the meter");temporary.originalRestored();
 }
 static void cancellation(Path root)throws Exception{
  for(String stage:new String[]{"quiesce","suspend","permission","connect","http","hop","cleanup","restore"}){
   Fixture f=new Fixture(root,"router",stage.equals("hop")?"multihop":"external");
   if(stage.equals("suspend"))RuntimeBoundary.holdStop=true;
   if(stage.equals("permission"))android.net.VpnService.needsPermission=true;
   if(stage.equals("connect"))RuntimeBoundary.holdConnect=true;
   if(stage.equals("hop"))AndroidNativeHopMeasurement.hold=true;
   if(stage.equals("restore"))RuntimeBoundary.holdRestore=true;
   f.start();if(stage.equals("quiesce")){f.controller.cancel();check(f.result.count==0&&AndroidMTUMeasurementGate.held(),"cancel abandoned MTU quiescence");f.quiesce();f.complete();check(AndroidHomeStateStore.current.sessionId.equals(f.originalSession),"quiescence cancel replaced untouched original");continue;}
   f.quiesce();
   if(stage.equals("suspend")){waitFor(()->RuntimeBoundary.stopEntered,"original stop missing");f.controller.cancel();check(f.result.count==0&&AndroidMTUMeasurementGate.held(),"cancel released blocked stop");RuntimeBoundary.holdStop=false;RuntimeBoundary.stopRelease.countDown();}
   else if(stage.equals("permission")){waitFor(()->f.activity.permissionRequest!=0,"permission not requested");f.controller.cancel();android.net.VpnService.needsPermission=false;}
   else if(stage.equals("connect")){waitFor(()->RuntimeBoundary.pendingConnect!=null,"connection not captured");f.controller.cancel();}
   else{
    waitFor(()->AndroidSpeedLab.pending!=null,"HTTP did not start");
    if(stage.equals("http")){f.controller.cancel();check(AndroidSpeedLab.cancels==1&&f.result.count==0&&AndroidMTUMeasurementGate.held()&&RuntimeBoundary.stops==1,"cancel did not retain HTTP and temporary path until drain");AndroidSpeedLab.drained(true);}
    else{if(stage.equals("cleanup")){RuntimeBoundary.holdStop=true;RuntimeBoundary.stopEntered=false;}AndroidSpeedLab.drained(false);
     if(stage.equals("hop")){waitFor(()->AndroidNativeHopMeasurement.pending!=null,"native hop did not start");f.controller.cancel();check(AndroidNativeHopMeasurement.cancels==1&&RuntimeBoundary.stops==1&&f.result.count==0&&AndroidMTUMeasurementGate.held(),"native-hop cancel skipped actual drain");AndroidNativeHopMeasurement.drained(true);}
     if(stage.equals("cleanup")){waitFor(()->RuntimeBoundary.stopEntered,"test cleanup missing");f.controller.cancel();check(f.result.count==0&&AndroidMTUMeasurementGate.held(),"cancel abandoned temporary cleanup");RuntimeBoundary.holdStop=false;RuntimeBoundary.stopRelease.countDown();}
     if(stage.equals("restore")){waitFor(()->RuntimeBoundary.pendingRestore!=null,"restoration never started");f.controller.cancel();check(f.result.count==0&&AndroidMTUMeasurementGate.held(),"cancel abandoned original proof");RuntimeBoundary.pendingRestore.run();}
    }
   }
   f.complete();check(f.result.error!=null&&f.result.result==null,"cancel kept a successful score");if(!stage.equals("permission"))f.originalRestored();
  }
 }
 static void stale(Path root)throws Exception{
  for(String mutation:new String[]{"node","multihop-node","external-profile","external-map","newer-connected","manual-off","during-stop","restored-proof"}){
   Fixture f=new Fixture(root,(mutation.equals("node")||mutation.equals("external-profile")||mutation.equals("external-map"))?"external-openvpn":mutation.equals("multihop-node")?"multihop":"router","external");f.start();f.quiesce();waitFor(()->AndroidSpeedLab.pending!=null,"stale fixture not measured");
   if(mutation.equals("node")||mutation.equals("multihop-node"))Files.writeString(f.original.file.toPath(),"changed original DNS");
   if(mutation.equals("external-profile")){AndroidStandardExitStore.Entry e=AndroidStandardExitStore.copy(f.external);e.secret="replacement key";AndroidStandardExitStore.saved.put(e.id,e);}
   if(mutation.equals("external-map")){AndroidStandardExitStore.Entry e=AndroidStandardExitStore.copy(f.external);e.responseMap="replacement-owner-map";AndroidStandardExitStore.saved.put(e.id,e);}
   if(mutation.equals("newer-connected")){AndroidHomeStateStore.begin("new-user","wg","","new-node","","");AndroidHomeStateStore.proved();}
   if(mutation.equals("manual-off"))AndroidHomeStateStore.off();
   if(mutation.equals("during-stop")){RuntimeBoundary.holdStop=true;RuntimeBoundary.stopEntered=false;}
   if(mutation.equals("restored-proof"))RuntimeBoundary.afterRestoredProof=()->{AndroidHomeStateStore.begin("new-user","wg","","new-node","","");AndroidHomeStateStore.proved();};
   AndroidSpeedLab.drained(false);
   if(mutation.equals("during-stop")){waitFor(()->RuntimeBoundary.stopEntered,"cleanup not started");AndroidHomeStateStore.advancePathGeneration(f.activity);RuntimeBoundary.holdStop=false;RuntimeBoundary.stopRelease.countDown();}
   f.complete();check(f.result.error!=null&&f.result.result==null,"stale transaction kept result");check(RuntimeBoundary.restores==(mutation.equals("restored-proof")?1:0),"stale transaction restored old runtime");if(mutation.equals("newer-connected")||mutation.equals("restored-proof"))check(AndroidHomeStateStore.current.logicalMode.equals("new-user")&&AndroidHomeStateStore.current.connected,"cleanup disconnected replacement");
  }
 }


 static void multihopPins(Path root)throws Exception{
  for(String phase:new String[]{"before-stop","after-restore"}){
   Fixture f=new Fixture(root,"multihop","external");f.start();
   if(phase.equals("before-stop"))AndroidRuntimeRegistry.instance.multihop.serverPins="replacement-public-pins";
   f.quiesce();
   if(phase.equals("after-restore")){
    waitFor(()->AndroidSpeedLab.pending!=null,"pin fixture did not measure temporary path");
    RuntimeBoundary.afterRestoredProof=()->AndroidRuntimeRegistry.instance.multihop.serverPins="replacement-public-pins";
    AndroidSpeedLab.drained(false);
   }
   f.complete();check(f.result.error!=null&&f.result.result==null,"changed Server identities retained a temporary result: "+phase);
   if(phase.equals("before-stop"))check(RuntimeBoundary.stops==0&&RuntimeBoundary.restores==0&&AndroidHomeStateStore.current.sessionId.equals(f.originalSession),"changed original Server owner was stopped or restored");
   else check(RuntimeBoundary.restores==1&&RuntimeBoundary.restoredPins.equals("original-public-pins"),"restoration did not forward original public identities");
  }
 }

 static void permissionCapture(Path root)throws Exception{
  for(String topology:new String[]{"router","multihop","external"}){
   Fixture f=new Fixture(root,"router",topology);android.net.VpnService.needsPermission=true;f.start();f.quiesce();waitFor(()->f.activity.permissionRequest!=0,"permission boundary never reached");
   Files.writeString(f.first.file.toPath(),"changed test credentials during permission");android.net.VpnService.needsPermission=false;f.connection.onActivityResult(f.activity.permissionRequest,Activity.RESULT_OK);f.complete();
   check(f.result.error!=null&&RuntimeBoundary.starts==0&&AndroidSpeedLab.starts==0,"permission completion used changed test profile: "+topology);f.originalRestored();
  }
 }
 static void permissionSelection(Path root)throws Exception{
  for(String topology:List.of("router","multihop","external","ordinary"))for(boolean changed:new boolean[]{false,true}){
   Fixture f=new Fixture(root,"router",topology.equals("ordinary")?"external":topology);if(topology.equals("ordinary"))f.ordinaryTemporary("socks5");
   android.content.Context.speedPreferences.put("selected_kind","router-vpn");android.content.Context.speedPreferences.put("selected_id",f.original.id);android.content.Context.speedPreferences.put("mode","custom:Saved original");android.content.Context.speedPreferences.put("custom_presets","SAVED_LAYERS_DIFFERENT_FROM_TEST");
   Map<String,String> saved=new HashMap<>(android.content.Context.speedPreferences);android.net.VpnService.needsPermission=true;f.start();f.quiesce();waitFor(()->f.activity.permissionRequest!=0,"temporary permission boundary never reached");
   check(f.connection.isPermissionPending()&&f.connection.isActiveOrTransitioning()&&RuntimeBoundary.starts==0,"temporary permission owner was invisible to Product busy/cancel");
   if(changed)android.content.Context.speedPreferences.put("mode","user replacement choice");else android.content.Context.speedPreferences.put("map_theme","dark");
   android.net.VpnService.needsPermission=false;f.connection.onActivityResult(f.activity.permissionRequest,Activity.RESULT_OK);
   if(!changed)f.measured();f.complete();f.originalRestored();
   if(changed)check(f.result.error!=null&&f.result.result==null&&RuntimeBoundary.starts==0&&AndroidSpeedLab.starts==0&&android.content.Context.speedPreferences.get("mode").equals("user replacement choice"),"changed saved choice launched temporary test or overwrote user choice");
   else{check(f.result.error==null&&f.result.result!=null&&RuntimeBoundary.starts==1,"temporary path was required to equal saved selection");android.content.Context.speedPreferences.remove("map_theme");check(saved.equals(android.content.Context.speedPreferences),"permission-approved temporary path rewrote saved selection");}
  }
 }
 static void uiCancellation(Path root)throws Exception{
  for(boolean dismiss:new boolean[]{false,true}){
   Fixture f=new Fixture(root,"router","external");AndroidSpeedLabDialog ui=new AndroidSpeedLabDialog(f.activity,f.nodes,f.connection,f.controller);ui.show();
   java.lang.reflect.Field runField=AndroidSpeedLabDialog.class.getDeclaredField("run"),cancelField=AndroidSpeedLabDialog.class.getDeclaredField("cancel");runField.setAccessible(true);cancelField.setAccessible(true);
   android.widget.Button run=(android.widget.Button)runField.get(ui),cancel=(android.widget.Button)cancelField.get(ui);
   check(!cancel.isEnabled()&&run.performClick(),"Speed Lab initial buttons unavailable");check(cancel.isEnabled()&&!run.isEnabled()&&AndroidMTUMeasurementGate.held(),"run did not expose owned Cancel");
   LayeredVpnService.quiesce.accept(null);waitFor(()->AndroidSpeedLab.pending!=null,"UI measurement never started");
   if(dismiss)android.app.AlertDialog.last.dismiss();else check(cancel.performClick(),"Cancel button callback missing");
   check(AndroidSpeedLab.cancels==1&&f.controller.isRunning()&&AndroidMTUMeasurementGate.held(),"UI cancel or dismissal abandoned actual HTTP drain");
   AndroidSpeedLab.drained(true);waitFor(()->!f.controller.isRunning(),"UI cancellation never finalized");check(!AndroidMTUMeasurementGate.held()&&run.isEnabled()&&!cancel.isEnabled(),"UI completion failed to restore action buttons");check(AndroidHomeStateStore.current.sessionId.equals(f.originalSession),"current-path cancel replaced the existing connection");
  }
 }

 static android.widget.Spinner spinner(AndroidSpeedLabDialog dialog,String name)throws Exception{java.lang.reflect.Field field=AndroidSpeedLabDialog.class.getDeclaredField(name);field.setAccessible(true);return (android.widget.Spinner)field.get(dialog);}
 static android.widget.Button runButton(AndroidSpeedLabDialog dialog)throws Exception{java.lang.reflect.Field field=AndroidSpeedLabDialog.class.getDeclaredField("run");field.setAccessible(true);return (android.widget.Button)field.get(dialog);}
 static void externalUI(Path root)throws Exception{
  for(String protocol:new String[]{"shadowsocks","tor","tor-bridge"})for(String requested:new String[]{"local","server","auto"}){
   Fixture f=new Fixture(root,"router","external");f.external.protocol=protocol;AndroidStandardExitStore.saved.put(f.external.id,AndroidStandardExitStore.copy(f.external));
   JSONObject profiles=new JSONObject();JSONArray modes=new JSONArray();for(String mode:new String[]{"wg","max-quic-awg","reality-xhttp"}){profiles.put(mode,new JSONObject());modes.put(new JSONObject().put("id",mode).put("name",mode));}Files.writeString(f.first.file.toPath(),new JSONObject().put("profiles",profiles).put("modes",modes).toString());
   AndroidConnectionProfileStore.saved=new AndroidConnectionProfileStore.ExternalSelection(f.first,AndroidStandardExitStore.copy(f.external),"reality-xhttp","auto");
   android.content.Context.speedPreferences.put("selected_kind","external");android.content.Context.speedPreferences.put("selected_id",f.external.id);
   Map<String,String> saved=new HashMap<>(android.content.Context.speedPreferences);
   AndroidSpeedLabDialog ui=new AndroidSpeedLabDialog(f.activity,f.nodes,f.connection,f.controller);ui.show();
   check(spinner(ui,"topology").getSelectedItemPosition()==3&&spinner(ui,"execution").getSelectedItemPosition()==2&&spinner(ui,"entry").getSelectedItemPosition()==1&&spinner(ui,"entryMode").getSelectedItemPosition()==2,"Speed Lab replaced saved external entry/mode/Compare defaults");
   spinner(ui,"scope").setSelection(1);check(spinner(ui,"execution").getVisibility()==android.view.View.VISIBLE,"External Speed Lab hides execution choices");
   spinner(ui,"execution").setSelection(java.util.Arrays.asList("local","server","auto").indexOf(requested));check(runButton(ui).performClick(),"Actual external Run callback missing");
   spinner(ui,"execution").setSelection(0);LayeredVpnService.quiesce.accept(null);waitFor(()->AndroidSpeedLab.pending!=null,"Temporary external UI did not reach measurement");
   AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.instance.standardExit;
   check(runtime.execution.equals(requested)&&runtime.selected.equals(requested.equals("auto")?"server":requested)&&AndroidHomeStateStore.current.activeEntryMode.equals("reality-xhttp"),"Actual Speed Lab Run substituted Local or a different entry mode");
   AndroidSpeedLab.drained(false);waitFor(()->!f.controller.isRunning(),"UI external cleanup never finished");f.originalRestored();check(saved.equals(android.content.Context.speedPreferences),"Temporary external choices rewrote saved path");android.app.AlertDialog.last.dismiss();
  }
  Fixture invalid=new Fixture(root,"router","external");invalid.request.execution="auto";invalid.request.externalDirect=true;invalid.start();check(invalid.result.error!=null&&LayeredVpnService.quiesce==null&&RuntimeBoundary.stops==0&&AndroidHomeStateStore.current.sessionId.equals(invalid.originalSession),"Direct Tor comparison without a private entry stopped the original path");
 }
 @SuppressWarnings("unchecked") static List<AndroidStandardExitStore.Entry> ordinaryChoices(AndroidSpeedLabDialog ui)throws Exception{var field=AndroidSpeedLabDialog.class.getDeclaredField("ordinaryEntryValues");field.setAccessible(true);return (List<AndroidStandardExitStore.Entry>)field.get(ui);}
 static void ordinaryUI(Path root)throws Exception{
  Fixture f=new Fixture(root,"router","external");List<String> protocols=List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn");AndroidStandardExitStore.Entry saved=null;
  for(String protocol:protocols){var value=f.ordinary(protocol,protocol.equals("socks5")?f.first.id:"ordinary-"+protocol);if(protocol.equals("socks5"))saved=value;}
  JSONObject profiles=new JSONObject();JSONArray modes=new JSONArray();for(String mode:List.of("wg","max-quic-awg")){profiles.put(mode,new JSONObject());modes.put(new JSONObject().put("id",mode).put("name",mode));}Files.writeString(f.first.file.toPath(),new JSONObject().put("profiles",profiles).put("modes",modes).toString());
  AndroidConnectionProfileStore.saved=new AndroidConnectionProfileStore.ExternalSelection(null,AndroidStandardExitStore.copy(saved),AndroidStandardExitStore.copy(f.external),"socks5","local");android.content.Context.speedPreferences.put("selected_kind","external");android.content.Context.speedPreferences.put("selected_id",f.external.id);Map<String,String> preferences=new HashMap<>(android.content.Context.speedPreferences);
  AndroidSpeedLabDialog ui=new AndroidSpeedLabDialog(f.activity,f.nodes,f.connection,f.controller);ui.show();spinner(ui,"scope").setSelection(1);List<AndroidStandardExitStore.Entry> choices=ordinaryChoices(ui);
  check(choices.size()==8&&spinner(ui,"entry").getAdapter().getCount()==11&&spinner(ui,"entry").getSelectedItemPosition()>=3&&spinner(ui,"entryMode").getAdapter().getCount()==1&&spinner(ui,"execution").getAdapter().getCount()==1,"actual Speed Lab picker lost ordinary protocols or collapsed the typed colliding ID");
  spinner(ui,"entry").setSelection(1);check(spinner(ui,"entryMode").getAdapter().getCount()==2&&spinner(ui,"execution").getAdapter().getCount()==3,"same-ID private Router choice inherited ordinary modes/execution");
  for(String protocol:protocols){int index=-1;for(int i=0;i<choices.size();i++)if(choices.get(i).protocol.equals(protocol))index=i;check(index>=0,"ordinary transport absent from picker: "+protocol);var expected=choices.get(index);spinner(ui,"entry").setSelection(3+index);
   check(spinner(ui,"entryMode").getAdapter().getCount()==1&&spinner(ui,"entryMode").getSelectedItemPosition()==0&&spinner(ui,"execution").getAdapter().getCount()==1&&spinner(ui,"execution").getSelectedItemPosition()==0,"ordinary picker retained Router modes or Server/Compare: "+protocol);check(runButton(ui).performClick(),"ordinary Speed Lab Run is not wired");
   spinner(ui,"entry").setSelection(1);LayeredVpnService.quiesce.accept(null);waitFor(()->AndroidSpeedLab.pending!=null,"ordinary picker did not start measurement");var actual=AndroidRuntimeRegistry.instance.standardExit.capturedOrdinaryEntry(AndroidHomeStateStore.current);
   check(actual!=null&&actual.id.equals(expected.id)&&actual.protocol.equals(protocol)&&actual.secret.equals(expected.secret)&&AndroidHomeStateStore.current.activeEntryMode.equals(AndroidExternalPolicy.protocol(protocol)),"ordinary UI choice changed after capture or used colliding private source");
   AndroidSpeedLab.drained(false);waitFor(()->!f.controller.isRunning(),"ordinary UI cleanup did not finish");f.originalRestored();check(preferences.equals(android.content.Context.speedPreferences),"ordinary temporary picker changed saved selection");
  }
  android.app.AlertDialog.last.dismiss();
 }
 public static void main(String[]args)throws Exception{Path root=Path.of(args[0]);matrix(root);externalUI(root);ordinaryUI(root);ordinaryRestoration(root);ordinaryRestoreChanges(root);exactMultihopWinner(root);exactExternalWinner(root);exactTorExecution(root);cancellation(root);stale(root);multihopPins(root);permissionCapture(root);permissionSelection(root);uiCancellation(root);System.out.println("Shipping Android Speed Lab restoration: "+checks+" checks; captured winners,40 ordinary graph restores,8-protocol typed picker,cleanup/permission source changes,saved/test selection separation,8 cancellation phases and newer-user ownership");}
}
'''

def replace_class(text, name, replacement):
    start=text.index('final class '+name+' {')
    end=text.find('\nfinal class ',start+1)
    if end<0:end=len(text)
    return text[:start]+replacement+text[end:]

def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    ui=dict(P.T.UI)
    ui['android/content/Context.java']=ui['android/content/Context.java'].replace('public SharedPreferences getSharedPreferences(String name,int mode){return (key,fallback)->fallback;}', 'public static final java.util.Map<String,String> speedPreferences=new java.util.HashMap<>();public SharedPreferences getSharedPreferences(String name,int mode){return new SharedPreferences(){public String getString(String key,String fallback){return speedPreferences.getOrDefault(key,fallback);}public java.util.Map<String,?> getAll(){return new java.util.LinkedHashMap<>(speedPreferences);}};}')
    ui['android/content/SharedPreferences.java']='package android.content;public interface SharedPreferences{String getString(String key,String fallback);java.util.Map<String,?> getAll();}'
    # AdapterView.INVALID_POSITION represents an unavailable saved selection;
    # it must stay unselected instead of implicitly choosing another entry mode.
    ui['android/widget/Spinner.java']=ui['android/widget/Spinner.java'].replace('if(value<0||adapter==null||value>=adapter.getCount())','if(value < -1||adapter==null||value>=adapter.getCount())').replace('if(listener!=null)listener.onItemSelected(this,null,position,position);','if(listener!=null){if(position<0)listener.onNothingSelected(this);else listener.onItemSelected(this,null,position,position);}')
    ui['android/os/Bundle.java']=ui['android/os/Bundle.java'][:-1]+'public void putStringArrayList(String k,java.util.ArrayList<String> v){values.put(k,v);}public java.util.ArrayList<String> getStringArrayList(String k){return (java.util.ArrayList<String>)values.get(k);}public boolean containsKey(String k){return values.containsKey(k);}}'

    ui['android/graphics/Color.java']='package android.graphics;public final class Color{public static final int WHITE=-1;public static int rgb(int r,int g,int b){return r*65536+g*256+b;}}'
    ui['android/view/Gravity.java']='package android.view;public final class Gravity{public static final int CENTER_VERTICAL=16;}'
    ui['android/view/View.java']=ui['android/view/View.java'][:-1]+'public static final int VISIBLE=0,GONE=8;private Object tag;public void setTag(Object v){tag=v;}public Object getTag(){return tag;}private int visibility;public void setVisibility(int v){visibility=v;}public int getVisibility(){return visibility;}public void setBackgroundColor(int c){} }'
    ui['android/widget/TextView.java']=ui['android/widget/TextView.java'][:-1]+'public void setTextIsSelectable(boolean v){}public void setHintTextColor(int c){} }'
    ui['android/widget/LinearLayout.java']=ui['android/widget/LinearLayout.java'].replace('public static final int VERTICAL=1;','public static final int VERTICAL=1,HORIZONTAL=0;public void setGravity(int g){}').replace('public LayoutParams(int width,int height){}','public LayoutParams(int width,int height){}public LayoutParams(int width,int height,float weight){}')
    ui['android/widget/CheckBox.java']=ui['android/widget/CheckBox.java'][:-1]+'public interface OnCheckedChangeListener{void onChanged(CheckBox c,boolean v);}public void setOnCheckedChangeListener(OnCheckedChangeListener l){} }'
    ui['android/widget/ArrayAdapter.java']=ui['android/widget/ArrayAdapter.java'].replace('public void setDropDownViewResource', 'public ArrayAdapter(android.content.Context c,int layout,java.util.List<T> source){values=(T[])source.toArray();}public void setDropDownViewResource')
    ui['android/widget/SeekBar.java']='package android.widget;public final class SeekBar extends android.view.View{int value;OnSeekBarChangeListener listener;public SeekBar(android.content.Context c){super(c);}public void setMax(int v){}public void setProgress(int v){value=v;if(listener!=null)listener.onProgressChanged(this,v,false);}public int getProgress(){return value;}public void setOnSeekBarChangeListener(OnSeekBarChangeListener l){listener=l;}public interface OnSeekBarChangeListener{void onStartTrackingTouch(SeekBar b);void onStopTrackingTouch(SeekBar b);void onProgressChanged(SeekBar b,int p,boolean u);}}'
    ui['android/app/AlertDialog.java']=ui['android/app/AlertDialog.java'].replace('public void dismiss(){','public boolean isShowing(){return showing;}public void dismiss(){')
    boundaries=P.BOUNDARIES.replace('String id="saved-exit",protocol','String name="Saved exit",id="saved-exit",protocol')
    for name in ('AndroidHomeStateStore','AndroidModeOrchestrator','AndroidMultihopRuntime','AndroidStandardExitRuntime','AndroidConnectionProfileStore'):
        boundaries=replace_class(boundaries,name,'')
    boundaries=boundaries.replace('return busy;','return busy||RuntimeBoundary.stopping||AndroidHomeStateStore.current.connected||AndroidHomeStateStore.current.phase.equals("connecting");')
    native=(JAVA/'NativeSingBoxController.java').read_text()
    predicates=[]
    for name in ('nativeMultihopEntry','nativeWireGuardFamily','nativeNaiveFamily','nativePQFamily'):
        predicates.append(re.findall(r'(?ms)^    static boolean '+name+r'\(String mode\) \{\n.*?^    \}',native)[0])
    composite=re.findall(r'(?ms)^    static boolean isMode\(String mode\) \{\n.*?^    \}',(JAVA/'AndroidNativeCompositeProfile.java').read_text())[0]
    speed=(JAVA/'AndroidSpeedLab.java').read_text();duration=speed[speed.index('    static final class DurationPolicy'):speed.index('    static final class Latency')]
    boundaries=boundaries.replace(' // PRODUCTION_TRANSPORT_PREDICATES','\n'.join(predicates)).replace(' // PRODUCTION_COMPOSITE_PREDICATE',composite)+OWNERS+METERS.replace(' // PRODUCTION_DURATION',duration)
    with tempfile.TemporaryDirectory(prefix='routervpn-speed-restore-') as directory:
        root=Path(directory)
        for name,body in ui.items():
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(body)
        app=root/'com/eabusham/routervpn';app.mkdir(parents=True)
        (app/'Boundaries.java').write_text(boundaries);(app/'SpeedLabRestoreTest.java').write_text(HARNESS)
        for name in ('AndroidConnectionSelection.java','AndroidUnifiedConnectionController.java','AndroidSpeedLabController.java','AndroidMTUMeasurementGate.java','AndroidSpeedLabDialog.java'):
            shutil.copyfile(JAVA/name,app/name)
        compile=['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(root/'classes'),*map(str,root.rglob('*.java'))]
        run=['java','-cp',os.pathsep.join((str(root/'classes'),str(jar))),'com.eabusham.routervpn.SpeedLabRestoreTest',str(root/'data')]
        (root/'data').mkdir()
        subprocess.run(compile,check=True,timeout=45);subprocess.run(run,check=True,timeout=35)
        cases=(
            ('AndroidSpeedLabDialog.java','cancel.setOnClickListener(v->{controller.cancel();','cancel.setOnClickListener(v->{;','Cancel button'),
            ('AndroidSpeedLabDialog.java','dialog.setOnDismissListener(d->{if(controller.isRunning())controller.cancel();});','dialog.setOnDismissListener(d->{});','dialog cancellation'),
            ('AndroidSpeedLabController.java','if(!originalSuspended||original==null||!original.connected())','if(true)','original restore'),
            ('AndroidSpeedLabController.java','meter.cancel();return;','return;','HTTP cancellation'),
            ('AndroidSpeedLabController.java','nativeHopMeter.cancel();return;','return;','native cancellation'),
            ('AndroidUnifiedConnectionController.java','point.home.runtimeMode,point.home.logicalMode,point.home.fallback','"wg",point.home.logicalMode,point.home.fallback','exact original transport'),
            ('AndroidUnifiedConnectionController.java','if(!file.getValue().equals(', 'if(false&&!file.getValue().equals(', 'changed original node'),
            ('AndroidSpeedLabController.java','if(!ok||!connection.restoredCurrent(original,restoredOwner[0]))','if(!ok)','fresh restoration owner'),
            ('AndroidUnifiedConnectionController.java','multihop.restoreCaptured(point.entry,point.exit,point.multihopCapture,idle,','multihop.connect(point.entry,point.exit,point.home.runtimeMode,point.execution,point.home.activeEntryMode,','captured original winner'),
            ('AndroidUnifiedConnectionController.java','multihop.captureCurrent(point.multihopCapture)','true','original Server pin owner'),
            ('AndroidUnifiedConnectionController.java','multihop.restoredMatches(point.multihopCapture,point.entry,point.exit,now)','true','restored Server pin owner'),
            ('AndroidUnifiedConnectionController.java','execution=runtime.standardExit.capturedRequestedExecution(home);selectedExecution=runtime.standardExit.capturedExternalExecution(home);','execution="local";selectedExecution="local";','captured Tor Server execution'),
            ('AndroidUnifiedConnectionController.java','ordinaryEntry=runtime.standardExit.capturedOrdinaryEntry(home);','ordinaryEntry=null;','captured ordinary source kind'),
            ('AndroidUnifiedConnectionController.java','if(point.ordinaryEntry==null?restored!=null:restored==null||!point.ordinaryEntryDigest.equals(externalDigest(restored)))return false;','','restored ordinary source identity'),
        )
        for filename,old,new,label in cases:
            path=app/filename;source=path.read_text();assert source.count(old)==1,label
            path.write_text(source.replace(old,new));subprocess.run(compile,check=True,timeout=45,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            result=subprocess.run(run,capture_output=True,text=True,timeout=35)
            assert result.returncode!=0 and 'AssertionError' in result.stderr,label+' negative control escaped'
            path.write_text(source)
        print(f'Android connected Speed Lab negative controls: {len(cases)} rejected')

if __name__=='__main__':main()
