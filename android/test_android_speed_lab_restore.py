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
 static volatile Runnable pendingConnect,pendingRestore,afterRestoredProof;static volatile java.util.concurrent.CountDownLatch stopRelease;
 static int starts,stops,restores,proofs;static String restoredRaw="",restoredLogical="",restoredExecution="",restoredEntry="",restoredExternal="";
 static void reset(){holdConnect=false;holdRestore=false;holdStop=false;stopEntered=false;stopping=false;pendingConnect=null;pendingRestore=null;afterRestoredProof=null;stopRelease=new java.util.concurrent.CountDownLatch(1);starts=stops=restores=proofs=0;restoredRaw=restoredLogical=restoredExecution=restoredEntry=restoredExternal="";}
 static void ready(Runnable r){if(holdConnect)pendingConnect=r;else r.run();}
 static boolean stop(String id)throws Exception{if(!id.equals(AndroidHomeStateStore.current.sessionId))return false;stops++;stopping=true;AndroidHomeStateStore.Snapshot s=AndroidHomeStateStore.copy();if(s.connected)s.pathGeneration++;s.connected=false;s.phase="connecting";s.pathProof="pending";AndroidHomeStateStore.current=s;stopEntered=true;if(holdStop)stopRelease.await();boolean owned=id.equals(AndroidHomeStateStore.current.sessionId);if(owned)AndroidHomeStateStore.off();stopping=false;return owned;}
}
final class AndroidModeOrchestrator {
 interface Callback{void progress(String message);void finished(boolean ok,String mode,String message);default void owned(String id){}}
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
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String id){}}
 String execution="local",selected="local";
 boolean isConnected(){return AndroidHomeStateStore.current.connected&&AndroidHomeStateStore.current.logicalMode.equals("multihop");}boolean isActiveOrTransitioning(){return isConnected();}
 String activeEntryId(){return AndroidHomeStateStore.current.activeEntryId;}String activeExitId(){return AndroidHomeStateStore.current.activeExitId;}String activeEntryMode(){return AndroidHomeStateStore.current.activeEntryMode;}String activeExitMode(){return AndroidHomeStateStore.current.runtimeMode;}String activeExecution(){return execution;}String activeSelectedExecution(){return selected;}
 boolean disconnectAndDrainCaptured(String id)throws Exception{return RuntimeBoundary.stop(id);}void disconnect(){}
 void connect(AndroidNodeStore.Node a,AndroidNodeStore.Node b,String mode,String exec,String entry,Callback cb){RuntimeBoundary.starts++;execution=exec;selected=exec.equals("auto")?"server":exec;AndroidHomeStateStore.begin("multihop",mode,a.id,b.id,entry,"");cb.owned(AndroidHomeStateStore.current.sessionId);RuntimeBoundary.ready(()->{AndroidHomeStateStore.proved();cb.finished(true,"proved graph");});}
 void restoreCaptured(AndroidNodeStore.Node a,AndroidNodeStore.Node b,String mode,String policy,String winner,String entry,Callback cb){RuntimeBoundary.restores++;RuntimeBoundary.restoredExecution=winner;execution=policy;selected=winner;AndroidHomeStateStore.begin("multihop",mode,a.id,b.id,entry,"");cb.owned(AndroidHomeStateStore.current.sessionId);Runnable finish=()->{AndroidHomeStateStore.proved();if(RuntimeBoundary.afterRestoredProof!=null)RuntimeBoundary.afterRestoredProof.run();cb.finished(true,"fresh exact winner proof");};if(RuntimeBoundary.holdRestore)RuntimeBoundary.pendingRestore=finish;else finish.run();}
 List<NativeSingBoxController.ModeInfo> listSupportedExitModes(File f){return Collections.emptyList();}
}
final class AndroidStandardExitRuntime {
 String execution="local",selected="local";
 String capturedRequestedExecution(AndroidHomeStateStore.Snapshot s){return execution;}String capturedExternalExecution(AndroidHomeStateStore.Snapshot s){return selected;}
 void connect(File f,AndroidStandardExitStore.Entry e,String mode,String execution,Callback cb){this.execution=execution;selected=execution.equals("auto")?"server":execution;connect(f,e,mode,cb);}
 void restoreCaptured(File f,AndroidStandardExitStore.Entry e,String mode,String execution,String winner,Callback cb){RuntimeBoundary.restores++;RuntimeBoundary.restoredExecution=winner;this.execution=execution;selected=winner;connect(f,e,mode,cb);}
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String id){}}
 boolean isActiveOrTransitioning(){return AndroidHomeStateStore.current.connected&&AndroidHomeStateStore.current.logicalMode.equals("external");}
 String capturedTorExit(AndroidHomeStateStore.Snapshot s){return "8.8.4.4";}String capturedExternalExit(AndroidHomeStateStore.Snapshot s){return "8.8.4.4";}
 void disconnect(){}boolean disconnectCaptured(String id)throws Exception{return RuntimeBoundary.stop(id);}boolean disconnectAndDrainCaptured(String id)throws Exception{return RuntimeBoundary.stop(id);}
 void connectDirect(AndroidStandardExitStore.Entry e,Callback cb){connect(null,e,"",cb);}void connect(File f,AndroidStandardExitStore.Entry e,String mode,Callback cb){RuntimeBoundary.starts++;AndroidHomeStateStore.begin("external",e.protocol,f==null?"":AndroidModeOrchestrator.node(f),"",mode,e.id);cb.owned(AndroidHomeStateStore.current.sessionId);RuntimeBoundary.ready(()->{AndroidHomeStateStore.proved();cb.finished(true,"proved external");});}
}
'''
METERS = r'''
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
import android.app.*;import java.nio.file.*;import java.util.*;
public final class SpeedLabRestoreTest {
 static int checks;static void check(boolean v,String msg){checks++;if(!v)throw new AssertionError(msg);}
 interface Condition{boolean ready();}static void waitFor(Condition c,String msg)throws Exception{long until=System.nanoTime()+3_000_000_000L;while(!c.ready()&&System.nanoTime()<until)Thread.sleep(2);check(c.ready(),msg);}
 static final class Result implements AndroidSpeedLabController.Callback {volatile int count;volatile Throwable error;volatile AndroidSpeedLab.Result result;public void progress(String s){}public void finished(AndroidSpeedLab.Result r,Throwable e){result=r;error=e;count++;}}
 static final class Fixture {
  final Activity activity=new Activity();final AndroidNodeStore nodes=new AndroidNodeStore(activity);final AndroidUnifiedConnectionController connection;final AndroidSpeedLabController controller;final Result result=new Result();final AndroidSpeedLabController.Request request=new AndroidSpeedLabController.Request();
  final AndroidNodeStore.Node original,first,last;final AndroidStandardExitStore.Entry external=new AndroidStandardExitStore.Entry();final String type,raw;String originalSession,originalWinner="server";
  Fixture(Path directory,String type,String topology)throws Exception{check(!AndroidMTUMeasurementGate.held(),"previous case leaked hold");this.type=type;this.raw=type.equals("multihop")?"max-quic-awg":type.startsWith("external")?type.substring(9):"reality-pq-vision";
   RuntimeBoundary.reset();AndroidHomeStateStore.current=new AndroidHomeStateStore.Snapshot();AndroidRuntimeRegistry.instance=new AndroidRuntimeRegistry();AndroidVpnMutationGuard.busy=false;AndroidNodeStore.nodes.clear();AndroidStandardExitStore.saved.clear();android.net.VpnService.needsPermission=false;AndroidSpeedLab.starts=AndroidSpeedLab.cancels=0;AndroidSpeedLab.pending=null;AndroidNativeHopMeasurement.starts=AndroidNativeHopMeasurement.cancels=0;AndroidNativeHopMeasurement.hold=false;AndroidNativeHopMeasurement.pending=null;LayeredVpnService.quiesce=null;LayeredVpnService.automatic=0;
   original=node(directory,"original");first=node(directory,"entry");last=node(directory,"exit");external.protocol=type.startsWith("external")?raw:"tor-bridge";AndroidStandardExitStore.saved.put(external.id,AndroidStandardExitStore.copy(external));
   connection=new AndroidUnifiedConnectionController(activity,nodes);controller=new AndroidSpeedLabController(activity,connection);
   if(type.equals("router")){AndroidHomeStateStore.begin("SMART AUTO",raw,"",original.id,"","");AndroidRuntimeRegistry.instance.orchestrator.source=Files.readString(original.file.toPath());AndroidHomeStateStore.proved();}
   if(type.equals("multihop")){AndroidHomeStateStore.begin("multihop",raw,original.id,last.id,"reality-xhttp","");AndroidRuntimeRegistry.instance.multihop.execution="auto";AndroidRuntimeRegistry.instance.multihop.selected="server";AndroidHomeStateStore.proved();}
   if(type.startsWith("external")){AndroidHomeStateStore.begin("external",raw,original.id,"","max-quic-awg",external.id);AndroidHomeStateStore.proved();}
   originalSession=AndroidHomeStateStore.current.sessionId;
   request.scope="temporary";request.topology=topology;request.node=first;request.entry=first;request.exit=last;request.mode="all";request.entryMode="wg-pq";request.exitMode="shadowsocks";request.execution="server";request.standardExit=external;request.externalDirect=false;
  }
  AndroidNodeStore.Node node(Path root,String id)throws Exception{Path folder=Files.createTempDirectory(root,id);Path file=folder.resolve(id+".json");Files.writeString(file,"{\"private\":\""+id+"\",\"dns\":\"home-adguard\",\"mtu\":\"auto\"}");AndroidNodeStore.Node n=new AndroidNodeStore.Node(id,file.toFile());AndroidNodeStore.nodes.add(n);return n;}
  void start(){controller.run(request,result);}void quiesce(){LayeredVpnService.quiesce.accept(null);}void measured()throws Exception{waitFor(()->AndroidSpeedLab.pending!=null,"measurement never started");AndroidSpeedLab.drained(false);}
  void complete()throws Exception{waitFor(()->result.count>0,"transaction never completed");check(result.count==1&&!controller.isRunning()&&!AndroidMTUMeasurementGate.held(),"completion did not release its drained lease exactly once");}
  void originalRestored(){AndroidHomeStateStore.Snapshot s=AndroidHomeStateStore.current;check(s.connected&&s.pathProof.equals("passed")&&!s.sessionId.equals(originalSession),"original lacks fresh proof/session");check(s.runtimeMode.equals(raw),"original raw transport changed");if(type.equals("router"))check(s.logicalMode.equals("SMART AUTO")&&s.activeNodeId.equals(original.id)&&RuntimeBoundary.restoredRaw.equals(raw),"SMART AUTO was reselected or node changed");if(type.equals("multihop"))check(s.activeEntryId.equals(original.id)&&s.activeEntryMode.equals("reality-xhttp")&&s.activeExitId.equals(last.id)&&AndroidRuntimeRegistry.instance.multihop.execution.equals("auto")&&AndroidRuntimeRegistry.instance.multihop.selected.equals(originalWinner)&&RuntimeBoundary.restoredExecution.equals(originalWinner),"original multihop execution/entry changed");if(type.startsWith("external"))check(s.activeExternalId.equals(external.id)&&s.activeEntryMode.equals("max-quic-awg")&&s.activeEntryId.equals(original.id),"external original entry or profile changed");check(nodes.activeId().equals("original"),"temporary path rewrote selected saved node");}
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
  for(String selected:new String[]{"local","server"})for(String topology:new String[]{"router","multihop","external","system-direct"}){
   Fixture f=new Fixture(root,"external-shadowsocks",topology);AndroidStandardExitRuntime owner=AndroidRuntimeRegistry.instance.standardExit;owner.execution="auto";owner.selected=selected;
   f.start();f.quiesce();f.measured();f.complete();check(f.result.error==null,"external winner restoration failed");f.originalRestored();
   check(owner.execution.equals("auto")&&owner.selected.equals(selected)&&RuntimeBoundary.restoredExecution.equals(selected),"external Compare was rerun instead of restoring its proved winner");
  }
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
  for(String mutation:new String[]{"node","external-profile","newer-connected","manual-off","during-stop","restored-proof"}){
   Fixture f=new Fixture(root,mutation.equals("external-profile")?"external-openvpn":mutation.equals("node")?"multihop":"router","external");f.start();f.quiesce();waitFor(()->AndroidSpeedLab.pending!=null,"stale fixture not measured");
   if(mutation.equals("node"))Files.writeString(f.original.file.toPath(),"changed original DNS");
   if(mutation.equals("external-profile")){AndroidStandardExitStore.Entry e=AndroidStandardExitStore.copy(f.external);e.secret="replacement key";AndroidStandardExitStore.saved.put(e.id,e);}
   if(mutation.equals("newer-connected")){AndroidHomeStateStore.begin("new-user","wg","","new-node","","");AndroidHomeStateStore.proved();}
   if(mutation.equals("manual-off"))AndroidHomeStateStore.off();
   if(mutation.equals("during-stop")){RuntimeBoundary.holdStop=true;RuntimeBoundary.stopEntered=false;}
   if(mutation.equals("restored-proof"))RuntimeBoundary.afterRestoredProof=()->{AndroidHomeStateStore.begin("new-user","wg","","new-node","","");AndroidHomeStateStore.proved();};
   AndroidSpeedLab.drained(false);
   if(mutation.equals("during-stop")){waitFor(()->RuntimeBoundary.stopEntered,"cleanup not started");AndroidHomeStateStore.advancePathGeneration(f.activity);RuntimeBoundary.holdStop=false;RuntimeBoundary.stopRelease.countDown();}
   f.complete();check(f.result.error!=null&&f.result.result==null,"stale transaction kept result");check(RuntimeBoundary.restores==(mutation.equals("restored-proof")?1:0),"stale transaction restored old runtime");if(mutation.equals("newer-connected")||mutation.equals("restored-proof"))check(AndroidHomeStateStore.current.logicalMode.equals("new-user")&&AndroidHomeStateStore.current.connected,"cleanup disconnected replacement");
  }
 }


 static void permissionCapture(Path root)throws Exception{
  for(String topology:new String[]{"router","multihop","external"}){
   Fixture f=new Fixture(root,"router",topology);android.net.VpnService.needsPermission=true;f.start();f.quiesce();waitFor(()->f.activity.permissionRequest!=0,"permission boundary never reached");
   Files.writeString(f.first.file.toPath(),"changed test credentials during permission");android.net.VpnService.needsPermission=false;f.connection.onActivityResult(AndroidUnifiedConnectionController.PREPARE_UNIFIED,Activity.RESULT_OK);f.complete();
   check(f.result.error!=null&&RuntimeBoundary.starts==0&&AndroidSpeedLab.starts==0,"permission completion used changed test profile: "+topology);f.originalRestored();
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
 public static void main(String[]args)throws Exception{Path root=Path.of(args[0]);matrix(root);exactMultihopWinner(root);exactExternalWinner(root);cancellation(root);stale(root);permissionCapture(root);uiCancellation(root);System.out.println("Shipping Android Speed Lab restoration: "+checks+" checks;24 paths,8 exact-winner restores,8 cancellation phases,changed profile and newer-user ownership");}
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
    ui['android/content/SharedPreferences.java']='package android.content;public interface SharedPreferences{String getString(String key,String fallback);}'
    ui['android/os/Bundle.java']=ui['android/os/Bundle.java'][:-1]+'public void putStringArrayList(String k,java.util.ArrayList<String> v){values.put(k,v);}public java.util.ArrayList<String> getStringArrayList(String k){return (java.util.ArrayList<String>)values.get(k);}public boolean containsKey(String k){return values.containsKey(k);}}'

    ui['android/graphics/Color.java']='package android.graphics;public final class Color{public static final int WHITE=-1;public static int rgb(int r,int g,int b){return r*65536+g*256+b;}}'
    ui['android/view/Gravity.java']='package android.view;public final class Gravity{public static final int CENTER_VERTICAL=16;}'
    ui['android/view/View.java']=ui['android/view/View.java'][:-1]+'public static final int VISIBLE=0,GONE=8;private Object tag;public void setTag(Object v){tag=v;}public Object getTag(){return tag;}public void setVisibility(int v){}public void setBackgroundColor(int c){} }'
    ui['android/widget/TextView.java']=ui['android/widget/TextView.java'][:-1]+'public void setTextIsSelectable(boolean v){}public void setHintTextColor(int c){} }'
    ui['android/widget/LinearLayout.java']=ui['android/widget/LinearLayout.java'].replace('public static final int VERTICAL=1;','public static final int VERTICAL=1,HORIZONTAL=0;public void setGravity(int g){}').replace('public LayoutParams(int width,int height){}','public LayoutParams(int width,int height){}public LayoutParams(int width,int height,float weight){}')
    ui['android/widget/CheckBox.java']=ui['android/widget/CheckBox.java'][:-1]+'public interface OnCheckedChangeListener{void onChanged(CheckBox c,boolean v);}public void setOnCheckedChangeListener(OnCheckedChangeListener l){} }'
    ui['android/widget/ArrayAdapter.java']=ui['android/widget/ArrayAdapter.java'].replace('public void setDropDownViewResource', 'public ArrayAdapter(android.content.Context c,int layout,java.util.List<T> source){values=(T[])source.toArray();}public void setDropDownViewResource')
    ui['android/widget/SeekBar.java']='package android.widget;public final class SeekBar extends android.view.View{int value;OnSeekBarChangeListener listener;public SeekBar(android.content.Context c){super(c);}public void setMax(int v){}public void setProgress(int v){value=v;if(listener!=null)listener.onProgressChanged(this,v,false);}public int getProgress(){return value;}public void setOnSeekBarChangeListener(OnSeekBarChangeListener l){listener=l;}public interface OnSeekBarChangeListener{void onStartTrackingTouch(SeekBar b);void onStopTrackingTouch(SeekBar b);void onProgressChanged(SeekBar b,int p,boolean u);}}'
    ui['android/app/AlertDialog.java']=ui['android/app/AlertDialog.java'].replace('public void dismiss(){','public boolean isShowing(){return showing;}public void dismiss(){')
    boundaries=P.BOUNDARIES.replace('String id="saved-exit",protocol','String name="Saved exit",id="saved-exit",protocol')
    for name in ('AndroidHomeStateStore','AndroidModeOrchestrator','AndroidMultihopRuntime','AndroidStandardExitRuntime'):
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
        for name in ('AndroidUnifiedConnectionController.java','AndroidSpeedLabController.java','AndroidMTUMeasurementGate.java','AndroidSpeedLabDialog.java'):
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
            ('AndroidUnifiedConnectionController.java','point.execution,point.selectedExecution,point.home.activeEntryMode','point.execution,"local",point.home.activeEntryMode','captured original winner'),
        )
        for filename,old,new,label in cases:
            path=app/filename;source=path.read_text();assert source.count(old)==1,label
            path.write_text(source.replace(old,new));subprocess.run(compile,check=True,timeout=45,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            result=subprocess.run(run,capture_output=True,text=True,timeout=35)
            assert result.returncode!=0 and 'AssertionError' in result.stderr,label+' negative control escaped'
            path.write_text(source)
        print('Android connected Speed Lab negative controls: 9 rejected')

if __name__=='__main__':main()
