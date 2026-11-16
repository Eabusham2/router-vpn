#!/usr/bin/env python3
"""Exercise the shipping Android Server/Compare fifty-response host composition.

Session, execution capture, full VPN service, worker, stores, MTU gate and dialog
are shipping Java. Native execution/probe exchanges, Android widgets and file
syscalls are explicit controlled boundaries. This is host lifecycle evidence;
the shared real-path tests, generated SDK and device acceptance are separate.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

import test_android_node_chain_execution_runtime as E
import test_android_ordered_latency as F

ROOT, JAVA, APP, NATIVE = E.ROOT, E.JAVA, E.APP, E.NATIVE


def replace_once(source, before, after):
    assert source.count(before) == 1, before
    return source.replace(before, after)


NATIVE_FIFTY = r'''package io.nekohasekai.libbox;
import org.json.*;import java.util.concurrent.*;
public final class RouterOrderedLatency {
 public static volatile RouterOrderedLatency latest;public static volatile String fault="";
 public static volatile Runnable afterDrain,beforeStart,beforeClose,validationCheck,afterValidation,factoryHook;
 public static volatile boolean holdClose,holdDrain,holdResponses,mtuOccupied;
 public static volatile CountDownLatch quiesceEntered,quiesceRelease;public static int factories;
 public final RouterNodeChainExecution plan;public final CommandServer server;public final RouterHopMeasurement measurement;
 public final String selected,epoch,raw;public final JSONArray nodes;
 public volatile String request,node;public volatile int starts,cancels,drains,closes,validations;
 public final java.util.concurrent.atomic.AtomicReference<Runnable> beforeCancel=new java.util.concurrent.atomic.AtomicReference<>();
 public volatile boolean drained,closed;public final CountDownLatch closeEntered=new CountDownLatch(1),drainEntered=new CountDownLatch(1);
 public RouterOrderedLatency(RouterNodeChainExecution plan,CommandServer server,RouterHopMeasurement measurement)throws Exception{
  if(plan==null||!plan.healthy()||plan.server!=server||plan.measurement!=measurement||measurement==null||measurement.invalidated||mtuOccupied)
   throw new IllegalStateException("facade did not borrow the original execution measurement");
  this.plan=plan;this.server=server;this.measurement=measurement;selected=plan.selected;epoch=plan.epoch;
  JSONObject launch=new JSONObject(plan.localLaunch);JSONArray originals=launch.getJSONArray("nodes"),identities=launch.getJSONArray("identity_sources");nodes=new JSONArray();
  for(int i=0;i<originals.length();i++){
   String id="native-"+originals.getString(i).substring("original-node-".length());
   nodes.put(new JSONObject().put("node_id",id).put("position",i).put("role",i==0?"entry":i==originals.length()-1?"exit":"intermediate").put("kind",identities.getString(i).isEmpty()?"public-path":"private-node"));
  }
  raw=new JSONObject().put("schema",1).put("source_sha256","d".repeat(64)).put("config_sha256","e".repeat(64)).put("generation_sha256",epoch).put("selected_execution",selected).put("nodes",nodes).toString();
  latest=this;factories++;Runnable hook=factoryHook;factoryHook=null;if(hook!=null)hook.run();
 }
 public String captureJSON()throws Exception{
  if(closed)return "";JSONObject value=new JSONObject(raw);
  if(fault.equals("capture-empty"))return "";
  if(fault.equals("capture-selection"))value.put("selected_execution",selected.equals("server")?"local":"server");
  if(fault.equals("capture-inventory"))value.getJSONArray("nodes").getJSONObject(0).put("node_id","another-native-node");
  if(fault.equals("capture-kind"))value.getJSONArray("nodes").getJSONObject(1).put("kind","public-path");
  if(fault.equals("capture-generation"))value.put("generation_sha256","invalid-generation");
  return value.toString();
 }
 public void start(String request,String node)throws Exception{
  starts++;this.request=request;this.node=node;Runnable hook=beforeStart;beforeStart=null;if(hook!=null)hook.run();
  if(fault.equals("start"))throw new IllegalStateException("native start refused");
 }
 public void cancel(String request){if(this.request!=null&&!this.request.equals(request))throw new AssertionError("cancel substituted another request");Runnable hook=beforeCancel.getAndSet(null);if(hook!=null)hook.run();cancels++;}
 public void drain(String request)throws Exception{
  if(!request.equals(this.request))throw new AssertionError("drain substituted another request");drains++;drainEntered.countDown();
  if(holdDrain)throw new IllegalStateException("original drain pending");drained=true;Runnable hook=afterDrain;afterDrain=null;if(hook!=null)hook.run();
 }
 public void close()throws Exception{
  closes++;closeEntered.countDown();if(holdClose)throw new IllegalStateException("original facade pending");
  Runnable hook=beforeClose;beforeClose=null;if(hook!=null)hook.run();closed=true;
 }
 public void validateClosedCapture(String request,String capture)throws Exception{
  validations++;Runnable check=validationCheck;if(check!=null)check.run();
  if(!closed||!drained||starts!=1||this.request==null||!this.request.equals(request)||!raw.equals(capture)
    ||plan.measurement!=measurement||measurement.invalidated||!plan.healthy()||plan.server!=server||server.closed
    ||!selected.equals(plan.selected)||!epoch.equals(plan.epoch)||fault.equals("closed-proof"))
   throw new IllegalStateException("original closed capture no longer has its selected proof");
  Runnable hook=afterValidation;afterValidation=null;if(hook!=null)hook.run();
 }
 private int position()throws Exception{for(int i=0;i<nodes.length();i++)if(nodes.getJSONObject(i).getString("node_id").equals(node))return i;throw new IllegalStateException("unknown captured node");}
 public JSONObject receipt()throws Exception{
  int position=position();JSONObject member=nodes.getJSONObject(position);boolean pub=member.getString("kind").equals("public-path");
  JSONObject distribution=new JSONObject().put("samples",fault.equals("49")?49:50).put("min_ms",1).put("median_ms",2).put("average_ms",2.1).put("p90_ms",3).put("max_ms",4).put("jitter_ms",0.2);
  JSONObject benchmark=new JSONObject().put("schema",1).put("measurement",pub?"routed-https-response-after-tls":"routed-private-response-including-connection").put("endpoint",pub?"https://speed.cloudflare.com/__down?bytes=1":"").put("attempts",50).put("failed",0).put("distribution",distribution).put("trimmed_mean_ms",2);
  String path=fault.equals("receipt-selected")?(selected.equals("server")?"local":"server"):selected;
  JSONObject row=new JSONObject().put("node_id",node).put("role",member.getString("role")).put("kind",member.getString("kind")).put("label","Cumulative "+path+" path through "+(pub?"custom node "+(position+1)+" of "+nodes.length()+" → Cloudflare edge":"node "+(position+1)+" of "+nodes.length())).put("ready",true).put("benchmark",benchmark);
  if(fault.equals("count"))row.put("label","Cumulative "+path+" path through node 1 of 2");
  String source=fault.equals("receipt-preparation")?plan.sourceSHA256():fault.equals("receipt-local")?plan.localSHA:"d".repeat(64);
  JSONObject value=new JSONObject().put("schema",1).put("source_sha256",source).put("config_sha256",fault.equals("receipt-config")?plan.configSHA256():"e".repeat(64)).put("generation_sha256",fault.equals("receipt-generation")?"f".repeat(64):epoch).put("position",position).put("node_id",node).put("request_id",fault.equals("receipt-request")?"f".repeat(32):request).put("measured_at",System.currentTimeMillis()).put("result",row);
  if(fault.equals("receipt-inventory"))row.put("role","exit");return value;
 }
 public String statusJSON()throws Exception{
  JSONObject value=new JSONObject().put("request_id",request).put("stage",holdResponses?"node 1: response 49/50":"complete").put("complete",!holdResponses).put("drained",drained).put("results",holdResponses?new JSONArray():new JSONArray().put(receipt().getJSONObject("result")));
  if(fault.equals("last"))value.put("failure","fiftieth response failed");return value.toString();
 }
 public String savedJSON(String node)throws Exception{if(!node.equals(this.node)||!drained)throw new AssertionError("history before original worker drain");return receipt().toString();}
 public static void reset(){fault="";afterDrain=beforeStart=beforeClose=validationCheck=afterValidation=factoryHook=null;holdClose=holdDrain=holdResponses=mtuOccupied=false;quiesceEntered=quiesceRelease=null;latest=null;}
}'''


def sources():
    result = E.sources()
    for path in tuple(result):
        if path.startswith('android/') and path in F.SOURCES:
            result[path] = F.SOURCES[path]
    for path, text in F.SOURCES.items():
        if path.startswith(('android/widget/', 'android/view/', 'android/graphics/')) or path in ('android/app/AlertDialog.java', 'android/app/Activity.java', 'android/content/DialogInterface.java'):
            result[path] = text
    result[APP+'AndroidPrivateFileStore.java'] = F.SOURCES[APP+'AndroidPrivateFileStore.java']
    result[APP+'AndroidTorProfile.java'] = F.SOURCES[APP+'AndroidTorProfile.java']
    result[APP+'AndroidNodeStore.java'] = replace_once(result[APP+'AndroidNodeStore.java'], 'final boolean imported=false;', 'boolean imported=false;')
    result[APP+'AndroidNodeStore.java'] = replace_once(result[APP+'AndroidNodeStore.java'], 'modes=java.util.List.copyOf(selected);', 'modes=new java.util.ArrayList<>(selected);')
    result[APP+'AndroidNodeChainCapture.java'] = replace_once(E.CAPTURE, 'identities.put(source.imported&&i==source.members.size()-2?"":"original-identity-"+source.members.get(i).id);', 'identities.put(source.members.get(i).imported?"":"original-identity-"+source.members.get(i).id);')
    result[APP+'AndroidNodeChainCapture.java'] = replace_once(result[APP+'AndroidNodeChainCapture.java'], '.put("schema",source.imported?2:1)', '.put("schema",source.members.stream().anyMatch(item->item.imported)?2:1)')
    result[NATIVE+'RouterNodeChainExecution.java'] = replace_once(E.EXECUTION, 'public CommandServer server;', 'public RouterHopMeasurement measurement;public volatile String epoch="c".repeat(64);public CommandServer server;')
    if result[NATIVE+'RouterNodeChainExecution.java'].count('JSONObject local=new JSONObject().put("schema",original.getInt("schema"))') != 1:
        raise AssertionError("execution fixture no longer retains the original Local schema")
    result[NATIVE+'RouterOrderedLatency.java'] = NATIVE_FIFTY
    lib = replace_once(result[NATIVE+'Libbox.java'], 'executionMeasurement=owner;executionServer=server;return new RouterHopMeasurement();', 'executionMeasurement=owner;executionServer=server;return owner.measurement=new RouterHopMeasurement();')
    result[NATIVE+'Libbox.java'] = replace_once(lib, 'throw new IllegalStateException("No execution fifty factory in type boundary");', 'return new RouterOrderedLatency(p,s,m);')
    result[APP+'AndroidMTUSession.java'] = replace_once(result[APP+'AndroidMTUSession.java'], 'public void drainForMeasurement()throws Exception{}', '''public void drainForMeasurement()throws Exception{if(io.nekohasekai.libbox.RouterOrderedLatency.quiesceEntered!=null)io.nekohasekai.libbox.RouterOrderedLatency.quiesceEntered.countDown();if(io.nekohasekai.libbox.RouterOrderedLatency.quiesceRelease!=null&&!io.nekohasekai.libbox.RouterOrderedLatency.quiesceRelease.await(5,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("fixture MTU drain did not join");if(io.nekohasekai.libbox.RouterOrderedLatency.fault.equals("quiesce"))throw new IllegalStateException("MTU drain failed");io.nekohasekai.libbox.RouterOrderedLatency.mtuOccupied=false;}''')
    return result


def existing_family(begin, end):
    return F.HARNESS[F.HARNESS.index(begin):F.HARNESS.index(end)]


HARNESS = E.HARNESS[:E.HARNESS.index(' static void success()')].replace('OrderedExecutionRuntimeTest', 'ExecutionFiftyTest')
HARNESS = replace_once(HARNESS, '  Fixture(int count,String requested)', '  Fixture(int count)throws Exception{this(count,"auto");if(count==3){source.members.get(1).imported=true;source.modes.set(1,"shadowsocks");}}\n  Fixture(int count,String requested)')
HARNESS += existing_family(' static final class Outcome', ' static AndroidOrderedLatencyStore.Record saved')
HARNESS += r'''
 static AndroidOrderedExecutionLatencyStore.Entry history(Fixture f,LayeredVpnService.OrderedLatencyTarget target)throws Exception{return AndroidOrderedExecutionLatencyStore.load(f.service,target.namespaceSource,target.namespaceConfig,target.requested,target.selected,target.position,target.node,target.kind);}
 static AndroidOrderedLatencyStore.Record saved(Fixture f,LayeredVpnService.OrderedLatencyTarget target)throws Exception{var entry=history(f,target);return entry==null?null:entry.record;}
 static Outcome measure(LayeredVpnService.OrderedLatencyTarget target)throws Exception{Outcome result=new Outcome();new AndroidOrderedLatencyBenchmark().run(target,result);result.joined();return result;}
 static void success()throws Exception{
  int shapes=0,positions=0;
  for(int count=2;count<=8;count++)for(boolean imported:(count==3||count==4||count==8)?new boolean[]{false,true}:new boolean[]{false})for(String variant:List.of("server/server","auto/server","auto/local")){
   RouterOrderedLatency.reset();String requested=variant.split("/")[0],selected=variant.split("/")[1];
   try(Fixture f=new Fixture(count,requested)){
    if(imported){f.source.members.get(count-2).imported=true;f.source.modes.set(count-2,"shadowsocks");}RouterNodeChainExecution.configured=plan->plan.selected=selected;f.connected();shapes++;
    var original=f.owner();var plan=original.execution.plan;var probe=(RouterHopMeasurement)get(f.service,"hopMeasurement");int preparations=RouterNodeChainExecution.ordinaryPreparations,runs=plan.runs;
    var targets=LayeredVpnService.orderedLatencyTargets();check(targets.size()==count,"execution inventory lost an original member");
    for(var target:targets){
     positions++;Outcome result=measure(target);check(result.error==null&&result.record!=null,"complete execution benchmark not adopted: "+result.error);var facade=RouterOrderedLatency.latest;var entry=history(f,target);
     check(facade.plan==plan&&facade.server==plan.server&&facade.measurement==probe,"execution benchmark replaced its original typed native owners");
     check(entry.record.raw.equals(result.record.raw)&&entry.capture.raw.equals(facade.raw),"execution history altered the native receipt or capture bytes");
     check(result.record.source.equals("d".repeat(64))&&result.record.config.equals("e".repeat(64))&&result.record.generation.equals(plan.epoch),"execution receipt borrowed preparation or dormant Local identity");
     check(!result.record.source.equals(target.namespaceSource)&&!result.record.source.equals(target.source)&&entry.namespaceSource.equals(plan.sourceSHA256()),"execution history confused preparation lookup and measured projection");
     check(result.record.selectedExecution.equals(selected)&&result.record.node.equals(target.node)&&target.kind.equals(imported&&target.position==count-2?"public-path":"private-node"),"execution result lost winner or captured node kind");
     check(result.record.detail().contains("Selected execution: "+(selected.equals("server")?"Server":"Local"))&&facade.closed&&facade.validations==1&&!AndroidMTUMeasurementGate.held(),"execution receipt escaped selected label, joined close or fresh proof");
     check(AndroidOrderedLatencyStore.load(f.service,target.source,target.config,target.position,target.node,target.kind)==null,"execution result entered ordinary Local history");
    }
    check(plan.runs==runs&&RouterNodeChainExecution.ordinaryPreparations==preparations&&probe.closes==0&&get(f.service,"hopMeasurement")==probe,"fifty reran Compare or retired the borrowed throughput service");
    ((AndroidMTUSession)get(f.service,"mtuSession")).token=1L;check(measure(targets.get(0)).error==null,"current MTU epoch prevented a fresh original execution measurement");f.stop();check(probe.closes==1,"complete session teardown did not retire original throughput");
   }
  }
  check(shapes==30&&positions==150,"execution host matrix silently narrowed");
 }
 static void captureFaults()throws Exception{
  for(String fault:List.of("capture-empty","capture-selection","capture-inventory","capture-kind","capture-generation","receipt-preparation","receipt-local","receipt-config","receipt-generation","receipt-selected","receipt-request","receipt-inventory")){
   RouterOrderedLatency.reset();try(Fixture f=new Fixture(3,"auto")){
    f.connected();var target=LayeredVpnService.orderedLatencyTargets().get(0);var before=measure(target).record;check(before!=null,"capture refusal baseline missing");RouterOrderedLatency.fault=fault;
    Outcome result=measure(target);check(result.error!=null&&result.record==null,"invalid execution capture or receipt adopted: "+fault);check(saved(f,target).raw.equals(before.raw),"invalid execution metadata replaced previous history: "+fault);
    var facade=RouterOrderedLatency.latest;check(facade.closed&&!AndroidMTUMeasurementGate.held()&&get(f.owner(),"orderedLatency")==null,"failed capture lost its exact facade cleanup: "+fault);f.stop();
   }
  }
 }
 static void authority()throws Exception{
  for(String fault:List.of("epoch","measurement","closed-proof","after-proof-source","after-proof-selected","after-proof-mtu","original-request","file-monitor")){
   RouterOrderedLatency.reset();try(Fixture f=new Fixture(3,"auto")){
    f.connected();var target=LayeredVpnService.orderedLatencyTargets().get(0);var baseline=measure(target).record;check(baseline!=null,"post-close baseline missing");var plan=f.owner().execution.plan;var probe=plan.measurement;
    RouterOrderedLatency.validationCheck=()->check(!Thread.holdsLock(AndroidHomeStateStore.class)&&!Thread.holdsLock(AndroidPrivateFileStore.class),"fresh execution proof ran under Home or private-file monitor");
    if(fault.equals("epoch"))RouterOrderedLatency.beforeClose=()->plan.epoch="f".repeat(64);
    if(fault.equals("measurement"))RouterOrderedLatency.beforeClose=()->plan.measurement=new RouterHopMeasurement();
    if(fault.equals("closed-proof"))RouterOrderedLatency.fault="closed-proof";
    if(fault.equals("after-proof-source"))RouterOrderedLatency.afterValidation=()->f.source.valid=false;
    if(fault.equals("after-proof-selected"))RouterOrderedLatency.afterValidation=()->plan.selected="local";
    if(fault.equals("after-proof-mtu"))RouterOrderedLatency.afterValidation=()->{try{((AndroidMTUSession)get(f.service,"mtuSession")).token=99L;}catch(Exception failure){throw new RuntimeException(failure);}};
    Outcome result=measure(target);
    if(fault.equals("original-request")||fault.equals("file-monitor"))check(result.error==null&&result.record!=null&&RouterOrderedLatency.latest.validations==1,"exact request or unlocked closed proof was lost");
    else check(result.error!=null&&result.record==null&&saved(f,target).raw.equals(baseline.raw),"stale native closed proof adopted: "+fault);
    check(RouterOrderedLatency.latest.closed&&!AndroidMTUMeasurementGate.held(),"post-close refusal leaked owned cleanup");
    f.source.valid=true;plan.selected="server";plan.epoch="c".repeat(64);plan.measurement=probe;RouterOrderedLatency.validationCheck=null;f.stop();
   }
  }
 }
 static void factoryRetirement()throws Exception{RouterOrderedLatency.reset();try(Fixture f=new Fixture(3,"auto")){
  f.connected();var target=LayeredVpnService.orderedLatencyTargets().get(0);RouterOrderedLatency.factoryHook=()->f.source.valid=false;var result=measure(target);
  check(result.error!=null&&result.record==null&&RouterOrderedLatency.latest!=null&&RouterOrderedLatency.latest.closed,"source replacement during factory lost original cleanup");
  check(saved(f,target)==null&&!AndroidMTUMeasurementGate.held(),"retired factory saved receipt or leaked MTU");f.source.valid=true;f.stop();
 }}
'''
HARNESS += existing_family(' static void faults()', ' static String mutate(').replace('f.owner().capture.socks.plan', 'f.owner().execution.plan')
HARNESS += existing_family(' static void staleUI()', ' public static void main(')
HARNESS += r'''
 // The native boundary can hold its fresh proof or an already captured Cancel.
 // Neither hold is a successful native proof, and every worker is released and
 // joined before an assertion can terminate this fixture.
 static void holdCancelFixture(CountDownLatch release){
  try{if(!release.await(5,TimeUnit.SECONDS))throw new AssertionError("held cancellation fixture did not release");}
  catch(InterruptedException error){Thread.currentThread().interrupt();throw new AssertionError("held cancellation fixture interrupted",error);}
 }
 static boolean blockedOnOriginal(Thread waiter,Object monitor,Thread owner){
  if(owner==null)return false;
  java.lang.management.ThreadInfo info=java.lang.management.ManagementFactory.getThreadMXBean().getThreadInfo(waiter.getId());
  return info!=null&&info.getThreadState()==Thread.State.BLOCKED&&info.getLockInfo()!=null
    &&info.getLockInfo().getIdentityHashCode()==System.identityHashCode(monitor)&&info.getLockOwnerId()==owner.getId();
 }
 static void joinCancelFixture(Thread... threads)throws Exception{
  InterruptedException interrupted=null;
  for(Thread thread:threads)if(thread!=null)try{thread.join(5000L);}catch(InterruptedException error){interrupted=error;}
  for(Thread thread:threads)if(thread!=null)check(!thread.isAlive(),"original cancellation fixture thread did not join");
  if(interrupted!=null){Thread.currentThread().interrupt();throw interrupted;}
 }
 static void cancelCommit()throws Exception{
  RouterOrderedLatency.reset();try(Fixture f=new Fixture(3,"auto")){
   f.connected();var target=LayeredVpnService.orderedLatencyTargets().get(0);var baseline=measure(target).record;check(baseline!=null,"held-proof history baseline missing");
   android.app.Activity activity=new android.app.Activity();activity.files=f.service.files;
   AndroidOrderedLatencyDialog view=new AndroidOrderedLatencyDialog(activity);view.show();android.app.AlertDialog.last.clickItem(0);
   var dialog=android.app.AlertDialog.last;var runner=(AndroidOrderedLatencyBenchmark)get(view,"benchmark");
   CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1),returned=new CountDownLatch(1);
   var worker=new java.util.concurrent.atomic.AtomicReference<Thread>();var cancellationError=new java.util.concurrent.atomic.AtomicReference<Throwable>();
   RouterOrderedLatency.validationCheck=()->{check(Thread.holdsLock(runner),"held proof did not execute inside the original commit");worker.set(Thread.currentThread());entered.countDown();holdCancelFixture(release);};
   Thread cancel=new Thread(()->{try{view.close();}catch(Throwable error){cancellationError.set(error);}finally{returned.countDown();}},"execution-fifty-ui-cancel");
   boolean returnedWhileHeld=false,retainedWhileHeld=false;RouterOrderedLatency original=null;
   try{
    dialog.getButton(-1).performClick();check(entered.await(5,TimeUnit.SECONDS),"fresh original proof was not held");original=RouterOrderedLatency.latest;
    cancel.start();await(()->returned.getCount()==0||blockedOnOriginal(cancel,runner,worker.get()),"Cancel neither returned nor exposed its original held monitor");
    returnedWhileHeld=returned.getCount()==0;
    retainedWhileHeld=runner.isRunning()&&AndroidMTUMeasurementGate.held()&&worker.get().isAlive();
   }finally{
    release.countDown();joinCancelFixture(cancel,worker.get());RouterOrderedLatency.validationCheck=null;
   }
   check(cancellationError.get()==null,"public Cancel failed at its original owner");
   check(returnedWhileHeld,"Cancel waited for the held native history proof");
   check(retainedWhileHeld,"Cancel released the original worker or MTU before proof join");
   check(original!=null&&original.cancels>0&&original.closed&&!runner.isRunning()&&!AndroidMTUMeasurementGate.held(),"held-proof Cancel lost its original joined cleanup");
   check(saved(f,target).raw.equals(baseline.raw),"cancelled fresh proof replaced previous execution history");
   activity.deliver();check(!dialog.isShowing(),"late cancelled callback reopened the old dialog");f.stop();
  }
  RouterOrderedLatency.reset();try(Fixture f=new Fixture(3,"auto")){
   f.connected();var target=LayeredVpnService.orderedLatencyTargets().get(0);var runner=new AndroidOrderedLatencyBenchmark();var first=new Outcome();var replacement=new Outcome();
   CountDownLatch captured=new CountDownLatch(1),release=new CountDownLatch(1);var firstWorker=new java.util.concurrent.atomic.AtomicReference<Thread>();var nextWorker=new java.util.concurrent.atomic.AtomicReference<Thread>();
   var cancellationError=new java.util.concurrent.atomic.AtomicReference<Throwable>();RouterOrderedLatency.holdResponses=true;RouterOrderedLatency.beforeStart=()->firstWorker.set(Thread.currentThread());
   Thread lateCancel=new Thread(()->{try{runner.cancel();}catch(Throwable error){cancellationError.set(error);}},"execution-fifty-retained-cancel");
   RouterOrderedLatency original=null,next=null;boolean replacementStarted=false;
   try{
    runner.run(target,first);await(()->RouterOrderedLatency.latest!=null&&RouterOrderedLatency.latest.starts==1,"original request did not start");original=RouterOrderedLatency.latest;
    original.beforeCancel.set(()->{captured.countDown();holdCancelFixture(release);});lateCancel.start();check(captured.await(5,TimeUnit.SECONDS),"Cancel did not retain its original facade");
    first.joined();joinCancelFixture(firstWorker.get());check(first.error!=null&&first.record==null&&!runner.isRunning()&&!AndroidMTUMeasurementGate.held(),"cancelled old job did not retire before replacement");
    RouterOrderedLatency.beforeStart=()->nextWorker.set(Thread.currentThread());runner.run(target,replacement);replacementStarted=true;
    final RouterOrderedLatency old=original;await(()->RouterOrderedLatency.latest!=old&&RouterOrderedLatency.latest.starts==1,"replacement request did not start");next=RouterOrderedLatency.latest;
    check(!next.request.equals(original.request)&&next.cancels==0,"replacement did not retain a new uncancelled request");
    release.countDown();joinCancelFixture(lateCancel);
    check(cancellationError.get()==null,"retained original cancellation substituted a request");
    check(next.cancels==0&&runner.isRunning()&&AndroidMTUMeasurementGate.held()&&replacement.done.getCount()==1,"late original Cancel borrowed the replacement job");
   }finally{
    release.countDown();joinCancelFixture(lateCancel);
    runner.cancel();RouterOrderedLatency.holdResponses=false;
    if(replacementStarted)replacement.joined();else first.joined();
    joinCancelFixture(firstWorker.get(),nextWorker.get());
   }
   check(original!=null&&next!=null&&original.closed&&next.closed&&replacement.error!=null&&saved(f,target)==null&&!AndroidMTUMeasurementGate.held(),"late original cancellation lost independent request cleanup");f.stop();
  }
 }

 public static void main(String[] args)throws Exception{
  String selected=args.length==0?"all":args[0];
  for(String family:List.of("success","faults","pending","quiesce","retirement","capture-faults","authority","factory-retirement","ui","stale-ui","cancel-commit"))if(selected.equals("all")||selected.equals(family)){
   switch(family){case "success":success();break;case "faults":faults();break;case "pending":pending();break;case "quiesce":quiesce();break;case "retirement":retirement();break;case "capture-faults":captureFaults();break;case "authority":authority();break;case "factory-retirement":factoryRetirement();break;case "ui":ui();break;case "stale-ui":staleUI();break;case "cancel-commit":cancelCommit();break;}
   System.out.println("Android execution fifty case passed: "+family);
  }
  System.out.println("Android execution fifty: "+checks+" checks; native/OS boundaries explicit");
 }
}'''

NAMES = ('AndroidHomeStateStore','AndroidConnectionSelection','AndroidNodeChainExecutionCapture','AndroidNodeChainSession','AndroidNodeChainMTUPlatform','AndroidNodeChainRuntime','LayeredVpnService','AndroidOrderedLatencyStore','AndroidOrderedExecutionLatencyCapture','AndroidOrderedExecutionLatencyStore','AndroidOrderedLatencySourceTransaction','AndroidOrderedLatencyBenchmark','AndroidOrderedLatencyDialog','AndroidMTUMeasurementGate')
CONTROLS = (
 ('AndroidNodeChainSession','execution.plan,server,measurement','execution.plan,server,new io.nekohasekai.libbox.RouterHopMeasurement()','success','complete execution benchmark not adopted'),
 ('AndroidOrderedLatencyBenchmark','job.owner.drain();break;','break;','success','complete execution benchmark not adopted'),
 ('AndroidOrderedLatencyBenchmark','job.owner.close();break;','break;','success','complete execution benchmark not adopted'),
 ('LayeredVpnService','facade.validateClosedCapture(request,executionCapture.raw);','/* broken: joined cleanup treated as current proof */','authority','stale native closed proof adopted: epoch'),
 ('LayeredVpnService','facade.validateClosedCapture(request,executionCapture.raw);','facade.validateClosedCapture("f".repeat(32),executionCapture.raw);','success','complete execution benchmark not adopted'),
 ('LayeredVpnService','facade.validateClosedCapture(request,executionCapture.raw);','synchronized(AndroidHomeStateStore.class){facade.validateClosedCapture(request,executionCapture.raw);}','authority','exact request or unlocked closed proof was lost'),
 ('AndroidOrderedExecutionLatencyCapture','||!generation.equals(record.generation)','||false','capture-faults','invalid execution capture or receipt adopted: receipt-generation'),
 ('AndroidOrderedLatencyBenchmark','active=job;','job.owner=LayeredVpnService.captureOrderedLatency(job.id,target);active=job;','quiesce','MTU did not drain before facade capture'),
 ('LayeredVpnService','if(mtuObservation!=null&&!mtuObservation.equals(original.mtu==null?Long.valueOf(0L):original.mtu.proofObservationToken()))','if(false)','faults','failed/stale/cancelled run adopted: mtu'),
 ('LayeredVpnService','if(nodeChainSession!=null)try{nodeChainSession.closeOrderedLatency();}','if(false)try{nodeChainSession.closeOrderedLatency();}','retirement','retirement discarded facade before original join'),
 ('AndroidOrderedLatencyDialog','try{owner.requireDelivery();output.setText','try{output.setText','stale-ui','queued stale progress borrowed current UI'),
 ('AndroidOrderedLatencyBenchmark',
  'final Job job=active;if(job==null)return;job.cancelled=true;',
  'final Job job;synchronized(this){job=active;if(job==null)return;job.cancelled=true;}',
  'cancel-commit','Cancel waited for the held native history proof'),
 ('AndroidOrderedLatencyBenchmark',
  'if(owner!=null)owner.cancel();',
  'if(owner!=null)owner.cancel();Job replacement=active;if(replacement!=null&&replacement!=job&&replacement.owner!=null)replacement.owner.cancel();',
  'cancel-commit','late original Cancel borrowed the replacement job'),
)


def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):
        raise RuntimeError('JDK and actual Android JSON library required')
    with tempfile.TemporaryDirectory(prefix='routervpn-execution-fifty-') as directory:
        work=Path(directory);src=work/'src';classes=work/'classes'
        for path,text in sources().items():
            target=src/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
        originals={name:(JAVA/(name+'.java')).read_text() for name in NAMES}
        for name,text in originals.items():(src/APP/(name+'.java')).write_text(text)
        (src/APP/'ExecutionFiftyTest.java').write_text(HARNESS)
        subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(classes),*map(str,src.rglob('*.java'))],check=True,timeout=60)
        cp=os.pathsep.join((str(classes),str(jar)))
        subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.ExecutionFiftyTest'],check=True,timeout=120)
        for index,(name,before,after,family,witness) in enumerate(CONTROLS):
            changed=replace_once(originals[name],before,after);target=work/f'mutant-{index}'/(name+'.java');target.parent.mkdir();target.write_text(changed)
            output=work/f'negative-{index}';shutil.copytree(classes,output);classpath=os.pathsep.join((str(output),str(jar)))
            subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',classpath,'-d',str(output),str(target)],check=True,timeout=60)
            result=subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.ExecutionFiftyTest',family],capture_output=True,text=True,timeout=60)
            if result.returncode==0 or witness not in result.stderr:
                raise AssertionError(f'Execution fifty causal control missed {index}/{family}/{witness}\n{result.stdout}\n{result.stderr}')
            print(f'Execution fifty causal control rejected: {index}/{family}')
        print('Android execution fifty eleven families and thirteen causal controls passed')


if __name__=='__main__':
    main()
