#!/usr/bin/env python3
"""Execute the complete Android ordered execution host with native boundaries.

Session, Runtime, execution capture, Home and the full LayeredVpnService are
shipping sources. Native preparation/proof, Android TUN and sockets are explicit
controlled doubles. Pure original-source compilation is exercised separately;
these checks do not claim native encrypted Server/Compare or device acceptance.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

import test_android_node_chain_runtime as LOCAL

ROOT, JAVA, APP, NATIVE = LOCAL.ROOT, LOCAL.JAVA, LOCAL.APP, LOCAL.NATIVE


EXECUTION = r'''package io.nekohasekai.libbox;
import org.json.*;import java.nio.charset.StandardCharsets;import java.security.*;import java.util.concurrent.*;
public final class RouterNodeChainExecution {
 public static java.util.function.Consumer<RouterNodeChainExecution> configured;public static volatile RouterNodeChainExecution latest;
 public final String localLaunch,requested,source,config,sourceSHA,configSHA,localSHA,launch;
 public CommandServer server;public volatile boolean valid=true,cancelled,closed,cleanupToken,paused,nativeReceipt=true;public volatile String selected;
 public int runs,closes,failCloses,binds,failBindBefore,failBindAfter;public Runnable afterRun,duringClose;public CountDownLatch entered,release;
 public RouterNodeChainExecutionRestoreCapture restore;
 RouterNodeChainExecution(String input,String requested)throws Exception{
  localLaunch=input;this.requested=requested;JSONObject original=new JSONObject(input);localSHA=original.getString("source_sha256");
  JSONObject local=new JSONObject().put("schema",1).put("execution","local").put("nodes",original.getJSONArray("nodes")).put("identity_sources",original.getJSONArray("identity_sources"));
  source=new JSONObject().put("schema",1).put("execution",requested).put("local_source",local.toString()).toString();
  config=new JSONObject().put("inbounds",new JSONArray().put(new JSONObject().put("type","tun").put("tag","routervpn-chain-tun")))
   .put("route",new JSONObject().put("final","routervpn-chain-application")).put("original_source",digest(source)).toString();
  sourceSHA=digest(source);configSHA=digest(config);
  launch=new JSONObject().put("kind","routervpn-node-chain-execution-preparation-input").put("schema",1).put("source",source).put("source_sha256",sourceSHA).put("config_sha256",configSHA).toString();
  selected="server";latest=this;if(configured!=null)configured.accept(this);
 }
 public static String digest(String value)throws Exception{StringBuilder out=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)))out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();}
 public String source(){return source;}public String config(){return config;}public String launchInput(){return launch;}public String sourceSHA256(){return sourceSHA;}public String configSHA256(){return configSHA;}public String localSourceSHA256(){return localSHA;}public String requestedExecution(){return requested;}
 public void bindNative(CommandServer captured){binds++;if(failBindBefore-->0)throw new IllegalStateException("controlled deadline before construction reservation");if(captured==null||captured.closed||server!=null)throw new IllegalStateException("foreign or repeated native construction");server=captured;if(failBindAfter-->0)throw new IllegalStateException("controlled late binding failure after reservation");if(closed||cancelled)throw new IllegalStateException("original deny-only construction retained");}
 public void run(CommandServer captured)throws Exception{
  if(runs++!=0||closed||cancelled||captured==null||captured!=server||captured.closed)throw new IllegalStateException("foreign or repeated native execution");
  if(entered!=null)entered.countDown();if(release!=null&&!release.await(3,TimeUnit.SECONDS))throw new IllegalStateException("controlled execution proof did not drain");
  if(afterRun!=null)afterRun.run();if(!healthy())throw new IllegalStateException("original complete execution proof failed");
 }
 public boolean healthy(){return runs==1&&valid&&!cancelled&&!paused&&!closed&&server!=null&&!server.closed;}
 public String execution(){return healthy()?selected:"";}public String progressJSON(){return "{\"execution\":\""+execution()+"\",\"ready\":"+healthy()+",\"complete\":"+healthy()+"}";}
 public void networkChanged(){cancelled=true;if(release!=null)release.countDown();}
 public boolean retainsServerCleanup(CommandServer original){return cleanupToken&&(cancelled||paused)&&!closed&&server==original&&original!=null&&!original.closed;}
 public boolean nativeClosed(){return closed&&server!=null&&(server.closed||runs==0)&&nativeReceipt;}
 public void close()throws Exception{
  closes++;cancelled=true;if(closed)return;if(server==null){closed=true;return;}
  if(server.closed)throw new IllegalStateException("execution lost lower Box before lease drain");cleanupToken=true;
  try{server.platform.autoDetectInterfaceControl(10);if(duringClose!=null)duringClose.run();if(failCloses-->0)throw new IllegalStateException("controlled original lease drain pending");closed=true;}
  finally{cleanupToken=false;}
 }
 public RouterNodeChainExecutionRestoreCapture captureRestore(){if(!healthy())throw new IllegalStateException("no original execution proof");return new RouterNodeChainExecutionRestoreCapture(this,selected);}
 public void requireRestore(RouterNodeChainExecutionRestoreCapture capture){if(capture==null||restore!=capture||capture.original==this||!capture.original.nativeClosed())throw new IllegalStateException("foreign or unjoined native restore capsule");}
}
'''

CAPTURE = r'''package com.eabusham.routervpn;
import org.json.*;import io.nekohasekai.libbox.*;
final class AndroidNodeChainCapture {
 static final int MAX_INPUT=40*1024*1024;static final String SESSION_FILE="routervpn-node-chain.json";
 final AndroidNodeStore.ChainCapture source;final RouterNodeChain plan;final String config="{\"original\":\"local-pure-graph\"}",launchInput,sourceSHA256,configSHA256;final boolean strict;
 private AndroidNodeChainCapture(AndroidNodeStore.ChainCapture source)throws Exception{
  this.source=source;strict=source.strict;plan=new RouterNodeChain(source.members.size());sourceSHA256="a".repeat(64);configSHA256=RouterNodeChainExecution.digest(config);
  JSONArray nodes=new JSONArray(),identities=new JSONArray();for(int i=0;i<source.members.size();i++){nodes.put("original-node-"+source.members.get(i).id);identities.put("original-identity-"+source.members.get(i).id);}
  launchInput=new JSONObject().put("kind","routervpn-node-chain-launch-input").put("schema",1).put("execution","local").put("nodes",nodes).put("identity_sources",identities).put("source_sha256",sourceSHA256).put("config_sha256",configSHA256).toString();
 }
 static AndroidNodeChainCapture compile(AndroidNodeStore.ChainCapture source)throws Exception{source.requireCurrent();return new AndroidNodeChainCapture(source);}
 boolean ownsSource(AndroidNodeStore.ChainCapture original){return source==original;}
 void requireCurrent(){source.requireCurrent();}void close()throws Exception{plan.close();}
}
'''

HARNESS = r'''package com.eabusham.routervpn;
import io.nekohasekai.libbox.*;import java.nio.file.*;import java.lang.reflect.*;import java.util.concurrent.*;import java.util.*;
public final class OrderedExecutionRuntimeTest {
 static int checks;interface Action{void run()throws Exception;}static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
 static void reject(Action call,String message)throws Exception{try{call.run();}catch(Exception expected){checks++;return;}throw new AssertionError(message);}
 static Object get(Object owner,String name)throws Exception{Field field=owner.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(owner);}
 static void set(Object owner,String name,Object value)throws Exception{Field field=owner.getClass().getDeclaredField(name);field.setAccessible(true);field.set(owner,value);}
 static void await(java.util.function.BooleanSupplier done,String why)throws Exception{long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(4);while(!done.getAsBoolean()&&System.nanoTime()<end)Thread.sleep(5);check(done.getAsBoolean(),why);}
 static final class Result implements AndroidNodeChainRuntime.Callback {final CountDownLatch done=new CountDownLatch(1);volatile boolean ok;String message;public void progress(String ignored){}public void finished(boolean value,String text){ok=value;message=text;done.countDown();}void finished()throws Exception{check(done.await(5,TimeUnit.SECONDS),"execution callback did not join");}}
 static final class Fixture implements AutoCloseable {
  final LayeredVpnService service=new LayeredVpnService();final NativeSingBoxController nativeOwner;final AndroidNodeChainRuntime runtime;final AndroidNodeStore.ChainCapture source;final Path files;
  Fixture(int count,String requested)throws Exception{files=Files.createTempDirectory("ordered-execution-runtime-");service.files=files.toFile();service.onCreate();nativeOwner=new NativeSingBoxController(service);runtime=new AndroidNodeChainRuntime(service,nativeOwner);source=new AndroidNodeStore.ChainCapture(count);source.execution=requested;RouterNodeChain.configured=null;CommandServer.afterConstruction=null;android.net.VpnService.revoked=false;}
  AndroidNodeChainSession owner()throws Exception{return (AndroidNodeChainSession)get(runtime,"owner");}
  Result start(){Result result=new Result();runtime.connect(source,result);return result;}
  void connected()throws Exception{Result result=start();result.finished();check(result.ok,"execution did not connect: "+result.message);check(runtime.isConnected(),"execution had no retained complete proof");drain();}
  void drain()throws Exception{((ExecutorService)get(service,"executor")).submit(()->{}).get(5,TimeUnit.SECONDS);}
  void stop()throws Exception{check(runtime.stopAndProve(),"original execution cleanup did not join");drain();}
  public void close()throws Exception{
   RouterNodeChainExecution.configured=null;CommandServer.afterConstruction=null;AndroidNodeChainSession value=owner();if(value!=null){value.capture.plan.failCloses=0;if(value.execution!=null){value.execution.plan.failCloses=0;value.execution.plan.duringClose=null;value.execution.plan.nativeReceipt=true;}CommandServer core=(CommandServer)get(service,"commandServer");if(core!=null)core.failClose=false;runtime.stopAndProve();}
   ((ExecutorService)get(runtime,"executor")).shutdownNow();((ExecutorService)get(service,"executor")).shutdownNow();((ExecutorService)get(service,"nodeChainObservations")).shutdownNow();
   try(var all=Files.walk(files)){for(Path path:all.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}
  }
 }
 static void success()throws Exception{
  for(int count:new int[]{2,3,4,8})for(String variant:List.of("server/server","auto/server","auto/local"))try(Fixture f=new Fixture(count,variant.split("/")[0])){
   String chosen=variant.split("/")[1];RouterNodeChainExecution.configured=plan->plan.selected=chosen;int initial=CommandServer.created;f.connected();var original=f.owner();var plan=original.execution.plan;var server=(CommandServer)get(f.service,"commandServer");
   check(CommandServer.created==initial+1&&plan.server==server&&plan.runs==1&&original.capture.plan.runs==0,"execution used another Box, reran Local or substituted the final graph");
   check(Files.readString(original.directory.toPath().resolve("sing-box.json")).equals(original.execution.config)&&Files.readString(original.directory.toPath().resolve(AndroidNodeChainCapture.SESSION_FILE)).equals(original.execution.launchInput),"staged execution borrowed the dormant Local config or source");
   check(original.provedExecution().equals(chosen)&&f.runtime.activeSources()==f.source.members,"execution lost concrete winner or complete original members");
   check(Libbox.executionMTU==plan&&Libbox.executionMeasurement==plan&&Libbox.executionServer==server,"execution MTU or measurement dispatched through dormant Local plan");
   var capture=f.runtime.captureRestore();check(f.runtime.captureCurrent(capture),"proved execution restore capture was not current");
   reject(()->AndroidNodeChainExecutionCapture.restore(original.capture,original.execution.captureRestore()),"restore admitted before original cleanup");
   f.stop();check(plan.closed&&server.closed&&original.released(),"execution cleanup or original Box join was missing");
   check(!f.runtime.captureCurrent(capture)&&!f.runtime.restoredMatches(capture),"retired original counted as a restored execution");
   RouterNodeChainExecution.configured=next->next.selected=chosen.equals("server")?"local":"server";
   Result restored=new Result();f.runtime.restore(capture,AndroidHomeStateStore.snapshot(f.service),restored);restored.finished();f.drain();
   check(restored.ok&&f.runtime.restoredMatches(capture),"temporary restore reran Compare or lost its captured execution");
   var replacement=f.owner();check(replacement!=original&&replacement.source==original.source&&replacement.execution.plan!=plan&&replacement.execution.plan.restore!=null,"restore reconstructed authority instead of retaining original capture");
   check(replacement.provedExecution().equals(chosen)&&CommandServer.created==initial+2,"restore chose another execution or reused original Box");
   if(variant.startsWith("auto")){replacement.execution.plan.selected=chosen.equals("server")?"local":"server";check(!f.runtime.restoredMatches(capture),"restored match accepted another execution winner");replacement.execution.plan.selected=chosen;}
   f.stop();
  }
 }
 static void failure()throws Exception{
  for(String fault:List.of("proof","source","selection","config"))try(Fixture f=new Fixture(3,"auto")){
   RouterNodeChainExecution.configured=plan->{if(fault.equals("proof"))plan.valid=false;if(fault.equals("source"))plan.afterRun=()->f.source.valid=false;if(fault.equals("selection"))plan.afterRun=()->f.service.getSharedPreferences("router-vpn-unified",0).edit().putBoolean("multihop_on",false).apply();};
   if(fault.equals("config"))f.nativeOwner.beforeStart=()->{try{var owner=AndroidNodeChainSession.retained();Files.writeString(owner.directory.toPath().resolve("sing-box.json"),owner.capture.config);}catch(Exception e){throw new IllegalStateException(e);}};
   int before=CommandServer.created;Result result=f.start();result.finished();f.drain();check(!result.ok&&!f.runtime.isConnected()&&!AndroidHomeStateStore.snapshot(f.service).connected,"failed original execution reached Connected: "+fault);
   if(fault.equals("config"))check(CommandServer.created==before,"mixed Local file constructed an execution Box");
   check(!f.runtime.isActiveOrTransitioning(),"failed execution lost complete cleanup: "+fault);
  }
 }
 static void cleanup()throws Exception{
  try(Fixture f=new Fixture(3,"server")){
   f.connected();var owner=f.owner();var plan=owner.execution.plan;var server=(CommandServer)get(f.service,"commandServer");Object tun=get(f.service,"tunDescriptor");plan.failCloses=1;
   plan.duringClose=()->{try{
    check(owner.retainsServerCleanup(server),"cleanup token did not belong to original native server");check(!owner.retainsServerCleanup(new CommandServer(server.platform,null)),"foreign native server obtained cleanup socket authority");
    Object scope=get(f.service,"nodeChainCleanup");long deadline=(Long)get(scope,"deadline");set(scope,"deadline",0L);
    try{reject(()->f.service.autoDetectInterfaceControl(10),"expired execution cleanup scope opened a physical socket");}finally{set(scope,"deadline",deadline);}
    plan.cleanupToken=false;try{reject(()->f.service.autoDetectInterfaceControl(10),"Java scope bypassed the original native cleanup token");}finally{plan.cleanupToken=true;}
    Object network=get(f.service,"nodeChainPhysicalNetwork");set(f.service,"nodeChainPhysicalNetwork",new android.net.Network());
    try{reject(()->f.service.autoDetectInterfaceControl(10),"execution cleanup adopted a replacement physical Network");}finally{set(f.service,"nodeChainPhysicalNetwork",network);}
   }catch(Exception e){throw new IllegalStateException(e);}};
   Method stop=f.service.getClass().getDeclaredMethod("shutdown",String.class,String.class);stop.setAccessible(true);
   reject(()->stop.invoke(f.service,"DOWN",""),"failed execution cleanup was reported complete");
   check(!server.closed&&!plan.closed&&!owner.released()&&get(f.service,"commandServer")==server&&get(f.service,"tunDescriptor")==tun&&owner.directory.exists(),"failed Server cleanup destroyed original lower Box or TUN");
   check(get(f.service,"nodeChainCleanup")==null&&!owner.retainsServerCleanup(server),"cleanup permit escaped its exact native call");
   check(f.runtime.isActiveOrTransitioning(),"failed execution cleanup lost retained runtime owner");
   f.stop();check(plan.closes==2&&plan.closed&&server.closed&&owner.released(),"cleanup retry failed to join exact original execution");
  }
 }
 static void cancel()throws Exception{
  try(Fixture f=new Fixture(4,"auto")){
   CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);RouterNodeChainExecution.configured=plan->{plan.entered=entered;plan.release=release;};
   Result result=f.start();check(entered.await(3,TimeUnit.SECONDS),"native execution trial did not start");var original=f.owner();check(!AndroidHomeStateStore.snapshot(f.service).connected,"pending trial published Connected");
   f.runtime.disconnect();result.finished();f.drain();check(!result.ok&&original.execution.plan.closed&&original.released()&&!f.runtime.isConnected(),"late cancelled execution escaped original cleanup");
  }
 }
 static void mtuCleanup()throws Exception{
  try(Fixture f=new Fixture(3,"server")){
   f.connected();var owner=f.owner();var plan=owner.execution.plan;var server=(CommandServer)get(f.service,"commandServer");var mtu=(AndroidMTUSession)get(f.service,"mtuSession");Object[] capturedScope={null};int[] attempts={0};
   mtu.beforeClose=()->{plan.cleanupToken=true;try{
    f.service.autoDetectInterfaceControl(10);Object scope=get(f.service,"nodeChainCleanup");check(scope!=null&&scope!=capturedScope[0],"MTU cleanup reused an expired caller scope");capturedScope[0]=scope;
    long remaining=(Long)get(scope,"deadline")-System.nanoTime();check(remaining>0&&remaining<=5_000_000_000L,"MTU cleanup changed the original five-second native bound");
    if(attempts[0]++==0)throw new IllegalStateException("controlled MTU cleanup pending");set(scope,"deadline",0L);
   }finally{plan.cleanupToken=false;}};
   Method stop=f.service.getClass().getDeclaredMethod("shutdown",String.class,String.class);stop.setAccessible(true);reject(()->stop.invoke(f.service,"DOWN",""),"failed MTU cleanup released Server host");
   check(plan.closes==0&&!server.closed&&get(f.service,"mtuSession")==mtu&&get(f.service,"nodeChainCleanup")==null,"MTU failure retired execution or leaked its call scope");
   plan.duringClose=()->{try{check(get(f.service,"nodeChainCleanup")!=capturedScope[0],"execution Close reused MTU's expired call scope");}catch(Exception e){throw new IllegalStateException(e);}};
   f.stop();check(attempts[0]==2&&plan.closes==1&&server.closed&&owner.released(),"MTU retry did not precede original execution and Box joins");
  }
 }
 static void mtuPause()throws Exception{
  try(Fixture f=new Fixture(3,"server")){
   f.connected();var owner=f.owner();var plan=owner.execution.plan;var server=(CommandServer)get(f.service,"commandServer");var mtu=(AndroidMTUSession)get(f.service,"mtuSession");var platform=Libbox.executionPlatform;
   check(platform instanceof AndroidNodeChainMTUPlatform,"execution MTU lost its original asynchronous cleanup wrapper");
   check(platform.captureMTU()==mtu.captureMTU(),"MTU wrapper replaced original platform readback");
   platform.beginMTUChange(mtu.captureMTU());Object original=get(f.service,"nodeChainCleanup");
   check(original!=null&&get(original,"chain")==owner&&get(original,"server")==server,"MTU Begin omitted its original cleanup call");
   long deadline=(Long)get(original,"deadline");check(deadline>System.nanoTime()&&deadline-System.nanoTime()<=5_000_000_000L,"MTU Begin extended native cleanup deadline");
   reject(()->platform.beginMTUChange(mtu.captureMTU()),"MTU Begin replaced an outstanding original change");
   plan.paused=true;plan.cleanupToken=true;f.source.valid=false;
   try{
    check(owner.retainsServerCleanup(server),"active MTU pause lost exact native cleanup authority");f.service.autoDetectInterfaceControl(10);
    plan.cleanupToken=false;try{reject(()->f.service.autoDetectInterfaceControl(10),"active MTU Java scope bypassed native pause token");}finally{plan.cleanupToken=true;}
    set(original,"deadline",0L);try{reject(()->f.service.autoDetectInterfaceControl(10),"expired active MTU scope opened a physical socket");}finally{set(original,"deadline",deadline);}
    Object network=get(f.service,"nodeChainPhysicalNetwork");set(f.service,"nodeChainPhysicalNetwork",new android.net.Network());try{reject(()->f.service.autoDetectInterfaceControl(10),"active MTU scope changed original Network");}finally{set(f.service,"nodeChainPhysicalNetwork",network);}
   }finally{platform.endMTUChange();plan.paused=false;plan.cleanupToken=false;f.source.valid=true;}
   check(get(f.service,"nodeChainCleanup")==null&&!mtu.changing&&mtu.begins==1&&mtu.ends==1,"MTU End lost or retained another cleanup scope");
   reject(platform::endMTUChange,"MTU End borrowed another completed change");
   platform.bindMTUSocket(mtu.captureMTU(),10);check(mtu.bindings==1,"MTU wrapper bypassed original VPN socket binding");
   check(platform.compareAndSwapMTUCache("","exact")&&platform.readMTUCache().equals("exact")&&!platform.compareAndSwapMTUCache("","wrong"),"MTU wrapper replaced original cache authority");
   set(f.service,"explicitStop",true);try{reject(()->platform.beginMTUChange(mtu.captureMTU()),"retired host admitted another MTU cleanup call");}finally{set(f.service,"explicitStop",false);}
   check(!mtu.changing&&mtu.begins==2&&mtu.ends==2&&get(f.service,"nodeChainCleanup")==null,"refused cleanup callback leaked platform changing state");
   platform.beginMTUChange(mtu.captureMTU());mtu.failEnd=true;try{reject(platform::endMTUChange,"failed platform readback was swallowed");}finally{mtu.failEnd=false;}
   check(!mtu.changing&&get(f.service,"nodeChainCleanup")==null,"failed MTU End retained expired physical cleanup authority");
   var nativeOwner=(AndroidNodeChainSession.Owner)get(owner,"owner");
   reject(()->nativeOwner.beginMTUCleanup(owner,new CommandServer(server.platform,null),mtu),"foreign server borrowed MTU cleanup");
   reject(()->nativeOwner.beginMTUCleanup(owner,server,new RouterMTUPlatform(){}),"foreign MTU platform borrowed cleanup");
   check(get(f.service,"nodeChainCleanup")==null,"refused foreign MTU callback changed cleanup owner");
   f.stop();
  }
 }
 static void mtuPauseClose()throws Exception{
  try(Fixture f=new Fixture(3,"server")){
   f.connected();var owner=f.owner();var plan=owner.execution.plan;var mtu=(AndroidMTUSession)get(f.service,"mtuSession");var platform=Libbox.executionPlatform;
   platform.beginMTUChange(mtu.captureMTU());Object original=get(f.service,"nodeChainCleanup");
   mtu.beforeClose=()->{plan.cleanupToken=true;try{
    Object later=get(f.service,"nodeChainCleanup");check(later!=original&&get(later,"previous")==original,"Close lost original outstanding MTU cleanup call");
    set(original,"deadline",0L);
    reject(()->f.service.autoDetectInterfaceControl(10),"later Close extended an outstanding MTU deadline");
    platform.endMTUChange();
    check(get(f.service,"nodeChainCleanup")==later,"late MTU End cleared another Close cleanup scope");
    f.service.autoDetectInterfaceControl(10);
   }finally{plan.cleanupToken=false;}};
   f.stop();check(owner.released()&&mtu.ends==1&&get(f.service,"nodeChainCleanup")==null,"Close did not join original MTU End and native cleanup");
  }
 }
 static void nativeReceipt()throws Exception{
  try(Fixture f=new Fixture(3,"server")){
   f.connected();var owner=f.owner();var plan=owner.execution.plan;var server=(CommandServer)get(f.service,"commandServer");Object tun=get(f.service,"tunDescriptor");plan.nativeReceipt=false;
   Method stop=f.service.getClass().getDeclaredMethod("shutdown",String.class,String.class);stop.setAccessible(true);
   reject(()->stop.invoke(f.service,"DOWN",""),"missing original Box receipt was accepted as native cleanup");
   check(plan.closed&&server.closed&&!owner.released()&&get(f.service,"commandServer")==server&&get(f.service,"tunDescriptor")==tun&&owner.directory.exists(),"missing Box receipt discarded original cleanup owner");
   check(f.runtime.isActiveOrTransitioning(),"missing Box receipt lost pending original session");
   plan.nativeReceipt=true;f.stop();check(owner.released(),"original positive Box receipt did not finish retained cleanup");
  }
 }
 static void bindFailure()throws Exception{
  for(String fault:List.of("before","after"))try(Fixture f=new Fixture(3,"server")){
   AndroidNodeChainSession[] original={null};int started=CommandServer.started;
   RouterNodeChainExecution.configured=plan->{if(fault.equals("before"))plan.failBindBefore=1;else plan.failBindAfter=1;};
   CommandServer.afterConstruction=()->original[0]=AndroidNodeChainSession.retained();
   Result result=f.start();await(()->original[0]!=null&&original[0].released()&&!f.runtime.isActiveOrTransitioning(),"failed Bind did not acquire original deny-only cleanup receipt: "+fault);result.finished();f.drain();var plan=RouterNodeChainExecution.latest;
   check(!result.ok&&CommandServer.started==started&&plan.runs==0,"failed Bind started original native service: "+fault);
   check(plan.binds==2&&plan.server!=null&&plan.server.closed&&plan.nativeClosed()&&original[0].released(),"failed Bind retry replaced or lost original reserved construction: "+fault);
  }
 }
 static void bindPending()throws Exception{
  try(Fixture f=new Fixture(3,"server")){
   AndroidNodeChainSession[] original={null};int started=CommandServer.started;RouterNodeChainExecution.configured=plan->plan.failBindBefore=1000;CommandServer.afterConstruction=()->original[0]=AndroidNodeChainSession.retained();
   f.start();f.drain();await(()->original[0]!=null&&original[0].execution!=null&&RouterNodeChainExecution.latest==original[0].execution.plan&&original[0].execution.plan.binds>=2,"failed Bind never attempted original cleanup reservation");f.drain();var plan=RouterNodeChainExecution.latest;var server=(CommandServer)get(f.service,"commandServer");
   check(original[0]!=null&&server!=null&&!server.closed&&!original[0].released()&&f.runtime.isActiveOrTransitioning()&&original[0].directory.exists(),"failed reservation destroyed original unstarted server before positive receipt");
   check(CommandServer.started==started&&plan.server==null&&!plan.nativeClosed(),"failed reservation fabricated native startup or empty receipt");
   plan.failBindBefore=0;f.stop();check(plan.server==server&&server.closed&&plan.nativeClosed()&&original[0].released(),"reservation retry failed to seal the same original server");
  }
 }
 static void constructorFailure()throws Exception{
  try(Fixture f=new Fixture(3,"server")){
   AndroidNodeChainSession[] original={null};int started=CommandServer.started;
   CommandServer.afterConstruction=()->{original[0]=AndroidNodeChainSession.retained();throw new IllegalStateException("controlled CommandServer constructor failed before native Bind");};
   Result result=f.start();await(()->original[0]!=null&&original[0].released()&&!f.runtime.isActiveOrTransitioning(),"unbound constructor failure retained its original preparation indefinitely");result.finished();f.drain();var plan=RouterNodeChainExecution.latest;
   check(!result.ok&&CommandServer.started==started&&plan.runs==0&&plan.server==null,"failed server construction reached native startup or Bind");
   check(original[0]!=null&&original[0].released()&&plan.closed&&!f.runtime.isActiveOrTransitioning(),"unbound constructor failure retained its original preparation indefinitely");
   check(!plan.nativeClosed(),"unbound cleanup fabricated an Instance close receipt");
  }
 }
 static void beforeBind()throws Exception{
  for(String fault:List.of("cancel","source","closed"))try(Fixture f=new Fixture(3,"server")){
   int started=CommandServer.started;
   CommandServer.afterConstruction=()->{var source=AndroidNodeChainSession.retained();if(fault.equals("source"))f.source.valid=false;else if(fault.equals("cancel"))source.cancel();else try{source.closePlan();}catch(Exception invalid){throw new IllegalStateException(invalid);}};
   Result result=f.start();result.finished();f.drain();var plan=RouterNodeChainExecution.latest;
   check(!result.ok&&CommandServer.started==started&&plan.runs==0,"retired source started native construction after binding: "+fault);
   check(plan.server!=null&&plan.closed&&plan.server.closed&&plan.nativeClosed()&&!f.runtime.isActiveOrTransitioning(),"before-bind failure lost original sealed construction receipt: "+fault);
  }
 }
 public static void main(String[] args)throws Exception{String family=args.length==0?"all":args[0];if(family.equals("all")||family.equals("success"))success();if(family.equals("all")||family.equals("failure"))failure();if(family.equals("all")||family.equals("cleanup"))cleanup();if(family.equals("all")||family.equals("cancel"))cancel();if(family.equals("all")||family.equals("mtu-cleanup"))mtuCleanup();if(family.equals("all")||family.equals("mtu-pause"))mtuPause();if(family.equals("all")||family.equals("mtu-pause-close"))mtuPauseClose();if(family.equals("all")||family.equals("native-receipt"))nativeReceipt();if(family.equals("all")||family.equals("bind-failure"))bindFailure();if(family.equals("all")||family.equals("bind-pending"))bindPending();if(family.equals("all")||family.equals("constructor"))constructorFailure();if(family.equals("all")||family.equals("before-bind"))beforeBind();System.out.println("Android ordered execution host: "+checks+" actual shipping Java checks PASS; native/OS boundaries doubled");}
}
'''


def sources():
    result = dict(LOCAL.SOURCES)
    result.pop(APP + 'AndroidNodeChainExecutionCapture.java')
    result[APP + 'AndroidNodeStore.java'] = result[APP + 'AndroidNodeStore.java'].replace('final String execution="local";', 'String execution="local";')
    result[APP + 'AndroidNodeChainCapture.java'] = CAPTURE
    result[NATIVE + 'RouterNodeChainExecution.java'] = EXECUTION
    result[NATIVE + 'CommandServer.java'] = result[NATIVE + 'CommandServer.java'].replace('public static int created;', 'public static int created,started;public static Runnable afterConstruction;').replace('platform=p;created++;', 'platform=p;created++;if(afterConstruction!=null)afterConstruction.run();').replace('public void start(){}', 'public void start(){started++;}')
    result[APP + 'AndroidMTUSession.java'] = result[APP + 'AndroidMTUSession.java'].replace('public void close()throws Exception{}', 'interface Closing{void run()throws Exception;}Closing beforeClose;boolean joined;public void close()throws Exception{if(joined)return;if(beforeClose!=null)beforeClose.run();joined=true;}')
    mtu = result[APP + 'AndroidMTUSession.java']
    result[APP + 'AndroidMTUSession.java'] = mtu[:-1] + r'''
 public boolean changing,failEnd;public int begins,ends,bindings;public String cache="";
 private final io.nekohasekai.libbox.RouterMTUState state=state();
 private static io.nekohasekai.libbox.RouterMTUState state(){var s=new io.nekohasekai.libbox.RouterMTUState();s.setSession("original-mtu-session");s.setPath("original-mtu-path");s.setInterface("tun0");s.setMTU(1400);return s;}
 public io.nekohasekai.libbox.RouterMTUState captureMTU(){return state;}
 public synchronized void beginMTUChange(io.nekohasekai.libbox.RouterMTUState expected){if(changing||expected!=state)throw new IllegalStateException("stale controlled MTU");changing=true;begins++;}
 public synchronized void endMTUChange(){changing=false;ends++;if(failEnd)throw new IllegalStateException("controlled MTU readback failed");}
 public void bindMTUSocket(io.nekohasekai.libbox.RouterMTUState expected,long fd){if(expected!=state||fd<0)throw new IllegalStateException("foreign controlled MTU socket");bindings++;}
 public String readMTUCache(){return cache;}public boolean compareAndSwapMTUCache(String before,String after){if(!before.equals(cache))return false;cache=after;return true;}public void abortMTU(String reason){current=false;}
}'''
    result[NATIVE + 'RouterNodeChainExecutionRestoreCapture.java'] = '''package io.nekohasekai.libbox;public final class RouterNodeChainExecutionRestoreCapture {final RouterNodeChainExecution original;final String selected;RouterNodeChainExecutionRestoreCapture(RouterNodeChainExecution original,String selected){this.original=original;this.selected=selected;}}'''
    lib = result[NATIVE + 'Libbox.java']
    result[NATIVE + 'Libbox.java'] = lib[:-1] + r'''
 public static void routerValidatePrivateNodeJSON(String value)throws Exception{new org.json.JSONObject(value);}
 public static RouterNodeChainExecution routerNodeChainExecutionFromLaunch(String launch,String requested)throws Exception{return new RouterNodeChainExecution(launch,requested);}
 public static RouterNodeChainExecution newRouterNodeChainExecutionLaunch(String launch){throw new AssertionError("Host cannot reconstruct process authority from a private file");}
 public static RouterNodeChainExecution newRouterNodeChainExecutionRestore(RouterNodeChainExecutionRestoreCapture capture)throws Exception{
  if(capture==null||!capture.original.closed||capture.original.server==null||!capture.original.server.closed)throw new IllegalStateException("original Box and remote cleanup not joined");
  RouterNodeChainExecution result=new RouterNodeChainExecution(capture.original.localLaunch,capture.original.requested);result.restore=capture;result.selected=capture.selected;return result;}
 public static RouterNodeChainExecution executionMTU,executionMeasurement;public static CommandServer executionServer;public static RouterMTUPlatform executionPlatform;
 public static RouterMTU routerNodeChainExecutionNewMTU(RouterNodeChainExecution owner,CommandServer server,RouterMTUPlatform platform){if(!owner.healthy()||owner.server!=server)throw new IllegalStateException("foreign execution MTU");executionMTU=owner;executionServer=server;executionPlatform=platform;return new RouterMTU();}
 public static RouterHopMeasurement routerNodeChainExecutionNewHopMeasurement(RouterNodeChainExecution owner,CommandServer server){if(!owner.healthy()||owner.server!=server)throw new IllegalStateException("foreign execution measurement");executionMeasurement=owner;executionServer=server;return new RouterHopMeasurement();}
}'''
    return result


def main():
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if not jar.is_file() or not shutil.which('javac'):
        raise RuntimeError('JDK and actual Android JSON library required')
    with tempfile.TemporaryDirectory(prefix='routervpn-ordered-execution-host-') as directory:
        work = Path(directory)
        src = work / 'src'
        for path, text in sources().items():
            target = src / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        app = src / APP
        names = ('AndroidHomeStateStore', 'AndroidConnectionSelection', 'AndroidNodeChainExecutionCapture', 'AndroidNodeChainSession', 'AndroidNodeChainMTUPlatform', 'AndroidNodeChainRuntime', 'LayeredVpnService')
        originals = {}
        for name in names:
            originals[name] = (JAVA / (name + '.java')).read_text()
            (app / (name + '.java')).write_text(originals[name])
        (app / 'OrderedExecutionRuntimeTest.java').write_text(HARNESS)
        classes = work / 'classes'
        subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', str(jar), '-d', str(classes), *map(str, src.rglob('*.java'))], check=True, timeout=60)
        cp = os.pathsep.join((str(classes), str(jar)))
        subprocess.run(['java', '-cp', cp, 'com.eabusham.routervpn.OrderedExecutionRuntimeTest'], check=True, timeout=120)
        controls = (
            ('AndroidNodeChainSession', 'if (execution == null) capture.plan.run(server); else execution.run(server);', 'capture.plan.run(server);', 'success', 'execution did not connect'),
            ('AndroidNodeChainRuntime', 'false, capture.execution, callback);', 'false, null, callback);', 'success', 'temporary restore reran Compare or lost its captured execution'),
            ('LayeredVpnService', 'throw new IllegalStateException("The original ordered Server execution has not acknowledged cleanup.", pending);', '', 'cleanup', 'failed Server cleanup destroyed original lower Box or TUN'),
            ('LayeredVpnService', 'NodeChainCleanup cleanup = beginNodeChainCleanup(chain, capturedServer);', 'NodeChainCleanup cleanup = new NodeChainCleanup(chain, capturedServer, nodeChainPhysicalNetwork, executionNetwork);', 'cleanup', 'original execution cleanup did not join'),
            ('LayeredVpnService', 'System.nanoTime() < cleanup.deadline', 'true', 'cleanup', 'expired execution cleanup scope opened a physical socket'),
            ('LayeredVpnService', 'chain.retainsServerCleanup(cleanup.server)', 'true', 'cleanup', 'Java scope bypassed the original native cleanup token'),
            ('LayeredVpnService', 'NodeChainCleanup mtuCleanup = beginNodeChainCleanup(chain, capturedServer);', 'NodeChainCleanup mtuCleanup = new NodeChainCleanup(chain, capturedServer, nodeChainPhysicalNetwork, executionNetwork);', 'mtu-cleanup', 'original execution cleanup did not join'),
            ('AndroidNodeChainExecutionCapture', '&& captured.execution.equals(execution()) && healthy();', '&& healthy();', 'success', 'restored match accepted another execution winner'),
            ('AndroidNodeChainMTUPlatform', 'cleanup = owner.beginMTUCleanup(session, server, platform);', 'cleanup = () -> {};', 'mtu-pause', 'MTU Begin omitted its original cleanup call'),
            ('LayeredVpnService', 'if (!item.closed) original = item;', 'if (!item.closed && original == null) original = item;', 'mtu-pause-close', 'later Close extended an outstanding MTU deadline'),
            ('LayeredVpnService', 'while (nodeChainCleanup != null && nodeChainCleanup.closed) nodeChainCleanup = nodeChainCleanup.previous;', 'nodeChainCleanup = null;', 'mtu-pause-close', 'late MTU End cleared another Close cleanup scope'),
            ('AndroidNodeChainSession', 'execution != null && (server == null ? owner != null || !proofClosed : !execution.nativeClosed())', 'false', 'native-receipt', 'missing original Box receipt was accepted as native cleanup'),
            ('AndroidNodeChainSession', 'try { execution.bindNative(server); } catch (Exception admissionRefused)', 'try { if (false) execution.bindNative(server); } catch (Exception admissionRefused)', 'bind-failure', 'failed Bind did not acquire original deny-only cleanup receipt: before'),
            ('LayeredVpnService', 'chain.closePlan(); chain.requireNativeBindingDrain();', 'chain.closePlan();', 'bind-pending', 'failed reservation destroyed original unstarted server before positive receipt'),
            ('AndroidNodeChainSession', 'server == null ? owner != null || !proofClosed : !execution.nativeClosed()', '!execution.nativeClosed()', 'constructor', 'unbound constructor failure retained its original preparation indefinitely'),
            ('AndroidNodeChainSession', 'execution.bindNative(original);\n        nativeBound = true;\n        requireSource();', 'execution.bindNative(original);\n        nativeBound = true;', 'before-bind', 'retired source started native construction after binding'),
        )
        for number, (name, old, new, family, witness) in enumerate(controls):
            original = originals[name]
            if original.count(old) != 1:
                raise AssertionError('Execution causal control lost source seam: ' + name + '/' + old)
            source = work / ('mutation-' + str(number)) / (name + '.java')
            source.parent.mkdir()
            source.write_text(original.replace(old, new))
            out = work / ('negative-' + str(number))
            shutil.copytree(classes, out)
            cp = os.pathsep.join((str(out), str(jar)))
            subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', cp, '-d', str(out), str(source)], check=True, timeout=60)
            result = subprocess.run(['java', '-cp', cp, 'com.eabusham.routervpn.OrderedExecutionRuntimeTest', family], text=True, capture_output=True, timeout=120)
            if result.returncode == 0 or witness not in result.stderr:
                raise AssertionError('Execution causal control missed exact witness: ' + family + '\n' + result.stdout + result.stderr)
            print('Android execution host causal control rejected: ' + name + '/' + family, flush=True)


if __name__ == '__main__':
    main()
