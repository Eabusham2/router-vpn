#!/usr/bin/env python3
"""Execute shipping Android mode selection with real catalog and JSON inputs.

The unmodified orchestrator, selected-profile parser and kill-switch policy run
on the JVM. Android services, graph compilers and path probes are deterministic
boundaries; this verifies strategy/lifecycle behavior, not device VPN traffic.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT/'android/app/src/main/java/com/eabusham/routervpn'

SOURCES = {
    'android/content/Context.java': '''package android.content;
public final class Context {public Context getApplicationContext(){return this;}}''',
    'com/wireguard/android/backend/Tunnel.java': '''package com.wireguard.android.backend;
public interface Tunnel {enum State {DOWN,UP}}''',
    'org/amnezia/awg/backend/Tunnel.java': '''package org.amnezia.awg.backend;
public interface Tunnel {enum State {DOWN,UP}}''',
    'com/eabusham/routervpn/StrategyBoundaries.java': r'''package com.eabusham.routervpn;
import android.content.Context;
import org.json.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CancellationException;

final class Step {
 final String fault; boolean proof=true, failStop; Runnable prepared, proved;
 Step(String fault){this.fault=fault;}
}
final class Engine {
 final String kind; String state="DOWN",mode=""; Step step;
 Engine(String kind){this.kind=kind;}
 Step prepare(File bundle,String id)throws Exception {
  Env.attempts.add(kind+":"+id);Env.events.add("prepare:"+id);
  Deque<Step> values=Env.steps.get(id);Step next=values==null||values.isEmpty()?new Step(""):values.removeFirst();
  if(next.prepared!=null)next.prepared.run();
  switch(next.fault){
   case"prepare":throw new IOException("injected preparation failure");
   case"interrupt":throw new InterruptedException("injected cancellation");
   case"cancel":throw new CancellationException("injected cancellation");
   case"permission":throw new SecurityException("injected revocation");
  }
  return next;
 }
 void start(String id,Step next){
  mode=id;step=next;Env.current=this;state="UP";Env.events.add("start:"+id);Env.starts++;
  // LayeredVpnService.shutdown closes the core/TUN before publishing FAILED.
  if("failed".equals(next.fault)){Env.events.add("terminal:"+id);state="FAILED";}
  if("revoked".equals(next.fault))state="REVOKED";
  if("start".equals(next.fault))throw new IllegalStateException("injected partial start failure");
 }
 void stop(){
  Env.events.add("stop:"+mode);
  if(step!=null&&step.failStop)throw new IllegalStateException("injected unconfirmed teardown");
  state="DOWN";
 }
}
final class Env {
 static final List<String> attempts=new ArrayList<>(),events=new ArrayList<>();
 static final Map<String,Deque<Step>> steps=new HashMap<>();
 static Engine current;static int starts,adoptions,mtuStarts;static boolean preserved;
 static void reset(){attempts.clear();events.clear();steps.clear();current=null;starts=0;adoptions=0;mtuStarts=0;preserved=false;AndroidHomeStateStore.reset();}
 static void plan(String id,Step... values){steps.put(id,new ArrayDeque<>(Arrays.asList(values)));}
}
final class NativeSingBoxController {
 final Engine engine=new Engine("libbox");
 static final class ModeInfo {final String id,name;ModeInfo(String id){this.id=id;name=id;}}
 static final class SessionInfo {final String id;final Step step;SessionInfo(String id,Step step){this.id=id;this.step=step;}}
 List<ModeInfo> listDirectLibboxModes(File bundle)throws Exception {
  JSONArray modes=new JSONObject(Files.readString(bundle.toPath())).getJSONArray("modes");List<ModeInfo> out=new ArrayList<>();
  for(int i=0;i<modes.length();i++)out.add(new ModeInfo(modes.getJSONObject(i).getString("id")));return out;
 }
 SessionInfo prepareSession(File bundle,String id)throws Exception{return new SessionInfo(id,engine.prepare(bundle,id));}
 void start(SessionInfo session){engine.start(session.id,session.step);}
 void stop(){engine.stop();}String getState(){return engine.state;}
}
final class NativeXrayController {
 final Engine engine=new Engine("xray");
 static final class ModeInfo {String id;}
 static final class SessionInfo {final String id;final Step step;SessionInfo(String id,Step step){this.id=id;this.step=step;}}
 List<ModeInfo> listDirectXrayModes(File file){return Collections.emptyList();}
 SessionInfo prepareSession(File file,String id)throws Exception{return new SessionInfo(id,engine.prepare(file,id));}
 void start(SessionInfo session){engine.start(session.id,session.step);}
 void stop(){engine.stop();}String getState(){return engine.state;}
}
final class NativeWireGuardController {
 final Engine engine=new Engine("raw-wg");
 interface Callback {void finished(com.wireguard.android.backend.Tunnel.State state,String message,Throwable error);}
 com.wireguard.android.backend.Tunnel.State getState(){return"UP".equals(engine.state)?com.wireguard.android.backend.Tunnel.State.UP:com.wireguard.android.backend.Tunnel.State.DOWN;}
 void connectManaged(File file,Callback callback){try{engine.start("wg",engine.prepare(file,"wg"));callback.finished(getState(),"",null);}catch(Exception error){callback.finished(getState(),"",error);}}
 void disconnectManaged(Callback callback){engine.stop();callback.finished(getState(),"",null);}
}
final class NativeAmneziaWGController {
 final Engine engine=new Engine("raw-awg");
 interface Callback {void finished(org.amnezia.awg.backend.Tunnel.State state,String message,Throwable error);}
 static boolean supportedRawProfile(String id){return"awg2-fast".equals(id)||"awg2-strong".equals(id);}
 org.amnezia.awg.backend.Tunnel.State getState(){return"UP".equals(engine.state)?org.amnezia.awg.backend.Tunnel.State.UP:org.amnezia.awg.backend.Tunnel.State.DOWN;}
 void connectManaged(File file,String id,Callback callback){try{engine.start(id,engine.prepare(file,id));callback.finished(getState(),"",null);}catch(Exception error){callback.finished(getState(),"",error);}}
 void disconnectManaged(Callback callback){engine.stop();callback.finished(getState(),"",null);}
}
final class AndroidNativeProfilePolicy {
 static boolean requiresLibbox(JSONObject root){return AndroidProfileSelection.selectedRouterProfile(root).optBoolean("force_libbox",true);}
}
final class AndroidStartLayer {
 static final String OFF="off";
 static String selectedMode(JSONObject root){return AndroidProfileSelection.selectedRouterProfile(root).optString("start_layer",OFF);}
 static String nativeCapabilityReason(JSONObject root,String id){return"unsupported".equals(selectedMode(root))?"unavailable start layer":"";}
 static boolean nativeXray(String id){return id.startsWith("reality-")||id.equals("split")||id.equals("max");}
 static boolean supportsRawMode(String id){return true;}
}
final class AndroidPathProbe {
 static boolean prove(File file,int timeout)throws Exception {
  Engine engine=Env.current;if(engine==null)throw new AssertionError("proof without a started transport");
  Env.events.add("proof:"+engine.mode);Step step=engine.step;
  if(step.proved!=null)step.proved.run();
  if("proof-interrupt".equals(step.fault))throw new InterruptedException("injected proof cancellation");
  if("proof-error".equals(step.fault))throw new IOException("injected failed proof request");
  return step.proof;
 }
}
final class LayeredVpnService {
 static void startAutomaticMTU(){if(!AndroidHomeStateStore.current.connected)throw new AssertionError("MTU before adoption");Env.mtuStarts++;}
}
final class AndroidHomeStateStore {
 static final class Snapshot {String sessionId="",phase="off",activeNodeId="",runtimeMode="",actualBase="",fallback="",logicalMode="";boolean connected;long pathGeneration;}
 static Snapshot current=new Snapshot();static boolean emergency;static int sequence;
 static void reset(){current=new Snapshot();emergency=false;}
 static Snapshot snapshot(Context context){return current;}
 static String nodeIdFromBundleFile(File file){return"captured-node";}
 static boolean emergencyDisconnectPending(Context context){return emergency;}
 static String begin(Context context,String logical,String raw,String base,String node){Snapshot s=new Snapshot();s.pathGeneration=current.pathGeneration+1;s.sessionId="selection-"+(++sequence);s.phase="connecting";s.activeNodeId=node;s.logicalMode=logical;current=s;return s.sessionId;}
 static synchronized void advancePathGeneration(Context context){current.pathGeneration++;}
 static void connected(Context context,String logical,String raw,String base,String fallback,String node){current.phase="connected";current.logicalMode=logical;current.connected=true;current.runtimeMode=raw;current.actualBase=base;current.fallback=fallback;current.activeNodeId=node;Env.adoptions++;}
 static void beginPathRevalidation(Context context,String why){current.phase="disconnecting";current.connected=false;}
 static void failed(Context context,String why){current.phase="failed";current.connected=false;}
 static void failedPreservingOwnership(Context context,String why){failed(context,why);Env.preserved=true;}
 static void disconnected(Context context){current=new Snapshot();}
}
''',
    'com/eabusham/routervpn/StrategyHarness.java': r'''package com.eabusham.routervpn;
import android.content.Context;
import org.json.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

public final class StrategyHarness {
 static JSONArray catalog,logical;static Path directory;static int checks,cases;static final List<String> failures=new ArrayList<>();
 static final String[] MAX={"max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"};
 interface Test {void run()throws Exception;}
 static void check(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
 static void test(String name,Test body){cases++;try{body.run();System.out.println("PASS "+name);}catch(Throwable error){failures.add(name+": "+error);System.out.println("FAIL "+name+": "+error);}}
 static JSONObject source(String base,boolean fallback,boolean strict,String... ids)throws Exception {
  Set<String>wanted=new HashSet<>(Arrays.asList(ids));JSONArray modes=new JSONArray();JSONObject profiles=new JSONObject();
  for(int i=0;i<catalog.length();i++){JSONObject mode=catalog.getJSONObject(i);String id=mode.getString("id");if(!wanted.remove(id))continue;modes.put(new JSONObject(mode.toString()));profiles.put(id,new JSONObject().put(id.startsWith("awg2")?"awg.conf":"wg.conf","fixture"));}
  check(wanted.isEmpty(),"fixture requested a mode outside the shipping catalog");
  JSONObject profile=new JSONObject().put("id","node").put("base_tunnel",base).put("base_fallback",fallback).put("kill_switch",strict).put("force_libbox",true);
  return new JSONObject().put("selectedRouterID","node").put("routerProfiles",new JSONArray().put(profile)).put("modes",modes).put("profiles",profiles).put("logicalModes",new JSONArray(logical.toString()));
 }
 static final class Result implements AndroidModeOrchestrator.Callback {
  final CountDownLatch done=new CountDownLatch(1);final List<String>progress=new ArrayList<>();boolean success;String mode="",message="",owner="",provedRaw="",provedSource="",provedOwner="";int receipts;
  public void owned(String session){owner=session;}public void proved(String session,String raw,String source){receipts++;provedOwner=session;provedRaw=raw;provedSource=source;}
  public void progress(String value){progress.add(value);}
  public void finished(boolean ok,String mode,String value){success=ok;this.mode=mode;message=value;done.countDown();}
 }
 static final class Owner implements AutoCloseable {
  final Context context=new Context();final NativeSingBoxController sing=new NativeSingBoxController();
  final NativeXrayController xray=new NativeXrayController();final NativeWireGuardController wg=new NativeWireGuardController();final NativeAmneziaWGController awg=new NativeAmneziaWGController();
  final AndroidModeOrchestrator chooser=new AndroidModeOrchestrator(context,wg,awg,sing,xray);final File file;
  Owner(JSONObject source)throws Exception{Env.reset();file=Files.createTempFile(directory,"bundle-",".json").toFile();Files.writeString(file.toPath(),source.toString());}
  Result run(String kind,String... layers)throws Exception {
   Result result=new Result();if(kind.equals("all"))chooser.all(file,result);else if(kind.equals("auto"))chooser.auto(file,false,result);else if(kind.equals("smart"))chooser.auto(file,true,result);else if(kind.equals("custom"))chooser.custom(file,Arrays.asList(layers),result);else chooser.logical(file,kind,result);
   check(result.done.await(4,TimeUnit.SECONDS),"selection did not complete");long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);while(chooser.isRunning()&&System.nanoTime()<deadline)Thread.yield();check(!chooser.isRunning(),"selection retained transition flag");return result;
  }
  void selected(Result result,String mode)throws Exception{check(result.success&&mode.equals(result.mode),"wrong result: "+result.message);check(Env.adoptions==1&&Env.mtuStarts==1,"unproved or duplicate adoption/MTU start");}
  public void close(){chooser.close();}
 }
 static void attempted(String... modes){List<String>wanted=new ArrayList<>();for(String mode:modes)wanted.add("libbox:"+mode);check(Env.attempts.equals(wanted),"attempts changed: "+Env.attempts+" expected "+wanted);}
 static void stoppedBefore(String failed,String next){int stop=Env.events.indexOf("stop:"+failed),terminal=Env.events.indexOf("terminal:"+failed),prepare=Env.events.indexOf("prepare:"+next);check((stop>=0&&stop<prepare)||(terminal>=0&&terminal<prepare),"another candidate began before failed transport teardown: "+Env.events);}
 static Step badProof(){Step step=new Step("");step.proof=false;return step;}
 static void await(Owner o,Result result)throws Exception{check(result.done.await(3,TimeUnit.SECONDS),"captured operation did not finish");long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);while(o.chooser.isRunning()&&System.nanoTime()<end)Thread.yield();}
 static void restorationTests()throws Exception{
  for(String raw:new String[]{"wg","awg2-fast","awg2-strong","shadowsocks","hysteria2","reality-vision","reality-xhttp","max-tls-wg","max-quic-awg"})test("restore exact native candidate "+raw,()->{
   try(Owner o=new Owner(source("auto",true,true,raw))){Result first=o.run("auto");check(first.success,"original path did not connect");String session=first.owner,source=o.chooser.captureSource(o.file,session,raw);String original=Files.readString(o.file.toPath());
    Result stale=new Result();int stops=Env.events.size();o.chooser.disconnectCaptured("another-session",stale);await(o,stale);check(!stale.success&&AndroidHomeStateStore.current.connected&&Env.events.size()==stops,"captured stop changed another session");
    Result stop=new Result();o.chooser.disconnectCaptured(session,stop);await(o,stop);check(stop.success&&!o.chooser.isActive(),"original path did not drain");
    Result restore=new Result();o.chooser.restoreCaptured(o.file,raw,"SMART AUTO","original-fallback",source,restore);await(o,restore);
    check(restore.success&&restore.mode.equals(raw)&&AndroidHomeStateStore.current.logicalMode.equals("SMART AUTO")&&AndroidHomeStateStore.current.fallback.equals("original-fallback"),"restore changed exact runtime or logical selection");
    check(Env.attempts.equals(List.of("libbox:"+raw,"libbox:"+raw))&&Env.adoptions==2,"restore selected a substitute candidate or skipped fresh proof");check(Files.readString(o.file.toPath()).equals(original),"restore edited saved node preferences");
   }
  });
  test("changed original profile prevents restoration",()->{try(Owner o=new Owner(source("wg",true,true,"wg","awg2-fast"))){Result first=o.run("auto");String source=o.chooser.captureSource(o.file,first.owner,"wg");Result stop=new Result();o.chooser.disconnectCaptured(first.owner,stop);await(o,stop);Files.writeString(o.file.toPath(),new JSONObject(source).put("new-setting",true).toString());Result restore=new Result();int attempts=Env.attempts.size();o.chooser.restoreCaptured(o.file,"wg","AUTO","",source,restore);await(o,restore);check(!restore.success&&Env.attempts.size()==attempts&&!AndroidHomeStateStore.current.connected,"changed saved profile silently restored");}});
  test("restoration failure cannot fallback to another mode",()->{try(Owner o=new Owner(source("wg",true,true,"wg","awg2-fast"))){Result first=o.run("auto");String source=o.chooser.captureSource(o.file,first.owner,"wg");Result stop=new Result();o.chooser.disconnectCaptured(first.owner,stop);await(o,stop);Env.plan("wg",badProof());Result restore=new Result();o.chooser.restoreCaptured(o.file,"wg","AUTO","",source,restore);await(o,restore);check(!restore.success&&!AndroidHomeStateStore.current.connected&&Env.attempts.equals(List.of("libbox:wg","libbox:wg")),"failed exact restore switched to another candidate");}});
  test("captured selector cancellation waits for late proof",()->{try(Owner o=new Owner(source("wg",true,true,"wg","awg2-fast"))){CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);Step late=new Step("");late.proved=()->{entered.countDown();boolean interrupted=false;while(true)try{release.await();break;}catch(InterruptedException ignored){interrupted=true;}if(interrupted)Thread.currentThread().interrupt();};Env.plan("wg",late);Result selected=new Result();o.chooser.auto(o.file,false,selected);check(entered.await(2,TimeUnit.SECONDS),"proof boundary missing");Result stop=new Result();o.chooser.disconnectCaptured(selected.owner,stop);try{check(!stop.done.await(100,TimeUnit.MILLISECONDS)&&o.chooser.isRunning(),"captured cleanup outran selector worker");}finally{release.countDown();}await(o,selected);await(o,stop);check(!selected.success&&stop.success&&!o.chooser.isActive()&&!AndroidHomeStateStore.current.connected,"late selected path survived captured cancellation");attempted("wg");}});
 }
 static Result startup(Owner owner,String mode,String raw,String source)throws Exception{Result r=new Result();owner.chooser.startup(owner.file,mode,raw,source,r);await(owner,r);return r;}
 static void startupTests()throws Exception{
  test("startup Last tries the exact prior raw before AUTO order",()->{try(Owner o=new Owner(source("auto",true,true,"wg","shadowsocks"))){String source=Files.readString(o.file.toPath());Result r=startup(o,"last","shadowsocks",source);o.selected(r,"shadowsocks");attempted("shadowsocks");check(r.receipts==1&&r.provedRaw.equals("shadowsocks")&&r.provedSource.equals(source)&&r.provedOwner.equals(r.owner),"startup receipt did not follow exact current proof");}});
  for(String failure:new String[]{"prepare","start","failed","proof-error","bad-proof"})test("Last ordinary "+failure+" failure joins cleanup before AUTO",()->{try(Owner o=new Owner(source("auto",true,true,"wg","shadowsocks"))){Env.plan("shadowsocks",failure.equals("bad-proof")?badProof():new Step(failure));Result r=startup(o,"last","shadowsocks",Files.readString(o.file.toPath()));o.selected(r,"wg");attempted("shadowsocks","wg");if(!failure.equals("prepare"))stoppedBefore("shadowsocks","wg");check(r.receipts==1&&r.provedRaw.equals("wg"),"failed last candidate entered proved startup memory");}});
  for(String failure:new String[]{"interrupt","cancel","permission","revoked","proof-interrupt"})test("Last "+failure+" never falls through to AUTO",()->{try(Owner o=new Owner(source("auto",true,true,"wg","shadowsocks"))){Env.plan("shadowsocks",new Step(failure));Result r=startup(o,"last","shadowsocks",Files.readString(o.file.toPath()));check(!r.success&&r.receipts==0,"cancelled/revoked last attempt was adopted");attempted("shadowsocks");}});
  test("Last unconfirmed cleanup keeps ownership and forbids AUTO",()->{try(Owner o=new Owner(source("auto",true,true,"wg","shadowsocks"))){Step late=new Step("start");late.failStop=true;Env.plan("shadowsocks",late);Result r=startup(o,"last","shadowsocks",Files.readString(o.file.toPath()));check(!r.success&&r.receipts==0&&Env.preserved,"last cleanup failure was replaced by AUTO");attempted("shadowsocks");}});
  test("Last current AUTO requirements exclude an obsolete raw",()->{JSONObject input=source("auto",true,true,"wg","reality-vision");input.getJSONArray("routerProfiles").getJSONObject(0).put("auto_require_obfuscation",true);try(Owner o=new Owner(input)){o.selected(startup(o,"last","wg",Files.readString(o.file.toPath())),"reality-vision");attempted("reality-vision");}});
  test("Last can freshly prove an explicit non-AUTO raw",()->{JSONObject input=source("auto",true,true,"wg","shadowsocks");for(int i=0;i<input.getJSONArray("modes").length();i++){JSONObject m=input.getJSONArray("modes").getJSONObject(i);if(m.getString("id").equals("shadowsocks"))m.put("auto_eligible",false);}try(Owner o=new Owner(input)){o.selected(startup(o,"last","shadowsocks",Files.readString(o.file.toPath())),"shadowsocks");attempted("shadowsocks");}});
  test("missing last receipt selects freshly proved AUTO",()->{try(Owner o=new Owner(source("auto",true,true,"wg","shadowsocks"))){o.selected(startup(o,"last","",Files.readString(o.file.toPath())),"wg");attempted("wg");}});
  for(String mode:new String[]{"smart-auto","auto","last"})test("startup "+mode+" rejects changed captured source before launch",()->{try(Owner o=new Owner(source("auto",true,true,"wg","shadowsocks"))){String source=Files.readString(o.file.toPath());Files.writeString(o.file.toPath(),new JSONObject(source).put("changed",true).toString());Result r=startup(o,mode,"shadowsocks",source);check(!r.success&&r.receipts==0&&Env.attempts.isEmpty()&&AndroidHomeStateStore.current.phase.equals("off"),"changed startup source launched a different strategy");}});
  test("Last source change inside preparation never becomes AUTO",()->{try(Owner o=new Owner(source("auto",true,true,"wg","shadowsocks"))){Step step=new Step("");step.prepared=()->{try{Files.writeString(o.file.toPath(),new JSONObject(Files.readString(o.file.toPath())).put("changed",true).toString());}catch(Exception e){throw new RuntimeException(e);}};Env.plan("shadowsocks",step);Result r=startup(o,"last","shadowsocks",Files.readString(o.file.toPath()));check(!r.success&&r.receipts==0&&Env.starts==0,"last changed source became AUTO");attempted("shadowsocks");}});
  test("Last newer Home owner prevents fallback and old receipt",()->{try(Owner o=new Owner(source("auto",true,true,"wg","shadowsocks"))){Step step=new Step("prepare");step.prepared=()->AndroidHomeStateStore.begin(o.context,"external","","","new-owner");Env.plan("shadowsocks",step);Result r=startup(o,"last","shadowsocks",Files.readString(o.file.toPath()));check(!r.success&&r.receipts==0&&AndroidHomeStateStore.current.activeNodeId.equals("new-owner"),"last operation replaced a newer owner");attempted("shadowsocks");}});
  test("manual Disconnect during startup joins the actual selector and forbids AUTO",()->{try(Owner o=new Owner(source("auto",true,true,"wg","shadowsocks"))){CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);Step late=new Step("");late.proved=()->{entered.countDown();boolean interrupted=false;while(true)try{release.await();break;}catch(InterruptedException ignored){interrupted=true;}if(interrupted)Thread.currentThread().interrupt();};Env.plan("shadowsocks",late);Result started=new Result();o.chooser.startup(o.file,"last","shadowsocks",Files.readString(o.file.toPath()),started);check(entered.await(2,TimeUnit.SECONDS),"startup proof did not enter");Result stop=new Result();o.chooser.disconnect(stop);try{check(!stop.done.await(100,TimeUnit.MILLISECONDS)&&o.chooser.isRunning(),"manual Disconnect outran pending native proof");}finally{release.countDown();}await(o,started);await(o,stop);check(!started.success&&started.receipts==0&&stop.success&&!o.chooser.isActive()&&!AndroidHomeStateStore.current.connected,"startup connected after manual Disconnect");attempted("shadowsocks");}});
  test("Disconnect generation cancels late startup proof before its queued stop worker",()->{try(Owner o=new Owner(source("auto",true,true,"wg","shadowsocks"))){Step late=new Step("");late.proved=()->AndroidHomeStateStore.advancePathGeneration(o.context);Env.plan("shadowsocks",late);Result started=startup(o,"last","shadowsocks",Files.readString(o.file.toPath()));check(!started.success&&started.receipts==0&&Env.adoptions==0&&!o.chooser.isActive()&&!AndroidHomeStateStore.current.connected,"generation-only Disconnect was ignored before the stop worker");attempted("shadowsocks");}});

 }
 public static void main(String[] args)throws Exception {
  directory=Path.of(args[0]);catalog=new JSONArray(Files.readString(Path.of(args[1])));logical=new JSONArray(Files.readString(Path.of(args[2])));
  for(String base:new String[]{"wg","awg"}){
   test("ALL honors explicit "+base+" without base fallback",()->{try(Owner o=new Owner(source(base,false,true,MAX))){o.selected(o.run("all"),"max-tls-"+base);attempted("max-tls-"+base);check(AndroidHomeStateStore.current.actualBase.equals(base),"reported compiler instead of actual tunnel base");}});
   test("ALL TLS alternate base before QUIC for "+base,()->{try(Owner o=new Owner(source(base,true,true,MAX))){String first="max-tls-"+base,second="max-tls-"+(base.equals("wg")?"awg":"wg");Env.plan(first,badProof());o.selected(o.run("all"),second);attempted(first,second);stoppedBefore(first,second);check(AndroidHomeStateStore.current.fallback.equals(first+" -> "+second),"fallback provenance missing");}});
   test("ALL no-fallback stays on "+base+" for QUIC",()->{try(Owner o=new Owner(source(base,false,true,MAX))){String first="max-tls-"+base,last="max-quic-"+base;Env.plan(first,new Step("prepare"));o.selected(o.run("all"),last);attempted(first,last);}});
  }
  test("ALL complete fallback order, never weaker substitute",()->{try(Owner o=new Owner(source("wg",true,true,"wg","reality-xhttp",MAX[0],MAX[1],MAX[2],MAX[3]))){for(String id:MAX)Env.plan(id,badProof());Result result=o.run("all");check(!result.success&&Env.adoptions==0,"ALL adopted a weaker graph after complete MAX failures");attempted(MAX);}});
  test("ALL auto base starts with WG and permits other base",()->{try(Owner o=new Owner(source("auto",false,true,MAX))){Env.plan(MAX[0],new Step("prepare"));o.selected(o.run("all"),MAX[1]);attempted(MAX[0],MAX[1]);}});
  test("logical ALL retains one selection owner",()->{try(Owner o=new Owner(source("wg",false,true,MAX))){Result result=new Result();o.chooser.logical(o.file,"all",result);check(result.done.await(4,TimeUnit.SECONDS),"logical ALL did not complete");check(result.success&&MAX[0].equals(result.mode),"logical ALL lost runtime ownership");}});
  test("AWG-only logical mode ignores unrelated WG preference",()->{try(Owner o=new Owner(source("wg",false,true,"awg2-strong"))){o.selected(o.run("awg-strong"),"awg2-strong");attempted("awg2-strong");}});
  test("native logical mode keeps its exact independent transport",()->{try(Owner o=new Owner(source("awg",false,true,"shadowsocks"))){o.selected(o.run("shadowsocks"),"shadowsocks");attempted("shadowsocks");}});
  test("dual-base logical mode keeps disabled fallback",()->{try(Owner o=new Owner(source("wg",false,true,"awg2-fast"))){Result result=o.run("base-raw");check(!result.success&&Env.attempts.isEmpty(),"explicit WG was substituted by AWG");}});
  test("logical fallback survives preparation exception",()->{try(Owner o=new Owner(source("wg",true,true,"wg","awg2-fast"))){Env.plan("wg",new Step("prepare"));o.selected(o.run("base-raw"),"awg2-fast");attempted("wg","awg2-fast");check(AndroidHomeStateStore.current.fallback.equals("wg -> awg2-fast"),"logical fallback was not reported");}});
  for(String fault:new String[]{"prepare","start","failed","proof-error"}){
   test("strict AUTO survives ordinary "+fault+" failure",()->{try(Owner o=new Owner(source("wg",true,true,"wg","awg2-fast"))){Env.plan("wg",new Step(fault));o.selected(o.run("auto"),"awg2-fast");attempted("wg","awg2-fast");if(!fault.equals("prepare"))stoppedBefore("wg","awg2-fast");}});
  }
  test("CUSTOM preserves every requested layer during fallback",()->{try(Owner o=new Owner(source("wg",true,true,"wg","shadowsocks","ss-v2ray"))){Env.plan("shadowsocks",new Step("prepare"));o.selected(o.run("custom","shadowsocks2022"),"ss-v2ray");attempted("shadowsocks","ss-v2ray");}});
  test("SMART restores last proven mode after simplification exception",()->{try(Owner o=new Owner(source("wg",true,true,"wg","reality-vision"))){Env.plan("wg",badProof(),new Step("prepare"));o.selected(o.run("smart"),"reality-vision");attempted("wg","reality-vision","wg","reality-vision");}});
  test("SMART cancellation never restores or adopts another candidate",()->{try(Owner o=new Owner(source("wg",true,true,"wg","reality-vision"))){Env.plan("wg",badProof(),new Step("interrupt"));Result result=o.run("smart");check(!result.success&&Env.adoptions==0,"cancelled SMART restored/adopted a transport");attempted("wg","reality-vision","wg");}});
  for(String fault:new String[]{"interrupt","cancel","permission","revoked","proof-interrupt"}){
   test("AUTO does not swallow "+fault,()->{try(Owner o=new Owner(source("wg",true,true,"wg","awg2-fast"))){Env.plan("wg",new Step(fault));Result result=o.run("auto");check(!result.success&&Env.adoptions==0,"cancellation or permission loss became fallback success");attempted("wg");}});
  }
  test("raw WG permission loss is not an ordinary candidate failure",()->{JSONObject input=source("wg",true,false,"wg","awg2-fast");input.getJSONArray("routerProfiles").getJSONObject(0).put("force_libbox",false);try(Owner o=new Owner(input)){Env.plan("wg",new Step("permission"));Result result=o.run("auto");check(!result.success&&Env.attempts.equals(List.of("raw-wg:wg")),"raw callback revocation was swallowed");}});
  for(String raw:new String[]{"wg","awg2-fast"}){
   test("raw "+raw+" UP plus start error cannot be proved or adopted",()->{JSONObject input=source("wg",true,false,raw,"shadowsocks");input.getJSONArray("routerProfiles").getJSONObject(0).put("force_libbox",false);try(Owner o=new Owner(input)){Env.plan(raw,new Step("start"));o.selected(o.run("auto"),"shadowsocks");check(Env.attempts.equals(List.of((raw.equals("wg")?"raw-wg:":"raw-awg:")+raw,"libbox:shadowsocks")),"raw error did not fall through after teardown");check(!Env.events.contains("proof:"+raw),"failed raw start was allowed to prove/adopt its retained UP state");stoppedBefore(raw,"shadowsocks");}});
   test("raw "+raw+" failed cleanup prevents fallback",()->{JSONObject input=source("wg",true,false,raw,"shadowsocks");input.getJSONArray("routerProfiles").getJSONObject(0).put("force_libbox",false);try(Owner o=new Owner(input)){Step step=new Step("start");step.failStop=true;Env.plan(raw,step);Result result=o.run("auto");check(!result.success&&Env.adoptions==0&&Env.preserved,"raw error discarded unconfirmed transport ownership");check(Env.attempts.equals(List.of((raw.equals("wg")?"raw-wg:":"raw-awg:")+raw))&&!Env.events.contains("proof:"+raw),"another proof or engine began before raw teardown");}});
  }
  test("unconfirmed cleanup aborts instead of starting another engine",()->{try(Owner o=new Owner(source("wg",true,true,"wg","awg2-fast"))){Step step=new Step("start");step.failStop=true;Env.plan("wg",step);Result result=o.run("auto");check(!result.success&&Env.adoptions==0&&Env.preserved,"failed cleanup discarded runtime ownership");attempted("wg");}});
  test("lost session owner is neither adopted nor overwritten",()->{try(Owner o=new Owner(source("wg",true,true,"wg","awg2-fast"))){Step step=new Step("prepare");step.prepared=()->AndroidHomeStateStore.begin(o.context,"external","","","new-node");Env.plan("wg",step);Result result=o.run("auto");check(!result.success&&Env.adoptions==0&&Env.starts==0,"lost ownership became another candidate start");check(AndroidHomeStateStore.current.activeNodeId.equals("new-node")&&AndroidHomeStateStore.current.phase.equals("connecting"),"old selection overwrote a new session");attempted("wg");}});
  test("changed captured node aborts before a prepared engine starts",()->{try(Owner o=new Owner(source("wg",true,true,"wg","awg2-fast"))){Step step=new Step("");step.prepared=()->{try{JSONObject changed=new JSONObject(Files.readString(o.file.toPath()));changed.put("changed",true);Files.writeString(o.file.toPath(),changed.toString());}catch(Exception e){throw new RuntimeException(e);}};Env.plan("wg",step);Result result=o.run("auto");check(!result.success&&Env.starts==0&&Env.adoptions==0,"changed node policy started a stale prepared engine");attempted("wg");}});
  test("engine loss during successful proof cannot be adopted",()->{try(Owner o=new Owner(source("wg",true,true,"wg","awg2-fast"))){Step step=new Step("");step.proved=()->o.sing.engine.state="DOWN";Env.plan("wg",step);o.selected(o.run("auto"),"awg2-fast");attempted("wg","awg2-fast");}});
  test("unknown base fails before any engine prepares",()->{try(Owner o=new Owner(source("invalid",true,true,MAX))){Result result=o.run("all");check(!result.success&&Env.attempts.isEmpty(),"unknown base silently defaulted to a real tunnel");}});
  test("typed fallback policy cannot silently enable another base",()->{JSONObject input=source("wg",true,true,MAX);input.getJSONArray("routerProfiles").getJSONObject(0).put("base_fallback","false");try(Owner o=new Owner(input)){Result result=o.run("all");check(!result.success&&Env.attempts.isEmpty(),"nonboolean fallback silently selected another base");}});
  restorationTests();
  startupTests();
  if(!failures.isEmpty())throw new AssertionError(String.join("\n",failures));
  System.out.println("Shipping Android strategy: "+cases+" scenarios, "+checks+" checks PASS (Android/engine boundaries doubled)");
 }
}
''',
}


def main():
    spec = importlib.util.spec_from_file_location('android_json', ROOT/'deploy/test_android_multihop_pinned.py')
    dependency = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dependency)
    with tempfile.TemporaryDirectory(prefix='routervpn-android-strategy-') as directory:
        root = Path(directory)
        jar = dependency.android_json_dependency(root, dict(os.environ))
        for path, contents in SOURCES.items():
            target = root/path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(contents)
        for name in ('AndroidModeOrchestrator', 'AndroidProfileSelection', 'AndroidKillSwitchPolicy'):
            source = JAVA/(name+'.java')
            if name == 'AndroidModeOrchestrator':
                source = Path(os.environ.get('ROUTERVPN_ORCHESTRATOR_SOURCE', str(source)))
            (root/'com/eabusham/routervpn'/(name+'.java')).write_bytes(source.read_bytes())
        compile_command=['javac', '--release', '17', '-Xlint:all,-auxiliaryclass', '-Werror', '-cp', str(jar),
                         '-d', str(root), *map(str, root.rglob('*.java'))]
        execute_command=['java', '-cp', os.pathsep.join((str(root), str(jar))), 'com.eabusham.routervpn.StrategyHarness',
                         str(root), str(ROOT/'configs/client/modes.json'), str(ROOT/'configs/client/logical-modes.json')]
        subprocess.run(compile_command, check=True, timeout=45)
        subprocess.run(execute_command, check=True, timeout=30)
        if not os.environ.get('ROUTERVPN_ORCHESTRATOR_SOURCE'):
            path=root/'com/eabusham/routervpn/AndroidModeOrchestrator.java'
            original=path.read_text()
            guard='state.pathGeneration!=selectionPathGeneration||'
            assert original.count(guard)==1, 'missing exact captured path-generation guard'
            path.write_text(original.replace(guard,''))
            subprocess.run(compile_command, check=True, timeout=45)
            mutated=subprocess.run(execute_command,capture_output=True,text=True,timeout=30)
            assert mutated.returncode and 'generation-only Disconnect was ignored before the stop worker' in mutated.stdout+mutated.stderr, 'Disconnect-generation mutation was not rejected by its executable regression'
            print('Android strategy Disconnect-generation negative control rejected')


if __name__ == '__main__':
    main()
