#!/usr/bin/env python3
"""Shipping candidate catalog/result/transaction against real stores and Go sources.

The native measurement boundary is a deterministic lifecycle double. Encrypted
prefix and fifty-socket acceptance belongs to the pinned native bridge tests.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import test_android_connection_profiles as profiles
import test_android_node_chain_capture as chain

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'
ORIGINAL_PREPARE = chain.prepare_sources
ORIGINAL_COMPILER = chain.compiler_source


def compiler(source):
    return ORIGINAL_COMPILER(source).replace('case len(args)==2:', '''case len(args)==2&&args[0]=="candidate-supported":result=fmt.Sprint(mobilemultihop.NodeChainCandidateInputSupported(args[1]));case len(args)==4&&args[0]=="candidate-metadata":var plan *mobilemultihop.NodeChain;plan,err=mobilemultihop.ParseNodeChainLaunchInput(args[1]);if err==nil{var position int;_,err=fmt.Sscan(args[2],&position);if err==nil{var captured *mobilemultihop.NodeChainCandidatePlan;captured,err=plan.NewCandidatePlan(position,args[3]);if err==nil{result=captured.Metadata()}}};case len(args)==2:''')


SESSION = '''package com.eabusham.routervpn;
final class AndroidNodeChainSession {
 static AndroidNodeChainSession retained;static AndroidNodeChainSession retained(){return retained;}
 final AndroidNodeStore.ChainCapture source;final AndroidNodeChainCapture capture;
 io.nekohasekai.libbox.CommandServer server=new io.nekohasekai.libbox.CommandServer();boolean current=true;
 AndroidNodeChainSession(AndroidNodeStore.ChainCapture source)throws Exception{this.source=source;capture=AndroidNodeChainCapture.compile(source);retained=this;}
 void requireCurrent()throws Exception{source.requireCurrent();if(!current)throw new IllegalStateException("Retired native session/network");}
 io.nekohasekai.libbox.CommandServer candidateServer()throws Exception{requireCurrent();return server;}
}'''

NATIVE = r'''package io.nekohasekai.libbox;
import org.json.*;
public final class RouterNodeChainCandidateMeasurement {
 public static volatile boolean holdClose,factoryFailure;public static volatile int closeAttempts;public static volatile RouterNodeChainCandidateMeasurement last;
 final String info;final RouterNodeChainCandidateCatalog guard;final String original;String request="",id="";
 RouterNodeChainCandidateMeasurement(RouterNodeChain plan,int prefix,String inventory,RouterNodeChainCandidateCatalog guard)throws Exception{
  info=Libbox.call("candidate-metadata",plan.launchInput(),Integer.toString(prefix),inventory);this.guard=guard;original=guard.currentInventorySHA256();last=this;
 }
 public String metadata(){return info;}public String captureSHA256()throws Exception{return new JSONObject(info).getString("capture_sha256");}
 public void start(String request,String id){this.request=request;this.id=id;}
 public void cancel(String request){}public void drain(String request){}
 public void close()throws Exception{closeAttempts++;if(holdClose)throw new IllegalStateException("Original native callback not joined");}
 public String statusJSON()throws Exception{
  JSONObject meta=new JSONObject(info);String source="";JSONArray targets=meta.getJSONArray("targets");for(int i=0;i<targets.length();i++)if(id.equals(targets.getJSONObject(i).getString("id")))source=targets.getJSONObject(i).getString("source_sha256");
  long now=System.currentTimeMillis();JSONObject distribution=new JSONObject().put("samples",50).put("min_ms",1).put("median_ms",2).put("average_ms",2).put("p90_ms",3).put("max_ms",4).put("jitter_ms",1);
  JSONObject row=new JSONObject().put("node_id",id).put("role","candidate").put("kind","tcp-connect").put("ready",true).put("benchmark",new JSONObject().put("schema",1).put("measurement","routed-tcp-connect").put("attempts",50).put("failed",0).put("distribution",distribution).put("trimmed_mean_ms",id.startsWith("chain-")?1.5:2.5));
  boolean current=!original.isEmpty()&&original.equals(guard.currentInventorySHA256());
  return new JSONObject().put("schema",1).put("measurement","routed-tcp-connect").put("request_id",request).put("complete",true).put("drained",true).put("stage",current?"complete":"invalidated").put("failure",current?"":"retired").put("capture_sha256",meta.getString("capture_sha256")).put("prefix_position",meta.getInt("prefix_position")).put("prefix_id",meta.getString("prefix_id")).put("candidate_id",id).put("candidate_source_sha256",source).put("measured_at",now).put("expires_at",now+120000).put("results",new JSONArray().put(row)).toString();
 }
}'''

HARNESS = r'''package com.eabusham.routervpn;
import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.util.*;import java.util.concurrent.*;import org.json.*;import io.nekohasekai.libbox.*;
public final class NodeCandidateHarness {
 static int checks;static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
 interface Work{void run()throws Exception;}static void reject(Work action,String message)throws Exception{try{action.run();}catch(Exception expected){checks++;return;}throw new AssertionError(message);}
 static NodeChainCaptureHarness.Fixture fixture(Path root)throws Exception{return new NodeChainCaptureHarness.Fixture(root,"2/");}
 static AndroidStandardExitStore.Entry custom(String method){AndroidStandardExitStore.Entry entry=new AndroidStandardExitStore.Entry();entry.id="1234567890abcdef1234567890abcdef";entry.name="Custom candidate";entry.protocol="shadowsocks";entry.server="198.51.100.76";entry.serverPort=443;entry.expectedPublicIp="203.0.113.76";entry.method=method;entry.secret=Base64.getEncoder().encodeToString(new byte[method.contains("aes-128")?16:32]);return entry;}
 static void capturedSources(Path root)throws Exception{
  var f=fixture(root);var source=f.profiles.currentOrderedPath();
  var unopened=AndroidNodeCandidateCatalog.captureSources(f.context,source,0);unopened.requireSourcesCurrent();
  check(unopened.originalSource==source&&unopened.session==null&&unopened.server==null,"saved catalog capture acquired native authority before permission");
  check(unopened.currentInventorySHA256().isEmpty(),"unbound saved catalog lent live callback authority");
  var session=new AndroidNodeChainSession(source);reject(()->unopened.bind(session),"observed unbound catalog revived native authority");
  var catalog=AndroidNodeCandidateCatalog.captureSources(f.context,source,0);String inventory=catalog.inventory;
  reject(()->catalog.bind(new AndroidNodeChainSession(f.profiles.currentOrderedPath())),"same-byte foreign source bound captured catalog");
  catalog.bind(session);check(catalog.session==session&&catalog.server==session.server&&inventory.equals(catalog.inventory)&&catalog.inventorySHA.equals(catalog.currentInventorySHA256()),"saved catalog binding rebuilt inventory or lost exact native owner");
  reject(()->catalog.bind(session),"saved catalog bound its native owner twice");
  var pending=AndroidNodeCandidateCatalog.captureSources(f.context,source,0);Path path=f.control().file.toPath();byte[] before=Files.readAllBytes(path);
  Files.writeString(path,new String(before,StandardCharsets.UTF_8)+" ");reject(pending::requireSourcesCurrent,"prepermission source mutation was ignored");Files.write(path,before);
  reject(()->pending.bind(session),"prepermission source change-away/back revived catalog");
 }
 static void sources(Path root)throws Exception{
  for(String method:List.of("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305")){
   var f=new NodeChainCaptureHarness.Fixture(root,method.contains("aes-128")?"2/":method.contains("aes-256")?"2/awg-fast":"3/awg-strong");var exits=new AndroidStandardExitStore(f.context);var entry=custom(method);exits.save(entry);var unsupported=new AndroidStandardExitStore.Entry();unsupported.id="unsupported-socks";unsupported.name="Unscored SOCKS";unsupported.protocol="socks5";unsupported.server="192.0.2.90";unsupported.serverPort=1080;unsupported.expectedPublicIp="203.0.113.90";exits.save(unsupported);
   var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   check(catalog.rows.stream().anyMatch(row->row.id.equals(entry.id)&&!row.input.isEmpty()),"original three-cipher custom source was omitted");
   JSONObject inventory=new JSONObject(catalog.inventory);check(inventory.getJSONArray("inputs").length()==2,"complete paired/custom candidate inventory lost a source");
   check(catalog.inventorySHA.equals(catalog.currentInventorySHA256()),"original live catalog was rejected");
   check(catalog.rows.size()==session.source.members.size()+1&&catalog.rows.stream().anyMatch(row->row.id.equals(unsupported.id)&&row.input.isEmpty()),"unsupported transport was hidden or fabricated a TCP score");
   Path allSources=f.context.getFilesDir().toPath().resolve("standard-exits.json");byte[] originalCatalog=Files.readAllBytes(allSources);Files.writeString(allSources,new String(originalCatalog,StandardCharsets.UTF_8).replace("Unscored SOCKS","Changed unscored SOCKS"));check(catalog.currentInventorySHA256().isEmpty(),"unsupported candidate source replacement accepted");Files.write(allSources,originalCatalog);reject(catalog::requireSavedSourcesCurrent,"observed source change-away/back revived post-DOWN catalog authority");catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   Path retainedImports=allSources.resolveSibling("retained-imported-original");Files.move(allSources,retainedImports);Files.write(allSources,originalCatalog);check(catalog.currentInventorySHA256().isEmpty(),"same-byte imported container replacement revived original identity");Files.delete(allSources);Files.move(retainedImports,allSources);check(catalog.currentInventorySHA256().isEmpty(),"observed imported container replacement revived after restoring original inode");catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   byte[] old=Files.readAllBytes(f.control().file.toPath());Files.writeString(f.control().file.toPath(),new String(old,StandardCharsets.UTF_8)+" ");check(catalog.currentInventorySHA256().isEmpty(),"raw source replacement accepted");Files.write(f.control().file.toPath(),old);catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   session.current=false;check(catalog.currentInventorySHA256().isEmpty(),"retired native session/network accepted");catalog.requireSavedSourcesCurrent();check(true,"normal native retirement wrongly invalidated saved sources");session.current=true;catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   CommandServer original=session.server;session.server=new CommandServer();check(catalog.currentInventorySHA256().isEmpty(),"replaced native server accepted");session.server=original;catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   Path replaced=f.control().file.toPath(),retained=replaced.resolveSibling("retained-original");Files.move(replaced,retained);Files.write(replaced,old);check(catalog.currentInventorySHA256().isEmpty(),"same-byte replacement revived original file identity");Files.delete(replaced);Files.move(retained,replaced);check(catalog.currentInventorySHA256().isEmpty(),"observed file replacement revived after restoring original inode");catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   String saved=entry.name;entry.name="temporary";exits.save(entry);entry.name=saved;exits.save(entry);check(catalog.currentInventorySHA256().isEmpty(),"catalog change-away/back revived a capture");
  }
  var f=fixture(root);var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());reject(()->new AndroidNodeCandidateCatalog(f.context,session,1),"lazy SS prefix falsely timed destination TCP");
 }
 static void overlappingSavedSources(Path root)throws Exception{
  var f=fixture(root);new AndroidStandardExitStore(f.context).save(custom("2022-blake3-aes-256-gcm"));
  var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
  Path imported=f.context.getFilesDir().toPath().resolve("standard-exits.json");byte[] original=Files.readAllBytes(imported);
  CountDownLatch reading=new CountDownLatch(1),resume=new CountDownLatch(1);var rejected=new java.util.concurrent.atomic.AtomicReference<Throwable>();
  Thread detached=new Thread(()->{try{catalog.requireSavedSourcesCurrent();}catch(Throwable failure){rejected.set(failure);}},"detached-source-authority");
  android.system.Os.beforeLstat=path->{if(Thread.currentThread()==detached&&path.equals(imported.toString())){reading.countDown();try{if(!resume.await(10,TimeUnit.SECONDS))throw new AssertionError("source overlap was not released");}catch(InterruptedException failure){throw new RuntimeException(failure);}}};
  try{
   detached.start();check(reading.await(10,TimeUnit.SECONDS),"detached authority never reached the original source-read boundary");
   Files.writeString(imported,new String(original,StandardCharsets.UTF_8).replace("Custom candidate","Changed custom candidate"));
   check(catalog.currentInventorySHA256().isEmpty(),"overlapping live source observer did not invalidate changed bytes");Files.write(imported,original);
   resume.countDown();detached.join(10000);check(!detached.isAlive(),"detached source read did not finish");
   check(rejected.get() instanceof IllegalStateException,"overlapping observed source change revived detached authority");
  }finally{Files.write(imported,original);resume.countDown();android.system.Os.beforeLstat=null;detached.join(10000);}
 }
 static void receipts(Path root)throws Exception{
  var f=fixture(root);var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
  var nativeOwner=Libbox.routerNodeChainNewCandidateMeasurement(session.capture.plan,session.server,0,catalog.inventory,catalog);JSONObject meta=new JSONObject(nativeOwner.metadata());String id=meta.getJSONArray("targets").getJSONObject(0).getString("id"),request="a".repeat(32);nativeOwner.start(request,id);String raw=nativeOwner.statusJSON();long now=System.currentTimeMillis();
  var accepted=AndroidNodeCandidateResult.capture(raw,request,meta,id,"Original",now);check(accepted.current(now)&&!accepted.current(accepted.expiresAt),"receipt read renewed120-second completion deadline");
  for(String fault:List.of("capture","source","prefix","candidate","request","measurement","drain","expiry","samples","failed","nan","partial","alien-row","typed-samples","typed-complete","fractional-expiry")){
   JSONObject bad=new JSONObject(raw);JSONObject row=bad.getJSONArray("results").getJSONObject(0),b=row.getJSONObject("benchmark");
   switch(fault){case "capture":bad.put("capture_sha256","0".repeat(64));break;case "source":bad.put("candidate_source_sha256","0".repeat(64));break;case "prefix":bad.put("prefix_position",1);break;case "candidate":bad.put("candidate_id","other");break;case "request":bad.put("request_id","b".repeat(32));break;case "measurement":bad.put("measurement","routed-https");break;case "drain":bad.put("drained",false);break;case "expiry":bad.put("expires_at",bad.getLong("expires_at")+1);break;case "samples":b.getJSONObject("distribution").put("samples",49);break;case "failed":b.put("failed",1);break;case "nan":b.put("trimmed_mean_ms","NaN");break;case "partial":row.put("ready",false);break;case "alien-row":row.put("kind","private-node");break;case "typed-samples":b.getJSONObject("distribution").put("samples","50");break;case "typed-complete":bad.put("complete","true");break;case "fractional-expiry":bad.put("expires_at",bad.getLong("expires_at")+0.5);break;}
   reject(()->AndroidNodeCandidateResult.capture(bad.toString(),request,meta,id,"Original",now),"foreign/partial candidate receipt accepted: "+fault);
  }
 }
 static void lifetime(Path root,boolean factoryFailure)throws Exception{
  var f=fixture(root);new AndroidStandardExitStore(f.context).save(custom("2022-blake3-aes-256-gcm"));var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
  RouterNodeChainCandidateMeasurement.factoryFailure=factoryFailure;RouterNodeChainCandidateMeasurement.holdClose=true;RouterNodeChainCandidateMeasurement.closeAttempts=0;
  CountDownLatch delivered=new CountDownLatch(1),finished=new CountDownLatch(1),observer=new CountDownLatch(1);java.util.concurrent.atomic.AtomicBoolean sorted=new java.util.concurrent.atomic.AtomicBoolean();
  var operation=AndroidNodeCandidateMeasurement.start(catalog,new AndroidNodeCandidateMeasurement.Callback(){public void changed(List<AndroidNodeCandidateResult> rows,String detail){if(detail.startsWith("Cancelling;")){observer.countDown();throw new IllegalStateException("disposed observer");}if(rows.size()==2){sorted.set(rows.get(0).id.startsWith("chain-")&&rows.get(0).score<rows.get(1).score);delivered.countDown();}}public void finished(Throwable failure){finished.countDown();}});
  if(!factoryFailure){check(delivered.await(10,TimeUnit.SECONDS),"actual host transaction never adopted a native completion");check(sorted.get(),"candidate display order did not use measured trimmed mean");}
  operation.cancel();long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);while(RouterNodeChainCandidateMeasurement.closeAttempts==0&&System.nanoTime()<end)Thread.yield();
  check(RouterNodeChainCandidateMeasurement.closeAttempts>0&&AndroidMTUMeasurementGate.held()&&AndroidNodeCandidateMeasurement.busy(),"failed close released original MTU/worker ownership");
  reject(()->AndroidNodeCandidateMeasurement.start(catalog,null),"pending old cleanup allowed a replacement host");
  check(observer.await(10,TimeUnit.SECONDS),"cleanup did not notify original observer");RouterNodeChainCandidateMeasurement.holdClose=false;check(finished.await(10,TimeUnit.SECONDS),"original native cleanup did not finish");check(!AndroidMTUMeasurementGate.held()&&!AndroidNodeCandidateMeasurement.busy(),"joined cleanup retained a dead parent lease");RouterNodeChainCandidateMeasurement.factoryFailure=false;
 }
 static void borrowedLifetime(Path root,boolean factoryFailure)throws Exception{
  var f=fixture(root);new AndroidStandardExitStore(f.context).save(custom("2022-blake3-aes-256-gcm"));var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
  Object lease=AndroidMTUMeasurementGate.acquire();
  reject(()->AndroidNodeCandidateMeasurement.startBorrowed(catalog,new Object(),null),"foreign outer lease entered a temporary candidate worker");
  RouterNodeChainCandidateMeasurement.factoryFailure=factoryFailure;RouterNodeChainCandidateMeasurement.holdClose=true;RouterNodeChainCandidateMeasurement.closeAttempts=0;
  CountDownLatch completed=new CountDownLatch(1),closing=new CountDownLatch(1),finished=new CountDownLatch(1);var callbackThread=new java.util.concurrent.atomic.AtomicReference<Thread>();var original=new java.util.concurrent.atomic.AtomicReference<AndroidNodeCandidateMeasurement>();
  var uncaught=new java.util.concurrent.ConcurrentLinkedQueue<Throwable>();Thread.UncaughtExceptionHandler previous=Thread.getDefaultUncaughtExceptionHandler();Thread.setDefaultUncaughtExceptionHandler((thread,error)->uncaught.add(error));
  try{
   var operation=AndroidNodeCandidateMeasurement.startBorrowed(catalog,lease,new AndroidNodeCandidateMeasurement.Callback(){
    public void changed(List<AndroidNodeCandidateResult> rows,String detail){if(detail.startsWith("Cancelling;"))closing.countDown();}
    public void completed(AndroidNodeCandidateMeasurement owner,List<AndroidNodeCandidateResult> rows)throws Exception{check(!owner.joined()&&rows.size()==2,"temporary completion lost the full original candidate inventory");for(var result:rows)owner.requireResult(result);completed.countDown();}
    public void finished(Throwable failure){callbackThread.set(Thread.currentThread());check(original.get().joined(),"completion observer ran before the native candidate join receipt");finished.countDown();throw new IllegalStateException("disposed temporary observer");}
   });original.set(operation);
   if(!factoryFailure)check(completed.await(10,TimeUnit.SECONDS),"temporary batch did not finish without waiting for a UI close");
   check(closing.await(10,TimeUnit.SECONDS),"temporary candidate cleanup did not retain a failed native join");
   check(!operation.joined()&&AndroidMTUMeasurementGate.owns(lease)&&AndroidNodeCandidateMeasurement.busy(),"borrowed candidate published join before native cleanup");
   reject(()->AndroidNodeCandidateMeasurement.startBorrowed(catalog,lease,null),"pending temporary native join allowed a second worker");
   RouterNodeChainCandidateMeasurement.holdClose=false;check(finished.await(10,TimeUnit.SECONDS),"temporary native cleanup did not finish");callbackThread.get().join(2000);
   check(!callbackThread.get().isAlive()&&uncaught.isEmpty(),"disposed completion observer escaped the retained cleanup worker");
   check(operation.joined()&&!AndroidNodeCandidateMeasurement.busy()&&AndroidMTUMeasurementGate.owns(lease),"borrowed candidate released the outer graph MTU lease");
   operation.cancel();check(AndroidMTUMeasurementGate.owns(lease),"retired inner worker released its preparation lease");
  }finally{Thread.setDefaultUncaughtExceptionHandler(previous);RouterNodeChainCandidateMeasurement.holdClose=false;RouterNodeChainCandidateMeasurement.factoryFailure=false;AndroidMTUMeasurementGate.release(lease);}
 }
 static void presentation(Path root)throws Exception{
  var f=fixture(root);new AndroidNodeChainSession(f.profiles.currentOrderedPath());
  var dialog=new AndroidNodeCandidateDialog(new android.app.Activity(f.context));dialog.show();
  var picker=android.app.AlertDialog.last;check(picker.items.length==1,"shipping picker offered lazy SS as a TCP timing prefix");picker.selected.run(picker,0);
  long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);while(!android.widget.TextView.latest.contains("50/50")&&System.nanoTime()<end)Thread.yield();
  check(android.widget.TextView.latest.contains("50/50")&&android.widget.TextView.latest.contains("not HTTP, ICMP"),"shipping candidate readout did not label actual callback TCP scope");
  android.widget.Button.last.click.run(android.widget.Button.last);android.app.AlertDialog.last.selected.run(android.app.AlertDialog.last,0);
  end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);while((android.widget.EditText.last==null||android.app.AlertDialog.last.positive==null)&&System.nanoTime()<end)Thread.yield();
  check(android.widget.EditText.last!=null&&android.app.AlertDialog.last.positive!=null,"shipping candidate action did not show named path preview");android.widget.EditText.last.text="Measured UI future path";android.app.AlertDialog.last.positive.run(android.app.AlertDialog.last,0);
  end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);while(System.nanoTime()<end){try{if(Files.exists(f.rows)&&new JSONObject(Files.readString(f.rows)).getJSONArray("profiles").length()==1)break;}catch(org.json.JSONException partialFixtureWrite){}Thread.yield();}
  check(Files.exists(f.rows)&&f.profiles.list().get(0).name.equals("Measured UI future path"),"shipping Save callback did not append future profile");AndroidNodeChainSession.retained().requireCurrent();
  dialog.close();end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);while(AndroidNodeCandidateMeasurement.busy()&&System.nanoTime()<end)Thread.yield();
  check(!AndroidNodeCandidateMeasurement.busy()&&!AndroidMTUMeasurementGate.held()&&!android.app.AlertDialog.last.isShowing(),"Activity cleanup lost the original dialog or native lease");
 }
 static void adoption(Path root)throws Exception{
  for(String method:List.of("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305")){
   var f=new NodeChainCaptureHarness.Fixture(root,method.contains("aes-128")?"2/":method.contains("aes-256")?"2/awg-fast":"3/awg-strong");var entry=custom(method);new AndroidStandardExitStore(f.context).save(entry);
   var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
   CountDownLatch ready=new CountDownLatch(1),finished=new CountDownLatch(1);var measured=new java.util.concurrent.atomic.AtomicReference<List<AndroidNodeCandidateResult>>();
   var operation=AndroidNodeCandidateMeasurement.start(catalog,new AndroidNodeCandidateMeasurement.Callback(){public void changed(List<AndroidNodeCandidateResult> rows,String detail){if(rows.size()==2){measured.set(rows);ready.countDown();}}public void finished(Throwable failure){finished.countDown();}});
   check(ready.await(10,TimeUnit.SECONDS),"candidate adoption never received complete native results");
   AndroidVpnMutationGuard.busy=true;var before=new NodeChainCaptureHarness.State(f);
   var imported=measured.get().stream().filter(row->row.id.equals(entry.id)).findFirst().orElseThrow();var paired=measured.get().stream().filter(row->!row.id.equals(entry.id)).findFirst().orElseThrow();
   var proposal=new AndroidNodeCandidateProfile(operation,imported);check(proposal.description.contains(entry.id)&&proposal.description.contains(session.source.control.profileId),"proposal preview omitted custom candidate or original paired final");
   var saved=proposal.save(f.context,"Measured custom "+method);check(saved.mode.equals("shadowsocks"),"candidate profile saved runtime mode instead of actual final transport");
   var other=new AndroidNodeCandidateProfile(operation,paired).save(f.context,"Measured paired "+method);
   var after=new NodeChainCaptureHarness.State(f);for(Path path:before.files.keySet())if(!path.equals(f.rows))check(Arrays.equals(before.files.get(path),after.files.get(path)),"candidate save changed active original source");check(before.preferences.equals(after.preferences),"candidate save changed active builder preferences");session.requireCurrent();check(AndroidMTUMeasurementGate.held(),"candidate save retired original measurement lease");
   JSONArray records=new JSONObject(Files.readString(f.rows)).getJSONArray("profiles");check(records.length()==2,"candidate profile replaced another saved profile");
   JSONObject customRow=records.getJSONObject(0),pairedRow=records.getJSONObject(1);check(customRow.getJSONArray("multihop_nodes").length()==3&&pairedRow.getJSONArray("multihop_nodes").length()==2,"saved candidate path changed prefix/suffix composition");check(!customRow.toString().contains("api_token")&&!customRow.toString().contains("wg_private_key")&&!customRow.toString().contains(entry.secret),"future profile copied private credentials");
   reject(()->f.profiles.load(saved.id),"candidate profile loaded while connected");
   session.current=false;byte[] beforeStale=Files.readAllBytes(f.rows);reject(()->proposal.save(f.context,"Stale"),"retired candidate saved a future profile");check(Arrays.equals(beforeStale,Files.readAllBytes(f.rows)),"stale candidate wrote profile storage");
   operation.cancel();check(finished.await(10,TimeUnit.SECONDS),"candidate profile cleanup did not join");AndroidVpnMutationGuard.busy=false;
   f.profiles.load(saved.id);try(var compiled=AndroidNodeChainCapture.compile(f.profiles.currentOrderedPath())){check(new JSONObject(compiled.launchInput).getInt("schema")==2,"future imported profile did not compile after normal Load");}
   f.profiles.load(other.id);try(var compiled=AndroidNodeChainCapture.compile(f.profiles.currentOrderedPath())){check(new JSONObject(compiled.launchInput).getJSONArray("nodes").length()==2,"future paired profile did not compile its exact truncated suffix");}
  }
 }
 public static void main(String[] args)throws Exception{try{Path root=Path.of(args[0]);capturedSources(root);sources(root);overlappingSavedSources(root);receipts(root);lifetime(root,false);lifetime(root,true);borrowedLifetime(root,false);borrowedLifetime(root,true);adoption(root);presentation(root);System.out.println("Android retained-prefix candidates: "+checks+" shipping source, receipt and drain checks PASS");}finally{AndroidVpnMutationGuard.busy=false;RouterNodeChainCandidateMeasurement.holdClose=false;AndroidNodeCandidateMeasurement.cancelActive();}}
}'''


def prepare(src, app, java):
    ORIGINAL_PREPARE(src, app, java)
    for name in ('AndroidNodeCandidateCatalog','AndroidNodeCandidateResult','AndroidNodeCandidateMeasurement','AndroidNodeCandidateDialog','AndroidNodeCandidateProfile','AndroidMTUMeasurementGate'):
        shutil.copyfile(java/(name+'.java'),app/(name+'.java'))
    ui = {
        'android/system/StructStat.java': 'package android.system;public final class StructStat{public long st_dev,st_ino;}',
        'android/system/Os.java': 'package android.system;public final class Os{public static volatile java.util.function.Consumer<String> beforeLstat;public static StructStat lstat(String path)throws Exception{var hook=beforeLstat;if(hook!=null)hook.accept(path);try{java.util.Map<String,Object> a=java.nio.file.Files.readAttributes(java.nio.file.Path.of(path),"unix:dev,ino",java.nio.file.LinkOption.NOFOLLOW_LINKS);StructStat s=new StructStat();s.st_dev=((Number)a.get("dev")).longValue();s.st_ino=((Number)a.get("ino")).longValue();return s;}catch(java.nio.file.NoSuchFileException missing){throw new ErrnoException("lstat",OsConstants.ENOENT);}}}',
        'android/system/ErrnoException.java': 'package android.system;public final class ErrnoException extends Exception{public final int errno;public ErrnoException(String operation,int errno){super(operation);this.errno=errno;}}',
        'android/system/OsConstants.java': 'package android.system;public final class OsConstants{public static final int ENOENT=2;}',
        'android/app/Activity.java': 'package android.app;public class Activity extends android.content.Context{final android.content.Context original;public Activity(android.content.Context original){super(original.getFilesDir());this.original=original;}public android.content.Context getApplicationContext(){return original;}public android.content.MemoryPreferences getSharedPreferences(String key,int mode){return original.getSharedPreferences(key,mode);}public boolean isFinishing(){return false;}public boolean isDestroyed(){return false;}public void runOnUiThread(Runnable action){action.run();}}',
        'android/app/AlertDialog.java': 'package android.app;public class AlertDialog{public interface Click{void run(AlertDialog d,int which);}public interface Dismiss{void run(AlertDialog d);}public static volatile AlertDialog last;public CharSequence[] items;public Click selected,negative,positive;boolean showing;Dismiss dismissed;public boolean isShowing(){return showing;}public void show(){showing=true;last=this;}public void dismiss(){showing=false;if(dismissed!=null)dismissed.run(this);}public void setOnDismissListener(Dismiss callback){dismissed=callback;}public static class Builder{final AlertDialog dialog=new AlertDialog();public Builder(Activity a){}public Builder setTitle(String text){return this;}public Builder setMessage(String text){return this;}public Builder setItems(CharSequence[] items,Click callback){dialog.items=items;dialog.selected=callback;return this;}public Builder setNegativeButton(String text,Click callback){dialog.negative=callback;return this;}public Builder setPositiveButton(String text,Click callback){dialog.positive=callback;return this;}public Builder setView(Object view){return this;}public AlertDialog create(){return dialog;}public AlertDialog show(){dialog.show();return dialog;}}}',
        'android/widget/TextView.java': 'package android.widget;public class TextView{public static volatile String latest="";public TextView(android.content.Context c){}public void setPadding(int a,int b,int c,int d){}public void setTextIsSelectable(boolean value){}public void setText(String text){latest=text;}}',
        'android/widget/LinearLayout.java': 'package android.widget;public class LinearLayout{public static final int VERTICAL=1;public LinearLayout(android.content.Context c){}public void setOrientation(int value){}public void addView(Object view){}}',
        'android/widget/Button.java': 'package android.widget;public class Button{public interface Click{void run(Button b);}public static volatile Button last;public Click click;public Button(android.content.Context c){last=this;}public void setText(String value){}public void setOnClickListener(Click value){click=value;}}',
        'android/widget/EditText.java': 'package android.widget;public class EditText{public static volatile EditText last;public String text="";public EditText(android.content.Context c){last=this;}public void setHint(String value){}public CharSequence getText(){return text;}}',
        'android/widget/ScrollView.java': 'package android.widget;public class ScrollView{public ScrollView(android.content.Context c){}public void addView(Object view){}}',
    }
    for name,body in ui.items():
        target=src/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(body)
    (app/'AndroidNodeChainSession.java').write_text(SESSION)
    (app/'NodeCandidateHarness.java').write_text(HARNESS)
    native=src/'io/nekohasekai/libbox'
    (native/'CommandServer.java').write_text('package io.nekohasekai.libbox;public class CommandServer{}')
    (native/'RouterNodeChainCandidateCatalog.java').write_text('package io.nekohasekai.libbox;public interface RouterNodeChainCandidateCatalog{String currentInventorySHA256();}')
    (native/'RouterNodeChainCandidateMeasurement.java').write_text(NATIVE)
    p=native/'Libbox.java';s=p.read_text();s=s[:-1]+r'''
public static boolean routerNodeChainCandidateInputSupported(String input)throws Exception{return "true".equals(call("candidate-supported",input));}
public static RouterNodeChainCandidateMeasurement routerNodeChainNewCandidateMeasurement(RouterNodeChain plan,CommandServer server,int position,String inventory,RouterNodeChainCandidateCatalog catalog)throws Exception{RouterNodeChainCandidateMeasurement value=new RouterNodeChainCandidateMeasurement(plan,position,inventory,catalog);if(RouterNodeChainCandidateMeasurement.factoryFailure)throw new IllegalStateException("late original callback");return value;}
public static void routerNodeChainCloseCandidateMeasurement(RouterNodeChain plan,int position,String inventory)throws Exception{RouterNodeChainCandidateMeasurement.last.close();}
}''';p.write_text(s)


def generate_fixture(root, work, env):
    generator=work/'android_candidate_fixture_test.go';generator.write_text(chain.GENERATOR.replace('nodes:=nodeChainModeFixtureNodes(t,modes,layers)', r'''nodes:=nodeChainModeFixtureNodes(t,modes,layers)
  for position,node:=range nodes{if node.mode=="shadowsocks"{var assets map[string]string;_ = json.Unmarshal([]byte(node.inputs.Files),&assets);graph:=externalTestRead(t,string(mustDecodeChainAsset(t,assets["sing-box.json"])));out:=graph["outbounds"].([]any)[0].(map[string]any);out["method"]="2022-blake3-aes-256-gcm";assets["sing-box.json"]=base64.StdEncoding.EncodeToString([]byte(startJSON(t,graph)));var err error;nodes[position],err=NewNodeProfile(node.mode,startJSON(t,assets),node.inputs.ProfileJSON,node.inputs.Start,"");if err!=nil{t.Fatal(err)}}}'''))
    overlay=work/'candidate-overlay.json';overlay.write_text(json.dumps({'Replace':{str(root/'internal/mobilemultihop/android_candidate_fixture_test.go'):str(generator)}}))
    env=dict(env,ROUTERVPN_ANDROID_CHAIN_FIXTURE=str(work/'candidate-originals.json'))
    subprocess.run(['go','test','-count=1','-overlay='+str(overlay),'./internal/mobilemultihop','-run','^TestAndroidOrderedSourceFixture$'],cwd=root,env=env,check=True,timeout=180)
    return env


def run(root, work, app, classes, jar, env, imported_only=False):
    env = generate_fixture(root, work, env)
    data=work/'candidate-data';data.mkdir()
    subprocess.run(['java','-cp',str(classes)+os.pathsep+str(jar),'com.eabusham.routervpn.NodeCandidateHarness',str(data)],env=env,check=True,timeout=120)
    controls = (
        ('AndroidNodeCandidateCatalog', 'original.source!=originalSource', 'false', 'same-byte foreign source bound captured catalog'),
        ('AndroidNodeCandidateCatalog', 'catch(Exception changed){savedSourcesInvalidated=true;throw changed;}', 'catch(Exception changed){throw changed;}', 'prepermission source change-away/back revived catalog'),
        ('AndroidNodeCandidateProfile', 'private void requireCurrent()throws Exception {operation.requireResult(result);}', 'private void requireCurrent()throws Exception {}', 'retired candidate saved a future profile'),
        ('AndroidNodeCandidateCatalog', '||!signature.equals(currentSignature())', '||false', 'unsupported candidate source replacement accepted'),
        ('AndroidNodeCandidateCatalog', '+before.st_dev+":"+before.st_ino+":"', '+""', 'same-byte replacement revived original file identity'),
        ('AndroidNodeCandidateCatalog', 'return before.st_dev + ":" + before.st_ino + ":" + AndroidTorProfile.digest(bytes);', 'return AndroidTorProfile.digest(bytes);', 'same-byte imported container replacement revived original identity'),
        ('AndroidNodeCandidateMeasurement', 'catch(Throwable observerFailure){ /* An observer cannot abandon retained native cleanup. */ }', 'catch(Throwable observerFailure){ throw observerFailure; }', 'original native cleanup did not finish'),
        ('AndroidNodeCandidateResult', 'integer(benchmark,"failed")!=0', 'false', 'foreign/partial candidate receipt accepted: failed'),
        ('AndroidNodeCandidateResult', 'expires-measured!=120000', 'false', 'foreign/partial candidate receipt accepted: expiry'),
        ('AndroidNodeCandidateMeasurement', 'boolean joined=false;', 'AndroidMTUMeasurementGate.release(lease);boolean joined=false;', 'failed close released original MTU/worker ownership'),
        ('AndroidNodeCandidateMeasurement', 'if(!borrowedLease)AndroidMTUMeasurementGate.release(lease);', 'AndroidMTUMeasurementGate.release(lease);', 'borrowed candidate released the outer graph MTU lease'),
        ('AndroidNodeCandidateMeasurement', 'boolean joined=false;', 'this.joined.countDown();boolean joined=false;', 'borrowed candidate published join before native cleanup'),
        ('AndroidNodeCandidateMeasurement', 'try{callback.finished(failure);}catch(Throwable ignored){}', 'callback.finished(failure);', 'disposed completion observer escaped the retained cleanup worker'),
        ('AndroidNodeCandidateCatalog', 'if(signature!=null&&!signature.equals(current))savedSourcesInvalidated=true;', '', 'observed source change-away/back revived post-DOWN catalog authority'),
        ('AndroidNodeCandidateCatalog', 'if(savedSourcesInvalidated||!signature.equals(observed))', 'if(!signature.equals(observed))', 'overlapping observed source change revived detached authority'),
    )
    for index,(name,old,new,witness) in enumerate(controls):
        original=(app/(name+'.java')).read_text();assert original.count(old)==1,old
        source=work/('candidate-mutant-'+str(index));source.mkdir();mutation=source/(name+'.java');mutation.write_text(original.replace(old,new))
        target=source/'classes';shutil.copytree(classes,target);classpath=str(target)+os.pathsep+str(jar)
        subprocess.run(['javac','--release','17','-cp',classpath,'-d',str(target),str(mutation)],check=True,timeout=60)
        private=source/'private';private.mkdir()
        failed=subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeCandidateHarness',str(private)],env=env,capture_output=True,text=True,timeout=120)
        assert failed.returncode!=0 and witness in failed.stderr,failed.stdout+failed.stderr
        print('Android candidate causal control rejected:',name,witness,flush=True)



if __name__=='__main__':
    chain.prepare_sources=prepare;chain.compiler_source=compiler;chain.run=run
    sys.argv=[sys.argv[0],'--case-family','ordered-chain'];profiles.main()
