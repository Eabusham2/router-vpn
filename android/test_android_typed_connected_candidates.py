#!/usr/bin/env python3
"""Shipping connected typed chooser against actual stores and shared compilers.

Java native handles and completed TCP callbacks are explicit boundary models.
The source, complete future-profile compiler, original catalog and operation
ownership are real. Actual native fifty-socket/Box proof has its separate gate.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import test_android_node_candidate_prefix_capture as prefix
from test_android_typed_candidate_abi import verify_factory_abi

candidates = prefix.candidates
chain = candidates.chain
profiles = candidates.profiles


def compiler(source):
    source = prefix.compiler(source)
    before = 'case len(args)==2:'
    cases = r'''case len(args)==4&&args[0]=="typed-connected-socks-metadata":var original *mobilemultihop.NodeChainSOCKSSource;original,err=mobilemultihop.NewNodeChainSOCKSSource(args[1]);if err==nil{var runtime *mobilemultihop.NodeChainSOCKSRuntime;runtime,err=mobilemultihop.NewNodeChainSOCKSRuntime(original);if err==nil{var position int;_,err=fmt.Sscan(args[2],&position);if err==nil{var captured *mobilemultihop.NodeChainSOCKSConnectedCandidatePlan;captured,err=mobilemultihop.NewNodeChainSOCKSConnectedCandidatePlan(runtime,position,args[3]);if err==nil{result=captured.Metadata()}}}};case len(args)==4&&args[0]=="typed-connected-connect-metadata":var original *mobilemultihop.NodeChainCONNECTSource;original,err=mobilemultihop.NewNodeChainCONNECTSource(args[1]);if err==nil{var runtime *mobilemultihop.NodeChainCONNECTRuntime;runtime,err=mobilemultihop.NewNodeChainCONNECTRuntime(original);if err==nil{var position int;_,err=fmt.Sscan(args[2],&position);if err==nil{var captured *mobilemultihop.NodeChainCONNECTConnectedCandidatePlan;captured,err=mobilemultihop.NewNodeChainCONNECTConnectedCandidatePlan(runtime,position,args[3]);if err==nil{result=captured.Metadata()}}}};'''
    if source.count(before) != 1:
        raise AssertionError('Actual shared compiler command boundary changed')
    return source.replace(before, cases+before)


def native_state():
    # Keep the existing explicitly modelled receipt payload, including its
    # complete fifty-sample fields, and obtain metadata from the actual new
    # shared typed plan. This double never asserts native Run/Box acceptance.
    # Remove only the ordinary reservation hooks before reusing the original
    # typed model. Every seam is exact; generated typed state remains unchanged.
    source = candidates.NATIVE
    normalizations = (
        (' private static final java.util.IdentityHashMap<RouterNodeChain,RouterNodeChainCandidateMeasurement> slots=new java.util.IdentityHashMap<>();\n final RouterNodeChain owner;final String info;final RouterNodeChainCandidateCatalog guard;String original="";String request="",id="";boolean closed,prepareAttempted,prepared;', ' final String info;final RouterNodeChainCandidateCatalog guard;final String original;String request="",id="";'),
        (' RouterNodeChainCandidateMeasurement(RouterNodeChain plan,int prefix,String inventory,RouterNodeChainCandidateCatalog guard)throws Exception{\n  info=Libbox.call("candidate-metadata",plan.launchInput(),Integer.toString(prefix),inventory);this.guard=guard;owner=plan;\n  synchronized(slots){if(slots.containsKey(plan))throw new IllegalStateException("Original candidate reservation remains owned");slots.put(plan,this);last=this;}\n }\n public void prepare()throws Exception{\n  synchronized(slots){if(closed||slots.get(owner)!=this||prepareAttempted)throw new IllegalStateException("Foreign or repeated ordinary preparation");prepareAttempted=true;}\n  String captured=guard.currentInventorySHA256();if(factoryFailure)throw new IllegalStateException("late original callback");\n  if(captured.isEmpty())throw new IllegalStateException("Original candidate catalog retired");\n  synchronized(slots){if(closed||slots.get(owner)!=this)throw new IllegalStateException("Retired ordinary preparation");original=captured;prepared=true;}\n }\n public boolean isClosed(){synchronized(slots){return closed;}}\n private void requirePrepared(){synchronized(slots){if(closed||slots.get(owner)!=this||!prepared)throw new IllegalStateException("Original ordinary candidate did not prepare");}}', ' RouterNodeChainCandidateMeasurement(RouterNodeChain plan,int prefix,String inventory,RouterNodeChainCandidateCatalog guard)throws Exception{\n  info=Libbox.call("candidate-metadata",plan.launchInput(),Integer.toString(prefix),inventory);this.guard=guard;original=guard.currentInventorySHA256();last=this;\n }'),
        (' public void start(String request,String id){requirePrepared();this.request=request;this.id=id;}', ' public void start(String request,String id){this.request=request;this.id=id;}'),
        (' public void close()throws Exception{synchronized(slots){RouterNodeChainCandidateMeasurement retained=slots.get(owner);if(retained!=null&&retained!=this)throw new IllegalStateException("Foreign ordinary cleanup receipt");if(closed)return;if(retained!=this)throw new IllegalStateException("Missing original ordinary cleanup receipt");closeAttempts++;if(holdClose)throw new IllegalStateException("Original native callback not joined");closed=true;slots.remove(owner);}}', ' public void close()throws Exception{closeAttempts++;if(holdClose)throw new IllegalStateException("Original native callback not joined");}'),
        (' public String statusJSON()throws Exception{requirePrepared();\n', ' public String statusJSON()throws Exception{\n'),
    )
    for before, after in normalizations:
        if source.count(before) != 1:
            raise AssertionError('Ordinary reservation fixture seam changed')
        source = source.replace(before, after)
    source = source.replace('RouterNodeChainCandidateMeasurement', 'TypedCandidateState').replace('public final class TypedCandidateState', 'public class TypedCandidateState')
    old = ''' TypedCandidateState(RouterNodeChain plan,int prefix,String inventory,RouterNodeChainCandidateCatalog guard)throws Exception{
  info=Libbox.call("candidate-metadata",plan.launchInput(),Integer.toString(prefix),inventory);this.guard=guard;original=guard.currentInventorySHA256();last=this;
 }'''
    new = ''' public static volatile Object expectedOwner;public static volatile CommandServer expectedServer;public static volatile int factories,prepares,starts;public static volatile String factory="",fault="";public static volatile TypedCandidateState slot;
 public static volatile boolean prepareFailure;public final Object owner;public final CommandServer server;public final int prefix;public final String inventory;public boolean closed,prepareAttempted,prepared;
 TypedCandidateState(String command,String source,Object owner,CommandServer server,int prefix,String inventory,RouterNodeChainCandidateCatalog guard)throws Exception{
  factories++;if(owner==null||owner!=expectedOwner||server==null||server!=expectedServer)throw new IllegalStateException("foreign typed fixture owner or server");
  this.owner=owner;this.server=server;this.prefix=prefix;this.inventory=inventory;factory=command;
  info=Libbox.call(command,source,Integer.toString(prefix),inventory);this.guard=guard;
  synchronized(TypedCandidateState.class){if(slot!=null)throw new IllegalStateException("original typed candidate slot remains owned");slot=this;last=this;}
 }
 public synchronized void prepare()throws Exception{if(closed||slot!=this||prepareAttempted)throw new IllegalStateException("foreign or repeated typed preparation");prepareAttempted=true;prepares++;original=guard.currentInventorySHA256();if(prepareFailure)throw new IllegalStateException("late original typed preparation");if(original.isEmpty())throw new IllegalStateException("typed original catalog retired");prepared=true;}
 private void requirePrepared(){if(closed||slot!=this||!prepared)throw new IllegalStateException("typed candidate was not prepared by its original handle");}
 public static void reset(Object owner,CommandServer server){if(slot!=null)throw new IllegalStateException("old typed callback still owns its slot");expectedOwner=owner;expectedServer=server;factories=0;prepares=0;starts=0;closeAttempts=0;factory="";fault="";holdClose=false;prepareFailure=false;last=null;}
 public static String sourceOf(Object owner)throws Exception{return owner instanceof RouterNodeChainSOCKS?((RouterNodeChainSOCKS)owner).source():((RouterNodeChainCONNECT)owner).source();}
 public static String compileSource(String...args)throws Exception{return Libbox.call(args);}'''
    if source.count(old) != 1:
        raise AssertionError('Original explicit candidate boundary constructor changed')
    source = source.replace(old, new)
    source = source.replace('final String original;', 'String original="";')
    source = source.replace('public String metadata(){return info;}', '''public String metadata(){requirePrepared();try{JSONObject changed=new JSONObject(info);switch(fault){case "source":changed.put("source_sha256","f".repeat(64));break;case "config":changed.put("config_sha256","f".repeat(64));break;case "capture":changed.put("capture_sha256","f".repeat(64));break;case "position":changed.put("prefix_position",prefix+1);break;}return changed.toString();}catch(Exception failure){throw new IllegalStateException(failure);}}''')
    source = source.replace('this.request=request;this.id=id;', 'requirePrepared();this.request=request;this.id=id;starts++;')
    source = source.replace('public String statusJSON()throws Exception{', 'public String statusJSON()throws Exception{requirePrepared();')
    source = source.replace('public void close()throws Exception{closeAttempts++;if(holdClose)throw new IllegalStateException("Original native callback not joined");}', 'public void close()throws Exception{synchronized(TypedCandidateState.class){if(slot!=null&&slot!=this)throw new IllegalStateException("foreign typed cleanup receipt");if(closed)return;if(slot!=this)throw new IllegalStateException("missing original typed cleanup receipt");closeAttempts++;if(holdClose)throw new IllegalStateException("Original native callback not joined");closed=true;slot=null;}}')
    return source


HARNESS = r'''package com.eabusham.routervpn;
import java.nio.file.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import org.json.*;import io.nekohasekai.libbox.*;
public final class TypedConnectedCandidateHarness {
 static int checks;static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
 interface Work{void run()throws Exception;}static void reject(Work work,String message)throws Exception{try{work.run();}catch(Exception refused){checks++;return;}throw new AssertionError(message);}
 static Object owner(AndroidNodeChainSession session){return session.capture.socks!=null?session.capture.socks.plan:session.capture.connect.plan;}
 static String source(AndroidNodeChainSession session)throws Exception{return TypedCandidateState.sourceOf(owner(session));}
 static String command(String wire){return wire.equals("socks5")?"typed-connected-socks-metadata":"typed-connected-connect-metadata";}
 static NodeChainCaptureHarness.Fixture fixture(Path root,String wire,int count,boolean alternative)throws Exception{
  var f=NodeCandidatePrefixCaptureHarness.typedFixture(root,wire,count);
  if(alternative){var entry=new AndroidStandardExitStore.Entry();entry.id="fedcba9876543210fedcba9876543210";entry.name="Measured typed replacement";entry.protocol=wire;entry.server="198.51.100.77";entry.serverPort=9443;entry.expectedPublicIp="203.0.113.77";entry.username="replacement-user";entry.password="replacement-private-password";entry.tlsServerName="replacement.proxy.example";entry.policy.put("start_layer","off").put("dns_mode","rescue").put("home_lan_access",false).put("kill_switch_policy","always");new AndroidStandardExitStore(f.context).save(entry);}
  return f;
 }
 static final class Completion implements AndroidNodeCandidateMeasurement.Callback {
  final CountDownLatch ready=new CountDownLatch(1),done=new CountDownLatch(1),closing=new CountDownLatch(1);volatile List<AndroidNodeCandidateResult> rows=List.of();volatile Throwable failure;
  public void changed(List<AndroidNodeCandidateResult> values,String detail){rows=values;if(detail.startsWith("Cancelling;"))closing.countDown();if(values.stream().anyMatch(row->row.id.equals("fedcba9876543210fedcba9876543210")))ready.countDown();}
  public void finished(Throwable value){failure=value;done.countDown();}
 }
 static void finish(AndroidNodeCandidateMeasurement operation,Completion callback)throws Exception{TypedCandidateState.holdClose=false;operation.cancel();check(callback.done.await(10,TimeUnit.SECONDS)&&operation.joined(),"typed measurement did not join its original cleanup");check(!AndroidNodeCandidateMeasurement.busy()&&!AndroidMTUMeasurementGate.held(),"joined typed measurement retained parent activity");}
 static void positive(Path root,String wire)throws Exception{
  for(int count:new int[]{3,4,8}){
   var f=fixture(root,wire,count,true);var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var before=new NodeChainCaptureHarness.State(f);String original=source(session);int position=count-3;
   var catalog=new AndroidNodeCandidateCatalog(f.context,session,position);TypedCandidateState.reset(owner(session),session.server);Completion callback=new Completion();var operation=AndroidNodeCandidateMeasurement.start(catalog,callback);
   try{
    check(callback.ready.await(20,TimeUnit.SECONDS),"typed connected host never delivered its captured candidate: "+wire+"/"+count);
    check(TypedCandidateState.factory.equals(command(wire))&&TypedCandidateState.factories==1&&TypedCandidateState.prepares==1&&TypedCandidateState.last.owner==owner(session)&&TypedCandidateState.last.server==catalog.server,"typed host substituted its native family or original owner");
    JSONObject meta=new JSONObject(TypedCandidateState.last.metadata());check(meta.getString("source_sha256").equals(session.capture.sourceSHA256)&&meta.getString("config_sha256").equals(session.capture.configSHA256)&&meta.getInt("prefix_position")==position&&meta.getString("prefix_id").equals(session.source.members.get(position).profileId),"typed metadata lost complete captured source or ordered packet prefix");
    check(session.capture.plan==null&&session.capture.memberInputs.size()==count,"typed connected host borrowed an ordinary graph");
    reject(()->TypedCandidateState.compileSource("candidate-metadata",original,Integer.toString(position),catalog.inventory),"generic connected candidate parser accepted typed source");
    reject(()->TypedCandidateState.compileSource(command(wire),original,Integer.toString(count-2),catalog.inventory),"typed imported middle became candidate packet prefix");
    reject(()->TypedCandidateState.compileSource(command(wire),original,Integer.toString(count-1),catalog.inventory),"typed final became candidate packet prefix");
    var measured=callback.rows.stream().filter(row->row.id.equals("fedcba9876543210fedcba9876543210")).findFirst().orElseThrow();operation.requireResult(measured);
    AndroidVpnMutationGuard.busy=true;var proposal=new AndroidNodeCandidateProfile(operation,measured);var saved=proposal.save(f.context,"Connected "+wire+" "+count);
    var after=new NodeChainCaptureHarness.State(f);for(Path path:before.files.keySet())if(!path.equals(f.rows))check(Arrays.equals(before.files.get(path),after.files.get(path)),"typed profile Save changed an active private source");check(before.preferences.equals(after.preferences),"typed profile Save changed active settings");
    JSONArray all=new JSONObject(Files.readString(f.rows)).getJSONArray("profiles");JSONObject record=all.getJSONObject(all.length()-1);JSONArray members=record.getJSONArray("multihop_nodes");
    check(members.length()==count&&record.getString("multihop_execution").equals("local"),"typed proposal truncated its suffix or reran execution selection");
    for(int index=0;index<count;index++)check(members.getJSONObject(index).getString("id").equals(index==position+1?measured.id:session.source.members.get(index).profileId),"typed proposal replaced a different original position");
    check(!record.toString().contains("replacement-private-password")&&!record.toString().contains("wg_private_key"),"typed future profile duplicated private credentials");
    reject(()->f.profiles.load(saved.id),"typed future profile loaded over active native connection");
    var duplicate=callback.rows.stream().filter(row->row.id.equals(session.source.control.profileId)).findFirst().orElseThrow();reject(()->new AndroidNodeCandidateProfile(operation,duplicate),"typed future profile duplicated its retained final identity");
    check(original.equals(source(session))&&AndroidMTUMeasurementGate.held(),"typed Save retired original source or measurement lease");
    finish(operation,callback);check(original.equals(source(session)),"typed measurement cleanup retired the complete original owner");
    session.current=false;AndroidVpnMutationGuard.busy=false;f.profiles.load(saved.id);
    try(var loaded=AndroidNodeChainCapture.compile(f.profiles.currentOrderedPath())){check(loaded.plan==null&&loaded.memberInputs.size()==count&&(wire.equals("socks5")?loaded.socks!=null:loaded.connect!=null),"typed saved profile failed complete normal Load compilation");}
   }finally{AndroidVpnMutationGuard.busy=false;if(!operation.joined())finish(operation,callback);}
  }
 }
 static void metadata(Path root)throws Exception{
  for(String wire:List.of("socks5","https"))for(String fault:List.of("source","config","capture","position")){
   var f=fixture(root,wire,3,true);var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);TypedCandidateState.reset(owner(session),session.server);TypedCandidateState.fault=fault;
   Completion callback=new Completion();var operation=AndroidNodeCandidateMeasurement.start(catalog,callback);
   try{check(callback.done.await(10,TimeUnit.SECONDS)&&callback.failure!=null&&TypedCandidateState.starts==0,"foreign typed candidate metadata was accepted: "+fault);check(TypedCandidateState.last.closed&&!AndroidMTUMeasurementGate.held(),"foreign typed metadata abandoned its exact candidate slot");}
   finally{TypedCandidateState.fault="";if(!operation.joined())finish(operation,callback);}
  }
 }
 static void localOnly(Path root)throws Exception{
  for(String wire:List.of("socks5","http","https"))for(String execution:List.of("server","auto")){
   var f=fixture(root,wire,3,true);f.chooseExecution(execution);var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);TypedCandidateState.reset(owner(session),session.server);Completion callback=new Completion();var operation=AndroidNodeCandidateMeasurement.start(catalog,callback);
   try{check(callback.done.await(10,TimeUnit.SECONDS)&&callback.failure!=null&&TypedCandidateState.factories==0&&TypedCandidateState.closeAttempts==0,"Server or Compare borrowed an unused Local candidate owner");check(!AndroidMTUMeasurementGate.held()&&!AndroidNodeCandidateMeasurement.busy(),"unstarted typed refusal retained candidate activity");}
   finally{if(!operation.joined())finish(operation,callback);}
  }
 }
 static void lifetime(Path root,boolean failedPrepare)throws Exception{
  for(String wire:List.of("socks5","https")){
   var f=fixture(root,wire,3,true);var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);TypedCandidateState.reset(owner(session),session.server);TypedCandidateState.prepareFailure=failedPrepare;TypedCandidateState.holdClose=true;Completion callback=new Completion();var operation=AndroidNodeCandidateMeasurement.start(catalog,callback);
   try{
    if(!failedPrepare)check(callback.ready.await(15,TimeUnit.SECONDS),"typed lifetime never received complete callback");operation.cancel();
    check(callback.closing.await(10,TimeUnit.SECONDS),"typed failed cleanup did not retain its original callback");
    check(!operation.joined()&&AndroidNodeCandidateMeasurement.busy()&&AndroidMTUMeasurementGate.held(),"typed pending close released original measurement authority");
    reject(()->AndroidNodeCandidateMeasurement.start(catalog,null),"typed replacement acquired an unjoined measurement slot");
    if(failedPrepare)check(TypedCandidateState.prepares==1&&TypedCandidateState.closeAttempts>0&&TypedCandidateState.slot==TypedCandidateState.last,"typed failed preparation lost its returned handle");
   }finally{TypedCandidateState.prepareFailure=false;finish(operation,callback);}
   check(source(session).equals(TypedCandidateState.sourceOf(owner(session))),"typed candidate cleanup lost complete source");
  }
 }
 static TypedCandidateState reserve(AndroidNodeChainSession session,AndroidNodeCandidateCatalog catalog)throws Exception{return session.capture.socks!=null?Libbox.routerNodeChainSOCKSNewCandidateMeasurement(session.capture.socks.plan,catalog.server,catalog.prefix,catalog.inventory,catalog):Libbox.routerNodeChainCONNECTNewCandidateMeasurement(session.capture.connect.plan,catalog.server,catalog.prefix,catalog.inventory,catalog);}
 static void reservation(Path root)throws Exception{
  for(String wire:List.of("socks5","https")){
   var f=fixture(root,wire,3,true);var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);TypedCandidateState.reset(owner(session),session.server);
   var original=reserve(session,catalog);check(TypedCandidateState.prepares==0&&!original.prepareAttempted,"typed constructor admitted callback work before returning its handle");original.prepare();reject(original::prepare,"typed candidate prepared twice");
   Completion callback=new Completion();var operation=AndroidNodeCandidateMeasurement.start(catalog,callback);
   try{
    check(callback.done.await(10,TimeUnit.SECONDS)&&callback.failure!=null&&operation.joined(),"same-key duplicate constructor did not finish its refusal");
    check(TypedCandidateState.slot==original&&!original.closed&&TypedCandidateState.closeAttempts==0&&TypedCandidateState.prepares==1,"refused same-key constructor closed an earlier active native operation");
    check(!AndroidMTUMeasurementGate.held()&&!AndroidNodeCandidateMeasurement.busy(),"refused constructor retained Java activity");original.close();
    var replacement=reserve(session,catalog);replacement.prepare();reject(original::close,"old handle accepted a same-key replacement cleanup receipt");check(TypedCandidateState.slot==replacement&&!replacement.closed,"old handle cleanup retired a same-key replacement");replacement.close();
   }finally{TypedCandidateState.holdClose=false;if(!operation.joined())finish(operation,callback);if(TypedCandidateState.slot!=null)TypedCandidateState.slot.close();}
  }
 }
 static void sourceChanges(Path root)throws Exception{
  for(String fault:List.of("session","server","file-aba")){
   var f=fixture(root,"socks5",3,true);var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);TypedCandidateState.reset(owner(session),session.server);Completion callback=new Completion();var operation=AndroidNodeCandidateMeasurement.start(catalog,callback);
   try{
    check(callback.ready.await(15,TimeUnit.SECONDS),"typed source-change test never received original completion");var result=callback.rows.stream().filter(row->row.id.equals("fedcba9876543210fedcba9876543210")).findFirst().orElseThrow();
    if(fault.equals("session"))session.current=false;else if(fault.equals("server"))session.server=new CommandServer();else{Path path=f.control().file.toPath();byte[] saved=Files.readAllBytes(path);Files.writeString(path,new String(saved,java.nio.charset.StandardCharsets.UTF_8)+" ");check(catalog.currentInventorySHA256().isEmpty(),"typed catalog accepted changed original source");Files.write(path,saved);}
    reject(()->operation.requireResult(result),"typed stale owner/source still offered Save: "+fault);
    check(callback.done.await(10,TimeUnit.SECONDS),"typed replaced owner did not join original candidate");check(TypedCandidateState.last.closed,"typed stale host abandoned original candidate cleanup");
   }finally{if(!operation.joined())finish(operation,callback);}
  }
 }
 static boolean replacementMeasured(String text){for(String line:text.split("\\R"))if(line.startsWith("Measured typed replacement • ")&&line.endsWith(" ms (50/50, trimmed mean)"))return true;return false;}
 static void presentation(Path root)throws Exception{
  var f=fixture(root,"https",4,true);var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());TypedCandidateState.reset(owner(session),session.server);
  var dialog=new AndroidNodeCandidateDialog(new android.app.Activity(f.context));dialog.show();
  try{
   var prefixes=android.app.AlertDialog.last;check(prefixes.items.length==2,"typed connected picker lost its complete packet prefix choices");prefixes.selected.run(prefixes,prefixes.items.length-1);
   long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(20);while(!replacementMeasured(android.widget.TextView.latest)&&System.nanoTime()<deadline)Thread.sleep(1);
   check(replacementMeasured(android.widget.TextView.latest),"typed connected UI did not publish the replacement's own complete score: "+android.widget.TextView.latest);
   check(android.widget.TextView.latest.contains("50/50")&&android.widget.TextView.latest.contains("not HTTP, ICMP"),"typed connected UI changed candidate TCP measurement scope");
   android.widget.Button.last.click.run(android.widget.Button.last);var candidates=android.app.AlertDialog.last;int chosen=-1;
   for(int index=0;index<candidates.items.length;index++)if(candidates.items[index].toString().startsWith("Measured typed replacement"))chosen=index;
   check(chosen>=0,"typed connected chooser lost its measured saved source");candidates.selected.run(candidates,chosen);
   deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);while((android.widget.EditText.last==null||android.app.AlertDialog.last.positive==null)&&System.nanoTime()<deadline)Thread.sleep(1);
   check(android.widget.EditText.last!=null&&android.app.AlertDialog.last.positive!=null,"typed connected UI did not compile a complete named proposal");android.widget.EditText.last.text="Typed UI future path";android.app.AlertDialog.last.positive.run(android.app.AlertDialog.last,0);
   deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);while(System.nanoTime()<deadline){try{if(f.profiles.list().stream().anyMatch(row->row.name.equals("Typed UI future path")))break;}catch(org.json.JSONException writing){}Thread.sleep(1);}
   check(f.profiles.list().stream().anyMatch(row->row.name.equals("Typed UI future path")),"typed connected UI Save did not retain complete compiled proposal");session.requireCurrent();
  }finally{dialog.close();long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);while(AndroidNodeCandidateMeasurement.busy()&&System.nanoTime()<deadline)Thread.sleep(1);check(!AndroidNodeCandidateMeasurement.busy()&&!AndroidMTUMeasurementGate.held(),"typed connected Activity close lost exact candidate cleanup");}
 }
 public static void main(String[] args)throws Exception{
  try{Path root=Path.of(args[0]);switch(args[1]){case "socks"->positive(root,"socks5");case "http"->positive(root,"http");case "https"->positive(root,"https");case "metadata"->metadata(root);case "local-only"->localOnly(root);case "lifetime"->lifetime(root,false);case "prepare-recovery"->lifetime(root,true);case "reservation"->reservation(root);case "source-change"->sourceChanges(root);case "presentation"->presentation(root);default->throw new IllegalArgumentException("Unknown typed connected phase");}
   System.out.println("Android typed connected "+args[1]+": "+checks+" actual source/host checks PASS; native transport callbacks are modelled");
  }finally{AndroidVpnMutationGuard.busy=false;TypedCandidateState.holdClose=false;AndroidNodeCandidateMeasurement.cancelActive();}
 }
}'''


def prepare(src, app, java):
    prefix.prepare(src, app, java)
    (app/'TypedConnectedCandidateHarness.java').write_text(HARNESS)
    native = src/'io/nekohasekai/libbox'
    (native/'TypedCandidateState.java').write_text(native_state())
    libbox = native/'Libbox.java'
    source = libbox.read_text()
    for family, command_name in (('SOCKS', 'socks'), ('CONNECT', 'connect')):
        name = 'RouterNodeChain'+family+'CandidateMeasurement'
        (native/(name+'.java')).write_text('''package io.nekohasekai.libbox;
public final class %s extends TypedCandidateState {
 %s(RouterNodeChain%s owner,CommandServer server,int prefix,String inventory,RouterNodeChainCandidateCatalog guard)throws Exception{super("typed-connected-%s-metadata",owner.source(),owner,server,prefix,inventory,guard);}
}''' % (name, name, family, command_name))
        before = '''public static %s routerNodeChain%sNewCandidateMeasurement(RouterNodeChain%s owner,CommandServer server,int prefix,String inventory,Object catalog)throws Exception{throw new IllegalStateException("No typed connected candidate runtime in this ordinary fixture");}''' % (name, family, family)
        after = '''public static %s routerNodeChain%sNewCandidateMeasurement(RouterNodeChain%s owner,CommandServer server,int prefix,String inventory,RouterNodeChainCandidateCatalog catalog)throws Exception{return new %s(owner,server,prefix,inventory,catalog);}''' % (name, family, family, name)
        if source.count(before) != 1:
            raise AssertionError('Typed native source boundary changed: '+family)
        source = source.replace(before, after)
        if 'routerNodeChain'+family+'CloseCandidateMeasurement' in source:
            raise AssertionError('Ambiguous typed cleanup fallback remains: '+family)
    libbox.write_text(source)


CONTROLS = (
    ('return new NativeOwner(Libbox.routerNodeChainSOCKSNewCandidateMeasurement(captured.socks.plan,catalog.server,catalog.prefix,catalog.inventory,catalog));', 'return new NativeOwner(Libbox.routerNodeChainNewCandidateMeasurement(captured.plan,catalog.server,catalog.prefix,catalog.inventory,catalog));', 'socks', 'typed connected host never delivered its captured candidate: socks5/3'),
    ('return new NativeOwner(Libbox.routerNodeChainCONNECTNewCandidateMeasurement(captured.connect.plan,catalog.server,catalog.prefix,catalog.inventory,catalog));', 'return new NativeOwner(Libbox.routerNodeChainNewCandidateMeasurement(captured.plan,catalog.server,catalog.prefix,catalog.inventory,catalog));', 'http', 'typed connected host never delivered its captured candidate: http/3'),
    ('||!(prefix==null?catalog.session.capture.sourceSHA256:prefix.sourceSHA256).equals(metadata.getString("source_sha256"))', '', 'metadata', 'foreign typed candidate metadata was accepted: source'),
    ('||!(prefix==null?catalog.session.capture.configSHA256:prefix.configSHA256).equals(metadata.getString("config_sha256"))', '', 'metadata', 'foreign typed candidate metadata was accepted: config'),
    ('!"local".equals(catalog.session.source.execution)||captured.plan!=null', 'captured.plan!=null', 'local-only', 'Server or Compare borrowed an unused Local candidate owner'),
    ('boolean joined=false;', 'AndroidMTUMeasurementGate.release(lease);boolean joined=false;', 'lifetime', 'typed pending close released original measurement authority'),
    ('nativeOwner.prepare();', 'NativeOwner unretained=nativeOwner;nativeOwner=null;unretained.prepare();', 'prepare-recovery', 'typed failed cleanup did not retain its original callback'),
)


def run(root, work, app, classes, jar, env, imported_only=False):
    env = candidates.generate_fixture(root, work, env)
    classpath = str(classes)+os.pathsep+str(jar)
    for phase in ('socks', 'http', 'https', 'metadata', 'local-only', 'lifetime', 'prepare-recovery', 'reservation', 'source-change', 'presentation'):
        data = work/('typed-connected-'+phase)
        data.mkdir()
        subprocess.run(['java', '-cp', classpath, 'com.eabusham.routervpn.TypedConnectedCandidateHarness', str(data), phase], env=env, check=True, timeout=180)
    original = (app/'AndroidNodeCandidateMeasurement.java').read_text()
    for index, (before, after, phase, witness) in enumerate(CONTROLS):
        if original.count(before) != 1:
            raise AssertionError('Original typed host control changed: '+before)
        private = work/('typed-connected-control-'+str(index));private.mkdir()
        target = private/'classes';shutil.copytree(classes, target)
        source = private/'AndroidNodeCandidateMeasurement.java';source.write_text(original.replace(before, after))
        mutated_classpath = str(target)+os.pathsep+str(jar)
        subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', mutated_classpath, '-d', str(target), str(source)], check=True, timeout=60)
        data = private/'data';data.mkdir()
        result = subprocess.run(['java', '-cp', mutated_classpath, 'com.eabusham.routervpn.TypedConnectedCandidateHarness', str(data), phase], env=env, capture_output=True, text=True, timeout=180)
        if result.returncode != 1 or witness not in result.stderr or 'Exception in thread "main" java.lang.AssertionError: '+witness not in result.stderr:
            raise AssertionError('Typed host omission missed exact runnable witness: '+witness+'\n'+result.stdout+result.stderr)
        print('Android typed connected causal refusal:', witness, flush=True)


if __name__ == '__main__':
    verify_factory_abi()
    chain.compiler_source=compiler;chain.prepare_sources=prepare;chain.run=run
    sys.argv=[sys.argv[0], '--case-family', 'ordered-chain'];profiles.main()
