#!/usr/bin/env python3
"""Execute the shipping multihop Home state boundary and native mode catalog.

The complete Home store and NativeSingBoxController compile unchanged. Android
preferences/OS handles use deterministic boundaries from the graph suite. This
checks live state publication, owner failure, and atomic adoption. A compiled
negative control removes the Home transaction lock and must lose the race.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT/'android/app/src/main/java/com/eabusham/routervpn'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


SOURCES = {
    'android/content/SharedPreferences.java': '''package android.content;
public interface SharedPreferences {
 String getString(String key,String fallback);long getLong(String key,long fallback);
 boolean getBoolean(String key,boolean fallback);Editor edit();
 interface Editor {Editor putString(String key,String value);Editor putLong(String key,long value);
  Editor putBoolean(String key,boolean value);Editor remove(String key);void apply();}
}''',
    'android/content/Context.java': r'''package android.content;
import java.io.File;
import java.util.*;
public final class Context {
 public static final int MODE_PRIVATE=0;
 public final Store store=new Store();public int fileAccesses;
 public Context getApplicationContext(){return this;}
 public SharedPreferences getSharedPreferences(String name,int mode){return store;}
 public File getFilesDir(){fileAccesses++;throw new AssertionError("State publication cannot stage a native session");}
 public Object startService(Intent intent){throw new AssertionError("State publication cannot start a VPN");}
 public Object startForegroundService(Intent intent){throw new AssertionError("State publication cannot start a VPN");}
 public static final class Store implements SharedPreferences {
  public final Map<String,Object> values=Collections.synchronizedMap(new HashMap<>());public int edits,writes;
  public volatile Runnable beforeConnectedApply;
  public String getString(String key,String fallback){synchronized(values){return values.containsKey(key)?(String)values.get(key):fallback;}}
  public long getLong(String key,long fallback){synchronized(values){return values.containsKey(key)?(Long)values.get(key):fallback;}}
  public boolean getBoolean(String key,boolean fallback){synchronized(values){return values.containsKey(key)?(Boolean)values.get(key):fallback;}}
  public Editor edit(){synchronized(values){edits++;}return new Editor(){
   final Map<String,Object> staged=new LinkedHashMap<>();
   public Editor putString(String key,String value){staged.put(key,value);return this;}
   public Editor putLong(String key,long value){staged.put(key,value);return this;}
   public Editor putBoolean(String key,boolean value){staged.put(key,value);return this;}
   public Editor remove(String key){staged.put(key,null);return this;}
   public void apply(){
    Runnable hook=beforeConnectedApply;
    if(hook!=null&&"connected".equals(staged.get("phase"))&&Boolean.TRUE.equals(staged.get("connected")))hook.run();
    synchronized(values){writes++;for(Map.Entry<String,Object> entry:staged.entrySet()){
    if(entry.getValue()==null)values.remove(entry.getKey());else values.put(entry.getKey(),entry.getValue());
   }}}
  };}
 }
}''',
    'com/wireguard/android/backend/Tunnel.java': '''package com.wireguard.android.backend;
public interface Tunnel {enum State {DOWN,UP}}''',
    'org/amnezia/awg/backend/Tunnel.java': '''package org.amnezia.awg.backend;
public interface Tunnel {enum State {DOWN,UP}}''',
    'com/eabusham/routervpn/HomeBoundaries.java': r'''package com.eabusham.routervpn;
import android.content.Context;
final class AndroidTorProfile {static boolean isTor(String protocol){return "tor".equals(protocol)||"tor-bridge".equals(protocol);}}
final class AndroidExternalPolicy {static boolean supports(String protocol){return java.util.Arrays.asList("wireguard","socks5","http","https","shadowsocks","hysteria2").contains(protocol);}}
final class AndroidRuntimeRegistry {
 static final AndroidRuntimeRegistry INSTANCE=new AndroidRuntimeRegistry();
 static AndroidRuntimeRegistry get(Context context){return INSTANCE;}
 final WG wireGuard=new WG();final AWG amneziaWG=new AWG();
 static final class WG {com.wireguard.android.backend.Tunnel.State getState(){return com.wireguard.android.backend.Tunnel.State.DOWN;}}
 static final class AWG {org.amnezia.awg.backend.Tunnel.State getState(){return org.amnezia.awg.backend.Tunnel.State.DOWN;}}
}
''',
    'com/eabusham/routervpn/MultihopHomeHarness.java': r'''package com.eabusham.routervpn;
import android.content.Context;
import org.json.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

public final class MultihopHomeHarness {
 static int checks,pairs,rejections,atomicRaces;static final List<String> failures=new ArrayList<>();
 static final String ENTRY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",EXIT="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
 static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
 static String base(String mode){
  switch(mode){
   case"wg":case"wg-pq":case"max-tls-wg":case"max-quic-wg":return"wg";
   case"awg2-fast":case"awg2-strong":case"awg2-pq":case"max-tls-awg":case"max-quic-awg":return"awg";
   default:return"libbox";
  }
 }
 static Context externalOwner(){
  Context context=new Context();
  AndroidHomeStateStore.beginExternal(context,"external-owner","External","socks5","192.0.2.10","libbox");
  AndroidHomeStateStore.connectedExternal(context,"external-owner","External","socks5","192.0.2.10","libbox","192.0.2.10");
  return context;
 }
 static void verifyIdentity(AndroidHomeStateStore.Snapshot state,String session,String entryMode,String exitMode){
  check(session.equals(state.sessionId),"multihop created/reused another session while adopting "+entryMode);
  check("multihop".equals(state.logicalMode)&&exitMode.equals(state.runtimeMode),"captured exit transport changed");
  check(ENTRY.equals(state.activeEntryId)&&EXIT.equals(state.activeExitId)&&EXIT.equals(state.activeNodeId),"entry/exit node ownership changed");
  check(entryMode.equals(state.activeEntryMode),"exact entry mode was substituted");
  check(base(entryMode).equals(state.actualBase),"Home labelled a proxy/MAX/PQ entry with the wrong base: "+entryMode);
  check(state.activeExternalId.isEmpty()&&state.activeExternalName.isEmpty()&&state.activeExternalProtocol.isEmpty()&&state.expectedExternalIp.isEmpty(),"old external exit identity survived");
 }
 static void pair(String entryMode,String exitMode){
  pairs++;Context context=externalOwner();AndroidHomeStateStore.Snapshot old=AndroidHomeStateStore.snapshot(context);
  String session=AndroidHomeStateStore.beginMultihop(context,ENTRY,EXIT,exitMode,entryMode);
  check(!session.isEmpty()&&!session.equals(old.sessionId),"new graph reused previous external owner");
  AndroidHomeStateStore.Snapshot pending=AndroidHomeStateStore.snapshot(context);verifyIdentity(pending,session,entryMode,exitMode);
  check("connecting".equals(pending.phase)&&!pending.connected&&"pending".equals(pending.pathProof),"begin claimed Connected before proof");
  check(pending.pathGeneration==old.pathGeneration+1L,"graph start did not invalidate previous path generation");
  check(AndroidHomeStateStore.actualExitForCurrentSession(context).isEmpty(),"old exit-IP proof was reused");
  AndroidHomeStateStore.connectedMultihop(context,ENTRY,EXIT,exitMode,entryMode);
  AndroidHomeStateStore.Snapshot connected=AndroidHomeStateStore.snapshot(context);verifyIdentity(connected,session,entryMode,exitMode);
  check("connected".equals(connected.phase)&&connected.connected&&"passed".equals(connected.pathProof),"proved graph was not adopted");
  check(connected.pathGeneration==pending.pathGeneration,"adoption changed the captured path generation");
  check(context.fileAccesses==0,"Home attempted to stage a native graph");
 }
 static void rejected(String mode,boolean adopt){
  rejections++;Context context=externalOwner();Map<String,Object> before=new HashMap<>(context.store.values);
  int edits=context.store.edits,writes=context.store.writes;
  boolean refused=false;
  try{if(adopt)AndroidHomeStateStore.connectedMultihop(context,ENTRY,EXIT,"shadowsocks",mode);
      else AndroidHomeStateStore.beginMultihop(context,ENTRY,EXIT,"shadowsocks",mode);}
  catch(IllegalArgumentException expected){refused=true;}
  check(refused,"unknown entry was accepted: "+mode);
  check(context.store.edits==edits&&context.store.writes==writes,"rejected entry staged or published a new owner");
  check(before.equals(context.store.values),"rejected entry changed the current session/node/exit identity");
  check(context.fileAccesses==0,"rejected entry staged a native session");
 }
 static void tor(String mode){
  Context context=externalOwner();String entry=mode.equals("direct")?"":ENTRY;
  String session=AndroidHomeStateStore.beginTorExternal(context,"tor-node","Private Tor","tor-bridge",entry,mode.equals("direct")?"external":mode);
  AndroidHomeStateStore.Snapshot captured=AndroidHomeStateStore.snapshot(context);
  check(!captured.connected&&captured.pathProof.equals("pending")&&captured.expectedExternalIp.isEmpty(),"Tor began with reused fixed exit proof");
  check(captured.activeNodeId.isEmpty()&&captured.activeExitId.isEmpty()&&captured.activeEntryId.equals(entry),"Tor retained a previous graph identity");
  check(captured.activeEntryMode.equals(entry.isEmpty()?"":mode)&&captured.actualBase.equals(entry.isEmpty()?"external":base(mode)),"Tor silently changed its captured entry/base");
  check(AndroidHomeStateStore.connectedTorExternal(context,captured,"8.8.4.4"),"valid Tor proof was not adopted");
  AndroidHomeStateStore.Snapshot current=AndroidHomeStateStore.snapshot(context);
  check(current.connected&&current.sessionId.equals(session)&&current.activeExternalProtocol.equals("tor-bridge")&&current.activeEntryId.equals(entry),"Tor proof changed the session owner");
  check(AndroidHomeStateStore.actualExitForCurrentSession(context).equals("8.8.4.4"),"Tor dynamic exit lost its current session");
  check(!AndroidHomeStateStore.connectedTorExternal(context,captured,"9.9.9.9"),"one proof adopted twice");
 }
 static void torStale(String key,Object value){
  Context context=new Context();AndroidHomeStateStore.beginTorExternal(context,"tor-node","Tor","tor",ENTRY,"naive-h3");AndroidHomeStateStore.Snapshot captured=AndroidHomeStateStore.snapshot(context);
  context.store.values.put(key,value);Map<String,Object> before=new HashMap<>(context.store.values);int writes=context.store.writes;
  check(!AndroidHomeStateStore.connectedTorExternal(context,captured,"8.8.4.4"),"Tor accepted stale "+key);
  check(before.equals(context.store.values)&&writes==context.store.writes,"stale Tor completion overwrote Home state: "+key);
 }
 static void externalPolicy(String mode){
  Context context=externalOwner();String entry=mode.equals("direct")?"":ENTRY;
  String session=AndroidHomeStateStore.beginPolicyExternal(context,"ordinary-node","Selected exit","socks5","8.8.4.4",entry,entry.isEmpty()?"external":mode);
  AndroidHomeStateStore.Snapshot captured=AndroidHomeStateStore.snapshot(context);
  check(!captured.connected&&captured.pathProof.equals("pending")&&captured.expectedExternalIp.equals("8.8.4.4"),"ordinary external began before proof or changed expected exit");
  check(captured.activeEntryId.equals(entry)&&captured.activeEntryMode.equals(entry.isEmpty()?"":mode),"ordinary external lost exact entry");
  check(AndroidHomeStateStore.connectedPolicyExternal(context,captured,"8.8.4.4"),"proved ordinary owner rejected");
  check(AndroidHomeStateStore.snapshot(context).sessionId.equals(session)&&AndroidHomeStateStore.actualExitForCurrentSession(context).equals("8.8.4.4"),"ordinary external adopted another session");
  check(!AndroidHomeStateStore.connectedPolicyExternal(context,captured,"8.8.4.4"),"ordinary proof adopted twice");
 }
 static void externalStale(String key,Object value){
  Context context=new Context();AndroidHomeStateStore.beginPolicyExternal(context,"ordinary-node","Selected exit","socks5","8.8.4.4",ENTRY,"naive-h3");AndroidHomeStateStore.Snapshot captured=AndroidHomeStateStore.snapshot(context);
  context.store.values.put(key,value);Map<String,Object> before=new HashMap<>(context.store.values);int writes=context.store.writes;
  check(!AndroidHomeStateStore.connectedPolicyExternal(context,captured,"8.8.4.4"),"ordinary external accepted stale "+key);
  check(before.equals(context.store.values)&&writes==context.store.writes,"stale ordinary completion overwrote Home state: "+key);
 }
 static AndroidHomeStateStore.Snapshot beginPolicy(Context context){
  AndroidHomeStateStore.beginPolicyExternal(context,"ordinary-node","Selected exit","socks5","8.8.4.4",ENTRY,"naive-h3");
  return AndroidHomeStateStore.snapshot(context);
 }
 static void externalFailure(boolean released,String phase,boolean emergency){
  Context context=new Context();AndroidHomeStateStore.Snapshot captured=beginPolicy(context);
  check(AndroidHomeStateStore.ownsPolicyExternal(context,captured),"pending external owner was rejected");
  if(!phase.equals("pending")){
   check(AndroidHomeStateStore.connectedPolicyExternal(context,captured,"8.8.4.4"),"external failure fixture could not connect");
   if(phase.equals("revalidating"))check(AndroidHomeStateStore.beginPathRevalidation(context,"Revalidating captured network")!=null,"external revalidation did not begin");
  }
  check(AndroidHomeStateStore.ownsPolicyExternal(context,captured),"same external session lost ownership during "+phase);
  AndroidHomeStateStore.saveActualExit(context,captured.sessionId,"8.8.4.4");
  String emergencyWarning="Emergency Disconnect requested; waiting for all captured owners";
  if(emergency){AndroidHomeStateStore.warning(context,emergencyWarning);check(!AndroidHomeStateStore.ownsPolicyExternal(context,captured),"emergency retained a healthy external owner");}
  AndroidHomeStateStore.Snapshot before=AndroidHomeStateStore.snapshot(context);
  check(AndroidHomeStateStore.failedPolicyExternal(context,captured,"Captured native proof failed",released),"matching external failure was rejected after "+phase);
  AndroidHomeStateStore.Snapshot failed=AndroidHomeStateStore.snapshot(context);
  check(!failed.connected&&failed.phase.equals("failed")&&failed.pathProof.equals("failed"),"native failure retained Connected evidence");
  check(failed.sessionId.equals(captured.sessionId)&&failed.pathGeneration==before.pathGeneration,"native failure replaced its session/generation");
  check(failed.logicalMode.equals("external")&&failed.runtimeMode.equals(captured.runtimeMode),"native failure relabelled its runtime");
  check(AndroidHomeStateStore.actualExitForCurrentSession(context).isEmpty()&&!context.store.values.containsKey("actual_exit_ip")&&!context.store.values.containsKey("actual_exit_session"),"native failure retained actual-IP evidence");
  check(failed.warning.equals(emergency?emergencyWarning:"Captured native proof failed"),"native failure erased emergency warning or failure reason");
  check(!AndroidHomeStateStore.ownsPolicyExternal(context,captured),"failed owner could still prove a path");
  if(released){
   check(failed.activeNodeId.isEmpty()&&failed.activeExitId.isEmpty()&&failed.activeEntryId.isEmpty()&&!context.store.values.containsKey("active_entry_mode"),"released external failure retained Router graph identity");
   check(failed.activeExternalId.isEmpty()&&failed.activeExternalName.isEmpty()&&failed.activeExternalProtocol.isEmpty()&&failed.expectedExternalIp.isEmpty(),"released external failure retained external identity");
   int writes=context.store.writes;check(!AndroidHomeStateStore.failedPolicyExternal(context,captured,"Late duplicate failure",false)&&writes==context.store.writes,"released owner rewrote Home on duplicate failure");
  }else{
   check(failed.activeEntryId.equals(before.activeEntryId)&&failed.activeEntryMode.equals(before.activeEntryMode)&&failed.activeNodeId.equals(before.activeNodeId)&&failed.activeExitId.equals(before.activeExitId),"unconfirmed teardown lost Router graph identity");
   check(failed.activeExternalId.equals(before.activeExternalId)&&failed.activeExternalName.equals(before.activeExternalName)&&failed.activeExternalProtocol.equals(before.activeExternalProtocol)&&failed.expectedExternalIp.equals(before.expectedExternalIp),"unconfirmed teardown lost external identity");
   check(AndroidHomeStateStore.failedPolicyExternal(context,captured,"Captured native drain completed",true),"retained external owner could not finish its later drain");
   check(AndroidHomeStateStore.snapshot(context).activeExternalId.isEmpty(),"proved later drain failed to release external identity");
   if(emergency)check(AndroidHomeStateStore.snapshot(context).warning.equals(emergencyWarning),"later drain erased pending emergency warning");
  }
 }
 static void externalFailureStale(String key,Object value,boolean released){
  Context context=new Context();AndroidHomeStateStore.Snapshot captured=beginPolicy(context);
  context.store.values.put(key,value);Map<String,Object> before=new HashMap<>(context.store.values);int edits=context.store.edits,writes=context.store.writes;
  check(!AndroidHomeStateStore.ownsPolicyExternal(context,captured),"external health accepted changed owner field "+key);
  check(!AndroidHomeStateStore.failedPolicyExternal(context,captured,"Stale native failure",released),"external failure accepted changed owner field "+key);
  check(before.equals(context.store.values)&&edits==context.store.edits&&writes==context.store.writes,"stale failure mutated replacement owner: "+key);
 }
 static void externalFailureBoundary(){
  for(boolean released:new boolean[]{false,true})for(String phase:new String[]{"pending","connected","revalidating"})for(boolean emergency:new boolean[]{false,true})externalFailure(released,phase,emergency);
  for(String[] change:new String[][]{{"session_id","new"},{"active_external_id","other"},{"active_external_protocol","http"},{"expected_external_ip","9.9.9.9"},{"logical_mode","manual"},{"runtime_mode","wg"},{"active_entry_id","other"},{"active_entry_mode","wg"},{"active_node_id","other"},{"active_exit_id","other"}})for(boolean released:new boolean[]{false,true})externalFailureStale(change[0],change[1],released);
  Context context=new Context();AndroidHomeStateStore.Snapshot captured=beginPolicy(context);int writes=context.store.writes;
  check(!AndroidHomeStateStore.ownsPolicyExternal(context,null)&&!AndroidHomeStateStore.failedPolicyExternal(context,null,"Missing owner",true)&&writes==context.store.writes,"missing owner mutated Home");
  for(String[] change:new String[][]{{"phase","off"},{"phase","failed"},{"path_proof","failed"}}){
   Context invalid=new Context();AndroidHomeStateStore.Snapshot owner=beginPolicy(invalid);invalid.store.values.put(change[0],change[1]);
   check(!AndroidHomeStateStore.ownsPolicyExternal(invalid,owner),"non-live external state retained native health: "+change[0]);
  }
  AndroidHomeStateStore.beginPolicyExternal(context,"ordinary-node","Selected exit","socks5","8.8.4.4",ENTRY,"naive-h3");
  Map<String,Object> replacement=new HashMap<>(context.store.values);writes=context.store.writes;
  check(!AndroidHomeStateStore.failedPolicyExternal(context,captured,"Same path, previous session",false)&&replacement.equals(context.store.values)&&writes==context.store.writes,"same selected path let an old service fail a replacement session");
 }
 static void await(CountDownLatch latch,String description){
  try{if(!latch.await(5,TimeUnit.SECONDS))throw new AssertionError("Timed out waiting for "+description);}
  catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new AssertionError(interrupted);}
 }
 static final class Job {
  final CountDownLatch entered=new CountDownLatch(1),done=new CountDownLatch(1);
  final AtomicReference<Throwable> error=new AtomicReference<>();final Thread thread;
  Job(String name,Runnable action){thread=new Thread(()->{entered.countDown();try{action.run();}catch(Throwable failure){error.set(failure);}finally{done.countDown();}},name);thread.start();}
  void finish()throws Exception{thread.join(5000);check(!thread.isAlive(),"Home worker did not finish: "+thread.getName());if(error.get()!=null)throw new AssertionError("Home worker failed: "+thread.getName(),error.get());}
 }
 static boolean blockedOnHome(Job job){
  await(job.entered,"competing Home writer");long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
  while(job.thread.getState()!=Thread.State.BLOCKED&&job.done.getCount()!=0&&System.nanoTime()<deadline)Thread.yield();
  return job.thread.getState()==Thread.State.BLOCKED&&job.done.getCount()!=0;
 }
 static void atomicAdoption(String adoption,String competing)throws Exception{
  atomicRaces++;Context context=new Context();AndroidHomeStateStore.Snapshot owner;
  if(adoption.equals("tor")){AndroidHomeStateStore.beginTorExternal(context,"tor-node","Tor","tor",ENTRY,"naive-h3");owner=AndroidHomeStateStore.snapshot(context);}
  else owner=beginPolicy(context);
  AndroidHomeStateStore.Snapshot token=owner;
  if(adoption.equals("revalidation")){check(AndroidHomeStateStore.connectedPolicyExternal(context,owner,"8.8.4.4"),"atomic fixture could not connect");token=AndroidHomeStateStore.beginPathRevalidation(context,"Revalidating");}
  final AndroidHomeStateStore.Snapshot captured=token;
  CountDownLatch writing=new CountDownLatch(1),release=new CountDownLatch(1);
  context.store.beforeConnectedApply=()->{writing.countDown();await(release,"adoption release");};
  AtomicBoolean adopted=new AtomicBoolean();
  Job proof=new Job("home-adoption-"+adoption,()->adopted.set(adoption.equals("tor")?AndroidHomeStateStore.connectedTorExternal(context,captured,"8.8.4.4"):adoption.equals("revalidation")?AndroidHomeStateStore.completePathRevalidation(context,captured):AndroidHomeStateStore.connectedPolicyExternal(context,captured,"8.8.4.4")));
  Job writer=null;boolean blocked=false;
  try{
   await(writing,"paused adoption preference write");
   writer=new Job("home-competing-"+competing,()->{
    if(competing.equals("warning"))AndroidHomeStateStore.warning(context,"Emergency Disconnect requested; writer owns warning");
    else if(competing.equals("begin"))AndroidHomeStateStore.beginPolicyExternal(context,"replacement-node","Replacement","http","9.9.9.9","","external");
    else AndroidHomeStateStore.failed(context,"Competing runtime failure");
   });
   blocked=blockedOnHome(writer);
  }finally{release.countDown();proof.finish();if(writer!=null)writer.finish();context.store.beforeConnectedApply=null;}
  check(blocked,"Home transaction allowed competing "+competing+" while "+adoption+" adoption was paused");
  check(adopted.get(),"serialized adoption unexpectedly failed");
  AndroidHomeStateStore.Snapshot finalState=AndroidHomeStateStore.snapshot(context);
  if(competing.equals("warning"))check(finalState.warning.equals("Emergency Disconnect requested; writer owns warning"),"adoption erased the later emergency warning");
  else if(competing.equals("begin"))check(!finalState.connected&&finalState.phase.equals("connecting")&&!finalState.sessionId.equals(captured.sessionId)&&finalState.activeExternalId.equals("replacement-node")&&AndroidHomeStateStore.actualExitForCurrentSession(context).isEmpty(),"old adoption overwrote the replacement session");
  else check(!finalState.connected&&finalState.phase.equals("failed")&&finalState.pathProof.equals("failed")&&finalState.warning.equals("Competing runtime failure")&&AndroidHomeStateStore.actualExitForCurrentSession(context).isEmpty(),"old adoption resurrected a failed owner");
 }
 static void atomicAdoptions()throws Exception{
  for(String adoption:new String[]{"policy","tor","revalidation"})for(String competing:new String[]{"warning","begin","failed"})atomicAdoption(adoption,competing);
  Context context=new Context();AndroidHomeStateStore.Snapshot owner=beginPolicy(context);
  check(AndroidHomeStateStore.connectedPolicyExternal(context,owner,"8.8.4.4"),"emergency revalidation fixture could not connect");
  AndroidHomeStateStore.Snapshot token=AndroidHomeStateStore.beginPathRevalidation(context,"Revalidating");
  AndroidHomeStateStore.warning(context,"Emergency Disconnect requested; proof must stay invalid");
  Map<String,Object> before=new HashMap<>(context.store.values);int writes=context.store.writes;
  check(!AndroidHomeStateStore.completePathRevalidation(context,token),"revalidation adopted after emergency was already pending");
  check(before.equals(context.store.values)&&writes==context.store.writes,"revalidation erased an existing emergency warning");
 }
 static void idleRestorationEpochs(){
  Context context=new Context();long idle=AndroidHomeStateStore.snapshot(context).pathGeneration;
  AndroidHomeStateStore.disconnected(context);check(AndroidHomeStateStore.snapshot(context).pathGeneration==idle+1,"explicit idle Disconnect did not revoke a captured restoration");
  AndroidHomeStateStore.disconnected(context);check(AndroidHomeStateStore.snapshot(context).pathGeneration==idle+2,"a repeated idle Disconnect reused an old restoration epoch");
  long before=AndroidHomeStateStore.snapshot(context).pathGeneration;
  AndroidHomeStateStore.warning(context,"Emergency Disconnect requested; cancel pending restoration");
  check(AndroidHomeStateStore.snapshot(context).pathGeneration==before+1,"emergency stop did not revoke queued restoration");
 }
 public static void main(String[] args)throws Exception {
  if(args.length==1&&args[0].equals("--atomic-only")){atomicAdoptions();return;}
  JSONArray catalog=new JSONArray(Files.readString(Path.of(args[0])));List<String> supported=new ArrayList<>(),unsupported=new ArrayList<>();
  for(int i=0;i<catalog.length();i++){String id=catalog.getJSONObject(i).getString("id");
   (NativeSingBoxController.nativeMultihopEntry(id)?supported:unsupported).add(id);
  }
  for(String required:new String[]{"wg-pq","awg2-pq","naive-h2","naive-h3","reality-vision","reality-pq-vision","reality-xhttp","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"}){
   check(supported.contains(required),"shipping captured catalog lost required entry "+required);
  }
  for(String entry:supported)for(String exit:supported)try{pair(entry,exit);}catch(Throwable error){failures.add(entry+" -> "+exit+": "+error);}
  tor("direct");for(String entry:supported)tor(entry);
  externalPolicy("direct");for(String entry:supported)externalPolicy(entry);
  for(String[] change:new String[][]{{"session_id","new"},{"active_external_id","other"},{"active_external_protocol","http"},{"expected_external_ip","9.9.9.9"},{"logical_mode","manual"},{"runtime_mode","wg"},{"active_entry_id","other"},{"active_entry_mode","wg"},{"phase","off"},{"path_proof","failed"},{"warning","Emergency Disconnect requested; awaiting drain"}})externalStale(change[0],change[1]);
  externalStale("path_generation",99L);
  externalFailureBoundary();atomicAdoptions();idleRestorationEpochs();
  for(String[] change:new String[][]{{"session_id","new"},{"active_external_id","other"},{"active_external_protocol","socks5"},{"logical_mode","manual"},{"runtime_mode","wg"},{"active_entry_id","other"},{"active_entry_mode","wg"},{"phase","off"},{"path_proof","failed"},{"warning","Emergency Disconnect requested; awaiting drain"}})torStale(change[0],change[1]);
  torStale("path_generation",99L);
  unsupported.addAll(Arrays.asList(null,"","WG"," wg","wg ","unknown","naive","naive-h2;exec","max-tls-other"));
  for(String mode:unsupported)for(boolean adopt:new boolean[]{false,true})try{rejected(mode,adopt);}catch(Throwable error){failures.add("reject "+mode+"/"+adopt+": "+error);}
  Context legacy=new Context();String session=AndroidHomeStateStore.beginMultihop(legacy,ENTRY,EXIT,"shadowsocks");
  AndroidHomeStateStore.connectedMultihop(legacy,ENTRY,EXIT,"shadowsocks");
  verifyIdentity(AndroidHomeStateStore.snapshot(legacy),session,"wg","shadowsocks");
  if(!failures.isEmpty())throw new AssertionError(String.join("\n",failures));
  System.out.println("Shipping Android multihop Home state: "+supported.size()+" exact entry modes, "+pairs+" identity pairs, "+rejections+" no-write rejections, "+atomicRaces+" serialized adoption races, "+checks+" checks PASS (OS handles doubled)");
 }
}
''',
}


def main():
    graph = module('multihop_graph_boundary', ROOT/'android/test_android_multihop_graph.py')
    dependency = module('android_json', ROOT/'deploy/test_android_multihop_pinned.py')
    with tempfile.TemporaryDirectory(prefix='routervpn-android-home-') as directory:
        root = Path(directory)
        jar = dependency.android_json_dependency(root, dict(os.environ))
        sources = dict(graph.STUBS)
        sources.update(SOURCES)
        context = 'android/content/Context.java'
        sources[context] = sources[context].replace('public final class Context {', 'public final class Context {public static final String CONNECTIVITY_SERVICE="connectivity";public Object getSystemService(String name){return null;}', 1)
        for name, source in sources.items():
            target = root/name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source)
        for name in ('AndroidHomeStateStore', 'AndroidMultihopController', 'NativeSingBoxController',
                     'AndroidNativeMAXProfile','AndroidNativeCompositeProfile', 'AndroidProfileSelection', 'AndroidNumericAddress',
                     'AndroidNativeProfilePolicy', 'AndroidWireGuardLibboxPolicy', 'AndroidStartLayer',
                     'AndroidXrayLibboxPolicy', 'NativeXrayController', 'AndroidMultihopStartLayer'):
            source = JAVA/(name+'.java')
            if name == 'AndroidHomeStateStore':
                source = Path(os.environ.get('ROUTERVPN_MULTIHOP_HOME_SOURCE', str(source)))
            shutil.copyfile(source, root/'com/eabusham/routervpn'/(name+'.java'))
        subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none', '-cp', str(jar),
                        '-d', str(root), *map(str, root.rglob('*.java'))], check=True, timeout=60)
        subprocess.run(['java', '-cp', os.pathsep.join((str(root), str(jar))),
                        'com.eabusham.routervpn.MultihopHomeHarness', str(ROOT/'configs/client/modes.json')],
                       check=True, timeout=30)
        home = root/'com/eabusham/routervpn/AndroidHomeStateStore.java'
        unlocked = home.read_text().replace('static synchronized ', 'static ')
        if unlocked == home.read_text():
            raise AssertionError('Home negative control did not remove a transaction lock')
        mutant = root/'negative-control-source/AndroidHomeStateStore.java'
        mutant.parent.mkdir()
        mutant.write_text(unlocked)
        mutant_classes = root/'negative-control-classes'
        mutant_classes.mkdir()
        subprocess.run(['javac', '--release', '17', '-encoding', 'UTF-8', '-proc:none',
                        '-cp', os.pathsep.join((str(root), str(jar))), '-d', str(mutant_classes), str(mutant)],
                       check=True, timeout=60)
        negative = subprocess.run(['java', '-cp', os.pathsep.join((str(mutant_classes), str(root), str(jar))),
                                   'com.eabusham.routervpn.MultihopHomeHarness', '--atomic-only'],
                                  capture_output=True, text=True, timeout=30)
        if negative.returncode == 0 or 'Home transaction allowed competing' not in negative.stderr:
            raise AssertionError('Unlocked Home negative control did not expose the adoption race:\n'
                                 + negative.stdout + negative.stderr)
        print('Unlocked Home transaction negative control: rejected the competing write PASS')


if __name__ == '__main__':
    main()
