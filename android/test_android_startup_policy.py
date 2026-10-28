#!/usr/bin/env python3
"""Execute shipping cold-start policy, controller, Home state, Settings and app hook.

Android permission, widgets, network inventory and native runtimes are explicit
boundaries. Files and saved-state round trips are real; strategy proof/fallback
is exercised separately by test_android_mode_orchestrator.py.
"""
from pathlib import Path
import importlib.util
import os
import re
import subprocess
import tempfile

PRIVATE_JSON_GO='''package main
import (
 "io"
 "os"
 libbox "router-vpn/mobile"
)
func main() {
 raw,err:=io.ReadAll(io.LimitReader(os.Stdin,4097))
 if err!=nil || len(raw)>4096 || libbox.RouterValidatePrivateNodeJSON(string(raw))!=nil { os.Exit(1) }
}
'''
PRIVATE_JSON_JAVA=r'''package io.nekohasekai.libbox;
import java.nio.charset.StandardCharsets;import java.util.concurrent.TimeUnit;
public final class Libbox {
 public static void routerValidatePrivateNodeJSON(String raw)throws Exception{
  Process child=new ProcessBuilder(System.getProperty("fixture.privatejson")).start();
  try{
   child.getOutputStream().write(raw.getBytes(StandardCharsets.UTF_8));child.getOutputStream().close();
   if(!child.waitFor(5,TimeUnit.SECONDS)||child.exitValue()!=0)throw new IllegalArgumentException("unambiguous raw receipt required");
  }finally{
   child.getInputStream().close();child.getErrorStream().close();child.getOutputStream().close();
   if(child.isAlive()){child.destroyForcibly();if(!child.waitFor(5,TimeUnit.SECONDS))throw new IllegalStateException("private parser child did not drain");}
  }
 }
}
'''

ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'
spec=importlib.util.spec_from_file_location('startup_permission_boundaries',ROOT/'android/test_android_external_permission.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)


def block(source,signature):
    start=source.index(signature);at=source.index('{',start);depth=1;end=at+1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]


def replace_class(source,name,replacement):
    start=source.index('final class '+name+' ')
    at=source.index('{',start);depth=1;end=at+1
    while depth:
        if source[end]=='{':depth+=1
        if source[end]=='}':depth-=1
        end+=1
    return source[:start]+replacement+source[end:]


PREFS=r'''package android.content;
import java.util.*;
public interface SharedPreferences {
 String getString(String k,String fallback);boolean getBoolean(String k,boolean fallback);long getLong(String k,long fallback);Map<String,?> getAll();Editor edit();
 interface Editor {Editor putString(String k,String v);Editor putBoolean(String k,boolean v);Editor putLong(String k,long v);Editor remove(String k);void apply();boolean commit();}
}
'''
MEMORY=r'''package android.content;
import java.util.*;
public final class MemoryPreferences implements SharedPreferences {
 public final Map<String,Object> values=new LinkedHashMap<>();
 public synchronized String getString(String k,String v){return (String)values.getOrDefault(k,v);}
 public synchronized boolean getBoolean(String k,boolean v){return (Boolean)values.getOrDefault(k,v);}
 public synchronized long getLong(String k,long v){return (Long)values.getOrDefault(k,v);}
 public synchronized Map<String,?> getAll(){return new LinkedHashMap<>(values);}
 public Editor edit(){return new Editor(){final Map<String,Object> next=new LinkedHashMap<>();final Set<String> removed=new HashSet<>();
  public Editor putString(String k,String v){next.put(k,v);removed.remove(k);return this;}public Editor putBoolean(String k,boolean v){next.put(k,v);removed.remove(k);return this;}public Editor putLong(String k,long v){next.put(k,v);removed.remove(k);return this;}
  public Editor remove(String k){removed.add(k);next.remove(k);return this;}public void apply(){commit();}public boolean commit(){synchronized(MemoryPreferences.this){for(String k:removed)values.remove(k);values.putAll(next);return true;}}
 };}
}
'''
NODE=r'''final class AndroidNodeStore {
 static final int MAX_BUNDLE=32*1024*1024;static final List<Node> nodes=new ArrayList<>();static String active="";static int imports;
 static final class Node {final String id,name,endpoint="";final File file;Node(String id,File f){this.id=id;name=id;file=f;}}
 AndroidNodeStore(Context c){}List<Node> list(){return new ArrayList<>(nodes);}String activeId(){return active;}
 File file(String id){for(Node n:nodes)if(n.id.equals(id)&&n.file.isFile())return n.file;throw new IllegalStateException("missing private node");}
 static void validateBundle(JSONObject b)throws Exception{b.getJSONObject("profiles");b.getJSONArray("modes");AndroidProfileSelection.selectedRouterProfile(b);}
 static String deriveId(JSONObject b,byte[] bytes)throws Exception{return b.getString("fixture_store_id");}
 Node importBundle(byte[] bytes)throws Exception{JSONObject b=new JSONObject(new String(bytes,StandardCharsets.UTF_8));validateBundle(b);String id=deriveId(b,bytes);Files.write(file(id).toPath(),bytes);imports++;for(Node n:nodes)if(n.id.equals(id))return n;throw new AssertionError();}
}
'''
ORCHESTRATOR=r'''final class AndroidModeOrchestrator {
 interface Callback{void progress(String m);void finished(boolean ok,String raw,String m);default void owned(String s){}default void proved(String s,String raw,String source){}}
 int starts;String mode="",last="",source="",session="";File file;boolean rejectProof,changeBeforeReceipt;
 void startup(File f,String mode,String raw,String source,Callback cb){this.last=raw;this.source=source;start(f,mode,raw.isEmpty()?"wg":raw,cb);}
 void start(File f,String choice,String raw,Callback cb){starts++;file=f;mode=choice;try{String actual=new JSONObject(Files.readString(f.toPath())).toString();if(!source.isEmpty()&&!source.equals(actual))throw new IllegalStateException("changed source");source=actual;
  session=AndroidHomeStateStore.begin(new Context(),choice,raw,"wg",AndroidHomeStateStore.nodeIdFromBundleFile(f));cb.owned(session);
  if(rejectProof){AndroidHomeStateStore.failed(new Context(),"proof failed");cb.finished(false,"","proof failed");return;}
  AndroidHomeStateStore.connected(new Context(),choice,raw,"wg","",AndroidHomeStateStore.nodeIdFromBundleFile(f));
  if(changeBeforeReceipt)AndroidHomeStateStore.begin(new Context(),"external","http","","new-owner");
  cb.proved(session,raw,source);cb.finished(true,raw,"fresh native proof");
 }catch(Exception e){cb.finished(false,"",e.toString());}}
 String captureSource(File f,String s,String raw)throws Exception{return Files.readString(f.toPath());}
 void restoreCaptured(File f,String raw,String logical,String fallback,String source,Callback cb){}
 void disconnectCaptured(String session,Callback cb){AndroidHomeStateStore.disconnected(new Context());cb.finished(true,"","drained");}
 void disconnect(Callback cb){AndroidHomeStateStore.disconnected(new Context());cb.finished(true,"","drained");}
 void auto(File f,boolean smart,Callback cb){start(f,smart?"smart-auto":"auto","wg",cb);}void all(File f,Callback cb){start(f,"all","max-tls-wg",cb);}void custom(File f,List<String> l,Callback cb){start(f,"custom","shadowsocks",cb);}void logical(File f,String m,Callback cb){start(f,m,m,cb);}
}
'''
MULTIHOP=r'''final class AndroidMultihopRuntime {
 // MULTIHOP_CAPTURE_TYPES
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String id){}}
 int starts,lastStarts;String entryID="",exitID="",entryMode="",exitMode="",execution="",selected="",pins="";
 void connect(AndroidNodeStore.Node a,AndroidNodeStore.Node b,String mode,String execution,String entry,Callback cb){starts++;entryID=a.id;exitID=b.id;entryMode=entry;exitMode=mode;this.execution=execution;cb.owned(AndroidHomeStateStore.beginMultihop(new Context(),a.id,b.id,mode,entry));AndroidHomeStateStore.connectedMultihop(new Context(),a.id,b.id,mode,entry);cb.finished(true,"proved captured graph");}
 String activeExecution(){return execution;}String activeSelectedExecution(){return execution.equals("auto")?"server":execution;}
 void connectLast(AndroidNodeStore.Node a,AndroidNodeStore.Node b,StartupCapture capture,AndroidHomeStateStore.Snapshot idle,Callback cb){try{capture.require(a,b);AndroidHomeStateStore.Snapshot current=AndroidHomeStateStore.snapshot(new Context());if(idle.connected||current.connected||!idle.sessionId.equals(current.sessionId)||idle.pathGeneration!=current.pathGeneration||!idle.phase.equals(current.phase))throw new IllegalStateException("changed startup idle owner");lastStarts++;selected=capture.selected;pins=capture.serverIdentityPins;connect(a,b,capture.exitMode,capture.policy,capture.entryMode,cb);}catch(Exception changed){cb.finished(false,changed.toString());}}
 void restoreCaptured(AndroidNodeStore.Node a,AndroidNodeStore.Node b,RestoreCapture capture,AndroidHomeStateStore.Snapshot idle,Callback cb){}
 RestoreCapture captureRestore(AndroidNodeStore.Node a,AndroidNodeStore.Node b,AndroidHomeStateStore.Snapshot home)throws Exception{throw new IllegalStateException("startup fixture cannot capture an old native graph");}boolean captureCurrent(RestoreCapture capture){return false;}boolean restoredMatches(RestoreCapture capture,AndroidNodeStore.Node a,AndroidNodeStore.Node b,AndroidHomeStateStore.Snapshot home){return false;}
 boolean disconnectAndDrainCaptured(String s){return true;}boolean isConnected(){return starts>0;}boolean isActiveOrTransitioning(){return false;}
 String activeEntryId(){return entryID;}String activeExitId(){return exitID;}String activeEntryMode(){return entryMode;}String activeExitMode(){return exitMode;}
 void disconnect(){}List<NativeSingBoxController.ModeInfo> listSupportedExitModes(File f){return Collections.emptyList();}
}
'''
MULTIHOP=MULTIHOP.replace('// MULTIHOP_CAPTURE_TYPES',P.MULTIHOP_CAPTURE_TYPES.replace(' static final class StartupCapture{}',' // SHIPPING_STARTUP_CAPTURE'))

EXTRA=r'''
final class AndroidExternalPolicy {
 static boolean supports(String s){return List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn").contains(s);}
 static String protocol(String s){return s.equals("http")?"http-connect":s.equals("https")?"https-connect":s;}
}
final class AndroidStartLayer {static final String OFF="off",AES="aes-256-gcm",AES_XOR="aes-256-gcm+xor-whitening";}
final class AndroidMTUDialog {static void show(android.app.Activity a){}}
final class AndroidConnectionProfilesDialog {static void show(android.app.Activity a,AndroidNodeStore n,AndroidStandardExitStore s,Runnable r){}}
final class AndroidUnifiedNodeCatalog {AndroidUnifiedNodeCatalog(AndroidNodeStore n,AndroidStandardExitStore e){}}
final class AndroidTelemetry {AndroidTelemetry(android.app.Activity a,AndroidNodeStore n){}}
final class AndroidForwardingMaster {AndroidForwardingMaster(android.app.Activity a,AndroidNodeStore n){}}
final class AndroidViaEntryLatencyProbe {AndroidViaEntryLatencyProbe(android.app.Activity a,AndroidRuntimeRegistry r,AndroidTelemetry t){}boolean isBusy(){return false;}}
final class AndroidProductOnboarding {static void showIfNeeded(android.app.Activity a){}}
final class AndroidConnectionProfileStore {
 static final String SELECTED_KIND="selected_kind",SELECTED_ID="selected_id",MULTI_ON="multihop_on",MULTI_ENTRY="multihop_entry",MULTI_EXIT="multihop_exit",MULTI_MODE="multihop_exit_mode",MULTI_ENTRY_KIND="multihop_entry_kind";
 final Context context;final AndroidNodeStore nodes;final AndroidStandardExitStore exits;
 AndroidConnectionProfileStore(Context c,AndroidNodeStore n,AndroidStandardExitStore e){context=c;nodes=n;exits=e;}
 android.content.SharedPreferences prefs(){return context.getSharedPreferences("router-vpn-unified",0);}
 AndroidNodeStore.Node findNode(String id){for(AndroidNodeStore.Node n:nodes.list())if(n.id.equals(id))return n;return null;}
 static String normalizeExecution(String s){if(!List.of("local","server","auto").contains(s))throw new IllegalArgumentException("bad execution");return s;}
 static String normalizeEntryMode(String s){if(!NativeSingBoxController.nativeMultihopEntry(s))throw new IllegalArgumentException("bad entry mode");return s;}
 static void requireEntryMode(AndroidNodeStore.Node n,String mode){if(n==null)throw new IllegalStateException("missing entry");normalizeEntryMode(mode);}
 // The store and compiler have their own executable suites. Here only source
 // storage/runtime are doubled; currentExternalPath and kind parsing ship intact.
 static void validateExternalGraph(AndroidStandardExitStore.Entry e,AndroidNodeStore.Node n,AndroidStandardExitStore.Entry ordinary,String mode,String execution){AndroidStandardExitStore.validate(e);AndroidStandardExitStore.validateExecution(e,n!=null,execution);if(ordinary!=null&&(n!=null||!AndroidExternalPolicy.supports(ordinary.protocol)||!AndroidTorProfile.isTor(e.protocol)||ordinary.id.equals(e.id)||!execution.equals("local")||!mode.equals(AndroidExternalPolicy.protocol(ordinary.protocol))))throw new IllegalArgumentException("invalid ordinary startup graph");}
 // SHIPPING_EXTERNAL_SELECTION
}
'''
ACTIVITY=r'''package com.eabusham.routervpn;
import android.os.Bundle;import java.util.*;
final class StartupActivity extends android.app.Activity {
 static final String STATE_IMPORT_DECISION="routervpn.import.decision",STATE_PROBE_ENTRY="routervpn.via_entry_probe.entry",STATE_PROBE_CANDIDATES="routervpn.via_entry_probe.candidates";
 AndroidNodeStore nodeStore;AndroidStandardExitStore exitStore;AndroidUnifiedNodeCatalog catalog;AndroidUnifiedConnectionController connection;AndroidTelemetry telemetry;AndroidForwardingMaster forwardingMaster;AndroidViaEntryLatencyProbe viaEntryProbe;
 String importDecision="",pendingProbeEntryId="";ArrayList<String> pendingProbeCandidateIds=new ArrayList<>();
 android.widget.TextView statusView=new android.widget.TextView(this);final StartupTest.Callback cb=new StartupTest.Callback();
 android.view.View buildUi(){return new android.view.View(this);}void refreshAll(){}AndroidUnifiedConnectionController.Callback callback(){return cb;}static String safe(Throwable e){return e.getMessage();}
 // SHIPPING_ACTIVITY_METHODS
}
'''
HARNESS=r'''package com.eabusham.routervpn;
import android.app.*;import android.content.*;import android.os.*;import android.net.*;import android.widget.*;import org.json.*;import java.nio.file.*;import java.util.*;
public final class StartupTest {
 static int checks;static void check(boolean v,String msg){checks++;if(!v)throw new AssertionError(msg);}
 static final String FIRST="a".repeat(32),ENTRY="b".repeat(32),EXIT="c".repeat(32);
 static final List<String> EXTERNAL_PROTOCOLS=List.of("tor","tor-bridge","wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn");
 static class Callback implements AndroidUnifiedConnectionController.Callback {int completions;boolean ok;String message="";public void progress(String m){message=m;}public void finished(boolean ok,String m){this.ok=ok;message=m;completions++;}}
 static void resetProcess()throws Exception{var owner=AndroidUnifiedConnectionController.class.getDeclaredField("permissionOwner");owner.setAccessible(true);owner.set(null,null);for(String name:new String[]{"coldLaunchClaimed","pending"}){var f=AndroidStartupPolicy.class.getDeclaredField(name);f.setAccessible(true);if(name.equals("pending"))f.set(null,null);else f.setBoolean(null,false);}}
 static JSONObject bundle(String id)throws Exception{return new JSONObject().put("fixture_store_id",id).put("selectedRouterID","router").put("routerProfiles",new JSONArray().put(new JSONObject().put("id","router").put("home_lan_access",true).put("dns_mode","home").put("private_key","SECRET_PROFILE_BYTES"))).put("profiles",new JSONObject().put("wg",new JSONObject().put("wg.conf","SECRET_NATIVE_BYTES"))).put("modes",new JSONArray().put(new JSONObject().put("id","wg")));}
 static final class Fixture {
  final Path dir;final Activity activity;final AndroidNodeStore nodes;AndroidUnifiedConnectionController controller;final Callback cb=new Callback();AndroidStartupPolicy.Attempt captured;
  Fixture(Path parent)throws Exception{resetProcess();dir=Files.createTempDirectory(parent,"case-");Context.nextFiles=dir.toFile();Context.preferences.clear();Context.connectivity=new ConnectivityManager();AndroidNodeStore.nodes.clear();AndroidNodeStore.active=FIRST;AndroidNodeStore.imports=0;AndroidRuntimeRegistry.instance=new AndroidRuntimeRegistry();AndroidVpnMutationGuard.busy=false;VpnService.needsPermission=true;AndroidPrivateFileStore.failWrite=false;
   activity=new Activity();nodes=new AndroidNodeStore(activity);for(String id:List.of(FIRST,ENTRY,EXIT)){Path file=dir.resolve(id+".json");Files.writeString(file,bundle(id).toString());AndroidNodeStore.nodes.add(new AndroidNodeStore.Node(id,file.toFile()));}controller=new AndroidUnifiedConnectionController(activity,nodes);prefs().edit().putString("selected_kind","router-vpn").putString("selected_id",FIRST).putString("mode","base-raw").apply();}
  SharedPreferences prefs(){return activity.getSharedPreferences("router-vpn-unified",0);}
  JSONObject root()throws Exception{return new JSONObject(Files.readString(nodes.file(FIRST).toPath()));}
  void policy(String mode,Boolean auto)throws Exception{JSONObject root=root(),p=AndroidProfileSelection.selectedRouterProfile(root);if(mode==null)p.remove("startup_mode");else p.put("startup_mode",mode);if(auto==null)p.remove("auto_connect");else p.put("auto_connect",auto);Files.writeString(nodes.file(FIRST).toPath(),root.toString());}
  AndroidStartupPolicy.Attempt capture()throws Exception{captured=AndroidStartupPolicy.coldLaunch(activity,nodes,controller,false);return captured;}
  Bundle request()throws Exception{AndroidStartupPolicy.Attempt a=capture();check(a!=null,"enabled startup not captured");controller.connectStartup(a,cb);Bundle out=new Bundle();controller.savePending(out);check(controller.isStartupPending(),"startup lost pending permission owner");return out;}
  void allow(){controller.onActivityResult(activity.permissionRequest,Activity.RESULT_OK);}
  int starts(){return AndroidRuntimeRegistry.instance.orchestrator.starts+AndroidRuntimeRegistry.instance.multihop.starts;}
  void restore(Bundle state){controller.close();controller=new AndroidUnifiedConnectionController(activity,nodes);controller.restorePending(state,cb);}
 }
 static void defaults(Path root)throws Exception{
  for(String mode:new String[]{"smart-auto","auto","last","manual"})for(Boolean auto:new Boolean[]{null,false,true}){Fixture f=new Fixture(root);f.policy(mode,auto);AndroidStartupPolicy.Attempt a=f.capture();check((a!=null)==(Boolean.TRUE.equals(auto)&&!mode.equals("manual")),"startup default/manual did not remain opt-in");check(f.capture()==null,"a cold process attempted startup twice");if(a!=null)a.cancel();}
  Fixture defaultMode=new Fixture(root);defaultMode.policy(null,true);check(defaultMode.capture().mode.equals("smart-auto"),"missing startup mode is not SMART AUTO");
  Fixture restored=new Fixture(root);restored.policy("auto",true);check(AndroidStartupPolicy.coldLaunch(restored.activity,restored.nodes,restored.controller,true)==null&&restored.capture()==null,"Activity recreation claimed a new cold launch");
  Fixture external=new Fixture(root);external.policy("auto",true);AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();AndroidStandardExitStore.saved.put(e.id,e);external.prefs().edit().putString("selected_kind","external").putString("selected_id",e.id).apply();check(external.capture()==null,"an external selection silently launched a remembered Router");
 }
 static void permission(Path root)throws Exception{
  for(String mode:new String[]{"smart-auto","auto","last"})for(boolean recreate:new boolean[]{false,true}){Fixture f=new Fixture(root);f.policy(mode,true);Bundle saved=f.request();check(f.starts()==0&&f.activity.permissionRequest>=AndroidUnifiedConnectionController.PREPARE_UNIFIED,"startup bypassed ordinary Android permission");check(!saved.values.toString().contains("SECRET_")&&!saved.values.toString().contains("private_key"),"private node bytes entered Activity saved state");if(recreate)f.restore(saved);f.allow();check(f.cb.ok&&f.starts()==1&&AndroidRuntimeRegistry.instance.orchestrator.mode.equals(mode),"captured startup strategy was not dispatched once");f.allow();check(f.starts()==1,"late duplicate permission result restarted startup");check(f.capture()==null,"completion rearmed cold launch");}
  Fixture ready=new Fixture(root);ready.policy("auto",true);VpnService.needsPermission=false;ready.controller.connectStartup(ready.capture(),ready.cb);check(ready.cb.ok&&ready.starts()==1&&ready.activity.permission==null,"existing permission did not use the same guarded startup dispatch");
  Fixture denied=new Fixture(root);denied.policy("auto",true);denied.request();denied.controller.onActivityResult(denied.activity.permissionRequest,0);denied.allow();check(!denied.cb.ok&&denied.starts()==0&&!denied.controller.isStartupPending(),"denied startup was later revived");
  Fixture cancelled=new Fixture(root);cancelled.policy("auto",true);Bundle saved=cancelled.request();check(cancelled.controller.cancelStartupPending(),"Cancel startup did not own its pending request");cancelled.restore(saved);cancelled.allow();check(cancelled.starts()==0&&!cancelled.cb.ok&&cancelled.capture()==null,"cancelled startup revived across recreation or late permission");
  Fixture died=new Fixture(root);died.policy("auto",true);Bundle stale=died.request();resetProcess();died.restore(stale);died.allow();check(died.starts()==0&&!died.cb.ok,"a new process adopted old private startup capture");
 }
 static void changes(Path root)throws Exception{
  for(String change:new String[]{"source","entry-source","exit-source","selected","active","mode","graph","entry-mode","exit-mode","execution","idle-generation","idle-session","busy","foreign-vpn","unavailable-network"})for(boolean recreate:new boolean[]{false,true}){
   Fixture f=new Fixture(root);f.policy("auto",true);f.prefs().edit().putBoolean("multihop_on",true).putString("multihop_entry",ENTRY).putString("multihop_exit",EXIT).putString("multihop_entry_mode","max-tls-awg").putString("multihop_exit_mode","shadowsocks").putString("multihop_execution","auto").apply();Bundle state=f.request();
   if(change.endsWith("source")){String id=change.equals("entry-source")?ENTRY:change.equals("exit-source")?EXIT:FIRST;Path p=f.nodes.file(id).toPath();Files.writeString(p,Files.readString(p)+" ");}
   if(change.equals("selected"))f.prefs().edit().putString("selected_id",EXIT).apply();if(change.equals("active"))AndroidNodeStore.active=ENTRY;
   if(change.equals("mode"))f.prefs().edit().putString("mode","new-choice").apply();if(change.equals("graph"))f.prefs().edit().putBoolean("multihop_on",false).apply();
   if(change.equals("entry-mode"))f.prefs().edit().putString("multihop_entry_mode","wg").apply();if(change.equals("exit-mode"))f.prefs().edit().putString("multihop_exit_mode","hysteria2").apply();if(change.equals("execution"))f.prefs().edit().putString("multihop_execution","local").apply();
   if(change.equals("idle-generation"))AndroidHomeStateStore.advancePathGeneration(f.activity);if(change.equals("idle-session")){AndroidHomeStateStore.begin(f.activity,"other","","",FIRST);AndroidHomeStateStore.failed(f.activity,"failed newer decision");}
   if(change.equals("busy"))AndroidVpnMutationGuard.busy=true;if(change.equals("foreign-vpn"))Context.connectivity.vpn=true;if(change.equals("unavailable-network"))Context.connectivity=null;
   if(recreate)f.restore(state);f.allow();check(f.starts()==0&&!f.cb.ok,"stale startup capture started: "+change+" / "+recreate);
  }
  for(String state:new String[]{"foreign","unknown","busy"}){Fixture f=new Fixture(root);f.policy("auto",true);if(state.equals("foreign"))Context.connectivity.vpn=true;if(state.equals("unknown"))Context.connectivity=null;if(state.equals("busy"))AndroidVpnMutationGuard.busy=true;boolean failed=false;try{f.capture();}catch(Exception expected){failed=true;}check(failed&&f.starts()==0,"initial occupied/unknown VPN was automatically replaced: "+state);}
 }
 static AndroidNodeStore.Node node(Fixture f,String id){for(var n:f.nodes.list())if(n.id.equals(id))return n;throw new AssertionError("missing fixture node");}
 static void routerPath(Fixture f,String entryMode,String exitMode,String requested)throws Exception{
  f.policy("auto",false);f.prefs().edit().putBoolean("multihop_on",true).putString("multihop_entry_kind","router-vpn").putString("multihop_entry",ENTRY).putString("multihop_exit",EXIT).putString("multihop_entry_mode",entryMode).putString("multihop_exit_mode",exitMode).putString("multihop_execution",requested).apply();
 }
 static String pins(String selected,String mode)throws Exception{
  boolean pq=NativeSingBoxController.nativePQFamily(mode)||AndroidNativeMAXProfile.isMode(mode),packet=NativeSingBoxController.nativeWireGuardFamily(mode)||pq;JSONObject value=new JSONObject();
  if(selected.equals("server")&&packet){byte[] publicKey=new byte[32];Arrays.fill(publicKey,(byte)7);value.put("expected_packet_public_key",java.util.Base64.getEncoder().encodeToString(publicKey));if(pq)value.put("expected_pq_client_identity","2".repeat(64));}return value.toString();
 }
 static AndroidStartupPolicy.MultihopLast prepareRouterLast(Fixture f)throws Exception{
  var a=node(f,ENTRY);var b=node(f,EXIT);var prefs=f.prefs();return AndroidStartupPolicy.prepareMultihopExecution(f.activity,a,b,prefs.getString("multihop_entry_mode",""),prefs.getString("multihop_exit_mode",""),prefs.getString("multihop_execution",""),AndroidMultihopController.captureSource(a.file,Files.readAllBytes(a.file.toPath())),AndroidMultihopController.captureSource(b.file,Files.readAllBytes(b.file.toPath())));
 }
 static AndroidHomeStateStore.Snapshot routerOwner(Fixture f,boolean prove){
  String mode=f.prefs().getString("multihop_exit_mode",""),entry=f.prefs().getString("multihop_entry_mode","");AndroidHomeStateStore.beginMultihop(f.activity,ENTRY,EXIT,mode,entry);
  if(prove)AndroidHomeStateStore.connectedMultihop(f.activity,ENTRY,EXIT,mode,entry);return AndroidHomeStateStore.snapshot(f.activity);
 }
 static void saveRouterLast(Fixture f,String selected)throws Exception{
  var prepared=prepareRouterLast(f);check(prepared!=null,"complete private graph did not prepare Last source identity");check(AndroidStartupPolicy.recordMultihopExecution(f.activity,prepared,routerOwner(f,true),selected,pins(selected,f.prefs().getString("multihop_exit_mode",""))),"proved private graph did not persist Last execution");
 }
 static void enableRouterLast(Fixture f)throws Exception{f.policy("last",true);AndroidHomeStateStore.disconnected(f.activity);resetProcess();}
 static void routerLastReceipts(Path root)throws Exception{
  for(String entry:List.of("wg","awg2-strong","max-quic-awg"))for(String exit:List.of("wg","awg2-fast","wg-pq","awg2-pq","shadowsocks","max-tls-wg","naive-h3","reality-xhttp"))for(String selected:List.of("local","server"))for(boolean rotate:new boolean[]{false,true}){
   Fixture f=new Fixture(root);routerPath(f,entry,exit,"auto");saveRouterLast(f,selected);Path path=f.dir.resolve("startup-multihop-last-v1.json");String raw=Files.readString(path);JSONObject receipt=new JSONObject(raw);
   check(receipt.length()==6&&receipt.getInt("schema")==1&&receipt.getString("entry_id").equals(ENTRY)&&receipt.getString("exit_id").equals(EXIT)&&receipt.getString("path_sha256").matches("[0-9a-f]{64}")&&receipt.getString("selected_execution").equals(selected)&&receipt.getString("server_identity_pins").equals(pins(selected,exit)),"private Last receipt lost complete identity or public constraints");
   check(!raw.contains("SECRET_")&&!raw.contains("lease")&&!raw.contains("session")&&!raw.contains("score")&&!raw.contains("private_key"),"private Last retained private credentials, proof or measurement");
   enableRouterLast(f);Bundle state=f.request();var captured=f.captured.lastMultihop;check(captured!=null&&captured.policy.equals("auto")&&captured.selected.equals(selected)&&captured.serverIdentityPins.equals(pins(selected,exit)),"cold Last did not capture actual selected leaf and public identity");
   if(rotate){state.putString("multihop_execution_pending",selected.equals("local")?"server":"local");state.putString("multihop_entry_mode_pending","wg");f.restore(state);}f.allow();var runtime=AndroidRuntimeRegistry.instance.multihop;
   check(f.cb.ok&&runtime.lastStarts==1&&runtime.starts==1&&runtime.execution.equals("auto")&&runtime.selected.equals(selected)&&runtime.pins.equals(pins(selected,exit)),"Router Last reran Compare or changed its historical winner");
   check(runtime.entryID.equals(ENTRY)&&runtime.exitID.equals(EXIT)&&runtime.entryMode.equals(entry)&&runtime.exitMode.equals(exit)&&Files.readString(path).equals(raw),"Router Last changed graph or overwrote historical receipt");f.allow();check(runtime.starts==1,"late Last permission started a second graph");
  }
  Fixture missing=new Fixture(root);routerPath(missing,"wg","wg-pq","auto");enableRouterLast(missing);boolean rejected=false;try{missing.capture();}catch(Exception expected){rejected=true;}check(rejected&&missing.starts()==0,"Router Last without historical choice reran Compare");
  for(String fault:List.of("selected-dns","selected-key","entry-dns","entry-key","entry-native","exit-dns","exit-key","exit-native","entry-mode","exit-mode","entry-id","exit-id","selected-id","requested","receipt-entry","receipt-exit","receipt-source","receipt-leaf","receipt-extra","receipt-missing","pins-missing","pins-extra","pins-key","pins-pq","pins-duplicate","pins-space")){
   Fixture f=new Fixture(root);routerPath(f,"max-tls-awg","wg-pq",fault.equals("requested")?"local":"auto");saveRouterLast(f,fault.equals("requested")?"local":"server");Path file=f.dir.resolve("startup-multihop-last-v1.json");JSONObject receipt=new JSONObject(Files.readString(file));enableRouterLast(f);
   for(String role:List.of("selected","entry","exit"))if(fault.startsWith(role+"-")){String id=role.equals("selected")?FIRST:role.equals("entry")?ENTRY:EXIT;JSONObject bundle=new JSONObject(Files.readString(f.nodes.file(id).toPath()));if(fault.endsWith("dns"))AndroidProfileSelection.selectedRouterProfile(bundle).put("dns_mode","rescue");if(fault.endsWith("key"))AndroidProfileSelection.selectedRouterProfile(bundle).put("private_key","changed private key");if(fault.endsWith("native"))bundle.getJSONObject("profiles").getJSONObject("wg").put("wg.conf","replacement generated graph");Files.writeString(f.nodes.file(id).toPath(),bundle.toString());}
   if(fault.equals("entry-mode"))f.prefs().edit().putString("multihop_entry_mode","wg").apply();if(fault.equals("exit-mode"))f.prefs().edit().putString("multihop_exit_mode","awg2-pq").apply();if(fault.equals("entry-id"))f.prefs().edit().putString("multihop_entry",FIRST).apply();if(fault.equals("exit-id"))f.prefs().edit().putString("multihop_exit",FIRST).apply();if(fault.equals("selected-id")){f.prefs().edit().putString("selected_id",ENTRY).apply();AndroidNodeStore.active=ENTRY;JSONObject changed=new JSONObject(Files.readString(f.nodes.file(ENTRY).toPath()));AndroidProfileSelection.selectedRouterProfile(changed).put("startup_mode","last").put("auto_connect",true);Files.writeString(f.nodes.file(ENTRY).toPath(),changed.toString());}if(fault.equals("requested"))f.prefs().edit().putString("multihop_execution","auto").apply();
   if(fault.equals("receipt-entry"))receipt.put("entry_id",FIRST);if(fault.equals("receipt-exit"))receipt.put("exit_id",FIRST);if(fault.equals("receipt-source"))receipt.put("path_sha256","0".repeat(64));if(fault.equals("receipt-leaf"))receipt.put("selected_execution","auto");if(fault.equals("receipt-extra"))receipt.put("lease","stale");if(fault.equals("receipt-missing"))receipt.remove("server_identity_pins");
   if(fault.startsWith("pins-")){JSONObject pins=new JSONObject(receipt.getString("server_identity_pins"));if(fault.equals("pins-missing"))pins.remove("expected_packet_public_key");if(fault.equals("pins-extra"))pins.put("private_key","invalid");if(fault.equals("pins-key"))pins.put("expected_packet_public_key","bad");if(fault.equals("pins-pq"))pins.put("expected_pq_client_identity","0".repeat(64));String raw=pins.toString();if(fault.equals("pins-duplicate"))raw=raw.substring(0,raw.length()-1)+",\"expected_pq_client_identity\":\""+"2".repeat(64)+"\"}";if(fault.equals("pins-space"))raw=" "+raw;receipt.put("server_identity_pins",raw);}
   Files.writeString(file,receipt.toString());boolean stale=false;try{f.capture();}catch(Exception expected){stale=true;}check(stale&&f.starts()==0,"changed private Last source or receipt accepted: "+fault);
  }
  for(String fault:RAW_FAULTS){Fixture f=new Fixture(root);routerPath(f,"wg","wg-pq","auto");saveRouterLast(f,"server");Path file=f.dir.resolve("startup-multihop-last-v1.json");Files.writeString(file,corruptReceipt(new JSONObject(Files.readString(file)),"selected_execution",fault));enableRouterLast(f);boolean stale=false;try{f.capture();}catch(Exception expected){stale=true;}check(stale,"ambiguous private Last receipt accepted: "+fault);}
  for(String fault:List.of("unproved","superseded","generation","emergency","selection","source","speed-lab","wrong-leaf","wrong-pins","write-failure")){
   Fixture f=new Fixture(root);routerPath(f,"wg","wg-pq",fault.equals("wrong-leaf")?"local":"auto");Object lease=fault.equals("speed-lab")?AndroidMTUMeasurementGate.acquire():null;AndroidStartupPolicy.MultihopLast record;
   try{if(fault.equals("source")){var a=node(f,ENTRY);var b=node(f,EXIT);var source=AndroidMultihopController.captureSource(a.file,Files.readAllBytes(a.file.toPath()));Files.writeString(a.file.toPath(),bundle(ENTRY).put("new-captured-value",true).toString());record=AndroidStartupPolicy.prepareMultihopExecution(f.activity,a,b,"wg","wg-pq","auto",source,AndroidMultihopController.captureSource(b.file,Files.readAllBytes(b.file.toPath())));}else record=prepareRouterLast(f);}finally{if(lease!=null)AndroidMTUMeasurementGate.release(lease);}
   var home=routerOwner(f,!fault.equals("unproved"));if(fault.equals("superseded"))routerOwner(f,true);if(fault.equals("generation"))AndroidHomeStateStore.advancePathGeneration(f.activity);if(fault.equals("emergency"))AndroidHomeStateStore.warning(f.activity,"Emergency Disconnect requested; retained");if(fault.equals("selection"))f.prefs().edit().putString("multihop_entry_mode","awg2-fast").apply();if(fault.equals("write-failure"))AndroidPrivateFileStore.failWrite=true;
   check(!AndroidStartupPolicy.recordMultihopExecution(f.activity,record,home,"server",fault.equals("wrong-pins")?"{}":pins("server","wg-pq"))&&!Files.exists(f.dir.resolve("startup-multihop-last-v1.json")),"unowned private Last receipt persisted: "+fault);
  }
  for(String fault:List.of("entry","exit","selected","selection","idle","replacement"))for(boolean rotate:new boolean[]{false,true}){
   Fixture f=new Fixture(root);routerPath(f,"max-quic-awg","max-tls-wg","auto");saveRouterLast(f,"server");enableRouterLast(f);Bundle state=f.request();
   if(fault.equals("entry")||fault.equals("exit")||fault.equals("selected")){String id=fault.equals("entry")?ENTRY:fault.equals("exit")?EXIT:FIRST;Files.writeString(f.nodes.file(id).toPath(),bundle(id).put("new-native-source",true).toString());}if(fault.equals("selection"))f.prefs().edit().putString("multihop_exit_mode","wg-pq").apply();if(fault.equals("idle"))AndroidHomeStateStore.advancePathGeneration(f.activity);if(fault.equals("replacement"))routerOwner(f,true);
   if(rotate)f.restore(state);f.allow();check(!f.cb.ok&&f.starts()==0&&AndroidRuntimeRegistry.instance.multihop.lastStarts==0,"stale private Last permission launched: "+fault);
  }
 }
 static void graph(Path root)throws Exception{
  for(String mode:new String[]{"smart-auto","auto","last"})for(String execution:new String[]{"local","server","auto"}){Fixture f=new Fixture(root);f.policy(mode,true);f.prefs().edit().putBoolean("multihop_on",true).putString("multihop_entry",ENTRY).putString("multihop_exit",EXIT).putString("multihop_entry_mode","max-tls-awg").putString("multihop_exit_mode","shadowsocks").putString("multihop_execution",execution).apply();if(mode.equals("last")&&execution.equals("auto")){saveRouterLast(f,"server");enableRouterLast(f);}Bundle state=f.request();state.putString("routervpn.pending.mode","auto");state.putString("multihop_entry_mode_pending","wg");state.putString("multihop_execution_pending","local");f.restore(state);f.allow();AndroidMultihopRuntime m=AndroidRuntimeRegistry.instance.multihop;check(f.cb.ok&&m.starts==1&&AndroidRuntimeRegistry.instance.orchestrator.starts==0&&m.entryID.equals(ENTRY)&&m.exitID.equals(EXIT)&&m.entryMode.equals("max-tls-awg")&&m.exitMode.equals("shadowsocks")&&m.execution.equals(execution),"startup or restored Bundle substituted its captured graph");}
  Fixture incomplete=new Fixture(root);incomplete.policy("auto",true);incomplete.prefs().edit().putBoolean("multihop_on",true).apply();boolean failed=false;try{incomplete.capture();}catch(Exception expected){failed=true;}check(failed&&incomplete.starts()==0,"incomplete multihop silently became single-hop startup");
 }
 static void receipts(Path root)throws Exception{
  Fixture f=new Fixture(root);f.policy("smart-auto",false);VpnService.needsPermission=false;f.controller.connect("auto",List.of(),f.cb);Path saved=f.dir.resolve("startup-last-v1.json");check(f.cb.ok&&Files.isRegularFile(saved),"ordinary proved runtime did not record last mode");JSONObject receipt=new JSONObject(Files.readString(saved));check(receipt.length()==4&&receipt.getString("node_id").equals(FIRST)&&receipt.getString("raw_id").equals("wg")&&receipt.getString("profile_sha256").matches("[0-9a-f]{64}")&&!receipt.toString().contains("SECRET_"),"last receipt includes more than exact node/profile/raw identity");
  AndroidHomeStateStore.disconnected(f.activity);resetProcess();f.policy("last",true);AndroidStartupPolicy.Attempt captured=f.capture();check(captured.lastRaw.equals("wg"),"enabling Last mode lost the exact same node/path receipt");captured.cancel();
  for(String change:new String[]{"dns","key","raw","extra","legacy"}){resetProcess();String original=Files.readString(saved);JSONObject changed=new JSONObject(original);JSONObject bundle=f.root();if(change.equals("dns"))AndroidProfileSelection.selectedRouterProfile(bundle).put("dns_mode","rescue");if(change.equals("key"))AndroidProfileSelection.selectedRouterProfile(bundle).put("private_key","replacement");if(change.equals("raw"))changed.put("raw_id","../wg");if(change.equals("extra"))changed.put("secret","invalid");if(change.equals("legacy"))changed.remove("profile_sha256");Files.writeString(f.nodes.file(FIRST).toPath(),bundle.toString());Files.writeString(saved,changed.toString());AndroidStartupPolicy.Attempt stale=f.capture();check(stale.lastRaw.isEmpty(),"changed or unbound last receipt was accepted: "+change);stale.cancel();Files.writeString(saved,original);}
  for(String kind:new String[]{"test-node","unproved","superseded","write-failure"}){Fixture x=new Fixture(root);VpnService.needsPermission=false;AndroidModeOrchestrator o=AndroidRuntimeRegistry.instance.orchestrator;if(kind.equals("unproved"))o.rejectProof=true;if(kind.equals("superseded"))o.changeBeforeReceipt=true;if(kind.equals("write-failure"))AndroidPrivateFileStore.failWrite=true;if(kind.equals("test-node"))x.controller.connectNode(AndroidNodeStore.nodes.get(0),"auto",List.of(),x.cb);else x.controller.connect("auto",List.of(),x.cb);check(!Files.exists(x.dir.resolve("startup-last-v1.json")),"temporary, failed, stale or uncommitted proof entered last memory: "+kind);}
 }
 static final List<String> RAW_FAULTS=List.of("schema-text","schema-decimal","duplicate-schema","duplicate-value","duplicate-identical","duplicate-escaped","trailing-object","trailing-array","wrong-text","null-text");
 static String corruptReceipt(JSONObject receipt,String field,String fault)throws Exception{
  if(fault.equals("schema-text"))receipt.put("schema","1");if(fault.equals("wrong-text"))receipt.put(field,1);if(fault.equals("null-text"))receipt.put(field,JSONObject.NULL);
  String raw=receipt.toString();if(fault.equals("schema-decimal"))return raw.replace("\"schema\":1","\"schema\":1.0");
  if(fault.equals("duplicate-schema"))return raw.substring(0,raw.length()-1)+",\"schema\":1}";
  if(fault.startsWith("duplicate-")){
   String key=fault.equals("duplicate-escaped")?field.substring(0,1)+"\\"+String.format("u%04x",(int)field.charAt(1))+field.substring(2):field;
   String value=fault.equals("duplicate-value")?(field.equals("raw_id")?"awg2-fast":"local"):receipt.getString(field);
   return raw.substring(0,raw.length()-1)+",\""+key+"\":"+JSONObject.quote(value)+"}";
  }
  if(fault.equals("trailing-object"))return raw+"{}";if(fault.equals("trailing-array"))return raw+"[]";return raw;
 }
 static void strictReceipts(Path root)throws Exception{
  for(String fault:RAW_FAULTS){
   Fixture f=new Fixture(root);f.policy("smart-auto",false);VpnService.needsPermission=false;f.controller.connect("auto",List.of(),f.cb);Path file=f.dir.resolve("startup-last-v1.json");check(f.cb.ok&&Files.isRegularFile(file),"strict raw receipt setup failed");
   Files.writeString(file,corruptReceipt(new JSONObject(Files.readString(file)),"raw_id",fault));AndroidHomeStateStore.disconnected(f.activity);resetProcess();f.policy("last",true);var attempt=f.capture();
   check(attempt.lastRaw.isEmpty(),"ambiguous single-node Last receipt accepted: "+fault);attempt.cancel();
  }
  for(String protocol:List.of("tor","shadowsocks","openvpn"))for(String fault:RAW_FAULTS){
   Fixture f=new Fixture(root);var exit=external(f,protocol,"auto",true,"auto");check(AndroidStartupPolicy.recordExternalExecution(f.activity,preparedExternalLast(f,exit,"auto","server"),externalOwner(f,exit,true)),"strict external receipt setup failed");
   Path file=f.dir.resolve("startup-tor-last-v1.json");Files.writeString(file,corruptReceipt(new JSONObject(Files.readString(file)),"selected_execution",fault));enableExternalLast(f,exit);boolean rejected=false;try{f.capture();}catch(Exception expected){rejected=true;}
   check(rejected,"ambiguous external Last receipt accepted: "+fault);
  }
 }
 static <T> List<T> widgets(android.view.View root,Class<T> type){List<T> result=new ArrayList<>();if(type.isInstance(root))result.add(type.cast(root));if(root instanceof LinearLayout)for(android.view.View child:((LinearLayout)root).children)result.addAll(widgets(child,type));return result;}
 static void settings(Path root)throws Exception{
  Fixture f=new Fixture(root);AndroidProfileSettingsDialog.show(f.activity,f.nodes,()->{});AlertDialog dialog=AlertDialog.last;List<Spinner> spinners=widgets(dialog.view,Spinner.class);Spinner startup=null;for(Spinner s:spinners)if(s.getAdapter().getItem(0).toString().startsWith("SMART AUTO"))startup=s;CheckBox auto=null;for(CheckBox c:widgets(dialog.view,CheckBox.class))if(c.getText().toString().startsWith("Auto-connect once"))auto=c;check(startup!=null&&auto!=null&&startup.getSelectedItemPosition()==0&&!auto.isChecked(),"Settings has no real default startup/opt-in controls");auto.setChecked(true);startup.setSelection(2);dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();JSONObject p=AndroidProfileSelection.selectedRouterProfile(f.root());check(p.getString("startup_mode").equals("last")&&p.getBoolean("auto_connect"),"Settings did not persist explicit startup controls");
  AndroidProfileSettingsDialog.show(f.activity,f.nodes,()->{});dialog=AlertDialog.last;for(Spinner s:widgets(dialog.view,Spinner.class))if(s.getAdapter().getItem(0).toString().startsWith("SMART AUTO"))startup=s;for(CheckBox c:widgets(dialog.view,CheckBox.class))if(c.getText().toString().startsWith("Auto-connect once"))auto=c;startup.setSelection(3);check(!auto.isChecked()&&!auto.isEnabled(),"Manual retained active auto-connect");dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();p=AndroidProfileSelection.selectedRouterProfile(f.root());check(p.getString("startup_mode").equals("manual")&&!p.getBoolean("auto_connect"),"Manual did not save disconnected startup");
 }
 static void activity(Path root)throws Exception{
  Fixture f=new Fixture(root);f.policy("auto",true);StartupActivity first=new StartupActivity();first.onCreate(null);check(first.connection.isStartupPending()&&first.permissionRequest>=AndroidUnifiedConnectionController.PREPARE_UNIFIED,"shipping onCreate did not execute startup");first.importDecision="held-import";Bundle state=new Bundle();first.onSaveInstanceState(state);first.connection.close();StartupActivity rotated=new StartupActivity();rotated.onCreate(state);check(rotated.connection.isStartupPending()&&rotated.permission==null&&rotated.importDecision.equals("held-import"),"Activity rotation lost pending startup or existing import lifecycle");rotated.connection.onActivityResult(first.permissionRequest,Activity.RESULT_OK);check(AndroidRuntimeRegistry.instance.orchestrator.starts==1,"restored Activity did not start its captured request once");AndroidHomeStateStore.disconnected(f.activity);StartupActivity reopened=new StartupActivity();reopened.onCreate(null);check(!reopened.connection.isStartupPending()&&reopened.permission==null&&AndroidRuntimeRegistry.instance.orchestrator.starts==1,"same process reopen rearmed automatic connection");
 }
 static AndroidStandardExitStore.Entry external(Fixture f,String protocol,String mode,boolean hopped,String execution){AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.protocol=protocol;e.responseMap=AndroidTorProfile.isTor(protocol)?"":"prevalidated exact provider response and pairing contract";e.startupMode=mode;e.autoConnect=true;AndroidStandardExitStore.saved.clear();AndroidStandardExitStore.saved.put(e.id,AndroidStandardExitStore.copy(e));f.prefs().edit().putString("selected_kind","external").putString("selected_id",e.id).putBoolean("multihop_on",hopped).putString("multihop_entry",hopped?ENTRY:"").putString("multihop_exit",hopped?e.id:"").putString("multihop_exit_mode",protocol).putString("multihop_entry_mode",hopped?"max-tls-awg":"wg").putString("multihop_execution",execution).apply();return e;}
 static void missingExternalLast(Path root)throws Exception{
  for(String protocol:EXTERNAL_PROTOCOLS){Fixture f=new Fixture(root);external(f,protocol,"last",true,"auto");boolean rejected=false;try{f.capture();}catch(Exception expected){rejected=true;}
  check(rejected,"external Last without a source-bound winner reran Compare: "+protocol);}
 }
 static AndroidStartupPolicy.ExternalLast preparedExternalLast(Fixture f,AndroidStandardExitStore.Entry exit,String requested,String selected)throws Exception{
  return AndroidStartupPolicy.prepareExternalExecution(f.activity,f.nodes.file(ENTRY),exit,"max-tls-awg",requested,selected,AndroidTorProfile.digest(Files.readAllBytes(f.nodes.file(ENTRY).toPath())));
 }
 static AndroidHomeStateStore.Snapshot externalOwner(Fixture f,AndroidStandardExitStore.Entry exit,boolean prove){
  boolean tor=AndroidTorProfile.isTor(exit.protocol);
  if(tor)AndroidHomeStateStore.beginTorExternal(f.activity,exit.id,exit.name,exit.protocol,ENTRY,"max-tls-awg");else AndroidHomeStateStore.beginPolicyExternal(f.activity,exit.id,exit.name,exit.protocol,exit.expectedPublicIp,ENTRY,"max-tls-awg");var owner=AndroidHomeStateStore.snapshot(f.activity);
  if(prove)check(tor?AndroidHomeStateStore.connectedTorExternal(f.activity,owner,"8.8.4.4"):AndroidHomeStateStore.connectedPolicyExternal(f.activity,owner,"8.8.4.4"),"test owner did not adopt proof");return owner;
 }
 static void enableExternalLast(Fixture f,AndroidStandardExitStore.Entry exit)throws Exception{
  exit.startupMode="last";exit.autoConnect=true;AndroidStandardExitStore.saved.put(exit.id,AndroidStandardExitStore.copy(exit));
  JSONObject source=new JSONObject(Files.readString(f.nodes.file(ENTRY).toPath()));AndroidProfileSelection.selectedRouterProfile(source).put("startup_mode","manual").put("auto_connect",false);Files.writeString(f.nodes.file(ENTRY).toPath(),source.toString());
  AndroidHomeStateStore.disconnected(f.activity);resetProcess();
 }
 static void externalLastReceipts(Path root)throws Exception{
  for(String protocol:EXTERNAL_PROTOCOLS)for(String selected:List.of("local","server"))for(boolean rotate:new boolean[]{false,true}){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry exit=external(f,protocol,"smart-auto",true,"auto");exit.autoConnect=false;AndroidStandardExitStore.saved.put(exit.id,AndroidStandardExitStore.copy(exit));
   var prepared=preparedExternalLast(f,exit,"auto",selected);check(prepared!=null,"current selected external path did not prepare a Last receipt");var home=externalOwner(f,exit,true);
   check(AndroidStartupPolicy.recordExternalExecution(f.activity,prepared,home),"proved external execution was not persisted");Path file=f.dir.resolve("startup-tor-last-v1.json");String bytes=Files.readString(file);JSONObject receipt=new JSONObject(bytes);
   check(receipt.length()==5&&receipt.getInt("schema")==1&&receipt.getString("entry_id").equals(ENTRY)&&receipt.getString("exit_id").equals(exit.id)&&receipt.getString("selected_execution").equals(selected)&&receipt.getString("path_sha256").matches("[0-9a-f]{64}"),"external Last receipt is not complete and source-bound");
   check(!bytes.contains("SECRET_")&&!bytes.contains(exit.secret)&&!bytes.contains("score")&&!bytes.contains("private_key"),"external Last receipt leaked credentials or retained a stale measurement");
   enableExternalLast(f,exit);Bundle saved=f.request();check(f.captured.execution.equals("auto")&&f.captured.lastExecution.equals(selected),"Last lost saved Compare or exact proved execution");
   if(rotate){saved.putString("multihop_execution_pending",selected.equals("local")?"server":"local");f.restore(saved);}f.allow();AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.instance.standardExit;
   check(f.cb.ok&&runtime.starts==1&&runtime.restores==1&&runtime.execution.equals("auto")&&runtime.selected.equals(selected),"external Last reran Compare or restored the wrong execution");
   check(Files.readString(file).equals(bytes)&&!saved.values.toString().contains(exit.secret),"Last dispatch rewrote historical receipt or leaked private source");
  }
  for(String protocol:EXTERNAL_PROTOCOLS)for(String fault:List.of("entry-dns","entry-key","entry-native","exit-dns","exit-key","exit-pairing","entry-mode","receipt-entry","receipt-exit","receipt-leaf","receipt-source","receipt-extra","receipt-schema","receipt-missing","requested")){
   Fixture f=new Fixture(root);String requested=fault.equals("requested")?"local":"auto";var exit=external(f,protocol,"auto",true,requested);var prepared=preparedExternalLast(f,exit,requested,requested.equals("local")?"local":"server");check(AndroidStartupPolicy.recordExternalExecution(f.activity,prepared,externalOwner(f,exit,true)),"stale-case setup did not persist");Path file=f.dir.resolve("startup-tor-last-v1.json");JSONObject receipt=new JSONObject(Files.readString(file));enableExternalLast(f,exit);
   JSONObject source=new JSONObject(Files.readString(f.nodes.file(ENTRY).toPath()));if(fault.equals("entry-dns"))AndroidProfileSelection.selectedRouterProfile(source).put("dns_mode","rescue");if(fault.equals("entry-key"))AndroidProfileSelection.selectedRouterProfile(source).put("private_key","REPLACED");if(fault.equals("entry-native"))source.getJSONObject("profiles").getJSONObject("wg").put("wg.conf","REPLACED");Files.writeString(f.nodes.file(ENTRY).toPath(),source.toString());
   if(fault.equals("exit-dns"))exit.policy="new selected resolver";if(fault.equals("exit-key"))exit.secret="new provider credential";if(fault.equals("exit-pairing"))exit.responseMap="changed authenticated provider contract";AndroidStandardExitStore.saved.put(exit.id,AndroidStandardExitStore.copy(exit));if(fault.equals("entry-mode"))f.prefs().edit().putString("multihop_entry_mode","wg").apply();
   if(fault.equals("receipt-entry"))receipt.put("entry_id",FIRST);if(fault.equals("receipt-exit"))receipt.put("exit_id","other");if(fault.equals("receipt-leaf"))receipt.put("selected_execution","auto");if(fault.equals("receipt-source"))receipt.put("path_sha256","0".repeat(64));if(fault.equals("receipt-extra"))receipt.put("score",0);if(fault.equals("receipt-schema"))receipt.put("schema",0);if(fault.equals("receipt-missing"))receipt.remove("path_sha256");if(fault.equals("requested"))f.prefs().edit().putString("multihop_execution","auto").apply();Files.writeString(file,receipt.toString());
   boolean rejected=false;try{f.capture();}catch(Exception expected){rejected=true;}check(rejected&&f.starts()==0&&AndroidRuntimeRegistry.instance.standardExit.starts==0,"changed external Last source or receipt was accepted: "+fault);
  }
  for(String protocol:EXTERNAL_PROTOCOLS)for(String fault:List.of("unproved","superseded","generation","emergency","selected","native-digest","exit-source","request-leaf","speed-lab","write-failure")){
   Fixture f=new Fixture(root);var exit=external(f,protocol,"auto",true,"auto");String digest=AndroidTorProfile.digest(Files.readAllBytes(f.nodes.file(ENTRY).toPath()));
   if(fault.equals("native-digest"))digest="0".repeat(64);if(fault.equals("exit-source"))exit.secret="not saved";Object lease=null;if(fault.equals("speed-lab"))lease=AndroidMTUMeasurementGate.acquire();
   var prepared=AndroidStartupPolicy.prepareExternalExecution(f.activity,f.nodes.file(ENTRY),exit,"max-tls-awg",fault.equals("request-leaf")?"local":"auto","server",digest);if(lease!=null)AndroidMTUMeasurementGate.release(lease);
   var home=externalOwner(f,exit,!fault.equals("unproved"));if(fault.equals("superseded"))externalOwner(f,exit,true);if(fault.equals("generation"))AndroidHomeStateStore.advancePathGeneration(f.activity);if(fault.equals("selected"))f.prefs().edit().putString("selected_id","other").apply();if(fault.equals("emergency"))AndroidHomeStateStore.warning(f.activity,"Emergency Disconnect requested; retained");if(fault.equals("write-failure"))AndroidPrivateFileStore.failWrite=true;
   check(!AndroidStartupPolicy.recordExternalExecution(f.activity,prepared,home)&&!Files.exists(f.dir.resolve("startup-tor-last-v1.json")),"unowned or uncommitted external Last receipt persisted: "+fault);
  }
 }
 static void externalStartup(Path root)throws Exception{
  for(String protocol:new String[]{"wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn","tor","tor-bridge"})for(String mode:new String[]{"smart-auto","auto","last"})for(boolean hopped:new boolean[]{false,true})for(boolean restore:new boolean[]{false,true}){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry e=external(f,protocol,mode,hopped,"local");Bundle state=f.request();if(restore){state.putBoolean("routervpn.pending.external_direct",!hopped);state.putString("multihop_entry_mode_pending","wg");f.restore(state);}f.allow();AndroidStandardExitRuntime r=AndroidRuntimeRegistry.instance.standardExit;check(f.cb.ok&&r.starts==1&&AndroidRuntimeRegistry.instance.orchestrator.starts==0&&AndroidRuntimeRegistry.instance.multihop.starts==0,"external startup selected another runtime");check(r.exit.protocol.equals(protocol)&&r.exit.secret.equals(e.secret)&&(hopped?r.entry.equals(f.nodes.file(ENTRY))&&r.mode.equals("max-tls-awg"):r.entry==null),"external startup changed captured protocol, credentials or entry");check(!state.values.toString().contains(e.secret)&&!state.values.toString().contains(e.policy),"external credentials entered Activity state");
  }
  for(String choice:List.of("server","auto")){Fixture f=new Fixture(root);external(f,"shadowsocks","auto",true,choice);Bundle state=f.request();f.restore(state);f.allow();check(f.cb.ok&&AndroidRuntimeRegistry.instance.standardExit.execution.equals(choice),"external startup dropped captured Server/Compare preference");}
  for(String protocol:List.of("tor","tor-bridge"))for(String mode:List.of("smart-auto","auto","last"))for(boolean restore:new boolean[]{false,true}){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry e=external(f,protocol,mode,true,"server");Bundle state=f.request();if(restore)f.restore(state);f.allow();AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.instance.standardExit;
   check(f.cb.ok&&runtime.starts==1&&runtime.execution.equals("server")&&runtime.mode.equals("max-tls-awg")&&runtime.exit.protocol.equals(protocol)&&runtime.exit.secret.equals(e.secret),"Tor startup replaced captured Server execution or source");
  }
  for(String change:new String[]{"key","dns","startup","removed","kind","selected","entry-bytes","entry-mode","execution","direct","idle","foreign-vpn"})for(boolean restore:new boolean[]{false,true}){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry e=external(f,"shadowsocks","auto",true,"auto");Bundle state=f.request();
   if(change.equals("key"))e.secret="changed";if(change.equals("dns"))e.policy="changed-dns";if(change.equals("startup"))e.autoConnect=false;AndroidStandardExitStore.saved.put(e.id,AndroidStandardExitStore.copy(e));
   if(change.equals("removed"))AndroidStandardExitStore.saved.clear();if(change.equals("kind"))f.prefs().edit().putString("selected_kind","router-vpn").apply();if(change.equals("selected"))f.prefs().edit().putString("selected_id",FIRST).apply();if(change.equals("entry-bytes"))Files.writeString(f.nodes.file(ENTRY).toPath(),"changed");
   if(change.equals("entry-mode"))f.prefs().edit().putString("multihop_entry_mode","wg").apply();if(change.equals("execution"))f.prefs().edit().putString("multihop_execution","local").apply();if(change.equals("direct"))f.prefs().edit().putBoolean("multihop_on",false).apply();if(change.equals("idle"))AndroidHomeStateStore.advancePathGeneration(f.activity);if(change.equals("foreign-vpn"))Context.connectivity.vpn=true;
   if(restore)f.restore(state);f.allow();check(!f.cb.ok&&AndroidRuntimeRegistry.instance.standardExit.starts==0&&f.starts()==0,"stale external startup accepted: "+change+"/"+restore);
  }
 }
 static AndroidStandardExitStore.Entry ordinary(Fixture f,String protocol,String mode){
  AndroidStandardExitStore.Entry exit=external(f,"tor-bridge",mode,true,"local");exit.policy="explicit selected Tor DNS";AndroidStandardExitStore.saved.put(exit.id,AndroidStandardExitStore.copy(exit));
  AndroidStandardExitStore.Entry entry=new AndroidStandardExitStore.Entry();entry.id=ENTRY;entry.protocol=protocol;entry.secret="ORDINARY_PRIVATE_SOURCE";entry.policy="distinct ordinary selected DNS";AndroidStandardExitStore.saved.put(entry.id,AndroidStandardExitStore.copy(entry));
  f.prefs().edit().putString("multihop_entry_kind","external").putString("multihop_entry_mode",AndroidExternalPolicy.protocol(protocol)).apply();return entry;
 }
 static void ordinaryStartup(Path root)throws Exception{
  for(String protocol:List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn"))for(String mode:List.of("smart-auto","auto","last"))for(boolean rotate:new boolean[]{false,true}){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry entry=ordinary(f,protocol,mode);String router=Files.readString(f.nodes.file(ENTRY).toPath());Bundle state=f.request();
   check(f.captured.multihop()&&f.captured.entry==null&&f.captured.ordinaryEntry!=null&&f.captured.ordinaryEntry.id.equals(ENTRY)&&f.captured.ordinaryEntry!=entry,"startup did not capture a separate immutable ordinary entry");
   check(!state.values.toString().contains(entry.secret)&&!state.values.toString().contains(entry.policy)&&!state.values.toString().contains("explicit selected Tor DNS"),"ordinary private sources leaked into Activity state");
   if(rotate){state.putString("multihop_entry_mode_pending","wg");state.putBoolean("routervpn.pending.external_direct",true);f.restore(state);}f.allow();AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.instance.standardExit;
   check(f.cb.ok&&runtime.starts==1&&runtime.ordinaryEntry!=null&&runtime.ordinaryEntry.id.equals(ENTRY)&&runtime.ordinaryEntry.protocol.equals(protocol)&&runtime.ordinaryEntry.secret.equals(entry.secret)&&runtime.entry==null&&runtime.exit.protocol.equals("tor-bridge")&&runtime.execution.equals("local"),"ordinary startup substituted Router/direct/execution/credentials: "+protocol+"/"+mode+"/"+rotate);
   check(f.starts()==0&&Files.readString(f.nodes.file(ENTRY).toPath()).equals(router),"ordinary startup used or rewrote colliding Router identity");f.allow();check(runtime.starts==1,"duplicate ordinary startup permission started twice");
  }
  for(String change:List.of("entry-key","entry-policy","entry-protocol","entry-identity","entry-removed","exit-key","captured-key","kind","entry-id","execution","direct","mode","idle","foreign-vpn"))for(boolean rotate:new boolean[]{false,true}){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry entry=ordinary(f,"socks5","last");Bundle state=f.request();
   if(change.equals("entry-key"))entry.secret="replacement ordinary private source";if(change.equals("entry-policy"))entry.policy="replacement ordinary policy";if(change.equals("entry-protocol"))entry.protocol="http";if(change.equals("entry-identity"))entry.expectedPublicIp="1.1.1.1";AndroidStandardExitStore.saved.put(entry.id,AndroidStandardExitStore.copy(entry));
   if(change.equals("entry-removed"))AndroidStandardExitStore.saved.remove(entry.id);if(change.equals("exit-key")){var exit=AndroidStandardExitStore.saved.get("saved-exit");exit.secret="replacement Tor source";}if(change.equals("captured-key"))f.captured.ordinaryEntry.secret="mutable captured source";
   if(change.equals("kind"))f.prefs().edit().putString("multihop_entry_kind","router-vpn").apply();if(change.equals("entry-id"))f.prefs().edit().putString("multihop_entry",FIRST).apply();if(change.equals("execution"))f.prefs().edit().putString("multihop_execution","server").apply();if(change.equals("direct"))f.prefs().edit().putBoolean("multihop_on",false).apply();if(change.equals("mode"))f.prefs().edit().putString("multihop_entry_mode","wg").apply();if(change.equals("idle"))AndroidHomeStateStore.advancePathGeneration(f.activity);if(change.equals("foreign-vpn"))Context.connectivity.vpn=true;
   if(rotate)f.restore(state);f.allow();check(!f.cb.ok&&AndroidRuntimeRegistry.instance.standardExit.starts==0&&f.starts()==0,"stale ordinary startup capture started: "+change+"/"+rotate);
  }
  for(String invalid:List.of("server","auto","unknown-kind","router-kind","unknown-mode","same-id","private-router-selection")){
   Fixture f=new Fixture(root);ordinary(f,"socks5","auto");
   if(invalid.equals("server")||invalid.equals("auto"))f.prefs().edit().putString("multihop_execution",invalid).apply();
   if(invalid.equals("unknown-kind"))f.prefs().edit().putString("multihop_entry_kind","unknown").apply();if(invalid.equals("router-kind"))f.prefs().edit().putString("multihop_entry_kind","router-vpn").apply();if(invalid.equals("unknown-mode"))f.prefs().edit().putString("multihop_entry_mode","wg").apply();if(invalid.equals("same-id"))f.prefs().edit().putString("multihop_entry","saved-exit").apply();
   if(invalid.equals("private-router-selection")){f.policy("auto",true);f.prefs().edit().putString("selected_kind","router-vpn").putString("selected_id",FIRST).putString("multihop_exit",EXIT).putString("multihop_entry_mode","wg").apply();}
   boolean rejected=false;try{f.capture();}catch(Exception expected){rejected=true;}check(rejected&&f.starts()==0&&AndroidRuntimeRegistry.instance.standardExit.starts==0,"invalid ordinary startup acquired private authority: "+invalid);
  }
 }
 public static void main(String[] args)throws Exception{Path root=Path.of(args[0]);defaults(root);missingExternalLast(root);permission(root);changes(root);graph(root);receipts(root);strictReceipts(root);routerLastReceipts(root);settings(root);activity(root);externalLastReceipts(root);externalStartup(root);ordinaryStartup(root);System.out.println("Android startup: "+checks+" shipping policy, Activity, Settings, permission and receipt checks PASS");}
}
'''


def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    if not jar.is_file():raise RuntimeError('Android JSON JAR is required')
    ui=dict(P.T.UI);ui['android/content/SharedPreferences.java']=PREFS;ui['android/content/MemoryPreferences.java']=MEMORY
    ui['android/content/Context.java']=ui['android/content/Context.java'].replace('public Object getSystemService(String name){return null;}','public static android.net.ConnectivityManager connectivity=new android.net.ConnectivityManager();public Object getSystemService(String name){return connectivity;}').replace('return (key,fallback)->fallback;','return preferences.computeIfAbsent(name,key->new MemoryPreferences());').replace('public static final int MODE_PRIVATE=0;','public static final java.util.Map<String,MemoryPreferences> preferences=new java.util.LinkedHashMap<>();public static final int MODE_PRIVATE=0;')
    ui['android/os/Bundle.java']=ui['android/os/Bundle.java'][:-1]+'public void putStringArrayList(String k,java.util.ArrayList<String> v){values.put(k,new java.util.ArrayList<>(v));}public java.util.ArrayList<String> getStringArrayList(String k){return (java.util.ArrayList<String>)values.get(k);}public boolean containsKey(String k){return values.containsKey(k);}}'
    ui['android/net/Network.java']='package android.net;public final class Network {}'
    ui['android/net/NetworkCapabilities.java']='package android.net;public final class NetworkCapabilities {public static final int TRANSPORT_VPN=4;final boolean vpn;NetworkCapabilities(boolean vpn){this.vpn=vpn;}public boolean hasTransport(int value){return value==TRANSPORT_VPN&&vpn;}}'
    ui['android/net/ConnectivityManager.java']='package android.net;public final class ConnectivityManager {public boolean vpn;final Network physical=new Network(),other=new Network();public Network getActiveNetwork(){return physical;}public Network[] getAllNetworks(){return vpn?new Network[]{physical,other}:new Network[]{physical};}public NetworkCapabilities getNetworkCapabilities(Network n){return new NetworkCapabilities(vpn&&n==other);}}'
    ui['com/wireguard/android/backend/Tunnel.java']='package com.wireguard.android.backend;public interface Tunnel{enum State{UP,DOWN}}'
    ui['org/amnezia/awg/backend/Tunnel.java']='package org.amnezia.awg.backend;public interface Tunnel{enum State{UP,DOWN}}'
    ui['io/nekohasekai/libbox/Libbox.java']=PRIVATE_JSON_JAVA
    ui['android/util/Base64.java']='package android.util;public final class Base64{public static final int DEFAULT=0,NO_WRAP=2;public static byte[] decode(String raw,int flags){return java.util.Base64.getMimeDecoder().decode(raw);}public static String encodeToString(byte[] raw,int flags){return java.util.Base64.getEncoder().encodeToString(raw);}}'
    boundaries=P.BOUNDARIES.replace('import android.content.Context;', 'import android.content.Context;import android.content.SharedPreferences;import android.util.Base64;')
    # Receipt ownership covers every externally authenticated protocol. The
    # runtime/graph suites compile actual provider/pairing admission; this
    # boundary marks a fully validated response contract without minting one.
    old='e.protocol.equals("shadowsocks")||e.protocol.equals("openvpn")&&!e.responseMap.isEmpty()||AndroidTorProfile.isTor(e.protocol)'
    assert boundaries.count(old)==1
    boundaries=boundaries.replace(old,'AndroidExternalPolicy.supports(e.protocol)&&!e.responseMap.isEmpty()||AndroidTorProfile.isTor(e.protocol)')
    boundaries=boundaries.replace('int starts;String mode,execution=', 'int starts,restores;String mode,execution=').replace('winner,Callback cb){connect(f,e,mode,execution,cb);selected=winner;}', 'winner,Callback cb){restores++;connect(f,e,mode,execution,cb);selected=winner;}')
    for name in ('AndroidStartupPolicy','AndroidHomeStateStore'):boundaries=replace_class(boundaries,name,'')
    if 'final class AndroidExternalPolicy ' in boundaries:boundaries=replace_class(boundaries,'AndroidExternalPolicy','')
    if 'final class AndroidConnectionProfileStore ' in boundaries:boundaries=replace_class(boundaries,'AndroidConnectionProfileStore','')
    boundaries=replace_class(boundaries,'AndroidNodeStore',NODE);boundaries=replace_class(boundaries,'AndroidModeOrchestrator',ORCHESTRATOR)
    runtime=(JAVA/'AndroidMultihopRuntime.java').read_text()
    startup_capture=block(runtime,'    static final class StartupCapture {')+'\n'+block(runtime,'    static StartupCapture startupCapture(')
    boundaries=replace_class(boundaries,'AndroidMultihopRuntime',MULTIHOP.replace(' // SHIPPING_STARTUP_CAPTURE',startup_capture))
    controller=(JAVA/'AndroidMultihopController.java').read_text()
    source_methods='\n'.join(block(controller,signature) for signature in ('    static final class Source {','    private static final class LoadedBundle {','    static Source captureSource(', '    static String validatedServerIdentityPins(', '    private static String sourceDigest(', '    private static byte[] readBundleBytes('))
    boundaries+='\nfinal class AndroidMultihopController{private static final int MAX_BUNDLE=32*1024*1024;'+source_methods+'\n}\n'
    max_source=(JAVA/'AndroidNativeMAXProfile.java').read_text()
    modes=max_source[max_source.index('    private static final Set<String> MODES'):max_source.index(';',max_source.index('    private static final Set<String> MODES'))+1]
    boundaries+='\nfinal class AndroidNativeMAXProfile{'+modes+block(max_source,'    static boolean isMode(')+'}\n'
    boundaries=boundaries.replace('final class NativeWireGuardController {}','final class NativeWireGuardController {com.wireguard.android.backend.Tunnel.State getState(){return com.wireguard.android.backend.Tunnel.State.DOWN;}}').replace('final class NativeAmneziaWGController {}','final class NativeAmneziaWGController {org.amnezia.awg.backend.Tunnel.State getState(){return org.amnezia.awg.backend.Tunnel.State.DOWN;}}')
    boundaries=boundaries.replace('static byte[] read(File f,int max)', 'static boolean failWrite;static void write(File f,byte[] b,int max)throws Exception{if(failWrite)throw new IOException("injected durable failure");if(b.length==0||b.length>max)throw new IllegalArgumentException("bounded private write");Path t=Files.createTempFile(f.getParentFile().toPath(),"staged-",".json");Files.write(t,b);Files.move(t,f.toPath(),StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);}static byte[] read(File f,int max)')
    native=(JAVA/'NativeSingBoxController.java').read_text();methods=[]
    for name in ('nativeMultihopEntry','nativeWireGuardFamily','nativeNaiveFamily','nativePQFamily'):
        methods.append(re.findall(r'(?ms)^    static boolean '+name+r'\(String mode\) \{\n.*?^    \}',native)[0])
    composite=re.findall(r'(?ms)^    static boolean isMode\(String mode\) \{\n.*?^    \}',(JAVA/'AndroidNativeCompositeProfile.java').read_text())[0]
    profiles=(JAVA/'AndroidConnectionProfileStore.java').read_text();selection=[]
    for signature in ('    private static String normalizeEntryKind(', '    private static String normalizeOrdinaryMode(', '    static final class ExternalSelection {','    synchronized ExternalSelection currentExternalPath('):
        start=profiles.index(signature);at=profiles.index('{',start);depth=1;end=at+1
        while depth:
            depth+=(profiles[end]=='{')-(profiles[end]=='}');end+=1
        selection.append(profiles[start:end])
    boundaries=boundaries.replace(' // PRODUCTION_TRANSPORT_PREDICATES','\n'.join(methods)).replace(' // PRODUCTION_COMPOSITE_PREDICATE',composite)+EXTRA.replace(' // SHIPPING_EXTERNAL_SELECTION','\n'.join(selection))
    product=(JAVA/'ProductActivity.java').read_text();extracted=[]
    for prefix in ('    @Override protected void onCreate(', '    @Override protected void onSaveInstanceState(', '    private void applyStartupPolicy('):
        start=product.index(prefix);end=product.find('\n    ',start+len(prefix));
        if prefix.endswith('applyStartupPolicy('):end=product.index('\n    private ',start+len(prefix))
        extracted.append(product[start:end])
    resume=product.split('    @Override protected void onResume(',1)[1].split('\n    @Override',1)[0]
    assert 'applyStartupPolicy(' not in resume and 'coldLaunch(' not in resume, 'resume must never rearm startup'
    with tempfile.TemporaryDirectory(prefix='routervpn-startup-') as directory, tempfile.TemporaryDirectory(prefix='.startup-json-',dir=ROOT) as validator_directory:
        root=Path(directory)
        # The exact exported gomobile parser, not a permissive JSON test double,
        # sees raw duplicates/trailing content before Android JSONObject does.
        validator_source=Path(validator_directory)/'main.go';validator_source.write_text(PRIVATE_JSON_GO)
        validator=root/('private-json.exe' if os.name=='nt' else 'private-json')
        subprocess.run(['go','build','-o',str(validator),str(validator_source)],cwd=ROOT,check=True,timeout=120)
        for path,source in ui.items():target=root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(source)
        app=root/'com/eabusham/routervpn';app.mkdir(parents=True)
        (app/'Boundaries.java').write_text(boundaries);(app/'StartupTest.java').write_text(HARNESS);(app/'StartupActivity.java').write_text(ACTIVITY.replace(' // SHIPPING_ACTIVITY_METHODS','\n'.join(extracted)))
        names=('AndroidMTUMeasurementGate.java','AndroidConnectionSelection.java','AndroidStartupPolicy.java','AndroidUnifiedConnectionController.java','AndroidHomeStateStore.java','AndroidProfileSelection.java','AndroidProfileSettingsDialog.java')
        for name in names:(app/name).write_bytes((JAVA/name).read_bytes())
        compile=['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(root/'classes'),*map(str,root.rglob('*.java'))]
        run=['java','-Dfixture.privatejson='+str(validator),'-cp',os.pathsep.join((str(root/'classes'),str(jar))),'com.eabusham.routervpn.StartupTest',str(root/'data')]
        (root/'data').mkdir();subprocess.run(compile,check=True,timeout=45);subprocess.run(run,check=True,timeout=60)
        controls=(
            ('AndroidUnifiedConnectionController.java','if(startup!=null&&startup.lastMultihop!=null)','if(false&&startup!=null&&startup.lastMultihop!=null)','Router Last reran Compare or changed its historical winner'),
            ('AndroidStartupPolicy.java','.put("selected_sha256",profileIdentity(selected))','.put("selected_sha256","unbound")','changed private Last source or receipt accepted: selected-dns'),
            ('AndroidStartupPolicy.java','.put("exit_sha256",profileIdentity(exit))','.put("exit_sha256","unbound")','changed private Last source or receipt accepted: exit-dns'),
            ('AndroidStartupPolicy.java','if(AndroidMTUMeasurementGate.held()||entry==null','if(false||entry==null','unowned private Last receipt persisted: speed-lab'),
            ('AndroidStartupPolicy.java','io.nekohasekai.libbox.Libbox.routerValidatePrivateNodeJSON(raw);','/* mutation: raw duplicate and trailing validation omitted */','ambiguous single-node Last receipt accepted: duplicate-schema'),
            ('AndroidStartupPolicy.java','!(schema instanceof Integer||schema instanceof Long)||((Number)schema).longValue()!=1','object.getInt("schema")!=1','ambiguous single-node Last receipt accepted: schema-text'),
            ('AndroidStartupPolicy.java','if(!(object.opt(key) instanceof String))','if(false&&!(object.opt(key) instanceof String))','ambiguous single-node Last receipt accepted: wrong-text'),
            ('AndroidUnifiedConnectionController.java','execution,startup.lastExecution,bridge','execution,"local",bridge','external Last reran Compare or restored the wrong execution'),
            ('AndroidStartupPolicy.java','lastExecution=lastExternalExecution(context,path.entry.id,files.get(path.entry.id),saved,path.entryMode,path.execution);','lastExecution="server";','external Last without a source-bound winner reran Compare'),
            ('AndroidStartupPolicy.java','.put("exit",external)','.put("exit",exit.id)','changed external Last source or receipt was accepted: exit-dns'),
            ('AndroidStartupPolicy.java','.put("entry_sha256",profileIdentity(bundle))','.put("entry_sha256","unbound")','changed external Last source or receipt was accepted: entry-dns'),
            ('AndroidStartupPolicy.java','.put("entry_mode",mode).put("execution",requested)','.put("entry_mode",mode).put("execution","auto")','changed external Last source or receipt was accepted: requested'),
            ('AndroidStartupPolicy.java','||!capturedHome.sessionId.equals(home.sessionId)\n                        ||capturedHome.pathGeneration!=home.pathGeneration||!home.connected||!"connected".equals(home.phase)||!"passed".equals(home.pathProof)\n                        ||!"external".equals(home.logicalMode)','||false||!home.connected||!"connected".equals(home.phase)||!"passed".equals(home.pathProof)\n                        ||!"external".equals(home.logicalMode)','unowned or uncommitted external Last receipt persisted: superseded'),
            ('AndroidStartupPolicy.java','if(AndroidMTUMeasurementGate.held()||entryFile==null','if(false||entryFile==null','unowned or uncommitted external Last receipt persisted: speed-lab'),
            ('AndroidUnifiedConnectionController.java','startup.requireCurrent(activity,nodeStore,this);startup.dispatched();','startup.dispatched();','stale startup capture started'),
            ('AndroidStartupPolicy.java','if(!Arrays.equals(captured.getValue(),AndroidPrivateFileStore.read(current,AndroidNodeStore.MAX_BUNDLE)))','if(false&&!Arrays.equals(captured.getValue(),AndroidPrivateFileStore.read(current,AndroidNodeStore.MAX_BUNDLE)))','stale startup capture started'),
            ('AndroidStartupPolicy.java','if(ordinaryEntry!=null&&(!ordinaryEntrySnapshot.equals(AndroidStandardExitStore.snapshot(ordinaryEntry))','if(false&&ordinaryEntry!=null&&(!ordinaryEntrySnapshot.equals(AndroidStandardExitStore.snapshot(ordinaryEntry))','stale ordinary startup capture started: captured-key'),
        )
        for name,old,new,assertion in controls:
            target=app/name;original=target.read_text();assert original.count(old)==1,(name,old);target.write_text(original.replace(old,new));subprocess.run(compile,check=True,timeout=45,stdout=subprocess.PIPE,stderr=subprocess.PIPE);broken=subprocess.run(run,timeout=60,capture_output=True,text=True);target.write_text(original)
            assert broken.returncode and assertion in broken.stderr,'startup negative control was not rejected at the intended assertion: '+name+'\n'+broken.stdout+broken.stderr
            print('Android startup negative control rejected: '+name)


if __name__=='__main__':main()
