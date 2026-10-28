#!/usr/bin/env python3
"""Execute the shipping unified external permission and restored-state bridge."""
from pathlib import Path
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
spec = importlib.util.spec_from_file_location("external_permission_widgets", ROOT / "android/test_android_tor_form.py")
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)

MULTIHOP_CAPTURE_TYPES = r'''
 static final class CapturedSource {final File file;final String digest;CapturedSource(File file)throws Exception{this.file=file.getCanonicalFile();digest=AndroidTorProfile.digest(AndroidPrivateFileStore.read(file,AndroidNodeStore.MAX_BUNDLE));}void require(File other)throws Exception{if(!file.equals(other.getCanonicalFile())||!digest.equals(AndroidTorProfile.digest(AndroidPrivateFileStore.read(other,AndroidNodeStore.MAX_BUNDLE))))throw new IllegalStateException("changed captured source");}}
 static final class CapturedOwner {final String homeSession,entryId,exitId,entryMode,exitMode,pins;final long generation;CapturedOwner(AndroidHomeStateStore.Snapshot home,String pins){homeSession=home.sessionId;generation=home.pathGeneration;entryId=home.activeEntryId;exitId=home.activeExitId;entryMode=home.activeEntryMode;exitMode=home.runtimeMode;this.pins=pins;}boolean matchesHome(AndroidHomeStateStore.Snapshot home){return home.connected&&homeSession.equals(home.sessionId)&&generation==home.pathGeneration&&entryId.equals(home.activeEntryId)&&exitId.equals(home.activeExitId)&&entryMode.equals(home.activeEntryMode)&&exitMode.equals(home.runtimeMode);}}
 static final class RestoreCapture {final String policy,selected;final CapturedOwner owner;final CapturedSource entrySource,exitSource;RestoreCapture(String policy,String selected,AndroidHomeStateStore.Snapshot home,AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,String pins)throws Exception{this.policy=policy;this.selected=selected;owner=new CapturedOwner(home,pins);entrySource=new CapturedSource(entry.file);exitSource=new CapturedSource(exit.file);}void require(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit)throws Exception{if(!owner.entryId.equals(entry.id)||!owner.exitId.equals(exit.id))throw new IllegalStateException("wrong captured nodes");entrySource.require(entry.file);exitSource.require(exit.file);}}
'''

BOUNDARIES = r'''package com.eabusham.routervpn;
import android.content.Context;import java.io.*;import java.util.*;import java.nio.file.*;import java.nio.charset.*;import org.json.*;
final class AndroidPrivateFileStore {static byte[] read(File f,int max)throws Exception{byte[] b=Files.readAllBytes(f.toPath());if(b.length==0||b.length>max)throw new IllegalArgumentException("bounded private input required");return b;}}
final class AndroidTorProfile {static String compileOrdinary(AndroidStandardExitStore.Entry entry,AndroidStandardExitStore.Entry exit,String session,String execution){if(!AndroidExternalPolicy.supports(entry.protocol)||!isTor(exit.protocol)||entry.id.equals(exit.id)||!execution.equals("local"))throw new IllegalArgumentException("invalid ordinary Tor selection");return "{}";}static boolean isTor(String p){return "tor".equals(p)||"tor-bridge".equals(p);}static String strictText(byte[] b)throws Exception{return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(b)).toString();}static String digest(byte[] b)throws Exception{return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(b));}}
final class AndroidVpnMutationGuard {static boolean busy;static boolean isBusy(Context c){return busy;}}
final class AndroidHomeStateStore {static final class Snapshot{boolean connected;long pathGeneration;String sessionId="",phase="off",pathProof="not-run",logicalMode="",runtimeMode="",fallback="",activeNodeId="",activeEntryId="",activeExitId="",activeEntryMode="",activeExternalId="",activeExternalProtocol="";}static Snapshot current=new Snapshot();static Snapshot snapshot(Context c){return current;}static long advancePathGeneration(Context c){return ++current.pathGeneration;}}
final class AndroidNodeStore {
 static final int MAX_BUNDLE=32*1024*1024;static final List<Node> nodes=new ArrayList<>();static String active;
 static final class Node {final String id,name,endpoint="";final File file;Node(String id,File f){this.id=id;name=id;file=f;}}
 AndroidNodeStore(Context c){}List<Node> list(){return new ArrayList<>(nodes);}String activeId(){return active!=null?active:nodes.isEmpty()?"":nodes.get(0).id;}File file(String id){for(Node n:nodes)if(n.id.equals(id))return n.file;return null;}
 static void validateBundle(JSONObject b)throws Exception{b.getJSONObject("profiles");b.getJSONArray("modes");}
}
final class AndroidStandardExitStore {
 static final Map<String,Entry> saved=new HashMap<>();
 static final class Entry {String id="saved-exit",name="Saved external",protocol="openvpn",secret="private-endpoint-key",policy="captured-home",expectedPublicIp="8.8.4.4";String startupMode="smart-auto",responseMap="";boolean autoConnect;}
 AndroidStandardExitStore(Context c){}List<Entry> list()throws Exception{List<Entry> list=new ArrayList<>();for(Entry e:saved.values())list.add(copy(e));return list;}Entry get(String id)throws Exception{Entry e=saved.get(id);if(e==null)throw new IllegalArgumentException("missing exit");return copy(e);}
 static void validateExecution(Entry e,boolean entry,String execution){if(!List.of("local","server","auto").contains(execution)||!execution.equals("local")&&(!entry||!(e.protocol.equals("shadowsocks")||e.protocol.equals("openvpn")&&!e.responseMap.isEmpty()||AndroidTorProfile.isTor(e.protocol)&&execution.equals("server"))))throw new IllegalArgumentException("unowned execution");}
 static void validate(Entry e){if(e==null||e.id.isEmpty())throw new IllegalArgumentException("missing saved exit");}
 static Entry copy(Entry e){Entry x=new Entry();x.id=e.id;x.name=e.name;x.protocol=e.protocol;x.secret=e.secret;x.policy=e.policy;x.expectedPublicIp=e.expectedPublicIp;x.startupMode=e.startupMode;x.autoConnect=e.autoConnect;x.responseMap=e.responseMap;return x;}
 static String snapshot(Entry e)throws Exception{return new JSONObject().put("startup_mode",e.startupMode).put("auto_connect",e.autoConnect).put("id",e.id).put("name",e.name).put("protocol",e.protocol).put("secret",e.secret).put("policy",e.policy).put("expected",e.expectedPublicIp).put("openvpn_response_probes",e.responseMap).toString();}
}
final class AndroidExternalPolicy {
 static boolean supports(String p){return List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn").contains(p);}
 static String protocol(String p){return p.equals("http")?"http-connect":p.equals("https")?"https-connect":p;}
}
final class AndroidConnectionProfileStore {
 AndroidConnectionProfileStore(Context c,AndroidNodeStore n,AndroidStandardExitStore e){}ExternalSelection currentExternalPath(String id){throw new AssertionError("permission UI must cancel before selecting a new path");}
 static final class ExternalSelection{final AndroidNodeStore.Node entry;final AndroidStandardExitStore.Entry ordinaryEntry,exit;final String entryMode,execution;
 ExternalSelection(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry ordinaryEntry,AndroidStandardExitStore.Entry exit,String mode,String execution){this.entry=entry;this.ordinaryEntry=ordinaryEntry;this.exit=exit;entryMode=mode;this.execution=execution;}boolean direct(){return entry==null&&ordinaryEntry==null;}}
}
final class NativeWireGuardController {}final class NativeAmneziaWGController {}final class NativeXrayController {}
final class NativeSingBoxController {
 static final class ModeInfo {final String id,name;ModeInfo(String id,String name){this.id=id;this.name=name;}}
 // PRODUCTION_TRANSPORT_PREDICATES
}
final class AndroidNativeCompositeProfile {
 // PRODUCTION_COMPOSITE_PREDICATE
}
final class AndroidModeOrchestrator {
 int starts;String mode="";File file;List<String> layers;
 interface Callback{void progress(String message);void finished(boolean ok,String mode,String message);default void owned(String id){}default void proved(String session,String raw,String source){}}
 void startup(File file,String mode,String raw,String source,Callback cb){throw new AssertionError("external permission cannot dispatch Router startup");}
 String captureSource(File f,String session,String raw)throws Exception{return Files.readString(f.toPath());}void restoreCaptured(File f,String raw,String logical,String fallback,String source,Callback cb){}void disconnectCaptured(String session,Callback cb){cb.finished(true,"","stopped");}
 void disconnect(Callback cb){cb.finished(true,"","stopped");}void auto(File f,boolean smart,Callback cb){logical(f,smart?"smart-auto":"auto",cb);}void all(File f,Callback cb){logical(f,"all",cb);}void custom(File f,List<String> l,Callback cb){layers=new ArrayList<>(l);logical(f,"custom",cb);}void logical(File f,String m,Callback cb){starts++;file=f;mode=m;cb.finished(true,m,"proved selected path");}
}
final class AndroidMultihopRuntime {
 int starts;
 // MULTIHOP_CAPTURE_TYPES
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String id){}}
 String activeExecution(){return "local";}String activeSelectedExecution(){return "local";}void restoreCaptured(AndroidNodeStore.Node a,AndroidNodeStore.Node b,RestoreCapture capture,AndroidHomeStateStore.Snapshot idle,Callback cb){}
 RestoreCapture captureRestore(AndroidNodeStore.Node a,AndroidNodeStore.Node b,AndroidHomeStateStore.Snapshot home)throws Exception{throw new IllegalStateException("multihop not owned by this external fixture");}boolean captureCurrent(RestoreCapture capture){return false;}boolean restoredMatches(RestoreCapture capture,AndroidNodeStore.Node a,AndroidNodeStore.Node b,AndroidHomeStateStore.Snapshot home){return false;}boolean disconnectAndDrainCaptured(String session){return true;}
 boolean isConnected(){return false;}boolean isActiveOrTransitioning(){return false;}String activeEntryId(){return "";}String activeExitId(){return "";}String activeEntryMode(){return "";}String activeExitMode(){return "";}
 void disconnect(){}void connect(AndroidNodeStore.Node a,AndroidNodeStore.Node b,String mode,String execution,String entry,Callback cb){starts++;cb.finished(true,"proved captured multihop");}List<NativeSingBoxController.ModeInfo> listSupportedExitModes(File f){return Collections.emptyList();}
}
final class AndroidStandardExitRuntime {
 interface Callback{void progress(String s);void finished(boolean ok,String s);default void owned(String id){}}
 int starts;String mode,execution="local",selected="local";File entry;AndroidStandardExitStore.Entry exit,ordinaryEntry;
 AndroidStandardExitStore.Entry capturedOrdinaryEntry(AndroidHomeStateStore.Snapshot s){return ordinaryEntry==null?null:AndroidStandardExitStore.copy(ordinaryEntry);}
 void connectOrdinary(AndroidStandardExitStore.Entry a,AndroidStandardExitStore.Entry e,String execution,Callback cb){starts++;ordinaryEntry=AndroidStandardExitStore.copy(a);entry=null;exit=e;mode=AndroidExternalPolicy.protocol(a.protocol);this.execution=execution;selected=execution;cb.finished(true,"owned ordinary entry");}
 String capturedRequestedExecution(AndroidHomeStateStore.Snapshot s){return execution;}String capturedExternalExecution(AndroidHomeStateStore.Snapshot s){return selected;}
 void restoreCaptured(File f,AndroidStandardExitStore.Entry e,String mode,String execution,String winner,Callback cb){connect(f,e,mode,execution,cb);selected=winner;}
 void connect(File f,AndroidStandardExitStore.Entry e,String m,String execution,Callback cb){this.execution=execution;selected=execution.equals("auto")?"server":execution;connect(f,e,m,cb);}
 String capturedTorExit(AndroidHomeStateStore.Snapshot s){return "8.8.4.4";}String capturedExternalExit(AndroidHomeStateStore.Snapshot s){return "8.8.4.4";}boolean disconnectAndDrainCaptured(String id){return true;}
 boolean isActiveOrTransitioning(){return false;}void disconnect(){}boolean disconnectCaptured(String id){return true;}
 void connectDirect(AndroidStandardExitStore.Entry e,Callback cb){starts++;mode="external";exit=e;cb.finished(true,"owned direct");}
 void connect(File f,AndroidStandardExitStore.Entry e,Callback cb){connect(f,e,"wg",cb);}
 void connect(File f,AndroidStandardExitStore.Entry e,String m,Callback cb){starts++;entry=f;mode=m;exit=e;cb.finished(true,"owned entry");}
}
final class AndroidRuntimeRegistry {
 static AndroidRuntimeRegistry instance=new AndroidRuntimeRegistry();static AndroidRuntimeRegistry get(Context c){return instance;}
 final NativeWireGuardController wireGuard=new NativeWireGuardController();final NativeAmneziaWGController amneziaWG=new NativeAmneziaWGController();final NativeSingBoxController singBox=new NativeSingBoxController();final NativeXrayController xray=new NativeXrayController();final AndroidModeOrchestrator orchestrator=new AndroidModeOrchestrator();final AndroidMultihopRuntime multihop=new AndroidMultihopRuntime();final AndroidStandardExitRuntime standardExit=new AndroidStandardExitRuntime();
}
// Startup has its own shipping-policy/permission fixture. This suite never
// creates a startup capture or records a single-Router proof.
final class AndroidStartupPolicy {
 static final class Attempt {String nonce="",mode="",source="",lastRaw="",entryMode="wg",exitMode="",execution="local";AndroidNodeStore.Node node,entry,exit;AndroidStandardExitStore.Entry external,ordinaryEntry;boolean external(){return external!=null;}boolean multihop(){return entry!=null;}void requireCurrent(Context c,AndroidNodeStore n,AndroidUnifiedConnectionController o){throw new AssertionError("unexpected startup capture");}void dispatched(){}void cancel(){}}
 static Attempt restore(String nonce){return null;}static void cancelPending(){}static boolean recordProven(Context c,AndroidNodeStore n,File f,String session,String raw,String source){return false;}
}
'''
BOUNDARIES = BOUNDARIES.replace('// MULTIHOP_CAPTURE_TYPES', MULTIHOP_CAPTURE_TYPES)

PREFS = r'''package android.content;public interface SharedPreferences {
 String getString(String key,String fallback);boolean getBoolean(String key,boolean fallback);java.util.Map<String,?> getAll();
}'''
PREFERENCE_ACCESS = r'''public static final java.util.Map<String,Object> connectionPreferences=new java.util.LinkedHashMap<>();
 public SharedPreferences getSharedPreferences(String name,int mode){return new SharedPreferences(){
  public String getString(String key,String fallback){return (String)connectionPreferences.getOrDefault(key,fallback);}
  public boolean getBoolean(String key,boolean fallback){return (Boolean)connectionPreferences.getOrDefault(key,fallback);}
  public java.util.Map<String,?> getAll(){return new java.util.LinkedHashMap<>(connectionPreferences);}
 };}'''

PRODUCT = r'''package com.eabusham.routervpn;
import android.app.*;import android.content.*;import android.widget.*;import java.util.*;
final class AndroidViaEntryLatencyProbe {boolean isBusy(){return false;}static boolean hasActiveOperation(){return false;}static boolean cancelActiveOperation(){return false;}}
final class AndroidUnifiedNodeCatalog {static final class Item{String id="";boolean isRouterVpn(){return false;}}}
final class AndroidHomeSummary {static String format(Context c,AndroidNodeStore n){return "idle";}}
final class PermissionActivity extends Activity {
 AndroidUnifiedConnectionController connection;AndroidNodeStore nodeStore;AndroidStandardExitStore exitStore;AndroidViaEntryLatencyProbe viaEntryProbe=new AndroidViaEntryLatencyProbe();
 Button connectButton=new Button(this),nodeButton=new Button(this),fastestButton=new Button(this);CheckBox killSwitch=new CheckBox(this),multihopToggle=new CheckBox(this);
 Spinner modeSpinner=new Spinner(this),dnsSpinner=new Spinner(this);TextView statusView=new TextView(this),liveLatency=new TextView(this);double currentPathMs;int changes;
 boolean resumed;String pendingProbeEntryId="";final Runnable telemetryTick=()->{};final Handler telemetryHandler=new Handler();static final class Handler{void removeCallbacks(Runnable r){}void post(Runnable r){}}void refreshAll(){refreshConnectionState();}
 static final String MULTI_ENTRY="multihop_entry",MULTI_EXIT="multihop_exit",MULTI_MODE="multihop_exit_mode";
 static final class ModeChoice {String id="";String title="";List<String> layers=List.of();}
 boolean isExternalSelected(){return false;}String multihopExecutionSummary(){return "";}void refreshConnectionLater(){refreshConnectionState();}
 AndroidUnifiedNodeCatalog.Item selectedCatalogItem(){throw new AssertionError("pending cancel reached a new connection decision");}void showNodes(){}AndroidNodeStore.Node nodeById(String id){return null;}void configureMultihop(){}
 SharedPreferences prefs(){return getSharedPreferences("router-vpn-unified",0);}ModeChoice currentMode(){return null;}void refreshModeChoices(){}void toast(String s){throw new AssertionError(s);}static String safe(Exception e){return e.getMessage();}
 AndroidUnifiedConnectionController.Callback callback(){return new ExternalPermissionTest.Callback();}
 void editChoice(){if(!mutationBusy())changes++;}void press(){connectOrDisconnect();}void display(){refreshConnectionState();}void resume(){onResume();}
 // SHIPPING_PRODUCT_METHODS
}
'''


HARNESS = r'''package com.eabusham.routervpn;
import android.app.*;import android.os.*;import java.nio.file.*;import java.nio.charset.*;import java.util.*;import org.json.*;
public class ExternalPermissionTest {
 // ALL_CAPTURED_MODES
 static int checks;static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
 static final class Callback implements AndroidUnifiedConnectionController.Callback {int completions;boolean ok;String message="";public void progress(String s){message=s;}public void finished(boolean b,String s){completions++;ok=b;message=s;}}
 static void resetOwner()throws Exception{var owner=AndroidUnifiedConnectionController.class.getDeclaredField("permissionOwner");owner.setAccessible(true);owner.set(null,null);}
 static final class Fixture {
  final Activity activity=new Activity();final AndroidNodeStore nodes=new AndroidNodeStore(activity);final AndroidStandardExitStore.Entry exit=new AndroidStandardExitStore.Entry();final AndroidNodeStore.Node entry;
  AndroidUnifiedConnectionController controller;final Callback callback=new Callback();final Path file;
  Fixture(Path root)throws Exception{resetOwner();android.content.Context.connectionPreferences.clear();AndroidNodeStore.active=null;AndroidNodeStore.nodes.clear();AndroidStandardExitStore.saved.clear();AndroidRuntimeRegistry.instance=new AndroidRuntimeRegistry();AndroidVpnMutationGuard.busy=false;AndroidHomeStateStore.current=new AndroidHomeStateStore.Snapshot();android.net.VpnService.needsPermission=true;
   file=Files.createTempFile(root,"entry-",".json");JSONObject profiles=new JSONObject();JSONArray modes=new JSONArray();for(String mode:ALL){profiles.put(mode,new JSONObject());modes.put(new JSONObject().put("id",mode).put("name","Captured "+mode));}
   modes.put(new JSONObject().put("id","wg").put("name","duplicate"));modes.put(new JSONObject().put("id","unowned"));Files.writeString(file,new JSONObject().put("profiles",profiles).put("modes",modes).toString());entry=new AndroidNodeStore.Node("entry-owned",file.toFile());AndroidNodeStore.nodes.add(entry);controller=new AndroidUnifiedConnectionController(activity,nodes);save();}
  void save(){AndroidStandardExitStore.saved.put(exit.id,AndroidStandardExitStore.copy(exit));}
  AndroidStandardExitRuntime runtime(){return AndroidRuntimeRegistry.instance.standardExit;}
  Bundle request(String mode,boolean direct){controller.connectExternal(entry,exit,direct,mode,callback);Bundle state=new Bundle();controller.savePending(state);return state;}
  void restore(Bundle state){controller.close();controller=new AndroidUnifiedConnectionController(activity,nodes);controller.restorePending(state,callback);}
  void allow(){check(controller.onActivityResult(activity.permissionRequest,Activity.RESULT_OK),"permission result ignored");}
 }
 static void allModes(Path root)throws Exception{
  for(String protocol:new String[]{"wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn","tor","tor-bridge"})for(String mode:ALL)for(boolean restore:new boolean[]{false,true}){
   Fixture f=new Fixture(root);f.exit.protocol=protocol;f.save();Bundle state=f.request(mode,false);
   check(f.activity.permissionRequest>=AndroidUnifiedConnectionController.PREPARE_UNIFIED&&f.runtime().starts==0,"external test ran before Android permission");
   check(!state.values.toString().contains(f.exit.secret)&&!state.values.toString().contains(f.exit.policy),"private profile was copied into Android saved state");
   if(restore)f.restore(state);f.allow();check(f.callback.ok&&f.callback.completions==1&&f.runtime().starts==1,"captured permission request was not completed");
   check(mode.equals(f.runtime().mode)&&f.runtime().entry.equals(f.entry.file)&&protocol.equals(f.runtime().exit.protocol),"temporary external/Tor path discarded its selected native entry");
  }
 }
 static void directAndFrozen(Path root)throws Exception{
  for(boolean restore:new boolean[]{false,true}){Fixture f=new Fixture(root);Bundle state=f.request("reality-xhttp",true);if(restore)f.restore(state);f.allow();check(f.callback.ok&&f.runtime().mode.equals("external")&&f.runtime().entry==null,"direct external capture acquired an entry");}
  Fixture f=new Fixture(root);f.request("max-quic-awg",false);String secret=f.exit.secret;f.exit.secret="new-caller-value";f.exit.protocol="http";f.allow();check(f.callback.ok&&f.runtime().exit.secret.equals(secret)&&f.runtime().exit.protocol.equals("openvpn"),"permission reused mutable caller credentials");
  Fixture modes=new Fixture(root);List<NativeSingBoxController.ModeInfo> values=modes.controller.supportedNativeEntryModes(modes.entry);check(values.size()==19,"native entry picker omitted or duplicated modes");for(int i=0;i<ALL.length;i++)check(values.get(i).id.equals(ALL[i])&&values.get(i).name.endsWith("["+ALL[i]+"]"),"native entry identity and displayed label diverged");
 }
 static void execution(Path root)throws Exception{
  for(String protocol:List.of("shadowsocks","openvpn"))for(String choice:List.of("local","server","auto"))for(boolean restore:new boolean[]{false,true}){
   Fixture f=new Fixture(root);f.exit.protocol=protocol;f.exit.responseMap=protocol.equals("openvpn")?"captured-private-two-host-map":"";f.save();f.controller.connectExternal(f.entry,f.exit,false,"max-quic-awg",choice,f.callback);Bundle state=new Bundle();f.controller.savePending(state);
   check(f.runtime().starts==0,"execution launched before permission");if(restore)f.restore(state);f.allow();check(f.callback.ok&&f.runtime().execution.equals(choice)&&f.runtime().exit.responseMap.equals(f.exit.responseMap),"permission lost external execution choice or captured remote map");
  }
  Fixture tampered=new Fixture(root);tampered.exit.protocol="shadowsocks";tampered.save();tampered.controller.connectExternal(tampered.entry,tampered.exit,false,"wg","auto",tampered.callback);Bundle state=new Bundle();tampered.controller.savePending(state);state.putString("multihop_execution_pending","server");tampered.restore(state);tampered.allow();check(!tampered.callback.ok&&tampered.runtime().starts==0,"restored permission substituted Server for Compare");
  Fixture direct=new Fixture(root);direct.exit.protocol="shadowsocks";direct.save();direct.controller.connectExternal(null,direct.exit,true,"wg","server",direct.callback);check(!direct.callback.ok&&direct.runtime().starts==0,"direct path acquired a server execution owner");
 }
 static void changes(Path root)throws Exception{
  for(String change:new String[]{"entry-file","exit-policy","exit-key","exit-removed","entry-removed","mode","direct","digest","legacy","permission-denied","busy","closed"})for(boolean restore:new boolean[]{false,true}){
   Fixture f=new Fixture(root);Bundle state=f.request("max-quic-awg",false);
   if(change.equals("entry-file"))Files.writeString(f.file,"{}");if(change.equals("entry-removed"))Files.delete(f.file);
   if(change.equals("exit-policy")){f.exit.policy="changed-dns";f.save();}if(change.equals("exit-key")){f.exit.secret="changed-key";f.save();}if(change.equals("exit-removed"))AndroidStandardExitStore.saved.clear();
   if(change.equals("mode"))state.putString("multihop_entry_mode_pending","wg");if(change.equals("direct"))state.putBoolean("routervpn.pending.external_direct",true);if(change.equals("digest"))state.putString("external_profile_digest_pending","0".repeat(64));if(change.equals("legacy"))state.values.remove("external_request_digest_pending");
   boolean stateOnly=Set.of("mode","direct","digest","legacy").contains(change);if(restore||stateOnly)f.restore(state);
   if(change.equals("permission-denied")){f.controller.onActivityResult(f.activity.permissionRequest,0);}else{if(change.equals("busy"))AndroidVpnMutationGuard.busy=true;if(change.equals("closed"))f.controller.close();f.allow();}
   check(f.runtime().starts==0&&!f.callback.ok,"changed external permission selection started a different graph: "+change+"/"+restore);
  }
  Fixture pending=new Fixture(root);pending.request("wg",false);Callback rejected=new Callback();pending.controller.connectExternal(pending.entry,pending.exit,false,"max",rejected);check(rejected.completions==1&&!rejected.ok,"new request overwrote pending external permission");pending.allow();check(pending.callback.ok&&pending.runtime().mode.equals("wg"),"second request replaced the original permission owner");
 }
 static AndroidStandardExitStore.Entry ordinary(Fixture f,String protocol){AndroidStandardExitStore.Entry entry=new AndroidStandardExitStore.Entry();entry.id=f.entry.id;entry.protocol=protocol;entry.secret="independent-provider-credential";entry.policy="selected-provider-policy";AndroidStandardExitStore.saved.put(entry.id,AndroidStandardExitStore.copy(entry));f.exit.protocol="tor-bridge";f.save();return entry;}
 static void ordinaryPaths(Path root)throws Exception{
  for(String protocol:List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn"))for(boolean restored:new boolean[]{false,true}){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry entry=ordinary(f,protocol);String source=AndroidStandardExitStore.snapshot(entry);
   f.controller.connectExternal(new AndroidConnectionProfileStore.ExternalSelection(null,entry,f.exit,AndroidExternalPolicy.protocol(protocol),"local"),f.callback);
   Bundle state=new Bundle();f.controller.savePending(state);check(f.runtime().starts==0&&f.activity.permissionRequest>=AndroidUnifiedConnectionController.PREPARE_UNIFIED,"ordinary Tor bypassed VPN permission");
   check(state.getString("routervpn.pending.ordinary_entry","").equals(entry.id)&&!state.containsKey("routervpn.pending.entry"),"ordinary path borrowed colliding Router identity");
   check(!state.values.toString().contains(entry.secret)&&!state.values.toString().contains(entry.policy),"ordinary credentials leaked into saved Activity state");
   if(restored)f.restore(state);entry.secret="changed caller object";f.allow();
   check(f.callback.ok&&f.runtime().starts==1&&f.runtime().entry==null&&f.runtime().ordinaryEntry!=null&&source.equals(AndroidStandardExitStore.snapshot(f.runtime().ordinaryEntry)),"ordinary permission lost exact frozen provider source");
   check(f.runtime().mode.equals(AndroidExternalPolicy.protocol(protocol))&&f.runtime().execution.equals("local"),"ordinary permission changed exact transport or Local execution");
  }
  for(String fault:List.of("entry-source","exit-source","remove-entry","remove-exit","kind","direct","mode","execution","digest","legacy","denied","busy","closed")){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry entry=ordinary(f,"socks5");f.controller.connectOrdinaryTor(entry,f.exit,"local",f.callback);Bundle state=new Bundle();f.controller.savePending(state);
   if(fault.equals("entry-source")){entry.secret+=" changed";AndroidStandardExitStore.saved.put(entry.id,entry);}if(fault.equals("exit-source")){f.exit.secret+=" changed";f.save();}
   if(fault.equals("remove-entry"))AndroidStandardExitStore.saved.remove(entry.id);if(fault.equals("remove-exit"))AndroidStandardExitStore.saved.remove(f.exit.id);
   if(fault.equals("kind")){state.values.remove("routervpn.pending.ordinary_entry");state.putString("routervpn.pending.entry",entry.id);}if(fault.equals("direct"))state.putBoolean("routervpn.pending.external_direct",true);
   if(fault.equals("mode"))state.putString("multihop_entry_mode_pending","wg");if(fault.equals("execution"))state.putString("multihop_execution_pending","server");if(fault.equals("digest"))state.putString("external_entry_digest_pending","0".repeat(64));if(fault.equals("legacy"))state.values.remove("external_request_digest_pending");
   f.restore(state);if(fault.equals("denied"))f.controller.onActivityResult(f.activity.permissionRequest,0);else{if(fault.equals("busy"))AndroidVpnMutationGuard.busy=true;if(fault.equals("closed"))f.controller.close();f.allow();}
   check(f.runtime().starts==0&&!f.callback.ok,"ordinary permission adopted changed source, kind or owner: "+fault);
  }
  for(String execution:List.of("server","auto")){Fixture f=new Fixture(root);AndroidStandardExitStore.Entry entry=ordinary(f,"socks5");f.controller.connectOrdinaryTor(entry,f.exit,execution,f.callback);check(f.runtime().starts==0&&!f.callback.ok&&f.callback.completions==1,"ordinary provider acquired private server authority");}
 }
 static void savedChoice(Fixture f){Map<String,Object> prefs=android.content.Context.connectionPreferences;prefs.put("selected_kind","router-vpn");prefs.put("selected_id",f.entry.id);prefs.put("mode","custom:Saved");prefs.put("custom_presets","USER_SAVED_CUSTOM_LAYERS_ONLY");prefs.put("multihop_on",false);prefs.put("multihop_entry",f.entry.id);prefs.put("multihop_exit","another-saved-node");prefs.put("multihop_exit_mode","shadowsocks");prefs.put("multihop_entry_mode","wg");prefs.put("multihop_entry_kind","router-vpn");prefs.put("multihop_execution","local");}
 static Bundle request(Fixture f,String shape)throws Exception{
  if(shape.equals("router"))f.controller.connect("custom:Temporary",List.of("wg","shadowsocks"),f.callback);
  else if(shape.equals("test-node"))f.controller.connectNode(f.entry,"max-tls-wg",List.of(),f.callback);
  else if(shape.equals("multihop")){AndroidNodeStore.Node second=new AndroidNodeStore.Node("second",f.entry.file);AndroidNodeStore.nodes.add(second);f.controller.connectMultihop(f.entry,second,"shadowsocks","server","wg-pq",f.callback);}
  else if(shape.equals("ordinary"))f.controller.connectOrdinaryTor(ordinary(f,"socks5"),f.exit,"local",f.callback);
  else f.controller.connectExternal(f.entry,f.exit,shape.equals("direct"),"reality-xhttp",f.callback);
  Bundle state=new Bundle();f.controller.savePending(state);return state;
 }
 static int starts(Fixture f){return f.runtime().starts+AndroidRuntimeRegistry.instance.orchestrator.starts+AndroidRuntimeRegistry.instance.multihop.starts;}
 static void selectedChanges(Path root)throws Exception{
  String[] keys={"selected_kind","selected_id","mode","custom_presets","multihop_on","multihop_entry","multihop_exit","multihop_exit_mode","multihop_entry_mode","multihop_entry_kind","multihop_execution","active_node"};
  for(String shape:List.of("router","test-node","multihop","direct","external","ordinary"))for(String key:keys)for(boolean rotated:new boolean[]{false,true})for(boolean resumed:new boolean[]{false,true}){
   Fixture f=new Fixture(root);savedChoice(f);Bundle state=request(f,shape);check(f.controller.isActiveOrTransitioning()&&f.controller.isPermissionPending()&&starts(f)==0,"pending permission did not block mutations");
   check(state.getString("routervpn.pending.selection_digest","").matches("[0-9a-f]{64}")&&!state.values.toString().contains("USER_SAVED_CUSTOM_LAYERS_ONLY"),"saved choice contents leaked into Activity state");
   if(key.equals("active_node"))AndroidNodeStore.active="replacement-active";else if(key.equals("multihop_on"))android.content.Context.connectionPreferences.put(key,true);else android.content.Context.connectionPreferences.put(key,"changed choice");
   if(rotated)f.restore(state);if(resumed)f.controller.resumePending();f.allow();
   check(starts(f)==0&&!f.callback.ok&&f.callback.completions==1&&!f.controller.isPermissionPending(),"changed saved choice started: "+shape+" / "+key+" / "+rotated+" / "+resumed);
  }
  for(String shape:List.of("router","test-node","multihop","direct","external","ordinary"))for(boolean rotated:new boolean[]{false,true}){
   Fixture f=new Fixture(root);savedChoice(f);Bundle state=request(f,shape);android.content.Context.connectionPreferences.put("map_theme","dark");android.content.Context.connectionPreferences.put("last_panel_height",315L);
   if(rotated)f.restore(state);f.controller.resumePending();check(f.controller.isPermissionPending(),"display preference rejected captured permission: "+shape+" / "+rotated+" / "+f.callback.message);f.allow();
   check(f.callback.ok&&starts(f)==1,"temporary requested graph was forced to equal saved selection: "+shape);
  }
  Fixture malformed=new Fixture(root);savedChoice(malformed);android.content.Context.connectionPreferences.put("mode",true);malformed.controller.connectExternal(malformed.entry,malformed.exit,false,"wg",malformed.callback);check(!malformed.callback.ok&&malformed.callback.completions==1&&malformed.activity.permission==null&&!malformed.controller.isPermissionPending(),"malformed saved choice reached Android permission");
 }
 static void owners(Path root)throws Exception{
  Fixture f=new Fixture(root);Bundle old=f.request("wg",false);int oldCode=f.activity.permissionRequest;Callback wrong=new Callback();
  check(!f.controller.cancelPending(wrong)&&f.controller.isPermissionPending()&&f.callback.completions==0,"foreign callback cancelled a pending owner");
  f.controller.restorePending(old,wrong);check(wrong.completions==1&&!wrong.ok&&f.controller.isPermissionPending(),"duplicate restore cleared its current pending owner");
  check(f.controller.cancelPending(f.callback)&&!f.controller.cancelPending(f.callback)&&f.callback.completions==1,"captured cancellation was not terminal");
  Callback replacement=new Callback();f.controller.connectExternal(f.entry,f.exit,false,"max",replacement);int nextCode=f.activity.permissionRequest;
  check(nextCode!=oldCode&&f.controller.isPermissionPending(),"replacement reused an old Android permission request code");
  check(!f.controller.cancelPending(f.callback),"cancelled callback acquired its replacement");
  Callback stale=new Callback();f.controller.restorePending(old,stale);check(stale.completions==1&&!stale.ok&&f.controller.isPermissionPending(),"stale Bundle replaced a newer pending owner");
  f.controller.onActivityResult(oldCode,Activity.RESULT_OK);f.controller.onActivityResult(oldCode,0);check(f.runtime().starts==0&&replacement.completions==0&&f.controller.isPermissionPending(),"late permission result acted on replacement owner");
  f.controller.onActivityResult(nextCode,Activity.RESULT_OK);f.controller.onActivityResult(nextCode,Activity.RESULT_OK);check(replacement.ok&&replacement.completions==1&&f.runtime().starts==1&&!f.controller.isActiveOrTransitioning(),"replacement permission was not consumed exactly once");
  AndroidUnifiedConnectionController dead=new AndroidUnifiedConnectionController(f.activity,f.nodes);Callback replay=new Callback();dead.restorePending(old,replay);dead.onActivityResult(oldCode,Activity.RESULT_OK);check(!replay.ok&&f.runtime().starts==1&&!dead.isPermissionPending(),"cancelled Bundle revived a consumed request");
  for(String lifecycle:List.of("consumed","cancelled","finishing","process-death")){
   Fixture x=new Fixture(root);Bundle state=x.request("wg",false);if(lifecycle.equals("consumed"))x.allow();if(lifecycle.equals("cancelled"))x.controller.cancelPermissionPending();if(lifecycle.equals("finishing"))x.activity.finished=true;if(lifecycle.equals("process-death"))resetOwner();int before=x.runtime().starts;x.restore(state);x.allow();check(x.runtime().starts==before&&!x.controller.isPermissionPending(),"retired owner revived after "+lifecycle);
  }
  Fixture transferred=new Fixture(root);Bundle state=transferred.request("wg",false);AndroidUnifiedConnectionController original=transferred.controller;transferred.restore(state);Callback duplicate=new Callback();AndroidUnifiedConnectionController other=new AndroidUnifiedConnectionController(transferred.activity,transferred.nodes);other.restorePending(state,duplicate);check(!duplicate.ok&&transferred.controller.isPermissionPending(),"another screen stole the transferred owner");original.onActivityResult(transferred.activity.permissionRequest,Activity.RESULT_OK);check(transferred.runtime().starts==0,"old Activity dispatched a transferred permission owner");Bundle again=new Bundle();transferred.controller.savePending(again);transferred.restore(again);transferred.allow();check(transferred.runtime().starts==1&&transferred.callback.ok,"second recreation lost the exact pending request");
  Fixture tampered=new Fixture(root);savedChoice(tampered);Bundle changed=request(tampered,"router");changed.putString("routervpn.pending.mode","all");tampered.restore(changed);tampered.allow();check(starts(tampered)==0&&!tampered.callback.ok,"Bundle substituted a new Router request under the same saved selection");
  Fixture immediate=new Fixture(root);savedChoice(immediate);android.net.VpnService.needsPermission=false;request(immediate,"ordinary");check(immediate.callback.ok&&immediate.runtime().starts==1&&!immediate.controller.isPermissionPending()&&immediate.activity.permission==null,"existing Android permission bypassed captured dispatch or self-blocked");
 }
 static void activity(Path root)throws Exception{
  Fixture f=new Fixture(root);savedChoice(f);f.request("wg",false);PermissionActivity ui=new PermissionActivity();ui.connection=f.controller;ui.nodeStore=f.nodes;ui.exitStore=new AndroidStandardExitStore(ui);ui.display();ui.editChoice();
  check(ui.changes==0&&!ui.nodeButton.isEnabled()&&!ui.fastestButton.isEnabled()&&!ui.killSwitch.isEnabled()&&!ui.multihopToggle.isEnabled()&&!ui.modeSpinner.isEnabled()&&!ui.dnsSpinner.isEnabled(),"shipping Product controls remained mutable during Android permission");
  check(ui.connectButton.getText().toString().equals("Cancel connection")&&ui.statusView.getText().toString().contains("Waiting for Android permission"),"shipping Product hid pending permission or cancellation");
  long generation=AndroidHomeStateStore.current.pathGeneration;ui.press();check(!f.controller.isPermissionPending()&&f.callback.completions==1&&!f.callback.ok&&AndroidHomeStateStore.current.pathGeneration==generation,"shipping pending Cancel disconnected a runtime instead of cancelling its owner");f.allow();check(f.runtime().starts==0,"UI-cancelled request started later");
  Fixture resume=new Fixture(root);savedChoice(resume);resume.request("wg",false);ui=new PermissionActivity();ui.connection=resume.controller;ui.nodeStore=resume.nodes;ui.exitStore=new AndroidStandardExitStore(ui);android.content.Context.connectionPreferences.put("mode","another-choice");ui.resume();check(resume.callback.completions==1&&!resume.callback.ok&&resume.runtime().starts==0&&!resume.controller.isPermissionPending(),"shipping Activity resume retained changed connection selection");resume.allow();check(resume.runtime().starts==0,"resumed stale request started after permission");
 }
 static void exhaustion(Path root)throws Exception{
  var counter=AndroidUnifiedConnectionController.class.getDeclaredField("nextPermissionCode");counter.setAccessible(true);int original=counter.getInt(null);
  try{counter.setInt(null,0xffff);Fixture last=new Fixture(root);last.request("wg",false);check(last.activity.permissionRequest==0xffff,"last safe request code was unavailable");last.controller.cancelPermissionPending();Fixture over=new Fixture(root);over.request("wg",false);check(over.callback.completions==1&&!over.callback.ok&&over.activity.permission==null&&!over.controller.isPermissionPending(),"permission request code exhaustion reused a stale identity");}
  finally{counter.setInt(null,original);}
 }
 public static void main(String[]args)throws Exception{Path root=Path.of(args[0]);allModes(root);directAndFrozen(root);execution(root);changes(root);ordinaryPaths(root);selectedChanges(root);owners(root);activity(root);exhaustion(root);System.out.println("Android external permission: "+checks+" checks;19 Router entries,8 ordinary entries,saved selection/rotation/resume,owned cancellation/replacement,actual Product busy/cancel");}
}
'''


def main():
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file() or not shutil.which("javac"):
        raise RuntimeError("JDK and Android JSON are required for unified permission tests")
    ui = dict(T.UI)
    ui["android/content/SharedPreferences.java"] = PREFS
    ui["android/content/Context.java"] = ui["android/content/Context.java"].replace('public SharedPreferences getSharedPreferences(String name,int mode){return (key,fallback)->fallback;}', PREFERENCE_ACCESS)
    ui["android/os/Bundle.java"] = ui["android/os/Bundle.java"][:-1] + "public void putStringArrayList(String k,java.util.ArrayList<String> v){values.put(k,v);}public java.util.ArrayList<String> getStringArrayList(String k){return (java.util.ArrayList<String>)values.get(k);}public boolean containsKey(String k){return values.containsKey(k);}}"
    native = (JAVA / "NativeSingBoxController.java").read_text()
    methods = []
    for name in ("nativeMultihopEntry", "nativeWireGuardFamily", "nativeNaiveFamily", "nativePQFamily"):
        matches = re.findall(r"(?ms)^    static boolean " + name + r"\(String mode\) \{\n.*?^    \}", native)
        assert len(matches) == 1, "exact shipping native mode predicate is required"
        methods.append(matches[0])
    composite = re.findall(r"(?ms)^    static boolean isMode\(String mode\) \{\n.*?^    \}", (JAVA / "AndroidNativeCompositeProfile.java").read_text())
    assert len(composite) == 1
    boundaries = BOUNDARIES.replace(" // PRODUCTION_TRANSPORT_PREDICATES", "\n".join(methods)).replace(" // PRODUCTION_COMPOSITE_PREDICATE", composite[0])
    modes = next(line for line in T.T.HARNESS.splitlines() if "static final String[] ALL=" in line)
    product = (JAVA / 'ProductActivity.java').read_text()
    methods = []
    for signature in ('    private boolean mutationBusy(', '    private void connectOrDisconnect(', '    private void refreshConnectionState(', '    @Override protected void onResume('):
        start = product.index(signature)
        end = product.index('\n', start)
        methods.append(product[start:end])
    with tempfile.TemporaryDirectory(prefix="routervpn-external-permission-") as directory:
        temp = Path(directory)
        for name, source in ui.items():
            path = temp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        app = temp / "com/eabusham/routervpn"
        app.mkdir(parents=True)
        (app / "Boundaries.java").write_text(boundaries)
        (app / "ExternalPermissionTest.java").write_text(HARNESS.replace(" // ALL_CAPTURED_MODES", modes))
        (app / 'PermissionActivity.java').write_text(PRODUCT.replace(' // SHIPPING_PRODUCT_METHODS', '\n'.join(methods)))
        shutil.copyfile(JAVA / 'AndroidConnectionSelection.java', app / 'AndroidConnectionSelection.java')
        target = app / "AndroidUnifiedConnectionController.java"
        source = (JAVA / target.name).read_text()
        target.write_text(source)
        compile_args = ["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(temp / "classes"), *map(str, temp.rglob("*.java"))]
        subprocess.run(compile_args, check=True, timeout=45)
        data = temp / "data"
        data.mkdir()
        run = ["java", "-cp", os.pathsep.join((str(temp / "classes"), str(jar))), "com.eabusham.routervpn.ExternalPermissionTest", str(data)]
        subprocess.run(run, check=True, timeout=30)
        controls = (
            ('AndroidConnectionSelection.java', '||!expected.equals(digest(context,nodes))', '', 'changed saved choice started'),
            ('AndroidConnectionSelection.java', 'append(source,"active_node_id",active);', '', 'changed saved choice started'),
            ('AndroidUnifiedConnectionController.java', 'return pendingCallback!=null || disconnecting.get()', 'return disconnecting.get()', 'pending permission did not block mutations'),
            ('AndroidUnifiedConnectionController.java', 'if(owner==null||pendingCallback!=owner)return false;', 'if(owner==null)return false;', 'foreign callback cancelled a pending owner'),
            ('AndroidUnifiedConnectionController.java', 'if(pendingCallback!=null){callback.finished(false,"Another Android permission request already owns this screen.");return;}', '', 'duplicate restore cleared its current pending owner'),
            ('AndroidUnifiedConnectionController.java', 'prompt?nextPermissionCode++:0', 'prompt?PREPARE_UNIFIED:0', 'replacement reused an old Android permission request code'),
            ('PermissionActivity.java', 'if(connection!=null)connection.resumePending();', '', 'shipping Activity resume retained changed connection selection'),
        )
        for name, old, new, assertion in controls:
            target = app / name
            original = target.read_text()
            assert original.count(old) == 1, (name, old)
            target.write_text(original.replace(old, new))
            subprocess.run(compile_args, check=True, timeout=45, capture_output=True)
            broken = subprocess.run(run, timeout=30, capture_output=True, text=True)
            target.write_text(original)
            assert broken.returncode and assertion in broken.stderr, 'permission negative control escaped its intended assertion: ' + name + '\n' + broken.stdout + broken.stderr
        print(f'Android pending permission: {len(controls)} broken selection, owner and UI decisions rejected')


if __name__ == "__main__":
    main()
