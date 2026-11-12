#!/usr/bin/env python3
"""Execute the shipping profile, node and exit stores against real Android JSON.

Private publication, SharedPreferences and idle runtime handles are boundary
doubles. Faults include commit(false) after in-memory publication. Native graph
compilation is covered by the external/Tor/imported-Router suites; this suite neither connects
nor claims device or network proof.
"""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"

GO = r'''package main
import("encoding/json";"fmt";"io";"os";"router-vpn/internal/mobilemultihop";"router-vpn/mobile")
func main(){raw,err:=io.ReadAll(os.Stdin);var args []string;if err==nil{err=json.Unmarshal(raw,&args)};var result string;if err==nil{switch {case len(args)==2:result,err=mobilemultihop.CompileAmneziaProfile(args[0],args[1]);case len(args)==1:err=libbox.RouterValidatePrivateNodeJSON(args[0]);case len(args)==3&&args[0]=="chain-imported":result,err=mobilemultihop.NodeChainImportedMemberInput(args[1],args[2]);case len(args)==3&&args[0]=="original-wg":result,err=mobilemultihop.CompileWireGuardProfile(args[1],args[2]);case len(args)==6&&args[0]=="openvpn-endpoint":result,err=libbox.RouterOpenVPNEndpoint(args[1],args[2],args[3],args[4],args[5]);case len(args)==3&&args[0]=="openvpn-pairing":err=libbox.RouterValidateExternalOpenVPNPairing(args[1],args[2]);case len(args)==3&&args[0]=="openvpn-probes":err=libbox.RouterValidateExternalOpenVPNResponseProbes(args[1],args[2]);case len(args)==5&&args[0]=="openvpn-layers":err=libbox.RouterValidateExternalOpenVPNStartLayers(args[1],args[2],args[3],args[4]);default:panic("invalid fixture request")}};if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)};fmt.Print(result)}'''


def method(name, signature):
    source = (JAVA / name).read_text()
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


STUBS = {
    "android/content/SharedPreferences.java": r'''package android.content;
public interface SharedPreferences {
 java.util.Map<String,?> getAll();String getString(String key,String fallback);boolean getBoolean(String key,boolean fallback);Editor edit();
 interface Editor {Editor putString(String key,String value);Editor putBoolean(String key,boolean value);Editor putInt(String key,int value);Editor putLong(String key,long value);Editor putFloat(String key,float value);Editor remove(String key);boolean commit();void apply();}
}''',
    "android/content/Context.java": r'''package android.content;
public class Context {
 public static final int MODE_PRIVATE=0;private final java.io.File files;
 public final java.util.Map<String,MemoryPreferences> preferences=new java.util.LinkedHashMap<>();
 public Context(java.io.File files){this.files=files;}public Context getApplicationContext(){return this;}public java.io.File getFilesDir(){return files;}
 public MemoryPreferences getSharedPreferences(String name,int mode){return preferences.computeIfAbsent(name,n->new MemoryPreferences());}
}''',
    "android/content/MemoryPreferences.java": r'''package android.content;
public final class MemoryPreferences implements SharedPreferences {
 public final java.util.Map<String,Object> values=new java.util.LinkedHashMap<>();public int writes;public int failures;public Runnable beforeFailure;public Runnable beforeRead;public Runnable beforeCommit;
 public java.util.Map<String,?> getAll(){Runnable hook=beforeRead;beforeRead=null;if(hook!=null)hook.run();return new java.util.LinkedHashMap<>(values);}public String getString(String key,String fallback){return (String)values.getOrDefault(key,fallback);}
 public boolean getBoolean(String key,boolean fallback){return (Boolean)values.getOrDefault(key,fallback);}
 public Editor edit(){return new Editor(){final java.util.Map<String,Object> staged=new java.util.LinkedHashMap<>();
  public Editor putString(String key,String value){staged.put(key,value);return this;}public Editor putBoolean(String key,boolean value){staged.put(key,value);return this;}
  public Editor putInt(String key,int value){staged.put(key,value);return this;}public Editor putLong(String key,long value){staged.put(key,value);return this;}public Editor putFloat(String key,float value){staged.put(key,value);return this;}
  public Editor remove(String key){staged.put(key,null);return this;}public void apply(){commit();}
  public boolean commit(){Runnable first=beforeCommit;beforeCommit=null;if(first!=null)first.run();writes++;for(java.util.Map.Entry<String,Object> e:staged.entrySet()){if(e.getValue()==null)values.remove(e.getKey());else values.put(e.getKey(),e.getValue());}if(failures>0){failures--;Runnable hook=beforeFailure;beforeFailure=null;if(hook!=null)hook.run();return false;}return true;}
 };}
}''',
    "android/util/Base64.java": r'''package android.util;public final class Base64 {public static final int DEFAULT=0;
 public static byte[] decode(String value,int flags){return java.util.Base64.getMimeDecoder().decode(value);}
}''',
    "io/nekohasekai/libbox/Libbox.java": r'''package io.nekohasekai.libbox;import org.json.JSONArray;import java.nio.charset.StandardCharsets;
public final class Libbox {public static String routerCompileAmneziaProfile(String profile,String identity)throws Exception{return call(profile,identity);}
public static void routerValidatePrivateNodeJSON(String source)throws Exception{call(source);}
public static String version(){return "1.14.1";}
public static String routerNodeChainImportedMemberInput(String config,String capture)throws Exception{return call("chain-imported",config,capture);}
public static String routerCompileWireGuardProfile(String config,String node)throws Exception{return call("original-wg",config,node);}
public static String routerOpenVPNEndpoint(String config,String user,String password,String tag,String detour)throws Exception{return call("openvpn-endpoint",config,user,password,tag,detour);}
public static void routerValidateExternalOpenVPNPairing(String profile,String pairing)throws Exception{call("openvpn-pairing",profile,pairing);}
public static void routerValidateExternalOpenVPNResponseProbes(String profile,String probes)throws Exception{call("openvpn-probes",profile,probes);}
public static void routerValidateExternalOpenVPNStartLayers(String profile,String probes,String layers,String mode)throws Exception{call("openvpn-layers",profile,probes,layers,mode);}
private static String call(String...args)throws Exception{
 Process process=new ProcessBuilder(System.getenv("ROUTERVPN_PROFILE_COMPILER")).start();process.getOutputStream().write(new JSONArray(java.util.Arrays.asList(args)).toString().getBytes(StandardCharsets.UTF_8));process.getOutputStream().close();String out=new String(process.getInputStream().readAllBytes(),StandardCharsets.UTF_8),error=new String(process.getErrorStream().readAllBytes(),StandardCharsets.UTF_8);if(process.waitFor()!=0)throw new IllegalStateException(error);return out;
}}''',
}

BOUNDARIES = r'''package com.eabusham.routervpn;
import org.json.*;import java.util.*;import java.io.*;import java.nio.file.*;import android.content.Context;import java.nio.charset.StandardCharsets;import io.nekohasekai.libbox.Libbox;
final class AndroidPrivateFileStore {
 static String failPath="";static int failures;static int writes;static volatile Runnable beforeWrite;
 static void ensurePrivateDirectory(File file)throws Exception{Files.createDirectories(file.toPath());}
 static byte[] read(File file,int max)throws Exception{byte[] bytes=Files.readAllBytes(file.toPath());if(bytes.length==0||bytes.length>max)throw new IOException("bad size");return bytes;}
 static void write(File file,byte[] bytes,int max)throws Exception{if(bytes.length==0||bytes.length>max)throw new IOException("bad size");Runnable hook=beforeWrite;if(hook!=null)hook.run();Files.createDirectories(file.getParentFile().toPath());Files.write(file.toPath(),bytes);writes++;if(failures>0&&file.getAbsolutePath().equals(failPath)){failures--;throw new IOException("injected post-publication failure");}}
 static void remove(File file,int max)throws Exception{Files.deleteIfExists(file.toPath());}
}
final class AndroidStartupPolicy {static int cancellations;static void cancelPending(){cancellations++;}}
final class AndroidVpnMutationGuard {static boolean busy;static boolean isBusy(android.content.Context context){return busy;}}
// Controlled Home epoch only. This fixture does not supply native readiness.
final class AndroidHomeStateStore {static final class Snapshot{boolean connected;String phase="off";}static volatile Snapshot current=new Snapshot();static Snapshot snapshot(android.content.Context c){return current;}}
final class AndroidRuntimeRegistry {
 static final class Engine{boolean isRunning(){return false;}boolean isActiveOrTransitioning(){return false;}String getState(){return "DOWN";}}
 final Engine orchestrator=new Engine(),multihop=new Engine(),singBox=new Engine(),xray=new Engine();static AndroidRuntimeRegistry get(android.content.Context c){return new AndroidRuntimeRegistry();}
}

final class AndroidTorProfile {
 static String strictText(byte[] raw)throws Exception{return java.nio.charset.StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(raw)).toString();}
 static boolean isTor(String protocol){return "tor".equals(protocol)||"tor-bridge".equals(protocol);}
 static String digest(byte[] bytes)throws Exception{return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));}
 // Compiler boundary only. The actual Tor form/profile tests exercise shared Go validation.
 static void validate(AndroidStandardExitStore.Entry exit)throws Exception{AndroidConnectionProfilePolicy.external(exit.torPolicy,exit.protocol);if("tor-bridge".equals(exit.protocol)&&exit.torBridges.isEmpty())throw new IllegalArgumentException("missing bridge");}
 // Persistence boundary only: real ordinary graph compilation and immutable
 // native source matching execute in test_android_tor_profile.py/form.py.
 static Runnable afterOrdinaryValidation;
 static String compileOrdinary(AndroidStandardExitStore.Entry entry,AndroidStandardExitStore.Entry exit,String session,String execution)throws Exception{
  if(!AndroidExternalPolicy.supports(entry.protocol)||!isTor(exit.protocol)||entry.id.equals(exit.id)||!execution.equals("local")||!session.equals("selection-validation"))throw new IllegalArgumentException("unowned ordinary Tor capture");
  AndroidExternalPolicy.checkPolicy(entry.policy);validate(exit);Runnable hook=afterOrdinaryValidation;if(hook!=null)hook.run();return "{}";
 }
}
// Pure compiler boundary only: persistence must pass exact role, mode and
// referenced sources; native graph/traffic tests exercise the actual compiler.
final class AndroidImportedRouterPath {
 static Runnable afterValidation;
 IMPORTED_CAPTURE_METHODS
 static JSONObject finalBundle(File file)throws Exception{
  JSONObject bundle=new JSONObject(AndroidTorProfile.strictText(AndroidPrivateFileStore.read(file,AndroidNodeStore.MAX_BUNDLE)));
  AndroidNodeStore.validateBundle(bundle);return bundle;
 }
 static void compile(AndroidStandardExitStore.Entry entry,JSONObject bundle,String mode,String execution)throws Exception{
  AndroidStandardExitStore.validate(entry);AndroidNodeStore.validateBundle(bundle);
  JSONObject last=AndroidProfileSelection.selectedRouterProfile(bundle);
  String identity=AndroidNodeStore.stableNodeIdentity(bundle);
  if(!List.of("shadowsocks","hysteria2","wireguard","amneziawg","http","https").contains(entry.protocol)||entry.protocol.equals("shadowsocks")&&!List.of("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305").contains(entry.method)
   ||!supports(entry.protocol,mode)||!execution.equals("local")||!last.optString("node_kind").equals("router-vpn")
   ||entry.id.equals(last.getString("id"))||!identity.matches("[0-9a-f]{64}")||!identity.equals(last.optString("node_proof_id")))throw new IllegalArgumentException("invalid imported Router compiler input");
  if(List.of("http","https").contains(entry.protocol)&&(!mode.equals("shadowsocks")||!last.optString("start_layer","off").equals("off")||!entry.policy.optString("start_layer","off").equals("off")||!last.optString("dns_protocol").equals("tcp")))throw new IllegalArgumentException("CONNECT boundary requires captured TCP DNS and both layers Off");
  JSONObject assets=bundle.getJSONObject("profiles").getJSONObject(mode);
  if(List.of("wg","awg2-fast","awg2-strong").contains(mode)){
   String conf=new String(Base64.getDecoder().decode(assets.getString(mode.equals("wg")?"wg.conf":"awg.conf")),StandardCharsets.UTF_8);
   if(!conf.contains("Address =")||!conf.contains("Endpoint =")||!conf.contains("AllowedIPs ="))throw new IllegalArgumentException("incomplete packet final compiler boundary");
  }else if(assets.getString("sing-box.json").isEmpty())throw new IllegalArgumentException("incomplete final mode");
  if(!last.optString("start_layer","off").equals("off")&&bundle.getJSONObject("profiles").getJSONObject("shadowsocks").getString("sing-box.json").isEmpty())throw new IllegalArgumentException("missing original layer assets");
  Runnable hook=afterValidation;if(hook!=null)hook.run();
 }
}
final class AndroidMultihopController {
 static final int MAX_BUNDLE=AndroidNodeStore.MAX_BUNDLE;
 CAPTURE_SOURCE
}
final class AndroidExternalPolicy {
 EXTERNAL_POLICY_FIELDS
 static final int MAX_CAPTURE=8*1024*1024;static boolean bounded(String value,int max){return value!=null&&!value.isEmpty()&&value.length()<=max;}
 static final class Captured {final String source,capture;Captured(String source,String capture){this.source=source;this.capture=capture;}}
 EXTERNAL_METHODS
}
final class AndroidExternalEntry {JSONObject profile;String config;}
final class AndroidDirectStandardExitController { EXTERNAL_TRANSPORT }

'''

PRODUCT = r'''package com.eabusham.routervpn;
import android.content.*;import java.util.*;import org.json.*;import java.nio.charset.StandardCharsets;
// Native-owned ordered display capture is exercised by the ordered usage suite.
final class AndroidOrderedPathPresentation {static final class Member{String name,mode;double httpResponseMs;boolean imported;}boolean live;List<Member> members;}
// Only UI rendering and runtime dispatch are doubled. The shipping handler reads
// the same actual profile/node/exit stores used by the persistence regression.
final class ProductConnectSurface extends Context {
 static final String MULTI_ON="multihop_on",MULTI_ENTRY="multihop_entry",MULTI_EXIT="multihop_exit",MULTI_MODE="multihop_exit_mode";
 static final String SELECTED_ID="selected_id",SELECTED_KIND="selected_kind";
 final Context storeContext;final AndroidNodeStore nodeStore;final AndroidStandardExitStore exitStore;
 boolean orderedConnectCapturePending,startupCapturePending,destroyed;long orderedConnectTicket,startupCaptureTicket;
 final java.util.concurrent.BlockingQueue<Runnable> uiCallbacks=new java.util.concurrent.LinkedBlockingQueue<>();
 static final class View{String text="";boolean checked,enabled;void setText(String value){text=value;}boolean isChecked(){return checked;}void setChecked(boolean value){checked=value;}void setEnabled(boolean value){enabled=value;}}
 final View statusView=new View(),connectButton=new View(),multihopToggle=new View(),multihopHint=new View();String message="";double currentPathMs;static final class Telemetry{double cachedMedian(String id){return 0;}}final Telemetry telemetry=new Telemetry();
 final View killSwitch=new View(),autoRequirementsHint=new View();private String externalProtectionID="",externalProtectionSource="";
 static final class Probe{boolean isBusy(){return false;}}final Probe viaEntryProbe=new Probe();
 static final class Connection{
  int starts;boolean direct;AndroidNodeStore.Node entry;AndroidStandardExitStore.Entry ordinaryEntry,exit;String mode,execution;
  boolean cancelStartupPending(){return false;}boolean cancelPermissionPending(){return false;}boolean isActiveOrTransitioning(){return false;}void disconnect(Object callback){throw new AssertionError("unexpected disconnect");}
  void connectExternal(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,boolean direct,String mode,String execution,Object callback){starts++;this.entry=entry;this.exit=exit;this.direct=direct;this.mode=mode;this.execution=execution;}
  void connectExternal(AndroidConnectionProfileStore.ExternalSelection path,Object callback){if(path.ordinaryEntry!=null){starts++;ordinaryEntry=path.ordinaryEntry;exit=path.exit;mode=path.entryMode;execution=path.execution;direct=false;}else connectExternal(path.entry,path.exit,path.direct(),path.entryMode,path.execution,callback);}
  AndroidNodeStore.Node importedFinal;
  boolean isMultihopConnected(){return false;}String activeMultihopEntryId(){return ordinaryEntry==null?"":ordinaryEntry.id;}String activeMultihopExitId(){return importedFinal==null?"":importedFinal.id;}String activeMultihopExitMode(){return mode;}String activeMultihopEntryMode(){return ordinaryEntry==null?"":ordinaryEntry.protocol;}AndroidStandardExitStore.Entry activeImportedMultihopEntry(){return ordinaryEntry;}
  AndroidNodeStore.ChainCapture ordered;
  AndroidHomeStateStore.Snapshot orderedHome;String orderedSelection;
  boolean pathCurrent(AndroidHomeStateStore.Snapshot captured){return captured==AndroidHomeStateStore.current;}
  boolean isOrderedConnected(){return false;}List<AndroidNodeStore.ChainSource> activeOrderedSources(){throw new AssertionError("store fixture has no live ordered owner");}List<String> activeOrderedModes(){throw new AssertionError("store fixture has no live ordered modes");}
  void connectOrdered(AndroidNodeStore.ChainCapture captured,AndroidHomeStateStore.Snapshot home,String selection,Object callback){starts++;ordered=captured;orderedHome=home;orderedSelection=selection;}
  void connectImportedMultihop(AndroidStandardExitStore.Entry entry,AndroidNodeStore.Node exit,String mode,String execution,Object callback){starts++;ordinaryEntry=entry;importedFinal=exit;this.mode=mode;this.execution=execution;if(!AndroidImportedRouterPath.supports(entry.protocol,mode)||!execution.equals("local"))throw new AssertionError("changed imported Router path");}
  void connectMultihop(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,String mode,String execution,String entryMode,Object callback){throw new AssertionError("external selection became Router multihop");}
  void connect(String mode,List<String> layers,Object callback){throw new AssertionError("external selection used unrelated active Router");}
 }final Connection connection=new Connection();
 static final class ModeChoice{String id,title;List<String> layers;}
 ProductConnectSurface(ConnectionProfilesHarness.Fixture f){this(f,false);}ProductConnectSurface(ConnectionProfilesHarness.Fixture f,boolean independent){this(f.context,independent?new AndroidNodeStore(f.context):f.nodes,independent?new AndroidStandardExitStore(f.context):f.exits);}
 ProductConnectSurface(Context context,AndroidNodeStore nodes,AndroidStandardExitStore exits){super(context.getFilesDir());storeContext=context;nodeStore=nodes;exitStore=exits;}
 @Override public MemoryPreferences getSharedPreferences(String name,int mode){return storeContext.getSharedPreferences(name,mode);}
 SharedPreferences prefs(){return getSharedPreferences("router-vpn-unified",0);}void toast(String text){message=text;}void showNodes(){throw new AssertionError("selected external disappeared");}
 AndroidUnifiedNodeCatalog.Item selectedCatalogItem(){return new AndroidUnifiedNodeCatalog.Item(prefs().getString("selected_id",""),"router-vpn".equals(prefs().getString("selected_kind","router-vpn")));}
 AndroidNodeStore.Node nodeById(String id)throws Exception{for(var n:nodeStore.list())if(n.id.equals(id))return n;return null;}
 Object callback(){return new Object();}void configureMultihop(){}void refreshModeChoices(){}void refreshConnectionLater(){}ModeChoice currentMode(){throw new AssertionError("external selection used Router mode");}
 static String safe(Exception error){return error.getMessage();}void pressConnect(){connectOrDisconnect();}
 void runOnUiThread(Runnable delivery){uiCallbacks.add(delivery);}boolean isFinishing(){return false;}boolean isDestroyed(){return destroyed;}
 Runnable awaitOrderedDelivery()throws Exception{Runnable delivery=uiCallbacks.poll(5,java.util.concurrent.TimeUnit.SECONDS);if(delivery==null)throw new AssertionError("actual ordered capture worker did not return its UI callback");return delivery;}
 boolean mutationBusy(){return AndroidVpnMutationGuard.isBusy(this);}
 boolean orderedPathEnabled(){return prefs().getBoolean(MULTI_ON,false)&&!prefs().getString("multihop_nodes","").isEmpty();}AndroidOrderedPathPresentation currentOrderedPresentation(){return null;}
 void pressDNS(String mode){setQuickDns(mode);}void refreshDnsSelection(){}boolean openSelectedExternal(boolean edit){return isExternalSelected();}
 JSONObject activeBundle()throws Exception{return new JSONObject(ConnectionProfilesHarness.text(nodeStore.file(nodeStore.activeId())));}
 JSONObject selectedProfile(JSONObject bundle)throws Exception{return AndroidProfileSelection.selectedRouterProfile(bundle);}
 JSONObject activeRouterProfile(){try{return selectedProfile(activeBundle());}catch(Exception invalid){return null;}}
 void displayMultihop(){refreshMultihopSummary();}void displayProtection(){refreshSettingsState();}void pressProtection(boolean enabled){setQuickKillSwitch(enabled);}
 interface Click {void run(Object dialog,int index);}
 final class Choice {final String title;CharSequence[] labels;Click selected;Choice(String title){this.title=title;}Choice setItems(CharSequence[] labels,Click selected){this.labels=labels;this.selected=selected;return this;}Choice setNegativeButton(String text,Object ignored){return this;}void show(){dialog=this;}}
 Choice dialog;int refreshes;Choice choiceDialog(String title,String detail){return new Choice(title);}
 void choose(int index){Choice captured=dialog;dialog=null;captured.selected.run(captured,index);}void cancelChoice(){dialog=null;}
 void refreshAll(){refreshes++;}void offer(AndroidStandardExitStore.Entry first,List<AndroidNodeStore.Node> finals){chooseImportedRouterFinal(first,finals);}
 PRODUCT_IMPORTED
 PRODUCT_CONNECT
 PRODUCT_PROTECTION
}
final class LayeredVpnService {static Boolean lockdown;static Boolean currentLockdownState(){return lockdown;}}
final class AndroidUnifiedNodeCatalog {static final class Item{final String id;final boolean router;Item(String id,boolean router){this.id=id;this.router=router;}boolean isRouterVpn(){return router;}}}
// Process-wide cancellation boundary only; the comparison suite executes its
// actual native drain/restoration lifecycle.
final class AndroidExternalNodeComparison {static boolean active;static int cancellations;static boolean cancelActiveOperation(){if(!active)return false;cancellations++;return true;}}
final class AndroidViaEntryLatencyProbe {static boolean active;static int cancellations;static boolean cancelActiveOperation(){if(!active)return false;cancellations++;return true;}}
'''

HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;import java.util.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.io.*;
import android.content.*;
public final class ConnectionProfilesHarness {
 static int checks,cases;interface Action{void run()throws Exception;}
 static void check(boolean value,String text){checks++;if(!value)throw new AssertionError(text);}
 static Exception rejected(Action action,String label)throws Exception{try{action.run();}catch(Exception expected){checks++;return expected;}throw new AssertionError("accepted "+label);}
 static String text(File file)throws Exception{return Files.readString(file.toPath());}
 static JSONObject bundle(AndroidNodeStore.Node node)throws Exception{return new JSONObject(text(node.file));}
 static JSONObject profile(AndroidNodeStore.Node node)throws Exception{return AndroidProfileSelection.selectedRouterProfile(bundle(node));}
 // Android JSON object iteration order is not a persisted policy contract.
 // Compare every typed field and ordered array; file rollback tests still
 // require exact bytes.
 static boolean sameJSONValue(Object a,Object b)throws Exception{
  if(a instanceof JSONObject&&b instanceof JSONObject){JSONObject left=(JSONObject)a,right=(JSONObject)b;if(left.length()!=right.length())return false;for(Iterator<String> keys=left.keys();keys.hasNext();){String key=keys.next();if(!right.has(key)||!sameJSONValue(left.get(key),right.get(key)))return false;}return true;}
  if(a instanceof JSONArray&&b instanceof JSONArray){JSONArray left=(JSONArray)a,right=(JSONArray)b;if(left.length()!=right.length())return false;for(int i=0;i<left.length();i++)if(!sameJSONValue(left.get(i),right.get(i)))return false;return true;}
  return Objects.equals(a,b);
 }
 static boolean sameJSON(String a,String b)throws Exception{return sameJSONValue(new JSONObject(a),new JSONObject(b));}
 static JSONObject policy(String dns)throws Exception{return new JSONObject().put("dns_mode",dns).put("dns_protocol","doh").put("dns_host","149.112.112.112").put("dns_port",8443).put("dns_server_name","resolver.example").put("dns_path","/private-query").put("ipv6_mode","off").put("home_lan_access",false).put("home_lan_cidrs",new JSONArray().put("192.168.50.0/24")).put("mtu_policy","fixed").put("manual_mtu",1360);}
 static JSONObject node(String name,int key)throws Exception{
  byte[] publicKey=new byte[32];Arrays.fill(publicKey,(byte)key);String peer=Base64.getEncoder().encodeToString(publicKey);
  String proof=HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(("router-vpn-node-proof-v1\n"+peer).getBytes(StandardCharsets.UTF_8)));
  JSONObject p=policy("home").put("adguard_ipv4","10.12.0.53").put("adguard_ipv6","fd12::53").put("dns_host","10.12.0.53").put("id",name).put("name",name).put("node_proof_id",proof).put("api_token","fixture-api-"+name).put("socks_password","fixture-socks-"+name)
    .put("start_layer","aes-256-gcm+xor-whitening").put("auto_require_encrypted",true).put("auto_require_obfuscation",true).put("base_tunnel","awg").put("base_fallback",false).put("kill_switch",true).put("kill_switch_policy","always").put("daita_enabled",true).put("jumbo_tun",true).put("socks_enabled",false);
  JSONObject assets=new JSONObject().put("wg.conf",Base64.getEncoder().encodeToString(("[Interface]\nPrivateKey = fixture-private-"+name+"\n[Peer]\nPublicKey = "+peer+"\n").getBytes(StandardCharsets.UTF_8)));
  return new JSONObject().put("selectedRouterID",name).put("nodeProofId",proof).put("routerProfiles",new JSONArray().put(p)).put("profiles",new JSONObject().put("wg",assets).put("hysteria2",new JSONObject().put("fixture","entry"))).put("modes",new JSONArray().put(new JSONObject().put("id","wg")).put(new JSONObject().put("id","hysteria2")));
 }
 static AndroidStandardExitStore.Entry external(String id,boolean tor)throws Exception{
  AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id=id;e.name=id;e.protocol=tor?"tor-bridge":"socks5";
  if(tor){e.torTransport="obfs4";e.torBridges.add("obfs4 198.51.100.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=fixture-private-bridge iat-mode=0");e.torPolicy=policy("custom");}
  else{e.server="198.51.100.8";e.serverPort=1080;e.expectedPublicIp="203.0.113.9";e.username="fixture-private-user";e.password="fixture-private-password";e.policy=policy("custom");}
  return e;
 }
 static final class Fixture {
  final Context context;final AndroidNodeStore nodes;final AndroidStandardExitStore exits;final AndroidConnectionProfileStore store;final AndroidNodeStore.Node first,second;final MemoryPreferences prefs;final File rows;
  Fixture(Path root)throws Exception{cases++;context=new Context(Files.createTempDirectory(root,"case-").toFile());nodes=new AndroidNodeStore(context);exits=new AndroidStandardExitStore(context);store=new AndroidConnectionProfileStore(context,nodes,exits);prefs=context.getSharedPreferences("router-vpn-unified",0);rows=new File(context.getFilesDir(),"connection-profiles-v4.json");first=nodes.importBundle(node("first",1).toString().getBytes(StandardCharsets.UTF_8));second=nodes.importBundle(node("second",2).toString().getBytes(StandardCharsets.UTF_8));nodes.select(first.id);prefs.edit().putString("selected_kind","router-vpn").putString("selected_id",first.id).putString("mode","smart-auto").putString("unrelated","keep").commit();exits.save(external("external-a",false));exits.save(external("external-b",true));}
  void changeNode(AndroidNodeStore.Node n)throws Exception{JSONObject b=bundle(n),p=AndroidProfileSelection.selectedRouterProfile(b);p.put("start_layer","off").put("dns_mode","rescue").put("home_lan_access",true).put("manual_mtu",1400).put("auto_require_encrypted",false);nodes.importBundle(b.toString().getBytes(StandardCharsets.UTF_8));}
  void changeExternal(String id)throws Exception{AndroidStandardExitStore.Entry e=exits.get(id);JSONObject p=AndroidTorProfile.isTor(e.protocol)?e.torPolicy:e.policy;p.put("dns_host","9.9.9.9").put("manual_mtu",1280).put("home_lan_access",true);exits.save(e);}
  void otherSelection()throws Exception{nodes.select(second.id);prefs.edit().putString("selected_kind","router-vpn").putString("selected_id",second.id).putString("mode","auto").putBoolean("multihop_on",false).putString("custom_presets","[{\"name\":\"other\",\"layers\":[\"hysteria2\"]}]").commit();}
  JSONObject rows()throws Exception{return new JSONObject(text(rows));}JSONObject row()throws Exception{return rows().getJSONArray("profiles").getJSONObject(0);}
  void row(JSONObject value)throws Exception{Files.writeString(rows.toPath(),new JSONObject().put("schema_version",AndroidConnectionProfileStore.SCHEMA_VERSION).put("profiles",new JSONArray().put(value)).toString());}
 }
 static final class State {
  final Map<String,byte[]> files=new TreeMap<>();final Map<String,Map<String,?>> preferences=new TreeMap<>();
  State(Fixture f)throws Exception{try(var paths=Files.walk(f.context.getFilesDir().toPath())){for(Path p:paths.filter(Files::isRegularFile).toList())files.put(p.toString(),Files.readAllBytes(p));}for(var e:f.context.preferences.entrySet())preferences.put(e.getKey(),e.getValue().getAll());}
  void same(Fixture f,String label)throws Exception{State after=new State(f);check(files.keySet().equals(after.files.keySet()),label+" files");for(String key:files.keySet())check(Arrays.equals(files.get(key),after.files.get(key)),label+" byte rollback "+key);check(preferences.equals(after.preferences),label+" all preference rollback");}
 }
 static AndroidStandardExitStore.Entry ordinary(String protocol,String id)throws Exception{
  AndroidStandardExitStore.Entry e=external(id,false);e.protocol=protocol;e.startupMode="auto";e.autoConnect=true;e.policy.put("kill_switch",true).put("kill_switch_policy","always");
  e.tlsServerName="ordinary.example.test";e.method="2022-blake3-aes-256-gcm";e.secret=Base64.getEncoder().encodeToString("S".repeat(32).getBytes(StandardCharsets.UTF_8));
  if(protocol.equals("wireguard")||protocol.equals("amneziawg")){
   e.wgPrivateKey=Base64.getEncoder().encodeToString("x".repeat(32).getBytes(StandardCharsets.UTF_8));e.wgPeerPublicKey=Base64.getEncoder().encodeToString("p".repeat(32).getBytes(StandardCharsets.UTF_8));e.wgAddresses.addAll(List.of("10.93.0.2/32","fd93::2/128"));e.wgAllowedIps.addAll(List.of("0.0.0.0/0","::/0"));e.wgMtu=1360;e.wgKeepalive=25;
   if(protocol.equals("amneziawg"))e.awgParameters=new JSONObject().put("jc","3").put("jmin","40").put("jmax","900").put("s1","15").put("s2","16").put("s3","32").put("s4","32").put("h1","100-110").put("h2","200-210").put("h3","300-310").put("h4","400-410");
  }
  if(protocol.equals("openvpn")){JSONObject source=new JSONObject(Files.readString(Path.of(System.getenv("ROUTERVPN_OPENVPN_MULTIHOST_CLIENT_FIXTURE")))).getJSONObject("external"),inline=source.getJSONObject("openvpn");e.openVPNConfig=inline.getString("config");e.username=inline.getString("username");e.password=inline.getString("password");e.expectedPublicIp=source.getString("expected_public_ip");e.openVPNPairing=new JSONObject(source.getJSONObject("openvpn_pairing").toString());e.openVPNResponseProbes=new JSONObject(source.getJSONObject("openvpn_response_probes").toString());}
  return e;
 }
 static AndroidStandardExitStore.Entry mixedSetup(Fixture f,String protocol)throws Exception{return mixedSetup(f,protocol,"shadowsocks");}
 static AndroidStandardExitStore.Entry mixedSetup(Fixture f,String protocol,String finalMode)throws Exception{
  var entry=ordinary(protocol,"imported-first");f.exits.save(entry);
  JSONObject last=bundle(f.first),profile=AndroidProfileSelection.selectedRouterProfile(last);
  profile.put("node_kind","router-vpn");
  last.getJSONObject("profiles").put("shadowsocks",new JSONObject().put("sing-box.json","fixture compiler boundary only"));
  last.getJSONObject("profiles").put("hysteria2",new JSONObject().put("sing-box.json","separate HY2 final compiler boundary"));
  if(packetFinal(finalMode))completePacketFinal(last,finalMode);
  f.nodes.importBundle(last.toString().getBytes(StandardCharsets.UTF_8));
  if(finalMode.equals("shadowsocks"))f.store.selectImportedRouterPath(entry,f.first);else f.store.selectImportedRouterPath(entry,f.first,finalMode);return entry;
 }
 static boolean packetFinal(String mode){return List.of("wg","awg2-fast","awg2-strong").contains(mode);}
 static String finalLabel(String mode){return switch(mode){case "wg"->"WireGuard";case "awg2-fast"->"AmneziaWG Fast";case "awg2-strong"->"AmneziaWG Strong";case "hysteria2"->"Hysteria2";default->"Shadowsocks";};}
 static String finalAsset(String mode){return packetFinal(mode)?mode.equals("wg")?"wg.conf":"awg.conf":"sing-box.json";}
 static void completePacketFinal(JSONObject value,String mode)throws Exception{
  String conf=new String(Base64.getDecoder().decode(value.getJSONObject("profiles").getJSONObject("wg").getString("wg.conf")),StandardCharsets.UTF_8);
  if(!conf.contains("Address ="))conf=conf.replace("[Interface]\n","[Interface]\nAddress = 10.70.0.2/32\n");
  if(!conf.contains("Endpoint ="))conf+="Endpoint = 198.51.100.70:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n";
  if(!mode.equals("wg"))conf+="Jc = 4\nJmin = 40\nJmax = 70\nS1 = 12\nS2 = 24\nH1 = 100\nH2 = 200\nH3 = 300\nH4 = 400\n";
  value.getJSONObject("profiles").put(mode,new JSONObject().put(finalAsset(mode),Base64.getEncoder().encodeToString(conf.getBytes(StandardCharsets.UTF_8))));
 }
 static void connectRouterProfiles(Path root)throws Exception{
  for(String protocol:List.of("http","https")){
   Fixture f=new Fixture(root);var entry=ordinary(protocol,"connect-first");entry.policy.put("start_layer","off");f.exits.save(entry);
   JSONObject last=bundle(f.first),finalPolicy=AndroidProfileSelection.selectedRouterProfile(last);
   finalPolicy.put("node_kind","router-vpn").put("start_layer","off").put("dns_mode","home").put("dns_protocol","tcp").put("dns_host","192.168.50.133").put("dns_port",5353).put("adguard_ipv4","192.168.50.133");
   last.getJSONObject("profiles").put("shadowsocks",new JSONObject().put("sing-box.json","original SS2022 bytes; compiler boundary covered by actual247 gate"));
   f.nodes.importBundle(last.toString().getBytes(StandardCharsets.UTF_8));f.store.selectImportedRouterPath(entry,f.first,"shadowsocks");var saved=f.store.add("Captured CONNECT path");
   check(f.row().getString("ordinary_entry_protocol").equals(protocol)&&f.row().getString("multihop_entry_mode").equals(AndroidExternalPolicy.protocol(protocol)),"CONNECT row lost distinct stored-source and canonical native labels");
   String originalPassword=entry.password;entry.password="new exact CONNECT password";f.exits.save(entry);f.changeNode(f.first);f.otherSelection();f.store.load(saved.id);
   var path=f.store.currentImportedRouterPath();JSONObject restored=profile(f.first);
   check(path.entry.protocol.equals(protocol)&&path.entry.password.equals(entry.password)&&path.entry.tlsServerName.equals(entry.tlsServerName)&&path.exit.id.equals(f.first.id)&&path.exitMode.equals("shadowsocks")&&path.execution.equals("local"),"CONNECT profile lost current referenced credentials or original direction");
   check(restored.getString("dns_mode").equals("home")&&restored.getString("dns_protocol").equals("tcp")&&restored.getString("dns_host").equals("192.168.50.133")&&restored.getInt("dns_port")==5353&&restored.getString("start_layer").equals("off"),"CONNECT profile changed exact saved DNS or layer");
   check(!text(f.rows).contains(originalPassword)&&!text(f.rows).contains(entry.password),"CONNECT row persisted transport secret");
   ProductConnectSurface ui=new ProductConnectSurface(f);ui.displayMultihop();check(ui.multihopHint.text.equals(entry.name+" → "+f.first.name+" • "+(protocol.equals("http")?"HTTP CONNECT":"HTTPS CONNECT")+" → Shadowsocks • Local"),"CONNECT UI changed its captured entry, final or Local identity");ui.multihopToggle.setChecked(true);ui.pressConnect();check(ui.connection.starts==1&&ui.connection.ordinaryEntry.password.equals(entry.password)&&ui.connection.mode.equals("shadowsocks"),"CONNECT public selection replaced original credentials");
   JSONObject original=f.row();for(String fault:List.of("udp","layer","execution","source","alias")){
    JSONObject row=new JSONObject(original.toString());
    if(fault.equals("udp"))row.getJSONObject("exit_policy").put("dns_protocol","udp");
    else if(fault.equals("layer"))row.getJSONObject("exit_policy").put("start_layer","aes-256-gcm");
    else if(fault.equals("execution"))row.put("multihop_execution","server");
    else if(fault.equals("alias"))row.put("multihop_entry_mode",protocol);
    else row.put("multihop_entry_id","foreign-original");
    f.row(row);State before=new State(f);rejected(()->f.store.load(saved.id),"CONNECT "+fault);before.same(f,"CONNECT refusal "+fault);
   }
   f.row(original);f.changeExternal(entry.id);f.otherSelection();State before=new State(f);f.prefs.failures=1;rejected(()->f.store.load(saved.id),"CONNECT selection publication");before.same(f,"CONNECT original rollback");
   f.store.delete(saved.id);check(f.exits.get(entry.id).password.equals(entry.password)&&f.first.file.isFile(),"CONNECT Delete removed referenced owners");
  }
 }
 static List<String> importedProtocols=List.of("shadowsocks","hysteria2");
 static List<String> importedFinalModes=List.of("shadowsocks","hysteria2");
 static void importedRouterRoundtrip(Path root)throws Exception{for(String protocol:importedProtocols)for(String finalMode:importedFinalModes){
  Fixture f=new Fixture(root);var entry=mixedSetup(f,protocol,finalMode);var saved=f.store.add("Imported to paired");JSONObject row=f.row();
  check(f.rows().getInt("schema_version")==7&&row.getString("node_kind").equals("router-vpn")&&row.getString("multihop_entry_kind").equals("external")&&row.getString("node_id").equals(f.first.id),"mixed schema6 lost exact role references");
  check(row.has("ordinary_entry_policy")&&row.has("exit_policy")&&!row.has("entry_policy")&&!row.has("entry_profile_id"),"mixed policy replaced imported role with Router identity");
  String serialized=text(f.rows);for(String secret:List.of("fixture-api-","fixture-socks-","fixture-private-",entry.secret,entry.wgPrivateKey,entry.wgPreSharedKey,"sing-box.json","api_token"))if(!secret.isEmpty())check(!serialized.contains(secret),"mixed row copied private bytes");
  entry.secret=Base64.getEncoder().encodeToString("N".repeat(32).getBytes(StandardCharsets.UTF_8));if(List.of("wireguard","amneziawg").contains(protocol)){entry.wgPrivateKey=Base64.getEncoder().encodeToString("K".repeat(32).getBytes(StandardCharsets.UTF_8));entry.wgPreSharedKey=Base64.getEncoder().encodeToString("P".repeat(32).getBytes(StandardCharsets.UTF_8));}entry.policy.put("manual_mtu",1280);f.exits.save(entry);
  f.changeNode(f.first);JSONObject changed=bundle(f.first);AndroidProfileSelection.selectedRouterProfile(changed).put("api_token","new referenced final credential");String retainedFinalAsset=changed.getJSONObject("profiles").getJSONObject(finalMode).getString(finalAsset(finalMode));if(packetFinal(finalMode)){String currentConf=new String(Base64.getDecoder().decode(retainedFinalAsset),StandardCharsets.UTF_8)+"# current referenced private asset\n";retainedFinalAsset=Base64.getEncoder().encodeToString(currentConf.getBytes(StandardCharsets.UTF_8));changed.getJSONObject("profiles").getJSONObject(finalMode).put(finalAsset(finalMode),retainedFinalAsset);}f.nodes.importBundle(changed.toString().getBytes(StandardCharsets.UTF_8));
  f.otherSelection();f.store.load(saved.id);check(bundle(f.first).getJSONObject("profiles").getJSONObject(finalMode).getString(finalAsset(finalMode)).equals(retainedFinalAsset),"profile Load replaced current referenced final transport credentials");var path=f.store.currentImportedRouterPath();
  check(path.entry.id.equals(entry.id)&&path.entry.protocol.equals(protocol)&&path.entry.tlsServerName.equals(entry.tlsServerName)&&path.exit.id.equals(f.first.id)&&path.exitMode.equals(finalMode)&&path.execution.equals("local")&&row.getString("ordinary_entry_protocol").equals(protocol)&&row.getString("multihop_entry_mode").equals(protocol),"mixed load changed original direction or execution");
  if(List.of("wireguard","amneziawg").contains(protocol))check(path.entry.wgPrivateKey.equals(entry.wgPrivateKey)&&path.entry.wgPreSharedKey.equals(entry.wgPreSharedKey)&&path.entry.wgPeerPublicKey.equals(entry.wgPeerPublicKey)&&path.entry.wgMtu==entry.wgMtu&&path.entry.wgKeepalive.equals(entry.wgKeepalive),"profile Load replaced current referenced packet credentials or endpoint settings");
  check(path.entry.secret.equals(entry.secret)&&path.entry.policy.getInt("manual_mtu")==1360&&profile(f.first).getInt("manual_mtu")==1360&&profile(f.first).getString("api_token").equals("new referenced final credential"),"mixed load did not restore separate policies while retaining referenced credentials");
  ProductConnectSurface ui=new ProductConnectSurface(f);ui.displayMultihop();check(ui.multihopHint.text.contains(" → "+finalLabel(finalMode)+" • Local"),"saved imported path mislabeled its selected final transport");ui.multihopToggle.setChecked(true);ui.pressConnect();
  check(ui.connection.starts==1&&ui.connection.ordinaryEntry.id.equals(entry.id)&&ui.connection.importedFinal.id.equals(f.first.id)&&ui.connection.entry==null&&ui.connection.mode.equals(finalMode),"shipping Connect lost imported Router direction");
  f.exits.get(entry.id);var updated=f.exits.get(entry.id);updated.policy.put("manual_mtu",1400);f.exits.save(updated);f.store.update(saved.id,"Updated mixed");f.changeExternal(entry.id);f.otherSelection();f.store.load(saved.id);
  check(f.exits.get(entry.id).policy.getInt("manual_mtu")==1400&&f.store.list().size()==1,"mixed Update lost original row or current policy");
  f.store.delete(saved.id);check(f.store.list().isEmpty()&&f.exits.get(entry.id).secret.equals(entry.secret)&&f.first.file.isFile(),"mixed Delete removed private referenced owners");
 }}
 static void importedRouterInvalid(Path root)throws Exception{for(String protocol:importedProtocols)for(String finalMode:importedFinalModes){
  for(String fault:List.of("server","auto","wrong-mode","other-supported-mode","wrong-direction","wrong-kind","missing-source","public-identity","foreign-secret","downgrade")){
   Fixture f=new Fixture(root);mixedSetup(f,protocol,finalMode);var saved=f.store.add("Mixed rejection");JSONObject row=f.row();
   switch(fault){case "server","auto":row.put("multihop_execution",fault);break;case "wrong-mode":row.put("multihop_entry_mode","socks5");break;case "other-supported-mode":row.put("multihop_entry_mode",protocol.equals("shadowsocks")?"hysteria2":"shadowsocks");break;
    case "wrong-direction":row.put("multihop_exit_id",f.second.id);break;case "wrong-kind":row.put("multihop_entry_kind","router-vpn");break;
    case "missing-source":row.put("multihop_entry_id","missing");break;case "public-identity":row.put("ordinary_entry_public_ip","203.0.113.200");break;
    case "foreign-secret":row.getJSONObject("ordinary_entry_policy").put("password","must not persist");break;
   }
   f.row(row);if(fault.equals("downgrade"))Files.writeString(f.rows.toPath(),f.rows().put("schema_version",5).toString());
   State before=new State(f);int writes=AndroidPrivateFileStore.writes;rejected(()->f.store.load(saved.id),fault);before.same(f,"mixed rejection "+fault);check(writes==AndroidPrivateFileStore.writes,"mixed rejection wrote before validation");
  }
 }}
 static void importedRouterRollback(Path root)throws Exception{for(String protocol:importedProtocols)for(String finalMode:importedFinalModes){
  for(String fault:List.of("node","entry","preferences","rollback")){
   Fixture f=new Fixture(root);var entry=mixedSetup(f,protocol,finalMode);var saved=f.store.add("Mixed rollback");f.changeExternal(entry.id);f.changeNode(f.first);f.otherSelection();State before=new State(f);
   if(fault.equals("preferences")||fault.equals("rollback"))f.prefs.failures=fault.equals("rollback")?2:1;
   else{AndroidPrivateFileStore.failPath=(fault.equals("node")?f.first.file:new File(f.context.getFilesDir(),"standard-exits.json")).getAbsolutePath();AndroidPrivateFileStore.failures=1;}
   try{Exception error=rejected(()->f.store.load(saved.id),fault);before.same(f,"mixed transactional "+fault);check(error.getMessage().contains(fault.equals("rollback")?"rollback is incomplete":"prior connection state was restored"),"mixed rollback status inaccurate");}
   finally{AndroidPrivateFileStore.failures=0;AndroidPrivateFileStore.failPath="";}
  }
  Fixture f=new Fixture(root);var entry=mixedSetup(f,protocol,finalMode);var saved=f.store.add("Mixed source race");f.changeExternal(entry.id);f.otherSelection();Map<String,?> preferences=f.prefs.getAll();
  AndroidImportedRouterPath.afterValidation=()->{AndroidImportedRouterPath.afterValidation=null;try{var current=f.exits.get(entry.id);current.secret=Base64.getEncoder().encodeToString("R".repeat(32).getBytes(StandardCharsets.UTF_8));f.exits.save(current);}catch(Exception error){throw new IllegalStateException(error);}};
  try{rejected(()->f.store.load(saved.id),"mixed source changed during validation");check(f.exits.get(entry.id).policy.getInt("manual_mtu")==1280&&preferences.equals(f.prefs.getAll()),"mixed race replaced newer source or selected stale path");}finally{AndroidImportedRouterPath.afterValidation=null;}
  State before=new State(f);f.prefs.failures=1;rejected(()->f.store.selectImportedRouterPath(f.exits.get(entry.id),f.first,finalMode),"mixed selection publication failure");before.same(f,"mixed selection rollback");
 }}
 static void importedRouterProduct(Path root)throws Exception{
  String selectedImportedProtocol=importedProtocols.get(importedProtocols.size()-1),selectedFinalMode=importedFinalModes.get(importedFinalModes.size()-1);
  for(String protocol:importedProtocols)for(String finalMode:importedFinalModes){
   Fixture f=new Fixture(root);var first=mixedSetup(f,protocol,finalMode);f.otherSelection();State before=new State(f);
   ProductConnectSurface ui=new ProductConnectSurface(f);ui.offer(first,List.of(f.first));
   check(ui.dialog!=null&&ui.dialog.title.equals("Final Router node"),"shipping final chooser missing");before.same(f,"opening node chooser");
   ui.choose(0);CharSequence[] expectedModes=packetFinal(finalMode)?new CharSequence[]{"Shadowsocks","Hysteria2",finalLabel(finalMode)}:new CharSequence[]{"Shadowsocks","Hysteria2"};check(ui.dialog!=null&&Arrays.equals(ui.dialog.labels,expectedModes),"shipping transport chooser lost complete modes");before.same(f,"opening mode chooser");
   ui.choose(Arrays.asList(expectedModes).indexOf(finalLabel(finalMode)));check(ui.dialog==null&&ui.refreshes==1&&ui.message.startsWith("Saved "),"shipping mode callback did not save");
   var current=f.store.currentImportedRouterPath();check(current.entry.id.equals(first.id)&&current.exitMode.equals(finalMode)&&current.execution.equals("local"),"shipping choice persisted wrong final mode");
   var saved=f.store.add("Product "+protocol+" to "+finalMode);check(f.row().getString("multihop_exit_mode").equals(finalMode),"Add lost Product mode");
   f.otherSelection();f.store.load(saved.id);ProductConnectSurface connect=new ProductConnectSurface(f);connect.multihopToggle.setChecked(f.prefs.getBoolean("multihop_on",false));connect.pressConnect();check(connect.connection.starts==1&&connect.connection.mode.equals(finalMode)&&connect.connection.ordinaryEntry.protocol.equals(protocol),"Product Add Load Connect lost selected mode");
   f.store.update(saved.id,"Updated Product mode");f.otherSelection();f.store.load(saved.id);check(f.store.currentImportedRouterPath().exitMode.equals(finalMode),"Product Update Load lost selected mode");f.store.delete(saved.id);check(f.store.list().isEmpty(),"Product Delete failed");
  }
  for(String available:List.of("shadowsocks","hysteria2","none","malformed","missing-layer")){
   Fixture f=new Fixture(root);var first=mixedSetup(f,selectedImportedProtocol);JSONObject value=bundle(f.first),maps=value.getJSONObject("profiles");
   for(String mode:List.of("shadowsocks","hysteria2"))if(!mode.equals(available.equals("missing-layer")?"hysteria2":available))maps.remove(mode);
   if(available.equals("hysteria2"))AndroidProfileSelection.selectedRouterProfile(value).put("start_layer","off");
   if(available.equals("malformed"))maps.put("hysteria2",new JSONObject().put("certificate","only a fragment"));
   f.nodes.importBundle(value.toString().getBytes(StandardCharsets.UTF_8));f.otherSelection();State before=new State(f);ProductConnectSurface ui=new ProductConnectSurface(f);ui.offer(first,List.of(f.first));ui.choose(0);
   if(List.of("none","malformed","missing-layer").contains(available))check(ui.dialog==null&&ui.message.contains("no complete"),"incomplete transport was offered");
   else{check(ui.dialog!=null&&ui.dialog.labels.length==1&&ui.dialog.labels[0].equals(available.equals("hysteria2")?"Hysteria2":"Shadowsocks"),"chooser offered missing final transport");ui.cancelChoice();}
   before.same(f,"filtered choice/cancel");
  }
  for(String fault:List.of("cancel-final","cancel-mode","changed-entry","changed-profile","changed-final-bytes","busy","stale-final-digest","compiler-final-race")){
   Fixture f=new Fixture(root);var first=mixedSetup(f,selectedImportedProtocol,selectedFinalMode);f.otherSelection();ProductConnectSurface ui=new ProductConnectSurface(f);ui.offer(first,List.of(f.first));
   if(fault.equals("cancel-final")){State before=new State(f);ui.cancelChoice();before.same(f,fault);continue;}
   ui.choose(0);check(ui.dialog!=null,"negative did not reach actual transport callback");
   if(fault.equals("changed-entry")){var changed=f.exits.get(first.id);changed.password="replacement original entry password";f.exits.save(changed);}
   if(fault.equals("changed-profile"))f.changeNode(f.first);
   if(fault.equals("changed-final-bytes")){JSONObject changed=bundle(f.first);changed.getJSONObject("profiles").getJSONObject(selectedFinalMode).put(finalAsset(selectedFinalMode),"replacement final credential bytes");f.nodes.importBundle(changed.toString().getBytes(StandardCharsets.UTF_8));}
   State before=new State(f);int writes=AndroidPrivateFileStore.writes;
   if(fault.equals("cancel-mode")){ui.cancelChoice();before.same(f,fault);continue;}
   if(fault.equals("stale-final-digest")){rejected(()->f.store.selectImportedRouterPath(first,f.first,selectedFinalMode,"0".repeat(64)),fault);before.same(f,fault);continue;}
   if(fault.equals("compiler-final-race"))AndroidImportedRouterPath.afterValidation=()->{AndroidImportedRouterPath.afterValidation=null;try{JSONObject changed=bundle(f.first);AndroidProfileSelection.selectedRouterProfile(changed).put("api_token","new concurrently captured final");Files.writeString(f.first.file.toPath(),changed.toString());}catch(Exception error){throw new IllegalStateException(error);}};
   if(fault.equals("busy"))AndroidVpnMutationGuard.busy=true;
   try{ui.choose(Arrays.asList(ui.dialog.labels).indexOf(finalLabel(selectedFinalMode)));check(ui.refreshes==0&&!ui.message.startsWith("Saved "),"shipping callback accepted "+fault);
    if(fault.equals("compiler-final-race")){check(profile(f.first).getString("api_token").equals("new concurrently captured final")&&f.nodes.activeId().equals(f.second.id)&&f.prefs.getString("selected_id","").equals(f.second.id),"compiler race overwrote replacement or selected stale final");}
    else{before.same(f,"shipping callback "+fault);check(writes==AndroidPrivateFileStore.writes,"rejected callback wrote source "+fault);}
   }finally{AndroidVpnMutationGuard.busy=false;AndroidImportedRouterPath.afterValidation=null;}
  }
 }
 static void importedSummary(Path root)throws Exception{
  Fixture f=new Fixture(root);mixedSetup(f,"shadowsocks");
  for(String mode:List.of("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong","unknown-saved-final")){
   f.prefs.edit().putString("multihop_exit_mode",mode).commit();ProductConnectSurface ui=new ProductConnectSurface(f);ui.displayMultihop();String label=mode.equals("unknown-saved-final")?"Unsupported final transport":finalLabel(mode);
   check(ui.multihopHint.text.contains(" → "+label+" • Local"),"saved final transport summary mislabeled "+mode);
  }
 }
 static void packetFinalBoundaries(Path root)throws Exception{
  if(!packetFinal(importedFinalModes.get(0)))return;String mode=importedFinalModes.get(0);
  for(String protocol:List.of("shadowsocks","hysteria2")){
   Fixture f=new Fixture(root);var entry=mixedSetup(f,protocol,mode);JSONObject bytes=bundle(f.first);String conf=new String(Base64.getDecoder().decode(bytes.getJSONObject("profiles").getJSONObject(mode).getString(finalAsset(mode))),StandardCharsets.UTF_8);bytes.getJSONObject("profiles").getJSONObject(mode).put(finalAsset(mode),Base64.getEncoder().encodeToString(conf.replace("Endpoint =","EndpointMissing =").getBytes(StandardCharsets.UTF_8)));f.nodes.importBundle(bytes.toString().getBytes(StandardCharsets.UTF_8));f.otherSelection();State before=new State(f);ProductConnectSurface ui=new ProductConnectSurface(f);ui.offer(entry,List.of(f.first));ui.choose(0);check(ui.dialog!=null&&!Arrays.asList(ui.dialog.labels).contains(finalLabel(mode)),"picker offered incomplete paired packet final");ui.cancelChoice();before.same(f,"incomplete packet final choice");
   Fixture layers=new Fixture(root);var first=mixedSetup(layers,protocol,mode);JSONObject missing=bundle(layers.first);missing.getJSONObject("profiles").remove("shadowsocks");layers.nodes.importBundle(missing.toString().getBytes(StandardCharsets.UTF_8));layers.otherSelection();State unchanged=new State(layers);ProductConnectSurface layerUI=new ProductConnectSurface(layers);layerUI.offer(first,List.of(layers.first));layerUI.choose(0);check(layerUI.dialog==null&&layerUI.message.contains("no complete supported"),"picker offered layered packet final without original same-node layer source");unchanged.same(layers,"missing packet layer");
   if(mode.equals("wg")){Fixture all=new Fixture(root);var imported=mixedSetup(all,protocol);JSONObject complete=bundle(all.first);for(String packet:List.of("wg","awg2-fast","awg2-strong"))completePacketFinal(complete,packet);all.nodes.importBundle(complete.toString().getBytes(StandardCharsets.UTF_8));all.otherSelection();State stable=new State(all);ProductConnectSurface choices=new ProductConnectSurface(all);choices.offer(imported,List.of(all.first));choices.choose(0);check(choices.dialog!=null&&Arrays.equals(choices.dialog.labels,new CharSequence[]{"Shadowsocks","Hysteria2","WireGuard","AmneziaWG Fast","AmneziaWG Strong"}),"picker lost distinct complete paired packet variants");choices.cancelChoice();stable.same(all,"all five final choices");}
  }
  for(String entryProtocol:List.of("wireguard","amneziawg")){
   Fixture f=new Fixture(root);var packet=mixedSetup(f,entryProtocol);JSONObject complete=bundle(f.first);completePacketFinal(complete,mode);f.nodes.importBundle(complete.toString().getBytes(StandardCharsets.UTF_8));f.otherSelection();State before=new State(f);f.store.selectImportedRouterPath(packet,f.first,mode);f.otherSelection();before=new State(f);ProductConnectSurface ui=new ProductConnectSurface(f);ui.offer(packet,List.of(f.first));ui.choose(0);check(ui.dialog!=null&&Arrays.asList(ui.dialog.labels).contains(finalLabel(mode)),"picker omitted configured nested packet graph");ui.cancelChoice();before.same(f,"packet-packet picker refusal");
  }
 }
 static void completeSecond(Fixture f)throws Exception{JSONObject value=bundle(f.second);AndroidProfileSelection.selectedRouterProfile(value).put("node_kind","router-vpn");value.getJSONObject("profiles").put("shadowsocks",new JSONObject().put("sing-box.json","second SS compiler boundary")).put("hysteria2",new JSONObject().put("sing-box.json","second HY2 compiler boundary"));f.nodes.importBundle(value.toString().getBytes(StandardCharsets.UTF_8));f.nodes.select(f.first.id);}
 static void selectSuccessor(Fixture f,String entryID,AndroidNodeStore.Node last,int mode)throws Exception{
  ProductConnectSurface ui=new ProductConnectSurface(f);ui.offer(f.exits.get(entryID),List.of(last));ui.choose(0);ui.choose(mode);
  check(ui.refreshes==1&&ui.message.startsWith("Saved "),"successor Product choice failed: "+ui.message);
 }
 static void profilePreferences(Path root)throws Exception{
  Fixture f=new Fixture(root);var first=mixedSetup(f,"shadowsocks");completeSecond(f);var saved=f.store.add("Preference owner");f.otherSelection();final Map<String,?>[] successor=new Map[]{null};
  f.prefs.failures=1;f.prefs.beforeFailure=()->{try{selectSuccessor(f,first.id,f.second,1);successor[0]=f.prefs.getAll();}catch(Exception error){throw new IllegalStateException(error);}};
  Exception failure=rejected(()->f.store.load(saved.id),"older profile selection failure");
  check(successor[0]!=null,"successor Product publication did not complete before old failure: "+failure.getCause());check(successor[0].equals(f.prefs.getAll()),"profile preference rollback overwrote the successor Product selection");
  check(f.nodes.activeId().equals(f.second.id),"profile preference rollback changed successor node selection");
  check(failure.getMessage().contains("rollback is incomplete")&&failure.getSuppressed().length>0,"newer preference ownership was falsely reported as restored");
  for(boolean failBeforePublication:List.of(true)){
   Fixture early=new Fixture(root);var entry=mixedSetup(early,"shadowsocks");completeSecond(early);var row=early.store.add("Original preference admission");early.changeNode(early.first);early.otherSelection();final Map<String,?>[] captured=new Map[]{null};
   AndroidPrivateFileStore.beforeWrite=()->{AndroidPrivateFileStore.beforeWrite=null;try{selectSuccessor(early,entry.id,early.second,1);captured[0]=early.prefs.getAll();}catch(Exception error){throw new IllegalStateException(error);}if(failBeforePublication)throw new IllegalStateException("owned node write rejected before preferences");};
   try{Exception rejected=rejected(()->early.store.load(row.id),"changed original preferences");check(captured[0]!=null&&captured[0].equals(early.prefs.getAll()),"profile apply or unattempted rollback replaced newer preferences");check(early.nodes.activeId().equals(early.second.id),"unattempted preference rollback changed successor active node");check(rejected.getMessage().contains("rollback is incomplete"),"changed preference owner was falsely restored");}finally{AndroidPrivateFileStore.beforeWrite=null;}
  }
  Fixture atomic=new Fixture(root);mixedSetup(atomic,"shadowsocks");var row=atomic.store.add("Atomic preference restore");atomic.otherSelection();
  var entered=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);var writerStarted=new java.util.concurrent.CountDownLatch(1);final Throwable[] outcomes=new Throwable[2];
  atomic.prefs.failures=1;atomic.prefs.beforeFailure=()->atomic.prefs.beforeCommit=()->{entered.countDown();try{if(!release.await(5,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("preference restore barrier missing");}catch(InterruptedException error){throw new IllegalStateException(error);}};
  Thread restoring=new Thread(()->{try{atomic.store.load(row.id);}catch(Throwable error){outcomes[0]=error;}},"owned-preference-restore");
  Thread writer=new Thread(()->{writerStarted.countDown();try{AndroidConnectionProfileStore.applySelection(atomic.prefs,atomic.prefs.edit().putString("mode","newer Product mode"));}catch(Throwable error){outcomes[1]=error;}},"independent-Product-editor");
  try{restoring.start();check(entered.await(5,java.util.concurrent.TimeUnit.SECONDS),"preference rollback did not reach actual commit");writer.start();check(writerStarted.await(5,java.util.concurrent.TimeUnit.SECONDS),"preference writer did not start");long end=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(5);boolean blocked=false;while(writer.isAlive()&&System.nanoTime()<end){StackTraceElement[] stack=writer.getStackTrace();if(writer.getState()==Thread.State.BLOCKED&&stack.length>0&&stack[0].getClassName().equals("com.eabusham.routervpn.AndroidConnectionProfileStore")&&stack[0].getMethodName().equals("applySelection")){blocked=true;break;}Thread.yield();}release.countDown();restoring.join(5000);writer.join(5000);check(blocked,"preference rollback comparison and publication did not exclude the Product writer");check(!restoring.isAlive()&&!writer.isAlive()&&outcomes[0]!=null&&outcomes[1]==null,"original preference rollback/writer did not join");check(atomic.prefs.getString("mode","").equals("newer Product mode"),"preference rollback erased the later committed choice");}finally{release.countDown();restoring.join(5000);if(writer.getState()!=Thread.State.NEW)writer.join(5000);atomic.prefs.beforeCommit=null;}
  Fixture concurrent=new Fixture(root);var imported=mixedSetup(concurrent,"shadowsocks");completeSecond(concurrent);var selectedRow=concurrent.store.add("Whole selection admission");concurrent.otherSelection();
  var captured=new java.util.concurrent.CountDownLatch(1);var continueLoad=new java.util.concurrent.CountDownLatch(1);final Throwable[] concurrentErrors=new Throwable[2];
  concurrent.prefs.beforeRead=()->{captured.countDown();try{if(!continueLoad.await(5,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("selection capture barrier missing");}catch(InterruptedException error){throw new IllegalStateException(error);}};
  var lockField=AndroidNodeStore.class.getDeclaredField("STORE_LOCK");lockField.setAccessible(true);Object nodeLock=lockField.get(null);
  Thread loading=new Thread(()->{try{concurrent.store.load(selectedRow.id);}catch(Throwable error){concurrentErrors[0]=error;}},"profile-selection-admission");
  Thread choosing=new Thread(()->{try{ProductConnectSurface ui=new ProductConnectSurface(concurrent,true);ui.offer(concurrent.exits.get(imported.id),List.of(concurrent.second));ui.choose(0);ui.choose(1);if(ui.refreshes!=1)throw new IllegalStateException("independent Product selection failed: "+ui.message);}catch(Throwable error){concurrentErrors[1]=error;}},"actual-independent-Product");
  try{loading.start();check(captured.await(5,java.util.concurrent.TimeUnit.SECONDS),"whole selection was not captured");
   synchronized(nodeLock){continueLoad.countDown();long end=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(5);boolean admitted=false;while(loading.isAlive()&&System.nanoTime()<end){StackTraceElement[] stack=loading.getStackTrace();if(loading.getState()==Thread.State.BLOCKED&&stack.length>0&&stack[0].getClassName().equals("com.eabusham.routervpn.AndroidNodeStore")&&stack[0].getMethodName().equals("applyProfileBundle")){admitted=true;break;}Thread.yield();}check(admitted,"profile did not enter actual source admission");choosing.start();boolean blocked=false;end=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(5);while(choosing.isAlive()&&System.nanoTime()<end){StackTraceElement[] stack=choosing.getStackTrace();if(choosing.getState()==Thread.State.BLOCKED&&stack.length>0&&stack[0].getClassName().equals("com.eabusham.routervpn.AndroidConnectionProfileStore")){blocked=true;break;}Thread.yield();}check(blocked,"whole profile selection did not exclude the independent Product chooser");}
   loading.join(5000);choosing.join(5000);check(!loading.isAlive()&&!choosing.isAlive()&&concurrentErrors[0]==null&&concurrentErrors[1]==null,"whole selection owners did not join");check(concurrent.nodes.activeId().equals(concurrent.second.id)&&concurrent.prefs.getString("selected_id","").equals(concurrent.second.id)&&concurrent.prefs.getString("mode","").equals("hysteria2"),"profile left successor preferences and active node inconsistent");
  }finally{continueLoad.countDown();loading.join(5000);if(choosing.getState()!=Thread.State.NEW)choosing.join(5000);}
  Fixture normal=new Fixture(root);mixedSetup(normal,"shadowsocks");var normalRow=normal.store.add("Uncontested preference restore");normal.otherSelection();State before=new State(normal);normal.prefs.failures=1;Exception restored=rejected(()->normal.store.load(normalRow.id),"normal preference failure");before.same(normal,"original preferences");check(restored.getMessage().contains("prior connection state was restored"),"ordinary preference rollback no longer restores exactly");
 }
 static void profileApply(Path root)throws Exception{
  Fixture f=new Fixture(root);mixedSetup(f,"shadowsocks");var saved=f.store.add("Owned forward apply");f.changeNode(f.first);f.otherSelection();
  JSONObject newer=bundle(f.first);AndroidProfileSelection.selectedRouterProfile(newer).put("api_token","independent forward successor");byte[] successor=newer.toString().getBytes(StandardCharsets.UTF_8);
  var snapshot=new java.util.concurrent.CountDownLatch(1);var proceed=new java.util.concurrent.CountDownLatch(1);final Throwable[] failure={null};
  f.prefs.beforeRead=()->{snapshot.countDown();try{if(!proceed.await(5,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("profile snapshot barrier missing");}catch(InterruptedException error){throw new IllegalStateException(error);}};
  var field=AndroidNodeStore.class.getDeclaredField("STORE_LOCK");field.setAccessible(true);Object lock=field.get(null);
  Thread load=new Thread(()->{try{f.store.load(saved.id);}catch(Throwable error){failure[0]=error;}},"captured-profile-apply");
  try{load.start();check(snapshot.await(5,java.util.concurrent.TimeUnit.SECONDS),"profile did not retain original selection before apply");
   synchronized(lock){proceed.countDown();long end=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(5);boolean blocked=false;while(load.isAlive()&&System.nanoTime()<end){StackTraceElement[] stack=load.getStackTrace();if(load.getState()==Thread.State.BLOCKED&&stack.length>0&&stack[0].getClassName().equals("com.eabusham.routervpn.AndroidNodeStore")&&(stack[0].getMethodName().equals("importBundle")||stack[0].getMethodName().equals("applyProfileBundle"))){blocked=true;break;}Thread.yield();}check(blocked,"profile did not reach original node apply admission");new AndroidNodeStore(f.context).importBundle(successor);}
   load.join(5000);check(!load.isAlive(),"profile apply did not join");
   check(Arrays.equals(Files.readAllBytes(f.first.file.toPath()),successor),"profile forward apply overwrote the successor node credentials");
   check(f.nodes.activeId().equals(f.first.id)&&Arrays.equals(Files.readAllBytes(new File(f.context.getFilesDir(),AndroidNodeStore.ACTIVE_BUNDLE).toPath()),successor),"profile forward apply overwrote successor selection");
   check(failure[0]!=null,"profile accepted an obsolete original node source");
  }finally{proceed.countDown();load.join(5000);f.prefs.beforeRead=null;}
 }
 static void profileRollback(Path root)throws Exception{
  Fixture f=new Fixture(root);var entry=mixedSetup(f,"shadowsocks");var saved=f.store.add("Retained rollback");f.changeNode(f.first);f.otherSelection();
  final byte[][] successor={null};final Throwable[] editFailure={null};
  f.prefs.failures=1;f.prefs.beforeFailure=()->{
   Thread editor=new Thread(()->{try{JSONObject replacement=bundle(f.first);AndroidProfileSelection.selectedRouterProfile(replacement).put("api_token","successor private credential").put("dns_host","192.0.2.53");successor[0]=replacement.toString().getBytes(StandardCharsets.UTF_8);new AndroidNodeStore(f.context).importBundle(successor[0]);}catch(Throwable error){editFailure[0]=error;}},"independent-node-editor");
   editor.start();try{editor.join(5000);}catch(InterruptedException interrupted){throw new IllegalStateException(interrupted);}if(editor.isAlive()||editFailure[0]!=null)throw new IllegalStateException("successor edit did not join",editFailure[0]);
  };
  Exception failure=rejected(()->f.store.load(saved.id),"later selection failure");
  check(successor[0]!=null&&Arrays.equals(Files.readAllBytes(f.first.file.toPath()),successor[0]),"profile rollback overwrote the successor node credentials");
  check(f.nodes.activeId().equals(f.first.id)&&Arrays.equals(Files.readAllBytes(new File(f.context.getFilesDir(),AndroidNodeStore.ACTIVE_BUNDLE).toPath()),successor[0]),"profile rollback overwrote the successor active selection");
  check(failure.getMessage().contains("rollback is incomplete")&&failure.getSuppressed().length>0,"successor conflict was falsely reported as restored");
  Fixture retained=new Fixture(root);mixedSetup(retained,"shadowsocks");var retainedRow=retained.store.add("Retain failed rollback");retained.changeNode(retained.first);retained.otherSelection();byte[] originalNode=Files.readAllBytes(retained.first.file.toPath());final byte[][] applied={null};
  retained.prefs.failures=1;retained.prefs.beforeFailure=()->{try{applied[0]=Files.readAllBytes(retained.first.file.toPath());AndroidPrivateFileStore.beforeWrite=()->{throw new IllegalStateException("original rollback writer unavailable");};}catch(Exception error){throw new IllegalStateException(error);}};
  try{Exception pending=rejected(()->retained.store.load(retainedRow.id),"rollback writer failure");check(pending.getMessage().contains("rollback is incomplete")&&pending.getSuppressed().length>0,"rollback failure was hidden");check(applied[0]!=null&&!Arrays.equals(originalNode,applied[0])&&Arrays.equals(Files.readAllBytes(retained.first.file.toPath()),applied[0]),"failed rollback lost retained published bytes");}finally{AndroidPrivateFileStore.beforeWrite=null;}
  Fixture atomic=new Fixture(root);byte[] old=Files.readAllBytes(atomic.first.file.toPath());JSONObject proposed=bundle(atomic.first);AndroidProfileSelection.selectedRouterProfile(proposed).put("api_token","transaction candidate");byte[] ours=proposed.toString().getBytes(StandardCharsets.UTF_8);atomic.nodes.importBundle(ours);
  JSONObject next=new JSONObject(proposed.toString());AndroidProfileSelection.selectedRouterProfile(next).put("api_token","later independent editor");byte[] newer=next.toString().getBytes(StandardCharsets.UTF_8);
  var entered=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);var editorStarted=new java.util.concurrent.CountDownLatch(1);var once=new java.util.concurrent.atomic.AtomicBoolean(true);final Throwable[] errors=new Throwable[2];
  AndroidPrivateFileStore.beforeWrite=()->{if(once.compareAndSet(true,false)){entered.countDown();try{if(!release.await(5,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("rollback release missing");}catch(InterruptedException error){throw new IllegalStateException(error);}}};
  Thread restoring=new Thread(()->{try{atomic.nodes.restoreProfileBundle(atomic.first.id,old,ours);}catch(Throwable error){errors[0]=error;}});
  Thread editing=new Thread(()->{editorStarted.countDown();try{new AndroidNodeStore(atomic.context).importBundle(newer);}catch(Throwable error){errors[1]=error;}});
  try{restoring.start();check(entered.await(5,java.util.concurrent.TimeUnit.SECONDS),"restore never reached owned publication");editing.start();check(editorStarted.await(5,java.util.concurrent.TimeUnit.SECONDS),"competing editor did not start");long end=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(5);boolean blocked=false;while(editing.isAlive()&&System.nanoTime()<end){StackTraceElement[] stack=editing.getStackTrace();if(editing.getState()==Thread.State.BLOCKED&&stack.length>0&&stack[0].getClassName().equals("com.eabusham.routervpn.AndroidNodeStore")&&stack[0].getMethodName().equals("importBundle")){blocked=true;break;}Thread.yield();}release.countDown();restoring.join(5000);editing.join(5000);check(blocked,"node rollback compare and publication did not exclude the competing store");check(!restoring.isAlive()&&!editing.isAlive()&&errors[0]==null&&errors[1]==null,"atomic rollback/editor did not join");check(Arrays.equals(Files.readAllBytes(atomic.first.file.toPath()),newer),"atomic rollback erased the later committed edit");}finally{release.countDown();restoring.join(5000);if(editing.getState()!=Thread.State.NEW)editing.join(5000);AndroidPrivateFileStore.beforeWrite=null;}
  Fixture normal=new Fixture(root);mixedSetup(normal,"shadowsocks");var ordinary=normal.store.add("Exact rollback");normal.changeNode(normal.first);normal.otherSelection();State before=new State(normal);normal.prefs.failures=1;
  Exception restored=rejected(()->normal.store.load(ordinary.id),"ordinary exact rollback");before.same(normal,"original rollback");check(restored.getMessage().contains("prior connection state was restored"),"ordinary rollback was not recognized");
 }
 static void ordinaryTorRoundtrip(Path root)throws Exception{
  for(String protocol:List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn")){
   Fixture f=new Fixture(root);var entry=ordinary(protocol,"ordinary-"+protocol);f.exits.save(entry);var exit=f.exits.get("external-b");exit.startupMode="last";exit.autoConnect=true;exit.torPolicy.put("manual_mtu",1320);f.exits.save(exit);
   String originalEntry=AndroidStandardExitStore.snapshot(entry),originalExit=AndroidStandardExitStore.snapshot(exit),routerBytes=text(f.first.file);f.store.selectOrdinaryTorPath(exit,entry);var saved=f.store.add("Ordinary "+protocol+" to Tor");JSONObject row=f.row();
   check(f.rows().getInt("schema_version")==7&&row.getString("multihop_entry_kind").equals("external")&&row.getString("multihop_entry_mode").equals(AndroidExternalPolicy.protocol(protocol)),"ordinary schema/kind/canonical transport not captured");
   check(row.getJSONObject("ordinary_entry_policy").getInt("manual_mtu")==1360&&row.getJSONObject("external_policy").getInt("manual_mtu")==1320&&!row.has("entry_policy")&&!row.has("entry_profile_id"),"ordinary entry policy mixed with exit or private Router policy");
   String serialized=text(f.rows);for(String secret:List.of("fixture-api-","fixture-socks-","fixture-private-","openvpn_pairing","openvpn_response_probes","wg_private_key","tor_bridges","api_token"))check(!serialized.contains(secret),"ordinary profile copied private source: "+secret);
   for(String secret:List.of(entry.secret,entry.wgPrivateKey,entry.openVPNConfig))if(!secret.isEmpty())check(!serialized.contains(secret),"ordinary profile copied transport credentials");
   f.changeExternal(entry.id);f.changeExternal(exit.id);f.otherSelection();f.store.load(saved.id);var selected=f.store.currentExternalPath(exit.id);
   check(!selected.direct()&&selected.entry==null&&selected.ordinaryEntry.id.equals(entry.id)&&selected.entryMode.equals(AndroidExternalPolicy.protocol(protocol))&&selected.execution.equals("local"),"ordinary profile became Router/direct/another execution");
   check(originalEntry.equals(AndroidStandardExitStore.snapshot(selected.ordinaryEntry))&&originalExit.equals(AndroidStandardExitStore.snapshot(selected.exit)),"ordinary complete policies/startup/credentials did not restore separately");
   check(text(f.first.file).equals(routerBytes)&&f.nodes.activeId().equals(f.second.id),"ordinary load altered unrelated private Router owner");
   ProductConnectSurface ui=new ProductConnectSurface(f);ui.pressConnect();check(ui.connection.starts==1&&!ui.connection.direct&&ui.connection.entry==null&&ui.connection.ordinaryEntry.id.equals(entry.id)&&ui.connection.exit.id.equals(exit.id),"map Connect dropped loaded ordinary predecessor");
   f.store.selectExternalPath(f.exits.get(exit.id),null,"wg");f.store.update(saved.id,"Direct Tor");row=f.row();check(row.getString("multihop_entry_kind").equals("router-vpn")&&!row.has("ordinary_entry_policy"),"Update retained orphaned ordinary policy");
   f.otherSelection();f.store.load(saved.id);check(f.store.currentExternalPath(exit.id).direct(),"direct Update revived ordinary predecessor");f.store.delete(saved.id);check(f.store.list().isEmpty()&&f.exits.get(entry.id).id.equals(entry.id),"Delete removed linked ordinary credentials");
  }
  Fixture collision=new Fixture(root);var entry=ordinary("socks5",collision.first.id);collision.exits.save(entry);var exit=collision.exits.get("external-b");String router=text(collision.first.file);collision.store.selectOrdinaryTorPath(exit,entry);var saved=collision.store.add("Same text, separate identity");entry.password="current referenced password";entry.policy.put("manual_mtu",1400);collision.exits.save(entry);collision.otherSelection();collision.store.load(saved.id);var path=collision.store.currentExternalPath(exit.id);
  check(path.entry==null&&path.ordinaryEntry.id.equals(collision.first.id)&&path.ordinaryEntry.password.equals("current referenced password")&&path.ordinaryEntry.policy.getInt("manual_mtu")==1360&&text(collision.first.file).equals(router),"same-ID ordinary restore borrowed Router authority or replaced referenced credentials");
 }
 static void ordinaryTorInvalid(Path root)throws Exception{
  for(String bad:List.of("missing-kind","router-kind","unknown-kind","kind-type","missing-entry","same-id","wrong-mode","protocol","identity","entry-secret","entry-mtu","entry-policy","entry-startup","router-policy","home","server","compare","wrong-exit","downgraded-schema")){
   Fixture f=new Fixture(root);var entry=f.exits.get("external-a");var exit=f.exits.get("external-b");f.store.selectOrdinaryTorPath(exit,entry);var saved=f.store.add("Ordinary path");JSONObject row=f.row();
   switch(bad){case "missing-kind":row.remove("multihop_entry_kind");break;case "router-kind":row.put("multihop_entry_kind","router-vpn");break;case "unknown-kind":row.put("multihop_entry_kind","other");break;case "kind-type":row.put("multihop_entry_kind",true);break;
    case "missing-entry":row.put("multihop_entry_id","missing");break;case "same-id":row.put("multihop_entry_id",exit.id);break;case "wrong-mode":row.put("multihop_entry_mode","http-connect");break;case "protocol":row.put("ordinary_entry_protocol","http");break;case "identity":row.put("ordinary_entry_public_ip","203.0.113.10");break;
    case "entry-secret":row.getJSONObject("ordinary_entry_policy").put("password","wrong-owner");break;case "entry-mtu":row.getJSONObject("ordinary_entry_policy").put("manual_mtu",9001);break;case "entry-policy":row.put("ordinary_entry_policy",JSONObject.NULL);break;case "entry-startup":row.remove("ordinary_entry_startup");break;case "router-policy":row.put("entry_policy",new JSONObject().put("home_lan_access",true));break;
    case "home":row.getJSONObject("external_policy").put("dns_mode","home");break;case "server":row.put("multihop_execution","server");break;case "compare":row.put("multihop_execution","auto");break;case "wrong-exit":row.put("external_protocol","socks5").put("multihop_exit_mode","socks5");break;
   }
   f.row(row);if(bad.equals("downgraded-schema"))Files.writeString(f.rows.toPath(),f.rows().put("schema_version",4).toString());State before=new State(f);int writes=AndroidPrivateFileStore.writes;rejected(()->f.store.load(saved.id),bad);before.same(f,"ordinary invalid "+bad);check(writes==AndroidPrivateFileStore.writes,"invalid ordinary profile wrote before rejection: "+bad);
  }
 }
 static void ordinaryTorRollback(Path root)throws Exception{
  for(String fault:List.of("entry-write","exit-write","preferences","rollback")){
   Fixture f=new Fixture(root);f.store.selectOrdinaryTorPath(f.exits.get("external-b"),f.exits.get("external-a"));var saved=f.store.add("Ordinary transaction");f.changeExternal("external-a");f.changeExternal("external-b");f.otherSelection();State before=new State(f);
   if(fault.equals("preferences")||fault.equals("rollback"))f.prefs.failures=fault.equals("rollback")?2:1;
   else{AndroidPrivateFileStore.failPath=new File(f.context.getFilesDir(),"standard-exits.json").getAbsolutePath();if(fault.equals("entry-write"))AndroidPrivateFileStore.failures=1;else{var count=new java.util.concurrent.atomic.AtomicInteger();AndroidPrivateFileStore.beforeWrite=()->{if(count.incrementAndGet()==2)AndroidPrivateFileStore.failures=1;};}}
   try{Exception error=rejected(()->f.store.load(saved.id),fault);before.same(f,"ordinary two-row "+fault);check(error.getMessage().contains(fault.equals("rollback")?"rollback is incomplete":"prior connection state was restored"),"ordinary rollback status inaccurate");}
   finally{AndroidPrivateFileStore.failures=0;AndroidPrivateFileStore.failPath="";AndroidPrivateFileStore.beforeWrite=null;}
  }
  Fixture f=new Fixture(root);var entry=f.exits.get("external-a");var exit=f.exits.get("external-b");f.store.selectOrdinaryTorPath(exit,entry);var saved=f.store.add("Captured source");f.changeExternal(entry.id);f.changeExternal(exit.id);f.otherSelection();Map<String,?> preferences=f.prefs.getAll();
  AndroidTorProfile.afterOrdinaryValidation=()->{AndroidTorProfile.afterOrdinaryValidation=null;try{var current=f.exits.get(entry.id);current.password="concurrently edited private source";f.exits.save(current);}catch(Exception error){throw new IllegalStateException(error);}};
  try{rejected(()->f.store.load(saved.id),"source changed during pure graph validation");check(f.exits.get(entry.id).password.equals("concurrently edited private source")&&f.exits.get(entry.id).policy.getInt("manual_mtu")==1280&&preferences.equals(f.prefs.getAll()),"validation failure overwrote a newer ordinary source or selected stale path");}finally{AndroidTorProfile.afterOrdinaryValidation=null;}
  State before=new State(f);f.prefs.failures=1;rejected(()->f.store.selectOrdinaryTorPath(f.exits.get(exit.id),f.exits.get(entry.id)),"ordinary selection commit failure");before.same(f,"ordinary selection rollback");
  var stale=f.exits.get(entry.id);var changed=f.exits.get(entry.id);changed.password="later private source";f.exits.save(changed);before=new State(f);rejected(()->f.store.selectOrdinaryTorPath(f.exits.get(exit.id),stale),"stale ordinary selection source");before.same(f,"stale ordinary selection");
 }
 static void ordinarySchemaMigration(Path root)throws Exception{
  for(int schema:new int[]{2,3,4,5,6}){Fixture f=new Fixture(root);f.store.selectExternalPath(f.exits.get("external-b"),f.first,"wg");var saved=f.store.add("Legacy private entry");JSONObject rows=f.rows();rows.put("schema_version",schema);rows.getJSONArray("profiles").getJSONObject(0).remove("multihop_entry_kind");Files.writeString(f.rows.toPath(),rows.toString());f.otherSelection();f.store.load(saved.id);var path=f.store.currentExternalPath("external-b");check(f.rows().getInt("schema_version")==7&&path.ordinaryEntry==null&&path.entry.id.equals(f.first.id),"legacy Router entry was reinterpreted during schema migration");}
  Fixture future=new Fixture(root);future.store.add("Future schema");Files.writeString(future.rows.toPath(),future.rows().put("schema_version",8).toString());State before=new State(future);rejected(()->future.store.list(),"future profile schema");before.same(future,"future schema must not rewrite");
 }
 static void externalRoundtrip(Path root,boolean tor)throws Exception{
  Fixture f=new Fixture(root);String exit=tor?"external-b":"external-a";f.store.selectExternalPath(f.exits.get(exit),f.first,"hysteria2");
  AndroidConnectionProfileStore.Record r=f.store.add("Entry + "+exit);JSONObject row=f.row();String serialized=text(f.rows);
  for(String secret:List.of("fixture-api-","fixture-socks-","fixture-private-","api_token","wg_private_key","password","tor_bridge"))check(!serialized.contains(secret),"profile copied secret "+secret);
  check(row.getString("node_id").equals(exit)&&row.getString("multihop_entry_id").equals(f.first.id),"saved references");
  check(row.getJSONObject("entry_policy").getString("start_layer").equals("aes-256-gcm+xor-whitening"),"entry Start Layer captured");
  String beforeExit=AndroidStandardExitStore.snapshot(f.exits.get(exit));f.changeNode(f.first);f.changeExternal(exit);f.otherSelection();f.store.load(r.id);
  check(AndroidStandardExitStore.snapshot(f.exits.get(exit)).equals(beforeExit),"exact external policy restored with same credentials");
  check(profile(f.first).getString("start_layer").equals("aes-256-gcm+xor-whitening")&&profile(f.first).getString("api_token").equals("fixture-api-first"),"entry policy restored without replacing credentials");
  check(f.nodes.activeId().equals(f.second.id)&&text(new File(f.context.getFilesDir(),AndroidNodeStore.ACTIVE_BUNDLE)).equals(text(f.second.file)),"external selection preserves prior active Router and its bytes");
  var path=f.store.currentExternalPath(exit);check(!path.direct()&&path.entry.id.equals(f.first.id)&&path.entryMode.equals("hysteria2")&&path.exit.id.equals(exit),"main Connect resolves exact loaded external path");
  ProductConnectSurface surface=new ProductConnectSurface(f);surface.pressConnect();check(surface.connection.starts==1&&!surface.connection.direct&&surface.connection.entry.id.equals(f.first.id)&&surface.connection.exit.id.equals(exit)&&surface.connection.mode.equals("hysteria2"),"shipping map Connect dispatches saved graph and exact credentials");
  AndroidViaEntryLatencyProbe.active=true;int canceled=AndroidViaEntryLatencyProbe.cancellations;ProductConnectSurface recreated=new ProductConnectSurface(f);recreated.pressConnect();AndroidViaEntryLatencyProbe.active=false;check(recreated.connection.starts==0&&AndroidViaEntryLatencyProbe.cancellations==canceled+1,"recreated map cancels only the owned candidate operation before any connection dispatch");
  State beforeComparison=new State(f);int comparisons=AndroidExternalNodeComparison.cancellations,candidates=AndroidViaEntryLatencyProbe.cancellations;AndroidExternalNodeComparison.active=true;
  try{
   ProductConnectSurface recreatedComparison=new ProductConnectSurface(f);recreatedComparison.pressConnect();
   check(recreatedComparison.connection.starts==0&&AndroidExternalNodeComparison.cancellations==comparisons+1,"recreated map must cancel the active external comparison before connection dispatch");
   check(AndroidViaEntryLatencyProbe.cancellations==candidates,"external comparison cancellation reached the unrelated candidate operation");
   beforeComparison.same(f,"external comparison cancellation preserves saved path and private sources");
  }finally{AndroidExternalNodeComparison.active=false;}
  f.store.selectExternalPath(f.exits.get(exit),null,"wg");f.store.update(r.id,"Direct "+exit);check(f.store.list().size()==1&&f.store.list().get(0).name.equals("Direct "+exit),"Update preserves profile ID/count");f.otherSelection();f.store.load(r.id);check(f.store.currentExternalPath(exit).direct()&&!f.prefs.getBoolean("multihop_on",true),"direct Update/Load clears old hops");surface=new ProductConnectSurface(f);surface.pressConnect();check(surface.connection.starts==1&&surface.connection.direct&&surface.connection.entry==null&&surface.connection.exit.id.equals(exit),"shipping map Connect dispatches direct saved external path");f.store.delete(r.id);check(f.store.list().isEmpty(),"Delete external profile");
 }
 static void externalExecution(Path root)throws Exception{
  for(String protocol:List.of("wireguard","amneziawg","shadowsocks","hysteria2","socks5","http","https"))for(String layer:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))for(String execution:List.of("local","server","auto")){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry exit=external("paired-"+protocol,false);exit.protocol=protocol;exit.tlsServerName="exit.example.test";exit.method="2022-blake3-aes-256-gcm";exit.secret=Base64.getEncoder().encodeToString(new byte[32]);exit.responseProbe=new JSONObject().put("url","https://198.51.100.8:8443/response").put("server_name","paired.example.test");
   boolean packet=AndroidStandardExitStore.packetExecutionProtocol(protocol);if(packet){exit.wgPrivateKey=Base64.getEncoder().encodeToString("x".repeat(32).getBytes(StandardCharsets.UTF_8));exit.wgPeerPublicKey=Base64.getEncoder().encodeToString("p".repeat(32).getBytes(StandardCharsets.UTF_8));exit.wgAddresses.addAll(List.of("10.93.0.2/32","fd93::2/128"));exit.wgAllowedIps.addAll(List.of("0.0.0.0/0","::/0"));exit.wgMtu=1280;exit.wgKeepalive=25;exit.serverPeer=new JSONObject().put("public_key","bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg=").put("addresses",new JSONArray().put("10.94.0.3/32").put("fd94::3/128")).put("mtu",1360).put("persistent_keepalive_interval",25);if(protocol.equals("amneziawg"))exit.awgParameters=new JSONObject().put("jc","3").put("jmin","40").put("jmax","900").put("s1","15").put("s2","16").put("s3","32").put("s4","32").put("h1","100-110").put("h2","200-210").put("h3","300-310").put("h4","400-410");}
   if(!layer.equals("off")){exit.policy.put("start_layer",layer);exit.startLayer=new JSONObject().put("mode",layer).put("api","http://10.99.0.1:8787").put("transport",new JSONObject().put("type","shadowsocks").put("tag","provisioned-exit-layer").put("server",exit.server).put("server_port",8388).put("method","2022-blake3-aes-256-gcm").put("password",Base64.getEncoder().encodeToString("L".repeat(32).getBytes(StandardCharsets.UTF_8))));}f.exits.save(exit);
   f.store.selectExternalPath(exit,f.first,"hysteria2",execution);var saved=f.store.add("paired execution");String secret=exit.secret;check(!text(f.rows).contains(secret)&&!text(f.rows).contains("response_probe"),"connection choices duplicated private node material");
   if(!layer.equals("off"))check(!text(f.rows).contains(exit.startLayer.getJSONObject("transport").getString("password"))&&!text(f.rows).contains("10.99.0.1")&&f.store.list().get(0).startLayer.equals(layer),"saved layer choice leaked its private provisioned transport");
   f.otherSelection();f.store.load(saved.id);var selected=f.store.currentExternalPath(exit.id);check(selected.execution.equals(execution)&&selected.entry.id.equals(f.first.id),"profile load discarded external execution choice");
   if(packet)check(selected.exit.serverPeer.toString().equals(exit.serverPeer.toString())&&selected.exit.wgPrivateKey.equals(exit.wgPrivateKey)&&!text(f.rows).contains("server_peer")&&!text(f.rows).contains(exit.wgPrivateKey),"connection profile changed packet descriptor or duplicated private node material");
   ProductConnectSurface surface=new ProductConnectSurface(f);surface.pressConnect();check(surface.connection.starts==1&&surface.connection.execution.equals(execution),"main Connect discarded external execution");
   AndroidStandardExitStore.Entry copied=AndroidStandardExitStore.copy(exit);copied.responseProbe.put("url","https://198.51.100.8/changed");check(!copied.responseProbe.toString().equals(exit.responseProbe.toString()),"response endpoint aliases saved credentials");
   if(packet){copied.serverPeer.put("mtu",1400);check(exit.serverPeer.getInt("mtu")==1360&&f.exits.get(exit.id).serverPeer.getInt("mtu")==1360,"saved packet peer aliases temporary profile owner");}
   if(!execution.equals("local")){State before=new State(f);rejected(()->f.store.selectExternalPath(exit,null,"wg",execution),"direct path server owner");before.same(f,"direct execution rejection");}
   if(!layer.equals("off")){
    AndroidStandardExitStore.Entry changed=AndroidStandardExitStore.copy(exit);String other=layer.equals("aes-256-gcm")?"aes-256-gcm+xor-whitening":"aes-256-gcm";changed.policy.put("start_layer",other);changed.startLayer.put("mode",other);f.exits.save(changed);
    State before=new State(f);rejected(()->f.store.load(saved.id),"saved choice cannot replace a different provisioned private layer");before.same(f,"mismatched layer profile restoration");
   }
  }
 }
 static void torExecutionProfiles(Path root)throws Exception{
  for(String protocol:List.of("tor","tor-bridge"))for(String execution:List.of("local","server","auto")){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry exit=f.exits.get("external-b");exit.protocol=protocol;if(protocol.equals("tor")){exit.torBridges.clear();exit.torTransport="";}f.exits.save(exit);
   f.store.selectExternalPath(exit,f.first,"hysteria2",execution);var saved=f.store.add("Captured Tor "+execution);String source=AndroidStandardExitStore.snapshot(exit);
   for(String secret:List.of("fixture-api-","fixture-socks-","fixture-private-","api_token","tor_bridge"))check(!text(f.rows).contains(secret),"Tor connection profile duplicated private source material");
   f.changeNode(f.first);f.changeExternal(exit.id);f.otherSelection();f.store.load(saved.id);var selected=f.store.currentExternalPath(exit.id);
   check(selected.execution.equals(execution)&&selected.entry.id.equals(f.first.id)&&selected.entryMode.equals("hysteria2")&&source.equals(AndroidStandardExitStore.snapshot(selected.exit)),"complete Tor profile lost execution, DNS or source");
   check(profile(f.first).getString("api_token").equals("fixture-api-first")&&profile(f.first).getString("start_layer").equals("aes-256-gcm+xor-whitening"),"Tor restoration mixed private entry credentials or Start Layer");
   ProductConnectSurface surface=new ProductConnectSurface(f);surface.pressConnect();check(surface.connection.starts==1&&surface.connection.execution.equals(execution)&&surface.connection.entry.id.equals(f.first.id),"map Connect replaced the saved Tor execution");
  }
 }
 static void torPaddingProfiles(Path root)throws Exception{
  for(boolean enabled:new boolean[]{false,true})for(int rate:new int[]{0,32,64,192}){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry exit=f.exits.get("external-b");exit.torPolicy.put("daita_enabled",enabled).put("daita_rate_kbps",rate);f.exits.save(exit);
   f.store.selectExternalPath(exit,f.first,"hysteria2","server");var saved=f.store.add("Bounded outgoing cover");JSONObject policy=f.row().getJSONObject("external_policy");
   check(policy.getBoolean("daita_enabled")==enabled&&policy.getInt("daita_rate_kbps")==rate,"Add lost enabled or dormant Tor cover rate");
   exit.torPolicy.put("daita_enabled",!enabled).put("daita_rate_kbps",96);f.exits.save(exit);f.otherSelection();f.store.load(saved.id);
   var path=f.store.currentExternalPath(exit.id);check(path.execution.equals("server")&&path.entry.id.equals(f.first.id)&&path.exit.torPolicy.getBoolean("daita_enabled")==enabled&&path.exit.torPolicy.getInt("daita_rate_kbps")==rate,"Load changed exact cover policy or private Server path");
   f.store.update(saved.id,"Retained cover");check(f.row().getJSONObject("external_policy").getInt("daita_rate_kbps")==rate&&f.store.list().size()==1,"Update discarded the selected cover rate");
   String before=AndroidStandardExitStore.snapshot(f.exits.get(exit.id));f.store.delete(saved.id);check(f.store.list().isEmpty()&&AndroidStandardExitStore.snapshot(f.exits.get(exit.id)).equals(before),"Delete removed the node-owned cover policy");
  }
  for(String fault:new String[]{"enabled-type","rate-type","rate-small","rate-large"}){
   Fixture f=new Fixture(root);var exit=f.exits.get("external-b");exit.torPolicy.put("daita_enabled",true).put("daita_rate_kbps",64);f.exits.save(exit);f.store.selectExternalPath(exit,f.first,"hysteria2","server");var saved=f.store.add("Valid cover");JSONObject row=f.row(),policy=row.getJSONObject("external_policy");
   if(fault.equals("enabled-type"))policy.put("daita_enabled","true");else if(fault.equals("rate-type"))policy.put("daita_rate_kbps","64");else policy.put("daita_rate_kbps",fault.equals("rate-small")?31:193);
   f.row(row);State before=new State(f);rejected(()->f.store.load(saved.id),fault);before.same(f,"invalid cover restore must be transactional");
  }
 }
 static void mappedOpenVPNProfiles(Path root)throws Exception{
  for(String layer:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening")){
  String variable=layer.equals("off")?"ROUTERVPN_OPENVPN_MULTIHOST_CLIENT_FIXTURE":layer.equals("aes-256-gcm")?"ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_AES_FIXTURE":"ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_XOR_FIXTURE";JSONObject source=new JSONObject(Files.readString(Path.of(System.getenv(variable)))).getJSONObject("external"),inline=source.getJSONObject("openvpn");
  for(String execution:List.of("local","server","auto")){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry exit=external("mapped-openvpn",false);exit.protocol="openvpn";exit.openVPNConfig=inline.getString("config");exit.username=inline.getString("username");exit.password=inline.getString("password");exit.expectedPublicIp=source.getString("expected_public_ip");exit.openVPNPairing=new JSONObject(source.getJSONObject("openvpn_pairing").toString());exit.openVPNResponseProbes=new JSONObject(source.getJSONObject("openvpn_response_probes").toString());exit.policy.put("start_layer",layer);if(!layer.equals("off"))exit.openVPNStartLayers=new JSONObject(source.getJSONObject("openvpn_start_layers").toString());f.exits.save(exit);f.store.selectExternalPath(exit,f.first,"hysteria2",execution);var saved=f.store.add("Mapped OpenVPN");
   String rows=text(f.rows);check(!rows.contains("openvpn_start_layers")&&!rows.contains("10.93.0.1")&&!rows.contains("openvpn_response_probes")&&!rows.contains("openvpn_pairing")&&!rows.contains(exit.openVPNConfig)&&!rows.contains(exit.openVPNPairing.getString("private_key")),"complete connection profile duplicated private OpenVPN transport or map");
   String frozen=AndroidStandardExitStore.snapshot(exit);f.changeExternal(exit.id);f.otherSelection();f.store.load(saved.id);var selected=f.store.currentExternalPath(exit.id);check(selected.execution.equals(execution)&&selected.entry.id.equals(f.first.id)&&selected.entryMode.equals("hysteria2")&&AndroidStandardExitStore.snapshot(selected.exit).equals(frozen),"complete profile lost mapped OpenVPN policy, exact entry, execution or private references");
   ProductConnectSurface surface=new ProductConnectSurface(f);surface.pressConnect();check(surface.connection.starts==1&&surface.connection.execution.equals(execution)&&surface.connection.exit.openVPNResponseProbes.toString().equals(exit.openVPNResponseProbes.toString())&&surface.connection.exit.openVPNPairing.toString().equals(exit.openVPNPairing.toString()),"main Connect substituted mapped OpenVPN private owner after profile Load");
   check(surface.connection.exit.policy.getString("start_layer").equals(layer)&&java.util.Objects.equals(surface.connection.exit.openVPNStartLayers==null?null:surface.connection.exit.openVPNStartLayers.toString(),exit.openVPNStartLayers==null?null:exit.openVPNStartLayers.toString()),"complete profile changed exact mapped layer selection or keys");
   AndroidStandardExitStore.Entry copy=AndroidStandardExitStore.copy(selected.exit);String host=copy.openVPNResponseProbes.names().getString(0);copy.openVPNResponseProbes.getJSONObject(host).put("url","https://"+host+"/rotated-private-probe");if(copy.openVPNStartLayers!=null)copy.openVPNStartLayers.getJSONObject(host).getJSONObject("transport").put("password",Base64.getEncoder().encodeToString("r".repeat(32).getBytes(StandardCharsets.UTF_8)));f.exits.save(copy);f.otherSelection();f.store.load(saved.id);check(f.store.currentExternalPath(exit.id).exit.openVPNResponseProbes.toString().equals(copy.openVPNResponseProbes.toString()),"saved profile overwrote its linked node's newer private response map");check(java.util.Objects.equals(f.store.currentExternalPath(exit.id).exit.openVPNStartLayers==null?null:f.store.currentExternalPath(exit.id).exit.openVPNStartLayers.toString(),copy.openVPNStartLayers==null?null:copy.openVPNStartLayers.toString()),"saved profile replaced current linked node layer credentials");
   if(!execution.equals("local")){State before=new State(f);rejected(()->f.store.selectExternalPath(copy,null,"wg",execution),"mapped direct cannot own Server execution");before.same(f,"mapped direct rejection");}
   f.store.delete(saved.id);check(f.store.list().isEmpty()&&f.exits.get(exit.id).openVPNResponseProbes.toString().equals(copy.openVPNResponseProbes.toString()),"Delete removed another private node or retained the complete profile");
  }}
 }
 static void externalDefaultHome(Path root)throws Exception{
  for(boolean tor:new boolean[]{false,true})for(String mode:List.of("missing","","home")){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry exit=f.exits.get(tor?"external-b":"external-a");JSONObject policy=new JSONObject();if(!mode.equals("missing"))policy.put("dns_mode",mode);if(tor)exit.torPolicy=policy;else exit.policy=policy;f.exits.save(exit);
   String original=AndroidStandardExitStore.snapshot(exit);State before=new State(f);rejected(()->f.store.selectExternalPath(exit,null,"wg"),"implicit Home without captured entry");before.same(f,"implicit Home selection rejection");
   f.store.selectExternalPath(exit,f.first,"wg");var record=f.store.add("Default Home");f.otherSelection();f.store.load(record.id);
   check(!f.store.currentExternalPath(exit.id).direct()&&f.store.currentExternalPath(exit.id).entry.id.equals(f.first.id),"default Home lost its captured entry");check(original.equals(AndroidStandardExitStore.snapshot(f.exits.get(exit.id))),"profile restoration rewrote missing/blank Home or transport credentials");
  }
 }
 static void externalStartup(Path root)throws Exception{
  for(boolean tor:new boolean[]{false,true}){Fixture f=new Fixture(root);String id=tor?"external-b":"external-a";AndroidStandardExitStore.Entry exit=f.exits.get(id);exit.startupMode="last";exit.autoConnect=true;f.exits.save(exit);f.store.selectExternalPath(exit,f.first,"wg");var r=f.store.add("Startup profile");JSONObject row=f.row();check(row.getJSONObject("external_startup").getString("startup_mode").equals("last")&&row.getJSONObject("external_startup").getBoolean("auto_connect"),"external startup missing from connection profile");exit.startupMode="manual";exit.autoConnect=false;f.exits.save(exit);f.otherSelection();f.store.load(r.id);AndroidStandardExitStore.Entry loaded=f.exits.get(id);check(loaded.startupMode.equals("last")&&loaded.autoConnect,"connection profile did not restore external startup choice");
   JSONObject bad=f.row();bad.getJSONObject("external_startup").put("auto_connect","true");f.row(bad);State before=new State(f);rejected(()->f.store.load(r.id),"typed external startup");before.same(f,"invalid external startup did not mutate selection or credentials");
  }
 }
 static void torJumboProfiles(Path root)throws Exception{
  for(String mode:new String[]{"default","auto","fixed","manual"}){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry exit=f.exits.get("external-b");exit.torPolicy.put("mtu_policy",mode).put("jumbo_tun",true).put("manual_mtu",9000);f.exits.save(exit);f.store.selectExternalPath(exit,f.first,"hysteria2");
   String exact=AndroidStandardExitStore.snapshot(f.exits.get(exit.id));var saved=f.store.add("Tor Jumbo "+mode);JSONObject captured=f.row().getJSONObject("external_policy");
   check(captured.getBoolean("jumbo_tun")&&captured.getString("mtu_policy").equals(mode)&&captured.getInt("manual_mtu")==9000,"connection profile omitted Tor Jumbo or its saved MTU choice");
   AndroidStandardExitStore.Entry changed=f.exits.get(exit.id);changed.torPolicy.put("jumbo_tun",false).put("mtu_policy","auto");f.exits.save(changed);f.otherSelection();f.store.load(saved.id);
   check(exact.equals(AndroidStandardExitStore.snapshot(f.exits.get(exit.id))),"connection profile restored capacity with different credentials or DNS");
   JSONObject invalid=f.row();invalid.getJSONObject("external_policy").put("mtu_policy","fixed").put("manual_mtu",1420);f.row(invalid);State before=new State(f);
   rejected(()->f.store.load(saved.id),"Tor Jumbo and Fixed conflict");before.same(f,"Tor Jumbo conflict must reject transaction before mutation");
   invalid.getJSONObject("external_policy").put("manual_mtu",9000).put("jumbo_tun","true");f.row(invalid);before=new State(f);rejected(()->f.store.load(saved.id),"typed Tor Jumbo choice");before.same(f,"wrong Jumbo type must preserve private nodes");
  }
 }
 static void setRouterRate(Fixture f,AndroidNodeStore.Node node,Object rate,String token,boolean enabled)throws Exception{
  JSONObject bundle=bundle(node),profile=AndroidProfileSelection.selectedRouterProfile(bundle);
  if(rate==null)profile.remove("daita_rate_kbps");else profile.put("daita_rate_kbps",rate);
  profile.put("api_token",token).put("daita_enabled",enabled);
  f.nodes.importBundle(bundle.toString().getBytes(StandardCharsets.UTF_8));
 }
 static void routerRateProfiles(Path root)throws Exception{
  for(Integer rate:new Integer[]{null,0,32,64,192})for(boolean enabled:new boolean[]{false,true}){
   Fixture f=new Fixture(root);Integer exitRate=rate==null?64:null;
   setRouterRate(f,f.first,rate,"entry-old-private",enabled);setRouterRate(f,f.second,exitRate,"exit-old-private",enabled);f.nodes.select(f.first.id);
   f.prefs.edit().putBoolean("multihop_on",true).putString("multihop_entry",f.first.id).putString("multihop_exit",f.second.id).putString("multihop_exit_mode","hysteria2").putString("multihop_entry_mode","wg").putString("multihop_execution","local").commit();
   var saved=f.store.add("Captured Router rates");JSONObject row=f.row();
   for(String key:List.of("policy","entry_policy","exit_policy")){
    JSONObject policy=row.getJSONObject(key);Integer wanted=key.equals("exit_policy")?exitRate:rate;
    check(policy.has("daita_rate_kbps")&&(wanted==null?policy.isNull("daita_rate_kbps"):policy.getInt("daita_rate_kbps")==wanted),"Add omitted Router rate or captured default: "+key);
   }
   check(!row.toString().contains("entry-old-private")&&!row.toString().contains("exit-old-private"),"rate capture copied linked credentials");
   String entryAssets=bundle(f.first).getJSONObject("profiles").toString(),exitAssets=bundle(f.second).getJSONObject("profiles").toString();
   setRouterRate(f,f.first,128,"entry-current-private",!enabled);setRouterRate(f,f.second,160,"exit-current-private",!enabled);f.otherSelection();f.store.load(saved.id);
   JSONObject restoredEntry=profile(f.first),restoredExit=profile(f.second);
   check(rate==null?!restoredEntry.has("daita_rate_kbps"):restoredEntry.getInt("daita_rate_kbps")==rate,"Load did not restore entry rate/default");
   check(exitRate==null?!restoredExit.has("daita_rate_kbps"):restoredExit.getInt("daita_rate_kbps")==exitRate,"Load did not restore independent exit rate/default");
   check(restoredEntry.getBoolean("daita_enabled")==enabled&&restoredExit.getBoolean("daita_enabled")==enabled,"saved dormant rate changed padding enablement");
   check(restoredEntry.getString("api_token").equals("entry-current-private")&&restoredExit.getString("api_token").equals("exit-current-private"),"rate restore replaced current linked credentials");
   check(entryAssets.equals(bundle(f.first).getJSONObject("profiles").toString())&&exitAssets.equals(bundle(f.second).getJSONObject("profiles").toString()),"rate restore replaced private protocol assets");
   check(f.nodes.activeId().equals(f.first.id)&&f.prefs.getString("selected_id","").equals(f.first.id)&&f.prefs.getBoolean("multihop_on",false),"rate restore changed selected path identity");
   setRouterRate(f,f.first,96,"entry-current-private",false);setRouterRate(f,f.second,48,"exit-current-private",false);f.nodes.select(f.first.id);f.store.update(saved.id,"Updated independent rates");
   setRouterRate(f,f.first,144,"entry-newer-private",true);setRouterRate(f,f.second,176,"exit-newer-private",true);f.otherSelection();f.store.load(saved.id);
   check(profile(f.first).getInt("daita_rate_kbps")==96&&profile(f.second).getInt("daita_rate_kbps")==48,"Update did not capture independent Router rates");
   check(!profile(f.first).getBoolean("daita_enabled")&&!profile(f.second).getBoolean("daita_enabled")&&profile(f.first).getString("api_token").equals("entry-newer-private")&&profile(f.second).getString("api_token").equals("exit-newer-private"),"Update/Load changed dormant state or current credentials");
   row=f.row();for(String key:List.of("policy","entry_policy","exit_policy"))row.getJSONObject(key).remove("daita_rate_kbps");f.row(row);
   setRouterRate(f,f.first,128,"entry-newer-private",false);setRouterRate(f,f.second,160,"exit-newer-private",false);f.otherSelection();f.store.load(saved.id);
   check(profile(f.first).has("daita_rate_kbps")&&profile(f.second).has("daita_rate_kbps")&&profile(f.first).getInt("daita_rate_kbps")==128&&profile(f.second).getInt("daita_rate_kbps")==160,"legacy uncaptured rate was deleted or overwritten");
  }
  for(Object invalid:List.of(-1,31,193,64.5,true,"64")){
   Fixture f=new Fixture(root);var saved=f.store.add("Valid default");JSONObject row=f.row();row.getJSONObject("policy").put("daita_rate_kbps",invalid);f.row(row);State before=new State(f);
   rejected(()->f.store.load(saved.id),"invalid saved Router rate "+invalid);before.same(f,"invalid rate rejected before mutation");
  }
  for(Object invalid:List.of(-1,31,193,64.5,true,"64",JSONObject.NULL)){
   Fixture f=new Fixture(root);setRouterRate(f,f.first,invalid,"unchanged-private",true);f.nodes.select(f.first.id);State before=new State(f);
   rejected(()->f.store.add("Invalid runtime rate"),"invalid source Router rate "+invalid);before.same(f,"invalid source rate never wrote profile");
  }
 }
 static void routerRoundtrip(Path root)throws Exception{
  Fixture f=new Fixture(root);f.prefs.edit().putString("mode","custom:captured").putString("custom_presets","[{\"name\":\"captured\",\"layers\":[\"hysteria2\",\"shadowsocks\"]}]").putBoolean("multihop_on",true).putString("multihop_entry",f.first.id).putString("multihop_exit",f.second.id).putString("multihop_exit_mode","hysteria2").putString("multihop_execution","auto").putString("multihop_entry_mode","wg").commit();
  var r=f.store.add("Router graph");f.changeNode(f.first);f.changeNode(f.second);f.otherSelection();f.store.load(r.id);
  check(f.nodes.activeId().equals(f.first.id)&&profile(f.first).getBoolean("auto_require_encrypted")&&profile(f.second).getBoolean("auto_require_encrypted"),"Router entry and exit policy restored");
  check(f.prefs.getString("multihop_execution","").equals("auto")&&f.prefs.getString("mode","").equals("custom:captured")&&f.prefs.getString("custom_presets","").contains("captured")&&f.prefs.getString("custom_presets","").contains("other"),"Compare and CUSTOM restored without deleting unrelated presets");
  check(text(new File(f.context.getFilesDir(),AndroidNodeStore.ACTIVE_BUNDLE)).equals(text(f.first.file)),"selected Router bytes consistent");
 }
 static void routerLegacyPolicy(Path root)throws Exception{
  Fixture f=new Fixture(root);var r=f.store.add("Router defaults");JSONObject changed=bundle(f.first);AndroidProfileSelection.selectedRouterProfile(changed).put("startup_mode","manual").put("auto_connect",true);f.nodes.importBundle(changed.toString().getBytes(StandardCharsets.UTF_8));f.store.load(r.id);check(!profile(f.first).has("startup_mode")&&!profile(f.first).has("auto_connect"),"complete capture restores omitted choices to defaults");
  JSONObject old=f.row();old.remove("node_profile_id");old.getJSONObject("policy").remove("home_lan_cidrs");f.row(old);String ranges=profile(f.first).getJSONArray("home_lan_cidrs").toString();f.store.load(r.id);check(profile(f.first).getJSONArray("home_lan_cidrs").toString().equals(ranges),"legacy row preserves expanded fields it never captured");
 }
 static void rollback(Path root,String fault)throws Exception{
  Fixture f=new Fixture(root);f.store.selectExternalPath(f.exits.get("external-a"),f.first,"wg");var r=f.store.add("saved");f.changeNode(f.first);f.changeExternal("external-a");f.otherSelection();State before=new State(f);
  if(fault.equals("preferences")||fault.equals("rollback"))f.prefs.failures=fault.equals("rollback")?2:1;
  else{AndroidPrivateFileStore.failPath=fault.equals("external")?new File(f.context.getFilesDir(),"standard-exits.json").getAbsolutePath():f.first.file.getAbsolutePath();AndroidPrivateFileStore.failures=1;}
  Exception error=rejected(()->f.store.load(r.id),fault);before.same(f,fault);check(error.getMessage().contains(fault.equals("rollback")?"rollback is incomplete":"prior connection state was restored"),"accurate rollback report "+fault);
  AndroidPrivateFileStore.failures=0;AndroidPrivateFileStore.failPath="";
 }
 static void invalidBeforeMutation(Path root)throws Exception{
  for(String bad:List.of("missing-entry","missing-exit","server","wrong-mode","protocol-change","public-change","foreign-policy","bad-type","mtu","fractional-mtu","null-policy","null-identity","bad-cidr-type","bootstrap-secret","conflicting-router")){
   Fixture f=new Fixture(root);f.store.selectExternalPath(f.exits.get("external-a"),f.first,"wg");var r=f.store.add("saved");JSONObject row=f.row();
   switch(bad){case "missing-entry":row.put("multihop_entry_id","0".repeat(32));break;case "missing-exit":row.put("node_id","missing");break;
    case "server":row.put("multihop_execution","server");break;case "wrong-mode":row.put("multihop_entry_mode","reality-xhttp");break;
    case "protocol-change":row.put("external_protocol","http");break;case "public-change":row.put("external_public_ip","203.0.113.10");break;
    case "foreign-policy":row.getJSONObject("external_policy").put("password","not-a-policy");break;case "bad-type":row.getJSONObject("external_policy").put("home_lan_access","false");break;
    case "mtu":row.getJSONObject("external_policy").put("manual_mtu",9001);break;case "fractional-mtu":row.getJSONObject("external_policy").put("manual_mtu",1360.5);break;
    case "null-policy":row.put("entry_policy",JSONObject.NULL);break;case "null-identity":row.put("external_protocol",JSONObject.NULL);break;case "bad-cidr-type":row.getJSONObject("external_policy").put("home_lan_cidrs",new JSONArray().put(new JSONObject().put("password","secret")));break;
    case "bootstrap-secret":row.getJSONObject("external_policy").put("dns_bootstrap",new JSONObject().put("server",new JSONObject().put("tag","dns").put("password","secret")).put("query",new JSONObject().put("server","dns")));break;
    default:row.put("node_kind","router-vpn").put("node_id",f.first.id).put("mode","smart-auto").put("multihop_exit_id",f.second.id).put("multihop_exit_mode","hysteria2").put("policy",new JSONObject().put("start_layer","off"));row.remove("external_policy");
   }
   f.row(row);State before=new State(f);int writes=AndroidPrivateFileStore.writes;rejected(()->f.store.load(r.id),bad);before.same(f,bad);check(AndroidPrivateFileStore.writes==writes,"invalid profile mutated before rejection: "+bad);
  }
 }
 static void evidenceAndLegacy(Path root)throws Exception{
  Fixture f=new Fixture(root);var exit=f.exits.get("external-a");exit.policy.put("fastest_dns_host","9.9.9.9").put("fastest_dns_latency_ms",4.5).put("dns_results",new JSONArray().put(new JSONObject().put("name","Quad9").put("address","9.9.9.9").put("family","IPv4").put("working",true).put("latency_ms",4.5))).put("effective_mtu",9000)
   .put("dns_bootstrap",new JSONObject().put("server",new JSONObject().put("type","tls").put("tag","bootstrap").put("server","9.9.9.9").put("server_port",8853).put("detour","custom-exit").put("tls",new JSONObject().put("enabled",true).put("server_name","resolver.example").put("certificate",new JSONArray().put("public-certificate")))).put("query",new JSONObject().put("server","bootstrap").put("strategy","prefer_ipv4").put("disable_cache",true).put("rewrite_ttl",7).put("timeout","2300ms")));
  f.exits.save(exit);f.store.selectExternalPath(exit,null,"wg");var saved=f.store.add("Evidence");JSONObject captured=f.row().getJSONObject("external_policy");check(!captured.has("effective_mtu")&&captured.getJSONObject("dns_bootstrap").toString().equals(exit.policy.getJSONObject("dns_bootstrap").toString())&&captured.getJSONArray("dns_results").length()==1,"capture complete DNS evidence, omit stale MTU");f.changeExternal(exit.id);f.store.load(saved.id);check(!f.exits.get(exit.id).policy.has("effective_mtu"),"restore cannot resurrect stale MTU proof");
  JSONObject old=f.row();old.remove("external_policy");old.remove("external_startup");old.remove("external_protocol");old.remove("external_public_ip");old.put("multihop_exit_mode","shadowsocks");f.row(old);f.changeExternal(exit.id);String current=AndroidStandardExitStore.snapshot(f.exits.get(exit.id));f.otherSelection();f.store.load(saved.id);check(AndroidStandardExitStore.snapshot(f.exits.get(exit.id)).equals(current),"legacy external profile remains selection-only");
  Files.delete(f.rows.toPath());Files.writeString(f.context.getFilesDir().toPath().resolve("connection-profiles-v1.json"),new JSONObject().put("schema_version",1).put("profiles",new JSONArray().put(old)).toString());f.otherSelection();f.store.load(saved.id);check(f.rows().getInt("schema_version")==7&&!Files.exists(f.context.getFilesDir().toPath().resolve("connection-profiles-v1.json"))&&AndroidStandardExitStore.snapshot(f.exits.get(exit.id)).equals(current),"schema1 path migration preserves selection-only external semantics");
 }
 static void activeSelectionEdges(Path root)throws Exception{
  Fixture f=new Fixture(root);f.store.selectExternalPath(f.exits.get("external-a"),f.first,"wg");var r=f.store.add("captured entry");f.changeNode(f.first);f.nodes.select(f.first.id);f.store.load(r.id);check(f.nodes.activeId().equals(f.first.id)&&text(new File(f.context.getFilesDir(),AndroidNodeStore.ACTIVE_BUNDLE)).equals(text(f.first.file))&&profile(f.first).getString("start_layer").equals("aes-256-gcm+xor-whitening"),"entry that was already active receives restored policy in its active copy");
  f.nodes.restoreSelection(new AndroidNodeStore.SelectionSnapshot("",null));f.store.load(r.id);check(f.nodes.activeId().isEmpty()&&!new File(f.context.getFilesDir(),AndroidNodeStore.ACTIVE_BUNDLE).exists(),"external load preserves absent active Router selection");
  JSONObject replacement=bundle(f.first);AndroidProfileSelection.selectedRouterProfile(replacement).put("id","replacement").put("api_token","replacement-credential");replacement.put("selectedRouterID","replacement");check(f.nodes.importBundle(replacement.toString().getBytes(StandardCharsets.UTF_8)).id.equals(f.first.id),"same public Router identity fixture");State frozen=new State(f);rejected(()->f.store.load(r.id),"different credential profile inside same Router node");frozen.same(f,"credential profile binding");
  JSONObject legacy=node("legacy",3);legacy.remove("nodeProofId");AndroidProfileSelection.selectedRouterProfile(legacy).remove("node_proof_id");legacy.getJSONObject("profiles").getJSONObject("wg").remove("wg.conf");var node=f.nodes.importBundle(legacy.toString().getBytes(StandardCharsets.UTF_8));f.prefs.edit().putString("selected_kind","router-vpn").putString("selected_id",node.id).putString("mode","smart-auto").putBoolean("multihop_on",false).commit();var saved=f.store.add("legacy");JSONObject rows=f.rows();for(int i=0;i<rows.getJSONArray("profiles").length();i++){JSONObject row=rows.getJSONArray("profiles").getJSONObject(i);if(saved.id.equals(row.getString("id")))row.getJSONObject("policy").put("start_layer","off");}Files.writeString(f.rows.toPath(),rows.toString());State before=new State(f);rejected(()->f.store.load(saved.id),"unstable legacy Router identity");before.same(f,"legacy stable identity gate");
 }
 static void busyAndSelectionFailure(Path root)throws Exception{
  Fixture f=new Fixture(root);var saved=f.store.add("idle");AndroidVpnMutationGuard.busy=true;State before=new State(f);
  for(Action action:List.<Action>of(()->f.store.add("busy"),()->f.store.load(saved.id),()->f.store.update(saved.id,"busy"),()->f.store.delete(saved.id),()->f.store.selectExternalPath(f.exits.get("external-a"),f.first,"wg")))rejected(action,"busy mutation");before.same(f,"busy");AndroidVpnMutationGuard.busy=false;
  before=new State(f);f.prefs.failures=1;rejected(()->f.store.selectExternalPath(f.exits.get("external-a"),f.first,"wg"),"selection commit false");before.same(f,"selection");
  f.prefs.values.put("custom_presets",42);before=new State(f);rejected(()->f.store.selectExternalPath(f.exits.get("external-a"),f.first,"wg"),"wrong preference key type");before.same(f,"typed preference preflight");f.prefs.values.remove("custom_presets");
  var home=f.exits.get("external-a");home.policy.put("dns_mode","home");f.exits.save(home);before=new State(f);final var selectedHome=home;rejected(()->f.store.selectExternalPath(selectedHome,null,"wg"),"direct Home without entry");before.same(f,"Home rejection");f.store.selectExternalPath(home,f.first,"wg");check(!f.store.currentExternalPath(home.id).direct(),"Home keeps captured Router entry");
 }
 static void concurrentExternalEditors(Path root)throws Exception{
  Fixture fixture=new Fixture(root);AndroidStandardExitStore first=new AndroidStandardExitStore(fixture.context),second=new AndroidStandardExitStore(fixture.context);
  AndroidStandardExitStore.Entry original=first.get("external-a"),one=AndroidStandardExitStore.copy(original),two=AndroidStandardExitStore.copy(original);String source=first.storedSnapshot(original.id);one.password="first private owner";two.password="second private owner";
  var entered=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);var firstWrite=new java.util.concurrent.atomic.AtomicBoolean(true);var firstError=new java.util.concurrent.atomic.AtomicReference<Throwable>();var secondError=new java.util.concurrent.atomic.AtomicReference<Throwable>();
  AndroidPrivateFileStore.beforeWrite=()->{if(firstWrite.compareAndSet(true,false)){entered.countDown();try{if(!release.await(5,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("publication fixture did not release");}catch(InterruptedException error){Thread.currentThread().interrupt();throw new IllegalStateException(error);}}};
  Thread a=new Thread(()->{try{first.saveIfUnchanged(one,source);}catch(Throwable error){firstError.set(error);}},"captured-external-writer");Thread b=new Thread(()->{try{second.saveIfUnchanged(two,source);}catch(Throwable error){secondError.set(error);}},"stale-external-writer");a.setDaemon(true);b.setDaemon(true);
  try{
   a.start();check(entered.await(5,java.util.concurrent.TimeUnit.SECONDS),"first external writer never reached publication");b.start();long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(5);boolean decided=false;
   while(System.nanoTime()<deadline){var info=java.lang.management.ManagementFactory.getThreadMXBean().getThreadInfo(b.getId());if(!b.isAlive()||info!=null&&info.getThreadState()==Thread.State.BLOCKED&&info.getLockOwnerId()==a.getId()){decided=true;break;}Thread.yield();}
   check(decided,"second external writer neither waited for the transaction nor completed");release.countDown();a.join(5000);b.join(5000);
   check(!a.isAlive()&&!b.isAlive()&&firstError.get()==null&&secondError.get() instanceof IllegalStateException,"independent store instances both adopted the same obsolete editor source");check(first.get(original.id).password.equals(one.password),"concurrent stale editor replaced the retained private credential owner");
  }finally{release.countDown();AndroidPrivateFileStore.beforeWrite=null;a.join(5000);b.join(5000);}
 }
 static void strictRawImport(Path root)throws Exception{
  Fixture f=new Fixture(root);State before=new State(f);String valid=node("strict-import",3).toString(),prefix=valid.substring(0,valid.length()-1);
  for(String bad:List.of("null","[]",valid+" {}",prefix+",\"routerProfiles\":[]}",prefix+",\"extra\":{\"openvpn_pairing\":{\"private_key\":\"first\",\"private_key\":\"second\"}}}")){
   rejected(()->f.nodes.importBundle(bad.getBytes(StandardCharsets.UTF_8)),"ambiguous raw private bundle");before.same(f,"strict raw import rejection");
  }
  java.io.ByteArrayOutputStream invalid=new java.io.ByteArrayOutputStream();invalid.write((prefix+",\"unrelated\":\"").getBytes(StandardCharsets.UTF_8));invalid.write(255);invalid.write("\"}".getBytes(StandardCharsets.UTF_8));
  rejected(()->f.nodes.importBundle(invalid.toByteArray()),"malformed UTF-8 private bundle");before.same(f,"malformed byte import rejection");
 }
 static void quickProtection(Path root)throws Exception{
  for(boolean tor:new boolean[]{false,true})for(boolean via:new boolean[]{false,true})for(boolean enabled:new boolean[]{false,true}){
   Fixture f=new Fixture(root);String id=tor?"external-b":"external-a";AndroidStandardExitStore.Entry before=f.exits.get(id);String original=AndroidStandardExitStore.snapshot(before);String entryBytes=text(f.first.file);
   f.store.selectExternalPath(before,via?f.first:null,"hysteria2");ProductConnectSurface ui=new ProductConnectSurface(f);LayeredVpnService.lockdown=true;ui.displayProtection();
   check(ui.killSwitch.enabled&&ui.killSwitch.checked==(tor||!via),"quick external protection lost its legacy displayed default");
   ui.pressProtection(enabled);AndroidStandardExitStore.Entry saved=f.exits.get(id);JSONObject policy=tor?saved.torPolicy:saved.policy;
   check(policy.getBoolean("kill_switch")==enabled&&policy.getString("kill_switch_policy").equals(enabled?"always":"off"),"quick external protection did not save its exact choice");
   check(ui.killSwitch.checked==enabled&&ui.autoRequirementsHint.text.contains("Android system lockdown is currently On"),"quick external protection hid the independent OS lockdown floor");
   check(!via||ui.autoRequirementsHint.text.contains("Captured entry also requires lockdown"),"quick external protection hid its independent strict entry");
   check(entryBytes.equals(text(f.first.file)),"quick external protection changed the independent entry");
   AndroidStandardExitStore.Entry retained=AndroidStandardExitStore.copy(saved);JSONObject retainedPolicy=tor?retained.torPolicy:retained.policy;retainedPolicy.remove("kill_switch");retainedPolicy.remove("kill_switch_policy");
   check(sameJSON(original,AndroidStandardExitStore.snapshot(retained)),"quick external protection changed credentials DNS MTU or graph");
   for(String key:new String[]{"password","protocol","expected_public_ip"}){JSONObject wrong=new JSONObject(AndroidStandardExitStore.snapshot(retained));wrong.put(key,"different captured field");check(!sameJSON(original,wrong.toString()),"structural protection comparison ignored "+key);}
   AndroidConnectionProfileStore.Record record=f.store.add("Protection "+enabled);ui.pressProtection(!enabled);f.store.load(record.id);JSONObject restored=tor?f.exits.get(id).torPolicy:f.exits.get(id).policy;
   check(restored.getBoolean("kill_switch")==enabled&&restored.getString("kill_switch_policy").equals(enabled?"always":"off"),"connection profile did not restore exact external protection");
  }
  for(String fault:List.of("selection","router-selection","changed-source","removed","busy")){
   Fixture f=new Fixture(root);f.store.selectExternalPath(f.exits.get("external-a"),null,"wg");ProductConnectSurface ui=new ProductConnectSurface(f);ui.displayProtection();
   if(fault.equals("selection"))f.store.selectExternalPath(f.exits.get("external-b"),null,"wg");
   if(fault.equals("router-selection"))f.otherSelection();
   if(fault.equals("changed-source"))f.changeExternal("external-a");
   if(fault.equals("removed"))f.exits.remove("external-a");
   if(fault.equals("busy"))AndroidVpnMutationGuard.busy=true;
   State before=new State(f);ui.pressProtection(false);AndroidVpnMutationGuard.busy=false;before.same(f,"stale quick protection "+fault);
   check(!ui.message.isEmpty(),"stale quick protection failed without feedback");
  }
  LayeredVpnService.lockdown=null;
  Fixture f=new Fixture(root);AndroidStandardExitStore.Entry exit=f.exits.get("external-a");exit.policy.put("kill_switch","false");rejected(()->f.exits.save(exit),"string kill switch");
  exit.policy.put("kill_switch",false).put("kill_switch_policy","unknown");rejected(()->f.exits.save(exit),"unknown kill policy");
 }


 static void independentHomeDNSProfiles(Path root)throws Exception{
  Fixture f=new Fixture(root);
  for(AndroidNodeStore.Node n:List.of(f.first,f.second)){
   boolean exit=n==f.second;JSONObject b=bundle(n),p=AndroidProfileSelection.selectedRouterProfile(b);
   p.put("adguard_ipv4",exit?"10.13.0.53":"10.12.0.53").put("adguard_ipv6",exit?"fd13::53":"fd12::53").put("ipv6_mode","on").put("dns_host",exit?"fd13::53":"10.12.0.53").put("dns_protocol",exit?"h3":"tls").put("dns_port",exit?5443:5853).put("dns_server_name",exit?"exit.home.example":"entry.home.example").put("dns_path",exit?"/exit-dns":"");
   f.nodes.importBundle(b.toString().getBytes(StandardCharsets.UTF_8));
  }
  f.nodes.select(f.first.id);f.prefs.edit().putBoolean("multihop_on",true).putString("multihop_entry",f.first.id).putString("multihop_exit",f.second.id).putString("multihop_exit_mode","hysteria2").putString("multihop_execution","local").putString("multihop_entry_mode","wg").commit();
  var saved=f.store.add("Independent Home owners");JSONObject original=f.row();String firstAssets=bundle(f.first).getJSONObject("profiles").toString(),secondAssets=bundle(f.second).getJSONObject("profiles").toString();f.changeNode(f.first);f.changeNode(f.second);for(AndroidNodeStore.Node n:List.of(f.first,f.second)){JSONObject current=bundle(n),p=AndroidProfileSelection.selectedRouterProfile(current);p.put("api_token","rotated-api-"+n.id).put("socks_password","rotated-socks-"+n.id);f.nodes.importBundle(current.toString().getBytes(StandardCharsets.UTF_8));}f.otherSelection();f.store.load(saved.id);
  for(AndroidNodeStore.Node n:List.of(f.first,f.second))check(profile(n).getString("api_token").equals("rotated-api-"+n.id)&&profile(n).getString("socks_password").equals("rotated-socks-"+n.id),"Home profile replaced current independent node credentials");
  check(profile(f.first).getString("dns_host").equals("10.12.0.53")&&profile(f.first).getString("dns_protocol").equals("tls")&&profile(f.first).getInt("dns_port")==5853,"entry Home policy was substituted");
  check(profile(f.second).getString("dns_host").equals("fd13::53")&&profile(f.second).getString("dns_protocol").equals("h3")&&profile(f.second).getInt("dns_port")==5443&&profile(f.second).getString("dns_path").equals("/exit-dns"),"exit Home policy was substituted");
  check(firstAssets.equals(bundle(f.first).getJSONObject("profiles").toString())&&secondAssets.equals(bundle(f.second).getJSONObject("profiles").toString()),"independent Home restore replaced private transport assets");
  JSONObject swapped=new JSONObject(original.toString());swapped.getJSONObject("exit_policy").put("dns_host","10.12.0.53");f.row(swapped);State before=new State(f);int writes=AndroidPrivateFileStore.writes;rejected(()->f.store.load(saved.id),"swapped Home owner");before.same(f,"invalid exit must not adopt valid entry");check(writes==AndroidPrivateFileStore.writes,"invalid exit wrote before whole path validation");
  f.row(original);f.changeNode(f.first);f.changeNode(f.second);f.otherSelection();before=new State(f);AndroidPrivateFileStore.failPath=f.second.file.getAbsolutePath();AndroidPrivateFileStore.failures=1;try{rejected(()->f.store.load(saved.id),"failed second Home store");before.same(f,"failed exit publication rolls back entry, exit and selected path");}finally{AndroidPrivateFileStore.failures=0;AndroidPrivateFileStore.failPath="";}
 }
 static void homeDNSProfiles(Path root)throws Exception{
  independentHomeDNSProfiles(root);
  for(String type:List.of("udp","tcp","tls","https","h3"))for(String host:List.of("10.12.0.53","fd12::53")){
   Fixture f=new Fixture(root);JSONObject b=bundle(f.first),p=AndroidProfileSelection.selectedRouterProfile(b);p.put("dns_protocol",type).put("dns_host",host).put("dns_port",5443).put("dns_server_name","dns.home.example").put("dns_path","/private-dns").put("ipv6_mode","on");f.nodes.importBundle(b.toString().getBytes(StandardCharsets.UTF_8));
   ProductConnectSurface quick=new ProductConnectSurface(f);quick.pressDNS("home");check(quick.message.startsWith("DNS set to home"),"actual quick Home handler failed");check(profile(f.first).getString("dns_protocol").equals(type)&&profile(f.first).getString("dns_host").equals(host)&&profile(f.first).getInt("dns_port")==5443,"actual quick Home handler reset explicit DNS");State busyBefore=new State(f);AndroidVpnMutationGuard.busy=true;try{quick.pressDNS("home");busyBefore.same(f,"busy Home quick selection");}finally{AndroidVpnMutationGuard.busy=false;}
   b=bundle(f.first);p=AndroidProfileSelection.selectedRouterProfile(b);String assets=b.getJSONObject("profiles").toString();var saved=f.store.add("Exact Home DNS");f.changeNode(f.first);f.otherSelection();f.store.load(saved.id);JSONObject restored=profile(f.first);
   for(String key:List.of("dns_mode","dns_protocol","dns_host","dns_port","dns_server_name","dns_path","ipv6_mode"))check(restored.get(key).equals(p.get(key)),"profile restore replaced Home "+key);
   check(assets.equals(bundle(f.first).getJSONObject("profiles").toString()),"Home restore changed node credentials");
   for(String fault:List.of("foreign-owner","invalid-path","write")){
    JSONObject row=f.row();if(fault.equals("foreign-owner")){JSONObject current=bundle(f.first);AndroidProfileSelection.selectedRouterProfile(current).put("adguard_ipv4","10.13.0.53").put("adguard_ipv6","fd13::53");f.nodes.importBundle(current.toString().getBytes(StandardCharsets.UTF_8));}
    else if(fault.equals("invalid-path")){if(!type.equals("https")&&!type.equals("h3"))continue;row.getJSONObject("policy").put("dns_path","//other.example/dns");f.row(row);}
    else {f.changeNode(f.first);AndroidPrivateFileStore.failPath=f.first.file.getAbsolutePath();AndroidPrivateFileStore.failures=1;}
    State before=new State(f);try{rejected(()->f.store.load(saved.id),fault);before.same(f,"Home restore rollback "+fault);}finally{AndroidPrivateFileStore.failures=0;}
    // Each fault needs its own source identity/row; retain exact original policy.
    f.nodes.importBundle(b.toString().getBytes(StandardCharsets.UTF_8));f.row(row.put("policy",new JSONObject(f.row().getJSONObject("policy").toString()).put("dns_path","/private-dns")));
   }
  }
 }
 static java.util.List<String> generalCases(String family){return switch(family){
  case "store-tor" -> java.util.List.of("ordinaryTorRoundtrip","ordinaryTorInvalid","ordinaryTorRollback","ordinarySchemaMigration","torExecutionProfiles","torPaddingProfiles","torJumboProfiles");
  case "store-external" -> java.util.List.of("externalRoundtrip-direct","externalRoundtrip-entry","externalExecution","externalDefaultHome","externalStartup");
  case "store-openvpn" -> java.util.List.of("mappedOpenVPNProfiles");
  case "store-router" -> java.util.List.of("quickProtection","routerRoundtrip","routerLegacyPolicy","rollback-node","rollback-external","rollback-preferences","rollback-rollback","invalidBeforeMutation","evidenceAndLegacy","activeSelectionEdges","busyAndSelectionFailure","concurrentExternalEditors","strictRawImport");
  default -> throw new IllegalArgumentException("Unknown original profile group");};}
 static void generalProfiles(Path root,String family)throws Exception{
  for(String leaf:generalCases(family))switch(leaf){
   case "ordinaryTorRoundtrip" -> ordinaryTorRoundtrip(root);
   case "ordinaryTorInvalid" -> ordinaryTorInvalid(root);
   case "ordinaryTorRollback" -> ordinaryTorRollback(root);
   case "ordinarySchemaMigration" -> ordinarySchemaMigration(root);
   case "torExecutionProfiles" -> torExecutionProfiles(root);
   case "torPaddingProfiles" -> torPaddingProfiles(root);
   case "torJumboProfiles" -> torJumboProfiles(root);
   case "externalRoundtrip-direct" -> externalRoundtrip(root,false);
   case "externalRoundtrip-entry" -> externalRoundtrip(root,true);
   case "externalExecution" -> externalExecution(root);
   case "externalDefaultHome" -> externalDefaultHome(root);
   case "externalStartup" -> externalStartup(root);
   case "mappedOpenVPNProfiles" -> mappedOpenVPNProfiles(root);
   case "quickProtection" -> quickProtection(root);
   case "routerRoundtrip" -> routerRoundtrip(root);
   case "routerLegacyPolicy" -> routerLegacyPolicy(root);
   case "rollback-node" -> rollback(root,"node");
   case "rollback-external" -> rollback(root,"external");
   case "rollback-preferences" -> rollback(root,"preferences");
   case "rollback-rollback" -> rollback(root,"rollback");
   case "invalidBeforeMutation" -> invalidBeforeMutation(root);
   case "evidenceAndLegacy" -> evidenceAndLegacy(root);
   case "activeSelectionEdges" -> activeSelectionEdges(root);
   case "busyAndSelectionFailure" -> busyAndSelectionFailure(root);
   case "concurrentExternalEditors" -> concurrentExternalEditors(root);
   case "strictRawImport" -> strictRawImport(root);
   default -> throw new IllegalArgumentException("Unexecuted original profile case");
  }
  System.out.println("Android actual "+family+": "+checks+" checks across "+cases+" isolated cases passed");
  System.out.println("GENERAL_EXECUTED="+new JSONArray(generalCases(family)));
 }
 public static void main(String[] args)throws Exception{Path root=Path.of(args[0]);if(args.length>1&&args[1].equals("list-general")){JSONObject inventory=new JSONObject();for(String family:java.util.List.of("store-tor","store-external","store-openvpn","store-router"))inventory.put(family,new JSONArray(generalCases(family)));System.out.println(inventory);return;}if(args.length>1&&args[1].startsWith("store-")){generalProfiles(root,args[1]);return;}if(args.length>1&&args[1].equals("connect-router")){connectRouterProfiles(root);System.out.println("Android CONNECT persistence: "+checks+" checks across "+cases+" cases passed; compiler boundary independently verified");return;}if(args.length>1&&args[1].equals("home-dns")){homeDNSProfiles(root);System.out.println("Android Home profile stores: "+checks+" checks across "+cases+" cases passed");return;}if(args.length>1&&args[1].equals("router-rates")){routerRateProfiles(root);torPaddingProfiles(root);System.out.println("Android Router captured rates: "+checks+" checks across "+cases+" isolated cases passed");return;}if(args.length>1&&args[1].equals("imported-summary")){importedSummary(root);System.out.println("Android actual imported summary: "+checks+" checks across "+cases+" cases passed");return;}if(args.length>1&&args[1].equals("profile-preferences")){profilePreferences(root);System.out.println("Android profile preferences: "+checks+" checks across "+cases+" cases passed");return;}if(args.length>1&&args[1].equals("profile-apply")){profileApply(root);System.out.println("Android profile apply: "+checks+" checks across "+cases+" cases passed");return;}if(args.length>1&&args[1].equals("profile-rollback")){profileRollback(root);System.out.println("Android profile rollback: "+checks+" checks across "+cases+" cases passed");return;}if(args.length>1&&List.of("imported-router","imported-wireguard-router","imported-amneziawg-router","imported-final-wg","imported-final-awg2-fast","imported-final-awg2-strong","imported-nested-wg","imported-nested-awg2-fast","imported-nested-awg2-strong").contains(args[1])){if(args[1].equals("imported-wireguard-router"))importedProtocols=List.of("wireguard");if(args[1].equals("imported-amneziawg-router"))importedProtocols=List.of("amneziawg");if(args[1].startsWith("imported-nested-")){importedProtocols=List.of("wireguard","amneziawg");importedFinalModes=List.of(args[1].substring("imported-nested-".length()));}if(args[1].startsWith("imported-final-"))importedFinalModes=List.of(args[1].substring("imported-final-".length()));importedRouterRoundtrip(root);importedRouterInvalid(root);importedRouterRollback(root);importedRouterProduct(root);packetFinalBoundaries(root);System.out.println("Android "+args[1]+" actual persistence: "+checks+" checks across "+cases+" isolated cases passed (pure compiler boundary doubled)");return;}if(args.length>1&&args[1].equals("concurrency")){concurrentExternalEditors(root);return;}throw new IllegalArgumentException("Select an explicit complete profile case family");}
}
'''

# This is the complete leaf inventory of the former final JVM aggregate. Each
# named group retains the original 180-second owner; no case or control is lost.
GENERAL_FAMILIES = {'store-tor': ('ordinaryTorRoundtrip', 'ordinaryTorInvalid', 'ordinaryTorRollback', 'ordinarySchemaMigration', 'torExecutionProfiles', 'torPaddingProfiles', 'torJumboProfiles'), 'store-external': ('externalRoundtrip-direct', 'externalRoundtrip-entry', 'externalExecution', 'externalDefaultHome', 'externalStartup'), 'store-openvpn': ('mappedOpenVPNProfiles',), 'store-router': ('quickProtection', 'routerRoundtrip', 'routerLegacyPolicy', 'rollback-node', 'rollback-external', 'rollback-preferences', 'rollback-rollback', 'invalidBeforeMutation', 'evidenceAndLegacy', 'activeSelectionEdges', 'busyAndSelectionFailure', 'concurrentExternalEditors', 'strictRawImport')}

def validate_general_inventory(actual):
    expected = {family: list(cases) for family, cases in GENERAL_FAMILIES.items()}
    if actual != expected:
        raise AssertionError("Original profile case inventory was omitted, duplicated or reordered")
    flattened = [case for cases in actual.values() for case in cases]
    if len(flattened) != len(set(flattened)):
        raise AssertionError("An original profile case was selected twice")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-family", choices=("all", "connect-router", "home-dns", "router-rates", "imported-router", "profile-rollback", "profile-apply", "profile-preferences", "selection-ownership", "packet-finals", "imported-summary", "ordered-chain", "general-stores"), default="all")
    args = parser.parse_args()
    chain = None
    if args.case_family in ("all", "ordered-chain"):
        import test_android_node_chain_capture as chain
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file():
        raise RuntimeError("Real Android JSON implementation required")
    if not shutil.which("go"):
        raise RuntimeError("Go is required for actual AWG profile validation")
    with tempfile.TemporaryDirectory(prefix="android-connection-profiles-", dir=ROOT) as work:
        work = Path(work)
        module = next(line.split()[1] for line in (ROOT / "go.mod").read_text().splitlines() if line.startswith("module "))
        compiler = work / "compiler"
        (work / "main.go").write_text((chain.compiler_source(GO) if chain else GO).replace("router-vpn/internal/", module + "/internal/"))
        subprocess.run(["go", "build", "-o", str(compiler), str(work / "main.go")], cwd=ROOT, check=True, timeout=120)
        src = work / "src"
        for name, content in STUBS.items():
            target = src / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        app = src / "com/eabusham/routervpn"
        app.mkdir(parents=True)
        for name in ("AndroidExternalProtection", "AndroidKillSwitchPolicy", "AndroidConnectionProfileStore", "AndroidConnectionProfilePolicy", "AndroidConnectionSelection", "AndroidNodeStore", "AndroidStandardExitStore", "AndroidProfileSelection", "AndroidNumericAddress", "AndroidNativeProfilePolicy", "AndroidExternalAmnezia", "AndroidOpenVPN"):
            shutil.copyfile(JAVA / (name + ".java"), app / (name + ".java"))
        methods = "\n".join(method("AndroidExternalPolicy.java", signature) for signature in ("static boolean supports(", "static String protocol(", "static void checkPolicy(", "static JSONObject profile(", "static Captured captureImportedEntry(", "private static Captured capture(", "private static JSONObject copy("))
        methods = methods.replace("Base64.", "android.util.Base64.")
        policy_source = (JAVA / "AndroidExternalPolicy.java").read_text(encoding="utf-8")
        policy_fields = policy_source[policy_source.index("    private static final Set<String> POLICY"):policy_source.index("\n\n    static boolean supports", policy_source.index("    private static final Set<String> POLICY"))]
        controller = (JAVA / "AndroidMultihopController.java").read_text()
        captured = controller[controller.index("    static final class Source {"):controller.index("    private static final class EntryPrivate {")]
        captured += "\n" + "\n".join(method("AndroidMultihopController.java", signature) for signature in ("private static String sourceDigest(", "private static byte[] readBundleBytes("))
        imported_capture = "\n".join(method("AndroidImportedRouterPath.java", signature) for signature in ("static boolean supports(", "static void requireEntry(", "static AndroidMultihopController.Source captureSource(", "static AndroidStandardExitStore.Entry entry("))
        (app / "Boundaries.java").write_text(BOUNDARIES.replace("EXTERNAL_METHODS", methods).replace("EXTERNAL_POLICY_FIELDS", policy_fields).replace("CAPTURE_SOURCE", captured).replace("IMPORTED_CAPTURE_METHODS", imported_capture).replace("EXTERNAL_TRANSPORT", method("AndroidDirectStandardExitController.java", "static JSONObject customExitJson(")), encoding="utf-8")
        protection = "\n".join(method("ProductActivity.java", signature) for signature in ("private boolean isExternalSelected(", "private void setQuickKillSwitch(", "private void refreshSettingsState(", "private void setQuickDns("))
        connect = "\n".join(method("ProductActivity.java", signature) for signature in ("private void connectOrDisconnect(", "private void connectSavedOrderedPath("))
        (app / "ProductConnectSurface.java").write_text(PRODUCT.replace("PRODUCT_CONNECT", connect).replace("PRODUCT_PROTECTION", protection).replace("PRODUCT_IMPORTED", "\n".join(method("ProductActivity.java", signature) for signature in ("private void chooseImportedRouterFinal(", "private void chooseImportedRouterTransport(", "private void refreshMultihopSummary("))), encoding="utf-8")
        (app / "AndroidProductParity.java").write_text('package com.eabusham.routervpn; import org.json.*; final class AndroidProductParity {static void showDNS(android.content.Context c,AndroidNodeStore s){throw new AssertionError("Details sheet rendering boundary");}' + method("AndroidProductParity.java", "static void selectQuickDNS(") + '}')
        (app / "AndroidStartLayer.java").write_text('package com.eabusham.routervpn; final class AndroidStartLayer {static final String OFF="off";static String selectedMode(org.json.JSONObject root){throw new AssertionError("Raw eligibility is covered in native graph tests");}}')
        (app / "ConnectionProfilesHarness.java").write_text(HARNESS)
        if chain:
            chain.prepare_sources(src, app, JAVA)
        classes = work / "classes"
        subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(classes), *map(str, src.rglob("*.java"))], check=True, timeout=60)
        data = work / "data"
        data.mkdir()
        env = os.environ.copy(); env["ROUTERVPN_PROFILE_COMPILER"] = str(compiler);env["ROUTERVPN_OPENVPN_MULTIHOST_CLIENT_FIXTURE"] = str(ROOT/"deploy/fixtures/external-openvpn-multihost-client.json");env["ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_AES_FIXTURE"] = str(ROOT/"deploy/fixtures/external-openvpn-multihost-layered-aes-client.json");env["ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_XOR_FIXTURE"] = str(ROOT/"deploy/fixtures/external-openvpn-multihost-layered-xor-client.json")
        if chain:
            chain.run(ROOT, work, app, classes, jar, env)
            if args.case_family == "ordered-chain":
                return
        # Each complete case family retains the original finite JVM budget.
        if args.case_family in ("all", "home-dns"):
            subprocess.run(["java", "-cp", str(classes) + os.pathsep + str(jar), "com.eabusham.routervpn.ConnectionProfilesHarness", str(data), "home-dns"], env=env, check=True, timeout=80)
            original = (app / "AndroidConnectionProfileStore.java").read_text()
            mutation = work / "home-negative" / "AndroidConnectionProfileStore.java"; mutation.parent.mkdir()
            guard = "        AndroidNativeProfilePolicy.validateHomeDNS(profile);"
            if original.count(guard) != 2: raise AssertionError("Home capture/restore validation changed")
            mutation.write_text(original.replace(guard, ""))
            negative = work / "home-negative-classes"; shutil.copytree(classes, negative)
            classpath = str(negative) + os.pathsep + str(jar)
            subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", classpath, "-d", str(negative), str(mutation)], check=True, timeout=60)
            result = subprocess.run(["java", "-cp", classpath, "com.eabusham.routervpn.ConnectionProfilesHarness", str(data), "home-dns"], env=env, capture_output=True, text=True, timeout=80)
            if result.returncode == 0 or "accepted swapped Home owner" not in result.stderr: raise AssertionError("Home profile ownership causal control missed its defect\n" + result.stderr)
            print("Android Home profile causal control rejected: missing current-node validation")
            if args.case_family == "home-dns":
                return
        if args.case_family in ("all", "router-rates"):
            subprocess.run(["java", "-cp", str(classes) + os.pathsep + str(jar), "com.eabusham.routervpn.ConnectionProfilesHarness", str(data), "router-rates"], env=env, check=True, timeout=180)
            original_store = (app / "AndroidConnectionProfileStore.java").read_text()
            copy_rate = 'for(String key:POLICY_KEYS)if(profile.has(key))policy.put(key,profile.get(key));'
            default_rate = 'if(!profile.has("daita_rate_kbps"))policy.put("daita_rate_kbps",JSONObject.NULL);'
            legacy_rate = 'if(!"daita_rate_kbps".equals(key)||policy.has(key))profile.remove(key);'
            for marker in (copy_rate, default_rate, legacy_rate):
                assert original_store.count(marker) == 1, "Original rate ownership boundary changed: " + marker
            controls = (
                ("capture", original_store.replace(copy_rate, copy_rate.replace('profile.has(key)', 'profile.has(key)&&!"daita_rate_kbps".equals(key)')).replace(default_rate, ''), "Add omitted Router rate or captured default"),
                ("legacy", original_store.replace(legacy_rate, 'profile.remove(key);'), "legacy uncaptured rate was deleted or overwritten"),
            )
            for name, changed, witness in controls:
                negative = work / ("rate-negative-" + name); shutil.copytree(classes, negative)
                mutation = work / ("rate-source-" + name) / "AndroidConnectionProfileStore.java"; mutation.parent.mkdir(); mutation.write_text(changed)
                classpath = str(negative) + os.pathsep + str(jar)
                subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", classpath, "-d", str(negative), str(mutation)], check=True, timeout=60)
                result = subprocess.run(["java", "-cp", classpath, "com.eabusham.routervpn.ConnectionProfilesHarness", str(data), "router-rates"], env=env, capture_output=True, text=True, timeout=180)
                if result.returncode == 0 or witness not in result.stderr:
                    raise AssertionError("Router rate causal control missed its exact defect: " + name + "\n" + result.stderr)
                print("Android Router rate causal control rejected: " + name)
            if args.case_family == "router-rates":
                return
        if args.case_family in ("all", "imported-router", "packet-finals", "imported-summary"):
            subprocess.run(["java", "-cp", str(classes) + os.pathsep + str(jar), "com.eabusham.routervpn.ConnectionProfilesHarness", str(data), "imported-summary"], env=env, check=True, timeout=180)
            if args.case_family == "imported-summary":
                return
        if args.case_family in ("all", "selection-ownership", "profile-preferences"):
            subprocess.run(["java", "-cp", str(classes) + os.pathsep + str(jar), "com.eabusham.routervpn.ConnectionProfilesHarness", str(data), "profile-preferences"], env=env, check=True, timeout=180)
            original_store = (app / "AndroidConnectionProfileStore.java").read_text()
            ownership = "return update.original.equals(current)||(update.attempted&&update.next.equals(current));"
            product_lock = "static void applySelection(SharedPreferences preferences,SharedPreferences.Editor editor){synchronized(preferences)"
            admission = 'synchronized(prefs()) {\n        try{\n            if(!preferenceUpdate.original.equals(snapshotPreferences()))throw new IllegalStateException("The selected connection changed before profile mutation.");'
            for marker in (ownership, product_lock, admission):
                if original_store.count(marker) != 1:
                    raise AssertionError("Original preference ownership boundary changed: " + marker)
            controls = (("owner", original_store.replace(ownership,"return true;"),"profile preference rollback overwrote the successor Product selection"),
                        ("publication", original_store.replace(product_lock,product_lock.replace("synchronized(preferences)","synchronized(new Object())")),"preference rollback comparison and publication did not exclude the Product writer"),
                        ("transaction", original_store.replace(admission,admission.replace("synchronized(prefs())", "synchronized(new Object())")),"whole profile selection did not exclude the independent Product chooser"))
            for name, changed, witness in controls:
                negative = work / ("preferences-negative-" + name); shutil.copytree(classes, negative)
                mutation = work / ("preferences-source-" + name) / "AndroidConnectionProfileStore.java"; mutation.parent.mkdir(); mutation.write_text(changed)
                classpath = str(negative) + os.pathsep + str(jar)
                subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", classpath, "-d", str(negative), str(mutation)], check=True, timeout=60)
                result = subprocess.run(["java", "-cp", classpath, "com.eabusham.routervpn.ConnectionProfilesHarness", str(data), "profile-preferences"], env=env, capture_output=True, text=True, timeout=180)
                if result.returncode == 0 or witness not in result.stderr:
                    raise AssertionError("Preference causal control missed its exact defect: " + name + "\n" + result.stderr)
                print("Android profile preference causal control rejected: " + name)
            if args.case_family == "profile-preferences":
                return
        if args.case_family in ("all", "selection-ownership", "profile-apply"):
            subprocess.run(["java", "-cp", str(classes) + os.pathsep + str(jar), "com.eabusham.routervpn.ConnectionProfilesHarness", str(data), "profile-apply"], env=env, check=True, timeout=180)
            original_store = (app / "AndroidConnectionProfileStore.java").read_text()
            guarded = "nodes.applyProfileBundle(update.id,update.original,updatedBundle).id"
            if original_store.count(guarded) != 1:
                raise AssertionError("Original profile apply admission changed")
            original_node = (app / "AndroidNodeStore.java").read_text()
            admission = "synchronized Node applyProfileBundle(String id, byte[] original, byte[] updated) throws Exception { synchronized (STORE_LOCK)"
            if original_node.count(admission) != 1:
                raise AssertionError("Shared atomic profile apply boundary changed")
            controls = (("caller", "AndroidConnectionProfileStore", original_store.replace(guarded, "nodes.importBundle(updatedBundle).id")),
                        ("atomic", "AndroidNodeStore", original_node.replace(admission, admission.replace("STORE_LOCK", "new Object()"))))
            for name, target, changed in controls:
                negative = work / ("apply-negative-" + name); shutil.copytree(classes, negative)
                mutation = work / ("apply-source-" + name) / (target + ".java"); mutation.parent.mkdir(); mutation.write_text(changed)
                classpath = str(negative) + os.pathsep + str(jar)
                subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", classpath, "-d", str(negative), str(mutation)], check=True, timeout=60)
                result = subprocess.run(["java", "-cp", classpath, "com.eabusham.routervpn.ConnectionProfilesHarness", str(data), "profile-apply"], env=env, capture_output=True, text=True, timeout=180)
                if result.returncode == 0 or "profile forward apply overwrote the successor node credentials" not in result.stderr:
                    raise AssertionError("Profile apply causal control missed its exact defect: " + name + "\n" + result.stderr)
                print("Android node profile apply causal control rejected: " + name)
            if args.case_family == "profile-apply":
                return
        if args.case_family in ("all", "selection-ownership", "profile-rollback"):
            subprocess.run(["java", "-cp", str(classes) + os.pathsep + str(jar), "com.eabusham.routervpn.ConnectionProfilesHarness", str(data), "profile-rollback"], env=env, check=True, timeout=180)
            original_node = (app / "AndroidNodeStore.java").read_text()
            guard = '\n        if (!java.util.Arrays.equals(current, published)) {\n            throw new IllegalStateException("A concurrent Router-node update prevents safe rollback; its source was preserved.");\n        }'
            # Mutate only the actual rollback admission, not unrelated store APIs.
            rollback_admission = 'synchronized void restoreProfileBundle(String id, byte[] original, byte[] published) throws Exception { synchronized (STORE_LOCK) {'
            if original_node.count(guard) != 1 or original_node.count(rollback_admission) != 1:
                raise AssertionError("Owned node rollback publication boundary changed")
            controls = (("source", original_node.replace(guard, ""), "profile rollback overwrote the successor node credentials"),
                        ("atomic", original_node.replace(rollback_admission, rollback_admission.replace('synchronized (STORE_LOCK)', 'synchronized (new Object())')), "node rollback compare and publication did not exclude the competing store"))
            for name, changed, witness in controls:
                negative = work / ("rollback-negative-" + name); shutil.copytree(classes, negative)
                mutation = work / ("rollback-source-" + name) / "AndroidNodeStore.java"; mutation.parent.mkdir(); mutation.write_text(changed)
                classpath = str(negative) + os.pathsep + str(jar)
                subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", classpath, "-d", str(negative), str(mutation)], check=True, timeout=60)
                result = subprocess.run(["java", "-cp", classpath, "com.eabusham.routervpn.ConnectionProfilesHarness", str(data), "profile-rollback"], env=env, capture_output=True, text=True, timeout=180)
                if result.returncode == 0 or witness not in result.stderr:
                    raise AssertionError("Rollback causal control missed its exact defect: " + name + "\n" + result.stderr)
                print("Android node rollback causal control rejected: " + name)
            if args.case_family in ("profile-rollback", "selection-ownership"):
                return
        families=("connect-router",) if args.case_family=="connect-router" else ("imported-final-wg", "imported-final-awg2-fast", "imported-final-awg2-strong", "imported-nested-wg", "imported-nested-awg2-fast", "imported-nested-awg2-strong") if args.case_family=="packet-finals" else ("connect-router", "imported-router", "imported-wireguard-router", "imported-amneziawg-router", "imported-final-wg", "imported-final-awg2-fast", "imported-final-awg2-strong", "imported-nested-wg", "imported-nested-awg2-fast", "imported-nested-awg2-strong")
        for family in (() if args.case_family == "general-stores" else families):
            subprocess.run(["java", "-cp", str(classes) + os.pathsep + str(jar), "com.eabusham.routervpn.ConnectionProfilesHarness", str(data), family], env=env, check=True, timeout=180)
        if args.case_family in ("connect-router", "imported-router", "packet-finals"):
            return
        general_command = ["java", "-cp", str(classes) + os.pathsep + str(jar), "com.eabusham.routervpn.ConnectionProfilesHarness", str(data)]
        inventory = json.loads(subprocess.run(general_command + ["list-general"], env=env, check=True, capture_output=True, text=True, timeout=180).stdout)
        validate_general_inventory(inventory)
        for fault in ("omitted", "duplicated"):
            broken = {key: list(value) for key, value in inventory.items()}
            if fault == "omitted": broken["store-openvpn"].clear()
            else: broken["store-router"].append(broken["store-openvpn"][0])
            try: validate_general_inventory(broken)
            except AssertionError: pass
            else: raise AssertionError("Original profile inventory accepted " + fault + " case")
        executed = []
        for family, selected in GENERAL_FAMILIES.items():
            result = subprocess.run(general_command + [family], env=env, check=True, capture_output=True, text=True, timeout=180)
            print(result.stdout, end=""); print(result.stderr, end="")
            receipts = [line.removeprefix("GENERAL_EXECUTED=") for line in result.stdout.splitlines() if line.startswith("GENERAL_EXECUTED=")]
            if len(receipts) != 1 or json.loads(receipts[0]) != list(selected):
                raise AssertionError("Original profile group omitted or duplicated an executed case: " + family)
            executed.extend(json.loads(receipts[0]))
        if executed != [case for cases in GENERAL_FAMILIES.values() for case in cases]:
            raise AssertionError("Original profile case groups did not execute their complete inventory")

        # A per-instance transaction can still lose an update between separate
        # Activities. Reproduce that defect only in isolated compiled classes.
        original = (app / "AndroidStandardExitStore.java").read_text()
        if original.count("synchronized(STORE_LOCK)") != 5:
            raise AssertionError("Shared private-store transaction boundary changed")
        mutation = work / "negative-source" / "AndroidStandardExitStore.java"
        mutation.parent.mkdir()
        mutation.write_text(original.replace("synchronized(STORE_LOCK)", "synchronized(new Object())"))
        negative = work / "negative-classes"; shutil.copytree(classes, negative)
        classpath = str(negative) + os.pathsep + str(jar)
        subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", classpath, "-d", str(negative), str(mutation)], check=True, timeout=60)
        negative_data = work / "negative-data"; negative_data.mkdir()
        rejected = subprocess.run(["java", "-cp", classpath, "com.eabusham.routervpn.ConnectionProfilesHarness", str(negative_data), "concurrency"], env=env, capture_output=True, text=True, timeout=180)
        if rejected.returncode == 0 or "independent store instances both adopted the same obsolete editor source" not in rejected.stderr:
            raise AssertionError("Lost-update negative control did not reject the broken transaction\n" + rejected.stderr)
        print("Android private-store concurrency: independent-Activity lost-update negative control rejected")


if __name__ == "__main__":
    main()
