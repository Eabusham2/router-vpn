#!/usr/bin/env python3
"""Execute the shipping profile, node and exit stores against real Android JSON.

Private publication, SharedPreferences and idle runtime handles are boundary
doubles. Faults include commit(false) after in-memory publication. Native graph
compilation is covered by the external/Tor suites; this suite neither connects
nor claims device or network proof.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"

GO = r'''package main
import("encoding/json";"fmt";"io";"os";"router-vpn/internal/mobilemultihop";"router-vpn/mobile")
func main(){raw,err:=io.ReadAll(os.Stdin);var args []string;if err==nil{err=json.Unmarshal(raw,&args)};var result string;if err==nil{switch {case len(args)==2:result,err=mobilemultihop.CompileAmneziaProfile(args[0],args[1]);case len(args)==1:err=libbox.RouterValidatePrivateNodeJSON(args[0]);case len(args)==6&&args[0]=="openvpn-endpoint":result,err=libbox.RouterOpenVPNEndpoint(args[1],args[2],args[3],args[4],args[5]);case len(args)==3&&args[0]=="openvpn-pairing":err=libbox.RouterValidateExternalOpenVPNPairing(args[1],args[2]);case len(args)==3&&args[0]=="openvpn-probes":err=libbox.RouterValidateExternalOpenVPNResponseProbes(args[1],args[2]);case len(args)==5&&args[0]=="openvpn-layers":err=libbox.RouterValidateExternalOpenVPNStartLayers(args[1],args[2],args[3],args[4]);default:panic("invalid fixture request")}};if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)};fmt.Print(result)}'''


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
 public final java.util.Map<String,Object> values=new java.util.LinkedHashMap<>();public int writes;public int failures;
 public java.util.Map<String,?> getAll(){return new java.util.LinkedHashMap<>(values);}public String getString(String key,String fallback){return (String)values.getOrDefault(key,fallback);}
 public boolean getBoolean(String key,boolean fallback){return (Boolean)values.getOrDefault(key,fallback);}
 public Editor edit(){return new Editor(){final java.util.Map<String,Object> staged=new java.util.LinkedHashMap<>();
  public Editor putString(String key,String value){staged.put(key,value);return this;}public Editor putBoolean(String key,boolean value){staged.put(key,value);return this;}
  public Editor putInt(String key,int value){staged.put(key,value);return this;}public Editor putLong(String key,long value){staged.put(key,value);return this;}public Editor putFloat(String key,float value){staged.put(key,value);return this;}
  public Editor remove(String key){staged.put(key,null);return this;}public void apply(){commit();}
  public boolean commit(){writes++;for(java.util.Map.Entry<String,Object> e:staged.entrySet()){if(e.getValue()==null)values.remove(e.getKey());else values.put(e.getKey(),e.getValue());}if(failures>0){failures--;return false;}return true;}
 };}
}''',
    "android/util/Base64.java": r'''package android.util;public final class Base64 {public static final int DEFAULT=0;
 public static byte[] decode(String value,int flags){return java.util.Base64.getMimeDecoder().decode(value);}
}''',
    "io/nekohasekai/libbox/Libbox.java": r'''package io.nekohasekai.libbox;import org.json.JSONArray;import java.nio.charset.StandardCharsets;
public final class Libbox {public static String routerCompileAmneziaProfile(String profile,String identity)throws Exception{return call(profile,identity);}
public static void routerValidatePrivateNodeJSON(String source)throws Exception{call(source);}
public static String version(){return "1.14.1";}
public static String routerOpenVPNEndpoint(String config,String user,String password,String tag,String detour)throws Exception{return call("openvpn-endpoint",config,user,password,tag,detour);}
public static void routerValidateExternalOpenVPNPairing(String profile,String pairing)throws Exception{call("openvpn-pairing",profile,pairing);}
public static void routerValidateExternalOpenVPNResponseProbes(String profile,String probes)throws Exception{call("openvpn-probes",profile,probes);}
public static void routerValidateExternalOpenVPNStartLayers(String profile,String probes,String layers,String mode)throws Exception{call("openvpn-layers",profile,probes,layers,mode);}
private static String call(String...args)throws Exception{
 Process process=new ProcessBuilder(System.getenv("ROUTERVPN_PROFILE_COMPILER")).start();process.getOutputStream().write(new JSONArray(java.util.Arrays.asList(args)).toString().getBytes(StandardCharsets.UTF_8));process.getOutputStream().close();String out=new String(process.getInputStream().readAllBytes(),StandardCharsets.UTF_8),error=new String(process.getErrorStream().readAllBytes(),StandardCharsets.UTF_8);if(process.waitFor()!=0)throw new IllegalStateException(error);return out;
}}''',
}

BOUNDARIES = r'''package com.eabusham.routervpn;
import org.json.*;import java.util.*;import java.io.*;import java.nio.file.*;
final class AndroidPrivateFileStore {
 static String failPath="";static int failures;static int writes;static volatile Runnable beforeWrite;
 static void ensurePrivateDirectory(File file)throws Exception{Files.createDirectories(file.toPath());}
 static byte[] read(File file,int max)throws Exception{byte[] bytes=Files.readAllBytes(file.toPath());if(bytes.length==0||bytes.length>max)throw new IOException("bad size");return bytes;}
 static void write(File file,byte[] bytes,int max)throws Exception{if(bytes.length==0||bytes.length>max)throw new IOException("bad size");Runnable hook=beforeWrite;if(hook!=null)hook.run();Files.createDirectories(file.getParentFile().toPath());Files.write(file.toPath(),bytes);writes++;if(failures>0&&file.getAbsolutePath().equals(failPath)){failures--;throw new IOException("injected post-publication failure");}}
 static void remove(File file,int max)throws Exception{Files.deleteIfExists(file.toPath());}
}
final class AndroidStartupPolicy {static void cancelPending(){}}
final class AndroidVpnMutationGuard {static boolean busy;static boolean isBusy(android.content.Context context){return busy;}}
final class AndroidHomeStateStore {static final class Snapshot{boolean connected;String phase="off";}static Snapshot snapshot(android.content.Context c){return new Snapshot();}}
final class AndroidRuntimeRegistry {
 static final class Engine{boolean isRunning(){return false;}boolean isActiveOrTransitioning(){return false;}String getState(){return "DOWN";}}
 final Engine orchestrator=new Engine(),multihop=new Engine(),singBox=new Engine(),xray=new Engine();static AndroidRuntimeRegistry get(android.content.Context c){return new AndroidRuntimeRegistry();}
}

final class AndroidTorProfile {
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
final class AndroidExternalPolicy {
 EXTERNAL_POLICY_FIELDS
 static final int MAX_CAPTURE=8*1024*1024;static boolean bounded(String value,int max){return value!=null&&!value.isEmpty()&&value.length()<=max;}
 EXTERNAL_METHODS
}
'''

PRODUCT = r'''package com.eabusham.routervpn;
import android.content.*;import java.util.*;import org.json.*;import java.nio.charset.StandardCharsets;
// Only UI rendering and runtime dispatch are doubled. The shipping handler reads
// the same actual profile/node/exit stores used by the persistence regression.
final class ProductConnectSurface extends Context {
 static final String MULTI_ENTRY="multihop_entry",MULTI_EXIT="multihop_exit",MULTI_MODE="multihop_exit_mode";
 static final String SELECTED_ID="selected_id",SELECTED_KIND="selected_kind";
 final ConnectionProfilesHarness.Fixture fixture;final AndroidNodeStore nodeStore;final AndroidStandardExitStore exitStore;
 static final class View{String text="";boolean checked,enabled;void setText(String value){text=value;}boolean isChecked(){return checked;}void setChecked(boolean value){checked=value;}void setEnabled(boolean value){enabled=value;}}
 final View statusView=new View(),connectButton=new View(),multihopToggle=new View();String message="";
 final View killSwitch=new View(),autoRequirementsHint=new View();private String externalProtectionID="",externalProtectionSource="";
 static final class Probe{boolean isBusy(){return false;}}final Probe viaEntryProbe=new Probe();
 static final class Connection{
  int starts;boolean direct;AndroidNodeStore.Node entry;AndroidStandardExitStore.Entry ordinaryEntry,exit;String mode,execution;
  boolean cancelStartupPending(){return false;}boolean cancelPermissionPending(){return false;}boolean isActiveOrTransitioning(){return false;}void disconnect(Object callback){throw new AssertionError("unexpected disconnect");}
  void connectExternal(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,boolean direct,String mode,String execution,Object callback){starts++;this.entry=entry;this.exit=exit;this.direct=direct;this.mode=mode;this.execution=execution;}
  void connectExternal(AndroidConnectionProfileStore.ExternalSelection path,Object callback){if(path.ordinaryEntry!=null){starts++;ordinaryEntry=path.ordinaryEntry;exit=path.exit;mode=path.entryMode;execution=path.execution;direct=false;}else connectExternal(path.entry,path.exit,path.direct(),path.entryMode,path.execution,callback);}
  void connectMultihop(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,String mode,String execution,String entryMode,Object callback){throw new AssertionError("external selection became Router multihop");}
  void connect(String mode,List<String> layers,Object callback){throw new AssertionError("external selection used unrelated active Router");}
 }final Connection connection=new Connection();
 static final class ModeChoice{String id,title;List<String> layers;}
 ProductConnectSurface(ConnectionProfilesHarness.Fixture f){super(f.context.getFilesDir());fixture=f;nodeStore=f.nodes;exitStore=f.exits;}
 @Override public MemoryPreferences getSharedPreferences(String name,int mode){return fixture.context.getSharedPreferences(name,mode);}
 SharedPreferences prefs(){return fixture.prefs;}void toast(String text){message=text;}void showNodes(){throw new AssertionError("selected external disappeared");}
 AndroidUnifiedNodeCatalog.Item selectedCatalogItem(){return new AndroidUnifiedNodeCatalog.Item(fixture.prefs.getString("selected_id",""));}
 AndroidNodeStore.Node nodeById(String id)throws Exception{for(var n:nodeStore.list())if(n.id.equals(id))return n;return null;}
 Object callback(){return new Object();}void configureMultihop(){}void refreshModeChoices(){}void refreshConnectionLater(){}ModeChoice currentMode(){throw new AssertionError("external selection used Router mode");}
 static String safe(Exception error){return error.getMessage();}void pressConnect(){connectOrDisconnect();}
 boolean mutationBusy(){return AndroidVpnMutationGuard.isBusy(this);}
 JSONObject activeBundle()throws Exception{return new JSONObject(ConnectionProfilesHarness.text(nodeStore.file(nodeStore.activeId())));}
 JSONObject selectedProfile(JSONObject bundle)throws Exception{return AndroidProfileSelection.selectedRouterProfile(bundle);}
 JSONObject activeRouterProfile(){try{return selectedProfile(activeBundle());}catch(Exception invalid){return null;}}
 void displayProtection(){refreshSettingsState();}void pressProtection(boolean enabled){setQuickKillSwitch(enabled);}
 PRODUCT_CONNECT
 PRODUCT_PROTECTION
}
final class LayeredVpnService {static Boolean lockdown;static Boolean currentLockdownState(){return lockdown;}}
final class AndroidUnifiedNodeCatalog {static final class Item{final String id;Item(String id){this.id=id;}boolean isRouterVpn(){return false;}}}
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
  JSONObject p=policy("home").put("id",name).put("name",name).put("node_proof_id",proof).put("api_token","fixture-api-"+name).put("socks_password","fixture-socks-"+name)
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
  void row(JSONObject value)throws Exception{Files.writeString(rows.toPath(),new JSONObject().put("schema_version",5).put("profiles",new JSONArray().put(value)).toString());}
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
 static void ordinaryTorRoundtrip(Path root)throws Exception{
  for(String protocol:List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn")){
   Fixture f=new Fixture(root);var entry=ordinary(protocol,"ordinary-"+protocol);f.exits.save(entry);var exit=f.exits.get("external-b");exit.startupMode="last";exit.autoConnect=true;exit.torPolicy.put("manual_mtu",1320);f.exits.save(exit);
   String originalEntry=AndroidStandardExitStore.snapshot(entry),originalExit=AndroidStandardExitStore.snapshot(exit),routerBytes=text(f.first.file);f.store.selectOrdinaryTorPath(exit,entry);var saved=f.store.add("Ordinary "+protocol+" to Tor");JSONObject row=f.row();
   check(f.rows().getInt("schema_version")==5&&row.getString("multihop_entry_kind").equals("external")&&row.getString("multihop_entry_mode").equals(AndroidExternalPolicy.protocol(protocol)),"ordinary schema/kind/canonical transport not captured");
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
  for(int schema:new int[]{2,3,4}){Fixture f=new Fixture(root);f.store.selectExternalPath(f.exits.get("external-b"),f.first,"wg");var saved=f.store.add("Legacy private entry");JSONObject rows=f.rows();rows.put("schema_version",schema);rows.getJSONArray("profiles").getJSONObject(0).remove("multihop_entry_kind");Files.writeString(f.rows.toPath(),rows.toString());f.otherSelection();f.store.load(saved.id);var path=f.store.currentExternalPath("external-b");check(f.rows().getInt("schema_version")==5&&path.ordinaryEntry==null&&path.entry.id.equals(f.first.id),"legacy Router entry was reinterpreted during schema migration");}
  Fixture future=new Fixture(root);future.store.add("Future schema");Files.writeString(future.rows.toPath(),future.rows().put("schema_version",6).toString());State before=new State(future);rejected(()->future.store.list(),"future profile schema");before.same(future,"future schema must not rewrite");
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
  Files.delete(f.rows.toPath());Files.writeString(f.context.getFilesDir().toPath().resolve("connection-profiles-v1.json"),new JSONObject().put("schema_version",1).put("profiles",new JSONArray().put(old)).toString());f.otherSelection();f.store.load(saved.id);check(f.rows().getInt("schema_version")==5&&!Files.exists(f.context.getFilesDir().toPath().resolve("connection-profiles-v1.json"))&&AndroidStandardExitStore.snapshot(f.exits.get(exit.id)).equals(current),"schema1 path migration preserves selection-only external semantics");
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
 public static void main(String[] args)throws Exception{Path root=Path.of(args[0]);if(args.length>1&&args[1].equals("concurrency")){concurrentExternalEditors(root);return;}quickProtection(root);if(args.length>1){System.out.println("Android captured quick protection: "+checks+" checks passed");return;}ordinaryTorRoundtrip(root);ordinaryTorInvalid(root);ordinaryTorRollback(root);ordinarySchemaMigration(root);externalRoundtrip(root,false);externalRoundtrip(root,true);externalExecution(root);torExecutionProfiles(root);torPaddingProfiles(root);mappedOpenVPNProfiles(root);externalDefaultHome(root);externalStartup(root);torJumboProfiles(root);routerRoundtrip(root);routerLegacyPolicy(root);for(String fault:List.of("node","external","preferences","rollback"))rollback(root,fault);invalidBeforeMutation(root);evidenceAndLegacy(root);activeSelectionEdges(root);busyAndSelectionFailure(root);concurrentExternalEditors(root);strictRawImport(root);System.out.println("Android actual profile/node/exit stores: "+checks+" checks across "+cases+" isolated cases passed");}
}
'''


def main():
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file():
        raise RuntimeError("Real Android JSON implementation required")
    if not shutil.which("go"):
        raise RuntimeError("Go is required for actual AWG profile validation")
    with tempfile.TemporaryDirectory(prefix="android-connection-profiles-", dir=ROOT) as work:
        work = Path(work)
        module = next(line.split()[1] for line in (ROOT / "go.mod").read_text().splitlines() if line.startswith("module "))
        compiler = work / "compiler"
        (work / "main.go").write_text(GO.replace("router-vpn/internal/", module + "/internal/"))
        subprocess.run(["go", "build", "-o", str(compiler), str(work / "main.go")], cwd=ROOT, check=True, timeout=120)
        src = work / "src"
        for name, content in STUBS.items():
            target = src / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        app = src / "com/eabusham/routervpn"
        app.mkdir(parents=True)
        for name in ("AndroidExternalProtection", "AndroidKillSwitchPolicy", "AndroidConnectionProfileStore", "AndroidConnectionProfilePolicy", "AndroidNodeStore", "AndroidStandardExitStore", "AndroidProfileSelection", "AndroidNumericAddress", "AndroidExternalAmnezia", "AndroidOpenVPN"):
            shutil.copyfile(JAVA / (name + ".java"), app / (name + ".java"))
        methods = "\n".join(method("AndroidExternalPolicy.java", signature) for signature in ("static boolean supports(", "static String protocol(", "static void checkPolicy("))
        policy_source = (JAVA / "AndroidExternalPolicy.java").read_text(encoding="utf-8")
        policy_fields = policy_source[policy_source.index("    private static final Set<String> POLICY"):policy_source.index("\n\n    static boolean supports", policy_source.index("    private static final Set<String> POLICY"))]
        (app / "Boundaries.java").write_text(BOUNDARIES.replace("EXTERNAL_METHODS", methods).replace("EXTERNAL_POLICY_FIELDS", policy_fields), encoding="utf-8")
        protection = "\n".join(method("ProductActivity.java", signature) for signature in ("private boolean isExternalSelected(", "private void setQuickKillSwitch(", "private void refreshSettingsState("))
        (app / "ProductConnectSurface.java").write_text(PRODUCT.replace("PRODUCT_CONNECT", method("ProductActivity.java", "private void connectOrDisconnect(")).replace("PRODUCT_PROTECTION", protection), encoding="utf-8")
        (app / "ConnectionProfilesHarness.java").write_text(HARNESS)
        classes = work / "classes"
        subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(classes), *map(str, src.rglob("*.java"))], check=True, timeout=60)
        data = work / "data"
        data.mkdir()
        env = os.environ.copy(); env["ROUTERVPN_PROFILE_COMPILER"] = str(compiler);env["ROUTERVPN_OPENVPN_MULTIHOST_CLIENT_FIXTURE"] = str(ROOT/"deploy/fixtures/external-openvpn-multihost-client.json");env["ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_AES_FIXTURE"] = str(ROOT/"deploy/fixtures/external-openvpn-multihost-layered-aes-client.json");env["ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_XOR_FIXTURE"] = str(ROOT/"deploy/fixtures/external-openvpn-multihost-layered-xor-client.json")
        subprocess.run(["java", "-cp", str(classes) + os.pathsep + str(jar), "com.eabusham.routervpn.ConnectionProfilesHarness", str(data)], env=env, check=True, timeout=180)
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
