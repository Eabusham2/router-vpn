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
}

BOUNDARIES = r'''package com.eabusham.routervpn;
import org.json.*;import java.util.*;import java.io.*;import java.nio.file.*;
final class AndroidPrivateFileStore {
 static String failPath="";static int failures;static int writes;
 static void ensurePrivateDirectory(File file)throws Exception{Files.createDirectories(file.toPath());}
 static byte[] read(File file,int max)throws Exception{byte[] bytes=Files.readAllBytes(file.toPath());if(bytes.length==0||bytes.length>max)throw new IOException("bad size");return bytes;}
 static void write(File file,byte[] bytes,int max)throws Exception{if(bytes.length==0||bytes.length>max)throw new IOException("bad size");Files.createDirectories(file.getParentFile().toPath());Files.write(file.toPath(),bytes);writes++;if(failures>0&&file.getAbsolutePath().equals(failPath)){failures--;throw new IOException("injected post-publication failure");}}
 static void remove(File file,int max)throws Exception{Files.deleteIfExists(file.toPath());}
}
final class AndroidStartupPolicy {static void cancelPending(){}}
final class AndroidVpnMutationGuard {static boolean busy;static boolean isBusy(android.content.Context context){return busy;}}
final class AndroidHomeStateStore {static final class Snapshot{boolean connected;String phase="off";}static Snapshot snapshot(android.content.Context c){return new Snapshot();}}
final class AndroidRuntimeRegistry {
 static final class Engine{boolean isRunning(){return false;}boolean isActiveOrTransitioning(){return false;}String getState(){return "DOWN";}}
 final Engine orchestrator=new Engine(),multihop=new Engine(),singBox=new Engine(),xray=new Engine();static AndroidRuntimeRegistry get(android.content.Context c){return new AndroidRuntimeRegistry();}
}
final class AndroidOpenVPN {static JSONObject endpoint(AndroidStandardExitStore.Entry entry,String detour){throw new AssertionError("OpenVPN compiler is outside the persistence fixture");}}
final class AndroidExternalAmnezia {static JSONObject endpoint(AndroidStandardExitStore.Entry entry){throw new AssertionError("AWG compiler is outside the persistence fixture");}}
final class AndroidTorProfile {
 static boolean isTor(String protocol){return "tor".equals(protocol)||"tor-bridge".equals(protocol);}
 // Compiler boundary only. The actual Tor form/profile tests exercise shared Go validation.
 static void validate(AndroidStandardExitStore.Entry exit)throws Exception{AndroidConnectionProfilePolicy.external(exit.torPolicy,exit.protocol);if("tor-bridge".equals(exit.protocol)&&exit.torBridges.isEmpty())throw new IllegalArgumentException("missing bridge");}
}
final class AndroidExternalPolicy {
 private static final Set<String> POLICY=new HashSet<>(Arrays.asList("dns_mode","dns_protocol","dns_host","dns_port","dns_server_name","dns_path","fastest_dns_host","fastest_dns_latency_ms","dns_results","dns_bootstrap","ipv6_mode","home_lan_access","home_lan_cidrs","mtu_policy","manual_mtu","effective_mtu","start_layer"));
 static final int MAX_CAPTURE=8*1024*1024;static boolean bounded(String value,int max){return value!=null&&!value.isEmpty()&&value.length()<=max;}
 EXTERNAL_METHODS
}
'''

PRODUCT = r'''package com.eabusham.routervpn;
import android.content.*;import java.util.*;
// Only UI rendering and runtime dispatch are doubled. The shipping handler reads
// the same actual profile/node/exit stores used by the persistence regression.
final class ProductConnectSurface extends Context {
 static final String MULTI_ENTRY="multihop_entry",MULTI_EXIT="multihop_exit",MULTI_MODE="multihop_exit_mode";
 final ConnectionProfilesHarness.Fixture fixture;final AndroidNodeStore nodeStore;final AndroidStandardExitStore exitStore;
 static final class View{void setText(String value){}boolean isChecked(){return false;}}
 final View statusView=new View(),connectButton=new View(),multihopToggle=new View();String message="";
 static final class Probe{boolean isBusy(){return false;}}final Probe viaEntryProbe=new Probe();
 static final class Connection{
  int starts;boolean direct;AndroidNodeStore.Node entry;AndroidStandardExitStore.Entry exit;String mode,execution;
  boolean cancelStartupPending(){return false;}boolean isActiveOrTransitioning(){return false;}void disconnect(Object callback){throw new AssertionError("unexpected disconnect");}
  void connectExternal(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,boolean direct,String mode,String execution,Object callback){starts++;this.entry=entry;this.exit=exit;this.direct=direct;this.mode=mode;this.execution=execution;}
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
 PRODUCT_CONNECT
}
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
  void row(JSONObject value)throws Exception{Files.writeString(rows.toPath(),new JSONObject().put("schema_version",4).put("profiles",new JSONArray().put(value)).toString());}
 }
 static final class State {
  final Map<String,byte[]> files=new TreeMap<>();final Map<String,Map<String,?>> preferences=new TreeMap<>();
  State(Fixture f)throws Exception{try(var paths=Files.walk(f.context.getFilesDir().toPath())){for(Path p:paths.filter(Files::isRegularFile).toList())files.put(p.toString(),Files.readAllBytes(p));}for(var e:f.context.preferences.entrySet())preferences.put(e.getKey(),e.getValue().getAll());}
  void same(Fixture f,String label)throws Exception{State after=new State(f);check(files.keySet().equals(after.files.keySet()),label+" files");for(String key:files.keySet())check(Arrays.equals(files.get(key),after.files.get(key)),label+" byte rollback "+key);check(preferences.equals(after.preferences),label+" all preference rollback");}
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
  for(String protocol:List.of("shadowsocks","hysteria2","socks5","http","https"))for(String layer:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))for(String execution:List.of("local","server","auto")){
   Fixture f=new Fixture(root);AndroidStandardExitStore.Entry exit=external("paired-"+protocol,false);exit.protocol=protocol;exit.tlsServerName="exit.example.test";exit.method="2022-blake3-aes-256-gcm";exit.secret=Base64.getEncoder().encodeToString(new byte[32]);exit.responseProbe=new JSONObject().put("url","https://198.51.100.8:8443/response").put("server_name","paired.example.test");if(!layer.equals("off")){exit.policy.put("start_layer",layer);exit.startLayer=new JSONObject().put("mode",layer).put("api","http://10.99.0.1:8787").put("transport",new JSONObject().put("type","shadowsocks").put("tag","provisioned-exit-layer").put("server",exit.server).put("server_port",8388).put("method","2022-blake3-aes-256-gcm").put("password",Base64.getEncoder().encodeToString("L".repeat(32).getBytes(StandardCharsets.UTF_8))));}f.exits.save(exit);
   f.store.selectExternalPath(exit,f.first,"hysteria2",execution);var saved=f.store.add("paired execution");String secret=exit.secret;check(!text(f.rows).contains(secret)&&!text(f.rows).contains("response_probe"),"connection choices duplicated private node material");
   if(!layer.equals("off"))check(!text(f.rows).contains(exit.startLayer.getJSONObject("transport").getString("password"))&&!text(f.rows).contains("10.99.0.1")&&f.store.list().get(0).startLayer.equals(layer),"saved layer choice leaked its private provisioned transport");
   f.otherSelection();f.store.load(saved.id);var selected=f.store.currentExternalPath(exit.id);check(selected.execution.equals(execution)&&selected.entry.id.equals(f.first.id),"profile load discarded external execution choice");
   ProductConnectSurface surface=new ProductConnectSurface(f);surface.pressConnect();check(surface.connection.starts==1&&surface.connection.execution.equals(execution),"main Connect discarded external execution");
   AndroidStandardExitStore.Entry copied=AndroidStandardExitStore.copy(exit);copied.responseProbe.put("url","https://198.51.100.8/changed");check(!copied.responseProbe.toString().equals(exit.responseProbe.toString()),"response endpoint aliases saved credentials");
   if(!execution.equals("local")){State before=new State(f);rejected(()->f.store.selectExternalPath(exit,null,"wg",execution),"direct path server owner");before.same(f,"direct execution rejection");}
   if(!layer.equals("off")){
    AndroidStandardExitStore.Entry changed=AndroidStandardExitStore.copy(exit);String other=layer.equals("aes-256-gcm")?"aes-256-gcm+xor-whitening":"aes-256-gcm";changed.policy.put("start_layer",other);changed.startLayer.put("mode",other);f.exits.save(changed);
    State before=new State(f);rejected(()->f.store.load(saved.id),"saved choice cannot replace a different provisioned private layer");before.same(f,"mismatched layer profile restoration");
   }
  }
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
  Files.delete(f.rows.toPath());Files.writeString(f.context.getFilesDir().toPath().resolve("connection-profiles-v1.json"),new JSONObject().put("schema_version",1).put("profiles",new JSONArray().put(old)).toString());f.otherSelection();f.store.load(saved.id);check(f.rows().getInt("schema_version")==4&&!Files.exists(f.context.getFilesDir().toPath().resolve("connection-profiles-v1.json"))&&AndroidStandardExitStore.snapshot(f.exits.get(exit.id)).equals(current),"schema1 path migration preserves selection-only external semantics");
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
 public static void main(String[] args)throws Exception{Path root=Path.of(args[0]);externalRoundtrip(root,false);externalRoundtrip(root,true);externalExecution(root);externalDefaultHome(root);externalStartup(root);routerRoundtrip(root);routerLegacyPolicy(root);for(String fault:List.of("node","external","preferences","rollback"))rollback(root,fault);invalidBeforeMutation(root);evidenceAndLegacy(root);activeSelectionEdges(root);busyAndSelectionFailure(root);System.out.println("Android actual profile/node/exit stores: "+checks+" checks across "+cases+" isolated cases passed");}
}
'''


def main():
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file():
        raise RuntimeError("Real Android JSON implementation required")
    with tempfile.TemporaryDirectory(prefix="android-connection-profiles-") as work:
        work = Path(work)
        src = work / "src"
        for name, content in STUBS.items():
            target = src / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        app = src / "com/eabusham/routervpn"
        app.mkdir(parents=True)
        for name in ("AndroidConnectionProfileStore", "AndroidConnectionProfilePolicy", "AndroidNodeStore", "AndroidStandardExitStore", "AndroidProfileSelection", "AndroidNumericAddress"):
            shutil.copyfile(JAVA / (name + ".java"), app / (name + ".java"))
        methods = "\n".join(method("AndroidExternalPolicy.java", signature) for signature in ("static boolean supports(", "static void checkPolicy("))
        (app / "Boundaries.java").write_text(BOUNDARIES.replace("EXTERNAL_METHODS", methods))
        (app / "ProductConnectSurface.java").write_text(PRODUCT.replace("PRODUCT_CONNECT", method("ProductActivity.java", "private void connectOrDisconnect(")))
        (app / "ConnectionProfilesHarness.java").write_text(HARNESS)
        classes = work / "classes"
        subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(classes), *map(str, src.rglob("*.java"))], check=True, timeout=60)
        data = work / "data"
        data.mkdir()
        subprocess.run(["java", "-cp", str(classes) + os.pathsep + str(jar), "com.eabusham.routervpn.ConnectionProfilesHarness", str(data)], check=True, timeout=60)


if __name__ == "__main__":
    main()
