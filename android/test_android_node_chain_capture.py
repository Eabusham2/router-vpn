#!/usr/bin/env python3
"""Execute complete ordered Android sources and saved choices with real Go compilers.

Android storage and SharedPreferences use the existing publication fault harness.
The Libbox Java boundary invokes the shipping pure Go constructors; it never runs
a native service or claims Android TUN, encrypted traffic, or device acceptance.
The full connection-profile suite also runs this family automatically.
"""
from pathlib import Path
import json
import os
import shutil
import subprocess


def compiler_source(source):
    cases = r'''case len(args)==6&&args[0]=="chain-member":var node *mobilemultihop.NodeProfile;node,err=mobilemultihop.NewNodeProfile(args[1],args[2],args[3],args[4],args[5]);if err==nil{result,err=node.LaunchInput()};case len(args)==2&&args[0]=="chain-new":var chain *mobilemultihop.NodeChain;chain,err=mobilemultihop.NewNodeChain(args[1]);if err==nil{result,err=chain.LaunchInput()};case len(args)==2&&(args[0]=="chain-replay"||args[0]=="chain-config"):var chain *mobilemultihop.NodeChain;chain,err=mobilemultihop.ParseNodeChainLaunchInput(args[1]);if err==nil{if args[0]=="chain-config"{result=chain.Config()}else{result,err=chain.LaunchInput()}};'''
    assert source.count("case len(args)==2:") == 1
    return source.replace("case len(args)==2:", cases + "case len(args)==2:")


GENERATOR = r'''package mobilemultihop
import("encoding/json";"os";"testing";"fmt")
func TestAndroidOrderedSourceFixture(t *testing.T){
 result:=map[string]any{}
 for _,test:=range []struct{count int;layer string}{{2,""},{3,""},{4,""},{8,""},{3,"aes-256-gcm"},{4,"aes-256-gcm+xor-whitening"},{4,"fixed-middle"}}{
  layer:=test.layer;if layer=="fixed-middle"{layer=""}
  nodes:=nodeChainFixtureNodes(t,test.count,layer)
  selected:=[]map[string]string{}
  for _,node:=range nodes{selected=append(selected,map[string]string{"id":node.profile["id"].(string),"mode":node.mode})}
  bundles:=[]any{}
  for position,node:=range nodes{
   var profile map[string]any;var files map[string]string
   if err:=json.Unmarshal([]byte(node.inputs.ProfileJSON),&profile);err!=nil{t.Fatal(err)}
   if err:=json.Unmarshal([]byte(node.inputs.Files),&files);err!=nil{t.Fatal(err)}
   profile["schema_version"],profile["kill_switch"],profile["kill_switch_policy"]=4,true,"on-connect"
   if test.layer=="fixed-middle"&&position==1{profile["mtu_policy"],profile["manual_mtu"]="manual",1408}
   if position==len(nodes)-1{profile["multihop_enabled"],profile["multihop_execution"],profile["multihop_nodes"]=true,"local",selected}
   assets:=map[string]any{node.mode:files}
   if node.inputs.Start!=""{var start map[string]string;if err:=json.Unmarshal([]byte(node.inputs.Start),&start);err!=nil{t.Fatal(err)};assets["shadowsocks"]=start}
   bundles=append(bundles,map[string]any{"profileSchemaVersion":4,"selectedRouterID":profile["id"],"nodeProofId":profile["node_proof_id"],"routerProfiles":[]any{profile},"profiles":assets,"modes":[]any{map[string]string{"id":node.mode}}})
  }
  result[fmt.Sprintf("%d/%s",test.count,test.layer)]=bundles
 }
 raw,err:=json.Marshal(result);if err!=nil{t.Fatal(err)}
 if err=os.WriteFile(os.Getenv("ROUTERVPN_ANDROID_CHAIN_FIXTURE"),raw,0600);err!=nil{t.Fatal(err)}
}
'''

NATIVE = r'''package io.nekohasekai.libbox;
public final class RouterNodeChain {
 private final String input;private boolean closed;
 RouterNodeChain(String input){this.input=input;}
 public String launchInput()throws Exception{if(closed)throw new IllegalStateException("retired pure compiler handle");return input;}
 public String config()throws Exception{return Libbox.call("chain-config",launchInput());}
 public String sourceSHA256()throws Exception{return new org.json.JSONObject(launchInput()).getString("source_sha256");}
 public String configSHA256()throws Exception{return new org.json.JSONObject(launchInput()).getString("config_sha256");}
 public void close(){closed=true;}
}
'''

HARNESS = r'''package com.eabusham.routervpn;
import android.content.Context;import android.content.MemoryPreferences;import org.json.*;
import java.io.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.util.*;
public final class NodeChainCaptureHarness {
 static int checks;
 interface Checked{void run()throws Exception;}
 static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
 static void reject(Checked operation,String message)throws Exception{try{operation.run();}catch(Exception expected){checks++;return;}throw new AssertionError(message);}
 static final class Fixture {
  final Context context;final AndroidNodeStore nodes;final AndroidConnectionProfileStore profiles;final MemoryPreferences prefs;
  final List<AndroidNodeStore.Node> members=new ArrayList<>();final List<JSONObject> original=new ArrayList<>();final Path rows;
  Fixture(Path root,String key)throws Exception{
   context=new Context(Files.createTempDirectory(root,"ordered-").toFile());nodes=new AndroidNodeStore(context);
   profiles=new AndroidConnectionProfileStore(context,nodes,new AndroidStandardExitStore(context));prefs=context.getSharedPreferences("router-vpn-unified",0);
   rows=context.getFilesDir().toPath().resolve("connection-profiles-v4.json");
   JSONArray bundles=new JSONObject(Files.readString(Path.of(System.getenv("ROUTERVPN_ANDROID_CHAIN_FIXTURE")))).getJSONArray(key);
   for(int i=0;i<bundles.length();i++){JSONObject bundle=bundles.getJSONObject(i);original.add(new JSONObject(bundle.toString()));members.add(nodes.importBundle(bundle.toString().getBytes(StandardCharsets.UTF_8)));}
   JSONArray selected=AndroidNodeStore.orderedSelection(profile(original.get(original.size()-1)));
   prefs.edit().putString("selected_kind","router-vpn").putString("selected_id",control().id).putString("mode","smart-auto")
    .putBoolean("multihop_on",true).putString("multihop_nodes",selected.toString()).putString("multihop_execution","local").putString("multihop_entry_kind","router-vpn")
    .putString("multihop_entry","").putString("multihop_exit","").putString("multihop_entry_mode","").putString("multihop_exit_mode","").commit();
  }
  AndroidNodeStore.Node control(){return members.get(members.size()-1);}
  JSONObject bundle(int position)throws Exception{return new JSONObject(Files.readString(members.get(position).file.toPath()));}
  void replace(int position,JSONObject bundle)throws Exception{nodes.importBundle(bundle.toString().getBytes(StandardCharsets.UTF_8));}
  JSONObject row()throws Exception{return new JSONObject(Files.readString(rows)).getJSONArray("profiles").getJSONObject(0);}
  void row(JSONObject row,int schema)throws Exception{Files.writeString(rows,new JSONObject().put("schema_version",schema).put("profiles",new JSONArray().put(row)).toString());}
  void changePolicies()throws Exception{
   for(int i=0;i<members.size();i++){JSONObject bundle=bundle(i);profile(bundle).put("home_lan_access",false).put("mtu_policy","fixed").put("manual_mtu",1400);replace(i,bundle);}
   nodes.select(members.get(0).id);prefs.edit().putString("selected_id",members.get(0).id).putBoolean("multihop_on",false).putString("multihop_nodes","").commit();
  }
 }
 static JSONObject profile(JSONObject bundle){return AndroidProfileSelection.selectedRouterProfile(bundle);}
 static final class State {
  final Map<Path,byte[]> files=new LinkedHashMap<>();final Map<String,Map<String,?>> preferences=new LinkedHashMap<>();
  State(Fixture f)throws Exception{try(var paths=Files.walk(f.context.getFilesDir().toPath())){for(Path path:paths.filter(Files::isRegularFile).toList())files.put(path,Files.readAllBytes(path));}for(var e:f.context.preferences.entrySet())preferences.put(e.getKey(),e.getValue().getAll());}
  void same(Fixture f,String why)throws Exception{State actual=new State(f);check(files.keySet().equals(actual.files.keySet()),why+" changed file inventory");for(Path path:files.keySet())check(Arrays.equals(files.get(path),actual.files.get(path)),why+" lost exact file rollback");check(preferences.equals(actual.preferences),why+" lost selected preferences");}
 }
 static void roundtrip(Path root,String key)throws Exception{
  Fixture f=new Fixture(root,key);AndroidNodeStore.ChainCapture source=f.profiles.currentOrderedPath();
  check(source.control==source.members.get(source.members.size()-1),"original control was substituted");
  byte[] mutable=source.members.get(0).bytes();mutable[0]=0;source.requireCurrent();
  reject(()->source.members.clear(),"member list is mutable");reject(()->source.modes.clear(),"mode list is mutable");
  try(AndroidNodeChainCapture capture=AndroidNodeChainCapture.compile(source)){
   JSONObject config=new JSONObject(capture.config),launch=new JSONObject(capture.launchInput);
   check(config.getJSONArray("inbounds").length()==1&&config.getJSONArray("endpoints").length()==source.members.size()-1,"ordered graph lost one TUN or a WireGuard prefix");
   check(launch.getJSONArray("nodes").length()==source.members.size()&&capture.strict,"native compile dropped a member or protection policy");
   if(key.equals("4/fixed-middle"))check(config.getJSONArray("endpoints").getJSONObject(1).getInt("mtu")==1408&&capture.finalProfile().getString("mtu_policy").equals("auto"),"Fixed middle endpoint replaced the final Auto policy");
   for(int i=0;i<source.members.size();i++){
    JSONObject input=new JSONObject(launch.getJSONArray("nodes").getString(i));JSONObject p=new JSONObject(input.getString("profile_json"));
    check(p.getString("id").equals(source.members.get(i).profileId)&&p.getString("api_token").equals(profile(f.original.get(i)).getString("api_token")),"native capture borrowed another member token or position");
   }
   try(AndroidNodeChainCapture reopened=AndroidNodeChainCapture.reopen(capture.launchInput,source)){check(reopened.launchInput.equals(capture.launchInput)&&reopened.config.equals(capture.config),"canonical source did not replay");}
   JSONObject missing=new JSONObject(capture.launchInput);JSONArray cut=new JSONArray();for(int i=0;i<source.members.size();i++)if(i!=0)cut.put(launch.getJSONArray("nodes").get(i));missing.put("nodes",cut);
   reject(()->AndroidNodeChainCapture.reopen(missing.toString(),source),"altered launch adopted a partial chain");
  }
  var saved=f.profiles.add("Complete "+key);JSONObject row=f.row();
  check(row.getJSONArray("multihop_nodes").length()==source.members.size(),"saved path truncated ordered members");
  String serialized=Files.readString(f.rows);check(!serialized.contains("api_token")&&!serialized.contains("captured-chain-token")&&!serialized.contains("wg.conf")&&!serialized.contains("sing-box.json"),"saved choices duplicated private source material");
  f.changePolicies();f.profiles.load(saved.id);
  check(f.profiles.currentOrderedPath().members.size()==source.members.size(),"load did not restore every ordered reference");
  for(int i=0;i<f.members.size();i++){
   JSONObject restored=f.bundle(i),original=f.original.get(i);
   check(profile(restored).getBoolean("home_lan_access"),"saved middle policy was dropped");
   check(profile(restored).getString("mtu_policy").equals(profile(original).getString("mtu_policy")),"saved member MTU choice was dropped");
   if(profile(original).has("manual_mtu"))check(profile(restored).getInt("manual_mtu")==profile(original).getInt("manual_mtu"),"saved middle Fixed capacity was replaced");
   check(ConnectionProfilesHarness.sameJSONValue(restored.get("profiles"),original.get("profiles"))&&profile(restored).getString("api_token").equals(profile(original).getString("api_token")),"load replaced original credentials or member assets");
  }
  f.changePolicies();State before=new State(f);AndroidPrivateFileStore.failPath=f.members.get(f.members.size()/2).file.getAbsolutePath();AndroidPrivateFileStore.failures=1;
  try{reject(()->f.profiles.load(saved.id),"middle publication failure was accepted");before.same(f,"middle publication failure");}finally{AndroidPrivateFileStore.failPath="";AndroidPrivateFileStore.failures=0;}
 }
 static void sourceControls(Path root)throws Exception{
  Fixture f=new Fixture(root,"3/");AndroidNodeStore.ChainCapture captured=f.profiles.currentOrderedPath();
  byte[] original=Files.readAllBytes(f.members.get(1).file.toPath());JSONObject changed=f.bundle(1);profile(changed).put("api_token","newer-original-private-token");Files.writeString(f.members.get(1).file.toPath(),changed.toString());
  reject(captured::requireCurrent,"ordered capture accepted replacement middle source");Files.write(f.members.get(1).file.toPath(),original);
  captured=f.profiles.currentOrderedPath();Files.delete(f.members.get(1).file.toPath());reject(captured::requireCurrent,"ordered capture accepted a missing middle source");Files.write(f.members.get(1).file.toPath(),original);
 }
 static void generationControls(Path root)throws Exception{
  Fixture f=new Fixture(root,"3/");AndroidNodeStore.ChainCapture captured=f.profiles.currentOrderedPath();JSONObject original=f.bundle(1),changed=new JSONObject(original.toString());profile(changed).put("api_token","transient-private-token");
  f.replace(1,changed);f.replace(1,original);f.nodes.select(f.control().id);
  reject(captured::requireCurrent,"ordered capture revived after change-away and back");
  captured=f.profiles.currentOrderedPath();f.nodes.select(f.members.get(0).id);f.nodes.select(f.control().id);
  reject(captured::requireCurrent,"ordered capture revived after selection-away and back");
 }
 static void validationControls(Path root)throws Exception{
  for(String fault:List.of("missing-middle","duplicate-middle","unknown-mode","pair-field","wrong-control","server-execution","imported","extra-member-field","missing-selected-id","one","nine")){
   Fixture f=new Fixture(root,"3/");JSONObject rootBundle=f.bundle(2),control=profile(rootBundle);JSONArray refs=control.getJSONArray("multihop_nodes");
   switch(fault){case "missing-middle":refs.getJSONObject(1).put("id","missing-node");break;case "duplicate-middle":refs.getJSONObject(1).put("id",refs.getJSONObject(0).getString("id"));break;
    case "unknown-mode":refs.getJSONObject(1).put("mode","not-generated");break;case "pair-field":control.put("multihop_entry_id","legacy");break;case "wrong-control":refs.getJSONObject(2).put("id","another-control");break;
    case "server-execution":control.put("multihop_execution","server");break;case "imported":control.put("node_kind","external");break;case "extra-member-field":refs.getJSONObject(1).put("token","other");break;
    case "missing-selected-id":rootBundle.remove("selectedRouterID");break;case "one":control.put("multihop_nodes",new JSONArray().put(refs.getJSONObject(2)));break;case "nine":for(int i=3;i<9;i++)refs.put(new JSONObject().put("id","extra-"+i).put("mode","wg"));break;}
   Files.writeString(f.control().file.toPath(),rootBundle.toString());Files.writeString(new File(f.context.getFilesDir(),AndroidNodeStore.ACTIVE_BUNDLE).toPath(),rootBundle.toString());
   reject(()->f.nodes.captureChain(f.control().id),"ordered source accepted "+fault);
  }
  for(String fault:List.of("old-schema","missing-policy","duplicate-local","wrong-final-policy","secret","pair","wrong-final-id","numeric-mode","zero","nine")){
   Fixture f=new Fixture(root,"3/");var saved=f.profiles.add("All original nodes");JSONObject row=f.row();JSONArray refs=row.getJSONArray("multihop_nodes");int schema=7;
   switch(fault){case "old-schema":schema=6;break;case "missing-policy":refs.getJSONObject(1).remove("policy");break;case "duplicate-local":refs.getJSONObject(1).put("node_id",refs.getJSONObject(0).getString("node_id"));break;
    case "wrong-final-policy":refs.getJSONObject(2).getJSONObject("policy").put("kill_switch_policy","off");break;case "secret":refs.getJSONObject(1).getJSONObject("policy").put("api_token","private");break;case "pair":row.put("multihop_entry_id","old-entry");break;
    case "wrong-final-id":row.put("node_id",f.members.get(0).id);break;case "numeric-mode":refs.getJSONObject(1).put("mode",7);break;case "zero":row.put("multihop_nodes",new JSONArray());break;case "nine":for(int i=3;i<9;i++)refs.put(refs.getJSONObject(0));break;}
   f.row(row,schema);State before=new State(f);reject(()->f.profiles.load(saved.id),"saved ordered row accepted "+fault);before.same(f,"invalid ordered row "+fault);
  }
 }
 static void compilationRace(Path root)throws Exception{
  Fixture f=new Fixture(root,"3/");AndroidNodeStore.ChainCapture source=f.profiles.currentOrderedPath();
  io.nekohasekai.libbox.Libbox.afterChainMember=()->{try{JSONObject changed=f.bundle(1);profile(changed).put("api_token","replaced-during-compile");f.replace(1,changed);f.nodes.select(f.control().id);}catch(Exception error){throw new IllegalStateException(error);}};
  try{reject(()->AndroidNodeChainCapture.compile(source),"native compilation adopted a changed middle source");}finally{io.nekohasekai.libbox.Libbox.afterChainMember=null;}
 }
 static void captureAtomicity(Path root)throws Exception{
  Fixture f=new Fixture(root,"3/");AndroidNodeStore independent=new AndroidNodeStore(f.context);
  var reading=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);var starting=new java.util.concurrent.CountDownLatch(1);var published=new java.util.concurrent.CountDownLatch(1);
  var once=new java.util.concurrent.atomic.AtomicBoolean();var captureFailure=new java.util.concurrent.atomic.AtomicReference<Throwable>();var writerFailure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
  JSONObject changed=f.bundle(1);profile(changed).put("api_token","independent-newer-source");
  AndroidPrivateFileStore.orderedRead=file->{if(file.equals(f.control().file)&&Thread.currentThread().getName().equals("ordered-capture")&&once.compareAndSet(false,true)){reading.countDown();try{if(!release.await(3,java.util.concurrent.TimeUnit.SECONDS))throw new AssertionError("capture read was not released");}catch(InterruptedException e){throw new IllegalStateException(e);}}};
  AndroidPrivateFileStore.beforeWrite=()->{if(Thread.currentThread().getName().equals("ordered-publisher"))published.countDown();};
  Thread capture=new Thread(()->{try{f.nodes.captureChain(f.control().id);}catch(Throwable e){captureFailure.set(e);}},"ordered-capture");
  Thread writer=new Thread(()->{starting.countDown();try{independent.importBundle(changed.toString().getBytes(StandardCharsets.UTF_8));}catch(Throwable e){writerFailure.set(e);}},"ordered-publisher");
  boolean premature=false;
  try{capture.start();check(reading.await(2,java.util.concurrent.TimeUnit.SECONDS),"capture never reached its original private read");writer.start();check(starting.await(2,java.util.concurrent.TimeUnit.SECONDS),"independent publisher never started");premature=published.await(250,java.util.concurrent.TimeUnit.MILLISECONDS);}
  finally{release.countDown();capture.join(4000);writer.join(4000);AndroidPrivateFileStore.orderedRead=null;AndroidPrivateFileStore.beforeWrite=null;}
  check(!capture.isAlive()&&!writer.isAlive(),"ordered source fixture left an unjoined writer");
  check(!premature,"ordered capture did not exclude the independent store publisher");
  check(captureFailure.get()==null&&writerFailure.get()==null&&published.getCount()==0,"original capture or subsequent publisher failed");
 }
 public static void main(String[] args)throws Exception{
  Path root=Path.of(args[0]);String family=args.length>1?args[1]:"all";
  if(family.equals("source")){sourceControls(root);return;}if(family.equals("generation")){generationControls(root);return;}
  if(family.equals("atomic")){captureAtomicity(root);return;}
  if(family.equals("restore")){roundtrip(root,"3/");return;}
  for(String key:List.of("2/","3/","4/","8/","3/aes-256-gcm","4/aes-256-gcm+xor-whitening","4/fixed-middle"))roundtrip(root,key);
  sourceControls(root);generationControls(root);validationControls(root);compilationRace(root);captureAtomicity(root);
  System.out.println("Android ordered sources: "+checks+" checks; actual Go compilation, exact all-member saved capture and rollback passed");
 }
}
'''


def prepare_sources(src, app, java):
    shutil.copyfile(java / "AndroidNodeChainCapture.java", app / "AndroidNodeChainCapture.java")
    (app / "NodeChainCaptureHarness.java").write_text(HARNESS)
    libbox = src / "io/nekohasekai/libbox/Libbox.java"
    source = libbox.read_text()
    marker = "private static String call(String...args)throws Exception{"
    assert source.count(marker) == 1
    source = source.replace(marker, r'''public static Runnable afterChainMember;
public static String routerNodeChainMemberInput(String mode,String files,String profile,String start,String bootstrap)throws Exception{String value=call("chain-member",mode,files,profile,start,bootstrap);Runnable hook=afterChainMember;afterChainMember=null;if(hook!=null)hook.run();return value;}
public static RouterNodeChain newRouterNodeChain(String source)throws Exception{return new RouterNodeChain(call("chain-new",source));}
public static RouterNodeChain newRouterNodeChainLaunch(String source)throws Exception{return new RouterNodeChain(call("chain-replay",source));}
static String call(String...args)throws Exception{''')
    libbox.write_text(source)
    (src / "io/nekohasekai/libbox/RouterNodeChain.java").write_text(NATIVE)
    boundaries = app / "Boundaries.java"
    source = boundaries.read_text()
    marker = "static byte[] read(File file,int max)throws Exception{byte[] bytes=Files.readAllBytes(file.toPath());"
    assert source.count(marker) == 1
    source = source.replace(marker, "static volatile java.util.function.Consumer<File> orderedRead;\nstatic byte[] read(File file,int max)throws Exception{java.util.function.Consumer<File> hook=orderedRead;if(hook!=null)hook.accept(file);byte[] bytes=Files.readAllBytes(file.toPath());")
    boundaries.write_text(source)


def run(root, work, app, classes, jar, env):
    generator = work / "android_chain_fixture_test.go"
    generator.write_text(GENERATOR)
    overlay = work / "chain-fixture-overlay.json"
    overlay.write_text(json.dumps({"Replace": {str(root / "internal/mobilemultihop/android_chain_fixture_test.go"): str(generator)}}))
    env = env.copy()
    env["ROUTERVPN_ANDROID_CHAIN_FIXTURE"] = str(work / "private-chain-fixtures.json")
    subprocess.run(["go", "test", "-count=1", "-overlay=" + str(overlay), "./internal/mobilemultihop", "-run", "^TestAndroidOrderedSourceFixture$"], cwd=root, env=env, check=True, timeout=180)
    data = work / "ordered-data"
    data.mkdir()
    command = ["java", "-cp", str(classes) + os.pathsep + str(jar), "com.eabusham.routervpn.NodeChainCaptureHarness", str(data)]
    subprocess.run(command, env=env, check=True, timeout=180)
    node = (app / "AndroidNodeStore.java").read_text()
    store = (app / "AndroidConnectionProfileStore.java").read_text()
    source_guard = "!java.util.Arrays.equals(source.original, snapshotOptional(nodeFile(source.id)))"
    epoch_guard = "captured.generation != selectionGeneration"
    capture_lock = "synchronized ChainCapture captureChain(String controlId) throws Exception { synchronized (STORE_LOCK)"
    stage_start = store.index("    private void stageOrderedNodes(")
    stage_end = store.index("    private static JSONArray orderedReferences(", stage_start)
    stage = store[stage_start:stage_end]
    assert stage.count("for(int i=0;i<members.length();i++)") == 1
    controls = (
        ("source", "AndroidNodeStore", node.replace(source_guard, "false"), "ordered capture accepted replacement middle source"),
        ("generation", "AndroidNodeStore", node.replace(epoch_guard, "false"), "ordered capture revived after change-away and back"),
        ("atomic", "AndroidNodeStore", node.replace(capture_lock, capture_lock.replace("STORE_LOCK", "new Object()")), "ordered capture did not exclude the independent store publisher"),
        ("restore", "AndroidConnectionProfileStore", store[:stage_start] + stage.replace("for(int i=0;i<members.length();i++)", "for(int i=0;i<members.length();i+=2)") + store[stage_end:], "saved middle policy was dropped"),
    )
    assert node.count(source_guard) == node.count(epoch_guard) == node.count(capture_lock) == 1
    for family, name, changed, witness in controls:
        negative = work / ("ordered-negative-" + family)
        shutil.copytree(classes, negative)
        source = work / ("ordered-source-" + family) / (name + ".java")
        source.parent.mkdir()
        source.write_text(changed)
        classpath = str(negative) + os.pathsep + str(jar)
        subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", classpath, "-d", str(negative), str(source)], check=True, timeout=60)
        result = subprocess.run(["java", "-cp", classpath, "com.eabusham.routervpn.NodeChainCaptureHarness", str(data), family], env=env, capture_output=True, text=True, timeout=180)
        if result.returncode == 0 or witness not in result.stderr:
            raise AssertionError("Ordered capture control missed its exact defect: " + family + "\n" + result.stderr)
        print("Android ordered source causal control rejected: " + family)


if __name__ == "__main__":
    import sys
    from test_android_connection_profiles import main
    sys.argv = [sys.argv[0], "--case-family", "ordered-chain"]
    main()
