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
import("encoding/json";"encoding/base64";"crypto/ecdh";"bytes";"strings";"os";"testing";"fmt")
func TestAndroidOrderedSourceFixture(t *testing.T){
 result:=map[string]any{}
 for _,test:=range []struct{count int;layer string}{{2,""},{3,""},{4,""},{8,""},{3,"aes-256-gcm"},{4,"aes-256-gcm+xor-whitening"},{4,"fixed-middle"},{2,"awg-fast"},{2,"awg-strong"},{3,"awg-strong"},{4,"mixed-awg"},{8,"mixed-awg"},{4,"mixed-options"},{2,"hy2-wg"},{3,"hy2-awg-fast"},{4,"hy2-awg-strong"},{8,"hy2-long"}}{
  hy2:=strings.HasPrefix(test.layer,"hy2-");layer:=test.layer;if layer=="fixed-middle"||hy2{layer=""}
  mixed:=strings.Contains(layer,"awg")||layer=="mixed-options"
  modes,layers:=make([]string,test.count),make([]string,test.count)
  for i:=range modes{modes[i],layers[i]="wg",layer;if mixed{modes[i]=[]string{"awg2-fast","wg","awg2-strong"}[i%3];layers[i]=""};if layer=="awg-strong"{modes[i]="awg2-strong"};if mixed&&test.count==4&&i==1{layers[i]="aes-256-gcm"};if mixed&&test.count==4&&i==2{layers[i]="aes-256-gcm+xor-whitening"}}
  if test.layer=="hy2-awg-fast"||test.layer=="hy2-awg-strong"{for i:=range modes{modes[i]="awg2-fast";if test.layer=="hy2-awg-strong"{modes[i]="awg2-strong"}}}
  modes[test.count-1]="shadowsocks";if hy2{modes[test.count-1]="hysteria2"}
  nodes:=nodeChainModeFixtureNodes(t,modes,layers)
  identityModes:=make([]string,test.count);for i:=range identityModes{identityModes[i]="wg"};identities:=nodeChainModeFixtureNodes(t,identityModes,layers)
  variants:=map[string][]*NodeProfile{}
  if mixed{for _,mode:=range []string{"wg","awg2-fast","awg2-strong"}{choices:=append([]string(nil),modes...);for i:=0;i<len(choices)-1;i++{choices[i]=mode};variants[mode]=nodeChainModeFixtureNodes(t,choices,layers)}}
  var ssFinal *NodeProfile
  if hy2{alternate:=append([]string(nil),modes...);alternate[test.count-1]="shadowsocks";ssFinal=nodeChainModeFixtureNodes(t,alternate,layers)[test.count-1]}
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
   if hy2&&position==len(nodes)-1{var ss map[string]string;if err:=json.Unmarshal([]byte(ssFinal.inputs.Files),&ss);err!=nil{t.Fatal(err)};assets["shadowsocks"]=ss}
   var identity map[string]string;if err:=json.Unmarshal([]byte(identities[position].inputs.Files),&identity);err!=nil{t.Fatal(err)};assets["wg"]=identity
   if mixed&&position<len(nodes)-1{
    for _,mode:=range []string{"awg2-fast","awg2-strong"}{if mode!=node.mode&&test.layer!="mixed-options"{continue};var packet map[string]string;if err:=json.Unmarshal([]byte(variants[mode][position].inputs.Files),&packet);err!=nil{t.Fatal(err)}
     oldServer,err:=ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{byte(71+position)},32));if err!=nil{t.Fatal(err)};newServer,err:=ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{byte(131+position)},32));if err!=nil{t.Fatal(err)}
     raw:=string(mustDecodeChainAsset(t,packet["awg.conf"]));raw=strings.ReplaceAll(raw,base64.StdEncoding.EncodeToString(oldServer.PublicKey().Bytes()),base64.StdEncoding.EncodeToString(newServer.PublicKey().Bytes()));packet["awg.conf"]=base64.StdEncoding.EncodeToString([]byte(raw));assets[mode]=packet
    }
   }
   if node.inputs.Start!=""{var start map[string]string;if err:=json.Unmarshal([]byte(node.inputs.Start),&start);err!=nil{t.Fatal(err)};assets["shadowsocks"]=start}
   available:=[]any{};for _,mode:=range []string{"wg","awg2-fast","awg2-strong","shadowsocks","hysteria2"}{if assets[mode]!=nil{available=append(available,map[string]string{"id":mode})}}
   bundles=append(bundles,map[string]any{"profileSchemaVersion":4,"selectedRouterID":profile["id"],"nodeProofId":profile["node_proof_id"],"routerProfiles":[]any{profile},"profiles":assets,"modes":available})
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
   JSONArray identities=launch.getJSONArray("identity_sources");check(identities.length()==source.members.size(),"native capture omitted the complete original identity inventory");
   reject(()->capture.identityInputs.clear(),"native identity input list is mutable");
   check(config.getJSONArray("inbounds").length()==1&&config.getJSONArray("endpoints").length()==source.members.size()-1,"ordered graph lost one TUN or a captured packet prefix");
   check(launch.getJSONArray("nodes").length()==source.members.size()&&capture.strict,"native compile dropped a member or protection policy");
   if(key.equals("4/fixed-middle"))check(config.getJSONArray("endpoints").getJSONObject(1).getInt("mtu")==1408&&capture.finalProfile().getString("mtu_policy").equals("auto"),"Fixed middle endpoint replaced the final Auto policy");
   for(int i=0;i<source.members.size();i++){
    JSONObject input=new JSONObject(launch.getJSONArray("nodes").getString(i));JSONObject p=new JSONObject(input.getString("profile_json"));
    check(p.getString("id").equals(source.members.get(i).profileId)&&p.getString("api_token").equals(profile(f.original.get(i)).getString("api_token")),"native capture borrowed another member token or position");
    check(input.getString("mode").equals(source.modes.get(i)),"native capture replaced an exact selected member mode");
    check(identities.getString(i).equals(source.members.get(i).bundle().getJSONObject("profiles").getJSONObject("wg").toString()),"native capture replaced an original identity asset map");
    if(i<source.members.size()-1){JSONObject endpoint=config.getJSONArray("endpoints").getJSONObject(i);String mode=source.modes.get(i);check(endpoint.getString("type").equals(mode.equals("wg")?"wireguard":"routervpn-amneziawg"),"native capture replaced a selected packet family");
     if(mode.startsWith("awg2-")){check(!peerKey(source.members.get(i).bundle(),"wg").equals(peerKey(source.members.get(i).bundle(),mode)),"AWG fixture failed to distinguish original Router identity from selected packet peer");check(p.getString("node_proof_id").equals(source.members.get(i).proofId),"AWG capture substituted its packet peer for the original Router identity");}}
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
  check(f.profiles.currentOrderedPath().modes.equals(source.modes),"load substituted an original ordered mode");
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
 static String peerKey(JSONObject bundle,String mode)throws Exception{
  String asset=mode.equals("wg")?"wg.conf":"awg.conf";String raw=new String(Base64.getDecoder().decode(bundle.getJSONObject("profiles").getJSONObject(mode).getString(asset)),StandardCharsets.UTF_8);
  for(String line:raw.split("\\r?\\n"))if(line.trim().startsWith("PublicKey"))return line.substring(line.indexOf('=')+1).trim();throw new AssertionError("missing actual packet peer");
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
 static void editorChecks(Path root)throws Exception{
  Fixture f=new Fixture(root,"4/fixed-middle");State before=new State(f);
  AndroidOrderedPathSelection draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);
  check(draft.members().size()==4,"editor omitted an original selected member");
  reject(()->draft.members().clear(),"editor exposes its mutable member list");
  draft.movePrefix(1,0);draft.removePrefix(2);before.same(f,"unpublished editor operations");
  var selected=draft.save();check(selected.members.size()==3&&selected.members.get(0).id.equals(f.members.get(1).id)&&selected.members.get(1).id.equals(f.members.get(0).id),"editor dropped or reordered the original chosen nodes");
  check(selected.control.id.equals(f.control().id)&&f.nodes.activeId().equals(f.control().id),"editor replaced the selected final control");
  check(profile(f.bundle(1)).getInt("manual_mtu")==1408,"editor changed the original middle Fixed MTU");
  for(int i=0;i<f.members.size();i++)check(ConnectionProfilesHarness.sameJSONValue(f.bundle(i).get("profiles"),f.original.get(i).get("profiles"))&&profile(f.bundle(i)).getString("api_token").equals(profile(f.original.get(i)).getString("api_token")),"editor duplicated or changed original private assets");
  check(!Files.exists(f.rows),"editing a path invented a saved profile row");
  reject(()->draft.save(),"saved draft can be published twice");
  var saved=f.profiles.add("Edited original path");f.changePolicies();f.profiles.load(saved.id);
  check(f.profiles.currentOrderedPath().members.get(0).id.equals(f.members.get(1).id),"saved profile lost editor order");
  f.prefs.edit().putBoolean("multihop_on",false).commit();AndroidOrderedPathSelection disabled=new AndroidOrderedPathSelection(f.nodes,f.profiles);
  check(disabled.members().size()==3,"disabled ordered selection cannot be edited");
  String remembered=f.prefs.getString("multihop_nodes","");f.profiles.add("Single node while ordered is off");
  JSONArray rows=new JSONObject(Files.readString(f.rows)).getJSONArray("profiles");JSONObject direct=rows.getJSONObject(rows.length()-1);
  check(!direct.getBoolean("multihop_enabled")&&!direct.has("multihop_nodes"),"disabled ordered path could not save its direct connection choice");
  check(remembered.equals(f.prefs.getString("multihop_nodes",""))&&!f.prefs.getBoolean("multihop_on",true),"saving the direct profile discarded or enabled its remembered ordered draft");
  Fixture fresh=new Fixture(root,"4/");fresh.prefs.edit().putString("multihop_nodes","").putBoolean("multihop_on",false).commit();State original=new State(fresh);
  AndroidOrderedPathSelection newPath=new AndroidOrderedPathSelection(fresh.nodes,fresh.profiles);check(newPath.members().size()==1,"new draft did not retain its selected final node");
  newPath.addPrefix(fresh.members.get(0).id);newPath.addPrefix(fresh.members.get(1).id);newPath.addPrefix(fresh.members.get(2).id);
  reject(()->newPath.addPrefix(fresh.members.get(0).id),"editor reused one original node twice");
  reject(()->newPath.movePrefix(0,3),"editor moved a prefix over the final member");original.same(fresh,"new unpublished editor draft");
  check(newPath.save().members.size()==4,"new editor path omitted an additional selected node");
 }
 static void editorGeneration(Path root)throws Exception{
  Fixture f=new Fixture(root,"3/");AndroidOrderedPathSelection draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);
  byte[] original=Files.readAllBytes(f.members.get(1).file.toPath());JSONObject changed=f.bundle(1);profile(changed).put("api_token","changed-away-and-back");
  f.replace(1,changed);f.nodes.importBundle(original);f.nodes.select(f.control().id);
  State before=new State(f);reject(()->draft.save(),"ordered editor revived after source change-away and back");before.same(f,"stale editor generation");
 }
 static void editorFailures(Path root)throws Exception{
  for(String fault:List.of("source","preferences","native","publication","readback")) {
   Fixture f=new Fixture(root,"3/");AndroidOrderedPathSelection draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);State original=new State(f);
   if(fault.equals("source")){JSONObject changed=f.bundle(1);profile(changed).put("api_token","replacement-private-token");Files.writeString(f.members.get(1).file.toPath(),changed.toString());}
   if(fault.equals("preferences"))f.prefs.edit().putString("mode","all").commit();
   if(fault.equals("native"))io.nekohasekai.libbox.Libbox.afterChainMember=()->{throw new IllegalStateException("native compile rejected captured input");};
   if(fault.equals("publication")){AndroidPrivateFileStore.failPath=f.control().file.getAbsolutePath();AndroidPrivateFileStore.failures=1;}
   if(fault.equals("readback")) {
    draft.removePrefix(0);
    f.prefs.beforeCommit=()->AndroidPrivateFileStore.orderedRead=file->{if(file.equals(f.control().file)){AndroidPrivateFileStore.orderedRead=null;throw new IllegalStateException("post-publication original source readback failed");}};
   }
   State before=new State(f);
   try{reject(()->draft.save(),"ordered editor accepted "+fault);before.same(f,"editor failure "+fault);}
   finally{io.nekohasekai.libbox.Libbox.afterChainMember=null;AndroidPrivateFileStore.failPath="";AndroidPrivateFileStore.failures=0;AndroidPrivateFileStore.orderedRead=null;f.prefs.beforeCommit=null;}
  }
 }
 static void orderedPermission(Path root)throws Exception{
  Fixture f=new Fixture(root,"3/");String before=AndroidConnectionSelection.digest(f.context,f.nodes);
  JSONArray original=new JSONArray(f.prefs.getString("multihop_nodes",""));JSONArray reordered=new JSONArray().put(original.getJSONObject(1)).put(original.getJSONObject(0)).put(original.getJSONObject(2));
  f.prefs.edit().putString("multihop_nodes",reordered.toString()).commit();
  check(!before.equals(AndroidConnectionSelection.digest(f.context,f.nodes)),"permission digest omitted ordered member choices");
  reject(()->AndroidConnectionSelection.requireCurrent(f.context,f.nodes,before),"changed ordered permission choice was accepted");
 }
 static void editorNative(Path root)throws Exception{
  Fixture f=new Fixture(root,"3/");JSONObject first=f.bundle(0),second=f.bundle(1);
  String a=new String(Base64.getDecoder().decode(first.getJSONObject("profiles").getJSONObject("wg").getString("wg.conf")),StandardCharsets.UTF_8);
  String b=new String(Base64.getDecoder().decode(second.getJSONObject("profiles").getJSONObject("wg").getString("wg.conf")),StandardCharsets.UTF_8);
  String client=java.util.regex.Pattern.compile("(?m)^PrivateKey\\s*=\\s*(.+)$").matcher(b).results().findFirst().orElseThrow().group(1);
  a=a.replaceFirst("(?m)^PrivateKey\\s*=\\s*.+$","PrivateKey = "+client);
  first.getJSONObject("profiles").getJSONObject("wg").put("wg.conf",Base64.getEncoder().encodeToString(a.getBytes(StandardCharsets.UTF_8)));f.replace(0,first);f.nodes.select(f.control().id);
  AndroidOrderedPathSelection draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);State before=new State(f);
  reject(()->draft.save(),"ordered editor skipped complete native chain validation");before.same(f,"native duplicate-client refusal");
 }
 static void editorAtomicity(Path root)throws Exception{
  Fixture f=new Fixture(root,"3/");AndroidOrderedPathSelection draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);AndroidNodeStore independent=new AndroidNodeStore(f.context);
  var committing=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);var starting=new java.util.concurrent.CountDownLatch(1);var published=new java.util.concurrent.CountDownLatch(1);
  var editorFailure=new java.util.concurrent.atomic.AtomicReference<Throwable>();var writerFailure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
  JSONObject changed=f.bundle(1);profile(changed).put("api_token","independent-during-publication");
  f.prefs.beforeCommit=()->{committing.countDown();try{if(!release.await(3,java.util.concurrent.TimeUnit.SECONDS))throw new AssertionError("editor commit was not released");}catch(InterruptedException e){throw new IllegalStateException(e);}};
  AndroidPrivateFileStore.beforeWrite=()->{if(Thread.currentThread().getName().equals("editor-publisher"))published.countDown();};
  Thread editor=new Thread(()->{try{draft.save();}catch(Throwable e){editorFailure.set(e);}},"ordered-editor");
  Thread writer=new Thread(()->{starting.countDown();try{independent.importBundle(changed.toString().getBytes(StandardCharsets.UTF_8));}catch(Throwable e){writerFailure.set(e);}},"editor-publisher");
  boolean premature=false;
  try{editor.start();check(committing.await(3,java.util.concurrent.TimeUnit.SECONDS),"editor never reached its original preference publication");writer.start();check(starting.await(2,java.util.concurrent.TimeUnit.SECONDS),"editor's independent publisher never started");premature=published.await(250,java.util.concurrent.TimeUnit.MILLISECONDS);}
  finally{release.countDown();editor.join(4000);writer.join(4000);f.prefs.beforeCommit=null;AndroidPrivateFileStore.beforeWrite=null;}
  check(!editor.isAlive()&&!writer.isAlive(),"ordered editor left an unjoined publisher");
  check(!premature,"ordered editor did not exclude an independent source publisher until complete publication");
  check(editorFailure.get()==null&&writerFailure.get()==null&&published.getCount()==0,"original editor or subsequent publisher failed");
 }
 static void editorFinalBudget(Path root)throws Exception{
  Fixture f=new Fixture(root,"2/");JSONObject a=f.bundle(0),b=f.bundle(1);
  for(String key:List.of("multihop_nodes","multihop_enabled","multihop_execution"))profile(b).remove(key);
  a.put("unused_private_source","");b.put("unused_private_source","");
  int payload=AndroidNodeStore.MAX_CHAIN_SOURCE-8-a.toString().getBytes(StandardCharsets.UTF_8).length-b.toString().getBytes(StandardCharsets.UTF_8).length;
  a.put("unused_private_source","x".repeat(payload/2));b.put("unused_private_source","y".repeat(payload-payload/2));f.replace(0,a);f.replace(1,b);f.nodes.select(f.control().id);
  f.prefs.edit().putString("multihop_nodes","").putBoolean("multihop_on",false).commit();
  AndroidOrderedPathSelection draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);draft.addPrefix(f.members.get(0).id);int before=AndroidPrivateFileStore.writes;
  reject(()->draft.save(),"ordered editor accepted sources beyond the final aggregate budget");
  check(AndroidPrivateFileStore.writes==before,"ordered final references exceeded their aggregate bound after private publication");
 }
 static void editorHandlers(Path root)throws Exception{
  Fixture f=new Fixture(root,"3/");State before=new State(f);OrderedProductSurface ui=new OrderedProductSurface(f);
  ui.open();ui.choose(0);check(ui.dialog.title.equals("Ordered Router path")&&ui.dialog.labels.length==4&&ui.dialog.detail.contains("two to eight"),"shipping ordered editor omitted original nodes or its supported transport boundary");
  ui.choose(0);ui.choose(0);check(ui.dialog.labels[0].toString().contains(profile(f.original.get(1)).optString("name",profile(f.original.get(1)).getString("id"))),"shipping ordered editor did not move the original first node later");
  ui.choose(0);ui.choose(1);check(ui.dialog.labels.length==3,"shipping ordered editor did not remove one selected prefix");
  ui.choose(2);check(ui.dialog.title.equals("Add intermediate Router node"),"shipping ordered editor did not expose repeated addition");ui.choose(0);check(ui.dialog.title.equals("Intermediate transport"),"shipping ordered editor omitted the selected node transport choice");ui.choose(0);
  check(ui.dialog.labels.length==4,"shipping ordered editor failed to add another original node before final");ui.cancel();before.same(f,"actual ordered editor cancellation");
  ui.open();ui.choose(0);ui.choose(0);ui.choose(1);ui.save();
  check(ui.refreshes==1&&ui.statusView.text.contains("Press Connect")&&ui.message.isEmpty(),"shipping ordered Save did not publish a reviewable path without connection");
  var saved=f.profiles.currentOrderedPath();check(saved.members.size()==2&&saved.control.id.equals(f.control().id)&&saved.members.get(0).id.equals(f.members.get(1).id),"shipping ordered Save substituted its original final or prefix");
  OrderedProductSurface stale=new OrderedProductSurface(f);stale.open();stale.choose(0);JSONObject changed=f.bundle(1);profile(changed).put("api_token","changed while actual editor open");f.replace(1,changed);f.nodes.select(f.control().id);State replacement=new State(f);stale.save();
  check(stale.refreshes==0&&!stale.message.isEmpty(),"shipping ordered editor published a replaced source");replacement.same(f,"actual editor refused replaced source");
 }
 static void pairedIdentity(Path root)throws Exception{
  for(int position:new int[]{0,3}){
   Fixture f=new Fixture(root,"4/mixed-awg");AndroidNodeStore.ChainCapture original=f.profiles.currentOrderedPath();
   JSONObject missing=f.bundle(position);missing.getJSONObject("profiles").remove("wg");f.replace(position,missing);f.nodes.select(f.control().id);
   reject(original::requireCurrent,"ordered source accepted removal of its separate WireGuard identity");
   reject(()->f.profiles.currentOrderedPath(),"ordered admission accepted a saved identity label without its original WireGuard asset");
   AndroidNodeStore.ChainSource unproved=f.nodes.captureChainCatalog().source(f.members.get(position).id);
   reject(()->AndroidNodeChainCapture.memberInput(unproved,original.modes.get(position),unproved.profile()),"ordered compiler preview accepted an unproved saved identity label");
  }
  Fixture f=new Fixture(root,"4/mixed-awg");JSONObject changed=f.bundle(0);
  JSONObject replacement=f.bundle(1).getJSONObject("profiles").getJSONObject("wg");changed.getJSONObject("profiles").put("wg",replacement);State before=new State(f);
  reject(()->f.replace(0,changed),"ordered source imported a replacement WireGuard identity beside unchanged AWG keys");before.same(f,"separate identity replacement");
 }
 static void nativeIdentityReceipt(Path root)throws Exception{
  Fixture f=new Fixture(root,"4/mixed-awg");var original=f.profiles.currentOrderedPath();
  try(AndroidNodeChainCapture capture=AndroidNodeChainCapture.compile(original)){
   JSONObject launch=new JSONObject(capture.launchInput);
   for(String fault:List.of("missing","replaced","reordered","short","bad-final")){
    JSONObject source=new JSONObject().put("schema",1).put("execution","local").put("nodes",launch.getJSONArray("nodes"));JSONArray identities=new JSONArray(launch.getJSONArray("identity_sources").toString());source.put("identity_sources",identities);
    if(fault.equals("missing"))source.remove("identity_sources");
    if(fault.equals("replaced")){JSONObject map=new JSONObject(identities.getString(2));String raw=new String(Base64.getDecoder().decode(map.getString("wg.conf")),StandardCharsets.UTF_8)+"\n# another original identity asset\n";map.put("wg.conf",Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8)));identities.put(2,map.toString());}
    if(fault.equals("reordered")){String first=identities.getString(0);identities.put(0,identities.getString(2));identities.put(2,first);}
    if(fault.equals("short"))source.put("identity_sources",new JSONArray().put(identities.getString(0)));
    if(fault.equals("bad-final"))identities.put(3,new JSONObject().put("wg.conf",Base64.getEncoder().encodeToString("not a complete original WG source".getBytes(StandardCharsets.UTF_8))).toString());
    if(fault.equals("missing")||fault.equals("replaced")){
     io.nekohasekai.libbox.RouterNodeChain changed=io.nekohasekai.libbox.Libbox.newRouterNodeChain(source.toString());
     try{check(changed.config().equals(capture.config)&&!changed.sourceSHA256().equals(capture.sourceSHA256),"identity inventory changed the selected transport or escaped its native source digest");String record=changed.launchInput();reject(()->{try(AndroidNodeChainCapture replay=AndroidNodeChainCapture.reopen(record,original)){}},"Android accepted a different native identity inventory: "+fault);}finally{changed.close();}
    }else reject(()->{io.nekohasekai.libbox.RouterNodeChain changed=io.nekohasekai.libbox.Libbox.newRouterNodeChain(source.toString());changed.close();},"native parser accepted a damaged identity inventory: "+fault);
   }
  }
 }
 static void identityCompilerAdmission(Path root)throws Exception{
  for(int position:new int[]{0,3}){
   Fixture f=new Fixture(root,"4/mixed-awg");JSONObject bundle=f.bundle(position),assets=bundle.getJSONObject("profiles").getJSONObject("wg");
   String raw=new String(Base64.getDecoder().decode(assets.getString("wg.conf")),StandardCharsets.UTF_8);raw=raw.replaceFirst("(?m)^PrivateKey\\s*=.*$","PrivateKey = invalid-original-private-key");assets.put("wg.conf",Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8)));f.replace(position,bundle);f.nodes.select(f.control().id);
   var original=f.profiles.currentOrderedPath();reject(()->{try(AndroidNodeChainCapture capture=AndroidNodeChainCapture.compile(original)){}},"Android compiler accepted malformed original identity beside valid selected transport");
   AndroidOrderedPathSelection draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);State before=new State(f);reject(draft::save,"ordered editor skipped full native identity source validation");before.same(f,"malformed original identity preview");
  }
 }
 static void editorMixed(Path root)throws Exception{
  Fixture f=new Fixture(root,"4/mixed-options");f.prefs.edit().putString("multihop_nodes","").putBoolean("multihop_on",false).commit();
  AndroidOrderedPathSelection draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);State before=new State(f);
  check(draft.prefixModes(f.members.get(0).id).equals(List.of("wg","awg2-fast","awg2-strong")),"editor omitted exact complete WG/AWG choices");
  draft.addPrefix(f.members.get(0).id,"awg2-strong");draft.addPrefix(f.members.get(1).id,"wg");draft.addPrefix(f.members.get(2).id,"awg2-fast");
  draft.movePrefix(2,0);check(draft.members().get(0).source.id.equals(f.members.get(2).id)&&draft.members().get(0).mode.equals("awg2-fast"),"editor reordered a node without its exact transport");
  draft.setPrefixMode(1,"awg2-fast");check(draft.members().get(1).source.id.equals(f.members.get(0).id)&&draft.members().get(1).mode.equals("awg2-fast"),"editor changed transport by replacing its original source");
  reject(()->draft.setPrefixMode(3,"awg2-strong"),"editor changed the fixed Shadowsocks final transport");
  for(String invalid:List.of("WG","awg","awg2-pq","wg-pq","shadowsocks"," awg2-fast","awg2-strong "))reject(()->draft.setPrefixMode(0,invalid),"editor accepted an unsupported or normalized intermediate transport: "+invalid);
  before.same(f,"mixed draft before explicit Save");AndroidNodeStore.ChainCapture saved=draft.save();
  check(saved.modes.equals(List.of("awg2-fast","awg2-fast","wg","shadowsocks")),"editor saved a substituted ordered transport");
  try(AndroidNodeChainCapture compiled=AndroidNodeChainCapture.compile(saved)){check(new JSONObject(compiled.launchInput).getJSONArray("nodes").length()==4,"mixed editor omitted a native compiler input");}
  var row=f.profiles.add("Mixed captured modes");f.changePolicies();f.profiles.load(row.id);check(f.profiles.currentOrderedPath().modes.equals(saved.modes),"mixed saved profile dropped per-prefix modes");
  for(int i=0;i<f.members.size();i++)check(ConnectionProfilesHarness.sameJSONValue(f.bundle(i).get("profiles"),f.original.get(i).get("profiles")),"mixed editor changed unselected identity or packet assets");
  Fixture limited=new Fixture(root,"2/awg-fast");AndroidOrderedPathSelection exact=new AndroidOrderedPathSelection(limited.nodes,limited.profiles);
  reject(()->exact.setPrefixMode(0,"awg2-strong"),"editor substituted an absent Strong source from its Fast asset");
 }
 static void editorMixedHandlers(Path root)throws Exception{
  Fixture f=new Fixture(root,"4/mixed-options");OrderedProductSurface ui=new OrderedProductSurface(f);State before=new State(f);
  ui.open();ui.choose(0);check(ui.dialog.labels[0].toString().contains("AmneziaWG Fast")&&ui.dialog.labels[1].toString().contains("WireGuard")&&ui.dialog.labels[2].toString().contains("AmneziaWG Strong"),"shipping ordered editor mislabeled exact per-prefix transports");
  ui.choose(0);ui.choose(2);check(ui.dialog.title.equals("Intermediate transport")&&Arrays.equals(ui.dialog.labels,new String[]{"WireGuard","AmneziaWG Fast","AmneziaWG Strong"}),"shipping ordered editor did not expose original node's exact transport choices");ui.choose(2);
  check(ui.dialog.labels[0].toString().contains("AmneziaWG Strong"),"shipping ordered mode callback ignored the selected transport");
  ui.choose(0);ui.choose(0);check(ui.dialog.labels[1].toString().contains("AmneziaWG Strong"),"shipping ordered move lost the selected transport");
  before.same(f,"actual mixed editor before explicit Save");ui.save();
  var saved=f.profiles.currentOrderedPath();check(ui.message.isEmpty()&&saved.members.get(1).id.equals(f.members.get(0).id)&&saved.modes.equals(List.of("wg","awg2-strong","awg2-strong","shadowsocks")),"shipping mixed editor published a different source or selected mode");
  for(int i=0;i<f.members.size();i++)check(ConnectionProfilesHarness.sameJSONValue(f.bundle(i).get("profiles"),f.original.get(i).get("profiles")),"actual mixed editor replaced original private assets");
 }
 static void productHandoff(Path root)throws Exception{
  AndroidHomeStateStore.Snapshot previous=AndroidHomeStateStore.current;
  try{
   for(String fault:List.of("current","choice","Home","cancel","destroy")){
    Fixture f=new Fixture(root,"3/");AndroidHomeStateStore.current=new AndroidHomeStateStore.Snapshot();
    AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(f.context);String selection=AndroidConnectionSelection.digest(f.context,f.nodes);
    ProductConnectSurface ui=new ProductConnectSurface(f.context,f.nodes,new AndroidStandardExitStore(f.context));ui.multihopToggle.setChecked(true);
    ui.pressConnect();check(ui.orderedConnectCapturePending&&ui.connection.starts==0,"ordered Product dispatched before its actual capture worker returned");
    Runnable delivery=ui.awaitOrderedDelivery();check(ui.connection.starts==0,"ordered Product bypassed its queued UI handoff");
    switch(fault){
     case "choice"->f.prefs.edit().putBoolean("multihop_on",false).commit();
     case "Home"->AndroidHomeStateStore.current=new AndroidHomeStateStore.Snapshot();
     case "cancel"->{long ticket=ui.orderedConnectTicket;ui.pressConnect();check(!ui.orderedConnectCapturePending&&ui.orderedConnectTicket==ticket+1,"ordered Product cancellation lost its queued capture ticket");}
     case "destroy"->ui.destroyed=true;
    }
    delivery.run();
    if(fault.equals("current")){
     check(ui.connection.starts==1&&ui.connection.orderedHome==home&&selection.equals(ui.connection.orderedSelection),"ordered Product replaced its original Home or selection receipt");
     var source=ui.connection.ordered;source.requireCurrent();check(source.control.id.equals(f.control().id)&&source.members.size()==3,"ordered Product omitted its original complete source");
     for(int i=0;i<3;i++)check(source.members.get(i).id.equals(f.members.get(i).id),"ordered Product changed original member order");
    }else check(ui.connection.starts==0,"ordered Product adopted a replaced "+fault);
   }
   Fixture f=new Fixture(root,"3/");ProductConnectSurface startup=new ProductConnectSurface(f.context,f.nodes,new AndroidStandardExitStore(f.context));
   startup.startupCapturePending=true;long ticket=startup.startupCaptureTicket;int cancelled=AndroidStartupPolicy.cancellations;startup.pressConnect();
   check(!startup.startupCapturePending&&startup.startupCaptureTicket==ticket+1&&AndroidStartupPolicy.cancellations==cancelled+1&&startup.connection.starts==0&&startup.uiCallbacks.isEmpty(),"Product cancelled startup capture fell through to a new connection");
  }finally{AndroidHomeStateStore.current=previous;}
 }

 static void importedMiddle(Path root)throws Exception{
  for(String method:List.of("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305")){
  int keySize=method.equals("2022-blake3-aes-128-gcm")?16:32;
  Fixture f=new Fixture(root,"2/");AndroidStandardExitStore exits=new AndroidStandardExitStore(f.context);
  AndroidStandardExitStore.Entry custom=new AndroidStandardExitStore.Entry();custom.id="1234567890abcdef1234567890abcdef";custom.name="Original custom middle";custom.protocol="shadowsocks";custom.server="198.51.100.76";custom.serverPort=443;custom.expectedPublicIp="203.0.113.76";custom.method=method;custom.secret=Base64.getEncoder().encodeToString(new byte[keySize]);custom.policy.put("dns_mode","rescue").put("start_layer","off");exits.save(custom);
  AndroidOrderedPathSelection editor=new AndroidOrderedPathSelection(f.nodes,f.profiles);
  check(editor.prefixModes(custom.id).equals(List.of("shadowsocks")),"original imported middle not offered by editor");editor.addPrefix(custom.id,"shadowsocks");
  reject(()->editor.movePrefix(1,0),"imported source moved into physical first position");
  AndroidNodeStore.ChainCapture saved=editor.save();check(saved.members.size()==3&&saved.members.get(1).imported&&saved.members.get(1).proofId.isEmpty(),"custom member borrowed paired identity");
  try(AndroidNodeChainCapture capture=AndroidNodeChainCapture.compile(saved)){
   JSONObject launch=new JSONObject(capture.launchInput),middle=new JSONObject(capture.memberInputs.get(1));
   JSONObject profile=new JSONObject(middle.getString("capture")).getJSONObject("profile");
   JSONObject ss=profile.getJSONObject("external").getJSONObject("shadowsocks");
   check(ss.getString("method").equals(method)&&ss.getString("password").equals(custom.secret),"custom cipher or original PSK changed during native compilation");
   check(launch.getInt("schema")==2&&capture.identityInputs.get(1).isEmpty()&&middle.getString("kind").equals("routervpn-node-chain-imported-member"),"custom source did not retain typed schema2");
   check(profile.getString("id").equals(custom.id)&&profile.getString("node_kind").equals("external")&&!profile.has("node_proof_id")&&!profile.has("api_token")&&!profile.has("router_api"),"custom source forged private Router authority");
   try(AndroidNodeChainCapture replay=AndroidNodeChainCapture.reopen(capture.launchInput,saved)){check(replay.launchInput.equals(capture.launchInput),"custom middle replay changed original source");}
  }
  var row=f.profiles.add("Original custom middle route");String serialized=Files.readString(f.rows);check(!serialized.contains(custom.secret)&&!serialized.contains("api_token"),"saved custom route copied credentials");
  f.profiles.load(row.id);check(f.profiles.currentOrderedPath().members.get(1).imported&&f.profiles.currentOrderedPath().members.get(1).external().method.equals(method),"saved profile lost imported member or selected cipher");
  AndroidNodeStore.ChainCapture live=f.profiles.currentOrderedPath();AndroidOrderedPathSelection stale=new AndroidOrderedPathSelection(f.nodes,f.profiles);
  String original=custom.name;custom.name="Replaced";exits.save(custom);custom.name=original;exits.save(custom);
  reject(live::requireCurrent,"imported change-away/back revived old native source");reject(stale::save,"imported change-away/back revived old editor");
  AndroidStandardExitStore.Entry changed=AndroidStandardExitStore.copy(custom);changed.method="aes-256-gcm";reject(()->AndroidNodeStore.ChainSource.requireImported(changed),"legacy SS admitted as custom middle");
  changed.method=custom.method;changed.server="example.com";reject(()->AndroidNodeStore.ChainSource.requireImported(changed),"hostname middle bypassed its explicit saved resolver policy");
  changed.server=custom.server;
  for(String secret:List.of(Base64.getEncoder().encodeToString(new byte[keySize==16?32:16]),Base64.getEncoder().encodeToString(new byte[keySize+1]),custom.secret.replace("=",""),custom.secret+":"+custom.secret,"invalid!")){
   changed.secret=secret;reject(()->AndroidNodeStore.ChainSource.requireImported(changed),"invalid single PSK shown as ordered eligible");
  }
  changed.secret=custom.secret;
  for(String server:List.of(":","2001:db8:::1","2001:db8::1::2","192.168.001.1")){
   changed.server=server;reject(()->AndroidNodeStore.ChainSource.requireImported(changed),"malformed literal shown as ordered eligible");
  }
  changed.server="2001:db8::76";AndroidNodeStore.ChainSource.requireImported(changed);check(true,"strict IPv6 custom source eligibility");
  }
 }
 static AndroidStandardExitStore.Entry hostnameEntry(String method)throws Exception{
  var custom=new AndroidStandardExitStore.Entry();custom.id="1234567890abcdef1234567890abcdef";custom.name="Original DNS middle";custom.protocol="shadowsocks";
  custom.server="Middle.Example.Test";custom.serverPort=443;custom.expectedPublicIp="203.0.113.76";custom.method=method;
  custom.secret=Base64.getEncoder().encodeToString(new byte[method.equals("2022-blake3-aes-128-gcm")?16:32]);
  custom.policy.put("dns_mode","custom").put("dns_protocol","tcp").put("dns_host","10.81.0.53").put("dns_port",5353)
   .put("start_layer","off").put("ipv6_mode","off").put("home_lan_access",false).put("kill_switch",true).put("kill_switch_policy","always");
  return custom;
 }
 static JSONObject tagged(JSONArray values,String tag)throws Exception{
  JSONObject found=null;for(int i=0;i<values.length();i++)if(tag.equals(values.getJSONObject(i).optString("tag"))){check(found==null,"duplicate native DNS or transport tag");found=values.getJSONObject(i);}
  check(found!=null,"native graph lost captured DNS or transport tag");return found;
 }
 static void hostnameMiddle(Path root)throws Exception{
  for(String fixture:List.of("2/","2/awg-fast","2/awg-strong"))for(String method:List.of("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305")){
   Fixture f=new Fixture(root,fixture);AndroidStandardExitStore exits=new AndroidStandardExitStore(f.context);var custom=hostnameEntry(method);
   var unsaved=AndroidStandardExitStore.copy(custom);unsaved.policy=new JSONObject();AndroidStandardExitStore.validateForPolicyEditor(unsaved);
   check(unsaved.server.equals(custom.server),"transport editor normalized the exact saved hostname");
   reject(()->exits.save(unsaved),"transport-only hostname escaped final saved-policy validation");
   AndroidExternalPolicy.validateDraft(custom);exits.save(custom);String original=AndroidStandardExitStore.snapshot(exits.get(custom.id));
   AndroidOrderedPathSelection editor=new AndroidOrderedPathSelection(f.nodes,f.profiles);
   check(editor.prefixModes(custom.id).equals(List.of("shadowsocks")),"hostname middle omitted from actual editor");editor.addPrefix(custom.id,"shadowsocks");
   reject(()->editor.movePrefix(1,0),"hostname middle acquired physical first position");var saved=editor.save();
   check(saved.members.size()==3&&saved.members.get(1).imported&&saved.members.get(1).proofId.isEmpty(),"hostname middle borrowed paired Router identity");
   try(AndroidNodeChainCapture capture=AndroidNodeChainCapture.compile(saved)){
    JSONObject member=new JSONObject(capture.memberInputs.get(1)),selection=new JSONObject(member.getString("capture")),p=selection.getJSONObject("profile");
    JSONObject source=new JSONObject(member.getString("config"));
    check(p.getString("endpoint").equals(custom.server)&&p.getJSONObject("external").getJSONObject("shadowsocks").getString("server").equals(custom.server)
      &&source.getJSONArray("outbounds").getJSONObject(0).getString("server").equals(custom.server),"hostname capture replaced an original endpoint copy");
    check(!source.has("dns")&&p.getString("dns_protocol").equals("tcp")&&p.getInt("dns_port")==5353,"hostname source lost its saved resolver or invented application DNS");
    reject(()->io.nekohasekai.libbox.Libbox.routerCompileExternalPolicy(member.getString("config"),member.getString("capture")),"hostname middle acquired ordinary physical native policy");
    JSONObject graph=new JSONObject(capture.config),middle=null;JSONArray outs=graph.getJSONArray("outbounds");
    for(int i=0;i<outs.length();i++)if(custom.server.equals(outs.getJSONObject(i).optString("server")))middle=outs.getJSONObject(i);
    check(middle!=null&&middle.getString("password").equals(custom.secret)&&middle.getString("method").equals(method),"hostname graph replaced exact transport credentials");
    String prefix=graph.getJSONArray("endpoints").getJSONObject(0).getString("tag"),finalTag=tagged(outs,graph.getJSONObject("route").getString("final")).getString("default");
    JSONObject dns=graph.getJSONObject("dns"),query=middle.getJSONObject("domain_resolver"),transport=tagged(dns.getJSONArray("servers"),query.getString("server")),application=tagged(dns.getJSONArray("servers"),dns.getString("final"));
    check(middle.getString("detour").equals(prefix)&&query.getString("strategy").equals("ipv4_only")&&transport.getString("detour").equals(prefix)
      &&transport.getString("type").equals("tcp")&&transport.getString("server").equals("10.81.0.53")&&transport.getInt("server_port")==5353,"hostname resolver escaped original preceding packet prefix");
    check(!transport.getString("tag").equals(application.getString("tag"))&&application.getString("detour").equals(finalTag)
      &&application.getString("type").equals("udp")&&application.getString("server").equals(profile(f.original.get(1)).getString("adguard_ipv4")),"hostname resolver replaced final Home application DNS");
    check(capture.identityInputs.get(1).isEmpty()&&new JSONObject(capture.launchInput).getInt("schema")==2,"hostname source borrowed native identity authority");
    try(AndroidNodeChainCapture replay=AndroidNodeChainCapture.reopen(capture.launchInput,saved)){check(replay.launchInput.equals(capture.launchInput)&&replay.config.equals(capture.config),"hostname replay changed original source or DNS route");}
    for(String fault:List.of("profile-endpoint","external-endpoint","outbound-endpoint","resolver-port")){
     JSONObject altered=new JSONObject(member.getString("capture")),config=new JSONObject(member.getString("config"));
     switch(fault){case "profile-endpoint"->altered.getJSONObject("profile").put("endpoint","middle.example.test");case "external-endpoint"->altered.getJSONObject("profile").getJSONObject("external").getJSONObject("shadowsocks").put("server","other.example.test");case "outbound-endpoint"->config.getJSONArray("outbounds").getJSONObject(0).put("server","other.example.test");case "resolver-port"->altered.getJSONObject("profile").put("dns_port",0);}
     reject(()->io.nekohasekai.libbox.Libbox.routerNodeChainImportedMemberInput(config.toString(),altered.toString()),"shared hostname source accepted "+fault);
    }
   }
   check(original.equals(AndroidStandardExitStore.snapshot(exits.get(custom.id))),"hostname compile mutated saved original source");
   var row=f.profiles.add("Original hostname middle route");String serialized=Files.readString(f.rows);
   check(!serialized.contains(custom.secret)&&!serialized.contains("api_token"),"hostname saved profile copied private credentials");
   var changed=exits.get(custom.id);changed.policy.put("dns_port",5354).put("home_lan_access",true);exits.save(changed);
   f.profiles.load(row.id);var restored=exits.get(custom.id);
   check(restored.server.equals(custom.server)&&restored.secret.equals(custom.secret)&&restored.method.equals(method)&&restored.policy.getInt("dns_port")==5353&&!restored.policy.getBoolean("home_lan_access"),"hostname profile restore lost original resolver, source or protection");
   var live=f.profiles.currentOrderedPath();var stale=new AndroidOrderedPathSelection(f.nodes,f.profiles);changed=exits.get(custom.id);changed.policy.put("dns_port",5354);exits.save(changed);
   reject(live::requireCurrent,"hostname live source ignored a changed saved resolver");reject(stale::save,"hostname editor ignored a changed saved resolver");
   changed.policy.put("dns_port",5353);exits.save(changed);
   reject(live::requireCurrent,"hostname resolver change-away/back revived old native source");reject(stale::save,"hostname resolver change-away/back revived old editor");
   var credentialCapture=f.profiles.currentOrderedPath();var credentialEditor=new AndroidOrderedPathSelection(f.nodes,f.profiles);
   var replacement=exits.get(custom.id);byte[] key=Base64.getDecoder().decode(replacement.secret);key[0]=1;replacement.secret=Base64.getEncoder().encodeToString(key);exits.save(replacement);
   reject(credentialCapture::requireCurrent,"hostname live capture accepted replacement credentials");reject(credentialEditor::save,"hostname live editor accepted replacement credentials");
   // Saved profiles retain node references and settings, never stale secret
   // copies. Explicit future Load revalidates the same node's current key.
   f.profiles.load(row.id);check(exits.get(custom.id).secret.equals(replacement.secret)&&!exits.get(custom.id).secret.equals(custom.secret),"hostname profile Load restored stale private credentials");
   replacement=exits.get(custom.id);replacement.expectedPublicIp="203.0.113.77";exits.save(replacement);
   reject(()->f.profiles.load(row.id),"hostname saved profile accepted replaced public identity");
   exits.remove(custom.id);replacement.id="fedcba0987654321fedcba0987654321";exits.save(replacement);
   reject(()->f.profiles.load(row.id),"hostname saved profile borrowed another imported node");
  }
 }
 static void hostnamePolicyControls(Path root)throws Exception{
  for(String fault:List.of("home","rescue","fastest","udp","tls","resolver-hostname","resolver-loopback","missing-port","zero-port","negative-port","large-port","fractional-port","text-port","bootstrap","tls-name","dns-path","layer","legacy-method","bad-key","colon-key","trailing-dot","numeric-looking","unicode-host")){
   var custom=hostnameEntry("2022-blake3-aes-128-gcm");
   switch(fault){case "home","rescue","fastest"->custom.policy.put("dns_mode",fault);case "udp","tls"->custom.policy.put("dns_protocol",fault);case "resolver-hostname"->custom.policy.put("dns_host","resolver.example.test");case "resolver-loopback"->custom.policy.put("dns_host","127.0.0.1");case "missing-port"->custom.policy.remove("dns_port");case "zero-port"->custom.policy.put("dns_port",0);case "negative-port"->custom.policy.put("dns_port",-1);case "large-port"->custom.policy.put("dns_port",65536);case "fractional-port"->custom.policy.put("dns_port",5353.5);case "text-port"->custom.policy.put("dns_port","5353");case "bootstrap"->custom.policy.put("dns_bootstrap",new JSONObject());case "tls-name"->custom.policy.put("dns_server_name","resolver.example.test");case "dns-path"->custom.policy.put("dns_path","/dns-query");case "layer"->custom.policy.put("start_layer","aes-256-gcm");case "legacy-method"->custom.method="aes-256-gcm";case "bad-key"->custom.secret="invalid!";case "colon-key"->custom.secret=custom.secret+":"+custom.secret;case "trailing-dot"->custom.server="middle.example.test.";case "numeric-looking"->custom.server="192.168.001.1";case "unicode-host"->custom.server="m\u00e9dia.example.test";}
   if(!fault.equals("resolver-loopback"))reject(()->AndroidStandardExitStore.validate(custom),"hostname saved policy accepted "+fault);
   reject(()->AndroidExternalPolicy.validateDraft(custom),"hostname policy editor accepted "+fault);
  }
 }
 static void hysteriaFinal(Path root)throws Exception{
  for(String key:List.of("2/hy2-wg","3/hy2-awg-fast","4/hy2-awg-strong","8/hy2-long")){
   Fixture f=new Fixture(root,key);var original=f.profiles.currentOrderedPath();int last=original.members.size()-1;
   check(original.modes.get(last).equals("hysteria2"),"paired HY2 source lost exact selected final mode");
   try(AndroidNodeChainCapture capture=AndroidNodeChainCapture.compile(original)){
    JSONObject launch=new JSONObject(capture.launchInput),member=new JSONObject(capture.memberInputs.get(last));
    check(launch.getInt("schema")==1&&member.getString("mode").equals("hysteria2")&&member.getString("start").isEmpty(),"paired HY2 final borrowed imported, layered or execution source");
    JSONObject graph=new JSONObject(capture.config);JSONArray outbounds=graph.getJSONArray("outbounds");JSONObject selected=tagged(outbounds,graph.getJSONObject("route").getString("final"));String tag=selected.getString("default");JSONObject out=tagged(outbounds,tag);
    JSONObject raw=new JSONObject(new String(Base64.getDecoder().decode(original.members.get(last).bundle().getJSONObject("profiles").getJSONObject("hysteria2").getString("sing-box.json")),StandardCharsets.UTF_8)),transport=null;
    for(int i=0;i<raw.getJSONArray("outbounds").length();i++)if("hysteria2".equals(raw.getJSONArray("outbounds").getJSONObject(i).optString("type")))transport=raw.getJSONArray("outbounds").getJSONObject(i);
    check(transport!=null,"HY2 final lost its captured original transport");JSONObject tls=new JSONObject(transport.getJSONObject("tls").toString());
    check(tls.getString("certificate_path").equals("cert.pem"),"HY2 fixture lost its original private trust asset");tls.remove("certificate_path");tls.put("certificate",new JSONArray().put(new String(Base64.getDecoder().decode(original.members.get(last).bundle().getJSONObject("profiles").getJSONObject("hysteria2").getString("cert.pem")),StandardCharsets.UTF_8)));
    check(out.getString("type").equals("hysteria2")&&out.getString("password").equals(transport.getString("password"))&&ConnectionProfilesHarness.sameJSONValue(out.getJSONObject("tls"),tls),"HY2 final substituted original authentication or TLS identity");
    check(out.getString("detour").equals(graph.getJSONArray("endpoints").getJSONObject(last-1).getString("tag")),"HY2 final bypassed its complete preceding packet prefix");
    JSONObject dns=graph.getJSONObject("dns"),resolver=tagged(dns.getJSONArray("servers"),dns.getString("final"));
    check(resolver.getString("detour").equals(tag)&&resolver.getString("server").equals(profile(f.original.get(last)).getString("adguard_ipv4")),"HY2 final lost original selected Home DNS");
    for(int i=0;i<original.members.size();i++)check(capture.identityInputs.get(i).equals(original.members.get(i).bundle().getJSONObject("profiles").getJSONObject("wg").toString()),"HY2 ordered graph replaced original paired identity assets");
    try(AndroidNodeChainCapture replay=AndroidNodeChainCapture.reopen(capture.launchInput,original)){check(replay.launchInput.equals(capture.launchInput)&&replay.config.equals(capture.config),"HY2 ordered replay changed original source");}
   }
   var row=f.profiles.add("Original paired HY2 path");check(f.row().getJSONArray("multihop_nodes").getJSONObject(last).getString("mode").equals("hysteria2"),"HY2 saved profile silently selected SS final");
   f.changePolicies();f.profiles.load(row.id);var restored=f.profiles.currentOrderedPath();check(restored.modes.equals(original.modes),"HY2 profile Load replaced original ordered transports");
   for(int i=0;i<f.members.size();i++)check(ConnectionProfilesHarness.sameJSONValue(f.bundle(i).get("profiles"),f.original.get(i).get("profiles"))&&profile(f.bundle(i)).getString("mtu_policy").equals(profile(f.original.get(i)).getString("mtu_policy")),"HY2 profile Load replaced credentials, TLS source or MTU policy");
   AndroidOrderedPathSelection draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);check(draft.finalModes(f.control().id).equals(List.of("shadowsocks","hysteria2")),"paired final chooser omitted exact compatible HY2 source");
   reject(()->draft.finalModes(f.control().id).clear(),"final mode list is mutable");
   for(String mode:List.of("HY2","Hysteria2"," hysteria2","hysteria2 ","wg","awg2-fast","reality-vision"))reject(()->draft.setFinal(f.control().id,mode),"final editor normalized or widened unsupported transport");
   OrderedProductSurface ui=new OrderedProductSurface(f);ui.open();ui.choose(0);check(ui.dialog.labels[last].toString().contains("Final • Hysteria2"),"actual ordered editor mislabeled HY2 final as SS");
   ui.choose(last);ui.choose(0);check(ui.dialog.title.equals("Final Router transport")&&Arrays.equals(ui.dialog.labels,new String[]{"Shadowsocks 2022","Hysteria2"}),"actual ordered editor omitted explicit final transport choice");ui.choose(0);
   check(ui.dialog.labels[last].toString().contains("Final • Shadowsocks 2022"),"actual final callback ignored SS choice");ui.choose(last);ui.choose(0);ui.choose(1);ui.save();
   check(ui.message.isEmpty()&&ui.refreshes==1&&f.profiles.currentOrderedPath().modes.get(last).equals("hysteria2"),"actual final callback ignored selected HY2 transport");
   var live=f.profiles.currentOrderedPath();var stale=new AndroidOrderedPathSelection(f.nodes,f.profiles);JSONObject changed=f.bundle(last);profile(changed).put("api_token","new-hy2-original-token");f.replace(last,changed);f.nodes.select(f.control().id);
   reject(live::requireCurrent,"HY2 live capture adopted replaced final source");reject(stale::save,"HY2 editor adopted replaced final source");
  }
 }
 static void hysteriaFinalBoundaries(Path root)throws Exception{
  Fixture f=new Fixture(root,"2/hy2-wg");f.prefs.edit().putString("multihop_nodes","").putBoolean("multihop_on",false).commit();
  var legacy=new AndroidOrderedPathSelection(f.nodes,f.profiles);check(legacy.members().get(0).mode.equals("shadowsocks"),"new final support changed existing SS default");legacy.setFinal(f.control().id);check(legacy.members().get(0).mode.equals("shadowsocks"),"legacy final setter changed existing SS choice");
  JSONObject bundle=f.bundle(1);bundle.getJSONObject("profiles").remove("shadowsocks");f.replace(1,bundle);f.nodes.select(f.control().id);var only=new AndroidOrderedPathSelection(f.nodes,f.profiles);
  check(only.members().size()==1&&only.members().get(0).mode.equals("hysteria2")&&only.finalModes(f.control().id).equals(List.of("hysteria2")),"HY2-only paired final cannot be selected");
  Fixture layered=new Fixture(root,"3/aes-256-gcm");JSONObject source=layered.bundle(2);source.getJSONObject("profiles").put("hysteria2",f.bundle(1).getJSONObject("profiles").getJSONObject("hysteria2"));layered.replace(2,source);layered.nodes.select(layered.control().id);var denied=new AndroidOrderedPathSelection(layered.nodes,layered.profiles);
  check(!denied.finalModes(layered.control().id).contains("hysteria2"),"final picker offered unproved HY2 Start Layer");reject(()->denied.setFinal(layered.control().id,"hysteria2"),"final editor accepted layered HY2 source");
  Fixture mixed=new Fixture(root,"2/hy2-wg");var external=hostnameEntry("2022-blake3-aes-128-gcm");external.server="198.51.100.76";new AndroidStandardExitStore(mixed.context).save(external);var imported=new AndroidOrderedPathSelection(mixed.nodes,mixed.profiles);
  check(imported.prefixModes(external.id).isEmpty(),"HY2 final offered unsupported imported middle");reject(()->imported.addPrefix(external.id,"shadowsocks"),"HY2 final admitted imported middle before Save");
  imported.setFinal(mixed.control().id,"shadowsocks");imported.addPrefix(external.id,"shadowsocks");check(imported.finalModes(mixed.control().id).equals(List.of("shadowsocks")),"imported schema2 offered unsupported HY2 final");reject(()->imported.setFinal(mixed.control().id,"hysteria2"),"imported schema2 admitted HY2 final before Save");
 }
 public static void main(String[] args)throws Exception{
  Path root=Path.of(args[0]);String family=args.length>1?args[1]:"all";
  if(family.equals("hysteria-final")){hysteriaFinalBoundaries(root);hysteriaFinal(root);System.out.println("Android paired HY2 final sources: "+checks+" shipping Java/shared Go checks passed; native crypto separate");return;}
  if(family.equals("hostname")){hostnamePolicyControls(root);hostnameMiddle(root);System.out.println("Android hostname ordered sources: "+checks+" shipping Java/shared Go checks passed; no native execution");return;}
  if(family.equals("imported")){importedMiddle(root);System.out.println("Android imported ordered methods: "+checks+" shipping Java/shared Go checks passed");return;}
  if(family.equals("source")){sourceControls(root);return;}if(family.equals("generation")){generationControls(root);return;}
  if(family.equals("atomic")){captureAtomicity(root);return;}
  if(family.equals("restore")){roundtrip(root,"3/");return;}
  if(family.equals("editor-generation")){editorGeneration(root);return;}
  if(family.equals("ordered-permission")){orderedPermission(root);return;}
  if(family.equals("editor-native")){editorNative(root);return;}
  if(family.equals("editor-atomic")){editorAtomicity(root);return;}
  if(family.equals("editor-budget")){editorFinalBudget(root);return;}
  if(family.equals("editor-ui")){editorHandlers(root);return;}
  if(family.equals("product-handoff")){productHandoff(root);return;}
  if(family.equals("paired-identity")){pairedIdentity(root);return;}
  if(family.equals("native-identity")){nativeIdentityReceipt(root);return;}
  if(family.equals("identity-compiler")){identityCompilerAdmission(root);return;}
  if(family.equals("editor-mixed")){editorMixed(root);return;}
  if(family.equals("editor-mixed-ui")){editorMixedHandlers(root);return;}
  for(String key:List.of("2/","3/","4/","8/","3/aes-256-gcm","4/aes-256-gcm+xor-whitening","4/fixed-middle","2/awg-fast","3/awg-strong","4/mixed-awg","8/mixed-awg"))roundtrip(root,key);
  sourceControls(root);generationControls(root);validationControls(root);compilationRace(root);captureAtomicity(root);
  editorChecks(root);editorGeneration(root);editorFailures(root);orderedPermission(root);editorNative(root);editorAtomicity(root);editorFinalBudget(root);editorHandlers(root);productHandoff(root);
  pairedIdentity(root);nativeIdentityReceipt(root);identityCompilerAdmission(root);editorMixed(root);editorMixedHandlers(root);
  importedMiddle(root);System.out.println("Android ordered sources: "+checks+" checks; actual Go compilation, exact all-member saved capture and rollback passed");
 }
}
'''


def prepare_sources(src, app, java):
    shutil.copyfile(java / "AndroidNodeChainCapture.java", app / "AndroidNodeChainCapture.java")
    shutil.copyfile(java / "AndroidOrderedPathSelection.java", app / "AndroidOrderedPathSelection.java")
    shutil.copyfile(java / "AndroidConnectionSelection.java", app / "AndroidConnectionSelection.java")
    (app / "NodeChainCaptureHarness.java").write_text(HARNESS)
    from test_android_connection_profiles import method
    handlers="\n".join(method("ProductActivity.java", signature) for signature in ("private void configureMultihop(","private void showOrderedEditor(","private void chooseOrderedNode(","private void chooseOrderedFinalMode(","private void chooseOrderedMode(","private void editOrderedPrefix("))
    surface=r'''package com.eabusham.routervpn;
import android.content.*;import java.util.*;
final class OrderedProductSurface extends Context {
 final NodeChainCaptureHarness.Fixture fixture;final AndroidNodeStore nodeStore;final AndroidStandardExitStore exitStore;
 OrderedProductSurface(NodeChainCaptureHarness.Fixture f){super(f.context.getFilesDir());fixture=f;nodeStore=f.nodes;exitStore=new AndroidStandardExitStore(f.context);}
 @Override public MemoryPreferences getSharedPreferences(String name,int mode){return fixture.context.getSharedPreferences(name,mode);}
 static final class Label{String text="";void setText(String value){text=value;}}final Label statusView=new Label();String message="";int refreshes;
 boolean mutationBusy(){return AndroidVpnMutationGuard.isBusy(this);}boolean isExternalSelected(){return false;}void configurePairMultihop(){throw new AssertionError("ordered editor silently became pair editor");}
 void toast(String value){message=value;}static String safe(Exception e){return e.getMessage();}void refreshAll(){refreshes++;}
 interface Click{void run(Object d,int index);}
 static final class Choice{final OrderedProductSurface owner;String title,detail;CharSequence[] labels;Click selected,positive,negative;Choice(OrderedProductSurface owner,String title,String detail){this.owner=owner;this.title=title;this.detail=detail;}Choice setItems(CharSequence[] items,Click listener){labels=items;selected=listener;return this;}Choice setPositiveButton(String label,Click listener){positive=listener;return this;}Choice setNegativeButton(String label,Click listener){negative=listener;return this;}void show(){owner.dialog=this;}}
 Choice dialog;Choice choiceDialog(String title,String detail){return new Choice(this,title,detail);}void open(){configureMultihop();}void choose(int i){Choice before=dialog;dialog=null;before.selected.run(before,i);}void save(){Choice before=dialog;dialog=null;before.positive.run(before,0);}void cancel(){dialog=null;}
 static final class AlertDialog{static final class Builder{final Choice choice;Builder(OrderedProductSurface owner){choice=owner.choiceDialog("","");}Builder setTitle(String title){choice.title=title;return this;}Builder setItems(CharSequence[] items,Click selected){choice.setItems(items,selected);return this;}Builder setNegativeButton(String label,Click selected){choice.setNegativeButton(label,selected);return this;}void show(){choice.show();}}}
 // ACTUAL_ORDERED_HANDLERS
}
'''
    (app / "OrderedProductSurface.java").write_text(surface.replace("// ACTUAL_ORDERED_HANDLERS", handlers))
    libbox = src / "io/nekohasekai/libbox/Libbox.java"
    source = libbox.read_text()
    marker = "private static String call(String...args)throws Exception{"
    assert source.count(marker) == 1
    source = source.replace(marker, r'''public static Runnable afterChainMember;
public static String routerNodeChainMemberInput(String mode,String files,String profile,String start,String bootstrap)throws Exception{String value=call("chain-member",mode,files,profile,start,bootstrap);Runnable hook=afterChainMember;afterChainMember=null;if(hook!=null)hook.run();return value;}
public static RouterNodeChain newRouterNodeChain(String source)throws Exception{return new RouterNodeChain(call("chain-new",source));}
public static RouterNodeChain routerNodeChainLaunch(String source)throws Exception{return new RouterNodeChain(call("chain-replay",source));}
static String call(String...args)throws Exception{''')
    libbox.write_text(source)
    (src / "io/nekohasekai/libbox/RouterNodeChain.java").write_text(NATIVE)
    boundaries = app / "Boundaries.java"
    source = boundaries.read_text()
    marker = "static byte[] read(File file,int max)throws Exception{byte[] bytes=Files.readAllBytes(file.toPath());"
    assert source.count(marker) == 1
    source = source.replace(marker, "static volatile java.util.function.Consumer<File> orderedRead;\nstatic byte[] read(File file,int max)throws Exception{java.util.function.Consumer<File> hook=orderedRead;if(hook!=null)hook.accept(file);byte[] bytes=Files.readAllBytes(file.toPath());")
    boundaries.write_text(source)


def run(root, work, app, classes, jar, env, imported_only=False):
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
    subprocess.run(command + (["imported"] if imported_only else []), env=env, check=True, timeout=180)
    subprocess.run(command + ["hostname"], env=env, check=True, timeout=180)
    if not imported_only:
        subprocess.run(command + ["hysteria-final"], env=env, check=True, timeout=180)
    node = (app / "AndroidNodeStore.java").read_text()
    store = (app / "AndroidConnectionProfileStore.java").read_text()
    permission = (app / "AndroidConnectionSelection.java").read_text()
    editor = (app / "AndroidOrderedPathSelection.java").read_text()
    editor_ui = (app / "OrderedProductSurface.java").read_text()
    product_ui = (app / "ProductConnectSurface.java").read_text()
    capture = (app / "AndroidNodeChainCapture.java").read_text()
    standard = (app / "AndroidStandardExitStore.java").read_text()
    from test_android_connection_profiles import method
    hostname_policy = method("AndroidStandardExitStore.java", "static void validateImportedHostnamePolicy(")
    assert standard.count(hostname_policy) == 1
    preview_start = editor.index("        RouterNodeChain preview=")
    preview_end = editor.index("        AndroidNodeStore.ChainCapture captured=", preview_start)
    publication_lock = "synchronized <T> T publishChainCatalog(ChainCatalog captured, ChainPublication<T> publication) throws Exception { synchronized (STORE_LOCK)"
    source_guard = "!java.util.Arrays.equals(source.original, chainSourceBytes(source))"
    epoch_guard = "captured.generation != selectionGeneration"
    capture_lock = "synchronized ChainCapture captureChain(String controlId) throws Exception { synchronized (STORE_LOCK)"
    stage_start = store.index("    private void stageOrderedNodes(")
    stage_end = store.index("    private static JSONArray orderedReferences(", stage_start)
    stage = store[stage_start:stage_end]
    assert stage.count("for(int i=0;i<members.length();i++)") == 1
    controls = (
        ("hysteria-final", "OrderedProductSurface", editor_ui.replace('draft.setFinal(id,modes.get(w));', 'draft.setFinal(id,"shadowsocks");'), "actual final callback ignored selected HY2 transport"),
        ("hysteria-final", "OrderedProductSurface", editor_ui.replace('AndroidOrderedPathSelection.finalModeTitle(member.mode)', '"Shadowsocks 2022"'), "actual ordered editor mislabeled HY2 final as SS"),
        ("hysteria-final", "AndroidOrderedPathSelection", editor.replace('if(!imported&&(layer.isEmpty()||"off".equals(layer))&&hasMode(source,"hysteria2"))', 'if(!imported&&hasMode(source,"hysteria2"))'), "final picker offered unproved HY2 Start Layer"),
        ("hostname", "AndroidStandardExitStore", standard.replace(hostname_policy, "static void validateImportedHostnamePolicy(Entry e) throws Exception {}"), "hostname saved policy accepted home"),
        ("hostname", "AndroidNodeStore", node.replace("source.importedGeneration!=AndroidStandardExitStore.publicationGeneration()", "false"), "hostname resolver change-away/back revived old native source"),
        ("imported", "AndroidNodeStore", node.replace('if(key.length!=expected||!java.util.Base64.getEncoder().encodeToString(key).equals(entry.secret))', 'if(false)'), "invalid single PSK shown as ordered eligible"),
        ("imported", "AndroidNodeStore", node.replace("source.importedGeneration!=AndroidStandardExitStore.publicationGeneration()", "false"), "imported change-away/back revived old native source"),
        ("native-identity", "AndroidNodeChainCapture", capture.replace('record.getJSONArray("identity_sources")', 'record.has("identity_sources")?record.getJSONArray("identity_sources"):new JSONArray(identityInputs)'), "Android accepted a different native identity inventory: missing"),
        ("native-identity", "AndroidNodeChainCapture", capture.replace('if(!identityInputs.get(i).equals(returnedIdentities.getString(i)))', 'if(false)'), "Android accepted a different native identity inventory: replaced"),
        ("identity-compiler", "AndroidOrderedPathSelection", editor.replace('.put("identity_sources",identities)', ''), "ordered editor skipped full native identity source validation"),
        ("paired-identity", "AndroidNodeStore", node.replace('source.requirePairedIdentity();', ''), "ordered admission accepted a saved identity label without its original WireGuard asset"),
        ("paired-identity", "AndroidNodeChainCapture", capture.replace('member.requirePairedIdentity();', ''), "ordered compiler preview accepted an unproved saved identity label"),
        ("editor-mixed", "AndroidOrderedPathSelection", editor.replace('members.add(members.size()-1,new Member(source,mode));', 'members.add(members.size()-1,new Member(source,"wg"));'), "editor reordered a node without its exact transport"),
        ("editor-mixed-ui", "OrderedProductSurface", editor_ui.replace('else draft.setPrefixMode(position,modes.get(w));', 'else draft.setPrefixMode(position,"wg");'), "shipping ordered mode callback ignored the selected transport"),
        ("editor-mixed-ui", "OrderedProductSurface", editor_ui.replace('AndroidOrderedPathSelection.prefixModeTitle(member.mode)', '"WireGuard"'), "shipping ordered editor mislabeled exact per-prefix transports"),
        ("product-handoff", "ProductConnectSurface", product_ui.replace("AndroidConnectionSelection.requireCurrent(this,nodeStore,selection);", ""), "ordered Product adopted a replaced choice"),
        ("product-handoff", "ProductConnectSurface", product_ui.replace("if(!connection.pathCurrent(home))", "if(false)"), "ordered Product adopted a replaced Home"),
        ("product-handoff", "ProductConnectSurface", product_ui.replace("ticket!=orderedConnectTicket", "false"), "ordered Product adopted a replaced cancel"),
        ("product-handoff", "ProductConnectSurface", product_ui.replace("isFinishing()||isDestroyed()", "false"), "ordered Product adopted a replaced destroy"),
        ("source", "AndroidNodeStore", node.replace(source_guard, "false"), "ordered capture accepted replacement middle source"),
        ("generation", "AndroidNodeStore", node.replace(epoch_guard, "false"), "ordered capture revived after change-away and back"),
        ("atomic", "AndroidNodeStore", node.replace(capture_lock, capture_lock.replace("STORE_LOCK", "new Object()")), "ordered capture did not exclude the independent store publisher"),
        ("restore", "AndroidConnectionProfileStore", store[:stage_start] + stage.replace("for(int i=0;i<members.length();i++)", "for(int i=0;i<members.length();i+=2)") + store[stage_end:], "saved middle policy was dropped"),
        ("editor-generation", "AndroidNodeStore", node.replace("captured.selected.generation != selectionGeneration", "false"), "ordered editor revived after source change-away and back"),
        ("ordered-permission", "AndroidConnectionSelection", permission.replace('"multihop_on","multihop_nodes",', '"multihop_on",'), "permission digest omitted ordered member choices"),
        ("editor-native", "AndroidOrderedPathSelection", editor[:preview_start] + editor[preview_end:], "ordered editor skipped complete native chain validation"),
        ("editor-atomic", "AndroidNodeStore", node.replace(publication_lock, publication_lock.replace("STORE_LOCK", "new Object()")), "ordered editor did not exclude an independent source publisher until complete publication"),
        ("editor-budget", "AndroidConnectionProfileStore", store.replace('if(complete>AndroidNodeStore.MAX_CHAIN_SOURCE)', 'if(false)'), "ordered final references exceeded their aggregate bound after private publication"),
        ("editor-ui", "OrderedProductSurface", editor_ui.replace('else draft.movePrefix(position,target);', 'else {}'), "shipping ordered editor did not move the original first node later"),
    )
    assert node.count(source_guard) == node.count(epoch_guard) == node.count(capture_lock) == 1
    for index, (family, name, changed, witness) in enumerate(controls):
        if imported_only and family not in ("imported", "hostname"):
            continue
        control_id = f"{index}-{family}"
        negative = work / ("ordered-negative-" + control_id)
        shutil.copytree(classes, negative)
        source = work / ("ordered-source-" + control_id) / (name + ".java")
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
