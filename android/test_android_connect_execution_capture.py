#!/usr/bin/env python3
"""Actual Android CONNECT execution stores/capture against the shared Go compiler.

Native Run, lease, TUN and restoration stay explicit refusing boundaries. This
is source/profile evidence; the separate libbox and host gates own lifecycle.
"""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import test_android_node_chain_execution_capture as BASE

compiler_source = BASE.compiler_source
FINAL_LAYER_PHASES=tuple(f"layers-{count}-{execution}" for count in range(3,6) for execution in ("server","auto"))+("layers-invalid-http",)
FINAL_LAYER_EXTENDED_PHASES=tuple(f"layers-{count}-{execution}" for count in range(6,9) for execution in ("server","auto"))+("layers-invalid-https",)
HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;import java.nio.file.*;import java.util.*;import io.nekohasekai.libbox.*;
public final class ConnectExecutionCaptureHarness {
 static int checks;interface Checked{void run()throws Exception;}static void check(boolean yes,String why){checks++;if(!yes)throw new AssertionError(why);}
 static void reject(Checked call,String why)throws Exception{try{call.run();}catch(Exception expected){checks++;return;}throw new AssertionError(why);}
 static String sha256(String value)throws Exception{return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));}
 static AndroidStandardExitStore.Entry proxy(String wire,boolean auth){var e=new AndroidStandardExitStore.Entry();e.id="1234567890abcdef1234567890abcdef";e.name="Original execution proxy";e.protocol=wire;e.server="198.51.100.76";e.serverPort=1080;e.expectedPublicIp="203.0.113.76";e.tlsServerName="original.proxy.example";e.username=auth?"original-user":"";e.password=auth?"original-password":"";return e;}
 static void proofInventory(AndroidNodeChainCapture local,int count)throws Exception{
  JSONArray proofs=new JSONObject(local.connect.plan.metadata()).getJSONArray("proofs");check(proofs.length()==count,"complete CONNECT omitted original proof inventory");
  for(int i=0;i<count;i++){
   JSONObject proof=proofs.getJSONObject(i),member=new JSONObject(local.memberInputs.get(i));
   check(proof.getInt("position")==i,"complete CONNECT renumbered an original proof");
   if(i==count-2)check(proof.getString("node_id").isEmpty()&&proof.getString("node_kind").equals("external"),"complete CONNECT import borrowed a private Router proof");
   else{JSONObject profile=new JSONObject(member.getString("profile_json"));String layer=profile.optString("start_layer","off");if(layer.isEmpty())layer="off";
    check(proof.getString("node_id").equals(profile.getString("node_proof_id"))&&proof.getString("profile_id").equals(profile.getString("id"))&&proof.getString("mode").equals(member.getString("mode"))&&proof.getString("start_layer").equals(layer),"complete CONNECT proof replaced original paired identity, mode or layer");}
  }
 }
 static void positive(Path root,int count,String selectedWire)throws Exception {
  for(String first:count==3?List.of("","awg-fast","awg-strong"):List.of("mixed-awg"))for(String wire:selectedWire.isEmpty()?List.of("http","https"):List.of(selectedWire))for(String requested:List.of("server","auto")) {
   var f=new NodeChainCaptureHarness.Fixture(root,"connect/"+(count-1)+"/"+first);var exits=new AndroidStandardExitStore(f.context);var custom=proxy(wire,true);exits.save(custom);
   var editor=new AndroidOrderedPathSelection(f.nodes,f.profiles);editor.addPrefix(custom.id,AndroidExternalPolicy.protocol(wire));editor.save();
   var ui=new OrderedProductSurface(f);ui.open();ui.choose(0);ui.execution();
   check(ui.dialog.labels.length==3&&ui.dialog.labels[2].toString().equals("Compare both"),"CONNECT prefix editor lost original execution choices");
   ui.choose(requested.equals("server")?1:2);check(ui.dialog!=null&&ui.message.isEmpty(),"CONNECT prefix editor refused captured execution");ui.save();
   check(ui.message.isEmpty(),"CONNECT prefix editor refused captured execution");var saved=f.profiles.currentOrderedPath();
   check(saved.members.size()==count&&saved.execution.equals(requested),"CONNECT prefix editor changed its complete requested source");
   AndroidNodeChainCapture compiled;try{compiled=AndroidNodeChainCapture.compile(saved);}catch(Exception error){throw new AssertionError("CONNECT prefix launch capture was refused",error);}
   try(var local=compiled) {
    AndroidNodeChainExecutionCapture prepared;try{prepared=AndroidNodeChainExecutionCapture.compile(local,requested);}catch(Exception error){throw new AssertionError("CONNECT prefix execution was refused",error);}
    try(var capture=prepared) {
    check(local.plan==null&&local.connect!=null&&local.socks==null,"CONNECT execution replaced typed source with ordinary authority");
    JSONObject prep=new JSONObject(capture.source),source=new JSONObject(prep.getString("local_source"));
    check(prep.getInt("schema")==4&&source.getInt("schema")==4&&requested.equals(prep.getString("execution")),"CONNECT execution lost its distinct source schema");
    check(new JSONObject(capture.launchInput).getString("kind").equals("routervpn-node-chain-connect-execution-preparation-input"),"CONNECT execution used generic launch authority");
    check(source.getJSONArray("nodes").length()==count&&source.getJSONArray("identity_sources").length()==count,"CONNECT execution omitted original prefix members");
    for(int i=0;i<count;i++)check(source.getJSONArray("nodes").getString(i).equals(local.memberInputs.get(i))&&source.getJSONArray("identity_sources").getString(i).equals(local.identityInputs.get(i))&&local.identityInputs.get(i).isEmpty()==(i==count-2),"CONNECT execution substituted original member or identity");
    proofInventory(local,count);
    try(var reopened=AndroidNodeChainExecutionCapture.reopen(local,capture.launchInput)){check(reopened.source.equals(capture.source)&&reopened.config.equals(capture.config),"typed execution replay changed original source");}
    reject(()->Libbox.newRouterNodeChainExecutionLaunch(capture.launchInput),"generic launch accepted CONNECT authority");
    reject(capture::captureRestore,"source fabricated native restoration");check(!capture.healthy(),"source fabricated native proof");
    var row=f.profiles.add("Original typed execution");String record=Files.readString(f.rows);check(!record.contains("original-password")&&!record.contains("original-user"),"saved profile copied private proxy credentials");
    f.profiles.load(row.id);var loaded=f.profiles.currentOrderedPath();check(loaded.execution.equals(requested)&&loaded.members.size()==count&&loaded.members.get(count-2).profileId.equals(custom.id)&&loaded.members.get(count-2).external().password.equals(custom.password),"profile Load changed exact proxy or execution");
    try(var after=AndroidNodeChainCapture.compile(loaded);var execution=AndroidNodeChainExecutionCapture.compile(after,requested)){check(execution.source.equals(capture.source),"profile roundtrip changed complete typed execution source");}
    custom.password="replacement-password";exits.save(custom);reject(capture::requireCurrent,"replaced proxy revived old execution source");
    String next=requested.equals("server")?"auto":"server";var update=new AndroidOrderedPathSelection(f.nodes,f.profiles);update.setExecution(next);update.save();f.profiles.update(row.id,"Updated complete CONNECT execution");f.changePolicies();f.profiles.load(row.id);
    var updated=f.profiles.currentOrderedPath();check(updated.execution.equals(next)&&updated.members.size()==count&&updated.members.get(count-2).external().password.equals("replacement-password"),"CONNECT profile Update lost current execution or original credential reference");
    try(var after=AndroidNodeChainCapture.compile(updated);var execution=AndroidNodeChainExecutionCapture.compile(after,next)){
     JSONObject replaced=f.bundle(count-3);NodeChainCaptureHarness.profile(replaced).put("api_token","replacement-later-prefix-token");f.replace(count-3,replaced);reject(execution::requireCurrent,"CONNECT execution survived a replaced later prefix");
    }
    f.profiles.delete(row.id);check(f.members.stream().allMatch(n->n.file.isFile()),"CONNECT profile Delete removed original private nodes");
    }
   }
  }
 }
 static void finalLayers(Path root,int count,String selectedExecution)throws Exception {
  for(String wire:List.of("http","https"))for(String layer:List.of("aes-256-gcm","aes-256-gcm+xor-whitening"))for(String requested:selectedExecution.isEmpty()?List.of("server","auto"):List.of(selectedExecution)){
   var f=new NodeChainCaptureHarness.Fixture(root,"connect/"+(count-1)+"/"+(count==3?"":"mixed-awg"));var exits=new AndroidStandardExitStore(f.context);var custom=proxy(wire,true);exits.save(custom);
   JSONObject selected=f.bundle(count-2);NodeChainCaptureHarness.profile(selected).put("start_layer",layer);f.replace(count-2,selected);
   var editor=new AndroidOrderedPathSelection(f.nodes,f.profiles);editor.addPrefix(custom.id,AndroidExternalPolicy.protocol(wire));editor.save();
   var ui=new OrderedProductSurface(f);ui.open();ui.choose(0);ui.execution();ui.choose(requested.equals("server")?1:2);ui.save();
   check(ui.message.isEmpty(),"CONNECT public editor refused selected final Start Layer");
   var saved=f.profiles.currentOrderedPath();check(saved.execution.equals(requested)&&saved.members.size()==count,"CONNECT final layer changed original execution or path");
   AndroidNodeChainCapture compiled;try{compiled=AndroidNodeChainCapture.compile(saved);}catch(Exception error){throw new AssertionError("CONNECT layered launch capture was refused",error);}
   try(var local=compiled;var execution=AndroidNodeChainExecutionCapture.compile(local,requested)){
    proofInventory(local,count);
    JSONObject original=new JSONObject(local.config),after=new JSONObject(execution.config);
    JSONArray proofs=new JSONObject(local.connect.plan.metadata()).getJSONArray("proofs");
    check(proofs.length()==count&&proofs.getJSONObject(count-1).getString("start_layer").equals(layer),"CONNECT proof inventory lost original final Start Layer");
    String tag=proofs.getJSONObject(count-1).getString("tag");JSONObject finalOutbound=NodeChainCaptureHarness.tagged(original.getJSONArray("outbounds"),tag);
    check(finalOutbound.getString("type").equals(layer.equals("aes-256-gcm+xor-whitening")?"routervpn-aes-xor":"shadowsocks"),"CONNECT execution omitted selected final Start Layer");
    check(finalOutbound.getString("method").equals("2022-blake3-aes-256-gcm"),"CONNECT final layer lost original AES-256-GCM method");
    check(finalOutbound.getJSONObject("udp_over_tcp").getBoolean("enabled")&&finalOutbound.getJSONObject("udp_over_tcp").getInt("version")==2,"CONNECT final layer lost its captured UoT-v2 owner");
    check(finalOutbound.getString("detour").equals(proofs.getJSONObject(count-2).getString("tag")),"CONNECT final layer changed its original proxy predecessor");
    check(ConnectionProfilesHarness.sameJSONValue(finalOutbound,NodeChainCaptureHarness.tagged(after.getJSONArray("outbounds"),tag)),"CONNECT execution replaced original layered final");
    JSONObject prep=new JSONObject(execution.source),source=new JSONObject(prep.getString("local_source"));
    check(source.getJSONArray("nodes").length()==count&&source.getJSONArray("identity_sources").length()==count,"CONNECT final layer lost complete prefix inventory");
    for(int i=0;i<count;i++)check(source.getJSONArray("nodes").getString(i).equals(local.memberInputs.get(i))&&source.getJSONArray("identity_sources").getString(i).equals(local.identityInputs.get(i)),"CONNECT final layer substituted original member or identity");
    JSONObject finalMember=new JSONObject(source.getJSONArray("nodes").getString(count-1));
    check(new JSONObject(finalMember.getString("profile_json")).getString("start_layer").equals(layer),"CONNECT source omitted selected final Start Layer");
    JSONObject originalAssets=new JSONObject(finalMember.getString("files"));JSONObject originalFinal=new JSONObject(new String(Base64.getDecoder().decode(originalAssets.getString("sing-box.json")),java.nio.charset.StandardCharsets.UTF_8)).getJSONArray("outbounds").getJSONObject(0);
    check(finalOutbound.getString("password").equals(originalFinal.getString("password"))&&finalOutbound.getString("method").equals(originalFinal.getString("method")),"CONNECT final layer replaced original cipher credentials");
    try(var reopened=AndroidNodeChainExecutionCapture.reopen(local,execution.launchInput)){check(reopened.source.equals(execution.source)&&reopened.config.equals(execution.config),"CONNECT layered execution reopen replaced original graph");}
    var row=f.profiles.add("Layered CONNECT execution");String record=Files.readString(f.rows);check(!record.contains("original-password")&&!record.contains("original-user"),"CONNECT layered profile copied private credentials");
    f.profiles.load(row.id);var loaded=f.profiles.currentOrderedPath();
    check(loaded.execution.equals(requested)&&loaded.members.size()==count&&loaded.members.get(count-1).profile().getString("start_layer").equals(layer)&&loaded.members.get(count-2).external().password.equals(custom.password),"CONNECT profile Load changed original final layer or proxy");
    try(var restored=AndroidNodeChainCapture.compile(loaded);var prepared=AndroidNodeChainExecutionCapture.compile(restored,requested)){check(prepared.source.equals(execution.source)&&prepared.config.equals(execution.config),"CONNECT layered profile roundtrip replaced captured graph");}
    String next=requested.equals("server")?"auto":"server";var update=new AndroidOrderedPathSelection(f.nodes,f.profiles);update.setExecution(next);update.save();f.profiles.update(row.id,"Updated layered CONNECT execution");f.changePolicies();f.profiles.load(row.id);
    var updated=f.profiles.currentOrderedPath();check(updated.execution.equals(next)&&updated.members.size()==count&&updated.members.get(count-1).profile().getString("start_layer").equals(layer),"CONNECT profile Update lost original final layer");
    try(var captured=AndroidNodeChainCapture.compile(updated);var prepared=AndroidNodeChainExecutionCapture.compile(captured,next)){
     JSONObject replacement=f.bundle(count-2);NodeChainCaptureHarness.profile(replacement).put("start_layer","off");f.replace(count-2,replacement);reject(prepared::requireCurrent,"CONNECT execution survived final-layer replacement");
    }
    f.profiles.delete(row.id);check(f.members.stream().allMatch(n->n.file.isFile()),"CONNECT layered profile Delete removed private nodes");
   }
  }
 }
 static void invalidFinalLayers(Path root,String wire)throws Exception {
  for(Object invalid:List.of(JSONObject.NULL,Boolean.TRUE,7,new JSONObject().put("mode","off"),new JSONArray().put("off"),"unknown-layer","xor-whitening"," aes-256-gcm"))for(String requested:List.of("server","auto")){
   var f=new NodeChainCaptureHarness.Fixture(root,"connect/2/");var exits=new AndroidStandardExitStore(f.context);var custom=proxy(wire,true);exits.save(custom);
   var original=new AndroidOrderedPathSelection(f.nodes,f.profiles);original.addPrefix(custom.id,AndroidExternalPolicy.protocol(wire));original.save();var requestedDraft=new AndroidOrderedPathSelection(f.nodes,f.profiles);requestedDraft.setExecution(requested);requestedDraft.save();
   JSONObject corrupted=f.bundle(1);NodeChainCaptureHarness.profile(corrupted).put("start_layer",invalid);f.replace(1,corrupted);
   reject(()->{var edit=new AndroidOrderedPathSelection(f.nodes,f.profiles);edit.setExecution(requested);edit.save();},"CONNECT public Save accepted malformed final Start Layer: "+invalid);
   reject(()->{try(var captured=AndroidNodeChainCapture.compile(f.profiles.currentOrderedPath())){}},"CONNECT launch accepted malformed final Start Layer: "+invalid);
   check(ConnectionProfilesHarness.sameJSONValue(NodeChainCaptureHarness.profile(f.bundle(1)).get("start_layer"),invalid),"CONNECT rejection rewrote malformed final layer as Off");
  }
 }
 static void refused(Path root)throws Exception {
  for(String key:List.of("3/","7/"))for(String wire:List.of("http","https")){
   var f=new NodeChainCaptureHarness.Fixture(root,"connect/"+key);var exits=new AndroidStandardExitStore(f.context);var e=proxy(wire,false);exits.save(e);var draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);draft.addPrefix(e.id,AndroidExternalPolicy.protocol(wire));
   try(var local=AndroidNodeChainCapture.compile(draft.save())){
    // Preserve the independent real shared-constructor and malformed-source
    // checks alongside the public editor/capture acceptance above.
    for(String requested:List.of("server","auto")){
     RouterNodeChainExecution plan=Libbox.newRouterNodeChainCONNECTExecution(local.launchInput,requested);
     try{
      int count=local.memberInputs.size();JSONObject preparation=new JSONObject(plan.source());JSONObject source=new JSONObject(preparation.getString("local_source"));
      check(count==Integer.parseInt(key.split("/")[0])+1&&preparation.getInt("schema")==4&&preparation.getString("execution").equals(requested)&&plan.requestedExecution().equals(requested),"complete CONNECT preparation changed its schema, count or requested execution");
      check(preparation.getString("local_source").equals(local.launchInput)&&source.getJSONArray("nodes").length()==count&&source.getJSONArray("identity_sources").length()==count,"complete CONNECT preparation omitted or replaced original source");
      for(int i=0;i<count;i++)check(source.getJSONArray("nodes").getString(i).equals(local.memberInputs.get(i))&&source.getJSONArray("identity_sources").getString(i).equals(local.identityInputs.get(i))&&local.identityInputs.get(i).isEmpty()==(i==count-2),"complete CONNECT preparation changed original member or identity");
      check(plan.localSourceSHA256().equals(local.sourceSHA256)&&plan.configSHA256().equals(sha256(plan.config())),"complete CONNECT preparation changed original source or config digest");
      JSONObject graph=new JSONObject(plan.config()),original=new JSONObject(local.config);
      check(ConnectionProfilesHarness.sameJSONValue(graph.getJSONArray("endpoints"),original.getJSONArray("endpoints"))&&ConnectionProfilesHarness.sameJSONValue(graph.getJSONArray("inbounds"),original.getJSONArray("inbounds")),"complete CONNECT preparation replaced original packet prefixes or TUN");
      JSONObject gate=NodeChainCaptureHarness.tagged(graph.getJSONArray("outbounds"),"routervpn-chain-application");check(graph.getJSONObject("route").getString("final").equals("routervpn-chain-application")&&gate.getString("type").equals("routervpn-node-chain-gate"),"complete CONNECT preparation removed the initially closed application gate");
      for(int i=0;i<original.getJSONArray("outbounds").length();i++){JSONObject outbound=original.getJSONArray("outbounds").getJSONObject(i);check(ConnectionProfilesHarness.sameJSONValue(outbound,NodeChainCaptureHarness.tagged(graph.getJSONArray("outbounds"),outbound.getString("tag"))),"complete CONNECT preparation changed original transport credentials or detour");}
      JSONObject launch=new JSONObject(plan.launchInput());check(launch.getInt("schema")==1&&launch.getString("kind").equals("routervpn-node-chain-connect-execution-preparation-input")&&launch.getString("source").equals(plan.source())&&launch.getString("source_sha256").equals(plan.sourceSHA256())&&launch.getString("config_sha256").equals(plan.configSHA256()),"complete CONNECT preparation lost its exact typed launch");
      RouterNodeChainExecution replay=Libbox.newRouterNodeChainCONNECTExecutionLaunch(plan.launchInput());try{check(replay.source().equals(plan.source())&&replay.config().equals(plan.config())&&replay.launchInput().equals(plan.launchInput()),"complete CONNECT replay changed original graph");}finally{replay.close();}
      reject(()->Libbox.newRouterNodeChainExecutionLaunch(plan.launchInput()),"generic source replay borrowed complete CONNECT authority");
      reject(plan::captureRestore,"complete CONNECT source fabricated restore authority");reject(plan::captureLastJSON,"complete CONNECT source fabricated Last authority");check(!plan.healthy(),"complete CONNECT source fabricated native proof");
     }finally{plan.close();}
    }
    for(String fault:List.of("family","short-identities","proxy-identity","duplicate-prefix","no-paired-prefix")){
     JSONObject changed=new JSONObject(local.launchInput);JSONArray members=changed.getJSONArray("nodes"),identities=changed.getJSONArray("identity_sources");
     if(fault.equals("family"))changed.put("schema",2);else if(fault.equals("short-identities"))identities.remove(0);else if(fault.equals("proxy-identity"))identities.put(members.length()-2,identities.getString(0));else if(fault.equals("no-paired-prefix")){changed.put("nodes",new JSONArray().put(members.getString(members.length()-2)).put(members.getString(members.length()-1)));changed.put("identity_sources",new JSONArray().put("").put(identities.getString(identities.length()-1)));}else members.put(1,members.getString(0));
     for(String requested:List.of("server","auto"))reject(()->Libbox.newRouterNodeChainCONNECTExecution(changed.toString(),requested),"complete CONNECT accepted malformed "+fault);
    }
    for(String requested:List.of("","local","Server","compare"))reject(()->Libbox.newRouterNodeChainCONNECTExecution(local.launchInput,requested),"complete CONNECT accepted unsupported requested execution");
    if(key.equals("7/")){
     var over=new NodeChainCaptureHarness.Fixture(root,"connect/8/");
     try(var paired=AndroidNodeChainCapture.compile(over.profiles.currentOrderedPath())){
      JSONArray members=new JSONArray(),identities=new JSONArray();for(int i=0;i<8;i++){if(i==7){members.put(local.memberInputs.get(6));identities.put("");}members.put(paired.memberInputs.get(i));identities.put(paired.identityInputs.get(i));}
      JSONObject changed=new JSONObject(local.launchInput).put("nodes",members).put("identity_sources",identities);check(members.length()==9&&identities.length()==9,"overbound control lost complete nine-member inventory");
      for(String requested:List.of("server","auto"))reject(()->Libbox.newRouterNodeChainCONNECTExecution(changed.toString(),requested),"complete CONNECT accepted nine original members");
     }
    }
   }
  }
 }
 static void readback(Path root,int count)throws Exception{
  for(String fault:count==3?List.of("family","member","identity","config","requested"):List.of("family","member","identity","config","requested","later-member","later-identity","missing-prefix","final-member")){
   var f=new NodeChainCaptureHarness.Fixture(root,"connect/"+(count-1)+"/");var exits=new AndroidStandardExitStore(f.context);var e=proxy("https",true);exits.save(e);var d=new AndroidOrderedPathSelection(f.nodes,f.profiles);d.addPrefix(e.id,"https-connect");d.setExecution("server");
   try(var local=AndroidNodeChainCapture.compile(d.save())){
    Libbox.afterExecution=p->{try{if(fault.equals("config")){p.value.put("config_sha256","f".repeat(64));return;}if(fault.equals("requested")){p.value.put("requested","auto");return;}JSONObject prep=new JSONObject(p.value.getString("source"));JSONObject source=new JSONObject(prep.getString("local_source"));if(fault.equals("family"))prep.put("schema",1);else{String field=fault.endsWith("identity")?"identity_sources":"nodes";JSONArray a=source.getJSONArray(field);if(fault.equals("missing-prefix"))a.remove(count-3);else a.put(fault.startsWith("later-")?count-3:fault.equals("final-member")?count-1:1,a.getString(0));prep.put("local_source",source.toString());}p.value.put("source",prep.toString());JSONObject launch=new JSONObject(p.value.getString("launch"));launch.put("source",prep.toString());p.value.put("launch",launch.toString());}catch(Exception x){throw new IllegalStateException(x);}};
    reject(()->AndroidNodeChainExecutionCapture.compile(local,"server"),"typed execution accepted substituted "+fault);
   }finally{Libbox.afterExecution=null;}
  }
 }
 public static void main(String[] args)throws Exception{Path root=Path.of(args[0]);String phase=args.length>1?args[1]:"all";if(phase.equals("all")||phase.equals("positive"))positive(root,3,"");if(phase.startsWith("positive-")){String[] parts=phase.substring(9).split("-");positive(root,Integer.parseInt(parts[0]),parts.length==1?"":parts[1]);}if(phase.equals("all")||phase.equals("layers"))finalLayers(root,3,"server");if(phase.startsWith("layers-invalid-"))invalidFinalLayers(root,phase.substring(15));else if(phase.startsWith("layers-")){String[] parts=phase.substring(7).split("-");finalLayers(root,Integer.parseInt(parts[0]),parts[1]);}if(phase.equals("all")||phase.equals("refused"))refused(root);if(phase.equals("all")||phase.equals("readback"))readback(root,3);if(phase.startsWith("readback-"))readback(root,Integer.parseInt(phase.substring(9)));System.out.println("Android typed CONNECT execution: "+checks+" actual compiler/store checks PASS");}
}
'''

def prepare_sources(src, app, java):
    BASE.prepare_sources(src, app, java)
    (app / "ConnectExecutionCaptureHarness.java").write_text(HARNESS)

def run(root, work, app, classes, jar, env, imported_only=False, family="ordinary"):
    if family not in ("ordinary","final-layers","final-layers-extended"):raise ValueError("Unknown complete CONNECT source family")
    original_generator=BASE.LOCAL.GENERATOR
    anchor='{4,"mixed-awg"},{8,"mixed-awg"}'
    if original_generator.count(anchor)!=1:raise AssertionError("Complete CONNECT mixed fixture inventory changed")
    generator=work/"android_chain_fixture_test.go";generator.write_text(original_generator.replace(anchor,'{4,"mixed-awg"},{5,"mixed-awg"},{6,"mixed-awg"},{8,"mixed-awg"}'))
    overlay=work/"connect-fixture-overlay.json";overlay.write_text(json.dumps({"Replace":{str(root/"internal/mobilemultihop/android_chain_fixture_test.go"):str(generator)}}))
    env=env.copy();env["ROUTERVPN_ANDROID_CHAIN_FIXTURE"]=str(work/"private-chain-fixtures.json")
    subprocess.run(["go","test","-p=1","-count=1","-overlay="+str(overlay),"./internal/mobilemultihop","-run","^TestAndroidOrderedSourceFixture$"],cwd=root,env=env,check=True,timeout=180)
    run_prepared(work,app,classes,jar,env,family)

def run_prepared(work,app,classes,jar,env,family):
    if family not in ("ordinary","final-layers","final-layers-extended"):raise ValueError("Unknown complete CONNECT source family")
    data=work/"connect-data";data.mkdir();cp=str(classes)+os.pathsep+str(jar)
    command=["java","-cp",cp,"com.eabusham.routervpn.ConnectExecutionCaptureHarness",str(data)]
    # Preserve every complete eight-member profile transaction while giving each
    # HTTP/HTTPS inventory the same original 120-second per-process limit.
    phases=FINAL_LAYER_PHASES if family=="final-layers" else FINAL_LAYER_EXTENDED_PHASES if family=="final-layers-extended" else ("positive","refused","readback","positive-4",*("positive-"+str(count)+"-"+wire for count in (5,6,7,8) for wire in ("http","https")),"readback-4","readback-8")
    for phase in phases:
        subprocess.run([*command,phase],env=env,check=True,timeout=120)
    if family=="final-layers-extended":return
    if family=="final-layers":
        run_final_layer_controls(work,app,classes,jar,env,data)
        return
    original=(app/"AndroidNodeChainExecutionCapture.java").read_text()
    for name,old,witness in (("member",'!sameStrings(original.getJSONArray("nodes"), returned.getJSONArray("nodes"))','typed execution accepted substituted member'),("identity",'!sameStrings(original.getJSONArray("identity_sources"), returned.getJSONArray("identity_sources"))','typed execution accepted substituted identity')):
        if original.count(old)!=1:raise AssertionError(name+" guard anchor changed")
        source=work/("connect-mutant-"+name)/"AndroidNodeChainExecutionCapture.java";source.parent.mkdir();source.write_text(original.replace(old,"false"))
        out=work/("connect-negative-"+name);shutil.copytree(classes,out);classpath=str(out)+os.pathsep+str(jar)
        subprocess.run(["javac","--release","17","-encoding","UTF-8","-proc:none","-cp",classpath,"-d",str(out),str(source)],check=True,timeout=60)
        result=subprocess.run(["java","-cp",classpath,command[3],str(data),"readback"],env=env,text=True,capture_output=True,timeout=120)
        if result.returncode!=1 or witness not in result.stderr:raise AssertionError(name+" missed exact ownership witness:\n"+result.stdout+result.stderr)
        print("CONNECT execution ownership causal control rejected: "+name)
    admission_controls=(
        ("editor-trio","AndroidOrderedPathSelection",'schema==4&&(members.size()<3||members.size()>8)','schema==4&&members.size()!=3',"CONNECT prefix editor refused captured execution"),
        ("stored-trio","AndroidNodeStore",'|| java.util.Arrays.asList("http-connect","https-connect").contains(mode)','|| selected.length()==3 && java.util.Arrays.asList("http-connect","https-connect").contains(mode)',"CONNECT prefix editor refused captured execution"),
        ("returned-trio","AndroidNodeChainExecutionCapture",'originalSchema == 4 && (originalCount < 3 || originalCount > 8)','originalSchema == 4 && originalCount != 3',"CONNECT prefix execution was refused"),
    )
    for name,owner,before,after,witness in admission_controls:
        captured=(app/(owner+".java")).read_text()
        if captured.count(before)!=1:raise AssertionError(name+" complete-prefix anchor changed")
        target=work/("connect-prefix-mutant-"+name)/(owner+".java");target.parent.mkdir();target.write_text(captured.replace(before,after))
        out=work/("connect-prefix-negative-"+name);shutil.copytree(classes,out);classpath=str(out)+os.pathsep+str(jar)
        subprocess.run(["javac","--release","17","-encoding","UTF-8","-proc:none","-cp",classpath,"-d",str(out),str(target)],check=True,timeout=60)
        result=subprocess.run(["java","-cp",classpath,command[3],str(data),"positive-4"],env=env,text=True,capture_output=True,timeout=120)
        if result.returncode!=1 or witness not in result.stderr:raise AssertionError(name+" missed exact complete-prefix admission witness:\n"+result.stdout+result.stderr)
        print("CONNECT complete-prefix admission causal control rejected: "+name)
    # These controls corrupt readback only after the actual shared constructor
    # succeeds. No source-only result can stand in for native Run or authority.
    native='RouterNodeChainExecution plan=Libbox.newRouterNodeChainCONNECTExecution(local.launchInput,requested);'
    if HARNESS.count(native)!=1:raise AssertionError("complete CONNECT constructor anchor changed")
    for name,corruption,witness in (
        ("complete-source", 'JSONObject preparation=new JSONObject(p.value.getString("source"));JSONObject source=new JSONObject(preparation.getString("local_source"));source.getJSONArray("nodes").remove(0);preparation.put("local_source",source.toString());p.value.put("source",preparation.toString());', 'complete CONNECT preparation omitted or replaced original source'),
        ("packet-prefix", 'JSONObject graph=new JSONObject(p.value.getString("config"));graph.getJSONArray("endpoints").remove(0);p.value.put("config",graph.toString());p.value.put("config_sha256",sha256(graph.toString()));', 'complete CONNECT preparation replaced original packet prefixes or TUN'),
    ):
        hook='Libbox.afterExecution=p->{try{'+corruption+'}catch(Exception error){throw new IllegalStateException(error);}};'
        source=work/("connect-complete-mutant-"+name)/"ConnectExecutionCaptureHarness.java";source.parent.mkdir();source.write_text(HARNESS.replace(native,hook+native))
        out=work/("connect-complete-negative-"+name);shutil.copytree(classes,out);classpath=str(out)+os.pathsep+str(jar)
        subprocess.run(["javac","--release","17","-encoding","UTF-8","-proc:none","-cp",classpath,"-d",str(out),str(source)],check=True,timeout=60)
        result=subprocess.run(["java","-cp",classpath,command[3],str(data),"refused"],env=env,text=True,capture_output=True,timeout=120)
        if result.returncode!=1 or witness not in result.stderr:raise AssertionError(name+" missed exact complete-source witness:\n"+result.stdout+result.stderr)
        print("CONNECT complete source causal control rejected: "+name)

def run_final_layer_controls(work,app,classes,jar,env,data):
    command=["java","-cp",str(classes)+os.pathsep+str(jar),"com.eabusham.routervpn.ConnectExecutionCaptureHarness",str(data)]
    for name,owner,before,after,witness in (
        ("editor-final-off","AndroidOrderedPathSelection",'for(Member member:members)if(member.source.imported) {','if(schema==4&&!java.util.Arrays.asList("","off").contains(members.get(members.size()-1).source.profile().optString("start_layer","off")))throw new IllegalStateException("old Off-only editor");for(Member member:members)if(member.source.imported) {',"CONNECT public editor refused selected final Start Layer"),
        ("preview-final-off","AndroidNodeChainCapture",'RouterNodeChainExecution preview=Libbox.newRouterNodeChainCONNECTExecution(input,execution);','if(!java.util.Arrays.asList("","off").contains(new JSONObject(new JSONObject(original.getJSONArray("nodes").getString(count-1)).getString("profile_json")).optString("start_layer","off")))throw new IllegalStateException("old Off-only preview");RouterNodeChainExecution preview=Libbox.newRouterNodeChainCONNECTExecution(input,execution);',"CONNECT public editor refused selected final Start Layer"),
        ("capture-final-off","AndroidNodeChainCapture",'connect=isCONNECT?AndroidNodeChainCONNECTCapture.compile(source,inputs,identities):null;','if(isCONNECT&&!"local".equals(selectionExecution)&&!java.util.Arrays.asList("","off").contains(original.members.get(count-1).profile().optString("start_layer","off")))throw new IllegalStateException("old Off-only capture");connect=isCONNECT?AndroidNodeChainCONNECTCapture.compile(source,inputs,identities):null;',"CONNECT layered launch capture was refused"),
    ):
        captured=(app/(owner+".java")).read_text()
        if captured.count(before)!=1:raise AssertionError(name+" original final-layer source changed")
        target=work/("connect-layer-mutant-"+name)/(owner+".java");target.parent.mkdir();target.write_text(captured.replace(before,after))
        out=work/("connect-layer-negative-"+name);shutil.copytree(classes,out);classpath=str(out)+os.pathsep+str(jar)
        sources=[str(target)]
        if name=="editor-final-off":
            # Only this counterfactual refuses the choice before another Save
            # dialog exists. Require its exact injected refusal at that point;
            # unrelated UI failures must not acquire the intended witness.
            before_choice='ui.choose(requested.equals("server")?1:2);ui.save();'
            after_choice='ui.choose(requested.equals("server")?1:2);if(ui.message.equals("old Off-only editor"))throw new AssertionError("CONNECT public editor refused selected final Start Layer");ui.save();'
            if HARNESS.count(before_choice)!=1:raise AssertionError("Original final-layer UI choice changed")
            causal=target.parent/"ConnectExecutionCaptureHarness.java"
            causal.write_text(HARNESS.replace(before_choice,after_choice));sources.append(str(causal))
        subprocess.run(["javac","--release","17","-encoding","UTF-8","-proc:none","-cp",classpath,"-d",str(out),*sources],check=True,timeout=60)
        result=subprocess.run(["java","-cp",classpath,command[3],str(data),"layers"],env=env,text=True,capture_output=True,timeout=120)
        if result.returncode!=1 or witness not in result.stderr:raise AssertionError(name+" missed original final-layer witness:\n"+result.stdout+result.stderr)
        print("CONNECT independent final-layer causal control rejected: "+name)

if __name__=="__main__":
    import test_android_connection_profiles as profiles
    if len(sys.argv)!=1:raise ValueError("This gate takes no arguments")
    sys.argv += ["--case-family","ordered-connect-execution"]
    profiles.main()
