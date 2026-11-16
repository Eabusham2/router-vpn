#!/usr/bin/env python3
"""Exercise Android's original execution preparation with the shared Go compiler.

This uses the real stores and Local source constructor from the ordered source
gate. The Java execution boundary invokes NewNodeChainExecutionPreparation;
native Run/measurement/restore are refusing boundaries here. This is source
capture evidence, never Android VPN or Server traffic acceptance.
"""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys

import test_android_node_chain_capture as LOCAL


def compiler_source(source):
    return LOCAL.compiler_source(source)


HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;import java.nio.file.*;import java.util.*;import io.nekohasekai.libbox.*;
public final class NodeChainExecutionCaptureHarness {
 static int checks;interface Checked{void run()throws Exception;}static void check(boolean yes,String why){checks++;if(!yes)throw new AssertionError(why);}
 static void reject(Checked operation,String why)throws Exception{try{operation.run();}catch(Exception expected){checks++;return;}throw new AssertionError(why);}
 static void source(Path root)throws Exception {
  for(String key:List.of("2/","3/awg-strong","4/mixed-awg","8/mixed-awg"))for(String requested:List.of("server","auto")){
   var fixture=new NodeChainCaptureHarness.Fixture(root,key);fixture.chooseExecution(requested);var original=fixture.profiles.currentOrderedPath();
   try(var local=AndroidNodeChainCapture.compile(original);var captured=AndroidNodeChainExecutionCapture.compile(local,requested)){
    check(captured.local==local&&captured.requested.equals(requested),"execution lost complete original Local capture");
    JSONObject source=new JSONObject(captured.source),retained=new JSONObject(source.getString("local_source"));
    check(retained.getJSONArray("nodes").length()==original.members.size()&&retained.getJSONArray("identity_sources").length()==original.members.size(),"execution shortened original source inventory");
    for(int i=0;i<original.members.size();i++)check(retained.getJSONArray("nodes").getString(i).equals(local.memberInputs.get(i))&&retained.getJSONArray("identity_sources").getString(i).equals(local.identityInputs.get(i)),"execution substituted original node/identity at "+i);
    JSONObject graph=new JSONObject(captured.config);check(graph.getJSONArray("inbounds").length()==1&&graph.getJSONObject("route").getString("final").equals("routervpn-chain-application"),"preparation lost its one gated TUN");
    JSONObject gate=null;JSONArray outbounds=graph.getJSONArray("outbounds");for(int i=0;i<outbounds.length();i++){JSONObject row=outbounds.getJSONObject(i);if(row.optString("tag").equals("routervpn-chain-application"))gate=row;}
    check(gate!=null&&gate.getString("type").equals("routervpn-node-chain-gate")&&gate.getString("detour").equals("proxy")&&!gate.has("open"),"preparation forwarded application traffic before proof");
    try(var reopened=AndroidNodeChainExecutionCapture.reopen(local,captured.launchInput)){check(reopened.config.equals(captured.config)&&reopened.source.equals(captured.source),"source replay changed original projection");}
    reject(captured::execution,"source preparation fabricated a proved choice");reject(captured::captureRestore,"source preparation fabricated a restore owner");
    for(String invalid:List.of("local","Server","compare","", " auto"))reject(()->AndroidNodeChainExecutionCapture.compile(local,invalid),"execution normalized an unowned choice");
    JSONObject altered=new JSONObject(captured.launchInput).put("source_sha256","f".repeat(64));reject(()->AndroidNodeChainExecutionCapture.reopen(local,altered.toString()),"replay accepted a substituted source hash");
   }
  }
 }
 static void nativeReadback(Path root)throws Exception {
  for(String fault:List.of("requested","local-digest","config-digest","envelope","member-order","identity-order","identity-missing","source-schema")){
   var fixture=new NodeChainCaptureHarness.Fixture(root,"3/");fixture.chooseExecution("auto");try(var local=AndroidNodeChainCapture.compile(fixture.profiles.currentOrderedPath())){
    Libbox.afterExecution=plan->{try{
     if(fault.equals("requested")){plan.value.put("requested","server");return;}
     if(fault.equals("local-digest")){plan.value.put("local_source_sha256","e".repeat(64));return;}
     if(fault.equals("config-digest")){plan.value.put("config_sha256","e".repeat(64));return;}
     JSONObject launch=new JSONObject(plan.value.getString("launch"));
     if(fault.equals("envelope")){launch.put("session_id","foreign");plan.value.put("launch",launch.toString());return;}
     JSONObject prep=new JSONObject(plan.value.getString("source")),source=new JSONObject(prep.getString("local_source"));
     if(fault.equals("source-schema"))source.put("schema",2);
     else{String field=fault.startsWith("member")?"nodes":"identity_sources";JSONArray rows=source.getJSONArray(field),replacement=new JSONArray();
      if(fault.equals("identity-missing")){for(int i=1;i<rows.length();i++)replacement.put(rows.get(i));}
      else{replacement.put(rows.get(1)).put(rows.get(0));for(int i=2;i<rows.length();i++)replacement.put(rows.get(i));}source.put(field,replacement);}
     prep.put("local_source",source.toString());plan.value.put("source",prep.toString());launch.put("source",prep.toString());plan.value.put("launch",launch.toString());
    }catch(Exception error){throw new IllegalStateException(error);}};
    reject(()->AndroidNodeChainExecutionCapture.compile(local,"auto"),"execution accepted native readback substitution: "+fault);
   }finally{Libbox.afterExecution=null;}
  }
 }
 static void changedSource(Path root)throws Exception{
  var fixture=new NodeChainCaptureHarness.Fixture(root,"3/");fixture.chooseExecution("auto");try(var local=AndroidNodeChainCapture.compile(fixture.profiles.currentOrderedPath())){
   Libbox.afterExecution=plan->{try{JSONObject bundle=fixture.bundle(0);NodeChainCaptureHarness.profile(bundle).put("name","newer member");fixture.replace(0,bundle);}catch(Exception error){throw new IllegalStateException(error);}};
   try{reject(()->AndroidNodeChainExecutionCapture.compile(local,"auto"),"execution survived original source replacement during compile");}finally{Libbox.afterExecution=null;}
  }
 }
 static AndroidNodeChainCapture importedLocal(Path root,String first,String method,String requested)throws Exception{return importedLocalCount(root,"2/"+first,method,requested);}
 static AndroidNodeChainCapture importedLocalCount(Path root,String key,String method,String requested)throws Exception{
  var fixture=new NodeChainCaptureHarness.Fixture(root,key);
  var exits=new AndroidStandardExitStore(fixture.context);var custom=NodeChainCaptureHarness.hostnameEntry(method);
  custom.server="198.51.100.76";custom.name="Original execution middle";
  exits.save(custom);var editor=new AndroidOrderedPathSelection(fixture.nodes,fixture.profiles);
  editor.addPrefix(custom.id,"shadowsocks");editor.setExecution(requested);return AndroidNodeChainCapture.compile(editor.save());
 }
 static void importedPrefixSource(Path root)throws Exception{
  for(String fixture:List.of("3/","7/"))for(String requested:List.of("server","auto")) {
   var original=new NodeChainCaptureHarness.Fixture(root,fixture);var exits=new AndroidStandardExitStore(original.context);
   var custom=NodeChainCaptureHarness.hostnameEntry("2022-blake3-aes-256-gcm");custom.server="198.51.100.76";exits.save(custom);
   var editor=new AndroidOrderedPathSelection(original.nodes,original.profiles);editor.addPrefix(custom.id,"shadowsocks");editor.setExecution(requested);
   AndroidNodeStore.ChainCapture selected;
   try{selected=editor.save();}catch(Exception refused){throw new AssertionError("complete imported execution Save was refused",refused);}
   int count=selected.members.size();check(count==Integer.parseInt(fixture.split("/")[0])+1,"complete imported editor omitted a prefix");
   try(var local=AndroidNodeChainCapture.compile(selected);var captured=AndroidNodeChainExecutionCapture.compile(local,requested)){
    JSONObject retained=new JSONObject(new JSONObject(captured.source).getString("local_source"));JSONArray nodes=retained.getJSONArray("nodes"),ids=retained.getJSONArray("identity_sources");
    check(retained.getInt("schema")==2&&nodes.length()==count&&ids.length()==count,"complete imported execution lost source shape");
    for(int i=0;i<count;i++)check(nodes.getString(i).equals(local.memberInputs.get(i))&&ids.getString(i).equals(local.identityInputs.get(i))&&ids.getString(i).isEmpty()==(i==count-2),"complete imported execution moved original member/identity");
    try(var replay=AndroidNodeChainExecutionCapture.reopen(local,captured.launchInput)){check(replay.source.equals(captured.source)&&replay.config.equals(captured.config),"complete imported execution replay changed source");}
    reject(captured::captureRestore,"source-only complete imported execution fabricated native proof");
   }
   var saved=original.profiles.add("Complete imported "+requested);original.changePolicies();original.profiles.load(saved.id);
   var loaded=original.profiles.currentOrderedPath();check(loaded.members.size()==count&&loaded.execution.equals(requested),"complete imported saved Load changed original graph");
   for(int i=0;i<count;i++)check(java.util.Arrays.equals(loaded.members.get(i).bytes(),selected.members.get(i).bytes()),"complete imported Load changed original private member or credential");
   var changed=new AndroidOrderedPathSelection(original.nodes,original.profiles);String next=requested.equals("auto")?"server":"auto";changed.setExecution(next);var updated=changed.save();original.profiles.update(saved.id,"Changed complete imported");
   original.changePolicies();original.profiles.load(saved.id);var reloaded=original.profiles.currentOrderedPath();check(reloaded.members.size()==count&&reloaded.execution.equals(next),"complete imported saved Update lost choice");
   for(int i=0;i<count;i++)check(java.util.Arrays.equals(reloaded.members.get(i).bytes(),updated.members.get(i).bytes()),"complete imported Update changed original private member or credential");
   var before=new NodeChainCaptureHarness.State(original);Libbox.afterExecution=plan->{throw new IllegalStateException("controlled complete imported preview refusal");};
   try{reject(()->original.profiles.load(saved.id),"complete imported Load bypassed compiler refusal");before.same(original,"complete imported preview failed before publication");}finally{Libbox.afterExecution=null;}
   original.profiles.delete(saved.id);check(original.members.stream().allMatch(n->n.file.isFile()),"complete imported Delete removed linked originals");
  }
  importedReadback(root,List.of("3/","7/"));
 }
 static void importedSource(Path root)throws Exception{
  for(String first:List.of("","awg-fast","awg-strong"))for(String method:List.of("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305"))for(String requested:List.of("server","auto")){
   try(var local=importedLocal(root,first,method,requested)){
    AndroidNodeChainExecutionCapture captured;
    try{captured=AndroidNodeChainExecutionCapture.compile(local,requested);}catch(Exception refused){throw new AssertionError("imported SS execution was refused",refused);}
    try(captured){
     JSONObject source=new JSONObject(captured.source),retained=new JSONObject(source.getString("local_source")),launch=new JSONObject(captured.launchInput);
     check(source.getInt("schema")==1&&launch.getInt("schema")==1&&retained.getInt("schema")==2,"imported execution conflated preparation, Local, and saved Last schemas");
     JSONArray nodes=retained.getJSONArray("nodes"),identities=retained.getJSONArray("identity_sources");
     check(nodes.length()==3&&identities.length()==3&&identities.getString(1).isEmpty()&&!identities.getString(0).isEmpty()&&!identities.getString(2).isEmpty(),"imported execution invented or omitted paired identity");
     for(int i=0;i<3;i++)check(nodes.getString(i).equals(local.memberInputs.get(i))&&identities.getString(i).equals(local.identityInputs.get(i)),"imported execution substituted original source at "+i);
     JSONObject middle=new JSONObject(nodes.getString(1)),external=new JSONObject(middle.getString("capture")).getJSONObject("profile");
     check("external".equals(external.getString("node_kind"))&&!external.has("node_proof_id")&&!external.has("api_token")&&!external.has("router_api"),"imported execution manufactured Router authority");
     check(method.equals(external.getJSONObject("external").getJSONObject("shadowsocks").getString("method")),"imported execution changed the captured cipher");
     try(var replay=AndroidNodeChainExecutionCapture.reopen(local,captured.launchInput)){check(replay.source.equals(captured.source)&&replay.config.equals(captured.config),"imported execution replay changed source or policy");}
     check(!captured.healthy()&&!captured.nativeClosed(),"source-only imported execution claimed native readiness");
     reject(captured::captureRestore,"source-only imported execution fabricated saved proof");
    }
   }
  }
 }
 static void importedReadback(Path root)throws Exception{importedReadback(root,List.of("2/"));}
 static void importedReadback(Path root,List<String> keys)throws Exception{
  for(String key:keys)for(String fault:List.of("local-schema","imported-identity","member-order","local-execution","preparation-schema","launch-schema")){
   try(var local=importedLocalCount(root,key,"2022-blake3-aes-256-gcm","auto")){
    Libbox.afterExecution=plan->{try{
     JSONObject launch=new JSONObject(plan.value.getString("launch")),prep=new JSONObject(plan.value.getString("source")),source=new JSONObject(prep.getString("local_source"));
     if(fault.equals("local-schema"))source.put("schema",1);
     if(fault.equals("imported-identity")){JSONArray ids=source.getJSONArray("identity_sources");ids.put(ids.length()-2,ids.getString(0));}
     if(fault.equals("member-order")){JSONArray nodes=source.getJSONArray("nodes");String first=nodes.getString(0);nodes.put(0,nodes.getString(1));nodes.put(1,first);}
     if(fault.equals("local-execution"))source.put("execution","server");
     prep.put("local_source",source.toString());if(fault.equals("preparation-schema"))prep.put("schema",2);
     plan.value.put("source",prep.toString());launch.put("source",prep.toString());if(fault.equals("launch-schema"))launch.put("schema",2);plan.value.put("launch",launch.toString());
    }catch(Exception error){throw new IllegalStateException(error);}};
    reject(()->AndroidNodeChainExecutionCapture.compile(local,"auto"),"imported execution accepted native readback substitution: "+fault);
   }finally{Libbox.afterExecution=null;}
  }
 }

 static void publicRoundtrip(Path root)throws Exception{
  for(String requested:List.of("server","auto"))for(String key:List.of("2/","3/awg-strong","8/mixed-awg")){
   var f=new NodeChainCaptureHarness.Fixture(root,key);var ui=new OrderedProductSurface(f);ui.open();ui.choose(0);ui.execution();
   check(ui.dialog.labels.length==3&&ui.dialog.labels[2].toString().equals("Compare both"),"public editor lost exact three execution choices");
   ui.choose(requested.equals("server")?1:2);ui.save();
   check(f.profiles.currentOrderedPath().execution.equals(requested)&&f.prefs.getString("multihop_execution","").equals(requested),"public editor did not publish its requested execution");
   var saved=f.profiles.add("Full "+requested);check(f.row().getString("multihop_execution").equals(requested),"Add lost complete requested execution");
   f.changePolicies();f.profiles.load(saved.id);check(f.profiles.currentOrderedPath().execution.equals(requested),"Load replaced complete saved execution");
   var draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);String next=requested.equals("auto")?"server":"auto";draft.setExecution(next);draft.save();f.profiles.update(saved.id,"Updated execution");
   f.changePolicies();f.profiles.load(saved.id);check(f.profiles.currentOrderedPath().execution.equals(next)&&f.row().getString("multihop_execution").equals(next),"Update failed to preserve exact saved execution");
   // The actual preparation is evaluated before the first private mutation.
   f.changePolicies();var before=new NodeChainCaptureHarness.State(f);
   Libbox.afterExecution=plan->{throw new IllegalStateException("controlled actual execution preview refusal");};
   try{reject(()->f.profiles.load(saved.id),"profile load bypassed real execution compiler refusal");before.same(f,"execution preview refusal before publication");}finally{Libbox.afterExecution=null;}
   // A replacement made during the compiler call belongs to the new writer.
   byte[] controlBefore=Files.readAllBytes(f.control().file.toPath());Map<String,?> prefsBefore=f.prefs.getAll();final String[] replacement={""};
   Libbox.afterExecution=plan->{try{JSONObject changed=f.bundle(0);NodeChainCaptureHarness.profile(changed).put("api_token","newer-exact-entry-secret");replacement[0]=changed.toString();f.replace(0,changed);}catch(Exception e){throw new IllegalStateException(e);}};
   try{reject(()->f.profiles.load(saved.id),"profile load borrowed a member replaced during execution preview");
    check(Files.readString(f.members.get(0).file.toPath()).equals(replacement[0])&&java.util.Arrays.equals(controlBefore,Files.readAllBytes(f.control().file.toPath()))&&prefsBefore.equals(f.prefs.getAll()),"execution preview rollback overwrote the newer source owner");
   }finally{Libbox.afterExecution=null;}
   f.profiles.delete(saved.id);check(f.members.stream().allMatch(n->n.file.isFile()),"Delete removed referenced private sources");
  }
  for(String requested:List.of("server","auto")){
   var hy2=new NodeChainCaptureHarness.Fixture(root,"2/hy2-wg");JSONObject layered=hy2.bundle(1);NodeChainCaptureHarness.profile(layered).put("start_layer","aes-256-gcm");hy2.replace(1,layered);var draft=new AndroidOrderedPathSelection(hy2.nodes,hy2.profiles);var before=new NodeChainCaptureHarness.State(hy2);
   reject(()->draft.setExecution(requested),"Server/Compare accepted a layered HY2 final");before.same(hy2,"unsupported execution choice");
   check(draft.execution().equals("local"),"invalid execution choice changed the draft");
   for(String protocol:List.of("socks5","http","https")){
    boolean isSOCKS=protocol.equals("socks5");String family=isSOCKS?"SOCKS":"CONNECT";int schema=isSOCKS?3:4;
    var f=new NodeChainCaptureHarness.Fixture(root,(isSOCKS?"":"connect/")+"2/");var custom=NodeChainCaptureHarness.hostnameEntry("2022-blake3-aes-256-gcm");custom.protocol=protocol;custom.server="198.51.100.75";custom.username="original-user";custom.password="original-password";custom.tlsServerName="middle.example.test";
    var exits=new AndroidStandardExitStore(f.context);exits.save(custom);var typed=new AndroidOrderedPathSelection(f.nodes,f.profiles);typed.addPrefix(custom.id,protocol.equals("socks5")?"socks5":protocol.equals("http")?"http-connect":"https-connect");
    {
     typed.setExecution(requested);var selected=typed.save();
     check(selected.execution.equals(requested)&&selected.members.size()==3,family+" editor lost its exact trio or execution choice");
     try(var local=AndroidNodeChainCapture.compile(selected);var captured=AndroidNodeChainExecutionCapture.compile(local,requested)){
      JSONObject preparation=new JSONObject(captured.source),retained=new JSONObject(preparation.getString("local_source")),original=new JSONObject(local.launchInput);
      check((isSOCKS?local.socks!=null&&local.connect==null:local.connect!=null&&local.socks==null)&&captured.local==local&&captured.requested.equals(requested),family+" execution borrowed an ordinary or foreign source");
      check(preparation.getInt("schema")==schema&&retained.getInt("schema")==schema&&retained.getString("execution").equals("local"),family+" execution entered the ordinary compiler or changed its Local source");
      for(String field:List.of("nodes","identity_sources"))check(retained.getJSONArray(field).toString().equals(original.getJSONArray(field).toString()),family+" execution changed its original "+field);
      check(!captured.healthy(),"source-only "+family+" editor fabricated native readiness");
      reject(captured::captureRestore,"source-only "+family+" editor fabricated a restore owner");
     }
     // Choosing a draft value is pure. Save must reach the real typed compiler
     // before it publishes any replacement private source or preference.
     var retry=new AndroidOrderedPathSelection(f.nodes,f.profiles);String next=requested.equals("server")?"auto":"server";retry.setExecution(next);
     var beforePreview=new NodeChainCaptureHarness.State(f);final boolean[] compilerReached={false};
     Libbox.afterExecution=plan->{compilerReached[0]=true;throw new IllegalStateException("controlled "+family+" execution preview refusal");};
     try{reject(retry::save,family+" editor Save bypassed its typed compiler refusal");check(compilerReached[0]&&retry.execution().equals(next),"rejected "+family+" Save missed the real compiler or changed the draft");beforePreview.same(f,family+" compiler refusal before publication");check(f.profiles.currentOrderedPath().execution.equals(requested),"rejected "+family+" Save changed the original saved execution");}
     finally{Libbox.afterExecution=null;}
    }
   }
  }
 }


 static void hysteria(Path root)throws Exception{
  for(String key:List.of("2/hy2-wg","8/hy2-long"))for(String requested:List.of("server","auto")){
   var f=new NodeChainCaptureHarness.Fixture(root,key);int count=f.members.size();var ui=new OrderedProductSurface(f);ui.open();ui.choose(0);ui.execution();ui.choose(requested.equals("server")?1:2);ui.save();
   check(f.profiles.currentOrderedPath().execution.equals(requested),"paired HY2 public execution was refused");
   try(var local=AndroidNodeChainCapture.compile(f.profiles.currentOrderedPath());var captured=AndroidNodeChainExecutionCapture.compile(local,requested);var replay=AndroidNodeChainExecutionCapture.reopen(local,captured.launchInput)){
    JSONObject original=new JSONObject(local.launchInput),returned=new JSONObject(new JSONObject(captured.source).getString("local_source"));
    check(local.socks==null&&local.connect==null&&!local.openVPN&&original.getInt("schema")==1&&returned.getInt("schema")==1,"paired HY2 entered an imported execution family");
    check(original.getJSONArray("nodes").length()==count&&original.getJSONArray("nodes").toString().equals(returned.getJSONArray("nodes").toString())&&original.getJSONArray("identity_sources").toString().equals(returned.getJSONArray("identity_sources").toString()),"paired HY2 execution replaced source or independent identities");
    JSONObject last=new JSONObject(returned.getJSONArray("nodes").getString(count-1));check(last.getString("mode").equals("hysteria2")&&last.getString("start").isEmpty(),"paired HY2 final changed transport or final layer");
    check(captured.source.equals(replay.source)&&captured.config.equals(replay.config),"paired HY2 execution replay changed the native graph");
    reject(captured::execution,"source-only HY2 preparation fabricated current native proof");
   }
   var saved=f.profiles.add("Paired HY2 "+requested);f.changePolicies();f.profiles.load(saved.id);
   check(f.profiles.currentOrderedPath().execution.equals(requested)&&f.profiles.currentOrderedPath().modes.get(count-1).equals("hysteria2"),"paired HY2 saved Load lost original choice");
   for(int i=0;i<count;i++)check(ConnectionProfilesHarness.sameJSONValue(f.bundle(i).get("profiles"),f.original.get(i).get("profiles"))&&NodeChainCaptureHarness.profile(f.bundle(i)).getString("api_token").equals(NodeChainCaptureHarness.profile(f.original.get(i)).getString("api_token")),"paired HY2 profile action replaced credentials or trust");
   var draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);String changed=requested.equals("auto")?"server":"auto";draft.setExecution(changed);draft.save();f.profiles.update(saved.id,"Updated paired HY2");f.changePolicies();f.profiles.load(saved.id);
   check(f.profiles.currentOrderedPath().execution.equals(changed),"paired HY2 Update lost exact requested execution");
   f.changePolicies();var before=new NodeChainCaptureHarness.State(f);Libbox.afterExecution=plan->{throw new IllegalStateException("controlled paired HY2 preview refusal");};
   try{reject(()->f.profiles.load(saved.id),"paired HY2 Load bypassed real execution compiler refusal");before.same(f,"paired HY2 preview rollback");}finally{Libbox.afterExecution=null;}
   f.profiles.delete(saved.id);check(f.members.stream().allMatch(n->n.file.isFile()),"paired HY2 Delete removed private linked source");
  }
  for(String requested:List.of("server","auto"))for(String fault:List.of("final-layer","proxy-prefix","imported-prefix","wrong-final")){
   var f=new NodeChainCaptureHarness.Fixture(root,fault.equals("imported-prefix")?"3/hy2-awg-fast":"2/hy2-wg");int last=f.members.size()-1;JSONObject profile=NodeChainCaptureHarness.profile(f.bundle(last));profile.put("multihop_execution",requested);
   if(fault.equals("final-layer"))profile.put("start_layer","aes-256-gcm");
   if(fault.equals("proxy-prefix"))profile.getJSONArray("multihop_nodes").getJSONObject(0).put("mode","hysteria2");
   if(fault.equals("imported-prefix"))profile.getJSONArray("multihop_nodes").getJSONObject(last-1).put("mode","shadowsocks");
   if(fault.equals("wrong-final"))profile.getJSONArray("multihop_nodes").getJSONObject(last).put("mode","naive-h2");
   reject(()->AndroidNodeStore.orderedSelection(profile),"paired HY2 saved selection admitted unsupported graph: "+fault);
  }
  for(String key:List.of("2/hy2-wg","8/hy2-long")){
   var missing=new NodeChainCaptureHarness.Fixture(root,key);int last=missing.members.size()-1;JSONObject bundle=missing.bundle(last);bundle.getJSONObject("profiles").remove("wg");missing.replace(last,bundle);var prior=new NodeChainCaptureHarness.State(missing);
   reject(()->missing.chooseExecution("server"),"paired HY2 execution admitted missing independent identity asset");prior.same(missing,"paired HY2 independent identity refusal");
  }
  var f=new NodeChainCaptureHarness.Fixture(root,"2/hy2-wg");var external=NodeChainCaptureHarness.hostnameEntry("2022-blake3-aes-256-gcm");external.server="198.51.100.76";new AndroidStandardExitStore(f.context).save(external);var before=new NodeChainCaptureHarness.State(f);
  reject(()->new AndroidOrderedPathSelection(f.nodes,f.profiles).addPrefix(external.id,"shadowsocks"),"paired HY2 editor admitted imported middle");before.same(f,"paired HY2 imported middle refusal");
 }

 static void exportLastSources(Path root)throws Exception{exportLastSources(root,false);}
 static void exportLastSources(Path root,boolean hysteria)throws Exception{
  JSONObject exported=new JSONObject();
  for(int count:hysteria?new int[]{2,8}:new int[]{0,4,8})for(String mode:List.of("server/server","auto/local","auto/server")){
   String variant=hysteria?"hysteria-"+count+"/"+mode:count==0?mode:"imported-"+count+"/"+mode,requested=mode.split("/")[0];var f=new NodeChainCaptureHarness.Fixture(root,hysteria?(count==2?"2/hy2-wg":"8/hy2-long"):count==0?"3/":(count-1)+"/");
   if(count!=0&&!hysteria){var custom=NodeChainCaptureHarness.hostnameEntry("2022-blake3-aes-256-gcm");custom.server="198.51.100.76";custom.expectedPublicIp="203.0.113.88";new AndroidStandardExitStore(f.context).save(custom);var editor=new AndroidOrderedPathSelection(f.nodes,f.profiles);editor.addPrefix(custom.id,"shadowsocks");editor.setExecution(requested);editor.save();}else f.chooseExecution(requested);
   // Startup timing does not change the native graph identity.
   JSONObject bundle=f.bundle(f.members.size()-1);NodeChainCaptureHarness.profile(bundle).put("startup_mode","last").put("auto_connect",true);f.replace(f.members.size()-1,bundle);
   try(var local=AndroidNodeChainCapture.compile(f.profiles.currentOrderedPath())){
    JSONArray bundles=new JSONArray();for(int i=0;i<f.members.size();i++)bundles.put(f.bundle(i));
    JSONObject projected=new JSONObject(new JSONObject(local.memberInputs.get(local.memberInputs.size()-1)).getString("profile_json"));
    check(!projected.has("startup_mode")&&!projected.has("auto_connect")&&NodeChainCaptureHarness.profile(f.bundle(f.members.size()-1)).getBoolean("auto_connect"),"execution projection changed private startup choices or included timing in native identity");
    exported.put(variant,new JSONObject().put("bundles",bundles).put("local_launch",local.launchInput).put("requested",requested).put("selected",mode.split("/")[1]).put("imported_store",count==0||hysteria?"":Files.readString(f.context.getFilesDir().toPath().resolve("standard-exits.json"))));
   }
  }
  Files.writeString(Path.of(System.getenv("ROUTERVPN_ANDROID_EXECUTION_LAST_INPUT")),exported.toString());
 }
 static void lastSources(Path root)throws Exception{lastSources(root,false);}
 static void lastSources(Path root,boolean hysteria)throws Exception{
  JSONObject sources=new JSONObject(Files.readString(Path.of(System.getenv("ROUTERVPN_ANDROID_EXECUTION_LAST_INPUT"))));
  JSONObject records=new JSONObject(Files.readString(Path.of(System.getenv("ROUTERVPN_ANDROID_EXECUTION_LAST_OUTPUT"))));
  for(int count:hysteria?new int[]{2,8}:new int[]{0,4,8})for(String mode:List.of("server/server","auto/local","auto/server")){
   String variant=hysteria?"hysteria-"+count+"/"+mode:count==0?mode:"imported-"+count+"/"+mode;
   JSONObject original=sources.getJSONObject(variant);var f=new NodeChainCaptureHarness.Fixture(root,original.getJSONArray("bundles"));String requested=original.getString("requested"),raw=records.getString(variant);
   if(count!=0&&!hysteria)Files.writeString(f.context.getFilesDir().toPath().resolve("standard-exits.json"),original.getString("imported_store"));
   try(var local=AndroidNodeChainCapture.compile(f.profiles.currentOrderedPath());var last=AndroidNodeChainExecutionCapture.fromLast(local,requested,raw)){
    check(local.launchInput.equals(original.getString("local_launch")),"Last fixture changed the original Android launch before native parsing");
    JSONObject launch=new JSONObject(last.launchInput);check(launch.getInt("schema")==2&&launch.getString("last").equals(raw)&&new JSONObject(raw).getString("execution").equals(original.getString("selected")),"actual native Last parser lost saved choice or distinct envelope");
    reject(last::execution,"source-only Last fabricated current native proof");reject(last::captureLastRecord,"source-only Last minted another proved record");
    reject(()->AndroidNodeChainExecutionCapture.reopen(local,last.launchInput),"ordinary replay admitted a native Last envelope");
    for(String field:List.of("digest","setting","execution","local_source_sha256","dns_policy_sha256")){
     JSONObject changed=new JSONObject(raw).put(field,field.endsWith("sha256")||field.equals("digest")?"f".repeat(64):"changed");
     reject(()->AndroidNodeChainExecutionCapture.fromLast(local,requested,changed.toString()),"native Last parser accepted changed "+field);
    }
    JSONObject changed=f.bundle(0);NodeChainCaptureHarness.profile(changed).put("api_token","changed-entry-credential");f.replace(0,changed);f.nodes.select(f.control().id);
    try(var replacement=AndroidNodeChainCapture.compile(f.profiles.currentOrderedPath())){reject(()->AndroidNodeChainExecutionCapture.fromLast(replacement,requested,raw),"native Last parser borrowed changed original private source");}
   }
  }
 }
 public static void main(String[] args)throws Exception{Path root=Path.of(args[0]);String family=args.length>1?args[1]:"all";if(family.equals("hysteria")){hysteria(root);System.out.println("Android paired HY2 execution: "+checks+" checks PASS");return;}if(family.equals("hysteria-last-export")){exportLastSources(root,true);return;}if(family.equals("hysteria-last")){lastSources(root,true);System.out.println("Android paired HY2 native Last source: "+checks+" checks PASS");return;}if(family.equals("last-export")){exportLastSources(root);return;}if(family.equals("last")){lastSources(root);System.out.println("Android exact native Last source: "+checks+" checks PASS");return;}if(family.equals("all")||family.equals("source")){source(root);System.out.println("Android source phase completed: source");}if(family.equals("all")||family.equals("public")){publicRoundtrip(root);System.out.println("Android source phase completed: publicRoundtrip");}if(family.equals("all")||family.equals("readback")){nativeReadback(root);System.out.println("Android source phase completed: nativeReadback");}if(family.equals("all")||family.equals("changed")){changedSource(root);System.out.println("Android source phase completed: changedSource");}if(family.equals("all")||family.equals("imported")){importedSource(root);System.out.println("Android source phase completed: importedSource");}if(family.equals("imported-prefix")){importedPrefixSource(root);System.out.println("Android source phase completed: importedPrefixSource");}if(family.equals("all")||family.equals("imported-readback")){importedReadback(root);System.out.println("Android source phase completed: importedReadback");}System.out.println("Android execution source: "+checks+" checks; actual shared preparation with original all-member captures PASS");}
}
'''


LAST_GENERATOR = r'''package mobilemultihop
import("context";"encoding/json";"os";"testing";"time")
func TestAndroidOrderedExecutionLastSourceFixture(t *testing.T){
 raw,err:=os.ReadFile(os.Getenv("ROUTERVPN_ANDROID_EXECUTION_LAST_INPUT"));if err!=nil{t.Fatal(err)}
 var rows map[string]struct{Local string `json:"local_launch"`;Requested string `json:"requested"`;Selected string `json:"selected"`};if err=json.Unmarshal(raw,&rows);err!=nil{t.Fatal(err)}
 if len(rows)!=9{t.Fatal("incomplete original Android Last source matrix")};records:=map[string]string{}
 for _,name:=range []string{"server/server","auto/local","auto/server","imported-4/server/server","imported-4/auto/local","imported-4/auto/server","imported-8/server/server","imported-8/auto/local","imported-8/auto/server"}{t.Run(name,func(t *testing.T){
  row,ok:=rows[name];if !ok{t.Fatal("missing original Last source")};local,err:=ParseNodeChainLaunchInput(row.Local);if err!=nil{t.Fatal(err)}
  var envelope NodeChainSource;if err=json.Unmarshal([]byte(row.Local),&envelope);err!=nil{t.Fatal(err)}
  var source NodeChainExecutionSource
  if local.importedMiddle != nil { source=androidImportedLastExecutionSource(t,local,envelope,row.Requested) } else {
   identities:=make([]*NodeProfile,len(local.nodes));for i,node:=range local.nodes{identities[i],err=NewNodeProfile("wg",envelope.IdentitySources[i],node.inputs.ProfileJSON,"",node.inputs.DNSBootstrap);if err!=nil{t.Fatal(err)}}
   source=nodeChainExecutionFixtureFromNodes(t,local.nodes,identities,row.Requested)
  };f:=newNodeChainExecutionRuntimeFixtureFromSource(t,source)
  if f.runtime.projection.preparation.LocalSourceSHA256()!=local.SourceSHA256(){t.Fatal("runtime Last generator changed original Android source")}
  f.engine.localDelay,f.engine.serverDelay=200*time.Millisecond,time.Millisecond;if row.Selected=="local"{f.engine.localDelay,f.engine.serverDelay=time.Millisecond,200*time.Millisecond}
  ctx,cancel:=context.WithTimeout(context.Background(),35*time.Second);defer cancel();if err=f.runtime.Run(ctx);err!=nil{t.Fatal(err)}
  last,err:=f.runtime.CaptureLastContext(ctx);if err!=nil||last.Execution()!=row.Selected{t.Fatal("actual runtime did not capture requested original selected path",err)}
  if _,err=ParseNodeChainExecutionLast(last.JSON(),f.runtime.projection.preparation);err!=nil{t.Fatal(err)};records[name]=last.JSON()
 })};if len(records)!=9{t.Fatal("incomplete actual Last records")};output,err:=json.Marshal(records);if err!=nil{t.Fatal(err)};if err=os.WriteFile(os.Getenv("ROUTERVPN_ANDROID_EXECUTION_LAST_OUTPUT"),output,0600);err!=nil{t.Fatal(err)}
}

// Actual original Java source supplies every member. Only the remote/native
// engine is the existing explicit owner double; shared Run/Last is unchanged.
func androidImportedLastExecutionSource(t *testing.T,local *NodeChain,source NodeChainSource,execution string) NodeChainExecutionSource {
 entry:=local.nodes[0];count:=len(local.nodes)-2
 plan:=map[string]any{"schema":1,"entry_node_id":entry.profile["node_proof_id"],"entry":map[string]any{"bundle":nodeChainServerPlanBundle(t,entry,source.IdentitySources[0]),"profile_id":entry.profile["id"],"mode":entry.mode}}
 var members []any
 for i:=1;i<len(source.Nodes);i++ {
  if i==count {var imported nodeChainImportedInput;if json.Unmarshal([]byte(source.Nodes[i]),&imported)!=nil{t.Fatal("missing original imported capture")};members=append(members,map[string]any{"imported":map[string]any{"config":imported.Config,"capture":imported.Capture}});continue}
  node:=local.nodes[i];bundle:=nodeChainServerPlanBundle(t,node,source.IdentitySources[i]);members=append(members,map[string]any{"paired":map[string]any{"bundle":bundle,"profile_id":node.profile["id"],"mode":node.mode},"server_peer":map[string]any{"bundle":nodeChainServerPlanPeerBundle(t,bundle,i),"profile_id":"server-"+node.profile["id"].(string)}})
 };plan["members"]=members;server,err:=NewNodeChainServerPlan(startJSON(t,plan));if err!=nil{t.Fatal(err)}
 capture:=nodeChainServerCaptureFixture(t,server);q:=capture.Request.Clone();q.LocalPacketPublicKeys=nil;q.LocalPacketPositions=nil
 for i,node:=range local.nodes[:count]{key,err:=node.PacketClientPublicKey();if err!=nil{t.Fatal(err)};q.LocalPacketPublicKeys=append(q.LocalPacketPublicKeys,key);q.LocalPacketPositions=append(q.LocalPacketPositions,i)}
 q.Peer,q.Port="10.80.0.2",32003
 return NodeChainExecutionSource{Schema:1,Execution:execution,LocalSource:startJSON(t,source),Server:server.Descriptor(),Request:q,FirstPort:32000,LastPort:32007}
}
'''


HYSTERIA_LAST_NAMES = tuple("hysteria-"+str(count)+"/"+mode for count in (2,8)
                            for mode in ("server/server","auto/local","auto/server"))
HYSTERIA_LAST_GENERATOR = LAST_GENERATOR.replace(
    "TestAndroidOrderedExecutionLastSourceFixture", "TestAndroidHysteriaExecutionLastSourceFixture"
).replace('len(rows)!=9', 'len(rows)!=6').replace('len(records)!=9', 'len(records)!=6').replace(
    '"server/server","auto/local","auto/server","imported-4/server/server","imported-4/auto/local","imported-4/auto/server","imported-8/server/server","imported-8/auto/local","imported-8/auto/server"',
    ','.join(json.dumps(name) for name in HYSTERIA_LAST_NAMES))


def prepare_sources(src, app, java):
    LOCAL.prepare_sources(src, app, java)
    shutil.copyfile(java / "AndroidNodeChainExecutionCapture.java", app / "AndroidNodeChainExecutionCapture.java")
    (app / "NodeChainExecutionCaptureHarness.java").write_text(HARNESS)


def run(root, work, app, classes, jar, env, imported_only=False):
    assert not imported_only
    generator = work / "android_chain_fixture_test.go"
    generator.write_text(LOCAL.GENERATOR)
    overlay = work / "chain-fixture-overlay.json"
    overlay.write_text(json.dumps({"Replace": {str(root / "internal/mobilemultihop/android_chain_fixture_test.go"): str(generator)}}))
    env = env.copy()
    env["ROUTERVPN_ANDROID_CHAIN_FIXTURE"] = str(work / "private-chain-fixtures.json")
    subprocess.run(["go", "test", "-p=1", "-count=1", "-overlay=" + str(overlay), "./internal/mobilemultihop", "-run", "^TestAndroidOrderedSourceFixture$"], cwd=root, env=env, check=True, timeout=180)
    data = work / "execution-data"
    data.mkdir()
    command = ["java", "-cp", str(classes) + os.pathsep + str(jar), "com.eabusham.routervpn.NodeChainExecutionCaptureHarness", str(data)]
    # Preserve the original aggregate six-family invocation and its120s cap.
    subprocess.run(command, env=env, check=True, timeout=120)
    # Add complete4/8 member Save/capture/readback on the same compiled inputs.
    subprocess.run([*command,"imported-prefix"], env=env, check=True, timeout=120)
    env["ROUTERVPN_ANDROID_EXECUTION_LAST_INPUT"]=str(work/"original-last-sources.json")
    env["ROUTERVPN_ANDROID_EXECUTION_LAST_OUTPUT"]=str(work/"proved-last-records.json")
    subprocess.run([*command,"last-export"],env=env,check=True,timeout=120)
    last_generator=work/"android_execution_last_fixture_test.go";last_generator.write_text(LAST_GENERATOR)
    last_overlay=work/"execution-last-overlay.json"
    last_overlay.write_text(json.dumps({"Replace":{str(root/"internal/mobilemultihop/android_execution_last_fixture_test.go"):str(last_generator)}}))
    subprocess.run(["go","test","-p=1","-count=1","-overlay="+str(last_overlay),"./internal/mobilemultihop","-run","^TestAndroidOrderedExecutionLastSourceFixture$"],cwd=root,env=env,check=True,timeout=180)
    subprocess.run([*command,"last"],env=env,check=True,timeout=120)
    subprocess.run([*command,"hysteria"], env=env, check=True, timeout=120)
    env["ROUTERVPN_ANDROID_EXECUTION_LAST_INPUT"]=str(work/"hysteria-last-sources.json")
    env["ROUTERVPN_ANDROID_EXECUTION_LAST_OUTPUT"]=str(work/"hysteria-last-records.json")
    subprocess.run([*command,"hysteria-last-export"],env=env,check=True,timeout=120)
    hy_generator=work/"android_hysteria_last_fixture_test.go";hy_generator.write_text(HYSTERIA_LAST_GENERATOR)
    hy_overlay=work/"hysteria-last-overlay.json"
    hy_overlay.write_text(json.dumps({"Replace":{str(root/"internal/mobilemultihop/android_hysteria_last_fixture_test.go"):str(hy_generator)}}))
    subprocess.run(["go","test","-p=1","-count=1","-overlay="+str(hy_overlay),"./internal/mobilemultihop","-run","^TestAndroidHysteriaExecutionLastSourceFixture$"],cwd=root,env=env,check=True,timeout=180)
    subprocess.run([*command,"hysteria-last"],env=env,check=True,timeout=120)
    original = (app / "AndroidNodeChainExecutionCapture.java").read_text()
    controls = (
        ("complete-prefix", 'originalSchema == 3 && (originalCount < 3 || originalCount > 8)', '(originalSchema == 2 || originalSchema == 3) && originalCount != 3', 'imported-prefix', 'Server execution requires every original member'),
        ("local-digest", '!local.sourceSHA256.equals(plan.localSourceSHA256())', 'false', 'readback', 'execution accepted native readback substitution: local-digest'),
        ("member-order", '!sameStrings(original.getJSONArray("nodes"), returned.getJSONArray("nodes"))', 'false', 'readback', 'execution accepted native readback substitution: member-order'),
        ("identity-order", '!sameStrings(original.getJSONArray("identity_sources"), returned.getJSONArray("identity_sources"))', 'false', 'readback', 'execution accepted native readback substitution: identity-order'),
        ("imported-schema", '(originalSchema != 1 && originalSchema != 2 && !(local.socks != null && originalSchema == 3) && !(local.connect != null && originalSchema == 4) && !(local.openVPN && originalSchema == 5))', 'originalSchema != 1', 'imported', 'imported SS execution was refused'),
        ("schema-substitution", 'returned.getInt("schema") != originalSchema', 'false', 'imported-readback', 'imported execution accepted native readback substitution: local-schema'),
        ("imported-identity", '!sameStrings(original.getJSONArray("identity_sources"), returned.getJSONArray("identity_sources"))', 'false', 'imported-readback', 'imported execution accepted native readback substitution: imported-identity'),
        ("source-change", '        local.requireCurrent();\n        if (restore != null) plan.requireRestore(restore.nativeCapture);\n    }\n\n    void requireCurrent()', '        if (restore != null) plan.requireRestore(restore.nativeCapture);\n    }\n\n    void requireCurrent()', 'changed', 'execution survived original source replacement during compile'),
    )
    for name, old, new, family, witness in controls:
        assert original.count(old) == 1, name
        source = work / ("execution-mutant-" + name) / "AndroidNodeChainExecutionCapture.java"
        source.parent.mkdir()
        source.write_text(original.replace(old, new))
        output = work / ("execution-negative-" + name)
        shutil.copytree(classes, output)
        cp = str(output) + os.pathsep + str(jar)
        subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", cp, "-d", str(output), str(source)], check=True, timeout=60)
        result = subprocess.run(["java", "-cp", cp, command[3], str(data), family], env=env, text=True, capture_output=True, timeout=120)
        if result.returncode == 0 or witness not in result.stderr:
            raise AssertionError(name + " missed exact causal witness:\n" + result.stdout + result.stderr)
        print("Android execution source causal control rejected: " + name)
    # These public-path controls compile the actual profile transaction class,
    # retaining the real execution compiler and the complete original stores.
    public_original=(app / "AndroidConnectionProfileStore.java").read_text()
    public_controls=(
        ("profile-preview", 'if(ordered&&!"local".equals(execution))validateOrderedExecution(updates,row,updatedOrdinary);',
         'if(false&&ordered&&!"local".equals(execution))validateOrderedExecution(updates,row,updatedOrdinary);',
         "profile load bypassed real execution compiler refusal"),
        ("profile-request", '.put("multihop_enabled",true).put("multihop_execution",captured.execution)',
         '.put("multihop_enabled",true).put("multihop_execution","local")',
         "Add lost complete requested execution"),
    )
    for name,old,new,witness in public_controls:
        assert public_original.count(old)==1,name
        source=work/("execution-mutant-"+name)/"AndroidConnectionProfileStore.java"
        source.parent.mkdir();source.write_text(public_original.replace(old,new))
        output=work/("execution-negative-"+name);shutil.copytree(classes,output)
        cp=str(output)+os.pathsep+str(jar)
        subprocess.run(["javac","--release","17","-encoding","UTF-8","-proc:none","-cp",cp,"-d",str(output),str(source)],check=True,timeout=60)
        result=subprocess.run(["java","-cp",cp,command[3],str(data),"public"],env=env,text=True,capture_output=True,timeout=120)
        if result.returncode==0 or witness not in result.stderr:
            raise AssertionError(name+" missed exact public transaction witness:\n"+result.stdout+result.stderr)
        print("Android execution public causal control rejected: "+name)

    admission_controls = (
        ("hysteria-final-layer", "AndroidNodeStore.java", 'if (hysteriaFinal && !java.util.Arrays.asList("", "off").contains(profile.optString("start_layer", "off")))', 'if (false)', 'paired HY2 saved selection admitted unsupported graph: final-layer'),
        ("hysteria-imported", "AndroidNodeStore.java", '&& !(!hysteriaFinal && selected.length()>=3', '&& !(selected.length()>=3', 'paired HY2 saved selection admitted unsupported graph: imported-prefix'),
    )
    for name, filename, old, new, witness in admission_controls:
        original_source=(app/filename).read_text()
        assert original_source.count(old)==1,name
        source=work/("execution-mutant-"+name)/filename;source.parent.mkdir();source.write_text(original_source.replace(old,new,1))
        output=work/("execution-negative-"+name);shutil.copytree(classes,output)
        cp=str(output)+os.pathsep+str(jar)
        subprocess.run(["javac","--release","17","-encoding","UTF-8","-proc:none","-cp",cp,"-d",str(output),str(source)],check=True,timeout=60)
        result=subprocess.run(["java","-cp",cp,command[3],str(data),"hysteria"],env=env,text=True,capture_output=True,timeout=120)
        if result.returncode==0 or witness not in result.stderr:
            raise AssertionError(name+" missed exact paired HY2 admission witness:\n"+result.stdout+result.stderr)
        print("Android paired HY2 admission causal control rejected: "+name)


if __name__ == "__main__":
    import test_android_connection_profiles as profiles
    if len(sys.argv) != 1:
        raise ValueError("This source gate takes no arguments")
    sys.argv += ["--case-family", "ordered-execution"]
    profiles.main()
