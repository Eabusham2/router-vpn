#!/usr/bin/env python3
"""Actual Android SOCKS5 execution stores/capture against the shared Go compiler.

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
HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;import java.nio.file.*;import java.util.*;import io.nekohasekai.libbox.*;
public final class SOCKSExecutionCaptureHarness {
 static int checks;interface Checked{void run()throws Exception;}static void check(boolean yes,String why){checks++;if(!yes)throw new AssertionError(why);}
 static void reject(Checked call,String why)throws Exception{try{call.run();}catch(Exception expected){checks++;return;}throw new AssertionError(why);}
 static AndroidStandardExitStore.Entry proxy(String wire,boolean auth){var e=new AndroidStandardExitStore.Entry();e.id="1234567890abcdef1234567890abcdef";e.name="Original execution proxy";e.protocol=wire;e.server="198.51.100.76";e.serverPort=1080;e.expectedPublicIp="203.0.113.76";e.username=auth?"original-user":"";e.password=auth?"original-password":"";return e;}
 static void positive(Path root,int count,String selectedExecution)throws Exception {
  for(String first:count==3?List.of("","awg-fast","awg-strong"):List.of("mixed-awg"))for(String wire:List.of("socks5"))for(String requested:selectedExecution.isEmpty()?List.of("server","auto"):List.of(selectedExecution))for(boolean auth:List.of(false,true)) {
   var f=new NodeChainCaptureHarness.Fixture(root,(count-1)+"/"+first);var exits=new AndroidStandardExitStore(f.context);var custom=proxy(wire,auth);exits.save(custom);
   var editor=new AndroidOrderedPathSelection(f.nodes,f.profiles);editor.addPrefix(custom.id,AndroidExternalPolicy.protocol(wire));editor.save();
   var ui=new OrderedProductSurface(f);ui.open();ui.choose(0);ui.execution();
   check(ui.dialog.labels.length==3&&ui.dialog.labels[2].toString().equals("Compare both"),"SOCKS public editor lost exact execution choices");
   ui.choose(requested.equals("server")?1:2);check(ui.dialog!=null&&ui.message.isEmpty(),"SOCKS prefix editor refused captured execution");ui.save();
   var saved=f.profiles.currentOrderedPath();check(ui.message.isEmpty()&&saved.execution.equals(requested)&&saved.members.size()==count,"SOCKS prefix editor refused captured execution");
   AndroidNodeChainCapture compiled;try{compiled=AndroidNodeChainCapture.compile(saved);}catch(Exception error){throw new AssertionError("SOCKS prefix launch capture was refused",error);}
   try(var local=compiled) {
    AndroidNodeChainExecutionCapture prepared;try{prepared=AndroidNodeChainExecutionCapture.compile(local,requested);}catch(Exception error){throw new AssertionError("SOCKS prefix execution was refused",error);}
    try(var capture=prepared) {
    check(local.plan==null&&local.socks!=null&&local.connect==null,"SOCKS5 execution replaced typed source with ordinary authority");
    JSONObject prep=new JSONObject(capture.source),source=new JSONObject(prep.getString("local_source"));
    check(prep.getInt("schema")==3&&source.getInt("schema")==3&&requested.equals(prep.getString("execution")),"SOCKS5 execution lost its distinct source schema");
    check(new JSONObject(capture.launchInput).getString("kind").equals("routervpn-node-chain-socks-execution-preparation-input"),"SOCKS5 execution used generic launch authority");
    check(source.getJSONArray("nodes").length()==count&&source.getJSONArray("identity_sources").length()==count,"SOCKS5 execution omitted original prefix inventory");
    for(int i=0;i<count;i++)check(source.getJSONArray("nodes").getString(i).equals(local.memberInputs.get(i))&&source.getJSONArray("identity_sources").getString(i).equals(local.identityInputs.get(i))&&local.identityInputs.get(i).isEmpty()==(i==count-2),"SOCKS5 execution substituted original member or identity");
    check(local.identityInputs.get(count-2).isEmpty()&&!local.identityInputs.get(0).isEmpty()&&!local.identityInputs.get(count-1).isEmpty(),"proxy borrowed packet identity");
    try(var reopened=AndroidNodeChainExecutionCapture.reopen(local,capture.launchInput)){check(reopened.source.equals(capture.source)&&reopened.config.equals(capture.config),"typed execution replay changed original source");}
    reject(()->Libbox.newRouterNodeChainExecutionLaunch(capture.launchInput),"generic launch accepted SOCKS5 authority");
    reject(()->Libbox.newRouterNodeChainCONNECTExecutionLaunch(capture.launchInput),"CONNECT launch accepted SOCKS5 authority");
    reject(capture::captureRestore,"source fabricated native restoration");check(!capture.healthy(),"source fabricated native proof");
    var row=f.profiles.add("Original typed execution");String record=Files.readString(f.rows);check(!record.contains("original-password")&&!record.contains("original-user"),"saved profile copied private proxy credentials");
    f.profiles.load(row.id);var loaded=f.profiles.currentOrderedPath();check(loaded.execution.equals(requested)&&loaded.members.size()==count&&loaded.members.get(count-2).profileId.equals(custom.id)&&loaded.members.get(count-2).external().password.equals(custom.password),"profile Load changed exact proxy or execution");
    try(var after=AndroidNodeChainCapture.compile(loaded);var execution=AndroidNodeChainExecutionCapture.compile(after,requested)){check(execution.source.equals(capture.source),"profile roundtrip changed complete typed execution source");}
    custom.username="replacement-user";custom.password="replacement-password";exits.save(custom);reject(capture::requireCurrent,"replaced proxy revived old execution source");
    String next=requested.equals("server")?"auto":"server";var update=new AndroidOrderedPathSelection(f.nodes,f.profiles);update.setExecution(next);update.save();f.profiles.update(row.id,"Updated complete SOCKS execution");f.changePolicies();f.profiles.load(row.id);
    var updated=f.profiles.currentOrderedPath();check(updated.execution.equals(next)&&updated.members.size()==count&&updated.members.get(count-2).external().password.equals("replacement-password"),"SOCKS profile Update lost current execution or original credential reference");
    try(var after=AndroidNodeChainCapture.compile(updated);var execution=AndroidNodeChainExecutionCapture.compile(after,next)){
     JSONObject replaced=f.bundle(count-3);NodeChainCaptureHarness.profile(replaced).put("api_token","replacement-later-prefix-token");f.replace(count-3,replaced);reject(execution::requireCurrent,"SOCKS execution survived a replaced later prefix");
    }
    f.profiles.delete(row.id);check(f.members.stream().allMatch(n->n.file.isFile()),"SOCKS profile Delete removed original private nodes");
    }
   }
  }
 }
 static void finalLayers(Path root,int count,String selectedExecution)throws Exception {
  for(String layer:List.of("aes-256-gcm","aes-256-gcm+xor-whitening"))for(String requested:selectedExecution.isEmpty()?List.of("server","auto"):List.of(selectedExecution)){
   var f=new NodeChainCaptureHarness.Fixture(root,(count-1)+"/"+(count==3?"":"mixed-awg"));var exits=new AndroidStandardExitStore(f.context);var custom=proxy("socks5",true);exits.save(custom);
   JSONObject selected=f.bundle(count-2);NodeChainCaptureHarness.profile(selected).put("start_layer",layer);f.replace(count-2,selected);
   var editor=new AndroidOrderedPathSelection(f.nodes,f.profiles);editor.addPrefix(custom.id,"socks5");editor.save();
   var ui=new OrderedProductSurface(f);ui.open();ui.choose(0);ui.execution();ui.choose(requested.equals("server")?1:2);ui.save();
   check(ui.message.isEmpty(),"SOCKS public editor refused selected final Start Layer");
   var saved=f.profiles.currentOrderedPath();check(saved.execution.equals(requested)&&saved.members.size()==count,"SOCKS final layer changed original execution or path");
   try(var local=AndroidNodeChainCapture.compile(saved);var execution=AndroidNodeChainExecutionCapture.compile(local,requested)){
    JSONObject original=new JSONObject(local.config),after=new JSONObject(execution.config);
    JSONArray proofs=new JSONObject(local.socks.plan.metadata()).getJSONArray("proofs");
    check(proofs.length()==count&&proofs.getJSONObject(count-1).getString("start_layer").equals(layer),"SOCKS proof inventory lost original final Start Layer");
    String tag=proofs.getJSONObject(count-1).getString("tag");JSONObject finalOutbound=NodeChainCaptureHarness.tagged(original.getJSONArray("outbounds"),tag);
    check(finalOutbound.getString("type").equals(layer.equals("aes-256-gcm+xor-whitening")?"routervpn-aes-xor":"shadowsocks"),"SOCKS execution omitted selected final Start Layer");
    check(finalOutbound.getString("method").equals("2022-blake3-aes-256-gcm"),"SOCKS final layer lost original AES-256-GCM method");
    check(!finalOutbound.has("udp_over_tcp"),"SOCKS final layer borrowed CONNECT packet authority");
    check(ConnectionProfilesHarness.sameJSONValue(finalOutbound,NodeChainCaptureHarness.tagged(after.getJSONArray("outbounds"),tag)),"SOCKS execution replaced original layered final");
    JSONObject prep=new JSONObject(execution.source),source=new JSONObject(prep.getString("local_source"));
    check(source.getJSONArray("nodes").length()==count&&source.getJSONArray("identity_sources").length()==count,"SOCKS final layer lost complete prefix inventory");
    for(int i=0;i<count;i++)check(source.getJSONArray("nodes").getString(i).equals(local.memberInputs.get(i))&&source.getJSONArray("identity_sources").getString(i).equals(local.identityInputs.get(i)),"SOCKS final layer substituted original member or identity");
    JSONObject finalMember=new JSONObject(source.getJSONArray("nodes").getString(count-1));
    check(new JSONObject(finalMember.getString("profile_json")).getString("start_layer").equals(layer),"SOCKS source omitted selected final Start Layer");
    try(var reopened=AndroidNodeChainExecutionCapture.reopen(local,execution.launchInput)){check(reopened.source.equals(execution.source)&&reopened.config.equals(execution.config),"SOCKS layered execution reopen replaced original graph");}
    var row=f.profiles.add("Layered SOCKS execution");String record=Files.readString(f.rows);check(!record.contains("original-password")&&!record.contains("original-user"),"SOCKS layered profile copied private credentials");
    f.profiles.load(row.id);var loaded=f.profiles.currentOrderedPath();
    check(loaded.execution.equals(requested)&&loaded.members.size()==count&&loaded.members.get(count-1).profile().getString("start_layer").equals(layer)&&loaded.members.get(count-2).external().password.equals(custom.password),"SOCKS profile Load changed original final layer or proxy");
    try(var restored=AndroidNodeChainCapture.compile(loaded);var prepared=AndroidNodeChainExecutionCapture.compile(restored,requested)){check(prepared.source.equals(execution.source)&&prepared.config.equals(execution.config),"SOCKS layered profile roundtrip replaced captured graph");}
    String next=requested.equals("server")?"auto":"server";var update=new AndroidOrderedPathSelection(f.nodes,f.profiles);update.setExecution(next);update.save();f.profiles.update(row.id,"Updated layered SOCKS execution");f.changePolicies();f.profiles.load(row.id);
    var updated=f.profiles.currentOrderedPath();check(updated.execution.equals(next)&&updated.members.size()==count&&updated.members.get(count-1).profile().getString("start_layer").equals(layer),"SOCKS profile Update lost original final layer");
    try(var captured=AndroidNodeChainCapture.compile(updated);var prepared=AndroidNodeChainExecutionCapture.compile(captured,next)){
     JSONObject replacement=f.bundle(count-2);NodeChainCaptureHarness.profile(replacement).put("start_layer","off");f.replace(count-2,replacement);reject(prepared::requireCurrent,"SOCKS execution survived final-layer replacement");
    }
    f.profiles.delete(row.id);check(f.members.stream().allMatch(n->n.file.isFile()),"SOCKS layered profile Delete removed private nodes");
   }
  }
 }
 static void refused(Path root)throws Exception {
  var f=new NodeChainCaptureHarness.Fixture(root,"7/mixed-awg");var exits=new AndroidStandardExitStore(f.context);var e=proxy("socks5",true);exits.save(e);
  var draft=new AndroidOrderedPathSelection(f.nodes,f.profiles);draft.addPrefix(e.id,"socks5");draft.setExecution("server");
  try(var local=AndroidNodeChainCapture.compile(draft.save())){
   for(String fault:List.of("family","short-identities","proxy-identity","duplicate-prefix","no-paired-prefix")){
    JSONObject changed=new JSONObject(local.launchInput);JSONArray members=changed.getJSONArray("nodes"),identities=changed.getJSONArray("identity_sources");
    if(fault.equals("family"))changed.put("schema",4);else if(fault.equals("short-identities"))identities.remove(0);else if(fault.equals("proxy-identity"))identities.put(members.length()-2,identities.getString(0));else if(fault.equals("no-paired-prefix")){changed.put("nodes",new JSONArray().put(members.getString(members.length()-2)).put(members.getString(members.length()-1)));changed.put("identity_sources",new JSONArray().put("").put(identities.getString(identities.length()-1)));}else members.put(1,members.getString(0));
    for(String requested:List.of("server","auto"))reject(()->Libbox.newRouterNodeChainSOCKSExecution(changed.toString(),requested),"complete SOCKS accepted malformed "+fault);
   }
   for(String requested:List.of("","local","Server","compare"))reject(()->Libbox.newRouterNodeChainSOCKSExecution(local.launchInput,requested),"complete SOCKS accepted unsupported requested execution");
   var over=new NodeChainCaptureHarness.Fixture(root,"8/");
   try(var paired=AndroidNodeChainCapture.compile(over.profiles.currentOrderedPath())){
    JSONArray members=new JSONArray(),identities=new JSONArray();for(int i=0;i<8;i++){if(i==7){members.put(local.memberInputs.get(6));identities.put("");}members.put(paired.memberInputs.get(i));identities.put(paired.identityInputs.get(i));}
    JSONObject changed=new JSONObject(local.launchInput).put("nodes",members).put("identity_sources",identities);check(members.length()==9&&identities.length()==9,"overbound control lost complete nine-member inventory");
    for(String requested:List.of("server","auto"))reject(()->Libbox.newRouterNodeChainSOCKSExecution(changed.toString(),requested),"complete SOCKS accepted nine original members");
   }
  }
 }
 static void readback(Path root,int count)throws Exception{
  for(String fault:count==3?List.of("family","member","identity","config","requested"):List.of("family","member","identity","config","requested","later-member","later-identity","missing-prefix","final-member")){
   var f=new NodeChainCaptureHarness.Fixture(root,(count-1)+"/");var exits=new AndroidStandardExitStore(f.context);var e=proxy("socks5",true);exits.save(e);var d=new AndroidOrderedPathSelection(f.nodes,f.profiles);d.addPrefix(e.id,"socks5");d.setExecution("server");
   try(var local=AndroidNodeChainCapture.compile(d.save())){
    Libbox.afterExecution=p->{try{if(fault.equals("config")){p.value.put("config_sha256","f".repeat(64));return;}if(fault.equals("requested")){p.value.put("requested","auto");return;}JSONObject prep=new JSONObject(p.value.getString("source"));JSONObject source=new JSONObject(prep.getString("local_source"));if(fault.equals("family"))prep.put("schema",1);else{String field=fault.endsWith("identity")?"identity_sources":"nodes";JSONArray a=source.getJSONArray(field);if(fault.equals("missing-prefix"))a.remove(count-3);else a.put(fault.startsWith("later-")?count-3:fault.equals("final-member")?count-1:1,a.getString(0));prep.put("local_source",source.toString());}p.value.put("source",prep.toString());JSONObject launch=new JSONObject(p.value.getString("launch"));launch.put("source",prep.toString());p.value.put("launch",launch.toString());}catch(Exception x){throw new IllegalStateException(x);}};
    reject(()->AndroidNodeChainExecutionCapture.compile(local,"server"),"typed execution accepted substituted "+fault);
   }finally{Libbox.afterExecution=null;}
  }
 }
 public static void main(String[] args)throws Exception{Path root=Path.of(args[0]);String phase=args.length>1?args[1]:"all";if(phase.equals("all")||phase.equals("positive"))positive(root,3,"");if(phase.startsWith("positive-")){String[] parts=phase.substring(9).split("-");positive(root,Integer.parseInt(parts[0]),parts.length==1?"":parts[1]);}if(phase.equals("all")||phase.equals("layers"))finalLayers(root,3,"");if(phase.startsWith("layers-")){String[] parts=phase.substring(7).split("-");finalLayers(root,Integer.parseInt(parts[0]),parts.length==1?"":parts[1]);}if(phase.equals("all")||phase.equals("refused"))refused(root);if(phase.equals("all")||phase.equals("readback"))readback(root,3);if(phase.startsWith("readback-"))readback(root,Integer.parseInt(phase.substring(9)));System.out.println("Android typed SOCKS5 execution: "+checks+" actual compiler/store checks PASS");}
}
'''

def prepare_sources(src, app, java):
    BASE.prepare_sources(src, app, java)
    (app / "SOCKSExecutionCaptureHarness.java").write_text(HARNESS)

def run(root, work, app, classes, jar, env, imported_only=False):
    generator=work/"android_chain_fixture_test.go";generator.write_text(BASE.LOCAL.GENERATOR)
    overlay=work/"socks-fixture-overlay.json";overlay.write_text(json.dumps({"Replace":{str(root/"internal/mobilemultihop/android_chain_fixture_test.go"):str(generator)}}))
    env=env.copy();env["ROUTERVPN_ANDROID_CHAIN_FIXTURE"]=str(work/"private-chain-fixtures.json")
    subprocess.run(["go","test","-p=1","-count=1","-overlay="+str(overlay),"./internal/mobilemultihop","-run","^TestAndroidOrderedSourceFixture$"],cwd=root,env=env,check=True,timeout=180)
    data=work/"socks-data";data.mkdir();cp=str(classes)+os.pathsep+str(jar)
    command=["java","-cp",cp,"com.eabusham.routervpn.SOCKSExecutionCaptureHarness",str(data)]
    admission_controls=(
        ("editor-trio","AndroidOrderedPathSelection",'schema==3&&(members.size()<3||members.size()>8)','schema==3&&members.size()!=3',"SOCKS prefix editor refused captured execution"),
        ("stored-trio","AndroidNodeStore",'|| "socks5".equals(mode)','|| selected.length()==3 && "socks5".equals(mode)',"SOCKS prefix editor refused captured execution"),
        ("returned-trio","AndroidNodeChainExecutionCapture",'originalSchema == 3 && (originalCount < 3 || originalCount > 8)','originalSchema == 3 && originalCount != 3',"SOCKS prefix execution was refused"),
    )
    for name,owner,before,after,witness in admission_controls:
        captured=(app/(owner+".java")).read_text()
        if captured.count(before)!=1:raise AssertionError(name+" complete SOCKS prefix anchor changed")
        target=work/("socks-prefix-mutant-"+name)/(owner+".java");target.parent.mkdir();target.write_text(captured.replace(before,after))
        out=work/("socks-prefix-negative-"+name);shutil.copytree(classes,out);classpath=str(out)+os.pathsep+str(jar)
        subprocess.run(["javac","--release","17","-encoding","UTF-8","-proc:none","-cp",classpath,"-d",str(out),str(target)],check=True,timeout=60)
        result=subprocess.run(["java","-cp",classpath,command[3],str(data),"positive-4"],env=env,text=True,capture_output=True,timeout=120)
        if result.returncode!=1 or witness not in result.stderr:raise AssertionError(name+" missed exact complete-prefix admission witness:\n"+result.stdout+result.stderr)
        print("SOCKS complete-prefix admission causal control rejected: "+name)

    for phase in ("layers","layers-4-server","layers-8-auto","positive","refused","readback","positive-4","positive-8-server","positive-8-auto","readback-4","readback-8"):
        subprocess.run([*command,phase],env=env,check=True,timeout=120)
    original=(app/"AndroidNodeChainExecutionCapture.java").read_text()
    for name,old,witness in (("member",'!sameStrings(original.getJSONArray("nodes"), returned.getJSONArray("nodes"))','typed execution accepted substituted member'),("identity",'!sameStrings(original.getJSONArray("identity_sources"), returned.getJSONArray("identity_sources"))','typed execution accepted substituted identity')):
        if original.count(old)!=1:raise AssertionError(name+" guard anchor changed")
        source=work/("socks-mutant-"+name)/"AndroidNodeChainExecutionCapture.java";source.parent.mkdir();source.write_text(original.replace(old,"false"))
        out=work/("socks-negative-"+name);shutil.copytree(classes,out);classpath=str(out)+os.pathsep+str(jar)
        subprocess.run(["javac","--release","17","-encoding","UTF-8","-proc:none","-cp",classpath,"-d",str(out),str(source)],check=True,timeout=60)
        result=subprocess.run(["java","-cp",classpath,command[3],str(data),"readback"],env=env,text=True,capture_output=True,timeout=120)
        if result.returncode!=1 or witness not in result.stderr:raise AssertionError(name+" missed exact ownership witness:\n"+result.stdout+result.stderr)
        print("SOCKS5 execution ownership causal control rejected: "+name)


if __name__=="__main__":
    import test_android_connection_profiles as profiles
    if len(sys.argv)!=1:raise ValueError("This gate takes no arguments")
    sys.argv += ["--case-family","ordered-socks-execution"]
    profiles.main()
