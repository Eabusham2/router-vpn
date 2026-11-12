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
    source = LOCAL.compiler_source(source)
    cases = r'''case len(args)==3&&args[0]=="execution-preparation":result,err=executionPreparation(args[1],args[2]);case len(args)==2&&args[0]=="execution-replay":result,err=executionReplay(args[1]);'''
    assert source.count("case len(args)==2:") == 1
    return source.replace("case len(args)==2:", cases + "case len(args)==2:") + r'''
type executionEnvelope struct{Kind string `json:"kind"`;Schema int `json:"schema"`;Source string `json:"source"`;SourceSHA string `json:"source_sha256"`;ConfigSHA string `json:"config_sha256"`}
func executionPrepared(prep *mobilemultihop.NodeChainExecutionPreparation)(string,error){
 launch,err:=json.Marshal(executionEnvelope{"routervpn-node-chain-execution-preparation-input",1,prep.Source(),prep.SourceSHA256(),prep.ConfigSHA256()});if err!=nil{return "",err}
 raw,err:=json.Marshal(map[string]string{"source":prep.Source(),"source_sha256":prep.SourceSHA256(),"config":prep.Config(),"config_sha256":prep.ConfigSHA256(),"local_source_sha256":prep.LocalSourceSHA256(),"requested":prep.Execution(),"launch":string(launch)});return string(raw),err
}
func executionPreparation(input,requested string)(string,error){
 if _,err:=mobilemultihop.ParseNodeChainLaunchInput(input);err!=nil{return "",err}
 var original mobilemultihop.NodeChainSource;if err:=json.Unmarshal([]byte(input),&original);err!=nil{return "",err};raw,err:=json.Marshal(original);if err!=nil{return "",err}
 prep,err:=mobilemultihop.NewNodeChainExecutionPreparation(string(raw),requested);if err!=nil{return "",err};return executionPrepared(prep)
}
func executionReplay(input string)(string,error){
 if err:=libbox.RouterValidatePrivateNodeJSON(input);err!=nil{return "",err}
 var envelope executionEnvelope;var fields map[string]json.RawMessage
 if err:=json.Unmarshal([]byte(input),&fields);err!=nil{return "",err};if len(fields)!=5{return "",fmt.Errorf("unexpected execution envelope")}
 if err:=json.Unmarshal([]byte(input),&envelope);err!=nil{return "",err};if envelope.Kind!="routervpn-node-chain-execution-preparation-input"||envelope.Schema!=1{return "",fmt.Errorf("foreign execution envelope")}
 if err:=libbox.RouterValidatePrivateNodeJSON(envelope.Source);err!=nil{return "",err}
 var source mobilemultihop.NodeChainExecutionPreparationSource
 if err:=json.Unmarshal([]byte(envelope.Source),&source);err!=nil{return "",err}
 prep,err:=mobilemultihop.NewNodeChainExecutionPreparation(source.LocalSource,source.Execution);if err!=nil{return "",err}
 if source.Schema!=1||prep.Source()!=envelope.Source||prep.SourceSHA256()!=envelope.SourceSHA||prep.ConfigSHA256()!=envelope.ConfigSHA{return "",fmt.Errorf("changed execution source")}
 return executionPrepared(prep)
}
'''


NATIVE = r'''package io.nekohasekai.libbox;
import org.json.*;
public final class RouterNodeChainExecution {
 public final JSONObject value;public boolean closed;
 RouterNodeChainExecution(String raw)throws Exception{value=new JSONObject(raw);java.util.function.Consumer<RouterNodeChainExecution> hook=Libbox.afterExecution;Libbox.afterExecution=null;if(hook!=null)hook.accept(this);}
 private void current(){if(closed)throw new IllegalStateException("retired pure execution constructor");}
 public String source()throws Exception{current();return value.getString("source");}public String launchInput()throws Exception{current();return value.getString("launch");}
 public String config()throws Exception{current();return value.getString("config");}public String sourceSHA256()throws Exception{current();return value.getString("source_sha256");}
 public String configSHA256()throws Exception{current();return value.getString("config_sha256");}public String localSourceSHA256()throws Exception{current();return value.getString("local_source_sha256");}
 public String requestedExecution()throws Exception{current();return value.getString("requested");}
 public void bindNative(CommandServer server){throw new AssertionError("Source-only gate cannot bind a native execution");}public boolean nativeClosed(){return false;}
 public void run(CommandServer server){throw new AssertionError("Source-only gate cannot run a native execution");}public boolean healthy(){return false;}
 public String execution(){throw new IllegalStateException("No native execution proof");}public String progressJSON(){return "{}";}
 public void networkChanged(){}public boolean retainsServerCleanup(CommandServer server){return false;}public void close(){closed=true;}
 public RouterNodeChainExecutionRestoreCapture captureRestore(){throw new IllegalStateException("No native restore owner");}
 public void requireRestore(RouterNodeChainExecutionRestoreCapture capture){throw new IllegalStateException("No native restore authority in pure source fixture");}
}
'''

HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;import java.nio.file.*;import java.util.*;import io.nekohasekai.libbox.*;
public final class NodeChainExecutionCaptureHarness {
 static int checks;interface Checked{void run()throws Exception;}static void check(boolean yes,String why){checks++;if(!yes)throw new AssertionError(why);}
 static void reject(Checked operation,String why)throws Exception{try{operation.run();}catch(Exception expected){checks++;return;}throw new AssertionError(why);}
 static void source(Path root)throws Exception {
  for(String key:List.of("2/","3/awg-strong","4/mixed-awg","8/mixed-awg"))for(String requested:List.of("server","auto")){
   var fixture=new NodeChainCaptureHarness.Fixture(root,key);var original=fixture.profiles.currentOrderedPath();
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
   var fixture=new NodeChainCaptureHarness.Fixture(root,"3/");try(var local=AndroidNodeChainCapture.compile(fixture.profiles.currentOrderedPath())){
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
  var fixture=new NodeChainCaptureHarness.Fixture(root,"3/");try(var local=AndroidNodeChainCapture.compile(fixture.profiles.currentOrderedPath())){
   Libbox.afterExecution=plan->{try{JSONObject bundle=fixture.bundle(0);NodeChainCaptureHarness.profile(bundle).put("name","newer member");fixture.replace(0,bundle);}catch(Exception error){throw new IllegalStateException(error);}};
   try{reject(()->AndroidNodeChainExecutionCapture.compile(local,"auto"),"execution survived original source replacement during compile");}finally{Libbox.afterExecution=null;}
  }
 }
 public static void main(String[] args)throws Exception{Path root=Path.of(args[0]);String family=args.length>1?args[1]:"all";if(family.equals("all")||family.equals("source"))source(root);if(family.equals("all")||family.equals("readback"))nativeReadback(root);if(family.equals("all")||family.equals("changed"))changedSource(root);System.out.println("Android execution source: "+checks+" checks; actual shared preparation with original all-member captures PASS");}
}
'''


def prepare_sources(src, app, java):
    LOCAL.prepare_sources(src, app, java)
    shutil.copyfile(java / "AndroidNodeChainExecutionCapture.java", app / "AndroidNodeChainExecutionCapture.java")
    (app / "NodeChainExecutionCaptureHarness.java").write_text(HARNESS)
    native = src / "io/nekohasekai/libbox"
    (native / "RouterNodeChainExecution.java").write_text(NATIVE)
    for name in ("CommandServer", "RouterNodeChainExecutionRestoreCapture", "RouterMTU", "RouterHopMeasurement"):
        (native / (name + ".java")).write_text("package io.nekohasekai.libbox;public final class " + name + "{}")
    (native / "RouterMTUPlatform.java").write_text("package io.nekohasekai.libbox;public interface RouterMTUPlatform{}")
    path = native / "Libbox.java"
    source = path.read_text()
    marker = "static String call(String...args)throws Exception{"
    assert source.count(marker) == 1
    methods = r'''public static java.util.function.Consumer<RouterNodeChainExecution> afterExecution;
public static RouterNodeChainExecution routerNodeChainExecutionFromLaunch(String source,String requested)throws Exception{return new RouterNodeChainExecution(call("execution-preparation",source,requested));}
public static RouterNodeChainExecution newRouterNodeChainExecutionLaunch(String source)throws Exception{return new RouterNodeChainExecution(call("execution-replay",source));}
public static RouterNodeChainExecution newRouterNodeChainExecutionRestore(RouterNodeChainExecutionRestoreCapture captured){throw new AssertionError("No native restore owner in source-only fixture");}
public static RouterMTU routerNodeChainExecutionNewMTU(RouterNodeChainExecution plan,CommandServer server,RouterMTUPlatform platform){throw new AssertionError("No native MTU in source-only fixture");}
public static RouterHopMeasurement routerNodeChainExecutionNewHopMeasurement(RouterNodeChainExecution plan,CommandServer server){throw new AssertionError("No native measurement in source-only fixture");}
'''
    path.write_text(source.replace(marker, methods + marker))


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
    subprocess.run(command, env=env, check=True, timeout=120)
    original = (app / "AndroidNodeChainExecutionCapture.java").read_text()
    controls = (
        ("local-digest", '!local.sourceSHA256.equals(plan.localSourceSHA256())', 'false', 'readback', 'execution accepted native readback substitution: local-digest'),
        ("member-order", '!sameStrings(original.getJSONArray("nodes"), returned.getJSONArray("nodes"))', 'false', 'readback', 'execution accepted native readback substitution: member-order'),
        ("identity-order", '!sameStrings(original.getJSONArray("identity_sources"), returned.getJSONArray("identity_sources"))', 'false', 'readback', 'execution accepted native readback substitution: identity-order'),
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


if __name__ == "__main__":
    import test_android_connection_profiles as profiles
    if len(sys.argv) != 1:
        raise ValueError("This source gate takes no arguments")
    sys.argv += ["--case-family", "ordered-execution"]
    profiles.main()
