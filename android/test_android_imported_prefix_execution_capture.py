#!/usr/bin/env python3
"""Exercise complete Android imported-SS execution sources through the real compiler.

Native Run, leases and TUN remain refusing boundaries here. The shipping editor,
stores, profile transactions and capture classes run their actual implementation.
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
public final class ImportedPrefixExecutionHarness {
 static int checks;interface Checked{void run()throws Exception;}static void check(boolean yes,String why){checks++;if(!yes)throw new AssertionError(why);}
 static void reject(Checked call,String why)throws Exception{try{call.run();}catch(Exception expected){checks++;return;}throw new AssertionError(why);}
 static final class Fixture {
  final NodeChainCaptureHarness.Fixture original;final AndroidStandardExitStore exits;final AndroidStandardExitStore.Entry imported;
  Fixture(Path root,String key,String method,String requested)throws Exception{
   original=new NodeChainCaptureHarness.Fixture(root,key);exits=new AndroidStandardExitStore(original.context);imported=NodeChainCaptureHarness.hostnameEntry(method);
   imported.server="198.51.100.76";imported.name="Original complete imported execution";exits.save(imported);
   var draft=new AndroidOrderedPathSelection(original.nodes,original.profiles);draft.addPrefix(imported.id,"shadowsocks");draft.save();
   var ui=new OrderedProductSurface(original);ui.open();ui.choose(0);ui.execution();
   check(ui.dialog.labels.length==3&&ui.dialog.labels[2].toString().equals("Compare both"),"imported prefix public editor lost its execution choices");
   ui.choose(requested.equals("server")?1:2);if(ui.dialog==null||!ui.message.isEmpty())throw new AssertionError("imported prefix public editor refused captured execution");ui.save();
   check(ui.message.isEmpty()&&original.profiles.currentOrderedPath().execution.equals(requested),"imported prefix public editor refused captured execution");
  }
 }
 static void verify(AndroidNodeChainCapture local,AndroidNodeChainExecutionCapture execution,int count,String requested)throws Exception{
  JSONObject preparation=new JSONObject(execution.source),source=new JSONObject(preparation.getString("local_source")),launch=new JSONObject(execution.launchInput);
  int middle=count-2;JSONArray nodes=source.getJSONArray("nodes"),identities=source.getJSONArray("identity_sources");
  check(local.plan!=null&&local.socks==null&&local.connect==null&&preparation.getInt("schema")==1&&source.getInt("schema")==2&&launch.getInt("schema")==1,"long imported execution borrowed a typed family or Last schema");
  check(nodes.length()==count&&identities.length()==count&&requested.equals(preparation.getString("execution"))&&source.getString("execution").equals("local"),"long imported execution shortened its complete source");
  for(int i=0;i<count;i++){
   check(nodes.getString(i).equals(local.memberInputs.get(i)),"long imported execution substituted a retained member");
   check(identities.getString(i).equals(local.identityInputs.get(i)),"long imported execution substituted a retained identity");
   check(identities.getString(i).isEmpty()==(i==middle),"long imported execution changed paired authority");
  }
  JSONObject imported=new JSONObject(nodes.getString(middle));JSONObject profile=new JSONObject(imported.getString("capture")).getJSONObject("profile");
  check(profile.getString("node_kind").equals("external")&&!profile.has("node_proof_id")&&!profile.has("router_api")&&!profile.has("api_token"),"long imported execution manufactured Router authority");
  check(!execution.healthy()&&!execution.nativeClosed(),"source-only long imported execution fabricated readiness");
  reject(execution::captureRestore,"source-only long imported execution fabricated a native restore capsule");
  try(var replay=AndroidNodeChainExecutionCapture.reopen(local,execution.launchInput)){check(replay.source.equals(execution.source)&&replay.config.equals(execution.config),"long imported execution canonical replay changed its complete source");}
 }
 static void positive(Path root,int prefixes,boolean mixed)throws Exception{
  for(String method:List.of("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305"))for(String requested:List.of("server","auto")){
   String key=(prefixes+1)+"/"+(mixed?"mixed-awg":"");var f=new Fixture(root,key,method,requested);int count=prefixes+2,middle=count-2;
   var selected=f.original.profiles.currentOrderedPath();List<String> ids=new ArrayList<>(),modes=new ArrayList<>();
   for(int i=0;i<count;i++){ids.add(selected.members.get(i).id);modes.add(selected.modes.get(i));}
   check(count==selected.members.size()&&selected.members.get(middle).imported&&selected.members.get(middle).id.equals(f.imported.id),"long imported editor changed its original penultimate member");
   try(var local=AndroidNodeChainCapture.compile(selected)){
    AndroidNodeChainExecutionCapture captured;try{captured=AndroidNodeChainExecutionCapture.compile(local,requested);}catch(Exception error){throw new AssertionError("long imported execution was refused",error);}
    try(captured){verify(local,captured,count,requested);}
   }
   var row=f.original.profiles.add("Complete imported "+requested);String stored=Files.readString(f.original.rows);
   check(!stored.contains(f.imported.secret)&&!stored.contains("api_token"),"long imported profile duplicated private credentials");
   f.original.changePolicies();f.original.profiles.load(row.id);var loaded=f.original.profiles.currentOrderedPath();
   check(loaded.execution.equals(requested)&&loaded.members.size()==count,"long imported profile Load lost complete execution");
   for(int i=0;i<count;i++)check(loaded.members.get(i).id.equals(ids.get(i))&&loaded.modes.get(i).equals(modes.get(i)),"long imported profile Load reordered or replaced a source");
   String next=requested.equals("server")?"auto":"server";var draft=new AndroidOrderedPathSelection(f.original.nodes,f.original.profiles);draft.setExecution(next);draft.save();f.original.profiles.update(row.id,"Updated complete imported execution");
   f.original.changePolicies();f.original.profiles.load(row.id);check(f.original.profiles.currentOrderedPath().execution.equals(next),"long imported profile Update lost its execution");
   try(var local=AndroidNodeChainCapture.compile(f.original.profiles.currentOrderedPath());var captured=AndroidNodeChainExecutionCapture.compile(local,next)){
    verify(local,captured,count,next);
    JSONObject replacement=f.original.bundle(prefixes-1);NodeChainCaptureHarness.profile(replacement).put("api_token","replacement-prefix-private-token");f.original.replace(prefixes-1,replacement);
    reject(captured::requireCurrent,"long imported execution survived replacement of a later paired prefix");
   }
   f.original.profiles.delete(row.id);check(f.original.members.stream().allMatch(n->n.file.isFile()),"long imported profile Delete removed original private nodes");
  }
 }
 static void readback(Path root,String requested)throws Exception{
  for(String fault:List.of("later-member","later-identity","missing-prefix","imported-identity","final-member")){
   var f=new Fixture(root,"7/mixed-awg","2022-blake3-aes-256-gcm",requested);
   try(var local=AndroidNodeChainCapture.compile(f.original.profiles.currentOrderedPath())){
    Libbox.afterExecution=plan->{try{
     JSONObject preparation=new JSONObject(plan.value.getString("source")),source=new JSONObject(preparation.getString("local_source"));
     JSONArray nodes=source.getJSONArray("nodes"),identities=source.getJSONArray("identity_sources");
     if(fault.equals("later-member"))nodes.put(5,nodes.getString(0));
     if(fault.equals("later-identity"))identities.put(5,identities.getString(0));
     if(fault.equals("imported-identity"))identities.put(6,identities.getString(0));
     if(fault.equals("final-member"))nodes.put(7,nodes.getString(0));
     if(fault.equals("missing-prefix")){JSONArray changed=new JSONArray();for(int i=0;i<nodes.length();i++)if(i!=5)changed.put(nodes.getString(i));source.put("nodes",changed);}
     preparation.put("local_source",source.toString());plan.value.put("source",preparation.toString());JSONObject launch=new JSONObject(plan.value.getString("launch"));launch.put("source",preparation.toString());plan.value.put("launch",launch.toString());
    }catch(Exception error){throw new IllegalStateException(error);}};
    reject(()->AndroidNodeChainExecutionCapture.compile(local,requested),"long imported readback accepted "+fault);
   }finally{Libbox.afterExecution=null;}
  }
 }
 public static void main(String[] args)throws Exception{
  Path root=Path.of(args[0]);String phase=args[1];
  if(phase.startsWith("prefix-"))positive(root,Integer.parseInt(phase.substring(7)),false);
  else if(phase.startsWith("mixed-"))positive(root,Integer.parseInt(phase.substring(6)),true);
  else if(phase.equals("readback")){readback(root,"server");readback(root,"auto");}
  else throw new IllegalArgumentException("unknown original prefix phase");
  System.out.println("Android imported execution prefixes "+phase+": "+checks+" shipping source/profile checks PASS");
 }
}
'''


def prepare_sources(src, app, java):
    BASE.prepare_sources(src, app, java)
    (app / "ImportedPrefixExecutionHarness.java").write_text(HARNESS)


def run(root, work, app, classes, jar, env, imported_only=False):
    if imported_only:
        raise ValueError("Complete imported execution uses its own source inventory")
    generator=work/"android_chain_fixture_test.go";generator.write_text(BASE.LOCAL.GENERATOR)
    overlay=work/"prefix-fixture-overlay.json"
    overlay.write_text(json.dumps({"Replace":{str(root/"internal/mobilemultihop/android_chain_fixture_test.go"):str(generator)}}))
    env=env.copy();env["ROUTERVPN_ANDROID_CHAIN_FIXTURE"]=str(work/"private-chain-fixtures.json")
    subprocess.run(["go","test","-p=1","-count=1","-overlay="+str(overlay),"./internal/mobilemultihop","-run","^TestAndroidOrderedSourceFixture$"],cwd=root,env=env,check=True,timeout=180)
    data=work/"prefix-data";data.mkdir()
    command=["java","-cp",str(classes)+os.pathsep+str(jar),"com.eabusham.routervpn.ImportedPrefixExecutionHarness",str(data)]
    phases=[*("prefix-"+str(n) for n in range(1,7)),"mixed-2","mixed-6","readback"]
    for phase in phases:
        subprocess.run([*command,phase],env=env,check=True,timeout=120)
    originals={name:(app/(name+".java")).read_text() for name in ("AndroidNodeStore","AndroidNodeChainCapture","AndroidNodeChainExecutionCapture","AndroidOrderedPathSelection")}
    controls=(
        ("node-store","AndroidNodeStore",'selected.length()>=3 && i==selected.length()-2 && ("shadowsocks".equals(mode)','selected.length()==3 && i==1 && ("shadowsocks".equals(mode)',"prefix-2","imported prefix public editor refused captured execution"),
        ("editor","AndroidOrderedPathSelection",'schema>4||(schema==3||schema==4)&&members.size()!=3','schema>4||(schema==2||schema==3||schema==4)&&members.size()!=3',"prefix-2","imported prefix public editor refused captured execution"),
        ("returned-size","AndroidNodeChainExecutionCapture",'(originalSchema == 3 || originalSchema == 4) && original.getJSONArray("nodes").length() != 3','(originalSchema == 2 || originalSchema == 3 || originalSchema == 4) && original.getJSONArray("nodes").length() != 3',"prefix-2","long imported execution was refused"),
        ("member","AndroidNodeChainExecutionCapture",'!sameStrings(original.getJSONArray("nodes"), returned.getJSONArray("nodes"))','false',"readback","long imported readback accepted later-member"),
        ("identity","AndroidNodeChainExecutionCapture",'!sameStrings(original.getJSONArray("identity_sources"), returned.getJSONArray("identity_sources"))','false',"readback","long imported readback accepted later-identity"),
    )
    for name,owner,before,after,phase,witness in controls:
        if originals[owner].count(before)!=1:
            raise AssertionError(name+" original source anchor changed")
        target=work/("prefix-mutant-"+name)/(owner+".java");target.parent.mkdir();target.write_text(originals[owner].replace(before,after))
        output=work/("prefix-negative-"+name);shutil.copytree(classes,output);cp=str(output)+os.pathsep+str(jar)
        subprocess.run(["javac","--release","17","-encoding","UTF-8","-proc:none","-cp",cp,"-d",str(output),str(target)],check=True,timeout=60)
        result=subprocess.run(["java","-cp",cp,command[3],str(data),phase],env=env,text=True,capture_output=True,timeout=120)
        if result.returncode!=1 or witness not in result.stderr:
            raise AssertionError(name+" missed original causal witness:\n"+result.stdout+result.stderr)
        print("Android imported prefix execution causal refusal: "+name)


if __name__=="__main__":
    import test_android_connection_profiles as profiles
    if len(sys.argv)!=1:
        raise ValueError("This gate takes no arguments")
    sys.argv += ["--case-family","ordered-imported-execution"]
    profiles.main()
