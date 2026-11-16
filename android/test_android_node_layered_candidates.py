#!/usr/bin/env python3
"""Paired SS layer catalogs and future Save use real Java stores/shared Go sources.

Native TCP timing is the existing explicit lifecycle double. The required
native listener gate separately proves fifty original encrypted-prefix dials.
"""
import os
import shutil
import subprocess
import sys
import test_android_node_candidates as C

HARNESS = r'''package com.eabusham.routervpn;
import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import org.json.*;import io.nekohasekai.libbox.*;
public final class NodeLayeredCandidateHarness {
 static int checks;static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
 interface Work{void run()throws Exception;}static void reject(Work action,String why)throws Exception{try{action.run();}catch(Exception expected){checks++;return;}throw new AssertionError(why);}
 static void run(Path root,String layer)throws Exception{
  var f=new NodeChainCaptureHarness.Fixture(root,"4/mixed-awg");int last=f.members.size()-1;
  JSONObject bundle=f.bundle(last);NodeChainCaptureHarness.profile(bundle).put("start_layer",layer);f.replace(last,bundle);f.nodes.select(f.control().id);
  var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var original=session.source;
  AndroidNodeCandidateCatalog catalog;try{catalog=new AndroidNodeCandidateCatalog(f.context,session,last-1);}catch(Exception refused){throw new AssertionError("paired layered candidate omitted from eligible catalog",refused);}
  var row=catalog.rows.stream().filter(r->r.id.equals(original.members.get(last).profileId)).findFirst().orElseThrow();
  check(!row.input.isEmpty()&&row.reason.isEmpty(),"paired layered candidate omitted from eligible catalog");
  JSONObject member=new JSONObject(row.input),profile=new JSONObject(member.getString("profile_json"));
  check(profile.getString("start_layer").equals(layer)&&profile.getString("node_proof_id").equals(original.members.get(last).proofId),"layered catalog changed original profile or private proof");
  JSONObject graph=new JSONObject(Libbox.routerLayeredCandidateConfig(row.input));JSONObject finalNode=null;String tag=graph.getJSONObject("route").getString("final");
  JSONArray outs=graph.getJSONArray("outbounds");for(int i=0;i<outs.length();i++)if(outs.getJSONObject(i).optString("tag").equals(tag))finalNode=outs.getJSONObject(i);
  String type=layer.endsWith("xor-whitening")?"routervpn-aes-xor":"shadowsocks";
  JSONObject originalGraph=new JSONObject(new String(Base64.getDecoder().decode(bundle.getJSONObject("profiles").getJSONObject("shadowsocks").getString("sing-box.json")),StandardCharsets.UTF_8));JSONObject originalSS=originalGraph.getJSONArray("outbounds").getJSONObject(0);
  check(finalNode!=null&&finalNode.getString("type").equals(type)&&finalNode.getString("password").equals(originalSS.getString("password"))&&finalNode.getString("server").equals(originalSS.getString("server")),"layered candidate changed concrete original TCP owner or key");
  check(finalNode.getInt("server_port")== (layer.endsWith("xor-whitening")?8389:originalSS.getInt("server_port"))&&!finalNode.has("detour")&&!finalNode.has("udp_over_tcp"),"layered candidate guessed a TCP endpoint or nested transport");
  var before=new NodeChainCaptureHarness.State(f);CountDownLatch completed=new CountDownLatch(1),finished=new CountDownLatch(1);AtomicReference<Throwable> failure=new AtomicReference<>();AtomicReference<AndroidNodeCandidateResult> measured=new AtomicReference<>();AtomicReference<AndroidNodeCandidateMeasurement> retained=new AtomicReference<>();
  try{
   var owner=AndroidNodeCandidateMeasurement.start(catalog,new AndroidNodeCandidateMeasurement.Callback(){
    public void changed(List<AndroidNodeCandidateResult> rows,String detail){for(var result:rows)if(result.id.equals(row.id)){measured.set(result);completed.countDown();}}
    public void finished(Throwable error){failure.set(error);finished.countDown();}});
   retained.set(owner);check(completed.await(15,TimeUnit.SECONDS),"paired candidate completion did not arrive");if(failure.get()!=null)throw new AssertionError("paired candidate measurement failed",failure.get());
   var result=measured.get();owner.requireResult(result);
   var proposed=new AndroidNodeCandidateProfile(owner,result);var saved=proposed.save(f.context,"Measured paired "+layer);JSONObject stored=new JSONObject(Files.readString(f.rows)).getJSONArray("profiles").getJSONObject(0);
   check(stored.getJSONArray("multihop_nodes").length()==original.members.size()&&stored.getString("multihop_execution").equals(original.execution),"paired candidate Save truncated path or changed execution");
   JSONArray nodes=stored.getJSONArray("multihop_nodes");for(int i=0;i<nodes.length();i++)check(nodes.getJSONObject(i).getString("id").equals(original.members.get(i).profileId),"paired candidate Save changed a retained position");
   check(nodes.getJSONObject(last).getJSONObject("policy").getString("start_layer").equals(layer),"paired candidate Save dropped selected final layer");
   check(!stored.toString().contains(originalSS.getString("password"))&&!stored.toString().contains("api_token"),"paired candidate Save duplicated private credentials");
   var after=new NodeChainCaptureHarness.State(f);check(before.preferences.equals(after.preferences),"paired candidate Save changed active selection");for(Path path:before.files.keySet())if(!path.equals(f.rows))check(Arrays.equals(before.files.get(path),after.files.get(path)),"paired candidate Save edited original source");
  }finally{if(retained.get()!=null)retained.get().cancel();check(finished.await(10,TimeUnit.SECONDS),"paired candidate worker did not join");}
  var stale=new AndroidNodeCandidateCatalog(f.context,session,last-1);byte[] originalBytes=Files.readAllBytes(f.control().file.toPath());
  JSONObject changed=f.bundle(last);JSONObject assets=changed.getJSONObject("profiles").getJSONObject("shadowsocks");JSONObject changedGraph=new JSONObject(new String(Base64.getDecoder().decode(assets.getString("sing-box.json")),StandardCharsets.UTF_8));changedGraph.getJSONArray("outbounds").getJSONObject(0).put("password",Base64.getEncoder().encodeToString(new byte[32]));assets.put("sing-box.json",Base64.getEncoder().encodeToString(changedGraph.toString().getBytes(StandardCharsets.UTF_8)));
  Files.writeString(f.control().file.toPath(),changed.toString());check(stale.currentInventorySHA256().isEmpty(),"changed captured candidate secret retained old catalog");Files.write(f.control().file.toPath(),originalBytes);reject(stale::requireSavedSourcesCurrent,"restored candidate secret revived invalidated catalog");
  for(Object invalid:List.of("xor-whitening","foreign",true,7)){
   var malformed=new JSONObject(profile.toString()).put("start_layer",invalid);reject(()->AndroidNodeChainCapture.memberInput(original.members.get(last),"shadowsocks",malformed),"noncanonical paired layer admitted");
  }
 }
 public static void main(String[] args)throws Exception{try{run(Path.of(args[0]),args[1]);System.out.println("Android layered paired candidates "+args[1]+": "+checks+" source, closure and Save checks PASS");}finally{RouterNodeChainCandidateMeasurement.holdClose=false;AndroidNodeCandidateMeasurement.cancelActive();}}
}'''


def compiler(source):
    text=C.compiler(source)
    anchor='case len(args)==2&&args[0]=="candidate-supported":'
    assert text.count(anchor)==1
    return text.replace(anchor,'case len(args)==2&&args[0]=="candidate-node-config":var node *mobilemultihop.NodeProfile;node,err=mobilemultihop.ParseNodeLaunchInput(args[1]);if err==nil{result=node.Config()};'+anchor)


def prepare(src,app,java):
    C.prepare(src,app,java)
    libbox=src/'io/nekohasekai/libbox/Libbox.java';source=libbox.read_text()
    assert source.endswith('}')
    libbox.write_text(source[:-1]+'public static String routerLayeredCandidateConfig(String input)throws Exception{return call("candidate-node-config",input);}}')
    (app/'NodeLayeredCandidateHarness.java').write_text(HARNESS)


def run(root,work,app,classes,jar,env,imported_only=False):
    env=C.generate_fixture(root,work,env)
    def execute(output,layer,check=True):
        private=output/'private';private.mkdir(parents=True)
        return subprocess.run(['java','-cp',str(output)+os.pathsep+str(jar),'com.eabusham.routervpn.NodeLayeredCandidateHarness',str(private),layer],env=env,check=check,text=True,capture_output=not check,timeout=120)
    for index,layer in enumerate(('off','aes-256-gcm','aes-256-gcm+xor-whitening')):
        target=work/('layered-baseline-'+str(index));shutil.copytree(classes,target);execute(target,layer)
    original=(app/'AndroidNodeCandidateCatalog.java').read_text()
    anchor='if(!java.util.Arrays.asList("","off","aes-256-gcm","aes-256-gcm+xor-whitening").contains(layer)'
    assert original.count(anchor)==1
    for index,layer in enumerate(('aes-256-gcm','aes-256-gcm+xor-whitening')):
        mutant=work/('layered-old-off-'+str(index));mutant.mkdir();source=mutant/'AndroidNodeCandidateCatalog.java'
        source.write_text(original.replace(anchor,'if(!java.util.Arrays.asList("","off").contains(layer)',1))
        target=mutant/'classes';shutil.copytree(classes,target)
        subprocess.run(['javac','--release','17','-cp',str(target)+os.pathsep+str(jar),'-d',str(target),str(source)],check=True,timeout=60)
        failed=execute(target,layer,False)
        if failed.returncode!=1 or 'paired layered candidate omitted from eligible catalog' not in failed.stderr or any(x in failed.stderr for x in ('OutOfMemoryError','SIGSEGV','Internal Error')):
            raise AssertionError('old Off guard control did not reach intended witness: '+failed.stdout+failed.stderr)
        print('Android original Off-only candidate guard rejected:',layer,flush=True)

if __name__=='__main__':
    C.chain.prepare_sources=prepare;C.chain.compiler_source=compiler;C.chain.run=run
    sys.argv=[sys.argv[0],'--case-family','ordered-chain'];C.profiles.main()
