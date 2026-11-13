#!/usr/bin/env python3
"""Execute post-drain candidate proposal saves with real stores/shared compiler.

Only the preparation's graph-drain authority and native measurement callbacks
are doubled here. The integrated preparation gate owns the actual handoff.
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import test_android_node_candidates as candidates

ROOT=candidates.ROOT
HARNESS=r'''package com.eabusham.routervpn;
import java.nio.file.*;import java.util.*;import java.util.concurrent.*;import org.json.*;import io.nekohasekai.libbox.*;
public final class NodeCandidateProfileHarness {
 static int checks;
 static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
 interface Work{void run()throws Exception;}
 static void reject(Work work,String message)throws Exception{try{work.run();}catch(Exception expected){checks++;return;}throw new AssertionError(message);}
 // This deliberately exposes separate native-candidate and outer-graph joins.
 // A completed TCP receipt is never itself evidence that the graph is DOWN.
 static final class Authority implements AndroidNodeCandidateProfile.SavedResultAuthority {
  final AndroidNodeCandidateResult original;boolean drained,current=true;int calls,rejectAt;
  Authority(AndroidNodeCandidateResult result){original=result;}
  public void requireCurrent(AndroidNodeCandidateResult result){calls++;if(!drained||!current||result!=original||calls==rejectAt)throw new IllegalStateException("Original detached preparation is not current");}
 }
 static final class Captured implements AutoCloseable {
  final NodeChainCaptureHarness.Fixture fixture;final AndroidNodeChainSession session;final Object lease;
  final CountDownLatch completed=new CountDownLatch(1),finished=new CountDownLatch(1);
  AndroidNodeCandidateMeasurement owner;AndroidNodeCandidateResult result;Authority authority;
  AndroidNodeCandidateProfile temporary,live;
  Captured(Path root,String method)throws Exception{
   fixture=new NodeChainCaptureHarness.Fixture(root,method.contains("aes-128")?"2/":method.contains("aes-256")?"2/awg-fast":"3/awg-strong");
   var entry=NodeCandidateHarness.custom(method);new AndroidStandardExitStore(fixture.context).save(entry);
   session=new AndroidNodeChainSession(fixture.profiles.currentOrderedPath());
   var catalog=new AndroidNodeCandidateCatalog(fixture.context,session,0);lease=AndroidMTUMeasurementGate.acquire();
   RouterNodeChainCandidateMeasurement.holdClose=true;
   owner=AndroidNodeCandidateMeasurement.startBorrowed(catalog,lease,new AndroidNodeCandidateMeasurement.Callback(){
    public void changed(List<AndroidNodeCandidateResult> rows,String detail){}
    public void completed(AndroidNodeCandidateMeasurement operation,List<AndroidNodeCandidateResult> rows)throws Exception{
     owner=operation;
     try{
      result=rows.stream().filter(row->row.id.equals(entry.id)).findFirst().orElseThrow();authority=new Authority(result);
      reject(()->AndroidNodeCandidateProfile.captureTemporary(operation,result,null),"temporary proposal accepted no detached authority");
      var constructor=AndroidNodeCandidateResult.class.getDeclaredConstructors()[0];constructor.setAccessible(true);
      var copied=(AndroidNodeCandidateResult)constructor.newInstance(result.id,result.name,result.source,result.measuredAt,result.expiresAt,result.score);
      reject(()->AndroidNodeCandidateProfile.captureTemporary(operation,copied,authority),"temporary proposal accepted a copied unadmitted result");
      live=new AndroidNodeCandidateProfile(operation,result);
      temporary=AndroidNodeCandidateProfile.captureTemporary(operation,result,authority);
     }finally{completed.countDown();}
    }
    public void finished(Throwable failure){finished.countDown();}
   });
   check(completed.await(15,TimeUnit.SECONDS)&&temporary!=null,"temporary proposal was not captured while original measurement was live");
  }
  void joinCandidate()throws Exception{
   RouterNodeChainCandidateMeasurement.holdClose=false;
   check(finished.await(10,TimeUnit.SECONDS)&&owner.joined(),"original candidate worker did not join");
   check(AndroidMTUMeasurementGate.owns(lease),"candidate join released the still-owned outer graph lease");
  }
  void drainGraph(){session.current=false;AndroidMTUMeasurementGate.release(lease);authority.drained=true;}
  public void close()throws Exception{RouterNodeChain.afterConfig=null;RouterNodeChainCandidateMeasurement.holdClose=false;owner.cancel();finished.await(10,TimeUnit.SECONDS);AndroidMTUMeasurementGate.release(lease);}
 }
 static void saveAfterDown(Path root,String method)throws Exception{
  try(var capture=new Captured(root,method)){
   var f=capture.fixture;var before=new NodeChainCaptureHarness.State(f);
   capture.authority.drained=true;
   reject(()->capture.temporary.save(f.context,"Before candidate join"),"temporary proposal saved before original candidate join");
   capture.authority.drained=false;capture.joinCandidate();
   reject(()->capture.live.save(f.context,"Closed live receipt"),"ordinary live proposal survived closed measurement");
   reject(()->AndroidNodeCandidateProfile.captureTemporary(capture.owner,capture.result,capture.authority),"closed measurement minted a new temporary proposal");
   reject(()->capture.temporary.save(f.context,"Before graph drain"),"temporary proposal saved before original graph drain authority");
   check(!Files.exists(f.rows),"unjoined temporary proposal wrote profile storage");
   capture.drainGraph();
   var saved=capture.temporary.save(f.context,"Detached "+method);
   check(saved.mode.equals("shadowsocks"),"detached save lost its actual final transport");
   JSONArray rows=new JSONObject(Files.readString(f.rows)).getJSONArray("profiles");JSONObject row=rows.getJSONObject(0);
   check(rows.length()==1&&row.getJSONArray("multihop_nodes").length()==3,"detached proposal lost original paired prefix/custom middle/final");
   check(!row.toString().contains("api_token")&&!row.toString().contains("wg_private_key")&&!row.toString().contains(NodeCandidateHarness.custom(method).secret),"detached profile copied original private credentials");
   var after=new NodeChainCaptureHarness.State(f);
   for(Path path:before.files.keySet())if(!path.equals(f.rows))check(Arrays.equals(before.files.get(path),after.files.get(path)),"detached Save edited an original node source");
   check(before.preferences.equals(after.preferences),"detached Save changed selected or active path preferences");
   byte[] original=Files.readAllBytes(f.rows);
   capture.authority.current=false;
   reject(()->capture.temporary.save(f.context,"Retired detached receipt"),"retired detached authority saved a profile");
   capture.authority.current=true;capture.authority.rejectAt=capture.authority.calls+3;
   reject(()->capture.temporary.save(f.context,"Changed during append"),"late detached authority change wrote profile storage");
   check(Arrays.equals(original,Files.readAllBytes(f.rows)),"rejected detached save changed stored profiles");
   capture.authority.rejectAt=0;
   var expiry=AndroidNodeCandidateResult.class.getDeclaredField("expiresAt");expiry.setAccessible(true);expiry.setLong(capture.result,System.currentTimeMillis()-1);
   reject(()->capture.temporary.save(f.context,"Expired detached receipt"),"expired detached result saved a profile");
   check(Arrays.equals(original,Files.readAllBytes(f.rows)),"expired result wrote profile storage");
   f.profiles.load(saved.id);
   try(var compiled=AndroidNodeChainCapture.compile(f.profiles.currentOrderedPath())){check(new JSONObject(compiled.launchInput).getInt("schema")==2,"detached saved path did not compile on normal explicit Load");}
  }
 }
 static void cancellationDuringCompile(Path root)throws Exception{
  var f=new NodeChainCaptureHarness.Fixture(root,"2/");var session=new AndroidNodeChainSession(f.profiles.currentOrderedPath());var catalog=new AndroidNodeCandidateCatalog(f.context,session,0);
  CountDownLatch ready=new CountDownLatch(1),finished=new CountDownLatch(1);var results=new java.util.concurrent.atomic.AtomicReference<List<AndroidNodeCandidateResult>>();
  var operation=AndroidNodeCandidateMeasurement.start(catalog,new AndroidNodeCandidateMeasurement.Callback(){public void changed(List<AndroidNodeCandidateResult> rows,String detail){if(!rows.isEmpty()){results.set(rows);ready.countDown();}}public void finished(Throwable failure){finished.countDown();}});
  try{
   check(ready.await(10,TimeUnit.SECONDS),"live compiler cancellation fixture received no result");
   var result=results.get().get(0);RouterNodeChain.afterConfig=operation::cancel;
   reject(()->AndroidNodeCandidateProfile.captureTemporary(operation,result,new Authority(result)),"temporary proposal ignored cancellation during original graph compile");
  }finally{RouterNodeChain.afterConfig=null;operation.cancel();check(finished.await(10,TimeUnit.SECONDS),"compile-cancelled candidate did not join");}
 }
 public static void main(String[] args)throws Exception{
  try{Path root=Path.of(args[0]);for(String method:List.of("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305"))saveAfterDown(root,method);cancellationDuringCompile(root);System.out.println("Android detached candidate proposals: "+checks+" complete source, drain and explicit Save checks PASS");}
  finally{RouterNodeChain.afterConfig=null;RouterNodeChainCandidateMeasurement.holdClose=false;AndroidNodeCandidateMeasurement.cancelActive();}
 }
}'''


def prepare(src,app,java):
    candidates.prepare(src,app,java)
    (app/'NodeCandidateProfileHarness.java').write_text(HARNESS)
    source=src/'io/nekohasekai/libbox/RouterNodeChain.java'
    raw=source.read_text()
    before=' public String config()throws Exception{return Libbox.call("chain-config",launchInput());}'
    after=' public static Runnable afterConfig; public String config()throws Exception{String config=Libbox.call("chain-config",launchInput());Runnable hook=afterConfig;afterConfig=null;if(hook!=null)hook.run();return config;}'
    assert raw.count(before)==1
    source.write_text(raw.replace(before,after))


def run_profiles(root,work,app,classes,jar,env):
    classpath=str(classes)+os.pathsep+str(jar)
    data=work/'candidate-profile-data';data.mkdir()
    subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeCandidateProfileHarness',str(data)],env=env,check=True,timeout=120)
    controls=(
        ('!operation.joined()||','', 'temporary proposal saved before original candidate join'),
        ('savedAuthority.requireCurrent(result);','', 'temporary proposal saved before original graph drain authority'),
        ('try{requireSavedCurrent();}catch','try{}catch', 'late detached authority change wrote profile storage'),
        ('||!result.current(System.currentTimeMillis())','', 'expired detached result saved a profile'),
        ('throw new IllegalStateException("The compiler returned no complete proposed graph.");requireCurrent();','throw new IllegalStateException("The compiler returned no complete proposed graph.");', 'temporary proposal ignored cancellation during original graph compile'),
    )
    original=(app/'AndroidNodeCandidateProfile.java').read_text()
    for index,(old,new,witness) in enumerate(controls):
        assert original.count(old)==1 and old!=new,old
        mutation=work/('candidate-profile-mutant-'+str(index));mutation.mkdir()
        source=mutation/'AndroidNodeCandidateProfile.java';source.write_text(original.replace(old,new))
        target=mutation/'classes';shutil.copytree(classes,target);classpath=str(target)+os.pathsep+str(jar)
        subprocess.run(['javac','--release','17','-cp',classpath,'-d',str(target),str(source)],check=True,timeout=60)
        data=mutation/'private';data.mkdir()
        failed=subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeCandidateProfileHarness',str(data)],env=env,capture_output=True,text=True,timeout=120)
        assert failed.returncode!=0 and witness in failed.stderr,failed.stdout+failed.stderr
        print('Android detached proposal causal control rejected:',witness,flush=True)


def run(root,work,app,classes,jar,env,imported_only=False):
    env=candidates.generate_fixture(root,work,env)
    run_profiles(root,work,app,classes,jar,env)


if __name__=='__main__':
    candidates.chain.prepare_sources=prepare;candidates.chain.compiler_source=candidates.compiler;candidates.chain.run=run
    sys.argv=[sys.argv[0],'--case-family','ordered-chain'];candidates.profiles.main()
