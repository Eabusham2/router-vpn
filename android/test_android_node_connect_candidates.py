#!/usr/bin/env python3
"""Shipping CONNECT candidate catalogs/proposals with real stores and Go parsers.

Only native TCP measurement and the outer graph's drain receipt are doubled.
This does not claim a CONNECT authentication, TLS handshake, or installed run.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import test_android_node_candidates as candidates

HARNESS=r'''package com.eabusham.routervpn;
import java.nio.file.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import org.json.*;import io.nekohasekai.libbox.*;
public final class NodeConnectCandidateHarness {
 static final AtomicInteger checks=new AtomicInteger();
 static void check(boolean value,String message){checks.incrementAndGet();if(!value)throw new AssertionError(message);}
 interface Work{void run()throws Exception;}
 static void reject(Work work,String message)throws Exception{try{work.run();}catch(Exception expected){checks.incrementAndGet();return;}throw new AssertionError(message);}
 static AndroidStandardExitStore.Entry entry(String wire)throws Exception{var e=new AndroidStandardExitStore.Entry();e.id="1234567890abcdef1234567890abcdef";e.name="Original CONNECT candidate";e.protocol=wire;e.server="198.51.100.76";e.serverPort=8443;e.expectedPublicIp="203.0.113.76";e.username="original-proxy-user";e.password="private-original-proxy-password";e.tlsServerName="original.proxy.example";e.policy.put("start_layer","off").put("dns_mode","rescue");return e;}
 static final class Authority implements AndroidNodeCandidateProfile.SavedResultAuthority {
  final AndroidNodeCandidateCatalog catalog;final AndroidNodeCandidateResult result;boolean drained;
  Authority(AndroidNodeCandidateCatalog catalog,AndroidNodeCandidateResult result){this.catalog=catalog;this.result=result;}
  public void requireCurrent(AndroidNodeCandidateResult current)throws Exception{if(!drained||current!=result)throw new IllegalStateException("Original graph has not drained");catalog.requireSavedSourcesCurrent();}
 }
 static final class Captured implements AutoCloseable {
  final NodeChainCaptureHarness.Fixture fixture;final AndroidStandardExitStore.Entry entry;final AndroidNodeChainSession session;final AndroidNodeCandidateCatalog catalog;
  final Object lease;final CountDownLatch completed=new CountDownLatch(1),finished=new CountDownLatch(1);final AtomicReference<Throwable> failure=new AtomicReference<>();
  AndroidNodeCandidateMeasurement owner;AndroidNodeCandidateResult result;AndroidNodeCandidateProfile proposal;Authority authority;
  Captured(Path root,String key,String wire,int prefix,String fault)throws Exception{
   fixture=new NodeChainCaptureHarness.Fixture(root,key);entry=entry(wire);var exits=new AndroidStandardExitStore(fixture.context);exits.save(entry);
   var hostname=AndroidStandardExitStore.copy(entry);hostname.id="unsupported-connect-host";hostname.server="unscored.proxy.example";reject(()->exits.save(hostname),"CONNECT hostname acquired an unowned resolver path");
   var unsupported=AndroidStandardExitStore.copy(entry);unsupported.id="unsupported-socks";unsupported.protocol="socks5";unsupported.tlsServerName="";unsupported.username="u".repeat(256);unsupported.password="bounded-password";exits.save(unsupported);
   session=new AndroidNodeChainSession(fixture.profiles.currentOrderedPath());catalog=new AndroidNodeCandidateCatalog(fixture.context,session,prefix);
   var row=catalog.rows.stream().filter(v->v.localID.equals(entry.id)).findFirst().orElseThrow();
   check(!row.input.isEmpty()&&row.reason.isEmpty(),"original CONNECT candidate was omitted from eligible catalog");
   check(catalog.rows.stream().anyMatch(v->v.localID.equals(unsupported.id)&&v.input.isEmpty()),"unsupported SOCKS candidate acquired a TCP score");
   JSONObject member=new JSONObject(row.input),capture=new JSONObject(member.getString("capture")),transport=capture.getJSONObject("profile").getJSONObject("external").getJSONObject(AndroidExternalPolicy.protocol(wire).replace('-','_'));
   check(member.getString("kind").equals("routervpn-node-chain-connect-member")&&capture.getString("protocol").equals(AndroidExternalPolicy.protocol(wire)),"CONNECT catalog changed exact source kind or protocol");
   check(transport.getString("username").equals(entry.username)&&transport.getString("password").equals(entry.password),"CONNECT catalog changed original proxy credentials");
   if("https".equals(wire))check(transport.getString("tls_server_name").equals(entry.tlsServerName),"CONNECT catalog changed original TLS identity");
   lease=AndroidMTUMeasurementGate.acquire();RouterNodeChainCandidateMeasurement.holdClose=true;
   try{
    owner=AndroidNodeCandidateMeasurement.startBorrowed(catalog,lease,new AndroidNodeCandidateMeasurement.Callback(){
     public void changed(List<AndroidNodeCandidateResult> rows,String detail){}
     public void completed(AndroidNodeCandidateMeasurement operation,List<AndroidNodeCandidateResult> rows)throws Exception{
      owner=operation;
      try{
       result=rows.stream().filter(v->v.id.equals(entry.id)).findFirst().orElseThrow();operation.requireResult(result);
       JSONObject raw=new JSONObject(RouterNodeChainCandidateMeasurement.last.statusJSON());
       check(raw.getString("measurement").equals("routed-tcp-connect")&&raw.getJSONArray("results").getJSONObject(0).getJSONObject("benchmark").getInt("attempts")==50,"CONNECT TCP score was promoted to authentication or TLS proof");
       int opened=RouterNodeChainCONNECT.opens,closed=RouterNodeChainCONNECT.closes;
       if(fault.equals("cancel")){
        RouterNodeChainCONNECT.afterConfig=operation::cancel;
        reject(()->new AndroidNodeCandidateProfile(operation,result),"CONNECT proposal ignored cancellation during typed compile");
       }else if(!fault.isEmpty()){
        reject(()->new AndroidNodeCandidateProfile(operation,result),"unsupported CONNECT proposal escaped its captured prefix or final UoT bound");
       }else{
        authority=new Authority(catalog,result);proposal=AndroidNodeCandidateProfile.captureTemporary(operation,result,authority);
        check(RouterNodeChainCONNECT.opens==opened+1,"CONNECT proposal bypassed its typed native compiler");
        JSONObject proposed=new JSONObject(RouterNodeChainCONNECT.lastSource);
        check(proposed.getInt("schema")==4&&proposed.getJSONArray("nodes").length()==3&&proposed.getJSONArray("identity_sources").getString(1).isEmpty(),"CONNECT proposal borrowed a generic or paired identity");
        check(proposed.getJSONArray("nodes").getString(1).equals(row.input),"CONNECT proposal substituted the measured original member");
       }
       check(RouterNodeChainCONNECT.closes==closed+(RouterNodeChainCONNECT.opens-opened),"CONNECT typed compiler handle escaped exact cleanup");
      }catch(Throwable e){failure.set(e);}finally{completed.countDown();}
     }
     public void finished(Throwable error){finished.countDown();}
    });
    check(completed.await(15,TimeUnit.SECONDS),"CONNECT candidate completion did not arrive");
    if(failure.get()!=null)throw new AssertionError("CONNECT proposal failed its original shared capture",failure.get());
   }catch(Exception|AssertionError e){close();throw e;}
  }
  void join()throws Exception{RouterNodeChainCandidateMeasurement.holdClose=false;check(finished.await(10,TimeUnit.SECONDS)&&owner.joined(),"CONNECT native TCP worker did not join");check(AndroidMTUMeasurementGate.owns(lease),"CONNECT candidate released original outer graph lease");}
  public void close()throws Exception{RouterNodeChainCONNECT.afterConfig=null;RouterNodeChainCandidateMeasurement.holdClose=false;if(owner!=null)owner.cancel();finished.await(10,TimeUnit.SECONDS);AndroidMTUMeasurementGate.release(lease);}
 }
 static void save(Path root,String key,String wire)throws Exception{
  try(var c=new Captured(root,"connect/"+key,wire,0,"")){
   var f=c.fixture;var before=new NodeChainCaptureHarness.State(f);
   c.authority.drained=true;reject(()->c.proposal.save(f.context,"Before candidate join"),"CONNECT proposal saved before native candidate join");c.authority.drained=false;
   c.join();reject(()->c.proposal.save(f.context,"Before graph drain"),"CONNECT proposal saved before original graph drain");
   c.session.current=false;AndroidMTUMeasurementGate.release(c.lease);c.authority.drained=true;
   var saved=c.proposal.save(f.context,"Measured "+wire);String stored=Files.readString(f.rows);JSONObject row=new JSONObject(stored).getJSONArray("profiles").getJSONObject(0);
   check(row.getJSONArray("multihop_nodes").length()==3&&row.getJSONArray("multihop_nodes").getJSONObject(1).getString("mode").equals(AndroidExternalPolicy.protocol(wire)),"CONNECT saved proposal lost exact measured mode or retained final");
   check(!stored.contains(c.entry.username)&&!stored.contains(c.entry.password)&&!stored.contains("api_token"),"CONNECT saved proposal duplicated original credentials");
   var after=new NodeChainCaptureHarness.State(f);check(before.preferences.equals(after.preferences),"CONNECT Save changed active selection");for(Path path:before.files.keySet())if(!path.equals(f.rows))check(Arrays.equals(before.files.get(path),after.files.get(path)),"CONNECT Save edited an original source");
   var exits=new AndroidStandardExitStore(f.context);var changed=AndroidStandardExitStore.copy(c.entry);changed.password="changed-after-measurement";exits.save(changed);
   reject(()->c.proposal.save(f.context,"Changed credentials"),"CONNECT proposal saved after captured credentials changed");check(Files.readString(f.rows).equals(stored),"stale CONNECT proposal changed stored profiles");
   exits.save(c.entry);reject(()->c.proposal.save(f.context,"Restored bytes"),"CONNECT proposal revived after credential change-away/back");
   f.profiles.load(saved.id);
   try(var loaded=AndroidNodeChainCapture.compile(f.profiles.currentOrderedPath())){
    check(loaded.plan==null&&loaded.connect!=null&&new JSONObject(loaded.launchInput).getInt("schema")==4,"explicit CONNECT Load did not use its typed source");
    JSONObject middle=new JSONObject(loaded.memberInputs.get(1));check(middle.getString("capture").contains(c.entry.password),"explicit CONNECT Load lost original credentials");
   }
  }
 }
 public static void main(String[] args)throws Exception{
  try{Path root=Path.of(args[0]);for(String key:List.of("2/","2/awg-fast","2/awg-strong"))for(String wire:List.of("http","https"))save(root,key,wire);
   for(String wire:List.of("http","https")){
    try(var c=new Captured(root,"connect/2/",wire,0,"cancel")){c.join();check(!Files.exists(c.fixture.rows),"cancelled CONNECT compile wrote a profile");}
    try(var c=new Captured(root,"2/",wire,0,"no-uot")){c.join();check(!Files.exists(c.fixture.rows),"unproved CONNECT final wrote a profile");}
    try(var c=new Captured(root,"connect/3/",wire,1,"long-prefix")){c.join();check(!Files.exists(c.fixture.rows),"unsupported CONNECT prefix wrote a profile");}
   }
   System.out.println("Android CONNECT candidates: "+checks.get()+" actual source, typed proposal, credential, metric and joined Save checks PASS");
  }finally{RouterNodeChainCONNECT.afterConfig=null;RouterNodeChainCandidateMeasurement.holdClose=false;AndroidNodeCandidateMeasurement.cancelActive();}
 }
}'''


def prepare(src,app,java):
    candidates.prepare(src,app,java)
    (app/'NodeConnectCandidateHarness.java').write_text(HARNESS)
    target=src/'io/nekohasekai/libbox/RouterNodeChainCONNECT.java';raw=target.read_text()
    old='private final String original;private boolean closed;RouterNodeChainCONNECT(String source){original=source;}'
    new='public static volatile int opens,closes;public static volatile String lastSource;public static Runnable afterConfig;private final String original;private boolean closed;RouterNodeChainCONNECT(String source){original=source;lastSource=source;opens++;}'
    assert raw.count(old)==1;raw=raw.replace(old,new)
    old='public String config()throws Exception{return Libbox.call("chain-connect-config",source());}'
    new='public String config()throws Exception{String value=Libbox.call("chain-connect-config",source());Runnable hook=afterConfig;afterConfig=null;if(hook!=null)hook.run();return value;}'
    assert raw.count(old)==1;raw=raw.replace(old,new)
    old='public void close(){closed=true;}'
    assert raw.count(old)==1;raw=raw.replace(old,'public void close(){if(!closed)closes++;closed=true;}');target.write_text(raw)


def run(root,work,app,classes,jar,env,imported_only=False):
    env=candidates.generate_fixture(root,work,env);classpath=str(classes)+os.pathsep+str(jar)
    private=work/'connect-candidate-data';private.mkdir()
    subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeConnectCandidateHarness',str(private)],env=env,check=True,timeout=120)
    controls=(
        ('AndroidNodeCandidateCatalog','if(!source.imported)return "shadowsocks";','if(source.imported||!source.imported)return "shadowsocks";','original CONNECT candidate was omitted'),
        ('AndroidNodeCandidateProfile','sources.add(candidate);modes.add(candidateMode);','sources.add(candidate);modes.add("shadowsocks");','CONNECT proposal failed its original shared capture'),
        ('AndroidNodeCandidateProfile','if(schema==4){','if(schema==3){','CONNECT proposal failed its original shared capture'),
        ('AndroidNodeCandidateProfile','if(schema==4){\n            try(AndroidNodeChainCONNECTCapture compiled=AndroidNodeChainCONNECTCapture.compile(input,capturedInputs,capturedIdentities)){\n                requireCurrent();','if(schema==4){\n            try(AndroidNodeChainCONNECTCapture compiled=AndroidNodeChainCONNECTCapture.compile(input,capturedInputs,capturedIdentities)){' ,'CONNECT proposal ignored cancellation during typed compile'),
        ('AndroidNodeCandidateProfile','try(AndroidNodeChainCONNECTCapture compiled=AndroidNodeChainCONNECTCapture.compile(input,capturedInputs,capturedIdentities)){','{AndroidNodeChainCONNECTCapture compiled=AndroidNodeChainCONNECTCapture.compile(input,capturedInputs,capturedIdentities);','CONNECT typed compiler handle escaped exact cleanup'),
    )
    for index,(name,old,new,witness) in enumerate(controls):
        original=(app/(name+'.java')).read_text();assert original.count(old)==1,old
        directory=work/('connect-candidate-mutant-'+str(index));directory.mkdir();source=directory/(name+'.java');source.write_text(original.replace(old,new));target=directory/'classes';shutil.copytree(classes,target);cp=str(target)+os.pathsep+str(jar)
        subprocess.run(['javac','--release','17','-cp',cp,'-d',str(target),str(source)],check=True,timeout=60)
        private=directory/'private';private.mkdir();failed=subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.NodeConnectCandidateHarness',str(private)],env=env,capture_output=True,text=True,timeout=120)
        assert failed.returncode!=0 and witness in failed.stderr,failed.stdout+failed.stderr
        print('Android CONNECT candidate causal control rejected:',witness,flush=True)


if __name__=='__main__':
    candidates.chain.prepare_sources=prepare;candidates.chain.compiler_source=candidates.compiler;candidates.chain.run=run
    sys.argv=[sys.argv[0],'--case-family','ordered-chain'];candidates.profiles.main()
