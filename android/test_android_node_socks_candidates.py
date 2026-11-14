#!/usr/bin/env python3
"""Shipping SOCKS candidate catalogs/proposals with real stores and Go parsers.

Only native TCP measurement and the outer graph's drain receipt are doubled.
This does not claim SOCKS authentication, a UDP association, or an installed run.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import test_android_node_candidates as candidates

HARNESS=r'''package com.eabusham.routervpn;
import java.nio.file.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import org.json.*;import io.nekohasekai.libbox.*;
public final class NodeSOCKSCandidateHarness {
 static final AtomicInteger checks=new AtomicInteger();
 static void check(boolean value,String message){checks.incrementAndGet();if(!value)throw new AssertionError(message);}
 interface Work{void run()throws Exception;}
 static void reject(Work work,String message)throws Exception{try{work.run();}catch(Exception expected){checks.incrementAndGet();return;}throw new AssertionError(message);}
 static AndroidStandardExitStore.Entry entry(String wire)throws Exception{var e=new AndroidStandardExitStore.Entry();e.id="1234567890abcdef1234567890abcdef";e.name="Original SOCKS candidate";e.protocol="socks5";e.server="198.51.100.76";e.serverPort=8443;e.expectedPublicIp="203.0.113.76";e.username=wire.equals("password")?"original-proxy-user":"";e.password=wire.equals("password")?"private-original-proxy-password":"";e.tlsServerName="original.proxy.example";e.policy.put("start_layer","off").put("dns_mode","rescue");return e;}
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
   var hostname=AndroidStandardExitStore.copy(entry);hostname.id="unsupported-socks-host";hostname.server="unscored.proxy.example";reject(()->exits.save(hostname),"SOCKS hostname acquired an unowned resolver path");
   var unsupported=AndroidStandardExitStore.copy(entry);unsupported.id="unsupported-socks";unsupported.protocol="socks5";unsupported.tlsServerName="";unsupported.username="u".repeat(256);unsupported.password="bounded-password";exits.save(unsupported);
   var udp=AndroidStandardExitStore.copy(entry);udp.id="unsupported-hysteria2";udp.protocol="hysteria2";udp.secret="private-udp-secret";udp.tlsServerName="udp.example";exits.save(udp);
   session=new AndroidNodeChainSession(fixture.profiles.currentOrderedPath());catalog=new AndroidNodeCandidateCatalog(fixture.context,session,prefix);
   var row=catalog.rows.stream().filter(v->v.localID.equals(entry.id)).findFirst().orElseThrow();
   check(!row.input.isEmpty()&&row.reason.isEmpty(),"original SOCKS candidate was omitted from eligible catalog");
   check(catalog.rows.stream().anyMatch(v->v.localID.equals(unsupported.id)&&v.input.isEmpty()),"unsupported SOCKS candidate acquired a TCP score");
   check(catalog.rows.stream().anyMatch(v->v.localID.equals(udp.id)&&v.input.isEmpty()),"UDP-only candidate acquired a guessed TCP score");
   JSONObject member=new JSONObject(row.input),capture=new JSONObject(member.getString("capture")),transport=capture.getJSONObject("profile").getJSONObject("external").getJSONObject("socks5".replace('-','_'));
   check(member.getString("kind").equals("routervpn-node-chain-socks-member")&&capture.getString("protocol").equals("socks5"),"SOCKS catalog changed exact source kind or protocol");
   check(transport.optString("username","").equals(entry.username)&&transport.optString("password","").equals(entry.password),"SOCKS catalog changed original proxy credentials");
   
   lease=AndroidMTUMeasurementGate.acquire();RouterNodeChainCandidateMeasurement.holdClose=true;
   try{
    owner=AndroidNodeCandidateMeasurement.startBorrowed(catalog,lease,new AndroidNodeCandidateMeasurement.Callback(){
     public void changed(List<AndroidNodeCandidateResult> rows,String detail){}
     public void completed(AndroidNodeCandidateMeasurement operation,List<AndroidNodeCandidateResult> rows)throws Exception{
      owner=operation;
      try{
       result=rows.stream().filter(v->v.id.equals(entry.id)).findFirst().orElseThrow();operation.requireResult(result);
       JSONObject raw=new JSONObject(RouterNodeChainCandidateMeasurement.last.statusJSON());
       check(raw.getString("measurement").equals("routed-tcp-connect")&&raw.getJSONArray("results").getJSONObject(0).getJSONObject("benchmark").getInt("attempts")==50,"SOCKS TCP score was promoted to authentication or UDP-association proof");
       int opened=RouterNodeChainSOCKS.opens,closed=RouterNodeChainSOCKS.closes;
       if(fault.equals("cancel")){
        RouterNodeChainSOCKS.afterConfig=operation::cancel;
        reject(()->new AndroidNodeCandidateProfile(operation,result),"SOCKS proposal ignored cancellation during typed compile");
       }else if(!fault.isEmpty()){
        reject(()->new AndroidNodeCandidateProfile(operation,result),"unsupported SOCKS proposal escaped its captured prefix bound");
       }else{
        authority=new Authority(catalog,result);proposal=AndroidNodeCandidateProfile.captureTemporary(operation,result,authority);
        check(RouterNodeChainSOCKS.opens==opened+1,"SOCKS proposal bypassed its typed native compiler");
        JSONObject proposed=new JSONObject(RouterNodeChainSOCKS.lastSource);
        check(proposed.getInt("schema")==3&&proposed.getJSONArray("nodes").length()==3&&proposed.getJSONArray("identity_sources").getString(1).isEmpty(),"SOCKS proposal borrowed a generic or paired identity");
        check(proposed.getJSONArray("nodes").getString(1).equals(row.input),"SOCKS proposal substituted the measured original member");
       }
       check(RouterNodeChainSOCKS.closes==closed+(RouterNodeChainSOCKS.opens-opened),"SOCKS typed compiler handle escaped exact cleanup");
      }catch(Throwable e){failure.set(e);}finally{completed.countDown();}
     }
     public void finished(Throwable error){finished.countDown();}
    });
    check(completed.await(15,TimeUnit.SECONDS),"SOCKS candidate completion did not arrive");
    if(failure.get()!=null)throw new AssertionError("SOCKS proposal failed its original shared capture",failure.get());
   }catch(Exception|AssertionError e){close();throw e;}
  }
  void join()throws Exception{RouterNodeChainCandidateMeasurement.holdClose=false;check(finished.await(10,TimeUnit.SECONDS)&&owner.joined(),"SOCKS native TCP worker did not join");check(AndroidMTUMeasurementGate.owns(lease),"SOCKS candidate released original outer graph lease");}
  public void close()throws Exception{RouterNodeChainSOCKS.afterConfig=null;RouterNodeChainCandidateMeasurement.holdClose=false;if(owner!=null)owner.cancel();finished.await(10,TimeUnit.SECONDS);AndroidMTUMeasurementGate.release(lease);}
 }
 static void save(Path root,String key,String wire)throws Exception{
  try(var c=new Captured(root,key,wire,0,"")){
   var f=c.fixture;var before=new NodeChainCaptureHarness.State(f);
   c.authority.drained=true;reject(()->c.proposal.save(f.context,"Before candidate join"),"SOCKS proposal saved before native candidate join");c.authority.drained=false;
   c.join();reject(()->c.proposal.save(f.context,"Before graph drain"),"SOCKS proposal saved before original graph drain");
   c.session.current=false;AndroidMTUMeasurementGate.release(c.lease);c.authority.drained=true;
   var saved=c.proposal.save(f.context,"Measured "+wire);String stored=Files.readString(f.rows);JSONObject row=new JSONObject(stored).getJSONArray("profiles").getJSONObject(0);
   check(row.getJSONArray("multihop_nodes").length()==3&&row.getJSONArray("multihop_nodes").getJSONObject(1).getString("mode").equals("socks5"),"SOCKS saved proposal lost exact measured mode or retained final");
   check((c.entry.username.isEmpty()||!stored.contains(c.entry.username))&&(c.entry.password.isEmpty()||!stored.contains(c.entry.password))&&!stored.contains("api_token"),"SOCKS saved proposal duplicated original credentials");
   var after=new NodeChainCaptureHarness.State(f);check(before.preferences.equals(after.preferences),"SOCKS Save changed active selection");for(Path path:before.files.keySet())if(!path.equals(f.rows))check(Arrays.equals(before.files.get(path),after.files.get(path)),"SOCKS Save edited an original source");
   var exits=new AndroidStandardExitStore(f.context);var changed=AndroidStandardExitStore.copy(c.entry);changed.username="changed-user";changed.password="changed-after-measurement";exits.save(changed);
   reject(()->c.proposal.save(f.context,"Changed credentials"),"SOCKS proposal saved after captured credentials changed");check(Files.readString(f.rows).equals(stored),"stale SOCKS proposal changed stored profiles");
   exits.save(c.entry);reject(()->c.proposal.save(f.context,"Restored bytes"),"SOCKS proposal revived after credential change-away/back");
   f.profiles.load(saved.id);
   try(var loaded=AndroidNodeChainCapture.compile(f.profiles.currentOrderedPath())){
    check(loaded.plan==null&&loaded.socks!=null&&new JSONObject(loaded.launchInput).getInt("schema")==3,"explicit SOCKS Load did not use its typed source");
    JSONObject middle=new JSONObject(loaded.memberInputs.get(1));check(middle.getString("capture").contains(c.entry.password),"explicit SOCKS Load lost original credentials");
   }
  }
 }
 public static void main(String[] args)throws Exception{
  try{Path root=Path.of(args[0]);for(String key:List.of("2/","2/awg-fast","2/awg-strong"))for(String wire:List.of("password","none"))save(root,key,wire);
   for(String wire:List.of("password","none")){
    try(var c=new Captured(root,"2/",wire,0,"cancel")){c.join();check(!Files.exists(c.fixture.rows),"cancelled SOCKS compile wrote a profile");}
    try(var c=new Captured(root,"3/",wire,1,"long-prefix")){c.join();check(!Files.exists(c.fixture.rows),"unsupported SOCKS prefix wrote a profile");}
   }
   System.out.println("Android SOCKS candidates: "+checks.get()+" actual source, typed proposal, credential, metric and joined Save checks PASS");
  }finally{RouterNodeChainSOCKS.afterConfig=null;RouterNodeChainCandidateMeasurement.holdClose=false;AndroidNodeCandidateMeasurement.cancelActive();}
 }
}'''


def prepare(src,app,java):
    candidates.prepare(src,app,java)
    (app/'NodeSOCKSCandidateHarness.java').write_text(HARNESS)
    target=src/'io/nekohasekai/libbox/RouterNodeChainSOCKS.java';raw=target.read_text()
    old='private final String original;private boolean closed;RouterNodeChainSOCKS(String source){original=source;}'
    new='public static volatile int opens,closes;public static volatile String lastSource;public static Runnable afterConfig;private final String original;private boolean closed;RouterNodeChainSOCKS(String source){original=source;lastSource=source;opens++;}'
    assert raw.count(old)==1;raw=raw.replace(old,new)
    old='public String config()throws Exception{return Libbox.call("chain-socks-config",source());}'
    new='public String config()throws Exception{String value=Libbox.call("chain-socks-config",source());Runnable hook=afterConfig;afterConfig=null;if(hook!=null)hook.run();return value;}'
    assert raw.count(old)==1;raw=raw.replace(old,new)
    old='public void close(){closed=true;}'
    assert raw.count(old)==1;raw=raw.replace(old,'public void close(){if(!closed)closes++;closed=true;}');target.write_text(raw)


def run(root,work,app,classes,jar,env,imported_only=False):
    env=candidates.generate_fixture(root,work,env);classpath=str(classes)+os.pathsep+str(jar)
    private=work/'socks-candidate-data';private.mkdir()
    subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeSOCKSCandidateHarness',str(private)],env=env,check=True,timeout=120)
    controls=(
        ('AndroidNodeCandidateCatalog','if(!source.imported)return "shadowsocks";','if(source.imported||!source.imported)return "shadowsocks";','original SOCKS candidate was omitted'),
        ('AndroidNodeCandidateProfile','sources.add(candidate);modes.add(candidateMode);','sources.add(candidate);modes.add("shadowsocks");','SOCKS proposal failed its original shared capture'),
        ('AndroidNodeCandidateProfile','}else if(schema==3){','}else if(schema==2){','SOCKS proposal failed its original shared capture'),
        ('AndroidNodeCandidateProfile','}else if(schema==3){\n            try(AndroidNodeChainSOCKSCapture compiled=AndroidNodeChainSOCKSCapture.compile(input,capturedInputs,capturedIdentities)){\n                requireCurrent();','}else if(schema==3){\n            try(AndroidNodeChainSOCKSCapture compiled=AndroidNodeChainSOCKSCapture.compile(input,capturedInputs,capturedIdentities)){' ,'SOCKS proposal ignored cancellation during typed compile'),
        ('AndroidNodeCandidateProfile','try(AndroidNodeChainSOCKSCapture compiled=AndroidNodeChainSOCKSCapture.compile(input,capturedInputs,capturedIdentities)){','{AndroidNodeChainSOCKSCapture compiled=AndroidNodeChainSOCKSCapture.compile(input,capturedInputs,capturedIdentities);','SOCKS typed compiler handle escaped exact cleanup'),
    )
    for index,(name,old,new,witness) in enumerate(controls):
        original=(app/(name+'.java')).read_text();assert original.count(old)==1,old
        directory=work/('socks-candidate-mutant-'+str(index));directory.mkdir();source=directory/(name+'.java');source.write_text(original.replace(old,new));target=directory/'classes';shutil.copytree(classes,target);cp=str(target)+os.pathsep+str(jar)
        subprocess.run(['javac','--release','17','-cp',cp,'-d',str(target),str(source)],check=True,timeout=60)
        private=directory/'private';private.mkdir();failed=subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.NodeSOCKSCandidateHarness',str(private)],env=env,capture_output=True,text=True,timeout=120)
        assert failed.returncode!=0 and witness in failed.stderr,failed.stdout+failed.stderr
        print('Android SOCKS candidate causal control rejected:',witness,flush=True)


if __name__=='__main__':
    candidates.chain.prepare_sources=prepare;candidates.chain.compiler_source=candidates.compiler;candidates.chain.run=run
    sys.argv=[sys.argv[0],'--case-family','ordered-chain'];candidates.profiles.main()
