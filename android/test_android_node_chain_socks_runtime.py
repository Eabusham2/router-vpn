#!/usr/bin/env python3
"""Run the shipping typed SOCKS capture/session/runtime and complete VPN service.

OS, storage publication and native handles are explicit doubles. Native traffic
and source compilation have independent gates; this fixture proves host ownership.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'
spec=importlib.util.spec_from_file_location('ordinary_chain_host',ROOT/'android/test_android_node_chain_runtime.py')
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
APP,NATIVE=R.APP,R.NATIVE
SOURCES=dict(R.SOURCES)
SOURCES.pop(APP+'AndroidNodeChainSOCKSCapture.java')
SOURCES[NATIVE+'CommandServer.java']=SOURCES[NATIVE+'CommandServer.java'].replace('public void start(){}','public boolean typed,bound;public void start(){if(typed&&!bound)throw new IllegalStateException("typed server started before binding");}')
SOURCES[APP+'AndroidNodeStore.java']=SOURCES[APP+'AndroidNodeStore.java'].replace('selected.add(i==count-1?finalMode:prefixMode);','selected.add(i==count-1?finalMode:i==1?"socks5":prefixMode);')
SOURCES[APP+'AndroidNodeChainCapture.java']=r'''package com.eabusham.routervpn;final class AndroidNodeChainCapture {
 static final int MAX_INPUT=40*1024*1024;static final String SESSION_FILE="routervpn-node-chain.json";
 final AndroidNodeStore.ChainCapture source;final io.nekohasekai.libbox.RouterNodeChain plan=null;final AndroidNodeChainSOCKSCapture socks;final String sourceSHA256="a".repeat(64);final String configSHA256;final String config,launchInput;final boolean strict;final AndroidNodeChainCONNECTCapture connect=null;
 private AndroidNodeChainCapture(AndroidNodeStore.ChainCapture source)throws Exception{
  this.source=source;strict=source.strict;java.util.List<String> nodes=java.util.List.of("original-first","private-socks-credentials","original-final"),ids=java.util.List.of("first-paired-identity","","final-paired-identity");
  String input=new org.json.JSONObject().put("schema",3).put("execution","local").put("nodes",new org.json.JSONArray(nodes)).put("identity_sources",new org.json.JSONArray(ids)).toString();
  socks=AndroidNodeChainSOCKSCapture.compile(input,nodes,ids);config=socks.config;configSHA256=socks.configSHA256;launchInput=socks.source;
 }
 static AndroidNodeChainCapture compile(AndroidNodeStore.ChainCapture source)throws Exception{source.requireCurrent();return new AndroidNodeChainCapture(source);}
 boolean ownsSource(AndroidNodeStore.ChainCapture source){return this.source==source;}void requireCurrent(){source.requireCurrent();}void close()throws Exception{socks.close();}
}'''
SOURCES[NATIVE+'RouterNodeChainSOCKS.java']=r'''package io.nekohasekai.libbox;public class RouterNodeChainSOCKS {
 public static java.util.function.Consumer<RouterNodeChainSOCKS> configured;public static RouterNodeChainSOCKS latest;
 public final String input;public CommandServer server;public boolean bound,retired,closed,proved,missingReceipt,failBind,failProof,failClose,failFactory;public int factories,binds,runs,closes,hopCalls,mtuCalls;public Runnable afterFactory,afterRun;public RouterMTUPlatform mtuPlatform;
 public RouterNodeChainSOCKS(String input){this.input=input;latest=this;if(configured!=null)configured.accept(this);}
 public String source(){return input;}public String config(){return "{\"original\":\"typed-socks-owned-TUN\"}";}
 public String sourceSHA256(){return "a".repeat(64);}public String configSHA256()throws Exception{StringBuilder v=new StringBuilder();for(byte b:java.security.MessageDigest.getInstance("SHA-256").digest(config().getBytes(java.nio.charset.StandardCharsets.UTF_8)))v.append(String.format("%02x",b&255));return v.toString();}
 public String metadata()throws Exception{return new org.json.JSONObject().put("kind","routervpn-node-chain-socks-source").put("schema",1).put("source_sha256",sourceSHA256()).put("config_sha256",configSHA256()).toString();}
 public CommandServer newCommandServer(CommandServerHandler h,PlatformInterface p)throws Exception{if(retired||server!=null)throw new IllegalStateException("retired factory");factories++;if(failFactory)throw new IllegalStateException("native factory refused before construction");server=new CommandServer(h,p);server.typed=true;if(afterFactory!=null)afterFactory.run();return server;}
 public void bindNative(CommandServer s)throws Exception{if(s!=server||!s.startedConfig.isEmpty())throw new IllegalStateException("foreign or started server");binds++;if(failBind&&!retired)throw new IllegalStateException("bind pending");bound=true;s.bound=true;if(retired)throw new IllegalStateException("cleanup-only retired bind");}
 public void run(CommandServer s)throws Exception{if(retired||!bound||s!=server||s.startedConfig.isEmpty())throw new IllegalStateException("no original bound service");runs++;if(failProof)throw new IllegalStateException("selected DNS proof failed");proved=true;if(afterRun!=null)afterRun.run();}
 public boolean healthy(){return bound&&proved&&!retired&&server!=null&&!server.closed;}
 public void networkChanged(){retired=true;}public String progressJSON(){return "{}";}
 public void close()throws Exception{closes++;retired=true;if(failClose||server!=null&&!bound)throw new IllegalStateException("shared close pending");closed=true;}
 public boolean nativeClosed(){return closed&&server!=null&&(server.closed||bound&&server.startedConfig.isEmpty())&&!missingReceipt;}public boolean retainsServerCleanup(CommandServer s){return s==server&&retired&&!closed;}
}'''
SOURCES[NATIVE+'Libbox.java']=SOURCES[NATIVE+'Libbox.java'].replace('throw new IllegalStateException("No typed measurement in ordinary host fixture");','if(!plan.healthy()||plan.server!=server)throw new IllegalStateException("unproved typed measurement");plan.hopCalls++;return new RouterHopMeasurement();').replace('throw new IllegalStateException("No typed MTU in ordinary host fixture");','if(!plan.healthy()||plan.server!=server)throw new IllegalStateException("unproved typed MTU");plan.mtuCalls++;plan.mtuPlatform=platform;return new RouterMTU();')[:-1]+'''public static RouterNodeChainSOCKS newRouterNodeChainSOCKS(String input){return new RouterNodeChainSOCKS(input);}public static void routerValidatePrivateNodeJSON(String input)throws Exception{new org.json.JSONObject(input);}}'''
HARNESS=R.HARNESS[:R.HARNESS.index(' static void success()')].replace('check(done.await(5,TimeUnit.SECONDS),"ordered callback did not finish");','boolean finished=done.await(5,TimeUnit.SECONDS);check(RouterNodeChainSOCKS.latest==null||RouterNodeChainSOCKS.latest.factories==1,"typed factory was bypassed");check(finished||RouterNodeChainSOCKS.latest.bound,"typed native construction was not bound");check(finished,"ordered callback did not finish");').replace('public final class OrderedRuntimeTest','public final class TypedSOCKSHostTest').replace('RouterNodeChain.configured=null','RouterNodeChainSOCKS.configured=null').replace('value.capture.plan.failCloses=0;','value.capture.socks.plan.failClose=false;value.capture.socks.plan.missingReceipt=false;')+r'''
 static void success()throws Exception{for(String prefix:List.of("wg","awg2-fast","awg2-strong"))try(Fixture f=new Fixture(3,prefix,"shadowsocks")){
  f.connected();AndroidNodeChainSession owner=f.owner();RouterNodeChainSOCKS plan=owner.capture.socks.plan;CommandServer server=(CommandServer)get(f.service,"commandServer");
  check(plan.factories==1&&plan.binds==1&&plan.runs==1&&plan.server==server&&server.typed,"typed source did not own factory, bind and proof");
  check(owner.capture.plan==null&&plan.hopCalls==1&&plan.mtuCalls==1&&plan.mtuPlatform instanceof AndroidNodeChainMTUPlatform,"typed measurement or MTU borrowed generic native authority");
  check(Files.readString(owner.directory.toPath().resolve(AndroidNodeChainCapture.SESSION_FILE)).equals(plan.source()),"typed private source was replaced by generic launch");
  check(AndroidHomeStateStore.snapshot(f.service).activeChain.contains("socks5"),"Home lost original imported transport");
  var restored=f.runtime.captureRestore();f.stop();check(plan.nativeClosed()&&owner.released(),"typed Disconnected preceded original native receipt");
  Result r=new Result();f.runtime.restore(restored,AndroidHomeStateStore.snapshot(f.service),r);r.finished();check(r.ok&&f.runtime.restoredMatches(restored),"typed complete source did not restore with fresh proof");
  check(f.owner().capture.socks.plan!=plan&&f.owner().source==owner.source&&f.owner().capture.socks.plan.runs==1,"typed restore substituted source or reused native owner");f.stop();
 }}
 static void fault(String fault)throws Exception{try(Fixture f=new Fixture(3)){
  RouterNodeChainSOCKS.configured=p->{if(fault.equals("stale-proof"))p.afterRun=()->f.source.valid=false;if(fault.equals("binding"))p.failBind=true;if(fault.equals("factory"))p.failFactory=true;if(fault.equals("retired-factory"))p.afterFactory=()->f.source.valid=false;};
  Result result=f.connect();check(!result.ok&&!f.runtime.isConnected(),"typed stale or unproved native owner reached Connected: "+fault);RouterNodeChainSOCKS plan=RouterNodeChainSOCKS.latest;
  if(fault.equals("retired-factory"))check(plan.server.startedConfig.isEmpty(),"retired factory reached native Start");
  check(plan.closes>0&&(fault.equals("factory")?plan.server==null:plan.nativeClosed()),"typed failed startup lost original native cleanup: "+fault);
  check(AndroidNodeChainSession.retained()==null,"typed failed startup retained released source: "+fault);
 }}
 static void receipt()throws Exception{try(Fixture f=new Fixture(3)){
  f.connected();AndroidNodeChainSession owner=f.owner();RouterNodeChainSOCKS plan=owner.capture.socks.plan;plan.missingReceipt=true;
  check(!f.runtime.stopAndProve()&&!owner.released()&&owner.directory.exists(),"typed missing receipt published DOWN or discarded private owner");
  plan.missingReceipt=false;f.stop();check(owner.released(),"typed receipt retry lost original cleanup owner");
 }}
 static void pending()throws Exception{try(Fixture f=new Fixture(3)){
  f.connected();AndroidNodeChainSession owner=f.owner();RouterNodeChainSOCKS plan=owner.capture.socks.plan;plan.failClose=true;
  check(!f.runtime.stopAndProve()&&!owner.released()&&owner.directory.exists(),"typed shared drain failure discarded original owner");check(plan.closes>0,"typed shared drain was skipped");check(!plan.server.closed,"typed shared drain failure closed original Box before joining");plan.failClose=false;f.stop();
 }}
 public static void main(String[] args)throws Exception{
  String selected=args.length==0?"all":args[0];
  for(String family:List.of("success","pending","receipt","binding","factory","retired-factory","stale-proof"))if(selected.equals("all")||selected.equals(family)){
   if(family.equals("success"))success();else if(family.equals("pending"))pending();else if(family.equals("receipt"))receipt();else fault(family);
   System.out.println("Android typed SOCKS host case passed: "+family);
  }
  System.out.println("Android typed SOCKS host: "+checks+" executable ownership checks passed; OS/native boundaries doubled.");
 }
}'''

def main():
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    with tempfile.TemporaryDirectory(prefix='routervpn-typed-socks-host-') as directory:
        work=Path(directory);src=work/'src';classes=work/'classes'
        for name,text in SOURCES.items():
            target=src/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
        names=('AndroidHomeStateStore','AndroidConnectionSelection','AndroidNodeChainSOCKSCapture','AndroidNodeChainSession','AndroidNodeChainMTUPlatform','AndroidNodeChainRuntime','LayeredVpnService')
        originals={name:(JAVA/(name+'.java')).read_text() for name in names}
        for name,text in originals.items():(src/APP/(name+'.java')).write_text(text)
        (src/APP/'TypedSOCKSHostTest.java').write_text(HARNESS)
        subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(classes),*map(str,src.rglob('*.java'))],check=True,timeout=60)
        run=['java','-cp',os.pathsep.join((str(classes),str(jar))),'com.eabusham.routervpn.TypedSOCKSHostTest']
        subprocess.run(run,check=True,timeout=120)
        controls=(
            ('LayeredVpnService','commandServer = preparedChain==null?new CommandServer(this, this):preparedChain.newCommandServer(this,this);','commandServer = new CommandServer(this,this);','success','typed factory was bypassed'),
            ('LayeredVpnService','if (preparedChain != null) preparedChain.bindNative(commandServer);','','success','typed native construction was not bound'),
            ('LayeredVpnService','chain.execution != null || chain.typedNative()','chain.execution != null','pending','typed shared drain failure closed original Box before joining'),
            ('AndroidNodeChainSession','if(capture.socks!=null&&(server==null?owner!=null||!proofClosed:!capture.socks.plan.nativeClosed()))','if(false)','receipt','typed missing receipt published DOWN'),
            ('AndroidNodeChainSession','nativeBound = true;\n        requireSource();','nativeBound = true;','retired-factory','retired factory reached native Start'),
            ('AndroidNodeChainSession','capture.socks!=null?Libbox.routerNodeChainSOCKSNewMTU(capture.socks.plan,server,new AndroidNodeChainMTUPlatform(this,server,owner,platform))','capture.socks!=null?Libbox.routerNodeChainNewMTU(capture.plan,server,platform)','success','typed measurement or MTU borrowed generic native authority'),
        )
        for i,(name,old,new,family,witness) in enumerate(controls):
            assert originals[name].count(old)==1,(name,old)
            target=work/f'mutant-{i}'/(name+'.java');target.parent.mkdir();target.write_text(originals[name].replace(old,new))
            out=work/f'negative-{i}';shutil.copytree(classes,out);cp=os.pathsep.join((str(out),str(jar)))
            subprocess.run(['javac','--release','17','-proc:none','-cp',cp,'-d',str(out),str(target)],check=True,timeout=60)
            result=subprocess.run(['java','-cp',cp,'com.eabusham.routervpn.TypedSOCKSHostTest',family],text=True,capture_output=True,timeout=60)
            assert result.returncode!=0 and witness in result.stderr,(family,result.stdout,result.stderr)
            print('Android typed SOCKS host causal control rejected: '+str(i)+'/'+family)
        print('Android typed SOCKS host: all 7 case families and 6 compiled controls passed')
if __name__=='__main__':main()
