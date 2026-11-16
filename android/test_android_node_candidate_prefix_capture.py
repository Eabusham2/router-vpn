#!/usr/bin/env python3
"""Execute Android prefix captures against the real shared source compiler.

Only the Java/native transport is a double. This source gate starts no VPN and
does not claim Android TUN, encrypted packet transport or host acceptance.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import test_android_node_candidates as candidates

chain = candidates.chain
profiles = candidates.profiles


def compiler(source):
    source = candidates.compiler(source)
    before = 'case len(args)==2:'
    cases = r'''case len(args)==4&&args[0]=="prefix-new":var position int;_,err=fmt.Sscan(args[2],&position);if err==nil{var p *mobilemultihop.NodeChainCandidatePreparation;p,err=mobilemultihop.NewNodeChainCandidatePreparation(args[1],position,args[3]);if err==nil{var raw []byte;raw,err=json.Marshal(map[string]string{"launch":p.Source(),"config":p.Config(),"metadata":p.Metadata()});result=string(raw)}};case len(args)==2&&args[0]=="prefix-replay":var p *mobilemultihop.NodeChainCandidatePreparation;p,err=mobilemultihop.ParseNodeChainCandidatePreparation(args[1]);if err==nil{var raw []byte;raw,err=json.Marshal(map[string]string{"launch":p.Source(),"config":p.Config(),"metadata":p.Metadata()});result=string(raw)};'''
    assert source.count(before) == 1
    return source.replace(before, cases+before)


NATIVE = r'''package io.nekohasekai.libbox;
import org.json.*;
public final class RouterNodeChainCandidatePreparation {
 public static String fault="";public static Runnable afterMetadata;public static int closed;
 private final JSONObject value,meta;
 RouterNodeChainCandidatePreparation(String raw)throws Exception{value=new JSONObject(raw);meta=new JSONObject(value.getString("metadata"));
  switch(fault){
   case "original":meta.put("original_source_sha256","f".repeat(64));break;
   case "application":meta.put("application_open",true);break;
   case "dns":meta.put("dns_open",true);break;
   case "ready":meta.put("ready",true);break;
   case "proof":meta.getJSONArray("prefixes").getJSONObject(0).put("source_sha256","f".repeat(64));break;
   case "position":meta.getJSONArray("prefixes").getJSONObject(0).put("position",1);break;
   case "mtu":JSONObject graph=new JSONObject(value.getString("config"));JSONObject tun=graph.getJSONArray("inbounds").getJSONObject(0);tun.put("mtu",tun.getInt("mtu")+1);value.put("config",graph.toString());meta.put("config_sha256",digest(graph.toString()));break;
   case "measured":meta.put("mtu_measurement","measured");break;
   case "numeric":meta.getJSONObject("mtu").put("original","1280");break;
   case "config":value.put("config",value.getString("config")+" ");break;
  }
 }
 public String launchInput()throws Exception{return value.getString("launch");}
 public String config()throws Exception{return value.getString("config");}
 public String metadata(){Runnable hook=afterMetadata;afterMetadata=null;if(hook!=null)hook.run();return meta.toString();}
 public String sourceSHA256()throws Exception{return meta.getString("source_sha256");}
 public String configSHA256()throws Exception{return meta.getString("config_sha256");}
 public String originalSourceSHA256()throws Exception{return meta.getString("original_source_sha256");}
 public String captureSHA256()throws Exception{return meta.getString("capture_sha256");}
 public void start(String request,String candidate)throws Exception{throw new IllegalStateException("Pure source fixture cannot start native candidate work");}
 public void cancel(String request){}public void drain(String request)throws Exception{throw new IllegalStateException("Pure source fixture has no native candidate work");}public String statusJSON(){return "{}";}
 public void close(){closed++;}
 private static String digest(String raw)throws Exception{byte[] digest=java.security.MessageDigest.getInstance("SHA-256").digest(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8));StringBuilder value=new StringBuilder();for(byte b:digest)value.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return value.toString();}
}'''

HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;import java.util.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;import io.nekohasekai.libbox.*;
public final class NodeCandidatePrefixCaptureHarness {
 static int checks;static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
 interface Work{void run()throws Exception;}static void reject(Work work,String message)throws Exception{try{work.run();}catch(Exception expected){checks++;return;}throw new AssertionError(message);}
 static String inventory(AndroidNodeChainCapture capture)throws Exception{return new JSONObject().put("schema",1).put("revision","exact-original-source-fixture").put("inputs",new JSONArray().put(capture.memberInputs.get(capture.memberInputs.size()-1))).toString();}
 static void positive(Path root)throws Exception{
  for(String key:List.of("2/","2/awg-fast","3/awg-strong","4/mixed-awg")){
   var fixture=new NodeChainCaptureHarness.Fixture(root,key);var original=AndroidNodeChainCapture.compile(fixture.profiles.currentOrderedPath());
   var before=new NodeChainCaptureHarness.State(fixture);int position=original.memberInputs.size()-2;String inventory=inventory(original);
   try(var capture=AndroidNodeCandidatePrefixCapture.compile(original,position,inventory)){
    check(capture.original==original&&capture.prefix==position,"prefix capture replaced its original source owner");
    check(!capture.sourceSHA256.equals(original.sourceSHA256)&&capture.plan.originalSourceSHA256().equals(original.sourceSHA256),"prefix capture lost separate source identity");
    JSONObject metadata=new JSONObject(capture.metadata);check(metadata.getJSONArray("prefixes").length()==position+1&&!metadata.getBoolean("ready")&&!metadata.getBoolean("dns_open")&&!metadata.getBoolean("application_open"),"source capture claimed connected traffic authority");
    check(capture.originalMTU>=1280&&capture.ceilingMTU>=capture.originalMTU,"configured prefix MTU bounds are invalid");
    check(!capture.config.contains("routervpn-chain-"+(position+1)+"-"),"prefix graph contacted the saved final");
    try(var replay=AndroidNodeCandidatePrefixCapture.reopen(capture.launchInput,original,position,inventory)){
     check(replay.config.equals(capture.config)&&replay.sourceSHA256.equals(capture.sourceSHA256)&&replay.captureSHA256.equals(capture.captureSHA256),"strict prefix replay changed original graph");
    }
    reject(()->AndroidNodeCandidatePrefixCapture.reopen(" "+capture.launchInput,original,position,inventory),"noncanonical prefix launch was adopted");
    JSONObject foreign=new JSONObject(capture.launchInput).put("config",capture.config);
    reject(()->AndroidNodeCandidatePrefixCapture.reopen(foreign.toString(),original,position,inventory),"unchecked supplied graph was adopted");
   }
   reject(()->AndroidNodeCandidatePrefixCapture.compile(original,-1,inventory),"negative prefix admitted");
   reject(()->AndroidNodeCandidatePrefixCapture.compile(original,original.memberInputs.size()-1,inventory),"saved final became prefix-only preparation");
   before.same(fixture,"pure prefix capture");
   try(var restored=AndroidNodeChainCapture.reopen(original.launchInput,fixture.profiles.currentOrderedPath());var prefix=AndroidNodeCandidatePrefixCapture.compile(restored,position,inventory)){
    check(prefix.plan.originalSourceSHA256().equals(original.sourceSHA256),"strict original replay lost its plain constructor source");
   }
   original.close();
  }
 }
 static void openVPNPrefixes(Path root)throws Exception{
  for(String key:List.of("2/","2/awg-fast","2/awg-strong","3/","7/"))for(String network:List.of("tcp","udp")){
   var fixture=new NodeChainCaptureHarness.Fixture(root,key);var exits=new AndroidStandardExitStore(fixture.context);
   var custom=new AndroidStandardExitStore.Entry();custom.id="1234567890abcdef1234567890abcdef";custom.name="Saved prefix OpenVPN";custom.protocol="openvpn";
   custom.server="203.0.113.20";custom.serverPort=1194;custom.expectedPublicIp="203.0.113.88";custom.username=" exact prefix user ";custom.password=" exact prefix secret ";
   custom.openVPNConfig="client\ndev tun\nproto "+network+"\nremote 203.0.113.20 1194\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint "+"ab".repeat(32)+"\ntun-mtu 1400\ndata-ciphers AES-256-GCM:AES-128-GCM\n";
   custom.policy.put("dns_mode","rescue").put("start_layer","off").put("home_lan_access",false).put("kill_switch_policy","always");AndroidNodeStore.ChainSource.requireImported(custom);exits.save(custom);
   var editor=new AndroidOrderedPathSelection(fixture.nodes,fixture.profiles);editor.addPrefix(custom.id,"openvpn");editor.save();
   try(var original=AndroidNodeChainCapture.compile(fixture.profiles.currentOrderedPath())){
    int lastPrefix=original.memberInputs.size()-3;String inventory=inventory(original);var before=new NodeChainCaptureHarness.State(fixture);
    for(int position=0;position<=lastPrefix;position++){
     try(var capture=AndroidNodeCandidatePrefixCapture.compile(original,position,inventory)){
      var meta=new JSONObject(capture.metadata);
      check(capture.original==original&&capture.plan.originalSourceSHA256().equals(original.sourceSHA256),"OpenVPN prefix lost original complete saved owner");
      check(meta.getJSONArray("prefixes").length()==position+1&&!meta.getBoolean("ready")&&!meta.getBoolean("dns_open")&&!meta.getBoolean("application_open"),"OpenVPN prefix source claimed connected ingress");
      check(!capture.config.contains("openvpn-client")&&!capture.config.contains("203.0.113.20")&&!capture.config.contains(" exact prefix secret "),"OpenVPN suffix entered executable candidate preparation");
      check(!capture.config.contains("routervpn-chain-"+(position+1)+"-"),"OpenVPN candidate preparation retained an unselected member");
      try(var reopened=AndroidNodeCandidatePrefixCapture.reopen(capture.launchInput,original,position,inventory)){
       check(reopened.config.equals(capture.config)&&reopened.captureSHA256.equals(capture.captureSHA256),"OpenVPN saved prefix replay changed original source");
      }
     }
    }
    reject(()->AndroidNodeCandidatePrefixCapture.compile(original,lastPrefix+1,inventory),"OpenVPN middle became a packet candidate prefix");
    reject(()->AndroidNodeCandidatePrefixCapture.compile(original,lastPrefix+2,inventory),"OpenVPN final became a packet candidate prefix");
    before.same(fixture,"OpenVPN prefix capture leaves saved source unchanged");
   }
  }
 }
 static void importedSSPrefixes(Path root,boolean hostname)throws Exception{
  for(String key:List.of("2/","2/awg-fast","2/awg-strong","3/","7/")){
   var fixture=new NodeChainCaptureHarness.Fixture(root,key);var exits=new AndroidStandardExitStore(fixture.context);
   String method=key.equals("7/")?"2022-blake3-chacha20-poly1305":key.equals("3/")?"2022-blake3-aes-256-gcm":"2022-blake3-aes-128-gcm";
   var custom=NodeChainCaptureHarness.hostnameEntry(method);if(!hostname)custom.server="203.0.113.24";
   AndroidNodeStore.ChainSource.requireImported(custom);exits.save(custom);
   var editor=new AndroidOrderedPathSelection(fixture.nodes,fixture.profiles);editor.addPrefix(custom.id,"shadowsocks");editor.save();
   var before=new NodeChainCaptureHarness.State(fixture);String saved=AndroidStandardExitStore.snapshot(exits.get(custom.id));
   try(var original=AndroidNodeChainCapture.compile(fixture.profiles.currentOrderedPath())){
    int middle=original.memberInputs.size()-2;String inventory=inventory(original);
    check(new JSONObject(original.sourceInput).getInt("schema")==2,"imported prefix lost exact source family");
    JSONObject transport=null;JSONArray outbounds=new JSONObject(original.config).getJSONArray("outbounds");
    for(int i=0;i<outbounds.length();i++){JSONObject row=outbounds.getJSONObject(i);if(custom.server.equals(row.optString("server"))&&"shadowsocks".equals(row.optString("type"))){check(transport==null,"imported prefix found duplicate saved transport");transport=row;}}
    check(transport!=null,"original imported transport disappeared before preparation");
    String resolver=hostname?transport.getJSONObject("domain_resolver").getString("server"):"";
    if(hostname)check(!resolver.isEmpty(),"original imported resolver owner is absent");
    for(int position=0;position<middle;position++){
     try(var capture=AndroidNodeCandidatePrefixCapture.compile(original,position,inventory)){
      var meta=new JSONObject(capture.metadata);
      check(capture.original==original&&capture.plan.originalSourceSHA256().equals(original.sourceSHA256),"imported prefix lost original complete saved owner");
      check(meta.getJSONArray("prefixes").length()==position+1&&!meta.getBoolean("ready")&&!meta.getBoolean("dns_open")&&!meta.getBoolean("application_open"),"imported prefix source claimed connected ingress");
      check(!capture.config.contains(custom.server)&&!capture.config.contains(custom.secret),"imported suffix credentials entered candidate runtime");
      if(hostname)check(!capture.config.contains(resolver),"imported resolver owner entered candidate runtime");
      check(!capture.config.contains("routervpn-chain-"+(position+1)+"-"),"imported prefix retained an unselected member");
      try(var reopened=AndroidNodeCandidatePrefixCapture.reopen(capture.launchInput,original,position,inventory)){
       check(reopened.config.equals(capture.config)&&reopened.captureSHA256.equals(capture.captureSHA256),"imported saved prefix replay changed original source");
      }
     }
    }
    reject(()->AndroidNodeCandidatePrefixCapture.compile(original,middle,inventory),"imported SS middle became a packet candidate prefix");
    reject(()->AndroidNodeCandidatePrefixCapture.compile(original,middle+1,inventory),"imported SS final became a packet candidate prefix");
   }
   check(saved.equals(AndroidStandardExitStore.snapshot(exits.get(custom.id))),"prefix preparation rewrote the saved imported source");
   before.same(fixture,"imported prefix capture leaves saved source unchanged");
  }
 }
 static void refusals(Path root)throws Exception{
  for(String fault:List.of("original","application","dns","ready","proof","position","mtu","measured","numeric","config")){
   var fixture=new NodeChainCaptureHarness.Fixture(root,"2/");try(var original=AndroidNodeChainCapture.compile(fixture.profiles.currentOrderedPath())){
    String inventory=inventory(original);int before=RouterNodeChainCandidatePreparation.closed;RouterNodeChainCandidatePreparation.fault=fault;
    try{reject(()->AndroidNodeCandidatePrefixCapture.compile(original,0,inventory),"foreign prefix capture admitted: "+fault);}
    finally{RouterNodeChainCandidatePreparation.fault="";}
    check(RouterNodeChainCandidatePreparation.closed==before+1,"failed prefix capture abandoned its created native source");
   }
  }
  var fixture=new NodeChainCaptureHarness.Fixture(root,"2/");try(var original=AndroidNodeChainCapture.compile(fixture.profiles.currentOrderedPath())){
   String inventory=inventory(original);Path path=fixture.control().file.toPath();byte[] old=Files.readAllBytes(path);
   RouterNodeChainCandidatePreparation.afterMetadata=()->{try{Files.writeString(path,new String(old,StandardCharsets.UTF_8)+" ");}catch(Exception e){throw new RuntimeException(e);}};
   try{reject(()->AndroidNodeCandidatePrefixCapture.compile(original,0,inventory),"late original source change admitted prefix capture");}
   finally{RouterNodeChainCandidatePreparation.afterMetadata=null;Files.write(path,old);}
  }
 }
 public static void main(String[] args)throws Exception{Path root=Path.of(args[0]);String phase=args.length==1?"original":args[1];switch(phase){case "original" -> {positive(root);refusals(root);openVPNPrefixes(root);}case "imported-literal" -> importedSSPrefixes(root,false);case "imported-hostname" -> importedSSPrefixes(root,true);default -> throw new IllegalArgumentException("Unknown required prefix capture phase");}System.out.println("Android prefix capture"+(phase.equals("original")?"":" "+phase)+": "+checks+" real compiler/source checks PASS");}
}'''


def prepare(src, app, java):
    candidates.prepare(src, app, java)
    shutil.copyfile(java/'AndroidNodeCandidatePrefixCapture.java', app/'AndroidNodeCandidatePrefixCapture.java')
    (app/'NodeCandidatePrefixCaptureHarness.java').write_text(HARNESS)
    native=src/'io/nekohasekai/libbox'
    (native/'RouterNodeChainCandidatePreparation.java').write_text(NATIVE)
    libbox=native/'Libbox.java'
    source=libbox.read_text();assert source.endswith('}')
    source=source[:-1]+r'''
public static RouterNodeChainCandidatePreparation newRouterNodeChainCandidatePreparation(String source,int prefix,String inventory)throws Exception{return new RouterNodeChainCandidatePreparation(call("prefix-new",source,Integer.toString(prefix),inventory));}
public static RouterNodeChainCandidatePreparation routerNodeChainCandidatePreparationLaunch(String input)throws Exception{return new RouterNodeChainCandidatePreparation(call("prefix-replay",input));}
}'''
    libbox.write_text(source)


def run(root,work,app,classes,jar,env,imported_only=False):
    env=candidates.generate_fixture(root,work,env)
    data=work/'prefix-data';data.mkdir()
    command=['java','-cp',str(classes)+os.pathsep+str(jar),'com.eabusham.routervpn.NodeCandidatePrefixCaptureHarness',str(data)]
    subprocess.run(command,env=env,check=True,timeout=180)
    # Each additive saved-SS form keeps the original finite caller bound. The
    # original positive/refusal matrix and all five causal controls still run.
    for phase in ('imported-literal','imported-hostname'):
        subprocess.run(command+[phase],env=env,check=True,timeout=180)
    controls=(
        ('||!original.sourceSHA256.equals(plan.originalSourceSHA256())||!original.sourceSHA256.equals(meta.getString("original_source_sha256"))','', 'foreign prefix capture admitted: original'),
        ('||!Boolean.FALSE.equals(meta.get("application_open"))','', 'foreign prefix capture admitted: application'),
        ('||!member.getString("source_sha256").equals(proof.getString("source_sha256"))','', 'foreign prefix capture admitted: proof'),
        ('||integer(tun,"mtu")!=originalMTU','', 'foreign prefix capture admitted: mtu'),
        ('        original.requireCurrent();\n    }','    }', 'late original source change admitted prefix capture'),
    )
    original=(app/'AndroidNodeCandidatePrefixCapture.java').read_text()
    for index,(before,after,witness) in enumerate(controls):
        assert original.count(before)==1,before
        private=work/('prefix-control-'+str(index));private.mkdir();target=private/'classes';shutil.copytree(classes,target)
        source=private/'AndroidNodeCandidatePrefixCapture.java';source.write_text(original.replace(before,after))
        classpath=str(target)+os.pathsep+str(jar)
        subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',classpath,'-d',str(target),str(source)],check=True,timeout=60)
        data=private/'data';data.mkdir()
        result=subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeCandidatePrefixCaptureHarness',str(data)],env=env,capture_output=True,text=True,timeout=180)
        if result.returncode==0 or witness not in result.stderr:raise AssertionError('Prefix capture control missed exact defect: '+witness+'\n'+result.stdout+result.stderr)
        print('Android prefix capture causal control:',witness,flush=True)


if __name__=='__main__':
    chain.compiler_source=compiler;chain.prepare_sources=prepare;chain.run=run
    sys.argv=[sys.argv[0],'--case-family','ordered-chain'];profiles.main()
