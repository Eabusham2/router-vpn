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
import tempfile
import test_android_node_candidates as candidates

chain = candidates.chain
profiles = candidates.profiles


def verify_typed_factory_abi():
    """Run the shipping shell guard with explicit javap-text boundary inputs.

    This proves guard rejection, not that a generated AAR exists locally. The
    AAR verifier invokes this exact function on its actual javap output.
    """
    source=(candidates.ROOT/'android/build-sing-box-libbox.sh').read_text()
    start=source.index('require_typed_candidate_prefix_api() {')
    end=source.index('\n}\n',start)+3
    body=source[start:end]
    call='  require_typed_candidate_prefix_api "$api_list" || return 1'
    assert source.count(call)==1
    assert source.index('javap -classpath "$classes" io.nekohasekai.libbox.Libbox >"$api_list"')<source.index(call)
    signatures=[f'io.nekohasekai.libbox.RouterNodeChainCandidatePreparation newRouterNodeChain{family}CandidatePreparation(java.lang.String, int, java.lang.String) throws java.lang.Exception;' for family in ('SOCKS','CONNECT')]
    with tempfile.TemporaryDirectory(prefix='routervpn-typed-prefix-abi-') as directory:
        path=Path(directory)/'api.txt'
        cases=[('complete',signatures,True)]
        for index,signature in enumerate(signatures):
            for label,replacement in (('missing',''),('wrong-position',signature.replace(', int,',', long,')),('wrong-owner',signature.replace('RouterNodeChainCandidatePreparation ','RouterNodeChain ')),('no-error',signature.replace(' throws java.lang.Exception',''))):
                changed=list(signatures);changed[index]=replacement;cases.append((f'{index}-{label}',changed,False))
        for label,lines,accepted in cases:
            path.write_text('\n'.join(lines)+'\n')
            result=subprocess.run(['bash','-c',body+'\nrequire_typed_candidate_prefix_api "$1"','prefix-abi',str(path)],text=True,capture_output=True,timeout=10)
            if (result.returncode==0)!=accepted or not accepted and 'missing typed packet-prefix API' not in result.stderr:
                raise AssertionError('Typed prefix ABI guard missed '+label+'\n'+result.stdout+result.stderr)
    print('Android typed prefix actual shell ABI guard: 9 boundary cases PASS',flush=True)


def compiler(source):
    source = candidates.compiler(source)
    before = 'case len(args)==2:'
    cases = r'''case len(args)==4&&args[0]=="prefix-new":var position int;_,err=fmt.Sscan(args[2],&position);if err==nil{var p *mobilemultihop.NodeChainCandidatePreparation;p,err=mobilemultihop.NewNodeChainCandidatePreparation(args[1],position,args[3]);if err==nil{var raw []byte;raw,err=json.Marshal(map[string]string{"launch":p.Source(),"config":p.Config(),"metadata":p.Metadata()});result=string(raw)}};case len(args)==2&&args[0]=="prefix-replay":var p *mobilemultihop.NodeChainCandidatePreparation;p,err=mobilemultihop.ParseNodeChainCandidatePreparationCapture(args[1]);if err==nil{var raw []byte;raw,err=json.Marshal(map[string]string{"launch":p.Source(),"config":p.Config(),"metadata":p.Metadata()});result=string(raw)};'''
    cases += r'''case len(args)==4&&(args[0]=="prefix-socks"||args[0]=="prefix-connect"):var position int;_,err=fmt.Sscan(args[2],&position);if err==nil{var p *mobilemultihop.NodeChainCandidatePreparation;if args[0]=="prefix-socks"{p,err=mobilemultihop.NewNodeChainSOCKSCandidatePreparation(args[1],position,args[3])}else{p,err=mobilemultihop.NewNodeChainCONNECTCandidatePreparation(args[1],position,args[3])};if err==nil{var raw []byte;raw,err=json.Marshal(map[string]string{"launch":p.Source(),"config":p.Config(),"metadata":p.Metadata()});result=string(raw)}};case len(args)==2&&args[0]=="prefix-generic-replay":_,err=mobilemultihop.ParseNodeChainCandidatePreparation(args[1]);'''
    envelope='var raw []byte;raw,err=json.Marshal(map[string]string{"launch":p.Source(),"config":p.Config(),"metadata":p.Metadata()});result=string(raw)'
    assert cases.count(envelope)==3
    cases=cases.replace(envelope,'var frames []string;frames,err=fixtureCandidateFrames(p);if err==nil{var raw []byte;raw,err=json.Marshal(map[string]any{"launch":p.Source(),"config":p.Config(),"metadata":frames[0],"frames":frames});result=string(raw)}')
    assert source.count(before) == 1
    return source.replace(before, cases+before)


NATIVE = r'''package io.nekohasekai.libbox;
import org.json.*;
public final class RouterNodeChainCandidatePreparation {
 public static String fault="";public static Runnable afterMetadata;public static int closed;
 private final JSONObject value,meta;
 RouterNodeChainCandidatePreparation(String raw)throws Exception{value=new JSONObject(raw);meta=new JSONObject(value.getString("metadata"));
  switch(fault){
   case "purpose":JSONObject purpose=new JSONObject(value.getString("launch"));purpose.put("kind","routervpn-node-chain-candidate-preparation");value.put("launch",purpose.toString());break;
   case "typed-original":JSONObject changed=new JSONObject(value.getString("launch"));changed.put("original_source",changed.getString("original_source")+" ");value.put("launch",changed.toString());break;
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
public String metadataPage(int offset)throws Exception{
  JSONArray frames=value.getJSONArray("frames");for(int i=1;i<frames.length();i++){String frame=frames.getString(i);if(new JSONObject(frame).getInt("target_offset")==offset)return frame;}return "";
 } public String metadata(){Runnable hook=afterMetadata;afterMetadata=null;if(hook!=null)hook.run();return meta.toString();}
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
 static NodeChainCaptureHarness.Fixture typedFixture(Path root,String wire,int count)throws Exception{
  String key=count==3?"2/":count==4?"3/mixed-awg":"7/mixed-awg";
  var fixture=new NodeChainCaptureHarness.Fixture(root,(wire.equals("socks5")?"":"connect/")+key);
  var custom=new AndroidStandardExitStore.Entry();custom.id="1234567890abcdef1234567890abcdef";custom.name="Original typed suffix";
  custom.protocol=wire;custom.server="198.51.100.76";custom.serverPort=8443;custom.expectedPublicIp="203.0.113.76";
  custom.username="original-typed-prefix-user";custom.password="original-typed-prefix-private-password";custom.tlsServerName="original.proxy.example";
  custom.policy.put("start_layer","off").put("dns_mode","rescue").put("home_lan_access",false).put("kill_switch_policy","always");
  var exits=new AndroidStandardExitStore(fixture.context);exits.save(custom);
  var editor=new AndroidOrderedPathSelection(fixture.nodes,fixture.profiles);editor.addPrefix(custom.id,AndroidExternalPolicy.protocol(wire));editor.save();
  var row=fixture.profiles.add("Original complete "+wire+" path");
  check(!Files.readString(fixture.rows).contains(custom.password),"typed prefix profile duplicated imported credentials");
  fixture.profiles.load(row.id);
  check(fixture.profiles.currentOrderedPath().members.size()==count,"typed prefix Load truncated the complete saved path");
  return fixture;
 }
 static void typedPrefixes(Path root,String wire)throws Exception{
  for(int count:new int[]{3,4,8}){
   var fixture=typedFixture(root,wire,count);var before=new NodeChainCaptureHarness.State(fixture);
   try(var original=AndroidNodeChainCapture.compile(fixture.profiles.currentOrderedPath())){
    int middle=count-2;String inventory=inventory(original),family=wire.equals("socks5")?"socks":"connect";
    String complete=wire.equals("socks5")?original.socks.source:original.connect.source;
    String kind="routervpn-node-chain-"+family+"-candidate-preparation";
    check(original.plan==null&&original.memberInputs.size()==count&&original.identityInputs.get(middle).isEmpty(),"typed prefix borrowed generic or paired middle identity");
    check(original.strict&&!original.homeLANAccess,"typed prefix dropped saved suffix protection");
    int[] positions=count==3?new int[]{0}:new int[]{0,middle-1};
    for(int position:positions){
     try(var capture=AndroidNodeCandidatePrefixCapture.compile(original,position,inventory)){
      check(Libbox.prefixFactory.equals(family),"typed prefix bypassed its exact factory: "+family);
      var source=new JSONObject(capture.launchInput);var meta=new JSONObject(capture.metadata);var graph=new JSONObject(capture.config);
      check(capture.original==original&&kind.equals(source.getString("kind"))&&complete.equals(source.getString("original_source")),"typed prefix replaced complete original source");
      check(capture.plan.originalSourceSHA256().equals(original.sourceSHA256)&&meta.getString("original_source_sha256").equals(original.sourceSHA256),"typed prefix borrowed paired-only provenance");
      check(meta.getJSONArray("prefixes").length()==position+1&&!meta.getBoolean("ready")&&!meta.getBoolean("dns_open")&&!meta.getBoolean("application_open"),"typed prefix claimed connected ingress");
      check(!capture.config.contains("198.51.100.76")&&!capture.config.contains("original-typed-prefix-private-password")&&!capture.config.contains("original.proxy.example"),"typed suffix entered candidate runtime");
      check(!capture.config.contains("routervpn-chain-"+(position+1)+"-"),"typed prefix retained an unselected member");
      check(ConnectionProfilesHarness.sameJSONValue(graph.getJSONArray("inbounds"),new JSONObject(original.config).getJSONArray("inbounds")),"typed prefix changed complete original TUN policy");
      try(var reopened=AndroidNodeCandidatePrefixCapture.reopen(capture.launchInput,original,position,inventory)){
       check(reopened.config.equals(capture.config)&&reopened.captureSHA256.equals(capture.captureSHA256),"typed prefix canonical replay changed its owner");
      }
      reject(()->Libbox.prefixGenericReplay(capture.launchInput),"generic replay accepted typed prefix purpose");
      reject(()->AndroidNodeCandidatePrefixCapture.reopen(" "+capture.launchInput,original,position,inventory),"typed prefix accepted noncanonical replay");
     }catch(Exception failure){throw new AssertionError("typed prefix source failed: "+wire+"/"+count,failure);}
    }
    reject(()->Libbox.newRouterNodeChainCandidatePreparation(complete,0,inventory),"generic factory accepted typed saved source");
    reject(()->AndroidNodeCandidatePrefixCapture.compile(original,middle,inventory),"typed imported member became packet prefix");
    reject(()->AndroidNodeCandidatePrefixCapture.compile(original,middle+1,inventory),"typed final became packet prefix");
   }
   before.same(fixture,"typed prefix capture leaves complete saved source unchanged");
  }
 }
 static void typedRefusals(Path root)throws Exception{
  for(String wire:List.of("socks5","http","https")){
   var fixture=typedFixture(root,wire,3);
   try(var original=AndroidNodeChainCapture.compile(fixture.profiles.currentOrderedPath())){
    String inventory=inventory(original);
    for(String fault:List.of("purpose","typed-original","original","application","dns","ready","proof","position","mtu","measured","numeric","config")){
     int closed=RouterNodeChainCandidatePreparation.closed;RouterNodeChainCandidatePreparation.fault=fault;
     try{reject(()->AndroidNodeCandidatePrefixCapture.compile(original,0,inventory),"foreign typed prefix capture admitted: "+fault);}
     finally{RouterNodeChainCandidatePreparation.fault="";}
     check(RouterNodeChainCandidatePreparation.closed==closed+1,"failed typed prefix capture abandoned its native source");
    }
    var exits=new AndroidStandardExitStore(fixture.context);var changed=exits.get("1234567890abcdef1234567890abcdef");changed.password="replaced-after-prefix-capture";exits.save(changed);
    reject(()->AndroidNodeCandidatePrefixCapture.compile(original,0,inventory),"stale typed original acquired a new prefix");
   }
   for(String requested:List.of("server","auto")){
    var selected=typedFixture(root,wire,3);selected.chooseExecution(requested);
    try(var original=AndroidNodeChainCapture.compile(selected.profiles.currentOrderedPath())){
     String inventory=inventory(original);reject(()->AndroidNodeCandidatePrefixCapture.compile(original,0,inventory),"typed prefix silently changed selected execution");
    }
   }
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
 public static void main(String[] args)throws Exception{Path root=Path.of(args[0]);String phase=args.length==1?"original":args[1];switch(phase){case "original" -> {positive(root);refusals(root);openVPNPrefixes(root);}case "capacity" -> NodeCandidateHarness.largeCatalog(root,(original,inventory,count)->{
  try(var prefix=AndroidNodeCandidatePrefixCapture.compile(original,0,inventory)){
   check(new JSONObject(prefix.metadata).getJSONArray("targets").length()==count,"temporary prefix truncated original catalog");
   check(new JSONObject(prefix.plan.metadata()).getInt("schema")==2,"temporary prefix sent an oversized legacy frame");
   try(var reopened=AndroidNodeCandidatePrefixCapture.reopen(prefix.launchInput,original,0,inventory)){
    check(reopened.metadata.equals(prefix.metadata)&&reopened.captureSHA256.equals(prefix.captureSHA256),"temporary prefix reopened another source or catalog");
   }
  }
 });case "imported-literal" -> importedSSPrefixes(root,false);case "imported-hostname" -> importedSSPrefixes(root,true);case "typed-socks" -> typedPrefixes(root,"socks5");case "typed-http" -> typedPrefixes(root,"http");case "typed-https" -> typedPrefixes(root,"https");case "typed-refusals" -> typedRefusals(root);default -> throw new IllegalArgumentException("Unknown required prefix capture phase");}System.out.println("Android prefix capture"+(phase.equals("original")?"":" "+phase)+": "+checks+" real compiler/source checks PASS");}
}'''


def prepare(src, app, java):
    candidates.prepare(src, app, java)
    for name in ('AndroidNodeCandidateMetadata','AndroidNodeCandidatePrefixCapture'):
        shutil.copyfile(java/(name+'.java'),app/(name+'.java'))
    (app/'NodeCandidatePrefixCaptureHarness.java').write_text(HARNESS)
    native=src/'io/nekohasekai/libbox'
    (native/'RouterNodeChainCandidatePreparation.java').write_text(NATIVE)
    libbox=native/'Libbox.java'
    source=libbox.read_text();assert source.endswith('}')
    source=source[:-1]+r'''
public static String prefixFactory="";
public static RouterNodeChainCandidatePreparation newRouterNodeChainCandidatePreparation(String source,int prefix,String inventory)throws Exception{prefixFactory="generic";return new RouterNodeChainCandidatePreparation(call("prefix-new",source,Integer.toString(prefix),inventory));}
public static RouterNodeChainCandidatePreparation newRouterNodeChainSOCKSCandidatePreparation(String source,int prefix,String inventory)throws Exception{prefixFactory="socks";return new RouterNodeChainCandidatePreparation(call("prefix-socks",source,Integer.toString(prefix),inventory));}
public static RouterNodeChainCandidatePreparation newRouterNodeChainCONNECTCandidatePreparation(String source,int prefix,String inventory)throws Exception{prefixFactory="connect";return new RouterNodeChainCandidatePreparation(call("prefix-connect",source,Integer.toString(prefix),inventory));}
public static void prefixGenericReplay(String input)throws Exception{call("prefix-generic-replay",input);}
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
    for phase in ('capacity','imported-literal','imported-hostname','typed-socks','typed-http','typed-https','typed-refusals'):
        subprocess.run(command+[phase],env=env,check=True,timeout=180)
    controls=(
        ('||!original.sourceSHA256.equals(plan.originalSourceSHA256())||!original.sourceSHA256.equals(meta.getString("original_source_sha256"))','', 'foreign prefix capture admitted: original'),
        ('||!Boolean.FALSE.equals(meta.get("application_open"))','', 'foreign prefix capture admitted: application'),
        ('||!member.getString("source_sha256").equals(proof.getString("source_sha256"))','', 'foreign prefix capture admitted: proof'),
        ('||integer(tun,"mtu")!=originalMTU','', 'foreign prefix capture admitted: mtu'),
        ('        original.requireCurrent();if(paged)AndroidNodeCandidateMetadata.requireBefore(observationDeadline);','        if(paged)AndroidNodeCandidateMetadata.requireBefore(observationDeadline);', 'late original source change admitted prefix capture'),
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
    typed_controls=(
        ('Libbox.newRouterNodeChainSOCKSCandidatePreparation(original.socks.source,prefix,inventory)', 'Libbox.newRouterNodeChainCandidatePreparation(original.socks.source,prefix,inventory)', 'typed-socks', 'typed prefix source failed: socks5/3'),
        ('Libbox.newRouterNodeChainCONNECTCandidatePreparation(original.connect.source,prefix,inventory)', 'Libbox.newRouterNodeChainCandidatePreparation(original.connect.source,prefix,inventory)', 'typed-http', 'typed prefix source failed: http/3'),
        ('!purposeKind(original).equals(source.getString("kind"))', 'false', 'typed-refusals', 'foreign typed prefix capture admitted: purpose'),
        ('||original.socks!=null&&!original.socks.source.equals(source.getString("original_source"))', '', 'typed-refusals', 'foreign typed prefix capture admitted: typed-original'),
    )
    for index,(before,after,phase,witness) in enumerate(typed_controls):
        assert original.count(before)==1,before
        private=work/('typed-prefix-control-'+str(index));private.mkdir();target=private/'classes';shutil.copytree(classes,target)
        source=private/'AndroidNodeCandidatePrefixCapture.java';source.write_text(original.replace(before,after))
        classpath=str(target)+os.pathsep+str(jar)
        subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',classpath,'-d',str(target),str(source)],check=True,timeout=60)
        data=private/'data';data.mkdir()
        result=subprocess.run(['java','-cp',classpath,'com.eabusham.routervpn.NodeCandidatePrefixCaptureHarness',str(data),phase],env=env,capture_output=True,text=True,timeout=180)
        if result.returncode==0 or witness not in result.stderr:raise AssertionError('Typed prefix capture control missed exact defect: '+witness+'\n'+result.stdout+result.stderr)
        print('Android typed prefix capture causal control:',witness,flush=True)


if __name__=='__main__':
    verify_typed_factory_abi()
    chain.compiler_source=compiler;chain.prepare_sources=prepare;chain.run=run
    sys.argv=[sys.argv[0],'--case-family','ordered-chain'];profiles.main()
