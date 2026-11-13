#!/usr/bin/env python3
"""Execute the shipping imported-entry capture, store binding and staging.

Android handles/filesystem APIs and the Libbox Java ABI are boundary doubles.
Every constructor calls the real shared Go compiler. Native CheckConfig and
encrypted peer traffic are separate mandatory gates, which consume these exact
Android-produced original source arrays when an export directory is supplied.
"""
from pathlib import Path
import argparse
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
spec = importlib.util.spec_from_file_location("imported_external_capture", ROOT / "android/test_android_external_policy.py")
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)


def block(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


GO_CASE = r'''case "proxy-entry":
 out,err=mobilemultihop.CompileProxyEntry(args[1],args[2])
 case "chain-imported":
 out,err=mobilemultihop.NodeChainImportedMemberInput(args[1],args[2])
 case "ss-service":
 err=mobilemultihop.ValidateCapturedSSService(args[1],args[2]);if err==nil{out="true"}
 case "imported-router":
 if len(args)!=8 { panic("missing original sources") }
 var c *mobilemultihop.Controller
 c,err=mobilemultihop.NewImportedEntry(args[1],args[2],args[3],args[4],args[5],args[6],args[7])
 if err==nil { var raw []byte;raw,err=json.Marshal(map[string]string{"config":c.Config(),"metadata":c.Metadata(),"mtu":c.MTUProfile(),"source":c.SourceSHA256()});out=string(raw);if closed:=c.Close();err==nil{err=closed} }
'''
OWNER = r'''package io.nekohasekai.libbox;
public final class RouterMultihop {
 private final org.json.JSONObject data;public static int open;public static String capabilityOverride;
 private boolean closed;
 RouterMultihop(String raw)throws Exception{data=new org.json.JSONObject(raw);open++;}
 public String config()throws Exception{return data.getString("config");}
 public String metadata()throws Exception{return capabilityOverride==null?data.getString("metadata"):new org.json.JSONObject(data.getString("metadata")).put("transport_capability",capabilityOverride).toString();}
 public String mtuProfile()throws Exception{return data.getString("mtu");}
 public String sourceSHA256()throws Exception{return data.getString("source");}
 public void close(){if(!closed){closed=true;open--;}}
}'''

HARNESS = r'''package com.eabusham.routervpn;
import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.util.*;import org.json.*;import io.nekohasekai.libbox.*;
public final class ImportedRouterTest {
 static int checks;static void check(boolean ok,String reason){checks++;if(!ok)throw new AssertionError(reason);}
 static String exportEnvironment="ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES";
 interface Work{void run()throws Exception;}
 static void reject(String label,Work work)throws Exception{boolean refused=false;try{work.run();}catch(Exception expected){refused=true;}check(refused,"accepted "+label);check(RouterMultihop.open==0,"owner leaked after "+label);}
 static JSONObject object(String s)throws Exception{return new JSONObject(s);}
 static void importedMemberBoundary()throws Exception{
  AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id="original-middle";e.name="Imported hostname";e.protocol="shadowsocks";e.server="Middle.Example";e.serverPort=8388;e.expectedPublicIp="198.51.100.31";e.method="2022-blake3-aes-128-gcm";e.secret=Base64.getEncoder().encodeToString(new byte[16]);e.policy=new JSONObject().put("dns_mode","custom").put("dns_protocol","tcp").put("dns_host","192.0.2.53").put("dns_port",53).put("ipv6_mode","off").put("kill_switch",true);
  AndroidStandardExitStore.validate(e);AndroidExternalPolicy.validateDraft(e);AndroidExternalPolicy.Captured captured=AndroidExternalPolicy.captureImportedEntry(e);
  JSONObject member=object(Libbox.routerNodeChainImportedMemberInput(captured.source,captured.capture));check(member.getString("kind").equals("routervpn-node-chain-imported-member")&&member.getInt("schema")==1,"imported member boundary lost its actual shared constructor");check(member.getString("config").equals(captured.source)&&member.getString("capture").equals(captured.capture),"imported member boundary changed original source bytes");
  reject("malformed imported member source",()->Libbox.routerNodeChainImportedMemberInput("{}",captured.capture));reject("malformed imported member capture",()->Libbox.routerNodeChainImportedMemberInput(captured.source,"{}"));
 }
 static JSONObject outbound(JSONObject graph,String tag)throws Exception{JSONArray rows=graph.getJSONArray("outbounds");for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);if(tag.equals(row.optString("tag")))return row;}throw new AssertionError("missing captured outbound "+tag);}
 static AndroidStandardExitStore.Entry entry(JSONArray args)throws Exception{
  JSONObject capture=object(args.getString(1)),profile=capture.getJSONObject("profile"),external=profile.getJSONObject("external"),transport=external.getJSONObject(capture.getString("protocol").replace("-","_"));
  AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id=capture.getString("exit_id");e.name="Imported first";e.protocol=capture.getString("protocol");e.expectedPublicIp=capture.getString("expected_public_ip");
  if(List.of("wireguard","amneziawg").contains(e.protocol)){
   String endpoint=transport.getString("endpoint");int split=endpoint.lastIndexOf(':');e.server=endpoint.substring(0,split);if(e.server.startsWith("[")&&e.server.endsWith("]"))e.server=e.server.substring(1,e.server.length()-1);e.serverPort=Integer.parseInt(endpoint.substring(split+1));
   e.wgPrivateKey=transport.getString("private_key");e.wgPeerPublicKey=transport.getString("peer_public_key");e.wgPreSharedKey=transport.optString("preshared_key","");e.wgMtu=transport.optInt("mtu",0);
   if(transport.has("persistent_keepalive_interval"))e.wgKeepalive=transport.getInt("persistent_keepalive_interval");
   for(String key:List.of("addresses","allowed_ips","dns")){JSONArray values=transport.optJSONArray(key);List<String> into=key.equals("addresses")?e.wgAddresses:key.equals("allowed_ips")?e.wgAllowedIps:e.wgDns;for(int i=0;values!=null&&i<values.length();i++)into.add(values.getString(i));}
   if(e.protocol.equals("amneziawg"))e.awgParameters=object(transport.getJSONObject("parameters").toString());
  }else if(e.protocol.equals("openvpn")){e.openVPNConfig=transport.getString("config");e.username=transport.optString("username","");e.password=transport.optString("password","");e.openVPNPairing=external.optJSONObject("openvpn_pairing");e.openVPNResponseProbes=external.optJSONObject("openvpn_response_probes");e.openVPNStartLayers=external.optJSONObject("openvpn_start_layers");}
  else if(List.of("socks5","http-connect","https-connect").contains(e.protocol)){e.server=transport.getString("host");e.serverPort=transport.getInt("port");e.username=transport.getString("username");e.password=transport.getString("password");e.tlsServerName=transport.optString("tls_server_name","");}
  else{e.server=transport.getString("server");e.serverPort=transport.getInt("port");e.method=transport.optString("method","");e.secret=transport.getString("password");e.tlsServerName=transport.optString("tls_server_name","");}
  e.policy=object(profile.toString());for(String name:List.of("external","id","node_kind"))e.policy.remove(name);
  e.startLayer=external.optJSONObject("start_layer");AndroidStandardExitStore.validate(e);return e;
 }
 static JSONObject bundle(JSONArray args)throws Exception{
  JSONObject profile=object(args.getString(4));
  JSONObject files=new JSONObject().put(args.getString(2),object(args.getString(3)));
  if(!args.getString(5).isEmpty())files.put("shadowsocks",object(args.getString(5)));
  return new JSONObject().put("selectedRouterID",profile.getString("id")).put("routerProfiles",new JSONArray().put(profile)).put("profiles",files);
 }
 static JSONObject profile(JSONObject bundle)throws Exception{return bundle.getJSONArray("routerProfiles").getJSONObject(0);}
 static void export(String name,AndroidImportedRouterPath.Compiled c)throws Exception{
  String directory=System.getenv(exportEnvironment);if(directory==null||directory.isEmpty())return;
  JSONObject raw=object(c.input);JSONArray array=new JSONArray();
  for(String key:List.of("entry_config","entry_capture","exit_mode","exit_files","exit_profile","exit_start","dns_bootstrap"))array.put(raw.getString(key));
  array.put(c.source).put(c.config);Files.writeString(Path.of(directory).resolve("android-"+name),array.toString());
 }
 static void retainedStaging(Path root)throws Exception{
  String id="a".repeat(32);Path folder=Files.createDirectory(root.resolve(id));Path secret=Files.writeString(folder.resolve("captured-source.json"),"original private source");
  java.io.File held=new java.io.File(folder.toString()){
   @Override public java.io.File[] listFiles(){return new java.io.File[]{new java.io.File(secret.toString()){@Override public boolean delete(){return false;}}};}
  };
  Exception original=new Exception("controlled original preparation failure");AndroidImportedRouterPath.PreparationFailure retained=null;
  try{AndroidImportedRouterPath.cleanupFailedPreparation(held,original);}catch(AndroidImportedRouterPath.PreparationFailure failure){retained=failure;}
  check(retained!=null,"failed staging cleanup lost its retained session capability");
  check(retained.sessionId.equals(id)&&retained.getCause()==original,"partial preparation replaced its original session or failure");
  check(retained.getSuppressed().length==1&&retained.getSuppressed()[0] instanceof java.io.IOException,"partial preparation lost actual cleanup failure");
  check(Files.readString(secret).equals("original private source"),"failed cleanup did not retain actual original private bytes");
  AndroidImportedRouterPath.cleanupFailedPreparation(folder.toFile(),original);
  check(!Files.exists(folder),"original staging retry did not join exact retained directory");
  Path clean=Files.createDirectory(root.resolve("b".repeat(32)));AndroidImportedRouterPath.cleanupFailedPreparation(clean.toFile(),original);
  check(!Files.exists(clean),"successful staging cleanup invented pending ownership");
 }
 static boolean lockChecked;
 static void sourceDoesNotWaitForMutation(AndroidMultihopController.Source source)throws Exception{
  if(lockChecked)return;lockChecked=true;var field=AndroidStandardExitStore.class.getDeclaredField("STORE_LOCK");field.setAccessible(true);Object lock=field.get(null);
  var held=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);
  Thread writer=new Thread(()->{synchronized(lock){held.countDown();try{release.await();}catch(InterruptedException stop){Thread.currentThread().interrupt();}}});writer.start();
  var executor=java.util.concurrent.Executors.newSingleThreadExecutor();boolean completed=false;
  try{check(held.await(5,java.util.concurrent.TimeUnit.SECONDS),"writer did not own store mutation gate");var task=executor.submit(()->{source.require(null);return true;});completed=task.get(10,java.util.concurrent.TimeUnit.SECONDS);}
  catch(java.util.concurrent.TimeoutException blocked){completed=false;}
  finally{release.countDown();writer.join(5000);executor.shutdownNow();check(executor.awaitTermination(5,java.util.concurrent.TimeUnit.SECONDS),"source checker did not join");}
  check(completed,"source check deadlocked behind store mutation owner");
 }
 static String serviceSHA(byte[] data)throws Exception{return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(data));}
 static void encryptedCONNECTDNS(AndroidStandardExitStore.Entry entry,JSONObject original,boolean service)throws Exception{
  for(String protocol:List.of("tls","https","h3"))for(boolean hostname:List.of(false,true)){
   JSONObject bundle=object(original.toString()),p=profile(bundle);
   if(!service){bundle.getJSONObject("profiles").getJSONObject("shadowsocks").remove("routervpn-ss-service.json");p.put("start_layer","off");}
   p.put("dns_mode",hostname?Map.of("tls","dot","https","doh","h3","doh3").get(protocol):"custom").put("dns_protocol",protocol).put("dns_host",hostname?"resolver.example.net":"203.0.113.53").put("dns_port",8853).put("dns_server_name","resolver.example.net").put("dns_path","/owned-dns-query");
   if(hostname)p.put("dns_bootstrap",new JSONObject().put("server",new JSONObject().put("type",service?"udp":"tcp").put("tag","external-dns-bootstrap").put("server","203.0.113.54").put("server_port",5354).put("detour","proxy")).put("query",new JSONObject().put("server","external-dns-bootstrap").put("timeout","3s").put("disable_optimistic_cache",true)));
   if(!service&&protocol.equals("h3")){reject("unprovisioned CONNECT cannot carry H3",()->AndroidImportedRouterPath.compile(entry,bundle,"shadowsocks","local"));continue;}
   String before=bundle.toString();AndroidImportedRouterPath.Compiled c=AndroidImportedRouterPath.compile(entry,bundle,"shadowsocks","local");JSONObject input=object(c.input),dns=object(c.config).getJSONObject("dns").getJSONArray("servers").getJSONObject(0);
   check(dns.getString("type").equals(protocol)&&dns.getString("server").equals(p.getString("dns_host"))&&dns.getInt("server_port")==8853&&dns.getString("detour").equals("proxy")&&dns.getJSONObject("tls").getString("server_name").equals("resolver.example.net"),"encrypted CONNECT changed selected DNS identity");
   if(!protocol.equals("tls"))check(dns.getString("path").equals("/owned-dns-query"),"encrypted CONNECT changed DNS path");
   check(before.equals(bundle.toString()),"encrypted CONNECT changed captured node");
   RouterMultihop restored=AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,c.input);restored.close();
   if(hostname){check(input.getString("dns_bootstrap").equals(p.getJSONObject("dns_bootstrap").toString()),"encrypted CONNECT changed captured bootstrap");reject("changed CONNECT bootstrap cannot restore",()->{JSONObject changed=object(c.input),bootstrap=object(changed.getString("dns_bootstrap"));bootstrap.getJSONObject("server").put("server","203.0.113.99");changed.put("dns_bootstrap",bootstrap.toString());AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});}
  }
 }
 static void configuredCONNECT(AndroidStandardExitStore.Entry entry,JSONObject original)throws Exception{
  for(String layer:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))for(String mode:List.of("home","custom"))for(String transport:List.of("udp","tcp")){
   JSONObject bundle=object(original.toString()),profile=profile(bundle),files=bundle.getJSONObject("profiles").getJSONObject("shadowsocks");
   profile.put("start_layer",layer).put("dns_mode",mode).put("dns_protocol",transport);
   if(mode.equals("custom"))profile.put("dns_host","203.0.113.53");
   byte[] source=Base64.getDecoder().decode(files.getString("sing-box.json"));JSONObject out=object(new String(source,StandardCharsets.UTF_8)).getJSONArray("outbounds").getJSONObject(0);
   JSONObject claim=new JSONObject().put("schema",1).put("node_id",profile.getString("node_proof_id")).put("configured_image","ghcr.io/sagernet/sing-box:v1.13.12").put("uot_version",2).put("endpoint",out.getString("server")).put("port",out.getInt("server_port")).put("method",out.getString("method")).put("key_sha256",serviceSHA(out.getString("password").getBytes(StandardCharsets.UTF_8))).put("source_sha256",serviceSHA(source));
   files.put("routervpn-ss-service.json",Base64.getEncoder().encodeToString(claim.toString().getBytes(StandardCharsets.UTF_8)));
   if(mode.equals("home")&&transport.equals("udp")){encryptedCONNECTDNS(entry,bundle,true);if(layer.equals("off"))encryptedCONNECTDNS(entry,bundle,false);}
   String before=bundle.toString();AndroidImportedRouterPath.Compiled compiled=AndroidImportedRouterPath.compile(entry,bundle,"shadowsocks","local");
   JSONObject metadata=object(compiled.metadata),dns=object(compiled.config).getJSONObject("dns").getJSONArray("servers").getJSONObject(0);
   check(metadata.getString("transport_capability").equals("uot-v2")&&dns.getString("type").equals(transport)&&dns.getString("server").equals(profile.getString("dns_host"))&&dns.getInt("server_port")==profile.getInt("dns_port"),"configured CONNECT changed DNS or capability");
   check(before.equals(bundle.toString())&&object(object(compiled.input).getString("exit_files")).toString().equals(files.toString()),"configured CONNECT changed original source assets");
   RouterMultihop restored=AndroidImportedRouterPath.prepareExecution(compiled.config,compiled.metadata,compiled.input);restored.close();
   reject("configured CONNECT source replacement",()->{JSONObject changed=object(compiled.input),assets=object(changed.getString("exit_files"));assets.remove("routervpn-ss-service.json");changed.put("exit_files",assets.toString());AndroidImportedRouterPath.prepareExecution(compiled.config,compiled.metadata,changed.toString());});
   Libbox.rejectSSService=true;try{reject("false service bridge result",()->AndroidImportedRouterPath.compile(entry,bundle,"shadowsocks","local"));}finally{Libbox.rejectSSService=false;}
   JSONObject foreign=object(before),claim2=object(claim.toString());claim2.put("node_id","f".repeat(64));foreign.getJSONObject("profiles").getJSONObject("shadowsocks").put("routervpn-ss-service.json",Base64.getEncoder().encodeToString(claim2.toString().getBytes(StandardCharsets.UTF_8)));
   reject("foreign configured CONNECT owner",()->AndroidImportedRouterPath.compile(entry,foreign,"shadowsocks","local"));
  }
 }
 static void connectLayer(JSONArray source,AndroidStandardExitStore.Entry entry,JSONObject bundle,AndroidImportedRouterPath.Compiled compiled)throws Exception{
  JSONObject graph=object(compiled.config),first=outbound(graph,"entry-wg"),last=outbound(graph,"routervpn-execution-local"),outer=outbound(graph,first.getString("detour")),provision=entry.startLayer,transport=provision.getJSONObject("transport"),expected=object(source.getString(8));
  String layer=entry.policy.getString("start_layer");
  check(first.getString("type").equals("http")&&first.getString("server").equals(new java.net.URI(provision.getString("api")).getHost())&&first.getInt("server_port")==entry.serverPort&&first.getString("username").equals(entry.username)&&first.getString("password").equals(entry.password),"CONNECT wrapper changed private service or authentication");
  check(outer.getString("server").equals(transport.getString("server"))&&outer.getString("password").equals(transport.getString("password"))&&!outer.has("detour")&&outer.getString("type").equals(layer.equals("aes-256-gcm+xor-whitening")?"routervpn-aes-xor":"shadowsocks")&&!outer.getString("password").equals(last.getString("password")),"CONNECT wrapper borrowed another node's outer provision");
  if(AndroidExternalPolicy.protocol(entry.protocol).equals("https-connect")){JSONObject tls=first.getJSONObject("tls");check(tls.getBoolean("enabled")&&tls.getString("server_name").equals(entry.tlsServerName)&&!tls.has("insecure"),"CONNECT wrapper changed original TLS identity");}
  check(last.toString().equals(outbound(expected,"routervpn-execution-local").toString())&&graph.getJSONObject("dns").toString().equals(expected.getJSONObject("dns").toString()),"CONNECT wrapper changed exact final or selected DNS");
  JSONObject assets=bundle.getJSONObject("profiles").getJSONObject("shadowsocks");boolean configured=assets.has("routervpn-ss-service.json");
  if(configured){JSONObject uot=last.getJSONObject("udp_over_tcp");check(!last.has("network")&&uot.getBoolean("enabled")&&uot.getInt("version")==2,"CONNECT wrapper lost configured final service");JSONObject wrong=object(bundle.toString());wrong.getJSONObject("profiles").getJSONObject("shadowsocks").put("routervpn-ss-service.json",Base64.getEncoder().encodeToString("{}".getBytes(StandardCharsets.UTF_8)));reject("CONNECT wrapper cannot supply final authority",()->AndroidImportedRouterPath.compile(entry,wrong,"shadowsocks","local"));}
  else{check(last.getString("network").equals("tcp")&&!last.has("udp_over_tcp"),"CONNECT wrapper granted unconfigured datagram authority");for(String fault:List.of("dns","final-layer")){JSONObject wrong=object(bundle.toString());profile(wrong).put(fault.equals("dns")?"dns_protocol":"start_layer",fault.equals("dns")?"udp":"aes-256-gcm");reject("CONNECT wrapper invented final "+fault,()->AndroidImportedRouterPath.compile(entry,wrong,"shadowsocks","local"));}}
  if(configured){
   for(String field:List.of("key_sha256","source_sha256")){JSONObject wrong=object(bundle.toString()),claim=object(new String(Base64.getDecoder().decode(assets.getString("routervpn-ss-service.json")),StandardCharsets.UTF_8));claim.put(field,"0".repeat(64));wrong.getJSONObject("profiles").getJSONObject("shadowsocks").put("routervpn-ss-service.json",Base64.getEncoder().encodeToString(claim.toString().getBytes(StandardCharsets.UTF_8)));reject("CONNECT configured service changed actual SHA-256 "+field,()->AndroidImportedRouterPath.compile(entry,wrong,"shadowsocks","local"));}
   JSONObject unused=object(bundle.toString());unused.getJSONObject("profiles").getJSONObject("shadowsocks").put("unused-service.json",Base64.getEncoder().encodeToString("{}".getBytes(StandardCharsets.UTF_8)));reject("CONNECT final service has unused source authority",()->AndroidImportedRouterPath.compile(entry,unused,"shadowsocks","local"));
  }
  for(String fault:List.of("missing-provision","mode-mismatch","borrowed-final","public-inner","unused-provision","unused-service","malformed-layer","invalid-layer")){
   AndroidStandardExitStore.Entry changed=AndroidStandardExitStore.copy(entry);
   if(fault.equals("missing-provision"))changed.startLayer=null;
   else if(fault.equals("mode-mismatch"))changed.startLayer.put("mode",layer.equals("aes-256-gcm")?"aes-256-gcm+xor-whitening":"aes-256-gcm");
   else if(fault.equals("borrowed-final"))changed.startLayer.getJSONObject("transport").put("server",profile(bundle).getString("endpoint"));
   else if(fault.equals("public-inner"))changed.startLayer.put("api","http://203.0.113.20:8787");
   else if(fault.equals("unused-provision"))changed.policy.put("start_layer","off");
   else if(fault.equals("unused-service"))changed.startLayer.getJSONObject("transport").put("udp_over_tcp",new JSONObject().put("enabled",true).put("version",2));
   else if(fault.equals("malformed-layer"))changed.policy.put("start_layer",true);
   else changed.policy.put("start_layer","xor-only");
   reject("CONNECT unowned entry layer "+fault,()->AndroidImportedRouterPath.compile(changed,bundle,"shadowsocks","local"));
  }
  reject("CONNECT changed original layer key on restore",()->{JSONObject input=object(compiled.input),capture=object(input.getString("entry_capture"));capture.getJSONObject("profile").getJSONObject("external").getJSONObject("start_layer").getJSONObject("transport").put("password",Base64.getEncoder().encodeToString(new byte[32]));input.put("entry_capture",capture.toString());AndroidImportedRouterPath.prepareExecution(compiled.config,compiled.metadata,input.toString());});
  reject("CONNECT substituted final transport key on restore",()->{JSONObject input=object(compiled.input),files=object(input.getString("exit_files")),raw=object(new String(Base64.getDecoder().decode(files.getString("sing-box.json")),StandardCharsets.UTF_8));outbound(raw,"proxy").put("password",transport.getString("password"));files.put("sing-box.json",Base64.getEncoder().encodeToString(raw.toString().getBytes(StandardCharsets.UTF_8)));input.put("exit_files",files.toString());AndroidImportedRouterPath.prepareExecution(compiled.config,compiled.metadata,input.toString());});
 }
 static void connectReality(AndroidStandardExitStore.Entry entry,JSONObject bundle,AndroidImportedRouterPath.Compiled compiled)throws Exception{
  String finalMode=object(compiled.input).getString("exit_mode");
  JSONObject graph=object(compiled.config),first=outbound(graph,"entry-wg"),captured=object(compiled.input);
  check(first.getString("type").equals("http")&&first.getString("username").equals(entry.username)&&first.getString("password").equals(entry.password)&&first.getInt("server_port")==entry.serverPort,"REALITY changed CONNECT authentication or port");
  if(entry.protocol.equals("https"))check(first.getJSONObject("tls").getBoolean("enabled")&&!first.getJSONObject("tls").optBoolean("insecure")&&first.getJSONObject("tls").getString("server_name").equals(entry.tlsServerName),"REALITY changed captured CONNECT TLS identity");
  else check(!first.has("tls"),"HTTP CONNECT acquired unrequested TLS");
  if(entry.startLayer==null)check(!first.has("detour")&&first.getString("server").equals(entry.server),"CONNECT changed its original public endpoint");
  else{
   JSONObject outer=outbound(graph,first.getString("detour")),transport=entry.startLayer.getJSONObject("transport");
   check(first.getString("server").equals(java.net.URI.create(entry.startLayer.getString("api")).getHost())&&!outer.has("detour")&&outer.getString("server").equals(transport.getString("server"))&&outer.getString("password").equals(transport.getString("password")),"CONNECT replaced independent layer or private inner owner");
   for(String fault:List.of("missing","mismatch","foreign","unused")){
    AndroidStandardExitStore.Entry changed=AndroidStandardExitStore.copy(entry);
    if(fault.equals("missing"))changed.startLayer=null;
    else if(fault.equals("mismatch"))changed.startLayer.put("mode",entry.policy.optString("start_layer").equals("aes-256-gcm")?"aes-256-gcm+xor-whitening":"aes-256-gcm");
    else if(fault.equals("foreign"))changed.startLayer.getJSONObject("transport").put("server","203.0.113.99");
    else changed.policy.put("start_layer","off");
    reject("CONNECT REALITY unowned entry layer "+fault,()->AndroidImportedRouterPath.compile(changed,bundle,finalMode,"local"));
   }
  }
  for(String foreign:List.of("tcp-only","uot-v2"))try{RouterMultihop.capabilityOverride=foreign;reject("CONNECT REALITY foreign compiler capability",()->AndroidImportedRouterPath.compile(entry,bundle,finalMode,"local"));}finally{RouterMultihop.capabilityOverride=null;}
  try{Libbox.rejectSSService=true;AndroidImportedRouterPath.Compiled independent=AndroidImportedRouterPath.compile(entry,bundle,finalMode,"local");check(independent.config.equals(compiled.config)&&independent.metadata.equals(compiled.metadata),"CONNECT REALITY borrowed the final layer's SS service capability");}finally{Libbox.rejectSSService=false;}
  JSONObject foreign=object(bundle.toString());foreign.getJSONObject("profiles").getJSONObject(finalMode).put("routervpn-ss-service.json",Base64.getEncoder().encodeToString("{}".getBytes(StandardCharsets.UTF_8)));
  reject("CONNECT REALITY foreign service declaration",()->AndroidImportedRouterPath.compile(entry,foreign,finalMode,"local"));
  JSONArray outputs=graph.getJSONArray("outbounds");for(int i=0;i<outputs.length();i++)check(!outputs.getJSONObject(i).has("udp_over_tcp"),"CONNECT injected SS UoT into its actual VLESS carrier");
  JSONObject original=object(new String(Base64.getDecoder().decode(object(captured.getString("exit_files")).getString("xray.json")),StandardCharsets.UTF_8));
  String flow=original.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0).optString("flow","");
  JSONObject running=object(outbound(graph,"routervpn-execution-local").getString("config_json"));
  check(running.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0).optString("flow","").equals(flow),"CONNECT silently changed original REALITY UDP443 permission");
  if(entry.startLayer==null&&profile(bundle).optString("start_layer","off").equals("off"))connectRealityDNS(entry,bundle,finalMode);
 }
 static void connectRealityDNS(AndroidStandardExitStore.Entry entry,JSONObject original,String finalMode)throws Exception{
  String before=original.toString();int cases=0;
  for(String flow:(finalMode.equals("reality-xhttp")?List.of(""):List.of("xtls-rprx-vision","xtls-rprx-vision-udp443")))for(String transport:List.of("udp","tcp","tls","https","h3"))for(boolean hostname:List.of(false,true)){
   if(transport.equals("h3")&&!finalMode.equals("reality-xhttp")&&!flow.endsWith("-udp443"))continue;
   JSONObject bundle=object(before),p=profile(bundle),files=bundle.getJSONObject("profiles").getJSONObject(finalMode),xray=object(new String(Base64.getDecoder().decode(files.getString("xray.json")),StandardCharsets.UTF_8));
   xray.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0).put("flow",flow.isEmpty()?null:flow);
   files.put("xray.json",Base64.getEncoder().encodeToString(xray.toString().getBytes(StandardCharsets.UTF_8)));
   int port=transport.equals("h3")?443:8853;
   p.put("dns_mode",Map.of("tls","dot","https","doh","h3","doh3").getOrDefault(transport,"custom")).put("dns_protocol",transport).put("dns_host",hostname?"resolver.example.net":"203.0.113.53").put("dns_port",port).put("dns_server_name","resolver.example.net").put("dns_path","/owned-dns-query");
   if(hostname)p.put("dns_bootstrap",new JSONObject().put("server",new JSONObject().put("type","udp").put("tag","external-dns-bootstrap").put("server","203.0.113.54").put("server_port",5354).put("detour","proxy")).put("query",new JSONObject().put("server","external-dns-bootstrap").put("timeout","3s").put("disable_optimistic_cache",true)));
   String captured=bundle.toString();AndroidImportedRouterPath.Compiled c=AndroidImportedRouterPath.compile(entry,bundle,finalMode,"local");JSONObject input=object(c.input),graph=object(c.config),dns=graph.getJSONObject("dns").getJSONArray("servers").getJSONObject(0);
   check(bundle.toString().equals(captured)&&object(c.metadata).getString("transport_capability").equals("vless-stream")&&dns.getString("type").equals(transport)&&dns.getString("server").equals(p.getString("dns_host"))&&dns.getInt("server_port")==port&&dns.getString("detour").equals("proxy"),"CONNECT REALITY changed selected DNS or original sources");
   if(List.of("tls","https","h3").contains(transport))check(dns.getJSONObject("tls").getString("server_name").equals("resolver.example.net"),"CONNECT REALITY changed selected DNS TLS name");
   if(List.of("https","h3").contains(transport))check(dns.getString("path").equals("/owned-dns-query"),"CONNECT REALITY changed selected DNS request path");
   check(object(input.getString("exit_files")).toString().equals(files.toString())&&object(outbound(graph,"routervpn-execution-local").getString("config_json")).getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0).optString("flow","").equals(flow),"CONNECT REALITY substituted original selected flow assets");
   RouterMultihop owner=AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,c.input);owner.close();
   if(hostname){check(object(input.getString("dns_bootstrap")).toString().equals(p.getJSONObject("dns_bootstrap").toString()),"CONNECT REALITY lost captured bootstrap/query policy");reject("changed REALITY bootstrap cannot restore",()->{JSONObject changed=object(c.input),bootstrap=object(changed.getString("dns_bootstrap"));bootstrap.getJSONObject("server").put("server","203.0.113.99");changed.put("dns_bootstrap",bootstrap.toString());AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});}
   cases++;
  }
  check(cases==(finalMode.equals("reality-xhttp")?10:18)&&original.toString().equals(before),"CONNECT REALITY selected DNS inventory or original owner changed");
 }
 static void xhttpIdentity(AndroidStandardExitStore.Entry entry,JSONObject bundle,AndroidImportedRouterPath.Compiled compiled)throws Exception{
  String mode="reality-xhttp";JSONObject files=bundle.getJSONObject("profiles").getJSONObject(mode);
  JSONObject original=object(new String(Base64.getDecoder().decode(files.getString("xray.json")),StandardCharsets.UTF_8));
  JSONObject actual=object(outbound(object(compiled.config),"routervpn-execution-local").getString("config_json"));
  JSONObject out=actual.getJSONArray("outbounds").getJSONObject(0),user=out.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0),stream=out.getJSONObject("streamSettings");
  check(stream.toString().equals(original.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings").toString())&&user.toString().equals(original.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0).toString())&&user.optString("flow","").isEmpty()&&user.getString("encryption").startsWith("mlkem768x25519plus.native.0rtt."),"XHTTP replaced original hybrid key, empty flow or native settings");
  check(stream.getString("network").equals("xhttp")&&stream.getJSONObject("xhttpSettings").getString("path").equals("/assets/sync")&&stream.getJSONObject("xhttpSettings").getString("mode").equals("auto")&&stream.getJSONObject("finalmask").getJSONArray("tcp").length()>0,"XHTTP replaced captured request path, auto mode or FinalMask");
  JSONObject legacy=object(bundle.toString());legacy.getJSONObject("profiles").getJSONObject(mode).remove("sing-box.json");
  AndroidImportedRouterPath.Compiled rawOnly=AndroidImportedRouterPath.compile(entry,legacy,mode,"local");
  check(!object(object(rawOnly.input).getString("exit_files")).has("sing-box.json")&&outbound(object(rawOnly.config),"routervpn-execution-local").getString("config_json").equals(outbound(object(compiled.config),"routervpn-execution-local").getString("config_json")),"XHTTP raw-only asset was rewritten or refused");
  RouterMultihop owner=AndroidImportedRouterPath.prepareExecution(rawOnly.config,rawOnly.metadata,rawOnly.input);owner.close();
  for(String fault:List.of("ordinary","missing-encryption","missing-xray","malformed-wrapper","vision-flow","wrong-network","missing-settings","bad-path","bad-mode","pq-label")){
   JSONObject changed=object(bundle.toString()),assets=changed.getJSONObject("profiles").getJSONObject(mode),raw=object(original.toString()),row=raw.getJSONArray("outbounds").getJSONObject(0),u=row.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0),transport=row.getJSONObject("streamSettings");
   if(fault.equals("missing-xray"))assets.remove("xray.json");
   else if(fault.equals("malformed-wrapper"))assets.put("sing-box.json",Base64.getEncoder().encodeToString("{".getBytes(StandardCharsets.UTF_8)));
   else if(fault.equals("pq-label"))changed.getJSONObject("profiles").put("reality-pq-vision",assets);
   else{if(fault.equals("ordinary"))u.put("encryption","none");else if(fault.equals("missing-encryption"))u.remove("encryption");else if(fault.equals("vision-flow"))u.put("flow","xtls-rprx-vision");else if(fault.equals("wrong-network"))transport.put("network","raw");else if(fault.equals("missing-settings"))transport.remove("xhttpSettings");else if(fault.equals("bad-path"))transport.getJSONObject("xhttpSettings").put("path","uncaptured");else transport.getJSONObject("xhttpSettings").put("mode","stream-one");assets.put("xray.json",Base64.getEncoder().encodeToString(raw.toString().getBytes(StandardCharsets.UTF_8)));}
   reject("XHTTP refuses invalid native source "+fault,()->AndroidImportedRouterPath.compile(entry,changed,fault.equals("pq-label")?"reality-pq-vision":mode,"local"));
  }
  for(String fault:List.of("path","mask","raw-only")){
   JSONObject changed=object(compiled.input),assets=object(changed.getString("exit_files")),raw=object(original.toString()),transport=raw.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings");
   if(fault.equals("raw-only"))assets.remove("sing-box.json");else{if(fault.equals("path"))transport.getJSONObject("xhttpSettings").put("path","/different-original");else transport.remove("finalmask");assets.put("xray.json",Base64.getEncoder().encodeToString(raw.toString().getBytes(StandardCharsets.UTF_8)));}
   changed.put("exit_files",assets.toString());reject("XHTTP restore refuses substituted original "+fault,()->AndroidImportedRouterPath.prepareExecution(compiled.config,compiled.metadata,changed.toString()));
  }
 }
 static void naiveH2Identity(AndroidStandardExitStore.Entry entry,JSONObject bundle,AndroidImportedRouterPath.Compiled compiled)throws Exception{
  String mode="naive-h2",before=bundle.toString();JSONObject files=bundle.getJSONObject("profiles").getJSONObject(mode);
  JSONObject original=object(new String(Base64.getDecoder().decode(files.getString("sing-box.json")),StandardCharsets.UTF_8));
  JSONObject expected=object(Libbox.routerCompileProxyEntry(files.toString(),mode)),graph=object(compiled.config),actual=outbound(graph,"routervpn-execution-local");
  check(actual.getString("type").equals("naive")&&!actual.getBoolean("quic")&&actual.getString("username").equals(expected.getString("username"))&&actual.getString("password").equals(expected.getString("password"))&&actual.getJSONObject("tls").toString().equals(expected.getJSONObject("tls").toString())&&actual.getJSONObject("udp_over_tcp").toString().equals(expected.getJSONObject("udp_over_tcp").toString()),"Naive H2 changed original authenticated stream, UoT or captured trust");
  String layer=AndroidStartLayer.selectedMode(bundle),outer=layer.equals("off")?"entry-wg":"start-layer-aes";
  check(actual.getString("detour").equals(outer)&&actual.getString("server").equals(layer.equals("off")?expected.getString("server"):"127.0.0.1")&&actual.getInt("server_port")==expected.getInt("server_port"),"Naive H2 changed final-owned receiver or independent layer");
  JSONArray servers=graph.getJSONObject("dns").getJSONArray("servers");check(servers.length()==2,"Naive H2 Home source lost its separate captured lower resolver");
  JSONObject selected=servers.getJSONObject(0),lower=servers.getJSONObject(1);
  check(selected.getString("type").equals("tcp")&&selected.getString("server").equals(profile(bundle).getString("adguard_ipv4"))&&selected.getString("detour").equals("proxy"),"Naive H2 rewrote selected Home TCP policy");
  check(lower.getString("type").equals(selected.getString("type"))&&lower.getString("server").equals(selected.getString("server"))&&lower.getString("detour").equals(outer)&&actual.getJSONObject("domain_resolver").getString("server").equals(lower.getString("tag")),"Naive H2 dropped or bypassed its captured bootstrap owner");
  boolean connect=List.of("http","https").contains(entry.protocol);
  if(entry.protocol.equals("shadowsocks"))for(String key:List.of("not-base64",Base64.getEncoder().encodeToString(new byte[31]))){
   AndroidStandardExitStore.Entry invalid=AndroidStandardExitStore.copy(entry);invalid.secret=key;
   reject("Naive H2 refuses malformed original SS2022 entry key",()->AndroidImportedRouterPath.compile(invalid,bundle,mode,"local"));
  }
  if(connect){
   for(String foreign:List.of("tcp-only","uot-v2","vless-stream"))try{RouterMultihop.capabilityOverride=foreign;reject("Naive H2 foreign compiler capability "+foreign,()->AndroidImportedRouterPath.compile(entry,bundle,mode,"local"));}finally{RouterMultihop.capabilityOverride=null;}
   try{Libbox.rejectSSService=true;check(AndroidImportedRouterPath.compile(entry,bundle,mode,"local").config.equals(compiled.config),"Naive H2 borrowed final SS service authority");}finally{Libbox.rejectSSService=false;}
  }
  for(String fault:List.of("h3","numeric-quic","missing-uot","uot-version","numeric-uot","missing-user","missing-password","insecure","missing-sni","missing-certificate","malformed-certificate","unused-asset","missing-source","foreign-service")){
   JSONObject changed=object(before),assets=changed.getJSONObject("profiles").getJSONObject(mode),raw=object(original.toString()),row=outbound(raw,"proxy");
   switch(fault){case "h3":row.put("quic",true);break;case "numeric-quic":row.put("quic",0);break;case "missing-uot":row.remove("udp_over_tcp");break;case "uot-version":row.getJSONObject("udp_over_tcp").put("version",1);break;case "numeric-uot":row.getJSONObject("udp_over_tcp").put("enabled",1);break;case "missing-user":row.remove("username");break;case "missing-password":row.remove("password");break;case "insecure":row.getJSONObject("tls").put("insecure",true);break;case "missing-sni":row.getJSONObject("tls").remove("server_name");break;case "missing-certificate":row.getJSONObject("tls").remove("certificate");row.getJSONObject("tls").put("certificate_path","missing.crt");break;case "malformed-certificate":assets.put(row.getJSONObject("tls").getString("certificate_path"),Base64.getEncoder().encodeToString("not a certificate".getBytes(StandardCharsets.UTF_8)));break;case "unused-asset":assets.put("unused.crt",Base64.getEncoder().encodeToString("unused asset".getBytes(StandardCharsets.UTF_8)));break;case "missing-source":assets.remove("sing-box.json");break;default:assets.put("routervpn-ss-service.json",Base64.getEncoder().encodeToString("{}".getBytes(StandardCharsets.UTF_8)));}
   if(!fault.equals("missing-source"))assets.put("sing-box.json",Base64.getEncoder().encodeToString(raw.toString().getBytes(StandardCharsets.UTF_8)));
   reject("Naive H2 rejects invalid captured source "+fault,()->AndroidImportedRouterPath.compile(entry,changed,mode,"local"));
  }
  for(String fault:List.of("username","password","server","server_name")){
   JSONObject changed=object(compiled.input),assets=object(changed.getString("exit_files")),raw=object(original.toString()),row=outbound(raw,"proxy");
   if(fault.equals("server_name"))row.getJSONObject("tls").put(fault,"different.example.net");else row.put(fault,fault.equals("server")?"203.0.113.99":"different-original");
   assets.put("sing-box.json",Base64.getEncoder().encodeToString(raw.toString().getBytes(StandardCharsets.UTF_8)));changed.put("exit_files",assets.toString());
   reject("Naive H2 replay refuses replaced original "+fault,()->AndroidImportedRouterPath.prepareExecution(compiled.config,compiled.metadata,changed.toString()));
  }
  if(layer.equals("off")&&entry.startLayer==null)naiveH2DNS(entry,bundle);
  if(connect){
   JSONObject home=object(before);profile(home).remove("dns_protocol");String capturedHome=home.toString();
   AndroidImportedRouterPath.Compiled retained=AndroidImportedRouterPath.compile(entry,home,mode,"local");
   JSONObject homeGraph=object(retained.config);JSONArray homeDNS=homeGraph.getJSONObject("dns").getJSONArray("servers");
   JSONObject selectedHome=homeDNS.getJSONObject(0),bootstrapHome=homeDNS.getJSONObject(1),homeFinal=outbound(homeGraph,"routervpn-execution-local");
   check(homeDNS.length()==2&&selectedHome.getString("type").equals("udp")&&selectedHome.getString("server").equals(profile(home).getString("adguard_ipv4"))&&selectedHome.getInt("server_port")==53&&selectedHome.getString("detour").equals("proxy"),"CONNECT literal layered path changed default Home UDP");
   check(bootstrapHome.getString("type").equals("udp")&&bootstrapHome.getString("server").equals(selectedHome.getString("server"))&&bootstrapHome.getString("detour").equals(outer)&&homeFinal.getString("detour").equals(outer)&&homeFinal.getJSONObject("domain_resolver").getString("server").equals(bootstrapHome.getString("tag")),"CONNECT literal layered path changed its dormant lower owner");
   RouterMultihop replay=AndroidImportedRouterPath.prepareExecution(retained.config,retained.metadata,retained.input);
   try{check(replay.config().equals(retained.config)&&replay.sourceSHA256().equals(retained.source),"CONNECT literal layered replay replaced original graph/source");}finally{replay.close();}
   check(home.toString().equals(capturedHome)&&RouterMultihop.open==0,"CONNECT literal layered capture changed source or leaked owner");
   JSONObject stale=object(retained.input);stale.put("exit_profile",stale.getString("exit_profile")+" ");
   reject("CONNECT literal layered replay rejects substituted original source",()->AndroidImportedRouterPath.prepareExecution(retained.config,retained.metadata,stale.toString()));
  }
  check(bundle.toString().equals(before),"Naive H2 validation rewrote original sources");
 }
 static void naiveH2DNS(AndroidStandardExitStore.Entry entry,JSONObject original)throws Exception{
  boolean connect=List.of("http","https").contains(entry.protocol);String before=original.toString();
  JSONObject system=object(before),assets=system.getJSONObject("profiles").getJSONObject("naive-h2"),wrapper=object(new String(Base64.getDecoder().decode(assets.getString("sing-box.json")),StandardCharsets.UTF_8));
  JSONObject tls=outbound(wrapper,"proxy").getJSONObject("tls");tls.remove("certificate");tls.remove("certificate_path");List<String> names=new ArrayList<>();assets.keys().forEachRemaining(key->names.add((String)key));for(String name:names)if(!name.equals("sing-box.json"))assets.remove(name);assets.put("sing-box.json",Base64.getEncoder().encodeToString(wrapper.toString().getBytes(StandardCharsets.UTF_8)));
  JSONObject systemGraph=object(AndroidImportedRouterPath.compile(entry,system,"naive-h2","local").config);check(!outbound(systemGraph,"routervpn-execution-local").getJSONObject("tls").has("certificate"),"Naive H2 replaced explicit system trust with a borrowed certificate");
  JSONObject home=object(before);profile(home).put("dns_protocol","udp");String saved=home.toString();
  {var homeCompiled=AndroidImportedRouterPath.compile(entry,home,"naive-h2","local");JSONObject graph=object(homeCompiled.config);String homeDirectory=System.getenv("ROUTERVPN_ANDROID_NAIVE_H2_HOME_GRAPHS");if(connect&&homeDirectory!=null)Files.writeString(Path.of(homeDirectory).resolve(entry.protocol.equals("http")?"http-connect.json":"https-connect.json"),homeCompiled.config,StandardOpenOption.CREATE_NEW);JSONObject dns=graph.getJSONObject("dns").getJSONArray("servers").getJSONObject(0);check(dns.getString("type").equals("udp")&&dns.getString("server").equals(profile(home).getString("adguard_ipv4"))&&dns.getString("detour").equals("proxy"),"Literal Naive H2 lost original final-owned Home UDP");}
  check(home.toString().equals(saved),"Naive H2 rewrote incompatible saved Home policy");
  for(String transport:List.of("tcp","tls","https","h3"))for(boolean hostname:List.of(false,true)){
   JSONObject bundle=object(before),p=profile(bundle);p.put("dns_mode","custom").put("dns_protocol",transport).put("dns_host",hostname?"resolver.example.net":"203.0.113.53").put("dns_port",8853).put("dns_server_name","resolver.example.net").put("dns_path","/owned-dns-query");
   if(hostname)p.put("dns_bootstrap",new JSONObject().put("server",new JSONObject().put("type","tcp").put("tag","external-dns-bootstrap").put("server","203.0.113.54").put("server_port",5354).put("detour","proxy")).put("query",new JSONObject().put("server","external-dns-bootstrap").put("timeout","3s").put("disable_optimistic_cache",true)));
   String captured=bundle.toString();AndroidImportedRouterPath.Compiled c=AndroidImportedRouterPath.compile(entry,bundle,"naive-h2","local");JSONArray servers=object(c.config).getJSONObject("dns").getJSONArray("servers");JSONObject dns=servers.getJSONObject(0);
   check(captured.equals(bundle.toString())&&servers.length()==(hostname?4:2)&&dns.getString("type").equals(transport)&&dns.getString("server").equals(p.getString("dns_host"))&&dns.getInt("server_port")==8853&&dns.getString("detour").equals("proxy"),"Naive H2 lost captured selected/transport resolver closure");
   for(int i=0;i<servers.length();i++){JSONObject server=servers.getJSONObject(i);check(server.getString("detour").equals(server.getString("tag").startsWith("routervpn-predecessor-bootstrap-")?"entry-wg":"proxy"),"Naive H2 resolver escaped its original owner");}
   if(!transport.equals("tcp"))check(dns.getJSONObject("tls").getString("server_name").equals("resolver.example.net"),"Naive H2 replaced selected DNS trust name");
   if(List.of("https","h3").contains(transport))check(dns.getString("path").equals("/owned-dns-query"),"Naive H2 replaced selected DNS request path");
   RouterMultihop restored=AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,c.input);restored.close();
   if(hostname&&connect)for(String lower:List.of("udp","h3")){
    JSONObject changed=object(captured),server=profile(changed).getJSONObject("dns_bootstrap").getJSONObject("server");server.put("type",lower);
    if(lower.equals("h3"))server.put("tls",new JSONObject().put("enabled",true).put("server_name","bootstrap.example.net")).put("path","/captured-bootstrap");
    String immutable=changed.toString();AndroidImportedRouterPath.Compiled selected=AndroidImportedRouterPath.compile(entry,changed,"naive-h2","local");JSONArray resolvers=object(selected.config).getJSONObject("dns").getJSONArray("servers");
    check(changed.toString().equals(immutable)&&resolvers.length()==4&&resolvers.getJSONObject(1).getString("type").equals(lower)&&resolvers.getJSONObject(1).getString("detour").equals("proxy")&&resolvers.getJSONObject(0).getJSONObject("domain_resolver").getString("server").equals("external-dns-bootstrap"),"Naive H2 replaced captured selected bootstrap");
    for(int i=0;i<resolvers.length();i++){JSONObject resolver=resolvers.getJSONObject(i);check(resolver.getString("detour").equals(resolver.getString("tag").startsWith("routervpn-predecessor-bootstrap-")?"entry-wg":"proxy"),"Naive H2 explicit bootstrap escaped original owner");}
    RouterMultihop replay=AndroidImportedRouterPath.prepareExecution(selected.config,selected.metadata,selected.input);replay.close();
    if(lower.equals("h3")){server.remove("tls");reject("Naive H2 refuses malformed captured H3 bootstrap",()->AndroidImportedRouterPath.compile(entry,changed,"naive-h2","local"));}
   }
  }
  check(before.equals(original.toString()),"Naive H2 DNS coverage mutated original sources");
 }
 static void naiveH3Identity(AndroidStandardExitStore.Entry entry,JSONObject bundle,AndroidImportedRouterPath.Compiled compiled)throws Exception{
  String mode="naive-h3",before=bundle.toString();JSONObject files=bundle.getJSONObject("profiles").getJSONObject(mode);
  JSONObject original=object(new String(Base64.getDecoder().decode(files.getString("sing-box.json")),StandardCharsets.UTF_8));
  JSONObject expected=object(Libbox.routerCompileProxyEntry(files.toString(),mode)),graph=object(compiled.config),actual=outbound(graph,"routervpn-execution-local");
  check(actual.getString("type").equals("naive")&&actual.getBoolean("quic")&&actual.getString("username").equals(expected.getString("username"))&&actual.getString("password").equals(expected.getString("password"))&&actual.getJSONObject("tls").toString().equals(expected.getJSONObject("tls").toString())&&actual.getJSONObject("udp_over_tcp").toString().equals(expected.getJSONObject("udp_over_tcp").toString()),"Naive H3 changed original authenticated stream, UoT or captured trust");
  String layer=AndroidStartLayer.selectedMode(bundle),outer=layer.equals("off")?"entry-wg":"start-layer-aes";
  check(actual.getString("detour").equals(outer)&&actual.getString("server").equals(layer.equals("off")?expected.getString("server"):"127.0.0.1")&&actual.getInt("server_port")==expected.getInt("server_port"),"Naive H3 changed final-owned receiver or independent layer");
  JSONArray servers=graph.getJSONObject("dns").getJSONArray("servers");check(servers.length()==2,"Naive H3 Home source lost its separate captured lower resolver");
  JSONObject selected=servers.getJSONObject(0),lower=servers.getJSONObject(1);
  check(selected.getString("type").equals("udp")&&selected.getString("server").equals(profile(bundle).getString("adguard_ipv4"))&&selected.getString("detour").equals("proxy"),"Naive H3 rewrote selected Home UDP policy");
  check(lower.getString("type").equals(selected.getString("type"))&&lower.getString("server").equals(selected.getString("server"))&&lower.getString("detour").equals(outer)&&actual.getJSONObject("domain_resolver").getString("server").equals(lower.getString("tag")),"Naive H3 dropped or bypassed its captured bootstrap owner");
  boolean connect=List.of("http","https").contains(entry.protocol);
  if(entry.protocol.equals("shadowsocks"))for(String key:List.of("not-base64",Base64.getEncoder().encodeToString(new byte[31]))){
   AndroidStandardExitStore.Entry invalid=AndroidStandardExitStore.copy(entry);invalid.secret=key;
   reject("Naive H3 refuses malformed original SS2022 entry key",()->AndroidImportedRouterPath.compile(invalid,bundle,mode,"local"));
  }
  check(!connect&&!AndroidImportedRouterPath.supports("http","naive-h3")&&!AndroidImportedRouterPath.supports("https","naive-h3"),"Naive H3 cannot borrow CONNECT stream authority");
  for(String fault:List.of("h2","numeric-quic","missing-uot","uot-version","numeric-uot","missing-user","missing-password","insecure","missing-sni","missing-certificate","malformed-certificate","unused-asset","missing-source","foreign-service")){
   JSONObject changed=object(before),assets=changed.getJSONObject("profiles").getJSONObject(mode),raw=object(original.toString()),row=outbound(raw,"proxy");
   switch(fault){case "h2":row.put("quic",false);break;case "numeric-quic":row.put("quic",0);break;case "missing-uot":row.remove("udp_over_tcp");break;case "uot-version":row.getJSONObject("udp_over_tcp").put("version",1);break;case "numeric-uot":row.getJSONObject("udp_over_tcp").put("enabled",1);break;case "missing-user":row.remove("username");break;case "missing-password":row.remove("password");break;case "insecure":row.getJSONObject("tls").put("insecure",true);break;case "missing-sni":row.getJSONObject("tls").remove("server_name");break;case "missing-certificate":row.getJSONObject("tls").remove("certificate");row.getJSONObject("tls").put("certificate_path","missing.crt");break;case "malformed-certificate":assets.put(row.getJSONObject("tls").getString("certificate_path"),Base64.getEncoder().encodeToString("not a certificate".getBytes(StandardCharsets.UTF_8)));break;case "unused-asset":assets.put("unused.crt",Base64.getEncoder().encodeToString("unused asset".getBytes(StandardCharsets.UTF_8)));break;case "missing-source":assets.remove("sing-box.json");break;default:assets.put("routervpn-ss-service.json",Base64.getEncoder().encodeToString("{}".getBytes(StandardCharsets.UTF_8)));}
   if(!fault.equals("missing-source"))assets.put("sing-box.json",Base64.getEncoder().encodeToString(raw.toString().getBytes(StandardCharsets.UTF_8)));
   reject("Naive H3 rejects invalid captured source "+fault,()->AndroidImportedRouterPath.compile(entry,changed,mode,"local"));
  }
  for(String fault:List.of("username","password","server","server_name")){
   JSONObject changed=object(compiled.input),assets=object(changed.getString("exit_files")),raw=object(original.toString()),row=outbound(raw,"proxy");
   if(fault.equals("server_name"))row.getJSONObject("tls").put(fault,"different.example.net");else row.put(fault,fault.equals("server")?"203.0.113.99":"different-original");
   assets.put("sing-box.json",Base64.getEncoder().encodeToString(raw.toString().getBytes(StandardCharsets.UTF_8)));changed.put("exit_files",assets.toString());
   reject("Naive H3 replay refuses replaced original "+fault,()->AndroidImportedRouterPath.prepareExecution(compiled.config,compiled.metadata,changed.toString()));
  }
  if(layer.equals("off")&&entry.startLayer==null)naiveH3DNS(entry,bundle);
  check(bundle.toString().equals(before),"Naive H3 validation rewrote original sources");
 }
 static void naiveH3DNS(AndroidStandardExitStore.Entry entry,JSONObject original)throws Exception{
  boolean connect=List.of("http","https").contains(entry.protocol);String before=original.toString();
  JSONObject system=object(before),assets=system.getJSONObject("profiles").getJSONObject("naive-h3"),wrapper=object(new String(Base64.getDecoder().decode(assets.getString("sing-box.json")),StandardCharsets.UTF_8));
  JSONObject tls=outbound(wrapper,"proxy").getJSONObject("tls");tls.remove("certificate");tls.remove("certificate_path");List<String> names=new ArrayList<>();assets.keys().forEachRemaining(key->names.add((String)key));for(String name:names)if(!name.equals("sing-box.json"))assets.remove(name);assets.put("sing-box.json",Base64.getEncoder().encodeToString(wrapper.toString().getBytes(StandardCharsets.UTF_8)));
  JSONObject systemGraph=object(AndroidImportedRouterPath.compile(entry,system,"naive-h3","local").config);check(!outbound(systemGraph,"routervpn-execution-local").getJSONObject("tls").has("certificate"),"Naive H3 replaced explicit system trust with a borrowed certificate");
  JSONObject home=object(before);profile(home).put("dns_protocol","udp");String saved=home.toString();
  if(connect)reject("Naive H3 CONNECT cannot rewrite saved Home UDP",()->AndroidImportedRouterPath.compile(entry,home,"naive-h3","local"));
  else{JSONObject graph=object(AndroidImportedRouterPath.compile(entry,home,"naive-h3","local").config);check(graph.getJSONObject("dns").getJSONArray("servers").getJSONObject(0).getString("type").equals("udp"),"Naive H3 capable entry lost selected Home UDP");}
  check(home.toString().equals(saved),"Naive H3 rewrote incompatible saved Home policy");
  for(String transport:List.of("udp","tcp","tls","https","h3"))for(boolean hostname:List.of(false,true)){
   JSONObject bundle=object(before),p=profile(bundle);p.put("dns_mode","custom").put("dns_protocol",transport).put("dns_host",hostname?"resolver.example.net":"203.0.113.53").put("dns_port",8853).put("dns_server_name","resolver.example.net").put("dns_path","/owned-dns-query");
   if(hostname)p.put("dns_bootstrap",new JSONObject().put("server",new JSONObject().put("type","tcp").put("tag","external-dns-bootstrap").put("server","203.0.113.54").put("server_port",5354).put("detour","proxy")).put("query",new JSONObject().put("server","external-dns-bootstrap").put("timeout","3s").put("disable_optimistic_cache",true)));
   String captured=bundle.toString();AndroidImportedRouterPath.Compiled c=AndroidImportedRouterPath.compile(entry,bundle,"naive-h3","local");JSONArray servers=object(c.config).getJSONObject("dns").getJSONArray("servers");JSONObject dns=servers.getJSONObject(0);
   check(captured.equals(bundle.toString())&&servers.length()==(hostname?4:2)&&dns.getString("type").equals(transport)&&dns.getString("server").equals(p.getString("dns_host"))&&dns.getInt("server_port")==8853&&dns.getString("detour").equals("proxy"),"Naive H3 lost captured selected/transport resolver closure");
   for(int i=0;i<servers.length();i++){JSONObject server=servers.getJSONObject(i);check(server.getString("detour").equals(server.getString("tag").startsWith("routervpn-predecessor-bootstrap-")?"entry-wg":"proxy"),"Naive H3 resolver escaped its original owner");}
   if(List.of("tls","https","h3").contains(transport))check(dns.getJSONObject("tls").getString("server_name").equals("resolver.example.net"),"Naive H3 replaced selected DNS trust name");
   if(List.of("https","h3").contains(transport))check(dns.getString("path").equals("/owned-dns-query"),"Naive H3 replaced selected DNS request path");
   RouterMultihop restored=AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,c.input);restored.close();
   if(hostname)for(String lower:List.of("udp","h3")){JSONObject changed=object(captured);JSONObject bootstrap=changed.getJSONArray("routerProfiles").getJSONObject(0).getJSONObject("dns_bootstrap").getJSONObject("server");bootstrap.put("type",lower);if(lower.equals("h3"))bootstrap.put("tls",new JSONObject().put("enabled",true).put("server_name","bootstrap.example.net")).put("path","/bootstrap-dns-query");JSONObject changedGraph=object(AndroidImportedRouterPath.compile(entry,changed,"naive-h3","local").config);JSONArray tree=changedGraph.getJSONObject("dns").getJSONArray("servers");check(tree.length()==4,"Naive H3 lost selected and lower bootstrap tree");int retained=0;for(int i=0;i<tree.length();i++){JSONObject row=tree.getJSONObject(i);if(row.optString("server").equals("203.0.113.54")){check(row.getString("type").equals(lower),"Naive H3 rewrote original bootstrap protocol");retained++;}}check(retained==2,"Naive H3 did not retain both original bootstrap owners");}

  }
  Path lowerSources=Path.of(System.getenv("ROUTERVPN_IMPORTED_NAIVE_H2_SOURCES"));
  for(String protocol:List.of("http-connect","https-connect")){
   AndroidStandardExitStore.Entry forbidden=entry(new JSONArray(Files.readString(lowerSources.resolve(protocol+"--naive-h2--off--off.json"))));AndroidImportedRouterPath.requireEntry(forbidden);
   for(String transport:List.of("udp","tcp","h3")){JSONObject changed=object(before);profile(changed).put("dns_protocol",transport);reject("Naive H3 refuses valid "+protocol+" despite selected "+transport,()->AndroidImportedRouterPath.compile(forbidden,changed,"naive-h3","local"));}
  }
  check(before.equals(original.toString()),"Naive H3 DNS coverage mutated original sources");
 }
 static void one(Path root,Path fixture)throws Exception{
  JSONArray args=new JSONArray(Files.readString(fixture));String finalMode=args.getString(2);AndroidStandardExitStore.Entry e=entry(args);JSONObject b=bundle(args);
  String before=AndroidStandardExitStore.snapshot(e),beforeFinal=b.toString();AndroidImportedRouterPath.Compiled c=AndroidImportedRouterPath.compile(e,b,finalMode,"local");
  check(before.equals(AndroidStandardExitStore.snapshot(e))&&beforeFinal.equals(b.toString()),"compiler mutated original source");
  JSONObject selected=object(c.metadata),raw=object(c.input),graph=object(c.config);
  if(finalMode.equals("reality-xhttp"))xhttpIdentity(e,b,c);
  if(finalMode.equals("naive-h2"))naiveH2Identity(e,b,c);
  if(finalMode.equals("naive-h3"))naiveH3Identity(e,b,c);
  if(finalMode.equals("reality-pq-vision")){
   JSONObject files=b.getJSONObject("profiles").getJSONObject(finalMode),xray=object(new String(Base64.getDecoder().decode(files.getString("xray.json")),StandardCharsets.UTF_8));
   JSONObject user=xray.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0);
   check(user.getString("encryption").startsWith("mlkem768x25519plus.native.0rtt."),"PQ host lost exact hybrid encryption");
   for(String fault:List.of("ordinary","missing-encryption","missing-xray","missing-wrapper","ordinary-label")){
    JSONObject changed=object(b.toString()),asset=changed.getJSONObject("profiles").getJSONObject(finalMode),changedXray=object(xray.toString());
    if(fault.equals("missing-xray"))asset.remove("xray.json");
    else if(fault.equals("missing-wrapper"))asset.remove("sing-box.json");
    else if(fault.equals("ordinary-label"))changed.getJSONObject("profiles").put("reality-vision",asset);
    else{JSONObject changedUser=changedXray.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0);if(fault.equals("ordinary"))changedUser.put("encryption","none");else changedUser.remove("encryption");asset.put("xray.json",Base64.getEncoder().encodeToString(changedXray.toString().getBytes(StandardCharsets.UTF_8)));}
    reject("PQ rejects changed encryption source "+fault,()->AndroidImportedRouterPath.compile(e,changed,fault.equals("ordinary-label")?"reality-vision":finalMode,"local"));
   }
  }

  check(selected.getString("entry_kind").equals("external")&&selected.getString("entry_id").equals(e.id)&&selected.getString("exit_id").equals(profile(b).getString("id"))&&selected.getString("entry_mode").equals(AndroidMultihopRuntime.importedEntryMode(e))&&selected.getString("exit_mode").equals(finalMode),"host changed selected identities or transport");
  if(List.of("http","https").contains(e.protocol)){
   if(AndroidImportedRouterPath.xrayFinal(finalMode)){check(selected.getString("transport_capability").equals("vless-stream"),"CONNECT REALITY capability was lost");connectReality(e,b,c);}
   else if(finalMode.equals("naive-h2")){check(selected.getString("transport_capability").equals("naive-h2-stream"),"CONNECT lost Naive H2 stream authority");}
   else{check(selected.getString("transport_capability").equals(b.getJSONObject("profiles").getJSONObject("shadowsocks").has("routervpn-ss-service.json")?"uot-v2":"tcp-only"),"CONNECT capability was lost");if(e.startLayer!=null)connectLayer(args,e,b,c);}
   if(fixture.getFileName().toString().contains("--2022-blake3-aes-256-gcm--home"))configuredCONNECT(e,b);
   JSONObject dns=graph.getJSONObject("dns").getJSONArray("servers").getJSONObject(0),saved=profile(b);
   if(!finalMode.equals("naive-h2"))check(dns.getString("type").equals(AndroidImportedRouterPath.xrayFinal(finalMode)?"udp":saved.getString("dns_protocol"))&&dns.getString("server").equals(AndroidImportedRouterPath.xrayFinal(finalMode)?saved.getString("adguard_ipv4"):saved.getString("dns_host"))&&dns.getInt("server_port")== (AndroidImportedRouterPath.xrayFinal(finalMode)?53:saved.getInt("dns_port"))&&dns.getString("detour").equals("proxy"),"CONNECT changed exact saved DNS");
   for(String execution:List.of("server","auto"))reject("CONNECT unsupported execution",()->AndroidImportedRouterPath.compile(e,b,finalMode,execution));
   for(String field:List.of("username","password"))reject("CONNECT replaced source "+field,()->{JSONObject changed=object(c.input),capture=object(changed.getString("entry_capture"));capture.getJSONObject("profile").getJSONObject("external").getJSONObject(AndroidExternalPolicy.protocol(e.protocol).replace("-","_")).put(field,"foreign");changed.put("entry_capture",capture.toString());AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});
  }
  if(e.protocol.equals("openvpn")){
   JSONObject captured=object(raw.getString("entry_capture")).getJSONObject("profile").getJSONObject("external").getJSONObject("openvpn");JSONObject first=null;JSONArray endpoints=graph.getJSONArray("endpoints");for(int i=0;i<endpoints.length();i++)if(endpoints.getJSONObject(i).optString("tag").equals("entry-wg"))first=endpoints.getJSONObject(i);
   check(captured.getString("config").equals(e.openVPNConfig)&&captured.getString("username").equals(e.username)&&captured.getString("password").equals(e.password),"OpenVPN original inline source or whitespace credentials changed");
   check(first!=null&&first.getString("type").equals("openvpn-client")&&!first.getBoolean("system")&&first.getInt("mtu")==1500&&first.getString("username").equals(e.username)&&first.getString("password").equals(e.password),"OpenVPN native endpoint or independent MTU changed");
   String[] sourceAxes=fixture.getFileName().toString().split("--");String wireNetwork=sourceAxes[0].equals("openvpn")?sourceAxes[1]:sourceAxes[0].replaceFirst("^openvpn-","");
   check(List.of("tcp","udp").contains(wireNetwork)&&first.getString("network").equals(wireNetwork),"OpenVPN original TCP/UDP transport changed");
   String layer=e.policy.optString("start_layer","off");if(layer.isEmpty())layer="off";
   check(first.getString("server").equals("203.0.113.24")&&first.getInt("server_port")==1194&&first.has("detour")==!layer.equals("off"),"OpenVPN original peer or owned layer changed");
   if(!layer.equals("off")){
    JSONObject mapping=null;JSONArray outs=graph.getJSONArray("outbounds");for(int i=0;i<outs.length();i++)if(outs.getJSONObject(i).optString("tag").equals(first.getString("detour")))mapping=outs.getJSONObject(i);
    check(mapping!=null&&mapping.getString("type").equals("routervpn-openvpn-layer-map")&&mapping.getString("mode").equals(layer)&&!mapping.has("detour"),"OpenVPN original identity lost owned layer map");
    JSONArray remotes=mapping.getJSONArray("remotes");JSONObject remote=remotes.getJSONObject(0),owners=mapping.getJSONObject("layers");
    check(remotes.length()==1&&remote.getString("host").equals("203.0.113.24")&&remote.getInt("port")==1194&&remote.getString("network").equals(first.getString("network"))&&owners.length()==1&&owners.getJSONObject("203.0.113.24").toString().equals(e.startLayer.toString()),"OpenVPN layer map changed original remote or private owner");
    check(object(raw.getString("entry_capture")).getJSONObject("profile").getJSONObject("external").getJSONObject("start_layer").toString().equals(e.startLayer.toString()),"OpenVPN captured private layer changed");
    AndroidStandardExitStore.Entry missing=AndroidStandardExitStore.copy(e);missing.startLayer=null;reject("OpenVPN missing own layer",()->AndroidImportedRouterPath.compile(missing,b,finalMode,"local"));
   }
   if(layer.equals("off")){
    AndroidStandardExitStore.Entry multi=AndroidStandardExitStore.copy(e);multi.openVPNConfig+="remote 203.0.113.25 1194\n";
    AndroidExternalPolicy.Captured capturedMulti=AndroidExternalPolicy.captureImportedEntry(multi);JSONObject endpoint=object(capturedMulti.source).getJSONArray("endpoints").getJSONObject(0);JSONArray remotes=endpoint.getJSONArray("servers");
    check(remotes.length()==2&&remotes.getJSONObject(0).getString("server").equals("203.0.113.24")&&remotes.getJSONObject(1).getString("server").equals("203.0.113.25")&&!endpoint.has("server"),"OpenVPN fallback capture collapsed original remote list");
    check(object(capturedMulti.capture).getJSONObject("profile").getJSONObject("external").getJSONObject("openvpn").getString("config").equals(multi.openVPNConfig),"OpenVPN multi-remote raw source was normalized away");
   }
   for(String unavailable:List.of("server","auto"))reject("OpenVPN cannot authorize "+unavailable,()->AndroidImportedRouterPath.compile(e,b,finalMode,unavailable));
   for(String field:List.of("config","username","password"))reject("changed OpenVPN source "+field,()->{JSONObject changed=object(c.input),capture=object(changed.getString("entry_capture"));capture.getJSONObject("profile").getJSONObject("external").getJSONObject("openvpn").put(field,"foreign");changed.put("entry_capture",capture.toString());AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});
  }
  if(e.protocol.equals("socks5")){
   JSONObject captured=object(raw.getString("entry_capture")).getJSONObject("profile").getJSONObject("external").getJSONObject("socks5");JSONObject first=null;JSONArray out=graph.getJSONArray("outbounds");for(int i=0;i<out.length();i++)if(out.getJSONObject(i).optString("tag").equals("entry-wg"))first=out.getJSONObject(i);
   check(first!=null&&first.getString("type").equals("socks")&&first.getString("version").equals("5")&&first.getString("username").equals(e.username)&&first.getString("password").equals(e.password),"SOCKS native credentials changed");
   check(captured.getString("username").equals(e.username)&&captured.getString("password").equals(e.password),"captured SOCKS credentials changed");
   String entryLayer=e.policy.optString("start_layer","off"),finalLayer=profile(b).optString("start_layer","off");
   check(object(raw.getString("entry_capture")).getJSONObject("profile").optString("start_layer","off").equals(entryLayer)&&object(raw.getString("exit_profile")).optString("start_layer","off").equals(finalLayer),"SOCKS independent layer selections changed");
   if(!entryLayer.equals("off")){
    JSONObject provision=object(raw.getString("entry_capture")).getJSONObject("profile").getJSONObject("external").getJSONObject("start_layer");
    check(provision.toString().equals(e.startLayer.toString())&&provision.getString("mode").equals(entryLayer),"SOCKS wrapper private provision changed");
    check(first.has("detour")&&first.getString("server").equals(java.net.URI.create(provision.getString("api")).getHost())&&first.getInt("server_port")==e.serverPort,"SOCKS wrapper did not retain inside peer and native detour");
    AndroidStandardExitStore.Entry missing=AndroidStandardExitStore.copy(e);missing.startLayer=null;
    reject("SOCKS enabled wrapper requires private provision",()->AndroidImportedRouterPath.compile(missing,b,finalMode,"local"));
    reject("SOCKS changed wrapper credential",()->{JSONObject changed=object(c.input),capture=object(changed.getString("entry_capture"));capture.getJSONObject("profile").getJSONObject("external").getJSONObject("start_layer").getJSONObject("transport").put("password",java.util.Base64.getEncoder().encodeToString("Z".repeat(32).getBytes(StandardCharsets.UTF_8)));changed.put("entry_capture",capture.toString());AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});
   }else check(!first.has("detour")&&first.getString("server").equals(e.server)&&first.getInt("server_port")==e.serverPort,"unwrapped SOCKS physical peer changed");
   for(String unavailable:List.of("server","auto"))reject("SOCKS layers do not authorize "+unavailable,()->AndroidImportedRouterPath.compile(e,b,finalMode,unavailable));
   for(String field:List.of("username","password"))reject("changed SOCKS source "+field,()->{JSONObject changed=object(c.input),capture=object(changed.getString("entry_capture"));capture.getJSONObject("profile").getJSONObject("external").getJSONObject("socks5").put(field,"foreign");changed.put("entry_capture",capture.toString());AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});
  }
  if(e.protocol.equals("hysteria2")){
   JSONObject captured=object(raw.getString("entry_capture")).getJSONObject("profile").getJSONObject("external").getJSONObject("hysteria2");JSONObject first=null;JSONArray out=graph.getJSONArray("outbounds");for(int i=0;i<out.length();i++)if(out.getJSONObject(i).optString("tag").equals("entry-wg"))first=out.getJSONObject(i);
   check(captured.getString("password").equals(e.secret)&&captured.getString("tls_server_name").equals(e.tlsServerName),"host changed captured QUIC password or TLS name");
   check(first!=null&&first.getString("type").equals("hysteria2")&&first.getString("password").equals(e.secret)&&first.getJSONObject("tls").getString("server_name").equals(e.tlsServerName)&&first.getJSONObject("tls").getBoolean("enabled")&&!first.getJSONObject("tls").optBoolean("insecure",false),"host changed native QUIC TLS/password policy");
   for(String field:List.of("password","tls_server_name"))reject("changed imported "+field,()->{JSONObject changed=object(c.input),capture=object(changed.getString("entry_capture"));capture.getJSONObject("profile").getJSONObject("external").getJSONObject("hysteria2").put(field,"replacement.example");changed.put("entry_capture",capture.toString());AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});
  }
  if(List.of("wireguard","amneziawg").contains(e.protocol)){
   JSONObject captured=object(raw.getString("entry_capture")).getJSONObject("profile").getJSONObject("external").getJSONObject(e.protocol);JSONObject first=null;JSONArray endpoints=graph.getJSONArray("endpoints");for(int i=0;i<endpoints.length();i++)if(endpoints.getJSONObject(i).optString("tag").equals("entry-wg"))first=endpoints.getJSONObject(i);
   check(first!=null&&first.getString("type").equals(e.protocol.equals("amneziawg")?"routervpn-amneziawg":"wireguard"),"host omitted or substituted original packet endpoint");
   JSONObject peer=first.getJSONArray("peers").getJSONObject(0);
   check(first.getString("private_key").equals(e.wgPrivateKey)&&peer.getString("public_key").equals(e.wgPeerPublicKey)&&peer.optString("pre_shared_key","").equals(e.wgPreSharedKey),"host changed original packet private/public/PSK ownership");
   check(captured.getString("private_key").equals(e.wgPrivateKey)&&captured.getString("peer_public_key").equals(e.wgPeerPublicKey)&&captured.optString("preshared_key","").equals(e.wgPreSharedKey),"host lost captured packet credentials");
   check(first.getInt("mtu")==e.wgMtu&&first.getJSONArray("address").toString().equals(new JSONArray(e.wgAddresses).toString())&&peer.getJSONArray("allowed_ips").toString().equals(new JSONArray(e.wgAllowedIps).toString()),"host changed packet endpoint MTU, addresses or routes");
   check(e.wgKeepalive==null?!peer.has("persistent_keepalive_interval"):peer.getInt("persistent_keepalive_interval")==e.wgKeepalive,"host changed captured packet keepalive");
   if(e.protocol.equals("amneziawg"))for(String key:List.of("jc","jmin","jmax","s1","s2","s3","s4","h1","h2","h3","h4"))check(first.getJSONObject("amnezia").getString(key).equals(e.awgParameters.getString(key)),"host changed captured AWG parameter "+key);
   for(String field:List.of("private_key","peer_public_key","preshared_key","endpoint","mtu","persistent_keepalive_interval"))reject("changed captured packet "+field,()->{JSONObject changed=object(c.input),capture=object(changed.getString("entry_capture"));JSONObject packet=capture.getJSONObject("profile").getJSONObject("external").getJSONObject(e.protocol);if(field.equals("mtu"))packet.put(field,e.wgMtu+1);else if(field.equals("persistent_keepalive_interval"))packet.put(field,e.wgKeepalive==null?21:e.wgKeepalive+1);else if(field.equals("endpoint"))packet.put(field,"203.0.113.99:40000");else packet.put(field,java.util.Base64.getEncoder().encodeToString("X".repeat(32).getBytes(StandardCharsets.UTF_8)));changed.put("entry_capture",capture.toString());AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});
   if(e.protocol.equals("amneziawg"))reject("changed captured AWG parameter",()->{JSONObject changed=object(c.input),capture=object(changed.getString("entry_capture"));capture.getJSONObject("profile").getJSONObject("external").getJSONObject(e.protocol).getJSONObject("parameters").put("s1","37");changed.put("entry_capture",capture.toString());AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});
  }
  if(AndroidImportedRouterPath.xrayFinal(finalMode)&&List.of("shadowsocks","hysteria2").contains(e.protocol)){
   JSONObject first=null;JSONArray rows=graph.getJSONArray("outbounds");for(int i=0;i<rows.length();i++)if(rows.getJSONObject(i).optString("tag").equals("entry-wg"))first=rows.getJSONObject(i);
   check(first!=null&&first.getString("type").equals(e.protocol)&&first.getString("password").equals(e.secret),"REALITY changed original encrypted entry authentication");
   if(e.protocol.equals("shadowsocks"))check(first.getString("method").equals(e.method),"REALITY changed selected SS2022 method");
   else check(first.getJSONObject("tls").getBoolean("enabled")&&!first.getJSONObject("tls").optBoolean("insecure")&&first.getJSONObject("tls").getString("server_name").equals(e.tlsServerName),"REALITY changed original Hysteria TLS identity");
   String layer=e.policy.optString("start_layer","off");boolean layered=!List.of("","off").contains(layer);
   if(layered){
    JSONObject outer=null;for(int i=0;i<rows.length();i++)if(rows.getJSONObject(i).optString("tag").equals(first.getString("detour")))outer=rows.getJSONObject(i);
    JSONObject transport=e.startLayer.getJSONObject("transport");
    check(outer!=null&&!outer.has("detour")&&outer.getString("password").equals(transport.getString("password"))&&outer.getString("server").equals(transport.getString("server"))&&outer.getInt("server_port")== (layer.equals("aes-256-gcm+xor-whitening")?8389:transport.getInt("server_port"))&&outer.getString("type").equals(layer.equals("aes-256-gcm+xor-whitening")?"routervpn-aes-xor":"shadowsocks"),"REALITY entry wrapper changed independent endpoint key or codec");
    check(first.getString("server").equals(java.net.URI.create(e.startLayer.getString("api")).getHost())&&first.getInt("server_port")==e.serverPort,"REALITY encrypted entry lost original private destination");
    AndroidStandardExitStore.Entry missing=AndroidStandardExitStore.copy(e);missing.startLayer=null;reject("REALITY encrypted entry requires its own provision",()->AndroidImportedRouterPath.compile(missing,b,finalMode,"local"));
    reject("REALITY replaced encrypted entry wrapper key",()->{JSONObject changed=object(c.input),capture=object(changed.getString("entry_capture"));capture.getJSONObject("profile").getJSONObject("external").getJSONObject("start_layer").getJSONObject("transport").put("password",java.util.Base64.getEncoder().encodeToString("Z".repeat(32).getBytes(StandardCharsets.UTF_8)));changed.put("entry_capture",capture.toString());AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});
   }else check(!first.has("detour")&&first.getString("server").equals(e.server)&&first.getInt("server_port")==e.serverPort,"REALITY encrypted entry changed its original physical owner");
   for(String field:List.of("server","password"))reject("REALITY replaced original encrypted entry "+field,()->{JSONObject changed=object(c.input),capture=object(changed.getString("entry_capture"));capture.getJSONObject("profile").getJSONObject("external").getJSONObject(e.protocol).put(field,"foreign-original");changed.put("entry_capture",capture.toString());AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});
   if(e.protocol.equals("shadowsocks"))for(String key:List.of("bad-key",java.util.Base64.getEncoder().encodeToString("x".repeat(31).getBytes(StandardCharsets.UTF_8)),java.util.Base64.getEncoder().encodeToString("x".repeat(33).getBytes(StandardCharsets.UTF_8)))){AndroidStandardExitStore.Entry malformed=AndroidStandardExitStore.copy(e);malformed.secret=key;reject("REALITY rejects malformed inner SS2022 key",()->AndroidImportedRouterPath.compile(malformed,b,finalMode,"local"));}
   for(String execution:List.of("server","auto"))reject("REALITY encrypted entry cannot acquire "+execution,()->AndroidImportedRouterPath.compile(e,b,finalMode,execution));
  }
  if(AndroidImportedRouterPath.xrayFinal(finalMode)){
   JSONObject assets=object(raw.getString("exit_files"));
   check(assets.toString().equals(object(args.getString(3)).toString())&&assets.has("xray.json")&&assets.has("sing-box.json"),"REALITY lost complete original Xray assets");
   check(List.of("socks5","shadowsocks","hysteria2","http","https","wireguard","amneziawg","openvpn").contains(e.protocol)&&selected.getString("exit_mode").equals(finalMode),"REALITY expanded exact captured entry");
   JSONObject finalNative=null,outer=null;JSONArray nativeOut=graph.getJSONArray("outbounds");for(int i=0;i<nativeOut.length();i++){JSONObject n=nativeOut.getJSONObject(i);if(n.optString("tag").equals("routervpn-execution-local"))finalNative=n;if(n.optString("tag").equals("start-layer-aes"))outer=n;}
   String finalLayer=profile(b).optString("start_layer","off");boolean layered=!List.of("","off").contains(finalLayer);
   check(finalNative!=null&&finalNative.getString("type").equals("routervpn-xray")&&finalNative.getString("mode").equals(finalMode)&&finalNative.getString("detour").equals(layered?"start-layer-aes":"entry-wg"),"REALITY lost selected inner layer edge");
   check(layered?outer!=null&&outer.getString("detour").equals("entry-wg")&&!raw.getString("exit_start").isEmpty():outer==null&&raw.getString("exit_start").isEmpty(),"REALITY lost independent final layer provision");
   for(String mode:List.of("reality-pq-vision","reality-xhttp","split","max","max-tls-wg"))check(AndroidImportedRouterPath.supports("socks5",mode)==List.of("reality-pq-vision","reality-xhttp").contains(mode),"REALITY changed exact admitted final "+mode);
   for(String kind:List.of("openvpn","wireguard","amneziawg","shadowsocks","hysteria2","http-connect","https-connect"))check(AndroidImportedRouterPath.supports(kind,finalMode),"REALITY refused captured entry "+kind);
   for(String kind:List.of("tor","reality-pq-vision","reality-xhttp","unknown"))check(!AndroidImportedRouterPath.supports(kind,finalMode),"REALITY admitted unsupported entry "+kind);
   JSONObject unprovisioned=object(b.toString());profile(unprovisioned).put("start_layer","aes-256-gcm");unprovisioned.getJSONObject("profiles").remove("shadowsocks");reject("REALITY final layer requires own provision",()->AndroidImportedRouterPath.compile(e,unprovisioned,finalMode,"local"));
   AndroidStandardExitStore.Entry unowned=AndroidStandardExitStore.copy(e);unowned.policy.put("start_layer","aes-256-gcm");unowned.startLayer=null;reject("REALITY entry layer requires own provision",()->AndroidImportedRouterPath.compile(unowned,b,finalMode,"local"));
   if(layered)reject("REALITY replaced final layer original bytes",()->{JSONObject changed=object(c.input);changed.put("exit_start",changed.getString("exit_start")+" ");AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});
   for(String name:List.of("xray.json","sing-box.json")){
    JSONObject missing=object(b.toString());missing.getJSONObject("profiles").getJSONObject(finalMode).remove(name);if(!finalMode.equals("reality-xhttp")||!name.equals("sing-box.json"))reject("REALITY missing original "+name,()->AndroidImportedRouterPath.compile(e,missing,finalMode,"local"));
    reject("REALITY replaced original "+name,()->{JSONObject changed=object(c.input),files=object(changed.getString("exit_files"));String original=new String(Base64.getDecoder().decode(files.getString(name)),StandardCharsets.UTF_8);files.put(name,Base64.getEncoder().encodeToString((original+"\n").getBytes(StandardCharsets.UTF_8)));changed.put("exit_files",files.toString());AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});
   }
   reject("REALITY replaced valid UUID",()->{JSONObject changed=object(c.input),files=object(changed.getString("exit_files"));String original=new String(Base64.getDecoder().decode(files.getString("xray.json")),StandardCharsets.UTF_8);String replacement=original.replaceFirst("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}","99999999-9999-4999-8999-999999999999");check(!replacement.equals(original),"REALITY UUID fixture did not change");files.put("xray.json",Base64.getEncoder().encodeToString(replacement.getBytes(StandardCharsets.UTF_8)));changed.put("exit_files",files.toString());AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});
  }
  if(List.of("wg","awg2-fast","awg2-strong").contains(finalMode)){
   check(raw.getString("exit_files").equals(object(args.getString(3)).toString()),"host replaced captured paired packet assets");
   JSONObject last=null;JSONArray endpoints=graph.getJSONArray("endpoints");for(int i=0;i<endpoints.length();i++)if(endpoints.getJSONObject(i).optString("tag").equals("routervpn-execution-local"))last=endpoints.getJSONObject(i);
   check(last!=null&&last.getString("type").equals(finalMode.equals("wg")?"wireguard":"routervpn-amneziawg"),"host omitted or substituted paired packet endpoint");
   check(last.getInt("mtu")>=1280&&!last.getString("private_key").isEmpty()&&!last.getJSONArray("peers").getJSONObject(0).getString("public_key").isEmpty(),"host lost paired packet MTU or key sources");
   for(String key:List.of("exit_files","exit_start")){if(raw.getString(key).isEmpty())continue;reject("changed paired packet original source",()->{JSONObject changed=object(c.input);changed.put(key,raw.getString(key)+" ");AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});}
   if(!finalMode.equals("wg"))check(last.has("amnezia"),"host lost captured final AWG parameters");
  }
  check(selected.optString("entry_api").isEmpty()&&selected.optString("entry_token").isEmpty()&&selected.optString("entry_node_id").isEmpty(),"import acquired private pairing");
  check(raw.getString("exit_start").equals(args.getString(5).isEmpty()?"":object(args.getString(5)).toString())&&object(raw.getString("entry_capture")).getJSONObject("profile").getString("dns_mode").equals(object(args.getString(1)).getJSONObject("profile").getString("dns_mode")),"raw entry policy or inherent final layer changed");
  JSONObject dns=graph.getJSONObject("dns").getJSONArray("servers").getJSONObject(0);
  check(dns.getString("server").equals(List.of("http","https").contains(e.protocol)&&!AndroidImportedRouterPath.xrayFinal(finalMode)&&!finalMode.equals("naive-h2")?profile(b).getString("dns_host"):"192.168.50.133")&&dns.getString("detour").equals("proxy"),"exact selected final DNS policy lost");
  try{RouterMultihop exact=AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,c.input);check(exact.sourceSHA256().equals(c.source),"reconstruction source changed");exact.close();}finally{check(RouterMultihop.open==0,"pure compilation leaked");}
  AndroidImportedRouterPath.requireSessionMode("multihop-imported-"+finalMode,c.metadata);
  reject("changed final session label",()->AndroidImportedRouterPath.requireSessionMode("multihop-imported-"+(finalMode.equals("shadowsocks")?"hysteria2":"shadowsocks"),c.metadata));
  reject("changed final source mode",()->AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,object(c.input).put("exit_mode",finalMode.equals("shadowsocks")?"hysteria2":"shadowsocks").toString()));
  if(!finalMode.equals("shadowsocks")&&!args.getString(5).isEmpty()){
   check(object(raw.getString("exit_start")).has("sing-box.json")&&!object(raw.getString("exit_start")).has("profile"),"final layer did not keep its raw original asset map");
   JSONObject missing=object(b.toString());missing.getJSONObject("profiles").remove("shadowsocks");reject("missing final layer source",()->AndroidImportedRouterPath.compile(e,missing,finalMode,"local"));
   reject("wrapped final layer source",()->AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,object(c.input).put("exit_start",new JSONObject().put("mode",profile(b).getString("start_layer")).put("profile",object(args.getString(5))).toString()).toString()));
  }
  export(fixture.getFileName().toString(),c);
  if(fixture.getFileName().toString().equals("off--off--2022-blake3-aes-256-gcm.json")){
   for(String kind:List.of("absent","")){JSONObject legacy=object(b.toString());if(kind.equals("absent"))profile(legacy).remove("node_kind");else profile(legacy).put("node_kind",kind);String bytes=legacy.toString();var compiled=AndroidImportedRouterPath.compile(e,legacy,finalMode,"local");check(compiled.config.equals(c.config)&&!compiled.source.equals(c.source)&&legacy.toString().equals(bytes),"legacy normalization changed original source or graph");JSONObject frozen=object(object(compiled.input).getString("exit_profile"));check(kind.equals("absent")?!frozen.has("node_kind"):frozen.getString("node_kind").isEmpty(),"legacy source was rewritten before hashing");}
   for(Object invalid:List.of("external",true,JSONObject.NULL)){JSONObject changed=object(b.toString());profile(changed).put("node_kind",invalid);reject("unpaired final kind",()->AndroidImportedRouterPath.compile(e,changed,finalMode,"local"));}
   for(String historical:List.of("server","auto")){JSONObject importedFinal=object(b.toString());profile(importedFinal).put("multihop_execution",historical);String original=importedFinal.toString();var compiled=AndroidImportedRouterPath.compile(e,importedFinal,finalMode,"local");check(original.equals(importedFinal.toString())&&profile(importedFinal).getString("multihop_execution").equals(historical),"selected Local projection changed original final source");check(object(object(compiled.input).getString("exit_profile")).getString("multihop_execution").equals("local")&&compiled.config.equals(c.config),"historical final preference replaced explicit Local graph");reject("explicit Server remains unavailable",()->AndroidImportedRouterPath.compile(e,importedFinal,finalMode,"server"));}
  }

  reject("forged graph",()->AndroidImportedRouterPath.prepareExecution(c.config+" ",c.metadata,c.input));
  reject("forged metadata",()->AndroidImportedRouterPath.prepareExecution(c.config,c.metadata+" ",c.input));
  reject("forged source hash",()->AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,object(c.input).put("source_sha256","a".repeat(64)).toString()));
  reject("noninteger schema",()->AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,c.input.replace("\"schema\":1", "\"schema\":1.0")));
  reject("extra source field",()->AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,object(c.input).put("borrowed_api","http://127.0.0.1").toString()));
  reject("duplicate session field",()->AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,"{\"schema\":1,"+c.input.substring(1)));
  reject("trailing session object",()->AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,c.input+"{}"));
  reject("wrong final key source",()->{JSONObject changed=object(c.input);JSONObject p=object(changed.getString("exit_profile"));p.put("api_token","replacement-secret");changed.put("exit_profile",p.toString());AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});
  for(String execution:List.of("server","auto"))reject(execution,()->AndroidImportedRouterPath.compile(e,b,finalMode,execution));
  reject("different final protocol",()->AndroidImportedRouterPath.compile(e,b,"split","local"));
  if(List.of("wireguard","amneziawg").contains(e.protocol)&&!List.of("wg","awg2-fast","awg2-strong").contains(finalMode))for(String nested:List.of("wg","awg2-fast","awg2-strong"))reject("unproved nested packet graph",()->AndroidImportedRouterPath.compile(e,b,nested,"local"));
  JSONObject same=object(b.toString());profile(same).put("id",e.id);same.put("selectedRouterID",e.id);reject("same source identity",()->AndroidImportedRouterPath.compile(e,same,finalMode,"local"));
  JSONObject unpaired=object(b.toString());profile(unpaired).remove("node_proof_id");reject("unpaired final",()->AndroidImportedRouterPath.compile(e,unpaired,finalMode,"local"));
  Path privateRoot=Files.createTempDirectory(root,"sources-");android.content.Context context=new android.content.Context(privateRoot.toFile());AndroidStandardExitStore store=new AndroidStandardExitStore(context);store.save(e);
  Path file=privateRoot.resolve("final.json");Files.writeString(file,b.toString());
  AndroidMultihopController.Source original=AndroidImportedRouterPath.captureSource(context,e),last=AndroidMultihopController.captureSource(file.toFile(),Files.readAllBytes(file));
  check(original.file==null&&original.imported()&&!original.same(last),"import borrowed a private Router source");
  sourceDoesNotWaitForMutation(original);
  reject("import supplied paired file",()->original.require(file.toFile()));
  AndroidMultihopController.Prepared prepared=AndroidImportedRouterPath.prepare(context,original,file.toFile(),finalMode,"local",last);
  Path staged=privateRoot.resolve("layered-sessions").resolve(prepared.session.sessionId);
  check(prepared.session.mode.equals("multihop-imported-"+finalMode)&&Files.readString(staged.resolve(AndroidImportedRouterPath.SESSION_FILE)).equals(c.input),"staged owner differs from original source");
  check(Files.exists(staged.resolve(AndroidKillSwitchPolicy.SESSION_MARKER))==AndroidImportedRouterPath.requiresProtection(c.input),"strict protection marker mismatch");
  java.io.File owned=staged.toFile().getCanonicalFile(),executionFile=staged.resolve("routervpn-multihop.json").toFile().getCanonicalFile(),entryLayerFile=staged.resolve("entry-layer.json").toFile().getCanonicalFile(),exitLayerFile=staged.resolve("exit-layer.json").toFile().getCanonicalFile(),importedEntryFile=staged.resolve(AndroidImportedRouterPath.SESSION_FILE).toFile().getCanonicalFile();
  LayeredVpnService.requireOwnedImportedFiles(owned,prepared.session.mode,executionFile,entryLayerFile,exitLayerFile,importedEntryFile);check(true,"actual service accepted captured imported mode");
  reject("service unknown imported mode",()->LayeredVpnService.requireOwnedImportedFiles(owned,"multihop-imported-split",executionFile,entryLayerFile,exitLayerFile,importedEntryFile));
  reject("service missing final metadata",()->LayeredVpnService.requireOwnedImportedFiles(owned,prepared.session.mode,staged.resolve("absent.json").toFile(),entryLayerFile,exitLayerFile,importedEntryFile));
  Files.writeString(entryLayerFile.toPath(),"foreign layer");try{reject("service extra layer owner",()->LayeredVpnService.requireOwnedImportedFiles(owned,prepared.session.mode,executionFile,entryLayerFile,exitLayerFile,importedEntryFile));}finally{Files.delete(entryLayerFile.toPath());}
  reject("service missing original capture",()->LayeredVpnService.requireOwnedImportedFiles(owned,prepared.session.mode,executionFile,entryLayerFile,exitLayerFile,staged.resolve("absent.json").toFile()));

  long count;try(var dirs=Files.list(staged.getParent())){count=dirs.count();}
  AndroidPrivateFileStore.failName=AndroidImportedRouterPath.SESSION_FILE;
  try{reject("private staging failure",()->AndroidImportedRouterPath.prepare(context,original,file.toFile(),finalMode,"local",last));}finally{AndroidPrivateFileStore.failName="";}
  try(var dirs=Files.list(staged.getParent())){check(dirs.count()==count,"failed staging left a private workspace");}
  Libbox.hook=()->{try{Files.writeString(file,b.toString()+" ");}catch(Exception err){throw new RuntimeException(err);}};
  reject("source replaced during native compile",()->AndroidImportedRouterPath.prepare(context,original,file.toFile(),finalMode,"local",last));
  try(var dirs=Files.list(staged.getParent())){check(dirs.count()==count,"source mutation staged an owner");}
  Files.writeString(file,b.toString());AndroidStandardExitStore.Entry replacement=AndroidStandardExitStore.copy(e);replacement.name="Replacement import";store.save(replacement);
  reject("changed imported capture",()->original.require(null));
  reject("changed imported restore",()->AndroidImportedRouterPath.prepare(context,original,file.toFile(),finalMode,"local",last));
  check(RouterMultihop.open==0,"constructor ownership escaped fixture");
 }
 public static void main(String[] args)throws Exception{
  Libbox.compiler=args[0];importedMemberBoundary();Path root=Path.of(args[1]),fixtures=Path.of(args[2]);retainedStaging(Files.createTempDirectory(root,"retained-staging-"));List<Path> all;
  if(args[3].startsWith("naive-h2--")){
   String kind=args[3].substring("naive-h2--".length());List<String> kinds=List.of("socks5","shadowsocks","hysteria2","http-connect","https-connect","wireguard","amneziawg","openvpn-tcp","openvpn-udp");check(kinds.contains(kind),"unknown Naive H2 entry phase");
   Path sources=Path.of(System.getenv("ROUTERVPN_IMPORTED_NAIVE_H2_SOURCES"));List<Path> paths;try(var entries=Files.list(sources)){paths=entries.sorted().toList();}
   Set<String> expected=new HashSet<>();for(String protocol:kinds)for(String first:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))for(String last:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))expected.add(protocol+"--naive-h2--"+first+"--"+last+".json");
   check(paths.size()==81&&new HashSet<>(paths.stream().map(p->p.getFileName().toString()).toList()).equals(expected),"incomplete independent Naive H2 sources");for(Path p:paths)check(!Files.isSymbolicLink(p)&&Files.isRegularFile(p)&&Files.size(p)>0&&Files.size(p)<=32*1024*1024,"unowned Naive H2 source");
   List<Path> selected=paths.stream().filter(p->p.getFileName().toString().startsWith(kind+"--")).toList();check(selected.size()==9,"incomplete independent Naive H2 phase");exportEnvironment="ROUTERVPN_ANDROID_IMPORTED_NAIVE_H2_FIXTURES";for(Path p:selected)one(root,p);
   System.out.println("Android Naive H2 entries: "+checks+" checks; "+kind+", "+selected.size()+" original independent layer graphs");return;
  }
  if(args[3].startsWith("naive-h3--")){
   String kind=args[3].substring("naive-h3--".length());List<String> kinds=List.of("socks5","shadowsocks","hysteria2","wireguard","amneziawg","openvpn-tcp","openvpn-udp");check(kinds.contains(kind),"unknown Naive H3 entry phase");
   Path sources=Path.of(System.getenv("ROUTERVPN_IMPORTED_NAIVE_H3_SOURCES"));List<Path> paths;try(var entries=Files.list(sources)){paths=entries.sorted().toList();}
   Set<String> expected=new HashSet<>();for(String protocol:kinds)for(String first:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))for(String last:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))expected.add(protocol+"--naive-h3--"+first+"--"+last+".json");
   check(paths.size()==63&&new HashSet<>(paths.stream().map(p->p.getFileName().toString()).toList()).equals(expected),"incomplete independent Naive H3 sources");for(Path p:paths)check(!Files.isSymbolicLink(p)&&Files.isRegularFile(p)&&Files.size(p)>0&&Files.size(p)<=32*1024*1024,"unowned Naive H3 source");
   List<Path> selected=paths.stream().filter(p->p.getFileName().toString().startsWith(kind+"--")).toList();check(selected.size()==9,"incomplete independent Naive H3 phase");exportEnvironment="ROUTERVPN_ANDROID_IMPORTED_NAIVE_H3_FIXTURES";for(Path p:selected)one(root,p);
   System.out.println("Android Naive H3 entries: "+checks+" checks; "+kind+", "+selected.size()+" original independent layer graphs");return;
  }
  if(args[3].startsWith("xhttp--")){
   String kind=args[3].substring("xhttp--".length());List<String> kinds=List.of("socks5","shadowsocks","hysteria2","http-connect","https-connect","wireguard","amneziawg","openvpn-tcp","openvpn-udp");check(kinds.contains(kind),"unknown XHTTP entry phase");
   Path sources=Path.of(System.getenv("ROUTERVPN_IMPORTED_XHTTP_XRAY_SOURCES"));List<Path> paths;try(var entries=Files.list(sources)){paths=entries.sorted().toList();}
   Set<String> expected=new HashSet<>();for(String protocol:kinds)for(String first:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))for(String last:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))expected.add(protocol+"--reality-xhttp--"+first+"--"+last+".json");
   check(paths.size()==81&&new HashSet<>(paths.stream().map(p->p.getFileName().toString()).toList()).equals(expected),"incomplete independent XHTTP sources");for(Path p:paths)check(!Files.isSymbolicLink(p)&&Files.isRegularFile(p)&&Files.size(p)>0&&Files.size(p)<=32*1024*1024,"unowned XHTTP source");
   List<Path> selected=paths.stream().filter(p->p.getFileName().toString().startsWith(kind+"--")).toList();check(selected.size()==9,"incomplete independent XHTTP phase");exportEnvironment="ROUTERVPN_ANDROID_IMPORTED_XHTTP_XRAY_FIXTURES";for(Path p:selected)one(root,p);
   System.out.println("Android XHTTP entries: "+checks+" checks; "+kind+", "+selected.size()+" original independent layer graphs");return;
  }
  if(args[3].startsWith("pq-reality--")){
   String kind=args[3].substring("pq-reality--".length());List<String> kinds=List.of("socks5","shadowsocks","hysteria2","http-connect","https-connect","wireguard","amneziawg","openvpn-tcp","openvpn-udp");check(kinds.contains(kind),"unknown PQ REALITY entry phase");
   Path sources=Path.of(System.getenv("ROUTERVPN_IMPORTED_PQ_XRAY_SOURCES"));List<Path> paths;try(var entries=Files.list(sources)){paths=entries.sorted().toList();}
   Set<String> expected=new HashSet<>();for(String protocol:kinds)for(String first:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))for(String last:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))expected.add(protocol+"--reality-pq-vision--"+first+"--"+last+".json");
   check(paths.size()==81&&new HashSet<>(paths.stream().map(p->p.getFileName().toString()).toList()).equals(expected),"incomplete independent PQ REALITY sources");for(Path p:paths)check(!Files.isSymbolicLink(p)&&Files.isRegularFile(p)&&Files.size(p)>0&&Files.size(p)<=32*1024*1024,"unowned PQ REALITY source");
   List<Path> selected=paths.stream().filter(p->p.getFileName().toString().startsWith(kind+"--")).toList();check(selected.size()==9,"incomplete independent PQ REALITY phase");exportEnvironment="ROUTERVPN_ANDROID_IMPORTED_PQ_XRAY_FIXTURES";for(Path p:selected)one(root,p);
   System.out.println("Android PQ REALITY entries: "+checks+" checks; "+kind+", "+selected.size()+" original independent layer graphs");return;
  }
  if(args[3].startsWith("packet-reality--")){
   String kind=args[3].substring("packet-reality--".length());check(List.of("wireguard","amneziawg","openvpn-tcp","openvpn-udp").contains(kind),"unknown packet REALITY entry phase");
   Path sources=Path.of(System.getenv("ROUTERVPN_IMPORTED_PACKET_XRAY_SOURCES"));List<Path> paths;try(var entries=Files.list(sources)){paths=entries.sorted().toList();}
   Set<String> expected=new HashSet<>();for(String protocol:List.of("wireguard","amneziawg","openvpn-tcp","openvpn-udp"))for(String first:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))for(String last:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))expected.add(protocol+"--reality-vision--"+first+"--"+last+".json");
   check(paths.size()==36&&new HashSet<>(paths.stream().map(p->p.getFileName().toString()).toList()).equals(expected),"incomplete independent packet REALITY sources");for(Path p:paths)check(!Files.isSymbolicLink(p)&&Files.isRegularFile(p)&&Files.size(p)>0&&Files.size(p)<=32*1024*1024,"unowned packet REALITY source");
   List<Path> selected=paths.stream().filter(p->p.getFileName().toString().startsWith(kind+"--")).toList();check(selected.size()==9,"incomplete independent packet REALITY phase");exportEnvironment="ROUTERVPN_ANDROID_IMPORTED_PACKET_XRAY_FIXTURES";for(Path p:selected)one(root,p);
   System.out.println("Android packet REALITY entries: "+checks+" checks; "+kind+", "+selected.size()+" original independent layer graphs");return;
  }
  if(args[3].startsWith("connect-reality--")){
   String kind=args[3].substring("connect-reality--".length());check(List.of("http-connect","https-connect").contains(kind),"unknown CONNECT REALITY entry phase");
   Path sources=Path.of(System.getenv("ROUTERVPN_IMPORTED_CONNECT_XRAY_SOURCES"));List<Path> paths;try(var entries=Files.list(sources)){paths=entries.sorted().toList();}
   Set<String> expected=new HashSet<>();for(String protocol:List.of("http-connect","https-connect"))for(String first:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))for(String last:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))expected.add(protocol+"--reality-vision--"+first+"--"+last+".json");
   check(paths.size()==18&&new HashSet<>(paths.stream().map(p->p.getFileName().toString()).toList()).equals(expected),"incomplete independent CONNECT REALITY sources");for(Path p:paths)check(!Files.isSymbolicLink(p)&&Files.isRegularFile(p)&&Files.size(p)>0&&Files.size(p)<=32*1024*1024,"unowned CONNECT REALITY source");
   List<Path> selected=paths.stream().filter(p->p.getFileName().toString().startsWith(kind+"--")).toList();check(selected.size()==9,"incomplete independent CONNECT REALITY phase");exportEnvironment="ROUTERVPN_ANDROID_IMPORTED_CONNECT_XRAY_FIXTURES";for(Path p:selected)one(root,p);
   System.out.println("Android CONNECT REALITY entries: "+checks+" checks; "+kind+", "+selected.size()+" original independent layer graphs");return;
  }
  if(args[3].startsWith("proxy-reality--")){
   String kind=args[3].substring("proxy-reality--".length());check(List.of("shadowsocks","hysteria2").contains(kind),"unknown encrypted REALITY entry phase");
   Path sources=Path.of(System.getenv("ROUTERVPN_IMPORTED_PROXY_XRAY_SOURCES"));List<Path> paths;try(var entries=Files.list(sources)){paths=entries.sorted().toList();}
   Set<String> expected=new HashSet<>();for(String protocol:List.of("shadowsocks","hysteria2"))for(String first:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))for(String last:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))expected.add(protocol+"--reality-vision--"+first+"--"+last+".json");
   check(paths.size()==18&&new HashSet<>(paths.stream().map(p->p.getFileName().toString()).toList()).equals(expected),"incomplete independent encrypted REALITY sources");for(Path p:paths)check(!Files.isSymbolicLink(p)&&Files.isRegularFile(p)&&Files.size(p)>0&&Files.size(p)<=32*1024*1024,"unowned encrypted REALITY source");
   List<Path> selected=paths.stream().filter(p->p.getFileName().toString().startsWith(kind+"--")).toList();check(selected.size()==9,"incomplete independent encrypted REALITY phase");exportEnvironment="ROUTERVPN_ANDROID_IMPORTED_PROXY_XRAY_FIXTURES";for(Path p:selected)one(root,p);
   System.out.println("Android encrypted REALITY entries: "+checks+" checks; "+kind+", "+selected.size()+" original independent layer graphs");return;
  }
  if(args[3].startsWith("connect-entry-layers--")){
   String phase=args[3].substring("connect-entry-layers--".length());Set<String> expected=new HashSet<>();for(String kind:List.of("http-connect","https-connect"))for(String layer:List.of("aes-256-gcm","aes-256-gcm+xor-whitening"))for(String last:List.of("plain","off","aes-256-gcm","aes-256-gcm+xor-whitening"))for(String policy:List.of("home","custom"))expected.add(kind+"--"+layer+"--"+last+"--"+policy+".json");
   try(var rows=Files.list(Path.of(System.getenv("ROUTERVPN_CONNECT_LAYER_SOURCES")))){all=rows.sorted().toList();}
   check(all.size()==32&&all.stream().map(p->p.getFileName().toString()).collect(java.util.stream.Collectors.toSet()).equals(expected),"CONNECT independent source inventory changed");
   check(List.of("http-connect--aes-256-gcm","http-connect--aes-256-gcm+xor-whitening","https-connect--aes-256-gcm","https-connect--aes-256-gcm+xor-whitening").contains(phase),"unknown CONNECT entry layer phase");
   List<Path> selected=all.stream().filter(p->p.getFileName().toString().startsWith(phase+"--")).toList();check(selected.size()==8,"incomplete CONNECT entry layer phase");exportEnvironment="ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES";for(Path path:selected)one(root,path);
   System.out.println("Android CONNECT entry layers: "+checks+" checks; "+phase+", "+selected.size()+" original independent source graphs");return;
  }
  try(var rows=Files.list(fixtures)){all=rows.filter(p->p.toString().endsWith(".json")).sorted().toList();}
  check(all.size()==346,"the complete proxy/packet independent entry/final layer matrix is incomplete");
  String phase=args[3];boolean openvpn=phase.startsWith("openvpn--");boolean connect=phase.startsWith("connect--");boolean packet=phase.startsWith("packet-");boolean socks=phase.startsWith("socks5--final-");
  check(List.of("openvpn--tcp--final-shadowsocks","openvpn--tcp--final-hysteria2","openvpn--tcp--final-wg","openvpn--tcp--final-awg2-fast","openvpn--tcp--final-awg2-strong","openvpn--udp--final-shadowsocks","openvpn--udp--final-hysteria2","openvpn--udp--final-wg","openvpn--udp--final-awg2-fast","openvpn--udp--final-awg2-strong","connect--http-connect","connect--https-connect","socks5--final-shadowsocks","socks5--final-hysteria2","socks5--final-wg","socks5--final-awg2-fast","socks5--final-awg2-strong","socks5--final-reality-vision","shadowsocks","hysteria2","packet-wireguard--final-shadowsocks","packet-wireguard--final-hysteria2","packet-amneziawg--final-shadowsocks","packet-amneziawg--final-hysteria2","packet-wireguard--final-wg","packet-wireguard--final-awg2-fast","packet-wireguard--final-awg2-strong","packet-amneziawg--final-wg","packet-amneziawg--final-awg2-fast","packet-amneziawg--final-awg2-strong","wg","awg2-fast","awg2-strong").contains(phase),"unknown original matrix phase");
  List<Path> selected=all.stream().filter(p->{String name=p.getFileName().toString();return openvpn?name.startsWith(phase+"--"):connect?name.startsWith(phase+"--"):socks?(name.equals(phase+".json")||name.startsWith(phase+"--")):packet?name.startsWith(phase+"--"):phase.equals("shadowsocks")?!name.startsWith("openvpn--")&&!name.startsWith("connect--")&&!name.startsWith("socks5--")&&!name.startsWith("packet-")&&!name.startsWith("final-"):name.startsWith("final-"+phase+"--");}).toList();check(selected.size()==(openvpn?9:connect?6:socks?9:packet?9:20),"incomplete entry/final phase");for(Path p:selected)one(root,p);
  System.out.println("Android imported-entry original sources: "+checks+" checks; "+phase+", "+selected.size()+" original independent layer graphs");
 }
}'''


PRIMARY_PHASES = ("openvpn--tcp--final-shadowsocks","openvpn--tcp--final-hysteria2","openvpn--tcp--final-wg","openvpn--tcp--final-awg2-fast","openvpn--tcp--final-awg2-strong","openvpn--udp--final-shadowsocks","openvpn--udp--final-hysteria2","openvpn--udp--final-wg","openvpn--udp--final-awg2-fast","openvpn--udp--final-awg2-strong","connect--http-connect", "connect--https-connect", "socks5--final-shadowsocks", "socks5--final-hysteria2", "socks5--final-wg", "socks5--final-awg2-fast", "socks5--final-awg2-strong", "socks5--final-reality-vision", "shadowsocks", "hysteria2", "packet-wireguard--final-shadowsocks", "packet-wireguard--final-hysteria2", "packet-amneziawg--final-shadowsocks", "packet-amneziawg--final-hysteria2","packet-wireguard--final-wg","packet-wireguard--final-awg2-fast","packet-wireguard--final-awg2-strong","packet-amneziawg--final-wg","packet-amneziawg--final-awg2-fast","packet-amneziawg--final-awg2-strong", "wg", "awg2-fast", "awg2-strong")
CONNECT_LAYER_PHASES = tuple('connect-entry-layers--'+kind+'--'+layer
    for kind in ('http-connect', 'https-connect')
    for layer in ('aes-256-gcm', 'aes-256-gcm+xor-whitening'))


PROXY_XRAY_PHASES = ('proxy-reality--shadowsocks', 'proxy-reality--hysteria2')
CONNECT_XRAY_PHASES = ('connect-reality--http-connect', 'connect-reality--https-connect')
PACKET_XRAY_PHASES = tuple('packet-reality--'+kind for kind in ('wireguard','amneziawg','openvpn-tcp','openvpn-udp'))


PQ_XRAY_PHASES = tuple("pq-reality--"+kind for kind in ("socks5","shadowsocks","hysteria2","http-connect","https-connect","wireguard","amneziawg","openvpn-tcp","openvpn-udp"))
XHTTP_XRAY_PHASES = tuple("xhttp--"+kind for kind in ("socks5","shadowsocks","hysteria2","http-connect","https-connect","wireguard","amneziawg","openvpn-tcp","openvpn-udp"))
NAIVE_H2_PHASES = tuple("naive-h2--"+kind for kind in ("socks5","shadowsocks","hysteria2","http-connect","https-connect","wireguard","amneziawg","openvpn-tcp","openvpn-udp"))
NAIVE_H3_PHASES = tuple("naive-h3--"+kind for kind in ("socks5","shadowsocks","hysteria2","wireguard","amneziawg","openvpn-tcp","openvpn-udp"))

def selected_phases(phases=None):
    allowed = PRIMARY_PHASES + CONNECT_LAYER_PHASES + PROXY_XRAY_PHASES + CONNECT_XRAY_PHASES + PACKET_XRAY_PHASES
    selected = allowed if phases is None else tuple(phases)
    allowed += PQ_XRAY_PHASES + XHTTP_XRAY_PHASES + NAIVE_H2_PHASES + NAIVE_H3_PHASES
    if not selected or any(phase not in allowed for phase in selected) or len(set(selected)) != len(selected):
        raise ValueError('Choose a nonempty, exact, duplicate-free imported-entry phase selection')
    return selected


def main(phases=None):
    phases = selected_phases(phases)
    naive_output = os.environ.get('ROUTERVPN_ANDROID_IMPORTED_NAIVE_H2_FIXTURES')
    if naive_output is not None:
        destination = Path(naive_output)
        if not naive_output or not destination.is_dir() or destination.is_symlink() or any(destination.iterdir()) or tuple(phases) != NAIVE_H2_PHASES:
            raise ValueError('Naive H2 export requires its own empty directory and all nine exact Naive H2 phases')
        if any(os.environ.get(key) is not None for key in ('ROUTERVPN_ANDROID_IMPORTED_XHTTP_XRAY_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_PQ_XRAY_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES','ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_PROXY_XRAY_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_CONNECT_XRAY_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_PACKET_XRAY_FIXTURES')):
            raise ValueError('Naive H2 exports cannot replace or share an ordinary or PQ inventory')
    naive_h3_output = os.environ.get('ROUTERVPN_ANDROID_IMPORTED_NAIVE_H3_FIXTURES')
    if naive_h3_output is not None:
        destination = Path(naive_h3_output)
        if not naive_h3_output or not destination.is_dir() or destination.is_symlink() or any(destination.iterdir()) or tuple(phases) != NAIVE_H3_PHASES:
            raise ValueError('Naive H3 export requires its own empty directory and all seven exact Naive H3 phases')
        if any(os.environ.get(key) is not None for key in ('ROUTERVPN_ANDROID_IMPORTED_NAIVE_H2_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_XHTTP_XRAY_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_PQ_XRAY_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES','ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_PROXY_XRAY_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_CONNECT_XRAY_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_PACKET_XRAY_FIXTURES')):
            raise ValueError('Naive H3 exports cannot replace or share an ordinary or PQ inventory')
    xhttp_output = os.environ.get('ROUTERVPN_ANDROID_IMPORTED_XHTTP_XRAY_FIXTURES')
    if xhttp_output is not None:
        destination = Path(xhttp_output)
        if not xhttp_output or not destination.is_dir() or destination.is_symlink() or any(destination.iterdir()) or tuple(phases) != XHTTP_XRAY_PHASES:
            raise ValueError('XHTTP export requires its own empty directory and all nine exact XHTTP phases')
        if any(os.environ.get(key) is not None for key in ('ROUTERVPN_ANDROID_IMPORTED_PQ_XRAY_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES','ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_PROXY_XRAY_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_CONNECT_XRAY_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_PACKET_XRAY_FIXTURES')):
            raise ValueError('XHTTP exports cannot replace or share an ordinary or PQ inventory')
    pq_output = os.environ.get('ROUTERVPN_ANDROID_IMPORTED_PQ_XRAY_FIXTURES')
    if pq_output is not None:
        destination = Path(pq_output)
        if not pq_output or not destination.is_dir() or destination.is_symlink() or any(destination.iterdir()) or tuple(phases) != PQ_XRAY_PHASES:
            raise ValueError('PQ export requires its own empty directory and all nine exact PQ phases')
        if any(os.environ.get(key) is not None for key in ('ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES','ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_PROXY_XRAY_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_CONNECT_XRAY_FIXTURES','ROUTERVPN_ANDROID_IMPORTED_PACKET_XRAY_FIXTURES')):
            raise ValueError('PQ exports cannot replace or share an ordinary graph inventory')
    connect_output = os.environ.get('ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES')
    if connect_output is not None:
        destination = Path(connect_output)
        if not connect_output or not destination.is_dir() or destination.is_symlink() or any(destination.iterdir()):
            raise ValueError('ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES must name an existing empty owned directory')
        primary_output = os.environ.get('ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES')
        if primary_output is not None:
            primary, separate = Path(primary_output).resolve(), destination.resolve()
            if primary == separate or primary in separate.parents or separate in primary.parents:
                raise ValueError('CONNECT entry layer evidence requires separate non-overlapping inventories')
    proxy_output = os.environ.get('ROUTERVPN_ANDROID_IMPORTED_PROXY_XRAY_FIXTURES')
    if proxy_output is not None:
        destination = Path(proxy_output)
        if not proxy_output or not destination.is_dir() or destination.is_symlink() or any(destination.iterdir()):
            raise ValueError('ROUTERVPN_ANDROID_IMPORTED_PROXY_XRAY_FIXTURES must name an existing empty owned directory')
        separate = destination.resolve()
        for key in ('ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES', 'ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES'):
            if key in os.environ:
                other = Path(os.environ[key]).resolve()
                if other == separate or other in separate.parents or separate in other.parents:
                    raise ValueError('Encrypted REALITY evidence requires separate non-overlapping inventories')
    connect_xray_output = os.environ.get('ROUTERVPN_ANDROID_IMPORTED_CONNECT_XRAY_FIXTURES')
    if connect_xray_output is not None:
        destination = Path(connect_xray_output)
        if not connect_xray_output or not destination.is_dir() or destination.is_symlink() or any(destination.iterdir()):
            raise ValueError('ROUTERVPN_ANDROID_IMPORTED_CONNECT_XRAY_FIXTURES must name an existing empty owned directory')
        separate = destination.resolve()
        for key in ('ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES', 'ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES', 'ROUTERVPN_ANDROID_IMPORTED_PROXY_XRAY_FIXTURES'):
            if key in os.environ:
                other = Path(os.environ[key]).resolve()
                if other == separate or other in separate.parents or separate in other.parents:
                    raise ValueError('CONNECT REALITY evidence requires separate non-overlapping inventories')
    packet_xray_output = os.environ.get('ROUTERVPN_ANDROID_IMPORTED_PACKET_XRAY_FIXTURES')
    if packet_xray_output is not None:
        destination = Path(packet_xray_output)
        if not packet_xray_output or not destination.is_dir() or destination.is_symlink() or any(destination.iterdir()):
            raise ValueError('ROUTERVPN_ANDROID_IMPORTED_PACKET_XRAY_FIXTURES must name an existing empty owned directory')
        separate = destination.resolve()
        for key in ('ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES', 'ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES', 'ROUTERVPN_ANDROID_IMPORTED_PROXY_XRAY_FIXTURES', 'ROUTERVPN_ANDROID_IMPORTED_CONNECT_XRAY_FIXTURES'):
            if key in os.environ:
                other = Path(os.environ[key]).resolve()
                if other == separate or other in separate.parents or separate in other.parents:
                    raise ValueError('Packet REALITY evidence requires separate non-overlapping inventories')
    for tool in ("java", "javac", "go"):
        if not shutil.which(tool):
            raise RuntimeError(f"{tool} is required; imported-entry tests cannot be skipped")
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file():
        raise RuntimeError("The actual Android JSON library is required")
    with tempfile.TemporaryDirectory(prefix="routervpn-imported-entry-", dir=ROOT) as directory:
        temp = Path(directory)
        fixtures = temp / "fixtures"
        fixtures.mkdir()
        env = dict(os.environ, ROUTERVPN_IMPORTED_ENTRY_FIXTURES=str(fixtures))
        subprocess.run(["go", "test", "./internal/mobilemultihop", "-run", "^TestImportedEntry(CONNECTGraphs|SOCKS(RealityVisionCapturedGraphs|RealityVisionIndependentLayers|PairedFinalGraphs|PairedFinalLayers|PacketFinalLayers|EntryLayers|PacketFinalGraphs)|PairedFinal(CompleteLayers|PolicyAndCipherOwnership)|HysteriaPairedFinalCompleteLayers|HysteriaFinalCompleteGraphs|PacketCompleteGraphs|PacketFinalCompleteGraphs|NestedPacketCompleteGraphs)$", "-count=1"], cwd=ROOT, env=env, check=True, timeout=120)
        subprocess.run(["go", "test", "./internal/mobilemultihop", "-run", "^TestImportedOpenVPNCompleteLayerMatrix$", "-count=1", "-timeout=20s"], cwd=ROOT, env=dict(os.environ,ROUTERVPN_IMPORTED_OPENVPN_FIXTURES=str(fixtures)), check=True, timeout=30)
        connect_sources = temp / 'connect-entry-layers'
        connect_sources.mkdir()
        if any(phase in CONNECT_LAYER_PHASES for phase in phases):
            subprocess.run(['go','test','./internal/mobilemultihop','-run','^TestImportedEntryCONNECTIndependentLayers$','-count=1','-timeout=30s'], cwd=ROOT, env=dict(os.environ,ROUTERVPN_CONNECT_LAYER_FIXTURES=str(connect_sources)), check=True, timeout=45)
        proxy_sources = temp / 'proxy-reality'
        proxy_sources.mkdir()
        if any(phase in PROXY_XRAY_PHASES for phase in phases):
            subprocess.run(['go','test','./internal/mobilemultihop','-run','^TestImportedProxyRealityVisionIndependentLayers$','-count=1','-timeout=30s'], cwd=ROOT, env=dict(os.environ,ROUTERVPN_IMPORTED_PROXY_XRAY_FIXTURES=str(proxy_sources)), check=True, timeout=45)
        connect_xray_sources = temp / 'connect-reality'
        connect_xray_sources.mkdir()
        if any(phase in CONNECT_XRAY_PHASES for phase in phases):
            subprocess.run(['go','test','./internal/mobilemultihop','-run','^TestImportedCONNECTRealityVisionIndependentLayers$','-count=1','-timeout=30s'], cwd=ROOT, env=dict(os.environ,ROUTERVPN_IMPORTED_CONNECT_XRAY_FIXTURES=str(connect_xray_sources)), check=True, timeout=45)
        packet_xray_sources = temp / 'packet-reality'
        packet_xray_sources.mkdir()
        if any(phase in PACKET_XRAY_PHASES for phase in phases):
            subprocess.run(['go','test','./internal/mobilemultihop','-run','^TestImportedPacketRealityVisionIndependentLayers$','-count=1','-timeout=30s'], cwd=ROOT, env=dict(os.environ,ROUTERVPN_IMPORTED_PACKET_XRAY_FIXTURES=str(packet_xray_sources)), check=True, timeout=45)
        child_env = dict(os.environ, ROUTERVPN_CONNECT_LAYER_SOURCES=str(connect_sources), ROUTERVPN_IMPORTED_PROXY_XRAY_SOURCES=str(proxy_sources), ROUTERVPN_IMPORTED_CONNECT_XRAY_SOURCES=str(connect_xray_sources), ROUTERVPN_IMPORTED_PACKET_XRAY_SOURCES=str(packet_xray_sources))
        pq_sources = temp / 'pq-reality'
        pq_sources.mkdir()
        if any(phase in PQ_XRAY_PHASES for phase in phases):
            subprocess.run(['go','test','./internal/mobilemultihop','-run','^TestImportedPQRealityIndependentLayers$','-count=1','-timeout=30s'], cwd=ROOT, env=dict(os.environ,ROUTERVPN_IMPORTED_PQ_XRAY_FIXTURES=str(pq_sources)), check=True, timeout=45)
        child_env['ROUTERVPN_IMPORTED_PQ_XRAY_SOURCES'] = str(pq_sources)
        xhttp_sources = temp / 'xhttp'
        xhttp_sources.mkdir()
        if any(phase in XHTTP_XRAY_PHASES for phase in phases):
            subprocess.run(['go','test','./internal/mobilemultihop','-run','^TestImportedXHTTPIndependentLayers$','-count=1','-timeout=30s'], cwd=ROOT, env=dict(os.environ,ROUTERVPN_IMPORTED_XHTTP_XRAY_FIXTURES=str(xhttp_sources)), check=True, timeout=45)
        child_env['ROUTERVPN_IMPORTED_XHTTP_XRAY_SOURCES'] = str(xhttp_sources)
        naive_sources = temp / 'naive-h2'
        naive_sources.mkdir()
        if any(phase in NAIVE_H2_PHASES + NAIVE_H3_PHASES for phase in phases):
            subprocess.run(['go','test','./internal/mobilemultihop','-run','^TestImportedNaiveH2IndependentLayers$','-count=1','-timeout=30s'], cwd=ROOT, env=dict(os.environ,ROUTERVPN_IMPORTED_NAIVE_H2_FIXTURES=str(naive_sources)), check=True, timeout=45)
        child_env['ROUTERVPN_IMPORTED_NAIVE_H2_SOURCES'] = str(naive_sources)
        naive_h3_sources = temp / 'naive-h3'
        naive_h3_sources.mkdir()
        if any(phase in NAIVE_H3_PHASES for phase in phases):
            subprocess.run(['go','test','./internal/mobilemultihop','-run','^TestImportedNaiveH3IndependentLayers$','-count=1','-timeout=30s'], cwd=ROOT, env=dict(os.environ,ROUTERVPN_IMPORTED_NAIVE_H3_FIXTURES=str(naive_h3_sources)), check=True, timeout=45)
        child_env['ROUTERVPN_IMPORTED_NAIVE_H3_SOURCES'] = str(naive_h3_sources)
        module = next(line.split()[1] for line in (ROOT / "go.mod").read_text().splitlines() if line.startswith("module "))
        helper = E.GO.replace('switch args[0]{', 'switch args[0]{'+GO_CASE).replace("github.com/Eabusham2/router-vpn", module)
        (temp / "main.go").write_text(helper)
        subprocess.run(["go", "build", "-o", str(temp / "compiler"), str(temp / "main.go")], cwd=ROOT, check=True, timeout=120)
        stubs = dict(E.STUBS)
        lib = stubs["io/nekohasekai/libbox/Libbox.java"]
        addition = '''public static String routerNodeChainImportedMemberInput(String config,String capture)throws Exception{return call("chain-imported",config,capture);} public static String routerCompileProxyEntry(String files,String mode)throws Exception{return call("proxy-entry",files,mode);} public static boolean rejectSSService; public static boolean routerValidateSSService(String files,String node)throws Exception{return !rejectSSService && "true".equals(call("ss-service",files,node));} public static RouterMultihop newRouterImportedEntryMultihop(String a,String b,String c,String d,String e,String f,String g)throws Exception{String result=call("imported-router",a,b,c,d,e,f,g);Runnable h=hook;hook=null;if(h!=null)h.run();return new RouterMultihop(result);}'''
        stubs["io/nekohasekai/libbox/Libbox.java"] = lib[:lib.rindex("}")] + addition + "}"
        stubs["io/nekohasekai/libbox/RouterMultihop.java"] = OWNER
        for name, source in stubs.items():
            target = temp / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source)
        app = temp / "com/eabusham/routervpn"
        app.mkdir(parents=True)
        for name in ("AndroidImportedRouterPath", "AndroidExternalProtection", "AndroidExternalPolicy", "AndroidStandardExitStore", "AndroidExternalAmnezia", "AndroidProfileSelection", "AndroidDirectStandardExitController", "AndroidStandardExitController", "AndroidNumericAddress", "AndroidOpenVPN"):
            shutil.copyfile(JAVA / f"{name}.java", app / f"{name}.java")
        # Retain shipping layer normalization; empty saved values mean Off.
        layer_source=(JAVA / "AndroidStartLayer.java").read_text()
        layer_methods="\n".join(block(layer_source, signature) for signature in ("    static String selectedMode(", "    private static JSONObject selectedRouterProfile(", "    private static JSONObject requireHome(", "    private static String normalize("))
        layer_constants="\n".join(line for line in layer_source.splitlines() if any("static final String "+name+" =" in line for name in ("OFF", "AES", "AES_XOR")))
        (app / "AndroidStartLayer.java").write_text("package com.eabusham.routervpn;import org.json.JSONObject;import java.util.Locale;final class AndroidStartLayer{"+layer_constants+layer_methods+"}")
        boundaries=E.BOUNDARIES.replace(block(E.BOUNDARIES,"final class AndroidStartLayer"),"")
        (app / "Boundaries.java").write_text("package com.eabusham.routervpn;\n"+boundaries)
        runtime = (JAVA / "AndroidMultihopRuntime.java").read_text()
        if "String firstMode=importedEntryMode(AndroidImportedRouterPath.entry(context,first));" not in runtime:
            raise AssertionError("Runtime dropped original-source canonical receipt identity")
        (app / "AndroidMultihopRuntime.java").write_text("package com.eabusham.routervpn;final class AndroidMultihopRuntime{"+block(runtime,"    static String importedEntryMode(")+"}")
        controller = (JAVA / "AndroidMultihopController.java").read_text()
        capture = "\n".join(block(controller, signature) for signature in ("    static final class Prepared {", "    static final class Source {", "    private static final class LoadedBundle {", "    static Source captureSource(", "    private static String sourceDigest(", "    private static byte[] readBundleBytes("))
        (app / "AndroidMultihopController.java").write_text("package com.eabusham.routervpn;import java.io.*;import java.nio.charset.StandardCharsets;import org.json.*;final class AndroidMultihopController{private static final int MAX_BUNDLE=32*1024*1024;"+capture+"}")
        service=(JAVA/'LayeredVpnService.java').read_text()
        if service.count('requireOwnedImportedFiles(session,modeId,executionFile,entryLayerFile,exitLayerFile,importedEntryFile);') != 1:
            raise AssertionError('Native service dropped its exact imported source admission')
        admission=block(service,'    static void requireOwnedImportedFiles(')
        (app/'LayeredVpnService.java').write_text('package com.eabusham.routervpn;import java.io.File;final class LayeredVpnService{'+admission+'}')
        (app / "ImportedRouterTest.java").write_text(HARNESS)
        classes = temp / "classes"
        compile_command=["javac", "--release", "17", "-encoding", "UTF-8", "-cp", str(jar), "-d", str(classes), *map(str, temp.rglob("*.java"))]
        subprocess.run(compile_command, check=True, timeout=60)
        private = temp / "private"
        private.mkdir()
        command=["java", "-cp", os.pathsep.join((str(classes), str(jar))), "com.eabusham.routervpn.ImportedRouterTest", str(temp / "compiler"), str(private), str(fixtures)]
        # Preserve the original finite bound for each complete final-mode family.
        for final_mode in phases:
            subprocess.run(command+[final_mode], env=child_env, check=True, timeout=180)
        # This ABI reaches the real shared constructor; prove malformed source
        # cannot be replaced by an unconditional fixture success.
        lib_path=temp/"io/nekohasekai/libbox/Libbox.java"
        original_lib=lib_path.read_text()
        call='return call("chain-imported",config,capture);'
        assert original_lib.count(call)==1
        lib_path.write_text(original_lib.replace(call,'if(config.equals("{}"))return "{}";'+call))
        subprocess.run(compile_command,check=True,timeout=60,capture_output=True)
        boundary_env=dict(child_env)
        for key in tuple(boundary_env):
            if key.startswith("ROUTERVPN_ANDROID_") and key.endswith("_FIXTURES"):boundary_env.pop(key)
        broken=subprocess.run(command+[phases[0]],env=boundary_env,capture_output=True,text=True,timeout=180)
        lib_path.write_text(original_lib)
        if broken.returncode==0 or 'accepted malformed imported member source' not in broken.stderr:
            raise AssertionError('Imported member ABI causal control missed malformed source: '+broken.stdout+broken.stderr)
        print('Android imported member ABI causal rejected: malformed original source')
        source=app/"AndroidImportedRouterPath.java"
        original=source.read_text()
        controls=(
            ('|| !("multihop-imported-" + mode).equals(modeId)', '|| false', 'accepted changed final session label'),
            ('throw new PreparationFailure(ownedFolder.getName(), original, cleanup);', 'original.addSuppressed(cleanup);', 'failed staging cleanup lost its retained session capability'),
            ('if (!config.equals(owner.config()) || !metadata.equals(owner.metadata()) || !input.getString("source_sha256").equals(owner.sourceSHA256()))', 'if (false)', 'accepted forged graph'),
            ('if (!original.equals(AndroidStandardExitStore.snapshot(AndroidStandardExitStore.capturedEntry(owner,id))))', 'if (false)', 'accepted changed imported capture'),
            ('AndroidStandardExitStore.capturedEntry(owner,id)', 'new AndroidStandardExitStore(owner).get(id)', 'source check deadlocked behind store mutation owner'),
        )
        causal_env=dict(os.environ)
        causal_env.pop("ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES",None)
        causal_env.pop("ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES",None)
        causal_env.pop("ROUTERVPN_ANDROID_IMPORTED_PROXY_XRAY_FIXTURES",None)
        causal_env.pop("ROUTERVPN_ANDROID_IMPORTED_CONNECT_XRAY_FIXTURES",None)
        causal_env.pop("ROUTERVPN_ANDROID_IMPORTED_PACKET_XRAY_FIXTURES",None)
        causal_env.pop("ROUTERVPN_ANDROID_IMPORTED_PQ_XRAY_FIXTURES",None)
        causal_env.pop("ROUTERVPN_ANDROID_IMPORTED_XHTTP_XRAY_FIXTURES",None)
        causal_env.pop("ROUTERVPN_ANDROID_IMPORTED_NAIVE_H2_FIXTURES",None)
        causal_env.pop("ROUTERVPN_ANDROID_IMPORTED_NAIVE_H3_FIXTURES",None)
        for old,new,assertion in controls:
            if original.count(old)!=1:raise AssertionError("Imported source ownership control changed")
            source.write_text(original.replace(old,new))
            subprocess.run(compile_command,check=True,timeout=60,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            result=subprocess.run(command+["shadowsocks"],env=causal_env,capture_output=True,text=True,timeout=180)
            if result.returncode==0 or assertion not in result.stderr:raise AssertionError("Imported ownership causal was not rejected at its intended assertion: "+result.stderr)
            print("Android imported source causal rejected:",assertion)
        source.write_text(original)
        if any(phase in PQ_XRAY_PHASES for phase in phases):
            admission_source=app/'LayeredVpnService.java';actual=admission_source.read_text()
            absent=',"multihop-imported-reality-pq-vision"'
            if actual.count(absent)!=1:raise AssertionError('Exact native PQ admission changed')
            admission_source.write_text(actual.replace(absent,''))
            subprocess.run(compile_command,check=True,timeout=60,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            service_causal_env=dict(causal_env,ROUTERVPN_IMPORTED_PQ_XRAY_SOURCES=str(pq_sources))
            result=subprocess.run(command+[PQ_XRAY_PHASES[0]],env=service_causal_env,capture_output=True,text=True,timeout=180)
            if result.returncode==0 or 'Imported entry sources have no exclusive original multihop owner.' not in result.stderr:raise AssertionError('Old service PQ refusal was not reproduced: '+result.stderr)
            admission_source.write_text(actual)
            print('Android imported PQ service causal rejected: old native session allowlist')
        if any(phase in XHTTP_XRAY_PHASES for phase in phases):
            admission_source=app/'LayeredVpnService.java';actual=admission_source.read_text()
            absent=',"multihop-imported-reality-xhttp"'
            if actual.count(absent)!=1:raise AssertionError('Exact native XHTTP admission changed')
            admission_source.write_text(actual.replace(absent,''))
            subprocess.run(compile_command,check=True,timeout=60,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            service_causal_env=dict(causal_env,ROUTERVPN_IMPORTED_XHTTP_XRAY_SOURCES=str(xhttp_sources))
            result=subprocess.run(command+[XHTTP_XRAY_PHASES[0]],env=service_causal_env,capture_output=True,text=True,timeout=180)
            if result.returncode==0 or 'Imported entry sources have no exclusive original multihop owner.' not in result.stderr:raise AssertionError('Old service XHTTP refusal was not reproduced: '+result.stderr)
            admission_source.write_text(actual)
            print('Android imported XHTTP service causal rejected: old native session allowlist')
        if any(phase in NAIVE_H2_PHASES for phase in phases):
            admission_source=app/'LayeredVpnService.java';actual=admission_source.read_text()
            absent=',"multihop-imported-naive-h2"'
            if actual.count(absent)!=1:raise AssertionError('Exact native Naive H2 admission changed')
            admission_source.write_text(actual.replace(absent,''))
            subprocess.run(compile_command,check=True,timeout=60,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            service_causal_env=dict(causal_env,ROUTERVPN_IMPORTED_NAIVE_H2_SOURCES=str(naive_sources))
            result=subprocess.run(command+[NAIVE_H2_PHASES[0]],env=service_causal_env,capture_output=True,text=True,timeout=180)
            if result.returncode==0 or 'Imported entry sources have no exclusive original multihop owner.' not in result.stderr:raise AssertionError('Old service Naive H2 refusal was not reproduced: '+result.stderr)
            admission_source.write_text(actual)
            print('Android imported Naive H2 service causal rejected: old native session allowlist')
        if any(phase in NAIVE_H3_PHASES for phase in phases):
            admission_source=app/'LayeredVpnService.java';actual=admission_source.read_text()
            absent=',"multihop-imported-naive-h3"'
            if actual.count(absent)!=1:raise AssertionError('Exact native Naive H3 admission changed')
            admission_source.write_text(actual.replace(absent,''))
            subprocess.run(compile_command,check=True,timeout=60,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            service_causal_env=dict(causal_env,ROUTERVPN_IMPORTED_NAIVE_H3_SOURCES=str(naive_h3_sources),ROUTERVPN_IMPORTED_NAIVE_H2_SOURCES=str(naive_sources))
            result=subprocess.run(command+[NAIVE_H3_PHASES[0]],env=service_causal_env,capture_output=True,text=True,timeout=180)
            if result.returncode==0 or 'Imported entry sources have no exclusive original multihop owner.' not in result.stderr:raise AssertionError('Old service Naive H3 refusal was not reproduced: '+result.stderr)
            admission_source.write_text(actual)
            print('Android imported Naive H3 service causal rejected: old native session allowlist')


def cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', action='append', choices=PRIMARY_PHASES + CONNECT_LAYER_PHASES + PROXY_XRAY_PHASES + CONNECT_XRAY_PHASES + PACKET_XRAY_PHASES + PQ_XRAY_PHASES + XHTTP_XRAY_PHASES + NAIVE_H2_PHASES + NAIVE_H3_PHASES,
                        help='Run this exact bounded phase; repeat for several phases. The default runs every phase.')
    args = parser.parse_args(argv)
    try:
        phases = selected_phases(args.phase)
    except ValueError as error:
        parser.error(str(error))
    main(phases=phases)


if __name__ == "__main__":
    cli()
