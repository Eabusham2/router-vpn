#!/usr/bin/env python3
"""Execute the shipping imported-entry capture, store binding and staging.

Android handles/filesystem APIs and the Libbox Java ABI are boundary doubles.
Every constructor calls the real shared Go compiler. Native CheckConfig and
encrypted peer traffic are separate mandatory gates, which consume these exact
Android-produced original source arrays when an export directory is supplied.
"""
from pathlib import Path
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


GO_CASE = r'''case "imported-router":
 if len(args)!=8 { panic("missing original sources") }
 var c *mobilemultihop.Controller
 c,err=mobilemultihop.NewImportedEntry(args[1],args[2],args[3],args[4],args[5],args[6],args[7])
 if err==nil { var raw []byte;raw,err=json.Marshal(map[string]string{"config":c.Config(),"metadata":c.Metadata(),"mtu":c.MTUProfile(),"source":c.SourceSHA256()});out=string(raw);if closed:=c.Close();err==nil{err=closed} }
'''
OWNER = r'''package io.nekohasekai.libbox;
public final class RouterMultihop {
 private final org.json.JSONObject data;public static int open;
 private boolean closed;
 RouterMultihop(String raw)throws Exception{data=new org.json.JSONObject(raw);open++;}
 public String config()throws Exception{return data.getString("config");}
 public String metadata()throws Exception{return data.getString("metadata");}
 public String mtuProfile()throws Exception{return data.getString("mtu");}
 public String sourceSHA256()throws Exception{return data.getString("source");}
 public void close(){if(!closed){closed=true;open--;}}
}'''

HARNESS = r'''package com.eabusham.routervpn;
import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.util.*;import org.json.*;import io.nekohasekai.libbox.*;
public final class ImportedRouterTest {
 static int checks;static void check(boolean ok,String reason){checks++;if(!ok)throw new AssertionError(reason);}
 interface Work{void run()throws Exception;}
 static void reject(String label,Work work)throws Exception{boolean refused=false;try{work.run();}catch(Exception expected){refused=true;}check(refused,"accepted "+label);check(RouterMultihop.open==0,"owner leaked after "+label);}
 static JSONObject object(String s)throws Exception{return new JSONObject(s);}
 static AndroidStandardExitStore.Entry entry(JSONArray args)throws Exception{
  JSONObject capture=object(args.getString(1)),profile=capture.getJSONObject("profile"),external=profile.getJSONObject("external"),transport=external.getJSONObject(capture.getString("protocol"));
  AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id=capture.getString("exit_id");e.name="Imported first";e.protocol=capture.getString("protocol");e.expectedPublicIp=capture.getString("expected_public_ip");
  if(List.of("wireguard","amneziawg").contains(e.protocol)){
   String endpoint=transport.getString("endpoint");int split=endpoint.lastIndexOf(':');e.server=endpoint.substring(0,split);if(e.server.startsWith("[")&&e.server.endsWith("]"))e.server=e.server.substring(1,e.server.length()-1);e.serverPort=Integer.parseInt(endpoint.substring(split+1));
   e.wgPrivateKey=transport.getString("private_key");e.wgPeerPublicKey=transport.getString("peer_public_key");e.wgPreSharedKey=transport.optString("preshared_key","");e.wgMtu=transport.optInt("mtu",0);
   if(transport.has("persistent_keepalive_interval"))e.wgKeepalive=transport.getInt("persistent_keepalive_interval");
   for(String key:List.of("addresses","allowed_ips","dns")){JSONArray values=transport.optJSONArray(key);List<String> into=key.equals("addresses")?e.wgAddresses:key.equals("allowed_ips")?e.wgAllowedIps:e.wgDns;for(int i=0;values!=null&&i<values.length();i++)into.add(values.getString(i));}
   if(e.protocol.equals("amneziawg"))e.awgParameters=object(transport.getJSONObject("parameters").toString());
  }else if(e.protocol.equals("socks5")){e.server=transport.getString("host");e.serverPort=transport.getInt("port");e.username=transport.getString("username");e.password=transport.getString("password");}
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
  String directory=System.getenv("ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES");if(directory==null||directory.isEmpty())return;
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
 static void one(Path root,Path fixture)throws Exception{
  JSONArray args=new JSONArray(Files.readString(fixture));String finalMode=args.getString(2);AndroidStandardExitStore.Entry e=entry(args);JSONObject b=bundle(args);
  String before=AndroidStandardExitStore.snapshot(e),beforeFinal=b.toString();AndroidImportedRouterPath.Compiled c=AndroidImportedRouterPath.compile(e,b,finalMode,"local");
  check(before.equals(AndroidStandardExitStore.snapshot(e))&&beforeFinal.equals(b.toString()),"compiler mutated original source");
  JSONObject selected=object(c.metadata),raw=object(c.input),graph=object(c.config);
  check(selected.getString("entry_kind").equals("external")&&selected.getString("entry_id").equals(e.id)&&selected.getString("exit_id").equals(profile(b).getString("id"))&&selected.getString("entry_mode").equals(e.protocol)&&selected.getString("exit_mode").equals(finalMode),"host changed selected identities or transport");
  if(e.protocol.equals("socks5")){
   JSONObject captured=object(raw.getString("entry_capture")).getJSONObject("profile").getJSONObject("external").getJSONObject("socks5");JSONObject first=null;JSONArray out=graph.getJSONArray("outbounds");for(int i=0;i<out.length();i++)if(out.getJSONObject(i).optString("tag").equals("entry-wg"))first=out.getJSONObject(i);
   check(first!=null&&first.getString("type").equals("socks")&&first.getString("version").equals("5")&&first.getString("username").equals(e.username)&&first.getString("password").equals(e.password),"SOCKS native credentials changed");
   check(captured.getString("username").equals(e.username)&&captured.getString("password").equals(e.password),"captured SOCKS credentials changed");
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
  if(List.of("wg","awg2-fast","awg2-strong").contains(finalMode)){
   check(raw.getString("exit_files").equals(object(args.getString(3)).toString()),"host replaced captured paired packet assets");
   JSONObject last=null;JSONArray endpoints=graph.getJSONArray("endpoints");for(int i=0;i<endpoints.length();i++)if(endpoints.getJSONObject(i).optString("tag").equals("routervpn-execution-local"))last=endpoints.getJSONObject(i);
   check(last!=null&&last.getString("type").equals(finalMode.equals("wg")?"wireguard":"routervpn-amneziawg"),"host omitted or substituted paired packet endpoint");
   check(last.getInt("mtu")>=1280&&!last.getString("private_key").isEmpty()&&!last.getJSONArray("peers").getJSONObject(0).getString("public_key").isEmpty(),"host lost paired packet MTU or key sources");
   for(String key:List.of("exit_files","exit_start")){if(raw.getString(key).isEmpty())continue;reject("changed paired packet original source",()->{JSONObject changed=object(c.input);changed.put(key,raw.getString(key)+" ");AndroidImportedRouterPath.prepareExecution(c.config,c.metadata,changed.toString());});}
   if(!finalMode.equals("wg"))check(last.has("amnezia"),"host lost captured final AWG parameters");
  }
  check(selected.optString("entry_api").isEmpty()&&selected.optString("entry_token").isEmpty()&&selected.optString("entry_node_id").isEmpty(),"import acquired private pairing");
  check(raw.getString("exit_start").equals(args.getString(5).isEmpty()?"":object(args.getString(5)).toString())&&object(raw.getString("entry_capture")).getJSONObject("profile").getString("dns_mode").equals("home"),"raw entry policy or inherent final layer changed");
  JSONObject dns=graph.getJSONObject("dns").getJSONArray("servers").getJSONObject(0);
  check(dns.getString("server").equals("192.168.50.133")&&dns.getString("detour").equals("proxy"),"Home AdGuard final policy lost");
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
  reject("different final protocol",()->AndroidImportedRouterPath.compile(e,b,"naive-h3","local"));
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
  Libbox.compiler=args[0];Path root=Path.of(args[1]),fixtures=Path.of(args[2]);retainedStaging(Files.createTempDirectory(root,"retained-staging-"));List<Path> all;
  try(var rows=Files.list(fixtures)){all=rows.filter(p->p.toString().endsWith(".json")).sorted().toList();}
  check(all.size()==205,"the complete proxy/packet independent entry/final layer matrix is incomplete");
  String phase=args[3];boolean packet=phase.startsWith("packet-");boolean socks=phase.equals("socks5");
  check(List.of("socks5","shadowsocks","hysteria2","packet-wireguard--final-shadowsocks","packet-wireguard--final-hysteria2","packet-amneziawg--final-shadowsocks","packet-amneziawg--final-hysteria2","packet-wireguard--final-wg","packet-wireguard--final-awg2-fast","packet-wireguard--final-awg2-strong","packet-amneziawg--final-wg","packet-amneziawg--final-awg2-fast","packet-amneziawg--final-awg2-strong","wg","awg2-fast","awg2-strong").contains(phase),"unknown original matrix phase");
  List<Path> selected=all.stream().filter(p->{String name=p.getFileName().toString();return socks?name.startsWith("socks5--"):packet?name.startsWith(phase+"--"):phase.equals("shadowsocks")?!name.startsWith("socks5--")&&!name.startsWith("packet-")&&!name.startsWith("final-"):name.startsWith("final-"+phase+"--");}).toList();check(selected.size()==(socks?15:packet?9:20),"incomplete entry/final phase");for(Path p:selected)one(root,p);
  System.out.println("Android imported-entry original sources: "+checks+" checks; "+phase+", "+selected.size()+" original independent layer graphs");
 }
}'''


def main():
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
        subprocess.run(["go", "test", "./internal/mobilemultihop", "-run", "^TestImportedEntry(SOCKS(PairedFinalGraphs|PairedFinalLayers|PacketFinalLayers|PacketFinalGraphs)|PairedFinal(CompleteLayers|PolicyAndCipherOwnership)|HysteriaPairedFinalCompleteLayers|HysteriaFinalCompleteGraphs|PacketCompleteGraphs|PacketFinalCompleteGraphs|NestedPacketCompleteGraphs)$", "-count=1"], cwd=ROOT, env=env, check=True, timeout=120)
        module = next(line.split()[1] for line in (ROOT / "go.mod").read_text().splitlines() if line.startswith("module "))
        helper = E.GO.replace('switch args[0]{', 'switch args[0]{'+GO_CASE).replace("github.com/Eabusham2/router-vpn", module)
        (temp / "main.go").write_text(helper)
        subprocess.run(["go", "build", "-o", str(temp / "compiler"), str(temp / "main.go")], cwd=ROOT, check=True, timeout=120)
        stubs = dict(E.STUBS)
        lib = stubs["io/nekohasekai/libbox/Libbox.java"]
        addition = '''public static RouterMultihop newRouterImportedEntryMultihop(String a,String b,String c,String d,String e,String f,String g)throws Exception{String result=call("imported-router",a,b,c,d,e,f,g);Runnable h=hook;hook=null;if(h!=null)h.run();return new RouterMultihop(result);}'''
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
        controller = (JAVA / "AndroidMultihopController.java").read_text()
        capture = "\n".join(block(controller, signature) for signature in ("    static final class Prepared {", "    static final class Source {", "    private static final class LoadedBundle {", "    static Source captureSource(", "    private static String sourceDigest(", "    private static byte[] readBundleBytes("))
        (app / "AndroidMultihopController.java").write_text("package com.eabusham.routervpn;import java.io.*;import java.nio.charset.StandardCharsets;import org.json.*;final class AndroidMultihopController{private static final int MAX_BUNDLE=32*1024*1024;"+capture+"}")
        (app / "ImportedRouterTest.java").write_text(HARNESS)
        classes = temp / "classes"
        compile_command=["javac", "--release", "17", "-encoding", "UTF-8", "-cp", str(jar), "-d", str(classes), *map(str, temp.rglob("*.java"))]
        subprocess.run(compile_command, check=True, timeout=60)
        private = temp / "private"
        private.mkdir()
        command=["java", "-cp", os.pathsep.join((str(classes), str(jar))), "com.eabusham.routervpn.ImportedRouterTest", str(temp / "compiler"), str(private), str(fixtures)]
        # Preserve the original finite bound for each complete final-mode family.
        for final_mode in ("socks5", "shadowsocks", "hysteria2", "packet-wireguard--final-shadowsocks", "packet-wireguard--final-hysteria2", "packet-amneziawg--final-shadowsocks", "packet-amneziawg--final-hysteria2","packet-wireguard--final-wg","packet-wireguard--final-awg2-fast","packet-wireguard--final-awg2-strong","packet-amneziawg--final-wg","packet-amneziawg--final-awg2-fast","packet-amneziawg--final-awg2-strong", "wg", "awg2-fast", "awg2-strong"):
            subprocess.run(command+[final_mode], check=True, timeout=180)
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
        for old,new,assertion in controls:
            if original.count(old)!=1:raise AssertionError("Imported source ownership control changed")
            source.write_text(original.replace(old,new))
            subprocess.run(compile_command,check=True,timeout=60,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            result=subprocess.run(command+["shadowsocks"],env=causal_env,capture_output=True,text=True,timeout=180)
            if result.returncode==0 or assertion not in result.stderr:raise AssertionError("Imported ownership causal was not rejected at its intended assertion: "+result.stderr)
            print("Android imported source causal rejected:",assertion)
        source.write_text(original)


if __name__ == "__main__":
    main()
