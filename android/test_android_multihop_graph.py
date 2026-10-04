#!/usr/bin/env python3
"""Exercise the shipping Android graph builder against the real shared Go policy.

Android service handles and the node-file store are boundary doubles. JSON uses
Android's real implementation, and native compiler/MTU/LAN calls execute the
shipping Go package, not precomputed answers. Actual AAR/SDK and packet traffic
are verified separately; this test does not claim physical-device acceptance.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'
GO_HELPER=r'''package main
import("crypto/ecdsa";"crypto/elliptic";"crypto/rand";"crypto/x509";"crypto/x509/pkix";"encoding/pem";"math/big";"time";"encoding/json";"fmt";"os";"io";"router-vpn/internal/mobilemultihop";"router-vpn/internal/mobileperf")
func main(){
 var r struct{Operation string;Config string;Policy string}
 if err:=json.NewDecoder(io.LimitReader(os.Stdin,8*1024*1024)).Decode(&r);err!=nil{fmt.Fprintln(os.Stderr,"invalid request");os.Exit(2)}
 var value string;var err error
 switch r.Operation{
 case "parse":value,err=mobilemultihop.CompileWireGuardProfile(r.Config,r.Policy)
 case "exit":value,err=mobilemultihop.WireGuardExitConfig(r.Config,r.Policy)
 case "awg-parse":value,err=mobilemultihop.CompileAmneziaProfile(r.Config,r.Policy)
 case "awg-exit":value,err=mobilemultihop.AmneziaExitConfig(r.Config,r.Policy)
 case "test-certificate":
  var key *ecdsa.PrivateKey; key,err=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
  if err==nil{template:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:r.Config},DNSNames:[]string{r.Config},NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature};var der []byte;der,err=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key);if err==nil{value=string(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}))}}
 case "plan":
  var controller *mobilemultihop.Controller;controller,err=mobilemultihop.New(r.Config,r.Policy);if err==nil{value=controller.Config();err=controller.Close()}
 case "proxy-entry":value,err=mobilemultihop.CompileProxyEntry(r.Config,r.Policy)
 case "mtu-profile":value,err=mobilemultihop.MultihopMTUProfile(r.Config,r.Policy)
 case "mtu":value,err=mobilemultihop.ApplyMTUPolicy(r.Config,r.Policy)
 case "lan":value,err=mobilemultihop.ApplyLANPolicy(r.Config,r.Policy)
 case "performance":value,err=mobileperf.Apply(r.Config,r.Policy)
 default:fmt.Fprintln(os.Stderr,"unknown test operation");os.Exit(2)
 }
 if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}
 fmt.Print(value)
}
'''
STUBS={
'android/content/Context.java':r'''package android.content;
public class Context {
 private final java.io.File root;
 public Context(java.io.File root){this.root=root;}
 public Context getApplicationContext(){return this;} public java.io.File getFilesDir(){return root;}
 public static final int MODE_PRIVATE=0;
 public Object startService(Intent i){throw new AssertionError("No service may start while preparing a graph");}
 public Object startForegroundService(Intent i){throw new AssertionError("No service may start while preparing a graph");}
 public SharedPreferences getSharedPreferences(String s,int mode){return (key,fallback)->fallback;}
}''',
'android/content/SharedPreferences.java':'package android.content; public interface SharedPreferences {String getString(String key,String fallback);}',
'android/content/Intent.java':r'''package android.content; public class Intent {
 public Intent(Context c,Class<?> cls){} public Intent setAction(String s){return this;}
 public Intent putExtra(String key,String value){return this;} public Intent putExtra(String key,long value){return this;}
}''',
'android/os/Build.java':'package android.os; public final class Build {public static class VERSION {public static int SDK_INT=36;} public static class VERSION_CODES {public static final int O=26;}}',
'android/util/Base64.java':'package android.util; public final class Base64 {public static final int DEFAULT=0,NO_WRAP=2; public static String encodeToString(byte[] data,int flags){return java.util.Base64.getEncoder().encodeToString(data);} public static byte[] decode(String s,int flags){return java.util.Base64.getMimeDecoder().decode(s);}}',
'com/eabusham/routervpn/Boundaries.java':r'''package com.eabusham.routervpn;
import org.json.JSONObject;
final class AndroidNodeStore {
 static String stableNodeIdentity(JSONObject b)throws Exception {return b.getString("nodeProofId");}
 static void validateBundle(JSONObject b){AndroidProfileSelection.selectedRouterProfile(b);}
}
final class AndroidKillSwitchPolicy {
 static final String SESSION_MARKER="strict-session";
 static boolean strictRequested(JSONObject b){return AndroidProfileSelection.selectedRouterProfile(b).optBoolean("kill_switch",false);}
}
final class AndroidStartLayerRelay {static final String SESSION_FILE="start-layer.json";static final int LISTEN_PORT=18389,SERVER_PORT=8389;}
final class AndroidServiceStopConfirmation {
 static final String EXTRA_COMMAND="command";
 static void start(String key,Runnable r){throw new AssertionError("No runtime starts in a compiler test");}
 static void request(String key,java.util.function.LongConsumer c){throw new AssertionError("No stop side effect in compiler test");}
 static String state(String key,java.util.function.Supplier<String> value){return value.get();}
}
final class LayeredVpnService {static final String ACTION_START="start",ACTION_STOP="stop",EXTRA_SESSION_ID="session",EXTRA_MODE_ID="mode";}
''',
'io/nekohasekai/libbox/Libbox.java':r'''package io.nekohasekai.libbox;
import org.json.JSONObject;import java.nio.charset.StandardCharsets;import java.util.concurrent.TimeUnit;
public final class Libbox {
 private static String call(String op,String config,String policy)throws Exception {
  Process p=new ProcessBuilder(System.getenv("ROUTERVPN_GO_POLICY_TEST")).start();
  try {
   JSONObject input=new JSONObject().put("Operation",op).put("Config",config).put("Policy",policy);
   p.getOutputStream().write(input.toString().getBytes(StandardCharsets.UTF_8));p.getOutputStream().close();
   // Fixtures are deliberately bounded to less than a pipe buffer.
   if(!p.waitFor(10,TimeUnit.SECONDS))throw new IllegalStateException("Native policy test timed out");
   String out=new String(p.getInputStream().readAllBytes(),StandardCharsets.UTF_8);
   String error=new String(p.getErrorStream().readAllBytes(),StandardCharsets.UTF_8);
   if(p.exitValue()!=0)throw new IllegalArgumentException(error);
   return out;
  }finally{p.destroyForcibly();}
 }
 public static String routerCompileWireGuardProfile(String c,String p)throws Exception{return call("parse",c,p);}
 public static String routerWireGuardExitConfig(String c,String p)throws Exception{return call("exit",c,p);}
 public static String routerCompileAmneziaProfile(String c,String p)throws Exception{return call("awg-parse",c,p);}
 public static String routerAmneziaExitConfig(String c,String p)throws Exception{return call("awg-exit",c,p);}
 public static String testCertificate(String name)throws Exception{return call("test-certificate",name,"");}
 public static String testPlan(String c,String p)throws Exception{return call("plan",c,p);}
 public static String routerCompileProxyEntry(String c,String p)throws Exception{return call("proxy-entry",c,p);}
 public static String routerMultihopMTUProfile(String c,String p)throws Exception{return call("mtu-profile",c,p);}
 public static String routerApplyMultihopMTUPolicy(String c,String p)throws Exception{return call("mtu",c,p);}
 public static String routerApplyMultihopLANPolicy(String c,String p)throws Exception{return call("lan",c,p);}
 public static String routerApplyPerformancePolicy(String c,String p)throws Exception{return call("performance",c,p);}
 public static String routerCompileSIP003Profile(String a,String b){throw new AssertionError("Unrelated native compiler cannot be substituted");}
 public static boolean rejectConfig;
 public static void checkConfig(String c)throws Exception {if(rejectConfig)throw new IllegalArgumentException("Injected native schema failure");new JSONObject(c);}
}''',
}
HARNESS=r'''package com.eabusham.routervpn;
import android.content.Context;import org.json.*;import java.io.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.security.MessageDigest;import java.util.*;
public final class MultihopGraphHarness {
 static int checks;
 static void check(boolean b,String message){if(!b)throw new AssertionError(message);checks++;}
 static boolean has(JSONArray values,String text)throws Exception {for(int i=0;i<values.length();i++)if(text.equals(values.getString(i)))return true;return false;}
 static String key(char ch){char[] c=new char[32];Arrays.fill(c,ch);return Base64.getEncoder().encodeToString(new String(c).getBytes(StandardCharsets.UTF_8));}
 static String proof(String key)throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(("router-vpn-node-proof-v1\n"+key).getBytes(StandardCharsets.UTF_8)));}
 static String wg(char ch){return "[Interface]\nAddress = 10.77.0.2/24, fd77:77::2/64\nPrivateKey = "+key('z')+"\nDNS = 192.168.50.133\nMTU = 1420\n[Peer]\nPublicKey = "+key(ch)+"\nPresharedKey = "+key('p')+"\nEndpoint = 192.0.2."+(ch=='a'?1:2)+":51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n";}
 static JSONObject bundle(char ch)throws Exception {
  String id="node-"+ch;
  JSONObject profile=new JSONObject().put("id",id).put("dns_mode","home").put("adguard_ipv4","192.168.50.133")
    .put("socks_host","10.77.0.1").put("socks_port",1080).put("router_api","http://10.77.0.1:8787").put("api_token","fixture-token");
  return new JSONObject().put("selectedRouterID",id).put("nodeProofId",proof(key(ch))).put("routerProfiles",new JSONArray().put(profile))
   .put("profiles",new JSONObject().put("wg",new JSONObject().put("wg.conf",Base64.getEncoder().encodeToString(wg(ch).getBytes(StandardCharsets.UTF_8)))))
   .put("modes",new JSONArray().put(new JSONObject().put("id","wg").put("name","WireGuard")));
 }
 static File save(Path dir,JSONObject b)throws Exception{return Files.writeString(dir.resolve(UUID.randomUUID()+".json"),b.toString()).toFile();}
 static JSONObject profile(JSONObject b)throws Exception{return b.getJSONArray("routerProfiles").getJSONObject(0);}
 static int sessions(Path app)throws Exception {Path p=app.resolve("layered-sessions");if(!Files.exists(p))return 0;try(var stream=Files.list(p)){return (int)stream.count();}}
 static JSONObject prepare(AndroidMultihopController builder,Path app,File a,File b,String execution)throws Exception{
  AndroidMultihopController.Prepared result=builder.prepare(a,b,"wg",execution);
  Path session=app.resolve("layered-sessions").resolve(result.session.sessionId);
  check(result.session.modeId.equals("multihop-wg"),"mode was relabelled");
  check(!Files.exists(session.resolve("wg.conf")),"raw second-backend config was staged");
  JSONObject metadata=new JSONObject(Files.readString(session.resolve("routervpn-multihop.json")));
  check(metadata.getString("execution").equals(execution),"execution choice was lost");
  check(!metadata.getString("entry_node_id").equals(metadata.getString("exit_node_id")),"node proofs collapsed");
  JSONObject config=new JSONObject(Files.readString(session.resolve("sing-box.json")));
  check(config.getJSONArray("endpoints").length()==2,"expected two native endpoints");
  JSONObject entry=config.getJSONArray("endpoints").getJSONObject(0),exit=config.getJSONArray("endpoints").getJSONObject(1);
  check(entry.getString("tag").equals("entry-wg")&&!entry.has("detour"),"entry socket ownership changed");
  check(exit.getString("tag").equals("proxy")&&exit.getString("detour").equals("entry-wg"),"exit bypasses entry");
  check(exit.getInt("mtu")==1360&&entry.getInt("mtu")==1420,"nested MTU bound lost");
  for(JSONObject e:new JSONObject[]{entry,exit})check(e.getJSONArray("peers").getJSONObject(0).getInt("persistent_keepalive_interval")==25,"keepalive dropped");
  check(config.getJSONArray("outbounds").length()==1,"unexpected alternate exit outbound");
  check(config.getJSONArray("outbounds").getJSONObject(0).getString("detour").equals("entry-wg"),"private proof path lost entry");
  check(config.getJSONArray("inbounds").length()==3,"one TUN and separate proof lanes required");
  check(config.getJSONArray("inbounds").getJSONObject(1).getInt("listen_port")==1098,"entry proof lane changed");
  check(config.getJSONArray("inbounds").getJSONObject(2).getInt("listen_port")==1099,"exit proof lane changed");
  JSONObject dns=config.getJSONObject("dns").getJSONArray("servers").getJSONObject(0);
  check(dns.getString("detour").equals("proxy"),"DNS bypasses the encrypted exit");
  return config;
 }
 interface Mutation {void apply(JSONObject b)throws Exception;}
 static JSONObject direct(NativeSingBoxController nativeWG,Path dir,Path app,JSONObject bundle)throws Exception {
  File source=save(dir,bundle);byte[] original=Files.readAllBytes(source.toPath());
  check(nativeWG.listDirectLibboxModes(source).stream().anyMatch(m->m.id.equals("wg")),"native single WG absent from selector");
  NativeSingBoxController.SessionInfo info=nativeWG.prepareSession(source,"wg");
  Path session=app.resolve("layered-sessions").resolve(info.sessionId);
  check(info.modeId.equals("wg"),"native single WG mode relabelled");
  check(!Files.exists(session.resolve("wg.conf")),"single WG staged a second raw VPN config");
  check(!Files.exists(session.resolve("routervpn-multihop.json")),"single WG claimed multihop");
  JSONObject graph=new JSONObject(Files.readString(session.resolve("sing-box.json")));
  check(graph.getJSONArray("inbounds").length()==1,"single WG has multiple OS inbounds");
  check(graph.getJSONArray("endpoints").length()==1&&graph.getJSONArray("outbounds").length()==0,"single WG has an unowned exit");
  check(!graph.getJSONArray("endpoints").getJSONObject(0).has("detour"),"single WG depends on another tunnel");
  check(graph.getJSONArray("endpoints").getJSONObject(0).getJSONArray("peers").getJSONObject(0).getInt("persistent_keepalive_interval")==25,"single WG lost keepalive");
  check(Arrays.equals(original,Files.readAllBytes(source.toPath())),"single WG mutated source credentials");
  JSONArray dns=graph.getJSONObject("dns").getJSONArray("servers");
  for(int n=0;n<dns.length();n++)check(dns.getJSONObject(n).getString("detour").equals("proxy"),"DNS or bootstrap escapes native WG");
  return graph;
 }
 static void directRejected(NativeSingBoxController nativeWG,Path dir,Path app,Mutation mutation)throws Exception {
  JSONObject source=bundle('b');mutation.apply(source);File file=save(dir,source);int count=sessions(app);
  boolean failed=false;try{nativeWG.prepareSession(file,"wg");}catch(Exception expected){failed=true;}
  check(failed,"invalid single WG policy accepted");check(sessions(app)==count,"invalid single WG left session state");
  check(nativeWG.listDirectLibboxModes(file).stream().noneMatch(m->m.id.equals("wg")),"invalid WG policy advertised as runnable");
 }

 static JSONObject awgBundle(char ch)throws Exception {
  JSONObject source=bundle(ch);
  String options="Jc=3\nJmin=40\nJmax=900\nS1=56\nS2=48\nS3=24\nS4=32\nH1=10000000-19999999\nH2=20000000-29999999\nH3=30000000-39999999\nH4=40000000-49999999\n";
  String config=wg(ch).replace("[Peer]",options+"[Peer]").replace(key(ch),key((char)(ch+5)));
  for(String mode:new String[]{"awg2-fast","awg2-strong"}) {
   String variant=mode.equals("awg2-strong")?config.replace("Jc=3","Jc=6").replace("S4=32","S4=80"):config;
   source.getJSONObject("profiles").put(mode,new JSONObject().put("awg.conf",Base64.getEncoder().encodeToString(variant.getBytes(StandardCharsets.UTF_8))));
   source.getJSONArray("modes").put(new JSONObject().put("id",mode).put("name",mode));
  }
  return source;
 }
 static void awgChecks(Context context,Path dir,Path app)throws Exception {
  NativeSingBoxController controller=new NativeSingBoxController(context);
  for(String mode:new String[]{"awg2-fast","awg2-strong"})for(String dnsMode:new String[]{"home","custom","dot","doh","doh3"}) {
   JSONObject source=awgBundle('b'),policy=profile(source);
   policy.put("dns_mode",dnsMode).put("dns_host","resolver.example.test").put("dns_protocol","tcp").put("dns_server_name","resolver.example.test")
     .put("home_lan_access",false).put("ipv6_mode","off").put("kill_switch",true).put("mtu_policy","fixed").put("manual_mtu",1360);
   File bundleFile=save(dir,source);byte[] original=Files.readAllBytes(bundleFile.toPath());
   check(controller.listDirectLibboxModes(bundleFile).stream().anyMatch(m->m.id.equals(mode)),"native AWG missing from mode selection");
   NativeSingBoxController.SessionInfo selected=controller.prepareSession(bundleFile,mode);
   Path session=app.resolve("layered-sessions").resolve(selected.sessionId);
   JSONObject config=new JSONObject(Files.readString(session.resolve("sing-box.json")));
   JSONObject endpoint=config.getJSONArray("endpoints").getJSONObject(0);
   check(selected.modeId.equals(mode)&&endpoint.getString("type").equals("routervpn-amneziawg"),"AWG variant was relabelled as standard WG");
   check(config.getJSONArray("endpoints").length()==1&&config.getJSONArray("inbounds").length()==1,"AWG opened a second VPN");
   check(!Files.exists(session.resolve("awg.conf"))&&Files.exists(session.resolve(AndroidKillSwitchPolicy.SESSION_MARKER)),"AWG staging lost strict ownership");
   check(endpoint.getJSONObject("amnezia").length()==11,"AWG obfuscation parameters were dropped");
   check(endpoint.getJSONObject("amnezia").getString("s4").equals(mode.equals("awg2-strong")?"80":"32"),"AWG Strong became Fast");
   check(endpoint.getJSONArray("peers").getJSONObject(0).getString("public_key").equals(key('g')),"AWG key was replaced with the node's WG identity key");
   check(endpoint.getInt("mtu")==1360&&config.getJSONArray("inbounds").getJSONObject(0).getInt("mtu")==1360,"AWG MTU policy not applied");
   JSONArray servers=config.getJSONObject("dns").getJSONArray("servers");String expected=dnsMode.equals("home")?"udp":dnsMode.equals("custom")?"tcp":dnsMode.equals("dot")?"tls":dnsMode.equals("doh")?"https":"h3";
   check(servers.getJSONObject(servers.length()-1).getString("type").equals(expected),"AWG selected DNS transport was lost");
   for(int i=0;i<servers.length();i++)check(servers.getJSONObject(i).getString("detour").equals("proxy"),"AWG DNS escaped its encrypted endpoint");
   check(config.getJSONObject("dns").getString("strategy").equals("ipv4_only"),"AWG IPv6-Off policy lost");
   check(Arrays.equals(original,Files.readAllBytes(bundleFile.toPath())),"AWG source credentials mutated");
  }
  JSONObject invalid=awgBundle('b');String encoded=invalid.getJSONObject("profiles").getJSONObject("awg2-fast").getString("awg.conf");
  String raw=new String(Base64.getDecoder().decode(encoded),StandardCharsets.UTF_8).replace("S4=32\n","");
  invalid.getJSONObject("profiles").getJSONObject("awg2-fast").put("awg.conf",Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8)));
  int before=sessions(app);boolean failed=false;
  try{controller.prepareSession(save(dir,invalid),"awg2-fast");}catch(Exception expected){failed=true;}
  check(failed&&sessions(app)==before,"incomplete AWG was silently downgraded");
 }

 static void awgEntryChecks(Context context,Path dir)throws Exception {
  Path app=Files.createDirectory(dir.resolve("awg-entry-app"));Context isolated=new Context(app.toFile());
  AndroidMultihopController builder=new AndroidMultihopController(isolated,new NativeSingBoxController(isolated));
  JSONObject a=awgBundle('a'),b=bundle('b');File entry=save(dir,a),exit=save(dir,b);
  for(String mode:new String[]{"awg2-fast","awg2-strong"})for(String execution:new String[]{"local","server","auto"}) {
   AndroidMultihopController.Prepared result=builder.prepare(entry,exit,"wg",execution,mode);
   Path session=app.resolve("layered-sessions").resolve(result.session.sessionId);
   JSONObject graph=new JSONObject(Files.readString(session.resolve("sing-box.json")));
   JSONObject meta=new JSONObject(Files.readString(session.resolve("routervpn-multihop.json")));
   JSONObject first=graph.getJSONArray("endpoints").getJSONObject(0),last=graph.getJSONArray("endpoints").getJSONObject(1);
   check(first.getString("type").equals("routervpn-amneziawg")&&last.getString("type").equals("wireguard"),"AWG entry was silently converted to WG");
   check(last.getString("detour").equals(first.getString("tag")),"exit does not use the AWG entry");
   check(meta.getString("entry_mode").equals(mode)&&meta.getString("execution").equals(execution),"frozen AWG graph identity lost");
   check(first.getJSONObject("amnezia").getString("jc").equals(mode.equals("awg2-fast")?"3":"6"),"AWG entry strength silently changed");
   check(first.getJSONArray("peers").getJSONObject(0).getString("public_key").equals(key('f')),"AWG entry used wrong peer key");
   check(meta.getString("entry_node_id").equals(a.getString("nodeProofId")),"AWG entry discarded independent node proof");
   check(graph.getJSONArray("inbounds").length()==3,"AWG entry opened another OS TUN");
  }
  boolean failed=false;try{builder.prepare(entry,exit,"wg","local","awg2-pq");}catch(Exception expected){failed=true;}
  check(failed,"unimplemented AWG PQ mislabeled as Fast");
 }

 static void awgExitChecks(Path dir)throws Exception {
  Path app=Files.createDirectory(dir.resolve("awg-exit-app"));Context context=new Context(app.toFile());
  AndroidMultihopController builder=new AndroidMultihopController(context,new NativeSingBoxController(context));
  JSONObject a=awgBundle('a'),b=awgBundle('b');
  // The entry and exit are distinct nodes with different AWG server keys.
  File entry=save(dir,a),exit=save(dir,b);byte[] original=Files.readAllBytes(exit.toPath());
  for(String mode:new String[]{"awg2-fast","awg2-strong"}) {
   check(builder.listSupportedExitModes(exit).stream().anyMatch(m->m.id.equals(mode)),"AWG exit not offered by real readiness picker");
   for(String entryMode:new String[]{"wg","awg2-fast","awg2-strong"})for(String execution:new String[]{"local","server","auto"}) {
    // Strong's 80-byte S4 fits the dual-stack floor with a 1500-byte entry.
    JSONObject imported=new JSONObject(a.toString());profile(imported).put("mtu_policy","fixed").put("manual_mtu",1500);
    AndroidMultihopController.Prepared result=builder.prepare(save(dir,imported),exit,mode,execution,entryMode);
    Path session=app.resolve("layered-sessions").resolve(result.session.sessionId);
    JSONObject graph=new JSONObject(Files.readString(session.resolve("sing-box.json"))),meta=new JSONObject(Files.readString(session.resolve("routervpn-multihop.json")));
    JSONArray endpoints=graph.getJSONArray("endpoints");JSONObject first=endpoints.getJSONObject(0),last=endpoints.getJSONObject(1);
    check(last.getString("type").equals("routervpn-amneziawg"),"AWG exit silently replaced with WG");
    check(last.getString("detour").equals(first.getString("tag")),"AWG exit escaped selected entry");
    check(last.getJSONObject("amnezia").length()==11&&last.getJSONObject("amnezia").getString("s4").equals(mode.equals("awg2-strong")?"80":"32"),"AWG exit strength or padding lost");
    check(last.getJSONArray("peers").getJSONObject(0).getString("public_key").equals(key('g')),"exit uses entry or WG peer credentials");
    check(meta.getString("exit_mode").equals(mode)&&meta.getString("entry_mode").equals(entryMode)&&meta.getString("execution").equals(execution),"native graph identity drifted");
    int limit=((1500-60-Integer.parseInt(last.getJSONObject("amnezia").getString("s4")))/16)*16;
    check(last.getInt("mtu")==Math.min(1420,limit),"AWG exit sizing forgot transport padding");
    check(graph.getJSONArray("inbounds").length()==3&&!Files.exists(session.resolve("awg.conf")),"AWG exit opened a second VPN");
    JSONArray dns=graph.getJSONObject("dns").getJSONArray("servers");for(int i=0;i<dns.length();i++)check(dns.getJSONObject(i).getString("detour").equals("proxy"),"AWG exit DNS escaped");
   }
  }
  check(Arrays.equals(original,Files.readAllBytes(exit.toPath())),"AWG exit mutated its saved source");
  for(String mode:new String[]{"awg2-fast","awg2-strong"}) {
   JSONObject bad=new JSONObject(b.toString());JSONObject nativeFiles=bad.getJSONObject("profiles").getJSONObject(mode);
   String raw=new String(Base64.getDecoder().decode(nativeFiles.getString("awg.conf")),StandardCharsets.UTF_8).replace(mode.equals("awg2-strong")?"S4=80\n":"S4=32\n","");
   nativeFiles.put("awg.conf",Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8)));
   File broken=save(dir,bad);int before=sessions(app);boolean failed=false;
   try{builder.prepare(entry,broken,mode);}catch(Exception expected){failed=true;}
   check(failed&&sessions(app)==before,"missing AWG exit parameter left staged session");
   List<NativeSingBoxController.ModeInfo> available=builder.listSupportedExitModes(broken);
   check(available.stream().noneMatch(m->m.id.equals(mode)),"malformed AWG exit falsely ready");
   String intact=mode.equals("awg2-fast")?"awg2-strong":"awg2-fast";
   check(available.stream().anyMatch(m->m.id.equals(intact)),"one invalid AWG exit hid the other valid AWG variant");
   check(available.stream().anyMatch(m->m.id.equals("wg")),"invalid AWG exit hid valid standard WireGuard");
   check(sessions(app)==before,"read-only mode listing staged a native session");
  }
 }

 static JSONObject proxyBundle(char ch,String mode,String certificate)throws Exception {
  JSONObject source=awgBundle(ch);
  JSONObject outbound=new JSONObject().put("tag","proxy").put("type",mode).put("server",ch=='a'?"192.0.2.11":"198.51.100.12").put("server_port",8443)
   .put("password",ch=='a'?"entry-only-secret":"exit-only-secret");
  if(mode.equals("shadowsocks"))outbound.put("method","chacha20-ietf-poly1305");
  else outbound.put("tls",new JSONObject().put("enabled",true).put("server_name",ch=='a'?"entry.example.test":"exit.example.test").put("certificate_path","trust.pem"));
  JSONObject config=new JSONObject().put("log",new JSONObject().put("level","warn"))
   .put("inbounds",new JSONArray().put(new JSONObject().put("type","tun").put("tag","tun-in").put("address",new JSONArray().put("172.29.94.1/30").put("fd29:94::1/126")).put("auto_route",true).put("strict_route",true).put("mtu",1280)))
   .put("outbounds",new JSONArray().put(outbound))
   .put("dns",new JSONObject().put("servers",new JSONArray().put(new JSONObject().put("type","udp").put("tag","selected-dns").put("server","192.168.50.133").put("detour","proxy"))))
   .put("route",new JSONObject().put("final","proxy").put("auto_detect_interface",true).put("rules",new JSONArray().put(new JSONObject().put("protocol","dns").put("action","hijack-dns"))));
  JSONObject files=new JSONObject().put("sing-box.json",Base64.getEncoder().encodeToString(config.toString().getBytes(StandardCharsets.UTF_8)));
  if(mode.equals("hysteria2"))files.put("trust.pem",Base64.getEncoder().encodeToString(certificate.getBytes(StandardCharsets.UTF_8)));
  source.getJSONObject("profiles").put(mode,files);
  source.getJSONArray("modes").put(new JSONObject().put("id",mode).put("name",mode));
  return source;
 }
 static JSONObject byTag(JSONObject graph,String tag)throws Exception {
  for(String list:new String[]{"endpoints","outbounds"}){
   JSONArray entries=graph.optJSONArray(list);if(entries==null)continue;
   for(int i=0;i<entries.length();i++)if(entries.getJSONObject(i).optString("tag").equals(tag))return entries.getJSONObject(i);
  }
  throw new AssertionError("Missing graph owner: "+tag);
 }
 static void proxyRejected(Path dir,JSONObject a,JSONObject b,String entryMode,String exitMode)throws Exception {
  Path app=Files.createTempDirectory(dir,"rejected-proxy-");Context context=new Context(app.toFile());
  AndroidMultihopController builder=new AndroidMultihopController(context,new NativeSingBoxController(context));
  File entry=save(dir,a),exit=save(dir,b);byte[] beforeA=Files.readAllBytes(entry.toPath()),beforeB=Files.readAllBytes(exit.toPath());
  boolean rejected=false;try{builder.prepare(entry,exit,exitMode,"auto",entryMode);}catch(Exception expected){rejected=true;}
  check(rejected,"invalid proxy entry was accepted");check(sessions(app)==0,"invalid proxy entry staged private session state");
  check(Arrays.equals(beforeA,Files.readAllBytes(entry.toPath()))&&Arrays.equals(beforeB,Files.readAllBytes(exit.toPath())),"rejected proxy graph changed source credentials");
 }
 static void proxyEntryChecks(Path dir)throws Exception {
  String entryCert=io.nekohasekai.libbox.Libbox.testCertificate("entry.example.test"),exitCert=io.nekohasekai.libbox.Libbox.testCertificate("exit.example.test");
  for(String entryMode:new String[]{"shadowsocks","hysteria2"})for(String exitMode:new String[]{"wg","awg2-fast","awg2-strong","shadowsocks","hysteria2"}) {
   Path app=Files.createTempDirectory(dir,"proxy-app-");Context context=new Context(app.toFile());
   AndroidMultihopController builder=new AndroidMultihopController(context,new NativeSingBoxController(context));
   JSONObject a=proxyBundle('a',entryMode,entryCert),b=NativeSingBoxController.nativeWireGuardFamily(exitMode)?awgBundle('b'):proxyBundle('b',exitMode,exitCert);
   profile(a).put("mtu_policy","fixed").put("manual_mtu",1500).put("kill_switch",true);
   profile(b).put("mtu_policy","auto").put("effective_mtu",9000);
   File entry=save(dir,a),exit=save(dir,b);byte[] beforeA=Files.readAllBytes(entry.toPath()),beforeB=Files.readAllBytes(exit.toPath());
   for(String execution:new String[]{"local","server","auto"}) {
    AndroidMultihopController.Prepared result=builder.prepare(entry,exit,exitMode,execution,entryMode);
    Path session=app.resolve("layered-sessions").resolve(result.session.sessionId);
    JSONObject graph=new JSONObject(Files.readString(session.resolve("sing-box.json"))),meta=new JSONObject(Files.readString(session.resolve("routervpn-multihop.json"))),mtu=new JSONObject(Files.readString(session.resolve("routervpn-mtu.json")));
    JSONObject first=byTag(graph,"entry-wg"),last=byTag(graph,"proxy"),privateProxy=byTag(graph,"entry-private");
    check(first.getString("type").equals(entryMode)&&first.getString("password").equals("entry-only-secret"),"entry lost its exact native transport or credential");
    check(!first.has("detour")&&!first.has("mtu"),"proxy entry gained a fake packet interface or upstream bypass");
    check(last.getString("detour").equals("entry-wg")&&privateProxy.getString("detour").equals("entry-wg"),"exit/private proof sockets do not traverse entry");
    check(graph.getJSONArray("endpoints").length()==(NativeSingBoxController.nativeWireGuardFamily(exitMode)?1:0),"proxy entry staged an extra native packet endpoint");
    check(graph.getJSONArray("inbounds").length()==3&&graph.getJSONArray("inbounds").getJSONObject(0).getString("type").equals("tun"),"proxy entry did not retain one system TUN plus two proof lanes");
    check(graph.getJSONArray("inbounds").getJSONObject(1).getInt("listen_port")==1098&&graph.getJSONArray("inbounds").getJSONObject(2).getInt("listen_port")==1099,"separate entry/exit measurement ports collapsed");
    check(graph.getJSONArray("inbounds").getJSONObject(0).getInt("mtu")==1500,"entry fixed MTU was overwritten by exit Auto");
    check(mtu.getString("mtu_policy").equals("fixed")&&mtu.getInt("manual_mtu")==1500&&mtu.getString("node_proof_id").equals(b.getString("nodeProofId")),"optimizer metadata lost fixed shared TUN or selected exit proof");
    check(meta.getString("entry_mode").equals(entryMode)&&meta.getString("exit_mode").equals(exitMode)&&meta.getString("execution").equals(execution),"frozen transport/execution identity drifted");
    check(meta.getString("entry_node_id").equals(a.getString("nodeProofId"))&&meta.getString("exit_node_id").equals(b.getString("nodeProofId")),"node proof ownership collapsed");
    check(Files.exists(session.resolve(AndroidKillSwitchPolicy.SESSION_MARKER))&&!Files.exists(session.resolve("wg.conf"))&&!Files.exists(session.resolve("awg.conf")),"strict policy or single-VPN staging ownership lost");
    if(NativeSingBoxController.nativeWireGuardFamily(exitMode)){
     check(last.getInt("mtu")==1500,"packet exit ignored fixed shared TUN policy");
     check(last.getJSONArray("peers").getJSONObject(0).getString("public_key").equals(key(exitMode.equals("wg")?'b':'g')),"exit peer key came from the entry");
     if(!exitMode.equals("wg"))check(last.getJSONObject("amnezia").length()==11&&last.getJSONObject("amnezia").getString("s4").equals(exitMode.equals("awg2-strong")?"80":"32"),"AWG exit strength lost through proxy entry");
    }else check(last.getString("type").equals(exitMode)&&last.getString("password").equals("exit-only-secret"),"proxy exit borrowed entry credentials");
    if(entryMode.equals("hysteria2"))check(!first.getJSONObject("tls").has("certificate_path")&&first.getJSONObject("tls").getJSONArray("certificate").getString(0).equals(entryCert),"entry TLS did not retain its own inlined trust asset");
    if(exitMode.equals("hysteria2"))check(Files.readString(session.resolve("trust.pem")).equals(exitCert)&&last.getJSONObject("tls").getString("certificate_path").equals("trust.pem"),"entry certificate overwrote exit same-name trust asset");
    else check(!Files.exists(session.resolve("trust.pem")),"entry-only certificate leaked into exit files");
    JSONArray dns=graph.getJSONObject("dns").getJSONArray("servers");for(int i=0;i<dns.length();i++)check(dns.getJSONObject(i).getString("detour").equals("proxy"),"DNS escaped the selected exit");
    JSONObject planned=new JSONObject(io.nekohasekai.libbox.Libbox.testPlan(graph.toString(),meta.toString()));
    check(byTag(planned,"entry-wg").toString().equals(first.toString()),"Local/Server/Auto compiler changed entry credential ownership");
    check(byTag(planned,"routervpn-execution-local").getString("detour").equals("entry-wg"),"local candidate bypasses entry");
    check(byTag(planned,"routervpn-execution-server").getString("detour").equals("entry-wg"),"server candidate bypasses entry");
    check(byTag(planned,"proxy").getString("type").equals("selector"),"execution is not owned by native selector");
    String fixtures=System.getenv("ROUTERVPN_ANDROID_GRAPH_FIXTURES");
    if(fixtures!=null&&!fixtures.isEmpty()){
     Path out=Path.of(fixtures).resolve(entryMode+"-"+exitMode+"-"+execution);Files.createDirectories(out);
     Files.writeString(out.resolve("sing-box.json"),graph.toString());Files.writeString(out.resolve("planned.json"),planned.toString());
     if(exitMode.equals("hysteria2"))Files.writeString(out.resolve("trust.pem"),exitCert);
    }
   }
   check(Arrays.equals(beforeA,Files.readAllBytes(entry.toPath()))&&Arrays.equals(beforeB,Files.readAllBytes(exit.toPath())),"proxy graph preparation mutated private source bundles");
   JSONObject conflict=new JSONObject(b.toString());profile(conflict).put("mtu_policy","fixed").put("manual_mtu",1400);proxyRejected(dir,a,conflict,entryMode,exitMode);
  }
  for(String mode:new String[]{"shadowsocks","hysteria2"}) {
   JSONObject a=proxyBundle('a',mode,entryCert),b=awgBundle('b');
   for(String kind:new String[]{"detour","network","server","mode","routing","helper","missing"}) {
    JSONObject bad=new JSONObject(a.toString()),files=bad.getJSONObject("profiles").getJSONObject(mode);
    JSONObject config=new JSONObject(new String(Base64.getDecoder().decode(files.getString("sing-box.json")),StandardCharsets.UTF_8)),out=config.getJSONArray("outbounds").getJSONObject(0);
    if(kind.equals("detour"))out.put("detour","bypass");else if(kind.equals("network"))out.put("network","tcp");else if(kind.equals("server"))out.put("server","unowned.example.test");else if(kind.equals("mode"))out.put("type","socks");else if(kind.equals("routing"))config.getJSONObject("route").put("rules",new JSONArray().put(new JSONObject().put("ip_is_private",true).put("outbound","direct")));else if(kind.equals("helper"))files.put("xray.json","e30=");
    files.put("sing-box.json",Base64.getEncoder().encodeToString(config.toString().getBytes(StandardCharsets.UTF_8)));
    if(kind.equals("missing"))bad.getJSONObject("profiles").remove(mode);
    proxyRejected(dir,bad,b,mode,"wg");
   }
   io.nekohasekai.libbox.Libbox.rejectConfig=true;
   try{proxyRejected(dir,a,b,mode,"wg");}finally{io.nekohasekai.libbox.Libbox.rejectConfig=false;}
  }
 }

 static void directChecks(Context context,Path dir,Path app)throws Exception {
  NativeSingBoxController nativeWG=new NativeSingBoxController(context);
  JSONObject source=bundle('b');profile(source).put("effective_mtu",9000).put("mtu_policy","auto");
  JSONObject graph=direct(nativeWG,dir,app,source);
  check(graph.getJSONArray("endpoints").getJSONObject(0).getInt("mtu")==1420,"stale saved MTU adopted as current path proof");
  check(AndroidNativeProfilePolicy.selectedMtu(source,1380)==1380,"raw backend adopted stale saved MTU");
  check(AndroidNativeProfilePolicy.requiresLibbox(source),"adaptive MTU selected an address-only backend without its owner");
  JSONObject fixedHome=new JSONObject(source.toString());profile(fixedHome).put("mtu_policy","fixed").put("manual_mtu",1380);
  check(!AndroidNativeProfilePolicy.requiresLibbox(fixedHome),"fixed home DNS lost raw WG capability");
  String fixedRaw=AndroidNativeProfilePolicy.patchWireGuardLikeConfig(fixedHome,wg('b'),1380);
  check(fixedRaw.contains("DNS = 192.168.50.133")&&fixedRaw.contains("MTU = 1380"),"raw fixed policy lost its requested DNS or MTU");
  boolean adaptiveRawRejected=false;
  try{AndroidNativeProfilePolicy.patchWireGuardLikeConfig(source,wg('b'),1380);}catch(Exception expected){adaptiveRawRejected=true;}
  check(adaptiveRawRejected,"address-only backend silently accepted adaptive MTU");
  check(AndroidNativeProfilePolicy.selectedPlainUdpDns(source).equals("192.168.50.133"),"literal home DNS rejected");
  for(String mode:new String[]{"custom","dot","doh","doh3"}) {
   source=bundle('b');JSONObject policy=profile(source);
   policy.put("mtu_policy","fixed").put("manual_mtu",1380).put("dns_mode",mode).put("dns_host","192.0.2.53").put("dns_protocol","tcp").put("dns_server_name","dns.example.test");
   if(mode.equals("custom"))policy.put("dns_port",5353);
   graph=direct(nativeWG,dir,app,source);
   JSONObject dns=graph.getJSONObject("dns").getJSONArray("servers").getJSONObject(0);
   String expected=mode.equals("custom")?"tcp":mode.equals("dot")?"tls":mode.equals("doh")?"https":"h3";
   check(dns.getString("type").equals(expected),"advanced DNS protocol was downgraded");
   check(dns.getString("server").equals("192.0.2.53"),"saved DNS was substituted");
   if(!mode.equals("custom"))check(dns.getJSONObject("tls").getString("server_name").equals("dns.example.test"),"TLS identity was lost");
   check(AndroidNativeProfilePolicy.requiresLibbox(source),"AUTO would choose address-only backend for advanced DNS");
  }
  source=bundle('b');profile(source).put("dns_mode","doh").put("dns_host","resolver.example.test");
  graph=direct(nativeWG,dir,app,source);JSONArray dns=graph.getJSONObject("dns").getJSONArray("servers");
  check(dns.length()==2&&dns.getJSONObject(0).getString("server").equals("192.168.50.133"),"hostname bootstrap lost configured AdGuard");
  check(dns.getJSONObject(1).getString("domain_resolver").equals("routervpn-bootstrap-dns"),"hostname DNS bootstrap can recurse");
  source=bundle('b');profile(source).put("adguard_ipv4","").put("adguard_ipv6","fd50::53");
  graph=direct(nativeWG,dir,app,source);
  check(graph.getJSONObject("dns").getJSONArray("servers").getJSONObject(0).getString("server").equals("fd50::53"),"IPv6-only AdGuard policy lost");
  source=bundle('b');profile(source).put("mtu_policy","fixed").put("manual_mtu",1350).put("ipv6_mode","off").put("home_lan_access",false).put("kill_switch",true);
  graph=direct(nativeWG,dir,app,source);JSONObject tun=graph.getJSONArray("inbounds").getJSONObject(0);
  check(tun.getInt("mtu")==1350&&graph.getJSONArray("endpoints").getJSONObject(0).getInt("mtu")==1350,"fixed MTU not applied to both native interfaces");
  check(tun.getJSONArray("address").length()==2,"IPv6 off removed capture instead of rejecting traffic");
  check(graph.getJSONObject("dns").getString("strategy").equals("ipv4_only"),"IPv6 off DNS policy lost");
  JSONArray rules=graph.getJSONObject("route").getJSONArray("rules");boolean v6=false,lan=false,proof=false;
  for(int i=0;i<rules.length();i++){
   JSONObject rule=rules.getJSONObject(i);
   if("reject".equals(rule.optString("action"))&&rule.optInt("ip_version")==6)v6=true;
   if("reject".equals(rule.optString("action"))&&rule.has("ip_cidr")&&has(rule.getJSONArray("ip_cidr"),"192.168.0.0/16"))lan=true;
   if("route".equals(rule.optString("action"))&&rule.has("port")&&rule.getInt("port")==8787)proof=true;
  }
  check(v6&&lan&&proof,"single WG lost IPv6/LAN rejection or exact private proof exception");
  check(AndroidNativeProfilePolicy.requiresLibbox(source),"LAN/IPv6 constraints do not select policy-capable WG");
  for(Object invalid:new Object[]{0,1279,9001,1340.5,true,"1350",JSONObject.NULL}) {
   directRejected(nativeWG,dir,app,x->profile(x).put("mtu_policy","fixed").put("manual_mtu",invalid));
  }
  directRejected(nativeWG,dir,app,x->x.put("selectedRouterID","missing-node"));
  directRejected(nativeWG,dir,app,x->x.getJSONArray("routerProfiles").put(new JSONObject(profile(x).toString())));
  directRejected(nativeWG,dir,app,x->x.put("nodeProofId",proof(key('x'))));
  directRejected(nativeWG,dir,app,x->profile(x).put("mtu_policy","unknown"));
  directRejected(nativeWG,dir,app,x->profile(x).put("ipv6_mode","unknown"));
  directRejected(nativeWG,dir,app,x->profile(x).put("home_lan_access","false"));
  source=bundle('b');profile(source).put("daita_enabled",true);
  graph=direct(nativeWG,dir,app,source);
  check(graph.getJSONArray("services").length()==1&&graph.getJSONArray("services").getJSONObject(0).getString("packet_tag").equals("proxy"),"WG padding is not owned by the selected native endpoint");
  directRejected(nativeWG,dir,app,x->profile(x).put("daita_enabled",true).put("daita_rate_kbps",9999));
  directRejected(nativeWG,dir,app,x->profile(x).put("jumbo_tun",true));
  directRejected(nativeWG,dir,app,x->profile(x).put("start_layer","aes"));
  directRejected(nativeWG,dir,app,x->profile(x).put("dns_mode","fastest"));
  directRejected(nativeWG,dir,app,x->profile(x).put("dns_mode","unknown"));
  directRejected(nativeWG,dir,app,x->profile(x).put("dns_mode","custom").put("dns_host","192.0.2.53").put("dns_port",65536));
  directRejected(nativeWG,dir,app,x->x.getJSONObject("profiles").getJSONObject("wg").put("outer-xray.json","e30="));
  io.nekohasekai.libbox.Libbox.rejectConfig=true;
  try { directRejected(nativeWG,dir,app,x->{}); }
  finally { io.nekohasekai.libbox.Libbox.rejectConfig=false; }
  // The strict marker must belong to the newly prepared single-node session.
  source=bundle('b');profile(source).put("kill_switch",true);
  NativeSingBoxController.SessionInfo strict=nativeWG.prepareSession(save(dir,source),"wg");
  check(Files.isRegularFile(app.resolve("layered-sessions").resolve(strict.sessionId).resolve(AndroidKillSwitchPolicy.SESSION_MARKER)),"strict WG policy was not delivered to the VpnService");
  for(String extra:new String[]{"DNS = 192.0.2.53\n", "MTU = 1350\n", "[Interface]\n"}) {
   String raw=wg('b').replace("[Peer]",extra+"[Peer]");boolean failed=false;
   try{AndroidNativeProfilePolicy.patchWireGuardLikeConfig(fixedHome,raw,1380);}catch(Exception expected){failed=true;}
   check(failed,"raw policy silently repaired ambiguous interface fields");
  }
 }
 static void rejected(AndroidMultihopController builder,Path app,Path dir,File a,Mutation mutation)throws Exception {
  JSONObject b=bundle('b');mutation.apply(b);int before=sessions(app);File file=save(dir,b);boolean rejected=false;
  try{builder.prepare(a,file,"wg");}catch(Exception expected){rejected=true;}
  check(rejected,"invalid graph was accepted");check(sessions(app)==before,"rejected graph left session state");
 }
 public static void main(String[] args)throws Exception {
  Path dir=Path.of(args[0]);Path app=Files.createDirectory(dir.resolve("app"));Context context=new Context(app.toFile());
  AndroidMultihopController builder=new AndroidMultihopController(context,new NativeSingBoxController(context));
  File a=save(dir,bundle('a')),b=save(dir,bundle('b'));byte[] originalA=Files.readAllBytes(a.toPath()),originalB=Files.readAllBytes(b.toPath());
  check(builder.listSupportedExitModes(b).stream().anyMatch(m->m.id.equals("wg")),"WireGuard absent from picker");
  for(String execution:new String[]{"local","server","auto"}) prepare(builder,app,a,b,execution);
  JSONObject encrypted=bundle('b');profile(encrypted).put("dns_mode","doh").put("dns_host","1.1.1.1");
  JSONObject config=prepare(builder,app,a,save(dir,encrypted),"local");
  JSONObject dns=config.getJSONObject("dns").getJSONArray("servers").getJSONObject(0);
  check(dns.getString("type").equals("https")&&dns.getJSONObject("tls").getBoolean("enabled"),"DoH silently downgraded");
  JSONObject off=bundle('b');profile(off).put("home_lan_access",false).put("ipv6_mode","off");
  config=prepare(builder,app,a,save(dir,off),"local");
  check(config.getJSONObject("dns").getString("strategy").equals("ipv4_only"),"IPv6-off DNS policy lost");
  check(config.getJSONArray("inbounds").getJSONObject(0).getJSONArray("address").length()==2,"IPv6 capture removed");
  boolean blockedLAN=false;
  JSONArray rules=config.getJSONObject("route").getJSONArray("rules");
  for(int i=0;i<rules.length();i++){
   JSONObject rule=rules.getJSONObject(i);JSONArray cidrs=rule.optJSONArray("ip_cidr");
   if("reject".equals(rule.optString("action")) && cidrs!=null && has(cidrs,"192.168.0.0/16") && rule.getJSONArray("inbound").getString(0).equals("tun-in")) blockedLAN=true;
  }
  check(blockedLAN,"LAN-Off has no TUN-owned private-network rejection");
  check(has(config.getJSONArray("inbounds").getJSONObject(0).getJSONArray("route_address"),"192.168.0.0/16"),"LAN capture routes were not installed");
  rejected(builder,app,dir,a,x->x.put("nodeProofId",proof(key('x'))));
  rejected(builder,app,dir,a,x->x.put("selectedRouterID","missing-node"));
  rejected(builder,app,dir,a,x->profile(x).put("mtu_policy","fixed").put("manual_mtu",1400));
  JSONObject padded=bundle('b');profile(padded).put("daita_enabled",true);
  JSONObject paddingGraph=prepare(builder,app,a,save(dir,padded),"local");
  check(paddingGraph.getJSONArray("services").getJSONObject(0).getString("node_id").equals(padded.getString("nodeProofId")),"multihop padding used the wrong node identity");
  rejected(builder,app,dir,a,x->profile(x).put("daita_enabled",true).put("daita_host","192.0.2.12"));
  rejected(builder,app,dir,a,x->profile(x).put("jumbo_tun",true));
  rejected(builder,app,dir,a,x->profile(x).put("start_layer","unowned"));
  rejected(builder,app,dir,a,x->x.getJSONObject("profiles").getJSONObject("wg").put("wg.conf",Base64.getEncoder().encodeToString((wg('b')+"[Peer]\n").getBytes(StandardCharsets.UTF_8))));
  JSONObject same=bundle('a');rejected(builder,app,dir,a,x->{x.put("nodeProofId",same.getString("nodeProofId"));x.put("profiles",same.getJSONObject("profiles"));});
  check(Arrays.equals(originalA,Files.readAllBytes(a.toPath()))&&Arrays.equals(originalB,Files.readAllBytes(b.toPath())),"source bundles mutated");
  boolean failed=false;try{NativeSingBoxController.applySelectedDns(bundle('b'),new JSONObject().put("outbounds",new JSONArray().put(new JSONObject().put("type","direct").put("tag","proxy"))));}catch(Exception expected){failed=true;}
  check(failed,"DNS accepted a direct-only proxy tag");
  directChecks(context,dir,app);
  awgChecks(context,dir,app);
  awgEntryChecks(context,dir);
  awgExitChecks(dir);
  proxyEntryChecks(dir);
  System.out.println("Android shipping native/proxy multihop compiler: PASS ("+checks+" checks; real Go policy, Android handles doubled)");
 }
}
'''

def main():
    for command in ('go','javac','java'):
        if not shutil.which(command):raise RuntimeError(command+' is required for native graph integration tests')
    jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'))
    if not jar.is_file():raise RuntimeError('Install libandroid-json-java or set ANDROID_JSON_JAR to the Android JSON implementation')
    with tempfile.TemporaryDirectory(prefix='.native-graph-test-',dir=ROOT) as go_dir,tempfile.TemporaryDirectory(prefix='routervpn-android-graph-') as temp:
        go_dir=Path(go_dir);temp=Path(temp);(go_dir/'main.go').write_text(GO_HELPER)
        binary=temp/'policy';subprocess.run(['go','build','-o',str(binary),str(go_dir/'main.go')],cwd=ROOT,check=True,timeout=90)
        sources=temp/'src';sources.mkdir()
        for name,source in STUBS.items():
            target=sources/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(source)
        app=sources/'com/eabusham/routervpn';app.mkdir(parents=True,exist_ok=True)
        for name in ('AndroidMultihopController','NativeSingBoxController','AndroidProfileSelection','AndroidNumericAddress','AndroidNativeProfilePolicy','AndroidWireGuardLibboxPolicy','AndroidStartLayer'):
            shutil.copyfile(JAVA/(name+'.java'),app/(name+'.java'))
        (app/'MultihopGraphHarness.java').write_text(HARNESS)
        classes=temp/'classes'
        subprocess.run(['javac','--release','17','-encoding','UTF-8','-proc:none','-cp',str(jar),'-d',str(classes),*[str(p) for p in sources.rglob('*.java')]],check=True,timeout=60)
        fixtures=temp/'fixtures';fixtures.mkdir();env=dict(os.environ,ROUTERVPN_GO_POLICY_TEST=str(binary))
        subprocess.run(['java','-cp',str(classes)+os.pathsep+str(jar),'com.eabusham.routervpn.MultihopGraphHarness',str(fixtures)],env=env,check=True,timeout=80)
if __name__=='__main__':main()
