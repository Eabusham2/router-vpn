#!/usr/bin/env python3
"""Run the shipping Android external-policy capture with the real shared compiler.

Android filesystem handles and the Libbox startup boundary are doubles. Profile
serialization, graph construction, native compilation and session adoption are
production Java/Go. These tests open no network connections.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
GO = r'''package main
import("encoding/json";"fmt";"io";"os";"github.com/Eabusham2/router-vpn/internal/mobilemultihop";nativeopenvpn "github.com/Eabusham2/router-vpn/mobile")
func main(){ raw,_:=io.ReadAll(os.Stdin); var args []string; if err:=json.Unmarshal(raw,&args);err!=nil{panic(err)}; var out string;var err error
switch args[0]{case "transport":err=mobilemultihop.ValidateExternalTransport(args[1],args[2]);case "dns":err=mobilemultihop.ValidateExternalDNS(args[1],args[2]);case "response":err=mobilemultihop.ValidateExternalResponseProbe(args[1],args[2]);case "execution":out,err=mobilemultihop.PrepareExternalExecutionCapture(args[1],args[2],args[3]);case "external":out,err=mobilemultihop.CompileExternalPolicy(args[1],args[2]);case "wg":out,err=mobilemultihop.CompileWireGuardProfile(args[1],args[2]);case "awg":out,err=mobilemultihop.CompileAmneziaProfile(args[1],args[2]);case "private-node-json":err=nativeopenvpn.RouterValidatePrivateNodeJSON(args[1]);case "openvpn-probes":err=nativeopenvpn.RouterValidateExternalOpenVPNResponseProbes(args[1],args[2]);case "openvpn-layers":err=nativeopenvpn.RouterValidateExternalOpenVPNStartLayers(args[1],args[2],args[3],args[4]);case "openvpn-pairing":err=nativeopenvpn.RouterValidateExternalOpenVPNPairing(args[1],args[2]);case "openvpn":out,err=nativeopenvpn.RouterOpenVPNEndpoint(args[1],args[2],args[3],args[4],args[5]);default:panic("unknown operation")};if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)};fmt.Print(out)}'''

STUBS = {
"android/content/Context.java": '''package android.content; public class Context { final java.io.File root; public Context(java.io.File r){root=r;} public Context getApplicationContext(){return this;} public java.io.File getFilesDir(){return root;} }''',
"android/util/Base64.java": '''package android.util; public class Base64 {public static final int DEFAULT=0,NO_WRAP=2;public static byte[] decode(String s,int f){return java.util.Base64.getDecoder().decode(s);}public static String encodeToString(byte[] b,int f){return java.util.Base64.getEncoder().encodeToString(b);}}''',
"io/nekohasekai/libbox/Libbox.java": '''package io.nekohasekai.libbox;
import org.json.JSONArray;import java.nio.charset.StandardCharsets;
public class Libbox { public static Runnable hook;public static String compiler;public static int checked;
static String call(String...args)throws Exception{Process p=new ProcessBuilder(compiler).start();p.getOutputStream().write(new JSONArray(java.util.Arrays.asList(args)).toString().getBytes(StandardCharsets.UTF_8));p.getOutputStream().close();String out=new String(p.getInputStream().readAllBytes(),StandardCharsets.UTF_8),err=new String(p.getErrorStream().readAllBytes(),StandardCharsets.UTF_8);if(p.waitFor()!=0)throw new IllegalStateException(err);return out;}
public static String routerPrepareExternalExecutionCapture(String s,String c,String restored)throws Exception{return call("execution",s,c,restored);}
public static void routerValidateExternalTransport(String s,String c)throws Exception{call("transport",s,c);}public static void routerValidateExternalDNS(String p,String e)throws Exception{call("dns",p,e);}public static void routerValidateExternalResponseProbe(String h,String p)throws Exception{call("response",h,p);}
public static String routerCompileExternalPolicy(String s,String c)throws Exception{String out=call("external",s,c);Runnable h=hook;hook=null;if(h!=null)h.run();return out;}
public static void routerValidatePrivateNodeJSON(String raw)throws Exception{call("private-node-json",raw);}
public static void routerValidateExternalOpenVPNResponseProbes(String profile,String probes)throws Exception{call("openvpn-probes",profile,probes);}
public static void routerValidateExternalOpenVPNStartLayers(String profile,String probes,String layers,String mode)throws Exception{call("openvpn-layers",profile,probes,layers,mode);}
public static void routerValidateExternalOpenVPNPairing(String profile,String pairing)throws Exception{call("openvpn-pairing",profile,pairing);}
public static String version(){return "1.14.1";}public static String routerOpenVPNEndpoint(String c,String u,String p,String t,String d)throws Exception{return call("openvpn",c,u,p,t,d);}
public static String routerCompileWireGuardProfile(String s,String n)throws Exception{return call("wg",s,n);}public static String routerCompileAmneziaProfile(String s,String n)throws Exception{return call("awg",s,n);}public static void checkConfig(String c){checked++;}}
''',
}

BOUNDARIES = r'''
final class AndroidPrivateFileStore {
 static String failName="";
 static byte[] read(java.io.File f,int max)throws Exception{byte[] b=java.nio.file.Files.readAllBytes(f.toPath());if(b.length==0||b.length>max)throw new IllegalStateException("size");return b;}
 static void write(java.io.File f,byte[] b,int max)throws Exception{if(b.length>max||f.getName().equals(failName))throw new IllegalStateException("private write");java.nio.file.Files.write(f.toPath(),b);}
}
final class AndroidTorProfile {
 static boolean isTor(String s){return "tor".equals(s)||"tor-bridge".equals(s);}static void validate(AndroidStandardExitStore.Entry e){throw new IllegalArgumentException("Tor boundary");}
 static NativeSingBoxController.SessionInfo prepare(android.content.Context c,java.io.File f,AndroidStandardExitStore.Entry e,String m){return prepare(c,f,e,m,"local");}
 static NativeSingBoxController.SessionInfo prepare(android.content.Context c,java.io.File f,AndroidStandardExitStore.Entry e,String m,String execution){throw new IllegalArgumentException("Tor boundary");}
 static String strictText(byte[] b)throws Exception{return java.nio.charset.StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(b)).toString();}
 static String digest(byte[] b)throws Exception{StringBuilder s=new StringBuilder();for(byte x:java.security.MessageDigest.getInstance("SHA-256").digest(b))s.append(String.format(java.util.Locale.ROOT,"%02x",x&255));return s.toString();}
}
final class AndroidKillSwitchPolicy {static final String SESSION_MARKER="strict";static boolean strictRequested(org.json.JSONObject b){return false;}}
final class AndroidVpnMutationGuard {static boolean isBusy(android.content.Context c){return false;}}
final class AndroidHomeStateStore {static class Snapshot{boolean connected=false;String phase="off";}static Snapshot snapshot(android.content.Context c){return new Snapshot();}}
final class AndroidRuntimeRegistry {final Engine orchestrator=new Engine(),multihop=new Engine(),singBox=new Engine(),xray=new Engine();static AndroidRuntimeRegistry get(android.content.Context c){return new AndroidRuntimeRegistry();}static class Engine{boolean isRunning(){return false;}boolean isActiveOrTransitioning(){return false;}String getState(){return "DOWN";}}}
final class NativeSingBoxController {static class SessionInfo {final String sessionId,mode;SessionInfo(String s,String m){sessionId=s;mode=m;}SessionInfo(String s,String m,Object owner){this(s,m);}}}
// Full entry assembly is executed by test_android_external_entries.py. These
// direct/policy-focused checks retain their strict raw-WG compiler boundary.
final class AndroidExternalEntry implements AutoCloseable {org.json.JSONObject profile;String config;Object maxPreparation;static AndroidExternalEntry prepare(android.content.Context c,java.io.File f,org.json.JSONObject b,String mode){return null;}void stage(java.io.File f,String s,String m,String g){}public void close(){}}
final class RouterPQNative {static void install(){}}
final class AndroidNodeStore {static final int MAX_BUNDLE=32*1024*1024;static void validateBundle(org.json.JSONObject b)throws Exception{if(!b.has("profiles"))throw new IllegalArgumentException("bundle");}static String stableNodeIdentity(org.json.JSONObject b){return AndroidProfileSelection.selectedRouterProfile(b).optString("node_proof_id");}}
final class AndroidStartLayer {static String selectedMode(org.json.JSONObject b)throws Exception{Object raw=AndroidProfileSelection.selectedRouterProfile(b).opt("start_layer");if(raw==null)return "off";if(!(raw instanceof String))throw new IllegalArgumentException("start layer");return (String)raw;}}
'''

HARNESS = r'''
package com.eabusham.routervpn;
import org.json.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.util.*;
public class ExternalPolicyTest {
static int checks;interface Action{void run()throws Exception;}static void check(boolean b,String s){checks++;if(!b)throw new AssertionError(s);}static void reject(Action r,String s)throws Exception{checks++;try{r.run();}catch(Exception expected){return;}throw new AssertionError(s);}
static JSONObject profile(JSONObject b)throws Exception{return b.getJSONArray("routerProfiles").getJSONObject(0);}static String key(char c){byte[]b=new byte[32];Arrays.fill(b,(byte)c);return Base64.getEncoder().encodeToString(b);}
static boolean sameParams(JSONObject a,JSONObject b)throws Exception{if(a.length()!=11||b.length()!=11)return false;for(String key:AndroidExternalAmnezia.PARAMETERS)if(!a.get(key).equals(b.get(key)))return false;return true;}
static JSONObject awgParameters()throws Exception{return new JSONObject().put("jc","3").put("jmin","40").put("jmax","900").put("s1","15").put("s2","16").put("s3","32").put("s4","32").put("h1","100-110").put("h2","200-210").put("h3","300-310").put("h4","400-410");}
static JSONObject serverPeer()throws Exception{return new JSONObject().put("public_key","bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg=").put("addresses",new JSONArray().put("10.94.0.3/32").put("fd94::3/128")).put("mtu",1360).put("persistent_keepalive_interval",25);}
static AndroidStandardExitStore.Entry exit(String kind)throws Exception{AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id="saved-"+kind;e.protocol=kind;e.name=kind;e.server="203.0.113.20";e.serverPort=443;e.expectedPublicIp="203.0.113.88";
 if(kind.equals("wireguard")||kind.equals("amneziawg")){e.wgPrivateKey=key('x');e.wgPeerPublicKey=key('p');e.wgAddresses.addAll(List.of("10.93.0.2/32","fd93::2/128"));e.wgAllowedIps.addAll(List.of("0.0.0.0/0","::/0"));e.wgPreSharedKey=key('s');e.wgMtu=1380;e.wgKeepalive=25;if(kind.equals("amneziawg"))e.awgParameters=awgParameters();}
 if(kind.equals("socks5")||kind.equals("http")||kind.equals("https")){e.username=" exact user ";e.password=" exact-password ";}
 if(kind.equals("shadowsocks")){e.method="2022-blake3-aes-256-gcm";e.secret=key('s');}
 if(kind.equals("hysteria2"))e.secret="captured-only-secret";e.tlsServerName="selected.example.test";
 if(kind.equals("openvpn")){e.username=" exact user ";e.password=" exact password ";e.openVPNConfig="client\ndev tun\nproto udp\nremote 203.0.113.20 443\nremote 203.0.113.21 1194 udp\nremote-random\nauth-user-pass\nremote-cert-tls server\ntun-mtu 1380\nfragment 1200\n<ca>\n-----BEGIN CERTIFICATE-----\nfixture-only\n-----END CERTIFICATE-----\n</ca>\n";}
 e.policy.put("dns_mode","custom").put("dns_protocol","tcp").put("dns_host","149.112.112.112").put("dns_port",5353)
 .put("ipv6_mode","off").put("home_lan_access",false).put("home_lan_cidrs",new JSONArray().put("192.168.50.0/24").put("fd12::/48"))
 .put("mtu_policy","auto").put("effective_mtu",8800);return e;}
static JSONObject entry()throws Exception{String pub=key('p');String proof=AndroidTorProfile.digest(("router-vpn-node-proof-v1\n"+pub).getBytes(StandardCharsets.UTF_8));
 String wg="[Interface]\nPrivateKey = "+key('e')+"\nAddress = 10.77.0.2/32, fd77::2/128\nMTU = 1500\n[Peer]\nPublicKey = "+pub+"\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 198.51.100.20:51820\n";
 JSONObject p=new JSONObject().put("id","entry").put("node_kind","router-vpn").put("node_proof_id",proof).put("router_api","http://10.77.0.1:8787").put("api_token","exact-entry-token").put("adguard_ipv4","10.77.0.1").put("adguard_ipv6","fd77::1").put("dns_mode","home").put("start_layer","off").put("mtu_policy","auto").put("effective_mtu",9000);
 return new JSONObject().put("selectedRouterID","entry").put("routerProfiles",new JSONArray().put(p)).put("profiles",new JSONObject().put("wg",new JSONObject().put("wg.conf",Base64.getEncoder().encodeToString(wg.getBytes(StandardCharsets.UTF_8)))));}
static void storeValidation(AndroidStandardExitStore.Entry e)throws Exception{AndroidStandardExitStore.validate(e);}
static void layer(AndroidStandardExitStore.Entry e,String mode)throws Exception{e.policy.put("start_layer",mode);e.startLayer=mode.equals("off")?null:new JSONObject().put("mode",mode).put("api","http://10.99.0.1:8787").put("transport",new JSONObject().put("type","shadowsocks").put("tag","provisioned-exit-layer").put("server",e.server).put("server_port",8388).put("method","2022-blake3-aes-256-gcm").put("password",key('l')));}
static JSONObject copy(JSONObject p)throws Exception{return new JSONObject(p.toString());}
static JSONObject find(JSONObject g,String tag)throws Exception{for(String f:List.of("outbounds","endpoints")){JSONArray a=g.optJSONArray(f);if(a!=null)for(int i=0;i<a.length();i++)if(tag.equals(a.getJSONObject(i).optString("tag")))return a.getJSONObject(i);}throw new AssertionError(tag);}
static void capturedProtection(Path root)throws Exception{
 for(String setting:List.of("legacy","off","on"))for(int predecessor=0;predecessor<3;predecessor++){
  Path home=Files.createTempDirectory(root,"protection-capture-");android.content.Context context=new android.content.Context(home.toFile());AndroidStandardExitStore.Entry saved=exit("socks5");
  if(!setting.equals("legacy"))saved.policy=AndroidExternalProtection.withChoice(saved.policy,setting.equals("on"));
  java.io.File entryFile=null;if(predecessor!=0){JSONObject bundle=entry();profile(bundle).put("kill_switch",predecessor==2).put("kill_switch_policy",predecessor==2?"always":"off");Path file=home.resolve("entry.json");Files.writeString(file,bundle.toString());entryFile=file.toFile();}
  String source=AndroidStandardExitStore.snapshot(saved);NativeSingBoxController.SessionInfo prepared=AndroidExternalPolicy.prepare(context,entryFile,saved,predecessor==0?"external":"wg");Path folder=home.resolve("layered-sessions").resolve(prepared.sessionId);
  JSONObject metadata=AndroidExternalPolicy.session(Files.readString(folder.resolve("sing-box.json")),Files.readString(folder.resolve(AndroidExternalPolicy.SESSION_FILE)),prepared.sessionId,prepared.mode);
  JSONObject capture=new JSONObject(metadata.getString("capture_json"));boolean required=setting.equals("on")||setting.equals("legacy")&&predecessor==0||predecessor==2;
  check(AndroidExternalProtection.externalCapture(capture)==required&&Files.exists(folder.resolve(AndroidKillSwitchPolicy.SESSION_MARKER))==required,"actual external compiler/staging lost its captured protection owner");
  check(AndroidStandardExitStore.snapshot(saved).equals(source),"native protection preparation changed saved private input");
  if(!setting.equals("legacy"))check(capture.getJSONObject("profile").getBoolean("kill_switch")==setting.equals("on"),"native external capture dropped explicit protection");
 }
}
public static void main(String[]args)throws Exception{io.nekohasekai.libbox.Libbox.compiler=args[0];Path root=Path.of(args[1]);android.content.Context context=new android.content.Context(root.toFile());capturedProtection(root);
 String[] kinds={"wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn"};
 for(String kind:kinds)for(boolean hopped:new boolean[]{false,true}){
  AndroidStandardExitStore.Entry e=exit(kind);JSONObject b=hopped?entry():null;String before=AndroidStandardExitStore.snapshot(e),nodeBefore=b==null?"":b.toString();
  AndroidExternalPolicy.Compiled c=AndroidExternalPolicy.compile(e,b,hopped?"wg":"external");JSONObject g=new JSONObject(c.config),m=c.metadata;
  check(before.equals(AndroidStandardExitStore.snapshot(e)),"compiler mutated external source");check(nodeBefore.equals(b==null?"":b.toString()),"compiler mutated entry");
  check(m.getString("dns_server").equals("149.112.112.112")&&m.getInt("dns_port")==5353&&m.getString("dns_protocol").equals("tcp"),"saved DNS was replaced");
  check(m.getString("ipv6_mode").equals("off")&&!m.getBoolean("home_lan_access"),"device policy lost");check(m.getInt("configured_mtu")<8800,"stale MTU reused");check(m.getString("auto_mtu").equals("unmeasured"),"baseline falsely measured");
  check(g.getJSONArray("inbounds").length()==1,"second local VPN/listener");check(g.getJSONObject("route").getString("final").equals("custom-exit"),"final route owner");
  check(find(g,"custom-exit").optString("detour").equals(hopped?"entry-wg":""),"entry bypass");
  JSONObject captured=new JSONObject(c.capture);check(captured.getJSONObject("profile").getString("id").equals(e.id),"exit id changed");check(!captured.getJSONObject("profile").has("effective_mtu"),"stale policy captured");
  if(kind.equals("wireguard")||kind.equals("amneziawg")){JSONObject ep=find(g,"custom-exit");check(ep.getJSONArray("peers").getJSONObject(0).getInt("persistent_keepalive_interval")==25,"imported keepalive lost");if(kind.equals("amneziawg")){check(ep.getString("type").equals("routervpn-amneziawg")&&sameParams(ep.getJSONObject("amnezia"),e.awgParameters),"imported AWG replaced its native protocol or parameters");check(sameParams(captured.getJSONObject("profile").getJSONObject("external").getJSONObject("amneziawg").getJSONObject("parameters"),e.awgParameters),"captured AWG lost exact ranges");}}
  if(kind.equals("openvpn")){JSONObject endpoint=find(g,"custom-exit"),inline=captured.getJSONObject("profile").getJSONObject("external").getJSONObject("openvpn");check(endpoint.getString("type").equals("openvpn-client")&&!endpoint.getBoolean("system")&&endpoint.getJSONArray("servers").length()==2,"OpenVPN remote/native owner was reduced");check(endpoint.getString("username").equals(e.username)&&endpoint.getString("password").equals(e.password)&&inline.getString("config").equals(e.openVPNConfig),"OpenVPN capture changed inline config or credential spacing");check(endpoint.getInt("mtu")==1380&&endpoint.getJSONObject("tls").getString("remote_certificate_tls").equals("server"),"OpenVPN transport MTU or authentication was changed");}
  for(String dns:List.of("home","rescue","doh","dot","doh3")){
   AndroidStandardExitStore.Entry d=AndroidStandardExitStore.copy(e);d.policy.put("dns_mode",dns);
   if(dns.equals("home")){d.policy.remove("dns_host");d.policy.put("dns_protocol","udp").put("dns_port",53);}
   if(dns.equals("dot")||dns.startsWith("doh"))d.policy.put("dns_host","9.9.9.9").put("dns_server_name","resolver.example.test").put("dns_path","/saved-query").put("dns_port",8443);
   if(dns.equals("home")&&!hopped||dns.equals("doh3")&&(kind.equals("http")||kind.equals("https"))){reject(()->AndroidExternalPolicy.compile(d,b,hopped?"wg":"external"),"unsupported DNS changed silently");continue;}
   AndroidExternalPolicy.Compiled x=AndroidExternalPolicy.compile(d,b,hopped?"wg":"external");check(x.metadata.getString("dns_mode").equals(dns),"DNS mode lost");if(dns.equals("home"))check(x.metadata.getString("dns_detour").equals("entry-wg"),"Home DNS left captured private entry");
  }
 }

 for(String protocol:List.of("wireguard","amneziawg","shadowsocks","hysteria2","socks5","http","https"))for(String layer:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening")){
 AndroidStandardExitStore.Entry relay=exit(protocol);boolean packet=AndroidStandardExitStore.packetExecutionProtocol(protocol);if(packet){relay.serverPeer=serverPeer();relay.wgMtu=1280;}layer(relay,layer);AndroidExternalPolicy.validateDraft(relay);relay.responseProbe=new JSONObject().put("url","https://203.0.113.20:8443/response").put("server_name","exit.example.test");
 for(String execution:List.of("local","server","auto")){
  JSONObject entry=entry();String saved=AndroidStandardExitStore.snapshot(relay);
  AndroidExternalPolicy.Compiled c=AndroidExternalPolicy.compile(relay,entry,"wg",null,execution,"");JSONObject graph=new JSONObject(c.config),capture=new JSONObject(c.capture);
  check(saved.equals(AndroidStandardExitStore.snapshot(relay)),"execution changed saved private credentials");
  check(capture.getJSONObject("profile").getString("multihop_execution").equals(execution),"execution choice was dropped");
  JSONObject local=find(graph,execution.equals("local")?"custom-exit":"routervpn-execution-local");
  if(packet){
   check(local.getString("private_key").equals(relay.wgPrivateKey)&&local.getJSONArray("address").toString().equals(new JSONArray(relay.wgAddresses).toString()),"Local packet keys or addresses were replaced by Server credentials");
   JSONObject selectedPeer=capture.getJSONObject("profile").getJSONObject("external").getJSONObject("server_peer");check(selectedPeer.getString("public_key").equals(relay.serverPeer.getString("public_key"))&&selectedPeer.getJSONArray("addresses").toString().equals(relay.serverPeer.getJSONArray("addresses").toString())&&selectedPeer.getInt("mtu")==1360&&selectedPeer.getInt("persistent_keepalive_interval")==25&&!c.config.contains(key('v')),"public Server descriptor lost or Server private key entered client graph");
   check(local.getJSONArray("peers").getJSONObject(0).getString("public_key").equals(relay.wgPeerPublicKey),"Server identity replaced provider remote key");
   if(protocol.equals("amneziawg"))check(local.getString("type").equals("routervpn-amneziawg")&&sameParams(local.getJSONObject("amnezia"),relay.awgParameters),"packet execution dropped AWG parameters");
  }
  if(List.of("socks5","http","https").contains(protocol))check(local.getString("username").equals(" exact user ")&&local.getString("password").equals(" exact-password "),"private credentials were normalized or borrowed");
  if(!layer.equals("off")){JSONObject wrapper=find(graph,"routervpn-exit-start-layer");String localServer=packet?local.getJSONArray("peers").getJSONObject(0).getString("address"):local.getString("server");check(wrapper.getString("type").equals(layer.equals("aes-256-gcm")?"shadowsocks":"routervpn-aes-xor")&&localServer.equals("10.99.0.1")&&local.getString("detour").equals("routervpn-exit-start-layer")&&wrapper.getString("server").equals(relay.server),"exit layer lost its exact server or native ownership");}
  if(execution.equals("local")){check(!c.metadata.has("execution"),"local unnecessarily obtained a server lease");continue;}
  check(c.metadata.getString("execution").equals(execution)&&c.metadata.getString("last_node_measurement").equals("https-response-time"),"execution proof contract missing");
  check(find(graph,"custom-exit").getString("type").equals("selector")&&find(graph,"routervpn-execution-server").getString("detour").equals("entry-wg"),"execution bypassed entry or lacks selector");
  check(new AndroidExternalPolicy.Compiled(c.source,c.capture).config.equals(c.config),"captured lease proposal changed on recompile");
  AndroidExternalPolicy.Compiled fresh=AndroidExternalPolicy.compile(relay,entry,"wg",null,execution,"");check(!fresh.capture.equals(c.capture),"fresh session reused private relay credentials");
  for(String winner:List.of("local","server")){
   if(execution.equals("server")&&winner.equals("local")){reject(()->AndroidExternalPolicy.compile(relay,entry,"wg",null,execution,winner),"restore replaced explicit Server selection");continue;}
   AndroidExternalPolicy.Compiled restored=AndroidExternalPolicy.compile(relay,entry,"wg",null,execution,winner);
   check(restored.metadata.getString("execution").equals(winner)&&new JSONObject(restored.capture).getJSONObject("profile").getString("multihop_execution").equals(execution),"restoration reran Compare or changed saved choice");
  }
  JSONObject wrongCapture=new JSONObject(c.capture);wrongCapture.getJSONObject("execution").getJSONObject("request").put("password","foreign-private-password");
  reject(()->new AndroidExternalPolicy.Compiled(c.source,wrongCapture.toString()),"substituted relay credentials accepted");
 }
 for(String fault:List.of("choice","mode","host","key","api","extra")){
  AndroidStandardExitStore.Entry bad=AndroidStandardExitStore.copy(relay);layer(bad,"aes-256-gcm");
  if(fault.equals("choice"))bad.policy.put("start_layer","off");else if(fault.equals("mode"))bad.startLayer.put("mode","aes-256-gcm+xor-whitening");else if(fault.equals("api"))bad.startLayer.put("api","https://203.0.113.20:8787");else bad.startLayer.getJSONObject("transport").put(fault.equals("host")?"server":fault.equals("key")?"password":"detour",fault.equals("host")?"203.0.113.21":"foreign");
  reject(()->AndroidExternalPolicy.validateDraft(bad),"invalid provisioned exit layer accepted: "+fault);
 }
 }
 AndroidStandardExitStore.Entry relay=exit("shadowsocks");relay.responseProbe=new JSONObject().put("url","https://203.0.113.20:8443/response").put("server_name","exit.example.test");
 for(String kind:List.of("socks5","http","https")){AndroidStandardExitStore.Entry anonymous=exit(kind);anonymous.username="";anonymous.password="";anonymous.responseProbe=new JSONObject(relay.responseProbe.toString());reject(()->AndroidExternalPolicy.compile(anonymous,entry(),"wg",null,"server",""),"anonymous proxy gained Server execution");}
 reject(()->AndroidExternalPolicy.compile(relay,null,"external",null,"server",""),"direct path gained an unowned server relay");
 AndroidStandardExitStore.Entry missing=AndroidStandardExitStore.copy(relay);missing.responseProbe=new JSONObject();reject(()->AndroidExternalPolicy.compile(missing,entry(),"wg",null,"auto",""),"Compare used an invented response endpoint");
 for(String url:List.of("http://203.0.113.20/", "https://203.0.113.21/", "https://203.0.113.20/?secret=hidden", "https://user:pass@203.0.113.20/", "https://203.0.113.20/#fragment")){
  AndroidStandardExitStore.Entry bad=AndroidStandardExitStore.copy(relay);bad.responseProbe.put("url",url);reject(()->storeValidation(bad),"unowned response endpoint accepted");
 }

 for(String protocol:List.of("wireguard","amneziawg")){
  AndroidStandardExitStore.Entry paired=exit(protocol);paired.wgMtu=1280;paired.serverPeer=serverPeer();paired.responseProbe=new JSONObject(relay.responseProbe.toString());
  AndroidExternalPolicy.validateDraft(paired);AndroidStandardExitStore packetStore=new AndroidStandardExitStore(context);packetStore.save(paired);
  check(AndroidStandardExitStore.snapshot(paired).equals(AndroidStandardExitStore.snapshot(packetStore.get(paired.id))),"Server peer descriptor changed in private store roundtrip");
  check(!paired.summary().has("server_peer")&&!paired.summary().toString().contains(paired.wgPrivateKey),"packet public summary exposed private capture");
  JSONObject capturedProfile=AndroidExternalPolicy.profile(paired);AndroidStandardExitStore.Entry detachedPeer=AndroidStandardExitStore.copy(paired);detachedPeer.serverPeer.put("mtu",1400);paired.serverPeer.getJSONArray("addresses").put(0,"10.94.0.4/32");
  check(detachedPeer.serverPeer.getInt("mtu")==1400&&capturedProfile.getJSONObject("external").getJSONObject("server_peer").getInt("mtu")==1360&&capturedProfile.getJSONObject("external").getJSONObject("server_peer").getJSONArray("addresses").getString(0).equals("10.94.0.3/32"),"captured Server descriptor aliases a mutable node");paired.serverPeer=serverPeer();
  AndroidStandardExitStore.Entry unpaired=AndroidStandardExitStore.copy(paired);unpaired.serverPeer=null;AndroidExternalPolicy.validateDraft(unpaired);reject(()->AndroidExternalPolicy.compile(unpaired,entry(),"wg",null,"server",""),"packet Server accepted missing independent peer descriptor");
  for(String fault:List.of("private-key","psk","unknown","null","mtu-type","mtu-small","mtu-large","keepalive-type","keepalive-large","addresses-type","family","overlap","duplicate-family","noncanonical-ip","borrowed-key","clamped-key","low-order","noncanonical-key","missing-local-key","missing-probe")){
   AndroidStandardExitStore.Entry bad=AndroidStandardExitStore.copy(paired);
   switch(fault){
    case "private-key":bad.serverPeer.put("private_key",key('v'));break;case "psk":bad.serverPeer.put("preshared_key",key('p'));break;case "unknown":bad.serverPeer.put("endpoint","203.0.113.21:443");break;
    case "null":bad.serverPeer.put("mtu",JSONObject.NULL);break;case "mtu-type":bad.serverPeer.put("mtu","1360");break;case "mtu-small":bad.serverPeer.put("mtu",1279);break;case "mtu-large":bad.serverPeer.put("mtu",9001);break;
    case "keepalive-type":bad.serverPeer.put("persistent_keepalive_interval",25.5);break;case "keepalive-large":bad.serverPeer.put("persistent_keepalive_interval",65536);break;case "addresses-type":bad.serverPeer.put("addresses","10.94.0.3/32");break;
    case "family":bad.serverPeer.put("addresses",new JSONArray().put("10.94.0.3/32"));break;case "overlap":bad.serverPeer.getJSONArray("addresses").put(0,"10.93.0.2/24");break;case "duplicate-family":bad.serverPeer.getJSONArray("addresses").put(1,"10.94.0.4/32");break;case "noncanonical-ip":bad.serverPeer.getJSONArray("addresses").put(1,"fd94:0::3/128");break;
    case "borrowed-key":bad.wgPrivateKey=key('v');break;case "clamped-key":byte[] aliasKey=Base64.getDecoder().decode(key('v'));aliasKey[0]^=7;aliasKey[31]^=(byte)128;bad.wgPrivateKey=Base64.getEncoder().encodeToString(aliasKey);break;
    case "low-order":bad.serverPeer.put("public_key",key('\0'));break;case "noncanonical-key":bad.serverPeer.put("public_key",key('\377'));break;case "missing-local-key":bad.wgPrivateKey="";break;case "missing-probe":bad.responseProbe=new JSONObject();break;
   }
   reject(()->AndroidExternalPolicy.compile(bad,entry(),"wg",null,"auto",""),"invalid packet Server capture accepted: "+fault);
   if(!fault.equals("missing-probe"))reject(()->AndroidExternalPolicy.validateDraft(bad),"invalid packet descriptor passed actual shared idle validation: "+fault);
  }
  JSONObject edited=AndroidStandardExitStore.parseServerPeer(paired.serverPeer.toString());check(edited.getString("public_key").equals(paired.serverPeer.getString("public_key")),"descriptor editor changed key");
  String descriptor=paired.serverPeer.toString();for(String invalid:List.of("null","[]","{}",descriptor+" {}",descriptor.replace("\"mtu\":1360","\"mtu\":1360,\"mtu\":1400"),descriptor.replace("\"mtu\":1360","\"private_key\":\"secret\""),descriptor.replace("\"mtu\":1360","\"mtu\":null"),descriptor.replace("\"mtu\":1360","\"mtu\":1360.0"),descriptor.replace("\"mtu\":1360","\"mtu\":01360"),descriptor.replace("\"mtu\":1360","mtu:1360"),descriptor+" ".repeat(2048))){reject(()->AndroidStandardExitStore.parseServerPeer(invalid),"descriptor editor accepted non-strict or secret-bearing JSON");}
  check(AndroidStandardExitStore.parseServerPeer("  ")==null,"empty optional descriptor became an invented Server identity");
 }
 AndroidStandardExitStore.Entry foreignDescriptor=exit("shadowsocks");foreignDescriptor.serverPeer=serverPeer();reject(()->storeValidation(foreignDescriptor),"proxy silently discarded a packet Server descriptor");

 for(String kind:kinds){AndroidStandardExitStore.Entry e=exit(kind);e.server="2001:DB8:0:0:0:0:0:20";e.expectedPublicIp="2606:4700:0:0:0:0:0:1111";e.policy.put("dns_host","2001:4860:4860:0:0:0:0:8888");AndroidExternalPolicy.Compiled c=AndroidExternalPolicy.compile(e,null,"external");check(c.metadata.getString("expected_public_ip").equals("2606:4700::1111"),"IPv6 public exit rejected or not canonical");check(c.metadata.getString("dns_server").equals("2001:4860:4860::8888"),"IPv6 selected DNS was replaced");}
 for(String[] pair:new String[][]{{"0:0:0:0:0:0:0:0","::"},{"0:0:1:0:0:2:3:4","::1:0:0:2:3:4"},{"1:2:3:4:5:6:0:0","1:2:3:4:5:6::"},{"1:2:3:4:5:6:0:8","1:2:3:4:5:6:0:8"}})check(AndroidNumericAddress.canonical(pair[0]).equals(pair[1]),"IPv6 canonical compression changed identity");

 AndroidStandardExitStore.Entry hostname=exit("socks5");hostname.policy.put("dns_host","dns.owner.example.test");reject(()->AndroidExternalPolicy.compile(hostname,null,"external"),"DNS hostname borrowed ambient resolver");JSONObject bootstrap=new JSONObject().put("server",new JSONObject().put("type","tcp").put("tag","external-dns-bootstrap").put("server","9.9.9.9").put("server_port",5354).put("detour","custom-exit")).put("query",new JSONObject().put("server","external-dns-bootstrap"));hostname.policy.put("dns_bootstrap",bootstrap);
 AndroidExternalPolicy.Compiled named=AndroidExternalPolicy.compile(hostname,null,"external");check(named.metadata.getString("dns_server").equals("dns.owner.example.test")&&!named.metadata.getString("dns_bootstrap_sha256").isEmpty(),"explicit bootstrap changed selected DNS or lost identity");check(new JSONObject(named.config).getJSONObject("dns").getJSONArray("servers").length()==2,"bootstrap server was not preserved");bootstrap.getJSONObject("server").put("detour","entry-wg");reject(()->AndroidExternalPolicy.compile(hostname,null,"external"),"bootstrap escaped captured DNS owner");bootstrap.getJSONObject("server").put("detour","custom-exit");hostname.policy.put("dns_host","8.8.8.8");reject(()->AndroidExternalPolicy.compile(hostname,null,"external"),"unused bootstrap silently retained");
 int checkedBeforeDraft=io.nekohasekai.libbox.Libbox.checked;
 for(String kind:kinds)for(String mode:List.of("missing","","home")){
  AndroidStandardExitStore.Entry draft=exit(kind);draft.policy=new JSONObject();if(!mode.equals("missing"))draft.policy.put("dns_mode",mode);String beforeDraft=AndroidStandardExitStore.snapshot(draft);
  AndroidExternalPolicy.validateDraft(draft);check(beforeDraft.equals(AndroidStandardExitStore.snapshot(draft)),"idle validation rewrote missing or saved Home settings");
  check(AndroidExternalPolicy.editorPolicy(draft).getString("dns_mode").equals("home"),"ordinary empty DNS silently migrated to Rescue");
  reject(()->AndroidExternalPolicy.compile(draft,null,"external"),"validated Home draft became a runnable direct exit");
  JSONObject foreignDNS=entry();profile(foreignDNS).put("dns_mode","rescue");AndroidExternalPolicy.Compiled captured=AndroidExternalPolicy.compile(draft,foreignDNS,"wg");
  check(captured.metadata.getString("dns_mode").equals("home")&&captured.metadata.getString("dns_server").equals("10.77.0.1")&&captured.metadata.getString("dns_detour").equals("entry-wg"),"missing exit DNS borrowed the entry's independent Rescue setting");
 }
 check(checkedBeforeDraft==io.nekohasekai.libbox.Libbox.checked&&!Files.exists(root.resolve("layered-sessions")),"idle validation acquired native startup or session files");
 for(JSONObject invalid:List.of(new JSONObject().put("dns_protocol","smtp"),new JSONObject().put("dns_host","8.8.8.8"),new JSONObject().put("dns_protocol","tls").put("dns_server_name",""),new JSONObject().put("dns_protocol","https").put("dns_server_name","home.example.test").put("dns_path","https://other.example.test/query"))){
  AndroidStandardExitStore.Entry bad=exit("socks5");bad.policy=invalid;reject(()->AndroidExternalPolicy.validateDraft(bad),"invalid DNS shape bypassed Home draft validation");
 }
 AndroidStandardExitStore.Entry invalidTransport=exit("https");invalidTransport.policy=new JSONObject();invalidTransport.tlsServerName="invalid..example";reject(()->AndroidExternalPolicy.validateDraft(invalidTransport),"Home draft skipped native transport validation");
 AndroidStandardExitStore.Entry defaultPolicy=exit("socks5");defaultPolicy.policy=new JSONObject().put("dns_mode","rescue");AndroidExternalPolicy.validateDraft(defaultPolicy);check(AndroidExternalPolicy.editorPolicy(defaultPolicy).getString("dns_mode").equals("rescue"),"explicit Rescue changed to implicit Home");check(AndroidExternalPolicy.compile(defaultPolicy,null,"external").metadata.getString("ipv6_mode").equals("on"),"default IPv6 did not remain on");
 for(Object invalid:new Object[]{true,123,new JSONObject()}){AndroidStandardExitStore.Entry e=exit("socks5");e.policy.put("dns_mode",invalid);reject(()->AndroidExternalPolicy.editorPolicy(e),"malformed saved DNS changed in editor");}
 AndroidStandardExitStore store=new AndroidStandardExitStore(context);AndroidStandardExitStore.Entry saved=exit("socks5");store.save(saved);check(AndroidStandardExitStore.snapshot(saved).equals(AndroidStandardExitStore.snapshot(store.get(saved.id))),"private policy did not survive save/load");
 AndroidStandardExitStore.Entry clone=AndroidStandardExitStore.copy(saved);clone.policy.put("dns_host","8.8.8.8");check(!saved.policy.getString("dns_host").equals(clone.policy.getString("dns_host")),"policy copied by reference");check(!saved.summary().toString().contains("exact-password")&&!saved.summary().has("policy"),"private capture leaked to summary");
 JSONObject b=entry();Path node=root.resolve("entry.json");Files.writeString(node,b.toString());
 NativeSingBoxController.SessionInfo s=AndroidExternalPolicy.prepare(context,node.toFile(),saved,"wg");Path folder=root.resolve("layered-sessions").resolve(s.sessionId);String config=Files.readString(folder.resolve("sing-box.json")),meta=Files.readString(folder.resolve(AndroidExternalPolicy.SESSION_FILE));
 AndroidExternalPolicy.session(config,meta,s.sessionId,s.mode);check(true,"valid session rejected");reject(()->AndroidExternalPolicy.session(config,meta,"new-session",s.mode),"session copy adopted");reject(()->AndroidExternalPolicy.session(config+" ",meta,s.sessionId,s.mode),"changed staged config adopted");
 JSONObject altered=new JSONObject(meta);altered.put("external_id","another-exit");reject(()->AndroidExternalPolicy.session(config,altered.toString(),s.sessionId,s.mode),"changed external identity adopted");
 JSONObject wrong=entry();wrong.put("selectedRouterID","missing");reject(()->AndroidExternalPolicy.compile(saved,wrong,"wg"),"missing selection fell back");JSONObject duplicate=entry();duplicate.getJSONArray("routerProfiles").put(copy(profile(duplicate)));reject(()->AndroidExternalPolicy.compile(saved,duplicate,"wg"),"duplicate selection accepted");
 for(Object layer:new Object[]{"aes-256-gcm",new JSONObject().put("mode","off"),true}){JSONObject changed=entry();profile(changed).put("start_layer",layer);reject(()->AndroidExternalPolicy.compile(saved,changed,"wg"),"Start Layer discarded");}
 JSONObject old=entry();String encoded=old.getJSONObject("profiles").getJSONObject("wg").getString("wg.conf");String raw=new String(Base64.getDecoder().decode(encoded),StandardCharsets.UTF_8)+"PublicKey = "+key('x')+"\n";old.getJSONObject("profiles").getJSONObject("wg").put("wg.conf",Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8)));reject(()->AndroidExternalPolicy.compile(saved,old,"wg"),"duplicate WG peer key accepted");

 AndroidStandardExitStore.Entry alias=exit("http");alias.protocol=" HTTP-CONNECT ";NativeSingBoxController.SessionInfo aliasDirect=new AndroidDirectStandardExitController(context).prepare(alias);check(Files.isRegularFile(root.resolve("layered-sessions").resolve(aliasDirect.sessionId).resolve(AndroidExternalPolicy.SESSION_FILE)),"protocol alias bypassed direct policy compiler");alias.protocol="http-connect";NativeSingBoxController.SessionInfo aliasEntry=new AndroidStandardExitController(context).prepare(node.toFile(),alias,"wg");check(Files.isRegularFile(root.resolve("layered-sessions").resolve(aliasEntry.sessionId).resolve(AndroidExternalPolicy.SESSION_FILE)),"protocol alias bypassed entry policy compiler");
 int before=root.resolve("layered-sessions").toFile().list().length;io.nekohasekai.libbox.Libbox.hook=()->{try{saved.policy.put("dns_port",9999);}catch(Exception e){throw new RuntimeException(e);}};reject(()->AndroidExternalPolicy.prepare(context,node.toFile(),saved,"wg"),"changed saved selection staged");check(before==root.resolve("layered-sessions").toFile().list().length,"stale capture wrote files");
 io.nekohasekai.libbox.Libbox.hook=()->Thread.currentThread().interrupt();reject(()->AndroidExternalPolicy.prepare(context,node.toFile(),saved,"wg"),"cancelled preparation staged");Thread.interrupted();check(before==root.resolve("layered-sessions").toFile().list().length,"cancelled capture wrote files");
 AndroidPrivateFileStore.failName=AndroidExternalPolicy.SESSION_FILE;reject(()->AndroidExternalPolicy.prepare(context,node.toFile(),saved,"wg"),"failed metadata write accepted");check(before==root.resolve("layered-sessions").toFile().list().length,"failed staging retained partial graph");AndroidPrivateFileStore.failName="";
 for(int n:new int[]{0,1279,9001}){AndroidStandardExitStore.Entry d=exit("socks5");d.policy.put("mtu_policy","fixed").put("manual_mtu",n);reject(()->AndroidExternalPolicy.compile(d,null,"external"),"invalid fixed MTU ignored");}
 for(String forbidden:new String[]{"up /private/never-read", "plugin /private/never-load", "ca /private/never-read", "dhcp-option DNS 8.8.8.8", "remote localhost 1194"}){AndroidStandardExitStore.Entry e=exit("openvpn");e.openVPNConfig+=forbidden+"\n";reject(()->AndroidExternalPolicy.compile(e,null,"external"),"OpenVPN unsafe inline input reached shared policy");}

 for(String change:List.of("missing","unknown","type","whitespace","header","overlap","noise","keepalive","WG-fallback","missing-route","key","directive")){
  AndroidStandardExitStore.Entry e=exit("amneziawg");switch(change){case "missing":e.awgParameters.remove("s4");break;case "unknown":e.awgParameters.put("i1","unexpected");break;case "type":e.awgParameters.put("s4",32);break;case "whitespace":e.awgParameters.put("s4"," 32");break;case "header":e.awgParameters.put("h1","1");break;case "overlap":e.awgParameters.put("h2","100-110");break;case "noise":e.awgParameters.put("jc","129");break;case "keepalive":e.wgKeepalive=65536;break;case "WG-fallback":e.protocol="wireguard";break;case "missing-route":e.wgAllowedIps.remove("::/0");break;case "key":e.wgPrivateKey="invalid";break;case "directive":e.awgParameters.put("s4","32\nPostUp=bad");break;}
  reject(()->store.save(e),"invalid AWG data reached private store: "+change);
 }
 AndroidStandardExitStore.Entry imported=exit("amneziawg");imported.wgDns.addAll(List.of("9.9.9.9","2620:fe::fe"));store.save(imported);check(AndroidStandardExitStore.snapshot(imported).equals(AndroidStandardExitStore.snapshot(store.get(imported.id))),"AWG parameters/keepalive/DNS changed in private storage");AndroidStandardExitStore.Entry detached=AndroidStandardExitStore.copy(imported);detached.awgParameters.put("s4","8");detached.wgDns.clear();check(imported.awgParameters.getString("s4").equals("32")&&imported.wgDns.size()==2,"AWG parameters or DNS aliases persisted source");check(!imported.summary().toString().contains(imported.wgPrivateKey)&&!imported.summary().has("awg_parameters"),"AWG private input exposed in summary");
 String inline="[Interface]\nPrivateKey="+imported.wgPrivateKey+"\nAddress="+String.join(",",imported.wgAddresses)+"\nMTU=1380\nDNS=9.9.9.9,2620:fe::fe\n";for(String parameter:AndroidExternalAmnezia.PARAMETERS)inline+=parameter+"="+imported.awgParameters.getString(parameter)+"\n";inline+="[Peer]\nPublicKey="+imported.wgPeerPublicKey+"\nPresharedKey="+imported.wgPreSharedKey+"\nEndpoint=203.0.113.20:443\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\n";
 AndroidStandardExitStore.Entry parsed=AndroidExternalAmnezia.fromInline(inline,"Imported",imported.expectedPublicIp);check(sameParams(parsed.awgParameters,imported.awgParameters)&&parsed.wgKeepalive==25&&parsed.wgDns.equals(imported.wgDns)&&parsed.wgMtu==1380,"native AWG import lost supplied data");check(parsed.policy.getString("dns_host").equals("9.9.9.9")&&parsed.policy.getString("dns_protocol").equals("udp"),"imported DNS was overridden");AndroidExternalPolicy.Compiled parsedGraph=AndroidExternalPolicy.compile(parsed,null,"external");check(parsedGraph.metadata.getString("dns_server").equals("9.9.9.9"),"imported selected DNS did not reach native policy");
 for(String directive:List.of("PostUp=echo bad","PublicKey="+key('z'),"Endpoint=localhost:443","[Peer]\nPublicKey="+key('z'))){final String changed=inline+directive+"\n";reject(()->AndroidExternalAmnezia.fromInline(changed,"Invalid",imported.expectedPublicIp),"unsafe or duplicate AWG inline input accepted");}
 imported.protocol=" AWG ";NativeSingBoxController.SessionInfo awgSession=new AndroidDirectStandardExitController(context).prepare(imported);check(awgSession.mode.equals("standard-direct-amneziawg"),"AWG alias bypassed native policy capture");
 AndroidStandardExitStore.Entry ovpn=exit("openvpn");String ovpnBefore=AndroidStandardExitStore.snapshot(ovpn);store.save(ovpn);check(ovpnBefore.equals(AndroidStandardExitStore.snapshot(store.get(ovpn.id))),"OpenVPN inline credentials or policy changed in private persistence");ovpn.protocol=" OVPN ";NativeSingBoxController.SessionInfo ovpnSession=new AndroidDirectStandardExitController(context).prepare(ovpn);Path ovpnFolder=root.resolve("layered-sessions").resolve(ovpnSession.sessionId);check(Files.isRegularFile(ovpnFolder.resolve(AndroidExternalPolicy.SESSION_FILE)),"OpenVPN alias bypassed captured service proof");check(new JSONObject(Files.readString(ovpnFolder.resolve("sing-box.json"))).getJSONArray("inbounds").length()==1,"OpenVPN retained the old unowned public proof listener");
 System.out.println("Android external policy: "+checks+" executable checks passed");}
}
'''

def main():
    for tool in ("java", "javac", "go"):
        if not shutil.which(tool):
            raise RuntimeError(f"{tool} is required; external policy tests cannot be skipped")
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file():
        raise RuntimeError("The Android org.json library is required")
    with tempfile.TemporaryDirectory(prefix="routervpn-external-", dir=ROOT) as directory:
        temp = Path(directory)
        # The real module import is discovered, never a second copied compiler.
        module = next(line.split()[1] for line in (ROOT / "go.mod").read_text().splitlines() if line.startswith("module "))
        (temp / "main.go").write_text(GO.replace("github.com/Eabusham2/router-vpn", module))
        subprocess.run(["go", "build", "-o", str(temp / "compiler"), str(temp / "main.go")], cwd=ROOT, check=True)
        for path, source in STUBS.items():
            target = temp / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source)
        app = temp / "com/eabusham/routervpn"
        app.mkdir(parents=True, exist_ok=True)
        for name in ("AndroidExternalProtection", "AndroidExternalPolicy", "AndroidStandardExitStore", "AndroidExternalAmnezia", "AndroidProfileSelection", "AndroidDirectStandardExitController", "AndroidStandardExitController", "AndroidNumericAddress", "AndroidOpenVPN"):
            shutil.copyfile(JAVA / f"{name}.java", app / f"{name}.java")
        (app / "Boundaries.java").write_text("package com.eabusham.routervpn;\n" + BOUNDARIES)
        (app / "ExternalPolicyTest.java").write_text(HARNESS)
        classes = temp / "classes"
        subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-cp", str(jar), "-d", str(classes), *map(str, temp.rglob("*.java"))], check=True)
        files = temp / "private"
        files.mkdir()
        subprocess.run(["java", "-cp", os.pathsep.join((str(classes), str(jar))), "com.eabusham.routervpn.ExternalPolicyTest", str(temp / "compiler"), str(files)], check=True)


if __name__ == "__main__":
    main()
