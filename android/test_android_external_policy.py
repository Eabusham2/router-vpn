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
switch args[0]{case "external":out,err=mobilemultihop.CompileExternalPolicy(args[1],args[2]);case "wg":out,err=mobilemultihop.CompileWireGuardProfile(args[1],args[2]);case "openvpn":out,err=nativeopenvpn.RouterOpenVPNEndpoint(args[1],args[2],args[3],args[4],args[5]);default:panic("unknown operation")};if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)};fmt.Print(out)}'''

STUBS = {
"android/content/Context.java": '''package android.content; public class Context { final java.io.File root; public Context(java.io.File r){root=r;} public Context getApplicationContext(){return this;} public java.io.File getFilesDir(){return root;} }''',
"android/util/Base64.java": '''package android.util; public class Base64 {public static final int DEFAULT=0,NO_WRAP=2;public static byte[] decode(String s,int f){return java.util.Base64.getDecoder().decode(s);}public static String encodeToString(byte[] b,int f){return java.util.Base64.getEncoder().encodeToString(b);}}''',
"io/nekohasekai/libbox/Libbox.java": '''package io.nekohasekai.libbox;
import org.json.JSONArray;import java.nio.charset.StandardCharsets;
public class Libbox { public static Runnable hook;public static String compiler;public static int checked;
static String call(String...args)throws Exception{Process p=new ProcessBuilder(compiler).start();p.getOutputStream().write(new JSONArray(java.util.Arrays.asList(args)).toString().getBytes(StandardCharsets.UTF_8));p.getOutputStream().close();String out=new String(p.getInputStream().readAllBytes(),StandardCharsets.UTF_8),err=new String(p.getErrorStream().readAllBytes(),StandardCharsets.UTF_8);if(p.waitFor()!=0)throw new IllegalStateException(err);return out;}
public static String routerCompileExternalPolicy(String s,String c)throws Exception{String out=call("external",s,c);Runnable h=hook;hook=null;if(h!=null)h.run();return out;}
public static String version(){return "1.14.1";}public static String routerOpenVPNEndpoint(String c,String u,String p,String t,String d)throws Exception{return call("openvpn",c,u,p,t,d);}
public static String routerCompileWireGuardProfile(String s,String n)throws Exception{return call("wg",s,n);}public static void checkConfig(String c){checked++;}}
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
 static NativeSingBoxController.SessionInfo prepare(android.content.Context c,java.io.File f,AndroidStandardExitStore.Entry e,String m){throw new IllegalArgumentException("Tor boundary");}
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
static AndroidStandardExitStore.Entry exit(String kind)throws Exception{AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id="saved-"+kind;e.protocol=kind;e.name=kind;e.server="203.0.113.20";e.serverPort=443;e.expectedPublicIp="203.0.113.88";
 if(kind.equals("wireguard")){e.wgPrivateKey=key('x');e.wgPeerPublicKey=key('p');e.wgAddresses.addAll(List.of("10.93.0.2/32","fd93::2/128"));e.wgAllowedIps.addAll(List.of("0.0.0.0/0","::/0"));e.wgPreSharedKey=key('s');e.wgMtu=1380;}
 if(kind.equals("socks5")||kind.equals("http")||kind.equals("https")){e.username="exact user";e.password="exact-password";}
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
static JSONObject copy(JSONObject p)throws Exception{return new JSONObject(p.toString());}
static JSONObject find(JSONObject g,String tag)throws Exception{for(String f:List.of("outbounds","endpoints")){JSONArray a=g.optJSONArray(f);if(a!=null)for(int i=0;i<a.length();i++)if(tag.equals(a.getJSONObject(i).optString("tag")))return a.getJSONObject(i);}throw new AssertionError(tag);}
public static void main(String[]args)throws Exception{io.nekohasekai.libbox.Libbox.compiler=args[0];Path root=Path.of(args[1]);android.content.Context context=new android.content.Context(root.toFile());
 String[] kinds={"wireguard","socks5","http","https","shadowsocks","hysteria2","openvpn"};
 for(String kind:kinds)for(boolean hopped:new boolean[]{false,true}){
  AndroidStandardExitStore.Entry e=exit(kind);JSONObject b=hopped?entry():null;String before=AndroidStandardExitStore.snapshot(e),nodeBefore=b==null?"":b.toString();
  AndroidExternalPolicy.Compiled c=AndroidExternalPolicy.compile(e,b,hopped?"wg":"external");JSONObject g=new JSONObject(c.config),m=c.metadata;
  check(before.equals(AndroidStandardExitStore.snapshot(e)),"compiler mutated external source");check(nodeBefore.equals(b==null?"":b.toString()),"compiler mutated entry");
  check(m.getString("dns_server").equals("149.112.112.112")&&m.getInt("dns_port")==5353&&m.getString("dns_protocol").equals("tcp"),"saved DNS was replaced");
  check(m.getString("ipv6_mode").equals("off")&&!m.getBoolean("home_lan_access"),"device policy lost");check(m.getInt("configured_mtu")<8800,"stale MTU reused");check(m.getString("auto_mtu").equals("unmeasured"),"baseline falsely measured");
  check(g.getJSONArray("inbounds").length()==1,"second local VPN/listener");check(g.getJSONObject("route").getString("final").equals("custom-exit"),"final route owner");
  check(find(g,"custom-exit").optString("detour").equals(hopped?"entry-wg":""),"entry bypass");
  JSONObject captured=new JSONObject(c.capture);check(captured.getJSONObject("profile").getString("id").equals(e.id),"exit id changed");check(!captured.getJSONObject("profile").has("effective_mtu"),"stale policy captured");
  if(kind.equals("openvpn")){JSONObject endpoint=find(g,"custom-exit"),inline=captured.getJSONObject("profile").getJSONObject("external").getJSONObject("openvpn");check(endpoint.getString("type").equals("openvpn-client")&&!endpoint.getBoolean("system")&&endpoint.getJSONArray("servers").length()==2,"OpenVPN remote/native owner was reduced");check(endpoint.getString("username").equals(e.username)&&endpoint.getString("password").equals(e.password)&&inline.getString("config").equals(e.openVPNConfig),"OpenVPN capture changed inline config or credential spacing");check(endpoint.getInt("mtu")==1380&&endpoint.getJSONObject("tls").getString("remote_certificate_tls").equals("server"),"OpenVPN transport MTU or authentication was changed");}
  for(String dns:List.of("home","rescue","doh","dot","doh3")){
   AndroidStandardExitStore.Entry d=AndroidStandardExitStore.copy(e);d.policy.put("dns_mode",dns);
   if(dns.equals("home")){d.policy.remove("dns_host");d.policy.put("dns_protocol","udp").put("dns_port",53);}
   if(dns.equals("dot")||dns.startsWith("doh"))d.policy.put("dns_host","9.9.9.9").put("dns_server_name","resolver.example.test").put("dns_path","/saved-query").put("dns_port",8443);
   if(dns.equals("home")&&!hopped||dns.equals("doh3")&&(kind.equals("http")||kind.equals("https"))){reject(()->AndroidExternalPolicy.compile(d,b,hopped?"wg":"external"),"unsupported DNS changed silently");continue;}
   AndroidExternalPolicy.Compiled x=AndroidExternalPolicy.compile(d,b,hopped?"wg":"external");check(x.metadata.getString("dns_mode").equals(dns),"DNS mode lost");if(dns.equals("home"))check(x.metadata.getString("dns_detour").equals("entry-wg"),"Home DNS left captured private entry");
  }
 }

 for(String kind:kinds){AndroidStandardExitStore.Entry e=exit(kind);e.server="2001:DB8:0:0:0:0:0:20";e.expectedPublicIp="2606:4700:0:0:0:0:0:1111";e.policy.put("dns_host","2001:4860:4860:0:0:0:0:8888");AndroidExternalPolicy.Compiled c=AndroidExternalPolicy.compile(e,null,"external");check(c.metadata.getString("expected_public_ip").equals("2606:4700::1111"),"IPv6 public exit rejected or not canonical");check(c.metadata.getString("dns_server").equals("2001:4860:4860::8888"),"IPv6 selected DNS was replaced");}
 for(String[] pair:new String[][]{{"0:0:0:0:0:0:0:0","::"},{"0:0:1:0:0:2:3:4","::1:0:0:2:3:4"},{"1:2:3:4:5:6:0:0","1:2:3:4:5:6::"},{"1:2:3:4:5:6:0:8","1:2:3:4:5:6:0:8"}})check(AndroidNumericAddress.canonical(pair[0]).equals(pair[1]),"IPv6 canonical compression changed identity");

 AndroidStandardExitStore.Entry hostname=exit("socks5");hostname.policy.put("dns_host","dns.owner.example.test");reject(()->AndroidExternalPolicy.compile(hostname,null,"external"),"DNS hostname borrowed ambient resolver");JSONObject bootstrap=new JSONObject().put("server",new JSONObject().put("type","tcp").put("tag","external-dns-bootstrap").put("server","9.9.9.9").put("server_port",5354).put("detour","custom-exit")).put("query",new JSONObject().put("server","external-dns-bootstrap"));hostname.policy.put("dns_bootstrap",bootstrap);
 AndroidExternalPolicy.Compiled named=AndroidExternalPolicy.compile(hostname,null,"external");check(named.metadata.getString("dns_server").equals("dns.owner.example.test")&&!named.metadata.getString("dns_bootstrap_sha256").isEmpty(),"explicit bootstrap changed selected DNS or lost identity");check(new JSONObject(named.config).getJSONObject("dns").getJSONArray("servers").length()==2,"bootstrap server was not preserved");bootstrap.getJSONObject("server").put("detour","entry-wg");reject(()->AndroidExternalPolicy.compile(hostname,null,"external"),"bootstrap escaped captured DNS owner");bootstrap.getJSONObject("server").put("detour","custom-exit");hostname.policy.put("dns_host","8.8.8.8");reject(()->AndroidExternalPolicy.compile(hostname,null,"external"),"unused bootstrap silently retained");
 AndroidStandardExitStore.Entry defaultPolicy=exit("socks5");defaultPolicy.policy=new JSONObject().put("dns_mode","rescue");check(AndroidExternalPolicy.compile(defaultPolicy,null,"external").metadata.getString("ipv6_mode").equals("on"),"default IPv6 did not remain on");
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
        for name in ("AndroidExternalPolicy", "AndroidStandardExitStore", "AndroidProfileSelection", "AndroidDirectStandardExitController", "AndroidStandardExitController", "AndroidNumericAddress", "AndroidOpenVPN"):
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
