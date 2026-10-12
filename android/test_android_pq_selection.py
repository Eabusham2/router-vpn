#!/usr/bin/env python3
"""Execute Android's shipping PQ selection/staging with its real Go compiler.

The Android OS, immutable factory installation and Libbox configuration-loader
boundary are doubles. Native C/JNI and real Rosenpass traffic are independent
mandatory tests; no live VPN or private node is contacted by this test.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT/'android/app/src/main/java/com/eabusham/routervpn'
spec = importlib.util.spec_from_file_location('android_graph_fixtures', ROOT/'android/test_android_multihop_graph.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
GO = r'''package main
import("encoding/json";"fmt";"io";"os";"router-vpn/internal/mobilemultihop";"router-vpn/internal/mobileperf")
func main(){
 var r struct{Operation,Config,Policy string};err:=json.NewDecoder(io.LimitReader(os.Stdin,16*1024*1024)).Decode(&r)
 var value string
 if err==nil{switch r.Operation{
 case "pq-profile":var input struct{Mode,Files string};err=json.Unmarshal([]byte(r.Config),&input);if err==nil{value,err=mobilemultihop.CompilePQProfile(input.Mode,input.Files,r.Policy)}
 case "exit":value,err=mobilemultihop.WireGuardExitConfig(r.Config,r.Policy)
 case "base-start":var input struct{Config,Source string};err=json.Unmarshal([]byte(r.Config),&input);if err==nil{value,err=mobilemultihop.ComposeNativeBaseStartLayer(input.Config,input.Source,r.Policy)}
 case "lan":value,err=mobilemultihop.ApplyLANPolicy(r.Config,r.Policy)
 case "performance":value,err=mobileperf.Apply(r.Config,r.Policy)
 default:err=fmt.Errorf("unrequested test operation")
 }}
 if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)};fmt.Print(value)
}'''
HARNESS = r'''package com.eabusham.routervpn;
import android.content.Context;import org.json.*;import java.io.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.util.*;
import static com.eabusham.routervpn.MultihopGraphHarness.*;
public final class PQSelectionHarness {
 static String enc(byte[] value){return Base64.getEncoder().encodeToString(value);}
 static String enc(String value){return enc(value.getBytes(StandardCharsets.UTF_8));}
 static byte[] repeated(byte n,int count){byte[] value=new byte[count];Arrays.fill(value,n);return value;}
 static JSONObject source(String mode)throws Exception{
  JSONObject b=bundle('b'),assets=new JSONObject();String tool=mode.equals("wg-pq")?"wg":"awg";
  String raw=wg('b');
  if(tool.equals("awg"))raw=raw.replace("[Peer]","Jc=3\nJmin=40\nJmax=900\nS1=56\nS2=48\nS3=24\nS4=32\nH1=10000000-19999999\nH2=20000000-29999999\nH3=30000000-39999999\nH4=40000000-49999999\n[Peer]");
  assets.put(tool+".conf",enc(raw)).put("rosenpass-client-secret",enc(repeated((byte)1,64)))
    .put("rosenpass-client-public",enc(repeated((byte)2,128))).put("rosenpass-server-public",enc(repeated((byte)3,128)))
    .put("rosenpass.env",enc("ROSENPASS_TOOL="+tool+"\nROSENPASS_INTERFACE="+tool+"\nROSENPASS_WG_PEER="+key('b')+"\nROSENPASS_KEY_OUT=rosenpass.psk\nROSENPASS_PORT=51822\n"))
    .put("rosenpass.toml",enc("public_key = \"rosenpass-client-public\"\nsecret_key = \"rosenpass-client-secret\"\nlisten = []\nverbosity = \"Quiet\"\n[[peers]]\npublic_key = \"rosenpass-server-public\"\nendpoint = \"node.example.test:51822\"\nkey_out = \"rosenpass.psk\"\n"));
  b.getJSONObject("profiles").put(mode,assets);
  b.put("modes",new JSONArray().put(new JSONObject().put("id",mode).put("name",mode)));
  JSONObject outer=new JSONObject().put("type","shadowsocks").put("tag","proxy").put("method","2022-blake3-aes-256-gcm").put("password",key('s')).put("server","192.0.2.2").put("server_port",8388);
  b.getJSONObject("profiles").put("shadowsocks",new JSONObject().put("sing-box.json",enc(new JSONObject().put("outbounds",new JSONArray().put(outer)).toString())));
  return b;
 }
 interface Change {void run(JSONObject b)throws Exception;}
 static void reject(NativeSingBoxController owner,Path dir,Path app,String mode,Change change)throws Exception{
  JSONObject b=source(mode);change.run(b);int count=sessions(app);File file=save(dir,b);String before=Files.readString(file.toPath());
  boolean rejected=false;try{owner.prepareSession(file,mode);}catch(Exception expected){rejected=true;}
  check(rejected,"invalid PQ launch accepted");check(sessions(app)==count,"failed PQ created session files");
  check(before.equals(Files.readString(file.toPath())),"failed PQ rewrote source assets");
 }
 public static void main(String[] args)throws Exception{
  Path dir=Path.of(args[0]),app=dir.resolve("app");Files.createDirectories(app);NativeSingBoxController owner=new NativeSingBoxController(new Context(app.toFile()));
  for(String mode:new String[]{"wg-pq","awg2-pq"}){
   check(NativeSingBoxController.nativePQFamily(mode),"native PQ predicate missing");
   check(!NativeSingBoxController.nativeWireGuardFamily(mode),"PQ silently selected raw backend");
   check(!NativeSingBoxController.nativeMultihopEntry(mode),"unimplemented PQ multihop relabeled ready");
   for(String start:new String[]{"off","aes-256-gcm","aes-256-gcm+xor-whitening"})for(String dns:new String[]{"home","custom","dot","doh","doh3","hostname"}){
    JSONObject b=source(mode),p=profile(b);p.put("start_layer",start).put("mtu_policy","fixed").put("manual_mtu",1350).put("home_lan_access",false).put("ipv6_mode","off").put("kill_switch",true).put("daita_enabled",true);
    if(!dns.equals("home"))p.put("dns_mode",dns.equals("hostname")?"doh":dns).put("dns_host",dns.equals("hostname")?"resolver.example.test":"192.168.50.133").put("dns_server_name","resolver.example.test");
    if(dns.equals("custom"))p.put("dns_protocol","tcp").put("dns_port",5353);
    File file=save(dir,b);byte[] before=Files.readAllBytes(file.toPath());int installs=RouterPQNative.installs;
    check(owner.listDirectLibboxModes(file).stream().anyMatch(m->m.id.equals(mode)),"PQ missing from readiness picker");
    check(RouterPQNative.installs==installs,"discovery initialized a native protocol owner");
    NativeSingBoxController.SessionInfo session=owner.prepareSession(file,mode);Path path=app.resolve("layered-sessions").resolve(session.sessionId);
    check(RouterPQNative.installs==installs+1,"selected launch did not install compiled PQ factory");check(session.modeId.equals(mode),"selected PQ label changed");
    Set<String> staged=new HashSet<>();try(var stream=Files.list(path)){stream.forEach(f->staged.add(f.getFileName().toString()));}
    check(staged.equals(Set.of("sing-box.json","routervpn-mtu.json",AndroidKillSwitchPolicy.SESSION_MARKER)),"unused raw or helper assets staged");
    JSONObject graph=new JSONObject(Files.readString(path.resolve("sing-box.json"))),endpoint=graph.getJSONArray("endpoints").getJSONObject(0),peer=endpoint.getJSONArray("peers").getJSONObject(0),pq=endpoint.getJSONObject("pq");
    check(graph.getJSONArray("inbounds").length()==1&&graph.getJSONArray("endpoints").length()==1,"PQ created a second VPN");
    check(endpoint.getString("type").equals("routervpn-pq")&&endpoint.getString("mode").equals(mode)&&endpoint.getString("node_id").equals(b.getString("nodeProofId")),"PQ substituted base or node");
    check(endpoint.getString("private_key").equals(key('z'))&&peer.getString("public_key").equals(key('b'))&&peer.getString("pre_shared_key").equals(key('p')),"PQ changed WG peer credentials");
    for(String[] pair:new String[][]{{"secret","rosenpass-client-secret"},{"public","rosenpass-client-public"},{"peer","rosenpass-server-public"}})check(pq.getString(pair[0]).equals(b.getJSONObject("profiles").getJSONObject(mode).getString(pair[1])),"PQ key bytes changed");
    check(endpoint.getInt("mtu")==1350&&graph.getJSONArray("inbounds").getJSONObject(0).getInt("mtu")==1350,"fixed MTU detached from native PQ");
    if(mode.equals("awg2-pq"))check(endpoint.getJSONObject("amnezia").length()==11,"AWG parameters lost");
    check(pq.getString("endpoint").equals(start.equals("off")?"192.0.2.2:51822":"10.77.0.1:51822"),"PQ handshake bypassed owned Start Layer");
    check(peer.getString("address").equals(start.equals("off")?"192.0.2.2":"10.77.0.1"),"WG and PQ select different paths");
    if(!start.equals("off"))check(endpoint.getString("detour").equals("start-layer-aes"),"PQ outer route lost");
    JSONArray servers=graph.getJSONObject("dns").getJSONArray("servers");JSONObject selected=servers.getJSONObject(servers.length()-1);
    String expected=dns.equals("custom")?"tcp":dns.equals("dot")?"tls":dns.equals("doh3")?"h3":dns.equals("doh")||dns.equals("hostname")?"https":"udp";
    check(selected.getString("type").equals(expected),"selected DNS transport lost");
    check(selected.getString("server").equals(dns.equals("hostname")?"resolver.example.test":"192.168.50.133"),"AdGuard silently substituted");
    if(dns.equals("custom"))check(selected.getInt("server_port")==5353,"custom DNS port lost");
    for(int i=0;i<servers.length();i++)check(servers.getJSONObject(i).getString("detour").equals("proxy"),"DNS bypasses negotiated PQ peer");
    if(dns.equals("hostname"))check(servers.length()==2&&servers.getJSONObject(0).getString("server").equals("192.168.50.133"),"hostname bootstrap replaced AdGuard");
    boolean v6=false,lan=false;JSONArray rules=graph.getJSONObject("route").getJSONArray("rules");
    for(int i=0;i<rules.length();i++){JSONObject rule=rules.getJSONObject(i);if(rule.optString("action").equals("reject")&&rule.optInt("ip_version")==6)v6=true;if(rule.optString("action").equals("reject")&&rule.has("ip_cidr")&&has(rule.getJSONArray("ip_cidr"),"192.168.0.0/16"))lan=true;}
    check(v6&&lan,"PQ lost IPv6/LAN rejection");check(graph.getJSONArray("services").getJSONObject(0).getString("packet_tag").equals("proxy"),"padding detached from PQ owner");
    check(Arrays.equals(before,Files.readAllBytes(file.toPath())),"PQ rewrote saved profile");
   }
   reject(owner,dir,app,mode,b->b.getJSONObject("profiles").getJSONObject(mode).put("chain.env",enc("unowned helper")));
   reject(owner,dir,app,mode,b->b.getJSONObject("profiles").getJSONObject(mode).remove("rosenpass-client-secret"));
   reject(owner,dir,app,mode,b->b.getJSONObject("profiles").getJSONObject(mode).put("rosenpass-server-public",b.getJSONObject("profiles").getJSONObject(mode).getString("rosenpass-client-public")));
   reject(owner,dir,app,mode,b->b.put("nodeProofId",proof(key('x'))));
   reject(owner,dir,app,mode,b->b.put("selectedRouterID","missing"));
   reject(owner,dir,app,mode,b->b.getJSONArray("routerProfiles").put(new JSONObject(profile(b).toString())));
   reject(owner,dir,app,mode,b->profile(b).put("mtu_policy","fixed").put("manual_mtu",1279));
   reject(owner,dir,app,mode,b->profile(b).put("jumbo_tun",true));
   RouterPQNative.fail=true;try{reject(owner,dir,app,mode,b->{});}finally{RouterPQNative.fail=false;}
   io.nekohasekai.libbox.Libbox.rejectConfig=true;try{reject(owner,dir,app,mode,b->{});}finally{io.nekohasekai.libbox.Libbox.rejectConfig=false;}
   // A callback between core validation and staging models a profile switch.
   JSONObject b=source(mode);File file=save(dir,b);int count=sessions(app);
   io.nekohasekai.libbox.Libbox.afterCheck=()->{try{Files.writeString(file.toPath(),source("wg-pq").put("selectedRouterID","changed").toString());}catch(Exception e){throw new RuntimeException(e);}};
   boolean stale=false;try{owner.prepareSession(file,mode);}catch(Exception expected){stale=true;}finally{io.nekohasekai.libbox.Libbox.afterCheck=null;}
   check(stale&&sessions(app)==count,"changed bundle staged a stale PQ session");
   count=sessions(app);Thread.currentThread().interrupt();boolean cancelled=false;
   try{owner.prepareSession(save(dir,source(mode)),mode);}catch(Exception expected){cancelled=true;}finally{Thread.interrupted();}
   check(cancelled&&sessions(app)==count,"cancelled PQ preparation staged a session");
  }
  System.out.println("Android PQ selection + captured source + DNS/MTU/Start Layer: PASS ("+checks+" checks; real Java and Go policy, OS/FFI initialization doubled)");
 }
}'''

def run():
    jar = Path(os.environ.get('ANDROID_JSON_JAR', '/usr/share/java/com.android.json.jar'))
    if not jar.is_file():
        raise RuntimeError('Android JSON implementation required')
    with tempfile.TemporaryDirectory(prefix='.pq-java-policy-',dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix='android-pq-selection-') as temp:
        go_dir, temp = Path(go_dir), Path(temp)
        (go_dir/'main.go').write_text(GO)
        native = temp/'policy'
        subprocess.run(['go','build','-o',str(native),str(go_dir/'main.go')],cwd=ROOT,check=True,timeout=60)
        src=temp/'src'
        for path, text in M.STUBS.items():
            if path.endswith('/Boundaries.java'):
                # Compile the exact shipping identity/validation methods rather
                # than the generic graph harness's identity shortcut.
                node_source = (JAVA/'AndroidNodeStore.java').read_text()
                methods = node_source[node_source.index('    static String stableNodeIdentity('):node_source.index('    static String deriveId(')]
                methods += node_source[node_source.index('    private static String wireGuardPeerPublicKey('):node_source.index('    private static JSONObject load(')]
                methods += next(line for line in node_source.splitlines() if 'private static String hex(byte[] data)' in line)
                constants = '\n'.join(line for line in node_source.splitlines() if 'private static final String NODE_PROOF_DOMAIN =' in line or 'static final int MAX_PROFILE_SCHEMA =' in line)
                start = text.index('final class AndroidNodeStore {')
                end = text.index('final class AndroidKillSwitchPolicy {')
                text = text[:start] + 'final class AndroidNodeStore {\n' + constants + '\n' + methods + '\n}\n' + text[end:]
                text = text.replace('import org.json.JSONObject;', 'import org.json.JSONObject; import org.json.JSONArray; import java.security.MessageDigest; import java.nio.charset.StandardCharsets; import android.util.Base64;')
            if path.endswith('/Libbox.java'):
                text=text.replace(' public static boolean rejectConfig;', ' public static Runnable afterCheck;\n public static boolean rejectConfig;')
                text=text.replace('new JSONObject(c);}', 'new JSONObject(c);if(afterCheck!=null)afterCheck.run();}')
            target=src/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
        app=src/'com/eabusham/routervpn'
        for name in ('AndroidMultihopController','NativeSingBoxController','AndroidProfileSelection','AndroidNumericAddress','AndroidNativeProfilePolicy','AndroidWireGuardLibboxPolicy','AndroidStartLayer','AndroidXrayLibboxPolicy','NativeXrayController','AndroidMultihopStartLayer'):
            shutil.copyfile(JAVA/(name+'.java'),app/(name+'.java'))
        (app/'MultihopGraphHarness.java').write_text(M.HARNESS)
        (app/'PQSelectionHarness.java').write_text(HARNESS)
        subprocess.run(['javac','--release','17','-cp',str(jar),'-d',str(temp/'classes'),*map(str,src.rglob('*.java'))],check=True,timeout=60)
        data=temp/'data';data.mkdir()
        subprocess.run(['java','-cp',str(temp/'classes')+os.pathsep+str(jar),'com.eabusham.routervpn.PQSelectionHarness',str(data)],env=dict(os.environ,ROUTERVPN_GO_POLICY_TEST=str(native)),check=True,timeout=90)
    # The service must install the process-owned factory before constructing the
    # engine, including process restarts with already-staged session data.
    service=(JAVA/'LayeredVpnService.java').read_text()
    assert service.count('RouterPQNative.install();')==1
    assert service.index('RouterPQNative.install();') < service.index('new CommandServer(')

if __name__=='__main__':run()
