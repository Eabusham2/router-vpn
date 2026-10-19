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
# Reuse the same real compiler in a bounded, framed test process. Hundreds of
# graph combinations must not require thousands of operating-system processes.
# No configuration, score or expected answer is cached or substituted.
GO = M.GO_HELPER
GO = GO.replace('import("context";', 'import("context";"encoding/binary";"bytes";', 1)
old_main = 'func main(){\n var r struct{Operation string;Config string;Policy string}\n if err:=json.NewDecoder(io.LimitReader(os.Stdin,8*1024*1024)).Decode(&r);err!=nil{fmt.Fprintln(os.Stderr,"invalid request");os.Exit(2)}'
assert GO.count(old_main) == 1
GO = GO.replace(old_main, 'type request struct{Operation string;Config string;Policy string}\nfunc handle(r request)(string,error){', 1)
GO = GO.replace('default:fmt.Fprintln(os.Stderr,"unknown test operation");os.Exit(2)', 'default:return "",fmt.Errorf("unknown test operation")', 1)
old_tail = ' if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}\n fmt.Print(value)'
assert GO.count(old_tail) == 1
GO = GO.replace(old_tail, ' return value,err', 1)
GO += r'''
func main(){
 for {
  var size uint32
  if err:=binary.Read(os.Stdin,binary.BigEndian,&size);err==io.EOF{return}else if err!=nil{panic(err)}
  if size==0||size>8*1024*1024{panic("invalid bounded test request")}
  payload:=make([]byte,size);if _,err:=io.ReadFull(os.Stdin,payload);err!=nil{panic(err)}
  var input request;var value string
  err:=json.NewDecoder(bytes.NewReader(payload)).Decode(&input)
  if err==nil{value,err=handle(input)}
  response:=map[string]string{"value":value,"error":""};if err!=nil{response["value"]="";response["error"]=err.Error()}
  encoded,err:=json.Marshal(response);if err!=nil||len(encoded)>16*1024*1024{panic("invalid bounded test response")}
  if err=binary.Write(os.Stdout,binary.BigEndian,uint32(len(encoded)));err!=nil{panic(err)}
  if _,err=os.Stdout.Write(encoded);err!=nil{panic(err)}
 }
}
'''
PIPE_CALL = r'''
 private static Process worker;
 private static java.io.DataInputStream input;
 private static java.io.DataOutputStream output;
 private static java.util.concurrent.ExecutorService reader;
 static { Runtime.getRuntime().addShutdownHook(new Thread(()->{if(worker!=null)worker.destroyForcibly();if(reader!=null)reader.shutdownNow();})); }
 private static synchronized String call(String op,String config,String policy)throws Exception {
  if(worker==null){
   worker=new ProcessBuilder(System.getenv("ROUTERVPN_GO_POLICY_TEST")).redirectError(ProcessBuilder.Redirect.INHERIT).start();
   input=new java.io.DataInputStream(worker.getInputStream());output=new java.io.DataOutputStream(worker.getOutputStream());
   reader=java.util.concurrent.Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"bounded-policy-test");t.setDaemon(true);return t;});
  }
  byte[] request=new JSONObject().put("Operation",op).put("Config",config).put("Policy",policy).toString().getBytes(StandardCharsets.UTF_8);
  if(request.length>8*1024*1024)throw new IllegalArgumentException("Test request exceeds bound");
  final java.io.DataInputStream capturedInput=input;final java.io.DataOutputStream capturedOutput=output;
  java.util.concurrent.Future<JSONObject> pending=reader.submit(()->{
   capturedOutput.writeInt(request.length);capturedOutput.write(request);capturedOutput.flush();
   int size=capturedInput.readInt();if(size<=0||size>16*1024*1024)throw new java.io.IOException("Test response exceeds bound");
   byte[] result=new byte[size];capturedInput.readFully(result);return new JSONObject(new String(result,StandardCharsets.UTF_8));
  });
  JSONObject response;
  try {response=pending.get(10,TimeUnit.SECONDS);}
  catch(Exception failure){worker.destroyForcibly();worker=null;pending.cancel(true);reader.shutdownNow();reader=null;throw failure;}
  if(!response.getString("error").isEmpty())throw new IllegalArgumentException(response.getString("error"));
  return response.getString("value");
 }
'''
HARNESS = r'''package com.eabusham.routervpn;
import android.content.Context;import org.json.*;import java.io.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.util.*;
import static com.eabusham.routervpn.MultihopGraphHarness.*;
public final class PQSelectionHarness {
 static String enc(byte[] value){return Base64.getEncoder().encodeToString(value);}
 static String enc(String value){return enc(value.getBytes(StandardCharsets.UTF_8));}
 static byte[] repeated(byte n,int count){byte[] value=new byte[count];Arrays.fill(value,n);return value;}
 static JSONObject source(String mode)throws Exception{return source(mode,'b');}
 static JSONObject source(String mode,char node)throws Exception{
  JSONObject b=bundle(node),assets=new JSONObject();String tool=mode.equals("wg-pq")?"wg":"awg";
  String raw=wg(node);
  if(tool.equals("awg"))raw=raw.replace("[Peer]","Jc=3\nJmin=40\nJmax=900\nS1=56\nS2=48\nS3=24\nS4=32\nH1=10000000-19999999\nH2=20000000-29999999\nH3=30000000-39999999\nH4=40000000-49999999\n[Peer]");
  assets.put(tool+".conf",enc(raw)).put("rosenpass-client-secret",enc(repeated((byte)1,64)))
    .put("rosenpass-client-public",enc(repeated((byte)2,128))).put("rosenpass-server-public",enc(repeated((byte)3,128)))
    .put("rosenpass.env",enc("ROSENPASS_TOOL="+tool+"\nROSENPASS_INTERFACE="+tool+"\nROSENPASS_WG_PEER="+key(node)+"\nROSENPASS_KEY_OUT=rosenpass.psk\nROSENPASS_PORT=51822\n"))
    .put("rosenpass.toml",enc("public_key = \"rosenpass-client-public\"\nsecret_key = \"rosenpass-client-secret\"\nlisten = []\nverbosity = \"Quiet\"\n[[peers]]\npublic_key = \"rosenpass-server-public\"\nendpoint = \"node.example.test:51822\"\nkey_out = \"rosenpass.psk\"\n"));
  b.getJSONObject("profiles").put(mode,assets);
  b.put("modes",new JSONArray().put(new JSONObject().put("id",mode).put("name",mode)));
  JSONObject outer=new JSONObject().put("type","shadowsocks").put("tag","proxy").put("method","2022-blake3-aes-256-gcm").put("password",key('s')).put("server",node=='a'?"192.0.2.1":"192.0.2.2").put("server_port",8388);
  JSONObject aesFiles=proxyBundle(node,"shadowsocks","").getJSONObject("profiles").getJSONObject("shadowsocks");
  JSONObject aesGraph=new JSONObject(new String(Base64.getDecoder().decode(aesFiles.getString("sing-box.json")),StandardCharsets.UTF_8));
  aesGraph.put("outbounds",new JSONArray().put(outer));
  b.getJSONObject("profiles").put("shadowsocks",new JSONObject().put("sing-box.json",enc(aesGraph.toString())));
  return b;
 }
 interface Change {void run(JSONObject b)throws Exception;}
 static void reject(NativeSingBoxController owner,Path dir,Path app,String mode,Change change)throws Exception{
  JSONObject b=source(mode);change.run(b);int count=sessions(app);File file=save(dir,b);String before=Files.readString(file.toPath());
  boolean rejected=false;try{owner.prepareSession(file,mode);}catch(Exception expected){rejected=true;}
  check(rejected,"invalid PQ launch accepted");check(sessions(app)==count,"failed PQ created session files");
  check(before.equals(Files.readString(file.toPath())),"failed PQ rewrote source assets");
 }
 static JSONObject exitSource(String mode,String certificate)throws Exception{
  JSONObject b=NativeSingBoxController.nativeWireGuardFamily(mode)||mode.startsWith("reality-")?awgBundle('b'):proxyBundle('b',mode,certificate);
  if(mode.startsWith("reality-")){
   JSONObject generated=xrayBundle(mode,"192.0.2.12");
   b.getJSONObject("profiles").put(mode,generated.getJSONObject("profiles").getJSONObject(mode));
   b.getJSONArray("modes").put(new JSONObject().put("id",mode).put("name",mode));
  }
  // The generated AES service also supplies the Start Layer. Keep a complete
  // proxy exit graph when that service itself is selected as the exit.
  if(mode.equals("shadowsocks")){
   JSONObject assets=b.getJSONObject("profiles").getJSONObject(mode);
   JSONObject graph=new JSONObject(new String(Base64.getDecoder().decode(assets.getString("sing-box.json")),StandardCharsets.UTF_8));
   graph.getJSONArray("outbounds").getJSONObject(0).put("method","2022-blake3-aes-256-gcm").put("password",key('s'));
   assets.put("sing-box.json",enc(graph.toString()));
  }else {
   JSONObject aes=source("wg-pq").getJSONObject("profiles").getJSONObject("shadowsocks");
   JSONObject graph=new JSONObject(new String(Base64.getDecoder().decode(aes.getString("sing-box.json")),StandardCharsets.UTF_8));
   String host=mode.startsWith("reality-")?"192.0.2.12":mode.equals("hysteria2")?"198.51.100.12":"192.0.2.2";
   graph.getJSONArray("outbounds").getJSONObject(0).put("server",host);
   aes.put("sing-box.json",enc(graph.toString()));b.getJSONObject("profiles").put("shadowsocks",aes);
  }
  return b;
 }
 static void multihopChecks(Path dir)throws Exception{
  String cert=io.nekohasekai.libbox.Libbox.testCertificate("exit.example.test");
  String[][] layers={{"off","off"},{"aes-256-gcm","off"},{"off","aes-256-gcm+xor-whitening"},{"aes-256-gcm+xor-whitening","aes-256-gcm"}};
  int graphs=0;
  for(String mode:new String[]{"wg-pq","awg2-pq"}){
   for(String exit:new String[]{"wg","awg2-fast","awg2-strong","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp"}){
    for(String execution:new String[]{"local","server","auto"})for(String[] pair:layers){
     Path app=Files.createTempDirectory(dir,"pq-multihop-");Context ctx=new Context(app.toFile());
     AndroidMultihopController builder=new AndroidMultihopController(ctx,new NativeSingBoxController(ctx));
     JSONObject a=source(mode,'a'),b=exitSource(exit,cert);
     profile(a).put("mtu_policy","fixed").put("manual_mtu",1500).put("start_layer",pair[0]).put("home_lan_access",false).put("ipv6_mode","off");
     profile(b).put("mtu_policy","fixed").put("manual_mtu",1280).put("start_layer",pair[1]).put("home_lan_access",false).put("ipv6_mode","off")
       .put("dns_mode","doh3").put("dns_host","192.168.50.133").put("dns_server_name","resolver.example.test").put("kill_switch",true);
     File af=save(dir,a),bf=save(dir,b);byte[] beforeA=Files.readAllBytes(af.toPath()),beforeB=Files.readAllBytes(bf.toPath());
     int installs=RouterPQNative.installs;
     AndroidMultihopController.Prepared prepared=builder.prepare(af,bf,exit,execution,mode);
     Path session=app.resolve("layered-sessions").resolve(prepared.session.sessionId);
     check(RouterPQNative.installs==installs+1,"PQ entry did not initialize the compiled factory");
     JSONObject graph=new JSONObject(Files.readString(session.resolve("sing-box.json"))),metadata=new JSONObject(Files.readString(session.resolve("routervpn-multihop.json")));
     check(metadata.getString("entry_mode").equals(mode)&&metadata.getString("exit_mode").equals(exit)&&metadata.getString("execution").equals(execution),"saved PQ graph selection changed");
     check(metadata.getString("entry_node_id").equals(a.getString("nodeProofId"))&&!metadata.getString("entry_node_id").equals(metadata.getString("exit_node_id")),"independent node proofs collapsed");
     JSONObject captured=byTag(graph,"entry-wg"),pq=captured.getJSONObject("pq");
     check(captured.getString("type").equals("routervpn-pq")&&captured.getString("mode").equals(mode)&&captured.getString("node_id").equals(a.getString("nodeProofId")),"PQ entry silently became another mode/node");
     for(String[] key:new String[][]{{"secret","rosenpass-client-secret"},{"public","rosenpass-client-public"},{"peer","rosenpass-server-public"}})
       check(pq.getString(key[0]).equals(a.getJSONObject("profiles").getJSONObject(mode).getString(key[1])),"PQ entry borrowed or changed key material");
     check(captured.getInt("mtu")==1500&&graph.getJSONArray("inbounds").getJSONObject(0).getInt("mtu")==1280,"per-hop MTU policy changed");
     check(graph.getJSONArray("inbounds").length()==3&&!Files.exists(session.resolve("wg.conf"))&&!Files.exists(session.resolve("awg.conf"))&&!Files.exists(session.resolve("rosenpass-client-secret")),"a raw/helper/second VPN was staged");
     if(mode.equals("awg2-pq"))check(captured.getJSONObject("amnezia").length()==11,"AWG obfuscation was dropped");
     String entry=Files.exists(session.resolve(AndroidMultihopStartLayer.SESSION_FILE))?Files.readString(session.resolve(AndroidMultihopStartLayer.SESSION_FILE)):null;
     String outerExit=Files.exists(session.resolve(AndroidMultihopStartLayer.EXIT_SESSION_FILE))?Files.readString(session.resolve(AndroidMultihopStartLayer.EXIT_SESSION_FILE)):null;
     io.nekohasekai.libbox.RouterMultihop runtime=AndroidMultihopStartLayer.prepareExecution(graph.toString(),metadata.toString(),entry,outerExit);
     JSONObject finalGraph=runtime==null?graph:new JSONObject(runtime.config());
     JSONObject first=byTag(finalGraph,"entry-wg");
     String expected=pair[0].equals("off")?"192.0.2.1":"10.77.0.1";
     check(first.getJSONObject("pq").getString("endpoint").equals(expected+":51822")&&first.getJSONArray("peers").getJSONObject(0).getString("address").equals(expected),"WG/PQ handshake escaped the same entry layer");
     check(first.getJSONObject("pq").getString("peer").equals(pq.getString("peer")),"layer composition rewrote the PQ peer");
     check(byTag(finalGraph,"entry-private").getString("detour").equals("entry-wg"),"entry proof bypasses negotiated PQ");
     JSONObject dns=finalGraph.getJSONObject("dns").getJSONArray("servers").getJSONObject(0);
     check(dns.getString("type").equals("h3")&&dns.getString("server").equals("192.168.50.133")&&dns.getString("detour").equals("proxy"),"selected AdGuard/transport/exit path changed");
     if(runtime!=null){
      check(byTag(finalGraph,"routervpn-execution-server").getString("detour").equals("entry-wg"),"server candidate bypasses PQ entry");
      check(byTag(finalGraph,"proxy").getString("type").equals("selector"),"comparison lost its owned selector");runtime.close();
     }
     check(Arrays.equals(beforeA,Files.readAllBytes(af.toPath()))&&Arrays.equals(beforeB,Files.readAllBytes(bf.toPath())),"multihop changed saved node sources");
     graphs++;
    }
   }
   for(Change change:new Change[]{
    b->b.put("nodeProofId",proof(key('x'))),
    b->b.put("selectedRouterID","missing"),
    b->b.getJSONArray("routerProfiles").put(new JSONObject(profile(b).toString())),
    b->b.getJSONObject("profiles").getJSONObject(mode).remove("rosenpass-client-secret"),
    b->b.getJSONObject("profiles").getJSONObject(mode).put("rosenpass-server-public",b.getJSONObject("profiles").getJSONObject(mode).getString("rosenpass-client-public")),
    b->b.getJSONObject("profiles").getJSONObject(mode).put("chain.env",enc("unowned helper"))}){
     JSONObject a=source(mode,'a');change.run(a);proxyRejected(dir,a,bundle('b'),mode,"wg");
   }
   RouterPQNative.fail=true;try{proxyRejected(dir,source(mode,'a'),bundle('b'),mode,"wg");}finally{RouterPQNative.fail=false;}
   io.nekohasekai.libbox.Libbox.rejectConfig=true;try{proxyRejected(dir,source(mode,'a'),bundle('b'),mode,"wg");}finally{io.nekohasekai.libbox.Libbox.rejectConfig=false;}
   for(int fault=0;fault<3;fault++){
    Path app=Files.createTempDirectory(dir,"pq-cancel-");Context ctx=new Context(app.toFile());
    AndroidMultihopController builder=new AndroidMultihopController(ctx,new NativeSingBoxController(ctx));
    JSONObject a=source(mode,'a'),b=bundle('b');profile(a).put("start_layer","aes-256-gcm");
    File af=save(dir,a),bf=save(dir,b);final int selected=fault;
    io.nekohasekai.libbox.Libbox.afterEntryLayerPreflight=()->{if(selected==0)Thread.currentThread().interrupt();else try{Files.writeString((selected==1?af:bf).toPath(),"{}");}catch(Exception e){throw new RuntimeException(e);}};
    boolean rejected=false;try{builder.prepare(af,bf,"wg","auto",mode);}catch(Exception expected){rejected=true;}finally{io.nekohasekai.libbox.Libbox.afterEntryLayerPreflight=null;Thread.interrupted();}
    check(rejected&&sessions(app)==0,"cancelled/changed PQ multihop staged a stale session");
   }
  }
  check(graphs==192,"PQ entry matrix incomplete");
  System.out.println("Android PQ entries: "+graphs+" real compiler graphs; OS/native initialization doubled");
 }
 public static void main(String[] args)throws Exception{
  Path dir=Path.of(args[0]),app=dir.resolve("app");Files.createDirectories(app);NativeSingBoxController owner=new NativeSingBoxController(new Context(app.toFile()));
  for(String mode:new String[]{"wg-pq","awg2-pq"}){
   check(NativeSingBoxController.nativePQFamily(mode),"native PQ predicate missing");
   check(!NativeSingBoxController.nativeWireGuardFamily(mode),"PQ silently selected raw backend");
   check(NativeSingBoxController.nativeMultihopEntry(mode),"PQ entry missing from owned multihop path");
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
  multihopChecks(dir);
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
                begin=text.index(' private static String call(')
                end=text.index(' public static String routerCompilePQProfile(', begin)
                text=text[:begin]+PIPE_CALL+text[end:]
                text=text.replace(' public static boolean rejectConfig;', ' public static Runnable afterCheck;\n public static boolean rejectConfig;')
                text=text.replace('new JSONObject(c);}', 'new JSONObject(c);if(afterCheck!=null)afterCheck.run();}')
            target=src/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
        app=src/'com/eabusham/routervpn'
        for name in ('AndroidMultihopController','NativeSingBoxController','AndroidNativeMAXProfile','AndroidNativeCompositeProfile','AndroidProfileSelection','AndroidNumericAddress','AndroidNativeProfilePolicy','AndroidWireGuardLibboxPolicy','AndroidStartLayer','AndroidXrayLibboxPolicy','NativeXrayController','AndroidMultihopStartLayer'):
            shutil.copyfile(JAVA/(name+'.java'),app/(name+'.java'))
        (app/'MultihopGraphHarness.java').write_text(M.HARNESS)
        (app/'PQSelectionHarness.java').write_text(HARNESS)
        subprocess.run(['javac','--release','17','-cp',str(jar),'-d',str(temp/'classes'),*map(str,src.rglob('*.java'))],check=True,timeout=60)
        data=temp/'data';data.mkdir()
        subprocess.run(['java','-cp',str(temp/'classes')+os.pathsep+str(jar),'com.eabusham.routervpn.PQSelectionHarness',str(data)],env=dict(os.environ,ROUTERVPN_GO_POLICY_TEST=str(native)),check=True,timeout=180)
    # The service must install the process-owned factory before constructing the
    # engine, including process restarts with already-staged session data.
    service=(JAVA/'LayeredVpnService.java').read_text()
    assert service.count('RouterPQNative.install();')==1
    assert service.index('RouterPQNative.install();') < service.index('new CommandServer(')

if __name__=='__main__':run()
