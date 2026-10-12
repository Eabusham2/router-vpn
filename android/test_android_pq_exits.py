#!/usr/bin/env python3
"""Execute shipping Android PQ exit preparation using the real shared compiler.

Uses the existing bounded Java/Go harness. Only Android OS handles, native
factory installation and native loader handles are doubled, not graph policy.
Native encrypted traffic and packaged-device tests remain independent gates.
"""
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pq_host_checks', ROOT/'android/test_android_pq_selection.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
EXTRA = r'''
 static JSONObject entryForExitTest(String mode,String certificate)throws Exception{
  if(NativeSingBoxController.nativePQFamily(mode))return source(mode,'a');
  JSONObject a;
  String host="192.0.2.1";
  if(NativeSingBoxController.nativeWireGuardFamily(mode))a=awgBundle('a');
  else if(mode.startsWith("reality-")){a=xrayBundle(mode,"192.0.2.11");host="192.0.2.11";}
  else {a=proxyBundle('a',mode,certificate);host="192.0.2.11";}
  JSONObject aes=source("wg-pq",'a').getJSONObject("profiles").getJSONObject("shadowsocks");
  JSONObject graph=new JSONObject(new String(Base64.getDecoder().decode(aes.getString("sing-box.json")),StandardCharsets.UTF_8));
  graph.getJSONArray("outbounds").getJSONObject(0).put("server",host);
  if(mode.equals("shadowsocks")){
   a.getJSONObject("profiles").getJSONObject(mode).put("sing-box.json",enc(graph.toString()));
  }else a.getJSONObject("profiles").put("shadowsocks",new JSONObject().put("sing-box.json",enc(graph.toString())));
  return a;
 }
 static JSONObject exitForPQTest(String mode)throws Exception{
  JSONObject b=source(mode,'b');JSONObject files=b.getJSONObject("profiles").getJSONObject(mode);
  files.put("rosenpass-client-public",enc(repeated((byte)6,128))).put("rosenpass-client-secret",enc(repeated((byte)7,64)));
  String rawName=mode.equals("wg-pq")?"wg.conf":"awg.conf";
  String raw=new String(Base64.getDecoder().decode(files.getString(rawName)),StandardCharsets.UTF_8).replace(key('z'),key('y'));
  files.put(rawName,enc(raw));
  return b;
 }
 static void setExitTestPolicies(JSONObject a,JSONObject b,String entryMode)throws Exception{
  boolean packet=NativeSingBoxController.nativeWireGuardFamily(entryMode)||NativeSingBoxController.nativePQFamily(entryMode);
  profile(a).put("mtu_policy","fixed").put("manual_mtu",packet?1500:1280).put("home_lan_access",false).put("ipv6_mode","off");
  profile(b).put("mtu_policy","fixed").put("manual_mtu",1280).put("home_lan_access",false).put("ipv6_mode","off")
    .put("dns_mode","doh3").put("dns_host","192.168.50.133").put("dns_server_name","resolver.example.test").put("kill_switch",true).put("daita_enabled",true);
 }
 static void exitMatrices(Path dir)throws Exception{
  String cert=io.nekohasekai.libbox.Libbox.testCertificate("entry.example.test");
  String[][] layers={{"off","off"},{"aes-256-gcm","off"},{"off","aes-256-gcm+xor-whitening"},{"aes-256-gcm+xor-whitening","aes-256-gcm"}};
  int graphs=0;
  for(String entry:new String[]{"wg","awg2-fast","awg2-strong","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp","wg-pq","awg2-pq"})
   for(String exit:new String[]{"wg-pq","awg2-pq"})for(String execution:new String[]{"local","server","auto"})for(String[] layer:layers){
    Path app=Files.createTempDirectory(dir,"pq-exit-");Context ctx=new Context(app.toFile());
    NativeSingBoxController nativeOwner=new NativeSingBoxController(ctx);AndroidMultihopController builder=new AndroidMultihopController(ctx,nativeOwner);
    JSONObject a=entryForExitTest(entry,cert),b=exitForPQTest(exit);setExitTestPolicies(a,b,entry);
    profile(a).put("start_layer",layer[0]);profile(b).put("start_layer",layer[1]);
    File af=save(dir,a),bf=save(dir,b);byte[] beforeA=Files.readAllBytes(af.toPath()),beforeB=Files.readAllBytes(bf.toPath());
    int installed=RouterPQNative.installs;
    check(builder.listSupportedExitModes(bf).stream().anyMatch(mode->mode.id.equals(exit)),"valid PQ exit missing from picker");
    check(RouterPQNative.installs==installed,"exit discovery initialized native PQ");
    AndroidMultihopController.Prepared prepared=builder.prepare(af,bf,exit,execution,entry);
    check(RouterPQNative.installs==installed+1,"PQ exit launch failed to install one shared factory");
    check(prepared.exitMode.equals(exit)&&prepared.session.modeId.equals("multihop-"+exit),"exit status downgraded PQ");
    Path session=app.resolve("layered-sessions").resolve(prepared.session.sessionId);
    JSONObject graph=new JSONObject(Files.readString(session.resolve("sing-box.json"))),metadata=new JSONObject(Files.readString(session.resolve("routervpn-multihop.json")));
    JSONObject captured=byTag(graph,"proxy");
    check(captured.getString("type").equals("routervpn-pq")&&captured.getString("mode").equals(exit)&&captured.getString("node_id").equals(b.getString("nodeProofId")),"exit protocol or node changed");
    check(captured.getString("private_key").equals(key('y'))&&captured.getJSONArray("peers").getJSONObject(0).getString("public_key").equals(key('b')),"exit borrowed entry WG credentials");
    for(String[] pair:new String[][]{{"secret","rosenpass-client-secret"},{"public","rosenpass-client-public"},{"peer","rosenpass-server-public"}})
     check(captured.getJSONObject("pq").getString(pair[0]).equals(b.getJSONObject("profiles").getJSONObject(exit).getString(pair[1])),"exit changed its captured PQ identity");
    if(exit.equals("awg2-pq"))check(captured.getJSONObject("amnezia").length()==11,"exit lost AWG obfuscation");
    check(metadata.getString("entry_node_id").equals(a.getString("nodeProofId"))&&metadata.getString("exit_node_id").equals(b.getString("nodeProofId"))&&!metadata.getString("entry_node_id").equals(metadata.getString("exit_node_id")),"independent node proofs collapsed");
    check(metadata.getString("entry_mode").equals(entry)&&metadata.getString("exit_mode").equals(exit)&&metadata.getString("execution").equals(execution),"saved graph labels changed");
    check(graph.getJSONArray("inbounds").length()==3,"exit spawned another system VPN");
    for(String raw:new String[]{"wg.conf","awg.conf","rosenpass.toml","rosenpass.env","rosenpass-client-secret","rosenpass-client-public","rosenpass-server-public"})check(!Files.exists(session.resolve(raw)),"raw/helper artifact staged: "+raw);
    String outerEntry=Files.exists(session.resolve(AndroidMultihopStartLayer.SESSION_FILE))?Files.readString(session.resolve(AndroidMultihopStartLayer.SESSION_FILE)):null;
    String outerExit=Files.exists(session.resolve(AndroidMultihopStartLayer.EXIT_SESSION_FILE))?Files.readString(session.resolve(AndroidMultihopStartLayer.EXIT_SESSION_FILE)):null;
    io.nekohasekai.libbox.RouterMultihop runtime=AndroidMultihopStartLayer.prepareExecution(graph.toString(),metadata.toString(),outerEntry,outerExit);
    JSONObject finalGraph=runtime==null?graph:new JSONObject(runtime.config());
    JSONObject last=byTag(finalGraph,runtime==null?"proxy":"routervpn-execution-local");
    String host=layer[1].equals("off")?"192.0.2.2":"10.77.0.1";
    check(last.getJSONObject("pq").getString("endpoint").equals(host+":51822")&&last.getJSONArray("peers").getJSONObject(0).getString("address").equals(host),"PQ and WG handshake paths diverged");
    check(last.getInt("mtu")==1280&&finalGraph.getJSONArray("inbounds").getJSONObject(0).getInt("mtu")==1280,"exit MTU changed");
    check(byTag(finalGraph,"entry-private").getString("detour").equals("entry-wg"),"entry proof bypasses entry");
    JSONArray resolvers=finalGraph.getJSONObject("dns").getJSONArray("servers");
    for(int i=0;i<resolvers.length();i++)check(resolvers.getJSONObject(i).getString("detour").equals("proxy"),"DNS bypasses PQ exit");
    JSONObject resolver=resolvers.getJSONObject(resolvers.length()-1);
    check(resolver.getString("type").equals("h3")&&resolver.getString("server").equals("192.168.50.133"),"selected AdGuard/DoH3 policy changed");
    if(runtime!=null){check(byTag(finalGraph,"routervpn-execution-server").getString("detour").equals("entry-wg"),"server candidate bypasses captured entry");runtime.close();}
    check(Arrays.equals(beforeA,Files.readAllBytes(af.toPath()))&&Arrays.equals(beforeB,Files.readAllBytes(bf.toPath())),"launch rewrote either saved node");
    graphs++;
   }
  check(graphs==240,"PQ exit graph matrix incomplete");
  System.out.println("Android PQ exits: "+graphs+" real Java/Go graphs");
 }
 static void rejectExitChanges(Path dir)throws Exception{
  for(String mode:new String[]{"wg-pq","awg2-pq"}){
   for(Change change:new Change[]{
    b->b.getJSONObject("profiles").getJSONObject(mode).remove("rosenpass-client-secret"),
    b->b.getJSONObject("profiles").getJSONObject(mode).put("rosenpass-server-public",b.getJSONObject("profiles").getJSONObject(mode).getString("rosenpass-client-public")),
    b->b.getJSONObject("profiles").getJSONObject(mode).put("chain.env",enc("unrequested helper")),
    b->b.put("nodeProofId",proof(key('x'))),b->b.put("selectedRouterID","missing"),
    b->b.getJSONArray("routerProfiles").put(new JSONObject(profile(b).toString()))}){
    Path app=Files.createTempDirectory(dir,"pq-exit-reject-");Context ctx=new Context(app.toFile());
    AndroidMultihopController builder=new AndroidMultihopController(ctx,new NativeSingBoxController(ctx));
    JSONObject a=awgBundle('a'),b=exitForPQTest(mode);setExitTestPolicies(a,b,"wg");
    File af=save(dir,a),bf=save(dir,b);builder.prepare(af,bf,mode,"auto","wg");int count=sessions(app);
    change.run(b);Files.writeString(bf.toPath(),b.toString());
    boolean rejected=false;try{builder.prepare(af,bf,mode,"auto","wg");}catch(Exception expected){rejected=true;}
    check(rejected&&sessions(app)==count,"invalid exit staged or reused an old PQ graph");
   }
   for(int fault=0;fault<4;fault++){
    Path app=Files.createTempDirectory(dir,"pq-exit-cancel-");Context ctx=new Context(app.toFile());
    AndroidMultihopController builder=new AndroidMultihopController(ctx,new NativeSingBoxController(ctx));
    JSONObject a=awgBundle('a'),b=exitForPQTest(mode);setExitTestPolicies(a,b,"wg");File af=save(dir,a),bf=save(dir,b);
    final int selected=fault;
    if(fault==3)RouterPQNative.fail=true;
    else io.nekohasekai.libbox.Libbox.afterCheck=()->{if(selected==0)Thread.currentThread().interrupt();else try{Files.writeString((selected==1?af:bf).toPath(),"{}");}catch(Exception e){throw new RuntimeException(e);}};
    boolean rejected=false;try{builder.prepare(af,bf,mode,"auto","wg");}catch(Exception expected){rejected=true;}finally{RouterPQNative.fail=false;io.nekohasekai.libbox.Libbox.afterCheck=null;Thread.interrupted();}
    check(rejected&&sessions(app)==0,"cancelled/changed/uninitialized PQ exit staged a session");
   }
   JSONObject b=exitForPQTest(mode),assets=b.getJSONObject("profiles");assets.getJSONObject(mode).remove("rosenpass-client-secret");
   String other=mode.equals("wg-pq")?"awg2-pq":"wg-pq";
   assets.put(other,exitForPQTest(other).getJSONObject("profiles").getJSONObject(other));b.getJSONArray("modes").put(new JSONObject().put("id",other).put("name",other));
   Path app=Files.createTempDirectory(dir,"pq-exit-picker-");Context ctx=new Context(app.toFile());AndroidMultihopController builder=new AndroidMultihopController(ctx,new NativeSingBoxController(ctx));
   java.util.List<NativeSingBoxController.ModeInfo> choices=builder.listSupportedExitModes(save(dir,b));
   check(choices.stream().noneMatch(x->x.id.equals(mode))&&choices.stream().anyMatch(x->x.id.equals(other)),"one bad PQ exit hid a valid exit");
  }
 }
 public static void main(String[]args)throws Exception{
  Path dir=Path.of(args[0]);exitMatrices(dir);rejectExitChanges(dir);
  System.out.println("Android PQ exits: PASS ("+checks+" executable checks; native/OS handles doubled)");
 }
}'''
start = P.HARNESS.index(' public static void main(String[] args)throws Exception{')
P.HARNESS = P.HARNESS[:start] + EXTRA

if __name__ == '__main__':
    P.run()
