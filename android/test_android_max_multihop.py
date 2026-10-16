#!/usr/bin/env python3
"""Exercise complete MAX hops in shipping Java with real shared Go compilers.

The test uses Android's real org.json implementation. OS/FFI handles remain
explicit doubles; packet negotiation, APK and device acceptance have separate
native gates. Each case compiles raw generated assets rather than golden graphs.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('max_hop_android', ROOT/'android/test_android_pq_selection.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
# Retain existing raw PQ fixture constructors, not the old test entry point.
P.HARNESS=P.HARNESS[:P.HARNESS.index(' interface Change {')]+r'''
 static JSONObject fixtures;
 static final String[] MAX={"max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"};
 static final String[] ALL={"wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"};
 static JSONObject node(String mode,boolean entry,String layer,String certificate)throws Exception {
  char identity=entry?'a':'b';JSONObject b;
  if(AndroidNativeMAXProfile.isMode(mode)){
   JSONObject f=fixtures.getJSONObject(entry?"entry":"exit").getJSONObject(mode),policy=f.getJSONObject("policy");
   b=bundle(identity);b.getJSONObject("profiles").put(mode,new JSONObject(f.getJSONObject("files").toString()));
   b.getJSONArray("modes").put(new JSONObject().put("id",mode).put("name",mode));
   b.put("nodeProofId",policy.getString("node_id"));
   profile(b).put("endpoint",policy.getString("endpoint"));
  }else if(NativeSingBoxController.nativePQFamily(mode))b=source(mode,identity);
  else if(NativeSingBoxController.nativeWireGuardFamily(mode))b=awgBundle(identity);
  else if(mode.startsWith("reality-")){
   b=bundle(identity);JSONObject x=xrayBundle(mode,entry?"192.0.2.11":"192.0.2.12");
   b.getJSONObject("profiles").put(mode,x.getJSONObject("profiles").getJSONObject(mode));
   b.getJSONArray("modes").put(new JSONObject().put("id",mode).put("name",mode));
  }else b=proxyBundle(identity,mode,certificate);
  JSONObject p=profile(b);String service=entry?"10.77.0.1":"10.88.0.1";
  p.put("node_proof_id",b.getString("nodeProofId")).put("node_kind","router-vpn").put("socks_host",service)
   .put("router_api","http://"+service+":8787").put("api_token",entry?"entry-private-token":"exit-private-token")
   .put("start_layer",layer).put("ipv6_mode","off").put("home_lan_access",false).put("kill_switch",true);
  if(!AndroidNativeMAXProfile.isMode(mode)){
   String outer=entry?"192.0.2.1":"192.0.2.2";
   JSONObject aes=new JSONObject(source("wg-pq",identity).getJSONObject("profiles").getJSONObject("shadowsocks").toString());
   if(mode.equals("shadowsocks")||mode.equals("hysteria2")){
    JSONObject selected=new JSONObject(new String(Base64.getDecoder().decode(b.getJSONObject("profiles").getJSONObject(mode).getString("sing-box.json")),StandardCharsets.UTF_8));
    outer=selected.getJSONArray("outbounds").getJSONObject(0).getString("server");
    if(mode.equals("shadowsocks"))aes=b.getJSONObject("profiles").getJSONObject(mode);
   }else if(mode.startsWith("reality-"))outer=entry?"192.0.2.11":"192.0.2.12";
   JSONObject graph=new JSONObject(new String(Base64.getDecoder().decode(aes.getString("sing-box.json")),StandardCharsets.UTF_8));
   graph.getJSONArray("outbounds").getJSONObject(0).put("method","2022-blake3-aes-256-gcm").put("password",key('s')).put("server",outer);
   aes.put("sing-box.json",enc(graph.toString()));b.getJSONObject("profiles").put("shadowsocks",aes);
  }
  return b;
 }
 static JSONObject load(Path p)throws Exception{return new JSONObject(Files.readString(p));}
 static String layerFile(Path p)throws Exception{return Files.exists(p)?Files.readString(p):null;}
 static void complete(JSONObject g,JSONObject source,String mode,String tag,String prefix,boolean entry,String layer)throws Exception {
  JSONObject base=byTag(g,tag),middle=byTag(g,prefix+"ss"),outer=byTag(g,prefix+"outer");
  check(base.getString("type").equals("routervpn-pq")&&base.getString("mode").equals(mode.endsWith("-awg")?"awg2-pq":"wg-pq"),"MAX downgraded its base");
  check(base.getString("detour").equals(prefix+"ss")&&middle.getString("detour").equals(prefix+"outer"),"mandatory encryption edge changed");
  check(middle.getString("type").equals("shadowsocks")&&middle.getString("method").equals("2022-blake3-aes-256-gcm"),"MAX lost its SS2022 layer");
  check(outer.getString("type").equals(mode.startsWith("max-tls-")?"routervpn-xray":"hysteria2"),"MAX outer protocol changed");
  JSONObject assets=source.getJSONObject("profiles").getJSONObject(mode);
  for(String[] pair:new String[][]{{"secret","rosenpass-client-secret"},{"public","rosenpass-client-public"},{"peer","rosenpass-server-public"}})
   check(base.getJSONObject("pq").getString(pair[0]).equals(assets.getString(pair[1])),"MAX borrowed another hop's key");
  check(base.getString("node_id").equals(source.getString("nodeProofId")),"MAX node proof changed");
  String service=entry?"10.77.0.1":"10.88.0.1";
  check(base.getJSONObject("pq").getString("endpoint").equals(service+":51822")&&base.getJSONArray("peers").getJSONObject(0).getString("address").equals(service),"MAX base and handshake left the same node");
  if(mode.endsWith("-awg"))check(base.getJSONObject("amnezia").length()==11,"MAX AWG parameters dropped");
  JSONObject physical=outer;
  if(!layer.equals("off")){
   check(outer.getString("detour").equals(prefix+"start"),"MAX optional layer missing");physical=byTag(g,prefix+"start");
   check(physical.getString("type").equals(layer.equals("aes-256-gcm")?"shadowsocks":"routervpn-aes-xor"),"wrong optional layer owner");
  }
  check(entry?!physical.has("detour"):physical.getString("detour").equals("entry-wg"),"MAX physical routing escaped selected entry");
 }
 interface Change {void run(JSONObject source)throws Exception;}
 static void rejected(Path dir,String em,String xm,boolean editEntry,Change change)throws Exception {
  JSONObject a=node(em,true,"off",certificate),b=node(xm,false,"off",certificate);change.run(editEntry?a:b);
  profile(a).put("mtu_policy","fixed").put("manual_mtu",1500);profile(b).put("mtu_policy","fixed").put("manual_mtu",1280);
  File af=save(dir,a),bf=save(dir,b);byte[] sa=Files.readAllBytes(af.toPath()),sb=Files.readAllBytes(bf.toPath());
  Path app=Files.createTempDirectory(dir,"reject-");Context context=new Context(app.toFile());
  AndroidMultihopController owner=new AndroidMultihopController(context,new NativeSingBoxController(context));
  boolean failed=false;try{owner.prepare(af,bf,xm,"auto",em);}catch(Exception expected){failed=true;}
  check(failed&&sessions(app)==0,"invalid MAX hop staged a runnable session");
  check(Arrays.equals(sa,Files.readAllBytes(af.toPath()))&&Arrays.equals(sb,Files.readAllBytes(bf.toPath())),"rejection rewrote a source bundle");
 }
 static String certificate;
 public static void main(String[] args)throws Exception {
  Path dir=Path.of(args[0]);fixtures=load(Path.of(System.getenv("ROUTERVPN_MAX_MULTIHOP_FIXTURES")));
  certificate=io.nekohasekai.libbox.Libbox.testCertificate("exit.example.test");int graphs=0;
  String[][] layers={{"off","off"},{"aes-256-gcm","aes-256-gcm+xor-whitening"},{"aes-256-gcm+xor-whitening","aes-256-gcm"}};
  for(String em:ALL)for(String xm:ALL){
   if(!AndroidNativeMAXProfile.isMode(em)&&!AndroidNativeMAXProfile.isMode(xm))continue;
   for(String execution:new String[]{"local","server","auto"})for(String[] layer:layers){
    JSONObject a=node(em,true,layer[0],certificate),b=node(xm,false,layer[1],certificate);
    boolean packetEntry=NativeSingBoxController.nativeWireGuardFamily(em)||NativeSingBoxController.nativePQFamily(em)||AndroidNativeMAXProfile.isMode(em);
    profile(a).put("mtu_policy","fixed").put("manual_mtu",packetEntry?1500:1280);
    profile(b).put("mtu_policy","fixed").put("manual_mtu",1280).put("dns_mode","doh3").put("dns_host","192.168.50.133").put("dns_server_name","resolver.example.test").put("daita_enabled",true);
    File af=save(dir,a),bf=save(dir,b);byte[] sa=Files.readAllBytes(af.toPath()),sb=Files.readAllBytes(bf.toPath());
    Path app=Files.createTempDirectory(dir,"graph-");Context context=new Context(app.toFile());
    NativeSingBoxController nativeOwner=new NativeSingBoxController(context);AndroidMultihopController owner=new AndroidMultihopController(context,nativeOwner);
    check(NativeSingBoxController.nativeMultihopEntry(em),"requested MAX entry absent from runtime selector");
    if(AndroidNativeMAXProfile.isMode(xm))check(owner.listSupportedExitModes(bf).stream().anyMatch(m->m.id.equals(xm)),"requested MAX exit absent from readiness picker");
    int installs=RouterPQNative.installs;
    AndroidMultihopController.Prepared prepared=owner.prepare(af,bf,xm,execution,em);
    Path staged=app.resolve("layered-sessions").resolve(prepared.session.sessionId);
    check(RouterPQNative.installs==installs+1,"MAX native factory not captured before launch");
    JSONObject graph=load(staged.resolve("sing-box.json")),meta=load(staged.resolve("routervpn-multihop.json"));
    check(meta.getString("entry_mode").equals(em)&&meta.getString("exit_mode").equals(xm)&&meta.getString("execution").equals(execution),"MAX selection relabeled as a base tunnel");
    check(!meta.getString("entry_node_id").equals(meta.getString("exit_node_id")),"MAX node identities collapsed");
    check(prepared.session.modeId.equals("multihop-"+xm),"MAX prepared identity changed");
    check(graph.getJSONArray("inbounds").length()==3,"MAX created extra system VPN interfaces");
    check(graph.getJSONArray("inbounds").getJSONObject(0).getInt("mtu")==1280,"MAX changed the shared TUN's fixed MTU");
    check(Files.exists(staged.resolve(AndroidKillSwitchPolicy.SESSION_MARKER)),"MAX lost strict kill-switch staging");
    String ec=layerFile(staged.resolve(AndroidMultihopStartLayer.SESSION_FILE)),xc=layerFile(staged.resolve(AndroidMultihopStartLayer.EXIT_SESSION_FILE));
    if(AndroidNativeMAXProfile.isMode(em)){
     check(ec==null,"MAX entry staged a second outer-layer owner");complete(graph,a,em,"entry-wg","routervpn-entry-max-",true,layer[0]);
    }
    if(AndroidNativeMAXProfile.isMode(xm)){
     check(xc==null,"MAX exit staged a second outer-layer owner");complete(graph,b,xm,"proxy","routervpn-exit-max-",false,layer[1]);
    }
    for(String file:new String[]{"wg.conf","awg.conf","chain.env","rosenpass.toml","rosenpass-client-secret","outer-xray.json"})check(!Files.exists(staged.resolve(file)),"MAX helper/raw asset staged: "+file);
    io.nekohasekai.libbox.RouterMultihop runtime=AndroidMultihopStartLayer.prepareExecution(graph.toString(),meta.toString(),ec,xc);
    check(runtime!=null,"MAX Local skipped final complete graph validation");
    JSONObject finalGraph=new JSONObject(runtime.config());
    if(AndroidNativeMAXProfile.isMode(em))complete(finalGraph,a,em,"entry-wg","routervpn-entry-max-",true,layer[0]);
    if(AndroidNativeMAXProfile.isMode(xm))complete(finalGraph,b,xm,"routervpn-execution-local","routervpn-exit-max-",false,layer[1]);
    check(byTag(finalGraph,"proxy").getString("type").equals("selector"),"MAX comparison lost its single selector");
    check(byTag(finalGraph,"routervpn-execution-server").getString("detour").equals("entry-wg"),"MAX server candidate bypassed entry");
    JSONArray dns=finalGraph.getJSONObject("dns").getJSONArray("servers");JSONObject selected=dns.getJSONObject(dns.length()-1);
    check(selected.getString("server").equals("192.168.50.133")&&selected.getString("type").equals("h3")&&selected.getString("detour").equals("proxy"),"MAX replaced AdGuard or its exit route");
    runtime.close();
    check(Arrays.equals(sa,Files.readAllBytes(af.toPath()))&&Arrays.equals(sb,Files.readAllBytes(bf.toPath())),"MAX assembly changed stored node credentials");graphs++;
   }
  }
  check(graphs==864,"incomplete MAX multihop matrix");
  for(String mode:MAX)for(boolean entry:new boolean[]{true,false}){
   String em=entry?mode:"wg",xm=entry?"wg":mode;
   rejected(dir,em,xm,entry,b->b.getJSONObject("profiles").getJSONObject(mode).remove("rosenpass-client-secret"));
   rejected(dir,em,xm,entry,b->b.put("selectedRouterID","missing"));
   rejected(dir,em,xm,entry,b->b.getJSONArray("routerProfiles").put(new JSONObject(profile(b).toString())));
   rejected(dir,em,xm,entry,b->b.getJSONObject("profiles").getJSONObject(mode).put("run.sh",enc("do not execute")));
   rejected(dir,em,xm,entry,b->profile(b).put("start_layer","xor"));
   RouterPQNative.fail=true;try{rejected(dir,em,xm,entry,b->{});}finally{RouterPQNative.fail=false;}
   io.nekohasekai.libbox.Libbox.rejectConfig=true;try{rejected(dir,em,xm,entry,b->{});}finally{io.nekohasekai.libbox.Libbox.rejectConfig=false;}
   for(boolean cancel:new boolean[]{false,true}){
    JSONObject a=node(em,true,"off",certificate),b=node(xm,false,"off",certificate);
    File af=save(dir,a),bf=save(dir,b);Path app=Files.createTempDirectory(dir,"stale-");Context ctx=new Context(app.toFile());
    io.nekohasekai.libbox.Libbox.afterCheck=()->{if(cancel)Thread.currentThread().interrupt();else try{Files.writeString((entry?af:bf).toPath(),"{}");}catch(Exception error){throw new RuntimeException(error);}};
    boolean failed=false;try{new AndroidMultihopController(ctx,new NativeSingBoxController(ctx)).prepare(af,bf,xm,"auto",em);}catch(Exception expected){failed=true;}
    finally{Thread.interrupted();io.nekohasekai.libbox.Libbox.afterCheck=null;}
    check(failed&&sessions(app)==0,"stale/cancelled MAX graph staged a session");
   }
  }
  System.out.println("Android complete MAX multihop: "+graphs+" graphs, "+checks+" checks passed (real Java/Go/Android JSON; OS/FFI handles doubled)");
 }
}
'''

def main():
    if os.environ.get('ROUTERVPN_JSON_BOUNDARY_DOUBLE'):
        raise RuntimeError('This integration requires the actual Android JSON implementation')
    with tempfile.TemporaryDirectory(prefix='max-multihop-fixtures-') as tmp:
        fixture=Path(tmp)/'nodes.json'
        subprocess.run(['go','test','-count=1','-run','^TestExportMAXMultihopMobileProfiles$','./internal/mobilemultihop'],cwd=ROOT,env=dict(os.environ,ROUTERVPN_MAX_MULTIHOP_FIXTURES=str(fixture)),check=True,timeout=90)
        old=os.environ.get('ROUTERVPN_MAX_MULTIHOP_FIXTURES');os.environ['ROUTERVPN_MAX_MULTIHOP_FIXTURES']=str(fixture)
        try:P.run()
        finally:
            if old is None:os.environ.pop('ROUTERVPN_MAX_MULTIHOP_FIXTURES',None)
            else:os.environ['ROUTERVPN_MAX_MULTIHOP_FIXTURES']=old

if __name__=='__main__':main()
