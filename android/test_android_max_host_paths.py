#!/usr/bin/env python3
"""Execute hostname MAX through each shipping Android graph preparation path."""
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('max_tor_paths', ROOT/'android/test_android_tor_profile.py')
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)

T.HARNESS = T.HARNESS[:T.HARNESS.index(' public static void main(')] + r'''
 static void hostname(JSONObject b,String mode,String label)throws Exception{
  JSONObject assets=b.getJSONObject("profiles").getJSONObject(mode);String name=mode.startsWith("max-tls-")?"outer-xray.json":"middle-sing-box.json";
  JSONObject raw=new JSONObject(new String(Base64.getDecoder().decode(assets.getString(name)),StandardCharsets.UTF_8));
  if(mode.startsWith("max-tls-"))raw.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).put("address",label);
  else raw.getJSONArray("outbounds").getJSONObject(0).put("server",label);
  assets.put(name,enc(raw.toString()));profile(b).put("endpoint",label);
 }
 static void reset(){
  AndroidHomeStateStore.value=new AndroidHomeStateStore.Snapshot();AndroidHomeStateStore.emergency=false;
  android.net.DnsResolver.next=new android.net.DnsResolver.State();io.nekohasekai.libbox.RouterMAXProfileRequest.next=new io.nekohasekai.libbox.RouterMAXProfileRequest.State();
 }
 static void adopted(Context context,NativeSingBoxController.SessionInfo session,int requests)throws Exception{
  check(session.maxPreparation!=null,"shipping preparation dropped hostname owner");
  Path folder=context.getFilesDir().toPath().resolve("layered-sessions").resolve(session.sessionId);String config=Files.readString(folder.resolve("sing-box.json"));
  session.maxPreparation.beforeSubmit(session.sessionId,session.modeId);
  var proof=AndroidMAXProfilePreparation.claim(context,folder.toFile(),session.sessionId,session.modeId,config,session.maxPreparation.identity);
  check(proof!=null&&proof.current(true)&&!AndroidMAXProfilePreparation.busy(),"host launch escaped captured source/physical ownership");
  check(io.nekohasekai.libbox.RouterMAXProfileRequest.next.closes.get()==requests,"host lost one of its native resolve requests");
  JSONObject graph=new JSONObject(config);int tuns=0;for(int i=0;i<graph.getJSONArray("inbounds").length();i++)if(graph.getJSONArray("inbounds").getJSONObject(i).getString("type").equals("tun"))tuns++;
  check(tuns==1,"hostname preparation created a second VPN");
  proof.cancel();
 }
 static void resolved(JSONObject graph,String prefix,String layer,String mode)throws Exception{
  JSONObject last=byTag(graph,prefix+(layer.equals("off")?"outer":prefix.equals("routervpn-max-")?"start-layer":"start"));
  String endpoint=layer.equals("off")&&mode.startsWith("max-tls-")?new JSONObject(last.getString("config_json")).getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address"):last.getString("server");
  check(endpoint.equals("198.51.100.17"),"hostname graph did not retain exact resolver answer");
 }
 public static void main(String[] args)throws Exception{
  Path dir=Path.of(args[0]);fixtures=load(Path.of(System.getenv("ROUTERVPN_MAX_MULTIHOP_FIXTURES")));
  compositeEntry=load(Path.of(System.getenv("ROUTERVPN_COMPOSITE_ENTRY")));compositeExit=load(Path.of(System.getenv("ROUTERVPN_COMPOSITE_EXIT")));
  String certificate=io.nekohasekai.libbox.Libbox.testCertificate("entry.example.test");int direct=0,hops=0,tors=0;
  for(String mode:new String[]{"max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"})for(String layer:LAYERS){
   reset();Context ctx=new Context(Files.createTempDirectory(dir,"single-").toFile());NativeSingBoxController owner=new NativeSingBoxController(ctx);
   JSONObject b=entry(mode,layer,certificate);hostname(b,mode,"Selected-MAX.example.");File file=save(Files.createTempDirectory(dir,"single-node-"),b);byte[] original=Files.readAllBytes(file.toPath());
   check(owner.listDirectLibboxModes(file).stream().anyMatch(m->m.id.equals(mode)),"validated hostname mode is absent from manual/AUTO readiness");
   check(android.net.DnsResolver.next.network==null,"readiness resolved a hostname before connection ownership");
   NativeSingBoxController.SessionInfo session=owner.prepareSession(file,mode);JSONObject graph=load(ctx.getFilesDir().toPath().resolve("layered-sessions").resolve(session.sessionId).resolve("sing-box.json"));
   resolved(graph,"routervpn-max-",layer,mode);adopted(ctx,session,1);check(Arrays.equals(original,Files.readAllBytes(file.toPath())),"single MAX changed saved source");direct++;
   for(String direction:new String[]{"entry","exit","both"})for(String execution:new String[]{"local","server","auto"}){
    reset();Context c=new Context(Files.createTempDirectory(dir,"hops-").toFile());String em=direction.equals("exit")?"wg":mode,xm=direction.equals("entry")?"wg":mode;
    JSONObject a=node(em,true,layer,certificate),x=node(xm,false,layer,certificate);
    profile(a).put("mtu_policy","fixed").put("manual_mtu",1500);profile(x).put("mtu_policy","fixed").put("manual_mtu",1280).put("daita_enabled",true).put("dns_mode","doh3").put("dns_host","192.168.50.133").put("dns_server_name","resolver.example.test");
    if(!em.equals("wg"))hostname(a,em,"Entry-MAX.example.");if(!xm.equals("wg"))hostname(x,xm,"Exit-MAX.example.");
    File af=save(Files.createTempDirectory(dir,"entry-"),a),xf=save(Files.createTempDirectory(dir,"exit-"),x);byte[] beforeA=Files.readAllBytes(af.toPath()),beforeX=Files.readAllBytes(xf.toPath());
    AndroidMultihopController builder=new AndroidMultihopController(c,new NativeSingBoxController(c));
    if(!xm.equals("wg"))check(builder.listSupportedExitModes(xf).stream().anyMatch(m->m.id.equals(xm)),"hostname MAX exit disappeared from selector");
    check(android.net.DnsResolver.next.network==null,"multihop readiness opened unowned DNS");
    var prepared=builder.prepare(af,xf,xm,execution,em);Path folder=c.getFilesDir().toPath().resolve("layered-sessions").resolve(prepared.session.sessionId);
    JSONObject g=load(folder.resolve("sing-box.json")),metadata=load(folder.resolve("routervpn-multihop.json"));
    if(!em.equals("wg"))resolved(g,"routervpn-entry-max-",layer,em);if(!xm.equals("wg"))resolved(g,"routervpn-exit-max-",layer,xm);
    check(metadata.getString("entry_node_id").equals(a.getString("nodeProofId"))&&metadata.getString("exit_node_id").equals(x.getString("nodeProofId")),"hostname multihop lost independent proofs");
    String ec=Files.exists(folder.resolve(AndroidMultihopStartLayer.SESSION_FILE))?Files.readString(folder.resolve(AndroidMultihopStartLayer.SESSION_FILE)):null;
    String xc=Files.exists(folder.resolve(AndroidMultihopStartLayer.EXIT_SESSION_FILE))?Files.readString(folder.resolve(AndroidMultihopStartLayer.EXIT_SESSION_FILE)):null;
    var runtime=AndroidMultihopStartLayer.prepareExecution(g.toString(),metadata.toString(),ec,xc);check(runtime!=null,"hostname multihop skipped actual runtime planner");runtime.close();
    adopted(c,prepared.session,direction.equals("both")?2:1);check(Arrays.equals(beforeA,Files.readAllBytes(af.toPath()))&&Arrays.equals(beforeX,Files.readAllBytes(xf.toPath())),"hostname multihop rewrote a captured source");hops++;
   }
   for(String kind:new String[]{"tor","snowflake"}){
    reset();Context c=new Context(Files.createTempDirectory(dir,"tor-").toFile());JSONObject a=entry(mode,layer,certificate);hostname(a,mode,"Tor-Entry-MAX.example.");File source=save(Files.createTempDirectory(dir,"tor-node-"),a);byte[] before=Files.readAllBytes(source.toPath());
    var selected=tor(kind,"doh");var s=AndroidTorProfile.prepare(c,source,selected,mode);Path folder=c.getFilesDir().toPath().resolve("layered-sessions").resolve(s.sessionId);
    JSONObject g=load(folder.resolve("sing-box.json")),previous=new JSONObject(io.nekohasekai.libbox.Libbox.lastTorPredecessor);
    resolved(g,"routervpn-max-",layer,mode);capturedEntry(g,previous,a,mode,layer,certificate);
    JSONObject metadata=AndroidTorProfile.session(Files.readString(folder.resolve("sing-box.json")),Files.readString(folder.resolve(AndroidTorProfile.SESSION_FILE)),s.sessionId,s.modeId);
    check(metadata.has("predecessor_profile")&&byTag(g,"routervpn-tor-exit").getString("detour").equals("proxy"),"Tor proof did not retain complete selected MAX entry");
    adopted(c,s,1);check(Arrays.equals(before,Files.readAllBytes(source.toPath())),"Tor hostname entry changed saved source");tors++;
   }
  }
  check(direct==12&&hops==108&&tors==24,"MAX hostname launch matrix incomplete");
  System.out.println("Android MAX hostname launch paths: PASS "+direct+" single + "+hops+" multihop + "+tors+" Tor graphs, "+checks+" checks; real Java/Go, OS/JNI handles doubled");
 }
}
'''


if __name__ == '__main__':
    T.main()
