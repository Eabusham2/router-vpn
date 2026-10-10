#!/usr/bin/env python3
"""Execute shipping Android capture/staging/runtime with both node layers.

Java and Go production policies run unchanged. Only Android handles and the
remote resolver/transport boundary are doubled; native parsing is a CI gate.
"""
from pathlib import Path
import importlib.util
import os
import tempfile
ROOT=Path(__file__).resolve().parents[1]
TEST=r"""
 static int twoLayerCases;
 static JSONObject capturedLayerNode(String mode,String layer,boolean exit)throws Exception{
  JSONObject node;
  if(NativeSingBoxController.nativeWireGuardFamily(mode))node=awgBundle(exit?'b':'a');
  else if(mode.startsWith("reality-")){
   JSONObject asset=xrayBundle(mode,exit?"198.51.100.22":"192.0.2.11");
   node=bundle(exit?'b':'a');node.getJSONObject("profiles").put(mode,asset.getJSONObject("profiles").getJSONObject(mode));
   node.getJSONArray("modes").put(new JSONObject().put("id",mode).put("name",mode));
  }else node=proxyBundle(exit?'b':'a',mode,io.nekohasekai.libbox.Libbox.testCertificate(exit?"exit.example.test":"entry.example.test"));
  String host=NativeSingBoxController.nativeWireGuardFamily(mode)?"192.0.2.1":exit?(mode.startsWith("reality-")?"198.51.100.22":"198.51.100.12"):"192.0.2.11";
  JSONObject files=proxyBundle(exit?'b':'a',"shadowsocks","").getJSONObject("profiles").getJSONObject("shadowsocks");
  JSONObject graph=new JSONObject(new String(Base64.getDecoder().decode(files.getString("sing-box.json")),StandardCharsets.UTF_8));
  graph.getJSONArray("outbounds").getJSONObject(0).put("server",host).put("server_port",8388).put("method","2022-blake3-aes-256-gcm").put("password",key(exit?'z':'s'));
  files.put("sing-box.json",Base64.getEncoder().encodeToString(graph.toString().getBytes(StandardCharsets.UTF_8)));
  node.getJSONObject("profiles").put("shadowsocks",files);
  profile(node).put("start_layer",layer).put("kill_switch",true).put("home_lan_access",false).put("ipv6_mode","off");
  return node;
 }
 static void bothLayerCase(Path dir,String entryMode,String exitMode,String entryLayer,String exitLayer,String execution)throws Exception{
  Path app=Files.createTempDirectory(dir,"both-layers-");Context ctx=new Context(app.toFile());
  AndroidMultihopController builder=new AndroidMultihopController(ctx,new NativeSingBoxController(ctx));
  JSONObject entry=capturedLayerNode(entryMode,entryLayer,false),exit=capturedLayerNode(exitMode,exitLayer,true);
  profile(exit).put("dns_mode","doh3").put("dns_host","192.168.50.133").put("dns_port",5353).put("dns_server_name","adguard.example.test");
  File a=save(dir,entry),b=save(dir,exit);byte[] originalA=Files.readAllBytes(a.toPath()),originalB=Files.readAllBytes(b.toPath());
  AndroidMultihopController.Prepared prepared=builder.prepare(a,b,exitMode,execution,entryMode);
  Path session=app.resolve("layered-sessions").resolve(prepared.session.sessionId);
  String config=Files.readString(session.resolve("sing-box.json")),metadata=Files.readString(session.resolve("routervpn-multihop.json"));
  String capturedEntry=Files.exists(session.resolve(AndroidMultihopStartLayer.SESSION_FILE))?Files.readString(session.resolve(AndroidMultihopStartLayer.SESSION_FILE)):null;
  String capturedExit=Files.readString(session.resolve(AndroidMultihopStartLayer.EXIT_SESSION_FILE));
  check(capturedExit.equals(AndroidMultihopStartLayer.capture(exit)),"exit source borrowed entry credentials");
  check((capturedEntry==null)==entryLayer.equals("off"),"unrequested or missing entry source");
  if(capturedEntry!=null)check(capturedEntry.equals(AndroidMultihopStartLayer.capture(entry)),"entry source borrowed exit credentials");
  JSONObject frozen=new JSONObject(metadata);check(frozen.getString("exit_start_layer").equals(exitLayer)&&frozen.getString("exit_mode").equals(exitMode),"missing captured exit encryption identity");
  io.nekohasekai.libbox.RouterMultihop runtime=AndroidMultihopStartLayer.prepareExecution(config,metadata,capturedEntry,capturedExit);
  check(runtime!=null,"local-only execution omitted requested exit layer");
  JSONObject finalGraph=new JSONObject(runtime.config()),before=new JSONObject(config);
  JSONObject inner=byTag(finalGraph,"routervpn-execution-local"),outer=byTag(finalGraph,"routervpn-exit-start-layer");
  check(inner.getString("detour").equals("routervpn-exit-start-layer")&&outer.getString("detour").equals("entry-wg"),"exit encryption bypassed captured entry");
  check(outer.getString("password").equals(key('z'))&&outer.getString("type").equals(exitLayer.endsWith("whitening")?"routervpn-aes-xor":"shadowsocks"),"wrong exit AES credentials or engine");
  check(outer.getInt("server_port")== (exitLayer.endsWith("whitening")?8389:8388),"wrong native exit service");
  if(NativeSingBoxController.nativeWireGuardFamily(exitMode))check(inner.getJSONArray("peers").getJSONObject(0).getString("address").equals("10.77.0.1"),"WG/AWG private service not exit-encrypted");
  else if(exitMode.startsWith("reality-"))check(new JSONObject(inner.getString("config_json")).getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address").equals("10.77.0.1"),"native Xray private service not exit-encrypted");
  else check(inner.getString("server").equals("10.77.0.1"),"proxy private service not exit-encrypted");
  check(byTag(finalGraph,"routervpn-execution-server").getString("detour").equals("entry-wg"),"server candidate proof bypassed entry");
  if(capturedEntry!=null)check(byTag(finalGraph,"entry-wg").getString("detour").equals("routervpn-entry-start-layer")&&byTag(finalGraph,"routervpn-entry-start-layer").getString("password").equals(key('s')),"entry layer source lost");
  else check(!byTag(finalGraph,"entry-wg").has("detour"),"unexpected extra entry transport");
  check(jsonSame(finalGraph.getJSONObject("dns"),before.getJSONObject("dns"))&&jsonSame(finalGraph.getJSONObject("route"),before.getJSONObject("route")),"layer composition changed route or selected AdGuard DNS");
  check(jsonSame(finalGraph.getJSONArray("inbounds"),before.getJSONArray("inbounds")),"layer composition created another system capture interface");
  check(!Files.exists(session.resolve("xray.json"))&&!Files.exists(session.resolve("wg.conf"))&&!Files.exists(session.resolve("awg.conf")),"another raw backend was staged");
  for(String bad:new String[]{null,"","{}"}){
   boolean failed=false;try{AndroidMultihopStartLayer.prepareExecution(config,metadata,capturedEntry,bad);}catch(Exception expected){failed=true;}check(failed,"missing requested exit source chose a bare exit");
  }
  boolean failed=false;try{AndroidMultihopStartLayer.prepareExecution(config,metadata,capturedEntry);}catch(Exception expected){failed=true;}check(failed,"legacy entry-only factory silently omitted exit layer");
  JSONObject wrong=new JSONObject(metadata);wrong.remove("exit_start_layer");failed=false;try{AndroidMultihopStartLayer.prepareExecution(config,wrong.toString(),capturedEntry,capturedExit);}catch(Exception expected){failed=true;}check(failed,"unrequested exit layer enabled");
  runtime.close();check(Arrays.equals(originalA,Files.readAllBytes(a.toPath()))&&Arrays.equals(originalB,Files.readAllBytes(b.toPath())),"saved node configuration modified");
  String export=System.getenv("ROUTERVPN_BOTH_LAYER_FIXTURES");if(export!=null&&!export.isEmpty()){
   Path folder=Path.of(export);Files.createDirectories(folder);Files.writeString(folder.resolve(entryMode+"-"+exitMode+"-"+entryLayer+"-"+exitLayer+"-"+execution+".json"),finalGraph.toString());
  }
  twoLayerCases++;
 }
 public static void main(String[] args)throws Exception{
  Path dir=Path.of(args[0]);String[] modes={"wg","awg2-fast","awg2-strong","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp"};
  for(String entry:modes)for(String exit:modes)for(String execution:new String[]{"local","server","auto"}){
   bothLayerCase(dir,entry,exit,"off","aes-256-gcm",execution);
   bothLayerCase(dir,entry,exit,"aes-256-gcm","aes-256-gcm+xor-whitening",execution);
  }
  for(String fault:new String[]{"bad-key","wrong-node","missing","cancel"}){
   JSONObject a=capturedLayerNode("wg","aes-256-gcm",false),b=capturedLayerNode("wg","aes-256-gcm",true);
   JSONObject files=b.getJSONObject("profiles").getJSONObject("shadowsocks");
   if(fault.equals("missing"))b.getJSONObject("profiles").remove("shadowsocks");
   else if(!fault.equals("cancel")){JSONObject g=new JSONObject(new String(Base64.getDecoder().decode(files.getString("sing-box.json")),StandardCharsets.UTF_8));g.getJSONArray("outbounds").getJSONObject(0).put(fault.equals("bad-key")?"password":"server",fault.equals("bad-key")?"invalid":"192.0.2.99");files.put("sing-box.json",Base64.getEncoder().encodeToString(g.toString().getBytes(StandardCharsets.UTF_8)));}
   if(fault.equals("cancel"))io.nekohasekai.libbox.Libbox.afterEntryLayerPreflight=()->Thread.currentThread().interrupt();
   try{proxyRejected(dir,a,b,"wg","wg");}finally{io.nekohasekai.libbox.Libbox.afterEntryLayerPreflight=null;Thread.interrupted();}
  }
  check(twoLayerCases==384,"incomplete dual-layer execution matrix");
  System.out.println("Android two-node Start Layers: PASS ("+twoLayerCases+" graphs; "+checks+" checks; OS handles doubled)");
 }
}
"""
def main():
 spec=importlib.util.spec_from_file_location('layer_graph_fixture',ROOT/'android/test_android_multihop_graph.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 marker=' public static void main(String[] args)throws Exception {'
 if module.HARNESS.count(marker)!=1:raise RuntimeError('Shipping harness entry point changed')
 module.HARNESS=module.HARNESS.split(marker,1)[0]+TEST
 dep=importlib.util.spec_from_file_location('json_dep',ROOT/'deploy/test_android_multihop_pinned.py');dependency=importlib.util.module_from_spec(dep);dep.loader.exec_module(dependency)
 with tempfile.TemporaryDirectory() as tmp:
  previous=os.environ.get('ANDROID_JSON_JAR')
  try:
   os.environ['ANDROID_JSON_JAR']=str(dependency.android_json_dependency(Path(tmp),dict(os.environ)))
   module.main()
  finally:
   if previous is None:os.environ.pop('ANDROID_JSON_JAR',None)
   else:os.environ['ANDROID_JSON_JAR']=previous
if __name__=='__main__':main()
