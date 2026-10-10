#!/usr/bin/env python3
"""Execute actual Android entry-layer capture, staging and factory decisions.

Uses production Java and shared Go policy. OS handles are doubles; generated
native configurations are separately parsed by the pinned-engine gate.
"""
from pathlib import Path
import importlib.util
import os
import tempfile
ROOT=Path(__file__).resolve().parents[1]
TEST=r"""
 static int startLayerCases;
 static JSONObject layeredEntry(String mode,String layer)throws Exception {
  JSONObject entry=NativeSingBoxController.nativeWireGuardFamily(mode)?awgBundle('a'):
   mode.startsWith("reality-")?xrayBundle(mode,"192.0.2.11"):
   proxyBundle('a',mode,io.nekohasekai.libbox.Libbox.testCertificate("entry.example.test"));
  String host=NativeSingBoxController.nativeWireGuardFamily(mode)?"192.0.2.1":"192.0.2.11";
  JSONObject aesBundle=proxyBundle('a',"shadowsocks","");
  JSONObject aesFiles=aesBundle.getJSONObject("profiles").getJSONObject("shadowsocks");
  JSONObject aes=new JSONObject(new String(Base64.getDecoder().decode(aesFiles.getString("sing-box.json")),StandardCharsets.UTF_8));
  aes.getJSONArray("outbounds").getJSONObject(0).put("method","2022-blake3-aes-256-gcm").put("password",key('s')).put("server",host).put("server_port",8388);
  aesFiles.put("sing-box.json",Base64.getEncoder().encodeToString(aes.toString().getBytes(StandardCharsets.UTF_8)));
  entry.getJSONObject("profiles").put("shadowsocks",aesFiles);
  profile(entry).put("start_layer",layer).put("home_lan_access",false).put("ipv6_mode","off").put("kill_switch",true);
  return entry;
 }
 static void entryLayerCase(Path dir,String mode,String layer,String execution)throws Exception{
  Path app=Files.createTempDirectory(dir,"entry-layer-");Context context=new Context(app.toFile());
  AndroidMultihopController builder=new AndroidMultihopController(context,new NativeSingBoxController(context));
  JSONObject entry=layeredEntry(mode,layer),exit=awgBundle('b');
  profile(exit).put("dns_mode","doh3").put("dns_host","192.168.50.133").put("dns_port",5353).put("dns_server_name","dns.example.test");
  File a=save(dir,entry),b=save(dir,exit);byte[] beforeA=Files.readAllBytes(a.toPath()),beforeB=Files.readAllBytes(b.toPath());
  AndroidMultihopController.Prepared ready=builder.prepare(a,b,"wg",execution,mode);
  Path session=app.resolve("layered-sessions").resolve(ready.session.sessionId);
  String config=Files.readString(session.resolve("sing-box.json")),metadata=Files.readString(session.resolve("routervpn-multihop.json"));
  String captured=Files.readString(session.resolve(AndroidMultihopStartLayer.SESSION_FILE));
  check(captured.equals(AndroidMultihopStartLayer.capture(entry)),"saved entry layer borrowed another node source");
  JSONObject selected=new JSONObject(metadata);check(selected.getString("entry_start_layer").equals(layer),"requested layer not marked in frozen metadata");
  check(!byTag(new JSONObject(config),"entry-wg").has("detour"),"preflight mutated bare staged graph");
  io.nekohasekai.libbox.RouterMultihop runtime=AndroidMultihopStartLayer.prepareExecution(config,metadata,captured);
  check(runtime!=null,"Local mode silently skipped authenticated entry layer");
  JSONObject graph=new JSONObject(runtime.config()),inner=byTag(graph,"entry-wg"),outer=byTag(graph,"routervpn-entry-start-layer");
  check(inner.getString("detour").equals("routervpn-entry-start-layer")&&!outer.has("detour"),"wrong physical encryption ownership");
  check(outer.getString("password").equals(key('s'))&&outer.getString("server").equals(NativeSingBoxController.nativeWireGuardFamily(mode)?"192.0.2.1":"192.0.2.11"),"outer node or credentials changed");
  check(outer.getString("type").equals(layer.endsWith("whitening")?"routervpn-aes-xor":"shadowsocks")&&outer.getInt("server_port")== (layer.endsWith("whitening")?8389:8388),"wrong native AES transport");
  if(NativeSingBoxController.nativeWireGuardFamily(mode))check(inner.getJSONArray("peers").getJSONObject(0).getString("address").equals("10.77.0.1"),"packet entry does not use encrypted private service");
  else if(mode.startsWith("reality-"))check(new JSONObject(inner.getString("config_json")).getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address").equals("10.77.0.1"),"native Xray inner endpoint not private");
  else check(inner.getString("server").equals("10.77.0.1"),"proxy inner endpoint not private");
  check(byTag(graph,"routervpn-execution-local").getString("detour").equals("entry-wg")&&byTag(graph,"routervpn-execution-server").getString("detour").equals("entry-wg"),"candidate bypasses entry layer");
  check(jsonSame(graph.getJSONObject("dns"),new JSONObject(config).getJSONObject("dns")),"entry layer changed exit DNS");
  check(jsonSame(graph.getJSONArray("inbounds"),new JSONObject(config).getJSONArray("inbounds")),"entry layer added a second system VPN or proof listener");
  for(String missing:new String[]{null,"","{}"}){boolean fail=false;try{AndroidMultihopStartLayer.prepareExecution(config,metadata,missing);}catch(Exception expected){fail=true;}check(fail,"missing/malformed requested layer silently ignored");}
  JSONObject old=new JSONObject(metadata);old.remove("entry_start_layer");boolean rejected=false;try{AndroidMultihopStartLayer.prepareExecution(config,old.toString(),captured);}catch(Exception expected){rejected=true;}check(rejected,"unrequested private layer enabled");
  io.nekohasekai.libbox.RouterMultihop ordinary=AndroidMultihopStartLayer.prepareExecution(config,old.toString(),null);
  check((ordinary==null)==execution.equals("local"),"ordinary local/server behavior changed");if(ordinary!=null)ordinary.close();runtime.close();
  check(Arrays.equals(beforeA,Files.readAllBytes(a.toPath()))&&Arrays.equals(beforeB,Files.readAllBytes(b.toPath())),"capturing entry layer changed saved node secrets");
  String target=System.getenv("ROUTERVPN_ENTRY_LAYER_FIXTURES");if(target!=null&&!target.isEmpty()){
   Path folder=Path.of(target);Files.createDirectories(folder);Files.writeString(folder.resolve(mode+"-"+(layer.endsWith("whitening")?"aes-xor":"aes")+"-"+execution+".json"),graph.toString());
  }
  startLayerCases++;
 }
 public static void main(String[] args)throws Exception{
  Path dir=Path.of(args[0]);
  for(String mode:new String[]{"wg","awg2-fast","awg2-strong","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp"})
   for(String layer:new String[]{"aes-256-gcm","aes-256-gcm+xor-whitening"})for(String execution:new String[]{"local","server","auto"})entryLayerCase(dir,mode,layer,execution);
  for(String fault:new String[]{"wrong-node","bad-key","missing","too-large","cancel"}){
   JSONObject a=layeredEntry("wg","aes-256-gcm"),b=awgBundle('b');
   JSONObject profileFiles=a.getJSONObject("profiles").getJSONObject("shadowsocks");
   if(fault.equals("missing"))a.getJSONObject("profiles").remove("shadowsocks");
   else if(fault.equals("too-large"))profileFiles.put("extra","x".repeat(16384));
   else if(!fault.equals("cancel")){
    JSONObject g=new JSONObject(new String(Base64.getDecoder().decode(profileFiles.getString("sing-box.json")),StandardCharsets.UTF_8));
    g.getJSONArray("outbounds").getJSONObject(0).put(fault.equals("wrong-node")?"server":"password",fault.equals("wrong-node")?"192.0.2.99":"wrong-key");
    profileFiles.put("sing-box.json",Base64.getEncoder().encodeToString(g.toString().getBytes(StandardCharsets.UTF_8)));
   }
   if(fault.equals("cancel"))io.nekohasekai.libbox.Libbox.afterEntryLayerPreflight=()->Thread.currentThread().interrupt();
   try{proxyRejected(dir,a,b,"wg","wg");}finally{io.nekohasekai.libbox.Libbox.afterEntryLayerPreflight=null;Thread.interrupted();}
  }
  JSONObject a=layeredEntry("wg","aes-256-gcm"),b=awgBundle('b');profile(b).put("start_layer","aes-256-gcm");proxyRejected(dir,a,b,"wg","wg");
  check(startLayerCases==48,"incomplete entry layer execution matrix");
  System.out.println("Android entry Start Layers: PASS (48 graphs; "+checks+" checks; production Java/Go with OS handles doubled)");
 }
}
"""
def main():
    spec=importlib.util.spec_from_file_location('graph_fixture',ROOT/'android/test_android_multihop_graph.py')
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    marker=' public static void main(String[] args)throws Exception {'
    assert fixture.HARNESS.count(marker)==1
    fixture.HARNESS=fixture.HARNESS.split(marker,1)[0]+TEST
    dep_spec=importlib.util.spec_from_file_location('android_json',ROOT/'deploy/test_android_multihop_pinned.py')
    dependency=importlib.util.module_from_spec(dep_spec);dep_spec.loader.exec_module(dependency)
    with tempfile.TemporaryDirectory() as temp:
        previous=os.environ.get('ANDROID_JSON_JAR')
        try:
            os.environ['ANDROID_JSON_JAR']=str(dependency.android_json_dependency(Path(temp),dict(os.environ)))
            fixture.main()
        finally:
            if previous is None:os.environ.pop('ANDROID_JSON_JAR',None)
            else:os.environ['ANDROID_JSON_JAR']=previous
    runtime=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java').read_text()
    for marker in ['AndroidMultihopStartLayer.prepareExecution(config,metadata,captured)','readLimited(entryLayerFile,AndroidMultihopStartLayer.MAX_BYTES)','!entryLayerFile.getParentFile().equals(session)']:
        assert marker in runtime,marker
    print('Actual service uses the tested factory decision; no separate VPN or local relay is created.')
if __name__=='__main__':main()
