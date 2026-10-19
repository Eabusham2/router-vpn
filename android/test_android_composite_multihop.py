#!/usr/bin/env python3
"""Run captured two-lane multihop through shipping Java and real Go compilers.

Android JSON is real; OS/FFI handles are boundary doubles. Encrypted packet and
actual APK gates remain separate. Fixtures are generated raw node assets.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('composite_max_boundary', ROOT/'android/test_android_max_multihop.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
P = M.P
prefix = P.HARNESS[:P.HARNESS.index(' static JSONObject fixtures;')]
node = P.HARNESS[P.HARNESS.index(' static JSONObject node('):P.HARNESS.index(' static JSONObject load(')]
node = node.replace('if(AndroidNativeMAXProfile.isMode(mode)){', '''if(AndroidNativeCompositeProfile.isMode(mode)){
   b=new JSONObject((entry?compositeEntry:compositeExit).toString());
   b.put("modes",new JSONArray().put(new JSONObject().put("id",mode).put("name",mode)));
  }else if(AndroidNativeMAXProfile.isMode(mode)){''', 1)
node = node.replace('if(!AndroidNativeMAXProfile.isMode(mode)){', 'if(!AndroidNativeMAXProfile.isMode(mode)&&!AndroidNativeCompositeProfile.isMode(mode)){', 1)
P.HARNESS = prefix + r'''
 static JSONObject fixtures,compositeEntry,compositeExit;
 static final String[] COMPOSITE={"ss-v2ray","split","max"};
 static final String[] ALL={"wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg","ss-v2ray","split","max"};
''' + node + r'''
 static JSONObject load(Path path)throws Exception{return new JSONObject(Files.readString(path));}
 static String layerFile(Path path)throws Exception{return Files.exists(path)?Files.readString(path):null;}
 static void complete(JSONObject graph,JSONObject bundle,String mode,String tag,String prefix,boolean entry,String layer)throws Exception{
  JSONObject owner=byTag(graph,tag),tcp=byTag(graph,prefix+"tcp"),udp=byTag(graph,prefix+"udp");
  check(owner.length()==6&&owner.getString("type").equals("routervpn-composite")&&owner.getString("mode").equals(mode),"composite raw mode downgraded");
  check(owner.getString("node_id").equals(bundle.getString("nodeProofId")),"composite borrowed another node identity");
  check(owner.getString("tcp").equals(prefix+"tcp")&&owner.getString("udp").equals(prefix+"udp"),"missing independent network lane");
  check(tcp.getString("type").equals(mode.equals("ss-v2ray")?"shadowsocks":"routervpn-xray")&&udp.getString("type").equals("hysteria2"),"composite replaced encryption");
  JSONObject original=new JSONObject(AndroidNativeCompositeProfile.compile(bundle,bundle.getJSONObject("profiles").getJSONObject(mode),mode));
  for(String network:new String[]{"tcp","udp"}){
   JSONObject actual=new JSONObject(byTag(graph,prefix+network).toString()),expected=new JSONObject(byTag(original,"routervpn-composite-"+network).toString());
   actual.remove("tag");actual.remove("detour");expected.remove("tag");expected.remove("detour");
   check(io.nekohasekai.libbox.Libbox.testSameJSON(actual.toString(),expected.toString()),"composite changed a captured lane key, TLS or obfuscation");
  }
  check(!udp.getJSONObject("tls").has("certificate_path")&&udp.getJSONObject("tls").has("certificate"),"UDP trust escaped its captured node");
  if(!layer.equals("off")){
   check(tcp.getString("detour").equals(prefix+"start")&&udp.getString("detour").equals(prefix+"start"),"both lanes must traverse the requested AES layer");
   JSONObject outer=byTag(graph,prefix+"start");
   check(outer.getString("type").equals(layer.equals("aes-256-gcm")?"shadowsocks":"routervpn-aes-xor"),"composite changed authenticated outer layer");
   check(entry?!outer.has("detour"):outer.getString("detour").equals("entry-wg"),"composite outer layer bypasses entry");
  }else for(JSONObject lane:new JSONObject[]{tcp,udp})check(entry?!lane.has("detour"):lane.getString("detour").equals("entry-wg"),"composite lane bypasses entry");
 }
 interface Change{void run(JSONObject source)throws Exception;}
 static void rejected(Path dir,String mode,boolean entry,Change mutation,String certificate)throws Exception{
  JSONObject a=node(entry?mode:"wg",true,"off",certificate),b=node(entry?"wg":mode,false,"off",certificate);mutation.run(entry?a:b);
  File af=save(dir,a),bf=save(dir,b);Path app=Files.createTempDirectory(dir,"reject-");Context context=new Context(app.toFile());
  byte[] beforeA=Files.readAllBytes(af.toPath()),beforeB=Files.readAllBytes(bf.toPath());
  boolean refused=false;try{new AndroidMultihopController(context,new NativeSingBoxController(context)).prepare(af,bf,entry?"wg":mode,"auto",entry?mode:"wg");}catch(Exception expected){refused=true;}
  check(refused&&sessions(app)==0,"invalid composite was staged");
  check(Arrays.equals(beforeA,Files.readAllBytes(af.toPath()))&&Arrays.equals(beforeB,Files.readAllBytes(bf.toPath())),"rejection changed stored node assets");
 }
 public static void main(String[] args)throws Exception{
  Path dir=Path.of(args[0]);fixtures=load(Path.of(System.getenv("ROUTERVPN_MAX_MULTIHOP_FIXTURES")));
  compositeEntry=load(Path.of(System.getenv("ROUTERVPN_COMPOSITE_ENTRY")));compositeExit=load(Path.of(System.getenv("ROUTERVPN_COMPOSITE_EXIT")));
  String certificate=io.nekohasekai.libbox.Libbox.testCertificate("exit.example.test");int graphs=0;
  String[][] layers={{"off","off"},{"aes-256-gcm","aes-256-gcm+xor-whitening"},{"aes-256-gcm+xor-whitening","aes-256-gcm"}};
  for(String em:ALL)for(String xm:ALL){
   if(!AndroidNativeCompositeProfile.isMode(em)&&!AndroidNativeCompositeProfile.isMode(xm))continue;
   for(String execution:new String[]{"local","server","auto"})for(String[] layer:layers){
    JSONObject a=node(em,true,layer[0],certificate),b=node(xm,false,layer[1],certificate);
    boolean packet=NativeSingBoxController.nativeWireGuardFamily(em)||NativeSingBoxController.nativePQFamily(em)||AndroidNativeMAXProfile.isMode(em);
    profile(a).put("mtu_policy","fixed").put("manual_mtu",packet?1500:1280);
    profile(b).put("mtu_policy","fixed").put("manual_mtu",1280).put("dns_mode","doh3").put("dns_host","192.168.50.133").put("dns_server_name","resolver.example.test");
    File af=save(dir,a),bf=save(dir,b);byte[] beforeA=Files.readAllBytes(af.toPath()),beforeB=Files.readAllBytes(bf.toPath());
    Path app=Files.createTempDirectory(dir,"graph-");Context context=new Context(app.toFile());
    AndroidMultihopController owner=new AndroidMultihopController(context,new NativeSingBoxController(context));
    check(NativeSingBoxController.nativeMultihopEntry(em),"captured entry absent from selector");
    if(AndroidNativeCompositeProfile.isMode(xm))check(owner.listSupportedExitModes(bf).stream().anyMatch(m->m.id.equals(xm)),"valid composite absent from exit picker");
    AndroidMultihopController.Prepared prepared=owner.prepare(af,bf,xm,execution,em);
    Path staged=app.resolve("layered-sessions").resolve(prepared.session.sessionId);
    JSONObject graph=load(staged.resolve("sing-box.json")),meta=load(staged.resolve("routervpn-multihop.json"));
    check(meta.getString("entry_mode").equals(em)&&meta.getString("exit_mode").equals(xm)&&meta.getString("execution").equals(execution),"graph relabeled a captured mode");
    check(graph.getJSONArray("inbounds").length()==3&&graph.getJSONArray("inbounds").getJSONObject(0).getInt("mtu")==1280,"composite changed the single shared TUN");
    check(Files.exists(staged.resolve(AndroidKillSwitchPolicy.SESSION_MARKER)),"strict kill switch staging missing");
    String ec=layerFile(staged.resolve(AndroidMultihopStartLayer.SESSION_FILE)),xc=layerFile(staged.resolve(AndroidMultihopStartLayer.EXIT_SESSION_FILE));
    if(AndroidNativeCompositeProfile.isMode(em)){check(ec==null,"duplicate entry layer staged");complete(graph,a,em,"entry-wg","routervpn-entry-composite-",true,layer[0]);}
    if(AndroidNativeCompositeProfile.isMode(xm)){check(xc==null,"duplicate exit layer staged");complete(graph,b,xm,"proxy","routervpn-exit-composite-",false,layer[1]);}
    for(String file:new String[]{"xray.json","sslocal.json","run.sh","chain.env"})check(!Files.exists(staged.resolve(file)),"unowned executable helper staged");
    io.nekohasekai.libbox.RouterMultihop runtime=AndroidMultihopStartLayer.prepareExecution(graph.toString(),meta.toString(),ec,xc);
    check(runtime!=null,"Local omitted complete captured graph validation");
    JSONObject planned=new JSONObject(runtime.config());
    if(AndroidNativeCompositeProfile.isMode(em))complete(planned,a,em,"entry-wg","routervpn-entry-composite-",true,layer[0]);
    if(AndroidNativeCompositeProfile.isMode(xm))complete(planned,b,xm,"routervpn-execution-local","routervpn-exit-composite-",false,layer[1]);
    check(byTag(planned,"proxy").getString("type").equals("selector"),"comparison lost its owned selector");
    JSONArray dns=planned.getJSONObject("dns").getJSONArray("servers");JSONObject selected=dns.getJSONObject(dns.length()-1);
    check(selected.getString("server").equals("192.168.50.133")&&selected.getString("type").equals("h3")&&selected.getString("detour").equals("proxy"),"composite replaced selected AdGuard DNS");
    String output=System.getenv("ROUTERVPN_ANDROID_COMPOSITE_GRAPHS");
    if(output!=null){
     Path target=Path.of(output).resolve(em+"-"+xm+"-"+layer[0]+"-"+layer[1]+"-"+execution);Files.createDirectories(target);
     Files.writeString(target.resolve("planned.json"),runtime.config());
     if(xm.equals("hysteria2"))Files.copy(staged.resolve("trust.pem"),target.resolve("trust.pem"));
    }
    runtime.close();graphs++;
    check(Arrays.equals(beforeA,Files.readAllBytes(af.toPath()))&&Arrays.equals(beforeB,Files.readAllBytes(bf.toPath())),"composition modified stored private assets");
   }
  }
  check(graphs==837,"incomplete composite host matrix");
  for(String mode:COMPOSITE)for(boolean entry:new boolean[]{true,false}){
   rejected(dir,mode,entry,b->b.put("selectedRouterID","missing"),certificate);
   rejected(dir,mode,entry,b->b.getJSONArray("routerProfiles").put(new JSONObject(profile(b).toString())),certificate);
   rejected(dir,mode,entry,b->b.getJSONObject("profiles").getJSONObject(mode).remove(mode.equals("ss-v2ray")?"sslocal.json":"xray.json"),certificate);
   rejected(dir,mode,entry,b->b.getJSONObject("profiles").getJSONObject(mode).put("run.sh",enc("not executable")),certificate);
   rejected(dir,mode,entry,b->profile(b).put("start_layer","xor"),certificate);
  }
  System.out.println("Android composite multihop: "+graphs+" graphs, "+checks+" checks passed (shipping Java, real Go/Android JSON; OS handles doubled)");
 }
}
'''
# Structural comparison is performed in the real Go JSON parser, retaining all
# nested credentials and certificate bytes while ignoring object key order.
P.GO = P.GO.replace('case "xray-policy":', '''case "same-json":
  var a,b any;err=json.Unmarshal([]byte(r.Config),&a);if err==nil{err=json.Unmarshal([]byte(r.Policy),&b)}
  if err==nil{aBytes,_:=json.Marshal(a);bBytes,_:=json.Marshal(b);value=fmt.Sprint(string(aBytes)==string(bBytes))}
 case "xray-policy":''', 1)
key = 'io/nekohasekai/libbox/Libbox.java'
P.M.STUBS[key] = P.M.STUBS[key].replace(' public static String routerMAXMultihopBase(', ' public static boolean testSameJSON(String a,String b)throws Exception{return call("same-json",a,b).equals("true");}\n public static String routerMAXMultihopBase(', 1)


def main():
    with tempfile.TemporaryDirectory(prefix='routervpn-composite-host-') as tmp:
        folder = Path(tmp); generator = folder/'assets'
        subprocess.run(['go', 'build', '-o', str(generator), './deploy/testfixtures/composite'], cwd=ROOT, check=True, timeout=90)
        names = {'ROUTERVPN_COMPOSITE_ENTRY': [], 'ROUTERVPN_COMPOSITE_EXIT': ['--exits']}
        old = {key: os.environ.get(key) for key in names}
        try:
            for key, args in names.items():
                path = folder/(key+'.json')
                with path.open('wb') as output: subprocess.run([str(generator), *args], stdout=output, check=True, timeout=30)
                os.environ[key] = str(path)
            M.main()
        finally:
            for key, value in old.items():
                if value is None: os.environ.pop(key, None)
                else: os.environ[key] = value


if __name__ == '__main__': main()
