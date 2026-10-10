#!/usr/bin/env python3
"""Run shipping Android Xray-exit consumers with the existing real Go RPC fixture.

Only the test entry point changes. Production Java, native compiler/policy code
and the Android JSON implementation are unchanged by the harness. Android OS
handles remain doubles; native parser and device acceptance are separate gates.
"""
from pathlib import Path
import importlib.util
import os
import tempfile

ROOT = Path(__file__).resolve().parents[1]

TEST = r'''
 static int exitCases;
 static JSONObject capturedXrayExit(String mode)throws Exception {
  JSONObject raw=xrayBundle(mode,"198.51.100.22"),node=bundle('b');
  node.getJSONObject("profiles").put(mode,raw.getJSONObject("profiles").getJSONObject(mode));
  node.getJSONArray("modes").put(new JSONObject().put("id",mode).put("name",mode));
  profile(node).put("mtu_policy","auto").put("home_lan_access",false).put("ipv6_mode","off");
  return node;
 }
 static void xrayExitCase(Path dir,String phase,String entryMode,String exitMode,String execution,String dns)throws Exception {
  Path app=Files.createTempDirectory(dir,"native-exit-");Context context=new Context(app.toFile());
  AndroidMultihopController builder=new AndroidMultihopController(context,new NativeSingBoxController(context));
  JSONObject a=NativeSingBoxController.nativeWireGuardFamily(entryMode)?awgBundle('a'):
   entryMode.startsWith("reality-")?xrayBundle(entryMode,"192.0.2.11"):
   proxyBundle('a',entryMode,io.nekohasekai.libbox.Libbox.testCertificate("entry.example.test"));
  JSONObject b=capturedXrayExit(exitMode);
  profile(a).put("mtu_policy","fixed").put("manual_mtu",1500).put("kill_switch",true);
  profile(b).put("dns_mode",dns);
  if(!dns.equals("home"))profile(b).put("dns_host","192.168.50.133").put("dns_protocol","tcp")
   .put("dns_server_name","resolver.example.test").put("dns_port",5353).put("dns_path","/dns-query");
  File entry=save(dir,a),exit=save(dir,b);byte[] beforeA=Files.readAllBytes(entry.toPath()),beforeB=Files.readAllBytes(exit.toPath());
  int resolutions=io.nekohasekai.libbox.Libbox.xrayResolutions;
  check(builder.listSupportedExitModes(exit).stream().anyMatch(x->x.id.equals(exitMode)),"valid native exit not offered by actual picker source");
  check(sessions(app)==0&&resolutions==io.nekohasekai.libbox.Libbox.xrayResolutions,"exit readiness staged a session or performed bootstrap");
  AndroidMultihopController.Prepared ready=builder.prepare(entry,exit,exitMode,execution,entryMode);
  Path session=app.resolve("layered-sessions").resolve(ready.session.sessionId);
  JSONObject graph=new JSONObject(Files.readString(session.resolve("sing-box.json")));
  JSONObject metadata=new JSONObject(Files.readString(session.resolve("routervpn-multihop.json")));
  JSONObject last=byTag(graph,"proxy"),first=byTag(graph,"entry-wg");
  String original=new String(Base64.getDecoder().decode(b.getJSONObject("profiles").getJSONObject(exitMode).getString("xray.json")),StandardCharsets.UTF_8);
  check(ready.exitMode.equals(exitMode)&&ready.session.modeId.equals("multihop-"+exitMode),"selected exit mode was relabeled");
  check(last.getString("type").equals("routervpn-xray")&&last.getString("mode").equals(exitMode)&&last.getString("config_json").equals(original),"native exit authentication, PQ or transport changed");
  check(last.length()==5&&last.getString("detour").equals("entry-wg")&&!first.has("detour"),"exit acquired an unowned or direct physical dialer");
  check(byTag(graph,"entry-private").getString("detour").equals("entry-wg"),"entry proof was moved to exit");
  check(graph.getJSONArray("endpoints").length()==(NativeSingBoxController.nativeWireGuardFamily(entryMode)?1:0),"native exit started a second packet owner");
  JSONArray in=graph.getJSONArray("inbounds");check(in.length()==3&&in.getJSONObject(0).getString("type").equals("tun"),"one system capture path and two proof lanes required");
  boolean v4=false,v6=false;JSONArray addresses=in.getJSONObject(0).getJSONArray("address");
  for(int i=0;i<addresses.length();i++){String address=addresses.getString(i);if(address.contains(":"))v6=true;else v4=true;}
  check(v4&&v6,"IPv6-Off lost physical IPv6 capture");
  check(in.getJSONObject(1).getInt("listen_port")==1098&&in.getJSONObject(2).getInt("listen_port")==1099,"hop proof lanes collapsed");
  int expectedMTU=NativeSingBoxController.nativeWireGuardFamily(entryMode)?1280:1500;
  check(in.getJSONObject(0).getInt("mtu")==expectedMTU,"proxy fixed MTU or independent packet-entry MTU lost");
  JSONArray resolvers=graph.getJSONObject("dns").getJSONArray("servers");
  String kind=dns.equals("home")?"udp":dns.equals("custom")?"tcp":dns.equals("dot")?"tls":dns.equals("doh")?"https":"h3";
  for(int i=0;i<resolvers.length();i++){
   JSONObject resolver=resolvers.getJSONObject(i);
   check(resolver.getString("detour").equals("proxy")&&resolver.getString("server").equals("192.168.50.133"),"selected AdGuard DNS left exit");
  }
  JSONObject resolver=resolvers.getJSONObject(resolvers.length()-1);
  check(resolver.getString("type").equals(kind),"selected DNS transport was replaced");
  if(!dns.equals("home"))check(resolver.getInt("server_port")==5353,"custom DNS port lost");
  check(metadata.getString("entry_mode").equals(entryMode)&&metadata.getString("exit_mode").equals(exitMode)&&metadata.getString("execution").equals(execution),"frozen execution identity drifted");
  check(metadata.getString("entry_node_id").equals(a.getString("nodeProofId"))&&metadata.getString("exit_node_id").equals(b.getString("nodeProofId")),"paired node proofs collapsed");
  check(!Files.exists(session.resolve("xray.json"))&&!Files.exists(session.resolve("wg.conf"))&&!Files.exists(session.resolve("awg.conf")),"another backend was staged");
  check(Files.exists(session.resolve(AndroidKillSwitchPolicy.SESSION_MARKER)),"strict route policy lost");
  JSONObject planned=new JSONObject(io.nekohasekai.libbox.Libbox.testPlan(graph.toString(),metadata.toString()));
  check(byTag(planned,"routervpn-execution-local").getString("config_json").equals(original),"comparison rewrote local native exit");
  check(byTag(planned,"routervpn-execution-server").getString("detour").equals("entry-wg"),"server candidate bypassed entry");
  check(Arrays.equals(beforeA,Files.readAllBytes(entry.toPath()))&&Arrays.equals(beforeB,Files.readAllBytes(exit.toPath())),"source bundle changed during native preparation");
  String fixtures=System.getenv("ROUTERVPN_ANDROID_XRAY_EXIT_FIXTURES");
  if(fixtures!=null&&!fixtures.isEmpty()){
   Path folder=Path.of(fixtures).resolve(phase+"-"+entryMode+"-"+exitMode+"-"+execution+"-"+dns);Files.createDirectories(folder);
   Files.writeString(folder.resolve("sing-box.json"),graph.toString());Files.writeString(folder.resolve("planned.json"),planned.toString());
  }
  exitCases++;
 }
 static void rejectXrayExit(Path dir,String mode,Mutation change)throws Exception {
  Path app=Files.createTempDirectory(dir,"bad-native-exit-");Context context=new Context(app.toFile());
  AndroidMultihopController builder=new AndroidMultihopController(context,new NativeSingBoxController(context));
  JSONObject b=capturedXrayExit(mode);change.apply(b);File exit=save(dir,b);boolean failed=false;
  try{builder.prepare(save(dir,bundle('a')),exit,mode,"auto","wg");}catch(Exception expected){failed=true;}
  check(failed&&sessions(app)==0,"invalid native exit staged state");
  check(builder.listSupportedExitModes(exit).stream().noneMatch(x->x.id.equals(mode)),"invalid native exit remained available");
 }
 public static void main(String[] args)throws Exception {
  Path dir=Path.of(args[0]);
  String[] entries={"wg","awg2-fast","awg2-strong","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp"};
  String[] exits={"reality-vision","reality-pq-vision","reality-xhttp"};
  for(String entry:entries)for(String exit:exits)for(String execution:new String[]{"local","server","auto"})xrayExitCase(dir,"matrix",entry,exit,execution,"home");
  for(String exit:exits)for(String dns:new String[]{"home","custom","dot","doh","doh3"})xrayExitCase(dir,"dns","shadowsocks",exit,"auto",dns);
  for(String mode:exits){
   check(normalizeMultiMode(mode).equals(mode),"saved connection profile dropped exact Xray exit");
   rejectXrayExit(dir,mode,b->b.getJSONObject("profiles").getJSONObject(mode).put("extra.conf","e30="));
   rejectXrayExit(dir,mode,b->b.getJSONObject("profiles").getJSONObject(mode).put("xray.json","e30="));
   Path app=Files.createTempDirectory(dir,"cancel-native-exit-");Context ctx=new Context(app.toFile());AndroidMultihopController builder=new AndroidMultihopController(ctx,new NativeSingBoxController(ctx));
   File a=save(dir,bundle('a')),b=save(dir,capturedXrayExit(mode));boolean failed=false;
   io.nekohasekai.libbox.Libbox.afterProxyEntryCompilation=()->Thread.currentThread().interrupt();
   try{builder.prepare(a,b,mode,"local","wg");}catch(Exception expected){failed=true;}
   finally{io.nekohasekai.libbox.Libbox.afterProxyEntryCompilation=null;Thread.interrupted();}
   check(failed&&sessions(app)==0,"cancelled exit compiler staged a new owner");
  }
  for(String mode:new String[]{"max","split","tor","unregistered"}){boolean failed=false;try{normalizeMultiMode(mode);}catch(Exception expected){failed=true;}check(failed,"unsupported exit silently relabeled");}
  check(exitCases==87,"native exit matrix was not fully exercised");
  System.out.println("Android native Xray exits: PASS ("+exitCases+" graphs; "+checks+" executable checks; Android handles doubled)");
 }
}
'''


def main():
    spec = importlib.util.spec_from_file_location('android_graph_fixture', ROOT/'android/test_android_multihop_graph.py')
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    marker = ' public static void main(String[] args)throws Exception {'
    if fixture.HARNESS.count(marker) != 1:
        raise ValueError('The executable Android test entry-point boundary changed')
    profile_source = (fixture.JAVA/'AndroidConnectionProfileStore.java').read_text()
    normalizers = [line for line in profile_source.splitlines() if line.startswith('    private static String normalizeMultiMode(')]
    if len(normalizers) != 1 or not normalizers[0].rstrip().endswith('}'):
        raise ValueError('Saved-mode test must execute the complete shipping normalizer')
    fixture.HARNESS = fixture.HARNESS.split(marker, 1)[0] + normalizers[0] + '\n' + TEST
    # Use the production native-gate helper to choose its bounded pinned JSON
    # dependency on both Linux and macOS; never substitute a JSON implementation.
    dep_spec = importlib.util.spec_from_file_location('android_graph_dependency', ROOT/'deploy/test_android_multihop_pinned.py')
    dependency = importlib.util.module_from_spec(dep_spec)
    dep_spec.loader.exec_module(dependency)
    with tempfile.TemporaryDirectory(prefix='router-xray-json-') as directory:
        original = os.environ.get('ANDROID_JSON_JAR')
        try:
            os.environ['ANDROID_JSON_JAR'] = str(dependency.android_json_dependency(Path(directory), dict(os.environ)))
            fixture.main()
        finally:
            if original is None:
                os.environ.pop('ANDROID_JSON_JAR', None)
            else:
                os.environ['ANDROID_JSON_JAR'] = original


if __name__ == '__main__':
    main()
