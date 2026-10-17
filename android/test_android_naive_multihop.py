#!/usr/bin/env python3
"""Execute shipping Android Naive selection and complete multihop assembly.

Java and the shared Go compilers are real; Android handles and Libbox startup
are explicit doubles. Native encrypted traffic and APK execution remain separate
CI gates. Certificates/credentials are disposable and no remote node is contacted.
"""
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('naive_host_policy', ROOT/'android/test_android_pq_selection.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
P.HARNESS = r'''package com.eabusham.routervpn;
import android.content.Context;import org.json.*;import java.io.*;import java.nio.file.*;
import java.nio.charset.StandardCharsets;import java.util.*;
import static com.eabusham.routervpn.MultihopGraphHarness.*;
public final class PQSelectionHarness {
 static int graphs;
 static final String[] MODES={"wg","awg2-fast","awg2-strong","shadowsocks","hysteria2","naive-h2","naive-h3"};
 static String encoded(String value){return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));}
 static JSONObject readConfig(JSONObject assets)throws Exception{return new JSONObject(new String(Base64.getDecoder().decode(assets.getString("sing-box.json")),StandardCharsets.UTF_8));}
 static void saveConfig(JSONObject assets,JSONObject graph)throws Exception{assets.put("sing-box.json",encoded(graph.toString()));}
 static JSONObject source(char node,String mode,String cert,String layer)throws Exception{
  JSONObject b=NativeSingBoxController.nativeWireGuardFamily(mode)?awgBundle(node):proxyBundle(node,mode.startsWith("naive-")?"hysteria2":mode,cert);
  String host=NativeSingBoxController.nativeWireGuardFamily(mode)?(node=='a'?"192.0.2.1":"192.0.2.2"):(node=='a'?"192.0.2.11":"198.51.100.12");
  if(NativeSingBoxController.nativeNaiveFamily(mode)){
   JSONObject assets=new JSONObject(b.getJSONObject("profiles").getJSONObject("hysteria2").toString()),g=readConfig(assets),out=byTag(g,"proxy");
   out.put("type","naive").put("quic",mode.equals("naive-h3")).put("username",node=='a'?"entry-only-user":"exit-only-user")
      .put("udp_over_tcp",new JSONObject().put("enabled",true).put("version",2));
   saveConfig(assets,g);b.getJSONObject("profiles").put(mode,assets);b.getJSONArray("modes").put(new JSONObject().put("id",mode).put("name",mode));
  }
  // The generated AES service shares the selected node's public address. Its
  // own full wrapper is retained when it is also the selected Shadowsocks hop.
  JSONObject aes=proxyBundle(node,"shadowsocks","").getJSONObject("profiles").getJSONObject("shadowsocks"),ag=readConfig(aes);
  byTag(ag,"proxy").put("method","2022-blake3-aes-256-gcm").put("password",key(node=='a'?'s':'t')).put("server",host).put("server_port",8388);
  saveConfig(aes,ag);b.getJSONObject("profiles").put("shadowsocks",aes);
  profile(b).put("node_kind","router-vpn").put("node_proof_id",b.getString("nodeProofId")).put("start_layer",layer)
   .put("mtu_policy","fixed").put("manual_mtu",node=='a'&&NativeSingBoxController.nativeWireGuardFamily(mode)?1500:1280)
   .put("home_lan_access",false).put("ipv6_mode","off").put("kill_switch",true);
  return b;
 }
 static void verify(Path dir,String entryMode,String exitMode,String execution,String el,String xl,String dns,String ec,String xc)throws Exception{
  Path app=Files.createTempDirectory(dir,"naive-graph-");Context context=new Context(app.toFile());NativeSingBoxController controller=new NativeSingBoxController(context);
  AndroidMultihopController owner=new AndroidMultihopController(context,controller);
  JSONObject a=source('a',entryMode,ec,el),b=source('b',exitMode,xc,xl),p=profile(b);
  if(!dns.equals("home"))p.put("dns_mode",dns.equals("hostname")?"doh":dns).put("dns_host",dns.equals("hostname")?"resolver.example.test":"192.168.50.133").put("dns_server_name","resolver.example.test");
  if(dns.equals("custom"))p.put("dns_protocol","tcp").put("dns_port",5353);
  File af=save(dir,a),bf=save(dir,b);String beforeA=Files.readString(af.toPath()),beforeB=Files.readString(bf.toPath());
  AndroidMultihopController.Prepared result=owner.prepare(af,bf,exitMode,execution,entryMode);
  Path session=app.resolve("layered-sessions").resolve(result.session.sessionId);
  String config=Files.readString(session.resolve("sing-box.json")),metadata=Files.readString(session.resolve("routervpn-multihop.json"));
  JSONObject g=new JSONObject(config),m=new JSONObject(metadata);
  check(m.getString("entry_mode").equals(entryMode)&&m.getString("exit_mode").equals(exitMode)&&m.getString("execution").equals(execution),"exact saved graph choice lost");
  check(m.getString("entry_node_id").equals(a.getString("nodeProofId"))&&m.getString("exit_node_id").equals(b.getString("nodeProofId"))&&!m.getString("entry_node_id").equals(m.getString("exit_node_id")),"independent node identities collapsed");
  JSONArray ins=g.getJSONArray("inbounds");int tun=0;for(int i=0;i<ins.length();i++)if(ins.getJSONObject(i).optString("type").equals("tun"))tun++;
  check(tun==1&&ins.length()==3,"one VPN plus two proof lanes required");
  check(ins.getJSONObject(0).getInt("mtu")==1280,"captured interface MTU changed");
  check(ins.getJSONObject(1).getInt("listen_port")==1098&&ins.getJSONObject(2).getInt("listen_port")==1099,"per-hop measurement lanes merged");
  check(byTag(g,"proxy").getString("detour").equals("entry-wg")&&byTag(g,"entry-private").getString("detour").equals("entry-wg"),"exit or entry proof bypassed entry");
  String es=Files.exists(session.resolve(AndroidMultihopStartLayer.SESSION_FILE))?Files.readString(session.resolve(AndroidMultihopStartLayer.SESSION_FILE)):null;
  String xs=Files.exists(session.resolve(AndroidMultihopStartLayer.EXIT_SESSION_FILE))?Files.readString(session.resolve(AndroidMultihopStartLayer.EXIT_SESSION_FILE)):null;
  io.nekohasekai.libbox.RouterMultihop runtime=AndroidMultihopStartLayer.prepareExecution(config,metadata,es,xs);
  JSONObject planned=runtime==null?g:new JSONObject(runtime.config());
  for(boolean entry:new boolean[]{true,false}){
   String mode=entry?entryMode:exitMode;if(!NativeSingBoxController.nativeNaiveFamily(mode))continue;
   JSONObject out=byTag(planned,entry?"entry-wg":runtime==null?"proxy":"routervpn-execution-local"),tls=out.getJSONObject("tls"),udp=out.getJSONObject("udp_over_tcp");
   check(out.getString("type").equals("naive")&&out.get("quic") instanceof Boolean&&out.getBoolean("quic")==mode.equals("naive-h3"),"HTTP version changed or coerced");
   check(out.getString("username").equals(entry?"entry-only-user":"exit-only-user")&&out.getString("password").equals(entry?"entry-only-secret":"exit-only-secret"),"Naive credential borrowed from other node");
   check(tls.getJSONArray("certificate").length()==1&&tls.getJSONArray("certificate").getString(0).equals(entry?ec:xc)&&!tls.has("certificate_path")&&!tls.optBoolean("insecure"),"wrong-node or file-owned TLS trust");
   check(udp.get("enabled") instanceof Boolean&&udp.getBoolean("enabled")&&udp.getInt("version")==2,"UDP forwarding lost");
   String layer=entry?el:xl,host=layer.equals("off")?(entry?"192.0.2.11":"198.51.100.12"):"10.77.0.1";
   check(out.getString("server").equals(host),"captured Naive peer/outer layer changed");
  }
  if(NativeSingBoxController.nativeNaiveFamily(exitMode))check(!Files.exists(session.resolve("trust.pem"))&&!Files.exists(session.resolve("wg.conf")),"unneeded helper/trust file staged with Naive");
  JSONArray servers=planned.getJSONObject("dns").getJSONArray("servers");JSONObject selected=servers.getJSONObject(servers.length()-1);
  String type=dns.equals("custom")?"tcp":dns.equals("dot")?"tls":dns.equals("doh3")?"h3":dns.equals("doh")||dns.equals("hostname")?"https":"udp";
  check(selected.getString("type").equals(type)&&selected.getString("server").equals(dns.equals("hostname")?"resolver.example.test":"192.168.50.133"),"selected AdGuard/transport silently changed");
  if(dns.equals("custom"))check(selected.getInt("server_port")==5353,"DNS custom TCP port lost");
  for(int i=0;i<servers.length();i++)check(servers.getJSONObject(i).getString("detour").equals("proxy"),"DNS escaped exit");
  boolean ipv6=false,lan=false;JSONArray rules=planned.getJSONObject("route").getJSONArray("rules");for(int i=0;i<rules.length();i++){
   JSONObject rule=rules.getJSONObject(i);if(rule.optString("action").equals("reject")&&rule.optInt("ip_version")==6)ipv6=true;
   if(rule.optString("action").equals("reject")&&rule.has("ip_cidr")&&has(rule.getJSONArray("ip_cidr"),"192.168.0.0/16"))lan=true;
  }
  check(ipv6&&lan,"LAN/IPv6 policy omitted");
  if(runtime!=null){check(byTag(planned,"routervpn-execution-server").getString("detour").equals("entry-wg"),"server comparison candidate bypasses entry");runtime.close();}
  check(beforeA.equals(Files.readString(af.toPath()))&&beforeB.equals(Files.readString(bf.toPath())),"saved private source changed");graphs++;
 }
 static void negatives(Path dir,String mode,String ec,String xc)throws Exception{
  for(boolean entry:new boolean[]{true,false})for(String fault:new String[]{"quic","quic-type","udp","empty-password","tls","trust","helper","detour","route","selection","duplicate","mtu"}){
   JSONObject a=source('a',entry?mode:"wg",ec,"off"),b=source('b',entry?"shadowsocks":mode,xc,"off"),target=entry?a:b;
   JSONObject assets=target.getJSONObject("profiles").getJSONObject(mode),g=readConfig(assets),out=byTag(g,"proxy");
   switch(fault){
    case "quic":out.put("quic",!mode.equals("naive-h3"));break;
    case "quic-type":out.put("quic",mode.equals("naive-h3")?1:0);break;
    case "udp":out.put("udp_over_tcp",false);break;
    case "empty-password":out.put("password","");break;
    case "tls":out.getJSONObject("tls").put("insecure",true);break;
    case "trust":assets.remove("trust.pem");break;
    case "helper":assets.put("execute.sh",encoded("test-private-not-executed"));break;
    case "detour":out.put("detour","direct");break;
    case "route":g.getJSONObject("route").getJSONArray("rules").put(new JSONObject().put("network","tcp").put("outbound","direct"));break;
    case "selection":target.put("selectedRouterID","missing");break;
    case "duplicate":target.getJSONArray("routerProfiles").put(new JSONObject(profile(target).toString()));break;
    case "mtu":profile(target).put("manual_mtu",1279);break;
   }
   saveConfig(assets,g);proxyRejected(dir,a,b,entry?mode:"wg",entry?"shadowsocks":mode);
  }
  for(int fault=0;fault<3;fault++){
   Path app=Files.createTempDirectory(dir,"stale-naive-");Context ctx=new Context(app.toFile());AndroidMultihopController owner=new AndroidMultihopController(ctx,new NativeSingBoxController(ctx));
   File a=save(dir,source('a',mode,ec,"aes-256-gcm")),b=save(dir,source('b',mode,xc,"aes-256-gcm"));final int f=fault;
   io.nekohasekai.libbox.Libbox.afterEntryLayerPreflight=()->{if(f==0)Thread.currentThread().interrupt();else try{Files.writeString((f==1?a:b).toPath(),"{}");}catch(Exception e){throw new RuntimeException(e);}};
   boolean rejected=false;try{owner.prepare(a,b,mode,"auto",mode);}catch(Exception expected){rejected=true;}finally{io.nekohasekai.libbox.Libbox.afterEntryLayerPreflight=null;Thread.interrupted();}
   check(rejected&&sessions(app)==0,"cancelled or changed graph staged a private session");
  }
  Path app=Files.createTempDirectory(dir,"naive-picker-");Context ctx=new Context(app.toFile());NativeSingBoxController direct=new NativeSingBoxController(ctx);AndroidMultihopController owner=new AndroidMultihopController(ctx,direct);
  JSONObject b=source('b',mode,xc,"off");File file=save(dir,b);
  check(owner.listSupportedExitModes(file).stream().anyMatch(m->m.id.equals(mode)),"native Naive not selectable");
  NativeSingBoxController.SessionInfo session=direct.prepareSession(file,mode);
  check(!Files.exists(app.resolve("layered-sessions").resolve(session.sessionId).resolve("trust.pem")),"standalone Naive retained external trust file");
  JSONObject assets=b.getJSONObject("profiles").getJSONObject(mode),g=readConfig(assets);byTag(g,"proxy").put("quic",!mode.equals("naive-h3"));saveConfig(assets,g);File broken=save(dir,b);
  var valid=owner.listSupportedExitModes(broken);check(valid.stream().noneMatch(m->m.id.equals(mode))&&valid.stream().anyMatch(m->m.id.equals("wg")),"malformed Naive hid independent valid modes");
  int before=sessions(app);boolean rejected=false;try{direct.prepareSession(broken,mode);}catch(Exception expected){rejected=true;}
  check(rejected&&sessions(app)==before,"bad standalone Naive silently fell back or staged");
 }
 public static void main(String[] args)throws Exception{
  Path dir=Path.of(args[0]);String ec=io.nekohasekai.libbox.Libbox.testCertificate("entry.example.test"),xc=io.nekohasekai.libbox.Libbox.testCertificate("exit.example.test");
  for(String a:MODES)for(String b:MODES){if(!NativeSingBoxController.nativeNaiveFamily(a)&&!NativeSingBoxController.nativeNaiveFamily(b))continue;
   for(String execution:new String[]{"local","server","auto"})for(String[] layers:new String[][]{{"off","off"},{"aes-256-gcm","off"},{"off","aes-256-gcm+xor-whitening"},{"aes-256-gcm+xor-whitening","aes-256-gcm"}})
    verify(dir,a,b,execution,layers[0],layers[1],"home",ec,xc);
  }
  check(graphs==288,"entry/exit matrix incomplete");
  for(String mode:new String[]{"naive-h2","naive-h3"}){
   for(String dns:new String[]{"custom","dot","doh","doh3","hostname"})verify(dir,"shadowsocks",mode,"auto","off","off",dns,ec,xc);
   negatives(dir,mode,ec,xc);
  }
  System.out.println("Android Naive: PASS ("+graphs+" shipping Java/Go graphs; "+checks+" checks; OS/startup doubled, native traffic separate)");
 }
}'''

if __name__ == '__main__':
    P.run()
