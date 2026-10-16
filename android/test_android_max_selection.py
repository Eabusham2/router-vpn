#!/usr/bin/env python3
"""Execute complete MAX launch policy using shipping Java and the real Go compiler.

Android OS and Libbox initialization handles are doubled. The normal run uses
Android's org.json library (ANDROID_JSON_JAR); no physical VPN, native handshake,
APK build or signing result is claimed by these host tests.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('android_pq_host', ROOT/'android/test_android_pq_selection.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
# Use only the exact compilers exercised here, keeping unrelated test-only
# crypto/mlkem fixture generation out of this standalone policy bridge.
P.GO = r'''package main
import("bytes";"encoding/binary";"encoding/json";"fmt";"io";"os";"router-vpn/internal/mobilemultihop";"router-vpn/internal/mobileperf")
type request struct{Operation,Config,Policy string}
func handle(r request)(string,error){
 switch r.Operation {
 case "max-profile":var input struct{Mode,Files string};if err:=json.Unmarshal([]byte(r.Config),&input);err!=nil{return "",err};return mobilemultihop.CompileMAXProfile(input.Mode,input.Files,r.Policy)
 case "lan":return mobilemultihop.ApplyLANPolicy(r.Config,r.Policy)
 case "performance":return mobileperf.Apply(r.Config,r.Policy)
 default:return "",fmt.Errorf("unexpected single-MAX test operation: %s",r.Operation)
 }
}
''' + P.GO[P.GO.index('\nfunc main(){'):]
# Keep the MAX method when the existing bounded process adapter replaces call().
key='io/nekohasekai/libbox/Libbox.java'
text=P.M.STUBS[key]
method=' public static String routerCompileMAXProfile(String mode,String files,String policy)throws Exception{return call("max-profile",new JSONObject().put("Mode",mode).put("Files",files).toString(),policy);}'
assert text.count(method)==1
text=text.replace(method+'\n','',1)
anchor=' public static String routerCompilePQProfile('
idx=text.index(anchor)
# P.run replaces everything preceding the PQ method, so insert after it.
end=text.index('\n',idx)
max_method=r'''
 public static java.util.function.UnaryOperator<String> maxResult;
 public static String routerCompileMAXProfile(String mode,String files,String policy)throws Exception {
  String value=call("max-profile",new JSONObject().put("Mode",mode).put("Files",files).toString(),policy);
  return maxResult==null?value:maxResult.apply(value);
 }
'''
P.M.STUBS[key]=text[:end]+max_method+text[end:]
P.HARNESS=r'''package com.eabusham.routervpn;
import android.content.Context;import org.json.*;import java.io.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.util.*;
import static com.eabusham.routervpn.MultihopGraphHarness.*;
public final class PQSelectionHarness {
 static JSONObject fixtures;
 static JSONObject source(String mode,String dns,String layer)throws Exception {
  JSONObject f=fixtures.getJSONObject(mode),metadata=f.getJSONObject("policy");
  JSONObject b=bundle('b'),p=profile(b);String node=metadata.getString("node_id");
  b.put("nodeProofId",node).put("profiles",new JSONObject().put(mode,new JSONObject(f.getJSONObject("files").toString())))
   .put("modes",new JSONArray().put(new JSONObject().put("id",mode).put("name",mode)));
  p.put("node_proof_id",node).put("node_kind","router-vpn").put("endpoint",metadata.getString("endpoint"))
   .put("router_api",metadata.getString("router_api")).put("start_layer",layer).put("base_tunnel",mode.endsWith("-awg")?"awg":"wg")
   .put("mtu_policy","fixed").put("manual_mtu",1350).put("ipv6_mode","off").put("home_lan_access",false).put("kill_switch",true).put("daita_enabled",true);
  if(!dns.equals("home"))p.put("dns_mode",dns.equals("hostname")?"doh":dns).put("dns_host",dns.equals("hostname")?"resolver.example.test":"192.168.50.133").put("dns_server_name","resolver.example.test");
  if(dns.equals("custom"))p.put("dns_protocol","tcp").put("dns_port",5353);
  return b;
 }
 interface Change {void run(JSONObject b)throws Exception;}
 static void rejected(NativeSingBoxController owner,Path dir,Path app,String mode,Change change)throws Exception {
  JSONObject b=source(mode,"home","off");change.run(b);File input=save(dir,b);byte[] before=Files.readAllBytes(input.toPath());int count=sessions(app);
  boolean failed=false;try{owner.prepareSession(input,mode);}catch(Exception expected){failed=true;}
  check(failed,"invalid MAX graph/selection accepted");check(count==sessions(app),"rejected MAX staged a session");
  check(Arrays.equals(before,Files.readAllBytes(input.toPath())),"failed MAX launch rewrote source");
 }
 static boolean same(Object a,Object b)throws Exception {
  if(a instanceof JSONObject && b instanceof JSONObject){JSONObject x=(JSONObject)a,y=(JSONObject)b;if(x.length()!=y.length())return false;for(var i=x.keys();i.hasNext();){String k=i.next();if(!y.has(k)||!same(x.get(k),y.get(k)))return false;}return true;}
  if(a instanceof JSONArray && b instanceof JSONArray){JSONArray x=(JSONArray)a,y=(JSONArray)b;if(x.length()!=y.length())return false;for(int i=0;i<x.length();i++)if(!same(x.get(i),y.get(i)))return false;return true;}
  if(a instanceof Number&&b instanceof Number)return Double.compare(((Number)a).doubleValue(),((Number)b).doubleValue())==0;
  return Objects.equals(a,b);
 }
 public static void main(String[]args)throws Exception {
  fixtures=new JSONObject(Files.readString(Path.of(System.getenv("ROUTERVPN_MAX_PROFILE_FIXTURES"))));
  Path dir=Path.of(args[0]),app=dir.resolve("app");Files.createDirectories(app);NativeSingBoxController owner=new NativeSingBoxController(new Context(app.toFile()));int graphs=0;
  for(String mode:new String[]{"max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"}){
   check(AndroidNativeMAXProfile.isMode(mode),"exact MAX branch not registered");
   check(NativeSingBoxController.nativeMultihopEntry(mode),"complete MAX entry selection is missing");
   for(String layer:new String[]{"off","aes-256-gcm","aes-256-gcm+xor-whitening"})for(String dns:new String[]{"home","custom","dot","doh","doh3","hostname"}){
    JSONObject b=source(mode,dns,layer),assets=b.getJSONObject("profiles").getJSONObject(mode);File file=save(dir,b);byte[] before=Files.readAllBytes(file.toPath());
    JSONObject compiled=new JSONObject(AndroidNativeMAXProfile.compile(b,assets,mode));
    int installs=RouterPQNative.installs;
    check(owner.listDirectLibboxModes(file).stream().anyMatch(m->m.id.equals(mode)),"complete MAX missing from usable modes");
    check(installs==RouterPQNative.installs,"discovery initialized a native owner");
    NativeSingBoxController.SessionInfo result=owner.prepareSession(file,mode);Path session=app.resolve("layered-sessions").resolve(result.sessionId);
    check(RouterPQNative.installs==installs+1,"MAX launch skipped the pinned PQ factory");check(result.modeId.equals(mode),"requested MAX branch changed");
    Set<String> names=new HashSet<>();try(var stream=Files.list(session)){stream.forEach(f->names.add(f.getFileName().toString()));}
    check(names.equals(Set.of("sing-box.json","routervpn-mtu.json",AndroidKillSwitchPolicy.SESSION_MARKER)),"MAX staged raw helpers, extra secrets or another backend");
    JSONObject graph=new JSONObject(Files.readString(session.resolve("sing-box.json"))),ep=graph.getJSONArray("endpoints").getJSONObject(0),pq=ep.getJSONObject("pq");
    check(graph.getJSONArray("inbounds").length()==1&&graph.getJSONArray("endpoints").length()==1,"MAX lost one-TUN ownership");
    check(ep.getString("type").equals("routervpn-pq")&&ep.getString("mode").equals(mode.endsWith("-awg")?"awg2-pq":"wg-pq"),"MAX silently downgraded its base");
    check(ep.getString("node_id").equals(b.getString("nodeProofId")),"MAX changed its node proof identity");
    for(String[] pair:new String[][]{{"secret","rosenpass-client-secret"},{"public","rosenpass-client-public"},{"peer","rosenpass-server-public"}})check(pq.getString(pair[0]).equals(assets.getString(pair[1])),"MAX PQ key changed");
    JSONObject old=compiled.getJSONArray("endpoints").getJSONObject(0);
    for(String field:new String[]{"private_key","peers","pq"})check(same(ep.get(field),old.get(field)),"MAX endpoint credentials changed: "+field);
    if(mode.endsWith("-awg"))check(ep.getJSONObject("amnezia").length()==11&&same(ep.get("amnezia"),old.get("amnezia")),"AWG parameters dropped");
    check(ep.getInt("mtu")==1350&&graph.getJSONArray("inbounds").getJSONObject(0).getInt("mtu")==1350,"MAX MTU detached from actual TUN");
    JSONArray out=graph.getJSONArray("outbounds");check(same(out,compiled.getJSONArray("outbounds")),"device policy rewrote outer encryption");
    check(out.length()==(layer.equals("off")?2:3)&&out.getJSONObject(0).getString("type").equals("shadowsocks")&&out.getJSONObject(1).getString("type").equals(mode.startsWith("max-tls-")?"routervpn-xray":"hysteria2"),"MAX missing middle/outer encryption");
    JSONArray servers=graph.getJSONObject("dns").getJSONArray("servers");JSONObject selected=servers.getJSONObject(servers.length()-1);
    String transport=dns.equals("custom")?"tcp":dns.equals("dot")?"tls":dns.equals("doh3")?"h3":dns.equals("doh")||dns.equals("hostname")?"https":"udp";
    check(selected.getString("type").equals(transport),"MAX lost selected DNS transport");
    check(selected.getString("server").equals(dns.equals("hostname")?"resolver.example.test":"192.168.50.133"),"MAX replaced AdGuard");
    if(dns.equals("custom"))check(selected.getInt("server_port")==5353,"MAX lost custom DNS port");
    for(int i=0;i<servers.length();i++)check(servers.getJSONObject(i).getString("detour").equals("proxy"),"MAX DNS bypassed the complete chain");
    if(dns.equals("hostname"))check(servers.length()==2&&servers.getJSONObject(0).getString("server").equals("192.168.50.133"),"bootstrap replaced AdGuard");
    boolean ipv6=false,lan=false;JSONArray rules=graph.getJSONObject("route").getJSONArray("rules");
    for(int i=0;i<rules.length();i++){JSONObject r=rules.getJSONObject(i);if(r.optString("action").equals("reject")&&r.optInt("ip_version")==6)ipv6=true;if(r.optString("action").equals("reject")&&r.has("ip_cidr")&&has(r.getJSONArray("ip_cidr"),"192.168.0.0/16"))lan=true;}
    check(ipv6&&lan,"MAX leaked LAN or IPv6 policy");
    check(graph.getJSONArray("services").getJSONObject(0).getString("packet_tag").equals("proxy"),"MAX padding uses the wrong layer");
    check(Arrays.equals(before,Files.readAllBytes(file.toPath())),"MAX changed saved bundle");graphs++;
   }
   for(String asset:new String[]{mode.endsWith("-awg")?"awg.conf":"wg.conf","chain.env","middle-sing-box.json","rosenpass.env","rosenpass.toml","rosenpass-client-secret","rosenpass-client-public","rosenpass-server-public",mode.startsWith("max-tls-")?"outer-xray.json":"cert.pem"})
    rejected(owner,dir,app,mode,b->b.getJSONObject("profiles").getJSONObject(mode).remove(asset));
   for(String path:new String[]{"../escape","run.sh","sing-box.json"})rejected(owner,dir,app,mode,b->b.getJSONObject("profiles").getJSONObject(mode).put(path,Base64.getEncoder().encodeToString("unowned".getBytes(StandardCharsets.UTF_8))));
   rejected(owner,dir,app,mode,b->b.getJSONObject("profiles").getJSONObject(mode).put("rosenpass-server-public",b.getJSONObject("profiles").getJSONObject(mode).getString("rosenpass-client-public")));
   rejected(owner,dir,app,mode,b->b.getJSONObject("profiles").getJSONObject(mode).put("chain.env",Boolean.TRUE));
   rejected(owner,dir,app,mode,b->b.put("selectedRouterID","missing"));
   rejected(owner,dir,app,mode,b->b.getJSONArray("routerProfiles").put(new JSONObject(profile(b).toString())));
   for(String field:new String[]{"node_kind","node_proof_id","endpoint","router_api"})rejected(owner,dir,app,mode,b->profile(b).put(field,"wrong"));
   rejected(owner,dir,app,mode,b->profile(b).put("manual_mtu",1279));
   rejected(owner,dir,app,mode,b->profile(b).put("jumbo_tun",true));
   RouterPQNative.fail=true;try{rejected(owner,dir,app,mode,b->{});}finally{RouterPQNative.fail=false;}
   io.nekohasekai.libbox.Libbox.rejectConfig=true;try{rejected(owner,dir,app,mode,b->{});}finally{io.nekohasekai.libbox.Libbox.rejectConfig=false;}
   for(String fault:new String[]{"empty","base","middle","outer","key","extra-tun","wrong-node"}){
    io.nekohasekai.libbox.Libbox.maxResult=(value)->{try{if(fault.equals("empty"))return "";JSONObject g=new JSONObject(value),e=g.getJSONArray("endpoints").getJSONObject(0);switch(fault){case "base":e.put("type","wireguard");break;case "middle":g.getJSONArray("outbounds").remove(0);break;case "outer":g.getJSONArray("outbounds").getJSONObject(1).put("type","direct");break;case "key":e.getJSONObject("pq").put("secret","modified");break;case "extra-tun":g.getJSONArray("inbounds").put(g.getJSONArray("inbounds").get(0));break;default:e.put("node_id","f".repeat(64));}return g.toString();}catch(Exception x){throw new RuntimeException(x);}};
    try{rejected(owner,dir,app,mode,b->{});}finally{io.nekohasekai.libbox.Libbox.maxResult=null;}
   }
   for(boolean cancel:new boolean[]{false,true}){
    JSONObject b=source(mode,"home","off");File file=save(dir,b);int count=sessions(app);
    io.nekohasekai.libbox.Libbox.afterCheck=()->{if(cancel)Thread.currentThread().interrupt();else try{Files.writeString(file.toPath(),"{}");}catch(Exception e){throw new RuntimeException(e);}};
    boolean failed=false;try{owner.prepareSession(file,mode);}catch(Exception e){failed=true;}finally{Thread.interrupted();io.nekohasekai.libbox.Libbox.afterCheck=null;}
    check(failed&&count==sessions(app),"changed/cancelled MAX launch staged old identity");
   }
  }
  for(String mode:new String[]{"max","max-tls","max-quic","max-tls-WG","",null})check(!AndroidNativeMAXProfile.isMode(mode),"unknown MAX label treated as executable");
  check(graphs==72,"MAX matrix incomplete");
  System.out.println("Android complete MAX: "+graphs+" Java/Go graphs, "+checks+" checks passed (OS/FFI handles doubled)");
 }
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='android-max-fixtures-') as temp:
        fixture=Path(temp)/'profiles.json'
        subprocess.run(['go','test','-count=1','-run','^TestExportMAXMobileProfiles$','./internal/mobilemultihop'],cwd=ROOT,env=dict(os.environ,ROUTERVPN_MAX_PROFILE_FIXTURES=str(fixture)),check=True,timeout=90)
        old=os.environ.get('ROUTERVPN_MAX_PROFILE_FIXTURES')
        os.environ['ROUTERVPN_MAX_PROFILE_FIXTURES']=str(fixture)
        try:P.run()
        finally:
            if old is None:os.environ.pop('ROUTERVPN_MAX_PROFILE_FIXTURES',None)
            else:os.environ['ROUTERVPN_MAX_PROFILE_FIXTURES']=old
    if os.environ.get('ROUTERVPN_JSON_BOUNDARY_DOUBLE'):
        print('LOCAL LIMITATION: JSON API/parser also doubled; repeat with Android org.json before claiming native parser validation.')

if __name__=='__main__':main()
