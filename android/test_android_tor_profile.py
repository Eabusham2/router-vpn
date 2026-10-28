#!/usr/bin/env python3
"""Execute Android Tor capture/staging with shipping Java and real Go compilers.

The Android OS, private-file syscalls and Libbox startup are boundary doubles.
The selected nodes, compiler calls, Tor bridge grammar, store serialization and
session validation are production code. No Tor network or remote node is used.
Set ROUTERVPN_ANDROID_TOR_GRAPHS to an empty directory for the native parser gate.
"""
from pathlib import Path
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
EXTRA_SOURCES = ()
EXTRA_LIBBOX = ""
EXTERNAL_BOUNDARY = r'''
final class AndroidExternalPolicy {
 static boolean supports(String value){return false;}
 static String protocol(String value){return value;}
 static JSONObject captureTorPredecessor(AndroidStandardExitStore.Entry value){throw new AssertionError("ordinary entry is outside this Router-entry fixture");}
 static NativeSingBoxController.SessionInfo prepare(android.content.Context c,java.io.File f,AndroidStandardExitStore.Entry e,String m){throw new AssertionError("ordinary exit is outside this Tor fixture");}
 static NativeSingBoxController.SessionInfo prepare(android.content.Context c,java.io.File f,AndroidStandardExitStore.Entry e,String m,String x){throw new AssertionError("ordinary exit is outside this Tor fixture");}
 static NativeSingBoxController.SessionInfo prepare(android.content.Context c,java.io.File f,AndroidStandardExitStore.Entry e,String m,String x,String r){throw new AssertionError("ordinary exit is outside this Tor fixture");}
}
'''
spec = importlib.util.spec_from_file_location("tor_composite_fixture", ROOT / "android/test_android_composite_multihop.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
P = C.P
prefix = P.HARNESS[:P.HARNESS.index(" static JSONObject fixtures,")]
node = P.HARNESS[P.HARNESS.index(" static JSONObject node("):P.HARNESS.index(" static JSONObject load(")]
HARNESS = prefix + r'''
 static JSONObject fixtures,compositeEntry,compositeExit;
 static int graphs;
 static final String[] ALL={"wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg","ss-v2ray","split","max","naive-h2","naive-h3"};
 static final String[] KINDS={"tor","obfs4","meek_lite","snowflake","webtunnel","custom"};
 static final String[] LAYERS={"off","aes-256-gcm","aes-256-gcm+xor-whitening"};
 static final String OBFS="obfs4 198.51.100.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=Y2VydA iat-mode=0";
 static final String MEEK="meek_lite 192.0.2.2:2 url=https://bridge.example.test/ front=front.example.test";
 static final String SNOW="snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://broker.example.test/ front=cdn.example.test ice=stun:stun.example.test:3478 utls-imitate=hellorandomizedalpn";
 static final String WEB="webtunnel 10.0.0.2:443 89ABCDEF0123456789ABCDEF0123456789ABCDEF url=https://webtunnel.example.test/private ver=0.0.1";
''' + node + r'''
 static JSONObject load(Path path)throws Exception{return new JSONObject(Files.readString(path));}
 static JSONObject config(JSONObject assets)throws Exception{return new JSONObject(new String(Base64.getDecoder().decode(assets.getString("sing-box.json")),StandardCharsets.UTF_8));}
 static void config(JSONObject assets,JSONObject graph)throws Exception{assets.put("sing-box.json",enc(graph.toString()));}
 static boolean same(Object left,Object right)throws Exception{
  return io.nekohasekai.libbox.Libbox.testSameJSON(new JSONObject().put("value",left).toString(),new JSONObject().put("value",right).toString());
 }
 static JSONObject entry(String mode,String layer,String certificate)throws Exception{
  JSONObject b=node(mode.startsWith("naive-")?"hysteria2":mode,true,layer,certificate);
  if(mode.startsWith("naive-")){
   JSONObject assets=new JSONObject(b.getJSONObject("profiles").getJSONObject("hysteria2").toString()),graph=config(assets);
   byTag(graph,"proxy").put("type","naive").put("quic",mode.equals("naive-h3")).put("username","entry-only-user")
    .put("udp_over_tcp",new JSONObject().put("enabled",true).put("version",2));
   config(assets,graph);b.getJSONObject("profiles").put(mode,assets);
   b.getJSONArray("modes").put(new JSONObject().put("id",mode).put("name",mode));
  }
  profile(b).put("mtu_policy","fixed").put("manual_mtu",1360)
   .put("daita_enabled",true).put("dns_mode","doh").put("dns_host","9.9.9.9")
   .put("dns_port",443).put("dns_server_name","entry-dns.example.test").put("dns_path","/entry-query");
  return b;
 }
 static AndroidStandardExitStore.Entry tor(String kind,String dns)throws Exception{
  AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();
  e.id="saved-"+kind;e.name="Captured "+kind;e.protocol=kind.equals("tor")?"tor":"tor-bridge";
  if(!kind.equals("tor")){
   e.torTransport=kind;
   if(kind.equals("obfs4")||kind.equals("custom"))e.torBridges.add(OBFS);
   if(kind.equals("meek_lite")||kind.equals("custom"))e.torBridges.add(MEEK);
   if(kind.equals("snowflake")||kind.equals("custom"))e.torBridges.add(SNOW);
   if(kind.equals("webtunnel")||kind.equals("custom"))e.torBridges.add(WEB);
  }
  e.torPolicy.put("dns_mode",dns.equals("tcp")?"custom":dns).put("dns_protocol",dns)
   .put("dns_host","149.112.112.112").put("dns_port",dns.equals("tcp")?5353:dns.equals("dot")?8853:8443)
   .put("dns_server_name","tor-dns.example.test").put("dns_path","/captured-query")
   .put("ipv6_mode","off").put("home_lan_access",false).put("home_lan_cidrs",new JSONArray().put("192.168.50.0/24").put("fd12:3456::/48"))
   .put("mtu_policy","fixed").put("manual_mtu",1360);
  return e;
 }
 static JSONObject tagged(JSONArray values,String tag)throws Exception{
  JSONObject result=null;
  for(int i=0;i<values.length();i++)if(tag.equals(values.getJSONObject(i).optString("tag"))){
   check(result==null,"duplicate resolver owner");result=values.getJSONObject(i);
  }
  check(result!=null,"missing resolver "+tag);return result;
 }
 static void capturedNaiveResolver(JSONObject graph,JSONObject previous,JSONObject before,JSONObject after)throws Exception{
  JSONObject oldDNS=previous.getJSONObject("dns"),newDNS=graph.getJSONObject("dns");
  check(!before.has("domain_resolver")&&!previous.getJSONObject("route").has("default_domain_resolver"),"Naive bootstrap fixture no longer exercises implicit entry DNS");
  JSONObject query=after.getJSONObject("domain_resolver");
  String tag="routervpn-tor-naive-bootstrap-0";
  JSONObject expectedQuery=new JSONObject().put("server",tag);
  Object strategy=before.has("domain_strategy")?before.get("domain_strategy"):oldDNS.opt("strategy");
  if(strategy!=null)expectedQuery.put("strategy",strategy);
  check(same(query,expectedQuery),"Naive bootstrap borrowed Tor resolver or changed entry query strategy");
  JSONObject original=tagged(oldDNS.getJSONArray("servers"),oldDNS.getString("final"));
  JSONObject expected=new JSONObject(original.toString()).put("tag",tag);expected.remove("detour");
  if(before.has("detour"))expected.put("detour",before.get("detour"));
  JSONObject bootstrap=tagged(newDNS.getJSONArray("servers"),tag);
  check(same(bootstrap,expected),"Naive bootstrap changed captured DNS address, port, TLS, path or lower owner");
  check(same(original,tagged(newDNS.getJSONArray("servers"),original.getString("tag"))),"Naive bootstrap rewrote the original entry application resolver");
  check(newDNS.getJSONArray("servers").length()==oldDNS.getJSONArray("servers").length()+3,"Naive introduced an unowned DNS transport");
 }
 static void capturedEntry(JSONObject graph,JSONObject previous,JSONObject source,String mode,String layer,String certificate)throws Exception{
  int expected=1;
  for(String family:new String[]{"endpoints","outbounds"}){
   JSONArray rows=previous.optJSONArray(family);if(rows==null)continue;expected+=rows.length();
   for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);
    JSONObject actual=byTag(graph,row.getString("tag")),unchanged=new JSONObject(actual.toString());
    if(row.optString("type").equals("naive")){
     capturedNaiveResolver(graph,previous,row,actual);unchanged.remove("domain_resolver");
    }
    check(same(row,unchanged),"Tor changed a predecessor key, lane or routing owner");
   }
  }
  JSONArray endpoints=graph.optJSONArray("endpoints");
  check(expected==graph.getJSONArray("outbounds").length()+(endpoints==null?0:endpoints.length()),"Tor introduced a second encrypted owner");
  JSONObject owner=byTag(graph,"proxy");
  String type=NativeSingBoxController.nativeWireGuardFamily(mode)?mode.equals("wg")?"wireguard":"routervpn-amneziawg":
   NativeSingBoxController.nativePQFamily(mode)||AndroidNativeMAXProfile.isMode(mode)?"routervpn-pq":
   AndroidNativeCompositeProfile.isMode(mode)?"routervpn-composite":mode.startsWith("reality-")?"routervpn-xray":mode.startsWith("naive-")?"naive":mode;
  check(owner.getString("type").equals(type),"Tor silently substituted the selected entry family");
  if(type.equals("routervpn-composite")){
   check(owner.getString("node_id").equals(source.getString("nodeProofId"))&&owner.getString("mode").equals(mode),"composite lost its exact node/mode");
   check(owner.getString("tcp").equals("routervpn-composite-tcp")&&owner.getString("udp").equals("routervpn-composite-udp"),"composite collapsed the independent lanes");
   check(byTag(graph,owner.getString("tcp")).getString("type").equals(mode.equals("ss-v2ray")?"shadowsocks":"routervpn-xray")
    &&byTag(graph,owner.getString("udp")).getString("type").equals("hysteria2"),"composite encryption disappeared");
  }
  if(type.equals("routervpn-pq")){
   JSONObject assets=source.getJSONObject("profiles").getJSONObject(mode);
   check(owner.getString("node_id").equals(source.getString("nodeProofId")),"PQ owner switched nodes");
   for(String[] part:new String[][]{{"secret","rosenpass-client-secret"},{"public","rosenpass-client-public"},{"peer","rosenpass-server-public"}})
    check(owner.getJSONObject("pq").getString(part[0]).equals(assets.getString(part[1])),"PQ key borrowed from another capture");
   if(AndroidNativeMAXProfile.isMode(mode)){
    check(owner.getString("detour").equals("routervpn-max-ss")&&byTag(graph,"routervpn-max-ss").getString("detour").equals("routervpn-max-outer"),"MAX lost mandatory independent encryption layers");
    check(byTag(graph,"routervpn-max-outer").getString("type").equals(mode.startsWith("max-tls-")?"routervpn-xray":"hysteria2"),"MAX outer family changed");
   }
  }
  if(type.equals("naive")){
   check(owner.get("quic") instanceof Boolean&&owner.getBoolean("quic")==mode.equals("naive-h3"),"Naive HTTP version coerced");
   check(owner.getString("username").equals("entry-only-user")&&owner.getString("password").equals("entry-only-secret"),"Naive credentials changed");
   check(owner.getJSONObject("udp_over_tcp").getBoolean("enabled")&&owner.getJSONObject("udp_over_tcp").getInt("version")==2,"Naive lost owned packet underlay");
  }
  if(type.equals("hysteria2")||type.equals("naive")){
   JSONObject tls=owner.getJSONObject("tls");
   check(!tls.has("certificate_path")&&tls.has("certificate")&&tls.getJSONArray("certificate").getString(0).equals(certificate),"Tor predecessor TLS depends on an unstaged or foreign certificate");
  }
  if(type.equals("routervpn-xray")){
   JSONObject raw=new JSONObject(owner.getString("config_json"));
   check(raw.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").length()==1,"Xray authentication owner lost");
  }
  check(same(graph.opt("services"),previous.opt("services")),"Tor dropped the captured predecessor performance owner");
  check(previous.getJSONArray("services").length()>0,"DAITA test never exercised the predecessor owner");
  if(!layer.equals("off")&&!mode.equals("shadowsocks"))
   check(owner.has("detour")||type.equals("routervpn-composite"),"entry ignored its selected Start Layer");
 }
 static void verify(Path dir,String mode,String layer,String kind,String dns,String certificate)throws Exception{
  Path app=Files.createTempDirectory(dir,"tor-");Context context=new Context(app.toFile());
  AndroidStandardExitStore.Entry selected=tor(kind,dns);AndroidStandardExitStore store=new AndroidStandardExitStore(context);
  store.save(selected);selected=store.get(selected.id);
  String exitBefore=AndroidStandardExitStore.snapshot(selected);
  JSONObject source=mode.equals("direct")?null:entry(mode,layer,certificate);
  File file=source==null?null:save(dir,source);byte[] before=file==null?null:Files.readAllBytes(file.toPath());
  int installs=RouterPQNative.installs,calls=io.nekohasekai.libbox.Libbox.torCalls;
  NativeSingBoxController.SessionInfo prepared;
  try{prepared=AndroidTorProfile.prepare(context,file,selected,mode);}
  catch(Exception failure){throw new AssertionError("Tor preparation failed for "+kind+"/"+mode+"/"+layer+"/"+dns,failure);}
  check(RouterPQNative.installs==installs+1&&io.nekohasekai.libbox.Libbox.torCalls>calls,"Tor skipped real compilation/native registration");
  Path staged=app.resolve("layered-sessions").resolve(prepared.sessionId);
  String config=Files.readString(staged.resolve("sing-box.json")),metadata=Files.readString(staged.resolve(AndroidTorProfile.SESSION_FILE));
  JSONObject graph=new JSONObject(config),meta=AndroidTorProfile.session(config,metadata,prepared.sessionId,prepared.modeId);
  check(prepared.modeId.equals((source==null?"standard-direct-":"standard-")+selected.protocol),"Tor launch relabeled the captured selection");
  check(meta.getString("external_id").equals(selected.id)&&meta.getString("entry_mode").equals(source==null?"external":mode),"Tor metadata lost selected identities");
  check(meta.has("predecessor_profile")==(source!=null),"Tor metadata lost predecessor ownership");
  JSONObject capturedPolicy=new JSONObject(meta.getJSONObject("tor_profile").toString());
  check(capturedPolicy.getBoolean("multihop_enabled")== (source!=null),"Tor capture lost explicit entry selection");
  capturedPolicy.remove("multihop_enabled");
  if(source!=null){
   check(capturedPolicy.getString("multihop_entry_id").equals(profile(source).getString("id"))&&capturedPolicy.getString("multihop_exit_id").equals(selected.id)
    &&capturedPolicy.getString("multihop_entry_mode").equals(mode)&&capturedPolicy.getString("multihop_exit_mode").equals(selected.protocol)
    &&capturedPolicy.getString("multihop_execution").equals("local"),"Tor capture substituted entry, exit, mode or execution");
   for(String key:new String[]{"multihop_entry_id","multihop_exit_id","multihop_entry_mode","multihop_exit_mode","multihop_execution"})capturedPolicy.remove(key);
  }
  check(same(capturedPolicy,AndroidTorProfile.profile(selected)),"Tor metadata lost frozen selected policy");
  check(Files.readString(staged.resolve(AndroidKillSwitchPolicy.SESSION_MARKER)).equals("1\n"),"Tor did not stage strict lockdown");
  JSONObject tunnel=graph.getJSONArray("inbounds").getJSONObject(0),out=byTag(graph,AndroidTorProfile.OUTBOUND);
  check(graph.getJSONArray("inbounds").length()==1&&tunnel.getString("type").equals("tun")&&tunnel.getBoolean("auto_route")&&tunnel.getBoolean("strict_route"),"Tor created or weakened a second VPN");
  check(tunnel.getInt("mtu")==1360,"Tor ignored exact current interface policy");
  check(out.getString("type").equals("routervpn-tor")&&out.getString("session_id").equals(prepared.sessionId),"Tor compiler lost session owner");
  check(out.has("detour")==(source!=null)&&(!out.has("detour")||out.getString("detour").equals("proxy")),"Tor bypassed selected entry");
  check(same(out.getJSONArray("bridges"),new JSONArray(selected.torBridges)),"Tor changed saved bridge lines or ordering");
  check(out.has("domain_resolver")==!kind.equals("tor"),"Tor bridge bootstrap lost explicit resolver ownership");
  if(out.has("domain_resolver"))check(out.getJSONObject("domain_resolver").getString("server").equals("routervpn-tor-bootstrap"),"Tor borrowed the predecessor domain resolver");
  JSONObject d=graph.getJSONObject("dns"),exitDNS=tagged(d.getJSONArray("servers"),"routervpn-tor-dns"),bootstrap=tagged(d.getJSONArray("servers"),"routervpn-tor-bootstrap");
  check(d.getString("final").equals("routervpn-tor-dns")&&!d.has("rules")&&d.getBoolean("independent_cache"),"application DNS still follows predecessor rules");
  check(exitDNS.getString("detour").equals(AndroidTorProfile.OUTBOUND)&&bootstrap.has("detour")==(source!=null),"Tor DNS took an unselected path");
  if(source!=null)check(bootstrap.getString("detour").equals("proxy"),"Tor bootstrap bypassed entry");
  String protocol=dns.equals("tcp")?"tcp":dns.equals("dot")?"tls":"https";
  for(JSONObject resolver:new JSONObject[]{exitDNS,bootstrap}){
   check(resolver.getString("type").equals(protocol)&&resolver.getString("server").equals("149.112.112.112"),"Tor substituted a public or system resolver");
   check(resolver.getInt("server_port")==selected.torPolicy.getInt("dns_port"),"Tor changed custom DNS port");
   if(!dns.equals("tcp"))check(resolver.getJSONObject("tls").getString("server_name").equals("tor-dns.example.test"),"Tor DNS TLS owner changed");
   if(dns.equals("doh"))check(resolver.getString("path").equals("/captured-query"),"Tor DoH path changed");
  }
  boolean v6=false,udp=false,lan=false,dnsRule=false;JSONArray rules=graph.getJSONObject("route").getJSONArray("rules");
  for(int i=0;i<rules.length();i++){JSONObject r=rules.getJSONObject(i);
   if(r.optString("action").equals("reject")){if(r.optInt("ip_version")==6)v6=true;if(r.optString("network").equals("udp"))udp=true;if(r.has("ip_cidr")&&has(r.getJSONArray("ip_cidr"),"192.168.50.0/24")&&has(r.getJSONArray("ip_cidr"),"fd12:3456::/48"))lan=true;}
   if(r.optString("action").equals("hijack-dns"))dnsRule=true;
   check(!r.has("outbound")||r.getString("outbound").equals(AndroidTorProfile.OUTBOUND),"application traffic bypasses Tor");
  }
  check(v6&&udp&&lan&&dnsRule&&d.getString("strategy").equals("ipv4_only"),"Tor weakened LAN/IPv6/UDP policy");
  check(has(tunnel.getJSONArray("route_address"),"192.168.50.0/24")&&has(tunnel.getJSONArray("route_address"),"fd12:3456::/48"),"private traffic escaped OS capture");
  if(source!=null){
   check(same(meta.getJSONObject("predecessor_profile"),profile(source)),"Tor proof uses another captured profile");
   check(out.getString("entry_sha256").matches("[0-9a-f]{64}"),"Tor graph was compiled without its captured entry proof");
   io.nekohasekai.libbox.Libbox.testTorPredecessor(meta.getJSONObject("predecessor_profile").toString());
   JSONObject previous=new JSONObject(io.nekohasekai.libbox.Libbox.lastTorPredecessor);
   capturedEntry(graph,previous,source,mode,layer,certificate);
   check(same(graph.getJSONObject("route").opt("default_domain_resolver"),previous.getJSONObject("route").opt("default_domain_resolver")),"Tor overwrote entry hostname bootstrap");
   JSONObject entryDNS=tagged(d.getJSONArray("servers"),"selected-dns");
   check(entryDNS.getString("server").equals("9.9.9.9")&&entryDNS.getJSONObject("tls").getString("server_name").equals("entry-dns.example.test"),"entry DNS capture merged with Tor DNS");
  }else check(graph.getJSONObject("route").getJSONObject("default_domain_resolver").getString("server").equals("routervpn-tor-bootstrap"),"direct bootstrap has no captured resolver");
  boolean relay=source!=null&&layer.equals("aes-256-gcm+xor-whitening")&&(mode.equals("shadowsocks")||mode.equals("hysteria2")||mode.startsWith("naive-"));
  check(Files.exists(staged.resolve(AndroidStartLayerRelay.SESSION_FILE))==relay,"Start Layer has duplicate or missing owner");
  if(relay){JSONObject r=load(staged.resolve(AndroidStartLayerRelay.SESSION_FILE));check(!r.getString("target_host").equals("127.0.0.1")&&r.getInt("target_port")==8389&&Base64.getDecoder().decode(r.getString("key_b64")).length==32,"XOR relay lost captured underlay");}
  Set<String> expected=new HashSet<>(Arrays.asList("sing-box.json",AndroidTorProfile.SESSION_FILE,AndroidKillSwitchPolicy.SESSION_MARKER));if(relay)expected.add(AndroidStartLayerRelay.SESSION_FILE);
  try(var names=Files.list(staged)){check(names.map(p->p.getFileName().toString()).collect(java.util.stream.Collectors.toSet()).equals(expected),"Tor staged unowned scripts, credentials or trust files");}
  check(exitBefore.equals(AndroidStandardExitStore.snapshot(selected))&&(file==null||Arrays.equals(before,Files.readAllBytes(file.toPath()))),"Tor modified its saved source");
  check(!meta.has("expected_public_ip")&&!out.has("expected_public_ip")&&selected.expectedPublicIp.isEmpty(),"Tor used a fabricated fixed exit IP");
  String output=System.getenv("ROUTERVPN_ANDROID_TOR_GRAPHS");
  if(output!=null)Files.writeString(Path.of(output).resolve(kind+"-"+mode+"-"+layer+".json"),config,StandardOpenOption.CREATE_NEW);
  graphs++;
 }
 interface ExitChange{void apply(AndroidStandardExitStore.Entry e)throws Exception;}
 interface NodeChange{void apply(JSONObject b)throws Exception;}
 static void homePaths(Path dir,String certificate)throws Exception{
  for(String missing:new String[]{"missing","","home"}){
   AndroidStandardExitStore.Entry e=tor("obfs4","tcp");e.torPolicy=new JSONObject().put("ipv6_mode","on");
   if(!missing.equals("missing"))e.torPolicy.put("dns_mode",missing);
   Context c=new Context(Files.createTempDirectory(dir,"home-draft-").toFile());AndroidStandardExitStore store=new AndroidStandardExitStore(c);
   store.save(e);String before=AndroidStandardExitStore.snapshot(store.get(e.id));
   check(AndroidTorProfile.editorPolicy(e).getString("dns_mode").equals("home"),"unresolved Home draft changed its editor DNS");
   reject(dir,"Home needs a captured entry",e,null,"direct");
   check(before.equals(AndroidStandardExitStore.snapshot(store.get(e.id))),"Home draft was rewritten by validation");
  }
  int homeGraphs=0;
  for(String mode:ALL)for(String protocol:new String[]{"udp","tcp","dot","doh","doh3"}){
   JSONObject b=entry(mode,"off",certificate);profile(b).put("adguard_ipv4","10.77.0.53").put("adguard_ipv6","fd77::53");
   AndroidStandardExitStore.Entry e=tor("obfs4","doh");e.torPolicy.put("dns_mode","home").put("dns_protocol",protocol).put("dns_host","");
   Path app=Files.createTempDirectory(dir,"home-path-");Context c=new Context(app.toFile());File file=save(dir,b);
   String saved=AndroidStandardExitStore.snapshot(e);NativeSingBoxController.SessionInfo info=AndroidTorProfile.prepare(c,file,e,mode);
   Path folder=app.resolve("layered-sessions").resolve(info.sessionId);String config=Files.readString(folder.resolve("sing-box.json"));
   JSONObject graph=new JSONObject(config),meta=AndroidTorProfile.session(config,Files.readString(folder.resolve(AndroidTorProfile.SESSION_FILE)),info.sessionId,info.modeId);
   JSONObject dns=tagged(graph.getJSONObject("dns").getJSONArray("servers"),"routervpn-tor-dns"),bootstrap=tagged(graph.getJSONObject("dns").getJSONArray("servers"),"routervpn-tor-bootstrap");
   String type=protocol.equals("dot")?"tls":protocol.equals("doh")?"https":protocol.equals("doh3")?"h3":protocol;
   check(dns.getString("type").equals(type)&&dns.getString("server").equals("10.77.0.53")&&dns.getInt("server_port")==8443&&dns.getString("detour").equals("proxy"),"Home Tor substituted resolver, port, protocol or entry");
   check(bootstrap.getString("server").equals("10.77.0.53")&&bootstrap.getString("detour").equals("proxy"),"Home Tor bootstrap escaped its captured entry");
   check(graph.getJSONObject("route").getString("final").equals(AndroidTorProfile.OUTBOUND)&&byTag(graph,AndroidTorProfile.OUTBOUND).getString("entry_sha256").matches("[0-9a-f]{64}"),"Home DNS bypassed Tor or lost entry proof");
   check(meta.getJSONObject("tor_profile").getString("multihop_entry_mode").equals(mode)&&saved.equals(AndroidStandardExitStore.snapshot(e)),"Home Tor changed its saved source or entry mode");
   homeGraphs++;
  }
  check(homeGraphs==95,"Home Tor transport and entry matrix incomplete");
  JSONObject b=entry("shadowsocks","off",certificate);profile(b).put("adguard_ipv4","10.77.0.53");
  AndroidStandardExitStore.Entry e=tor("obfs4","tcp");e.torPolicy.put("dns_mode","home").put("dns_host","10.77.0.54");
  reject(dir,"Home resolver belongs to another Router node",e,b,"shadowsocks");
 }
 static void reject(Path dir,String label,AndroidStandardExitStore.Entry selected,JSONObject bundle,String mode)throws Exception{
  Path app=Files.createTempDirectory(dir,"reject-");File file=bundle==null?null:save(dir,bundle);
  String snapshot=AndroidStandardExitStore.snapshot(selected);byte[] before=file==null?null:Files.readAllBytes(file.toPath());
  boolean failed=false;try{AndroidTorProfile.prepare(new Context(app.toFile()),file,selected,mode);}catch(Exception expected){failed=true;}
  check(failed&&sessions(app)==0,"invalid Tor selection staged: "+label);
  check(snapshot.equals(AndroidStandardExitStore.snapshot(selected))&&(file==null||Arrays.equals(before,Files.readAllBytes(file.toPath()))),"Tor rejection mutated source: "+label);
 }
 static void policyNegatives(Path dir)throws Exception{
  Map<String,ExitChange> changes=new LinkedHashMap<>();
  changes.put("fixed-ip",e->e.expectedPublicIp="8.8.8.8");changes.put("second-server",e->e.server="192.0.2.8");
  changes.put("second-key",e->e.wgPrivateKey=key('x'));changes.put("second-credentials",e->e.password="another-owner");
  changes.put("home",e->e.torPolicy.put("dns_mode","home"));changes.put("fastest",e->e.torPolicy.put("dns_mode","fastest"));
  changes.put("UDP",e->e.torPolicy.put("dns_protocol","udp"));changes.put("DoH3",e->e.torPolicy.put("dns_mode","doh3"));
  changes.put("system-bootstrap",e->e.torPolicy.put("dns_host","resolver.example.test"));changes.put("private-DNS",e->e.torPolicy.put("dns_host","192.168.50.133"));
  changes.put("bad-TLS",e->e.torPolicy.put("dns_mode","dot").put("dns_server_name","bad/name"));
  changes.put("bad-port",e->e.torPolicy.put("dns_port","5353"));changes.put("bad-mode",e->e.torPolicy.put("dns_mode",true));
  changes.put("low-MTU",e->e.torPolicy.put("manual_mtu",1279));changes.put("MTU-type",e->e.torPolicy.put("manual_mtu","1360"));
  changes.put("Jumbo-type",e->e.torPolicy.put("jumbo_tun","true"));changes.put("Jumbo-Fixed-conflict",e->e.torPolicy.put("jumbo_tun",true));
  changes.put("LAN-type",e->e.torPolicy.put("home_lan_access","false"));changes.put("public-LAN",e->e.torPolicy.put("home_lan_cidrs",new JSONArray().put("8.0.0.0/8")));
  changes.put("foreign-policy",e->e.torPolicy.put("node_proof_id","a".repeat(64)));changes.put("disabled-start",e->e.torPolicy.put("start_layer","aes-256-gcm"));
  changes.put("wrong-transport",e->e.torTransport="exec");changes.put("injection",e->e.torBridges.set(0,OBFS+"\nSocksPort 0.0.0.0:9050"));
  for(var test:changes.entrySet()){AndroidStandardExitStore.Entry e=tor("obfs4","tcp");test.getValue().apply(e);reject(dir,test.getKey(),e,null,"direct");}
  for(String kind:new String[]{"tor","obfs4"}){
   AndroidStandardExitStore.Entry e=tor(kind,"tcp");
   if(kind.equals("tor")){e.torTransport="obfs4";e.torBridges.add(OBFS);}else e.torBridges.clear();
   reject(dir,"bridge settings must not disappear",e,null,"direct");
  }
 }
 static void jumboPaths(Path dir,String certificate)throws Exception{
  for(String kind:new String[]{"direct-jumbo","default-jumbo","exit-fixed","entry-jumbo","entry-fixed"})for(String mode:new String[]{"shadowsocks","wg"}){
   boolean inherited=kind.startsWith("entry-");JSONObject source=inherited?entry(mode,"off",certificate):null;
   if(source!=null){JSONObject p=profile(source);p.put("mtu_policy",kind.equals("entry-fixed")?"fixed":"auto").put("manual_mtu",9000).put("jumbo_tun",kind.equals("entry-jumbo"));}
   AndroidStandardExitStore.Entry selected=tor("obfs4","doh");String exitMode=kind.equals("default-jumbo")?"default":kind.equals("exit-fixed")?"fixed":"auto";
   selected.torPolicy.put("mtu_policy",exitMode).put("manual_mtu",kind.equals("exit-fixed")?9000:8192).put("jumbo_tun",!inherited&&!kind.equals("exit-fixed"));
   // The predecessor's existing Jumbo capability remains authoritative. A
   // raw packet-entry Jumbo request must not be silently converted to Fixed.
   if(kind.equals("entry-jumbo")&&mode.equals("wg")){reject(dir,"raw WireGuard entry Jumbo remains incompatible",selected,source,mode);continue;}
   Path app=Files.createTempDirectory(dir,"jumbo-");File file=source==null?null:save(dir,source);byte[] before=file==null?null:Files.readAllBytes(file.toPath());String saved=AndroidStandardExitStore.snapshot(selected);
   NativeSingBoxController.SessionInfo prepared=AndroidTorProfile.prepare(new Context(app.toFile()),file,selected,source==null?"direct":mode);Path staged=app.resolve("layered-sessions").resolve(prepared.sessionId);
   JSONObject graph=load(staged.resolve("sing-box.json")),metadata=load(staged.resolve(AndroidTorProfile.SESSION_FILE));JSONArray inbounds=graph.getJSONArray("inbounds");
   check(inbounds.length()==1&&inbounds.getJSONObject(0).getInt("mtu")==9000,"Jumbo path replaced or downsized its single OS interface: "+kind+"/"+mode);
   JSONObject exit=metadata.getJSONObject("tor_profile");check(exit.getString("mtu_policy").equals(exitMode)&&exit.getBoolean("jumbo_tun")==selected.torPolicy.getBoolean("jumbo_tun"),"effective inherited capacity relabelled saved exit policy");
   if(inherited){check(same(metadata.getJSONObject("predecessor_profile"),profile(source)),"Jumbo inherited another entry policy");JSONObject previous=new JSONObject(io.nekohasekai.libbox.Libbox.lastTorPredecessor);check(previous.getJSONArray("inbounds").getJSONObject(0).getInt("mtu")==9000,"inherited Jumbo fixture never built the captured predecessor TUN");if(mode.equals("wg"))check(byTag(graph,"proxy").getInt("mtu")<=1500,"virtual Jumbo became a WireGuard wire MTU");}
   check(saved.equals(AndroidStandardExitStore.snapshot(selected))&&(file==null||Arrays.equals(before,Files.readAllBytes(file.toPath()))),"Jumbo compilation rewrote a saved private profile");
  }
  for(String mismatch:new String[]{"fixed-entry","jumbo-entry","fixed-exit"}){
   JSONObject source=entry("shadowsocks","off",certificate);AndroidStandardExitStore.Entry selected=tor("obfs4","tcp");
   if(mismatch.equals("fixed-entry"))selected.torPolicy.put("jumbo_tun",true).put("mtu_policy","auto");
   else if(mismatch.equals("jumbo-entry"))profile(source).put("mtu_policy","auto").put("jumbo_tun",true);
   else selected.torPolicy.put("manual_mtu",1400);
   reject(dir,"captured Jumbo/Fixed conflict "+mismatch,selected,source,"shadowsocks");
  }
 }
 static void entryNegatives(Path dir,String certificate)throws Exception{
  for(String mode:ALL){
   for(String fault:new String[]{"selection","duplicate","proof","foreign-node","missing-assets","start-layer","helper"}){
    JSONObject b=entry(mode,"off",certificate);
    switch(fault){
     case "selection":b.put("selectedRouterID","missing");break;
     case "duplicate":b.getJSONArray("routerProfiles").put(new JSONObject(profile(b).toString()));break;
     case "proof":profile(b).put("node_proof_id","f".repeat(64));break;
     case "foreign-node":profile(b).put("node_kind","external");break;
     case "missing-assets":b.getJSONObject("profiles").remove(mode);break;
     case "start-layer":profile(b).put("start_layer","xor");break;
     case "helper":b.getJSONObject("profiles").getJSONObject(mode).put("run.sh",enc("unowned executable"));break;
    }
    reject(dir,mode+"/"+fault,tor("obfs4","tcp"),b,mode);
   }
  }
  reject(dir,"unknown raw entry",tor("obfs4","tcp"),entry("wg","off",certificate),"wg-unknown");
 }
 static void staleAndSessionNegatives(Path dir,String certificate)throws Exception{
  for(String mode:new String[]{"direct","wg-pq","hysteria2","naive-h3","max-tls-wg","split"}){
   for(String fault:new String[]{"native","install","cancel","exit-change","entry-change","write"}){
    if(mode.equals("direct")&&fault.equals("entry-change"))continue;
    Path app=Files.createTempDirectory(dir,"stale-");JSONObject b=mode.equals("direct")?null:entry(mode,"aes-256-gcm+xor-whitening",certificate);
    File file=b==null?null:save(dir,b);AndroidStandardExitStore.Entry e=tor("obfs4","tcp");
    if(fault.equals("native"))io.nekohasekai.libbox.Libbox.rejectConfig=true;
    if(fault.equals("install"))RouterPQNative.fail=true;
    if(fault.equals("write"))AndroidPrivateFileStore.failName=AndroidTorProfile.SESSION_FILE;
    io.nekohasekai.libbox.Libbox.afterCheck=()->{try{
     if(fault.equals("cancel"))Thread.currentThread().interrupt();
     if(fault.equals("exit-change"))e.torPolicy.put("dns_host","8.8.8.8");
     if(fault.equals("entry-change"))Files.writeString(file.toPath(),"{}");
    }catch(Exception error){throw new RuntimeException(error);}};
    boolean rejected=false;try{AndroidTorProfile.prepare(new Context(app.toFile()),file,e,mode);}catch(Exception expected){rejected=true;}
    finally{Thread.interrupted();io.nekohasekai.libbox.Libbox.afterCheck=null;io.nekohasekai.libbox.Libbox.rejectConfig=false;RouterPQNative.fail=false;AndroidPrivateFileStore.failName=null;}
    check(rejected&&sessions(app)==0,"changed/cancelled/failed Tor capture staged: "+mode+"/"+fault);
   }
  }
  Path app=Files.createTempDirectory(dir,"session-owner-");NativeSingBoxController.SessionInfo info=AndroidTorProfile.prepare(new Context(app.toFile()),null,tor("obfs4","tcp"),"direct");
  Path staged=app.resolve("layered-sessions").resolve(info.sessionId);
  String raw=Files.readString(staged.resolve("sing-box.json")),metaRaw=Files.readString(staged.resolve(AndroidTorProfile.SESSION_FILE));
  for(String fault:new String[]{"digest","session","version","protocol","final","tor-session","tor-tag","extra-tor","extra-tun","lost-tun","mode","lost-profile","profile-id","profile-protocol"}){
   JSONObject graph=new JSONObject(raw),meta=new JSONObject(metaRaw);String mode=info.modeId;
   switch(fault){
    case "digest":meta.put("config_sha256","0".repeat(64));break;
    case "session":meta.put("session_id","another-session");break;
    case "version":meta.put("version",2);break;
    case "protocol":meta.put("protocol","socks5");break;
    case "final":graph.getJSONObject("route").put("final","direct");break;
    case "tor-session":byTag(graph,AndroidTorProfile.OUTBOUND).put("session_id","other");break;
    case "tor-tag":byTag(graph,AndroidTorProfile.OUTBOUND).put("tag","other");break;
    case "extra-tor":graph.getJSONArray("outbounds").put(new JSONObject(byTag(graph,AndroidTorProfile.OUTBOUND).toString()).put("tag","second"));break;
    case "extra-tun":graph.getJSONArray("inbounds").put(new JSONObject(graph.getJSONArray("inbounds").getJSONObject(0).toString()));break;
    case "lost-tun":graph.getJSONArray("inbounds").getJSONObject(0).put("type","mixed");break;
    case "mode":mode="standard-direct-socks5";break;
    case "lost-profile":meta.remove("tor_profile");break;
    case "profile-id":meta.getJSONObject("tor_profile").put("id","another-exit");break;
    case "profile-protocol":meta.getJSONObject("tor_profile").getJSONObject("external").put("protocol","socks5");break;
   }
   String changed=graph.toString();if(!fault.equals("digest"))meta.put("config_sha256",AndroidTorProfile.digest(changed.getBytes(StandardCharsets.UTF_8)));
   boolean rejected=false;try{AndroidTorProfile.session(changed,meta.toString(),info.sessionId,mode);}catch(Exception expected){rejected=true;}
   check(rejected,"Tor session accepted changed owner: "+fault);
  }
 }
 static void capturedProtection(Path root)throws Exception{
  for(boolean enabled:new boolean[]{false,true}){
   Path directory=Files.createTempDirectory(root,"tor-protection-");AndroidStandardExitStore.Entry saved=tor("tor","tcp");saved.torPolicy=AndroidExternalProtection.withChoice(saved.torPolicy,enabled);String source=AndroidStandardExitStore.snapshot(saved);
   NativeSingBoxController.SessionInfo session=AndroidTorProfile.prepare(new Context(directory.toFile()),null,saved,"direct");Path folder=directory.resolve("layered-sessions").resolve(session.sessionId);
   JSONObject metadata=AndroidTorProfile.session(Files.readString(folder.resolve("sing-box.json")),Files.readString(folder.resolve(AndroidTorProfile.SESSION_FILE)),session.sessionId,session.modeId);
   check(metadata.getJSONObject("tor_profile").getBoolean("kill_switch")==enabled&&AndroidExternalProtection.torCapture(metadata)==enabled,"actual Tor compiler lost explicit captured protection");
   check(Files.exists(folder.resolve(AndroidKillSwitchPolicy.SESSION_MARKER))==enabled&&source.equals(AndroidStandardExitStore.snapshot(saved)),"Tor protection staging changed saved policy or explicit Off");
  }
 }
 static void paddingPaths(Path dir,String certificate)throws Exception{
  int padded=0;
  for(String mode:new String[]{"direct","wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg","ss-v2ray","split","max","naive-h2","naive-h3"})for(String kind:new String[]{"tor","obfs4"})for(int rate:new int[]{0,32,64,192}){
   Path app=Files.createTempDirectory(dir,"padding-");JSONObject predecessor=mode.equals("direct")?null:entry(mode,"off",certificate);File file=predecessor==null?null:save(dir,predecessor);
   AndroidStandardExitStore.Entry saved=tor(kind,"doh");saved.torPolicy.put("daita_enabled",true).put("daita_rate_kbps",rate);String snapshot=AndroidStandardExitStore.snapshot(saved);byte[] entryBefore=file==null?null:Files.readAllBytes(file.toPath());
   NativeSingBoxController.SessionInfo info=AndroidTorProfile.prepare(new Context(app.toFile()),file,saved,mode);Path staged=app.resolve("layered-sessions").resolve(info.sessionId);
   String raw=Files.readString(staged.resolve("sing-box.json")),metadata=Files.readString(staged.resolve(AndroidTorProfile.SESSION_FILE));JSONObject graph=new JSONObject(raw),meta=AndroidTorProfile.session(raw,metadata,info.sessionId,info.modeId),profile=meta.getJSONObject("tor_profile");
   check(profile.getBoolean("daita_enabled")&&profile.getInt("daita_rate_kbps")==rate,"Local Tor padding changed its saved/default rate");
   JSONObject source=byTag(graph,AndroidTorProfile.OUTBOUND).getJSONObject("padding_source");
   check(same(new JSONObject(source.getString("profile")),profile),"native padding source lost the captured selected Tor policy");
   String expected=io.nekohasekai.libbox.Libbox.routerTorPaddingSource(raw,profile.toString(),info.sessionId);
   check(expected.matches("[0-9a-f]{64}")&&expected.equals(io.nekohasekai.libbox.Libbox.routerTorPaddingSource(new JSONObject(raw).toString(),profile.toString(),info.sessionId)),"canonical padding source digest differs across formatting");
   check(snapshot.equals(AndroidStandardExitStore.snapshot(saved))&&(file==null||Arrays.equals(entryBefore,Files.readAllBytes(file.toPath()))),"padding preparation rewrote saved credentials or policy");
   for(String fault:new String[]{"source-profile","source-entry","lost-source","config","metadata-policy","metadata-session"}){
    JSONObject changed=new JSONObject(raw),owner=new JSONObject(metadata),outbound=byTag(changed,AndroidTorProfile.OUTBOUND);JSONObject captured=outbound.getJSONObject("padding_source");
    if(fault.equals("source-profile"))captured.put("profile",new JSONObject(captured.getString("profile")).put("daita_rate_kbps",rate==32?64:32).toString());
    if(fault.equals("source-entry"))captured.put("predecessor_config","{}");
    if(fault.equals("lost-source"))outbound.remove("padding_source");
    if(fault.equals("config"))changed.getJSONObject("route").put("auto_detect_interface",false);
    if(fault.equals("metadata-policy"))owner.getJSONObject("tor_profile").put("daita_enabled",false);
    if(fault.equals("metadata-session"))outbound.put("session_id","different-padding-owner");
    owner.put("config_sha256",AndroidTorProfile.digest(changed.toString().getBytes(StandardCharsets.UTF_8)));
    boolean rejected=false;try{AndroidTorProfile.session(changed.toString(),owner.toString(),info.sessionId,info.modeId);}catch(Exception expectedFailure){rejected=true;}
    check(rejected,"recomputed outer hash admitted changed padding source: "+mode+"/"+fault);
   }
   String output=System.getenv("ROUTERVPN_ANDROID_LOCAL_PADDING_GRAPHS");if(output!=null&&!output.isEmpty())Files.writeString(Path.of(output).resolve(String.format("padding-%03d.json",padded)),raw,StandardOpenOption.CREATE_NEW);
   padded++;
  }
  check(padded==160,"Local padding direct/private entry and rate matrix incomplete");
  System.out.println("Android Local Tor padding compiler: PASS ("+padded+" shipping Java/Go captures; "+checks+" source/policy/session checks; actual production admission)");
 }
 public static void main(String[] args)throws Exception{
  Path dir=Path.of(args[0]);fixtures=load(Path.of(System.getenv("ROUTERVPN_MAX_MULTIHOP_FIXTURES")));
  compositeEntry=load(Path.of(System.getenv("ROUTERVPN_COMPOSITE_ENTRY")));compositeExit=load(Path.of(System.getenv("ROUTERVPN_COMPOSITE_EXIT")));
  String certificate=io.nekohasekai.libbox.Libbox.testCertificate("entry.example.test");
  if(args.length>1&&args[1].equals("padding-only")){paddingPaths(dir,certificate);return;}
  if(args.length>1&&args[1].equals("capacity-only")){jumboPaths(dir,certificate);return;}
  for(String kind:KINDS){
   verify(dir,"direct","off",kind,"tcp",certificate);
   for(String mode:ALL){check(NativeSingBoxController.nativeMultihopEntry(mode),"captured Tor entry absent from native catalog");for(int i=0;i<LAYERS.length;i++)verify(dir,mode,LAYERS[i],kind,new String[]{"tcp","dot","doh"}[i],certificate);}
  }
  check(graphs==348,"Tor entry/Start Layer/bridge matrix incomplete");
  homePaths(dir,certificate);policyNegatives(dir);jumboPaths(dir,certificate);entryNegatives(dir,certificate);staleAndSessionNegatives(dir,certificate);capturedProtection(dir);
  System.out.println("Android Tor: PASS ("+graphs+" shipping Java/Go graphs; "+checks+" checks; OS/startup doubled, native Tor traffic separate)");
 }
}
'''

GO = P.GO.replace('"router-vpn/internal/mobileperf"', '"router-vpn/internal/mobileperf";"router-vpn/internal/mobiletor";privateparse "router-vpn/internal/nativeopenvpn"', 1)
GO = GO.replace('case "xray-policy":', '''case "private-node-json":err=privateparse.ValidatePrivateNodeJSON(r.Config);value="checked"
 case "tor-validate":err=mobiletor.ValidateProfile(r.Config);value="validated"
 case "tor-padding-source":
  var input struct{Profile string;Session string};err=json.Unmarshal([]byte(r.Config),&input)
  if err==nil{value,err=mobiletor.LocalPaddingSourceSHA256(r.Policy,input.Profile,input.Session)}
 case "tor-external-profile-captured":
  var input struct{Profile string;Session string;Entry string};err=json.Unmarshal([]byte(r.Config),&input)
  if err==nil{value,err=mobiletor.CompileProfileWithExternalPredecessor(input.Profile,input.Session,r.Policy,input.Entry)}
 case "tor-profile-captured":
  var input struct{Profile string;Session string;Entry string};err=json.Unmarshal([]byte(r.Config),&input)
  if err==nil{value,err=mobiletor.CompileProfileWithPredecessor(input.Profile,input.Session,r.Policy,input.Entry)}
 case "tor-server-profile-captured":
  var input struct{Profile string;Session string;Entry string};err=json.Unmarshal([]byte(r.Config),&input)
  if err==nil{value,err=mobiletor.CompileServerProfileWithPredecessor(input.Profile,input.Session,r.Policy,input.Entry)}
 case "tor-profile":
  var input struct{Profile string;Session string};err=json.Unmarshal([]byte(r.Config),&input)
  if err==nil{value,err=mobiletor.CompileProfile(input.Profile,input.Session,r.Policy)}
 case "tor-predecessor":_,err=mobiletor.NewPredecessorProof(r.Config);value="checked"
 case "xray-policy":''', 1)

TOR_BOUNDARIES = r'''
final class AndroidVpnMutationGuard {static boolean isBusy(android.content.Context c){return false;}}
final class AndroidRuntimeRegistry {
 static final class Engine{String getState(){return "STOPPED";}boolean isRunning(){return false;}boolean isActiveOrTransitioning(){return false;}}
 final Engine orchestrator=new Engine(),multihop=new Engine(),singBox=new Engine(),xray=new Engine();
 static AndroidRuntimeRegistry get(android.content.Context c){return new AndroidRuntimeRegistry();}
}
final class AndroidOpenVPN {static void validateResponseProbes(AndroidStandardExitStore.Entry entry){if(entry.openVPNResponseProbes!=null||entry.openVPNStartLayers!=null)throw new AssertionError("OpenVPN response map is outside this non-OpenVPN fixture");}static void validatePairing(AndroidStandardExitStore.Entry entry){if(entry.openVPNPairing!=null)throw new AssertionError("OpenVPN pairing is outside this non-OpenVPN fixture");}
 static JSONObject endpoint(AndroidStandardExitStore.Entry e,String value){throw new AssertionError("Tor must not invoke OpenVPN");}
}
'''


def build_padding_policy(go_dir, native):
    """Exercise complete enabled captures through the production compiler."""
    subprocess.run(["go", "build", "-o", str(native), str(go_dir / "main.go")],
                   cwd=ROOT, check=True, timeout=90)


def run():
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file():
        raise RuntimeError("Android JSON implementation required")
    with tempfile.TemporaryDirectory(prefix=".tor-java-policy-", dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix="android-tor-profile-") as work:
        go_dir, work = Path(go_dir), Path(work)
        (go_dir / "main.go").write_text(GO)
        native = work / "policy"
        subprocess.run(["go", "build", "-o", str(native), str(go_dir / "main.go")], cwd=ROOT, check=True, timeout=90)
        src = work / "src"
        for path, text in P.M.STUBS.items():
            if path.endswith("/Boundaries.java"):
                # Exact shipping public-key identity and bundle validation,
                # excluding Android's unrelated preference/storage handles.
                source = (JAVA / "AndroidNodeStore.java").read_text()
                methods = source[source.index("    static String stableNodeIdentity("):source.index("    static String deriveId(")]
                methods += source[source.index("    private static String wireGuardPeerPublicKey("):source.index("    private static JSONObject load(")]
                methods += next(line for line in source.splitlines() if "private static String hex(byte[] data)" in line)
                constants = "\n".join(line for line in source.splitlines() if any(part in line for part in ("private static final String NODE_PROOF_DOMAIN =", "static final int MAX_PROFILE_SCHEMA =", "static final int MAX_BUNDLE =")))
                start, end = text.index("final class AndroidNodeStore {"), text.index("final class AndroidKillSwitchPolicy {")
                external_boundary = "" if "AndroidExternalPolicy" in EXTRA_SOURCES else EXTERNAL_BOUNDARY
                text = text[:start] + "final class AndroidNodeStore {\n" + constants + "\n" + methods + "\n}\n" + text[end:] + TOR_BOUNDARIES + external_boundary
                text = text.replace("import org.json.JSONObject;", "import org.json.JSONObject; import org.json.JSONArray; import java.security.MessageDigest; import java.nio.charset.StandardCharsets; import android.util.Base64;")
            if path.endswith("/Libbox.java"):
                begin = text.index(" private static String call(")
                end = text.index(" public static String routerCompilePQProfile(", begin)
                text = text[:begin] + P.PIPE_CALL + text[end:]
                text = text.replace(" public static boolean rejectConfig;", " public static Runnable afterCheck;\n public static boolean rejectConfig;")
                text = text.replace("new JSONObject(c);}", "new JSONObject(c);if(afterCheck!=null)afterCheck.run();}")
                text = text.replace(" public static String routerCompilePQProfile(", r'''
 public static void routerValidatePrivateNodeJSON(String raw)throws Exception{call("private-node-json",raw,"");}
 public static int torCalls;
 public static String lastTorPredecessor="";
 public static String routerCompileTorProfile(String profile,String session,String predecessor)throws Exception{
  torCalls++;lastTorPredecessor=predecessor;
  return call("tor-profile",new JSONObject().put("Profile",profile).put("Session",session).toString(),predecessor);
 }
 public static void routerValidateTorProfile(String profile)throws Exception{call("tor-validate",profile,"");}
 public static String routerTorPaddingSource(String config,String profile,String session)throws Exception{return call("tor-padding-source",new JSONObject().put("Profile",profile).put("Session",session).toString(),config);}
 public static String routerCompileTorProfileWithPredecessor(String profile,String session,String predecessor,String entry)throws Exception{
  torCalls++;lastTorPredecessor=predecessor;
  return call("tor-profile-captured",new JSONObject().put("Profile",profile).put("Session",session).put("Entry",entry).toString(),predecessor);
 }
 public static String routerCompileTorProfileWithExternalPredecessor(String profile,String session,String predecessor,String entry)throws Exception{
  torCalls++;lastTorPredecessor=predecessor;
  return call("tor-external-profile-captured",new JSONObject().put("Profile",profile).put("Session",session).put("Entry",entry).toString(),predecessor);
 }
 public static String routerCompileServerTorProfileWithPredecessor(String profile,String session,String predecessor,String entry)throws Exception{
  torCalls++;lastTorPredecessor=predecessor;
  return call("tor-server-profile-captured",new JSONObject().put("Profile",profile).put("Session",session).put("Entry",entry).toString(),predecessor);
 }
 public static String testTorPredecessor(String profile)throws Exception{return call("tor-predecessor",profile,"");}
 public static String routerCompilePQProfile(''', 1)
            target = src / path
            if path.endswith("/Libbox.java") and EXTRA_LIBBOX:
                end=text.rfind("}");text=text[:end]+EXTRA_LIBBOX+text[end:]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        app = src / "com/eabusham/routervpn"
        for name in ("AndroidExternalProtection", "AndroidMultihopController", "NativeSingBoxController", "AndroidNativeMAXProfile", "AndroidNativeCompositeProfile", "AndroidProfileSelection", "AndroidNumericAddress", "AndroidNativeProfilePolicy", "AndroidWireGuardLibboxPolicy", "AndroidStartLayer", "AndroidXrayLibboxPolicy", "NativeXrayController", "AndroidMultihopStartLayer", "AndroidTorProfile", "AndroidStandardExitStore", "AndroidExternalAmnezia") + EXTRA_SOURCES:
            shutil.copyfile(JAVA / (name + ".java"), app / (name + ".java"))
        (app / "MultihopGraphHarness.java").write_text(P.M.HARNESS)
        (app / "PQSelectionHarness.java").write_text(HARNESS)
        subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(work / "classes"), *map(str, src.rglob("*.java"))], check=True, timeout=60)
        data = work / "data"
        data.mkdir()
        run_args=["java", "-cp", str(work / "classes") + os.pathsep + str(jar), "com.eabusham.routervpn.PQSelectionHarness", str(data)]
        environment=dict(os.environ, ROUTERVPN_GO_POLICY_TEST=str(native))
        subprocess.run(run_args, env=environment, check=True, timeout=180)
        # The capacity checks exercise the shipping preparation and real Go
        # compiler, including a real Fixed predecessor and explicit Jumbo.
        if 'if(args.length>1&&args[1].equals("capacity-only"))' in HARNESS:
            target=app/"AndroidTorProfile.java";original=target.read_text()
            for before,after,label in (
                ("applyCapturedEntryMTU(predecessorProfile, graph);", "", "captured entry Fixed application"),
                ("result.put(key, policy.get(key));", 'if(!key.equals("jumbo_tun"))result.put(key, policy.get(key));', "explicit saved Jumbo retention"),
            ):
                if original.count(before)!=1:raise AssertionError("Missing native capacity mutation: "+label)
                target.write_text(original.replace(before,after))
                subprocess.run(["javac","--release","17","-encoding","UTF-8","-proc:none","-cp",str(work/"classes")+os.pathsep+str(jar),"-d",str(work/"classes"),str(target)],check=True,timeout=45)
                result=subprocess.run(run_args+["capacity-only"],env=environment,text=True,capture_output=True,timeout=45)
                if result.returncode==0 or not any(marker in result.stderr for marker in ("AssertionError", "captured entry MTU policy")):
                    raise AssertionError("Capacity mutation was not rejected: "+label+"\n"+result.stderr)
                target.write_text(original)
            print("Android Tor capacity negative controls: 2 rejected by real compiler/host preparation")
            subprocess.run(["javac","--release","17","-encoding","UTF-8","-proc:none","-cp",str(work/"classes")+os.pathsep+str(jar),"-d",str(work/"classes"),str(target)],check=True,timeout=45)
        if 'if(args.length>1&&args[1].equals("padding-only"))' in HARNESS:
            enabled = work / "padding-policy"
            build_padding_policy(go_dir, enabled)
            subprocess.run(run_args+["padding-only"],env=dict(os.environ,ROUTERVPN_GO_POLICY_TEST=str(enabled)),check=True,timeout=180)


def main():
    for variable in ("ROUTERVPN_ANDROID_TOR_GRAPHS", "ROUTERVPN_ANDROID_LOCAL_PADDING_GRAPHS"):
        output = os.environ.get(variable)
        if output:
            folder = Path(output)
            if folder.is_symlink() or not folder.is_dir() or any(folder.iterdir()):
                raise RuntimeError("Tor parser fixtures require an existing empty owned directory")
    P.run = run
    C.main()


if __name__ == "__main__":
    main()
