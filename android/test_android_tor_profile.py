#!/usr/bin/env python3
"""Execute Android Tor capture/staging with shipping Java and real Go compilers.

The Android OS, private-file syscalls and Libbox startup are boundary doubles.
The selected nodes, compiler calls, Tor bridge grammar, store serialization and
session validation are production code. No Tor network or remote node is used.
Set ROUTERVPN_ANDROID_TOR_GRAPHS to an empty directory for the native parser gate.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
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
  boolean packet=NativeSingBoxController.nativeWireGuardFamily(mode)||NativeSingBoxController.nativePQFamily(mode)||AndroidNativeMAXProfile.isMode(mode);
  profile(b).put("mtu_policy","fixed").put("manual_mtu",packet?1500:1280)
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
 static void capturedEntry(JSONObject graph,JSONObject previous,JSONObject source,String mode,String layer,String certificate)throws Exception{
  int expected=1;
  for(String family:new String[]{"endpoints","outbounds"}){
   JSONArray rows=previous.optJSONArray(family);if(rows==null)continue;expected+=rows.length();
   for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);
    check(same(row,byTag(graph,row.getString("tag"))),"Tor changed a predecessor key, lane or routing owner");
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
  for(String fault:new String[]{"digest","session","version","protocol","final","tor-session","tor-tag","extra-tor","extra-tun","lost-tun","mode"}){
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
   }
   String changed=graph.toString();if(!fault.equals("digest"))meta.put("config_sha256",AndroidTorProfile.digest(changed.getBytes(StandardCharsets.UTF_8)));
   boolean rejected=false;try{AndroidTorProfile.session(changed,meta.toString(),info.sessionId,mode);}catch(Exception expected){rejected=true;}
   check(rejected,"Tor session accepted changed owner: "+fault);
  }
 }
 public static void main(String[] args)throws Exception{
  Path dir=Path.of(args[0]);fixtures=load(Path.of(System.getenv("ROUTERVPN_MAX_MULTIHOP_FIXTURES")));
  compositeEntry=load(Path.of(System.getenv("ROUTERVPN_COMPOSITE_ENTRY")));compositeExit=load(Path.of(System.getenv("ROUTERVPN_COMPOSITE_EXIT")));
  String certificate=io.nekohasekai.libbox.Libbox.testCertificate("entry.example.test");
  for(String kind:KINDS){
   verify(dir,"direct","off",kind,"tcp",certificate);
   for(String mode:ALL){check(NativeSingBoxController.nativeMultihopEntry(mode),"captured Tor entry absent from native catalog");for(int i=0;i<LAYERS.length;i++)verify(dir,mode,LAYERS[i],kind,new String[]{"tcp","dot","doh"}[i],certificate);}
  }
  check(graphs==348,"Tor entry/Start Layer/bridge matrix incomplete");
  policyNegatives(dir);entryNegatives(dir,certificate);staleAndSessionNegatives(dir,certificate);
  System.out.println("Android Tor: PASS ("+graphs+" shipping Java/Go graphs; "+checks+" checks; OS/startup doubled, native Tor traffic separate)");
 }
}
'''

GO = P.GO.replace('"router-vpn/internal/mobileperf"', '"router-vpn/internal/mobileperf";"router-vpn/internal/mobiletor"', 1)
GO = GO.replace('case "xray-policy":', '''case "tor-profile":
  var input struct{Profile string;Session string};err=json.Unmarshal([]byte(r.Config),&input)
  if err==nil{value,err=mobiletor.CompileProfile(input.Profile,input.Session,r.Policy)}
 case "tor-predecessor":_,err=mobiletor.NewPredecessorProof(r.Config);value="checked"
 case "xray-policy":''', 1)

TOR_BOUNDARIES = r'''
final class AndroidPrivateFileStore {
 static String failName;
 static byte[] read(java.io.File file,int maximum)throws Exception{
  if(file==null||!java.nio.file.Files.isRegularFile(file.toPath(),java.nio.file.LinkOption.NOFOLLOW_LINKS)||java.nio.file.Files.size(file.toPath())<=0||java.nio.file.Files.size(file.toPath())>maximum)throw new java.io.IOException("Invalid bounded private fixture");
  return java.nio.file.Files.readAllBytes(file.toPath());
 }
 static void write(java.io.File file,byte[] data,int maximum)throws Exception{
  if(file.getName().equals(failName))throw new java.io.IOException("Injected private staging failure");
  if(data==null||data.length==0||data.length>maximum)throw new java.io.IOException("Invalid bounded private fixture");
  java.nio.file.Files.createDirectories(file.toPath().getParent());java.nio.file.Files.write(file.toPath(),data);
 }
}
final class AndroidVpnMutationGuard {static boolean isBusy(android.content.Context c){return false;}}
final class AndroidHomeStateStore {
 static final class Snapshot{boolean connected;String phase="idle";}
 static Snapshot snapshot(android.content.Context c){return new Snapshot();}
}
final class AndroidRuntimeRegistry {
 static final class Engine{String getState(){return "STOPPED";}boolean isRunning(){return false;}boolean isActiveOrTransitioning(){return false;}}
 final Engine orchestrator=new Engine(),multihop=new Engine(),singBox=new Engine(),xray=new Engine();
 static AndroidRuntimeRegistry get(android.content.Context c){return new AndroidRuntimeRegistry();}
}
final class AndroidOpenVPN {
 static JSONObject endpoint(AndroidStandardExitStore.Entry e,String value){throw new AssertionError("Tor must not invoke OpenVPN");}
}
'''


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
                text = text[:start] + "final class AndroidNodeStore {\n" + constants + "\n" + methods + "\n}\n" + text[end:] + TOR_BOUNDARIES
                text = text.replace("import org.json.JSONObject;", "import org.json.JSONObject; import org.json.JSONArray; import java.security.MessageDigest; import java.nio.charset.StandardCharsets; import android.util.Base64;")
            if path.endswith("/Libbox.java"):
                begin = text.index(" private static String call(")
                end = text.index(" public static String routerCompilePQProfile(", begin)
                text = text[:begin] + P.PIPE_CALL + text[end:]
                text = text.replace(" public static boolean rejectConfig;", " public static Runnable afterCheck;\n public static boolean rejectConfig;")
                text = text.replace("new JSONObject(c);}", "new JSONObject(c);if(afterCheck!=null)afterCheck.run();}")
                text = text.replace(" public static String routerCompilePQProfile(", r'''
 public static int torCalls;
 public static String lastTorPredecessor="";
 public static String routerCompileTorProfile(String profile,String session,String predecessor)throws Exception{
  torCalls++;lastTorPredecessor=predecessor;
  return call("tor-profile",new JSONObject().put("Profile",profile).put("Session",session).toString(),predecessor);
 }
 public static String testTorPredecessor(String profile)throws Exception{return call("tor-predecessor",profile,"");}
 public static String routerCompilePQProfile(''', 1)
            target = src / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        app = src / "com/eabusham/routervpn"
        for name in ("AndroidMultihopController", "NativeSingBoxController", "AndroidNativeMAXProfile", "AndroidNativeCompositeProfile", "AndroidProfileSelection", "AndroidNumericAddress", "AndroidNativeProfilePolicy", "AndroidWireGuardLibboxPolicy", "AndroidStartLayer", "AndroidXrayLibboxPolicy", "NativeXrayController", "AndroidMultihopStartLayer", "AndroidTorProfile", "AndroidStandardExitStore"):
            shutil.copyfile(JAVA / (name + ".java"), app / (name + ".java"))
        (app / "MultihopGraphHarness.java").write_text(P.M.HARNESS)
        (app / "PQSelectionHarness.java").write_text(HARNESS)
        subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(work / "classes"), *map(str, src.rglob("*.java"))], check=True, timeout=60)
        data = work / "data"
        data.mkdir()
        subprocess.run(["java", "-cp", str(work / "classes") + os.pathsep + str(jar), "com.eabusham.routervpn.PQSelectionHarness", str(data)], env=dict(os.environ, ROUTERVPN_GO_POLICY_TEST=str(native)), check=True, timeout=180)


def main():
    output = os.environ.get("ROUTERVPN_ANDROID_TOR_GRAPHS")
    if output:
        folder = Path(output)
        if folder.is_symlink() or not folder.is_dir() or any(folder.iterdir()):
            raise RuntimeError("Tor parser fixtures require an existing empty owned directory")
    P.run = run
    C.main()


if __name__ == "__main__":
    main()
