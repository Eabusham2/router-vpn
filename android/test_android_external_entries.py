#!/usr/bin/env python3
"""Execute complete captured Android entry graphs before ordinary external exits.

The shipping Java assemblers and shared Go compilers run unchanged. Android
handles and native startup are doubled; exported graphs feed the native parser
gate separately. No device network or provider acceptance is claimed here.
"""
from pathlib import Path
import argparse
import importlib.util
import os

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("external_entry_fixture", ROOT / "android/test_android_tor_profile.py")
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
T.EXTRA_SOURCES = ("AndroidExternalPolicy", "AndroidExternalEntry", "AndroidDirectStandardExitController", "AndroidStandardExitController", "AndroidOpenVPN")
T.TOR_BOUNDARIES = T.TOR_BOUNDARIES[:T.TOR_BOUNDARIES.index("final class AndroidOpenVPN")]
T.EXTRA_LIBBOX = r'''
 public static String version(){return "1.14.1";}
 public static void routerValidateExternalOpenVPNResponseProbes(String profile,String probes)throws Exception{call("external-openvpn-probes",profile,probes);}
 public static void routerValidateExternalOpenVPNPairing(String profile,String pairing)throws Exception{call("external-openvpn-pairing",profile,pairing);}
 public static String routerPrepareExternalExecutionCapture(String source,String capture,String restored)throws Exception{return call("external-execution",source,new JSONObject().put("capture",capture).put("restored",restored).toString());}
 public static String routerCompileExternalPolicy(String source,String capture)throws Exception{return call("external-policy",source,capture);}
 public static void routerValidateExternalTransport(String source,String capture)throws Exception{call("external-transport",source,capture);}public static void routerValidateExternalDNS(String profile,String entry)throws Exception{call("external-dns",profile,entry);}public static void routerValidateExternalResponseProbe(String host,String probe)throws Exception{call("external-response",host,probe);}
 public static String routerOpenVPNEndpoint(String config,String username,String password,String tag,String detour)throws Exception{return call("external-openvpn",new JSONObject().put("config",config).put("username",username).put("password",password).put("tag",tag).put("detour",detour).toString(),"");}
'''
T.GO = T.GO.replace('"router-vpn/internal/mobiletor"', '"router-vpn/internal/mobiletor";nativeopenvpn "router-vpn/mobile"', 1)
T.GO = T.GO.replace('case "tor-profile":', '''case "external-openvpn":
  var p struct{Config,Username,Password,Tag,Detour string};err=json.Unmarshal([]byte(r.Config),&p)
  if err==nil{value,err=nativeopenvpn.RouterOpenVPNEndpoint(p.Config,p.Username,p.Password,p.Tag,p.Detour)}
 case "external-openvpn-probes":err=nativeopenvpn.RouterValidateExternalOpenVPNResponseProbes(r.Config,r.Policy)
 case "external-openvpn-pairing":err=nativeopenvpn.RouterValidateExternalOpenVPNPairing(r.Config,r.Policy)
 case "external-execution":
  var selected struct{Capture,Restored string};err=json.Unmarshal([]byte(r.Policy),&selected)
  if err==nil{value,err=mobilemultihop.PrepareExternalExecutionCapture(r.Config,selected.Capture,selected.Restored)}
 case "external-policy":value,err=mobilemultihop.CompileExternalPolicy(r.Config,r.Policy)
 case "external-transport":err=mobilemultihop.ValidateExternalTransport(r.Config,r.Policy)
 case "external-dns":err=mobilemultihop.ValidateExternalDNS(r.Config,r.Policy)
 case "external-response":err=mobilemultihop.ValidateExternalResponseProbe(r.Config,r.Policy)
 case "tor-profile":''', 1)
T.HARNESS = T.HARNESS[:T.HARNESS.index(" public static void main(")] + r'''
 static boolean sameParams(JSONObject a,JSONObject b)throws Exception{if(a.length()!=11||b.length()!=11)return false;for(String key:AndroidExternalAmnezia.PARAMETERS)if(!a.get(key).equals(b.get(key)))return false;return true;}
 static void paired(AndroidStandardExitStore.Entry exit)throws Exception{
  exit.responseProbe=new JSONObject().put("url","https://203.0.113.50:8443/response").put("server_name","external.example.test");
  if(AndroidStandardExitStore.packetExecutionProtocol(exit.protocol))exit.serverPeer=new JSONObject().put("public_key","bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg=").put("addresses",new JSONArray().put("10.94.0.3/32").put("fd94::3/128")).put("mtu",1360).put("persistent_keepalive_interval",25);
  if(exit.protocol.equals("openvpn")){
   JSONObject external=load(Path.of(System.getenv("ROUTERVPN_OPENVPN_CLIENT_FIXTURE"))).getJSONObject("layers").getJSONObject("off").getJSONObject("external"),original=external.getJSONObject("openvpn");
   exit.openVPNConfig=original.getString("config");exit.username=original.getString("username");exit.password=original.getString("password");exit.openVPNPairing=new JSONObject(external.getJSONObject("openvpn_pairing").toString());exit.responseProbe=new JSONObject(external.getJSONObject("response_probe").toString());exit.server="203.0.113.20";exit.serverPort=1194;exit.expectedPublicIp=external.getString("expected_public_ip");
  }
 }
 static String externalCertificate;static int executionGraphs,layerGraphs,mappedGraphs;
 static AndroidStandardExitStore.Entry external(String kind,String dns)throws Exception{
  AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id="ordinary-"+kind;e.name="Captured "+kind;e.protocol=kind;e.server="203.0.113.50";e.serverPort=443;e.expectedPublicIp="8.8.4.4";e.tlsServerName="exit.example.test";
  String key=MultihopGraphHarness.key('v');
  if(kind.equals("wireguard")||kind.equals("amneziawg")){e.wgPrivateKey=MultihopGraphHarness.key('x');e.wgPeerPublicKey=MultihopGraphHarness.key('w');e.wgAddresses.addAll(java.util.List.of("10.93.0.2/32","fd93::2/128"));e.wgAllowedIps.addAll(java.util.List.of("0.0.0.0/0","::/0"));e.wgMtu=1280;e.wgKeepalive=25;if(kind.equals("amneziawg"))e.awgParameters=new JSONObject().put("jc","3").put("jmin","40").put("jmax","900").put("s1","15").put("s2","16").put("s3","32").put("s4","32").put("h1","100-110").put("h2","200-210").put("h3","300-310").put("h4","400-410");}
  if(kind.equals("socks5")||kind.equals("http")||kind.equals("https")){e.username="exit-only-user";e.password="exit-only-password";}
  if(kind.equals("shadowsocks")){e.method="2022-blake3-aes-256-gcm";e.secret=key;}if(kind.equals("hysteria2"))e.secret="exit-only-hy2";
  if(kind.equals("openvpn")){e.username=" exit-only user ";e.password=" exit-only password ";e.openVPNConfig="client\ndev tun\nproto udp\nremote 203.0.113.50 443\nremote 203.0.113.51 1194 udp\nremote-random\nauth-user-pass\nremote-cert-tls server\ntun-mtu 1380\nfragment 1200\n<ca>\n"+externalCertificate+"\n</ca>\n";}
  e.policy=new JSONObject().put("dns_mode",dns).put("ipv6_mode","on").put("home_lan_access",false).put("home_lan_cidrs",new JSONArray().put("192.168.50.0/24")).put("mtu_policy","auto").put("effective_mtu",8800);
  if(!dns.equals("home"))e.policy.put("dns_protocol","tcp").put("dns_host","149.112.112.112").put("dns_port",5353);
  return e;
 }
 static void ordinary(Path directory,String mode,String layer,String kind,String certificate)throws Exception{
  Path app=Files.createTempDirectory(directory,"external-entry-");Context context=new Context(app.toFile());JSONObject selected=entry(mode,layer,certificate);
  // The final external interface owns its policy; the entry keeps its own
  // measured-independent transport sizing and authenticated performance owner.
  profile(selected).put("mtu_policy","auto").remove("manual_mtu");
  if(mode.equals("wg")&&AndroidStandardExitStore.packetExecutionProtocol(kind)||kind.equals("openvpn")&&(NativeSingBoxController.nativeWireGuardFamily(mode)||NativeSingBoxController.nativePQFamily(mode)||AndroidNativeMAXProfile.isMode(mode)))profile(selected).put("mtu_policy","fixed").put("manual_mtu",1500);
  File file=save(directory,selected);byte[] frozen=Files.readAllBytes(file.toPath());AndroidStandardExitStore.Entry exit=external(kind,graphs%2==0?"custom":"home");String frozenExit=AndroidStandardExitStore.snapshot(exit);
  NativeSingBoxController.SessionInfo info=AndroidExternalPolicy.prepare(context,file,exit,mode);Path folder=app.resolve("layered-sessions").resolve(info.sessionId);
  String config=Files.readString(folder.resolve("sing-box.json")),metadata=Files.readString(folder.resolve(AndroidExternalPolicy.SESSION_FILE));JSONObject session=AndroidExternalPolicy.session(config,metadata,info.sessionId,info.modeId),capture=new JSONObject(session.getString("capture_json")),graph=new JSONObject(config),proof=new JSONObject(session.getString("metadata_json"));
  check(capture.getString("entry_tag").equals("external-entry")&&capture.getJSONObject("entry").getString("node_proof_id").equals(selected.getString("nodeProofId")),"external graph lost exact private entry");
  check(proof.getString("predecessor_sha256").equals(AndroidTorProfile.digest(capture.getString("predecessor_config").getBytes(StandardCharsets.UTF_8))),"entry graph digest changed");
  JSONObject predecessor=new JSONObject(capture.getString("predecessor_config"));check(graph.getJSONArray("inbounds").length()==1&&graph.getJSONObject("route").getString("final").equals("custom-exit"),"entry created a second VPN owner");
  JSONObject output=byTag(graph,"custom-exit");check(output.getString("detour").equals("external-entry"),"selected external traffic bypassed entry");
  if(kind.equals("amneziawg")){JSONObject imported=capture.getJSONObject("profile").getJSONObject("external").getJSONObject("amneziawg");check(output.getString("type").equals("routervpn-amneziawg")&&sameParams(output.getJSONObject("amnezia"),exit.awgParameters),"AWG output lost exact native parameters");check(sameParams(imported.getJSONObject("parameters"),exit.awgParameters)&&output.getJSONArray("peers").getJSONObject(0).getInt("persistent_keepalive_interval")==25,"AWG capture lost exact ranges or keepalive");}
  if(kind.equals("openvpn")){JSONObject inline=capture.getJSONObject("profile").getJSONObject("external").getJSONObject("openvpn");check(output.getString("type").equals("openvpn-client")&&!output.getBoolean("system")&&output.getJSONArray("servers").length()==2,"OpenVPN lost its remote list or acquired a system TUN");check(output.getString("username").equals(exit.username)&&output.getString("password").equals(exit.password)&&inline.getString("config").equals(exit.openVPNConfig),"OpenVPN borrowed or normalized private credentials");check(output.getJSONObject("tls").getJSONArray("certificate").getString(0).equals(externalCertificate.trim()+"\n")&&output.getInt("mtu")==1380&&output.getInt("fragment")==1200,"OpenVPN changed inline TLS, transport MTU or captured fragmentation");}
  JSONObject entryOutput=byTag(graph,"external-entry"),original=byTag(predecessor,predecessor.getJSONObject("route").getString("final"));check(entryOutput.getString("type").equals(original.getString("type")),"selected entry family changed");
  check(proof.getString("dns_server").equals(exit.policy.getString("dns_mode").equals("home")?profile(selected).getString("adguard_ipv4"):"149.112.112.112"),"entry replaced selected exit DNS");
  check(proof.getString("dns_detour").equals(exit.policy.getString("dns_mode").equals("home")?"external-entry":"custom-exit"),"selected DNS escaped captured owner");
  check(proof.getString("auto_mtu").equals("unmeasured")&&proof.getInt("configured_mtu")<8800&&!proof.getBoolean("home_lan_access"),"external policy reused stale MTU or allowed LAN");
  check(graph.optJSONArray("services")!=null&&graph.getJSONArray("services").length()==predecessor.getJSONArray("services").length(),"entry lost its authenticated performance services");
  check(!Files.exists(folder.resolve(AndroidStartLayerRelay.SESSION_FILE)),"native predecessor staged an unowned local relay");
  for(String list:new String[]{"outbounds","endpoints"}){JSONArray outputs=graph.optJSONArray(list);if(outputs!=null)for(int i=0;i<outputs.length();i++){JSONObject outbound=outputs.getJSONObject(i);check(!"127.0.0.1".equals(outbound.optString("server"))||outbound.has("detour"),"physical localhost helper escaped native composition");}}
  check(Arrays.equals(frozen,Files.readAllBytes(file.toPath()))&&frozenExit.equals(AndroidStandardExitStore.snapshot(exit)),"external preparation changed saved private inputs");
  String export=System.getenv("ROUTERVPN_ANDROID_EXTERNAL_GRAPHS");if(export!=null)Files.writeString(Path.of(export).resolve(mode+"-"+layer+"-"+kind+".json"),config);
  if(info.maxPreparation!=null)info.maxPreparation.close();graphs++;
  if(AndroidStandardExitStore.serverExecutionProtocol(kind))for(String execution:new String[]{"server","auto"}){
   AndroidStandardExitStore.Entry paired=AndroidStandardExitStore.copy(exit);paired(paired);
   NativeSingBoxController.SessionInfo executionInfo=AndroidExternalPolicy.prepare(context,file,paired,mode,execution,"");Path owned=app.resolve("layered-sessions").resolve(executionInfo.sessionId);
   String executable=Files.readString(owned.resolve("sing-box.json")),details=Files.readString(owned.resolve(AndroidExternalPolicy.SESSION_FILE));
   JSONObject executionSession=AndroidExternalPolicy.session(executable,details,executionInfo.sessionId,executionInfo.modeId),executionGraph=new JSONObject(executable),executionMeta=new JSONObject(executionSession.getString("metadata_json"));
   check(executionMeta.getString("execution").equals(execution)&&executionMeta.getString("last_node_measurement").equals("https-response-time"),"captured external execution lost its required measurement");
   check(byTag(executionGraph,"custom-exit").getString("type").equals("selector")&&byTag(executionGraph,"routervpn-execution-server").getString("detour").equals("external-entry"),"server relay escaped complete captured entry");
   check(byTag(executionGraph,"external-entry").getString("type").equals(entryOutput.getString("type")),"server execution changed entry family");
   check(executionMeta.getString("dns_server").equals(proof.getString("dns_server"))&&executionMeta.getString("dns_detour").equals(proof.getString("dns_detour")),"server execution changed selected DNS owner");
   if(AndroidStandardExitStore.packetExecutionProtocol(kind)){
    JSONObject local=byTag(executionGraph,"routervpn-execution-local"),peer=local.getJSONArray("peers").getJSONObject(0);
    check(local.getString("private_key").equals(paired.wgPrivateKey)&&local.getJSONArray("address").toString().equals(new JSONArray(paired.wgAddresses).toString())&&peer.getString("public_key").equals(paired.wgPeerPublicKey),"packet execution substituted Server credentials into Local endpoint");
    JSONObject descriptor=new JSONObject(executionSession.getString("capture_json")).getJSONObject("profile").getJSONObject("external").getJSONObject("server_peer");
    check(descriptor.getString("public_key").equals(paired.serverPeer.getString("public_key"))&&descriptor.getJSONArray("addresses").toString().equals(paired.serverPeer.getJSONArray("addresses").toString()),"packet execution lost separately provisioned Server identity");
    if(kind.equals("amneziawg"))check(local.getString("type").equals("routervpn-amneziawg")&&sameParams(local.getJSONObject("amnezia"),paired.awgParameters),"Server/Compare changed captured AWG parameters");
   }
   if(kind.equals("openvpn")){
    JSONObject local=byTag(executionGraph,"routervpn-execution-local"),captured=new JSONObject(executionSession.getString("capture_json")).getJSONObject("profile").getJSONObject("external");
    check(local.getString("type").equals("openvpn-client")&&!local.getBoolean("system")&&local.getJSONArray("servers").length()==2&&local.getString("username").equals(paired.username)&&local.getString("password").equals(paired.password),"OpenVPN comparison borrowed Server credentials or replaced its owned remote list");
    check(captured.getJSONObject("openvpn").getString("config").equals(paired.openVPNConfig)&&same(captured.getJSONObject("openvpn_pairing"),paired.openVPNPairing),"OpenVPN comparison changed private source or pairing identity");
    check(!executionMeta.toString().contains(paired.password)&&!executionMeta.toString().contains(paired.openVPNPairing.getString("private_key")),"OpenVPN private pairing entered public metadata");
   }
   if(export!=null)Files.writeString(Path.of(export).resolve(mode+"-"+layer+"-"+kind+"-"+execution+".json"),executable);
   if(executionInfo.maxPreparation!=null)executionInfo.maxPreparation.close();executionGraphs++;
  }
  if(mode.equals("wg")&&AndroidStandardExitStore.serverExecutionProtocol(kind))for(String exitLayer:new String[]{"aes-256-gcm","aes-256-gcm+xor-whitening"})for(String execution:new String[]{"local","server","auto"}){
   AndroidStandardExitStore.Entry paired=AndroidStandardExitStore.copy(exit);paired(paired);paired.policy.put("start_layer",exitLayer);
   paired.startLayer=new JSONObject().put("mode",exitLayer).put("api","http://10.99.0.1:8787").put("transport",new JSONObject().put("type","shadowsocks").put("tag","provisioned-exit-layer").put("server",paired.server).put("server_port",8388).put("method","2022-blake3-aes-256-gcm").put("password",MultihopGraphHarness.key('l')));
   String originalExit=AndroidStandardExitStore.snapshot(paired);NativeSingBoxController.SessionInfo layered=AndroidExternalPolicy.prepare(context,file,paired,mode,execution,"");Path owned=app.resolve("layered-sessions").resolve(layered.sessionId);
   String executable=Files.readString(owned.resolve("sing-box.json"));JSONObject layeredGraph=new JSONObject(executable),local=byTag(layeredGraph,execution.equals("local")?"custom-exit":"routervpn-execution-local"),wrapper=byTag(layeredGraph,"routervpn-exit-start-layer");
   String localServer=AndroidStandardExitStore.packetExecutionProtocol(kind)?local.getJSONArray("peers").getJSONObject(0).getString("address"):kind.equals("openvpn")?local.getJSONArray("servers").getJSONObject(0).getString("server"):local.getString("server");
   check(localServer.equals("10.99.0.1")&&local.getString("detour").equals("routervpn-exit-start-layer")&&wrapper.getString("detour").equals("external-entry"),"independent entry and exit layers lost routing ownership");
   check(wrapper.getString("type").equals(exitLayer.equals("aes-256-gcm")?"shadowsocks":"routervpn-aes-xor")&&wrapper.getString("server").equals(paired.server),"exit layer changed its selected protocol or server");
   check(originalExit.equals(AndroidStandardExitStore.snapshot(paired))&&Arrays.equals(frozen,Files.readAllBytes(file.toPath())),"layered execution mutated private node capture");
   if(export!=null)Files.writeString(Path.of(export).resolve(mode+"-"+layer+"-"+kind+"-exit-"+exitLayer+"-"+execution+".json"),executable);
   if(layered.maxPreparation!=null)layered.maxPreparation.close();layerGraphs++;
  }
 }
 static AndroidStandardExitStore.Entry multiHostOpenVPN()throws Exception{
  JSONObject external=load(Path.of(System.getenv("ROUTERVPN_OPENVPN_MULTIHOST_CLIENT_FIXTURE"))).getJSONObject("external"),inline=external.getJSONObject("openvpn");AndroidStandardExitStore.Entry exit=external("openvpn","custom");
  exit.openVPNConfig=inline.getString("config");exit.username=inline.getString("username");exit.password=inline.getString("password");exit.expectedPublicIp=external.getString("expected_public_ip");exit.openVPNPairing=new JSONObject(external.getJSONObject("openvpn_pairing").toString());exit.openVPNResponseProbes=new JSONObject(external.getJSONObject("openvpn_response_probes").toString());return exit;
 }
 static void mappedCapture(JSONObject captured,AndroidStandardExitStore.Entry exit)throws Exception{
  check(same(captured.getJSONObject("openvpn_response_probes"),exit.openVPNResponseProbes)&&same(captured.getJSONObject("openvpn_pairing"),exit.openVPNPairing)&&captured.getJSONObject("openvpn").getString("config").equals(exit.openVPNConfig),"multi-host OpenVPN preparation changed private map, source, or provider identity");
 }
 static void multiHostOpenVPNPaths(Path directory,String certificate)throws Exception{
  String export=System.getenv("ROUTERVPN_ANDROID_EXTERNAL_GRAPHS");
  for(String mode:ALL)for(String layer:LAYERS)for(String execution:new String[]{"local","server","auto"}){
   Path app=Files.createTempDirectory(directory,"openvpn-remote-owner-");JSONObject selected=entry(mode,layer,certificate);if(NativeSingBoxController.nativeWireGuardFamily(mode)||NativeSingBoxController.nativePQFamily(mode)||AndroidNativeMAXProfile.isMode(mode))profile(selected).put("mtu_policy","fixed").put("manual_mtu",1500);File file=save(directory,selected);byte[] frozenEntry=Files.readAllBytes(file.toPath());AndroidStandardExitStore.Entry exit=multiHostOpenVPN();String frozen=AndroidStandardExitStore.snapshot(exit);
   NativeSingBoxController.SessionInfo info=AndroidExternalPolicy.prepare(new Context(app.toFile()),file,exit,mode,execution,"");Path session=app.resolve("layered-sessions").resolve(info.sessionId);String config=Files.readString(session.resolve("sing-box.json"));JSONObject saved=new JSONObject(Files.readString(session.resolve(AndroidExternalPolicy.SESSION_FILE))),capture=new JSONObject(saved.getString("capture_json")),metadata=new JSONObject(saved.getString("metadata_json")),graph=new JSONObject(config),captured=capture.getJSONObject("profile").getJSONObject("external");
   mappedCapture(captured,exit);JSONObject local=byTag(graph,execution.equals("local")?"custom-exit":"routervpn-execution-local");
   check(local.getString("type").equals("openvpn-client")&&!local.getBoolean("system")&&local.getJSONArray("servers").length()==2&&local.getString("username").equals(exit.username)&&local.getString("password").equals(exit.password),"mapped OpenVPN replaced its owned remote list or Local credentials");
   check(local.getString("detour").equals("external-entry")&&graph.getJSONArray("inbounds").length()==1,"mapped OpenVPN created a second VPN owner or bypassed its entry");
   check(frozen.equals(AndroidStandardExitStore.snapshot(exit))&&Arrays.equals(frozenEntry,Files.readAllBytes(file.toPath())),"mapped preparation mutated saved private node or entry");
   check(!metadata.toString().contains(exit.openVPNPairing.getString("private_key"))&&!metadata.toString().contains("openvpn_response_probes"),"private OpenVPN response map entered public execution metadata");
   check(metadata.getString("dns_server").equals("149.112.112.112")&&metadata.getString("dns_detour").equals("custom-exit"),"mapped OpenVPN substituted selected DNS");
   if(!execution.equals("local")){
    check(metadata.getString("execution").equals(execution)&&metadata.getString("last_node_measurement").equals("https-response-time"),"mapped execution lost exact choice or response measurement semantics");
    check(byTag(graph,"custom-exit").getString("type").equals("selector")&&byTag(graph,"routervpn-execution-server").getString("detour").equals("external-entry"),"mapped execution relay bypassed complete captured entry");
   }
   if(export!=null)Files.writeString(Path.of(export).resolve(mode+"-"+layer+"-openvpn-mapped-"+execution+".json"),config);
   if(info.maxPreparation!=null)info.maxPreparation.close();mappedGraphs++;
  }
  for(String winner:new String[]{"local","server"}){
   Path app=Files.createTempDirectory(directory,"openvpn-map-restore-");JSONObject selected=entry("wg","aes-256-gcm+xor-whitening",certificate);profile(selected).put("mtu_policy","fixed").put("manual_mtu",1500);File file=save(directory,selected);AndroidStandardExitStore.Entry exit=multiHostOpenVPN();String frozen=AndroidStandardExitStore.snapshot(exit);
   NativeSingBoxController.SessionInfo info=AndroidExternalPolicy.prepare(new Context(app.toFile()),file,exit,"wg","auto",winner);Path folder=app.resolve("layered-sessions").resolve(info.sessionId);JSONObject graph=load(folder.resolve("sing-box.json")),session=load(folder.resolve(AndroidExternalPolicy.SESSION_FILE)),capture=new JSONObject(session.getString("capture_json")),metadata=new JSONObject(session.getString("metadata_json"));
   check(capture.getJSONObject("profile").getString("multihop_execution").equals("auto")&&capture.getJSONObject("execution").getString("selection").equals(winner)&&metadata.getString("execution").equals(winner),"mapped restoration reran Compare or rewrote the saved preference");
   check(byTag(graph,"custom-exit").getString("default").equals("routervpn-execution-"+winner),"mapped restoration selected a different proved path");mappedCapture(capture.getJSONObject("profile").getJSONObject("external"),exit);
   check(frozen.equals(AndroidStandardExitStore.snapshot(exit)),"restored mapped execution overwrote the user's saved private map");if(info.maxPreparation!=null)info.maxPreparation.close();
  }
  for(String fault:new String[]{"missing-pairing","missing-map","partial-map","wrong-host","legacy-mixture","selected-layer","private-layer","invalid-winner","changed-map"}){
   Path app=Files.createTempDirectory(directory,"openvpn-map-reject-");JSONObject selected=entry("wg","off",certificate);profile(selected).put("mtu_policy","fixed").put("manual_mtu",1500);File file=save(directory,selected);AndroidStandardExitStore.Entry exit=multiHostOpenVPN();String host=exit.openVPNResponseProbes.names().getString(0);
   if(fault.equals("missing-pairing"))exit.openVPNPairing=null;
   if(fault.equals("missing-map")){exit.responseProbe=new JSONObject(exit.openVPNResponseProbes.getJSONObject(host).toString());exit.openVPNResponseProbes=null;}
   if(fault.equals("partial-map"))exit.openVPNResponseProbes.remove(host);
   if(fault.equals("wrong-host"))exit.openVPNResponseProbes.getJSONObject(host).put("url","https://8.8.8.8/response");
   if(fault.equals("legacy-mixture"))exit.responseProbe=new JSONObject(exit.openVPNResponseProbes.getJSONObject(host).toString());
   if(fault.equals("selected-layer"))exit.policy.put("start_layer","aes-256-gcm");
   if(fault.equals("private-layer"))exit.startLayer=new JSONObject().put("mode","off");
   io.nekohasekai.libbox.Libbox.afterCheck=()->{try{if(fault.equals("changed-map"))exit.openVPNResponseProbes.getJSONObject(host).put("url","https://"+host+"/replacement");}catch(Exception invalid){throw new RuntimeException(invalid);}};
   boolean rejected=false;try{AndroidExternalPolicy.prepare(new Context(app.toFile()),file,exit,"wg","auto",fault.equals("invalid-winner")?"auto":"");}catch(Exception expected){rejected=true;}finally{io.nekohasekai.libbox.Libbox.afterCheck=null;}
   check(rejected&&sessions(app)==0,"invalid or changed mapped OpenVPN owner staged a native session: "+fault);
  }
 }
 static void ordinaryRejections(Path directory,String certificate)throws Exception{
  AndroidStandardExitStore.Entry validOpenVPN=external("openvpn","custom");paired(validOpenVPN);
  AndroidStandardExitStore.validate(validOpenVPN);AndroidExternalPolicy.validateDraft(validOpenVPN);
  String pairingText=validOpenVPN.openVPNPairing.toString(),privateSource=validOpenVPN.openVPNConfig;
  check(same(AndroidOpenVPN.pairing(validOpenVPN,pairingText),validOpenVPN.openVPNPairing),"private OpenVPN editor changed its validated pairing");
  AndroidStandardExitStore.Entry copied=AndroidStandardExitStore.copy(validOpenVPN);copied.openVPNPairing.getJSONObject("server").getJSONObject("provider_identity").put("username","other-server-user");
  check(validOpenVPN.openVPNConfig.equals(privateSource)&&!same(copied.openVPNPairing,validOpenVPN.openVPNPairing),"private OpenVPN snapshot borrowed mutable pairing state");
  for(String raw:new String[]{"null",pairingText+" {}",pairingText.substring(0,pairingText.length()-1)+",\"private_key\":\""+validOpenVPN.openVPNPairing.getString("private_key")+"\"}",pairingText.substring(0,pairingText.length()-1)+",\"unknown\":true}"}){
   boolean rejected=false;try{AndroidOpenVPN.pairing(validOpenVPN,raw);}catch(Exception expected){rejected=true;}check(rejected,"raw malformed or duplicate OpenVPN pairing reached a saved object");
  }
  for(String fault:new String[]{"missing-pairing","provider-alias","server-private-key","changed-transport","wrong-response","pairing-change","credentials-change"}){
   Path app=Files.createTempDirectory(directory,"openvpn-pairing-");JSONObject source=entry("wg","off",certificate);File file=save(directory,source);AndroidStandardExitStore.Entry exit=AndroidStandardExitStore.copy(validOpenVPN);
   if(fault.equals("missing-pairing"))exit.openVPNPairing=null;
   if(fault.equals("provider-alias"))exit.openVPNPairing.getJSONObject("server").getJSONObject("provider_identity").put("username",exit.username);
   if(fault.equals("server-private-key"))exit.openVPNPairing.getJSONObject("server").put("private_key",MultihopGraphHarness.key('z'));
   if(fault.equals("changed-transport"))exit.openVPNPairing.getJSONObject("server").getJSONObject("transport").put("auth","SHA512");
   if(fault.equals("wrong-response"))exit.responseProbe.put("url","https://203.0.113.21/response");
   io.nekohasekai.libbox.Libbox.afterCheck=()->{try{if(fault.equals("pairing-change"))exit.openVPNPairing.put("private_key",MultihopGraphHarness.key('z'));if(fault.equals("credentials-change"))exit.password="replacement-owner-password";}catch(Exception invalid){throw new RuntimeException(invalid);}};
   boolean rejected=false;try{AndroidExternalPolicy.prepare(new Context(app.toFile()),file,exit,"wg","auto","");}catch(Exception expected){rejected=true;}finally{io.nekohasekai.libbox.Libbox.afterCheck=null;}
   check(rejected&&sessions(app)==0,"invalid or replaced private OpenVPN owner staged a comparison: "+fault);
  }
  for(String invalid:new String[]{"unfragmented","oversized-fragment"}){
   Path app=Files.createTempDirectory(directory,"openvpn-mtu-");JSONObject source=entry("wg","off",certificate);profile(source).put("mtu_policy","auto").remove("manual_mtu");File file=save(directory,source);AndroidStandardExitStore.Entry exit=external("openvpn","custom");
   exit.openVPNConfig=exit.openVPNConfig.replace("fragment 1200\n",invalid.equals("unfragmented")?"":"fragment 1400\n");boolean rejected=false;try{AndroidExternalPolicy.prepare(new Context(app.toFile()),file,exit,"wg");}catch(Exception expected){rejected=true;}
   check(rejected&&sessions(app)==0,"OpenVPN silently changed its incompatible captured packet framing: "+invalid);
  }
  for(String fault:new String[]{"selected","duplicate","missing-mode","layer-type","entry-change","exit-change","cancel","native","install","write"}){
   Path app=Files.createTempDirectory(directory,"external-reject-");JSONObject source=entry("hysteria2","aes-256-gcm+xor-whitening",certificate);AndroidStandardExitStore.Entry exit=external("socks5","custom");
   if(fault.equals("selected"))source.put("selectedRouterID","absent");if(fault.equals("duplicate"))source.getJSONArray("routerProfiles").put(new JSONObject(profile(source).toString()));if(fault.equals("missing-mode"))source.getJSONObject("profiles").remove("hysteria2");if(fault.equals("layer-type"))profile(source).put("start_layer",true);
   File file=save(directory,source);if(fault.equals("native"))io.nekohasekai.libbox.Libbox.rejectConfig=true;if(fault.equals("install"))RouterPQNative.fail=true;if(fault.equals("write"))AndroidPrivateFileStore.failName=AndroidExternalPolicy.SESSION_FILE;
   io.nekohasekai.libbox.Libbox.afterCheck=()->{try{if(fault.equals("entry-change"))Files.writeString(file.toPath(),"{}");if(fault.equals("exit-change"))exit.policy.put("dns_host","8.8.8.8");if(fault.equals("cancel"))Thread.currentThread().interrupt();}catch(Exception e){throw new RuntimeException(e);}};
   boolean rejected=false;try{AndroidExternalPolicy.prepare(new Context(app.toFile()),file,exit,"hysteria2");}catch(Exception expected){rejected=true;}finally{Thread.interrupted();io.nekohasekai.libbox.Libbox.afterCheck=null;io.nekohasekai.libbox.Libbox.rejectConfig=false;RouterPQNative.fail=false;AndroidPrivateFileStore.failName=null;}
   check(rejected&&sessions(app)==0,"invalid or cancelled complete entry staged files: "+fault);
  }
  for(String protocol:new String[]{"wireguard","amneziawg"})for(String fault:new String[]{"server-peer-change","packet-private-change"}){
   Path app=Files.createTempDirectory(directory,"packet-stale-");JSONObject source=entry("wg","off",certificate);File file=save(directory,source);AndroidStandardExitStore.Entry exit=external(protocol,"custom");paired(exit);
   io.nekohasekai.libbox.Libbox.afterCheck=()->{try{if(fault.equals("server-peer-change"))exit.serverPeer.put("mtu",1400);else exit.wgPrivateKey=MultihopGraphHarness.key('z');}catch(Exception invalid){throw new RuntimeException(invalid);}};
   boolean rejected=false;try{AndroidExternalPolicy.prepare(new Context(app.toFile()),file,exit,"wg","auto","");}catch(Exception expected){rejected=true;}finally{io.nekohasekai.libbox.Libbox.afterCheck=null;}
   check(rejected&&sessions(app)==0,"changed packet ownership staged an obsolete graph: "+fault);
  }
 }
 public static void main(String[] args)throws Exception{
  Path dir=Path.of(args[0]);fixtures=load(Path.of(System.getenv("ROUTERVPN_MAX_MULTIHOP_FIXTURES")));compositeEntry=load(Path.of(System.getenv("ROUTERVPN_COMPOSITE_ENTRY")));compositeExit=load(Path.of(System.getenv("ROUTERVPN_COMPOSITE_EXIT")));String certificate=io.nekohasekai.libbox.Libbox.testCertificate("entry.example.test");externalCertificate=io.nekohasekai.libbox.Libbox.testCertificate("external-openvpn.example.test").trim();
  multiHostOpenVPNPaths(dir,certificate);if("1".equals(System.getenv("ROUTERVPN_ANDROID_OPENVPN_PROBES_ONLY"))){System.out.println("Android private OpenVPN remote paths: PASS "+checks+" shipping Java/Go capture checks across 171 mapped entry/layer/execution graphs, exact winner restore and invalid maps rejected; no native/device acceptance claimed");return;}
  for(String mode:ALL)for(String layer:LAYERS)for(String kind:new String[]{"wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn"})ordinary(dir,mode,layer,kind,certificate);
  check(graphs==456&&executionGraphs==912&&layerGraphs==144&&mappedGraphs==171,"ordinary encrypted entry and execution matrix incomplete");ordinaryRejections(dir,certificate);
  System.out.println("Android ordinary external entries: PASS "+graphs+" local and "+executionGraphs+" Server/Compare and "+layerGraphs+" independent exit-layer and "+mappedGraphs+" mapped OpenVPN shipping Java/Go graphs, "+checks+" checks; all19 native entry modes and saved Start Layers");
 }
}
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openvpn-probes-only',action='store_true')
    args=parser.parse_args()
    os.environ["ROUTERVPN_OPENVPN_CLIENT_FIXTURE"] = str(ROOT / "deploy/fixtures/external-openvpn-client.json")
    os.environ["ROUTERVPN_OPENVPN_MULTIHOST_CLIENT_FIXTURE"] = str(ROOT / "deploy/fixtures/external-openvpn-multihost-client.json")
    if args.openvpn_probes_only:
        if os.environ.get("ROUTERVPN_ANDROID_EXTERNAL_GRAPHS"):
            raise RuntimeError("The focused response-map test cannot produce a complete graph export")
        os.environ["ROUTERVPN_ANDROID_OPENVPN_PROBES_ONLY"]="1"
    else:
        os.environ.pop("ROUTERVPN_ANDROID_OPENVPN_PROBES_ONLY",None)
    export = os.environ.get("ROUTERVPN_ANDROID_EXTERNAL_GRAPHS")
    if export:
        path = Path(export)
        if path.is_symlink() or not path.is_dir() or any(path.iterdir()):
            raise RuntimeError("External parser fixtures require an existing empty owned directory")
    T.P.run = T.run
    T.C.main()


if __name__ == "__main__":
    main()
