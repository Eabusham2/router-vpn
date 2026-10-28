#!/usr/bin/env python3
"""Execute the shipping Android Tor Server capture with the shared Go compiler.

The private file and Android OS boundaries are doubled. The real store,
controller, complete entry preparation, compiler and session admission run.
Native source matching, leases and traffic have separate native runtime gates.
"""
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tor_server_capture", ROOT / "android/test_android_tor_profile.py")
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
T.EXTRA_SOURCES = ("AndroidStandardExitController",)
T.HARNESS = T.HARNESS[:T.HARNESS.index(" public static void main(")] + r'''
 interface Attempt {void run()throws Exception;}
 static void rejection(Attempt task,String reason)throws Exception{boolean failed=false;try{task.run();}catch(Exception expected){failed=true;}check(failed,"Tor Server accepted "+reason);}
 static void server(Path dir,String mode,String layer,String kind,String dns,String certificate)throws Exception{
  Path app=Files.createTempDirectory(dir,"server-");Context context=new Context(app.toFile());
  JSONObject source=entry(mode,layer,certificate);File file=save(dir,source);byte[] entryBefore=Files.readAllBytes(file.toPath());
  AndroidStandardExitStore.Entry selected=tor(kind,dns);selected.torPolicy.put("daita_enabled",true).put("daita_rate_kbps",64);String exitBefore=AndroidStandardExitStore.snapshot(selected);
  NativeSingBoxController.SessionInfo prepared=new AndroidStandardExitController(context).prepare(file,selected,mode,"server","server");
  Path folder=app.resolve("layered-sessions").resolve(prepared.sessionId);
  String config=Files.readString(folder.resolve("sing-box.json"));String metadata=Files.readString(folder.resolve(AndroidTorProfile.SESSION_FILE));
  JSONObject graph=new JSONObject(config),capture=AndroidTorProfile.session(config,metadata,prepared.sessionId,prepared.modeId),out=byTag(graph,AndroidTorProfile.OUTBOUND);
  check(AndroidTorProfile.execution(capture).equals("server")&&capture.getJSONObject("tor_profile").getString("multihop_execution").equals("server"),"Server capture became Local");
  check(out.getString("type").equals("routervpn-server-tor")&&out.length()==6&&!out.has("detour")&&!out.has("bridges"),"Server installed an independent Local Tor owner");
  check(out.getString("session_id").equals(prepared.sessionId)&&same(new JSONObject(out.getString("profile")),capture.getJSONObject("tor_profile")),"Server source/session mismatch");
  check(capture.getJSONObject("tor_profile").getBoolean("daita_enabled")&&capture.getJSONObject("tor_profile").getInt("daita_rate_kbps")==64,"Server capture discarded the saved cover choice");
  AndroidStandardExitStore.Entry reopened=AndroidStandardExitStore.copy(selected);
  check(reopened.torPolicy.getBoolean("daita_enabled")&&reopened.torPolicy.getInt("daita_rate_kbps")==64,"saved node roundtrip discarded native cover policy");
  check(same(new JSONObject(out.getString("entry_profile")),profile(source))&&same(capture.getJSONObject("predecessor_profile"),profile(source)),"Server borrowed another private entry credential");
  check(out.getString("entry_config").equals(io.nekohasekai.libbox.Libbox.lastTorPredecessor),"Server changed captured entry graph bytes");
  check(capture.getString("predecessor_config_sha256").equals(AndroidTorProfile.digest(out.getString("entry_config").getBytes(StandardCharsets.UTF_8))),"Server lost entry graph identity");
  JSONObject tunnel=graph.getJSONArray("inbounds").getJSONObject(0);
  check(graph.getJSONArray("inbounds").length()==1&&tunnel.getString("type").equals("tun")&&tunnel.getBoolean("auto_route")&&tunnel.getBoolean("strict_route")&&tunnel.getInt("mtu")==1360,"Server changed the owned VPN interface or policy");
  check(graph.getJSONObject("route").getString("final").equals(AndroidTorProfile.OUTBOUND),"Server data bypassed the captured final owner");
  int owners=0;JSONArray outputs=graph.getJSONArray("outbounds");for(int i=0;i<outputs.length();i++){String type=outputs.getJSONObject(i).optString("type");if(type.equals("routervpn-server-tor"))owners++;check(!type.equals("routervpn-tor"),"Local runtime remained on the Server graph");}
  check(owners==1,"Server requires exactly one lease owner");
  JSONObject selectedDNS=tagged(graph.getJSONObject("dns").getJSONArray("servers"),"routervpn-tor-dns");
  check(selectedDNS.getString("server").equals("149.112.112.112")&&selectedDNS.getInt("server_port")==selected.torPolicy.getInt("dns_port")&&selectedDNS.getString("detour").equals(AndroidTorProfile.OUTBOUND),"Server DNS escaped the selected owner or changed address/port");
  JSONArray resolvers=graph.getJSONObject("dns").getJSONArray("servers");for(int i=0;i<resolvers.length();i++)check(!resolvers.getJSONObject(i).getString("tag").equals("routervpn-tor-bootstrap"),"Server retained device-side Tor bootstrap");
  check(Arrays.equals(entryBefore,Files.readAllBytes(file.toPath()))&&exitBefore.equals(AndroidStandardExitStore.snapshot(selected)),"Server staging rewrote a saved source");
  check(Files.readString(folder.resolve(AndroidKillSwitchPolicy.SESSION_MARKER)).equals("1\n"),"Server omitted captured strict protection");
  String output=System.getenv("ROUTERVPN_ANDROID_TOR_GRAPHS");if(output!=null)Files.writeString(Path.of(output).resolve("server-"+kind+"-"+mode+"-"+layer+".json"),config,StandardOpenOption.CREATE_NEW);
  graphs++;
 }
 static void serverNegative(Path dir,String certificate)throws Exception{
  Path app=Files.createTempDirectory(dir,"server-negative-");Context context=new Context(app.toFile());JSONObject source=entry("shadowsocks","off",certificate);File file=save(dir,source);AndroidStandardExitStore.Entry e=tor("obfs4","doh");
  AndroidStandardExitController controller=new AndroidStandardExitController(context);
  rejection(()->controller.prepare(file,e,"shadowsocks","server","local"),"a different restored execution");
  rejection(()->controller.prepare(file,e,"shadowsocks","local","server"),"Server receipt on Local selection");
  rejection(()->controller.prepare(file,e,"shadowsocks","auto","server"),"Compare without two independent measurements");
  rejection(()->controller.prepare(null,e,"shadowsocks","server",""),"Server without private entry");
  check(sessions(app)==0,"rejected execution staged a session");
  for(String fault:new String[]{"direct-padding","compare-padding","enabled-type","rate-type","rate-small","rate-large"}){
   AndroidStandardExitStore.Entry cover=tor("obfs4","tcp");cover.torPolicy.put("daita_enabled",true).put("daita_rate_kbps",64);
   if(fault.equals("enabled-type"))cover.torPolicy.put("daita_enabled","true");
   if(fault.equals("rate-type"))cover.torPolicy.put("daita_rate_kbps","64");
   if(fault.equals("rate-small"))cover.torPolicy.put("daita_rate_kbps",31);
   if(fault.equals("rate-large"))cover.torPolicy.put("daita_rate_kbps",193);
   String execution=fault.equals("compare-padding")?"auto":"server";
   File entryFile=fault.equals("direct-padding")?null:file;
   String captured=AndroidStandardExitStore.snapshot(cover);
   rejection(()->controller.prepare(entryFile,cover,"shadowsocks",execution,""),fault);
   check(captured.equals(AndroidStandardExitStore.snapshot(cover))&&sessions(app)==0,"failed cover selection changed saved policy or staged a session");
  }
  Path localApp=Files.createTempDirectory(dir,"local-cover-owner-");AndroidStandardExitStore.Entry localCover=tor("obfs4","tcp");localCover.torPolicy.put("daita_enabled",true).put("daita_rate_kbps",64);String localBefore=AndroidStandardExitStore.snapshot(localCover);
  NativeSingBoxController.SessionInfo localInfo=new AndroidStandardExitController(new Context(localApp.toFile())).prepare(file,localCover,"shadowsocks","local","local");Path localFolder=localApp.resolve("layered-sessions").resolve(localInfo.sessionId);
  String localRaw=Files.readString(localFolder.resolve("sing-box.json"));JSONObject localMeta=new JSONObject(Files.readString(localFolder.resolve(AndroidTorProfile.SESSION_FILE))),localGraph=new JSONObject(localRaw),localOut=byTag(localGraph,AndroidTorProfile.OUTBOUND);
  check(AndroidTorProfile.execution(AndroidTorProfile.session(localRaw,localMeta.toString(),localInfo.sessionId,localInfo.modeId)).equals("local")&&localOut.getString("type").equals("routervpn-tor")&&localOut.has("padding_source"),"Local cover borrowed Server execution or omitted its native source");
  check(localBefore.equals(AndroidStandardExitStore.snapshot(localCover)),"Local cover capture rewrote saved source");
  localOut.remove("padding_source");String missingLocalSource=localGraph.toString();localMeta.put("config_sha256",AndroidTorProfile.digest(missingLocalSource.getBytes(StandardCharsets.UTF_8)));
  rejection(()->AndroidTorProfile.session(missingLocalSource,localMeta.toString(),localInfo.sessionId,localInfo.modeId),"Local cover without captured native source despite updated checksum");
  NativeSingBoxController.SessionInfo info=controller.prepare(file,e,"shadowsocks","server","");Path folder=app.resolve("layered-sessions").resolve(info.sessionId);
  String raw=Files.readString(folder.resolve("sing-box.json")),metaRaw=Files.readString(folder.resolve(AndroidTorProfile.SESSION_FILE));
  for(String fault:new String[]{"local","auto","null","missing-execution","missing-entry","profile-execution","source","entry-profile","entry-config","extra-option","local-owner","duplicate-owner","session"}){
   JSONObject graph=new JSONObject(raw),metadata=new JSONObject(metaRaw),out=byTag(graph,AndroidTorProfile.OUTBOUND);
   switch(fault){
    case "local":metadata.put("execution","local");break;case "auto":metadata.put("execution","auto");break;case "null":metadata.put("execution",JSONObject.NULL);break;case "missing-execution":metadata.remove("execution");break;
    case "missing-entry":metadata.remove("predecessor_profile");break;case "profile-execution":metadata.getJSONObject("tor_profile").put("multihop_execution","local");break;
    case "source":out.put("profile",new JSONObject(out.getString("profile")).put("dns_host","8.8.8.8").toString());break;
    case "entry-profile":out.put("entry_profile",new JSONObject(out.getString("entry_profile")).put("api_token","another-owner").toString());break;
    case "entry-config":out.put("entry_config",out.getString("entry_config")+" ");break;
    case "extra-option":out.put("detour","direct");break;case "local-owner":out.put("type","routervpn-tor");break;
    case "duplicate-owner":graph.getJSONArray("outbounds").put(new JSONObject(out.toString()).put("tag","second"));break;case "session":out.put("session_id","replaced");break;
   }
   String changed=graph.toString();metadata.put("config_sha256",AndroidTorProfile.digest(changed.getBytes(StandardCharsets.UTF_8)));
   rejection(()->AndroidTorProfile.session(changed,metadata.toString(),info.sessionId,info.modeId),fault+" despite updated outer checksum");
  }
  for(String fault:new String[]{"source","cancel"}){
   Path cancelled=Files.createTempDirectory(dir,"server-stale-");AndroidStandardExitStore.Entry selected=tor("obfs4","tcp");String original=AndroidStandardExitStore.snapshot(selected);
   io.nekohasekai.libbox.Libbox.afterCheck=()->{if(fault.equals("source"))selected.torBridges.add(OBFS);else Thread.currentThread().interrupt();};
   try{rejection(()->AndroidTorProfile.prepare(new Context(cancelled.toFile()),file,selected,"shadowsocks","server"),"stale "+fault);}finally{Thread.interrupted();io.nekohasekai.libbox.Libbox.afterCheck=null;}
   check(sessions(cancelled)==0,"stale Server captured private staging");
  }
 }
 static void serverHome(Path dir,String certificate)throws Exception{
  for(String transport:new String[]{"udp","tcp","dot","doh","doh3"}){
   Path app=Files.createTempDirectory(dir,"server-home-");JSONObject source=entry("shadowsocks","off",certificate);
   profile(source).put("adguard_ipv4","10.77.0.53").put("adguard_ipv6","fd77::53");File file=save(dir,source);
   AndroidStandardExitStore.Entry selected=tor("obfs4","doh");selected.torPolicy.put("dns_mode","home").put("dns_protocol",transport).put("dns_host","");
   String before=AndroidStandardExitStore.snapshot(selected);NativeSingBoxController.SessionInfo prepared=AndroidTorProfile.prepare(new Context(app.toFile()),file,selected,"shadowsocks","server");
   Path folder=app.resolve("layered-sessions").resolve(prepared.sessionId);String config=Files.readString(folder.resolve("sing-box.json"));JSONObject metadata=AndroidTorProfile.session(config,Files.readString(folder.resolve(AndroidTorProfile.SESSION_FILE)),prepared.sessionId,prepared.modeId);
   JSONObject dns=tagged(new JSONObject(config).getJSONObject("dns").getJSONArray("servers"),"routervpn-tor-dns");
   check(dns.getString("server").equals("10.77.0.53")&&dns.getInt("server_port")==8443&&dns.getString("detour").equals("proxy"),"Tor Server substituted the private Home resolver or entry");
   check(metadata.getJSONObject("tor_profile").getString("dns_protocol").equals(transport)&&before.equals(AndroidStandardExitStore.snapshot(selected)),"Tor Server rewrote selected Home DNS");
  }
 }
 public static void main(String[] args)throws Exception{
  Path dir=Path.of(args[0]);fixtures=load(Path.of(System.getenv("ROUTERVPN_MAX_MULTIHOP_FIXTURES")));compositeEntry=load(Path.of(System.getenv("ROUTERVPN_COMPOSITE_ENTRY")));compositeExit=load(Path.of(System.getenv("ROUTERVPN_COMPOSITE_EXIT")));
  String certificate=io.nekohasekai.libbox.Libbox.testCertificate("entry.example.test");
  for(String kind:KINDS)for(String mode:ALL)for(int i=0;i<LAYERS.length;i++)server(dir,mode,LAYERS[i],kind,new String[]{"tcp","dot","doh"}[i],certificate);
  check(graphs==342,"Tor Server entry/Start Layer/bridge matrix incomplete");serverNegative(dir,certificate);serverHome(dir,certificate);
  System.out.println("Android Tor Server: PASS ("+graphs+" shipping Java/Go graphs; "+checks+" checks; native traffic separate)");
 }
}
'''

if __name__ == "__main__":
    T.main()
