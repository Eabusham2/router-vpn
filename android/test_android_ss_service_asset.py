#!/usr/bin/env python3
"""Actual Android capture/session consumers with the shared Go source validator."""
from pathlib import Path
import importlib.util
ROOT=Path(__file__).resolve().parents[1]
TEST=r'''
 static String sha(byte[] raw)throws Exception{return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(raw));}
 static void service(JSONObject b)throws Exception {
  JSONObject p=profile(b);p.put("node_kind","router-vpn").put("node_proof_id",b.getString("nodeProofId"));
  JSONObject assets=b.getJSONObject("profiles").getJSONObject("shadowsocks");
  byte[] raw=Base64.getDecoder().decode(assets.getString("sing-box.json"));JSONObject out=new JSONObject(new String(raw,StandardCharsets.UTF_8)).getJSONArray("outbounds").getJSONObject(0);
  JSONObject claim=new JSONObject().put("schema",1).put("node_id",p.getString("node_proof_id")).put("configured_image","ghcr.io/sagernet/sing-box:v1.13.12").put("uot_version",2).put("endpoint",out.getString("server")).put("port",out.getInt("server_port")).put("method",out.getString("method")).put("key_sha256",sha(out.getString("password").getBytes(StandardCharsets.UTF_8))).put("source_sha256",sha(raw));
  assets.put("routervpn-ss-service.json",Base64.getEncoder().encodeToString(claim.toString().getBytes(StandardCharsets.UTF_8)));
 }
 static JSONObject serviceBundle(String mode)throws Exception {
  JSONObject b=mode.startsWith("reality-")?xrayBundle(mode,"node.example.test"):proxyBundle('a',"shadowsocks","");
  JSONObject assets=b.getJSONObject("profiles").getJSONObject("shadowsocks"),g=new JSONObject(new String(Base64.getDecoder().decode(assets.getString("sing-box.json")),StandardCharsets.UTF_8));
  g.getJSONArray("outbounds").getJSONObject(0).put("method","2022-blake3-aes-256-gcm").put("password",key('s'));
  if(mode.equals("wg"))g.getJSONArray("outbounds").getJSONObject(0).put("server","node.example.test");
  assets.put("sing-box.json",Base64.getEncoder().encodeToString(g.toString().getBytes(StandardCharsets.UTF_8)));service(b);return b;
 }
 public static void main(String[] args)throws Exception {
  Path dir=Path.of(args[0]);
  for(String mode:List.of("shadowsocks","wg","reality-vision","reality-xhttp"))for(String layer:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening")) {
   if(mode.equals("wg")&&!layer.equals("off"))continue;
   JSONObject b=serviceBundle(mode);profile(b).put("start_layer",layer).put("dns_mode","custom").put("dns_protocol","tcp").put("dns_host","192.0.2.53").put("dns_port",5353);
   String original=b.getJSONObject("profiles").getJSONObject("shadowsocks").toString();
   Path app=Files.createTempDirectory(dir,"service-owner-");NativeSingBoxController c=new NativeSingBoxController(new Context(app.toFile()));File file=save(dir,b);byte[] saved=Files.readAllBytes(file.toPath());
   check(c.listDirectLibboxModes(file).stream().anyMatch(x->x.id.equals(mode)),"captured service hid existing mode "+mode+layer);
   NativeSingBoxController.SessionInfo info=c.prepareSession(file,mode);Path session=app.resolve("layered-sessions").resolve(info.sessionId);
   JSONObject graph=new JSONObject(Files.readString(session.resolve("sing-box.json"))),dns=graph.getJSONObject("dns").getJSONArray("servers").getJSONObject(0);
   check(dns.getString("server").equals("192.0.2.53")&&dns.getInt("server_port")==5353&&dns.getString("type").equals("tcp"),"selected DNS was lost");
   check(Arrays.equals(saved,Files.readAllBytes(file.toPath()))&&original.equals(b.getJSONObject("profiles").getJSONObject("shadowsocks").toString()),"original source mutated");
   check(!Files.exists(session.resolve("routervpn-ss-service.json"))&&!Files.exists(session.resolve("start-layer-source.json")),"consumed source claim escaped into rewritten graph");
   if(mode.startsWith("reality-")&&!layer.equals("off")) {
    AndroidXrayLibboxPolicy.resolve(b,b.getJSONObject("profiles").getJSONObject(mode),mode);
    check(original.equals(b.getJSONObject("profiles").getJSONObject("shadowsocks").toString()),"resolved AES overwrote original SS");
    check(b.getJSONObject("profiles").getJSONObject(mode).has("start-layer-source.json"),"resolved candidate lost its AES projection");
    AndroidStartLayer.validateSSService(b);
   }
  }
  for(String fault:List.of("node","missing-node","node-type","source","key","endpoint","image","version","extra","malformed")) {
   JSONObject b=serviceBundle("shadowsocks"),assets=b.getJSONObject("profiles").getJSONObject("shadowsocks");
   JSONObject claim=new JSONObject(new String(Base64.getDecoder().decode(assets.getString("routervpn-ss-service.json")),StandardCharsets.UTF_8));
   if(fault.equals("node"))claim.put("node_id","b".repeat(64));
   if(fault.equals("missing-node"))profile(b).remove("node_proof_id");
   if(fault.equals("node-type"))profile(b).put("node_proof_id",true);
   if(fault.equals("source"))claim.put("source_sha256","b".repeat(64));
   if(fault.equals("key"))claim.put("key_sha256","b".repeat(64));
   if(fault.equals("endpoint"))claim.put("endpoint","foreign.example.test");
   if(fault.equals("image"))claim.put("configured_image","foreign:latest");
   if(fault.equals("version"))claim.put("uot_version",1);
   if(fault.equals("extra"))claim.put("unowned",true);
   assets.put("routervpn-ss-service.json",Base64.getEncoder().encodeToString((fault.equals("malformed")?"{":claim.toString()).getBytes(StandardCharsets.UTF_8)));
   Path app=Files.createTempDirectory(dir,"service-negative-");NativeSingBoxController c=new NativeSingBoxController(new Context(app.toFile()));File file=save(dir,b);byte[] original=Files.readAllBytes(file.toPath());
   check(c.listDirectLibboxModes(file).isEmpty(),"picker accepted foreign source "+fault);
   boolean refused=false;try{c.prepareSession(file,"shadowsocks");}catch(Exception expected){refused=true;}
   check(refused&&sessions(app)==0&&Arrays.equals(original,Files.readAllBytes(file.toPath())),"foreign source staged or changed original "+fault);
  }
  for(String fault:List.of("password","server_port","method","graph")) {
   JSONObject b=serviceBundle("reality-vision");profile(b).put("start_layer","aes-256-gcm");String original=b.toString();
   Path app=Files.createTempDirectory(dir,"projection-negative-");NativeSingBoxController controller=new NativeSingBoxController(new Context(app.toFile()));File file=save(dir,b);
   io.nekohasekai.libbox.Libbox.ssResolvedMutation=result->{try{
    JSONObject response=new JSONObject(result),source=new JSONObject(new String(Base64.getDecoder().decode(response.getString("start-layer-source.json")),StandardCharsets.UTF_8));
    if(fault.equals("graph"))source.put("unowned",true);else source.getJSONArray("outbounds").getJSONObject(0).put(fault,fault.equals("server_port")?9999:fault.equals("password")?key('z'):"foreign");
    response.put("start-layer-source.json",Base64.getEncoder().encodeToString(source.toString().getBytes(StandardCharsets.UTF_8)));return response.toString();
   }catch(Exception error){throw new IllegalStateException(error);}};
   try {boolean rejected=false;try{controller.prepareSession(file,"reality-vision");}catch(Exception expected){rejected=true;}check(rejected&&sessions(app)==0&&Files.readString(file.toPath()).equals(original),"resolver substitution staged candidate "+fault);}
   finally{io.nekohasekai.libbox.Libbox.ssResolvedMutation=null;}
   JSONObject candidate=b.getJSONObject("profiles").getJSONObject("reality-vision");String graph=AndroidXrayLibboxPolicy.resolve(b,candidate,"reality-vision");
   JSONObject source=new JSONObject(new String(Base64.getDecoder().decode(candidate.getString("start-layer-source.json")),StandardCharsets.UTF_8));
   if(fault.equals("graph"))source.put("unowned",true);else source.getJSONArray("outbounds").getJSONObject(0).put(fault,fault.equals("server_port")?9999:fault.equals("password")?key('z'):"foreign");
   candidate.put("start-layer-source.json",Base64.getEncoder().encodeToString(source.toString().getBytes(StandardCharsets.UTF_8)));
   boolean rejected=false;try{AndroidStartLayer.apply(b,new JSONObject(graph),"reality-vision");}catch(Exception expected){rejected=true;}check(rejected,"consumption accepted altered resolved AES "+fault);
  }
  JSONObject falseResult=serviceBundle("shadowsocks");io.nekohasekai.libbox.Libbox.rejectSSService=true;
  try {boolean failed=false;try{AndroidStartLayer.validateSSService(falseResult);}catch(Exception expected){failed=true;}check(failed,"false native validation result accepted");}finally{io.nekohasekai.libbox.Libbox.rejectSSService=false;}
  System.out.println("Android SS service capture: PASS "+checks+" actual shipping/Go checks; no native socket claim");
 }
}
'''
def main():
 spec=importlib.util.spec_from_file_location('ss_service_android_fixture',ROOT/'android/test_android_multihop_graph.py')
 fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
 marker=' public static void main(String[] args)throws Exception {'
 if fixture.HARNESS.count(marker)!=1:raise ValueError('Actual Java fixture entry changed')
 fixture.HARNESS=fixture.HARNESS.split(marker,1)[0]+TEST
 fixture.main()
if __name__=='__main__':main()
