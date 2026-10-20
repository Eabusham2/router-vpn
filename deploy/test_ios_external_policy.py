#!/usr/bin/env python3
"""Exercise shipping Apple external-node policy with the real shared compiler.

Only the Apple Network/CryptoKit and gomobile boundaries are substituted on
Linux. Native runtime proof and device traffic have separate mandatory gates.
"""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('external_tor_fixture', ROOT / 'deploy/test_ios_tor_profile.py')
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)

SWIFT = T.SWIFT[:T.SWIFT.index('@MainActor final class RouterVPNModel')]
SWIFT += r'''
enum RouterVPNMultihopGraph { static let supportedExitModes:[String]=["wg"] }
enum IOSNativeMAXProfile { static let modeIDs:Set<String>=[] }
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ label:String,_ condition:@autoclosure ()throws->Bool)throws {
  guard try condition() else {throw NSError(domain:"ExternalPolicyTest",code:1,userInfo:[NSLocalizedDescriptionKey:label])};checks+=1
 }
 static func reject(_ label:String,_ operation:()throws->Void)throws {
  do {try operation()} catch {checks+=1;return};throw NSError(domain:"ExpectedExternalPolicyRejection",code:1,userInfo:[NSLocalizedDescriptionKey:label])
 }
 static func profile(_ kind:String)->[String:Any] {
  var e:[String:Any]=["protocol":kind,"expected_public_ip":"203.0.113.88"]
  switch kind {
  case "amneziawg": var block=(profile("wireguard")["external"] as! [String:Any])["wireguard"] as! [String:Any];block["parameters"]=amneziaParameters();block["persistent_keepalive_interval"]=29;e["amneziawg"]=block
  case "wireguard": e["wireguard"]=["endpoint":"198.51.100.8:51820","private_key":key(3),"peer_public_key":key(4),"preshared_key":key(5),"addresses":["10.8.0.2/24","fd00:8::2/64"],"allowed_ips":["0.0.0.0/0","::/0"],"mtu":1420]
  case "socks5": e["socks5"]=["host":"198.51.100.8","port":1080,"username":" saved &<> / user ","password":" saved p\"ass\\word \u{2028}\u{2029} "]
  case "http-connect", "https-connect": var proxy:[String:Any]=["host":"198.51.100.8","port":8443,"username":" exact user ","password":" exact secret "];if kind=="https-connect" {proxy["tls_server_name"]="exit.example.test"};e[kind.replacingOccurrences(of:"-",with:"_")]=proxy
  case "shadowsocks": e["shadowsocks"]=["server":"198.51.100.8","port":8388,"method":"aes-256-gcm","password":" exact &<> secret "]
  case "openvpn": e["openvpn"]=["config":openVPNConfig(),"username":" exact user ","password":" exact OpenVPN secret "]
  default: e["hysteria2"]=["server":"198.51.100.8","port":443,"password":" exact secret ","tls_server_name":"exit.example.test"]
  }
  return ["id":"saved-exit","node_kind":"external","name":"Saved <&> / node \u{2028}\u{2029}","external":e,
          "dns_mode":"custom","dns_protocol":"tcp","dns_host":"9.9.9.9","dns_port":5353,
          "home_lan_access":false,"home_lan_cidrs":["192.168.50.0/24","fd12:3456::/48"],"ipv6_mode":"off",
          "mtu_policy":"fixed","manual_mtu":1380,"effective_mtu":8999,"start_layer":"off"]
 }
 static func amneziaParameters()->[String:String] { ["jc":"3","jmin":"40","jmax":"900","s1":"56","s2":"48","s3":"24","s4":"32","h1":"10000000-19999999","h2":"20000000-29999999","h3":"30000000-39999999","h4":"40000000-49999999"] }
 static func openVPNConfig(_ network:String="udp",_ address:String="198.51.100.8")->String {
  "client\ndev tun\nproto \(network)\nremote \(address) 1194\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint "+String(repeating:"ab",count:32)+"\n"
 }
 static func policies()throws {
  let protocols=["wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn"]
  for kind in protocols {for dns in ["udp","tcp","tls","https","h3"] {for lan in [false,true] {for ipv6 in ["off","on"] {
   var p=profile(kind);p["dns_protocol"]=dns;p["home_lan_access"]=lan;p["ipv6_mode"]=ipv6
   if ["tls","https","h3"].contains(dns){p["dns_server_name"]="resolver.example.test";p["dns_path"]="/captured-query"}
   let before=try json(p)
   if ["http-connect","https-connect"].contains(kind) && ["udp","h3"].contains(dns) {
    try reject("TCP-only exit cannot fake UDP DNS"){_ = try RouterVPNExternalExitBuilder.build(profile:p)};continue
   }
   let result=try RouterVPNExternalExitBuilder.build(profile:p)
   try check("ordinary source has a compiled policy",result.policy != nil && result.torSessionID==nil)
   let policy=result.policy!,graph=try object(result.files["sing-box.json"]!),meta=try object(Data(policy.metadata.utf8))
   let tun=(graph["inbounds"] as! [[String:Any]])[0],route=graph["route"] as! [String:Any],rules=route["rules"] as! [[String:Any]]
   let servers=(graph["dns"] as! [String:Any])["servers"] as! [[String:Any]],selected=servers.first{$0["tag"] as? String=="selected-dns"}!
   try check("both IP families remain captured",(tun["address"] as? [String])?.count==2 && (tun["route_address"] as? [String])?.contains("::/0")==true)
   try check("fixed MTU is applied without historical value",tun["mtu"] as? Int==1380 && meta["configured_mtu"] as? Int==1380)
   try check("configured policy is never live proof",meta["dns_proof"] as? String=="required" && meta["public_exit_proof"] as? String=="required" && meta["auto_mtu"] as? String=="not-requested")
   try check("selected exact DNS transport and port",selected["type"] as? String==dns && selected["server"] as? String=="9.9.9.9" && selected["server_port"] as? Int==5353 && selected["detour"] as? String=="custom-exit")
   try check("IPv6 Off is fail-closed inside TUN",rules.contains{$0["ip_version"] as? Int==6 && $0["action"] as? String=="reject"} == (ipv6=="off"))
   try check("LAN access follows the saved policy",rules.contains{($0["ip_cidr"] as? [String])?.contains("192.168.50.0/24")==true} == !lan)
   try check("DNS port is hijacked independently of protocol sniffing",rules.contains{$0["port"] as? Int==53 && $0["action"] as? String=="hijack-dns"})
   try check("source node remains unchanged",json(p)==before)
   if ["wireguard","amneziawg"].contains(kind){try check("native endpoint owns fixed MTU",(graph["endpoints"] as? [[String:Any]])?[0]["mtu"] as? Int==1380)}
   if kind=="socks5" {let out=(graph["outbounds"] as! [[String:Any]])[0],saved=(p["external"] as! [String:Any])["socks5"] as! [String:Any];try check("credentials remain exact including spaces",out["username"] as? String==saved["username"] as? String && out["password"] as? String==saved["password"] as? String)}
  }}}}
  for kind in protocols {
   var p=profile(kind);p["mtu_policy"]="auto";p["effective_mtu"]=9000
   let result=try RouterVPNExternalExitBuilder.build(profile:p),meta=try object(Data(result.policy!.metadata.utf8))
   try check("Auto is explicitly unmeasured",meta["auto_mtu"] as? String=="unmeasured" && meta["configured_mtu"] as? Int != 9000)
   p["dns_mode"]="home"
   try reject("direct unrelated exit cannot claim Home AdGuard"){_ = try RouterVPNExternalExitBuilder.build(profile:p)}
  }
 }
 static func negativeAdoption()throws {
  let p=profile("socks5"),r=try RouterVPNExternalExitBuilder.build(profile:p),policy=r.policy!
  let envelope:[String:Any]=["schema":1,"source_sha256":policy.sourceSHA256,"config_json":policy.config,"metadata_json":policy.metadata]
  func adopt(_ e:[String:Any],_ source:String?=nil,_ capture:String?=nil)throws {
   _=try RouterVPNExternalPolicy.adopt(text(e),source:source ?? policy.sourceConfig,capture:capture ?? policy.capture,
       exitID:"saved-exit",protocolName:"socks5",expectedPublicIP:"203.0.113.88",entryID:nil,entryTag:nil)
  }
  try adopt(envelope)
  try reject("whitespace changes the captured source hash"){try adopt(envelope,policy.sourceConfig+"\n")}
  try reject("a changed capture cannot adopt old output"){try adopt(envelope,nil,policy.capture+" ")}
  for key in ["source_sha256","config_json"] {
   var e=envelope;e[key]=(e[key] as! String)+" "
   try reject("tampered "+key){try adopt(e)}
  }
  for key in ["exit_id","policy_id","protocol","expected_public_ip","entry_id","entry_tag","dns_proof","public_exit_proof","auto_mtu"] {
   var metadata=try object(Data(policy.metadata.utf8));metadata[key]="wrong"
   var e=envelope;e["metadata_json"]=try text(metadata)
   try reject("mismatched "+key){try adopt(e)}
  }
  for value:Any in [1279,9001,"1380",true] {
   var p=p;p["manual_mtu"]=value
   try reject("invalid fixed MTU type/range"){_ = try RouterVPNExternalExitBuilder.build(profile:p)}
  }
  for field in ["dns_mode","dns_protocol","ipv6_mode"] {var bad=p;bad[field]="unknown";try reject("unknown "+field){_ = try RouterVPNExternalExitBuilder.build(profile:bad)}}
  var bad=p;bad["dns_host"]="resolver.example.test"
  try reject("hostname DNS requires captured bootstrap"){_ = try RouterVPNExternalExitBuilder.build(profile:bad)}
 }
 static func openVPNPaths()throws {
  for network in ["udp","tcp-client"] {
   var p=profile("openvpn"),external=p["external"] as! [String:Any],ovpn=external["openvpn"] as! [String:Any]
   ovpn["config"]=openVPNConfig(network);external["openvpn"]=ovpn;p["external"]=external
   let runtime=try RouterVPNExternalExitBuilder.build(profile:p),policy=runtime.policy!,graph=try object(Data(policy.config.utf8))
   let endpoint=(graph["endpoints"] as! [[String:Any]])[0],capture=try object(Data(policy.capture.utf8))
   try check("OpenVPN stays in the existing native endpoint",endpoint["type"] as? String=="openvpn-client" && endpoint["system"] as? Bool==false)
   try check("OpenVPN credentials retain their exact bytes",endpoint["username"] as? String==ovpn["username"] as? String && endpoint["password"] as? String==ovpn["password"] as? String)
   try check("OpenVPN raw profile remains captured",json((capture["profile"] as! [String:Any])["external"]!)==json(external))
   try check("OpenVPN selected fixed MTU reaches the endpoint",endpoint["mtu"] as? Int==1380)
   try check("OpenVPN requires native DNS and exit proof",(try object(Data(policy.metadata.utf8)))["dns_proof"] as? String=="required")
   var entry=profile("http-connect");entry["id"]="http-entry"
   p["multihop_enabled"]=true;p["multihop_entry_id"]="http-entry";p["multihop_entry_mode"]="http-connect";p["multihop_exit_id"]="saved-exit";p["multihop_exit_mode"]="openvpn";p["multihop_execution"]="local"
   if network=="udp" {
    try reject("UDP OpenVPN cannot be sent through a TCP-only entry"){_ = try RouterVPNExternalExitBuilder.build(profile:p,predecessorProfile:entry)}
   } else {
    for dns in ["tcp","udp","h3"] {
     p["dns_protocol"]=dns
     if dns=="h3" {p["dns_server_name"]="resolver.example.test";p["dns_path"]="/exact-query"}
     let nested=try RouterVPNExternalExitBuilder.build(profile:p,predecessorProfile:entry),nestedGraph=try object(Data(nested.policy!.config.utf8)),meta=try object(Data(nested.policy!.metadata.utf8))
     let final=(nestedGraph["endpoints"] as! [[String:Any]])[0]
     try check("TCP OpenVPN keeps UDP payloads inside its own encrypted stream",final["detour"] as? String=="external-entry" && meta["udp_available"] as? Bool==true && meta["dns_protocol"] as? String==dns)
    }
   }
  }
  for invalid in ["up /private/unowned-script\n","ca /private/unowned-ca\n","remote resolver.example.test 1194\n"] {
   var p=profile("openvpn"),external=p["external"] as! [String:Any],ovpn=external["openvpn"] as! [String:Any]
   ovpn["config"]=openVPNConfig()+invalid;external["openvpn"]=ovpn;p["external"]=external
   try reject("OpenVPN import never adds outside process/file/resolver owners"){_ = try RouterVPNExternalExitBuilder.build(profile:p)}
  }
 }
 static func proofResults()throws {
  let runtime=try RouterVPNExternalExitBuilder.build(profile:profile("socks5")),policy=runtime.policy!
  let meta=try object(Data(policy.metadata.utf8)),began=Date(),session="captured-session"
  let valid:[String:Any]=["schema":1,"session_id":session,"source_sha256":policy.sourceSHA256,
    "config_sha256":meta["config_sha256"]!,"exit_id":"saved-exit","ip":"203.0.113.88",
    "dns_proven":true,"entry_proven":false,"checked_at":Int64(Date().timeIntervalSince1970*1000)]
  try policy.validateProof(text(valid),sessionID:session,began:began);checks+=1
  for key in ["schema","session_id","source_sha256","config_sha256","exit_id","ip","dns_proven","entry_proven","checked_at"] {
   var bad=valid;bad.removeValue(forKey:key)
   try reject("missing native result "+key){try policy.validateProof(text(bad),sessionID:session,began:began)}
  }
  let mutations:[(String,Any)]=[("schema",true),("schema",2),("session_id","retired"),("source_sha256","wrong"),
    ("config_sha256","wrong"),("exit_id","other-exit"),("ip","203.0.113.89"),("ip","203.0.113.88 "),
    ("dns_proven",false),("dns_proven",1),("entry_proven",true),("entry_proven",0),
    ("entry_id","other-entry"),("entry_node_id","other-private-node"),("checked_at",true),
    ("checked_at",Int64(Date().addingTimeInterval(-60).timeIntervalSince1970*1000)),
    ("checked_at",Int64(Date().addingTimeInterval(60).timeIntervalSince1970*1000))]
  for (key,value) in mutations {
   var bad=valid;bad[key]=value
   try reject("foreign/stale native result "+key){try policy.validateProof(text(bad),sessionID:session,began:began)}
  }
  try reject("oversized native response"){try policy.validateProof(String(repeating:" ",count:8193),sessionID:session,began:began)}
 }
 static func hostnameBootstrap()throws {
  for kind in ["wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn"] {
   for transport in ["tcp","udp","tls","https","h3"] {
    var p=profile(kind);p["dns_mode"]="doh";p["dns_host"]="resolver.example.test";p["dns_server_name"]="resolver.example.test";p["dns_port"]=443;p["dns_path"]="/captured-query"
    var server:[String:Any]=["type":transport,"tag":"external-dns-bootstrap","server":"9.9.9.9","server_port":5353,"detour":"custom-exit"]
    if ["tls","https","h3"].contains(transport){server["tls"]=["enabled":true,"server_name":"bootstrap.example.test"]}
    if ["https","h3"].contains(transport){server["path"]="/bootstrap-query"}
    let query:[String:Any]=["server":"external-dns-bootstrap","strategy":"ipv4_only","timeout":"3.5s","disable_cache":true,"disable_optimistic_cache":false,"rewrite_ttl":13,"client_subnet":"192.0.2.0/24"]
    let bootstrap:[String:Any]=["server":server,"query":query];p["dns_bootstrap"]=bootstrap
    if ["http-connect","https-connect"].contains(kind) && ["udp","h3"].contains(transport){try reject("TCP-only path rejects UDP bootstrap"){_ = try RouterVPNExternalExitBuilder.build(profile:p)};continue}
    let before=try json(p),runtime=try RouterVPNExternalExitBuilder.build(profile:p),policy=runtime.policy!
    let capture=try object(Data(policy.capture.utf8)),graph=try object(Data(policy.config.utf8)),meta=try object(Data(policy.metadata.utf8))
    let servers=(graph["dns"] as! [String:Any])["servers"] as! [[String:Any]],selected=servers.first{$0["tag"] as? String=="selected-dns"}!
    try check("complete explicit bootstrap capture is exact",json(capture["dns_bootstrap"]!)==json(bootstrap) && (capture["profile"] as! [String:Any])["dns_bootstrap"]==nil)
    try check("bootstrap transport retained by native compiler",json(servers.first{$0["tag"] as? String=="external-dns-bootstrap"}!)==json(server))
    try check("query options keep exact native resolver owner",json(selected["domain_resolver"]!)==json(query))
    try check("selected hostname and TLS identity survive",selected["server"] as? String=="resolver.example.test" && (selected["tls"] as? [String:Any])?["server_name"] as? String=="resolver.example.test")
    try check("bootstrap identity is included in metadata",(meta["dns_bootstrap_sha256"] as? String)?.count==64)
    try check("compiler capture does not mutate saved node",json(p)==before)
    for mutation in ["detour","server","query","timeout","cache","extra"] {
     var bad=p,wrong=bootstrap,s=server,q=query
     switch mutation {
     case "detour":s["detour"]="direct"
     case "server":s["server"]="another-resolver.example.test"
     case "query":q["server"]="selected-dns"
     case "timeout":q["timeout"]="forever"
     case "cache":q["disable_cache"]="true"
     default:q["unowned"]=true
     }
     wrong["server"]=s;wrong["query"]=q;bad["dns_bootstrap"]=wrong
     try reject("foreign bootstrap "+mutation){_ = try RouterVPNExternalExitBuilder.build(profile:bad)}
    }
    var literal=p;literal["dns_host"]="9.9.9.9"
    try reject("literal DNS cannot retain unused bootstrap"){_ = try RouterVPNExternalExitBuilder.build(profile:literal)}
   }
  }
 }
 static func entryGraphs()throws {
  let protocols=["wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn"]
  for entryKind in protocols {for exitKind in protocols {
   var entry=profile(entryKind),exit=profile(exitKind)
   entry["id"]="saved-entry";entry["home_lan_cidrs"]=["10.20.0.0/16"];entry["ipv6_mode"]="off"
   if ["wireguard","amneziawg"].contains(entryKind) {entry["manual_mtu"]=1500;var ext=entry["external"] as! [String:Any],wg=ext[entryKind] as! [String:Any];wg["private_key"]=key(9);wg["peer_public_key"]=key(10);ext[entryKind]=wg;entry["external"]=ext}
   if entryKind=="openvpn" {entry["manual_mtu"]=1500}
   if ["wireguard","amneziawg","openvpn"].contains(entryKind) && ["wireguard","amneziawg","openvpn"].contains(exitKind) {exit["manual_mtu"]=1280}
   exit["multihop_enabled"]=true;exit["multihop_entry_id"]="saved-entry";exit["multihop_entry_mode"]=entryKind
   exit["multihop_exit_id"]="saved-exit";exit["multihop_exit_mode"]=exitKind;exit["multihop_execution"]="local";exit["ipv6_mode"]="on"
   if ["http-connect","https-connect"].contains(entryKind) && ["wireguard","amneziawg","hysteria2","openvpn"].contains(exitKind) {
    try reject("TCP-only entry cannot carry UDP exit"){_ = try RouterVPNExternalExitBuilder.build(profile:exit,predecessorProfile:entry)};continue
   }
   let beforeEntry=try json(entry),beforeExit=try json(exit)
   let r=try RouterVPNExternalExitBuilder.build(profile:exit,predecessorProfile:entry),graph=try object(r.files["sing-box.json"]!),meta=try object(Data(r.policy!.metadata.utf8))
   let nodes=(graph["outbounds"] as! [[String:Any]])+(graph["endpoints"] as! [[String:Any]])
   try check("both exact native owners survive",nodes.count==2 && nodes.filter{$0["tag"] as? String=="external-entry"}.count==1)
   try check("selected exit is nested through entry",nodes.first{$0["tag"] as? String=="custom-exit"}?["detour"] as? String=="external-entry")
   try check("entry policy participates in IPv6/LAN",meta["ipv6_mode"] as? String=="off" && (meta["blocked_lan_cidrs"] as? [String])?.contains("10.20.0.0/16")==true)
   try check("exit DNS keeps the exit route",meta["dns_detour"] as? String=="custom-exit")
   try check("captured entry profile remains private and exact",json(entry)==beforeEntry && json(exit)==beforeExit && meta["entry_id"] as? String=="saved-entry")
   for field in ["multihop_entry_id","multihop_entry_mode","multihop_exit_id","multihop_exit_mode","multihop_execution"] {
    var bad=exit;bad[field]="wrong"
    try reject("foreign saved graph "+field){_ = try RouterVPNExternalExitBuilder.build(profile:bad,predecessorProfile:entry)}
   }
   try reject("missing captured entry cannot become direct"){_ = try RouterVPNExternalExitBuilder.build(profile:exit)}
  }}
  let node=SHA256.hash(data:Data(("router-vpn-node-proof-v1\n"+key(4)).utf8)).map{String(format:"%02x",$0)}.joined()
  var router:[String:Any]=["id":"paired-home","node_kind":"router-vpn","node_proof_id":node,"router_api":"http://10.8.0.1:8787","api_token":"private-entry-token","adguard_ipv4":"192.168.50.133","mtu_policy":"fixed","manual_mtu":1500,"home_lan_access":false,"ipv6_mode":"on","start_layer":"off"]
  var input=profile("wireguard");input["manual_mtu"]=1500;input["ipv6_mode"]="on"
  let direct=try RouterVPNExternalExitBuilder.build(profile:input)
  // A real lowered one-TUN source, retaining its DNS and route policy. Change
  // only the test's final tag; the native predecessor validator checks keys.
  let complete=direct.policy!.config.replacingOccurrences(of:"custom-exit",with:"proxy")
  let files=["sing-box.json":Data(complete.utf8)]
  var exit=profile("socks5");exit["dns_mode"]="home";exit["dns_host"]="192.168.50.133";exit["multihop_enabled"]=true;exit["multihop_entry_id"]="paired-home";exit["multihop_entry_mode"]="wg";exit["multihop_exit_id"]="saved-exit";exit["multihop_exit_mode"]="socks5";exit["multihop_execution"]="local"
  let r=try RouterVPNExternalExitBuilder.build(profile:exit,predecessorFiles:files,predecessorProfile:router),meta=try object(Data(r.policy!.metadata.utf8))
  try check("Home DNS stays on the proven paired entry",meta["dns_detour"] as? String=="external-entry" && meta["dns_server"] as? String=="192.168.50.133" && meta["entry_proof"] as? String=="required")
  try check("per-hop fixed MTUs retain separate owners",meta["entry_mtu"] as? Int==1500 && meta["configured_mtu"] as? Int==1380)
  router["node_proof_id"]="invalid"
  try reject("Home DNS cannot adopt an unpaired entry"){_ = try RouterVPNExternalExitBuilder.build(profile:exit,predecessorFiles:files,predecessorProfile:router)}
 }
 static func importedAmnezia()throws {
  let p=profile("amneziawg"),r=try RouterVPNExternalExitBuilder.build(profile:p),policy=r.policy!,g=try object(Data(policy.config.utf8))
  let awg=(g["endpoints"] as! [[String:Any]])[0],peer=(awg["peers"] as! [[String:Any]])[0]
  try check("imported AWG keeps its native protocol",awg["type"] as? String=="routervpn-amneziawg")
  try check("all eleven strings and header ranges remain exact",json(awg["amnezia"]!)==json(amneziaParameters()) && peer["persistent_keepalive_interval"] as? Int==29)
  for (field,value):(String,Any) in [("parameters",["s4":"32"]),("parameters",amneziaParameters().merging(["i1":"unowned"],uniquingKeysWith:{$1})),("parameters",amneziaParameters().merging(["s4":" 32"],uniquingKeysWith:{$1})),("parameters",amneziaParameters().merging(["h2":"10000001"],uniquingKeysWith:{$1})),("parameters",["jc":3]),("persistent_keepalive_interval",-1),("persistent_keepalive_interval",65536),("persistent_keepalive_interval",true),("persistent_keepalive_interval","29")] {
   var bad=p,ext=bad["external"] as! [String:Any],block=ext["amneziawg"] as! [String:Any];block[field]=value;ext["amneziawg"]=block;bad["external"]=ext
   try reject("invalid imported AWG "+field){_ = try RouterVPNExternalExitBuilder.build(profile:bad)}
  }
  var native=try object(Data(policy.sourceConfig.utf8)),endpoints=native["endpoints"] as! [[String:Any]]
  endpoints[0]["type"]="wireguard";endpoints[0].removeValue(forKey:"amnezia");native["endpoints"]=endpoints
  try reject("an imported AWG capture cannot become ordinary WG"){_ = try bridge(["Op":"external-policy","Config":text(native),"Policy":policy.capture])}
  for value in [0,1,65535] {
   var varied=p,ext=varied["external"] as! [String:Any],block=ext["amneziawg"] as! [String:Any];block["persistent_keepalive_interval"]=value;ext["amneziawg"]=block;varied["external"]=ext
   let out=try RouterVPNExternalExitBuilder.build(profile:varied),graph=try object(Data(out.policy!.config.utf8)),endpoint=(graph["endpoints"] as! [[String:Any]])[0]
   try check("every valid keepalive stays exact",(endpoint["peers"] as! [[String:Any]])[0]["persistent_keepalive_interval"] as? Int==value)
  }
 }
 static func main() {
  defer{RouterVPNTorTestClose()}
  do {
   try policies();try negativeAdoption();try proofResults();try entryGraphs();try hostnameBootstrap();try openVPNPaths();try importedAmnezia()
   print("Apple ordinary external policy: PASS (\(checks) shipping Swift/real Go checks; OS/FFI boundaries substituted)")
  } catch { FileHandle.standardError.write(Data((error.localizedDescription+"\n").utf8));exit(1) }
 }
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='.ios-external-policy-', dir=ROOT) as source, tempfile.TemporaryDirectory(prefix='ios-external-policy-') as temp:
        source, work = Path(source), Path(temp)
        (source / 'main.go').write_text(T.GO)
        compiler = work / 'compiler'
        subprocess.run(['go', 'build', '-o', str(compiler), str(source / 'main.go')], cwd=ROOT, check=True, timeout=180)
        suffix = '.dylib' if platform.system() == 'Darwin' else '.so'
        modules = [('WireGuardKit', T.W.TYPES), ('Libbox', T.LIBBOX)]
        if platform.system() != 'Darwin':
            modules.append(('Network', T.NETWORK))
        for name, body in modules:
            code = work / (name + '.swift'); code.write_text(body)
            subprocess.run(['swiftc', '-swift-version', '6', '-module-cache-path', str(work / 'module-cache'), '-emit-module', '-emit-library', '-module-name', name,
                            str(code), '-emit-module-path', str(work / (name + '.swiftmodule')), '-o', str(work / ('lib' + name + suffix))], check=True, timeout=90)
        code = work / 'Test.swift'; code.write_text(SWIFT)
        command = ['swiftc', '-swift-version', '6', '-module-cache-path', str(work / 'module-cache'), '-I', str(work), '-L', str(work), '-lWireGuardKit', '-lLibbox']
        if platform.system() != 'Darwin':
            command += ['-lNetwork']
        command += ['-Xlinker', '-rpath', '-Xlinker', str(work), str(ROOT / 'ios/RouterVPN/PacketTunnel/RouterVPNExternalExit.swift'), str(code), '-o', str(work / 'tests')]
        subprocess.run(command, check=True, timeout=120)
        subprocess.run([str(work / 'tests'), str(compiler)], check=True, timeout=90)


if __name__ == '__main__':
    main()
