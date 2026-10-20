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
enum RouterVPNMultihopGraph { static let supportedExitModes:[String]=[] }
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
  case "wireguard": e["wireguard"]=["endpoint":"198.51.100.8:51820","private_key":key(3),"peer_public_key":key(4),"preshared_key":key(5),"addresses":["10.8.0.2/24","fd00:8::2/64"],"allowed_ips":["0.0.0.0/0","::/0"],"mtu":1420]
  case "socks5": e["socks5"]=["host":"198.51.100.8","port":1080,"username":" saved &<> / user ","password":" saved p\"ass\\word \u{2028}\u{2029} "]
  case "http-connect", "https-connect": var proxy:[String:Any]=["host":"198.51.100.8","port":8443,"username":" exact user ","password":" exact secret "];if kind=="https-connect" {proxy["tls_server_name"]="exit.example.test"};e[kind.replacingOccurrences(of:"-",with:"_")]=proxy
  case "shadowsocks": e["shadowsocks"]=["server":"198.51.100.8","port":8388,"method":"aes-256-gcm","password":" exact &<> secret "]
  default: e["hysteria2"]=["server":"198.51.100.8","port":443,"password":" exact secret ","tls_server_name":"exit.example.test"]
  }
  return ["id":"saved-exit","node_kind":"external","name":"Saved <&> / node \u{2028}\u{2029}","external":e,
          "dns_mode":"custom","dns_protocol":"tcp","dns_host":"9.9.9.9","dns_port":5353,
          "home_lan_access":false,"home_lan_cidrs":["192.168.50.0/24","fd12:3456::/48"],"ipv6_mode":"off",
          "mtu_policy":"fixed","manual_mtu":1380,"effective_mtu":8999,"start_layer":"off"]
 }
 static func policies()throws {
  let protocols=["wireguard","socks5","http-connect","https-connect","shadowsocks","hysteria2"]
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
   if kind=="wireguard"{try check("native endpoint owns fixed MTU",(graph["endpoints"] as? [[String:Any]])?[0]["mtu"] as? Int==1380)}
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
 static func entryGraphs()throws {
  let protocols=["wireguard","socks5","http-connect","https-connect","shadowsocks","hysteria2"]
  for entryKind in protocols {for exitKind in protocols {
   var entry=profile(entryKind),exit=profile(exitKind)
   entry["id"]="saved-entry";entry["home_lan_cidrs"]=["10.20.0.0/16"];entry["ipv6_mode"]="off"
   if entryKind=="wireguard" {entry["manual_mtu"]=1500;var ext=entry["external"] as! [String:Any],wg=ext["wireguard"] as! [String:Any];wg["private_key"]=key(9);wg["peer_public_key"]=key(10);ext["wireguard"]=wg;entry["external"]=ext}
   exit["multihop_enabled"]=true;exit["multihop_entry_id"]="saved-entry";exit["multihop_entry_mode"]=entryKind
   exit["multihop_exit_id"]="saved-exit";exit["multihop_exit_mode"]=exitKind;exit["multihop_execution"]="local";exit["ipv6_mode"]="on"
   if ["http-connect","https-connect"].contains(entryKind) && ["wireguard","hysteria2"].contains(exitKind) {
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
  var router:[String:Any]=["id":"paired-home","node_kind":"router-vpn","node_proof_id":String(repeating:"a",count:64),"router_api":"http://10.8.0.1:8787","api_token":"private-entry-token","adguard_ipv4":"192.168.50.133","mtu_policy":"fixed","manual_mtu":1500,"home_lan_access":false,"ipv6_mode":"on","start_layer":"off"]
  let direct=try RouterVPNExternalExitBuilder.build(profile:profile("wireguard")),original=try object(Data(direct.policy!.sourceConfig.utf8))
  var endpoint=(original["endpoints"] as! [[String:Any]])[0];endpoint["tag"]="external-entry"
  let files=["sing-box.json":try json(["endpoints":[endpoint],"route":["final":"external-entry"]])]
  var exit=profile("socks5");exit["dns_mode"]="home";exit["dns_host"]="192.168.50.133";exit["multihop_enabled"]=true;exit["multihop_entry_id"]="paired-home";exit["multihop_entry_mode"]="wg";exit["multihop_exit_id"]="saved-exit";exit["multihop_exit_mode"]="socks5";exit["multihop_execution"]="local"
  let r=try RouterVPNExternalExitBuilder.build(profile:exit,predecessorFiles:files,predecessorProfile:router),meta=try object(Data(r.policy!.metadata.utf8))
  try check("Home DNS stays on the proven paired entry",meta["dns_detour"] as? String=="external-entry" && meta["dns_server"] as? String=="192.168.50.133" && meta["entry_proof"] as? String=="required")
  try check("per-hop fixed MTUs retain separate owners",meta["entry_mtu"] as? Int==1500 && meta["configured_mtu"] as? Int==1380)
  router["node_proof_id"]="invalid"
  try reject("Home DNS cannot adopt an unpaired entry"){_ = try RouterVPNExternalExitBuilder.build(profile:exit,predecessorFiles:files,predecessorProfile:router)}
 }
 static func main()throws {
  defer{RouterVPNTorTestClose()}
  try policies();try negativeAdoption();try proofResults();try entryGraphs()
  print("Apple ordinary external policy: PASS (\(checks) shipping Swift/real Go checks; OS/FFI boundaries substituted)")
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
