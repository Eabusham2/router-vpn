#!/usr/bin/env python3
"""Execute shared Home policy, shipping app resolver and PacketTunnel graph.

Network address parsing uses the existing Linux shim; no DNS service, OS VPN,
Keychain or physical path proof is claimed. Native Go compiler parity is a
separate executable test using its real graph compiler.
"""
from pathlib import Path
import importlib.util
import platform
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
TUN=ROOT/'ios/RouterVPN/PacketTunnel'
spec=importlib.util.spec_from_file_location('base',ROOT/'deploy/test_ios_native_base_selection.py')
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
TEST=r'''
import Foundation
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ value:@autoclosure ()throws->Bool)throws {guard try value()else{throw NSError(domain:"HomeDNS",code:1,userInfo:[NSLocalizedDescriptionKey:name])};checks+=1}
 static func reject(_ name:String,_ body:()throws->Void)throws {do{try body()}catch{checks+=1;return};throw NSError(domain:"HomeDNS",code:2,userInfo:[NSLocalizedDescriptionKey:"Accepted "+name])}
 static func data(_ value:Any)throws->Data{try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
 static func profile(_ proto:String,_ host:String,_ port:Int=5443)->[String:Any] {
  ["id":"home","name":"Home","node_kind":"router-vpn","node_proof_id":String(repeating:"a",count:64),"endpoint":"198.51.100.2",
   "router_api":"http://10.77.0.1:8787","api_token":"own-token","adguard_ipv4":"192.168.50.133","adguard_ipv6":"fd12::53",
   "socks_host":"10.77.0.1","socks_port":1080,"socks_username":"","socks_password":"",
   "dns_mode":"home","dns_protocol":proto,"dns_host":host,"dns_port":port,"dns_server_name":"adguard.home.example","dns_path":"/owned-query",
   "ipv6_mode":"on","mtu_policy":"fixed","manual_mtu":1380,"home_lan_access":true,"start_layer":"off"]
 }
 static var endpoint:[String:Any] {
  let key=Data(repeating:1,count:32).base64EncodedString()
  return ["type":"wireguard","address":["10.77.0.2/32","fd77::2/128"],"private_key":key,"mtu":1380,
    "peers":[["address":"198.51.100.2","port":51820,"public_key":key,"allowed_ips":["0.0.0.0/0","::/0"]]]]
 }
 static func decoded(_ value:[String:Any])throws->RouterProfile{try JSONDecoder().decode(RouterProfile.self,from:data(value))}
 static func graph(_ value:[String:Any],_ host:String)throws->[String:Any] {
  let files=try RouterVPNMultihopGraph.wireGuardFiles(endpoint:endpoint,profile:value,dnsServers:[host])
  return try JSONSerialization.jsonObject(with:files["sing-box.json"]!) as! [String:Any]
 }
 static func main() throws {
  for proto in ["udp","tcp","tls","https","h3"] {for host in ["192.168.50.133","fd12::53"] {for port in [0,5443] {
   let value=profile(proto,host,port),p=try decoded(value),resolved=try IOSDNSRuntimePolicy.resolve(p)!
   let wantedPort=port==0 ? (proto=="tls" ? 853:["https","h3"].contains(proto) ? 443:53):port
   try check("app retains exact Home transport/address/port",resolved.type==proto && resolved.host==host && resolved.port==wantedPort)
   var bundle=ClientBundle.empty;bundle.routerProfiles=[p];bundle.selectedRouterID=p.id
   try check("raw WG capability follows selected Home policy",try IOSDNSRuntimePolicy.requiresWireGuardLibbox(in:bundle)==(!(proto=="udp" && wantedPort==53)))
   for mode in ["wg","awg2-fast","awg2-strong"] {
    let asset=mode=="wg" ? "wg.conf":"awg.conf",raw="[Interface]\nPrivateKey = captured-own-key\nDNS = "+host+"\n"
    bundle.profiles[mode]=[asset:Data(raw.utf8).base64EncodedString()]
    let selected=try IOSRuntimeSelector.selectRaw(bundle:bundle,rawProfileID:mode)
    try check("single WG/AWG selects owned engine without changing raw peer",selected.engine == ((proto=="udp" && wantedPort==53) ? .wireGuard:.libbox) && selected.rawProfileID==mode && selected.files[asset]==Data(raw.utf8))
   }
   let graph=try graph(value,host),dns=graph["dns"] as! [String:Any],servers=dns["servers"] as! [[String:Any]],server=servers[0]
   try check("PacketTunnel retains exact Home fields and final owner",servers.count==1 && server["type"] as? String==proto && server["server"] as? String==host && server["server_port"] as? Int==wantedPort && server["detour"] as? String=="proxy")
   if ["tls","https","h3"].contains(proto) {try check("both retain TLS identity",resolved.serverName=="adguard.home.example" && (server["tls"] as? [String:Any])?["server_name"] as? String==resolved.serverName)}
   if ["https","h3"].contains(proto) {try check("both retain HTTP path",resolved.path=="/owned-query" && server["path"] as? String==resolved.path)}
   // The exact typed resolver survives the ordinary Router multihop builder.
   var entry=value;entry["id"]="entry";entry["node_proof_id"]=String(repeating:"b",count:64)
   var entryEndpoint=endpoint,entryPeers=endpoint["peers"] as! [[String:Any]];entryPeers[0]["public_key"]=Data(repeating:2,count:32).base64EncodedString();entryEndpoint["peers"]=entryPeers
   let nested=try RouterVPNMultihopGraph.build(entryEndpoint:entryEndpoint,entryProfile:entry,exitProfile:value,exitMode:"wg",files:["sing-box.json":data(graph)])
   let nestedGraph=try JSONSerialization.jsonObject(with:nested["sing-box.json"]!) as! [String:Any]
   try check("nested exit keeps exact selected DNS",try data(nestedGraph["dns"]!)==data(dns))
  }}}
  var defaults=profile("","",0);defaults.removeValue(forKey:"dns_server_name");defaults.removeValue(forKey:"dns_path")
  let defaultPolicy=try IOSDNSRuntimePolicy.resolve(decoded(defaults))!
  try check("untouched Home default stays first AdGuard UDP53",defaultPolicy.type=="udp" && defaultPolicy.host=="192.168.50.133" && defaultPolicy.port==53)
  for alias in ["dot":"tls","doh":"https","doh3":"h3"] {try check("supported aliases retain protocol",try IOSDNSRuntimePolicy.resolve(decoded(profile(alias.key,"192.168.50.133")))!.type==alias.value)}
  for fault in ["foreign","public-home","empty-home","invalid-port","negative-port","unknown-transport","ipv6-off","no-tls-name","ip-tls-name","numeric-tls-name","remote-path","query-path","fragment-path","bad-percent","unicode-path","wrong-family","noncanonical-home","nul"] {
   var p=profile("https","192.168.50.133")
   switch fault {
   case "foreign":p["dns_host"]="192.168.99.1"
   case "public-home":p["adguard_ipv4"]="1.1.1.1";p["dns_host"]="1.1.1.1"
   case "empty-home":p["adguard_ipv4"]="";p["adguard_ipv6"]="";p["dns_host"]=""
   case "invalid-port":p["dns_port"]=65536
   case "negative-port":p["dns_port"] = -1
   case "unknown-transport":p["dns_protocol"]="direct"
   case "ipv6-off":p["dns_host"]="fd12::53";p["ipv6_mode"]="off"
   case "no-tls-name":p["dns_server_name"]=""
   case "ip-tls-name":p["dns_server_name"]="192.168.50.133"
   case "numeric-tls-name":p["dns_server_name"]="999.999.999.999"
   case "remote-path":p["dns_path"]="//other.example/query"
   case "query-path":p["dns_path"]="/query?other=1"
   case "fragment-path":p["dns_path"]="/query#other"
   case "bad-percent":p["dns_path"]="/query%xx"
   case "unicode-path":p["dns_path"]="/café"
   case "wrong-family":p["adguard_ipv4"]="fd12::53"
   case "noncanonical-home":p["adguard_ipv6"]="FD12:0:0:0:0:0:0:53"
   case "nul":p["dns_host"]="192.168.50.133\u{0}foreign"
   default:break
   }
   try reject("app "+fault){_ = try IOSDNSRuntimePolicy.resolve(decoded(p))}
   try reject("PacketTunnel "+fault){_ = try graph(p,"192.168.50.133")}
  }
  print("Apple Home DNS: PASS (\(checks) shipping resolver/capability/PacketTunnel graph checks)")
 }
}
'''

def main():
    swift=shutil.which('swiftc');assert swift,'swiftc required'
    with tempfile.TemporaryDirectory(prefix='ios-home-dns-') as directory:
        work=Path(directory);dns=APP/'IOSDNSRuntimePolicy.swift'
        if platform.system()!='Darwin':
            source=dns.read_text();dns=work/dns.name;dns.write_text(source.replace('import Network\n',B.NETWORK_SHIM))
        code=work/'Tests.swift';code.write_text(TEST)
        sources=[APP/name for name in ['Models.swift','IOSHomeDNSPolicy.swift','IOSNativeXrayProfile.swift','IOSNativePQProfile.swift','IOSMultihopStartLayer.swift','IOSMultihopExecution.swift','IOSRuntimeSelection.swift']]
        sources += [dns,TUN/'RouterVPNMultihopGraph.swift',TUN/'RouterVPNMTUPolicy.swift',code]
        binary=work/'tests'
        command=[swift,'-swift-version','6',*map(str,sources),'-o',str(binary)]
        subprocess.run(command,check=True,timeout=120);subprocess.run([str(binary)],check=True,timeout=30)
        # Causal control: reproduces the original app resolver's silent UDP53
        # substitution while keeping the helper and PacketTunnel unchanged.
        original=dns.read_text();start=original.index('            let home = try IOSHomeDNSPolicy.resolve(');end=original.index('        case "fastest":',start)
        mutant=work/'MutantDNS.swift';mutant.write_text(original[:start]+'            host = firstNonEmpty(profile.adGuardIPv4, profile.adGuardIPv6)\n'+original[end:])
        mutated=[str(mutant) if item==str(dns) else item for item in command]
        subprocess.run(mutated,check=True,timeout=120)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
        assert result.returncode!=0 and 'app retains exact Home' in result.stderr,result.stderr[-2000:]
        print('Rejected original Home UDP53 substitution')
    subprocess.run(['go','test','./internal/mobilemultihop','-run','^TestNodeHomeDNSAllRawFamiliesRetainEncryptedTransport$','-count=1'],cwd=ROOT,check=True,timeout=120)

if __name__=='__main__':main()
