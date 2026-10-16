#!/usr/bin/env python3
"""Execute actual Swift and Go Naive graph consumers; no VPN or external node.

Compiles shipping graph/MTU/captured-trust code without mocking its validators.
Disposable certificates are test inputs; native sockets are not exercised here.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
GO=r'''package main
import("encoding/json";"fmt";"io";"os";"router-vpn/internal/mobilemultihop")
func main(){
 var i struct{Operation,Config,Policy,EntrySource,ExitSource string};e:=json.NewDecoder(io.LimitReader(os.Stdin,8<<20)).Decode(&i);var value string
 if e==nil{switch i.Operation{
 case "compile":value,e=mobilemultihop.CompileProxyEntry(i.Config,i.Policy)
 case "mtu":value,e=mobilemultihop.ApplyMTUPolicy(i.Config,i.Policy)
 case "lan":value,e=mobilemultihop.ApplyLANPolicy(i.Config,i.Policy)
 case "layers":var c *mobilemultihop.Controller;c,e=mobilemultihop.NewWithStartLayers(i.Config,i.Policy,i.EntrySource,i.ExitSource);if e==nil{value=c.Config();e=c.Close()}
 default:e=fmt.Errorf("unrequested test operation")
 }}
 if e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)};fmt.Print(value)
}
'''
TEST=r'''
import Foundation
typealias P = RouterVPNMultihopGraph
func json(_ value: Any) throws -> String { String(decoding: try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), as: UTF8.self) }
func object(_ text: String) throws -> [String: Any] { try JSONSerialization.jsonObject(with: Data(text.utf8)) as! [String: Any] }
func key(_ n: UInt8) -> String { Data(repeating:n,count:32).base64EncodedString() }
func rpc(_ operation: String, _ config: String, _ policy: String, _ entrySource: String="", _ exitSource: String="") throws -> String {
 let task=Process(),input=Pipe(),output=Pipe(),errors=Pipe()
 task.executableURL=URL(fileURLWithPath:ProcessInfo.processInfo.environment["NAIVE_POLICY"]!)
 task.standardInput=input;task.standardOutput=output;task.standardError=errors;try task.run()
 try input.fileHandleForWriting.write(contentsOf:Data(json(["Operation":operation,"Config":config,"Policy":policy,"EntrySource":entrySource,"ExitSource":exitSource]).utf8));try input.fileHandleForWriting.close()
 let result=output.fileHandleForReading.readDataToEndOfFile(),diagnostic=errors.fileHandleForReading.readDataToEndOfFile();task.waitUntilExit()
 guard task.terminationStatus==0 else { throw P.issue(String(decoding:diagnostic,as:UTF8.self)) }
 return String(decoding:result,as:UTF8.self)
}
func compiler(_ source: String,_ mode: String)throws->String {try rpc("compile",source,mode)}
func profile(_ entry: Bool,_ layer: String,_ dns: String)->[String:Any]{
 ["id":entry ? "entry":"exit","node_kind":"router-vpn","node_proof_id":String(repeating:entry ? "a":"b",count:64),"socks_host":entry ? "10.77.0.1":"10.88.0.1","socks_port":1080,
  "router_api":entry ? "http://10.77.0.1:8787":"http://10.88.0.1:8787","api_token":entry ? "entry-private-token":"exit-private-token","start_layer":layer,
  "mtu_policy":"fixed","manual_mtu":1280,"home_lan_access":false,"ipv6_mode":"off","adguard_ipv4":"192.168.50.133","dns_mode":dns]
}
func wire(_ entry: Bool)->[String:Any]{
 ["type":"wireguard","tag":"proxy","system":false,"mtu":1280,"address":[entry ? "10.77.0.2/32":"10.88.0.2/32"],"private_key":key(entry ? 3:4),
 "peers":[["address":entry ? "192.0.2.1":"198.51.100.2","port":51820,"public_key":key(entry ? 1:2),"pre_shared_key":key(9),"allowed_ips":["0.0.0.0/0","::/0"],"persistent_keepalive_interval":25]]]
}
func outbound(_ entry: Bool,_ mode: String,_ certificate: String)->[String:Any]{
 var v:[String:Any]=["type":P.nativeNaiveModes.contains(mode) ? "naive":mode,"tag":"proxy","server":entry ? "192.0.2.1":"198.51.100.2","server_port":8443,"password":entry ? "entry-only-password":"exit-only-password"]
 if mode=="shadowsocks" {v["method"]="2022-blake3-aes-256-gcm";v["password"]=key(entry ? 7:8)}
 else {v["tls"]=["enabled":true,"server_name":entry ? "entry.example.test":"exit.example.test","certificate_path":"trust.pem"]}
 if P.nativeNaiveModes.contains(mode){v["username"]=entry ? "entry-only-user":"exit-only-user";v["quic"]=mode=="naive-h3";v["udp_over_tcp"]=["enabled":true,"version":2] as [String:Any]}
 return v
}
func graph(_ proxy:[String:Any],_ dnsMode:String)->[String:Any]{
 let kind=["home":"udp","custom":"tcp","dot":"tls","doh":"https","doh3":"h3"][dnsMode]!
 var dns:[String:Any]=["type":kind,"tag":"selected-dns","server":"192.168.50.133","server_port":dnsMode=="home" ? 53:5353,"detour":"proxy"]
 if ["tls","https","h3"].contains(kind){dns["tls"]=["enabled":true,"server_name":"resolver.example.test"]}
 if ["https","h3"].contains(kind){dns["path"]="/dns-query"}
 return ["inbounds":[["type":"tun","tag":"tun-in","auto_route":true,"strict_route":true,"mtu":1280,"address":["172.29.94.1/30","fd29:94::1/126"]]],"outbounds":[proxy],
 "dns":["servers":[dns],"final":"selected-dns"],"route":["final":"proxy","rules":[["protocol":"dns","action":"hijack-dns"]]]]
}
func assets(_ entry:Bool,_ mode:String,_ cert:String,_ dns:String="home")throws->[String:String]{
 var source=["sing-box.json":Data(try json(graph(outbound(entry,mode,cert),dns)).utf8).base64EncodedString()]
 if mode != "shadowsocks"{source["trust.pem"]=Data(cert.utf8).base64EncodedString()}
 return source
}
func layerProfile(_ entry:Bool)throws->[String:[String:String]]{
 var v=outbound(entry,"shadowsocks","");v["server_port"]=8388
 return ["shadowsocks":["sing-box.json":Data(try json(graph(v,"home")).utf8).base64EncodedString()]]
}
func files(_ a:[String:String])->[String:Data]{a.mapValues{Data(base64Encoded:$0)!}}
func tagged(_ g:[String:Any],_ tag:String)->[String:Any]{
 let values=(g["outbounds"] as? [[String:Any]] ?? [])+(g["endpoints"] as? [[String:Any]] ?? [])
 return values.first{$0["tag"] as? String==tag}!
}
@main struct Tests {
 @MainActor static var checks=0,graphs=0
 @MainActor static func check(_ label:String,_ condition:@autoclosure ()throws->Bool)throws{guard try condition()else{fatalError("FAIL "+label)};checks+=1}
 @MainActor static func reject(_ label:String,_ body:()throws->Void){do{try body();fatalError("Accepted "+label)}catch{checks+=1}}
 @MainActor static func verify(_ entryMode:String,_ exitMode:String,_ execution:String,_ el:String,_ xl:String,_ dns:String,_ ec:String,_ xc:String)throws{
  var e=profile(true,el,"home"),x=profile(false,xl,dns)
  if entryMode=="wg"{e["manual_mtu"]=1500};x["multihop_entry_mode"]=entryMode;x["multihop_exit_mode"]=exitMode
  let entryCapture=try IOSMultihopStartLayer.capture(profile:e,profiles:layerProfile(true)),exitCapture=try IOSMultihopStartLayer.capture(profile:x,profiles:layerProfile(false))
  let endpoint=try entryMode=="wg" ? wire(true):object(compiler(json(assets(true,entryMode,ec)),entryMode))
  let source:[String:Data]
  if exitMode=="wg" {source=try P.wireGuardFiles(endpoint:wire(false),profile:x,dnsServers:["192.168.50.133"])}
  else {
   let a=try assets(false,exitMode,xc,dns)
   source=try exitMode=="shadowsocks" ? files(a):IOSMultihopStartLayer.inlineExitTLS(files:files(a),assets:a,mode:exitMode,compiler:compiler)
   if P.nativeNaiveModes.contains(exitMode){try check("no retained certificate-file owner",Set(source.keys)==Set(["sing-box.json"]))}
  }
  let built=try P.build(entryEndpoint:endpoint,entryProfile:entryCapture.graphProfile,exitProfile:exitCapture.graphProfile,exitMode:exitMode,files:source)
  let sized=try RouterVPNMTUPolicy.multihop(built,entryProfile:e,exitProfile:x)
  let profiles=try json(["entry":e,"exit":x]),mtu=try rpc("mtu",String(decoding:sized["sing-box.json"]!,as:UTF8.self),profiles),lan=try rpc("lan",mtu,profiles)
  let metadata=try json(["entry_id":"entry","exit_id":"exit","entry_node_id":String(repeating:"a",count:64),"exit_node_id":String(repeating:"b",count:64),"entry_tag":P.entryTag,"entry_mode":entryMode,"exit_mode":exitMode,"execution":execution,"entry_api":"http://10.77.0.1:8787","exit_api":"http://10.88.0.1:8787","entry_token":"entry-private-token","exit_token":"exit-private-token","entry_start_layer":el=="off" ? "":el,"exit_start_layer":xl=="off" ? "":xl])
  let plan=try rpc("layers",lan,metadata,entryCapture.source ?? "",exitCapture.source ?? ""),planned=try object(plan),g=try object(lan)
  try check("one TUN",(g["inbounds"] as! [[String:Any]]).filter{$0["type"] as? String=="tun"}.count==1)
  try check("exact entry proof route",tagged(planned,P.entryPrivateTag)["detour"] as? String==P.entryTag)
  try check("server candidate retains entry",tagged(planned,"routervpn-execution-server")["detour"] as? String==P.entryTag)
  for (isEntry,mode,certificate,layer) in [(true,entryMode,ec,el),(false,exitMode,xc,xl)] where P.nativeNaiveModes.contains(mode){
   let value=tagged(planned,isEntry ? P.entryTag:"routervpn-execution-local"),tls=value["tls"] as! [String:Any],u=value["udp_over_tcp"] as! [String:Any]
   try check("HTTP version unchanged",value["type"] as? String=="naive" && value["quic"] as? Bool==(mode=="naive-h3"))
   try check("credentials not borrowed",value["username"] as? String==(isEntry ? "entry-only-user":"exit-only-user") && value["password"] as? String==(isEntry ? "entry-only-password":"exit-only-password"))
   try check("UDP framing preserved",u["enabled"] as? Bool==true && u["version"] as? Int==2)
   try check("certificate owned inline",tls["certificate"] as? [String]==[certificate] && tls["certificate_path"]==nil && tls["insecure"]==nil)
   try check("same peer within captured layer",value["server"] as? String==(layer=="off" ? (isEntry ? "192.0.2.1":"198.51.100.2"):(isEntry ? "10.77.0.1":"10.88.0.1")))
  }
  let server=((planned["dns"] as! [String:Any])["servers"] as! [[String:Any]])[0]
  try check("selected AdGuard resolver retained",server["server"] as? String=="192.168.50.133" && server["detour"] as? String=="proxy")
  if exitMode != "wg"{try check("selected DNS protocol retained",server["type"] as? String==["home":"udp","custom":"tcp","dot":"tls","doh":"https","doh3":"h3"][dns])}
  if let root=ProcessInfo.processInfo.environment["ROUTERVPN_IOS_NAIVE_FIXTURES"]{
   let dir=URL(fileURLWithPath:root).appendingPathComponent(String(format:"case-%04d",graphs));try FileManager.default.createDirectory(at:dir,withIntermediateDirectories:true)
   try Data(lan.utf8).write(to:dir.appendingPathComponent("sing-box.json"));try Data(plan.utf8).write(to:dir.appendingPathComponent("planned.json"))
  }
  graphs+=1
 }
 @MainActor static func main()throws{
  let ec=try String(contentsOfFile:ProcessInfo.processInfo.environment["ENTRY_CERT"]!,encoding:.utf8),xc=try String(contentsOfFile:ProcessInfo.processInfo.environment["EXIT_CERT"]!,encoding:.utf8)
  for entry in ["wg","shadowsocks","naive-h2","naive-h3"]{for exit in ["wg","shadowsocks","hysteria2","naive-h2","naive-h3"]{
   if !P.nativeNaiveModes.contains(entry) && !P.nativeNaiveModes.contains(exit){continue}
   for execution in ["local","server","auto"]{for layers in [("off","off"),("aes-256-gcm","off"),("off","aes-256-gcm+xor-whitening"),("aes-256-gcm+xor-whitening","aes-256-gcm")]{try verify(entry,exit,execution,layers.0,layers.1,"home",ec,xc)}}
  }}
  for mode in P.nativeNaiveModes{for dns in ["home","custom","dot","doh","doh3"]{try verify("shadowsocks",mode,"auto","off","off",dns,ec,xc)}}
  for mode in P.nativeNaiveModes{
   let a=try assets(false,mode,xc),raw=files(a),inlined=try IOSMultihopStartLayer.inlineExitTLS(files:raw,assets:a,mode:mode,compiler:compiler)
   var x=profile(false,"off","home");x["multihop_entry_mode"]=mode
   let original=try object(compiler(json(assets(true,mode,ec)),mode))
   for field in ["quic","udp_over_tcp","password","username","tls","detour","bind_interface"]{
    var mutated=original;mutated[field]=field=="quic" ? NSNumber(value:1):(["username","password"].contains(field) ? "":"invalid")
    reject("entry field mutation "+field){_=try P.build(entryEndpoint:mutated,entryProfile:profile(true,"off","home"),exitProfile:x,exitMode:mode,files:inlined)}
    var g=try object(String(decoding:inlined["sing-box.json"]!,as:UTF8.self)),out=g["outbounds"] as! [[String:Any]];out[0][field]=mutated[field];g["outbounds"]=out
    reject("exit field mutation "+field){_=try P.build(entryEndpoint:wire(true),entryProfile:profile(true,"off","home"),exitProfile:profile(false,"off","home"),exitMode:mode,files:["sing-box.json":Data(json(g).utf8)])}
   }
   for field in ["username","password","quic","udp_over_tcp","server","tls","detour"]{
    reject("changed native compiler output "+field){_=try IOSMultihopStartLayer.inlineExitTLS(files:raw,assets:a,mode:mode){source,requested in var v=try object(compiler(source,requested));v[field]="unowned";return try json(v)}}
   }
   reject("missing certificate file"){var bad=raw;bad.removeValue(forKey:"trust.pem");_=try IOSMultihopStartLayer.inlineExitTLS(files:bad,assets:a,mode:mode,compiler:compiler)}
   reject("wrong HTTP mode"){_=try IOSMultihopStartLayer.inlineExitTLS(files:raw,assets:a,mode:mode=="naive-h2" ? "naive-h3":"naive-h2",compiler:compiler)}
   reject("compiler failure"){_=try IOSMultihopStartLayer.inlineExitTLS(files:raw,assets:a,mode:mode){_,_ in throw P.issue("failure")}}
  }
  try check("complete host graph matrix",graphs==178)
  print("Apple Naive multihop: PASS (\(graphs) real Swift/Go graphs; \(checks) checks; native sockets not exercised)")
 }
}
'''

def main():
    swift=shutil.which('swiftc')
    if not swift:raise RuntimeError('Swift compiler required')
    with tempfile.TemporaryDirectory(prefix='.ios-naive-policy-',dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix='ios-naive-host-') as temp:
        root=Path(temp);go=Path(go_dir)/'main.go';go.write_text(GO)
        native=root/'policy';subprocess.run(['go','build','-o',str(native),str(go)],cwd=ROOT,check=True,timeout=90)
        for name in ('entry','exit'):
            subprocess.run(['openssl','req','-x509','-newkey','ed25519','-nodes','-keyout',str(root/(name+'.key')),'-out',str(root/(name+'.pem')),'-days','2','-subj','/CN='+name+'.example.test'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        source=root/'Tests.swift';source.write_text(TEST);binary=root/'tests'
        sources=[ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNMultihopGraph.swift',ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNMTUPolicy.swift',ROOT/'ios/RouterVPN/App/IOSMultihopStartLayer.swift']
        subprocess.run([swift,'-swift-version','6','-parse-as-library',*map(str,sources),str(source),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary)],env=dict(os.environ,NAIVE_POLICY=str(native),ENTRY_CERT=str(root/'entry.pem'),EXIT_CERT=str(root/'exit.pem')),check=True,timeout=120)
    provider=(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
    assert 'RouterVPNMultihopGraph.nativeNaiveModes.contains(exitMode)' in provider
    assert 'inlineExitTLS(files: rawFiles, assets: assets, mode: exitMode)' in provider

if __name__=='__main__':main()
