#!/usr/bin/env python3
"""Execute Apple PQ selection/device policy with the real shared Go compiler.

Only Network.framework literal parsing and the gomobile call are replaced on
Linux. The native factory, SDK build and encrypted Rust protocol have independent
mandatory gates; this test does not claim physical-device traffic or signing.
"""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
TUN=ROOT/'ios/RouterVPN/PacketTunnel'
spec=importlib.util.spec_from_file_location('native_selection_fixture',ROOT/'deploy/test_ios_native_base_selection.py')
F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
GO=r'''package main
import("bytes";"encoding/binary";"crypto/sha256";"encoding/base64";"encoding/hex";"encoding/json";"fmt";"io";"os";"strings";"router-vpn/internal/mobilemultihop";"router-vpn/internal/mobileperf")
func fixture(mode string)string{
 key:=func(b byte)string{return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b},32))}
 node:=sha256.Sum256([]byte("router-vpn-node-proof-v1\n"+key('b')))
 peer:=key('b');asset,tool:="wg.conf","wg"
 if mode=="awg2-pq"{peer=key('d');asset,tool="awg.conf","awg"}
 raw:="[Interface]\nAddress=10.77.0.2/24,fd77:77::2/64\nPrivateKey="+key('a')+"\nDNS=192.168.50.133\nMTU=1420\n[Peer]\nPublicKey="+peer+"\nPresharedKey="+key('c')+"\nEndpoint=192.0.2.1:51820\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\n"
 if mode=="awg2-pq"{raw=strings.Replace(raw,"[Peer]","Jc=3\nJmin=40\nJmax=900\nS1=56\nS2=48\nS3=24\nS4=32\nH1=10000000-19999999\nH2=20000000-29999999\nH3=30000000-39999999\nH4=40000000-49999999\n[Peer]",1)}
 files:=map[string][]byte{asset:[]byte(raw),"rosenpass-client-secret":bytes.Repeat([]byte{1},64),"rosenpass-client-public":bytes.Repeat([]byte{2},128),"rosenpass-server-public":bytes.Repeat([]byte{3},128),"rosenpass.env":[]byte("ROSENPASS_TOOL="+tool+"\nROSENPASS_INTERFACE="+tool+"\nROSENPASS_WG_PEER="+peer+"\nROSENPASS_KEY_OUT=rosenpass.psk\nROSENPASS_PORT=51822\n"),"rosenpass.toml":[]byte("public_key = \"rosenpass-client-public\"\nsecret_key = \"rosenpass-client-secret\"\nlisten = []\nverbosity = \"Quiet\"\n[[peers]]\npublic_key = \"rosenpass-server-public\"\nendpoint = \"node.example.test:51822\"\nkey_out = \"rosenpass.psk\"\n")}
 out,_:=json.Marshal(map[string]any{"files":files,"node":hex.EncodeToString(node[:])});return string(out)
}

func exitFixture(mode string)(string,error){
 key:=func(b byte)string{return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b},32))}
 node:=sha256.Sum256([]byte("router-vpn-node-proof-v1\n"+key('x')))
 nodeID:=hex.EncodeToString(node[:]);var config string;var err error
 if mode=="wg"||mode=="awg2-fast"||mode=="awg2-strong"{
  raw:="[Interface]\nAddress=10.88.0.2/24,fd88:88::2/64\nPrivateKey="+key('v')+"\nDNS=192.168.50.133\nMTU=1280\n[Peer]\nPublicKey="+key('x')+"\nPresharedKey="+key('y')+"\nEndpoint=198.51.100.2:51820\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\n"
  if mode=="wg"{config,err=mobilemultihop.WireGuardExitConfig(raw,nodeID)}else{
   raw=strings.Replace(raw,"[Peer]","Jc=3\nJmin=40\nJmax=900\nS1=56\nS2=48\nS3=24\nS4=32\nH1=10000000-19999999\nH2=20000000-29999999\nH3=30000000-39999999\nH4=40000000-49999999\n[Peer]",1)
   config,err=mobilemultihop.AmneziaExitConfig(raw,nodeID)
  }
 }else{
  out:=map[string]any{"type":mode,"tag":"proxy","server":"198.51.100.2","server_port":443,"password":"test-only-hy2-secret"}
  if mode=="shadowsocks"{out["method"]="2022-blake3-aes-256-gcm";out["password"]=key('s')}else if mode=="hysteria2"{out["tls"]=map[string]any{"enabled":true,"server_name":"exit.example.test"}}else{return "",fmt.Errorf("invalid fixture mode")}
  graph:=map[string]any{"inbounds":[]any{map[string]any{"type":"tun","tag":"tun-in","auto_route":true,"strict_route":true,"stack":"system","mtu":1280,"address":[]string{"172.29.94.1/30","fd29:94::1/126"}}},"outbounds":[]any{out},"route":map[string]any{"auto_detect_interface":true,"final":"proxy","rules":[]any{map[string]any{"protocol":"dns","action":"hijack-dns"}}},"dns":map[string]any{"servers":[]any{map[string]any{"type":"udp","tag":"selected-dns","server":"192.168.50.133","server_port":53,"detour":"proxy"}},"final":"selected-dns"}}
  encoded,e:=json.Marshal(graph);config,err=string(encoded),e
 }
 if err!=nil{return "",err};out,err:=json.Marshal(map[string]any{"config":config,"node":nodeID});return string(out),err
}
type request struct{Op,Mode,Files,Node,Config,Source,Policy string}
func handle(r request)(string,error){
 var value string;var err error
 switch r.Op{
 case "fixture":value=fixture(r.Mode)
 case "exit-fixture":value,err=exitFixture(r.Mode)
 case "mtu":value,err=mobilemultihop.ApplyMTUPolicy(r.Config,r.Policy)
 case "mtu-profile":value,err=mobilemultihop.MultihopMTUProfile(r.Config,r.Policy)
 case "plan":
  var source struct{Entry,Exit string};err=json.Unmarshal([]byte(r.Source),&source)
  if err==nil{var c *mobilemultihop.Controller;c,err=mobilemultihop.NewWithStartLayers(r.Config,r.Policy,source.Entry,source.Exit);if err==nil{value=c.Config();c.Close()}}

 case "compile":value,err=mobilemultihop.CompilePQProfile(r.Mode,r.Files,r.Node)
 case "start":value,err=mobilemultihop.ComposeNativeBaseStartLayer(r.Config,r.Source,r.Policy)
 case "lan":value,err=mobilemultihop.ApplyLANPolicy(r.Config,r.Policy)
 case "performance":value,err=mobileperf.Apply(r.Config,r.Policy)
 case "validate":_,err=mobilemultihop.PQRuntimeConfig(r.Config);value="ok"
 default:err=fmt.Errorf("unknown test operation")}
 return value,err
}
func main(){
 for{
  var size uint32
  if err:=binary.Read(os.Stdin,binary.BigEndian,&size);err==io.EOF{return}else if err!=nil{panic(err)}
  if size==0||size>16<<20{panic("test input exceeds bound")}
  payload:=make([]byte,size);if _,err:=io.ReadFull(os.Stdin,payload);err!=nil{panic(err)}
  var input request;var value string;err:=json.Unmarshal(payload,&input)
  if err==nil{value,err=handle(input)}
  response:=map[string]string{"value":value,"error":""};if err!=nil{response["value"]="";response["error"]=err.Error()}
  output,err:=json.Marshal(response);if err!=nil||len(output)>16<<20{panic("test output exceeds bound")}
  if err=binary.Write(os.Stdout,binary.BigEndian,uint32(len(output)));err!=nil{panic(err)}
  if _,err=os.Stdout.Write(output);err!=nil{panic(err)}
 }
}'''
SWIFT=r'''
import Foundation
func json(_ value: Any) throws -> Data {try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
func text(_ value:Any)throws->String {String(decoding:try json(value),as:UTF8.self)}
func object(_ data:Data)throws->[String:Any] {try JSONSerialization.jsonObject(with:data) as! [String:Any]}
func key(_ b:UInt8)->String {Data(repeating:b,count:32).base64EncodedString()}

// Serialized test-only bridge. It executes the same compiler for every input,
// without result caching, and the Python driver bounds the complete run.
final class TestCompiler: @unchecked Sendable {
 static let shared=TestCompiler()
 private let lock=NSLock()
 private var task:Process?
 private var input:FileHandle?
 private var output:FileHandle?
 private func read(_ count:Int)throws->Data {
  var result=Data()
  while result.count<count {
   guard let part=try output!.read(upToCount:count-result.count),!part.isEmpty else {throw NSError(domain:"PQTestCompilerEOF",code:1)}
   result.append(part)
  };return result
 }
 func call(_ request:[String:String])throws->String {
  lock.lock();defer{lock.unlock()}
  if task==nil {
   let process=Process(),writer=Pipe(),reader=Pipe()
   process.executableURL=URL(fileURLWithPath:CommandLine.arguments[1]);process.standardInput=writer;process.standardOutput=reader;process.standardError=FileHandle.standardError
   try process.run();task=process;input=writer.fileHandleForWriting;output=reader.fileHandleForReading
  }
  let payload=try json(request);guard !payload.isEmpty,payload.count<=16*1024*1024 else{throw NSError(domain:"PQTestInputBound",code:1)}
  let size=UInt32(payload.count)
  try input!.write(contentsOf:Data([UInt8((size>>24)&255),UInt8((size>>16)&255),UInt8((size>>8)&255),UInt8(size&255)]))
  try input!.write(contentsOf:payload)
  let header=try read(4),length=header.reduce(UInt32(0)){($0<<8)|UInt32($1)}
  guard length>0,length<=16*1024*1024 else {throw NSError(domain:"PQTestOutputBound",code:1)}
  let response=try object(read(Int(length)))
  guard let error=response["error"] as? String,let value=response["value"] as? String else{throw NSError(domain:"PQTestResponse",code:1)}
  guard error.isEmpty else{throw NSError(domain:"PQTestCompiler",code:1,userInfo:[NSLocalizedDescriptionKey:error])}
  return value
 }
 func close(){
  lock.lock();defer{lock.unlock()}
  try? input?.close();task?.waitUntilExit();try? output?.close();task=nil;input=nil;output=nil
 }
}
func bridge(_ request:[String:String])throws->String {try TestCompiler.shared.call(request)}
func compile(_ mode:String,_ assets:String,_ node:String)throws->String {try bridge(["Op":"compile","Mode":mode,"Files":assets,"Node":node])}
func start(_ config:String,_ source:String,_ policy:String)throws->String {try bridge(["Op":"start","Config":config,"Source":source,"Policy":policy])}
func profile(_ node:String,_ dns:String,_ layer:String)->[String:Any] {
 var p:[String:Any]=["id":"home","name":"Home","node_kind":"router-vpn","node_proof_id":node,"endpoint":"192.0.2.1","router_api":"http://10.77.0.1:8787","api_token":"test-only-token","adguard_ipv4":"192.168.50.133","adguard_ipv6":"fd77:77::1","socks_host":"10.77.0.1","socks_port":1080,"socks_username":"","socks_password":"","dns_mode":dns,"home_lan_access":false,"ipv6_mode":"off","mtu_policy":"fixed","manual_mtu":1350,"daita_enabled":true,"start_layer":layer,"base_tunnel":"wg","base_fallback":false]
 if dns != "home" {p["dns_host"]=dns=="hostname" ? "resolver.example.test":"192.168.50.133";p["dns_server_name"]="resolver.example.test"}
 if dns=="custom"{p["dns_protocol"]="tcp";p["dns_port"]=5353}
 if dns=="hostname"{p["dns_mode"]="doh"}
 return p
}
func bundle(_ mode:String,_ assets:[String:String],_ node:String,_ p:[String:Any])throws->ClientBundle{
 var b=ClientBundle.empty;b.nodeProofID=node;b.selectedRouterID="home"
 b.routerProfiles=[try JSONDecoder().decode(RouterProfile.self,from:json(p))]
 b.logicalModes=[LogicalMode(id:"pq",name:"Post quantum",description:"",baseSelector:true,fallback:true,variants:["wg":"wg-pq","awg":"awg2-pq"])]
 b.profiles=[mode:assets];return b
}
func outer()throws->[String:Any]{["profiles":["shadowsocks":["sing-box.json":try json(["outbounds":[["type":"shadowsocks","tag":"proxy","method":"2022-blake3-aes-256-gcm","password":key(115),"server":"192.0.2.1","server_port":8388]]]).base64EncodedString()]]]}
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ label:String,_ body:@autoclosure ()throws->Bool)throws {guard try body() else{fatalError(label)};checks+=1}
 @MainActor static func reject(_ label:String,_ body:()throws->Void){do{try body();fatalError("accepted "+label)}catch{checks+=1}}

 @MainActor static func entries()throws{
  func endpoint(_ graph:[String:Any],_ tag:String)throws->[String:Any]{
   let matches=((graph["endpoints"] as? [[String:Any]] ?? [])+(graph["outbounds"] as? [[String:Any]] ?? [])).filter{$0["tag"] as? String==tag}
   guard matches.count==1 else{throw NSError(domain:"AmbiguousTestEndpoint",code:1)};return matches[0]
  }
  func aesAssets(_ host:String)throws->[String:[String:String]]{
   let fixture=try object(Data(bridge(["Op":"exit-fixture","Mode":"shadowsocks"]).utf8))
   var graph=try object(Data((fixture["config"] as! String).utf8));var out=(graph["outbounds"] as! [[String:Any]])[0]
   out["server"]=host;out["server_port"]=8388;graph["outbounds"]=[out]
   return ["shadowsocks":["sing-box.json":try json(graph).base64EncodedString()]]
  }
  let layers=[("off","off"),("aes-256-gcm","off"),("off","aes-256-gcm+xor-whitening"),("aes-256-gcm+xor-whitening","aes-256-gcm")]
  var graphs=0
  for mode in ["wg-pq","awg2-pq"]{
   let fixture=try object(Data(bridge(["Op":"fixture","Mode":mode]).utf8)),assets=fixture["files"] as! [String:String],node=fixture["node"] as! String
   let entry=try IOSNativePQProfile.entryEndpoint(mode:mode,encoded:assets,nodeID:node,compiler:compile),original=try text(entry)
   for exitMode in ["wg","awg2-fast","awg2-strong","shadowsocks","hysteria2"]{
    let exitFixture=try object(Data(bridge(["Op":"exit-fixture","Mode":exitMode]).utf8)),exitNode=exitFixture["node"] as! String
    let exitFiles=["sing-box.json":Data((exitFixture["config"] as! String).utf8)]
    for execution in ["local","server","auto"]{for pair in layers{
     var a=profile(node,"home",pair.0),b=profile(exitNode,"doh3",pair.1)
     a["id"]="entry";a["manual_mtu"]=1500
     b["id"]="exit";b["endpoint"]="198.51.100.2";b["manual_mtu"]=1280;b["router_api"]="http://10.88.0.1:8787";b["socks_host"]="10.88.0.1";b["api_token"]="different-test-token";b["multihop_entry_mode"]=mode
     let originalA=try text(a),originalB=try text(b),originalFiles=exitFiles
     let first=try IOSMultihopStartLayer.capture(profile:a,profiles:aesAssets("192.0.2.1")),last=try IOSMultihopStartLayer.capture(profile:b,profiles:aesAssets("198.51.100.2"))
     let preparedExit:[String:Data]
     if ["wg","awg2-fast","awg2-strong"].contains(exitMode){
      let parsed=try object(exitFiles["sing-box.json"]!),ep=(parsed["endpoints"] as! [[String:Any]])[0]
      preparedExit=try RouterVPNMultihopGraph.wireGuardFiles(endpoint:ep,profile:b,dnsServers:["192.168.50.133"])
     }else{
      var source=ClientBundle.empty;source.nodeProofID=exitNode;source.selectedRouterID="exit"
      source.routerProfiles=[try JSONDecoder().decode(RouterProfile.self,from:json(b))]
      source.profiles=[exitMode:["sing-box.json":exitFiles["sing-box.json"]!.base64EncodedString()]]
      let patched=try IOSDNSRuntimePolicy.patch(source)
      preparedExit=["sing-box.json":Data(base64Encoded:patched.profiles[exitMode]!["sing-box.json"]!)!]
     }
     let base=try RouterVPNMultihopGraph.build(entryEndpoint:entry,entryProfile:first.graphProfile,exitProfile:last.graphProfile,exitMode:exitMode,files:preparedExit)
     let policies=try text(["entry":a,"exit":b])
     var sized=try RouterVPNMTUPolicy.multihop(base,entryProfile:a,exitProfile:b)
     let native=try bridge(["Op":"mtu","Config":String(decoding:base["sing-box.json"]!,as:UTF8.self),"Policy":policies])
     // The shared policy also prepends IPv6 rejection; compare the actual
     // MTU owners, not rule ordering that is intentionally platform-specific.
     let swiftGraph=try object(sized["sing-box.json"]!),goGraph=try object(Data(native.utf8)),baseGraph=try object(base["sing-box.json"]!)
     for field in ["endpoints","inbounds"]{try check("Swift/shared MTU owner parity",text(swiftGraph[field]!)==text(goGraph[field]!))}
     for field in ["dns","route","outbounds"]{try check("Swift MTU preserves non-MTU policy",text(swiftGraph[field]!)==text(baseGraph[field]!))}
     try check("shared IPv6 rejection remains enabled",(goGraph["dns"] as! [String:Any])["strategy"] as? String=="ipv4_only")
     for op in ["lan","performance"]{sized["sing-box.json"]=Data(try bridge(["Op":op,"Config":String(decoding:sized["sing-box.json"]!,as:UTF8.self),"Policy":policies]).utf8)}
     let metadata:[String:String]=["entry_id":"entry","exit_id":"exit","entry_node_id":node,"exit_node_id":exitNode,"entry_api":a["router_api"] as! String,"exit_api":b["router_api"] as! String,"entry_token":a["api_token"] as! String,"exit_token":b["api_token"] as! String,"entry_tag":RouterVPNMultihopGraph.entryTag,"entry_mode":mode,"exit_mode":exitMode,"execution":execution,"entry_start_layer":first.source==nil ? "":first.mode,"exit_start_layer":last.source==nil ? "":last.mode]
     let meta=try text(metadata),entrySource=try IOSMultihopStartLayer.requiredSource(metadata:meta,source:first.source),exitSource=try IOSMultihopStartLayer.requiredExitSource(metadata:meta,source:last.source)
     let composed=try object(Data(bridge(["Op":"plan","Config":String(decoding:sized["sing-box.json"]!,as:UTF8.self),"Policy":meta,"Source":text(["Entry":entrySource ?? "","Exit":exitSource ?? ""])]).utf8))
     let captured=try endpoint(composed,RouterVPNMultihopGraph.entryTag),pq=captured["pq"] as! [String:Any],peer=(captured["peers"] as! [[String:Any]])[0]
     try check("captured PQ mode/node",captured["type"] as? String=="routervpn-pq" && captured["mode"] as? String==mode && captured["node_id"] as? String==node)
     try check("private key unchanged",captured["private_key"] as? String==entry["private_key"] as? String)
     for name in ["secret","public","peer"]{try check("independent PQ material preserved",pq[name] as? String==(entry["pq"] as! [String:Any])[name] as? String)}
     let host=pair.0=="off" ? "192.0.2.1":"10.77.0.1"
     try check("two exchanges share captured outer path",peer["address"] as? String==host && pq["endpoint"] as? String==host+":51822")
     if pair.0 != "off"{try check("entry layer retained",captured["detour"] as? String=="routervpn-entry-start-layer")}
     try check("PQ endpoint still validates",bridge(["Op":"validate","Config":text(captured)])=="ok")
     if mode=="awg2-pq"{try check("all eleven AWG settings retained",text(captured["amnezia"]!)==text(entry["amnezia"]!))}
     try check("entry proof inside PQ",endpoint(composed,RouterVPNMultihopGraph.entryPrivateTag)["detour"] as? String==RouterVPNMultihopGraph.entryTag)
     try check("one system TUN",(composed["inbounds"] as! [[String:Any]]).filter{$0["type"] as? String=="tun"}.count==1)
     try check("independent MTU",captured["mtu"] as? Int==1500 && (composed["inbounds"] as! [[String:Any]]).first{$0["type"] as? String=="tun"}!["mtu"] as? Int==1280)
     let dns=(composed["dns"] as! [String:Any])["servers"] as! [[String:Any]]
     try check("exit AdGuard and H3",dns.last!["type"] as? String=="h3" && dns.last!["server"] as? String=="192.168.50.133" && dns.last!["detour"] as? String=="proxy")
     try check("server comparison traverses PQ",endpoint(composed,"routervpn-execution-server")["detour"] as? String==RouterVPNMultihopGraph.entryTag)
     try check("both candidates remain owned",endpoint(composed,"proxy")["type"] as? String=="selector")
     try check("no staged helpers",sized.count==1 && originalFiles==exitFiles)
     try check("saved sources unchanged",text(a)==originalA && text(b)==originalB && text(entry)==original)
     if let source=entrySource{reject("missing requested entry layer"){_ = try IOSMultihopStartLayer.requiredSource(metadata:meta,source:nil)};reject("changed requested entry layer"){_ = try IOSMultihopStartLayer.requiredSource(metadata:meta,source:source.replacingOccurrences(of:"aes-",with:"wrong-"))}}
     if exitSource != nil{reject("missing requested exit layer"){_ = try IOSMultihopStartLayer.requiredExitSource(metadata:meta,source:nil)}}
     graphs+=1
    }}
   }
   let exitFixture=try object(Data(bridge(["Op":"exit-fixture","Mode":"wg"]).utf8))
   var a=profile(node,"home","off"),b=profile(exitFixture["node"] as! String,"home","off")
   a["id"]="entry";a["manual_mtu"]=1500;b["id"]="exit";b["manual_mtu"]=1280;b["multihop_entry_mode"]=mode
   let files=["sing-box.json":Data((exitFixture["config"] as! String).utf8)]
   let mutations:[(String,([String:Any])->[String:Any])]=[
    ("downgrade",{value in var v=value;v["type"]="wireguard";return v}),
    ("complete downgrade",{value in var v=value;v["type"]=mode=="wg-pq" ? "wireguard":"routervpn-amneziawg";for name in ["mode","node_id","pq","listen_port"]{v.removeValue(forKey:name)};if mode=="wg-pq"{v.removeValue(forKey:"amnezia")};return v}),
    ("discarded AWG",{value in var v=value;v["amnezia"]=["jc":"3"];return v}),
    ("mode",{value in var v=value;v["mode"]="wg";return v}),
    ("node",{value in var v=value;v["node_id"]=String(repeating:"f",count:64);return v}),
    ("missing pq",{value in var v=value;v.removeValue(forKey:"pq");return v}),
    ("unowned detour",{value in var v=value;v["detour"]="direct";return v}),
    ("listen port",{value in var v=value;v["listen_port"]=1234;return v}),
    ("hidden field",{value in var v=value;v["bind_interface"]="physical";return v}),
    ("handshake host",{value in var v=value;var p=v["pq"] as! [String:Any];p["endpoint"]="192.0.2.9:51822";v["pq"]=p;return v}),
    ("handshake route",{value in var v=value;var p=v["pq"] as! [String:Any];p["detour"]="direct";v["pq"]=p;return v}),
    ("same key",{value in var v=value;var p=v["pq"] as! [String:Any];p["peer"]=p["public"];v["pq"]=p;return v}),
    ("wrong encoding",{value in var v=value;var p=v["pq"] as! [String:Any];p["secret"]=(p["secret"] as! String)+"\n";v["pq"]=p;return v})]
   for (name,mutate) in mutations{reject("PQ graph "+name){_ = try RouterVPNMultihopGraph.build(entryEndpoint:mutate(entry),entryProfile:a,exitProfile:b,exitMode:"wg",files:files)}}
   for wrong in ["wg","awg2-fast","", "wg-pq-unknown"]{var selected=b;selected["multihop_entry_mode"]=wrong;reject("captured entry mode mismatch"){_ = try RouterVPNMultihopGraph.build(entryEndpoint:entry,entryProfile:a,exitProfile:selected,exitMode:"wg",files:files)}}
   var missing=b;missing.removeValue(forKey:"multihop_entry_mode");reject("captured entry mode absent"){_ = try RouterVPNMultihopGraph.build(entryEndpoint:entry,entryProfile:a,exitProfile:missing,exitMode:"wg",files:files)}
   let frozen=try RouterVPNMultihopGraph.build(entryEndpoint:entry,entryProfile:a,exitProfile:b,exitMode:"wg",files:files)
   var downgraded=try object(frozen["sing-box.json"]!),endpoints=downgraded["endpoints"] as! [[String:Any]]
   let index=endpoints.firstIndex{$0["tag"] as? String==RouterVPNMultihopGraph.entryTag}!
   endpoints[index]["type"]=mode=="wg-pq" ? "wireguard":"routervpn-amneziawg"
   for name in ["mode","node_id","pq","listen_port"]{endpoints[index].removeValue(forKey:name)}
   if mode=="wg-pq"{endpoints[index].removeValue(forKey:"amnezia")};downgraded["endpoints"]=endpoints
   reject("MTU cannot downgrade PQ"){_ = try RouterVPNMTUPolicy.multihop(["sing-box.json":json(downgraded)],entryProfile:a,exitProfile:b)}
   for exit in ["wg-pq","awg2-pq"]{reject("PQ exit cannot use an ordinary WG fixture"){_ = try RouterVPNMultihopGraph.build(entryEndpoint:entry,entryProfile:a,exitProfile:b,exitMode:exit,files:files)}}
   reject("failing native entry compiler"){_ = try IOSNativePQProfile.entryEndpoint(mode:mode,encoded:assets,nodeID:node){_,_,_ in throw NSError(domain:"test",code:1)}}
  }
  try check("complete Apple PQ-entry matrix",graphs==120)
  print("Apple PQ entries: \(graphs) executable Swift/shared-Go graph combinations")
 }
 @MainActor static func main()throws{
  defer{TestCompiler.shared.close()}
  for mode in ["wg-pq","awg2-pq"]{
   let fixture=try object(Data(bridge(["Op":"fixture","Mode":mode]).utf8)),assets=fixture["files"] as! [String:String],node=fixture["node"] as! String
   let original=try text(assets),rawName=mode=="wg-pq" ? "wg.conf":"awg.conf"
   for dns in ["home","custom","dot","doh","doh3","hostname"]{for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"]{
    let p=profile(node,dns,layer),b=try bundle(mode,assets,node,p)
    let selection=try IOSRuntimeSelector.selectRaw(bundle:b,rawProfileID:mode)
    try check("PQ always owned Libbox",selection.engine == .libbox && selection.rawProfileID==mode && selection.displayName.contains("Rosenpass"))
    try check("original profile preserved",selection.files[rawName]==Data(base64Encoded:assets[rawName]!))
    let patched=try IOSDNSRuntimePolicy.patch(b);try check("DNS patch does not rewrite PQ assets",patched.profiles==b.profiles)
    var files=try IOSNativePQProfile.compile(mode:mode,encoded:assets,nodeID:node,compiler:compile)
    let originalGraph=try object(files["sing-box.json"]!),originalEndpoint=(originalGraph["endpoints"] as! [[String:Any]])[0]
    files=try RouterVPNMultihopGraph.singlePQPolicy(files,profile:p)
    files=try IOSStartLayer.apply(root:outer(),selectedProfile:p,files:files,rawProfileID:mode,nativeBaseCompiler:start)
    files=try RouterVPNMTUPolicy.libbox(files,profile:p)
    let policies=try text(["entry":p,"exit":p])
    files["sing-box.json"]=Data(try bridge(["Op":"lan","Config":String(decoding:files["sing-box.json"]!,as:UTF8.self),"Policy":policies]).utf8)
    files["sing-box.json"]=Data(try bridge(["Op":"performance","Config":String(decoding:files["sing-box.json"]!,as:UTF8.self),"Policy":policies]).utf8)
    let graph=try object(files["sing-box.json"]!),ep=(graph["endpoints"] as! [[String:Any]])[0],peer=(ep["peers"] as! [[String:Any]])[0],pq=ep["pq"] as! [String:Any]
    try check("only compiled session data",files.count==1 && files["sing-box.json"] != nil)
    try check("single VPN",(graph["inbounds"] as! [Any]).count==1 && (graph["endpoints"] as! [Any]).count==1)
    try check("exact protocol and node",ep["type"] as? String=="routervpn-pq" && ep["mode"] as? String==mode && ep["node_id"] as? String==node)
    try check("exact private key",ep["private_key"] as? String==key(97))
    try check("exact peer",peer["public_key"] as? String==key(mode=="wg-pq" ? 98:100) && peer["pre_shared_key"] as? String==key(99))
    for (a,f) in [("rosenpass-client-secret","secret"),("rosenpass-client-public","public"),("rosenpass-server-public","peer")]{try check("exact PQ key "+f,pq[f] as? String==assets[a])}
    try check("two MTU owners updated",ep["mtu"] as? Int==1350 && (graph["inbounds"] as! [[String:Any]])[0]["mtu"] as? Int==1350)
    let host=layer=="off" ? "192.0.2.1":"10.77.0.1"
    try check("handshake uses same outer path",peer["address"] as? String==host && pq["endpoint"] as? String==host+":51822")
    if layer != "off"{try check("authenticated detour",ep["detour"] as? String=="start-layer-aes")}
    if mode=="awg2-pq"{try check("eleven AWG settings retained",text(ep["amnezia"]!)==text(originalEndpoint["amnezia"]!) && (ep["amnezia"] as! [String:Any]).count==11)}
    let resolvers=(graph["dns"] as! [String:Any])["servers"] as! [[String:Any]],selected=resolvers.last!
    let expected=["home":"udp","custom":"tcp","dot":"tls","doh":"https","doh3":"h3","hostname":"https"][dns]!
    try check("DNS transport preserved",selected["type"] as? String==expected)
    try check("AdGuard preserved",selected["server"] as? String==(dns=="hostname" ? "resolver.example.test":"192.168.50.133"))
    try check("DNS inside PQ",resolvers.allSatisfy{$0["detour"] as? String=="proxy"})
    if dns=="custom"{try check("custom DNS port",selected["server_port"] as? Int==5353)}
    if dns=="hostname"{try check("captured hostname bootstrap",resolvers.count==2 && resolvers[0]["server"] as? String=="192.168.50.133")}
    let rules=(graph["route"] as! [String:Any])["rules"] as! [[String:Any]]
    try check("IPv6 off",rules.contains{$0["action"] as? String=="reject" && $0["ip_version"] as? Int==6})
    try check("LAN off",rules.contains{$0["action"] as? String=="reject" && ($0["ip_cidr"] as? [String] ?? []).contains("192.168.0.0/16")})
    try check("padding owner",(graph["services"] as! [[String:Any]])[0]["packet_tag"] as? String=="proxy")
    try check("native endpoint still validates",bridge(["Op":"validate","Config":text(ep)])=="ok")
    try check("asset map unchanged",text(assets)==original)
   }}
   let p=profile(node,"home","off"),good=try IOSNativePQProfile.compile(mode:mode,encoded:assets,nodeID:node,compiler:compile)
   for policy in ["auto","default"]{var p=p;p["mtu_policy"]=policy;p["manual_mtu"]=1280;try check("unmeasured saved MTU not adopted",RouterVPNMTUPolicy.libbox(good,profile:p)==good)}
   var badMTU=p;badMTU["manual_mtu"]=1279;reject("invalid fixed MTU"){_ = try RouterVPNMTUPolicy.libbox(good,profile:badMTU)}
   var jumbo=p;jumbo["jumbo_tun"]=true;reject("incompatible packet Jumbo"){_ = try RouterVPNMultihopGraph.singlePQPolicy(good,profile:jumbo)}
   for name in ["chain.env","../escape","sing-box.json",mode=="wg-pq" ? "awg.conf":"wg.conf"]{var bad=assets;bad[name]=Data("unexpected".utf8).base64EncodedString();reject("foreign asset"){_ = try IOSNativePQProfile.decode(mode:mode,encoded:bad)}}
   for name in assets.keys{var bad=assets;bad.removeValue(forKey:name);reject("missing "+name){_ = try IOSNativePQProfile.decode(mode:mode,encoded:bad)}}
   for value in ["invalid",assets[rawName]!+"\n",Data([255]).base64EncodedString(),Data(repeating:65,count:1024*1024+1).base64EncodedString()]{var bad=assets;bad[rawName]=value;reject("raw envelope"){_ = try IOSNativePQProfile.decode(mode:mode,encoded:bad)}}
   for value in [Data(repeating:0,count:64),Data(repeating:1,count:31),Data(repeating:1,count:2*1024*1024+1)]{var bad=assets;bad["rosenpass-client-secret"]=value.base64EncodedString();reject("invalid key size/value"){_ = try IOSNativePQProfile.decode(mode:mode,encoded:bad)}}
   var same=assets;same["rosenpass-server-public"]=assets["rosenpass-client-public"];reject("same peer"){_ = try IOSNativePQProfile.decode(mode:mode,encoded:same)}
   reject("empty compiler result"){_ = try IOSNativePQProfile.compile(mode:mode,encoded:assets,nodeID:node){_,_,_ in ""}}
   reject("compiler failure"){_ = try IOSNativePQProfile.compile(mode:mode,encoded:assets,nodeID:node){_,_,_ in throw NSError(domain:"InjectedCompileFailure",code:1)}}
   for field in ["type","mode","node_id"]{var graph=try object(good["sing-box.json"]!);var ep=(graph["endpoints"] as! [[String:Any]])[0];ep[field]="changed";graph["endpoints"]=[ep];let wrong=try text(graph);reject("compiler replaced "+field){_ = try IOSNativePQProfile.compile(mode:mode,encoded:assets,nodeID:node){_,_,_ in wrong}}}
   var b=try bundle(mode,assets,node,p);b.selectedRouterID="missing";reject("missing saved profile"){_ = try IOSRuntimeSelector.selectRaw(bundle:b,rawProfileID:mode)}
   b=try bundle(mode,assets,node,p);b.routerProfiles.append(b.routerProfiles[0]);reject("ambiguous saved profile"){_ = try IOSRuntimeSelector.selectRaw(bundle:b,rawProfileID:mode)}
   b=try bundle(mode,assets,node,p);b.profiles=[:];reject("PQ missing assets no raw fallback"){_ = try IOSRuntimeSelector.selectRaw(bundle:b,rawProfileID:mode)}
   if mode=="wg-pq"{reject("wrong WG node"){_ = try IOSNativePQProfile.compile(mode:mode,encoded:assets,nodeID:String(repeating:"f",count:64),compiler:compile)}}
  }
  try entries()
  print("Apple PQ selection, captured peer, DNS, MTU, padding and Start Layers: PASS (\(checks) executable Swift/Go checks)")
 }
}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='.ios-pq-compiler-',dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix='ios-pq-policy-') as temp:
        go_dir,temp=Path(go_dir),Path(temp)
        (go_dir/'main.go').write_text(GO)
        binary=temp/'compiler'
        subprocess.run(['go','build','-o',str(binary),str(go_dir/'main.go')],cwd=ROOT,check=True,timeout=120)
        dns=APP/'IOSDNSRuntimePolicy.swift'
        if platform.system()!='Darwin':
            body=dns.read_text();assert body.count('import Network\n')==1
            dns=temp/dns.name;dns.write_text(body.replace('import Network\n',F.NETWORK_SHIM))
        source=temp/'Tests.swift';source.write_text(SWIFT)
        subprocess.run(['swiftc','-swift-version','6',str(APP/'Models.swift'),str(dns),str(APP/'IOSNativeXrayProfile.swift'),str(APP/'IOSNativePQProfile.swift'),str(APP/'IOSMultihopStartLayer.swift'),str(APP/'IOSRuntimeSelection.swift'),str(TUN/'RouterVPNMultihopGraph.swift'),str(TUN/'RouterVPNMTUPolicy.swift'),str(TUN/'IOSStartLayer.swift'),str(source),'-o',str(temp/'tests')],check=True,timeout=120)
        subprocess.run([str(temp/'tests'),str(binary)],check=True,timeout=150)
    provider=(TUN/'PacketTunnelProvider.swift').read_text()
    start=provider[provider.index('    private func startLibbox('):provider.index('    private func startExternalLibbox(')]
    for required in ['IOSNativePQProfile.compile(', 'LibboxRouterCompilePQProfile(', 'RouterVPNMultihopGraph.singlePQPolicy(', 'LibboxRouterApplyMultihopLANPolicy(', 'RouterVPNMTUPolicy.libbox(', 'performanceFiles(', 'expectedNodeID: provenNodeID']:
        assert required in start,required
    assert start.index('IOSNativePQProfile.compile(')<start.index('engine.start(')
    assert start.index('engine.start(')<start.index('proveSelectedNode(')
    assert 'IOSNativePQProfile' not in provider[provider.index('    private func startWireGuard('):provider.index('    private func startMultihop(')]
    multi=provider[provider.index('    private func startMultihop('):provider.index('    private func startLibbox(')]
    for required in ('IOSNativePQProfile.entryEndpoint(', 'LibboxRouterCompilePQProfile(', 'nodeID: entryProofID', 'RouterVPNMultihopGraph.build(', 'RouterVPNMTUPolicy.multihop('):
        assert required in multi, required
    assert multi.index('IOSNativePQProfile.entryEndpoint(') < multi.index('RouterVPNMultihopGraph.build(') < multi.index('engine.start(')
    engine=(TUN/'RouterVPNLibboxEngine.swift').read_text()
    assert engine.count('try RouterVPNPQFactory.install()')==1
    assert engine.index('try RouterVPNPQFactory.install()')<engine.index('LibboxNewCommandServer(')
    assert 'App/IOSNativePQProfile.swift' in (ROOT/'ios/RouterVPN/project.yml').read_text()
if __name__=='__main__':main()
