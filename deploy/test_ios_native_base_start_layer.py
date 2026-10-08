#!/usr/bin/env python3
"""Exercise shipping Apple WG/AWG Start Layer policy using the real Go compiler.

The Swift policy source is unchanged; only its gomobile boundary is replaced by
an executable running the same shipping Go package. Native framework linking and
real encrypted packet tests remain separate required build gates.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
GO=r''' package main
import("encoding/json";"fmt";"io";"os";"router-vpn/internal/mobilemultihop")
func main(){
 var input struct{Config string;Source string;Policy string}
 if json.NewDecoder(io.LimitReader(os.Stdin,12<<20)).Decode(&input)!=nil{os.Exit(2)}
 value,err:=mobilemultihop.ComposeNativeBaseStartLayer(input.Config,input.Source,input.Policy)
 if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}
 fmt.Print(value)
}
'''
SWIFT=r''' 
import Foundation
func encoded(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys]) }
func object(_ data: Data) throws -> [String:Any] { try JSONSerialization.jsonObject(with:data) as! [String:Any] }
func key(_ value: UInt8) -> String { Data(repeating:value,count:32).base64EncodedString() }
func configuration(_ mode: String) -> [String:Any] {
 var endpoint: [String:Any] = ["type":mode == "wg" ? "wireguard" : "routervpn-amneziawg","tag":"proxy","system":false,"mtu":1380,"address":["10.77.0.2/24","fd77:77::2/64"],"private_key":key(97),"peers":[["address":"192.0.2.1","port":51820,"public_key":key(98),"pre_shared_key":key(99),"allowed_ips":["0.0.0.0/0","::/0"],"persistent_keepalive_interval":25]]]
 if mode != "wg" {endpoint["amnezia"]=["jc":"3","jmin":"40","jmax":"900","s1":"56","s2":"48","s3":"24","s4":"32","h1":"10000000-19999999","h2":"20000000-29999999","h3":"30000000-39999999","h4":"40000000-49999999"]}
 return ["inbounds":[["type":"tun","tag":"tun-in","auto_route":true,"strict_route":true,"mtu":1380]],"endpoints":[endpoint],"outbounds":[],"dns":["servers":[["tag":"home","type":"tcp","server":"192.168.50.133","server_port":5353,"detour":"proxy"]],"final":"home"],"route":["final":"proxy","rules":[["inbound":["tun-in"],"ip_version":6,"action":"reject"]]]]
}
func source() -> [String:Any] { ["outbounds":[["type":"shadowsocks","tag":"proxy","method":"2022-blake3-aes-256-gcm","password":key(115),"server":"192.0.2.1","server_port":8388]]] }
func bridge(_ config: String,_ source: String,_ policy: String) throws -> String {
 let process=Process();process.executableURL=URL(fileURLWithPath:CommandLine.arguments[1])
 let input=Pipe(),output=Pipe(),errors=Pipe();process.standardInput=input;process.standardOutput=output;process.standardError=errors
 try process.run()
 try input.fileHandleForWriting.write(contentsOf:encoded(["Config":config,"Source":source,"Policy":policy]))
 try input.fileHandleForWriting.close()
 let result=output.fileHandleForReading.readDataToEndOfFile();process.waitUntilExit()
 guard process.terminationStatus==0,let text=String(data:result,encoding:.utf8) else {throw NSError(domain:"NativeCompilerTest",code:1)}
 return text
}
func compose(_ mode: String,_ start: String,profile: [String:Any]? = nil,config: [String:Any]? = nil,outer: [String:Any]? = nil) throws -> [String:Data] {
 let root: [String:Any] = ["profiles":["shadowsocks":["sing-box.json":try encoded(outer ?? source()).base64EncodedString()]]]
 return try IOSStartLayer.apply(root:root,selectedProfile:profile ?? ["node_kind":"router-vpn","start_layer":start,"router_api":"http://10.77.0.1:8787"],files:["sing-box.json":try encoded(config ?? configuration(mode)),"owned.pem":Data("unchanged-certificate".utf8)],rawProfileID:mode,nativeBaseCompiler:bridge)
}
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ label:String,_ condition:@autoclosure ()throws->Bool)throws{guard try condition() else{fatalError(label)};checks+=1}
 @MainActor static func reject(_ label:String,_ block:()throws->Void){do{try block();fatalError("accepted "+label)}catch{checks+=1}}
 @MainActor static func main()throws{
  for mode in ["wg","awg2-fast","awg2-strong"] {for start in [IOSStartLayer.aes,IOSStartLayer.aesXOR] {for service in ["http://10.77.0.1:8787","https://[fd77:77::1]:8787"] {
   let original=configuration(mode)
   let files=try compose(mode,start,profile:["node_kind":"router-vpn","start_layer":start,"router_api":service])
   let graph=try object(files["sing-box.json"]!)
   for field in ["inbounds","dns","route"] {try check("unchanged "+field,encoded(original[field]!)==encoded(graph[field]!))}
   try check("certificate bytes retained",files["owned.pem"]==Data("unchanged-certificate".utf8))
   var endpoint=(original["endpoints"] as! [[String:Any]])[0]
   var peer=(endpoint["peers"] as! [[String:Any]])[0];peer["address"]=service.contains("fd77") ? "fd77:77::1":"10.77.0.1"
   endpoint["peers"]=[peer];endpoint["detour"]=IOSStartLayer.aesTag
   try check("all native peer/key/AWG options preserved",encoded(endpoint)==encoded((graph["endpoints"] as! [[String:Any]])[0]))
   let aes=(graph["outbounds"] as! [[String:Any]])[0]
   try check("correct native AES/XOR",aes["type"] as? String==(start==IOSStartLayer.aesXOR ? "routervpn-aes-xor":"shadowsocks"))
   try check("outer authentication retained",aes["password"] as? String==key(115)&&aes["method"] as? String==IOSStartLayer.aesMethod)
   reject("raw backend silently accepts Start Layer"){try IOSStartLayer.validateWireGuard(profile:["start_layer":start])}
  }}}
  for mode in ["wg","awg2-fast","awg2-strong"]{
   let original=configuration(mode), files=try compose(mode,IOSStartLayer.off)
   try check("raw disabled unchanged",files["sing-box.json"]==encoded(original))
   reject("no second encapsulation") {let first=try compose(mode,IOSStartLayer.aes);_=try compose(mode,IOSStartLayer.aes,config:object(first["sing-box.json"]!))}
   for wrong:Any in [true,1,NSNull(),["mode":"aes"]]{reject("malformed saved Start Layer"){_=try compose(mode,"",profile:["start_layer":wrong])}}
   for api in ["http://localhost:8787","http://8.8.8.8:8787","http://10.77.0.1:8787/path"]{reject("foreign service address"){_=try compose(mode,IOSStartLayer.aes,profile:["start_layer":IOSStartLayer.aes,"router_api":api])}}
   reject("external profile"){_=try compose(mode,IOSStartLayer.aes,profile:["node_kind":"external","start_layer":IOSStartLayer.aes,"router_api":"http://10.77.0.1:8787"])}
  }
  var altered=source();var out=(altered["outbounds"] as! [[String:Any]])[0];out["plugin"]="unowned";altered["outbounds"]=[out]
  reject("unowned helper not discarded"){_=try compose("wg",IOSStartLayer.aes,outer:altered)}
  print("Apple WG/AWG Start Layer shipping Swift + Go compiler: PASS (\(checks) checks)")
 }
}
'''

def main():
    for name in ['go','swiftc']:
        if not shutil.which(name):raise RuntimeError(name+' is required')
    with tempfile.TemporaryDirectory(prefix='.start-layer-go-',dir=ROOT) as go_dir,tempfile.TemporaryDirectory(prefix='apple-start-layer-') as tmp:
        go_dir=Path(go_dir);tmp=Path(tmp);(go_dir/'main.go').write_text(GO)
        subprocess.run(['go','build','-o',str(tmp/'compiler'),str(go_dir/'main.go')],cwd=ROOT,check=True,timeout=90)
        (tmp/'Tests.swift').write_text(SWIFT)
        subprocess.run(['swiftc','-swift-version','6',str(ROOT/'ios/RouterVPN/PacketTunnel/IOSStartLayer.swift'),str(tmp/'Tests.swift'),'-o',str(tmp/'tests')],check=True,timeout=90)
        subprocess.run([str(tmp/'tests'),str(tmp/'compiler')],check=True,timeout=90)
if __name__=='__main__':main()
