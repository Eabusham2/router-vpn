#!/usr/bin/env python3
"""Run shipping Swift Xray device policy against the real Go policy compiler."""
from pathlib import Path
import importlib.util
import os
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
spec = importlib.util.spec_from_file_location('xray_device_fixture', ROOT/'deploy/test_ios_xray_start_layer.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
GO = r''' package main
import("encoding/json";"fmt";"io";"os";"router-vpn/internal/applexray";"router-vpn/internal/mobilemultihop")
func main(){
 var r struct{Operation string;Mode string;Config string;Raw string;AES string;Policy string}
 if json.NewDecoder(io.LimitReader(os.Stdin,16<<20)).Decode(&r)!=nil{os.Exit(2)}
 var output string;var err error
 switch r.Operation{
 case "device":output,err=mobilemultihop.ApplyNativeXrayDevicePolicy(r.Config,r.Policy)
 case "compile":var raw []byte;raw,err=applexray.Compile(r.Mode,[]byte(r.Config),[]byte(r.Raw));output=string(raw)
 case "layer":var raw []byte;raw,err=applexray.ComposeStartLayer(r.Mode,[]byte(r.Config),[]byte(r.Raw),[]byte(r.AES),[]byte(r.Policy));output=string(raw)
 default:os.Exit(2)
 }
 if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)};fmt.Print(output)
}
'''
TEST = r''' 
func call(_ operation:String,_ mode:String,_ config:String,_ raw:String,_ aes:String,_ policy:String)throws->String{
 let p=Process();p.executableURL=URL(fileURLWithPath:CommandLine.arguments[1]);let input=Pipe(),output=Pipe(),errors=Pipe();p.standardInput=input;p.standardOutput=output;p.standardError=errors
 try p.run();try input.fileHandleForWriting.write(contentsOf:json(["Operation":operation,"Mode":mode,"Config":config,"Raw":raw,"AES":aes,"Policy":policy]));try input.fileHandleForWriting.close()
 let result=output.fileHandleForReading.readDataToEndOfFile();p.waitUntilExit()
 guard p.terminationStatus==0,let text=String(data:result,encoding:.utf8)else{throw NSError(domain:"SharedXrayDevicePolicy",code:1)};return text
}
func object(_ data:Data)throws->[String:Any]{try JSONSerialization.jsonObject(with:data) as! [String:Any]}
func canonical(_ value:Any)throws->Data{try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
@main struct XrayDeviceTests {
 @MainActor static var checks=0
 @MainActor static func check(_ name:String,_ value:@autoclosure()throws->Bool)throws{guard try value() else{fatalError(name)};checks+=1}
 @MainActor static func reject(_ name:String,_ body:()throws->Void){do{try body();fatalError("accepted "+name)}catch{checks+=1}}
 @MainActor static func main()throws{
  for mode in ["reality-vision","reality-pq-vision","reality-xhttp","split","max"]{for layer in ["off","aes-256-gcm+xor-whitening"]{for lan in [true,false]{for ipv6 in ["on","off"]{
   var bundle=try xrayBundle(mode,dns:"doh3");bundle.routerProfiles[0].startLayer=layer
   bundle.routerProfiles[0].homeLANAccess=lan;bundle.routerProfiles[0].ipv6Mode=ipv6
   let patched=try IOSDNSRuntimePolicy.patch(bundle),selected=try IOSRuntimeSelector.selectRaw(bundle:patched,rawProfileID:mode)
   var profile=try object(JSONEncoder().encode(patched.routerProfiles[0]));profile["router_api"]="http://10.77.0.1:8787"
   var files=selected.files
   let raw=String(decoding:files["xray.json"]!,as:UTF8.self),wrapper=String(decoding:files["sing-box.json"]!,as:UTF8.self)
   let native=try call("compile",mode,wrapper,raw,"","");files["sing-box.json"]=Data(native.utf8)
   if layer != "off"{
    let aes=try json(["outbounds":[["type":"shadowsocks","tag":"proxy","server":"192.0.2.1","server_port":8388,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:9,count:32).base64EncodedString()]]])
    let policy=try json(["mode":layer,"raw_mode":mode,"node_kind":"router-vpn","router_api":"http://10.77.0.1:8787"])
    files["sing-box.json"]=Data(try call("layer",mode,native,raw,String(decoding:aes,as:UTF8.self),String(decoding:policy,as:UTF8.self)).utf8)
   }
   let withMTU=try RouterVPNMTUPolicy.libbox(files,profile:profile)
   let before=try object(withMTU["sing-box.json"]!)
   let protected=try IOSXrayDevicePolicy.apply(files:withMTU,profile:profile,compiler:{try call("device","",$0,"","",$1)})
   let after=try object(protected["sing-box.json"]!),route=after["route"] as! [String:Any],tun=(after["inbounds"] as! [[String:Any]])[0]
   try check("same original assets",protected["xray.json"]==withMTU["xray.json"]&&Set(protected.keys)==Set(withMTU.keys))
   try check("authentication and both legs unchanged",canonical(before["outbounds"]!)==canonical(after["outbounds"]!))
   try check("selected DNS preserved",canonical((before["dns"] as! [String:Any])["servers"]!)==canonical((after["dns"] as! [String:Any])["servers"]!))
   try check("fixed MTU retained",tun["mtu"] as? Int==1380)
   let final=(before["route"] as! [String:Any])["final"] as! String,rules=route["rules"] as? [[String:Any]] ?? []
   try check("native final route retained",route["final"] as? String==final)
   if ipv6=="off"{
    try check("IPv6 blocked inside captured TUN",rules.first?["ip_version"] as? Int==6 && rules.first?["action"] as? String=="reject")
    try check("IPv6 still captured",(tun["route_address"] as! [String]).contains("::/0") && (tun["address"] as! [String]).contains(where:{$0.contains(":")}))
   }
   if !lan{
    let index=ipv6=="off" ? 2:1
    try check("only exact control exception",rules[index]["outbound"] as? String==final && rules[index]["port"] as? Int==8787 && rules[index]["ip_cidr"] as? [String]==["10.77.0.1/32"])
    try check("LAN rejected",rules[index+1]["action"] as? String=="reject")
   }
   try check("caller graph untouched",withMTU["sing-box.json"]==Data(try JSONSerialization.data(withJSONObject:before,options:[.sortedKeys])))
   var invalid=profile;invalid["home_lan_access"]="false"
   reject("typed LAN policy"){_=try IOSXrayDevicePolicy.apply(files:withMTU,profile:invalid,compiler:{try call("device","",$0,"","",$1)})}
  }}}}
  print("Apple native Xray LAN/IPv6 policy: PASS (\(checks) checks; production Swift and Go)")
 }
}
'''

def main():
 with tempfile.TemporaryDirectory(prefix='.xray-device-',dir=ROOT) as work,tempfile.TemporaryDirectory(prefix='xray-device-tests-') as tmp:
  work=Path(work);tmp=Path(tmp);(work/'main.go').write_text(GO)
  subprocess.run(['go','build','-o',str(tmp/'compiler'),str(work/'main.go')],cwd=ROOT,check=True,timeout=120)
  dns=APP/'IOSDNSRuntimePolicy.swift'
  if platform.system()!='Darwin':
   text=dns.read_text();dns=tmp/dns.name;dns.write_text(text.replace('import Network\n',base.base.base.NETWORK_SHIM))
  fixture=base.base.TEST[:base.base.TEST.index('@main struct Tests')]
  (tmp/'Tests.swift').write_text('import Foundation\n'+base.base.FIXTURE+fixture+TEST)
  subprocess.run(['swiftc','-swift-version','6',str(APP/'Models.swift'),str(dns),str(APP/'IOSNativeXrayProfile.swift'),str(APP/'IOSRuntimeSelection.swift'),str(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNMTUPolicy.swift'),str(ROOT/'ios/RouterVPN/PacketTunnel/IOSXrayDevicePolicy.swift'),str(tmp/'Tests.swift'),'-o',str(tmp/'tests')],check=True,timeout=120)
  subprocess.run([str(tmp/'tests'),str(tmp/'compiler')],check=True,timeout=120)
 source=(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
 start=source.index('private func startLibbox(');end=source.index('private func startExternalLibbox(',start);body=source[start:end]
 assert body.index('LibboxRouterCompileXrayProfile')<body.index('IOSXrayDevicePolicy.apply')<body.index('engine.start(')
 assert body.index('RouterVPNMTUPolicy.libbox')<body.index('IOSXrayDevicePolicy.apply')<body.index('performanceFiles(')
if __name__=='__main__':main()
