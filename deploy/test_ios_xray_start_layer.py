#!/usr/bin/env python3
"""Execute Apple Xray selection and Start Layer against the real shared compiler."""
from pathlib import Path
import importlib.util
import os
import platform
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
base=load('xray_profile_fixture',ROOT/'deploy/test_ios_native_xray_profiles.py')
GO=r''' package main
import("context";"encoding/json";"fmt";"io";"os";"net/netip";"router-vpn/internal/applexray")
func main(){
 var r struct{Mode string;Config string;Xray string;AES string;Policy string;Resolve bool}
 if json.NewDecoder(io.LimitReader(os.Stdin,16<<20)).Decode(&r)!=nil{os.Exit(2)}
 if r.Resolve{
  files,e:=applexray.ResolveStartLayerInputs(context.Background(),r.Mode,[]byte(r.Config),[]byte(r.Xray),[]byte(r.AES),[]byte(r.Policy),func(context.Context,string)([]netip.Addr,error){return []netip.Addr{netip.MustParseAddr("192.0.2.77")},nil})
  if e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(2)};json.NewEncoder(os.Stdout).Encode(files);return
 }
 out,e:=applexray.ComposeStartLayer(r.Mode,[]byte(r.Config),[]byte(r.Xray),[]byte(r.AES),[]byte(r.Policy));if e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(2)};os.Stdout.Write(out)
}
'''
TEST=r''' 
func sourceAES() throws -> Data {
 try json(["outbounds":[["type":"shadowsocks","tag":"proxy","method":"2022-blake3-aes-256-gcm","password":Data(repeating:29,count:32).base64EncodedString(),"server":"192.0.2.1","server_port":8388]]])
}
func compile(_ mode:String,_ wrapper:String,_ raw:String,_ aes:String,_ policy:String,resolve:Bool=false)throws->String{
 let p=Process();p.executableURL=URL(fileURLWithPath:CommandLine.arguments[1]);let input=Pipe(),output=Pipe(),errors=Pipe();p.standardInput=input;p.standardOutput=output;p.standardError=errors
 try p.run();try input.fileHandleForWriting.write(contentsOf:json(["Mode":mode,"Config":wrapper,"Xray":raw,"AES":aes,"Policy":policy,"Resolve":resolve]));try input.fileHandleForWriting.close()
 let result=output.fileHandleForReading.readDataToEndOfFile();p.waitUntilExit()
 guard p.terminationStatus==0,let text=String(data:result,encoding:.utf8)else{throw NSError(domain:"SharedXrayCompiler",code:1)};return text
}
func decoded(_ data:Data)throws->[String:Any]{try JSONSerialization.jsonObject(with:data) as! [String:Any]}
func canonical(_ value:Any)throws->Data{try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
@main struct XrayStartLayerTests {
 @MainActor static var checks=0
 @MainActor static func check(_ name:String,_ value:@autoclosure()throws->Bool)throws{guard try value() else{fatalError(name)};checks+=1}
 @MainActor static func reject(_ name:String,_ block:()throws->Void){do{try block();fatalError("accepted "+name)}catch{checks+=1}}
 @MainActor static func main()throws{
  for mode in ["reality-vision","reality-pq-vision","reality-xhttp","split","max"]{for start in ["aes-256-gcm","aes-256-gcm+xor-whitening"]{for dns in ["home","custom","dot","doh","doh3","rescue"]{
   var value=try xrayBundle(mode,dns:dns);value.routerProfiles[0].startLayer=start;value.profiles["shadowsocks"]=["sing-box.json":try sourceAES().base64EncodedString()]
   let patched=try IOSDNSRuntimePolicy.patch(value)
   let selected=try IOSRuntimeSelector.selectRaw(bundle:patched,rawProfileID:mode)
   try check("Xray selection retains same single native runtime",selected.engine == .libbox && selected.rawProfileID == mode)
   let root=try decoded(JSONEncoder().encode(patched)),profile=try decoded(JSONEncoder().encode(patched.routerProfiles[0]))
   let next=try IOSStartLayer.apply(root:root,selectedProfile:profile,files:selected.files,rawProfileID:mode,nativeXrayCompiler:{try compile($0,$1,$2,$3,$4)})
   try check("all source assets retained",Set(next.keys)==Set(selected.files.keys))
   try check("original Xray credential file unchanged",next["xray.json"]==selected.files["xray.json"])
   let before=try decoded(selected.files["sing-box.json"]!),after=try decoded(next["sing-box.json"]!)
   for field in ["dns","route","inbounds"]{try check("exact selected "+field,canonical(before[field]!)==canonical(after[field]!))}
   let a=after["outbounds"] as! [[String:Any]],b=before["outbounds"] as! [[String:Any]]
   try check("one extra outer only",a.count==b.count+1&&after["endpoints"]==nil)
   for i in b.indices{
    var expected=b[i]
    if expected["type"] as? String=="routervpn-xray"{
     let old=try decoded(Data((expected["config_json"] as! String).utf8));var target=old
     var outs=target["outbounds"] as! [[String:Any]],out=outs[0],settings=out["settings"] as! [String:Any],remotes=settings["vnext"] as! [[String:Any]]
     remotes[0]["address"]="10.77.0.1";settings["vnext"]=remotes;out["settings"]=settings;outs[0]=out;target["outbounds"]=outs
     let actual=try decoded(Data((a[i]["config_json"] as! String).utf8))
     try check("PQ/REALITY/Vision/FinalMask unchanged",canonical(target)==canonical(actual))
     expected["config_json"]=a[i]["config_json"];expected["detour"]="start-layer-aes"
    }else if expected["type"] as? String=="hysteria2"{expected["server"]="10.77.0.1";expected["detour"]="start-layer-aes"}
    try check("full native leg settings retained",canonical(expected)==canonical(a[i]))
   }
   try check("authenticated AES selected",a.last?["type"] as? String==(start.hasSuffix("whitening") ? "routervpn-aes-xor":"shadowsocks"))
   reject("cannot apply twice"){_=try IOSStartLayer.apply(root:root,selectedProfile:profile,files:next,rawProfileID:mode,nativeXrayCompiler:{try compile($0,$1,$2,$3,$4)})}
   var broken=selected.files;broken["xray.json"]=Data("{}".utf8)
   reject("missing protocol cannot be relabeled"){_=try IOSStartLayer.apply(root:root,selectedProfile:profile,files:broken,rawProfileID:mode,nativeXrayCompiler:{try compile($0,$1,$2,$3,$4)})}
  }}}
  for mode in ["reality-vision","reality-pq-vision","reality-xhttp","split","max"]{
   var value=try xrayBundle(mode);value.routerProfiles[0].startLayer="aes+xor"
   try check("canonical saved aliases shared with launch",IOSRuntimeSelector.normalizedStartLayer(in:value)=="aes-256-gcm+xor-whitening")
   value.routerProfiles[0].startLayer="xor"
   reject("XOR never masquerades as encryption"){_=try IOSRuntimeSelector.selectRaw(bundle:value,rawProfileID:mode)}
  }
  print("Apple Xray Start Layer production Swift + Go: PASS (\(checks) checks)")
 }
}
'''
def main():
 with tempfile.TemporaryDirectory(prefix='.xray-start-compiler-',dir=ROOT) as work,tempfile.TemporaryDirectory(prefix='apple-xray-start-') as tmp:
  work=Path(work);tmp=Path(tmp);(work/'main.go').write_text(GO)
  subprocess.run(['go','build','-o',str(tmp/'compiler'),str(work/'main.go')],cwd=ROOT,check=True,timeout=90)
  dns=APP/'IOSDNSRuntimePolicy.swift'
  if platform.system()!='Darwin':
   text=dns.read_text();dns=tmp/dns.name;dns.write_text(text.replace('import Network\n',base.base.NETWORK_SHIM))
  fixture=base.TEST[:base.TEST.index('@main struct Tests')]
  (tmp/'Tests.swift').write_text('import Foundation\n'+base.FIXTURE+fixture+TEST)
  subprocess.run(['swiftc','-swift-version','6',str(APP/'Models.swift'),str(dns),str(APP/'IOSNativeXrayProfile.swift'),str(APP/'IOSRuntimeSelection.swift'),str(ROOT/'ios/RouterVPN/PacketTunnel/IOSStartLayer.swift'),str(tmp/'Tests.swift'),'-o',str(tmp/'tests')],check=True,timeout=90)
  subprocess.run([str(tmp/'tests'),str(tmp/'compiler')],check=True,timeout=90)
 source=(APP/'RouterVPNModel.swift').read_text()
 for marker in ['LibboxRouterResolveXrayStartLayerProfile','let capturedAES = aesInput, capturedPolicy = startPolicy','launchBundle.profiles["shadowsocks"]?["sing-box.json"] = aes.base64EncodedString()','self.bundle?.profiles == bundle.profiles','where name != "start-layer-source.json"']:
  assert marker in source,marker
 print('Original saved bundle remains unchanged; compile/network/device acceptance are separate gates.')
if __name__=='__main__':main()
