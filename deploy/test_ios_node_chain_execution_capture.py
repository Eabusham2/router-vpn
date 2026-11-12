#!/usr/bin/env python3
"""Execute Apple ordered execution capture with the real shared Go compiler.

Native lifecycle methods are refusing boundaries. No system VPN, privileged
traffic, generated Apple framework or signed-device acceptance is claimed.
"""
from pathlib import Path
import importlib.util
import os
import platform
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
spec=importlib.util.spec_from_file_location('apple_local_capture',ROOT/'deploy/test_ios_node_chain_capture.py')
LOCAL=importlib.util.module_from_spec(spec);spec.loader.exec_module(LOCAL)
GO=LOCAL.GO.replace('"router-vpn/internal/mobileperf"','"router-vpn/internal/mobileperf";libbox "router-vpn/mobile"',1)
# The eight-node layered fixture deliberately configures a 4000-byte packet
# ceiling. This is source capacity, never a measured-path/Jumbo success claim.
assert 'MTU=2000\\n' in GO
GO=GO.replace('MTU=2000\\n','MTU=4000\\n')
anchor=' case "chain-fixture":'
assert GO.count(anchor)==1
GO=GO.replace(anchor,r'''
 case "execution-new":value,err=executionNew(r.Source,r.Mode)
 case "execution-open":value,err=executionOpen(r.Source)
 case "execution-digest":sum:=sha256.Sum256([]byte(r.Source));value=hex.EncodeToString(sum[:])
'''+anchor,1)+r'''
type executionEnvelope struct{Kind string `json:"kind"`;Schema int `json:"schema"`;Source string `json:"source"`;SourceSHA string `json:"source_sha256"`;ConfigSHA string `json:"config_sha256"`}
func executionPrepared(p *mobilemultihop.NodeChainExecutionPreparation)(string,error){
 launch,err:=json.Marshal(executionEnvelope{"routervpn-node-chain-execution-preparation-input",1,p.Source(),p.SourceSHA256(),p.ConfigSHA256()});if err!=nil{return "",err}
 raw,err:=json.Marshal(map[string]string{"source":p.Source(),"source_sha256":p.SourceSHA256(),"config":p.Config(),"config_sha256":p.ConfigSHA256(),"local_source_sha256":p.LocalSourceSHA256(),"requested":p.Execution(),"launch":string(launch)});return string(raw),err
}
func executionNew(input,requested string)(string,error){
 if _,err:=mobilemultihop.ParseNodeChainLaunchInput(input);err!=nil{return "",err}
 var local mobilemultihop.NodeChainSource;if err:=json.Unmarshal([]byte(input),&local);err!=nil{return "",err};raw,err:=json.Marshal(local);if err!=nil{return "",err}
 p,err:=mobilemultihop.NewNodeChainExecutionPreparation(string(raw),requested);if err!=nil{return "",err};return executionPrepared(p)
}
func executionOpen(input string)(string,error){
 if err:=libbox.RouterValidatePrivateNodeJSON(input);err!=nil{return "",err}
 var e executionEnvelope;if err:=json.Unmarshal([]byte(input),&e);err!=nil{return "",err}
 canonical,err:=json.Marshal(e);if err!=nil||string(canonical)!=input||e.Kind!="routervpn-node-chain-execution-preparation-input"||e.Schema!=1{return "",fmt.Errorf("noncanonical private launch")}
 if err:=libbox.RouterValidatePrivateNodeJSON(e.Source);err!=nil{return "",err}
 var s mobilemultihop.NodeChainExecutionPreparationSource;if err:=json.Unmarshal([]byte(e.Source),&s);err!=nil{return "",err}
 p,err:=mobilemultihop.NewNodeChainExecutionPreparation(s.LocalSource,s.Execution);if err!=nil{return "",err}
 if s.Schema!=1||p.Source()!=e.Source||p.SourceSHA256()!=e.SourceSHA||p.ConfigSHA256()!=e.ConfigSHA{return "",fmt.Errorf("changed execution source")}
 return executionPrepared(p)
}
'''
LIBBOX=LOCAL.LIBBOX.replace('PQTest','OrdinarySourceTest')+r'''
public final class LibboxCommandServer { public var bindAttempts=0; public init(){} }
private final class ExecutionFault: @unchecked Sendable {
 static let shared=ExecutionFault();let lock=NSLock();var value=""
 func set(_ v:String){lock.lock();value=v;lock.unlock()}
 func take()->String{lock.lock();defer{lock.unlock()};let v=value;value="";return v}
}
public func LibboxTestExecutionFault(_ value:String){ExecutionFault.shared.set(value)}
public func LibboxTestDigest(_ data:Data)throws->[UInt8]{
 let raw=try bridge(["Op":"execution-digest","Source":String(decoding:data,as:UTF8.self)])
 return stride(from:0,to:64,by:2).map{offset in let start=raw.index(raw.startIndex,offsetBy:offset);return UInt8(raw[start..<raw.index(start,offsetBy:2)],radix:16)!}
}
public final class LibboxRouterNodeChainExecution {
 private var receipt:[String:String];private var closed=false;private var launchError=false
 init(_ receipt:[String:String])throws{
  self.receipt=receipt
  switch ExecutionFault.shared.take(){
  case "config":self.receipt["config"]=receipt["config"]!+" "
  case "requested":self.receipt["requested"]="local"
  case "launch-error":launchError=true
  case "local-node":
   var source=try JSONSerialization.jsonObject(with:Data(receipt["source"]!.utf8)) as! [String:Any]
   var local=try JSONSerialization.jsonObject(with:Data((source["local_source"] as! String).utf8)) as! [String:Any]
   var nodes=local["nodes"] as! [String];nodes.swapAt(0,1);local["nodes"]=nodes
   source["local_source"]=String(decoding:try JSONSerialization.data(withJSONObject:local,options:[.sortedKeys]),as:UTF8.self)
   self.receipt["source"]=String(decoding:try JSONSerialization.data(withJSONObject:source,options:[.sortedKeys]),as:UTF8.self)
   var launch=try JSONSerialization.jsonObject(with:Data(receipt["launch"]!.utf8)) as! [String:Any];launch["source"]=self.receipt["source"]!
   self.receipt["launch"]=String(decoding:try JSONSerialization.data(withJSONObject:launch,options:[.sortedKeys]),as:UTF8.self)
  default:break
  }
 }
 public func source()->String{receipt["source"]!}
 public func config()->String{receipt["config"]!}
 public func sourceSHA256()->String{receipt["source_sha256"]!}
 public func configSHA256()->String{receipt["config_sha256"]!}
 public func localSourceSHA256()->String{receipt["local_source_sha256"]!}
 public func requestedExecution()->String{receipt["requested"]!}
 public func launchInput(_ error:UnsafeMutablePointer<NSError?>?)->String{if launchError{error?.pointee=NSError(domain:"NativeLaunchFault",code:1)};return receipt["launch"]!}
 public func bindNative(_ server:LibboxCommandServer)throws{server.bindAttempts+=1;throw NSError(domain:"SourceOnly",code:1)}
 public func run(_ server:LibboxCommandServer)throws{throw NSError(domain:"SourceOnly",code:1)}
 public func healthy()->Bool{false}
 public func execution()->String{""}
 public func networkChanged(){}
 public func nativeClosed()->Bool{false}
 public func retainsServerCleanup(_ server:LibboxCommandServer)->Bool{false}
 public func close()throws{closed=true}
}
func executionMake(_ operation:String,_ source:String,_ requested:String)throws->LibboxRouterNodeChainExecution{
 let raw=try bridge(["Op":operation,"Source":source,"Mode":requested]);return try LibboxRouterNodeChainExecution(JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [String:String])
}
public func LibboxRouterNodeChainExecutionFromLaunch(_ input:String,_ execution:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{api(error){try executionMake("execution-new",input,execution)}}
public func LibboxNewRouterNodeChainExecutionLaunch(_ input:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{api(error){try executionMake("execution-open",input,"")}}
'''
CRYPTO='''import Foundation
import Libbox
public enum SHA256 { public static func hash(data:Data)->[UInt8] { try! LibboxTestDigest(data) } }
'''
SWIFT=r'''
import Foundation
import Libbox
func data(_ value:Any)throws->Data{try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
func object(_ value:Data)throws->[String:Any]{try JSONSerialization.jsonObject(with:value) as! [String:Any]}
func profile(_ value:Data)throws->[String:Any]{try (object(value)["routerProfiles"] as! [[String:Any]])[0]}
func edit(_ value:Data,_ change:(inout [String:Any])->Void)throws->Data{var root=try object(value);change(&root);return try data(root)}
func editProfile(_ value:Data,_ change:(inout [String:Any])->Void)throws->Data{var root=try object(value);var p=(root["routerProfiles"] as! [[String:Any]])[0];change(&p);root["routerProfiles"]=[p];return try data(root)}
func fixture(_ count:Int,_ layer:String,_ requested:String,_ awg:Bool)throws->[Data]{let raw=try awg ? LibboxTestAWGFixture(count,layer):LibboxTestFixture(count,layer);var bundles=try (JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [Any]).map{try data($0)};bundles[count-1]=try editProfile(bundles[count-1]){$0["multihop_execution"]=requested};return bundles}
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ yes:Bool,_ name:String){guard yes else{fatalError(name)};checks+=1}
 @MainActor static func reject(_ name:String,_ action:()throws->Void){do{try action();fatalError("ACCEPTED "+name)}catch{checks+=1}}
 @MainActor static func main()throws{
  defer{LibboxTestClose()}
  for count in [2,3,4,8]{for requested in ["server","auto"]{for awg in [false,true]{for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"]{
   let bundles=try fixture(count,layer,requested,awg)
   let capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested)
   check(capture.members.count==count && capture.requested==requested && capture.local.selectionExecution==requested,"captured count/execution changed")
   check(try data(capture.finalProfile)==data(profile(bundles.last!)),"original final execution profile normalized")
   check(capture.strict && !capture.homeLANAccess,"original aggregate protection lost")
   for (position,member) in capture.members.enumerated(){check(try data(member.profile)==data(profile(bundles[position])),"original member profile changed")}
   let graph=try object(Data(capture.config.utf8));let route=graph["route"] as! [String:Any]
   check(route["final"] as? String=="routervpn-chain-application","preparation bypassed native closed gate")
   let reopened=try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(bundles.last!))
   check(reopened.source==capture.source && reopened.config==capture.config,"exact source replay changed")
   check(!capture.healthy() && !capture.nativeClosed(),"source-only preparation claimed readiness or native retirement")
   reject("local entry accepted Server selection"){_ = try IOSNodeChainCapture.compile(bundles:bundles)}
   try reopened.close();try capture.close()
   reject("closed capture remained usable"){try capture.requireCurrent()}
  }}}}
  var tooSmall=try fixture(8,"aes-256-gcm+xor-whitening","server",true)
  for position in tooSmall.indices {
   tooSmall[position]=try edit(tooSmall[position]){root in
    var assets=root["profiles"] as! [String:[String:String]]
    for mode in ["wg","awg2-fast","awg2-strong"] {
     guard var files=assets[mode] else{continue}
     for key in files.keys{if let bytes=Data(base64Encoded:files[key]!),let raw=String(data:bytes,encoding:.utf8){files[key]=Data(raw.replacingOccurrences(of:"MTU=4000\n",with:"MTU=2000\n").utf8).base64EncodedString()}}
     assets[mode]=files
    }
    root["profiles"]=assets
   }
  }
  reject("undersized layered packet source"){_ = try IOSNodeChainExecutionCapture.compile(bundles:tooSmall,requested:"server")}
  let bundles=try fixture(3,"off","server",false)
  for fault in ["config","requested","launch-error","local-node"]{
   LibboxTestExecutionFault(fault)
   reject("native execution "+fault){_ = try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"server")}
  }
  let capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"server")
  var replaced=try profile(bundles.last!);replaced["api_token"]="another-private-node-token"
  reject("changed final control"){_ = try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:replaced)}
  reject("noncanonical launch"){_ = try IOSNodeChainExecutionCapture.reopen(capture.launchInput+" ",selectedProfile:profile(bundles.last!))}
  reject("requested execution normalized"){_ = try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"auto")}
  try capture.close()
  let cancelledNative=LibboxCommandServer()
  reject("cancelled binding admitted execution"){try capture.bindNative(cancelledNative)}
  check(cancelledNative.bindAttempts==1,"cancelled capture failed to reserve original native cleanup")
  print("PASS Apple execution source: \(checks) checks")
 }
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='.ios-execution-compiler-',dir=ROOT) as gd, tempfile.TemporaryDirectory(prefix='ios-execution-source-') as wd:
        gd,work=Path(gd),Path(wd);(gd/'main.go').write_text(GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(gd/'main.go')],cwd=ROOT,check=True,timeout=180)
        (work/'Libbox.swift').write_text(LIBBOX);(work/'CryptoKit.swift').write_text(CRYPTO);(work/'Tests.swift').write_text(SWIFT)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        suffix='.dylib' if platform.system()=='Darwin' else '.so'
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(work/'Libbox.swift'),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(work/('libLibbox'+suffix))],check=True,timeout=90)
        link=['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        subprocess.run(options+link+['-emit-module','-emit-library','-module-name','CryptoKit',str(work/'CryptoKit.swift'),'-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/('libCryptoKit'+suffix))],check=True,timeout=90)
        command=options+link+['-lCryptoKit',str(APP/'Models.swift'),str(APP/'IOSMultihopStartLayer.swift'),str(APP/'IOSNodeChainCapture.swift')]
        source=APP/'IOSNodeChainExecutionCapture.swift';tests=work/'Tests.swift';binary=work/'tests'
        subprocess.run(command+[str(source),str(tests),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary),str(compiler)],check=True,timeout=180)
        text=source.read_text()
        for name,before,after in (
          ('config','configSHA256 == SHA256.hash(data: Data(config.utf8)).map({ String(format: "%02x", $0) }).joined(),','true,'),
          ('requested','plan.requestedExecution() == requested,','true,'),
          ('launch-error','guard failure == nil, let input else {','guard let input else {'),
          ('local-node','nodes == original["nodes"] as? [String], identities == original["identity_sources"] as? [String] else {','!nodes.isEmpty, identities == original["identity_sources"] as? [String] else {'),
          ('cleanup-bind-order','func bindNative(_ server: LibboxCommandServer) throws { try plan.bindNative(server); try requireCurrent() }','func bindNative(_ server: LibboxCommandServer) throws { try requireCurrent(); try plan.bindNative(server) }'),
        ):
            assert text.count(before)==1,name
            mutant=work/(name+'.swift');mutant.write_text(text.replace(before,after,1));binary=work/name
            subprocess.run(command+[str(mutant),str(tests),'-o',str(binary)],check=True,timeout=90)
            result=subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
            witness='cancelled capture failed to reserve original native cleanup' if name=='cleanup-bind-order' else 'ACCEPTED native execution '+name
            assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,(result.stdout+result.stderr)[-1500:])
            print('Rejected Apple execution source control:',name)

if __name__=='__main__':main()
