#!/usr/bin/env python3
"""Execute the shipping Apple ordered-source capture against the real Go core.

Gomobile calls are a framed subprocess boundary. Native traffic, a generated
Apple SDK and original TUN lifecycle have their own required acceptance gates;
these socket-free compilation tests establish no live connection readiness.
"""
from pathlib import Path
import importlib.util
import os
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
spec = importlib.util.spec_from_file_location('chain_policy_boundary', ROOT / 'deploy/test_ios_pq_selection.py')
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)

GO = P.GO.replace('"crypto/sha256"', '"crypto/sha256";"crypto/ecdh";"strconv"', 1)
anchor = ' case "compile":value,err=mobilemultihop.CompilePQProfile(r.Mode,r.Files,r.Node)'
assert GO.count(anchor) == 1
GO = GO.replace(anchor, r'''
 case "chain-fixture":var count int;count,err=strconv.Atoi(r.Mode);if err==nil{value,err=chainFixture(count,r.Policy)}
 case "chain-awg-fixture":var count int;count,err=strconv.Atoi(r.Mode);if err==nil{value,err=chainFixtureModes(count,r.Policy,true)}
 case "chain-member":
  var node *mobilemultihop.NodeProfile;node,err=mobilemultihop.NewNodeProfile(r.Mode,r.Files,r.Policy,r.Source,r.Node)
  if err==nil{value,err=node.LaunchInput()}
 case "chain-new","chain-open","chain-project":
  var chain *mobilemultihop.NodeChain
  if r.Op=="chain-new"{chain,err=mobilemultihop.NewNodeChain(r.Source)}else{chain,err=mobilemultihop.ParseNodeChainLaunchInput(r.Source)}
  if err==nil&&r.Op=="chain-project"{chain,err=mobilemultihop.ProjectNodeChain(chain,r.Mode,0)}
  if err==nil{
   var launch string;launch,err=chain.LaunchInput()
   if err==nil{var encoded []byte;encoded,err=json.Marshal(map[string]string{"config":chain.Config(),"source":chain.SourceSHA256(),"config_sha":chain.ConfigSHA256(),"launch":launch});value=string(encoded)}
  }
''' + anchor, 1)
GO += r'''
func chainFixture(count int,layer string)(string,error){return chainFixtureModes(count,layer,false)}
func chainFixtureModes(count int,layer string,mixed bool)(string,error){
 if count<2||count>8{return "",fmt.Errorf("fixture node count")}
 bundles:=make([]any,0,count);selection:=make([]any,0,count)
 for i:=0;i<count;i++{
  mode:="wg";if mixed{mode=[]string{"awg2-fast","awg2-strong","wg"}[i%3]};if i==count-1{mode="shadowsocks"};selection=append(selection,map[string]string{"id":fmt.Sprintf("chain-node-%d",i),"mode":mode})
 }
 for i:=0;i<count;i++{
  endpoint:=fmt.Sprintf("198.51.100.%d",10+i);id:=fmt.Sprintf("chain-node-%d",i)
  key:=func(b byte)string{return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b},32))}
  server,e:=ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{byte(71+i)},32));if e!=nil{return "",e}
  public:=base64.StdEncoding.EncodeToString(server.PublicKey().Bytes());hash:=sha256.Sum256([]byte("router-vpn-node-proof-v1\n"+public))
  profile:=map[string]any{"id":id,"node_kind":"router-vpn","node_proof_id":hex.EncodeToString(hash[:]),"endpoint":endpoint,"router_api":fmt.Sprintf("http://10.%d.0.1:8787",80+i),"api_token":fmt.Sprintf("fixture-private-token-%d",i),"start_layer":layer,"dns_mode":"home","adguard_ipv4":fmt.Sprintf("10.%d.0.53",80+i),"mtu_policy":"auto","effective_mtu":9000,"ipv6_mode":"on","home_lan_access":true,"kill_switch_policy":"off"}
  if i==1{profile["home_lan_access"]=false;profile["kill_switch_policy"]="always"}
  raw:=fmt.Sprintf("[Interface]\nAddress=10.%d.0.2/24,fd80:%x::2/64\nPrivateKey=%s\nDNS=10.%d.0.53\nMTU=2000\n[Peer]\nPublicKey=%s\nPresharedKey=%s\nEndpoint=%s:51820\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\n",80+i,i+1,key(byte(21+i)),80+i,public,key(byte(101+i)),endpoint)
  graph:=map[string]any{"inbounds":[]any{map[string]any{"type":"tun","tag":"tun-in","auto_route":true,"strict_route":true,"mtu":1280}},"outbounds":[]any{map[string]any{"type":"shadowsocks","tag":"proxy","server":endpoint,"server_port":443,"method":"2022-blake3-aes-256-gcm","password":key(byte(141+i))},map[string]any{"type":"direct","tag":"direct"}},"route":map[string]any{"auto_detect_interface":true,"final":"proxy","rules":[]any{map[string]any{"protocol":"dns","action":"hijack-dns"}}},"dns":map[string]any{"servers":[]any{map[string]any{"type":"udp","tag":"home-dns","server":fmt.Sprintf("10.%d.0.53",80+i),"detour":"proxy"}},"final":"home-dns"}}
  ss,e:=json.Marshal(graph);if e!=nil{return "",e}
  assets:=map[string]any{"wg":map[string]string{"wg.conf":base64.StdEncoding.EncodeToString([]byte(raw))},"shadowsocks":map[string]string{"sing-box.json":base64.StdEncoding.EncodeToString(ss)}}
  for _,mode:=range []string{"awg2-fast","awg2-strong"}{
   jc:=3;if mode=="awg2-strong"{jc=8}
   parameters:=fmt.Sprintf("[Interface]\nJc=%d\nJmin=40\nJmax=900\nS1=56\nS2=48\nS3=24\nS4=32\nH1=10000000-19999999\nH2=20000000-29999999\nH3=30000000-39999999\nH4=40000000-49999999\n",jc)
   awgServer,e:=ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{byte(181+i)},32));if e!=nil{return "",e}
   awgPublic:=base64.StdEncoding.EncodeToString(awgServer.PublicKey().Bytes())
   awg:=strings.Replace(raw,"[Interface]\n",parameters,1)
   awg=strings.Replace(awg,"PrivateKey="+key(byte(21+i)),"PrivateKey="+key(byte(161+i)),1)
   awg=strings.Replace(awg,"PublicKey="+public,"PublicKey="+awgPublic,1)
   assets[mode]=map[string]string{"awg.conf":base64.StdEncoding.EncodeToString([]byte(awg))}
  }
  if i==count-1{profile["multihop_enabled"]=true;profile["multihop_execution"]="local";profile["multihop_nodes"]=selection}
  bundles=append(bundles,map[string]any{"selectedRouterID":id,"routerProfiles":[]any{profile},"profiles":assets})
 }
 encoded,e:=json.Marshal(bundles);return string(encoded),e
}
'''

LIBBOX = P.SWIFT[:P.SWIFT.index('func compile(')]
LIBBOX += r'''
public final class LibboxRouterNodeChain {
 private let receipt:[String:String]
 init(_ receipt:[String:String]){self.receipt=receipt}
 public func config()->String{receipt["config"]!}
 public func sourceSHA256()->String{receipt["source"]!}
 public func configSHA256()->String{receipt["config_sha"]!}
 // Match the generated gomobile NSErrorPointer ABI; this method is not
 // imported as a Swift throwing method by the real Apple framework.
 public func launchInput(_ error:UnsafeMutablePointer<NSError?>?)->String{
  if NativeLaunchFault.shared.active{error?.pointee=NSError(domain:"LaunchInputFixture",code:1)}
  return receipt["launch"]!
 }
 public func close()throws{}
}
private final class NativeLaunchFault: @unchecked Sendable {
 static let shared=NativeLaunchFault();private let lock=NSLock();private var failed=false
 var active:Bool{lock.lock();defer{lock.unlock()};return failed}
 func set(_ failed:Bool){lock.lock();self.failed=failed;lock.unlock()}
}
public func LibboxTestLaunchFailure(_ failed:Bool){NativeLaunchFault.shared.set(failed)}
func api<T>(_ error:UnsafeMutablePointer<NSError?>?,_ action:()throws->T)->T?{
 do{return try action()}catch let caught{error?.pointee=caught as NSError;return nil}
}
public func LibboxRouterNodeChainMemberInput(_ mode:String,_ files:String,_ profile:String,_ start:String,_ bootstrap:String,_ error:UnsafeMutablePointer<NSError?>?)->String?{
 api(error){try bridge(["Op":"chain-member","Mode":mode,"Files":files,"Policy":profile,"Source":start,"Node":bootstrap])}
}
func make(_ operation:String,_ source:String)throws->LibboxRouterNodeChain{
 let response=try bridge(["Op":operation,"Source":source])
 guard let value=try JSONSerialization.jsonObject(with:Data(response.utf8)) as? [String:String]else{throw NSError(domain:"FixtureReceipt",code:1)}
 return LibboxRouterNodeChain(value)
}
public func LibboxNewRouterNodeChain(_ source:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChain?{api(error){try make("chain-new",source)}}
public func LibboxNewRouterNodeChainLaunch(_ source:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChain?{api(error){try make("chain-open",source)}}
public func LibboxTestFixture(_ count:Int,_ layer:String)throws->String{try bridge(["Op":"chain-fixture","Mode":String(count),"Policy":layer])}
public func LibboxTestAWGFixture(_ count:Int,_ layer:String)throws->String{try bridge(["Op":"chain-awg-fixture","Mode":String(count),"Policy":layer])}
public func LibboxTestProjection(_ launch:String,_ target:String)throws->String{
 let raw=try bridge(["Op":"chain-project","Source":launch,"Mode":target])
 return try object(Data(raw.utf8))["launch"] as! String
}
public func LibboxTestClose(){TestCompiler.shared.close()}
'''

SWIFT = r'''
import Foundation
import Libbox
func data(_ value:Any)throws->Data{try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
func object(_ value:Data)throws->[String:Any]{try JSONSerialization.jsonObject(with:value) as! [String:Any]}
func profile(_ bundle:Data)throws->[String:Any]{(try object(bundle)["routerProfiles"] as! [[String:Any]])[0]}
func sources(_ count:Int,_ layer:String="off",_ mixed:Bool=false)throws->[Data]{
 let value=try mixed ? LibboxTestAWGFixture(count,layer):LibboxTestFixture(count,layer)
 return try (JSONSerialization.jsonObject(with:Data(value.utf8)) as! [Any]).map{try data($0)}
}
func edit(_ original:Data,_ action:(inout [String:Any])->Void)throws->Data{var value=try object(original);action(&value);return try data(value)}
func editProfile(_ original:Data,_ action:(inout [String:Any])->Void)throws->Data{
 try edit(original){root in var profiles=root["routerProfiles"] as! [[String:Any]];action(&profiles[0]);root["routerProfiles"]=profiles}
}
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ value:@autoclosure ()throws->Bool)throws{guard try value()else{throw NSError(domain:"ChainCheck",code:1,userInfo:[NSLocalizedDescriptionKey:name])};checks+=1}
 static func reject(_ name:String,_ action:()throws->Void)throws{do{try action()}catch{checks+=1;return};throw NSError(domain:"ChainRejected",code:1,userInfo:[NSLocalizedDescriptionKey:"ACCEPTED "+name])}
 static func main(){defer{LibboxTestClose()};do{try run();print("Apple ordered native capture: PASS (\(checks) shipping Swift / shared Go checks; no native connection)")}
 catch{FileHandle.standardError.write(Data(("FAIL after \(checks): \(error.localizedDescription)\n").utf8));exit(1)}}
 static func run()throws {
  for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   let bundles=try sources(4,layer,true),capture=try IOSNodeChainCapture.compile(bundles:bundles)
   defer{try? capture.plan.close()}
   try check("mixed packet modes stay exact",capture.members.map(\.mode)==["awg2-fast","awg2-strong","wg","shadowsocks"])
   let graph=try object(Data(capture.config.utf8)),endpoints=graph["endpoints"] as! [[String:Any]],awg=endpoints.filter{$0["type"] as? String=="routervpn-amneziawg"}
   try check("both AWG endpoints preserve distinct packet parameters",awg.count==2 && (awg[0]["amnezia"] as? [String:String])?["jc"]=="3" && (awg[1]["amnezia"] as? [String:String])?["jc"]=="8" && (awg[1]["amnezia"] as? [String:String])?["s4"]=="32")
   let restored=try IOSNodeChainCapture.reopen(capture.launchInput,selectedProfile:profile(bundles.last!));defer{try? restored.plan.close()}
   try check("mixed packet restoration keeps complete original source",restored.sourceSHA256==capture.sourceSHA256 && restored.config==capture.config && restored.members.map(\.mode)==capture.members.map(\.mode))
   var broken=bundles
   broken[1]=try edit(broken[1]){root in var assets=root["profiles"] as! [String:[String:String]];assets["awg2-strong"]!["awg.conf"]=Data("[Interface]\\nPrivateKey=missing\\n".utf8).base64EncodedString();root["profiles"]=assets}
   try reject("malformed selected AWG cannot borrow WG or Fast assets"){_ = try IOSNodeChainCapture.compile(bundles:broken)}
  }
  for count in [2,3,4,8] {for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   if count==8 && layer != "off" {
    try reject("deep layered chain retains minimum packet budget"){_ = try IOSNodeChainCapture.compile(bundles:sources(count,layer))}
    continue
   }
   let bundles=try sources(count,layer),captured=try IOSNodeChainCapture.compile(bundles:bundles)
   defer{try? captured.plan.close()}
   try check("exact ordered source",captured.members.map(\.id)==(0..<count).map{"chain-node-\($0)"} && captured.members.last?.mode=="shadowsocks")
   try check("all selected protection policies survive",captured.strict && !captured.homeLANAccess)
   try check("configured capture is not live proof",captured.startupTimeout==TimeInterval(25+10*count))
   for (position,member) in captured.members.enumerated(){try check("private member policy unchanged",try data(member.profile)==data(profile(bundles[position])))}
   let resumed=try IOSNodeChainCapture.reopen(captured.launchInput,selectedProfile:profile(bundles.last!))
   defer{try? resumed.plan.close()}
   try check("one exact native graph survives transfer",resumed.config==captured.config && resumed.sourceSHA256==captured.sourceSHA256 && resumed.configSHA256==captured.configSHA256)
   let graph=try object(Data(captured.config.utf8)),tun=graph["inbounds"] as! [[String:Any]]
   try check("single original TUN ignores historical effective MTU",tun.count==1 && tun[0]["type"] as? String=="tun" && tun[0]["mtu"] as? Int==1280)
   if count==3 && layer=="off" {
    let provider:[String:Any]=["engine":"multihop-libbox","mode":"shadowsocks","rawProfileID":"shadowsocks","modeCandidates":["shadowsocks"],"bundle":bundles.last!,IOSNodeChainProviderCapture.key:captured.launchInput]
    let handed=try IOSNodeChainProviderCapture.reopen(provider);defer{try? handed.plan.close()}
    try check("private provider reruns exact native source",handed.config==captured.config && handed.sourceSHA256==captured.sourceSHA256)
    for fault in ["mixed-entry","mixed-strategy","foreign-engine","missing-source","wrong-final-mode","fallback-candidate","stale final assets"] {
     var changed=provider
     switch fault {
     case "mixed-entry":changed["entryBundle"]=bundles[0]
     case "mixed-strategy":changed["strategy"]="smart"
     case "foreign-engine":changed["engine"]="libbox"
     case "missing-source":changed.removeValue(forKey:IOSNodeChainProviderCapture.key)
     case "wrong-final-mode":changed["rawProfileID"]="wg"
     case "fallback-candidate":changed["modeCandidates"]=["shadowsocks","wg"]
     case "stale final assets":changed["bundle"]=try edit(bundles.last!){var assets=$0["profiles"] as! [String:[String:String]];assets["shadowsocks"]!["sing-box.json"]=Data("replacement asset".utf8).base64EncodedString();$0["profiles"]=assets}
     default:fatalError()
     }
     try reject("provider "+fault){_ = try IOSNodeChainProviderCapture.reopen(changed)}
    }
    var replaced=try profile(bundles.last!);replaced["api_token"]="replacement-final-secret"
    try reject("replaced final control"){_ = try IOSNodeChainCapture.reopen(captured.launchInput,selectedProfile:replaced)}
    for target in ["darwin","linux","windows","ios","android"] {
     let projected=try LibboxTestProjection(captured.launchInput,target)
     try reject("foreign or unstaged platform projection "+target){_ = try IOSNodeChainCapture.reopen(projected,selectedProfile:profile(bundles.last!))}
    }
   }
  }}
  let original=try sources(4)
  LibboxTestLaunchFailure(true)
  try reject("native launch error cannot return usable source"){
   _ = try IOSNodeChainCapture.compile(bundles:original)
  }
  LibboxTestLaunchFailure(false)
  for fault in ["missing-middle","swapped-middle","duplicate-proof","missing-assets","duplicate-profile","foreign-kind","wrong-mode","implicit-execution","server","disabled","number-enabled","mixed-pair","extra-selection-key","different-control","final-order","missing-layer","unsupported-family","malformed-bootstrap","hostname-middle"] {
   var changed=original
   switch fault {
   case "missing-middle":changed.remove(at:1)
   case "swapped-middle":changed.swapAt(0,1)
   case "duplicate-proof":let other=try profile(changed[0]);changed[1]=try editProfile(changed[1]){$0["node_proof_id"]=other["node_proof_id"]}
   case "missing-assets":changed[1]=try edit(changed[1]){$0["profiles"]=[: ] as [String:String]}
   case "duplicate-profile":changed[1]=try edit(changed[1]){var profiles=$0["routerProfiles"] as! [[String:Any]];profiles.append(profiles[0]);$0["routerProfiles"]=profiles}
   case "foreign-kind":changed[1]=try editProfile(changed[1]){$0["node_kind"]="external"}
   case "wrong-mode":changed[3]=try editProfile(changed[3]){var nodes=$0["multihop_nodes"] as! [[String:Any]];nodes[1]["mode"]="shadowsocks";$0["multihop_nodes"]=nodes}
   case "implicit-execution":changed[3]=try editProfile(changed[3]){$0.removeValue(forKey:"multihop_execution")}
   case "server":changed[3]=try editProfile(changed[3]){$0["multihop_execution"]="server"}
   case "disabled":changed[3]=try editProfile(changed[3]){$0["multihop_enabled"]=false}
   case "number-enabled":changed[3]=try editProfile(changed[3]){$0["multihop_enabled"]=1}
   case "mixed-pair":changed[3]=try editProfile(changed[3]){$0["multihop_entry_id"]="chain-node-0"}
   case "extra-selection-key":changed[3]=try editProfile(changed[3]){var nodes=$0["multihop_nodes"] as! [[String:Any]];nodes[1]["borrowed_source"]="no";$0["multihop_nodes"]=nodes}
   case "different-control":changed[3]=try edit(changed[3]){$0["selectedRouterID"]="chain-node-0"}
   case "final-order":changed[3]=try editProfile(changed[3]){var nodes=$0["multihop_nodes"] as! [[String:Any]];nodes.swapAt(0,1);$0["multihop_nodes"]=nodes}
   case "missing-layer":changed[1]=try editProfile(changed[1]){$0["start_layer"]="aes-256-gcm"};changed[1]=try edit(changed[1]){var assets=$0["profiles"] as! [String:Any];assets.removeValue(forKey:"shadowsocks");$0["profiles"]=assets}
   case "unsupported-family":changed[3]=try editProfile(changed[3]){var nodes=$0["multihop_nodes"] as! [[String:Any]];nodes[1]["mode"]="shadowsocks";$0["multihop_nodes"]=nodes}
   case "malformed-bootstrap":changed[1]=try editProfile(changed[1]){$0["dns_bootstrap"]=true}
   case "hostname-middle":changed[1]=try edit(changed[1]){var assets=$0["profiles"] as! [String:[String:String]];let raw=String(decoding:Data(base64Encoded:assets["wg"]!["wg.conf"]!)!,as:UTF8.self);assets["wg"]!["wg.conf"]=Data(raw.replacingOccurrences(of:"198.51.100.11:51820",with:"middle.example.test:51820").utf8).base64EncodedString();$0["profiles"]=assets}
   default:fatalError()
   }
   try reject(fault){_ = try IOSNodeChainCapture.compile(bundles:changed)}
  }
  try reject("one-node chain"){_ = try IOSNodeChainCapture.compile(bundles:[original[0]])}
  try reject("nine-node chain"){_ = try IOSNodeChainCapture.compile(bundles:Array(repeating:original[0],count:9))}
  try reject("oversized private transfer"){_ = try IOSNodeChainCapture.reopen(String(repeating:" ",count:IOSNodeChainCapture.maximumInputBytes+1),selectedProfile:profile(original.last!))}
 }
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='.ios-chain-compiler-', dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix='ios-chain-capture-') as directory:
        go_dir, work = Path(go_dir), Path(directory)
        (go_dir / 'main.go').write_text(GO)
        compiler = work / 'compiler'
        subprocess.run(['go', 'build', '-p', '1', '-o', str(compiler), str(go_dir / 'main.go')], cwd=ROOT, check=True, timeout=180)
        stub, tests = work / 'Libbox.swift', work / 'Tests.swift'
        stub.write_text(LIBBOX); tests.write_text(SWIFT)
        options = ['swiftc', '-j', '1', '-swift-version', '6', '-module-cache-path', str(work / 'modules')]
        library = work / ('libLibbox.dylib' if platform.system() == 'Darwin' else 'libLibbox.so')
        subprocess.run(options + ['-emit-module', '-emit-library', '-module-name', 'Libbox', str(stub), '-emit-module-path', str(work / 'Libbox.swiftmodule'), '-o', str(library)], check=True, timeout=90)
        command = options + ['-I', str(work), '-L', str(work), '-lLibbox', '-Xlinker', '-rpath', '-Xlinker', str(work), str(APP / 'IOSMultihopStartLayer.swift')]
        provider = APP / 'IOSNodeChainProviderCapture.swift'
        source = APP / 'IOSNodeChainCapture.swift'
        binary = work / 'tests'
        subprocess.run(command + [str(source), str(provider), str(tests), '-o', str(binary)], check=True, timeout=90)
        subprocess.run([str(binary), str(compiler)], check=True, timeout=180)
        text = source.read_text()
        for name, before, after, failure in (
            ('native-launch-error', 'guard failure == nil, let launch = returned, !launch.isEmpty else {', 'guard let launch = returned, !launch.isEmpty else {', 'ACCEPTED native launch error cannot return usable source'),
            ('final-profile-bound', 'try json(selectedProfile, maximum: 256 * 1024) == json(capture.finalProfile, maximum: 256 * 1024)', 'true', 'ACCEPTED replaced final control'),
            ('mobile-projection-bound', 'root["projection_kind"] == nil, root["session_id"] == nil, root["target_os"] == nil, root["restored_mtu"] == nil,', 'true,', 'ACCEPTED foreign or unstaged platform projection'),
        ):
            assert text.count(before) == 1, name
            mutated = work / (name + '.swift'); mutated.write_text(text.replace(before, after, 1))
            executable = work / name
            subprocess.run(command + [str(mutated), str(provider), str(tests), '-o', str(executable)], check=True, timeout=90)
            failed = subprocess.run([str(executable), str(compiler)], capture_output=True, text=True, timeout=180)
            assert failed.returncode != 0 and failure in failed.stdout + failed.stderr, name + ': missing causal refusal: ' + (failed.stdout + failed.stderr)[-1000:]
            print('Rejected ordered-source defect mutation: ' + name)
        provider_text=provider.read_text();before='              selectedFiles == originalFiles else {'
        assert provider_text.count(before)==1
        changed=work/'ProviderAssetMutation.swift';changed.write_text(provider_text.replace(before,'              true else {',1))
        executable=work/'provider-assets'
        subprocess.run(command+[str(source),str(changed),str(tests),'-o',str(executable)],check=True,timeout=90)
        failed=subprocess.run([str(executable),str(compiler)],capture_output=True,text=True,timeout=180)
        assert failed.returncode != 0 and 'ACCEPTED provider stale final assets' in failed.stdout+failed.stderr,'Provider assets were not bound to the original compiled source'
        print('Rejected ordered-source defect mutation: provider-final-assets')


if __name__ == '__main__':
    main()
