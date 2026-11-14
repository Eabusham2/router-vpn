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

GO = P.GO.replace('"crypto/sha256"', '"crypto/sha256";"crypto/ecdh";"crypto/ed25519";"crypto/rand";"crypto/x509";"crypto/x509/pkix";"encoding/pem";"math/big";"strconv";"time";"router-vpn/internal/nativecomposite"', 1)
anchor = ' case "compile":value,err=mobilemultihop.CompilePQProfile(r.Mode,r.Files,r.Node)'
assert GO.count(anchor) == 1
GO = GO.replace(anchor, r'''
 case "chain-fixture":var count int;count,err=strconv.Atoi(r.Mode);if err==nil{value,err=chainFixture(count,r.Policy)}
 case "chain-socks-fixture":value,err=chainSOCKSFixture()
 case "chain-connect-fixture":value,err=chainCONNECTFixture(r.Mode)
 case "chain-connect-service":value,err=chainCONNECTService(r.Source)
 case "chain-awg-fixture":var count int;count,err=strconv.Atoi(r.Mode);if err==nil{value,err=chainFixtureModes(count,r.Policy,true)}
 case "chain-hysteria-fixture":var count int;count,err=strconv.Atoi(r.Node);if err==nil{value,err=chainHysteriaFixture(count,r.Mode,r.Policy)}
 case "chain-execution":_,err=mobilemultihop.NewNodeChainExecutionPreparation(r.Source,r.Mode)
 case "chain-candidate-supported":value=strconv.FormatBool(mobilemultihop.NodeChainCandidateInputSupported(r.Source))
 case "chain-imported":value,err=mobilemultihop.NodeChainImportedMemberInput(r.Source,r.Policy)
 case "chain-socks-imported":value,err=mobilemultihop.NodeChainImportedSOCKSMemberInput(r.Source,r.Policy)
 case "chain-socks-new":
  var source *mobilemultihop.NodeChainSOCKSSource;source,err=mobilemultihop.NewNodeChainSOCKSSource(r.Source)
  if err==nil{var config,input string;var meta mobilemultihop.NodeChainSOCKSSourceMetadata;config,meta,err=source.ReadValidated();if err==nil{input,err=source.Source()};if err==nil{var metadata,encoded []byte;metadata,err=json.Marshal(meta);if err==nil{encoded,err=json.Marshal(map[string]string{"source":input,"config":config,"metadata":string(metadata),"source_sha":meta.SourceSHA256,"config_sha":meta.ConfigSHA256});value=string(encoded)}}}
 case "chain-connect-imported":value,err=mobilemultihop.NodeChainImportedCONNECTMemberInput(r.Source,r.Policy)
 case "chain-connect-new":
  var source *mobilemultihop.NodeChainCONNECTSource;source,err=mobilemultihop.NewNodeChainCONNECTSource(r.Source)
  if err==nil{var config,input string;var meta mobilemultihop.NodeChainCONNECTSourceMetadata;config,meta,err=source.ReadValidated();if err==nil{input,err=source.Source()};if err==nil{var metadata,encoded []byte;metadata,err=json.Marshal(meta);if err==nil{encoded,err=json.Marshal(map[string]string{"source":input,"config":config,"metadata":string(metadata),"source_sha":meta.SourceSHA256,"config_sha":meta.ConfigSHA256});value=string(encoded)}}}
 case "chain-ordinary":value,err=mobilemultihop.CompileExternalPolicy(r.Source,r.Policy)
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
// Source fixtures construct their own paired service declaration, exactly as
// the shared source tests do. This is no native service or readiness receipt.
func chainCONNECTService(raw string)(string,error){
 var bundle map[string]any;if err:=json.Unmarshal([]byte(raw),&bundle);err!=nil{return "",err}
 profile:=bundle["routerProfiles"].([]any)[0].(map[string]any)
 assets:=bundle["profiles"].(map[string]any)["shadowsocks"].(map[string]any)
 data,err:=base64.StdEncoding.DecodeString(assets["sing-box.json"].(string));if err!=nil{return "",err}
 var graph map[string]any;if err=json.Unmarshal(data,&graph);err!=nil{return "",err}
 out:=graph["outbounds"].([]any)[0].(map[string]any)
 sourceHash,keyHash:=sha256.Sum256(data),sha256.Sum256([]byte(out["password"].(string)))
 claim:=map[string]any{"schema":1,"node_id":profile["node_proof_id"],"configured_image":nativecomposite.SSServiceImage,"uot_version":2,"endpoint":out["server"],"port":out["server_port"],"method":out["method"],"source_sha256":hex.EncodeToString(sourceHash[:]),"key_sha256":hex.EncodeToString(keyHash[:])}
 encoded,err:=json.Marshal(claim);if err!=nil{return "",err};assets[nativecomposite.SSServiceAsset]=base64.StdEncoding.EncodeToString(encoded)
 result,err:=json.Marshal(bundle);return string(result),err
}
func chainCONNECTFixture(protocol string)(string,error){
 raw,err:=chainSOCKSFixture();if err!=nil{return "",err};var bundles []map[string]any
 if err=json.Unmarshal([]byte(raw),&bundles);err!=nil{return "",err}
 middle:=bundles[1]["routerProfiles"].([]any)[0].(map[string]any)
 external:=middle["external"].(map[string]any);credentials:=external["socks5"].(map[string]any);delete(external,"socks5")
 if protocol!="http-connect"&&protocol!="https-connect"{return "",fmt.Errorf("invalid CONNECT fixture protocol")}
 external["protocol"]=protocol;external[strings.ReplaceAll(protocol,"-","_")]=credentials
 if protocol=="https-connect"{credentials["tls_server_name"]="Original.Proxy.Example"}
 final:=bundles[2]["routerProfiles"].([]any)[0].(map[string]any);final["multihop_nodes"].([]any)[1].(map[string]any)["mode"]=protocol
 data,err:=json.Marshal(bundles[2]);if err!=nil{return "",err};source,err:=chainCONNECTService(string(data));if err!=nil{return "",err}
 if err=json.Unmarshal([]byte(source),&bundles[2]);err!=nil{return "",err}
 data,err=json.Marshal(bundles);return string(data),err
}
func chainSOCKSFixture()(string,error){
 raw,err:=chainFixture(3,"off");if err!=nil{return "",err};var bundles []map[string]any
 if err=json.Unmarshal([]byte(raw),&bundles);err!=nil{return "",err}
 middle:=bundles[1]["routerProfiles"].([]any)[0].(map[string]any)
 middle["node_kind"]="external";delete(middle,"node_proof_id");middle["router_api"]="";middle["api_token"]="";middle["endpoint"]="203.0.113.20"
 middle["external"]=map[string]any{"protocol":"socks5","expected_public_ip":"203.0.113.88","socks5":map[string]any{"host":"203.0.113.20","port":1080,"username":"saved user","password":"saved:password"}}
 bundles[1]["profiles"]=map[string]any{}
 final:=bundles[2]["routerProfiles"].([]any)[0].(map[string]any);final["multihop_nodes"].([]any)[1].(map[string]any)["mode"]="socks5"
 data,err:=json.Marshal(bundles);return string(data),err
}
func chainHysteriaFixture(count int,first,layer string)(string,error){
 raw,err:=chainFixtureModes(count,layer,true);if err!=nil{return "",err}
 var bundles []map[string]any;if err=json.Unmarshal([]byte(raw),&bundles);err!=nil{return "",err}
 final:=bundles[count-1]["routerProfiles"].([]any)[0].(map[string]any)
 selection:=final["multihop_nodes"].([]any);selection[0].(map[string]any)["mode"]=first
 selection[count-1].(map[string]any)["mode"]="hysteria2";final["start_layer"]="off"
 encoded,err:=json.Marshal(bundles);return string(encoded),err
}
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
  private:=ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(41+i)},ed25519.SeedSize))
  cert:=&x509.Certificate{SerialNumber:big.NewInt(int64(i+1)),Subject:pkix.Name{CommonName:"ordered-final.example.test"},DNSNames:[]string{"ordered-final.example.test"},NotBefore:time.Unix(1577836800,0),NotAfter:time.Unix(2051222400,0),KeyUsage:x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,IsCA:true,BasicConstraintsValid:true}
  der,e:=x509.CreateCertificate(rand.Reader,cert,cert,private.Public(),private);if e!=nil{return "",e}
  certificate:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})
  graph["outbounds"].([]any)[0]=map[string]any{"type":"hysteria2","tag":"proxy","server":endpoint,"server_port":8443,"password":fmt.Sprintf("original-hy2-password-%d",i),"obfs":map[string]any{"type":"salamander","password":fmt.Sprintf("original-hy2-salamander-%d",i)},"tls":map[string]any{"enabled":true,"server_name":"ordered-final.example.test","certificate_path":"hy2-ca.pem"}}
  hy2,e:=json.Marshal(graph);if e!=nil{return "",e}
  assets["hysteria2"]=map[string]string{"sing-box.json":base64.StdEncoding.EncodeToString(hy2),"hy2-ca.pem":base64.StdEncoding.EncodeToString(certificate)}
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
public func LibboxRouterNodeChainImportedMemberInput(_ config:String,_ capture:String,_ error:UnsafeMutablePointer<NSError?>?)->String?{
 api(error){try bridge(["Op":"chain-imported","Source":config,"Policy":capture])}
}
public final class LibboxRouterNodeChainSOCKS {
 private let receipt:[String:String]
 init(_ receipt:[String:String]){self.receipt=receipt}
 public func source(_ error:UnsafeMutablePointer<NSError?>?)->String{receipt["source"]!}
 public func config(_ error:UnsafeMutablePointer<NSError?>?)->String{receipt["config"]!}
 public func sourceSHA256()->String{receipt["source_sha"]!}
 public func configSHA256()->String{receipt["config_sha"]!}
 public func metadata()->String{receipt["metadata"]!}
 public func close()throws{}
}
public func LibboxRouterNodeChainImportedSOCKSMemberInput(_ config:String,_ capture:String,_ error:UnsafeMutablePointer<NSError?>?)->String?{
 api(error){try bridge(["Op":"chain-socks-imported","Source":config,"Policy":capture])}
}
public func LibboxNewRouterNodeChainSOCKS(_ source:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainSOCKS?{
 api(error){let raw=try bridge(["Op":"chain-socks-new","Source":source]);return LibboxRouterNodeChainSOCKS(try JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [String:String])}
}
public final class LibboxRouterNodeChainCONNECT {
 private let receipt:[String:String]
 init(_ receipt:[String:String]){self.receipt=receipt}
 public func source(_ error:UnsafeMutablePointer<NSError?>?)->String{receipt["source"]!}
 public func config(_ error:UnsafeMutablePointer<NSError?>?)->String{receipt["config"]!}
 public func sourceSHA256()->String{receipt["source_sha"]!}
 public func configSHA256()->String{receipt["config_sha"]!}
 public func metadata()->String{receipt["metadata"]!}
 public func close()throws{}
}
public func LibboxRouterNodeChainImportedCONNECTMemberInput(_ config:String,_ capture:String,_ error:UnsafeMutablePointer<NSError?>?)->String?{
 api(error){try bridge(["Op":"chain-connect-imported","Source":config,"Policy":capture])}
}
public func LibboxNewRouterNodeChainCONNECT(_ source:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainCONNECT?{
 api(error){let raw=try bridge(["Op":"chain-connect-new","Source":source]);return LibboxRouterNodeChainCONNECT(try JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [String:String])}
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
public func LibboxRouterNodeChainLaunch(_ source:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChain?{api(error){try make("chain-open",source)}}
public func LibboxTestFixture(_ count:Int,_ layer:String)throws->String{try bridge(["Op":"chain-fixture","Mode":String(count),"Policy":layer])}
public func LibboxTestSOCKSFixture()throws->String{try bridge(["Op":"chain-socks-fixture"])}
public func LibboxTestCONNECTFixture()throws->String{try bridge(["Op":"chain-connect-fixture","Mode":"https-connect"])}
public func LibboxTestCONNECTService(_ source:String)throws->String{try bridge(["Op":"chain-connect-service","Source":source])}
public func LibboxTestAWGFixture(_ count:Int,_ layer:String)throws->String{try bridge(["Op":"chain-awg-fixture","Mode":String(count),"Policy":layer])}
public func LibboxTestHysteriaFixture(_ count:Int,_ first:String,_ layer:String="off")throws->String{try bridge(["Op":"chain-hysteria-fixture","Node":String(count),"Mode":first,"Policy":layer])}
public func LibboxTestChainExecution(_ source:String,_ mode:String)throws{_ = try bridge(["Op":"chain-execution","Source":source,"Mode":mode])}
public func LibboxTestCandidateSupported(_ input:String)throws->Bool{try bridge(["Op":"chain-candidate-supported","Source":input]) == "true"}
public func LibboxTestProjection(_ launch:String,_ target:String)throws->String{
 let raw=try bridge(["Op":"chain-project","Source":launch,"Mode":target])
 return try object(Data(raw.utf8))["launch"] as! String
}
public func LibboxTestClose(){TestCompiler.shared.close()}
public func LibboxTestOrdinarySource(_ config:String,_ capture:String)throws->String {
 try bridge(["Op":"chain-ordinary","Source":config,"Policy":capture])
}
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
  try socksMiddle()

  try hostnameMiddle()

  for (method,keySize) in [("2022-blake3-aes-128-gcm",16),("2022-blake3-aes-256-gcm",32),("2022-blake3-chacha20-poly1305",32)] {
  var imported = try sources(3)
  var middle = try object(imported[1]), custom = try profile(imported[1])
  custom["id"]="original-custom-middle";custom["name"]="Original custom middle";custom["node_kind"]="external";custom.removeValue(forKey:"node_proof_id")
  for key in ["router_api","api_token","adguard_ipv6","socks_host","socks_username","socks_password"] { custom[key]="" }
  custom["socks_port"]=0
  custom["external"]=["protocol":"shadowsocks","expected_public_ip":"203.0.113.76","shadowsocks":["server":"198.51.100.76","port":443,"method":method,"password":Data(repeating:0,count:keySize).base64EncodedString()]]
  middle["selectedRouterID"]="original-custom-middle";middle["routerProfiles"]=[custom];middle["profiles"]=[String:[String:String]]()
  imported[1]=try data(middle)
  imported[2]=try editProfile(imported[2]) { final in var refs=final["multihop_nodes"] as! [[String:Any]];refs[1]=["id":"original-custom-middle","mode":"shadowsocks"];final["multihop_nodes"]=refs }
  let complete = try IOSNodeChainCapture.compile(bundles:imported);defer{try? complete.plan.close()}
  let receipt=try object(Data(complete.launchInput.utf8))
  try check("custom middle keeps external source and empty paired identity",receipt["schema"] as? Int == 2 && (receipt["identity_sources"] as? [String])?[1] == "" && complete.members[1].profile["node_kind"] as? String == "external" && complete.members[1].profile["node_proof_id"] == nil)
  let reopened = try IOSNodeChainCapture.reopen(complete.launchInput,selectedProfile:profile(imported[2]));defer{try? reopened.plan.close()}
  try check("typed external original source replays",reopened.launchInput == complete.launchInput)
  let actualExternal=complete.members[1].profile["external"] as! [String:Any], actualSS=actualExternal["shadowsocks"] as! [String:Any]
  try check("native source retains exact cipher and original PSK",actualSS["method"] as? String == method && actualSS["password"] as? String == Data(repeating:0,count:keySize).base64EncodedString())
  var wrongFinal=imported
  wrongFinal[2]=try editProfile(wrongFinal[2]) { p in var refs=p["multihop_nodes"] as! [[String:Any]];refs[2]["mode"]="hysteria2";p["multihop_nodes"]=refs }
  try reject("imported schema2 retains SS-only final"){_ = try IOSNodeChainCapture.compile(bundles:wrongFinal)}
  for fault in ["private-token","proof","hostname","legacy","layer"] {
   var changed=imported
   changed[1]=try editProfile(changed[1]) { p in
    if fault=="private-token" {p["api_token"]="borrowed-private-token"}
    if fault=="proof" {p["node_proof_id"]=String(repeating:"a",count:64)}
    if fault=="layer" {p["start_layer"]="aes-256-gcm"}
    if fault=="hostname" || fault=="legacy" {var ext=p["external"] as! [String:Any];var ss=ext["shadowsocks"] as! [String:Any];ss[fault=="hostname" ? "server":"method"]=fault=="hostname" ? "example.com":"aes-256-gcm";ext["shadowsocks"]=ss;p["external"]=ext}
   }
   try reject("custom intermediate "+fault){_ = try IOSNodeChainCapture.compile(bundles:changed)}
  }
  let typed=try JSONDecoder().decode(RouterProfile.self,from:JSONSerialization.data(withJSONObject:custom))
  try check("supported custom cipher offered \(method)",IOSImportedShadowsocksSource.eligible(typed))
  for password in [Data(repeating:0,count:keySize == 16 ? 32 : 16).base64EncodedString(),Data(repeating:0,count:keySize+1).base64EncodedString(),Data(repeating:0,count:keySize).base64EncodedString().replacingOccurrences(of:"=",with:""),Data(repeating:0,count:keySize).base64EncodedString()+":"+Data(repeating:0,count:keySize).base64EncodedString(),"invalid!"] {
   var changed=typed;changed.external?.shadowsocks?.password=password
   try check("noncanonical or wrong-length PSK excluded \(method)",!IOSImportedShadowsocksSource.eligible(changed))
  }
  for host in [":","2001:db8:::1","2001:db8::1::2","[2001:db8::1]","fe80::1%en0","192.168.001.1","01.2.3.4","1.2.3.00","+1.2.3.4","-1.2.3.4","256.2.3.4","1.2.3","1.2.3.4.5","1..3.4","1.2.3.4 ","::ffff:192.168.001.1","198.51.100.76\u{0}other"] {
   var changed=typed;changed.external?.shadowsocks?.server=host
   try check("malformed literal excluded \(host)",!IOSImportedShadowsocksSource.eligible(changed))
   changed.endpoint=host;changed.dnsMode="custom";changed.dnsProtocol="tcp";changed.dnsHost="10.81.0.53";changed.dnsPort=5353
   try check("malformed literal cannot borrow selected hostname resolver \(host)",!IOSImportedShadowsocksSource.eligible(changed))
  }
  for host in ["0.0.0.0","255.255.255.255","192.168.1.1","2001:db8::76","2001:0DB8:0000:0000:0000:0000:0000:0076","::ffff:192.168.1.1"] {
   var changed=typed;changed.external?.shadowsocks?.server=host
   try check("valid literal source offered \(host)",IOSImportedShadowsocksSource.eligible(changed))
   try check("valid literal cannot become hostname transport \(host)",!IOSImportedShadowsocksSource.hasHostnameTransport(changed))
  }
  }
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
  try hysteriaFinal()
 }
 static func hysteriaFinal()throws {
  for mode in ["wg","awg2-fast","awg2-strong"] { for prefixLayer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   let raw=try LibboxTestHysteriaFixture(3,mode,prefixLayer)
   let bundles=try (JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [Any]).map{try data($0)}
   let capture=try IOSNodeChainCapture.compile(bundles:bundles);defer{try? capture.plan.close()}
   let final=capture.members.last!,originalFiles=try object(Data(final.filesJSON.utf8))
   let graph=try object(Data(capture.config.utf8)),outbounds=graph["outbounds"] as! [[String:Any]],hy2=outbounds.first{$0["type"] as? String=="hysteria2"}!
   let original=try object(Data(base64Encoded:originalFiles["sing-box.json"] as! String)!),native=(original["outbounds"] as! [[String:Any]])[0]
   try check("HY2 native password and Salamander stay original",hy2["password"] as? String==native["password"] as? String && NSDictionary(dictionary:hy2["obfs"] as! [String:Any]).isEqual(to:native["obfs"] as! [String:Any]))
   let tls=hy2["tls"] as! [String:Any],ca=String(decoding:Data(base64Encoded:originalFiles["hy2-ca.pem"] as! String)!,as:UTF8.self)
   try check("HY2 original TLS trust and name retained",tls["server_name"] as? String=="ordered-final.example.test" && tls["certificate"] as? [String]==[ca] && tls["insecure"] as? Bool != true)
   try check("HY2 keeps selected prefix modes and one TUN",capture.members.first?.mode==mode && final.mode=="hysteria2" && (graph["inbounds"] as! [Any]).count==1)
   let provider:[String:Any]=["engine":"multihop-libbox","mode":"hysteria2","rawProfileID":"hysteria2","modeCandidates":["hysteria2"],"bundle":bundles.last!,IOSNodeChainProviderCapture.key:capture.launchInput]
   let reopened=try IOSNodeChainProviderCapture.reopen(provider);defer{try? reopened.plan.close()}
   try check("HY2 provider reproduces entire original source",reopened.launchInput==capture.launchInput && reopened.config==capture.config && reopened.members.last?.profileJSON==final.profileJSON)
   for fault in ["raw-mode","candidate-mode","changed-ca"] {
    var changed=provider
    if fault=="raw-mode" {changed["rawProfileID"]="shadowsocks"}
    if fault=="candidate-mode" {changed["modeCandidates"]=["shadowsocks"]}
    if fault=="changed-ca" {changed["bundle"]=try edit(bundles.last!){var assets=$0["profiles"] as! [String:[String:String]];assets["hysteria2"]!["hy2-ca.pem"]=Data("different original CA".utf8).base64EncodedString();$0["profiles"]=assets}}
    try reject("HY2 provider "+fault){_ = try IOSNodeChainProviderCapture.reopen(changed)}
   }
   let record=try object(Data(capture.launchInput.utf8)),last=(record["nodes"] as! [String]).last!
   try check("UDP-only HY2 stays excluded from TCP candidate targets",try !LibboxTestCandidateSupported(last))
   for execution in ["server","auto"] {try reject("HY2 remains Local-only "+execution){try LibboxTestChainExecution(capture.originalSource!,execution)}}
   for layer in ["aes-256-gcm","aes-256-gcm+xor-whitening"] {
    var changed=bundles;changed[2]=try editProfile(changed[2]){$0["start_layer"]=layer}
    try reject("HY2 final layer "+layer){_ = try IOSNodeChainCapture.compile(bundles:changed)}
   }
  }}
 }
 static func socksMiddle()throws {
  for mode in ["wg","awg2-fast","awg2-strong"] {for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   var bundles=try sources(3,layer,true)
   for position in bundles.indices {
    bundles[position]=try editProfile(bundles[position]){p in
     p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""
    }
   }
   let originalMiddle=try profile(bundles[1]),id="saved-socks-middle"
   var middle=originalMiddle
   middle["id"]=id;middle["node_kind"]="external";middle.removeValue(forKey:"node_proof_id")
   middle["router_api"]="";middle["api_token"]="";middle["endpoint"]="203.0.113.20";middle["start_layer"]="off"
   middle["home_lan_access"]=false;middle["kill_switch_policy"]="always"
   middle["external"]=["protocol":"socks5","expected_public_ip":"203.0.113.88","socks5":["host":"203.0.113.20","port":1080,"username":"saved user","password":"saved:password"]] as [String:Any]
   bundles[1]=try data(["selectedRouterID":id,"routerProfiles":[middle],"profiles":[String:[String:String]]()])
   bundles[2]=try editProfile(bundles[2]){p in var nodes=p["multihop_nodes"] as! [[String:Any]];nodes[0]["mode"]=mode;nodes[1]=["id":id,"mode":"socks5"];p["multihop_nodes"]=nodes}
   let capture=try IOSNodeChainSOCKSCapture.compile(bundles:bundles);defer{try? capture.plan.close()}
   let source=try object(Data(capture.source.utf8)),graph=try object(Data(capture.config.utf8))
   try check("typed SOCKS source schema",source["schema"] as? Int==3 && source["kind"]==nil && (source["identity_sources"] as? [String])?[1]=="")
   try check("typed SOCKS device policy",capture.strict && !capture.homeLANAccess && capture.members[0].mode==mode && capture.members[1].mode=="socks5")
   let out=(graph["outbounds"] as! [[String:Any]]).first{$0["type"] as? String=="socks"}!
   try check("typed SOCKS original credentials and detour",out["username"] as? String=="saved user" && out["password"] as? String=="saved:password" && out["server"] as? String=="203.0.113.20" && out["detour"] is String)
   try check("typed SOCKS single original TUN",(graph["inbounds"] as! [Any]).count==1)
   let replay=try IOSNodeChainSOCKSCapture.reopen(capture.source,selectedProfile:profile(bundles[2]));defer{try? replay.plan.close()}
   try check("typed SOCKS exact replay",replay.source==capture.source && replay.config==capture.config)
   try reject("SOCKS cannot borrow generic launch"){_ = try IOSNodeChainCapture.reopen(capture.source,selectedProfile:profile(bundles[2]))}
   var provider:[String:Any]=["engine":"multihop-libbox","mode":"shadowsocks","rawProfileID":"shadowsocks","modeCandidates":["shadowsocks"],"bundle":bundles[2],IOSNodeChainSOCKSCapture.providerKey:capture.source]
   let reopened=try IOSNodeChainSOCKSCapture.reopenProvider(provider);try reopened.plan.close()
   var replacedFinal=try profile(bundles[2]);replacedFinal["api_token"]="relinked-final"
   try reject("SOCKS replaced final control"){_ = try IOSNodeChainSOCKSCapture.reopen(capture.source,selectedProfile:replacedFinal)}
   var staleProvider=provider
   staleProvider["bundle"]=try edit(bundles[2]){root in var files=root["profiles"] as! [String:[String:String]];files["shadowsocks"]!["sing-box.json"]=Data("replacement".utf8).base64EncodedString();root["profiles"]=files}
   try reject("SOCKS replaced provider assets"){_ = try IOSNodeChainSOCKSCapture.reopenProvider(staleProvider)}
   provider[IOSNodeChainProviderCapture.key]=capture.source
   try reject("SOCKS mixed provider owner"){_ = try IOSNodeChainSOCKSCapture.reopenProvider(provider)}
   for fault in ["credential","token","endpoint","layer","order","dns","final-assets"] {
    var changed=bundles
    if fault=="order"{changed.swapAt(0,1)}
    else if fault=="dns"{changed[2]=try editProfile(changed[2]){$0["dns_mode"]="custom";$0["dns_protocol"]="tcp";$0["dns_host"]="resolver.example.test";$0["dns_port"]=53}}
    else if fault=="final-assets"{changed[2]=try edit(changed[2]){$0["profiles"]=[String:[String:String]]()}}
    else {changed[1]=try editProfile(changed[1]){p in
     if fault=="token"{p["api_token"]="borrowed"}
     if fault=="endpoint"{p["endpoint"]="203.0.113.21"}
     if fault=="layer"{p["start_layer"]="aes-256-gcm"}
     if fault=="credential"{var ext=p["external"] as! [String:Any],socks=ext["socks5"] as! [String:Any];socks["password"]="";ext["socks5"]=socks;p["external"]=ext}
    }}
    try reject("SOCKS captured refusal "+fault){_ = try IOSNodeChainSOCKSCapture.compile(bundles:changed)}
   }
  }}
 }
 static func hostnameMiddle()throws {
  for mode in ["wg","awg2-fast","awg2-strong"] {
   for (method,keySize) in [("2022-blake3-aes-128-gcm",16),("2022-blake3-aes-256-gcm",32),("2022-blake3-chacha20-poly1305",32)] {
    var bundles=try sources(3),middle=try profile(bundles[1])
    let host="Middle.Example.Test",secret=Data(repeating:79,count:keySize).base64EncodedString()
    middle["id"]="original-hostname-middle";middle["name"]="Saved hostname middle";middle["node_kind"]="external";middle["endpoint"]=host
    middle.removeValue(forKey:"node_proof_id")
    for key in ["router_api","api_token","adguard_ipv6","socks_host","socks_username","socks_password"] { middle[key]="" }
    middle["socks_port"]=0;middle["start_layer"]="off";middle["dns_mode"]="custom";middle["dns_protocol"]="tcp";middle["dns_host"]="10.81.0.53";middle["dns_port"]=5353
    middle["home_lan_access"]=false;middle["ipv6_mode"]="off";middle["kill_switch_policy"]="always"
    middle["external"]=["protocol":"shadowsocks","expected_public_ip":"203.0.113.76","shadowsocks":["server":host,"port":8388,"method":method,"password":secret]]
    bundles[1]=try data(["selectedRouterID":"original-hostname-middle","routerProfiles":[middle],"profiles":[String:[String:String]]()])
    bundles[2]=try editProfile(bundles[2]) { p in
     var nodes=p["multihop_nodes"] as! [[String:Any]];nodes[0]["mode"]=mode;nodes[1]=["id":"original-hostname-middle","mode":"shadowsocks"];p["multihop_nodes"]=nodes
    }
    let original=bundles,typed=try JSONDecoder().decode(RouterProfile.self,from:data(middle))
    try check("saved hostname middle eligible "+mode+"/"+method,IOSImportedShadowsocksSource.eligible(typed))
    let raw=try IOSImportedShadowsocksSource.capture(typed),source=try object(Data(raw.config.utf8)),capture=try object(Data(raw.capture.utf8))
    try check("hostname capture performs no bootstrap or application DNS",source["dns"]==nil && capture["dns_bootstrap"]==nil)
    try check("original hostname survives all typed source copies",(capture["profile"] as? [String:Any])?["endpoint"] as? String==host && ((source["outbounds"] as? [[String:Any]])?.first?["server"] as? String)==host)
    try reject("hostname cannot become ordinary physical authority"){_ = try LibboxTestOrdinarySource(raw.config,raw.capture)}
    let chain=try IOSNodeChainCapture.compile(bundles:bundles);defer{try? chain.plan.close()}
    let replay=try IOSNodeChainCapture.reopen(chain.launchInput,selectedProfile:profile(bundles[2]));defer{try? replay.plan.close()}
    try check("hostname exact source replay",replay.launchInput==chain.launchInput && bundles==original)
    let graph=try object(Data(chain.config.utf8)),outs=graph["outbounds"] as! [[String:Any]],dns=graph["dns"] as! [String:Any],servers=dns["servers"] as! [[String:Any]]
    let transport=outs.first{$0["server"] as? String==host}!,query=transport["domain_resolver"] as! [String:Any]
    let resolver=servers.first{$0["tag"] as? String==query["server"] as? String}!,selected=servers.first{$0["tag"] as? String==dns["final"] as? String}!
    try check("hostname lookup follows preceding transport",resolver["type"] as? String=="tcp" && resolver["server"] as? String=="10.81.0.53" && resolver["server_port"] as? Int==5353 && resolver["detour"] as? String==transport["detour"] as? String)
    let final=try profile(bundles[2]),selector=outs.first{$0["tag"] as? String==((graph["route"] as? [String:Any])?["final"] as? String)}!
    try check("final selector retains one captured member",selector["type"] as? String=="selector" && selector["outbounds"] as? [String]==[selector["default"] as! String])
    try check("final Home resolver remains separate",selected["tag"] as? String != resolver["tag"] as? String && selected["server"] as? String==final["adguard_ipv4"] as? String && selected["detour"] as? String==selector["default"] as? String)
    try check("hostname device restrictions remain captured",chain.strict && !chain.homeLANAccess)
    for fault in ["home","rescue","udp","tls","zero-port","missing-port","resolver-name","noncanonical-resolver","bootstrap","tls-name","dns-path","endpoint-case","credential","private-token","first-position"] {
     var changed=bundles
     changed[1]=try editProfile(changed[1]) { p in
      switch fault {
      case "home","rescue":p["dns_mode"]=fault
      case "udp","tls":p["dns_protocol"]=fault
      case "zero-port":p["dns_port"]=0
      case "missing-port":p.removeValue(forKey:"dns_port")
      case "resolver-name":p["dns_host"]="resolver.example.test"
      case "noncanonical-resolver":p["dns_host"]="2001:0DB8::53"
      case "bootstrap":p["dns_bootstrap"]=["server":["type":"tcp","server":"10.81.0.53","server_port":5353]]
      case "tls-name":p["dns_server_name"]="resolver.example.test"
      case "dns-path":p["dns_path"]="/dns-query"
      case "endpoint-case":p["endpoint"]=host.lowercased()
      case "credential":var ext=p["external"] as! [String:Any],ss=ext["shadowsocks"] as! [String:Any];ss["password"]="invalid!";ext["shadowsocks"]=ss;p["external"]=ext
      case "private-token":p["api_token"]="borrowed-secret"
      default:break
      }
     }
     if fault=="first-position" { changed.swapAt(0,1) }
     try reject("hostname middle rejects "+fault){_ = try IOSNodeChainCapture.compile(bundles:changed)}
    }
   }
  }
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
        command = options + ['-I', str(work), '-L', str(work), '-lLibbox', '-Xlinker', '-rpath', '-Xlinker', str(work), str(APP / 'IOSMultihopStartLayer.swift'), str(APP / 'Models.swift'), str(APP / 'IOSNodeChainSOCKSCapture.swift')]
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
        typed_source = APP / 'IOSNodeChainSOCKSCapture.swift'
        typed_text = typed_source.read_text()
        for name, before, after, witness in (
            ('typed-final-control', 'try json(selectedProfile) == json(result.finalProfile)', 'true', 'ACCEPTED SOCKS replaced final control'),
            ('typed-final-assets', 'selected == original else', 'true else', 'ACCEPTED SOCKS replaced provider assets'),
            ('typed-device-policy', 'self.strict = strict; self.homeLANAccess = lan', 'self.strict = false; self.homeLANAccess = true', 'typed SOCKS device policy'),
        ):
            assert typed_text.count(before) == 1, name
            changed = work / (name + '.swift'); changed.write_text(typed_text.replace(before, after, 1))
            executable = work / name
            typed_command = [str(changed) if item == str(typed_source) else item for item in command]
            subprocess.run(typed_command + [str(source), str(provider), str(tests), '-o', str(executable)], check=True, timeout=90)
            failed = subprocess.run([str(executable), str(compiler)], capture_output=True, text=True, timeout=180)
            assert failed.returncode != 0 and witness in failed.stdout + failed.stderr, name + ': missing causal refusal: ' + (failed.stdout + failed.stderr)[-1000:]
            print('Rejected typed SOCKS source defect mutation: ' + name)


if __name__ == '__main__':
    main()
