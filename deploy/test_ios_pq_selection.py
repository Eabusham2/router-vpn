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
import("bytes";"crypto/sha256";"encoding/base64";"encoding/hex";"encoding/json";"fmt";"io";"os";"strings";"router-vpn/internal/mobilemultihop";"router-vpn/internal/mobileperf")
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
func main(){
 var r struct{Op,Mode,Files,Node,Config,Source,Policy string};err:=json.NewDecoder(io.LimitReader(os.Stdin,16<<20)).Decode(&r);var value string
 if err==nil{switch r.Op{
 case "fixture":value=fixture(r.Mode)
 case "compile":value,err=mobilemultihop.CompilePQProfile(r.Mode,r.Files,r.Node)
 case "start":value,err=mobilemultihop.ComposeNativeBaseStartLayer(r.Config,r.Source,r.Policy)
 case "lan":value,err=mobilemultihop.ApplyLANPolicy(r.Config,r.Policy)
 case "performance":value,err=mobileperf.Apply(r.Config,r.Policy)
 case "validate":_,err=mobilemultihop.PQRuntimeConfig(r.Config);value="ok"
 default:err=fmt.Errorf("unknown test operation")}}
 if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)};fmt.Print(value)
}'''
SWIFT=r'''
import Foundation
func json(_ value: Any) throws -> Data {try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
func text(_ value:Any)throws->String {String(decoding:try json(value),as:UTF8.self)}
func object(_ data:Data)throws->[String:Any] {try JSONSerialization.jsonObject(with:data) as! [String:Any]}
func key(_ b:UInt8)->String {Data(repeating:b,count:32).base64EncodedString()}
func bridge(_ request:[String:String])throws->String {
 let task=Process();task.executableURL=URL(fileURLWithPath:CommandLine.arguments[1])
 let input=Pipe(),output=Pipe();task.standardInput=input;task.standardOutput=output;task.standardError=FileHandle.nullDevice
 try task.run();try input.fileHandleForWriting.write(contentsOf:json(request));try input.fileHandleForWriting.close()
 let data=output.fileHandleForReading.readDataToEndOfFile();task.waitUntilExit()
 guard task.terminationStatus==0,let result=String(data:data,encoding:.utf8) else {throw NSError(domain:"PQTestCompiler",code:1)}
 return result
}
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
 @MainActor static func main()throws{
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
        subprocess.run(['swiftc','-swift-version','6',str(APP/'Models.swift'),str(dns),str(APP/'IOSNativeXrayProfile.swift'),str(APP/'IOSNativePQProfile.swift'),str(APP/'IOSRuntimeSelection.swift'),str(TUN/'RouterVPNMultihopGraph.swift'),str(TUN/'RouterVPNMTUPolicy.swift'),str(TUN/'IOSStartLayer.swift'),str(source),'-o',str(temp/'tests')],check=True,timeout=120)
        subprocess.run([str(temp/'tests'),str(binary)],check=True,timeout=150)
    provider=(TUN/'PacketTunnelProvider.swift').read_text()
    start=provider[provider.index('    private func startLibbox('):provider.index('    private func startExternalLibbox(')]
    for required in ['IOSNativePQProfile.compile(', 'LibboxRouterCompilePQProfile(', 'RouterVPNMultihopGraph.singlePQPolicy(', 'LibboxRouterApplyMultihopLANPolicy(', 'RouterVPNMTUPolicy.libbox(', 'performanceFiles(', 'expectedNodeID: provenNodeID']:
        assert required in start,required
    assert start.index('IOSNativePQProfile.compile(')<start.index('engine.start(')
    assert start.index('engine.start(')<start.index('proveSelectedNode(')
    assert 'IOSNativePQProfile' not in provider[provider.index('    private func startWireGuard('):provider.index('    private func startMultihop(')]
    engine=(TUN/'RouterVPNLibboxEngine.swift').read_text()
    assert engine.count('try RouterVPNPQFactory.install()')==1
    assert engine.index('try RouterVPNPQFactory.install()')<engine.index('LibboxNewCommandServer(')
    assert 'App/IOSNativePQProfile.swift' in (ROOT/'ios/RouterVPN/project.yml').read_text()
if __name__=='__main__':main()
