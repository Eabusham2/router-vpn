#!/usr/bin/env python3
"""Run shipping Apple prefix capture against the actual shared Go compiler.

The Libbox ABI is a framed subprocess boundary. No VPN is opened here; the
independent mandatory native Box/bridge gate owns real no-ingress evidence.
"""
from pathlib import Path
import platform
import subprocess
import tempfile
import test_ios_node_candidates as C

ROOT, APP = C.ROOT, C.APP
PREFIX_GO = r'''
 case "prefix-new","prefix-socks-new","prefix-connect-new","prefix-open":
  var prep *mobilemultihop.NodeChainCandidatePreparation
  if r.Op=="prefix-open"{prep,err=mobilemultihop.ParseNodeChainCandidatePreparationCapture(r.Source)}else{
   var position int;position,err=strconv.Atoi(r.Mode);if err==nil{switch r.Op{
    case "prefix-new":prep,err=mobilemultihop.NewNodeChainCandidatePreparation(r.Source,position,r.Files)
    case "prefix-socks-new":prep,err=mobilemultihop.NewNodeChainSOCKSCandidatePreparation(r.Source,position,r.Files)
    case "prefix-connect-new":prep,err=mobilemultihop.NewNodeChainCONNECTCandidatePreparation(r.Source,position,r.Files)
   }}
  }
  if err==nil{var raw []byte;raw,err=json.Marshal(map[string]string{"config":prep.Config(),"source":prep.SourceSHA256(),"config_sha":prep.ConfigSHA256(),"original":prep.OriginalSourceSHA256(),"capture":prep.CaptureSHA256(),"metadata":prep.Metadata(),"launch":prep.Source()});value=string(raw)}
 case "candidate-supported":'''

def prefix_go(base):
    assert base.count(' case "candidate-supported":') == 1
    return base.replace(' case "candidate-supported":', PREFIX_GO, 1)

GO = prefix_go(C.GO)

LIBBOX = C.LIBBOX + r'''
private final class PrefixFault: @unchecked Sendable {
 static let shared=PrefixFault();private let lock=NSLock();private var value=""
 func set(_ fault:String){lock.lock();value=fault;lock.unlock()}
 var current:String{lock.lock();defer{lock.unlock()};return value}
}
public func LibboxTestPrefixFault(_ fault:String){PrefixFault.shared.set(fault)}
public final class LibboxRouterNodeChainCandidatePreparation {
 private let value:[String:String]
 init(_ value:[String:String]){self.value=value}
 public func config()->String{value["config"]!}
 public func sourceSHA256()->String{value["source"]!}
 public func configSHA256()->String{value["config_sha"]!}
 public func captureSHA256()->String{value["capture"]!}
 public func originalSourceSHA256()->String{PrefixFault.shared.current=="original-owner" ? String(repeating:"b",count:64):value["original"]!}
 public func launchInput()->String{value["launch"]!}
 public func metadata()->String{
  let fault=PrefixFault.shared.current
  if fault.isEmpty || fault=="launch-error"{return value["metadata"]!}
  var raw=try! object(Data(value["metadata"]!.utf8))
  switch fault {
  case "original-owner":raw["original_source_sha256"]=String(repeating:"b",count:64)
  case "application","dns","ready":raw[fault=="application" ? "application_open":fault=="dns" ? "dns_open":"ready"]=true
  case "measured-mtu":raw["mtu_measurement"]="path-measured"
  case "mtu":var mtu=raw["mtu"] as! [String:Any];mtu["original"]=1400;raw["mtu"]=mtu
  case "source":raw["source_sha256"]=String(repeating:"b",count:64)
  case "capture":raw["capture_sha256"]=String(repeating:"b",count:64)
  case "prefix":var prefixes=raw["prefixes"] as! [[String:Any]];prefixes[0]["profile_id"]="foreign";raw["prefixes"]=prefixes
  default:raw["stage"]="connected"
  }
  return String(decoding:try! JSONSerialization.data(withJSONObject:raw,options:[.sortedKeys]),as:UTF8.self)
 }
 public func close()throws{}
}
func prefixMake(_ op:String,_ source:String,_ position:Int32=0,_ inventory:String="")throws->LibboxRouterNodeChainCandidatePreparation{
 let raw=try bridge(["Op":op,"Source":source,"Mode":String(position),"Files":inventory])
 return LibboxRouterNodeChainCandidatePreparation(try JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [String:String])
}
public func LibboxNewRouterNodeChainCandidatePreparation(_ source:String,_ position:Int32,_ inventory:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainCandidatePreparation?{api(error){try prefixMake("prefix-new",source,position,inventory)}}
public func LibboxNewRouterNodeChainSOCKSCandidatePreparation(_ source:String,_ position:Int32,_ inventory:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainCandidatePreparation?{api(error){try prefixMake("prefix-socks-new",source,position,inventory)}}
public func LibboxNewRouterNodeChainCONNECTCandidatePreparation(_ source:String,_ position:Int32,_ inventory:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainCandidatePreparation?{api(error){try prefixMake("prefix-connect-new",source,position,inventory)}}
public func LibboxRouterNodeChainCandidatePreparationLaunch(_ source:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainCandidatePreparation?{
 let result=api(error){try prefixMake("prefix-open",source)}
 if PrefixFault.shared.current=="launch-error"{error?.pointee=NSError(domain:"PrefixLaunchBoundary",code:1)}
 return result
}
'''

SWIFT = C.SWIFT[:C.SWIFT.index('@MainActor @main struct Tests')] + r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ value:@autoclosure ()throws->Bool)throws{guard try value()else{throw NSError(domain:"PrefixCheck",code:1,userInfo:[NSLocalizedDescriptionKey:name])};checks+=1}
 static func reject(_ name:String,_ action:()throws->Void)throws{do{try action()}catch{checks+=1;return};throw NSError(domain:"PrefixCheck",code:1,userInfo:[NSLocalizedDescriptionKey:"ACCEPTED "+name])}
 static func main(){defer{LibboxTestClose()};do{
  if let phase=CommandLine.arguments.last,phase.hasPrefix("imported-") {
   guard ["imported-literal","imported-hostname"].contains(phase) else{throw NSError(domain:"PrefixPhase",code:1)}
   try importedSSPrefixes(hostname:phase=="imported-hostname")
   print("Apple independent prefix capture \(phase): \(checks) shipping Swift/shared Go checks PASS")
  }else{try run();try openVPNPrefixes();print("Apple independent prefix capture: \(checks) shipping Swift/shared Go checks PASS")}}
 catch{FileHandle.standardError.write(Data(("FAIL after \(checks): \(error.localizedDescription)\n").utf8));exit(1)}}
 static func openVPNPrefixes()throws{
  for count in [3,4,8] {for mode in ["wg","awg2-fast","awg2-strong"] {for network in ["tcp","udp"] {
   let middlePosition=count-2,finalPosition=count-1,id="saved-openvpn-prefix-middle"
   var bundles=try sources(count,"off",true)
   for position in bundles.indices {bundles[position]=try editProfile(bundles[position]){p in
    p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""
   }}
   var middle=try profile(bundles[middlePosition]);middle["id"]=id;middle["node_kind"]="external";middle.removeValue(forKey:"node_proof_id")
   middle["router_api"]="";middle["api_token"]="";middle["endpoint"]="203.0.113.20";middle["start_layer"]="off";middle["home_lan_access"]=false;middle["kill_switch_policy"]="always"
   let raw="client\ndev tun\nproto "+network+"\nremote 203.0.113.20 1194\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint "+String(repeating:"ab",count:32)+"\ntun-mtu 1400\ndata-ciphers AES-256-GCM:AES-128-GCM\n"
   middle["external"]=["protocol":"openvpn","expected_public_ip":"203.0.113.88","openvpn":["config":raw,"username":" exact prefix user ","password":" exact prefix secret "]]
   bundles[middlePosition]=try data(["selectedRouterID":id,"routerProfiles":[middle],"profiles":[String:[String:String]]()])
   bundles[finalPosition]=try editProfile(bundles[finalPosition]){p in var nodes=p["multihop_nodes"] as! [[String:Any]];for i in 0..<middlePosition{nodes[i]["mode"]=mode};nodes[middlePosition]=["id":id,"mode":"openvpn"];p["multihop_nodes"]=nodes}
   let original=try IOSNodeChainCapture.compile(bundles:bundles);defer{try? original.plan.close()}
   let source=try object(Data(original.launchInput.utf8)),inputs=source["nodes"] as! [String]
   let inventory=String(decoding:try data(["schema":1,"revision":"original-openvpn-prefix-catalog","inputs":[inputs.last!]]),as:UTF8.self)
   let positions=middlePosition==1 ? [0] : [0,middlePosition-1]
   for position in positions {
    let value=try IOSNodeCandidatePrefixCapture.compile(original:original,position:position,inventory:inventory);defer{try? value.native.close()}
    try check("OpenVPN retained only saved original provenance",value.originalLaunchInput==original.launchInput && value.originalSourceSHA256==original.sourceSHA256 && value.sourceSHA256 != original.sourceSHA256)
    try check("OpenVPN prefix exact original paired identities",value.metadata.prefixes.map(\.profile_id)==Array(original.members.prefix(position+1)).map(\.id))
    try check("OpenVPN prefix has no application or DNS ingress",!value.metadata.ready && !value.metadata.application_open && !value.metadata.dns_open && value.metadata.stage=="pending-prefix-proof")
    try check("saved OpenVPN is absent from runnable prefix",!value.config.contains("openvpn-client") && !value.config.contains("203.0.113.20") && !value.config.contains(" exact prefix secret "))
    try check("saved suffix has no native tag in prefix",!value.config.contains("routervpn-chain-\(position+1)-"))
    try check("OpenVPN prefix preserves configured MTU semantics",value.metadata.mtu_measurement=="configured-bounds-only" && value.metadata.mtu.original<=value.metadata.mtu.ceiling)
    let reopened=try IOSNodeCandidatePrefixCapture.reopen(value.launchInput,originalInput:original.launchInput,selectedProfile:original.finalProfile,position:position,inventory:inventory);defer{try? reopened.native.close()}
    try check("OpenVPN saved-prefix private source roundtrip",reopened.config==value.config && reopened.captureSHA256==value.captureSHA256 && reopened.launchInput==value.launchInput)
   }
   try reject("OpenVPN middle cannot become packet candidate prefix"){_ = try IOSNodeCandidatePrefixCapture.compile(original:original,position:middlePosition,inventory:inventory)}
   try reject("OpenVPN final cannot become packet candidate prefix"){_ = try IOSNodeCandidatePrefixCapture.compile(original:original,position:finalPosition,inventory:inventory)}
  }}}
 }
 static func importedSSPrefixes(hostname:Bool)throws{
  for (index,count) in [3,4,8].enumerated() {for mode in ["wg","awg2-fast","awg2-strong"] {
   let middlePosition=count-2,finalPosition=count-1,id="saved-imported-prefix-middle",host=hostname ? "Middle.Example.Test":"203.0.113.24"
   let method=["2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305"][index]
   let secret=Data(repeating:79,count:index==0 ? 16:32).base64EncodedString()
   var bundles=try sources(count,"off",true)
   var middle=try profile(bundles[middlePosition])
   middle["id"]=id;middle["name"]="Saved imported prefix middle";middle["node_kind"]="external";middle["endpoint"]=host;middle.removeValue(forKey:"node_proof_id")
   for key in ["router_api","api_token","adguard_ipv6","socks_host","socks_username","socks_password"] {middle[key]=""}
   middle["socks_port"]=0;middle["start_layer"]="off";middle["dns_mode"]="custom";middle["dns_protocol"]="tcp";middle["dns_host"]="10.81.0.53";middle["dns_port"]=5353
   middle["home_lan_access"]=false;middle["ipv6_mode"]="off";middle["kill_switch_policy"]="always"
   middle["external"]=["protocol":"shadowsocks","expected_public_ip":"203.0.113.76","shadowsocks":["server":host,"port":8388,"method":method,"password":secret]]
   bundles[middlePosition]=try data(["selectedRouterID":id,"routerProfiles":[middle],"profiles":[String:[String:String]]()])
   bundles[finalPosition]=try editProfile(bundles[finalPosition]){p in var nodes=p["multihop_nodes"] as! [[String:Any]];for i in 0..<middlePosition{nodes[i]["mode"]=mode};nodes[middlePosition]=["id":id,"mode":"shadowsocks"];p["multihop_nodes"]=nodes}
   let saved=bundles,original=try IOSNodeChainCapture.compile(bundles:bundles);defer{try? original.plan.close()}
   let source=try object(Data(original.launchInput.utf8)),inputs=source["nodes"] as! [String]
   try check("imported prefix retains exact source family",source["schema"] as? Int==2)
   let complete=try object(Data(original.config.utf8)),transports=(complete["outbounds"] as! [[String:Any]]).filter{$0["server"] as? String==host && $0["type"] as? String=="shadowsocks"}
   try check("original imported transport has exact owner",transports.count==1)
   let resolver=hostname ? (transports[0]["domain_resolver"] as! [String:Any])["server"] as! String:""
   if hostname{try check("original imported resolver owner exists",!resolver.isEmpty)}
   let inventory=String(decoding:try data(["schema":1,"revision":"original-imported-ss-prefix-catalog","inputs":[inputs.last!]]),as:UTF8.self)
   for position in 0..<middlePosition {
    let value=try IOSNodeCandidatePrefixCapture.compile(original:original,position:position,inventory:inventory);defer{try? value.native.close()}
    try check("imported prefix retains complete original provenance",value.originalLaunchInput==original.launchInput && value.originalSourceSHA256==original.sourceSHA256 && value.sourceSHA256 != original.sourceSHA256)
    try check("imported prefix exact paired identity inventory",value.metadata.prefixes.map(\.profile_id)==Array(original.members.prefix(position+1)).map(\.id))
    try check("imported prefix has no application or DNS authority",!value.metadata.ready && !value.metadata.application_open && !value.metadata.dns_open && value.metadata.stage=="pending-prefix-proof")
    try check("saved SS transport absent from executable prefix",!value.config.contains(host) && !value.config.contains(secret))
    if hostname{try check("saved imported resolver owner absent from executable prefix",!value.config.contains(resolver))}
    try check("unselected suffix has no native prefix tag",!value.config.contains("routervpn-chain-\(position+1)-"))
    try check("imported prefix has only configured MTU bounds",value.metadata.mtu_measurement=="configured-bounds-only" && value.metadata.mtu.original<=value.metadata.mtu.ceiling)
    let reopened=try IOSNodeCandidatePrefixCapture.reopen(value.launchInput,originalInput:original.launchInput,selectedProfile:original.finalProfile,position:position,inventory:inventory);defer{try? reopened.native.close()}
    try check("imported saved prefix strict native source roundtrip",reopened.config==value.config && reopened.captureSHA256==value.captureSHA256 && reopened.launchInput==value.launchInput)
   }
   try reject("imported SS middle cannot become packet prefix"){_ = try IOSNodeCandidatePrefixCapture.compile(original:original,position:middlePosition,inventory:inventory)}
   try reject("imported SS final cannot become packet prefix"){_ = try IOSNodeCandidatePrefixCapture.compile(original:original,position:finalPosition,inventory:inventory)}
   try check("imported prefix preparation preserves saved source",saved==bundles)
  }}
 }
 static func run()throws{
  for mixed in [false,true] {
   let bundles=try sources(4,"off",mixed)
   let original=try IOSNodeChainCapture.compile(bundles:bundles);defer{try? original.plan.close()}
   try check("retained original compiler source",original.originalSource != nil && original.originalSource != original.launchInput)
   let proofs=original.members.enumerated().map{IOSNodeCandidatePrefix(position:$0.offset,profile_id:$0.element.id,node_id:$0.element.profile["node_proof_id"] as! String,mode:$0.element.mode)}
   let records=Dictionary(uniqueKeysWithValues:try bundles.map{(try profile($0)["id"] as! String,$0)})
   let stamp=IOSCandidateCatalogPublication.Stamp(schema:1,epoch:UUID().uuidString,generation:1,ready:true,sources_sha256:try IOSCandidateCatalogPublication.sourcesDigest(records))
   for position in 0..<3 {
    let inventory=String(decoding:try IOSNodeCandidateCapture.compile(records:records,stamp:stamp,prefixPosition:position,proofs:proofs).inventory,as:UTF8.self)
    let value=try IOSNodeCandidatePrefixCapture.compile(original:original,position:position,inventory:inventory);defer{try? value.native.close()}
    try check("complete original preserved only as provenance",value.originalLaunchInput==original.launchInput && value.originalSourceSHA256==original.sourceSHA256 && value.sourceSHA256 != original.sourceSHA256)
    try check("selected prefix identities",value.metadata.prefixes.map(\.profile_id)==Array(original.members.prefix(position+1)).map(\.id))
    try check("source capture is never Connected or DNS/application authority",!value.metadata.ready && !value.metadata.application_open && !value.metadata.dns_open && value.metadata.stage=="pending-prefix-proof")
    let graph=try object(Data(value.config.utf8)),outbounds=graph["outbounds"] as! [[String:Any]]
    try check("saved final absent from executable native outbounds",!outbounds.contains{$0["server"] as? String=="198.51.100.13"})
    try check("configured MTU bound is not measured PMTU",value.metadata.mtu_measurement=="configured-bounds-only" && value.metadata.mtu.original<=value.metadata.mtu.ceiling)
    let reopened=try IOSNodeCandidatePrefixCapture.reopen(value.launchInput,originalInput:original.launchInput,selectedProfile:original.finalProfile,position:position,inventory:inventory);defer{try? reopened.native.close()}
    try check("strict native prefix roundtrip",reopened.launchInput==value.launchInput && reopened.config==value.config && reopened.captureSHA256==value.captureSHA256)
    try reject("wrong prefix position"){_ = try IOSNodeCandidatePrefixCapture.reopen(value.launchInput,originalInput:original.launchInput,selectedProfile:original.finalProfile,position:(position+1)%3,inventory:inventory)}
    try reject("changed inventory bytes"){_ = try IOSNodeCandidatePrefixCapture.reopen(value.launchInput,originalInput:original.launchInput,selectedProfile:original.finalProfile,position:position,inventory:inventory+" ")}
    if position==0 && !mixed {
     let launchOriginal=try IOSNodeChainCapture.reopen(original.launchInput,selectedProfile:original.finalProfile);defer{try? launchOriginal.plan.close()}
     try reject("sealed launch must not become new plain constructor input"){_ = try IOSNodeCandidatePrefixCapture.compile(original:launchOriginal,position:0,inventory:inventory)}
     for fault in ["original-owner","application","dns","ready","measured-mtu","mtu","source","capture","prefix","stage","launch-error"] {
      LibboxTestPrefixFault(fault)
      try reject("native receipt "+fault){_ = try IOSNodeCandidatePrefixCapture.reopen(value.launchInput,originalInput:original.launchInput,selectedProfile:original.finalProfile,position:0,inventory:inventory)}
      LibboxTestPrefixFault("")
     }
     try reject("noncanonical prefix launch"){_ = try IOSNodeCandidatePrefixCapture.reopen(value.launchInput+" ",originalInput:original.launchInput,selectedProfile:original.finalProfile,position:0,inventory:inventory)}
     try reject("complete final cannot become prefix"){_ = try IOSNodeCandidatePrefixCapture.compile(original:original,position:3,inventory:inventory)}
     try reject("negative prefix"){_ = try IOSNodeCandidatePrefixCapture.compile(original:original,position:-1,inventory:inventory)}
     var foreign=original.finalProfile;foreign["api_token"]="replacement"
     try reject("replacement full original control source"){_ = try IOSNodeCandidatePrefixCapture.reopen(value.launchInput,originalInput:original.launchInput,selectedProfile:foreign,position:0,inventory:inventory)}
    }
   }
  }
 }
}
'''


CONTROLS = [
            ('IOSNodeChainCapture.swift','selectionExecution: selectionExecution, originalSource: source','selectionExecution: selectionExecution, originalSource: nil','retained original compiler source'),
            ('IOSNodeCandidatePrefixCapture.swift','value.original_source_sha256 == original.sourceSHA256,','true,','ACCEPTED native receipt original-owner'),
            ('IOSNodeCandidatePrefixCapture.swift','!value.application_open, !value.dns_open, !value.ready,','true, !value.dns_open, !value.ready,','ACCEPTED native receipt application'),
            ('IOSNodeCandidatePrefixCapture.swift','!value.application_open, !value.dns_open, !value.ready,','!value.application_open, true, !value.ready,','ACCEPTED native receipt dns'),
            ('IOSNodeCandidatePrefixCapture.swift','source["inventory"] as? String == inventory','true','ACCEPTED changed inventory bytes'),
            ('IOSNodeCandidatePrefixCapture.swift','guard failure == nil, let created else','guard let created else','ACCEPTED native receipt launch-error'),

]

def run_fixture(swift=SWIFT, files=None, controls=CONTROLS, imported_phases=(), go_source=GO, libbox_source=LIBBOX):
    with tempfile.TemporaryDirectory(prefix='.ios-prefix-compiler-',dir=ROOT) as gofolder,tempfile.TemporaryDirectory(prefix='ios-prefix-capture-') as folder:
        work=Path(folder);go=Path(gofolder)/'main.go';go.write_text(go_source);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(go)],cwd=ROOT,check=True,timeout=180)
        print('Apple prefix shared compiler built',flush=True)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        stub=work/'Libbox.swift';stub.write_text(libbox_source);test=work/'Tests.swift';test.write_text(swift)
        library=work/('libLibbox.dylib' if platform.system()=='Darwin' else 'libLibbox.so')
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(stub),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(library)],check=True,timeout=90)
        if platform.system()!='Darwin':
            crypto=work/'CryptoKit.swift';crypto.write_text(C.LINUX_CRYPTO)
            subprocess.run(options+['-emit-module','-emit-library','-module-name','CryptoKit',str(crypto),'-lcrypto','-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/'libCryptoKit.so')],check=True,timeout=90)
            options+=['-lCryptoKit']
        command=options+['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        files=files or ['Models.swift','IOSMultihopStartLayer.swift','IOSCandidateCatalogPublication.swift','IOSNodeChainCapture.swift','IOSImportedOpenVPNSource.swift','IOSNodeCandidateOriginalCapture.swift','IOSNodeChainProviderCapture.swift','IOSNodeChainSOCKSCapture.swift','IOSNodeChainCONNECTCapture.swift','IOSNodeCandidateCapture.swift','IOSNodeCandidatePrefixCapture.swift']
        binary=work/'test'
        def exercise(replacements=None,witness=None):
            replacements=replacements or {}
            inputs=[]
            for name in files:
                if name in replacements:
                    target=work/name;target.write_text(replacements[name]);inputs.append(str(target))
                else:inputs.append(str(APP/name))
            subprocess.run(command+inputs+[str(test),'-o',str(binary)],check=True,timeout=90)
            result=subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
            if witness:
                assert result.returncode!=0 and witness in result.stdout+result.stderr,(witness,result.stdout+result.stderr)
                print('Rejected Apple prefix capture defect: '+witness,flush=True)
            else:
                assert result.returncode==0,result.stdout+result.stderr
                print(result.stdout.strip(),flush=True)
                for phase in imported_phases:
                    assert phase in ('imported-literal','imported-hostname'),phase
                    result=subprocess.run([str(binary),str(compiler),phase],capture_output=True,text=True,timeout=180)
                    assert result.returncode==0,result.stdout+result.stderr
                    print(result.stdout.strip(),flush=True)
        exercise()
        for name,before,after,witness in controls:
            source=(APP/name).read_text();expected=2 if before=='guard failure == nil, let created else' else 1
            assert source.count(before)==expected,(name,before)
            altered=source.replace(before,after);assert altered!=source
            exercise({name:altered},witness)

if __name__=='__main__':run_fixture(imported_phases=('imported-literal','imported-hostname'))
