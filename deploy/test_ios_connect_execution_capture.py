#!/usr/bin/env python3
"""Compile shipping Apple execution consumers against the real shared Go parsers.

The Libbox source bridge executes the actual compiler. Native lifecycle calls
remain explicitly rejecting boundaries; this is not an Apple SDK/device gate.
"""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
spec=importlib.util.spec_from_file_location('apple_execution_source',ROOT/'deploy/test_ios_node_chain_execution_capture.py')
E=importlib.util.module_from_spec(spec);spec.loader.exec_module(E)
spec=importlib.util.spec_from_file_location('typed_latency_source',ROOT/'deploy/test_ios_ordered_latency_connect_capture.py')
F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)

LIBBOX=E.LIBBOX+r'''
public func LibboxTestCONNECTExecutionFixture(_ kind:String)throws->String{try bridge(["Op":"chain-connect-fixture","Mode":kind])}
'''
SWIFT=E.SWIFT[:E.SWIFT.index('@main struct Tests')]+r'''
func connectFixture(_ kind:String,_ mode:String,_ requested:String,_ count:Int=3,_ layer:String="off")throws->[Data]{
 let raw=try LibboxTestCONNECTExecutionFixture(kind)
 let original=try (JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [Any]).map{try data($0)}
 let middle=count-2,final=count-1
 var bundles:[Data]
 if count==3 && layer=="off" {bundles=original}else{bundles=try fixture(count,layer,requested,true)}
 if count != 3 || layer != "off" {
  // The constructed middle keeps its own record ID; copying the original
  // trio ID would alias the second paired prefix in a longer route.
  let id=try profile(bundles[middle])["id"] as! String
  let imported=try editProfile(original[1]){$0["id"]=id}
  bundles[middle]=try edit(imported){$0["selectedRouterID"]=id}
 }
 for position in bundles.indices {bundles[position]=try editProfile(bundles[position]){p in p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""}}
 let proxyID=try profile(bundles[middle])["id"] as! String
 bundles[final]=try editProfile(bundles[final]){p in
  p["multihop_execution"]=requested;p["startup_mode"]="manual";p["auto_connect"]=true;p["start_layer"]="off"
  var nodes=p["multihop_nodes"] as! [[String:Any]]
  for position in 0..<middle {nodes[position]["mode"]=mode}
  nodes[middle]=["id":proxyID,"mode":kind];p["multihop_nodes"]=nodes
 }
 bundles[final]=Data(try LibboxTestCONNECTService(String(decoding:bundles[final],as:UTF8.self)).utf8)
 return bundles
}
@main struct Tests{
 @MainActor static var checks=0
 @MainActor static func check(_ good:Bool,_ name:String){guard good else{fatalError(name)};checks+=1}
 @MainActor static func reject(_ name:String,_ run:()throws->Void){do{try run();fatalError("ACCEPTED "+name)}catch{checks+=1}}
 @MainActor static func main()throws{
  defer{LibboxTestClose()}
  try genericConsumers()
  for count in [3,4,8] {for kind in ["http-connect","https-connect"] {for mode in ["wg","awg2-fast","awg2-strong"] {for requested in ["server","auto"] {
   let middle=count-2,final=count-1,bundles=try connectFixture(kind,mode,requested,count)
   let capture:IOSNodeChainExecutionCapture
   do{capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested)}catch{fatalError("complete CONNECT execution source refused: \(error)")};defer{try? capture.close()}
   let source=try object(Data(capture.source.utf8)),local=try object(Data((source["local_source"] as! String).utf8)),launch=try object(Data(capture.launchInput.utf8))
   check(capture.isCONNECT && source["schema"] as? Int==4 && source["execution"] as? String==requested,"typed preparation family and choice")
   check(launch["kind"] as? String=="routervpn-node-chain-connect-execution-preparation-input" && launch["schema"] as? Int==1,"typed launch family")
   let identities=local["identity_sources"] as! [String]
   check(capture.members.map(\.mode)==Array(repeating:mode,count:middle)+[kind,"shadowsocks"] && identities.count==count && identities.enumerated().allSatisfy{$0.offset==middle ? $0.element.isEmpty : !$0.element.isEmpty},"original complete member order and sparse identity")
   for position in 0..<final {check(try data(capture.members[position].profile)==data(profile(bundles[position])),"every original prefix and proxy private profile retained")}
   check(capture.finalProfile["startup_mode"]==nil && capture.finalProfile["auto_connect"]==nil,"only original scheduling projection")
   let realNodes=try bundles.map{try JSONDecoder().decode(ClientBundle.self,from:$0)}
   check(IOSMultihopNodeSelection.supportsCONNECTExecution(realNodes[final].routerProfiles[0].multihopNodes!),"complete CONNECT execution choice")
   let identity:IOSSessionIdentity
   do{identity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:bundles[final],entryBundleData:nil,nodeChainExecutionSource:Data(capture.launchInput.utf8))}catch{fatalError("complete CONNECT session identity refused: \(error)")}
   let model=RouterVPNModel(realNodes,identity:identity),fifty=try IOSOrderedLatencyCapture(model)
   check(fifty.source==capture.sourceSHA256 && fifty.config==capture.configSHA256 && fifty.ids==capture.members.map(\.id) && fifty.kinds==Array(repeating:"private-node",count:middle)+["public-path","private-node"],"original execution latency capture")
   check(IOSNodeChainPresentation.active(identity)?.map(\.id)==capture.members.map(\.id),"active execution presentation original identities")
   for winner in requested=="auto" ? ["local","server"]:["server"] {
    let rows:[[String:Any]]=capture.members.enumerated().map{["position":$0.offset,"profile_id":$0.element.id,"kind":$0.offset==middle ? "public-path":"private-node","proven":true,"response_ms":1.0]}
    let value:[String:Any]=["stage":"selected","execution":winner,"prefixes":rows,"ready":true,"complete":true,"dns_proven":true,"public_proven":true]
    let text=IOSNodeChainPresentation.progress(value,expected:capture.members.map(\.id),requestedExecution:requested)
    check(text?.contains(winner=="server" ? "Ordered route • Server":"Ordered route • Local")==true && text?.contains("Every captured node and final path verified")==true,"typed progress actual selected winner and full proof")
   }
   try fifty.require(model)
   model.iosConnectGeneration=UUID();reject("latency replacement generation"){try fifty.require(model)};model.iosConnectGeneration=fifty.selection
   model.nodes[middle].routerProfiles[0].name="changed private record";reject("latency changed original member"){try fifty.require(model)}
   reject("latency initial source change"){_ = try IOSOrderedLatencyCapture(model)}

   let replay=try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(bundles[final]));defer{try? replay.close()}
   check(replay.source==capture.source && replay.config==capture.config,"exact private source replay")
   let member=try object(Data((local["nodes"] as! [String])[middle].utf8)),saved=try object(Data((member["capture"] as! String).utf8))["profile"] as! [String:Any]
   check(try data(saved)==data(profile(bundles[middle])),"original CONNECT private policy and credentials")
   let originalLocal=try IOSNodeChainCONNECTCapture.compileOriginalForExecution(bundles:bundles,requested:requested);defer{try? originalLocal.plan.close()}
   check(originalLocal.source==source["local_source"] as? String,"original Local typed source retained")
   reject("Local source cannot consume execution selection"){_ = try IOSNodeChainCONNECTCapture.compile(bundles:bundles)}
   var failure:NSError?
   let generic=LibboxNewRouterNodeChainExecutionLaunch(capture.launchInput,&failure)
   check(generic==nil && failure != nil,"generic launch remains closed")
   var changed=try profile(bundles[final]);changed["api_token"]="foreign-final"
   reject("changed final private source"){_ = try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:changed)}
   reject("requested selection mismatch"){_ = try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested=="server" ? "auto":"server")}
   for fault in ["local-node","local-identity","local-schema","config","requested"] {
    LibboxTestExecutionFault(fault)
    reject("typed native readback "+fault){_ = try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested)}
   }
   for fault in ["password","endpoint","service","order"] {
    var invalid=bundles
    if fault=="order"{invalid.swapAt(0,middle)}
    else if fault=="service"{invalid[final]=try edit(invalid[final]){v in var files=v["profiles"] as! [String:[String:String]];files["shadowsocks"]!.removeValue(forKey:"routervpn-ss-service.json");v["profiles"]=files}}
    else{invalid[middle]=try editProfile(invalid[middle]){p in if fault=="endpoint"{p["endpoint"]="203.0.113.99"}else{var ext=p["external"] as! [String:Any],credentials=ext[kind.replacingOccurrences(of:"-",with:"_")] as! [String:Any];credentials["password"]="";ext[kind.replacingOccurrences(of:"-",with:"_")]=credentials;p["external"]=ext}}}
    reject("typed source "+fault){_ = try IOSNodeChainExecutionCapture.compile(bundles:invalid,requested:requested)}
   }
   for fault in ["final-layer","later-prefix-layer","later-prefix-proof","duplicate-prefix"] where count>3 {
    var invalid=bundles
    if fault=="final-layer"{invalid[final]=try editProfile(invalid[final]){$0["start_layer"]="aes-256-gcm"}}
    if fault=="later-prefix-layer"{invalid[1]=try editProfile(invalid[1]){$0["start_layer"]="xor-only"}}
    if fault=="later-prefix-proof"{invalid[1]=try editProfile(invalid[1]){$0.removeValue(forKey:"node_proof_id")}}
    if fault=="duplicate-prefix"{invalid[1]=invalid[0]}
    reject("complete CONNECT private source "+fault){_ = try IOSNodeChainExecutionCapture.compile(bundles:invalid,requested:requested)}
   }
   var layered=try object(Data(originalLocal.source.utf8)),layeredNodes=layered["nodes"] as! [String]
   var layeredFinal=try object(Data(layeredNodes[final].utf8)),layeredProfile=try object(Data((layeredFinal["profile_json"] as! String).utf8))
   layeredProfile["start_layer"]="aes-256-gcm";layeredFinal["profile_json"]=String(decoding:try data(layeredProfile),as:UTF8.self)
   layeredNodes[final]=String(decoding:try data(layeredFinal),as:UTF8.self);layered["nodes"]=layeredNodes
   reject("private replay tampered member seal"){_ = try IOSNodeChainCONNECTCapture.open(String(decoding:try data(layered),as:UTF8.self),selectionExecution:requested)}
   var resealFailure:NSError?
   let rebuilt:String?=LibboxRouterNodeChainMemberInput(layeredFinal["mode"] as! String,layeredFinal["files"] as! String,layeredFinal["profile_json"] as! String,layeredFinal["start"] as! String,layeredFinal["dns_bootstrap"] as! String,&resealFailure)
   check(resealFailure==nil && rebuilt?.isEmpty==false,"private-layer replay uses a newly sealed real member input")
   layeredNodes[final]=rebuilt!;layered["nodes"]=layeredNodes
   reject("execution private replay final layer"){_ = try IOSNodeChainCONNECTCapture.open(String(decoding:try data(layered),as:UTF8.self),selectionExecution:requested)}
  }}}}
  try completePrefixBounds()
  print("PASS Apple CONNECT and generic execution consumers: \(checks) original-source checks")
 }
 @MainActor static func completePrefixBounds()throws{
  for count in 3...8 {for requested in ["server","auto"] {
   let layer=count==4 ? "aes-256-gcm":count==8 ? "aes-256-gcm+xor-whitening":"off"
   let bundles=try connectFixture("https-connect","awg2-strong",requested,count,layer)
   let capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested)
   check(capture.members.count==count && capture.members.prefix(count-2).allSatisfy{$0.profile["start_layer"] as? String==layer} && capture.finalProfile["start_layer"] as? String=="off","complete CONNECT preserves every independent prefix layer and final Off")
   var nodes=capture.members.map{IOSMultihopNodeSelection(id:$0.id,mode:$0.mode)}
   if count>3 {nodes[1].mode="shadowsocks";check(!IOSMultihopNodeSelection.supportsCONNECTExecution(nodes),"CONNECT refuses an unpaired later prefix");nodes[1].mode="awg2-strong";nodes[count-2].mode="socks5";check(IOSMultihopNodeSelection.supportsSOCKSExecution(nodes) && !IOSMultihopNodeSelection.supportsCONNECTExecution(nodes),"complete SOCKS remains separate from CONNECT");nodes[1].mode="shadowsocks";check(!IOSMultihopNodeSelection.supportsSOCKSExecution(nodes),"SOCKS refuses an unpaired later prefix")}
   try capture.close()
  }}
  for count in [2,9] {let nodes=(0..<count).map{IOSMultihopNodeSelection(id:"bound-\($0)",mode:$0==count-1 ? "shadowsocks":$0==count-2 ? "https-connect":"wg")};check(!IOSMultihopNodeSelection.supportsCONNECTExecution(nodes),"CONNECT preserves the complete three-to-eight bound")}
 }
 @MainActor static func genericConsumers()throws{
  var originals:[[Data]]=[]
  for requested in ["server","auto"] {
   for (count,layer,awg) in [(2,"off",false),(3,"aes-256-gcm",true),(8,"aes-256-gcm+xor-whitening",true)] {
    originals.append(try appFixture(fixture(count,layer,requested,awg)))
   }
   for mode in ["wg","awg2-fast","awg2-strong"] {for method in ["2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305"] {
    originals.append(try appFixture(importedFixture(requested,mode,method)))
   }}
   for count in [4,8] {originals.append(try appFixture(importedFixture(requested,"awg2-strong","2022-blake3-aes-256-gcm",count)))}
  }
  for bundles in originals {
   let selected=try profile(bundles.last!),requested=selected["multihop_execution"] as! String
   let capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested);defer{try? capture.close()}
   let nodes=try bundles.map{try JSONDecoder().decode(ClientBundle.self,from:$0)},control=nodes.last!.routerProfiles[0]
   check(!capture.isCONNECT && IOSMultihopNodeSelection.supportsGenericExecution(control.multihopNodes!),"generic choice retains original family")
   try IOSMultihopNodeSelection.validate(control.multihopNodes!,execution:requested,entryID:nil,entryMode:nil,exitID:nil,exitMode:nil,controlID:control.id)
   let identity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:bundles.last!,entryBundleData:nil,nodeChainExecutionSource:Data(capture.launchInput.utf8))
   let model=RouterVPNModel(nodes,identity:identity),fifty=try IOSOrderedLatencyCapture(model)
   let expected=capture.members.map(\.id),kinds=capture.members.map{$0.profile["node_kind"] as? String=="external" ? "public-path":"private-node"}
   check(fifty.source==capture.sourceSHA256 && fifty.config==capture.configSHA256 && fifty.ids==expected && fifty.kinds==kinds,"generic fifty exact source and measurement kinds")
   check(IOSNodeChainPresentation.planned(selected:control,catalog:nodes.flatMap(\.routerProfiles))?.map(\.id)==expected,"planned generic path retains all original positions")
   check(IOSNodeChainPresentation.active(identity)?.map(\.id)==expected,"active generic path retains all original positions")
   if kinds.contains("public-path") {
    var launch=try object(Data(capture.launchInput.utf8)),preparation=try object(Data(capture.source.utf8)),local=try object(Data((preparation["local_source"] as! String).utf8))
    var inputs=local["nodes"] as! [String],identities=local["identity_sources"] as! [String]
    let position=inputs.count-2
    let external:[String:Any]=["schema":1,"kind":"routervpn-node-launch-input","mode":"shadowsocks","profile_json":String(decoding:try data(profile(bundles[position])),as:UTF8.self)]
    inputs[position]=String(decoding:try data(external),as:UTF8.self);identities[position]=identities[0]
    local["schema"]=1;local["nodes"]=inputs;local["identity_sources"]=identities
    preparation["local_source"]=String(decoding:try data(local),as:UTF8.self);launch["source"]=String(decoding:try data(preparation),as:UTF8.self)
    let forged=try IOSSessionIdentity(connectedAt:identity.connectedAt,engine:identity.engine,rawProfile:identity.rawProfile,bundleData:identity.bundleData,entryBundleData:nil,nodeChainExecutionSource:try data(launch))
    check(IOSNodeChainPresentation.active(forged)==nil,"generic presentation rejects external member claiming paired schema")
   }
   for winner in requested=="auto" ? ["local","server"]:["server"] {
    let rows:[[String:Any]]=capture.members.enumerated().map{["position":$0.offset,"profile_id":$0.element.id,"kind":kinds[$0.offset],"proven":true,"response_ms":1.0]}
    let value:[String:Any]=["stage":"selected","execution":winner,"prefixes":rows,"ready":true,"complete":true,"dns_proven":true,"public_proven":true]
    check(IOSNodeChainPresentation.progress(value,expected:expected,requestedExecution:requested)?.contains("Every captured node and final path verified")==true,"generic progress preserves selected winner and all node proofs")
   }
   let changed=try editProfile(bundles.last!){$0["api_token"]="replacement-final"}
   let stale=try IOSSessionIdentity(connectedAt:identity.connectedAt,engine:identity.engine,rawProfile:identity.rawProfile,bundleData:changed,entryBundleData:nil,nodeChainExecutionSource:identity.nodeChainExecutionSource)
   check(IOSNodeChainPresentation.active(stale)==nil,"generic presentation rejects replaced final private source")
   try fifty.require(model)
   model.iosConnectGeneration=UUID();reject("generic latency replacement generation"){try fifty.require(model)};model.iosConnectGeneration=fifty.selection
   model.nodes[0].routerProfiles[0].name="changed original private member"
   reject("generic latency complete source"){try fifty.require(model)}
   reject("latency initial source change"){_ = try IOSOrderedLatencyCapture(model)}
  }
  let original=try appFixture(fixture(3,"off","server",false)),profile=try JSONDecoder().decode(ClientBundle.self,from:original.last!).routerProfiles[0]
  let valid=profile.multihopNodes!
  let typedSOCKS=["wg","wg","socks5","shadowsocks"].enumerated().map{IOSMultihopNodeSelection(id:"typed-\($0.offset)",mode:$0.element)}
  check(!IOSMultihopNodeSelection.supportsGenericExecution(typedSOCKS),"generic selector cannot borrow complete typed SOCKS")
  let typedOpenVPN=["wg","openvpn","shadowsocks"].enumerated().map{IOSMultihopNodeSelection(id:"typed-openvpn-\($0.offset)",mode:$0.element)}
  check(!IOSMultihopNodeSelection.supportsGenericExecution(typedOpenVPN),"generic selector cannot borrow typed OpenVPN")
  for modes in [["wg"],["wg","hysteria2"],["wg","hysteria2","socks5","shadowsocks"],["wg","hysteria2","openvpn","shadowsocks"],["wg","shadowsocks","wg","shadowsocks"],Array(repeating:"wg",count:8)+["shadowsocks"]] {
   let nodes=modes.enumerated().map{IOSMultihopNodeSelection(id:"original-\($0.offset)",mode:$0.element)}
   check(!IOSMultihopNodeSelection.supportsGenericExecution(nodes),"generic selector refuses unsupported graph shape")
   reject("unsupported generic execution choice"){try IOSMultihopNodeSelection.validate(nodes,execution:"server",entryID:nil,entryMode:nil,exitID:nil,exitMode:nil)}
  }
  reject("invalid generic execution name"){try IOSMultihopNodeSelection.validate(valid,execution:"fastest",entryID:nil,entryMode:nil,exitID:nil,exitMode:nil)}
 }
}
'''


# These new counterfactuals exercise one complete original four-node source.
# The separate original phase retains every full-matrix case and old control.
PREFIX_CONTROLS=SWIFT[:SWIFT.index('@main struct Tests')]+r'''
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ good:Bool,_ name:String){guard good else{fatalError(name)};checks+=1}
 @MainActor static func reject(_ name:String,_ run:()throws->Void){do{try run();fatalError("ACCEPTED "+name)}catch{checks+=1}}
 @MainActor static func main()throws {
  defer{LibboxTestClose()}
  let bundles=try connectFixture("https-connect","awg2-strong","auto",4),final=3
  let capture:IOSNodeChainExecutionCapture
  do{capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"auto")}catch{fatalError("complete CONNECT execution source refused: \(error)")}
  defer{try? capture.close()}
  check(capture.members.count==4 && capture.isCONNECT,"complete original four-node typed source")
  let identity:IOSSessionIdentity
  do{identity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:bundles[final],entryBundleData:nil,nodeChainExecutionSource:Data(capture.launchInput.utf8))}catch{fatalError("complete CONNECT session identity refused: \(error)")}
  check(IOSNodeChainPresentation.active(identity)?.map(\.id)==capture.members.map(\.id),"active execution presentation original identities")
  var nodes=capture.members.map{IOSMultihopNodeSelection(id:$0.id,mode:$0.mode)}
  nodes[1].mode="shadowsocks"
  check(!IOSMultihopNodeSelection.supportsCONNECTExecution(nodes),"CONNECT refuses an unpaired later prefix")
  var source=try object(Data(capture.local.launchInput.utf8)),members=source["nodes"] as! [String]
  let member=try object(Data(members[final].utf8))
  var profile=try object(Data((member["profile_json"] as! String).utf8));profile["start_layer"]="aes-256-gcm"
  var failure:NSError?
  let rebuilt:String?=LibboxRouterNodeChainMemberInput(member["mode"] as! String,member["files"] as! String,String(decoding:try data(profile),as:UTF8.self),member["start"] as! String,member["dns_bootstrap"] as! String,&failure)
  check(failure==nil && rebuilt?.isEmpty==false,"private-layer replay uses a newly sealed real member input")
  members[final]=rebuilt!;source["nodes"]=members
  reject("execution private replay final layer"){_ = try IOSNodeChainCONNECTCapture.open(String(decoding:try data(source),as:UTF8.self),selectionExecution:"auto")}
  print("PASS Apple complete CONNECT focused source: \(checks) checks")
 }
}
'''

def main(phase="original"):
    if phase not in ("original", "complete-prefix"):
        raise ValueError("unknown Apple CONNECT source phase")
    launch=(APP/'IOSNodeChainLaunch.swift').read_text()
    route=launch.split('@MainActor\nextension RouterVPNModel')[0]
    model=F.BOUNDARY.replace('// ORIGINAL_CAPTURE',F.member(launch,'    func captureIOSOrderedRoute('))
    latency=(APP/'IOSOrderedLatency.swift').read_text().split('private final class IOSOrderedLatencyReply')[0].replace('import Combine\n','').replace('@preconcurrency import NetworkExtension\n','')
    with tempfile.TemporaryDirectory(prefix='.ios-connect-execution-',dir=ROOT) as gd,tempfile.TemporaryDirectory(prefix='ios-connect-execution-') as wd:
        gd,work=Path(gd),Path(wd);(gd/'main.go').write_text(E.GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(gd/'main.go')],cwd=ROOT,check=True,timeout=180)
        (work/'Libbox.swift').write_text(LIBBOX);(work/'CryptoKit.swift').write_text(E.CRYPTO);(work/'Tests.swift').write_text(SWIFT if phase == 'original' else PREFIX_CONTROLS);(work/'Latency.swift').write_text(route+model+latency)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        suffix='.dylib' if platform.system()=='Darwin' else '.so'
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(work/'Libbox.swift'),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(work/('libLibbox'+suffix))],check=True,timeout=90)
        link=['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        subprocess.run(options+link+['-emit-module','-emit-library','-module-name','CryptoKit',str(work/'CryptoKit.swift'),'-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/('libCryptoKit'+suffix))],check=True,timeout=90)
        presentation=APP/'IOSNodeChainPresentation.swift';presented=presentation.read_text();presentationCopy=work/'Presentation.swift';presentationCopy.write_text(presented)
        models=(APP/'Models.swift').read_text();modelsCopy=work/'Models.swift';modelsCopy.write_text(models)
        connect=(APP/'IOSNodeChainCONNECTCapture.swift').read_text();connectCopy=work/'CONNECT.swift';connectCopy.write_text(connect)
        identity=(APP/'IOSSessionIdentity.swift').read_text();identityCopy=work/'Identity.swift';identityCopy.write_text(identity)
        command=options+link+['-lCryptoKit',str(modelsCopy),str(connectCopy),str(identityCopy)]+[str(APP/n) for n in ('IOSMultihopStartLayer.swift','IOSNodeChainCapture.swift','IOSImportedOpenVPNSource.swift','IOSNodeChainSOCKSCapture.swift','IOSNodeChainProviderCapture.swift')]+[str(presentationCopy),str(work/'Latency.swift')]
        source=APP/'IOSNodeChainExecutionCapture.swift';text=source.read_text();tests=work/'Tests.swift'
        def run(value):
            path=work/'Capture.swift';path.write_text(value);binary=work/'tests'
            subprocess.run(command+[str(path),str(tests),'-o',str(binary)],check=True,timeout=90)
            return subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
        result=run(text);assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip())
        if phase == 'original':
            for name,before,after,witness in (
              ('typed-members','nodes == original["nodes"] as? [String],','true,','ACCEPTED typed native readback local-node'),
              ('typed-identities','identities == original["identity_sources"] as? [String] else {','!identities.isEmpty else {','ACCEPTED typed native readback local-identity'),
              ('final-private-source','guard try canonical(IOSNodeChainCapture.executionProfile(selectedProfile)) == canonical(local.finalProfile) else {\n                throw','guard true else {\n                throw','ACCEPTED changed final private source'),
            ):
                assert text.count(before)==1,name
                result=run(text.replace(before,after,1))
                assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,result.stdout+result.stderr)
                print('Rejected CONNECT execution source control:',name)
            before='Data(original.ordinaryLaunchInput.utf8) == active'
            assert latency.count(before)==1
            (work/'Latency.swift').write_text(route+model+latency.replace(before,'true',1))
            result=run(text)
            assert result.returncode!=0 and 'ACCEPTED latency initial source change' in result.stdout+result.stderr,result.stdout+result.stderr
            print('Rejected CONNECT execution source control: latency-original-source')
            (work/'Latency.swift').write_text(route+model+latency)
            start=presented.index('    private static func capturedGenericExecution(')
            end=presented.index('    private static func capturedSOCKS(',start)
            section=presented[start:end]
            for name,before,after,witness in (
                ('original-final-presentation','guard last == expected else { return nil }','guard true else { return nil }','generic presentation rejects replaced final private source'),
                ('paired-schema-presentation','value.normalizedNodeKind == "router-vpn", value.external == nil','true','generic presentation rejects external member claiming paired schema'),
            ):
                assert section.count(before)==1
                presentationCopy.write_text(presented[:start]+section.replace(before,after,1)+presented[end:])
                result=run(text)
                assert result.returncode!=0 and witness in result.stdout+result.stderr,result.stdout+result.stderr
                print('Rejected generic execution source control:',name)
            presentationCopy.write_text(presented)
            return
        before='(3...IOSMultihopNodeSelection.maximumNodes).contains(bundles.count) else { throw issue() }'
        assert connect.count(before)==1
        connectCopy.write_text(connect.replace(before,'bundles.count == 3 else { throw issue() }',1))
        result=run(text)
        assert result.returncode!=0 and 'complete CONNECT execution source refused' in result.stdout+result.stderr,result.stdout+result.stderr
        print('Rejected CONNECT complete-prefix control: original-trio-capture')
        connectCopy.write_text(connect)
        before='schema == 4 && (3...8).contains(nodes.count)'
        assert identity.count(before)==1
        identityCopy.write_text(identity.replace(before,'schema == 4 && nodes.count == 3',1))
        result=run(text)
        assert result.returncode!=0 and 'complete CONNECT session identity refused' in result.stdout+result.stderr,result.stdout+result.stderr
        print('Rejected CONNECT complete-prefix control: original-trio-session')
        identityCopy.write_text(identity)
        before='try IOSMultihopStartLayer.validateExit(members[members.count - 1].profile)'
        assert connect.count(before)==1
        connectCopy.write_text(connect.replace(before,'// Omitted original final execution-layer admission.',1))
        result=run(text)
        assert result.returncode!=0 and 'ACCEPTED execution private replay final layer' in result.stdout+result.stderr,result.stdout+result.stderr
        print('Rejected CONNECT complete-prefix control: private-replay-final-layer')
        connectCopy.write_text(connect)
        start=presented.index('    private static func capturedCONNECT(');end=presented.index('    /// Progress durations',start)
        section=presented[start:end];before='["local", "server", "auto"].contains(selectionExecution),'
        assert section.count(before)==1
        presentationCopy.write_text(presented[:start]+section.replace(before,'selectionExecution == "local" || inputs.count == 3,',1)+presented[end:])
        result=run(text)
        assert result.returncode!=0 and 'active execution presentation original identities' in result.stdout+result.stderr,result.stdout+result.stderr
        print('Rejected CONNECT complete-prefix control: original-trio-presentation')
        presentationCopy.write_text(presented)
        start=models.index('    static func supportsCONNECTExecution(');end=models.index('    /// The shared generic execution compiler',start)
        section=models[start:end];before='nodes.dropLast(2).allSatisfy({ supportsNativePrefix($0.mode) })'
        assert section.count(before)==1
        modelsCopy.write_text(models[:start]+section.replace(before,'supportsNativePrefix(nodes[0].mode)',1)+models[end:])
        result=run(text)
        assert result.returncode!=0 and 'CONNECT refuses an unpaired later prefix' in result.stdout+result.stderr,result.stdout+result.stderr
        print('Rejected CONNECT complete-prefix control: later-paired-prefix')
if __name__=='__main__':main()
