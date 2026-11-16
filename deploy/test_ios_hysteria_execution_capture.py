#!/usr/bin/env python3
"""Exercise Apple Hysteria2 Server/Compare with the original shared compiler.

The shipping capture, route selection, latency ownership and map bodies execute.
Native lifecycle, system VPN and live measurements remain refusing boundaries.
Each supported node count retains the existing 180-second process deadline.
"""
import test_ios_socks_execution_capture as S

E = S.E
SWIFT = E.SWIFT[:E.SWIFT.index('@main struct Tests')] + r'''
func hysteriaFixture(_ count:Int,_ first:String,_ requested:String,_ layer:String,_ finalLayer:String="off")throws->[Data]{
 let raw=try LibboxTestHysteriaFixture(count,first,layer)
 var bundles=try appFixture((JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [Any]).map{try data($0)})
 bundles[count-1]=try editProfile(bundles[count-1]){$0["multihop_execution"]=requested;$0["start_layer"]=finalLayer}
 // The original execution helper already captures a 4000-byte packet
 // ceiling for complete independently layered paths; retain those exact assets.
 return bundles
}
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ yes:Bool,_ message:String){checks+=1;if !yes{print("FAIL "+message);exit(1)}}
 @MainActor static func reject(_ name:String,_ run:()throws->Void){do{try run();print("FAIL ACCEPTED "+name);exit(1)}catch{checks+=1}}
 @MainActor static func main()throws{
  defer{LibboxTestClose()}
  guard CommandLine.arguments.count==3,let count=Int(CommandLine.arguments[2]),(2...8).contains(count) else {print("FAIL missing original Hysteria2 phase");exit(1)}
  for mode in ["wg","awg2-fast","awg2-strong"] {for requested in ["server","auto"] {for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   try original(count,mode,requested,layer)
  }}}
  var layeredCases=0
  for (finalIndex,finalLayer) in ["aes-256-gcm","aes-256-gcm+xor-whitening"].enumerated() {
   for (prefixIndex,prefixLayer) in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"].enumerated() {
    let mode=["wg","awg2-fast","awg2-strong"][(prefixIndex+finalIndex)%3],requested=["server","auto"][(prefixIndex+finalIndex)%2]
    try original(count,mode,requested,prefixLayer,finalLayer);layeredCases+=1
   }
  }
  check(layeredCases==6,"complete independent Hysteria2 final layer phase")
  let bundles=try hysteriaFixture(count,"awg2-strong","auto","off")
  for fault in ["config","requested","local-node","local-schema","local-identity","local-execution","preparation-schema","launch-schema","launch-error"] {
   LibboxTestExecutionFault(fault);reject("typed native readback "+fault){_ = try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"auto")}
  }
  for operation in ["local-new","execution-new"] {
   LibboxTestReturnedOwnerError(operation)
   reject("returned Hysteria2 owner plus error "+operation){_ = try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"auto")}
   check(LibboxTestReturnedOwnerClosed(),"returned original Hysteria2 owner closed exactly once: "+operation)
  }
  let capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"auto")
  LibboxTestReturnedOwnerError("execution-open")
  reject("returned Hysteria2 replay plus error"){_ = try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(bundles[count-1]))}
  check(LibboxTestReturnedOwnerClosed(),"returned original Hysteria2 replay closed exactly once")
  try capture.close()
  for badLayer in ["unowned",true,7,NSNull(),["off"],["layer":"off"]] as [Any] {
   var launch=try object(Data(capture.launchInput.utf8)),source=try object(Data((launch["source"] as! String).utf8)),local=try object(Data((source["local_source"] as! String).utf8)),members=local["nodes"] as! [String]
   var member=try object(Data(members[count-1].utf8)),profile=try object(Data((member["profile_json"] as! String).utf8))
   profile["start_layer"]=badLayer;member["profile_json"]=String(decoding:try data(profile),as:UTF8.self);members[count-1]=String(decoding:try data(member),as:UTF8.self)
   local["nodes"]=members;source["local_source"]=String(decoding:try data(local),as:UTF8.self);launch["source"]=String(decoding:try data(source),as:UTF8.self)
   reject("Hysteria2 identity malformed final layer"){_ = try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:"multihop-libbox",rawProfile:"hysteria2",bundleData:bundles[count-1],entryBundleData:nil,nodeChainExecutionSource:try data(launch))}
  }
  for position in bundles.indices {
   var invalid=bundles;invalid[position]=try editProfile(invalid[position]){$0["node_proof_id"]=String(repeating:"f",count:64)}
   reject("independent original identity \(position)"){_ = try IOSNodeChainExecutionCapture.compile(bundles:invalid,requested:"auto")}
  }
  for layer in ["aes-256-gcm+unowned","xor-without-aes"] {
   var invalid=bundles;invalid[count-1]=try editProfile(invalid[count-1]){$0["start_layer"]=layer}
   reject("malformed Hysteria2 final layer "+layer){_ = try IOSNodeChainExecutionCapture.compile(bundles:invalid,requested:"auto")}
  }
  for fault in ["missing-wg","changed-ca","insecure-tls","missing-password","missing-salamander","unknown-mask","nonobject-mask"] {
   var invalid=bundles
   invalid[count-1]=try edit(invalid[count-1]){root in
    var assets=root["profiles"] as! [String:[String:String]]
    if fault=="missing-wg"{assets.removeValue(forKey:"wg")}
    else if fault=="changed-ca"{assets["hysteria2"]!["hy2-ca.pem"]=Data("foreign original CA".utf8).base64EncodedString()}
    else {
     var config=try! object(Data(base64Encoded:assets["hysteria2"]!["sing-box.json"]!)!),outs=config["outbounds"] as! [[String:Any]],hy2=outs[0]
     if fault=="insecure-tls"{var tls=hy2["tls"] as! [String:Any];tls["insecure"]=true;hy2["tls"]=tls}
     if fault=="missing-password"{hy2["password"]=""}
     if fault=="missing-salamander"{var obfs=hy2["obfs"] as! [String:Any];obfs["password"]="";hy2["obfs"]=obfs}
     if fault=="unknown-mask"{var obfs=hy2["obfs"] as! [String:Any];obfs["type"]="unknown-mask";hy2["obfs"]=obfs}
     if fault=="nonobject-mask"{hy2["obfs"]="salamander"}
     outs[0]=hy2;config["outbounds"]=outs;assets["hysteria2"]!["sing-box.json"]=(try! data(config)).base64EncodedString()
    }
    root["profiles"]=assets
   }
   reject("original Hysteria2 authority "+fault){_ = try IOSNodeChainExecutionCapture.compile(bundles:invalid,requested:"auto")}
  }
  for mask in ["absent","null","salamander","gecko"] {
   var selected=bundles
   selected[count-1]=try edit(selected[count-1]){root in
    var assets=root["profiles"] as! [String:[String:String]],config=try! object(Data(base64Encoded:assets["hysteria2"]!["sing-box.json"]!)!),outs=config["outbounds"] as! [[String:Any]],hy2=outs[0]
    if mask=="absent"{hy2.removeValue(forKey:"obfs")}
    else if mask=="null"{hy2["obfs"]=NSNull()}
    else{hy2["obfs"]=["type":mask,"password":"original-selected-obfuscation"]}
    outs[0]=hy2;config["outbounds"]=outs;assets["hysteria2"]!["sing-box.json"]=(try! data(config)).base64EncodedString();root["profiles"]=assets
   }
   let prepared=try IOSNodeChainExecutionCapture.compile(bundles:selected,requested:"auto");defer{try? prepared.close()}
   guard case .ordinary(let local)=prepared.local else{fatalError("original paired Hysteria2 source required")}
   let hy2=(try object(Data(local.config.utf8))["outbounds"] as! [[String:Any]]).first{$0["type"] as? String=="hysteria2"}!
   if mask=="absent"{check(hy2["obfs"]==nil,"optional absent Hysteria2 mask preserved")}
   else if mask=="null"{check(hy2["obfs"] is NSNull,"optional null Hysteria2 mask preserved")}
   else{let obfs=hy2["obfs"] as! [String:Any];check(obfs["type"] as? String==mask && obfs["password"] as? String=="original-selected-obfuscation","selected native Hysteria2 mask remains exact")}
   check(!prepared.healthy(),"optional source mask grants no native proof")
  }
  for modes in [["hysteria2"],["hysteria2","hysteria2"],["wg","shadowsocks","hysteria2"],["wg","socks5","hysteria2"],["wg","https-connect","hysteria2"],["wg","openvpn","hysteria2"],Array(repeating:"wg",count:8)+["hysteria2"]] {
   let nodes=modes.enumerated().map{IOSMultihopNodeSelection(id:"original-\($0.offset)",mode:$0.element)}
   check(!IOSMultihopNodeSelection.supportsServerExecution(nodes),"Hysteria2 rejects unsupported ordered roles")
  }
  print("PASS Apple Hysteria2 execution source nodes=\(count): \(checks) original source and consumer checks")
 }
 @MainActor static func original(_ count:Int,_ first:String,_ requested:String,_ layer:String,_ finalLayer:String="off")throws{
  let bundles=try hysteriaFixture(count,first,requested,layer,finalLayer)
  let typed=try JSONDecoder().decode(ClientBundle.self,from:bundles[count-1]).routerProfiles[0],refs=typed.multihopNodes!
  check(IOSMultihopNodeSelection.supportsGenericExecution(refs) && IOSMultihopNodeSelection.supportsServerExecution(refs) && !IOSMultihopNodeSelection.supportsSOCKSExecution(refs) && !IOSMultihopNodeSelection.supportsCONNECTExecution(refs) && !IOSMultihopNodeSelection.supportsOpenVPNExecution(refs),"distinct public Hysteria2 choice")
  try IOSMultihopNodeSelection.validate(refs,execution:requested,entryID:nil,entryMode:nil,exitID:nil,exitMode:nil,controlID:typed.id)
  let capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested);defer{try? capture.close()}
  let source=try object(Data(capture.source.utf8)),launch=try object(Data(capture.launchInput.utf8)),local=try object(Data((source["local_source"] as! String).utf8))
  check(!capture.isOpenVPN && !capture.isSOCKS && !capture.isCONNECT && source["schema"] as? Int==1 && source["execution"] as? String==requested,"original Hysteria2 preparation family and choice")
  check(launch["kind"] as? String=="routervpn-node-chain-execution-preparation-input" && local["schema"] as? Int==1 && local["execution"] as? String=="local","original generic source retains its paired shape")
  check(capture.members.map(\.id)==refs.map(\.id) && capture.members.map(\.mode)==refs.map(\.mode),"Hysteria2 retains all ordered modes and identities")
  let identities=local["identity_sources"] as! [String]
  for position in bundles.indices {
   let root=try object(bundles[position]),assets=root["profiles"] as! [String:[String:String]],member=capture.members[position]
   check(try data(object(Data(identities[position].utf8)))==data(assets["wg"]!),"independent original standard WG identity \(position)")
   check(try data(object(Data(member.filesJSON.utf8)))==data(assets[member.mode]!),"all original transport credentials and TLS assets \(position)")
  }
  guard case .ordinary(let original)=capture.local else {print("FAIL Hysteria2 substituted an imported preparation");exit(1)}
  let graph=try object(Data(original.config.utf8)),outs=graph["outbounds"] as! [[String:Any]],hy2=outs.first{$0["type"] as? String=="hysteria2"}!,tls=hy2["tls"] as! [String:Any]
  let assets=try object(bundles[count-1])["profiles"] as! [String:[String:String]],files=assets["hysteria2"]!,saved=(try object(Data(base64Encoded:files["sing-box.json"]!)!)["outbounds"] as! [[String:Any]])[0]
  let actualObfs=try data(hy2["obfs"]!),savedObfs=try data(saved["obfs"]!)
  check(hy2["password"] as? String==saved["password"] as? String && actualObfs==savedObfs,"original Hysteria2 password and Salamander")
  check(tls["server_name"] as? String=="ordered-final.example.test" && tls["certificate"] as? [String]==[String(decoding:Data(base64Encoded:files["hy2-ca.pem"]!)!,as:UTF8.self)] && tls["insecure"] as? Bool != true,"original Hysteria2 TLS trust and name")
  let dns=graph["dns"] as! [String:Any],servers=dns["servers"] as! [[String:Any]],selected=servers.first{$0["tag"] as? String==dns["final"] as? String}!
  check(selected["server"] as? String==typed.adGuardIPv4 && selected["detour"] as? String==hy2["tag"] as? String,"Hysteria2 retains selected exit-routed Home DNS")
  check(capture.members.dropLast().allSatisfy{$0.profile["start_layer"] as? String==layer} && capture.finalProfile["start_layer"] as? String==finalLayer,"original independent prefix and final layer policies")
  if finalLayer != "off" {
   let finalTag=hy2["tag"] as! String,outerTag=hy2["detour"] as! String,outer=outs.first{$0["tag"] as? String==outerTag}!
   let outerFiles=assets["shadowsocks"]!,savedOuter=(try object(Data(base64Encoded:outerFiles["sing-box.json"]!)!)["outbounds"] as! [[String:Any]])[0]
   check(hy2["server"] as? String=="127.0.0.1" && hy2["server_port"] as? Int==saved["server_port"] as? Int && outer["type"] as? String==(finalLayer=="aes-256-gcm" ? "shadowsocks":"routervpn-aes-xor"),"original inner QUIC tuple and independent outer owner")
   check(outer["password"] as? String==savedOuter["password"] as? String && outer["password"] as? String != hy2["password"] as? String && outer["method"] as? String==savedOuter["method"] as? String && outer["server"] as? String==typed.endpoint,"original independent outer key method and destination")
   let endpoints=graph["endpoints"] as! [[String:Any]],preceding=endpoints.last!["tag"] as! String
   check(outer["detour"] as? String==preceding && hy2["detour"] as? String != preceding && selected["detour"] as? String==finalTag,"only original outer traverses complete packet prefix")
  }
  check(!capture.healthy() && !capture.nativeClosed(),"source preparation grants no native readiness or retirement")
  reject("Local capture cannot consume Server selection"){_ = try IOSNodeChainCapture.compile(bundles:bundles)}
  reject("source-only native restoration"){_ = try capture.captureRestoration()}
  let replay=try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(bundles[count-1]));defer{try? replay.close()}
  check(replay.source==capture.source && replay.config==capture.config && replay.launchInput==capture.launchInput,"canonical complete Hysteria2 replay")
  let identity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:"multihop-libbox",rawProfile:"hysteria2",bundleData:bundles[count-1],entryBundleData:nil,nodeChainExecutionSource:Data(capture.launchInput.utf8))
  for wrong in ["shadowsocks","openvpn","xhttp"] {
   reject("Hysteria2 identity mismatched final transport "+wrong){_ = try IOSSessionIdentity(connectedAt:identity.connectedAt,engine:identity.engine,rawProfile:wrong,bundleData:identity.bundleData,entryBundleData:nil,nodeChainExecutionSource:identity.nodeChainExecutionSource)}
  }
  let nodes=try bundles.map{try JSONDecoder().decode(ClientBundle.self,from:$0)},model=RouterVPNModel(nodes,identity:identity),fifty=try IOSOrderedLatencyCapture(model)
  check(fifty.source==capture.sourceSHA256 && fifty.config==capture.configSHA256 && fifty.ids==capture.members.map(\.id) && fifty.kinds==Array(repeating:"private-node",count:count),"Hysteria2 measurements capture original complete path and ownership")
  check(IOSNodeChainPresentation.active(identity)?.map(\.mode)==refs.map{Optional($0.mode)} && IOSNodeChainPresentation.planned(selected:typed,catalog:nodes.flatMap(\.routerProfiles))?.map(\.mode)==refs.map{Optional($0.mode)},"Hysteria2 planned and active map retains all exact transports")
  let changed=try editProfile(bundles[count-1]){$0["api_token"]="foreign-final-source"}
  reject("changed final private source"){_ = try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(changed))}
  let stale=try IOSSessionIdentity(connectedAt:identity.connectedAt,engine:identity.engine,rawProfile:identity.rawProfile,bundleData:changed,entryBundleData:nil,nodeChainExecutionSource:identity.nodeChainExecutionSource)
  check(IOSNodeChainPresentation.active(stale)==nil,"Hysteria2 presentation rejects replaced final private source")
  try fifty.require(model);model.iosConnectGeneration=UUID();reject("Hysteria2 measurement replacement owner"){try fifty.require(model)}
 }
}
'''


def main():
    S.main(swift=SWIFT, family='Hysteria2')


if __name__ == '__main__':
    main()
