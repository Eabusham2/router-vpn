#!/usr/bin/env python3
"""Execute the shipping provider handoff against original Go source and files."""
import test_ios_node_candidate_prefix_capture as C
from ios_node_chain_independent_fixture import INDEPENDENT_BUNDLES
SWIFT=C.SWIFT[:C.SWIFT.index('@MainActor @main struct Tests')]+r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ text:String,_ condition:@autoclosure ()throws->Bool)throws{guard try condition()else{throw NSError(domain:"ProviderCheck",code:1,userInfo:[NSLocalizedDescriptionKey:text])};checks+=1}
 static func reject(_ text:String,_ action:()throws->Void)throws{do{try action()}catch{checks+=1;return};throw NSError(domain:"ProviderCheck",code:1,userInfo:[NSLocalizedDescriptionKey:"ACCEPTED "+text])}
 static func main(){defer{LibboxTestClose()};do{try run();print("Apple independent prefix provider: \(checks) shipping source/publication checks PASS")}catch{FileHandle.standardError.write(Data(("FAIL after \(checks): \(error.localizedDescription)\n").utf8));exit(1)}}
 static func independentSources(_ count:Int,_ positions:Set<Int>,_ mode:String="wg",_ layer:String="off",_ ceiling:Int=4096)throws->[Data]{
  var bundles=try sources(count,layer,true)
'''+INDEPENDENT_BUNDLES+r'''
 static func run()throws{
  try run(bundles:sources(4,"off",true))
  let raw=try LibboxTestHysteriaFixture(4,"wg","off")
  var layered=try (JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [Any]).map{try data($0)}
  layered[3]=try editProfile(layered[3]){$0["start_layer"]="aes-256-gcm+xor-whitening"}
  try run(bundles:layered)
  try run(bundles:packetMTU(sources(16),3000))
  for (count,positions) in [(9,[7]),(16,[8,14])] {
   try run(bundles:independentSources(count,Set(1..<count-1)),selectedPositions:positions)
   for packets in count==9 ? [2] : [2,9] {
    let selected=Set([packets-1,packets,count-2]).sorted()
    try run(bundles:independentSources(count,Set(packets..<count-1),"mixed"),selectedPositions:selected)
   }
  }
  let privateSlots:Set<Int>=[3,4,13]
  var saved=try independentSources(16,Set(2..<15).subtracting(privateSlots),"mixed")
  saved[15]=try editProfile(saved[15]){ p in
   var members=p["multihop_nodes"] as! [[String:Any]]
   for index in privateSlots { members[index]["mode"]="shadowsocks" }
   p["multihop_nodes"]=members
  }
  try run(bundles:saved,selectedPositions:[13,14])
 }
 static func run(bundles:[Data],selectedPositions:[Int]?=nil)throws{
  let original=try IOSNodeChainCapture.compile(bundles:bundles);defer{try? original.plan.close()}
  let records=Dictionary(uniqueKeysWithValues:try bundles.map{(try profile($0)["id"] as! String,$0)})
  let directory=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString,isDirectory:true)
  try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:false);defer{try? FileManager.default.removeItem(at:directory)}
  let publication=IOSCandidateCatalogPublication(container:directory);try publication.publish(records)
  let stamp=try publication.current(records:records),proofs=IOSNodeCandidateOriginalCapture.ordinary(original).candidatePrefixes
  for position in selectedPositions ?? (bundles.count > 8 ? [8] : [0,1,2]) {
   if selectedPositions != nil {
    try check("late original imported prefix and suffix keep their native authority",proofs[position].supported(in:proofs) && proofs[position].metric==(proofs[position].mode=="shadowsocks" ? "routed-candidate-response":"routed-tcp-connect") && proofs.last!.measurement==nil)
    let input=Data(original.launchInput.utf8)
    try IOSNodeCandidateOriginalCapture.validateExtendedResponseInfo(input:input,bundle:bundles.last!,proofs:proofs,sourceSHA256:original.sourceSHA256,configSHA256:original.configSHA256);checks+=1
    try reject("live late response lost original configuration"){try IOSNodeCandidateOriginalCapture.validateExtendedResponseInfo(input:input,bundle:bundles.last!,proofs:proofs,sourceSHA256:original.sourceSHA256,configSHA256:String(repeating:"0",count:64))}
    var revoked=proofs;revoked[bundles.count-2].measurement=nil
    try reject("live late response borrowed another prefix"){try IOSNodeCandidateOriginalCapture.validateExtendedResponseInfo(input:input,bundle:bundles.last!,proofs:revoked,sourceSHA256:original.sourceSHA256,configSHA256:original.configSHA256)}
    try reject("late responses need the whole original import family"){_ = try IOSNodeCandidateCapture.compile(records:records,stamp:stamp,prefixPosition:position,proofs:revoked)}
   }
   let compiled=try IOSNodeCandidateCapture.compile(records:records,stamp:stamp,prefixPosition:position,proofs:proofs)
   let request=UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased(),owner=UUID(),epoch=UUID()
   let source=try publication.capture(request:request,inventory:compiled.inventory,expected:stamp)
   let capture=try IOSNodeCandidatePrefixCapture.compile(original:original,position:position,inventory:String(decoding:compiled.inventory,as:UTF8.self));defer{try? capture.native.close()}
   let config=try IOSNodeCandidatePrefixProviderCapture.configuration(capture:capture,bundle:bundles.last!,owner:owner,epoch:epoch,request:request)
   let reopened=try IOSNodeCandidatePrefixProviderCapture.reopen(config,publication:publication);defer{try? reopened.capture.native.close()}
   try check("provider retains exact source and private publication",reopened.capture.launchInput==capture.launchInput && reopened.capture.originalLaunchInput==original.launchInput && reopened.source.inventory.identity==source.inventory.identity)
   try check("provider binds exact temporary owner and epoch",reopened.owner==owner && reopened.epoch==epoch.uuidString && reopened.source.request==request)
   if selectedPositions != nil {
    let meta=reopened.capture.metadata
    let response=proofs[position].metric=="routed-candidate-response"
    let targets=compiled.rows.filter{!$0.input.isEmpty}.map(\.id)
    try check("original provider binds the native role at each measured prefix",(meta.measurement ?? "routed-tcp-connect")==proofs[position].metric && meta.prefixes.count==position+1 && meta.mtu.prefixes.count==meta.prefixes.count && Set(meta.targets.map(\.id))==Set(targets) && (!response || targets==[proofs.last!.profile_id]) && !meta.application_open && !meta.dns_open && !meta.ready)
    for (i, proof) in meta.prefixes.enumerated() {
     try check("original provider retains paired and imported proof order",proof.profile_id==proofs[i].profile_id && proof.node_id==proofs[i].node_id && proof.mode==proofs[i].mode)
    }
    try check("late response provider preserves original source family",try object(Data(capture.launchInput.utf8))["kind"] as? String=="routervpn-node-chain-multiple-imported-candidate-preparation")
   }
   try reopened.requireCurrent();checks+=1
   for key in IOSNodeCandidatePrefixProviderCapture.fields {
    var missing=config;missing.removeValue(forKey:key);try reject("missing purpose "+key){_ = try IOSNodeCandidatePrefixProviderCapture.reopen(missing,publication:publication)}
   }
   for key in ["nodeChainSource","nodeChainExecutionSource","entryBundle","strategy","max_source_sha256","rawProfileID"] {
    var mixed=config;mixed[key]="foreign";try reject("mixed ordinary owner "+key){_ = try IOSNodeCandidatePrefixProviderCapture.reopen(mixed,publication:publication)}
   }
   for (key,value) in [("engine","multihop-libbox"),(IOSNodeCandidatePrefixProviderCapture.ownerKey,"invalid"),(IOSNodeCandidatePrefixProviderCapture.epochKey,"invalid"),(IOSNodeCandidatePrefixProviderCapture.requestKey,String(repeating:"a",count:32))] {
    var foreign=config;foreign[key]=value;try reject("foreign purpose "+key){_ = try IOSNodeCandidatePrefixProviderCapture.reopen(foreign,publication:publication)}
   }
   for value:Any in [true,0.5,-1,bundles.count-1,96] {
    var changed=config;changed[IOSNodeCandidatePrefixProviderCapture.positionKey]=value
    try reject("invalid prefix position"){_ = try IOSNodeCandidatePrefixProviderCapture.reopen(changed,publication:publication)}
   }
   var changed=config,root=try object(bundles.last!),files=root["profiles"] as! [String:[String:String]]
   files[original.members.last!.mode]=["different":"source"];root["profiles"]=files;changed["bundle"]=try data(root)
   try reject("changed complete final native assets"){_ = try IOSNodeCandidatePrefixProviderCapture.reopen(changed,publication:publication)}
   if original.members.last!.mode=="hysteria2" {
    var stale=config;stale["bundle"]=try edit(bundles.last!){var assets=$0["profiles"] as! [String:[String:String]];assets.removeValue(forKey:"shadowsocks");$0["profiles"]=assets}
    try reject("changed complete final outer assets"){_ = try IOSNodeCandidatePrefixProviderCapture.reopen(stale,publication:publication)}
   }
   try reopened.storeCandidatesClosed()
   try reject("retired source cannot relaunch"){_ = try IOSNodeCandidatePrefixProviderCapture.reopen(config,publication:publication)}
   try reject("retired live publication cannot remain current"){try reopened.requireCurrent()}
   try publication.remove(source)
  }
  let compiled=try IOSNodeCandidateCapture.compile(records:records,stamp:stamp,prefixPosition:0,proofs:proofs),request=String(repeating:"c",count:32)
  let source=try publication.capture(request:request,inventory:compiled.inventory,expected:stamp)
  let capture=try IOSNodeCandidatePrefixCapture.compile(original:original,position:0,inventory:String(decoding:compiled.inventory,as:UTF8.self));defer{try? capture.native.close()}
  let config=try IOSNodeCandidatePrefixProviderCapture.configuration(capture:capture,bundle:bundles.last!,owner:UUID(),epoch:UUID(),request:request)
  let retained=try IOSNodeCandidatePrefixProviderCapture.reopen(config,publication:publication);defer{try? retained.capture.native.close()}
  try publication.remove(source);_ = try publication.capture(request:request,inventory:compiled.inventory,expected:stamp)
  try reject("same-byte replacement inventory loses original identity"){try retained.requireCurrent()}
  try publication.publish(records)
  try reject("changed catalog generation loses original identity"){try retained.requireCurrent()}
 }
}
'''
FILES=['Models.swift','IOSMultihopStartLayer.swift','IOSCandidateCatalogPublication.swift','IOSNodeChainCapture.swift','IOSImportedOpenVPNSource.swift','IOSNodeCandidateOriginalCapture.swift','IOSNodeChainProviderCapture.swift','IOSNodeChainSOCKSCapture.swift','IOSNodeChainCONNECTCapture.swift','IOSNodeCandidateCapture.swift','IOSNodeCandidatePrefixCapture.swift','IOSNodeCandidatePrefixProviderCapture.swift']
CONTROLS=[
 ('IOSNodeCandidatePrefixProviderCapture.swift','try final.matchesStartLayer(in: assets),','true,','ACCEPTED changed complete final outer assets'),
 ('IOSNodeCandidatePrefixProviderCapture.swift','Set(configuration.keys) == fields,','true,','ACCEPTED mixed ordinary owner nodeChainSource'),
 ('IOSNodeCandidatePrefixProviderCapture.swift','configuration["engine"] as? String == engine,','true,','ACCEPTED foreign purpose engine'),
 ('IOSNodeCandidatePrefixProviderCapture.swift','assets[final.mode] == originalFiles','!originalFiles.isEmpty && !assets.isEmpty','ACCEPTED changed complete final native assets'),
 ('IOSNodeCandidatePrefixProviderCapture.swift','!publication.closed(epoch: epoch, request: source.request), publication.current(source)','publication.current(source)','ACCEPTED retired live publication cannot remain current'),
 ('IOSNodeCandidatePrefixProviderCapture.swift','!publication.closed(epoch: epoch, request: source.request), publication.current(source)','!publication.closed(epoch: epoch, request: source.request)','ACCEPTED same-byte replacement inventory loses original identity'),
]
if __name__=='__main__':C.run_fixture(swift=SWIFT,files=FILES,controls=CONTROLS)
