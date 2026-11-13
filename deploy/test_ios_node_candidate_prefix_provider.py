#!/usr/bin/env python3
"""Execute the shipping provider handoff against original Go source and files."""
import test_ios_node_candidate_prefix_capture as C
SWIFT=C.SWIFT[:C.SWIFT.index('@MainActor @main struct Tests')]+r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ text:String,_ condition:@autoclosure ()throws->Bool)throws{guard try condition()else{throw NSError(domain:"ProviderCheck",code:1,userInfo:[NSLocalizedDescriptionKey:text])};checks+=1}
 static func reject(_ text:String,_ action:()throws->Void)throws{do{try action()}catch{checks+=1;return};throw NSError(domain:"ProviderCheck",code:1,userInfo:[NSLocalizedDescriptionKey:"ACCEPTED "+text])}
 static func main(){defer{LibboxTestClose()};do{try run();print("Apple independent prefix provider: \(checks) shipping source/publication checks PASS")}catch{FileHandle.standardError.write(Data(("FAIL after \(checks): \(error.localizedDescription)\n").utf8));exit(1)}}
 static func run()throws{
  let bundles=try sources(4,"off",true),original=try IOSNodeChainCapture.compile(bundles:bundles);defer{try? original.plan.close()}
  let records=Dictionary(uniqueKeysWithValues:try bundles.map{(try profile($0)["id"] as! String,$0)})
  let directory=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString,isDirectory:true)
  try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:false);defer{try? FileManager.default.removeItem(at:directory)}
  let publication=IOSCandidateCatalogPublication(container:directory);try publication.publish(records)
  let stamp=try publication.current(records:records),proofs=original.members.enumerated().map{IOSNodeCandidatePrefix(position:$0.offset,profile_id:$0.element.id,node_id:$0.element.profile["node_proof_id"] as! String,mode:$0.element.mode)}
  for position in 0..<3 {
   let compiled=try IOSNodeCandidateCapture.compile(records:records,stamp:stamp,prefixPosition:position,proofs:proofs)
   let request=UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased(),owner=UUID(),epoch=UUID()
   let source=try publication.capture(request:request,inventory:compiled.inventory,expected:stamp)
   let capture=try IOSNodeCandidatePrefixCapture.compile(original:original,position:position,inventory:String(decoding:compiled.inventory,as:UTF8.self));defer{try? capture.native.close()}
   let config=try IOSNodeCandidatePrefixProviderCapture.configuration(capture:capture,bundle:bundles.last!,owner:owner,epoch:epoch,request:request)
   let reopened=try IOSNodeCandidatePrefixProviderCapture.reopen(config,publication:publication);defer{try? reopened.capture.native.close()}
   try check("provider retains exact source and private publication",reopened.capture.launchInput==capture.launchInput && reopened.capture.originalLaunchInput==original.launchInput && reopened.source.inventory.identity==source.inventory.identity)
   try check("provider binds exact temporary owner and epoch",reopened.owner==owner && reopened.epoch==epoch.uuidString && reopened.source.request==request)
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
   for value:Any in [true,0.5,-1,7] {
    var changed=config;changed[IOSNodeCandidatePrefixProviderCapture.positionKey]=value
    try reject("invalid prefix position"){_ = try IOSNodeCandidatePrefixProviderCapture.reopen(changed,publication:publication)}
   }
   var changed=config,root=try object(bundles.last!),files=root["profiles"] as! [String:[String:String]]
   files[original.members.last!.mode]=["different":"source"];root["profiles"]=files;changed["bundle"]=try data(root)
   try reject("changed complete final native assets"){_ = try IOSNodeCandidatePrefixProviderCapture.reopen(changed,publication:publication)}
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
FILES=['Models.swift','IOSMultihopStartLayer.swift','IOSCandidateCatalogPublication.swift','IOSNodeChainCapture.swift','IOSNodeCandidateCapture.swift','IOSNodeCandidatePrefixCapture.swift','IOSNodeCandidatePrefixProviderCapture.swift']
CONTROLS=[
 ('IOSNodeCandidatePrefixProviderCapture.swift','Set(configuration.keys) == fields,','true,','ACCEPTED mixed ordinary owner nodeChainSource'),
 ('IOSNodeCandidatePrefixProviderCapture.swift','configuration["engine"] as? String == engine,','true,','ACCEPTED foreign purpose engine'),
 ('IOSNodeCandidatePrefixProviderCapture.swift','assets[final.mode] == originalFiles','!originalFiles.isEmpty && !assets.isEmpty','ACCEPTED changed complete final native assets'),
 ('IOSNodeCandidatePrefixProviderCapture.swift','!publication.closed(epoch: epoch, request: source.request), publication.current(source)','publication.current(source)','ACCEPTED retired live publication cannot remain current'),
 ('IOSNodeCandidatePrefixProviderCapture.swift','!publication.closed(epoch: epoch, request: source.request), publication.current(source)','!publication.closed(epoch: epoch, request: source.request)','ACCEPTED same-byte replacement inventory loses original identity'),
]
if __name__=='__main__':C.run_fixture(swift=SWIFT,files=FILES,controls=CONTROLS)
