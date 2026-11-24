#!/usr/bin/env python3
"""Actual typed saved-source prefix, provider and future-profile composition.

The framed ABI executes the real shared constructors. It does not start a
PacketTunnel or establish native traffic, candidate authentication or PMTU.
"""
import test_ios_node_candidate_prefix_capture as C
from test_ios_startup_policy import member

# The source route is already compiled by the actual shared family constructor.
# Only the app's record-store/selector boundary is supplied here; the candidate
# dispatcher itself is extracted verbatim from the shipping app.
APP_DISPATCH = r'''
@MainActor enum CandidateRouteBoundary {
 case ordinary(IOSNodeChainCapture), socks(IOSNodeChainSOCKSCapture), connect(IOSNodeChainCONNECTCapture), execution
 func close()throws{switch self{case .ordinary(let v):try v.plan.close();case .socks(let v):try v.plan.close();case .connect(let v):try v.plan.close();case .execution:break}}
}
@MainActor enum IOSRuntimeSelector {static func selectNodeChain(_ route:CandidateRouteBoundary)throws->Bool{true}}
@MainActor final class RouterVPNModel {
 let route:CandidateRouteBoundary
 init(_ route:CandidateRouteBoundary){self.route=route}
 func captureIOSOrderedRoute(_ selected:ClientBundle)throws->CandidateRouteBoundary{route}
 // SHIPPING_CANDIDATE_DISPATCH
}
'''.replace('// SHIPPING_CANDIDATE_DISPATCH', member((C.APP/'IOSNodeCandidates.swift').read_text(), '    func captureIOSCandidateOriginal('))

SWIFT = C.SWIFT[:C.SWIFT.index('@MainActor @main struct Tests')] + APP_DISPATCH + r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ value:@autoclosure ()throws->Bool)throws{guard try value()else{throw NSError(domain:"TypedPrefixCheck",code:1,userInfo:[NSLocalizedDescriptionKey:name])};checks+=1}
 static func reject(_ name:String,_ action:()throws->Void)throws{do{try action()}catch{checks+=1;return};throw NSError(domain:"TypedPrefixCheck",code:1,userInfo:[NSLocalizedDescriptionKey:"ACCEPTED "+name])}
 static func main(){defer{LibboxTestClose()};do{try run();print("Apple typed saved-prefix source/provider/proposal: \(checks) checks PASS")}
 catch{FileHandle.standardError.write(Data(("FAIL after \(checks): \(error.localizedDescription)\n").utf8));exit(1)}}
 static func fixture(_ count:Int,_ kind:String)throws->[Data]{
  let middle=count-2,final=count-1,id="saved-typed-middle"
  var bundles=try sources(count,"off",true).map{try editProfile($0){p in
   p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""
  }}
  var importedProfile=try profile(bundles[middle]);importedProfile["id"]=id;importedProfile["node_kind"]="external";importedProfile.removeValue(forKey:"node_proof_id")
  importedProfile["router_api"]="";importedProfile["api_token"]="";importedProfile["endpoint"]="203.0.113.20";importedProfile["start_layer"]="off"
  var credentials:[String:Any]=["host":"203.0.113.20","port":8443,"username":"captured-user","password":"captured:password"]
  if kind=="https-connect"{credentials["tls_server_name"]="Original.Proxy.Example"}
  importedProfile["external"]=["protocol":kind,"expected_public_ip":"203.0.113.76",kind.replacingOccurrences(of:"-",with:"_"):credentials]
  bundles[middle]=try data(["selectedRouterID":id,"routerProfiles":[importedProfile],"profiles":[String:[String:String]]()])
  bundles[final]=try editProfile(bundles[final]){p in
   var nodes=p["multihop_nodes"] as! [[String:Any]]
   for i in 0..<middle{nodes[i]["mode"]=["wg","awg2-fast","awg2-strong"][i%3]}
   nodes[middle]=["id":id,"mode":kind];p["multihop_nodes"]=nodes
   p["dns_mode"]="custom";p["dns_protocol"]="tcp";p["dns_host"]="10.82.0.53";p["dns_port"]=5353
  }
  var root=try object(bundles[final]),assets=root["profiles"] as! [String:[String:String]]
  var graph=try object(Data(base64Encoded:assets["shadowsocks"]!["sing-box.json"]!)!)
  graph["dns"]=["servers":[["type":"tcp","tag":"home-dns","server":"10.82.0.53","server_port":5353,"detour":"proxy"]],"final":"home-dns"]
  assets["shadowsocks"]!["sing-box.json"]=try data(graph).base64EncodedString();root["profiles"]=assets
  bundles[final]=Data(try LibboxTestCONNECTService(String(decoding:try data(root),as:UTF8.self)).utf8)
  return bundles
 }
 static func original(_ bundles:[Data],_ kind:String)throws->IOSNodeCandidateOriginalCapture{
  let route:CandidateRouteBoundary
  if kind=="socks5"{route = .socks(try IOSNodeChainSOCKSCapture.compile(bundles:bundles))}
  else{route = .connect(try IOSNodeChainCONNECTCapture.compile(bundles:bundles))}
  let selected=try JSONDecoder().decode(ClientBundle.self,from:bundles.last!)
  return try RouterVPNModel(route).captureIOSCandidateOriginal(selected)
 }
 static func run()throws{
  for kind in ["socks5","http-connect","https-connect"] {for count in [3,4,8] {
   let bundles=try fixture(count,kind),saved=try original(bundles,kind);defer{try? saved.close()}
   try reject("execution preparation cannot grant candidate prefix purpose"){_ = try RouterVPNModel(.execution).captureIOSCandidateOriginal(JSONDecoder().decode(ClientBundle.self,from:bundles.last!))}
   try check("typed original is complete and Local",saved.requiresIndependentPrefix && saved.selectionExecution=="local" && saved.members.count==count)
   let connected=try IOSNodeCandidateOriginalCapture.reopenConnected(saved.launchInput,selectedProfile:saved.members.last!.profile,sourceSHA256:saved.sourceSHA256,configSHA256:saved.configSHA256);defer{try? connected.close()}
   try check("connected proposal retains full typed source",connected.launchInput==saved.launchInput && connected.members.count==count && connected.preparationKind(at:0)==saved.preparationKind(at:0))
   try reject("connected source digest substitution"){_ = try IOSNodeCandidateOriginalCapture.reopenConnected(saved.launchInput,selectedProfile:saved.members.last!.profile,sourceSHA256:String(repeating:"0",count:64),configSHA256:saved.configSHA256)}
   try reject("connected config digest substitution"){_ = try IOSNodeCandidateOriginalCapture.reopenConnected(saved.launchInput,selectedProfile:saved.members.last!.profile,sourceSHA256:saved.sourceSHA256,configSHA256:String(repeating:"0",count:64))}
   let records=Dictionary(uniqueKeysWithValues:try bundles.map{(try profile($0)["id"] as! String,$0)})
   let directory=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
   try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:false);defer{try? FileManager.default.removeItem(at:directory)}
   let publication=IOSCandidateCatalogPublication(container:directory);try publication.publish(records)
   let stamp=try publication.current(records:records)
   let proofs=saved.members.enumerated().map{IOSNodeCandidatePrefix(position:$0.offset,profile_id:$0.element.id,node_id:$0.element.profile["node_proof_id"] as? String ?? "",mode:$0.element.mode)}
   for position in Array(Set([0,count-3])).sorted(){
    let inventory=try IOSNodeCandidateCapture.compile(records:records,stamp:stamp,prefixPosition:position,proofs:proofs)
    let text=String(decoding:inventory.inventory,as:UTF8.self)
    let request=UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased(),owner=UUID(),epoch=UUID()
    let publicationSource=try publication.capture(request:request,inventory:inventory.inventory,expected:stamp)
    let prefix:IOSNodeCandidatePrefixCapture
    do{prefix=try IOSNodeCandidatePrefixCapture.compile(original:saved,position:position,inventory:text)}
    catch{throw NSError(domain:"TypedPrefixCheck",code:2,userInfo:[NSLocalizedDescriptionKey:"typed saved-prefix capture refused original family "+kind])}
    defer{try? prefix.native.close()}
    try check("typed prefix keeps complete original",prefix.originalLaunchInput==saved.launchInput && prefix.originalSourceSHA256==saved.sourceSHA256)
    try check("typed prefix executes only selected paired identities",prefix.metadata.prefixes.map(\.profile_id)==saved.members.prefix(position+1).map(\.id))
    try check("typed prefix cannot open application or DNS",!prefix.metadata.ready && !prefix.metadata.application_open && !prefix.metadata.dns_open && prefix.metadata.stage=="pending-prefix-proof")
    try check("typed suffix credentials remain absent from runnable config",!prefix.config.contains("captured:password") && !prefix.config.contains("203.0.113.20"))
    let launch=try object(Data(prefix.launchInput.utf8))
    try check("typed preparation has distinct outer kind",launch["kind"] as? String==saved.preparationKind(at:position))
    let final=saved.members.last!
    let reopened=try IOSNodeCandidatePrefixCapture.reopen(prefix.launchInput,originalInput:saved.launchInput,selectedProfile:final.profile,position:position,inventory:text);defer{try? reopened.native.close()}
    try check("typed strict launch replay retains exact config",reopened.launchInput==prefix.launchInput && reopened.config==prefix.config && reopened.captureSHA256==prefix.captureSHA256)
    let configuration=try IOSNodeCandidatePrefixProviderCapture.configuration(capture:prefix,bundle:bundles.last!,owner:owner,epoch:epoch,request:request)
    let provider=try IOSNodeCandidatePrefixProviderCapture.reopen(configuration,publication:publication);defer{try? provider.capture.native.close()}
    try check("provider retained original source/publication",provider.capture.originalLaunchInput==saved.launchInput && provider.source.inventory.identity==publicationSource.inventory.identity && provider.owner==owner)
    var changed=configuration,root=try object(bundles.last!),files=root["profiles"] as! [String:[String:String]]
    files[final.mode]=["foreign":"assets"];root["profiles"]=files;changed["bundle"]=try data(root)
    try reject("typed provider foreign final assets"){_ = try IOSNodeCandidatePrefixProviderCapture.reopen(changed,publication:publication)}
    var foreign=final.profile;foreign["api_token"]="replacement"
    try reject("typed provider foreign final identity"){_ = try IOSNodeCandidatePrefixCapture.reopen(prefix.launchInput,originalInput:saved.launchInput,selectedProfile:foreign,position:position,inventory:text)}
    var wrongKind=launch;wrongKind["kind"]="routervpn-node-chain-candidate-preparation"
    try reject("typed prefix cannot reopen as ordinary"){_ = try IOSNodeCandidatePrefixCapture.reopen(String(decoding:try data(wrongKind),as:UTF8.self),originalInput:saved.launchInput,selectedProfile:final.profile,position:position,inventory:text)}
    for excluded in [count-2,count-1] {
     try reject("typed suffix cannot become prefix"){_ = try IOSNodeCandidatePrefixCapture.compile(original:saved,position:excluded,inventory:text)}
    }
    var replacementRoot=try object(bundles[count-2]),replacementProfile=try profile(bundles[count-2])
    replacementProfile["id"]="replacement-typed-middle"
    replacementRoot["routerProfiles"]=[replacementProfile];replacementRoot["selectedRouterID"]="replacement-typed-middle"
    var replacementRecords=records;replacementRecords["replacement-typed-middle"]=try data(replacementRoot)
    let replacementInput=try IOSNodeCandidateCapture.member(profile:replacementProfile,files:[:])
    if position==count-3 {
     let changed=try IOSNodeCandidateProposal.compile(original:saved,records:replacementRecords,position:position,candidateID:"replacement-typed-middle",measuredInput:replacementInput)
     var expected=saved.members.map(\.id);expected[position+1]="replacement-typed-middle"
     try check("typed measured replacement changes exactly one member",changed.profiles.map(\.id)==expected && changed.profiles.last?.multihopNodes?.map(\.id)==expected)
     var stalePrefix=replacementRecords;stalePrefix[saved.members[0].id]=try editProfile(bundles[0]){$0["home_lan_access"]=false}
     try reject("typed proposal stale original prefix"){_ = try IOSNodeCandidateProposal.compile(original:saved,records:stalePrefix,position:position,candidateID:"replacement-typed-middle",measuredInput:replacementInput)}
    }
    guard let candidate=inventory.rows.first(where:{$0.id=="saved-typed-middle" && !$0.input.isEmpty})else{throw IOSNodeCandidateCapture.issue()}
    if position == count-3 {
     let proposal=try IOSNodeCandidateProposal.compile(original:saved,records:records,position:position,candidateID:candidate.id,measuredInput:candidate.input)
     let proposed=try object(Data(proposal.launchInput.utf8)),prior=try object(Data(saved.launchInput.utf8))
     try check("typed future proposal retains measured prefix bytes",Array((proposed["nodes"] as! [String]).prefix(position+1))==Array((prior["nodes"] as! [String]).prefix(position+1)))
     try check("typed future proposal retains all original identities",proposed["identity_sources"] as! [String]==prior["identity_sources"] as! [String])
     try check("typed future profile keeps complete order, family and selected DNS",proposal.profiles.map(\.id)==saved.members.map(\.id) && proposal.profiles.count==count && proposed["schema"] as? Int==(kind=="socks5" ? 3:4) && proposal.profiles.last?.dnsHost=="10.82.0.53")
    } else {
     try reject("typed proposal cannot discard original suffix"){_ = try IOSNodeCandidateProposal.compile(original:saved,records:records,position:position,candidateID:candidate.id,measuredInput:candidate.input)}
    }
    try reject("typed proposal position cannot exceed original prefix"){_ = try IOSNodeCandidateProposal.compile(original:saved,records:records,position:count-2,candidateID:candidate.id,measuredInput:candidate.input)}
    var changedRecords=records;changedRecords[final.id]=try editProfile(bundles.last!){$0["api_token"]="foreign-final"}
    try reject("typed proposal cannot replace original final"){_ = try IOSNodeCandidateProposal.compile(original:saved,records:changedRecords,position:position,candidateID:candidate.id,measuredInput:candidate.input)}
    try provider.storeCandidatesClosed()
    try reject("typed retired publication cannot reopen"){_ = try IOSNodeCandidatePrefixProviderCapture.reopen(configuration,publication:publication)}
    try publication.remove(publicationSource)
   }
  }}
 }
}
'''

FILES = ['Models.swift','IOSMultihopStartLayer.swift','IOSCandidateCatalogPublication.swift',
         'IOSNodeChainCapture.swift','IOSImportedOpenVPNSource.swift','IOSNodeChainProviderCapture.swift',
         'IOSNodeChainSOCKSCapture.swift','IOSNodeChainCONNECTCapture.swift','IOSNodeChainExecutionCapture.swift','IOSNodeCandidateOriginalCapture.swift',
         'IOSNodeCandidateCapture.swift','IOSNodeCandidatePrefixCapture.swift',
         'IOSNodeCandidatePrefixProviderCapture.swift','IOSNodeCandidateProposal.swift']
CONTROLS = [
    ('IOSNodeCandidateOriginalCapture.swift', 'original.sourceSHA256 == sourceSHA256, original.configSHA256 == configSHA256',
     'true, original.configSHA256 == configSHA256', 'ACCEPTED connected source digest substitution'),
    ('IOSNodeCandidatePrefixCapture.swift',
     'case .socks: created = LibboxNewRouterNodeChainSOCKSCandidatePreparation',
     'case .socks: created = LibboxNewRouterNodeChainCandidatePreparation',
     'typed saved-prefix capture refused original family socks5'),
    ('IOSNodeCandidatePrefixCapture.swift',
     'case .connect: created = LibboxNewRouterNodeChainCONNECTCandidatePreparation',
     'case .connect: created = LibboxNewRouterNodeChainCandidatePreparation',
     'typed saved-prefix capture refused original family http-connect'),
    ('IOSNodeCandidatePrefixProviderCapture.swift','assets[final.mode] == originalFiles',
     '!originalFiles.isEmpty && !assets.isEmpty','ACCEPTED typed provider foreign final assets'),
]

if __name__ == '__main__':
    C.run_fixture(swift=SWIFT, files=FILES, controls=CONTROLS,
                  go_source=C.prefix_go(C.C.SAVE_GO),
                  libbox_source=C.C.SAVE_LIBBOX + C.LIBBOX[len(C.C.LIBBOX):])
