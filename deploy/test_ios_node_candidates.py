#!/usr/bin/env python3
"""Run Apple candidate capture via the real shared Go input compiler, plus receipts."""
from pathlib import Path
import os
import platform
import subprocess
import tempfile
import test_ios_node_chain_capture as C
import test_ios_node_chain_execution_capture as E
from test_ios_physical_path import LINUX_CRYPTO
ROOT=C.ROOT
APP=C.APP
GO=C.GO.replace(' case "chain-imported":', ' case "candidate-supported":value=strconv.FormatBool(mobilemultihop.NodeChainCandidateInputSupported(r.Source))\n case "chain-imported":',1)
LIBBOX=C.LIBBOX+r'''
public func LibboxRouterNodeChainCandidateInputSupported(_ source:String)->Bool{(try? bridge(["Op":"candidate-supported","Source":source])) == "true"}
'''
# Keep the exported Local candidate fixture unchanged for prefix consumers.
# This Save gate additionally calls the existing typed execution source union.
SAVE_GO=E.GO.replace(' case "chain-imported":', ' case "candidate-supported":value=strconv.FormatBool(mobilemultihop.NodeChainCandidateInputSupported(r.Source))\n case "chain-imported":',1)
SAVE_LIBBOX=E.LIBBOX+LIBBOX[len(C.LIBBOX):]
SAVE_GO=SAVE_GO.replace(' case "chain-imported":', r''' case "candidate-inventory-metadata":
 var plan interface{MetadataPage(int32) string}
 if r.Mode=="prefix"{plan,err=mobilemultihop.NewNodeChainCandidatePreparation(r.Source,0,r.Policy)}else{
  var original *mobilemultihop.NodeChain;original,err=mobilemultihop.ParseNodeChainLaunchInput(r.Source)
  if err==nil{plan,err=original.NewCandidatePlan(0,r.Policy)}}
 if err==nil{
  var pages []string
  for position:=0;;{raw:=plan.MetadataPage(int32(position));if raw==""{err=fmt.Errorf("missing source-bound candidate page");break};pages=append(pages,raw)
   var page struct{Schema int; Targets []json.RawMessage; Total int `json:"target_total"`}
   if err=json.Unmarshal([]byte(raw),&page);err!=nil{break};position+=len(page.Targets)
   if page.Schema==1 || position==page.Total{break};if len(page.Targets)==0||position>page.Total{err=fmt.Errorf("invalid candidate page");break}}
  if err==nil{var encoded []byte;encoded,err=json.Marshal(pages);value=string(encoded)}}
 case "chain-imported":''',1)
SAVE_LIBBOX+=r'''
public func LibboxTestCandidateInventoryMetadata(_ source:String,_ inventory:String,_ mode:String="ordinary")throws->String{try bridge(["Op":"candidate-inventory-metadata","Source":source,"Policy":inventory,"Mode":mode])}
'''
MULTIPLE_FIXTURE = E.SWIFT[E.SWIFT.index('func multipleFixture('):E.SWIFT.index('@main struct Tests')]
MULTIPLE_FIXTURE = MULTIPLE_FIXTURE.replace('var bundles=try fixture(count,layer,requested,true)', 'var bundles=try sources(count,layer,true);bundles[count-1]=try editProfile(bundles[count-1]){$0["multihop_execution"]=requested}')
SWIFT=C.SWIFT[:C.SWIFT.index('@MainActor @main struct Tests')]+MULTIPLE_FIXTURE+r'''
@MainActor final class IOSNodeBundleStore {
 static let shared=IOSNodeBundleStore()
 func candidateSnapshot()throws->(records:[String:Data],stamp:IOSCandidateCatalogPublication.Stamp){throw NSError(domain:"NoPrivateStoreInCaptureFixture",code:1)}
}
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ value:@autoclosure ()throws->Bool)throws{guard try value()else{throw NSError(domain:"CandidateCheck",code:1,userInfo:[NSLocalizedDescriptionKey:name])};checks+=1}
 static func reject(_ name:String,_ action:()throws->Void)throws{do{try action()}catch{checks+=1;return};throw NSError(domain:"CandidateCheck",code:1,userInfo:[NSLocalizedDescriptionKey:"ACCEPTED "+name])}
 static func main(){defer{LibboxTestClose()};do{if CommandLine.arguments.count==3{if CommandLine.arguments[2]=="capacity"{try largeCatalog(479);try largeCatalog(513);print("Apple complete candidate inventory: \(checks) original source and Go metadata checks PASS");return};try completePaths(CommandLine.arguments[2]);print("Apple complete candidate paths: \(checks) source, execution and retained policy checks PASS");return};try run();print("Apple candidates: \(checks) shipping Swift/shared Go capture and receipt checks PASS")}
 catch{FileHandle.standardError.write(Data(("FAIL after \(checks): \(error.localizedDescription)\n").utf8));exit(1)}}
 static func largeCatalog(_ size:Int)throws {
  let fixture=try sources(3,"off",true).map{try editProfile($0){p in
   p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""
  }}
  let original=try IOSNodeChainCapture.compile(bundles:fixture);defer{try? original.plan.close()}
  let prefix=original.members.enumerated().map{IOSNodeCandidatePrefix(position:$0.offset,profile_id:$0.element.id,node_id:$0.element.profile["node_proof_id"] as! String,mode:$0.element.mode)}
  var records=Dictionary(uniqueKeysWithValues:fixture.enumerated().map{("original-\($0.offset)",$0.element)})
  var expected=Set<String>()
  for index in 0..<size {
   let id=String(format:"linked-candidate-%04d",index);expected.insert(id)
   var custom=try profile(fixture[1]);custom["id"]=id;custom["name"]="Same display name";custom["node_kind"]="external";custom.removeValue(forKey:"node_proof_id")
   custom["router_api"]="";custom["api_token"]="";custom["endpoint"]="198.51.100.76";custom["start_layer"]="off"
   custom["external"]=["protocol":"shadowsocks","expected_public_ip":"203.0.113.76","shadowsocks":["server":"198.51.100.76","port":443,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:0,count:32).base64EncodedString()]]
   records[id]=try data(["selectedRouterID":id,"routerProfiles":[custom],"profiles":[String:[String:String]]()])
  }
  let stamp=IOSCandidateCatalogPublication.Stamp(schema:1,epoch:UUID().uuidString,generation:1,ready:true,sources_sha256:try IOSCandidateCatalogPublication.sourcesDigest(records))
  let catalog=try IOSNodeCandidateCapture.compile(records:records,stamp:stamp,prefixPosition:0,proofs:prefix)
  let captured=Set(catalog.rows.filter{!$0.input.isEmpty}.map(\.id))
  try check("large Apple catalog retains every source after candidate 64",expected.isSubset(of:captured))
  let raw=try LibboxTestCandidateInventoryMetadata(original.launchInput,String(decoding:catalog.inventory,as:UTF8.self))
  let frames=try JSONDecoder().decode([String].self,from:Data(raw.utf8))
  try check("large catalog uses original bounded native frames",frames.count>1 && frames.allSatisfy{$0.utf8.count<=12*1024})
  var pages=try IOSCandidateMetadataPages(frames[0],inventoryBytes:catalog.inventory.count,legacyLimit:32768)
  for frame in frames.dropFirst(){try pages.append(frame)}
  let metadata=try JSONDecoder().decode(IOSNodeCandidateMetadata.self,from:pages.result())
  try check("native paged rows preserve complete original order",metadata.targets.map(\.id)==catalog.rows.filter{!$0.input.isEmpty}.map(\.id))
  try metadata.validate(prefix:prefix[0],source:original.sourceSHA256,config:original.configSHA256,ids:captured)
  try check("large Apple metadata retains distinct original identities",Set(metadata.targets.map(\.id))==captured)
  guard let plain=original.originalSource else{throw NSError(domain:"missing original source",code:1)}
  let prep=try LibboxTestCandidateInventoryMetadata(plain,String(decoding:catalog.inventory,as:UTF8.self),"prefix")
  let prefixFrames=try JSONDecoder().decode([String].self,from:Data(prep.utf8))
  var prefixPages=try IOSCandidateMetadataPages(prefixFrames[0],inventoryBytes:catalog.inventory.count,legacyLimit:65536,family:.preparation)
  for frame in prefixFrames.dropFirst(){try prefixPages.append(frame)}
  let prefixData=try prefixPages.result(), prefixMetadata=try JSONDecoder().decode(IOSNodeCandidateMetadata.self,from:prefixData)
  let prefixBody=try JSONSerialization.jsonObject(with:prefixData) as! [String:Any]
  try check("large private prefix preserves original source and exact complete inventory",prefixFrames.count>1 && prefixMetadata.targets.map(\.id)==metadata.targets.map(\.id) && prefixBody["original_source_sha256"] as? String==original.sourceSHA256 && prefixBody["ready"] as? Bool==false)
  var changed=records
  changed["linked-candidate-0128"]=try editProfile(records["linked-candidate-0128"]!){p in
   var external=p["external"] as! [String:Any],transport=external["shadowsocks"] as! [String:Any]
   transport["password"]=Data(repeating:1,count:32).base64EncodedString();external["shadowsocks"]=transport;p["external"]=external
  }
  try reject("off-page private source mutation invalidates whole Apple revision"){_ = try IOSNodeCandidateCapture.compile(records:changed,stamp:stamp,prefixPosition:0,proofs:prefix)}
 }
 static func completePaths(_ requested:String)throws {
  for count in [4,8] {for kind in ["shadowsocks","socks5","http-connect","https-connect"] {
   var fixture=try sources(count,"off",true).map{try editProfile($0){p in
    p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""
   }}
   fixture[count-1]=try editProfile(fixture[count-1]){p in p["multihop_execution"]=requested;p["startup_mode"]="smart-auto";p["auto_connect"]=true}
   fixture[count-1]=Data(try LibboxTestCONNECTService(String(decoding:fixture[count-1],as:UTF8.self)).utf8)
   let original:IOSNodeChainCapture
   if requested=="local"{original=try IOSNodeChainCapture.compile(bundles:fixture)}else{original=try IOSNodeChainCapture.compileOriginalForExecution(bundles:fixture,requested:requested)}
   defer{try? original.plan.close()}
   var custom=try profile(fixture[count-2]);custom["id"]="next-hop-candidate";custom["name"]="Measured next hop";custom["node_kind"]="external";custom.removeValue(forKey:"node_proof_id")
   custom["router_api"]="";custom["api_token"]="";custom["endpoint"]="203.0.113.20";custom["start_layer"]="off"
   var transport:[String:Any]
   if kind=="shadowsocks" {transport=["server":"203.0.113.20","port":443,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:11,count:32).base64EncodedString()]}
   else {transport=["host":"203.0.113.20","port":8443,"username":"captured-user","password":"captured:password"];if kind=="https-connect"{transport["tls_server_name"]="Original.Proxy.Example"}}
   custom["external"]=["protocol":kind,"expected_public_ip":"203.0.113.76",kind.replacingOccurrences(of:"-",with:"_"):transport]
   let imported=try data(["selectedRouterID":"next-hop-candidate","routerProfiles":[custom],"profiles":[String:[String:String]]()])
   var records=Dictionary(uniqueKeysWithValues:fixture.enumerated().map{("original-\($0.offset)",$0.element)});records["candidate"]=imported
   let measured=try IOSNodeCandidateCapture.member(profile:custom,files:[:])
   let proposal=try IOSNodeCandidateProposal.compile(original:original,records:records,position:count-3,candidateID:"next-hop-candidate",measuredInput:measured)
   var ids=original.members.map(\.id);ids[count-2]="next-hop-candidate"
   try check("complete proposal retains every original position",proposal.profiles.map(\.id)==ids)
   try check("complete proposal preserves requested execution",proposal.profiles.last?.multihopExecution==requested)
   try check("complete proposal retains startup choices outside native projection",proposal.profiles.last?.startupMode=="smart-auto" && proposal.profiles.last?.autoConnect==true)
   try check("complete proposal retains selected DNS",proposal.profiles.last?.adGuardIPv4==(try profile(fixture[count-1])["adguard_ipv4"] as? String))
   let source=try object(Data(proposal.launchInput.utf8)),nodes=source["nodes"] as! [String],identities=source["identity_sources"] as! [String]
   let before=try object(Data(original.launchInput.utf8)),beforeNodes=before["nodes"] as! [String],beforeIDs=before["identity_sources"] as! [String]
   try check("complete proposal retains whole source and identity inventories",nodes.count==count && identities.count==count && identities[count-2].isEmpty)
   for position in 0..<(count-2){try check("complete proposal retains original prefix source",nodes[position]==beforeNodes[position] && identities[position]==beforeIDs[position])}
   try check("complete proposal retains original paired final proof",identities[count-1]==beforeIDs[count-1])
   for position in [0,count-1] {
    var changed=records;changed["original-\(position)"]=try editProfile(fixture[position]){$0["api_token"]="changed-retained-private-authority"}
    try reject("complete proposal changed retained source \(position)"){_ = try IOSNodeCandidateProposal.compile(original:original,records:changed,position:count-3,candidateID:"next-hop-candidate",measuredInput:measured)}
   }
   try reject("complete proposal cannot put imported target at final"){_ = try IOSNodeCandidateProposal.compile(original:original,records:records,position:count-2,candidateID:"next-hop-candidate",measuredInput:measured)}
   if kind=="shadowsocks" {
    let early=try IOSNodeCandidateProposal.compile(original:original,records:records,position:0,candidateID:"next-hop-candidate",measuredInput:measured)
    var expected=original.members.map(\.id);expected[1]="next-hop-candidate"
    let earlySource=try object(Data(early.launchInput.utf8)),earlyNodes=earlySource["nodes"] as! [String],earlyIdentity=earlySource["identity_sources"] as! [String]
    try check("literal SS2022 earlier middle preserves the captured route and requested execution",early.profiles.map(\.id)==expected && early.profiles.last?.multihopExecution==requested && earlyNodes.count==count && earlyIdentity.count==count && earlyIdentity[1].isEmpty)
    for i in 0..<count where i != 1 {
     try check("earlier proposal retains every untouched identity",earlyIdentity[i]==beforeIDs[i])
     if i<count-1 { try check("earlier proposal retains every original intermediate source",earlyNodes[i]==beforeNodes[i]) }
    }
    // The final profile's saved route references necessarily contain the new member.
    let priorFinal=try object(Data(beforeNodes[count-1].utf8))
    var expectedFinal=original.members[count-1].profile
    expectedFinal["multihop_enabled"]=true;expectedFinal["multihop_execution"]=requested
    expectedFinal["multihop_nodes"]=original.members.enumerated().map { i,member in ["id":expected[i],"mode":i==1 ? kind:member.mode] }
    for key in ["multihop_entry_id","multihop_entry_mode","multihop_exit_id","multihop_exit_mode"] {expectedFinal.removeValue(forKey:key)}
    var failure:NSError?
    let expectedInput=LibboxRouterNodeChainMemberInput(priorFinal["mode"] as! String,priorFinal["files"] as! String,String(decoding:try data(expectedFinal),as:UTF8.self),priorFinal["start"] as! String,priorFinal["dns_bootstrap"] as! String,&failure)
    try check("earlier proposal retains private final sources with its updated references",failure==nil && expectedInput==earlyNodes[count-1])
    if requested != "local" {
     guard let selected=LibboxRouterNodeChainMultipleImportedExecutionFromLaunch(early.launchInput,requested,&failure) else {throw failure ?? IOSNodeCandidateCapture.issue()}
     defer { try? selected.close() }
     let selectedInput=try object(Data(selected.source().utf8))
     try check("earlier proposal reopens as the exact typed selected schema-six preparation",failure==nil && selectedInput["schema"] as? Int==6 && selectedInput["execution"] as? String==requested && selectedInput["multiple_imported_local_launch"] as? String==early.launchInput)
    }
   } else {
    try reject("complete proposal cannot replace an earlier unsupported middle"){_ = try IOSNodeCandidateProposal.compile(original:original,records:records,position:0,candidateID:"next-hop-candidate",measuredInput:measured)}
   }
   let final=try profile(fixture[count-1]),finalFiles=try object(fixture[count-1])["profiles"] as! [String:[String:String]]
   let finalInput=try IOSNodeCandidateCapture.member(profile:final,files:finalFiles)
   try reject("complete proposal cannot duplicate the retained final identity"){_ = try IOSNodeCandidateProposal.compile(original:original,records:records,position:count-3,candidateID:final["id"] as! String,measuredInput:finalInput)}
  }}
 }
 static func selectedPacketStops()throws {
  for requested in ["server","auto"] {
   let count=8,imports:Set<Int>=[1,3,5]
   let bundles=try multipleFixture(count,imports,requested,"aes-256-gcm")
   let retained=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested)
   defer{try? retained.close()}
   let proofs=retained.members.enumerated().map{ p,m in IOSNodeCandidatePrefix(position:p,profile_id:m.id,node_id:m.profile["node_proof_id"] as? String ?? "",mode:m.mode) }
   let input=Data(retained.ordinaryLaunchInput.utf8),bundle=bundles[count-1],original=try profile(bundle)
   let stops=try IOSNodeCandidateProposal.selectedPositions(input:input,bundle:bundle,proofs:proofs,source:retained.sourceSHA256,config:retained.configSHA256)
   try check("original typed source exposes each paired packet stop only",stops==[0,2,4,6])
   for stop in stops {for winner in (requested=="server" ? ["server"]:["local","server"]) {
    let prefix=proofs[stop], target=String(repeating:"d",count:64)
    let wire:[String:Any]=["schema":1,"capture_sha256":target,"prefix_position":stop,"prefix_id":prefix.profile_id,"source_sha256":String(repeating:"e",count:64),"config_sha256":String(repeating:"f",count:64),"targets":[["id":"candidate","source_sha256":target]],"preparation_source_sha256":retained.sourceSHA256,"preparation_config_sha256":retained.configSHA256,"requested_execution":requested,"execution":winner,"selection_epoch":17]
    func accepted(_ value:[String:Any],_ allowed:[Int])throws->Bool {
     let metadata=try JSONDecoder().decode(IOSNodeCandidateMetadata.self,from:data(value))
     return (try? metadata.validate(prefix:prefix,source:retained.sourceSHA256,config:retained.configSHA256,ids:["candidate"],requestedExecution:requested,selectedExecution:winner,selectedPositions:allowed)) != nil
    }
    try check("selected metadata admits each original paired packet stop",try accepted(wire,stops))
    var foreign=wire;foreign["prefix_id"]="copied-packet";try check("selected packet metadata rejects a copied prefix ID",try !accepted(foreign,stops))
    try check("selected packet metadata requires the retained position",try !accepted(wire,stops.filter{$0 != stop}))
   }}
   var wrong=proofs;let middle=proofs[3];wrong[3] = .init(position:3,profile_id:proofs[1].profile_id,node_id:middle.node_id,mode:middle.mode)
   try reject("foreign untouched imported member in full active census"){_ = try IOSNodeCandidateProposal.selectedPositions(input:input,bundle:bundle,proofs:wrong,source:retained.sourceSHA256,config:retained.configSHA256)}
   var records=Dictionary(uniqueKeysWithValues:bundles.enumerated().map{("original-\($0.offset)",$0.element)})
   var candidate=try profile(bundles[1]);candidate["id"]="next-candidate";candidate["name"]="Candidate"
   records["candidate"]=try data(["selectedRouterID":"next-candidate","routerProfiles":[candidate],"profiles":[String:[String:String]]()])
   let measured=try IOSNodeCandidateCapture.member(profile:candidate,files:[:])
   // Each non-final packet stop with an imported successor can propose a complete fresh route.
   for stop in [0,2,4] {
    let proposal=try IOSNodeCandidateProposal.compileConnectedExecution(retained.ordinaryLaunchInput,selectedProfile:original,sourceSHA256:retained.sourceSHA256,configSHA256:retained.configSHA256,records:records,position:stop,candidateID:"next-candidate",measuredInput:measured)
    var ids=proofs.map(\.profile_id);ids[stop+1]="next-candidate"
    try check("source-six packet proposal changes only the measured next member",proposal.profiles.map(\.id)==ids && proposal.profiles.last?.multihopExecution==requested)
   }
   for stop in [1,3,5,7] {try reject("imported or final stop cannot claim connected TCP samples"){_ = try IOSNodeCandidateProposal.compileConnectedExecution(retained.ordinaryLaunchInput,selectedProfile:original,sourceSHA256:retained.sourceSHA256,configSHA256:retained.configSHA256,records:records,position:stop,candidateID:"next-candidate",measuredInput:measured)}}
  }
 }
 static func selectedEntryProposals()throws {
  for requested in ["server","auto"] {
   var fixture=try sources(3,"off",true).map{try editProfile($0){p in
    p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""
   }}
   fixture[2]=try editProfile(fixture[2]){p in p["multihop_execution"]=requested;p["startup_mode"]="smart-auto";p["auto_connect"]=true}
   fixture[2]=Data(try LibboxTestCONNECTService(String(decoding:fixture[2],as:UTF8.self)).utf8)
   let original=try IOSNodeChainExecutionCapture.compile(bundles:fixture,requested:requested)
   defer{try? original.close()}
   var custom=try profile(fixture[1]);custom["id"]="entry-candidate";custom["name"]="Measured entry target";custom["node_kind"]="external";custom.removeValue(forKey:"node_proof_id")
   custom["router_api"]="";custom["api_token"]="";custom["endpoint"]="203.0.113.20";custom["start_layer"]="off"
   custom["external"]=["protocol":"shadowsocks","expected_public_ip":"203.0.113.76","shadowsocks":["server":"203.0.113.20","port":443,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:11,count:32).base64EncodedString()]]
   let imported=try data(["selectedRouterID":"entry-candidate","routerProfiles":[custom],"profiles":[String:[String:String]]()])
   let records=["entry":fixture[0],"middle":fixture[1],"final":fixture[2],"candidate":imported]
   let measured=try IOSNodeCandidateCapture.member(profile:custom,files:[:]),selected=try profile(fixture[2])
   let originalProofs=original.members.enumerated().map{IOSNodeCandidatePrefix(position:$0.offset,profile_id:$0.element.id,node_id:$0.element.profile["node_proof_id"] as? String ?? "",mode:$0.element.mode)}
   let packetPositions=try IOSNodeCandidateProposal.selectedPositions(input:Data(original.ordinaryLaunchInput.utf8),bundle:fixture[2],proofs:originalProofs,source:original.sourceSHA256,config:original.configSHA256)
   try check("original ordinary selected execution retains recursive packet stops",packetPositions==[0,1])
   func proposal(_ source:String?=nil,_ config:String?=nil,_ position:Int=0,_ captured:[String:Data]?=nil)throws->IOSNodeCandidateProposal {
    try IOSNodeCandidateProposal.compileConnectedExecution(original.ordinaryLaunchInput,selectedProfile:selected,sourceSHA256:source ?? original.sourceSHA256,configSHA256:config ?? original.configSHA256,records:captured ?? records,position:position,candidateID:"entry-candidate",measuredInput:measured)
   }
   let value=try proposal()
   try check("selected entry proposal retains full saved execution",value.profiles.map(\.id)==[original.members[0].id,"entry-candidate",original.members[2].id] && value.profiles.last?.multihopExecution==requested)
   try check("selected entry proposal retains startup and DNS",value.profiles.last?.startupMode=="smart-auto" && value.profiles.last?.autoConnect==true && value.profiles.last?.adGuardIPv4==selected["adguard_ipv4"] as? String)
   try reject("execution proposal substituted preparation source"){_ = try proposal(String(repeating:"0",count:64))}
   try reject("execution proposal substituted preparation config"){_ = try proposal(original.sourceSHA256,String(repeating:"0",count:64))}
   try reject("supported later packet stop cannot replace paired final with an imported stream"){_ = try proposal(original.sourceSHA256,original.configSHA256,1)}
   var changed=records;changed["entry"]=try editProfile(fixture[0]){$0["api_token"]="changed-entry"}
   try reject("execution proposal changed original entry"){_ = try proposal(original.sourceSHA256,original.configSHA256,0,changed)}
   changed=records;changed["final"]=try editProfile(fixture[2]){$0["api_token"]="changed-final"}
   try reject("execution proposal changed original final"){_ = try proposal(original.sourceSHA256,original.configSHA256,0,changed)}
   try check("execution proposal does not run original source",!original.healthy() && original.members[1].id != "entry-candidate")
  }
 }
 static func openVPNTCPCandidates()throws {
  var fixture=try sources(3,"off",true).map{try editProfile($0){p in
   p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""
  }}
  fixture[2]=Data(try LibboxTestCONNECTService(String(decoding:fixture[2],as:UTF8.self)).utf8)
  let original=try IOSNodeChainCapture.compile(bundles:fixture);defer{try? original.plan.close()}
  let prefix=original.members.enumerated().map{IOSNodeCandidatePrefix(position:$0.offset,profile_id:$0.element.id,node_id:$0.element.profile["node_proof_id"] as! String,mode:$0.element.mode)}
  var records=Dictionary(uniqueKeysWithValues:fixture.enumerated().map{("original-\($0.offset)",$0.element)})
  for network in ["tcp","udp"] {
   let id="provider-"+network
   var provider=try profile(fixture[1])
   provider["id"]=id;provider["name"]=id;provider["node_kind"]="external";provider.removeValue(forKey:"node_proof_id")
   provider["router_api"]="";provider["api_token"]="";provider["endpoint"]="203.0.113.20";provider["start_layer"]="off";provider["mtu_policy"]="manual";provider["manual_mtu"]=1280
   let config="client\ndev tun\nproto "+network+"\nremote 203.0.113.20 1194\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint "+String(repeating:"ab",count:32)+"\ntun-mtu 1280\ndata-ciphers AES-256-GCM:AES-128-GCM\n"
   provider["external"]=["protocol":"openvpn","expected_public_ip":"203.0.113.76","openvpn":["config":config,"username":"original-provider-user","password":"original-provider-secret"]]
   records[id]=try data(["selectedRouterID":id,"routerProfiles":[provider],"profiles":[String:[String:String]]()])
  }
  let stamp=IOSCandidateCatalogPublication.Stamp(schema:1,epoch:UUID().uuidString,generation:1,ready:true,sources_sha256:try IOSCandidateCatalogPublication.sourcesDigest(records))
  let catalog=try IOSNodeCandidateCapture.compile(records:records,stamp:stamp,prefixPosition:0,proofs:prefix)
  guard let tcp=catalog.rows.first(where:{$0.id=="provider-tcp"}),let udp=catalog.rows.first(where:{$0.id=="provider-udp"}) else {throw IOSNodeCandidateCapture.issue()}
  try check("OpenVPN TCP candidate retained its original typed transport",tcp.reason.isEmpty && !tcp.input.isEmpty && LibboxRouterNodeChainCandidateInputSupported(tcp.input))
  try check("OpenVPN UDP at the same address has an unmeasured row",udp.input.isEmpty && !udp.reason.isEmpty)
  let candidate=try IOSNodeCandidateProposal.compile(original:original,records:records,position:0,candidateID:tcp.id,measuredInput:tcp.input)
  let launch=try object(Data(candidate.launchInput.utf8))
  try check("OpenVPN TCP future route uses the native schema-five compiler",launch["schema"] as? Int==5 && candidate.profiles.last?.multihopNodes?.map(\.mode)==[original.members[0].mode,"openvpn","shadowsocks"] && candidate.profiles[1].external?.openVPN?.username=="original-provider-user")
  var changed=records
  changed[tcp.id]=try editProfile(records[tcp.id]!){p in
   var e=p["external"] as! [String:Any],provider=e["openvpn"] as! [String:Any];provider["password"]="changed";e["openvpn"]=provider;p["external"]=e
  }
  try reject("OpenVPN candidate cannot substitute its measured credentials"){_ = try IOSNodeCandidateProposal.compile(original:original,records:changed,position:0,candidateID:tcp.id,measuredInput:tcp.input)}
 }
 static func streamProxyCandidates()throws {
  for mode in ["wg","awg2-fast","awg2-strong"] {for kind in ["http-connect","https-connect","socks5"] {
   var fixture=try sources(3,"off",true).map{try editProfile($0){p in
    p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""
   }}
   fixture[2]=try editProfile(fixture[2]){p in
    var nodes=p["multihop_nodes"] as! [[String:Any]];nodes[0]["mode"]=mode;p["multihop_nodes"]=nodes
    p["dns_mode"]="custom";p["dns_protocol"]="tcp";p["dns_host"]="10.82.0.53";p["dns_port"]=5353
   }
   var finalRoot=try object(fixture[2]),assets=finalRoot["profiles"] as! [String:[String:String]]
   var finalGraph=try object(Data(base64Encoded:assets["shadowsocks"]!["sing-box.json"]!)!)
   finalGraph["dns"]=["servers":[["type":"tcp","tag":"home-dns","server":"10.82.0.53","server_port":5353,"detour":"proxy"]],"final":"home-dns"]
   assets["shadowsocks"]!["sing-box.json"]=try data(finalGraph).base64EncodedString();finalRoot["profiles"]=assets
   fixture[2]=Data(try LibboxTestCONNECTService(String(decoding:try data(finalRoot),as:UTF8.self)).utf8)
   let original=try IOSNodeChainCapture.compile(bundles:fixture);defer{try? original.plan.close()}
   let originalSource=original.launchInput,key=kind.replacingOccurrences(of:"-",with:"_")
   var custom=try profile(fixture[1]);custom["id"]="connect-candidate";custom["name"]="Saved CONNECT";custom["node_kind"]="external";custom.removeValue(forKey:"node_proof_id")
   custom["router_api"]="";custom["api_token"]="";custom["endpoint"]="203.0.113.20";custom["start_layer"]="off"
   var credentials:[String:Any]=["host":"203.0.113.20","port":8443,"username":"captured-user","password":"captured:password"]
   if kind=="https-connect"{credentials["tls_server_name"]="Original.Proxy.Example"}
   custom["external"]=["protocol":kind,"expected_public_ip":"203.0.113.76",key:credentials]
   let imported=try data(["selectedRouterID":"connect-candidate","routerProfiles":[custom],"profiles":[String:[String:String]]()])
   let records=["entry":fixture[0],"middle":fixture[1],"final":fixture[2],"connect":imported]
   let proofs=original.members.enumerated().map{IOSNodeCandidatePrefix(position:$0.offset,profile_id:$0.element.id,node_id:$0.element.profile["node_proof_id"] as! String,mode:$0.element.mode)}
   func catalog(_ values:[String:Data])throws->(inventory:Data,rows:[IOSNodeCandidateCapture.Row]){
    let stamp=IOSCandidateCatalogPublication.Stamp(schema:1,epoch:UUID().uuidString,generation:1,ready:true,sources_sha256:try IOSCandidateCatalogPublication.sourcesDigest(values))
    return try IOSNodeCandidateCapture.compile(records:values,stamp:stamp,prefixPosition:0,proofs:proofs)
   }
   let captured=try catalog(records),row=captured.rows.first{$0.id=="connect-candidate"}!
   try check("Proxy candidate uses authoritative typed input",!row.input.isEmpty && row.reason.isEmpty && LibboxRouterNodeChainCandidateInputSupported(row.input))
   let member=try object(Data(row.input.utf8))
   try check("Proxy candidate keeps distinct member kind",member["kind"] as? String==(kind=="socks5" ? "routervpn-node-chain-socks-member":"routervpn-node-chain-connect-member"))
   let proposal=try IOSNodeCandidateProposal.compile(original:original,records:records,position:0,candidateID:row.id,measuredInput:row.input)
   let launch=try object(Data(proposal.launchInput.utf8))
   try check("Proxy future proposal uses typed compiler",launch["schema"] as? Int==(kind=="socks5" ? 3:4) && proposal.profiles.map(\.id)==["chain-node-0","connect-candidate","chain-node-2"])
   try check("Proxy future proposal preserves protocol and selected DNS",proposal.profiles.last?.multihopNodes?.map(\.mode)==[mode,kind,"shadowsocks"] && proposal.profiles.last?.dnsProtocol=="tcp" && proposal.profiles.last?.dnsHost=="10.82.0.53" && proposal.profiles.last?.dnsPort==5353)
   let external=proposal.profiles[1].external!
   if kind=="socks5" {
    try check("SOCKS future proposal retains original credentials",external.protocolName==kind && external.socks5?.username=="captured-user" && external.socks5?.password=="captured:password")
    var anonymous=records
    anonymous["connect"]=try editProfile(imported){p in var ext=p["external"] as! [String:Any],value=ext[key] as! [String:Any];value.removeValue(forKey:"username");value.removeValue(forKey:"password");ext[key]=value;p["external"]=ext}
    let anonymousRow=try catalog(anonymous).rows.first{$0.id==row.id}!
    let anonymousProposal=try IOSNodeCandidateProposal.compile(original:original,records:anonymous,position:0,candidateID:row.id,measuredInput:anonymousRow.input)
    try check("SOCKS anonymous source stays anonymous",anonymousProposal.profiles[1].external?.socks5?.username==nil && anonymousProposal.profiles[1].external?.socks5?.password==nil)
    try reject("SOCKS anonymous source cannot adopt authenticated receipt"){_ = try IOSNodeCandidateProposal.compile(original:original,records:anonymous,position:0,candidateID:row.id,measuredInput:row.input)}
   } else {
    let capturedCredentials=kind=="https-connect" ? external.httpsConnect : external.httpConnect
    try check("Proxy future proposal retains original credentials",external.protocolName==kind && capturedCredentials?.username=="captured-user" && capturedCredentials?.password=="captured:password" && (kind != "https-connect" || capturedCredentials?.tlsServerName=="Original.Proxy.Example"))
   }
   try check("Proxy proposal leaves current path unchanged",original.launchInput==originalSource)
   try reject("Proxy candidate unsupported placement"){_ = try IOSNodeCandidateProposal.compile(original:original,records:records,position:1,candidateID:row.id,measuredInput:row.input)}
   var changedFinal=records;changedFinal["final"]=try editProfile(fixture[2]){$0["dns_host"]="10.82.0.54"}
   try reject("Proxy proposal changed retained final policy"){_ = try IOSNodeCandidateProposal.compile(original:original,records:changedFinal,position:0,candidateID:row.id,measuredInput:row.input)}
   for field in kind=="https-connect" ? ["password","tls_server_name"]:["password"] {
    var changed=records
    changed["connect"]=try editProfile(imported){p in var ext=p["external"] as! [String:Any],value=ext[key] as! [String:Any];value[field]="replacement.example";ext[key]=value;p["external"]=ext}
    try reject("Proxy proposal changed measured "+field){_ = try IOSNodeCandidateProposal.compile(original:original,records:changed,position:0,candidateID:row.id,measuredInput:row.input)}
   }
   for fault in ["hostname","layer","credential","borrowed-token"] {
    var changed=records
    changed["connect"]=try editProfile(imported){p in
     if fault=="layer"{p["start_layer"]="aes-256-gcm"}
     else if fault=="borrowed-token"{p["api_token"]="not-an-external-authority"}
     else{var ext=p["external"] as! [String:Any],value=ext[key] as! [String:Any];if fault=="hostname"{value["host"]="proxy.example";p["endpoint"]="proxy.example"}else{value["password"]=""};ext[key]=value;p["external"]=ext}
    }
    let rejected=try catalog(changed)
    try check("Proxy invalid "+fault+" remains unscored",rejected.rows.first{$0.id==row.id}?.input.isEmpty==true && rejected.rows.contains{!$0.input.isEmpty})
   }
  }}
 }
 static func earlierStreamProposals()throws {
  for (count,hostname) in [(4,false),(7,false),(9,false),(15,false),(4,true),(9,true)] {
   var originals=try multipleFixture(count,Set(1..<count-1),"local","off")
   if hostname {
    originals[1]=try editProfile(originals[1]){p in
     let host="Saved.Proxy.Example";var ext=p["external"] as! [String:Any],ss=ext["shadowsocks"] as! [String:Any]
     p["endpoint"]=host;ss["server"]=host;ext["shadowsocks"]=ss;p["external"]=ext
    }
   }
   let capture=try IOSNodeChainCapture.compile(bundles:originals);defer{try? capture.plan.close()}
   let original=IOSNodeCandidateOriginalCapture.ordinary(capture)
   let position=count-3,id="independent-paired-ss"
   func pairedCandidate(_ slot:Int,_ name:String,_ address:String,_ key:UInt8)throws->Data{
    var candidate=try object(multipleFixture(count,[],"local","off")[slot]),members=candidate["routerProfiles"] as! [[String:Any]]
    members[0]["id"]=name;candidate["selectedRouterID"]=name;candidate["routerProfiles"]=members
    var assets=candidate["profiles"] as! [String:[String:String]]
    var graph=try object(Data(base64Encoded:assets["shadowsocks"]!["sing-box.json"]!)!),outbounds=graph["outbounds"] as! [[String:Any]]
    let ss=outbounds.firstIndex{$0["type"] as? String=="shadowsocks"}!
    outbounds[ss]["server"]=address;outbounds[ss]["password"]=Data(repeating:key,count:32).base64EncodedString()
    graph["outbounds"]=outbounds;assets["shadowsocks"]!["sing-box.json"]=try data(graph).base64EncodedString();candidate["profiles"]=assets
    return try data(candidate)
   }
   var records=Dictionary(uniqueKeysWithValues:try originals.map{(try profile($0)["id"] as! String,$0)})
   records[id]=try pairedCandidate(count-2,id,"203.0.113.190",199)
   let stamp=IOSCandidateCatalogPublication.Stamp(schema:1,epoch:UUID().uuidString,generation:1,ready:true,sources_sha256:try IOSCandidateCatalogPublication.sourcesDigest(records))
   let targets=try IOSNodeCandidateCapture.compile(records:records,stamp:stamp,prefixPosition:position,proofs:original.candidatePrefixes)
   guard let input=targets.rows.first(where:{$0.id==id})?.input,!input.isEmpty else {throw IOSNodeCandidateCapture.issue()}
   try check("earlier import uses private response authority",original.candidatePrefixes[position].metric=="routed-candidate-response")
   let proposal=try IOSNodeCandidateProposal.compile(original:original,records:records,position:position,candidateID:id,measuredInput:input)
   var expected=original.members.map(\.id);expected.insert(id,at:position+1)
   try check("measured insertion preserves every original and control",proposal.profiles.map(\.id)==expected && proposal.profiles.last?.multihopNodes?.map(\.id)==expected && proposal.profiles.last?.id==original.members.last?.id)
   let after=try object(Data(proposal.launchInput.utf8)),before=try object(Data(capture.launchInput.utf8))
   let fresh=after["nodes"] as! [String],prior=before["nodes"] as! [String],identities=after["identity_sources"] as! [String]
   try check("private stream has separate original identity",after["schema"] as? Int==6 && !identities[position+1].isEmpty && identities[position].isEmpty && identities[position+2].isEmpty && (try object(Data(fresh[position+1].utf8)))["mode"] as? String=="shadowsocks")
   try check("original streams around inserted position remain exact",fresh[position]==prior[position] && fresh[position+2]==prior[position+1])
   let finalMember=try object(Data(fresh.last!.utf8))
   guard let finalJSON=finalMember["profile_json"] as? String else {throw IOSNodeCandidateCapture.issue()}
   let reopened=try IOSNodeChainCapture.reopen(proposal.launchInput,selectedProfile:object(Data(finalJSON.utf8)))
   defer {try? reopened.plan.close()}
   try check("provider reopens private interior and original final",reopened.members.map(\.id)==expected && reopened.members[position+1].profile["node_kind"] as? String=="router-vpn" && reopened.members[position+1].profile["external"]==nil)
   let next="second-paired-ss"
   var retained=records
   retained[expected.last!]=try editProfile(records[expected.last!]!){ $0=reopened.finalProfile }
   retained[next]=try pairedCandidate(count-3,next,"203.0.113.191",200)
   let independent=IOSNodeCandidateOriginalCapture.ordinary(reopened)
   let current=IOSCandidateCatalogPublication.Stamp(schema:1,epoch:UUID().uuidString,generation:2,ready:true,sources_sha256:try IOSCandidateCatalogPublication.sourcesDigest(retained))
   let compared=try IOSNodeCandidateCapture.compile(records:retained,stamp:current,prefixPosition:position+1,proofs:independent.candidatePrefixes)
   guard let secondInput=compared.rows.first(where:{$0.id==next})?.input,!secondInput.isEmpty else { throw IOSNodeCandidateCapture.issue() }
   let second=try IOSNodeCandidateProposal.compile(original:independent,records:retained,position:position+1,candidateID:next,measuredInput:secondInput)
   var twice=expected;twice.insert(next,at:position+2)
   try check("second measured private source keeps both paired owners before original suffix and final",second.profiles.map(\.id)==twice && second.profiles[position+1].nodeProofID != second.profiles[position+2].nodeProofID && second.profiles.last?.multihopNodes?.map(\.id)==twice)
   var changed=records
   let suffix=original.members[position+1].id
   changed[suffix]=try editProfile(records[suffix]!){$0["name"]="relinked original suffix"}
   try reject("insertion cannot accept a changed original suffix"){_ = try IOSNodeCandidateProposal.compile(original:original,records:changed,position:position,candidateID:id,measuredInput:input)}
  }
 }
 static func lateStreamFinalProposals()throws {
  for count in [9,16] { for packets in [1,2,count-3] {
   let originals=try multipleFixture(count,Set(packets..<count-1),"local","off"),capture=try IOSNodeChainCapture.compile(bundles:originals)
   defer{try? capture.plan.close()}
   let original=IOSNodeCandidateOriginalCapture.ordinary(capture),position=count-2,alternateID="measured-final"
   var records=Dictionary(uniqueKeysWithValues:try originals.map{(try profile($0)["id"] as! String,$0)})
   var alternate=try object(multipleFixture(count,[],"local","off")[count-2]),members=alternate["routerProfiles"] as! [[String:Any]]
   members[0]["id"]=alternateID;alternate["selectedRouterID"]=alternateID;alternate["routerProfiles"]=members
   records[alternateID]=try data(alternate)
   let stamp=IOSCandidateCatalogPublication.Stamp(schema:1,epoch:UUID().uuidString,generation:1,ready:true,sources_sha256:try IOSCandidateCatalogPublication.sourcesDigest(records))
   let targets=try IOSNodeCandidateCapture.compile(records:records,stamp:stamp,prefixPosition:position,proofs:original.candidatePrefixes)
   guard let input=targets.rows.first(where:{$0.id==alternateID})?.input,!input.isEmpty else {throw IOSNodeCandidateCapture.issue()}
   let proposal=try IOSNodeCandidateProposal.compile(original:original,records:records,position:position,candidateID:alternateID,measuredInput:input)
   let before=try object(Data(capture.launchInput.utf8)),after=try object(Data(proposal.launchInput.utf8))
   for field in ["nodes","identity_sources"] {
    let first=before[field] as! [String],second=after[field] as! [String]
    try check("late measured final retains every original preceding source",first.count==count && second.count==count && Array(first.dropLast())==Array(second.dropLast()) && first.last != second.last)
   }
   try check("late measured final retains paired Shadowsocks and all named imports",proposal.profiles.map(\.id)==original.members.dropLast().map(\.id)+[alternateID] && proposal.profiles.last?.multihopNodes?.last?.mode=="shadowsocks")
   let inserted=try IOSNodeCandidateProposal.compile(original:original,records:records,position:position-1,candidateID:alternateID,measuredInput:input)
   var expected=original.members.map(\.id);expected.insert(alternateID,at:position)
   try check("late measured insertion retains the original public import and final",inserted.profiles.map(\.id)==expected && inserted.profiles[position].normalizedNodeKind=="router-vpn" && inserted.profiles[position+1].normalizedNodeKind=="external" && inserted.profiles.last?.id==original.members.last?.id)
   try reject("late public import cannot acquire a paired candidate identity"){_ = try IOSNodeCandidateProposal.compile(original:original,records:records,position:position-1,candidateID:original.members[position].id,measuredInput:input)}
  }}
 }
 static func run()throws {
  let prefix=IOSNodeCandidatePrefix(position:0,profile_id:"chain-node-0",node_id:String(repeating:"a",count:64),mode:"wg")
  let tail=IOSNodeCandidatePrefix(position:1,profile_id:"other-final",node_id:String(repeating:"b",count:64),mode:"shadowsocks")
  func compile(_ records:[String:Data],_ proofs:[IOSNodeCandidatePrefix]?=nil)throws->(inventory:Data,rows:[IOSNodeCandidateCapture.Row]){
   let stamp=IOSCandidateCatalogPublication.Stamp(schema:1,epoch:UUID().uuidString,generation:1,ready:true,sources_sha256:try IOSCandidateCatalogPublication.sourcesDigest(records))
   return try IOSNodeCandidateCapture.compile(records:records,stamp:stamp,prefixPosition:0,proofs:proofs ?? [prefix,tail])
  }
  for(method,size)in[("2022-blake3-aes-128-gcm",16),("2022-blake3-aes-256-gcm",32),("2022-blake3-chacha20-poly1305",32)] {
   let fixture=try sources(3).map{try editProfile($0){p in
    p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""
   }}
   var paired=try object(fixture[1]), files=paired["profiles"] as! [String:[String:String]]
   var graph=try object(Data(base64Encoded:files["shadowsocks"]!["sing-box.json"]!)!),out=graph["outbounds"] as! [[String:Any]]
   out[0]["method"]=method;out[0]["password"]=Data(repeating:1,count:size).base64EncodedString();graph["outbounds"]=out
   files["shadowsocks"]!["sing-box.json"]=try data(graph).base64EncodedString();paired["profiles"]=files
   let actual=try compile(["candidate":data(paired)])
   try check("paired exact cipher source admitted",actual.rows.count==1 && actual.rows[0].reason.isEmpty && LibboxRouterNodeChainCandidateInputSupported(actual.rows[0].input))
   var custom=try profile(fixture[1]);custom["id"]="custom";custom["name"]="Custom";custom["node_kind"]="external";custom.removeValue(forKey:"node_proof_id")
   for key in ["router_api","api_token","adguard_ipv6","socks_host","socks_username","socks_password"]{custom[key]=""};custom["socks_port"]=0
   custom["external"]=["protocol":"shadowsocks","expected_public_ip":"203.0.113.76","shadowsocks":["server":"198.51.100.76","port":443,"method":method,"password":Data(repeating:0,count:size).base64EncodedString()]]
   var imported=paired;imported["selectedRouterID"]="custom";imported["routerProfiles"]=[custom];imported["profiles"]=[String:[String:String]]()
   let combined=try compile(["paired":data(paired),"custom":data(imported)])
   try check("original imported cipher admitted",combined.rows.count==2 && combined.rows.allSatisfy{$0.reason.isEmpty})
   for fault in ["hostname","layer","bad-key","legacy"] {
    var bad=imported,changed=custom
    if fault=="layer"{changed["start_layer"]="aes-256-gcm"}
    else{var ext=changed["external"] as! [String:Any],ss=ext["shadowsocks"] as! [String:Any];ss[fault=="hostname" ? "server":fault=="legacy" ? "method":"password"]=fault=="hostname" ? "hostname.example":fault=="legacy" ? "aes-256-gcm":"bad";ext["shadowsocks"]=ss;changed["external"]=ext}
    bad["routerProfiles"]=[changed]
    let result=try compile(["paired":data(paired),"unsupported":data(bad)])
    try check("unsupported \(fault) stays unscored without suppressing valid source",result.rows.count==2 && result.rows.filter{!$0.input.isEmpty}.count==1)
   }
   var legacy=paired,legacyFiles=files,legacyGraph=graph,legacyOut=out
   legacyOut[0]["method"]="aes-256-gcm";legacyOut[0]["password"]="legacy password";legacyGraph["outbounds"]=legacyOut
   legacyFiles["shadowsocks"]!["sing-box.json"]=try data(legacyGraph).base64EncodedString();legacy["profiles"]=legacyFiles
   let legacyResult=try compile(["legacy":data(legacy),"custom":data(imported)])
   try check("paired legacy stays unscored",legacyResult.rows.first{$0.id == "chain-node-1"}?.input.isEmpty == true)
   let original=try IOSNodeChainCapture.compile(bundles:fixture)
   defer{try? original.plan.close()}
   let records=["entry":fixture[0],"paired":try data(paired),"final":fixture[2],"custom":try data(imported)]
   try reject("paired final target cannot truncate the original suffix"){_ = try IOSNodeCandidateProposal.compile(original:original,records:records,position:0,candidateID:"chain-node-1",measuredInput:actual.rows[0].input)}
   let customInput=combined.rows.first{$0.id=="custom"}!.input
   let customProposal=try IOSNodeCandidateProposal.compile(original:original,records:records,position:0,candidateID:"custom",measuredInput:customInput)
   try check("future imported proposal preserves original paired final",customProposal.profiles.map(\.id)==["chain-node-0","custom","chain-node-2"] && customProposal.profiles[1].normalizedNodeKind=="external" && customProposal.profiles[1].nodeProofID==nil && customProposal.profiles.last?.adGuardIPv4 == "10.82.0.53")
   if method == "2022-blake3-aes-256-gcm" {
    let retainedFinal=try editProfile(fixture[2]){ p in p["multihop_nodes"]=[["id":"chain-node-0","mode":"wg"],["id":"custom","mode":"shadowsocks"],["id":"chain-node-2","mode":"shadowsocks"]] }
    let retained=try IOSNodeChainCapture.compile(bundles:[fixture[0],data(imported),retainedFinal]);defer{try? retained.plan.close()}
    let original=IOSNodeCandidateOriginalCapture.ordinary(retained)
    try check("literal SS penultimate retains native private response authority",original.candidatePrefixes[1].metric=="routed-candidate-response" && !original.requiresIndependentPrefix)
    var nextRecords=records;nextRecords["final"]=retainedFinal
    let proposed=try IOSNodeCandidateProposal.compile(original:original,records:nextRecords,position:1,candidateID:"chain-node-1",measuredInput:actual.rows[0].input)
    try check("measured paired final preserves entry and imported original",proposed.profiles.map(\.id)==["chain-node-0","custom","chain-node-1"] && proposed.profiles.last?.multihopNodes?.map(\.mode)==["wg","shadowsocks","shadowsocks"])
    try reject("private response cannot adopt imported candidate"){_ = try IOSNodeCandidateProposal.compile(original:original,records:nextRecords,position:1,candidateID:"custom",measuredInput:customInput)}
   }
   try reject("future custom candidate after second prefix"){_ = try IOSNodeCandidateProposal.compile(original:original,records:records,position:1,candidateID:"custom",measuredInput:customInput)}
   var stale=records;stale["entry"]=try editProfile(fixture[0]){$0["home_lan_access"]=false}
   try reject("future proposal changed original prefix"){_ = try IOSNodeCandidateProposal.compile(original:original,records:stale,position:0,candidateID:"custom",measuredInput:customInput)}
   var changedFinal=records;changedFinal["final"]=try editProfile(fixture[2]){$0["adguard_ipv4"]="10.82.0.54"}
   try reject("future custom proposal substituted final DNS"){_ = try IOSNodeCandidateProposal.compile(original:original,records:changedFinal,position:0,candidateID:"custom",measuredInput:customInput)}
   try reject("future proposal changed measured source"){_ = try IOSNodeCandidateProposal.compile(original:original,records:records,position:0,candidateID:"custom",measuredInput:actual.rows[0].input)}
   try check("proposal compilation leaves original chain unchanged",original.members.count==3 && original.members[1].id=="chain-node-1" && original.members.last?.id=="chain-node-2")
   try reject("no eligible inventory"){_ = try compile(["only-prefix":fixture[0]])}
   let lazy=IOSNodeCandidatePrefix(position:0,profile_id:prefix.profile_id,node_id:prefix.node_id,mode:"shadowsocks")
   try reject("lazy SS prefix"){_ = try compile(["candidate":data(paired)],[lazy,tail])}
  }
  try earlierStreamProposals()
  try lateStreamFinalProposals()
  try openVPNTCPCandidates()
  try streamProxyCandidates()
  try selectedEntryProposals()
  try selectedPacketStops()
  let hash=String(repeating:"c",count:64)
  let metadata=IOSNodeCandidateMetadata(schema:1,capture_sha256:hash,prefix_position:0,prefix_id:prefix.profile_id,source_sha256:hash,config_sha256:hash,targets:[.init(id:"target",source_sha256:hash)])
  try metadata.validate(prefix:prefix,source:hash,config:hash,ids:["target"])
  for requested in ["server","auto"] {for selected in ["local","server"] where requested=="auto" || selected=="server" {
   let projection=String(repeating:"d",count:64)
   let record:[String:Any]=["schema":1,"capture_sha256":hash,"prefix_position":0,"prefix_id":prefix.profile_id,"source_sha256":projection,"config_sha256":projection,"targets":[["id":"target","source_sha256":hash]],"preparation_source_sha256":hash,"preparation_config_sha256":hash,"requested_execution":requested,"execution":selected,"selection_epoch":17]
   func validate(_ value:[String:Any],_ requestedValue:String?,_ selectedValue:String?)throws {
    let parsed=try JSONDecoder().decode(IOSNodeCandidateMetadata.self,from:data(value))
    try parsed.validate(prefix:prefix,source:hash,config:hash,ids:["target"],requestedExecution:requestedValue,selectedExecution:selectedValue)
   }
   try validate(record,requested,selected)
   try check("selected metadata separates active projection from preparation",projection != hash)
   for key in ["preparation_source_sha256","preparation_config_sha256","requested_execution","execution","selection_epoch"] {
    var missing=record;missing.removeValue(forKey:key)
    try reject("execution metadata missing \(key)"){try validate(missing,requested,selected)}
    var wrong=record;wrong[key]=key=="selection_epoch" ? 0:"foreign"
    try reject("execution metadata changed \(key)"){try validate(wrong,requested,selected)}
   }
   try reject("execution metadata presented as Local"){try validate(record,nil,nil)}
   try reject("Local metadata presented as selected execution"){try metadata.validate(prefix:prefix,source:hash,config:hash,ids:["target"],requestedExecution:requested,selectedExecution:selected)}
  }}
  let distribution:[String:Any]=["samples":50,"min_ms":1.0,"median_ms":2.0,"average_ms":2.5,"p90_ms":3.0,"max_ms":4.0,"jitter_ms":0.5]
  let benchmark:[String:Any]=["schema":1,"measurement":"routed-tcp-connect","attempts":50,"failed":0,"distribution":distribution,"trimmed_mean_ms":2.4]
  let row:[String:Any]=["node_id":"target","role":"candidate","kind":"tcp-connect","ready":true,"benchmark":benchmark]
  let receipt:[String:Any]=["schema":1,"measurement":"routed-tcp-connect","request_id":"request","complete":true,"drained":true,"stage":"complete","capture_sha256":hash,"prefix_position":0,"prefix_id":prefix.profile_id,"candidate_id":"target","candidate_source_sha256":hash,"measured_at":1000000,"expires_at":1120000,"results":[row]]
  func score(_ value:[String:Any],_ now:Int64=1000001)throws->Double{try JSONDecoder().decode(IOSNodeCandidateResult.self,from:data(value)).score(request:"request",target:metadata.targets[0],metadata:metadata,now:now).trimmed_mean_ms}
  try check("complete50 TCP score",score(receipt)==2.4)
  let privateMetric = "routed-candidate-response"
  let stream = IOSNodeCandidatePrefix(position:1,profile_id:"original-ss",node_id:"",mode:"shadowsocks",measurement:privateMetric)
  var streamMeta = IOSNodeCandidateMetadata(schema:1,capture_sha256:hash,prefix_position:1,prefix_id:stream.profile_id,source_sha256:hash,config_sha256:hash,targets:metadata.targets)
  streamMeta.measurement = privateMetric
  try streamMeta.validate(prefix:stream,source:hash,config:hash,ids:["target"])
  var sr=receipt;sr["measurement"]=privateMetric;sr["prefix_position"]=1;sr["prefix_id"]=stream.profile_id
  var sb=benchmark;sb["measurement"]=privateMetric
  var srow=row;srow["kind"]="private-agent-response";srow["benchmark"]=sb;sr["results"]=[srow]
  func privateScore(_ value:[String:Any],_ meta:IOSNodeCandidateMetadata=streamMeta,_ now:Int64=1000001)throws->Double {
    try JSONDecoder().decode(IOSNodeCandidateResult.self,from:data(value)).score(request:"request",target:meta.targets[0],metadata:meta,now:now).trimmed_mean_ms
  }
  try check("private agent provided all 50 responses",privateScore(sr)==2.4)
  var substitute=streamMeta;substitute.measurement=nil
  try reject("private result without native metric"){_ = try privateScore(sr,substitute)}
  try reject("private metadata attached to packet prefix"){try streamMeta.validate(prefix:prefix,source:hash,config:hash,ids:["target"])}
  try reject("private response expired"){_ = try privateScore(sr,streamMeta,1120000)}
  for field in ["capture_sha256","prefix_id","candidate_source_sha256","request_id","measurement"] {
   var bad=sr;bad[field]="foreign";try reject("private receipt foreign "+field){_ = try privateScore(bad)}
  }
  for field in ["kind","role","measurement","attempts","failed"] {
   var r=srow,b=sb,bad=sr
   switch field {case "kind":r[field]="tcp-connect";case "role":r[field]="final";case "measurement":b[field]="routed-tcp-connect";case "attempts":b[field]=49;default:b[field]=1}
   r["benchmark"]=b;bad["results"]=[r];try reject("private row foreign "+field){_ = try privateScore(bad)}
  }
  for key in ["schema","measurement","request_id","complete","drained","stage","capture_sha256","prefix_position","prefix_id","candidate_id","candidate_source_sha256","expires_at","measured_at"] {
   var bad=receipt
   switch key {case "complete","drained":bad[key]=false;case "schema","prefix_position":bad[key]=99;case "expires_at":bad[key]=1120001;case "measured_at":bad[key]=1000002;default:bad[key]="foreign"}
   try reject("receipt foreign \(key)"){_ = try score(bad)}
  }
  try reject("expired without renewal"){_ = try score(receipt,1120000)}
  for key in ["attempts","failed","distribution","trimmed_mean_ms"] {
   var bad=receipt,changed=row,b=benchmark
   if key=="distribution"{var d=distribution;d["samples"]=49;b[key]=d}else{b[key]=key=="failed" ? 1:99}
   changed["benchmark"]=b;bad["results"]=[changed]
   try reject("incomplete benchmark \(key)"){_ = try score(bad)}
  }
 }
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='.ios-candidate-compiler-',dir=ROOT) as gofolder,tempfile.TemporaryDirectory(prefix='ios-candidates-') as folder:
        work=Path(folder);go=Path(gofolder)/'main.go';go.write_text(SAVE_GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(go)],cwd=ROOT,check=True,timeout=180)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        stub=work/'Libbox.swift';stub.write_text(SAVE_LIBBOX);test=work/'Tests.swift';test.write_text(SWIFT)
        library=work/('libLibbox.dylib' if platform.system()=='Darwin' else 'libLibbox.so')
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(stub),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(library)],check=True,timeout=90)
        if platform.system()!='Darwin':
            crypto=work/'CryptoKit.swift';crypto.write_text(LINUX_CRYPTO)
            subprocess.run(options+['-emit-module','-emit-library','-module-name','CryptoKit',str(crypto),'-lcrypto','-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/'libCryptoKit.so')],check=True,timeout=90)
            options+=['-lCryptoKit']
        command=options+['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        files=['Models.swift','IOSMultihopStartLayer.swift','IOSCandidateCatalogPublication.swift','IOSNodeChainCapture.swift','IOSImportedOpenVPNSource.swift','IOSNodeCandidateOriginalCapture.swift','IOSNodeChainProviderCapture.swift','IOSNodeChainSOCKSCapture.swift','IOSNodeChainCONNECTCapture.swift','IOSNodeChainExecutionCapture.swift','IOSNodeCandidateCapture.swift','IOSNodeCandidateResult.swift','IOSNodeCandidateProposal.swift']
        binary=work/'test'
        subprocess.run(command+[str(APP/name) for name in files]+[str(test),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary),str(compiler)],check=True,timeout=180)
        subprocess.run([str(binary),str(compiler),'capacity'],check=True,timeout=180)
        for execution in ('local','server','auto'):
            subprocess.run([str(binary),str(compiler),execution],check=True,timeout=180)
        for filename, before, after, marker in [
            ('IOSNodeChainExecutionCapture.swift', '(position == 0 || !isSOCKS && !isCONNECT)', '(position == 0 || !isMultipleImported && !isSOCKS && !isCONNECT)', 'original typed source exposes each paired packet stop only'),
            ('IOSNodeChainExecutionCapture.swift', '(position == 0 || !isSOCKS && !isCONNECT)', '(position == 0 || isMultipleImported)', 'original ordinary selected execution retains recursive packet stops'),
            ('IOSNodeCandidateResult.swift', 'selectedPositions.contains(prefix_position), prefix.supported,', 'selectedPositions.contains(prefix_position) && prefix_position == 0, prefix.supported,', 'selected metadata admits each original paired packet stop'),
            ('IOSNodeCandidateCapture.swift', 'guard LibboxRouterNodeChainCandidateInputSupported(input) else', 'guard true else', 'paired legacy stays unscored'),
            ('IOSNodeCandidateResult.swift', 'expires_at - measured_at == 120000,', 'true,', 'ACCEPTED receipt foreign expires_at'),
            ('IOSNodeCandidateProposal.swift', 'Array(priorNodes.prefix(position + 1)) == Array(afterNodes.prefix(position + 1)),', 'true,', 'ACCEPTED future proposal changed original prefix'),
            ('IOSNodeCandidateProposal.swift', 'guard try IOSNodeCandidateCapture.member(profile: candidate.profile, files: candidate.files) == measuredInput else', 'guard true else', 'ACCEPTED future proposal changed measured source'),
            ('IOSNodeCandidateProposal.swift', 'guard execution.sourceSHA256 == sourceSHA256, execution.configSHA256 == configSHA256 else', 'guard true else', 'ACCEPTED execution proposal substituted preparation source'),
        ]:
            code=(APP/filename).read_text();assert code.count(before)==1
            mutant=work/filename;mutant.write_text(code.replace(before,after))
            subprocess.run(command+[str(mutant if name==filename else APP/name) for name in files]+[str(test),'-o',str(binary)],check=True,timeout=90)
            result=subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
            if result.returncode==0 or marker not in result.stdout+result.stderr:raise AssertionError('candidate causal control failed: '+filename+' '+result.stderr[-1500:])
        print('Apple candidate capture/receipt/proposal: eight causal controls rejected')
if __name__=='__main__':main()
