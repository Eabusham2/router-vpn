#!/usr/bin/env python3
"""Actual Apple Local independent-import Add/Update/Load/Delete transactions.

The original persistence fixture and five compiled controls remain mandatory.
Full source compilation uses the real shared Go compiler; storage and platform
APIs remain explicit test boundaries, without native/device proof claims.
"""
import test_ios_node_chain_connect_profiles as C

ROUNDTRIP=r'''
 static func independentRoundtrip()throws {
  let choice=CommandLine.arguments.last!, count=Int(choice) ?? (["private-sixteen","all-imported-sixteen"].contains(choice) ? 16:9)
  let cases: [(Bool,Bool,Bool)]
  switch choice {
  case "private-nine","private-sixteen","all-imported-sixteen","insert-nine": cases=[(false,false,true)]
  case "later-nine": cases=[(false,true,true)]
  default: cases=[(false,false,false),(true,false,false)] + (count==9 ? [(false,true,false)] : [])
  }
  for (joined,hostname,singlePrivate) in cases {
   let insertion = choice == "insert-nine"
   let (model, inventory) = try setupTyped(count + (insertion ? 1 : 0)), store = IOSNodeBundleStore.shared
   var ids = inventory
   let measuredID = insertion ? ids.remove(at: 4) : nil
   let laterHostname=hostname && singlePrivate
   let privateStreams:Set<Int> = laterHostname || choice=="all-imported-sixteen" || insertion ? [] : count>8 && !singlePrivate ? [2,3,count-3] : [2]
   let positions:Set<Int> = count>8 ? Set(1..<count-1).subtracting(privateStreams) : count==3 ? (joined ? [0,1]:[1]):[1,count-2]
   for position in positions {
    var value=try stored(ids[position]),profile=value.routerProfiles[0]
    profile.nodeKind="external";profile.nodeProofID=nil;profile.routerAPI="";profile.apiToken="";profile.startLayer="off";profile.endpoint=hostname && position==(laterHostname ? count-2:1) ? "Saved.Proxy.Example":"203.0.113.\(30+position)"
    profile.homeLANAccess=false;profile.killSwitchPolicy="always";profile.dnsMode="custom";profile.dnsProtocol="tcp";profile.dnsHost="10.81.0.53";profile.dnsPort=5353
    let original:[String:Any]=["protocol":"shadowsocks","expected_public_ip":"203.0.113.\(80+position)","shadowsocks":["server":profile.endpoint,"port":8388+position,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:UInt8(91+position),count:32).base64EncodedString()]]
    profile.external=try JSONDecoder().decode(ExternalNodeConfig.self,from:JSONSerialization.data(withJSONObject:original));value.routerProfiles=[profile];value.profiles=[:];try store.save(value)
   }
   if joined && positions.count>1 {
    let before=store.records,originals=try positions.sorted().map{try stored(ids[$0])}
    var grouped=originals[0];grouped.routerProfiles=originals.flatMap(\.routerProfiles)
    let keys=try before.filter { _,bytes in let value=try JSONDecoder().decode(ClientBundle.self,from:bytes);return value.routerProfiles.contains{p in grouped.routerProfiles.contains{$0.id==p.id}} }.map(\.key)
    for key in keys{store.records.removeValue(forKey:key)}
    try store.save(grouped)
   }
   var final=try stored(ids[count-1]);final.routerProfiles[0].multihopExecution="local"
   if let measuredID {
    final.routerProfiles[0].multihopNodes!.removeAll { $0.id == measuredID }
    final.routerProfiles[0].multihopExecution = "auto"
   }
   for position in 0..<count-1{final.routerProfiles[0].multihopNodes![position].mode=positions.contains(position) || count>8 && privateStreams.contains(position) ? "shadowsocks":"wg"}
   try store.save(final);model.bundle=final
   if let measuredID {
    let position = 3, original = final.routerProfiles[0].multihopNodes!
    var proposed = final
    proposed.routerProfiles[0].multihopNodes!.insert(.init(id: measuredID, mode: "shadowsocks"), at: position + 1)
    let bundles = try model.iosNodeChainBundles(for: proposed)
    let profiles = bundles.map { bundle in bundle.routerProfiles.first { $0.id == bundle.selectedRouterID }! }
    let native = try IOSNodeChainExecutionCapture.compile(bundles: bundles.map { try encoded($0) }, requested: "auto")
    defer { try? native.close() }
    let before = store.records, home = try encoded(model.bundle!), expected = proposed.routerProfiles[0].multihopNodes!
    var editor = IOSNodeChainDraft(saved: original, finalID: final.selectedRouterID)
    try reject("another prefix cannot adopt this compiled draft") { try editor.insertMeasured(measuredID, after: position - 1, compiled: expected) }
    try reject("a truncated draft cannot adopt a complete measured insertion") { try editor.insertMeasured(measuredID, after: position, compiled: Array(expected.dropLast())) }
    try editor.insertMeasured(measuredID, after: position, compiled: expected)
    try check("Use changes only the draft and retains every original member",try editor.nodes == expected && encoded(model.bundle!) == home && store.records == before)
    try reject("the previous insertion cannot be replayed") { try editor.insertMeasured(measuredID, after: position, compiled: expected) }
    var unfilled = original
    unfilled.insert(.init(id:"",mode:"wg"),at:position+1)
    var partial = IOSNodeChainDraft(saved: unfilled, finalID: final.selectedRouterID)
    try partial.insertMeasured(measuredID, after:position, compiled:expected)
    try check("an empty editor row preserves every measured suffix member",partial.nodes==expected)
    let record = try IOSConnectionProfileStore.appendCandidate(name: "Measured intermediate after hop four", profiles: profiles, current: {})
    try check("saving the intermediate preserves Home and all original node records",
              try encoded(model.bundle!) == home && store.records == before && record.chainPolicies?.map(\.nodeID) == expected.map(\.id))
    let actions = TypedProfileActions(model)
    actions.selectedID = record.id
    actions.load()
    guard actions.status.hasPrefix("Loaded "), let loaded = model.bundle else { throw failure(actions.status) }
    let restored = try model.iosNodeChainBundles(for: loaded)
    let replay = try IOSNodeChainExecutionCapture.compile(bundles: restored.map { try encoded($0) }, requested: "auto")
    defer { try? replay.close() }
    try check("Load retains the measured intermediate, each original suffix member and the old final",
              loaded.routerProfiles[0].multihopNodes == expected && Array(expected.dropFirst(position+2)) == Array(original.dropFirst(position+1)) &&
              loaded.selectedRouterID == final.selectedRouterID && replay.source == native.source)
    actions.delete()
    continue
   }
   if ["private-sixteen","all-imported-sixteen"].contains(choice) {
    let originalNodes=final.routerProfiles[0].multihopNodes!
    var paths=[originalNodes]
    if choice=="private-sixteen" {var swapped=originalNodes;swapped.swapAt(2,count-2);paths.append(swapped)}
    for nodes in paths {
     var selected=final;selected.routerProfiles[0].multihopNodes=nodes;selected.routerProfiles[0].multihopExecution="auto"
     let linked=try model.iosNodeChainBundles(for:selected)
     let profiles=linked.map { bundle in bundle.routerProfiles.first(where:{$0.id==bundle.selectedRouterID})! }
     let draft=IOSNodeChainDraft(saved:nodes,finalID:ids.last!)
     try check("sixteen-member editor retains the original Compare source",try draft.measurementPath(through:count-2,execution:"auto",profiles:profiles)==nodes)
     try reject("Server cannot request a private response at position fourteen"){_=try draft.measurementPath(through:count-2,execution:"server",profiles:profiles)}
     let expectedStops=choice=="all-imported-sixteen" ? Array(1...count-2):[count-2]
     if expectedStops.contains(1) {try check("every earlier editor stop retains the original selected graph",try expectedStops.allSatisfy {try draft.measurementPath(through:$0,execution:"auto",profiles:profiles)==nodes})}
     else {try reject("existing private interior cannot accept another private intermediate"){_=try draft.measurementPath(through:1,execution:"auto",profiles:profiles)}}
     try reject("penultimate chooser requires every original source"){_=try draft.measurementPath(through:count-2,execution:"auto",profiles:Array(profiles.dropFirst()))}
     let original=try IOSNodeChainExecutionCapture.compile(bundles:linked.map {try encoded($0)},requested:"auto")
     defer {try? original.close()}
     try check("extended editor derives its stops from the original selected capture",original.extendedOriginalNodeCount==count && original.responsePositions(for:"local")==expectedStops && original.responsePositions(for:"server").isEmpty)
    }
    continue
   }
   let beforeSources=try model.iosNodeChainBundles(for:final),originals=try beforeSources.map{try encoded($0)},native=try IOSNodeChainCapture.compile(bundles:originals);defer{try? native.plan.close()}
   if laterHostname {
    let members=beforeSources.map { bundle in bundle.routerProfiles.first(where:{$0.id==bundle.selectedRouterID})! }
    let nodes=final.routerProfiles[0].multihopNodes!
    try check("later hostname retained its sole imported position",IOSMultihopNodeSelection.localStreamLayout(nodes,execution:"local",profiles:members)?.hostname == count-2)
    for execution in ["server","auto"] {
     var refused=final;refused.routerProfiles[0].multihopExecution=execution
     try check("later hostname cannot adopt selected execution",(try? model.iosNodeChainBundles(for:refused)) == nil)
    }
   }
   if (count==5 || count>8) && !joined && !laterHostname {
    var proposed=final
    proposed.routerProfiles[0].multihopNodes![2].mode="shadowsocks"
    let pairedBundles=try model.iosNodeChainBundles(for:proposed)
    let pairedProfiles=pairedBundles.map { value in value.routerProfiles.first{$0.id==value.selectedRouterID}! }
    let source=try IOSNodeChainCapture.compile(bundles:pairedBundles.map{try encoded($0)})
    defer {try? source.plan.close()}
    let home=try encoded(model.bundle!),records=store.records
    let named=try IOSConnectionProfileStore.appendCandidate(name:"Measured private intermediate",profiles:pairedProfiles,current:{})
    try check("named private intermediate save preserves Home and every node record",try encoded(model.bundle!)==home && store.records==records && named.nodeID==ids.last && named.chainPolicies?.map(\.nodeID)==ids)
    try check("named private intermediates preserve independent private and public identities",privateStreams.allSatisfy{named.chainPolicies?[$0].nodeProofID==pairedProfiles[$0].nodeProofID && named.chainPolicies?[$0].nodeKind=="router-vpn"} && positions.allSatisfy{named.chainPolicies?[$0].nodeKind=="external"})
    try check("private intermediates have exact map roles",IOSMultihopNodeSelection.pairedStreamPositions(proposed.routerProfiles[0].multihopNodes!,execution:"local",profiles:pairedProfiles)==privateStreams)
    let nodes=proposed.routerProfiles[0].multihopNodes!
    for execution in ["server","auto"] {
     let roles=IOSMultihopNodeSelection.pairedStreamPositions(nodes,execution:execution,profiles:pairedProfiles)
     let qualified=privateStreams.count==1 && !hostname
     try check("selected roles require the complete single private stream shape",roles==(qualified ? privateStreams:[]))
     var selected=proposed;selected.routerProfiles[0].multihopExecution=execution
     let draft=IOSNodeChainDraft(saved:nodes,finalID:ids.last!)
     if qualified {
      try check("selected entry candidate retains every private and public reference",try draft.measurementPath(through:0,execution:execution,profiles:pairedProfiles)==nodes)
      try reject("private stream has no selected response authority"){_ = try draft.measurementPath(through:2,execution:execution,profiles:pairedProfiles)}
      var penultimate=nodes;penultimate.swapAt(2,count-2)
      let complete=IOSNodeChainDraft(saved:penultimate,finalID:ids.last!)
      if execution=="auto" {
       try check("private penultimate chooser retains its complete Compare source",try complete.measurementPath(through:count-2,execution:execution,profiles:pairedProfiles)==penultimate)
      } else {try reject("Server cannot measure through the private penultimate"){_ = try complete.measurementPath(through:count-2,execution:execution,profiles:pairedProfiles)}}
      var crossed=nodes;crossed[0].mode="awg2-fast"
      try reject("private stream requires WG entry for candidate selection"){_ = try IOSNodeChainDraft(saved:crossed,finalID:ids.last!).measurementPath(through:0,execution:execution,profiles:pairedProfiles)}
      let linked=try model.iosNodeChainBundles(for:selected),bytes=try linked.map{try encoded($0)}
      let original=try IOSNodeChainExecutionCapture.compile(bundles:bytes,requested:execution)
      defer { try? original.close() }
      let session=try IOSSessionIdentity(connectedAt:Date(),engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:bytes.last!,entryBundleData:nil,nodeChainExecutionSource:Data(original.ordinaryLaunchInput.utf8))
      if count>8 {
       try check("extended selected session retains its sealed private position",session.selectedMeasurementSource?.privateStreamPosition==2 && session.selectedMeasurementSource?.ids==ids)
       for winner in execution=="server" ? ["server"]:["local","server"] {
        let rows:[[String:Any]]=ids.enumerated().map{ i,id in
         ["position":i,"profile_id":id,"proven":true,"response_ms":Double(i+1),"kind":positions.contains(i) ? "public-path":"private-node"]
        }
        var report:[String:Any]=["stage":"selected","execution":winner,"prefixes":rows,"ready":true,"complete":true,"dns_proven":true,"public_proven":true]
        func rendered(_ measured:[String:Any],_ count:Int)->String? { ProfileProgress.progress(measured,expected:ids,requestedExecution:execution,expectedPublicPositions:positions,capturedExtendedCount:count) }
        let text=rendered(report,session.hopMeasurementRows)
        try check("private and public RTTs retain original roles",text?.contains(ids[2]+": verification HTTP response 3.0 ms")==true && text?.contains(ids[1]+": public path via custom node 2.0 ms")==true)
        try check("foreign capture count cannot publish long progress",rendered(report,8)==nil)
        var crossed=rows;crossed[2]["kind"]="public-path";report["prefixes"]=crossed
        try check("private progress cannot adopt public measurement",rendered(report,count)==nil)
        crossed=rows;crossed[2]["proven"]=false;report["prefixes"]=crossed
        try check("unproved progress cannot publish a measured RTT",rendered(report,count)==nil)
       }
      }
      try check("selected native source retained the private stream identity",original.members.count==count && original.members[2].profile["node_proof_id"] as? String==pairedProfiles[2].nodeProofID)
      let row=try IOSConnectionProfileStore.appendCandidate(name:"Selected private stream",profiles:linked.map{ bundle in bundle.routerProfiles.first(where:{$0.id==bundle.selectedRouterID})!},current:{})
      let actions=TypedProfileActions(model);actions.selectedID=row.id;actions.load()
      try check("selected private stream named Load retained execution",actions.status.hasPrefix("Loaded ") && model.bundle?.routerProfiles.first?.multihopExecution==execution)
      let reloaded=try model.iosNodeChainBundles(for:model.bundle!).map{try encoded($0)}
      let replay=try IOSNodeChainExecutionCapture.compile(bundles:reloaded,requested:execution)
      defer { try? replay.close() }
      try check("selected private stream named Load retained native source",replay.source==original.source)
      actions.delete()
      try store.save(final);model.bundle=final
     } else {
      try reject("unqualified source cannot measure the selected entry"){_ = try draft.measurementPath(through:0,execution:execution,profiles:pairedProfiles)}
      var accepted=false
      if let linked=try? model.iosNodeChainBundles(for:selected), let bytes=try? linked.map({ try encoded($0) }),
         let unexpected=try? IOSNodeChainExecutionCapture.compile(bundles:bytes,requested:execution){accepted=true;try unexpected.close()}
      try check("selected execution refused unqualified original private roles",!accepted)
     }
    }
    var layered=pairedProfiles;layered[2].startLayer="aes-256-gcm"
    var duplicate=pairedProfiles;duplicate[2].nodeProofID=duplicate[0].nodeProofID
    for invalid in [layered,duplicate,Array(pairedProfiles.dropLast())] {try check("private role requires complete independent unlayered originals",IOSMultihopNodeSelection.pairedStreamPositions(nodes,execution:"local",profiles:invalid).isEmpty)}
    let namedActions=TypedProfileActions(model);namedActions.selectedID=named.id;namedActions.load()
    try check("named private intermediate Load reaches original sources",namedActions.status.hasPrefix("Loaded "))
    let loaded=try model.iosNodeChainBundles(for:model.bundle!),restored=try IOSNodeChainCapture.compile(bundles:loaded.map{try encoded($0)})
    defer{try? restored.plan.close()}
    try check("loaded private intermediate compiles identical launch",restored.launchInput==source.launchInput)
    namedActions.delete()
    for bundle in beforeSources {try store.save(bundle)}
    model.bundle=final
   }
   let actions=TypedProfileActions(model);actions.name="Independent Local original route";actions.add()
   guard let saved=IOSConnectionProfileStore.all().first(where:{$0.id==actions.selectedID})else{throw failure("independent Add callback failed: "+actions.status)}
   try check("independent Add callback",actions.status.hasPrefix("Added "))
   try check("independent complete policy inventory",saved.chainPolicies?.map(\.nodeID)==ids && saved.preferences?.multihopNodes==final.routerProfiles[0].multihopNodes)
   for position in 0..<count {
    try check("independent policy position",saved.chainPolicies?[position].nodeID==ids[position] && saved.chainPolicies?[position].nodeKind==(positions.contains(position) ? "external":"router-vpn"))
    if positions.contains(position){try check("independent original public identity",saved.chainPolicies?[position].externalPublicIP=="203.0.113.\(80+position)" && saved.chainPolicies?[position].nodeProofID==nil)}
   }
   let savedBytes=String(decoding:IOSPrivateJSONStore.bytes!,as:UTF8.self)
   for position in positions{try check("independent safe profile omits private key",!savedBytes.contains(Data(repeating:UInt8(91+position),count:32).base64EncodedString()))}
   model.bundle=nil;actions.load()
   try check("independent Load callback (hostname \(hostname), later \(laterHostname), single private \(singlePrivate)): \(actions.status)",actions.status.hasPrefix("Loaded "))
   let current=try model.iosNodeChainBundles(for:model.bundle!),restored=try IOSNodeChainCapture.compile(bundles:current.map{try encoded($0)});defer{try? restored.plan.close()}
   try check("independent Load native source equality",restored.launchInput==native.launchInput && restored.config==native.config)
   try check("independent Load every original record",try current.map{try encoded($0)}==originals)
   actions.name="Updated independent route";actions.update();try check("independent Update callback",actions.status.hasPrefix("Updated ") && IOSConnectionProfileStore.all().first{$0.id==saved.id}?.chainPolicies==saved.chainPolicies)
   let records=store.records,writes=store.writes,imports=model.imports
   store.failWrite=true;actions.load();store.failWrite=false
   try check("independent durable failure rollback",!actions.status.hasPrefix("Loaded ") && store.records==records && store.writes==writes && model.imports==imports)
   IOSDNSRuntimePolicy.onPrepare={
    IOSDNSRuntimePolicy.onPrepare=nil
    try! replaceRaw(ids[1]){source in let i=source.routerProfiles.firstIndex{$0.id==ids[1]}!;source.routerProfiles[i].external?.shadowsocks?.password=Data(repeating:199,count:32).base64EncodedString()}
   }
   actions.load()
   try check("independent source race rollback",!actions.status.hasPrefix("Loaded ") && store.writes==writes && model.imports==imports)
   try check("independent source race preserves current key",try stored(ids[1]).routerProfiles.first{$0.id==ids[1]}?.external?.shadowsocks?.password==Data(repeating:199,count:32).base64EncodedString())
   try replaceRaw(ids[1]){source in let i=source.routerProfiles.firstIndex{$0.id==ids[1]}!;source.routerProfiles[i].external?.expectedPublicIP="203.0.113.222"}
   let changed=store.records
   try reject("independent public identity replacement"){_ = try IOSConnectionProfileStore.load(model:model,id:saved.id)}
   try check("independent identity refusal unchanged state",store.records==changed && store.writes==writes && model.imports==imports)
   actions.delete();try check("independent Delete callback",actions.selectedID==nil && !IOSConnectionProfileStore.all().contains{$0.id==saved.id} && store.records==changed)
  }
 }
'''

def main():
    # setupTyped immediately replaces the placeholder records with the complete
    # native fixture. Reset the shared preferences using a valid two-node pair.
    source=C.TYPED.replace('_ = try setup(count)', '_ = try setup(2)', 1)
    start=source.index(' static func connectRoundtrip()throws {')
    source=source[:start]+ROUNDTRIP
    # Sufficient original packet assets are established before canonical capture.
    old='   profiles[0]=profile;root["routerProfiles"]=profiles\n'
    new=old+r'''
   // The current bundle format is established before capture. Load legitimately
   // upgrades legacy version-one wrappers; migration is covered separately.
   root["profileSchemaVersion"]=4
   var assets=root["profiles"] as! [String:[String:String]]
   for kind in ["wg","awg2-fast","awg2-strong"] {var files=assets[kind]!;for(name,encoded)in files {if name.hasSuffix(".conf"){let raw=String(decoding:Data(base64Encoded:encoded)!,as:UTF8.self);files[name]=Data(raw.replacingOccurrences(of:"MTU=2000",with:"MTU=4096").utf8).base64EncodedString()}};assets[kind]=files};root["profiles"]=assets
'''
    assert source.count(old)==1;source=source.replace(old,new,1)
    presentation=(C.P.APP/'IOSNodeChainPresentation.swift').read_text()
    progress=C.L.S.member(presentation,'    static func progress(')
    boolean=C.L.S.member(presentation,'    private static func boolean(')
    C.P.BOUNDARIES='import CoreFoundation\n'+C.P.BOUNDARIES+'\nenum ProfileProgress {\n'+boolean+'\n'+progress+'\n}\n'
    C.P.BOUNDARIES+='\n'+C.L.S.member((C.P.APP/'IOSNodeChainEditor.swift').read_text(),'struct IOSNodeChainDraft {')+'\n'
    C.TYPED=source
    C.main(label='independent Local imports',roundtrip='independentRoundtrip',binary_cases=[(str(n),) for n in range(3,10)]+[("private-nine",),("private-sixteen",),("all-imported-sixteen",),("insert-nine",),("later-nine",)],extra_source_names=("IOSSessionIdentity.swift",))
if __name__=='__main__':main()
