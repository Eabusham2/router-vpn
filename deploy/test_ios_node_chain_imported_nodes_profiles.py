#!/usr/bin/env python3
"""Actual Apple Local independent-import Add/Update/Load/Delete transactions.

The original persistence fixture and five compiled controls remain mandatory.
Full source compilation uses the real shared Go compiler; storage and platform
APIs remain explicit test boundaries, without native/device proof claims.
"""
import test_ios_node_chain_connect_profiles as C

ROUNDTRIP=r'''
 static func independentRoundtrip()throws {
  let count=Int(CommandLine.arguments.last!)!
  for joined in [false,true] {
   let(model,ids)=try setupTyped(count),store=IOSNodeBundleStore.shared
   let positions:Set<Int> = count==3 ? (joined ? [0,1]:[1]):[1,count-2]
   for position in positions {
    var value=try stored(ids[position]),profile=value.routerProfiles[0]
    profile.nodeKind="external";profile.nodeProofID=nil;profile.routerAPI="";profile.apiToken="";profile.startLayer="off";profile.endpoint="203.0.113.\(30+position)"
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
   for position in 0..<count-1{final.routerProfiles[0].multihopNodes![position].mode=positions.contains(position) ? "shadowsocks":"wg"}
   try store.save(final);model.bundle=final
   let beforeSources=try model.iosNodeChainBundles(for:final),originals=try beforeSources.map{try encoded($0)},native=try IOSNodeChainCapture.compile(bundles:originals);defer{try? native.plan.close()}
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
   try check("independent Load callback",actions.status.hasPrefix("Loaded "))
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
    source=C.TYPED
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
    C.TYPED=source
    C.main(label='independent Local imports',roundtrip='independentRoundtrip',binary_cases=[(str(n),) for n in range(3,9)])
if __name__=='__main__':main()
