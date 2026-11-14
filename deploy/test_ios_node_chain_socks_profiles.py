#!/usr/bin/env python3
"""Execute typed Add/Update/Load/Delete and real source replay with original controls.

View state, durable storage and NetworkExtension are explicit boundaries.
The shipping callback/store bodies and shared Go source compiler are real;
this fixture does not open a native tunnel or claim device acceptance.
"""
from pathlib import Path
import platform
import subprocess
import tempfile
import test_ios_node_chain_profiles as P
import test_ios_node_chain_capture as C
import test_ios_node_chain_launch as L

TYPED=r'''
 static func setupTyped()throws->(RouterVPNModel,[String]) {
  _ = try setup(3)
  let store=IOSNodeBundleStore.shared;store.records=[:]
  let roots=try JSONSerialization.jsonObject(with:Data(LibboxTestAWGFixture(3,"off").utf8)) as! [[String:Any]]
  var bundles=try roots.map{original -> ClientBundle in
   var root=original,profiles=root["routerProfiles"] as! [[String:Any]],profile=profiles[0]
   profile["name"]=profile["id"];profile["adguard_ipv6"]="";profile["socks_host"]="";profile["socks_port"]=0;profile["socks_username"]="";profile["socks_password"]=""
   profiles[0]=profile;root["routerProfiles"]=profiles
   return try JSONDecoder().decode(ClientBundle.self,from:JSONSerialization.data(withJSONObject:root))
  }
  let ids=bundles.map{"rvpn-"+String($0.routerProfiles[0].nodeProofID!.prefix(16))}
  for position in bundles.indices {
   bundles[position].selectedRouterID=ids[position];bundles[position].routerProfiles[0].id=ids[position]
   if position==2 {bundles[position].routerProfiles[0].multihopNodes=ids.enumerated().map{.init(id:$0.element,mode:$0.offset==2 ? "shadowsocks":"wg")}}
   bundles[position].routerProfiles[0]=try IOSConnectionProfileStore.fixtureCanonicalProfile(bundles[position].routerProfiles[0])
   try store.save(bundles[position])
  }
  let model=RouterVPNModel();model.bundle=try stored(ids[2]);return(model,ids)
 }

 static func socksRoundtrip()throws {
  for mode in ["wg","awg2-fast","awg2-strong"] {for host in ["198.51.100.76","2001:db8::76"] {for authenticated in [false,true] {
   let(model,ids)=try setupTyped(),store=IOSNodeBundleStore.shared
   var middle=try stored(ids[1]),profile=middle.routerProfiles[0]
   profile.nodeKind="external";profile.nodeProofID=nil;profile.routerAPI="";profile.apiToken="";profile.startLayer="off";profile.endpoint=host
   profile.homeLANAccess=false;profile.killSwitchPolicy="always";profile.dnsMode="custom";profile.dnsProtocol="tcp";profile.dnsHost="10.81.0.53";profile.dnsPort=5353
   var socks:[String:Any]=["host":host,"port":1080]
   if authenticated{socks["username"]="PRIVATE-SOCKS-USER";socks["password"]="PRIVATE-SOCKS-PASSWORD"}
   let original:[String:Any]=["protocol":"socks5","expected_public_ip":"203.0.113.76","socks5":socks]
   profile.external=try JSONDecoder().decode(ExternalNodeConfig.self,from:JSONSerialization.data(withJSONObject:original))
   middle.routerProfiles=[profile];middle.profiles=[:];try store.save(middle)
   var final=model.bundle!;final.routerProfiles[0].multihopNodes![0].mode=mode;final.routerProfiles[0].multihopNodes![1].mode="socks5";try store.save(final);model.bundle=try stored(ids.last!)
   let beforeSource=try IOSNodeChainSOCKSCapture.compile(bundles:try model.iosNodeChainBundles(for:model.bundle!).map{try encoded($0)});defer{try? beforeSource.plan.close()}
   let actions=TypedProfileActions(model);actions.name="Typed SOCKS original route";actions.add()
   guard let saved=IOSConnectionProfileStore.all().first(where:{$0.id==actions.selectedID}) else{throw failure("actual typed Add callback did not persist")}
   try check("actual Add callback selects saved profile",actions.status.hasPrefix("Added "))
   try check("typed profile stores exact three positions",saved.preferences?.multihopNodes?.map(\.mode)==[mode,"socks5","shadowsocks"] && saved.chainPolicies?.map(\.nodeID)==ids)
   try check("typed profile retains external authority",saved.chainPolicies?[1].nodeKind=="external" && saved.chainPolicies?[1].externalProtocol=="socks5" && saved.chainPolicies?[1].nodeProofID==nil && saved.chainPolicies?[1].externalPublicIP=="203.0.113.76")
   let visible=String(decoding:IOSPrivateJSONStore.bytes!,as:UTF8.self)
   try check("typed profile omits username",!visible.contains("PRIVATE-SOCKS-USER"))
   try check("typed profile omits password",!visible.contains("PRIVATE-SOCKS-PASSWORD"))
   let originalBytes=try encoded(middle.routerProfiles[0].external!),originalAssets=final.profiles
   model.bundle=nil
   actions.load()
   try check("actual Load callback keeps Connect separate",actions.status.hasPrefix("Loaded ") && actions.status.contains("Connect separately") && !actions.status.contains("Older profile"))
   let captured=try model.iosNodeChainBundles(for:model.bundle!)
   try check("typed profile loads all original independent records",captured.count==3 && captured[1].selectedRouterID==ids[1] && captured[2].selectedRouterID==ids[2])
   try check("typed profile Load keeps literal and private credentials",try encoded(captured[1].routerProfiles[0].external!)==originalBytes && captured[1].routerProfiles[0].endpoint==host)
   try check("typed profile Load keeps paired final assets",model.bundle!.profiles==originalAssets)
   try check("typed profile Load keeps middle protection and selected TCP resolver",captured[1].routerProfiles[0].homeLANAccess==false && captured[1].routerProfiles[0].killSwitchPolicy=="always" && captured[1].routerProfiles[0].dnsProtocol=="tcp" && captured[1].routerProfiles[0].dnsHost=="10.81.0.53" && captured[1].routerProfiles[0].dnsPort==5353)
   let afterSource=try IOSNodeChainSOCKSCapture.compile(bundles:try captured.map{try encoded($0)});defer{try? afterSource.plan.close()}
   try check("typed profile Load reopens exact native source and config",afterSource.source==beforeSource.source && afterSource.config==beforeSource.config)
   let round=try IOSConnectionProfileStore.snapshot(model:model,name:saved.name,id:saved.id)
   try check("typed profile roundtrip preserves safe policy",round.preferences==saved.preferences && round.chainPolicies==saved.chainPolicies)
   actions.name="Updated typed route";actions.update()
   guard let updated=IOSConnectionProfileStore.all().first(where:{$0.id==saved.id}) else{throw failure("actual typed Update callback lost record")}
   try check("actual Update callback reports stored result",actions.status.hasPrefix("Updated "))
   try check("typed Update keeps stable record identity and complete source references",updated.id==saved.id && updated.name=="Updated typed route" && updated.chainPolicies==saved.chainPolicies)
   let beforeRaceWrites=store.writes,beforeRaceImports=model.imports
   IOSDNSRuntimePolicy.onPrepare={
    IOSDNSRuntimePolicy.onPrepare=nil
    try! replaceRaw(ids[1]){$0.routerProfiles[0].external?.socks5?.username="relinked-user";$0.routerProfiles[0].external?.socks5?.password="relinked-valid-password"}
   }
   actions.load()
   try check("typed Load rejects private source changed during atomic preparation",!actions.status.hasPrefix("Loaded ") && store.writes==beforeRaceWrites && model.imports==beforeRaceImports)
   try check("typed Load refusal retains newer private credential source",try stored(ids[1]).routerProfiles[0].external?.socks5?.password=="relinked-valid-password")
   try replaceRaw(ids[1]){$0.routerProfiles[0].external?.expectedPublicIP="203.0.113.77"}
   let records=store.records,writes=store.writes,imports=model.imports
   try reject("typed profile replaced middle public identity"){_ = try IOSConnectionProfileStore.load(model:model,id:saved.id)}
   try check("typed failed Load preserves all private records",store.records==records && store.writes==writes)
   try check("typed failed Load never changes active selection",model.imports==imports)
   actions.load()
   try check("actual failed Load callback reports refusal",!actions.status.hasPrefix("Loaded ") && model.imports==imports)
   actions.delete()
   try check("actual Delete callback clears only saved selection",actions.selectedID==nil && actions.status=="Deleted saved connection profile.")
   try check("typed Delete removes only saved preference record",!IOSConnectionProfileStore.all().contains(where:{$0.id==saved.id}) && store.records==records && model.imports==imports)
  }}}
 }
'''

def main():
    anchor=' static func main(){do{'
    assert P.BOUNDARIES.count(anchor)==1
    P.BOUNDARIES=P.BOUNDARIES.replace(anchor,TYPED+'\n'+anchor,1)
    anchor='try hysteriaRoundtrip();print('
    assert P.BOUNDARIES.count(anchor)==1
    P.BOUNDARIES=P.BOUNDARIES.replace(anchor,'try hysteriaRoundtrip();try socksRoundtrip();print(',1)
    P.BOUNDARIES='import Libbox\n'+P.BOUNDARIES
    P.BOUNDARIES += '\nextension IOSConnectionProfileStore { static func fixtureCanonicalProfile(_ value:RouterProfile)throws->RouterProfile { applying(try capturePreferences(value),to:value) } }\n'
    P.BOUNDARIES=P.BOUNDARIES.replace('static func main(){do{','static func main(){defer{LibboxTestClose()};do{',1)
    view=(P.APP/'IOSConnectionProfilesView.swift').read_text()
    callbacks=[]
    for operation in ('add','update','load','delete'):
        callback=L.S.member(view,'    private func '+operation+'()')
        assert 'IOSConnectionProfileStore.'+operation+'(model: model' in callback
        callbacks.append(callback.replace('private func','func',1))
    actions='@MainActor final class TypedProfileActions { let model:RouterVPNModel; var name="",status=""; var selectedID:String?; init(_ model:RouterVPNModel){self.model=model}; func refresh(){}\n'+'\n'.join(callbacks)+'\n}\n'
    P.BOUNDARIES += actions
    with tempfile.TemporaryDirectory(prefix='.ios-socks-profile-compiler-',dir=P.ROOT) as go_dir,tempfile.TemporaryDirectory(prefix='ios-socks-profile-libbox-') as folder:
        go_dir,work=Path(go_dir),Path(folder)
        (go_dir/'main.go').write_text(C.GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(go_dir/'main.go')],cwd=P.ROOT,check=True,timeout=180)
        lib=work/'Libbox.swift';lib.write_text(C.LIBBOX)
        library=work/('libLibbox.dylib' if platform.system()=='Darwin' else 'libLibbox.so')
        subprocess.run(['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules'),'-emit-module','-emit-library','-module-name','Libbox',str(lib),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(library)],check=True,timeout=90)
        P.main(extra_sources=[P.APP/name for name in ('IOSMultihopStartLayer.swift','IOSNodeChainCapture.swift','IOSNodeChainProviderCapture.swift','IOSNodeChainSOCKSCapture.swift')],extra_flags=['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)],binary_args=[compiler])
    print('Apple typed SOCKS profile composition: original persistence and controls completed')
if __name__=='__main__':main()
