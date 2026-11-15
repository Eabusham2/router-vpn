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
import test_ios_node_chain_execution_capture as E

TYPED=r'''
 struct ProfileCapture {let source:String,config:String;let close:()throws->Void}
 static func profileSource(_ bundles:[Data],_ requested:String)throws->ProfileCapture{
  if requested=="local"{let value=try IOSNodeChainCONNECTCapture.compile(bundles:bundles);return ProfileCapture(source:value.source,config:value.config,close:{try value.plan.close()})}
  let value=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested);return ProfileCapture(source:value.source,config:value.config,close:{try value.close()})
 }

 static func setupTyped(_ count:Int=3)throws->(RouterVPNModel,[String]) {
  _ = try setup(count)
  let store=IOSNodeBundleStore.shared;store.records=[:]
  let roots=try JSONSerialization.jsonObject(with:Data(LibboxTestAWGFixture(count,"off").utf8)) as! [[String:Any]]
  var bundles=try roots.map{original -> ClientBundle in
   var root=original,profiles=root["routerProfiles"] as! [[String:Any]],profile=profiles[0]
   profile["name"]=profile["id"];profile["adguard_ipv6"]="";profile["socks_host"]="";profile["socks_port"]=0;profile["socks_username"]="";profile["socks_password"]=""
   profiles[0]=profile;root["routerProfiles"]=profiles
   return try JSONDecoder().decode(ClientBundle.self,from:JSONSerialization.data(withJSONObject:root))
  }
  let ids=bundles.map{"rvpn-"+String($0.routerProfiles[0].nodeProofID!.prefix(16))}
  for position in bundles.indices {
   bundles[position].selectedRouterID=ids[position];bundles[position].routerProfiles[0].id=ids[position]
   if position==count-1 {bundles[position].routerProfiles[0].multihopNodes=ids.enumerated().map{.init(id:$0.element,mode:$0.offset==count-1 ? "shadowsocks":"wg")}}
   bundles[position].routerProfiles[0]=try IOSConnectionProfileStore.fixtureCanonicalProfile(bundles[position].routerProfiles[0])
   try store.save(bundles[position])
  }
  let model=RouterVPNModel();model.bundle=try stored(ids[count-1]);return(model,ids)
 }

 static func connectRoundtrip()throws {
  for count in 3...8 {for mode in (count==3 ? ["wg","awg2-fast","awg2-strong"]:["wg"]) {for host in (count==3 ? ["198.51.100.76","2001:db8::76"]:["198.51.100.76"]) {for authenticated in (count==3 ? [false,true]:[true]) {for kind in ["http-connect","https-connect"] {for requested in (count==3 && mode=="wg" && host=="198.51.100.76" && authenticated ? ["local","server","auto"]:["local"]) {
   let middlePosition=count-2,finalPosition=count-1
   let(model,ids)=try setupTyped(count),store=IOSNodeBundleStore.shared
   var middle=try stored(ids[middlePosition]),profile=middle.routerProfiles[0]
   profile.nodeKind="external";profile.nodeProofID=nil;profile.routerAPI="";profile.apiToken="";profile.startLayer="off";profile.endpoint=host
   profile.homeLANAccess=false;profile.killSwitchPolicy="always";profile.dnsMode="custom";profile.dnsProtocol="tcp";profile.dnsHost="10.81.0.53";profile.dnsPort=5353
   var socks:[String:Any]=["host":host,"port":1080]
   if authenticated{socks["username"]="PRIVATE-CONNECT-USER";socks["password"]="PRIVATE-CONNECT-PASSWORD"}
   if kind=="https-connect" {socks["tls_server_name"]="Original.Proxy.Example"}
   let original:[String:Any]=["protocol":kind,"expected_public_ip":"203.0.113.76",kind.replacingOccurrences(of:"-",with:"_"):socks]
   profile.external=try JSONDecoder().decode(ExternalNodeConfig.self,from:JSONSerialization.data(withJSONObject:original))
   middle.routerProfiles=[profile];middle.profiles=[:];try store.save(middle)
   var final=model.bundle!;final.routerProfiles[0].multihopExecution=requested;for prefix in 0..<middlePosition {final.routerProfiles[0].multihopNodes![prefix].mode=mode};final.routerProfiles[0].multihopNodes![middlePosition].mode=kind;final.routerProfiles[0].dnsMode="custom";final.routerProfiles[0].dnsProtocol="tcp";final.routerProfiles[0].dnsHost="10.82.0.53";final.routerProfiles[0].dnsPort=5353
   var graph=try JSONSerialization.jsonObject(with:Data(base64Encoded:final.profiles["shadowsocks"]!["sing-box.json"]!)!) as! [String:Any]
   graph["dns"]=["servers":[["type":"tcp","tag":"home-dns","server":"10.82.0.53","server_port":5353,"detour":"proxy"]],"final":"home-dns"]
   final.profiles["shadowsocks"]!["sing-box.json"]=try JSONSerialization.data(withJSONObject:graph,options:[.sortedKeys]).base64EncodedString();final=try JSONDecoder().decode(ClientBundle.self,from:Data(LibboxTestCONNECTService(String(decoding:encoded(final),as:UTF8.self)).utf8));try store.save(final);model.bundle=try stored(ids.last!)
   let beforeSource=try profileSource(try model.iosNodeChainBundles(for:model.bundle!).map{try encoded($0)},requested);defer{try? beforeSource.close()}
   let actions=TypedProfileActions(model);actions.name="Typed CONNECT original route";actions.add()
   guard let saved=IOSConnectionProfileStore.all().first(where:{$0.id==actions.selectedID}) else{throw failure("actual typed Add callback did not persist")}
   try check("actual Add callback selects saved profile",actions.status.hasPrefix("Added "))
   try check("typed profile retains original execution choice",saved.preferences?.multihopExecution==requested)
   try check("typed profile stores every original position",saved.preferences?.multihopNodes?.map(\.mode)==Array(repeating:mode,count:count-2)+[kind,"shadowsocks"] && saved.chainPolicies?.map(\.nodeID)==ids)
   try check("typed profile retains external authority",saved.chainPolicies?[middlePosition].nodeKind=="external" && saved.chainPolicies?[middlePosition].externalProtocol==kind && saved.chainPolicies?[middlePosition].nodeProofID==nil && saved.chainPolicies?[middlePosition].externalPublicIP=="203.0.113.76")
   let visible=String(decoding:IOSPrivateJSONStore.bytes!,as:UTF8.self)
   try check("typed profile omits username",!visible.contains("PRIVATE-CONNECT-USER"))
   try check("typed profile omits password",!visible.contains("PRIVATE-CONNECT-PASSWORD"))
   let originalBytes=try encoded(middle.routerProfiles[0].external!),originalAssets=final.profiles
   model.bundle=nil
   actions.load()
   try check("actual Load callback keeps Connect separate",actions.status.hasPrefix("Loaded ") && actions.status.contains("Connect separately") && !actions.status.contains("Older profile"))
   let captured=try model.iosNodeChainBundles(for:model.bundle!)
   try check("typed profile loads all original independent records",captured.count==count && captured[middlePosition].selectedRouterID==ids[middlePosition] && captured[finalPosition].selectedRouterID==ids[finalPosition])
   try check("typed profile Load keeps literal and private credentials",try encoded(captured[middlePosition].routerProfiles[0].external!)==originalBytes && captured[middlePosition].routerProfiles[0].endpoint==host)
   try check("typed profile Load keeps paired final assets",model.bundle!.profiles==originalAssets)
   try check("typed profile Load keeps middle protection and selected TCP resolver",captured[middlePosition].routerProfiles[0].homeLANAccess==false && captured[middlePosition].routerProfiles[0].killSwitchPolicy=="always" && captured[middlePosition].routerProfiles[0].dnsProtocol=="tcp" && captured[middlePosition].routerProfiles[0].dnsHost=="10.81.0.53" && captured[middlePosition].routerProfiles[0].dnsPort==5353)
   let afterSource=try profileSource(try captured.map{try encoded($0)},requested);defer{try? afterSource.close()}
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
    try! replaceRaw(ids[middlePosition]){source in
     if kind=="https-connect" {source.routerProfiles[0].external?.httpsConnect?.username="relinked-user";source.routerProfiles[0].external?.httpsConnect?.password="relinked-valid-password"}
     else {source.routerProfiles[0].external?.httpConnect?.username="relinked-user";source.routerProfiles[0].external?.httpConnect?.password="relinked-valid-password"}
    }
   }
   actions.load()
   try check("typed Load rejects private source changed during atomic preparation",!actions.status.hasPrefix("Loaded ") && store.writes==beforeRaceWrites && model.imports==beforeRaceImports)
   try check("typed Load refusal retains newer private credential source",try (kind=="https-connect" ? stored(ids[middlePosition]).routerProfiles[0].external?.httpsConnect?.password : stored(ids[middlePosition]).routerProfiles[0].external?.httpConnect?.password)=="relinked-valid-password")
   try replaceRaw(ids[middlePosition]){$0.routerProfiles[0].external?.expectedPublicIP="203.0.113.77"}
   let records=store.records,writes=store.writes,imports=model.imports
   try reject("typed profile replaced middle public identity"){_ = try IOSConnectionProfileStore.load(model:model,id:saved.id)}
   try check("typed failed Load preserves all private records",store.records==records && store.writes==writes)
   try check("typed failed Load never changes active selection",model.imports==imports)
   actions.load()
   try check("actual failed Load callback reports refusal",!actions.status.hasPrefix("Loaded ") && model.imports==imports)
   actions.delete()
   try check("actual Delete callback clears only saved selection",actions.selectedID==nil && actions.status=="Deleted saved connection profile.")
   try check("typed Delete removes only saved preference record",!IOSConnectionProfileStore.all().contains(where:{$0.id==saved.id}) && store.records==records && model.imports==imports)
  }}}}}}
 }
'''

def main(label="typed CONNECT", roundtrip="connectRoundtrip"):
    anchor=' static func main(){do{'
    assert P.BOUNDARIES.count(anchor)==1
    P.BOUNDARIES=P.BOUNDARIES.replace(anchor,TYPED+'\n'+anchor,1)
    anchor='try hysteriaRoundtrip();print('
    assert P.BOUNDARIES.count(anchor)==1
    P.BOUNDARIES=P.BOUNDARIES.replace(anchor,'try hysteriaRoundtrip();try '+roundtrip+'();print(',1)
    P.BOUNDARIES='import Libbox\n'+P.BOUNDARIES
    P.BOUNDARIES += '\nextension IOSConnectionProfileStore { static func fixtureCanonicalProfile(_ value:RouterProfile)throws->RouterProfile { applying(try validatePreferences(capturePreferences(value)),to:value) } }\n'
    P.BOUNDARIES=P.BOUNDARIES.replace('static func main(){do{','static func main(){defer{LibboxTestClose()};do{',1)
    view=(P.APP/'IOSConnectionProfilesView.swift').read_text()
    callbacks=[]
    for operation in ('add','update','load','delete'):
        callback=L.S.member(view,'    private func '+operation+'()')
        assert 'IOSConnectionProfileStore.'+operation+'(model: model' in callback
        callbacks.append(callback.replace('private func','func',1))
    actions='@MainActor final class TypedProfileActions { let model:RouterVPNModel; var name="",status=""; var selectedID:String?; init(_ model:RouterVPNModel){self.model=model}; func refresh(){}\n'+'\n'.join(callbacks)+'\n}\n'
    P.BOUNDARIES += actions
    with tempfile.TemporaryDirectory(prefix='.ios-connect-profile-compiler-',dir=P.ROOT) as go_dir,tempfile.TemporaryDirectory(prefix='ios-connect-profile-libbox-') as folder:
        go_dir,work=Path(go_dir),Path(folder)
        (go_dir/'main.go').write_text(E.GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(go_dir/'main.go')],cwd=P.ROOT,check=True,timeout=180)
        lib=work/'Libbox.swift';lib.write_text(E.LIBBOX)
        library=work/('libLibbox.dylib' if platform.system()=='Darwin' else 'libLibbox.so')
        subprocess.run(['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules'),'-emit-module','-emit-library','-module-name','Libbox',str(lib),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(library)],check=True,timeout=90)
        crypto=work/'CryptoKit.swift';crypto.write_text(E.CRYPTO)
        subprocess.run(['swiftc','-j','1','-swift-version','6','-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work),'-emit-module','-emit-library','-module-name','CryptoKit',str(crypto),'-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/('libCryptoKit.dylib' if platform.system()=='Darwin' else 'libCryptoKit.so'))],check=True,timeout=90)
        P.main(extra_sources=[P.APP/name for name in ('IOSMultihopStartLayer.swift','IOSNodeChainCapture.swift','IOSImportedOpenVPNSource.swift','IOSNodeChainProviderCapture.swift','IOSNodeChainSOCKSCapture.swift','IOSNodeChainCONNECTCapture.swift','IOSNodeChainExecutionCapture.swift')],extra_flags=['-I',str(work),'-L',str(work),'-lLibbox','-lCryptoKit','-Xlinker','-rpath','-Xlinker',str(work)],binary_args=[compiler])
    print('Apple '+label+' profile composition: original persistence and controls completed')
if __name__=='__main__':main()
