#!/usr/bin/env python3
"""Shipping Apple Local schema-six consumers with the actual shared compiler.

No sockets, native tunnel, selected execution or device acceptance is claimed.
Every count3..8 and six independently compiled omission controls are required.
"""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile
import re
import test_ios_node_chain_imported_capture as I
from ios_node_chain_independent_fixture import INDEPENDENT_BUNDLES
C=I.C
ROOT=I.ROOT
APP=I.APP

CASES=r'''
 static func independentSources(_ count:Int,_ positions:Set<Int>,_ mode:String="wg",_ layer:String="off",_ ceiling:Int=4096)throws->[Data]{
  var bundles=try sources(count,layer,true)
'''+INDEPENDENT_BUNDLES+r'''
 static func independentImports(_ count:Int)throws {
  let arrangements:[Set<Int>] = count==3 ? [[1],[0,1]] : [[1],Set(1..<count-1),[1,count-2]]
  for positions in arrangements {for mode in ["wg","awg2-fast","awg2-strong"] {
   let finalLayer=positions.contains(0) ? (mode=="wg" ? "off":mode=="awg2-fast" ? "aes-256-gcm":"aes-256-gcm+xor-whitening"):"off"
   let bundles=try independentSources(count,positions,mode,finalLayer),value=try IOSNodeChainCapture.compile(bundles:bundles);defer{try? value.plan.close()}
   let launch=try object(Data(value.launchInput.utf8)),inputs=launch["nodes"] as! [String],identities=launch["identity_sources"] as! [String]
   let expectedSchema=positions.contains(0) ? 7 : positions.count==1 && positions.contains(count-2) ? 2:6
   try check("independent original source family",launch["schema"] as? Int==expectedSchema && inputs.count==count && identities.count==count)
   try check("independent original Local policy",value.selectionExecution=="local" && value.strict && !value.homeLANAccess)
   let decoded=try bundles.map { try JSONDecoder().decode(ClientBundle.self,from:$0) }
   let nodes=value.members.map{IOSMultihopNodeSelection(id:$0.id,mode:$0.mode)}
   try check("independent original editor order",IOSNodeChainDraft(saved:nodes,finalID:nodes.last!.id).canSave)
   for position in 0..<count {
    let member=try object(Data(inputs[position].utf8))
    try check("independent identity position \(position)",positions.contains(position) ? identities[position].isEmpty : !identities[position].isEmpty)
    try check("independent complete member position \(position)",value.members[position].id==nodes[position].id && value.members[position].profile["effective_mtu"] as? Int==9000)
    if positions.contains(position) {
     let capture=try object(Data((member["capture"] as! String).utf8)),original=try profile(bundles[position])
     try check("independent complete external credential \(position)",try data(capture["profile"]!)==data(original))
     let config=try object(Data((member["config"] as! String).utf8))
     try check("independent imported TUN unchanged",(config["inbounds"] as! [[String:Any]])[0]["mtu"] as? Int==1280)
    }
   }
   if expectedSchema==7 {
    try check("paired final retains independent Start Layer",(value.finalProfile["start_layer"] as? String ?? "off")==finalLayer)
    try check("custom entry never acquires Server or Compare",!IOSMultihopNodeSelection.supportsServerExecution(nodes))
    var malformed=launch;malformed["identity_sources"]=[identities[2],"",identities[2]]
    try check("custom entry cannot borrow paired identity",try IOSNodeChainPresentation.captured(source:data(malformed),bundleData:bundles[2])==nil)
    var wrong=nodes;wrong[1].mode="wg"
    try check("custom entry cannot precede paired middle",!IOSNodeChainDraft(saved:wrong,finalID:nodes[2].id).canSave)
    let draft=IOSNodeChainDraft(saved:nodes,finalID:nodes[2].id)
    try reject("public entry cannot open private packet candidate measurement"){_ = try draft.measurementPath(through:0)}
    let options=IOSNodeChainEditorVisible.candidates(decoded.flatMap(\.routerProfiles),nodes:nodes,position:0)
    try check("editor can select original literal public entry",options.contains(where:{$0.id==nodes[0].id}))
   }
   let graph=try object(Data(value.config.utf8)),dns=graph["dns"] as! [String:Any],servers=dns["servers"] as! [[String:Any]],selected=servers.first{$0["tag"] as? String==dns["final"] as? String}!
   try check("independent final selected DNS",selected["server"] as? String=="10.\(80+count-1).0.53")
   let finalInput=try object(Data(inputs[count-1].utf8)),finalSHA=finalInput["source_sha256"] as! String
   try check("independent final DNS captured owner",(selected["detour"] as? String)?.hasPrefix("routervpn-chain-\(count-1)-\(finalSHA.prefix(12))-node-")==true)
   let reopened=try IOSNodeChainCapture.reopen(value.launchInput,selectedProfile:profile(bundles[count-1]));try check("independent sealed replay",reopened.launchInput==value.launchInput && reopened.config==value.config);try reopened.plan.close()
   let chosen=try IOSRuntimeSelector.selectNodeChain(value);try check("independent ordinary native selection",chosen.nodeChainInput==value.launchInput)
   let path=IOSNodeChainPresentation.captured(source:Data(value.launchInput.utf8),bundleData:bundles[count-1])
   try check("independent complete captured presentation",path?.map(\.id)==nodes.map(\.id) && path?.enumerated().allSatisfy{positions.contains($0.offset) ? $0.element.kind=="external":$0.element.kind=="router-vpn"}==true)
   var rows:[[String:Any]]=[];for position in 0..<count {rows.append(["position":position,"profile_id":nodes[position].id,"proven":true,"response_ms":1,"kind":positions.contains(position) ? "public-path":"private-node"])}
   let progress:[String:Any]=["execution":"local","stage":"selected","prefixes":rows,"dns_proven":true,"public_proven":true,"ready":true,"complete":true]
   try check("independent captured public progress",IOSNodeChainPresentation.progress(progress,expected:nodes.map(\.id),expectedPublicPositions:positions)?.contains("Every captured node")==true)
   try check("independent unowned public progress refused",IOSNodeChainPresentation.progress(progress,expected:nodes.map(\.id),expectedPublicPositions:[])==nil)
   if positions.contains(1) && count>3 {try check("legacy progress keeps penultimate boundary",IOSNodeChainPresentation.progress(progress,expected:nodes.map(\.id))==nil)}
   var changed=try profile(bundles[count-1]);changed["api_token"]="replacement"
   try reject("independent final substitution"){_ = try IOSNodeChainCapture.reopen(value.launchInput,selectedProfile:changed)}
   if expectedSchema>=6 {for purpose in ["server","auto"] {var changed=bundles;changed[count-1]=try editProfile(changed[count-1]){$0["multihop_execution"]=purpose};try reject("independent Local-only execution"){_ = try IOSNodeChainCapture.compileOriginalForExecution(bundles:changed,requested:purpose)}}}
   var host=decoded[1].routerProfiles[0];host.endpoint="middle.example.test";host.external?.shadowsocks?.server=host.endpoint
   try check("independent literal eligibility",!IOSImportedShadowsocksSource.eligibleLiteral(host))
   if expectedSchema>=6 {
    var changed=bundles;changed[1]=try editProfile(changed[1]){p in var ext=p["external"] as! [String:Any],ss=ext["shadowsocks"] as! [String:Any];ss["server"]="middle.example.test";ext["shadowsocks"]=ss;p["external"]=ext;p["endpoint"]="middle.example.test"}
    try reject("independent hostname boundary"){_ = try IOSNodeChainCapture.compile(bundles:changed)}
   }
  }}
  if count==8 {for layer in ["aes-256-gcm","aes-256-gcm+xor-whitening"] {
   let importSets:[Set<Int>]=[[1],[1,3]]
   for imports in importSets {
    let original=try independentSources(count,imports,"mixed",layer),value=try IOSNodeChainCapture.compile(bundles:original)
    try check("independent same-node layers",value.members[0].profile["start_layer"] as? String==layer && value.members[7].profile["start_layer"] as? String==layer);try value.plan.close()
   }
   // The actual IPv4 AES envelope is 60 WG / 92 AWG bytes, plus58 for
   // each captured SS wrapper. Capacity rounds each predecessor cap down16.
   // With imports1,3 the successive packet caps are2000,1824,1616,1488,1328:
   // this is a valid Auto graph and must not be mislabeled undersized.
   let fitting=try independentSources(count,[1,3],"mixed",layer,2000),fit=try IOSNodeChainCapture.compile(bundles:fitting)
   let graph=try object(Data(fit.config.utf8)),packets=((graph["endpoints"] as! [[String:Any]])+(graph["outbounds"] as! [[String:Any]])).filter{["wireguard","routervpn-amneziawg"].contains($0["type"] as? String ?? "")}
   for (position,expected) in [(0,2000),(2,1824),(4,1616),(5,1488),(6,1328)] {
    let matching=packets.filter{($0["tag"] as? String)?.hasPrefix("routervpn-chain-\(position)-")==true}
    try check("independent exact Auto packet cap \(position)",matching.count==1 && matching[0]["mtu"] as? Int==expected)
   }
   try fit.plan.close()
   // Restoring packet3 gives six packet nodes:2000,1824,1664,1504,1376,
   // then1216 at packet6, below the unchanged1280 minimum. The ordinary
   // adjacent-packet projection refuses here before the imported-carrier helper.
   let tooSmall=try independentSources(count,[1],"mixed",layer,2000)
   do{let invalid=try IOSNodeChainCapture.compile(bundles:tooSmall);try invalid.plan.close();throw NSError(domain:"accepted-small-packet",code:1)}catch{try check("independent undersized original packet refusal: "+error.localizedDescription,error.localizedDescription == "entry MTU cannot carry the dual-stack nested WireGuard packet")}
   var fixed=fitting;fixed[2]=try editProfile(fixed[2]){$0["mtu_policy"]="fixed";$0["manual_mtu"]=2000}
   do{let invalid=try IOSNodeChainCapture.compile(bundles:fixed);try invalid.plan.close();throw NSError(domain:"accepted-fixed-overflow",code:1)}catch{try check("independent Fixed request remains unchanged: "+error.localizedDescription,error.localizedDescription.contains("captured nested packet MTU does not fit its entry"))}
  }}
 }
'''

def strict_failure(result,witness):
    output=result.stdout+result.stderr
    assert result.returncode==1 and witness in output and not re.search(r'(?i)fatal error|signal [0-9]|segmentation|stack dump|panic:',output),output

def main():
    tests=C.SWIFT.replace(' static func run()throws {',CASES+'\n static func run()throws {',1)
    old='try run();print("Apple ordered native capture: PASS (\\(checks) shipping Swift / shared Go checks; no native connection)")'
    new='let count=Int(CommandLine.arguments.last!)!;try independentImports(count);print("Apple independent Local imports: PASS \\(count) nodes / \\(checks) checks")'
    assert tests.count(old)==1;tests=tests.replace(old,new,1)
    with tempfile.TemporaryDirectory(prefix='.ios-independent-compiler-',dir=ROOT) as gd,tempfile.TemporaryDirectory(prefix='ios-independent-local-') as wd:
        go_dir,work=Path(gd),Path(wd);(go_dir/'main.go').write_text(C.GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(go_dir/'main.go')],cwd=ROOT,check=True,timeout=180)
        launch=(APP/'IOSNodeChainLaunch.swift').read_text();enum=launch.split('@MainActor\nextension RouterVPNModel')[0]
        selector=launch[launch.index('    static func selectNodeChain(_ capture: IOSNodeChainCapture)'):]
        (work/'Selector.swift').write_text('import Foundation\nstruct IOSRuntimeSelection {enum Engine {case multihop};let engine:Engine;let logicalModeID:String;let rawProfileID:String;let files:[String:String];let nodeChainInput:String}\nenum IOSRuntimeSelector {\n'+selector)
        model=I.MODEL.replace('// ORIGINAL_CAPTURE',I.member(launch,'    func captureIOSOrderedRoute('))
        editor=(APP/'IOSNodeChainEditor.swift').read_text()
        draft=I.member(editor,'struct IOSNodeChainDraft')+'\n'+I.member(editor,'enum IOSNodeChainEditorVisible')
        (work/'Ownership.swift').write_text(enum+model+draft+'\n'+C.EXECUTION_REFUSAL)
        (work/'Libbox.swift').write_text(C.LIBBOX);(work/'Tests.swift').write_text(tests)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        lib=work/('libLibbox.dylib' if platform.system()=='Darwin' else 'libLibbox.so')
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(work/'Libbox.swift'),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(lib)],check=True,timeout=90)
        originals={name:(APP/name).read_text() for name in ['Models.swift','IOSNodeChainCapture.swift','IOSNodeChainPresentation.swift']}
        for name,value in originals.items():(work/name).write_text(value)
        command=options+['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]+[str(APP/name) for name in ['IOSImportedOpenVPNSource.swift','IOSMultihopStartLayer.swift','IOSNodeChainProviderCapture.swift','IOSNodeChainSOCKSCapture.swift','IOSNodeChainCONNECTCapture.swift','IOSSessionIdentity.swift']]+[str(work/name) for name in originals]+[str(work/name) for name in ['Selector.swift','Ownership.swift','Tests.swift']]+['-o',str(work/'tests')]
        subprocess.run(command,check=True,timeout=90)
        for count in range(3,9):subprocess.run([str(work/'tests'),str(compiler),str(count)],check=True,timeout=180)
        controls=[
          ('old-source-family','IOSNodeChainCapture.swift','importedNodes ? 6 : importedOpenVPN ? 5 : imported ? 2 : 1','importedNodes ? 2 : importedOpenVPN ? 5 : imported ? 2 : 1','ordered node chain requires its complete bounded original Local capture'),
          ('old-readback-family','IOSNodeChainCapture.swift','schema == 6 && (selectionExecution == "local" || multipleExecution)','schema == 6 && false','another source or platform owner'),
          ('literal-source','Models.swift','eligible(profile) && profile.external?.shadowsocks.map { literal($0.server) } == true','eligible(profile)','independent literal eligibility'),
          ('final-owner','IOSNodeChainCapture.swift','try json(selectedProfile, maximum: 256 * 1024) == json(capture.finalProfile, maximum: 256 * 1024)','true','ACCEPTED independent final substitution'),
          ('public-inventory','IOSNodeChainPresentation.swift','publicPath == expectedPublicPositions.contains(position)','true','independent unowned public progress refused'),
          ('old-presentation-family','IOSNodeChainPresentation.swift','launch.schema == 2 || launch.schema == 5 || launch.schema == 6','launch.schema == 2 || launch.schema == 5','independent complete captured presentation'),
        ]
        assert len(controls)==6
        for label,name,before,after,witness in controls:
            assert originals[name].count(before)==1,label
            (work/name).write_text(originals[name].replace(before,after,1));subprocess.run(command,check=True,timeout=90)
            failed=subprocess.run([str(work/'tests'),str(compiler),'4'],capture_output=True,text=True,timeout=180)
            strict_failure(failed,witness);print('Rejected independent Local source control: '+label,flush=True)
            (work/name).write_text(originals[name])
if __name__=='__main__':main()
