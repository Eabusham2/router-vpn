#!/usr/bin/env python3
"""Run shipping Swift Imported SS middle capture/provider against the real Go compiler.

The bridge is socket-free. These checks do not certify an Apple native image,
VPN device, connected native proof, or encrypted traffic.
"""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
spec=importlib.util.spec_from_file_location('ordered_capture',ROOT/'deploy/test_ios_node_chain_capture.py')
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
MODEL=r'''
@MainActor final class RouterVPNModel {
 var iosCandidateTesting=false
 var allNodeProfiles:[RouterProfile]{nodes.flatMap{$0.routerProfiles}}
 var selectedNodeProfile:RouterProfile?{guard let bundle else{return nil};return bundle.routerProfiles.first{$0.id==bundle.selectedRouterID}}
 var nodes:[ClientBundle],bundle:ClientBundle?
 var connected=true,activeSessionIdentity:IOSSessionIdentity?,iosConnectGeneration=UUID(),selectedMode="multihop",selectedLogicalMode="multihop",auto=false
 init(_ nodes:[ClientBundle],identity:IOSSessionIdentity){self.nodes=nodes;bundle=nodes.last!;activeSessionIdentity=identity}
 func iosNodeChainBundles(for bundle:ClientBundle)throws->[ClientBundle]{nodes}
 nonisolated static func iosStrategyDigest(_ data:Data)->String{let h=data.reduce(UInt64(14695981039346656037)){($0 ^ UInt64($1)) &* 1099511628211};return String(repeating:String(format:"%016llx",h),count:4)}
 // ORIGINAL_CAPTURE
}
'''
def member(text,anchor):
    start=text.index(anchor);brace=text.index('{',start);depth=1;end=brace+1
    while depth:
        if text[end]=='{':depth+=1
        elif text[end]=='}':depth-=1
        end+=1
    return text[start:end]

CASES=r'''
 static func importedSSMiddle()throws {
  for count in [3,4,8] {for mode in ["wg","awg2-fast","awg2-strong"] {for hostname in [false,true] {
   let middlePosition=count-2, finalPosition=count-1
   var bundles=try sources(count,"off",true)
   for position in bundles.indices {bundles[position]=try editProfile(bundles[position]){p in
    p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""
   }}
   let id="saved-ss-middle",host=hostname ? "Middle.Example.Test":"203.0.113.20",secret=Data(repeating:79,count:32).base64EncodedString()
   var middle=try profile(bundles[middlePosition]);middle["id"]=id;middle["node_kind"]="external";middle.removeValue(forKey:"node_proof_id")
   middle["router_api"]="";middle["api_token"]="";middle["endpoint"]=host;middle["start_layer"]="off"
   middle["home_lan_access"]=false;middle["kill_switch_policy"]="always"
   middle["dns_mode"]="custom";middle["dns_protocol"]="tcp";middle["dns_host"]="10.81.0.53";middle["dns_port"]=5353
   middle["external"]=["protocol":"shadowsocks","expected_public_ip":"203.0.113.88","shadowsocks":["server":host,"port":8388,"method":"2022-blake3-aes-256-gcm","password":secret]]
   bundles[middlePosition]=try data(["selectedRouterID":id,"routerProfiles":[middle],"profiles":[String:[String:String]]()])
   bundles[finalPosition]=try editProfile(bundles[finalPosition]){p in var nodes=p["multihop_nodes"] as! [[String:Any]];for i in 0..<middlePosition { nodes[i]["mode"]=mode };nodes[middlePosition]=["id":id,"mode":"shadowsocks"];p["multihop_nodes"]=nodes}
   let capture=try IOSNodeChainCapture.compile(bundles:bundles);defer{try? capture.plan.close()}
   var draft=IOSNodeChainDraft(saved:capture.members.map{.init(id:$0.id,mode:$0.mode)},finalID:capture.members.last!.id)
   try check("Imported SS editor original bounded capture",draft.canSave)
   let originalSelection=draft.nodes
   if count<8 {try draft.append();try check("Imported SS editor preserves penultimate original import",draft.nodes[draft.nodes.count-2]==originalSelection[middlePosition] && draft.nodes.last==originalSelection.last)}
   else {
    try reject("Imported SS Server still rejects a ninth mixed member"){try draft.append(execution:"server")}
    try reject("Imported SS Compare still rejects a ninth mixed member"){try draft.append(execution:"auto")}
    try draft.append()
    try check("Imported SS Local extension retains every original in order",draft.nodes.count==9 && Array(draft.nodes.dropLast(2))==Array(originalSelection.dropLast()) && draft.nodes.last==originalSelection.last && draft.nodes[7].id.isEmpty && draft.nodes[7].mode=="shadowsocks" && !draft.canSave)
    let extra="another-ss-import"
    try draft.choose(extra,at:7)
    var added=middle
    added["id"]=extra;added["endpoint"]="203.0.113.21"
    added["external"]=["protocol":"shadowsocks","expected_public_ip":"203.0.113.89","shadowsocks":["server":"203.0.113.21","port":8389,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:83,count:32).base64EncodedString()]]
    let addedData=try data(["selectedRouterID":extra,"routerProfiles":[added],"profiles":[String:[String:String]]()])
    let final=try editProfile(bundles[finalPosition]){$0["multihop_nodes"]=draft.nodes.map{["id":$0.id,"mode":$0.mode]}}
    let proposed=Array(bundles.dropLast())+[addedData,final]
    if hostname {
     try reject("long Local route cannot borrow short hostname authority"){let plan=try IOSNodeChainCapture.compile(bundles:proposed);try plan.plan.close()}
    } else {
     let longer=try IOSNodeChainCapture.compile(bundles:proposed);defer{try? longer.plan.close()}
     try check("ninth literal Local member uses the original mixed source",longer.sourceSchema==6 && longer.members.map(\.id)==draft.nodes.map(\.id) && longer.members.map(\.mode)==draft.nodes.map(\.mode))
    }
   }
   let realNodes=try bundles.map{try JSONDecoder().decode(ClientBundle.self,from:$0)}
   let identity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:bundles[finalPosition],configuration:["nodeChainSource":capture.launchInput])
   let model=RouterVPNModel(realNodes,identity:identity),latency=try IOSOrderedLatencyCapture(model)
   try check("Imported SS latency exact original source",latency.source==capture.sourceSHA256 && latency.config==capture.configSHA256 && latency.ids==capture.members.map(\.id) && latency.kinds==Array(repeating:"private-node",count:middlePosition)+["public-path","private-node"])
   try latency.require(model)
   for changedPosition in realNodes.indices {
    model.nodes=realNodes;model.nodes[changedPosition].routerProfiles[0].name="replaced saved member"
    try reject("Imported SS latency complete original sources"){try latency.require(model)}
   }
   try reject("Imported SS latency initial current source"){_ = try IOSOrderedLatencyCapture(model)}
   model.nodes=realNodes;model.iosConnectGeneration=UUID()
   try reject("Imported SS latency original generation"){try latency.require(model)}
   model.iosConnectGeneration=latency.selection;model.bundle=nil
   try reject("Imported SS latency removed selected bundle"){try latency.require(model)}
   let launch=try object(Data(capture.launchInput.utf8)),graph=try object(Data(capture.config.utf8))
   try check("Imported SS exact source schema",launch["schema"] as? Int==2 && (launch["identity_sources"] as? [String])?[middlePosition]=="")
   try check("Imported SS original order and policy",capture.strict && !capture.homeLANAccess && capture.members.map(\.mode)==Array(repeating:mode,count:middlePosition)+["shadowsocks","shadowsocks"])
   let endpoint=(graph["outbounds"] as! [[String:Any]]).first{$0["type"] as? String=="shadowsocks" && $0["server"] as? String==host}!
   try check("Imported SS original credentials",endpoint["method"] as? String=="2022-blake3-aes-256-gcm" && endpoint["password"] as? String==secret)
   let proofs=capture.members
   let identities=launch["identity_sources"] as! [String]
   try check("Imported SS complete original identities",identities.count==count && identities.enumerated().allSatisfy { $0.offset==middlePosition ? $0.element.isEmpty : !$0.element.isEmpty })
   let beforeMiddle=((graph["endpoints"] as! [[String:Any]])+(graph["outbounds"] as! [[String:Any]])).filter { ["wireguard","routervpn-amneziawg"].contains($0["type"] as? String ?? "") }
   try check("Imported SS original last-prefix detour",beforeMiddle.count==middlePosition && endpoint["detour"] as? String==beforeMiddle.last?["tag"] as? String)
   try check("Imported SS every original captured member",proofs.count==count && Set(proofs.map(\.id)).count==count)
   let selected=try IOSRuntimeSelector.selectNodeChain(capture)
   try check("Imported SS actual app native selection",selected.nodeChainInput==capture.launchInput && selected.rawProfileID=="shadowsocks" && selected.files.isEmpty)
   let dns=graph["dns"] as! [String:Any],resolvers=dns["servers"] as! [[String:Any]]
   let resolver=resolvers.first{$0["tag"] as? String==dns["final"] as? String}!
   try check("Imported SS keeps final selected DNS",resolver["server"] as? String=="10.\(80+finalPosition).0.53" && resolver["detour"] is String && resolver["detour"] as? String != endpoint["tag"] as? String)
   let member=try object(Data((launch["nodes"] as! [String])[middlePosition].utf8)),saved=try object(Data((member["capture"] as! String).utf8))
   let ext=(saved["profile"] as! [String:Any])["external"] as! [String:Any]
   try check("Imported SS raw source retained",(ext["shadowsocks"] as! [String:Any])["server"] as? String==host && (ext["shadowsocks"] as! [String:Any])["password"] as? String==secret)
   let replay=try IOSNodeChainCapture.reopen(capture.launchInput,selectedProfile:profile(bundles[finalPosition]));defer{try? replay.plan.close()}
   try check("Imported SS exact replay",replay.launchInput==capture.launchInput && replay.config==capture.config)
   var provider:[String:Any]=["engine":"multihop-libbox","mode":"shadowsocks","rawProfileID":"shadowsocks","modeCandidates":["shadowsocks"],"bundle":bundles[finalPosition],IOSNodeChainProviderCapture.key:capture.launchInput]
   let reopened=try IOSNodeChainProviderCapture.reopen(provider);try reopened.plan.close()
   provider["external_entry_mode"]="openvpn"
   try reject("Imported SS mixed provider owner"){_ = try IOSNodeChainProviderCapture.reopen(provider)}
   var replaced=try profile(bundles[finalPosition]);replaced["api_token"]="replaced-final"
   try reject("Imported SS final identity substitution"){_ = try IOSNodeChainCapture.reopen(capture.launchInput,selectedProfile:replaced)}
   if hostname {
    let query=endpoint["domain_resolver"] as! [String:Any],transport=resolvers.first{$0["tag"] as? String==query["server"] as? String}!
    try check("Imported SS exact last-prefix hostname resolver",transport["type"] as? String=="tcp" && transport["server"] as? String=="10.81.0.53" && transport["server_port"] as? Int==5353 && transport["detour"] as? String==beforeMiddle.last?["tag"] as? String && transport["tag"] as? String != resolver["tag"] as? String)
   }
   for fault in ["token","layer","order","key","method"] {
    var changed=bundles
    if fault=="order" { changed.swapAt(0,middlePosition) }
    else {changed[middlePosition]=try editProfile(changed[middlePosition]){p in
     if fault=="token" {p["api_token"]="borrowed-paired-secret"}
     if fault=="layer" {p["start_layer"]="aes-256-gcm"}
     if fault=="key" || fault=="method" {var e=p["external"] as! [String:Any],ss=e["shadowsocks"] as! [String:Any];ss[fault=="key" ? "password":"method"]=fault=="key" ? "invalid!":"aes-256-gcm";e["shadowsocks"]=ss;p["external"]=e}
    }}
    try reject("Imported SS source refusal "+fault){_ = try IOSNodeChainCapture.compile(bundles:changed)}
   }
   for purpose in ["server","auto"] {
    var changed=bundles;changed[finalPosition]=try editProfile(changed[finalPosition]){$0["multihop_execution"]=purpose}
    try reject("Imported SS ordinary Local compiler keeps execution boundary "+purpose){_ = try IOSNodeChainCapture.compile(bundles:changed)}
    let prepared=try IOSNodeChainCapture.compileOriginalForExecution(bundles:changed,requested:purpose);defer{try? prepared.plan.close()}
    let preparedLaunch=try object(Data(prepared.launchInput.utf8))
    try check("Imported SS complete original execution source "+purpose,preparedLaunch["schema"] as? Int==2 && prepared.selectionExecution==purpose && prepared.members.map(\.id)==capture.members.map(\.id) && prepared.members.map(\.mode)==capture.members.map(\.mode) && preparedLaunch["identity_sources"] as? [String]==identities)
    let originalInputs=launch["nodes"] as! [String],preparedInputs=preparedLaunch["nodes"] as! [String]
    let originalFinal=try object(Data(originalInputs[finalPosition].utf8)),preparedFinal=try object(Data(preparedInputs[finalPosition].utf8))
    let originalFinalSHA=originalFinal["source_sha256"] as! String,preparedFinalSHA=preparedFinal["source_sha256"] as! String
    try check("Imported SS source preparation changes only final source ownership "+purpose,Array(originalInputs[..<finalPosition])==Array(preparedInputs[..<finalPosition]) && originalFinalSHA.count==64 && preparedFinalSHA.count==64 && originalFinalSHA != preparedFinalSHA && originalFinal["config_sha256"] as? String==preparedFinal["config_sha256"] as? String)
    // The full captured final profile includes the requested execution. Its
    // source digest therefore changes the compiler-generated DNS namespace,
    // while all resolver policy and preceding member bytes stay original.
    let originalNamespace="routervpn-chain-\(finalPosition)-\(originalFinalSHA.prefix(12))-",preparedNamespace="routervpn-chain-\(finalPosition)-\(preparedFinalSHA.prefix(12))-"
    func finalReference(_ value:Any?) -> Any? {
     guard let tag=value as? String,tag.hasPrefix(originalNamespace) else{return value}
     return preparedNamespace+String(tag.dropFirst(originalNamespace.count))
    }
    var expectedDNS=dns
    expectedDNS["final"]=finalReference(dns["final"])
    expectedDNS["servers"]=resolvers.map { original -> [String:Any] in
     var row=original;row["tag"]=finalReference(original["tag"]);row["detour"]=finalReference(original["detour"]);return row
    }
    let preparedGraph=try object(Data(prepared.config.utf8)),preparedDNS=preparedGraph["dns"] as! [String:Any],preparedResolvers=preparedDNS["servers"] as! [[String:Any]]
    try check("Imported SS source preparation retains exact selected and hostname DNS "+purpose,try data(preparedDNS)==data(expectedDNS))
    let preparedSelected=preparedResolvers.first{$0["tag"] as? String==preparedDNS["final"] as? String}!
    let preparedSelector=(preparedGraph["outbounds"] as! [[String:Any]]).first{$0["type"] as? String=="selector"}!,preparedFinalTags=preparedSelector["outbounds"] as! [String]
    try check("Imported SS source preparation binds DNS to its own final outbound "+purpose,(resolver["tag"] as! String).hasPrefix(originalNamespace+"dns-") && preparedFinalTags.count==1 && preparedSelector["default"] as? String==preparedFinalTags[0] && preparedFinalTags[0].hasPrefix(preparedNamespace+"node-") && preparedSelected["tag"] as? String==preparedNamespace+String((resolver["tag"] as! String).dropFirst(originalNamespace.count)) && preparedSelected["detour"] as? String==preparedFinalTags[0] && preparedSelected["type"] as? String==resolver["type"] as? String && preparedSelected["server"] as? String==resolver["server"] as? String && preparedSelected["server_port"] as? Int==resolver["server_port"] as? Int)
    if hostname {
     let preparedEndpoint=(preparedGraph["outbounds"] as! [[String:Any]]).first{$0["type"] as? String=="shadowsocks" && $0["server"] as? String==host}!,preparedQuery=preparedEndpoint["domain_resolver"] as! [String:Any]
     let originalQuery=endpoint["domain_resolver"] as! [String:Any],originalBootstrap=resolvers.first{$0["tag"] as? String==originalQuery["server"] as? String}!,preparedBootstrap=preparedResolvers.first{$0["tag"] as? String==preparedQuery["server"] as? String}!
     try check("Imported SS source preparation preserves original hostname bootstrap "+purpose,try data(preparedQuery)==data(originalQuery) && data(preparedBootstrap)==data(originalBootstrap) && preparedBootstrap["detour"] as? String==beforeMiddle.last?["tag"] as? String)
    }
    try reject("Imported SS missing execution source "+purpose){_ = try IOSNodeChainCapture.compileOriginalForExecution(bundles:Array(changed.dropLast()),requested:purpose)}
    var relinked=changed;relinked[middlePosition]=try editProfile(relinked[middlePosition]){$0["id"]="relinked-import"}
    try reject("Imported SS relinked execution source "+purpose){_ = try IOSNodeChainCapture.compileOriginalForExecution(bundles:relinked,requested:purpose)}
   }
  }}}
 }
'''

def main():
    tests=C.SWIFT.replace(' static func hostnameMiddle()',CASES+' static func hostnameMiddle()',1)
    tests=tests.replace('try run();print("Apple ordered native capture: PASS (\\(checks) shipping Swift / shared Go checks; no native connection)")','try importedSSMiddle();print("iOS Imported SS middle capture: PASS \\(checks) actual Swift/shared-Go checks; native/device acceptance separate")',1)
    assert tests!=C.SWIFT
    with tempfile.TemporaryDirectory(prefix='.ios-imported-ss-middle-',dir=ROOT) as go_dir,tempfile.TemporaryDirectory(prefix='ios-imported-ss-middle-') as folder:
        go_dir,work=Path(go_dir),Path(folder)
        (go_dir/'main.go').write_text(C.GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(go_dir/'main.go')],cwd=ROOT,check=True,timeout=180)
        launch=(APP/'IOSNodeChainLaunch.swift').read_text()
        enum=launch.split('@MainActor\nextension RouterVPNModel')[0]
        model=MODEL.replace('// ORIGINAL_CAPTURE',member(launch,'    func captureIOSOrderedRoute('))
        latency = C.latency_capture_source()
        selector=launch[launch.index('    static func selectNodeChain(_ capture: IOSNodeChainCapture)'):]
        boundary='import Foundation\nstruct IOSRuntimeSelection {enum Engine {case multihop};let engine:Engine;let logicalModeID:String;let rawProfileID:String;let files:[String:String];let nodeChainInput:String}\nenum IOSRuntimeSelector {\n'+selector
        (work/'Selector.swift').write_text(boundary)
        draft=member((APP/'IOSNodeChainEditor.swift').read_text(),'struct IOSNodeChainDraft')
        ownership=work/'Ownership.swift';ownership.write_text(enum+model+draft+"\n"+C.EXECUTION_REFUSAL+latency)
        (work/'Libbox.swift').write_text(C.LIBBOX);(work/'Tests.swift').write_text(tests)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        library=work/('libLibbox.dylib' if platform.system()=='Darwin' else 'libLibbox.so')
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(work/'Libbox.swift'),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(library)],check=True,timeout=90)
        command=options+['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        command += [str(APP/name) for name in ('Models.swift','IOSImportedOpenVPNSource.swift','IOSMultihopStartLayer.swift','IOSNodeChainProviderCapture.swift','IOSNodeChainSOCKSCapture.swift','IOSNodeChainCONNECTCapture.swift','IOSSessionIdentity.swift','IOSNodeChainPresentation.swift')]
        original=(APP/'IOSNodeChainCapture.swift').read_text();source=work/'Capture.swift';binary=work/'tests'
        def run(value):
            source.write_text(value)
            subprocess.run(command+[str(source),str(work/'Selector.swift'),str(ownership),str(work/'Tests.swift'),'-o',str(binary)],check=True,timeout=90)
            return subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
        result=run(original);assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip())
        before='try json(selectedProfile, maximum: 256 * 1024) == json(capture.finalProfile, maximum: 256 * 1024)'
        assert original.count(before)==1
        failed=run(original.replace(before,'true',1))
        assert failed.returncode!=0 and 'ACCEPTED Imported SS final identity substitution' in failed.stdout+failed.stderr,failed.stdout+failed.stderr
        print('Rejected Imported SS final-control substitution mutation',flush=True)
        for name,before,after,witness in [
            ('latency-source','Data(original.launchInput.utf8) == active','true','ACCEPTED Imported SS latency initial current source'),
            ('latency-members','try Self.bytes(model) == snapshot','!snapshot.isEmpty','ACCEPTED Imported SS latency complete original sources'),
            ('latency-generation','model.iosConnectGeneration == selection','true','ACCEPTED Imported SS latency original generation'),
        ]:
            assert latency.count(before)==1,name
            ownership.write_text(enum+model+draft+"\n"+C.EXECUTION_REFUSAL+latency.replace(before,after,1))
            failed=run(original)
            assert failed.returncode!=0 and witness in failed.stdout+failed.stderr,(name,failed.stdout+failed.stderr)
            print('Rejected Imported SS original-capture control: '+name,flush=True)
        ownership.write_text(enum+model+draft+"\n"+C.EXECUTION_REFUSAL+latency)
if __name__=='__main__':main()
