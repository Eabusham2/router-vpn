#!/usr/bin/env python3
"""Compile shipping Apple execution consumers against the real shared Go parsers.

The Libbox source bridge executes the actual compiler. Native lifecycle calls
remain explicitly rejecting boundaries; this is not an Apple SDK/device gate.
"""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
spec=importlib.util.spec_from_file_location('apple_execution_source',ROOT/'deploy/test_ios_node_chain_execution_capture.py')
E=importlib.util.module_from_spec(spec);spec.loader.exec_module(E)
spec=importlib.util.spec_from_file_location('typed_latency_source',ROOT/'deploy/test_ios_ordered_latency_connect_capture.py')
F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)

LIBBOX=E.LIBBOX+r'''
public func LibboxTestCONNECTExecutionFixture(_ kind:String)throws->String{try bridge(["Op":"chain-connect-fixture","Mode":kind])}
'''
SWIFT=E.SWIFT[:E.SWIFT.index('@main struct Tests')]+r'''
func connectFixture(_ kind:String,_ mode:String,_ requested:String)throws->[Data]{
 let raw=try LibboxTestCONNECTExecutionFixture(kind)
 var bundles=try (JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [Any]).map{try data($0)}
 for position in bundles.indices {bundles[position]=try editProfile(bundles[position]){p in p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="";p["socks_port"]=0;p["socks_username"]="";p["socks_password"]=""}}
 bundles[2]=try editProfile(bundles[2]){p in p["multihop_execution"]=requested;p["startup_mode"]="manual";p["auto_connect"]=true;var nodes=p["multihop_nodes"] as! [[String:Any]];nodes[0]["mode"]=mode;p["multihop_nodes"]=nodes}
 return bundles
}
@main struct Tests{
 @MainActor static var checks=0
 @MainActor static func check(_ good:Bool,_ name:String){guard good else{fatalError(name)};checks+=1}
 @MainActor static func reject(_ name:String,_ run:()throws->Void){do{try run();fatalError("ACCEPTED "+name)}catch{checks+=1}}
 @MainActor static func main()throws{
  defer{LibboxTestClose()}
  try genericConsumers()
  for kind in ["http-connect","https-connect"] {for mode in ["wg","awg2-fast","awg2-strong"] {for requested in ["server","auto"] {
   let bundles=try connectFixture(kind,mode,requested)
   let capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested);defer{try? capture.close()}
   let source=try object(Data(capture.source.utf8)),local=try object(Data((source["local_source"] as! String).utf8)),launch=try object(Data(capture.launchInput.utf8))
   check(capture.isCONNECT && source["schema"] as? Int==4 && source["execution"] as? String==requested,"typed preparation family and choice")
   check(launch["kind"] as? String=="routervpn-node-chain-connect-execution-preparation-input" && launch["schema"] as? Int==1,"typed launch family")
   check(capture.members.map(\.mode)==[mode,kind,"shadowsocks"] && (local["identity_sources"] as! [String])[1].isEmpty,"original member order and sparse identity")
   check(capture.finalProfile["startup_mode"]==nil && capture.finalProfile["auto_connect"]==nil,"only original scheduling projection")
   let realNodes=try bundles.map{try JSONDecoder().decode(ClientBundle.self,from:$0)}
   let identity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:bundles[2],entryBundleData:nil,nodeChainExecutionSource:Data(capture.launchInput.utf8))
   let model=RouterVPNModel(realNodes,identity:identity),fifty=try IOSOrderedLatencyCapture(model)
   check(fifty.source==capture.sourceSHA256 && fifty.config==capture.configSHA256 && fifty.ids==capture.members.map(\.id) && fifty.kinds==["private-node","public-path","private-node"],"original execution latency capture")
   check(IOSNodeChainPresentation.active(identity)?.map(\.id)==capture.members.map(\.id),"active execution presentation original identities")
   for winner in requested=="auto" ? ["local","server"]:["server"] {
    let rows:[[String:Any]]=capture.members.enumerated().map{["position":$0.offset,"profile_id":$0.element.id,"kind":$0.offset==1 ? "public-path":"private-node","proven":true,"response_ms":1.0]}
    let value:[String:Any]=["stage":"selected","execution":winner,"prefixes":rows,"ready":true,"complete":true,"dns_proven":true,"public_proven":true]
    let text=IOSNodeChainPresentation.progress(value,expected:capture.members.map(\.id),requestedExecution:requested)
    check(text?.contains(winner=="server" ? "Ordered route • Server":"Ordered route • Local")==true && text?.contains("Every captured node and final path verified")==true,"typed progress actual selected winner and full proof")
   }
   try fifty.require(model)
   model.iosConnectGeneration=UUID();reject("latency replacement generation"){try fifty.require(model)};model.iosConnectGeneration=fifty.selection
   model.nodes[1].routerProfiles[0].name="changed private record";reject("latency changed original member"){try fifty.require(model)}
   reject("latency initial source change"){_ = try IOSOrderedLatencyCapture(model)}

   let replay=try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(bundles[2]));defer{try? replay.close()}
   check(replay.source==capture.source && replay.config==capture.config,"exact private source replay")
   let member=try object(Data((local["nodes"] as! [String])[1].utf8)),saved=try object(Data((member["capture"] as! String).utf8))["profile"] as! [String:Any]
   check(try data(saved)==data(profile(bundles[1])),"original CONNECT private policy and credentials")
   let originalLocal=try IOSNodeChainCONNECTCapture.compileOriginalForExecution(bundles:bundles,requested:requested);defer{try? originalLocal.plan.close()}
   check(originalLocal.source==source["local_source"] as? String,"original Local typed source retained")
   reject("Local source cannot consume execution selection"){_ = try IOSNodeChainCONNECTCapture.compile(bundles:bundles)}
   var failure:NSError?
   let generic=LibboxNewRouterNodeChainExecutionLaunch(capture.launchInput,&failure)
   check(generic==nil && failure != nil,"generic launch remains closed")
   var changed=try profile(bundles[2]);changed["api_token"]="foreign-final"
   reject("changed final private source"){_ = try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:changed)}
   reject("requested selection mismatch"){_ = try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested=="server" ? "auto":"server")}
   for fault in ["local-node","local-identity","local-schema","config","requested"] {
    LibboxTestExecutionFault(fault)
    reject("typed native readback "+fault){_ = try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested)}
   }
   for fault in ["password","endpoint","service","order"] {
    var invalid=bundles
    if fault=="order"{invalid.swapAt(0,1)}
    else if fault=="service"{invalid[2]=try edit(invalid[2]){v in var files=v["profiles"] as! [String:[String:String]];files["shadowsocks"]!.removeValue(forKey:"routervpn-ss-service.json");v["profiles"]=files}}
    else{invalid[1]=try editProfile(invalid[1]){p in if fault=="endpoint"{p["endpoint"]="203.0.113.99"}else{var ext=p["external"] as! [String:Any],credentials=ext[kind.replacingOccurrences(of:"-",with:"_")] as! [String:Any];credentials["password"]="";ext[kind.replacingOccurrences(of:"-",with:"_")]=credentials;p["external"]=ext}}}
    reject("typed source "+fault){_ = try IOSNodeChainExecutionCapture.compile(bundles:invalid,requested:requested)}
   }
  }}}
  print("PASS Apple CONNECT and generic execution consumers: \(checks) original-source checks")
 }
 @MainActor static func genericConsumers()throws{
  var originals:[[Data]]=[]
  for requested in ["server","auto"] {
   for (count,layer,awg) in [(2,"off",false),(3,"aes-256-gcm",true),(8,"aes-256-gcm+xor-whitening",true)] {
    originals.append(try appFixture(fixture(count,layer,requested,awg)))
   }
   for mode in ["wg","awg2-fast","awg2-strong"] {for method in ["2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305"] {
    originals.append(try appFixture(importedFixture(requested,mode,method)))
   }}
   for count in [4,8] {originals.append(try appFixture(importedFixture(requested,"awg2-strong","2022-blake3-aes-256-gcm",count)))}
  }
  for bundles in originals {
   let selected=try profile(bundles.last!),requested=selected["multihop_execution"] as! String
   let capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested);defer{try? capture.close()}
   let nodes=try bundles.map{try JSONDecoder().decode(ClientBundle.self,from:$0)},control=nodes.last!.routerProfiles[0]
   check(!capture.isCONNECT && IOSMultihopNodeSelection.supportsGenericExecution(control.multihopNodes!),"generic choice retains original family")
   try IOSMultihopNodeSelection.validate(control.multihopNodes!,execution:requested,entryID:nil,entryMode:nil,exitID:nil,exitMode:nil,controlID:control.id)
   let identity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:bundles.last!,entryBundleData:nil,nodeChainExecutionSource:Data(capture.launchInput.utf8))
   let model=RouterVPNModel(nodes,identity:identity),fifty=try IOSOrderedLatencyCapture(model)
   let expected=capture.members.map(\.id),kinds=capture.members.map{$0.profile["node_kind"] as? String=="external" ? "public-path":"private-node"}
   check(fifty.source==capture.sourceSHA256 && fifty.config==capture.configSHA256 && fifty.ids==expected && fifty.kinds==kinds,"generic fifty exact source and measurement kinds")
   check(IOSNodeChainPresentation.planned(selected:control,catalog:nodes.flatMap(\.routerProfiles))?.map(\.id)==expected,"planned generic path retains all original positions")
   check(IOSNodeChainPresentation.active(identity)?.map(\.id)==expected,"active generic path retains all original positions")
   if kinds.contains("public-path") {
    var launch=try object(Data(capture.launchInput.utf8)),preparation=try object(Data(capture.source.utf8)),local=try object(Data((preparation["local_source"] as! String).utf8))
    var inputs=local["nodes"] as! [String],identities=local["identity_sources"] as! [String]
    let position=inputs.count-2
    let external:[String:Any]=["schema":1,"kind":"routervpn-node-launch-input","mode":"shadowsocks","profile_json":String(decoding:try data(profile(bundles[position])),as:UTF8.self)]
    inputs[position]=String(decoding:try data(external),as:UTF8.self);identities[position]=identities[0]
    local["schema"]=1;local["nodes"]=inputs;local["identity_sources"]=identities
    preparation["local_source"]=String(decoding:try data(local),as:UTF8.self);launch["source"]=String(decoding:try data(preparation),as:UTF8.self)
    let forged=try IOSSessionIdentity(connectedAt:identity.connectedAt,engine:identity.engine,rawProfile:identity.rawProfile,bundleData:identity.bundleData,entryBundleData:nil,nodeChainExecutionSource:try data(launch))
    check(IOSNodeChainPresentation.active(forged)==nil,"generic presentation rejects external member claiming paired schema")
   }
   for winner in requested=="auto" ? ["local","server"]:["server"] {
    let rows:[[String:Any]]=capture.members.enumerated().map{["position":$0.offset,"profile_id":$0.element.id,"kind":kinds[$0.offset],"proven":true,"response_ms":1.0]}
    let value:[String:Any]=["stage":"selected","execution":winner,"prefixes":rows,"ready":true,"complete":true,"dns_proven":true,"public_proven":true]
    check(IOSNodeChainPresentation.progress(value,expected:expected,requestedExecution:requested)?.contains("Every captured node and final path verified")==true,"generic progress preserves selected winner and all node proofs")
   }
   let changed=try editProfile(bundles.last!){$0["api_token"]="replacement-final"}
   let stale=try IOSSessionIdentity(connectedAt:identity.connectedAt,engine:identity.engine,rawProfile:identity.rawProfile,bundleData:changed,entryBundleData:nil,nodeChainExecutionSource:identity.nodeChainExecutionSource)
   check(IOSNodeChainPresentation.active(stale)==nil,"generic presentation rejects replaced final private source")
   try fifty.require(model)
   model.iosConnectGeneration=UUID();reject("generic latency replacement generation"){try fifty.require(model)};model.iosConnectGeneration=fifty.selection
   model.nodes[0].routerProfiles[0].name="changed original private member"
   reject("generic latency complete source"){try fifty.require(model)}
   reject("latency initial source change"){_ = try IOSOrderedLatencyCapture(model)}
  }
  let original=try appFixture(fixture(3,"off","server",false)),profile=try JSONDecoder().decode(ClientBundle.self,from:original.last!).routerProfiles[0]
  let valid=profile.multihopNodes!
  for modes in [["wg"],["wg","hysteria2"],["wg","wg","socks5","shadowsocks"],["wg","openvpn","shadowsocks"],["wg","shadowsocks","wg","shadowsocks"],Array(repeating:"wg",count:8)+["shadowsocks"]] {
   let nodes=modes.enumerated().map{IOSMultihopNodeSelection(id:"original-\($0.offset)",mode:$0.element)}
   check(!IOSMultihopNodeSelection.supportsGenericExecution(nodes),"generic selector refuses unsupported graph shape")
   reject("unsupported generic execution choice"){try IOSMultihopNodeSelection.validate(nodes,execution:"server",entryID:nil,entryMode:nil,exitID:nil,exitMode:nil)}
  }
  reject("invalid generic execution name"){try IOSMultihopNodeSelection.validate(valid,execution:"fastest",entryID:nil,entryMode:nil,exitID:nil,exitMode:nil)}
 }
}
'''

def main():
    launch=(APP/'IOSNodeChainLaunch.swift').read_text()
    route=launch.split('@MainActor\nextension RouterVPNModel')[0]
    model=F.BOUNDARY.replace('// ORIGINAL_CAPTURE',F.member(launch,'    func captureIOSOrderedRoute('))
    latency=(APP/'IOSOrderedLatency.swift').read_text().split('private final class IOSOrderedLatencyReply')[0].replace('import Combine\n','').replace('@preconcurrency import NetworkExtension\n','')
    with tempfile.TemporaryDirectory(prefix='.ios-connect-execution-',dir=ROOT) as gd,tempfile.TemporaryDirectory(prefix='ios-connect-execution-') as wd:
        gd,work=Path(gd),Path(wd);(gd/'main.go').write_text(E.GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(gd/'main.go')],cwd=ROOT,check=True,timeout=180)
        (work/'Libbox.swift').write_text(LIBBOX);(work/'CryptoKit.swift').write_text(E.CRYPTO);(work/'Tests.swift').write_text(SWIFT);(work/'Latency.swift').write_text(route+model+latency)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        suffix='.dylib' if platform.system()=='Darwin' else '.so'
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(work/'Libbox.swift'),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(work/('libLibbox'+suffix))],check=True,timeout=90)
        link=['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        subprocess.run(options+link+['-emit-module','-emit-library','-module-name','CryptoKit',str(work/'CryptoKit.swift'),'-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/('libCryptoKit'+suffix))],check=True,timeout=90)
        presentation=APP/'IOSNodeChainPresentation.swift';presented=presentation.read_text();presentationCopy=work/'Presentation.swift';presentationCopy.write_text(presented)
        command=options+link+['-lCryptoKit']+[str(APP/n) for n in ('Models.swift','IOSMultihopStartLayer.swift','IOSNodeChainCapture.swift','IOSImportedOpenVPNSource.swift','IOSNodeChainCONNECTCapture.swift','IOSNodeChainSOCKSCapture.swift','IOSNodeChainProviderCapture.swift','IOSSessionIdentity.swift')]+[str(presentationCopy),str(work/'Latency.swift')]
        source=APP/'IOSNodeChainExecutionCapture.swift';text=source.read_text();tests=work/'Tests.swift'
        def run(value):
            path=work/'Capture.swift';path.write_text(value);binary=work/'tests'
            subprocess.run(command+[str(path),str(tests),'-o',str(binary)],check=True,timeout=90)
            return subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
        result=run(text);assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip())
        for name,before,after,witness in (
          ('typed-members','nodes == original["nodes"] as? [String],','true,','ACCEPTED typed native readback local-node'),
          ('typed-identities','identities == original["identity_sources"] as? [String] else {','!identities.isEmpty else {','ACCEPTED typed native readback local-identity'),
          ('final-private-source','guard try canonical(IOSNodeChainCapture.executionProfile(selectedProfile)) == canonical(local.finalProfile) else {\n                throw','guard true else {\n                throw','ACCEPTED changed final private source'),
        ):
            assert text.count(before)==1,name
            result=run(text.replace(before,after,1))
            assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,result.stdout+result.stderr)
            print('Rejected CONNECT execution source control:',name)
        before='Data(original.ordinaryLaunchInput.utf8) == active'
        assert latency.count(before)==1
        (work/'Latency.swift').write_text(route+model+latency.replace(before,'true',1))
        result=run(text)
        assert result.returncode!=0 and 'ACCEPTED latency initial source change' in result.stdout+result.stderr,result.stdout+result.stderr
        print('Rejected CONNECT execution source control: latency-original-source')
        (work/'Latency.swift').write_text(route+model+latency)
        start=presented.index('    private static func capturedGenericExecution(')
        end=presented.index('    private static func capturedSOCKS(',start)
        section=presented[start:end]
        for name,before,after,witness in (
            ('original-final-presentation','guard last == expected else { return nil }','guard true else { return nil }','generic presentation rejects replaced final private source'),
            ('paired-schema-presentation','value.normalizedNodeKind == "router-vpn", value.external == nil','true','generic presentation rejects external member claiming paired schema'),
        ):
            assert section.count(before)==1
            presentationCopy.write_text(presented[:start]+section.replace(before,after,1)+presented[end:])
            result=run(text)
            assert result.returncode!=0 and witness in result.stdout+result.stderr,result.stdout+result.stderr
            print('Rejected generic execution source control:',name)
if __name__=='__main__':main()
