#!/usr/bin/env python3
"""Execute shipping app preference/launch capture against the real chain compiler.

Models, ordered record selection, source compilation, final launch method and
source revalidation are production Swift. The private record store and
NetworkExtension preferences/connection are explicit boundary doubles. This
does not certify a device tunnel or native traffic; provider/engine/peer gates
separately own those obligations.
"""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


C = module('chain_launch_compiler', 'test_ios_node_chain_capture.py')
S = module('chain_launch_startup', 'test_ios_startup_policy.py')

L=module("original_launch", "test_ios_node_chain_launch.py")
E=module("typed_control", "test_ios_connect_execution_control.py")
BOUNDARIES=L.BOUNDARIES
TESTS=E.SWIFT[:E.SWIFT.index('@MainActor final class Provider')]+r'''
@MainActor @main struct Tests {
 static func check(_ good:Bool,_ name:String){if !good{print("FAIL "+name);exit(1)}}
 static func reject(_ name:String,_ action:()async throws->Void)async{do{try await action();print("FAIL ACCEPTED "+name);exit(1)}catch{}}
 static func main()async throws {
  defer{LibboxTestClose()}
  for kind in ["http-connect","https-connect"]{for requested in ["server","auto"]{
   for fault in ["none","cold-last","middle-password","final-token","cancel"]{
    NETunnelProviderManager.reset();IOSNodeBundleStore.shared.records=[:]
    let bytes=try connectFixture(kind,"wg",requested),nodes=try bytes.map{try JSONDecoder().decode(ClientBundle.self,from:$0)}
    let model=RouterVPNModel(),manager=NETunnelProviderManager(),selected=nodes[2]
    model.bundle=selected
    for node in nodes{IOSNodeBundleStore.shared.records[node.selectedRouterID]=try JSONEncoder().encode(node)}
    let capture=try model.captureIOSOrderedRoute(selected);defer{try? capture.close()}
    let selection=try IOSRuntimeSelector.selectNodeChain(capture)
    check(selection.nodeChainExecution==requested && capture.providerKey==IOSNodeChainProviderCapture.executionKey,"typed route precedes Local capture")
    NETunnelProviderManager.hook={phase in
     guard phase=="save" else{return}
     if fault=="middle-password"{let key=nodes[1].selectedRouterID;var raw=try object(IOSNodeBundleStore.shared.records[key]!);var profiles=raw["routerProfiles"] as! [[String:Any]],ext=profiles[0]["external"] as! [String:Any],cfg=ext[kind.replacingOccurrences(of:"-",with:"_")] as! [String:Any];cfg["password"]="changed";ext[kind.replacingOccurrences(of:"-",with:"_")]=cfg;profiles[0]["external"]=ext;raw["routerProfiles"]=profiles;IOSNodeBundleStore.shared.records[key]=try data(raw)}
     if fault=="final-token"{model.bundle?.routerProfiles[0].apiToken="foreign"}
     if fault=="cancel"{model.iosConnectGeneration=UUID()}
    }
    if fault=="none" || fault=="cold-last"{
     if fault=="cold-last" {
      let source=try IOSNodeChainExecutionSession.Source.compile(bytes,requested:requested),id=String(repeating:"c",count:32)
      let record=try LibboxTestSavedLast(source.input,"server")
      let reply:[String:Any]=["schema":1,"kind":"routervpn-ordered-execution-last","request_id":id,"session_id":UUID().uuidString,"source_sha256":source.sourceSHA256,"preparation_config_sha256":source.configSHA256,"last":record]
      try IOSNodeChainExecutionLastStore.record(IOSNodeChainExecutionSession.Last.decode(data(reply),source:source,request:id))
      var lastSelected=selected;lastSelected.routerProfiles[0].startupMode="last";model.bundle=lastSelected
      _ = try await IOSSpeedLabContext.$startupAdmission.withValue({true}) {try await model.launch(manager,lastSelected,selection)}
      check(manager.connection.options?[IOSNodeChainExecutionSession.lastKey] as? String==record,"cold Last carries original record without Compare rerank")
     } else {_ = try await model.launch(manager,selected,selection)}
     let config=(manager.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
     check(NETunnelProviderManager.starts==1 && config[IOSNodeChainProviderCapture.executionKey] as? String==capture.launchInput && config[IOSNodeChainCONNECTCapture.providerKey]==nil,"exact execution source handed to original manager")
     let replay=try IOSNodeChainExecutionCapture.reopen(config[IOSNodeChainProviderCapture.executionKey] as! String,selectedProfile:profile(bytes[2]));try replay.close()
     check(!model.connected,"host preference save is not native proof")
    }else{
     await reject("stale launch "+fault){_ = try await model.launch(manager,selected,selection)}
     check(NETunnelProviderManager.starts==0,"stale source never starts native")
    }
   }
  }}
  try genericEditor()
  try await genericLaunch()
  print("PASS Apple ordered public launch: CONNECT and generic source, execution precedence, private edits and cancellation")
 }
 static func genericEditor()throws {
  for requested in ["server","auto"] {for (count,imported) in [(2,false),(8,false),(3,true),(4,true),(8,true)] {
   for fault in ["none","old-member","during-DNS","write"] {
    IOSNodeBundleStore.shared.records=[:];IOSDNSRuntimePolicy.beforePatch=nil
    let raw=try imported ? importedFixture(requested,"awg2-strong","2022-blake3-aes-256-gcm",count) : fixture(count,"off",requested,true)
    var nodes=try appFixture(raw).map{try JSONDecoder().decode(ClientBundle.self,from:$0)}
    nodes[count-1].routerProfiles[0].multihopExecution="local"
    let model=RouterVPNModel();model.bundle=nodes.last!
    for node in nodes{IOSNodeBundleStore.shared.records[node.selectedRouterID]=try JSONEncoder().encode(node)}
    let owner=try model.captureIOSNodeChainEditorOwner(),selection=model.selectedNodeProfile!.multihopNodes!
    let change={@MainActor in let key=nodes[0].selectedRouterID;IOSNodeBundleStore.shared.records[key]=try editProfile(IOSNodeBundleStore.shared.records[key]!){$0["api_token"]="replacement-original-member"}}
    if fault=="old-member"{try change()}
    if fault=="during-DNS"{IOSDNSRuntimePolicy.beforePatch=change}
    model.failLinkedWrite=fault=="write"
    if fault=="none" {
     try model.saveIOSNodeChain(selection,owner:owner,execution:requested)
     check(model.linkedWrites==1 && model.selectedNodeProfile?.multihopExecution==requested,"editor persists original generic execution choice once")
     let capture=try model.captureIOSOrderedRoute(model.bundle!);defer{try? capture.close()}
     check(capture.providerKey==IOSNodeChainProviderCapture.executionKey && capture.members.map(\.id)==selection.map(\.id),"editor compiles exact original generic sources before save")
    } else {
     do {try model.saveIOSNodeChain(selection,owner:owner,execution:requested);check(false,"ACCEPTED generic editor "+fault)}catch{}
     check(model.linkedWrites==0 && model.selectedNodeProfile?.multihopExecution=="local","failed generic save preserves original selection and storage")
    }
   }
  }}
 }
 static func genericLaunch()async throws {
  for requested in ["server","auto"] {for (count,imported,awg) in [(2,false,false),(3,false,true),(8,false,true),(3,true,true),(4,true,true),(8,true,true)] {
   for fault in ["none","cold-last-server","cold-last-local","member-private","member-removed","final-token","cancel"] where fault != "cold-last-local" || requested=="auto" {
    NETunnelProviderManager.reset();IOSNodeBundleStore.shared.records=[:];IOSPrivateJSONStore.bytes=nil
    let raw=try imported ? importedFixture(requested,"awg2-strong","2022-blake3-aes-256-gcm",count) : fixture(count,"off",requested,awg)
    let bytes=try appFixture(raw),nodes=try bytes.map{try JSONDecoder().decode(ClientBundle.self,from:$0)}
    let model=RouterVPNModel(),manager=NETunnelProviderManager(),selected=nodes.last!
    model.bundle=selected
    for node in nodes{IOSNodeBundleStore.shared.records[node.selectedRouterID]=try JSONEncoder().encode(node)}
    let capture=try model.captureIOSOrderedRoute(selected);defer{try? capture.close()}
    let selection=try IOSRuntimeSelector.selectNodeChain(capture)
    check(capture.providerKey==IOSNodeChainProviderCapture.executionKey && selection.nodeChainExecution==requested && capture.members.count==count,"generic public selection retains exact execution family and order")
    NETunnelProviderManager.hook={phase in
     guard phase=="save" else{return}
     let key=nodes[0].selectedRouterID
     if fault=="member-private"{IOSNodeBundleStore.shared.records[key]=try editProfile(IOSNodeBundleStore.shared.records[key]!){$0["api_token"]="relinked-original-member"}}
     if fault=="member-removed"{IOSNodeBundleStore.shared.records.removeValue(forKey:key)}
     if fault=="final-token"{model.bundle?.routerProfiles[0].apiToken="replacement-final"}
     if fault=="cancel"{model.iosConnectGeneration=UUID()}
    }
    if fault=="none" || fault.hasPrefix("cold-last-") {
     if fault.hasPrefix("cold-last-") {
      let source=try IOSNodeChainExecutionSession.Source.compile(bytes,requested:requested),id=String(repeating:"c",count:32)
      let winner=fault=="cold-last-local" ? "local":"server",record=try LibboxTestSavedLast(source.input,winner)
      let reply:[String:Any]=["schema":1,"kind":"routervpn-ordered-execution-last","request_id":id,"session_id":UUID().uuidString,"source_sha256":source.sourceSHA256,"preparation_config_sha256":source.configSHA256,"last":record]
      try IOSNodeChainExecutionLastStore.record(IOSNodeChainExecutionSession.Last.decode(data(reply),source:source,request:id))
      var lastSelected=selected;lastSelected.routerProfiles[0].startupMode="last";model.bundle=lastSelected
      _ = try await IOSSpeedLabContext.$startupAdmission.withValue({true}){try await model.launch(manager,lastSelected,selection)}
      check(manager.connection.options?[IOSNodeChainExecutionSession.lastKey] as? String==record,"generic cold Last retains original concrete winner without reranking")
     } else {_ = try await model.launch(manager,selected,selection)}
     let config=(manager.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
     check(NETunnelProviderManager.starts==1 && config[IOSNodeChainProviderCapture.executionKey] as? String==capture.launchInput && config[IOSNodeChainProviderCapture.key]==nil && config[IOSNodeChainCONNECTCapture.providerKey]==nil,"generic public launch hands exact source to original manager")
     let replay=try IOSNodeChainExecutionCapture.reopen(config[IOSNodeChainProviderCapture.executionKey] as! String,selectedProfile:profile(bytes.last!));try replay.close()
     check(!model.connected,"generic source handoff cannot claim native proof")
    } else {
     await reject("generic stale launch "+fault){_ = try await model.launch(manager,selected,selection)}
     check(NETunnelProviderManager.starts==0,"replaced generic private source cannot start native")
    }
   }
  }}
 }
}
'''
def main():
    model = (APP / 'RouterVPNModel.swift').read_text()
    view = (APP / 'IOSMultihopView.swift').read_text()
    dns = (APP / 'IOSDNSRuntimePolicy.swift').read_text()
    runtime = (APP / 'IOSRuntimeSelection.swift').read_text()
    boundary = S.BOUNDARIES[S.BOUNDARIES.index('enum NEVPNStatus'):S.BOUNDARIES.index('enum IOSRuntimeSelectionError')]
    body = BOUNDARIES.replace('// SHIPPING_NETWORK_EXTENSION_BOUNDARY', boundary)
    body = body.replace('// SHIPPING_SELECTION_TYPES', runtime[runtime.index('enum IOSRuntimeEngine'):runtime.index('enum IOSRuntimeSelectionError')])
    body = body.replace('// SHIPPING_SELECTED_PROFILE', S.member(dns, '    static func selectedProfile('))
    body = body.replace('// SHIPPING_CHAIN_BUNDLES', S.member(view, '    func iosNodeChainBundles('))
    body = body.replace('// SHIPPING_CANDIDATE_CONNECT', S.member(model, '    func connectCandidatePreparation('))
    body = body.replace('// SHIPPING_CONNECT', S.member(model, '    func connect(rawProfileID:'))
    body = body.replace('// SHIPPING_START', S.member(model, '    private func start(manager:'))
    # Actual editor methods share the real compiler and original source capture.
    # Durable writes and DNS preparation remain explicit host boundaries.
    body = body.replace(' var bundle:ClientBundle?\n', ''' var bundle:ClientBundle?
 var profileMutationBlocked=false,linkedWrites=0,failLinkedWrite=false
 var selectedNodeProfile:RouterProfile?{selectedRouterProfile}
 var allNodeProfiles:[RouterProfile]{IOSNodeBundleStore.shared.records.values.flatMap{(try? JSONDecoder().decode(ClientBundle.self,from:$0).routerProfiles) ?? []}}
 func linkNodeBundle(_ data:Data)throws{
  guard !failLinkedWrite else{throw CancellationError()}
  let value=try JSONDecoder().decode(ClientBundle.self,from:data)
  IOSNodeBundleStore.shared.records[value.selectedRouterID]=data;bundle=value;linkedWrites+=1
 }
''', 1)
    body = body.replace('static func patch(_ bundle:ClientBundle)throws->ClientBundle {throw CancellationError()}', '''@MainActor static var beforePatch:(@MainActor ()throws->Void)?
 @MainActor static func patch(_ bundle:ClientBundle)throws->ClientBundle {let change=beforePatch;beforePatch=nil;try change?();return bundle}''', 1)
    body = body.replace('nonisolated static func iosStrategyDigest(_ data:Data)->String{"boundary"}', 'nonisolated static func iosStrategyDigest(_ data:Data)->String{try! LibboxTestDigest(data).map{String(format:"%02x",$0)}.joined()}', 1)
    assert 'IOSMultihopNodeSelection.supportsServerExecution(draft.nodes)' in (APP/'IOSNodeChainEditorView.swift').read_text()
    with tempfile.TemporaryDirectory(prefix='.ios-chain-launch-', dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix='ios-chain-launch-') as directory:
        go_dir, work = Path(go_dir), Path(directory)
        (go_dir / 'main.go').write_text(E.SAVED.GO)
        compiler = work / 'compiler'
        subprocess.run(['go', 'build', '-p', '1', '-o', str(compiler), str(go_dir / 'main.go')], cwd=ROOT, check=True, timeout=180)
        stub = work / 'Libbox.swift'; stub.write_text(E.SAVED.LIBBOX)
        code = work / 'Tests.swift'; code.write_text(body + TESTS)
        options = ['swiftc', '-j', '1', '-swift-version', '6', '-module-cache-path', str(work / 'modules')]
        library = work / ('libLibbox.dylib' if platform.system() == 'Darwin' else 'libLibbox.so')
        subprocess.run(options + ['-emit-module', '-emit-library', '-module-name', 'Libbox', str(stub), '-emit-module-path', str(work / 'Libbox.swiftmodule'), '-o', str(library)], check=True, timeout=90)
        command = options + ['-I', str(work), '-L', str(work), '-lLibbox', '-Xlinker', '-rpath', '-Xlinker', str(work)]
        crypto=work/'CryptoKit.swift';crypto.write_text(E.SAVED.SOURCE.CRYPTO)
        subprocess.run(command+['-emit-module','-emit-library','-module-name','CryptoKit',str(crypto),'-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/('libCryptoKit.dylib' if platform.system()=='Darwin' else 'libCryptoKit.so'))],check=True,timeout=90)
        command+=['-lCryptoKit']
        command += [str(APP / name) for name in ('Models.swift', 'IOSSpeedLabOwnership.swift', 'IOSMultihopStartLayer.swift', 'IOSNodeChainCapture.swift','IOSImportedOpenVPNSource.swift', 'IOSNodeChainProviderCapture.swift', 'IOSNodeChainSOCKSCapture.swift', 'IOSNodeChainCONNECTCapture.swift', 'IOSNodeChainLaunch.swift','IOSNodeChainEditor.swift','IOSNodeChainExecutionCapture.swift','IOSNodeChainExecutionSession.swift','IOSNodeChainExecutionControl.swift','IOSSessionIdentity.swift')]
        binary = work / 'tests'
        subprocess.run(command + [str(code), '-o', str(binary)], check=True, timeout=120)
        subprocess.run([str(binary), str(compiler)], check=True, timeout=180)

        for name,before,after,witness in (
         ('original-source','try requireCurrentIOSNodeChain(nodeChainSource, selected: bundle)','_ = nodeChainSource','ACCEPTED stale launch middle-password'),
        ):
         assert body.count(before)==1,name
         code.write_text(body.replace(before,after,1)+TESTS)
         subprocess.run(command+[str(code),'-o',str(binary)],check=True,timeout=120)
         failed=subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
         assert failed.returncode==1 and ('FAIL '+witness+'\n') in failed.stdout+failed.stderr,(name,failed.returncode,(failed.stdout+failed.stderr)[-2000:])
         print('Rejected CONNECT launch omission:',name,flush=True)
if __name__=='__main__':main()
