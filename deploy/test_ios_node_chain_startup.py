#!/usr/bin/env python3
"""Execute ordered cold-start capture and dispatch with the actual Go compiler.

The shipping intent and selected-source checks execute unchanged. Native VPN
launch is an explicit boundary here; app launch, provider proof and encrypted
transport have their own independent gates.
"""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
spec = importlib.util.spec_from_file_location('chain_startup_launch', ROOT / 'deploy/test_ios_node_chain_launch.py')
L = importlib.util.module_from_spec(spec); spec.loader.exec_module(L)
C, S = L.C, L.S

MODEL = r'''
@MainActor final class RouterVPNModel {
 var bundle:ClientBundle?
 var iosConnectGeneration=UUID(),iosUserDisconnectInProgress=false,profileMutationBlocked=false
 var auto=false,message="",events:[String]=[]
 let iosSpeedLabOwnership=IOSSpeedLabOwnership()
 var iosStrategyProfile:RouterProfile? {bundle.flatMap{IOSDNSRuntimePolicy.selectedProfile(in:$0)}}
 var connected=false
 func iosMultihopEntryBundle(for bundle:ClientBundle)throws->ClientBundle{throw CancellationError()}
 func externalTorEntryData(source:ClientBundle)throws->Data?{throw CancellationError()}
 func connect()async {guard await iosSpeedLabOwnership.admitConnection()else{return};events.append("ordered")}
 func runIOSSmartAuto()async{events.append("raw-smart")}
 func connectIOSRawCandidate(_ raw:String)async->Bool{events.append("raw-last");return false}
 func recordIOSLastRuntime(){events.append("raw-history")}
 func capture()throws->IOSStartupCapture{try iosStartupCapture()}
 func matches(_ intent:IOSStartupIntent)->Bool{iosStartupMatches(intent)}
 func start(_ mode:String,intent:IOSStartupIntent)async {
  guard let profile=iosStrategyProfile else{return}
  await IOSSpeedLabContext.$startupAdmission.withValue({self.iosStartupMatches(intent)}) {
   await runIOSRouterStartup(mode:mode,profile:profile,intent:intent)
  }
 }
 // SHIPPING_CHAIN_BUNDLES
 // SHIPPING_STARTUP
}
private struct IOSLastRuntime:Codable {let routerID:String,rawProfileID:String,logicalModeID:String}
'''

TESTS = r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ ok:@autoclosure ()throws->Bool)throws {
  guard try ok()else{throw NSError(domain:"ChainStartupCheck",code:1,userInfo:[NSLocalizedDescriptionKey:name])};checks+=1
 }
 static func reject(_ name:String,_ action:()throws->Void)throws {
  do{try action()}catch{checks+=1;return};throw NSError(domain:"ChainStartupReject",code:1,userInfo:[NSLocalizedDescriptionKey:"ACCEPTED "+name])
 }
 // ORIGINAL_COMPILER_SOURCES
 static func setup(_ count:Int=3)throws->RouterVPNModel {
  IOSNodeBundleStore.shared.records=[:]
  let sources=try sources(count),model=RouterVPNModel();model.bundle=sources.last!
  for node in sources{IOSNodeBundleStore.shared.records[node.selectedRouterID]=try JSONEncoder().encode(node)}
  return model
 }
 static func editMiddle(_ edit:(inout ClientBundle)->Void)throws {
  var value=try JSONDecoder().decode(ClientBundle.self,from:IOSNodeBundleStore.shared.records["chain-node-1"]!)
  edit(&value);IOSNodeBundleStore.shared.records["chain-node-1"]=try JSONEncoder().encode(value)
 }
 static func main()async {
  defer{LibboxTestClose()}
  do{try await run();print("Apple ordered startup: PASS (\(checks) shipping Swift/shared Go checks; native launch boundary)")}
  catch{FileHandle.standardError.write(Data(("FAIL after \(checks): \(error.localizedDescription)\n").utf8));exit(1)}
 }
 static func run()async throws {
  for count in [3,4,8] {for mode in ["auto","smart-auto","last"] {
   let model=try setup(count),captured=try model.capture(),intent=IOSStartupIntent(captured)
   let plan=try model.captureIOSNodeChain(model.bundle!);defer{try? plan.plan.close()}
   try check("cold startup owns exact complete native source",captured.nodeChainSource==Data(plan.launchInput.utf8) && captured.entry==nil)
   try check("unchanged ordered intent matches",model.matches(intent))
   await model.start(mode,intent:intent)
   try check("ordered startup never selects a raw member",model.events==["ordered"] && !model.auto)
  }}
  for fault in ["middle-token","middle-asset","missing-middle","final-token","final-order","generation","disconnect","busy","speed-lab"] {
   let model=try setup(),intent=try IOSStartupIntent(model.capture())
   switch fault {
   case "middle-token":try editMiddle{$0.routerProfiles[0].apiToken="changed-middle-token"}
   case "middle-asset":try editMiddle{let raw=String(decoding:Data(base64Encoded:$0.profiles["wg"]!["wg.conf"]!)!,as:UTF8.self);$0.profiles["wg"]!["wg.conf"]=Data(raw.replacingOccurrences(of:"51820",with:"51821").utf8).base64EncodedString()}
   case "missing-middle":IOSNodeBundleStore.shared.records.removeValue(forKey:"chain-node-1")
   case "final-token":model.bundle?.routerProfiles[0].apiToken="changed-final-token"
   case "final-order":model.bundle?.routerProfiles[0].multihopNodes?.swapAt(0,1)
   case "generation":model.iosConnectGeneration=UUID()
   case "disconnect":model.iosUserDisconnectInProgress=true
   case "busy":model.profileMutationBlocked=true
   case "speed-lab":_ = try model.iosSpeedLabOwnership.begin{}
   default:fatalError()
   }
   try check("changed ordered startup refuses "+fault,!model.matches(intent))
   await model.start("smart-auto",intent:intent)
   try check("stale ordered intent makes no connection dispatch",model.events.isEmpty)
  }
  do {
   let model=try setup(),captured=try model.capture(),intent=IOSStartupIntent(captured)
   model.iosConnectGeneration=UUID();intent.generation=model.iosConnectGeneration
   try check("only original startup claim can advance its generation",model.matches(intent))
   try editMiddle{$0.routerProfiles[0].apiToken="later-replacement"}
   try check("advanced startup generation still binds original middle",!model.matches(intent))
  }

  for mode in ["auto","smart-auto","last"] {
   IOSNodeBundleStore.shared.records=[:]
   let nodes=try sources(3,false,"",true),model=RouterVPNModel();model.bundle=nodes.last!
   for node in nodes{IOSNodeBundleStore.shared.records[node.selectedRouterID]=try JSONEncoder().encode(node)}
   let captured=try model.capture(),intent=IOSStartupIntent(captured),owner=try model.captureIOSOrderedRoute(model.bundle!)
   defer{try? owner.close()}
   try check("typed cold startup keeps exact source",captured.nodeChainSource==Data(owner.launchInput.utf8) && owner.providerKey==IOSNodeChainSOCKSCapture.providerKey)
   await model.start(mode,intent:intent)
   try check("typed cold startup dispatches only complete ordered source",model.events==["ordered"])
   try editMiddle{$0.routerProfiles[0].external?.socks5?.password="replacement-private-password"}
   try check("changed typed startup refuses credential",!model.matches(intent))
   model.events=[];await model.start(mode,intent:intent)
   try check("changed typed startup makes no raw or ordered dispatch",model.events.isEmpty)
  }
  do {
   let model=try setup(),source=try model.capture(),bundle=model.bundle!
   try reject("ordered source omitted"){_ = try IOSStartupCapture(bundle:bundle,entry:nil,generation:model.iosConnectGeneration)}
   try reject("ordered source empty"){_ = try IOSStartupCapture(bundle:bundle,entry:nil,generation:model.iosConnectGeneration,nodeChainSource:Data())}
   try reject("ordered source oversized"){_ = try IOSStartupCapture(bundle:bundle,entry:nil,generation:model.iosConnectGeneration,nodeChainSource:Data(repeating:0,count:40*1024*1024+1))}
   try reject("ordered source with legacy entry"){_ = try IOSStartupCapture(bundle:bundle,entry:Data("other-entry".utf8),generation:model.iosConnectGeneration,nodeChainSource:source.nodeChainSource)}
   var ordinary=bundle;ordinary.routerProfiles[0].multihopNodes=nil
   try reject("ordered source with ordinary selection"){_ = try IOSStartupCapture(bundle:ordinary,entry:nil,generation:model.iosConnectGeneration,nodeChainSource:source.nodeChainSource)}
  }
 }
}
'''


def main():
    before = L.BOUNDARIES[:L.BOUNDARIES.index('@MainActor final class RouterVPNModel')]
    before = before.replace('enum IOSStartupPolicy {static func mode(_ value:String?)throws->String{value ?? "last"}}', '')
    boundary = S.BOUNDARIES[S.BOUNDARIES.index('enum NEVPNStatus'):S.BOUNDARIES.index('enum IOSRuntimeSelectionError')]
    runtime = (APP / 'IOSRuntimeSelection.swift').read_text()
    dns = (APP / 'IOSDNSRuntimePolicy.swift').read_text()
    before = before.replace('// SHIPPING_NETWORK_EXTENSION_BOUNDARY', boundary)
    before = before.replace('// SHIPPING_SELECTION_TYPES', runtime[runtime.index('enum IOSRuntimeEngine'):runtime.index('enum IOSRuntimeSelectionError')])
    before = before.replace('// SHIPPING_SELECTED_PROFILE', S.member(dns, '    static func selectedProfile('))
    view = (APP / 'IOSMultihopView.swift').read_text()
    strategy = (APP / 'IOSStrategySupport.swift').read_text()
    body = MODEL.replace('// SHIPPING_CHAIN_BUNDLES', S.member(view, '    func iosNodeChainBundles('))
    body = body.replace('// SHIPPING_STARTUP', '\n'.join(S.member(strategy, signature) for signature in (
        '    private func runIOSRouterStartup(', '    private func iosStartupCapture()',
        '    private func iosStartupMatches(_ captured:', '    private func iosStartupMatches(_ intent:')))
    tests = TESTS.replace('// ORIGINAL_COMPILER_SOURCES', S.member(L.TESTS, ' static func sources('))
    policy = (APP / 'IOSStartupPolicy.swift').read_text()
    with tempfile.TemporaryDirectory(prefix='.ios-chain-startup-', dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix='ios-chain-startup-') as directory:
        go_dir, work = Path(go_dir), Path(directory)
        (go_dir / 'main.go').write_text(C.GO); compiler = work / 'compiler'
        subprocess.run(['go', 'build', '-p', '1', '-o', str(compiler), str(go_dir / 'main.go')], cwd=ROOT, check=True, timeout=180)
        stub = work / 'Libbox.swift'; stub.write_text(C.LIBBOX)
        options = ['swiftc', '-j', '1', '-swift-version', '6', '-module-cache-path', str(work / 'modules')]
        library = work / ('libLibbox.dylib' if platform.system() == 'Darwin' else 'libLibbox.so')
        subprocess.run(options + ['-emit-module', '-emit-library', '-module-name', 'Libbox', str(stub), '-emit-module-path', str(work / 'Libbox.swiftmodule'), '-o', str(library)], check=True, timeout=90)
        command = options + ['-I', str(work), '-L', str(work), '-lLibbox', '-Xlinker', '-rpath', '-Xlinker', str(work)]
        command += [str(APP / name) for name in ('Models.swift', 'IOSSpeedLabOwnership.swift', 'IOSMultihopStartLayer.swift', 'IOSNodeChainCapture.swift', 'IOSNodeChainProviderCapture.swift', 'IOSNodeChainSOCKSCapture.swift', 'IOSNodeChainLaunch.swift')]
        code = work / 'Tests.swift'; binary = work / 'tests'

        def run(current_body, current_policy, expected=None):
            code.write_text(before + current_body + current_policy + tests)
            subprocess.run(command + [str(code), '-o', str(binary)], check=True, timeout=120)
            result = subprocess.run([str(binary), str(compiler)], capture_output=expected is not None, text=True, timeout=180)
            if expected is None:
                result.check_returncode()
            else:
                assert result.returncode != 0 and expected in result.stdout + result.stderr, 'Missing causal startup refusal: ' + expected
                print('Rejected ordered startup defect mutation: ' + expected)

        run(body, policy)
        anchor = 'current.nodeChainSource == captured.nodeChainSource && '
        assert policy.count(anchor) == 1
        run(body, policy.replace(anchor, '', 1), 'changed ordered startup refuses middle-token')
        branch = S.member(strategy, '        if profile.multihopNodes != nil {')
        assert body.count(branch) == 1
        run(body.replace(branch, '', 1), policy, 'ordered startup never selects a raw member')
        typed_tests=tests.replace('  for count in [3,4,8] {for mode in ["auto","smart-auto","last"] {','  for count in [Int]() {for mode in ["auto","smart-auto","last"] {',1)
        start=typed_tests.index('  for fault in ["middle-token"')
        end=typed_tests.index('  for mode in ["auto","smart-auto","last"] {',start)
        typed_tests=typed_tests[:start]+typed_tests[end:]
        original_tests=tests
        tests=typed_tests
        try:
            run(body,policy.replace(anchor,'',1),'changed typed startup refuses credential')
        finally:
            tests=original_tests



if __name__ == '__main__':
    main()
