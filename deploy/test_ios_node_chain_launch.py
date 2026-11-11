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

BOUNDARIES = r'''
import Foundation
import Libbox
// SHIPPING_NETWORK_EXTENSION_BOUNDARY
// SHIPPING_SELECTION_TYPES
enum IOSRuntimeSelectionError:Error {case unsupportedMode(String)}
enum IOSStrategyPlan {enum Kind {case manual,automatic,all,logical}}
enum IOSRuntimeSelector {
 static func selectMultihop(bundle:ClientBundle,rawProfileID:String?)throws->IOSRuntimeSelection{throw CancellationError()}
 static func normalizedStartLayer(in bundle:ClientBundle)throws->String {throw CancellationError()}
}
enum IOSDNSRuntimePolicy {
 // SHIPPING_SELECTED_PROFILE
 static func patch(_ bundle:ClientBundle)throws->ClientBundle {throw CancellationError()}
}
@MainActor enum IOSMAXSourceSelection {
 static var calls=0
 static func sourceHashes(provider:[String:Any],bridge:(String,String,String)throws->String)throws->[String:String]{calls+=1;return [:]}
 static func issue()->NSError{NSError(domain:"UncalledMAXBoundary",code:1)}
}
func LibboxRouterCheckMAXProfile(_ mode:String,_ assets:String,_ metadata:String,_ error:inout NSError?)->String?{nil}
func LibboxRouterResolveXrayProfile(_ mode:String,_ wrapper:String,_ original:String,_ error:inout NSError?)->String?{nil}
func LibboxRouterResolveXrayStartLayerProfile(_ mode:String,_ wrapper:String,_ original:String,_ aes:String,_ policy:String,_ error:inout NSError?)->String?{nil}
@MainActor enum IOSMTUMeasurementGate {static var current=""}
enum IOSStartupPolicy {static func mode(_ value:String?)throws->String{value ?? "last"}}
enum IOSMultihopExecution {
 static let startupLaunchKey="routervpn_multihop_startup"
 static func startupTimeout(execution:String,entryMode:String,exitMode:String)throws->TimeInterval{73}
 static func requiresCapture(configuration:[String:Any])throws->Bool{true}
}
@MainActor struct IOSStartupLastChoice {
 static var restores=0
 static func restored(configuration:[String:Any],digest:(Data)->String)throws->Self{restores+=1;return Self()}
 func encoded()throws->Data{Data("legacy-pair-receipt".utf8)}
}
@MainActor final class IOSNodeBundleStore {
 static let shared=IOSNodeBundleStore()
 var records:[String:Data]=[:]
 func bundleData(containing id:String,current:ClientBundle?)->Data?{records[id]}
}
@MainActor final class RouterVPNModel {
 var bundle:ClientBundle?
 var iosConnectGeneration=UUID(),userDisconnectInProgress=false
 var baseFallback=false,strictKillSwitchEnabled=false,homeLANAccess=true,routerName="Final node"
 var connected=false,activeEngine="",activeRawProfile="",observedTimeout:TimeInterval?
 var tunnelTransitioning=false,auto=false,message="",selectedMode="",selectedLogicalMode="",multihopProgressText=""
 var multihopProgressGeneration=UUID()
 var selectedRouterProfile:RouterProfile?{bundle.flatMap{IOSDNSRuntimePolicy.selectedProfile(in:$0)}}
 func saveRouter()->Bool{bundle != nil}
 func iosStrategySelections(kind:IOSStrategyPlan.Kind,rawProfileID:String?)throws->[IOSRuntimeSelection]{throw CancellationError()}
 func runIOSOwnedStrategy(kind:IOSStrategyPlan.Kind,selections:[IOSRuntimeSelection])async->Bool{false}
 func captureIOSNodeUsageOwner(_ manager:NETunnelProviderManager)->Int?{nil}
 func recordIOSNodeUsage(manager:NETunnelProviderManager,source:ClientBundle,generation:UUID,expected:Int?){}
 func rememberIOSMultihopExecution(manager:NETunnelProviderManager,source:ClientBundle,entry:Data?,generation:UUID)async throws{throw CancellationError()}
 func refreshTunnelStatus()async{connected=false;tunnelTransitioning=false}
 func engineName(_ selection:IOSRuntimeSelection)->String{selection.displayName}
 var activeSessionIdentity:Data?
 let iosSpeedLabOwnership=IOSSpeedLabOwnership()
 static func iosStrategyDigest(_ data:Data)->String{"boundary"}
 func iosMultihopEntryBundle(for bundle:ClientBundle)throws->ClientBundle{throw CancellationError()}
 func launch(_ manager:NETunnelProviderManager,_ selected:ClientBundle,_ selection:IOSRuntimeSelection)async throws->Bool {
  try await start(manager:manager,bundle:selected,selection:selection)
 }
 private func waitForConnection(_ manager:NETunnelProviderManager,timeout:TimeInterval)async->Bool {
  // Observe only the app's budget and handed-off state. No proof is simulated.
  observedTimeout=timeout;return false
 }
 // SHIPPING_CHAIN_BUNDLES
 // SHIPPING_CONNECT
 // SHIPPING_START
}
'''

TESTS = r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ ok:@autoclosure ()throws->Bool)throws {
  guard try ok()else{throw NSError(domain:"ChainAppCheck",code:1,userInfo:[NSLocalizedDescriptionKey:name])};checks+=1
 }
 static func reject(_ name:String,_ action:()async throws->Void)async throws {
  do{try await action()}catch{checks+=1;return};throw NSError(domain:"ChainAppRejected",code:1,userInfo:[NSLocalizedDescriptionKey:"ACCEPTED "+name])
 }
 static func reset(){NETunnelProviderManager.reset();IOSNodeBundleStore.shared.records=[:];IOSMAXSourceSelection.calls=0;IOSStartupLastChoice.restores=0;IOSMTUMeasurementGate.current=""}
 static func sources(_ count:Int)throws->[ClientBundle] {
  let raw=try LibboxTestFixture(count,"off")
  let roots=try JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [[String:Any]]
  return try roots.map{original in
   var root=original,profiles=root["routerProfiles"] as! [[String:Any]],p=profiles[0]
   p["name"]=p["id"];p["adguard_ipv6"]="";p["socks_host"]="10.80.0.1";p["socks_port"]=1080;p["socks_username"]="";p["socks_password"]="";p["startup_mode"]="last"
   profiles[0]=p;root["routerProfiles"]=profiles
   return try JSONDecoder().decode(ClientBundle.self,from:JSONSerialization.data(withJSONObject:root))
  }
 }
 static func setup(_ count:Int=3)throws->(RouterVPNModel,NETunnelProviderManager,ClientBundle,IOSRuntimeSelection) {
  reset();let nodes=try sources(count),final=nodes.last!,model=RouterVPNModel(),manager=NETunnelProviderManager()
  model.bundle=final
  for node in nodes {IOSNodeBundleStore.shared.records[node.selectedRouterID]=try JSONEncoder().encode(node)}
  let capture=try model.captureIOSNodeChain(final);defer{try? capture.plan.close()}
  return (model,manager,final,try IOSRuntimeSelector.selectNodeChain(capture))
 }
 static func editMiddle(_ mutation:(inout ClientBundle)->Void)throws {
  let key="chain-node-1",data=IOSNodeBundleStore.shared.records[key]!
  var node=try JSONDecoder().decode(ClientBundle.self,from:data);mutation(&node)
  IOSNodeBundleStore.shared.records[key]=try JSONEncoder().encode(node)
 }
 static func main()async {
  defer{LibboxTestClose()}
  do{try await run();print("Apple ordered app launch: PASS (\(checks) shipping Swift/shared Go checks; NetworkExtension doubled)")}
  catch{FileHandle.standardError.write(Data(("FAIL after \(checks): \(error.localizedDescription)\n").utf8));exit(1)}
 }
 static func run()async throws {
  for fault in ["none","middle-token","middle-source","final-source","cancel-owner"] {
   let (model,manager,_,_)=try setup()
   let proto=NETunnelProviderProtocol();proto.providerBundleIdentifier="com.eabusham.routervpn.PacketTunnel";manager.protocolConfiguration=proto
   NETunnelProviderManager.hook={phase in
    guard phase=="load-all" else{return}
    switch fault {
    case "middle-token":try editMiddle{$0.routerProfiles[0].apiToken="changed-before-manager-readback"}
    case "middle-source":try editMiddle{let raw=String(decoding:Data(base64Encoded:$0.profiles["wg"]!["wg.conf"]!)!,as:UTF8.self);$0.profiles["wg"]!["wg.conf"]=Data(raw.replacingOccurrences(of:"51820",with:"51821").utf8).base64EncodedString()}
    case "final-source":model.bundle?.routerProfiles[0].apiToken="changed-before-manager-readback"
    case "cancel-owner":model.iosConnectGeneration=UUID()
    default:break
    }
   }
   await model.connect(rawProfileID:nil)
   try check("initial manager await preserves captured ordered source "+fault,NETunnelProviderManager.starts==(fault=="none" ? 1:0))
   try check("Connect handoff has no simulated proof",!model.connected)
  }
  for count in [2,3,4,8] {
   let (model,manager,final,selection)=try setup(count)
   let expected=try model.captureIOSNodeChain(final);defer{try? expected.plan.close()}
   IOSMTUMeasurementGate.current="original-owned-hold"
   let result=try await IOSSpeedLabContext.$startupAdmission.withValue({true}){try await model.launch(manager,final,selection)}
   let proto=manager.protocolConfiguration as! NETunnelProviderProtocol,config=proto.providerConfiguration!
   try check("one original native connection receives captured source",manager.connection.starts==1 && config["nodeChainSource"] as? String==expected.launchInput)
   try check("all selected policies reach original native preferences",proto.includeAllNetworks && proto.enforceRoutes && !proto.excludeLocalNetworks)
   try check("chain cannot borrow pair or MAX capture",config["entryBundle"]==nil && config["max_source_sha256"]==nil && IOSMAXSourceSelection.calls==0)
   try check("chain carries its full startup budget",model.observedTimeout==TimeInterval(25+10*count))
   try check("handoff grants no app proof or ready flag",!result && !model.connected)
   try check("historical pair choice cannot authorize chain",IOSStartupLastChoice.restores==0 && manager.connection.options?[IOSMultihopExecution.startupLaunchKey]==nil)
   try check("captured original MTU hold is forwarded",manager.connection.options?["routervpn_mtu_hold"] as? String=="original-owned-hold")
   let reopened=try IOSNodeChainProviderCapture.reopen(config);defer{try? reopened.plan.close()}
   try check("app to provider source/config is exact",reopened.sourceSHA256==expected.sourceSHA256 && reopened.configSHA256==expected.configSHA256)
  }
  for phase in ["save","load","load-all"] {
   for fault in ["middle-token","middle-source","missing-middle","final-policy","final-selection","epoch","disconnect","saved-source","saved-mode","saved-candidates","saved-bundle","saved-flags","saved-provider","mixed-entry","busy-native"] {
    let (model,manager,final,selection)=try setup()
    NETunnelProviderManager.hook={observed in
     guard observed==phase else{return}
     switch fault {
     case "middle-token":try editMiddle{$0.routerProfiles[0].apiToken="replacement-private-token"}
     case "middle-source":try editMiddle{var raw=String(decoding:Data(base64Encoded:$0.profiles["wg"]!["wg.conf"]!)!,as:UTF8.self);raw=raw.replacingOccurrences(of:"51820",with:"51821");$0.profiles["wg"]!["wg.conf"]=Data(raw.utf8).base64EncodedString()}
     case "missing-middle":IOSNodeBundleStore.shared.records.removeValue(forKey:"chain-node-1")
     case "final-policy":model.bundle?.routerProfiles[0].homeLANAccess=false
     case "final-selection":model.bundle?.selectedRouterID="replacement-final"
     case "epoch":model.iosConnectGeneration=UUID()
     case "disconnect":model.userDisconnectInProgress=true
     case "busy-native":manager.connection.status = .connected
     default:
      let proto=manager.protocolConfiguration as! NETunnelProviderProtocol
      switch fault {
      case "saved-source":proto.providerConfiguration?["nodeChainSource"]="replacement-source"
      case "saved-mode":proto.providerConfiguration?["mode"]="wg"
      case "saved-candidates":proto.providerConfiguration?["modeCandidates"]=["shadowsocks","wg"]
      case "saved-bundle":proto.providerConfiguration?["bundle"]=Data("other-bundle".utf8)
      case "saved-flags":proto.enforceRoutes=false
      case "saved-provider":proto.providerBundleIdentifier="another-extension"
      case "mixed-entry":proto.providerConfiguration?["entryBundle"]=Data("other-entry".utf8)
      default:fatalError()
      }
     }
    }
    try await reject(phase+" "+fault){_ = try await IOSSpeedLabContext.$startupAdmission.withValue({true}){try await model.launch(manager,final,selection)}}
    try check("changed source never invokes native start",manager.connection.starts==0)
   }
  }
  do {
   let (model,manager,final,_)=try setup()
   let wrong=IOSRuntimeSelection(engine:.multihop,logicalModeID:"wg",rawProfileID:"wg",files:[:])
   try await reject("wrong final transport"){_ = try await model.launch(manager,final,wrong)}
   try check("wrong final source cannot save preferences",manager.protocolConfiguration==nil && manager.connection.starts==0)
  }
  for source in [nil,"an-unowned-source"] as [String?] {
   let (model,manager,final,_)=try setup()
   let forged=IOSRuntimeSelection(engine:.multihop,logicalModeID:"multihop",rawProfileID:"shadowsocks",files:[:],nodeChainInput:source)
   try await reject("matching labels without original typed source"){_ = try await model.launch(manager,final,forged)}
   try check("labels cannot authorize native preferences",manager.protocolConfiguration==nil && manager.connection.starts==0)
  }
  do {
   let (model,manager,final,selection)=try setup()
   let task=Task{@MainActor in try await model.launch(manager,final,selection)};task.cancel()
   try await reject("cancelled app launch"){_ = try await task.value}
   try check("cancelled task cannot start native connection",manager.connection.starts==0)
  }
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
    body = body.replace('// SHIPPING_CONNECT', S.member(model, '    func connect(rawProfileID:'))
    body = body.replace('// SHIPPING_START', S.member(model, '    private func start(manager:'))
    with tempfile.TemporaryDirectory(prefix='.ios-chain-launch-', dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix='ios-chain-launch-') as directory:
        go_dir, work = Path(go_dir), Path(directory)
        (go_dir / 'main.go').write_text(C.GO)
        compiler = work / 'compiler'
        subprocess.run(['go', 'build', '-p', '1', '-o', str(compiler), str(go_dir / 'main.go')], cwd=ROOT, check=True, timeout=180)
        stub = work / 'Libbox.swift'; stub.write_text(C.LIBBOX)
        code = work / 'Tests.swift'; code.write_text(body + TESTS)
        options = ['swiftc', '-j', '1', '-swift-version', '6', '-module-cache-path', str(work / 'modules')]
        library = work / ('libLibbox.dylib' if platform.system() == 'Darwin' else 'libLibbox.so')
        subprocess.run(options + ['-emit-module', '-emit-library', '-module-name', 'Libbox', str(stub), '-emit-module-path', str(work / 'Libbox.swiftmodule'), '-o', str(library)], check=True, timeout=90)
        command = options + ['-I', str(work), '-L', str(work), '-lLibbox', '-Xlinker', '-rpath', '-Xlinker', str(work)]
        command += [str(APP / name) for name in ('Models.swift', 'IOSSpeedLabOwnership.swift', 'IOSMultihopStartLayer.swift', 'IOSNodeChainCapture.swift', 'IOSNodeChainProviderCapture.swift', 'IOSNodeChainLaunch.swift')]
        binary = work / 'tests'
        subprocess.run(command + [str(code), '-o', str(binary)], check=True, timeout=120)
        subprocess.run([str(binary), str(compiler)], check=True, timeout=180)
        for name, before, after, failure in (
            ('initial-manager-source', 'selection.nodeChainInput == capture.launchInput else', 'true else', 'initial manager await preserves captured ordered source middle-token'),
            ('middle-source-revalidation', 'try requireCurrentIOSNodeChain(nodeChainSource, selected: bundle)', '_ = nodeChainSource', 'ACCEPTED save middle-token'),
            ('preference-readback', 'NSDictionary(dictionary: savedConfiguration).isEqual(to: configuration),', 'true,', 'ACCEPTED save saved-source'),
        ):
            assert body.count(before) == 1, name
            code.write_text(body.replace(before, after, 1) + TESTS)
            subprocess.run(command + [str(code), '-o', str(binary)], check=True, timeout=120)
            failed = subprocess.run([str(binary), str(compiler)], capture_output=True, text=True, timeout=180)
            assert failed.returncode != 0 and failure in failed.stdout + failed.stderr, name + ': no causal failure: ' + (failed.stdout + failed.stderr)[-1000:]
            print('Rejected ordered app launch defect mutation: ' + name)


if __name__ == '__main__':
    main()
