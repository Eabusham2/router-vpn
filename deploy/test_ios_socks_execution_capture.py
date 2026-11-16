#!/usr/bin/env python3
"""Run Apple SOCKS execution consumers against the actual shared source compiler.

Native Run, TUN, leases and live restoration remain explicit refusing boundaries.
"""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
spec = importlib.util.spec_from_file_location('original_connect_consumers', ROOT / 'deploy/test_ios_connect_execution_capture.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
E, F = C.E, C.F
LIBBOX = E.LIBBOX
PREFIX_NODE_COUNTS = (3, 4, 5, 6, 7, 8)
SWIFT = E.SWIFT[:E.SWIFT.index('@main struct Tests')] + r'''
func socksFixture(_ mode:String,_ requested:String,_ authenticated:Bool,_ count:Int=3,_ layer:String="off")throws->[Data]{
 var bundles=try appFixture(fixture(count,layer,requested,true))
 let middle=count-2,final=count-1
 bundles[middle]=try editProfile(bundles[middle]){p in
  p["node_kind"]="external";p.removeValue(forKey:"node_proof_id");p["router_api"]="";p["api_token"]="";p["endpoint"]="203.0.113.20";p["start_layer"]="off"
  p["external"]=["protocol":"socks5","expected_public_ip":"203.0.113.88","socks5":["host":"203.0.113.20","port":1080,"username":authenticated ? "saved user":"","password":authenticated ? "saved:password":""]]
 }
 bundles[middle]=try edit(bundles[middle]){$0["profiles"]=[String:[String:String]]()}
 bundles[final]=try editProfile(bundles[final]){p in
  p["multihop_execution"]=requested;p["start_layer"]="off";var nodes=p["multihop_nodes"] as! [[String:Any]]
  for position in 0..<middle{nodes[position]["mode"]=mode=="mixed" ? ["wg","awg2-fast","awg2-strong"][position%3]:mode}
  nodes[middle]["mode"]="socks5";p["multihop_nodes"]=nodes
 }
 return bundles
}
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ yes:Bool,_ message:String){checks+=1;if !yes{print("FAIL "+message);exit(1)}}
 @MainActor static func reject(_ name:String,_ run:()throws->Void){do{try run();print("FAIL ACCEPTED "+name);exit(1)}catch{checks+=1}}
 @MainActor static func main()throws{
  defer{LibboxTestClose()}
  guard CommandLine.arguments.count==3,let count=Int(CommandLine.arguments[2]),(3...8).contains(count) else {print("FAIL missing captured SOCKS prefix phase");exit(1)}
  for mode in ["wg","awg2-fast","awg2-strong"] {for requested in ["server","auto"] {for authenticated in [false,true] {
   let bundles=try socksFixture(mode,requested,authenticated,count)
   let capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested);defer{try? capture.close()}
   let source=try object(Data(capture.source.utf8)),launch=try object(Data(capture.launchInput.utf8)),local=try object(Data((source["local_source"] as! String).utf8))
   check(capture.isSOCKS && !capture.isCONNECT && source["schema"] as? Int==3 && source["execution"] as? String==requested,"original SOCKS preparation family and choice")
   check(launch["kind"] as? String=="routervpn-node-chain-socks-execution-preparation-input" && launch["schema"] as? Int==1,"original SOCKS launch family")
   check(capture.members.map(\.mode)==Array(repeating:mode,count:count-2)+["socks5","shadowsocks"] && (local["identity_sources"] as! [String]).enumerated().allSatisfy{$0.offset==count-2 ? $0.element.isEmpty:!$0.element.isEmpty},"original SOCKS member order and independent identities")
   check(capture.finalProfile["startup_mode"]==nil && capture.finalProfile["auto_connect"]==nil,"only original scheduling projection")
   check(!capture.healthy() && !capture.nativeClosed(),"source compiler cannot fabricate native proof or retirement")
   reject("source-only native restore"){_ = try capture.captureRestoration()}
   let replay=try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(bundles[count-1]));defer{try? replay.close()}
   check(replay.isSOCKS && replay.launchInput==capture.launchInput && replay.source==capture.source,"canonical original SOCKS replay")
   let saved=try object(Data((try object(Data((local["nodes"] as! [String])[count-2].utf8))["capture"] as! String).utf8))["profile"]!
   check(try data(saved)==data(profile(bundles[count-2])),"original SOCKS policy and authentication credentials")
   let typed=try JSONDecoder().decode(ClientBundle.self,from:bundles[count-1]).routerProfiles[0]
   check(IOSMultihopNodeSelection.supportsSOCKSExecution(typed.multihopNodes!) && !IOSMultihopNodeSelection.supportsCONNECTExecution(typed.multihopNodes!) && !IOSMultihopNodeSelection.supportsGenericExecution(typed.multihopNodes!),"distinct public SOCKS choice")
   reject("Local source cannot consume execution selection"){_ = try IOSNodeChainSOCKSCapture.compile(bundles:bundles)}
   var failure:NSError?
   check(LibboxNewRouterNodeChainExecutionLaunch(capture.launchInput,&failure)==nil && failure != nil,"ordinary parser cannot borrow SOCKS launch")
   failure=nil;check(LibboxNewRouterNodeChainCONNECTExecutionLaunch(capture.launchInput,&failure)==nil && failure != nil,"CONNECT parser cannot borrow SOCKS launch")
   let identity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:bundles[count-1],entryBundleData:nil,nodeChainExecutionSource:Data(capture.launchInput.utf8))
   let nodes=try bundles.map{try JSONDecoder().decode(ClientBundle.self,from:$0)},model=RouterVPNModel(nodes,identity:identity),fifty=try IOSOrderedLatencyCapture(model)
   check(fifty.source==capture.sourceSHA256 && fifty.config==capture.configSHA256 && fifty.ids==capture.members.map(\.id) && fifty.kinds==Array(repeating:"private-node",count:count-2)+["public-path","private-node"],"original SOCKS fifty captured source and roles")
   check(IOSNodeChainPresentation.active(identity)?.map(\.id)==capture.members.map(\.id),"active SOCKS execution presentation original identities")
   check(IOSNodeChainPresentation.planned(selected:typed,catalog:nodes.flatMap(\.routerProfiles))?.map(\.id)==capture.members.map(\.id),"planned SOCKS original identities")
   for winner in requested=="auto" ? ["local","server"]:["server"] {
    let rows:[[String:Any]]=capture.members.enumerated().map{["position":$0.offset,"profile_id":$0.element.id,"kind":$0.offset==count-2 ? "public-path":"private-node","proven":true,"response_ms":1.0]}
    let value:[String:Any]=["stage":"selected","execution":winner,"prefixes":rows,"ready":true,"complete":true,"dns_proven":true,"public_proven":true]
    check(IOSNodeChainPresentation.progress(value,expected:capture.members.map(\.id),requestedExecution:requested)?.contains("Every captured node and final path verified")==true,"SOCKS progress retains proved concrete choice")
   }
   let changed=try editProfile(bundles[count-1]){$0["api_token"]="replaced-private-source"}
   reject("changed final private source"){_ = try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(changed))}
   let stale=try IOSSessionIdentity(connectedAt:identity.connectedAt,engine:identity.engine,rawProfile:identity.rawProfile,bundleData:changed,entryBundleData:nil,nodeChainExecutionSource:identity.nodeChainExecutionSource)
   check(IOSNodeChainPresentation.active(stale)==nil,"SOCKS presentation rejects replaced final private source")
   try fifty.require(model);model.iosConnectGeneration=UUID();reject("SOCKS latency replacement generation"){try fifty.require(model)};model.iosConnectGeneration=fifty.selection
   model.nodes[0].routerProfiles[0].name="changed original private source";reject("SOCKS latency complete source"){try fifty.require(model)}
   reject("latency initial source change"){_ = try IOSOrderedLatencyCapture(model)}
   for fault in ["config","requested","local-node","local-schema","local-identity","local-execution","preparation-schema","launch-schema","launch-error"] {
    LibboxTestExecutionFault(fault);reject("typed native readback "+fault){_ = try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested)}
   }
  }}}
  if count==4 || count==8 {
   for requested in ["server","auto"] {for layer in ["aes-256-gcm","aes-256-gcm+xor-whitening"] {
    let bundles=try socksFixture("mixed",requested,true,count,layer)
    let capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested);defer{try? capture.close()}
    check(capture.members.prefix(count-2).enumerated().allSatisfy{$0.element.mode==["wg","awg2-fast","awg2-strong"][$0.offset%3] && $0.element.profile["start_layer"] as? String==layer},"complete mixed SOCKS prefixes retain original ciphers and layers")
    for position in 0..<count-2 {
     var replaced=bundles;replaced[position]=try editProfile(replaced[position]){$0["node_proof_id"]=String(repeating:"f",count:64)}
     reject("changed original SOCKS prefix proof \(position)"){_ = try IOSNodeChainExecutionCapture.compile(bundles:replaced,requested:requested)}
    }
    let local=try object(Data((try object(Data(capture.source.utf8))["local_source"] as! String).utf8))
    let identities=local["identity_sources"] as! [String]
    check(Set(identities.filter{!$0.isEmpty}).count==count-1,"complete mixed SOCKS prefixes keep independent paired identity sources")
   }}
  }
  for modes in [["wg","hysteria2","socks5","shadowsocks"],["socks5","shadowsocks"],["wg","socks5","hysteria2"],["wg","http-connect","shadowsocks"],["hysteria2","socks5","shadowsocks"],["wg","socks5","wg","shadowsocks"],Array(repeating:"wg",count:7)+["socks5","shadowsocks"]] {
   let selected=modes.enumerated().map{IOSMultihopNodeSelection(id:"original-\($0.offset)",mode:$0.element)}
   check(!IOSMultihopNodeSelection.supportsSOCKSExecution(selected),"SOCKS public choice refuses unsupported topology")
  }
  print("PASS Apple SOCKS execution source nodes=\(count): \(checks) original source and consumer checks")
 }
}
'''


def main(swift=SWIFT, family="SOCKS"):
    launch = (APP / 'IOSNodeChainLaunch.swift').read_text()
    route = launch.split('@MainActor\nextension RouterVPNModel')[0]
    model = F.BOUNDARY.replace('// ORIGINAL_CAPTURE', F.member(launch, '    func captureIOSOrderedRoute('))
    latency = (APP / 'IOSOrderedLatency.swift').read_text().split('private final class IOSOrderedLatencyReply')[0].replace('import Combine\n', '').replace('@preconcurrency import NetworkExtension\n', '')
    with tempfile.TemporaryDirectory(prefix='.ios-socks-execution-', dir=ROOT) as gd, tempfile.TemporaryDirectory(prefix='ios-socks-execution-') as wd:
        gd, work = Path(gd), Path(wd)
        (gd / 'main.go').write_text(E.GO)
        compiler = work / 'compiler'
        subprocess.run(['go', 'build', '-p', '1', '-o', str(compiler), str(gd / 'main.go')], cwd=ROOT, check=True, timeout=180)
        (work / 'Libbox.swift').write_text(LIBBOX)
        (work / 'CryptoKit.swift').write_text(E.CRYPTO)
        (work / 'Tests.swift').write_text(swift)
        (work / 'Latency.swift').write_text(route + model + latency)
        options = ['swiftc', '-j', '1', '-swift-version', '6', '-module-cache-path', str(work / 'modules')]
        suffix = '.dylib' if platform.system() == 'Darwin' else '.so'
        subprocess.run(options + ['-emit-module', '-emit-library', '-module-name', 'Libbox', str(work / 'Libbox.swift'), '-emit-module-path', str(work / 'Libbox.swiftmodule'), '-o', str(work / ('libLibbox' + suffix))], check=True, timeout=90)
        link = ['-I', str(work), '-L', str(work), '-lLibbox', '-Xlinker', '-rpath', '-Xlinker', str(work)]
        subprocess.run(options + link + ['-emit-module', '-emit-library', '-module-name', 'CryptoKit', str(work / 'CryptoKit.swift'), '-emit-module-path', str(work / 'CryptoKit.swiftmodule'), '-o', str(work / ('libCryptoKit' + suffix))], check=True, timeout=90)
        models = (APP / 'Models.swift').read_text()
        (work / 'Models.swift').write_text(models)
        presentation = (APP / 'IOSNodeChainPresentation.swift').read_text()
        (work / 'Presentation.swift').write_text(presentation)
        command = options + link + ['-lCryptoKit', str(work / 'Models.swift')] + [str(APP / n) for n in ( 'IOSMultihopStartLayer.swift', 'IOSNodeChainCapture.swift', 'IOSImportedOpenVPNSource.swift', 'IOSNodeChainCONNECTCapture.swift', 'IOSNodeChainSOCKSCapture.swift', 'IOSNodeChainProviderCapture.swift', 'IOSSessionIdentity.swift')] + [str(work / 'Presentation.swift'), str(work / 'Latency.swift')]
        original = (APP / 'IOSNodeChainExecutionCapture.swift').read_text()
        def compile_capture(value):
            path, binary = work / 'Capture.swift', work / 'tests'
            path.write_text(value)
            subprocess.run(command + [str(path), str(work / 'Tests.swift'), '-o', str(binary)], check=True, timeout=90)
        def execute(count):
            assert count in PREFIX_NODE_COUNTS
            return subprocess.run([str(work / 'tests'), str(compiler), str(count)], capture_output=True, text=True, timeout=180)
        def run(value, count=3):
            compile_capture(value)
            return execute(count)
        compile_capture(original)
        for count in PREFIX_NODE_COUNTS:
            result = execute(count)
            assert result.returncode == 0, (count, result.stdout, result.stderr)
            assert result.stdout.count('PASS Apple '+family+' execution source nodes='+str(count)+': ')==1, result.stdout
            print(result.stdout.strip(), flush=True)
        for name, before, after, witness in (
            ('original-members', 'nodes == original["nodes"] as? [String],', 'true,', 'ACCEPTED typed native readback local-node'),
            ('original-identities', 'identities == original["identity_sources"] as? [String] else {', '!identities.isEmpty else {', 'ACCEPTED typed native readback local-identity'),
            ('original-final', 'guard try canonical(IOSNodeChainCapture.executionProfile(selectedProfile)) == canonical(local.finalProfile) else {\n                throw', 'guard true else {\n                throw', 'ACCEPTED changed final private source'),
        ):
            assert original.count(before) == 1, name
            result = run(original.replace(before, after, 1))
            assert result.returncode == 1 and witness in result.stdout + result.stderr, (name, result.stdout, result.stderr)
            print('Rejected Apple '+family+' source control:', name)
        if family == 'OpenVPN':
            before = '!local.isOpenVPN || preparation["openvpn_local_launch"] as? String == local.launchInput,'
            assert original.count(before) == 1
            result = run(original.replace(before, 'true,', 1))
            assert result.returncode == 1 and 'ACCEPTED typed native readback openvpn-local-launch' in result.stdout + result.stderr, result.stdout + result.stderr
            print('Rejected Apple OpenVPN source control: sealed-local-launch')
        start = presentation.index('    private static func capturedOpenVPNExecution(' if family == 'OpenVPN' else '    private static func capturedSOCKS(')
        end = presentation.index('    private static func capturedGenericExecution(' if family == 'OpenVPN' else '    private static func capturedCONNECT(', start)
        section = presentation[start:end]
        before = 'guard last == expected else { return nil }'
        assert section.count(before) == 1
        (work / 'Presentation.swift').write_text(presentation[:start] + section.replace(before, 'guard true else { return nil }', 1) + presentation[end:])
        result = run(original)
        assert result.returncode == 1 and family+' presentation rejects replaced final private source' in result.stdout + result.stderr, result.stdout + result.stderr
        print('Rejected Apple '+family+' source control: original-presentation')
        (work / 'Presentation.swift').write_text(presentation)
        begin = models.index('    static func supports'+family+'Execution(')
        end = models.index('    static func supportsCONNECTExecution(' if family == 'OpenVPN' else '    static func supportsServerExecution(', begin)
        section = models[begin:end]
        before = '(3...maximumNodes).contains(nodes.count)'
        assert section.count(before) == 1
        (work / 'Models.swift').write_text(models[:begin] + section.replace(before, 'nodes.count == 3', 1) + models[end:])
        result = run(original, 4)
        assert result.returncode == 1 and 'FAIL distinct public '+family+' choice' in result.stdout + result.stderr, result.stdout + result.stderr
        print('Rejected Apple '+family+' source control: old-trio-admission')


if __name__ == '__main__':
    main()
