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
SWIFT = E.SWIFT[:E.SWIFT.index('@main struct Tests')] + r'''
func socksFixture(_ mode:String,_ requested:String,_ authenticated:Bool)throws->[Data]{
 let raw=try LibboxTestSOCKSFixture()
 var bundles=try appFixture((JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [Any]).map{try data($0)})
 bundles[2]=try editProfile(bundles[2]){p in p["multihop_execution"]=requested;var nodes=p["multihop_nodes"] as! [[String:Any]];nodes[0]["mode"]=mode;p["multihop_nodes"]=nodes}
 if !authenticated {bundles[1]=try editProfile(bundles[1]){p in var ext=p["external"] as! [String:Any],proxy=ext["socks5"] as! [String:Any];proxy["username"]="";proxy["password"]="";ext["socks5"]=proxy;p["external"]=ext}}
 return bundles
}
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ yes:Bool,_ message:String){checks+=1;if !yes{print("FAIL "+message);exit(1)}}
 @MainActor static func reject(_ name:String,_ run:()throws->Void){do{try run();print("FAIL ACCEPTED "+name);exit(1)}catch{checks+=1}}
 @MainActor static func main()throws{
  defer{LibboxTestClose()}
  for mode in ["wg","awg2-fast","awg2-strong"] {for requested in ["server","auto"] {for authenticated in [false,true] {
   let bundles=try socksFixture(mode,requested,authenticated)
   let capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested);defer{try? capture.close()}
   let source=try object(Data(capture.source.utf8)),launch=try object(Data(capture.launchInput.utf8)),local=try object(Data((source["local_source"] as! String).utf8))
   check(capture.isSOCKS && !capture.isCONNECT && source["schema"] as? Int==3 && source["execution"] as? String==requested,"original SOCKS preparation family and choice")
   check(launch["kind"] as? String=="routervpn-node-chain-socks-execution-preparation-input" && launch["schema"] as? Int==1,"original SOCKS launch family")
   check(capture.members.map(\.mode)==[mode,"socks5","shadowsocks"] && (local["identity_sources"] as! [String])[1].isEmpty,"original SOCKS member order and independent identities")
   check(capture.finalProfile["startup_mode"]==nil && capture.finalProfile["auto_connect"]==nil,"only original scheduling projection")
   check(!capture.healthy() && !capture.nativeClosed(),"source compiler cannot fabricate native proof or retirement")
   reject("source-only native restore"){_ = try capture.captureRestoration()}
   let replay=try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(bundles[2]));defer{try? replay.close()}
   check(replay.isSOCKS && replay.launchInput==capture.launchInput && replay.source==capture.source,"canonical original SOCKS replay")
   let saved=try object(Data((try object(Data((local["nodes"] as! [String])[1].utf8))["capture"] as! String).utf8))["profile"]!
   check(try data(saved)==data(profile(bundles[1])),"original SOCKS policy and authentication credentials")
   let typed=try JSONDecoder().decode(ClientBundle.self,from:bundles[2]).routerProfiles[0]
   check(IOSMultihopNodeSelection.supportsSOCKSExecution(typed.multihopNodes!) && !IOSMultihopNodeSelection.supportsCONNECTExecution(typed.multihopNodes!) && !IOSMultihopNodeSelection.supportsGenericExecution(typed.multihopNodes!),"distinct public SOCKS choice")
   reject("Local source cannot consume execution selection"){_ = try IOSNodeChainSOCKSCapture.compile(bundles:bundles)}
   var failure:NSError?
   check(LibboxNewRouterNodeChainExecutionLaunch(capture.launchInput,&failure)==nil && failure != nil,"ordinary parser cannot borrow SOCKS launch")
   failure=nil;check(LibboxNewRouterNodeChainCONNECTExecutionLaunch(capture.launchInput,&failure)==nil && failure != nil,"CONNECT parser cannot borrow SOCKS launch")
   let identity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:bundles[2],entryBundleData:nil,nodeChainExecutionSource:Data(capture.launchInput.utf8))
   let nodes=try bundles.map{try JSONDecoder().decode(ClientBundle.self,from:$0)},model=RouterVPNModel(nodes,identity:identity),fifty=try IOSOrderedLatencyCapture(model)
   check(fifty.source==capture.sourceSHA256 && fifty.config==capture.configSHA256 && fifty.ids==capture.members.map(\.id) && fifty.kinds==["private-node","public-path","private-node"],"original SOCKS fifty captured source and roles")
   check(IOSNodeChainPresentation.active(identity)?.map(\.id)==capture.members.map(\.id),"active SOCKS execution presentation original identities")
   check(IOSNodeChainPresentation.planned(selected:typed,catalog:nodes.flatMap(\.routerProfiles))?.map(\.id)==capture.members.map(\.id),"planned SOCKS original identities")
   for winner in requested=="auto" ? ["local","server"]:["server"] {
    let rows:[[String:Any]]=capture.members.enumerated().map{["position":$0.offset,"profile_id":$0.element.id,"kind":$0.offset==1 ? "public-path":"private-node","proven":true,"response_ms":1.0]}
    let value:[String:Any]=["stage":"selected","execution":winner,"prefixes":rows,"ready":true,"complete":true,"dns_proven":true,"public_proven":true]
    check(IOSNodeChainPresentation.progress(value,expected:capture.members.map(\.id),requestedExecution:requested)?.contains("Every captured node and final path verified")==true,"SOCKS progress retains proved concrete choice")
   }
   let changed=try editProfile(bundles[2]){$0["api_token"]="replaced-private-source"}
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
  for modes in [["wg","wg","socks5","shadowsocks"],["socks5","shadowsocks"],["wg","socks5","hysteria2"],["wg","http-connect","shadowsocks"],["hysteria2","socks5","shadowsocks"]] {
   let selected=modes.enumerated().map{IOSMultihopNodeSelection(id:"original-\($0.offset)",mode:$0.element)}
   check(!IOSMultihopNodeSelection.supportsSOCKSExecution(selected),"SOCKS public choice refuses unsupported topology")
  }
  print("PASS Apple SOCKS execution source: \(checks) original source and consumer checks")
 }
}
'''


def main():
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
        (work / 'Tests.swift').write_text(SWIFT)
        (work / 'Latency.swift').write_text(route + model + latency)
        options = ['swiftc', '-j', '1', '-swift-version', '6', '-module-cache-path', str(work / 'modules')]
        suffix = '.dylib' if platform.system() == 'Darwin' else '.so'
        subprocess.run(options + ['-emit-module', '-emit-library', '-module-name', 'Libbox', str(work / 'Libbox.swift'), '-emit-module-path', str(work / 'Libbox.swiftmodule'), '-o', str(work / ('libLibbox' + suffix))], check=True, timeout=90)
        link = ['-I', str(work), '-L', str(work), '-lLibbox', '-Xlinker', '-rpath', '-Xlinker', str(work)]
        subprocess.run(options + link + ['-emit-module', '-emit-library', '-module-name', 'CryptoKit', str(work / 'CryptoKit.swift'), '-emit-module-path', str(work / 'CryptoKit.swiftmodule'), '-o', str(work / ('libCryptoKit' + suffix))], check=True, timeout=90)
        presentation = (APP / 'IOSNodeChainPresentation.swift').read_text()
        (work / 'Presentation.swift').write_text(presentation)
        command = options + link + ['-lCryptoKit'] + [str(APP / n) for n in ('Models.swift', 'IOSMultihopStartLayer.swift', 'IOSNodeChainCapture.swift', 'IOSImportedOpenVPNSource.swift', 'IOSNodeChainCONNECTCapture.swift', 'IOSNodeChainSOCKSCapture.swift', 'IOSNodeChainProviderCapture.swift', 'IOSSessionIdentity.swift')] + [str(work / 'Presentation.swift'), str(work / 'Latency.swift')]
        original = (APP / 'IOSNodeChainExecutionCapture.swift').read_text()
        def run(value):
            path, binary = work / 'Capture.swift', work / 'tests'
            path.write_text(value)
            subprocess.run(command + [str(path), str(work / 'Tests.swift'), '-o', str(binary)], check=True, timeout=90)
            return subprocess.run([str(binary), str(compiler)], capture_output=True, text=True, timeout=180)
        result = run(original)
        assert result.returncode == 0, result.stdout + result.stderr
        print(result.stdout.strip())
        for name, before, after, witness in (
            ('original-members', 'nodes == original["nodes"] as? [String],', 'true,', 'ACCEPTED typed native readback local-node'),
            ('original-identities', 'identities == original["identity_sources"] as? [String] else {', '!identities.isEmpty else {', 'ACCEPTED typed native readback local-identity'),
            ('original-final', 'guard try canonical(IOSNodeChainCapture.executionProfile(selectedProfile)) == canonical(local.finalProfile) else {\n                throw', 'guard true else {\n                throw', 'ACCEPTED changed final private source'),
        ):
            assert original.count(before) == 1, name
            result = run(original.replace(before, after, 1))
            assert result.returncode == 1 and witness in result.stdout + result.stderr, (name, result.stdout, result.stderr)
            print('Rejected Apple SOCKS source control:', name)
        start = presentation.index('    private static func capturedSOCKS(')
        end = presentation.index('    private static func capturedCONNECT(', start)
        section = presentation[start:end]
        before = 'guard last == expected else { return nil }'
        assert section.count(before) == 1
        (work / 'Presentation.swift').write_text(presentation[:start] + section.replace(before, 'guard true else { return nil }', 1) + presentation[end:])
        result = run(original)
        assert result.returncode == 1 and 'SOCKS presentation rejects replaced final private source' in result.stdout + result.stderr, result.stdout + result.stderr
        print('Rejected Apple SOCKS source control: original-presentation')


if __name__ == '__main__':
    main()
