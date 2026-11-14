#!/usr/bin/env python3
"""Prove original WG identity capture across shipping Apple launch boundaries.

The source compiler and Swift capture/start methods are production code. The
private record store and NetworkExtension preferences are explicit doubles;
these checks neither open a native tunnel nor establish physical acceptance.
"""
from pathlib import Path
import importlib.util
import json
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
spec = importlib.util.spec_from_file_location('ordered_identity_launch', ROOT / 'deploy/test_ios_node_chain_launch.py')
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)

GO = L.C.GO.replace(' case "chain-fixture":', r'''
 case "chain-without-identities":
  var source mobilemultihop.NodeChainSource
  err=json.Unmarshal([]byte(r.Source),&source)
  if err==nil{source.IdentitySources=nil;var raw []byte;raw,err=json.Marshal(source)
   if err==nil{var chain *mobilemultihop.NodeChain;chain,err=mobilemultihop.NewNodeChain(string(raw));if err==nil{value,err=chain.LaunchInput()}}}
 case "chain-fixture":''', 1)
LIBBOX = L.C.LIBBOX + r'''
public func LibboxTestWithoutIdentities(_ launch:String)throws->String {
 try bridge(["Op":"chain-without-identities","Source":launch])
}
'''

TESTS = L.TESTS[:L.TESTS.index(' static func run()async throws {')].replace(
    'Apple ordered app launch: PASS', 'Apple ordered identity capture: PASS') + r'''
 static func object(_ value:Data)throws->[String:Any] {
  guard let value=try JSONSerialization.jsonObject(with:value) as? [String:Any] else{throw CancellationError()};return value
 }
 static func changeWG(_ node:inout ClientBundle,_ marker:String) {
  let original=String(decoding:Data(base64Encoded:node.profiles["wg"]!["wg.conf"]!)!,as:UTF8.self)
  node.profiles["wg"]!["wg.conf"]=Data((original+"\n# "+marker+"\n").utf8).base64EncodedString()
 }
 static func run()async throws {
  do {
   let(model,manager,selected,selection)=try setup(4,true)
   let capture=try model.captureIOSNodeChain(selected);defer{try? capture.plan.close()}
   let record=try object(Data(capture.launchInput.utf8)),identities=record["identity_sources"] as! [String]
   try check("every member retains its original standard WG identity",identities.count==4)
   let members=try model.iosNodeChainBundles(for:selected)
   let graph=try object(Data(capture.config.utf8)),endpoints=graph["endpoints"] as! [[String:Any]]
   for i in 0..<4 {
    let saved=try object(Data(identities[i].utf8)) as! [String:String]
    try check("ordered identity inventory is exact at position \(i)",saved==members[i].profiles["wg"]!)
    if i<2 {
     let raw=String(decoding:Data(base64Encoded:saved["wg.conf"]!)!,as:UTF8.self)
     let peer=(endpoints[i]["peers"] as! [[String:Any]])[0]["public_key"] as! String
     try check("AWG peer is independent of standard Router identity",!raw.contains(peer))
    }
   }
   _ = try await model.launch(manager,selected,selection)
   let config=(manager.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
   let provider=try IOSNodeChainProviderCapture.reopen(config);defer{try? provider.plan.close()}
   try check("one native handoff keeps complete identity source",manager.connection.starts==1 && provider.launchInput==capture.launchInput && provider.sourceSHA256==capture.sourceSHA256)
   try check("identity capture grants no app proof",!model.connected && !capture.plan.config().isEmpty)

   let legacy=try LibboxTestWithoutIdentities(capture.launchInput)
   let final=try object(JSONEncoder().encode(selected.routerProfiles[0]))
   try await reject("native handoff missing identity inventory"){_ = try IOSNodeChainCapture.reopen(legacy,selectedProfile:final)}
   var providerMissing=config;providerMissing[IOSNodeChainProviderCapture.key]=legacy
   try await reject("provider handoff missing identity inventory"){_ = try IOSNodeChainProviderCapture.reopen(providerMissing)}

   try editMiddle{changeWG(&$0,"new original identity bytes")}
   let changed=try model.captureIOSNodeChain(selected);defer{try? changed.plan.close()}
   try check("WG-only source change keeps AWG graph and changes receipt",changed.config==capture.config && changed.sourceSHA256 != capture.sourceSHA256 && changed.launchInput != capture.launchInput)
   try await reject("current source rejects original identity byte replacement"){try model.requireCurrentIOSNodeChain(capture.launchInput,selected:selected)}
  }
  for position in 0..<4 {
   let(model,_,selected,_)=try setup(4,true)
   var nodes=try model.iosNodeChainBundles(for:selected)
   nodes[position].profiles.removeValue(forKey:"wg")
   try await reject("missing standard WG identity at position \(position)"){
    _ = try IOSNodeChainCapture.compile(bundles:nodes.map{try JSONEncoder().encode($0)})
   }
  }
  for fault in ["wrong-proof","reordered-identities"] {
   let(model,_,selected,_)=try setup(4,true)
   var nodes=try model.iosNodeChainBundles(for:selected)
   if fault=="wrong-proof" {
    nodes[1].nodeProofID=String(repeating:"f",count:64)
    nodes[1].routerProfiles[0].nodeProofID=nodes[1].nodeProofID
   } else {
    let saved=nodes[0].profiles["wg"]!;nodes[0].profiles["wg"]=nodes[1].profiles["wg"];nodes[1].profiles["wg"]=saved
   }
   try await reject("original identity "+fault){
    _ = try IOSNodeChainCapture.compile(bundles:nodes.map{try JSONEncoder().encode($0)})
   }
  }
  for phase in ["save","load","load-all"] {
   for fault in ["changed-identity","missing-identity"] {
    let(model,manager,selected,selection)=try setup(4,true)
    NETunnelProviderManager.hook={observed in
     guard observed==phase else{return}
     try editMiddle{node in
      if fault=="changed-identity" {changeWG(&node,"changed while awaiting "+phase)}
      else {node.profiles.removeValue(forKey:"wg")}
     }
    }
    try await reject(phase+" "+fault){
     _ = try await IOSSpeedLabContext.$startupAdmission.withValue({true}){try await model.launch(manager,selected,selection)}
    }
    try check("late identity change never invokes native start",manager.connection.starts==0)
   }
  }
  do {
   let(model,manager,_,_)=try setup(4,true)
   let proto=NETunnelProviderProtocol();proto.providerBundleIdentifier="com.eabusham.routervpn.PacketTunnel";manager.protocolConfiguration=proto
   NETunnelProviderManager.hook={phase in guard phase=="load-all" else{return};try editMiddle{changeWG(&$0,"initial manager readback")}}
   await model.connect(rawProfileID:nil)
   try check("initial manager await cannot substitute original identity source",NETunnelProviderManager.starts==0)
  }
 }
}
'''


def main():
    model = (APP / 'RouterVPNModel.swift').read_text()
    view = (APP / 'IOSMultihopView.swift').read_text()
    dns = (APP / 'IOSDNSRuntimePolicy.swift').read_text()
    runtime = (APP / 'IOSRuntimeSelection.swift').read_text()
    boundary = L.S.BOUNDARIES[L.S.BOUNDARIES.index('enum NEVPNStatus'):L.S.BOUNDARIES.index('enum IOSRuntimeSelectionError')]
    body = L.BOUNDARIES.replace('// SHIPPING_NETWORK_EXTENSION_BOUNDARY', boundary)
    body = body.replace('// SHIPPING_SELECTION_TYPES', runtime[runtime.index('enum IOSRuntimeEngine'):runtime.index('enum IOSRuntimeSelectionError')])
    body = body.replace('// SHIPPING_SELECTED_PROFILE', L.S.member(dns, '    static func selectedProfile('))
    body = body.replace('// SHIPPING_CHAIN_BUNDLES', L.S.member(view, '    func iosNodeChainBundles('))
    body = body.replace('// SHIPPING_CONNECT', L.S.member(model, '    func connect(rawProfileID:'))
    body = body.replace('// SHIPPING_START', L.S.member(model, '    private func start(manager:'))
    with tempfile.TemporaryDirectory(prefix='.ios-chain-identity-', dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix='ios-chain-identity-') as directory:
        go_dir, work = Path(go_dir), Path(directory)
        go_source = go_dir / 'main.go'; go_source.write_text(GO)
        compiler = work / 'compiler'
        subprocess.run(['go', 'build', '-p', '1', '-o', str(compiler), str(go_source)], cwd=ROOT, check=True, timeout=180)
        stub = work / 'Libbox.swift'; stub.write_text(LIBBOX)
        code = work / 'Tests.swift'; code.write_text(body + TESTS)
        options = ['swiftc', '-j', '1', '-swift-version', '6', '-module-cache-path', str(work / 'modules')]
        library = work / ('libLibbox.dylib' if platform.system() == 'Darwin' else 'libLibbox.so')
        subprocess.run(options + ['-emit-module', '-emit-library', '-module-name', 'Libbox', str(stub), '-emit-module-path', str(work / 'Libbox.swiftmodule'), '-o', str(library)], check=True, timeout=90)
        command = options + ['-I', str(work), '-L', str(work), '-lLibbox', '-Xlinker', '-rpath', '-Xlinker', str(work)]
        capture = APP / 'IOSNodeChainCapture.swift'
        sources = [str(APP / name) for name in ('Models.swift', 'IOSSpeedLabOwnership.swift', 'IOSMultihopStartLayer.swift', 'IOSNodeChainCapture.swift', 'IOSNodeChainProviderCapture.swift', 'IOSNodeChainSOCKSCapture.swift', 'IOSNodeChainCONNECTCapture.swift', 'IOSNodeChainLaunch.swift')]
        binary = work / 'tests'
        subprocess.run(command + sources + [str(code), '-o', str(binary)], check=True, timeout=120)
        subprocess.run([str(binary), str(compiler)], check=True, timeout=180)

        source = capture.read_text()
        # The schema-two imported member has no paired identity, while every
        # native member still requires one. Remove both inventory-presence and
        # native-role requirements to reproduce the original missing-receipt
        # defect without weakening the source schema check or positive cases.
        before = '              let identitySources = root["identity_sources"] as? [String], identitySources.count == nodes.count,'
        after = '              let identitySources = Optional((root["identity_sources"] as? [String]) ?? []),'
        native_identity = 'guard !identitySources[position].isEmpty, !(schema == 2 && position == 1),'
        assert source.count(before) == 1 and source.count(native_identity) == 1
        changed = source.replace(before, after, 1).replace(native_identity, 'guard !(schema == 2 && position == 1),', 1)
        mutated = work / 'MissingIdentityReceipt.swift'; mutated.write_text(changed)
        variants = [
            ('required-native-inventory', [str(mutated) if path == str(capture) else path for path in sources], body, 'ACCEPTED native handoff missing identity inventory'),
            ('post-await-identity', sources, body.replace('try requireCurrentIOSNodeChain(nodeChainSource, selected: bundle)', '_ = nodeChainSource', 1), 'ACCEPTED save changed-identity'),
        ]
        assert body.count('try requireCurrentIOSNodeChain(nodeChainSource, selected: bundle)') == 1
        for name, selected_sources, selected_body, failure in variants:
            code.write_text(selected_body + TESTS)
            executable = work / name
            subprocess.run(command + selected_sources + [str(code), '-o', str(executable)], check=True, timeout=120)
            failed = subprocess.run([str(executable), str(compiler)], capture_output=True, text=True, timeout=180)
            assert failed.returncode != 0 and failure in failed.stdout + failed.stderr, name + ': missing causal refusal: ' + (failed.stdout + failed.stderr)[-1200:]
            print('Rejected ordered identity defect mutation: ' + name)

        native = ROOT / 'internal/mobilemultihop/node_chain_identity.go'
        native_text = native.read_text()
        before = 'if _, err := parseWireGuardProfile(string(raw), predecessorText(node.profile, "node_proof_id")); err != nil {'
        assert native_text.count(before) == 1
        native_mutant = work / 'UncheckedOriginalIdentity.go'
        native_mutant.write_text(native_text.replace(before, 'if len(raw) == 0 {', 1))
        overlay = work / 'overlay.json'; overlay.write_text(json.dumps({'Replace': {str(native): str(native_mutant)}}))
        mutant_compiler = work / 'unchecked-compiler'
        subprocess.run(['go', 'build', '-p', '1', '-overlay', str(overlay), '-o', str(mutant_compiler), str(go_source)], cwd=ROOT, check=True, timeout=180)
        failed = subprocess.run([str(binary), str(mutant_compiler)], capture_output=True, text=True, timeout=180)
        assert failed.returncode != 0 and 'ACCEPTED original identity wrong-proof' in failed.stdout + failed.stderr, 'original WG parser omission did not fail causally: ' + (failed.stdout + failed.stderr)[-1200:]
        print('Rejected ordered identity defect mutation: original-WG-proof')


if __name__ == '__main__':
    main()
