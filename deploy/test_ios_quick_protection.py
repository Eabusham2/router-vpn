#!/usr/bin/env python3
"""Execute the shipping quick kill-switch handler and native preference handoff.

Reuse the declared NetworkExtension/private-store boundaries from the startup
fixture. Selection, mutation, external source capture and strict route flags
are shipping code; this does not claim physical VPN or leak-test acceptance.
"""
from pathlib import Path
import argparse
import tempfile

import test_ios_startup_policy as STARTUP

APP = STARTUP.APP

TESTS = r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ condition:@autoclosure ()throws->Bool)throws {
  guard try condition()else{throw NSError(domain:"QuickProtectionFixture",code:1,userInfo:[NSLocalizedDescriptionKey:name])};checks+=1
 }
 // FIXTURE_BUILDERS
 static func controls()async throws {
  for kind in ["wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn","tor","tor-bridge"] {
   for enabled in [false,true] {for shape in ["direct","paired","paired-strict"] {
    let m=model(profile(kind))
    if shape != "direct" {attachEntry(m);m.entry!.routerProfiles[0].killSwitch=shape=="paired-strict"}
    var sibling=profile("shadowsocks");sibling.id="unselected";sibling.name="Other saved node"
    sibling.external!.shadowsocks!.password="other independent credential";m.bundle!.routerProfiles.insert(sibling,at:0)
    let before=m.bundle!,entryBefore=try m.entry.map(encoded)
    m.setUnifiedQuickKillSwitch(enabled)
    var expected=before;expected.routerProfiles[1].killSwitch=enabled;expected.routerProfiles[1].killSwitchPolicy=enabled ? "on-connect":"off"
    try check("quick kill switch changes only the exact selected node "+kind+" "+shape,m.imports==1 && (try encoded(m.bundle!))==encoded(expected))
    try check("quick protection reflects the saved native request",m.unifiedQuickKillSwitch==enabled)
    try check("quick protection preserves the independent entry",try m.entry.map(encoded)==entryBefore)
    await m.connectSelectedExternal()
    try check("saved external protection reaches native Connect",NETunnelProviderManager.starts==1 && m.connected)
    let manager=NETunnelProviderManager.instances[0],proto=manager.protocolConfiguration as! NETunnelProviderProtocol
    let strict=enabled || shape=="paired-strict"
    try check("quick protection enforces actual native route lockdown",proto.includeAllNetworks==strict && proto.enforceRoutes==strict && manager.isOnDemandEnabled==strict && !proto.excludeLocalNetworks)
    let config=proto.providerConfiguration!,runtime=try JSONDecoder().decode(ClientBundle.self,from:config["bundle"] as! Data)
    try check("protection handoff keeps the selected credentials and DNS",runtime.routerProfiles[0].external==expected.routerProfiles[1].external && runtime.routerProfiles[0].dnsHost==expected.routerProfiles[1].dnsHost)
    let key=["tor","tor-bridge"].contains(kind) ? "tor_entry_bundle":"external_entry_bundle"
    try check("native handoff retains exact entry policy and secrets",config[key] as? Data==entryBefore)
   }}
  }
  for enabled in [false,true] {
   var p=profile();p.nodeKind="router-vpn";p.external=nil
   let m=model(p);m.bundle=try JSONDecoder().decode(ClientBundle.self,from:encoded(m.bundle!))
   let before=m.bundle!;m.setUnifiedQuickKillSwitch(enabled)
   var expected=before;expected.routerProfiles[0].killSwitch=enabled;expected.routerProfiles[0].killSwitchPolicy=enabled ? "on-connect":"off"
   try check("Router quick protection remains transactional",m.imports==1 && (try encoded(m.bundle!))==encoded(expected))
  }
 }
 static func rejected()throws {
  for fault in ["missing-selection","empty-selection","duplicate","wrong-kind","unsupported","connected","transition","disconnect","write"] {
   let m=model(profile());attachEntry(m)
   switch fault {
   case "missing-selection":m.bundle!.selectedRouterID="missing"
   case "empty-selection":m.bundle!.selectedRouterID=""
   case "duplicate":m.bundle!.routerProfiles.append(m.bundle!.routerProfiles[0])
   case "wrong-kind":m.bundle!.routerProfiles[0].nodeKind="unowned-kind"
   case "unsupported":m.bundle!.routerProfiles[0].external!.protocolName="unowned-runtime"
   case "connected":m.connected=true
   case "transition":m.tunnelTransitioning=true
   case "disconnect":m.iosUserDisconnectInProgress=true
   default:m.failImport=true
   }
   let before=try encoded(m.bundle!),entry=try encoded(m.entry!);m.setUnifiedQuickKillSwitch(true)
   try check("quick protection rejects invalid or active mutation "+fault,m.imports==0 && (try encoded(m.bundle!))==before && (try encoded(m.entry!))==entry)
  }
  for policy in ["strict","always","enabled","on","lockdown"," STRICT ","off","on-connect","unknown"] {
   var p=profile();p.killSwitch=false;p.killSwitchPolicy=policy
   let m=model(p),expected=["strict","always","enabled","on","lockdown"].contains(policy.trimmingCharacters(in:.whitespacesAndNewlines).lowercased())
   try check("quick display matches native strict-policy semantics "+policy,m.unifiedQuickKillSwitch==expected)
  }
  let missing=model(profile());missing.bundle!.selectedRouterID="foreign"
  try check("missing selection never displays another node",missing.unifiedSelectedProfile==nil)
 }
 static func main()async {
  do {try await controls();try rejected();print("iOS quick protection and external native handoff: \(checks) executable checks PASS")}
  catch{FileHandle.standardError.write(Data(("FAIL: "+error.localizedDescription+"\n").utf8));exit(1)}
 }
}
'''


def source():
    unified = (APP / 'IOSUnifiedProductView.swift').read_text()
    shipping = '\n'.join(STARTUP.member(unified, signature) for signature in (
        'var unifiedSelectedProfile:', 'var unifiedQuickKillSwitch:', 'func setUnifiedQuickKillSwitch('))
    boundaries = STARTUP.source().split('@MainActor @main struct Tests {', 1)[0]
    builders = '\n'.join(STARTUP.member(STARTUP.TESTS, signature) for signature in (
        'static func encoded(', 'static func profile(', 'static func bundle(', 'static func model(', 'static func attachEntry('))
    return boundaries + '\n@MainActor extension RouterVPNModel {\n' + shipping + '\n}\n' + TESTS.replace('// FIXTURE_BUILDERS', builders)


def test(negative=True):
    shipping = source()
    with tempfile.TemporaryDirectory(prefix='routervpn-ios-quick-protection-') as temporary:
        root = Path(temporary)
        STARTUP.run_fixture(root / 'shipping', shipping)
        if negative:
            for name, before, after, expected in (
                ('router-only', 'selected.normalizedNodeKind == "router-vpn" || selectedExternalSupportedOnIOS', 'selected.normalizedNodeKind == "router-vpn"', 'quick kill switch changes only the exact selected node'),
                ('active-mutation', 'guard !profileMutationBlocked else { message = "Disconnect or let the active VPN transition finish before changing persistent kill-switch policy."; return }', 'guard true else { return }', 'quick protection rejects invalid or active mutation connected'),
                ('missing-native-flag', 'current.routerProfiles[index].killSwitch = enabled', 'current.routerProfiles[index].killSwitch = false', 'quick kill switch changes only the exact selected node'),
                ('route-lockdown-lost', 'proto.includeAllNetworks = strict\n            proto.enforceRoutes = strict', 'proto.includeAllNetworks = false\n            proto.enforceRoutes = false', 'saved external protection reaches native Connect'),
            ):
                if shipping.count(before) != 1:
                    raise AssertionError('Mutation anchor drifted: ' + name)
                STARTUP.run_fixture(root / name, shipping.replace(before, after, 1), expected)
                print('Rejected quick-protection defect mutation: ' + name, flush=True)
    print('iOS quick-protection gate PASS; physical leak/permission acceptance remains separate', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shipping-only', action='store_true')
    test(negative=not parser.parse_args().shipping_only)
