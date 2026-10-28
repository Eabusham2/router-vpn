#!/usr/bin/env python3
"""Execute actual Apple exclusion expressions and verify both native LAN owners."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]

def external_lan_boundary(provider):
    preparation=provider.split('private func prepareExternalLibbox(',1)[1].split('private func ',1)[0]
    launch=provider.split('private func startExternalLibbox(',1)[1].split('private func ',1)[0]
    intersection='tunnelProtocol.excludeLocalNetworks == ((entry["home_lan_access"] as? Bool ?? true) && (selectedProfile["home_lan_access"] as? Bool ?? true))'
    # Both Tor-entry and ordinary-entry preparation must combine the captured
    # policies before returning any graph to either Compare or direct launch.
    branches=preparation.split('} else if let entryData = provider["external_entry_bundle"] {')
    assert len(branches)==2, 'both captured entry preparation branches are required'
    for branch in branches:
        assert branch.count(intersection)==1, 'captured entry lost its LAN intersection'
        assert 'effectiveStrict = strict || strictKillSwitchRequested(entry)' in branch
        assert '!effectiveStrict || (tunnelProtocol.includeAllNetworks && tunnelProtocol.enforceRoutes &&' in branch
    capture='let prepared = try prepareExternalLibbox(provider: provider, selectedProfile: selectedProfile, strict: strict)'
    assert launch.count(capture)==1, 'external startup must prepare its exact captured policies'
    assert launch.index(capture)<launch.index('try beginTorComparison(profile: selectedProfile, entry: prepared,')
    assert launch.index(capture)<launch.index('engine.start(')
    assert 'effectiveStrict = prepared.strict' in launch
    assert launch.count('engine.start(files: files, strict: effectiveStrict')==2
    return intersection

class Tests(unittest.TestCase):
    def test_external_preparation_cannot_bypass_either_captured_policy(self):
        provider=(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
        intersection=external_lan_boundary(provider)
        prefix=provider.index('private func prepareExternalLibbox(')
        suffix=provider.index('private func startExternalLibbox(',prefix)
        for match in re.finditer(re.escape(intersection),provider[prefix:suffix]):
            position=prefix+match.start()
            broken=provider[:position]+provider[position:].replace(intersection,'true',1)
            with self.assertRaises(AssertionError):external_lan_boundary(broken)
        broken=provider.replace('let prepared = try prepareExternalLibbox(provider: provider, selectedProfile: selectedProfile, strict: strict)',
                                'let prepared = try prepareExternalLibbox(provider: provider, selectedProfile: selectedProfile, strict: false)',1)
        with self.assertRaises(AssertionError):external_lan_boundary(broken)
    def test_mobile_policy_runs_before_any_engine_start(self):
        provider=(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
        body=provider.split('private func startMultihop(',1)[1].split('private func multihopWireGuardEndpoint(',1)[0]
        self.assertLess(body.index('RouterVPNMTUPolicy.multihop('),body.index('LibboxRouterApplyMultihopLANPolicy('))
        self.assertLess(body.index('LibboxRouterApplyMultihopLANPolicy('),body.index('engine.start('))
        self.assertIn('if let failure { throw failure }',body)
        android=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopController.java').read_text()
        self.assertLess(android.index('makeMultihopConfig(config'),android.index('Libbox.routerApplyMultihopLANPolicy('))
        self.assertLess(android.index('Libbox.routerApplyMultihopLANPolicy('),android.index('File session ='))
        self.assertIn('selectedRouterProfile(entry)',android)
        self.assertIn('selectedRouterProfile(exit)',android)
        bridge=(ROOT/'mobile/routervpn_multihop_bridge.go.tmpl').read_text()
        self.assertIn('return mobilemultihop.ApplyLANPolicy(config, profiles)',bridge)
        self.assertNotIn('ProcessBuilder',android)
        self.assertIn('routerApplyPerformancePolicy(filtered,',android)
        self.assertIn('finalFiles = try performanceFiles(finalFiles',body)
    def test_native_build_checks_the_policy_graph(self):
        source=(ROOT/'mobile/routervpn_multihop_native_test.go.tmpl').read_text()
        for marker in ['RouterApplyMultihopLANPolicy(', 'CheckConfig(protected)', 'NewRouterMultihop(protected', 'CheckConfig(protectedPlan.Config())']:
            self.assertIn(marker,source)
        for path,marker in [('ios/RouterVPN/prepare-libbox.sh','LibboxRouterApplyMultihopLANPolicy'),('android/build-sing-box-libbox.sh','routerApplyMultihopLANPolicy')]:
            self.assertIn(marker,(ROOT/path).read_text())
    def test_actual_apple_exclusion_rules(self):
        swift=shutil.which('swiftc')
        if not swift:self.skipTest('Swift expressions are executed in the Apple native lane')
        app=(ROOT/'ios/RouterVPN/App/RouterVPNModel.swift').read_text()
        external=(ROOT/'ios/RouterVPN/App/RouterVPNModelExternal.swift').read_text()
        appCaptures=re.findall(r'(?m)^[ \t]*(let capturedLANExclusion = [^\n]+)\n[ \t]*(proto\.excludeLocalNetworks = [^\n]+)$',app)
        self.assertEqual(len(appCaptures),1,'one captured Apple LAN declaration and assignment must be present')
        appRule='\n'.join(appCaptures[0])
        externalExpr=re.search(r'proto\.excludeLocalNetworks = ([^\n]+)',external).group(1)
        provider=(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
        preflights=re.findall(r'guard (\(provider\["engine"\].+?) else \{ throw tunnelError\(5,',provider,re.S)
        self.assertEqual(len(preflights),1,'one owned Apple early LAN preflight must be present')
        preflight=preflights[0]
        capturedEntryCondition=' && (provider["tor_entry_bundle"] != nil || provider["external_entry_bundle"] != nil)'
        self.assertIn(capturedEntryCondition,preflight)
        external_lan_boundary(provider)
        source='''import Foundation
struct TunnelProtocol { var excludeLocalNetworks: Bool }
func preflight(_ engine: String, _ allowLAN: Bool, _ exclusion: Bool, _ capturedEntry: String?) -> Bool {
    var provider: [String: Any] = ["engine":engine]
    if let capturedEntry { provider[capturedEntry] = Data([1]) }
    let tunnelProtocol = TunnelProtocol(excludeLocalNetworks:exclusion)
    return PREFLIGHT
}

struct Profile {var homeLANAccess: Bool?}
func regular(_ strict: Bool, _ homeLANAccess: Bool, _ entryAllowsLAN: Bool) -> Bool {
    var proto = TunnelProtocol(excludeLocalNetworks:false)
    APP
    return proto.excludeLocalNetworks
}
func external(_ strict: Bool, _ profile: Profile, _ capturedEntryProfile: Profile?) -> Bool { EXTERNAL }
var checks=0
for strict in [false,true] { for home in [false,true] { for entry in [false,true] {
    precondition(regular(strict,home,entry) == (strict && home && entry)); checks += 1
    if !home || !entry { precondition(!regular(strict,home,entry));checks += 1 }
} } }
for strict in [false,true] {for home: Bool? in [nil,false,true] {
    for entry: Profile? in [nil,Profile(homeLANAccess:nil),Profile(homeLANAccess:false),Profile(homeLANAccess:true)] {
        precondition(external(strict,Profile(homeLANAccess:home),entry) == (strict && (home ?? true) && (entry?.homeLANAccess ?? true)));checks += 1
    }
}}
for home in [false,true] { for exclusion in [false,true] {
    for engine in ["multihop-libbox","libbox","wireguard","multihop","external-libbox","unknown"] {
        for capturedEntry: String? in [nil,"tor_entry_bundle","external_entry_bundle"] {
            let deferred = engine == "multihop-libbox" || (engine == "external-libbox" && capturedEntry != nil)
            precondition(preflight(engine,home,exclusion,capturedEntry) == (deferred || home == exclusion));checks += 1
        }
    }
} }
print("Shipping Apple LAN exclusion: PASS (\\(checks) checks)")
'''
        with tempfile.TemporaryDirectory(prefix='routervpn-lan-exclusion-') as tmp:
            tmp=Path(tmp)
            changes=[('shipping',preflight,appRule,externalExpr,True),
                     ('inverted-exclusion',preflight.replace('excludeLocalNetworks == allowLAN','excludeLocalNetworks != allowLAN'),appRule,externalExpr,False),
                     ('uncaptured-external-bypass',preflight.replace(capturedEntryCondition,'',1),appRule,externalExpr,False),
                     ('missing-tor-entry-capture',preflight.replace('provider["tor_entry_bundle"] != nil || ','',1),appRule,externalExpr,False),
                     ('missing-ordinary-entry-capture',preflight.replace(' || provider["external_entry_bundle"] != nil','',1),appRule,externalExpr,False),
                     ('entry-policy-bypass',preflight,appRule,externalExpr.replace(' && (capturedEntryProfile?.homeLANAccess ?? true)',''),False),
                     ('captured-entry-policy-bypass',preflight,appRule.replace(' && entryAllowsLAN',''),externalExpr,False),
                     ('captured-exclusion-inversion',preflight,appRule.replace('proto.excludeLocalNetworks = capturedLANExclusion','proto.excludeLocalNetworks = !capturedLANExclusion'),externalExpr,False)]
            for name,guard,regularRule,externalRule,accepted in changes:
                if not accepted:self.assertNotEqual((guard,regularRule,externalRule),(preflight,appRule,externalExpr),name+' mutation must change the shipping expression')
                file=tmp/(name+'.swift');binary=tmp/name
                file.write_text(source.replace('APP',regularRule).replace('EXTERNAL',externalRule).replace('PREFLIGHT',guard))
                subprocess.run([swift,'-swift-version','6',str(file),'-o',str(binary)],check=True,timeout=60)
                result=subprocess.run([str(binary)],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                if accepted:
                    self.assertEqual(result.returncode,0,result.stderr);print(result.stdout.strip())
                else:self.assertNotEqual(result.returncode,0,name+' bypass must fail the executed policy matrix')
            print('Seven compiled Apple LAN-policy negative controls rejected')
        self.assertNotIn('excludeLocalNetworks == !allowLAN',(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text())
if __name__=='__main__':unittest.main()
