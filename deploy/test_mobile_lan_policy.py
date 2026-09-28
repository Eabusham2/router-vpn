#!/usr/bin/env python3
"""Execute actual Apple exclusion expressions and verify both native LAN owners."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
class Tests(unittest.TestCase):
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
        appExpr=re.search(r'proto\.excludeLocalNetworks = ([^\n]+)',app).group(1)
        externalExpr=re.search(r'proto\.excludeLocalNetworks = ([^\n]+)',external).group(1)
        provider=(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
        preflight=re.search(r'guard (\(provider\["engine"\].+?) else \{ throw tunnelError\(5,',provider).group(1)
        source='''import Foundation
struct TunnelProtocol { var excludeLocalNetworks: Bool }
func preflight(_ engine: String, _ allowLAN: Bool, _ exclusion: Bool) -> Bool {
    let provider: [String: Any] = ["engine":engine]
    let tunnelProtocol = TunnelProtocol(excludeLocalNetworks:exclusion)
    return PREFLIGHT
}

struct Profile {var homeLANAccess: Bool?}
func regular(_ strict: Bool, _ homeLANAccess: Bool, _ entryAllowsLAN: Bool) -> Bool { APP }
func external(_ strict: Bool, _ profile: Profile) -> Bool { EXTERNAL }
var checks=0
for strict in [false,true] { for home in [false,true] { for entry in [false,true] {
    precondition(regular(strict,home,entry) == (strict && home && entry)); checks += 1
    if !home || !entry { precondition(!regular(strict,home,entry));checks += 1 }
} } }
for strict in [false,true] {for home: Bool? in [nil,false,true] {
    precondition(external(strict,Profile(homeLANAccess:home)) == (strict && (home ?? true)));checks += 1
}}
for home in [false,true] { for exclusion in [false,true] {
    precondition(preflight("multihop-libbox",home,exclusion));checks += 1
    precondition(preflight("libbox",home,exclusion) == (home == exclusion));checks += 1
    precondition(preflight("wireguard",home,exclusion) == (home == exclusion));checks += 1
    precondition(preflight("multihop",home,exclusion) == (home == exclusion));checks += 1
} }
print("Shipping Apple LAN exclusion: PASS (\\(checks) checks)")
'''.replace('APP',appExpr).replace('EXTERNAL',externalExpr).replace('PREFLIGHT',preflight)
        with tempfile.TemporaryDirectory(prefix='routervpn-lan-exclusion-') as tmp:
            tmp=Path(tmp);file=tmp/'main.swift';binary=tmp/'test';file.write_text(source)
            subprocess.run([swift,'-swift-version','6',str(file),'-o',str(binary)],check=True,timeout=60)
            subprocess.run([str(binary)],check=True,timeout=10)
        self.assertNotIn('excludeLocalNetworks == !allowLAN',(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text())
if __name__=='__main__':unittest.main()
