#!/usr/bin/env python3
"""Check that tested native performance policy is consumed by shipping owners."""
from pathlib import Path
import importlib.util
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('performance_prepare',ROOT/'deploy/prepare-mobile-multihop.py')
PREPARE=importlib.util.module_from_spec(spec);spec.loader.exec_module(PREPARE)
class Shipping(unittest.TestCase):
    def test_shared_policy_is_built_byte_exactly(self):
        with tempfile.TemporaryDirectory() as tmp:
            vendor=Path(tmp);(vendor/'go.mod').write_text('module github.com/sagernet/sing-box\n')
            with mock.patch.object(PREPARE.WHITENING,'prepare'),mock.patch.object(PREPARE.AMNEZIA,'prepare'),mock.patch.object(PREPARE.PERFORMANCE,'prepare'):
                PREPARE.prepare(vendor)
            for source in (ROOT/'internal/mobileperf').glob('*.go'):
                self.assertEqual(source.read_bytes(),(vendor/'experimental/libbox/routervpn/mobileperf'/source.name).read_bytes())
        expected=[ROOT/'deploy/prepare-mobile-performance.py',*sorted((ROOT/'mobile/performance').glob('*.tmpl'))]
        for path in expected:self.assertIn(path,PREPARE.inputs())
    def test_mobile_sdk_builds_run_real_worker_and_graph_tests(self):
        for path,capital in [('android/build-sing-box-libbox.sh','router'),('ios/RouterVPN/prepare-libbox.sh','LibboxRouter')]:
            text=(ROOT/path).read_text()
            self.assertIn('TestRouter(Multihop|NativeWireGuard|NativeAmnezia|NativePerformance)',text)
            self.assertIn('./service/routervpnperformance ./experimental/libbox/routervpn/mobileperf',text)
            for suffix in ['ApplyPerformancePolicy','StartPerformance','PerformanceFailure','InvalidatePerformance','PerformanceStatus']:
                self.assertIn(capital+suffix,text)
            line=next(line for line in text.splitlines() if 'TestRouter(Multihop|NativeWireGuard|NativeAmnezia|NativePerformance)' in line)
            self.assertIn('with_quic',line)
        tests=(ROOT/'mobile/performance/service_test.go.tmpl').read_text()
        for marker in ['TestNativePerformanceNoIOUntilExplicitActivation','TestNativePerformanceStopsOnReplacementAndNetworkChange','TestNativePerformanceCannotUsePlaintextOrWrongNode','TestNativePerformanceDestinationCannotBeReplaced']:
            self.assertIn(marker,tests)
    def test_android_stages_final_policy_after_mtu_and_lan(self):
        source=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopController.java').read_text()
        self.assertIn('routerApplyPerformancePolicy(filtered,',source)
        self.assertIn('byte[] patched = (config.toString() + "\\n")',source)
        self.assertLess(source.index('routerApplyPerformancePolicy('),source.index('File session ='))
        single=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/NativeSingBoxController.java').read_text()
        self.assertIn('patchedConfig = applyPerformance(root, patchedConfig)',single)
        owner=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java').read_text()
        self.assertLess(owner.index('ownedExecution.run(ownedServer)'),owner.index('Libbox.routerStartPerformance(ownedServer)'))
        self.assertIn('Libbox.routerInvalidatePerformance(commandServer)',owner)
        self.assertIn('commandServer == owned && performanceActive',owner)
    def test_apple_activates_only_after_path_proof(self):
        source=(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
        multi=source[source.index('private func startMultihop('):source.index('private func multihopWireGuardEndpoint(')]
        self.assertLess(multi.index('LibboxRouterApplyMultihopLANPolicy('),multi.index('performanceFiles(finalFiles'))
        self.assertLess(multi.index('if let exitError'),multi.index('engine.activatePerformance()'))
        self.assertLess(multi.index('engine.activatePerformance()'),multi.index('Multihop changed during performance activation.'))
        single=source[source.index('private func startLibbox('):source.index('private func performanceFiles(')]
        self.assertLess(single.index('performanceFiles(files'),single.index('engine.start('))
        self.assertLess(single.index('if let proofError'),single.index('engine.activatePerformance()'))
        self.assertIn('self.currentPathProofGuard() === singlePathGuard',single)
        engine=(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift').read_text()
        for marker in ['LibboxRouterInvalidatePerformance(owned)','PerformanceWatch','ownershipGeneration == generation','performanceHealth = nil','paddingHealth?.cancel()']:
            self.assertIn(marker,engine)
        prefs=(ROOT/'ios/RouterVPN/App/IOSConnectionProfilesView.swift').read_text()
        for name in ['daitaEnabled','jumboTUN']:
            self.assertIn('profile.'+name+' = prefs.'+name,prefs)
if __name__=='__main__':unittest.main()
