#!/usr/bin/env python3
"""Require native compiler ownership and real traffic verification in shipping builds."""
from pathlib import Path
import importlib.util,tempfile,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('prepare',ROOT/'deploy/prepare-mobile-multihop.py')
PREPARE=importlib.util.module_from_spec(spec);spec.loader.exec_module(PREPARE)
class Shipping(unittest.TestCase):
    def test_compiler_and_bridge_are_copied_byte_exactly(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'go.mod').write_text('module github.com/sagernet/sing-box\n')
            with mock.patch.object(PREPARE.WHITENING,'prepare'):
                PREPARE.prepare(root)
            native=root/'experimental/libbox/routervpn/nativesip003'
            for source in (ROOT/'internal/nativesip003').glob('*.go'):
                self.assertEqual(source.read_bytes(),(native/source.name).read_bytes())
            self.assertEqual((ROOT/'mobile/routervpn_sip003_bridge.go.tmpl').read_bytes(),(root/'experimental/libbox/routervpn_sip003_bridge.go').read_bytes())
            self.assertEqual((ROOT/'mobile/sip003/traffic_test.go.tmpl').read_bytes(),(root/'protocol/routervpnsip003test/traffic_test.go').read_bytes())
    def test_both_native_builds_require_compiler_api_and_real_traffic(self):
        android=(ROOT/'android/build-sing-box-libbox.sh').read_text();ios=(ROOT/'ios/RouterVPN/prepare-libbox.sh').read_text()
        self.assertIn('routerCompileSIP003Profile',android);self.assertIn('LibboxRouterCompileSIP003Profile',ios)
        for text in (android,ios):
            self.assertIn('test_mobile_sip003_pinned.sh',text)
            self.assertLess(text.index('test_mobile_sip003_pinned.sh'),text.index('go_retry run ./cmd/internal/build_libbox') if 'go_retry run ./cmd/internal/build_libbox' in text else text.index('go run ./cmd/internal/build_libbox'))
    def test_android_compilation_precedes_readiness_and_follows_dns(self):
        source=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/NativeSingBoxController.java').read_text()
        listing=source[source.index('List<ModeInfo> listDirectLibboxModes'):source.index('SessionInfo prepareSession')]
        self.assertLess(listing.index('compileNativeSIP003'),listing.index('isDirectFullDeviceConfig'))
        setup=source[source.index('SessionInfo prepareSession'):source.index('private static String strictUTF8')]
        self.assertLess(setup.index('compileNativeSIP003'),setup.index('isDirectFullDeviceConfig'))
        self.assertLess(setup.index('applySelectedDns'),setup.rindex('compileNativeSIP003'))
        self.assertLess(setup.rindex('compileNativeSIP003'),setup.index('AndroidStartLayer.apply'))
        self.assertIn('Libbox.routerCompileSIP003Profile(wrapper, strictUTF8(raw))',source)
        self.assertIn('CodingErrorAction.REPORT',source)
        self.assertNotIn('ProcessBuilder',source)
    def test_protocol_proof_is_not_replaced_by_configuration_success(self):
        orchestrator=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java').read_text()
        self.assertIn('AndroidPathProbe.prove(bundle',orchestrator)
        ios=(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
        self.assertIn('LibboxRouterCompileSIP003Profile',ios)
        traffic=(ROOT/'mobile/sip003/traffic_test.go.tmpl').read_text()
        for required in ('RouterCompileSIP003Profile','CheckConfig','tcpExchange','udpExchange','wrong-key','wrong-certificate'):
            self.assertIn(required,traffic)
if __name__=='__main__':unittest.main()
