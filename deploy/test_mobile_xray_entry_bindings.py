#!/usr/bin/env python3
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
MODES=('reality-vision','reality-pq-vision','reality-xhttp')
class XrayEntryBindings(unittest.TestCase):
    def test_mobile_entry_controls_and_profiles_retain_exact_mode(self):
        paths=('android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java',
               'android/app/src/main/java/com/eabusham/routervpn/NativeSingBoxController.java',
               'android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java',
               'ios/RouterVPN/App/IOSMultihopView.swift','ios/RouterVPN/App/IOSConnectionProfilesView.swift',
               'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift')
        for path in paths:
            source=(ROOT/path).read_text()
            for mode in MODES:self.assertIn('"'+mode+'"',source,path)
        java=(ROOT/paths[2]).read_text().split('private static String normalizeMultiMode',1)[1].split('\n',1)[0]
        self.assertNotIn('reality-',java,'entry implementation must not advertise unfinished Xray exits')
    def test_real_shared_compiler_and_two_node_proofs_remain_bound(self):
        java=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopController.java').read_text()
        swift=(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
        self.assertIn('Libbox.routerCompileProxyEntry(',java)
        self.assertIn('LibboxRouterCompileProxyEntry(',swift)
        self.assertIn('"entry_mode"',java);self.assertIn('"entry_mode"',swift)
        self.assertIn('entrySnapshot.equals(loadBundle(entryBundle).toString())',java)
        self.assertIn('exitSnapshot.equals(loadBundle(exitBundle).toString())',java)
        self.assertIn('expectedNodeID: entryProofID',swift);self.assertIn('expectedNodeID: exitProofID',swift)
    def test_native_parser_reads_expanded_generated_matrix(self):
        gate=(ROOT/'deploy/test_android_multihop_pinned.py').read_text()
        native=(ROOT/'mobile/routervpn_multihop_native_test.go.tmpl').read_text()
        for mode in MODES:self.assertIn(mode,gate);self.assertIn(mode,native)
        self.assertIn('checks != 150',native)
        self.assertIn('unimplemented-fixture-transport',native)
        apple=(ROOT/'deploy/test_ios_multihop_graph.py').read_text()
        self.assertIn('./deploy/testfixtures/xray-entry',apple)
        self.assertIn('proxy-'+ '"+entryMode',apple)
if __name__=='__main__':unittest.main()
