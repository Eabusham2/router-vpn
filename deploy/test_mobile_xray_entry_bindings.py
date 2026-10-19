#!/usr/bin/env python3
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
MODES=('reality-vision','reality-pq-vision','reality-xhttp')
COMPOSITE_MODES=('ss-v2ray','split','max')
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
        for mode in MODES:self.assertIn('"'+mode+'"',java)
        for mode in COMPOSITE_MODES:self.assertIn('"'+mode+'"',java,'implemented two-lane modes must survive saved exit restoration')
        profiles=(ROOT/paths[2]).read_text()
        entry=profiles.split('private static String normalizeEntryMode',1)[1].split('private static String normalizeExecution',1)[0]
        for mode in COMPOSITE_MODES:self.assertIn('"'+mode+'"',entry)
        self.assertIn('Unknown saved entry transport.',entry)
        self.assertIn('throw new IllegalArgumentException',java)
        self.assertIn('.putString(MULTI_MODE,multiMode)',profiles)
        self.assertIn('.putString("multihop_entry_mode",entryMode)',profiles)
    def test_composite_modes_use_complete_captured_compilation(self):
        java=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopController.java').read_text()
        compiler=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/AndroidNativeCompositeProfile.java').read_text()
        self.assertIn('AndroidNativeCompositeProfile.compile(entry, requiredProfile(entry, entryMode), entryMode)',java)
        self.assertIn('AndroidNativeCompositeProfile.compile(exit, requiredProfile(exit, exitMode), exitMode)',java)
        self.assertIn('Libbox.routerComposeCompositeMultihop(config.toString(), metadata.toString(), entryComposite, exitComposite)',java)
        self.assertIn('Libbox.routerCompileCompositeProfile(mode, captured, metadata.toString(), start)',compiler)
        self.assertIn('!node.equals(selected.getString("node_proof_id"))',compiler)
        self.assertIn('!mode.equals(owner.getString("mode"))',compiler)
        self.assertIn('!node.equals(owner.getString("node_id"))',compiler)
        host=(ROOT/'android/test_android_composite_multihop.py').read_text()
        for required in ('graph relabeled a captured mode','composite replaced encryption',
                         'missing independent network lane','invalid composite was staged',
                         'rejection changed stored node assets','check(graphs==837',
                         'b.put("selectedRouterID","missing")','b->profile(b).put("start_layer","xor")'):
            self.assertIn(required,host)
        runtime=(ROOT/'android/test_android_runtime_contract.py').read_text()
        self.assertIn('"test_android_composite_multihop.py"',runtime)
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
