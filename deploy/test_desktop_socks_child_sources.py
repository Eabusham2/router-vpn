#!/usr/bin/env python3
"""Exercise original child projection guards without running native code."""
from pathlib import Path
import importlib.util
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result

PREP = module("desktop_socks_child_source_preparer", ROOT/"deploy/prepare-desktop-external.py")
HEARTBEAT = module("desktop_socks_child_original_heartbeat", ROOT/"deploy/test_node_heartbeat_context.py")
NETWORK = {
    "node_chain_socks_physical_"+target+".go.tmpl": "routervpn/desktoppt/node_chain_socks_physical_"+target+".go"
    for target in ("linux", "windows", "darwin", "other")
}
BOX = {
    "node_chain_socks_box_physical.go.tmpl": "routervpn_desktop_node_chain_socks_box_physical.go",
    "node_chain_socks_box_physical_test.go.tmpl": "routervpn_desktop_node_chain_socks_box_physical_test.go",
    "node_chain_socks_box_linux.go.tmpl": "routervpn_desktop_node_chain_socks_box_linux.go",
    "node_chain_socks_box_darwin.go.tmpl": "routervpn_desktop_node_chain_socks_box_darwin.go",
}

class DesktopSOCKSChildProjection(unittest.TestCase):
    def test_actual_original_preparer_copies_every_native_adapter(self):
        copies = PREP.pt_copies()
        for name, target in {**NETWORK, **BOX}.items():
            with self.subTest(name=name):
                if name in NETWORK:
                    self.assertEqual(PREP.PT_TEMPLATES.count(name), 1)
                else:
                    self.assertEqual(PREP.BOX_TEMPLATES.get(name), target)
                self.assertEqual(copies[target], (ROOT/"mobile/desktop"/name).read_bytes())
        self.assertEqual(len(set({**NETWORK, **BOX}.values())), 8)

    def test_actual_preparer_refuses_changed_platform_package(self):
        original = Path.read_bytes
        for name in (*NETWORK, "node_chain_socks_box_linux.go.tmpl", "node_chain_socks_box_darwin.go.tmpl"):
            target = ROOT/"mobile/desktop"/name
            for fault in ("platform", "package"):
                with self.subTest(name=name, fault=fault):
                    before = original(target)
                    changed = before.replace(b"//go:build ", b"//go:build !", 1) if fault == "platform" else before.replace(b"package ", b"package changed_", 1)
                    self.assertNotEqual(changed, before)
                    def read(path):
                        return changed if path == target else original(path)
                    with mock.patch.object(Path, "read_bytes", read):
                        with self.assertRaisesRegex(ValueError, "package boundary changed"):
                            PREP.pt_copies()

    def test_command_enumeration_retains_separate_packages(self):
        excluded = set(PREP.PT_TEMPLATES) | set(PREP.BOX_TEMPLATES) | set(PREP.PEER_TEMPLATES)
        selected = [p for p in sorted((ROOT/"mobile/desktop").glob("node_chain_socks*.go.tmpl")) if p.name not in excluded]
        expected = {
            "node_chain_socks_command.go.tmpl", "node_chain_socks_command_test.go.tmpl",
            "node_chain_socks_command_darwin_native_test.go.tmpl",
            "node_chain_socks_construction.go.tmpl", "node_chain_socks_construction_test.go.tmpl",
            "node_chain_socks_runtime.go.tmpl", "node_chain_socks_runtime_test.go.tmpl",
            "node_chain_socks_mtu.go.tmpl", "node_chain_socks_measurement.go.tmpl",
            "node_chain_socks_control_linux.go.tmpl", "node_chain_socks_control_darwin.go.tmpl",
            "node_chain_socks_control_other.go.tmpl", "node_chain_socks_retirement_darwin.go.tmpl",
            "node_chain_socks_run_darwin.go.tmpl", "node_chain_socks_run_nonlinux.go.tmpl",
        }
        self.assertEqual({p.name for p in selected}, expected)
        for path in selected:
            self.assertIn(b"\npackage main\n", b"\n"+path.read_bytes())
        for name in NETWORK:
            self.assertIn(name, excluded)
        for name in BOX:
            self.assertIn(name, excluded)

    def test_original_heartbeat_extracts_complete_shipping_body(self):
        source = (ROOT/"mobile/desktop/mtu_node.go.tmpl").read_text()
        signatures = (
            "func routerVPNRunNodeMTULoop(", "func routerVPNRunNodeMTULoopWithChain(",
            "func routerVPNRunNodeMTULoopWithOwners(", "func routerVPNRunNodeMTULoopWithPrefix(",
            "func routerVPNRunNodeMTULoopWithComplete(",
        )
        extracted = "\n".join(HEARTBEAT.function(source, signature) for signature in signatures)
        self.assertEqual(extracted.count("heartbeatContext, stopHeartbeat := context.WithTimeout(observe, 2*time.Second)"), 1)
        self.assertEqual(extracted.count("next.NetworkReceipt, err = owner.DesktopNetworkReceiptContext(heartbeatContext)"), 1)
        fixture = (ROOT/"deploy/test_node_heartbeat_context.py").read_text()
        self.assertIn("'func routerVPNRunNodeMTULoopWithComplete('", fixture)
        self.assertIn("source.index('type routerVPNNodeMTUComplete interface {')", fixture)
        self.assertNotIn("type routerVPNDesktopSOCKSRuntime", HEARTBEAT.FIXTURE)

if __name__ == "__main__":
    unittest.main()
