#!/usr/bin/env python3
"""Check the native Node test overlay cannot lose its executable-only scope."""
from pathlib import Path
import importlib.util
import json
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("windows_node_kernel_gate", ROOT / "deploy/test_windows_node_physical.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class NativeNodeScope(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="windows-node-overlay-")
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        self.source = self.workspace / "core"
        self.observer = self.workspace / "overlay"
        self.observer.mkdir()
        self.files = {
            "routervpn/mobiletor/desktop_socket_windows_policy.go": ROOT / "internal/mobiletor/desktop_socket_windows_policy.go",
            "routervpn/mobiletor/desktop_socket_windows_transfer.go": ROOT / "internal/mobiletor/desktop_socket_windows_transfer.go",
            "routervpn/desktoppt/node_physical_windows.go": ROOT / "mobile/desktop/node_physical_windows.go.tmpl",
            "routervpn/desktoppt/node_physical.go": ROOT / "mobile/desktop/node_physical.go.tmpl",
        }
        self.original = {}
        for relative, actual in self.files.items():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            self.original[relative] = actual.read_bytes()
            path.write_bytes(self.original[relative])

    def test_both_actual_constructors_are_scoped_without_changing_shipping_files(self):
        path = GATE.overlay(self.source, self.observer)
        mapping = json.loads(path.read_text())["Replace"]
        self.assertEqual(len(mapping), 3)
        old = Path(mapping[str(self.source / "routervpn/mobiletor/desktop_socket_windows_policy.go")]).read_text()
        new = Path(mapping[str(self.source / "routervpn/mobiletor/desktop_socket_windows_transfer.go")]).read_text()
        self.assertIn("return desktopWindowsNodeCompositionConstruct(ctx, capture, options, nil, false)", old)
        self.assertIn("return desktopWindowsNodeCompositionConstruct(ctx, capture, options, predecessor, true)", new)
        for relative, raw in self.original.items():
            self.assertEqual((self.source / relative).read_bytes(), raw)
        self.assertFalse((self.source / "routervpn/mobiletor/desktop_socket_windows_node_composition_overlay.go").exists())

    def test_unknown_constructor_source_is_rejected_before_compilation(self):
        for relative, raw in self.original.items():
            if "mobiletor" not in relative:
                continue
            with self.subTest(relative=relative):
                path = self.source / relative
                changed = raw.replace(b"options, nil)", b"options, untrustedScope)") if "policy.go" in relative else raw.replace(b"predecessor, nil)", b"predecessor, untrustedScope)")
                self.assertNotEqual(changed, raw)
                path.write_bytes(changed)
                with self.assertRaisesRegex(ValueError, "exact production boundary"):
                    GATE.overlay(self.source, self.observer)
                path.write_bytes(raw)

    def test_existing_observer_is_never_overwritten_or_adopted(self):
        path = self.source / "routervpn/mobiletor/desktop_socket_windows_node_composition_overlay.go"
        path.write_bytes(b"package mobiletor\n// another owner\n")
        with self.assertRaisesRegex(ValueError, "Unowned Windows Node observer"):
            GATE.overlay(self.source, self.observer)
        self.assertEqual(path.read_bytes(), b"package mobiletor\n// another owner\n")

    def test_every_mutation_keeps_both_real_firewall_constructors_scoped(self):
        for mutation in GATE.mutants(self.source):
            with self.subTest(name=mutation[0]):
                selected = GATE.overlay(self.source, self.observer, mutation)
                mapping = json.loads(selected.read_text())["Replace"]
                self.assertEqual(len(mapping), 4)
                self.assertIn("nil, false)", Path(mapping[str(self.source / "routervpn/mobiletor/desktop_socket_windows_policy.go")]).read_text())
                self.assertIn("predecessor, true)", Path(mapping[str(self.source / "routervpn/mobiletor/desktop_socket_windows_transfer.go")]).read_text())
        forbidden = ("scope-mutation", "routervpn/mobiletor/desktop_socket_windows_policy.go", "test", "witness", "package mobiletor\n")
        with self.assertRaisesRegex(ValueError, "overlaps native scope ownership"):
            GATE.overlay(self.source, self.observer, forbidden)

    def test_observer_cannot_drop_its_compile_time_tag(self):
        fixtures = self.workspace / "fixtures"
        fixtures.mkdir()
        (fixtures / "kernel_observer.go").write_bytes(b"package mobiletor\n")
        with patch.object(GATE, "RESOURCES", fixtures), patch.object(GATE.NODE, "checked_sources", return_value=(self.source, {})):
            with self.assertRaisesRegex(ValueError, "explicit native test scope"):
                GATE.checked_sources(self.source)


if __name__ == "__main__":
    unittest.main()
