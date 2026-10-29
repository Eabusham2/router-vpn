#!/usr/bin/env python3
"""Reject changed Wintun dependencies and unowned executable-test overlays."""
from pathlib import Path
import importlib.util
import json
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("windows_tunnel_runner_test", ROOT / "deploy/test_windows_physical_tunnel.py")
GATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)


class ActualWintunSourceBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="windows-tunnel-source-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.expected, self.subject = self.root / "reference", self.root / "subject"
        self.files = {
            "tun_windows.go": b"package tun\n// exact shipping transformation\n",
            "internal/wintun/amd64/wintun.dll": b"exact checksum-pinned AMD64 native bytes",
            "internal/wintun/arm64/wintun.dll": b"exact checksum-pinned ARM64 native bytes",
        }
        for directory in (self.expected, self.subject):
            for name, raw in self.files.items():
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)

    def test_exact_dependency_and_both_embedded_drivers_are_read_only(self):
        before = GATE.tree(self.subject)
        self.assertEqual(GATE.compare_tun_source(self.expected, self.subject), before)
        self.assertEqual(set(before), set(self.files))
        self.assertTrue(all("\\" not in key for key in before))
        self.assertEqual(GATE.tree(self.subject), before)

    def test_changed_driver_and_native_source_are_rejected_without_repair(self):
        for name in self.files:
            with self.subTest(name=name):
                path = self.subject / name
                path.write_bytes(self.files[name] + b"changed")
                with self.assertRaisesRegex(ValueError, "differs from its checksum-pinned"):
                    GATE.compare_tun_source(self.expected, self.subject)
                self.assertEqual(path.read_bytes(), self.files[name] + b"changed")
                path.write_bytes(self.files[name])

    def test_missing_or_added_compiled_source_is_rejected(self):
        target = self.subject / "tun_windows.go"
        target.unlink()
        with self.assertRaisesRegex(ValueError, "differs from its checksum-pinned"):
            GATE.compare_tun_source(self.expected, self.subject)
        target.write_bytes(self.files["tun_windows.go"])
        (self.subject / "unowned_windows.go").write_text("package tun\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "differs from its checksum-pinned"):
            GATE.compare_tun_source(self.expected, self.subject)

    def test_overlay_has_no_production_or_os_admission_replacement(self):
        workspace = self.root / "overlay"
        workspace.mkdir()
        before = GATE.RESOURCE.read_bytes()
        record = json.loads(GATE.overlay(self.subject, workspace).read_text())["Replace"]
        self.assertEqual(set(record), {str(self.subject / GATE.TARGET)})
        self.assertEqual(Path(next(iter(record.values()))).read_bytes(), before)
        self.assertFalse((self.subject / GATE.TARGET).exists())
        self.assertEqual(GATE.RESOURCE.read_bytes(), before)

    def test_overlay_preserves_foreign_target_and_requires_test_only_tag(self):
        workspace = self.root / "overlay"
        workspace.mkdir()
        target = self.subject / GATE.TARGET
        target.parent.mkdir(parents=True)
        target.write_bytes(b"foreign test file\n")
        with self.assertRaisesRegex(ValueError, "Unowned actual-Wintun"):
            GATE.overlay(self.subject, workspace)
        self.assertEqual(target.read_bytes(), b"foreign test file\n")
        target.unlink()
        fixture = self.root / "unsafe.go"
        fixture.write_bytes(GATE.RESOURCE.read_bytes().replace(b"windows && routervpn_windows_physical_composition", b"windows"))
        with patch.object(GATE, "RESOURCE", fixture), self.assertRaisesRegex(ValueError, "compile-time test tag"):
            GATE.overlay(self.subject, workspace)

    def test_three_negative_controls_patch_distinct_shipping_protections(self):
        source = (ROOT / "internal/mobiletor/desktop_socket_windows_tunnel.go").read_text(encoding="utf-8")
        variants = GATE.mutants(source)
        self.assertEqual({name for name, _, _ in variants}, {"physical-interface", "retained-luid", "stale-reader"})
        self.assertEqual(len({changed for _, _, changed in variants}), 3)
        for _, marker, changed in variants:
            self.assertNotEqual(changed, source)
            self.assertIn(marker, GATE.RESOURCE.read_text(encoding="utf-8"))
        with self.assertRaises(ValueError):
            GATE.mutants(source.replace("desktopWFPNumber(desktopWFPInterface, 4, luid)", "alteredProduction()"))


if __name__ == "__main__":
    unittest.main()
