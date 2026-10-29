#!/usr/bin/env python3
"""Check exact Windows identity source preparation without native side effects."""
from pathlib import Path
import hashlib
import importlib.util
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "windows_identity_runner_gate", ROOT / "deploy/test_desktop_windows_identity.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class WindowsIdentitySourceCopies(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="windows-identity-copy-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repository"
        self.sources = self.root / "internal/mobiletor"
        self.sources.mkdir(parents=True)
        self.vendor = Path(self.temp.name) / "native"
        self.target = self.vendor / "routervpn/mobiletor"
        self.target.mkdir(parents=True)
        for path in (ROOT / "internal/mobiletor").glob("desktop_socket_*.go"):
            (self.sources / path.name).write_bytes(path.read_bytes())
        # A source-copy boundary fixture exercises both actual preparer maps,
        # including when the platform-specific importer is absent at this SHA.
        # No native execution result is synthesized by these Python tests.
        self.boundary = self.sources / "desktop_socket_import_boundary.go"
        self.boundary.write_bytes(
            b'package mobiletor\nimport (\n'
            b'_ "router-vpn/internal/common"\n'
            b'_ "router-vpn/internal/mobilemtu"\n)\n'
            b'// Unrelated bytes and spelling stay exact.\n')
        for path in self.sources.glob("desktop_socket_*.go"):
            (self.target / path.name).write_bytes(GATE.PREP.relocated_shared_source(path.read_bytes()))
        self.addCleanup(patch.stopall)
        patch.object(GATE, "ROOT", self.root).start()
        patch.object(GATE.PREP, "checked_vendor", side_effect=lambda source: Path(source).resolve()).start()

    def test_repository_source_uses_unchanged_bytes_and_no_native_relocation(self):
        with patch.object(GATE.PREP, "checked_vendor", side_effect=AssertionError("root source was relocated")):
            source, target, package, records = GATE.checked_sources(self.root)
        self.assertEqual((source, target, package), (self.root, self.sources, "./internal/mobiletor"))
        self.assertEqual(records[self.boundary.name], hashlib.sha256(self.boundary.read_bytes()).hexdigest())
        self.assertIn(b'"router-vpn/internal/common"', self.boundary.read_bytes())

    def test_prepared_copy_accepts_only_both_declared_module_relocations(self):
        source, target, package, records = GATE.checked_sources(self.vendor)
        self.assertEqual((source, target, package), (self.vendor, self.target, "./routervpn/mobiletor"))
        raw = (self.target / self.boundary.name).read_bytes()
        self.assertIn(b'"github.com/sagernet/sing-box/routervpn/common"', raw)
        self.assertIn(b'"github.com/sagernet/sing-box/experimental/libbox/routervpn/mobilemtu"', raw)
        self.assertEqual(records[self.boundary.name], hashlib.sha256(self.boundary.read_bytes()).hexdigest())

    def test_unrelocated_imports_never_acknowledge_the_prepared_copy(self):
        target = self.target / self.boundary.name
        target.write_bytes(self.boundary.read_bytes())
        with self.assertRaisesRegex(ValueError, "differs from shipping source"):
            GATE.checked_sources(self.vendor)

    def test_wrong_imports_and_unrelated_byte_changes_are_rejected(self):
        target = self.target / self.boundary.name
        expected = target.read_bytes()
        for replacement in (
                expected.replace(b'"github.com/sagernet/sing-box/routervpn/common"', b'"unrelated.example/borrowed/common"'),
                expected.replace(b'"github.com/sagernet/sing-box/experimental/libbox/routervpn/mobilemtu"', b'"github.com/sagernet/sing-box/routervpn/mobilemtu"'),
                expected + b"// modified prepared source\n"):
            with self.subTest(replacement=replacement):
                target.write_bytes(replacement)
                with self.assertRaisesRegex(ValueError, "differs from shipping source"):
                    GATE.checked_sources(self.vendor)
        target.write_bytes(expected)
        GATE.checked_sources(self.vendor)

    def test_changed_shipping_source_cannot_reuse_an_older_prepared_file(self):
        self.boundary.write_bytes(self.boundary.read_bytes() + b"// new source\n")
        with self.assertRaisesRegex(ValueError, "differs from shipping source"):
            GATE.checked_sources(self.vendor)

    def test_connect_lifecycle_source_is_a_required_gate_input(self):
        (self.sources / GATE.CONNECT).unlink()
        with self.assertRaisesRegex(ValueError, "source/test closure is incomplete"):
            GATE.checked_sources(self.vendor)


if __name__ == "__main__":
    unittest.main()
