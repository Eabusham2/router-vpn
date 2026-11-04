#!/usr/bin/env python3
"""Check exact Windows identity source preparation without native side effects."""
from pathlib import Path
import contextlib
import hashlib
import importlib.util
import io
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
        # Match the production gate's resolved ROOT even when Windows TEMP is
        # reached through an 8.3 path alias (or a native directory junction).
        workspace = Path(self.temp.name).resolve()
        self.root = workspace / "repository"
        self.sources = self.root / "internal/mobiletor"
        self.sources.mkdir(parents=True)
        self.vendor = workspace / "native"
        self.target = self.vendor / "routervpn/mobiletor"
        self.target.mkdir(parents=True)
        for pattern in ("desktop_socket_*.go", "desktop_protection_transfer_record*.go"):
            for path in (ROOT / "internal/mobiletor").glob(pattern):
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
        for path in self.sources.glob("*.go"):
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

    def test_bound_tcp_ownership_and_both_native_controls_are_mandatory(self):
        self.assertIn("TestDesktopSocketWindowsIdentityTCPRetainsBoundDescriptor", GATE.REQUIRED)
        raw = (ROOT / "internal/mobiletor" / GATE.IMPORTED).read_text(encoding="utf-8")
        changes = GATE.import_mutants(raw)
        self.assertEqual([item[0] for item in changes],
                         ["tcp-import-duplicate", "tcp-premature-source-close"])
        for label, test, witness, changed in changes:
            self.assertEqual(test, GATE.REQUIRED[18])
            self.assertNotEqual(changed, raw)
            self.assertIn(witness, (ROOT / "internal/mobiletor/desktop_socket_windows_identity_test.go").read_text(encoding="utf-8"))
        self.assertIn("c.handle = keeper.handle", changes[0][3])
        self.assertIn("c.keeper.Close(), c.DesktopSocketNative.Close()", changes[0][3])
        self.assertIn("if false && s.ioOwner != nil {", changes[1][3])
        for changed in (raw.replace("c.handle = syscall.Handle(handle)", "c.handle = 0"),
                        raw.replace("if s.ioOwner != nil {", "if s.ioOwner == nil {")):
            with self.assertRaisesRegex(ValueError, "lost its exact production boundary"):
                GATE.import_mutants(changed)

    def test_transfer_records_are_required_exact_shipping_inputs(self):
        for name in ("desktop_protection_transfer_record.go", "desktop_protection_transfer_record_test.go"):
            with self.subTest(name=name):
                self.assertIn(name, GATE.checked_sources(self.vendor)[3])
                copied = self.target / name
                expected = copied.read_bytes()
                copied.write_bytes(expected + b"// changed private transfer contract\n")
                with self.assertRaisesRegex(ValueError, "differs from shipping source"):
                    GATE.checked_sources(self.vendor)
                copied.unlink()
                with self.assertRaisesRegex(ValueError, "actual regular copied file"):
                    GATE.checked_sources(self.vendor)
                copied.write_bytes(expected)
                original = self.sources / name
                raw = original.read_bytes()
                original.unlink()
                with self.assertRaisesRegex(ValueError, "source/test closure is incomplete"):
                    GATE.checked_sources(self.vendor)
                original.write_bytes(raw)

    def test_shipping_preparer_emits_the_complete_identity_source_closure(self):
        # Exercise the real shared-source copying loop. The hand-copied fixtures
        # above cannot detect a file omitted by the production preparer itself.
        vendor = self.vendor.parent / "shipping-prepared"
        vendor.mkdir()
        prep = GATE.PREP
        with patch.object(GATE, "ROOT", ROOT), \
             patch.object(prep, "prepare_desktop_pt"), \
             patch.object(prep.MTU, "prepare"), patch.object(prep.DESKTOP_MTU, "prepare"), \
             patch.object(prep.STRATEGY, "prepare"), patch.object(prep.EXTERNAL, "prepare"), \
             patch.object(prep, "prepare_network_startup"), \
             patch.object(prep, "prepare_node_capture"), \
             patch.object(prep.RELAY.OPENVPN_REMOTE, "prepare"), \
             contextlib.redirect_stdout(io.StringIO()):
            prep.prepare(vendor)
            source, target, package, records = GATE.checked_sources(vendor)
            self.assertEqual((source, target, package),
                             (vendor, vendor / "routervpn/mobiletor", "./routervpn/mobiletor"))
            originals = tuple(path for pattern in ("desktop_socket_*.go", "desktop_protection_transfer_record*.go")
                              for path in (ROOT / "internal/mobiletor").glob(pattern))
            self.assertEqual(records, {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                       for path in originals})
            for name, relative in prep.PEER_TEMPLATES.items():
                self.assertEqual((vendor / relative).read_bytes(),
                                 (ROOT / 'mobile/desktop' / name).read_bytes())
            for name in ("desktop_socket_pf_inventory_test.go", "desktop_socket_darwin_frame_test.go",
                         "desktop_socket_grant_admission_test.go", "desktop_socket_identity_readback_test.go"):
                with self.subTest(name=name):
                    missing = target / name
                    expected = missing.read_bytes()
                    self.assertEqual(expected, prep.relocated_shared_source(
                        (ROOT / "internal/mobiletor" / name).read_bytes()))
                    missing.unlink()
                    with self.assertRaisesRegex(ValueError, "actual regular copied file: " + name):
                        GATE.checked_sources(vendor)
                    missing.write_bytes(expected)
                    GATE.checked_sources(vendor)


class DesktopEncryptedPeerSourceCopies(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='desktop-peer-copy-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / 'repository'
        self.sources = self.root / 'mobile/desktop'
        self.sources.mkdir(parents=True)
        self.vendor = self.root.parent / 'native'
        self.prep = GATE.PREP
        for name in self.prep.PEER_TEMPLATES:
            (self.sources / name).write_bytes((ROOT / 'mobile/desktop' / name).read_bytes())
        self.patch = patch.object(self.prep, 'ROOT', self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_all_shipping_peers_retain_exact_bytes_packages_and_platforms(self):
        self.prep.copy_encrypted_peer_templates(self.vendor)
        for name, relative in self.prep.PEER_TEMPLATES.items():
            with self.subTest(name=name):
                self.assertTrue(relative.endswith('_test.go'))
                self.assertEqual((self.vendor / relative).read_bytes(), (self.sources / name).read_bytes())

    def test_wg_and_awg_changed_platform_or_package_is_rejected_before_copy(self):
        for name in ('node_wg_peer_test.go.tmpl', 'node_awg_peer_test.go.tmpl'):
            source = self.sources / name
            original = source.read_bytes()
            for modified in (
                    original.replace(b'linux && !android', b'linux'),
                    original.replace(b'linux && !android', b'windows'),
                    original.replace(b'//go:build linux && !android\n\n', b''),
                    original.replace(b'package routervpnamnezia\n', b'package main\n')):
                with self.subTest(name=name, prefix=modified.split(b'import', 1)[0]):
                    source.write_bytes(modified)
                    with self.assertRaisesRegex(ValueError, 'test-only package or platform: ' + name.removesuffix('.go.tmpl')):
                        self.prep.copy_encrypted_peer_templates(self.vendor)
                    self.assertFalse((self.vendor / self.prep.PEER_TEMPLATES[name]).exists())
            source.write_bytes(original)

    def test_wg_and_awg_source_symlink_cannot_enter_test_package(self):
        for name in ('node_wg_peer_test.go.tmpl', 'node_awg_peer_test.go.tmpl'):
            with self.subTest(name=name):
                source = self.sources / name
                other = self.sources / 'borrowed.go'
                source.rename(other)
                source.symlink_to(other)
                with self.assertRaisesRegex(ValueError, 'peer test is a symlink: ' + name.removesuffix('.go.tmpl')):
                    self.prep.copy_encrypted_peer_templates(self.vendor)
                self.assertFalse((self.vendor / self.prep.PEER_TEMPLATES[name]).exists())
                source.unlink()
                other.rename(source)


if __name__ == "__main__":
    unittest.main()
