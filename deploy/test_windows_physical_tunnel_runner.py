#!/usr/bin/env python3
"""Reject changed Wintun dependencies and unowned executable-test overlays."""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
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


class PinnedWintunModuleAuthority(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="windows-tunnel-module-pin-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.git("init", "-q")
        self.original = {
            "go.mod": b"module fixture\n\ngo 1.26.3\n\nrequire github.com/sagernet/sing-tun v0.9.3\n",
            "go.sum": b"github.com/sagernet/sing-tun v0.9.3 h1:fCXbGezGMUXi00X0MmG3iX5QR91sPApZwzfr0MAVHv4=\n",
        }
        for name, raw in self.original.items():
            (self.root / name).write_bytes(raw)
        self.git("add", "go.mod", "go.sum")
        self.git("commit", "-q", "-m", "Pinned reference modules")
        self.pin = self.git("rev-parse", "HEAD").strip()
        (self.root / "go.mod").write_bytes(self.original["go.mod"] +
                                            b"\nreplace github.com/sagernet/sing-tun => ./routervpn-desktop-tun\n")
        # Actual post-preparation tidy no longer needs the original checksum.
        (self.root / "go.sum").write_bytes(b"unrelated.example/dependency v1.0.0 h1:retained\n")
        self.prepared = {name: (self.root / name).read_bytes() for name in self.original}

    def git(self, *args):
        completed = subprocess.run(
            ["git", "-c", "core.autocrlf=false", "-c", "core.hooksPath=",
             "-c", "commit.gpgsign=false", "-c", "user.name=Router VPN fixture",
             "-c", "user.email=fixture@invalid", "-C", str(self.root), *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
        return completed.stdout.decode("utf-8")

    @staticmethod
    def actual_run(command, *, cwd, env, timeout):
        completed = subprocess.run([str(value) for value in command], cwd=cwd, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return completed.returncode, completed.stdout.decode("utf-8", errors="replace")

    def read(self, pin):
        with patch.object(GATE.BOOT.PREP, "PIN", pin), patch.object(GATE.IDENTITY, "run", self.actual_run):
            return GATE.pinned_reference_modules(self.root, dict(os.environ))

    def assert_subject_unchanged(self):
        self.assertEqual({name: (self.root / name).read_bytes() for name in self.original}, self.prepared)

    def test_post_tidy_graph_uses_original_pinned_modules_without_repair(self):
        self.assertEqual(self.read(self.pin), self.original)
        self.assert_subject_unchanged()

    def test_git_replacement_object_cannot_substitute_checksum_authority(self):
        self.git("add", "go.mod", "go.sum")
        self.git("commit", "-q", "-m", "Prepared graph without original checksum")
        replacement = self.git("rev-parse", "HEAD").strip()
        self.git("replace", self.pin, replacement)
        self.assertNotEqual(self.git("show", self.pin + ":go.sum").encode(), self.original["go.sum"])
        self.assertEqual(self.read(self.pin), self.original)
        self.assert_subject_unchanged()

    def test_missing_pin_fails_without_using_prepared_or_downloaded_checksums(self):
        with self.assertRaisesRegex(ValueError, "Pinned Wintun reference module read failed"):
            self.read("0" * 40)
        self.assert_subject_unchanged()


class FailedSessionOverlayBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="windows-session-overlay-")
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "source"
        self.workspace = Path(self.temp.name) / "overlay"
        self.workspace.mkdir()
        self.native = self.source / GATE.SESSION_NATIVE
        self.native.parent.mkdir(parents=True)
        self.raw = ('package tun\nfunc fixture() {\n'
                    '\tsession, err := adapter.StartSession(0x800000)\n'
                    '\tif err != nil {\n\t\t_ = adapter.Close()\n\t\treturn nil, err\n\t}\n}\n')
        self.native.write_text(self.raw)

    def test_failure_overlay_changes_only_the_real_session_call_and_observes_its_owned_close(self):
        before = GATE.tree(self.source)
        record = json.loads(GATE.session_failure_overlay(self.source, self.workspace).read_text())["Replace"]
        self.assertEqual(set(record), {str(self.source / GATE.SESSION_TARGET), str(self.native)})
        self.assertEqual(Path(record[str(self.source / GATE.SESSION_TARGET)]).read_bytes(), GATE.SESSION_RESOURCE.read_bytes())
        expected = self.raw.replace('adapter.StartSession(0x800000)', 'routervpnWintunInvalidSession(adapter, 0x800000)').replace(
            '_ = adapter.Close()', '_ = routervpnWintunObservedFailureClose(adapter)')
        self.assertEqual(Path(record[str(self.native)]).read_text(), expected)
        self.assertEqual(GATE.tree(self.source), before)
        missing = self.workspace / "missing"
        missing.mkdir()
        record = json.loads(GATE.session_failure_overlay(self.source, missing, missing_close=True).read_text())["Replace"]
        self.assertEqual(Path(record[str(self.native)]).read_text(), expected.replace('\t\t_ = routervpnWintunObservedFailureClose(adapter)\n', ''))
        self.assertEqual(GATE.tree(self.source), before)

    def test_changed_cleanup_or_session_boundary_is_rejected(self):
        for removed in ('adapter.StartSession(0x800000)', '_ = adapter.Close()'):
            self.native.write_text(self.raw.replace(removed, 'unprovedOwner()'))
            with self.assertRaises(ValueError):
                GATE.session_failure_overlay(self.source, self.workspace)

    def test_foreign_fixture_and_shipping_package_injection_are_rejected(self):
        target = self.source / GATE.SESSION_TARGET
        target.write_text('unowned fixture')
        with self.assertRaisesRegex(ValueError, 'Unowned failed-session'):
            GATE.session_failure_overlay(self.source, self.workspace)
        self.assertEqual(target.read_text(), 'unowned fixture')
        target.unlink()
        unsafe = self.workspace / 'unsafe.go'
        unsafe.write_bytes(GATE.SESSION_RESOURCE.read_bytes().replace(b'windows && routervpn_windows_physical_composition', b'windows'))
        with patch.object(GATE, 'SESSION_RESOURCE', unsafe), self.assertRaisesRegex(ValueError, 'test-only package'):
            GATE.session_failure_overlay(self.source, self.workspace)


if __name__ == "__main__":
    unittest.main()
