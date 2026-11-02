#!/usr/bin/env python3
"""Exercise bootstrap source ownership and explicit prospective overlay bounds."""
from pathlib import Path
import contextlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("windows_bootstrap_runner_test", ROOT / "deploy/test_windows_physical_bootstrap.py")
GATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)
spec = importlib.util.spec_from_file_location("windows_external_runner_test", ROOT / "deploy/test_windows_external_physical.py")
EXTERNAL = importlib.util.module_from_spec(spec)
spec.loader.exec_module(EXTERNAL)


class ExternalOutputBoundary(unittest.TestCase):
    def report(self, status, output):
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="\n")
        self.addCleanup(stream.close)
        with contextlib.redirect_stdout(stream):
            EXTERNAL.report_baseline("command", ("NativeComposition",), status, output)
        return raw.getvalue()

    def test_redirected_cp1252_preserves_exact_utf8_native_output(self):
        output = "native path \u2192 Caf\u00e9/\u6771\u4eac\n--- PASS: NativeComposition (0.01s)\n"
        self.assertEqual(self.report(0, output), output.encode("utf-8"))

    def test_encoding_never_turns_failed_or_incomplete_native_output_into_success(self):
        success = "native path \u2192 selected exit\n--- PASS: NativeComposition (0.01s)\n"
        for status, output in ((1, success), (0, "native path \u2192 selected exit\n"),
                               (0, success + "--- SKIP: AnotherCase (0.01s)\n"),
                               (0, success + "WARNING: DATA RACE\n")):
            with self.subTest(status=status, output=output):
                raw = io.BytesIO()
                with io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="\n") as stream:
                    with contextlib.redirect_stdout(stream), self.assertRaisesRegex(ValueError, "did not prove its native composition"):
                        EXTERNAL.report_baseline("command", ("NativeComposition",), status, output)
                    self.assertEqual(raw.getvalue(), output.encode("utf-8"))


class BootstrapOverlayBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="windows-bootstrap-source-")
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        self.root, self.core = self.workspace / "repository", self.workspace / "native"
        copies = GATE.PREP.pt_copies()
        for package in ("common", "mobiletor"):
            incoming = ROOT / "internal" / package
            copied = self.root / "internal" / package
            copied.mkdir(parents=True)
            destination = self.core / "routervpn" / package
            destination.mkdir(parents=True)
            for source in incoming.glob("*.go"):
                raw = source.read_bytes()
                (copied / source.name).write_bytes(raw)
                (destination / source.name).write_bytes(GATE.PREP.relocated_shared_source(raw))
        for relative, raw in copies.items():
            target = self.core / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        resources = self.root / "deploy/fixtures/windows-physical-bootstrap"
        shutil.copytree(GATE.RESOURCES, resources)
        registry = self.core / "include/registry.go"
        registry.parent.mkdir()
        registry.write_bytes(GATE.PREP.pt_registry_source('''package include
import (
\t"github.com/sagernet/sing-box/service/resolved"
)
func ServiceRegistry() *service.Registry {
\tresolved.RegisterService(registry)
}
func OutboundRegistry() *outbound.Registry {
\tsocks.RegisterOutbound(registry)
}
func DNSTransportRegistry() *dns.TransportRegistry {
\ttransport.RegisterTCP(registry)
}
'''))
        self.addCleanup(patch.stopall)
        patch.object(GATE, "ROOT", self.root).start()
        patch.object(GATE, "RESOURCES", resources).start()
        patch.object(GATE.IDENTITY, "ROOT", self.root).start()
        patch.object(GATE.PREP, "pt_copies", return_value=copies).start()
        # This unit boundary supplies an already selected pinned directory.
        # The actual Windows gate independently checks the Git commit.
        patch.object(GATE.PREP, "checked_vendor", side_effect=lambda path: Path(path).resolve()).start()

    def test_exact_prepared_sources_and_test_resources_are_read_only(self):
        source, before = GATE.sources(self.core)
        self.assertEqual(source, self.core)
        self.assertIn("routervpn/desktoppt/tor_physical_windows.go", before)
        self.assertIn("routervpn/mobiletor/desktop_bridge.go", before)
        self.assertIn("fixture/kernel_observer.go", before)
        self.assertTrue(all("\\" not in name for name in before))
        work = self.workspace / "overlay"
        work.mkdir()
        selected = json.loads(GATE.overlay(source, work, True).read_text())["Replace"]
        self.assertEqual(len(selected), 8)
        for path in selected.values():
            self.assertTrue(Path(path).is_relative_to(work))
        self.assertEqual(GATE.sources(source)[1], before)
        self.assertFalse((source / "routervpn_windows_physical_composition_test.go").exists())

    def test_changed_compiler_factory_and_socket_copies_are_rejected(self):
        for relative in ("routervpn/mobiletor/desktop_bridge.go", "routervpn/desktoppt/tor_physical_windows.go",
                         "routervpn/mobiletor/desktop_socket_windows_policy.go"):
            with self.subTest(relative=relative):
                path = self.core / relative
                before = path.read_bytes()
                try:
                    path.write_bytes(before + b"// altered copied source\n")
                    with self.assertRaises(ValueError):
                        GATE.sources(self.core)
                finally:
                    path.write_bytes(before)
        GATE.sources(self.core)

    def test_changed_native_registration_is_rejected(self):
        path = self.core / "include/registry.go"
        path.write_text(path.read_text().replace("routervpndesktoppt.RegisterPhysicalOutbound(registry)", "other.RegisterPhysicalOutbound(registry)"))
        with self.assertRaises(ValueError):
            GATE.sources(self.core)

    def test_ordinary_mode_never_overlays_os_admission(self):
        work = self.workspace / "ordinary"
        work.mkdir()
        selected = json.loads(GATE.overlay(self.core, work, False).read_text())["Replace"]
        self.assertEqual(len(selected), 5)
        for path in ("routervpn/mobiletor/desktop_bridge.go", "routervpn/mobiletor/desktop_physical_policy.go",
                     "routervpn_desktop_tor_box_physical.go"):
            self.assertNotIn(str(self.core / path), selected)

    def test_overlay_refuses_existing_foreign_test_source(self):
        path = self.core / "routervpn_windows_physical_composition_test.go"
        path.write_text("// another owner's test file\n")
        work = self.workspace / "foreign"
        work.mkdir()
        with self.assertRaisesRegex(ValueError, "Unowned bootstrap test"):
            GATE.overlay(self.core, work, True)
        self.assertEqual(path.read_text(), "// another owner's test file\n")

    def test_fixture_tag_cannot_enter_an_ordinary_binary(self):
        path = GATE.RESOURCES / "kernel_observer.go"
        path.write_bytes(path.read_bytes().replace(b"windows && routervpn_windows_physical_composition", b"windows"))
        with self.assertRaisesRegex(ValueError, "compile-time test tag"):
            GATE.sources(self.core)

    def test_static_os_change_preserves_other_platform_boundary(self):
        paths = ("routervpn/mobiletor/desktop_bridge.go", "routervpn/mobiletor/desktop_physical_policy.go",
                 "routervpn_desktop_tor_box_physical.go")
        original = [self.core.joinpath(path).read_text() for path in paths]
        bridge, policy, box = GATE.prospective_admission(*original)
        self.assertIn('return targetOS == "linux" || targetOS == "windows"', policy)
        self.assertNotIn('targetOS == "darwin"', policy)
        self.assertIn("DesktopPhysicalBrokerSupported(targetOS)", bridge)
        self.assertIn("mobiletor.DesktopPhysicalBrokerSupported(runtime.GOOS)", box)
        for current in ('targetOS == "linux"', 'targetOS == "linux" || targetOS == "darwin"'):
            with self.subTest(current=current):
                shared = policy.replace('targetOS == "linux" || targetOS == "windows"', current)
                _, changed, _ = GATE.prospective_admission(bridge, shared, box)
                self.assertIn("return " + current + ' || targetOS == "windows"', changed)
        unsafe = policy.replace('return targetOS == "linux" || targetOS == "windows"', 'return true')
        with self.assertRaisesRegex(ValueError, "predicate changed"):
            GATE.prospective_admission(bridge, unsafe, box)


if __name__ == "__main__":
    unittest.main()
