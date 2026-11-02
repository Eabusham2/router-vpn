#!/usr/bin/env python3
"""Check the native Node test overlay cannot lose its executable-only scope."""
from pathlib import Path
import contextlib
import importlib.util
import io
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
        self.assertEqual(len(mapping), 4)
        old = Path(mapping[str(self.source / "routervpn/mobiletor/desktop_socket_windows_policy.go")]).read_text()
        new = Path(mapping[str(self.source / "routervpn/mobiletor/desktop_socket_windows_transfer.go")]).read_text()
        self.assertIn("return desktopWindowsNodeCompositionConstruct(ctx, capture, options, nil, false)", old)
        self.assertIn(GATE.LOOPBACK_COMPOSITION, old)
        self.assertIn("return desktopWindowsNodeCompositionConstruct(ctx, capture, options, predecessor, true)", new)
        for relative, raw in self.original.items():
            self.assertEqual((self.source / relative).read_bytes(), raw)
        self.assertFalse((self.source / "routervpn/mobiletor/desktop_socket_windows_node_composition_overlay.go").exists())
        self.assertFalse((self.source / "routervpn/mobiletor/desktop_socket_windows_node_peer_overlay.go").exists())

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
        for relative in ("routervpn/mobiletor/desktop_socket_windows_node_composition_overlay.go",
                         "routervpn/mobiletor/desktop_socket_windows_node_peer_overlay.go"):
            with self.subTest(relative=relative):
                path = self.source / relative
                path.write_bytes(b"package mobiletor\n// another owner\n")
                with self.assertRaisesRegex(ValueError, "Unowned Windows Node observer"):
                    GATE.overlay(self.source, self.observer)
                self.assertEqual(path.read_bytes(), b"package mobiletor\n// another owner\n")
                path.unlink()

    def test_every_mutation_keeps_both_real_firewall_constructors_scoped(self):
        for mutation in GATE.mutants(self.source):
            with self.subTest(name=mutation[0]):
                selected = GATE.overlay(self.source, self.observer, mutation)
                mapping = json.loads(selected.read_text())["Replace"]
                self.assertEqual(len(mapping), 4 if mutation[0] in ("ordinary-udp-deny", "missing-loopback-ipc") else 5)
                self.assertIn("nil, false)", Path(mapping[str(self.source / "routervpn/mobiletor/desktop_socket_windows_policy.go")]).read_text())
                self.assertIn("predecessor, true)", Path(mapping[str(self.source / "routervpn/mobiletor/desktop_socket_windows_transfer.go")]).read_text())
        forbidden = ("scope-mutation", "routervpn/mobiletor/desktop_socket_windows_policy.go", "test", "witness", "package mobiletor\n")
        with self.assertRaisesRegex(ValueError, "overlaps native scope ownership"):
            GATE.overlay(self.source, self.observer, forbidden)

    def test_udp_permit_defect_keeps_scope_and_requires_actual_peer_receipt(self):
        mutations = GATE.mutants(self.source)
        self.assertEqual([m[0] for m in mutations], ["legacy-adoption", "late-handshake", "ordinary-udp-deny", "missing-loopback-ipc"])
        mutation = mutations[2]
        self.assertEqual(mutation[2], GATE.REQUIRED[0])
        self.assertEqual(mutation[3], "independent peer marker receipt")
        selected = GATE.overlay(self.source, self.observer, mutation)
        mapping = json.loads(selected.read_text())["Replace"]
        relative = "routervpn/mobiletor/desktop_socket_windows_policy.go"
        changed = Path(mapping[str(self.source / relative)]).read_text()
        self.assertIn('p.pair("deny", family, 1, true, true)', changed)
        self.assertIn("return desktopWindowsNodeCompositionConstruct(ctx, capture, options, nil, false)", changed)
        self.assertEqual((self.source / relative).read_bytes(), self.original[relative])
        foreign = (*mutation[:4], mutation[4].replace("options, nil)", "options, untrustedScope)"))
        with self.assertRaisesRegex(ValueError, "overlaps native scope ownership"):
            GATE.overlay(self.source, self.observer, foreign)

    def test_native_ipc_keeps_both_loopback_addresses_and_physical_deny(self):
        selected = GATE.overlay(self.source, self.observer)
        mapping = json.loads(selected.read_text())["Replace"]
        relative = "routervpn/mobiletor/desktop_socket_windows_policy.go"
        actual = Path(mapping[str(self.source / relative)]).read_text()
        self.assertEqual(actual.count(GATE.LOOPBACK_COMPOSITION), 1)
        narrow = GATE.LOOPBACK_COMPOSITION[len(GATE.LOOPBACK_SOURCE):]
        self.assertIn('desktopWFPAddress(desktopWFPLocalAddress, address)', narrow)
        self.assertIn('desktopWFPAddress(desktopWFPRemoteAddress, address)', narrow)
        self.assertIn('netip.IPv6Loopback()', narrow)
        self.assertIn('netip.MustParseAddr("127.0.0.1")', narrow)
        self.assertNotIn('desktopWFPFlags', narrow)
        self.assertIn('p.pair("deny", family, 1, false, true)', actual)
        self.assertIn('conditions = append(conditions, desktopWFPCondition{Field: desktopWFPAppID', actual)
        self.assertEqual((self.source / relative).read_bytes(), self.original[relative])

    def test_missing_ipc_control_restores_only_the_old_scoped_fixture(self):
        mutation = GATE.mutants(self.source)[3]
        self.assertIn(mutation[2], GATE.REQUIRED)
        self.assertEqual(mutation[3], 'captured WFP loopback IPC was denied')
        selected = GATE.overlay(self.source, self.observer, mutation)
        mapping = json.loads(selected.read_text())["Replace"]
        actual = Path(mapping[str(self.source / "routervpn/mobiletor/desktop_socket_windows_policy.go")]).read_text()
        self.assertIn(GATE.LOOPBACK_SOURCE, actual)
        self.assertNotIn('loopback-ipc', actual)
        self.assertIn('p.pair("deny", family, 1, false, true)', actual)
        self.assertIn('return desktopWindowsNodeCompositionConstruct(ctx, capture, options, nil, false)', actual)
        # An unrelated loopback-source change is rejected before native compile.
        source = self.source / "routervpn/mobiletor/desktop_socket_windows_policy.go"
        source.write_bytes(self.original[source.relative_to(self.source).as_posix()].replace(b'"loopback", family, 60', b'"other-loopback", family, 60'))
        with self.assertRaisesRegex(ValueError, 'exact production boundary'):
            GATE.overlay(self.source, self.observer)

    def test_observer_cannot_drop_its_compile_time_tag(self):
        fixtures = self.workspace / "fixtures"
        fixtures.mkdir()
        names = ("kernel_observer.go", "socket_peer.go", "socket_peer_test.go")
        for name in names:
            (fixtures / name).write_bytes((GATE.RESOURCES / name).read_bytes())
        for name in names:
            with self.subTest(name=name):
                original = (fixtures / name).read_bytes()
                (fixtures / name).write_bytes(b"package mobiletor\n")
                with patch.object(GATE, "RESOURCES", fixtures), patch.object(GATE.NODE, "checked_sources", return_value=(self.source, {})):
                    with self.assertRaisesRegex(ValueError, "explicit native test scope"):
                        GATE.checked_sources(self.source)
                (fixtures / name).write_bytes(original)


class OrdinaryHysteria2Scope(unittest.TestCase):
    def setUp(self):
        NativeNodeScope.setUp(self)
        for relative, actual in (
                ("routervpn/mobiletor/desktop_socket_windows_commit.go", ROOT / "internal/mobiletor/desktop_socket_windows_commit.go"),
                ("routervpn/desktoppt/external_physical_windows.go", ROOT / "mobile/desktop/external_physical_windows.go.tmpl")):
            self.original[relative] = actual.read_bytes()
            (self.source / relative).write_bytes(self.original[relative])

    def test_durable_constructor_and_every_mutant_keep_actual_scope(self):
        for mutation in (None, "ordinary-udp-deny", "missing-durable-intent"):
            with self.subTest(mutation=mutation):
                selected = GATE.external_overlay(self.source, self.observer, mutation)
                mapping = json.loads(selected.read_text())["Replace"]
                self.assertEqual(len(mapping), 6 if mutation == "missing-durable-intent" else 5)
                policy = Path(mapping[str(self.source / "routervpn/mobiletor/desktop_socket_windows_policy.go")]).read_text()
                transfer = Path(mapping[str(self.source / "routervpn/mobiletor/desktop_socket_windows_transfer.go")]).read_text()
                commit = Path(mapping[str(self.source / "routervpn/mobiletor/desktop_socket_windows_commit.go")]).read_text()
                self.assertIn("desktopWindowsNodeCompositionConstruct(ctx, capture, options, nil, false)", policy)
                self.assertIn("desktopWindowsNodeCompositionConstruct(ctx, capture, options, predecessor, true)", transfer)
                self.assertIn("desktopWindowsNodeCompositionWithBarrier(ctx, capture, options, predecessor, barrier)", commit)
                self.assertIn(GATE.LOOPBACK_COMPOSITION, policy)
                self.assertIn('p.pair("deny", family, 1, ' + ("true" if mutation == "ordinary-udp-deny" else "false") + ', true)', policy)
                if mutation == "missing-durable-intent":
                    factory = Path(mapping[str(self.source / "routervpn/desktoppt/external_physical_windows.go")]).read_text()
                    self.assertIn("if false && commit != nil {", factory)
                for relative, raw in self.original.items():
                    self.assertEqual((self.source / relative).read_bytes(), raw)
        with self.assertRaisesRegex(ValueError, "Unknown ordinary Hysteria2"):
            GATE.external_overlay(self.source, self.observer, "permit-whole-host")

    def test_changed_durable_constructor_is_rejected(self):
        path = self.source / "routervpn/mobiletor/desktop_socket_windows_commit.go"
        path.write_bytes(path.read_bytes().replace(b"predecessor, nil, barrier)", b"predecessor, foreignScope, barrier)"))
        with self.assertRaisesRegex(ValueError, "exact production boundary"):
            GATE.external_overlay(self.source, self.observer)

    def test_external_native_fixture_cannot_lose_its_compile_time_tag(self):
        root = self.workspace / "repository"
        mobile = root / "mobile/desktop"
        mobile.mkdir(parents=True)
        for name in ("node_peer_windows_test.go.tmpl", "external_box_windows_hysteria2_test.go.tmpl"):
            (mobile / name).write_bytes((ROOT / "mobile/desktop" / name).read_bytes())
        source = mobile / "external_box_windows_hysteria2_test.go.tmpl"
        original = source.read_bytes()
        with patch.object(GATE, "ROOT", root), patch.object(GATE.NODE, "checked_sources", return_value=(self.source, {})):
            _, before = GATE.checked_sources(self.source)
            self.assertIn("external_hysteria2", before)
            source.write_bytes(original.replace(GATE.TAG, b"//go:build windows\n", 1))
            with self.assertRaisesRegex(ValueError, "explicit native test scope"):
                GATE.checked_sources(self.source)
            source.write_bytes(original)
            self.assertEqual(GATE.checked_sources(self.source)[1], before)

    def test_required_root_and_each_real_leaf_are_mandatory(self):
        root = "TestRouterVPNDesktopExternalWindowsHysteria2WFP"
        expected = (root, *(root + "/" + leaf for leaf in (
            "on-connect", "always", "successor-and-original-restore", "reject/password", "reject/trust",
            "reject/dns", "reject/exit", "cancelled-proof", "foreign-predecessor", "commit-refused")))
        self.assertEqual(GATE.EXTERNAL_HY2_CASES, expected)
        complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in expected)
        with contextlib.redirect_stdout(io.StringIO()):
            GATE.report_external_hysteria2(0, complete)
        bad = [(1, complete), (0, complete + "--- SKIP: hidden (0.01s)\n"),
               (0, complete + "WARNING: DATA RACE\n")]
        bad += [(0, complete.replace("--- PASS: " + case + " (0.01s)\n", "")) for case in expected]
        for status, output in bad:
            with self.subTest(status=status, output=output), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "required native result"):
                    GATE.report_external_hysteria2(status, output)

    def dispatch(self, fault=None):
        calls = []
        complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in GATE.EXTERNAL_HY2_CASES)
        witnesses = {"ordinary-udp-deny": "ordinary token bypassed actual external WFP UDP deny: independent peer marker",
                     "missing-durable-intent": "actual HY2 source skipped its durable WFP intent"}

        def run(command, **kwargs):
            command = tuple(str(value) for value in command)
            calls.append((command, kwargs["timeout"]))
            self.assertEqual(kwargs["cwd"], self.source)
            self.assertEqual(kwargs["env"], {"captured": "environment"})
            if command[0] == "owned-go":
                self.assertIn("-race", command)
                self.assertIn("-mod=readonly", command)
                self.assertEqual(command[-1], ".")
                self.assertEqual(kwargs["timeout"], 600)
                selected = next(value.removeprefix("-overlay=") for value in command if value.startswith("-overlay="))
                self.assertEqual(len(json.loads(Path(selected).read_text())["Replace"]),
                                 6 if Path(selected).parent.name == "external-hysteria2-missing-durable-intent" else 5)
                binary = Path(command[command.index("-o") + 1])
                binary.write_bytes(b"explicit native compiler boundary")
                return 0, ""
            binary = Path(command[0])
            if binary.parent.name == "external-hysteria2":
                self.assertIn("-test.run=^" + GATE.EXTERNAL_HY2_ROOT + "$", command)
                self.assertIn("-test.timeout=180s", command)
                self.assertEqual(kwargs["timeout"], 195)
                if fault == "image":
                    binary.write_bytes(b"replaced native image")
                if fault == "leaf":
                    return 0, complete.replace("--- PASS: " + GATE.EXTERNAL_HY2_ROOT + "/reject/trust (0.01s)\n", "")
                return 0, complete
            label = binary.parent.name.removeprefix("external-hysteria2-")
            self.assertIn("-test.run=^" + GATE.EXTERNAL_HY2_ROOT + "$/^always$", command)
            self.assertIn("-test.timeout=60s", command)
            self.assertEqual(kwargs["timeout"], 75)
            output = "--- FAIL: " + GATE.EXTERNAL_HY2_ROOT + "/always (0.01s)\n" + witnesses[label] + "\n"
            if fault == label:
                return 0, output
            if fault == "timeout":
                return 1, output + "panic: test timed out\n"
            return 1, output

        build = ["owned-go", "test", "-c", "-mod=readonly", "-race", "-tags=windows,routervpn_windows_node_composition"]
        with patch.object(GATE.BOOT.IDENTITY, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            GATE.execute_external_hysteria2(self.source, self.workspace, build, {"captured": "environment"})
        return calls

    def test_real_dispatch_keeps_binary_identity_all_cases_and_both_compiled_controls(self):
        calls = self.dispatch()
        self.assertEqual(len(calls), 6)
        self.assertEqual([timeout for _, timeout in calls], [600, 195, 600, 75, 600, 75])

    def test_native_dispatch_rejects_missing_result_replaced_image_or_successful_mutants(self):
        for fault, message in (("leaf", "required native result"), ("image", "native executable changed"),
                               ("ordinary-udp-deny", "exact defect"), ("missing-durable-intent", "exact defect"),
                               ("timeout", "exact defect")):
            with self.subTest(fault=fault):
                # Each dispatch owns a fresh temporary fixture; an earlier
                # failed child never supplies the next candidate's image.
                previous = self.workspace
                self.workspace = previous / fault
                self.workspace.mkdir()
                try:
                    with self.assertRaisesRegex(ValueError, message):
                        self.dispatch(fault)
                finally:
                    self.workspace = previous


if __name__ == "__main__":
    unittest.main()
