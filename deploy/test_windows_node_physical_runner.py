#!/usr/bin/env python3
"""Check the native Node test overlay cannot lose its executable-only scope."""
from pathlib import Path
import contextlib
import importlib.util
import io
import json
import re
import subprocess
import sys
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
        for name in ("node_peer_windows_test.go.tmpl", "external_box_windows_hysteria2_test.go.tmpl", "external_box_windows_socks_test.go.tmpl", "external_box_windows_packet_test.go.tmpl", "external_box_windows_alias_test.go.tmpl", "external_box_windows_openvpn_test.go.tmpl", "external_box_windows_hysteria2_layer_test.go.tmpl", "external_hysteria_layer_peer_test.go.tmpl"):
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
        first = "--- PASS: " + expected[0] + " (0.01s)\n"
        bad = [(1, complete), (0, complete + first), (0, complete.replace(first, "diagnostic: " + first))]
        bad.extend((0, complete + marker + "\n") for marker in (
            "--- SKIP: hidden", "WARNING: DATA RACE", "--- FAIL: hidden", "FAIL", "panic: bad", "fatal error: bad", "x [build failed]"))
        bad += [(0, complete.replace("--- PASS: " + case + " (0.01s)\n", "")) for case in expected]
        for status, output in bad:
            with self.subTest(status=status, output=output), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "required native result"):
                    GATE.report_external_hysteria2(status, output)

    def test_layer_inventory_rejects_missing_duplicate_prefixed_or_aborted_verdicts(self):
        for mode in GATE.EXTERNAL_HY2_LAYERS:
            cases = GATE.EXTERNAL_HY2_LAYER_CASES[mode]
            self.assertEqual(len(cases), 14 if mode.endswith("+xor-whitening") else 13)
            self.assertTrue(all(GATE.EXTERNAL_HY2_LAYER_ROOT + "/" + mode + "/" + case.split("/", 1)[1] in cases for case in GATE.EXTERNAL_HY2_CASES[1:]))
            complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in cases)
            with contextlib.redirect_stdout(io.StringIO()):
                GATE.report_external_hysteria2_layer(mode, 0, complete)
            bad = [complete.replace("--- PASS: " + case + " (0.01s)\n", "") for case in cases]
            first = "--- PASS: " + cases[0] + " (0.01s)\n"
            bad.extend((complete + first, complete.replace(first, "diagnostic: " + first)))
            bad.extend(complete + marker + "\n" for marker in ("--- SKIP: hidden", "WARNING: DATA RACE", "--- FAIL: hidden", "FAIL", "panic: bad", "fatal error: bad", "x [build failed]"))
            for output in bad:
                with self.subTest(mode=mode, output=output), contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, "required native result"):
                    GATE.report_external_hysteria2_layer(mode, 0, output)

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
                selector = next(value for value in command if value.startswith("-test.run="))
                mode = next((mode for mode in GATE.EXTERNAL_HY2_LAYERS if selector == "-test.run=^" + GATE.EXTERNAL_HY2_LAYER_ROOT + "$/^" + re.escape(mode) + "$"), None)
                self.assertTrue(mode or selector == "-test.run=^" + GATE.EXTERNAL_HY2_ROOT + "$")
                result = "".join("--- PASS: " + case + " (0.01s)\n" for case in GATE.EXTERNAL_HY2_LAYER_CASES[mode]) if mode else complete
                self.assertIn("-test.timeout=180s", command)
                self.assertEqual(kwargs["timeout"], 195)
                if fault == "image":
                    binary.write_bytes(b"replaced native image")
                if fault == "leaf":
                    return 0, complete.replace("--- PASS: " + GATE.EXTERNAL_HY2_ROOT + "/reject/trust (0.01s)\n", "")
                if fault == "layer-leaf" and mode:
                    return 0, result.replace("--- PASS: " + GATE.EXTERNAL_HY2_LAYER_CASES[mode][-1] + " (0.01s)\n", "")
                return 0, result
            label = binary.parent.name.removeprefix("external-hysteria2-")
            selector = next(value for value in command if value.startswith("-test.run="))
            mode = next((mode for mode in GATE.EXTERNAL_HY2_LAYERS if selector == "-test.run=^" + GATE.EXTERNAL_HY2_LAYER_ROOT + "$/^" + re.escape(mode) + "$/^always$"), None)
            self.assertTrue(mode or selector == "-test.run=^" + GATE.EXTERNAL_HY2_ROOT + "$/^always$")
            selected = GATE.EXTERNAL_HY2_LAYER_ROOT + "/" + mode if mode else GATE.EXTERNAL_HY2_ROOT
            self.assertIn("-test.timeout=60s", command)
            self.assertEqual(kwargs["timeout"], 75)
            output = "--- FAIL: " + selected + "/always (0.01s)\n" + witnesses[label] + "\n"
            if fault == "control-image":
                binary.write_bytes(b"changed control image")
            if fault == "prefixed-failure":
                return 1, "diagnostic: " + output
            if fault == "duplicate-failure":
                return 1, output + output
            if fault == "layer-control-success" and mode:
                return 0, output
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
        self.assertEqual(len(calls), 12)
        self.assertEqual([timeout for _, timeout in calls], [600, 195, 195, 195, 600, 75, 75, 75, 600, 75, 75, 75])

    def test_native_dispatch_rejects_missing_result_replaced_image_or_successful_mutants(self):
        for fault, message in (("layer-leaf", "required native result"), ("leaf", "required native result"), ("image", "native executable changed"),
                               ("ordinary-udp-deny", "exact defect"), ("missing-durable-intent", "exact defect"),
                               ("timeout", "exact defect"), ("prefixed-failure", "exact defect"),
                               ("duplicate-failure", "exact defect"), ("layer-control-success", "exact defect"),
                               ("control-image", "control executable changed")):
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


class OrdinarySOCKSScope(unittest.TestCase):
    def test_exact_retirement_observer_after_full_close_and_during_timeout(self):
        subprocess.run([sys.executable, str(ROOT / 'deploy/test_windows_socket_retirement_observer.py')],
                       check=True, timeout=100)

    def setUp(self):
        OrdinaryHysteria2Scope.setUp(self)
        relative = "routervpn/mobiletor/desktop_socket_windows_identity.go"
        self.original[relative] = (ROOT / "internal/mobiletor/desktop_socket_windows_identity.go").read_bytes()
        (self.source / relative).write_bytes(self.original[relative])

    def test_local_retirement_controls_keep_native_scope_and_exact_source(self):
        cases = {
            "missing-socks-release": ("routervpn/mobiletor/desktop_socket_windows_policy.go", "if err := error(nil); err != nil {"),
            "missing-socks-readback": ("routervpn/mobiletor/desktop_socket_windows_identity.go", "if false && record.endpoint != 0 {"),
            "missing-socks-grant-removal": ("routervpn/mobiletor/desktop_socket_windows_policy.go", "func (p *DesktopWindowsSocketPolicy) Revoke("),
        }
        for mutation, (relative, witness) in cases.items():
            with self.subTest(mutation=mutation):
                selected = GATE.external_overlay(self.source, self.observer, mutation)
                mapping = json.loads(selected.read_text())["Replace"]
                self.assertEqual(len(mapping), 6 if mutation == "missing-socks-readback" else 5)
                self.assertIn(witness, Path(mapping[str(self.source / relative)]).read_text())
                policy = Path(mapping[str(self.source / "routervpn/mobiletor/desktop_socket_windows_policy.go")]).read_text()
                self.assertIn("desktopWindowsNodeCompositionConstruct(ctx, capture, options, nil, false)", policy)
                self.assertIn(GATE.LOOPBACK_COMPOSITION, policy)
                self.assertIn('p.pair("deny", family, 1, false, true)', policy)
                if mutation == "missing-socks-grant-removal":
                    revoke = policy.split("func (p *DesktopWindowsSocketPolicy) Revoke(", 1)[1].split("func (p *DesktopWindowsSocketPolicy) CreateSocket", 1)[0]
                    self.assertNotIn("p.revoke(q)", revoke)
                for path, original in self.original.items():
                    self.assertEqual((self.source / path).read_bytes(), original)

    def test_every_socks_native_verdict_is_required(self):
        expected = (GATE.EXTERNAL_SOCKS_ROOT, *(GATE.EXTERNAL_SOCKS_ROOT + "/" + leaf for leaf in (
            "refusal-receipts", "on-connect", "always", "home-lan-off", "home-lan-off/tcp-deny", "home-lan-off/udp-deny",
            "home-lan-off/tcp-retained-deny", "home-lan-off/udp-retained-deny",
            "reject/password", "reject/trust", "reject/dns", "reject/exit", "reject/auth-downgrade",
            "reject/relay-domain", "reject/relay-wildcard", "reject/relay-zero", "reject/relay-other-private", "reject/control-eof",
            "successor-and-original-restore", "cancelled-proof", "replacement-keeps-new-source",
            "foreign-predecessor", "commit-refused")))
        self.assertEqual(GATE.EXTERNAL_SOCKS_CASES, expected)
        complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in expected)
        with contextlib.redirect_stdout(io.StringIO()):
            GATE.report_external_socks(0, complete)
        bad = [(1, complete)]
        bad += [(0, complete + marker + "\n") for marker in (
            "--- SKIP: hidden (0.01s)", "WARNING: DATA RACE", "--- FAIL: hidden (0.01s)",
            "FAIL", "panic: unexpected", "fatal error: unexpected", "package [build failed]")]
        first = "--- PASS: " + expected[0] + " (0.01s)\n"
        bad += [(0, complete.replace(first, "expected diagnostic: " + first)), (0, complete + first)]
        bad += [(0, complete.replace("--- PASS: " + case + " (0.01s)\n", "")) for case in expected]
        for status, output in bad:
            with self.subTest(status=status, output=output), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "required native result"):
                    GATE.report_external_socks(status, output)

    def test_socks_fixture_is_part_of_checked_native_scope(self):
        root = self.workspace / "repository"
        mobile = root / "mobile/desktop"
        mobile.mkdir(parents=True)
        for name in ("node_peer_windows_test.go.tmpl", "external_box_windows_hysteria2_test.go.tmpl", "external_box_windows_socks_test.go.tmpl", "external_box_windows_packet_test.go.tmpl", "external_box_windows_alias_test.go.tmpl", "external_box_windows_openvpn_test.go.tmpl", "external_box_windows_hysteria2_layer_test.go.tmpl", "external_hysteria_layer_peer_test.go.tmpl"):
            (mobile / name).write_bytes((ROOT / "mobile/desktop" / name).read_bytes())
        source = mobile / "external_box_windows_socks_test.go.tmpl"
        original = source.read_bytes()
        with patch.object(GATE, "ROOT", root), patch.object(GATE.NODE, "checked_sources", return_value=(self.source, {})):
            _, before = GATE.checked_sources(self.source)
            self.assertIn("external_socks", before)
            source.write_bytes(original.replace(GATE.TAG, b"//go:build windows\n", 1))
            with self.assertRaisesRegex(ValueError, "explicit native test scope"):
                GATE.checked_sources(self.source)
            source.write_bytes(original)
            self.assertEqual(GATE.checked_sources(self.source)[1], before)

    def dispatch(self, fault=None):
        calls = []
        complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in GATE.EXTERNAL_SOCKS_CASES)
        controls = {
            "ordinary-tcp-deny": ("home-lan-off/tcp-deny", "ordinary token bypassed actual SOCKS WFP TCP deny: independent peer marker"),
            "ordinary-udp-deny": ("home-lan-off/udp-deny", "ordinary token bypassed actual SOCKS WFP UDP deny: independent peer marker"),
            "missing-durable-intent": ("always", "actual SOCKS source skipped its durable WFP intent"),
            "missing-socket-release": ("reject/relay-other-private", "native retirement bypassed exact socket release or grant join"),
            "missing-endpoint-readback": ("reject/relay-other-private", "native retirement bypassed independent endpoint readback"),
            "missing-grant-removal": ("reject/relay-other-private", "completed native refusal retained its original grant and exact WFP filters"),
        }

        def run(command, **kwargs):
            calls.append((command, kwargs["timeout"]))
            self.assertEqual(kwargs["cwd"], self.source)
            self.assertEqual(kwargs["env"], {"captured": "environment"})
            if "-c" in command:
                binary = Path(command[command.index("-o") + 1])
                self.assertIn("-mod=readonly", command)
                self.assertIn("-race", command)
                self.assertTrue(any(str(arg).startswith("-overlay=") for arg in command))
                binary.write_bytes(b"captured-native-socks-image")
                if fault == "compile":
                    return 1, "actual compiler failed"
                return 0, ""
            binary = Path(command[0])
            if binary.parent.name == "external-socks":
                self.assertIn("-test.run=^" + GATE.EXTERNAL_SOCKS_ROOT + "$", command)
                self.assertIn("-test.timeout=300s", command)
                self.assertEqual(kwargs["timeout"], 315)
                if fault == "image":
                    binary.write_bytes(b"replaced-native-image")
                if fault == "leaf":
                    return 0, complete.replace("--- PASS: " + GATE.EXTERNAL_SOCKS_ROOT + "/reject/control-eof (0.01s)\n", "")
                return 0, complete
            label = binary.parent.name.removeprefix("external-socks-")
            leaf, witness = controls[label]
            expression = "^" + GATE.EXTERNAL_SOCKS_ROOT + "$/" + "/".join("^" + part + "$" for part in leaf.split("/"))
            self.assertIn("-test.run=" + expression, command)
            self.assertIn("-test.timeout=60s", command)
            self.assertEqual(kwargs["timeout"], 75)
            output = "--- FAIL: " + GATE.EXTERNAL_SOCKS_ROOT + "/" + leaf + " (0.01s)\n" + witness + "\n"
            if fault == label:
                return 0, output
            if fault == "timeout":
                return 1, output + "panic: test timed out\n"
            if fault == "witness":
                return 1, output.replace(witness, "unrelated failure")
            if label == "missing-grant-removal" and fault in (
                    "grant-old-completion", "grant-old-timeout", "grant-observation-error"):
                refused = {
                    "grant-old-completion": "native retirement bypassed exact socket release or grant join",
                    "grant-old-timeout": "native retirement did not reach exact socket release and grant join",
                    "grant-observation-error": "native retirement grant observation failed: native read refused",
                }[fault]
                return 1, output.replace(witness, refused)
            if fault == "prefixed-failure":
                return 1, "displayed expectation: " + output
            if fault == "duplicate-failure":
                return 1, output + output
            if fault == "fatal":
                return 1, output + "fatal error: unrelated crash\n"
            return 1, output

        build = ["owned-go", "test", "-c", "-mod=readonly", "-race", "-tags=windows,routervpn_windows_node_composition"]
        with patch.object(GATE.BOOT.IDENTITY, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            GATE.execute_external_socks(self.source, self.workspace, build, {"captured": "environment"})
        return calls

    def test_real_socks_dispatch_preserves_all_six_compiled_controls(self):
        calls = self.dispatch()
        self.assertEqual(len(calls), 14)
        self.assertEqual([timeout for _, timeout in calls], [600, 315] + [600, 75] * 6)
        for relative, raw in self.original.items():
            self.assertEqual((self.source / relative).read_bytes(), raw)

    def test_socks_dispatch_rejects_false_native_acceptance(self):
        for fault, message in (("compile", "compilation failed"), ("leaf", "required native result"),
                               ("image", "native executable changed"), ("ordinary-tcp-deny", "exact defect"),
                               ("ordinary-udp-deny", "exact defect"), ("missing-durable-intent", "exact defect"),
                               ("missing-socket-release", "exact defect"), ("missing-endpoint-readback", "exact defect"),
                               ("missing-grant-removal", "exact defect"),
                               ("grant-old-completion", "exact defect"), ("grant-old-timeout", "exact defect"),
                               ("grant-observation-error", "exact defect"),
                               ("timeout", "exact defect"), ("witness", "exact defect"),
                               ("prefixed-failure", "exact defect"), ("duplicate-failure", "exact defect"),
                               ("fatal", "exact defect")):
            with self.subTest(fault=fault):
                previous = self.workspace
                self.workspace = previous / fault
                self.workspace.mkdir()
                try:
                    with self.assertRaisesRegex(ValueError, message):
                        self.dispatch(fault)
                finally:
                    self.workspace = previous


class OrdinaryPacketScope(unittest.TestCase):
    setUp = OrdinaryHysteria2Scope.setUp

    def test_packet_fixture_remains_part_of_the_exact_native_scope_digest(self):
        root = self.workspace / "repository"
        mobile = root / "mobile/desktop"
        mobile.mkdir(parents=True)
        for name in ("node_peer_windows_test.go.tmpl", "external_box_windows_hysteria2_test.go.tmpl", "external_box_windows_socks_test.go.tmpl", "external_box_windows_packet_test.go.tmpl", "external_box_windows_alias_test.go.tmpl", "external_box_windows_openvpn_test.go.tmpl", "external_box_windows_hysteria2_layer_test.go.tmpl", "external_hysteria_layer_peer_test.go.tmpl"):
            (mobile / name).write_bytes((ROOT / "mobile/desktop" / name).read_bytes())
        source = mobile / "external_box_windows_packet_test.go.tmpl"
        original = source.read_bytes()
        with patch.object(GATE, "ROOT", root), patch.object(GATE.NODE, "checked_sources", return_value=(self.source, {})):
            _, before = GATE.checked_sources(self.source)
            self.assertIn("external_packet", before)
            source.write_bytes(original.replace(GATE.TAG, b"//go:build windows\n", 1))
            with self.assertRaisesRegex(ValueError, "explicit native test scope"):
                GATE.checked_sources(self.source)
            source.write_bytes(original)
            self.assertEqual(GATE.checked_sources(self.source)[1], before)

    def test_every_protocol_and_native_leaf_requires_one_real_verdict(self):
        self.assertEqual(GATE.EXTERNAL_PACKET_PROTOCOLS, ("wireguard", "awg2-fast", "awg2-strong"))
        for protocol in GATE.EXTERNAL_PACKET_PROTOCOLS:
            prefix = GATE.EXTERNAL_PACKET_ROOT + "/" + protocol
            leaves = ("on-connect", "always", "successor-and-original-restore", "reject/private-key", "reject/psk",
                      "reject/trust", "reject/dns", "reject/exit", "cancelled-proof", "foreign-predecessor", "commit-refused")
            if protocol != "wireguard":
                leaves += ("reject/parameters",)
            expected = (GATE.EXTERNAL_PACKET_ROOT, prefix, *(prefix + "/" + leaf for leaf in leaves))
            self.assertEqual(GATE.EXTERNAL_PACKET_CASES[protocol], expected)
            complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in expected)
            with contextlib.redirect_stdout(io.StringIO()):
                GATE.report_external_packet(0, complete, protocol)
            bad = [(1, complete)]
            bad += [(0, complete + value + "\n") for value in ("--- SKIP: hidden (0.1s)", "DATA RACE", "panic: crash", "fatal error: crash", "[build failed]", "--- FAIL: hidden (0.1s)", "FAIL")]
            for case in expected:
                verdict = "--- PASS: " + case + " (0.01s)\n"
                bad += [(0, complete.replace(verdict, "")), (0, complete.replace(verdict, "expected: " + verdict)), (0, complete + verdict)]
            for status, output in bad:
                with self.subTest(protocol=protocol, output=output), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, "required native result"):
                        GATE.report_external_packet(status, output, protocol)

    def dispatch(self, fault=None):
        calls = []
        witnesses = {"ordinary-udp-deny": "ordinary token bypassed actual external WFP UDP deny: independent peer marker",
                     "missing-durable-intent": "actual packet source skipped its durable WFP intent"}
        def run(command, **kwargs):
            command = tuple(str(value) for value in command)
            calls.append((command, kwargs["timeout"]))
            self.assertEqual(kwargs["cwd"], self.source)
            self.assertEqual(kwargs["env"], {"captured": "environment"})
            if "-c" in command:
                self.assertIn("-mod=readonly", command)
                self.assertIn("-race", command)
                selected = Path(next(value.removeprefix("-overlay=") for value in command if value.startswith("-overlay=")))
                self.assertEqual(len(json.loads(selected.read_text())["Replace"]), 6 if "missing-durable-intent" in selected.parent.name else 5)
                Path(command[command.index("-o") + 1]).write_bytes(b"captured-native-packet-image/" + selected.parent.name.encode())
                return (1, "compile failed") if fault == "compile" else (0, "")
            binary = Path(command[0])
            if binary.parent.name == "external-packet":
                if any("PacketReference|" in value for value in command):
                    self.assertIn("-test.timeout=60s", command)
                    self.assertEqual(kwargs["timeout"], 75)
                    reference = "TestRouterVPNDesktopExternalPacketReference"
                    leaves = (reference + "Authority", *(reference + "/" + protocol for protocol in GATE.EXTERNAL_PACKET_PROTOCOLS))
                    output = "".join("--- PASS: " + case + " (0.01s)\n" for case in leaves)
                    if fault == "reference":
                        output = output.replace("--- PASS: " + leaves[-1] + " (0.01s)\n", "")
                    return 0, output
                protocol = next(p for p in GATE.EXTERNAL_PACKET_PROTOCOLS if "-test.run=^" + GATE.EXTERNAL_PACKET_ROOT + "$/^" + p + "$" in command)
                self.assertIn("-test.timeout=180s", command)
                self.assertEqual(kwargs["timeout"], 195)
                output = "".join("--- PASS: " + case + " (0.01s)\n" for case in GATE.EXTERNAL_PACKET_CASES[protocol])
                if fault == "image":
                    binary.write_bytes(b"another-image")
                if fault == "leaf":
                    output = output.replace("--- PASS: " + GATE.EXTERNAL_PACKET_CASES[protocol][-1] + " (0.01s)\n", "")
                return 0, output
            label = binary.parent.name.removeprefix("external-packet-")
            self.assertIn("-test.run=^" + GATE.EXTERNAL_PACKET_ROOT + "$/^wireguard$/^always$", command)
            self.assertIn("-test.timeout=60s", command)
            self.assertEqual(kwargs["timeout"], 75)
            output = "--- FAIL: " + GATE.EXTERNAL_PACKET_ROOT + "/wireguard/always (0.01s)\n" + witnesses[label] + "\n"
            if fault == "prefix":
                output = "expected: " + output
            if fault == "duplicate":
                output += output
            if fault == "panic":
                output += "panic: test timed out\n"
            if fault == "witness":
                output = output.replace(witnesses[label], "unrelated failure")
            if fault == "mutant-image":
                binary.write_bytes(b"changed-negative-image")
            return (0 if fault == label else 1), output
        build = ["owned-go", "test", "-c", "-mod=readonly", "-race", "-tags=windows,routervpn_windows_node_composition"]
        with patch.object(GATE.BOOT.IDENTITY, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            GATE.execute_external_packet(self.source, self.workspace, build, {"captured": "environment"})
        return calls

    def test_all_three_protocols_share_one_owned_build_and_both_controls(self):
        calls = self.dispatch()
        self.assertEqual([timeout for _, timeout in calls], [600, 75, 195, 195, 195, 600, 75, 600, 75])
        self.assertEqual(len({command[0] for command, timeout in calls if timeout == 195}), 1)

    def test_packet_dispatch_rejects_changed_images_missing_leaves_and_invalid_controls(self):
        for fault, message in (("compile", "compilation failed"), ("image", "native executable changed"), ("leaf", "required native result"), ("reference", "required encrypted result"),
                               ("ordinary-udp-deny", "exact defect"), ("missing-durable-intent", "exact defect"),
                               ("prefix", "exact defect"), ("duplicate", "exact defect"), ("panic", "exact defect"), ("witness", "exact defect"), ("mutant-image", "control executable changed")):
            with self.subTest(fault=fault):
                previous = self.workspace
                self.workspace = previous / fault
                self.workspace.mkdir()
                try:
                    with self.assertRaisesRegex(ValueError, message):
                        self.dispatch(fault)
                finally:
                    self.workspace = previous


class OrdinaryOpenVPNScope(unittest.TestCase):
    setUp = OrdinaryHysteria2Scope.setUp

    def test_each_alias_and_transport_verdict_is_unique_and_mandatory(self):
        self.assertEqual(GATE.EXTERNAL_OPENVPN_NETWORKS, ("tcp", "udp", "mixed"))
        self.assertEqual(GATE.EXTERNAL_OPENVPN_LEAVES, ("on-connect", "always", "successor-and-original-restore", "reject/trust", "reject/control-key", "reject/dns", "cancelled-proof", "foreign-predecessor", "commit-refused"))
        for network in ("alias", *GATE.EXTERNAL_OPENVPN_NETWORKS):
            required = GATE.EXTERNAL_OPENVPN_ALIAS_CASES if network == "alias" else GATE.EXTERNAL_OPENVPN_CASES[network]
            complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
            with contextlib.redirect_stdout(io.StringIO()):
                GATE.report_external_openvpn(0, complete, network)
            bad = [(1, complete)]
            bad += [(0, complete + value + "\n") for value in ("--- SKIP: hidden (0.1s)", "DATA RACE", "panic: crash", "fatal error: crash", "[build failed]", "--- FAIL: hidden (0.1s)", "FAIL")]
            for case in required:
                verdict = "--- PASS: " + case + " (0.01s)\n"
                bad += [(0, complete.replace(verdict, "")), (0, complete.replace(verdict, "expected: " + verdict)), (0, complete + verdict)]
            for status, output in bad:
                with self.subTest(network=network), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, "required native result"):
                        GATE.report_external_openvpn(status, output, network)

    def dispatch(self, fault=None):
        calls = []
        def run(command, **kwargs):
            command = tuple(map(str, command)); calls.append((command, kwargs["timeout"]))
            if "-c" in command:
                Path(command[command.index("-o") + 1]).write_bytes(b"captured-openvpn-image")
                return (1, "compile failed") if fault == "compile" else (0, "")
            binary = Path(command[0])
            if binary.parent.name == "external-openvpn":
                expression = next(value.removeprefix("-test.run=") for value in command if value.startswith("-test.run="))
                network = "alias" if expression == "^" + GATE.EXTERNAL_OPENVPN_ALIAS + "$" else next(network for network in GATE.EXTERNAL_OPENVPN_NETWORKS if expression.endswith("/^" + network + "$"))
                required = GATE.EXTERNAL_OPENVPN_ALIAS_CASES if network == "alias" else GATE.EXTERNAL_OPENVPN_CASES[network]
                if fault == "image":
                    binary.write_bytes(b"foreign image")
                if fault == "leaf":
                    required = required[:-1]
                return 0, "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
            label = binary.parent.name.removeprefix("external-openvpn-")
            witness = "ordinary token bypassed actual external WFP UDP deny: independent peer marker" if label == "ordinary-udp-deny" else "actual OpenVPN source skipped its durable WFP intent"
            self.assertIn("-test.run=^" + GATE.EXTERNAL_OPENVPN_ROOT + "$/^udp$/^always$", command)
            output = "--- FAIL: " + GATE.EXTERNAL_OPENVPN_ROOT + "/udp/always (0.01s)\n" + witness
            if fault == "prefix": output = "expected: " + output
            if fault == "duplicate": output += "\n" + output
            if fault == "panic": output += "\npanic: deadline"
            if fault == "witness": output = output.replace(witness, "unrelated failure")
            if fault == "mutant-image": binary.write_bytes(b"foreign negative image")
            return (0 if fault == label else 1), output
        with patch.object(GATE.BOOT.IDENTITY, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            GATE.execute_external_openvpn(self.source, self.workspace, ["go", "test", "-c", "-mod=readonly", "-race"], {})
        return calls

    def test_openvpn_builds_are_separate_and_all_native_cases_and_controls_execute(self):
        calls = self.dispatch()
        self.assertEqual([timeout for _, timeout in calls], [600, 75, 195, 195, 195, 600, 75, 600, 75])
        self.assertEqual(len({command[0] for command, timeout in calls if timeout == 195}), 1)

    def test_native_openvpn_rejects_spoofed_controls_changed_images_and_omitted_results(self):
        for fault, message in (("compile", "compilation failed"), ("image", "native executable changed"), ("leaf", "required native result"),
                               ("ordinary-udp-deny", "exact defect"), ("missing-durable-intent", "exact defect"),
                               ("prefix", "exact defect"), ("duplicate", "exact defect"), ("panic", "exact defect"), ("witness", "exact defect"), ("mutant-image", "negative executable changed")):
            with self.subTest(fault=fault):
                previous = self.workspace
                self.workspace = previous / fault
                self.workspace.mkdir()
                try:
                    with self.assertRaisesRegex(ValueError, message):
                        self.dispatch(fault)
                finally:
                    self.workspace = previous


class NativePhaseOrchestration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="windows-phase-parser-")
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)
        self.records = {"actual-generated-source": "a" * 64}
        self.source_sha = GATE.source_digest(self.records)
        self.env = {"GOARCH": "amd64", "captured": "unchanged"}

    def receipt(self, phase):
        return {"format": "routervpn-windows-physical-phase-v1", "phase": phase,
                "architecture": "amd64", "source_sha256": self.source_sha,
                "executables": {name: "b" * 64 for name in GATE._PHASE_IMAGES[phase]}}

    def dispatch(self, fault=None):
        calls = []
        records = dict(self.records)
        def run(command, *, env, timeout):
            self.assertIs(env, self.env)
            phase = command[command.index("--phase") + 1]
            receipt = command[command.index("--receipt") + 1]
            self.assertEqual(timeout, GATE.PHASE_TIMEOUTS[phase])
            self.assertEqual(command[2], self.source)
            self.assertFalse(receipt.exists())
            calls.append(phase)
            value = self.receipt(phase)
            if fault == "child-failure" and phase == "node-controls":
                raise RuntimeError("original owned child failure")
            if fault == "missing":
                return "PASS"
            if fault == "source":
                value["source_sha256"] = "c" * 64
            if fault == "phase":
                value["phase"] = "complete"
            if fault == "target":
                value["architecture"] = "arm64"
            if fault == "image":
                value["executables"].pop(next(iter(value["executables"])))
            if fault == "unrelated-image":
                digest = value["executables"].pop(next(iter(value["executables"])))
                value["executables"]["unrelated.exe"] = digest
            if fault == "mutated-source":
                records["actual-generated-source"] = "d" * 64
            receipt.write_text(json.dumps(value))
            if fault == "oversized":
                receipt.write_text(" " * 32769)
            return "Actual native phase report"
        with patch.object(GATE, "checked_sources", side_effect=lambda source: (source, dict(records))), contextlib.redirect_stdout(io.StringIO()) as stdout:
            try:
                result = GATE.execute_partitioned(self.source, self.env, run)
            except BaseException:
                self.assertNotIn("all six native phases", stdout.getvalue())
                self.assertEqual(len(calls), 2 if fault == "child-failure" else 1)
                raise
        return calls, result, stdout.getvalue()

    def test_packaging_requires_all_serial_exact_source_and_executable_receipts(self):
        calls, results, output = self.dispatch()
        self.assertEqual(tuple(calls), GATE.PHASES)
        self.assertEqual(len(set(calls)), 6)
        self.assertEqual(len(results), 6)
        self.assertIn("all six native phases and their controls passed", output)
        self.assertEqual([len(row["executables"]) for row in results], [3, 6, 3, 7, 3, 3])

    def test_partial_wrong_target_changed_source_or_missing_images_never_complete(self):
        for fault in ("missing", "source", "phase", "target", "image", "unrelated-image", "mutated-source", "oversized"):
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.dispatch(fault)
        with self.assertRaisesRegex(RuntimeError, "original owned child failure"):
            self.dispatch("child-failure")

    def test_complete_set_rejects_missing_duplicate_reordered_and_mixed_sources(self):
        valid = [self.receipt(phase) for phase in GATE.PHASES]
        GATE.validate_phase_set(valid)
        mutations = (valid[:-1], valid + [valid[0]], [valid[0], valid[0], *valid[2:]], list(reversed(valid)))
        for candidate in mutations:
            with self.subTest(phases=[v["phase"] for v in candidate]), self.assertRaises(ValueError):
                GATE.validate_phase_set(candidate)
        valid[-1] = dict(valid[-1], source_sha256="c" * 64)
        with self.assertRaises(ValueError):
            GATE.validate_phase_set(valid)

    def test_default_execution_keeps_complete_inventory_and_failure_propagation(self):
        original = GATE.execute
        calls = []
        def child(source, go, **kwargs):
            calls.append(kwargs["phase"])
            return self.receipt(kwargs["phase"])
        with patch.object(GATE, "execute", side_effect=child), contextlib.redirect_stdout(io.StringIO()):
            results = original(self.source)
        self.assertEqual(tuple(calls), GATE.PHASES)
        self.assertEqual(len(results), 6)
        calls.clear()
        def failed(source, go, **kwargs):
            calls.append(kwargs["phase"])
            raise RuntimeError("native phase failure")
        with patch.object(GATE, "execute", side_effect=failed), self.assertRaisesRegex(RuntimeError, "native phase failure"):
            original(self.source)
        self.assertEqual(calls, [GATE.PHASES[0]])
        with self.assertRaises(ValueError):
            original(self.source, phase="unknown")
        with self.assertRaises(ValueError):
            original(self.source, receipt_path=self.source / "partial.json")

    def test_parent_budgets_cover_existing_serial_child_bounds(self):
        self.assertEqual(set(GATE.PHASES), set(GATE.PHASE_TIMEOUTS))
        self.assertEqual(set(GATE.PHASES), set(GATE._PHASE_IMAGES))
        self.assertEqual(GATE.PHASE_TIMEOUTS["node-baseline"], 2 * 180 + 90 + 60 + 300 + 30 + 600 + 300 + 3600 + 600 + 1215)
        self.assertEqual(GATE.PHASE_TIMEOUTS["node-controls"] - GATE.PHASE_TIMEOUTS["node-baseline"], 4 * (600 + 105) - 600 - 1215)
        self.assertEqual(GATE.PHASE_TIMEOUTS["external-socks"], 2 * 180 + 90 + 60 + 600 + 315 + 6 * (600 + 75))

    def test_builder_calls_complete_phase_orchestrator_without_old_aggregate(self):
        source = (ROOT / "deploy/build-native-runtime.py").read_text()
        self.assertIn("physical.execute_partitioned(source, env, run)", source)
        self.assertNotIn("run([sys.executable, ROOT/'deploy/test_windows_node_physical.py', source],", source)


if __name__ == "__main__":
    unittest.main()
