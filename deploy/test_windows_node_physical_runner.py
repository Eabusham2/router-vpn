#!/usr/bin/env python3
"""Check the native Node test overlay cannot lose its executable-only scope."""
from pathlib import Path
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
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
        self.files.update({relative: ROOT / "mobile/externalpolicy" / name for relative, name in GATE.EXTERNAL_LEASE_SOURCES.items()})
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

    def test_handshake_control_keeps_caller_and_changes_only_readiness_phase(self):
        relative = "routervpn/desktoppt/node_physical.go"
        path = self.source / relative
        original = path.read_text(encoding="utf-8")
        before, after = "owner.SocketCurrentContext(ctx)", "owner.CurrentContext(ctx)"
        self.assertEqual(original.count(before), 1)
        mutation = next(item for item in GATE.mutants(self.source) if item[0] == "late-handshake")
        self.assertEqual(mutation[1:4], (relative, GATE.REQUIRED[0], "actual WFP eager encrypted node startup failed"))
        self.assertEqual(mutation[4], original.replace(before, after, 1))
        self.assertEqual(mutation[4].count(after), 1)
        self.assertNotIn("!owner.Current()", mutation[4])
        selected = GATE.overlay(self.source, self.observer, mutation)
        mapping = json.loads(selected.read_text())["Replace"]
        self.assertEqual(Path(mapping[str(path)]).read_text(encoding="utf-8"), mutation[4])
        self.assertEqual(path.read_bytes(), self.original[relative])
        # A missing or duplicated call is source drift, not permission to
        # mutate a different check or silently omit the compiled control.
        for changed in (original.replace(before, after, 1), original + "\n// " + before + "\n"):
            path.write_text(changed, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exact production boundary"):
                GATE.mutants(self.source)
        path.write_bytes(self.original[relative])

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
        policy = root / "mobile/externalpolicy"
        policy.mkdir(parents=True)
        for name in GATE.EXTERNAL_LEASE_SOURCES.values():
            (policy / name).write_bytes((ROOT / "mobile/externalpolicy" / name).read_bytes())
        for name in ("node_peer_windows_test.go.tmpl", "external_box_windows_hysteria2_test.go.tmpl", "external_box_windows_socks_test.go.tmpl", "external_box_windows_packet_test.go.tmpl", "external_box_windows_server_test.go.tmpl", "external_box_windows_compare_test.go.tmpl", "external_box_windows_alias_test.go.tmpl", "external_box_windows_openvpn_test.go.tmpl", "external_box_windows_ss_entry_test.go.tmpl", "external_box_windows_hysteria2_layer_test.go.tmpl", "external_hysteria_layer_peer_test.go.tmpl"):
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
    def test_retained_grant_observation_precedes_impossible_proof_completion(self):
        source = (ROOT / 'mobile/desktop/external_box_windows_socks_test.go.tmpl').read_text()
        start = source.index('ready, failure := nativeRetirement.ReadyToRelease(probeCtx)')
        joined = source.index('nativeRetirement.RetainedGrantAfterIOClose(observeCtx)', start)
        witness = source.index('joined native I/O retained its original grant and exact WFP filters', joined)
        completion = source.index('case <-done:', start)
        self.assertLess(joined, witness)
        self.assertLess(witness, completion)
        self.assertIn('context.WithDeadline(context.Background(), deadline)', source[start:joined])
        self.assertIn('nativeRetirement.ReleaseHeldEndpoint()', source[completion:])

    def test_exact_retirement_observer_after_full_close_and_during_timeout(self):
        subprocess.run([sys.executable, str(ROOT / 'deploy/test_windows_socket_retirement_observer.py')],
                       check=True, timeout=100)

    def test_identity_observer_rejects_original_publication_lock_wait(self):
        source = (ROOT / 'internal/mobiletor/desktop_socket_windows_identity.go').read_text()
        needle = '\texpected := p.owner.Load()'
        self.assertEqual(source.count(needle), 1)
        mutant = source.replace(needle, '\tp.mu.Lock()\n' + needle + '\n\tp.mu.Unlock()', 1)
        with tempfile.TemporaryDirectory(prefix='identity-observation-control-') as temporary:
            identity = Path(temporary) / 'identity.go'
            identity.write_text(mutant)
            result = subprocess.run(
                [sys.executable, str(ROOT / 'deploy/test_windows_socket_retirement_observer.py'),
                 '--identity', str(identity)], capture_output=True, text=True, timeout=100)
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        expected = 'TestWindowsIdentityCurrentDoesNotWaitForPublicationMutex'
        failures = [line.split(': ', 1)[1].split(' ', 1)[0]
                    for line in output.splitlines() if line.startswith('--- FAIL: ')]
        self.assertEqual(failures, [expected], output)
        self.assertEqual(output.count('native identity observation waited for publication mutex'), 1, output)
        for infrastructure in ('panic:', 'build failed', 'setup failed', 'test timed out', 'DATA RACE'):
            self.assertNotIn(infrastructure, output, output)
        self.assertIn('FAIL\tretirement\t', output)

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
        policy = root / "mobile/externalpolicy"
        policy.mkdir(parents=True)
        for name in GATE.EXTERNAL_LEASE_SOURCES.values():
            (policy / name).write_bytes((ROOT / "mobile/externalpolicy" / name).read_bytes())
        for name in ("node_peer_windows_test.go.tmpl", "external_box_windows_hysteria2_test.go.tmpl", "external_box_windows_socks_test.go.tmpl", "external_box_windows_packet_test.go.tmpl", "external_box_windows_server_test.go.tmpl", "external_box_windows_compare_test.go.tmpl", "external_box_windows_alias_test.go.tmpl", "external_box_windows_openvpn_test.go.tmpl", "external_box_windows_ss_entry_test.go.tmpl", "external_box_windows_hysteria2_layer_test.go.tmpl", "external_hysteria_layer_peer_test.go.tmpl"):
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
            "missing-grant-removal": ("reject/relay-other-private", "joined native I/O retained its original grant and exact WFP filters"),
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
                    "grant-old-completion", "grant-completed-only", "grant-old-timeout", "grant-observation-error"):
                refused = {
                    "grant-old-completion": "native retirement bypassed exact socket release or grant join",
                    "grant-completed-only": "completed native refusal retained its original grant and exact WFP filters",
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
                               ("grant-completed-only", "exact defect"),
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
    def setUp(self):
        OrdinaryHysteria2Scope.setUp(self)
        for relative, actual in (
                ("routervpn_external_policy.go", ROOT / "mobile/externalpolicy/box.go.tmpl"),
                ("routervpn_external_lease_cleanup.go", ROOT / "mobile/externalpolicy/lease_cleanup.go.tmpl"),
                ("experimental/libbox/routervpn/mobilemultihop/lease_cleanup.go", ROOT / "internal/mobilemultihop/lease_cleanup.go")):
            self.original[relative] = actual.read_bytes()
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.original[relative])

    def test_router_local_requires_every_exact_unique_verdict(self):
        required = GATE.EXTERNAL_LOCAL_CASES
        self.assertEqual(len(required), 15)
        self.assertNotIn(GATE.EXTERNAL_LOCAL_ROOT + "/lease-stop-retry", required)
        complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
        with contextlib.redirect_stdout(io.StringIO()):
            GATE.report_external_local(0, complete)
            for case in required:
                line = "--- PASS: " + case + " (0.01s)\n"
                for output in (complete.replace(line, ""), complete + line, complete.replace(line, "expected: " + line)):
                    with self.assertRaises(ValueError): GATE.report_external_local(0, output)

    def test_router_compare_requires_every_exact_unique_verdict(self):
        required = GATE.EXTERNAL_COMPARE_CASES
        self.assertEqual(len(required), 22)
        self.assertEqual(len(required), len(set(required)))
        complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
        with contextlib.redirect_stdout(io.StringIO()):
            GATE.report_external_compare(0, complete)
            for case in required:
                line = "--- PASS: " + case + " (0.01s)\n"
                for output in (complete.replace(line, ""), complete + line, complete.replace(line, "expected: " + line)):
                    with self.assertRaises(ValueError): GATE.report_external_compare(0, output)
            for suffix in ("--- SKIP: hidden", "DATA RACE", "panic: crash", "--- FAIL: hidden", "FAIL"):
                with self.assertRaises(ValueError): GATE.report_external_compare(0, complete + suffix + "\n")

    def test_router_server_requires_every_unique_native_and_retirement_verdict(self):
        required = GATE.EXTERNAL_SERVER_CASES
        self.assertEqual(len(required), 25)
        self.assertIn(GATE.EXTERNAL_SERVER_ROOT + "/lease-stop-retry", required)
        self.assertEqual(len(required), len(set(required)))
        self.assertIn(GATE.EXTERNAL_SERVER_ROOT + "/reject/psk", required)
        self.assertIn(GATE.EXTERNAL_SERVER_ROOT + "/successor-and-original-restore", required)
        complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
        with contextlib.redirect_stdout(io.StringIO()):
            GATE.report_external_server(0, complete)
        bad = [(1, complete)]
        for case in required:
            line = "--- PASS: " + case + " (0.01s)\n"
            bad += [(0, complete.replace(line, "")), (0, complete + line), (0, complete.replace(line, "expected: " + line))]
        bad += [(0, complete + value + "\n") for value in ("--- SKIP: hidden (0.1s)", "DATA RACE", "panic: crash", "fatal error: crash", "[build failed]", "--- FAIL: hidden (0.1s)", "FAIL")]
        for status, output in bad:
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, "required native result"):
                GATE.report_external_server(status, output)

    def test_router_server_groups_retain_all_original_children_and_exact_verdicts(self):
        groups = GATE.EXTERNAL_SERVER_GROUPS
        self.assertEqual(tuple(groups), ("lifecycle", "rejection", "association"))
        combined = []
        for group, (expression, required) in groups.items():
            combined.extend(required)
            self.assertTrue(required)
            self.assertEqual(len(required), len(set(required)))
            # Go's slash-separated matcher admits a parent for its selected
            # descendants; it must not move another child into this process.
            matches = lambda case: all(re.search(pattern, part) for pattern, part in zip(expression.split("/"), case.split("/")))
            self.assertEqual({case for case in GATE.EXTERNAL_SERVER_CASES if matches(case)}, set(required))
            complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
            with contextlib.redirect_stdout(io.StringIO()):
                GATE.report_external_server(0, complete, group)
                for case in required:
                    line = "--- PASS: " + case + " (0.01s)\n"
                    for output in (complete.replace(line, ""), complete + line, complete.replace(line, "expected: " + line)):
                        with self.assertRaises(ValueError): GATE.report_external_server(0, output, group)
                for foreign in set(GATE.EXTERNAL_SERVER_CASES) - set(required):
                    with self.assertRaises(ValueError):
                        GATE.report_external_server(0, complete + "--- PASS: " + foreign + " (0.01s)\n", group)
                for suffix in ("--- SKIP: hidden", "DATA RACE", "panic: crash", "--- FAIL: hidden", "FAIL"):
                    with self.assertRaises(ValueError): GATE.report_external_server(0, complete + suffix + "\n", group)
                with self.assertRaises(ValueError): GATE.report_external_server(1, complete, group)
        self.assertEqual(set(combined), set(GATE.EXTERNAL_SERVER_CASES))
        self.assertEqual(combined.count(GATE.EXTERNAL_SERVER_ROOT), 2)
        for case in set(combined) - {GATE.EXTERNAL_SERVER_ROOT}:
            self.assertEqual(combined.count(case), 1, case)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
            GATE.report_external_server(0, "", "unknown")

    def test_actual_go_filter_executes_every_captured_server_child_in_one_group(self):
        source = (ROOT / "mobile/desktop/external_box_windows_server_test.go.tmpl").read_text()
        server = source[source.index("func desktopWFPTestRouterExecution("):source.index("func desktopWFPRouterServerLeaseStopRetry(")]
        match = re.search(r'for _, name := range (\[\]string\{[^\n]+\})', server)
        self.assertIsNotNone(match)
        association = source.split("func " + GATE.EXTERNAL_SERVER_ASSOCIATION + "(", 1)[1].split("\nfunc ", 1)[0]
        names = re.findall(r't\.Run\("([^"\n]+)"', association)
        self.assertEqual(len(names), 6)
        self.assertEqual(len(names), len(set(names)))
        body = "package inventory\nimport \"testing\"\n"
        body += "func " + GATE.EXTERNAL_SERVER_ROOT + "(t *testing.T){for _, name := range " + match.group(1) + "{t.Run(name,func(t *testing.T){})}}\n"
        body += "func " + GATE.EXTERNAL_SERVER_ASSOCIATION + "(t *testing.T){for _, name := range []string{" + ",".join(json.dumps(name) for name in names) + "}{t.Run(name,func(t *testing.T){})}}\n"
        compiler = shutil.which("go")
        self.assertIsNotNone(compiler, "Go is required for actual native inventory selection")
        with tempfile.TemporaryDirectory(prefix="windows-server-selection-") as directory:
            folder = Path(directory)
            path = folder / "inventory_test.go"
            path.write_text(body)
            binary = folder / ("inventory.test.exe" if os.name == "nt" else "inventory.test")
            built = subprocess.run([compiler, "test", "-c", "-o", str(binary), str(path)],
                                   capture_output=True, text=True, timeout=90,
                                   env=dict(os.environ, GOTOOLCHAIN="local"))
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            for group, (expression, _) in GATE.EXTERNAL_SERVER_GROUPS.items():
                result = subprocess.run([str(binary), "-test.run=" + expression, "-test.v", "-test.timeout=5s"],
                                        capture_output=True, text=True, timeout=10)
                with contextlib.redirect_stdout(io.StringIO()):
                    GATE.report_external_server(result.returncode, result.stdout + result.stderr, group)

    def test_all_shipping_lease_scope_results_are_mandatory(self):
        required = GATE.EXTERNAL_LEASE_UNIT_CASES
        self.assertEqual(len(GATE.EXTERNAL_LEASE_UNIT_ROOTS), 11)
        self.assertEqual(len(required), 21)
        self.assertEqual(len(required), len(set(required)))
        complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
        with contextlib.redirect_stdout(io.StringIO()):
            GATE.report_external_lease_unit(0, complete)
            for case in required:
                line = "--- PASS: " + case + " (0.01s)\n"
                for output in (complete.replace(line, ""), complete + line, complete.replace(line, "expected: " + line)):
                    with self.assertRaises(ValueError): GATE.report_external_lease_unit(0, output)
            for suffix in ("--- SKIP: hidden", "DATA RACE", "panic: crash", "--- FAIL: hidden", "FAIL"):
                with self.assertRaises(ValueError): GATE.report_external_lease_unit(0, complete + suffix + "\n")
            with self.assertRaises(ValueError): GATE.report_external_lease_unit(1, complete)

    def test_lease_generated_source_requires_every_exact_shipping_dependency(self):
        before = GATE.external_lease_sources(self.source)
        self.assertEqual(len(before), 7)
        for relative in GATE.EXTERNAL_LEASE_SOURCES:
            path = self.source / relative
            original = path.read_bytes()
            with self.subTest(relative=relative):
                path.unlink()
                with self.assertRaisesRegex(ValueError, "original generated source"):
                    GATE.external_lease_sources(self.source)
                path.write_bytes(original + b"\n// replaced compiled dependency\n")
                with self.assertRaisesRegex(ValueError, "shipping bytes"):
                    GATE.external_lease_sources(self.source)
                path.write_bytes(original)
        self.assertEqual(GATE.external_lease_sources(self.source), before)

    def test_lease_controls_use_exact_isolated_shipping_copies(self):
        self.assertEqual(len(GATE.EXTERNAL_LEASE_CONTROLS), 6)
        for label, (patches, cases, witness) in GATE.EXTERNAL_LEASE_CONTROLS.items():
            with self.subTest(label=label):
                directory = self.observer / label
                directory.mkdir()
                mapping = json.loads(GATE.external_overlay(self.source, directory, label).read_text())["Replace"]
                self.assertEqual(len(mapping), 5 + len({relative for relative, _, _ in patches}))
                self.assertTrue(cases)
                self.assertTrue(witness)
                for relative, before, after in patches:
                    copy = Path(mapping[str(self.source / relative)]).read_text(encoding="utf-8")
                    self.assertNotIn(before, copy)
                    if after: self.assertIn(after, copy)
                for relative, raw in self.original.items():
                    self.assertEqual((self.source / relative).read_bytes(), raw)
                relative, before, _ = patches[0]
                original = self.source / relative
                raw = original.read_bytes()
                original.write_text(original.read_text(encoding="utf-8").replace(before, "changed-original-boundary", 1), encoding="utf-8")
                try:
                    with self.assertRaisesRegex(ValueError, "exact production boundary"):
                        GATE.external_overlay(self.source, directory, label)
                finally:
                    original.write_bytes(raw)

    def test_packet_fixture_remains_part_of_the_exact_native_scope_digest(self):
        root = self.workspace / "repository"
        mobile = root / "mobile/desktop"
        mobile.mkdir(parents=True)
        policy = root / "mobile/externalpolicy"
        policy.mkdir(parents=True)
        for name in GATE.EXTERNAL_LEASE_SOURCES.values():
            (policy / name).write_bytes((ROOT / "mobile/externalpolicy" / name).read_bytes())
        for name in ("node_peer_windows_test.go.tmpl", "external_box_windows_hysteria2_test.go.tmpl", "external_box_windows_socks_test.go.tmpl", "external_box_windows_packet_test.go.tmpl", "external_box_windows_server_test.go.tmpl", "external_box_windows_compare_test.go.tmpl", "external_box_windows_alias_test.go.tmpl", "external_box_windows_openvpn_test.go.tmpl", "external_box_windows_ss_entry_test.go.tmpl", "external_box_windows_hysteria2_layer_test.go.tmpl", "external_hysteria_layer_peer_test.go.tmpl"):
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
                label = selected.parent.name.removeprefix("external-packet-")
                self.assertEqual(len(json.loads(selected.read_text())["Replace"]), 6 if label == "missing-durable-intent" or label in GATE.EXTERNAL_LEASE_CONTROLS else 5)
                Path(command[command.index("-o") + 1]).write_bytes(b"captured-native-packet-image/" + selected.parent.name.encode())
                return (1, "compile failed") if fault == "compile" or fault == "lease-compile" and label in GATE.EXTERNAL_LEASE_CONTROLS else (0, "")
            binary = Path(command[0])
            if binary.parent.name == "external-packet":
                if "-test.run=^TestRouterVPNExternalLease" in command:
                    self.assertIn("-test.timeout=60s", command)
                    self.assertEqual(kwargs["timeout"], 75)
                    required = GATE.EXTERNAL_LEASE_UNIT_CASES
                    if fault == "lease-leaf": required = required[:-1]
                    if fault == "lease-image": binary.write_bytes(b"changed-lease-image")
                    return 0, "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
                if any("PacketReference|" in value for value in command):
                    self.assertIn("-test.timeout=60s", command)
                    self.assertEqual(kwargs["timeout"], 75)
                    reference = "TestRouterVPNDesktopExternalPacketReference"
                    leaves = (reference + "Authority", *(reference + "/" + protocol for protocol in GATE.EXTERNAL_PACKET_PROTOCOLS))
                    output = "".join("--- PASS: " + case + " (0.01s)\n" for case in leaves)
                    if fault == "reference":
                        output = output.replace("--- PASS: " + leaves[-1] + " (0.01s)\n", "")
                    return 0, output
                if any(GATE.EXTERNAL_COMPARE_ROOT in value for value in command):
                    self.assertEqual(kwargs["timeout"], 195)
                    required = GATE.EXTERNAL_COMPARE_CASES
                    if fault == "compare-leaf": required = required[:-1]
                    if fault == "compare-image": binary.write_bytes(b"changed-compare-image")
                    return 0, "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
                if any(GATE.EXTERNAL_LOCAL_ROOT in value for value in command):
                    self.assertEqual(kwargs["timeout"], 195)
                    required = GATE.EXTERNAL_LOCAL_CASES
                    if fault == "local-leaf": required = required[:-1]
                    if fault == "local-image": binary.write_bytes(b"changed-local-image")
                    return 0, "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
                if any(GATE.EXTERNAL_SERVER_ROOT in value or GATE.EXTERNAL_SERVER_ASSOCIATION in value for value in command):
                    self.assertEqual(kwargs["timeout"], 195)
                    self.assertIn("-test.timeout=180s", command)
                    selected = next(value.removeprefix("-test.run=") for value in command if value.startswith("-test.run="))
                    required = next(required for expression, required in GATE.EXTERNAL_SERVER_GROUPS.values() if expression == selected)
                    if fault == "server-leaf": required = required[:-1]
                    if fault == "server-image": binary.write_bytes(b"changed-server-image")
                    return 0, "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
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
            if label in GATE.EXTERNAL_LEASE_CONTROLS:
                _, cases, witness = GATE.EXTERNAL_LEASE_CONTROLS[label]
                root = cases[0].split("/")[0]
                expression = "^" + GATE.re.escape(root) + "$"
                if all("/" in case for case in cases):
                    expression += "/^(" + "|".join(GATE.re.escape(case.split("/", 1)[1]) for case in cases) + ")$"
                self.assertIn("-test.run=" + expression, command)
                self.assertIn("-test.timeout=60s", command)
                self.assertEqual(kwargs["timeout"], 75)
                output = "".join("--- FAIL: " + case + " (0.01s)\n" + witness + "\n" for case in cases)
                if fault == "lease-prefix": output = output.replace("--- FAIL:", "expected: --- FAIL:")
                if fault == "lease-duplicate": output += output
                if fault == "lease-panic": output += "panic: test timed out\n"
                if isinstance(fault, str) and fault.startswith("lease-cleanup-"):
                    output += "    original_fixture_test.go:1: " + GATE.EXTERNAL_LEASE_CLEANUP_FAILURES[int(fault.removeprefix("lease-cleanup-"))] + "\n"
                if fault == "lease-witness": output = output.replace(witness, "unrelated failure")
                if fault == "lease-mutant-image": binary.write_bytes(b"changed-lease-negative-image")
                return (0 if fault == label else 1), output
            compare = any(GATE.EXTERNAL_COMPARE_ROOT in value for value in command)
            local = any(GATE.EXTERNAL_LOCAL_ROOT in value for value in command)
            server = any(GATE.EXTERNAL_SERVER_ROOT in value for value in command)
            leaf = GATE.EXTERNAL_COMPARE_ROOT + "/always" if compare else GATE.EXTERNAL_LOCAL_ROOT + "/always" if local else GATE.EXTERNAL_SERVER_ROOT + "/always" if server else GATE.EXTERNAL_PACKET_ROOT + "/wireguard/always"
            self.assertIn("-test.run=" + "/".join("^" + p + "$" for p in leaf.split("/")), command)
            self.assertIn("-test.timeout=60s", command)
            self.assertEqual(kwargs["timeout"], 75)
            witness = "actual Router Compare source skipped its durable WFP intent" if compare and label == "missing-durable-intent" else "actual Router Local source skipped its durable WFP intent" if local and label == "missing-durable-intent" else "actual Router Server source skipped its durable WFP intent" if server and label == "missing-durable-intent" else witnesses[label]
            output = "--- FAIL: " + leaf + " (0.01s)\n" + witness + "\n"
            if fault == "prefix":
                output = "expected: " + output
            if fault == "duplicate":
                output += output
            if fault == "panic":
                output += "panic: test timed out\n"
            if fault == "witness":
                output = output.replace(witness, "unrelated failure")
            if fault == "mutant-image":
                binary.write_bytes(b"changed-negative-image")
            return (0 if fault == label else 1), output
        build = ["owned-go", "test", "-c", "-mod=readonly", "-race", "-tags=windows,routervpn_windows_node_composition"]
        with patch.object(GATE.BOOT.IDENTITY, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            GATE.execute_external_packet(self.source, self.workspace, build, {"captured": "environment"})
        return calls

    def test_packet_native_scope_and_lease_controls_keep_each_owned_image(self):
        calls = self.dispatch()
        self.assertEqual([timeout for _, timeout in calls], [600, 75, 75] + [195] * (5 + len(GATE.EXTERNAL_SERVER_GROUPS)) + [600, 75, 75, 75, 75, 600, 75, 75, 75, 75] + [600, 75] * len(GATE.EXTERNAL_LEASE_CONTROLS))
        self.assertEqual(len({command[command.index("-o") + 1] for command, _ in calls if "-c" in command}), 3 + len(GATE.EXTERNAL_LEASE_CONTROLS))
        self.assertEqual(len({command[0] for command, timeout in calls if timeout == 195}), 1)

    def test_packet_dispatch_rejects_changed_images_missing_leaves_and_invalid_controls(self):
        for fault, message in (("compile", "compilation failed"), ("image", "native executable changed"), ("leaf", "required native result"), ("reference", "required encrypted result"), ("server-leaf", "required native result"), ("server-image", "native executable changed"), ("local-leaf", "required native result"), ("local-image", "native executable changed"), ("compare-leaf", "required native result"), ("compare-image", "native executable changed"),
                               ("ordinary-udp-deny", "exact defect"), ("missing-durable-intent", "exact defect"),
                               ("lease-leaf", "required result"), ("lease-image", "native executable changed"), ("lease-compile", "control did not compile"),
                               ("lease-prefix", "exact defect"), ("lease-duplicate", "exact defect"), ("lease-panic", "exact defect"), ("lease-witness", "exact defect"), ("lease-mutant-image", "control executable changed"),
                               *((label, "exact defect") for label in GATE.EXTERNAL_LEASE_CONTROLS),
                               *(("lease-cleanup-" + str(index), "exact defect") for index in range(len(GATE.EXTERNAL_LEASE_CLEANUP_FAILURES))),
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


class LeaseRetryFailureRecovery(unittest.TestCase):
    def test_actual_fixture_defers_writable_stream_failure_until_original_retry_and_close(self):
        source = (ROOT / "mobile/desktop/external_box_windows_server_test.go.tmpl").read_text()
        helper = source[source.index("func desktopWFPRouterServerLeaseStopRetry("):]
        start = helper.index("\tvar retirementFailure error\n")
        end = helper.index("\n\tselect{\n\tcase <-cancelled:", start)
        observed = helper[start:end]
        retry = helper[helper.index("\tif err:=f.proof.Close();err==nil{"):]
        self.assertTrue(retry.endswith("\n}\n"))
        retry = retry[:-2]
        failure = 'retirementFailure=fmt.Errorf("returned native data stream remained writable after lease cancellation: %d %v",n,err)'
        self.assertEqual(observed.count(failure), 1)
        # Run the actual observation and stop/retry/stream-close statements.
        # Native WFP/quiescence and HTTP transport remain separate native gates;
        # these explicit doubles test the fixture's FailNow and cleanup order.
        header = r'''package leasefixture
import("errors";"fmt";"net";"os";"testing")
type originalStream struct{writable,closed,failClose bool}
func(c *originalStream)Write(p []byte)(int,error){if c.writable{return len(p),nil};return 0,net.ErrClosed}
func(c *originalStream)Close()error{if c.failClose{return errors.New("original stream refuses close")};c.closed=true;return nil}
type originalProof struct{calls int;failRetry bool}
func(p *originalProof)Close()error{p.calls++;if p.calls==1{return errors.New("original invalid stop receipt")};if p.failRetry{return errors.New("original retry refuses close")};return nil}
type originalFixture struct{proof *originalProof;closed bool}
type originalReceipt struct{Deletes int;Live,StopRequestsMatch bool}
type originalReply struct{RouterServer *originalReceipt}
type originalPeer struct{proof *originalProof}
func(p *originalPeer)call(t *testing.T,method,body string)originalReply{t.Helper();if method!="stats"||body!=""{t.Fatal("fixture changed original peer request")};return originalReply{&originalReceipt{Deletes:p.proof.calls,StopRequestsMatch:true}}}
func replay(t *testing.T,f *originalFixture,peer *originalPeer,connection *originalStream)error{
 t.Helper()
 defer connection.Close()
 readback:=func()int{return 0}
'''
        check = r'''
func TestOriginalLeaseFixtureRecovery(t *testing.T){
 mode:=os.Getenv("ROUTERVPN_LEASE_FIXTURE_MODE")
 connection:=&originalStream{writable:mode!="retired",failClose:mode=="stream-failure"}
 f:=&originalFixture{proof:&originalProof{failRetry:mode=="retry-failure"}}
 peer:=&originalPeer{proof:f.proof}
 failure:=replay(t,f,peer,connection)
 if f.proof.calls!=2||!connection.closed{t.Fatal("original fixture returned before stop retry and stream cleanup")}
 if mode=="retired"&&failure!=nil||mode=="writable"&&failure==nil{t.Fatal("fixture changed the observed retirement result")}
 if failure!=nil&&failure.Error()!="returned native data stream remained writable after lease cancellation: 7 <nil>"{t.Fatal("fixture lost exact original writable-stream witness",failure)}
}
'''
        compiler = shutil.which("go")
        self.assertIsNotNone(compiler, "Go is required for the original lease fixture recovery regression")
        with tempfile.TemporaryDirectory(prefix="windows-lease-fixture-") as directory:
            folder = Path(directory)
            path = folder / "fixture_test.go"
            binary = folder / ("fixture.test.exe" if os.name == "nt" else "fixture.test")
            for variant in ("current", "original-fatal"):
                observation = observed if variant == "current" else observed.replace(failure, 't.Fatal(fmt.Errorf("returned native data stream remained writable after lease cancellation: %d %v",n,err))')
                path.write_text(header + observation + "\n" + retry + "}\n" + check)
                built = subprocess.run([compiler, "test", "-c", "-o", str(binary), str(path)],
                                       capture_output=True, text=True, timeout=90,
                                       env=dict(os.environ, GOTOOLCHAIN="local"))
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                modes = ("retired", "writable", "retry-failure", "stream-failure") if variant == "current" else ("writable",)
                for mode in modes:
                    with self.subTest(variant=variant, mode=mode):
                        result = subprocess.run([str(binary), "-test.run=^TestOriginalLeaseFixtureRecovery$", "-test.v", "-test.timeout=5s"],
                                                capture_output=True, text=True, timeout=10,
                                                env=dict(os.environ, ROUTERVPN_LEASE_FIXTURE_MODE=mode))
                        output = result.stdout + result.stderr
                        if variant == "current" and mode in ("retired", "writable"):
                            self.assertEqual(result.returncode, 0, output)
                            self.assertIn("--- PASS: TestOriginalLeaseFixtureRecovery (", output)
                        else:
                            self.assertNotEqual(result.returncode, 0, output)
                            self.assertIn("--- FAIL: TestOriginalLeaseFixtureRecovery (", output)
                            expected = "returned native data stream remained writable after lease cancellation" if variant == "original-fatal" else "same native Server stop could not retry" if mode == "retry-failure" else "original native data stream recovery did not join"
                            self.assertIn(expected, output)
                            if variant == "current":
                                self.assertNotIn("returned native data stream remained writable after lease cancellation", output)
                        for invalid in ("panic:", "fatal error:", "DATA RACE", "[build failed]", "fixture changed original peer request"):
                            self.assertNotIn(invalid, output)
        # The returned defect is published only after the unchanged native
        # teardown and original lease/blocked-path observations in the caller.
        caller = source[source.index("func desktopWFPTestRouterExecution("):source.index("func desktopWFPRouterServerLeaseStopRetry(")]
        observed_at = caller.index("retirementFailure = desktopWFPRouterServerLeaseStopRetry(")
        drained_at = caller.index("retained = f.drain(t)", observed_at)
        blocked_at = caller.index("desktopExternalWFPRequireBlocked(t, peer)", drained_at)
        self.assertGreater(caller.index("if retirementFailure != nil { t.Fatal(retirementFailure) }"), blocked_at)


class OrdinaryOpenVPNScope(unittest.TestCase):
    setUp = OrdinaryHysteria2Scope.setUp

    def test_each_alias_and_transport_verdict_is_unique_and_mandatory(self):
        self.assertEqual(GATE.EXTERNAL_OPENVPN_NETWORKS, ("tcp", "udp", "mixed"))
        self.assertIn(GATE.EXTERNAL_OPENVPN_ALIAS + "/unavailable-tcp-reservation", GATE.EXTERNAL_OPENVPN_ALIAS_CASES)
        self.assertEqual(len(GATE.EXTERNAL_OPENVPN_ALIAS_CASES), 11)
        self.assertEqual(GATE.EXTERNAL_OPENVPN_LEAVES, ("on-connect", "always", "successor-and-original-restore", "reject/trust", "reject/control-key", "reject/dns", "cancelled-proof", "foreign-predecessor", "commit-refused"))
        self.assertEqual(len(GATE.EXTERNAL_OPENVPN_CODEC_CASES), 27)
        self.assertEqual(len(GATE.EXTERNAL_OPENVPN_OWNERSHIP_CASES), 22)
        for network in GATE.EXTERNAL_OPENVPN_INVOCATIONS:
            required = GATE.external_openvpn_cases(network)
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
                network = next(value for value in GATE.EXTERNAL_OPENVPN_INVOCATIONS if "-test.run=" + expression == GATE.external_openvpn_arguments(value)[0])
                self.assertEqual([value for value in command if value.startswith(("-test.run=", "-test.skip="))], GATE.external_openvpn_arguments(network))
                self.assertIn("-test.timeout=" + ("60s" if network in ("alias", "witness") else "180s"), command)
                required = GATE.external_openvpn_cases(network)
                if fault == "image":
                    binary.write_bytes(b"foreign image")
                if fault == "leaf":
                    required = required[:-1]
                return 0, "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
            label = binary.parent.name.removeprefix("external-openvpn-")
            controls = {
                "ordinary-udp-deny": (GATE.EXTERNAL_OPENVPN_ROOT + "/udp/always", "ordinary token bypassed actual external WFP UDP deny: independent peer marker"),
                "missing-durable-intent": (GATE.EXTERNAL_OPENVPN_ROOT + "/udp/always", "actual OpenVPN source skipped its durable WFP intent"),
                "missing-mac-callback": (GATE.EXTERNAL_OPENVPN_CODEC + "/tls-crypt/wrong-mac", "actual failed control MAC did not emit exactly one final-candidate witness"),
                "missing-session-correlation": (GATE.EXTERNAL_OPENVPN_OWNERSHIP + "/wrong-session", "stale OpenVPN MAC event matched a replacement session"),
                "missing-proof-read": (GATE.EXTERNAL_OPENVPN_ROOT + "/udp/reject/control-key", "original OpenVPN proof did not observe its captured pending remote"),
            }
            leaf, witness = controls[label]
            self.assertIn("-test.timeout=60s", command)
            self.assertIn("-test.run=" + "/".join("^" + part + "$" for part in leaf.split("/")), command)
            output = "--- FAIL: " + leaf + " (0.01s)\n" + witness
            if fault == "prefix": output = "expected: " + output
            if fault == "duplicate": output += "\n" + output
            if fault == "panic": output += "\npanic: deadline"
            if fault == "witness": output = output.replace(witness, "unrelated failure")
            if fault == "mutant-image": binary.write_bytes(b"foreign negative image")
            return (0 if fault == label else 1), output
        # This is the orchestration test boundary; real module/fixture compiler
        # overlay checks have their own source-scope tests and native execution.
        with patch.object(GATE.OPENVPN_BOX, "compose", side_effect=lambda source, directory, existing, mutation=None: existing), patch.object(GATE.BOOT.IDENTITY, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            GATE.execute_external_openvpn(self.source, self.workspace, ["go", "test", "-c", "-mod=readonly", "-race"], {})
        return calls

    def test_openvpn_builds_are_separate_and_all_native_cases_and_controls_execute(self):
        calls = self.dispatch()
        self.assertEqual([timeout for _, timeout in calls], [600, 75, 75, 195, 195, 195, 195, 600, 75, 600, 75, 600, 75, 600, 75, 600, 75])
        self.assertEqual(len({command[0] for command, timeout in calls if timeout == 195}), 1)

    def test_native_openvpn_rejects_spoofed_controls_changed_images_and_omitted_results(self):
        for fault, message in (("compile", "compilation failed"), ("image", "native executable changed"), ("leaf", "required native result"),
                               ("ordinary-udp-deny", "exact defect"), ("missing-durable-intent", "exact defect"),
                               ("missing-mac-callback", "exact defect"), ("missing-session-correlation", "exact defect"), ("missing-proof-read", "exact defect"),
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



    def test_mixed_partitions_preserve_every_original_leaf_once_and_exact_go_arguments(self):
        root = GATE.EXTERNAL_OPENVPN_ROOT
        self.assertEqual(GATE.EXTERNAL_OPENVPN_INVOCATIONS, ("alias", "witness", "tcp", "udp", "mixed", "mixed-control-key"))
        exact = "^" + root + "$/^mixed$/^reject$/^control-key$"
        self.assertEqual(GATE.external_openvpn_arguments("mixed"), ["-test.run=^" + root + "$/^mixed$", "-test.skip=" + exact])
        self.assertEqual(GATE.external_openvpn_arguments("mixed-control-key"), ["-test.run=" + exact])
        mixed = GATE.external_openvpn_cases("mixed")
        control = GATE.external_openvpn_cases("mixed-control-key")
        self.assertEqual(mixed[:2], (root, root + "/mixed"))
        self.assertEqual(control, (root, root + "/mixed", root + "/mixed/reject/control-key"))
        leaves = mixed[2:] + control[2:]
        self.assertEqual(len(leaves), 9)
        self.assertEqual(len(set(leaves)), 9)
        self.assertEqual(set(leaves), set(GATE.EXTERNAL_OPENVPN_CASES["mixed"][2:]))
        with self.assertRaisesRegex(ValueError, "Unknown mandatory"):
            GATE.external_openvpn_arguments("unowned")

    def test_wrong_partition_leaf_is_never_accepted(self):
        for network, foreign in (("mixed", GATE.EXTERNAL_OPENVPN_MIXED_CONTROL),
                                 ("mixed-control-key", GATE.EXTERNAL_OPENVPN_ROOT + "/mixed/on-connect")):
            complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in GATE.external_openvpn_cases(network))
            with self.subTest(network=network), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "required native result"):
                    GATE.report_external_openvpn(0, complete + "--- PASS: " + foreign + " (0.01s)\n", network)

    def test_original_phase_budget_includes_separate_mixed_control_and_fifth_mutant(self):
        self.assertEqual(GATE.PHASE_TIMEOUTS["external-openvpn"], GATE._PHASE_COMMON + 600 + 2 * 75 + 4 * 195 + 5 * (600 + 75))
        images = GATE._PHASE_IMAGES["external-openvpn"]
        self.assertEqual(len(images), 6)
        self.assertEqual(len(set(images)), 6)
        self.assertIn("external-openvpn-missing-proof-read/external-openvpn.test.exe", images)

class OpenVPNWitnessCompilerScope(unittest.TestCase):
    """Exercise compiler-copy ownership; native codec results are tested in Go."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="windows-openvpn-witness-")
        self.addCleanup(self.temporary.cleanup)
        # Compose resolves the real source before validating its exact overlay
        # keys. Windows TEMP may use the same profile through a short alias.
        self.workspace = Path(self.temporary.name).resolve()
        self.source = self.workspace / "core"
        self.source.mkdir()
        self.directory = self.workspace / "compiler"
        self.directory.mkdir()
        self.helper = GATE.OPENVPN_BOX
        self.original = {}
        for name, target in (
                ("external_box_openvpn_reference_test.go.tmpl", "routervpn_desktop_external_box_openvpn_reference_test.go"),
                ("external_box_windows_openvpn_test.go.tmpl", "routervpn_desktop_external_box_windows_openvpn_test.go")):
            raw = (ROOT / "mobile/desktop" / name).read_bytes()
            self.original[target] = raw
            (self.source / target).write_bytes(raw)
        proof = self.helper.PROOF.read_bytes()
        self.original["routervpn_external_policy.go"] = proof
        (self.source / "routervpn_external_policy.go").write_bytes(proof)
        self.existing = self.directory / "native.json"
        self.native = {str(self.source / "original-native.go"): str(self.directory / "original-native.go")}
        Path(next(iter(self.native.values()))).write_text("package box\n// original native boundary\n")
        kernel = self.directory / "kernel-observer.go"
        kernel.write_bytes((ROOT / "deploy/fixtures/windows-node-physical/kernel_observer.go").read_bytes())
        self.native[str(self.source / "routervpn/mobiletor/desktop_socket_windows_node_composition_overlay.go")] = str(kernel)
        self.existing.write_text(json.dumps({"Replace": self.native}))

    def module_overlay(self, source, directory):
        # The pinned-module verifier is a separate, actual native-build boundary.
        # This fixture isolates composing its owned map without network downloads.
        staged = Path(directory) / "module-owned"
        staged.mkdir()
        mapping = {}
        for name in ("control_wrap.go", "udp_predecrypt.go", "server_listener.go", "client_session_tls.go",
                     "routervpn_test_control_witness.go", "routervpn_test_control_codec.go"):
            target = Path(source) / self.helper.MODULE.POLICY.COPY / name
            copied = staged / name
            text = "package openvpn\n"
            if name == "control_wrap.go":
                text += "if c.routerVPNTestMACRejected != nil {\n\tc.routerVPNTestMACRejected()\n}\n" * 2
            copied.write_text(text)
            mapping[str(target)] = str(copied)
        copied = staged / "endpoint.go"
        copied.write_text("package openvpn\n")
        mapping[str(Path(source) / "protocol/openvpn/routervpn_test_control_witness.go")] = str(copied)
        path = staged / "overlay.json"
        path.write_text(json.dumps({"Replace": mapping}))
        return path

    def compose(self, mutation=None):
        with patch.object(self.helper.MODULE, "overlay", side_effect=self.module_overlay), patch.object(self.helper.MODULE, "checked_sources", return_value={}) as verified:
            result = self.helper.compose(self.source, self.directory, self.existing, mutation)
        verified.assert_called_once_with(self.source)
        return json.loads(result.read_text())["Replace"]

    def test_original_native_map_and_source_fixtures_survive_composition(self):
        mapping = self.compose()
        for target, path in self.native.items():
            self.assertEqual(mapping[target], path)
        for target, raw in self.original.items():
            self.assertEqual((self.source / target).read_bytes(), raw)
        provider = Path(mapping[str(self.source / "routervpn_desktop_external_box_openvpn_reference_test.go")]).read_text()
        self.assertIn("ControlMode: request.Control, ControlRejects: controlWitness.Snapshot()", provider)
        self.assertIn("reply.ControlMode != p.initial.ControlMode", provider)
        self.assertIn("p.initial.ControlMode != request.Control", provider)
        self.assertIn("len(p.initial.ControlRejects.Events) != 0", provider)
        self.assertIn("initialContext, initialCancel := context.WithTimeout(ctx, 10*time.Second)", provider)
        rejection = Path(mapping[str(self.source / "routervpn_desktop_external_box_windows_openvpn_test.go")]).read_text()
        self.assertIn('if fault == "reject/control-key" && provider.network == "udp"', rejection)
        self.assertIn("alias.original.Address.Addr()", rejection)
        self.assertIn("expected[tuple]", rejection)
        self.assertEqual(self.existing.read_text(), json.dumps({"Replace": self.native}))

    def test_changed_original_fixture_is_rejected(self):
        target = self.source / "routervpn_desktop_external_box_openvpn_reference_test.go"
        target.write_bytes(target.read_bytes() + b"\n// another source owner\n")
        with self.assertRaisesRegex(ValueError, "exact original prepared fixture"):
            self.compose()

    def test_existing_box_witness_is_never_adopted(self):
        target = self.source / "routervpn_desktop_external_windows_openvpn_control_witness_test.go"
        target.write_text("package box\n// another owner\n")
        with self.assertRaisesRegex(ValueError, "Unowned OpenVPN box witness"):
            self.compose()
        self.assertIn("another owner", target.read_text())

    def test_missing_original_native_observer_is_rejected(self):
        target = str(self.source / "routervpn/mobiletor/desktop_socket_windows_node_composition_overlay.go")
        del self.native[target]
        self.existing.write_text(json.dumps({"Replace": self.native}))
        with self.assertRaisesRegex(ValueError, "original strict native observer"):
            self.compose()

    def test_changed_original_native_observer_is_rejected(self):
        target = str(self.source / "routervpn/mobiletor/desktop_socket_windows_node_composition_overlay.go")
        original = Path(self.native[target])
        original.write_bytes(original.read_bytes() + b"\n// another native observer\n")
        with self.assertRaisesRegex(ValueError, "native observer changed before bounded acquisition"):
            self.compose()

    def test_mac_callback_control_changes_only_both_original_hook_guards(self):
        mapping = self.compose("missing-mac-callback")
        copied = Path(mapping[str(self.source / self.helper.MODULE.POLICY.COPY / "control_wrap.go")]).read_text()
        self.assertEqual(copied.count("if false && c.routerVPNTestMACRejected != nil {"), 2)
        self.assertEqual(copied.count("\tc.routerVPNTestMACRejected()"), 2)

    def test_session_control_changes_only_the_matching_guard(self):
        mapping = self.compose("missing-session-correlation")
        target = self.source / "routervpn_desktop_external_windows_openvpn_control_witness_test.go"
        changed = Path(mapping[str(target)]).read_text()
        actual = self.helper.BOX.read_text()
        self.assertEqual(changed, actual.replace(
            "if event.SessionID == view.SessionID && event.Network == view.Network",
            "if true && event.Network == view.Network", 1))
        self.assertIn("event.SessionID != view.SessionID", changed)

    def test_proof_observer_is_fresh_atomic_and_preserves_original_call_and_returns(self):
        original = self.helper.PROOF.read_text()
        actual = self.helper.proof_source(original)
        field = "\trouterVPNTestOpenVPNProofRead atomic.Pointer[func(string, adapter.Outbound, nativeopenvpn.RemoteReceipt, error)]\n"
        old = "\treceipt, err := endpoint.RouterVPNConnectedRemoteContext(ctx)\n"
        observation = (
            "\tobserver := e.routerVPNTestOpenVPNProofRead.Load()\n"
            "\treceipt, err := endpoint.RouterVPNConnectedRemoteContext(ctx)\n"
            "\tif observer != nil && e.routerVPNTestOpenVPNProofRead.Load() == observer &&\n"
            "\t\tctx.Err() == nil && e.routes[tag] == owner {\n"
            "\t\t(*observer)(tag, owner, receipt, err)\n"
            "\t}\n")
        expected = original.replace("type routerVPNExternalNativeEngine struct {\n", "type routerVPNExternalNativeEngine struct {\n" + field, 1).replace(old, observation, 1)
        self.assertEqual(actual, expected)
        self.assertEqual(actual.replace(field, "", 1).replace(observation, old, 1), original)
        self.assertIn(self.helper.PROOF, self.helper.inputs())

    def test_proof_mutant_changes_only_the_original_observer_guard(self):
        mapping = self.compose("missing-proof-read")
        target = self.source / "routervpn_external_policy.go"
        actual = self.helper.proof_source(self.helper.PROOF.read_text())
        changed = Path(mapping[str(target)]).read_text()
        self.assertEqual(changed, actual.replace("if observer != nil", "if false && observer != nil", 1))
        self.assertEqual(target.read_bytes(), self.original[target.name])

    def test_changed_prepared_proof_is_rejected(self):
        target = self.source / "routervpn_external_policy.go"
        target.write_bytes(target.read_bytes() + b"\n// foreign proof source\n")
        with self.assertRaisesRegex(ValueError, "exact original proof source"):
            self.compose()

    def test_existing_proof_compiler_owner_is_never_replaced(self):
        target = str(self.source / "routervpn_external_policy.go")
        original = self.directory / "foreign-proof.go"
        original.write_text("package box\n// original separate compiler owner\n")
        self.native[target] = str(original)
        self.existing.write_text(json.dumps({"Replace": self.native}))
        with self.assertRaisesRegex(ValueError, "replace another compiler owner"):
            self.compose()
        self.assertEqual(original.read_text(), "package box\n// original separate compiler owner\n")
        self.assertEqual(json.loads(self.existing.read_text())["Replace"][target], str(original))

    def test_provider_lifetime_is_original_and_observer_removal_follows_join(self):
        raw = (ROOT / "mobile/desktop/external_box_openvpn_reference_test.go.tmpl").read_text()
        provider = self.helper.provider_source(raw)
        self.assertIn("context.WithTimeout(context.Background(), 100*time.Second)", raw)
        self.assertEqual(provider.count("context.WithTimeout(context.Background(), 100*time.Second)"), raw.count("context.WithTimeout(context.Background(), 100*time.Second)"))
        self.assertIn("lifetime: ctx", provider)
        witness = self.helper.BOX.read_text()
        self.assertIn("context.WithTimeout(peer.lifetime, budget)", witness)
        self.assertIn("budget = 90*time.Second", witness)
        self.assertLess(witness.index("failure = errors.Join(failure, join())"), witness.index("CompareAndSwap(proofObserver, nil)"))
        self.assertIn("if joined && proofObserver != nil", witness)

    def test_unknown_control_is_rejected_before_any_module_staging(self):
        with patch.object(self.helper.MODULE, "overlay") as module:
            with self.assertRaisesRegex(ValueError, "Unknown OpenVPN MAC witness mutation"):
                self.helper.compose(self.source, self.directory, self.existing, "unowned")
        module.assert_not_called()


class OrdinarySSEntryScope(unittest.TestCase):
    setUp = OrdinaryHysteria2Scope.setUp

    def test_each_alias_and_transport_verdict_is_unique_and_mandatory(self):
        self.assertEqual(GATE.EXTERNAL_SS_ENTRY_NETWORKS, ("shadowsocks", "http-connect", "https-connect", "hysteria2"))
        self.assertEqual(len(GATE.EXTERNAL_SS_ENTRY_LEAVES), 13)
        expected_layers = {"layers/" + entry + "/" + final for entry in ("off", "aes-256-gcm", "aes-256-gcm+xor-whitening") for final in ("off", "aes-256-gcm", "aes-256-gcm+xor-whitening")} | {"reject/"+fault for fault in ("entry-layer-key","final-layer-key","entry-whitening","final-whitening","entry-layer-inner","final-layer-inner")}
        self.assertEqual(set(GATE.EXTERNAL_SS_ENTRY_LAYER_LEAVES), expected_layers | {"receipt-identity", "retired-initial-packet"})
        self.assertEqual(len(GATE.EXTERNAL_SS_ENTRY_CASES["shadowsocks"]), 32)
        self.assertEqual(len(GATE.EXTERNAL_SS_ENTRY_CASES["hysteria2"]), 32)
        self.assertIn(GATE.EXTERNAL_SS_ENTRY_ROOT + "/hysteria2/reject/final-trust", GATE.EXTERNAL_SS_ENTRY_CASES["hysteria2"])
        self.assertIn(GATE.EXTERNAL_SS_ENTRY_ROOT + "/hysteria2/final-wrapper-tcp-denied", GATE.EXTERNAL_SS_ENTRY_CASES["hysteria2"])
        self.assertEqual(set(GATE.EXTERNAL_SS_ENTRY_LAYER_TRAFFIC_LEAVES), expected_layers)
        for network in GATE.EXTERNAL_SS_ENTRY_NETWORKS:
            required = GATE.EXTERNAL_SS_ENTRY_CASES[network]
            complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
            with contextlib.redirect_stdout(io.StringIO()):
                GATE.report_external_ss_entry(0, complete, network)
            bad = [(1, complete)]
            bad += [(0, complete + value + "\n") for value in ("--- SKIP: hidden (0.1s)", "DATA RACE", "panic: crash", "fatal error: crash", "[build failed]", "--- FAIL: hidden (0.1s)", "FAIL")]
            for case in required:
                verdict = "--- PASS: " + case + " (0.01s)\n"
                bad += [(0, complete.replace(verdict, "")), (0, complete.replace(verdict, "expected: " + verdict)), (0, complete + verdict)]
            for status, output in bad:
                with self.subTest(network=network), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, "required native result"):
                        GATE.report_external_ss_entry(status, output, network)

    def test_groups_keep_every_original_leaf_once_and_refuse_foreign_or_missing_verdicts(self):
        self.assertEqual(tuple(GATE.EXTERNAL_SS_ENTRY_GROUPS), GATE.EXTERNAL_SS_ENTRY_NETWORKS)
        self.assertEqual([len(groups) for groups in GATE.EXTERNAL_SS_ENTRY_GROUPS.values()], [4, 2, 2, 3])
        for network, groups in GATE.EXTERNAL_SS_ENTRY_GROUPS.items():
            required = GATE.EXTERNAL_SS_ENTRY_CASES[network]
            captured = []
            for group, (expression, cases) in groups.items():
                captured.extend(cases[2:])
                self.assertEqual(cases[:2], required[:2])
                self.assertEqual(len(cases), len(set(cases)))
                matches = lambda case: all(re.search(pattern, part) for pattern, part in zip(expression.split("/"), case.split("/")))
                self.assertEqual({case for case in required if matches(case)}, set(cases))
                complete = "".join("--- PASS: " + case + " (0.01s)\n" for case in cases)
                with contextlib.redirect_stdout(io.StringIO()):
                    GATE.report_external_ss_entry(0, complete, network, group)
                    for case in cases:
                        line = "--- PASS: " + case + " (0.01s)\n"
                        for output in (complete.replace(line, ""), complete + line, complete.replace(line, "expected: " + line)):
                            with self.assertRaises(ValueError): GATE.report_external_ss_entry(0, output, network, group)
                    for foreign in set(required) - set(cases):
                        with self.assertRaises(ValueError):
                            GATE.report_external_ss_entry(0, complete + "--- PASS: " + foreign + " (0.01s)\n", network, group)
                    for suffix in ("--- SKIP: hidden", "DATA RACE", "panic: crash", "--- FAIL: hidden", "FAIL"):
                        with self.assertRaises(ValueError): GATE.report_external_ss_entry(0, complete + suffix + "\n", network, group)
                    with self.assertRaises(ValueError): GATE.report_external_ss_entry(1, complete, network, group)
            self.assertEqual(set(captured), set(required[2:]))
            self.assertEqual(len(captured), len(required) - 2)
            self.assertEqual(len(captured), len(set(captured)))
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                GATE.report_external_ss_entry(0, "", network, "unknown")
        with patch.object(GATE, "EXTERNAL_SS_ENTRY_CASES", {"shadowsocks": (*GATE.EXTERNAL_SS_ENTRY_CASES["shadowsocks"], GATE.EXTERNAL_SS_ENTRY_CASES["shadowsocks"][-1])}):
            with self.assertRaisesRegex(ValueError, "complete native inventory"):
                GATE.external_ss_entry_groups()
        with patch.object(GATE, "EXTERNAL_SS_ENTRY_CASES", {"shadowsocks": (*GATE.EXTERNAL_SS_ENTRY_CASES["shadowsocks"], GATE.EXTERNAL_SS_ENTRY_ROOT + "/shadowsocks/unowned/child")}):
            with self.assertRaisesRegex(ValueError, "complete native inventory"):
                GATE.external_ss_entry_groups()

    def test_actual_go_filter_covers_source_names_and_rejects_omitted_or_repeated_execution(self):
        source = (ROOT / "mobile/desktop/external_box_windows_ss_entry_test.go.tmpl").read_text()
        start = source.index('\tfor _, final := range []string{', source.index("func " + GATE.EXTERNAL_SS_ENTRY_ROOT + "("))
        end = source.index('\t\t\tfor _, name := range names {', start)
        original_names = source[start:end]
        self.assertIn('names = append(names, "layers/"+entry+"/"+last)', original_names)
        body = "package inventory\nimport \"testing\"\nfunc " + GATE.EXTERNAL_SS_ENTRY_ROOT + "(t *testing.T){\n" + original_names
        body += '\t\t\tfor _, name := range names {\nCONTROL\n\t\t\t\tt.Run(name,func(t *testing.T){})\n\t\t\t}\n\t\t})\n\t}\n}\n'
        omitted = 'if final == "shadowsocks" && name == "layers/aes-256-gcm+xor-whitening/aes-256-gcm+xor-whitening" { continue }'
        compiler = shutil.which("go")
        self.assertIsNotNone(compiler, "Go is required for actual SS entry inventory selection")
        with tempfile.TemporaryDirectory(prefix="windows-ss-entry-selection-") as directory:
            folder = Path(directory)
            path = folder / "inventory_test.go"
            binary = folder / ("inventory.test.exe" if os.name == "nt" else "inventory.test")
            for control in ("", omitted):
                path.write_text(body.replace("CONTROL", control))
                built = subprocess.run([compiler, "test", "-c", "-o", str(binary), str(path)],
                                       capture_output=True, text=True, timeout=90,
                                       env=dict(os.environ, GOTOOLCHAIN="local"))
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                selected = ((network, group, expression) for network, groups in GATE.EXTERNAL_SS_ENTRY_GROUPS.items()
                            for group, (expression, _) in groups.items()) if not control else (
                                ("shadowsocks", "layers", GATE.EXTERNAL_SS_ENTRY_GROUPS["shadowsocks"]["layers"][0]),)
                for network, group, expression in selected:
                    def run():
                        return subprocess.run([str(binary), "-test.run=" + expression, "-test.v", "-test.timeout=5s"],
                                              capture_output=True, text=True, timeout=10)
                    result = run()
                    output = result.stdout + result.stderr
                    with contextlib.redirect_stdout(io.StringIO()):
                        if control:
                            self.assertEqual(result.returncode, 0, output)
                            with self.assertRaisesRegex(ValueError, "required native result"):
                                GATE.report_external_ss_entry(result.returncode, output, network, group)
                        else:
                            GATE.report_external_ss_entry(result.returncode, output, network, group)
                            if network == "shadowsocks" and group == "layers":
                                duplicate = run()
                                self.assertEqual(duplicate.returncode, 0, duplicate.stdout + duplicate.stderr)
                                with self.assertRaisesRegex(ValueError, "required native result"):
                                    GATE.report_external_ss_entry(0, output + duplicate.stdout + duplicate.stderr, network, group)

    def dispatch(self, fault=None):
        calls = []
        def run(command, **kwargs):
            command = tuple(map(str, command)); calls.append((command, kwargs["timeout"]))
            if "-c" in command:
                Path(command[command.index("-o") + 1]).write_bytes(b"captured-ss_entry-image")
                return (1, "compile failed") if fault == "compile" else (0, "")
            binary = Path(command[0])
            if binary.parent.name == "external-ss-entry":
                expression = next(value.removeprefix("-test.run=") for value in command if value.startswith("-test.run="))
                required = next(required for groups in GATE.EXTERNAL_SS_ENTRY_GROUPS.values() for selected, required in groups.values() if expression == selected)
                self.assertIn("-test.timeout=180s", command)
                self.assertEqual(kwargs["timeout"], 195)
                if fault == "image":
                    binary.write_bytes(b"foreign image")
                if fault == "leaf":
                    required = required[:-1]
                return 0, "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
            label = binary.parent.name.removeprefix("external-ss-entry-")
            witness = "ordinary token bypassed actual external WFP UDP deny: independent peer marker" if label == "ordinary-udp-deny" else "actual SS entry source skipped its durable WFP intent"
            self.assertIn("-test.run=^" + GATE.EXTERNAL_SS_ENTRY_ROOT + "$/^shadowsocks$/^always$", command)
            output = "--- FAIL: " + GATE.EXTERNAL_SS_ENTRY_ROOT + "/shadowsocks/always (0.01s)\n" + witness
            if fault == "prefix": output = "expected: " + output
            if fault == "duplicate": output += "\n" + output
            if fault == "panic": output += "\npanic: deadline"
            if fault == "witness": output = output.replace(witness, "unrelated failure")
            if fault == "mutant-image": binary.write_bytes(b"foreign negative image")
            return (0 if fault == label else 1), output
        with patch.object(GATE.BOOT.IDENTITY, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            GATE.execute_external_ss_entry(self.source, self.workspace, ["go", "test", "-c", "-mod=readonly", "-race"], {})
        return calls

    def test_ss_entry_builds_are_separate_and_all_native_cases_and_controls_execute(self):
        calls = self.dispatch()
        self.assertEqual([timeout for _, timeout in calls], [600, *([195] * 11), 600, 75, 600, 75])
        self.assertEqual(len({command[0] for command, timeout in calls if timeout == 195}), 1)
        expressions = [next(value.removeprefix("-test.run=") for value in command if value.startswith("-test.run=")) for command, timeout in calls if timeout == 195]
        self.assertEqual(expressions, [expression for groups in GATE.EXTERNAL_SS_ENTRY_GROUPS.values() for expression, _ in groups.values()])
        self.assertEqual(len(expressions), len(set(expressions)))

    def test_native_ss_entry_rejects_spoofed_controls_changed_images_and_omitted_results(self):
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
                self.assertNotIn("all seven native phases", stdout.getvalue())
                self.assertEqual(len(calls), 2 if fault == "child-failure" else 1)
                raise
        return calls, result, stdout.getvalue()

    def test_packaging_requires_all_serial_exact_source_and_executable_receipts(self):
        calls, results, output = self.dispatch()
        self.assertEqual(tuple(calls), GATE.PHASES)
        self.assertEqual(len(set(calls)), 7)
        self.assertEqual(len(results), 7)
        self.assertIn("all seven native phases and their controls passed", output)
        self.assertEqual([len(row["executables"]) for row in results], [3, 6, 3, 7, 3 + len(GATE.EXTERNAL_LEASE_CONTROLS), 6, 3])

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
        self.assertEqual(len(results), 7)
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
        self.assertEqual(GATE.PHASE_TIMEOUTS["external-packet"], 2 * 180 + 90 + 60 + 600 + 2 * 75 + (5 + len(GATE.EXTERNAL_SERVER_GROUPS)) * 195 + 2 * (600 + 4 * 75) + len(GATE.EXTERNAL_LEASE_CONTROLS) * (600 + 75))
        self.assertEqual(GATE.PHASE_TIMEOUTS["external-ss-entry"], GATE._PHASE_COMMON + 600 + 11 * 195 + 2 * (600 + 75))

    def test_builder_calls_complete_phase_orchestrator_without_old_aggregate(self):
        source = (ROOT / "deploy/build-native-runtime.py").read_text()
        self.assertIn("physical.execute_partitioned(source, env, run)", source)
        self.assertNotIn("run([sys.executable, ROOT/'deploy/test_windows_node_physical.py', source],", source)


if __name__ == "__main__":
    unittest.main()
