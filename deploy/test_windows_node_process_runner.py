#!/usr/bin/env python3
"""Reject missing source and false native-process gate acknowledgments."""
from pathlib import Path
import hashlib
import importlib.util
import io
import json
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "windows_node_process_runner_gate", ROOT / "deploy/test_windows_node_process.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class NodeProcessRunner(unittest.TestCase):
    def test_imported_parent_requires_real_dispatch_proofs_and_both_original_sources(self):
        self.assertEqual(len(GATE.IMPORTED_CASES), 13)
        self.assertEqual(sum(map(len, GATE.IMPORTED_CASES.values())), 66)
        for root, children in GATE.IMPORTED_CASES.items():
            self.assertIn(root, GATE.SHARED_TESTS)
            self.assertIn(root, GATE.EXPECTED)
            for child in children:
                self.assertIn(root + "/" + child, GATE.EXPECTED)
        self.assertEqual(GATE.IMPORTED_CASES["TestDesktopImportedOwnedSpeedLabActualOpenAndProofs"],
                         ("success", "wrong-entry", "entry-replaced", "wrong-final", "failed-DNS", "caller-after-create"))
        self.assertEqual(GATE.IMPORTED_CASES["TestDesktopImportedOwnedSuccessionRetainsLatestPredecessor"],
                         ("on-connect", "always"))
        self.assertEqual(GATE.IMPORTED_CASES["TestDesktopImportedOwnedSpeedLabProtectedPreSuspendAdmission"],
                         ("on-connect", "always"))
        self.assertEqual(GATE.IMPORTED_CASES["TestDesktopImportedMTUMergedPolicyControlsAutoRetestAndStatus"],
                         ("entry-fixed", "entry-jumbo", "final-fixed", "compatible-auto", "packet-entry-fixed"))
        self.assertEqual(GATE.IMPORTED_CASES["TestDesktopImportedMTUMergedPolicyRefusesChangedOriginalSource"],
                         ("envelope", "resealed-source", "resealed-graph", "entry-policy", "final-authority"))
        for path in ("cmd/client/desktop_imported_owned.go", "cmd/client/desktop_imported_owned_test.go",
                     "cmd/client/desktop_imported_mtu_policy.go", "cmd/client/desktop_imported_mtu_policy_test.go",
                     "cmd/client/desktop_imported_mtu_ui.go",
                     "cmd/client/desktop_imported_speedlab_owned_test.go", "internal/mobilemultihop/desktop_imported_policy.go",
                     "internal/mobilemultihop/imported_entry_launch_input.go", "internal/mobilemultihop/desktop_physical_policy.go"):
            self.assertIn(path, GATE.REQUIRED_SOURCES)

    def test_external_process_and_retained_application_cases_are_mandatory(self):
        self.assertIn("TestWindowsOwnedExternalChildActualRetirement", GATE.NATIVE_TESTS)
        self.assertIn("TestWindowsOwnedExternalProcessRequiresOriginalJournal", GATE.NATIVE_TESTS)
        for root in ("TestDesktopWindowsExternalPublicConnectAndDisconnect",
                     "TestDesktopWindowsExternalRetirementRetriesExactOwner",
                     "TestDesktopWindowsExternalInvalidProofCannotConnect",
                     "TestDesktopWindowsExternalStagesBeforeStoppingPrevious",
                     "TestDesktopWindowsExternalProtectionKeepsCapturedController",
                     "TestDesktopWindowsExternalUnsupportedGraphPreservesPrevious",
                     "TestDesktopWindowsExternalUnenteredRetirementRequiresOriginalJournal",
                     "TestDesktopWindowsExternalDNSUsesOnlyOriginalNativeProof",
                     "TestDesktopWindowsExternalSpeedLabRestoresOriginalTypedHost"):
            self.assertIn(root, GATE.SHARED_TESTS)
        for policy in ("on-connect", "always"):
            for protocol in ("shadowsocks", "http-connect", "https-connect", "hysteria2", "socks5", "wireguard", "amneziawg-fast", "amneziawg-strong", "openvpn-tcp", "openvpn-udp", "openvpn-mixed"):
                self.assertIn("TestDesktopWindowsExternalPublicConnectAndDisconnect/" + policy + "/" + protocol,
                              GATE.EXPECTED)
        self.assertIn("cmd/client/desktop_external_owned_test.go", GATE.REQUIRED_SOURCES)
        self.assertEqual(len(GATE.EXPECTED), len(set(GATE.EXPECTED)))

    def test_packet_identity_and_both_restoration_directions_are_mandatory(self):
        parent = "TestDesktopWindowsExternalPacketAuthorityKeepsOriginalKeysAndVariant"
        self.assertIn(parent, GATE.SHARED_TESTS)
        for protocol in ("wireguard", "amneziawg-fast", "amneziawg-strong"):
            for fault in ("private-key", "peer-key", "preshared-key", "resolver"):
                self.assertIn(parent + "/" + protocol + "/" + fault, GATE.EXPECTED)
            if protocol != "wireguard":
                self.assertIn(parent + "/" + protocol + "/parameters", GATE.EXPECTED)
            for direction in ("router-" + protocol + "-router", protocol + "-router-" + protocol):
                self.assertIn("TestDesktopWindowsExternalSpeedLabRestoresOriginalTypedHost/" + direction, GATE.EXPECTED)

    def test_openvpn_original_import_and_both_restore_directions_are_mandatory(self):
        parent = "TestDesktopWindowsExternalOpenVPNAuthorityKeepsOriginalImport"
        self.assertIn(parent, GATE.SHARED_TESTS)
        self.assertIn("cmd/client/desktop_external_openvpn_owned_test.go", GATE.REQUIRED_SOURCES)
        for protocol in ("openvpn-tcp", "openvpn-udp", "openvpn-mixed"):
            self.assertIn(parent + "/" + protocol, GATE.EXPECTED)
            for direction in ("router-" + protocol + "-router", protocol + "-router-" + protocol):
                self.assertIn("TestDesktopWindowsExternalSpeedLabRestoresOriginalTypedHost/" + direction, GATE.EXPECTED)

    def test_hysteria_layers_keep_public_source_and_restoration_mandatory(self):
        for protocol in ("hysteria2-aes", "hysteria2-aes-xor"):
            for policy in ("on-connect", "always"):
                self.assertIn("TestDesktopWindowsExternalPublicConnectAndDisconnect/" + policy + "/" + protocol, GATE.EXPECTED)
            for direction in ("router-" + protocol + "-router", protocol + "-router-" + protocol):
                self.assertIn("TestDesktopWindowsExternalSpeedLabRestoresOriginalTypedHost/" + direction, GATE.EXPECTED)
            for fault in ("layer-key", "layer-mode", "private-peer", "inner-key", "inner-trust", "resolver"):
                self.assertIn("TestDesktopWindowsExternalHysteria2LayerAuthorityKeepsOriginalSource/" + protocol + "/" + fault, GATE.EXPECTED)
        for layer in ("aes-256-gcm", "aes-256-gcm+xor-whitening"):
            for policy in ("on-connect", "always"):
                self.assertIn("TestDesktopExternalPhysicalWindowsHysteria2LayersKeepOuterAndInnerOwners/" + layer + "/" + policy, GATE.EXPECTED)

    def test_complete_source_closure_includes_actual_adapter_and_embedded_command(self):
        records = GATE.sources()
        self.assertTrue(set(GATE.REQUIRED_SOURCES).issubset(records))
        self.assertIn("cmd/client/ui.html", records)
        self.assertIn("cmd/client/logical_ui.js", records)

    def test_missing_or_linked_native_adapter_cannot_reuse_a_source_receipt(self):
        with tempfile.TemporaryDirectory(prefix="node-process-source-") as directory:
            root = Path(directory)
            for relative in GATE.REQUIRED_SOURCES:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"captured source\n")
            with patch.object(GATE, "ROOT", root):
                for relative in ("cmd/client/desktop_node_process_windows_native_test.go",
                                 "cmd/client/desktop_node_toolchain_test.go",
                                 "cmd/client/desktop_node_all_toolchain_test.go"):
                    with self.subTest(required=relative):
                        missing = root / relative
                        GATE.sources()
                        missing.unlink()
                        with self.assertRaisesRegex(ValueError, "actual regular source"):
                            GATE.sources()
                        missing.symlink_to(root / "cmd/client/desktop_node_process_test.go")
                        with self.assertRaisesRegex(ValueError, "actual regular source"):
                            GATE.sources()
                        missing.unlink()
                        missing.write_bytes(b"captured source\n")

    def test_baseline_requires_every_native_shared_and_command_case(self):
        output = "\n".join("--- PASS: " + name + " (0.01s)" for name in GATE.EXPECTED)
        GATE.check_baseline(0, output)
        for name in GATE.EXPECTED:
            with self.subTest(missing=name):
                with self.assertRaisesRegex(ValueError, "every required ownership case"):
                    GATE.check_baseline(0, output.replace("--- PASS: " + name + " (", "--- PASS: omitted ("))
        for status, suffix in ((1, ""), (0, "\n--- SKIP: hidden (0.00s)"),
                               (0, "\nWARNING: DATA RACE"), (0, "\npanic: test timed out"),
                               (0, "\n--- FAIL: actual (0.01s)"),
                               (0, "\n--- PASS: " + GATE.EXPECTED[0] + " (0.01s)")):
            with self.subTest(status=status, suffix=suffix):
                with self.assertRaisesRegex(ValueError, "every required ownership case"):
                    GATE.check_baseline(status, output + suffix)

    def test_negative_requires_its_actual_failure_and_specific_witness(self):
        for _, name, test, witness, _ in GATE.mutants():
            output = "--- FAIL: " + test + " (0.01s)\n    source_test.go:1: " + witness + "\n"
            with self.subTest(name=name):
                GATE.check_rejection(name, test, witness, 1, output)
                for status, wrong in ((0, output), (1, output.replace(witness, "another error")),
                                      (1, output.replace(test, "AnotherTest")),
                                      (1, output + "panic: test timed out"),
                                      (1, output + "WARNING: DATA RACE"),
                                      (1, output + "--- SKIP: other (0.00s)"),
                                      (1, output + "[build failed]")):
                    with self.assertRaisesRegex(ValueError, "intended boundary"):
                        GATE.check_rejection(name, test, witness, status, wrong)

    def test_native_unicode_output_survives_cp1252_and_keeps_actual_exit_gate(self):
        output = "\n".join("--- PASS: " + name + " (0.01s)" for name in GATE.EXPECTED)
        output += "\nprivate path: C:\\Portable 路由器\\Data\\routers.json\n"
        for status in (0, 1):
            with self.subTest(status=status):
                raw = io.BytesIO()
                with io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="") as stream:
                    with patch.object(GATE.sys, "stdout", stream):
                        if status:
                            with self.assertRaisesRegex(ValueError, "every required ownership case"):
                                GATE.report_baseline(status, output)
                        else:
                            GATE.report_baseline(status, output)
                    self.assertEqual(raw.getvalue().decode("utf-8"), output)
                    self.assertEqual(stream.encoding, "utf-8")

    def test_mutations_are_exact_production_changes_and_leave_the_source_unchanged(self):
        originals = {name: (ROOT / name).read_bytes() for name in
                     ("cmd/client/desktop_node_process.go", "cmd/client/desktop_node_journal.go", "cmd/client/desktop_node_journal_release.go", "cmd/client/private_store_replace_windows.go", "cmd/client/private_store.go",
                      "cmd/client/desktop_node_journal_off.go", "cmd/client/desktop_node_protection_off.go", "cmd/client/profile_protection_owned.go",
                      "cmd/client/desktop_node_recovery.go", "cmd/client/desktop_node_protection.go", "cmd/client/operation_guard.go",
                      "cmd/client/desktop_node_health.go", "cmd/client/desktop_node_startup.go",
                      "cmd/client/desktop_node_recovery_initial.go", "cmd/client/desktop_node_owned.go",
                      "cmd/client/desktop_node_connection_host.go", "cmd/client/desktop_node_native.go",
                      "cmd/client/strategy_requirements.go", "cmd/client/desktop_node_smart.go", "cmd/client/start_layer_routes.go",
                      "cmd/client/logical_modes.go", "cmd/client/logical_base_preference.go",
                      "cmd/client/desktop_imported_owned.go", "cmd/client/multihop_native_launch.go")}
        changes = GATE.mutants()
        self.assertEqual(len(changes), 49)
        self.assertEqual(len({change[1] for change in changes}), 49)
        for filename, _, test, witness, replacement in changes:
            self.assertIn(filename, originals)
            self.assertNotEqual(replacement.encode(), originals[filename])
            self.assertTrue(test.split("/")[0] in GATE.REQUIRED)
            self.assertTrue(witness)
        for filename, original in originals.items():
            self.assertEqual((ROOT / filename).read_bytes(), original)

    def test_imported_fallback_mutant_disables_only_original_windows_capture_guard(self):
        selected = [change for change in GATE.mutants() if change[1] == "protected-imported-legacy-fallback"]
        self.assertEqual(len(selected), 1)
        filename, _, test, witness, changed = selected[0]
        original = (ROOT / filename).read_text(encoding="utf-8")
        guard = "if sel.Native.importedHost != nil || sel.Native.importedPlatform != nil {"
        mutant = "if (false && sel.Native.importedHost != nil) || sel.Native.importedPlatform != nil {"
        self.assertEqual(original.count(guard), 1)
        self.assertEqual(changed, original.replace(guard, mutant, 1))
        self.assertEqual(test, "TestDesktopImportedOwnedSourceAndNativeDispatch/reality-vision/shadowsocks")
        self.assertEqual(witness, "protected capture silently used a legacy helper")

    def test_other_host_cannot_report_native_windows_execution(self):
        with patch.object(GATE.platform, "system", return_value="Linux"):
            with self.assertRaisesRegex(ValueError, "actual Windows execution"):
                GATE.execute()

    def test_prospective_all_requires_every_unique_real_controller_marker(self):
        complete = "\n".join("--- PASS: " + name + " (0.01s)" for name in GATE.ALL_EXPECTED) + "\nPASS\n"
        GATE.check_all_composition(0, complete)
        for name in GATE.ALL_EXPECTED:
            marker = "--- PASS: " + name + " (0.01s)"
            for output in (complete.replace(marker, ""), complete.replace(marker, "fixture.go:1: " + marker), complete + marker + "\n"):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, "every actual controller case"):
                    GATE.check_all_composition(0, output)
        for status, output in ((1, complete), (0, complete + "\n--- FAIL: hidden (0.01s)"),
                               (0, complete + "\n--- SKIP: hidden (0.01s)"), (0, complete + "\nDATA RACE")):
            with self.assertRaises(ValueError):
                GATE.check_all_composition(status, output)

    def test_all_controls_keep_the_shipping_capability_and_source_unchanged(self):
        names = (GATE.ALL_CAPABILITY_FILE, "cmd/client/logical_modes.go", "cmd/client/desktop_node_all.go",
                 "cmd/client/connection_cancellation.go", "cmd/client/speed_lab_fallback.go")
        before = {name: (ROOT / name).read_bytes() for name in names}
        prospective = GATE.all_capability_source()
        self.assertEqual(prospective.encode(), before[GATE.ALL_CAPABILITY_FILE])
        self.assertIn('case "max-quic-wg", "max-quic-awg", "max-tls-wg", "max-tls-awg":', prospective)
        controls = GATE.all_mutants()
        self.assertEqual(len(controls), 8)
        self.assertEqual(len({item[1] for item in controls}), 8)
        for filename, _, test, witness, changed in controls:
            self.assertIn(filename, before)
            self.assertNotEqual(changed.encode(), before[filename])
            self.assertIn(test.split("/")[0], (*GATE.REQUIRED, *GATE.ALL_GROUPS))
            self.assertTrue(witness)
        for name, body in before.items():
            self.assertEqual((ROOT / name).read_bytes(), body)

    def test_all_uses_the_exact_shipping_native_max_predicate(self):
        spec = importlib.util.spec_from_file_location("all_matching_native_max", ROOT / "deploy/test_windows_node_max.py")
        native_max = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native_max)
        before = (ROOT / GATE.ALL_CAPABILITY_FILE).read_bytes()
        prospective = GATE.all_capability_source()
        closed = native_max.closed_predicate(before.decode())
        self.assertNotEqual(closed, before.decode())
        self.assertEqual(prospective, native_max.prospective_predicate(closed))
        self.assertEqual((ROOT / GATE.ALL_CAPABILITY_FILE).read_bytes(), before)
        self.assertEqual(len(GATE.ALL_EXPECTED), 26)
        self.assertEqual(len(GATE.all_mutants()), 8)

    def test_native_arm64_all_keeps_every_case_and_only_omits_unsupported_race(self):
        controls = {label: (test, witness) for _, label, test, witness, _ in GATE.all_mutants()}
        compiled, executed = [], []
        def run(command, *, cwd, env, timeout):
            self.assertEqual(env['GOOS'], 'windows')
            self.assertEqual(env['GOARCH'], 'arm64')
            self.assertEqual(env['CGO_ENABLED'], '0')
            if '-o' in command:
                self.assertNotIn('-race', command)
                self.assertEqual(timeout, 240)
                binary = Path(command[command.index('-o') + 1])
                compiled.append(binary.name.removesuffix('.test.exe'))
                binary.write_bytes(b'original modeled ARM64 executable')
                return 0, ''
            label = Path(command[0]).name.removesuffix('.test.exe')
            executed.append(label)
            self.assertEqual(timeout, 375 if label == 'node-all' else 75)
            if label == 'node-all':
                self.assertIn('-test.timeout=360s', command)
                return 0, '\n'.join('--- PASS: '+case+' (0.01s)' for case in GATE.ALL_EXPECTED)
            self.assertIn('-test.timeout=60s', command)
            test, witness = controls[label]
            return 1, '--- FAIL: '+test+' (0.01s)\n    source_test.go:1: '+witness+'\n'
        native = SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: True))
        with patch.object(GATE.platform, 'system', return_value='Windows'), \
             patch.object(GATE.ctypes, 'windll', native, create=True), \
             patch.object(GATE.NATIVE, 'selected_compiler', return_value=('go', {'GOOS':'windows','GOARCH':'arm64'}, 'arm64')), \
             patch.object(GATE.NATIVE, 'run', side_effect=run), patch('sys.stdout', new_callable=io.StringIO) as output:
            GATE.execute(suite='prospective-all')
        receipt = json.loads(output.getvalue().splitlines()[-1])
        self.assertEqual(compiled, ['node-all', *controls])
        self.assertEqual(executed, compiled)
        self.assertEqual(receipt['host'], 'windows/arm64')
        self.assertEqual(receipt['prospective_all_markers'], 26)
        self.assertEqual(receipt['prospective_all_controls'], 8)

    def test_all_refuses_closed_partial_or_duplicate_shipping_admission(self):
        original = (ROOT / GATE.ALL_CAPABILITY_FILE).read_text()
        case = '\tcase "max-quic-wg", "max-quic-awg", "max-tls-wg", "max-tls-awg":\n\t\treturn true\n'
        with tempfile.TemporaryDirectory(prefix="shipping-all-admission-") as directory:
            root = Path(directory)
            source = root / GATE.ALL_CAPABILITY_FILE
            source.parent.mkdir(parents=True)
            for changed in (original.replace(case, ""), original.replace(case, case.replace('"max-tls-awg"', '"foreign"')),
                            original.replace(case, case + case), original.replace(case, case.replace('true', 'false'))):
                source.write_text(changed)
                with patch.object(GATE, "ROOT", root), self.assertRaisesRegex(ValueError, "exact four-family shipping capability"):
                    GATE.all_capability_source()

    def test_all_positive_and_eight_controls_never_overlay_shipping_admission(self):
        original = (ROOT / GATE.ALL_CAPABILITY_FILE).read_bytes().replace(b"\r\n", b"\n")
        controls = {label: (test, witness) for _, label, test, witness, _ in GATE.all_mutants()}
        compiled = []
        raw, changed_source = None, False
        def run(command, *, cwd, env, timeout):
            if "-o" in command:
                overlay = Path(next(str(arg).removeprefix("-overlay=") for arg in command if str(arg).startswith("-overlay=")))
                mapping = json.loads(overlay.read_text())["Replace"]
                self.assertNotIn(str(GATE.ROOT / GATE.ALL_CAPABILITY_FILE), mapping)
                self.assertEqual((GATE.ROOT / GATE.ALL_CAPABILITY_FILE).read_bytes(), raw)
                binary = Path(command[command.index("-o") + 1])
                label = binary.name.removesuffix(".test.exe")
                self.assertEqual(len(mapping), 0 if label == "node-all" else 1)
                compiled.append(label)
                binary.write_bytes(b"original modeled compiled controller")
                return 0, ""
            label = Path(command[0]).name.removesuffix(".test.exe")
            if label == "node-all":
                if changed_source:
                    (GATE.ROOT / GATE.ALL_CAPABILITY_FILE).write_bytes(raw + b"\n// replaced compiled source\n")
                return 0, "\n".join("--- PASS: " + name + " (0.01s)" for name in GATE.ALL_EXPECTED)
            test, witness = controls[label]
            return 1, "--- FAIL: " + test + " (0.01s)\n    source_test.go:1: " + witness + "\n"

        write_text = Path.write_text
        def windows_write_text(path, data, *args, **kwargs):
            if kwargs.get("newline") is None:
                kwargs["newline"] = "\r\n"
            return write_text(path, data, *args, **kwargs)

        # Both checkout encodings must identify the actual compiled bytes under
        # Windows text I/O; the capability file is never an overlay candidate.
        for newline in (b"\n", b"\r\n"):
            for changed_source in (False, True):
                with self.subTest(newline=newline, replaced=changed_source), \
                     tempfile.TemporaryDirectory(prefix="shipping-all-controller-") as directory:
                    root, workspace = Path(directory) / "source", Path(directory) / "build"
                    workspace.mkdir()
                    for relative in (GATE.ALL_CAPABILITY_FILE, "cmd/client/logical_modes.go", "cmd/client/desktop_node_all.go",
                                     "cmd/client/connection_cancellation.go", "cmd/client/speed_lab_fallback.go"):
                        target = root / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes((ROOT / relative).read_bytes())
                    raw = original.replace(b"\n", newline)
                    (root / GATE.ALL_CAPABILITY_FILE).write_bytes(raw)
                    compiled.clear()
                    with patch.object(GATE, "ROOT", root), patch.object(Path, "write_text", windows_write_text), \
                         patch.object(GATE.NATIVE, "run", side_effect=run), patch("sys.stdout", new_callable=io.StringIO):
                        if changed_source:
                            with self.assertRaisesRegex(ValueError, "changed its retained binary or compiled capability"):
                                GATE.execute_all_composition(["go", "test", "-c", "-tags=" + GATE.TAG], {}, workspace)
                            self.assertEqual(compiled, ["node-all"])
                        else:
                            digest = GATE.execute_all_composition(["go", "test", "-c", "-tags=" + GATE.TAG], {}, workspace)
                            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
                            self.assertEqual((workspace / "all-capability.go").read_bytes(), raw)
                            self.assertEqual((root / GATE.ALL_CAPABILITY_FILE).read_bytes(), raw)
                            self.assertEqual(compiled, ["node-all", *controls])

    def test_expanded_baseline_keeps_individual_control_deadlines(self):
        controls = {name: (test, witness) for _, name, test, witness, _ in (*GATE.mutants(), *GATE.all_mutants())}
        executions = []

        def run(command, *, cwd, env, timeout):
            if "-o" in command:
                self.assertIn("-race", command)
                self.assertEqual(env["CGO_ENABLED"], "1")
                Path(command[command.index("-o") + 1]).write_bytes(b"retained compiled fixture")
                return 0, ""
            executions.append((command, timeout))
            if Path(command[0]).name == "node-process.test.exe":
                selection = next(value.removeprefix("-test.run=") for value in map(str, command) if value.startswith("-test.run="))
                return 0, "\n".join("--- PASS: " + name + " (0.01s)" for name in GATE.EXPECTED
                                     if re.fullmatch(selection, name.split("/", 1)[0]))
            if Path(command[0]).name == "node-all.test.exe":
                return 0, "\n".join("--- PASS: " + name + " (0.01s)" for name in GATE.ALL_EXPECTED)
            test, witness = controls[Path(command[0]).name.removesuffix(".test.exe")]
            return 1, "--- FAIL: " + test + " (0.01s)\n    source_test.go:1: " + witness + "\n"

        native = SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: True))
        with patch.object(GATE.platform, "system", return_value="Windows"), \
             patch.object(GATE.ctypes, "windll", native, create=True), \
             patch.object(GATE.NATIVE, "selected_compiler", return_value=("go", {}, "amd64")), \
             patch.object(GATE.NATIVE, "run", side_effect=run), \
             patch.object(GATE, "report_baseline", wraps=GATE.check_baseline), \
             patch("sys.stdout", new_callable=io.StringIO):
            GATE.execute()
        groups = GATE.baseline_groups()
        self.assertEqual(len(executions), len(groups) + 1 + len(controls))
        for command, timeout in executions[:len(groups)]:
            self.assertIn("-test.timeout=360s", command)
            self.assertEqual(timeout, 375)
        for command, timeout in executions[len(groups):]:
            if Path(command[0]).name == "node-all.test.exe":
                self.assertIn("-test.timeout=360s", command)
                self.assertEqual(timeout, 375)
            else:
                self.assertIn("-test.timeout=60s", command)
                self.assertEqual(timeout, 75)

    def test_required_execution_suites_cover_the_complete_gate_once(self):
        changes = GATE.mutants()
        partitions = [GATE.suite_controls(suite, changes) for suite in GATE.EXECUTION_SUITES]
        self.assertEqual(tuple(item for part in partitions for item in part), changes)
        self.assertEqual(len({item[1] for part in partitions for item in part}), len(changes))
        self.assertEqual([len(part) for part in partitions], [0, 25, 24, 0])
        self.assertEqual(GATE.suite_controls("complete", changes), changes)
        with self.assertRaisesRegex(ValueError, "Unknown native Node process execution suite"):
            GATE.suite_controls("ownership-controls-3", changes)

        workflow = (ROOT / ".github/workflows/windows-controller-contract.yml").read_text(encoding="utf-8")
        node = workflow.split("  node-process:\n", 1)[1].split("  ui-state:\n", 1)[0]
        selected = re.search(r"suite: \[([^\]]+)\]", node).group(1).split(", ")
        self.assertEqual(tuple(selected), GATE.EXECUTION_SUITES)
        self.assertIn("fail-fast: false", node)
        self.assertNotIn("continue-on-error", node)
        self.assertIn("windows-node-process-${{ github.ref }}-${{ matrix.suite }}", node)
        self.assertIn("test_windows_node_process.py --suite '${{ matrix.suite }}'", node)
        self.assertIn("timeout-minutes: 20", node)

    def test_each_execution_suite_runs_and_reports_only_its_required_cases(self):
        changes = GATE.mutants()
        controls = {name: (test, witness) for _, name, test, witness, _ in (*changes, *GATE.all_mutants())}
        all_executions = []
        native = SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: True))
        for suite in GATE.EXECUTION_SUITES:
            executions = []
            def run(command, *, cwd, env, timeout):
                if "-o" in command:
                    self.assertEqual(timeout, 240)
                    Path(command[command.index("-o") + 1]).write_bytes(b"retained compiled fixture")
                    return 0, ""
                name = Path(command[0]).name.removesuffix(".test.exe")
                executions.append(name)
                if name == "node-process":
                    self.assertEqual(timeout, 375)
                    self.assertIn("-test.timeout=360s", command)
                    selection = next(value.removeprefix("-test.run=") for value in map(str, command) if value.startswith("-test.run="))
                    return 0, "\n".join("--- PASS: " + case + " (0.01s)" for case in GATE.EXPECTED
                                         if re.fullmatch(selection, case.split("/", 1)[0]))
                if name == "node-all":
                    self.assertEqual(timeout, 375)
                    self.assertIn("-test.timeout=360s", command)
                    return 0, "\n".join("--- PASS: " + case + " (0.01s)" for case in GATE.ALL_EXPECTED)
                self.assertEqual(timeout, 75)
                self.assertIn("-test.timeout=60s", command)
                test, witness = controls[name]
                return 1, "--- FAIL: " + test + " (0.01s)\n    source_test.go:1: " + witness + "\n"
            with self.subTest(suite=suite), \
                 patch.object(GATE.platform, "system", return_value="Windows"), \
                 patch.object(GATE.ctypes, "windll", native, create=True), \
                 patch.object(GATE.NATIVE, "selected_compiler", return_value=("go", {}, "amd64")), \
                 patch.object(GATE.NATIVE, "run", side_effect=run), \
                 patch.object(GATE, "report_baseline", wraps=GATE.check_baseline), \
                 patch("sys.stdout", new_callable=io.StringIO) as output:
                GATE.execute(suite=suite)
                receipt = json.loads(output.getvalue().splitlines()[-1])
                selected = GATE.suite_controls(suite, changes)
                self.assertEqual(receipt["execution_suite"], suite)
                self.assertEqual(receipt["negative_control_names"], [item[1] for item in selected])
                self.assertEqual(receipt["negative_controls"], len(selected))
                self.assertEqual(receipt["native_process_cases"], len(GATE.NATIVE_TESTS) if suite == "baseline" else 0)
                self.assertEqual(receipt["shared_ownership_cases"], len(GATE.SHARED_TESTS) if suite == "baseline" else 0)
                self.assertEqual(receipt["prospective_all_controls"], len(GATE.all_mutants()) if suite == "prospective-all" else 0)
                self.assertEqual(receipt["actual_child_fixture_sha256"] is not None, suite == "baseline")
                self.assertEqual(receipt["prospective_all_capability_sha256"] is not None, suite == "prospective-all")
                self.assertEqual(len(receipt["source_sha256"]), 64)
            all_executions.extend(executions)
        self.assertEqual(all_executions.count("node-process"), len(GATE.baseline_groups()))
        self.assertEqual(all_executions.count("node-all"), 1)
        self.assertEqual(sorted(name for name in all_executions if name not in ("node-process", "node-all")), sorted(controls))

    def test_serial_groups_cover_every_original_root_and_leaf_once(self):
        groups = GATE.baseline_groups()
        roots = tuple(root for _, selected, _ in groups for root in selected)
        leaves = tuple(leaf for _, _, expected in groups for leaf in expected)
        self.assertEqual(roots, GATE.REQUIRED)
        self.assertEqual(len(set(roots)), len(roots))
        self.assertEqual(sorted(leaves), sorted(GATE.EXPECTED))
        self.assertEqual(len(set(leaves)), len(leaves))
        self.assertEqual(groups[0][1], GATE.NATIVE_TESTS)
        self.assertTrue(all(0 < len(selected) <= 16 for _, selected, _ in groups))
        for policy in ("on-connect", "always"):
            self.assertIn("TestDesktopWindowsExternalPublicConnectAndDisconnect/" + policy + "/socks5", leaves)
        for shared in (GATE.SHARED_TESTS[1:], (*GATE.SHARED_TESTS, GATE.SHARED_TESTS[0])):
            with patch.object(GATE, "SHARED_TESTS", shared):
                with self.assertRaisesRegex(ValueError, "exact required case partition"):
                    GATE.baseline_groups()

    def test_each_group_rejects_missing_failed_duplicate_or_changed_evidence(self):
        for fault in ("missing-root", "missing-leaf", "duplicate", "failed", "skipped", "changed-image", "timeout"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="node-process-groups-") as directory:
                binary = Path(directory) / "node-process.test.exe"
                binary.write_bytes(b"original compiled fixture")
                digest = hashlib.sha256(binary.read_bytes()).hexdigest()
                calls = []
                def run(command, *, cwd, env, timeout):
                    calls.append(command)
                    _, _, expected = GATE.baseline_groups()[0]
                    verdicts = ["--- PASS: " + name + " (0.01s)" for name in expected]
                    if fault == "missing-root":
                        verdicts.remove("--- PASS: " + expected[0] + " (0.01s)")
                    elif fault == "missing-leaf":
                        verdicts.remove("--- PASS: " + next(name for name in expected if "/" in name) + " (0.01s)")
                    elif fault == "duplicate":
                        verdicts.append(verdicts[0])
                    elif fault in ("failed", "skipped"):
                        verdicts.append("--- " + ("FAIL" if fault == "failed" else "SKIP") + ": hidden (0.01s)")
                    elif fault == "changed-image":
                        binary.write_bytes(b"foreign replacement fixture")
                    else:
                        raise TimeoutError("actual bounded group timed out")
                    return 0, "\n".join(verdicts)
                with patch.object(GATE.NATIVE, "run", side_effect=run), \
                     patch("sys.stdout", new_callable=io.StringIO):
                    with self.assertRaises((ValueError, TimeoutError)):
                        GATE.execute_baseline(binary, {}, digest)
                self.assertEqual(len(calls), 1, "a failed group allowed later baseline execution")

    def test_changed_compiled_image_cannot_start_a_group(self):
        with tempfile.TemporaryDirectory(prefix="node-process-group-image-") as directory:
            binary = Path(directory) / "node-process.test.exe"
            binary.write_bytes(b"original compiled fixture")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            binary.write_bytes(b"foreign replacement fixture")
            with patch.object(GATE.NATIVE, "run") as run:
                with self.assertRaisesRegex(ValueError, "changed before baseline group"):
                    GATE.execute_baseline(binary, {}, digest)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
