#!/usr/bin/env python3
"""Reject missing source and false native-process gate acknowledgments."""
from pathlib import Path
import hashlib
import importlib.util
import io
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
            for protocol in ("shadowsocks", "http-connect", "https-connect", "hysteria2", "socks5", "wireguard", "amneziawg-fast", "amneziawg-strong"):
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
                      "cmd/client/logical_modes.go", "cmd/client/logical_base_preference.go")}
        changes = GATE.mutants()
        self.assertEqual(len(changes), 46)
        self.assertEqual(len({change[1] for change in changes}), 46)
        for filename, _, test, witness, replacement in changes:
            self.assertIn(filename, originals)
            self.assertNotEqual(replacement.encode(), originals[filename])
            self.assertTrue(test.split("/")[0] in GATE.REQUIRED)
            self.assertTrue(witness)
        for filename, original in originals.items():
            self.assertEqual((ROOT / filename).read_bytes(), original)

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

    def test_all_controls_keep_the_shipping_capability_closed_and_source_unchanged(self):
        names = (GATE.ALL_CAPABILITY_FILE, "cmd/client/logical_modes.go", "cmd/client/desktop_node_all.go",
                 "cmd/client/connection_cancellation.go", "cmd/client/speed_lab_fallback.go")
        before = {name: (ROOT / name).read_bytes() for name in names}
        prospective = GATE.all_capability_source()
        self.assertNotEqual(prospective.encode(), before[GATE.ALL_CAPABILITY_FILE])
        self.assertIn('case "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg":', prospective)
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

    def test_expanded_baseline_keeps_individual_control_deadlines(self):
        controls = {name: (test, witness) for _, name, test, witness, _ in (*GATE.mutants(), *GATE.all_mutants())}
        executions = []

        def run(command, *, cwd, env, timeout):
            if "-o" in command:
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
                self.assertIn("-test.timeout=240s", command)
                self.assertEqual(timeout, 255)
            else:
                self.assertIn("-test.timeout=60s", command)
                self.assertEqual(timeout, 75)

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
