#!/usr/bin/env python3
"""Reject incomplete or misleading scoped SOCKS/REALITY native receipts."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "socks_xray_gate", ROOT / "deploy/test_mobile_imported_socks_xray.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ScopedSOCKSRealityVerdicts(unittest.TestCase):
    def scopes(self):
        return (gate.CORE, gate.PEERS, gate.LAYER_CORE, gate.LAYER_PEERS,
                gate.REFERENCE_DETECTOR_TESTS, gate.REFERENCE_STARTUP_TESTS)

    def events(self, expected):
        return [{"Action": action, "Test": name}
                for name in sorted(expected) for action in ("run", "pass")]

    def encode(self, events):
        return "\n".join(map(json.dumps, events))

    def test_complete_exact_scopes(self):
        self.assertEqual(len(gate.CORE), 2)
        self.assertEqual(len(gate.PEER_CASES), 12)
        self.assertEqual(len(gate.PEERS), 13)
        self.assertEqual(len(set(gate.PEERS)), 13)
        self.assertEqual(gate.REFERENCE_DETECTOR_TESTS, (
            "TestReferenceDetectorRequiresEveryCapturedCompletion",
            "TestReferenceDetectorCancellationJoinsOriginalOwner",
            "TestReferenceDetectorRejectsUncapturedConfiguration",
        ))
        self.assertEqual(gate.REFERENCE_STARTUP_TESTS, (
            "TestRouterVPNDesktopNodeXrayStartupRecords",
            "TestRouterVPNDesktopNodeXrayDetectorRecords",
        ))
        for expected in self.scopes():
            gate.require_verdicts(self.encode(self.events(expected)), 0, expected)

    def test_independent_layer_native_scope(self):
        self.assertEqual(len(gate.LAYER_CORE), 10)
        self.assertEqual(len(gate.LAYER_PEER_CASES), 8)
        self.assertEqual(len(gate.LAYER_PEERS), 51)
        self.assertEqual(sum(map(len, gate.LAYER_PEER_CASES.values())), 42)
        for label, faults in gate.LAYER_PEER_CASES.items():
            self.assertIn("success", faults)
            self.assertIn("cancel", faults)
            self.assertIn("close-owner", faults)
            self.assertIn("socks5--final-"+label+".json", gate.IMPORTED.SOCKS_XRAY_FILES)
        with self.assertRaises(ValueError):
            gate.require_verdicts(self.encode(self.events(gate.PEERS)), 0, gate.LAYER_PEERS)

    def test_every_case_is_mandatory(self):
        for expected in self.scopes():
            for omitted in expected:
                events = self.events(set(expected) - {omitted})
                with self.subTest(omitted=omitted), self.assertRaises(ValueError):
                    gate.require_verdicts(self.encode(events), 0, expected)

    def test_duplicate_foreign_failed_and_skipped_cases(self):
        for expected in self.scopes():
            events = self.events(expected)
            for mutation in (
                events + [events[-1]],
                events + [{"Action": "pass", "Test": "TestUnselectedNativePeer"}],
                events[:-1] + [dict(events[-1], Action="skip")],
                events[:-1] + [dict(events[-1], Action="fail")],
            ):
                with self.assertRaises(ValueError):
                    gate.require_verdicts(self.encode(mutation), 0, expected)

    def test_successful_leaves_cannot_hide_process_failure(self):
        events = self.events(gate.PEERS)
        with self.assertRaises(ValueError):
            gate.require_verdicts(self.encode(events), 1, gate.PEERS)
        for package_action in ("fail", "skip"):
            with self.assertRaises(ValueError):
                gate.require_verdicts(
                    self.encode(events + [{"Action": package_action, "Package": "routervpnamnezia"}]),
                    0, gate.PEERS)

    def test_abort_after_passes_is_not_a_native_receipt(self):
        events = self.events(gate.PEERS)
        for output in ("panic: fixture failed", "fatal error: concurrent map writes", "WARNING: DATA RACE"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                gate.require_verdicts(
                    self.encode(events + [{"Action": "output", "Output": output + "\n"}]), 0, gate.PEERS)

    def test_existing_full_source_matrix_is_retained(self):
        self.assertEqual(len(gate.IMPORTED.FILES), 346)
        self.assertEqual(len(gate.IMPORTED.SOCKS_XRAY_FILES), 9)
        self.assertIn(gate.FIXTURE, gate.IMPORTED.FILES)
        self.assertEqual(len(gate.IMPORTED.SOCKS_FILES), 45)

    def test_layer_export_cannot_replace_original_or_omit_any_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixtures = Path(temporary)
            original = b"retained original Off/Off receipt"
            for name in gate.IMPORTED.SOCKS_XRAY_FILES:
                (fixtures / name).write_bytes(original if name == gate.FIXTURE else name.encode())
            captured = gate.captured_source_matrix(fixtures, original)
            self.assertEqual(set(captured), gate.IMPORTED.SOCKS_XRAY_FILES)
            (fixtures / gate.FIXTURE).write_bytes(original + b" changed")
            with self.assertRaises(ValueError): gate.captured_source_matrix(fixtures, original)
            (fixtures / gate.FIXTURE).write_bytes(original)
            for name in gate.IMPORTED.SOCKS_XRAY_FILES:
                target = fixtures / name
                raw = target.read_bytes(); target.unlink()
                with self.assertRaises(ValueError): gate.captured_source_matrix(fixtures, original)
                target.symlink_to(fixtures / gate.FIXTURE if name != gate.FIXTURE else fixtures / "missing")
                with self.assertRaises(ValueError): gate.captured_source_matrix(fixtures, original)
                target.unlink(); target.write_bytes(raw)
            (fixtures / "foreign.json").write_bytes(b"foreign")
            with self.assertRaises(ValueError): gate.captured_source_matrix(fixtures, original)

    def test_real_peer_boundaries_cannot_be_replaced_by_parser(self):
        for leaf in (
            "entry-auth", "auth-downgrade", "wrong-entry-ip", "final-reality-key",
            "final-user", "final-route", "dns-route", "final-identity",
            "final-token", "cancel", "close-owner",
        ):
            self.assertIn(gate.PEER_PARENT + "/" + leaf, gate.PEERS)
        with self.assertRaises(ValueError):
            gate.require_verdicts(self.encode(self.events((gate.IMPORTED.SOCKS_XRAY_PARSER,))), 0, gate.PEERS)



class ScopedSOCKSRealitySourceContext(unittest.TestCase):
    def test_reference_instrumentation_retains_exact_overlay_and_copies(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "pinned-xray"
            (source / "main").mkdir(parents=True)
            workspace = Path(temporary) / "owned-build"
            workspace.mkdir()
            overlay, records = gate.reference_instrumentation(source, workspace)
            gate.check_reference_instrumentation(source, workspace, overlay, records)
            original_overlay = overlay.read_bytes()
            replacements = json.loads(original_overlay)["Replace"]
            self.assertEqual(len(replacements), 2)
            self.assertEqual(set(records), {
                "mobile/applexray/reference_readiness.go.tmpl",
                "mobile/applexray/reference_readiness_test.go.tmpl",
                "overlay_sha256",
            })
            for target, copied in replacements.items():
                target, copied = Path(target), Path(copied)
                raw = copied.read_bytes()
                for mutation in (b"", raw + b"\n// changed observer\n"):
                    copied.write_bytes(mutation)
                    with self.assertRaises(ValueError):
                        gate.check_reference_instrumentation(source, workspace, overlay, records)
                copied.unlink()
                with self.assertRaises(ValueError):
                    gate.check_reference_instrumentation(source, workspace, overlay, records)
                copied.symlink_to(overlay)
                with self.assertRaises(ValueError):
                    gate.check_reference_instrumentation(source, workspace, overlay, records)
                copied.unlink()
                copied.write_bytes(raw)
                target.write_bytes(raw)
                with self.assertRaises(ValueError):
                    gate.check_reference_instrumentation(source, workspace, overlay, records)
                with self.assertRaises(ValueError):
                    gate.reference_instrumentation(source, workspace)
                target.unlink()
            changed = json.loads(original_overlay)
            changed["Replace"][str(source / "main/undeclared.go")] = str(workspace / "foreign.go")
            overlay.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                gate.check_reference_instrumentation(source, workspace, overlay, records)
            # A new matching digest cannot authorize an undeclared build input.
            changed_records = dict(records, overlay_sha256=hashlib.sha256(overlay.read_bytes()).hexdigest())
            with self.assertRaises(ValueError):
                gate.check_reference_instrumentation(source, workspace, overlay, changed_records)
            overlay.write_bytes(original_overlay)
            gate.check_reference_instrumentation(source, workspace, overlay, records)

    def prepared_templates(self, vendor):
        # Project from the official desktop mapping, not the gate's own list.
        # This source fixture installs no mobile bridge or libbox parser.
        templates = (
            "node_imported_socks_xray_test.go.tmpl",
            "node_imported_socks_entry_test.go.tmpl",
            "node_xray_peer_test.go.tmpl",
            "node_layer_peer_test.go.tmpl",
            "node_peer_test.go.tmpl",
        )
        copies = {"mobile/applexray/outbound.go.tmpl": "protocol/routervpnxray/outbound.go"}
        for name in templates:
            copies["mobile/desktop/" + name] = gate.DESKTOP.PEER_TEMPLATES[name]
        for original, relative in copies.items():
            destination = vendor / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / original).read_bytes())
        return copies

    def test_desktop_templates_require_no_mobile_bridge(self):
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary)
            copies = self.prepared_templates(vendor)
            self.assertEqual(copies, gate.reference_copies())
            self.assertFalse((vendor / "experimental/libbox/routervpn_imported_entry.go").exists())
            self.assertFalse((vendor / "experimental/libbox/routervpn_imported_entry_native_test.go").exists())
            records = {}
            gate.check_reference_templates(vendor, records)
            self.assertEqual(set(records), set(copies.values()))

    def test_changed_or_missing_desktop_template_cannot_borrow_mobile_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary)
            copies = self.prepared_templates(vendor)
            mobile = vendor / "experimental/libbox/routervpn_imported_entry_native_test.go"
            mobile.parent.mkdir(parents=True, exist_ok=True)
            mobile.write_bytes((ROOT / "mobile/routervpn_imported_entry_native_test.go.tmpl").read_bytes())
            for relative in copies.values():
                with self.subTest(relative=relative):
                    destination = vendor / relative
                    original = destination.read_bytes()
                    destination.unlink()
                    with self.assertRaises(ValueError):
                        gate.check_reference_templates(vendor, {})
                    destination.write_bytes(original + b"\n// changed reference source\n")
                    with self.assertRaises(ValueError):
                        gate.check_reference_templates(vendor, {})
                    destination.write_bytes(original)
            gate.check_reference_templates(vendor, {})

    def test_reference_enters_existing_desktop_peer_closure(self):
        class ReachedOriginalClosure(Exception):
            pass

        def check(vendor, peers):
            self.assertTrue(peers, "Desktop reference selected mobile-only bridge closure")
            raise ReachedOriginalClosure()

        with mock.patch.object(gate.subprocess, "check_output", return_value=gate.PIN + "\n"):
            with mock.patch.object(gate.IMPORTED, "checked_sources", side_effect=check):
                with self.assertRaises(ReachedOriginalClosure):
                    gate.checked_sources(Path("prepared-desktop-reference"))

    def test_generated_observation_source_is_bound_before_reference_templates(self):
        class ReachedTemplates(Exception):
            pass

        def templates(vendor, records):
            self.assertIn(gate.RELAY.OBSERVATION.RELATIVE, records)
            raise ReachedTemplates()

        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary)
            gate.RELAY.OBSERVATION.prepare(vendor)
            generated = vendor / gate.RELAY.OBSERVATION.RELATIVE
            original = generated.read_bytes()
            with mock.patch.object(gate.subprocess, "check_output", return_value=gate.PIN + "\n"):
                with mock.patch.object(gate.IMPORTED, "checked_sources"):
                    with mock.patch.object(gate, "check_reference_templates", side_effect=templates):
                        with self.assertRaises(ReachedTemplates):
                            gate.checked_sources(vendor)
                        generated.write_bytes(original + b"\n// changed observation policy\n")
                        with self.assertRaisesRegex(ValueError, "missing or modified"):
                            gate.checked_sources(vendor)
                        generated.unlink()
                        with self.assertRaisesRegex(ValueError, "missing or modified"):
                            gate.checked_sources(vendor)
                        generated.write_bytes(original)
                        undeclared = generated.with_name("undeclared.go")
                        undeclared.write_bytes(b"package common\n")
                        with self.assertRaisesRegex(ValueError, "undeclared common sources"):
                            gate.checked_sources(vendor)
                        undeclared.unlink()
                        with self.assertRaises(ReachedTemplates):
                            gate.checked_sources(vendor)

    def native_stage(self):
        path = ROOT / "deploy/build-native-runtime.py"
        tree = ast.parse(path.read_text(), filename=str(path))
        matches = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.If)
            and ast.unparse(node.test) == "target.startswith(('linux/', 'windows/'))"
        ]
        self.assertEqual(len(matches), 1)
        selected = matches[0]
        ancestors = []

        def locate(node, conditions):
            if node is selected:
                ancestors.extend(conditions)
            for child in ast.iter_child_nodes(node):
                locate(child, conditions + ([ast.unparse(node.test)] if isinstance(node, ast.If) else []))

        locate(tree, [])
        self.assertIn("target == host", ancestors)
        return path, selected, tree

    def test_actual_build_stage_keeps_reference_separate_and_linux_only(self):
        path, selected, tree = self.native_stage()
        stage = ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(selected)], type_ignores=[]))
        for target in ("linux/amd64", "linux/arm64", "windows/amd64", "windows/arm64", "darwin/arm64"):
            with self.subTest(target=target):
                calls = []

                def capture(command, **options):
                    calls.append(([str(value) for value in command], options))

                namespace = dict(ROOT=ROOT, sys=sys, target=target, source=Path("original-core"),
                                 pq=Path("original-pq"), cache=None, env={"ORIGINAL_ENV": "1"}, run=capture)
                exec(compile(stage, str(path), "exec"), namespace)
                node = [(i, options) for i, (command, options) in enumerate(calls)
                        if any(Path(value).name == "test_desktop_node_physical.py" for value in command)]
                reference = [(i, command, options) for i, (command, options) in enumerate(calls)
                             if any(Path(value).name == "test_mobile_imported_socks_xray.py" for value in command)]
                self.assertEqual(len(node), int(target.startswith(("linux/", "windows/"))))
                for _, options in node:
                    self.assertEqual(options["timeout"], 3600 if target.startswith("linux/") else 1800)
                self.assertEqual(len(reference), int(target.startswith("linux/")))
                for index, command, options in reference:
                    self.assertGreater(index, node[0][0])
                    self.assertEqual(command[-1], "--reference-only")
                    self.assertEqual(options["timeout"], 3000)
                    self.assertEqual(options["env"], {"ORIGINAL_ENV": "1"})
        inputs = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "inputs")
        literals = {node.value for node in ast.walk(inputs) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        for name in ("deploy/test_mobile_imported_socks_xray.py", "deploy/test_mobile_imported_socks_xray_runner.py"):
            self.assertIn(name, literals)

    def test_original_imported_parent_is_not_extended_or_reentered(self):
        path = ROOT / "deploy/test_desktop_node_physical.py"
        tree = ast.parse(path.read_text(), filename=str(path))
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "run"
            and node.args and any(isinstance(value, ast.Constant) and value.value == "deploy/test_mobile_imported_entry.py"
                                 for value in ast.walk(node.args[0]))
        ]
        self.assertEqual(len(calls), 1)
        timeout = next(keyword.value for keyword in calls[0].keywords if keyword.arg == "timeout")
        self.assertEqual(ast.literal_eval(timeout), 1200)
        imported = ast.parse((ROOT / "deploy/test_mobile_imported_entry.py").read_text())
        self.assertFalse(any(isinstance(node, ast.Constant) and isinstance(node.value, str)
                             and "test_mobile_imported_socks_xray.py" in node.value
                             for node in ast.walk(imported)))

if __name__ == "__main__":
    unittest.main()
