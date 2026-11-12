#!/usr/bin/env python3
"""Keep both bounded Windows source phases mandatory for native packaging."""
from pathlib import Path
import contextlib
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("node_source_phases", ROOT / "deploy/test_desktop_node_physical.py")
NODE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NODE)


class SourcePhases(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="node-source-phase-test-")
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name)
        self.input = self.source / "original.go"
        self.input.write_text("package original\n")
        self.names = {"baselines": ["original-owner", "original-retirement"],
                      "controls": ["missing-owner", "unjoined-retirement"]}
        self.images = {phase: [name + ".exe" for name in names] for phase, names in self.names.items()}
        self.architecture = "amd64"

    def records(self, source):
        self.assertEqual(source, self.source)
        return source, {"original.go": hashlib.sha256(self.input.read_bytes()).hexdigest()}

    def receipt(self, phase):
        return {"format": "routervpn-node-source-phase-v1", "phase": phase,
                "architecture": self.architecture,
                "source_sha256": NODE.source_records_digest(self.records(self.source)[1]),
                "completed": list(self.names[phase]),
                "executables": {name: "a" * 64 for name in self.images[phase]}}

    def run_phases(self, fault=None, target="baselines"):
        calls = []
        def runner(command, *, env, timeout):
            self.assertEqual(timeout, 1800)
            self.assertEqual(env, {"GOARCH": self.architecture, "original": "environment"})
            self.assertEqual(command[2], self.source)
            phase = command[command.index("--phase") + 1]
            self.assertEqual(phase, NODE.SOURCE_PHASES[len(calls)])
            calls.append(phase)
            path = command[command.index("--receipt") + 1]
            value = self.receipt(phase)
            if phase == target:
                if fault == "failed-child":
                    raise RuntimeError("original native child failed")
                if fault == "no-receipt":
                    return "partial console output cannot certify a native phase"
                if fault == "source-change":
                    self.input.write_text("package replacement\n")
                if fault == "source": value["source_sha256"] = "b" * 64
                if fault == "architecture": value["architecture"] = "arm64" if self.architecture == "amd64" else "amd64"
                if fault == "phase": value["phase"] = "controls" if phase == "baselines" else "baselines"
                if fault == "missing": value["completed"].pop()
                if fault == "duplicate": value["completed"].append(value["completed"][0])
                if fault == "order": value["completed"].reverse()
                if fault == "foreign": value["completed"][0] = "unrelated"
                if fault == "missing-image": value["executables"].pop(next(iter(value["executables"])))
                if fault == "foreign-image": value["executables"]["unrelated.exe"] = "b" * 64
                if fault == "bad-image": value["executables"][next(iter(value["executables"]))] = "not-a-digest"
                if fault == "extra": value["unexpected"] = True
                if fault == "oversized":
                    path.write_text(" " * 65537)
                    return ""
            encoded = json.dumps(value)
            if phase == target and fault == "symlink":
                alternate = self.source / "foreign-receipt.json"
                alternate.write_text(encoded)
                path.symlink_to(alternate)
            else:
                path.write_text(encoded)
            return "native phase output"
        with patch.object(NODE.platform, "system", return_value="Windows"), \
             patch.object(NODE, "checked_sources", side_effect=self.records), \
             patch.object(NODE, "source_phase_inventory", return_value=(self.names, self.images)), \
             contextlib.redirect_stdout(io.StringIO()):
            try:
                result = NODE.execute_partitioned(self.source, {"GOARCH": self.architecture, "original": "environment"}, runner)
            finally:
                self.calls = calls
        return result

    def test_each_architecture_requires_both_serial_original_phases(self):
        for architecture in ("amd64", "arm64"):
            self.architecture = architecture
            with self.subTest(architecture=architecture):
                result = self.run_phases()
                self.assertEqual(self.calls, ["baselines", "controls"])
                self.assertEqual([value["phase"] for value in result], self.calls)

    def test_every_bad_receipt_or_failed_child_blocks_complete_packaging(self):
        faults = ("failed-child", "no-receipt", "source-change", "source", "architecture", "phase", "missing",
                  "duplicate", "order", "foreign", "missing-image", "foreign-image", "bad-image", "extra", "oversized")
        for target in ("baselines", "controls"):
            for fault in faults:
                with self.subTest(phase=target, fault=fault):
                    self.input.write_text("package original\n")
                    with self.assertRaises((ValueError, RuntimeError)):
                        self.run_phases(fault, target)
                    self.assertEqual(self.calls, ["baselines"] if target == "baselines" else ["baselines", "controls"])

    def test_receipt_symlink_cannot_borrow_an_identical_result(self):
        probe = self.source / "probe"
        try:
            probe.symlink_to(self.input)
        except OSError:
            self.skipTest("host lacks symlink creation permission")
        probe.unlink()
        with self.assertRaisesRegex(ValueError, "bounded regular receipt"):
            self.run_phases("symlink")

    def test_complete_mode_cannot_emit_a_partial_receipt_or_accept_unknown_phase(self):
        for options in ({"phase": "unknown"}, {"receipt_path": self.source / "partial.json"}):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, "partial complete receipt"):
                NODE.execute(self.source, **options)
        with patch.object(NODE.platform, "system", return_value="Linux"):
            with self.assertRaisesRegex(ValueError, "actual Windows"):
                NODE.execute(self.source, phase="controls")
            with self.assertRaisesRegex(ValueError, "actual Windows"):
                NODE.execute_partitioned(self.source, {}, lambda *args, **kwargs: None)
        with patch.object(NODE.platform, "system", return_value="Windows"):
            with self.assertRaisesRegex(ValueError, "full actual Windows"):
                NODE.execute(self.source, phase="baselines", bootstrap_only=True)

    def test_real_baseline_inventory_keeps_all_roots_and_shared_package_images(self):
        with patch.object(NODE.platform, "system", return_value="Windows"), \
             patch.object(NODE, "mutants", return_value=[("original-defect",)]):
            names, images = NODE.source_phase_inventory(self.source)
            suites = NODE.baseline_suites(True)
        self.assertGreater(len(suites), 30)
        self.assertEqual(len(names["baselines"]), len(set(names["baselines"])))
        self.assertTrue({"encrypted", "composite-traffic", "composite-credentials", "ordered-execution-owner", "tor-registration-owner"} <= set(names["baselines"]))
        self.assertTrue(all(selector and required for _, _, selector, required in suites))
        self.assertEqual(len(images["baselines"]) - 2, len({suite[1] for suite in suites}))
        with patch.object(NODE.platform, "system", return_value="Windows"):
            for controls in ([], [("duplicate",), ("duplicate",)]):
                with patch.object(NODE, "mutants", return_value=controls), self.assertRaisesRegex(ValueError, "empty or duplicated"):
                    NODE.source_phase_inventory(self.source)

    def test_builder_requires_complete_orchestrator_before_native_package(self):
        source = (ROOT / "deploy/build-native-runtime.py").read_text()
        self.assertIn("node_source.execute_partitioned(source, env, run)", source)
        self.assertIn("ROOT/'deploy/test_desktop_node_phases.py'", source)
        self.assertNotIn("timeout=3600 if target.startswith('linux/') else 1800", source)


if __name__ == "__main__":
    unittest.main()
