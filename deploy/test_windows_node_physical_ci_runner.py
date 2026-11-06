#!/usr/bin/env python3
"""Exercise complete CI receipt admission; native execution is an explicit double."""
from pathlib import Path
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("windows_ci_receipts", ROOT / "deploy/test_windows_node_physical_ci.py")
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)


class CompleteNativeReceipts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="windows-ci-receipts-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.env = {"GITHUB_REPOSITORY": "Eabusham2/router-vpn", "GITHUB_SHA": "a" * 40,
                    "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2"}
        self.expected = CI.context(self.env)

    def receipt(self, architecture, phase):
        return {"format": CI.FORMAT, **self.expected, "comparable_source_sha256": "d" * 64, "native": {
            "format": "routervpn-windows-physical-phase-v1", "phase": phase,
            "architecture": architecture, "source_sha256": "b" * 64,
            "executables": {name: "c" * 64 for name in CI.NATIVE._PHASE_IMAGES[phase]}}}

    def populate(self):
        for architecture in CI.ARCHITECTURES:
            for phase in CI.NATIVE.PHASES:
                (self.directory / CI.filename(architecture, phase)).write_text(json.dumps(self.receipt(architecture, phase)))

    def aggregate(self, result="success"):
        with patch.object(CI, "verify_checkout"), contextlib.redirect_stdout(io.StringIO()) as output:
            try:
                value = CI.aggregate(self.directory, result, env=self.env)
            except BaseException:
                self.assertNotIn("all seven original phases passed", output.getvalue())
                raise
        self.assertIn(self.expected["commit"], output.getvalue())
        return value

    def test_both_architectures_require_every_original_phase(self):
        self.populate()
        results = self.aggregate()
        self.assertEqual(tuple(results), CI.ARCHITECTURES)
        for architecture, rows in results.items():
            self.assertEqual(tuple(row["phase"] for row in rows), CI.NATIVE.PHASES)
            self.assertTrue(all(row["architecture"] == architecture for row in rows))
        for path in tuple(self.directory.iterdir()):
            original = path.read_bytes()
            path.unlink()
            with self.subTest(missing=path.name), self.assertRaisesRegex(ValueError, "fourteen"):
                self.aggregate()
            path.write_bytes(original)

    def test_wrong_source_run_phase_target_images_and_mixed_closures_are_rejected(self):
        self.populate()
        path = self.directory / CI.filename("arm64", CI.NATIVE.PHASES[-1])
        for fault in ("commit", "repository", "run_id", "future-attempt", "extra-field", "phase", "architecture",
                      "missing-image", "extra-image", "image-digest", "source-digest", "mixed-source"):
            value = self.receipt("arm64", CI.NATIVE.PHASES[-1])
            if fault in ("commit", "repository", "run_id"):
                value[fault] = "foreign"
            elif fault == "future-attempt": value["run_attempt"] = "3"
            elif fault == "extra-field": value["unowned"] = True
            elif fault == "phase": value["native"]["phase"] = CI.NATIVE.PHASES[0]
            elif fault == "architecture": value["native"]["architecture"] = "amd64"
            elif fault == "missing-image": value["native"]["executables"].pop(next(iter(value["native"]["executables"])))
            elif fault == "extra-image": value["native"]["executables"]["foreign.exe"] = "c" * 64
            elif fault == "image-digest": value["native"]["executables"][next(iter(value["native"]["executables"]))] = "bad"
            elif fault == "source-digest": value["native"]["source_sha256"] = None
            elif fault == "mixed-source": value["comparable_source_sha256"] = "e" * 64
            path.write_text(json.dumps(value))
            with self.subTest(fault=fault), self.assertRaises(ValueError): self.aggregate()

    def test_failed_cancelled_or_skipped_jobs_never_admit_prior_receipts(self):
        self.populate()
        for result in ("failure", "cancelled", "skipped", "", None):
            with self.subTest(result=result), self.assertRaisesRegex(ValueError, "every matrix job"):
                self.aggregate(result)
        # A rerun can retain a successful original job from the same immutable
        # commit/run, but cannot reuse another run or override a failed matrix.
        for path in self.directory.iterdir():
            value = json.loads(path.read_text()); value["run_attempt"] = "1"
            path.write_text(json.dumps(value))
        self.aggregate()

    def test_extra_duplicate_oversized_and_nonregular_receipts_are_rejected(self):
        self.populate()
        extra = self.directory / "unrequired.json"
        extra.write_text("{}"); self.assertRaises(ValueError, self.aggregate); extra.unlink()
        path = self.directory / CI.filename("amd64", CI.NATIVE.PHASES[0])
        original = path.read_bytes()
        for invalid in (b'{"format":1,"format":2}', b" " * 32769, b"not json"):
            path.write_bytes(invalid)
            with self.assertRaises(ValueError): self.aggregate()
        path.unlink(); path.mkdir()
        self.assertRaises(ValueError, self.aggregate)
        path.rmdir(); path.write_bytes(original)
        self.aggregate()

    def test_native_child_failure_or_changed_checkout_emits_no_ci_receipt(self):
        phase = CI.NATIVE.PHASES[0]
        destination = self.directory / CI.filename("amd64", phase)
        records = {"go.mod": "b" * 64}
        native = self.receipt("amd64", phase)["native"]
        native["source_sha256"] = CI.NATIVE.source_digest(records)
        def prepared(go, *, native_test):
            native_test(self.directory / "core", go, prospective=False, env={}, bootstrap_only=True)
        with patch.object(CI.NATIVE.BOOT, "standalone", side_effect=prepared), \
                patch.object(CI.NATIVE, "checked_sources", return_value=(self.directory / "core", records)), \
                patch.object(CI, "comparable_source", return_value="d" * 64), \
                patch.object(CI.NATIVE, "execute", return_value=native), patch.object(CI, "verify_checkout") as checked:
            value = CI.run_phase("amd64", phase, destination, "original-go", env=self.env)
            self.assertEqual(checked.call_count, 2)
            self.assertEqual(CI.read_receipt(destination), value)
            destination.unlink()
            with patch.object(CI, "verify_checkout", side_effect=[None, ValueError("changed checkout")]):
                with self.assertRaisesRegex(ValueError, "changed checkout"):
                    CI.run_phase("amd64", phase, destination, env=self.env)
            self.assertFalse(destination.exists())
            with patch.object(CI, "comparable_source", side_effect=["d" * 64, "e" * 64]):
                with self.assertRaisesRegex(ValueError, "dependency changed"):
                    CI.run_phase("amd64", phase, destination, env=self.env)
            self.assertFalse(destination.exists())
        destination.write_text(json.dumps(value))
        original = destination.read_bytes()
        with self.assertRaisesRegex(ValueError, "new owned"): CI.run_phase("amd64", phase, destination, env=self.env)
        self.assertEqual(destination.read_bytes(), original); destination.unlink()
        with patch.object(CI, "verify_checkout"), patch.object(CI.NATIVE.BOOT, "standalone", side_effect=RuntimeError("original phase failed")):
            with self.assertRaisesRegex(RuntimeError, "original phase failed"):
                CI.run_phase("amd64", phase, destination, env=self.env)
        self.assertFalse(destination.exists())

    def test_independent_temp_paths_keep_raw_modules_and_compare_the_owned_dependency(self):
        sources = []
        originals = []
        # Module parsing is the real selected Go command. Pin admission alone
        # is doubled; the compared dependency's fixture bytes remain real.
        def xray_records(directory):
            return {"source.go": hashlib.sha256((directory / "source.go").read_bytes()).hexdigest()}
        for name in ("first", "second"):
            source = self.directory / name / "core"; source.mkdir(parents=True)
            xray = source.parent / "xray"; xray.mkdir()
            (xray / "source.go").write_bytes(b"package core\n")
            raw = ("module example.invalid/native\n\ngo 1.26.3\n\nreplace github.com/xtls/xray-core => " + json.dumps(str(xray.resolve())) + "\n").encode()
            (source / "go.mod").write_bytes(raw)
            originals.append(raw); sources.append(source)
        def comparable(source):
            records = {"go.mod": hashlib.sha256((source / "go.mod").read_bytes()).hexdigest(), "other-source": "f" * 64}
            return CI.comparable_source(source, records, "go", dict(os.environ))
        with patch.object(CI.NATIVE.NODE, "xray_reference_sources", side_effect=xray_records):
            baseline = comparable(sources[0])
            self.assertEqual(baseline, comparable(sources[1]))
            self.assertNotEqual(originals[0], originals[1])
            for source, raw in zip(sources, originals): self.assertEqual((source / "go.mod").read_bytes(), raw)
            module = sources[1] / "go.mod"
            module.write_bytes(originals[1] + b"// independently changed module bytes\n")
            self.assertNotEqual(baseline, comparable(sources[1]))
            module.write_bytes(originals[1])
            dependency = sources[1].parent / "xray" / "source.go"
            dependency.write_bytes(b"package core\n// changed dependency\n")
            self.assertNotEqual(baseline, comparable(sources[1]))
            for replacement in (json.dumps(str(sources[0].parent / "xray")), '"../xray"'):
                module.write_text("module example.invalid/native\n\nreplace github.com/xtls/xray-core => " + replacement + "\n")
                with self.assertRaisesRegex(ValueError, "exact owned sibling"): comparable(sources[1])
            module.write_bytes(originals[1] + ("\nreplace example.invalid/foreign => " + json.dumps(str(sources[0])) + "\n").encode())
            with self.assertRaisesRegex(ValueError, "foreign local"): comparable(sources[1])
            module.write_bytes(originals[1])
            with self.assertRaisesRegex(ValueError, "original raw source"):
                CI.comparable_source(sources[1], {"go.mod": "0" * 64}, "go", dict(os.environ))

    def test_standalone_retains_original_preparation_and_default_complete_mode(self):
        def prepared(go, *, native_test):
            return native_test("original-source", go, prospective=False, env={"owned": "yes"}, bootstrap_only=True)
        with patch.object(CI.NATIVE.BOOT, "standalone", side_effect=prepared), patch.object(CI.NATIVE, "execute", return_value="original-result") as executed:
            self.assertEqual(CI.NATIVE.standalone("original-go"), "original-result")
            executed.assert_called_once_with("original-source", "original-go", phase="complete", receipt_path=None,
                                            prospective=False, env={"owned": "yes"}, bootstrap_only=True)
            executed.reset_mock()
            CI.NATIVE.standalone("original-go", phase="external-socks", receipt_path=self.directory / "native.json")
            self.assertEqual(executed.call_args.kwargs["phase"], "external-socks")
            self.assertTrue(executed.call_args.kwargs["bootstrap_only"])
        with self.assertRaises(ValueError): CI.NATIVE.standalone(phase="unknown")
        with self.assertRaises(ValueError): CI.NATIVE.standalone(receipt_path=self.directory / "partial.json")

    def test_real_checkout_identity_rejects_dirty_or_foreign_source(self):
        def git(*args):
            return subprocess.check_output(["git", *args], cwd=self.directory, text=True, stderr=subprocess.DEVNULL).strip()
        git("init"); git("config", "user.name", "Native receipt test"); git("config", "user.email", "native-receipt@example.invalid")
        source = self.directory / "source"; source.write_text("original")
        git("add", "source"); git("commit", "-m", "owned source")
        expected = dict(self.expected, commit=git("rev-parse", "HEAD"))
        with patch.object(CI, "ROOT", self.directory):
            CI.verify_checkout(expected)
            with self.assertRaises(ValueError): CI.verify_checkout(dict(expected, commit="f" * 40))
            source.write_text("changed")
            with self.assertRaises(ValueError): CI.verify_checkout(expected)
            git("add", "source")
            with self.assertRaises(ValueError): CI.verify_checkout(expected)

    def test_workflow_matrix_keeps_complete_inventory_and_required_aggregate(self):
        source = (ROOT / ".github/workflows/windows-physical-bootstrap-contract.yml").read_text()
        native = source.split("  native-node-kernel:\n", 1)[1].split("  native-node-composition:\n", 1)[0]
        phases = re.search(r"^        phase: \[([^\]]+)\]$", native, re.MULTILINE).group(1)
        self.assertEqual(tuple(value.strip() for value in phases.split(",")), CI.NATIVE.PHASES)
        self.assertIn("architecture: [amd64, arm64]", native)
        self.assertIn("timeout-minutes: 30", native)
        self.assertIn("needs: native-node-kernel\n    if: always()", native)
        self.assertIn('os.environ["NATIVE_RESULT"] == "success"', native)
        self.assertIn("--aggregate", native)
        self.assertIn("overwrite: true", native)
        self.assertNotIn("continue-on-error", native)


if __name__ == "__main__":
    unittest.main()
