#!/usr/bin/env python3
"""Exercise the fixed CONNECT runtime composition without native acceptance."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value

D = module("connect_runtime_under_test", ROOT / "deploy/test_focused_connect_runtime.py")
HELPER = module("connect_runtime_original_fixture", ROOT / "deploy/test_focused_socks_runtime_runner.py")
CONTROL_SOURCE = dict(HELPER.CONTROL_SOURCE)
socks_call = "\tif err := c.observeSOCKSMiddleContext(ctx, engine); err != nil {\n\t\treturn err\n\t}\n"
connect_call = "\tif err := c.observeCONNECTMiddleContext(ctx, engine); err != nil {\n\t\treturn err\n\t}\n"
CONTROL_SOURCE[D.BASE.RUNTIME] = CONTROL_SOURCE[D.BASE.RUNTIME].replace(socks_call, connect_call + socks_call)
for control in D.INVENTORY["controls"]:
    if control["path"] == D.BASE.RUNTIME:
        continue
    CONTROL_SOURCE.setdefault(control["path"], "package mobilemultihop\n")
    CONTROL_SOURCE[control["path"]] += control["before"] + "\n"

class CONNECTRuntimeGate(unittest.TestCase):
    @contextmanager
    def fixture(self, mutate=None, formatter=None):
        with patch.object(HELPER, "D", D.BASE), patch.object(HELPER, "CONTROL_SOURCE", CONTROL_SOURCE):
            with HELPER.RunnerTests.fixture(self, mutate=mutate) as values:
                args, source, output, calls = values
                original = D.BASE.CORE.execute
                formats = []
                def execute(command, candidate, environment, log, bound):
                    if Path(command[0]).name == "gofmt":
                        self.assertEqual(candidate, source)
                        self.assertEqual(bound, 60)
                        self.assertEqual(command, ["/captured/gofmt", "-d",
                                          *(str(source / p) for p in D.INVENTORY["files"])])
                        formats.append(command)
                        log.write_bytes(b"")
                        return formatter(source, log) if formatter else (0, False, True)
                    return original(command, candidate, environment, log, bound)
                with patch.object(D.BASE.CORE, "execute", side_effect=execute):
                    yield args, source, output, calls, formats

    def test_fixed_dispatch_and_candidate_allowlist_are_exact(self):
        identity = module("connect_runtime_identity", ROOT / "deploy/focused_source_identity.py")
        self.assertEqual(identity.ALLOWLISTS[D.SUITE], frozenset(D.INVENTORY["files"]))
        self.assertEqual(identity.ALLOWLISTS["socks-runtime"], frozenset(D.ORIGINAL_SOURCE_PATHS))
        workflow = (ROOT / ".github/workflows/focused-source-validation.yml").read_text()
        self.assertEqual(workflow.count("          - connect-runtime\n"), 1)
        self.assertEqual(workflow.count("if: inputs.suite == 'connect-runtime'"), 1)
        self.assertEqual(workflow.count("python3 validator/deploy/test_focused_connect_runtime.py"), 1)
        self.assertEqual(workflow.count("python3 validator/deploy/test_focused_connect_runtime_runner.py"), 1)

    def test_original_six_attempts_and_all_original_controls_survive(self):
        self.assertEqual([len(c.expected) for c in D.ORIGINAL_CASES], [36, 27, 17, 9, 5, 1])
        self.assertEqual(D.cases()[:6], D.ORIGINAL_CASES)
        self.assertTrue(set(D.ORIGINAL_SOURCE_PATHS).issubset(D.BASE.SOURCE_PATHS))
        for key, value in D.ORIGINAL_MUTATION_PATHS.items():
            self.assertEqual(D.BASE.MUTATION_PATHS[key], value)
        for case in D.ORIGINAL_CASES[3:]:
            original = CONTROL_SOURCE[D.BASE.MUTATION_PATHS[case.mutation]]
            self.assertEqual(D.mutation_source(case, original), D.ORIGINAL_MUTATION_SOURCE(case, original))

    def test_exact_new_inventory_original_commands_and_bounds(self):
        selected = D.cases()
        self.assertEqual([len(c.expected) for c in selected[6:]], [52, 10, 6, 2, 1])
        self.assertEqual(sum(len(c.expected) for c in selected if not c.mutation), 132)
        self.assertEqual(sum(bool(c.mutation) for c in selected), 7)
        self.assertEqual(len(D.INVENTORY["files"]), 11)
        self.assertEqual(len(D.BASE.SOURCE_PATHS), 13)
        for case in selected:
            self.assertEqual((case.seconds, case.outer_seconds), (120, 600))
            command = D.BASE.command_for("/captured/go", case, Path("/overlay") if case.mutation else None)
            for item in ("-race", "-p=2", "-mod=readonly", "-json", "-count=1", "-timeout=120s"):
                self.assertIn(item, command)
            self.assertEqual(command[-1], "./internal/mobilemultihop")

    def test_foreign_suite_control_or_missing_overlay_cannot_execute(self):
        for name in ("", "socks-runtime", "connect-source", None):
            with self.assertRaises(ValueError):
                D.cases(name)
        for case in D.cases()[7:]:
            with self.assertRaises(ValueError):
                D.BASE.command_for("/go", case)
            control = next(c for c in D.INVENTORY["controls"] if c["name"] == case.mutation)
            original = "before\n" + control["before"] + "\nafter"
            self.assertEqual(D.mutation_source(case, original), "before\n" + control["after"] + "\nafter")
            for wrong in ("", original + original):
                with self.assertRaises(ValueError):
                    D.mutation_source(case, wrong)

    def test_actual_composition_preserves_all_records_hashes_and_source(self):
        with self.fixture() as (args, source, output, calls, formats):
            D.validate(args)
            receipt = json.loads((output / "manifest.json").read_text())
            self.assertEqual(receipt["status"], "passed")
            self.assertEqual([x["name"] for x in receipt["attempts"]], [c.name for c in D.cases()])
            self.assertEqual(len(calls), 11)
            self.assertEqual(len(formats), 1)
            self.assertEqual(receipt["composition"]["driver_sha256"], hashlib.sha256(Path(D.__file__).read_bytes()).hexdigest())
            self.assertEqual(receipt["composition"]["original_driver_sha256"], hashlib.sha256(D.BASE_PATH.read_bytes()).hexdigest())
            self.assertEqual(receipt["composition"]["encrypted_native_host_delivery"], "unfinished")
            self.assertIn("no encrypted CONNECT", receipt["scope"])
            self.assertEqual(receipt["formatting"]["exit"], 0)
            self.assertTrue(receipt["formatting"]["process_group_joined"])
            for row in receipt["attempts"]:
                self.assertEqual(row["log_sha256"], hashlib.sha256((output / row["log"]).read_bytes()).hexdigest())

    def test_original_failure_stops_before_added_runtime_and_controls(self):
        def bad(case, source, log, calls):
            if case == D.ORIGINAL_CASES[0]:
                log.write_bytes(b"not a framed test result\n")
            return (1 if case.mutation else 0), False, True
        with self.fixture(mutate=bad) as (args, source, output, calls, formats):
            with self.assertRaises(RuntimeError):
                D.validate(args)
            self.assertEqual(len(calls), 1)
            self.assertEqual(json.loads((output / "manifest.json").read_text())["status"], "failed")

    def test_missing_duplicate_skipped_foreign_and_racy_runtime_records_fail(self):
        for fault in ("missing", "duplicate", "skip", "foreign", "race"):
            def bad(case, source, log, calls):
                if case.name == "ordered-connect-runtime":
                    rows = [json.loads(line) for line in log.read_bytes().splitlines()]
                    if fault == "missing":
                        rows.pop(0)
                    elif fault == "duplicate":
                        rows.insert(1, dict(rows[0]))
                    elif fault == "skip":
                        rows[1]["Action"] = "skip"
                    elif fault == "foreign":
                        rows[0]["Package"] = "foreign/package"
                    else:
                        rows.insert(1, {"Action": "output", "Package": D.BASE.CORE.PACKAGE,
                                         "Test": rows[0]["Test"], "Output": "WARNING: DATA RACE\n"})
                    log.write_bytes(b"\n".join(json.dumps(row).encode() for row in rows) + b"\n")
                return (1 if case.mutation else 0), False, True
            with self.subTest(fault=fault), self.fixture(mutate=bad) as (args, source, output, calls, formats):
                with self.assertRaises(RuntimeError):
                    D.validate(args)
                self.assertEqual(len(calls), 7)
                self.assertEqual(json.loads((output / "manifest.json").read_text())["status"], "failed")

    def test_each_new_control_requires_its_original_witness_and_owned_join(self):
        for chosen in D.cases()[7:]:
            for fault in ("witness", "unjoined", "timeout"):
                def bad(case, source, log, calls):
                    if case.name == chosen.name:
                        if fault == "witness":
                            log.write_bytes(log.read_bytes().replace(case.witness.encode(), b"foreign witness"))
                        if fault == "unjoined":
                            return 1, False, False
                        if fault == "timeout":
                            return 1, True, True
                    return (1 if case.mutation else 0), False, True
                with self.subTest(control=chosen.name, fault=fault), self.fixture(mutate=bad) as (args, source, output, calls, formats):
                    with self.assertRaises(RuntimeError):
                        D.validate(args)
                    self.assertEqual(calls[-1][0].name, chosen.name)
                    self.assertEqual(json.loads((output / "manifest.json").read_text())["status"], "failed")

    def test_formatter_diff_failure_timeout_unjoined_and_source_change_block_tests(self):
        for fault in ("diff", "failure", "timeout", "unjoined", "source"):
            def formatter(source, log):
                if fault == "diff":
                    log.write_bytes(b"diff original original\n")
                    return 1, False, True
                if fault == "failure":
                    return 2, False, True
                if fault == "timeout":
                    return -1, True, True
                if fault == "unjoined":
                    return 0, False, False
                (source / D.INVENTORY["files"][0]).write_text("changed original source\n")
                return 0, False, True
            with self.subTest(fault=fault), self.fixture(formatter=formatter) as (args, source, output, calls, formats):
                with self.assertRaises(RuntimeError):
                    D.validate(args)
                self.assertFalse(calls)
                self.assertEqual(len(formats), 1)
                receipt = json.loads((output / "manifest.json").read_text())
                self.assertEqual(receipt["status"], "failed")
                self.assertIsInstance(receipt["formatting"], dict)

    def test_stale_or_symlinked_manifest_is_never_adopted(self):
        for kind in ("existing", "symlink"):
            with self.subTest(kind=kind), self.fixture() as (args, source, output, calls, formats):
                output.mkdir()
                path = output / "manifest.json"
                if kind == "existing":
                    path.write_text('{"status":"passed"}')
                else:
                    path.symlink_to(output / "missing.json")
                with self.assertRaisesRegex(ValueError, "fresh"):
                    D.validate(args)
                self.assertFalse(calls)
                self.assertFalse(formats)

if __name__ == "__main__":
    unittest.main(verbosity=2)
