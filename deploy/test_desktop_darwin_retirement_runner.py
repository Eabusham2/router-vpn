#!/usr/bin/env python3
"""Executable omission controls for the required Darwin retirement runner."""
from pathlib import Path
import importlib.util
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("darwin_retirement_runner", ROOT / "deploy/test_desktop_darwin_retirement.py")
RUNNER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RUNNER)


def wire(cases):
    rows = [{"Package": RUNNER.PACKAGE, "Action": "start"}]
    for root, leaves in cases.items():
        rows.append({"Package": RUNNER.PACKAGE, "Test": root, "Action": "run"})
        for leaf in leaves:
            for action in ("run", "pass"):
                rows.append({"Package": RUNNER.PACKAGE, "Test": root + "/" + leaf, "Action": action})
        rows.append({"Package": RUNNER.PACKAGE, "Test": root, "Action": "pass"})
    rows.append({"Package": RUNNER.PACKAGE, "Action": "pass"})
    return "\n".join(json.dumps(row) for row in rows)


class DarwinRetirementRunnerTests(unittest.TestCase):
    def test_original_inventory_and_bounds(self):
        self.assertEqual(RUNNER.require_pass(wire(RUNNER.SOURCE_CASES), RUNNER.SOURCE_CASES), 20)
        native = {RUNNER.NATIVE_ROOT: RUNNER.NATIVE_CASES}
        self.assertEqual(RUNNER.require_pass(wire(native), native), 5)
        self.assertEqual(RUNNER.TEST_TIMEOUT, "120s")
        self.assertEqual(RUNNER.PROCESS_TIMEOUT, 600)
        self.assertEqual(len(RUNNER.MUTATIONS), 5)

    def test_compiled_root_omission_and_substitution(self):
        roots = [*RUNNER.SOURCE_CASES, RUNNER.NATIVE_ROOT]
        RUNNER.discover("\n".join(roots))
        for changed in (roots[:-1], [*roots, roots[0]], [*roots[:-1], "TestForeignNativeOwner"]):
            with self.assertRaises(ValueError):
                RUNNER.discover("\n".join(changed))

    def test_missing_extra_duplicate_or_skipped_verdict(self):
        original = wire(RUNNER.SOURCE_CASES).splitlines()
        alterations = [original[:-1], [*original, original[0]],
                       [*original, json.dumps({"Package": RUNNER.PACKAGE, "Test": "TestForeign", "Action": "pass"})],
                       [*original[:-1], original[-1].replace('"pass"', '"skip"')]]
        for changed in alterations:
            with self.assertRaises(ValueError):
                RUNNER.require_pass("\n".join(changed), RUNNER.SOURCE_CASES)

    def test_race_and_changed_package_rejected(self):
        baseline = wire(RUNNER.SOURCE_CASES)
        race = json.dumps({"Package": RUNNER.PACKAGE, "Action": "output", "Output": "WARNING: DATA RACE"})
        for changed in (baseline + "\n" + race, baseline.replace(RUNNER.PACKAGE, "foreign/package"), "compile failed"):
            with self.assertRaises(ValueError):
                RUNNER.require_pass(changed, RUNNER.SOURCE_CASES)

    def test_native_leaf_cannot_be_replaced_by_source_pass(self):
        native = {RUNNER.NATIVE_ROOT: RUNNER.NATIVE_CASES}
        with self.assertRaises(ValueError):
            RUNNER.require_pass(wire(RUNNER.SOURCE_CASES), native)

    def test_original_runs_and_package_end_are_mandatory(self):
        rows = [json.loads(line) for line in wire(RUNNER.SOURCE_CASES).splitlines()]
        altered = [
            [row for row in rows if row["Action"] != "run"],
            rows[1:],
            rows[:-1],
            [rows[0], *rows[2:]],
            [*rows, rows[-1]],
            [*rows, {"Package": RUNNER.PACKAGE, "Action": "output", "Output": "late"}],
        ]
        for changed in altered:
            with self.assertRaises(ValueError):
                RUNNER.require_pass("\n".join(json.dumps(row) for row in changed), RUNNER.SOURCE_CASES)

    def test_run_pass_order_and_joined_children_are_required(self):
        rows = [json.loads(line) for line in wire(RUNNER.SOURCE_CASES).splitlines()]
        before_run = list(rows)
        before_run[2], before_run[3] = before_run[3], before_run[2]
        repeated_run = [*rows[:3], rows[2], *rows[3:]]
        root = next(iter(RUNNER.SOURCE_CASES))
        early_parent = [*rows[:3], {"Package": RUNNER.PACKAGE, "Test": root, "Action": "pass"}, *rows[3:]]
        for changed in (before_run, repeated_run, early_parent):
            with self.assertRaises(ValueError):
                RUNNER.require_pass("\n".join(json.dumps(row) for row in changed), RUNNER.SOURCE_CASES)

    def test_control_requires_exact_causal_failure(self):
        witness = "TestRouterVPNDarwinNodeChainRouteRetirement/missing"
        message = "unowned route was deleted or adopted"
        root = witness.split("/")[0]
        output = "\n".join(json.dumps(event) for event in (
            {"Package": RUNNER.PACKAGE, "Action": "start"},
            {"Package": RUNNER.PACKAGE, "Action": "run", "Test": root},
            {"Package": RUNNER.PACKAGE, "Action": "run", "Test": witness},
            {"Package": RUNNER.PACKAGE, "Action": "output", "Test": witness, "Output": message},
            {"Package": RUNNER.PACKAGE, "Action": "fail", "Test": witness},
            {"Package": RUNNER.PACKAGE, "Action": "fail", "Test": root},
            {"Package": RUNNER.PACKAGE, "Action": "fail"},
        ))
        RUNNER.require_rejection(1, output, witness, message)
        for code, changed in ((0, output), (2, output), (1, output.replace(witness, "TestForeign")),
                              (1, output.replace(message, "unrelated assertion")), (1, "compile failed")):
            with self.assertRaises(ValueError):
                RUNNER.require_rejection(code, changed, witness, message)


if __name__ == "__main__":
    unittest.main()
