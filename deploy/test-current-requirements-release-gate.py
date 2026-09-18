#!/usr/bin/env python3
"""Execute release orchestration with deterministic child-process outcomes.

Only subprocesses are doubled: the actual source/workflow dependency checks and
actual checked delegation list execute. The current and reconciled audits are
executed for real by the parent gate; these tests prove a failed audit cannot be
ignored before release orchestration declares success.
"""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import runpy
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
LATEST = (
    "deploy/current-requirements-audit.py",
    "deploy/reconciled-project-contract-audit.py",
)
ORCHESTRATOR = ROOT / "deploy/release-orchestration-audit.py"


class CurrentRequirementsReleaseGateTest(unittest.TestCase):
    def execute(self, failed=None):
        calls = []
        output = io.StringIO()

        def run(args, **kwargs):
            script = Path(args[1]).relative_to(ROOT).as_posix()
            calls.append(script)
            if script == failed:
                # check=True is what prevents a failure from being discarded.
                if kwargs.get("check"):
                    raise subprocess.CalledProcessError(9, args, stderr="injected latest-contract failure")
                return subprocess.CompletedProcess(args, 9, stdout="", stderr="injected failure")
            report = {
                "source_weight": 88.0, "manual_live_weight": 12.0,
                "source_earned": 88.0, "recovered_gates": [], "legacy_gates": [],
            }
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps(report), stderr="")

        error = None
        with patch.object(subprocess, "run", side_effect=run), redirect_stdout(output):
            try:
                runpy.run_path(str(ORCHESTRATOR), run_name="__main__")
            except subprocess.CalledProcessError as exc:
                error = exc
        return calls, output.getvalue(), error

    def test_both_latest_contracts_run_before_historical_delegates(self):
        calls, output, error = self.execute()
        self.assertIsNone(error)
        self.assertEqual(calls[:2], list(LATEST))
        for script in LATEST:
            self.assertEqual(calls.count(script), 1)
        self.assertIn("authoritative one-SHA release orchestration", output)

    def test_each_latest_contract_failure_prevents_success(self):
        for failed in LATEST:
            with self.subTest(failed=failed):
                calls, output, error = self.execute(failed)
                self.assertIsNotNone(error, "latest-contract failure was silently ignored")
                self.assertEqual(error.returncode, 9)
                self.assertEqual(calls[-1], failed)
                self.assertNotIn("authoritative one-SHA release orchestration", output)
                self.assertNotIn("deploy/docker-cleanup-safety-audit.py", calls)


if __name__ == "__main__":
    unittest.main()
