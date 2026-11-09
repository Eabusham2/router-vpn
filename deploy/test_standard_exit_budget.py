#!/usr/bin/env python3
"""Keep the complete Custom standard-exit Go gate finite and mandatory.

The identical 7c4a3eed controller/common inventory completed in 632.093s in
Multihop CI with its existing 15m package limit. This workflow instead hit Go's
implicit 10m limit at 600.037s while its current leaf was only 0s old. The bound
below applies to the aggregate package; runtime and fixture deadlines stay in
their own source, and every original test/example/fuzz seed still executes.
"""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/standard-exit-contract.yml"
COMMAND = "go test ./cmd/client ./internal/common -timeout=15m"
STEP = "      - name: Go custom-exit unified-profile and external-entry tests\n"
CONTRACT = "      - name: Validate complete custom-exit package budget\n"


def check(source):
    jobs = re.findall(r"(?ms)^  desktop:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", source)
    if len(jobs) != 1:
        raise AssertionError("Custom standard-exit lost its single desktop job")
    job = jobs[0]
    header = job.split("    steps:\n", 1)[0]
    if re.search(r"(?m)^    (?:if|continue-on-error):", header):
        raise AssertionError("Custom standard-exit became conditional or nonblocking")
    for marker, command in ((CONTRACT, "python3 deploy/test_standard_exit_budget.py"), (STEP, COMMAND)):
        if job.count(marker) != 1:
            raise AssertionError("Custom standard-exit lost or duplicated a mandatory gate")
        block = job.split(marker, 1)[1].split("      - ", 1)[0]
        actual = "\n".join(line for line in block.splitlines() if line.strip() and not line.lstrip().startswith("#"))
        if actual != "        run: " + command:
            raise AssertionError("Custom standard-exit must retain the entire finite, unfiltered command")
    if job.index(CONTRACT) >= job.index(STEP):
        raise AssertionError("Custom standard-exit contract must run before the complete package gate")


class CompleteStandardExitBudget(unittest.TestCase):
    def setUp(self):
        self.source = WORKFLOW.read_text(encoding="utf-8")

    def test_shipping_complete_inventory_and_finite_budget(self):
        check(self.source)

    def test_rejects_omitted_filtered_and_unbounded_execution(self):
        commands = (
            "true",
            "go test ./cmd/client ./internal/common",
            COMMAND.replace("15m", "10m"),
            COMMAND.replace("15m", "0"),
            COMMAND.replace("15m", "360m"),
            COMMAND.replace("./cmd/client ./internal/common", "./internal/common"),
            COMMAND.replace("./cmd/client ./internal/common", "./cmd/client"),
            COMMAND + " -run '^$'",
            COMMAND + " -run '^Test'",
            COMMAND + " -skip '^TestDesktopTor'",
            COMMAND + " -short",
            COMMAND.replace("go test", "go test -c"),
            COMMAND + " || true",
            COMMAND + " &",
            COMMAND + "\n          || true",
        )
        self.assertEqual(self.source.count("        run: " + COMMAND + "\n"), 1)
        for command in commands:
            with self.subTest(command=command), self.assertRaises(AssertionError):
                check(self.source.replace(COMMAND, command, 1))

    def test_rejects_missing_duplicate_and_nonblocking_steps(self):
        for marker in (STEP, CONTRACT):
            variants = (
                self.source.replace(marker, "      - name: Omitted gate\n", 1),
                self.source.replace(marker, marker + "        run: true\n" + marker, 1),
                self.source.replace(marker, marker + "        if: false\n", 1),
                self.source.replace(marker, marker + "        continue-on-error: true\n", 1),
            )
            for index, source in enumerate(variants):
                with self.subTest(step=marker.strip(), variant=index), self.assertRaises(AssertionError):
                    check(source)

    def test_rejects_conditional_nonblocking_and_duplicate_job(self):
        for addition in ("    if: false\n", "    continue-on-error: true\n"):
            with self.subTest(addition=addition), self.assertRaises(AssertionError):
                check(self.source.replace("  desktop:\n", "  desktop:\n" + addition, 1))
        with self.assertRaises(AssertionError):
            check(self.source + "\n  desktop:\n    runs-on: ubuntu-24.04\n")


if __name__ == "__main__":
    unittest.main()
