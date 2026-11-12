#!/usr/bin/env python3
"""Keep the entire original package gate mandatory in bounded whole-root phases.

Compiled controller roots are exhaustive, including examples and ordinary fuzz
seeds. The runner keeps each 15m Go alarm and every test-owned operation bound;
other requested packages remain unfiltered. This guard rejects scope loss.
"""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/mtu-throughput-contract.yml"
COMMAND = "python3 deploy/test_go_source_groups.py --scope client"
STEP = "      - name: Go client MTU Retest and Portable path seam compiles\n"
CONTRACT = "      - name: Validate complete MTU controller package budget\n"


def check(source):
    jobs = re.findall(r"(?ms)^  unix-contract:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", source)
    if len(jobs) != 1:
        raise AssertionError("MTU throughput lost its single unix-contract job")
    job = jobs[0]
    header = job.split("    steps:\n", 1)[0]
    if re.search(r"(?m)^    (?:if|continue-on-error):", header):
        raise AssertionError("MTU throughput became conditional or nonblocking")
    for marker, command in ((CONTRACT, "python3 deploy/test_mtu_throughput_budget.py"), (STEP, COMMAND)):
        if job.count(marker) != 1:
            raise AssertionError("MTU throughput lost or duplicated a mandatory gate")
        block = job.split(marker, 1)[1].split("      - ", 1)[0]
        actual = "\n".join(line for line in block.splitlines() if line.strip() and not line.lstrip().startswith("#"))
        if actual != "        run: " + command:
            raise AssertionError("MTU throughput must retain the entire finite, unfiltered command")
    if job.index(CONTRACT) >= job.index(STEP):
        raise AssertionError("MTU throughput contract must run before the complete package gate")


class CompleteMTUThroughputBudget(unittest.TestCase):
    def setUp(self):
        self.source = WORKFLOW.read_text(encoding="utf-8")

    def test_shipping_complete_inventory_and_finite_budget(self):
        check(self.source)

    def test_rejects_omitted_filtered_and_unbounded_execution(self):
        commands = (
            "true",
            'go test ./cmd/client -count=1',
            'go test ./cmd/client -count=1 -timeout=10m',
            'go test ./cmd/client -count=1 -timeout=0',
            'go test ./cmd/client -count=1 -timeout=360m',
            'go test ./internal/common -count=1 -timeout=15m',
            'go test ./cmd/client -timeout=15m',
            "python3 deploy/test_go_source_groups.py --scope omitted",
            COMMAND.replace("--scope client", "--scope client-common"),
            COMMAND + " --timeout=0",
            COMMAND + " --timeout=360m",
            COMMAND + " -run '^$'",
            COMMAND + " -run '^Test'",
            COMMAND + " -skip '^TestDesktopTor'",
            COMMAND + " -short",
            'go test -c ./cmd/client -timeout=15m',
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
                check(self.source.replace("  unix-contract:\n", "  unix-contract:\n" + addition, 1))
        with self.assertRaises(AssertionError):
            check(self.source + "\n  unix-contract:\n    runs-on: ubuntu-24.04\n")


if __name__ == "__main__":
    unittest.main()
