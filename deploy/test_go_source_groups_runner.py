#!/usr/bin/env python3
"""Negative controls for complete compiled controller phases and required callers.

--compiled-fixture additionally executes a tiny, non-network Go test binary to
verify real test2json ordering, parallel children, examples and fuzz seeds. It
does not execute or stand in for native Router VPN acceptance.
"""
from pathlib import Path
import argparse
import json
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_go_source_groups as gate

WORKFLOWS = (
    ("multihop-contract.yml", "multihop-source", "Runtime and UI Go contracts", "client-common"),
    ("standard-exit-contract.yml", "desktop", "Go custom-exit unified-profile and external-entry tests", "client-common"),
    ("release-gap-audit.yml", "audit", "Compile and test shared source contracts", "client-common"),
    ("requirements-closure.yml", "source-contract", "Compile and test Go source", "all"),
    ("release-candidate.yml", "source-audit", "Go source contracts", "all"),
    ("client-apps-ci.yml", "desktop-unix", "Test Go controller and shared API", "all"),
    ("mtu-throughput-contract.yml", "unix-contract", "Go client MTU Retest and Portable path seam compiles", "client"),
)


def check_workflow(source, job_name, step_name, scope):
    jobs = re.findall(r"(?ms)^  " + re.escape(job_name) + r":\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", source)
    if len(jobs) != 1:
        raise ValueError("Missing or duplicated complete Go source job")
    header = jobs[0].split("    steps:\n", 1)[0]
    if re.search(r"(?m)^    (?:if|continue-on-error):", header):
        raise ValueError("Complete Go source job became conditional or nonblocking")
    marker = "      - name: " + step_name + "\n"
    if jobs[0].count(marker) != 1:
        raise ValueError("Missing or duplicated complete Go source step")
    block = jobs[0].split(marker, 1)[1].split("      - ", 1)[0]
    actual = "\n".join(line for line in block.splitlines()
                       if line.strip() and not line.lstrip().startswith("#"))
    expected = "        run: python3 deploy/test_go_source_groups.py --scope " + scope
    if actual != expected:
        raise ValueError("Complete Go source scope, status or execution changed")
    if job_name == "source-contract" and "requirements-closure" in source:
        if re.findall(r"(?m)^    timeout-minutes: (\d+)$", header) != ["45"]:
            raise ValueError("Requirements closure lost its original finite job budget")


def event(action, name="", **fields):
    result = {"Action": action, "Package": gate.PACKAGE}
    if name:
        result["Test"] = name
    result.update(fields)
    return result


def encode(events):
    return "\n".join(json.dumps(value) for value in events)


def receipts(root="TestWhole"):
    return [event("start"), event("run", root), event("run", root + "/negative"),
            event("pass", root + "/negative"), event("pass", root), event("pass")]


class RunnerTests(unittest.TestCase):
    def test_inventory_preserves_new_tests_examples_and_fuzz_but_not_benchmarks(self):
        names = ("TestOriginal", "TestFutureNegative", "Example", "ExampleNamed_suffix", "FuzzSeed", "BenchmarkReader")
        self.assertEqual(gate.inventory("\n".join(names) + "\n"), names[:-1])

    def test_inventory_rejects_empty_duplicate_noise_and_child_only_lists(self):
        for value in ("", "BenchmarkOnly\n", "TestA\nTestA\n", "TestA/negative\n", "PASS\n", " TestA\n", "TestA\n\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.inventory(value)

    def test_packages_keep_the_complete_original_scope(self):
        original = (gate.PACKAGE, "router-vpn/internal/common", "router-vpn/future/package", "router-vpn")
        self.assertEqual(gate.packages("\n".join(original), "all"), original)
        self.assertEqual(gate.other_command(original), ["go", "test", "-timeout=15m", *original[1:]])
        self.assertIsNone(gate.other_command((gate.PACKAGE,)))
        self.assertEqual(gate.packages(gate.PACKAGE, "client"), (gate.PACKAGE,))
        for value, scope in (("", "all"), (original[1], "all"), (gate.PACKAGE + "\n" + gate.PACKAGE, "all"),
                             (gate.PACKAGE, "client-common"), ("\n".join(original), "client-common"),
                             (gate.PACKAGE + "\nerror text", "all")):
            with self.subTest(scope=scope, value=value), self.assertRaises(ValueError):
                gate.packages(value, scope)

    def test_partition_rejects_missing_duplicate_reordered_and_child_phases(self):
        roots = ("TestOriginal", "Example", "FuzzSeed", "TestNewNegative")
        gate.validate_partition(roots, roots)
        for phases in (roots[:-1], roots + roots[:1], roots[::-1], ("TestOriginal/negative",) + roots[1:]):
            with self.subTest(phases=phases), self.assertRaises(ValueError):
                gate.validate_partition(roots, phases)
        with self.assertRaises(ValueError):
            gate.validate_partition((), ())

    def test_real_command_keeps_whole_root_and_original_timeout(self):
        command = gate.command(Path("/tmp/captured.test"), "TestOriginal", Path("/original/go/test2json"))
        self.assertEqual(command, ["/original/go/test2json", "-p", gate.PACKAGE, "-t", "/tmp/captured.test",
                                  "-test.v=test2json", "-test.count=1", "-test.timeout=15m", "-test.run=^TestOriginal$"])
        for root in ("TestOriginal/negative", "BenchmarkReader", "TestA|TestB", ""):
            with self.subTest(root=root), self.assertRaises(ValueError):
                gate.command(Path("/tmp/captured.test"), root, Path("/original/go/test2json"))

    def test_resolves_the_exact_selected_tool_including_go126_cached_images(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-original-tool-") as directory:
            original = Path(directory) / "cache with spaces" / "test2json"
            original.parent.mkdir()
            original.write_bytes(b"component tool identity only\n")
            original.chmod(0o700)
            with patch.object(gate.subprocess, "check_output", return_value=str(original) + "\n") as resolve:
                self.assertEqual(gate.test2json_tool(Path(directory)), original)
                resolve.assert_called_once_with(["go", "tool", "-n", "test2json"], cwd=Path(directory), text=True, timeout=120)

    def test_missing_relative_nonexecutable_or_extra_tool_output_rejects(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-rejected-tool-") as directory:
            original = Path(directory) / "test2json"
            original.write_bytes(b"not executable\n")
            original.chmod(0o600)
            for value in ("", "relative/test2json", str(original), str(original) + " -p alternate", str(original) + "\nextra"):
                with self.subTest(value=value), patch.object(gate.subprocess, "check_output", return_value=value), self.assertRaises(ValueError):
                    gate.test2json_tool(Path(directory))

    def test_actual_descendants_remain_required_and_skips_are_not_passes(self):
        result = gate.verdict(encode(receipts()), 0, "TestWhole")
        self.assertEqual(result, {"TestWhole/negative": "pass", "TestWhole": "pass"})
        skipped = [event("start"), event("run", "TestNeedsNativeHost"),
                   event("output", "TestNeedsNativeHost", Output="actual native host required\n"),
                   event("skip", "TestNeedsNativeHost"), event("pass")]
        terminal = gate.verdict(encode(skipped), 0, "TestNeedsNativeHost")
        self.assertEqual(terminal, {"TestNeedsNativeHost": "skip"})
        reported = [json.loads(line) for line in gate.report_lines(encode(skipped), terminal)]
        self.assertEqual(reported, skipped[2:4])

    def test_zero_exit_or_pass_text_cannot_replace_receipts(self):
        for value in ("", "PASS", encode([event("start"), event("pass")]), encode(receipts()[:-1])):
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.verdict(value, 0, "TestWhole")
        with self.assertRaises(ValueError):
            gate.verdict(encode(receipts()), 1, "TestWhole")

    def test_missing_negative_receipt_and_wrong_root_are_rejected(self):
        missing = [value for value in receipts() if not (value["Action"] == "pass" and value.get("Test") == "TestWhole/negative")]
        with self.assertRaises(ValueError):
            gate.verdict(encode(missing), 0, "TestWhole")
        with self.assertRaises(ValueError):
            gate.verdict(encode(receipts("TestOther")), 0, "TestWhole")

    def test_failure_race_malformed_package_and_unknown_events_reject(self):
        variants = []
        failed = receipts()
        failed[3] = event("fail", "TestWhole/negative")
        variants.append(encode(failed))
        variants.append(encode(receipts()).replace(gate.PACKAGE, "other/package"))
        variants.append(encode([event("start"), event("unknown")]))
        variants.append(encode([event("start"), event("output", Output="WARNING: DATA RACE\n"), *receipts()[1:]]))
        variants.append(encode(receipts()) + "\nnot-json")
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.verdict(value, 0, "TestWhole")
        with self.assertRaises(ValueError):
            gate.verdict(encode(receipts()), 0, "TestWhole", "race detected during execution of test")

    def test_duplicate_or_out_of_order_original_receipts_reject(self):
        original = receipts()
        variants = [original[:2] + [original[1]] + original[2:], original[:4] + [original[3]] + original[4:],
                    [original[1], original[0], *original[2:]], original + [event("output", Output="late")],
                    [original[0], original[2], original[1], *original[3:]],
                    [*original[:3], original[4], original[3], original[5]]]
        for values in variants:
            with self.subTest(values=values), self.assertRaises(ValueError):
                gate.verdict(encode(values), 0, "TestWhole")

    def test_no_new_child_after_an_original_ancestor_completed(self):
        values = receipts()[:-1] + [event("run", "TestWhole/late"), event("pass", "TestWhole/late"), event("pass")]
        with self.assertRaises(ValueError):
            gate.verdict(encode(values), 0, "TestWhole")
        values = [*receipts()[:4], event("run", "TestWhole/negative/late"), event("pass", "TestWhole/negative/late"), *receipts()[4:]]
        with self.assertRaises(ValueError):
            gate.verdict(encode(values), 0, "TestWhole")

    def test_parallel_children_must_resume_and_join(self):
        values = [event("start"), event("run", "TestWhole"), event("run", "TestWhole/parallel"),
                  event("pause", "TestWhole/parallel"), event("cont", "TestWhole/parallel"),
                  event("pass", "TestWhole/parallel"), event("pass", "TestWhole"), event("pass")]
        gate.verdict(encode(values), 0, "TestWhole")
        for index in (3, 4):
            with self.subTest(removed=index), self.assertRaises(ValueError):
                gate.verdict(encode(values[:index] + values[index + 1:]), 0, "TestWhole")

    def test_final_inventory_does_not_accept_omissions_or_reused_receipts(self):
        roots = ("TestWhole", "Example")
        results = [(root, gate.verdict(encode(receipts(root)), 0, root)) for root in roots]
        self.assertEqual(gate.complete(roots, results), {"pass": 4})
        for result in (results[:-1], results + results[:1], results[::-1],
                       [(roots[0], {roots[0]: "pass"}), (roots[1], results[0][1])]):
            with self.subTest(result=result), self.assertRaises(ValueError):
                gate.complete(roots, result)

    def test_timeout_reaps_only_the_original_phase_group_before_propagating(self):
        process = Mock(pid=123456)
        process.communicate.side_effect = [subprocess.TimeoutExpired("original phase", 930), ("", "")]
        with patch.object(gate.subprocess, "Popen", return_value=process) as start, patch.object(gate.os, "killpg") as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                gate.run_phase(Path("/tmp/original.test"), "TestWhole", Path("/tmp/original-package"), Path("/original/go/test2json"))
            self.assertEqual(start.call_count, 1)
            self.assertTrue(start.call_args.kwargs["start_new_session"])
            self.assertEqual(start.call_args.kwargs["cwd"], Path("/tmp/original-package"))
            kill.assert_called_once_with(process.pid, gate.signal.SIGKILL)
            self.assertEqual(process.communicate.call_count, 2)

    def test_all_seven_shipping_workflows_keep_the_original_required_scope(self):
        self.assertEqual(len(WORKFLOWS), 7)
        for filename, job, step, scope in WORKFLOWS:
            with self.subTest(workflow=filename):
                check_workflow((gate.ROOT / ".github/workflows" / filename).read_text(encoding="utf-8"), job, step, scope)

    def test_workflow_filters_subset_and_ignored_exit_cannot_weaken_the_gate(self):
        for filename, job, step, scope in WORKFLOWS:
            source = (gate.ROOT / ".github/workflows" / filename).read_text(encoding="utf-8")
            command = "python3 deploy/test_go_source_groups.py --scope " + scope
            for replacement in ("true", command + " --run '^$'", command + " --short", command + " || true", command + " &",
                                command + " --timeout=0", "go test ./cmd/client -run '^$'", command.replace("--scope " + scope, "--scope omitted")):
                with self.subTest(workflow=filename, replacement=replacement), self.assertRaises(ValueError):
                    check_workflow(source.replace(command, replacement, 1), job, step, scope)
            for different in set(gate.SCOPES) - {scope}:
                with self.subTest(workflow=filename, scope=different), self.assertRaises(ValueError):
                    check_workflow(source.replace(command, command.replace(scope, different), 1), job, step, scope)

    def test_workflow_missing_duplicate_conditional_and_nonblocking_steps_reject(self):
        for filename, job, step, scope in WORKFLOWS:
            source = (gate.ROOT / ".github/workflows" / filename).read_text(encoding="utf-8")
            marker = "      - name: " + step + "\n"
            for changed in (source.replace(marker, "      - name: Omitted\n", 1),
                            source.replace(marker, marker + "        run: true\n" + marker, 1),
                            source.replace(marker, marker + "        if: false\n", 1),
                            source.replace(marker, marker + "        continue-on-error: true\n", 1),
                            source.replace("  " + job + ":\n", "  " + job + ":\n    if: false\n", 1),
                            source + "\n  " + job + ":\n    runs-on: ubuntu-24.04\n"):
                with self.subTest(workflow=filename), self.assertRaises(ValueError):
                    check_workflow(changed, job, step, scope)


GO_FIXTURE = r'''package inventory
import ("flag"; "fmt"; "os"; "testing")
func TestMain(m *testing.M) {
    flag.Parse()
    if flag.Lookup("test.list").Value.String() == "" { fmt.Println("component TestMain entered") }
    os.Exit(m.Run())
}
func TestWhole(t *testing.T) {
    t.Run("original-negative", func(t *testing.T) { if 2 + 2 != 4 { t.Fatal("real failed assertion") } })
    t.Run("nested/slash", func(t *testing.T) {})
    t.Run("parallel", func(t *testing.T) { t.Parallel() })
}
func TestExplicitSkip(t *testing.T) { t.Skip("explicit original environment boundary") }
func TestFailure(t *testing.T) { t.Fatal("intended negative verdict witness") }
func FuzzSeed(f *testing.F) { f.Add("seed"); f.Fuzz(func(t *testing.T, value string) { if value != "seed" { t.Fatal(value) } }) }
func Example() { fmt.Println("original example")
    // Output: original example
}
func BenchmarkExcluded(b *testing.B) { panic("ordinary go test must not run benchmarks") }
'''


class CompiledFixtureTests(unittest.TestCase):
    def test_actual_go_inventory_parallel_example_fuzz_skip_and_failed_verdict(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-go-gate-component-") as directory:
            path = Path(directory)
            (path / "go.mod").write_text("module example.com/gatecomponent\n\ngo 1.24.13\n", encoding="utf-8")
            (path / "inventory_test.go").write_text(GO_FIXTURE, encoding="utf-8")
            binary = path / "inventory.test"
            subprocess.run(["go", "test", "-c", "-o", str(binary), "."], cwd=path, check=True, timeout=120)
            listed = subprocess.check_output([str(binary), "-test.list=."], cwd=path, text=True, timeout=30)
            roots = gate.inventory(listed)
            tool = gate.test2json_tool(path)
            self.assertEqual(set(roots), {"TestWhole", "TestExplicitSkip", "TestFailure", "FuzzSeed", "Example"})
            results = {}
            for root in roots:
                result = subprocess.run(gate.command(binary, root, tool), cwd=path, text=True, capture_output=True, timeout=30)
                self.assertEqual(result.stdout.count("component TestMain entered"), 1)
                if root == "TestFailure":
                    self.assertIn("intended negative verdict witness", result.stdout)
                    with self.assertRaises(ValueError):
                        gate.verdict(result.stdout, result.returncode, root, result.stderr)
                else:
                    results[root] = gate.verdict(result.stdout, result.returncode, root, result.stderr)
            self.assertEqual(results["TestExplicitSkip"], {"TestExplicitSkip": "skip"})
            self.assertEqual(results["Example"], {"Example": "pass"})
            self.assertEqual(results["FuzzSeed"]["FuzzSeed/seed#0"], "pass")
            self.assertEqual(results["TestWhole"]["TestWhole/parallel"], "pass")
            self.assertEqual(results["TestWhole"]["TestWhole/nested/slash"], "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiled-fixture", action="store_true")
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunnerTests)
    if args.compiled_fixture:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(CompiledFixtureTests))
    sys.exit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
