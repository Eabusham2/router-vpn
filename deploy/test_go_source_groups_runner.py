#!/usr/bin/env python3
"""Negative controls for complete compiled package phases and required callers.

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


# Both jobs compile/test only the triggering revision. Keep the complete original
# command inventory and the dependency that blocks publishing on either failure.
def check_requirements_release(source, caller):
    def job(workflow, name):
        parts = re.findall(r"(?ms)^  " + re.escape(name) + r":\n(.*?)(?=^  [\w-]+:\n|\Z)", workflow.split("jobs:\n", 1)[1])
        if len(parts) != 1:
            raise ValueError("Missing or duplicate requirements job: " + name)
        return parts[0]

    if not all(source.splitlines().count(line) == 1 for line in (
            "  workflow_call:", "  workflow_dispatch:", "  push:", "    branches: [main]",
            "  group: requirements-closure-${{ github.workflow }}-${{ github.ref }}",
            "  cancel-in-progress: true", "  contents: read")):
        raise ValueError("Requirements lost its independent same-source caller or push")
    groups = {
        "source-contract": [
            ["python3 deploy/test_go_source_groups.py --scope all"],
        ],
        "requirements-and-safety": [
            ["python3 deploy/test_startup_race_groups.py"],
            ["python3 deploy/test_appkit_profile_load_loopback.py --race"],
            ["python3 deploy/test_reference_peer_boundaries.py"],
            ["python3 deploy/" + name for name in (
                "recovered-requirements-1-264-audit.py", "recovered-requirements-265-311-audit.py",
                "recovered-addendum-312-356-audit.py", "recovered-corrections-audit.py")],
            ["python3 deploy/" + name for name in (
                "backend-session-transaction-audit.py", "durable-state-transaction-audit.py",
                "native-session-mutation-audit.py", "profile-settings-audit.py")],
            ["python3 deploy/" + name for name in (
                "product-parity-audit.py", "full-audit-v4.py", "router-acceleration-safety-audit.py",
                "source-snapshot-durability-audit.py")],
            ["python3 deploy/validate-repo.py", "python3 deploy/release-orchestration-audit.py", "git diff --check"],
        ],
    }
    setup = ["    runs-on: ubuntu-24.04", "    timeout-minutes: 45", "    steps:",
             "      - uses: actions/checkout@v4", "        with:", "          fetch-depth: 1",
             "      - uses: actions/setup-go@v5", "        with:", "          go-version: '1.26.3'",
             "          cache: false"]
    for name, commands in groups.items():
        sections = re.split(r"^      - name: [^\n]+\n", job(source, name), flags=re.M)
        contents = [[line for line in section.splitlines() if line.strip() and not line.lstrip().startswith("#")]
                    for section in sections]
        expected = [setup]
        for group in commands:
            if len(group) == 1:
                expected.append(["        run: " + group[0]])
            else:
                expected.append(["        shell: bash", "        run: |", "          set -euo pipefail",
                                 *["          " + command for command in group]])
        if contents != expected:
            raise ValueError("Requirements job changed its source, bound, or blocking commands: " + name)

    if job(caller, "requirements-closure").strip().splitlines() != [
            "name: Recovered requirements and complete source", "    permissions:", "      contents: read",
            "    uses: ./.github/workflows/requirements-closure.yml"]:
        raise ValueError("Build-all lost its blocking read-only requirements call")
    publish = job(caller, "publish-exact-sha-release").split("    runs-on:", 1)[0]
    needs = re.findall(r"^    needs:\n((?:      - [\w-]+\n)+)", publish, flags=re.M)
    dependencies = ["release-delivery-contracts", "requirements-closure", "source-snapshot", "release-candidate",
                    "portainer-preflight", "publish-arm64-images", "production-compose"]
    if len(needs) != 1 or sorted(needs[0].splitlines()) != sorted("      - " + name for name in dependencies) or (
            re.findall(r"^    if: (.+)$", publish, flags=re.M) != ["github.ref == 'refs/heads/main'"] or
            "continue-on-error:" in publish):
        raise ValueError("Exact-SHA release publication bypasses requirements closure")


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
        original = (gate.PACKAGE, "router-vpn/internal/common", gate.NATIVE_PACKAGE,
                    "router-vpn/future/package", "router-vpn")
        self.assertEqual(gate.packages("\n".join(original), "all"), original)
        self.assertEqual(gate.grouped_packages(original), gate.GROUPED_PACKAGES)
        self.assertEqual(gate.other_command(original, gate.GROUPED_PACKAGES),
                         ["go", "test", "-timeout=15m", original[1], *original[3:]])
        self.assertIsNone(gate.other_command((gate.PACKAGE,), (gate.PACKAGE,)))
        self.assertEqual(gate.packages(gate.PACKAGE, "client"), (gate.PACKAGE,))
        for value, scope in (("", "all"), (original[1], "all"), (gate.PACKAGE + "\n" + gate.PACKAGE, "all"),
                             (gate.PACKAGE, "all"),
                             (gate.PACKAGE, "client-common"), ("\n".join(original), "client-common"),
                             (gate.PACKAGE + "\nerror text", "all")):
            with self.subTest(scope=scope, value=value), self.assertRaises(ValueError):
                gate.packages(value, scope)

    def test_no_grouped_or_future_package_can_disappear_before_complete_execution(self):
        selected = (gate.PACKAGE, "router-vpn/internal/common", gate.NATIVE_PACKAGE,
                    "router-vpn/future/native")
        for completed in ((), (gate.PACKAGE,), (gate.NATIVE_PACKAGE,),
                          gate.GROUPED_PACKAGES[::-1], gate.GROUPED_PACKAGES * 2,
                          gate.GROUPED_PACKAGES + (selected[-1],)):
            with self.subTest(completed=completed), self.assertRaises(ValueError):
                gate.other_command(selected, completed)
        self.assertEqual(gate.other_command(selected, gate.GROUPED_PACKAGES),
                         ["go", "test", "-timeout=15m", selected[1], selected[-1]])
        self.assertEqual(gate.other_command(selected[:2], (gate.PACKAGE,)),
                         ["go", "test", "-timeout=15m", selected[1]])

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

    def test_native_package_has_the_same_whole_root_alarm_and_exact_package_identity(self):
        command = gate.command(Path("/tmp/native.test"), "TestWhole", Path("/original/go/test2json"),
                               gate.NATIVE_PACKAGE)
        self.assertEqual(command, ["/original/go/test2json", "-p", gate.NATIVE_PACKAGE,
                                  "-t", "/tmp/native.test", "-test.v=test2json", "-test.count=1",
                                  "-test.timeout=15m", "-test.run=^TestWhole$"])
        native = [{**value, "Package": gate.NATIVE_PACKAGE} for value in receipts()]
        self.assertEqual(gate.verdict(encode(native), 0, "TestWhole", package=gate.NATIVE_PACKAGE),
                         {"TestWhole/negative": "pass", "TestWhole": "pass"})
        for output, package in ((encode(native), gate.PACKAGE), (encode(receipts()), gate.NATIVE_PACKAGE)):
            with self.subTest(package=package), self.assertRaises(ValueError):
                gate.verdict(output, 0, "TestWhole", package=package)
        mixed = native[:3] + receipts()[3:]
        with self.assertRaises(ValueError):
            gate.verdict(encode(mixed), 0, "TestWhole", package=gate.NATIVE_PACKAGE)
        for package in ("router-vpn/future/native", "../replacement", ""):
            with self.subTest(package=package), self.assertRaises(ValueError):
                gate.command(Path("/tmp/native.test"), "TestWhole", Path("/original/go/test2json"), package)

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

    def test_appkit_loopback_requires_original_execution_receipts(self):
        import test_appkit_profile_load_loopback as loopback
        names = [loopback.LOOPBACK + "/" + fault for fault in ("none", "reject", "after-prepare", "after-commit")] + [loopback.LOOPBACK]
        def events(choices):
            return "\n".join(json.dumps({"Action": action, "Test": name}) for name, action in choices)
        passed = [(name, "pass") for name in names]
        loopback.require_executions(events(passed))
        for index, (name, _) in enumerate(passed):
            for replacement in ([], [(name, "skip")], [(name, "pass"), (name, "pass")]):
                with self.subTest(name=name, replacement=replacement), self.assertRaises(ValueError):
                    loopback.require_executions(events(passed[:index] + replacement + passed[index + 1:]))

    def test_requirements_jobs_and_release_caller_keep_every_original_command(self):
        folder = gate.ROOT / ".github/workflows"
        source = (folder / "requirements-closure.yml").read_text()
        caller = (folder / "build-all.yml").read_text()
        check_requirements_release(source, caller)
        for changed in (
                source.replace("  source-contract:", "  other-source:"),
                source.replace("  requirements-and-safety:", "  other-safety:"),
                source.replace("  workflow_call:", "  repository_dispatch:"),
                source.replace("${{ github.workflow }}-", ""),
                source.replace("          fetch-depth: 1", "          ref: main"),
                source.replace("    timeout-minutes: 45", "    timeout-minutes: 90"),
                source.replace("          set -euo pipefail", "          set +e"),
                source.replace("        run: python3 deploy/test_startup_race_groups.py",
                               "        run: python3 deploy/test_startup_race_groups.py || true"),
                source.replace("        run: python3 deploy/test_appkit_profile_load_loopback.py --race\n", ""),
                source.replace("        run: python3 deploy/test_appkit_profile_load_loopback.py --race",
                               "        run: python3 deploy/test_appkit_profile_load_loopback.py --build-swift /tmp/compile-only"),
                source.replace("        run: python3 deploy/test_reference_peer_boundaries.py\n", ""),
                source.replace("        run: python3 deploy/test_reference_peer_boundaries.py",
                               "        run: python3 deploy/test_reference_peer_boundaries.py || true"),
                source.replace("          python3 deploy/native-session-mutation-audit.py\n", ""),
                source.replace("          git diff --check", "          true")):
            with self.subTest(change=changed), self.assertRaises(ValueError):
                check_requirements_release(changed, caller)
        for changed in (
                caller.replace("  requirements-closure:", "  omitted-closure:"),
                caller.replace("    uses: ./.github/workflows/requirements-closure.yml",
                               "    if: false\n    uses: ./.github/workflows/requirements-closure.yml"),
                *(caller.replace("      - " + name + "\n", "") for name in (
                    "requirements-closure", "release-delivery-contracts", "source-snapshot", "release-candidate",
                    "portainer-preflight", "publish-arm64-images", "production-compose")),
                caller.replace("      - requirements-closure\n", "      - requirements-closure\n" * 2),
                caller.replace("    if: github.ref == 'refs/heads/main'", "    if: always()")):
            with self.subTest(change=changed), self.assertRaises(ValueError):
                check_requirements_release(source, changed)

    def test_original_requirements_job_budget_cannot_grow(self):
        source = (gate.ROOT / ".github/workflows/requirements-closure.yml").read_text(encoding="utf-8")
        for budget in ("0", "46", "90"):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                check_workflow(source.replace("    timeout-minutes: 45\n", "    timeout-minutes: " + budget + "\n", 1),
                               "source-contract", "Compile and test Go source", "all")


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
            # The shared native package uses the same executable protocol while
            # retaining its own exact identity. A controller receipt cannot be
            # reused as evidence that the shared root executed.
            result = subprocess.run(gate.command(binary, "TestWhole", tool, gate.NATIVE_PACKAGE),
                                    cwd=path, text=True, capture_output=True, timeout=30)
            native = gate.verdict(result.stdout, result.returncode, "TestWhole", result.stderr,
                                  gate.NATIVE_PACKAGE)
            self.assertEqual(native, results["TestWhole"])
            with self.assertRaises(ValueError):
                gate.verdict(result.stdout, result.returncode, "TestWhole", result.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiled-fixture", action="store_true")
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunnerTests)
    if args.compiled_fixture:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(CompiledFixtureTests))
    sys.exit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
