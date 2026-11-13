#!/usr/bin/env python3
"""Run trusted, fixed multihop clock gates against a separate exact Git checkout."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import unittest

PACKAGE = "router-vpn/internal/mobilemultihop"
ORDERED = "TestNodeChainExecutionProofClock"
LEGACY_ROOTS = (
    "TestControllerProofClockPublishesActualMeasuredResponses",
    "TestControllerProofClockRejectsInvalidOriginalInterval",
    "TestControllerProofClockPreservesOriginalHTTPFailure",
    "TestControllerProofClockPreservesHeldHTTPCancellation",
    "TestControllerProofClockCannotBlockLeaseAcquisitionOrDelete",
)
ORDERED_PRESERVATION = tuple("TestNodeChainExecutionRuntime" + suffix for suffix in (
    "ComparesExactPathsAndFreshWinner", "ServerIsSeparateFromLocalComparison",
    "RejectsIncompleteLeaseAndProofReceipts", "RetainsConnectionReturnedWithErrorAndFailedClose",
    "KeepsLateUnacknowledgedPUTUntilExactStop", "CancelsEnteredOpenWithoutLateActivation",
    "ObservedReplacementRevokesApplication", "RestoreKeepsWinnerAndFreshAttempt",
))
LEGACY_PRESERVATION = (
    "TestRealSharedControllerRequestsScoresSelectsAndCleans",
    "TestFailedOrUnavailableServerDoesNotReplaceValidLocal",
    "TestAllFailuresNeverMarkConnected",
    "TestNetworkCancellationAndCleanupOwnership",
)


@dataclass(frozen=True)
class Case:
    name: str
    selection: str
    expected: frozenset[str]
    seconds: int
    outer_seconds: int
    mutation: str = ""
    witness: str = ""
    witness_tests: frozenset[str] = frozenset()


def cases(suite: str) -> tuple[Case, ...]:
    if suite == "ordered-clock":
        expected = {ORDERED + suffix for suffix in (
            "RetainsRealMeasurements", "RejectsInvalidIntervals", "CancellationKeepsOriginalJoin")}
        for execution in ("local", "server"):
            for suffix in ("RetainsRealMeasurements", "RejectsInvalidIntervals", "CancellationKeepsOriginalJoin"):
                expected.add(ORDERED + suffix + "/" + execution)
            for phase in ("prefix", "public-admission", "last-score", "public-score"):
                stem = ORDERED + "RejectsInvalidIntervals/" + execution + "/" + phase
                expected.add(stem)
                expected.update(stem + "/" + fault for fault in ("capture", "completion"))
            expected.update(ORDERED + "CancellationKeepsOriginalJoin/" + execution + "/" + kind
                            for kind in ("private", "public"))
        original = set(ORDERED_PRESERVATION)
        original.update(ORDERED_PRESERVATION[2] + "/" + fault for fault in (
            "host", "port", "credential", "owner", "source", "dns", "expiry", "bootstrap",
            "nonce", "sequence", "receipt-dns", "missing-prefix", "pending-traffic", "old-proof",
            "private-proof", "selected-dns", "public-ip", "epoch-away-back"))
        original.update(ORDERED_PRESERVATION[6] + "/" + field
                        for field in ("engine", "session", "network", "source", "config", "epoch"))
        result = [
            Case("new-clock", "^" + ORDERED, frozenset(expected), 120, 600),
            Case("preserved-runtime", "^(" + "|".join(ORDERED_PRESERVATION) + ")$",
                 frozenset(original), 120, 600),
        ]
        root = ORDERED + "RejectsInvalidIntervals"
        for name, phase in (("unchecked-prefix", "prefix"), ("unchecked-public", "public-admission")):
            failures = {root}
            leaves = set()
            for execution in ("local", "server"):
                stem = root + "/" + execution
                failures.update((stem, stem + "/" + phase, stem + "/" + phase + "/completion"))
                leaves.add(stem + "/" + phase + "/completion")
            result.append(Case(name, "^" + root + "$/^(local|server)$/^" + phase + "$/^completion$",
                               frozenset(failures), 120, 600, name,
                               "invalid original interval admitted ordered execution", frozenset(leaves)))
        return tuple(result)
    if suite == "legacy-clock":
        expected = set(LEGACY_ROOTS)
        for execution in ("local", "server"):
            for kind in ("private", "external"):
                expected.add(LEGACY_ROOTS[0] + "/" + execution + "/" + kind)
                expected.add(LEGACY_ROOTS[3] + "/" + execution + "/" + kind)
                expected.update(LEGACY_ROOTS[1] + "/" + execution + "/" + kind + "/" + phase
                                for phase in ("capture", "completion"))
            expected.add(LEGACY_ROOTS[2] + "/" + execution)
        leaves = frozenset(LEGACY_ROOTS[1] + "/" + execution + "/" + kind + "/completion"
                           for execution in ("local", "server") for kind in ("private", "external"))
        return (
            Case("new-proof-clock", "^TestControllerProofClock", frozenset(expected), 90, 300),
            Case("original-controller-preservation", "^(" + "|".join(LEGACY_PRESERVATION) + ")$",
                 frozenset(LEGACY_PRESERVATION), 90, 300),
            Case("unchecked-completion", "^" + LEGACY_ROOTS[1] + "/.*/.*/completion$",
                 leaves | {LEGACY_ROOTS[1]}, 90, 300, "unchecked-completion",
                 "unchecked measurement clock admitted original routed proof", leaves),
            Case("clock-blocks-lease", "^" + LEGACY_ROOTS[4] + "$", frozenset({LEGACY_ROOTS[4]}),
                 90, 300, "clock-blocks-lease", "measurement clock blocked original lease acquisition",
                 frozenset({LEGACY_ROOTS[4]})),
        )
    raise ValueError("unknown suite")


def verdict(raw: bytes, case: Case, code: int, timed_out: bool = False,
            process_group_joined: bool = True) -> dict:
    events = []
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(event, dict):
            events.append(event)
    actions = {action: [e["Test"] for e in events
                        if e.get("Action") == action and isinstance(e.get("Test"), str)]
               for action in ("run", "pass", "fail", "skip")}
    terminals = [e.get("Action") for e in events
                 if not e.get("Test") and e.get("Package") == PACKAGE
                 and e.get("Action") in ("pass", "fail", "skip")]
    expected_action = "fail" if case.mutation else "pass"
    started, ended, package_ended = set(), set(), False
    order_error = ""
    for event in events:
        action, test = event.get("Action"), event.get("Test")
        if test and action == "run":
            if package_ended or test in started or test in ended:
                order_error = "test starts after its terminal or package completion"
                break
            started.add(test)
        elif test and action in ("pass", "fail", "skip"):
            if package_ended or test not in started or test in ended:
                order_error = "test terminal lacks its preceding unique start"
                break
            ended.add(test)
        elif not test and event.get("Package") == PACKAGE and action in ("pass", "fail", "skip"):
            if package_ended or ended != set(case.expected):
                order_error = "package terminal precedes required test completion"
                break
            package_ended = True
    record = {
        "exit": code, "timed_out": timed_out, "process_group_joined": process_group_joined,
        "expected": sorted(case.expected), "ran": sorted(actions["run"]),
        "passed": sorted(actions["pass"]), "failed": sorted(actions["fail"]),
        "skipped": sorted(actions["skip"]), "package_terminals": terminals,
    }
    reason = ""
    if timed_out or not process_group_joined:
        reason = "timeout or unjoined original process group"
    elif code != (1 if case.mutation else 0):
        reason = "unexpected process exit"
    elif any(token in raw for token in (b"WARNING: DATA RACE", b"panic:", b"fatal error:", b"[build failed]")):
        reason = "race, panic or build failure"
    elif any(e.get("Action") in ("skip", "build-fail") for e in events):
        reason = "skipped or failed build"
    elif any(e.get("Package") != PACKAGE for e in events if e.get("Test")):
        reason = "foreign test package"
    elif terminals != [expected_action]:
        reason = "missing or duplicate terminal package verdict"
    elif order_error:
        reason = order_error
    elif Counter(actions["run"]) != Counter(case.expected):
        reason = "missing, duplicate or unexpected test start"
    elif Counter(actions[expected_action]) != Counter(case.expected):
        reason = "missing, duplicate or unexpected test verdict"
    elif actions["pass" if case.mutation else "fail"] or actions["skip"]:
        reason = "mixed or skipped test verdict"
    elif case.mutation:
        for test in case.witness_tests:
            output = "".join(e.get("Output", "") for e in events
                             if e.get("Action") == "output" and e.get("Test") == test)
            if case.witness not in output:
                reason = "missing intended witness in " + test
                break
    record["accepted"] = not reason
    record["reason"] = reason
    return record


def mutation_source(case: Case, source: str) -> str:
    if case.mutation in ("unchecked-prefix", "unchecked-public"):
        needle = "\treturn started.Duration()"
        if source.count(needle) != 2:
            raise ValueError("ordered mutation lost its two exact original anchors")
        pieces = source.split(needle)
        replacement = "\telapsed, _ := started.Duration()\n\treturn elapsed, nil"
        index = 0 if case.mutation == "unchecked-prefix" else 1
        return pieces[0] + (replacement if index == 0 else needle) + pieces[1] + (
            replacement if index == 1 else needle) + pieces[2]
    if case.mutation == "unchecked-completion":
        needle = "elapsed, err := interval.Duration()"
        replacement = "elapsed, err := time.Duration(0), error(nil)\n\t_ = interval"
    elif case.mutation == "clock-blocks-lease":
        needle = "data, _, e := c.exchangeBounded(ctx, c.meta.EntryTag, method, target.String(), c.meta.EntryToken, body, multihoprelay.LeaseResponseLimit(method))"
        replacement = "data, _, e := c.exchange(ctx, c.meta.EntryTag, method, target.String(), c.meta.EntryToken, body)"
    else:
        raise ValueError("unknown mutation")
    if source.count(needle) != 1:
        raise ValueError("legacy mutation lost its exact original anchor")
    return source.replace(needle, replacement)


def git(source: Path, *arguments: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(source), *arguments], stderr=subprocess.STDOUT, timeout=30)


def snapshot(source: Path) -> dict:
    result = {}
    for row in git(source, "ls-files", "--stage", "-z").split(b"\0"):
        if not row:
            continue
        attributes, raw_path = row.split(b"\t", 1)
        mode, _, stage = attributes.decode().split()
        path = raw_path.decode()
        if stage != "0" or mode not in ("100644", "100755", "120000"):
            raise ValueError("unsupported source entry: " + path)
        target = source / path
        if mode == "120000":
            data = os.readlink(target).encode()
        else:
            if target.is_symlink() or not target.is_file():
                raise ValueError("source type changed: " + path)
            data = target.read_bytes()
        result[path] = {"mode": mode, "sha256": hashlib.sha256(data).hexdigest()}
    return result


def group_exists(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


def execute(command: list[str], source: Path, env: dict, log: Path, bound: int) -> tuple[int, bool, bool]:
    timed_out = False
    with log.open("wb") as output:
        process = subprocess.Popen(command, cwd=source, env=env, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=bound)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait(timeout=10)
        finally:
            leaked = group_exists(process.pid)
            if leaked:
                os.killpg(process.pid, signal.SIGKILL)
            until = time.monotonic() + 10
            while group_exists(process.pid) and time.monotonic() < until:
                time.sleep(0.05)
    return code, timed_out, not leaked and not group_exists(process.pid)


def validate(args: argparse.Namespace) -> None:
    source, output = Path(args.source).resolve(), Path(args.output).resolve()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        raise ValueError("--source-sha must be an exact lowercase 40-hex commit")
    if output == source or source in output.parents:
        raise ValueError("--output must be outside the candidate source checkout")
    if git(source, "rev-parse", "HEAD").decode().strip() != args.source_sha:
        raise ValueError("candidate checkout does not match requested source SHA")
    if git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("candidate checkout is not clean")
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    before = snapshot(source)
    serialized = json.dumps(before, sort_keys=True, separators=(",", ":")).encode()
    (output / "source-before.json").write_bytes(serialized + b"\n")
    go = shutil.which("go")
    if not go:
        raise ValueError("Go is missing from PATH")
    env = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local", GOFLAGS="", CGO_ENABLED="1",
               GOMAXPROCS="2", GOGC="100", GOMEMLIMIT="2GiB")
    version = subprocess.check_output([go, "version"], env=env, text=True, timeout=30).strip()
    if not re.fullmatch(r"go version go1\.26\.3 linux/amd64", version):
        raise ValueError("focused host gate requires pinned Go1.26.3 linux/amd64: " + version)
    go_environment = json.loads(subprocess.check_output(
        [go, "env", "-json", "GOROOT", "GOPATH", "GOCACHE"], env=env, text=True, timeout=30))
    goroot = Path(go_environment["GOROOT"]).resolve()
    if any(Path(path).resolve() == goroot for path in go_environment["GOPATH"].split(os.pathsep) if path):
        raise ValueError("GOPATH must not equal the captured GOROOT")
    manifest = {
        "schema": 1, "suite": args.suite, "requested_source_sha": args.source_sha,
        "actual_source_sha": git(source, "rev-parse", "HEAD").decode().strip(),
        "tree_sha": git(source, "rev-parse", "HEAD^{tree}").decode().strip(),
        "source_file_count": len(before), "source_closure_sha256": hashlib.sha256(serialized).hexdigest(),
        "validator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "go": go, "go_version": version, "go_environment": go_environment, "status": "running", "attempts": [],
        "resource_limits": {"parallel_packages": 2, "GOMAXPROCS": 2, "GOGC": 100, "GOMEMLIMIT": "2GiB"},
    }
    def save() -> None:
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    save()
    try:
        for case in cases(args.suite):
            command = [go, "test", "-race", "-p=2", "-mod=readonly", "-json", "-count=1",
                       "-timeout=" + str(case.seconds) + "s", "-run", case.selection]
            overlay_record = None
            if case.mutation:
                relative = "internal/mobilemultihop/" + (
                    "node_chain_execution_proof.go" if args.suite == "ordered-clock" else "runtime.go")
                original = source / relative
                changed = output / (case.name + ".go")
                changed.write_text(mutation_source(case, original.read_text()))
                overlay = output / (case.name + ".overlay.json")
                overlay.write_text(json.dumps({"Replace": {str(original): str(changed)}}) + "\n")
                command += ["-overlay", str(overlay)]
                overlay_record = {"path": relative, "original_sha256": before[relative]["sha256"],
                                  "mutant_sha256": hashlib.sha256(changed.read_bytes()).hexdigest()}
            command.append("./internal/mobilemultihop")
            log = output / (case.name + ".jsonl")
            started = time.monotonic()
            code, timed_out, joined = execute(command, source, env, log, case.outer_seconds)
            raw = log.read_bytes()
            record = verdict(raw, case, code, timed_out, joined)
            record.update(name=case.name, command=command, seconds=round(time.monotonic() - started, 3),
                          go_test_seconds=case.seconds, outer_seconds=case.outer_seconds,
                          log=log.name, log_sha256=hashlib.sha256(raw).hexdigest(), overlay=overlay_record)
            manifest["attempts"].append(record)
            save()
            if snapshot(source) != before or git(source, "status", "--porcelain", "--untracked-files=all"):
                raise RuntimeError("candidate source changed during " + case.name)
            if not record["accepted"]:
                raise RuntimeError(case.name + ": " + record["reason"])
            print(json.dumps({"name": case.name, "accepted": True, "exit": code,
                              "passed": len(record["passed"]), "failed": len(record["failed"])}), flush=True)
        manifest["status"] = "passed"
    except BaseException as error:
        manifest["status"] = "failed"
        manifest["error"] = str(error)
        raise
    finally:
        save()


def run_self_tests() -> bool:
    def encoded(case: Case, action: str | None = None) -> bytes:
        action = action or ("fail" if case.mutation else "pass")
        rows = []
        for name in sorted(case.expected):
            rows.append({"Action": "run", "Package": PACKAGE, "Test": name})
            if name in case.witness_tests:
                rows.append({"Action": "output", "Package": PACKAGE, "Test": name, "Output": case.witness + "\n"})
            rows.append({"Action": action, "Package": PACKAGE, "Test": name})
        rows.append({"Action": action, "Package": PACKAGE})
        return b"\n".join(json.dumps(row).encode() for row in rows) + b"\n"

    class Gates(unittest.TestCase):
        def test_exact_inventories_and_bounds(self):
            self.assertEqual([len(c.expected) for c in cases("ordered-clock")], [37, 32, 7, 7])
            self.assertEqual([len(c.expected) for c in cases("legacy-clock")], [23, 4, 5, 1])
            for suite, bounds in (("ordered-clock", (120, 600)), ("legacy-clock", (90, 300))):
                for case in cases(suite):
                    self.assertEqual((case.seconds, case.outer_seconds), bounds)
        def test_all_valid_baselines_and_controls(self):
            for suite in ("ordered-clock", "legacy-clock"):
                for case in cases(suite):
                    self.assertTrue(verdict(encoded(case), case, 1 if case.mutation else 0)["accepted"])
        def test_terminal_before_original_start(self):
            case = cases("legacy-clock")[0]
            rows = encoded(case).splitlines()
            rows[0], rows[1] = rows[1], rows[0]
            result = verdict(b"\n".join(rows), case, 0)
            self.assertFalse(result["accepted"])
            self.assertIn("preceding unique start", result["reason"])
        def test_package_terminal_before_test_completions(self):
            case = cases("ordered-clock")[2]
            rows = encoded(case).splitlines()
            result = verdict(b"\n".join([rows[-1], *rows[:-1]]), case, 1)
            self.assertFalse(result["accepted"])
            self.assertIn("precedes required test completion", result["reason"])
        def test_test_run_after_package_terminal(self):
            case = cases("legacy-clock")[3]
            rows = encoded(case).splitlines()
            result = verdict(b"\n".join(rows + [rows[0]]), case, 1)
            self.assertFalse(result["accepted"])
            self.assertIn("package completion", result["reason"])
        def test_missing_record(self):
            case = cases("ordered-clock")[0]
            raw = encoded(case).splitlines()
            self.assertFalse(verdict(b"\n".join(raw[2:]), case, 0)["accepted"])
        def test_duplicate_record(self):
            case = cases("legacy-clock")[0]
            raw = encoded(case)
            self.assertFalse(verdict(raw + raw.splitlines()[0] + b"\n", case, 0)["accepted"])
        def test_unexpected_record(self):
            case = cases("ordered-clock")[1]
            row = json.dumps({"Action": "pass", "Package": PACKAGE, "Test": "TestUnselected"}).encode()
            self.assertFalse(verdict(encoded(case) + row, case, 0)["accepted"])
        def test_skip_rejected(self):
            case = cases("legacy-clock")[0]
            row = json.dumps({"Action": "skip", "Package": PACKAGE, "Test": "TestSkipped"}).encode()
            self.assertFalse(verdict(encoded(case) + row, case, 0)["accepted"])
        def test_no_terminal_package(self):
            case = cases("legacy-clock")[0]
            self.assertFalse(verdict(b"\n".join(encoded(case).splitlines()[:-1]), case, 0)["accepted"])
        def test_duplicate_terminal_package(self):
            case = cases("legacy-clock")[0]
            raw = encoded(case)
            self.assertFalse(verdict(raw + raw.splitlines()[-1], case, 0)["accepted"])
        def test_build_failure_not_control(self):
            for case in (cases("ordered-clock")[2], cases("legacy-clock")[2]):
                self.assertFalse(verdict(b"FAIL [build failed]\n" + case.witness.encode(), case, 1)["accepted"])
        def test_build_failure_with_spoofed_inventory(self):
            case = cases("ordered-clock")[2]
            self.assertFalse(verdict(encoded(case) + b"[build failed]\n", case, 1)["accepted"])
        def test_timeout_not_control(self):
            case = cases("legacy-clock")[2]
            self.assertFalse(verdict(encoded(case), case, 1, timed_out=True)["accepted"])
        def test_unjoined_group_not_control(self):
            case = cases("ordered-clock")[2]
            self.assertFalse(verdict(encoded(case), case, 1, process_group_joined=False)["accepted"])
        def test_signal_exit_not_control(self):
            case = cases("legacy-clock")[3]
            self.assertFalse(verdict(encoded(case), case, -9)["accepted"])
        def test_race_panic_fatal_not_control(self):
            case = cases("legacy-clock")[2]
            for token in (b"WARNING: DATA RACE", b"panic:", b"fatal error:"):
                self.assertFalse(verdict(encoded(case) + token, case, 1)["accepted"])
        def test_witness_must_belong_to_each_selected_leaf(self):
            case = cases("ordered-clock")[2]
            raw = encoded(case).replace(case.witness.encode(), b"unrelated failure", 1)
            self.assertFalse(verdict(raw + case.witness.encode(), case, 1)["accepted"])
        def test_foreign_package_not_control(self):
            case = cases("legacy-clock")[2]
            raw = encoded(case).replace(PACKAGE.encode(), b"foreign/package", 1)
            self.assertFalse(verdict(raw, case, 1)["accepted"])
        def test_control_cannot_pass(self):
            case = cases("legacy-clock")[2]
            self.assertFalse(verdict(encoded(case, "pass"), case, 0)["accepted"])
        def test_baseline_cannot_fail(self):
            case = cases("legacy-clock")[0]
            self.assertFalse(verdict(encoded(case, "fail"), case, 1)["accepted"])
        def test_ordered_mutations_remain_disjoint(self):
            source = "first\n\treturn started.Duration()\nsecond\n\treturn started.Duration()\n"
            one, two = (mutation_source(case, source) for case in cases("ordered-clock")[2:])
            self.assertNotEqual(one, two)
            self.assertIn("second\n\treturn started.Duration()", one)
            self.assertIn("first\n\treturn started.Duration()", two)
            for case in cases("ordered-clock")[2:]:
                with self.assertRaises(ValueError):
                    mutation_source(case, source + "\treturn started.Duration()")
        def test_legacy_mutations_require_exact_anchor(self):
            for case in cases("legacy-clock")[2:]:
                with self.assertRaises(ValueError):
                    mutation_source(case, "changed source")
        def test_unknown_suite_rejected(self):
            with self.assertRaises(ValueError):
                cases("arbitrary")
    return unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Gates)).wasSuccessful()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("ordered-clock", "legacy-clock"))
    parser.add_argument("--source")
    parser.add_argument("--source-sha")
    parser.add_argument("--output")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        if any((args.suite, args.source, args.source_sha, args.output)):
            parser.error("--self-test is independent of candidate execution")
        return 0 if run_self_tests() else 1
    if not all((args.suite, args.source, args.source_sha, args.output)):
        parser.error("--suite, --source, --source-sha and --output are required")
    validate(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
