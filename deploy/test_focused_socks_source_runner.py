#!/usr/bin/env python3
"""Python-only controls for the trusted SOCKS source validation runner."""
from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

DRIVER_PATH = Path(__file__).resolve().with_name("test_focused_socks_source.py")
_spec = importlib.util.spec_from_file_location("routervpn_socks_source_validator", DRIVER_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("trusted SOCKS source validator is missing")
D = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = D
_spec.loader.exec_module(D)

SHA = "a" * 40
TREE = "b" * 40


def events(case, action=None):
    action = action or ("fail" if case.mutation else "pass")
    rows = []
    for name in sorted(case.expected):
        rows.append({"Action": "run", "Package": D.CORE.PACKAGE, "Test": name})
        if name in case.witness_tests:
            rows.append({"Action": "output", "Package": D.CORE.PACKAGE, "Test": name,
                         "Output": case.witness + "\n"})
        rows.append({"Action": action, "Package": D.CORE.PACKAGE, "Test": name})
    rows.append({"Action": action, "Package": D.CORE.PACKAGE})
    return b"\n".join(json.dumps(row).encode() for row in rows) + b"\n"


class RunnerTests(unittest.TestCase):
    @contextmanager
    def fixture(self, mutate=None, toolchain=None):
        # Only process/Git observations are doubled. The production source
        # snapshot, overlay files, strict verdict and manifest are exercised.
        # No Go binary, native provider or network connection is executed here.
        with tempfile.TemporaryDirectory(prefix="routervpn-socks-validator-") as directory:
            root = Path(directory)
            source, output = root / "candidate", root / "output"
            source.mkdir()
            for relative in D.SOURCE_PATHS:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("package mobilemultihop\n")
            (source / D.COMPILER).write_text(
                "package mobilemultihop\n"
                "if source.Execution != \"local\" || source.Schema != 3 {}\n"
                "if p.digest() != p.seal || p.seal == \"\" {}\n")
            args = argparse.Namespace(suite=D.SUITE, source=str(source), source_sha=SHA, output=str(output))
            calls = []
            selected = {case.selection: case for case in D.cases()}

            def git(candidate, *arguments):
                self.assertEqual(candidate, source)
                if arguments == ("rev-parse", "HEAD"):
                    return (SHA + "\n").encode()
                if arguments == ("rev-parse", "HEAD^{tree}"):
                    return (TREE + "\n").encode()
                if arguments == ("status", "--porcelain", "--untracked-files=all"):
                    return b""
                if arguments == ("ls-files", "--stage", "-z"):
                    return b"".join(("100644 " + "c" * 40 + " 0\t" + path + "\0").encode()
                                    for path in D.SOURCE_PATHS)
                self.fail("unexpected Git operation: " + repr(arguments))

            def go(command, **kwargs):
                self.assertEqual(kwargs["timeout"], 30)
                self.assertEqual(kwargs["env"]["GOTOOLCHAIN"], "local")
                if command == ["/captured/go", "version"]:
                    return "go version go1.26.3 linux/amd64\n"
                self.assertEqual(command, ["/captured/go", "env", "-json", "GOROOT", "GOPATH", "GOCACHE"])
                return json.dumps(toolchain or {
                    "GOROOT": str(root / "go"), "GOPATH": str(root / "modules"),
                    "GOCACHE": str(root / "build-cache"),
                })

            def execute(command, candidate, env, log, bound):
                self.assertEqual(candidate, source)
                self.assertEqual(bound, 600)
                self.assertEqual(env["GOMAXPROCS"], "2")
                self.assertEqual(env["GOGC"], "100")
                self.assertEqual(env["GOMEMLIMIT"], "2GiB")
                self.assertEqual(env["CGO_ENABLED"], "1")
                self.assertEqual(env["GOFLAGS"], "")
                case = selected[command[command.index("-run") + 1]]
                self.assertEqual(command, D.command_for(
                    "/captured/go", case,
                    Path(command[command.index("-overlay") + 1]) if case.mutation else None))
                log.write_bytes(events(case))
                calls.append((case, command))
                if mutate is not None:
                    return mutate(case, source, log, calls)
                return (1 if case.mutation else 0), False, True

            with patch.object(D.CORE, "git", side_effect=git), \
                    patch.object(D.CORE, "execute", side_effect=execute), \
                    patch.object(D.shutil, "which", return_value="/captured/go"), \
                    patch.object(D.subprocess, "check_output", side_effect=go), \
                    redirect_stdout(io.StringIO()):
                yield args, source, output, calls

    def test_exact_new_and_preserved_inventory(self):
        self.assertEqual([len(case.expected) for case in D.cases()], [70, 44, 2, 3])
        self.assertEqual((len(D.MEMBER_FAULTS), len(D.ORDER_FAULTS), len(D.SEAL_FAULTS)), (29, 17, 9))
        self.assertEqual(len(D.SCHEMA2_FAULTS), 22)
        self.assertEqual(len(D.PRESERVATION_ROOTS), 4)
        self.assertIn("TestNodeChainCompleteCapturedPaths/2/", D.cases()[1].expected)
        self.assertIn("TestNodeChainImportedMiddleSourceAndNativeProjection/awg2-strong/",
                      D.cases()[1].expected)
        self.assertIn("TestNodeChainImportedMiddleRejectsUncapturedAuthority/unknown-schema",
                      D.cases()[1].expected)

    def test_fixed_race_commands_and_original_bounds(self):
        for case in D.cases():
            self.assertEqual((case.seconds, case.outer_seconds), (120, 600))
            command = D.command_for("/go", case, Path("/overlay") if case.mutation else None)
            self.assertEqual(command[-1], "./internal/mobilemultihop")
            for value in ("-race", "-p=2", "-mod=readonly", "-json", "-count=1", "-timeout=120s"):
                self.assertIn(value, command)
            self.assertEqual(command[command.index("-run") + 1], case.selection)

    def test_control_cannot_omit_its_compiled_overlay(self):
        with self.assertRaisesRegex(ValueError, "own compiled overlay"):
            D.command_for("/go", D.cases()[2])
        with self.assertRaisesRegex(ValueError, "own compiled overlay"):
            D.command_for("/go", D.cases()[0], Path("/overlay"))

    def test_unknown_suite_and_mutation_refused(self):
        with self.assertRaises(ValueError):
            D.cases("arbitrary")
        with self.assertRaises(ValueError):
            D.mutation_source(D.cases()[0], "anything")

    def test_both_unique_guard_mutations_are_disjoint(self):
        original = 'if source.Execution != "local" || source.Schema != 3 {}\nif p.digest() != p.seal || p.seal == "" {}\n'
        seal, local = (D.mutation_source(case, original) for case in D.cases()[2:])
        self.assertNotEqual(seal, local)
        self.assertNotIn("p.digest() != p.seal", seal)
        self.assertIn('source.Execution != "local"', seal)
        self.assertIn("p.digest() != p.seal", local)
        self.assertNotIn('source.Execution != "local"', local)

    def test_changed_or_duplicate_guard_refused(self):
        for case in D.cases()[2:]:
            with self.assertRaises(ValueError):
                D.mutation_source(case, "changed original source")
            anchor = "p.digest() != p.seal || " if case.mutation == "omitted-source-seal" else 'source.Execution != "local" || '
            with self.assertRaises(ValueError):
                D.mutation_source(case, anchor + anchor)

    def test_exact_baselines_and_causal_records_accepted(self):
        for case in D.cases():
            self.assertTrue(D.CORE.verdict(events(case), case, 1 if case.mutation else 0)["accepted"])

    def test_missing_original_record_refused(self):
        case = D.cases()[1]
        self.assertFalse(D.CORE.verdict(b"\n".join(events(case).splitlines()[2:]), case, 0)["accepted"])

    def test_extra_or_duplicate_record_refused(self):
        case = D.cases()[0]
        raw = events(case)
        self.assertFalse(D.CORE.verdict(raw + raw.splitlines()[0], case, 0)["accepted"])
        extra = json.dumps({"Action": "pass", "Package": D.CORE.PACKAGE, "Test": "TestUnselected"}).encode()
        self.assertFalse(D.CORE.verdict(raw + extra, case, 0)["accepted"])

    def test_terminal_event_order_enforced(self):
        case = D.cases()[2]
        rows = events(case).splitlines()
        rows[0], rows[1] = rows[1], rows[0]
        self.assertFalse(D.CORE.verdict(b"\n".join(rows), case, 1)["accepted"])
        rows = events(case).splitlines()
        self.assertFalse(D.CORE.verdict(b"\n".join([rows[-1], *rows[:-1]]), case, 1)["accepted"])

    def test_each_negative_leaf_requires_its_own_witness(self):
        case = D.cases()[3]
        raw = events(case).replace(case.witness.encode(), b"unrelated failure", 1)
        self.assertFalse(D.CORE.verdict(raw + case.witness.encode(), case, 1)["accepted"])

    def test_build_timeout_unjoined_signal_not_controls(self):
        case = D.cases()[2]
        self.assertFalse(D.CORE.verdict(b"FAIL [build failed]\n" + events(case), case, 1)["accepted"])
        self.assertFalse(D.CORE.verdict(events(case), case, 1, timed_out=True)["accepted"])
        self.assertFalse(D.CORE.verdict(events(case), case, 1, process_group_joined=False)["accepted"])
        self.assertFalse(D.CORE.verdict(events(case), case, -9)["accepted"])

    def test_skip_race_panic_not_controls(self):
        case = D.cases()[3]
        for suffix in (b"WARNING: DATA RACE", b"panic:", b"fatal error:"):
            self.assertFalse(D.CORE.verdict(events(case) + suffix, case, 1)["accepted"])
        skip = json.dumps({"Action": "skip", "Package": D.CORE.PACKAGE, "Test": "TestSkipped"}).encode()
        self.assertFalse(D.CORE.verdict(events(case) + skip, case, 1)["accepted"])

    def test_control_pass_or_baseline_failure_refused(self):
        case = D.cases()[2]
        self.assertFalse(D.CORE.verdict(events(case, "pass"), case, 0)["accepted"])
        case = D.cases()[0]
        self.assertFalse(D.CORE.verdict(events(case, "fail"), case, 1)["accepted"])

    def test_foreign_package_or_missing_terminal_refused(self):
        case = D.cases()[2]
        raw = events(case).replace(D.CORE.PACKAGE.encode(), b"foreign/package", 1)
        self.assertFalse(D.CORE.verdict(raw, case, 1)["accepted"])
        self.assertFalse(D.CORE.verdict(b"\n".join(events(case).splitlines()[:-1]), case, 1)["accepted"])

    def test_artifact_manifest_and_independent_overlays(self):
        with self.fixture() as (args, source, output, calls):
            before = D.CORE.snapshot(source)
            D.validate(args)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "passed")
            self.assertEqual(manifest["suite"], "socks-source")
            self.assertEqual(manifest["requested_source_sha"], SHA)
            self.assertEqual(manifest["actual_source_sha"], SHA)
            self.assertEqual(manifest["tree_sha"], TREE)
            self.assertEqual(manifest["trusted_executor_sha256"], hashlib.sha256(D.CORE_PATH.read_bytes()).hexdigest())
            self.assertEqual(manifest["validator_sha256"], hashlib.sha256(DRIVER_PATH.read_bytes()).hexdigest())
            self.assertEqual(len(calls), 4)
            self.assertEqual(D.CORE.snapshot(source), before)
            for case, _ in calls:
                overlay = output / (case.name + ".overlay.json")
                if case.mutation:
                    mapping = json.loads(overlay.read_text())["Replace"]
                    self.assertEqual(set(mapping), {str(source / D.COMPILER)})
                    changed = Path(mapping[str(source / D.COMPILER)])
                    self.assertEqual(changed.parent, output)
                    self.assertEqual(changed.read_text(), D.mutation_source(case, (source / D.COMPILER).read_text()))
                else:
                    self.assertFalse(overlay.exists())

    def test_failed_verdict_stops_and_preserves_exact_log(self):
        def fail(case, source, log, calls):
            log.write_bytes(events(case, "fail"))
            return 1, False, True
        with self.fixture(mutate=fail) as (args, source, output, calls):
            with self.assertRaises(RuntimeError):
                D.validate(args)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(len(calls), 1)
            record = manifest["attempts"][0]
            self.assertEqual(record["log_sha256"], hashlib.sha256((output / record["log"]).read_bytes()).hexdigest())

    def test_candidate_change_during_execution_is_not_accepted(self):
        def mutate(case, source, log, calls):
            with (source / D.COMPILER).open("a") as stream:
                stream.write("// modified candidate\n")
            return 0, False, True
        with self.fixture(mutate=mutate) as (args, source, output, calls):
            with self.assertRaisesRegex(RuntimeError, "candidate source changed"):
                D.validate(args)
            self.assertEqual(json.loads((output / "manifest.json").read_text())["status"], "failed")
            self.assertEqual(len(calls), 1)

    def test_exact_sha_is_required_before_execution(self):
        with self.fixture() as (args, source, output, calls):
            for changed in ("a" * 39, "A" * 40, "c" * 40):
                args.source_sha = changed
                with self.assertRaises(ValueError):
                    D.validate(args)
            self.assertEqual(calls, [])

    def test_source_output_overlap_and_old_output_refused(self):
        with self.fixture() as (args, source, output, calls):
            args.output = str(source / "results")
            with self.assertRaisesRegex(ValueError, "outside"):
                D.validate(args)
            args.output = str(output)
            output.mkdir()
            (output / "old.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "new or empty"):
                D.validate(args)
            self.assertEqual(calls, [])

    def test_gopath_cannot_be_goroot(self):
        with self.fixture(toolchain={"GOROOT": "/same", "GOPATH": "/same", "GOCACHE": "/cache"}) as (args, source, output, calls):
            with self.assertRaisesRegex(ValueError, "GOPATH"):
                D.validate(args)
            self.assertEqual(calls, [])

    def test_cli_does_not_accept_arbitrary_suite(self):
        with patch.object(sys, "argv", ["validator", "--suite", "arbitrary"]), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                D.main()
            self.assertEqual(result.exception.code, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
