#!/usr/bin/env python3
"""Source, image, transcript and retry boundaries for Windows Node phase receipts."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import windows_node_process_phases as phases


def transcript(selected):
    return "".join("=== RUN   " + name + "\r\n--- PASS: " + name + " (0.01s)\r\n" for name in selected) + "PASS\r\n"


class WindowsNodePhases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.scope = {"repository": "owner/router", "commit": "a" * 40, "run_id": "44", "run_attempt": "2"}
        self.source = "c" * 64
        self.image = self.work / "image"
        self.image.mkdir()
        binary = self.image / phases.IMAGE
        binary.write_bytes(b"original compiled native image")
        self.manifest = phases.image_manifest(self.scope, self.source, "1", hashlib.sha256(binary.read_bytes()).hexdigest(), binary.stat().st_size)
        phases.write_json(self.image / "image.json", self.manifest)
        self.receipts = self.work / "receipts"
        self.receipts.mkdir()
        self.jobs = {name: {"result": "success"} for name in ("image", "baseline", "controls")}
        self.groups = phases.partition()

    def path(self, name):
        return self.receipts / ("windows-node-process-baseline-" + name + "-" + self.scope["commit"] + "-44")

    def produce(self):
        for index, (name, selected) in enumerate(self.groups.items()):
            path = self.path(name)
            path.mkdir()
            raw = "".join(phases.HEADER + label + "\n" + transcript(names) for label, _, names in selected).encode()
            (path / "native.log").write_bytes(raw)
            phases.write_json(path / "phase.json", phases.phase_record(self.manifest, "2" if index else "1", name, raw, selected))

    def verify(self, needs=None):
        out = self.work / "accepted"
        with patch.object(phases, "source_snapshot", return_value=self.source):
            phases.aggregate(self.image, self.receipts, out, self.scope, self.jobs if needs is None else needs)
        return phases.load_json(out / "accepted.json")

    def test_disjoint_original_partition_and_same_run_retry(self):
        self.assertEqual([(len(items), sum(len(rows) for _, _, rows in items)) for items in self.groups.values()],
                         [(7, 334), (3, 205), (23, 163), (13, 202), (20, 57)])
        self.assertEqual(tuple(group for groups in self.groups.values() for group in groups), phases.gate.baseline_groups())
        self.produce()
        receipt = self.verify()
        self.assertEqual((receipt["roots"], receipt["groups"], receipt["verdicts"]), (200, 66, 961))
        self.assertEqual(receipt["image"], self.manifest)
        self.assertEqual([r["run_attempt"] for r in receipt["phases"]], ["1", "2", "2", "2", "2"])
        self.assertEqual([r["group"] for r in receipt["phases"]], list(phases.GROUPS))

    def test_incomplete_cancelled_failed_or_skipped_jobs_publish_no_acceptance(self):
        for job in self.jobs:
            for status in ("failure", "skipped", "cancelled", "missing"):
                needs = {**self.jobs, job: {"result": status}}
                if status == "missing":
                    del needs[job]
                with self.subTest(job=job, status=status), self.assertRaisesRegex(ValueError, "every baseline shard"):
                    self.verify(needs)
                self.assertFalse((self.work / "accepted").exists())

    def test_foreign_attempt_source_processor_and_image_refuse(self):
        path = self.image / "image.json"
        for key, wrong in (("producer_attempt", "3"), ("source_sha256", "d" * 64), ("commit", "b" * 40),
                           ("run_id", "45"), ("repository", "foreign/router"), ("target", "windows/arm64"),
                           ("sha256", "0" * 64), ("bytes", self.manifest["bytes"] + 1), ("toolchain", "go1.26.5")):
            path.write_text(json.dumps({**self.manifest, key: wrong}))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "another source"):
                phases.adopt(self.image, self.scope, self.source)
        path.write_text(json.dumps(self.manifest))
        (self.image / phases.IMAGE).write_bytes(b"foreign compiled native image!")
        with self.assertRaisesRegex(ValueError, "another source"):
            phases.adopt(self.image, self.scope, self.source)

    def test_shard_executes_only_original_groups_retains_actual_transcript_and_image(self):
        group = "latency"
        selected = self.groups[group]
        raw = [transcript(names) for _, _, names in selected]
        def execute(image, captured, digest, *, groups):
            self.assertEqual((image, captured, digest, groups),
                             (self.image / phases.IMAGE, {"original": "env"}, self.manifest["sha256"], selected))
            return raw
        compile_context = ("go", {"original": "env"}, ["go", "test", *phases.FLAGS])
        for fault in ("same-bytes-image", "source", None):
            out = self.work / ("output-" + str(fault))
            def original_run(*args, **kwargs):
                result = execute(*args, **kwargs)
                if fault == "same-bytes-image":
                    image = self.image / phases.IMAGE
                    backup = self.work / "retained-original.exe"
                    image.rename(backup)
                    image.write_bytes(backup.read_bytes())
                return result
            with self.subTest(fault=fault), patch.object(phases, "source_snapshot", side_effect=[self.source, "other" if fault == "source" else self.source]), patch.object(phases, "verify_test_image"), patch.object(phases, "original_compiler", return_value=compile_context), patch.object(phases.gate, "execute_baseline", side_effect=original_run):
                if fault:
                    with self.assertRaisesRegex(ValueError, "source changed during native execution"):
                        phases.run_group(group, self.image, out, self.scope, "go", {})
                    self.assertFalse(out.exists())
                else:
                    phases.run_group(group, self.image, out, self.scope, "go", {})
                    expected = "".join(phases.HEADER + row[0] + "\n" + output for row, output in zip(selected, raw)).encode()
                    self.assertEqual((out / "native.log").read_bytes(), expected)

    def test_rehashed_partial_duplicate_skipped_or_wrong_group_transcript_refuses(self):
        self.produce()
        name = "product"
        path = self.path(name)
        log = path / "native.log"
        source = log.read_bytes()
        root = self.groups[name][0][1][0].encode()
        run = b"=== RUN   " + root + b"\r\n"
        for fault, replacement in (("omitted", b""), ("duplicate", run + run), ("foreign", b"=== RUN   TestForeign\r\n"),
                                    ("skipped", run + b"--- SKIP: TestForeign\r\n")):
            raw = source.replace(run, replacement, 1)
            self.assertNotEqual(source, raw)
            log.write_bytes(raw)
            (path / "phase.json").write_text(json.dumps(phases.phase_record(self.manifest, "2", name, raw, self.groups[name])))
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.verify()
        log.write_bytes(source)
        for key, value in (("run_attempt", "3"), ("group", "ordered"), ("roots", 0), ("log_sha256", "0" * 64)):
            phase = phases.phase_record(self.manifest, "2", name, source, self.groups[name])
            (path / "phase.json").write_text(json.dumps({**phase, key: value}))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "original run"):
                self.verify()
        (path / "native.log").unlink()
        with self.assertRaisesRegex(ValueError, "inventory"):
            self.verify()

    def test_native_compiler_failure_mismatch_and_checkout_drift_never_publish_a_manifest(self):
        context = ("go", {"original": "env"}, ["go", "test", *phases.FLAGS])
        for fault in ("compile", "wrong-image", "source", None):
            out = self.work / ("build-" + str(fault))
            def compile_image(path, build, env):
                self.assertEqual((build, env), (context[-1], context[1]))
                if fault == "compile":
                    raise ValueError("original compile failed")
                path.write_bytes(b"actual selected image")
                return "0" * 64 if fault == "wrong-image" else hashlib.sha256(path.read_bytes()).hexdigest()
            with self.subTest(fault=fault), patch.object(phases, "source_snapshot", side_effect=[self.source, "changed" if fault == "source" else self.source]), patch.object(phases, "original_compiler", return_value=context), patch.object(phases, "verify_test_image"), patch.object(phases.gate, "compile_baseline", side_effect=compile_image):
                if fault:
                    with self.assertRaises(ValueError):
                        phases.prepare_image(out, self.scope, "go", {})
                    self.assertFalse((out / "image.json").exists())
                else:
                    phases.prepare_image(out, self.scope, "go", {})
                    self.assertEqual(phases.adopt(out, self.scope, self.source)[2]["producer_attempt"], "2")

    def test_original_native_build_readback_refuses_wrong_modes_and_targets(self):
        image = self.image / phases.IMAGE
        original = phases.read_file(image, phases.IMAGE_LIMIT)[:2]
        info = "\n".join([str(image) + ": go1.26.3", "\tpath\trouter-vpn/cmd/client",
            *(f"\tbuild\t{flag}" for flag in ("-buildmode=exe", "-compiler=gc", "-gcflags=all=-d=checkptr=2",
              "-race=true", "-tags=" + phases.gate.TAG, "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=1"))])
        roots = [root for _, group, _ in phases.gate.baseline_groups() for root in group]
        listing = "\r\n".join(reversed(roots)) + "\r\n"
        for dropped in ("go1.26.3", "router-vpn/cmd/client", "-buildmode=exe", "-compiler=gc", "-race=true",
                        "-d=checkptr=2", phases.gate.TAG, "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=1"):
            with self.subTest(dropped=dropped), patch.object(phases.gate.NATIVE, "run", return_value=(0, info.replace(dropped, "foreign"))) as run:
                with self.assertRaisesRegex(ValueError, "original target"):
                    phases.verify_test_image("go", image, {}, original)
                self.assertEqual(run.call_count, 1)
        for extra in ("\tbuild\tGOOS=linux", "\tpath\trouter-vpn/cmd/client.test"):
            with self.subTest(extra=extra), patch.object(phases.gate.NATIVE, "run", return_value=(0, info + "\n" + extra)):
                with self.assertRaisesRegex(ValueError, "differing fields"):
                    phases.verify_test_image("go", image, {}, original)

        for fault in ("command", "failed", "missing-native", "extra", "duplicate", "before-list", "during-list", None):
            calls = []
            def run(command, *, cwd, env, timeout):
                calls.append(command)
                self.assertEqual(timeout, 30)
                if len(calls) == 1:
                    self.assertEqual(command, ["go", "version", "-m", image])
                    if fault == "before-list":
                        image.rename(self.work / "before-list.exe")
                        image.write_bytes((self.work / "before-list.exe").read_bytes())
                    return 0, info
                self.assertEqual(cwd, phases.gate.ROOT / "cmd/client")
                self.assertEqual(command, [image, "-test.list=^(" + "|".join(roots) + ")$"])
                if fault == "during-list":
                    image.rename(self.work / "during-list.exe")
                    image.write_bytes((self.work / "during-list.exe").read_bytes())
                if fault == "missing-native":
                    return 0, listing.replace("TestWindowsOwnedNodeProcessActualRetirement\r\n", "")
                if fault == "extra":
                    return 0, listing + "TestForeign\r\n"
                if fault == "duplicate":
                    return 0, listing + roots[0] + "\r\n"
                return (1 if fault == "failed" else 0), ("" if fault == "command" else listing)
            original = phases.read_file(image, phases.IMAGE_LIMIT)[:2]
            with self.subTest(fault=fault), patch.object(phases.gate.NATIVE, "run", side_effect=run):
                if fault:
                    with self.assertRaisesRegex(ValueError, "test inventory"):
                        phases.verify_test_image("go", image, {}, original)
                else:
                    phases.verify_test_image("go", image, {}, original)
                self.assertEqual(len(calls), 1 if fault == "before-list" else 2)



if __name__ == "__main__":
    unittest.main()
