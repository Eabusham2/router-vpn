#!/usr/bin/env python3
"""Exercise native family orchestration; compiler/OS boundaries are modeled."""
from pathlib import Path
import contextlib
import importlib.util
import io
import json
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_box_phases", ROOT / "deploy/test_desktop_native_root_phases.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
NAMES = ("TestRouterVPNDesktopTorOriginal", "TestRouterVPNDesktopExternalOriginal",
         "TestRouterVPNDesktopNodeChainOriginal", "TestRouterVPNNodeChainCandidatePreparationOriginal",
         "TestRouterVPNNodeChainOriginal", "TestRouterVPNExecutionOriginal")


def wire(names):
    rows = [{"Package": GATE.PACKAGE, "Action": "start"}]
    for name in names:
        for action, test in (("run", name), ("run", name + "/child"), ("pass", name + "/child"), ("pass", name)):
            rows.append({"Package": GATE.PACKAGE, "Action": action, "Test": test})
    rows.append({"Package": GATE.PACKAGE, "Action": "pass"})
    return rows


def encoded(rows):
    return "\n".join(json.dumps(row) for row in rows)


class NativeRootPhases(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native-root-phase-tests-")
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name)
        (self.source / "go.mod").write_text("module fixture\n")
        self.input = self.source / "original.go"
        self.input.write_text("package fixture\n")
        self.calls = []

    def run_gate(self, fault=None, bad_family=0, target="linux/amd64"):
        environment = dict(zip(("GOOS", "GOARCH"), target.split("/")))
        environment["captured"] = "original"
        images, executed = [], []
        def child(command, *, cwd, env, timeout):
            self.assertEqual(cwd, self.source)
            self.assertEqual(timeout, 600)
            self.calls.append(command)
            if command[:3] == ["go", "test", "-c"]:
                self.assertEqual(command[3:-3], ([] if target == "windows/arm64" else ["-race"]) +
                                 ["-mod=readonly", "-tags=original-tags", "-ldflags=-checklinkname=0"])
                self.assertEqual(command[-3], "-o")
                self.assertEqual(command[-1], ".")
                image = command[-2]
                image.write_bytes(b"original native executable")
                images.append(image)
                return ""
            if str(command[1]).startswith("-test.list="):
                self.assertEqual(command[0], images[0])
                selected = command[1] != "-test.list=."
                names = list(NAMES) + ([] if selected else ["TestUnrelated"])
                if selected and fault == "omitted-discovery": names.pop(1)
                if selected and fault == "duplicate-discovery": names.append(names[0])
                return "\n".join(names)
            self.assertEqual(command[:6], ["go", "tool", "test2json", "-p", GATE.PACKAGE, "-t"])
            self.assertEqual(command[6], images[0])
            self.assertEqual(command[7], "-test.v")
            self.assertEqual(command[-2:], ["-test.count=1", "-test.timeout=" + ("180s" if target.startswith("linux/") else "120s")])
            selection = command[8].removeprefix("-test.run=")
            names = [name for name in NAMES if re.fullmatch(selection, name)]
            self.assertEqual(names, [NAMES[len(executed)]])
            executed.append(names[0])
            rows = wire(names)
            if len(executed) - 1 == bad_family:
                if fault == "failed-child": raise subprocess.CalledProcessError(17, command, output="original assertion")
                if fault == "timeout": raise subprocess.TimeoutExpired(command, timeout, output="original held owner")
                if fault == "source": self.input.write_text("package changed\n")
                if fault == "image": images[0].write_bytes(b"foreign native executable")
                if fault == "image-replacement":
                    replacement = images[0].with_name("replacement")
                    replacement.write_bytes(images[0].read_bytes())
                    replacement.replace(images[0])
                if fault == "environment": env["captured"] = "foreign"
                if fault == "missing": rows = [rows[0], rows[-1]]
                if fault == "duplicate": rows.insert(-1, rows[-2])
                if fault == "wrong-family": rows = wire([NAMES[(bad_family + 1) % len(NAMES)]])
                if fault == "fail": rows[-2]["Action"] = "fail"; rows[-1]["Action"] = "fail"
                if fault == "skip": rows[3]["Action"] = "skip"
                if fault == "truncated": rows.pop()
            return encoded(rows)
        with contextlib.redirect_stdout(io.StringIO()):
            result = GATE.execute(self.source, target, "original-tags", environment, child)
        self.assertEqual(executed, list(NAMES))
        self.assertEqual(len(images), 1)
        return result

    def test_all_six_targets_require_each_family_on_one_image_with_original_bounds(self):
        for target in ("linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64", "windows/arm64"):
            with self.subTest(target=target):
                self.calls = []
                result = self.run_gate(target=target)
                self.assertEqual(result["roots"], list(NAMES))
                self.assertEqual(result["verdicts"], dict.fromkeys(GATE.FAMILIES, 2))
                self.assertEqual(result["race"], target != "windows/arm64")
                self.assertEqual(len(self.calls), 9)

    def test_failed_or_changed_phase_never_reaches_next_family(self):
        faults = ("failed-child", "timeout", "source", "image", "image-replacement", "environment", "missing", "duplicate", "wrong-family", "fail", "skip", "truncated")
        for position in range(len(NAMES)):
            for fault in faults:
                with self.subTest(family=position, fault=fault):
                    self.input.write_text("package fixture\n")
                    self.calls = []
                    with self.assertRaises((ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired)):
                        self.run_gate(fault, position)
                    self.assertEqual(len(self.calls), 4 + position)

    def test_discovery_omissions_and_duplicates_stop_before_execution(self):
        for fault in ("omitted-discovery", "duplicate-discovery"):
            with self.subTest(fault=fault):
                self.calls = []
                with self.assertRaises(ValueError): self.run_gate(fault)
                self.assertEqual(len(self.calls), 3)
        listing = "\n".join(NAMES)
        for altered in ("", listing + "\n" + NAMES[0], listing.replace(NAMES[0], "TestForeign"), "\n".join(NAMES[1:])):
            with self.assertRaises(ValueError): GATE.partition(altered, listing)
        with self.assertRaises(ValueError): GATE.partition("\n".join(NAMES[1:]), "\n".join(NAMES[1:]))

    def test_completed_phase_requires_exact_runs_passes_and_no_skips(self):
        rows = wire([NAMES[0]])
        self.assertEqual(GATE.require_phase(encoded(rows), [NAMES[0]]), 2)
        for altered in (rows[1:], rows[:-1], rows + [rows[-1]], [row for row in rows if row["Action"] != "run"]):
            with self.assertRaises(ValueError): GATE.require_phase(encoded(altered), [NAMES[0]])
        with self.assertRaises(ValueError): GATE.require_phase(encoded(rows), [NAMES[1]])

    def test_actual_source_and_image_readback_reject_replacement(self):
        before = GATE.source_digest(self.source)
        self.input.write_text("package replacement\n")
        self.assertNotEqual(GATE.source_digest(self.source), before)
        image = self.source / "original.test"
        image.write_bytes(b"original image")
        original = GATE.image_identity(image)
        replacement = self.source / "replacement.test"
        replacement.write_bytes(image.read_bytes())
        replacement.replace(image)
        self.assertNotEqual(GATE.image_identity(image), original)
        try:
            linked = self.source / "linked.test"
            linked.symlink_to(image)
        except OSError:
            return  # Windows without symlink permission still ran identity checks.
        with self.assertRaises(ValueError): GATE.image_identity(linked)
        self.input.unlink(); self.input.symlink_to(image)
        with self.assertRaises(ValueError): GATE.source_digest(self.source)

    def test_exact_original_platform_guards_are_source_bound(self):
        roots = []
        for filename, _, _, _, names in GATE.PLATFORM_SKIP_SOURCES:
            original = ROOT / 'mobile/desktop' / (filename.removeprefix('routervpn_desktop_') + '.tmpl')
            (self.source / filename).write_bytes(original.read_bytes())
            roots.extend(names)
        for system, count in (("linux", 0), ("windows", 4), ("darwin", 10)):
            for architecture in ("amd64", "arm64"):
                with self.subTest(target=system + '/' + architecture):
                    allowed = GATE.platform_skips(self.source, system + '/' + architecture, roots)
                    self.assertEqual(len(allowed), count)
        filename, _, guard, _, _ = GATE.PLATFORM_SKIP_SOURCES[0]
        path = self.source / filename
        original = path.read_text()
        path.write_text(original.replace(guard, 'if true {', 1))
        with self.assertRaisesRegex(ValueError, "original guard"):
            GATE.platform_skips(self.source, "windows/amd64", roots)

    def test_complete_driver_executes_and_reports_original_platform_skip(self):
        filename, _, _, reason, names = GATE.PLATFORM_SKIP_SOURCES[0]
        (self.source / filename).write_bytes((ROOT / 'mobile/desktop' / (filename.removeprefix('routervpn_desktop_') + '.tmpl')).read_bytes())
        skipped = names[0]
        roots = [NAMES[0], skipped, *NAMES[1:]]
        executed = []
        def child(command, **options):
            if command[:3] == ["go", "test", "-c"]:
                command[-2].write_bytes(b"original compiled target fixture")
                return ""
            if str(command[1]).startswith("-test.list="):
                return "\n".join(roots)
            selector = command[8].removeprefix("-test.run=")
            selected = [name for name in roots if re.fullmatch(selector, name)]
            executed.extend(selected)
            rows = wire([name for name in selected if name != skipped])
            if skipped in selected:
                rows[-1:-1] = [{"Package": GATE.PACKAGE, "Action": "run", "Test": skipped},
                               {"Package": GATE.PACKAGE, "Action": "output", "Test": skipped, "Output": "original.go:26: " + reason + "\n"},
                               {"Package": GATE.PACKAGE, "Action": "skip", "Test": skipped}]
            return encoded(rows)
        with contextlib.redirect_stdout(io.StringIO()):
            result = GATE.execute(self.source, "windows/amd64", "original-tags", {"GOOS": "windows", "GOARCH": "amd64"}, child)
        self.assertEqual(executed, roots)
        self.assertEqual(result["roots"], roots)
        self.assertEqual(result["platform_skips"], {skipped: reason})
        self.assertEqual(sum(result["verdicts"].values()), 12)

    def test_original_platform_skips_remain_distinct_from_passes(self):
        applicable = "TestRouterVPNDesktopTorApplicableOriginal"
        for _, systems, _, reason, names in GATE.PLATFORM_SKIP_SOURCES:
            for name in names:
                with self.subTest(root=name):
                    block = [{"Package": GATE.PACKAGE, "Action": "run", "Test": name},
                             {"Package": GATE.PACKAGE, "Action": "output", "Test": name, "Output": "    original.go:26: " + reason + "\n"},
                             {"Package": GATE.PACKAGE, "Action": "skip", "Test": name}]
                    rows = wire([applicable])
                    rows[-1:-1] = block
                    self.assertEqual(GATE.require_phase(encoded(rows), [applicable, name], {name: reason}), 2)
                    # Linux has no exceptions; other-platform receipt cannot
                    # manufacture native acceptance on its applicable host.
                    with self.assertRaises(ValueError): GATE.require_phase(encoded(rows), [applicable, name])
                    for fault in ("reason", "missing-run", "duplicate", "child", "pass", "after-package"):
                        changed = [dict(row) for row in rows]
                        if fault == "reason": changed[-3]["Output"] = "different skip cause"
                        if fault == "missing-run": del changed[-4]
                        if fault == "duplicate": changed.insert(-1, dict(changed[-2]))
                        if fault == "child": changed[-3]["Test"] += "/foreign-child"
                        if fault == "pass": changed[-2]["Action"] = "pass"
                        if fault == "after-package": changed = wire([applicable]) + block
                        with self.subTest(fault=fault), self.assertRaises(ValueError):
                            GATE.require_phase(encoded(changed), [applicable, name], {name: reason})

    def test_builder_requires_runner_and_all_families_before_package(self):
        text = (ROOT / "deploy/build-native-runtime.py").read_text()
        self.assertIn("root_phases.execute(source, target, ','.join(tags(target)), env, run)", text)
        self.assertEqual(text.count("ROOT/'deploy/test_desktop_native_root_phases_runner.py'"), 2)
        self.assertIn("ROOT/'deploy/test_desktop_native_root_phases.py'", text)
        release = (ROOT / ".github/workflows/release-candidate.yml").read_text()
        self.assertIn("python3 deploy/test_desktop_native_root_phases_runner.py", release)
        linux = (ROOT / ".github/workflows/linux-native-app.yml").read_text()
        for name in ("test_desktop_native_root_phases.py", "test_desktop_native_root_phases_runner.py"):
            self.assertEqual(linux.count("      - 'deploy/" + name + "'"), 2)



if __name__ == "__main__":
    unittest.main()
