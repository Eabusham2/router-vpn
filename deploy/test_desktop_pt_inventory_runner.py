#!/usr/bin/env python3
"""Exercise the exact compiled-image inventory and original deadline runner."""
from collections import Counter
from pathlib import Path
import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("desktop_pt_inventory", ROOT / "deploy/test_desktop_pt_inventory.py")
GATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)


def events(names):
    rows = [{"Action": "start", "Package": GATE.PACKAGE}]
    for name in names:
        rows.extend({"Action": action, "Package": GATE.PACKAGE, "Test": name} for action in ("run", "pass"))
    rows.append({"Action": "pass", "Package": GATE.PACKAGE})
    return rows


def encoded(rows):
    return "\n".join(json.dumps(row) for row in rows)


class OriginalInventory(unittest.TestCase):
    def test_manifest_retains_every_original_shipping_root_and_platform_boundary(self):
        selected = {target: set() for target in ("linux", "darwin", "windows")}
        for name, raw in GATE.PREP.pt_copies().items():
            if not name.startswith("routervpn/desktoppt/") or not name.endswith("_test.go"):
                continue
            source = raw.decode()
            condition = source.splitlines()[0] if source.startswith("//go:build") else ""
            for target in selected:
                if condition and target not in condition.removeprefix("//go:build ").split(" || "):
                    continue
                selected[target].update(name for name in re.findall(r"^func (Test\w+)\(", source, re.M)
                                        if re.match(GATE.SELECTION, name))
        for target, wanted in selected.items():
            self.assertEqual(wanted, set(GATE.expected_roots(target)), target)
        self.assertEqual({target: len(roots) for target, roots in selected.items()}, {"linux": 70, "darwin": 69, "windows": 64})

    def test_every_original_darwin_leaf_runs_once_with_unchanged_names_and_bounds(self):
        source = (ROOT / "mobile/desktop/external_physical_darwin_test.go.tmpl").read_text()
        protocols = re.search(r"for _, selected := range \[\]string\{(.*?)\} \{", source).group(1)
        self.assertEqual(tuple(re.findall(r'"([a-z0-9-]+)"', protocols)), GATE.DARWIN_PROTOCOLS)
        self.assertEqual(len(GATE.darwin_leaves(GATE.DARWIN_PROTOCOLS)), 2856)
        for target in ("linux", "darwin", "windows"):
            roots = GATE.expected_roots(target)
            phases = GATE.plan(roots)
            self.assertEqual(len(phases), 10 if target == "darwin" else 1)
            self.assertEqual(set(root for _, _, selected, _ in phases for root in selected), set(roots))
            ordinary = [root for _, _, selected, _ in phases for root in selected if root != GATE.DARWIN_CAPTURE]
            self.assertEqual(Counter(ordinary), Counter(root for root in roots if root != GATE.DARWIN_CAPTURE))
            required = [leaf for _, _, _, leaves in phases for leaf in leaves]
            self.assertEqual(Counter(required), Counter(GATE.darwin_leaves(GATE.DARWIN_PROTOCOLS)) if target == "darwin" else Counter())
        self.assertEqual(GATE.TEST_TIMEOUT, "120s")
        self.assertEqual(GATE.PROCESS_TIMEOUT, 600)

    def test_missing_duplicate_renamed_and_foreign_compiled_roots_fail(self):
        roots = GATE.expected_roots("darwin")
        self.assertEqual(GATE.discover("\n".join(roots), roots), roots)
        for changed in (roots[:-1], (*roots, roots[0]), (*roots[:-1], roots[-1] + "Moved"), (*roots, "TestForeign")):
            with self.subTest(changed=changed[-1]):
                with self.assertRaises(ValueError):
                    GATE.discover("\n".join(changed), roots)

    def test_actual_projected_test_bytes_and_extra_file_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            for name, raw in GATE.PREP.pt_copies().items():
                if name.startswith(("routervpn/desktoppt/", "routervpn/torpt/")):
                    path = source / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw)
            for name in ("go.mod", "go.sum"):
                (source / name).write_text("fixture\n")
            with patch.object(GATE.PREP, "checked_vendor", return_value=source):
                _, expected = GATE.checked_sources(source)
                self.assertIn("routervpn/desktoppt/external_physical_darwin_test.go", expected)
                path = source / "routervpn/desktoppt/foreign_test.go"
                path.write_text("package routervpndesktoppt\n")
                with self.assertRaisesRegex(ValueError, "inventory moved"):
                    GATE.checked_sources(source)
                path.unlink()
                path = source / "routervpn/desktoppt/external_physical_darwin_test.go"
                path.write_bytes(path.read_bytes().replace(b'"ss-entry-http"', b'"ss-entry-http-moved"', 1))
                with self.assertRaisesRegex(ValueError, "shipping bytes"):
                    GATE.checked_sources(source)


class JoinedVerdicts(unittest.TestCase):
    def setUp(self):
        self.root = GATE.DARWIN_CAPTURE
        self.required = GATE.darwin_leaves((GATE.DARWIN_PROTOCOLS[0],))
        self.names = (self.root, *self.required)
        self.rows = events(self.names)

    def test_exact_original_case_inventory_passes_once(self):
        self.assertEqual(GATE.verdicts(encoded(self.rows), (self.root,), self.required), set(self.names))

    def test_missing_duplicate_skipped_failed_moved_and_unjoined_cases_fail(self):
        case = self.required[0]
        edits = {
            "missing-leaf": [row for row in self.rows if row.get("Test") != case],
            "missing-root": [row for row in self.rows if row.get("Test") != self.root],
            "missing-pass": [row for row in self.rows if not (row.get("Test") == case and row["Action"] == "pass")],
            "duplicate": self.rows + [{"Action": "run", "Package": GATE.PACKAGE, "Test": case}, {"Action": "pass", "Package": GATE.PACKAGE, "Test": case}],
            "skip": [dict(row, Action="skip") if row.get("Test") == case and row["Action"] == "pass" else row for row in self.rows],
            "fail": [dict(row, Action="fail") if row.get("Test") == case and row["Action"] == "pass" else row for row in self.rows],
            "moved": [dict(row, Test=case + "-moved") if row.get("Test") == case else row for row in self.rows],
            "foreign-root": [dict(row, Test="TestForeign/leaf") if row.get("Test") == case else row for row in self.rows],
            "foreign-package": [dict(row, Package="foreign") for row in self.rows],
            "unjoined-package": self.rows[:-1],
        }
        for name, rows in edits.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    GATE.verdicts(encoded(rows), (self.root,), self.required)


class FailureDiagnostics(unittest.TestCase):
    @staticmethod
    def large_failure():
        name = "TestRouterVPNExternalPhysicalOriginal/failed-middle"
        ordinary = (encoded([{"Package": GATE.PACKAGE, "Action": "output", "Test": "TestOther",
                             "Output": "ordinary successful output " * 40}]) + "\n").encode() * 180
        failed = (encoded([
            {"Package": GATE.PACKAGE, "Action": "output", "Test": name,
             "Output": "    actual_native_test.go:77: original physical owner was lost\n"},
            {"Package": GATE.PACKAGE, "Action": "fail", "Test": name},
        ]) + "\n").encode()
        return name, ordinary + failed + ordinary

    def test_middle_assertion_survives_both_native_logging_bounds(self):
        name, raw = self.large_failure()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original-native-output.jsonl"
            original.write_bytes(raw)
            driver = root / "nested-failure.py"
            driver.write_text("""import importlib.util, os, pathlib, subprocess, sys
spec = importlib.util.spec_from_file_location('original_pt_gate', sys.argv[1])
gate = importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)
gate.run([sys.executable, '-c', "import pathlib,sys; sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes()); sys.exit(17)", sys.argv[2]], cwd=pathlib.Path(sys.argv[2]).parent, env=dict(os.environ), timeout=30)
""")
            build = GATE.load("pt_diagnostic_actual_parent", "build-native-runtime.py")
            shown = io.StringIO()
            with contextlib.redirect_stderr(shown), self.assertRaises(subprocess.CalledProcessError) as caught:
                build.run([sys.executable, driver, Path(GATE.__file__), original], timeout=45)
            self.assertEqual(caught.exception.returncode, 1)
            self.assertIn("returned non-zero exit status 17", caught.exception.stderr.decode())
            self.assertIn("FAILED native test: " + name, shown.getvalue())
            self.assertIn("actual_native_test.go:77: original physical owner was lost", shown.getvalue())
            self.assertLess(len(shown.getvalue().encode()), build.MAX_BUILD_DIAGNOSTIC + 256)
            self.assertEqual(original.read_bytes(), raw)

    def test_failure_and_timeout_keep_original_exception_bytes_and_deadline(self):
        name, raw = self.large_failure()
        for error in (subprocess.CalledProcessError(17, ["native"], output=raw, stderr=b"\xffinvalid-tail\n"),
                      subprocess.TimeoutExpired(["native"], 123, output=raw, stderr=b"\xffinvalid-tail\n")):
            with self.subTest(error=type(error).__name__):
                shown = io.StringIO()
                with patch.object(GATE.os, "name", "posix"), patch.object(GATE.subprocess, "run", side_effect=error) as run:
                    with contextlib.redirect_stderr(shown), self.assertRaises(type(error)) as caught:
                        GATE.run(["native"], cwd=ROOT, env={}, timeout=123)
                self.assertIs(caught.exception, error)
                self.assertIs(error.stdout, raw)
                self.assertEqual(run.call_args.kwargs["timeout"], 123)
                self.assertTrue(run.call_args.kwargs["check"])
                self.assertIn("FAILED native test: " + name, shown.getvalue())
                self.assertIn("original physical owner was lost", shown.getvalue())
                self.assertLess(len(shown.getvalue().encode()), 65536 + 16384 + 256)

    def test_foreign_malformed_and_package_only_events_cannot_invent_test_failure(self):
        raw = b"malformed\xff\n[]\n17\n" + encoded([
            {"Package": "foreign", "Action": "fail", "Test": "TestForeign"},
            {"Package": GATE.PACKAGE, "Action": "fail"},
            {"Package": GATE.PACKAGE, "Action": "pass", "Test": "TestPassed"},
        ]).encode()
        self.assertEqual(GATE.failed_test_diagnostics(raw), b"")

    def test_many_large_actual_failures_remain_bounded(self):
        rows = []
        for index in range(100):
            name = "TestRouterVPNExternalPhysicalOriginal/" + str(index)
            rows.extend([
                {"Package": GATE.PACKAGE, "Action": "output", "Test": name, "Output": "assertion" * 5000},
                {"Package": GATE.PACKAGE, "Action": "fail", "Test": name},
            ])
        shown = GATE.failed_test_diagnostics(encoded(rows).encode())
        self.assertLess(len(shown), 16384 + 80)
        self.assertIn(b"FAILED native test: TestRouterVPNExternalPhysicalOriginal/0", shown)
        self.assertIn(b"additional failed-test diagnostics omitted", shown)


class ActualCompilerDiscovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.source = Path(cls.temporary.name)
        cls.binary = cls.source / ("inventory.test.exe" if os.name == "nt" else "inventory.test")
        (cls.source / "go.mod").write_text("module inventory-fixture\n\ngo 1.26.0\n")
        (cls.source / "inventory_test.go").write_text('''package inventory
import "testing"
func TestRouterVPNExternalPhysicalOriginal(t *testing.T) {
 for _, name := range []string{"ss-entry-http/leaf", "ss-entry-https/leaf"} {
  t.Run(name, func(t *testing.T) {})
 }
}
func TestRouterVPNExternalPhysicalOriginalNeighbor(t *testing.T) { t.Fatal("unselected neighboring root ran") }
''')
        subprocess.run(["go", "test", "-c", "-o", str(cls.binary)], cwd=cls.source,
                       capture_output=True, check=True, timeout=60)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_actual_image_discovers_roots_and_exact_components_preserve_leaf_paths(self):
        env = dict(os.environ)
        roots = ("TestRouterVPNExternalPhysicalOriginal", "TestRouterVPNExternalPhysicalOriginalNeighbor")
        listed = GATE.run([self.binary, "-test.list=" + GATE.SELECTION], cwd=self.source, env=env)
        self.assertEqual(GATE.discover(listed, roots), roots)
        selection = "^" + roots[0] + "$/^ss-entry-http$"
        output = GATE.run(["go", "tool", "test2json", "-t", "-p", GATE.PACKAGE, self.binary,
                           "-test.v=test2json", "-test.run=" + selection, "-test.count=1", "-test.timeout=" + GATE.TEST_TIMEOUT],
                          cwd=self.source, env=env)
        leaf = roots[0] + "/ss-entry-http/leaf"
        self.assertEqual(GATE.verdicts(output, roots[:1], (leaf,)), {roots[0], leaf})


if __name__ == "__main__":
    unittest.main()
