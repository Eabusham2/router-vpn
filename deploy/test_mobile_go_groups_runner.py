#!/usr/bin/env python3
"""Exercise mobile build selections against executable Go packages with the vendor layout."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_mobile_go_groups as mobile


ROOT = Path(__file__).resolve().parents[1]


class MobileGoGroups(unittest.TestCase):
    def test_typed_partition_rejects_incomplete_or_overlapping_receipts(self):
        root = mobile.TYPED_ROOT
        required = mobile.CANDIDATE_CASES[mobile.MODULE][root]
        complete = [{root: "pass", **{root + "/" + case: "pass" for case in required
                                     if case.startswith(family + "/")}}
                    for family in ("socks", "http", "https")]
        complete.append({root: "pass", root + "/new-family/case": "skip"})
        for defect in ("missing", "wrong-branch", "duplicate", "parent-verdict"):
            with self.subTest(defect=defect):
                outputs = [dict(phase) for phase in complete]
                if defect == "missing":
                    del outputs[2][root + "/https/8"]
                elif defect == "wrong-branch":
                    outputs[0][root + "/future-family/1"] = "pass"
                elif defect == "duplicate":
                    outputs[-1][root + "/socks/3"] = "pass"
                else:
                    outputs[-1][root] = "skip"
                with patch.object(mobile.groups, "run_phase", side_effect=outputs), self.assertRaises(ValueError):
                    mobile.run_root(None, root, None, None, mobile.MODULE, (mobile.MODULE,), 90)

    def test_native_builds_use_both_scopes(self):
        for platform, path, prefix in (
            ("android", "android/build-sing-box-libbox.sh", "$ROOT/../deploy"),
            ("ios", "ios/RouterVPN/prepare-libbox.sh", "$ROOT/../../deploy"),
        ):
            lines = (ROOT / path).read_text().splitlines()
            self.assertEqual(lines.count(f'  python3 "{prefix}/test_mobile_go_groups_runner.py"'), 1)
            for suite in ("shared", platform + "-chain"):
                self.assertEqual(lines.count(f'  python3 "{prefix}/test_mobile_go_groups.py" {suite} "$VENDOR"'), 1)

    def test_compiled_inventory_and_receipts(self):
        with tempfile.TemporaryDirectory() as temp:
            vendor = Path(temp)
            (vendor / "go.mod").write_text("module " + mobile.MODULE + "\n\ngo 1.23\n")
            for part, name in (("", "box"), ("route", "route"), ("daemon", "daemon"),
                               ("experimental/libbox/routervpn/mobilemultihop", "mobilemultihop"),
                               ("experimental/libbox/routervpn/other", "other")):
                folder = vendor / part
                folder.mkdir(exist_ok=True, parents=True)
                source = f'package {name}\nimport "testing"\n'
                if name == "other":
                    source += 'func TestOutsideGroupedPackage(t *testing.T) {}\n'
                elif name == "mobilemultihop":
                    source += ('func TestNewRoot(t *testing.T) { t.Run("descendant",func(t *testing.T){}) }\n'
                               'func TestExplicitSkip(t *testing.T) { t.Skip("real prerequisite") }\n'
                               'func FuzzSeed(f *testing.F) { f.Add(42); f.Fuzz(func(t *testing.T, i int){}) }\n')
                else:
                    source = "//go:build race\n\n" + source
                    source += ('func TestRouterVPNNodeChainOriginal(t *testing.T) {}\n'
                               'func TestRouterVPNStrategyOriginal(t *testing.T) {}\n'
                               'func TestUnselected(t *testing.T) { t.Fatal("selector expanded") }\n')
                (folder / "gate_test.go").write_text(source)
            (vendor / "android_test.go").write_text(
                "//go:build race && with_quic && with_wireguard && with_gvisor\n\n"
                'package box\nimport "testing"\nfunc TestRouterVPNNodeChainTagged(t *testing.T) {}\n')
            typed = vendor / "candidate_test.go"
            typed.write_text(
                'package box\nimport "testing"\nfunc ' + mobile.TYPED_ROOT + '(t *testing.T) {\n'
                '  for _, family := range []string{"socks","http","https","socks2"} {\n'
                '    for _, count := range []string{"3","4","8","12"} {\n'
                '      t.Run(family+"/"+count, func(t *testing.T) {\n'
                '        t.Run("nested", func(t *testing.T) {})\n'
                '      })\n    }\n  }\n}\n')

            def invoke(scope):
                return subprocess.run([sys.executable, str(ROOT / "deploy/test_mobile_go_groups.py"),
                                       scope, str(vendor)], capture_output=True, text=True, timeout=180)

            shared = invoke("shared")
            self.assertEqual(shared.returncode, 0, shared.stdout + shared.stderr)
            for receipt in ('"Test":"TestNewRoot/descendant"', '"Test":"FuzzSeed/seed#0"',
                            "real prerequisite", "1 explicit skip", mobile.SHARED + "other"):
                self.assertIn(receipt, shared.stdout)
            for scope, expected in (("android-chain", 7), ("ios-chain", 10)):
                native = invoke(scope)
                self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
                self.assertEqual(native.stdout.count("(Go alarm 90s)"), expected)
                self.assertNotIn("TestUnselected", native.stdout)
                for family in ("socks", "http", "https", "socks2"):
                    for count in ("3", "4", "8", "12"):
                        for suffix in ("", "/nested"):
                            full = mobile.TYPED_ROOT + "/" + family + "/" + count + suffix
                            self.assertEqual(native.stdout.count('"Test":"' + full + '"'), 1, full)

            typed.write_text(typed.read_text().replace('for _, count :=', 'if family == "socks2" { '
                             't.Run("unexpected", func(t *testing.T) { t.Fatal("future failed") }) }; for _, count :='))
            failed = invoke("android-chain")
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("future failed", failed.stdout)

            ordinary = vendor / "experimental/libbox/routervpn/other/gate_test.go"
            ordinary.write_text(ordinary.read_text().replace("t *testing.T) {}", 't *testing.T) { t.Fatal("ordinary failed") }'))
            failed = invoke("shared")
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("ordinary failed", failed.stdout)


if __name__ == "__main__":
    unittest.main()
