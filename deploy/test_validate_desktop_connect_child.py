#!/usr/bin/env python3
"""Keep typed CONNECT inventories, causal witnesses and projections strict."""
from pathlib import Path
from collections import Counter
import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/"deploy"/filename)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


G = module("desktop_connect_child_gate_tests", "validate-desktop-connect-child.py")
ORIGINAL = module("desktop_connect_original_parser_tests", "test_validate_desktop_socks_child.py")


class CONNECTChildGate(unittest.TestCase):
    def test_original_regressions_and_bounds_are_unchanged(self):
        self.assertEqual(G.REGRESSIONS, G.ORIGINAL_REGRESSIONS)
        self.assertEqual([len(item["cases"]) for item in G.REGRESSIONS], [16, 28, 52, 27, 11])
        self.assertEqual(G.CHILD["limits"], {"compile_seconds": 600, "case_seconds": 90, "process_seconds": 100})
        self.assertEqual(len(G.CHILD["command_cases"]), 83)
        self.assertEqual(len(G.CHILD["box_cases"]), 15)
        self.assertEqual(len(G.CONTROLS), 7)
        self.assertEqual([item["name"] for item in G.CONTROLS], [item["name"] for item in G.ORIGINAL_CONTROLS])
        self.assertEqual([item["witness"] for item in G.CONTROLS], [item["witness"] for item in G.ORIGINAL_CONTROLS])
        self.assertEqual(G.SUITE, "desktop-connect-child")

    def test_every_original_and_connect_verdict_is_mandatory(self):
        suites = [(G.PACKAGE["cmd"], G.CHILD["command_cases"]),
                  (G.PACKAGE["box"], G.CHILD["box_cases"])]
        suites.extend((G.PACKAGE[item["package"]], item["cases"]) for item in G.REGRESSIONS)
        for package, cases in suites:
            events = ORIGINAL.transcript(cases, package)
            G.require_verdict(ORIGINAL.raw(events), 0, package, cases)
            for omitted in cases:
                with self.subTest(omitted=omitted), self.assertRaises(ValueError):
                    G.require_verdict(ORIGINAL.raw([item for item in events if item.get("Test") != omitted]), 0, package, cases)
            duplicate = copy.deepcopy(events)
            duplicate.insert(-1, copy.deepcopy(events[-2]))
            with self.assertRaises(ValueError):
                G.require_verdict(ORIGINAL.raw(duplicate), 0, package, cases)

    def test_command_groups_are_exact_disjoint_bounded_and_used(self):
        suites = G.child_command_suites()
        self.assertEqual([suite["name"] for suite in suites],
                         ["typed-child-command", "typed-child-construction", "typed-child-runtime"])
        self.assertEqual([len(suite["cases"]) for suite in suites], [53, 11, 19])
        self.assertEqual(Counter(case for suite in suites for case in suite["cases"]),
                         Counter(G.CHILD["command_cases"]))
        self.assertIs(G.BASE.child_command_suites, G.child_command_suites)
        self.assertIn("*child_command_suites(),", (ROOT/"deploy/validate-desktop-socks-child.py").read_text())
        for suite in suites:
            self.assertEqual(suite["process_seconds"], 100)
            self.assertEqual(suite["package"], "cmd")
            package = G.PACKAGE["cmd"]
            cases = suite["cases"]
            events = ORIGINAL.transcript(cases, package)
            G.require_verdict(ORIGINAL.raw(events), 0, package, cases)
            for omitted in cases:
                with self.subTest(omitted=omitted), self.assertRaises(ValueError):
                    G.require_verdict(ORIGINAL.raw([e for e in events if e.get("Test") != omitted]), 0, package, cases)
            with self.assertRaises(ValueError):
                G.require_verdict(ORIGINAL.raw(events+events), 0, package, cases)
            foreign = next(other for other in suites if other is not suite)
            with self.assertRaises(ValueError):
                G.require_verdict(ORIGINAL.raw(ORIGINAL.transcript(foreign["cases"], package)), 0, package, cases)
        original = ORIGINAL.G.child_command_suites()
        self.assertEqual(len(original), 1)
        self.assertEqual(original[0]["name"], "typed-child")
        self.assertEqual(original[0]["cases"], ORIGINAL.G.CHILD["command_cases"])
        self.assertEqual(original[0]["process_seconds"], 100)

    def test_command_group_omissions_duplicates_and_foreign_roots_are_rejected(self):
        groups = G.COMMAND_GROUPS
        changed = list(groups); changed[0] = (groups[0][0], groups[0][1][1:])
        variants = [tuple(changed), groups[:-1], groups+groups[:1]]
        changed = list(groups); changed[0] = (groups[0][0], groups[0][1]+groups[0][1][:1])
        variants.append(tuple(changed))
        changed = list(groups); changed[0] = ("foreign-group", groups[0][1])
        variants.append(tuple(changed))
        changed = list(groups); changed[0] = (groups[0][0], groups[0][1]+("TestForeign",))
        variants.append(tuple(changed))
        for changed in variants:
            with self.subTest(groups=changed), mock.patch.object(G, "COMMAND_GROUPS", changed), self.assertRaises(ValueError):
                G.child_command_suites()
        for key in ("command_roots", "command_cases"):
            for replacement in (G.CHILD[key][1:], G.CHILD[key]+G.CHILD[key][:1], G.CHILD[key]+["TestForeign"]):
                changed = copy.deepcopy(G.CHILD); changed[key] = replacement
                with self.subTest(key=key), mock.patch.object(G, "CHILD", changed), self.assertRaises(ValueError):
                    G.child_command_suites()

    def test_all_controls_mutate_only_the_exact_original_seam(self):
        for control in G.CONTROLS:
            with self.subTest(control=control["name"]):
                path = ROOT/control["path"]
                self.assertFalse(path.is_symlink())
                original = path.read_text()
                changed = G.mutate(original, control)
                self.assertNotEqual(changed, original)
                with self.assertRaises(ValueError):
                    G.mutate(changed, control)
                with self.assertRaises(ValueError):
                    G.mutate(original+original, control)
                package = G.PACKAGE[control["package"]]
                events = ORIGINAL.transcript(control["cases"], package, control)
                raw = ORIGINAL.raw(events)
                G.require_verdict(raw, 1, package, control["cases"], control=control)
                with self.assertRaises(ValueError):
                    G.require_verdict(raw, 0, package, control["cases"], control=control)
                with self.assertRaises(ValueError):
                    G.require_verdict(raw.replace(control["witness"], "unrelated failure"), 1, package, control["cases"], control=control)

    def test_real_projection_reports_only_its_exact_family(self):
        result = subprocess.run([sys.executable, str(ROOT/G.BASE.SOURCE_PROJECTION_SCRIPT), "-v"],
                                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=30, text=True, check=False)
        G.require_projection(result.stdout, result.returncode)
        with self.assertRaises(ValueError):
            G.require_projection(result.stdout.replace("DesktopCONNECTChildProjection", "DesktopSOCKSChildProjection"), 0)
        with self.assertRaises(ValueError):
            G.require_projection(result.stdout, 1)

    def test_all_concrete_templates_have_exact_declared_projection(self):
        prep = module("desktop_connect_gate_original_preparer", "prepare-desktop-external.py")
        excluded = set(prep.PEER_TEMPLATES)
        templates = {path.relative_to(ROOT).as_posix() for path in (ROOT/"mobile/desktop").glob("node_chain_connect*.go.tmpl") if path.name not in excluded}
        declared = {path for path in G.PROJECTIONS if path.startswith("mobile/desktop/node_chain_connect")}
        self.assertEqual(templates, declared)
        self.assertEqual(len(declared), 23)
        for path in G.CHILD["source_files"]:
            self.assertTrue((ROOT/path).is_file(), path)
            self.assertFalse((ROOT/path).is_symlink(), path)
        for relative, projected in G.PROJECTIONS.items():
            self.assertTrue((ROOT/relative).is_file(), relative)
            self.assertFalse(Path(projected).is_absolute())
            self.assertNotIn("..", Path(projected).parts)

    def test_carrier_removal_is_an_executed_box_control(self):
        case = "TestRouterVPNDesktopNodeChainCONNECTPhysicalRejectsGraphDrift/final-carrier"
        self.assertEqual(G.CHILD["box_cases"].count(case), 1)
        controls = [item for item in G.CONTROLS if item["name"] == "typed-whole-box-before-acquisition"]
        self.assertEqual(len(controls), 1)
        self.assertEqual(controls[0]["cases"].count(case), 1)
        self.assertEqual(controls[0]["path"], "mobile/chain/connect_box.go.tmpl")
        self.assertEqual(G.PROJECTIONS[controls[0]["path"]], "routervpn_node_chain_connect.go")


if __name__ == "__main__":
    unittest.main()
