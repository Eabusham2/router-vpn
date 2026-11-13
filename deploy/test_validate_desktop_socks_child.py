#!/usr/bin/env python3
"""Test strict desktop child receipt, overlay and source ownership without Go."""
from pathlib import Path
from contextlib import redirect_stderr
from io import StringIO
import ast
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("desktop_socks_child_gate", ROOT/"deploy/validate-desktop-socks-child.py")
G = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = G
spec.loader.exec_module(G)


def transcript(cases, package, control=None):
    events = [{"Action": "start", "Package": package}]
    def event(action, name=None, output=None):
        value = {"Action": action, "Package": package}
        if name is not None:
            value["Test"] = name
        if output is not None:
            value["Output"] = output
        events.append(value)
    names = set(cases)
    physical_root = "TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox"
    physical_modes = (
        ("awg2-fast", "wg"), ("awg2-strong", "wg"),
        ("wg", "awg2-fast"), ("wg", "awg2-strong"),
        ("wg", "awg2-fast", "wg"), ("wg", "awg2-strong", "wg"),
        ("awg2-fast", "awg2-strong", "wg"),
        ("awg2-strong", "wg", "awg2-fast"),
    )
    siblings = {physical_root+"/"+"/".join(modes) for modes in physical_modes}
    def parent(other):
        if other in siblings:
            return physical_root
        candidates = [name for name in names if other.startswith(name+"/")]
        return max(candidates, key=len) if candidates else None
    def emit(name):
        event("run", name)
        children = [other for other in cases if parent(other) == name]
        if children:
            for child in children:
                emit(child)
        elif control is not None:
            event("output", name, "    fixture_test.go:42: "+control["witness"]+"\n")
        event("fail" if control else "pass", name)
    for name in cases:
        if not any(name.startswith(parent+"/") for parent in names):
            emit(name)
    event("fail" if control else "pass")
    return events


def raw(events):
    return "\n".join(json.dumps(event) for event in events)+"\n"


class ChildVerdictTests(unittest.TestCase):
    def test_exact_every_baseline_and_control_inventory(self):
        self.assertEqual(len(G.CHILD["command_cases"]), 68)
        self.assertEqual(len(G.CHILD["box_cases"]), 14)
        self.assertEqual([len(item["cases"]) for item in G.REGRESSIONS], [16, 28, 52, 27, 11])
        for family, key in (("cmd", "command_cases"), ("box", "box_cases")):
            cases = G.CHILD[key]
            G.require_verdict(raw(transcript(cases, G.PACKAGE[family])), 0, G.PACKAGE[family], cases)
        for suite in G.REGRESSIONS:
            G.require_verdict(raw(transcript(suite["cases"], G.PACKAGE[suite["package"]])), 0,
                              G.PACKAGE[suite["package"]], suite["cases"])
        self.assertEqual(len(G.CONTROLS), 7)
        for control in G.CONTROLS:
            with self.subTest(control=control["name"]):
                package = G.PACKAGE[control["package"]]
                G.require_verdict(raw(transcript(control["cases"], package, control)), 1,
                                  package, control["cases"], control=control)

    def test_physical_slash_siblings_keep_real_nested_parent_authority(self):
        root = "TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox"
        first = root+"/awg2-strong/wg"
        second = first+"/awg2-fast"
        cases = [root, first, first+"/different-original-mode",
                 second, second+"/different-original-mode"]
        package = G.PACKAGE["box"]
        valid = transcript(cases, package)
        self.assertLess(
            next(i for i,e in enumerate(valid) if e.get("Test")==first and e["Action"]=="pass"),
            next(i for i,e in enumerate(valid) if e.get("Test")==second and e["Action"]=="run"))
        G.require_verdict(raw(valid), 0, package, cases)
        faults = {}
        changed = copy.deepcopy(valid)
        start = next(i for i,e in enumerate(changed) if e.get("Test")==second and e["Action"]=="run")
        leaf = start+1
        changed[start],changed[leaf] = changed[leaf],changed[start]
        faults["real-nested-child-before-parent"] = changed
        for name in (root, first, second):
            changed = copy.deepcopy(valid)
            terminal = next(i for i,e in enumerate(changed) if e.get("Test")==name and e["Action"]=="pass")
            value = changed.pop(terminal)
            start = next(i for i,e in enumerate(changed) if e.get("Test")==name and e["Action"]=="run")
            changed.insert(start+1,value)
            faults["parent-before-required-children-"+name] = changed
        changed = copy.deepcopy(valid)
        terminal = next(i for i,e in enumerate(changed) if e.get("Test")==second and e["Action"]=="pass")
        changed.insert(terminal+1,dict(changed[terminal]))
        faults["duplicate-sibling-terminal"] = changed
        for omitted in cases:
            faults["omitted-"+omitted] = [e for e in valid if e.get("Test")!=omitted]
        changed = copy.deepcopy(valid)
        next(e for e in changed if e.get("Test")==second)["Test"] += "/foreign"
        faults["foreign-sibling"] = changed
        for fault,events in faults.items():
            with self.subTest(fault=fault),self.assertRaises(ValueError):
                G.require_verdict(raw(events), 0, package, cases)
        with self.assertRaises(ValueError):
            G.require_verdict(raw(transcript(cases[1:], package)), 0, package, cases[1:])

    def test_captured_hosted_physical_52_event_order(self):
        # Run43468906436/job132035311992, artifact14060576462. Exact test2json
        # start/run/terminal sequence; only timestamps/output are omitted here.
        # The unmodified complete log is also replayed in the repair receipt.
        cases = next(suite["cases"] for suite in G.REGRESSIONS if len(suite["cases"]) == 52)
        order = (('start', None), ('run', 0), ('pass', 0), ('run', 1), ('run', 2), ('pass', 2), ('run', 3), ('pass', 3), ('run', 4), ('pass', 4), ('run', 5), ('pass', 5), ('run', 6), ('pass', 6), ('pass', 1), ('run', 7), ('run', 8), ('run', 9), ('pass', 9), ('pass', 8), ('run', 10), ('run', 11), ('pass', 11), ('pass', 10), ('run', 12), ('run', 13), ('pass', 13), ('pass', 12), ('run', 14), ('run', 15), ('pass', 15), ('pass', 14), ('run', 16), ('run', 17), ('pass', 17), ('pass', 16), ('run', 18), ('run', 19), ('pass', 19), ('pass', 18), ('run', 20), ('run', 21), ('pass', 21), ('pass', 20), ('run', 22), ('run', 23), ('pass', 23), ('pass', 22), ('pass', 7), ('run', 24), ('run', 25), ('pass', 25), ('run', 26), ('pass', 26), ('run', 27), ('pass', 27), ('run', 28), ('pass', 28), ('run', 29), ('pass', 29), ('run', 30), ('pass', 30), ('pass', 24), ('run', 31), ('run', 32), ('pass', 32), ('run', 33), ('pass', 33), ('run', 34), ('pass', 34), ('pass', 31), ('run', 35), ('run', 36), ('pass', 36), ('run', 37), ('pass', 37), ('run', 38), ('pass', 38), ('run', 39), ('pass', 39), ('run', 40), ('pass', 40), ('run', 41), ('pass', 41), ('run', 42), ('pass', 42), ('pass', 35), ('run', 43), ('run', 44), ('pass', 44), ('run', 45), ('pass', 45), ('run', 46), ('pass', 46), ('run', 47), ('pass', 47), ('run', 48), ('pass', 48), ('run', 49), ('pass', 49), ('run', 50), ('pass', 50), ('run', 51), ('pass', 51), ('pass', 43), ('pass', None))
        package = G.PACKAGE["box"]
        events = []
        for action,index in order:
            event = {"Action": action, "Package": package}
            if index is not None:
                event["Test"] = cases[index]
            events.append(event)
        self.assertEqual(sum(action=="run" for action,index in order), 52)
        G.require_verdict(raw(events), 0, package, cases)
        # Every captured required test remains mandatory.
        for omitted in cases:
            with self.subTest(omitted=omitted),self.assertRaises(ValueError):
                G.require_verdict(raw([e for e in events if e.get("Test")!=omitted]), 0, package, cases)

    def test_control_rejects_unrelated_missing_duplicated_or_moved_evidence(self):
        control = G.CONTROLS[3]
        package, cases = G.PACKAGE["cmd"], control["cases"]
        valid = transcript(cases, package, control)
        output_index = next(i for i, value in enumerate(valid) if value["Action"] == "output")
        terminal_index = len(valid)-1
        variants = {}
        variants["unframed"] = raw(valid)+"unframed\n"
        variants["non-event"] = raw(valid[:-1])+"[]\n"+raw(valid[-1:])
        changed = copy.deepcopy(valid); changed[output_index]["Package"] += "/foreign"; variants["foreign-package"] = raw(changed)
        changed = copy.deepcopy(valid); changed[output_index]["Test"] = "TestForeign"; variants["foreign-test"] = raw(changed)
        changed = copy.deepcopy(valid); changed.insert(1, dict(changed[1])); variants["duplicate-run"] = raw(changed)
        changed = copy.deepcopy(valid); changed.pop(output_index); variants["missing-witness"] = raw(changed)
        changed = copy.deepcopy(valid); changed[output_index]["Output"] *= 2; variants["duplicate-witness"] = raw(changed)
        changed = copy.deepcopy(valid); changed[output_index].pop("Test"); variants["package-witness"] = raw(changed)
        changed = copy.deepcopy(valid); changed[output_index]["Test"] = cases[0]; variants["root-witness"] = raw(changed)
        changed = copy.deepcopy(valid); changed[1], changed[2] = changed[2], changed[1]; variants["child-before-parent"] = raw(changed)
        changed = copy.deepcopy(valid); changed[terminal_index]["Action"] = "pass"; variants["wrong-package-result"] = raw(changed)
        changed = copy.deepcopy(valid); changed[-2]["Action"] = "pass"; variants["wrong-root-result"] = raw(changed)
        changed = copy.deepcopy(valid); changed[1]["Action"] = "skip"; variants["skipped-test"] = raw(changed)
        changed = copy.deepcopy(valid); changed[1]["Action"] = "pause"; variants["unknown-test-action"] = raw(changed)
        changed = copy.deepcopy(valid); changed.insert(1, {"Action": "foreign", "Package": package}); variants["unknown-package-action"] = raw(changed)
        changed = copy.deepcopy(valid); changed.append({"Action": "output", "Package": package, "Output": "late"}); variants["late-package"] = raw(changed)
        changed = copy.deepcopy(valid); changed.insert(-1, {"Action": "output", "Package": package, "Test": cases[0], "Output": "late"}); variants["late-test"] = raw(changed)
        changed = copy.deepcopy(valid); changed[output_index]["Output"] += "WARNING: DATA RACE"; variants["race"] = raw(changed)
        changed = copy.deepcopy(valid); changed[output_index]["Output"] += "panic: broken"; variants["panic"] = raw(changed)
        changed = copy.deepcopy(valid); changed[output_index]["Output"] += "signal: killed"; variants["signal"] = raw(changed)
        changed = copy.deepcopy(valid); changed[output_index]["Output"] += "[build failed]"; variants["build"] = raw(changed)
        changed = copy.deepcopy(valid); changed[output_index]["Output"] += "test timed out"; variants["timeout"] = raw(changed)
        variants["missing-terminal"] = raw(valid[:-1])
        variants["missing-start"] = raw(valid[1:])
        for name, text in variants.items():
            with self.subTest(fault=name), self.assertRaises(ValueError):
                G.require_verdict(text, 1, package, cases, control=control)
        for status in (0, -9, 2):
            with self.subTest(status=status), self.assertRaises(ValueError):
                G.require_verdict(raw(valid), status, package, cases, control=control)

    def test_every_required_original_record_is_mandatory(self):
        cases = G.CHILD["command_cases"]
        package = G.PACKAGE["cmd"]
        valid = transcript(cases, package)
        for omitted in cases:
            with self.subTest(omitted=omitted), self.assertRaises(ValueError):
                changed = [value for value in valid if value.get("Test") != omitted]
                G.require_verdict(raw(changed), 0, package, cases)
        for repeated in cases:
            index = next(i for i, value in enumerate(valid) if value.get("Test") == repeated and value["Action"] == "pass")
            changed = copy.deepcopy(valid);changed.insert(index, dict(changed[index]))
            with self.subTest(duplicate=repeated), self.assertRaises(ValueError):
                G.require_verdict(raw(changed), 0, package, cases)

    def test_only_original_prestart_build_output_is_allowed(self):
        cases, package = ["TestOriginal"], G.PACKAGE["cmd"]
        valid = transcript(cases, package)
        build = {"Action": "build-output", "ImportPath": package+".test", "Output": "# checked compiler diagnostic\n"}
        G.require_verdict(raw([build, *valid]), 0, package, cases)
        for changed in (
            [dict(build, ImportPath="foreign.test"), *valid],
            [dict(build, Output=2), *valid],
            [valid[0], build, *valid[1:]],
            [*valid, build],
            [{"Action": "build-fail", "ImportPath": package+".test"}, *valid],
        ):
            with self.subTest(events=changed), self.assertRaises(ValueError):
                G.require_verdict(raw(changed), 0, package, cases)

    def test_actual_unittest_projection_report_and_refusals(self):
        fixture = type("DesktopSOCKSChildProjection", (unittest.TestCase,),
                       {name: lambda self: None for name in G.PROJECTION_TESTS})
        fixture.__module__ = "__main__"
        stream = StringIO()
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(fixture))
        self.assertTrue(result.wasSuccessful())
        text = stream.getvalue()
        for transcript_text in (text, text.replace("\n", "\r\n"), text.replace("\n", "\r\r\n")):
            G.require_projection(transcript_text, 0)
        for changed in (text.replace("... ok", "... skipped", 1),
                        text.replace("Ran 4 tests", "Ran 3 tests"),
                        text.replace("OK", "FAILED (failures=1)"),
                        text+"OK\n", text+"foreign\n",
                        text.replace(G.PROJECTION_TESTS[0], "test_foreign")):
            with self.subTest(output=changed), self.assertRaises(ValueError):
                G.require_projection(changed, 0)
        with self.assertRaises(ValueError):
            G.require_projection(text, 1)

    def test_original_heartbeat_records_and_all_five_controls_required(self):
        text = "".join("=== RUN   "+name+"\n    --- PASS: "+name+" (0.01s)\n" for name in G.HEARTBEAT_CASES)
        text += "PASS\nok heartbeat 1s\n"+"\n".join(G.HEARTBEAT_CONTROLS)+"\n"
        G.require_heartbeat(text, 0)
        for case in G.HEARTBEAT_CASES:
            with self.subTest(case=case), self.assertRaises(ValueError):
                G.require_heartbeat(text.replace("=== RUN   "+case+"\n", "", 1), 0)
        for control in G.HEARTBEAT_CONTROLS:
            for changed in (text.replace(control+"\n", "", 1), text+control+"\n"):
                with self.subTest(control=control), self.assertRaises(ValueError):
                    G.require_heartbeat(changed, 0)
        for changed in (text+"--- SKIP: TestOther\n", text+"panic: failed\n", text+"=== RUN   TestOther\n"):
            with self.assertRaises(ValueError):
                G.require_heartbeat(changed, 0)

    def test_each_exact_overlay_preserves_original_and_refuses_moved_seam(self):
        for control in G.CONTROLS:
            original = "\n".join(item["before"] for item in (control, *control.get("additional_replacements", ())))
            changed = G.mutate(original, control)
            self.assertNotEqual(original, changed)
            for part in (control, *control.get("additional_replacements", ())):
                self.assertNotIn(part["before"], changed)
            for invalid in ("unrelated", original+"\n"+control["before"]):
                with self.subTest(control=control["name"]), self.assertRaises(ValueError):
                    G.mutate(invalid, control)

    def test_projection_and_native_tree_refuse_replacement_or_link(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp);source,core = root/"source",root/"core";source.mkdir();core.mkdir()
            (source/"template").write_bytes(b"exact source\n");(core/"projection").write_bytes(b"exact source\n")
            G.bind_projection(source,core,"template","projection")
            before = G.native_tree(core)
            (core/"projection").write_bytes(b"foreign source\n")
            self.assertNotEqual(G.native_tree(core),before)
            with self.assertRaises(ValueError):
                G.bind_projection(source,core,"template","projection")
            (core/"projection").unlink();(core/"projection").symlink_to(source/"template")
            with self.assertRaises(ValueError):
                G.bind_projection(source,core,"template","projection")
            with self.assertRaises(ValueError):
                G.native_tree(core)


class ChildIdentityAndExecutionTests(unittest.TestCase):
    def git(self, path, *args):
        return subprocess.check_output(["git", "-C", str(path), *args], text=True, stderr=subprocess.STDOUT, timeout=10).strip()

    def repo(self, root):
        root.mkdir(); self.git(root,"init","-q");self.git(root,"config","user.name","Original fixture");self.git(root,"config","user.email","fixture@example.invalid")
        (root/"source").write_text("original\n");(root/".gitignore").write_text("ignored\n")
        self.git(root,"add",".");self.git(root,"commit","-qm","original")
        return self.git(root,"rev-parse","HEAD"),self.git(root,"rev-parse","HEAD^{tree}")

    def test_real_git_selection_and_ignored_tracked_metadata_refusals(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);candidate,validator=root/"candidate",root/"validator"
            sha,tree=self.repo(candidate);vsha,vtree=self.repo(validator)
            evidence=root/"evidence";evidence.mkdir();output=evidence/"tests"
            record=dict(schema=1,suite=G.SUITE,source_sha=sha,source_tree=tree,
                        validator_sha=vsha,validator_tree=vtree,base_sha=vsha,base_tree=vtree,
                        validation_scope="read-only-source-candidate")
            selected=evidence/"selection.json";selected.write_text(json.dumps(record))
            with mock.patch.object(G,"ROOT",validator):
                G.selection(candidate,sha,output)
                for path in (candidate/"ignored",candidate/"untracked",validator/"ignored"):
                    path.write_text("do not waive")
                    try:
                        with self.subTest(path=path),self.assertRaises(ValueError):
                            G.selection(candidate,sha,output)
                    finally:path.unlink()
                (candidate/"source").write_text("changed")
                with self.assertRaises(ValueError):G.selection(candidate,sha,output)
                (candidate/"source").write_text("original\n")
                for field,value in (("suite","foreign"),("source_sha","f"*40),("source_tree","f"*40),
                                    ("validator_sha","f"*40),("validation_scope","native-accepted")):
                    changed=dict(record);changed[field]=value;selected.write_text(json.dumps(changed))
                    with self.subTest(field=field),self.assertRaises(ValueError):G.selection(candidate,sha,output)
                selected.write_text(json.dumps(record))
                original=root/"selection-copy";original.write_bytes(selected.read_bytes());selected.unlink();selected.symlink_to(original)
                with self.assertRaises(ValueError):G.selection(candidate,sha,output)

    def test_actual_owned_python_process_is_joined_and_log_retained(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);log=root/"original.log"
            owner=G.OwnedWorkspace(root)
            code,timed_out,joined=owner.execute([sys.executable,"-c","print('original child joined')"],owner.path,dict(os.environ),log,5)
            self.assertEqual((code,timed_out,joined),(0,False,True))
            self.assertTrue(owner.cleanup()["removed"])
            self.assertFalse(owner.path.exists())
            self.assertEqual(log.read_text(),"original child joined\n")


    def test_workspace_retains_false_or_unknown_original_join(self):
        for fault in ("false-join", "unknown-join", "executor-error", "malformed-result"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                parent = Path(temp)
                owner = G.OwnedWorkspace(parent)
                marker = owner.path/"original-source"
                marker.write_text("preserve original source")
                if fault == "executor-error":
                    context = mock.patch.object(G, "execute", side_effect=RuntimeError("unknown child lifetime"))
                else:
                    result = (0, False, False) if fault == "false-join" else (0, False, None) if fault == "unknown-join" else ()
                    context = mock.patch.object(G, "execute", return_value=result)
                with context:
                    if fault in ("executor-error", "malformed-result"):
                        with self.assertRaises((RuntimeError, IndexError)):
                            owner.execute(["unexecuted-boundary"], owner.path, {}, parent/"log", 1)
                    else:
                        owner.execute(["unexecuted-boundary"], owner.path, {}, parent/"log", 1)
                result = owner.cleanup()
                self.assertFalse(result["removed"])
                self.assertEqual(result["retained_reason"], "original-process-join-unproved")
                self.assertEqual(marker.read_text(), "preserve original source")
                with self.assertRaises(ValueError):
                    owner.begin_command()

    def test_workspace_refuses_replaced_directory_and_link(self):
        for linked in (False, True):
            with self.subTest(linked=linked), tempfile.TemporaryDirectory() as temp:
                parent = Path(temp)
                owner = G.OwnedWorkspace(parent)
                (owner.path/"original-source").write_text("captured")
                moved = parent/"moved-original"
                owner.path.rename(moved)
                if linked:
                    replacement = parent/"foreign-target";replacement.mkdir()
                    owner.path.symlink_to(replacement, target_is_directory=True)
                else:
                    owner.path.mkdir();replacement=owner.path
                (replacement/"unowned").write_text("preserve replacement")
                result = owner.cleanup()
                self.assertFalse(result["removed"])
                self.assertEqual(result["retained_reason"], "original-directory-replaced")
                self.assertEqual((replacement/"unowned").read_text(), "preserve replacement")
                self.assertEqual((moved/"original-source").read_text(), "captured")

    def test_workspace_cleans_only_after_positive_original_join(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp);owner = G.OwnedWorkspace(parent)
            (owner.path/"original").write_text("owned")
            token = owner.begin_command()
            with self.assertRaises(ValueError):
                owner.begin_command()
            with self.assertRaises(ValueError):
                owner.complete_command(object(), True)
            self.assertFalse(owner.cleanup()["removed"])
            owner.complete_command(token, True)
            # A known joined timeout can be cleaned, but the driver still
            # rejects its timeout before parsing any native acceptance.
            with mock.patch.object(G, "execute", return_value=(1, True, True)):
                self.assertEqual(owner.execute(["unexecuted-boundary"],owner.path,{},parent/"log",1),(1,True,True))
            self.assertTrue(owner.cleanup()["removed"])
            self.assertFalse(owner.path.exists())

    def test_driver_bounds_and_no_native_acceptance_claim(self):
        source=(ROOT/"deploy/validate-desktop-socks-child.py").read_text()
        ast.parse(source)
        self.assertIn('"-test.timeout=90s"',source)
        self.assertIn('"-timeout=90s"',source)
        self.assertIn('"-race", "-p=1", "-mod=readonly"',source)
        self.assertIn('installed_native_accepted=False',source)
        self.assertIn('windows_native_accepted=False',source)
        self.assertIn('darwin_native_accepted=False',source)
        self.assertEqual(len(G.PROJECTIONS),26)


if __name__ == "__main__":
    unittest.main(verbosity=2)
