#!/usr/bin/env python3
"""Refuse incomplete or false preclose evidence while retaining the original gates."""
from pathlib import Path
import importlib.util
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
V=module("socks_preclose_validator",ROOT/"deploy/test_focused_socks_preclose.py")
FIXTURE=module("socks_preclose_bridge_support",ROOT/"deploy/test_focused_socks_bridge_runner.py")

class CapturedSOCKSPrecloseValidator(unittest.TestCase):
    def fixture(self,directory,fault=None):
        value=FIXTURE.Composition(Path(directory),fault)
        value.validator=V.validate
        original=value.execute
        def execute(command,cwd,env,log,bound):
            result=original(command,cwd,env,log,bound)
            if log.stem in ("prepare-owner","prepare-mobile"):
                core=Path(command[command.index("--core")+1])
                # Original support installs the desktop-owner anchors last.
                # The real single owner source also has the new native anchors.
                path=core/V.BASE.OWNER.OWNER_PROJECTION
                text=path.read_text()
                for control in V.CONTROLS:
                    if control["path"]==V.BASE.OWNER.OWNER_PROJECTION and control["before"] not in text:
                        text+="\n"+control["before"]
                path.write_text(text)
            return result
        value.execute=execute
        return value

    def test_exact_new_and_preserved_inventories(self):
        self.assertEqual((len(V.ROOTS),len(V.CASES),len(V.CONTROLS)),(5,11,6))
        self.assertEqual((len(V.ORIGINAL_TYPED),len(V.ORIGINAL_BOX),len(V.ORIGINAL_CONTROLS)),(63,45,19))
        self.assertEqual((len(V.BASE.VERDICTS),len(V.BASE.ORIGINAL_LIBBOX),len(V.BASE.ORIGINAL_BOX)),(74,13,45))
        self.assertEqual((len(V.BASE.OWNER.VERDICTS),len(V.BASE.OWNER.ORIGINAL)),(22,15))
        self.assertEqual((len(V.BASE.CONTROLS),len(V.BASE.OWNER.CONTROLS)),(25,4))
        self.assertEqual(tuple(V.BASE.VERDICTS[:63]),V.ORIGINAL_TYPED)
        self.assertEqual(tuple(V.BASE.CONTROLS[:19]),V.ORIGINAL_CONTROLS)
        self.assertEqual([len(x["cases"]) for x in V.CONTROLS],[3,3,1,2,2,1])
        for names in (V.CASES,V.BASE.VERDICTS,V.BASE.ORIGINAL_BOX):
            self.assertEqual(len(names),len(set(names)))
        self.assertEqual(len({x["name"] for x in V.BASE.CONTROLS}),25)
        self.assertEqual(V.BASE.PROJECTIONS["socks_close_native_test.go.tmpl"],
                         "experimental/libbox/routervpn_node_chain_socks_close_test.go")
        for control in V.CONTROLS:
            self.assertEqual(V.BASE.control_target(control),(V.BASE.LIBBOX,"./experimental/libbox"))

    def test_all_original_and_added_phases_keep_original_bounds_and_joins(self):
        with patch.object(FIXTURE,"V",V.BASE),tempfile.TemporaryDirectory() as directory:
            f=self.fixture(directory);receipt=f.run()
            self.assertEqual(len(f.calls),40)
            self.assertEqual((len(receipt["controls"]),len(receipt["owner_controls"])),(25,4))
            self.assertEqual(f.owner_calls,[tuple(V.BASE.OWNER.VERDICTS),tuple(V.BASE.OWNER.ORIGINAL)])
            self.assertTrue(receipt["preclose_component_accepted"])
            self.assertTrue(receipt["native_mtu_component_accepted"])
            for key in ("successful_run_accepted","public_native_admission","installed_native_accepted",
                        "public_mtu_constructor_accepted","generated_sdk_accepted","physical_mtu_accepted"):
                self.assertFalse(receipt[key],key)
            self.assertEqual(receipt["preclose_cases"],list(V.CASES))
            self.assertEqual(receipt["preserved_preclose_typed_cases"],list(V.ORIGINAL_TYPED))
            self.assertEqual(receipt["preserved_preclose_box_cases"],list(V.ORIGINAL_BOX))
            self.assertEqual(json.loads((f.output/"receipt.json").read_text()),receipt)
            self.assertEqual(json.loads((f.output/"progress.json").read_text()),receipt)
            calls={name:(command,bound) for name,command,bound in f.calls}
            self.assertEqual(calls["original-owner-preflight"][1],60)
            for name in ("prepare-owner","prepare-mobile","owner-build","libbox-build","box-build"):
                self.assertEqual(calls[name][1],600)
            for control in V.BASE.CONTROLS:
                command,bound=calls[control["name"]]
                self.assertEqual(bound,600)
                self.assertEqual(command[-1],V.BASE.control_target(control)[1])
                self.assertIn("-timeout=90s",command);self.assertIn("-race",command)
                self.assertIn("-p=1",command);self.assertIn("-mod=readonly",command)
                self.assertIn("-run=^"+control["root"]+"$",command)
            for name in ("typed-native","original-libbox","original-box"):
                command,bound=calls[name]
                self.assertEqual(bound,100);self.assertIn("-test.timeout=90s",command)
            for root in V.ROOTS:
                self.assertIn(root," ".join(calls["typed-native"][0]))

    def test_each_control_requires_exact_status_package_and_original_leaf_witness(self):
        with patch.object(FIXTURE,"V",V.BASE):
            for control in V.CONTROLS:
                with self.subTest(control=control["name"]):
                    rows=FIXTURE.events(V.BASE.LIBBOX,control["cases"],control)
                    raw=FIXTURE.encoded(rows)
                    self.assertTrue(V.BASE.require_events(raw,1,V.BASE.LIBBOX,control["cases"],control)["accepted"])
                    for code in (0,-9,2,124):
                        with self.assertRaises(ValueError):
                            V.BASE.require_events(raw,code,V.BASE.LIBBOX,control["cases"],control)
                    with self.assertRaises(ValueError):
                        V.BASE.require_events(raw,1,V.BASE.BOX,control["cases"],control)
                    with self.assertRaises(ValueError):
                        V.BASE.require_events(raw.replace(control["witness"].encode(),b"unrelated assertion"),
                                              1,V.BASE.LIBBOX,control["cases"],control)
                    for leaf in [n for n in control["cases"] if not any(o.startswith(n+"/") for o in control["cases"])]:
                        dropped=[r for r in rows if not(r.get("Test")==leaf and r.get("Action")=="output")]
                        with self.assertRaises(ValueError):
                            V.BASE.require_events(FIXTURE.encoded(dropped),1,V.BASE.LIBBOX,control["cases"],control)

    def test_baseline_rejects_missing_duplicate_foreign_skip_and_reordered_events(self):
        with patch.object(FIXTURE,"V",V.BASE):
            rows=FIXTURE.events(V.BASE.LIBBOX,V.CASES)
            self.assertTrue(V.BASE.require_events(FIXTURE.encoded(rows),0,V.BASE.LIBBOX,V.CASES)["accepted"])
            for name in V.CASES:
                dropped=[r for r in rows if not(r.get("Test")==name and r.get("Action")=="pass")]
                with self.assertRaises(ValueError):
                    V.BASE.require_events(FIXTURE.encoded(dropped),0,V.BASE.LIBBOX,V.CASES)
            for fault in ("duplicate","foreign-package","foreign-test","skip","early-parent","no-start"):
                changed=[dict(row) for row in rows]
                if fault=="duplicate":changed.insert(-1,dict(changed[-2]))
                elif fault=="foreign-package":changed[1]["Package"]=V.BASE.BOX
                elif fault=="foreign-test":changed[1]["Test"]="TestForeign"
                elif fault=="skip":next(r for r in changed if r.get("Action")=="pass" and r.get("Test"))["Action"]="skip"
                elif fault=="no-start":changed.pop(0)
                else:
                    root=V.ROOTS[0]
                    at=next(i for i,r in enumerate(changed) if r.get("Test")==root and r["Action"]=="pass")
                    row=changed.pop(at);changed.insert(2,row)
                with self.subTest(fault=fault),self.assertRaises(ValueError):
                    V.BASE.require_events(FIXTURE.encoded(changed),0,V.BASE.LIBBOX,V.CASES)

    def test_control_refuses_panic_build_failure_unframed_or_late_output(self):
        with patch.object(FIXTURE,"V",V.BASE):
            control=V.CONTROLS[0];rows=FIXTURE.events(V.BASE.LIBBOX,control["cases"],control)
            for suffix in (b"panic: unrelated\n",b"fatal error: unrelated\n",b"WARNING: DATA RACE\n",
                           FIXTURE.encoded([dict(Action="build-fail",ImportPath=V.BASE.LIBBOX)]),
                           FIXTURE.encoded([dict(Action="output",Package=V.BASE.LIBBOX,
                                                Test=control["cases"][-1],Output=control["witness"]+"\n")])):
                with self.assertRaises(ValueError):
                    V.BASE.require_events(FIXTURE.encoded(rows)+suffix,1,V.BASE.LIBBOX,control["cases"],control)

    def test_every_added_mutation_has_one_exact_non_noop_seam(self):
        for control in V.CONTROLS:
            original="before\n"+control["before"]+"\nafter"
            self.assertNotEqual(V.BASE.mutate(control,original),original)
            for bad in ("absent",original+control["before"]):
                with self.assertRaises(ValueError):V.BASE.mutate(control,bad)

    def test_original_failed_or_unjoined_phase_cannot_publish_preclose_acceptance(self):
        with patch.object(FIXTURE,"V",V.BASE):
            for fault in ("preflight-missing","prepare-fail","owner-prepare-fail","compile-fail","owner-missing",
                          "peer-missing","native-missing","old-box-missing","native-control-pass",
                          "native-control-signal","timeout","unjoined","source-change","native-change",
                          "owner-native-change","image-change","selection-change"):
                with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                    f=self.fixture(directory,fault)
                    with self.assertRaises((ValueError,RuntimeError,OSError)):f.run()
                    receipt=json.loads((f.output/"progress.json").read_text())
                    self.assertEqual(receipt["status"],"failed")
                    self.assertNotIn("preclose_component_accepted",receipt)
                    self.assertFalse((f.output/"receipt.json").exists())

    def test_each_added_control_timeout_or_unjoined_process_is_retained_as_failure(self):
        with patch.object(FIXTURE,"V",V.BASE):
            for control in V.CONTROLS:
                for fault in ("timeout","unjoined","pass","signal"):
                    with self.subTest(control=control["name"],fault=fault),tempfile.TemporaryDirectory() as directory:
                        f=self.fixture(directory);original=f.execute
                        def execute(command,cwd,env,log,bound):
                            code,timed,joined=original(command,cwd,env,log,bound)
                            if log.stem==control["name"]:
                                if fault=="timeout":timed=True
                                elif fault=="unjoined":joined=False
                                elif fault=="pass":code=0
                                else:code=-9
                            return code,timed,joined
                        f.execute=execute
                        with self.assertRaises((ValueError,RuntimeError)):f.run()
                        self.assertEqual(f.calls[-1][0],control["name"])
                        receipt=json.loads((f.output/"progress.json").read_text())
                        self.assertEqual(receipt["status"],"failed")
                        self.assertNotIn("preclose_component_accepted",receipt)
                        self.assertFalse((f.output/"receipt.json").exists())

if __name__=="__main__":unittest.main(verbosity=2)
