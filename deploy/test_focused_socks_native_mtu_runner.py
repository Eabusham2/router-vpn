#!/usr/bin/env python3
"""Exercise finite MTU gate composition, exact control packages and retained bounds."""
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
V=module("socks_native_mtu_validator",ROOT/"deploy/test_focused_socks_native_mtu.py")
FIXTURE=module("socks_native_mtu_bridge_test_support",ROOT/"deploy/test_focused_socks_bridge_runner.py")

class NativeSOCKSMTUValidator(unittest.TestCase):
    def fixture(self,directory,fault=None):
        value=FIXTURE.Composition(Path(directory),fault)
        value.validator=V.validate
        return value
    def test_exact_native_wrapper_original_and_control_inventory(self):
        self.assertEqual((len(V.NATIVE_ROOTS),len(V.NATIVE_CASES),len(V.WRAPPER_ROOTS),len(V.WRAPPER_CASES)),(8,18,7,13))
        self.assertEqual((len(V.ORIGINAL_TYPED),len(V.ORIGINAL_BOX),len(V.ORIGINAL_CONTROLS)),(50,27,6))
        self.assertEqual((len(V.BASE.VERDICTS),len(V.BASE.ORIGINAL_BOX),len(V.BASE.CONTROLS)),(63,45,19))
        for names in (V.NATIVE_CASES,V.WRAPPER_CASES,V.BASE.VERDICTS,V.BASE.ORIGINAL_BOX):
            self.assertEqual(len(names),len(set(names)))
        self.assertEqual(len({x["name"] for x in V.BASE.CONTROLS}),19)
        self.assertEqual(sum(V.BASE.control_target(x)[0]==V.BASE.BOX for x in V.CONTROLS),9)
    def test_all_original_phases_and_mtu_controls_execute_with_unchanged_bounds(self):
        with patch.object(FIXTURE,"V",V.BASE),tempfile.TemporaryDirectory() as directory:
            f=self.fixture(directory);receipt=f.run()
            self.assertEqual(len(f.calls),34)
            self.assertEqual(len(receipt["controls"]),19)
            self.assertEqual(len(receipt["owner_controls"]),4)
            self.assertEqual(f.owner_calls,[tuple(V.BASE.OWNER.VERDICTS),tuple(V.BASE.OWNER.ORIGINAL)])
            self.assertTrue(receipt["native_mtu_component_accepted"])
            for key in ("successful_run_accepted","public_native_admission","installed_native_accepted",
                        "public_mtu_constructor_accepted","generated_sdk_accepted","physical_mtu_accepted"):
                self.assertFalse(receipt[key],key)
            self.assertEqual(receipt["native_mtu_cases"],list(V.NATIVE_CASES))
            self.assertEqual(receipt["libbox_mtu_cases"],list(V.WRAPPER_CASES))
            self.assertEqual(json.loads((f.output/"receipt.json").read_text()),receipt)
            calls={name:(cmd,bound) for name,cmd,bound in f.calls}
            for control in V.BASE.CONTROLS:
                command,bound=calls[control["name"]];package,target=V.BASE.control_target(control)
                self.assertEqual(command[-1],target)
                self.assertEqual(bound,600)
                self.assertIn("-timeout=90s",command)
                self.assertIn("-race",command)
                self.assertIn("-run=^"+control["root"]+"$",command)
            for name in ("typed-native","original-libbox","original-box"):
                command,bound=calls[name];self.assertEqual(bound,100);self.assertIn("-test.timeout=90s",command)
    def test_every_added_control_uses_exact_native_package_and_failing_original_leaf(self):
        with patch.object(FIXTURE,"V",V.BASE):
            for control in V.CONTROLS:
                package,_=V.BASE.control_target(control)
                raw=FIXTURE.encoded(FIXTURE.events(package,control["cases"],control))
                self.assertTrue(V.BASE.require_events(raw,1,package,control["cases"],control)["accepted"])
                other=V.BASE.BOX if package==V.BASE.LIBBOX else V.BASE.LIBBOX
                with self.assertRaises(ValueError):V.BASE.require_events(raw,1,other,control["cases"],control)
                with self.assertRaises(ValueError):V.BASE.require_events(raw,0,package,control["cases"],control)
                with self.assertRaises(ValueError):V.BASE.require_events(raw,-9,package,control["cases"],control)
                with self.assertRaises(ValueError):V.BASE.require_events(raw.replace(control["witness"].encode(),b"unrelated refusal"),1,package,control["cases"],control)
    def test_missing_or_duplicate_mtu_verdict_never_becomes_acceptance(self):
        with patch.object(FIXTURE,"V",V.BASE):
            for package,names in ((V.BASE.BOX,V.NATIVE_CASES),(V.BASE.LIBBOX,V.WRAPPER_CASES)):
                rows=FIXTURE.events(package,names)
                self.assertTrue(V.BASE.require_events(FIXTURE.encoded(rows),0,package,names)["accepted"])
                for name in names:
                    dropped=[r for r in rows if not(r.get("Test")==name and r.get("Action")=="pass")]
                    with self.assertRaises(ValueError):V.BASE.require_events(FIXTURE.encoded(dropped),0,package,names)
                with self.assertRaises(ValueError):V.BASE.require_events(FIXTURE.encoded(rows+rows[-1:]),0,package,names)
    def test_only_two_known_compiled_package_targets_are_admitted(self):
        self.assertEqual(V.BASE.control_target({}),(V.BASE.LIBBOX,"./experimental/libbox"))
        self.assertEqual(V.BASE.control_target({"package":V.BASE.BOX}),(V.BASE.BOX,"."))
        for package in ("","./other","github.com/foreign/core",None):
            with self.assertRaises(ValueError):V.BASE.control_target({"package":package})
    def test_each_control_has_one_original_non_noop_seam(self):
        for control in V.CONTROLS:
            original="before\n"+control["before"]+"\nafter"
            self.assertNotEqual(V.BASE.mutate(control,original),original)
            for bad in ("absent",original+control["before"]):
                with self.assertRaises(ValueError):V.BASE.mutate(control,bad)
    def test_failure_timeout_stale_source_or_unjoined_child_withholds_component_acceptance(self):
        with patch.object(FIXTURE,"V",V.BASE):
            for fault in ("owner-missing","peer-missing","compile-fail","native-missing","old-box-missing",
                          "native-control-pass","native-control-signal","timeout","unjoined",
                          "source-change","native-change","image-change","selection-change"):
                with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                    f=self.fixture(directory,fault)
                    with self.assertRaises((ValueError,RuntimeError)):f.run()
                    receipt=json.loads((f.output/"progress.json").read_text())
                    self.assertEqual(receipt["status"],"failed")
                    self.assertNotIn("native_mtu_component_accepted",receipt)

if __name__=="__main__":unittest.main(verbosity=2)
