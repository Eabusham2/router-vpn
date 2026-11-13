#!/usr/bin/env python3
"""Check the fixed CONNECT composition using original source/event boundaries."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result
D = module("connect_gate_under_test", ROOT / "deploy/test_focused_connect_source.py")
HELPER = module("connect_original_fixture", ROOT / "deploy/test_focused_socks_source_runner.py")

class CONNECTSourceGate(unittest.TestCase):
    @contextmanager
    def fixture(self, mutate=None):
        with patch.object(HELPER, "D", D.BASE):
            with HELPER.RunnerTests.fixture(self, mutate=mutate) as values:
                yield values

    def test_original_nine_attempts_and_all_original_controls_are_preserved(self):
        self.assertEqual([len(x.expected) for x in D.ORIGINAL_CASES], [70,44,2,3,49,2,2,2,2])
        self.assertEqual(D.cases()[:9], D.ORIGINAL_CASES)
        for key,value in D.ORIGINAL_MUTATIONS.items():
            self.assertEqual(D.BASE.CONTROL_MUTATIONS[key], value)
        self.assertTrue(set(D.ORIGINAL_SOURCE_PATHS).issubset(D.BASE.SOURCE_PATHS))
        self.assertTrue(set(D.ORIGINAL_FORMAT_PATHS).issubset(D.BASE.FORMAT_PATHS))

    def test_exact_new_and_original_connect_inventory_and_bounds(self):
        selected=D.cases()
        self.assertEqual([len(x.expected) for x in selected[9:]], [84,52,2,2,1])
        self.assertEqual(len(D.INVENTORY["files"]),6)
        self.assertEqual(len(D.INVENTORY["roots"]),7)
        self.assertEqual(sum(len(x.expected) for x in selected if not x.mutation),299)
        self.assertEqual(sum(bool(x.mutation) for x in selected),9)
        self.assertEqual(len({x.name for x in selected}),14)
        for case in selected:
            self.assertEqual((case.seconds,case.outer_seconds),(120,600))
            args=D.BASE.command_for("/captured/go",case,Path("/exact.overlay.json") if case.mutation else None)
            self.assertIn("-race",args);self.assertIn("-mod=readonly",args)
            self.assertEqual(args[-1],"./internal/mobilemultihop")

    def test_unknown_suite_and_foreign_control_cannot_reach_candidate(self):
        for suite in ["socks-source","",None,"connect-runtime"]:
            with self.assertRaises(ValueError):D.cases(suite)
        for case in D.cases()[11:]:
            with self.assertRaises(ValueError):D.BASE.command_for("/go",case)
            path,anchor,replacement=D.BASE.CONTROL_MUTATIONS[case.mutation]
            self.assertIn(path,D.INVENTORY["files"])
            self.assertEqual(D.BASE.mutation_source(case,"before\n"+anchor+"\nafter"),"before\n"+replacement+"\nafter")
            for invalid in ["",anchor+anchor]:
                with self.assertRaises(ValueError):D.BASE.mutation_source(case,invalid)

    def test_composed_execution_preserves_all_attempts_and_exact_driver_receipts(self):
        with self.fixture() as (args,source,output,calls):
            D.validate(args)
            value=json.loads((output/"manifest.json").read_bytes())
            self.assertEqual(value["status"],"passed")
            self.assertEqual([x["name"] for x in value["attempts"]],[x.name for x in D.cases()])
            self.assertEqual(len(calls),14)
            self.assertEqual(value["composition"]["driver_sha256"],hashlib.sha256(Path(D.__file__).read_bytes()).hexdigest())
            self.assertEqual(value["composition"]["original_driver_sha256"],hashlib.sha256(D.BASE_PATH.read_bytes()).hexdigest())
            self.assertEqual(value["composition"]["runtime_native_host_delivery"],"unfinished")
            self.assertTrue(value["formatting"]["process_group_joined"])
            self.assertIn("no native owner",value["scope"])

    def test_missing_duplicate_skipped_or_foreign_native_record_is_rejected(self):
        for fault in ["missing","duplicate","skip","foreign","race"]:
            def mutate(case,source,log,calls):
                if case.name=="ordered-connect-source":
                    rows=[json.loads(x) for x in log.read_bytes().splitlines()]
                    if fault=="missing":rows.pop(0)
                    elif fault=="duplicate":rows.insert(1,dict(rows[0]))
                    elif fault=="skip":rows[1]["Action"]="skip"
                    elif fault=="foreign":rows[0]["Package"]="foreign/package"
                    else:rows.insert(1,{"Action":"output","Package":D.BASE.CORE.PACKAGE,"Test":rows[0]["Test"],"Output":"WARNING: DATA RACE\n"})
                    log.write_bytes(b"\n".join(json.dumps(x).encode() for x in rows)+b"\n")
                return (1 if case.mutation else 0),False,True
            with self.subTest(fault=fault),self.fixture(mutate) as (args,source,output,calls):
                with self.assertRaises(RuntimeError):D.validate(args)
                self.assertEqual(json.loads((output/"manifest.json").read_bytes())["status"],"failed")

    def test_new_control_needs_original_failure_and_exact_leaf_witness(self):
        for fault in ["success","witness","foreign-witness"]:
            def mutate(case,source,log,calls):
                if case.name.startswith("connect-"):
                    raw=log.read_bytes()
                    if fault=="success":raw=raw.replace(b'"fail"',b'"pass"')
                    elif fault=="witness":raw=raw.replace(case.witness.encode(),b"foreign original witness")
                    else:
                        rows=[json.loads(x) for x in raw.splitlines()]
                        for row in rows:
                            if case.witness in row.get("Output",""):row["Test"]="foreign/test"
                        raw=b"\n".join(json.dumps(x).encode() for x in rows)+b"\n"
                    log.write_bytes(raw)
                    return (0 if fault=="success" else 1),False,True
                return (1 if case.mutation else 0),False,True
            with self.subTest(fault=fault),self.fixture(mutate) as (args,source,output,calls):
                with self.assertRaises(RuntimeError):D.validate(args)

    def test_timed_out_or_unjoined_new_execution_cannot_publish(self):
        for timed,joined in [(True,True),(False,False)]:
            def mutate(case,source,log,calls):
                if case.name=="ordered-connect-source":return 0,timed,joined
                return (1 if case.mutation else 0),False,True
            with self.subTest(timed=timed,joined=joined),self.fixture(mutate) as (args,source,output,calls):
                with self.assertRaises(RuntimeError):D.validate(args)
                self.assertEqual(json.loads((output/"manifest.json").read_bytes())["status"],"failed")

    def test_existing_manifest_is_rejected_without_relabeling_old_results(self):
        with self.fixture() as (args,source,output,calls):
            output.mkdir();path=output/"manifest.json"
            raw=b'{"suite":"connect-source","status":"passed","actual_source_sha":"old"}\n';path.write_bytes(raw)
            with self.assertRaises(ValueError):D.validate(args)
            self.assertEqual(path.read_bytes(),raw);self.assertFalse(calls)

    def test_changed_candidate_is_not_accepted_after_new_native_observation(self):
        def mutate(case,source,log,calls):
            if case.name=="ordered-connect-source":
                (source/D.INVENTORY["files"][0]).write_text("changed captured source")
            return (1 if case.mutation else 0),False,True
        with self.fixture(mutate) as (args,source,output,calls):
            with self.assertRaises(RuntimeError):D.validate(args)
            self.assertEqual(json.loads((output/"manifest.json").read_bytes())["status"],"failed")

if __name__=="__main__":
    unittest.main(verbosity=2)
