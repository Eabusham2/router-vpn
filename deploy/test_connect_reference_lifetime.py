#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location("lifetime",Path(__file__).with_name("connect_reference_lifetime.py"))
V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)

class EstablishedLifetimeControl(unittest.TestCase):
    def raw(self):
        return (f"=== RUN   {V.ROOT}\n=== RUN   {V.ROOT}/retained\n"
                f"    fixture.go:1: {V.CONTROL['witness']} EOF\n"
                f"--- FAIL: {V.ROOT} (31.00s)\n    --- FAIL: {V.ROOT}/retained (31.00s)\nFAIL\n").encode()
    def test_original_restored_deadline(self):
        self.assertTrue(V.control_events(self.raw(),1)["expected_failure"])
    def test_success_cannot_be_failure(self):
        with self.assertRaises(ValueError):V.control_events(self.raw(),0)
    def test_wrong_or_missing_witness(self):
        for witness in ("", "unrelated original failure"):
            with self.subTest(witness=witness),self.assertRaises(ValueError):V.control_events(self.raw().replace(V.CONTROL['witness'].encode(),witness.encode()),1)
    def test_missing_or_extra_inventory(self):
        for raw in (self.raw().replace(f"=== RUN   {V.ROOT}/retained\n".encode(),b""), self.raw()+b"=== RUN   unrelated\n"):
            with self.assertRaises(ValueError):V.control_events(raw,1)
    def test_duplicate_witness_is_not_exact(self):
        with self.assertRaises(ValueError):V.control_events(self.raw()+V.CONTROL['witness'].encode(),1)
    def test_race_panic_skip_pass_and_compile_failure_refused(self):
        for marker in ("DATA RACE", "panic:", "--- SKIP:", "--- PASS:", "[build failed]"):
            with self.subTest(marker=marker),self.assertRaises(ValueError):V.control_events(self.raw()+marker.encode(),1)

if __name__=="__main__":unittest.main(verbosity=2)
