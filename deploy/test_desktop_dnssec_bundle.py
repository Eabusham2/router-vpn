#!/usr/bin/env python3
"""Pure receipt wiring controls plus optional actual pinned package mutations."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('dnssec_bundle',ROOT/'deploy/desktop-dnssec-bundle.py')
B=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(B)
class Wiring(unittest.TestCase):
    def test_source_freshness_covers_builder_verifier_abi_and_pins(self):
        sources=B.source_inputs()
        for name in ('deploy/build-dnssec-validator.py','deploy/verify-dnssec-validator.py','native/dnssec/validator.c','native/dnssec/validator.h','native/dnssec/sources.json','cmd/client/bundled_dnssec.go'):
            self.assertIn(name,sources)
        self.assertEqual(len(sources),len(set(sources)))
    def test_library_is_mandatory_only_for_linux(self):
        self.assertEqual(len(B.names('linux/amd64')),4)
        self.assertEqual(B.names('linux/amd64'),B.names('linux/arm64'))
        self.assertFalse(B.names('darwin/arm64'))
        self.assertFalse(B.names('windows/amd64'))
        with self.assertRaises(ValueError):B.bound(B.LIBRARY,'windows/amd64')
    def test_native_gate_requires_every_actual_verdict_once(self):
        lines=[json.dumps({'Action':action,'Test':name}) for name in B.ACTUAL_CASES for action in ('run','pass')]
        B.require_actual_verdicts('\n'.join(lines))
        for changed in (lines[:-1],lines+lines[:1],lines+[json.dumps({'Action':'skip','Test':B.ACTUAL_CASES[0]})],lines+[json.dumps({'Action':'fail'})]):
            with self.assertRaises(ValueError):B.require_actual_verdicts('\n'.join(changed))
    def test_non_native_producer_cannot_issue_foreign_receipt(self):
        foreign='linux/arm64' if B.platform.machine()=='x86_64' else 'linux/amd64'
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):B.build(foreign,Path(tmp)/'out',compiled=Path(tmp)/'absent')
            self.assertFalse((Path(tmp)/'out').exists())

def actual(directory,target):
    B.verify(directory,target)
    with tempfile.TemporaryDirectory() as tmp:
        copy=Path(tmp)
        for name in B.names(target):shutil.copyfile(directory/name,copy/name)
        original=(copy/B.RECEIPT).read_bytes()
        def refuse():
            try:B.verify(copy,target)
            except ValueError:return
            raise AssertionError('changed actual DNSSEC package admitted')
        for field,value in (('abi',2),('target','linux/foreign'),('source_inputs',{})):
            receipt=json.loads(original);receipt[field]=value;(copy/B.RECEIPT).write_text(json.dumps(receipt));refuse();(copy/B.RECEIPT).write_bytes(original)
        for name in B.names(target)-{B.RECEIPT}:
            saved=(copy/name).read_bytes();(copy/name).write_bytes(saved+b'changed');refuse();(copy/name).write_bytes(saved)
        body=(copy/B.LIBRARY).read_bytes()
        for foreign in ('linux/arm64','linux/amd64'):
            if foreign!=target:
                try:B.elf_identity(body,foreign)
                except ValueError:pass
                else:raise AssertionError('foreign ELF target admitted')
    print('Actual DNSSEC flat package, source/payload refusals and foreign ELF rejection passed')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--bundle',type=Path);p.add_argument('--target',choices=B.TARGETS,default='linux/amd64');a=p.parse_args()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Wiring))
    if not result.wasSuccessful():raise SystemExit(1)
    if a.bundle:actual(a.bundle,a.target)
