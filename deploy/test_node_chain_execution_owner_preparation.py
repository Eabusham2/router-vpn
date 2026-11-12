#!/usr/bin/env python3
"""Check exact original native Box owner preparation before compiled tests."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('ordered_execution_owner', ROOT/'deploy/prepare-node-chain-execution-owner.py')
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
BOX = '''package box
type Box struct {
\trouterVPNNodeChainOptions string
\tpreserveOtherState string
}
func New(options Options) (*Box, error) {
\tchainOptionsDigest := routerVPNNodeChainOptionsDigest(options.Context, options.Options)
\tpreserveOriginalConstruction()
\treturn &Box{
\t\trouterVPNNodeChainOptions: chainOptionsDigest,
\t\tpreserveOtherState: "original",
\t}, nil
}
'''


class Preparation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.vendor = Path(self.temp.name)/'core'
        self.vendor.mkdir()
        (self.vendor/'box.go').write_text(BOX)
        (self.vendor/'go.mod').write_text('module github.com/sagernet/sing-box\n')

    def snapshot(self):
        return {p.relative_to(self.vendor).as_posix(): p.read_bytes() for p in self.vendor.rglob('*') if p.is_file()}

    def prepare(self, vendor=None, pin=None):
        with patch.object(PREP.subprocess, 'check_output', return_value=(pin or PREP.PIN)+'\n'), contextlib.redirect_stdout(io.StringIO()):
            PREP.prepare(vendor or self.vendor)

    def test_exact_idempotent_source_inventory(self):
        self.prepare()
        before = self.snapshot()
        self.prepare()
        self.assertEqual(self.snapshot(), before)
        self.assertIn('preserveOriginalConstruction()', (self.vendor/'box.go').read_text())
        manifest = json.loads((self.vendor/PREP.OWNER).read_text())
        self.assertEqual(set(manifest['files']), set(PREP.TEMPLATES.values()))
        for template, name in PREP.TEMPLATES.items():
            self.assertEqual((self.vendor/name).read_bytes(), (ROOT/'mobile/chain'/template).read_bytes())
            self.assertEqual(hashlib.sha256((self.vendor/name).read_bytes()).hexdigest(), manifest['files'][name])

    def test_snapshot_stays_after_original_local_capture(self):
        derived = PREP.box_source(BOX).decode()
        self.assertEqual(PREP.box_source(derived).decode(), derived)
        for before, after in (
            ('routerVPNNodeChainExecutionOptions string', 'routerVPNNodeChainExecutionOptions string\n\trouterVPNNodeChainExecutionOptions string'),
            ('options.Context, options.Options)\n\tpreserveOriginalConstruction', 'context.Background(), options.Options)\n\tpreserveOriginalConstruction'),
            ('\t\trouterVPNNodeChainExecutionOptions: chainExecutionOptionsDigest,', '\t\trouterVPNNodeChainExecutionOptions: "",'),
        ):
            with self.subTest(before=before), self.assertRaises(ValueError):
                PREP.box_source(derived.replace(before, after, 1))

    def test_partial_source_change_refuses_all_mutation(self):
        self.prepare()
        (self.vendor/'routervpn_node_chain_execution.go').write_text('foreign original owner\n')
        before = self.snapshot()
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.snapshot(), before)

    def test_incomplete_or_foreign_owner_refused(self):
        self.prepare()
        original = (self.vendor/PREP.OWNER).read_bytes()
        for fault in ('missing', 'foreign'):
            with self.subTest(fault=fault):
                record = json.loads(original)
                if fault == 'missing': record['files'].pop(next(iter(record['files'])))
                else: record['files']['unrelated.go'] = 'a'*64
                (self.vendor/PREP.OWNER).write_text(json.dumps(record))
                before = self.snapshot()
                with self.assertRaises(ValueError): self.prepare()
                self.assertEqual(self.snapshot(), before)

    def test_pin_and_module_are_required(self):
        before = self.snapshot()
        with self.assertRaises(ValueError): self.prepare(pin='0'*40)
        self.assertEqual(self.snapshot(), before)
        (self.vendor/'go.mod').write_text('module another/core\n')
        before = self.snapshot()
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.snapshot(), before)

    def test_unowned_output_refused(self):
        (self.vendor/'routervpn_node_chain_execution.go').write_text('unrelated original\n')
        before = self.snapshot()
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.snapshot(), before)

    def test_linked_checkout_and_output_refused(self):
        link = Path(self.temp.name)/'linked'
        link.symlink_to(self.vendor, target_is_directory=True)
        with self.assertRaises(ValueError): self.prepare(vendor=link)
        foreign = Path(self.temp.name)/'foreign.go'
        foreign.write_text('retained\n')
        (self.vendor/'routervpn_node_chain_execution.go').symlink_to(foreign)
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(foreign.read_text(), 'retained\n')


if __name__ == '__main__':
    unittest.main()
