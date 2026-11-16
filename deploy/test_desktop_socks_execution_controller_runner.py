#!/usr/bin/env python3
"""Adversarial checks for the required typed SOCKS parent component gate."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('socks_parent',Path(__file__).with_name('test_desktop_socks_execution_controller.py'))
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def events(root, children):
    rows = [{'Action':'start','Package':G.PACKAGE},{'Action':'run','Package':G.PACKAGE,'Test':root}]
    for child in children:
        rows += [{'Action':action,'Package':G.PACKAGE,'Test':root+'/'+child} for action in ('run','pass')]
    rows += [{'Action':'pass','Package':G.PACKAGE,'Test':root},{'Action':'pass','Package':G.PACKAGE}]
    return rows


class SOCKSParentRunnerTests(unittest.TestCase):
    def test_complete_native_inventories_and_missing_records(self):
        for target, roots, records in (('linux/amd64',18,153),('windows/arm64',17,140),('darwin/arm64',13,132)):
            inventory = G.inventory(target)
            self.assertEqual((len(inventory),len(G.expected(inventory))),(roots,records))
            for root, children in inventory.items():
                rows = events(root,children)
                raw = '\n'.join(json.dumps(row) for row in rows)
                G.BUILDER.verify_imported_native_verdicts(raw,G.PACKAGE,G.expected({root:children}))
                for missing in G.expected({root:children}):
                    bad = '\n'.join(json.dumps(row) for row in rows if row.get('Test') != missing)
                    with self.subTest(target=target,missing=missing), self.assertRaises(ValueError):
                        G.BUILDER.verify_imported_native_verdicts(bad,G.PACKAGE,G.expected({root:children}))

    def test_foreign_duplicate_late_racing_failed_and_skipped_records(self):
        root, children = next(iter(G.CASES.items()))
        for fault in ('foreign','duplicate','late','race','failed','skip','no-start','duplicate-key'):
            rows = events(root,children)
            if fault=='foreign': rows[2]['Package']='foreign'
            elif fault=='duplicate': rows.insert(2,dict(rows[1]))
            elif fault=='late': rows.append(dict(rows[1]))
            elif fault=='race': rows.insert(-1,{'Action':'output','Package':G.PACKAGE,'Output':'WARNING: DATA RACE\n'})
            elif fault in ('failed','skip'): rows[3]['Action']='fail' if fault=='failed' else 'skip'
            elif fault=='no-start': rows.pop(0)
            raw = '\n'.join(json.dumps(row) for row in rows)
            if fault=='duplicate-key': raw=raw.replace('"Action": "start"','"Action":"run", "Action":"start"',1)
            with self.subTest(fault=fault),self.assertRaises(ValueError):
                G.BUILDER.verify_imported_native_verdicts(raw,G.PACKAGE,G.expected({root:children}))

    def exercise(self,target='linux/amd64',fault=None):
        calls=[]
        image=None
        def run(command,**options):
            nonlocal image
            calls.append(command)
            self.assertEqual(options['env'],{'CAPTURED':'original'})
            if command[1:3]==['test','-c']:
                self.assertEqual(options['timeout'],240)
                self.assertEqual(options['cwd'],G.ROOT)
                self.assertEqual('-race' in command,target!='windows/arm64')
                self.assertIn('-p=1',command)
                self.assertIn('-mod=readonly',command)
                image=Path(command[command.index('-o')+1])
                if fault!='compile': image.write_bytes(b'original native controller')
                return subprocess.CompletedProcess(command,1 if fault=='compile' else 0,'','')
            self.assertEqual(options['timeout'],135)
            self.assertEqual(options['cwd'],G.ROOT/'cmd/client')
            self.assertEqual(command[5],str(image))
            self.assertIn('-test.timeout=120s',command)
            self.assertIn('-test.count=1',command)
            root=command[-1].removeprefix('-test.run=^').removesuffix('$')
            children=G.inventory(target)[root]
            if fault=='timeout': raise subprocess.TimeoutExpired(command,135,output=b'original bounded stack\n')
            if fault=='image': image.write_bytes(b'changed image')
            rows=events(root,children)
            if fault=='missing': rows=[row for row in rows if row.get('Test') != root]
            return subprocess.CompletedProcess(command,1 if fault=='status' else 0,'\n'.join(json.dumps(row) for row in rows),'')
        identities=['original']*100
        if fault=='source': identities[1]='changed'
        with tempfile.TemporaryDirectory() as directory:
            receipt=Path(directory)/'receipt.json'
            output=io.StringIO()
            with patch.object(G,'native_environment',return_value=('/selected/go',{'CAPTURED':'original'},target)),patch.object(G,'source_identity',side_effect=identities),patch.object(G.subprocess,'run',side_effect=run),contextlib.redirect_stdout(output):
                if fault:
                    with self.assertRaises((ValueError,subprocess.TimeoutExpired)):
                        G.run(receipt=receipt,without_race=target=='windows/arm64')
                    self.assertFalse(receipt.exists())
                else:
                    result=G.run(receipt=receipt,without_race=target=='windows/arm64')
                    self.assertEqual(result,json.loads(receipt.read_text()))
                    self.assertEqual(len(result['records']),len(G.inventory(target)))
                    self.assertEqual(len(list(Path(directory).glob('*.jsonl'))),len(G.inventory(target)))
                    self.assertEqual(len({row['image_sha256'] for row in result['records']}),1)
            if fault=='timeout': self.assertIn('original bounded stack',output.getvalue())
        return calls

    def test_each_native_target_keeps_original_environment_image_and_bounds(self):
        for target in ('linux/amd64','linux/arm64','windows/amd64','windows/arm64','darwin/amd64','darwin/arm64'):
            with self.subTest(target=target): self.assertEqual(len(self.exercise(target)),len(G.inventory(target))+1)

    def test_failure_never_produces_completed_receipt(self):
        for fault in ('compile','source','image','status','missing','timeout'):
            with self.subTest(fault=fault): self.assertLessEqual(len(self.exercise(fault=fault)),2)

    def test_native_target_and_race_mode_cannot_be_borrowed(self):
        for target,without,environment in (('linux/amd64',True,{}),('windows/arm64',False,{}),('darwin/arm64',True,{}),('linux/amd64',False,{'GOOS':'windows'}),('darwin/amd64',False,{'GOARCH':'arm64'}),('freebsd/amd64',False,{})):
            with self.subTest(target=target,without=without),patch.object(G.shutil,'which',return_value='/selected/go'),patch.object(G.subprocess,'check_output',return_value='/selected'),patch.object(G.BUILDER,'native_host_target',return_value=target),patch.dict(G.os.environ,environment,clear=True),self.assertRaises(ValueError):
                G.native_environment('go',without)

    def test_controls_bind_exact_production_boundaries_and_original_test_witnesses(self):
        self.assertEqual(len(G.CONTROLS),2)
        for source,before,after,root,child,witness in G.CONTROLS:
            original=(G.ROOT/source).read_text()
            self.assertEqual(original.count(before),1)
            self.assertNotEqual(before,after)
            self.assertIn(root,G.inventory('linux/amd64'))
            self.assertIn(root+('/'+child if child else ''),G.expected(G.inventory('linux/amd64')))
            self.assertTrue(witness)


    def test_causal_witness_followed_by_abort_cannot_supply_expected_failure(self):
        root, case, witness = 'TestOriginal', 'TestOriginal/selected', 'original assertion failed'
        rows = [
            {'Action':'start','Package':G.PACKAGE},
            {'Action':'run','Package':G.PACKAGE,'Test':root},
            {'Action':'run','Package':G.PACKAGE,'Test':case},
            {'Action':'output','Package':G.PACKAGE,'Test':case,'Output':witness+'\n'},
            {'Action':'fail','Package':G.PACKAGE,'Test':case},
            {'Action':'fail','Package':G.PACKAGE,'Test':root},
            {'Action':'fail','Package':G.PACKAGE},
        ]
        raw = lambda value: '\n'.join(json.dumps(row) for row in value)
        G.verify_causal_result(subprocess.CompletedProcess([],1,raw(rows),''),root,case,witness)
        for diagnostic in ('panic: late close', 'fatal error: concurrent map writes', 'signal: killed',
                           'SIGSEGV: segmentation violation', 'panic: test timed out after 120s',
                           'FAIL router-vpn/cmd/client [build failed]', 'build aborted',
                           'compile: signal: killed', 'link: running clang failed', 'exit status 2',
                           'WARNING: DATA RACE'):
            # Keep the valid assertion and failed case, then append an abort
            # before the package failure. A nonzero result alone cannot pass.
            changed = rows[:-1]+[{'Action':'output','Package':G.PACKAGE,'Output':diagnostic+'\n'}]+rows[-1:]
            with self.subTest(diagnostic=diagnostic), self.assertRaises(ValueError):
                G.verify_causal_result(subprocess.CompletedProcess([],1,raw(changed),''),root,case,witness)
        for status, stderr in ((0,''),(2,''),(-9,''),(1,'signal: killed\n')):
            with self.subTest(status=status,stderr=stderr), self.assertRaises(ValueError):
                G.verify_causal_result(subprocess.CompletedProcess([],status,raw(rows),stderr),root,case,witness)



if __name__=='__main__':
    unittest.main()
