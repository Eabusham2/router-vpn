#!/usr/bin/env python3
"""Require every original imported-trio controller root and captured image."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('imported_controller', Path(__file__).with_name('test_desktop_imported_trio_controller.py'))
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)

def events(root):
    names = G.expected(root)
    rows = [{'Action':'start', 'Package':G.PACKAGE}]
    def emit(name):
        rows.append({'Action':'run', 'Package':G.PACKAGE, 'Test':name})
        for child in sorted(names):
            if child.startswith(name+'/') and not any(child.startswith(parent+'/') for parent in names if parent != name and parent.startswith(name+'/')):
                emit(child)
        rows.append({'Action':'pass', 'Package':G.PACKAGE, 'Test':name})
    emit(G.PREFIX+root)
    rows.append({'Action':'pass', 'Package':G.PACKAGE})
    return rows

def raw(root):
    return '\n'.join(json.dumps(row) for row in events(root))+'\n'

class ControllerGateTests(unittest.TestCase):
    def test_six_original_whole_roots_and_every_nested_case(self):
        self.assertEqual(tuple(G.CASES), ('OriginalPreparation', 'SelectionAndSourceRefusals', 'PublicConnectUsesOriginalChild',
                                        'RestoreRetainsChosenSource', 'RefusesMissingOrForeignNativeMiddle', 'SavedProfileRetainsSource'))
        self.assertEqual([len(G.expected(root)) for root in G.CASES], [13,31,4,3,3,3])
        self.assertEqual(len(G.expected()),57)
        for root in G.CASES:
            G.BUILDER.verify_imported_native_verdicts(raw(root),G.PACKAGE,G.expected(root))
            for missing in G.expected(root):
                damaged='\n'.join(json.dumps(row) for row in events(root) if row.get('Test') != missing)
                with self.subTest(root=root,missing=missing),self.assertRaises(ValueError):
                    G.BUILDER.verify_imported_native_verdicts(damaged,G.PACKAGE,G.expected(root))

    def test_actual_parser_refuses_foreign_late_duplicate_raced_or_failed_records(self):
        root=next(iter(G.CASES))
        for fault in ('foreign','late','duplicate','race','failed','skip','start','duplicate-key'):
            rows=events(root)
            if fault=='foreign':rows[2]['Package']='foreign'
            elif fault=='late':rows.append({'Action':'run','Package':G.PACKAGE,'Test':G.PREFIX+root})
            elif fault=='duplicate':rows.insert(2,dict(rows[1]))
            elif fault=='race':rows.append({'Action':'output','Package':G.PACKAGE,'Output':'WARNING: DATA RACE\n'})
            elif fault in ('failed','skip'):rows[2]['Action']='fail' if fault=='failed' else 'skip'
            elif fault=='start':rows.pop(0)
            output='\n'.join(json.dumps(row) for row in rows)
            if fault=='duplicate-key':output=output.replace('"Action": "start"','"Action": "run", "Action": "start"',1)
            with self.subTest(fault=fault),self.assertRaises(ValueError):G.BUILDER.verify_imported_native_verdicts(output,G.PACKAGE,G.expected(root))

    def exercise(self,target='linux/amd64',fault=None):
        calls=[];binary=None
        def run(command,**options):
            nonlocal binary
            calls.append((command,options))
            if command[1:3]==['test','-c']:
                self.assertEqual(options['timeout'],240)
                self.assertEqual(options['cwd'],G.ROOT)
                self.assertEqual(options['env'],{'CAPTURED':'original'})
                self.assertEqual('-race' in command,target!='windows/arm64')
                self.assertEqual(command[-1],'./cmd/client')
                if fault=='compile':raise subprocess.CalledProcessError(1,command)
                binary=Path(command[command.index('-o')+1]);binary.write_bytes(b'original compiled controller')
                return subprocess.CompletedProcess(command,0)
            self.assertEqual(options['timeout'],135)
            self.assertEqual(options['cwd'],G.ROOT/'cmd/client')
            self.assertEqual(options['env'],{'CAPTURED':'original'})
            self.assertEqual(command[5],str(binary))
            self.assertIn('-test.timeout=120s',command)
            self.assertIn('-test.count=1',command)
            root=command[-1].removeprefix('-test.run=^'+G.PREFIX).removesuffix('$')
            self.assertIn(root,G.CASES)
            if fault=='timeout':raise subprocess.TimeoutExpired(command,135)
            if fault=='image':binary.write_bytes(b'foreign controller')
            output=raw(root)
            if fault=='missing':output='\n'.join(line for line in output.splitlines() if json.loads(line).get('Test')!=G.PREFIX+root)
            return subprocess.CompletedProcess(command,1 if fault=='status' else 0,output,'')
        identities=['original']*20
        if fault=='compile-source':identities[1]='changed'
        if fault=='run-source':identities[2]='changed'
        with tempfile.TemporaryDirectory(prefix='controller-gate-receipt-') as directory:
            receipt=Path(directory)/'receipt.json'
            with patch.object(G,'native_environment',return_value=('/selected/go',{'CAPTURED':'original'},target)),patch.object(G,'source_identity',side_effect=identities),patch.object(G.subprocess,'run',side_effect=run),contextlib.redirect_stdout(io.StringIO()):
                if fault:
                    with self.assertRaises((ValueError,subprocess.CalledProcessError,subprocess.TimeoutExpired)):G.run(receipt=receipt,without_race=target=='windows/arm64')
                    self.assertFalse(receipt.exists())
                else:
                    result=G.run(receipt=receipt,without_race=target=='windows/arm64')
                    self.assertEqual(result['tests'],57)
                    self.assertEqual(len(result['roots']),6)
                    self.assertEqual(result,json.loads(receipt.read_text()))
                    self.assertEqual(len(list(Path(directory).glob('*.jsonl'))),6)
                    self.assertEqual(len({row['image_sha256'] for row in result['roots']}),1)
        return calls

    def test_all_native_targets_keep_original_compiler_environment_image_and_per_root_bounds(self):
        for target in ('linux/amd64','linux/arm64','windows/amd64','windows/arm64'):
            with self.subTest(target=target):self.assertEqual(len(self.exercise(target)),7)

    def test_failed_compile_source_image_or_verdict_stops_before_later_roots(self):
        for fault in ('compile','compile-source','run-source','image','status','missing','timeout'):
            with self.subTest(fault=fault):self.assertLessEqual(len(self.exercise(fault=fault)),2)

    def test_native_host_and_race_mode_cannot_be_borrowed(self):
        for host,race,env in (('darwin/arm64',False,{}),('linux/amd64',True,{}),('windows/arm64',False,{}),('linux/amd64',False,{'GOOS':'windows'}),('windows/amd64',False,{'GOARCH':'arm64'})):
            with self.subTest(host=host,race=race,env=env),patch.object(G.shutil,'which',return_value='/selected/go'),patch.object(G.subprocess,'check_output',return_value='/selected'),patch.object(G.BUILDER,'native_host_target',return_value=host),patch.dict(G.os.environ,env,clear=True),self.assertRaises(ValueError):G.native_environment('go',race)

if __name__=='__main__':
    unittest.main()
