#!/usr/bin/env python3
"""Keep every captured native UDP443 case and its real shipping caller required."""
import ast
import copy
import fnmatch
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_udp443_gate', ROOT / 'deploy/test_native_xray_udp443.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class NativeUDP443Contracts(unittest.TestCase):
    def events(self, names):
        return '\n'.join(json.dumps({'Action': action, 'Test': name}) for name in sorted(names) for action in ('run', 'pass'))

    def test_every_native_and_shared_verdict_is_required(self):
        shared = gate.SOCKS.IMPORTED.names(gate.SHARED)
        native = gate.SOCKS.IMPORTED.names(gate.NATIVE)
        self.assertEqual(len(shared), 19)
        self.assertEqual(len(native), 37)
        self.assertIn('TestNativeXrayUDP443DoTProbeAdmission', native)
        self.assertEqual(len(gate.CASES), 16)
        self.assertEqual(set(gate.CASES), {'home-udp53', 'dot853', 'doh443', 'doh3-udp443', 'plain-vision-udp443',
            'wrong-dns-sni', 'wrong-dns-trust', 'wrong-dns-route', 'wrong-dns-port', 'wrong-dns-path',
            'wrong-reality-key', 'wrong-owner', 'cancel-before-query', 'cancel-inflight', 'close-owner', 'replacement-owner'})
        self.assertEqual(gate.MODES, ('reality-vision', 'reality-pq-vision'))
        for names in (shared, native):
            gate.SOCKS.require_verdicts(self.events(names), 0, names)
            for missing in names:
                with self.subTest(missing=missing), self.assertRaises(ValueError):
                    gate.SOCKS.require_verdicts(self.events(names - {missing}), 0, names)
            for action in ('skip', 'fail'):
                with self.assertRaises(ValueError):
                    gate.SOCKS.require_verdicts(self.events(names).replace('"Action": "pass"', '"Action": "' + action + '"', 1), 0, names)
            for extra in ('TestUncapturedDNS', next(iter(names))):
                with self.assertRaises(ValueError):
                    gate.SOCKS.require_verdicts(self.events(names) + '\n' + json.dumps({'Action': 'pass', 'Test': extra}), 0, names)
            with self.assertRaises(ValueError):
                gate.SOCKS.require_verdicts(self.events(names), 1, names)

    def test_actual_generation_inventory_cannot_be_omitted_or_skipped(self):
        def output(names, verdict='ok'):
            return '\n'.join(name+' (__main__.VisionGeneration.'+name+') ... '+verdict for name in names)
        self.assertEqual(len(gate.GENERATION_CASES), 13)
        expected = sorted(gate.GENERATION_CASES)
        self.assertEqual(gate.require_generation(output(expected),0), expected)
        for missing in expected:
            with self.assertRaises(ValueError):
                gate.require_generation(output([name for name in expected if name != missing]),0)
        for extra in ('test_foreign_generation',expected[0]):
            with self.assertRaises(ValueError):gate.require_generation(output(expected+[extra]),0)
        for verdict in ('skipped', 'FAIL', 'ERROR'):
            with self.assertRaises(ValueError):gate.require_generation(output(expected,verdict),0)
        with self.assertRaises(ValueError):gate.require_generation(output(expected),1)
        with mock.patch.object(gate.SOCKS,'run_command',return_value=(0,output(expected))) as run, mock.patch('builtins.print'):
            self.assertEqual(gate.generation({'CAPTURED_ENV':'1'}),expected)
            run.assert_called_once_with([sys.executable,ROOT/'deploy/test_xray_udp443_generation.py','-v'],ROOT,{'CAPTURED_ENV':'1'},300)

    def test_generation_and_preparation_are_in_the_source_receipt(self):
        sources = set(gate.inputs())
        for name in ('server/scripts/create-bundle-json.py', 'server/scripts/ensure-node-proof.py',
                     'server/scripts/atomic-private-batch.py', 'server/scripts/atomic-private-write.py',
                     'server/scripts/private-directory.py', 'server/scripts/verified-regular-read.py',
                     'server/scripts/ss_service_capability.py', 'configs/client/modes.json',
                     'configs/client/logical-modes.json'):
            self.assertIn(ROOT / name, sources)
        for name in (*gate.GENERATION, *gate.COPIES, 'deploy/prepare-apple-xray.py',
                     'deploy/build-native-runtime.py', 'deploy/test_native_xray_udp443_runner.py',
                     '.github/workflows/imported-socks-reality-native.yml'):
            self.assertIn(ROOT / name, sources)
        preparer = ast.parse((ROOT / 'deploy/prepare-apple-xray.py').read_text())
        tuples = [tuple(item.value for item in node.elts) for node in ast.walk(preparer)
                  if isinstance(node, ast.Tuple) and all(isinstance(item, ast.Constant) for item in node.elts)]
        self.assertIn(('udp443_traffic_test.go.tmpl', 'udp443_traffic_test.go'), tuples)
        self.assertEqual((ROOT / 'mobile/applexray/udp443_traffic_test.go.tmpl').read_text().splitlines()[0],
                         '//go:build routervpn_udp443_integration')

    def test_every_generation_input_schedules_the_mandatory_reference_workflow(self):
        workflow = (ROOT / '.github/workflows/imported-socks-reality-native.yml').read_text()
        paths = workflow.split('    paths:\n', 1)[1].split('\npermissions:', 1)[0]
        patterns = [ast.literal_eval(line.strip()[2:]) for line in paths.splitlines()
                    if line.strip().startswith('- ')]
        self.assertTrue(patterns)
        for source in gate.GENERATION:
            with self.subTest(source=source):
                self.assertTrue(any(fnmatch.fnmatchcase(source, pattern) for pattern in patterns),
                                'Original generation dependency does not schedule the required native gate: ' + source)

    def test_native_compile_uses_the_explicit_reference_tag_and_race_gate(self):
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            def compile(command, cwd, env, timeout):
                calls.append((command, cwd, env, timeout))
                Path(command[command.index('-o')+1]).write_bytes(b'owned native image')
                return 0, ''
            with mock.patch.object(gate.SOCKS, 'run_command', side_effect=compile):
                image, digest = gate.compile_image('captured-go', Path('captured-core'), workspace, {'GOOS':'linux'})
            self.assertEqual(image, workspace/'udp443-native')
            self.assertEqual(len(digest), 64)
        command, cwd, env, timeout = calls[0]
        self.assertEqual(command[:6], ['captured-go','test','-mod=readonly','-race','-c','-ldflags=-checklinkname=0'])
        self.assertEqual(command[command.index('-tags')+1], gate.SOCKS.TAGS+',routervpn_udp443_integration')
        self.assertEqual(command[-1], './protocol/routervpnxray')
        self.assertEqual(timeout, 600)

    def test_native_failure_keeps_original_case_events_before_rejecting_verdicts(self):
        with tempfile.TemporaryDirectory() as temporary:
            image=Path(temporary)/'native';image.write_bytes(b'original native owner')
            digest=gate.hashlib.sha256(image.read_bytes()).hexdigest()
            original=json.dumps({'Action':'output','Test':gate.PARENT+'/reality-vision/wrong-dns-sni',
                                 'Output':'original typed TLS diagnostic\n'})+'\n'
            with mock.patch.object(gate.SOCKS,'run_command',return_value=(1,original)) as run, mock.patch('builtins.print') as output:
                with self.assertRaises(ValueError):
                    gate.execute_native('captured-go',Path('captured-core'),{'CAPTURED_ENV':'1'},image,digest,gate.PARENT,{gate.PARENT})
                output.assert_called_once_with(original,end='',flush=True)
                run.assert_called_once_with(['captured-go','tool','test2json','-t','-p','routervpnxray',image,
                    '-test.v','-test.run=^'+gate.PARENT+'$','-test.count=1','-test.timeout=90s'],
                    Path('captured-core'),{'CAPTURED_ENV':'1'},105)
            with mock.patch.object(gate.SOCKS,'run_command') as run:
                image.write_bytes(b'foreign native owner')
                with self.assertRaises(ValueError):
                    gate.execute_native('captured-go',Path('captured-core'),{},image,digest,gate.PARENT,{gate.PARENT})
                run.assert_not_called()

    def test_missing_or_changed_native_template_cannot_use_an_old_receipt(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(gate.SOCKS, 'checked_sources', return_value={}):
            core = Path(temporary)
            for source, target in gate.COPIES.items():
                path = core/target;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes((ROOT/source).read_bytes())
            self.assertEqual(len(gate.checked_sources(core)), 4)
            for source,target in gate.COPIES.items():
                path = core/target;original=path.read_bytes();path.write_bytes(original+b'\nchanged\n')
                with self.assertRaises(ValueError):gate.checked_sources(core)
                path.unlink()
                with self.assertRaises((ValueError,FileNotFoundError)):gate.checked_sources(core)
                path.write_bytes(original)

    def test_actual_release_builder_retains_old_gates_and_adds_separate_dns_gate(self):
        contracts = gate.module('udp443_original_reference_contract', 'test_mobile_imported_socks_xray_runner.py')
        path, selected, tree = contracts.ScopedSOCKSRealitySourceContext().native_stage()
        stage=ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(selected)],type_ignores=[]))
        names=('test_mobile_imported_socks_xray.py','test_mobile_imported_proxy_xray.py','test_native_xray_udp443.py')
        for target in ('linux/amd64','linux/arm64','windows/amd64','darwin/arm64'):
            calls=[]
            def capture(command,**options):calls.append(([str(part)for part in command],options))
            exec(compile(stage,str(path),'exec'),dict(ROOT=ROOT,sys=sys,target=target,source=Path('captured-core'),pq=Path('captured-pq'),cache=None,env={'CAPTURED_ENV':'1'},run=capture))
            relevant=[(Path(command[1]).name,command,options)for command,options in calls if len(command)>1 and Path(command[1]).name in names]
            self.assertEqual(tuple(name for name,_,_ in relevant),names if target.startswith('linux/')else())
            for _,_,options in relevant:self.assertEqual(options,{'env':{'CAPTURED_ENV':'1'},'timeout':3000})
        inputs=next(node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name=='inputs')
        literals={node.value for node in ast.walk(inputs)if isinstance(node,ast.Constant)and isinstance(node.value,str)}
        self.assertIn('deploy/test_native_xray_udp443.py',literals)
        self.assertIn('deploy/test_native_xray_udp443_runner.py',literals)


if __name__ == '__main__':
    unittest.main()
