#!/usr/bin/env python3
"""Keep the real Vision race witness and all positive ownership cases required."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vision_state_gate', ROOT / 'deploy/test_xray_vision_state.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def events(names, failed=()):
    return '\n'.join(json.dumps({'Action': action, 'Test': name}) for name in sorted(names)
                     for action in ('run', 'fail' if name in failed else 'pass'))


class VisionStateContracts(unittest.TestCase):
    def test_all_six_real_parser_and_ownership_verdicts_are_required(self):
        self.assertEqual(len(gate.NAMES), 6)
        self.assertEqual(gate.NAMES - gate.CONTROL_NAMES, {
            'TestRouterVPNVisionReadIOReleasesParser', 'TestRouterVPNVisionWriteIOReleasesParser',
            'TestRouterVPNVisionFilterLoggingReleasesParser'})
        gate.SOCKS.require_verdicts(events(gate.NAMES), 0, gate.NAMES)
        for missing in gate.NAMES:
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                gate.SOCKS.require_verdicts(events(gate.NAMES - {missing}), 0, gate.NAMES)
        for action in ('fail', 'skip'):
            with self.assertRaises(ValueError):
                gate.SOCKS.require_verdicts(events(gate.NAMES).replace('"Action": "pass"', '"Action": "' + action + '"', 1), 0, gate.NAMES)

    def test_control_requires_the_original_race_not_an_unrelated_failure(self):
        diagnostic = ('WARNING: DATA RACE\n github.com/xtls/xray-core/proxy.(*VisionWriter).WriteMultiBuffer\n'
                      ' github.com/xtls/xray-core/proxy.XtlsFilterTls\n race detected during execution of test\n')
        def original(text=diagnostic):
            return events(gate.CONTROL_NAMES, {gate.DUPLEX, gate.DUPLEX + '/datagram'}) + '\n' + json.dumps({
                'Action': 'output', 'Test': gate.DUPLEX + '/datagram', 'Output': text})
        gate.require_original_race(original(), 1)
        for changed in ('link: signal: killed', 'context deadline exceeded', diagnostic.replace('VisionWriter', 'ForeignWriter'),
                        diagnostic.replace('XtlsFilterTls', 'ForeignFilter'), diagnostic.replace('WARNING: DATA RACE', ''),
                        diagnostic + 'panic: an unrelated failure'):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                gate.require_original_race(original(changed), 1)
        for changed in (events(gate.CONTROL_NAMES), original().replace('"Action": "fail"', '"Action": "skip"'),
                        original() + '\n' + json.dumps({'Action': 'pass', 'Test': gate.DUPLEX}),
                        original().replace(gate.DUPLEX + '/tls13', 'TestForeignFixture')):
            with self.assertRaises(ValueError):
                gate.require_original_race(changed, 1)
        with self.assertRaises(ValueError):
            gate.require_original_race(original(), 0)

    def test_original_overlay_binds_one_pinned_source_without_mutating_prepared_owner(self):
        original, prepared = b'original pinned source\n', b'complete prepared source\n'
        policy = types.SimpleNamespace(SOURCE='proxy/proxy.go', SOURCE_SHA256=hashlib.sha256(original).hexdigest(),
                                       patch_text=lambda path, text: prepared.decode())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);source = root/'xray';workspace = root/'owned-overlay'
            (source/'proxy').mkdir(parents=True);workspace.mkdir()
            target = source/policy.SOURCE;target.write_bytes(prepared)
            with mock.patch.object(gate, 'POLICY', policy), mock.patch.object(gate.subprocess, 'check_output', return_value=original) as read:
                overlay, records = gate.original_overlay(source, workspace)
                read.assert_called_once_with(['git','-C',str(source),'show',gate.SOCKS.XRAY.XRAY_PIN+':proxy/proxy.go'])
                self.assertEqual(json.loads(overlay.read_text()), {'Replace':{str(target):str(workspace/'original-proxy.go')}})
                self.assertEqual((workspace/'original-proxy.go').read_bytes(), original)
                self.assertEqual(target.read_bytes(), prepared)
                self.assertEqual(len(records), 2)
                target.write_bytes(prepared+b'partial change')
                with self.assertRaises(ValueError):gate.original_overlay(source, workspace)
            target.write_bytes(prepared)
            with mock.patch.object(gate, 'POLICY', policy), mock.patch.object(gate.subprocess, 'check_output', return_value=original+b'foreign'):
                with self.assertRaises(ValueError):gate.original_overlay(source, workspace)

    def test_native_images_keep_race_and_original_process_bounds(self):
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            def compile(command, cwd, env, timeout):
                calls.append((command, cwd, env, timeout))
                Path(command[command.index('-o')+1]).write_bytes(b'original image')
                return 0, ''
            with mock.patch.object(gate.SOCKS, 'run_command', side_effect=compile):
                image, digest = gate.compile_image('owned-go',Path('owned-source'),workspace,{'GOOS':'linux'},overlay=Path('owned-overlay'))
            self.assertEqual(calls[0][0][:6], ['owned-go','test','-mod=readonly','-race','-c','-ldflags=-checklinkname=0'])
            self.assertIn('-overlay=owned-overlay',calls[0][0])
            self.assertEqual(calls[0][0][-1], './proxy')
            self.assertEqual(calls[0][-1], 600)
            raw = json.dumps({'Action':'output','Test':gate.DUPLEX,'Output':'original failure details\n'})+'\n'
            with mock.patch.object(gate.SOCKS,'run_command',return_value=(1,raw)) as run, mock.patch('builtins.print') as output:
                self.assertEqual(gate.execute_image('owned-go',Path('owned-source'),{},image,digest,gate.PATTERN),(1,raw))
                self.assertEqual(run.call_args.args[0][-3:], ['-test.run='+gate.PATTERN,'-test.count=1','-test.timeout=30s'])
                self.assertEqual(run.call_args.args[-1],45)
                output.assert_called_once_with(raw,end='',flush=True)
            image.write_bytes(b'foreign image')
            with mock.patch.object(gate.SOCKS,'run_command') as run, self.assertRaises(ValueError):
                gate.execute_image('owned-go',Path('owned-source'),{},image,digest,gate.PATTERN)
            run.assert_not_called()

    def test_mandatory_dns_gate_executes_and_retains_parser_receipt(self):
        path=ROOT/'deploy/test_native_xray_udp443.py'
        tree=ast.parse(path.read_text())
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='run')
        selected=[node for node in function.body if isinstance(node,ast.Assign) and isinstance(node.value,ast.Call) and
                  isinstance(node.value.func,ast.Attribute) and isinstance(node.value.func.value,ast.Name) and
                  node.value.func.value.id=='VISION' and node.value.func.attr=='run']
        self.assertEqual(len(selected),1)
        stage=ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(selected[0])],type_ignores=[]))
        result={};native=mock.Mock(return_value={'verdicts':sorted(gate.NAMES),'causal_data_race':True})
        exec(compile(stage,str(path),'exec'),dict(receipt=result,VISION=types.SimpleNamespace(run=native),
             resolved=(Path('owned-prepared-xray'),{'captured':'digest'}),compiler='owned-go',env={'CAPTURED_ENV':'1'}))
        native.assert_called_once_with(Path('owned-prepared-xray'),'owned-go',{'CAPTURED_ENV':'1'})
        self.assertEqual(result['vision_parser']['verdicts'],sorted(gate.NAMES))
        udp=gate.SOCKS.module('vision_state_udp_caller','test_native_xray_udp443.py')
        sources=set(udp.inputs())
        for name in ('deploy/xray_vision_policy.py','deploy/test_xray_vision_state.py','deploy/test_xray_vision_state_runner.py',
                     'mobile/applexray/vision_state_test.go.tmpl'):
            self.assertIn(ROOT/name,sources)
        builder=ast.parse((ROOT/'deploy/build-native-runtime.py').read_text())
        inputs=next(node for node in builder.body if isinstance(node,ast.FunctionDef) and node.name=='inputs')
        literals={node.value for node in ast.walk(inputs) if isinstance(node,ast.Constant) and isinstance(node.value,str)}
        self.assertIn('deploy/test_xray_vision_state.py',literals)
        self.assertIn('deploy/test_xray_vision_state_runner.py',literals)


if __name__ == '__main__':
    unittest.main()
