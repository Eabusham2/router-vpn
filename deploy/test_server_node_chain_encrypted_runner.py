#!/usr/bin/env python3
"""Causal tests of the encrypted Server gate; these are not native acceptance."""
from pathlib import Path
import importlib.util
import ast
import hashlib
import subprocess
import sys
import json
import re
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('server_encrypted_gate_test', ROOT/'deploy/test_server_node_chain_encrypted.py')
GATE = importlib.util.module_from_spec(spec); spec.loader.exec_module(GATE)


def sample(case='wg'):
    ready = case not in GATE.NEGATIVE
    receipt = dict(modes=list(GATE.MODES[case]), case=case, capture_sha256='a'*64, source_sha256='b'*64, prefixes=3 if case == 'mixed-three' else 2,
                   ready=ready, retired=True, selected_dns=ready, final_tcp=14 if ready else 0, final_udp=9 if ready else 0,
                   peer_joined=True, worker_joined=True)
    # Go's real nested output reports the parent PASS before buffered child
    # PASS. A receipt belongs to native work and must precede that parent.
    return '\n'.join(('=== RUN   '+GATE.NATIVE, '=== RUN   '+GATE.NATIVE+'/'+case,
        '    fixture_test.go:140: ENCRYPTED_SERVER_RECEIPT '+json.dumps(receipt),
        '--- PASS: '+GATE.NATIVE+' (1.20s)', '    --- PASS: '+GATE.NATIVE+'/'+case+' (1.20s)', 'PASS', ''))


def workflow(value):
    required = ('  workflow_call:\n', '  encrypted:\n', '    runs-on: ${{ matrix.runner }}',
        '          - arch: amd64\n            runner: ubuntu-24.04\n',
        '          - arch: arm64\n            runner: ubuntu-24.04-arm\n',
        '  group: server-node-chain-encrypted-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}',
        '  cancel-in-progress: true', '          persist-credentials: false', '          go-version: \'1.26.3\'',
        'python3 deploy/test_server_node_chain_encrypted_runner.py',
        'python3 deploy/test_server_node_chain_encrypted.py --standalone --require-commit "$ROUTERVPN_EXPECTED_SOURCE" --receipt "$ROUTERVPN_SERVER_RECEIPT"',
        '          if-no-files-found: error')
    if any(value.count(anchor) != 1 for anchor in required) or re.search(r'^\s*(?:if|continue-on-error|inputs):', value, re.M) or '--compile-only' in value or '|| true' in value:
        raise ValueError('Required native Server architecture/invocation was removed or made conditional')


class GateTests(unittest.TestCase):
    def test_actual_logger_io_copy_obeys_snapshot_mutex(self):
        template=(ROOT/GATE.TEMPLATE).read_text()
        begin=template.index('type serverChainEncryptedLog struct {')
        end=template.index('type serverChainEncryptedProcess struct {',begin)
        shipping=template[begin:end]
        harness=r'''package main
import("bytes";"io";"runtime";"strings";"sync";"testing")
SHIPPING
func TestNoPromotedReadFrom(t *testing.T){var log serverChainEncryptedLog;if _,ok:=any(&log).(io.ReaderFrom);ok{t.Fatal("logger exposes unguarded ReaderFrom")}}
func TestActualCopyAndSnapshot(t *testing.T){
 var log serverChainEncryptedLog;start:=make(chan struct{});done:=make(chan struct{})
 go func(){defer close(done);<-start;for i:=0;i<512;i++{if _,err:=io.Copy(&log,struct{io.Reader}{strings.NewReader(strings.Repeat("x",1024))});err!=nil{panic(err)};runtime.Gosched()}}()
 close(start);for i:=0;i<1000;i++{if len(log.text())>8192{t.Fatal("unbounded snapshot")};runtime.Gosched()};<-done
 if got:=log.text();len(got)!=8192||got!=strings.Repeat("x",8192){t.Fatal("original complete logger tail lost")}
}
'''
        with tempfile.TemporaryDirectory(prefix='server-actual-log-race-') as directory:
            root=Path(directory);(root/'go.mod').write_text('module routervpn-server-log-test\n\ngo 1.26\n')
            test=root/'log_test.go';test.write_text(harness.replace('SHIPPING',shipping))
            command=['go','test','-race','-count=1','-timeout=30s','.']
            result=subprocess.run(command,cwd=root,capture_output=True,text=True,timeout=45)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(shipping.count('buffer bytes.Buffer'),1)
            old=shipping.replace('buffer bytes.Buffer','bytes.Buffer',1).replace('b.buffer.','b.Buffer.')
            test.write_text(harness.replace('SHIPPING',old))
            failed=subprocess.run(command[:-1]+['-run=^TestActualCopyAndSnapshot$','.'],cwd=root,capture_output=True,text=True,timeout=45)
            self.assertNotEqual(failed.returncode,0,failed.stdout+failed.stderr)
            self.assertIn('WARNING: DATA RACE',failed.stdout+failed.stderr)

    def test_all_required_native_success_and_refusal_shapes(self):
        self.assertEqual(len(GATE.CASES), 14)
        for case in GATE.CASES:
            with self.subTest(case=case): self.assertEqual(GATE.check_verdict(sample(case), case)['case'], case)

    def test_missing_native_case_or_receipt_cannot_pass(self):
        text=sample()
        for before in ('=== RUN   '+GATE.NATIVE+'/wg\n', '    --- PASS: '+GATE.NATIVE+'/wg (1.20s)\n', 'PASS\n'):
            with self.subTest(before=before), self.assertRaises(ValueError): GATE.check_verdict(text.replace(before, '', 1), 'wg')
        with self.assertRaises(ValueError): GATE.check_verdict('\n'.join(line for line in text.splitlines() if 'ENCRYPTED_SERVER_RECEIPT' not in line), 'wg')

    def test_failed_skipped_raced_or_duplicate_is_never_native_success(self):
        for extra in ('--- FAIL: irrelevant (0.1s)\n', '--- SKIP: irrelevant (0.1s)\n', 'WARNING: DATA RACE\n', 'panic: owner\n', '=== RUN   '+GATE.NATIVE+'/wg\n', '--- PASS: '+GATE.NATIVE+'/wg (0.1s)\n'):
            with self.subTest(extra=extra), self.assertRaises(ValueError): GATE.check_verdict(sample()+extra, 'wg')

    def test_real_buffered_pass_order_allowed_but_late_work_receipt_rejected(self):
        text=sample();self.assertTrue(GATE.check_verdict(text, 'wg')['retired'])
        lines=text.splitlines();receipt=lines.pop(2);lines.insert(4,receipt)
        with self.assertRaises(ValueError): GATE.check_verdict('\n'.join(lines), 'wg')
        lines=text.splitlines();passed=lines.pop(3);lines.insert(1,passed)
        with self.assertRaises(ValueError): GATE.check_verdict('\n'.join(lines), 'wg')

    def test_exact_original_retirement_and_source_identity_required(self):
        for before,after in (('"retired": true','"retired": false'), ('"peer_joined": true','"peer_joined": false'),
             ('"worker_joined": true','"worker_joined": false'), ('"prefixes": 2','"prefixes": 1'),
             ('"ready": true','"ready": false'), ('"final_udp": 9','"final_udp": 0'),
             ('"selected_dns": true','"selected_dns": false'), ('"case": "wg"','"case": "awg-fast"'),
             ('"capture_sha256": "'+'a'*64+'"','"capture_sha256": "foreign"'),
             ('"ready": true','"ready": true, "ready": true'), ('"retired": true','"unexpected": true, "retired": true')):
            with self.subTest(before=before), self.assertRaises(ValueError): GATE.check_verdict(sample().replace(before,after,1), 'wg')

    def test_actual_awg_mode_cannot_be_relabelled_as_wireguard(self):
        text=sample('awg-fast')
        with self.assertRaisesRegex(ValueError, 'downgraded'):
            GATE.check_verdict(text.replace('"modes": ["wg", "awg2-fast"]','"modes": ["wg", "wg"]',1),'awg-fast')

    def test_source_inventory_is_separate_from_encrypted_receipts(self):
        lines=['=== RUN   '+GATE.SOURCE, '    fixture.go:1: ENCRYPTED_SERVER_CARRIER_CAPACITY 2092']
        for case in GATE.CASES: lines.append('=== RUN   '+GATE.SOURCE+'/'+case)
        lines.append('--- PASS: '+GATE.SOURCE+' (1.00s)')
        for case in GATE.CASES: lines.append('    --- PASS: '+GATE.SOURCE+'/'+case+' (0.01s)')
        lines.append('PASS');text='\n'.join(lines)
        self.assertEqual(GATE.check_verdict(text,None,source_only=True)['source_cases'],list(GATE.CASES))
        self.assertEqual(GATE.check_verdict(text,None,source_only=True)['carrier_mtu'],2092)
        for declaration in ('', 'ENCRYPTED_SERVER_CARRIER_CAPACITY 1279', 'ENCRYPTED_SERVER_CARRIER_CAPACITY 9001', 'ENCRYPTED_SERVER_CARRIER_CAPACITY 02092', 'ENCRYPTED_SERVER_CARRIER_CAPACITY 2092 junk', 'ENCRYPTED_SERVER_CARRIER_CAPACITY 2092\nENCRYPTED_SERVER_CARRIER_CAPACITY 2092'):
            with self.subTest(declaration=declaration), self.assertRaises(ValueError):
                GATE.check_verdict(text.replace('ENCRYPTED_SERVER_CARRIER_CAPACITY 2092',declaration),None,source_only=True)
        with self.assertRaises(ValueError): GATE.check_verdict(text,'wg')
        with self.assertRaises(ValueError): GATE.check_verdict(text.replace('=== RUN   '+GATE.SOURCE+'/awg-fast','=== RUN   foreign'),None,source_only=True)

    def test_changed_generated_or_linked_native_source_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            core=Path(temporary);target=core/GATE.TARGET;target.parent.mkdir(parents=True)
            with mock.patch.object(GATE.subprocess,'check_output',return_value=GATE.BUILD.PIN+'\n'):
                GATE.install_fixture(core);original=target.read_bytes();GATE.install_fixture(core)
                target.write_bytes(original+b'\n// unowned change\n')
                with self.assertRaisesRegex(ValueError,'generated fixture was changed'): GATE.install_fixture(core)
                target.unlink();target.symlink_to(ROOT/GATE.TEMPLATE)
                with self.assertRaisesRegex(ValueError,'linked owner'): GATE.install_fixture(core)

    def test_compiled_image_must_be_original_regular_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'image';path.write_bytes(b'not a fake acceptance; identity-only unit fixture');path.chmod(0o755)
            self.assertEqual(GATE.image_identity(path)[2],path.stat().st_size)
            linked=path.with_name('link');linked.symlink_to(path)
            with self.assertRaises(ValueError): GATE.image_identity(linked)
            path.chmod(0o777)
            with self.assertRaises(ValueError): GATE.image_identity(path)

    def test_namespace_projection_preserves_exact_functions_and_guards(self):
        path = ROOT/'deploy/test_server_node_chain_encrypted.py'
        original = path.read_bytes()
        program = GATE.namespace_program(hashlib.sha256(original).hexdigest())
        source = ast.parse(original)
        projected = ast.parse(program)
        names = ('image_identity', 'inside_namespace')
        actual = {node.name: node for node in source.body if isinstance(node, ast.FunctionDef) and node.name in names}
        transferred = {node.name: node for node in projected.body if isinstance(node, ast.FunctionDef)}
        self.assertEqual(set(transferred), set(names))
        for name in names:
            self.assertEqual(ast.dump(actual[name]), ast.dump(transferred[name]))
        imports = [ast.unparse(node) for node in projected.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertEqual(imports, ['from pathlib import Path', 'import hashlib', 'import os', 'import platform', 'import re', 'import stat', 'import subprocess', 'import sys'])
        namespace = {'__name__': 'projection_verification'}
        exec(compile(program, '<captured-native-namespace>', 'exec'), namespace)
        self.assertEqual(namespace['CASES'], GATE.CASES)
        self.assertEqual(namespace['NATIVE'], GATE.NATIVE)
        # This real interpreter test stops at the mandatory case/privilege
        # boundary before any native image, mount or network operation.
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-I', '-c', program, 'driver', 'peer', 'worker',
                                     'a'*64, 'b'*64, 'c'*64, 'foreign-case'], cwd=directory,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Encrypted Server needs its isolated native Linux root', result.stderr)
        self.assertNotIn('ENCRYPTED_SERVER_RECEIPT', result.stdout)

    def test_projected_valid_case_dispatches_exact_driver_and_joins_cleanup(self):
        original = (ROOT/'deploy/test_server_node_chain_encrypted.py').read_bytes()
        program = GATE.namespace_program(hashlib.sha256(original).hexdigest())
        with tempfile.TemporaryDirectory() as directory:
            images = {role: Path(directory)/role for role in ('driver', 'peer', 'worker')}
            for role, path in images.items():
                path.write_bytes(('identity-only regression image: '+role).encode())
                path.chmod(0o755)
            identities = {role: GATE.image_identity(path)[-1] for role, path in images.items()}
            declared = 2092  # Unit-boundary declaration; production derives this in native source inventory.
            def execute(projected, *, missing_dependency=False, carrier=None):
                namespace = {'__name__': 'projection_verification'}
                exec(compile(projected, '<captured-native-namespace>', 'exec'), namespace)
                # Execute the actual transferred function through valid image,
                # case and isolated-namespace guards. Only privileged process
                # effects are mocked; this is not native acceptance evidence.
                with mock.patch.object(namespace['platform'], 'system', return_value='Linux'), \
                     mock.patch.object(namespace['os'], 'geteuid', return_value=0), \
                     mock.patch.dict(namespace['os'].environ, {'ROUTERVPN_SERVER_CHAIN_OUTER_NETNS': '0:0', 'ROUTERVPN_SERVER_CHAIN_CARRIER_MTU':str(declared)}), \
                     mock.patch.object(namespace['subprocess'], 'run', return_value=subprocess.CompletedProcess([], 7)) as run, \
                     mock.patch.object(namespace['subprocess'], 'check_output', side_effect=carrier or [f'1: rvpn-test: mtu {declared} state UP',f'2: rvpn-peer: mtu {declared} state UP']) as read:
                    if missing_dependency:
                        with self.assertRaisesRegex(NameError, "name 're' is not defined"):
                            namespace['inside_namespace'](images['driver'], images['peer'], images['worker'], identities, 'wrong-first-key')
                    elif carrier:
                        with self.assertRaisesRegex(ValueError,'actual carrier differs'):
                            namespace['inside_namespace'](images['driver'], images['peer'], images['worker'], identities, 'wrong-first-key')
                        self.assertFalse(any(call.args[0][0]==str(images['driver']) for call in run.call_args_list))
                    else:
                        self.assertEqual(read.call_count,0)
                        self.assertEqual(namespace['inside_namespace'](images['driver'], images['peer'], images['worker'], identities, 'wrong-first-key'), 7)
                        calls = [call for call in run.call_args_list if call.args[0][0] == str(images['driver'])]
                        self.assertEqual(len(calls), 1)
                        self.assertEqual(read.call_count,2)
                        for name in ('rvpn-test','rvpn-peer'):
                            self.assertIn(mock.call(['ip','link','set',name,'mtu',str(declared)],check=True,timeout=5),run.call_args_list)
                        command = [str(images['driver']), '-test.run=^'+GATE.NATIVE+'$/^'+re.escape('wrong-first-key')+'$',
                                   '-test.v', '-test.count=1', '-test.timeout=90s']
                        self.assertEqual(calls[0].args, (command,))
                        self.assertEqual(calls[0].kwargs['timeout'], 105)
                        self.assertEqual(calls[0].kwargs['env']['ROUTERVPN_SERVER_CHAIN_PEER_SHA256'], identities['peer'])
                        self.assertEqual(calls[0].kwargs['env']['ROUTERVPN_SERVER_CHAIN_IMAGE_SHA256'], identities['worker'])
                    if not missing_dependency:
                        self.assertEqual(run.call_args, mock.call(['ip', 'netns', 'delete', 'rvpn-peer'], check=True, timeout=5))
            for invalid in ('', '1500junk', '01280', '1279', '9001'):
                namespace = {'__name__': 'projection_verification'}
                exec(compile(program, '<captured-native-namespace>', 'exec'), namespace)
                with mock.patch.object(namespace['platform'], 'system', return_value='Linux'), \
                     mock.patch.object(namespace['os'], 'geteuid', return_value=0), \
                     mock.patch.dict(namespace['os'].environ, {'ROUTERVPN_SERVER_CHAIN_OUTER_NETNS':'0:0', 'ROUTERVPN_SERVER_CHAIN_CARRIER_MTU':invalid}), \
                     mock.patch.object(namespace['subprocess'], 'run') as run:
                    with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError,'compiled carrier declaration'):
                        namespace['inside_namespace'](images['driver'], images['peer'], images['worker'], identities, 'wrong-first-key')
                    run.assert_not_called()
            execute(program)
            execute(program.replace('import re\n', '', 1), missing_dependency=True)
            execute(program,carrier=['1: rvpn-test: mtu 1500 state UP'])
            execute(program,carrier=[f'1: rvpn-test: mtu {declared} state UP','2: rvpn-peer: mtu 1500 state UP'])

    def test_namespace_projection_rejects_source_tamper_or_lost_inventory(self):
        path = ROOT/'deploy/test_server_node_chain_encrypted.py'
        original = path.read_bytes()
        captured = hashlib.sha256(original).hexdigest()
        with self.assertRaisesRegex(ValueError, 'source changed after capture'):
            GATE.namespace_program('0'*64)
        mutations = (
            original.replace(b'def inside_namespace(', b'def lost_inside_namespace(', 1),
            original + b'\ndef image_identity(path):\n    return None\n',
            original.replace(b"CASES = ('wg',", b"CASES = ('missing-wg',", 1),
        )
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory)/'source.py'
            for changed in mutations:
                copy.write_bytes(changed)
                with mock.patch.object(GATE, '__file__', str(copy)):
                    with self.assertRaisesRegex(ValueError, 'source changed after capture'):
                        GATE.namespace_program(captured)
                    with self.assertRaisesRegex(ValueError, 'required function|case inventory'):
                        GATE.namespace_program(hashlib.sha256(changed).hexdigest())

    def test_required_workflow_and_native_architectures(self):
        value=(ROOT/'.github/workflows/server-node-chain-encrypted.yml').read_text();workflow(value)
        for before,after in (('          - arch: arm64\n            runner: ubuntu-24.04-arm\n',''),
                            ('  workflow_call:\n','  workflow_call:\n    inputs: {}\n'),
                            ('  encrypted:\n','  encrypted:\n    if: false\n'),
                            ('    timeout-minutes: 60','    continue-on-error: true\n    timeout-minutes: 60'),
                            ('${{ github.run_id }}','shared'), ('--standalone --require-commit','--compile-only --require-commit')):
            with self.subTest(before=before), self.assertRaises(ValueError): workflow(value.replace(before,after,1))


if __name__=='__main__': unittest.main()
