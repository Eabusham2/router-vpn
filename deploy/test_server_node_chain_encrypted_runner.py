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
        lines=['=== RUN   '+GATE.SOURCE]
        for case in GATE.CASES: lines.append('=== RUN   '+GATE.SOURCE+'/'+case)
        lines.append('--- PASS: '+GATE.SOURCE+' (1.00s)')
        for case in GATE.CASES: lines.append('    --- PASS: '+GATE.SOURCE+'/'+case+' (0.01s)')
        lines.append('PASS');text='\n'.join(lines)
        self.assertEqual(GATE.check_verdict(text,None,source_only=True)['source_cases'],list(GATE.CASES))
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
        self.assertEqual(imports, ['from pathlib import Path', 'import hashlib', 'import os', 'import platform', 'import stat', 'import subprocess', 'import sys'])
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
