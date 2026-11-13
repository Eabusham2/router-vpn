#!/usr/bin/env python3
"""Preserve every Android multihop gate across bounded jobs and their aggregate."""
from collections import Counter
from itertools import product
from pathlib import Path
import ast
import os
import re
import subprocess
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/android-multihop-contract.yml'
RUNTIME = WORKFLOW.parents[2] / 'android/test_android_runtime_contract.py'
ANDROID = tuple('python3 android/test_android_' + name + '.py' for name in (
    'multihop_contract', 'node_chain_capture', 'node_chain_execution_capture', 'node_candidates', 'ordered_presentation',
    'node_chain_runtime', 'node_candidate_preparation', 'node_chain_execution_runtime', 'node_chain_execution_restore', 'node_chain_mtu', 'multihop_modes', 'home_dns',
    'router_dns_retest', 'multihop_graph', 'pq_selection', 'max_selection',
    'naive_multihop',
))
EXPECTED = {
    'android': ANDROID + ('python3 deploy/test_android_multihop_workflow.py',),
    'shared_core': ('python3 deploy/test_mobile_multihop_groups.py --group core',),
    'shared_runtime': ('python3 deploy/test_mobile_multihop_groups.py --group runtime',),
    'relay': ('go test -race -count=1 -timeout=5m ./internal/multihoprelay ./internal/awgpolicy',),
}


def validate_runtime(source):
    loops = [node for node in ast.parse(source).body
             if isinstance(node, ast.For) and isinstance(node.target, ast.Name)
             and node.target.id == 'executable_contract']
    assert len(loops) == 1 and isinstance(loops[0].iter, ast.Tuple), 'Runtime gate loop missing'
    values = [node.value for node in loops[0].iter.elts if isinstance(node, ast.Constant)]
    assert len(values) == len(loops[0].iter.elts), 'Runtime gate inventory is not literal'
    assert values.count('test_android_node_chain_execution_capture.py') == 1, 'Runtime execution capture gate missing/duplicate'
    assert values.count('test_android_node_candidate_preparation.py') == 1, 'Runtime temporary preparation gate missing/duplicate'
    expected = ast.parse('subprocess.run([sys.executable, str(ROOT / executable_contract)], cwd=ROOT.parent, check=True)').body
    assert not loops[0].orelse and len(loops[0].body) == 1, 'Runtime gate can be conditionally skipped'
    assert ast.dump(loops[0].body[0]) == ast.dump(expected[0]), 'Runtime gate no longer executes its exact checked script'


def validate(source):
    # This intentionally checks this workflow's simple explicit jobs; introducing
    # matrix/conditional execution requires updating this executable contract.
    jobs_text = source.split('\njobs:\n', 1)[1]
    matches = list(re.finditer(r'^  ([a-z_]+):\n', jobs_text, re.M))
    jobs = {m[1]: jobs_text[m.end():matches[i + 1].start() if i + 1 < len(matches) else len(jobs_text)]
            for i, m in enumerate(matches)}
    assert len(matches) == 5 and set(jobs) == {*EXPECTED, 'contract'}, 'Missing/duplicate job'
    assert source.count("- 'deploy/test_android_multihop_workflow.py'") == 2, 'Audit trigger missing'
    for path in ('android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainExecutionCapture.java', 'android/test_android_node_chain_execution_capture.py', 'android/test_android_node_candidate_preparation.py', 'android/test_android_runtime_contract.py'):
        assert source.count("- '" + path + "'") == 2, 'Execution capture source/test trigger missing'
    for name, expected in EXPECTED.items():
        body = jobs[name]
        assert '    timeout-minutes: 15\n' in body, 'Job deadline changed'
        assert 'if:' not in body and 'continue-on-error:' not in body and 'strategy:' not in body, 'Gate can be skipped'
        assert "with: {go-version: '1.26.3', cache: false}" in body, 'Actual pinned Go toolchain missing'
        commands = []
        for line in body.splitlines():
            command = line.strip().removeprefix('run: ')
            if command.startswith(('python3 ', 'go test ')):
                commands.append(command)
        assert Counter(commands) == Counter(expected), 'Missing/duplicate/changed command in ' + name
    contract = jobs['contract']
    assert '    if: ${{ always() }}\n' in contract, 'Aggregate skips failed dependencies'
    assert '    needs: [android, shared_core, shared_runtime, relay]\n' in contract, 'Aggregate dependency missing'
    assert 'continue-on-error:' not in contract, 'Aggregate failure ignored'
    for name in EXPECTED:
        assert f'          {name.upper()}_RESULT: ${{{{ needs.{name}.result }}}}\n' in contract, 'Result binding changed'
    script = contract.split('        run: |\n', 1)[1]
    script = '\n'.join(line[10:] for line in script.splitlines() if line.strip())
    return script


class WorkflowContract(unittest.TestCase):
    def setUp(self):
        self.source = WORKFLOW.read_text()

    def test_complete_inventory(self):
        validate(self.source)

    def test_runtime_execution_capture_gate(self):
        validate_runtime(RUNTIME.read_text())

    def test_runtime_execution_capture_controls(self):
        source = RUNTIME.read_text()
        gate = '    "test_android_node_chain_execution_capture.py",'
        for old, new in ((gate, ''), (gate, gate + '\n' + gate),
                         ('    subprocess.run(\n', '    ignored.run(\n'),
                         ('        check=True,\n', '        check=False,\n')):
            with self.subTest(change=old):
                self.assertEqual(source.count(old), 1)
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(old, new, 1))

    def test_runtime_temporary_preparation_controls(self):
        source = RUNTIME.read_text()
        gate = '"test_android_node_candidate_preparation.py",'
        self.assertEqual(source.count(gate), 1)
        for replacement in ('', gate + gate):
            with self.subTest(replacement=replacement):
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement))

    def test_actual_aggregate_rejects_every_incomplete_result(self):
        script = validate(self.source)
        for results in product(('success', 'failure', 'cancelled', 'skipped'), repeat=4):
            with self.subTest(results=results):
                env = dict(os.environ, **{name.upper() + '_RESULT': result
                                         for name, result in zip(EXPECTED, results)})
                actual = subprocess.run(['bash', '-e', '-c', script], env=env, timeout=5)
                self.assertEqual(actual.returncode == 0, all(result == 'success' for result in results))

    def test_inventory_controls(self):
        changes = (
            (ANDROID[1], '# omitted'),
            (ANDROID[2], '# omitted execution capture'),
            ('python3 android/test_android_node_candidate_preparation.py', '# omitted temporary preparation'),
            ('python3 android/test_android_node_candidate_preparation.py', 'python3 android/test_android_node_chain_runtime.py'),
            ('python3 android/test_android_node_chain_execution_runtime.py', '# omitted execution runtime'),
            ('python3 android/test_android_node_chain_execution_restore.py', '# omitted execution restore'),
            ("- 'android/test_android_node_candidate_preparation.py'", "- 'android/omitted-preparation.py'"),
            ("- 'android/test_android_runtime_contract.py'", "- 'android/omitted-runtime.py'"),
            ("- 'android/test_android_node_chain_execution_capture.py'", "- 'android/omitted-execution.py'"),
            ("- 'android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainExecutionCapture.java'", "- 'android/omitted-execution.java'"),
            (ANDROID[1], ANDROID[0]),
            ('go test -race -count=1 -timeout=5m', 'go test -count=1 -timeout=5m'),
            ('timeout-minutes: 15', 'timeout-minutes: 30'),
            ('--group runtime', '--group core'),
            ('needs: [android, shared_core, shared_runtime, relay]', 'needs: [android, shared_core, relay]'),
            ('if: ${{ always() }}', 'if: ${{ success() }}'),
            ('  shared_core:\n', '  shared_core:\n    if: ${{ false }}\n'),
            ('SHARED_RUNTIME_RESULT: ${{ needs.shared_runtime.result }}', 'SHARED_RUNTIME_RESULT: success'),
        )
        for old, new in changes:
            with self.subTest(change=old):
                self.assertIn(old, self.source)
                with self.assertRaises(AssertionError):
                    validate(self.source.replace(old, new, 1))

    def test_aggregate_bypass_control(self):
        script = validate(self.source).replace('test "$SHARED_RUNTIME_RESULT" = success', 'true')
        env = dict(os.environ, ANDROID_RESULT='success', SHARED_CORE_RESULT='success', SHARED_RUNTIME_RESULT='failure', RELAY_RESULT='success')
        # Proves the negative result matrix above would detect a silently omitted check.
        self.assertEqual(subprocess.run(['bash', '-e', '-c', script], env=env, timeout=5).returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
