#!/usr/bin/env python3
"""Verify the native Xray workflow dispatches every shared phase before native parsing."""
from collections import Counter
from fnmatch import fnmatchcase
import json
from pathlib import Path
import re
import subprocess
import textwrap
import unittest

import test_mobile_multihop_groups as shared

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/native-xray-exits.yml'
DISPATCHER = 'python3 deploy/test_mobile_multihop_groups.py'
SHARDS = (
    ('shared-core', 'shard', 'CORE_SHARD', '--group core --core-shard "$CORE_SHARD"'),
    ('shared-groups', 'group', 'SHARED_GROUP', '--group "$SHARED_GROUP"'),
)


def job(source, name):
    matches = re.findall(r'(?ms)^  '+re.escape(name)+r':\n(.*?)(?=^  [\w-]+:\n|\Z)', source)
    if len(matches) != 1:
        raise ValueError('Expected exactly one workflow job: '+name)
    return matches[0].rstrip()


def shared_plan(source, groups):
    """Expand the bound matrix values through the same partition used by the real CLI."""
    if source.count(DISPATCHER) != len(SHARDS):
        raise ValueError('Unexpected shared dispatcher outside the two matrix steps')
    selected = []
    for name, axis, variable, selector in SHARDS:
        body = job(source, name)
        # The complete job shape prevents conditional rows, skipped steps, matrix
        # exclusions and ignored exit codes from appearing to cover a selector.
        template = f"""    runs-on: ubuntu-24.04
    timeout-minutes: 45
    strategy:
      fail-fast: false
      matrix:
        {axis}: MATRIX_VALUES
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.26.3'
      - name: Run the shared multihop tests
        env:
          {variable}: ${{{{ matrix.{axis} }}}}
        run: {DISPATCHER} {selector}"""
        match = re.fullmatch(re.escape(template).replace('MATRIX_VALUES', r'(\[[^\n]+\])'), body)
        if not match:
            raise ValueError('Shared workflow lost the bound matrix command: '+name)
        command = body.rsplit('        run: ', 1)[1]
        # Capture the argv delivered by the workflow's own shell command.
        capture = 'python3() { printf "%s\\0" "$@"; }\n' + command
        for value in json.loads(match[1]):
            run = subprocess.run(['bash', '-eu', '-c', capture], env={variable:str(value)},
                                 capture_output=True, check=True, timeout=5)
            args = run.stdout.decode().split('\0')[:-1]
            if args[:2] != ['deploy/test_mobile_multihop_groups.py', '--group']:
                raise ValueError('Shared job invoked the wrong dispatcher')
            if len(args) == 5 and args[2:4] == ['core', '--core-shard'] and type(value) is int:
                selected.extend(shared.core_shard(shared.select_ci_group(groups, 'core'), int(args[4])))
            elif len(args) == 3 and args[2] != 'core':
                selected.extend(shared.select_ci_group(groups, args[2]))
            else:
                raise ValueError('Shared job did not dispatch an exact shard or group')
    if Counter(label for label, _ in selected) != Counter(label for label, _ in groups):
        raise ValueError('Matrix omitted or duplicated a shared logical phase')
    shared.validate_partition([name for _, names in groups for name in names], selected)
    return selected


def parser_guard(source):
    body = job(source, 'android-and-native-parser')
    header, marker, after = body.partition('        run: |\n')
    required = """    needs: [apple-graphs, shared-core, shared-groups]
    if: always()
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    steps:
      - name: Require the Apple fixtures and every shared shard
        env:
          APPLE_RESULT: ${{ needs.apple-graphs.result }}
          CORE_RESULT: ${{ needs.shared-core.result }}
          GROUP_RESULT: ${{ needs.shared-groups.result }}
"""
    script, boundary, later = after.partition('      - uses: actions/checkout@v4\n')
    check = '      - name: Verify complete shared test coverage\n        run: python3 deploy/test_native_xray_shared_workflow.py\n'
    if (not marker or header != required or not boundary or not later.startswith(check)
            or re.search(r'(?m)^\s+(?:- )?(?:if|continue-on-error):', later)):
        raise ValueError('Native parser must require every original job result before building')
    return textwrap.dedent(script)


def declared_groups():
    # The hosted dispatcher discovers executable roots with go test -list.
    # Audit the selectors here against the actual roots declared in this checkout.
    names = [name for path in (ROOT/'internal/mobilemultihop').glob('*_test.go')
             for name in re.findall(r'^func ((?:Test|Example|Fuzz)\w*)\(', path.read_text(), re.M)]
    return shared.partition(shared.inventory('\n'.join(names)))


def check_source_triggers(source):
    push = re.search(r"(?m)^  push:\n    branches: \[main\]\n    paths:\n((?:      - '[^'\n]+'\n)+)", source)
    if not push:
        raise ValueError('Missing main push triggers')
    patterns = re.findall(r"      - '([^'\n]+)'", push[1])
    for path in ('.github/workflows/native-xray-exits.yml', 'internal/hopmeasure/ordered.go',
                 'internal/mobilemultihop/node_chain_selected_private_stream_test.go',
                 'deploy/test_mobile_multihop_groups.py', 'deploy/test_focused_multihop_clocks.py',
                 'deploy/test_native_xray_shared_workflow.py', 'deploy/test_desktop_node_chain_ss_prefix_contract_runner.py'):
        if not any(fnmatchcase(path, pattern) for pattern in patterns):
            raise ValueError('Missing shared workflow source trigger: '+path)


class NativeXraySharedWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text()
        cls.groups = declared_groups()

    def test_exact_shared_roots_and_imported_prefix(self):
        selected = shared_plan(self.source, self.groups)
        self.assertEqual(sorted(selected), sorted(self.groups))
        self.assertIn((shared.PREFIX_PHASE, [shared.PREFIX_ROOT]), selected)
        self.assertIn((shared.SELECTED_DEPTH_PHASE, [shared.SELECTED_DEPTH_ROOT]), selected)
        remaining = 'controller, proof and remaining ownership'
        self.assertEqual(shared.select_ci_group(self.groups, 'runtime_remaining'),
                         [(remaining, dict(self.groups)[remaining])])
        print(f'Native Xray matrix covers {len(selected)} phases and {sum(len(roots) for _, roots in selected)} declared roots')

    def test_shared_limit_and_verdict_change_trigger_this_workflow(self):
        check_source_triggers(self.source)
        for path in ('internal/hopmeasure/ordered.go', 'deploy/test_focused_multihop_clocks.py'):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, re.escape(path)):
                check_source_triggers(self.source.replace("      - '"+path+"'\n", ''))

    def test_shard_union_rejects_missing_duplicate_or_bypassed_dispatch(self):
        for old, new in (
            ('[1, 2, 3, 4]', '[1, 2, 3]'), ('[1, 2, 3, 4]', '[1, 2, 2, 4]'),
            ('"runtime_depth", ', ''), ('"runtime_remaining", ', ''), ('"runtime_remaining"', '"runtime"'),
            ('"imported_prefix"', '"fifty"'),
            ('${{ matrix.shard }}', '1'), ('${{ matrix.group }}', 'runtime'),
            ('--core-shard "$CORE_SHARD"', '--core-shard 1'),
            ('--group "$SHARED_GROUP"', '--group "$SHARED_GROUP" || true'),
            ('        group: [', '        exclude: [{}]\n        group: ['),
            ('  shared-core:\n', '  shared-core:\n    if: false\n'),
            ('        run: '+DISPATCHER, '        continue-on-error: true\n        run: '+DISPATCHER),
        ):
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                shared_plan(self.source.replace(old, new), self.groups)
        with self.assertRaises(ValueError):
            shared_plan(self.source+'\n  repeated:\n    run: '+DISPATCHER+'\n', self.groups)

    def test_actual_shell_gates_build_on_every_result(self):
        script = parser_guard(self.source)
        results = dict.fromkeys(('APPLE_RESULT', 'CORE_RESULT', 'GROUP_RESULT'), 'success')
        completed = lambda env: subprocess.run(['bash', '-e', '-c', script], env=env, timeout=5).returncode
        self.assertEqual(completed(results), 0)
        for name in results:
            for status in ('failure', 'cancelled', 'skipped', ''):
                with self.subTest(name=name, status=status):
                    self.assertNotEqual(completed({**results, name:status}), 0)

    def test_parser_requires_original_dependency_and_unconditional_next_steps(self):
        for old, new in (
            ('apple-graphs, shared-core, shared-groups', 'apple-graphs, shared-groups'),
            ('${{ needs.shared-groups.result }}', 'success'),
            ('${{ needs.shared-core.result }}', '${{ needs.apple-graphs.result }}'),
            ('    if: always()', '    if: success()'),
            ('      - name: Build the exact-source', '      - if: always()\n        name: Build the exact-source'),
            ('        run: python3 deploy/test_native_xray_shared_workflow.py', '        run: true'),
        ):
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                parser_guard(self.source.replace(old, new))


if __name__ == '__main__':
    unittest.main()
