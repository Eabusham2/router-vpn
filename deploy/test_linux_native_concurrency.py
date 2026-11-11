#!/usr/bin/env python3
"""Keep superseded automatic Linux pushes separate from retained evidence runs.

Evaluate the actual workflow expressions, not a second dispatch implementation.
GitHub re-evaluates job conditions during cancellation; a true always() job
continues running. Reusable workflow github context belongs to its caller:
https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-cancellation
https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations
"""
import ast
import itertools
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
LINUX = ROOT / '.github/workflows/linux-native-app.yml'
NATIVE = ROOT / '.github/workflows/desktop-native-runtime.yml'
RESULTS = ('success', 'skipped', 'failure', 'cancelled')


def section(raw, key, indent):
    prefix = ' ' * indent
    matches = list(re.finditer(r'(?m)^' + prefix + re.escape(key) + r':\n', raw))
    if len(matches) != 1:
        raise AssertionError('Missing or duplicated workflow section: ' + key)
    start = matches[0].end()
    end = re.search(r'(?m)^ {0,' + str(indent) + r'}\S', raw[start:])
    return raw[start:start + end.start()] if end else raw[start:]


def field(raw, key, indent):
    values = re.findall(r'(?m)^' + ' ' * indent + re.escape(key) + r': (.+)$', raw)
    if len(values) != 1:
        raise AssertionError('Missing or duplicated workflow field: ' + key)
    return values[0]


def expression(raw, values, cancelled=False):
    text = raw.strip()
    if text.startswith('${{') and text.endswith('}}'):
        text = text[3:-2].strip()
    text = re.sub(r'\b(?:github|needs)(?:\.[A-Za-z_][A-Za-z0-9_-]*)+',
                  lambda match: 'fields[' + repr(match.group()) + ']', text)
    text = re.sub(r'!(?!=)', ' not ', text.replace('&&', ' and ').replace('||', ' or '))
    tree = ast.parse(text.strip(), mode='eval')

    def evaluate(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bool, int)):
            return node.value
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == 'fields':
            return values[evaluate(node.slice)]
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and not node.args and not node.keywords:
            if node.func.id == 'always':
                return True
            if node.func.id == 'cancelled':
                return cancelled
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not evaluate(node.operand)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            value = evaluate(node.values[0])
            for part in node.values[1:]:
                if isinstance(node.op, ast.And) and not value or isinstance(node.op, ast.Or) and value:
                    return value
                value = evaluate(part)
            return value
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
            left, right = evaluate(node.left), evaluate(node.comparators[0])
            if isinstance(node.ops[0], ast.Eq):
                return left == right
            if isinstance(node.ops[0], ast.NotEq):
                return left != right
        raise AssertionError('Unsupported workflow expression: ' + ast.dump(node))

    return evaluate(tree.body)


def render(raw, values):
    return re.sub(r'\$\{\{(.*?)\}\}', lambda match: str(expression(match.group(), values)), raw)


def context(event='push', ref='refs/heads/main', caller='Linux native app', run=101):
    return {'github.event_name': event, 'github.ref': ref, 'github.workflow': caller, 'github.run_id': run}


def check_runtime(raw):
    header = section(raw, 'runtime', 2).split('    steps:\n', 1)[0]
    if field(header, 'needs', 4) != '[targets, tor-windows, macos-physical-sockets]':
        raise AssertionError('Native runtime lost its original prerequisite jobs')
    condition = field(header, 'if', 4)
    contexts = (
        (context(), True), (context(run=202), True),
        (context(event='workflow_dispatch'), False),
        (context(event='pull_request', ref='refs/pull/7/merge'), False),
        (context(ref='refs/heads/release'), False), (context(ref='refs/tags/v1'), False),
        (context(caller='Build all Router VPN release gates'), False),
        (context(caller='Router VPN release candidate'), False),
        (context(event='workflow_dispatch', caller='Complete native desktop transport runtimes'), False),
        (context(caller='macOS native app'), False),
    )
    for (values, automatic_linux), results, cancelled in itertools.product(contexts, itertools.product(RESULTS, repeat=3), (False, True)):
        captured = dict(values, **dict(zip(('needs.targets.result', 'needs.tor-windows.result', 'needs.macos-physical-sockets.result'), results)))
        original = results[0] == 'success' and results[1] in ('success', 'skipped') and results[2] in ('success', 'skipped')
        expected = original and not (cancelled and automatic_linux)
        if expression(condition, captured, cancelled) is not expected:
            raise AssertionError('Native runtime changed a prerequisite or cancellation boundary: ' + repr((values, results, cancelled)))


def check_concurrency(raw):
    if field(raw, 'name', 0) != 'Linux native app':
        raise AssertionError('Native cancellation lost its exact Linux caller')
    block = section(raw, 'concurrency', 0)
    group, cancel = field(block, 'group', 2), field(block, 'cancel-in-progress', 2)
    seen = {}
    for event, ref in itertools.product(('push', 'workflow_dispatch', 'pull_request'),
                                        ('refs/heads/main', 'refs/heads/release', 'refs/tags/v1')):
        for run in (101, 202):
            values = context(event, ref, run=run)
            automatic = event == 'push' and ref == 'refs/heads/main'
            if expression(cancel, values) is not automatic:
                raise AssertionError('Cancellation extended beyond automatic main pushes')
            actual = render(group, values)
            expected = 'linux-native-' + (ref if automatic else str(run))
            if actual != expected:
                raise AssertionError('Dispatch or other event shares an automatic main push group')
            seen[event, ref, run] = actual
    if seen['push', 'refs/heads/main', 101] != seen['push', 'refs/heads/main', 202]:
        raise AssertionError('New main push cannot supersede its old automatic run')


class LinuxNativeCancellation(unittest.TestCase):
    def test_actual_runtime_preserves_all_prerequisites_and_protected_callers(self):
        check_runtime(NATIVE.read_text())

    def test_actual_groups_cancel_only_superseded_automatic_main_pushes(self):
        check_concurrency(LINUX.read_text())

    def test_original_blocker_broad_cancellation_and_missing_prerequisite_are_rejected(self):
        raw = NATIVE.read_text()
        exclusion = " && !(cancelled() && github.event_name == 'push' && github.ref == 'refs/heads/main' && github.workflow == 'Linux native app')"
        self.assertEqual(raw.count(exclusion), 1)
        for changed in (raw.replace(exclusion, ''), raw.replace(exclusion, ' && !cancelled()'),
                        raw.replace(" && needs.targets.result == 'success'", ''),
                        raw.replace("needs.tor-windows.result == 'success' || needs.tor-windows.result == 'skipped'", "always()"),
                        raw.replace("needs.macos-physical-sockets.result == 'success' || needs.macos-physical-sockets.result == 'skipped'", "always()")):
            with self.subTest(condition=field(section(changed, 'runtime', 2), 'if', 4)), self.assertRaises(AssertionError):
                check_runtime(changed)

    def test_manual_group_collision_or_nonpush_cancellation_is_rejected(self):
        raw = LINUX.read_text()
        group = field(section(raw, 'concurrency', 0), 'group', 2)
        cancel = field(section(raw, 'concurrency', 0), 'cancel-in-progress', 2)
        for changed in (raw.replace(group, 'linux-native-${{ github.ref }}'),
                        raw.replace(cancel, '${{ always() }}'),
                        raw.replace(cancel, '${{ github.event_name == \'push\' }}')):
            with self.subTest(workflow=changed), self.assertRaises(AssertionError):
                check_concurrency(changed)

    def test_validation_inventory_and_cleanup_still_execute(self):
        raw = NATIVE.read_text()
        runtime = section(raw, 'runtime', 2)
        commands = ('python3 deploy/test_linux_native_concurrency.py',
                    'python3 deploy/build-native-runtime.py "${runtime_args[@]}"',
                    'python3 deploy/test_desktop_dnssec_bundle.py',
                    'python3 deploy/test_desktop_tor_package.py',
                    'python3 deploy/test_desktop_native_bundle.py',
                    'python3 deploy/test_native_runtime_delivery.py',
                    'python3 deploy/native-runtime-bundle.py archive')
        for command in commands:
            self.assertEqual(runtime.count(command), 1)
        self.assertEqual([runtime.index(command) for command in commands], sorted(runtime.index(command) for command in commands))
        self.assertIn('    needs: runtime\n', section(raw, 'kernel-mtu', 2))
        self.assertIn('        if: always()\n', section(raw, 'kernel-mtu', 2))
        self.assertNotIn('\nconcurrency:\n', raw, 'A reusable job must not cancel its caller through a new shared workflow group')
        self.assertIn('      platform: linux\n', section(LINUX.read_text(), 'native-runtimes', 2))
        self.assertIn('    needs: native-runtimes\n', section(LINUX.read_text(), 'native-linux', 2))
        for path in ('deploy/test_linux_native_concurrency.py', '.github/workflows/desktop-native-runtime.yml'):
            self.assertEqual(LINUX.read_text().count("      - '" + path + "'\n"), 2)


if __name__ == '__main__':
    unittest.main()
