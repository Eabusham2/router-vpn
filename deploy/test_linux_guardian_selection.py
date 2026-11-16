#!/usr/bin/env python3
"""Exercise the guardian's exact Go root/subtest selector with a real test image.

The executable contains ordinary testing.T roots and leaves only. These
controls establish selection and strict verdict behavior, not kernel access.
"""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('guardian_selection_'+name.replace('-', '_'), ROOT/'deploy'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GUARD = load('test_desktop_linux_guardian')
NODE = load('test_desktop_node_physical')
PREFIX = 'TestDesktopLinuxGuardianKernel'
SOURCE = '''package selection
import "testing"
func TestDesktopLinuxGuardianKernelNodeHostTUN(t *testing.T) {
 for _, name := range []string{"selected", "other", "selected-extra", "literal[one]|two"} {
  t.Run(name, func(t *testing.T) {})
 }
 t.Run("nested", func(t *testing.T) {
  t.Run("leaf", func(t *testing.T) {})
  t.Run("other", func(t *testing.T) {})
 })
}
func TestDesktopLinuxGuardianKernelCONNECTExecution(t *testing.T) {
 for _, name := range []string{"selected", "other", "selected-extra"} {
  t.Run(name, func(t *testing.T) {})
 }
}
func TestDesktopLinuxGuardianKernelOff(t *testing.T) {}
func TestDesktopLinuxGuardianKernelOffExtra(t *testing.T) {}
func TestForeignGuardianRoot(t *testing.T) {}
'''


def expected(cases):
    names = []
    for case in cases:
        parts = (PREFIX+case).split('/')
        for count in range(1, len(parts)+1):
            name = '/'.join(parts[:count])
            if name not in names:
                names.append(name)
    return tuple(names)


class GuardianGoSelection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='routervpn-guardian-selection-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.work = Path(cls.temporary.name)
        (cls.work/'go.mod').write_text('module selection\n\ngo 1.25\n')
        (cls.work/'selection_test.go').write_text(SOURCE)
        environment = dict(os.environ, GOWORK='off', GOFLAGS='', GORACE='atexit_sleep_ms=0')
        cls.compiler, cls.environment = GUARD.UID.compiler_toolchain(ROOT, os.environ.get('GO', 'go'), environment)
        cls.image = cls.work/'selection.test'
        built = subprocess.run([str(cls.compiler), 'test', '-race', '-c', '-p=1', '-o', str(cls.image), '.'],
                               cwd=cls.work, env=cls.environment, check=True, timeout=120,
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        cls.image_sha256 = hashlib.sha256(cls.image.read_bytes()).hexdigest()
        print('Guardian selector executable: '+json.dumps({'compiler': str(cls.compiler),
              'source_sha256': hashlib.sha256(SOURCE.encode()).hexdigest(), 'image_sha256': cls.image_sha256}), flush=True)

    def run_image(self, selector):
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(), self.image_sha256)
        result = subprocess.run([str(self.image), '-test.v', '-test.count=1', '-test.timeout=10s', '-test.run='+selector],
                                cwd=self.work, env=self.environment, check=True, timeout=15,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(), self.image_sha256)
        self.assertNotIn('DATA RACE', result.stdout)
        self.assertNotIn('--- SKIP:', result.stdout)
        return result.stdout

    def exact(self, cases):
        selector = GUARD.namespace_test_selector(cases)
        output = self.run_image(selector)
        NODE.require_native_verdicts(output, expected(cases), 'actual guardian Go selector')
        self.assertEqual(output.splitlines().count('PASS'), 1)
        print('Guardian selector exact: '+json.dumps({'cases': list(cases), 'selector': selector,
              'records': len(expected(cases)), 'output_sha256': hashlib.sha256(output.encode()).hexdigest()}), flush=True)
        return selector, output

    def test_exact_single_leaf_does_not_select_siblings(self):
        for case in ('NodeHostTUN/selected', 'CONNECTExecution/selected'):
            with self.subTest(case=case):
                self.exact((case,))

    def test_branch_alternation_keeps_each_root_with_its_original_leaf(self):
        self.exact(('NodeHostTUN/selected', 'CONNECTExecution/other'))

    def test_same_root_multiple_leaves_runs_the_root_once(self):
        self.exact(('NodeHostTUN/selected', 'NodeHostTUN/other'))

    def test_nested_and_literal_regexp_characters_remain_exact(self):
        self.exact(('NodeHostTUN/nested/leaf',))
        self.exact(('NodeHostTUN/literal[one]|two',))

    def test_original_top_level_group_remains_exact(self):
        self.exact(('Off', 'OffExtra'))
        self.exact(('Off',))
        for group, cases in GUARD.KERNEL_GROUPS:
            selector = GUARD.namespace_test_selector(cases)
            self.assertTrue(selector)
            self.assertEqual(selector.count('^'+PREFIX), len(cases), group)

    def test_original_whole_path_group_is_rejected_even_with_zero_exit(self):
        cases = ('NodeHostTUN/selected',)
        original = '^'+PREFIX+'('+'|'.join(map(re.escape, cases))+')$'
        output = self.run_image(original)
        self.assertIn('no tests to run', output)
        self.assertNotIn('=== RUN', output)
        self.assertEqual(output.splitlines().count('PASS'), 1)
        with self.assertRaises(ValueError):
            NODE.require_native_verdicts(output, expected(cases), 'original broken grouped selector')
        print('Guardian selector causal: original grouped path ran zero tests and strict verdict refused it.', flush=True)

    def test_unanchored_leaf_and_cartesian_product_are_rejected(self):
        cases = ('NodeHostTUN/selected',)
        widened = '^'+PREFIX+'NodeHostTUN$/selected'
        with self.assertRaises(ValueError):
            NODE.require_native_verdicts(self.run_image(widened), expected(cases), 'widened leaf selector')
        cases = ('NodeHostTUN/selected', 'CONNECTExecution/other')
        widened = '^'+PREFIX+'(NodeHostTUN|CONNECTExecution)$/^(selected|other)$'
        with self.assertRaises(ValueError):
            NODE.require_native_verdicts(self.run_image(widened), expected(cases), 'crossed branch selector')

    def test_missing_duplicate_or_partial_paths_are_refused(self):
        for cases in ((), [], 'Off', ('',), ('Off', 'Off'), ('NodeHostTUN/',), ('/selected',), (None,), ('Off', 2)):
            with self.subTest(cases=cases), self.assertRaises(ValueError):
                GUARD.namespace_test_selector(cases)

    def test_original_namespace_uses_this_selector_once(self):
        tree = ast.parse((ROOT/'deploy/test_desktop_linux_guardian.py').read_text())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'namespace_test']
        self.assertEqual(len(functions), 1)
        selected = [node for node in ast.walk(functions[0]) if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == 'selector' for target in node.targets)]
        self.assertEqual(len(selected), 1)
        self.assertEqual(ast.unparse(selected[0].value), 'namespace_test_selector(cases)')


if __name__ == '__main__':
    unittest.main()
