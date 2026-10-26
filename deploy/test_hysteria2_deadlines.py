#!/usr/bin/env python3
"""Check the exact owned-module preparation, drift rejection, and source closure."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hy2_deadline_preparation', ROOT/'deploy/prepare-hysteria2-deadlines.py')
POLICY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(POLICY)


class DeadlinePreparation(unittest.TestCase):
    def archive(self, root, rows):
        target = root/'module.zip'
        with zipfile.ZipFile(target, 'w') as output:
            for name, content in rows:
                output.writestr(name, content)
        return target

    def fixture(self):
        original = b'package bounded\n'
        module = dict(module='test.invalid/deadline', version='v1.0.0', copy='owned',
                      guards={'queue.go': POLICY.git_blob(original)},
                      patches={'queue.go': (('package bounded', 'package repaired'),)},
                      extra={})
        rows = [('test.invalid/deadline@v1.0.0/queue.go', original),
                ('test.invalid/deadline@v1.0.0/LICENSE', b'fixture license\n')]
        module['sum'] = POLICY.h1([(name, hashlib.sha256(data).hexdigest()) for name, data in rows])
        return module, rows

    def test_owned_copy_reverses_to_exact_entire_archive(self):
        module, rows = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root/'copy'; target.mkdir()
            POLICY.extract_verified(module, self.archive(root, rows), target)
            self.assertEqual((target/'queue.go').read_bytes(), b'package repaired\n')
            POLICY.verify_tree(module, target)
            for name, data in [('queue.go', b'package repaired\n// drift\n'),
                               ('LICENSE', b'foreign license\n'), ('foreign.go', b'package repaired\n')]:
                path = target/name; previous = path.read_bytes() if path.exists() else None
                path.write_bytes(data)
                with self.assertRaises(ValueError, msg=name): POLICY.verify_tree(module, target)
                if previous is None: path.unlink()
                else: path.write_bytes(previous)
            POLICY.verify_tree(module, target)

    def test_archive_identity_and_path_negatives(self):
        module, rows = self.fixture()
        candidates = [rows[:1], rows+rows[:1],
                      [(rows[0][0], b'package changed\n'), rows[1]],
                      [(rows[0][0].replace('/queue.go', '/../queue.go'), rows[0][1])],
                      [(rows[0][0].replace('test.invalid/deadline', 'test.invalid/other'), rows[0][1])],
                      [(rows[0][0].replace('/queue.go', '/C:queue.go'), rows[0][1])]]
        for index, candidate in enumerate(candidates):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); target = root/'copy'; target.mkdir()
                with self.assertRaises(ValueError): POLICY.extract_verified(module, self.archive(root, candidate), target)

    def test_foreign_symlink_or_hardlink_owner_rejected(self):
        module, rows = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root/'copy'; target.mkdir()
            POLICY.extract_verified(module, self.archive(root, rows), target)
            original = target/'LICENSE'; data = original.read_bytes(); original.unlink()
            foreign = root/'foreign'; foreign.write_bytes(data)
            try: original.symlink_to(foreign)
            except OSError: pass  # Windows unprivileged hosts still check the hardlink boundary.
            else:
                with self.assertRaises(ValueError): POLICY.verify_tree(module, target)
                original.unlink()
            os.link(foreign, original)
            with self.assertRaises(ValueError): POLICY.verify_tree(module, target)

    def test_changed_or_unversioned_replacements_rejected(self):
        plan = {'Module': {'Path': 'github.com/sagernet/sing-box'},
                'Require': [{'Path': s['module'], 'Version': s['version']} for s in POLICY.MODULES]}
        with patch.object(subprocess, 'check_output', return_value=json.dumps(plan)):
            POLICY.module_plan(Path('.'))
        for replacement in [
            {'Old': {'Path': POLICY.QUIC['module']}, 'New': {'Path': './'+POLICY.QUIC['copy']}},
            {'Old': {'Path': POLICY.QUIC['module'], 'Version': POLICY.QUIC['version']}, 'New': {'Path': '../unowned'}},
        ]:
            changed = {**plan, 'Replace': [replacement]}
            with patch.object(subprocess, 'check_output', return_value=json.dumps(changed)):
                with self.assertRaises(ValueError): POLICY.module_plan(Path('.'))

    def test_every_deadline_template_enters_both_native_source_identities(self):
        own = set(POLICY.inputs())
        self.assertEqual(set((ROOT/'mobile/hysteria2').glob('*.tmpl')), {p for p in own if p.suffix == '.tmpl'})
        for filename in ['prepare-mobile-multihop.py', 'prepare-relay-core.py', 'build-native-runtime.py']:
            spec = importlib.util.spec_from_file_location('hy2_inputs_'+filename, ROOT/'deploy'/filename)
            owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
            self.assertTrue(own <= set(owner.inputs()), filename)

    def test_native_runner_uses_selected_go_environment_and_windows_arm64(self):
        spec = importlib.util.spec_from_file_location('hy2_executable_gate', ROOT/'deploy/test_hysteria2_deadlines_pinned.py')
        runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
        for system, machine, target, race in [('Windows', 'ARM64', 'windows\narm64\n', False),
                                             ('Windows', 'AMD64', 'windows\namd64\n', True),
                                             ('Linux', 'aarch64', 'linux\narm64\n', True)]:
            with self.subTest(system=system, machine=machine), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve(); environment = {'OWNED_BUILD': 'selected'}
                with patch.object(runner.platform, 'system', return_value=system), \
                     patch.object(runner.platform, 'machine', return_value=machine), \
                     patch.object(runner.POLICY, 'verify') as verify, \
                     patch.object(runner.subprocess, 'check_output', return_value=target) as metadata, \
                     patch.object(runner.subprocess, 'run') as execute:
                    runner.run(root, 'owned-go', environment)
                self.assertEqual(verify.call_count, 2)
                for call in verify.call_args_list: self.assertEqual(call.args, (root, 'owned-go', environment))
                self.assertEqual(metadata.call_args.args[0], ['owned-go', 'env', 'GOOS', 'GOARCH'])
                self.assertEqual(metadata.call_args.kwargs['env'], environment)
                self.assertEqual(execute.call_count, 2)
                for index, call in enumerate(execute.call_args_list):
                    command = call.args[0]
                    self.assertEqual(command[0], 'owned-go')
                    self.assertEqual('-race' in command, race)
                    self.assertEqual('-tags=low_memory' in command, index == 1)
                    self.assertIn('github.com/sagernet/quic-go', command)
                    self.assertIn('github.com/sagernet/sing-quic/hysteria2', command)
                    self.assertEqual(call.kwargs['env'], environment)

    def test_native_runner_rejects_foreign_target_before_execution(self):
        spec = importlib.util.spec_from_file_location('hy2_foreign_gate', ROOT/'deploy/test_hysteria2_deadlines_pinned.py')
        runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
        with patch.object(runner.platform, 'system', return_value='Linux'), \
             patch.object(runner.platform, 'machine', return_value='x86_64'), \
             patch.object(runner.POLICY, 'verify'), \
             patch.object(runner.subprocess, 'check_output', return_value='windows\narm64\n'), \
             patch.object(runner.subprocess, 'run') as execute:
            with self.assertRaisesRegex(ValueError, 'selected native host'): runner.run(ROOT)
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
