#!/usr/bin/env python3
"""Offline integrity and ownership tests for the pinned scheduler patch."""
from pathlib import Path
import hashlib
import importlib.util
import json
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('gvisor_scheduler', ROOT/'deploy/prepare-gvisor-scheduler.py')
PATCH = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PATCH)
# Exact public upstream assembly, including its license and original defect.
ASM = b'// Copyright 2020 The gVisor Authors.\n//\n// Licensed under the Apache License, Version 2.0 (the "License");\n// you may not use this file except in compliance with the License.\n// You may obtain a copy of the License at\n//\n//     http://www.apache.org/licenses/LICENSE-2.0\n//\n// Unless required by applicable law or agreed to in writing, software\n// distributed under the License is distributed on an "AS IS" BASIS,\n// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n// See the License for the specific language governing permissions and\n// limitations under the License.\n\n//go:build race && arm64\n// +build race,arm64\n\n#include "textflag.h"\n\n// func RaceUncheckedAtomicCompareAndSwapUintptr(ptr *uintptr, old, new uintptr) bool\nTEXT \xc2\xb7RaceUncheckedAtomicCompareAndSwapUintptr(SB),NOSPLIT,$0-25\n\tMOVD ptr+0(FP), R0\n\tMOVD old+8(FP), R1\n\tMOVD new+16(FP), R1\nagain:\n\tLDAXR (R0), R3\n\tCMP R1, R3\n\tBNE ok\n\tSTLXR R2, (R0), R3\n\tCBNZ R3, again\nok:\n\tCSET EQ, R0\n\tMOVB R0, ret+24(FP)\n\tRET\n\n'


class SchedulerPreparation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.files = {PATCH.ASSEMBLY: ASM, 'go.mod': b'module github.com/sagernet/gvisor\n', 'LICENSE': b'fixture license\n', 'pkg/other.go': b'package other\n'}
        self.sum = PATCH.h1([(PATCH.PREFIX+n, hashlib.sha256(b).hexdigest()) for n, b in self.files.items()])
        self.archive = self.root/'source.zip'
        self.write_zip(self.files)
        self.vendor = self.root/'core'
        self.vendor.mkdir()
        self.plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}

    def write_zip(self, files):
        with zipfile.ZipFile(self.archive, 'w') as archive:
            for name, data in files.items():
                archive.writestr(PATCH.PREFIX+name, data)

    def extract(self):
        target = self.vendor/PATCH.COPY
        target.mkdir()
        with mock.patch.object(PATCH, 'SUM', self.sum):
            PATCH.extract_verified(self.archive, target)
        return target

    def test_patch_is_exactly_one_instruction_and_preserves_the_archive(self):
        before = self.archive.read_bytes()
        target = self.extract()
        for name, data in self.files.items():
            self.assertEqual((target/name).read_bytes(), PATCH.patch(data) if name == PATCH.ASSEMBLY else data)
        self.assertEqual(before, self.archive.read_bytes())
        self.assertEqual(PATCH.BLOB, PATCH.git_blob(ASM))
        self.assertEqual(ASM, PATCH.original(PATCH.patch(ASM)))
        with self.assertRaises(ValueError):
            PATCH.patch(ASM+b'// unexpected edit\n')

    def test_h1_matches_an_independent_canonical_summary(self):
        summary = b''.join(hashlib.sha256(self.files[n]).hexdigest().encode()+b'  '+(PATCH.PREFIX+n).encode()+b'\n' for n in sorted(self.files))
        import base64
        self.assertEqual('h1:'+base64.b64encode(hashlib.sha256(summary).digest()).decode(), self.sum)

    def test_verification_rejects_missing_extra_changed_or_reverted_files(self):
        target = self.extract()
        cases = [('pkg/other.go', b'package tampered\n'), ('extra.go', b'package extra\n'), (PATCH.ASSEMBLY, ASM), ('LICENSE', None)]
        for name, new in cases:
            path = target/name
            old = path.read_bytes() if path.exists() else None
            if new is None:
                path.unlink()
            else:
                path.write_bytes(new)
            with mock.patch.object(PATCH, 'SUM', self.sum), self.assertRaises(ValueError):
                PATCH.verify_tree(target)
            if old is None:
                path.unlink()
            else:
                path.write_bytes(old)
        with mock.patch.object(PATCH, 'SUM', self.sum):
            PATCH.verify_tree(target)

    def test_linked_output_is_rejected(self):
        target = self.extract()
        outside = self.root/'outside.go'
        outside.write_bytes(self.files['pkg/other.go'])
        (target/'pkg/other.go').unlink()
        (target/'pkg/other.go').symlink_to(outside)
        with mock.patch.object(PATCH, 'SUM', self.sum), self.assertRaises(ValueError):
            PATCH.verify_tree(target)
        self.assertEqual(outside.read_bytes(), self.files['pkg/other.go'])

    def test_unsafe_archive_names_are_rejected_without_escape(self):
        for name in ('../escaped', '/absolute', 'pkg/../../escaped', 'pkg//empty', 'bad\nname', 'bad\\name'):
            self.write_zip({name: b'data'})
            target = self.vendor/'stage'
            target.mkdir(exist_ok=True)
            with self.assertRaises(ValueError):
                PATCH.extract_verified(self.archive, target)
        self.assertFalse((self.vendor/'escaped').exists())
        self.assertFalse((self.root/'escaped').exists())

    def test_wrong_version_or_foreign_replace_fails_before_writes(self):
        for plan in ({'Require': []}, {'Require': [{'Path': PATCH.MODULE, 'Version': 'v0.0.0'}]}, {**self.plan, 'Replace': [{'Old': {'Path': PATCH.MODULE}, 'New': {'Path': '/outside'}}]}):
            with mock.patch.object(PATCH.subprocess, 'check_output', return_value=json.dumps(plan)), self.assertRaises(ValueError):
                PATCH.module_plan(self.vendor)
        self.assertFalse((self.vendor/PATCH.COPY).exists())

    def commands(self, command, **kwargs):
        if command[0] == 'git':
            return PATCH.CORE+'\n'
        if command[1:4] == ['mod', 'edit', '-json']:
            return json.dumps(self.plan)
        if command[1:4] == ['mod', 'download', '-json']:
            return json.dumps({'Path': PATCH.MODULE, 'Version': PATCH.VERSION, 'Sum': self.sum, 'Zip': str(self.archive)})
        if command[1:5] == ['list', '-m', '-json', PATCH.MODULE]:
            return json.dumps({'Version': PATCH.VERSION, 'Replace': {'Path': './'+PATCH.COPY, 'Dir': str(self.vendor/PATCH.COPY)}})
        raise AssertionError(command)

    def test_prepare_is_idempotent_and_verify_checks_the_real_selected_copy(self):
        with mock.patch.object(PATCH, 'SUM', self.sum), mock.patch.object(PATCH.subprocess, 'check_output', side_effect=self.commands) as commands, mock.patch.object(PATCH.subprocess, 'run') as run:
            PATCH.prepare(self.vendor)
            self.plan['Replace'] = [{'Old': {'Path': PATCH.MODULE, 'Version': PATCH.VERSION}, 'New': {'Path': './'+PATCH.COPY}}]
            PATCH.prepare(self.vendor)
            PATCH.verify(self.vendor)
            downloads = [c for c in commands.call_args_list if c.args[0][1:3] == ['mod', 'download']]
            self.assertEqual(len(downloads), 1)
            run.assert_called_with(['go', 'mod', 'edit', '-replace='+PATCH.MODULE+'@'+PATCH.VERSION+'=./'+PATCH.COPY], cwd=self.vendor.resolve(), check=True)

    def test_prepare_and_verify_use_the_resolved_vendor_for_every_command(self):
        # Windows may return an 8.3 TEMP name while Path.resolve expands it.
        # A lexical alias exercises the same canonical-cwd contract on Unix.
        alias = self.vendor / '..' / self.vendor.name
        canonical = self.vendor.resolve()
        with mock.patch.object(PATCH, 'SUM', self.sum), mock.patch.object(PATCH.subprocess, 'check_output', side_effect=self.commands) as commands, mock.patch.object(PATCH.subprocess, 'run') as run:
            PATCH.prepare(alias)
            self.plan['Replace'] = [{'Old': {'Path': PATCH.MODULE, 'Version': PATCH.VERSION}, 'New': {'Path': './'+PATCH.COPY}}]
            PATCH.verify(alias)
            for call in commands.call_args_list:
                if call.args[0][0] == 'git':
                    self.assertEqual(call.args[0][1:3], ['-C', str(canonical)])
                else:
                    self.assertEqual(call.kwargs['cwd'], canonical)
            run.assert_called_once_with(['go', 'mod', 'edit', '-replace='+PATCH.MODULE+'@'+PATCH.VERSION+'=./'+PATCH.COPY], cwd=canonical, check=True)

    def test_verify_rejects_a_foreign_selected_directory(self):
        self.extract()
        def selected(command, **kwargs):
            if command[1:5] == ['list', '-m', '-json', PATCH.MODULE]:
                return json.dumps({'Version': PATCH.VERSION, 'Replace': {'Path': './'+PATCH.COPY, 'Dir': str(self.root/'foreign')}})
            return self.commands(command, **kwargs)
        with mock.patch.object(PATCH, 'SUM', self.sum), mock.patch.object(PATCH.subprocess, 'check_output', side_effect=selected), self.assertRaises(ValueError):
            PATCH.verify(self.vendor)

    def test_failed_checksum_cannot_publish_a_partial_dependency(self):
        self.files['pkg/other.go'] = b'package altered\n'
        self.write_zip(self.files)
        with mock.patch.object(PATCH, 'SUM', self.sum), mock.patch.object(PATCH.subprocess, 'check_output', side_effect=self.commands), mock.patch.object(PATCH.subprocess, 'run') as run, self.assertRaises(ValueError):
            PATCH.prepare(self.vendor)
        run.assert_not_called()
        self.assertFalse((self.vendor/PATCH.COPY).exists())
        self.assertEqual(list(self.vendor.iterdir()), [])

    def test_patch_enters_both_mobile_cache_keys_and_the_native_gate(self):
        spec = importlib.util.spec_from_file_location('amnezia_preparation', ROOT/'deploy/prepare-mobile-amnezia.py')
        preparation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preparation)
        self.assertIn(ROOT/'deploy/prepare-gvisor-scheduler.py', preparation.inputs())
        self.assertIn(ROOT/'mobile/amnezia/scheduler_test.go.tmpl', preparation.inputs())
        self.assertIn("../deploy/prepare-gvisor-scheduler.py", (ROOT/'android/app/build.gradle').read_text())
        for path in ('android/build-sing-box-libbox.sh', 'ios/RouterVPN/prepare-libbox.sh'):
            text = (ROOT/path).read_text()
            self.assertIn('prepare-mobile-multihop.py', text)
            self.assertIn('prepare-mobile-amnezia.py" --verify-dependency', text)
        gate = (ROOT/'deploy/test_native_awg_return.sh').read_text()
        self.assertIn('TestNativeTunSchedulerAtomicCAS', gate)
        self.assertIn('SCHEDULER.original', gate)
        self.assertIn('finally:', gate)
        self.assertIn('-race', gate)


if __name__ == '__main__':
    unittest.main()
