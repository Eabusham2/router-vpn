#!/usr/bin/env python3
"""Exercise the real pinned Apple module selection and incremental make graph.

Use disposable local clones of the supplied exact checkout. The make control is
an actual dry run of its upstream Makefile, not an Xcode compilation claim.
"""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('apple_amnezia_timer_preparation', ROOT / 'deploy/prepare-apple-amnezia-timers.py')
PREP = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(PREP)
ORIGINAL = None


class AppleTimerPreparation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if ORIGINAL is None:
            raise ValueError('Supply the actual pinned Apple checkout with --kit')
        cls.go, cls.env = PREP.environment()
        PREP.checkout(ORIGINAL)
        info = json.loads(subprocess.check_output(
            [cls.go, 'mod', 'download', '-json', PREP.TIMERS.MODULE + '@' + PREP.TIMERS.VERSION],
            cwd=ORIGINAL / PREP.MODULE_ROOT, env=cls.env, text=True))
        if info.get('Sum') != PREP.TIMERS.SUM:
            raise ValueError('The Apple timer control lost the actual pinned module archive')
        cls.cache_timer = Path(info['Dir']) / PREP.TIMERS.TIMER
        cls.cache_before = (cls.cache_timer.read_bytes(), cls.cache_timer.stat().st_mode)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='routervpn apple timers-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.kit = self.root / 'wireguard-apple'
        subprocess.run(['git', 'clone', '--shared', '--quiet', '--no-checkout', str(ORIGINAL), str(self.kit)], check=True)
        subprocess.run(['git', '-C', str(self.kit), 'checkout', '--quiet', '--detach', PREP.PIN], check=True)

    def tearDown(self):
        PREP.checkout(ORIGINAL)
        self.assertEqual((self.cache_timer.read_bytes(), self.cache_timer.stat().st_mode), self.cache_before)

    def prepared(self):
        PREP.prepare(self.kit, self.go, self.env)
        return PREP.verify(self.kit, self.go, self.env)

    def test_real_go_selection_preserves_original_inputs_and_cached_identity(self):
        _, _, original = PREP.checkout(self.kit)
        source, work, selected = self.prepared()
        before = {p.relative_to(work): (p.read_bytes(), p.stat().st_ino) for p in work.rglob('*') if p.is_file()}
        PREP.prepare(self.kit, self.go, self.env)
        self.assertEqual(before, {p.relative_to(work): (p.read_bytes(), p.stat().st_ino) for p in work.rglob('*') if p.is_file()})
        self.assertEqual(PREP.checkout(self.kit)[2], original)
        info = json.loads(subprocess.check_output([self.go, 'list', '-m', '-json', PREP.TIMERS.MODULE], cwd=source, env=selected, text=True))
        self.assertEqual(Path(info['Dir']).resolve(), work / PREP.TIMERS.COPY)
        self.assertEqual(info['Replace']['Path'], '../../../' + PREP.WORK + '/' + work.name + '/' + PREP.TIMERS.COPY)
        self.assertNotIn(str(self.root), (work / 'go.mod').read_text())
        self.assertEqual((work / 'go.sum').read_bytes(), original['go.sum'])
        self.assertEqual(PREP.TIMERS.original((work / PREP.TIMERS.COPY / PREP.TIMERS.TIMER).read_bytes()), self.cache_before[0])

    def test_alternate_inputs_and_full_module_drift_are_rejected_without_repair(self):
        _, work, _ = self.prepared()
        faults = [('go.mod', b'\nreplace example.invalid/unowned => /tmp/unowned\n'),
                  ('go.sum', b'changed checksum\n'),
                  (PREP.TIMERS.COPY + '/' + PREP.TIMERS.TIMER, self.cache_before[0]),
                  (PREP.TIMERS.COPY + '/LICENSE', b'foreign license'),
                  (PREP.TIMERS.COPY + '/' + PREP.TIMERS.TEST, None),
                  ('foreign.go', b'package foreign\n')]
        for relative, bad in faults:
            with self.subTest(relative=relative):
                path = work / relative
                original = path.read_bytes() if path.exists() else None
                try:
                    if bad is None:
                        path.unlink()
                    else:
                        path.write_bytes(bad)
                    with self.assertRaises(ValueError):
                        PREP.verify(self.kit, self.go, self.env)
                    with self.assertRaises(ValueError):
                        PREP.prepare(self.kit, self.go, self.env)
                    self.assertEqual(path.read_bytes() if path.exists() else None, bad)
                finally:
                    if original is None:
                        path.unlink(missing_ok=True)
                    else:
                        path.write_bytes(original)
        PREP.verify(self.kit, self.go, self.env)

    def test_linked_cache_and_shared_modfile_are_not_adopted(self):
        _, work, _ = self.prepared()
        base = work.parent
        elsewhere = self.root / 'foreign-cache'
        base.rename(elsewhere)
        base.symlink_to(elsewhere, target_is_directory=True)
        try:
            with self.assertRaises(ValueError):
                PREP.verify(self.kit, self.go, self.env)
        finally:
            base.unlink()
            elsewhere.rename(base)
        modfile = work / 'go.mod'
        saved = modfile.read_bytes()
        foreign = self.root / 'foreign.mod'
        foreign.write_bytes(saved)
        modfile.unlink()
        os.link(foreign, modfile)
        with self.assertRaises(ValueError):
            PREP.verify(self.kit, self.go, self.env)
        self.assertEqual(foreign.read_bytes(), saved)

    def test_physical_parent_alias_keeps_exact_checkout_and_rejects_linked_kit(self):
        self.prepared()
        alias = self.root / 'parent-alias'
        alias.symlink_to(self.root, target_is_directory=True)
        captured = PREP.checkout_argument(alias / self.kit.name)
        self.assertEqual(captured, self.kit)
        PREP.verify(captured, self.go, self.env)
        linked = self.root / 'linked-kit'
        linked.symlink_to(self.kit, target_is_directory=True)
        with self.assertRaises(ValueError):
            PREP.checkout_argument(linked)

    def test_dirty_and_wrong_pin_checkout_fail_before_creating_dependencies(self):
        modfile = self.kit / PREP.MODULE_ROOT / 'go.mod'
        saved = modfile.read_bytes()
        modfile.write_bytes(saved + b'\n// unrelated source change\n')
        with self.assertRaisesRegex(ValueError, 'remain clean'):
            PREP.prepare(self.kit, self.go, self.env)
        self.assertFalse((self.root / PREP.WORK).exists())
        self.assertTrue(modfile.read_bytes().endswith(b'// unrelated source change\n'))
        modfile.write_bytes(saved)
        subprocess.run(['git', '-C', str(self.kit), '-c', 'user.name=Timer fixture', '-c',
                        'user.email=timer@example.invalid', 'commit', '--quiet', '--allow-empty', '-m', 'Wrong pin control'], check=True)
        with self.assertRaisesRegex(ValueError, 'unchanged WireGuardKit pin'):
            PREP.prepare(self.kit, self.go, self.env)
        self.assertFalse((self.root / PREP.WORK).exists())

    def test_foreign_download_metadata_does_not_publish_a_workspace(self):
        real = PREP.subprocess.check_output

        def changed(command, *args, **kwargs):
            if command[:3] == [self.go, 'mod', 'download']:
                return json.dumps({'Path': PREP.TIMERS.MODULE, 'Version': PREP.TIMERS.VERSION, 'Sum': 'h1:foreign'})
            return real(command, *args, **kwargs)

        with mock.patch.object(PREP.subprocess, 'check_output', side_effect=changed), self.assertRaisesRegex(ValueError, 'original pinned checksum'):
            PREP.prepare(self.kit, self.go, self.env)
        self.assertEqual(list((self.root / PREP.WORK).iterdir()), [])

    def test_ambient_workspace_and_modfile_cannot_override_selected_dependency(self):
        env = dict(self.env, GOWORK=str(self.root / 'foreign.work'), GOFLAGS='-modfile=/foreign/go.mod',
                   GOOS='invalid-target', GOARCH='invalid-target', GOROOT='/foreign/toolchain')
        compiler, captured = PREP.environment(self.go, env)
        PREP.prepare(self.kit, compiler, captured)
        source, work, selected = PREP.verify(self.kit, compiler, captured)
        info = json.loads(subprocess.check_output([compiler, 'list', '-m', '-json', PREP.TIMERS.MODULE], cwd=source, env=selected, text=True))
        self.assertEqual(Path(info['Dir']).resolve(), work / PREP.TIMERS.COPY)

    def test_actual_upstream_make_rebuilds_a_newer_cached_archive(self):
        source, _, selected = self.prepared()
        # Upstream make uses unescaped target names. Its actual Xcode output
        # directories have no spaces; keep that independent native limitation
        # out of the alternate modfile's space-containing path control.
        temporary = tempfile.TemporaryDirectory(prefix='routervpn-apple-make-')
        self.addCleanup(temporary.cleanup)
        make_root = Path(temporary.name).resolve()
        build_root, output = make_root / 'build', make_root / 'output'
        bridge = build_root / 'wireguard-go-bridge'
        (bridge / 'goroot').mkdir(parents=True)
        (bridge / 'goroot/.prepared').touch()
        output.mkdir()
        future = time.time() + 3600
        for path in (bridge / 'libwg-go-arm64.a', output / 'libwg-go.a'):
            path.write_bytes(b'old cached archive')
            os.utime(path, (future, future))
        selected.update(CONFIGURATION_TEMP_DIR=str(build_root), CONFIGURATION_BUILD_DIR=str(output),
                        ARCHS='arm64', SDKROOT='/owned/fixture-sdk', PLATFORM_NAME='iphoneos')
        original = subprocess.run(['make', '-n', '-C', str(source), 'build'], env=selected,
                                  check=True, capture_output=True, text=True)
        self.assertNotIn('go build ', original.stdout)
        real_run, calls = PREP.subprocess.run, []

        def dry_run(command, *args, **kwargs):
            if command[0] != 'make':
                return real_run(command, *args, **kwargs)
            self.assertEqual(command, ['make', '-C', str(source), '-W', 'go.mod', 'build'])
            calls.append(real_run(command + ['-n'], *args, capture_output=True, text=True, **kwargs))
            return calls[-1]

        with mock.patch.object(PREP.platform, 'system', return_value='Darwin'), \
                mock.patch.object(PREP.subprocess, 'run', side_effect=dry_run):
            PREP.build(self.kit, self.go, selected)
        self.assertEqual(len(calls), 1)
        self.assertIn('go build -ldflags=-w -trimpath -v', calls[0].stdout)
        self.assertIn('-buildmode c-archive', calls[0].stdout)
        self.assertIn('lipo -create', calls[0].stdout)
        self.assertNotIn('rsync ', calls[0].stdout)
        self.assertEqual((output / 'libwg-go.a').read_bytes(), b'old cached archive')

    def test_missing_skipped_duplicate_foreign_and_raced_verdicts_are_rejected(self):
        rows = [{'Package': PREP.PACKAGE, 'Test': name, 'Action': action}
                for name in sorted(PREP.REQUIRED) for action in ('run', 'pass')]
        rows.append({'Package': PREP.PACKAGE, 'Action': 'pass'})
        encode = lambda values: '\n'.join(json.dumps(row) for row in values)
        PREP.verdicts(encode(rows))
        for values in ([], rows[:-1], rows[1:], rows + rows[:1],
                       rows + [{'Package': PREP.PACKAGE, 'Action': 'skip'}],
                       rows + [{'Package': 'foreign', 'Test': 'foreign', 'Action': 'pass'}],
                       rows + [{'Output': 'WARNING: DATA RACE'}]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                PREP.verdicts(encode(values))

    def test_real_pinned_timer_controls_execute_through_apple_module_graph(self):
        self.prepared()
        PREP.test(self.kit, self.go, self.env)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kit', required=True, type=Path)
    args, remaining = parser.parse_known_args()
    ORIGINAL = args.kit.resolve()
    unittest.main(argv=[sys.argv[0], *remaining])
