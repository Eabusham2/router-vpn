#!/usr/bin/env python3
"""Reject missing native verdicts, changed images and unpinned route transforms."""
from pathlib import Path
import hashlib
import contextlib
import io
import importlib.util
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('darwin_route_gate_test', ROOT / 'deploy/test_desktop_darwin_route.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def transcript(mutant=False):
    roots = G.GROUPS[:1] if mutant else (*G.GROUPS, *G.INVENTORY_CASES)
    lines = []
    for root in roots:
        lines.append('=== RUN   ' + root)
        for case in G.INVENTORY_CASES.get(root, ('ipv4', 'ipv6')):
            name = root + '/' + case
            lines.append('=== RUN   ' + name)
            if mutant:
                lines.append('    route_test.go:1: ' + G.WITNESS + ': expected original EEXIST, got <nil>')
            lines.append('    --- ' + ('FAIL' if mutant else 'PASS') + ': ' + name + ' (0.01s)')
        lines.append('--- ' + ('FAIL' if mutant else 'PASS') + ': ' + root + ' (0.02s)')
    lines.append('FAIL' if mutant else 'PASS')
    return '\n'.join(lines) + '\n'


class DarwinRouteVerdicts(unittest.TestCase):
    def test_exact_positive_and_actual_takeover_negative(self):
        G.check_verdicts(transcript())
        G.check_verdicts(transcript(True), mutant=True)

    def test_every_missing_line_is_rejected(self):
        for mutant in (False, True):
            lines = transcript(mutant).splitlines()
            for index in range(len(lines)):
                with self.subTest(mutant=mutant, omitted=index), self.assertRaises(ValueError):
                    G.check_verdicts('\n'.join(lines[:index] + lines[index + 1:]), mutant=mutant)

    def test_duplicate_skip_foreign_race_and_wrong_verdict_are_rejected(self):
        original = transcript()
        first = G.GROUPS[0]
        variants = (
            original + '=== RUN   ' + first + '\n',
            original + '--- PASS: ' + first + ' (0.1s)\n',
            original.replace('--- PASS:', '--- SKIP:', 1),
            original.replace('--- PASS:', '--- FAIL:', 1),
            original.replace(first, first + 'Foreign'),
            original + 'WARNING: DATA RACE\n',
            original.replace('=== RUN   ' + first + '\n', ''),
        )
        for output in variants:
            with self.subTest(output=output[-100:]), self.assertRaises(ValueError):
                G.check_verdicts(output)

    def test_mutant_requires_both_exact_takeover_witnesses(self):
        for output in (transcript(True).replace(G.WITNESS, 'another failure', 1),
                       transcript(True).replace('expected original EEXIST', 'different boundary'),
                       transcript(True).replace('--- FAIL:', '--- PASS:', 1)):
            with self.assertRaises(ValueError):
                G.check_verdicts(output, mutant=True)

    def test_other_host_refuses_before_source_or_privilege(self):
        with patch.object(G.platform, 'system', return_value='Linux'), \
             patch.object(G, 'checked_sources') as sources, patch.object(G.UID, 'privilege_tool') as privilege:
            with self.assertRaisesRegex(ValueError, 'matching native host'):
                G.execute(Path('absent'))
            sources.assert_not_called()
            privilege.assert_not_called()


class DarwinRouteSelectedModule(unittest.TestCase):
    def test_exact_local_module_and_foreign_replacements(self):
        with tempfile.TemporaryDirectory(prefix='darwin-route-module-') as temporary:
            source = Path(temporary).resolve()
            native = source / 'routervpn-desktop-tun'
            original = {'Path': G.MTU.MODULE, 'Version': G.MTU.VERSION, 'Dir': str(native),
                        'Replace': {'Path': './routervpn-desktop-tun', 'Dir': str(native)}}
            G.verify_selected_module(original, source)
            import copy
            for fault in ('pin', 'module', 'missing', 'alias', 'foreign-dir', 'replacement-version', 'replacement-sum', 'nested'):
                changed = copy.deepcopy(original)
                if fault == 'pin': changed['Version'] = 'v0.0.0'
                elif fault == 'module': changed['Path'] = 'example.invalid/other'
                elif fault == 'missing': del changed['Replace']
                elif fault == 'alias': changed['Replace']['Path'] = str(native)
                elif fault == 'foreign-dir': changed['Replace']['Dir'] = str(source / 'foreign')
                elif fault == 'replacement-version': changed['Replace']['Version'] = 'v0.0.0'
                elif fault == 'replacement-sum': changed['Replace']['Sum'] = 'h1:foreign'
                elif fault == 'nested': changed['Replace']['Replace'] = {}
                with self.subTest(fault=fault), self.assertRaises(ValueError):
                    G.verify_selected_module(changed, source)


class DarwinRouteCapturedImage(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='darwin-route-image-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.image = self.root / 'fixture.test'
        self.raw = b'exact owned fixture image\n'
        self.image.write_bytes(self.raw)
        self.image.chmod(0o700)
        self.expected = hashlib.sha256(self.raw).hexdigest()

    def test_exact_original_image(self):
        self.assertEqual(G.captured_image(self.image, self.expected), self.raw)

    def test_changed_image_hash_and_malformed_digest_rejected(self):
        for value in ('0' * 64, 'A' * 64, 'abc'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                G.captured_image(self.image, value)

    def test_link_hardlink_and_other_owner_writes_rejected(self):
        alias = self.root / 'alias.test'
        alias.symlink_to(self.image)
        with self.assertRaises(OSError):
            G.captured_image(alias, self.expected)
        alias.unlink()
        os.link(self.image, alias)
        with self.assertRaises(ValueError):
            G.captured_image(self.image, self.expected)
        alias.unlink()
        self.image.chmod(0o722)
        with self.assertRaises(ValueError):
            G.captured_image(self.image, self.expected)

    def test_named_replacement_during_capture_rejected(self):
        real_fstat = os.fstat
        calls = 0
        def fstat(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                replacement = self.root / 'replacement'
                replacement.write_bytes(self.raw)
                replacement.chmod(0o700)
                replacement.replace(self.image)
            return real_fstat(descriptor)
        with patch.object(G.os, 'fstat', side_effect=fstat), self.assertRaisesRegex(ValueError, 'changed during original capture'):
            G.captured_image(self.image, self.expected)


class DarwinRouteJoinedCleanup(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='darwin-route-cleanup-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / 'owned'
        self.root.mkdir()
        self.image = self.root / 'route.test'
        self.image.write_bytes(b'original captured route test')
        self.image.chmod(0o500)
        self.expected = G.digest(self.image)

    def test_unknown_completion_preserves_image_and_records_without_cleanup(self):
        record = self.root / 'ipv4-true.json'
        record.write_bytes(b'original native recovery record')
        failure = RuntimeError('process group could not be joined')
        with patch.object(G.UID, 'run', side_effect=failure) as run, contextlib.redirect_stderr(io.StringIO()), self.assertRaises(RuntimeError) as raised:
            G.run_fixture_image(self.root, self.image, self.expected, False)
        self.assertIs(raised.exception, failure)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(G.digest(self.image), self.expected)
        self.assertEqual(record.read_bytes(), b'original native recovery record')

    def test_successful_join_permits_exact_cleanup_then_removes_private_image(self):
        with patch.object(G.UID, 'run', side_effect=['actual native result\n', '']) as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(G.run_fixture_image(self.root, self.image, self.expected, False), 0)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[1].args[0], [self.image, 'routervpn-darwin-route-cleanup'])
        self.assertFalse(self.root.exists())

    def test_failed_but_joined_child_preserves_exit_after_owned_cleanup(self):
        failure = subprocess.CalledProcessError(1, ['original'], output=b'original native failure\n')
        with patch.object(G.UID, 'run', side_effect=[failure, '']) as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(G.run_fixture_image(self.root, self.image, self.expected, True), 1)
        self.assertEqual(run.call_count, 2)
        self.assertFalse(self.root.exists())

    def test_cleanup_failure_or_changed_image_keeps_recovery_directory(self):
        failure = subprocess.CalledProcessError(1, ['cleanup'], output=b'changed native route')
        with patch.object(G.UID, 'run', side_effect=['joined native result\n', failure]) as run, contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, 'retained its protected recovery'):
            G.run_fixture_image(self.root, self.image, self.expected, False)
        self.assertEqual(run.call_count, 2)
        self.assertTrue(self.image.exists())
        def replace(command, **kwargs):
            other = self.root / 'new-image'
            other.write_bytes(self.image.read_bytes())
            other.chmod(0o500)
            other.replace(self.image)
            return 'joined native result\n'
        with patch.object(G.UID, 'run', side_effect=replace) as run, contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, 'retained its protected recovery'):
            G.run_fixture_image(self.root, self.image, self.expected, False)
        self.assertEqual(run.call_count, 1)
        self.assertTrue(self.image.exists())


class DarwinRouteTransformation(unittest.TestCase):
    def setUp(self):
        # A bounded source model tests transformation/rejection mechanics. The
        # actual pinned blob and generated method are separately verified and
        # compiled by the matching-host native gate.
        self.raw = b'package tun\nimport (\n\t"errors"\n)\n' + G.MTU.DARWIN_ROUTE_TAKEOVER + b'\n'
        self.hash = hashlib.sha256(self.raw).hexdigest()

    def test_exact_guard_changes_only_takeover_and_unused_import(self):
        with patch.object(G.MTU, 'DARWIN_SOURCE_SHA256', self.hash):
            actual = G.MTU.darwin_route_conflict_patch(self.raw)
        self.assertEqual(actual, self.raw.replace(G.MTU.DARWIN_ROUTE_TAKEOVER, G.MTU.DARWIN_ROUTE_REFUSAL, 1).replace(b'\t"errors"\n', b'', 1))
        self.assertNotIn(b'RTM_DELETE', actual)
        self.assertIn(b'return E.Cause(err, "add route: ", destination)', actual)

    def test_changed_blob_and_already_transformed_input_refused(self):
        with patch.object(G.MTU, 'DARWIN_SOURCE_SHA256', self.hash):
            fixed = G.MTU.darwin_route_conflict_patch(self.raw)
            for changed in (self.raw + b'\n', self.raw.replace(b'package tun', b'package other'), fixed):
                with self.assertRaisesRegex(ValueError, 'source changed'):
                    G.MTU.darwin_route_conflict_patch(changed)

    def test_missing_duplicate_or_changed_guard_refused_even_with_model_hash(self):
        variants = (self.raw.replace(G.MTU.DARWIN_ROUTE_TAKEOVER, b''),
                    self.raw + G.MTU.DARWIN_ROUTE_TAKEOVER,
                    self.raw.replace(b'\t"errors"\n', b''), self.raw + b'errors.New("different use")\n')
        for raw in variants:
            with self.subTest(raw=raw[-70:]), patch.object(G.MTU, 'DARWIN_SOURCE_SHA256', hashlib.sha256(raw).hexdigest()), self.assertRaisesRegex(ValueError, 'boundary changed'):
                G.MTU.darwin_route_conflict_patch(raw)

    def test_native_negative_overlay_restores_only_original_route_branch(self):
        with tempfile.TemporaryDirectory(prefix='darwin-route-overlay-') as temporary:
            root = Path(temporary).resolve()
            target = root / 'routervpn-desktop-tun/tun_darwin.go'
            target.parent.mkdir()
            raw = b'package tun\nimport (\n)\n' + G.MTU.DARWIN_ROUTE_REFUSAL + b'\n'
            target.write_bytes(raw)
            overlay = G.restore_takeover_overlay(root, root)
            import json
            mapping = json.loads(overlay.read_text())['Replace']
            self.assertEqual(set(mapping), {str(target)})
            expected = raw.replace(G.MTU.DARWIN_ROUTE_REFUSAL, G.MTU.DARWIN_ROUTE_TAKEOVER.replace(b'err = execRoute(', b'err = t.routervpnExecRoute('), 1).replace(b'import (\n', b'import (\n\t"errors"\n', 1)
            self.assertEqual(Path(mapping[str(target)]).read_bytes(), expected)
            self.assertEqual(target.read_bytes(), raw)

    def test_changed_native_overlay_seam_refused_before_write(self):
        with tempfile.TemporaryDirectory(prefix='darwin-route-overlay-') as temporary:
            root = Path(temporary).resolve()
            target = root / 'routervpn-desktop-tun/tun_darwin.go'
            target.parent.mkdir()
            target.write_bytes(b'package tun\nimport (\n)\n')
            with self.assertRaises(ValueError):
                G.restore_takeover_overlay(root, root)
            self.assertFalse((root / 'takeover.go').exists())
            self.assertFalse((root / 'takeover-overlay.json').exists())


if __name__ == '__main__':
    unittest.main()
