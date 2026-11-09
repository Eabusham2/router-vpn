#!/usr/bin/env python3
"""Retain the exact Cronet source and captured IPv6 resolver authority."""
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT/'deploy'/name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


POLICY = load('native_naive_literal_policy.py')


class NativeNaiveLiteral(unittest.TestCase):
    @contextmanager
    def source(self):
        with tempfile.TemporaryDirectory(prefix='naive-literal-source-') as name:
            base = Path(name)
            vendor = base/'core'
            vendor.mkdir()
            (vendor/'go.mod').write_text('module github.com/sagernet/sing-box\n')
            (vendor/'go.sum').write_text('original checksum record\n')
            original = {POLICY.SOURCE: b'package cronet\nfunc original() {\n'+POLICY.NAME_OLD+POLICY.OLD+b'}\n',
                        'go.mod': b'module github.com/sagernet/cronet-go\n',
                        'LICENSE': b'original module license\n', 'sub/source.go': b'package sub\n'}
            archive = base/'module.zip'
            with zipfile.ZipFile(archive, 'w') as output:
                for path, raw in original.items():
                    output.writestr(POLICY.PREFIX+path, raw)
            digest = POLICY.h1([(POLICY.PREFIX+path, hashlib.sha256(raw).hexdigest()) for path, raw in original.items()])
            state = {'replace': []}

            def read(argv, **kwargs):
                if argv == ['git', '-C', str(vendor), 'rev-parse', 'HEAD']:
                    return POLICY.CORE+'\n'
                self.assertEqual(kwargs, {'cwd': vendor, 'text': True})
                if argv == ['go', 'mod', 'edit', '-json']:
                    return json.dumps({'Require': [{'Path': POLICY.MODULE, 'Version': POLICY.VERSION}], 'Replace': state['replace']})
                if argv == ['go', 'mod', 'download', '-json', POLICY.MODULE+'@'+POLICY.VERSION]:
                    return json.dumps({'Path': POLICY.MODULE, 'Version': POLICY.VERSION, 'Sum': digest, 'Zip': str(archive)})
                raise AssertionError('Unexpected dependency read: '+repr(argv))

            def edit(argv, **kwargs):
                self.assertEqual(argv, ['go', 'mod', 'edit', '-replace='+POLICY.MODULE+'@'+POLICY.VERSION+'=./'+POLICY.COPY])
                self.assertEqual(kwargs, {'cwd': vendor, 'check': True})
                state['replace'] = [{'Old': {'Path': POLICY.MODULE, 'Version': POLICY.VERSION}, 'New': {'Path': './'+POLICY.COPY}}]

            with mock.patch.object(POLICY, 'SUM', digest), \
                    mock.patch.object(POLICY, 'SOURCE_SHA256', hashlib.sha256(original[POLICY.SOURCE]).hexdigest()), \
                    mock.patch.object(POLICY.subprocess, 'check_output', side_effect=read), \
                    mock.patch.object(POLICY.subprocess, 'run', side_effect=edit):
                yield vendor, archive, original, state

    def test_pinned_complete_module_and_single_engine_projection(self):
        self.assertEqual(POLICY.SUM, 'h1:CsvsLVIli53L6nzgEpyRjjWnRRhTds4D3eh5sEnF5Sw=')
        self.assertEqual(POLICY.SOURCE_SHA256, '367a29cbc783270e07f00d28d77f6b463033805bf4e100b53100f9373bf0f5a5')
        self.assertEqual(POLICY.VERSION, 'v0.0.0-20260912104727-0d28acc44093')
        with self.source() as (vendor, _, original, _):
            POLICY.prepare(vendor)
            records = POLICY.verify(vendor)
            self.assertEqual(set(records), {POLICY.COPY+'/'+name for name in (*original, *POLICY.TEMPLATES.values())})
            for name, raw in original.items():
                actual = (vendor/POLICY.COPY/name).read_bytes()
                self.assertEqual(actual, raw.replace(POLICY.NAME_OLD, POLICY.NAME_NEW, 1).replace(POLICY.OLD, POLICY.NEW, 1) if name == POLICY.SOURCE else raw)
                self.assertEqual(POLICY.transform(name, actual, reverse=True), raw)
            before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (vendor/POLICY.COPY).rglob('*') if p.is_file()}
            POLICY.prepare(vendor)
            POLICY.verify(vendor)
            self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before})

    def test_original_or_partial_engine_drift_refuses_before_publication(self):
        with self.source() as (_, _, original, _):
            raw = original[POLICY.SOURCE]
            projected = POLICY.transform(POLICY.SOURCE, raw)
            for changed, reverse in ((raw+b'foreign', False), (raw+POLICY.OLD, False),
                                     (projected+b'foreign', True), (raw, True),
                                     (projected.replace(b'c.quicEnabled', b'false'), True),
                                     (projected.replace(b'config.QUIC', b'true'), True),
                                     (raw.replace(POLICY.OLD, POLICY.NEW, 1), True),
                                     (raw.replace(POLICY.NAME_OLD, POLICY.NAME_NEW, 1), True)):
                with self.subTest(reverse=reverse, changed=changed), self.assertRaises(ValueError):
                    POLICY.transform(POLICY.SOURCE, changed, reverse=reverse)

    def test_archive_checksum_and_member_ownership_before_publication(self):
        for fault in ('changed', 'foreign-prefix', 'escape', 'duplicate', 'injected-helper', 'symlink'):
            with self.subTest(fault=fault), self.source() as (vendor, archive, original, _):
                with zipfile.ZipFile(archive, 'w') as output:
                    for name, raw in original.items():
                        output.writestr(POLICY.PREFIX+name, raw+b'foreign' if fault == 'changed' and name == 'LICENSE' else raw)
                    extra = {'foreign-prefix': 'foreign/file', 'escape': POLICY.PREFIX+'../foreign',
                             'duplicate': POLICY.PREFIX+'LICENSE', 'injected-helper': POLICY.PREFIX+'routervpn_naive_literal.go',
                             'symlink': POLICY.PREFIX+'link'}.get(fault)
                    if extra:
                        info = zipfile.ZipInfo(extra)
                        if fault == 'symlink': info.external_attr = 0o120777 << 16
                        output.writestr(info, b'foreign')
                with self.assertRaises(ValueError): POLICY.prepare(vendor)
                self.assertFalse((vendor/POLICY.COPY).exists())

    def test_prepared_source_missing_changed_or_extra_is_never_repaired_silently(self):
        for name in (POLICY.SOURCE, 'LICENSE', 'routervpn_naive_literal.go', 'routervpn_naive_literal_test.go', 'foreign.go'):
            with self.subTest(name=name), self.source() as (vendor, _, _, _):
                POLICY.prepare(vendor)
                path = vendor/POLICY.COPY/name
                raw = path.read_bytes() if path.exists() else b''
                path.write_bytes(raw+b'foreign')
                for operation in (POLICY.prepare, POLICY.verify):
                    with self.assertRaises(ValueError): operation(vendor)
                self.assertEqual(path.read_bytes(), raw+b'foreign')
                path.unlink()
                if name != 'foreign.go':
                    with self.assertRaises(ValueError): POLICY.verify(vendor)

    def test_shared_or_linked_source_has_no_write_authority(self):
        for name in ('go.mod', 'go.sum', POLICY.COPY+'/LICENSE', POLICY.COPY+'/routervpn_naive_literal.go'):
            for kind in ('symbolic', 'hard'):
                with self.subTest(name=name, kind=kind), self.source() as (vendor, _, _, _):
                    POLICY.prepare(vendor)
                    path = vendor/name
                    original = path.read_bytes()
                    other = vendor.parent/'original-owner'
                    other.write_bytes(original)
                    path.unlink()
                    if kind == 'symbolic': path.symlink_to(other)
                    else: os.link(other, path)
                    with self.assertRaises(ValueError): POLICY.prepare(vendor)
                    self.assertEqual(other.read_bytes(), original)

    def test_foreign_replacement_version_or_checkout_refuses(self):
        for replacement in ([{'Old': {'Path': POLICY.MODULE}, 'New': {'Path': './'+POLICY.COPY}}],
                            [{'Old': {'Path': POLICY.MODULE, 'Version': POLICY.VERSION}, 'New': {'Path': '../foreign'}}]):
            with self.subTest(replacement=replacement), self.source() as (vendor, _, _, state):
                state['replace'] = replacement
                with self.assertRaises(ValueError): POLICY.prepare(vendor)
                self.assertFalse((vendor/POLICY.COPY).exists())
        with self.source() as (vendor, _, _, _):
            with mock.patch.object(POLICY.subprocess, 'check_output', return_value=json.dumps({'Require': [{'Path': POLICY.MODULE, 'Version': 'foreign'}]})), self.assertRaises(ValueError):
                POLICY.module_plan(vendor)
            with mock.patch.object(POLICY.subprocess, 'check_output', return_value='foreign\n'), self.assertRaises(ValueError):
                POLICY.checked_vendor(vendor)
            with self.assertRaises(ValueError): POLICY.module_plan(vendor, required=True)

    def test_all_shipping_preparations_and_receipts_require_literal_source(self):
        transport = load('native_naive_transport_policy.py')
        for path in POLICY.inputs(): self.assertIn(path, transport.inputs())
        for name in ('prepare-mobile-multihop.py', 'prepare-relay-core.py', 'prepare-desktop-external.py'):
            preparation = load(name)
            for path in POLICY.inputs(): self.assertIn(path, preparation.inputs())
        text = (ROOT/'deploy/native_naive_transport_policy.py').read_text()
        self.assertIn('LITERAL.prepare(vendor)', text)
        self.assertIn('LITERAL.verify(vendor)', text)
        self.assertIn('python3 deploy/test_native_naive_literal_policy.py', (ROOT/'.github/workflows/release-candidate.yml').read_text())

    def test_native_peer_gate_requires_each_original_ipv6_and_refusal_verdict(self):
        node = load('test_desktop_node_physical.py')
        names = node.NAIVE_LITERAL_VERDICTS
        self.assertEqual(len(names), 24)
        self.assertEqual(len(names), len(set(names)))
        self.assertIn('TestRouterVPNDesktopNodeNaiveLiteral/literal-ipv6-with-udp-bootstrap', names)
        self.assertIn('TestRouterVPNDesktopNodeNaiveLiteral/ipv6-wrong-certificate', names)
        for leaf in ('ipv4-trailing-dot-name', 'ipv6-trailing-dot-name', 'ipv4-dotted-wrong-server-name',
                     'ipv4-dotted-wrong-certificate', 'ipv6-dotted-wrong-server-name', 'ipv6-dotted-wrong-certificate'):
            self.assertIn('TestRouterVPNDesktopNodeNaiveLiteral/'+leaf, names)
        def output(selected):
            return ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.00s)\n' for name in selected)
        baseline = mock.Mock()
        baseline.execute.return_value = (0, output(names))
        with redirect_stdout(io.StringIO()): node.execute_baseline_suite(baseline, node.NAIVE_LITERAL_SUITE)
        baseline.execute.assert_called_once_with(*node.NAIVE_LITERAL_SUITE[:3], 90)
        for missing in names:
            baseline.execute.return_value = (0, output([name for name in names if name != missing]))
            with self.subTest(missing=missing), redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                node.execute_baseline_suite(baseline, node.NAIVE_LITERAL_SUITE)
        for changed in (output([*names, names[0]]), output(names)+'--- SKIP: foreign (0.00s)\n', output(names)+'--- FAIL: foreign (0.00s)\n'):
            baseline.execute.return_value = (0, changed)
            with redirect_stdout(io.StringIO()), self.assertRaises(ValueError): node.execute_baseline_suite(baseline, node.NAIVE_LITERAL_SUITE)

    def test_shipping_mapping_and_instruction_refusal_with_causal_controls(self):
        go = shutil.which('go')
        self.assertIsNotNone(go, 'the native literal policy gate requires Go')
        with tempfile.TemporaryDirectory(prefix='native-naive-literal-go-') as name:
            directory = Path(name)
            (directory/'go.mod').write_text('module routervpn-naive-literal-test\n\ngo 1.26.0\n\nrequire github.com/sagernet/sing v0.9.4\n')
            for source, target in POLICY.TEMPLATES.items():
                (directory/target).write_bytes((ROOT/'mobile/naive'/source).read_bytes())
            env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off')
            command = [go, 'test', '-mod=mod', '-count=1', '-timeout=30s', './...']
            subprocess.run(command[:2]+['-race']+command[2:], cwd=directory, env=env, check=True, timeout=120)
            path = directory/'routervpn_naive_literal.go'
            original = path.read_text()
            for label, changed, root in (
                ('h3-rewritten', original.replace('if quic || !address.Addr.Is6()', 'if !address.Addr.Is6()'), 'TestRouterVPNNaiveLiteralRule'),
                ('mapping-disabled', original.replace('if quic || !address.Addr.Is6()', 'if true || quic || !address.Addr.Is6()'), 'TestRouterVPNNaiveLiteralRule'),
                ('instructions-accepted', original.replace('return errors.New("Naive resolver rule has an unsafe hostname")', 'continue'), 'TestRouterVPNNaiveLiteralRule'),
                ('wire-name-unchanged', original.replace('if quic || !strings.HasSuffix(name, ".") {', 'if true {'), 'TestRouterVPNNaiveWireName'),
                ('h3-wire-name-changed', original.replace('if quic || !strings.HasSuffix(name, ".") {', 'if !strings.HasSuffix(name, ".") {'), 'TestRouterVPNNaiveWireName'),
            ):
                self.assertNotEqual(changed, original)
                path.write_text(changed)
                result = subprocess.run(command, cwd=directory, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
                self.assertEqual(result.returncode, 1, label+' did not reject the original authority loss\n'+result.stdout)
                self.assertIn('--- FAIL: '+root, result.stdout)
                self.assertNotIn('build failed', result.stdout)
                self.assertNotIn('DATA RACE', result.stdout)


if __name__ == '__main__':
    unittest.main()
