#!/usr/bin/env python3
"""Keep the declared captured transport patch in every prepared native runtime."""
from pathlib import Path
from contextlib import contextmanager
import contextlib
import hashlib
import importlib.util
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT/'deploy'/name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


POLICY = load('native_naive_transport_policy.py')


class NativeNaiveTransport(unittest.TestCase):
    def test_amnezia_checkout_preserves_git_bytes_under_inherited_crlf_policy(self):
        build = load('build-amnezia-runtime.py')
        with tempfile.TemporaryDirectory(prefix='amnezia-source-checkout-') as tmp:
            root = Path(tmp)
            upstream = root/'upstream'
            upstream.mkdir()
            global_config = root/'gitconfig'
            global_config.write_bytes(b'[core]\n\tautocrlf = true\n')
            env = dict(os.environ, GIT_CONFIG_GLOBAL=str(global_config), GIT_CONFIG_NOSYSTEM='1')

            def git(*args):
                return subprocess.check_output(['git', *args], env=env, stderr=subprocess.PIPE, timeout=30)

            git('init', str(upstream))
            git('-C', str(upstream), 'config', '--local', 'core.autocrlf', 'false')
            files = {'go.mod': b'module github.com/sagernet/sing-box\n\ngo 1.26.3\n',
                     'protocol/naive/source.go': b'package naive\n// exact checkout fixture\n'}
            for name, raw in files.items():
                path = upstream/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            git('-C', str(upstream), 'add', '.')
            git('-C', str(upstream), '-c', 'user.name=Source checkout test', '-c',
                'user.email=source-checkout@example.invalid', 'commit', '-m', 'Exact LF fixture')
            revision = git('-C', str(upstream), 'rev-parse', 'HEAD').decode().strip()

            for omit_policy in (False, True):
                with self.subTest(omit_policy=omit_policy):
                    destination = root/('omitted' if omit_policy else 'captured')

                    def captured_run(command, **kwargs):
                        self.assertEqual(kwargs, {})
                        if command[-3:] == ['--local', 'core.autocrlf', 'false'] and omit_policy:
                            return ''
                        command = [str(upstream) if item == 'https://github.com/SagerNet/sing-box.git'
                                   else item for item in command]
                        return subprocess.check_output(command, env=env, stderr=subprocess.PIPE,
                                                       text=True, timeout=30).strip()

                    # Only the remote transport and fixture revision differ;
                    # initialization, configuration, fetch and checkout use Git.
                    with mock.patch.object(build, 'PIN', revision), mock.patch.object(build, 'run', side_effect=captured_run):
                        build.fetch_source(destination)
                    self.assertEqual(git('-C', str(destination), 'rev-parse', 'HEAD').decode().strip(), revision)
                    for name, original in files.items():
                        self.assertEqual(git('-C', str(destination), 'show', revision+':'+name), original)
                        expected = original.replace(b'\n', b'\r\n') if omit_policy else original
                        self.assertEqual((destination/name).read_bytes(), expected)
                    if omit_policy:
                        # Matching HEAD does not authorize converted source.
                        with mock.patch.object(POLICY, 'PIN', revision), self.assertRaisesRegex(
                                ValueError, '^Native Naive transport requires the exact pinned core$'):
                            POLICY.planned_sources(destination)
                    else:
                        self.assertEqual(git('-C', str(destination), 'config', '--local', '--get', 'core.autocrlf'), b'false\n')
            self.assertEqual(global_config.read_bytes(), b'[core]\n\tautocrlf = true\n')

    @contextmanager
    def original(self):
        with tempfile.TemporaryDirectory(prefix='native-naive-transport-source-') as tmp:
            vendor = Path(tmp)
            (vendor/'go.mod').write_text('module github.com/sagernet/sing-box\n')
            original = {
                POLICY.OUTBOUND: b'package naive\nfunc original() {\n'+POLICY.OLD+b'\n\t\tDNSResolver:              dnsResolver,\n}\n',
                'protocol/naive/inbound.go': b'package naive\n// original inbound\n',
                'common/uot/router.go': b'package uot\n// original UoT\n',
            }
            for name, raw in original.items():
                path = vendor/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)

            def git(argv, **kwargs):
                prefix = ['git', '-C', str(vendor)]
                self.assertEqual(argv[:3], prefix)
                suffix = argv[3:]
                if suffix == ['rev-parse', 'HEAD'] and kwargs == {'text': True}:
                    return POLICY.PIN+'\n'
                if suffix == ['ls-tree', '-r', '--name-only', POLICY.PIN, '--', 'protocol/naive', 'common/uot'] and kwargs == {'text': True}:
                    return '\n'.join(sorted(original))+'\n'
                if len(suffix) == 2 and suffix[0] == 'show' and not kwargs:
                    return original[suffix[1].removeprefix(POLICY.PIN+':')]
                raise AssertionError('Unexpected native source read: '+repr(argv))

            with mock.patch.object(POLICY, 'SOURCE_SHA256', hashlib.sha256(original[POLICY.OUTBOUND]).hexdigest()), \
                    mock.patch.object(POLICY.subprocess, 'check_output', side_effect=git), \
                    mock.patch.object(POLICY.LITERAL, 'prepare'), \
                    mock.patch.object(POLICY.LITERAL, 'verify', return_value={}):
                yield vendor, original

    @staticmethod
    def snapshot(vendor):
        return {p.relative_to(vendor).as_posix(): p.read_bytes()
                for p in vendor.rglob('*') if p.is_file()}

    def test_exact_outbound_pin_and_only_cronet_argument_changes(self):
        self.assertEqual(POLICY.SOURCE_SHA256, '9e01f79402408a0325b7e14334c0c8e72183f7963ca5efcc80bf201ea14c59f3')
        self.assertEqual(POLICY.PIN, '1ac1a339cb1223e9c70eae14c44411c75033c02d')
        with self.original() as (_, original):
            raw = original[POLICY.OUTBOUND]
            patched = POLICY.patch(raw)
            self.assertEqual(patched, raw.replace(POLICY.OLD, POLICY.NEW, 1))
            self.assertIn(b"DNSResolver:              dnsResolver,", patched)
            self.assertNotIn(b"routerVPNNaiveDNSResolver", patched)
            self.assertEqual(POLICY.patch(patched), patched)
            for changed in (raw+b'changed', patched+b'changed', patched+POLICY.NEW,
                            patched.replace(b'options.QUIC', b'true'), patched.replace(POLICY.NEW, POLICY.NEW+b' changed')):
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    POLICY.patch(changed)
        with self.assertRaises(ValueError):
            POLICY.patch(b'package naive\n'+POLICY.OLD)

    def test_complete_transaction_and_idempotent_read_only_verification(self):
        with self.original() as (vendor, original):
            with self.assertRaises(ValueError):
                POLICY.verify(vendor)
            POLICY.prepare(vendor)
            POLICY.LITERAL.prepare.assert_called_once_with(vendor)
            POLICY.LITERAL.verify.assert_called_once_with(vendor)
            expected = dict(original)
            expected[POLICY.OUTBOUND] = POLICY.patch(original[POLICY.OUTBOUND])
            expected.update({relative: (ROOT/'mobile/naive'/name).read_bytes()
                             for name, relative in POLICY.TEMPLATES.items()})
            self.assertEqual(POLICY.verify(vendor), {name: hashlib.sha256(raw).hexdigest() for name, raw in expected.items()})
            for name, raw in expected.items():
                self.assertEqual((vendor/name).read_bytes(), raw)
            before = {name: (vendor/name).stat().st_mtime_ns for name in expected}
            POLICY.verify(vendor)
            POLICY.prepare(vendor)
            self.assertEqual(before, {name: (vendor/name).stat().st_mtime_ns for name in expected})

    def test_drift_and_extra_sources_refuse_before_any_write(self):
        subjects = (POLICY.OUTBOUND, 'protocol/naive/inbound.go', 'common/uot/router.go',
                    *POLICY.TEMPLATES.values(), 'protocol/naive/foreign.go')
        for name in subjects:
            with self.subTest(name=name), self.original() as (vendor, _):
                path = vendor/name
                raw = path.read_bytes() if path.exists() else b'package naive\n'
                path.write_bytes(raw+b'// foreign source\n')
                before = self.snapshot(vendor)
                with self.assertRaises(ValueError):
                    POLICY.prepare(vendor)
                self.assertEqual(self.snapshot(vendor), before)

    def test_receipt_rejects_missing_unpatched_or_changed_outputs(self):
        for name in (POLICY.OUTBOUND, *POLICY.TEMPLATES.values()):
            with self.subTest(name=name), self.original() as (vendor, original):
                POLICY.prepare(vendor)
                path = vendor/name
                expected = path.read_bytes()
                path.write_bytes(original.get(name, expected+b'changed'))
                before = self.snapshot(vendor)
                with self.assertRaises(ValueError):
                    POLICY.verify(vendor)
                self.assertEqual(self.snapshot(vendor), before)
                path.write_bytes(expected)
                path.unlink()
                with self.assertRaises(ValueError):
                    POLICY.verify(vendor)

    def test_linked_or_shared_outputs_cannot_mutate_another_owner(self):
        for name in (POLICY.OUTBOUND, *POLICY.TEMPLATES.values()):
            for kind in ('symbolic', 'hard'):
                with self.subTest(name=name, kind=kind), self.original() as (vendor, _):
                    path = vendor/name
                    raw = path.read_bytes() if path.exists() else (ROOT/'mobile/naive'/'transport.go.tmpl').read_bytes()
                    other = vendor/'foreign-owner.go'
                    other.write_bytes(raw)
                    if path.exists(): path.unlink()
                    if kind == 'symbolic': path.symlink_to(other)
                    else: os.link(other, path)
                    before = self.snapshot(vendor)
                    with self.assertRaises(ValueError):
                        POLICY.prepare(vendor)
                    self.assertEqual(self.snapshot(vendor), before)

    def test_all_preparations_and_source_receipts_own_the_policy(self):
        for name, owner in (('prepare-mobile-multihop.py', 'NAIVE'), ('prepare-relay-core.py', 'NAIVE'),
                            ('prepare-desktop-external.py', 'RELAY.NAIVE')):
            module = load(name)
            for path in POLICY.inputs():
                self.assertIn(path, module.inputs())
            self.assertIn(owner+'.prepare(vendor)', (ROOT/'deploy'/name).read_text())
        self.assertIn('m.NAIVE.verify(vendor)', (ROOT/'deploy/test_mobile_imported_entry.py').read_text())
        node = (ROOT/'deploy/test_desktop_node_physical.py').read_text()
        self.assertIn('naive_policy = PREP.RELAY.NAIVE', node)
        self.assertIn('records.update(naive_policy.verify(source))', node)
        self.assertIn('"naive-transport-policy", "./protocol/naive", "^TestRouterVPNNaiveTransport"', node)
        self.assertIn('python3 deploy/test_native_naive_transport_policy.py', (ROOT/'.github/workflows/release-candidate.yml').read_text())

    def test_native_runner_requires_each_original_transport_verdict(self):
        node = load('test_desktop_node_physical.py')
        names = node.NAIVE_TRANSPORT_VERDICTS
        self.assertEqual(len(names), 40)
        self.assertEqual(len(set(names)), 40)
        def output(selected):
            return ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.00s)\n' for name in selected)
        baseline = mock.Mock()
        baseline.execute.return_value = (0, output(names))
        with contextlib.redirect_stdout(io.StringIO()):
            node.execute_baseline_suite(baseline, node.NAIVE_TRANSPORT_SUITE)
        baseline.execute.assert_called_once_with(*node.NAIVE_TRANSPORT_SUITE[:3], 90)
        for missing in names:
            with self.subTest(missing=missing):
                baseline.execute.return_value = (0, output([name for name in names if name != missing]))
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                    node.execute_baseline_suite(baseline, node.NAIVE_TRANSPORT_SUITE)
        for changed in (output([*names, names[0]]), output(names).replace('=== RUN', 'prefix === RUN', 1),
                        output(names)+'--- SKIP: foreign (0.00s)\n', output(names)+'--- FAIL: foreign (0.00s)\n'):
            baseline.execute.return_value = (0, changed)
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                node.execute_baseline_suite(baseline, node.NAIVE_TRANSPORT_SUITE)

    def test_existing_physical_bypass_and_h3_controls_keep_exact_original_source(self):
        node = load('test_desktop_node_physical.py')
        with tempfile.TemporaryDirectory(prefix='naive-original-physical-controls-') as tmp:
            source = Path(tmp)
            path = source/POLICY.OUTBOUND
            path.parent.mkdir(parents=True)
            original = 'package naive\n'+POLICY.NEW.decode()+'\n\t\tQUIC:                     options.QUIC,\n'
            path.write_text(original)
            bypass, downgrade = node.naive_transport_mutants(source)
            self.assertEqual(bypass[:6], ('uncaptured-naive-physical-dial', POLICY.OUTBOUND,
                './protocol/routervpnamnezia', 'TestRouterVPNDesktopNodeNaiveTraffic', 'naive-h2/off',
                'layered graph bypassed its captured socket grants'))
            self.assertEqual(bypass[6], original.replace(POLICY.NEW.decode(), '\t\tDialer:                   N.SystemDialer,', 1))
            self.assertEqual(downgrade[:6], ('downgraded-naive-h3', POLICY.OUTBOUND,
                './protocol/routervpnamnezia', 'TestRouterVPNDesktopNodeNaiveTraffic', 'naive-h3/off',
                'layered encrypted payload escaped or lost its exact native lower'))
            self.assertEqual(downgrade[6], original.replace('QUIC:                     options.QUIC,',
                                                         'QUIC:                     false,', 1))
            for changed in (original.replace(POLICY.NEW.decode(), POLICY.OLD.decode()), original+POLICY.NEW.decode(),
                            original.replace('QUIC:                     options.QUIC,', 'QUIC:                     true,')):
                path.write_text(changed)
                with self.assertRaises(ValueError):
                    node.naive_transport_mutants(source)

    def test_shipping_literal_guards_and_original_hostname_with_causal_mutants(self):
        go = shutil.which('go')
        self.assertIsNotNone(go, 'the native transport policy gate requires Go')
        with tempfile.TemporaryDirectory(prefix='native-naive-transport-go-') as tmp:
            tmp = Path(tmp)
            (tmp/'go.mod').write_text('module routervpn-naive-transport-test\n\ngo 1.26.0\n\nrequire github.com/sagernet/sing v0.9.4\n')
            for name in ('transport.go', 'transport_test.go'):
                (tmp/name).write_bytes((ROOT/'mobile/naive'/(name+'.tmpl')).read_bytes())
            env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off')
            command = [go, 'test', '-mod=mod', '-tags=with_naive_outbound', '-count=1', '-timeout=30s', './...']
            subprocess.run(command[:2]+['-race']+command[2:], cwd=tmp, env=env, check=True, timeout=120)
            path = tmp/'transport.go'
            original = path.read_text()
            controls = (
                ('h2-unwrapped', original.replace('return &routerVPNNaiveH2Transport{original: original}', 'return original', 1), 'H2'),
                ('h2-datagram-dial', original.replace('if network != N.NetworkTCP {', 'if false {', 1), 'H2'),
                ('h3-unwrapped', original.replace('return &routerVPNNaiveH3Transport{original: original, peer: peer}', 'return original', 1), 'H3'),
                ('h3-foreign-tuple', original.replace('destination != d.peer || ', '', 1), 'H3'),
                ('h3-tcp-authority', original.replace('network != N.NetworkUDP || ', '', 1), 'H3'),
                ('h3-invalid-peer', original.replace('!d.peer.Addr.IsValid() || d.peer.Fqdn != "" ||\n\t\td.peer.Port == 0 || d.peer.Addr.Zone() != "" || d.peer.Addr.Is4In6() || d.peer.Addr.IsUnspecified() || d.peer.Addr.IsMulticast()', 'false', 1), 'H3'),
                ('raw-hostname-wrapped', original.replace('if peer.Fqdn != "" {', 'if false {', 1), 'RawHostname'),
            )
            for name, changed, root in controls:
                self.assertNotEqual(changed, original, name)
                path.write_text(changed)
                result = subprocess.run(command+["-run=^TestRouterVPNNaiveTransport"+root+"$"], cwd=tmp, env=env, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, timeout=120)
                self.assertEqual(result.returncode, 1, name+' did not fail the original policy boundary\n'+result.stdout)
                self.assertIn('--- FAIL: TestRouterVPNNaiveTransport'+root, result.stdout)
                self.assertNotIn('build failed', result.stdout)
                self.assertNotIn('DATA RACE', result.stdout)
                self.assertNotIn('panic:', result.stdout)
            print('Shipping literal H2/H3 transport and original raw-hostname ownership passed with seven causal controls')


if __name__ == '__main__':
    unittest.main()
