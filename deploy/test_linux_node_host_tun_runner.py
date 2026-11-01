#!/usr/bin/env python3
"""Require real installed-host lifecycle evidence and exact namespace inputs."""
from pathlib import Path
from contextlib import redirect_stderr
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installed_linux_host_runner', ROOT / 'deploy/test_linux_node_host_tun.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class InstalledLinuxHostVerdict(unittest.TestCase):
    def completed(self, cases=None):
        cases = G.CASES if cases is None else cases
        prefix = '--- PASS: TestDesktopLinuxGuardianKernelNodeHostTUN'
        return '\n'.join([prefix + ' (0.1s)', *(prefix + '/' + case + ' (0.1s)' for case in cases),
                          *('    native_test.go:1: verified installed host native lifecycle: ' + case for case in cases),
                          *('    native_test.go:2: verified installed host active lifetime: ' + case for case in cases if case in G.ACTIVE_CASES),
                          *('    native_test.go:3: verified installed host retained DNS observation: ' + case for case in cases if case in ('active-request-ended', *G.PUBLIC_CASES)),
                          *('    native_test.go:4: verified installed host original MTU lease: ' + case for case in cases if case in G.MTU_CASES),
                          *('    native_test.go:5: verified installed host live MTU status: ' + case for case in cases if case in ('active-request-ended', *G.PUBLIC_CASES) or case.startswith('mtu-')),
                          *('    native_test.go:6: verified installed host sealed temporary restoration: ' + case for case in cases if case in G.RESTORE_CASES),
                          *('    native_test.go:7: verified installed host public Connect and Disconnect: ' + case for case in cases if case in G.PUBLIC_CASES),
                          *('    native_test.go:8: verified installed host native cover: ' + case for case in cases if case in G.COVER_CASES),
                          *('    native_test.go:9: verified installed host saved Linux protection Off: ' + case for case in cases if case in G.OFF_CASES),
                          *('    native_test.go:10: verified installed host captured Start Layer: ' + case for case in cases if case in G.LAYER_CASES),
                          *('    native_test.go:11: verified installed host plain WireGuard: ' + case for case in cases if case in G.WIREGUARD_CASES)]) + '\n'

    def test_requires_every_real_positive_negative_and_joined_lifecycle(self):
        output = self.completed()
        G.check_verdict(output)
        for line in output.splitlines():
            with self.subTest(line=line), self.assertRaises(ValueError):
                G.check_verdict(output.replace(line, ''))

    def test_same_architecture_and_case_remain_required(self):
        for case in G.CASES:
            output = self.completed((case,))
            G.check_verdict(output, case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                G.check_verdict(output)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(), 'unrelated')

    def test_failed_skipped_or_child_only_output_cannot_replace_installed_host(self):
        for output in ('', '--- PASS: TestDesktopLinuxGuardianKernelNodeChildCommandTUN (1s)',
                       '--- PASS: TestDesktopLinuxGuardianKernelNodeRouterHealthPeer (1s)',
                       self.completed() + '--- FAIL: original-controller (1s)', self.completed() + '--- SKIP: unavailable-TUN (1s)'):
            with self.subTest(output=output[-100:]), self.assertRaises(ValueError):
                G.check_verdict(output)

    def test_failed_original_child_retains_status_and_bounded_native_output(self):
        for noisy in (False, True):
            with self.subTest(noisy=noisy):
                command = [sys.executable, '-c',
                           'import os; ' + ("os.write(1, b'old-prefix\\n' + b'x' * 60000 + b'\\xff'); "
                           "os.write(2, b'original installed host failure\\n'); " if noisy else '') + 'raise SystemExit(37)']
                failures = []
                def failed(source, bundle, go, *, receipt_path):
                    self.assertEqual((source, bundle, go, receipt_path),
                                     (Path('/captured-core'), Path('/captured-bundle'), '/captured-go', Path('/captured-receipt')))
                    try:
                        G.GUARD.UID.run(command, timeout=5)
                    except subprocess.CalledProcessError as error:
                        failures.append(error)
                        raise
                diagnostic = io.StringIO()
                with patch.object(G, 'execute', side_effect=failed), redirect_stderr(diagnostic):
                    with self.assertRaises(subprocess.CalledProcessError) as caught:
                        G.main(['/captured-core', '--bundle', '/captured-bundle', '--go', '/captured-go', '--receipt', '/captured-receipt'])
                self.assertEqual(len(failures), 1)
                self.assertIs(caught.exception, failures[0])
                self.assertEqual(caught.exception.returncode, 37)
                self.assertEqual(caught.exception.cmd, command)
                original = caught.exception.output
                self.assertEqual(diagnostic.getvalue(), original[-32768:].decode('utf-8', errors='replace'))
                if noisy:
                    self.assertNotIn('old-prefix', diagnostic.getvalue())
                    self.assertIn('\uFFFDoriginal installed host failure', diagnostic.getvalue())
                    self.assertLessEqual(len(diagnostic.getvalue()), 32768)
                else:
                    self.assertEqual(diagnostic.getvalue(), '')

    def test_cli_preserves_success_namespace_and_other_failure_types(self):
        arguments = ['/captured-core', '--bundle', '/captured-bundle', '--go', '/captured-go']
        diagnostic = io.StringIO()
        with patch.object(G, 'execute') as execute, redirect_stderr(diagnostic):
            G.main(arguments)
        execute.assert_called_once_with(Path('/captured-core'), Path('/captured-bundle'), '/captured-go', receipt_path=None)
        self.assertEqual(diagnostic.getvalue(), '')
        with patch.object(G, 'namespace_test', return_value=23) as enter, patch.object(G, 'execute') as execute:
            with self.assertRaises(SystemExit) as caught:
                G.main(['--bundle', '/captured-bundle', '--namespace-test-binary', '/captured-controller',
                        '--peer-binary', '/captured-peer', '--namespace-test-sha256', 'a' * 64,
                        '--peer-sha256', 'b' * 64, '--bundle-sha256', 'c' * 64, '--case', 'home-lan'])
        self.assertEqual(caught.exception.code, 23)
        enter.assert_called_once_with(Path('/captured-controller'), Path('/captured-peer'), Path('/captured-bundle'),
                                      'a' * 64, 'b' * 64, 'c' * 64, 'home-lan', whitening=None, whitening_sha256=None)
        execute.assert_not_called()
        for error in (subprocess.TimeoutExpired(['original-child'], 5), ValueError('original native validation')):
            diagnostic = io.StringIO()
            with self.subTest(error=type(error).__name__), patch.object(G, 'execute', side_effect=error), redirect_stderr(diagnostic):
                with self.assertRaises(type(error)) as caught:
                    G.main(arguments)
            self.assertIs(caught.exception, error)
            self.assertEqual(diagnostic.getvalue(), '')

    def images(self, root):
        images = []
        for name in ('controller', 'peer'):
            path = root / name
            path.write_bytes(name.encode())
            path.chmod(0o755)
            images.append((path, hashlib.sha256(path.read_bytes()).hexdigest()))
        bundle = root / 'bundle'
        bundle.mkdir()
        receipt = bundle / 'NATIVE-RUNTIME.json'
        receipt.write_bytes(b'{"original":"receipt boundary; complete verifier remains native"}')
        receipt.chmod(0o644)
        return (*images, bundle, hashlib.sha256(receipt.read_bytes()).hexdigest())

    def test_foreign_compiled_image_or_bundle_never_enters_namespace(self):
        with tempfile.TemporaryDirectory() as temporary:
            (binary, image_sha), (peer, peer_sha), bundle, bundle_sha = self.images(Path(temporary).resolve())
            cases = ((image_sha, peer_sha, '0' * 64, 'on-connect'),
                     (image_sha, '0' * 64, bundle_sha, 'on-connect'),
                     ('0' * 64, peer_sha, bundle_sha, 'on-connect'),
                     (image_sha, peer_sha, bundle_sha, 'unknown'))
            for first, second, third, case in cases:
                with self.subTest(case=(first, second, third, case)), patch.object(G.GUARD, 'namespace_test') as native, self.assertRaises(ValueError):
                    G.namespace_test(binary, peer, bundle, first, second, third, case)
                native.assert_not_called()
            receipt = bundle / 'NATIVE-RUNTIME.json'
            receipt.rename(bundle / 'original.json')
            receipt.symlink_to(bundle / 'original.json')
            with patch.object(G.GUARD, 'namespace_test') as native, self.assertRaises(ValueError):
                G.namespace_test(binary, peer, bundle, image_sha, peer_sha, bundle_sha, 'on-connect')
            native.assert_not_called()

    def test_original_namespace_and_complete_inputs_are_restored_on_refusal(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ):
            (binary, image_sha), (peer, peer_sha), bundle, bundle_sha = self.images(Path(temporary).resolve())
            previous = {name: 'previous-' + str(index) for index, name in enumerate(G.NAMESPACE_ENVIRONMENT)}
            os.environ.update(previous)
            current = os.stat('/proc/self/ns/net')
            def native(actual, selector, digest):
                self.assertEqual(actual, binary)
                self.assertEqual(selector, 'NodeHostTUN/home-lan')
                self.assertEqual(digest, image_sha)
                self.assertEqual(os.environ['ROUTERVPN_NODE_OUTER_NETNS_ID'], str(current.st_dev) + ':' + str(current.st_ino))
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_BUNDLE'], str(bundle))
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_BUNDLE_SHA256'], bundle_sha)
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_PEER_BINARY'], str(peer))
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_PEER_SHA256'], peer_sha)
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_WHITENING_BINARY'], '')
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_WHITENING_SHA256'], '')
                raise RuntimeError('actual namespace refusal')
            with patch.object(G.GUARD, 'namespace_test', side_effect=native), self.assertRaisesRegex(RuntimeError, 'actual namespace refusal'):
                G.namespace_test(binary, peer, bundle, image_sha, peer_sha, bundle_sha, 'home-lan')
            self.assertEqual({name: os.environ[name] for name in previous}, previous)

    def test_whitening_requires_exact_shipping_image_before_namespace_entry(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ):
            root = Path(temporary).resolve()
            (binary, image_sha), (peer, peer_sha), bundle, bundle_sha = self.images(root)
            relay = root / 'start-layer-relay'
            relay.write_bytes(b'exact shipping relay image boundary')
            relay.chmod(0o755)
            digest = hashlib.sha256(relay.read_bytes()).hexdigest()
            previous = {name: 'previous-' + str(index) for index, name in enumerate(G.NAMESPACE_ENVIRONMENT)}
            os.environ.update(previous)
            for selected, expected in ((None, None), (relay, None), (relay, '0' * 64)):
                with self.subTest(selected=selected, expected=expected), patch.object(G.GUARD, 'namespace_test') as native, self.assertRaises(ValueError):
                    G.namespace_test(binary, peer, bundle, image_sha, peer_sha, bundle_sha, 'layer-whitening-connect',
                                     whitening=selected, whitening_sha256=expected)
                native.assert_not_called()
            def native(actual, selector, identity):
                self.assertEqual((actual, selector, identity), (binary, 'NodeHostTUN/layer-whitening-connect', image_sha))
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_WHITENING_BINARY'], str(relay))
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_WHITENING_SHA256'], digest)
                raise RuntimeError('original whitening namespace refusal')
            with patch.object(G.GUARD, 'namespace_test', side_effect=native), self.assertRaisesRegex(RuntimeError, 'original whitening namespace refusal'):
                G.namespace_test(binary, peer, bundle, image_sha, peer_sha, bundle_sha, 'layer-whitening-connect',
                                 whitening=relay, whitening_sha256=digest)
            self.assertEqual({name: os.environ[name] for name in previous}, previous)
            original = root / 'original-relay'
            relay.rename(original)
            relay.symlink_to(original)
            with patch.object(G.GUARD, 'namespace_test') as native, self.assertRaises(ValueError):
                G.namespace_test(binary, peer, bundle, image_sha, peer_sha, bundle_sha, 'layer-whitening-connect',
                                 whitening=relay, whitening_sha256=digest)
            native.assert_not_called()

    def test_bundle_capture_calls_the_ordinary_complete_verifier_first(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary).resolve()
            receipt = {'files': {'engine': {}}}
            for name in ('engine', 'NATIVE-RUNTIME.json'):
                (bundle / name).write_bytes(name.encode())
                (bundle / name).chmod(0o644)
            calls = []
            def reuse(path, target, env=None):
                calls.append((path, target, env))
                return receipt
            with patch.object(G.BUILD, 'reuse', side_effect=reuse):
                actual, records = G.bundle_identity(bundle, 'linux/amd64', {'captured': 'env'})
            self.assertEqual(actual, receipt)
            self.assertEqual(calls, [(bundle, 'linux/amd64', {'captured': 'env'})])
            self.assertEqual(set(records), {'engine', 'NATIVE-RUNTIME.json'})
            with patch.object(G.BUILD, 'reuse', side_effect=ValueError('changed complete native bundle')), self.assertRaisesRegex(ValueError, 'changed complete native bundle'):
                G.bundle_identity(bundle, 'linux/amd64')
            (bundle / 'engine').chmod(0o666)
            with patch.object(G.BUILD, 'reuse', return_value=receipt), self.assertRaises(ValueError):
                G.bundle_identity(bundle, 'linux/amd64')

    def test_bundle_builder_requires_verified_stage_before_any_host_execution(self):
        for target in ('linux/amd64', 'linux/arm64'):
            with self.subTest(target=target):
                source, bundle, env = Path('/captured/core'), Path('/captured/complete-stage'), {'GOOS': 'linux', 'GOARCH': target.split('/')[1]}
                calls = []
                def reuse(directory, selected, env=None):
                    calls.append(('reuse', directory, selected, env))
                def run(arguments, **kwargs):
                    calls.append(('run', [str(value) for value in arguments], kwargs))
                with patch.object(G.BUILD, 'reuse', side_effect=reuse), patch.object(G.BUILD, 'run', side_effect=run):
                    G.BUILD.verify_installed_linux_host(source, bundle, target, env)
                self.assertEqual(calls[0], ('reuse', bundle, target, env))
                self.assertEqual(calls[1][1][1:], [str(ROOT / 'deploy/test_linux_node_host_tun_runner.py')])
                self.assertEqual(calls[2][1][1:], [str(ROOT / 'deploy/test_linux_node_host_tun.py'), str(source), '--bundle', str(bundle)])
                self.assertEqual(calls[1][2]['env'], env)
                self.assertEqual(calls[2][2]['env'], env)
                with patch.object(G.BUILD, 'reuse', side_effect=ValueError('unverified stage')), patch.object(G.BUILD, 'run') as run, self.assertRaisesRegex(ValueError, 'unverified stage'):
                    G.BUILD.verify_installed_linux_host(source, bundle, target, env)
                run.assert_not_called()
        for target, env in (('windows/amd64', {'GOOS': 'windows', 'GOARCH': 'amd64'}), ('linux/amd64', {'GOOS': 'linux', 'GOARCH': 'arm64'})):
            with patch.object(G.BUILD, 'run') as run, self.assertRaises(ValueError):
                G.BUILD.verify_installed_linux_host(Path('/core'), Path('/bundle'), target, env)
            run.assert_not_called()

    def test_missing_binding_requires_the_actual_targeted_native_failure(self):
        output = ('installed Router proof used the direct LAN response or bypassed its exact encrypted graph\n'
                  '--- FAIL: TestDesktopLinuxGuardianKernelNodeHostTUN/home-lan (1.0s)\n')
        G.check_missing_binding_control(1, output)
        for code, text in ((0, output), (1, 'compile failed'), (1, output.replace('home-lan', 'wrong-node')),
                           (1, output + '--- SKIP: missing TUN (1s)'), (1, output.split('\n', 1)[1])):
            with self.subTest(code=code, output=text), self.assertRaises(ValueError):
                G.check_missing_binding_control(code, text)
        original = 'before\nreturn bindDesktopLinuxNodeProofSocket(ctx, actualNetwork, raw, live)\nafter\n'
        changed = G.missing_binding_source(original)
        self.assertIn('before\nreturn nil', changed)
        self.assertTrue(changed.endswith('\nafter\n'))
        for source in ('other source', original + original):
            with self.assertRaises(ValueError):
                G.missing_binding_source(source)


if __name__ == '__main__':
    unittest.main()
