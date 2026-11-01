#!/usr/bin/env python3
"""Keep generated TUN acceptance distinct from its bounded peer prerequisite."""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('linux_child_tun_verdict', ROOT/'deploy/test_linux_node_child_tun.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class LinuxChildTUNVerdict(unittest.TestCase):
    def output(self):
        prefix = '--- PASS: TestDesktopLinuxGuardianKernelNodeChildCommandTUN'
        return '\n'.join([*(prefix + suffix + ' (0.1s)' for suffix in ('', *('/' + case for case in G.CASES))),
                          *('    native_test.go:1: verified original TUN retirement: ' + case for case in G.CASES)]) + '\n'

    def test_requires_every_actual_positive_and_negative(self):
        output = self.output()
        G.check_verdict(output)
        for line in output.splitlines():
            with self.subTest(line=line), self.assertRaises(ValueError):
                G.check_verdict(output.replace(line, ''))

    def test_failure_or_skip_never_reports_native_acceptance(self):
        for marker in ('--- FAIL: other', '--- SKIP: unavailable'):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                G.check_verdict(self.output() + '\n' + marker)

    def test_passing_leaf_without_original_retirement_cannot_close_gate(self):
        output = self.output()
        for case in G.CASES:
            with self.subTest(case=case), self.assertRaises(ValueError):
                G.check_verdict(output.replace('verified original TUN retirement: ' + case, 'retirement was omitted: ' + case))

    def test_original_receive_timeout_cannot_be_successful_retirement(self):
        output = self.output().replace('verified original TUN retirement: wrong-key',
                                      'generated TUN child lost its actual joined source receipt read unixpacket: i/o timeout')
        with self.assertRaises(ValueError):
            G.check_verdict(output)

    def test_peer_smoke_cannot_replace_actual_tun_command(self):
        smoke = '--- PASS: TestDesktopLinuxGuardianKernelNodeChildCommandPeer (0.1s)'
        G.check_verdict(smoke, peer_only=True)
        with self.assertRaises(ValueError):
            G.check_verdict(smoke)
        with self.assertRaises(ValueError):
            G.check_verdict(self.output(), peer_only=True)

    def test_foreign_compiled_image_never_enters_namespace(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve()/'compiled'
            path.write_bytes(b'owned compile boundary')
            path.chmod(0o755)
            identity = G.image_identity(path)
            with patch.object(G.GUARD, 'namespace_test') as native, self.assertRaises(ValueError):
                G.namespace_test(path, path, identity[-1], '0'*64)
            native.assert_not_called()
            linked = path.with_name('linked')
            linked.symlink_to(path)
            with self.assertRaises(ValueError):
                G.image_identity(linked)
            path.chmod(0o777)
            with self.assertRaises(ValueError):
                G.image_identity(path)

    def test_receipt_requires_owned_workspace_cleanup_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            owned = directory / 'owned'
            owned.mkdir()
            receipt = G.new_receipt_path(directory / 'receipt.json')
            result = {'scope': 'peer-prerequisite'}
            with self.assertRaises(ValueError):
                G.publish_receipt(receipt, result, owned)
            self.assertFalse(receipt.exists())
            owned.rmdir()
            G.publish_receipt(receipt, result, owned)
            self.assertEqual(json.loads(receipt.read_text()), result)
            with self.assertRaises((FileExistsError, ValueError)):
                G.publish_receipt(receipt, {'scope': 'other'}, owned)
            with self.assertRaises(ValueError):
                G.new_receipt_path(receipt)
            self.assertEqual(json.loads(receipt.read_text()), result)

    def test_exact_commit_receipt_rejects_dirty_or_unpublished_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def git(*arguments):
                return subprocess.check_output(['git', *arguments], cwd=root, text=True, stderr=subprocess.STDOUT).strip()
            git('init', '--quiet')
            git('config', 'user.name', 'Router VPN native test')
            git('config', 'user.email', 'native-test@example.invalid')
            path = root / 'go.mod'
            path.write_text('module owned\n')
            git('add', '--', 'go.mod')
            git('-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Owned native receipt fixture')
            commit = git('rev-parse', 'HEAD')
            with patch.object(G, 'ROOT', root):
                self.assertEqual(G.repository_identity(commit)['commit'], commit)
                with self.assertRaises(ValueError):
                    G.repository_identity('0' * 40)
                path.write_text('module replacement\n')
                with self.assertRaises(subprocess.CalledProcessError):
                    G.repository_identity(commit)
                git('restore', '--', 'go.mod')
                (root / 'mobile').mkdir()
                (root / 'mobile' / 'unpublished.go').write_text('package unpublished\n')
                with self.assertRaises(ValueError):
                    G.repository_identity(commit)

    def test_standalone_requires_pinned_preparation_before_actual_gate_and_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / 'standalone.json'
            calls, workspaces = [], []
            captured = dict(os.environ, CGO_ENABLED='1', GOOS='linux', GOARCH='amd64', GOTOOLCHAIN='local')
            original = dict(os.environ)
            def checkout(path, url, pin):
                path.mkdir()
                calls.append(('checkout', url, pin))
                workspaces.append(path.parent)
            def mark(name):
                def call(*args, **kwargs):
                    calls.append((name,))
                    self.assertEqual(os.environ['GOTOOLCHAIN'], 'local')
                return call
            result = {'scope': 'generated-command-tun', 'cases': list(G.CASES)}
            def execute(source, go, **kwargs):
                calls.append(('actual-gate',))
                self.assertTrue(source.is_dir())
                self.assertFalse(kwargs['peer_only'])
                self.assertFalse(receipt.exists())
                return dict(result)
            with patch.object(G.platform, 'system', return_value='Linux'), \
                 patch.object(G.NODE, 'selected_compiler', return_value=(Path('/pinned/go'), captured, 'amd64')), \
                 patch.object(G.BUILD, 'checkout', side_effect=checkout), \
                 patch.object(G.BUILD, 'pristine', side_effect=mark('pristine')), \
                 patch.object(G.BUILD.POLICY, 'prepare_native', side_effect=mark('policy')), \
                 patch.object(G.BUILD.PERFORMANCE, 'prepare', side_effect=mark('performance')), \
                 patch.object(G.BUILD.OPENVPN, 'prepare', side_effect=mark('openvpn')), \
                 patch.object(G.BUILD.EXTERNAL, 'prepare', side_effect=mark('external')), \
                 patch.object(G.BUILD.BUFFERS, 'prepare', side_effect=mark('buffers')), \
                 patch.object(G.BUILD, 'run', side_effect=mark('module-verification')), \
                 patch.object(G.BUILD.POLICY.AMNEZIA, 'verify', side_effect=mark('amnezia')), \
                 patch.object(G, 'execute', side_effect=execute):
                G.standalone(receipt_path=receipt)
            self.assertEqual(calls[:2], [('checkout', 'https://github.com/SagerNet/sing-box.git', G.BUILD.PIN),
                                       ('checkout', 'https://github.com/XTLS/Xray-core.git', G.BUILD.POLICY.XRAY.XRAY_PIN)])
            self.assertEqual([row[0] for row in calls[2:]],
                             ['pristine', 'pristine', 'policy', 'performance', 'openvpn', 'external', 'buffers',
                              'module-verification', 'module-verification', 'amnezia', 'actual-gate'])
            self.assertTrue(all(not path.exists() for path in workspaces))
            self.assertEqual(dict(os.environ), original)
            self.assertEqual(json.loads(receipt.read_text())['cases'], list(G.CASES))


if __name__ == '__main__':
    unittest.main()
