#!/usr/bin/env python3
"""Keep generated TUN acceptance distinct from its bounded peer prerequisite."""
from pathlib import Path
import importlib.util
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

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


class LinuxChildTUNDiagnostics(unittest.TestCase):
    marker = 'generated MTU owner omitted its exact current native routing receipt\noriginal namespace child joined\n'
    safe = 'NODE-MTU-DIAGNOSTIC receipt reason=unique-addition generation=3 reader=2 index=9 mtu=1376'

    def test_success_does_not_build_or_run_diagnostics(self):
        diagnose = Mock()
        with patch.object(G.GUARD.UID, 'run', return_value='mandatory success') as native:
            self.assertEqual(G.run_native_acceptance(['actual'], captured={'owned': 'env'}, sudo=None,
                                                    peer_only=False, diagnose=diagnose), 'mandatory success')
        native.assert_called_once_with(['actual'], cwd=G.ROOT, env={'owned': 'env'}, timeout=150, sudo=None)
        diagnose.assert_not_called()

    def test_diagnostic_success_failure_and_exception_retain_exact_original_failure(self):
        for result in ('diagnostic pass', subprocess.CalledProcessError(4, ['diagnostic'], output=b'private-password'),
                       RuntimeError('private-password'), SystemExit(0), KeyboardInterrupt('private-password')):
            with self.subTest(result=type(result).__name__):
                original = subprocess.CalledProcessError(23, ['original'], output=self.marker.encode())
                diagnose = Mock(side_effect=result if isinstance(result, BaseException) else None, return_value=result)
                output = io.StringIO()
                with patch.object(G.GUARD.UID, 'run', side_effect=original), contextlib.redirect_stdout(output):
                    with self.assertRaises(subprocess.CalledProcessError) as actual:
                        G.run_native_acceptance(['actual'], captured={}, sudo=None, peer_only=False, diagnose=diagnose)
                self.assertIs(actual.exception, original)
                self.assertEqual(actual.exception.returncode, 23)
                self.assertEqual(actual.exception.output, self.marker.encode())
                diagnose.assert_called_once_with()
                self.assertNotIn('private-password', output.getvalue())

    def test_unjoined_timeout_peer_and_unrelated_failures_cannot_start_another_trial(self):
        cases = ((False, self.marker.replace('original namespace child joined', 'namespace still owned')),
                 (False, 'different mandatory failure\noriginal namespace child joined\n'), (True, self.marker))
        for peer, output in cases:
            with self.subTest(peer=peer, output=output):
                diagnose = Mock()
                original = subprocess.CalledProcessError(1, ['actual'], output=output)
                with patch.object(G.GUARD.UID, 'run', side_effect=original), self.assertRaises(subprocess.CalledProcessError):
                    G.run_native_acceptance(['actual'], captured={}, sudo=None, peer_only=peer, diagnose=diagnose)
                diagnose.assert_not_called()
        diagnose = Mock()
        with patch.object(G.GUARD.UID, 'run', side_effect=RuntimeError('owned join timed out')), self.assertRaises(RuntimeError):
            G.run_native_acceptance(['actual'], captured={}, sudo=None, peer_only=False, diagnose=diagnose)
        diagnose.assert_not_called()

    def test_diagnostics_emit_only_bounded_allowlisted_codes_and_numeric_metadata(self):
        private = 'secret-token-with-private-node-password'
        raw = '\n'.join((private, self.safe, self.safe + ' password=' + private,
                         'NODE-MTU-DIAGNOSTIC receipt reason=' + private + ' generation=3 reader=2 index=9 mtu=1376',
                         'NODE-MTU-DIAGNOSTIC added kind=route family=6 index=9 table=254 priority=256 flags=0 destination=linklocal6',
                         '--- PASS: an unrelated diagnostic result'))
        safe = G.receipt_diagnostic_output(raw.encode())
        self.assertEqual(len(safe.splitlines()), 2)
        self.assertNotIn(private, safe)
        self.assertNotIn('PASS', safe)
        self.assertEqual(G.receipt_diagnostic_output('native_test.go:265: joined child output: '+self.safe), self.safe)
        self.assertEqual(G.receipt_diagnostic_output(private+' '+self.safe), self.safe)
        self.assertEqual(G.receipt_diagnostic_output(self.safe.replace('index=9', 'index='+'1'*600)), '')
        self.assertEqual(len(G.receipt_diagnostic_output((self.safe + '\n') * 100).splitlines()), 64)

    def source(self, directory):
        source = directory / 'source'
        for relative, original in (
            ('cmd/sing-box/routervpn_network_command.go', ROOT/'mobile/desktop/network_command.go.tmpl'),
            ('routervpn-desktop-tun/routervpn_sing_tun_network_linux.go', ROOT/'mobile/desktop/sing_tun_network_linux.go.tmpl'),
        ):
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(original.read_bytes())
        return source

    def test_overlay_retains_exact_original_sources_and_all_rejection_operations(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = self.source(workspace)
            original = {path: path.read_bytes() for path in source.rglob('*.go')}
            overlay, records = G.receipt_diagnostic_overlay(source, workspace)
            changed = json.loads(overlay.read_text())['Replace']
            self.assertEqual(len(changed), 2)
            self.assertEqual(len(records), 2)
            for path, raw in original.items():
                self.assertEqual(path.read_bytes(), raw)
                text = Path(changed[str(path)]).read_text()
                for line in raw.decode().splitlines():
                    self.assertIn(line, text)
            network = Path(changed[str(source/'cmd/sing-box/routervpn_network_command.go')]).read_text()
            self.assertNotIn('fmt.Fprint(os.Stderr, err)', network)
            self.assertIn('routerVPNNodeMTUDiagnosticReason(err.Error())', network)
            self.assertNotIn('record.Session', network)
            self.assertNotIn('record.Config', network)
            self.assertNotIn('record.Path', network)
            self.assertNotIn('record.Request', network)
            route = Path(changed[str(source/'routervpn-desktop-tun/routervpn_sing_tun_network_linux.go')]).read_text()
            self.assertIn('if i == 8 { break }', route)
            self.assertNotIn('object.Native)', route)
            self.assertNotIn('object.Gateway)', route)

    def test_changed_source_anchor_cannot_generate_a_different_overlay(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = self.source(workspace)
            path = source/'cmd/sing-box/routervpn_network_command.go'
            path.write_text(path.read_text().replace('reader.RouterVPNDesktopNetworkReceipt()', 'differentReader()'))
            with self.assertRaisesRegex(ValueError, 'exact source'):
                G.receipt_diagnostic_overlay(source, workspace)

    def test_actual_generated_go_reason_classifier_redacts_arbitrary_error_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = self.source(workspace)
            overlay, _ = G.receipt_diagnostic_overlay(source, workspace)
            generated = Path(json.loads(overlay.read_text())['Replace'][str(source/'cmd/sing-box/routervpn_network_command.go')]).read_text()
            start = generated.index('func routerVPNNodeMTUDiagnosticReason(')
            end = generated.index('func routerVPNNodeMTUReceiptDiagnostic(', start)
            module = workspace/'redaction'
            module.mkdir()
            (module/'go.mod').write_text('module native-diagnostic-redaction\n\ngo 1.20\n')
            (module/'reason.go').write_text('package redaction\nimport "strings"\n'+generated[start:end])
            cases = '\n'.join('{' + json.dumps(prefix + ' private-key=secret-token') + ', ' + json.dumps(code) + '},'
                              for code, prefix in G.RECEIPT_DIAGNOSTIC_REASONS)
            (module/'reason_test.go').write_text('''package redaction
import "testing"
func TestReasonNeverReturnsPrivateMessage(t *testing.T) {
 for _, c := range []struct{message, want string}{
''' + cases + '''
 {"private-key=secret-token", "unclassified"},
 } { if got:=routerVPNNodeMTUDiagnosticReason(c.message);got!=c.want {t.Fatal("private or incorrect diagnostic reason",got)} }
}
''')
            subprocess.run(['go', 'test', '-mod=readonly', './...'], cwd=module, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)

    def test_diagnostic_run_retains_images_sources_overlay_and_owned_cleanup(self):
        for fault in ('none', 'diagnostic-failure', 'peer-during-compile', 'source-during-compile', 'overlay-during-compile', 'image-during-run'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                source = self.source(workspace)
                binary, peer = workspace/'original.test', workspace/'peer.test'
                for image in (binary, peer):
                    image.write_bytes(b'original compiled image')
                    image.chmod(0o755)
                identities = {image: G.image_identity(image) for image in (binary, peer)}
                calls, owned = [], []
                before = {'original': 'source-hash'}
                def run(command, **options):
                    calls.append((command, options))
                    if 'test' in command:
                        image = Path(command[command.index('-o') + 1])
                        owned.append(image.parent)
                        image.write_bytes(b'diagnostic compiled image')
                        image.chmod(0o755)
                        if fault == 'peer-during-compile':
                            peer.write_bytes(b'replaced peer image')
                        if fault == 'overlay-during-compile':
                            overlay = Path(next(arg.removeprefix('-overlay=') for arg in command if isinstance(arg, str) and arg.startswith('-overlay=')))
                            overlay.write_text('{}')
                        return ''
                    image = Path(command[command.index('--namespace-test-binary') + 1])
                    if fault == 'image-during-run':
                        image.write_bytes(b'replaced diagnostic image')
                    if fault == 'diagnostic-failure':
                        raise subprocess.CalledProcessError(7, command, output=(self.safe+'\nprivate-password').encode())
                    return self.safe+'\nprivate-password\n--- PASS: diagnostic trial'
                output = io.StringIO()
                def source_capture(_):
                    current = {'changed': 'source'} if fault == 'source-during-compile' and calls else before
                    return source, current
                with patch.object(G, 'checked_sources', side_effect=source_capture), \
                     patch.object(G.GUARD.UID, 'run', side_effect=run), contextlib.redirect_stdout(output):
                    if fault in ('none', 'diagnostic-failure'):
                        G.native_receipt_diagnostics(source, '/original/go', {}, workspace, peer, identities, before, '/usr/bin/sudo')
                    else:
                        with self.assertRaises(ValueError):
                            G.native_receipt_diagnostics(source, '/original/go', {}, workspace, peer, identities, before, '/usr/bin/sudo')
                self.assertTrue(owned)
                self.assertTrue(all(not path.exists() for path in owned))
                self.assertEqual(calls[0][1]['timeout'], 120)
                if fault.endswith('during-compile'):
                    self.assertEqual(len(calls), 1)
                else:
                    self.assertEqual(len(calls), 2)
                    self.assertEqual(calls[1][0][:3], ['/usr/bin/sudo', '-n', '--'])
                    self.assertEqual(calls[1][1]['timeout'], 150)
                    self.assertEqual(calls[1][1]['sudo'], '/usr/bin/sudo')
                self.assertNotIn('private-password', output.getvalue())
                self.assertNotIn('--- PASS:', output.getvalue())


if __name__ == '__main__':
    unittest.main()
