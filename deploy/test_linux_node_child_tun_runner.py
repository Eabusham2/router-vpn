#!/usr/bin/env python3
"""Keep generated TUN acceptance distinct from its bounded peer prerequisite."""
from pathlib import Path
import importlib.util
import contextlib
import io
import json
import os
import re
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

    def test_success_runs_only_original_native_command(self):
        with patch.object(G.GUARD.UID, 'run', return_value='mandatory success') as native:
            self.assertEqual(G.run_native_acceptance(['actual'], captured={'owned': 'env'}, sudo=None),
                             'mandatory success')
        native.assert_called_once_with(['actual'], cwd=G.ROOT, env={'owned': 'env'}, timeout=150, sudo=None)

    def test_first_run_diagnostics_preserve_exact_original_failure_without_replay(self):
        for raw in ((self.marker + self.safe + '\nprivate-password').encode(),
                    self.marker + self.safe + '\nprivate-password'):
            with self.subTest(encoding=type(raw).__name__):
                original = subprocess.CalledProcessError(23, ['original'], output=raw)
                output = io.StringIO()
                with patch.object(G.GUARD.UID, 'run', side_effect=original) as native, contextlib.redirect_stdout(output):
                    with self.assertRaises(subprocess.CalledProcessError) as actual:
                        G.run_native_acceptance(['actual'], captured={}, sudo=None)
                self.assertIs(actual.exception, original)
                self.assertEqual(actual.exception.returncode, 23)
                self.assertIs(actual.exception.output, raw)
                native.assert_called_once()
                self.assertIn(self.safe, output.getvalue())
                self.assertNotIn('private-password', output.getvalue())
                self.assertIn('First-run', output.getvalue())

    def test_absent_cause_unjoined_and_peer_failures_never_start_a_replay(self):
        for raw in (self.marker, 'different failure', None,
                    self.marker.replace('original namespace child joined', 'namespace still owned'),
                    '--- FAIL: TestDesktopLinuxGuardianKernelNodeChildCommandPeer\n'):
            with self.subTest(output=raw):
                original = subprocess.CalledProcessError(9, ['actual'], output=raw)
                output = io.StringIO()
                with patch.object(G.GUARD.UID, 'run', side_effect=original) as native, contextlib.redirect_stdout(output):
                    with self.assertRaises(subprocess.CalledProcessError) as actual:
                        G.run_native_acceptance(['actual'], captured={}, sudo=None)
                self.assertIs(actual.exception, original)
                native.assert_called_once()
                self.assertEqual(output.getvalue(), '')

    def test_formatter_exceptions_cannot_replace_original_native_failure(self):
        for diagnostic in (RuntimeError('private-password'), SystemExit(0), KeyboardInterrupt('private-password')):
            with self.subTest(error=type(diagnostic).__name__):
                original = subprocess.CalledProcessError(4, ['original'], output=self.marker)
                output = io.StringIO()
                with patch.object(G.GUARD.UID, 'run', side_effect=original) as native, \
                     patch.object(G, 'receipt_diagnostic_output', side_effect=diagnostic), contextlib.redirect_stdout(output):
                    with self.assertRaises(subprocess.CalledProcessError) as actual:
                        G.run_native_acceptance(['actual'], captured={}, sudo=None)
                self.assertIs(actual.exception, original)
                native.assert_called_once()
                self.assertNotIn('private-password', output.getvalue())

    def test_timeout_or_nonprocess_exception_is_not_retried_or_normalized(self):
        for original in (RuntimeError('owned join timed out'), subprocess.TimeoutExpired(['actual'], 150)):
            with self.subTest(error=type(original).__name__):
                with patch.object(G.GUARD.UID, 'run', side_effect=original) as native:
                    with self.assertRaises(type(original)) as actual:
                        G.run_native_acceptance(['actual'], captured={}, sudo=None)
                self.assertIs(actual.exception, original)
                native.assert_called_once()

    def test_diagnostics_emit_only_terminated_bounded_allowlisted_lines(self):
        private = 'secret-token-with-private-node-password'
        added = 'NODE-MTU-DIAGNOSTIC added kind=route family=6 index=9 table=254 priority=256 flags=0 destination=linklocal6'
        removed = 'NODE-MTU-DIAGNOSTIC removed kind=rule family=4 index=0 table=252 priority=9001 flags=0 destination=other'
        raw = '\n'.join((private, self.safe, self.safe + ' password=' + private,
                         'NODE-MTU-DIAGNOSTIC receipt reason=' + private + ' generation=3 reader=2 index=9 mtu=1376',
                         added, removed, '--- PASS: unrelated result', ''))
        safe = G.receipt_diagnostic_output(raw.encode())
        self.assertEqual(safe.splitlines(), [self.safe, added, removed])
        self.assertNotIn(private, safe)
        self.assertNotIn('PASS', safe)
        self.assertEqual(G.receipt_diagnostic_output('native_test.go:265: joined child output: '+self.safe+'\n'), self.safe)
        self.assertEqual(G.receipt_diagnostic_output(private+' '+self.safe+'\n'), self.safe)
        self.assertEqual(G.receipt_diagnostic_output(self.safe), '')
        self.assertEqual(G.receipt_diagnostic_output(self.safe+'\n'+removed), self.safe)
        self.assertEqual(G.receipt_diagnostic_output(self.safe.replace('index=9', 'index='+'1'*600)+'\n'), '')
        self.assertEqual(len(G.receipt_diagnostic_output((self.safe + '\n') * 100).splitlines()), 64)

    def test_diagnostic_output_cannot_satisfy_missing_native_acceptance(self):
        with self.assertRaises(ValueError):
            G.check_verdict(self.safe+'\n')
        # Even complete-looking text cannot convert a nonzero original exit.
        raw = LinuxChildTUNVerdict().output() + self.safe+'\n'
        original = subprocess.CalledProcessError(7, ['actual'], output=raw)
        with patch.object(G.GUARD.UID, 'run', side_effect=original) as native, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(subprocess.CalledProcessError) as actual:
                G.run_native_acceptance(['actual'], captured={}, sudo=None)
        self.assertIs(actual.exception, original)
        native.assert_called_once()

    def test_actual_first_failure_functions_preserve_bounds_and_redaction(self):
        # Compile the exact diagnostic functions with only their data-shape
        # fixtures. No TUN, route inventory, owner proof or acceptance is mocked
        # into passing by this small standard-library gate.
        command = (ROOT/'mobile/desktop/network_command.go.tmpl').read_text()
        # Project these complete shipping declarations, not the rest of the
        # file: unrelated startup helpers may follow or sit between them.
        functions = ''
        for signature in ('func (owner *routerVPNNodeMTU) reportNetworkReceiptFailure(',
                          'func routerVPNNodeMTUDiagnosticReason('):
            self.assertEqual(command.count(signature), 1)
            start = command.index(signature)
            end = command.index('\n}\n', start) + 3
            functions += command[start:end] + '\n'
        native = (ROOT/'mobile/desktop/sing_tun_network_linux.go.tmpl').read_text()
        start = native.index('func (t *NativeTun) routervpnLinuxAdditionFailure(')
        end = native.index('// RuleAdd of our final NOP', start)
        functions += '\n'+native[start:end]
        # Keep the real observation/qualification closure. A replacement
        # hand-written route shape would omit fields that reject forged proof.
        start = native.index('type routerVPNLinuxRouteAddress struct')
        end = native.index('func routervpnLinuxIPPrefix(', start)
        functions += '\n'+native[start:end]
        start = native.index('func routervpnLinuxSameRouteOwner(')
        end = native.index('// Preserve the same sticky first failure.', start)
        functions += '\n'+native[start:end]
        native_tests = (ROOT/'mobile/desktop/sing_tun_network_linux_test.go.tmpl').read_text()
        start = native_tests.index('func TestRouterVPNNativeLinuxRoutingOriginalOwnerDiagnostics(')
        end = native_tests.index('func nativeRoutingRule(', start)
        actual_owner_tests = native_tests[start:end]
        start = native_tests.index('func nativeRoutingConcurrentFixture(')
        end = native_tests.index('func TestRouterVPNNativeLinuxRoutingConcurrentAddressProof(', start)
        actual_owner_tests += '\n'+native_tests[start:end]
        cases = '\n'.join('{' + json.dumps(prefix + ' private-key=secret-token') + ', ' + json.dumps(code) + '},'
                          for code, prefix in G.RECEIPT_DIAGNOSTIC_REASONS)
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary)
            language = re.search(r'^go ([0-9]+\.[0-9]+(?:\.[0-9]+)?)$', (ROOT/'go.mod').read_text(), re.MULTILINE)
            self.assertIsNotNone(language)
            (module/'go.mod').write_text('module native-first-diagnostic\n\ngo '+language.group(1)+'\n')
            # Keep the qualified production marker dependency as well as the
            # existing local parser projection. Do not substitute its text or
            # its cross-package capability/error identity with a test stub.
            dependency = module/'desktopnetwork'
            dependency.mkdir()
            for name in ('desktop_network_receipt.go', 'desktop_network_wire.go'):
                source = (ROOT/'internal/desktopnetwork'/name).read_text()
                self.assertEqual(source.count('package desktopnetwork\n'), 1)
                (dependency/name).write_bytes((ROOT/'internal/desktopnetwork'/name).read_bytes())
                (module/name).write_text(source.replace('package desktopnetwork\n', 'package diagnostic\n', 1))
            (module/'diagnostic.go').write_text('''package diagnostic
import ("encoding/base64"; "encoding/binary"; "fmt"; "io"; "net"; "net/netip"; "os"; "runtime"; "slices"; "strings"; "sync"; "syscall"; "native-first-diagnostic/desktopnetwork")
type routerVPNNodeMTURecord struct { Generation, Reader uint64; Index, MTU int; Session, Config, Path, Request string }
type routerVPNNodeMTU struct { record routerVPNNodeMTURecord; networkReceiptDiagnosticReader uint64 }
type routerVPNNativeNetworkLedger struct { mu sync.Mutex; failure error; objects map[string]DesktopNetworkObject }
type NativeTun struct { routervpnNetwork routerVPNNativeNetworkLedger; routervpnOwnedIndex int }
'''+functions)
            (module/'diagnostic_test.go').write_text('''package diagnostic
import ("bytes"; "encoding/base64"; "errors"; "fmt"; "io"; "net"; "net/netip"; "os"; "runtime"; "strings"; "syscall"; "testing")
func TestReasonsRedactEveryKnownAndUnknownNativeError(t *testing.T) {
 for _, c := range []struct{message, want string}{
'''+cases+'''
 {"private-key=secret-token", "unclassified"},
 } {
  for _, prefix:=range []string{"",ErrNetworkReceiptUnavailable.Error()+"\\n"} {
   if got:=routerVPNNodeMTUDiagnosticReason(prefix+c.message);got!=c.want {t.Fatal("private or incorrect diagnostic reason",got)}
  }
  if got:=routerVPNNodeMTUDiagnosticReason("private-key=secret-token\\n"+c.message);got!="unclassified" {t.Fatal("unrecognized prefix became a trusted diagnostic reason",got)}
 }
}
func capture(t *testing.T, run func()) string {
 t.Helper(); r,w,e:=os.Pipe(); if e!=nil {t.Fatal(e)}; defer r.Close()
 old:=os.Stderr; os.Stderr=w; defer func(){os.Stderr=old;w.Close()}(); run()
 if e=w.Close();e!=nil{t.Fatal(e)}; b,e:=io.ReadAll(r);if e!=nil{t.Fatal(e)};return string(b)
}
func TestActualOwnerReportsOnlyFirstFailurePerReader(t *testing.T) {
 o:=&routerVPNNodeMTU{record:routerVPNNodeMTURecord{Reader:1,Index:8,MTU:1420,Session:"secret"}}
 before:=o.record
 text:=capture(t,func(){o.reportNetworkReceiptFailure("native Linux routing call has no unique owned addition secret");o.reportNetworkReceiptFailure("other secret")})
 want:="NODE-MTU-DIAGNOSTIC receipt reason=unique-addition generation=0 reader=1 index=8 mtu=1420\\n"
 if runtime.GOOS!="linux"{want=""};if text!=want||o.record!=before{t.Fatal("first report changed state or redaction",text)}
 o.record.Reader=2;o.record.Generation=2;o.record.MTU=1376
 text=capture(t,func(){o.reportNetworkReceiptFailure("secret");o.reportNetworkReceiptFailure("another secret")})
 want="NODE-MTU-DIAGNOSTIC receipt reason=unclassified generation=2 reader=2 index=8 mtu=1376\\n"
 if runtime.GOOS!="linux"{want=""};if text!=want{t.Fatal("replacement reader lost its separate first report",text)}
}
func TestActualNativeDeltaKeepsStickyFailureAndBounds(t *testing.T) {
 o:=DesktopNetworkObject{Kind:"route",Family:6,Index:8,Table:254,Priority:256,Destination:"fe80::/64",Gateway:"secret",Native:"secret"}
 gone:=DesktopNetworkObject{Kind:"rule",Family:4,Table:252,Priority:9001,Destination:"secret",Native:"secret"}
 n:=&NativeTun{routervpnOwnedIndex:8}; original:=errors.New("private native failure secret")
 text:=capture(t,func(){n.routervpnLinuxAdditionFailure("route",original,[]DesktopNetworkObject{o},[]DesktopNetworkObject{gone});n.routervpnLinuxAdditionFailure("secret",errors.New("replacement"),nil,nil)})
 if n.routervpnNetwork.failure!=original||len(n.routervpnNetwork.objects)!=0||strings.Contains(text,"secret")||strings.Count(text,"NODE-MTU-DIAGNOSTIC")!=3||!strings.Contains(text,"removed kind=rule"){t.Fatal("native diagnostic changed ownership or disclosed private data",text)}
 var output bytes.Buffer;many:=make([]DesktopNetworkObject,16);for i:=range many{many[i]=o}
 routervpnLinuxMTUDiagnostic(&output,"route",8,many[:3],many)
 if strings.Count(output.String(),"NODE-MTU-DIAGNOSTIC")!=9{t.Fatal("object diagnostic bound changed")}
 output.Reset();o.Kind="secret";o.Destination="secret";routervpnLinuxMTUDiagnostic(&output,"secret",8,[]DesktopNetworkObject{o},nil)
 if strings.Contains(output.String(),"secret")||!strings.Contains(output.String(),"kind=other"){t.Fatal("unknown field escaped the diagnostic vocabulary")}
}
func TestActualOriginalOwnerRecordsReachStrictParser(t *testing.T) {
 before,after,explicit,local:=nativeRoutingConcurrentFixture(t)
 var output bytes.Buffer
 routervpnLinuxRouteOwnerDiagnostic(&output,routerVPNLinuxRouteAdditionObservation{before:before,after:after},[]DesktopNetworkObject{explicit,local})
 fmt.Print(output.String())
}
'''+actual_owner_tests)
            result = subprocess.run(['go', 'test', '-v', '-race', '-count=1', '-timeout=30s', '-mod=readonly', './...'],
                                    cwd=module, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout)
            safe = G.receipt_diagnostic_output(result.stdout)
            self.assertEqual(len(safe.splitlines()), 4, result.stdout)
            self.assertIn('owner readback_error=false same_owner=true', safe)
            self.assertIn('address ordinal=0', safe)
            self.assertIn('qualification ordinal=1 canonical_local=true', safe)
            self.assertIn('attributes=[1:20 4:8 6:8 15:8 20:5]', safe)
            for row in safe.splitlines():
                with self.subTest(row=row):
                    self.assertEqual(G.receipt_diagnostic_output(row+' private-key=secret\n'), '')
                    self.assertEqual(G.receipt_diagnostic_output(row), '')
                    self.assertEqual(G.receipt_diagnostic_output(row.replace('false','secret').replace('true','secret')+'\n'), '')
            route = safe.splitlines()[-1]
            for attributes in ('[secret]', '['+' '.join(['1:4']*17)+']', '[1:secret]', '[655360:4]'):
                replaced = re.sub(r'attributes=\[[^]]*\]', 'attributes='+attributes, route)
                self.assertEqual(G.receipt_diagnostic_output(replaced+'\n'), '')


class LinuxChildOriginalCleanupDiagnostics(unittest.TestCase):
    def test_exact_original_cleanup_loop_preserves_its_phase_and_error_identity(self):
        # Execute the shipping methods and unchanged 15s/50ms defer body.
        # Native callbacks are explicit models; this is not namespace evidence.
        source = (ROOT/'mobile/desktop/node_command_control_linux.go.tmpl').read_text()
        methods = []
        for name in ('joinNative', 'retire'):
            start = source.index('func (owner *routerVPNLinuxNodeControl) '+name+'(')
            end = source.index('\nfunc ', start + 1)
            methods.append(source[start:end])
        run = (ROOT/'mobile/desktop/node_command_run_linux.go.tmpl').read_text()
        start = run.index('\tdefer func() {\n\t\tstopped.Store(true)')
        end = run.index('\n\tfor _, name := range', start)
        cleanup = run[start:end]
        fixture = r"""package main
import (
 "context"
 "errors"
 "fmt"
 "strings"
 "sync/atomic"
 "testing"
 "testing/synctest"
 "time"
 mobiletor "cleanup-phase/mobiletor"
)
var routerVPNExternalFailure = errors.New("original admission refused")
var cause = errors.New("original native operation refused")
var preceding = errors.New("original operation failed before Stop")
type trace struct { fault string; ctx context.Context; started time.Time; native, source, receipt, exchange, protection, removed, published int }
func (s *trace) called(ctx context.Context, phase string) error {
 if s.ctx == nil { s.ctx=ctx } else if s.ctx!=ctx {panic("cleanup substituted original request")}
 deadline,ok:=ctx.Deadline();if !ok||deadline.Sub(s.started)!=15*time.Second{panic("cleanup extended or replaced original bound")}
 if s.fault==phase {return cause}
 return nil
}
type phaseNative struct { s *trace }
func(n *phaseNative)CloseContext(ctx context.Context)error{n.s.native++;if n.s.fault=="retry"&&n.s.native<3{return cause};return n.s.called(ctx,"Box close")}
type phasePreparation struct{s *trace}
func(p *phasePreparation)CloseSource(ctx context.Context)error{p.s.source++;return p.s.called(ctx,"source close")}
func(p *phasePreparation)JoinedSource(ctx context.Context)(*mobiletor.DesktopLinuxSourceJoinRecord,bool,error){p.s.receipt++;return &mobiletor.DesktopLinuxSourceJoinRecord{},true,p.s.called(ctx,"joined-source receipt")}
func(p *phasePreparation)CloseProtection(ctx context.Context)error{p.s.protection++;return p.s.called(ctx,"retained protection close")}
type phaseControl struct{s *trace}
func(c *phaseControl)Retire(ctx context.Context,_ *mobiletor.DesktopLinuxSourceJoinRecord)error{c.s.exchange++;return c.s.called(ctx,"retirement exchange")}
type routerVPNLinuxNodeControl struct{native *phaseNative;preparation *phasePreparation;control *phaseControl;retiring atomic.Bool;closed,joined,retired,acknowledged bool}
type routerVPNExternalStop struct {Schema int;Session,SourceSHA256 string}
type phaseFiles struct{s *trace}
func(f *phaseFiles)remove(name string)error{if name!="node-ready.json"{panic("different ready owner")};f.s.removed++;return nil}
func(f *phaseFiles)publish(name string,_ any)error{if name!="stopped.json"{panic("different stopped owner")};f.s.published++;return nil}
"""
        fixture += '\n'.join(methods)
        fixture += '\nfunc originalCleanup(control *routerVPNLinuxNodeControl, files *phaseFiles, incoming error)(failure error){\n failure=incoming\n var stopped atomic.Bool\n cancel:=func(){}\n session,config:="original-session","original-source"\n' + cleanup + '\n return failure\n}\n'
        fixture += r"""
func TestOriginalCleanupPhase(t *testing.T){
 for _,phase:=range []string{"Box close","source close","joined-source receipt","retirement exchange","retained protection close","retry","current"}{t.Run(phase,func(t *testing.T){synctest.Test(t,func(t *testing.T){
  s:=&trace{fault:phase,started:time.Now()}
  owner:=&routerVPNLinuxNodeControl{native:&phaseNative{s},preparation:&phasePreparation{s},control:&phaseControl{s}}
  failure:=originalCleanup(owner,&phaseFiles{s},preceding)
  if !errors.Is(failure,preceding){t.Fatal("prior failure identity was discarded",failure)}
  if s.removed!=1||owner.closed{t.Fatal("diagnostics changed original ready/descriptor ownership")}
  if phase=="retry"||phase=="current"{
   if errors.Is(failure,cause)||!owner.joined||!owner.acknowledged||!owner.retired||s.published!=1{t.Fatal("successful original cleanup changed",failure,s)}
   want:=1;if phase=="retry"{want=3};if s.native!=want||s.source!=1||s.receipt!=1||s.exchange!=1||s.protection!=1{t.Fatal("original cleanup order/count changed",s)}
   if phase=="retry"&&time.Since(s.started)!=100*time.Millisecond{t.Fatal("existing retry cadence changed")}
   return
  }
  if !errors.Is(failure,cause)||!strings.Contains(failure.Error(),fmt.Sprintf("Linux Node original %s:",phase)){t.Fatal("original cleanup phase/cause was discarded",failure)}
  if s.published!=0||owner.retired{t.Fatal("unresolved native cleanup became stopped")}
  if phase=="Box close"||phase=="source close"{
   if !errors.Is(failure,context.DeadlineExceeded)||time.Since(s.started)!=15*time.Second{t.Fatal("exhaustion lost original Stop deadline",failure,time.Since(s.started))}
   if s.exchange!=0||s.protection!=0||owner.joined||owner.acknowledged{t.Fatal("failed original join entered terminal exchange")}
  }
 })})}
}
"""
        with tempfile.TemporaryDirectory(prefix='routervpn-original-cleanup-phase-') as directory:
            root = Path(directory)
            (root/'go.mod').write_text('module cleanup-phase\ngo 1.26.3\n')
            (root/'mobiletor').mkdir()
            (root/'mobiletor/types.go').write_text('package mobiletor\ntype DesktopLinuxSourceJoinRecord struct{}\n')
            (root/'phase_test.go').write_text(fixture)
            result = subprocess.run(['go', 'test', '-race', '-count=1', '-timeout=30s', '-v', '.'],
                                    cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout)
            for phase in ('Box_close', 'source_close', 'joined-source_receipt', 'retirement_exchange',
                          'retained_protection_close', 'retry', 'current'):
                self.assertEqual(result.stdout.count('--- PASS: TestOriginalCleanupPhase/'+phase+' '), 1, result.stdout)
            self.assertNotIn('--- SKIP:', result.stdout)


if __name__ == '__main__':
    unittest.main()
