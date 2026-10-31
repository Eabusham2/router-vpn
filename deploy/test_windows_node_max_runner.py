#!/usr/bin/env python3
"""Check MAX runner scope, exact evidence and cleanup without network peers.

Subprocess models below exercise publication boundaries only. They cannot
establish native Windows, WFP, cryptographic or physical-device acceptance.
"""
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
import importlib.util
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('windows_complete_max_checks', ROOT / 'deploy/test_windows_node_max.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def failure(parent, case, witness):
    return witness + '\n--- FAIL: ' + parent + ' (0.01s)\n    --- FAIL: ' + parent + '/' + case + ' (0.01s)\nFAIL\n'


class MAXNativeBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='max-native-source-check-')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.source = self.work / 'core'
        self.original = {}
        files = {
            GATE.PREDICATE: 'internal/mobilemultihop/desktop_node_admission.go',
            'routervpn/mobiletor/desktop_socket_windows_policy.go': 'internal/mobiletor/desktop_socket_windows_policy.go',
            'routervpn/mobiletor/desktop_socket_windows_transfer.go': 'internal/mobiletor/desktop_socket_windows_transfer.go',
            'routervpn/desktoppt/node_physical_windows.go': 'mobile/desktop/node_physical_windows.go.tmpl',
            'routervpn/desktoppt/node_physical.go': 'mobile/desktop/node_physical.go.tmpl',
            GATE.PEER: GATE.PEER_TEMPLATE,
        }
        for relative, real in files.items():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            self.original[relative] = (ROOT / real).read_bytes()
            path.write_bytes(self.original[relative])
        # The source-only tests deliberately suppress modeled subprocess output.
        self.output = io.StringIO()
        self.stdout = redirect_stdout(self.output)
        self.stdout.__enter__()
        self.addCleanup(self.stdout.__exit__, None, None, None)

    def directory(self, name):
        directory = self.work / name
        directory.mkdir()
        return directory

    def assert_native_scope(self, overlay):
        mapping = json.loads(overlay.read_text())['Replace']
        for relative, raw in self.original.items():
            self.assertEqual((self.source / relative).read_bytes(), raw)
        first = Path(mapping[str(self.source / 'routervpn/mobiletor/desktop_socket_windows_policy.go')]).read_text()
        second = Path(mapping[str(self.source / 'routervpn/mobiletor/desktop_socket_windows_transfer.go')]).read_text()
        self.assertIn('return desktopWindowsNodeCompositionConstruct(ctx, capture, options, nil, false)', first)
        self.assertIn('return desktopWindowsNodeCompositionConstruct(ctx, capture, options, predecessor, true)', second)
        return mapping

    def test_current_and_exact_four_family_overlay_keep_original_native_scope(self):
        closed = self.assert_native_scope(GATE.overlay(self.source, self.directory('closed'), prospective=False))
        opened = self.assert_native_scope(GATE.overlay(self.source, self.directory('opened'), prospective=True))
        self.assertNotIn(str(self.source / GATE.PREDICATE), closed)
        self.assertEqual(len(opened), len(closed)+1)
        raw = self.original[GATE.PREDICATE].decode()
        expected = raw.replace(GATE.PROSPECTIVE_BEFORE, GATE.PROSPECTIVE_AFTER, 1)
        actual = Path(opened[str(self.source / GATE.PREDICATE)]).read_text()
        self.assertEqual(actual, expected)
        self.assertEqual(set(GATE.MODES), {'max-quic-wg', 'max-quic-awg', 'max-tls-wg', 'max-tls-awg'})
        for mode in GATE.MODES:
            self.assertEqual(actual.count('"'+mode+'"'), 1)
        self.assertIn('startLayer != "aes-256-gcm+xor-whitening"', actual)
        self.assertIn('default:\n\t\treturn false', actual)
        for raw in (raw.replace(GATE.PROSPECTIVE_BEFORE, '\tswitch other {\n'),
                    raw.replace('func DesktopNodePhysicalGraphSupported', 'func other'),
                    expected, raw+'\n// "max-tls-awg"\n'):
            with self.assertRaises(ValueError):
                GATE.prospective_predicate(raw)

    def test_native_mutations_remain_scoped_and_cannot_replace_another_owner(self):
        with patch.object(GATE.MAX, 'mutations', return_value=()):
            controls = GATE.mutations(self.source)
            self.assertEqual(len(controls), 6)
            self.assertEqual({row[2].split('/')[0] for row in controls}, {'max-quic-wg', 'max-tls-wg'})
            for mutation in controls:
                mapping = self.assert_native_scope(GATE.overlay(self.source, self.directory(mutation[0]), prospective=True, mutation=mutation))
                self.assertIn(str(self.source / GATE.PREDICATE), mapping)
                if mutation[0].startswith('ordinary-max-'):
                    raw = Path(mapping[str(self.source / mutation[4][1])]).read_text()
                    self.assertIn('p.pair("deny", family, 1, true, true)', raw)
            unowned = (*controls[0][:-1], ('routervpn/mobiletor/desktop_socket_windows_policy.go', 'package mobiletor\n'))
            with self.assertRaisesRegex(ValueError, 'exact compiled controls'):
                GATE.overlay(self.source, self.directory('unowned'), prospective=True, mutation=unowned)
        foreign = self.source / 'routervpn/mobiletor/desktop_socket_windows_node_composition_overlay.go'
        foreign.write_text('package mobiletor\n// retained another owner\n')
        with self.assertRaisesRegex(ValueError, 'Unowned Windows Node observer'):
            GATE.overlay(self.source, self.directory('foreign'), prospective=True)
        self.assertIn('retained another owner', foreign.read_text())

    def test_wrong_tuple_controls_observe_the_unchanged_live_lower_rejection(self):
        lower = 'routervpn/desktoppt/node_physical.go'
        for protocol, family, relative in (('tcp', 'TLS', 'protocol/routervpnxray/outbound.go'),
                                           ('udp', 'QUIC', 'protocol/hysteria2/outbound.go')):
            label = 'different-outer-' + protocol + '-tuple'
            parent = 'TestRouterVPNDesktopNodeCompleteMAX' + family
            case = 'max-' + family.lower() + '-wg/off'
            witness = GATE.MAX.tuple_witness(protocol)
            replacement = 'package captured\n// changed exact ' + protocol + ' tuple\n'
            control = (label, relative, parent, case, witness, replacement)
            with self.subTest(protocol=protocol), patch.object(GATE.MAX, 'mutations', return_value=(control,)):
                mutation = GATE.mutations(self.source)[0]
                selected = GATE.overlay(self.source, self.directory(label), prospective=True, mutation=mutation)
                mapping = self.assert_native_scope(selected)
                self.assertEqual(Path(mapping[str(self.source / relative)]).read_text(), replacement)
                observer = Path(mapping[str(self.source / lower)]).read_text()
                self.assertIn('!closed && !allowed && owner != nil && owner.SocketCurrent() && base == "' + protocol + '"', observer)
                self.assertIn('if closed || !allowed || owner == nil || !owner.SocketCurrent() {', observer)
                self.assertIn('println(' + json.dumps(witness) + ')', observer)
                self.assertEqual((self.source / lower).read_bytes(), self.original[lower])
                recorded = GATE.overlay_source_hashes(self.source, selected)
                self.assertEqual(recorded[lower], GATE.MAX.regular_digest(Path(mapping[str(self.source / lower)])))
                self.assertIn(relative, recorded)
                native_parent = GATE.native_parent(parent)
                actual = failure(native_parent, case, witness)
                GATE.rejected_output(1, actual, native_parent, case, witness)
                for unrelated in ('PQ transport write failed', 'protected PQ peer transport could not open', 'context deadline exceeded'):
                    with self.assertRaises(ValueError):
                        GATE.rejected_output(1, actual.replace(witness, unrelated), native_parent, case, witness)

    def test_ordinary_bypass_controls_require_native_access_denial_for_the_captured_owner(self):
        for protocol, family, relative, replacement in (
                ('tcp', 'TLS', 'protocol/routervpnxray/outbound.go',
                 'conn, err := (&net.Dialer{}).DialContext(cctx, N.NetworkTCP, b.server.String())'),
                ('udp', 'QUIC', 'protocol/hysteria2/outbound.go',
                 'Dialer:             func() N.Dialer { _ = outboundDialer; return N.SystemDialer }(),')):
            label, parent, case = 'uncaptured-outer-' + protocol, 'TestRouterVPNDesktopNodeCompleteMAX' + family, 'max-' + family.lower() + '-wg/off'
            control = (label, relative, parent, case, 'old generic witness', replacement)
            with self.subTest(protocol=protocol), patch.object(GATE.MAX, 'mutations', return_value=(control,)):
                mutation = GATE.mutations(self.source)[0]
                self.assertEqual(mutation[3], GATE.ordinary_witness(protocol))
                selected = GATE.overlay(self.source, self.directory(label), prospective=True, mutation=mutation)
                mapping = self.assert_native_scope(selected)
                observer = 'routervpn/mobiletor/desktop_socket_windows_max_control_overlay.go'
                body = Path(mapping[str(self.source / observer)]).read_text()
                self.assertEqual(body, GATE.ORDINARY_OBSERVER)
                self.assertIn('if !errors.Is(err, syscall.Errno(10013)) {', body)
                self.assertIn('before.Target != after.Target || before.Capture != after.Capture || before.Owner != after.Owner', body)
                self.assertIn('policy.Current(snapshot.Capture, snapshot.Owner)', body)
                self.assertIn('snapshot.Options.PrivateDestinations[0] != (DesktopWindowsSocketDestination{Network: network, Address: remote})', body)
                self.assertNotIn('timeout.Timeout()', body)
                self.assertIn(observer, GATE.overlay_source_hashes(self.source, selected))
                witness = mutation[3]
                actual = failure(GATE.native_parent(parent), case, witness)
                GATE.rejected_output(1, actual, GATE.native_parent(parent), case, witness)
                for unrelated in ('actual PQ Node startup', 'context deadline exceeded', 'WSAETIMEDOUT', GATE.ordinary_witness('udp' if protocol == 'tcp' else 'tcp')):
                    with self.assertRaises(ValueError):
                        GATE.rejected_output(1, actual.replace(witness, unrelated), GATE.native_parent(parent), case, witness)
                owned = self.source / observer
                owned.write_text('package mobiletor\n// another retained owner\n')
                with self.assertRaisesRegex(ValueError, 'unowned source'):
                    GATE.overlay(self.source, self.directory(label + '-occupied'), prospective=True, mutation=mutation)
                owned.unlink()

    def test_late_handshake_witness_requires_the_live_unready_native_lower(self):
        with patch.object(GATE.MAX, 'mutations', return_value=()):
            for control in GATE.mutations(self.source):
                if not control[0].startswith('late-max-handshake-'):
                    continue
                protocol = 'tcp' if control[0].endswith('tls') else 'udp'
                selected = GATE.overlay(self.source, self.directory(control[0]), prospective=True, mutation=control)
                mapping = self.assert_native_scope(selected)
                raw = Path(mapping[str(self.source / 'routervpn/desktoppt/node_physical.go')]).read_text()
                self.assertIn('!closed && allowed && owner != nil && owner.SocketCurrent() && !owner.Current() && base == "' + protocol + '"', raw)
                self.assertIn('snapshot.Capture == owner.brokerCapture()', raw)
                self.assertIn('if closed || !allowed || owner == nil || !owner.Current() {', raw)
                self.assertEqual(control[3], GATE.handshake_witness(protocol))
                for wrong in ('actual PQ Node startup', 'context deadline exceeded', GATE.handshake_witness('udp' if protocol == 'tcp' else 'tcp')):
                    with self.assertRaises(ValueError):
                        GATE.rejected_output(1, failure(control[1], control[2], wrong), control[1], control[2], control[3])

    def test_compiled_overlay_receipts_detect_changed_aliased_and_escaped_sources(self):
        selected = GATE.overlay(self.source, self.directory('overlay-receipt'), prospective=True)
        captured = GATE.overlay_source_hashes(self.source, selected)
        value = json.loads(selected.read_text())
        original, replacement = next(iter(value['Replace'].items()))
        path = Path(replacement)
        raw = path.read_bytes()
        path.write_bytes(raw + b'\n// changed compiled overlay\n')
        self.assertNotEqual(GATE.overlay_source_hashes(self.source, selected), captured)
        path.unlink()
        path.symlink_to(self.source / GATE.PREDICATE)
        with self.assertRaisesRegex(ValueError, 'captured regular file'):
            GATE.overlay_source_hashes(self.source, selected)
        path.unlink()
        path.write_bytes(raw)
        value['Replace'][str(self.work / 'foreign-owner.go')] = value['Replace'].pop(original)
        selected.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            GATE.overlay_source_hashes(self.source, selected)

    def test_every_native_graph_case_requires_real_unique_pass_evidence(self):
        self.assertEqual(sum(map(len, GATE.MAX.TRAFFIC.values())), 12)
        self.assertEqual(sum(map(len, GATE.MAX.CREDENTIALS.values())), 48)
        for family in GATE.MAX.FAMILIES:
            for suffix, cases in (('', GATE.MAX.TRAFFIC[family]), ('Credentials', GATE.MAX.CREDENTIALS[family])):
                parent = 'TestRouterVPNDesktopNodeWindowsMAX'+family+suffix
                complete = '\n'.join('--- PASS: '+value+' (1.00s)' for value in (parent, *(parent+'/'+case for case in cases)))+'\nPASS\n'
                GATE.MAX.required_output(0, complete, parent, cases)
                for case in cases:
                    marker = '--- PASS: '+parent+'/'+case+' (1.00s)'
                    for changed in (complete.replace(marker, 'fixture.go:42: '+marker), complete+marker+'\n'):
                        with self.assertRaisesRegex(ValueError, 'omitted or duplicated'):
                            GATE.MAX.required_output(0, changed, parent, cases)

    def test_missing_or_failed_startup_parser_cannot_reuse_graph_evidence(self):
        graph = 'TestRouterVPNDesktopNodeWindowsMAXTLS'
        complete = '\n'.join('--- PASS: ' + value + ' (0.01s)' for value in
                             (graph, *(graph + '/' + case for case in GATE.MAX.TRAFFIC['TLS'])))
        marker = '--- PASS: ' + GATE.STARTUP_RECORDS + ' (0.00s)'
        GATE.MAX.required_output(0, complete + '\n' + marker, GATE.STARTUP_RECORDS, ())
        for status, output in ((0, complete), (1, complete + '\n' + marker.replace('PASS', 'FAIL')),
                               (0, complete + '\n    fixture.go:1: ' + marker),
                               (0, complete + '\n' + marker + '\n' + marker)):
            with self.assertRaises(ValueError):
                GATE.MAX.required_output(status, output, GATE.STARTUP_RECORDS, ())

    def test_compiled_control_requires_exact_failure_and_acknowledged_cleanup(self):
        parent, case, witness = 'TestMAX', 'max-tls-wg/aes-256-gcm+xor-whitening/middle-key', 'actual intended defect'
        output = failure(parent, case, witness)
        GATE.rejected_output(1, output, parent, case, witness)
        GATE.rejected_output(1, output.replace('\n', '\r\n'), parent, case, witness)
        for status, changed in ((0,output), (2,output), (-9,output), (1,output.replace(witness,'unrelated')),
                (1,output.replace(parent+'/'+case, parent+'/other')),
                (1,output+'--- FAIL: malformed failure\n'), (1,output+'--- FAIL: unrelated (0.01s)\n'),
                (1,output.replace('\nFAIL\n','\n')), (1,output+'fatal: unrelated failure'),
                (1,output+'--- SKIP: other (0.01s)'), (1,output+'DATA RACE'),
                *((1,output+message.upper()) for message in GATE.JOIN_FAILURES)):
            with self.subTest(status=status, changed=changed[-80:]):
                with self.assertRaises(ValueError):
                    GATE.rejected_output(status, changed, parent, case, witness)

    def test_authoritative_receipt_requires_the_exact_clean_commit(self):
        sha, tree = 'a'*40, 'b'*40
        def answer(commit=sha, status=''):
            def call(command, **kwargs):
                self.assertEqual(kwargs['cwd'], GATE.ROOT)
                return commit+'\n' if command[-1]=='HEAD^{commit}' else tree+'\n' if command[-1]=='HEAD^{tree}' else status
            return call
        with patch.object(GATE.subprocess,'check_output',side_effect=answer()):
            actual = GATE.repository_identity(sha)
            self.assertEqual(actual['commit'],sha)
            self.assertEqual(actual['tree'],tree)
            self.assertTrue(actual['clean'])
        for expected, reply in ((sha,answer('c'*40)), (sha,answer(status=' M cmd/client/main.go\n')),
                               (sha,answer(status='?? internal/other.go\n')), ('a'*8,answer()), (sha.upper(),answer())):
            with patch.object(GATE.subprocess,'check_output',side_effect=reply):
                with self.assertRaisesRegex(ValueError,'exact clean repository commit'):
                    GATE.repository_identity(expected)

    def test_native_source_closure_binds_actual_acl_helper_and_acceptance(self):
        dependencies = ('client/Protect-RouterVPN-Windows-PrivateRoot.ps1',
                        'client/test-windows-private-acl.ps1',
                        'deploy/build_pq_reference_fixture.py',
                        'deploy/test_pq_reference_preparation.py')
        with patch.object(GATE.MAX, 'checked_sources', return_value=(self.source, {})), \
             patch.object(GATE.WPQ, 'checked_sources', return_value=(self.source, {})):
            actual, records = GATE.checked_sources(self.source)
            self.assertEqual(actual, self.source)
            for relative in dependencies:
                self.assertEqual(records['windows-max/' + relative], GATE.MAX.regular_digest(ROOT / relative))
            # A source receipt cannot attest an alias to a different owner's
            # helper even when its current bytes happen to be identical.
            shadow = self.directory('aliased-reference-source')
            for relative in (GATE.PEER_TEMPLATE, 'deploy/test_windows_node_max.py',
                             'deploy/test_windows_node_max_runner.py', *dependencies):
                target = shadow / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            helper = shadow / dependencies[0]
            helper.unlink()
            helper.symlink_to(ROOT / dependencies[0])
            with patch.object(GATE, 'ROOT', shadow), self.assertRaisesRegex(ValueError, 'captured regular file'):
                GATE.checked_sources(self.source)

    def test_foreign_host_and_disabled_cgo_cannot_reach_a_native_operation(self):
        with patch.object(GATE.platform,'system',return_value='Linux'), patch.object(GATE,'checked_sources') as source:
            with self.assertRaisesRegex(ValueError,'actual elevated Windows'):
                GATE.execute(self.source,self.work/'pq',self.work/'cache')
            source.assert_not_called()
        for captured in ({'GOOS':'windows','CGO_ENABLED':'0'}, {'GOOS':'linux','CGO_ENABLED':'1'}):
            with patch.object(GATE.platform,'system',return_value='Windows'), \
                 patch.object(GATE.WFP.BOOT.IDENTITY.ctypes,'windll',create=True) as native, \
                 patch.object(GATE,'repository_identity',return_value={'commit':'a'*40}), \
                 patch.object(GATE,'checked_sources',return_value=(self.source,{})), \
                 patch.object(GATE.NODE,'selected_compiler',return_value=(Path('go'),captured,'amd64')), \
                 patch.object(GATE.REFERENCE.BUILD.PQ,'verify') as archive:
                native.shell32.IsUserAnAdmin.return_value=True
                with self.assertRaisesRegex(ValueError,'real CGO ABI'):
                    GATE.execute(self.source,self.work/'pq',self.work/'cache')
                archive.assert_not_called()

    def test_preexisting_receipts_and_unretired_workspaces_are_preserved(self):
        output=self.work/'receipt.json'
        output.write_text('retained original receipt')
        with self.assertRaisesRegex(ValueError,'new owned file'):
            GATE.WPQ.new_receipt_path(output)
        self.assertEqual(output.read_text(),'retained original receipt')
        missing=self.work/'new.json'
        owner=self.directory('retained-workspace')
        with self.assertRaisesRegex(ValueError,'cleanup was not acknowledged'):
            GATE.WPQ.publish_receipt(missing,{},owner)
        self.assertFalse(missing.exists())
        owner.rmdir()
        GATE.WPQ.publish_receipt(missing,{'joined':True},owner)
        self.assertTrue(json.loads(missing.read_text())['joined'])

    def test_standalone_receipt_waits_for_source_workspace_cleanup(self):
        for fail in (False, True):
            with self.subTest(cleanup_failure=fail):
                receipt=self.work/('failed.json' if fail else 'joined.json')
                repository={'commit':'a'*40,'tree':'b'*40,'clean':True}
                native=GATE.REFERENCE.BUILD
                original=dict(os.environ)
                observed=[]
                real_temporary=GATE.tempfile.TemporaryDirectory
                owned_root=self.work
                class OwnedTemporary:
                    def __init__(self, **kwargs): self.owner=real_temporary(dir=owned_root,**kwargs)
                    def __enter__(self): return self.owner.__enter__()
                    def __exit__(self,*args):
                        result=self.owner.__exit__(*args)
                        if fail: raise OSError('owned source cleanup acknowledgment failed')
                        return result
                def modeled_execute(source,pq,cache,go,**kwargs):
                    self.assertTrue(source.parent.is_dir())
                    self.assertFalse(receipt.exists())
                    self.assertNotIn('receipt_path',kwargs)
                    self.assertEqual(kwargs['expected_sha'],'a'*40)
                    observed.append(source.parent)
                    return {'repository':repository,'private_key_workspace_removed':True}
                with ExitStack() as stack:
                    stack.enter_context(patch.object(GATE.platform,'system',return_value='Windows'))
                    windll=stack.enter_context(patch.object(GATE.WFP.BOOT.IDENTITY.ctypes,'windll',create=True))
                    windll.shell32.IsUserAnAdmin.return_value=True
                    stack.enter_context(patch.object(GATE.NODE,'selected_compiler',return_value=(Path('go'),{'PATH':os.defpath,'GOOS':'windows','CGO_ENABLED':'1'},'amd64')))
                    stack.enter_context(patch.object(GATE,'execute',side_effect=modeled_execute))
                    stack.enter_context(patch.object(GATE,'repository_identity',return_value=repository))
                    stack.enter_context(patch.object(GATE.tempfile,'TemporaryDirectory',OwnedTemporary))
                    stack.enter_context(patch.object(native,'checkout',side_effect=lambda path,*args:path.mkdir()))
                    for owner,name in ((native,'pristine'),(native.PQ,'build'),(native.POLICY,'prepare_native'),
                            (native.PERFORMANCE,'prepare'),(native.OPENVPN,'prepare'),(native.EXTERNAL,'prepare'),
                            (native.BUFFERS,'prepare'),(native,'run'),(native.POLICY.AMNEZIA,'verify')):
                        stack.enter_context(patch.object(owner,name,return_value=None))
                    if fail:
                        with self.assertRaisesRegex(OSError,'cleanup acknowledgment'):
                            GATE.standalone(prospective=True,receipt_path=receipt,expected_sha='a'*40)
                    else:
                        GATE.standalone(prospective=True,receipt_path=receipt,expected_sha='a'*40)
                self.assertEqual(dict(os.environ),original)
                self.assertEqual(len(observed),1)
                self.assertFalse(observed[0].exists())
                self.assertEqual(receipt.exists(),not fail)
                if not fail:
                    self.assertTrue(json.loads(receipt.read_text())['standalone_source_workspace_removed'])

    def test_registration_requires_same_sha_native_workflow_in_authoritative_aggregate(self):
        self.assertEqual(GATE.NODE.PREP.PEER_TEMPLATES['node_max_peer_windows_test.go.tmpl'],GATE.PEER)
        self.assertTrue((ROOT/GATE.PEER_TEMPLATE).read_bytes().startswith(GATE.PREFIX))
        workflow=(ROOT/'.github/workflows/windows-node-max-contract.yml').read_text()
        for target in ('windows/amd64','windows/arm64'):
            self.assertIn('target: '+target,workflow)
        self.assertIn('timeout-minutes: 180',workflow)
        self.assertIn('timeout-minutes: 150',workflow)
        self.assertIn('--standalone --prospective --sha $env:GITHUB_SHA --receipt',workflow)
        self.assertIn('if-no-files-found: error',workflow)
        self.assertIn('name: windows-max-native-${{ matrix.slug }}-${{ github.sha }}',workflow)
        self.assertIn("go-version: '1.26.3'",workflow)
        self.assertIn("python deploy/setup-desktop-native-toolchain.py '${{ matrix.target }}'",workflow)
        self.assertIn('python deploy/test_pq_reference_preparation.py',workflow)
        for dependency in ('deploy/test_pq_reference_preparation.py',
                           'client/Protect-RouterVPN-Windows-PrivateRoot.ps1',
                           'client/test-windows-private-acl.ps1'):
            self.assertEqual(workflow.count("      - '"+dependency+"'"),2)
        acl = workflow.index('      - name: Private ACL readback in Windows PowerShell 5.1 and 7\n')
        toolchain = workflow.index('      - name: Select exact native Rust target and verified LLVM compiler\n')
        self.assertLess(acl, toolchain)
        acl_step = workflow[acl:toolchain]
        self.assertIn('timeout-minutes: 6', acl_step)
        self.assertIn('foreach ($shell in @($systemShell, $coreShell))', acl_step)
        self.assertIn('-File client/test-windows-private-acl.ps1', acl_step)
        self.assertIn("if ($LASTEXITCODE -ne 0) { throw 'Actual private ACL readback/failure controls failed' }", acl_step)
        release=(ROOT/'.github/workflows/release-candidate.yml').read_text()
        self.assertIn('  windows-complete-max:\n',release)
        self.assertIn('    uses: ./.github/workflows/windows-node-max-contract.yml',release)
        aggregate=release.split('\n  aggregate:\n',1)[1]
        self.assertIn('windows-complete-max',aggregate.split('\n    runs-on:',1)[0])
        builder=(ROOT/'deploy/build-native-runtime.py').read_text()
        for name in ('test_windows_node_max.py','test_windows_node_max_runner.py'):
            self.assertIn("ROOT/'deploy/"+name+"'",builder)
        # It runs in the required parallel native workflow, not again inside
        # the packaged runtime command with an unrelated aggregate deadline.
        self.assertNotIn("run([sys.executable, ROOT/'deploy/test_windows_node_max.py'",builder)


if __name__ == '__main__':
    unittest.main()
