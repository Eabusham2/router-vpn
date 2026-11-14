#!/usr/bin/env python3
"""Causal source/runner boundary tests; these never claim native Darwin acceptance."""
from pathlib import Path
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import sys
import time
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('darwin_child_gate', ROOT/'deploy/test_darwin_node_child_tun.py')
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)


def transcript():
    lines = ['=== RUN   '+G.HARNESS, '=== RUN   '+G.NATIVE]
    for case in G.CASES:
        name = G.NATIVE+'/'+case
        lines += ['=== RUN   '+name, '    native_test.go:1: verified original Darwin child retirement: '+case,
                  '--- PASS: '+name+' (1.00s)']
    lines += ['--- PASS: '+G.NATIVE+' (8.00s)', 'PASS', '--- PASS: '+G.HARNESS+' (9.00s)', 'PASS']
    return '\n'.join(lines)+'\n'


def preflight_transcript():
    return '\n'.join([
        '=== RUN   '+G.PREFLIGHT_HARNESS,
        '=== RUN   '+G.PREFLIGHT_NATIVE,
        *('verified original Darwin handshake preflight: '+stage for stage in G.PREFLIGHT_RECEIPTS),
        '--- PASS: '+G.PREFLIGHT_NATIVE+' (1.00s)',
        '--- PASS: '+G.PREFLIGHT_HARNESS+' (2.00s)',
        'PASS',
    ])+'\n'



def diagnostic_transcript():
    lines = ['=== RUN   '+G.DIAGNOSTIC_HARNESS, '=== RUN   '+G.DIAGNOSTIC_NATIVE]
    name = G.DIAGNOSTIC_NATIVE+'/'+G.DIAGNOSTIC_CASE
    lines += ['=== RUN   '+name, '    native_test.go:1: verified original Darwin child retirement: '+G.DIAGNOSTIC_CASE,
              '--- PASS: '+name+' (1.00s)', '--- PASS: '+G.DIAGNOSTIC_NATIVE+' (2.00s)',
              'PASS', '--- PASS: '+G.DIAGNOSTIC_HARNESS+' (3.00s)', 'PASS']
    return '\n'.join(lines)+'\n'


def workflow_inventory(raw):
    """Check the small exact native gate surface without optional YAML packages."""
    if not isinstance(raw, str) or len(raw) > 16384:
        raise ValueError('native workflow is not bounded source')
    if re.search(r'^\s*(?:if|continue-on-error|inputs):', raw, re.M):
        raise ValueError('native workflow became conditional, nonblocking or caller-replaced')
    if re.search(r'\b(?:fallback|workflow_run)\b', raw):
        raise ValueError('native workflow added an alternate result authority')
    required = (
        '  workflow_call:\n  push:',
        '  group: darwin-node-child-tun-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}',
        '  cancel-in-progress: true',
        'jobs:\n  child:',
        '    runs-on: ${{ matrix.runner }}',
        '    timeout-minutes: 60',
        '      fail-fast: false',
        '          - arch: amd64\n            runner: macos-15-intel',
        '          - arch: arm64\n            runner: macos-15',
        "          ROUTERVPN_DARWIN_NODE_CHILD_ACCEPTANCE: '1'",
        '          ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}',
        '          ROUTERVPN_CHILD_RECEIPT: ${{ runner.temp }}/darwin-node-child-${{ matrix.arch }}.json',
        "          CGO_ENABLED: '1'",
        '          if-no-files-found: error',
        '          name: RouterVPN-Darwin-ordered-child-${{ matrix.arch }}-${{ github.sha }}',
        '          path: ${{ runner.temp }}/darwin-node-child-${{ matrix.arch }}.json',
        '      - name: Compile and authenticate original child before changing host networking\n        timeout-minutes: 25',
        '        run: ROUTERVPN_DARWIN_NODE_CHILD_ACCEPTANCE=1 CGO_ENABLED=1 python3 deploy/test_darwin_node_child_tun.py --standalone --preflight-only --require-commit "$GITHUB_SHA"',
    )
    if any(raw.count(value) != 1 for value in required):
        raise ValueError('native workflow lost its exact required architecture/source/receipt inventory')
    if len(re.findall(r'^          - arch:', raw, re.M)) != 2 or re.findall(r'^  ([A-Za-z][\w-]*):', raw.split('jobs:\n', 1)[1], re.M) != ['child']:
        raise ValueError('native workflow changed its complete job or architecture inventory')
    command = 'python3 deploy/test_darwin_node_child_tun.py --standalone --require-commit "$ROUTERVPN_EXPECTED_SOURCE" --receipt "$ROUTERVPN_CHILD_RECEIPT"'
    run = re.findall(r'^        run: \|\n((?:          [^\n]*\n)+)', raw, re.M)
    if len(run) != 1:
        raise ValueError('native workflow lost its one actual standalone invocation')
    commands = [line.strip() for line in run[0].splitlines() if line.strip() and not line.lstrip().startswith('#')]
    if commands != [command] or raw.count('run: python3 deploy/test_darwin_node_child_tun_runner.py') != 1:
        raise ValueError('native workflow weakened actual invocation or its runner checks')
    if raw.count('--preflight-only') != 1 or raw.index('--preflight-only') > raw.index(command) or '--compile-only' in raw:
        raise ValueError('handshake preflight replaced or followed mandatory native acceptance')


class NativeVerdict(unittest.TestCase):
    def test_complete_exact_native_transcript(self):
        G.check_verdict(transcript())
        G.check_verdict(transcript().replace('\n', '\r\n'))

    def test_actual_go_buffered_subtest_pass_order_is_preserved(self):
        # Captured native Go component logs print root PASS before child PASS
        # lines, after every RUN and t.Log receipt. Model that exact ordering.
        lines = transcript().splitlines()
        child_passes = [line for line in lines if line.startswith('--- PASS: '+G.NATIVE+'/')]
        lines = [line for line in lines if line not in child_passes]
        parent = next(index for index, line in enumerate(lines) if line.startswith('--- PASS: '+G.NATIVE+' ('))
        lines[parent+1:parent+1] = child_passes
        G.check_verdict('\n'.join(lines)+'\n')

    def test_every_case_and_original_retirement_is_mandatory(self):
        original = transcript()
        for name in G.EXPECTED:
            for prefix in ('=== RUN   ', '--- PASS: '):
                with self.subTest(name=name, prefix=prefix):
                    target = next(line for line in original.splitlines() if line == prefix+name or line.startswith(prefix+name+' ('))
                    with self.assertRaises(ValueError):
                        G.check_verdict(original.replace(target+'\n', '', 1))
        for case in G.CASES:
            with self.subTest(retirement=case), self.assertRaises(ValueError):
                G.check_verdict(original.replace('verified original Darwin child retirement: '+case, 'missing native retirement: '+case))

    def test_failure_skip_race_panic_remain_failure_even_with_all_passes(self):
        for line in ('--- FAIL: '+G.NATIVE+' (0.00s)', '--- SKIP: '+G.NATIVE+' (0.00s)',
                     'WARNING: DATA RACE', 'panic: original owner missing', 'fatal error: native join'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                G.check_verdict(transcript()+line+'\n')

    def test_duplicate_unknown_and_unrun_cannot_be_native_evidence(self):
        for line in ('=== RUN   '+G.NATIVE, '--- PASS: '+G.NATIVE+' (1.00s)',
                     '=== RUN   TestUnrelated', '--- PASS: TestUnrelated (1.00s)',
                     'native.go:2: verified original Darwin child retirement: '+G.CASES[0],
                     'native.go:2: verified original Darwin child retirement: foreign'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                G.check_verdict(transcript()+line+'\n')
        with self.assertRaises(ValueError):
            G.check_verdict(transcript().replace('=== RUN   '+G.NATIVE+'\n', ''))

    def test_late_native_children_and_retirement_cannot_extend_a_passed_owner(self):
        original = transcript()
        for root in (G.HARNESS, G.NATIVE):
            line = next(line for line in original.splitlines() if line.startswith('--- PASS: '+root+' ('))
            without = original.replace(line+'\n', '', 1)
            before = '=== RUN   '+(G.NATIVE if root == G.HARNESS else G.NATIVE+'/'+G.CASES[0])
            with self.subTest(root=root), self.assertRaises(ValueError):
                G.check_verdict(without.replace(before, line+'\n'+before, 1))
        name = G.NATIVE+'/'+G.CASES[0]
        receipt = next(line for line in original.splitlines() if line.endswith('retirement: '+G.CASES[0]))
        without = original.replace(receipt+'\n', '', 1)
        passed = next(line for line in original.splitlines() if line.startswith('--- PASS: '+name+' ('))
        with self.assertRaises(ValueError):
            G.check_verdict(without.replace(passed, passed+'\n'+receipt, 1))

    def test_parent_pass_requires_all_native_work_and_joined_receipts(self):
        original = transcript()
        native_pass = next(line for line in original.splitlines() if line.startswith('--- PASS: '+G.NATIVE+' ('))
        without = original.replace(native_pass+'\n', '', 1)
        receipt = next(line for line in original.splitlines() if line.endswith('retirement: '+G.CASES[-1]))
        with self.assertRaisesRegex(ValueError, 'before all original native joins'):
            G.check_verdict(without.replace(receipt, native_pass+'\n'+receipt, 1))
        harness_pass = next(line for line in original.splitlines() if line.startswith('--- PASS: '+G.HARNESS+' ('))
        without = original.replace(harness_pass+'\n', '', 1)
        with self.assertRaisesRegex(ValueError, 'before all original child reports'):
            G.check_verdict(without.replace(native_pass, harness_pass+'\n'+native_pass, 1))
        case_pass = next(line for line in original.splitlines() if line.startswith('--- PASS: '+G.NATIVE+'/'+G.CASES[-1]+' ('))
        without = original.replace(case_pass+'\n', '', 1)
        with self.assertRaisesRegex(ValueError, 'before all original child reports'):
            G.check_verdict(without.replace(harness_pass, harness_pass+'\n'+case_pass, 1))

    def test_native_source_and_runner_inventory_match(self):
        raw = (ROOT/'mobile/desktop/node_chain_command_darwin_native_test.go.tmpl').read_text()
        import re
        body = re.search(r'var darwinChildCases = \[\]string\{([^}]+)\}', raw)
        self.assertIsNotNone(body)
        self.assertEqual(tuple(re.findall(r'"([^"\n]+)"', body[1])), G.CASES)
        for name in (G.NATIVE, G.HARNESS):
            self.assertIn('func '+name+'(', raw)
        for required in ('macosprocess.OpenCapture(', 'macosprocess.BindCreated(', 'o.bootstrap.Stop(ctx)',
                         'o.transfer, e = o.transferDigest()', 'transfer, e := o.transferDigest()',
                         'proof, e = o.parseReady(raw)', 'mobiletor.RunDesktopDarwinPFBaseline(',
                         'net.InterfaceByName(mtu.Interface)',
                         'status.Reader != old.Reader+1', 'device.Index == old.Index',
                         'stats.Final.DirectQueries != 0', 'stats.Final.EntryPublicQueries != 0'):
            self.assertIn(required, raw)
        # The family helper retains the ordinary transfer and parser branches;
        # the common native owner must call it at acquisition and readback.
        family = (ROOT/'mobile/desktop/node_chain_socks_command_darwin_native_test.go.tmpl').read_text()
        def member(name):
            signature = 'func(o *darwinChildOwner) '+name+'('
            self.assertEqual(family.count(signature), 1)
            begin = family.index(signature)
            return family[begin:family.index('\n}', begin)+2]
        metadata = member('metadata')
        self.assertIn('o==nil||(o.policy==nil)==(o.socksPolicy==nil)', metadata)
        self.assertIn('_,meta,_,err:=o.policy.ReadValidated();return meta,err', metadata)
        for name in ('transferDigest', 'parseReady'):
            helper = member(name)
            self.assertIn('if _,err:=o.metadata();err!=nil', helper)
            if name == 'transferDigest':
                self.assertIn('if o.capture==nil', helper)
                self.assertIn('if o.socksPolicy!=nil{return macosprocess.NodeChainSOCKSTransferSHA256(o.capture.Selection())}', helper)
                self.assertIn('return macosprocess.NodeChainTransferSHA256(o.capture.Selection())', helper)
            else:
                self.assertIn('mobilemultihop.ParseDesktopNodeChainSOCKSReadyRecord(raw,o.socksPolicy,o.transfer)', helper)
                self.assertIn('return mobilemultihop.ParseDesktopNodeChainReadyRecord(raw,o.policy,o.transfer)', helper)
        self.assertNotIn('t.Skip(', raw)
        self.assertNotIn('t.Skip(', family)


class ActualHostSelection(unittest.TestCase):
    def test_fixture_debug_stripping_keeps_actual_race_and_native_tags(self):
        for package in ('./cmd/sing-box', './protocol/routervpnamnezia'):
            command = G.native_fixture_compile('/captured/go', Path('/captured/native.test'), package)
            self.assertEqual(command[:6], ['/captured/go', 'test', '-c', '-race', '-mod=readonly', '-tags='+','.join(G.TAGS)])
            self.assertEqual(command[6:], ['-ldflags=-checklinkname=0 -s -w', '-o', Path('/captured/native.test'), package])
        source = (ROOT/'deploy/test_darwin_node_child_tun.py').read_text()
        self.assertIn('UID.run(native_fixture_compile(compiler, image, package), cwd=source, env=captured, timeout=600)', source)
        self.assertIn("identities = {path: image_identity(path) for path in (child, peer)}", source)
        self.assertIn('any(image_identity(path) != value for path, value in identities.items())', source)

    def test_signing_failure_keeps_original_deadline_and_uncancelled_cause(self):
        source = (ROOT/'mobile/desktop/node_chain_command_darwin_native_test.go.tmpl').read_text()
        start = source.index('for _, p := range []string{macosprocess.ControllerPath, macosprocess.EnginePath}')
        stop = source.index('\n\tpeer := macosprocess.InstallRoot', start)
        signing = source[start:stop]
        self.assertIn('darwinChildImage(t, image, p, expected)', signing)
        self.assertIn('context.WithTimeout(context.Background(), 10*time.Second)', signing)
        self.assertIn('cause := ctx.Err()\n\t\tcancel()', signing)
        self.assertIn('native fixture signing image=%s bytes=%d elapsed=%s context=%v: %v', signing)
        self.assertIn('p, before.Size(), time.Since(started), cause, e, out', signing)
        self.assertNotIn('continue', signing)

    def test_explicit_native_host_and_ordinary_uid(self):
        with patch.object(G.platform, 'system', return_value='Darwin'), patch.object(G.platform, 'machine', return_value='arm64'), patch.object(G.os, 'getuid', return_value=501):
            self.assertEqual(G.required_host({G.FLAG: '1'}), ('arm64', 501))
            for value in ({}, {G.FLAG:'0'}, {G.FLAG:'1','GOOS':'linux'}, {G.FLAG:'1','GOARCH':'amd64'}, {G.FLAG:'1','CGO_ENABLED':'0'}):
                with self.subTest(environment=value), self.assertRaises(ValueError):
                    G.required_host(value)
        with patch.object(G.platform, 'system', return_value='Darwin'), patch.object(G.platform, 'machine', return_value='x86_64'), patch.object(G.os, 'getuid', return_value=0):
            self.assertEqual(G.required_host({G.FLAG:'1','SUDO_UID':'501'}), ('amd64',501))
            for uid in ('0','-1',str(2**32-1),'unknown'):
                with self.subTest(uid=uid), self.assertRaises(ValueError):
                    G.required_host({G.FLAG:'1','SUDO_UID':uid})
        with patch.object(G.platform, 'system', return_value='Linux'), self.assertRaises(ValueError):
            G.required_host({G.FLAG:'1'})

    def test_image_identity_rejects_links_writeability_empty_and_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'native.test'
            path.write_bytes(b'owned compiled fixture')
            path.chmod(0o755)
            original = G.image_identity(path)
            self.assertEqual(G.image_identity(path), original)
            link = path.with_name('link')
            link.symlink_to(path)
            with self.assertRaises(ValueError): G.image_identity(link)
            link.unlink(); os.link(path, link)
            with self.assertRaises(ValueError): G.image_identity(path)
            link.unlink(); path.chmod(0o777)
            with self.assertRaises(ValueError): G.image_identity(path)
            path.chmod(0o755); path.write_bytes(b'')
            with self.assertRaises(ValueError): G.image_identity(path)
            # Allocate the replacement while the original inode still exists;
            # unlink/recreate can immediately recycle that same inode on tmpfs.
            replacement = path.with_name('replacement')
            replacement.write_bytes(b'owned compiled fixture'); replacement.chmod(0o755)
            self.assertNotEqual(replacement.stat().st_ino, path.stat().st_ino)
            replacement.replace(path)
            self.assertNotEqual(G.image_identity(path), original)
        with self.assertRaises(ValueError): G.image_identity(Path('relative'))

    def test_receipt_requires_new_file_and_joined_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);path=G.receipt_path(root/'receipt.json');workspace=root/'unjoined';workspace.mkdir()
            with self.assertRaises(ValueError):G.publish_receipt(path, {'native':True}, workspace)
            self.assertFalse(path.exists())
            workspace.rmdir();G.publish_receipt(path, {'scope':'actual'}, workspace)
            self.assertIn('actual',path.read_text())
            with self.assertRaises(ValueError):G.receipt_path(path)
            with self.assertRaises(FileExistsError):G.publish_receipt(path, {'overwrite':True}, workspace)


class CompilationDiagnostics(unittest.TestCase):
    def execute_boundary(self, *, compile_only=True, preflight_only=False, diagnostic_original_case=False, failure=False, source_changed=False, image_changed=False, wrong_image_compiler=False):
        calls=[]
        def run(command, **kwargs):
            calls.append((command,kwargs))
            if command[1:3] == ['test','-c']:
                if failure: raise subprocess.CalledProcessError(1,command,output='actual compiler failed')
                Path(command[command.index('-o')+1]).write_bytes(b'controlled native image')
                return ''
            if compile_only: self.fail('compilation-only diagnostic entered native PF/utun execution')
            if image_changed:
                first=calls[0][0];Path(first[first.index('-o')+1]).write_bytes(b'replaced native image')
            return preflight_transcript() if preflight_only else diagnostic_transcript() if diagnostic_original_case else transcript()
        source=Path('/captured/source');before={'original':'a'*64}
        inventory=[(source,before),(source,{'changed':'b'*64})] if source_changed else None
        with contextlib.redirect_stdout(io.StringIO()), patch.object(G,'required_host',return_value=('arm64',501)), patch.object(G,'checked_sources',side_effect=inventory,return_value=(source,before)), patch.object(G,'selected_compiler',return_value=('/captured/go',{})), patch.object(G.UID.RACE,'verify_image',side_effect=ValueError('wrong native compiler') if wrong_image_compiler else None) as image_readback, patch.object(G.UID,'privilege_tool',return_value='/usr/bin/sudo'), patch.object(G.UID,'run',side_effect=run), patch.object(G,'native_output',side_effect=run):
            result=G.execute(source,environment={},compile_only=compile_only,preflight_only=preflight_only,diagnostic_original_case=diagnostic_original_case)
        self.assertEqual(image_readback.call_count,2)
        self.assertEqual(result['toolchain'],'go1.26.5')
        for index,(command,kwargs) in enumerate(calls[:2]):
            self.assertEqual(image_readback.call_args_list[index].args,('/captured/go',command[command.index('-o')+1],source,{}))
            self.assertEqual(command[:6],G.native_fixture_compile('/captured/go',Path('/unused'),command[-1])[:6])
            self.assertEqual(kwargs['timeout'],600)
            self.assertFalse(Path(command[command.index('-o')+1]).exists())
        return result,calls

    def test_compilation_diagnostics_never_execute_or_publish_native_acceptance(self):
        result,calls=self.execute_boundary()
        self.assertEqual(len(calls),2)
        self.assertEqual(result['scope'],'native-compilation-only')
        self.assertIs(result['native_accepted'],False)
        self.assertNotIn('cases',result)
        self.assertEqual(set(result['artifacts']),{'generated-child-test','independent-ordered-peer'})
        with self.assertRaises(ValueError):G.check_verdict(json.dumps(result))
        with tempfile.TemporaryDirectory() as directory:
            receipt=Path(directory)/'native.json'
            with self.assertRaisesRegex(ValueError,'not native acceptance'):
                G.publish_receipt(receipt,result,Path(directory)/'retired')
            self.assertFalse(receipt.exists())
            with self.assertRaisesRegex(ValueError,'cannot publish'):
                G.standalone(compile_only=True,receipt=receipt)

    def test_original_default_still_requires_all_native_verdicts(self):
        result,calls=self.execute_boundary(compile_only=False)
        self.assertEqual(len(calls),3)
        self.assertEqual(calls[-1][1]['timeout'],960)
        self.assertIn('-test.timeout=930s',calls[-1][0])
        self.assertEqual(result['scope'],'generated-command-utun')
        self.assertEqual(result['cases'],list(G.CASES))

    def test_failed_compilation_or_changed_source_has_no_diagnostic_success(self):
        with self.assertRaises(subprocess.CalledProcessError):self.execute_boundary(failure=True)
        with self.assertRaisesRegex(ValueError,'wrong native compiler'):self.execute_boundary(wrong_image_compiler=True)
        with self.assertRaisesRegex(ValueError,'sources changed'):self.execute_boundary(source_changed=True)
        with self.assertRaisesRegex(ValueError,'purpose must be explicit'):G.execute(Path('/unused'),compile_only='true')



class HandshakePreflight(unittest.TestCase):
    def test_exact_signed_refusal_stop_and_wait_order(self):
        G.check_preflight_verdict(preflight_transcript())
        with self.assertRaises(ValueError): G.check_verdict(preflight_transcript())
        with self.assertRaises(ValueError): G.check_preflight_verdict(transcript())

    def test_every_original_root_and_refusal_stop_join_receipt_is_required(self):
        original=preflight_transcript()
        for line in original.splitlines():
            if line == 'PASS': continue
            with self.subTest(omitted=line), self.assertRaises(ValueError):
                G.check_preflight_verdict(original.replace(line+'\n','',1))
            with self.subTest(duplicated=line), self.assertRaises(ValueError):
                G.check_preflight_verdict(original.replace(line+'\n',line+'\n'+line+'\n',1))

    def test_receipt_order_foreign_owner_and_early_pass_are_rejected(self):
        original=preflight_transcript()
        first='verified original Darwin handshake preflight: source-refused'
        stop='verified original Darwin handshake preflight: authenticated-stop'
        joined='verified original Darwin handshake preflight: original-join'
        native_pass='--- PASS: '+G.PREFLIGHT_NATIVE+' (1.00s)'
        changes=[
            original.replace(G.PREFLIGHT_NATIVE, G.PREFLIGHT_NATIVE+'Foreign'),
            original.replace(first+'\n','').replace(native_pass,native_pass+'\n'+first),
            original.replace(joined+'\n','').replace(native_pass,native_pass+'\n'+joined),
        ]
        # Explicit swaps cannot accidentally collapse to the original transcript.
        lines=original.splitlines()
        for a,b in ((2,3),(3,4),(4,5),(5,6)):
            altered=lines[:];altered[a],altered[b]=altered[b],altered[a];changes.append('\n'.join(altered)+'\n')
        for number, changed in enumerate(changes):
            with self.subTest(change=number), self.assertRaises(ValueError):
                G.check_preflight_verdict(changed)

    def test_failed_skipped_raced_or_panicked_preflight_is_not_a_receipt(self):
        for failure in ('--- FAIL: x (0.00s)', '--- SKIP: x (0.00s)', 'WARNING: DATA RACE', 'panic: original owner'):
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                G.check_preflight_verdict(preflight_transcript()+failure+'\n')

    def test_preflight_mode_uses_original_images_without_full_native_acceptance(self):
        result,calls=CompilationDiagnostics().execute_boundary(compile_only=False,preflight_only=True)
        self.assertEqual(len(calls),3)
        self.assertEqual(calls[-1][1]['timeout'],120)
        self.assertIn('-test.run=^'+G.PREFLIGHT_HARNESS+'$',calls[-1][0])
        self.assertIn('-test.timeout=115s',calls[-1][0])
        self.assertNotIn('-test.run=^'+G.HARNESS+'$',calls[-1][0])
        self.assertEqual(result['scope'],'native-handshake-only')
        self.assertIs(result['native_accepted'],False)
        self.assertEqual(result['receipts'],list(G.PREFLIGHT_RECEIPTS))
        with tempfile.TemporaryDirectory() as directory:
            receipt=Path(directory)/'native.json'
            with self.assertRaisesRegex(ValueError,'not native acceptance'):
                G.publish_receipt(receipt,result,Path(directory)/'retired')
            with self.assertRaisesRegex(ValueError,'cannot publish'):
                G.standalone(preflight_only=True,receipt=receipt)
            self.assertFalse(receipt.exists())

    def test_preflight_source_image_and_exclusive_purpose_remain_bound(self):
        with self.assertRaisesRegex(ValueError,'sources changed'):
            CompilationDiagnostics().execute_boundary(compile_only=False,preflight_only=True,source_changed=True)
        with self.assertRaisesRegex(ValueError,'sources or images'):
            CompilationDiagnostics().execute_boundary(compile_only=False,preflight_only=True,image_changed=True)
        for kwargs in ({'compile_only':True,'preflight_only':True},{'preflight_only':'true'}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError,'purpose must be explicit'):
                G.execute(Path('/unused'),**kwargs)

    def test_source_refusal_is_staged_before_capture_without_pf_launcher(self):
        raw=(ROOT/'mobile/desktop/node_chain_command_darwin_native_test.go.tmpl').read_text()
        body=raw[raw.index('func TestRouterVPNNodeChainDarwinNativeHandshake(t *testing.T) {'):]
        self.assertLess(body.index('"node-chain-source.json":'),body.index('macosprocess.OpenCapture('))
        self.assertIn('"sing-box.json": policy.Config()',body)
        for forbidden in ('installBaseline(', 'darwinChildOwner', 'box.New(', 'darwinChildPeerStart('):
            self.assertNotIn(forbidden,body)
        for required in ('macosprocess.BindCreated(', 'bootstrap.Current(ctx)', 'bootstrap.Stop(stopping)',
                         'command.Wait()', 'checkStopped()', 'darwinChildHandshakeUnchanged(ctx, before)',
                         'authority.close()', '"node-mtu-status.json"'):
            self.assertIn(required,body)
        self.assertLess(body.index('fmt.Println("verified original Darwin handshake preflight: source-refused")'),
                        body.index('bootstrap.Stop(stopping)'))
        production=(ROOT/'mobile/desktop/node_chain_run_darwin.go.tmpl').read_text()
        self.assertLess(production.index('macosprocess.BindInherited('),production.index('return routerVPNExternalControlledLifetime('))
        self.assertLess(production.index('control.compile(admission, files)'),production.index('control.prepare(graph, policy)'))
        self.assertLess(production.index('control.prepare(graph, policy)'),production.index('box.New('))



class OriginalCaseDiagnostic(unittest.TestCase):
    def test_fixed_case_is_distinct_from_both_existing_native_purposes(self):
        G.check_diagnostic_verdict(diagnostic_transcript())
        with self.assertRaises(ValueError): G.check_verdict(diagnostic_transcript())
        with self.assertRaises(ValueError): G.check_preflight_verdict(diagnostic_transcript())
        for foreign in (transcript(), preflight_transcript(), diagnostic_transcript().replace('wg-three','mixed-four')):
            with self.subTest(foreign=foreign[:60]), self.assertRaises(ValueError):
                G.check_diagnostic_verdict(foreign)
        for line in diagnostic_transcript().splitlines():
            if line == 'PASS': continue
            for replacement in ('', line+'\n'+line+'\n'):
                with self.subTest(line=line,replacement=replacement), self.assertRaises(ValueError):
                    G.check_diagnostic_verdict(diagnostic_transcript().replace(line+'\n',replacement,1))
        for failure in ('--- FAIL: x (0.00s)','--- SKIP: x (0.00s)','WARNING: DATA RACE','panic: original'):
            with self.subTest(failure=failure),self.assertRaises(ValueError):
                G.check_diagnostic_verdict(diagnostic_transcript()+failure+'\n')

    def test_original_images_bounds_and_exact_selection_cannot_claim_full_native(self):
        result,calls=CompilationDiagnostics().execute_boundary(compile_only=False,diagnostic_original_case=True)
        self.assertEqual(len(calls),3)
        self.assertEqual(calls[-1][1]['timeout'],960)
        self.assertIn('-test.timeout=930s',calls[-1][0])
        self.assertIn('-test.run=^'+G.DIAGNOSTIC_HARNESS+'$',calls[-1][0])
        self.assertIs(result['native_accepted'],False)
        self.assertEqual(result['cases'],['wg-three'])
        self.assertEqual(result['scope'],'original-single-case-diagnostic')
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'receipt.json';retired=Path(directory)/'retired'
            with self.assertRaises(ValueError):G.publish_receipt(path,result,retired)
            G.publish_diagnostic_receipt(path,result,retired)
            self.assertEqual(json.loads(path.read_text()),result)
            with self.assertRaises(FileExistsError):G.publish_diagnostic_receipt(path,result,retired)
            for changed in (dict(result,native_accepted=True),dict(result,cases=list(G.CASES)),dict(result,scope='generated-command-utun')):
                with self.assertRaises(ValueError):G.publish_diagnostic_receipt(None,changed,retired)
            retired.mkdir()
            with self.assertRaises(ValueError):G.publish_diagnostic_receipt(None,result,retired)
        for change in ('source_changed','image_changed'):
            with self.subTest(change=change),self.assertRaises(ValueError):
                CompilationDiagnostics().execute_boundary(compile_only=False,diagnostic_original_case=True,**{change:True})

    def test_scheduled_checkpoint_is_exact_source_bound_and_never_a_started_case(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'scheduled.json'
            identity=dict(repository='Eabusham2/router-vpn',commit='a'*40,tree='b'*40)
            with patch.object(G,'required_host',return_value=('arm64',501)),patch.object(G,'repository_identity',return_value=identity),patch.object(G.BUILD,'digest',return_value='c'*64):
                value=G.write_diagnostic_checkpoint(path,'a'*40,{})
                raw=G.read_diagnostic_checkpoint(path,'a'*40,{})
                self.assertEqual(json.loads(raw),value)
                self.assertEqual(value['state'],'scheduled')
                self.assertIs(value['case_started'],False)
                self.assertIs(value['native_accepted'],False)
                self.assertEqual(value['case'],'wg-three')
                self.assertEqual(value['repository'],identity)
                with self.assertRaises(ValueError):G.write_diagnostic_checkpoint(path,'a'*40,{})
                for key,changed in (('case','mixed-four'),('case_started',True),('native_accepted',True),('state','completed'),('source_sha256','d'*64),('schema',True)):
                    altered=dict(value,**{key:changed});path.write_text(json.dumps(altered,indent=2,sort_keys=True)+'\n')
                    with self.subTest(key=key),self.assertRaises(ValueError):G.read_diagnostic_checkpoint(path,'a'*40,{})
                path.write_bytes(raw)
                with patch.object(G.BUILD,'digest',return_value='d'*64),self.assertRaises(ValueError):G.read_diagnostic_checkpoint(path,'a'*40,{})
                with self.assertRaises(ValueError):G.write_diagnostic_checkpoint(Path(directory)/'other.json',None,{})
                path.unlink();path.symlink_to(Path(directory)/'missing')
                with self.assertRaises(ValueError):G.read_diagnostic_checkpoint(path,'a'*40,{})

    def test_diagnostic_never_bypasses_original_scope_before_preparation(self):
        invalid=(
            dict(diagnostic_original_case=True),dict(diagnostic_original_case='true'),
            dict(diagnostic_original_case=True,compile_only=True),
            dict(diagnostic_original_case=True,preflight_only=True),
            dict(diagnostic_original_case=True,receipt=Path('/unused')),
            dict(diagnostic_checkpoint=Path('/unused')),dict(diagnostic_receipt=Path('/unused')),
        )
        for kwargs in invalid:
            with self.subTest(kwargs=kwargs),patch.object(G,'required_host',side_effect=AssertionError('preparation reached')),self.assertRaises(ValueError):
                G.standalone(**kwargs)

    def test_tagged_diagnostic_uses_original_case_cleanup_and_distinct_marker(self):
        source=(ROOT/'mobile/desktop/node_chain_command_darwin_native_test.go.tmpl').read_text()
        self.assertIn('func TestRouterVPNNodeChainDarwinNativeCommand(t *testing.T) {\n\tdarwinChildCommandCases(t, false)\n}',source)
        self.assertIn('func TestRouterVPNNodeChainDarwinNativeDiagnostic(t *testing.T) {\n\tdarwinChildCommandCases(t, true)\n}',source)
        self.assertIn('cases := darwinChildCases\n\tif diagnostic {\n\t\tcases = darwinChildCases[:1]\n\t}',source)
        self.assertIn('darwinChildCases[0] != "wg-three"',source)
        body=source[source.index('func darwinChildCommandCases('):source.index('// The handshake diagnostic')]
        for unchanged in ('owner.start(t, ctx, authority, policy)','owner.stop(cleanup)','owner.stopUnstarted(cleanup, t.Failed())','authority.close()','90*time.Second','15*time.Second'):
            self.assertIn(unchanged,body)
        self.assertIn('"native-child-complete", "all original child owners joined\\n"',body)
        self.assertIn('"native-child-diagnostic-complete", "original wg-three diagnostic joined\\n"',body)

    def test_manual_checkpoint_upload_precedes_pf_attempt_and_cannot_replace_push_gate(self):
        raw=(ROOT/'.github/workflows/darwin-original-case-diagnostic.yml').read_text()
        self.assertIn('  workflow_dispatch:',raw)
        for forbidden in ('  push:','  pull_request:','  workflow_call:','inputs:','matrix:','continue-on-error:'):
            self.assertNotIn(forbidden,raw)
        self.assertIn('    runs-on: macos-15',raw)
        self.assertIn('--write-diagnostic-checkpoint',raw)
        self.assertLess(raw.index('--write-diagnostic-checkpoint'),raw.index('name: Preserve scheduled source and case before PF'))
        self.assertLess(raw.index('name: Preserve scheduled source and case before PF'),raw.index('--diagnostic-original-case'))
        self.assertIn('if-no-files-found: error',raw)
        self.assertEqual(raw.count('--diagnostic-original-case'),1)
        self.assertNotIn('--receipt ',raw)
        workflow_inventory((ROOT/'.github/workflows/darwin-node-child-tun.yml').read_text())


class EncryptedPeerSourceClosure(unittest.TestCase):
    def test_darwin_projects_only_original_build_constraint(self):
        copies=G.NODE.PREP.darwin_node_chain_peer_copies()
        self.assertEqual(set(copies),set(G.NODE.PREP.DARWIN_NODE_CHAIN_PEERS.values()))
        before=b'//go:build linux && !android\n\npackage routervpnamnezia\n'
        after=b'//go:build darwin && routervpn_darwin_node_chain && routervpn_darwin_external_host\n\npackage routervpnamnezia\n'
        for name,target in G.NODE.PREP.DARWIN_NODE_CHAIN_PEERS.items():
            source=(ROOT/'mobile/desktop'/name).read_bytes()
            self.assertTrue(source.startswith(before))
            self.assertEqual(copies[target],after+source[len(before):])
            self.assertTrue(target.endswith('_darwin_test.go'))

    def test_wrong_original_platform_or_symlink_cannot_be_projected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'mobile/desktop';source.mkdir(parents=True)
            for name in G.NODE.PREP.DARWIN_NODE_CHAIN_PEERS:
                (source/name).write_bytes((ROOT/'mobile/desktop'/name).read_bytes())
            with patch.object(G.NODE.PREP,'ROOT',root):
                G.NODE.PREP.darwin_node_chain_peer_copies()
                target=source/next(iter(G.NODE.PREP.DARWIN_NODE_CHAIN_PEERS));raw=target.read_bytes()
                target.write_bytes(raw.replace(b'linux && !android',b'windows',1))
                with self.assertRaises(ValueError):G.NODE.PREP.darwin_node_chain_peer_copies()
                target.unlink();other=source/'foreign';other.write_bytes(raw);target.symlink_to(other)
                with self.assertRaises(ValueError):G.NODE.PREP.darwin_node_chain_peer_copies()

    def test_address_and_final_only_benchmark_scope_remain_explicit(self):
        raw=(ROOT/'mobile/desktop/node_chain_peer_linux_test.go.tmpl').read_text()
        for needle in ('address == "192.168.210.2" && client == "192.168.210.1"',
                       'address != client', 'ROUTERVPN_DARWIN_NODE_CHAIN_ADDRESS', 'found == 1',
                       'request.BenchmarkPort != 0 && request.BenchmarkPort != 45998',
                       'Destination: "10.77.0.1:45998"', 'if p.held.Load()', 'n > 8972'):
            self.assertIn(needle,raw)
        imported=(ROOT/'mobile/desktop/node_imported_peer_linux_test.go.tmpl').read_text()
        self.assertIn('if !request.Cover || n < 1 || n > 1200',imported)
        self.assertNotIn('45998',imported)


class StreamingNativeOutput(unittest.TestCase):
    def assert_sink_flags_restored(self, actual, original, *, platform=None):
        # Darwin records successful writes in sticky FWASWRITTEN (0x10000).
        # XNU F_GETFL exposes it, while F_SETFL preserves it outside
        # FCNTLFLAGS. Only its transition from clear to set is incidental;
        # access mode, nonblocking, append and every other bit remain exact.
        # https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/fcntl.h
        # https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_descrip.c
        # https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/sys_generic.c
        platform = sys.platform if platform is None else platform
        allowed = (original, original | 0x10000) if platform == 'darwin' else (original,)
        self.assertIn(actual, allowed)

    def test_only_darwin_sticky_write_history_is_incidental(self):
        for original in (os.O_WRONLY, os.O_WRONLY | os.O_NONBLOCK,
                         os.O_WRONLY | os.O_APPEND,
                         os.O_WRONLY | os.O_NONBLOCK | os.O_APPEND):
            with self.subTest(original=original):
                self.assert_sink_flags_restored(original, original, platform='darwin')
                self.assert_sink_flags_restored(original | 0x10000, original, platform='darwin')
                with self.assertRaises(AssertionError):
                    self.assert_sink_flags_restored(original, original | 0x10000, platform='darwin')
                with self.assertRaises(AssertionError):
                    self.assert_sink_flags_restored(original | 0x10000, original, platform='linux')
                changes = (os.O_NONBLOCK, os.O_APPEND, os.O_RDWR,
                           getattr(os, 'O_ASYNC', 0), getattr(os, 'O_SYNC', 0),
                           getattr(os, 'O_DSYNC', 0), 0x40000000)
                for changed in filter(None, changes):
                    with self.subTest(changed=changed), self.assertRaises(AssertionError):
                        self.assert_sink_flags_restored((original ^ changed) | 0x10000,
                                                        original, platform='darwin')

    def test_actual_pipe_write_history_and_refused_flags_join_original_reader(self):
        # Exercise the real reporting subprocess/pipe on every host. Inject
        # only Darwin's observed sticky bit at final readback on other hosts;
        # an additional nonblocking drift must still fail after reader join.
        check = self.assert_sink_flags_restored
        popen = subprocess.Popen
        for drift in (False, True):
            children = []
            observed = []
            def capture(*args, **kwargs):
                child = popen(*args, **kwargs); children.append(child); return child
            def readback(actual, original):
                observed.append((actual, original))
                check(actual | 0x10000 | (os.O_NONBLOCK if drift else 0),
                      original, platform='darwin')
            with self.subTest(drift=drift), patch.object(subprocess, 'Popen', side_effect=capture), patch.object(self, 'assert_sink_flags_restored', side_effect=readback):
                expected = self.assertRaises(AssertionError) if drift else contextlib.nullcontext()
                with expected:
                    with self.captured_sink() as sink:
                        output = G.native_output([sys.executable, '-c',
                            'print("original written pipe",flush=True)'], timeout=3)
                    self.assertEqual(output, 'original written pipe\n')
                    self.assertEqual(sink['output'], b'original written pipe\n')
            self.assertEqual(len(observed), 1)
            self.assertEqual(len(children), 2)
            for child in children:
                self.assertEqual(child.returncode, 0)
                with self.assertRaises(ProcessLookupError): os.killpg(child.pid, 0)

    @contextlib.contextmanager
    def captured_sink(self, *, ack=None, partial=False):
        import fcntl
        with tempfile.TemporaryDirectory(prefix='native-reporting-pipe-') as temporary:
            output = Path(temporary)/'output'
            read, write = os.pipe()
            reader = subprocess.Popen([sys.executable, '-c', """import os,pathlib,sys
fd=int(sys.argv[1]);body=bytearray()
while True:
 chunk=os.read(fd,65536)
 if not chunk:break
 body.extend(chunk)
 if sys.argv[3] and b'original native stage\\n' in body:pathlib.Path(sys.argv[3]).write_text('original bytes observed')
pathlib.Path(sys.argv[2]).write_bytes(body)
""", str(read), str(output), str(ack) if ack else ''], pass_fds=(read,),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            os.close(read)
            original_flags = fcntl.fcntl(write, fcntl.F_GETFL)
            stream = os.fdopen(write, 'wb', buffering=0)
            class Sink:
                buffer = stream
            captured = {'partial_writes': 0}
            original_write = os.write
            def shorter(fd, data):
                if partial and len(data) > 17:
                    captured['partial_writes'] += 1
                    return original_write(fd, data[:17])
                return original_write(fd, data)
            try:
                with patch.object(G.sys, 'stdout', Sink()), patch.object(G.os, 'write', side_effect=shorter):
                    yield captured
            finally:
                try:
                    self.assert_sink_flags_restored(fcntl.fcntl(write, fcntl.F_GETFL), original_flags)
                finally:
                    stream.close()
                    try:
                        _, errors = reader.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(reader.pid, signal.SIGKILL); reader.communicate(timeout=2)
                        raise
                    self.assertEqual(reader.returncode, 0, errors.decode())
                    captured['output'] = output.read_bytes()

    def test_actual_native_bytes_arrive_before_original_process_exit(self):
        source = (ROOT/'deploy/test_darwin_node_child_tun.py').read_text()
        helper = source[source.index('def native_output('):source.index('\ndef execute_native_images(')]
        needle = 'forward(chunk, deadline)'
        self.assertEqual(helper.count(needle), 2)
        # Mutate only the call, retaining the original forwarding definition.
        needle = '                            forward(chunk, deadline)'
        self.assertEqual(helper.count(needle), 1)
        child = """import pathlib,sys,time
ack=pathlib.Path(sys.argv[1])
print("original native stage",flush=True)
while not ack.exists():time.sleep(0.01)
print("original command completed",flush=True)
"""
        with tempfile.TemporaryDirectory() as directory:
            for mutated in (False, True):
                ack = Path(directory)/('mutant' if mutated else 'original')
                namespace = dict(G.__dict__)
                changed = helper.replace(needle, '                            pass # withheld output', 1) if mutated else helper
                self.assertEqual(changed != helper, mutated)
                exec(changed, namespace)
                with self.captured_sink(ack=ack) as sink:
                    if mutated:
                        with self.assertRaisesRegex(RuntimeError, 'timed out after its process group was joined') as refused:
                            namespace['native_output']([sys.executable, '-c', child, str(ack)], timeout=3)
                        self.assertIsInstance(refused.exception.__cause__, subprocess.TimeoutExpired)
                        self.assertEqual(refused.exception.__cause__.output, b'original native stage\n')
                        self.assertFalse(ack.exists())
                    else:
                        output = namespace['native_output']([sys.executable, '-c', child, str(ack)], timeout=3)
                        self.assertEqual(output, 'original native stage\noriginal command completed\n')
                        with self.assertRaises(ValueError): G.check_verdict(output)
                self.assertEqual(sink['output'], b'' if mutated else output.encode())

    def test_actual_failure_preserves_same_captured_output_and_exit(self):
        with self.captured_sink() as sink, self.assertRaises(subprocess.CalledProcessError) as failed:
            G.native_output([sys.executable, '-c', 'import sys;print("actual native refusal",flush=True);sys.exit(17)'], timeout=3)
        self.assertEqual(failed.exception.returncode, 17)
        self.assertEqual(failed.exception.output, b'actual native refusal\n')
        self.assertEqual(sink['output'], b'actual native refusal\n')

    def test_actual_timeout_signals_only_new_original_group_and_stays_failed(self):
        kill = os.killpg
        calls = []
        def captured(group, sig):
            calls.append((group, sig)); return kill(group, sig)
        started = time.monotonic()
        with self.captured_sink() as output, patch.object(G.os, 'killpg', side_effect=captured), self.assertRaisesRegex(RuntimeError, 'timed out after its process group was joined'):
            G.native_output([sys.executable, '-c', 'import os,time;print("original-group="+str(os.getpid()),flush=True);time.sleep(30)'], timeout=0.25)
        self.assertLess(time.monotonic()-started, 3)
        group = int(output['output'].decode().strip().split('=')[1])
        self.assertNotEqual(group, os.getpgrp())
        self.assertEqual(calls, [(group, signal.SIGKILL)])

    def test_actual_partial_writes_preserve_every_original_byte_and_flags(self):
        body = ('original complete native transcript\n'*4096).encode()
        with self.captured_sink(partial=True) as sink:
            output = G.native_output([sys.executable, '-c', 'import sys;sys.stdout.write("original complete native transcript\\n"*4096)'], timeout=5)
        self.assertGreater(sink['partial_writes'], 0)
        self.assertEqual(output.encode(), body)
        self.assertEqual(sink['output'], body)

    def test_unsupported_sink_refuses_before_any_native_process(self):
        with contextlib.redirect_stdout(io.StringIO()), patch.object(G.subprocess, 'Popen') as start:
            with self.assertRaisesRegex(ValueError, 'captured writable pipe'):
                G.native_output(['must-not-start'], timeout=1)
            start.assert_not_called()

    def test_spawn_failure_restores_flags_and_concurrent_writer_refuses_before_start(self):
        import fcntl
        import threading
        with self.captured_sink(), patch.object(G.subprocess, 'Popen', side_effect=OSError('captured spawn refusal')):
            with self.assertRaisesRegex(OSError, 'captured spawn refusal'):
                G.native_output(['does-not-start'], timeout=1)
        entered, release = threading.Event(), threading.Event()
        def other_writer():
            entered.set(); release.wait(3)
        worker = threading.Thread(target=other_writer)
        worker.start()
        try:
            self.assertTrue(entered.wait(1))
            with patch.object(G.subprocess, 'Popen') as start:
                with self.assertRaisesRegex(ValueError, 'sole original caller'):
                    G.native_output(['must-not-start'], timeout=1)
                start.assert_not_called()
        finally:
            release.set(); worker.join(2)
        self.assertFalse(worker.is_alive())

    def test_closed_pipe_keeps_failure_and_joins_original_group(self):
        import fcntl
        read, write = os.pipe(); os.close(read)
        stream = os.fdopen(write, 'wb', buffering=0)
        class Sink:
            buffer = stream
        flags = fcntl.fcntl(write, fcntl.F_GETFL)
        children = []
        popen = subprocess.Popen
        def captured(*args, **kwargs):
            process = popen(*args, **kwargs); children.append(process); return process
        try:
            with patch.object(G.sys, 'stdout', Sink()), patch.object(G.subprocess, 'Popen', side_effect=captured):
                with self.assertRaisesRegex(RuntimeError, 'reporting failed after its process group was joined') as failed:
                    G.native_output([sys.executable, '-c', 'import time;print("original refusal",flush=True);time.sleep(30)'], timeout=1)
            self.assertIsInstance(failed.exception.__cause__, BrokenPipeError)
            self.assertIn('original refusal', str(failed.exception))
            self.assertEqual(fcntl.fcntl(write, fcntl.F_GETFL), flags)
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].returncode)
            with self.assertRaises(ProcessLookupError): os.killpg(children[0].pid, 0)
        finally:
            stream.close()

    def test_full_pipe_cannot_defer_original_deadline_and_blocking_control_is_detected(self):
        import fcntl
        import select
        # The parent owns and fills the report pipe, then withholds all reads.
        # Both implementations run the real imported function in one original
        # process. The old blocking behavior is released and joined afterward.
        script = r"""import fcntl,importlib.util,json,os,pathlib,subprocess,sys
source,receipt,mode=sys.argv[1:]
spec=importlib.util.spec_from_file_location('actual_native_gate',source);g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
if mode=='blocking':
 text=pathlib.Path(source).read_text();begin=text.index('def native_output(');end=text.index('\ndef execute_preflight_images(',begin)
 helper=text[begin:end];needle='flags | os.O_NONBLOCK'
 assert helper.count(needle)==1
 exec(helper.replace(needle,'flags',1),g.__dict__)
children=[];original=subprocess.Popen
def capture(*args,**kwargs):
 p=original(*args,**kwargs);children.append(p);return p
subprocess.Popen=capture
flags=fcntl.fcntl(1,fcntl.F_GETFL)
result={}
try:g.native_output([sys.executable,'-c','import time;print("captured native output",flush=True);time.sleep(30)'],timeout=0.10)
except BaseException as e:result={'error':str(e),'cause':type(e.__cause__).__name__}
result['flags_restored']=fcntl.fcntl(1,fcntl.F_GETFL)==flags
result['children']=[]
for p in children:
 try:os.killpg(p.pid,0);absent=False
 except ProcessLookupError:absent=True
 result['children'].append({'joined':p.returncode is not None,'group_absent':absent})
pathlib.Path(receipt).write_text(json.dumps(result))
"""
        with tempfile.TemporaryDirectory(prefix='native-reporting-backpressure-') as directory:
            for mode in ('bounded', 'blocking'):
                receipt = Path(directory)/mode
                read, write = os.pipe()
                flags = fcntl.fcntl(write, fcntl.F_GETFL)
                fcntl.fcntl(write, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                try:
                    while True: os.write(write, b'held reporter '*4096)
                except BlockingIOError:
                    pass
                fcntl.fcntl(write, fcntl.F_SETFL, flags)
                process = subprocess.Popen([sys.executable, '-c', script, str(ROOT/'deploy/test_darwin_node_child_tun.py'), str(receipt), mode],
                    stdout=write, stderr=subprocess.PIPE, start_new_session=True)
                os.close(write)
                completed_while_held = False
                try:
                    try:
                        process.wait(timeout=1.5)
                        completed_while_held = True
                    except subprocess.TimeoutExpired:
                        pass
                    # Release the same pipe for the blocking causal control;
                    # its own original deadline must now kill/join its child.
                    os.set_blocking(read, False)
                    deadline = time.monotonic()+5
                    while process.poll() is None:
                        if time.monotonic() >= deadline: self.fail('original reporter process did not join after its pipe was released')
                        if select.select([read], [], [], 0.05)[0]:
                            try: os.read(read, 65536)
                            except BlockingIOError: pass
                    _, errors = process.communicate(timeout=2)
                    self.assertEqual(process.returncode, 0, errors.decode())
                    result = json.loads(receipt.read_text())
                    self.assertEqual(completed_while_held, mode=='bounded', result)
                    self.assertIn('timed out after its process group was joined', result['error'])
                    self.assertEqual(result['cause'], 'TimeoutExpired')
                    self.assertTrue(result['flags_restored'])
                    self.assertEqual(result['children'], [{'joined': True, 'group_absent': True}])
                finally:
                    os.close(read)
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL); process.communicate(timeout=2)

    def test_each_post_spawn_selector_setup_failure_joins_the_actual_original_child(self):
        real_selector = G.selectors.DefaultSelector
        real_popen = subprocess.Popen
        for stage in ('first-constructor', 'second-constructor', 'capture-register', 'forward-register'):
            with self.subTest(stage=stage), self.captured_sink():
                children = []
                constructions = 0
                def capture(*args, **kwargs):
                    process = real_popen(*args, **kwargs); children.append(process); return process
                def construct():
                    nonlocal constructions
                    constructions += 1
                    current = constructions
                    if (stage == 'first-constructor' and current == 1
                            or stage == 'second-constructor' and current == 2):
                        raise OSError('original selector setup refused')
                    selector = real_selector()
                    if (stage == 'capture-register' and current == 1
                            or stage == 'forward-register' and current == 2):
                        def refused(*args, **kwargs):
                            raise ValueError('original selector registration refused')
                        selector.register = refused
                    return selector
                with patch.object(G.subprocess, 'Popen', side_effect=capture), patch.object(G.selectors, 'DefaultSelector', side_effect=construct):
                    with self.assertRaisesRegex(RuntimeError, 'reporting failed after its process group was joined') as failed:
                        G.native_output([sys.executable, '-c', 'import time;time.sleep(30)'], timeout=1)
                self.assertIn('original selector', str(failed.exception.__cause__))
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].returncode)
                with self.assertRaises(ProcessLookupError): os.killpg(children[0].pid, 0)

    def test_foreign_duplicate_refuses_before_flags_or_native_ownership_change(self):
        import fcntl
        read, write = os.pipe()
        flags = fcntl.fcntl(write, fcntl.F_GETFL)
        duplicate = os.dup
        try:
            with self.captured_sink(), patch.object(G.os, 'dup', side_effect=lambda original: duplicate(write)), patch.object(G.subprocess, 'Popen') as start:
                with self.assertRaisesRegex(ValueError, 'duplicate lost its captured original sink'):
                    G.native_output(['must-not-start'], timeout=1)
                start.assert_not_called()
                self.assertEqual(fcntl.fcntl(write, fcntl.F_GETFL), flags)
        finally:
            os.close(read); os.close(write)

    def test_sudo_timeout_keeps_captured_negative_group_delimiter(self):
        source = (ROOT/'deploy/test_darwin_node_child_tun.py').read_text()
        helper = source[source.index('def native_output('):source.index('\ndef execute_native_images(')]
        self.assertIn("[sudo, '-n', '--', '/bin/kill', '-KILL', '--', '-'+str(process.pid)]", helper)
        self.assertIn('start_new_session=True', helper)
        self.assertIn('process.communicate(timeout=5)', helper)
        self.assertNotIn('native_down', helper)
        self.assertNotIn('pfctl', helper)


class BoundedHarnessReporting(unittest.TestCase):
    def test_actual_inner_command_streams_before_original_exit(self):
        source = (ROOT/'mobile/desktop/node_chain_command_darwin_native_test.go.tmpl').read_text()
        begin = source.index('func darwinChildHarnessOutput(')
        helper = source[begin:source.index('\n}', begin)+2]
        needle = 'command.Stdout = io.MultiWriter(&output, os.Stdout)'
        self.assertEqual(helper.count(needle), 1)
        fixture = r'''package main
import (
 "bufio"
 "bytes"
 "context"
 "errors"
 "fmt"
 "io"
 "os"
 "os/exec"
 "strings"
 "time"
)
var _ io.Writer = (*bytes.Buffer)(nil)
// SHIPPING_HARNESS_OUTPUT
func main() {
 if len(os.Args)>1 && os.Args[1]=="child" {
  fmt.Println("original native stage")
  deadline:=time.Now().Add(time.Second)
  for time.Now().Before(deadline) {
   if _,err:=os.Stat(os.Args[2]);err==nil {fmt.Println("original command joined");return}
   time.Sleep(time.Millisecond)
  }
  fmt.Fprintln(os.Stderr,"original native diagnostic was buffered until command exit")
  os.Exit(7)
 }
 if err:=verify(os.Args[1]);err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 fmt.Println("actual original native output streamed once before exit")
}
func verify(ack string) error {
 r,w,err:=os.Pipe();if err!=nil{return err};defer r.Close()
 original:=os.Stdout
 os.Stdout=w
 observed:=make(chan string,1)
 go func(){
  var output strings.Builder
  scanner:=bufio.NewScanner(r)
  for scanner.Scan(){line:=scanner.Text();output.WriteString(line+"\n");if line=="original native stage" {_=os.WriteFile(ack,[]byte("same original bytes"),0600)}}
  observed<-output.String()
 }()
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel()
 command:=exec.CommandContext(ctx,os.Args[0],"child",ack)
 output,failure:=darwinChildHarnessOutput(command)
 os.Stdout=original
 w.Close()
 streamed:=<-observed
 expected:="original native stage\noriginal command joined\n"
 if failure!=nil || string(output)!=expected || streamed!=expected {
  return errors.New("original native diagnostic was buffered until command exit")
 }
 return nil
}
'''
        with tempfile.TemporaryDirectory(prefix='darwin-child-streaming-') as directory:
            work=Path(directory);code=work/'main.go';image=work/'streaming'
            for mutated in (False, True):
                changed=helper.replace(needle,'command.Stdout = &output',1) if mutated else helper
                self.assertEqual(changed != helper, mutated)
                code.write_text(fixture.replace('// SHIPPING_HARNESS_OUTPUT',changed))
                subprocess.run([shutil.which('go'),'build','-p=1','-o',str(image),str(code)],cwd=work,check=True,timeout=90)
                result=subprocess.run([str(image),str(work/('mutant' if mutated else 'original'))],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=10)
                if mutated:
                    self.assertNotEqual(result.returncode,0,result.stdout)
                    self.assertIn('original native diagnostic was buffered until command exit',result.stdout)
                else:
                    self.assertEqual(result.returncode,0,result.stdout)
                    self.assertIn('actual original native output streamed once before exit',result.stdout)

    def test_actual_escaped_output_writer_cannot_hide_controller_failure(self):
        source = (ROOT/'mobile/desktop/node_chain_command_darwin_native_test.go.tmpl').read_text()
        signature = 'func darwinChildHarnessOutput(command *exec.Cmd) ([]byte, error) {'
        self.assertEqual(source.count(signature), 1)
        self.assertEqual(source.count('_, e = darwinChildHarnessOutput(command)'), 1)
        start = source.index(signature)
        end = source.index('\n}', start) + 2
        original = source[start:end]
        needle = 'command.WaitDelay = 5 * time.Second'
        self.assertEqual(original.count(needle), 1)
        go = shutil.which('go')
        self.assertIsNotNone(go, 'actual process-pipe reporting requires Go')
        fixture = r'''package main
import (
 "bytes"
 "io"
 "context"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "strconv"
 "strings"
 "syscall"
 "time"
)
// SHIPPING_HARNESS_OUTPUT
func main() {
 if len(os.Args)>1 && os.Args[1]=="writer" {
  fmt.Println("original escaped writer")
  time.Sleep(20*time.Second)
  return
 }
 if len(os.Args)>1 && os.Args[1]=="parent" {
  child:=exec.Command(os.Args[0],"writer")
  child.SysProcAttr=&syscall.SysProcAttr{Setpgid:true}
  child.Stdout=os.Stdout;child.Stderr=os.Stderr
  if err:=child.Start();err!=nil {panic(err)}
  if err:=os.WriteFile(os.Args[2],[]byte(strconv.Itoa(child.Process.Pid)),0600);err!=nil {panic(err)}
  return
 }
 if err:=verify(os.Args[1]);err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 fmt.Println("actual escaped output pipe bounded; native retirement remains unproved")
}
func verify(pidFile string) error {
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
 defer cancel()
 command:=exec.CommandContext(ctx,os.Args[0],"parent",pidFile)
 type result struct {output []byte;failure error}
 joined:=make(chan result,1)
 go func(){out,err:=darwinChildHarnessOutput(command);joined<-result{out,err}}()
 deadline:=time.Now().Add(2*time.Second)
 pid:=0
 for time.Now().Before(deadline) {
  raw,err:=os.ReadFile(pidFile)
  if err==nil {pid,err=strconv.Atoi(string(raw));if err!=nil{return err};break}
  time.Sleep(5*time.Millisecond)
 }
 if pid<=1 {return errors.New("actual escaped writer was never created")}
 group,err:=syscall.Getpgid(pid)
 if err!=nil || group!=pid || group==syscall.Getpgrp() {
  return errors.New("actual writer did not retain its independent process group")
 }
 // This fixture owns only a disposable writer, no native VPN/PF resources.
 // Never use this group signal as evidence of the production guardian join.
 defer syscall.Kill(-pid,syscall.SIGKILL)
 select {
 case result:=<-joined:
  if command.ProcessState==nil || !command.ProcessState.Success() {
   return errors.New("original direct controller did not exit successfully")
  }
  if !errors.Is(result.failure,exec.ErrWaitDelay) || !strings.Contains(string(result.output),"original escaped writer") {
   return errors.New("escaped output closure lost its failure or original diagnostic")
  }
  return nil
 case <-time.After(7*time.Second):
  syscall.Kill(-pid,syscall.SIGKILL)
  select {case <-joined:case <-time.After(2*time.Second):return errors.New("reporting control could not join its disposable writer")}
  return errors.New("Darwin native harness waited beyond its retained output bound")
 }
}
'''
        def member(signature):
            self.assertEqual(source.count(signature), 1)
            begin = source.index(signature)
            return source[begin:source.index('\n}', begin)+2]
        engine = member('func darwinChildEngineOutput(')
        utility = member('func darwinChildCommand(')
        self.assertEqual(source.count('darwinChildEngineOutput(o.command, &o.output)'), 1)
        engine_wrapper = '\nfunc darwinChildHarnessOutput(command *exec.Cmd) ([]byte,error) {var output bytes.Buffer;darwinChildEngineOutput(command,&output);err:=command.Run();return output.Bytes(),err}\n'
        utility_wrapper = '\nfunc darwinChildHarnessOutput(command *exec.Cmd) ([]byte,error) {return darwinChildCommand(context.Background(),command.Path,command.Args[1:]...)}\n'
        process_check = '  if command.ProcessState==nil || !command.ProcessState.Success() {\n   return errors.New("original direct controller did not exit successfully")\n  }\n'
        self.assertEqual(fixture.count(process_check), 1)
        fixture = fixture.replace('// SHIPPING_HARNESS_OUTPUT', 'var _ io.Writer = (*bytes.Buffer)(nil)\n// SHIPPING_HARNESS_OUTPUT', 1)
        implementations = [('controller', original, fixture, needle),
                           ('engine', engine+engine_wrapper, fixture, needle),
                           # The utility constructs its own exec.Cmd; ErrWaitDelay
                           # still requires its direct process to have exited zero.
                           ('utility', utility+utility_wrapper, fixture.replace(process_check, '', 1), 'c.WaitDelay = 5 * time.Second')]
        with tempfile.TemporaryDirectory(prefix='darwin-child-reporting-') as temporary:
            work = Path(temporary); code = work/'main.go'; image = work/'reporting'
            for label, actual, selected_fixture, bound in implementations:
                self.assertEqual(actual.count(bound), 1, label)
                for mutated in (False, True):
                    helper = actual.replace(bound, '', 1) if mutated else actual
                    self.assertEqual(helper != actual, mutated)
                    code.write_text(selected_fixture.replace('// SHIPPING_HARNESS_OUTPUT', helper))
                    subprocess.run([go, 'build', '-p=1', '-o', str(image), str(code)], cwd=work, check=True, timeout=90)
                    result = subprocess.run([str(image), str(work/(label+('-mutant.pid' if mutated else '-original.pid')))],
                                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
                    if mutated:
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                        self.assertIn('Darwin native harness waited beyond its retained output bound', result.stdout)
                    else:
                        self.assertEqual(result.returncode, 0, result.stdout)
                        self.assertIn('actual escaped output pipe bounded; native retirement remains unproved', result.stdout)


class BoundedPeerRetirement(unittest.TestCase):
    def test_actual_peer_kill_cannot_wait_forever_or_claim_join(self):
        source=(ROOT/'mobile/desktop/node_chain_command_darwin_native_test.go.tmpl').read_text()
        signature='func darwinChildPeerJoin('
        self.assertEqual(source.count(signature),1)
        begin=source.index(signature);helper=source[begin:source.index('\n}',begin)+2]
        self.assertEqual(source.count('joined, joinErr := darwinChildPeerJoin(p.command, p.done)'),1)
        needle='\tcase <-time.After(5 * time.Second):\n\t\treturn false, errors.Join(failure, errors.New("original encrypted peer waiter remains unjoined"))'
        self.assertEqual(helper.count(needle),1)
        fixture=r'''package main
import("errors";"fmt";"os";"os/exec";"strings";"sync";"time")
// SHIPPING_PEER_JOIN
func main(){
 if len(os.Args)>1{if os.Args[1]=="held"{time.Sleep(30*time.Second)};return}
 if err:=verify();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 fmt.Println("actual peer join bounded; held original receipt remains failure")
}
func verify()error{
 positive:=exec.Command(os.Args[0],"exit")
 if err:=positive.Start();err!=nil{return err}
 done:=make(chan struct{});var failure error
 go func(){failure=positive.Wait();close(done)}()
 joined,err:=darwinChildPeerJoin(positive,done)
 if !joined||err!=nil||failure!=nil{return errors.New("original successful peer did not join")}
 command:=exec.Command(os.Args[0],"held")
 if err:=command.Start();err!=nil{return err}
 reaped,release,held:=make(chan struct{}),make(chan struct{}),make(chan struct{})
 var once sync.Once
 go func(){_ = command.Wait();close(reaped);<-release;close(held)}()
 defer func(){_ = command.Process.Kill();once.Do(func(){close(release)});select{case <-held:case <-time.After(time.Second):}}()
 type result struct{joined bool;failure error}
 results:=make(chan result,1)
 go func(){joined,err:=darwinChildPeerJoin(command,held);results<-result{joined,err}}()
 select{
 case result:=<-results:
  if result.joined||result.failure==nil||!strings.Contains(result.failure.Error(),"original encrypted peer waiter remains unjoined"){
   return errors.New("missing original peer waiter receipt became successful retirement")
  }
  select{case <-reaped:default:return errors.New("cleanup did not signal its original disposable peer")}
 case <-time.After(12*time.Second):
  once.Do(func(){close(release)})
  select{case <-results:case <-time.After(time.Second):return errors.New("disposable peer control could not be recovered")}
  return errors.New("Darwin peer cleanup waited beyond its bounded post-kill join")
 }
 once.Do(func(){close(release)})
 select{case <-held:case <-time.After(time.Second):return errors.New("original held peer waiter did not finally join")}
 return nil
}
'''
        with tempfile.TemporaryDirectory(prefix='darwin-peer-join-') as directory:
            work=Path(directory);code=work/'main.go';image=work/'join'
            for mutated in (False,True):
                changed=helper.replace(needle,'',1) if mutated else helper
                self.assertEqual(changed!=helper,mutated)
                code.write_text(fixture.replace('// SHIPPING_PEER_JOIN',changed))
                subprocess.run([shutil.which('go'),'build','-p=1','-o',str(image),str(code)],cwd=work,check=True,timeout=90)
                result=subprocess.run([str(image)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=18)
                if mutated:
                    self.assertNotEqual(result.returncode,0,result.stdout)
                    self.assertIn('Darwin peer cleanup waited beyond its bounded post-kill join',result.stdout)
                else:
                    self.assertEqual(result.returncode,0,result.stdout)
                    self.assertIn('actual peer join bounded; held original receipt remains failure',result.stdout)


class UnstartedFixtureRetirement(unittest.TestCase):
    def test_actual_prestart_plan_and_monotonic_start_barriers(self):
        source = (ROOT/'mobile/desktop/node_chain_command_darwin_native_test.go.tmpl').read_text()
        def member(signature):
            self.assertEqual(source.count(signature), 1)
            begin = source.index(signature)
            return source[begin:source.index('\n}', begin)+2]
        install = member('func (o *darwinChildOwner) installBaseline(ctx context.Context) error {')
        retire = member('func (o *darwinChildOwner) stopUnstarted(ctx context.Context, failed bool) error {')
        wrapper = member('func (o *darwinChildOwner) start(')
        self.assertIn('o.policy = policy', wrapper)
        self.assertEqual(wrapper.count('o.startCaptured(t, ctx, a)'), 1)
        self.assertLess(wrapper.index('o.policy = policy'), wrapper.index('o.startCaptured(t, ctx, a)'))
        self.assertNotIn('o.command.Start()', wrapper)
        start = member('func (o *darwinChildOwner) startCaptured(')
        self.assertEqual(start.count('o.childStartAttempted = true'), 1)
        self.assertLess(start.index('o.childStartAttempted = true'), start.index('o.command.Start()'))
        self.assertEqual(source.count('o.childStartAttempted = true'), 1)
        self.assertNotIn('o.childStartAttempted = false', source)
        self.assertIn('if owner.childStartAttempted {\n\t\t\t\t\te = owner.stop(cleanup)\n\t\t\t\t} else {\n\t\t\t\t\te = owner.stopUnstarted(cleanup, t.Failed())', source)
        family = (ROOT/'mobile/desktop/node_chain_socks_command_darwin_native_test.go.tmpl').read_text()
        signature = 'func(o *darwinChildOwner) metadata()'
        self.assertEqual(family.count(signature), 1)
        begin = family.index(signature)
        metadata_helper = family[begin:family.index('\n}', begin)+2]
        # Only policy validation, PF/syscall and retained-descriptor boundaries
        # are modeled. The exclusive-family helper is actual fixture source.
        # Both complete fixture methods above execute with their actual guards.
        fixture = r"""package main
import("context";"errors";"fmt";"os";"os/exec";"time")
type DesktopDarwinPFBaselineProof struct {Present bool;RulesSHA256 string}
type DesktopDarwinPFBaselineRequest struct {Schema int;Action,SessionID,SourceSHA256 string;Expected []DesktopDarwinPFBaselineProof}
type DesktopDarwinPFBaselineResult struct {Schema int;Applied bool;Previous,Target DesktopDarwinPFBaselineProof}
type metadata struct{SessionID,SourceSHA256 string}
type DesktopNodeChainMetadata = metadata
type policy struct{invalid bool}
func(p *policy)ReadValidated()(string,metadata,struct{},error){if p.invalid{return "",metadata{},struct{}{},errors.New("invalid original policy")};return "",metadata{"original-session","original-source"},struct{}{},nil}
type socksMetadata struct{DesktopNodeChainMetadata metadata}
type socksPolicy struct{}
func(*socksPolicy)ReadValidated()(string,socksMetadata,struct{},error){return "",socksMetadata{metadata{"original-session","original-source"}},struct{}{},nil}
type retained struct{failure bool;closes int}
func(r *retained)Current(ctx context.Context)error{if r.failure{return errors.New("changed retained source")};return ctx.Err()}
func(r *retained)Close()error{r.closes++;return nil}
type files struct{root *retained}
type darwinChildOwner struct{
 policy *policy;socksPolicy *socksPolicy;baseline *DesktopDarwinPFBaselineResult;childStartAttempted bool
 command *exec.Cmd;bootstrap *int;done chan struct{};observed map[int]string
 closed bool;capture,channel *retained;files *files
}
var absent=DesktopDarwinPFBaselineProof{}
var target=DesktopDarwinPFBaselineProof{true,"exact-original-target"}
var actual DesktopDarwinPFBaselineProof
var lateFailure,children bool
var writes int
func darwinChildBaseline(ctx context.Context,r DesktopDarwinPFBaselineRequest,apply bool)(DesktopDarwinPFBaselineResult,error){
 if err:=ctx.Err();err!=nil{return DesktopDarwinPFBaselineResult{},err}
 accepted:=false;for _,value:=range r.Expected{accepted=accepted || value==actual}
 if !accepted || children{return DesktopDarwinPFBaselineResult{},errors.New("unknown PF owner remains")}
 next:=target;if r.Action=="clear"{next=absent}
 result:=DesktopDarwinPFBaselineResult{Schema:1,Applied:apply,Previous:actual,Target:next}
 if apply{writes++;actual=next;if lateFailure && r.Action=="replace"{return DesktopDarwinPFBaselineResult{},errors.New("committed but readback unavailable")}}
 return result,nil
}
// SHIPPING_PRESTART_METHODS
func fresh()*darwinChildOwner{actual=absent;lateFailure=false;children=false;writes=0;return &darwinChildOwner{policy:&policy{},capture:&retained{},channel:&retained{},files:&files{root:&retained{}}}}
func check(ok bool,text string){if !ok{panic(text)}}
func main(){
 ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel()
 for _,typed:=range []bool{false,true}{
 for _,committed:=range []bool{false,true}{
  owner:=fresh();if typed{owner.policy=nil;owner.socksPolicy=&socksPolicy{}};lateFailure=committed;err:=owner.installBaseline(ctx)
  check((err!=nil)==committed,"baseline boundary did not exercise late apply failure")
  check(owner.baseline!=nil && owner.baseline.Previous==absent && owner.baseline.Target==target,"lost original PF plan after partial apply")
  if !committed{actual=absent} // An apply that made no change is also an allowed exact prior.
  check(owner.stopUnstarted(ctx,true)==nil && owner.closed && actual==absent,"never-started failed fixture did not retire its exact PF plan")
  check(owner.capture.closes==1 && owner.channel.closes==1 && owner.files.root.closes==1,"never-started cleanup lost original descriptor joins")
 }
 }
 for _,fault:=range []string{"missing-policy","mixed-policy","invalid-policy"}{
  owner:=fresh()
  switch fault{case "missing-policy":owner.policy=nil;case "mixed-policy":owner.socksPolicy=&socksPolicy{};case "invalid-policy":owner.policy.invalid=true}
  err:=owner.installBaseline(ctx)
  check(err!=nil && owner.baseline==nil && writes==0,"invalid family acquired PF plan: "+fault)
 }
 for _,fault:=range []string{"attempted","process","bootstrap","joined-channel","utun","capture","missing-capture","foreign-baseline","child-rules","not-failed","deadline"}{
  owner:=fresh();check(owner.installBaseline(ctx)==nil,"original baseline install");before:=writes;failed:=true;call:=ctx
  switch fault{
  case "attempted":owner.childStartAttempted=true
  case "process":owner.command=&exec.Cmd{Process:&os.Process{Pid:os.Getpid()}}
  case "bootstrap":value:=1;owner.bootstrap=&value
  case "joined-channel":owner.done=make(chan struct{})
  case "utun":owner.observed=map[int]string{7:"utun-original"}
  case "capture":owner.capture.failure=true
  case "missing-capture":owner.capture=nil
  case "foreign-baseline":actual=DesktopDarwinPFBaselineProof{true,"foreign-owner"}
  case "child-rules":children=true
  case "not-failed":failed=false
  case "deadline":var cancel context.CancelFunc;call,cancel=context.WithCancel(ctx);cancel()
  }
  err:=owner.stopUnstarted(call,failed)
  check(err!=nil && !owner.closed && writes==before,"unproved pre-start cleanup erased PF: "+fault)
 }
 fmt.Println("actual pre-start fixture: planned late failure, both exact prior states, descriptor joins and11 ownership refusals PASS")
}
"""
        with tempfile.TemporaryDirectory(prefix='darwin-child-prestart-') as temporary:
            work = Path(temporary); code = work/'main.go'; image = work/'prestart'
            original = metadata_helper.replace('mobilemultihop.', '')+'\n'+install+'\n'+retire
            controls = (
                ('baseline plan', 'o.baseline = &plan', '', 'lost original PF plan after partial apply'),
                ('attempted start', '|| o.childStartAttempted ||', '||', 'unproved pre-start cleanup erased PF: attempted'),
                ('failed fixture', '!failed ||', '', 'unproved pre-start cleanup erased PF: not-failed'),
            )
            for label,before,after,witness in (('baseline','','',''),*controls):
                helper=original
                if before:
                    self.assertEqual(helper.count(before),1,label)
                    helper=helper.replace(before,after,1)
                    self.assertNotEqual(helper,original,label)
                code.write_text(fixture.replace('// SHIPPING_PRESTART_METHODS',helper.replace('mobiletor.','')))
                subprocess.run([shutil.which('go'),'build','-p=1','-o',str(image),str(code)],cwd=work,check=True,timeout=90)
                result=subprocess.run([str(image)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
                if witness:
                    self.assertNotEqual(result.returncode,0,label+result.stdout)
                    self.assertIn(witness,result.stdout)
                else:
                    self.assertEqual(result.returncode,0,result.stdout)
                    self.assertIn('and11 ownership refusals PASS',result.stdout)


class RequiredWorkflowInventory(unittest.TestCase):
    def test_both_actual_native_architectures_and_exact_caller_receipts(self):
        raw = (ROOT/'.github/workflows/darwin-node-child-tun.yml').read_text()
        workflow_inventory(raw)

    def test_missing_architecture_or_weakened_invocation_cannot_pass(self):
        raw = (ROOT/'.github/workflows/darwin-node-child-tun.yml').read_text()
        changes = (
            ('missing-amd64', '          - arch: amd64\n            runner: macos-15-intel\n', ''),
            ('missing-arm64', '          - arch: arm64\n            runner: macos-15\n', ''),
            ('wrong-runner', 'runner: macos-15-intel', 'runner: ubuntu-latest'),
            ('conditional-job', '  child:\n', '  child:\n    if: false\n'),
            ('nonblocking-job', '  child:\n', '  child:\n    continue-on-error: true\n'),
            ('caller-input', '  workflow_call:\n', '  workflow_call:\n    inputs:\n'),
            ('cross-caller-cancel', '-${{ github.sha }}-${{ github.run_id }}', ''),
            ('no-standalone', ' --standalone --require-commit "$ROUTERVPN_EXPECTED_SOURCE"', ' --require-commit "$ROUTERVPN_EXPECTED_SOURCE"'),
            ('no-handshake-boundary', ' --standalone --preflight-only --require-commit "$GITHUB_SHA"', ' --standalone --require-commit "$GITHUB_SHA"'),
            ('compile-only-replaces-handshake', ' --preflight-only', ' --compile-only'),
            ('compilation-replaces-native', ' --receipt "$ROUTERVPN_CHILD_RECEIPT"', ' --compile-only'),
            ('no-exact-commit', ' --require-commit "$ROUTERVPN_EXPECTED_SOURCE"', ''),
            ('no-receipt', ' --receipt "$ROUTERVPN_CHILD_RECEIPT"', ''),
            ('ignored-native-failure', ' --receipt "$ROUTERVPN_CHILD_RECEIPT"', ' --receipt "$ROUTERVPN_CHILD_RECEIPT" || true'),
            ('optional-artifact', 'if-no-files-found: error', 'if-no-files-found: warn'),
            ('fallback-result', '    timeout-minutes: 60', '    fallback: true\n    timeout-minutes: 60'),
        )
        for name, before, after in changes:
            self.assertEqual(raw.count(before), 1, name)
            with self.subTest(change=name), self.assertRaises(ValueError):
                workflow_inventory(raw.replace(before, after, 1))


if __name__=='__main__':
    unittest.main(verbosity=2)
