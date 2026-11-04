#!/usr/bin/env python3
"""Exercise the PQ native gate's actual source, scope and admission boundaries."""
from pathlib import Path
import ast
from contextlib import ExitStack, contextmanager, nullcontext, redirect_stdout
import importlib.util
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('windows_node_pq_gate', ROOT / 'deploy/test_windows_node_pq.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class NativePQScope(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='windows-pq-overlay-')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name).resolve()
        self.source = self.work / 'core'
        files = {
            GATE.PREDICATE: 'internal/mobilemultihop/desktop_node_admission.go',
            GATE.PEER: GATE.PEER_TEMPLATE,
            'routervpn/mobiletor/desktop_socket_windows_policy.go': 'internal/mobiletor/desktop_socket_windows_policy.go',
            'routervpn/mobiletor/desktop_socket_windows_transfer.go': 'internal/mobiletor/desktop_socket_windows_transfer.go',
            'routervpn/desktoppt/node_physical_windows.go': 'mobile/desktop/node_physical_windows.go.tmpl',
            'routervpn/desktoppt/node_physical.go': 'mobile/desktop/node_physical.go.tmpl',
        }
        self.original = {}
        for relative, actual in files.items():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = (ROOT / actual).read_bytes()
            if relative == GATE.PREDICATE and any(json.dumps(mode).encode() in raw for mode in GATE.PQ.MODES):
                # Counterfactual closed-source fixture only; real shipping
                # execution is covered independently below without overlays.
                raw = GATE.closed_predicate(raw.decode()).encode()
            path.write_bytes(raw)
            self.original[relative] = raw

    def directory(self, name):
        result = self.work / name
        result.mkdir()
        return result

    def test_required_shipping_workflow_and_builder_do_not_overlay_pq_admission(self):
        predicate = (ROOT / 'internal/mobilemultihop/desktop_node_admission.go').read_text()
        closed = GATE.closed_predicate(predicate)
        self.assertEqual(predicate, GATE.prospective_predicate(closed))
        workflow = (ROOT / '.github/workflows/windows-node-pq-contract.yml').read_text()
        commands = [line.strip() for line in workflow.splitlines()
                    if line.strip().startswith('python deploy/test_windows_node_pq.py ')]
        self.assertEqual(len(commands), 1)
        self.assertIn('--standalone --receipt', commands[0])
        self.assertNotIn('--prospective', commands[0])
        self.assertIn('runner: windows-latest', workflow)
        self.assertIn('runner: windows-11-arm', workflow)
        self.assertIn('if-no-files-found: error', workflow)
        build = ast.parse((ROOT / 'deploy/build-native-runtime.py').read_text())
        calls = [node for node in ast.walk(build)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'run'
                 and node.args and isinstance(node.args[0], ast.List)
                 and any(isinstance(item, ast.Constant) and item.value == 'deploy/test_windows_node_pq.py'
                         for item in ast.walk(node.args[0]))]
        self.assertEqual(len(calls), 1)
        self.assertNotIn('--prospective', [node.value for node in ast.walk(calls[0].args[0]) if isinstance(node, ast.Constant)])

    def test_pq_and_max_reopen_independent_controls_in_exact_shipping_order(self):
        maximum = GATE.load('pq_max_roundtrip_control', 'test_windows_node_max.py')
        shipping = (ROOT / 'internal/mobilemultihop/desktop_node_admission.go').read_text()
        without_pq = GATE.closed_predicate(shipping)
        without_max = maximum.closed_predicate(shipping)
        neither = GATE.closed_predicate(without_max)
        self.assertEqual(neither, maximum.closed_predicate(without_pq))
        self.assertEqual(GATE.prospective_predicate(without_pq), shipping)
        self.assertEqual(maximum.prospective_predicate(without_max), shipping)
        self.assertEqual(GATE.prospective_predicate(maximum.prospective_predicate(neither)), shipping)
        self.assertEqual(maximum.prospective_predicate(GATE.prospective_predicate(neither)), shipping)
        before, after = GATE.prospective_edit(without_pq)
        own = GATE.PROSPECTIVE_AFTER[len(GATE.PROSPECTIVE_BEFORE):]
        self.assertEqual(after, before + own)
        self.assertEqual(without_pq.replace(before, after, 1), shipping)
        self.assertEqual(GATE.prospective_edit(neither), (GATE.PROSPECTIVE_BEFORE, GATE.PROSPECTIVE_AFTER))

    def test_pq_reopen_refuses_malformed_or_reordered_max_anchor(self):
        shipping = (ROOT / 'internal/mobilemultihop/desktop_node_admission.go').read_text()
        closed = GATE.closed_predicate(shipping)
        other = '\tcase ' + ', '.join(json.dumps(mode) for mode in GATE.MAX_MODES) + ':\n\t\treturn true\n'
        without = GATE.closed_admission(closed, GATE.MAX_MODES)
        for bad in (closed + '\n' + other, closed + '\n// "max-tls-wg"\n',
                    closed.replace('"max-tls-awg"', '"unknown-max"'),
                    closed.replace(other, other.replace('return true', 'return false')),
                    without + '\n' + other,
                    closed.replace(other, '', 1).replace('\tdefault:', other + '\tdefault:', 1)):
            with self.subTest(source=bad[-100:]):
                with self.assertRaises(ValueError):
                    GATE.prospective_predicate(bad)

    def assert_scope(self, path):
        mapping = json.loads(path.read_text())['Replace']
        old = Path(mapping[str(self.source / 'routervpn/mobiletor/desktop_socket_windows_policy.go')]).read_text()
        new = Path(mapping[str(self.source / 'routervpn/mobiletor/desktop_socket_windows_transfer.go')]).read_text()
        self.assertIn('return desktopWindowsNodeCompositionConstruct(ctx, capture, options, nil, false)', old)
        self.assertIn('return desktopWindowsNodeCompositionConstruct(ctx, capture, options, predecessor, true)', new)
        for relative, raw in self.original.items():
            self.assertEqual((self.source / relative).read_bytes(), raw)
        return mapping

    def test_current_gate_and_prospective_gate_share_unmodified_native_scope(self):
        closed = self.assert_scope(GATE.overlay(self.source, self.directory('closed'), prospective=False))
        self.assertNotIn(str(self.source / GATE.PREDICATE), closed)
        opened = self.assert_scope(GATE.overlay(self.source, self.directory('opened'), prospective=True))
        self.assertEqual(len(opened), len(closed) + 1)
        raw = self.original[GATE.PREDICATE].decode()
        actual = Path(opened[str(self.source / GATE.PREDICATE)]).read_text()
        self.assertEqual(actual, (ROOT / 'internal/mobilemultihop/desktop_node_admission.go').read_text())
        self.assertEqual(actual.count('case "wg-pq", "awg2-pq":'), 1)
        self.assertIn('startLayer != "aes-256-gcm+xor-whitening"', actual)
        self.assertIn('default:\n\t\treturn false', actual)

    def test_unknown_or_already_open_predicate_cannot_be_reinterpreted(self):
        raw = self.original[GATE.PREDICATE].decode()
        values = (raw.replace(GATE.PROSPECTIVE_BEFORE, '\tswitch unrelated {\n'),
                  raw.replace('func DesktopNodePhysicalGraphSupported', 'func unrelated'),
                  raw.replace(GATE.PROSPECTIVE_BEFORE, GATE.PROSPECTIVE_AFTER),
                  raw + '\n// "awg2-pq"\n')
        for value in values:
            with self.subTest(value=value[-40:]):
                with self.assertRaises(ValueError):
                    GATE.prospective_predicate(value)

    def shipping_predicate(self):
        raw = GATE.prospective_predicate(self.original[GATE.PREDICATE].decode())
        self.original[GATE.PREDICATE] = raw.encode()
        (self.source / GATE.PREDICATE).write_bytes(self.original[GATE.PREDICATE])
        return raw

    def test_shipping_execution_keeps_its_predicate_and_only_closed_control_removes_pq(self):
        raw = self.shipping_predicate()
        shipping = self.assert_scope(GATE.overlay(self.source, self.directory('shipping'), prospective=False))
        self.assertNotIn(str(self.source / GATE.PREDICATE), shipping)
        closed = self.assert_scope(GATE.overlay(self.source, self.directory('shipping-closed'), prospective=False, closed=True))
        self.assertEqual(set(closed) - set(shipping), {str(self.source / GATE.PREDICATE)})
        actual = Path(closed[str(self.source / GATE.PREDICATE)]).read_text()
        self.assertEqual(actual, raw.replace(GATE.PROSPECTIVE_AFTER[len(GATE.PROSPECTIVE_BEFORE):], '', 1))
        for original in shipping:
            self.assertEqual(Path(shipping[original]).read_bytes(), Path(closed[original]).read_bytes())
        for mutation in GATE.mutations(self.source):
            mapping = self.assert_scope(GATE.overlay(self.source, self.directory('shipping-' + mutation[0]), prospective=False, mutation=mutation))
            self.assertNotIn(str(self.source / GATE.PREDICATE), mapping)

    def test_closed_control_preserves_other_family_in_either_case_order(self):
        raw = self.original[GATE.PREDICATE].decode()
        other = ('max-quic-wg', 'max-quic-awg', 'max-tls-wg', 'max-tls-awg')
        if any(json.dumps(mode) in raw for mode in other):
            raw = GATE.closed_admission(raw, other)
        own_case = GATE.PROSPECTIVE_AFTER[len(GATE.PROSPECTIVE_BEFORE):]
        other_case = '\tcase ' + ', '.join(json.dumps(mode) for mode in other) + ':\n\t\treturn true\n'
        for cases in (own_case + other_case, other_case + own_case):
            combined = raw.replace(GATE.PROSPECTIVE_BEFORE, GATE.PROSPECTIVE_BEFORE + cases, 1)
            self.assertEqual(GATE.closed_predicate(combined), combined.replace(own_case, '', 1))
        opened = GATE.prospective_predicate(raw)
        for wrong in (raw, opened + '\n// "wg-pq"\n', opened.replace('"awg2-pq"', '"other-pq"'),
                      opened.replace(own_case, own_case.replace('return true', 'return false')),
                      opened.replace('func DesktopNodePhysicalGraphSupported', 'func unrelated'),
                      raw + '\n' + own_case):
            with self.assertRaisesRegex(ValueError, 'exact shipping family|captured function'):
                GATE.closed_predicate(wrong)
        for kwargs in ({'prospective': True, 'closed': True},
                       {'prospective': False, 'closed': True, 'mutation': GATE.mutations(self.source)[0]}):
            with self.assertRaisesRegex(ValueError, 'cannot alter native execution controls'):
                GATE.overlay(self.source, self.directory('conflict-' + str(len(kwargs))), **kwargs)

    def test_all_six_real_controls_keep_exact_native_scope_and_two_mode_admission(self):
        controls = GATE.mutations(self.source)
        self.assertEqual([item[0] for item in controls], ['legacy-pq-adoption', 'late-pq-handshake',
            'ordinary-pq-udp-deny', 'valid-native-kem-peer', 'valid-native-packet-peer', 'valid-native-aes-key'])
        for item in controls:
            with self.subTest(control=item[0]):
                mapping = self.assert_scope(GATE.overlay(self.source, self.directory(item[0]), prospective=True, mutation=item))
                self.assertIn(str(self.source / GATE.PREDICATE), mapping)
                if item[5] is not None:
                    self.assertEqual(Path(mapping[str(self.source / GATE.PEER)]).read_text(), item[5][1])
                if item[0] == 'ordinary-pq-udp-deny':
                    policy = Path(mapping[str(self.source / 'routervpn/mobiletor/desktop_socket_windows_policy.go')]).read_text()
                    self.assertIn('p.pair("deny", family, 1, true, true)', policy)
                    self.assertEqual(item[3], 'independent peer marker receipt')
        wrong = (*controls[0][:4], None, ('routervpn/mobiletor/desktop_socket_windows_policy.go', 'package mobiletor\n'))
        with self.assertRaisesRegex(ValueError, 'exact compiled controls'):
            GATE.overlay(self.source, self.directory('foreign-mutation'), prospective=True, mutation=wrong)

    def test_unknown_native_constructor_and_foreign_observer_are_preserved(self):
        relative = 'routervpn/mobiletor/desktop_socket_windows_transfer.go'
        path = self.source / relative
        changed = path.read_text().replace('predecessor, nil)', 'predecessor, foreignScope)')
        path.write_text(changed)
        with self.assertRaisesRegex(ValueError, 'exact production boundary'):
            GATE.overlay(self.source, self.directory('constructor'), prospective=True)
        self.assertEqual(path.read_text(), changed)
        path.write_bytes(self.original[relative])
        foreign = self.source / 'routervpn/mobiletor/desktop_socket_windows_node_composition_overlay.go'
        foreign.write_text('package mobiletor\n// retained different owner\n')
        with self.assertRaisesRegex(ValueError, 'Unowned Windows Node observer'):
            GATE.overlay(self.source, self.directory('observer'), prospective=True)
        self.assertIn('retained different owner', foreign.read_text())

    def test_execution_rejects_foreign_host_before_source_or_native_actions(self):
        with patch.object(GATE.platform, 'system', return_value='Linux'), patch.object(GATE, 'checked_sources') as checked:
            with self.assertRaisesRegex(ValueError, 'actual elevated Windows'):
                GATE.execute(self.source, self.work / 'pq', self.work / 'cache')
            checked.assert_not_called()

    def test_execution_cannot_disable_the_real_cgo_abi_or_use_a_foreign_target(self):
        for captured in ({'GOOS': 'windows', 'CGO_ENABLED': '0'}, {'GOOS': 'linux', 'CGO_ENABLED': '1'}):
            with self.subTest(captured=captured), patch.object(GATE.platform, 'system', return_value='Windows'), \
                 patch.object(GATE.WFP.BOOT.IDENTITY.ctypes, 'windll', create=True) as native, \
                 patch.object(GATE, 'checked_sources', return_value=(self.source, {})), \
                 patch.object(GATE.NODE, 'selected_compiler', return_value=(Path('go'), captured, 'arm64')), \
                 patch.object(GATE.REFERENCE.BUILD.PQ, 'verify') as archive:
                native.shell32.IsUserAnAdmin.return_value = True
                with self.assertRaisesRegex(ValueError, 'real CGO ABI'):
                    GATE.execute(self.source, self.work / 'pq', self.work / 'cache')
                archive.assert_not_called()

    def test_closed_main_requires_explicit_prospective_before_native_actions(self):
        with patch.object(GATE.platform, 'system', return_value='Windows'), \
             patch.object(GATE.WFP.BOOT.IDENTITY.ctypes, 'windll', create=True) as native, \
             patch.object(GATE, 'checked_sources', return_value=(self.source, {})), \
             patch.object(GATE.NODE, 'selected_compiler', return_value=(Path('go'), {'GOOS': 'windows', 'CGO_ENABLED': '1'}, 'arm64')), \
             patch.object(GATE.REFERENCE.BUILD.PQ, 'verify') as archive:
            native.shell32.IsUserAnAdmin.return_value = True
            with self.assertRaisesRegex(ValueError, 'exact shipping family'):
                GATE.execute(self.source, self.work / 'pq', self.work / 'cache')
            archive.assert_not_called()

    def test_leaf_or_parent_omission_and_skip_cannot_satisfy_native_evidence(self):
        test = GATE.TRAFFIC
        complete = '--- PASS: ' + test + ' (1s)\n' + ''.join('--- PASS: ' + test + '/' + case + ' (1s)\n' for case in GATE.PQ.TRAFFIC) + 'PASS\n'
        GATE.required_output(0, complete, test, GATE.PQ.TRAFFIC)
        GATE.required_output(0, complete.replace('\n', '\r\n'), test, GATE.PQ.TRAFFIC)
        for line in complete.splitlines():
            with self.subTest(line=line):
                with self.assertRaisesRegex(ValueError, 'required real native case'):
                    GATE.required_output(0, complete.replace(line, ''), test, GATE.PQ.TRAFFIC)
        for marker in ('--- SKIP:', 'DATA RACE', 'FAIL', 'panic:', 'fatal:', 'testing: warning:', *GATE.CLEANUP_DIAGNOSTICS):
            with self.assertRaises(ValueError):
                GATE.required_output(0, complete + marker, test, GATE.PQ.TRAFFIC)
        for line in complete.splitlines():
            with self.assertRaises(ValueError):
                GATE.required_output(0, complete.replace(line, 'fixture.go:1: ' + line), test, GATE.PQ.TRAFFIC)
            if line != 'PASS':
                with self.assertRaises(ValueError):
                    GATE.required_output(0, complete + line + '\n', test, GATE.PQ.TRAFFIC)
        with self.assertRaises(ValueError):
            GATE.required_output(1, complete, test, GATE.PQ.TRAFFIC)

    def test_compiled_overlay_receipt_rejects_aliases_and_changed_or_escaped_input(self):
        selected = GATE.overlay(self.source, self.directory('overlay-source'), prospective=True)
        captured = GATE.overlay_source_hashes(self.source, selected)
        mapping = json.loads(selected.read_text())['Replace']
        path = Path(mapping[str(self.source / GATE.PREDICATE)])
        raw = path.read_bytes()
        path.write_bytes(raw + b'\n// altered compiled predicate\n')
        self.assertNotEqual(GATE.overlay_source_hashes(self.source, selected), captured)
        path.unlink()
        path.symlink_to(self.source / GATE.PREDICATE)
        with self.assertRaises(ValueError):
            GATE.overlay_source_hashes(self.source, selected)
        path.unlink()
        path.write_bytes(raw)
        mapping[str(self.work / 'foreign.go')] = str(path)
        selected.write_text(json.dumps({'Replace': mapping}))
        with self.assertRaises(ValueError):
            GATE.overlay_source_hashes(self.source, selected)

    def test_native_peer_cannot_drop_its_windows_cgo_or_test_tag(self):
        root = self.directory('tag-root')
        peer = root / GATE.PEER_TEMPLATE
        peer.parent.mkdir(parents=True)
        peer.write_bytes(b'package routervpnpq\n')
        with patch.object(GATE, 'ROOT', root), patch.object(GATE.PQ, 'checked_sources', return_value=(self.source, {})), \
             patch.object(GATE.WFP, 'checked_sources', return_value=(self.source, {})):
            with self.assertRaisesRegex(ValueError, 'native/CGO/test-only scope'):
                GATE.checked_sources(self.source)

    @contextmanager
    def shared_private_reference_source(self, name):
        # Only prepared-core identity is modeled. Capture all actual shared PQ
        # dependency bytes, including the script invoked before key generation.
        shared = GATE.PQ
        with patch.object(shared.NODE, 'checked_sources', side_effect=lambda _source: (self.source, {})), \
             patch.object(shared.REFERENCE, 'verify_sources', return_value=self.source):
            _, original = shared.checked_sources(self.source)
            root = self.directory(name)
            for key in original:
                relative = key.removeprefix('pq-source/')
                self.assertNotEqual(relative, key)
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            with patch.object(shared, 'ROOT', root):
                yield root, original

    def test_shared_source_capture_requires_actual_private_acl_dependencies(self):
        with self.shared_private_reference_source('private-reference-source') as (root, before):
            self.assertEqual(GATE.PQ.checked_sources(self.source)[1], before)
            for relative in ('client/Protect-RouterVPN-Windows-PrivateRoot.ps1',
                             'client/test-windows-private-acl.ps1',
                             'deploy/test_pq_reference_preparation.py'):
                path = root / relative
                original = path.read_bytes()
                key = 'pq-source/' + relative
                self.assertEqual(before[key], GATE.PQ.regular_digest(ROOT / relative))
                path.write_bytes(original + b'\n# changed captured dependency\n')
                self.assertNotEqual(GATE.PQ.checked_sources(self.source)[1][key], before[key])
                path.unlink()
                with self.assertRaisesRegex(ValueError, 'captured regular file'):
                    GATE.PQ.checked_sources(self.source)
                path.symlink_to(ROOT / relative)
                with self.assertRaisesRegex(ValueError, 'captured regular file'):
                    GATE.PQ.checked_sources(self.source)
                path.unlink()
                path.write_bytes(original)

    @staticmethod
    def negative_output(mutation):
        _, parent, selector, witness, _, _ = mutation
        leaf = '/'.join(part[1:-1] for part in selector.split('/'))
        failures = '--- FAIL: ' + parent + ' (1.00s)\n'
        if leaf != parent:
            failures += '    --- FAIL: ' + leaf + ' (1.00s)\n'
        return '    node_pq_peer_windows_test.go:100: ' + witness + '\n' + failures + 'FAIL\n'

    def test_control_requires_exact_leaf_status_and_no_other_failure(self):
        for mutation in GATE.mutations(self.source):
            output = self.negative_output(mutation)
            with self.subTest(control=mutation[0]):
                GATE.rejected_control(1, output, mutation)
                for status in (0, 2, -1, 124, 255):
                    with self.assertRaisesRegex(ValueError, 'missed its actual defect'):
                        GATE.rejected_control(status, output, mutation)
                faults = [output.replace(mutation[3], 'different failure'),
                          output.replace('FAIL\n', '', 1),
                          output + '--- FAIL: TestUnrelated (0.01s)\n',
                          output + '--- FAIL: malformed duration\n',
                          output + '--- FAIL: ' + mutation[1] + ' (0.01s)\n']
                if mutation[1] != GATE.FOREIGN:
                    leaf = '/'.join(part[1:-1] for part in mutation[2].split('/'))
                    faults += [output.replace('    --- FAIL: ' + leaf + ' (1.00s)\n', ''),
                               output.replace(leaf + ' (1.00s)', leaf + '-other (1.00s)')]
                else:
                    faults.append(output + '    --- FAIL: ' + GATE.FOREIGN + '/unexpected (0.01s)\n')
                for faulty in faults:
                    with self.assertRaisesRegex(ValueError, 'missed its actual defect'):
                        GATE.rejected_control(1, faulty, mutation)

    def test_control_rejects_panics_skips_and_every_known_cleanup_failure(self):
        mutation = GATE.mutations(self.source)[1]
        output = self.negative_output(mutation)
        for marker in ('--- SKIP: ignored (0s)', 'WARNING: DATA RACE', 'panic: unexpected nil',
                       'fatal error: concurrent map access', 'FATAL: lost worker',
                       'testing: warning: no tests to run', *GATE.CLEANUP_DIAGNOSTICS):
            with self.subTest(marker=marker), self.assertRaisesRegex(ValueError, 'missed its actual defect'):
                GATE.rejected_control(1, output + marker + '\n', mutation)

    @contextmanager
    def receipt_harness(self, receipt, cleanup='joined'):
        # Native execution is deliberately modeled here. Actual file lifetimes
        # and the real execute/standalone receipt paths are exercised on this OS.
        real_temporary = tempfile.TemporaryDirectory
        state = {'paths': [], 'removed_controls': [], 'native_calls': [], 'native_timeouts': [], 'compiled_overlays': {}, 'closed_binary': None}
        state.update(dependency_events=[], process_commands=[], key_calls=0)
        controls = {item[0]: item for item in GATE.mutations(self.source)}
        timers = GATE.REFERENCE.BUILD.POLICY.AMNEZIA.TIMERS

        def timer_command(args, **kwargs):
            # Keep the real module-plan and selected-copy verifier. Only the Go
            # subprocess metadata and complete archive filesystem are modeled.
            self.assertEqual(kwargs, {'cwd': self.source, 'env': state['dependency_env'], 'text': True})
            self.assertIs(kwargs['env'], state['dependency_env'])
            self.assertEqual(kwargs['env'], state['dependency_snapshot'])
            if args == [Path('go'), 'mod', 'edit', '-json']:
                state['dependency_events'].append('plan')
                replacements = [{'Old': {'Path': timers.MODULE, 'Version': timers.VERSION},
                                 'New': {'Path': './' + timers.COPY}}]
                if state.get('dependency_fault') == 'missing':
                    replacements = []
                elif state.get('dependency_fault') == 'foreign':
                    replacements[0]['New']['Path'] = './foreign-module'
                return json.dumps({'Require': [{'Path': timers.MODULE, 'Version': timers.VERSION}], 'Replace': replacements})
            if args == [Path('go'), 'list', '-m', '-mod=readonly', '-json', timers.MODULE]:
                state['dependency_events'].append('selection')
                selected = self.source / (timers.COPY if state.get('dependency_fault') != 'selected' else 'foreign-module')
                return json.dumps({'Path': timers.MODULE, 'Version': timers.VERSION, 'Dir': str(selected),
                                  'Replace': {'Path': './' + timers.COPY, 'Dir': str(selected)}})
            self.fail('Unexpected timer verifier command: ' + repr(args))

        def timer_tree(selected):
            self.assertEqual(selected, self.source / timers.COPY)
            self.assertEqual(state['dependency_events'], ['checksum', 'plan', 'selection'])
            state['dependency_events'].append('tree')
            if state.get('dependency_fault') == 'tree':
                raise ValueError('modeled pinned AWG tree rejection')

        @contextmanager
        def workspace(*, prefix):
            owned = real_temporary(prefix=prefix, dir=self.work)
            self.addCleanup(owned.cleanup)
            path = Path(owned.name)
            state['paths'].append(path)
            try:
                yield str(path)
            finally:
                self.assertFalse(receipt.exists(), 'success receipt preceded workspace retirement')
                if cleanup == 'error':
                    raise OSError('injected owned workspace cleanup failure')
                if cleanup == 'joined':
                    owned.cleanup()

        def keys(_target, _cache, path):
            self.assertEqual(state['dependency_events'], ['checksum', 'plan', 'selection', 'tree'])
            state['key_calls'] += 1
            path.mkdir(parents=True)
            (path / 'private-test-marker').write_bytes(b'owned test-only key marker')

        def relay(_compiler, path, _env, _race):
            binary = path / 'relay.exe'
            binary.write_bytes(b'owned test-only reference')
            return binary, GATE.PQ.regular_digest(binary)

        def command(args, **_kwargs):
            self.assertFalse(receipt.exists())
            args = [str(value) for value in args]
            state['process_commands'].append(args)
            if args[1:3] == ['mod', 'verify']:
                state['dependency_events'].append('checksum')
                state['dependency_env'] = _kwargs['env']
                state['dependency_snapshot'] = dict(_kwargs['env'])
                if state.get('dependency_fault') == 'checksum':
                    return 1, 'modeled original module checksum rejection'
                return 0, 'all modules verified\n'
            if args[1:3] == ['test', '-c']:
                binary = Path(args[args.index('-o') + 1])
                closed = state['closed_binary']
                if closed is not None:
                    self.assertFalse(closed.exists(), 'closed-admission executable survived into positive compilation')
                selected = Path(next(value.removeprefix('-overlay=') for value in args if value.startswith('-overlay=')))
                mapping = json.loads(selected.read_text())['Replace']
                state['compiled_overlays'][binary.parent.name] = {Path(original).relative_to(self.source).as_posix(): Path(replacement).read_text()
                                                                for original, replacement in mapping.items()}
                binary.write_bytes(('test-only compiled ' + binary.parent.name).encode())
                if binary.parent.name.endswith('closed-capability'):
                    state['closed_binary'] = binary
                if 'on_compile' in state:
                    state['on_compile'](binary, selected)
                return 0, ''
            binary = Path(args[0])
            for previous in state['removed_controls']:
                self.assertFalse(previous.exists(), 'joined mutant accumulated before the next native case')
            state['native_calls'].append(args)
            state['native_timeouts'].append(_kwargs.get('timeout'))
            if 'on_run' in state:
                state['on_run'](binary)
            if binary.parent.name in controls:
                state['removed_controls'].append(binary)
                return 1, self.negative_output(controls[binary.parent.name])
            parent = next(value for value in args if value.startswith('-test.run=')).split('=^', 1)[1][:-1]
            cases = {GATE.CLOSED: GATE.PQ.MODES, GATE.OPEN: (), GATE.TRAFFIC: GATE.PQ.TRAFFIC,
                     GATE.CREDENTIALS: GATE.PQ.CREDENTIALS, GATE.SUCCESSION: GATE.PQ.LAYERS, GATE.FOREIGN: ()}[parent]
            return 0, '--- PASS: ' + parent + ' (1s)\n' + ''.join(
                '    --- PASS: ' + parent + '/' + case + ' (1s)\n' for case in cases) + 'PASS\n'

        with ExitStack() as stack:
            stack.enter_context(redirect_stdout(io.StringIO()))
            stack.enter_context(patch.object(GATE.platform, 'system', return_value='Windows'))
            native = stack.enter_context(patch.object(GATE.WFP.BOOT.IDENTITY.ctypes, 'windll', create=True))
            native.shell32.IsUserAnAdmin.return_value = True
            stack.enter_context(patch.object(GATE, 'checked_sources', return_value=(self.source, {'test-model': 'source'})))
            stack.enter_context(patch.object(GATE.NODE, 'selected_compiler', return_value=(
                Path('go'), dict(os.environ, GOOS='windows', CGO_ENABLED='1'), 'arm64')))
            stack.enter_context(patch.object(GATE.REFERENCE.BUILD.PQ, 'verify', return_value={'native_static_libs': []}))
            stack.enter_context(patch.object(timers.subprocess, 'check_output', side_effect=timer_command))
            stack.enter_context(patch.object(timers, 'verify_tree', side_effect=timer_tree))
            state['timer_verifier'] = stack.enter_context(patch.object(timers, 'verify', wraps=timers.verify))
            stack.enter_context(patch.object(GATE.REFERENCE, 'generate_keys', side_effect=keys))
            stack.enter_context(patch.object(GATE.REFERENCE, 'key_files', return_value={'test-key': 'unchanged'}))
            stack.enter_context(patch.object(GATE.REFERENCE, 'test_sources', side_effect=lambda _source: nullcontext()))
            stack.enter_context(patch.object(GATE.NODE, 'build_layer_reference', side_effect=relay))
            stack.enter_context(patch.object(GATE.NODE, 'run', side_effect=command))
            stack.enter_context(patch.object(GATE.tempfile, 'TemporaryDirectory', side_effect=workspace))
            yield state

    def test_execute_publishes_after_actual_workspace_removal_and_bounds_mutants(self):
        receipt = self.work / 'native-receipt.json'
        with self.receipt_harness(receipt) as state:
            result = GATE.execute(self.source, self.work / 'pq', self.work / 'cache',
                                  prospective=True, receipt_path=receipt)
        self.assertEqual(json.loads(receipt.read_text()), json.loads(json.dumps(result)))
        edit = result['prospective_predicate']
        self.assertEqual(set(edit), {'before', 'after'})
        shipping = (ROOT / 'internal/mobilemultihop/desktop_node_admission.go').read_text()
        self.assertEqual(self.original[GATE.PREDICATE].decode().replace(edit['before'], edit['after'], 1), shipping)
        self.assertEqual(state['compiled_overlays']['native-composition'][GATE.PREDICATE], shipping)
        state['timer_verifier'].assert_called_once_with(self.source, Path('go'), env=state['dependency_env'])
        self.assertEqual(state['dependency_events'], ['checksum', 'plan', 'selection', 'tree'])
        self.assertEqual(len(result['compiled_negative_controls']), 6)
        self.assertEqual(len(state['removed_controls']), 6)
        self.assertTrue(all(not path.exists() for path in state['paths']))
        for parent, budget in ((GATE.TRAFFIC, 480), (GATE.CREDENTIALS, 900), (GATE.SUCCESSION, 720), (GATE.FOREIGN, 160)):
            calls = [args for args in state['native_calls']
                     if Path(args[0]).parent.name == 'native-composition' and '-test.run=^' + parent + '$' in args]
            self.assertEqual(len(calls), 1)
            self.assertIn('-test.timeout=' + str(budget) + 's', calls[0])
        for args, outer_timeout in zip(state['native_calls'], state['native_timeouts'], strict=True):
            inner_timeout = int(next(value for value in args if value.startswith('-test.timeout=')).split('=', 1)[1][:-1])
            self.assertEqual(outer_timeout, inner_timeout + 15)
            if Path(args[0]).parent.name not in ('current-closed-capability', 'shipping-closed-capability', 'native-composition'):
                self.assertEqual(inner_timeout, 160 if Path(args[0]).parent.name == 'legacy-pq-adoption' else 90)

    def test_unverified_timer_dependency_prevents_keys_native_work_and_receipt(self):
        for fault, witness in (('checksum', 'module verification failed'),
                               ('missing', 'unrelated or missing AWG timer replacement'),
                               ('foreign', 'unrelated or missing AWG timer replacement'),
                               ('selected', 'exact selected private AWG timer copy'),
                               ('tree', 'pinned AWG tree rejection')):
            receipt = self.work / ('timer-' + fault + '.json')
            with self.subTest(fault=fault), self.receipt_harness(receipt) as state:
                state['dependency_fault'] = fault
                with self.assertRaisesRegex(ValueError, witness):
                    GATE.execute(self.source, self.work / 'pq', self.work / 'cache',
                                 prospective=True, receipt_path=receipt)
            self.assertFalse(receipt.exists())
            self.assertEqual(state['key_calls'], 0)
            self.assertEqual(state['paths'], [])
            self.assertEqual(state['native_calls'], [])
            self.assertEqual(state['compiled_overlays'], {})
            self.assertEqual(state['process_commands'], [['go', 'mod', 'verify']])
            if fault == 'checksum':
                state['timer_verifier'].assert_not_called()
            else:
                state['timer_verifier'].assert_called_once_with(self.source, Path('go'), env=state['dependency_env'])

    def test_shipping_execution_requires_separate_closed_proof_and_retains_all_six_controls(self):
        raw = self.shipping_predicate()
        receipt = self.work / 'shipping-native.json'
        with self.receipt_harness(receipt) as state:
            result = GATE.execute(self.source, self.work / 'pq', self.work / 'cache', receipt_path=receipt)
        self.assertEqual(result['public_admission'], 'shipping-predicate')
        self.assertFalse(result['prospective'])
        self.assertEqual(result['closed_admission_source'], 'exact-family-removed')
        self.assertEqual(len(result['compiled_negative_controls']), 6)
        self.assertEqual(result['closed_admission_control']['parent'], GATE.CLOSED)
        self.assertIn(GATE.PREDICATE, result['closed_admission_control']['source_overlay_sha256'])
        self.assertFalse(state['closed_binary'].exists())
        for name, mapping in state['compiled_overlays'].items():
            if name == 'shipping-closed-capability':
                self.assertEqual(mapping[GATE.PREDICATE], GATE.closed_predicate(raw))
            else:
                self.assertNotIn(GATE.PREDICATE, mapping)
        self.assertTrue(all(item['source_overlay_sha256'] for item in result['compiled_negative_controls']))
        self.assertEqual((self.source / GATE.PREDICATE).read_text(), raw)

    def test_compiled_or_running_overlay_change_cannot_publish_any_receipt(self):
        for phase in ('compile', 'closed', 'positive', 'negative'):
            receipt = self.work / (phase + '-changed-overlay.json')
            def changed(binary, selected=None):
                applies = phase == 'compile' or phase == 'closed' and binary.parent.name == 'current-closed-capability' or \
                    phase == 'positive' and binary.parent.name == 'native-composition' or phase == 'negative' and binary.parent.name == 'legacy-pq-adoption'
                if not applies:
                    return
                mapping = json.loads((selected or binary.parent / 'overlay.json').read_text())['Replace']
                path = Path(next(iter(mapping.values())))
                path.write_text(path.read_text() + '\n// changed after exact capture\n')
            with self.subTest(phase=phase), self.receipt_harness(receipt) as state:
                state['on_compile' if phase == 'compile' else 'on_run'] = changed
                with self.assertRaisesRegex(ValueError, 'overlay changed|executable or overlay changed'):
                    GATE.execute(self.source, self.work / 'pq', self.work / 'cache', prospective=True, receipt_path=receipt)
            self.assertFalse(receipt.exists())

    def test_execute_cleanup_error_or_unremoved_workspace_never_publishes(self):
        for cleanup, failure in (('error', OSError), ('retained', ValueError)):
            receipt = self.work / (cleanup + '-native-receipt.json')
            with self.subTest(cleanup=cleanup), self.receipt_harness(receipt, cleanup):
                with self.assertRaisesRegex(failure, 'workspace cleanup'):
                    GATE.execute(self.source, self.work / 'pq', self.work / 'cache',
                                 prospective=True, receipt_path=receipt)
            self.assertFalse(receipt.exists())

    def test_private_acl_change_or_loss_cannot_publish_native_evidence(self):
        real_capture = GATE.checked_sources
        for change in ('changed', 'missing', 'aliased'):
            receipt = self.work / (change + '-private-acl-receipt.json')
            with self.subTest(change=change), \
                 self.shared_private_reference_source(change + '-private-acl-source') as (root, _before), \
                 self.receipt_harness(receipt) as state, \
                 patch.object(GATE.WFP, 'checked_sources', side_effect=lambda _source: (self.source, {})):
                captures = 0
                def capture(source):
                    nonlocal captures
                    captures += 1
                    if captures == 2:
                        helper = root / 'client/Protect-RouterVPN-Windows-PrivateRoot.ps1'
                        if change == 'changed':
                            helper.write_bytes(helper.read_bytes() + b'\n# helper changed during native execution\n')
                        else:
                            helper.unlink()
                            if change == 'aliased':
                                helper.symlink_to(ROOT / 'client/Protect-RouterVPN-Windows-PrivateRoot.ps1')
                    return real_capture(source)
                with patch.object(GATE, 'checked_sources', side_effect=capture), \
                     self.assertRaisesRegex(ValueError, 'prepared source changed|captured regular file'):
                    GATE.execute(self.source, self.work / 'pq', self.work / 'cache',
                                 prospective=True, receipt_path=receipt)
                self.assertEqual(captures, 2)
                self.assertTrue(state['native_calls'], 'receipt boundary was not reached after modeled execution')
                self.assertTrue(all(not path.exists() for path in state['paths']))
            self.assertFalse(receipt.exists())

    def test_standalone_defers_receipt_until_its_outer_workspace_joins(self):
        for cleanup, failure in (('joined', None), ('error', OSError), ('retained', ValueError)):
            receipt = self.work / (cleanup + '-standalone-receipt.json')
            previous = dict(os.environ)
            with self.subTest(cleanup=cleanup), self.receipt_harness(receipt, cleanup) as state, ExitStack() as stack:
                native = GATE.REFERENCE.BUILD
                for owner, method in ((native, 'checkout'), (native, 'pristine'), (native, 'run'),
                                      (native.PQ, 'build'), (native.POLICY, 'prepare_native'),
                                      (native.PERFORMANCE, 'prepare'), (native.OPENVPN, 'prepare'),
                                      (native.EXTERNAL, 'prepare'), (native.BUFFERS, 'prepare'),
                                      (native.POLICY.AMNEZIA, 'verify')):
                    stack.enter_context(patch.object(owner, method))
                result = {'test-only': 'modeled execution; real outer file lifecycle'}
                inner = stack.enter_context(patch.object(GATE, 'execute', return_value=result))
                if failure is None:
                    self.assertEqual(GATE.standalone(prospective=True, receipt_path=receipt), result)
                else:
                    with self.assertRaisesRegex(failure, 'workspace cleanup'):
                        GATE.standalone(prospective=True, receipt_path=receipt)
                self.assertNotIn('receipt_path', inner.call_args.kwargs)
            self.assertEqual(dict(os.environ), previous)
            if failure is None:
                self.assertEqual(json.loads(receipt.read_text()), result)
                self.assertTrue(all(not path.exists() for path in state['paths']))
            else:
                self.assertFalse(receipt.exists())


if __name__ == '__main__':
    unittest.main()
