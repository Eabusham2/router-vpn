#!/usr/bin/env python3
"""Exercise MAX gate outcomes and ownership without launching network peers.

The subprocess model below tests the runner's evidence/cleanup boundaries only.
Actual Rust, encrypted peers and compiled defects run in test_desktop_node_max.
"""
from contextlib import ExitStack, contextmanager, redirect_stdout
from pathlib import Path
import ast
import importlib.util
import io
import json
import re
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('complete_max_runner_checks', ROOT / 'deploy/test_desktop_node_max.py')
GATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)


def success(parent, cases=()):
    return '\n'.join('--- PASS: ' + name + ' (0.01s)' for name in (parent, *(parent + '/' + case for case in cases))) + '\nPASS\n'


def failure(parent, case, witness):
    return witness + '\n--- FAIL: ' + parent + ' (0.01s)\n    --- FAIL: ' + parent + '/' + case + ' (0.01s)\nFAIL\n'


class MAXOutcomeChecks(unittest.TestCase):
    def test_exact_four_family_matrix_keeps_every_layer_and_paired_key_fault(self):
        self.assertEqual(set(GATE.FAMILIES['QUIC']), {'max-quic-wg', 'max-quic-awg'})
        self.assertEqual(set(GATE.FAMILIES['TLS']), {'max-tls-wg', 'max-tls-awg'})
        self.assertEqual(sum(map(len, GATE.TRAFFIC.values())), 12)
        self.assertEqual(sum(map(len, GATE.CREDENTIALS.values())), 48)
        for family, modes in GATE.FAMILIES.items():
            self.assertEqual(len(set(GATE.CREDENTIALS[family])), 24)
            for mode in modes:
                for layer in ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening'):
                    self.assertIn(mode + '/' + layer, GATE.TRAFFIC[family])
                    for fault in ('kem-peer', 'packet-peer', 'middle-key'):
                        self.assertIn(mode + '/' + layer + '/' + fault, GATE.CREDENTIALS[family])
                    self.assertNotIn(mode + '/' + layer + '/aes-key', GATE.CREDENTIALS[family])

    def test_each_missing_real_case_and_embedded_forged_pass_is_rejected(self):
        for family in GATE.FAMILIES:
            for credentials, cases in ((False, GATE.TRAFFIC[family]), (True, GATE.CREDENTIALS[family])):
                parent = 'TestRouterVPNDesktopNodeCompleteMAX' + family + ('Credentials' if credentials else '')
                complete = success(parent, cases)
                GATE.required_output(0, complete, parent, cases)
                for case in cases:
                    with self.subTest(parent=parent, case=case):
                        marker = '--- PASS: ' + parent + '/' + case + ' (0.01s)'
                        missing = complete.replace(marker, 'fixture.go:99: log text ' + marker)
                        with self.assertRaisesRegex(ValueError, 'omitted or duplicated'):
                            GATE.required_output(0, missing, parent, cases)
                        with self.assertRaisesRegex(ValueError, 'omitted or duplicated'):
                            GATE.required_output(0, complete + marker + '\n', parent, cases)

    def test_zero_status_pass_markers_do_not_hide_baseline_failure(self):
        parent, cases = 'TestComplete', ('max-tls-wg/off',)
        complete = success(parent, cases)
        for status, suffix in ((1, ''), (0, '--- SKIP: other (0.00s)'), (0, 'DATA RACE'),
                               (0, 'panic: test timed out'), (0, 'fatal error: deadlock'),
                               (0, 'warning: no tests to run'), (0, '--- FAIL: unrelated (0.01s)')):
            with self.subTest(status=status, suffix=suffix):
                with self.assertRaises(ValueError):
                    GATE.required_output(status, complete + suffix, parent, cases)

    def test_control_requires_exact_executable_assertion_and_never_a_crash(self):
        parent, case, witness = 'TestComplete', 'max-quic-wg/off', 'actual captured defect'
        output = failure(parent, case, witness)
        GATE.rejected_output(1, output, parent, case, witness)
        variants = ((0, output), (2, output), (-9, output), (1, output.replace(witness, 'other failure')),
                    (1, output.replace(parent + '/' + case, parent + '/other/off')),
                    (1, output.replace('--- FAIL: ' + parent + ' (', '--- PASS: ' + parent + ' (')),
                    (1, output + '--- FAIL: unrelated (0.01s)'),
                    (1, output + '--- SKIP: later (0.00s)'), (1, output + 'DATA RACE'),
                    (1, output + 'panic: another fault'), (1, output + 'fatal error: deadlock'),
                    *((1, output + message) for message in GATE.JOIN_FAILURES))
        for status, altered in variants:
            with self.subTest(status=status, altered=altered):
                with self.assertRaisesRegex(ValueError, 'exact executable rejection'):
                    GATE.rejected_output(status, altered, parent, case, witness)

    def test_selector_matches_literal_whitening_plus_and_exact_mode(self):
        parent, case = 'TestComplete', 'max-tls-wg/aes-256-gcm+xor-whitening/middle-key'
        patterns = GATE.selector(parent, case).split('/')
        for pattern, value in zip(patterns, (parent, *case.split('/')), strict=True):
            self.assertIsNotNone(re.fullmatch(pattern, value))
        self.assertIsNone(re.fullmatch(patterns[2], 'aes-256-gcmxor-whitening'))
        self.assertIsNone(re.fullmatch(patterns[1], 'max-tls-wg-other'))

    def test_tuple_control_observes_the_original_live_denial_without_replacing_it(self):
        original = (ROOT / 'mobile/desktop/node_physical.go.tmpl').read_text()
        relative = 'routervpn/desktoppt/node_physical.go'
        boundary = '\tif closed || !allowed || owner == nil {\n'
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            path = source / relative
            path.parent.mkdir(parents=True)
            path.write_text(original)
            for protocol in ('tcp', 'udp'):
                label = 'different-outer-' + protocol + '-tuple'
                replacements = GATE.control_sources(source, label, 'outer.go', 'actual changed outer tuple')
                self.assertEqual(replacements['outer.go'], 'actual changed outer tuple')
                observed = replacements[relative]
                self.assertEqual(observed.count(boundary), 1)
                prefix, suffix = observed.split(boundary)
                original_prefix, original_suffix = original.split(boundary)
                self.assertEqual(suffix, original_suffix)
                self.assertTrue(prefix.startswith(original_prefix))
                observation = prefix[len(original_prefix):]
                self.assertEqual(observation, '\tif !closed && !allowed && owner != nil && owner.SocketCurrentContext(ctx) == nil && ctx.Err() == nil && base == "' +
                                 protocol + '" {\n\t\tprintln("' + GATE.tuple_witness(protocol) + '")\n\t}\n')
            path.write_text(original.replace(boundary, '\tif closed {\n'))
            with self.assertRaisesRegex(ValueError, 'exact captured tuple rejection boundary'):
                GATE.control_sources(source, 'different-outer-tcp-tuple', 'outer.go', 'changed')

    def test_tuple_control_rejects_generic_transport_errors_and_other_protocol_witnesses(self):
        parent, case = 'TestRouterVPNDesktopNodeCompleteMAXTLS', 'max-tls-wg/off'
        for error in ('protected PQ peer transport could not open', 'PQ transport write failed',
                      'Router node desktop lower socket lost its captured native capability',
                      GATE.tuple_witness('udp')):
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, 'exact executable rejection'):
                GATE.rejected_output(1, failure(parent, case, error), parent, case, GATE.tuple_witness('tcp'))

    def test_native_registration_preserves_platform_scope_and_aggregate_bounds(self):
        for name in GATE.TEMPLATES:
            self.assertEqual(GATE.NODE.PREP.PEER_TEMPLATES[name], 'protocol/routervpnpq/' + name.removesuffix('.tmpl'))
            self.assertTrue((ROOT / 'mobile/desktop' / name).read_bytes().startswith(GATE.TAG))
        builder = (ROOT / 'deploy/build-native-runtime.py').read_text()
        calls = [node for node in ast.walk(ast.parse(builder)) if isinstance(node, ast.Call) and
                 isinstance(node.func, ast.Name) and node.func.id == 'run']
        actual = [node for node in calls if "ROOT/'deploy/test_desktop_node_max.py'" in ast.get_source_segment(builder, node)]
        self.assertEqual(len(actual), 1)
        self.assertEqual({item.arg: ast.literal_eval(item.value) for item in actual[0].keywords if item.arg == 'timeout'}, {'timeout': 5400})
        workflow = (ROOT / '.github/workflows/desktop-native-runtime.yml').read_text()
        self.assertEqual(workflow.count("timeout-minutes: ${{ startsWith(matrix.target, 'darwin/') && 60 || startsWith(matrix.target, 'linux/') && 200 || 150 }}"), 1)
        linux = (ROOT / '.github/workflows/linux-native-app.yml').read_text()
        for path in ('deploy/test_desktop_node_max.py', 'deploy/test_desktop_node_max_runner.py', 'mobile/desktop/node_max*.go.tmpl'):
            self.assertEqual(linux.count("      - '" + path + "'"), 2)


class ModeledRun:
    """Deterministic runner process model; never a native/crypto success claim."""
    def __init__(self, root, failure_kind=None):
        root = root.resolve()
        self.root, self.failure_kind = root, failure_kind
        self.core, self.library, self.cache = (root / name for name in ('core', 'library', 'cache'))
        for directory in (self.core, self.library, self.cache):
            directory.mkdir()
        self.compiler = root / 'go'
        self.compiler.write_bytes(b'runner-test compiler identity')
        self.receipt = root / 'receipt.json'
        self.private = []
        self.events = []
        self.source_reads = 0
        self.native_reads = 0
        self.control = ('intentional-defect', 'protocol/routervpnpq/endpoint.go',
                        'TestRouterVPNDesktopNodeCompleteMAXQUIC', 'max-quic-wg/off',
                        'modeled exact assertion', 'package routervpnpq\n')
        self.commands = []
        self.dependency_events = []
        self.dependency_env = None
        self.dependency_snapshot = None

    def timer_command(self, command, **kwargs):
        """Model only Go metadata; exercise the shipping timer verifier itself."""
        timers = GATE.REFERENCE.BUILD.POLICY.AMNEZIA.TIMERS
        if kwargs != {'cwd': self.core, 'env': self.dependency_env, 'text': True} or kwargs['env'] is not self.dependency_env:
            raise AssertionError('Timer verification lost the captured source or compiler environment')
        if dict(kwargs['env']) != self.dependency_snapshot:
            raise AssertionError('Timer verification changed the captured compiler environment')
        if command == [self.compiler, 'mod', 'edit', '-json']:
            self.dependency_events.append('plan')
            replacements = [{'Old': {'Path': timers.MODULE, 'Version': timers.VERSION},
                             'New': {'Path': './' + timers.COPY}}]
            if self.failure_kind == 'timer-missing':
                replacements = []
            elif self.failure_kind == 'timer-foreign':
                replacements[0]['New']['Path'] = './foreign-module'
            return json.dumps({'Require': [{'Path': timers.MODULE, 'Version': timers.VERSION}], 'Replace': replacements})
        if command == [self.compiler, 'list', '-m', '-mod=readonly', '-json', timers.MODULE]:
            self.dependency_events.append('selection')
            selected = self.core / (timers.COPY if self.failure_kind != 'timer-selected' else 'foreign-module')
            return json.dumps({'Path': timers.MODULE, 'Version': timers.VERSION, 'Dir': str(selected),
                              'Replace': {'Path': './' + timers.COPY, 'Dir': str(selected)}})
        raise AssertionError(command)

    def timer_tree(self, selected):
        # Full pinned archive/h1 and exact patch validation has its own actual
        # archive suite. This runner model stops only at that filesystem boundary.
        timers = GATE.REFERENCE.BUILD.POLICY.AMNEZIA.TIMERS
        if selected != self.core / timers.COPY or self.dependency_events != ['checksum', 'plan', 'selection']:
            raise AssertionError('Timer verification did not select the exact captured private module')
        self.dependency_events.append('tree')
        if self.failure_kind == 'timer-tree':
            raise ValueError('modeled pinned AWG tree rejection')

    def sources(self, source):
        self.source_reads += 1
        return self.core, {'captured': 'changed' if self.failure_kind == 'changed-source' and self.source_reads > 1 else 'original'}

    def native(self, library, target):
        self.native_reads += 1
        return {'native_static_libs': [], 'identity': 'changed' if self.failure_kind == 'changed-archive' and self.native_reads > 1 else 'original'}

    def keys(self, target, cache, keys):
        if self.dependency_events != ['checksum', 'plan', 'selection', 'tree']:
            raise AssertionError('Private keys preceded complete timer dependency verification')
        self.assert_new = not keys.parent.exists()
        keys.parent.mkdir(mode=0o700)
        keys.mkdir(mode=0o700)
        for index, name in enumerate(('client', 'server', 'other'), 1):
            for kind in ('secret', 'public'):
                path = keys / (name + '.' + kind)
                path.write_bytes(bytes([index]) * 64)
                path.chmod(0o600)
        self.private.append(keys.parent)
        executable = cache / GATE.REFERENCE.BUILD.PQ.TARGETS[target] / 'release/examples/native_keys'
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b'runner-test key generator')

    @contextmanager
    def test_sources(self, source):
        self.events.append('source-enter')
        try:
            yield
        finally:
            self.events.append('source-joined')

    def relay(self, compiler, workspace, captured, race):
        path = workspace / 'relay'
        path.write_bytes(b'runner-test relay')
        return path, GATE.regular_digest(path)

    def xray(self, compiler, source, workspace, captured, race):
        path = workspace / 'xray'
        path.write_bytes(b'runner-test xray')
        return path, GATE.regular_digest(path), self.core, {'captured': 'xray'}

    def run(self, command, **kwargs):
        command = [str(value) for value in command]
        self.commands.append(command)
        if command[0] == str(self.compiler):
            if command[1:3] == ['mod', 'verify']:
                self.dependency_events.append('checksum')
                self.dependency_env = kwargs['env']
                self.dependency_snapshot = dict(kwargs['env'])
                if self.failure_kind == 'module-checksum':
                    return 1, 'modeled original module checksum rejection'
                return 0, 'all modules verified'
            if command[1:3] == ['test', '-c']:
                if self.failure_kind == 'control-compile' and any(value.startswith('-overlay=') for value in command):
                    return 1, 'intentional compiler rejection'
                path = Path(command[command.index('-o') + 1])
                path.write_bytes(('runner-test executable ' + path.name).encode())
                return 0, ''
            raise AssertionError(command)
        if Path(command[0]).name.startswith('intentional-defect.test'):
            output = failure(self.control[2], self.control[3], self.control[4])
            return (0 if self.failure_kind == 'control-succeeded' else 1), output
        selected = next(value.removeprefix('-test.run=') for value in command if value.startswith('-test.run='))
        if selected.startswith('^Test(RealPinnedFactory'):
            if not re.search(selected, GATE.STARTUP_RECORDS) or not re.search(selected, GATE.PORT_PAIR):
                raise AssertionError('MAX execution omitted its startup parser or retained port-pair regression')
            output = ''.join(success(parent, ('v2', 'v3') if parent == 'TestRealPinnedFactoryExchangeAndRekey' else ())
                             for parent in GATE.PQ.NATIVE_CASES)
            if self.failure_kind == 'failed-startup-records':
                return 1, output + '--- FAIL: ' + GATE.STARTUP_RECORDS + ' (0.01s)\n'
            if self.failure_kind != 'missing-startup-records':
                output += success(GATE.STARTUP_RECORDS)
            if self.failure_kind == 'failed-port-pair':
                return 1, output + '--- FAIL: ' + GATE.PORT_PAIR + ' (0.01s)\n'
            if self.failure_kind != 'missing-port-pair':
                cases = GATE.PORT_PAIR_CASES[:-1] if self.failure_kind == 'missing-port-pair-leaf' else GATE.PORT_PAIR_CASES
                output += success(GATE.PORT_PAIR, cases)
            return 0, output
        parent = selected.strip('^$')
        family = 'QUIC' if 'QUIC' in parent else 'TLS'
        cases = (GATE.CREDENTIALS if parent.endswith('Credentials') else GATE.TRAFFIC)[family]
        output = success(parent, cases)
        if self.failure_kind == 'missing-case':
            output = output.replace('--- PASS: ' + parent + '/' + cases[-1], 'fixture log only: ' + parent + '/' + cases[-1])
        return 0, output

    @contextmanager
    def installed(self):
        with ExitStack() as stack:
            stack.enter_context(redirect_stdout(io.StringIO()))
            for owner, attribute, value in (
                (GATE, 'checked_sources', self.sources),
                (GATE, 'tool_receipts', lambda *args: {'runner-test': 'stable'}),
                (GATE, 'dependency_receipt', lambda *args: {'runner-test': 'stable'}),
                (GATE, 'mutations', lambda source: (self.control,)),
                (GATE.NODE, 'selected_compiler', lambda *args: (self.compiler, {'GOOS': 'linux', 'GOARCH': 'amd64', 'CGO_ENABLED': '1'}, 'amd64')),
                (GATE.NODE, 'run', self.run),
                (GATE.NODE, 'build_layer_reference', self.relay),
                (GATE.NODE, 'build_xray_reference', self.xray),
                (GATE.NODE, 'xray_reference_sources', lambda source: {'captured': 'xray'}),
                (GATE.REFERENCE, 'generate_keys', self.keys),
                (GATE.REFERENCE, 'test_sources', self.test_sources),
                (GATE.REFERENCE.BUILD.PQ, 'verify', self.native),
                (GATE.REFERENCE.BUILD.POLICY.AMNEZIA.TIMERS.subprocess, 'check_output', self.timer_command),
                (GATE.REFERENCE.BUILD.POLICY.AMNEZIA.TIMERS, 'verify_tree', self.timer_tree),
            ):
                stack.enter_context(patch.object(owner, attribute, value))
            timers = GATE.REFERENCE.BUILD.POLICY.AMNEZIA.TIMERS
            self.timer_verifier = stack.enter_context(patch.object(timers, 'verify', wraps=timers.verify))
            yield

    def execute(self):
        return GATE.execute(self.core, self.library, self.cache, self.compiler, receipt_path=self.receipt)


class MAXOwnershipChecks(unittest.TestCase):
    def test_receipt_is_published_after_joined_source_and_private_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            run = ModeledRun(Path(directory))
            with run.installed():
                result = run.execute()
            self.assertTrue(run.assert_new)
            run.timer_verifier.assert_called_once_with(run.core, run.compiler, env=run.dependency_env)
            self.assertEqual(run.dependency_events, ['checksum', 'plan', 'selection', 'tree'])
            self.assertEqual(run.events, ['source-enter', 'source-joined'])
            self.assertTrue(all(not path.exists() for path in run.private))
            self.assertTrue(result['private_key_workspace_removed'])
            self.assertEqual(result['startup_record_case'], GATE.STARTUP_RECORDS)
            self.assertEqual(result['port_pair_case'], GATE.PORT_PAIR)
            self.assertEqual(result['port_pair_subcases'], GATE.PORT_PAIR_CASES)
            self.assertEqual(json.loads(run.receipt.read_text())['target'], 'linux/amd64')
            deadlines = [value for command in run.commands for value in command if value.startswith('-test.timeout=')]
            self.assertCountEqual(deadlines, ['-test.timeout=120s', '-test.timeout=600s', '-test.timeout=1800s',
                                             '-test.timeout=600s', '-test.timeout=1800s', '-test.timeout=90s'])

    def test_unverified_timer_dependency_cannot_reach_keys_compilation_or_receipt(self):
        for fault, witness in (('module-checksum', 'checksum verification'),
                               ('timer-missing', 'unrelated or missing AWG timer replacement'),
                               ('timer-foreign', 'unrelated or missing AWG timer replacement'),
                               ('timer-selected', 'exact selected private AWG timer copy'),
                               ('timer-tree', 'pinned AWG tree rejection')):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                run = ModeledRun(Path(directory), fault)
                with run.installed(), self.assertRaisesRegex(ValueError, witness):
                    run.execute()
                self.assertFalse(run.receipt.exists())
                self.assertEqual(run.private, [])
                self.assertEqual(run.events, [])
                self.assertEqual(run.commands, [[str(run.compiler), 'mod', 'verify']])
                if fault == 'module-checksum':
                    run.timer_verifier.assert_not_called()
                else:
                    run.timer_verifier.assert_called_once_with(run.core, run.compiler, env=run.dependency_env)

    def test_failed_compile_execution_or_postflight_never_publishes_a_receipt(self):
        for fault in ('control-compile', 'control-succeeded', 'missing-case', 'changed-source', 'changed-archive',
                      'missing-startup-records', 'failed-startup-records',
                      'missing-port-pair', 'missing-port-pair-leaf', 'failed-port-pair'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                run = ModeledRun(Path(directory), fault)
                with run.installed(), self.assertRaises(ValueError):
                    run.execute()
                self.assertFalse(run.receipt.exists())
                self.assertEqual(run.events, ['source-enter', 'source-joined'])
                self.assertTrue(all(not path.exists() for path in run.private))

    def test_existing_receipt_is_refused_before_compilation_or_key_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            run = ModeledRun(Path(directory))
            run.receipt.write_text('another owner')
            with run.installed(), self.assertRaisesRegex(ValueError, 'new owned output file'):
                run.execute()
            self.assertEqual(run.receipt.read_text(), 'another owner')
            self.assertEqual(run.source_reads, 0)
            self.assertEqual(run.private, [])

    def test_cleanup_failure_cannot_leave_success_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            run = ModeledRun(Path(directory))
            original = tempfile.TemporaryDirectory

            @contextmanager
            def failed_cleanup(*args, **kwargs):
                with original(*args, **kwargs) as workspace:
                    yield workspace
                raise RuntimeError('joined private cleanup failure')

            with run.installed(), patch.object(GATE.tempfile, 'TemporaryDirectory', failed_cleanup):
                with self.assertRaisesRegex(RuntimeError, 'joined private cleanup failure'):
                    run.execute()
            self.assertFalse(run.receipt.exists())
            self.assertEqual(run.events[-1], 'source-joined')
            self.assertTrue(all(not path.exists() for path in run.private))


if __name__ == '__main__':
    unittest.main()
