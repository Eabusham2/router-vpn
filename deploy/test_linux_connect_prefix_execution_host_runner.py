#!/usr/bin/env python3
"""Reject incomplete, stale or bypassed installed CONNECT prefix evidence.

These tests exercise the receipt validator and orchestration with explicit
observations. They do not claim that a synthetic transcript ran a native tunnel.
"""
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
from pathlib import Path
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('linux_connect_prefix_gate', ROOT/'deploy/test_linux_connect_prefix_execution_host.py')
GATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)


def observation(case):
    item = GATE.scenario(case)
    count, fault = item['prefixes'], item['fault']

    def prefix(position, active):
        mode = GATE.MODES[(position+count+item['arm']-1) % 3] if item['restored'] else GATE.MODES[position % 3]
        return dict(position=position, mode=mode, parameters_sha256='' if mode == 'wg' else f'{position+1:064x}',
                    raw_udp=int(active), tcp=int(active), udp=0, proof_queries=int(active), auth_refusals=0)

    local = [prefix(position, position == 0 or item['requested'] == 'auto') for position in range(count)]
    server = [prefix(position, True) for position in range(1, count)]
    middle = dict(method=item['protocol'], auth_refusals=0, target_refusals=0, tls_refusals=0, open_streams=0,
                  raw_tcp=1, raw_udp=0, tcp=1, udp=0, public_queries=1)
    final = dict(raw_tcp=1, raw_udp=0, tcp=1, udp=0, proof_queries=1, dns_queries=1,
                 public_queries=1, direct_queries=0, entry_public_queries=0)

    def clear(values, keys=None):
        for key in keys if keys is not None else tuple(values):
            if type(values[key]) is int:
                values[key] = 0

    if fault in ('wrong-first-key', 'wrong-later-key'):
        failed = 1 if fault == 'wrong-first-key' else count-1
        for row in server:
            if row['position'] >= failed:
                clear(row, ('raw_udp', 'tcp', 'udp', 'proof_queries', 'auth_refusals'))
                row['raw_udp'] = int(row['position'] == failed)
        clear(middle)
        clear(final)
    elif fault in ('wrong-auth','tls-name'):
        clear(middle, ('tcp', 'udp', 'public_queries'))
        clear(final)
        middle['auth_refusals' if fault=='wrong-auth' else 'tls_refusals']=1
    elif fault == 'wrong-public':
        clear(final)
    elif fault == 'wrong-final-key':
        clear(final, ('tcp', 'udp', 'proof_queries', 'dns_queries', 'public_queries'))
    elif fault == 'failed-dns':
        final['public_queries'] = 0
    final['uot_version']=2
    return dict(case=case, prefixes=count, protocol=item['protocol'], requested=item['requested'], winner=item['winner'],
                carrier_required=item['carrier_required'], launches=1,
                restore_launches=int(item['restored'] and item['winner'] == 'server'),
                comparison_trials=2 if item['requested'] == 'auto' else 0, entry_proofs=1,
                local_prefixes=local, server_prefixes=server, carrier_packets=int(count > 1),
                carrier_tcp=int(count == 1), local_delayed_packets=0, middle=middle, final=final)


def output(case, values=None):
    values = observation(case) if values is None else values
    root = GATE.TEST
    return '\n'.join(('=== RUN   '+root, '=== RUN   '+root+'/'+case,
                      '    desktop_connect_prefix_linux_tun_native_test.go:710: LINUX_CONNECT_PREFIX_EXECUTION_COUNTERS '+json.dumps(values),
                      '    desktop_connect_prefix_linux_tun_native_test.go:711: '+GATE.receipt(case),
                      '--- PASS: '+root+' (1.00s)', '    --- PASS: '+root+'/'+case+' (1.00s)', 'PASS',
                      *(f'Linux guardian namespace phase: {phase} (pid=1, monotonic=123.456)'
                        for phase in GATE.NAMESPACE_RETIREMENT_PHASES), ''))


class CONNECTPrefixExecutionRunner(unittest.TestCase):
    def test_complete_case_and_source_inventory(self):
        self.assertEqual(GATE.case_inventory(), GATE.CASES)
        self.assertEqual(len(GATE.CASES), 40)
        self.assertEqual(len(set(GATE.CASES)), 40)
        self.assertEqual(len(GATE.POSITIVE), 30)
        self.assertEqual(sum(len(children)+1 for children in GATE.SOURCE_TESTS.values()), 60)
        self.assertEqual(len(GATE.peer_inventory()), 9)

    def test_all_forty_receipts_have_distinct_original_paths(self):
        for case in GATE.CASES:
            with self.subTest(case=case):
                GATE.check_verdict(output(case), case)

    def test_terminal_go_verdict_cannot_be_missing_duplicated_or_nonterminal(self):
        for case in GATE.CASES:
            original = output(case)
            for changed in (original.replace('\nPASS\n', '\n', 1),
                            original.replace('\nPASS\n', '\nPASS\nPASS\n', 1),
                            original.replace('\nPASS\n', '\nPASS\nforeign trailing output\n', 1),
                            original.replace('\nPASS\n', '\n PASS\n', 1),
                            original+'foreign trailing output\n'):
                with self.subTest(case=case), self.assertRaises(ValueError):
                    GATE.check_verdict(changed, case)

    def test_actual_namespace_retirement_format_is_required_in_original_order(self):
        case = GATE.CASES[0]
        original = output(case)
        before, tail = original.split('\nPASS\n', 1)
        captured = io.StringIO()
        with redirect_stdout(captured):
            for phase in GATE.NAMESPACE_RETIREMENT_PHASES:
                GATE.GUARD.namespace_progress(phase)
        GATE.check_verdict(before+'\nPASS\n'+captured.getvalue(), case)
        lines = tail.splitlines()
        changes = ['', '\n'.join(reversed(lines))+'\n', tail+tail,
                   tail.replace('test status 0', 'test status 1'),
                   tail.replace('pid=1', 'pid=foreign'),
                   tail.replace('monotonic=123.456', 'monotonic=nan')]
        changes += ['\n'.join(lines[:index]+lines[index+1:])+'\n' for index in range(len(lines))]
        for changed in changes:
            with self.subTest(tail=changed), self.assertRaises(ValueError):
                GATE.check_verdict(before+'\nPASS\n'+changed, case)

    def test_missing_duplicate_foreign_or_reordered_case_verdict_is_rejected(self):
        for case in GATE.CASES:
            original = output(case)
            lines = original.splitlines()
            for index, line in enumerate(lines):
                if 'LINUX_CONNECT_PREFIX_EXECUTION_' in line or line.startswith('=== RUN') or '--- PASS:' in line:
                    with self.subTest(case=case, line=index), self.assertRaises(ValueError):
                        GATE.check_verdict('\n'.join(lines[:index]+lines[index+1:]), case)
            for changed in (original+original, original.replace('case='+case, 'case=foreign'),
                            original.replace(GATE.TEST+'/'+case, GATE.TEST+'/foreign'),
                            '\n'.join(lines[:1]+lines[2:3]+lines[1:2]+lines[3:])):
                with self.subTest(case=case), self.assertRaises(ValueError):
                    GATE.check_verdict(changed, case)

    def test_fail_skip_race_panic_and_foreign_leaf_are_not_success(self):
        case = GATE.CASES[0]
        for marker in ('--- FAIL: x (0.01s)', '--- SKIP: x (0.01s)', 'WARNING: DATA RACE', 'panic: failed',
                       '=== RUN   Foreign\n--- PASS: Foreign (0.01s)'):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                GATE.check_verdict(output(case)+marker+'\n', case)

    def test_evidence_requires_actual_running_leaf_and_original_file(self):
        case = GATE.CASES[0]
        lines = output(case).splitlines()
        for index in (2, 3):
            for changed in ('\n'.join([lines[index]]+lines[:index]+lines[index+1:]),
                            '\n'.join(lines[:index]+lines[index+1:]+[lines[index]]),
                            output(case).replace('desktop_connect_prefix_linux_tun_native_test.go:', 'foreign.go:'),
                            output(case).replace(lines[index], lines[index].strip())):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    GATE.check_verdict(changed, case)

    def test_every_counter_object_requires_its_exact_fields(self):
        case = 'connect-https-p6-auto-server'
        for location in ((), ('local_prefixes', 0), ('server_prefixes', 0), ('middle',), ('final',)):
            original = observation(case)
            target = original
            for key in location:
                target = target[key]
            for key in target:
                changed = deepcopy(original)
                value = changed
                for part in location:
                    value = value[part]
                del value[key]
                with self.subTest(location=location, key=key), self.assertRaises(ValueError):
                    GATE.check_verdict(output(case, changed), case)
            changed = deepcopy(original)
            value = changed
            for part in location:
                value = value[part]
            value['foreign'] = 0
            with self.assertRaises(ValueError):
                GATE.check_verdict(output(case, changed), case)

    def test_counter_types_ranges_and_duplicate_json_keys_are_rejected(self):
        case = 'connect-https-p6-auto-server'
        original = observation(case)
        for location in (('launches',), ('prefixes',), ('local_prefixes', 0, 'raw_udp'),
                         ('server_prefixes', 0, 'proof_queries'), ('middle', 'tcp'), ('final', 'dns_queries')):
            for replacement in (True, -1, 1.5, '1', None, 2**64):
                changed = deepcopy(original)
                target = changed
                for key in location[:-1]:
                    target = target[key]
                target[location[-1]] = replacement
                with self.subTest(location=location, replacement=replacement), self.assertRaises(ValueError):
                    GATE.check_verdict(output(case, changed), case)
        for before, after in (('"launches": 1', '"launches": 1, "launches": 1'),
                              ('"raw_udp": 1', '"raw_udp": 1, "raw_udp": 1')):
            with self.assertRaises(ValueError):
                GATE.check_verdict(output(case).replace(before, after, 1), case)

    def test_prefix_positions_modes_and_parameters_cannot_be_substituted(self):
        case = 'connect-https-p6-auto-server'
        original = observation(case)
        for lane in ('local_prefixes', 'server_prefixes'):
            for changed_rows in (original[lane][:-1], original[lane]+original[lane][:1], list(reversed(original[lane]))):
                changed = deepcopy(original)
                changed[lane] = changed_rows
                with self.subTest(lane=lane), self.assertRaises(ValueError):
                    GATE.check_verdict(output(case, changed), case)
            for position, row in enumerate(original[lane]):
                for key, replacement in (('position', row['position']+1), ('mode', 'foreign'),
                                         ('parameters_sha256', 'f'*64 if row['mode'] == 'wg' else ''),
                                         ('auth_refusals', 1)):
                    changed = deepcopy(original)
                    changed[lane][position][key] = replacement
                    with self.subTest(lane=lane, position=position, key=key), self.assertRaises(ValueError):
                        GATE.check_verdict(output(case, changed), case)
        for position, row in enumerate(original['server_prefixes']):
            if row['mode'] != 'wg':
                changed = deepcopy(original)
                changed['server_prefixes'][position]['parameters_sha256'] = 'f'*64
                with self.assertRaises(ValueError):
                    GATE.check_verdict(output(case, changed), case)

    def test_carrier_comparison_and_retained_execution_are_exact(self):
        for case in GATE.CASES:
            original = observation(case)
            for key in ('restore_launches', 'comparison_trials'):
                changed = deepcopy(original)
                changed[key] += 1
                with self.subTest(case=case, key=key), self.assertRaises(ValueError):
                    GATE.check_verdict(output(case, changed), case)
            for key, value in (('requested', 'local'), ('winner', 'foreign'), ('carrier_required', 1),
                               ('case', 'foreign'), ('prefixes', original['prefixes']+1)):
                changed = deepcopy(original)
                changed[key] = value
                with self.subTest(case=case, key=key), self.assertRaises(ValueError):
                    GATE.check_verdict(output(case, changed), case)
            for key in ('launches', 'entry_proofs', 'carrier_packets' if original['prefixes'] > 1 else 'carrier_tcp'):
                changed = deepcopy(original)
                changed[key] = 0
                with self.subTest(case=case, key=key), self.assertRaises(ValueError):
                    GATE.check_verdict(output(case, changed), case)
            if original['prefixes'] > 1:
                changed = deepcopy(original)
                changed['carrier_tcp'] = 1
                with self.assertRaises(ValueError):
                    GATE.check_verdict(output(case, changed), case)

    def test_each_successful_original_prefix_middle_final_and_dns_is_observed(self):
        for case in GATE.POSITIVE:
            original = observation(case)
            locations = [('local_prefixes', 0, key) for key in ('raw_udp', 'tcp')]
            for lane in ('local_prefixes', 'server_prefixes'):
                for position, row in enumerate(original[lane]):
                    if lane == 'server_prefixes' or (position and original['requested'] == 'auto'):
                        locations += [(lane, position, key) for key in ('raw_udp', 'tcp', 'proof_queries')]
            locations += [('middle', key) for key in ('raw_tcp', 'tcp', 'public_queries')]
            locations += [('final', key) for key in ('raw_tcp', 'tcp', 'proof_queries', 'dns_queries', 'public_queries')]
            for location in locations:
                changed = deepcopy(original)
                target = changed
                for part in location[:-1]:
                    target = target[part]
                target[location[-1]] = 0
                with self.subTest(case=case, location=location), self.assertRaises(ValueError):
                    GATE.check_verdict(output(case, changed), case)
            for key in ('direct_queries', 'entry_public_queries'):
                changed = deepcopy(original)
                changed['final'][key] = 1
                with self.assertRaises(ValueError):
                    GATE.check_verdict(output(case, changed), case)

    def test_failed_original_boundary_cannot_be_skipped_or_reached_past(self):
        for case, witness, bypass in (
            ('connect-https-p6-wrong-first-key', ('server_prefixes', 0, 'raw_udp'), ('server_prefixes', 0, 'tcp')),
            ('connect-https-p6-wrong-later-key', ('server_prefixes', 4, 'raw_udp'), ('server_prefixes', 4, 'proof_queries')),
            ('connect-https-p6-wrong-auth', ('middle', 'raw_tcp'), ('middle', 'tcp')),
            ('connect-https-p6-wrong-public', ('middle', 'public_queries'), ('final', 'raw_tcp')),
            ('connect-https-p6-wrong-final-key', ('final', 'raw_tcp'), ('final', 'proof_queries')),
            ('connect-https-p6-failed-dns', ('final', 'dns_queries'), ('final', 'direct_queries')),
        ):
            for location, replacement in ((witness, 0), (bypass, 1)):
                changed = observation(case)
                target = changed
                for part in location[:-1]:
                    target = target[part]
                target[location[-1]] = replacement
                with self.subTest(case=case, location=location), self.assertRaises(ValueError):
                    GATE.check_verdict(output(case, changed), case)

    def test_real_linux_opt_in_and_native_architecture_are_required(self):
        for machine, architecture in (('x86_64', 'amd64'), ('aarch64', 'arm64')):
            with patch.object(GATE.platform, 'system', return_value='Linux'), patch.object(GATE.platform, 'machine', return_value=machine):
                self.assertEqual(GATE.required_host({GATE.FLAG: '1'}), 'linux/'+architecture)
                for env in ({}, {GATE.FLAG: '0'}, {GATE.FLAG: '1', 'HOMEVPN_MTU_BENCH_FAKE': ''},
                            {GATE.FLAG: '1', 'GOOS': 'darwin'}, {GATE.FLAG: '1', 'CGO_ENABLED': '0'},
                            {GATE.FLAG: '1', 'GOARCH': 'foreign'}):
                    with self.subTest(machine=machine, env=env), self.assertRaises(ValueError):
                        GATE.required_host(env)
        for system, machine in (('Darwin', 'aarch64'), ('Linux', 'foreign')):
            with patch.object(GATE.platform, 'system', return_value=system), patch.object(GATE.platform, 'machine', return_value=machine), self.assertRaises(ValueError):
                GATE.required_host({GATE.FLAG: '1'})

    def test_selected_compiler_keeps_original_native_target_and_sanitized_capture(self):
        environment = {'GOFLAGS': 'foreign-overlay', 'GOWORK': 'foreign-work'}
        for arch in ('amd64', 'arm64'):
            captured = {'GOOS': 'linux', 'GOARCH': arch, 'GOTOOLCHAIN': 'local', 'GOWORK': 'off', 'GOFLAGS': ''}
            compiler = Path('/captured/go/bin/go')
            with patch.object(GATE.NODE, 'selected_compiler', return_value=(compiler, captured, arch)) as select:
                actual, values = GATE.selected_compiler('go', environment, 'linux/'+arch)
            select.assert_called_once_with('go', GATE.ROOT, environment)
            self.assertEqual(actual, compiler)
            self.assertEqual(values['CGO_ENABLED'], '1')
            for target, changed in (('linux/foreign', captured), ('linux/'+arch, dict(captured, GOOS='darwin')),
                                    ('linux/'+arch, dict(captured, GOARCH='foreign'))):
                with patch.object(GATE.NODE, 'selected_compiler', return_value=(compiler, changed, arch)), self.assertRaises(ValueError):
                    GATE.selected_compiler('go', environment, target)

    def test_namespace_keeps_original_images_receipt_and_environment_on_failure(self):
        case = GATE.CASES[0]
        with self.assertRaises(ValueError):
            GATE.namespace_test(Path('/x'), Path('/y'), Path('/z'), 'a'*64, 'b'*64, 'c'*64, 'foreign')
        with patch.object(GATE.CHILD, 'image_identity', return_value=(1, 2, 3, 4, 'd'*64)), self.assertRaises(ValueError):
            GATE.namespace_test(Path('/x'), Path('/y'), Path('/z'), 'a'*64, 'b'*64, 'c'*64, case)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            receipt = bundle/'NATIVE-RUNTIME.json'
            receipt.write_text('{}')
            receipt.chmod(0o600)
            digest = hashlib.sha256(receipt.read_bytes()).hexdigest()
            keys = (*GATE.BASE.NAMESPACE_ENVIRONMENT, 'ROUTERVPN_CONNECT_PREFIX_EXECUTION_SOURCE')
            before = {key: os.environ.get(key) for key in keys}

            def failed(binary, selector, image):
                self.assertEqual((binary, selector, image), (Path('/x'), 'CONNECTPrefixExecution/'+case, 'a'*64))
                self.assertEqual(os.environ['ROUTERVPN_CONNECT_PREFIX_EXECUTION_SOURCE'], str(GATE.ROOT))
                raise RuntimeError('owned namespace failed')

            identity = lambda path: (1, 2, 3, 4, ('a' if str(path) == '/x' else 'b')*64)
            with patch.object(GATE.CHILD, 'image_identity', side_effect=identity), patch.object(GATE.GUARD, 'namespace_test', side_effect=failed):
                with self.assertRaisesRegex(RuntimeError, 'owned namespace failed'):
                    GATE.namespace_test(Path('/x'), Path('/y'), bundle, 'a'*64, 'b'*64, digest, case)
            self.assertEqual({key: os.environ.get(key) for key in keys}, before)
            with patch.object(GATE.CHILD, 'image_identity', side_effect=identity), self.assertRaises(ValueError):
                GATE.namespace_test(Path('/x'), Path('/y'), bundle, 'a'*64, 'b'*64, 'f'*64, case)

    def test_existing_finite_native_case_budgets_are_preserved(self):
        with patch.object(GATE.GUARD.subprocess, 'run') as run:
            for case in GATE.CASES:
                GATE.GUARD.namespace_test_execution('/image', 'selector', 'CONNECTPrefixExecution/'+case, {})
                self.assertIn('-test.timeout=240s', run.call_args.args[0])
                self.assertEqual(run.call_args.kwargs['timeout'], 250)

    def exercise_executor(self, failed_case=None):
        """Run actual orchestration against explicit subprocess observations."""
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            work = Path(directory)
            bundle, core = work/'bundle', work/'core'
            bundle.mkdir()
            core.mkdir()
            source = {'native': {'source': 'a'*64}, 'fixture': {'fixture': 'b'*64}}
            stack.enter_context(patch.object(GATE, 'required_host', return_value='linux/amd64'))
            stack.enter_context(patch.object(GATE.REPOSITORY, 'repository_identity', return_value={'commit': 'c'*40}))
            stack.enter_context(patch.object(GATE, 'case_inventory', return_value=GATE.CASES))
            stack.enter_context(patch.object(GATE, 'peer_inventory', return_value=()))
            stack.enter_context(patch.object(GATE, 'selected_compiler', return_value=(Path('/compiler/go'), {'GOOS': 'linux', 'GOARCH': 'amd64'})))
            stack.enter_context(patch.object(GATE.BASE, 'bundle_identity', return_value=({'owned': True}, {'NATIVE-RUNTIME.json': {'sha256': 'd'*64}})))
            stack.enter_context(patch.object(GATE.BUILD, 'digest', return_value='e'*64))
            stack.enter_context(patch.object(GATE.GUARD.UID, 'privilege_tool', return_value=None))
            stack.enter_context(patch.object(GATE.CHILD, 'new_receipt_path', return_value=work/'receipt.json'))
            stack.enter_context(patch.object(GATE, 'source_identity', return_value=source))
            stack.enter_context(patch.object(GATE.CHILD, 'image_identity', return_value=(1, 2, 3, 4, 'f'*64)))
            publish = stack.enter_context(patch.object(GATE.CHILD, 'publish_receipt'))
            calls, cases = [], []

            def process(command, **kwargs):
                calls.append((command, kwargs))
                value = ''
                if command[1] == 'version':
                    value = command[2]+': '+GATE.BUILD.TOOLCHAIN+'\n'
                elif command[0].endswith('peer.test'):
                    root = command[-1][len('-test.run=^'):-1]
                    names = (root, *(root+'/'+leaf for leaf in GATE.SOURCE_TESTS[root]))
                    value = '\n'.join(['=== RUN   '+name for name in names]+['--- PASS: '+name+' (0.01s)' for name in names]+['PASS', ''])
                return subprocess.CompletedProcess(command, 0, stdout=value)

            def namespace(command, **kwargs):
                case = command[command.index('--case')+1]
                cases.append((case, kwargs))
                if case == failed_case:
                    return output(case).replace('native_joined=true', 'native_joined=false')
                return output(case)

            stack.enter_context(patch.object(GATE.subprocess, 'run', side_effect=process))
            stack.enter_context(patch.object(GATE.GUARD.UID, 'run', side_effect=namespace))
            with redirect_stdout(io.StringIO()):
                if failed_case:
                    with self.assertRaises(ValueError):
                        GATE.execute(bundle, core, required_commit='c'*40, receipt_file=work/'receipt.json')
                    publish.assert_not_called()
                    result = None
                else:
                    result = GATE.execute(bundle, core, required_commit='c'*40, receipt_file=work/'receipt.json')
                    publish.assert_called_once()
            return result, calls, cases

    def test_executor_runs_every_original_component_and_native_case_before_receipt(self):
        result, calls, cases = self.exercise_executor()
        self.assertEqual(result['completed'], list(GATE.CASES))
        self.assertEqual(result['cases'], list(GATE.CASES))
        self.assertFalse(result['remote_private_deployment'])
        self.assertEqual([case for case, kwargs in cases], list(GATE.CASES))
        self.assertTrue(all(kwargs['timeout'] == 265 for case, kwargs in cases))
        compiles = [(command, kwargs) for command, kwargs in calls if command[1] == 'test']
        self.assertEqual(len(compiles), 2)
        self.assertTrue(all('-race' in command and kwargs['timeout'] == 300 for command, kwargs in compiles))
        roots = [(command, kwargs) for command, kwargs in calls if command[0].endswith('peer.test')]
        self.assertEqual(len(roots), 6)
        self.assertTrue(all('-test.timeout=120s' in command and kwargs['timeout'] == 135 for command, kwargs in roots))

    def test_partial_native_failure_never_publishes_complete_receipt(self):
        case = GATE.CASES[7]
        result, calls, cases = self.exercise_executor(case)
        self.assertIsNone(result)
        self.assertEqual([name for name, kwargs in cases], list(GATE.CASES[:8]))


if __name__ == '__main__':
    unittest.main()
