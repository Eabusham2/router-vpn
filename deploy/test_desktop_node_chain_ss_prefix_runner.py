#!/usr/bin/env python3
"""Refuse omitted, foreign, substituted or unjoined SS2022 prefix evidence."""
from pathlib import Path
from contextlib import ExitStack, redirect_stdout
import copy
import importlib.util
import io
import json
import re
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ss_prefix_gate', ROOT / 'deploy/test_desktop_node_chain_ss_prefix.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def passed(names):
    return ''.join('=== RUN   ' + name + '\n--- PASS: ' + name + ' (0.01s)\n' for name in names) + 'PASS\n'


def workflow_contract(workflow, release):
    # Acceptance is unconditional. Only the named diagnostics uploader may
    # run after failure, and it cannot carry an accepting contract receipt.
    conditions = [line for line in workflow.splitlines() if re.match(r"^\s*(?:if|['\"]if['\"])\s*:", line)]
    diagnostic_step = ('      - name: Retain failed source/native contract diagnostics\n'
                       '        if: always()\n'
                       '        uses: actions/upload-artifact@v4\n')
    if conditions != ['        if: always()'] or workflow.count(diagnostic_step) != 1:
        raise ValueError('SS2022 accepting jobs and commands cannot be conditional')
    required = ("PYTHONDONTWRITEBYTECODE: '1'", 'mode: [wg, awg2-fast, awg2-strong]', 'form: [literal, hostname]', 'fail-fast: false',
                'needs: [contracts, encrypted]', 'test_desktop_node_chain_ss_prefix_contract.py',
                'test_desktop_node_chain_ss_prefix_contract_runner.py',
                '--contracts "$RUNNER_TEMP/ss-prefix-contracts/ss-prefix-contracts.json"', 'path: validator', 'path: source', "go-version: '1.26.3'",
                'test_desktop_node_chain_ss_prefix_runner.py', '--source-checkout "$GITHUB_WORKSPACE/source"',
                '--require-commit "$ROUTERVPN_EXPECTED_SOURCE"', '--mode "$ROUTERVPN_IMPORTED_SS_MODE"',
                '--form "$ROUTERVPN_IMPORTED_SS_FORM"', '--aggregate "$RUNNER_TEMP/ss-prefix-units"',
                'pattern: RouterVPN-SS2022-prefix-*-${{ github.sha }}',
                'RouterVPN-SS2022-prefix-complete-${{ github.sha }}')
    if any(part not in workflow for part in required) or workflow.count('if-no-files-found: error') != 3:
        raise ValueError('SS2022 prefix workflow lost a required matrix, source or receipt boundary')
    if workflow.count('--source-checkout "$GITHUB_WORKSPACE/source"') != 3 or workflow.count('--require-commit "$ROUTERVPN_EXPECTED_SOURCE"') != 3:
        raise ValueError('SS2022 prefix unit or aggregate omitted its exact source binding')
    if workflow.index('go-version:') > workflow.index('test_desktop_node_chain_ss_prefix_runner.py'):
        raise ValueError('SS2022 prefix validator ran before its captured compiler')
    for job, following, runner in (
            ('contracts', 'encrypted', 'test_desktop_node_chain_ss_prefix_contract_runner.py'),
            ('encrypted', 'complete', 'test_desktop_node_chain_ss_prefix_runner.py')):
        block = workflow.split('\n  ' + job + ':\n', 1)[1].split('\n  ' + following + ':\n', 1)[0]
        if (block.count("go-version: '1.26.3'") != 1 or
                block.index("go-version: '1.26.3'") > block.index('run: python3 validator/deploy/' + runner)):
            raise ValueError('SS2022 original compiler must precede each job validator')
    contracts = workflow.split('\n  contracts:\n', 1)[1].split('\n  encrypted:\n', 1)[0]
    udp_call = '        run: python3 validator/deploy/test_reference_udp_lifetime.py\n'
    if (contracts.count(udp_call) != 1 or contracts.index(udp_call) < contracts.index("go-version: '1.26.3'") or
            contracts.index(udp_call) > contracts.index('python3 validator/deploy/test_desktop_node_chain_ss_prefix_contract.py')):
        raise ValueError('SS2022 contracts require the actual reference UDP controls before acceptance')
    udp_step = contracts.split('      - name: Require actual reference UDP lifetime and ownership controls\n', 1)
    if len(udp_step) != 2 or 'if:' in udp_step[1].split('      - ', 1)[0]:
        raise ValueError('SS2022 reference UDP controls cannot be conditional')
    if 'continue-on-error:' in workflow or workflow.count('if: always()') != 1 or 'run-id:' in workflow:
        raise ValueError('SS2022 prefix workflow borrowed or ignored another run')
    diagnostic = workflow.split('      - name: Retain failed source/native contract diagnostics\n', 1)
    if len(diagnostic) != 2 or 'if: always()' not in diagnostic[1].split('\n  encrypted:', 1)[0] or 'contracts.json' in diagnostic[1].split('\n  encrypted:', 1)[0]:
        raise ValueError('Only non-accepting diagnostics may survive a failed contract job')
    if ('uses: ./.github/workflows/ss-node-chain-prefix.yml' not in release or
            'desktop-connect-child, ss-prefix-native]' not in release):
        raise ValueError('SS2022 prefix workflow is not required by release aggregation')


class SS2022PrefixRunner(unittest.TestCase):
    def setUp(self):
        self.repository = {'repository': 'Eabusham2/router-vpn', 'commit': 'a' * 40, 'tree': 'b' * 40}
        self.selection = {'suite': G.SUITE, 'source_sha': 'a' * 40, 'validator_sha': 'a' * 40}
        self.sources = {key: 'c' * 64 for key in (*G.BASE.ORIGINAL.REQUIRED, *G.BASE.REQUIRED, *G.REQUIRED)}
        self.sources.update({'gate/' + key: value for key, value in G.validator_identity().items()})

    def receipt(self, mode='wg', form='literal'):
        return {'schema': 1, 'gate': 'encrypted-ss-prefix-unit', 'mode': mode, 'form': form,
                'repository': self.repository, 'selection': self.selection, 'validator': G.validator_identity(),
                'target': 'linux/amd64', 'pins': {'sing-box': G.BUILD.PIN, 'xray': G.BUILD.POLICY.XRAY.XRAY_PIN},
                'scope': 'encrypted-reference-component', 'installed_host_accepted': False, 'kernel_tun_accepted': False,
                'source_files': dict(self.sources), 'image_sha256': 'd' * 64,
                'phases': [{**phase, 'image_sha256': 'd' * 64, 'output_sha256': 'e' * 64}
                           for phase in G.unit_phases(mode, form)]}

    def check(self, receipt):
        return G.check_receipt(receipt, self.repository, self.selection)

    def test_complete_additive_inventory_preserves_original_phases(self):
        self.assertEqual(len(G.UNITS), 6)
        self.assertEqual(len(G.ORIGINAL_SS.NODE_CHAIN_IMPORTED_VERDICTS), 73)
        self.assertEqual(len(G.ORIGINAL_SS.NODE_CHAIN_IMPORTED_MTU_VERDICTS), 134)
        phases = [phase for unit in G.UNITS for phase in G.unit_phases(*unit)]
        self.assertEqual(len(phases), 42)
        self.assertEqual(len({phase['name'] for phase in phases}), 42)
        self.assertEqual(sum('nodes' in phase for phase in phases), 36)
        self.assertEqual(sum('nodes' not in phase for phase in phases), 6)
        for unit in G.UNITS:
            group = G.unit_phases(*unit)
            for nodes in (4, 8):
                positions = [position for phase in group if phase.get('nodes') == nodes for position in phase['positions']]
                self.assertEqual(positions, list(range(nodes)))
            self.check(self.receipt(*unit))

    def test_foreign_unit_cannot_select_partial_phase(self):
        for unit in (('wg', 'quic'), ('foreign', 'literal'), ('WG', 'hostname'), (None, 'literal')):
            with self.subTest(unit=unit), self.assertRaises(ValueError):
                G.unit_phases(*unit)

    def test_native_parser_requires_each_actual_run_and_pass(self):
        names = G.unit_phases('wg', 'literal')[0]['verdicts']
        original = passed(names)
        G.NODE.require_native_verdicts(original, names, 'prefix')
        for name in names:
            for part in ('=== RUN   ' + name + '\n', '--- PASS: ' + name + ' (0.01s)\n'):
                with self.subTest(part=part), self.assertRaises(ValueError):
                    G.NODE.require_native_verdicts(original.replace(part, '', 1), names, 'prefix')
        for extra in (passed(names[:1]), passed(('TestForeign',)), '--- SKIP: foreign (0s)\n',
                      '--- FAIL: foreign (0s)\n', 'WARNING: DATA RACE\n', 'panic: foreign\n'):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                G.NODE.require_native_verdicts(original + extra, names, 'prefix')

    def peer(self, unit=('wg', 'literal'), mutate=None, statuses=None):
        stack = ExitStack()
        self.addCleanup(stack.close)
        identity = stack.enter_context(mock.patch.object(G.NODE, 'retained_binary', return_value=('file', 'd' * 64)))
        source = stack.enter_context(mock.patch.object(G, 'checked_sources', return_value=(Path('/source'), self.sources)))
        phases = G.unit_phases(*unit)
        calls = []
        def run(command, **kwargs):
            index = len(calls)
            calls.append((command, kwargs))
            output = passed(phases[index]['verdicts'])
            status = 0 if statuses is None else statuses[index]
            if mutate:
                output = mutate(index, output, identity, source)
            return status, output
        stack.enter_context(mock.patch.object(G.NODE, 'run', side_effect=run))
        return calls

    def test_actual_commands_retain_image_deadlines_and_exclusive_selectors(self):
        for unit in G.UNITS:
            calls = self.peer(unit)
            with redirect_stdout(io.StringIO()):
                records = G.execute_peer(Path('/peer'), Path('/source'), {G.CASE_ENV: 'foreign', G.REFUSAL_ENV: 'foreign', 'PATH': '/captured'}, *unit)
            phases = G.unit_phases(*unit)
            self.assertEqual(len(records), len(phases))
            for (command, options), phase in zip(calls, phases):
                self.assertEqual(command, [Path('/peer'), '-test.run=' + phase['selection'], '-test.count=1', '-test.timeout=180s', '-test.v'])
                self.assertEqual(options, {'cwd': Path('/source'), 'env': {'PATH': '/captured', **phase['environment']}, 'timeout': 190})
            self.assertTrue(all(record['image_sha256'] == 'd' * 64 for record in records))

    def test_phase_process_failure_cannot_borrow_complete_output(self):
        calls = self.peer(statuses=[1] * 6)
        with redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
            G.execute_peer(Path('/peer'), Path('/source'), {}, 'wg', 'literal')
        self.assertEqual(len(calls), 1)

    def test_each_phase_refuses_missing_or_borrowed_verdict(self):
        for bad_index in range(6):
            calls = self.peer(mutate=lambda index, output, *_: 'PASS\n' if index == bad_index else output)
            with redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                G.execute_peer(Path('/peer'), Path('/source'), {}, 'wg', 'literal')
            self.assertEqual(len(calls), bad_index + 1)

    def test_source_or_image_change_cannot_finish_phase(self):
        for field in ('source', 'image'):
            def mutate(index, output, identity, source):
                if field == 'source':
                    source.return_value = (Path('/source'), {'replaced': 'f' * 64})
                else:
                    identity.return_value = ('foreign', 'f' * 64)
                return output
            calls = self.peer(mutate=mutate)
            with redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                G.execute_peer(Path('/peer'), Path('/source'), {}, 'wg', 'literal')
            self.assertEqual(len(calls), 1)

    def test_receipt_identity_scope_source_and_scalar_refusals(self):
        mutations = [('schema', True), ('schema', 1.0), ('repository', {}), ('selection', {}),
                     ('validator', {}), ('target', 'linux/arm64'), ('pins', {}),
                     ('scope', 'installed-host'), ('installed_host_accepted', True),
                     ('kernel_tun_accepted', True), ('image_sha256', 'bad'), ('source_files', {})]
        for key, value in mutations:
            receipt = self.receipt(); receipt[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.check(receipt)
        receipt = self.receipt(); receipt['source_files']['gate/' + G.GATES[0]] = 'f' * 64
        with self.assertRaises(ValueError):
            self.check(receipt)

    def test_each_receipt_phase_and_measurement_binding_is_required(self):
        for unit in G.UNITS:
            original = self.receipt(*unit)
            for index in range(len(original['phases'])):
                for change in ('omit', 'duplicate', 'image', 'output', 'foreign-leaf', 'environment'):
                    receipt = copy.deepcopy(original)
                    phase = receipt['phases'][index]
                    if change == 'omit': del receipt['phases'][index]
                    elif change == 'duplicate': receipt['phases'].append(phase)
                    elif change == 'image': phase['image_sha256'] = 'f' * 64
                    elif change == 'output': phase['output_sha256'] = ''
                    elif change == 'foreign-leaf': phase['verdicts'][-1] += '-foreign'
                    else: phase['environment'] = {}
                    with self.subTest(unit=unit, index=index, change=change), self.assertRaises(ValueError):
                        self.check(receipt)
        for key, value in (('nodes', 4.0), ('nodes', True), ('positions', [2, 3]),
                           ('positions', [False, 1]), ('samples', 49), ('samples', 50.0), ('method', 'aes-256-gcm'), ('method', G.METHODS['awg2-fast'])):
            receipt = self.receipt(); receipt['phases'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.check(receipt)

    def test_aggregate_requires_all_six_original_units_and_same_source(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(G.HOST, 'repository_identity', return_value=self.repository), mock.patch.object(G, 'published_identity', return_value=self.selection), mock.patch.object(G, 'contracts_identity', return_value=(self.sources, 'f' * 64)):
            paths = []
            for mode, form in G.UNITS:
                path = Path(directory) / (mode + '-' + form + '.json')
                path.write_text(json.dumps(self.receipt(mode, form))); paths.append(path)
            result = G.aggregate(paths, 'a' * 40, Path('/captured'), Path('/contracts.json'))
            self.assertEqual((result['phases'], result['positive_phases'], result['refusal_phases']), (42, 36, 6))
            for altered in (paths[:-1], [*paths[:-1], paths[0]]):
                with self.assertRaises(ValueError): G.aggregate(altered, 'a' * 40, Path('/captured'), Path('/contracts.json'))
            receipt = json.loads(paths[-1].read_text()); receipt['source_files'][G.NATIVE_TEMPLATE] = 'f' * 64
            paths[-1].write_text(json.dumps(receipt))
            with self.assertRaises(ValueError): G.aggregate(paths, 'a' * 40, Path('/captured'), Path('/contracts.json'))

    def test_receipt_json_duplicate_keys_nonfinite_and_symlink_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for raw in ('{"schema":1,"schema":2}', '{"nested":{"image":1,"image":2}}', '{"samples":NaN}'):
                path.write_text(raw)
                with self.subTest(raw=raw), self.assertRaises(ValueError): G.strict_receipt(path)
            path.write_text('{"schema":1}')
            alias = Path(directory) / 'alias.json'
            alias.symlink_to(path)
            with self.assertRaises(ValueError): G.strict_receipt(alias)
            self.assertEqual(G.strict_receipt(path), {'schema': 1})

    def test_original_ss_native_phases_keep_exact_commands_and_refusals(self):
        source = (ROOT / 'deploy/test_linux_node_host_tun.py').read_text()
        for function, names in ((G.ORIGINAL_SS.execute_node_chain_imported_peer, G.ORIGINAL_SS.NODE_CHAIN_IMPORTED_VERDICTS),
                                (G.ORIGINAL_SS.execute_node_chain_imported_mtu, G.ORIGINAL_SS.NODE_CHAIN_IMPORTED_MTU_VERDICTS)):
            marker = function.__name__+'(peer, source, captured)'
            self.assertEqual(source.count('= '+marker), 1)
            with mock.patch.object(G.ORIGINAL_SS.NODE, 'run', return_value=(0, passed(names))) as run, redirect_stdout(io.StringIO()):
                function(Path('/peer'), Path('/source'), {'PATH': '/original'})
            command = run.call_args.args[0]
            self.assertEqual(command[:3], ['/peer', '-test.v', '-test.timeout=90s'])
            self.assertEqual(run.call_args.kwargs, {'cwd': Path('/source'), 'env': {'PATH': '/original'}, 'timeout': 100})
            with mock.patch.object(G.ORIGINAL_SS.NODE, 'run', return_value=(0, passed(names[:-1]))), self.assertRaises(ValueError):
                function(Path('/peer'), Path('/source'), {})
            with mock.patch.object(G.ORIGINAL_SS.NODE, 'run', return_value=(1, passed(names))), self.assertRaises(ValueError):
                function(Path('/peer'), Path('/source'), {})

if __name__ == '__main__':
    unittest.main()
