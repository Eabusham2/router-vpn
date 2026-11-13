#!/usr/bin/env python3
"""Causal refusal checks for the actual Darwin ordered native host gate."""
from pathlib import Path
from types import SimpleNamespace
import importlib.util
import hashlib
import json
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ordered_native_host_gate', ROOT/'deploy/test_macos_node_chain_host.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def workflow_inventory(consumer, wrapper):
    """Bound the two small checked-in workflows without an optional YAML parser."""
    for source in (consumer, wrapper):
        if not isinstance(source, str) or len(source) > 16384 or re.search(r'^\s*(?:if|continue-on-error|inputs|workflow_run):', source, re.M):
            raise ValueError('Ordered native workflow became conditional or caller-replaceable')
        if source.count('jobs:\n') != 1 or source.count('  cancel-in-progress: true') != 1:
            raise ValueError('Ordered native workflow lost its exact job/concurrency boundary')
    if consumer.count('on:\n  workflow_call:\n') != 1 or re.search(r'^  (?:workflow_dispatch|push|pull_request):', consumer, re.M):
        raise ValueError('Ordered host consumer must use this caller run without optional inputs')
    if re.findall(r'^  ([A-Za-z][\w-]*):', consumer.split('jobs:\n')[1], re.M) != ['host']:
        raise ValueError('Ordered host consumer changed its complete job inventory')
    required = (
        '  group: darwin-node-host-tun-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}',
        '    runs-on: ${{ matrix.runner }}', '    timeout-minutes: 120', '      fail-fast: false',
        '          - arch: amd64\n            runner: macos-15-intel',
        '          - arch: arm64\n            runner: macos-15',
        '      - uses: actions/download-artifact@v4',
        '          name: RouterVPN-native-runtime-darwin-${{ matrix.arch }}-${{ github.sha }}',
        '          path: ${{ runner.temp }}/ordered-host-bundle',
        '        run: python3 deploy/test_macos_node_chain_host_runner.py',
        '        run: python3 deploy/native-runtime-bundle.py extract \'darwin/${{ matrix.arch }}\' "$RUNNER_TEMP/ordered-host-bundle/native-darwin-${{ matrix.arch }}.tar.gz" "$RUNNER_TEMP/ordered-host-verified"',
        '        timeout-minutes: 110', "          ROUTERVPN_DARWIN_NODE_CHAIN_HOST_ACCEPTANCE: '1'",
        '          ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}',
        '          ROUTERVPN_HOST_RECEIPT: ${{ runner.temp }}/darwin-node-host-${{ matrix.arch }}.json',
        "          CGO_ENABLED: '1'", '          if-no-files-found: error',
        '          name: RouterVPN-Darwin-ordered-host-${{ matrix.arch }}-${{ github.sha }}',
        '          path: ${{ runner.temp }}/darwin-node-host-${{ matrix.arch }}.json',
    )
    if any(consumer.count(value) != 1 for value in required) or len(re.findall(r'^          - arch:', consumer, re.M)) != 2:
        raise ValueError('Ordered host consumer lost an exact architecture, source or artifact boundary')
    if re.search(r'^\s*(?:run-id|repository|github-token|pattern|merge-multiple):', consumer, re.M):
        raise ValueError('Ordered host consumer borrowed another run or ambiguous bundle')
    command = 'python3 deploy/test_macos_node_chain_host.py --bundle "$RUNNER_TEMP/ordered-host-verified" --require-commit "$ROUTERVPN_EXPECTED_SOURCE" --receipt "$ROUTERVPN_HOST_RECEIPT"'
    commands = re.findall(r'^        run: \|\n((?:          [^\n]*\n)+)', consumer, re.M)
    if len(commands) != 1 or [line.strip() for line in commands[0].splitlines()] != [command]:
        raise ValueError('Ordered host consumer weakened its actual native invocation')
    if re.findall(r'^  ([A-Za-z][\w-]*):', wrapper.split('jobs:\n')[1], re.M) != ['native-runtimes', 'host', 'prefix-host']:
        raise ValueError('Ordered native wrapper changed its complete producer/consumer jobs')
    for value in ('  workflow_dispatch:', '  push:', '  pull_request:',
                  '  group: darwin-node-host-native-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}',
                  '  native-runtimes:\n    uses: ./.github/workflows/desktop-native-runtime.yml\n    with:\n      platform: darwin',
                  '  host:\n    needs: native-runtimes\n    uses: ./.github/workflows/darwin-node-host-tun.yml',
                  '  prefix-host:\n    needs: native-runtimes\n    uses: ./.github/workflows/darwin-node-prefix-host-tun.yml'):
        if wrapper.count(value) != 1:
            raise ValueError('Ordered native wrapper lost exact successful current-run producer dependency')


class OrderedNativeVerdicts(unittest.TestCase):
    def completed(self, case):
        lines = ['=== RUN   '+G.TEST, '=== RUN   '+G.TEST+'/'+case]
        if case in G.MTU_CASES:
            lines += ['    desktop_node_chain_darwin_native_test.go:701: '+G.MTU_RECEIPT]
        if case in G.MEASUREMENT_CASES:
            lines += ['    desktop_node_chain_darwin_native_test.go:702: '+G.MEASUREMENT_RECEIPT]
        lines += ['    desktop_node_chain_darwin_native_test.go:555: '+G.receipt(case),
                  '--- PASS: '+G.TEST+' (1.0s)',
                  '    --- PASS: '+G.TEST+'/'+case+' (1.0s)', 'PASS']
        return '\n'.join(lines)+'\n'

    def test_exact_source_inventory_preserves_twenty_six_paths_and_two_mtu_cases(self):
        self.assertEqual(G.case_inventory(), G.CASES)
        self.assertEqual(len(G.CASES), 28)
        self.assertEqual(len(G.MTU_CASES), 2)
        self.assertEqual(len(G.MEASUREMENT_CASES), 19)
        linux = (ROOT/'cmd/client/desktop_node_chain_linux_tun_native_test.go').read_text()
        import re
        match = re.search(r'var linuxNodeChainHostCases = \[\]string\{([^}]+)\}', linux)
        self.assertIsNotNone(match)
        original = tuple(re.findall(r'"([a-z0-9-]+)"', match[1]))
        prefixes = ('node-chain-3-', 'node-chain-3-awg-fast-wg-', 'node-chain-3-awg-strong-awg-fast-')
        selected = tuple(prefix+'prefix-candidates-'+action for prefix in prefixes for action in ('save', 'cancel'))
        complete = tuple(prefix+'candidates-'+action for prefix in prefixes for action in ('save', 'cancel'))
        self.assertEqual(original, selected + G.CASES[:-2] + complete)
        self.assertEqual(len(original), 38)

    def test_inventory_rejects_missing_duplicate_reordered_or_unparsed_cases(self):
        source = (ROOT/'cmd/client/desktop_node_chain_darwin_peer_native_test.go').read_text()
        first, second = ('"'+case+'"' for case in G.CASES[:2])
        for broken in (source.replace(first+',', '', 1), source.replace(first, first+','+first, 1),
                       source.replace(first, second, 1), source.replace(first, 'computedCase()', 1),
                       source.replace('var macOSNodeChainHostCases', 'var replaced')):
            with self.subTest(fault=broken[:80]), self.assertRaises(ValueError):
                G.case_inventory(broken)

    def test_complete_unique_execution_accepts_every_original_case(self):
        for case in G.CASES:
            G.check_verdict(self.completed(case), case)

    def test_prefix_measurement_receipt_is_required_only_after_original_native_proof(self):
        line = '    desktop_node_chain_darwin_native_test.go:702: '+G.MEASUREMENT_RECEIPT+'\n'
        for case in G.CASES:
            valid = self.completed(case)
            if case in G.MEASUREMENT_CASES:
                changed = (valid.replace(line, ''), valid.replace(line, line+line), valid.replace(line, 'diagnostic: '+line))
            else:
                changed = (valid.replace('--- PASS: '+G.TEST+' ', line+'--- PASS: '+G.TEST+' ', 1),)
            for broken in changed:
                with self.subTest(case=case), self.assertRaises(ValueError):
                    G.check_verdict(broken, case)

    def test_missing_and_duplicate_run_or_pass_cannot_claim_a_case(self):
        for case in G.CASES:
            valid = self.completed(case)
            lines = ['=== RUN   '+G.TEST+'\n', '=== RUN   '+G.TEST+'/'+case+'\n',
                     '--- PASS: '+G.TEST+' (1.0s)\n', '    --- PASS: '+G.TEST+'/'+case+' (1.0s)\n']
            for line in lines:
                for broken in (valid.replace(line, ''), valid.replace(line, line+line), valid.replace(line, 'diagnostic: '+line)):
                    with self.subTest(case=case, line=line), self.assertRaises(ValueError):
                        G.check_verdict(broken, case)

    def test_unselected_case_and_wrong_selected_verdict_are_refused(self):
        first, second = G.CASES[:2]
        valid = self.completed(first)
        for broken, selected in ((valid, second), (valid.replace(G.TEST+'/'+first, G.TEST+'/'+second), first),
                                 (valid.replace('PASS\n', '=== RUN   '+G.TEST+'/unselected\nPASS\n'), first)):
            with self.assertRaises(ValueError):
                G.check_verdict(broken, selected)
        with self.assertRaises(ValueError):
            G.check_verdict(valid, 'unknown')

    def test_ownership_receipt_is_not_a_substitute_for_execution(self):
        for case in G.CASES:
            valid = self.completed(case)
            line = '    desktop_node_chain_darwin_native_test.go:555: '+G.receipt(case)+'\n'
            for broken in (valid.replace(line, ''), valid.replace(line, line+line), valid.replace(line, 'diagnostic: '+line),
                           valid.replace('=== RUN   '+G.TEST+'/'+case+'\n', '').replace('    --- PASS: '+G.TEST+'/'+case+' (1.0s)\n', '')):
                with self.subTest(case=case), self.assertRaises(ValueError):
                    G.check_verdict(broken, case)

    def test_mtu_receipts_must_belong_to_both_original_mtu_cases(self):
        for case in G.MTU_CASES:
            valid = self.completed(case)
            line = '    desktop_node_chain_darwin_native_test.go:701: '+G.MTU_RECEIPT+'\n'
            for broken in (valid.replace(line, ''), valid.replace(line, line+line), valid.replace(line, 'diagnostic: '+line)):
                with self.subTest(case=case), self.assertRaises(ValueError):
                    G.check_verdict(broken, case)
        case = G.CASES[0]
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(case).replace('--- PASS: '+G.TEST+' ',
                '    desktop_node_chain_darwin_native_test.go:701: '+G.MTU_RECEIPT+'\n--- PASS: '+G.TEST+' ', 1), case)

    def test_failure_skip_race_panic_and_build_error_always_fail(self):
        case = G.CASES[0]
        for failure in ('--- FAIL: another (0.1s)', '--- SKIP: another (0.1s)', 'FAIL', 'SKIP',
                        'WARNING: DATA RACE', 'panic: original child lost', 'fatal error: deadlock', 'package [build failed]'):
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                G.check_verdict(failure+'\n'+self.completed(case), case)

    def test_reordered_run_pass_and_receipts_are_refused(self):
        case = G.CASES[0]
        valid = self.completed(case)
        root = '=== RUN   '+G.TEST+'\n'
        child = '=== RUN   '+G.TEST+'/'+case+'\n'
        receipt = '    desktop_node_chain_darwin_native_test.go:555: '+G.receipt(case)+'\n'
        passed = '--- PASS: '+G.TEST+' (1.0s)\n'
        for broken in (valid.replace(root+child, child+root), passed+valid.replace(passed, ''),
                       receipt+valid.replace(receipt, ''), valid.replace(child, '').replace(passed, passed+child),
                       valid.replace(receipt, '').replace(passed, passed+receipt)):
            with self.assertRaises(ValueError):
                G.check_verdict(broken, case)

    def test_missing_duplicate_or_late_package_completion_is_refused(self):
        case = G.CASES[0]
        valid = self.completed(case)
        for broken in (valid.removesuffix('PASS\n'), valid+'PASS\n', valid+'unfinished\n', 'PASS\n'+valid,
                       valid.replace('    --- PASS: '+G.TEST+'/'+case+' (1.0s)\nPASS\n', 'PASS\n    --- PASS: '+G.TEST+'/'+case+' (1.0s)\n')):
            with self.assertRaises(ValueError):
                G.check_verdict(broken, case)

    def test_explicit_disposable_opt_in_and_no_fake_benchmark(self):
        with patch.object(G.EXTERNAL, 'required_host', return_value=('darwin/arm64', 501)) as native:
            self.assertEqual(G.required_host({G.FLAG:'1'}), ('darwin/arm64', 501))
            self.assertEqual(native.call_args.args[0][G.EXTERNAL.FLAG], '1')
            for environment in ({}, {G.FLAG:'0'}, {G.FLAG:'true'}, {G.FLAG:'1','HOMEVPN_MTU_BENCH_FAKE':'0'}, {G.FLAG:'1','HOMEVPN_MTU_BENCH_FAKE':'1'}):
                with self.subTest(environment=environment), self.assertRaises(ValueError):
                    G.required_host(environment)

    def test_native_target_and_original_ordinary_uid_are_not_bypassed(self):
        with patch.object(G.EXTERNAL.platform, 'system', return_value='Linux'):
            with self.assertRaises(ValueError):
                G.required_host({G.FLAG:'1'})
        with patch.object(G.EXTERNAL.platform, 'system', return_value='Darwin'), patch.object(G.EXTERNAL.platform, 'machine', return_value='arm64'), patch.object(G.EXTERNAL.os, 'getuid', return_value=0):
            for environment in ({G.FLAG:'1'}, {G.FLAG:'1','SUDO_UID':'501','GOOS':'linux'}, {G.FLAG:'1','SUDO_UID':'501','GOARCH':'amd64'}):
                with self.assertRaises(ValueError):
                    G.required_host(environment)

    def test_complete_peer_projection_and_changed_source_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = ('one', 'two')
            for name in files:
                (root/name).write_text('captured '+name)
            copies = {f'peer-{i}.go':('original-'+str(i)).encode() for i in range(5)}
            for name, raw in copies.items():
                (root/name).write_bytes(raw)
            with patch.object(G, 'ROOT', root), patch.object(G, 'SOURCE_FILES', files), \
                 patch.object(G.EXTERNAL, 'source_identity', side_effect=lambda core: {'application':{},'peer':{}}), \
                 patch.object(G.BUILD, 'EXTERNAL', SimpleNamespace(darwin_node_chain_peer_copies=lambda:copies)):
                original = G.source_identity(root)
                self.assertEqual(len(original['peer']), 5)
                self.assertEqual(set(original['application']), set(files))
                for name in copies:
                    (root/name).write_bytes(b'replaced')
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        G.source_identity(root)
                    (root/name).write_bytes(copies[name])
                with patch.object(G.BUILD.EXTERNAL, 'darwin_node_chain_peer_copies', return_value=dict(list(copies.items())[:4])):
                    with self.assertRaises(ValueError):
                        G.source_identity(root)
                (root/'one').unlink()
                (root/'one').symlink_to(root/'two')
                with self.assertRaises(ValueError):
                    G.source_identity(root)

    def test_exact_commit_and_tree_refuse_changed_or_unpublished_inputs(self):
        commit, tree = 'a'*40, 'b'*40
        def git(args, **kwargs):
            values = {('rev-parse','HEAD'):commit, ('rev-parse','HEAD^{tree}'):tree,
                      ('diff','--quiet','HEAD','--'):'',
                      ('ls-files','--others','--exclude-standard','--','mobile','internal','deploy','cmd','configs','modes','.github','go.mod','go.sum'):''}
            return values[tuple(args[1:])]+'\n'
        with patch.object(G.subprocess, 'check_output', side_effect=git):
            self.assertEqual(G.repository_identity(commit), {'repository':'Eabusham2/router-vpn','commit':commit,'tree':tree})
            for wrong in ('abc', 'A'*40, 'c'*40, 7):
                with self.subTest(commit=wrong), self.assertRaises(ValueError):
                    G.repository_identity(wrong)
        for fault in ('tree', 'dirty', 'untracked'):
            def changed(args, **kwargs):
                if fault == 'tree' and args[1:] == ['rev-parse','HEAD^{tree}']:
                    return 'unknown\n'
                if fault == 'dirty' and args[1] == 'diff':
                    raise subprocess.CalledProcessError(1, args)
                if fault == 'untracked' and args[1] == 'ls-files':
                    return 'cmd/client/unpublished.go\n'
                return git(args, **kwargs)
            with self.subTest(fault=fault), patch.object(G.subprocess, 'check_output', side_effect=changed), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                G.repository_identity(commit)

    def test_receipt_never_overwrites_an_existing_or_symlink_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'receipt.json'
            value = {'commit':'a'*40,'cases':list(G.CASES)}
            G.write_receipt(path, value)
            self.assertEqual(json.loads(path.read_text()), value)
            with self.assertRaises(ValueError):
                G.write_receipt(path, {'replaced':True})
            alias = path.with_name('alias.json')
            alias.symlink_to(path)
            with self.assertRaises(ValueError):
                G.write_receipt(alias, value)
            self.assertEqual(json.loads(path.read_text()), value)


class ImportedSourceAuthority(unittest.TestCase):
    def completed(self):
        return '\n'.join(['=== RUN   '+name for name in G.AUTHORITY_CASES] +
                         [('    ' if '/' in name else '')+'--- PASS: '+name+' (0.01s)' for name in G.AUTHORITY_CASES] + ['PASS', ''])

    def test_original_root_and_every_entry_mode_require_actual_unique_verdicts(self):
        valid = self.completed()
        G.check_authority_verdict(valid)
        self.assertEqual(G.AUTHORITY_CASES, (G.AUTHORITY_TEST, *(G.AUTHORITY_TEST+'/'+name for name in
            ('custom-wg', 'custom-awg-fast', 'custom-awg-strong'))))
        for name in G.AUTHORITY_CASES:
            run = '=== RUN   '+name+'\n'
            passed = ('    ' if '/' in name else '')+'--- PASS: '+name+' (0.01s)\n'
            for changed in (valid.replace(run, ''), valid.replace(passed, ''), valid.replace(run, run+run),
                            valid.replace(passed, passed+passed), valid.replace(name, 'TestForeignAuthority')):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    G.check_authority_verdict(changed)
        for changed in (valid+'PASS\n', valid.removesuffix('PASS\n'), 'PASS\n'+valid, valid+'unfinished\n',
                        valid.replace('--- PASS:', '--- SKIP:', 1), valid.replace('--- PASS:', '--- FAIL:', 1),
                        'WARNING: DATA RACE\n'+valid, 'panic: stopped\n'+valid):
            with self.assertRaises(ValueError):
                G.check_authority_verdict(changed)

    def test_actual_gate_requires_authority_before_all_native_cases(self):
        for fault in ('success', 'missing-child', 'wrong-root', 'failed', 'timeout', 'changed-image'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bundle = root/'bundle'
                bundle.mkdir()
                (bundle/'NATIVE-RUNTIME.json').write_bytes(b'original delivered bundle')
                authority_calls, native_calls = [], []
                output = self.completed()
                def run(command, **options):
                    if '-o' in command:
                        Path(command[command.index('-o')+1]).write_bytes(b'original captured native image')
                    if any(str(arg).startswith('-test.list=') for arg in command):
                        return SimpleNamespace(returncode=0, stdout=G.TEST+'\n')
                    if any(str(arg).startswith('-test.run=') for arg in command):
                        self.assertEqual(command[1:], ['-test.v', '-test.count=1', '-test.timeout=30s', '-test.run=^'+G.AUTHORITY_TEST+'$'])
                        self.assertEqual(options['timeout'], 40)
                        self.assertTrue(options['check'])
                        self.assertEqual(options['env']['CAPTURED_ENV'], '1')
                        self.assertEqual(native_calls, [])
                        authority_calls.append(Path(command[0]))
                        if fault == 'failed':
                            raise subprocess.CalledProcessError(1, command, output='actual authority failure')
                        if fault == 'timeout':
                            raise subprocess.TimeoutExpired(command, 40)
                        actual = output
                        if fault == 'missing-child':
                            actual = actual.replace('    --- PASS: '+G.AUTHORITY_CASES[-1]+' (0.01s)\n', '')
                        if fault == 'wrong-root':
                            actual = actual.replace(G.AUTHORITY_TEST, 'TestForeignSourceAuthority')
                        if fault == 'changed-image':
                            Path(command[0]).write_bytes(b'replaced native image')
                        return SimpleNamespace(returncode=0, stdout=actual)
                    return SimpleNamespace(returncode=0, stdout='')
                def native(command, **options):
                    self.assertEqual(len(authority_calls), 1)
                    self.assertIn(str(authority_calls[0]), command)
                    case = command[command.index('-test.v')-1].removeprefix('-test.run=^'+G.TEST+'$/^').removesuffix('$')
                    native_calls.append(case)
                    return OrderedNativeVerdicts().completed(case)
                with patch.object(G, 'required_host', return_value=('darwin/arm64', 501)), \
                     patch.object(G.CONTROLLER.UID, 'compiler_toolchain', return_value=(Path('captured-go'), {'CAPTURED_ENV':'1'})), \
                     patch.object(G.CONTROLLER.UID, 'privilege_tool', return_value=None), \
                     patch.object(G.CONTROLLER, 'discover_python', return_value='/usr/bin/python3'), \
                     patch.object(G.BUILD, 'reuse', return_value={'original':True}), \
                     patch.object(G.BUILD, 'digest', return_value='a'*64), \
                     patch.object(G, 'source_identity', return_value={'application':{'owned':'b'*64}, 'peer':{'original':'c'*64}}), \
                     patch.object(G.subprocess, 'run', side_effect=run), \
                     patch.object(G.CONTROLLER, 'reported_run', side_effect=native), patch('builtins.print'):
                    if fault == 'success':
                        receipt = G.execute(bundle, source=root/'core')
                        self.assertEqual(receipt['authority_cases'], list(G.AUTHORITY_CASES))
                        self.assertEqual(receipt['authority_output_sha256'], hashlib.sha256(output.encode()).hexdigest())
                        self.assertEqual(native_calls, list(G.CASES))
                    else:
                        with self.assertRaises((ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired)):
                            G.execute(bundle, source=root/'core')
                        self.assertEqual(native_calls, [])
                self.assertEqual(len(authority_calls), 1)


class OrderedNativeWorkflows(unittest.TestCase):
    def setUp(self):
        self.consumer = (ROOT/'.github/workflows/darwin-node-host-tun.yml').read_text()
        self.wrapper = (ROOT/'.github/workflows/darwin-node-host-native.yml').read_text()

    def test_both_native_architectures_consume_only_this_run_complete_bundles(self):
        workflow_inventory(self.consumer, self.wrapper)

    def test_missing_architecture_or_cross_run_bundle_never_satisfies_gate(self):
        changes = (
            ('          - arch: amd64\n            runner: macos-15-intel\n', ''),
            ('          - arch: arm64\n            runner: macos-15\n', ''),
            ('runner: macos-15-intel', 'runner: ubuntu-latest'),
            ('      fail-fast: false', '      fail-fast: true'),
            ('  host:\n', '  host:\n    if: false\n'),
            ('  host:\n', '  host:\n    continue-on-error: true\n'),
            ('  workflow_call:\n', '  workflow_call:\n    inputs:\n'),
            ('-${{ github.sha }}-${{ github.run_id }}', ''),
            ('          name: RouterVPN-native-runtime-darwin-${{ matrix.arch }}-${{ github.sha }}', '          name: RouterVPN-native-runtime-darwin-${{ matrix.arch }}-other'),
            ('          path: ${{ runner.temp }}/ordered-host-bundle', '          run-id: 123\n          path: ${{ runner.temp }}/ordered-host-bundle'),
            ('          path: ${{ runner.temp }}/ordered-host-bundle', '          repository: different/source\n          path: ${{ runner.temp }}/ordered-host-bundle'),
            (' --require-commit "$ROUTERVPN_EXPECTED_SOURCE"', ''),
            (' --receipt "$ROUTERVPN_HOST_RECEIPT"', ''),
            (' --receipt "$ROUTERVPN_HOST_RECEIPT"', ' --receipt "$ROUTERVPN_HOST_RECEIPT" || true'),
            ('          if-no-files-found: error', '          if-no-files-found: warn'),
        )
        for before, after in changes:
            self.assertEqual(self.consumer.count(before), 1)
            with self.subTest(change=before), self.assertRaises(ValueError):
                workflow_inventory(self.consumer.replace(before, after, 1), self.wrapper)

    def test_standalone_wrapper_cannot_skip_or_borrow_runtime_producer(self):
        for before, after in (
                ('  host:\n    needs: native-runtimes', '  host:\n    needs: []'),
                ('  prefix-host:\n    needs: native-runtimes', '  prefix-host:\n    needs: []'),
                ('      platform: darwin', '      platform: linux'),
                ('  host:\n', '  host:\n    if: false\n'),
                ('  native-runtimes:\n', '  native-runtimes:\n    continue-on-error: true\n'),
                ('./.github/workflows/desktop-native-runtime.yml', './.github/workflows/darwin-node-child-tun.yml'),
                ('-${{ github.sha }}-${{ github.run_id }}', ''),
                ('  workflow_dispatch:\n', '')):
            self.assertEqual(self.wrapper.count(before), 1)
            with self.subTest(change=before), self.assertRaises(ValueError):
                workflow_inventory(self.consumer, self.wrapper.replace(before, after, 1))


if __name__ == '__main__':
    unittest.main(verbosity=2)
