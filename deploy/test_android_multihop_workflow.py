#!/usr/bin/env python3
"""Preserve every Android multihop gate across bounded jobs and their aggregate."""
from collections import Counter
from itertools import product
from pathlib import Path
import ast
import os
import re
import subprocess
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/android-multihop-contract.yml'
RUNTIME = WORKFLOW.parents[2] / 'android/test_android_runtime_contract.py'
ANDROID = tuple('python3 android/test_android_' + name + '.py' for name in (
    'multihop_contract', 'node_chain_capture', 'node_chain_execution_capture', 'connect_execution_capture', 'connect_execution_layers', 'connect_execution_layers_extended', 'socks_execution_capture', 'openvpn_execution_capture', 'openvpn_execution_runtime', 'imported_prefix_execution_capture', 'multiple_imported_local', 'connect_execution_runtime', 'socks_execution_runtime', 'node_candidates', 'node_layered_candidates', 'typed_connected_candidates', 'typed_connected_candidate_host', 'execution_entry_candidates', 'selected_draft_candidates', 'node_connect_candidates', 'node_socks_candidates', 'node_candidate_profile', 'node_candidate_prefix_capture', 'node_candidate_prefix_host', 'node_candidate_prefix_owner', 'ordered_presentation', 'control_row', 'ordered_candidate_picker',
    'node_chain_runtime', 'node_chain_openvpn_runtime', 'node_chain_imported_runtime', 'node_chain_socks_runtime', 'node_chain_connect_runtime', 'ordered_latency', 'ordinary_ordered_latency', 'connect_ordered_latency', 'execution_ordered_latency', 'execution_ordered_latency_data', 'ordered_history_source_transaction', 'node_candidate_preparation', 'node_candidate_preparation_owner', 'node_candidate_preparation_ui', 'node_chain_execution_runtime', 'node_chain_execution_restore', 'node_chain_mtu', 'multihop_modes', 'home_dns',
    'router_dns_retest', 'multihop_graph', 'pq_selection', 'max_selection',
    'naive_multihop',
))
ANDROID_GROUPS = {
    'android': ('multihop_contract', 'ordered_presentation', 'control_row', 'ordered_candidate_picker', 'multihop_modes', 'home_dns', 'router_dns_retest', 'multihop_graph', 'pq_selection', 'max_selection', 'naive_multihop'),
    'android_ordered_source': ('node_chain_capture',),
    'android_execution_source': ('node_chain_execution_capture',),
    'android_connect_source': ('connect_execution_capture',),
    'android_connect_final_layers': ('connect_execution_layers',),
    'android_connect_final_layers_extended': ('connect_execution_layers_extended',),
    'android_socks_source': ('socks_execution_capture',),
    'android_openvpn_source': ('openvpn_execution_capture',),
    'android_openvpn_host': ('openvpn_execution_runtime',),
    'android_imported_source': ('imported_prefix_execution_capture',),
    'android_multiple_imported': ('multiple_imported_local',),
    'android_candidates': ('node_candidates', 'node_connect_candidates', 'node_socks_candidates', 'node_candidate_profile', 'node_candidate_prefix_capture', 'node_candidate_prefix_host', 'node_candidate_prefix_owner', 'node_candidate_preparation', 'node_candidate_preparation_owner', 'node_candidate_preparation_ui'),
    'android_layered_candidates': ('node_layered_candidates',),
    'android_typed_connected_candidates': ('typed_connected_candidates', 'typed_connected_candidate_host', 'execution_entry_candidates', 'selected_draft_candidates'),
    'android_hosts': ('connect_execution_runtime', 'socks_execution_runtime', 'node_chain_runtime', 'node_chain_openvpn_runtime', 'node_chain_imported_runtime', 'node_chain_socks_runtime', 'node_chain_connect_runtime', 'node_chain_execution_runtime', 'node_chain_execution_restore', 'node_chain_mtu'),
    'android_latency': ('ordered_latency', 'ordinary_ordered_latency', 'connect_ordered_latency', 'execution_ordered_latency', 'execution_ordered_latency_data', 'ordered_history_source_transaction'),
}
ANDROID_GROUPS = {name: tuple("python3 android/test_android_" + gate + ".py" for gate in gates)
                  for name, gates in ANDROID_GROUPS.items()}
assert Counter(command for gates in ANDROID_GROUPS.values() for command in gates) == Counter(ANDROID)
LEGACY_RESULTS = ("android", "shared_core", "shared_runtime", "shared_fifty", "shared_fifty_closed", "shared_imported_prefix", "relay")
EXPECTED = {
    **ANDROID_GROUPS,
    'android': ANDROID_GROUPS['android'] + ('python3 deploy/test_android_multihop_workflow.py',),
    'shared_core': ('python3 deploy/test_mobile_multihop_groups.py --group core',),
    'shared_runtime': ('python3 deploy/test_mobile_multihop_groups.py --group runtime',),
    'shared_fifty': ('python3 deploy/test_mobile_multihop_groups.py --group fifty',),
    'shared_fifty_closed': ('python3 deploy/test_mobile_multihop_groups.py --group fifty_closed',),
    'shared_imported_prefix': ('python3 deploy/test_mobile_multihop_groups.py --group imported_prefix',),
    'relay': ('go test -race -count=1 -timeout=5m ./internal/multihoprelay ./internal/awgpolicy',),
}



def validate_connect_layer_partitions(source):
    tree=ast.parse(source)
    values={}
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ('FINAL_LAYER_PHASES','FINAL_LAYER_EXTENDED_PHASES'):
            values[node.targets[0].id]=eval(compile(ast.Expression(node.value),'<phase inventory>','eval'),{'__builtins__':{},'tuple':tuple,'range':range})
    expected={
        'FINAL_LAYER_PHASES':tuple(f'layers-{count}-{mode}' for count in (3,4,5) for mode in ('server','auto'))+('layers-invalid-http',),
        'FINAL_LAYER_EXTENDED_PHASES':tuple(f'layers-{count}-{mode}' for count in (6,7,8) for mode in ('server','auto'))+('layers-invalid-https',),
    }
    assert values==expected,'Complete CONNECT layer phase union changed'
    assert len(set(values['FINAL_LAYER_PHASES'])|set(values['FINAL_LAYER_EXTENDED_PHASES']))==14,'Missing or duplicate layer phase'
    prepared=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='run_prepared')
    loop=next(node for node in prepared.body if isinstance(node,ast.For) and isinstance(node.target,ast.Name) and node.target.id=='phase')
    required=ast.parse('for phase in phases:\n subprocess.run([*command,phase],env=env,check=True,timeout=120)').body[0]
    assert ast.dump(loop)==ast.dump(required),'Layer phase lost mandatory bounded execution'
    controls=next(node for node in prepared.body if isinstance(node,ast.If) and ast.dump(node.test)==ast.dump(ast.parse('family=="final-layers"',mode='eval').body))
    assert ast.dump(controls.body[0])==ast.dump(ast.parse('run_final_layer_controls(work,app,classes,jar,env,data)').body[0]),'Final-layer causal dispatcher omitted'
    causal=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='run_final_layer_controls')
    entries=next(node for node in causal.body if isinstance(node,ast.For)).iter
    assert isinstance(entries,ast.Tuple) and [entry.elts[0].value for entry in entries.elts]==['editor-final-off','preview-final-off','capture-final-off'],'Original Off restriction controls missing'
    assert 'if(ui.message.equals("old Off-only editor"))throw new AssertionError("CONNECT public editor refused selected final Start Layer")' in source,'Early causal UI refusal lost its exact injected message'
    run=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='run')
    assert ast.dump(run.body[-1])==ast.dump(ast.parse('run_prepared(work,app,classes,jar,env,family)').body[0]),'Prepared source phase dispatcher omitted'
    assert any(isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Attribute) and node.value.func.attr=='run' and any(kw.arg=='timeout' and isinstance(kw.value,ast.Constant) and kw.value.value==180 for kw in node.value.keywords) for node in run.body),'Original actual Go generator omitted'


def validate_runtime(source):
    loops = [node for node in ast.parse(source).body
             if isinstance(node, ast.For) and isinstance(node.target, ast.Name)
             and node.target.id == 'executable_contract']
    assert len(loops) == 1 and isinstance(loops[0].iter, ast.Tuple), 'Runtime gate loop missing'
    values = [node.value for node in loops[0].iter.elts if isinstance(node, ast.Constant)]
    assert len(values) == len(loops[0].iter.elts), 'Runtime gate inventory is not literal'
    assert values.count('test_android_control_row.py') == 1, 'Runtime adaptive control gate missing/duplicate'
    assert values.count('test_android_ordered_candidate_picker.py') == 1, 'Runtime ordered picker gate missing/duplicate'
    assert values.count('test_android_ordered_latency.py') == 1, 'Runtime ordered fifty caller gate missing/duplicate'
    assert values.count('test_android_ordinary_ordered_latency.py') == 1, 'Runtime ordinary fifty caller gate missing/duplicate'
    assert values.count('test_android_connect_ordered_latency.py') == 1, 'Runtime CONNECT fifty caller gate missing/duplicate'
    assert values.count('test_android_execution_ordered_latency.py') == 1, 'Runtime execution fifty host gate missing/duplicate'
    assert values.count('test_android_execution_ordered_latency_data.py') == 1, 'Runtime execution fifty data gate missing/duplicate'
    assert values.count('test_android_ordered_history_source_transaction.py') == 1, 'Runtime original history source transaction gate missing/duplicate'
    assert values.count('test_android_node_chain_connect_runtime.py') == 1, 'Runtime typed CONNECT host gate missing/duplicate'
    assert values.count('test_android_node_chain_openvpn_runtime.py') == 1, 'Runtime OpenVPN middle host gate missing/duplicate'
    assert values.count('test_android_node_chain_imported_runtime.py') == 1, 'Runtime imported SS host gate missing/duplicate'
    assert values.count('test_android_node_chain_socks_runtime.py') == 1, 'Runtime typed SOCKS host gate missing/duplicate'
    assert values.count('test_android_node_chain_execution_capture.py') == 1, 'Runtime execution capture gate missing/duplicate'
    assert values.count('test_android_connect_execution_capture.py') == 1, 'Runtime CONNECT execution source gate missing/duplicate'
    assert values.count('test_android_connect_execution_layers.py') == 1, 'Runtime CONNECT final-layer source gate missing/duplicate'
    assert values.count('test_android_connect_execution_layers_extended.py') == 1, 'Runtime CONNECT extended final-layer source gate missing/duplicate'
    assert values.count('test_android_connect_execution_runtime.py') == 1, 'Runtime CONNECT execution host gate missing/duplicate'
    assert values.count('test_android_socks_execution_capture.py') == 1, 'Runtime SOCKS execution source gate missing/duplicate'
    assert values.count('test_android_openvpn_execution_capture.py') == 1, 'Runtime OpenVPN execution source gate missing/duplicate'
    assert values.count('test_android_openvpn_execution_runtime.py') == 1, 'Runtime OpenVPN execution host gate missing/duplicate'
    assert values.count('test_android_imported_prefix_execution_capture.py') == 1, 'Runtime imported prefix execution source gate missing/duplicate'
    assert values.count('test_android_multiple_imported_local.py') == 1, 'Runtime independent imported Local gate missing/duplicate'
    assert values.count('test_android_socks_execution_runtime.py') == 1, 'Runtime SOCKS execution host gate missing/duplicate'
    assert values.count('test_android_node_candidate_preparation.py') == 1, 'Runtime temporary preparation gate missing/duplicate'
    assert values.count('test_android_node_candidate_profile.py') == 1, 'Runtime detached candidate profile gate missing/duplicate'
    assert values.count('test_android_node_connect_candidates.py') == 1, 'Runtime CONNECT candidate gate missing/duplicate'
    assert values.count('test_android_node_socks_candidates.py') == 1, 'Runtime SOCKS candidate gate missing/duplicate'
    assert values.count('test_android_typed_connected_candidates.py') == 1, 'Runtime typed connected source gate missing/duplicate'
    assert values.count('test_android_typed_connected_candidate_host.py') == 1, 'Runtime typed connected host gate missing/duplicate'
    assert values.count('test_android_selected_draft_candidates.py') == 1, 'Runtime selected draft candidate gate missing/duplicate'
    assert values.count('test_android_execution_entry_candidates.py') == 1, 'Runtime selected execution entry gate missing/duplicate'
    assert values.count('test_android_node_candidate_prefix_capture.py') == 1, 'Runtime independent prefix capture gate missing/duplicate'
    assert values.count('test_android_node_candidate_prefix_host.py') == 1, 'Runtime actual prefix host gate missing/duplicate'
    assert values.count('test_android_node_candidate_prefix_owner.py') == 1, 'Runtime actual prefix supervisor gate missing/duplicate'
    assert values.count('test_android_node_candidate_preparation_owner.py') == 1, 'Runtime temporary candidate owner gate missing/duplicate'
    assert values.count('test_android_node_candidate_preparation_ui.py') == 1, 'Runtime temporary candidate UI gate missing/duplicate'
    expected = ast.parse('subprocess.run([sys.executable, str(ROOT / executable_contract)], cwd=ROOT.parent, check=True)').body
    assert not loops[0].orelse and len(loops[0].body) == 1, 'Runtime gate can be conditionally skipped'
    assert ast.dump(loops[0].body[0]) == ast.dump(expected[0]), 'Runtime gate no longer executes its exact checked script'


def validate(source):
    # This intentionally checks this workflow's simple explicit jobs; introducing
    # matrix/conditional execution requires updating this executable contract.
    jobs_text = source.split('\njobs:\n', 1)[1]
    matches = list(re.finditer(r'^  ([a-z_]+):\n', jobs_text, re.M))
    jobs = {m[1]: jobs_text[m.end():matches[i + 1].start() if i + 1 < len(matches) else len(jobs_text)]
            for i, m in enumerate(matches)}
    assert len(matches) == len(EXPECTED) + 1 and set(jobs) == {*EXPECTED, 'contract'}, 'Missing/duplicate job'
    assert source.count("- 'deploy/test_android_multihop_workflow.py'") == 2, 'Audit trigger missing'
    assert source.count("- 'deploy/test_focused_multihop_clocks.py'") == 2, 'Prefix verdict parser trigger missing'
    for path in ('android/test_android_control_row.py', 'android/test_android_ordered_candidate_picker.py', 'android/app/src/main/java/com/eabusham/routervpn/AndroidControlRow.java', 'android/app/src/main/java/com/eabusham/routervpn/AndroidOrderedCandidatePicker.java', 'android/app/src/main/java/com/eabusham/routervpn/AndroidOrderedPathSelection.java', 'android/test_android_multiple_imported_local.py', 'android/typed_candidate_fixture_boundary.py', 'android/test_android_typed_candidate_abi.py', 'android/test_android_typed_connected_candidates.py', 'android/test_android_typed_connected_candidate_host.py', 'android/test_android_execution_entry_candidates.py', 'android/test_android_selected_draft_candidates.py', 'android/test_android_imported_prefix_execution_capture.py', 'android/test_android_socks_execution_capture.py', 'android/test_android_openvpn_execution_capture.py', 'android/test_android_openvpn_execution_runtime.py', 'android/test_android_socks_execution_runtime.py', 'android/test_android_connect_execution_capture.py', 'android/test_android_connect_execution_layers.py', 'android/test_android_connect_execution_layers_extended.py', 'android/test_android_connect_execution_runtime.py', 'android/test_android_node_chain_openvpn_runtime.py', 'android/test_android_node_chain_imported_runtime.py', 'android/test_android_ordered_history_source_transaction.py', 'android/app/src/main/java/com/eabusham/routervpn/AndroidOrderedLatencySourceTransaction.java', 'android/test_android_execution_ordered_latency.py', 'android/test_android_execution_ordered_latency_data.py', 'android/app/src/main/java/com/eabusham/routervpn/AndroidOrderedExecutionLatencyCapture.java', 'android/app/src/main/java/com/eabusham/routervpn/AndroidOrderedExecutionLatencyStore.java', 'android/test_android_connect_ordered_latency.py', 'android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainCONNECTCapture.java', 'android/test_android_node_chain_connect_runtime.py', 'android/test_android_ordered_latency.py', 'android/test_android_ordinary_ordered_latency.py', 'android/app/src/main/java/com/eabusham/routervpn/AndroidOrderedLatencyBenchmark.java', 'android/app/src/main/java/com/eabusham/routervpn/AndroidOrderedLatencyStore.java', 'android/app/src/main/java/com/eabusham/routervpn/AndroidOrderedLatencyDialog.java', 'android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java', 'android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainSOCKSCapture.java', 'android/test_android_node_chain_socks_runtime.py', 'android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainExecutionCapture.java', 'android/test_android_node_chain_execution_capture.py', 'android/test_android_node_candidate_preparation.py', 'android/test_android_node_candidate_preparation_owner.py', 'android/test_android_node_candidate_preparation_ui.py', 'android/test_android_node_candidate_profile.py', 'android/test_android_node_connect_candidates.py', 'android/test_android_node_socks_candidates.py', 'android/test_android_node_candidate_prefix_capture.py', 'android/test_android_node_candidate_prefix_host.py', 'android/test_android_node_candidate_prefix_owner.py', 'android/app/src/main/java/com/eabusham/routervpn/AndroidNodeCandidatePrefixCapture.java', 'android/test_android_runtime_contract.py'):
        assert source.count("- '" + path + "'") == 2, 'Execution capture source/test trigger missing'
    for name, expected in EXPECTED.items():
        body = jobs[name]
        assert '    timeout-minutes: ' + ('35' if name == 'shared_imported_prefix' else '15') + '\n' in body, 'Job deadline changed'
        assert 'if:' not in body and 'continue-on-error:' not in body and 'strategy:' not in body, 'Gate can be skipped'
        assert "with: {go-version: '1.26.3', cache: false}" in body, 'Actual pinned Go toolchain missing'
        if name in ANDROID_GROUPS:
            assert 'uses: actions/setup-java@v5' in body and "java-version: '17'" in body, 'Actual pinned Java toolchain missing'
            assert 'sudo apt-get install -y -qq libandroid-json-java' in body, 'Actual Android JSON dependency missing'
        commands = []
        for line in body.splitlines():
            command = line.strip().removeprefix('run: ')
            if command.startswith(('python3 ', 'go test ')):
                commands.append(command)
        assert Counter(commands) == Counter(expected), 'Missing/duplicate/changed command in ' + name
    contract = jobs['contract']
    assert '    if: ${{ always() }}\n' in contract, 'Aggregate skips failed dependencies'
    assert '    needs: [android, android_ordered_source, android_execution_source, android_connect_source, android_connect_final_layers, android_connect_final_layers_extended, android_socks_source, android_openvpn_source, android_openvpn_host, android_imported_source, android_multiple_imported, android_candidates, android_layered_candidates, android_typed_connected_candidates, android_hosts, android_latency, shared_core, shared_runtime, shared_fifty, shared_fifty_closed, shared_imported_prefix, relay]\n' in contract, 'Aggregate dependency missing'
    assert 'continue-on-error:' not in contract, 'Aggregate failure ignored'
    for name in EXPECTED:
        assert f'          {name.upper()}_RESULT: ${{{{ needs.{name}.result }}}}\n' in contract, 'Result binding changed'
    script = contract.split('        run: |\n', 1)[1]
    script = '\n'.join(line[10:] for line in script.splitlines() if line.strip())
    assert script.splitlines() == [f'test "${name.upper()}_RESULT" = success' for name in EXPECTED], 'Aggregate must check every exact result once'
    return script


def validate_ios_openvpn_source_gate(source):
    loops = [node for node in ast.walk(ast.parse(source))
             if isinstance(node, ast.For) and isinstance(node.target, ast.Name)
             and node.target.id == 'external_test']
    assert len(loops) == 1 and isinstance(loops[0].iter, ast.Tuple), 'Apple source gate inventory missing'
    values = [node.value for node in loops[0].iter.elts if isinstance(node, ast.Constant)]
    assert values.count('test_ios_node_chain_openvpn_capture.py') == 1, 'Apple OpenVPN middle source gate missing/duplicate'
    assert values.count('test_ios_node_chain_openvpn_profiles.py') == 1, 'Apple OpenVPN middle profile gate missing/duplicate'
    assert values.count('test_ios_node_chain_imported_capture.py') == 1, 'Apple imported SS capture gate missing/duplicate'
    assert values.count('test_ios_node_chain_imported_profiles.py') == 1, 'Apple imported SS profile gate missing/duplicate'


class WorkflowContract(unittest.TestCase):
    def test_ios_openvpn_source_gate_and_omission(self):
        source = (WORKFLOW.parents[2] / 'ios/RouterVPN/test_runtime_selection_contract.py').read_text()
        validate_ios_openvpn_source_gate(source)
        for gate in ('test_ios_node_chain_openvpn_capture.py', 'test_ios_node_chain_openvpn_profiles.py', 'test_ios_node_chain_imported_capture.py', 'test_ios_node_chain_imported_profiles.py'):
            with self.assertRaises(AssertionError):
                validate_ios_openvpn_source_gate(source.replace("'"+gate+"',", "", 1))

    def setUp(self):
        self.source = WORKFLOW.read_text()

    def test_imported_prefix_job_and_failure_propagation_are_mandatory(self):
        begin = self.source.index('  shared_imported_prefix:\n')
        end = self.source.index('  shared_runtime:\n', begin)
        block = self.source[begin:end]
        self.assertEqual(300 + 6 * 240 + 360, 35 * 60)
        for replacement in ('', block + block,
                block.replace('timeout-minutes: 35', 'timeout-minutes: 15'),
                block.replace('--group imported_prefix', '--group core'),
                block.replace('  shared_imported_prefix:\n', '  shared_imported_prefix:\n    if: false\n'),
                block.replace('  shared_imported_prefix:\n', '  shared_imported_prefix:\n    continue-on-error: true\n')):
            with self.subTest(replacement=replacement), self.assertRaises(AssertionError):
                validate(self.source[:begin] + replacement + self.source[end:])
        for before, after in (
                (', shared_imported_prefix, relay]', ', relay]'),
                ('SHARED_IMPORTED_PREFIX_RESULT: ${{ needs.shared_imported_prefix.result }}', 'SHARED_IMPORTED_PREFIX_RESULT: success'),
                ("- 'deploy/test_focused_multihop_clocks.py'", "- 'deploy/omitted-parser.py'")):
            with self.assertRaises(AssertionError): validate(self.source.replace(before, after, 1))
        script = validate(self.source)
        for result in ('failure', 'cancelled', 'skipped', ''):
            env = dict(os.environ, **{name.upper() + '_RESULT': 'success' for name in EXPECTED})
            env['SHARED_IMPORTED_PREFIX_RESULT'] = result
            self.assertNotEqual(subprocess.run(['bash', '-e', '-c', script], env=env, timeout=5).returncode, 0)
        bypass = script.replace('test "$SHARED_IMPORTED_PREFIX_RESULT" = success', 'true')
        self.assertNotEqual(script, bypass)
        self.assertEqual(subprocess.run(['bash', '-e', '-c', bypass], env=env, timeout=5).returncode, 0)

    def test_connect_final_layer_partition_inventory(self):
        source=(WORKFLOW.parents[2]/'android/test_android_connect_execution_capture.py').read_text()
        validate_connect_layer_partitions(source)
        for before,after in (('range(3,6)','range(3,5)'),('range(6,9)','range(6,8)'),('"layers-invalid-http"','"layers-invalid-https"'),('timeout=120','timeout=240'),('"capture-final-off"','"omitted-final-off"'),('run_prepared(work,app,classes,jar,env,family)','None'),('run_final_layer_controls(work,app,classes,jar,env,data)','None'),('if(ui.message.equals("old Off-only editor"))','if(!ui.message.isEmpty())')):
            with self.subTest(before=before),self.assertRaises((AssertionError,StopIteration)):
                validate_connect_layer_partitions(source.replace(before,after,1))

    def test_complete_inventory(self):
        validate(self.source)

    def test_android_source_shards_retain_every_original_command_and_result(self):
        # Include the adaptive row, ordered picker and selected draft candidate flows.
        self.assertEqual(len(ANDROID), 52)
        self.assertEqual(Counter(command for gates in ANDROID_GROUPS.values() for command in gates), Counter(ANDROID))
        for command in ANDROID:
            for replacement in ('# omitted required source gate', command + '\n          ' + command):
                with self.subTest(command=command), self.assertRaises(AssertionError):
                    validate(self.source.replace(command, replacement, 1))
        script = validate(self.source)
        for name in ANDROID_GROUPS:
            begin = self.source.index('  ' + name + ':\n', self.source.index('\njobs:\n'))
            # Find the next complete job, never an indented step.
            following = re.search(r'^  [a-z_]+:\n', self.source[begin + len('  ' + name + ':\n'):], re.M)
            self.assertIsNotNone(following)
            end = begin + len('  ' + name + ':\n') + following.start()
            block = self.source[begin:end]
            for replacement in ('', block + block,
                    block.replace('timeout-minutes: 15', 'timeout-minutes: 30'),
                    block.replace('runs-on: ubuntu-latest', 'if: false\n    runs-on: ubuntu-latest'),
                    block.replace('runs-on: ubuntu-latest', 'continue-on-error: true\n    runs-on: ubuntu-latest'),
                    block.replace("java-version: '17'", "java-version: '21'"),
                    block.replace('libandroid-json-java', 'omitted-json-package')):
                with self.subTest(job=name, replacement=replacement), self.assertRaises(AssertionError):
                    validate(self.source[:begin] + replacement + self.source[end:])
            binding = name.upper() + '_RESULT: ${{ needs.' + name + '.result }}'
            with self.assertRaises(AssertionError):
                validate(self.source.replace(binding, name.upper() + '_RESULT: success'))
            check = 'test "$' + name.upper() + '_RESULT" = success'
            for replacement in ('true', '', check + ' || true', check + '\n          ' + check):
                with self.assertRaises(AssertionError):
                    validate(self.source.replace(check, replacement))
            for result in ('failure', 'cancelled', 'skipped', ''):
                env = dict(os.environ, **{job.upper() + '_RESULT': 'success' for job in EXPECTED})
                env[name.upper() + '_RESULT'] = result
                with self.subTest(job=name, result=result):
                    self.assertNotEqual(subprocess.run(['bash', '-e', '-c', script], env=env, timeout=5).returncode, 0)
                # Removing this one actual predicate would hide that failure.
                self.assertEqual(subprocess.run(['bash', '-e', '-c', script.replace(check, 'true')], env=env, timeout=5).returncode, 0)

    def test_runtime_execution_capture_gate(self):
        validate_runtime(RUNTIME.read_text())

    def test_runtime_execution_capture_controls(self):
        source = RUNTIME.read_text()
        gate = '    "test_android_node_chain_execution_capture.py",'
        for old, new in ((gate, ''), (gate, gate + '\n' + gate),
                         ('    subprocess.run(\n', '    ignored.run(\n'),
                         ('        check=True,\n', '        check=False,\n')):
            with self.subTest(change=old):
                self.assertEqual(source.count(old), 1)
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(old, new, 1))

    def test_runtime_openvpn_execution_controls(self):
        source = RUNTIME.read_text()
        for name in ('capture', 'runtime'):
            gate = '"test_android_openvpn_execution_' + name + '.py",'
            self.assertEqual(source.count(gate), 1)
            for replacement in ('', gate + gate):
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement))

    def test_runtime_connect_execution_controls(self):
        source = RUNTIME.read_text()
        for name in ('capture', 'layers', 'layers_extended', 'runtime'):
            gate = '"test_android_connect_execution_' + name + '.py",'
            self.assertEqual(source.count(gate), 1)
            for replacement in ('', gate + gate):
                with self.subTest(name=name, replacement=replacement):
                    with self.assertRaises(AssertionError):
                        validate_runtime(source.replace(gate, replacement))

    def test_connect_execution_workflow_controls(self):
        validate(self.source)
        for name in ('capture', 'layers', 'layers_extended', 'runtime'):
            command = 'python3 android/test_android_connect_execution_' + name + '.py'
            trigger = "- 'android/test_android_connect_execution_" + name + ".py'"
            self.assertEqual(self.source.count(command), 1)
            self.assertEqual(self.source.count(trigger), 2)
            for changed in (
                self.source.replace(command, '# omitted CONNECT execution', 1),
                self.source.replace(command, command + '\n          ' + command, 1),
                self.source.replace(command, 'python3 android/test_android_node_chain_execution_capture.py', 1),
                self.source.replace(trigger, "- 'android/omitted-connect-execution.py'", 1),
            ):
                with self.subTest(name=name, changed=changed):
                    with self.assertRaises(AssertionError):
                        validate(changed)

    def test_imported_prefix_execution_controls(self):
        name = 'test_android_imported_prefix_execution_capture.py'
        command = 'python3 android/' + name
        trigger = "- 'android/" + name + "'"
        gate = '"' + name + '",'
        source = RUNTIME.read_text()
        self.assertEqual(source.count(gate), 1)
        for replacement in ('', gate + gate):
            with self.assertRaises(AssertionError):
                validate_runtime(source.replace(gate, replacement))
        for changed in (
            self.source.replace(command, '# omitted imported prefix execution', 1),
            self.source.replace(command, command + '\n          ' + command, 1),
            self.source.replace(command, 'python3 android/test_android_node_chain_execution_capture.py', 1),
            self.source.replace(trigger, "- 'android/omitted-imported-prefix.py'", 1),
        ):
            with self.assertRaises(AssertionError):
                validate(changed)

    def test_typed_connected_candidate_workflow_is_mandatory(self):
        script = validate(self.source)
        name = 'android_typed_connected_candidates'
        begin = self.source.index('  '+name+':\n')
        end = self.source.index('\n  android_hosts:', begin)
        block = self.source[begin:end]
        for replacement in ('', block+'\n'+block,
                            block.replace('  '+name+':\n', '  '+name+':\n    if: ${{ false }}\n'),
                            block.replace('  '+name+':\n', '  '+name+':\n    continue-on-error: true\n')):
            with self.subTest(replacement=replacement), self.assertRaises(AssertionError):
                validate(self.source[:begin]+replacement+self.source[end:])
        for gate in ('typed_connected_candidates', 'typed_connected_candidate_host', 'execution_entry_candidates', 'selected_draft_candidates'):
            command = 'python3 android/test_android_'+gate+'.py'
            trigger = "- 'android/test_android_"+gate+".py'"
            self.assertEqual(self.source.count(command), 1)
            self.assertEqual(self.source.count(trigger), 2)
            for changed in (
                self.source.replace(command, '# omitted connected host', 1),
                self.source.replace(command, command+'\n          '+command, 1),
                self.source.replace(command, 'python3 android/test_android_node_candidates.py', 1),
                self.source.replace(trigger, "- 'android/omitted-connected-host.py'", 1),
            ):
                with self.subTest(gate=gate), self.assertRaises(AssertionError):
                    validate(changed)
        binding = 'ANDROID_TYPED_CONNECTED_CANDIDATES_RESULT: ${{ needs.android_typed_connected_candidates.result }}'
        success = 'test "$ANDROID_TYPED_CONNECTED_CANDIDATES_RESULT" = success'
        for changed in (
            self.source.replace(', android_typed_connected_candidates,', ',', 1),
            self.source.replace(binding, 'ANDROID_TYPED_CONNECTED_CANDIDATES_RESULT: success', 1),
            self.source.replace(success, 'true', 1),
        ):
            with self.assertRaises(AssertionError):
                validate(changed)
        env = dict(os.environ, **{name.upper()+'_RESULT': 'success' for name in EXPECTED})
        self.assertEqual(subprocess.run(['bash', '-e', '-c', script], env=env, timeout=5).returncode, 0)
        for result in ('failure', 'cancelled', 'skipped', ''):
            env['ANDROID_TYPED_CONNECTED_CANDIDATES_RESULT'] = result
            with self.subTest(result=result):
                self.assertNotEqual(subprocess.run(['bash', '-e', '-c', script], env=env, timeout=5).returncode, 0)

    def test_runtime_typed_connected_candidate_controls(self):
        source = RUNTIME.read_text()
        validate_runtime(source)
        for name in ('typed_connected_candidates', 'typed_connected_candidate_host', 'execution_entry_candidates', 'selected_draft_candidates'):
            gate = '"test_android_'+name+'.py",'
            self.assertEqual(source.count(gate), 1)
            for replacement in ('', gate+gate):
                with self.subTest(gate=gate, replacement=replacement), self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement, 1))

    def test_runtime_socks_execution_controls(self):
        source = RUNTIME.read_text()
        for name in ('capture', 'runtime'):
            gate = '"test_android_socks_execution_' + name + '.py",'
            self.assertEqual(source.count(gate), 1)
            for replacement in ('', gate + gate):
                with self.subTest(name=name, replacement=replacement):
                    with self.assertRaises(AssertionError):
                        validate_runtime(source.replace(gate, replacement))

    def test_socks_execution_workflow_controls(self):
        validate(self.source)
        for name in ('capture', 'runtime'):
            command = 'python3 android/test_android_socks_execution_' + name + '.py'
            trigger = "- 'android/test_android_socks_execution_" + name + ".py'"
            self.assertEqual(self.source.count(command), 1)
            self.assertEqual(self.source.count(trigger), 2)
            for changed in (
                self.source.replace(command, '# omitted SOCKS execution', 1),
                self.source.replace(command, command + '\n          ' + command, 1),
                self.source.replace(command, 'python3 android/test_android_node_chain_execution_capture.py', 1),
                self.source.replace(trigger, "- 'android/omitted-socks-execution.py'", 1),
            ):
                with self.subTest(name=name, changed=changed):
                    with self.assertRaises(AssertionError):
                        validate(changed)

    def test_runtime_connect_fifty_controls(self):
        source = RUNTIME.read_text()
        gate = '"test_android_connect_ordered_latency.py",'
        self.assertEqual(source.count(gate), 1)
        for replacement in ('', gate + gate):
            with self.subTest(replacement=replacement):
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement))

    def test_runtime_execution_fifty_controls(self):
        source = RUNTIME.read_text()
        for name in ('execution_ordered_latency', 'execution_ordered_latency_data', 'ordered_history_source_transaction'):
            gate = '"test_android_' + name + '.py",'
            self.assertEqual(source.count(gate), 1)
            for replacement in ('', gate + gate):
                with self.subTest(name=name, replacement=replacement):
                    with self.assertRaises(AssertionError):
                        validate_runtime(source.replace(gate, replacement))


    def test_runtime_ordered_fifty_controls(self):
        source = RUNTIME.read_text()
        gate = '"test_android_ordered_latency.py",'
        self.assertEqual(source.count(gate), 1)
        for replacement in ('', gate + gate):
            with self.subTest(replacement=replacement):
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement))

    def test_runtime_ordinary_fifty_controls(self):
        source = RUNTIME.read_text()
        gate = '"test_android_ordinary_ordered_latency.py",'
        self.assertEqual(source.count(gate), 1)
        for replacement in ('', gate + gate):
            with self.subTest(replacement=replacement):
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement))

    def test_runtime_temporary_preparation_controls(self):
        source = RUNTIME.read_text()
        gate = '"test_android_node_candidate_preparation.py",'
        self.assertEqual(source.count(gate), 1)
        for replacement in ('', gate + gate):
            with self.subTest(replacement=replacement):
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement))

    def test_runtime_detached_profile_controls(self):
        source = RUNTIME.read_text()
        gate = '"test_android_node_candidate_profile.py",'
        self.assertEqual(source.count(gate), 1)
        for replacement in ('', gate + gate):
            with self.subTest(replacement=replacement):
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement))

    def test_runtime_connect_candidate_controls(self):
        source = RUNTIME.read_text()
        gate = '"test_android_node_connect_candidates.py",'
        self.assertEqual(source.count(gate), 1)
        for replacement in ('', gate + gate):
            with self.subTest(replacement=replacement):
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement))

    def test_runtime_socks_candidate_controls(self):
        source = RUNTIME.read_text()
        gate = '"test_android_node_socks_candidates.py",'
        self.assertEqual(source.count(gate), 1)
        for replacement in ('', gate + gate):
            with self.subTest(replacement=replacement):
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement))

    def test_runtime_prefix_capture_controls(self):
        source = RUNTIME.read_text()
        gate = '"test_android_node_candidate_prefix_capture.py",'
        self.assertEqual(source.count(gate), 1)
        for replacement in ('', gate + gate):
            with self.subTest(replacement=replacement):
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement))

    def test_runtime_prefix_host_controls(self):
        source = RUNTIME.read_text()
        gate = '"test_android_node_candidate_prefix_host.py",'
        self.assertEqual(source.count(gate), 1)
        for replacement in ('', gate + gate):
            with self.subTest(replacement=replacement):
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement))

    def test_runtime_prefix_owner_controls(self):
        source = RUNTIME.read_text()
        gate = '"test_android_node_candidate_prefix_owner.py",'
        self.assertEqual(source.count(gate), 1)
        for replacement in ('', gate + gate):
            with self.subTest(replacement=replacement):
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement))

    def test_runtime_preparation_owner_controls(self):
        source = RUNTIME.read_text()
        gate = '"test_android_node_candidate_preparation_owner.py",'
        self.assertEqual(source.count(gate), 1)
        for replacement in ('', gate + gate):
            with self.subTest(replacement=replacement):
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement))

    def test_runtime_preparation_ui_controls(self):
        source = RUNTIME.read_text()
        gate = '"test_android_node_candidate_preparation_ui.py",'
        self.assertEqual(source.count(gate), 1)
        for replacement in ('', gate + gate):
            with self.subTest(replacement=replacement):
                with self.assertRaises(AssertionError):
                    validate_runtime(source.replace(gate, replacement))

    def test_actual_aggregate_rejects_every_incomplete_result(self):
        script = validate(self.source)
        # Retain every original 4**7 actual-shell combination. Each new Android
        # job inherits the original Android axis; separate controls below vary
        # every new result independently under the exact conjunction contract.
        for results in product(('success', 'failure', 'cancelled', 'skipped'), repeat=len(LEGACY_RESULTS)):
            with self.subTest(results=results):
                legacy = dict(zip(LEGACY_RESULTS, results))
                env = dict(os.environ, **{name.upper() + '_RESULT': legacy['android' if name in ANDROID_GROUPS else name]
                                         for name in EXPECTED})
                actual = subprocess.run(['bash', '-e', '-c', script], env=env, timeout=5)
                self.assertEqual(actual.returncode == 0, all(result == 'success' for result in results))

    def test_inventory_controls(self):
        changes = (
            ('python3 android/test_android_node_candidate_preparation_ui.py', '# omitted temporary candidate UI'),
            ('python3 android/test_android_node_candidate_preparation_ui.py', 'python3 android/test_android_node_candidate_preparation_owner.py'),
            ("- 'android/test_android_node_candidate_preparation_ui.py'", "- 'android/omitted-candidate-ui.py'"),
            (ANDROID[1], '# omitted'),
            (ANDROID[2], '# omitted execution capture'),
            ('python3 android/test_android_node_candidate_preparation.py', '# omitted temporary preparation'),
            ('python3 android/test_android_node_candidate_preparation_owner.py', '# omitted temporary candidate owner'),
            ('python3 android/test_android_node_candidate_preparation_owner.py', 'python3 android/test_android_node_candidate_preparation.py'),
            ("- 'android/test_android_node_candidate_preparation_owner.py'", "- 'android/omitted-candidate-owner.py'"),
            ('python3 android/test_android_node_candidate_profile.py', '# omitted detached candidate profile'),
            ('python3 android/test_android_node_connect_candidates.py', '# omitted CONNECT candidate'),
            ('python3 android/test_android_node_socks_candidates.py', '# omitted SOCKS candidate'),
            ('python3 android/test_android_node_socks_candidates.py', 'python3 android/test_android_node_candidates.py'),
            ("- 'android/test_android_node_socks_candidates.py'", "- 'android/omitted-socks-candidate.py'"),
            ('python3 android/test_android_node_connect_candidates.py', 'python3 android/test_android_node_candidates.py'),
            ("- 'android/test_android_node_connect_candidates.py'", "- 'android/omitted-connect-candidate.py'"),
            ('python3 android/test_android_node_candidate_prefix_capture.py', '# omitted independent prefix capture'),
            ('python3 android/test_android_node_candidate_prefix_host.py', '# omitted actual prefix host'),
            ('python3 android/test_android_node_candidate_prefix_owner.py', '# omitted actual prefix supervisor'),
            ('python3 android/test_android_node_candidate_prefix_owner.py', 'python3 android/test_android_node_candidates.py'),
            ("- 'android/test_android_node_candidate_prefix_owner.py'", "- 'android/omitted-prefix-owner.py'"),
            ('python3 android/test_android_node_candidate_prefix_host.py', 'python3 android/test_android_node_candidates.py'),
            ("- 'android/test_android_node_candidate_prefix_host.py'", "- 'android/omitted-prefix-host.py'"),
            ('python3 android/test_android_node_candidate_prefix_capture.py', 'python3 android/test_android_node_candidates.py'),
            ("- 'android/test_android_node_candidate_prefix_capture.py'", "- 'android/omitted-prefix-capture.py'"),
            ('python3 android/test_android_node_candidate_profile.py', 'python3 android/test_android_node_candidates.py'),
            ("- 'android/test_android_node_candidate_profile.py'", "- 'android/omitted-candidate-profile.py'"),
            ('python3 android/test_android_node_candidate_preparation.py', 'python3 android/test_android_node_chain_runtime.py'),
            ('python3 android/test_android_node_chain_connect_runtime.py', '# omitted typed CONNECT host'),
            ('python3 android/test_android_node_chain_openvpn_runtime.py', '# omitted OpenVPN middle host'),
            ('python3 android/test_android_node_chain_imported_runtime.py', '# omitted imported SS middle host'),
            ("- 'android/test_android_node_chain_imported_runtime.py'", "- 'android/omitted-ss-middle.py'"),
            ("- 'android/test_android_node_chain_openvpn_runtime.py'", "- 'android/omitted-openvpn-middle.py'"),
            ('python3 android/test_android_connect_ordered_latency.py', '# omitted CONNECT fifty caller'),
            ("- 'android/test_android_connect_ordered_latency.py'", "- 'android/omitted-connect-fifty.py'"),
            ("- 'android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainCONNECTCapture.java'", "- 'android/omitted-connect-source.java'"),
            ('python3 android/test_android_node_chain_socks_runtime.py', '# omitted typed SOCKS host'),
            ('python3 android/test_android_ordered_latency.py', '# omitted ordered fifty host'),
            ('python3 android/test_android_ordinary_ordered_latency.py', '# omitted ordinary fifty host'),
            ("- 'android/app/src/main/java/com/eabusham/routervpn/AndroidOrderedLatencyStore.java'", "- 'android/omitted-ordered-fifty.java'"),
            ("- 'android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainSOCKSCapture.java'", "- 'android/omitted-socks-source.java'"),
            ('python3 android/test_android_node_chain_execution_runtime.py', '# omitted execution runtime'),
            ('python3 android/test_android_node_chain_execution_restore.py', '# omitted execution restore'),
            ("- 'android/test_android_node_candidate_preparation.py'", "- 'android/omitted-preparation.py'"),
            ("- 'android/test_android_runtime_contract.py'", "- 'android/omitted-runtime.py'"),
            ("- 'android/test_android_node_chain_execution_capture.py'", "- 'android/omitted-execution.py'"),
            ("- 'android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainExecutionCapture.java'", "- 'android/omitted-execution.java'"),
            (ANDROID[1], ANDROID[0]),
            ('go test -race -count=1 -timeout=5m', 'go test -count=1 -timeout=5m'),
            ('timeout-minutes: 15', 'timeout-minutes: 30'),
            ('--group runtime', '--group core'),
            ('--group fifty', '--group core'),
            ('  shared_fifty:\n', '  shared_fifty:\n    if: ${{ false }}\n'),
            ('SHARED_FIFTY_RESULT: ${{ needs.shared_fifty.result }}', 'SHARED_FIFTY_RESULT: success'),
            ('needs: [android, android_ordered_source, android_execution_source, android_connect_source, android_connect_final_layers, android_connect_final_layers_extended, android_socks_source, android_openvpn_source, android_openvpn_host, android_imported_source, android_multiple_imported, android_candidates, android_layered_candidates, android_typed_connected_candidates, android_hosts, android_latency, shared_core, shared_runtime, shared_fifty, shared_fifty_closed, shared_imported_prefix, relay]', 'needs: [android, shared_core, relay]'),
            ('if: ${{ always() }}', 'if: ${{ success() }}'),
            ('  shared_core:\n', '  shared_core:\n    if: ${{ false }}\n'),
            ('SHARED_RUNTIME_RESULT: ${{ needs.shared_runtime.result }}', 'SHARED_RUNTIME_RESULT: success'),
        )
        for old, new in changes:
            with self.subTest(change=old):
                self.assertIn(old, self.source)
                with self.assertRaises(AssertionError):
                    validate(self.source.replace(old, new, 1))

    def test_execution_fifty_dependency_and_result_cannot_be_omitted(self):
        original = 'needs: [android, android_ordered_source, android_execution_source, android_connect_source, android_connect_final_layers, android_connect_final_layers_extended, android_socks_source, android_openvpn_source, android_openvpn_host, android_imported_source, android_multiple_imported, android_candidates, android_layered_candidates, android_typed_connected_candidates, android_hosts, android_latency, shared_core, shared_runtime, shared_fifty, shared_fifty_closed, shared_imported_prefix, relay]'
        with self.assertRaises(AssertionError):
            validate(self.source.replace(original, 'needs: [android, shared_core, shared_runtime, relay]'))
        script = validate(self.source)
        env = dict(os.environ, **{name.upper() + '_RESULT': 'success' for name in EXPECTED})
        env['SHARED_FIFTY_RESULT'] = 'failure'
        self.assertNotEqual(subprocess.run(['bash', '-e', '-c', script], env=env, timeout=5).returncode, 0)
        bypass = script.replace('test "$SHARED_FIFTY_RESULT" = success', 'true')
        self.assertNotEqual(script, bypass)
        self.assertEqual(subprocess.run(['bash', '-e', '-c', bypass], env=env, timeout=5).returncode, 0)

    def test_closed_fifty_job_cannot_be_missing_duplicated_or_skipped(self):
        begin = self.source.index('  shared_fifty_closed:\n')
        end = self.source.index('\n  relay:', begin)
        block = self.source[begin:end]
        for replacement in ('', block + '\n' + block,
                            block.replace('  shared_fifty_closed:\n', '  shared_fifty_closed:\n    if: ${{ false }}\n'),
                            block.replace('  shared_fifty_closed:\n', '  shared_fifty_closed:\n    continue-on-error: true\n'),
                            block.replace('--group fifty_closed', '--group fifty')):
            with self.subTest(replacement=replacement), self.assertRaises(AssertionError):
                validate(self.source[:begin] + replacement + self.source[end:])

    def test_closed_fifty_dependency_and_terminal_result_are_mandatory(self):
        original = 'needs: [android, android_ordered_source, android_execution_source, android_connect_source, android_connect_final_layers, android_connect_final_layers_extended, android_socks_source, android_openvpn_source, android_openvpn_host, android_imported_source, android_multiple_imported, android_candidates, android_layered_candidates, android_typed_connected_candidates, android_hosts, android_latency, shared_core, shared_runtime, shared_fifty, shared_fifty_closed, shared_imported_prefix, relay]'
        with self.assertRaises(AssertionError):
            validate(self.source.replace(original, original.replace(', shared_fifty_closed', '')))
        binding = 'SHARED_FIFTY_CLOSED_RESULT: ${{ needs.shared_fifty_closed.result }}'
        with self.assertRaises(AssertionError):
            validate(self.source.replace(binding, 'SHARED_FIFTY_CLOSED_RESULT: success'))
        script = validate(self.source)
        for result in ('failure', 'cancelled', 'skipped', ''):
            env = dict(os.environ, **{name.upper() + '_RESULT': 'success' for name in EXPECTED})
            env['SHARED_FIFTY_CLOSED_RESULT'] = result
            with self.subTest(result=result):
                self.assertNotEqual(subprocess.run(['bash', '-e', '-c', script], env=env, timeout=5).returncode, 0)
        # The exhaustive actual-shell matrix above must catch this bypass too.
        bypass = script.replace('test "$SHARED_FIFTY_CLOSED_RESULT" = success', 'true')
        self.assertNotEqual(script, bypass)
        self.assertEqual(subprocess.run(['bash', '-e', '-c', bypass], env=env, timeout=5).returncode, 0)

    def test_aggregate_bypass_control(self):
        script = validate(self.source).replace('test "$SHARED_RUNTIME_RESULT" = success', 'true')
        env = dict(os.environ, **{name.upper() + '_RESULT': 'success' for name in EXPECTED})
        env['SHARED_RUNTIME_RESULT'] = 'failure'
        # Proves the negative result matrix above would detect a silently omitted check.
        self.assertEqual(subprocess.run(['bash', '-e', '-c', script], env=env, timeout=5).returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
