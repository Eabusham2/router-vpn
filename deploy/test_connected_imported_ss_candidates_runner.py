#!/usr/bin/env python3
"""Validator controls only; synthetic transcripts never establish native proof."""
from pathlib import Path
from contextlib import redirect_stdout
import copy
import importlib.util
import inspect
import io
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('connected_imported_candidate_gate', ROOT / 'deploy/test_connected_imported_ss_candidates.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def passed(phase):
    output = ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in phase['verdicts'])
    if phase['root'] == G.TRAFFIC:
        output += f"CONNECTED_IMPORTED_CANDIDATE_RECEIPT count={phase['prefixes']} position={phase['position']} samples=50 closed=50 released=1 complete_ready=true selected_dns=true joined=true\n"
    if phase['root'] == G.PRIVATE_ROOT and phase['fault'] == 'original':
        output += f"CONNECTED_IMPORTED_PRIVATE_RECEIPT count={phase['prefixes']} position={phase['position']} samples=50 decrypted=50 closed=50 released=1 complete_ready=true selected_dns=true joined=true\n"
    return output + 'PASS\n'


class ConnectedImportedCandidateRunner(unittest.TestCase):
    def test_exact_full_path_inventory(self):
        phases = G.phases()
        self.assertEqual(len(phases), 44)
        self.assertEqual(len(G.CASES), 24)
        self.assertEqual(len(G.FAULTS), 8)
        self.assertEqual(len({p['name'] for p in phases}), 44)
        for mode in ('wg', 'awg2-fast', 'awg2-strong'):
            for count in (2, 6):
                selected = [p for p in phases if p['root'] == G.TRAFFIC and p.get('mode') == mode and p.get('prefixes') == count]
                self.assertEqual([p['position'] for p in selected], list(range(count)))
                self.assertTrue(all(p['samples'] == 50 for p in selected))
        for phase in phases:
            G.check_verdict(passed(phase), phase)

    def test_private_response_requires_original_qualifications_and_decryption(self):
        private = [p for p in G.phases() if p['root'] == G.PRIVATE_ROOT]
        self.assertEqual({p['name'] for p in private}, {
            'awg2-fast/1/literal/original', 'wg/2/literal/original', 'awg2-strong/6/literal/original',
            'wg/2/literal/wrong-intermediate-key', 'awg2-fast/1/literal/wrong-candidate-key',
            'awg2-strong/2/literal/forged-response', 'wg/2/literal/late-owner', 'awg2-fast/1/literal/cancel-held-close',
            'awg2-strong/2/hostname/original', 'wg/2/hostname/wrong-transport-dns',
            'wg/1/hostname/original', 'wg/1/hostname/wrong-transport-dns'})
        for phase in private:
            raw = passed(phase)
            if phase['fault'] == 'original':
                for field in ('samples=50', 'decrypted=50', 'closed=50', 'released=1', 'joined=true', 'complete_ready=true', 'selected_dns=true'):
                    with self.subTest(case=phase['name'], field=field), self.assertRaises(ValueError):
                        G.check_verdict(raw.replace(field, field+'changed'), phase)
            else:
                with self.assertRaises(ValueError):
                    G.check_verdict(raw+'CONNECTED_IMPORTED_PRIVATE_RECEIPT samples=50\n', phase)

    def test_missing_or_duplicate_original_case_is_not_acceptance(self):
        for phase in G.phases():
            original = passed(phase)
            for name in phase['verdicts']:
                for line in ('=== RUN   '+name+'\n', '--- PASS: '+name+' (0.01s)\n'):
                    with self.subTest(phase=phase['name'], line=line), self.assertRaises(ValueError):
                        G.check_verdict(original.replace(line, '', 1), phase)
            for suffix in (original, '--- SKIP: TestForeign (0s)\n', '--- FAIL: TestForeign (0s)\n',
                           'WARNING: DATA RACE\n', 'panic: changed\n', '=== RUN   TestForeign\n--- PASS: TestForeign (0s)\n'):
                with self.subTest(phase=phase['name'], suffix=suffix[:24]), self.assertRaises(ValueError):
                    G.check_verdict(original + suffix, phase)

    def test_complete_ready_fifty_sockets_and_join_are_mandatory(self):
        for phase in G.phases()[:24]:
            raw = passed(phase)
            for old, new in (('samples=50','samples=49'), ('closed=50','closed=49'), ('released=1','released=0'),
                             ('complete_ready=true','complete_ready=false'), ('selected_dns=true','selected_dns=false'),
                             ('joined=true','joined=false'), (f"position={phase['position']}", 'position=99')):
                with self.subTest(phase=phase['name'], field=old), self.assertRaises(ValueError):
                    G.check_verdict(raw.replace(old, new), phase)
            without = '\n'.join(line for line in raw.splitlines() if not line.startswith('CONNECTED_IMPORTED_CANDIDATE_RECEIPT'))+'\n'
            with self.assertRaises(ValueError): G.check_verdict(without, phase)
            marker = next(line for line in raw.splitlines() if line.startswith('CONNECTED_IMPORTED_CANDIDATE_RECEIPT'))
            with self.assertRaises(ValueError): G.check_verdict(raw+marker+'\n', phase)

    def test_foreign_phase_cannot_reduce_or_relabel_work(self):
        original = G.phases()[0]
        for key, value in (('samples', 1), ('prefixes', 1), ('position', 8), ('root', 'TestForeign'), ('verdicts', [])):
            phase = copy.deepcopy(original); phase[key] = value
            with self.assertRaises(ValueError): G.check_verdict(passed(original), phase)

    def test_one_original_image_whole_roots_and_original_clocks(self):
        phases = G.phases()
        source, image = Path('/original/core'), Path('/original/peer.test')
        captured = {G.CASE_ENV: 'foreign', G.FAULT_ENV: 'foreign', G.PRIVATE_ENV: 'foreign', 'GOWORK': 'off'}
        def run(command, *, cwd, env, timeout):
            selected = env.get(G.CASE_ENV) or env.get(G.FAULT_ENV) or env.get(G.PRIVATE_ENV)
            phase = next(p for p in phases if p['name'] == selected)
            self.assertEqual(command, [str(image), '-test.v', '-test.count=1', '-test.timeout=90s', '-test.run=^'+phase['root']+'$'])
            self.assertEqual(cwd, source); self.assertEqual(timeout, 100)
            self.assertEqual(sum(key in env for key in (G.CASE_ENV, G.FAULT_ENV, G.PRIVATE_ENV)), 1)
            return 0, passed(phase)
        with mock.patch.object(G, 'checked_sources', return_value=(source, {'source': 'a'*64})), \
             mock.patch.object(G.NODE, 'retained_binary', return_value=('original', 'b'*64)), \
             mock.patch.object(G.NODE, 'run', side_effect=run) as executed, redirect_stdout(io.StringIO()):
            result = G.execute_peer(image, source, captured)
        self.assertEqual(executed.call_count, 44)
        self.assertEqual([p['name'] for p in result['phases']], [p['name'] for p in phases])
        self.assertFalse(result['installed_host_accepted']); self.assertFalse(result['kernel_tun_accepted'])
        self.assertEqual(result['native_observation'], 'explicit-component-session-boundary')

    def test_compilation_or_runtime_failure_cannot_become_partial_success(self):
        source, image = Path('/original/core'), Path('/original/peer.test')
        for status, raw in ((1, passed(G.phases()[0])), (0, 'PASS\n'), (0, '')):
            with mock.patch.object(G, 'checked_sources', return_value=(source, {'source':'a'})), \
                 mock.patch.object(G.NODE, 'retained_binary', return_value=('original','b')), \
                 mock.patch.object(G.NODE, 'run', return_value=(status, raw)), redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                G.execute_peer(image, source, {})

    def test_original_source_or_image_replacement_refused(self):
        source, image = Path('/original/core'), Path('/original/peer.test')
        with mock.patch.object(G, 'checked_sources', side_effect=[(source, {'source':'a'}), (source, {'source':'changed'})]), \
             mock.patch.object(G.NODE, 'retained_binary', return_value=('original','b')), \
             mock.patch.object(G.NODE, 'run') as run, self.assertRaises(ValueError):
            G.execute_peer(image, source, {})
        run.assert_not_called()
        with mock.patch.object(G, 'checked_sources', return_value=(source, {'source':'a'})), \
             mock.patch.object(G.NODE, 'retained_binary', side_effect=[('original','b'),('replacement','b')]), \
             mock.patch.object(G.NODE, 'run') as run, self.assertRaises(ValueError):
            G.execute_peer(image, source, {})
        run.assert_not_called()

    def test_shipping_path_uses_complete_ready_constructor(self):
        text = (ROOT/'mobile/desktop'/G.TEMPLATE).read_text()
        self.assertIn('f.path.chain.Run(f.path.ctx, f.engine)', text)
        self.assertIn('f.plan.NewMeasurementContext(f.path.ctx, f.owner)', text)
        self.assertIn('!progress.Ready || !progress.Complete || !progress.DNSProven || !progress.PublicProven', text)
        self.assertNotIn('hopmeasure.NewPrefixCandidatesContext', text)
        self.assertNotIn('NewNodeChainCandidatePreparation', text)
        self.assertEqual(G.NODE.PREP.PEER_TEMPLATES[G.TEMPLATE], G.NATIVE_TEMPLATE)
        owner = (ROOT/'mobile/chain/imported_prefix_box_test.go.tmpl').read_text()
        self.assertIn('func '+G.OWNER_ROOT+'(', owner)
        for field in ('"prefix"', '"middle"', '"final"', '"resolver"', '"stale-owner"'):
            self.assertIn(field, owner)

    def test_original_box_ownership_inventory_stays_required(self):
        contract = G.load('connected_imported_existing_box_contract', 'test_desktop_node_chain_ss_prefix_contract.py')
        self.assertEqual(len(G.OWNER_CASES), 17)
        self.assertEqual({name for name in contract.BOX_CASES if name.split('/')[0] == G.OWNER_ROOT}, set(G.OWNER_CASES))
        workflow = (ROOT/'.github/workflows/ss-node-chain-prefix.yml').read_text()
        self.assertIn('test_desktop_node_chain_ss_prefix_contract.py', workflow)
        release = (ROOT/'.github/workflows/release-candidate.yml').read_text()
        self.assertIn('uses: ./.github/workflows/ss-node-chain-prefix.yml', release)

    def test_required_installed_host_and_builder_inputs(self):
        host = (ROOT/'deploy/test_linux_node_host_tun.py').read_text()
        self.assertIn("load('linux_connected_imported_candidates', 'test_connected_imported_ss_candidates.py')", host)
        self.assertLess(host.index('connected_imported_candidates.execute_peer(peer, source, captured)'), host.index('for case in (*CASES, *REVERSE_CASES)'))
        self.assertIn("'connected_imported_candidate_proof': connected_imported_candidate_proof", host)
        builder = (ROOT/'deploy/build-native-runtime.py').read_text()
        for path in G.GATES[:2]: self.assertIn("ROOT/'"+path+"'", builder)


if __name__ == '__main__':
    unittest.main()
