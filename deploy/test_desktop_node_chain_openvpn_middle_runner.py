#!/usr/bin/env python3
"""Refuse incomplete, skipped or substituted encrypted OpenVPN-hop evidence."""
from pathlib import Path
import importlib.util
import unittest
from unittest import mock
from contextlib import ExitStack

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('openvpn_middle_native_runner', ROOT / 'deploy/test_desktop_node_chain_openvpn_middle.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def passed(names):
    return '\n'.join('=== RUN   ' + name + '\n--- PASS: ' + name + ' (0.01s)' for name in names) + '\nPASS\n'


class OpenVPNMiddleNativeRunner(unittest.TestCase):
    def test_complete_original_inventory(self):
        self.assertEqual(len(G.VERDICTS), 48)
        self.assertEqual(len(set(G.VERDICTS)), 48)
        G.check_verdict(passed(G.VERDICTS))

    def test_each_run_and_pass_required(self):
        original = passed(G.VERDICTS)
        for name in G.VERDICTS:
            for needle in ('=== RUN   ' + name + '\n', '--- PASS: ' + name + ' (0.01s)\n'):
                with self.subTest(name=name, needle=needle), self.assertRaises(ValueError):
                    G.check_verdict(original.replace(needle, '', 1))

    def test_duplicate_foreign_failure_skip_and_race_refuse(self):
        original = passed(G.VERDICTS)
        for mutation in (original + passed(G.VERDICTS[:1]), original + passed(('TestForeign',)),
                         original + '--- FAIL: foreign (0.01s)\n', original + '--- SKIP: foreign (0.01s)\n',
                         original + 'WARNING: DATA RACE\n', original + 'panic: replaced source\n'):
            with self.subTest(mutation=mutation[-100:]), self.assertRaises(ValueError):
                G.check_verdict(mutation)

    def test_original_native_registration_and_transport_dependencies(self):
        self.assertEqual(G.NODE.PREP.PEER_TEMPLATES[G.TEMPLATE], G.NATIVE_TEMPLATE)
        raw = (ROOT / 'mobile/desktop' / G.TEMPLATE).read_bytes()
        self.assertTrue(raw.startswith(b'//go:build linux && !android\n\npackage routervpnamnezia\n'))
        for dependency in ('dns/router.go', 'dns/transport/udp.go', 'common/tls/std_client.go',
                           'protocol/openvpn/client.go', 'protocol/openvpn/server.go',
                           'protocol/routervpnamnezia/routervpn_desktop_node_chain_imported_test.go',
                           'protocol/routervpnamnezia/routervpn_desktop_node_imported_peer_linux_test.go',
                           'protocol/wireguard/endpoint.go', 'protocol/shadowsocks/outbound.go',
                           'experimental/libbox/routervpn/mobilemultihop/node_chain_openvpn_runtime.go'):
            self.assertIn(dependency, G.REQUIRED)

    def peer_mocks(self, outputs=None):
        stack = ExitStack()
        stack.enter_context(mock.patch.object(G.NODE, 'retained_binary', return_value=('original-image',)))
        stack.enter_context(mock.patch.object(G, 'checked_sources', return_value=(Path('/captured/source'), {'source': 'original'})))
        run = stack.enter_context(mock.patch.object(G.NODE, 'run', side_effect=outputs or [(0, passed(names)) for _, _, names in G.PHASES]))
        self.addCleanup(stack.close)
        return run

    def test_actual_peer_commands_retain_original_bounds_and_image(self):
        run = self.peer_mocks()
        outputs = [passed(names) for _, _, names in G.PHASES]
        self.assertEqual(G.execute_peer(Path('/captured/peer'), Path('/captured/source'), {'PATH': '/captured'}), ''.join(outputs))
        self.assertEqual(run.call_args_list, [mock.call(
            [Path('/captured/peer'), '-test.run=' + selection, '-test.count=1', '-test.timeout=180s', '-test.v'],
            cwd=Path('/captured/source'), env={'PATH': '/captured'}, timeout=190) for _, selection, _ in G.PHASES])
        self.assertEqual([len(names) for _, _, names in G.PHASES], [11, 11, 11, 17])

    def test_missing_repeated_reordered_or_wrong_phase_refused_before_execution(self):
        original = G.PHASES
        mutations = (original[:-1], original + original[:1], (original[1], original[0], *original[2:]),
                     (('foreign', *original[0][1:]), *original[1:]),
                     ((original[0][0], G.SELECTION, original[0][2]), *original[1:]),
                     ((original[0][0], original[0][1], original[0][2][:-1]), *original[1:]))
        for phases in mutations:
            with self.subTest(phases=phases), mock.patch.object(G, 'PHASES', phases), mock.patch.object(G.NODE, 'run') as run, self.assertRaises(ValueError):
                G.execute_peer(Path('/unused'), Path('/unused'), {})
            run.assert_not_called()

    def test_each_phase_refuses_borrowed_missing_duplicate_failed_verdicts(self):
        for index, (_, _, names) in enumerate(G.PHASES):
            for mutation in (passed(names[:-1]), passed(names) + passed(names[:1]), passed(G.VERDICTS),
                             passed(G.PHASES[(index + 1) % 4][2]), passed(names) + 'WARNING: DATA RACE\n'):
                outputs = [(0, passed(rows)) for _, _, rows in G.PHASES]
                outputs[index] = (0, mutation)
                with self.subTest(index=index, mutation=mutation[-60:]):
                    run = self.peer_mocks(outputs)
                    with self.assertRaises(ValueError):
                        G.execute_peer(Path('/captured/peer'), Path('/captured/source'), {})
                    self.assertEqual(run.call_count, index + 1)

    def test_failed_process_cannot_borrow_positive_verdicts(self):
        run = self.peer_mocks([(1, passed(G.PHASES[0][2]))])
        with self.assertRaises(ValueError):
            G.execute_peer(Path('/captured/peer'), Path('/captured/source'), {})
        self.assertEqual(run.call_count, 1)

    def test_success_without_complete_execution_is_refused(self):
        self.peer_mocks([(0, 'PASS\n')])
        with self.assertRaises(ValueError):
            G.execute_peer(Path('/captured/peer'), Path('/captured/source'), {})

    def test_changed_image_or_source_between_phases_refuses(self):
        for kind in ('image', 'source'):
            run = self.peer_mocks()
            def replace(*args, **kwargs):
                if kind == 'image':
                    G.NODE.retained_binary.return_value = ('replacement-image',)
                else:
                    G.checked_sources.return_value = (Path('/captured/source'), {'source': 'replacement'})
                return 0, passed(G.PHASES[0][2])
            run.side_effect = replace
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                G.execute_peer(Path('/captured/peer'), Path('/captured/source'), {})
            self.assertEqual(run.call_count, 1)

    def test_no_foreign_host_execution(self):
        with mock.patch.object(G.platform, 'system', return_value='Windows'), self.assertRaises(ValueError):
            G.execute(Path('/unused'))


if __name__ == '__main__':
    unittest.main()
