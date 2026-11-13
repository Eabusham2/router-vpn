#!/usr/bin/env python3
"""Require every hostname encrypted-native verdict and exact source dependency."""
from pathlib import Path
import importlib.util
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hostname_native_runner_gate', ROOT / 'deploy/test_desktop_node_imported_hostname.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def passed(names):
    return '\n'.join('=== RUN   ' + name + '\n--- PASS: ' + name + ' (0.01s)' for name in names) + '\nPASS\n'


class HostnameNativeRunner(unittest.TestCase):
    def test_complete_original_inventory(self):
        self.assertEqual(len(G.VERDICTS), 64)
        self.assertEqual(len(set(G.VERDICTS)), 64)
        G.check_verdict(passed(G.VERDICTS))

    def test_every_original_case_required(self):
        for name in G.VERDICTS:
            with self.subTest(name=name), self.assertRaises(ValueError):
                G.check_verdict(passed(tuple(value for value in G.VERDICTS if value != name)))

    def test_duplicate_foreign_failure_skip_and_race_refuse(self):
        original = passed(G.VERDICTS)
        for mutation in (original + passed(G.VERDICTS[:1]), original + passed(('TestForeign',)),
                         original + '--- FAIL: foreign (0.01s)\n', original + '--- SKIP: foreign (0.01s)\n',
                         original + 'WARNING: DATA RACE\n', original + 'panic: replaced source\n'):
            with self.subTest(mutation=mutation[-100:]), self.assertRaises(ValueError):
                G.check_verdict(mutation)

    def test_each_run_and_pass_required(self):
        original = passed(G.VERDICTS)
        for name in G.VERDICTS:
            for needle in ('=== RUN   ' + name + '\n', '--- PASS: ' + name + ' (0.01s)\n'):
                with self.subTest(name=name, needle=needle), self.assertRaises(ValueError):
                    G.check_verdict(original.replace(needle, '', 1))

    def test_original_encrypted_native_registration(self):
        self.assertEqual(G.NODE.PREP.PEER_TEMPLATES[G.TEMPLATE], G.NATIVE_TEMPLATE)
        raw = (ROOT / 'mobile/desktop' / G.TEMPLATE).read_bytes()
        self.assertTrue(raw.startswith(b'//go:build linux && !android\n\npackage routervpnamnezia\n'))
        for dependency in ('dns/router.go', 'dns/transport/tcp.go', 'common/dialer/resolve.go',
                           'protocol/shadowsocks/outbound.go', 'protocol/wireguard/endpoint.go',
                           'experimental/libbox/routervpn/mobilemultihop/node_chain_graph.go'):
            self.assertIn(dependency, G.REQUIRED)

    def test_actual_peer_command_keeps_original_bounds(self):
        output = passed(G.VERDICTS)
        with mock.patch.object(G.NODE, 'run', return_value=(0, output)) as run:
            self.assertEqual(G.execute_peer(Path('/captured/peer'), Path('/captured/source'), {'PATH': '/captured'}), output)
        run.assert_called_once_with([Path('/captured/peer'), '-test.run=^' + G.TEST + '$', '-test.count=1', '-test.timeout=90s', '-test.v'],
                                    cwd=Path('/captured/source'), env={'PATH': '/captured'}, timeout=100)

    def test_failed_process_cannot_borrow_positive_verdicts(self):
        with mock.patch.object(G.NODE, 'run', return_value=(1, passed(G.VERDICTS))), self.assertRaises(ValueError):
            G.execute_peer(Path('/captured/peer'), Path('/captured/source'), {})

    def test_success_without_complete_execution_is_refused(self):
        with mock.patch.object(G.NODE, 'run', return_value=(0, 'PASS\n')), self.assertRaises(ValueError):
            G.execute_peer(Path('/captured/peer'), Path('/captured/source'), {})

    def test_no_foreign_host_execution(self):
        with mock.patch.object(G.platform, 'system', return_value='Windows'), self.assertRaises(ValueError):
            G.execute(Path('/unused'))


if __name__ == '__main__':
    unittest.main()
