#!/usr/bin/env python3
"""Verify isolation and cleanup of the real-traffic gate's temporary sources."""
from pathlib import Path
from unittest import mock
import importlib.util
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pq_traffic_gate', ROOT/'deploy/test_server_pq_traffic.py')
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)

class TrafficPreparation(unittest.TestCase):
    def fixture(self, root):
        core = root/'core';core.mkdir()
        for source, destination in (
            ('mobile/pq/native_factory.go.tmpl', 'protocol/routervpnpq/native_factory.go'),
            ('mobile/pq/endpoint.go.tmpl', 'protocol/routervpnpq/endpoint.go'),
            ('mobile/amnezia/pq_reference_fixture.go.tmpl', 'protocol/routervpnamnezia/pq_reference_fixture.go'),
        ):
            path = core/destination;path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT/source).read_bytes())
        # The pinned core already contains these WireGuard package directories.
        for destination in P.COPIES.values():
            (core/destination).parent.mkdir(parents=True, exist_ok=True)
        library = root/'libroutervpn_rosenpass.a';library.write_bytes(b'test-only-placeholder')
        keys = root/'keys';keys.mkdir()
        return core, library, keys

    def test_exact_source_installed_only_for_bounded_native_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            core, library, keys = self.fixture(Path(tmp))
            def native(command, **kwargs):
                self.assertEqual(command[:2], ['go', 'test'])
                self.assertIn('^TestRealPQTraffic', command)
                self.assertIn('-race', command)
                self.assertEqual(kwargs['timeout'], 180)
                self.assertTrue(kwargs['check'])
                self.assertEqual(kwargs['env']['ROUTERVPN_PQ_TEST_KEYS'], str(keys))
                self.assertEqual(kwargs['cwd'], core)
                for source, destination in P.COPIES.items():
                    self.assertEqual((core/destination).read_bytes(), (ROOT/source).read_bytes())
                self.assertIn('routervpn_pq_traffic_test', command[command.index('-tags')+1])
            with mock.patch.object(P.subprocess, 'check_output', return_value=P.CORE+'\n'), mock.patch.object(P.subprocess, 'run', side_effect=native) as run:
                P.run(core, library, keys);self.assertEqual(run.call_count, 1)
            self.assertTrue(all(not(core/path).exists() for path in P.COPIES.values()))

    def test_failed_native_execution_removes_only_its_new_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            core, library, keys = self.fixture(Path(tmp))
            source, destination = next(iter(P.COPIES.items()))
            existing = core/destination;existing.write_bytes((ROOT/source).read_bytes())
            with mock.patch.object(P.subprocess, 'check_output', return_value=P.CORE), mock.patch.object(P.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'go')):
                with self.assertRaises(subprocess.CalledProcessError):P.run(core, library, keys)
            self.assertEqual(existing.read_bytes(), (ROOT/source).read_bytes())
            self.assertTrue(all(not(core/path).exists() for path in list(P.COPIES.values())[1:]))

    def test_wrong_revision_or_foreign_source_is_never_modified(self):
        with tempfile.TemporaryDirectory() as tmp:
            core, library, keys = self.fixture(Path(tmp))
            with mock.patch.object(P.subprocess, 'check_output', return_value='0'*40), mock.patch.object(P.subprocess, 'run') as run:
                with self.assertRaises(ValueError):P.run(core, library, keys)
                run.assert_not_called()
            bad = core/next(iter(P.COPIES.values()));bad.write_text('foreign source')
            with mock.patch.object(P.subprocess, 'check_output', return_value=P.CORE), mock.patch.object(P.subprocess, 'run') as run:
                with self.assertRaises(ValueError):P.run(core, library, keys)
                run.assert_not_called()
            self.assertEqual(bad.read_text(), 'foreign source')

    def test_test_only_fixture_is_not_in_the_delivered_build(self):
        fixture = (ROOT/'mobile/amnezia/pq_reference_fixture.go.tmpl').read_text()
        self.assertTrue(fixture.startswith('//go:build cgo && routervpn_native_pq && routervpn_pq_traffic_test\n'))
        docker = (ROOT/'deploy/router-agent.Dockerfile').read_text()
        self.assertIn('test_server_pq_traffic.py --core /core', docker)
        build = docker[docker.index(' && CGO_ENABLED=1 CGO_LDFLAGS='):docker.index(' && ! readelf')]
        self.assertNotIn('routervpn_pq_traffic_test', build)
        test = (ROOT/'mobile/pq/native_traffic_test.go.tmpl').read_text()
        self.assertNotIn('t.Skip(', test)
        self.assertIn('reference.PlaintextSeen()', test)
        self.assertIn('ep.InterfaceUpdated(', test)

if __name__ == '__main__':unittest.main()
