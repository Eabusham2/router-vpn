#!/usr/bin/env python3
"""Keep native baseline source readback tied to each original repository owner."""
from pathlib import Path
import hashlib
import importlib.util
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('baseline_source_authority', ROOT / 'deploy/test_desktop_node_physical.py')
NODE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NODE)


class BaselineAuthority(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='routervpn-baseline-authority-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repository, self.source, self.workspace = (self.root / name for name in ('repository', 'native', 'outputs'))
        for path in (self.repository, self.source, self.workspace):
            path.mkdir()
        # Retain real repository bytes and every supported record category;
        # only their owned fixture location changes. No source check is mocked.
        categories = {
            'runner': 'deploy/test_desktop_node_physical.py',
            'cronet-packaging': 'deploy/build-native-runtime.py',
            'namespace-launcher': 'deploy/test_desktop_socket_uid.py',
            'routing-runner': 'deploy/test_desktop_node_routing_runner.py',
            'layer-reference/go.mod': 'go.mod',
            'layer-reference/cmd/start-layer-relay/main.go': 'cmd/start-layer-relay/main.go',
            'gate/deploy/prepare-amnezia-timers.py': 'deploy/prepare-amnezia-timers.py',
            'gate/deploy/test_amnezia_timers_pinned.py': 'deploy/test_amnezia_timers_pinned.py',
            'gate/deploy/test_amnezia_timer_preparation.py': 'deploy/test_amnezia_timer_preparation.py',
            'gate/mobile/amneziatimers/timers_test.go.tmpl': 'mobile/amneziatimers/timers_test.go.tmpl',
        }
        self.paths = {}
        for key, relative in categories.items():
            target = self.repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())
            self.paths[key] = target
        for key, original in (('go.mod', 'go.mod'), ('protocol/native.go', 'internal/hopmeasure/public.go')):
            target = self.source / key
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / original).read_bytes())
            self.paths[key] = target
        self.records = {key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in self.paths.items()}
        owner = mock.patch.object(NODE, 'ROOT', self.repository)
        filename = mock.patch.object(NODE, '__file__', str(self.paths['runner']))
        owner.start()
        filename.start()
        self.addCleanup(owner.stop)
        self.addCleanup(filename.stop)
        self.baseline = NODE.BaselineBinaries(self.source, self.workspace, ['owned-go', 'test', '-c'],
                                              {'GOWORK': 'off'}, self.records)

    def decoy(self, key):
        target = self.source / key
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.paths[key].read_bytes())
        return target

    def test_complete_original_record_map_passes_without_native_core_gate_copies(self):
        self.assertFalse((self.source / 'gate').exists())
        self.baseline.check_inputs()
        self.assertFalse((self.source / 'gate').exists())

    def test_native_core_gate_lookalikes_cannot_replace_changed_or_missing_authorities(self):
        for key in sorted(key for key in self.paths if key.startswith('gate/')):
            with self.subTest(key=key):
                authority = self.paths[key]
                original = authority.read_bytes()
                decoy = self.decoy(key)
                authority.write_bytes(original + b'\nchanged original owner\n')
                with self.assertRaisesRegex(ValueError, 'captured source input: ' + key):
                    self.baseline.check_inputs()
                authority.unlink()
                with self.assertRaisesRegex(ValueError, 'captured source input: ' + key):
                    self.baseline.check_inputs()
                authority.write_bytes(original)
                self.baseline.check_inputs()
                self.assertEqual(decoy.read_bytes(), original)

    def test_symlinked_gate_cannot_borrow_identical_original_bytes(self):
        key = 'gate/deploy/prepare-amnezia-timers.py'
        authority = self.paths[key]
        other = self.root / 'other-owner.py'
        original = authority.read_bytes()
        other.write_bytes(original)
        authority.unlink()
        authority.symlink_to(other)
        with self.assertRaisesRegex(ValueError, 'captured source input: ' + key):
            self.baseline.check_inputs()
        self.assertEqual(other.read_bytes(), original)

    def test_layer_reference_keeps_its_original_repository_owner(self):
        key = 'layer-reference/cmd/start-layer-relay/main.go'
        authority = self.paths[key]
        original = authority.read_bytes()
        decoy = self.decoy(key)
        authority.write_bytes(original + b'\n// changed original layer source\n')
        with self.assertRaisesRegex(ValueError, 'captured source input: ' + key):
            self.baseline.check_inputs()
        authority.write_bytes(original)
        self.baseline.check_inputs()
        self.assertEqual(decoy.read_bytes(), original)

    def test_native_source_remains_owned_by_the_disposable_core(self):
        key = 'protocol/native.go'
        authority = self.paths[key]
        original = authority.read_bytes()
        decoy = self.repository / key
        decoy.parent.mkdir(parents=True)
        decoy.write_bytes(original)
        authority.write_bytes(original + b'\n// changed native implementation\n')
        with self.assertRaisesRegex(ValueError, 'captured source input: ' + key):
            self.baseline.check_inputs()
        authority.write_bytes(original)
        self.baseline.check_inputs()
        self.assertEqual(decoy.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
