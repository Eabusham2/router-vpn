#!/usr/bin/env python3
"""Exercise exact native composite installation and both shipping traffic gates."""
from pathlib import Path
import importlib.util
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_composite', ROOT/'deploy/prepare-mobile-composite.py')
PREPARE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREPARE)
gate_spec = importlib.util.spec_from_file_location('native_ordered_gate', ROOT/'deploy/prepare-node-chain-execution-gate.py')
GATE = importlib.util.module_from_spec(gate_spec)
gate_spec.loader.exec_module(GATE)

class CompositeShipping(unittest.TestCase):
    def fixture(self, path):
        core = Path(path)
        (core/'go.mod').write_text('module github.com/sagernet/sing-box\n')
        (core/'include').mkdir()
        (core/'include/registry.go').write_bytes(b'import (\n\t"github.com/sagernet/sing-box/protocol/group"\n)\nfunc register() {\n\tgroup.RegisterURLTest(registry)\n}\n')
        return core

    def test_native_source_and_tests_are_exact_and_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            core = self.fixture(temp)
            with mock.patch.object(PREPARE.subprocess, 'check_output', return_value=PREPARE.PIN+'\n'):
                PREPARE.prepare(core)
                before = {str(p.relative_to(core)):p.read_bytes() for p in core.rglob('*') if p.is_file()}
                PREPARE.prepare(core)
                self.assertEqual(before, {str(p.relative_to(core)):p.read_bytes() for p in core.rglob('*') if p.is_file()})
            for source in (ROOT/'mobile/composite').glob('*.tmpl'):
                self.assertEqual(source.read_bytes(), (core/'protocol/routervpncomposite'/source.stem).read_bytes())
            self.assertEqual((core/'include/registry.go').read_text().count('routervpncomposite.RegisterOutbound(registry)'), 1)
            for source in ('outbound.go.tmpl','outbound_test.go.tmpl','traffic_test.go.tmpl','xray_traffic_test.go.tmpl'):
                self.assertIn(ROOT/'mobile/composite'/source, PREPARE.inputs())

    def test_changed_registry_or_linked_target_fails_before_writes(self):
        for fault in ('pin','module','registry','duplicate','target-link','source-link'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                core = self.fixture(temp)
                registry = core/'include/registry.go'
                if fault == 'module': (core/'go.mod').write_text('module unowned\n')
                if fault == 'registry': registry.write_bytes(registry.read_text().replace('group.RegisterURLTest', 'changed.RegisterURLTest').encode())
                if fault == 'duplicate': registry.write_bytes((registry.read_text()+'\nroutervpncomposite.RegisterOutbound(registry)\n').encode())
                target = core/'protocol/routervpncomposite'
                if fault in ('target-link','source-link'):
                    (core/'unowned').mkdir()
                    target.parent.mkdir()
                    if fault == 'target-link': target.symlink_to(core/'unowned', target_is_directory=True)
                    else:
                        target.mkdir()
                        (core/'unowned/source.go').write_text('unowned fixture')
                        (target/'outbound.go').symlink_to(core/'unowned/source.go')
                before = {str(p.relative_to(core)):p.read_bytes() for p in core.rglob('*') if p.is_file() and not p.is_symlink()}
                with mock.patch.object(PREPARE.subprocess, 'check_output', return_value=('changed' if fault=='pin' else PREPARE.PIN)+'\n'):
                    with self.assertRaises(ValueError): PREPARE.prepare(core)
                self.assertEqual(before, {str(p.relative_to(core)):p.read_bytes() for p in core.rglob('*') if p.is_file() and not p.is_symlink()})

    def test_both_mobile_packages_require_real_encrypted_lanes(self):
        sip = (ROOT/'deploy/test_mobile_sip003_pinned.sh').read_text()
        self.assertIn('bash "$ROOT/deploy/test_mobile_composite_pinned.sh" "$VENDOR"', sip)
        self.assertIn('./protocol/routervpnsip003test', sip)
        for path in ('android/build-sing-box-libbox.sh','ios/RouterVPN/prepare-libbox.sh'):
            self.assertIn('test_mobile_sip003_pinned.sh', (ROOT/path).read_text())
        gate = (ROOT/'deploy/test_mobile_composite_pinned.sh').read_text()
        self.assertIn(PREPARE.PIN, gate)
        self.assertIn('50231eaff98ccc31b5cbd247a721c16e97fe5ec1', gate)
        self.assertIn('-race -mod=readonly', gate)
        self.assertIn('with_low_memory', gate)
        self.assertIn('Original shared Xray session did not fail', gate)
        self.assertIn('source.write_bytes(original)', gate)
        self.assertNotIn('t.Skip', (ROOT/'mobile/composite/traffic_test.go.tmpl').read_text())
        self.assertNotIn('t.Skip', (ROOT/'mobile/composite/xray_traffic_test.go.tmpl').read_text())

    def gate_fixture(self, path):
        core = self.fixture(path)
        registry = core/'include/registry.go'
        registry.write_bytes(registry.read_text().replace('func register() {', 'func OutboundRegistry() *outbound.Registry {').replace(
            '\tgroup.RegisterURLTest(registry)', '\tgroup.RegisterSelector(registry)\n\tgroup.RegisterURLTest(registry)').encode())
        for relative, template in GATE.PREREQUISITES.items():
            target = core/relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT/template).read_bytes())
        return core

    def test_mobile_repeated_gate_and_composite_preparation(self):
        # The APK's SIP003 acceptance reruns mobile preparation after the
        # first complete build preparation; desktop may install composite first.
        for first in ((GATE, PREPARE), (PREPARE, GATE)):
            with self.subTest(first=first[0].__name__), tempfile.TemporaryDirectory() as temp:
                core = self.gate_fixture(temp)
                with mock.patch.object(PREPARE.subprocess, 'check_output', return_value=PREPARE.PIN+'\n'):
                    for module in first:
                        module.prepare(core)
                    before = {str(p.relative_to(core)):p.read_bytes() for p in core.rglob('*') if p.is_file()}
                    for _ in range(3):
                        GATE.prepare(core)
                        PREPARE.prepare(core)
                    self.assertEqual(before, {str(p.relative_to(core)):p.read_bytes() for p in core.rglob('*') if p.is_file()})
                source = (core/'include/registry.go').read_text()
                self.assertNotIn(b'\r', (core/'include/registry.go').read_bytes())
                self.assertEqual(source.count(GATE.REGISTER), 1)
                self.assertEqual(source.count('routervpncomposite.RegisterOutbound(registry)'), 1)

    def test_windows_text_translation_preserves_actual_composed_source(self):
        original = Path.write_text
        def windows_text(path, data, *args, **kwargs):
            kwargs.setdefault('newline', '\r\n')
            return original(path, data, *args, **kwargs)
        with mock.patch.object(Path, 'write_text', windows_text):
            self.test_mobile_repeated_gate_and_composite_preparation()
            self.test_composed_import_neighbours_do_not_accept_foreign_or_moved_sources()

    def test_composed_import_neighbours_do_not_accept_foreign_or_moved_sources(self):
        for first in ((GATE, PREPARE), (PREPARE, GATE)):
            with tempfile.TemporaryDirectory() as temp:
                core = self.gate_fixture(temp)
                with mock.patch.object(PREPARE.subprocess, 'check_output', return_value=PREPARE.PIN+'\n'):
                    for module in first:
                        module.prepare(core)
                    registry = core/'include/registry.go'
                    original = registry.read_text()
                    faults = {
                        'foreign-between-imports': original.replace(GATE.IMPORT, '\t"foreign/module"\n'+GATE.IMPORT),
                        'duplicate-gate-import': original.replace(GATE.IMPORT, GATE.IMPORT*2),
                        'duplicate-composite-import': original.replace(GATE.COMPOSITE_IMPORT, GATE.COMPOSITE_IMPORT*2),
                        'gate-import-outside-block': original.replace(GATE.IMPORT, '')+GATE.IMPORT,
                        'gate-registration-outside-registry': original.replace(GATE.REGISTER, '')+GATE.REGISTER,
                        'composite-registration-moved': original.replace('\troutervpncomposite.RegisterOutbound(registry)\n', '')+'\troutervpncomposite.RegisterOutbound(registry)\n',
                    }
                    for label, broken in faults.items():
                        with self.subTest(first=first[0].__name__, fault=label):
                            registry.write_bytes(broken.encode())
                            before = {str(p.relative_to(core)):p.read_bytes() for p in core.rglob('*') if p.is_file()}
                            with self.assertRaises(ValueError):
                                GATE.prepare(core)
                                PREPARE.prepare(core)
                            self.assertEqual(before, {str(p.relative_to(core)):p.read_bytes() for p in core.rglob('*') if p.is_file()})

if __name__ == '__main__': unittest.main()
