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

class CompositeShipping(unittest.TestCase):
    def fixture(self, path):
        core = Path(path)
        (core/'go.mod').write_text('module github.com/sagernet/sing-box\n')
        (core/'include').mkdir()
        (core/'include/registry.go').write_text('import (\n\t"github.com/sagernet/sing-box/protocol/group"\n)\nfunc register() {\n\tgroup.RegisterURLTest(registry)\n}\n')
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
                if fault == 'registry': registry.write_text(registry.read_text().replace('group.RegisterURLTest', 'changed.RegisterURLTest'))
                if fault == 'duplicate': registry.write_text(registry.read_text()+'\nroutervpncomposite.RegisterOutbound(registry)\n')
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

if __name__ == '__main__': unittest.main()
