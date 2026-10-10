#!/usr/bin/env python3
"""Parent build orchestration tests remain in the parent, not native modules."""
from pathlib import Path
from contextlib import ExitStack
from unittest import mock
import importlib.util
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]

def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),ROOT/'deploy'/name)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

class NativePolicyScope(unittest.TestCase):
    def copied(self,name,stale=None):
        module=load(name)
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as mocks:
            vendor=Path(tmp);(vendor/'go.mod').write_text('module github.com/sagernet/sing-box\n')
            output=vendor/'experimental/libbox/routervpn/applexray';output.mkdir(parents=True)
            parent=output/'preparation_test.go'
            if stale=='old':parent.write_bytes((ROOT/'internal/applexray/preparation_test.go').read_bytes())
            if stale=='foreign':parent.write_text('do not erase unknown test')
            for hook in ('WHITENING','AMNEZIA','MTU','PERFORMANCE','WIREGUARD_BIND'):
                if hasattr(module,hook):mocks.enter_context(mock.patch.object(getattr(module,hook),'prepare'))
            if hasattr(module,'CORE'):
                mocks.enter_context(mock.patch.object(module.subprocess,'check_output',return_value=module.CORE+'\n'))
            if stale=='foreign':
                with self.assertRaises(ValueError):module.prepare(vendor)
                self.assertEqual(parent.read_text(),'do not erase unknown test');return
            module.prepare(vendor)
            self.assertFalse(parent.exists())
            for name in ('config.go','config_test.go','start_layer.go','start_layer_test.go'):
                self.assertEqual((output/name).read_bytes(),(ROOT/'internal/applexray'/name).read_bytes())
            before={str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()}
            module.prepare(vendor)
            self.assertEqual(before,{str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()})
    def test_mobile_copy_does_not_export_parent_build_audits(self):self.copied('prepare-mobile-multihop.py')
    def test_relay_copy_does_not_export_parent_build_audits(self):self.copied('prepare-relay-core.py')
    def test_owned_stale_parent_tests_are_removed(self):
        for name in ('prepare-mobile-multihop.py','prepare-relay-core.py'):self.copied(name,'old')
    def test_foreign_native_files_are_not_deleted(self):
        for name in ('prepare-mobile-multihop.py','prepare-relay-core.py'):self.copied(name,'foreign')
    def test_parent_audits_are_still_executable_source(self):
        source=(ROOT/'internal/applexray/preparation_test.go').read_text()
        for test in ('TestPinnedNativeCompositionAndFailureScope','TestSharedNativeXrayPreparation','TestCorrectedEngineBundleValidation'):
            self.assertIn('func '+test+'(',source)
        self.assertNotIn('t.Skip(',source)
        for name in ('config_test.go','start_layer_test.go','packet_test.go','stream_test.go'):
            self.assertTrue((ROOT/'internal/applexray'/name).is_file())

if __name__=='__main__':unittest.main()
