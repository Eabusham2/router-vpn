#!/usr/bin/env python3
"""Check deterministic native-engine composition; actual core builds run in CI."""
from pathlib import Path
from unittest import mock
import importlib.util
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('prepare_xray',ROOT/'deploy/prepare-apple-xray.py')
MODULE=importlib.util.module_from_spec(spec);spec.loader.exec_module(MODULE)

class Prepare(unittest.TestCase):
    def fixture(self,tmp):
        sing=Path(tmp)/'sing';xray=Path(tmp)/'xray'
        for root,path in ((sing,'include'),(sing,'experimental/libbox'),(xray,'core'),(xray,'transport/internet/reality')):
            (root/path).mkdir(parents=True,exist_ok=True)
        (sing/'include/registry.go').write_text('import (\n\t"github.com/sagernet/sing-box/protocol/vless"\n)\nfunc register() {\n\tvless.RegisterOutbound(registry)\n}\n')
        (xray/'transport/internet/reality/reality.go').write_text('package reality\nfunc client() {\n\tif !uConn.Verified {\n\t\tlegacySpider()\n\t}\n}\n')
        return sing,xray
    def run_prepare(self,sing,xray):
        with mock.patch.object(MODULE,'checkout') as check:
            MODULE.prepare(sing,xray)
            self.assertEqual(check.call_count,2)
    def test_deterministic_composition_and_instance_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            sing,xray=self.fixture(tmp);self.run_prepare(sing,xray)
            before={str(p.relative_to(tmp)):p.read_bytes() for p in Path(tmp).rglob('*') if p.is_file()}
            self.run_prepare(sing,xray)
            after={str(p.relative_to(tmp)):p.read_bytes() for p in Path(tmp).rglob('*') if p.is_file()}
            self.assertEqual(before,after)
            core=(xray/'core/routervpn_packet.go').read_text()
            self.assertIn('instance.ctx.Value(routerVPNNativeContextKey{}) == true',core)
            reality=(xray/'transport/internet/reality/reality.go').read_text()
            self.assertLess(reality.index('core.RouterVPNIsNativeContext(ctx)'),reality.index('legacySpider()'))
            self.assertIn('_ = uConn.Close()',reality)
            self.assertIn('legacySpider()',reality,'ordinary upstream instance behavior must not be rewritten')
            native=(sing/'protocol/routervpnxray/outbound.go').read_text()
            self.assertIn('xcore.NewWithContext(xcore.RouterVPNNativeContext(h.ctx), cfg)',native)
            self.assertIn('internet.UseAlternativeSystemDialer(systemDialer{})',native)
            self.assertIn('bindings.Delete(instance)',native)
    def test_wrong_revision_fails_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            sing,xray=self.fixture(tmp)
            with mock.patch.object(MODULE,'checkout',side_effect=ValueError('wrong pin')):
                with self.assertRaises(ValueError): MODULE.prepare(sing,xray)
            self.assertFalse((sing/'protocol/routervpnxray').exists())
    def test_moved_or_duplicate_registration_is_rejected(self):
        for text in ('no anchor','A\nA', 'A\nother\nB'):
            with self.subTest(text=text),self.assertRaises(ValueError):MODULE.insert_once(text,'A','B','test')
    def test_guard_drift_is_not_silently_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            sing,xray=self.fixture(tmp);self.run_prepare(sing,xray)
            file=xray/'transport/internet/reality/reality.go'
            file.write_text(file.read_text().replace('_ = uConn.Close()','weakenedClose()'))
            with mock.patch.object(MODULE,'checkout'),self.assertRaises(ValueError):MODULE.prepare(sing,xray)

if __name__=='__main__':unittest.main()
