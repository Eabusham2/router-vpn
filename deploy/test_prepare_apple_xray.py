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

VISION = '''
var p uintptr
p = uintptr(unsafe.Pointer(commonConn))
p = uintptr(unsafe.Pointer(tlsConn.Conn))
p = uintptr(unsafe.Pointer(utlsConn.Conn))
p = uintptr(unsafe.Pointer(realityConn.Conn))
\t\t\ti, _ := t.FieldByName("input")
\t\t\tr, _ := t.FieldByName("rawInput")
input = (*bytes.Reader)(unsafe.Pointer(p + i.Offset))
rawInput = (*bytes.Buffer)(unsafe.Pointer(p + r.Offset))
'''

class Prepare(unittest.TestCase):
    def fixture(self,tmp):
        sing=Path(tmp)/'sing';xray=Path(tmp)/'xray'
        for root,path in ((sing,'include'),(sing,'experimental/libbox'),(xray,'core'),(xray,'transport/internet/reality'),(xray,'proxy/vless/outbound')):
            (root/path).mkdir(parents=True,exist_ok=True)
        (sing/'include/registry.go').write_text('import (\n\t"github.com/sagernet/sing-box/protocol/vless"\n)\nfunc register() {\n\tvless.RegisterOutbound(registry)\n}\n')
        (xray/'transport/internet/reality/reality.go').write_text('package reality\nfunc client() {\n\tif !uConn.Verified {\n\t\tlegacySpider()\n\t}\n}\n')
        (xray/'proxy/vless/outbound/outbound.go').write_text(VISION)
        for name,pairs in MODULE.DATAGRAMS.PATCHES.items():
            path=xray/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('\n'.join(old for old,_ in pairs))
        for name,pairs in MODULE.CONNECTIONS.PATCHES.items():
            path=xray/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('\n'.join(old if old!='c.closed = true' else (old+'\n')*3 for old,_ in pairs))
        return sing,xray
    def run_prepare(self,sing,xray):
        with mock.patch.object(MODULE,'checkout') as check, mock.patch.object(MODULE.SHARED,'checkout'):
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
    def test_vision_pointer_checks_are_kept_not_suppressed(self):
        patched = MODULE.patch_vision_buffers(VISION)
        self.assertEqual(MODULE.patch_vision_buffers(patched), patched)
        self.assertNotIn('uintptr', patched)
        self.assertIn('unsafe.Add(p, i.Offset)', patched)
        self.assertIn('i.Type != reflect.TypeOf(bytes.Reader{})', patched)
        self.assertIn('r.Type != reflect.TypeOf(bytes.Buffer{})', patched)
        self.assertNotIn('nocheckptr', patched)
        with self.assertRaises(ValueError):
            MODULE.patch_vision_buffers(patched.replace('unsafe.Add(p, i.Offset)', 'unsafe.Pointer(p)'))
        with self.assertRaises(ValueError):
            MODULE.patch_vision_buffers(VISION.replace('realityConn.Conn', 'different(pointer)'))
    def test_datagram_patch_is_bounded_and_idempotent(self):
        for name,pairs in MODULE.DATAGRAMS.PATCHES.items():
            with self.subTest(path=name):
                old='\n'.join(before for before,_ in pairs)
                new=MODULE.DATAGRAMS.patch_text(name,old)
                self.assertEqual(MODULE.DATAGRAMS.patch_text(name,new),new)
                with self.assertRaises(ValueError):MODULE.DATAGRAMS.patch_text(name,'unrelated source')
        text='\n'.join(after for pairs in MODULE.DATAGRAMS.PATCHES.values() for _,after in pairs)
        self.assertIn('length > 65535',text)
        self.assertIn('b.UDP = address',text)
        self.assertIn('NewWithSize(65535)',text)

    def test_connection_corrections_are_exact_and_idempotent(self):
        for name,pairs in MODULE.CONNECTIONS.PATCHES.items():
            before='\n'.join(old if old!='c.closed = true' else (old+'\n')*3 for old,_ in pairs)
            after=MODULE.CONNECTIONS.patch_text(name,before)
            self.assertEqual(MODULE.CONNECTIONS.patch_text(name,after),after)
            with self.assertRaises(ValueError):MODULE.CONNECTIONS.patch_text(name,'changed source')
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
            with mock.patch.object(MODULE,'checkout'),mock.patch.object(MODULE.SHARED,'checkout'),self.assertRaises(ValueError):MODULE.prepare(sing,xray)

if __name__=='__main__':unittest.main()
