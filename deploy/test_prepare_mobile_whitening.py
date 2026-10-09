#!/usr/bin/env python3
"""Deterministic Start Layer inclusion and exact-pin failure boundaries."""
from pathlib import Path
from unittest import mock
import importlib.util
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('whitening',ROOT/'deploy/prepare-mobile-whitening.py')
MODULE=importlib.util.module_from_spec(spec);spec.loader.exec_module(MODULE)
class Tests(unittest.TestCase):
    def fixture(self,root):
        p=root/'include';p.mkdir(parents=True)
        (p/'registry.go').write_text('import (\n\t"github.com/sagernet/sing-box/protocol/shadowsocks"\n)\nfunc register() {\n\tshadowsocks.RegisterOutbound(registry)\n}\n')
    def test_actual_transport_and_policy_are_copied_exactly(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            with mock.patch.object(MODULE,'checkout') as check, mock.patch.object(MODULE.STREAM,'prepare') as stream:MODULE.prepare(root);check.assert_called_once_with(root.resolve())
            initial={str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            with mock.patch.object(MODULE,'checkout'), mock.patch.object(MODULE.STREAM,'prepare'):MODULE.prepare(root)
            self.assertEqual(initial,{str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()})
            self.assertEqual((root/'protocol/routervpnwhitening/outbound.go').read_bytes(),(ROOT/'mobile/startwhitening/outbound.go.tmpl').read_bytes())
            self.assertEqual((root/'experimental/libbox/routervpn/startwhitening/conn.go').read_bytes(),(ROOT/'internal/startwhitening/conn.go').read_bytes())
    def test_checkout_uses_canonical_path_through_directory_alias(self):
        with tempfile.TemporaryDirectory() as temp:
            parent=Path(temp);actual=parent/'source';self.fixture(actual)
            alias=parent/'alias'
            try:alias.symlink_to(actual,target_is_directory=True)
            except (OSError,NotImplementedError):self.skipTest('directory symlink unavailable on this host')
            with mock.patch.object(MODULE,'checkout') as check, mock.patch.object(MODULE.STREAM,'prepare') as stream:
                MODULE.prepare(alias)
                check.assert_called_once_with(actual.resolve())
            self.assertEqual((actual/'protocol/routervpnwhitening/outbound.go').read_bytes(),
                             (ROOT/'mobile/startwhitening/outbound.go.tmpl').read_bytes())
    def test_wrong_pin_never_changes_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root);before=(root/'include/registry.go').read_bytes()
            with mock.patch.object(MODULE,'checkout',side_effect=ValueError('wrong pin')):
                with self.assertRaises(ValueError):MODULE.prepare(root)
            self.assertEqual((root/'include/registry.go').read_bytes(),before)
            self.assertFalse((root/'protocol').exists())
    def test_registration_drift_is_not_duplicated(self):
        for text in ('X','A\nA','A\nother\nB','A\nB\nB'):
            with self.subTest(text=text),self.assertRaises(ValueError):MODULE.replace_once(text,'A','A\nB')
class StreamPolicy(unittest.TestCase):
    def test_exact_upstream_pin_and_all_or_nothing_transformation(self):
        policy=MODULE.STREAM
        self.assertEqual(policy.SOURCE_SHA,'10dd204d5f2516e5e7501c610484ed7103c8884f')
        fixture='package shadowsocks\nfunc dial() { '+policy.OLD+' }\n'
        with mock.patch.object(policy,'SOURCE_SHA',policy.blobsha(fixture.encode())):
            corrected=policy.patch(fixture)
            self.assertEqual(policy.patch(corrected),corrected)
            self.assertIn('routerVPNGuardStream(outConn, h.method.DialEarlyConn(outConn, destination))',corrected)
            for changed in (fixture+'drift',corrected+'drift',corrected.replace('routerVPNGuardStream','wrongGuard')):
                with self.assertRaises(ValueError):policy.patch(changed)
        with self.assertRaises(ValueError):policy.patch(fixture)
    def test_helper_is_installed_in_the_correct_package(self):
        policy=MODULE.STREAM
        fixture='package shadowsocks\nfunc dial() { '+policy.OLD+' }\n'
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(policy,'SOURCE_SHA',policy.blobsha(fixture.encode())):
            core=Path(tmp);source=core/'protocol/shadowsocks/outbound.go';source.parent.mkdir(parents=True)
            source.write_text(fixture)
            policy.prepare(core)
            helper=source.with_name('routervpn_stream_guard.go')
            self.assertEqual(helper.read_bytes(),(ROOT/'mobile/startwhitening/ss_stream_guard.go.tmpl').read_bytes())
            self.assertTrue(helper.read_text().startswith('package shadowsocks'))
            snapshot=(source.read_bytes(),helper.read_bytes())
            policy.prepare(core)
            self.assertEqual(snapshot,(source.read_bytes(),helper.read_bytes()))
            source.write_text(fixture+'drift')
            with self.assertRaises(ValueError):policy.prepare(core)
            self.assertEqual(helper.read_bytes(),snapshot[1])
    def test_source_and_helper_symlinks_are_never_followed(self):
        policy=MODULE.STREAM
        for which in ('outbound.go','routervpn_stream_guard.go'):
            with tempfile.TemporaryDirectory() as tmp:
                core=Path(tmp);directory=core/'protocol/shadowsocks';directory.mkdir(parents=True)
                target=core/'foreign';target.write_text('unchanged')
                try:(directory/which).symlink_to(target)
                except (OSError,NotImplementedError):continue
                with self.assertRaises(ValueError):policy.prepare(core)
                self.assertEqual(target.read_text(),'unchanged')
    def test_guard_is_in_the_native_build_cache_key(self):
        paths=MODULE.inputs()
        self.assertIn(ROOT/'deploy/mobile_shadowsocks_stream_policy.py',paths)
        self.assertIn(ROOT/'internal/startwhitening/stream_guard.go',paths)
        self.assertIn(ROOT/'internal/startwhitening/stream_guard_test.go',paths)

if __name__=='__main__':unittest.main()
