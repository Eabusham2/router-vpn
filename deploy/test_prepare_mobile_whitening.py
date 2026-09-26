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
            with mock.patch.object(MODULE,'checkout') as check:MODULE.prepare(root);check.assert_called_once_with(root.resolve())
            initial={str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            with mock.patch.object(MODULE,'checkout'):MODULE.prepare(root)
            self.assertEqual(initial,{str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()})
            self.assertEqual((root/'protocol/routervpnwhitening/outbound.go').read_bytes(),(ROOT/'mobile/startwhitening/outbound.go.tmpl').read_bytes())
            self.assertEqual((root/'experimental/libbox/routervpn/startwhitening/conn.go').read_bytes(),(ROOT/'internal/startwhitening/conn.go').read_bytes())
    def test_checkout_uses_canonical_path_through_directory_alias(self):
        with tempfile.TemporaryDirectory() as temp:
            parent=Path(temp);actual=parent/'source';self.fixture(actual)
            alias=parent/'alias'
            try:alias.symlink_to(actual,target_is_directory=True)
            except (OSError,NotImplementedError):self.skipTest('directory symlink unavailable on this host')
            with mock.patch.object(MODULE,'checkout') as check:
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
if __name__=='__main__':unittest.main()
