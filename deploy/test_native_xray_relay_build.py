#!/usr/bin/env python3
from pathlib import Path
from unittest import mock
import importlib.util
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('relaycore',ROOT/'deploy/prepare-relay-core.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
class NativeRelayBuild(unittest.TestCase):
    def test_exact_xray_and_guard_are_prepared_before_native_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            core=Path(tmp)/'core';xray=Path(tmp)/'xray';core.mkdir();xray.mkdir();(xray/'LICENSE').write_text('license fixture\n'*20)
            with mock.patch.object(M.XRAY,'checkout') as checkout, mock.patch.object(M,'prepare') as policy, mock.patch.object(M.XRAY,'prepare') as native, mock.patch.object(M.WHITENING,'prepare') as stream, mock.patch.object(M.subprocess,'run') as run:
                M.prepare_native(core,xray)
                self.assertEqual(checkout.call_count,2)
                checkout.assert_any_call(core,M.CORE,'github.com/sagernet/sing-box')
                checkout.assert_any_call(xray,M.XRAY.XRAY_PIN,'github.com/xtls/xray-core')
                policy.assert_called_once_with(core);native.assert_called_once_with(core,xray);stream.assert_called_once_with(core)
                self.assertEqual(run.call_count,2)
                self.assertIn('github.com/xtls/xray-core='+str(xray),run.call_args_list[1].args[0][-1])
            self.assertEqual((core/'routervpn-xray-LICENSE.txt').read_bytes(),(xray/'LICENSE').read_bytes())
    def test_cli_requires_both_pinned_checkouts_and_digest_covers_sources(self):
        source=(ROOT/'deploy/prepare-relay-core.py').read_text()
        self.assertIn('args.vendor and args.xray',source)
        inputs=M.inputs();self.assertEqual(len(inputs),len(set(inputs)))
        for p in (ROOT/'mobile/applexray/outbound.go.tmpl',ROOT/'deploy/prepare-apple-xray.py',ROOT/'internal/applexray/native_transport.go',ROOT/'internal/startwhitening/stream_guard.go'):
            self.assertIn(p,inputs)
        docker=(ROOT/'deploy/router-agent.Dockerfile').read_text()
        self.assertIn('ARG RELAY_XRAY_COMMIT='+M.XRAY.XRAY_PIN,docker)
        self.assertIn('prepare-relay-core.py /core /xray-core',docker)
        self.assertIn('-checklinkname=0',docker)
        self.assertIn('TestExportPinnedCore(Relay|XrayRelay)Configurations',docker)
        self.assertIn('routervpn-xray-LICENSE.txt',docker)
        self.assertIn('sing-box check -c',docker)
if __name__=='__main__':unittest.main()
