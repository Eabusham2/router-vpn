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
            (core/'go.mod').write_text('module github.com/sagernet/sing-box\n')
            (xray/'go.mod').write_text('module github.com/xtls/xray-core\n')
            def captured_identity(command,**kwargs):
                # The actual checkout validator runs against complete module
                # identities. Only Git metadata is a fixture; native patchers
                # have separate pinned source/executable integration gates.
                for path,pin in ((core,M.CORE),(xray,M.XRAY.XRAY_PIN)):
                    if command==['git','-C',str(path),'rev-parse','HEAD'] and kwargs=={'text':True}:
                        return pin+'\n'
                raise AssertionError('Unexpected checkout metadata read: '+repr(command))
            with mock.patch.object(M.subprocess,'check_output',side_effect=captured_identity), mock.patch.object(M.HY2_DEADLINES,'prepare') as hy2_deadlines, mock.patch.object(M.XRAY,'checkout',wraps=M.XRAY.checkout) as checkout, mock.patch.object(M,'prepare') as policy, mock.patch.object(M.XRAY,'prepare') as native, mock.patch.object(M.WHITENING,'prepare') as stream, mock.patch.object(M.PQ,'prepare') as pq, mock.patch.object(M.COMPOSITE,'prepare') as composite, mock.patch.object(M.OPENVPN_CLOSE,'prepare') as openvpn, mock.patch.object(M.STRATEGY,'prepare') as strategy, mock.patch.object(M.SERVER_TOR,'prepare') as tor, mock.patch.object(M.subprocess,'run') as run:
                M.prepare_native(core,xray)
                self.assertEqual(checkout.call_count,2)
                checkout.assert_any_call(core,M.CORE,'github.com/sagernet/sing-box')
                checkout.assert_any_call(xray,M.XRAY.XRAY_PIN,'github.com/xtls/xray-core')
                policy.assert_called_once_with(core);native.assert_called_once_with(core,xray);stream.assert_called_once_with(core);pq.assert_called_once_with(core)
                hy2_deadlines.assert_called_once_with(core)
                composite.assert_called_once_with(core)
                openvpn.assert_called_once_with(core)
                strategy.assert_called_once_with(core,mobile=False)
                tor.assert_called_once_with(core)
                self.assertEqual(run.call_count,2)
                self.assertIn('github.com/xtls/xray-core='+str(xray),run.call_args_list[1].args[0][-1])
            self.assertEqual((core/'routervpn-xray-LICENSE.txt').read_bytes(),(xray/'LICENSE').read_bytes())
    def test_ordinary_awg_preparation_emits_original_openvpn_transport_owner(self):
        remote=M.OPENVPN_REMOTE;close=M.OPENVPN_CLOSE
        original='package fixture\n'+close.OLD+'\n'+''.join(before*count for before,after,count in remote.CHANGES)
        server='package fixture\nfunc closeServer() {\n'+close.SERVER_OLD+'\n}\n'
        # Model only the pinned upstream fixture identity and unrelated module
        # preparation. Execute the actual ordinary AWG entrypoint and both
        # shipping OpenVPN transformations, helper projection and verification.
        with tempfile.TemporaryDirectory() as tmp:
            core=Path(tmp).resolve();directory=core/'protocol/openvpn';directory.mkdir(parents=True)
            (core/'cmd/sing-box').mkdir(parents=True)
            (core/'go.mod').write_bytes(b'module github.com/sagernet/sing-box\n')
            client=directory/'client.go';client.write_bytes(original.encode())
            (directory/'server.go').write_bytes(server.encode())
            def captured_identity(command,**kwargs):
                self.assertEqual(command,['git','-C',str(core),'rev-parse','HEAD'])
                self.assertEqual(kwargs,{'text':True})
                return M.CORE+'\n'
            with mock.patch.object(M.subprocess,'check_output',side_effect=captured_identity), \
                    mock.patch.object(M.AMNEZIA,'prepare'), \
                    mock.patch.object(remote.MODULE,'prepare'),mock.patch.object(remote.LAYERS,'prepare'), \
                    mock.patch.object(remote.STACK,'prepare'), \
                    mock.patch.object(remote,'SOURCE_SHA',close.blobsha(original.encode())), \
                    mock.patch.object(close,'SOURCE_SHA',close.blobsha(original.encode())), \
                    mock.patch.object(close.REMOTE,'SOURCE_SHA',close.blobsha(original.encode())), \
                    mock.patch.object(close,'SERVER_SOURCE_SHA',close.blobsha(server.encode())):
                for attempt in range(2):
                    M.prepare(core)
                    helper=directory/'routervpn_close_policy.go'
                    self.assertTrue(helper.is_file(),'ordinary AWG preparation omitted original OpenVPN transport owner')
                    self.assertEqual(helper.read_bytes(),(ROOT/'mobile/openvpn/close_policy.go.tmpl').read_bytes())
                    self.assertEqual(client.read_bytes(),remote.patch(close.patch(original)).encode())
                    self.assertEqual((directory/'server.go').read_bytes(),close.patch_server(server).encode())
                    self.assertEqual(set(close.verify(core)),{'protocol/openvpn/client.go','protocol/openvpn/server.go','protocol/openvpn/routervpn_close_policy.go'})
                # A pre-existing foreign helper remains an error; preparation
                # cannot overwrite it to make the newly required dependency fit.
                before=client.read_bytes();helper.write_bytes(helper.read_bytes()+b'foreign owner\n')
                with self.assertRaisesRegex(ValueError,'helper differs'):
                    M.prepare(core)
                self.assertEqual(client.read_bytes(),before)
                self.assertTrue(helper.read_bytes().endswith(b'foreign owner\n'))

    def test_cli_requires_both_pinned_checkouts_and_digest_covers_sources(self):
        source=(ROOT/'deploy/prepare-relay-core.py').read_text()
        self.assertIn('args.vendor and args.xray',source)
        inputs=M.inputs();self.assertEqual(len(inputs),len(set(inputs)))
        for p in (ROOT/'mobile/applexray/outbound.go.tmpl',ROOT/'deploy/prepare-apple-xray.py',ROOT/'internal/applexray/native_transport.go',ROOT/'internal/startwhitening/stream_guard.go',ROOT/'internal/nativecomposite/plan.go',ROOT/'internal/nativesip003/compile.go',ROOT/'mobile/composite/outbound.go.tmpl',ROOT/'deploy/prepare-server-tor.py',ROOT/'mobile/server_tor/native.go.tmpl'):
            self.assertIn(p,inputs)
        for path in (ROOT/'internal/linuxprocess').glob('*.go'):
            self.assertIn(path,inputs)
        docker=(ROOT/'deploy/router-agent.Dockerfile').read_text()
        self.assertIn('ARG RELAY_XRAY_COMMIT='+M.XRAY.XRAY_PIN,docker)
        self.assertIn('prepare-relay-core.py /core /xray-core',docker)
        self.assertIn('-checklinkname=0',docker)
        self.assertIn('TestExportPinnedCore(Relay|XrayRelay|PQRelay|NaiveRelay|CompositeRelay|MAXRelay)Configurations\' ./internal/multihoprelay ./internal/mobilemultihop',docker)
        self.assertIn('routervpn-xray-LICENSE.txt',docker)
        self.assertIn('sing-box check -c',docker)
        for source in ('deploy/prepare-server-pq.py', 'mobile/pq/native_factory.go.tmpl', 'mobile/rosenpass/Cargo.lock', 'mobile/rosenpass/src/lib.rs', 'deploy/mobile_openvpn_close_policy.py', 'mobile/openvpn/close_policy.go.tmpl', 'deploy/prepare-mobile-strategy.py', 'mobile/strategy/network_test.go.tmpl', 'deploy/test_external_openvpn_native.py', 'mobile/routervpn_openvpn_external_native_test.go.tmpl'):
            self.assertIn(ROOT/source, inputs)
        for marker in ('rust:1.99.0-alpine3.22', 'cargo build --release --locked --lib', 'test_server_pq_real.py', 'test_server_pq_traffic.py --core /core',
                       'CGO_ENABLED=1', 'with_openvpn', 'routervpn_native_pq', 'with_naive_outbound,with_musl', '-linkmode external', '-extldflags "-static"',
                       'pq-Cargo.lock.sha256', 'readelf -l', 'RUSTFLAGS="-C target-feature=-crt-static"'):
            self.assertIn(marker, docker)
        final = docker.split('FROM alpine:3.22\n', 1)[1]
        self.assertNotIn('pq-test-keys', final)
        self.assertNotIn('/pq-native/keys', final)

if __name__=='__main__':unittest.main()
