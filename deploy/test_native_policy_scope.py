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
    def copied(self,name,stale=None,windows_text=False):
        module=load(name)
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as mocks:
            vendor=Path(tmp);(vendor/'go.mod').write_text('module github.com/sagernet/sing-box\n')
            (vendor/'cmd/sing-box').mkdir(parents=True)
            # Preserve the upstream directory even while transport/native
            # preparation is doubled. The real mobile projection writes its
            # caller-bound instance observer here.
            (vendor/'daemon').mkdir()
            output=vendor/'experimental/libbox/routervpn/applexray';output.mkdir(parents=True)
            parent=output/'preparation_test.go'
            if stale=='old':parent.write_bytes((ROOT/'internal/applexray/preparation_test.go').read_bytes())
            if stale=='foreign':parent.write_text('do not erase unknown test')
            # This fixture owns package copying, not vendored transport files.
            # Every native patcher has its own exact-source/executable tests.
            prepared = {}
            for hook in ('WHITENING','AMNEZIA','MTU','PERFORMANCE','WIREGUARD_BIND','OPENVPN_CLOSE','OPENVPN_REMOTE','EXTERNAL_POLICY','PQ','STRATEGY','COMPOSITE','HY2_DEADLINES'):
                if hasattr(module,hook):
                    prepared[hook]=mocks.enter_context(mock.patch.object(getattr(module,hook),'prepare'))
            if hasattr(module,'CORE'):
                mocks.enter_context(mock.patch.object(module.subprocess,'check_output',return_value=module.CORE+'\n'))
            if windows_text:
                # Exercise the producer with the Windows default text newline
                # behavior even on Linux. Byte writes remain actual filesystem
                # writes, and every generated compiler is compared below.
                write_text=Path.write_text
                def native_windows_text(path,data,*args,**kwargs):
                    if path.resolve().is_relative_to(vendor):
                        kwargs.setdefault('newline','\r\n')
                    return write_text(path,data,*args,**kwargs)
                mocks.enter_context(mock.patch.object(Path,'write_text',native_windows_text))
            if stale=='foreign':
                with self.assertRaises(ValueError):module.prepare(vendor)
                self.assertEqual(parent.read_text(),'do not erase unknown test')
                return
            module.prepare(vendor)
            if name=='prepare-mobile-multihop.py':
                for observer in ('instance_context','instance_context_test'):
                    source=ROOT/'mobile/daemon'/(observer+'.go.tmpl')
                    self.assertIn(source,module.inputs())
                    self.assertEqual((vendor/'daemon'/('routervpn_'+observer+'.go')).read_bytes(),source.read_bytes())
            helper = module.OBSERVATION
            original = ROOT/'internal/common/observation_context.go'
            target = vendor/helper.RELATIVE
            self.assertEqual(target.read_bytes(), original.read_bytes())
            self.assertEqual([p.name for p in target.parent.glob('*.go')], ['observation_context.go'])
            self.assertIn(original, module.inputs())
            self.assertIn(ROOT/'deploy/native_observation_policy.py', module.inputs())
            self.assertEqual(set(helper.verify(vendor)), {helper.RELATIVE})
            target.unlink()
            with self.assertRaisesRegex(ValueError, 'missing or modified'):
                helper.verify(vendor)
            helper.prepare(vendor)
            target.write_bytes(original.read_bytes()+b'// changed classifier\n')
            with self.assertRaisesRegex(ValueError, 'missing or modified'):
                helper.verify(vendor)
            with self.assertRaisesRegex(ValueError, 'differs from its original'):
                helper.prepare(vendor)
            target.write_bytes(original.read_bytes())
            extra = target.parent/'parent_contract_test.go'
            extra.write_bytes(b'package common\n')
            with self.assertRaisesRegex(ValueError, 'undeclared common sources'):
                helper.verify(vendor)
            extra.unlink()
            helper.verify(vendor)
            if windows_text:
                for package in module.PACKAGES:
                    for path in (ROOT/'internal'/package).glob('*.go'):
                        if path.name=='core_config_test.go' or package=='applexray' and path.name=='preparation_test.go':continue
                        expected=module.OBSERVATION.rewrite(path.read_bytes())
                        for source_package in module.PACKAGES:
                            expected=expected.replace(('"router-vpn/internal/'+source_package+'"').encode(),
                                ('"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+source_package+'"').encode())
                        copied=vendor/'experimental/libbox/routervpn'/package/path.name
                        self.assertEqual(copied.read_bytes(),expected,
                            'Windows text translation changed the exact native compiler: '+package+'/'+path.name)
            # Both base paths emit the original OpenVPN transport helper
            # before its caller. Only the relay's HY2 guard waits for
            # prepare_native; repeated base preparation verifies both helpers.
            for hook in ('OPENVPN_CLOSE','OPENVPN_REMOTE','HY2_DEADLINES'):
                if hook in prepared:
                    expected=[] if name=='prepare-relay-core.py' and hook=='HY2_DEADLINES' else [mock.call(vendor.resolve())]
                    self.assertEqual(prepared[hook].call_args_list,expected)
            self.assertFalse(parent.exists())
            for filename in ('config.go','config_test.go','start_layer.go','start_layer_test.go'):
                self.assertEqual((output/filename).read_bytes(),(ROOT/'internal/applexray'/filename).read_bytes())
            pq=vendor/'experimental/libbox/routervpn/mobilepq'
            for source in (ROOT/'internal/mobilepq').glob('*.go'):
                self.assertEqual((pq/source.name).read_bytes(), source.read_bytes())
                self.assertIn(source, module.inputs())
            compiler=vendor/'experimental/libbox/routervpn/mobilemultihop/pq.go'
            self.assertEqual(compiler.read_text(), (ROOT/'internal/mobilemultihop/pq.go').read_text().replace('"router-vpn/internal/mobilepq"','"github.com/sagernet/sing-box/experimental/libbox/routervpn/mobilepq"'))
            for source in (vendor/'experimental/libbox/routervpn').rglob('*.go'):
                self.assertNotIn('"router-vpn/internal/', source.read_text())
            before={str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()}
            module.prepare(vendor)
            for hook in ('OPENVPN_CLOSE','OPENVPN_REMOTE','HY2_DEADLINES'):
                if hook in prepared:
                    expected=[] if name=='prepare-relay-core.py' and hook=='HY2_DEADLINES' else [mock.call(vendor.resolve())]*2
                    self.assertEqual(prepared[hook].call_args_list,expected)
            self.assertEqual(before,{str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()})
    def test_relay_native_guards_follow_verified_package_preparation(self):
        module=load('prepare-relay-core.py')
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as mocks:
            vendor=Path(tmp)/'core';vendor.mkdir()
            xray=Path(tmp)/'xray';xray.mkdir()
            (xray/'LICENSE').write_text('native license fixture\n'*20)
            (vendor/'go.mod').write_text('module github.com/sagernet/sing-box\n')
            (xray/'go.mod').write_text('module github.com/xtls/xray-core\n')
            pins={str(vendor):module.CORE,str(xray):module.XRAY.XRAY_PIN}
            def captured_identity(command,**kwargs):
                if len(command)==5 and command[:2]==['git','-C'] and command[2] in pins and command[3:]==['rev-parse','HEAD'] and kwargs=={'text':True}:
                    return pins[command[2]]+'\n'
                raise AssertionError('Unexpected checkout metadata read: '+repr(command))
            mocks.enter_context(mock.patch.object(module.subprocess,'check_output',side_effect=captured_identity))
            calls=mock.Mock()
            calls.attach_mock(mocks.enter_context(mock.patch.object(module.XRAY,'checkout',wraps=module.XRAY.checkout)),'checkout')
            for label,owner,method in (
                ('packages',module,'prepare'),
                ('whitening',module.WHITENING,'prepare'),('xray',module.XRAY,'prepare'),
                ('pq',module.PQ,'prepare'),('composite',module.COMPOSITE,'prepare'),
                ('hy2_deadlines',module.HY2_DEADLINES,'prepare'),
                ('close_policy',module.OPENVPN_CLOSE,'prepare'),('strategy',module.STRATEGY,'prepare'),
                ('server_tor',module.SERVER_TOR,'prepare'),
                ('go',module.subprocess,'run'),
            ):
                calls.attach_mock(mocks.enter_context(mock.patch.object(owner,method)),label)
            module.prepare_native(vendor,xray)
            self.assertEqual(calls.mock_calls[:3],[
                mock.call.checkout(vendor,module.CORE,'github.com/sagernet/sing-box'),
                mock.call.checkout(xray,module.XRAY.XRAY_PIN,'github.com/xtls/xray-core'),
                mock.call.packages(vendor),
            ])
            calls.hy2_deadlines.assert_called_once_with(vendor)
            calls.close_policy.assert_called_once_with(vendor)
            calls.strategy.assert_called_once_with(vendor,mobile=False)
            calls.server_tor.assert_called_once_with(vendor)
            first_go=next(i for i,call in enumerate(calls.mock_calls) if call[0]=='go')
            for guard in (mock.call.hy2_deadlines(vendor),mock.call.close_policy(vendor),mock.call.strategy(vendor,mobile=False),mock.call.server_tor(vendor)):
                self.assertLess(calls.mock_calls.index(guard),first_go)
            # Reject a mismatched second checkout before copying or patching
            # either tree, including before the native close-policy guard.
            calls.reset_mock()
            pins[str(xray)]='different-xray-source'
            with self.assertRaisesRegex(ValueError,'different native engine source revision'):
                module.prepare_native(vendor,xray)
            self.assertEqual(len(calls.mock_calls),2)
            calls.reset_mock()
            pins[str(xray)]=module.XRAY.XRAY_PIN
            (xray/'go.mod').write_text('module unrelated/module\n')
            with self.assertRaisesRegex(ValueError,'unrelated dependency module'):
                module.prepare_native(vendor,xray)
            self.assertEqual(len(calls.mock_calls),2)
            # A rejected Server Tor source never reaches module edits/build.
            # This is an orchestration fixture, not a substitute implementation
            # of the preparer's separately tested source/ownership guards.
            calls.reset_mock()
            (xray/'go.mod').write_text('module github.com/xtls/xray-core\n')
            calls.server_tor.side_effect=ValueError('captured Server Tor source rejected')
            with self.assertRaisesRegex(ValueError,'captured Server Tor source rejected'):
                module.prepare_native(vendor,xray)
            calls.server_tor.assert_called_once_with(vendor)
            calls.go.assert_not_called()
            self.assertEqual(calls.mock_calls[-1],mock.call.server_tor(vendor))
    def test_mobile_copy_does_not_export_parent_build_audits(self):self.copied('prepare-mobile-multihop.py')
    def test_relay_copy_does_not_export_parent_build_audits(self):self.copied('prepare-relay-core.py')
    def test_relay_copy_preserves_exact_source_bytes_on_windows(self):self.copied('prepare-relay-core.py',windows_text=True)
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
