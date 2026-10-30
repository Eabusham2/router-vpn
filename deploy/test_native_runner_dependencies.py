#!/usr/bin/env python3
"""Exercise isolated native runner dependencies without pretending to run packets."""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

class NativeRunnerDependencies(unittest.TestCase):
    def test_sip003_prepares_composite_tor_and_native_xray_before_module_resolution(self):
        script = (ROOT/'deploy/test_mobile_sip003_pinned.sh').read_text()
        prepare = script.split('FIXTURE_DIR=', 1)[0]
        shim = '''#!PYTHON
import json, os, pathlib, sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
state_path=pathlib.Path(os.environ['FIXTURE_STATE'])
state=json.loads(state_path.read_text()) if state_path.exists() else {'calls':[]}
state['calls'].append([name,*args])
status=0
if name=='git':
    pin='50231eaff98ccc31b5cbd247a721c16e97fe5ec1' if args[1]==os.environ['FIXTURE_XRAY'] else '1ac1a339cb1223e9c70eae14c44411c75033c02d'
    print(pin)
elif name=='python3':
    source=pathlib.Path(args[0]).name
    if source=='prepare-mobile-multihop.py':state['composite']=True
    if source=='prepare-mobile-tor.py':state['tor']=True
    if source=='prepare-apple-xray.py':state['xray']=True
elif name=='go':
    if args[0]=='list':print(os.environ['FIXTURE_XRAY'])
    if args[:2]==['mod','tidy'] and not (state.get('composite') and state.get('tor') and state.get('xray')):
        print('owned native composite/Tor/Xray import closure is missing',file=sys.stderr)
        status=73
state_path.write_text(json.dumps(state))
sys.exit(status)
'''.replace('#!PYTHON', '#!'+sys.executable, 1)
        for explicit, missing in ((False,None),(True,None),(True,'xray'),(True,'tor')):
            with self.subTest(explicit=explicit, missing=missing), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                (root/'deploy').mkdir()
                core=root/'core';core.mkdir()
                xray=root/'xray';xray.mkdir()
                commands=root/'bin';commands.mkdir()
                for name in ('git','go','python3'):
                    tool=commands/name;tool.write_text(shim);tool.chmod(0o755)
                driver=root/'deploy/prepare.sh'
                source=prepare
                if missing=='xray':
                    source=source.replace('python3 "$ROOT/deploy/prepare-apple-xray.py" "$VENDOR" "$XRAY"\n','')
                if missing=='tor':
                    source=source.replace('python3 "$ROOT/deploy/prepare-mobile-tor.py" "$VENDOR" --go "$(command -v go)"\n','')
                driver.write_text(source)
                state=root/'state.json'
                env=dict(os.environ,PATH=str(commands)+os.pathsep+os.environ['PATH'],
                    FIXTURE_STATE=str(state),FIXTURE_XRAY=str(xray))
                result=subprocess.run(['bash',str(driver),str(core),*([str(xray)] if explicit else [])],
                    env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
                calls=json.loads(state.read_text())['calls']
                if missing:
                    self.assertEqual(result.returncode,73,result.stdout)
                    self.assertIn('owned native composite/Tor/Xray import closure is missing',result.stdout)
                    continue
                self.assertEqual(result.returncode,0,result.stdout)
                source_calls=[Path(call[1]).name for call in calls if call[0]=='python3']
                self.assertEqual(source_calls,['prepare-mobile-multihop.py','prepare-mobile-tor.py','prepare-apple-xray.py','prepare-mobile-buffers.py'])
                tidy=calls.index(['go','mod','tidy'])
                for required in ('prepare-mobile-tor.py','prepare-apple-xray.py'):
                    self.assertLess(next(i for i,c in enumerate(calls) if c[0]=='python3' and Path(c[1]).name==required),tidy)
                self.assertIn(['go','mod','edit','-require=github.com/xtls/xray-core@v1.260327.1-0.20260711155151-50231eaff98c'],calls)
                self.assertIn(['go','mod','edit','-replace=github.com/xtls/xray-core='+str(xray)],calls)
                self.assertEqual(any(c[:2]==['go','list'] for c in calls),not explicit)

    def test_sip003_workflow_passes_both_exact_checkouts_to_the_shared_gate(self):
        workflow=(ROOT/'.github/workflows/mobile-sip003-native.yml').read_text()
        self.assertIn('git -C "$XRAY" fetch --depth=1 origin 50231eaff98ccc31b5cbd247a721c16e97fe5ec1',workflow)
        self.assertIn('bash deploy/test_mobile_sip003_pinned.sh "$SING" "$XRAY"',workflow)
        self.assertNotIn('go mod tidy',workflow)
        self.assertIn('python3 deploy/test_native_runner_dependencies.py',workflow)

    def test_awg_preparer_owns_every_required_local_package(self):
        script = (ROOT / 'deploy/test_native_awg_return.sh').read_text()
        self.assertIn('python3 "$ROOT/deploy/prepare-mobile-amnezia.py" "$WORK/core"',script)
        self.assertNotIn('packages=',script)
        spec=importlib.util.spec_from_file_location('native_awg_policy_preparer',ROOT/'deploy/prepare-mobile-amnezia.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertIn(ROOT/'deploy/mobile_wireguard_bind_policy.py',module.inputs())
        self.assertIn(ROOT/'mobile/wireguard/client_bind_test.go.tmpl',module.inputs())
        self.assertIn('WIREGUARD_BIND.prepare(vendor)',(ROOT/'deploy/prepare-mobile-amnezia.py').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            core = Path(tmp)
            module.prepare_policies(core)
            target = core / 'experimental/libbox/routervpn'
            for package in ('awgpolicy', 'routechoice', 'multihoprelay', 'mobilemultihop', 'mobilepq', 'applexray', 'startwhitening', 'nativesip003', 'nativecomposite', 'mobileperf', 'hopmeasure', 'nativeopenvpn'):
                originals = {p.name for p in (ROOT/'internal'/package).glob('*.go') if not p.name.endswith('_test.go')}
                self.assertEqual({p.name for p in (target/package).glob('*.go')}, originals)
            for source in target.rglob('*.go'):
                self.assertNotIn(b'"router-vpn/internal/', source.read_bytes())
                original=ROOT/'internal'/source.parent.name/source.name
                expected=original.read_bytes()
                for package in module.POLICY_PACKAGES:
                    expected=expected.replace(('"router-vpn/internal/'+package+'"').encode(),('"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+package+'"').encode())
                self.assertEqual(source.read_bytes(),expected)
                self.assertIn(original,module.inputs())
            # go mod tidy includes the custom-tag integration test imports too.
            native = (ROOT/'mobile/amnezia/start_layer_test.go.tmpl').read_text()
            self.assertIn('experimental/libbox/routervpn/startwhitening', native)
            self.assertTrue((target/'startwhitening/authenticated.go').is_file())
            self.assertFalse(list(target.rglob('*_test.go')))

    def test_awg_policy_recopy_preserves_nonimport_bytes_and_rejects_unknown_imports(self):
        spec=importlib.util.spec_from_file_location('native_awg_policy_bytes',ROOT/'deploy/prepare-mobile-amnezia.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'repository'
            original=root/'internal/awgpolicy/parameters.go'
            original.parent.mkdir(parents=True)
            raw=(b'package awgpolicy\r\nimport "router-vpn/internal/routechoice"\n'
                 b'// Preserve mixed newlines and UTF-8: \xc3\xa9\r\n')
            original.write_bytes(raw)
            core=Path(tmp)/'core'
            copied=core/'experimental/libbox/routervpn/awgpolicy/parameters.go'
            expected=raw.replace(b'"router-vpn/internal/routechoice"',
                                 b'"github.com/sagernet/sing-box/experimental/libbox/routervpn/routechoice"')
            with mock.patch.object(module,'ROOT',root):
                module.prepare_policies(core)
                self.assertEqual(copied.read_bytes(),expected)
                module.prepare_policies(core)
                self.assertEqual(copied.read_bytes(),expected)
                original.write_bytes(raw+b'import "router-vpn/internal/unowned"\r\n')
                with self.assertRaisesRegex(ValueError,'import closure is incomplete'):
                    module.prepare_policies(core)
                self.assertEqual(copied.read_bytes(),expected)

    def test_mtu_policy_recopy_preserves_source_bytes_and_rejects_unknown_imports(self):
        spec=importlib.util.spec_from_file_location('native_mtu_policy_bytes',ROOT/'deploy/prepare-mobile-mtu.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'repository'
            original=root/'internal/hopmeasure/activity.go'
            original.parent.mkdir(parents=True)
            raw=(b'package hopmeasure\r\nimport "router-vpn/internal/mtuprobe"\n'
                 b'// Keep mixed newlines and UTF-8: \xc3\xa9\r\n')
            original.write_bytes(raw)
            core=Path(tmp)/'core'
            copied=core/'experimental/libbox/routervpn/hopmeasure/activity.go'
            expected=raw.replace(b'"router-vpn/internal/mtuprobe"',
                                 b'"github.com/sagernet/sing-box/experimental/libbox/routervpn/mtuprobe"')
            with mock.patch.object(module,'ROOT',root):
                self.assertEqual(module.policy_copies(core),{copied:expected})
                self.assertEqual(module.policy_copies(core),{copied:expected})
                original.write_bytes(raw+b'import "router-vpn/internal/unowned"\r\n')
                with self.assertRaisesRegex(ValueError,'import closure is incomplete'):
                    module.policy_copies(core)
            self.assertFalse(core.exists(),'collecting policy source must not partially overwrite a prepared core')

    def test_mtu_policy_closure_matches_every_shipping_source(self):
        spec=importlib.util.spec_from_file_location('native_mtu_policy_closure',ROOT/'deploy/prepare-mobile-mtu.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            core=Path(tmp)/'core'
            copies=module.policy_copies(core)
            originals={p for package in module.PACKAGES for p in (ROOT/'internal'/package).glob('*.go')}
            self.assertTrue(originals)
            self.assertEqual(len(copies),len(originals))
            for source in originals:
                expected=source.read_bytes()
                for name in module.PACKAGES:
                    expected=expected.replace(('"router-vpn/internal/'+name+'"').encode(),
                        ('"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+name+'"').encode())
                self.assertEqual(copies[core/'experimental/libbox/routervpn'/source.parent.name/source.name],expected)
                self.assertNotIn(b'"router-vpn/internal/',expected)
                self.assertIn(source,module.inputs())

    def test_whitening_prepares_native_base_before_module_resolution(self):
        source=(ROOT/'deploy/test_mobile_whitening_pinned.sh').read_text().split('FIXTURE_DIR=',1)[0]
        shim='''#!PYTHON
import json,os,pathlib,sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
state_path=pathlib.Path(os.environ['FIXTURE_STATE'])
state=json.loads(state_path.read_text()) if state_path.exists() else {'calls':[]}
state['calls'].append([name,*args])
status=0
if name=='git':print('1ac1a339cb1223e9c70eae14c44411c75033c02d')
elif name=='python3':
    script=pathlib.Path(args[0]).name
    if script=='prepare-mobile-amnezia.py' and '--verify-dependency' not in args:state['awg']=True
    if script=='prepare-mobile-buffers.py' and not state.get('awg'):
        print('native base import closure is missing before buffer tidy',file=sys.stderr)
        status=73
state_path.write_text(json.dumps(state))
sys.exit(status)
'''.replace('#!PYTHON','#!'+sys.executable,1)
        for missing in (False,True):
            with self.subTest(missing=missing),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);(root/'deploy').mkdir();core=root/'core';core.mkdir()
                commands=root/'bin';commands.mkdir()
                for name in ('git','python3'):
                    tool=commands/name;tool.write_text(shim);tool.chmod(0o755)
                driver=root/'deploy/prepare.sh'
                driver.write_text(source.replace('python3 "$ROOT/deploy/prepare-mobile-amnezia.py" "$VENDOR"\n','') if missing else source)
                state=root/'state.json'
                env=dict(os.environ,PATH=str(commands)+os.pathsep+os.environ['PATH'],FIXTURE_STATE=str(state))
                result=subprocess.run(['bash',str(driver),str(core)],env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
                if missing:
                    self.assertEqual(result.returncode,73,result.stdout)
                    self.assertIn('native base import closure is missing',result.stdout)
                    continue
                self.assertEqual(result.returncode,0,result.stdout)
                calls=json.loads(state.read_text())['calls']
                self.assertEqual([Path(c[1]).name for c in calls if c[0]=='python3'],['prepare-mobile-amnezia.py','prepare-mobile-buffers.py','prepare-mobile-amnezia.py'])
                self.assertIn('--verify-dependency',calls[-1])
        workflow=(ROOT/'.github/workflows/mobile-start-layer-native.yml').read_text()
        self.assertIn('python3 deploy/test_native_runner_dependencies.py',workflow)

    def test_xray_runner_prepares_the_real_authenticated_outer(self):
        workflow = (ROOT/'.github/workflows/apple-xray-native.yml').read_text()
        prepare = 'python3 deploy/prepare-mobile-whitening.py "$SING"'
        self.assertEqual(workflow.count(prepare), 1)
        self.assertLess(workflow.index(prepare), workflow.index('go mod tidy'))
        self.assertLess(workflow.index(prepare), workflow.index('bash deploy/test_apple_xray_pinned.sh'))
        spec = importlib.util.spec_from_file_location('native_whitening', ROOT/'deploy/prepare-mobile-whitening.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            core = Path(tmp)
            (core/'include').mkdir()
            registry = core/'include/registry.go'
            registry.write_text('import (\n\t"github.com/sagernet/sing-box/protocol/shadowsocks"\n)\nfunc register() {\n\tshadowsocks.RegisterOutbound(registry)\n}\n')
            with mock.patch.object(module, 'checkout'), mock.patch.object(module.STREAM, 'prepare') as stream:
                module.prepare(core)
                before = {str(p.relative_to(core)):p.read_bytes() for p in core.rglob('*') if p.is_file()}
                module.prepare(core)
                self.assertEqual(before, {str(p.relative_to(core)):p.read_bytes() for p in core.rglob('*') if p.is_file()})
            self.assertIn('routervpnwhitening.RegisterOutbound(registry)', registry.read_text())
            self.assertEqual(stream.call_count,2)
            for p in (ROOT/'mobile/startwhitening').glob('*.tmpl'):
                if p.name=='ss_stream_guard.go.tmpl':continue
                self.assertEqual((core/'protocol/routervpnwhitening'/p.name.removesuffix('.tmpl')).read_bytes(), p.read_bytes())

    def test_original_native_packet_gates_remain_required(self):
        awg = (ROOT/'deploy/test_native_awg_return.sh').read_text()
        self.assertIn("-run 'TestNativeTun|TestActualAmnezia", awg)
        self.assertIn('scheduler CAS failed to install replacement', awg)
        self.assertIn('exit "$result"', awg)
        xray = (ROOT/'deploy/test_apple_xray_pinned.sh').read_text()
        self.assertIn('./protocol/routervpnxray', xray)
        self.assertIn("-run 'TestRouterXray'", xray)
        self.assertIn('with_quic,with_wireguard,with_gvisor', xray)

if __name__ == '__main__':
    unittest.main()
