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
    def test_sip003_prepares_composite_and_native_xray_before_module_resolution(self):
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
    if source=='prepare-apple-xray.py':state['xray']=True
elif name=='go':
    if args[0]=='list':print(os.environ['FIXTURE_XRAY'])
    if args[:2]==['mod','tidy'] and not (state.get('composite') and state.get('xray')):
        print('owned native composite/Xray import closure is missing',file=sys.stderr)
        status=73
state_path.write_text(json.dumps(state))
sys.exit(status)
'''.replace('#!PYTHON', '#!'+sys.executable, 1)
        for explicit, remove_xray in ((False,False),(True,False),(True,True)):
            with self.subTest(explicit=explicit, remove_xray=remove_xray), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                (root/'deploy').mkdir()
                core=root/'core';core.mkdir()
                xray=root/'xray';xray.mkdir()
                commands=root/'bin';commands.mkdir()
                for name in ('git','go','python3'):
                    tool=commands/name;tool.write_text(shim);tool.chmod(0o755)
                driver=root/'deploy/prepare.sh'
                source=prepare
                if remove_xray:
                    source=source.replace('python3 "$ROOT/deploy/prepare-apple-xray.py" "$VENDOR" "$XRAY"\n','')
                driver.write_text(source)
                state=root/'state.json'
                env=dict(os.environ,PATH=str(commands)+os.pathsep+os.environ['PATH'],
                    FIXTURE_STATE=str(state),FIXTURE_XRAY=str(xray))
                result=subprocess.run(['bash',str(driver),str(core),*([str(xray)] if explicit else [])],
                    env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
                calls=json.loads(state.read_text())['calls']
                if remove_xray:
                    self.assertEqual(result.returncode,73,result.stdout)
                    self.assertIn('owned native composite/Xray import closure is missing',result.stdout)
                    continue
                self.assertEqual(result.returncode,0,result.stdout)
                source_calls=[Path(call[1]).name for call in calls if call[0]=='python3']
                self.assertEqual(source_calls,['prepare-mobile-multihop.py','prepare-apple-xray.py','prepare-mobile-buffers.py'])
                tidy=calls.index(['go','mod','tidy'])
                self.assertLess(next(i for i,c in enumerate(calls) if c[0]=='python3' and Path(c[1]).name=='prepare-apple-xray.py'),tidy)
                self.assertIn(['go','mod','edit','-require=github.com/xtls/xray-core@v1.260327.1-0.20260711155151-50231eaff98c'],calls)
                self.assertIn(['go','mod','edit','-replace=github.com/xtls/xray-core='+str(xray)],calls)
                self.assertEqual(any(c[:2]==['go','list'] for c in calls),not explicit)

    def test_sip003_workflow_passes_both_exact_checkouts_to_the_shared_gate(self):
        workflow=(ROOT/'.github/workflows/mobile-sip003-native.yml').read_text()
        self.assertIn('git -C "$XRAY" fetch --depth=1 origin 50231eaff98ccc31b5cbd247a721c16e97fe5ec1',workflow)
        self.assertIn('bash deploy/test_mobile_sip003_pinned.sh "$SING" "$XRAY"',workflow)
        self.assertNotIn('go mod tidy',workflow)
        self.assertIn('python3 deploy/test_native_runner_dependencies.py',workflow)

    def test_awg_copies_every_required_local_package(self):
        script = (ROOT / 'deploy/test_native_awg_return.sh').read_text()
        block = script.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            core = Path(tmp)
            subprocess.run([sys.executable, '-', str(ROOT), str(core)], input=block,
                           text=True, check=True, timeout=15)
            target = core / 'experimental/libbox/routervpn'
            for package in ('awgpolicy', 'routechoice', 'multihoprelay', 'mobilemultihop', 'mobilepq', 'applexray', 'startwhitening', 'nativesip003', 'nativecomposite'):
                originals = {p.name for p in (ROOT/'internal'/package).glob('*.go') if not p.name.endswith('_test.go')}
                self.assertEqual({p.name for p in (target/package).glob('*.go')}, originals)
            for source in target.rglob('*.go'):
                self.assertNotIn('"router-vpn/internal/', source.read_text())
            # go mod tidy includes the custom-tag integration test imports too.
            native = (ROOT/'mobile/amnezia/start_layer_test.go.tmpl').read_text()
            self.assertIn('experimental/libbox/routervpn/startwhitening', native)
            self.assertTrue((target/'startwhitening/authenticated.go').is_file())
            self.assertFalse(list(target.rglob('*_test.go')))

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
