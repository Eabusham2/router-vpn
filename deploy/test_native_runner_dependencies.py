#!/usr/bin/env python3
"""Exercise isolated native runner dependencies without pretending to run packets."""
from pathlib import Path
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

class NativeRunnerDependencies(unittest.TestCase):
    def test_awg_copies_every_required_local_package(self):
        script = (ROOT / 'deploy/test_native_awg_return.sh').read_text()
        block = script.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            core = Path(tmp)
            subprocess.run([sys.executable, '-', str(ROOT), str(core)], input=block,
                           text=True, check=True, timeout=15)
            target = core / 'experimental/libbox/routervpn'
            for package in ('awgpolicy', 'routechoice', 'multihoprelay', 'mobilemultihop', 'applexray', 'startwhitening'):
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
