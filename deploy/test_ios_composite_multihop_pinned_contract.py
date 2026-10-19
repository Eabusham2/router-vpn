#!/usr/bin/env python3
"""Exercise the shipping composite gate's pin, matrix and host SDK boundaries.

Only external commands are doubled. The actual runner, source digest, fixture
validation and failure propagation execute; its native gate uses real Swift/Go.
"""
from pathlib import Path
import contextlib
import importlib.util
import io
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('apple_composite_pinned', ROOT/'deploy/test_ios_composite_multihop_pinned.py')
G = importlib.util.module_from_spec(spec); spec.loader.exec_module(G)


class AppleCompositeGate(unittest.TestCase):
    def exercise(self, fault='', linked_vendor=False):
        with tempfile.TemporaryDirectory(prefix='ios-composite-gate-contract-') as temp:
            root = Path(temp)
            if linked_vendor:
                actual = root/'actual'; actual.mkdir()
                alias = root/'alias'; alias.symlink_to(actual, target_is_directory=True)
                root = alias
            vendor = root/'vendor'; (vendor/'experimental/libbox').mkdir(parents=True)
            reader = vendor/'experimental/libbox/routervpn_multihop_native_test.go'
            reader.write_bytes((ROOT/'mobile/routervpn_multihop_native_test.go.tmpl').read_bytes())
            if fault == 'reader': reader.write_text('different native reader')
            calls, roots = [], []

            def run(command, *, cwd, env, check, timeout):
                self.assertTrue(check)
                self.assertGreater(timeout, 0)
                calls.append(command)
                if len(calls) == 1:
                    self.assertEqual(Path(command[1]), ROOT/'deploy/test_ios_composite_multihop.py')
                    if fault == 'host': raise subprocess.CalledProcessError(2, command)
                    fixtures = Path(env['ROUTERVPN_IOS_COMPOSITE_GRAPHS']); roots.append(fixtures)
                    for name in G.case_names(): (fixtures/name).write_text('{}')
                    if fault == 'short': next(fixtures.iterdir()).unlink()
                    if fault == 'extra': (fixtures/'unowned.json').write_text('{}')
                    if fault == 'symlink':
                        victim = next(fixtures.iterdir()); victim.unlink(); victim.symlink_to(reader)
                else:
                    self.assertEqual(Path(cwd), vendor.resolve(strict=True))
                    self.assertEqual(command[:3], ['go', 'test', '-mod=readonly'])
                    self.assertEqual(command[command.index('-run')+1], '^TestRouterMultihopAppleCompositeGeneratedGraphs$')
                    self.assertEqual(set(command[command.index('-tags')+1].split(',')), {'with_quic','with_wireguard','with_gvisor'})
                    self.assertEqual(env['ROUTERVPN_REQUIRE_IOS_COMPOSITE_GRAPHS'], '1')
                    self.assertIn('-count=1', command)
                    if fault == 'native': raise subprocess.CalledProcessError(3, command)

            with patch.object(G.subprocess, 'check_output', return_value='bad-pin' if fault == 'pin' else G.PIN), \
                 patch.object(G, 'host_environment', return_value={'GOTOOLCHAIN':'go1.26.3'}), \
                 patch.object(G.subprocess, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                if fault:
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        G.run(vendor)
                else:
                    G.run(vendor)
            for root in roots: self.assertFalse(root.exists(), 'private temporary graphs survived completion/failure')
            return calls

    def test_actual_runner_requires_host_then_native(self):
        self.assertEqual(len(self.exercise()), 2)

    def test_linked_source_uses_the_exact_canonical_native_directory(self):
        self.assertEqual(len(self.exercise(linked_vendor=True)), 2)
        self.assertEqual(len(self.exercise('native', linked_vendor=True)), 2)

    def test_bad_pin_or_reader_never_runs_a_compiler(self):
        for fault in ('pin', 'reader'):
            with self.subTest(fault=fault): self.assertEqual(self.exercise(fault), [])

    def test_failed_or_unowned_host_graphs_never_reach_native_parser(self):
        for fault in ('host', 'short', 'extra', 'symlink'):
            with self.subTest(fault=fault): self.assertEqual(len(self.exercise(fault)), 1)

    def test_native_parser_failure_is_fatal(self):
        self.assertEqual(len(self.exercise('native')), 2)

    def test_bound_and_regular_generated_graphs(self):
        with tempfile.TemporaryDirectory(prefix='ios-composite-matrix-') as temp:
            root=Path(temp)
            for name in G.case_names(): (root/name).write_text('{}')
            G.require_matrix(root)
            first=next(root.iterdir()); first.write_bytes(b'')
            with self.assertRaises(ValueError): G.require_matrix(root)
            first.write_bytes(b' '*(4*1024*1024+1))
            with self.assertRaises(ValueError): G.require_matrix(root)
            first.unlink(); first.mkdir()
            with self.assertRaises(ValueError): G.require_matrix(root)

    def test_xcode_target_environment_is_not_inherited(self):
        target={'SDKROOT':'/invalid/iphoneos','GOOS':'ios','GOARCH':'386','CGO_ENABLED':'0','CC':'/ios/clang','CXX':'/ios/clang++',
                **{name:'target-only' for name in ('IPHONEOS_DEPLOYMENT_TARGET','TVOS_DEPLOYMENT_TARGET','WATCHOS_DEPLOYMENT_TARGET',
                                                  'XROS_DEPLOYMENT_TARGET','CGO_CFLAGS','CGO_CPPFLAGS','CGO_CXXFLAGS','CGO_LDFLAGS')}}
        with tempfile.TemporaryDirectory(prefix='ios-composite-host-sdk-') as temp:
            def output(command, **kwargs):
                known={('go','env','GOHOSTOS'):'darwin', ('go','env','GOHOSTARCH'):'arm64',
                       ('xcrun','--sdk','macosx','--show-sdk-path'):temp,
                       ('xcrun','--sdk','macosx','--find','clang'):'/macos/clang',
                       ('xcrun','--sdk','macosx','--find','clang++'):'/macos/clang++'}
                return known[tuple(command)]+'\n'
            with patch.dict(os.environ,target), patch.object(G.platform,'system',return_value='Darwin'), \
                 patch.object(G.subprocess,'check_output',side_effect=output):
                env=G.host_environment()
                for name,value in target.items(): self.assertEqual(os.environ[name],value)
            self.assertEqual((env['GOOS'],env['GOARCH'],env['CGO_ENABLED']),('darwin','arm64','1'))
            self.assertEqual((env['SDKROOT'],env['CC'],env['CXX']),(temp,'/macos/clang','/macos/clang++'))
            for name in target.keys()-{'SDKROOT','GOOS','GOARCH','CGO_ENABLED','CC','CXX'}: self.assertNotIn(name,env)

    def test_gate_and_captured_sources_invalidate_framework_cache(self):
        paths={str(path.relative_to(ROOT)) for path in G.inputs()}
        for required in ('deploy/test_ios_composite_multihop_pinned.py','deploy/test_ios_composite_multihop.py',
                         'deploy/test_ios_max_multihop.py','deploy/test_ios_pq_selection.py','deploy/testfixtures/composite/main.go',
                         'ios/RouterVPN/App/IOSNativePQProfile.swift','ios/RouterVPN/App/IOSRuntimeSelection.swift',
                         'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift','ios/RouterVPN/PacketTunnel/RouterVPNMultihopGraph.swift',
                         'ios/RouterVPN/App/IOSMultihopStartLayer.swift','mobile/routervpn_multihop_native_test.go.tmpl'):
            self.assertIn(required,paths)
        before=G.digest(); original=Path.read_bytes; target=ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift'
        with patch.object(Path,'read_bytes',lambda path:original(path)+(b'\nmutation' if path==target else b'')):
            self.assertNotEqual(before,G.digest())
        build=(ROOT/'ios/RouterVPN/prepare-libbox.sh').read_text()
        self.assertLess(build.index('test_ios_composite_multihop_pinned.py" --digest'),build.index('if [[ -d "$FRAMEWORK"'))
        self.assertIn('"$BRIDGE_SHA" "$COMPOSITE_HOST_SHA"',build)
        self.assertLess(build.index('prepare-apple-xray.py" "$VENDOR"'),build.index('test_ios_composite_multihop_pinned.py" --vendor "$VENDOR"'))
        self.assertLess(build.index('test_ios_composite_multihop_pinned.py" --vendor "$VENDOR"'),build.index('go run ./cmd/internal/build_libbox'))
        for symbol in ('LibboxRouterCompileCompositeProfile','LibboxRouterCompositeMultihopBase','LibboxRouterComposeCompositeMultihop'):
            self.assertIn(symbol,build)
        for path in (ROOT/'.github/workflows/ios-native-compile-smoke.yml',ROOT/'.github/workflows/release-candidate.yml'):
            self.assertIn('test_ios_composite_multihop.py',path.read_text())
            self.assertIn(Path(__file__).name,path.read_text())


if __name__=='__main__': unittest.main()
