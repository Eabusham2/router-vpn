#!/usr/bin/env python3
"""Executable boundary checks for the native Cronet/Tor host toolchain."""
from pathlib import Path
import importlib.util
import os
import shlex
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tor_host_toolchain', ROOT/'deploy/native_tor_graph_host.py')
HOST = importlib.util.module_from_spec(spec)
spec.loader.exec_module(HOST)


class NativeHost(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='routervpn-native-host-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bin = self.root/'bin'
        self.bin.mkdir()
        self.library = self.root/'package with spaces/libroutervpn_tor.so'
        self.library.parent.mkdir()
        self.library.write_bytes(b'verified by package gate before environment selection')
        self.go = self.bin/'go'
        self.go_tool()
        self.llvm(self.bin)
        self.executable(self.bin/'swiftc', "print('Swift version 6.4.1')")
        self.environment = {'PATH': str(self.bin), 'GOCACHE': str(self.root/'cache'),
            'GOPATH': str(self.root/'modules'), 'GOPROXY': 'https://proxy.golang.org,direct',
            'GOSUMDB': 'sum.golang.org'}

    def executable(self, path, body):
        path.write_text('#!'+sys.executable+'\n'+body+'\n')
        path.chmod(0o755)

    def go_tool(self, version='go1.26.3', host=('linux', 'amd64')):
        # Real subprocesses reject a leaked mobile environment before reporting
        # a host. These are tool-reporting doubles, never parser/engine doubles.
        self.executable(self.go, '''import os, sys
for key in ('GOOS','GOARCH','GOARM','GOAMD64','CC','CXX','SDKROOT','CGO_CFLAGS','CGO_LDFLAGS'):
    assert key not in os.environ, key+' leaked into Go host discovery'
assert os.environ['GOENV'] == 'off'
assert os.environ['GOTOOLCHAIN'] == 'local'
assert os.environ['GOWORK'] == 'off'
assert os.environ['GOFLAGS'] == ''
assert os.environ['CGO_ENABLED'] == '1'
if sys.argv[1:] == ['version']:
    print('go version '+'''+repr(version)+'''+' linux/amd64')
elif sys.argv[1:] == ['env','GOHOSTOS','GOHOSTARCH']:
    print('\\n'.join('''+repr(host)+'''))
else:
    raise AssertionError('unexpected Go command')''')

    def llvm(self, directory, clang=21, cxx=21, lld=21):
        directory.mkdir(exist_ok=True)
        self.executable(directory/'clang', 'print('+repr('clang version '+str(clang))+')')
        self.executable(directory/'clang++', 'print('+repr('clang version '+str(cxx))+')')
        self.executable(directory/'ld.lld', 'print('+repr('LLD '+str(lld)+'.1.0')+')')

    def selected(self, clang=None, require_swift=False):
        with mock.patch.dict(os.environ, self.environment, clear=True):
            return HOST.environment(str(self.go), self.library, clang, require_swift)

    def test_cross_flags_are_discarded_and_host_linker_is_exact(self):
        poison = ('GOOS','GOARCH','GOARM','GOARM64','GOAMD64','GOMIPS','GOMIPS64',
                  'GOPPC64','GORISCV64','GOWASM','GOEXPERIMENT','GOFLAGS','GOWORK',
                  'GOENV','GOTOOLCHAIN','CC','CXX','CPP','AR','AS','LD','RANLIB',
                  'CFLAGS','CPPFLAGS','CXXFLAGS','LDFLAGS','SDKROOT','SDK_DIR',
                  'MACOSX_DEPLOYMENT_TARGET','IPHONEOS_DEPLOYMENT_TARGET',
                  'TVOS_DEPLOYMENT_TARGET','WATCHOS_DEPLOYMENT_TARGET','XROS_DEPLOYMENT_TARGET',
                  'DEVELOPER_DIR','TOOLCHAINS','CGO_CFLAGS','CGO_CPPFLAGS','CGO_CXXFLAGS',
                  'CGO_LDFLAGS','CGO_ENABLED','CGO_CFLAGS_ALLOW','CGO_LDFLAGS_DISALLOW',
                  'ROUTERVPN_IOS_TOR_MISSING_ENGINE')
        self.environment.update({key: 'mobile-target-poison' for key in poison})
        env = self.selected(require_swift=True)
        self.assertEqual((env['GOOS'], env['GOARCH']), ('linux','amd64'))
        self.assertEqual(env['GOTOOLCHAIN'], 'local')
        self.assertEqual(env['CGO_ENABLED'], '1')
        self.assertEqual(shlex.split(env['CC']), [str(self.bin/'clang')])
        self.assertEqual(shlex.split(env['CXX']), [str(self.bin/'clang++')])
        self.assertEqual(shlex.split(env['CGO_LDFLAGS']), [
            '-fuse-ld='+str(self.bin/'ld.lld'), '-L'+str(self.library.parent),
            '-Wl,-rpath,'+str(self.library.parent), '-lroutervpn_tor'])
        self.assertFalse(any('mobile-target-poison' in value for value in env.values()))
        for key in ('GOCACHE','GOPATH','GOPROXY','GOSUMDB'):
            self.assertEqual(env[key],self.environment[key])

    def test_fallback_uses_clang21_without_requiring_swift(self):
        self.llvm(self.bin,20,20,20)
        modern=self.root/'llvm-21'
        self.llvm(modern)
        (self.bin/'clang-21').symlink_to(modern/'clang')
        env=self.selected()
        self.assertEqual(shlex.split(env['CC']),[str(modern/'clang')])
        (self.bin/'swiftc').unlink()
        self.assertEqual(self.selected()['CC'],str(modern/'clang'))
        with self.assertRaisesRegex(ValueError,'Swift'):
            self.selected(require_swift=True)

    def test_explicit_old_compiler_does_not_silently_fall_back(self):
        old=self.root/'old'
        self.llvm(old,20,20,20)
        with self.assertRaisesRegex(ValueError,'matching'):
            self.selected(str(old/'clang'))

    def test_old_mismatched_and_missing_llvm_tools_are_rejected(self):
        for versions in ((20,20,20),(21,20,21),(21,21,20),(21,22,21),(21,21,22)):
            with self.subTest(versions=versions):
                self.llvm(self.bin,*versions)
                with self.assertRaises(ValueError):self.selected(str(self.bin/'clang'))
        for name in ('clang++','ld.lld'):
            with self.subTest(missing=name):
                self.llvm(self.bin)
                (self.bin/name).unlink()
                with self.assertRaises(ValueError):self.selected(str(self.bin/'clang'))

    def test_multicall_driver_symlink_names_are_preserved(self):
        driver=self.bin/'driver'
        self.executable(driver, "import os, sys\nname=os.path.basename(sys.argv[0])\nprint('LLD 21.1.0' if name == 'ld.lld' else 'clang version 21.1.0')")
        for name in ('clang++','ld.lld'):
            (self.bin/name).unlink()
            (self.bin/name).symlink_to(driver)
        env=self.selected()
        self.assertEqual(shlex.split(env['CXX']),[str(self.bin/'clang++')])
        self.assertIn('-fuse-ld='+str(self.bin/'ld.lld'),shlex.split(env['CGO_LDFLAGS']))

    def test_wrong_go_toolchain_and_nonhost_target_are_rejected(self):
        self.go_tool(version='go1.23.12')
        with self.assertRaisesRegex(ValueError,'1.26.3'):self.selected()
        self.go_tool(host=('android','arm64'))
        with self.assertRaisesRegex(ValueError,'real Linux host'):self.selected()

    def test_non_linux_and_missing_dso_are_rejected(self):
        with mock.patch.object(HOST.platform,'system',return_value='Darwin'):
            with self.assertRaisesRegex(ValueError,'Linux'):self.selected()
        self.library.unlink()
        with self.assertRaises(FileNotFoundError):self.selected()

    def test_every_source_input_is_real_and_unique(self):
        values=HOST.inputs()
        self.assertEqual(len(values),len(set(values)))
        self.assertIn(Path(__file__).resolve(),values)
        for path in values:self.assertTrue(path.is_file())


if __name__ == '__main__':unittest.main()
