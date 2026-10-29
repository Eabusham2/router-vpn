#!/usr/bin/env python3
"""Execute target setup and verified compiler installation at their OS boundaries."""
from pathlib import Path
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('desktop_native_setup_test', ROOT/'deploy/setup-desktop-native-toolchain.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)
W = G.WINDOWS
spec = importlib.util.spec_from_file_location('desktop_native_build_test', ROOT/'deploy/build-native-runtime.py')
N = importlib.util.module_from_spec(spec)
spec.loader.exec_module(N)


def file(path, data=b'tool', executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if executable:
        path.chmod(0o755)
    return path


class NativeSocketUIDGate(unittest.TestCase):
    def test_matching_unix_hosts_require_uid_gate_and_windows_remains_unchanged(self):
        class CompilerBoundary(Exception):
            pass

        for target in ('linux/amd64', 'linux/arm64', 'darwin/amd64', 'darwin/arm64',
                       'windows/amd64', 'windows/arm64'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source = root/'core'
                (source/'cmd/sing-box').mkdir(parents=True)
                system, arch = target.split('/')
                env = {'GOOS': system, 'GOARCH': arch, 'CGO_LDFLAGS': '', 'GOTOOLCHAIN': N.TOOLCHAIN}
                calls = []

                def run(command, **kwargs):
                    args = [str(value) for value in command]
                    calls.append(args)
                    if args == ['go', 'env', 'GOVERSION']:
                        return N.TOOLCHAIN
                    if args[:2] == ['go', 'build']:
                        raise CompilerBoundary()
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_socket_uid.py'):
                        self.assertIn(system, ('linux', 'darwin'))
                        self.assertEqual(args[2:], [str(source.resolve())])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertLessEqual(kwargs['timeout'], 300)
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_linux_guardian.py'):
                        self.assertEqual(system, 'linux')
                        self.assertEqual(args[2:], [str(source.resolve())])
                        self.assertEqual(kwargs['env']['GOOS'], system)
                        self.assertEqual(kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                        self.assertLessEqual(kwargs['timeout'], 300)
                        return ''
                    if args[:2] in (['go', 'test'], ['go', 'mod']):
                        return ''
                    if len(args) > 1 and args[1] == str(ROOT/'deploy/test_hysteria2_deadlines_pinned.py'):
                        return ''
                    self.fail('Unexpected native command before build: '+repr(args))

                def stage_cronet(_source, stage, actual, _env):
                    library = N.library_name(actual)
                    if library:
                        file(stage/library, b'captured fixture library')

                with patch.object(N, 'environment', return_value=env), patch.object(N, 'run', side_effect=run), \
                     patch.object(N.platform, 'system', return_value={'darwin': 'Darwin', 'linux': 'Linux', 'windows': 'Windows'}[system]), \
                     patch.object(N.platform, 'machine', return_value='x86_64' if arch == 'amd64' else 'arm64'), \
                     patch.object(N, 'pristine'), patch.object(N.PQ, 'verify', return_value={'native_static_libs': []}), \
                     patch.object(N.POLICY, 'prepare_native'), patch.object(N.PERFORMANCE, 'prepare'), \
                     patch.object(N.OPENVPN, 'prepare'), patch.object(N.BUFFERS, 'prepare'), \
                     patch.object(N.EXTERNAL, 'prepare'), patch.object(N.POLICY.AMNEZIA, 'verify'), \
                     patch.object(N, 'stage_cronet', side_effect=stage_cronet):
                    with self.assertRaises(CompilerBoundary):
                        N.build(target, root/'output', source=source, xray=root/'xray', pq=root/'pq')
                uid = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_socket_uid.py')]
                self.assertEqual(len(uid), 0 if system == 'windows' else 1)
                self.assertIn(ROOT/'deploy/test_desktop_socket_uid.py', N.inputs())
                guardian = [args for args in calls if len(args) > 1 and args[1] == str(ROOT/'deploy/test_desktop_linux_guardian.py')]
                self.assertEqual(len(guardian), 1 if system == 'linux' else 0)
                self.assertIn(ROOT/'deploy/test_desktop_linux_guardian.py', N.inputs())
                physical = [args for args in calls if './routervpn/desktoppt' in args]
                self.assertEqual(len(physical), 1)
                self.assertIn('PhysicalFactory|LinuxPhysicalFactory', physical[0][physical[0].index('-run') + 1])


class NativeSetup(unittest.TestCase):
    def exercise(self, target, actual_host=None, fault=''):
        system, arch = actual_host or tuple(target.split('/'))
        with tempfile.TemporaryDirectory(prefix='desktop-setup-contract-') as tmp:
            root = Path(tmp)
            bin_dir = root/'host-bin'
            for name in ('rustup', 'cmake', 'ninja', 'clang', 'clang++', 'llvm-ar', 'xcrun'):
                if name != fault:
                    file(bin_dir/name, executable=True)
            library = file(bin_dir/({'linux': 'libclang.so', 'darwin': 'libclang.dylib', 'windows': 'libclang.dll'}[system]))
            env = {'PATH': str(bin_dir), 'GITHUB_ENV': str(root/'env'), 'GITHUB_PATH': str(root/'path'),
                   'LIBCLANG_PATH': str(library), 'RUSTUP_TOOLCHAIN': 'unrelated-default'}
            file(root/'env', b'PRIOR=retained\n')
            file(root/'path', b'prior-path\n')
            calls, installs, loaded = [], [], []
            triple = G.PQ.TARGETS[target]

            def install(path):
                installs.append(path)
                suffix = '.exe' if system == 'windows' else ''
                for name in ('x86_64-w64-mingw32-clang', 'x86_64-w64-mingw32-clang++',
                             'aarch64-w64-mingw32-clang', 'aarch64-w64-mingw32-clang++', 'llvm-ar'):
                    file(path/'bin'/(name+suffix), executable=True)
                return path/'bin'

            def run(command, command_env, timeout=60):
                command = [str(arg) for arg in command]
                calls.append(command)
                self.assertGreater(timeout, 0)
                name = Path(command[0]).name
                if name in ('cmake', 'ninja'):
                    self.assertEqual(command[1:], ['--version'])
                    return '3.31.0' if name == 'cmake' else '1.12.1'
                if name == 'xcrun':
                    self.assertEqual(command[1:4], ['--sdk', 'macosx', '--find'])
                    return str(bin_dir/command[-1])
                if 'clang' in name:
                    return 'clang version 23.1.3 (fixture)'
                self.assertEqual(name, 'rustup')
                self.assertEqual(command_env['RUSTUP_TOOLCHAIN'], '1.99.0')
                self.assertTrue(command_env['PATH'].startswith(str(bin_dir)+os.pathsep))
                if command[1:3] == ['toolchain', 'install']:
                    self.assertEqual(command[3:], ['1.99.0', '--profile', 'minimal', '--no-self-update'])
                    if fault == 'rustup-failed':
                        raise RuntimeError('actual tool process failed')
                    return ''
                if command[1:3] == ['target', 'add']:
                    self.assertEqual(command[3:], ['--toolchain', '1.99.0', triple])
                    return ''
                if command[1] == 'run':
                    self.assertEqual(command[2], '1.99.0')
                    return command[3]+(' 1.98.0 ' if fault == command[3]+'-version' else ' 1.99.0 ')+'(fixture)'
                self.assertEqual(command[1:], ['target', 'list', '--installed', '--toolchain', '1.99.0'])
                return 'wrong-target' if fault == 'missing-target' else triple

            def validate(path):
                loaded.append(path)
                if fault == 'libclang':
                    raise OSError('wrong host architecture')
                self.assertEqual(path, library)
                return 'clang version 23.1.3'

            output = root/'native-toolchain'
            if fault == 'linked-output':
                other = root/'other'
                other.mkdir()
                output.symlink_to(other, target_is_directory=True)
            with patch.object(G, 'host', return_value=(system, arch)), \
                 patch.object(W, 'install', side_effect=install), \
                 patch.object(G, 'run', side_effect=run), \
                 patch.object(G, 'validate_libclang', side_effect=validate), contextlib.redirect_stdout(io.StringIO()):
                if fault:
                    with self.assertRaises((ValueError, RuntimeError)):
                        G.setup(target, output, env)
                    self.assertEqual((root/'env').read_text(), 'PRIOR=retained\n')
                    self.assertEqual((root/'path').read_text(), 'prior-path\n')
                else:
                    result = G.setup(target, output, env)
                    self.assertEqual((result['target'], result['rust_target']), (target, triple))
                    exports = result['environment']
                    self.assertEqual(exports['RUSTUP_TOOLCHAIN'], '1.99.0')
                    self.assertEqual(exports['LIBCLANG_PATH'], str(library))
                    self.assertEqual(exports['CC'], exports['CC_'+triple.replace('-', '_')])
                    self.assertEqual(exports['CC'], exports['CARGO_TARGET_'+triple.replace('-', '_').upper()+'_LINKER'])
                    self.assertEqual(loaded, [library])
                    for key, value in exports.items():
                        self.assertIn(key+'='+value+'\n', (root/'env').read_text())
                    self.assertEqual((root/'path').read_text().splitlines()[1:], list(reversed(result['prepend_path'])))
                    self.assertEqual(installs, [output/'llvm-mingw'] if target.startswith('windows/') else [])
                    if target.startswith('windows/'):
                        prefix = 'x86_64' if target.endswith('/amd64') else 'aarch64'
                        self.assertIn(prefix+'-w64-mingw32-clang', exports['CC'])
            return calls, installs

    def test_all_six_exact_native_targets_and_both_linux_cross_targets(self):
        self.assertEqual(G.PQ.RUST, '1.99.0')
        self.assertEqual(len(G.PQ.TARGETS), 6)
        for target in G.PQ.TARGETS:
            with self.subTest(target=target):
                self.exercise(target)
        for arch in ('amd64', 'arm64'):
            with self.subTest(linux_cross=arch):
                self.exercise('windows/'+arch, ('linux', arch))

    def test_setup_never_exports_missing_or_wrong_toolchains(self):
        for fault in ('rustup', 'cmake', 'ninja', 'clang', 'clang++', 'libclang',
                      'rustup-failed', 'rustc-version', 'cargo-version', 'missing-target', 'linked-output'):
            with self.subTest(fault=fault):
                self.exercise('linux/amd64', fault=fault)

    def test_unsupported_target_or_native_cross_host_fails_before_install(self):
        for target, host in [('linux/386', ('linux', 'amd64')), ('linux/arm64', ('linux', 'amd64')),
                             ('darwin/arm64', ('darwin', 'amd64')), ('windows/arm64', ('darwin', 'arm64')),
                             ('linux/amd64', ('windows', 'amd64'))]:
            with self.subTest(target=target, host=host), patch.object(G, 'host', return_value=host), \
                 patch.object(G, 'executable') as lookup, patch.object(W, 'install') as installer:
                with self.assertRaises(ValueError):
                    G.setup(target, Path('/unused-output'), {})
                lookup.assert_not_called()
                installer.assert_not_called()

    def test_invalid_explicit_libclang_does_not_fall_back_to_another_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file(root/'bin/libclang.so')
            file(root/'lib/libclang.so')
            foreign = file(root/'foreign.so')
            self.assertEqual(G.libclang_candidates('linux', root/'bin/clang', {'LIBCLANG_PATH':str(foreign)}), [])
            self.assertEqual(G.libclang_candidates('linux', root/'bin/clang', {'LIBCLANG_PATH':str(root/'absent')}), [])
            with self.assertRaisesRegex(ValueError, 'correct LIBCLANG_PATH'):
                G.find_libclang('linux', root/'bin/clang', {'LIBCLANG_PATH':str(root/'absent')})

    def test_host_libclang_c_api_is_exercised_and_disposed(self):
        for version, index, valid in [(b'clang version 23.1.3', 17, True),
                                      (b'clang version 8.0.0', 17, False),
                                      (b'clang version 23.1.3', 0, False)]:
            api = MagicMock()
            api.clang_getCString.return_value = version
            api.clang_createIndex.return_value = index
            with self.subTest(version=version, index=index), tempfile.TemporaryDirectory() as temp, \
                 patch.object(G.ctypes, 'CDLL', return_value=api):
                library = Path(temp)/'libclang.so'
                if valid:
                    self.assertEqual(G.validate_libclang(library), version.decode())
                    api.clang_disposeIndex.assert_called_once_with(17)
                else:
                    with self.assertRaises(ValueError):
                        G.validate_libclang(library)
                api.clang_disposeString.assert_called_once_with(api.clang_getClangVersion.return_value)

    def test_environment_rejects_newline_injection_before_any_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = {'GITHUB_ENV':str(root/'env'), 'GITHUB_PATH':str(root/'path')}
            for values, paths in [({'RUSTUP_TOOLCHAIN':'1.99.0\nCC=foreign'}, ['safe']),
                                  ({'INVALID=NAME':'value'}, ['safe']), ({'CC':'safe'}, ['safe\nforeign'])]:
                with self.assertRaises(ValueError):
                    G.export_environment(values, paths, env)
                self.assertFalse((root/'env').exists())
                self.assertFalse((root/'path').exists())


class DarwinPQEnvironment(unittest.TestCase):
    def test_both_architectures_use_the_selected_sdk_and_product_minimum(self):
        for target, arch in [('darwin/amd64', 'x86_64'), ('darwin/arm64', 'arm64')]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                sdk = root/'Xcode Selected.app/SDKs/MacOSX.sdk'
                file(sdk/'usr/include/stdio.h', b'/* selected SDK C header */\n')
                triple = G.PQ.TARGETS[target]
                compiler = str(root/'Xcode Selected.app/bin/clang')
                inherited = {'PATH': str(root/'bin'), 'LIBCLANG_PATH': str(root/'libclang.dylib'),
                             'SDKROOT': '/stale-ios-sdk', 'MACOSX_DEPLOYMENT_TARGET': '15.5',
                             'BINDGEN_EXTRA_CLANG_ARGS': '-isysroot /stale-generic',
                             'BINDGEN_EXTRA_CLANG_ARGS_'+triple: '-isysroot /stale-hyphen',
                             'BINDGEN_EXTRA_CLANG_ARGS_'+triple.replace('-', '_'): '-isysroot /stale-underscore',
                             'CC_'+triple.replace('-', '_'): compiler}
                queried_env = {}

                def query_sdk(command, *, env, merge_stderr):
                    queried_env.update(env)
                    return str(sdk)+'\n'

                with patch.dict(os.environ, inherited, clear=True), \
                     patch.object(G.PQ.shutil, 'which', return_value='/usr/bin/xcrun') as lookup, \
                     patch.object(G.PQ, 'run', side_effect=query_sdk) as command:
                    env = G.PQ.environment(target, root/'cargo-cache')
                lookup.assert_called_once_with('xcrun', path=inherited['PATH'])
                self.assertEqual(command.call_args.args[0], ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'])
                self.assertFalse(command.call_args.kwargs['merge_stderr'])
                self.assertNotIn('SDKROOT', queried_env)
                self.assertEqual(env['SDKROOT'], str(sdk))
                self.assertEqual(env['MACOSX_DEPLOYMENT_TARGET'], '13.0')
                expected = ['-target', arch+'-apple-macosx13.0', '-isysroot', str(sdk)]
                for key in ('BINDGEN_EXTRA_CLANG_ARGS', 'BINDGEN_EXTRA_CLANG_ARGS_'+triple,
                            'BINDGEN_EXTRA_CLANG_ARGS_'+triple.replace('-', '_')):
                    self.assertEqual(shlex.split(env[key]), expected)
                for key in ('PATH', 'LIBCLANG_PATH', 'CC_'+triple.replace('-', '_')):
                    self.assertEqual(env[key], inherited[key])
                self.assertEqual(env['CARGO_TARGET_DIR'], str(root/'cargo-cache'))

    def test_missing_xcrun_never_uses_an_ambient_sdk(self):
        with patch.dict(os.environ, {'PATH': '/no-tools', 'SDKROOT': '/ambient-sdk'}, clear=True), \
             patch.object(G.PQ.shutil, 'which', return_value=None), patch.object(G.PQ, 'run') as command:
            with self.assertRaisesRegex(ValueError, 'selected Xcode macOS SDK'):
                G.PQ.environment('darwin/arm64', Path('/unused-cache'))
            command.assert_not_called()

    def test_sdk_lookup_failure_is_propagated_without_an_ambient_fallback(self):
        failure = subprocess.CalledProcessError(1, ['xcrun'])
        with patch.dict(os.environ, {'PATH': '/tools', 'SDKROOT': '/ambient-sdk'}, clear=True), \
             patch.object(G.PQ.shutil, 'which', return_value='/usr/bin/xcrun'), \
             patch.object(G.PQ, 'run', side_effect=failure):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                G.PQ.environment('darwin/amd64', Path('/unused-cache'))
            self.assertIs(caught.exception, failure)

    def test_sdk_output_must_be_one_absolute_existing_path_with_c_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sdk = root/'complete.sdk'
            file(sdk/'usr/include/stdio.h')
            incomplete = root/'without-headers.sdk'
            incomplete.mkdir()
            for selected in ('', '\n', 'relative.sdk', str(root/'missing.sdk'), str(incomplete),
                             str(sdk)+'\n/other.sdk', str(sdk)+'\r/other.sdk', str(sdk)+'\0'):
                with self.subTest(selected=selected), \
                     patch.object(G.PQ.shutil, 'which', return_value='/usr/bin/xcrun'), \
                     patch.object(G.PQ, 'run', return_value=selected):
                    with self.assertRaisesRegex(ValueError, 'does not contain its C headers'):
                        G.PQ.environment('darwin/arm64', root/'cargo-cache')

    def test_linux_build_does_not_discover_or_require_an_apple_sdk(self):
        with patch.dict(os.environ, {'PATH': '/tools', 'SDKROOT': '/ambient-sdk'}, clear=True), \
             patch.object(G.PQ.shutil, 'which') as lookup, patch.object(G.PQ, 'run') as command:
            env = G.PQ.environment('linux/amd64', Path('/cargo-cache'))
            self.assertNotIn('SDKROOT', env)
            lookup.assert_not_called()
            command.assert_not_called()


class DarwinNativeEnvironment(unittest.TestCase):
    @staticmethod
    def sdk(root):
        sdk = root/'Xcode Selected.app/SDKs/MacOSX.sdk'
        for header in ('stdio.h', 'stdlib.h', 'pthread.h'):
            file(sdk/'usr/include'/header, b'#define ROUTERVPN_SELECTED_SDK 1\n')
        return sdk

    def test_metadata_only_foreign_verification_never_requires_xcode(self):
        for target in ('darwin/amd64', 'darwin/arm64'):
            with self.subTest(target=target), patch.dict(os.environ, {'PATH': '/no-apple-tools'}, clear=True), \
                 patch.object(N.shutil, 'which') as lookup, patch.object(N, 'run') as command:
                env = N.environment(target)
                self.assertEqual((env['GOOS'], env['GOARCH']), tuple(target.split('/')))
                self.assertNotIn('SDKROOT', env)
                self.assertNotIn('CGO_CFLAGS', env)
                lookup.assert_not_called()
                command.assert_not_called()

    def test_both_native_compilers_receive_exact_sdk_architecture_and_minimum(self):
        for target, arch in [('darwin/amd64', 'x86_64'), ('darwin/arm64', 'arm64')]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                sdk = self.sdk(root)
                inherited = {'PATH': str(root/'bin'), 'CC': str(root/'bin/clang'),
                             'SDKROOT': '/ambient-ios-sdk', 'MACOSX_DEPLOYMENT_TARGET': '15.5',
                             'CGO_CFLAGS': '-isysroot /stale-c-sdk',
                             'CGO_CXXFLAGS': '-isysroot /stale-cxx-sdk',
                             'CGO_LDFLAGS': '-isysroot /stale-link-sdk'}
                queried = {}

                def query(command, *, env):
                    queried.update(env)
                    return str(sdk)

                with patch.dict(os.environ, inherited, clear=True), \
                     patch.object(N.shutil, 'which', return_value='/usr/bin/xcrun') as lookup, \
                     patch.object(N, 'run', side_effect=query) as command:
                    env = N.environment(target, compiler=True)
                lookup.assert_called_once_with('xcrun', path=inherited['PATH'])
                self.assertEqual(command.call_args.args[0], ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'])
                self.assertNotIn('SDKROOT', queried)
                self.assertEqual(env['SDKROOT'], str(sdk))
                self.assertEqual(env['MACOSX_DEPLOYMENT_TARGET'], '13.0')
                expected = ['-target', arch+'-apple-macosx13.0', '-isysroot', str(sdk)]
                self.assertEqual(shlex.split(env['CGO_LDFLAGS']), expected)
                for key in ('CGO_CFLAGS', 'CGO_CXXFLAGS'):
                    self.assertEqual(shlex.split(env[key]), ['-O2', '-g', *expected])
                self.assertEqual(env['CC'], inherited['CC'])

    def test_invalid_sdk_or_failed_lookup_cannot_use_ambient_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sdk = self.sdk(root)
            incomplete = root/'incomplete.sdk'
            file(incomplete/'usr/include/stdio.h')
            for selected in ('', 'relative.sdk', str(root/'missing.sdk'), str(incomplete),
                             str(sdk)+'\n/other.sdk', str(sdk)+'\r/other.sdk', str(sdk)+'\0'):
                with self.subTest(selected=selected), \
                     patch.object(N.shutil, 'which', return_value='/usr/bin/xcrun'), \
                     patch.object(N, 'run', return_value=selected):
                    with self.assertRaisesRegex(ValueError, 'does not contain its C headers'):
                        N.environment('darwin/arm64', compiler=True)
            with patch.object(N.shutil, 'which', return_value=None), patch.object(N, 'run') as command:
                with self.assertRaisesRegex(ValueError, 'selected Xcode macOS SDK'):
                    N.environment('darwin/arm64', compiler=True)
                command.assert_not_called()
            error = subprocess.CalledProcessError(1, ['xcrun'])
            with patch.object(N.shutil, 'which', return_value='/usr/bin/xcrun'), \
                 patch.object(N, 'run', side_effect=error):
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    N.environment('darwin/amd64', compiler=True)
                self.assertIs(caught.exception, error)

    def test_final_go_build_preserves_sdk_and_verified_pq_link_flags(self):
        class CompilerBoundary(Exception):
            pass

        for target, arch in [('darwin/amd64', 'x86_64'), ('darwin/arm64', 'arm64')]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                sdk = self.sdk(root)
                pq = root/'verified pq'
                dependencies = ['-lresolv', '-framework', 'Security', '-framework', 'CoreFoundation']
                commands = []

                def run(command, *, env=None, **kwargs):
                    args = [str(value) for value in command]
                    if args[0] == '/usr/bin/xcrun':
                        self.assertNotIn('SDKROOT', env)
                        return str(sdk)
                    if args == ['go', 'env', 'GOVERSION']:
                        return N.TOOLCHAIN
                    if args[:2] == ['go', 'build']:
                        commands.append((args, env.copy()))
                        raise CompilerBoundary()
                    if args[:2] == ['go', 'test']:
                        package = args[args.index('-ldflags=-checklinkname=0')+1]
                        expected = {
                            './cmd/sing-box': '^TestRouterVPN(Desktop(External|MTU|DNS|Tor)|NodeMTU)',
                            './routervpn/desktoppt': '^Test(RouterVPNDesktopTorPT|DesktopTorNetworkOwner)',
                            './routervpn/mobiletor': '^TestDesktopSocket',
                            './route': '^TestRouterVPNDesktopTorNetwork',
                            '.': '^TestRouterVPNDesktopTor',
                        }
                        self.assertIn(package, expected)
                        self.assertIn(expected[package], args)
                        return ''
                    self.assertIn(args, [['go', 'mod', 'tidy'], ['go', 'mod', 'verify']])
                    return ''

                with patch.dict(os.environ, {'PATH': '/fixture-tools', 'SDKROOT': '/ambient-sdk'}, clear=True), \
                     patch.object(N.shutil, 'which', return_value='/usr/bin/xcrun'), \
                     patch.object(N, 'run', side_effect=run), patch.object(N, 'pristine'), \
                     patch.object(N.PQ, 'verify', return_value={'native_static_libs': dependencies}), \
                     patch.object(N.POLICY, 'prepare_native'), patch.object(N.PERFORMANCE, 'prepare'), \
                     patch.object(N.OPENVPN, 'prepare'), patch.object(N.BUFFERS, 'prepare'), \
                     patch.object(N.EXTERNAL, 'prepare') as external_prepare, \
                     patch.object(N.POLICY.AMNEZIA, 'verify'), patch.object(N, 'stage_cronet'):
                    with self.assertRaises(CompilerBoundary):
                        N.build(target, root/'output', source=root/'core', xray=root/'xray', pq=pq)
                    external_prepare.assert_called_once_with((root/'core').resolve(), env=commands[0][1])
                    self.assertEqual(external_prepare.call_args.kwargs['env']['GOTOOLCHAIN'], N.TOOLCHAIN)
                self.assertEqual(len(commands), 1)
                _, env = commands[0]
                expected = ['-target', arch+'-apple-macosx13.0', '-isysroot', str(sdk)]
                self.assertEqual(shlex.split(env['CGO_LDFLAGS']), [*expected, '-L'+str(pq), *dependencies])
                self.assertEqual(shlex.split(env['CGO_CFLAGS']), ['-O2', '-g', *expected])
                self.assertEqual(shlex.split(env['CGO_CXXFLAGS']), ['-O2', '-g', *expected])

    def test_actual_clang_uses_selected_headers_and_target_with_missing_sdk_control(self):
        clang = shutil.which('clang')
        if not clang:
            self.skipTest('Clang is not installed on this fixture host')
        for target, machine in [('darwin/amd64', '__x86_64__'), ('darwin/arm64', '__arm64__')]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                sdk = self.sdk(root)
                source = file(root/'sdk.c', (
                    '#include <stdio.h>\n'
                    '#if !defined(__APPLE__) || !defined('+machine+')\n#error wrong target\n#endif\n'
                    '#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ != 130000\n#error wrong minimum\n#endif\n'
                    '#if ROUTERVPN_SELECTED_SDK != 1\n#error missing selected SDK\n#endif\n'
                    '_Static_assert(sizeof(void*) == 8, "64-bit ABI");\n').encode())
                with patch.object(N.shutil, 'which', return_value='/usr/bin/xcrun'), \
                     patch.object(N, 'run', return_value=str(sdk)):
                    env = N.environment(target, compiler=True)
                flags = shlex.split(env['CGO_CFLAGS'])
                command = [clang, *flags, '-std=c11', '-fsyntax-only', str(source)]
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                without_sdk = flags[:-2]
                result = subprocess.run([clang, *without_sdk, '-std=c11', '-fsyntax-only', str(source)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                self.assertNotEqual(result.returncode, 0, 'Missing SDK control compiled without the selected header')


class Response(io.BytesIO):
    def __init__(self, data, url='https://release-assets.githubusercontent.com/pinned-asset'):
        super().__init__(data)
        self.url = url

    def geturl(self):
        return self.url


def zip_bytes(prefix, entries=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, data in (entries or [('bin/x86_64-w64-mingw32-clang.exe', b'compiler-a'),
                                      ('bin/aarch64-w64-mingw32-clang.exe', b'compiler-b')]):
            archive.writestr(prefix+'/'+name, data)
    return output.getvalue()


class VerifiedWindowsInstaller(unittest.TestCase):
    def test_official_pin_covers_all_supported_host_architectures(self):
        self.assertEqual(W.RELEASE, '20261006')
        self.assertEqual(set(W.ARCHIVES), {(s,a) for s in ('Windows','Linux') for a in ('amd64','arm64')})
        for (system, arch), (name, size, digest) in W.ARCHIVES.items():
            self.assertTrue(name.startswith('llvm-mingw-'+W.RELEASE+'-ucrt-'))
            self.assertTrue(name.endswith('.zip' if system == 'Windows' else '.tar.xz'))
            self.assertGreater(size, 70_000_000)
            self.assertRegex(digest, r'^[a-f0-9]{64}$')

    def test_actual_verified_install_reuse_and_file_drift_rejection(self):
        prefix = 'llvm-mingw-fixture'
        raw = zip_bytes(prefix)
        entry = (prefix+'.zip', len(raw), hashlib.sha256(raw).hexdigest())
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'installed'
            commands, urls = [], []

            def download(request, timeout):
                urls.append(request.full_url)
                self.assertEqual(timeout, 60)
                return Response(raw)

            def compiler(command, **kwargs):
                self.assertTrue(Path(command[0]).is_file())
                self.assertEqual(command[1:], ['--version'])
                commands.append(command)
                return W.CLANG+' (verified fixture)'

            with patch.object(W.platform, 'system', return_value='Windows'), \
                 patch.object(W.platform, 'machine', return_value='AMD64'), \
                 patch.dict(W.ARCHIVES, {('Windows','amd64'):entry}), \
                 patch.object(W.urllib.request, 'urlopen', side_effect=download), \
                 patch.object(W.subprocess, 'check_output', side_effect=compiler):
                self.assertEqual(W.install(output), output/'bin')
                self.assertEqual(W.install(output), output/'bin')
                self.assertEqual(len(urls), 1)
                self.assertEqual(urls[0], 'https://github.com/mstorsjo/llvm-mingw/releases/download/20261006/'+prefix+'.zip')
                self.assertEqual(len(commands), 4)
                receipt = json.loads((output/'INSTALL.json').read_text())
                self.assertEqual(receipt['files']['bin/x86_64-w64-mingw32-clang.exe']['sha256'], hashlib.sha256(b'compiler-a').hexdigest())
                file(output/'bin/x86_64-w64-mingw32-clang.exe', b'foreign')
                with self.assertRaisesRegex(ValueError, 'unowned or mismatched'):
                    W.install(output)
                self.assertEqual(len(commands), 4, 'modified compiler executed before receipt validation')

    def test_download_size_hash_and_https_fail_before_extract_or_execution(self):
        raw = zip_bytes('llvm-mingw-fixture')
        for fault in ('long', 'short', 'hash', 'http'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                size = len(raw)+(1 if fault == 'short' else -1 if fault == 'long' else 0)
                digest = '0'*64 if fault == 'hash' else hashlib.sha256(raw).hexdigest()
                response = Response(raw, 'http://invalid' if fault == 'http' else 'https://example.test/asset')
                with patch.object(W.platform, 'system', return_value='Windows'), \
                     patch.object(W.platform, 'machine', return_value='AMD64'), \
                     patch.dict(W.ARCHIVES, {('Windows','amd64'):('llvm-mingw-fixture.zip',size,digest)}), \
                     patch.object(W.urllib.request, 'urlopen', return_value=response), \
                     patch.object(W, 'extract') as extract, patch.object(W, 'check_compilers') as check:
                    with self.assertRaises(ValueError):
                        W.install(Path(tmp)/'out')
                    extract.assert_not_called()
                    check.assert_not_called()
                    self.assertFalse((Path(tmp)/'out').exists())

    def test_windows_extraction_rejects_unsafe_namespace_and_links(self):
        prefix = 'llvm-mingw-fixture'
        entries = [('..\u002fescape', b'bad'), ('bin\\escape', b'bad'), ('bin/../escape', b'bad'),
                   ('bin/CON.exe', b'bad'), ('bin/clang.exe:stream', b'bad'), ('INSTALL.JSON', b'bad')]
        for unsafe in entries:
            with self.subTest(name=unsafe[0]), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                archive = file(root/'input.zip', zip_bytes(prefix, [unsafe]))
                with self.assertRaises(ValueError):
                    W.extract(archive, root, prefix, 'Windows')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = file(root/'input.zip', zip_bytes(prefix, [('bin/clang.exe',b'a'),('bin/CLANG.exe',b'b')]))
            with self.assertRaises(ValueError):
                W.extract(archive, root, prefix, 'Windows')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root/'input.zip'
            with zipfile.ZipFile(archive, 'w') as zipped:
                link = zipfile.ZipInfo(prefix+'/bin/link')
                link.create_system = 3
                link.external_attr = (stat.S_IFLNK|0o777)<<16
                zipped.writestr(link, 'clang.exe')
            with self.assertRaises(ValueError):
                W.extract(archive, root, prefix, 'Windows')

    def test_tar_accepts_real_internal_tool_links_and_rejects_escapes(self):
        prefix = 'llvm-mingw-fixture'
        for target, valid in [('clang',True), ('../../escape',False), ('/outside',False), ('missing',False)]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                archive = root/'input.tar.xz'
                with tarfile.open(archive, 'w:xz') as tar:
                    compiler = tarfile.TarInfo(prefix+'/bin/clang')
                    compiler.size = 8
                    compiler.mode = 0o755
                    tar.addfile(compiler, io.BytesIO(b'compiler'))
                    link = tarfile.TarInfo(prefix+'/bin/x86_64-w64-mingw32-clang')
                    link.type = tarfile.SYMTYPE
                    link.linkname = target
                    tar.addfile(link)
                if valid:
                    W.extract(archive, root, prefix, 'Linux')
                    self.assertEqual((root/prefix/'bin/x86_64-w64-mingw32-clang').read_bytes(), b'compiler')
                    self.assertEqual(W.inventory(root/prefix)['bin/x86_64-w64-mingw32-clang'], {'link':'clang'})
                else:
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        W.extract(archive, root, prefix, 'Linux')

    def test_archive_expansion_and_existing_ownership_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = file(root/'input.zip', zip_bytes('compiler', [('large',b'0123456789')]))
            with patch.object(W, 'MAX_MEMBER', 9), self.assertRaises(ValueError):
                W.extract(archive, root, 'compiler', 'Windows')
            other = root/'unowned'
            other.mkdir()
            with patch.object(W.platform, 'system', return_value='Windows'), \
                 patch.object(W.platform, 'machine', return_value='AMD64'), \
                 patch.object(W.urllib.request, 'urlopen') as download, self.assertRaises(ValueError):
                W.install(other)
            download.assert_not_called()


if __name__ == '__main__':
    unittest.main()
