#!/usr/bin/env python3
"""Execute unchanged shipping Cgo owner against a controllable native C ABI."""
from pathlib import Path
import argparse
import os
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'mobile/torpack'


def run(command, directory, env):
    result = subprocess.run(command, cwd=directory, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    return result


def main(go):
    if not go or not shutil.which('cc'):
        raise RuntimeError('Go and a host C compiler are required; native loader tests cannot be skipped')
    with tempfile.TemporaryDirectory(prefix='routervpn-tor-loader-') as temporary:
        root = Path(temporary)
        (root / 'go.mod').write_text('module github.com/sagernet/sing-box/routervpn/nativetor\n\ngo 1.26.3\n')
        for name in ('native.go', 'backend.go', 'unavailable.go'):
            shutil.copyfile(SOURCE / (name + '.tmpl'), root / name)
        shutil.copyfile(ROOT / 'mobile/tor/routervpn_tor_host.h', root / 'routervpn_tor_host.h')
        for name in ('helpers.go', 'loader_test.go'):
            shutil.copyfile(SOURCE / 'testfixtures' / (name + '.tmpl'), root / name)
        library = root / 'lib'; library.mkdir()
        env = dict(os.environ)
        for key in list(env):
            if key.startswith('CGO_') or key in ('GOOS', 'GOARCH', 'GOARM', 'GOAMD64', 'GOFLAGS', 'CC', 'CXX', 'SDKROOT',
                    'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH',
                    'CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'MACOSX_DEPLOYMENT_TARGET', 'IPHONEOS_DEPLOYMENT_TARGET'):
                env.pop(key, None)
        compiler = shutil.which('cc')
        apple = platform.system() == 'Darwin'
        if apple:
            compiler = subprocess.check_output(['xcrun', '--sdk', 'macosx', '--find', 'clang'], env=env, text=True).strip()
            env['SDKROOT'] = subprocess.check_output(['xcrun', '--sdk', 'macosx', '--show-sdk-path'], env=env, text=True).strip()
        payload = library / ('libroutervpn_tor.dylib' if apple else 'libroutervpn_tor.so')
        subprocess.run([compiler, '-std=c11', '-fPIC', '-dynamiclib' if apple else '-shared',
                        '-Wall', '-Wextra', '-Werror', '-pthread', '-I' + str(root),
                        str(SOURCE / 'testfixtures/fake.c'), '-o', str(payload)], env=env, check=True)
        env.update(CGO_ENABLED='1', CC=compiler, GOTOOLCHAIN='local',
                   CGO_LDFLAGS='-L' + str(library) + ' -Wl,-rpath,' + str(library),
                   GOCACHE=env.get('GOCACHE', str(root / 'go-cache')))
        command = [go, 'test', '-race', '-count=1', '-tags=routervpn_tor_native_test', '-timeout=90s', './...']
        positive = run(command, root, env)
        if positive.returncode:
            raise RuntimeError('Shipping native Tor loader failed:\n' + positive.stdout)
        print('PASS actual Cgo Tor ownership: 13 scenarios, concurrent control/close, fd accounting, -race')
        original = (root / 'native.go').read_text()
        backend = (root / 'backend.go').read_text()
        mutations = {
            'duplicate native control claim': ('native.go', 'if i.claimed || i.closing || i.released {', 'if i.closing || i.released {'),
            'leaked FileConn original descriptor': ('native.go', 'closeErr := file.Close()', 'closeErr := error(nil)'),
            'NUL-truncated C argument': ('native.go', 'strings.IndexByte(argument, 0) >= 0', 'strings.IndexByte(argument, 0) >= len(argument)'),
            'premature release on native timeout': ('backend.go', 'case 1:\n\t\treturn false, nil', 'case 1:\n\t\treturn true, nil'),
        }
        for name, (file, before, after) in mutations.items():
            value = original if file == 'native.go' else backend
            if value.count(before) != 1:
                raise RuntimeError('Native loader negative-control anchor changed: ' + name)
            (root / file).write_text(value.replace(before, after, 1))
            result = run(command, root, env)
            (root / file).write_text(value)
            if result.returncode == 0 or '[build failed]' in result.stdout:
                raise RuntimeError('Native loader negative did not fail during execution: ' + name + '\n' + result.stdout)
            print('PASS actual Cgo negative:', name)
        # The ordinary host parser compiles the same owner with the explicit
        # unavailable backend and never claims that C Tor is present.
        (root / 'unavailable_test.go').write_text('''//go:build !routervpn_tor_native_test
package nativetor
import ("errors"; "testing")
func TestUnavailableHost(t *testing.T) {
 if ABI()!=0 || Version()!="" { t.Fatal("host falsely advertised mobile native ABI") }
 if value,err:=Start([]string{"tor"});value!=nil || !errors.Is(err,ErrUnavailable) { t.Fatal("host created a native runtime") }
}
''')
        result = run([go, 'test', '-count=1', './...'], root, env)
        if result.returncode:
            raise RuntimeError('Native Tor unavailable host contract failed:\n' + result.stdout)
        print('PASS ordinary host parser has no implicit native Tor runtime')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default=shutil.which('go'))
    main(parser.parse_args().go)
