#!/usr/bin/env python3
"""Keep late Tor preparation compatible with the one Android/Xray Go module."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tor_module_preparation', ROOT/'deploy/prepare-mobile-tor.py')
PREP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREP)
GO = 'go'


def digest():
    value = hashlib.sha256()
    paths = [Path(__file__).resolve(), ROOT/'android/build-sing-box-libbox.sh',
             ROOT/'android/routervpn_xray_bridge.go', *PREP.inputs()]
    for path in sorted(set(paths)):
        value.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+path.read_bytes()+b'\0')
    return value.hexdigest()


def run(command, cwd, env=None, success=True):
    result = subprocess.run([str(arg) for arg in command], cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
    output = result.stdout.decode('utf-8', errors='replace')
    if (result.returncode == 0) != success:
        raise AssertionError('Unexpected module-boundary result: '+repr(command)+'\n'+output)
    return output


def module(path):
    return json.loads(run([GO, 'mod', 'edit', '-json'], path))


class ModulePreparation(unittest.TestCase):
    def test_actual_go_edits_raise_only_the_required_minimum(self):
        for existing, expected in [('1.25.7', '1.26.0'), ('1.26', '1.26.0'),
                                   ('1.26.0', '1.26.0'), ('1.26.2', '1.26.2'),
                                   ('1.26.3', '1.26.3')]:
            with self.subTest(existing=existing), tempfile.TemporaryDirectory(prefix='tor-module-version-') as temp:
                root = Path(temp)
                (root/'go.mod').write_text('module github.com/sagernet/sing-box\n\ngo '+existing+'\n'
                                          '\nrequire golang.org/x/net v0.59.1\n'
                                          '\nreplace example.invalid/retained => ./retained\n')
                (root/'go.sum').write_bytes(b'')
                PREP.prepare_modules(root, GO)
                first = {name: (root/name).read_bytes() for name in ('go.mod', 'go.sum')}
                result = module(root)
                self.assertEqual(result['Go'], expected)
                self.assertEqual(next(row['Version'] for row in result['Require']
                                      if row['Path'] == 'golang.org/x/net'), 'v0.59.1')
                self.assertEqual(result['Replace'], [{'Old': {'Path': 'example.invalid/retained'},
                                                     'New': {'Path': './retained'}}])
                PREP.prepare_modules(root, GO)
                self.assertEqual({name: (root/name).read_bytes() for name in first}, first)

    def test_module_directive_comparison_keeps_patch_level(self):
        self.assertEqual(PREP.go_version_key('1.26'), (1, 26, -1))
        self.assertLess(PREP.go_version_key('1.26'), PREP.go_version_key('1.26.0'))
        self.assertLess(PREP.go_version_key('1.26.0'), PREP.go_version_key('1.26.3'))
        for value in ('', 'go1.26.3', '1.26.3\n', '1.26.3-extra', '1.26.3.4'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                PREP.go_version_key(value)


def shipping_graph(vendor, libxray):
    """Exercise real pinned sources without mutating the build's module graph."""
    vendor, libxray = vendor.resolve(), libxray.resolve()
    if run(['git', 'rev-parse', 'HEAD'], vendor).strip() != PREP.CORE:
        raise ValueError('Android module gate needs the exact pinned native core')
    script = (ROOT/'android/build-sing-box-libbox.sh').read_text()
    match = re.search(r'^LIBXRAY_COMMIT=([a-f0-9]{40})$', script, re.M)
    if not match or run(['git', 'rev-parse', 'HEAD'], libxray).strip() != match.group(1):
        raise ValueError('Android module gate needs the exact pinned libXray checkout')
    if run(['git', 'status', '--porcelain', '--untracked-files=all'], libxray).strip():
        raise ValueError('Android module gate cannot accept changed libXray sources')
    bridge = vendor/'experimental/libbox/routervpn_xray_bridge.go'
    if bridge.read_bytes() != (ROOT/'android/routervpn_xray_bridge.go').read_bytes():
        raise ValueError('Android module gate must load the shipping Xray bridge')
    required_go = module(libxray)['Go']
    current = module(vendor)
    if PREP.go_version_key(current['Go']) < PREP.go_version_key(required_go):
        raise ValueError('Late native preparation lowered the combined Android Go requirement')
    imports = [item for item in current.get('Replace', [])
               if item['Old']['Path'] == 'github.com/xtls/libxray']
    if len(imports) != 1 or Path(imports[0]['New']['Path']).resolve() != libxray:
        raise ValueError('Android module gate lost its exact libXray replacement')
    build = (vendor/'cmd/internal/build_libbox/main.go').read_text()
    groups = re.findall(r'^\s*sharedTags = append\(sharedTags,\s*((?:"[^"]+"\s*,?\s*)+)\)', build, re.M)
    tags = [tag for group in groups for tag in re.findall(r'"([^"]+)"', group)]
    if not tags or not {'with_naive_outbound', 'with_openvpn', 'with_wireguard'}.issubset(tags):
        raise ValueError('Android module gate could not read the pinned shipping build tags')
    before = {name: (vendor/name).read_bytes() for name in ('go.mod', 'go.sum')}
    environment = {**os.environ, 'GOWORK': 'off', 'GOTOOLCHAIN': 'go1.26.3',
                   'GOOS': 'android', 'CGO_ENABLED': '1'}
    for arch in ('arm', 'arm64', '386', 'amd64'):
        for name, selected in [('main', tags), ('legacy', [tag for tag in tags if tag != 'with_naive_outbound'])]:
            output = run([GO, 'list', '-mod=readonly', '-tags='+','.join(selected), './experimental/libbox'],
                         vendor, {**environment, 'GOARCH': arch})
            if output.strip() != 'github.com/sagernet/sing-box/experimental/libbox':
                raise ValueError('Android module gate did not load the bound native package')
            print('PASS unchanged pinned Android module graph:', arch, name, flush=True)
    if {name: (vendor/name).read_bytes() for name in before} != before:
        raise ValueError('Readonly Android target loading changed the tested native module')
    # Replay the late module preparation in a disposable copy. Its real Go
    # commands and the Android-only libXray import must keep working together.
    with tempfile.TemporaryDirectory(prefix='android-late-tor-module-') as temp:
        copied = Path(temp)/'core'
        shutil.copytree(vendor, copied, ignore=shutil.ignore_patterns('.git'))
        PREP.prepare_modules(copied, GO)
        PREP.prepare_modules(copied, GO)
        command = [GO, 'list', '-mod=readonly', '-tags='+','.join(tags), './experimental/libbox']
        run(command, copied, {**environment, 'GOARCH': 'arm'})
        if module(copied)['Go'] != current['Go']:
            raise ValueError('Repeated Tor preparation changed the combined Go directive')
        # This is the exact old preparation effect. Host-only resolution can
        # still pass, while the first gomobile Android target must reject it.
        run([GO, 'mod', 'edit', '-go='+module(ROOT/'mobile/torpt')['Go']], copied)
        host = {**os.environ, 'GOWORK': 'off', 'GOTOOLCHAIN': 'go1.26.3'}
        for name in ('GOOS', 'GOARCH'):
            host.pop(name, None)
        run([GO, 'list', '-mod=mod', './protocol/routervpntor', './routervpn/mobiletor',
             './routervpn/torpt/...'], copied, host)
        output = run(command, copied, {**environment, 'GOARCH': 'arm'}, success=False)
        if 'updates to go.mod needed' not in output:
            raise ValueError('Original Go directive negative control failed for an unrelated reason:\n'+output)
    if {name: (vendor/name).read_bytes() for name in before} != before:
        raise ValueError('Late-preparation regression changed the shipping native module')
    print('PASS actual pinned libXray late Tor preparation, eight readonly Android target loads, '
          'and original Go-downgrade negative control; module bytes unchanged', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default=shutil.which('go') or 'go')
    parser.add_argument('--vendor', type=Path)
    parser.add_argument('--libxray', type=Path)
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(digest())
    elif bool(args.vendor) != bool(args.libxray):
        parser.error('--vendor and --libxray are required together')
    else:
        GO = args.go
        # The source gate's bootstrap Go can be older than the native pin.
        # Select the exact compiler for PREP's subprocesses as well as ours.
        os.environ['GOTOOLCHAIN'] = 'go1.26.3'
        os.environ['GOWORK'] = 'off'
        if args.vendor:
            shipping_graph(args.vendor, args.libxray)
        else:
            result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ModulePreparation))
            raise SystemExit(not result.wasSuccessful())
