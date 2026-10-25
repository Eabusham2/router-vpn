#!/usr/bin/env python3
"""Install the shared native external proof owner and its private desktop CLI.

This extends the already prepared complete desktop engine. It installs the same
Box proof, DNS and retained-TUN code as mobile, without registering another Tor
runtime or importing the mobile platform service into the command-line process.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
MODULE = 'github.com/sagernet/sing-box'


def load(name):
    spec = importlib.util.spec_from_file_location('desktop_'+name.replace('-', '_'), ROOT/'deploy'/(name+'.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


EXTERNAL = load('prepare-mobile-external-policy')
MTU = load('prepare-mobile-mtu')
STRATEGY = load('prepare-mobile-strategy')
RELAY = load('prepare-relay-core')
DESKTOP_MTU = load('prepare-desktop-mtu')
SHARED = tuple(dict.fromkeys((*RELAY.PACKAGES, 'dnsmeasure', 'mobilemtu', 'mtuprobe')))
PURE = ('common', 'mobiletor', 'awgpolicy', 'nativeopenvpn')


def inputs():
    files = [Path(__file__).resolve(), *EXTERNAL.inputs(), *MTU.inputs(), *STRATEGY.inputs(),
             ROOT/'mobile/toroutbound/box.go.tmpl', ROOT/'mobile/toroutbound/box_test.go.tmpl',
             ROOT/'deploy/prepare-desktop-mtu.py', *sorted((ROOT/'mobile/desktop').glob('*.tmpl'))]
    for package in (*PURE, 'dnsmeasure'):
        files += sorted((ROOT/'internal'/package).glob('*.go'))
    return list(dict.fromkeys(files))


def digest():
    value = hashlib.sha256()
    for path in inputs():
        value.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+path.read_bytes())
    return value.hexdigest()


def write(vendor, relative, content):
    target = vendor/relative
    for parent in (target, *target.parents):
        if parent == vendor:
            break
        if parent.is_symlink():
            raise ValueError('Linked desktop external policy destination')
    if not target.resolve().is_relative_to(vendor):
        raise ValueError('Desktop external source escaped its pinned checkout')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)


def prepare(vendor):
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('Desktop external proof requires the exact pinned native core')
    # These pure policy types are shared by the Box's external and Tor proof
    # ownership code. No Tor/PT implementation, C invocation or registry changes
    # are installed in the desktop engine by this preparation.
    for package in PURE:
        for path in sorted((ROOT/'internal'/package).glob('*.go')):
            if path.name.endswith('_test.go'):
                continue
            raw = path.read_bytes()
            for name in PURE:
                raw = raw.replace(('"router-vpn/internal/'+name+'"').encode(), ('"'+MODULE+'/routervpn/'+name+'"').encode())
            for name in SHARED:
                raw = raw.replace(('"router-vpn/internal/'+name+'"').encode(), ('"'+MODULE+'/experimental/libbox/routervpn/'+name+'"').encode())
            write(vendor, 'routervpn/'+package+'/'+path.name, raw)
    for path in sorted((ROOT/'internal/dnsmeasure').glob('*.go')):
        write(vendor, 'experimental/libbox/routervpn/dnsmeasure/'+path.name, path.read_bytes())
    for name in ('box.go', 'box_test.go'):
        write(vendor, 'routervpn_tor'+('_test' if name.endswith('_test.go') else '')+'.go',
              (ROOT/'mobile/toroutbound'/(name+'.tmpl')).read_bytes())
    MTU.prepare(vendor, mobile=False)
    DESKTOP_MTU.prepare(vendor)
    STRATEGY.prepare(vendor, mobile=False)
    EXTERNAL.prepare(vendor, mobile=False)
    templates = [ROOT/'mobile/desktop/external.go.tmpl', ROOT/'mobile/desktop/external_test.go.tmpl', *sorted((ROOT/'mobile/desktop').glob('mtu*.go.tmpl'))]
    for template in templates:
        write(vendor, 'cmd/sing-box/routervpn_'+template.name.removesuffix('.tmpl'), template.read_bytes())
    print('Desktop native external proof source:', digest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path, nargs='?')
    parser.add_argument('--digest', action='store_true')
    arguments = parser.parse_args()
    if arguments.digest:
        print(digest())
    elif arguments.vendor:
        prepare(arguments.vendor)
    else:
        parser.error('vendor or --digest required')
