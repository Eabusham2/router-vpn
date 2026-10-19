#!/usr/bin/env python3
"""Install the pinned C Tor loader into the existing disposable Libbox runtime."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'mobile/torpack'
CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
OWNER = 'routervpn-torpack-source.json'
spec = importlib.util.spec_from_file_location('routervpn_tor_package', ROOT / 'deploy/build-mobile-tor-package.py')
PACKAGE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PACKAGE)


def inputs():
    return [Path(__file__).resolve(), *PACKAGE.inputs(), *sorted(SOURCE.glob('*.go.tmpl'))]


def digest():
    value = hashlib.sha256()
    for path in sorted(set(inputs())):
        value.update(str(path.relative_to(ROOT)).encode() + b'\0' + path.read_bytes() + b'\0')
    return value.hexdigest()


def destination(vendor, relative):
    if not PACKAGE.safe_relative(relative):
        raise ValueError('Unsafe native Tor generated destination')
    target = vendor / relative
    for parent in (target, *target.parents):
        if parent == vendor:
            break
        if parent.is_symlink():
            raise ValueError('Linked native Tor generated destination')
    if not target.resolve().is_relative_to(vendor):
        raise ValueError('Native Tor generated source escaped the pinned core')
    return target


def prepare(vendor, native_package=None):
    if vendor.is_symlink():
        raise ValueError('Native Tor requires an unlinked pinned checkout')
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != CORE:
        raise ValueError('Native Tor loader requires the exact pinned Libbox core')
    if not (vendor / 'go.mod').read_text().startswith('module github.com/sagernet/sing-box\n'):
        raise ValueError('Native Tor loader cannot create another Go runtime/module')
    PACKAGE.lock()
    copies = {'routervpn/nativetor/' + name: (SOURCE / (name + '.tmpl')).read_bytes()
              for name in ('native.go', 'backend.go', 'unavailable.go')}
    copies['routervpn/nativetor/routervpn_tor_host.h'] = (ROOT / 'mobile/tor/routervpn_tor_host.h').read_bytes()
    copies['experimental/libbox/routervpn_tor_native.go'] = (SOURCE / 'bridge.go.tmpl').read_bytes()
    if native_package is not None:
        if native_package.is_symlink():
            raise ValueError('Native Tor link package cannot be a symlink')
        native_package = native_package.resolve()
        kind = json.loads((native_package / 'source.json').read_text())['platform']
        if kind not in ('android', 'ios'):
            raise ValueError('Host test C packages cannot be installed as mobile runtime artifacts')
        PACKAGE.verify(native_package, kind, binaries=False)
        if kind == 'android':
            for abi, goarch, *_ in PACKAGE.ANDROID:
                copies['routervpn/nativetor/lib/android/' + goarch + '/libroutervpn_tor.so'] = \
                    (native_package / 'jni' / abi / 'libroutervpn_tor.so').read_bytes()
        else:
            copies['routervpn/nativetor/lib/apple/RouterVPNTor.framework/RouterVPNTor.tbd'] = \
                (native_package / 'link/apple/RouterVPNTor.framework/RouterVPNTor.tbd').read_bytes()
        copies['routervpn/nativetor/native-package.json'] = (native_package / 'source.json').read_bytes()
    owner_path = destination(vendor, OWNER)
    previous = {}
    allowed_paths = set(copies) | {'routervpn/nativetor/native-package.json',
        'routervpn/nativetor/lib/apple/RouterVPNTor.framework/RouterVPNTor.tbd'} | {
        'routervpn/nativetor/lib/android/' + goarch + '/libroutervpn_tor.so' for _, goarch, *_ in PACKAGE.ANDROID}
    if owner_path.exists():
        owner = json.loads(owner_path.read_text())
        if owner.get('schema') != 1 or owner.get('core') != CORE or not isinstance(owner.get('files'), dict):
            raise ValueError('Native Tor loader ownership record is invalid')
        previous = owner['files']
        for name, checksum in previous.items():
            if name not in allowed_paths:
                raise ValueError('Native Tor loader does not own an unrelated source path')
            path = destination(vendor, name)
            if not path.is_file() or PACKAGE.sha(path) != checksum:
                raise ValueError('Refusing to overwrite a changed native Tor generated file')
    # A generic re-preparation of the core preserves previously verified link
    # artifacts. A platform build supplies its freshly verified package after
    # the source-only host gates, before the one existing gomobile invocation.
    if native_package is None:
        for name in previous:
            if name.startswith('routervpn/nativetor/lib/') or name == 'routervpn/nativetor/native-package.json':
                copies[name] = destination(vendor, name).read_bytes()
    for name, content in copies.items():
        path = destination(vendor, name)
        if path.exists() and (not path.is_file() or (name not in previous and path.read_bytes() != content)):
            raise ValueError('Refusing to overwrite an unowned native Tor generated file')
    namespace = vendor / 'routervpn/nativetor'
    if namespace.exists():
        for path in namespace.rglob('*'):
            name = str(path.relative_to(vendor))
            if path.is_symlink() or (path.is_file() and name not in previous and name not in copies):
                raise ValueError('Native Tor package contains an unowned file')
    # Validate every current/destination byte before creating or replacing any
    # generated source. No native runtime is started by source preparation.
    for name, content in copies.items():
        path = destination(vendor, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    for name in set(previous) - set(copies):
        destination(vendor, name).unlink()
    record = dict(schema=1, core=CORE, source_sha256=digest(),
                  files={name: hashlib.sha256(content).hexdigest() for name, content in sorted(copies.items())})
    owner_path.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print('Prepared C Tor ABI loader inside existing Libbox runtime:', digest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path, nargs='?')
    parser.add_argument('--native-package', type=Path)
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(digest())
    elif args.vendor:
        prepare(args.vendor, args.native_package)
    else:
        parser.error('vendor or --digest is required')
