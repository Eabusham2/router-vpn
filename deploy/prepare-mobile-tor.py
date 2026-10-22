#!/usr/bin/env python3
"""Embed the owned native Tor outbound and PTs in the one pinned Libbox runtime."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
MODULE = 'github.com/sagernet/sing-box'
OWNER = 'routervpn-tor-source.json'
spec = importlib.util.spec_from_file_location('routervpn_native_tor_pack', ROOT/'deploy/prepare-mobile-torpack.py')
TORPACK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TORPACK)


def inputs():
    return sorted(set([Path(__file__).resolve(), ROOT/'deploy/test-mobile-tor-outbound.py', ROOT/'deploy/test_mobile_tor_dns_bootstrap.py', ROOT/'deploy/test_mobile_tor_thread_signals.py', ROOT/'deploy/test_mobile_tor_package_runtime.py', ROOT/'mobile/toroutbound/README.md', *TORPACK.inputs(),
        *[p for p in (ROOT/'internal/common').glob('*.go') if not p.name.endswith('_test.go')],
        *[p for p in (ROOT/'internal/awgpolicy').glob('*.go') if not p.name.endswith('_test.go')],
        *(ROOT/'internal/mobiletor').glob('*.go'),
        ROOT/'internal/dnsmeasure/catalog.go',
        *[p for p in (ROOT/'mobile/torpt').rglob('*') if p.is_file()],
        *(ROOT/'mobile/toroutbound').glob('*.tmpl')]))


def digest():
    result = hashlib.sha256()
    for path in inputs():
        result.update(str(path.relative_to(ROOT)).encode() + b'\0' + path.read_bytes() + b'\0')
    return result.hexdigest()


def destination(vendor, relative):
    if not relative or relative.startswith('/') or '..' in Path(relative).parts:
        raise ValueError('Unsafe native Tor source destination')
    target = vendor/relative
    for parent in (target, *target.parents):
        if parent == vendor:
            break
        if parent.is_symlink():
            raise ValueError('Linked native Tor source destination')
    if not target.resolve().is_relative_to(vendor):
        raise ValueError('Native Tor source escaped its pinned core')
    return target


def rewrite(data):
    for source, target in (
        ('router-vpn/internal/mobiletor', MODULE+'/routervpn/mobiletor'),
        ('router-vpn/internal/common', MODULE+'/routervpn/common'),
        ('router-vpn/internal/awgpolicy', MODULE+'/routervpn/awgpolicy'),
        ('router-vpn/mobile/torpt', MODULE+'/routervpn/torpt'),
    ):
        data = data.replace(('"'+source).encode(), ('"'+target).encode())
    return data


def copies():
    result = {}
    # The DNS-only native Tor adapter uses the same closed catalog as the full
    # mobile measurement bridge, including in standalone pinned Tor tests.
    result['routervpn/dnsmeasure/catalog.go'] = (ROOT/'internal/dnsmeasure/catalog.go').read_bytes()
    for name in ('common', 'mobiletor', 'awgpolicy'):
        for path in sorted((ROOT/'internal'/name).glob('*.go')):
            if name != 'mobiletor' and path.name.endswith('_test.go'):
                continue
            result['routervpn/'+name+'/'+path.name] = rewrite(path.read_bytes())
    for path in sorted((ROOT/'mobile/torpt').rglob('*')):
        if path.is_symlink():
            raise ValueError('Linked native Tor PT input')
        if not path.is_file() or path.name in ('go.mod', 'go.sum'):
            continue
        relative = str(path.relative_to(ROOT/'mobile/torpt'))
        result['routervpn/torpt/'+relative] = rewrite(path.read_bytes()) if path.suffix == '.go' else path.read_bytes()
    mapped = {'box.go.tmpl': 'routervpn_tor.go',
              'box_test.go.tmpl': 'routervpn_tor_test.go',
              'bridge.go.tmpl': 'experimental/libbox/routervpn_tor.go',
              'notices.go.tmpl': 'routervpn/tornotices/notices.go'}
    for path in sorted((ROOT/'mobile/toroutbound').glob('*.tmpl')):
        if path.name == 'dns_adapter.go.tmpl':
            continue
        relative = mapped.get(path.name, 'protocol/routervpntor/'+path.stem)
        result[relative] = path.read_bytes()
    notices = {}
    for path in sorted((ROOT/'mobile/torpt').rglob('*')):
        if path.is_file() and (path.name.startswith('LICENSE') or path.name in ('UPSTREAM.json', 'SOURCE_LOCK.json', 'go.mod', 'go.sum', 'README.md')):
            notices[str(path.relative_to(ROOT))] = path.read_text()
    result['routervpn/tornotices/source-notices.json'] = (json.dumps(notices, indent=2, sort_keys=True)+'\n').encode()
    return result


def insert_once(text, anchor, addition):
    if text.count(anchor) != 1:
        raise ValueError('Pinned native Tor registry boundary changed')
    if addition.strip() in text:
        if text.count(addition) != 1 or anchor+'\n'+addition not in text:
            raise ValueError('Existing native Tor registration differs')
        return text
    return text.replace(anchor, anchor+'\n'+addition, 1)


def bootstrap_dns_source(vendor: Path, generated: bytes) -> bytes:
    """Validate before any preparation mutation; the caller writes at commit."""
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=vendor, text=True).strip() != CORE:
        raise ValueError('Native Tor DNS bootstrap requires the exact pinned core')
    original = subprocess.check_output(['git', 'show', CORE+':dns/transport_adapter.go'], cwd=vendor)
    path = vendor/'dns/transport_adapter.go'
    for candidate in (path, *path.parents):
        if candidate == vendor:
            break
        if candidate.is_symlink():
            raise ValueError('Linked native Tor DNS adapter destination')
    actual = path.read_bytes()
    if actual not in (original, generated):
        raise ValueError('Pinned native Tor DNS bootstrap adapter changed outside its exact preparation')
    return generated


def version_key(version):
    match = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?', version)
    if not match:
        raise ValueError('Unrecognized pinned native module version')
    major, minor, patch, pre = match.groups()
    parts = tuple((0, int(item)) if item.isdigit() else (1, item) for item in (pre or '').split('.'))
    return (int(major), int(minor), int(patch), pre is None, parts)


def prepare_modules(vendor, go):
    if subprocess.check_output([go, 'version'], text=True).split()[2] != 'go1.26.3':
        raise ValueError('Native Tor preparation requires the pinned Go 1.26.3 toolchain')
    module = json.loads(subprocess.check_output([go, 'mod', 'edit', '-json'], cwd=vendor, text=True))
    versions = {item['Path']: item['Version'] for item in module.get('Require', [])}
    lock = json.loads((ROOT/'mobile/torpt/SOURCE_LOCK.json').read_text())
    if lock.get('schema') != 1 or lock.get('native_core') != CORE or lock.get('go') != 'go1.26.3':
        raise ValueError('Native Tor PT source lock changed schema or core')
    pt_module = json.loads(subprocess.check_output([go, 'mod', 'edit', '-json'], cwd=ROOT/'mobile/torpt', text=True))
    declared = {item['Path']: item['Version'] for item in pt_module.get('Require', []) if item['Path'] != 'router-vpn'}
    if declared != {item['path']: item['version'] for item in lock['modules']} or len(declared) != len(lock['modules']):
        raise ValueError('Native Tor PT source lock differs from its actual module requirements')
    pt_sums = {tuple(line.split()[:2]): line.split()[2] for line in (ROOT/'mobile/torpt/go.sum').read_text().splitlines()}
    for item in lock['modules']:
        if pt_sums.get((item['path'], item['version'])) != item['sum'] or pt_sums.get((item['path'], item['version']+'/go.mod')) != item['go_mod_sum']:
            raise ValueError('Native Tor PT source lock differs from its module checksums')
    required = []
    for item in lock['modules']:
        name, version = item['path'], item['version']
        if name in versions and version_key(versions[name]) >= version_key(version):
            continue
        required.append('-require='+name+'@'+version)
    # Keep the native core's newer shared dependencies. Source/traffic tests
    # run against the resulting single MVS graph, not another runtime/module.
    subprocess.run([go, 'mod', 'edit', '-go=1.26.0', *required], cwd=vendor, check=True)
    sum_path = destination(vendor, 'go.sum')
    current = sum_path.read_text().splitlines()
    known = {tuple(line.split()[:2]): line.split()[2] for line in current}
    for line in (ROOT/'mobile/torpt/go.sum').read_text().splitlines():
        path, version, checksum = line.split()
        previous = known.get((path, version))
        if previous is not None and previous != checksum:
            raise ValueError('Native Tor module checksum conflicts with the pinned core')
        if previous is None:
            current.append(line)
            known[(path, version)] = checksum
    sum_path.write_text('\n'.join(sorted(current))+'\n')


def prepare(vendor, go='go'):
    if vendor.is_symlink():
        raise ValueError('Native Tor requires an unlinked pinned checkout')
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != CORE:
        raise ValueError('Native Tor requires the exact pinned Libbox core')
    if not (vendor/'go.mod').read_text().startswith('module '+MODULE+'\n'):
        raise ValueError('Native Tor cannot create a second Go runtime/module')
    content = copies()
    owner_path = destination(vendor, OWNER)
    previous = {}
    if owner_path.exists():
        record = json.loads(owner_path.read_text())
        if record.get('schema') != 1 or record.get('core') != CORE or not isinstance(record.get('files'), dict):
            raise ValueError('Native Tor source ownership record is invalid')
        previous = record['files']
        for relative, checksum in previous.items():
            if relative not in content and not relative.startswith(('routervpn/common/', 'routervpn/mobiletor/', 'routervpn/awgpolicy/', 'routervpn/dnsmeasure/', 'routervpn/torpt/', 'routervpn/tornotices/', 'protocol/routervpntor/')):
                raise ValueError('Native Tor cannot own unrelated core source')
            path = destination(vendor, relative)
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
                raise ValueError('Refusing to overwrite changed native Tor generated source')
    for relative, data in content.items():
        path = destination(vendor, relative)
        if path.exists() and (not path.is_file() or relative not in previous and path.read_bytes() != data):
            raise ValueError('Refusing to overwrite unowned native Tor source')
    for namespace in ('routervpn/common', 'routervpn/mobiletor', 'routervpn/awgpolicy', 'routervpn/dnsmeasure', 'routervpn/torpt', 'routervpn/tornotices', 'protocol/routervpntor'):
        path = destination(vendor, namespace)
        if path.exists():
            for child in path.rglob('*'):
                if child.is_symlink() or child.is_file() and str(child.relative_to(vendor)) not in previous and str(child.relative_to(vendor)) not in content:
                    raise ValueError('Unowned file in native Tor generated namespace')
    registry = destination(vendor, 'include/registry.go')
    registry_text = insert_once(registry.read_text(), '\t"'+MODULE+'/protocol/socks"', '\t"'+MODULE+'/protocol/routervpntor"')
    registry_text = insert_once(registry_text, '\tsocks.RegisterOutbound(registry)', '\troutervpntor.RegisterOutbound(registry)')
    dns_adapter = destination(vendor, 'dns/transport_adapter.go')
    dns_adapter_source = bootstrap_dns_source(vendor, (ROOT/'mobile/toroutbound/dns_adapter.go.tmpl').read_bytes())
    # All destinations are checked before the one native module is changed.
    TORPACK.prepare(vendor)
    prepare_modules(vendor, go)
    for relative, data in content.items():
        path = destination(vendor, relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for relative in set(previous)-set(content):
        destination(vendor, relative).unlink()
    registry.write_text(registry_text)
    dns_adapter.write_bytes(dns_adapter_source)
    owner_path.write_text(json.dumps(dict(schema=1, core=CORE, source_sha256=digest(),
        dns_adapter_sha256=hashlib.sha256(dns_adapter_source).hexdigest(),
        files={relative: hashlib.sha256(data).hexdigest() for relative, data in sorted(content.items())}), indent=2, sort_keys=True)+'\n')
    print('Prepared owned native Tor outbound in existing Libbox:', digest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path, nargs='?')
    parser.add_argument('--go', default='go')
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(digest())
    elif args.vendor:
        prepare(args.vendor, args.go)
    else:
        parser.error('vendor or --digest is required')
