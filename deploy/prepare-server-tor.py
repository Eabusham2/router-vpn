#!/usr/bin/env python3
"""Install the no-TUN Tor lease command and in-process PTs in the pinned relay.

Tor remains the image's separately verified standalone child. This preparation
does not register an embedded Tor outbound or link the desktop TUN lifecycle.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'github.com/sagernet/sing-box'
CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
OWNER = 'routervpn-server-tor-source.json'
spec = importlib.util.spec_from_file_location('server_tor_modules', ROOT/'deploy/prepare-mobile-tor.py')
TOR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TOR)


def inputs():
    return sorted(set([Path(__file__).resolve(), ROOT/'deploy/prepare-mobile-tor.py',
        ROOT/'deploy/test_server_tor_preparation.py',
        ROOT/'mobile/toroutbound/network.go.tmpl', ROOT/'mobile/toroutbound/upstream.go.tmpl',
        ROOT/'mobile/toroutbound/dns_adapter.go.tmpl',
        *list((ROOT/'internal/mobiletor').glob('*.go')),
        *list((ROOT/'internal/common').glob('*.go')),
        *list((ROOT/'internal/awgpolicy').glob('*.go')),
        *list((ROOT/'internal/nativeopenvpn').glob('*.go')),
        *[p for p in (ROOT/'mobile/torpt').rglob('*') if p.is_file()],
        *list((ROOT/'mobile/server_tor').glob('*.tmpl'))]))


def digest():
    result = hashlib.sha256()
    for path in inputs():
        if path.is_symlink():
            raise ValueError('Linked server Tor source')
        result.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+path.read_bytes())
    return result.hexdigest()


def copies():
    content = {}
    for package in ('common', 'mobiletor'):
        for path in sorted((ROOT/'internal'/package).glob('*.go')):
            if path.name.endswith('_test.go'):
                continue
            raw = TOR.rewrite(path.read_bytes())
            raw = raw.replace(b'"router-vpn/internal/mobilemultihop"',
                              b'"github.com/sagernet/sing-box/experimental/libbox/routervpn/mobilemultihop"')
            raw = raw.replace(b'"router-vpn/internal/multihoprelay"',
                              b'"github.com/sagernet/sing-box/experimental/libbox/routervpn/multihoprelay"')
            content['routervpn/'+package+'/'+path.name] = raw
    for package in ('awgpolicy', 'nativeopenvpn'):
        for path in sorted((ROOT/'internal'/package).glob('*.go')):
            if not path.name.endswith('_test.go'):
                content['routervpn/'+package+'/'+path.name] = TOR.rewrite(path.read_bytes())
    notices = {}
    for path in sorted((ROOT/'mobile/torpt').rglob('*')):
        if path.is_symlink():
            raise ValueError('Linked server Tor PT source')
        if not path.is_file():
            continue
        if path.name.startswith('LICENSE') or path.name in ('UPSTREAM.json', 'SOURCE_LOCK.json', 'go.mod', 'go.sum', 'README.md'):
            notices[path.relative_to(ROOT).as_posix()] = path.read_text()
        if path.name not in ('go.mod', 'go.sum'):
            raw = TOR.rewrite(path.read_bytes()) if path.suffix == '.go' else path.read_bytes()
            content['routervpn/torpt/'+path.relative_to(ROOT/'mobile/torpt').as_posix()] = raw
    content['routervpn-server-tor-pt-notices.json'] = (json.dumps(notices, indent=2, sort_keys=True)+'\n').encode()
    for name in ('network.go.tmpl', 'upstream.go.tmpl'):
        raw = (ROOT/'mobile/toroutbound'/name).read_bytes()
        if not raw.startswith(b'package routervpntor\n'):
            raise ValueError('Shared Tor network package boundary changed')
        content['routervpn/servertor/'+name.removesuffix('.tmpl')] = raw.replace(b'package routervpntor\n', b'package routervpnservertor\n', 1)
    for path in sorted((ROOT/'mobile/server_tor').glob('*.tmpl')):
        name = path.name.removesuffix('.tmpl')
        if name.startswith('network_'):
            destination = 'routervpn/servertor/'+name
        elif name.startswith('box'):
            destination = 'routervpn_server_tor_'+name
        else:
            destination = 'cmd/sing-box/routervpn_server_tor_'+name
        content[destination] = path.read_bytes()
    return content


def prepare(vendor, go='go'):
    if vendor.is_symlink():
        raise ValueError('Server Tor requires an unlinked pinned checkout')
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != CORE:
        raise ValueError('Server Tor requires the exact pinned native relay core')
    content = copies()
    owner = TOR.destination(vendor, OWNER)
    previous = {}
    if owner.exists():
        record = json.loads(owner.read_text())
        if record.get('schema') != 1 or record.get('core') != CORE or not isinstance(record.get('files'), dict):
            raise ValueError('Invalid server Tor ownership record')
        previous = record['files']
    for name, expected in previous.items():
        if name not in content and not name.startswith(('routervpn/common/', 'routervpn/mobiletor/',
            'routervpn/awgpolicy/', 'routervpn/nativeopenvpn/', 'routervpn/torpt/', 'routervpn/servertor/',
            'cmd/sing-box/routervpn_server_tor_', 'routervpn_server_tor_')):
            raise ValueError('Server Tor cannot own unrelated native source')
        path = TOR.destination(vendor, name)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Changed server Tor generated source')
    for name, raw in content.items():
        path = TOR.destination(vendor, name)
        if path.exists() and name not in previous and (not path.is_file() or path.read_bytes() != raw):
            raise ValueError('Unowned server Tor generated source')
    dns = TOR.bootstrap_dns_source(vendor, (ROOT/'mobile/toroutbound/dns_adapter.go.tmpl').read_bytes())
    TOR.prepare_modules(vendor, go)
    for name, raw in content.items():
        path = TOR.destination(vendor, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    for name in set(previous)-set(content):
        TOR.destination(vendor, name).unlink()
    TOR.destination(vendor, 'dns/transport_adapter.go').write_bytes(dns)
    owner.write_text(json.dumps(dict(schema=1, core=CORE, source_sha256=digest(),
        files={name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(content.items())}), indent=2, sort_keys=True)+'\n')


if __name__ == '__main__':
    import argparse
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
        parser.error('vendor or --digest required')
