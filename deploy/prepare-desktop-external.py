#!/usr/bin/env python3
"""Install the shared native external proof owner and its private desktop CLI.

This extends the already prepared complete desktop engine. It installs the same
Box proof, DNS and retained-TUN code as mobile. Desktop PTs share that native
engine; Tor remains a separately owned executable, with no embedded Tor/C
outbound or mobile platform service in the command-line process.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import tempfile

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
TOR = load('prepare-mobile-tor')
SHARED = tuple(dict.fromkeys((*RELAY.PACKAGES, 'dnsmeasure', 'mobilemtu', 'mtuprobe')))
PURE = ('common', 'mobiletor', 'awgpolicy', 'nativeopenvpn')
PT_OWNER = 'routervpn-desktop-tor-source.json'
PT_NAMESPACES = ('routervpn/torpt/', 'routervpn/desktoppt/')
PT_TEMPLATES = ('tor_pt.go.tmpl', 'tor_pt_test.go.tmpl', 'tor_pt_entry_peers_test.go.tmpl',
                'tor_pt_entry_traffic_test.go.tmpl', 'tor_network.go.tmpl', 'tor_network_test.go.tmpl',
                'tor_server.go.tmpl', 'tor_plain_test.go.tmpl', 'tor_local.go.tmpl', 'tor_local_test.go.tmpl',
                'tor_physical.go.tmpl', 'tor_physical_test.go.tmpl',
                'tor_physical_factory_test.go.tmpl',
                'tor_physical_linux.go.tmpl', 'tor_physical_other.go.tmpl',
                'tor_physical_linux_test.go.tmpl',
                'tor_physical_source_unix_test.go.tmpl')
BOX_TEMPLATES = {
    'tor_box.go.tmpl': 'routervpn_desktop_tor_box.go',
    'tor_box_physical.go.tmpl': 'routervpn_desktop_tor_box_physical.go',
    'tor_box_physical_test.go.tmpl': 'routervpn_desktop_tor_box_physical_test.go',
    'tor_box_lastrelay.go.tmpl': 'routervpn_desktop_tor_box_lastrelay.go',
    'tor_box_lastrelay_test.go.tmpl': 'routervpn_desktop_tor_box_lastrelay_test.go',
    'tor_box_lastrelay_server_test.go.tmpl': 'routervpn_desktop_tor_box_lastrelay_server_test.go',
    'tor_box_padding.go.tmpl': 'routervpn_desktop_tor_box_padding.go',
    'tor_box_padding_test.go.tmpl': 'routervpn_desktop_tor_box_padding_test.go',
    'tor_box_test.go.tmpl': 'routervpn_desktop_tor_box_test.go',
    'tor_box_integration_test.go.tmpl': 'routervpn_desktop_tor_box_integration_test.go',
    'tor_box_external_test.go.tmpl': 'routervpn_desktop_tor_box_external_test.go',
    'tor_box_mtu.go.tmpl': 'routervpn_desktop_tor_box_mtu.go',
    'tor_box_mtu_test.go.tmpl': 'routervpn_desktop_tor_box_mtu_test.go',
    'tor_server_box_test.go.tmpl': 'routervpn_desktop_tor_server_box_test.go',
    'tor_server_cover_box_test.go.tmpl': 'routervpn_desktop_tor_server_cover_box_test.go',
    'tor_proof_dns_test.go.tmpl': 'routervpn_desktop_tor_proof_dns_test.go',
    'tor_plain_box_test.go.tmpl': 'routervpn_desktop_tor_plain_box_test.go',
}
ROUTE_TEMPLATES = {
    'tor_network_startup.go.tmpl': 'route/routervpn_desktop_tor_network_startup.go',
    'tor_network_startup_test.go.tmpl': 'route/routervpn_desktop_tor_network_startup_test.go',
}
NETWORK_DISPATCH = '''\t// Invalidate native performance proofs before endpoints rebind.
\tif manager := service.FromContext[adapter.ServiceManager](r.ctx); manager != nil {
\t\tfor _, owned := range manager.Services() {
\t\t\tif listener, ok := owned.(adapter.InterfaceUpdateListener); ok { listener.InterfaceUpdated(ctx) }
\t\t}
\t}

'''


def pt_inputs():
    directory = ROOT/'mobile/torpt'
    if directory.is_symlink():
        raise ValueError('Linked desktop PT source directory')
    files = []
    for path in sorted(directory.rglob('*'), key=lambda path: path.relative_to(ROOT).as_posix()):
        if path.is_symlink():
            raise ValueError('Linked desktop PT source input')
        if path.is_file():
            files.append(path)
    return files


def desktop_pt_notices():
    notices = {path.relative_to(ROOT).as_posix(): path.read_text()
               for path in pt_inputs() if path.name.startswith('LICENSE') or
               path.name in ('UPSTREAM.json', 'SOURCE_LOCK.json', 'go.mod', 'go.sum', 'README.md')}
    if not {'mobile/torpt/SOURCE_LOCK.json', 'mobile/torpt/LICENSE-DEPENDENCIES.json'}.issubset(notices):
        raise ValueError('Desktop PT source and dependency notices are incomplete')
    return (json.dumps(notices, indent=2, sort_keys=True)+'\n').encode()


def inputs():
    files = [Path(__file__).resolve(), *EXTERNAL.inputs(), *MTU.inputs(), *STRATEGY.inputs(), *RELAY.OPENVPN_REMOTE.inputs(),
             ROOT/'mobile/toroutbound/box.go.tmpl', ROOT/'mobile/toroutbound/box_test.go.tmpl',
             ROOT/'mobile/toroutbound/padding_box.go.tmpl', ROOT/'mobile/toroutbound/padding_box_test.go.tmpl',
             ROOT/'deploy/prepare-desktop-mtu.py', ROOT/'deploy/prepare-mobile-tor.py',
             ROOT/'deploy/test_desktop_tor_preparation.py',
             ROOT/'cmd/client/desktop_tor_comparison_native.go', ROOT/'cmd/client/multihop_exact_json.go',
             ROOT/'mobile/toroutbound/network.go.tmpl', ROOT/'mobile/toroutbound/upstream.go.tmpl',
             ROOT/'mobile/toroutbound/dns_adapter.go.tmpl', *pt_inputs(),
             *sorted((ROOT/'mobile/desktop').glob('*.tmpl'))]
    for package in (*PURE, 'dnsmeasure'):
        files += sorted((ROOT/'internal'/package).glob('*.go'))
    return sorted(dict.fromkeys(files), key=lambda path: path.relative_to(ROOT).as_posix())


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


def checked_vendor(vendor):
    if vendor.is_symlink():
        raise ValueError('Desktop PT preparation requires an unlinked native checkout')
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('Desktop external proof requires the exact pinned native core')
    return vendor


def pt_copies():
    content = {}
    for path in pt_inputs():
        if path.name in ('go.mod', 'go.sum'):
            continue
        relative = 'routervpn/torpt/'+path.relative_to(ROOT/'mobile/torpt').as_posix()
        raw = path.read_bytes()
        content[relative] = TOR.rewrite(raw) if path.suffix == '.go' else raw
    for name in ('network.go.tmpl', 'upstream.go.tmpl'):
        path = ROOT/'mobile/toroutbound'/name
        raw = path.read_bytes()
        if path.is_symlink() or raw.count(b'package routervpntor\n') != 1 or not raw.startswith(b'package routervpntor\n'):
            raise ValueError('Desktop PT shared package boundary changed')
        content['routervpn/desktoppt/'+name.removesuffix('.tmpl')] = raw.replace(b'package routervpntor\n', b'package routervpndesktoppt\n', 1)
    for name in PT_TEMPLATES:
        path = ROOT/'mobile/desktop'/name
        raw = path.read_bytes()
        prefix = { 'tor_physical_source_unix_test.go.tmpl': b'//go:build linux || darwin\n\n',
                   'tor_physical_linux.go.tmpl': b'//go:build linux\n\n',
                   'tor_physical_linux_test.go.tmpl': b'//go:build linux\n\n',
                   'tor_physical_other.go.tmpl': b'//go:build !linux\n\n' }.get(name, b'')
        if path.is_symlink() or not raw.startswith(prefix+b'package routervpndesktoppt\n'):
            raise ValueError('Desktop PT adapter package boundary changed')
        content['routervpn/desktoppt/'+name.removesuffix('.tmpl')] = raw
    for name, relative in BOX_TEMPLATES.items():
        path = ROOT/'mobile/desktop'/name
        raw = path.read_bytes()
        if path.is_symlink() or not raw.startswith(b'package box\n'):
            raise ValueError('Desktop Tor Box package boundary changed')
        content[relative] = raw
    for name, relative in ROUTE_TEMPLATES.items():
        path = ROOT/'mobile/desktop'/name
        raw = path.read_bytes()
        if path.is_symlink() or not raw.startswith(b'package route\n'):
            raise ValueError('Desktop Tor native network package boundary changed')
        content[relative] = raw
    return content


def pt_registry_source(source):
    # Windows preparation steps can write CRLF even when Git inputs are LF.
    # Parse the same Go source with canonical newlines; the caller retains the
    # original bytes for its ownership/replacement check before any write.
    source = source.replace('\r\n', '\n')
    if MODULE+'/protocol/routervpntor' in source or 'routervpntor.RegisterOutbound' in source:
        raise ValueError('Desktop PT preparation cannot share an embedded Tor registry')
    imported = '\t"'+MODULE+'/routervpn/desktoppt"'
    registered = '\troutervpndesktoppt.RegisterNetworkOwner(registry)'
    for marker, exact in ((MODULE+'/routervpn/desktoppt', imported), ('routervpndesktoppt.RegisterNetworkOwner', registered)):
        if marker in source and (source.count(marker) != 1 or source.count(exact) != 1):
            raise ValueError('Desktop Tor network observer registration differs')
    source = TOR.insert_once(source, '\t"'+MODULE+'/service/resolved"', imported)
    source = TOR.insert_once(source, '\tresolved.RegisterService(registry)', registered)
    start = source.index('func ServiceRegistry() *service.Registry {')
    end = source.index('\n}\n', start)
    if registered not in source[start:end]:
        raise ValueError('Desktop Tor network observer must belong to the service registry')
    registered = '\troutervpndesktoppt.RegisterServerTor(registry)'
    marker = 'routervpndesktoppt.RegisterServerTor'
    if marker in source and (source.count(marker) != 1 or source.count(registered) != 1):
        raise ValueError('Desktop Tor Server outbound registration differs')
    source = TOR.insert_once(source, '\tsocks.RegisterOutbound(registry)', registered)
    start = source.index('func OutboundRegistry() *outbound.Registry {')
    end = source.index('\n}\n', start)
    if registered not in source[start:end]:
        raise ValueError('Desktop Tor Server must belong to the outbound registry')
    for function, anchor, name in (
            ('RegisterLocalTor', '\troutervpndesktoppt.RegisterServerTor(registry)', 'func OutboundRegistry() *outbound.Registry {'),
            ('RegisterPhysicalOutbound', '\troutervpndesktoppt.RegisterLocalTor(registry)', 'func OutboundRegistry() *outbound.Registry {'),
            ('RegisterLocalTorDNS', '\ttransport.RegisterTCP(registry)', 'func DNSTransportRegistry() *dns.TransportRegistry {')):
        registered = '\troutervpndesktoppt.'+function+'(registry)'
        marker = 'routervpndesktoppt.'+function+'('
        if marker in source and (source.count(marker) != 1 or source.count(registered) != 1):
            raise ValueError('Desktop Tor Local padding registration differs')
        source = TOR.insert_once(source, anchor, registered)
        start = source.index(name)
        end = source.index('\n}\n', start)
        if registered not in source[start:end]:
            raise ValueError('Desktop Tor Local padding must belong to its native registry')
    return source.encode()


def pt_network_source(vendor, source):
    source = source.replace('\r\n', '\n')
    original = subprocess.check_output(['git', '-C', str(vendor), 'show', PIN+':route/network.go']).decode().replace('\r\n', '\n')
    marker, anchor = 'func (r *NetworkManager) ResetNetwork(ctx context.Context) {', '\tfor _, endpoint := range r.endpoint.Endpoints() {'
    if original.count(marker) != 1 or source.count(marker) != 1:
        raise ValueError('Desktop Tor network reset boundary changed')
    start, original_start = source.index(marker), original.index(marker)
    end, original_end = source.index('\n}\n', start)+2, original.index('\n}\n', original_start)+2
    baseline = original[original_start:original_end]
    if baseline.count(anchor) != 1:
        raise ValueError('Pinned desktop Tor network dispatch boundary changed')
    generated = baseline.replace(anchor, NETWORK_DISPATCH+anchor, 1)
    actual = source[start:end]
    if actual not in (baseline, generated) or source.count(NETWORK_DISPATCH) != (1 if actual == generated else 0):
        raise ValueError('Desktop Tor network service dispatch differs from its exact preparation')
    # Preserve the separately prepared atomic Start/Close lifecycle outside this
    # method. The exact shared fragment is also understood by performance prep.
    return (source[:start]+generated+source[end:]).encode()


def preflight_pt_files(vendor, content):
    owner = TOR.destination(vendor, PT_OWNER)
    previous = {}
    if owner.exists():
        if not owner.is_file() or owner.stat().st_size > 4*1024*1024:
            raise ValueError('Desktop PT ownership record is unsafe')
        record = json.loads(owner.read_bytes())
        if not isinstance(record, dict) or record.get('schema') != 1 or record.get('core') != PIN or not isinstance(record.get('files'), dict):
            raise ValueError('Desktop PT ownership record is invalid')
        previous = record['files']
        for relative, checksum in previous.items():
            if (not relative.startswith(PT_NAMESPACES) and relative not in (*BOX_TEMPLATES.values(), *ROUTE_TEMPLATES.values())) or not isinstance(checksum, str) or not re.fullmatch('[0-9a-f]{64}', checksum):
                raise ValueError('Desktop PT cannot own unrelated native source')
            path = TOR.destination(vendor, relative)
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
                raise ValueError('Refusing to overwrite changed desktop PT generated source')
    for relative, data in content.items():
        path = TOR.destination(vendor, relative)
        if path.exists() and (not path.is_file() or relative not in previous and path.read_bytes() != data):
            raise ValueError('Refusing to overwrite unowned desktop PT source')
    for namespace in PT_NAMESPACES:
        directory = TOR.destination(vendor, namespace)
        if directory.exists():
            if not directory.is_dir():
                raise ValueError('Desktop PT generated namespace is not a directory')
            for path in directory.rglob('*'):
                relative = path.relative_to(vendor).as_posix()
                if path.is_symlink() or path.is_file() and relative not in content and relative not in previous:
                    raise ValueError('Unowned file in desktop PT generated namespace')
    return previous


def pt_network_startup_source(vendor, source):
    """Join admitted native callbacks before publishing the started owner.

    Validate complete pinned lifecycle methods, including the separately owned
    strategy atomic edits. A bypassed join or changed callback cannot be silently
    overwritten by a later cache preparation.
    """
    source = source.replace('\r\n', '\n')
    original = subprocess.check_output(['git', '-C', str(vendor), 'show', PIN+':route/network.go']).decode().replace('\r\n', '\n')

    def method(text, name):
        marker = 'func (r *NetworkManager) '+name
        if text.count(marker) != 1:
            raise ValueError('Desktop Tor native network lifecycle boundary changed')
        start = text.index(marker)
        end = text.index('\n}\n', start)+2
        return text[start:end]

    start = method(original, 'Start(').replace('\t\tr.started = true\n', '\t\tr.started.Store(true)\n')
    joined = start.replace('\t\tr.started.Store(true)\n',
        '\t\tif err := r.routerVPNStartup.start(r.ctx, func() {\n'
        '\t\t\tr.started.Store(true)\n'
        '\t\t}); err != nil {\n\t\t\treturn err\n\t\t}\n')
    close = method(original, 'Close(').replace('Close() error {\n', 'Close() error {\n\tr.started.Store(false)\n')
    stopped = close.replace('\tr.started.Store(false)\n',
        '\tr.started.Store(false)\n'
        '\tr.routerVPNStartup.stop(func() { r.started.Store(false) })\n')
    interface = method(original, 'notifyInterfaceUpdate(')
    admitted = interface.replace('\tr.pauseManager.NetworkWake()\n',
        '\tfinish, accepted := r.routerVPNStartup.begin()\n'
        '\tif !accepted {\n\t\treturn\n\t}\n'
        '\tr.pauseManager.NetworkWake()\n').replace('\t\tdefer updateCancel()\n',
        '\t\tdefer finish()\n\t\tdefer updateCancel()\n')
    power = method(original, 'notifyWindowsPowerEvent(')
    power_admitted = power.replace('\tcase winpowrprof.EVENT_SUSPEND:\n',
        '\tcase winpowrprof.EVENT_SUSPEND:\n'
        '\t\tfinish, accepted := r.routerVPNStartup.begin()\n'
        '\t\tif !accepted {\n\t\t\treturn\n\t\t}\n\t\tdefer finish()\n').replace(
        '\tcase winpowrprof.EVENT_RESUME_AUTOMATIC:\n',
        '\tcase winpowrprof.EVENT_RESUME_AUTOMATIC:\n'
        '\t\tfinish, accepted := r.routerVPNStartup.begin()\n'
        '\t\tif !accepted {\n\t\t\treturn\n\t\t}\n').replace(
        '\t\t\tdefer updateCancel()\n', '\t\t\tdefer finish()\n\t\t\tdefer updateCancel()\n')
    for name, before, after in (('Start(', start, joined), ('Close(', close, stopped),
                                ('notifyInterfaceUpdate(', interface, admitted),
                                ('notifyWindowsPowerEvent(', power, power_admitted)):
        actual = method(source, name)
        if actual not in (before, after):
            raise ValueError('Desktop Tor native network startup differs from its exact preparation')
        source = source.replace(actual, after, 1)
    field = '\tstarted                  atomic.Bool\n'
    owned = '\trouterVPNStartup         routerVPNNetworkStartup\n'+field
    if source.count(field) != 1 or ('routerVPNStartup ' in source and source.count(owned) != 1):
        raise ValueError('Desktop Tor native network startup field differs')
    if owned not in source:
        source = source.replace(field, owned, 1)
    return source.encode()


def prepare_network_startup(vendor):
    path = TOR.destination(vendor, 'route/network.go')
    original = path.read_bytes()
    prepared = pt_network_startup_source(vendor, original.decode())
    if path.read_bytes() != original:
        raise ValueError('Desktop Tor native network changed before startup adoption')
    write(vendor, 'route/network.go', prepared)


def prepare_desktop_pt(vendor, go='go', *, env=None):
    vendor = checked_vendor(vendor)
    content = pt_copies()
    previous = preflight_pt_files(vendor, content)
    paths = {name: TOR.destination(vendor, name) for name in ('include/registry.go', 'route/network.go', 'dns/transport_adapter.go', 'go.mod', 'go.sum')}
    originals = {name: path.read_bytes() for name, path in paths.items()}
    if not originals['go.mod'].replace(b'\r\n', b'\n').startswith(('module '+MODULE+'\n').encode()):
        raise ValueError('Desktop PT preparation requires the existing single native Go module')
    registry = pt_registry_source(originals['include/registry.go'].decode())
    network = pt_network_source(vendor, originals['route/network.go'].decode())
    dns = TOR.bootstrap_dns_source(vendor, (ROOT/'mobile/toroutbound/dns_adapter.go.tmpl').read_bytes())
    # Reuse only the pinned module editor, never mobile prepare/copies/TORPACK.
    # Stage its edits first: checksum conflicts or a changed source lock cannot
    # partially update the real native module before the source is accepted.
    with tempfile.TemporaryDirectory(prefix='routervpn-desktop-pt-module-') as directory:
        # This directory was just created by this build. Capture its canonical
        # identity before child containment checks (Windows temp paths can use
        # 8.3 aliases, and macOS can expose /var through a symbolic link).
        staged = Path(directory).resolve(strict=True)
        for name in ('go.mod', 'go.sum'):
            (staged/name).write_bytes(originals[name])
        TOR.prepare_modules(staged, go, env=env)
        modules = {name: (staged/name).read_bytes() for name in ('go.mod', 'go.sum')}
    if any(TOR.destination(vendor, name).read_bytes() != data for name, data in originals.items()):
        raise ValueError('Desktop PT preparation target changed before adoption')
    if preflight_pt_files(vendor, content) != previous:
        raise ValueError('Desktop PT source ownership changed before adoption')
    for relative, raw in content.items():
        write(vendor, relative, raw)
    for relative in set(previous)-set(content):
        TOR.destination(vendor, relative).unlink()
    for relative, raw in {**modules, 'include/registry.go': registry, 'route/network.go': network, 'dns/transport_adapter.go': dns}.items():
        write(vendor, relative, raw)
    write(vendor, PT_OWNER, (json.dumps(dict(schema=1, core=PIN, source_sha256=digest(),
        dns_adapter_sha256=hashlib.sha256(dns).hexdigest(), registry_sha256=hashlib.sha256(registry).hexdigest(),
        network_sha256=hashlib.sha256(network).hexdigest(), module_sha256={name: hashlib.sha256(raw).hexdigest() for name, raw in modules.items()},
        files={name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(content.items())}), indent=2, sort_keys=True)+'\n').encode())


def comparison_client_contract():
    """Compile the actual controller receipt decoder beside native IPC tests.

    These are test-only files. No second validator or permissive boundary is
    maintained: changes to either shipping source enter native provenance and
    every emitted fixture receipt is checked by the actual client function.
    """
    source = (ROOT/'cmd/client/desktop_tor_comparison_native.go').read_text()
    start = 'func desktopTorComparisonStatus(raw []byte) (mobiletor.DesktopTorCompareStatus, error) {'
    end = 'func (c *desktopTorComparisonClient) read(cleanup bool) (mobiletor.DesktopTorCompareStatus, error) {'
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError('Desktop Tor controller receipt contract seam changed')
    begin, finish = source.index(start), source.index(end)
    if finish <= begin:
        raise ValueError('Desktop Tor controller receipt contract order changed')
    status = ('package main\n\nimport (\n "encoding/hex"\n "errors"\n "'+MODULE+'/routervpn/mobiletor"\n)\n\n'+source[begin:finish]).encode()
    exact = (ROOT/'cmd/client/multihop_exact_json.go').read_bytes().replace(
        b'"router-vpn/internal/multihoprelay"', ('"'+MODULE+'/experimental/libbox/routervpn/multihoprelay"').encode())
    return {'cmd/sing-box/routervpn_tor_controller_status_test.go': status,
            'cmd/sing-box/routervpn_tor_controller_json_test.go': exact}


def prepare(vendor, go='go', *, env=None):
    vendor = checked_vendor(vendor)
    controller_contract = comparison_client_contract()
    prepare_desktop_pt(vendor, go, env=env)
    # These pure policy types are shared by the Box's external and Tor proof
    # ownership code. The selective PT owner above shares this one Go runtime;
    # no embedded Tor implementation or C package is installed here.
    for package in PURE:
        for path in sorted((ROOT/'internal'/package).glob('*.go')):
            if path.name.endswith('_test.go') and not (package == 'mobiletor' and path.name in (
                    'desktop_socket_broker_test.go', 'desktop_socket_source_unix_test.go', 'desktop_socket_native_windows_test.go',
                    'desktop_socket_windows_identity_test.go',
                    'desktop_socket_source_privileged_test.go', 'desktop_socket_linux_guardian_test.go')):
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
    for name in ('padding_box.go', 'padding_box_test.go'):
        write(vendor, 'routervpn_tor_padding'+('_test' if name.endswith('_test.go') else '')+'.go',
              (ROOT/'mobile/toroutbound'/(name+'.tmpl')).read_bytes())
    MTU.prepare(vendor, mobile=False)
    DESKTOP_MTU.prepare(vendor)
    STRATEGY.prepare(vendor, mobile=False)
    prepare_network_startup(vendor)
    EXTERNAL.prepare(vendor, mobile=False)
    RELAY.OPENVPN_REMOTE.prepare(vendor)
    templates = [*sorted((ROOT/'mobile/desktop').glob('external*.go.tmpl')), *sorted((ROOT/'mobile/desktop').glob('mtu*.go.tmpl'))]
    for template in templates:
        write(vendor, 'cmd/sing-box/routervpn_'+template.name.removesuffix('.tmpl'), template.read_bytes())
    for relative, raw in controller_contract.items():
        write(vendor, relative, raw)
    print('Desktop native external proof source:', digest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path, nargs='?')
    parser.add_argument('--digest', action='store_true')
    parser.add_argument('--go', default='go')
    arguments = parser.parse_args()
    if arguments.digest:
        print(digest())
    elif arguments.vendor:
        prepare(arguments.vendor, arguments.go)
    else:
        parser.error('vendor or --digest required')
