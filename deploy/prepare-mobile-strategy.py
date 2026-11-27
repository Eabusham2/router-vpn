#!/usr/bin/env python3
"""Install bounded DNS proof and checked fresh native lifetime in the pinned core."""
from pathlib import Path
import argparse
import hashlib
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
UDP_PATH = 'dns/transport/udp.go'
UDP_TEST_PROJECTION = 'dns/transport/routervpn_udp_reuse_test.go'
UDP_ORIGINAL_SHA256 = '392d06470c8304e2af28a4361056b5433a6019d259310bc0e7c7b7074b4338d2'
UDP_PREPARED_SHA256 = '827b2e9468ec0bfa80843e925b3b43ab0bc4793dc5f99aae589086947e8d9fef'
NETWORK_STARTUP_TEMPLATE = ROOT / 'mobile/desktop/tor_network_startup.go.tmpl'
NETWORK_STARTUP_PATH = 'route/routervpn_desktop_tor_network_startup.go'

def udp_source(original):
    """One declared option on the exact pin; the multiplexer stays unchanged."""
    if hashlib.sha256(original).hexdigest() != UDP_ORIGINAL_SHA256:
        raise ValueError('pinned UDP DNS source changed')
    before = b'\t\twrite:    t.writeQuery,\n\t\treadNext: t.readResponse,\n'
    after = b'\t\twrite:          t.writeQuery,\n\t\treadNext:       t.readResponse,\n\t\tretryReadError: true,\n'
    if original.count(before) != 1:
        raise ValueError('pinned UDP DNS multiplexer boundary changed')
    result = original.replace(before, after, 1)
    if hashlib.sha256(result).hexdigest() != UDP_PREPARED_SHA256:
        raise ValueError('declared UDP DNS recovery source changed')
    return result

def udp_original(vendor):
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('UDP DNS recovery requires the exact pinned native core')
    return subprocess.check_output(['git', '-C', str(vendor), 'show', PIN + ':' + UDP_PATH])

def verify_udp(vendor):
    expected = udp_source(udp_original(vendor))
    path = vendor / UDP_PATH
    if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
        raise ValueError('declared UDP DNS projection changed: ' + UDP_PATH)
    return {UDP_PATH: hashlib.sha256(expected).hexdigest()}

def prepare_udp(vendor):
    original = udp_original(vendor)
    expected = udp_source(original)
    path = vendor / UDP_PATH
    if path.is_symlink() or path.read_bytes() not in (original, expected):
        raise ValueError('foreign UDP DNS preparation input')
    path.write_bytes(expected)
    verify_udp(vendor)

def network_startup_source(vendor, source):
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
            raise ValueError('Native network lifecycle boundary changed')
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
            raise ValueError('Native network startup differs from its exact preparation')
        source = source.replace(actual, after, 1)
    field = '\tstarted                  atomic.Bool\n'
    owned = '\trouterVPNStartup         routerVPNNetworkStartup\n'+field
    if source.count(field) != 1 or ('routerVPNStartup ' in source and source.count(owned) != 1):
        raise ValueError('Native network startup field differs')
    if owned not in source:
        source = source.replace(field, owned, 1)
    return source.encode()


def prepare_network_startup(vendor, original, source):
    # Reuse the one existing barrier source. The desktop PT inventory retains
    # its original exact helper entry; both projections accept identical bytes.
    template = NETWORK_STARTUP_TEMPLATE
    if template.is_symlink() or not template.is_file():
        raise ValueError('Linked or missing native network startup template')
    helper = template.read_bytes()
    if not helper.startswith(b'package route\n'):
        raise ValueError('Native network startup helper has another package')

    def destination(relative):
        path = vendor / relative
        for parent in (path, *path.parents):
            if parent == vendor:
                break
            if parent.is_symlink():
                raise ValueError('Linked native network startup destination')
        if not path.resolve().is_relative_to(vendor):
            raise ValueError('Native network startup destination escaped its core')
        return path

    network = destination('route/network.go')
    target = destination(NETWORK_STARTUP_PATH)
    if not network.is_file():
        raise ValueError('Missing native network lifecycle source')
    previous = None
    if target.exists():
        if not target.is_file():
            raise ValueError('Native network startup helper is not a regular file')
        previous = target.read_bytes()
        if previous != helper:
            raise ValueError('Changed native network startup helper')
    prepared = network_startup_source(vendor, source)
    if network.read_bytes() != original or template.read_bytes() != helper:
        raise ValueError('Native network startup source changed before adoption')
    if (target.read_bytes() if target.exists() else None) != previous:
        raise ValueError('Native network startup helper changed before adoption')
    target.write_bytes(helper)
    network.write_bytes(prepared)


def inputs():
    return [Path(__file__).resolve(), NETWORK_STARTUP_TEMPLATE] + sorted((ROOT / 'mobile/strategy').glob('*.tmpl'))

def digest():
    value = hashlib.sha256()
    for source in inputs():
        value.update(str(source.relative_to(ROOT)).encode() + b'\0' + source.read_bytes())
    return value.hexdigest()

def prepare(vendor, *, mobile=True):
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('provider strategy requires the exact pinned native core')
    prepare_udp(vendor)
    # The pinned managers already accumulate every close error but discard the
    # result. Preserve their close order, locking and retained-TUN changes; only
    # return the existing error so a strategy can quarantine failed teardown.
    for relative, receiver in {
        'adapter/inbound/manager.go': 'Manager',
        'adapter/outbound/manager.go': 'Manager',
        'adapter/endpoint/manager.go': 'Manager',
        'adapter/service/manager.go': 'Manager',
        'dns/transport_manager.go': 'TransportManager',
    }.items():
        path = vendor / relative
        if path.is_symlink():
            raise ValueError('symlink at strategy lifecycle boundary')
        source = path.read_text()
        marker = f'func (m *{receiver}) Close() error {{'
        if source.count(marker) != 1:
            raise ValueError('pinned native close boundary changed: ' + relative)
        start = source.index(marker)
        end = source.index('\n}\n', start) + 2
        close = source[start:end]
        if '\tvar err error\n' not in close or '\terr = E.Append(err,' not in close:
            raise ValueError('native close no longer aggregates errors: ' + relative)
        if close.endswith('\treturn nil\n}'):
            source = source[:start] + close[:-len('\treturn nil\n}')] + '\treturn err\n}' + source[end:]
            path.write_text(source)
        elif not close.endswith('\treturn err\n}'):
            raise ValueError('native close result boundary changed: ' + relative)
    # A real failed-start/close race test exposes the pinned interface monitor
    # reading this lifecycle flag while Start writes it. Publish and retire it
    # atomically; the existing callback cancellation/join remains unchanged.
    network = vendor / 'route/network.go'
    if network.is_symlink():
        raise ValueError('symlink at native network lifetime boundary')
    network_original = network.read_bytes()
    source = network_original.decode('utf-8').replace('\r\n', '\n')
    for before, after in [
        ('\t"sync"\n', '\t"sync"\n\t"sync/atomic"\n'),
        ('\tstarted                  bool\n', '\tstarted                  atomic.Bool\n'),
        ('\t\tr.started = true\n', '\t\tr.started.Store(true)\n'),
        ('\tif !r.started {\n', '\tif !r.started.Load() {\n'),
        ('func (r *NetworkManager) Close() error {\n',
         'func (r *NetworkManager) Close() error {\n\tr.started.Store(false)\n'),
    ]:
        if after in source:
            continue
        if source.count(before) != 1:
            raise ValueError('pinned network lifetime changed')
        source = source.replace(before, after, 1)
    prepare_network_startup(vendor, network_original, source)
    for name, target in {'box.go': 'routervpn_strategy_dns.go', 'observation.go': 'adapter/routervpn_observation.go', 'network_context.go': 'route/routervpn_observation.go', 'monitor_context.go': 'experimental/libbox/routervpn_monitor_context.go', 'inbound_context.go': 'adapter/inbound/routervpn_observation.go', 'outbound_context.go': 'adapter/outbound/routervpn_observation.go', 'endpoint_context.go': 'adapter/endpoint/routervpn_observation.go', 'service_context.go': 'adapter/service/routervpn_observation.go', 'dns_context.go': 'dns/routervpn_observation.go', 'daemon.go': 'daemon/routervpn_strategy.go', 'bridge.go': 'experimental/libbox/routervpn_strategy.go'}.items():
        if not mobile and (target.startswith('experimental/libbox/') or target.startswith('daemon/')):
            continue
        (vendor / target).write_bytes((ROOT / 'mobile/strategy' / (name + '.tmpl')).read_bytes())
    print('Owned provider strategy source:', digest())

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path, nargs='?')
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest: print(digest())
    elif args.vendor: prepare(args.vendor)
    else: parser.error('vendor or --digest required')
