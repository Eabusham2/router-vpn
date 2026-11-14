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
    template = ROOT / 'mobile/strategy/udp_reuse_test.go.tmpl'
    records = {}
    for relative, content in ((UDP_PATH, expected), (UDP_TEST_PROJECTION, template.read_bytes())):
        path = vendor / relative
        if template.is_symlink() or path.is_symlink() or not path.is_file() or path.read_bytes() != content:
            raise ValueError('declared UDP DNS projection changed: ' + relative)
        records[relative] = hashlib.sha256(content).hexdigest()
    return records

def prepare_udp(vendor):
    original = udp_original(vendor)
    expected = udp_source(original)
    path = vendor / UDP_PATH
    projection = vendor / UDP_TEST_PROJECTION
    template = ROOT / 'mobile/strategy/udp_reuse_test.go.tmpl'
    if path.is_symlink() or projection.is_symlink() or template.is_symlink() or path.read_bytes() not in (original, expected):
        raise ValueError('foreign UDP DNS preparation input')
    # The existing multiplexer retries a read failure only on a reused socket,
    # once, through the original dialer and caller context. A new socket's
    # failure, cancellation, Reset and Close retain their original outcomes.
    path.write_bytes(expected)
    projection.write_bytes(template.read_bytes())
    verify_udp(vendor)

def inputs():
    return [Path(__file__).resolve()] + sorted((ROOT / 'mobile/strategy').glob('*.tmpl'))

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
    source = network.read_text()
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
    network.write_text(source)
    for name, target in {
        'box.go': 'routervpn_strategy_dns.go',
        'observation.go': 'adapter/routervpn_observation.go',
        'network_context.go': 'route/routervpn_observation.go',
        'monitor_context.go': 'experimental/libbox/routervpn_monitor_context.go',
        'inbound_context.go': 'adapter/inbound/routervpn_observation.go',
        'inbound_context_test.go': 'adapter/inbound/routervpn_observation_test.go',
        'outbound_context.go': 'adapter/outbound/routervpn_observation.go',
        'outbound_context_test.go': 'adapter/outbound/routervpn_observation_test.go',
        'endpoint_context.go': 'adapter/endpoint/routervpn_observation.go',
        'endpoint_context_test.go': 'adapter/endpoint/routervpn_observation_test.go',
        'service_context.go': 'adapter/service/routervpn_observation.go',
        'service_context_test.go': 'adapter/service/routervpn_observation_test.go',
        'dns_context.go': 'dns/routervpn_observation.go',
        'dns_context_test.go': 'dns/routervpn_observation_test.go',
        'box_test.go': 'routervpn_strategy_dns_test.go',
        'daemon.go': 'daemon/routervpn_strategy.go',
        'daemon_test.go': 'daemon/routervpn_strategy_test.go',
        'network_test.go': 'route/routervpn_strategy_test.go',
        'bridge.go': 'experimental/libbox/routervpn_strategy.go',
    }.items():
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
