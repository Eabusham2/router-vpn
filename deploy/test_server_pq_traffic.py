#!/usr/bin/env python3
"""Run real PQ-keyed WG/AWG traffic inside an exact prepared native core.

Only loopback sockets and in-process IP stacks are used. The native protocol,
peer-key installation, cipher, production endpoint and endpoint teardown remain
real. These tests are not physical-device leak or deployed-node acceptance.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
COPIES = {
    'mobile/pq/native_factory_real_test.go.tmpl': 'protocol/routervpnpq/native_factory_real_test.go',
    'mobile/pq/native_traffic_test.go.tmpl': 'protocol/routervpnpq/native_traffic_test.go',
    'mobile/pq/wireguard_protocol_readback.go.tmpl': 'protocol/wireguard/routervpn_pq_readback.go',
    'mobile/pq/wireguard_transport_readback.go.tmpl': 'transport/wireguard/routervpn_pq_readback.go',
    'mobile/pq/amnezia_readback.go.tmpl': 'protocol/routervpnamnezia/routervpn_pq_readback.go',
}


def run(core, library, keys):
    core, library, keys = Path(core).resolve(), Path(library), Path(keys)
    if subprocess.check_output(['git', '-C', str(core), 'rev-parse', 'HEAD'], text=True).strip() != CORE:
        raise ValueError('traffic test requires the exact prepared native core')
    if library.is_symlink() or not library.is_file() or library.name != 'libroutervpn_rosenpass.a':
        raise ValueError('real pinned Rust library required')
    if keys.is_symlink() or not keys.is_dir():
        raise ValueError('disposable upstream test key directory required')
    # Verify the actual endpoint/factory and the test-only reference adapter;
    # never quietly replace a different production implementation for this gate.
    for source, destination in (
        ('mobile/pq/native_factory.go.tmpl', 'protocol/routervpnpq/native_factory.go'),
        ('mobile/pq/endpoint.go.tmpl', 'protocol/routervpnpq/endpoint.go'),
        ('mobile/amnezia/pq_reference_fixture.go.tmpl', 'protocol/routervpnamnezia/pq_reference_fixture.go'),
    ):
        path = core/destination
        if path.is_symlink() or not path.resolve().is_relative_to(core) or path.read_bytes() != (ROOT/source).read_bytes():
            raise ValueError('native traffic gate source differs from the prepared shipping implementation')
    pending = {}
    for source, destination in COPIES.items():
        path = core/destination
        data = (ROOT/source).read_bytes()
        if path.is_symlink() or not path.resolve().is_relative_to(core):
            raise ValueError('linked traffic-test destination')
        if path.exists() and (not path.is_file() or path.read_bytes() != data):
            raise ValueError('foreign traffic-test source')
        if not path.exists():
            pending[path] = data
    made = []
    try:
        for path, data in pending.items():
            with path.open('xb') as output:
                made.append(path)
                output.write(data)
        with tempfile.TemporaryDirectory(prefix='routervpn-pq-link-') as tmp:
            shutil.copyfile(library, Path(tmp)/library.name)
            environment = dict(os.environ, CGO_ENABLED='1', CGO_LDFLAGS='-L'+tmp,
                               ROUTERVPN_PQ_TEST_KEYS=str(keys.resolve()))
            subprocess.run([
                'go', 'test', '-mod=mod', '-race', '-count=1', '-timeout=100s',
                '-tags', 'with_quic,with_wireguard,with_gvisor,routervpn_native_pq,routervpn_pq_traffic_test',
                '-ldflags=-checklinkname=0', '-run', '^TestRealPQTraffic', './protocol/routervpnpq',
            ], cwd=core, env=environment, check=True, timeout=180)
    finally:
        for path in made:
            path.unlink()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--keys', type=Path, required=True)
    args = parser.parse_args()
    run(args.core, args.library, args.keys)
