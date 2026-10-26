#!/usr/bin/env python3
"""Execute the owned HY2/QUIC deadline tests in the actual prepared module graph."""
from pathlib import Path
import argparse
import importlib.util
import os
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_hy2_deadlines', ROOT/'deploy/prepare-hysteria2-deadlines.py')
POLICY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(POLICY)


def run(vendor, go='go', env=None):
    vendor = Path(vendor).resolve()
    env = dict(os.environ if env is None else env)
    POLICY.verify(vendor, go, env)
    # Each host executes its own binaries. Go's race detector does not support
    # Windows ARM64; that native matrix still executes both ordinary variants.
    target = subprocess.check_output([go, 'env', 'GOOS', 'GOARCH'], cwd=vendor, env=env, text=True).split()
    host = [('darwin' if platform.system() == 'Darwin' else platform.system().lower()),
            {'x86_64': 'amd64', 'AMD64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64', 'ARM64': 'arm64'}.get(platform.machine(), '')]
    if target != host:
        raise ValueError('HY2 deadline validation must execute on the selected native host')
    race = [] if target == ['windows', 'arm64'] else ['-race']
    packages = ['github.com/sagernet/quic-go', 'github.com/sagernet/sing-quic/hysteria2']
    for tags in ([], ['-tags=low_memory']):
        subprocess.run([go, 'test', *race, '-mod=readonly', *tags, *packages,
                        '-run', '^TestRouterVPN(Datagram|Hysteria)Deadline', '-count=1', '-timeout=60s'],
                       cwd=vendor, env=env, check=True, timeout=180)
    POLICY.verify(vendor, go, env)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    run(args.vendor, args.go)
