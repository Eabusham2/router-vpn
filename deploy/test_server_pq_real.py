#!/usr/bin/env python3
"""Exercise the shipping Go/C factory against real pinned-Rust protocol bytes.

Requires a built static library and disposable keys produced by the repository's
native_keys example. No test-double library, VPN interface or external server is
created by this test. The test uses no home credentials and logs no key material.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(library, keys):
    library, keys = Path(library), Path(keys)
    if library.is_symlink() or not library.is_file() or library.name != 'libroutervpn_rosenpass.a':
        raise ValueError('real pinned Rust static library is required')
    if keys.is_symlink() or not keys.is_dir():
        raise ValueError('disposable native key fixture directory is required')
    for name in ('client', 'server', 'other'):
        for kind in ('secret', 'public'):
            path = keys/(name+'.'+kind)
            if path.is_symlink() or not path.is_file() or not 32 <= path.stat().st_size <= 2*1024*1024:
                raise ValueError('native key fixture is missing or unbounded')
    with tempfile.TemporaryDirectory(prefix='routervpn-pq-real-') as tmp:
        root = Path(tmp)
        package = root/'protocol/routervpnpq'; package.mkdir(parents=True)
        shared = root/'experimental/libbox/routervpn/mobilepq'; shared.mkdir(parents=True)
        (root/'go.mod').write_text('module github.com/sagernet/sing-box\n\ngo 1.23\n')
        for source in (ROOT/'internal/mobilepq').glob('*.go'):
            if not source.name.endswith('_test.go'):
                shutil.copyfile(source, shared/source.name)
        shutil.copyfile(ROOT/'mobile/pq/native_factory.go.tmpl', package/'native_factory.go')
        shutil.copyfile(ROOT/'mobile/pq/native_factory_real_test.go.tmpl', package/'native_factory_real_test.go')
        for name in ('routervpn_rosenpass.h', 'routervpn_pq_host.h', 'routervpn_pq_host.c'):
            shutil.copyfile(ROOT/'mobile/rosenpass'/name, package/name)
        shutil.copyfile(library, root/library.name)
        # Only the build-owned temporary directory enters linker flags.
        environment = dict(os.environ, CGO_ENABLED='1', CGO_LDFLAGS='-L'+str(root),
                           ROUTERVPN_PQ_TEST_KEYS=str(keys.resolve()))
        subprocess.run(['go', 'test', '-race', '-count=1', '-timeout=120s', '-tags',
                        'routervpn_native_pq', './protocol/routervpnpq'], cwd=root,
                       env=environment, check=True, timeout=180)
        subprocess.run(['go', 'vet', '-tags', 'routervpn_native_pq', './protocol/routervpnpq'],
                       cwd=root, env=environment, check=True, timeout=90)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--keys', type=Path, required=True)
    args = parser.parse_args()
    run(args.library, args.keys)
