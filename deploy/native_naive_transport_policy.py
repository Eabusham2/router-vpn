"""Keep native Naive H2 on TCP without changing its captured DNS or H3 owner."""
from pathlib import Path
import argparse
import hashlib
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
SOURCE_SHA256 = '9e01f79402408a0325b7e14334c0c8e72183f7963ca5efcc80bf201ea14c59f3'
OUTBOUND = 'protocol/naive/outbound.go'
OLD = b'\t\tDialer:                   outboundDialer,'
NEW = b'\t\tDialer:                   routerVPNNaiveTransport(outboundDialer, options.QUIC),'
TEMPLATES = {
    'transport.go.tmpl': 'protocol/naive/routervpn_transport.go',
    'transport_test.go.tmpl': 'protocol/naive/routervpn_transport_test.go',
}


def inputs():
    return [Path(__file__).resolve(), ROOT/'deploy/test_native_naive_transport_policy.py',
            *(ROOT/'mobile/naive'/name for name in TEMPLATES)]


def patch(raw):
    original = raw.replace(NEW, OLD, 1) if raw.count(NEW) == 1 else raw
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256 or original.count(OLD) != 1:
        raise ValueError('Pinned Naive outbound differs; H2 transport policy refused')
    expected = original.replace(OLD, NEW, 1)
    if raw not in (original, expected):
        raise ValueError('Partial native Naive H2 transport policy')
    return expected


def owned(vendor, relative, *, required):
    path = vendor/relative
    for parent in (path, *path.parents):
        if parent == vendor:
            break
        if parent.is_symlink():
            raise ValueError('Linked native Naive transport source: '+relative)
    if not path.resolve().is_relative_to(vendor):
        raise ValueError('Native Naive transport source escaped its checkout')
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Native Naive transport source is not an owned regular file: '+relative)
    elif required:
        raise ValueError('Missing native Naive transport source: '+relative)
    return path


def planned_sources(vendor):
    vendor = Path(vendor).absolute()
    if vendor.is_symlink() or not vendor.is_dir():
        raise ValueError('Unsafe native Naive checkout')
    vendor = vendor.resolve()
    head = subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip()
    if head != PIN or not owned(vendor, 'go.mod', required=True).read_bytes().startswith(b'module github.com/sagernet/sing-box\n'):
        raise ValueError('Native Naive transport requires the exact pinned core')
    paths = subprocess.check_output(['git', '-C', str(vendor), 'ls-tree', '-r', '--name-only', PIN,
                                    '--', 'protocol/naive', 'common/uot'], text=True).splitlines()
    original_paths = {name for name in paths if name.endswith('.go')}
    actual = {path.relative_to(vendor).as_posix() for directory in ('protocol/naive', 'common/uot')
              for path in (vendor/directory).rglob('*.go')}
    generated = set(TEMPLATES.values())
    if OUTBOUND not in original_paths or actual - generated != original_paths or actual - original_paths - generated:
        raise ValueError('Native Naive implementation differs from its declared pinned file set')
    files = {}
    for relative in sorted(original_paths):
        path = owned(vendor, relative, required=True)
        original = subprocess.check_output(['git', '-C', str(vendor), 'show', PIN+':'+relative])
        raw = path.read_bytes()
        if relative == OUTBOUND:
            expected = patch(original)
            if patch(raw) != expected:
                raise ValueError('Native Naive outbound lost its exact H2 transport policy')
        else:
            expected = original
            if raw != original:
                raise ValueError('Native Naive implementation differs from its pinned source: '+relative)
        files[path] = expected
    for name, relative in TEMPLATES.items():
        source = ROOT/'mobile/naive'/name
        if source.is_symlink() or not source.is_file():
            raise ValueError('Native Naive transport lost its original template')
        path = owned(vendor, relative, required=False)
        expected = source.read_bytes()
        if path.exists() and path.read_bytes() != expected:
            raise ValueError('Native Naive transport helper differs from its original source')
        files[path] = expected
    return vendor, files


def verify(vendor):
    vendor, files = planned_sources(vendor)
    records = {}
    for path, expected in files.items():
        if not path.is_file() or path.read_bytes() != expected:
            raise ValueError('Native Naive H2 transport policy is absent or incomplete')
        records[path.relative_to(vendor).as_posix()] = hashlib.sha256(expected).hexdigest()
    return records


def prepare(vendor):
    vendor, files = planned_sources(vendor)
    for path, expected in files.items():
        if not path.exists() or path.read_bytes() != expected:
            path.write_bytes(expected)
    verify(vendor)
    print('Verified native Naive H2 TCP ownership; original DNS and H3 transport retained')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    verify(args.vendor) if args.verify else prepare(args.vendor)
