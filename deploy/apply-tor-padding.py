#!/usr/bin/env python3
"""Apply the versioned native extensions to the exact pinned Tor source.

The existing lock filename now covers both circuit cover and the private
last-relay BEGIN_DIR prerequisite. Shared relay/control hooks have one exact
final state; the extensions cannot be independently overlaid or certified.

The embedding and standalone builders use this same function. A changed,
partially patched, linked or merely similar upstream source is never accepted.
No network access, generated replacement source or fuzzy patching is used.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'mobile/tor'
LOCK = DIRECTORY / 'padding-source-lock.json'
PATCH = DIRECTORY / 'padding-integration.patch'
TOR_COMMIT = '4a522a3ca491c6c04d4a44cb006b92101c42efc1'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def relative(value):
    path = PurePosixPath(value)
    if not value or path.is_absolute() or '..' in path.parts or str(path) != value or '\\' in value:
        raise ValueError('Tor padding source path is not a canonical relative path')
    return path


def regular(root, name, *, absent=False):
    path = Path(root).joinpath(*relative(name).parts)
    current = path
    while current != Path(root):
        if current.is_symlink():
            raise ValueError('Tor padding source must not traverse a symbolic link')
        current = current.parent
    if absent:
        if path.exists():
            raise ValueError('Tor padding source would replace an existing file')
    elif not path.is_file():
        raise ValueError('Tor padding source file is missing: ' + name)
    return path


def lock():
    value = json.loads(LOCK.read_text())
    upstream = json.loads((ROOT / 'mobile/torpack/sources.json').read_text())
    if value.get('schema') != 1 or value.get('version') != 1 or \
            value.get('tor_commit') != TOR_COMMIT or upstream['sources']['tor']['commit'] != TOR_COMMIT:
        raise ValueError('Tor padding and the native source lock must advance together')
    if sha(PATCH) != value['patch_sha256']:
        raise ValueError('Tor padding integration patch checksum differs from its lock')
    if len(value['files']) != 11 or len(value['copies']) != 6 or \
            value.get('extensions') != {'circuit_cover': 1, 'last_relay_probe': 1} or \
            any(type(version) is not int for version in value['extensions'].values()):
        raise ValueError('Tor padding source closure is incomplete')
    for name, record in value['copies'].items():
        if sha(regular(ROOT, name)) != record['sha256']:
            raise ValueError('Tor padding implementation checksum differs from its lock')
        relative(record['target'])
    return value


def inputs():
    value = lock()
    return [Path(__file__).resolve(), LOCK, PATCH,
            *(ROOT / name for name in sorted(value['copies']))]


def receipt():
    value = lock()
    return dict(version=1, direction='outgoing', tor_commit=TOR_COMMIT,
                source_lock_sha256=sha(LOCK), patch_sha256=value['patch_sha256'])


def verify(source):
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise ValueError('Tor padding source must be an unlinked directory')
    value = lock()
    for name, record in value['files'].items():
        if sha(regular(source, name)) != record['patched']:
            raise ValueError('Tor padding patched source checksum differs: ' + name)
    for record in value['copies'].values():
        if sha(regular(source, record['target'])) != record['sha256']:
            raise ValueError('Tor padding copied source checksum differs')
    return receipt()


def apply(source):
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise ValueError('Tor padding source must be an unlinked directory')
    value = lock()
    for name, record in value['files'].items():
        if sha(regular(source, name)) != record['original']:
            raise ValueError('Tor padding requires the exact unmodified source: ' + name)
    for record in value['copies'].values():
        regular(source, record['target'], absent=True)
    command = ['patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch',
               '--reject-file=-', '-p1', '-i', str(PATCH)]
    subprocess.run([*command, '--dry-run'], cwd=source, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    subprocess.run(command, cwd=source, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    for name, record in value['copies'].items():
        target = regular(source, record['target'], absent=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write((ROOT / name).read_bytes())
    return verify(source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify(args.source) if args.verify else apply(args.source), sort_keys=True))


if __name__ == '__main__':
    main()
