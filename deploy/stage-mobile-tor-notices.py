#!/usr/bin/env python3
"""Stage the verified native Tor and PT notices as app resources."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('routervpn_tor_package', ROOT / 'deploy/build-mobile-tor-package.py')
PACKAGE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PACKAGE)
OWNER = 'NOTICES.json'


def payload(native_package):
    if native_package.is_symlink():
        raise ValueError('Tor notice source package is linked')
    kind = json.loads((native_package / 'source.json').read_text())['platform']
    record = PACKAGE.verify(native_package, kind, binaries=False)
    copies = {name: (native_package / name).read_bytes() for name in record['files']
              if name.startswith(('licenses/', 'notices/'))}
    copies['TOR-NATIVE-SOURCE.json'] = (native_package / 'source.json').read_bytes()
    copies['SHA256SUMS'] = ''.join(hashlib.sha256(content).hexdigest() + '  ' + name + '\n'
        for name, content in sorted(copies.items())).encode()
    owner = dict(schema=1, source_sha256=record['source_sha256'],
                 files={name: hashlib.sha256(content).hexdigest() for name, content in sorted(copies.items())})
    copies[OWNER] = (json.dumps(owner, sort_keys=True, indent=2) + '\n').encode()
    return copies


def read_tree(output):
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        raise ValueError('Tor notice output is not an owned directory')
    result = {}
    for path in output.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('Tor notice output contains a linked or nonregular entry')
        if path.is_file():
            result[str(path.relative_to(output))] = path.read_bytes()
    return result


def verify(output, copies):
    if read_tree(output) != copies:
        raise ValueError('Packaged native Tor/PT notices are missing, stale or changed')


def stage(native_package, output):
    copies = payload(native_package)
    output = output.parent.resolve() / output.name
    existing = read_tree(output)
    if existing:
        try:
            owner = json.loads(existing[OWNER])
            recorded = {name: hashlib.sha256(content).hexdigest() for name, content in existing.items() if name != OWNER}
            if owner['schema'] != 1 or owner['files'] != recorded or not set(existing) <= set(copies):
                raise ValueError('Refusing to replace changed or unrelated Tor notice resources')
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise ValueError('Refusing to replace unowned Tor notice resources') from error
    if existing == copies:
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.routervpn-tor-notices-', dir=output.parent) as temporary:
        work = Path(temporary)
        prepared = work / 'prepared'; prepared.mkdir()
        for name, content in copies.items():
            path = prepared / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        verify(prepared, copies)
        # Recheck ownership immediately before the atomic directory swap.
        if read_tree(output) != existing:
            raise ValueError('Tor notice resources changed during staging')
        backup = work / 'previous'
        if output.exists():
            os.replace(output, backup)
        try:
            os.replace(prepared, output)
        except BaseException:
            if backup.exists():
                os.replace(backup, output)
            raise
        if backup.exists():
            shutil.rmtree(backup)
    verify(output, copies)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    if args.verify:
        verify(args.output, payload(args.package))
    else:
        stage(args.package, args.output)
    print('Verified native Tor/PT redistribution notices:', args.output)
