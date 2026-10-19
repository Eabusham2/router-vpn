#!/usr/bin/env python3
"""Run real local PT traffic/lifecycle gates and exact upstream failure controls."""

from pathlib import Path
import argparse
import hashlib
import json
import shutil
import stat
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'mobile/torpt'


def run(command, directory, log, expected=0):
    result = subprocess.run(command, cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    log.write_text(result.stdout)
    if result.returncode != expected:
        raise RuntimeError(f'{log.name}: command returned {result.returncode}; see the complete gate log')
    return result.stdout


def extract_module(go, manifest, output):
    module = manifest['repository'].removeprefix('https://')
    version = manifest['module_version']
    result = subprocess.run([go, 'mod', 'download', '-json', module + '@' + version], cwd=MODULE,
                            check=True, stdout=subprocess.PIPE, text=True)
    info = json.loads(result.stdout)
    if info.get('Path') != module or info.get('Version') != version or info.get('Sum') != manifest['module_sum']:
        raise ValueError('upstream PT module identity or content checksum changed')
    if info.get('Origin', {}).get('Hash') != manifest['commit']:
        raise ValueError('upstream PT source commit changed')
    prefix = module + '@' + version + '/'
    output.mkdir()
    # Extract the checksum-verified module archive, never a mutable module-cache
    # worktree. Reject links and traversal at this source-copy boundary.
    total = 0
    with zipfile.ZipFile(info['Zip']) as archive:
        for item in archive.infolist():
            if not item.filename.startswith(prefix):
                raise ValueError('module archive has an unexpected prefix')
            relative = Path(item.filename[len(prefix):])
            if relative.is_absolute() or '..' in relative.parts or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError('unsafe path in module archive')
            total += item.file_size
            if total > 128 * 1024 * 1024 or item.file_size > 20 * 1024 * 1024:
                raise ValueError('oversized upstream PT archive')
            target = output / relative
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(item))
    for name, checksum in manifest['original_sha256'].items():
        source = output / manifest['source_directory'] / name
        if hashlib.sha256(source.read_bytes()).hexdigest() != checksum:
            raise ValueError('upstream PT source file changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--output', type=Path, required=True, help='new evidence directory')
    parser.add_argument('--upstream-negative-controls', action='store_true')
    args = parser.parse_args()
    go = shutil.which(args.go)
    if not go:
        parser.error('Go toolchain was not found')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    version = run([go, 'version'], MODULE, output / 'go-version.log').strip()
    if not version.startswith('go version go1.26.3 '):
        raise ValueError('the native PT gate requires the pinned Go 1.26.3 toolchain')
    negative = {}
    if args.upstream_negative_controls:
        for package, name, failure in [
            ('meeklite', 'TestMeekCloseDrainsBackpressuredReaderAndWriter',
             'meek Close left a backpressured application Write blocked'),
            ('httpupgrade', 'TestClientPreservesApplicationBytesBufferedWithUpgradeHeaders',
             'WebTunnel discarded application bytes buffered with upgrade headers'),
        ]:
            source = MODULE / 'internal' / package
            manifest = json.loads((source / 'UPSTREAM.json').read_text())
            fixture = output / ('original-' + package)
            extract_module(go, manifest, fixture)
            test = 'backpressure_test.go' if package == 'meeklite' else 'buffering_test.go'
            target = fixture / manifest['source_directory'] / ('routervpn_' + test)
            target.write_bytes((source / test).read_bytes())
            result = run([go, 'test', '-count=1', '-timeout=20s', '-run', '^' + name + '$',
                          './' + manifest['source_directory']], fixture, output / (package + '-upstream-negative.log'), expected=1)
            if failure not in result or 'build failed' in result or 'test timed out' in result:
                raise ValueError('upstream negative control did not reproduce the required defect')
            negative[package] = {'commit': manifest['commit'], 'expected_failure': failure, 'reproduced': True}
    run([go, 'test', '-race', '-count=1', '-timeout=60s', './...'], MODULE, output / 'pt-race.log')
    sources = [Path(__file__).resolve()] + sorted(p for p in MODULE.rglob('*') if p.is_file())
    sources += sorted((ROOT / 'internal/mobiletor').glob('*.go'))
    sources += sorted((ROOT / 'internal/common').glob('*.go'))
    evidence = {
        'go': version, 'scope': 'local actual PT traffic, certificate verification, and owned teardown',
        'public_tor_traffic_tested': False, 'mobile_host_packaged': False, 'mobile_tor_capability_enabled': False,
        'race_gate_passed': True, 'upstream_negative_controls': negative,
        'source_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
    }
    (output / 'pt-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print('Native PT local data-path and drain gate passed:', output / 'pt-evidence.json')


if __name__ == '__main__':
    main()
