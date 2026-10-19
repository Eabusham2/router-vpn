#!/usr/bin/env python3
"""Verify pinned PT sources, real local traffic, and retained-worker failure controls."""

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
CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'


def run(command, directory, log, expected=0):
    result = subprocess.run(command, cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    log.write_text(result.stdout)
    if result.returncode != expected:
        raise RuntimeError(f'{log.name}: command returned {result.returncode}; see the complete gate log')
    return result.stdout


def decode_stream(text):
    decoder = json.JSONDecoder()
    result = []
    text = text.lstrip()
    while text:
        value, end = decoder.raw_decode(text)
        result.append(value)
        text = text[end:].lstrip()
    return result


def source_snapshot():
    sources = {'deploy/test-mobile-tor-pt.py': Path(__file__).resolve()}
    for path in sorted(MODULE.rglob('*')):
        if path.is_symlink():
            raise ValueError('Linked PT gate input')
        if path.is_file():
            sources['mobile/torpt/' + str(path.relative_to(MODULE))] = path
    for name in ('mobiletor', 'common'):
        for path in sorted((ROOT / 'internal' / name).glob('*.go')):
            if path.is_symlink():
                raise ValueError('Linked shared PT gate input')
            sources[str(path.relative_to(ROOT))] = path
    sources['go.mod'] = ROOT / 'go.mod'
    return {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(sources.items())}


def archive_entries(info):
    prefix = info['Path'] + '@' + info['Version'] + '/'
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
            if not item.is_dir():
                yield relative, archive.read(item)


def verify_pins(go, output):
    lock = json.loads((MODULE / 'SOURCE_LOCK.json').read_text())
    if lock.get('schema') != 1 or lock.get('native_core') != CORE or lock.get('go') != 'go1.26.3':
        raise ValueError('PT source lock changed schema, Go toolchain, or native core')
    module = json.loads(run([go, 'mod', 'edit', '-json'], MODULE, output / 'pt-module.log'))
    required = {item['Path']: item['Version'] for item in module.get('Require', []) if item['Path'] != 'router-vpn'}
    pinned = {item['path']: item for item in lock['modules']}
    if len(pinned) != len(lock['modules']) or required != {name: item['version'] for name, item in pinned.items()}:
        raise ValueError('PT source lock differs from the actual module requirements')
    sums = {tuple(line.split()[:2]): line.split()[2] for line in (MODULE / 'go.sum').read_text().splitlines()}
    for name, item in pinned.items():
        if sums.get((name, item['version'])) != item['sum'] or sums.get((name, item['version'] + '/go.mod')) != item['go_mod_sum']:
            raise ValueError('PT source lock differs from its module checksums')
    downloaded = decode_stream(run([go, 'mod', 'download', '-json', *[name + '@' + pinned[name]['version'] for name in sorted(pinned)]],
                                  MODULE, output / 'pt-module-download.log'))
    archives = {item.get('Path'): item for item in downloaded}
    if len(archives) != len(downloaded) or set(archives) != set(pinned):
        raise ValueError('PT module download returned different pinned sources')
    for name, info in archives.items():
        item = pinned[name]
        if info.get('Error') or info.get('Version') != item['version'] or info.get('Sum') != item['sum'] or info.get('GoModSum') != item['go_mod_sum']:
            raise ValueError('upstream PT module identity or content checksum changed')
        if item.get('source_commit') and info.get('Origin', {}).get('Hash') != item['source_commit']:
            raise ValueError('upstream PT source commit changed')
    # Verify the actual archive/cache contents, not just cached metadata.
    # This archive-only graph omits the local router-vpn source replacement;
    # Go 1.26 otherwise tries to verify that local placeholder as an archive.
    verification = output / 'pinned-module-verification'
    verification.mkdir()
    requirements = ''.join('\t' + name + ' ' + pinned[name]['version'] + '\n' for name in sorted(pinned))
    (verification / 'go.mod').write_text('module routervpn-pt-archive-verification\n\ngo 1.26.0\n\nrequire (\n' + requirements + ')\n')
    (verification / 'go.sum').write_bytes((MODULE / 'go.sum').read_bytes())
    run([go, 'mod', 'verify'], verification, output / 'pt-module-verify.log')
    notices = []
    for name, info in sorted(archives.items()):
        files = []
        for relative, data in sorted(archive_entries(info), key=lambda pair: str(pair[0])):
            if len(relative.parts) == 1 and relative.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE', 'COPYRIGHT')):
                files.append(dict(path=str(relative), sha256=hashlib.sha256(data).hexdigest(), text=data.decode('utf-8')))
        if not files:
            raise ValueError('Pinned PT dependency has no captured root license notice')
        notices.append(dict(module=name, version=info['Version'], module_sum=info['Sum'], files=files))
    expected_notices = dict(schema=1, scope='Pinned PT module dependency root license and notice files; adapted source notices are adjacent to each package.', modules=notices)
    if json.loads((MODULE / 'LICENSE-DEPENDENCIES.json').read_text()) != expected_notices:
        raise ValueError('PT dependency notices differ from the exact pinned source archives')
    return module, archives


def manifest_identity(manifest):
    name = manifest.get('module', manifest['repository'].removeprefix('https://'))
    version = manifest.get('version', manifest.get('module_version'))
    return name, version


def extract_module(info, output):
    output.mkdir()
    for relative, data in archive_entries(info):
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def verify_adaptations(archives, output):
    verified = {}
    for path in sorted((MODULE / 'internal').glob('*/UPSTREAM.json')):
        manifest = json.loads(path.read_text())
        name, version = manifest_identity(manifest)
        info = archives.get(name, {})
        if info.get('Version') != version or info.get('Sum') != manifest['module_sum'] or info.get('Origin', {}).get('Hash') != manifest['commit']:
            raise ValueError('Adapted PT source manifest differs from its pinned archive')
        files = dict(archive_entries(info))
        original = manifest.get('original_files')
        if original is None:
            original = {str(Path(manifest['source_directory']) / name): checksum for name, checksum in manifest['original_sha256'].items()}
        for name, checksum in original.items():
            data = files.get(Path(name))
            if data is None or hashlib.sha256(data).hexdigest() != checksum:
                raise ValueError('upstream PT source file changed: ' + name)
            if 'modified_files' in manifest and name not in manifest['modified_files'] and name not in manifest.get('omitted_files', []):
                if (path.parent / name).read_bytes() != data:
                    raise ValueError('An unmodified private protocol source differs from upstream: ' + name)
        verified[path.parent.name] = dict(commit=manifest['commit'], module=info['Path'], version=version,
                                          module_sum=info['Sum'], original_files_verified=len(original))
    (output / 'pt-adapted-source-verification.json').write_text(json.dumps(verified, indent=2, sort_keys=True) + '\n')
    return verified


def prepare_negative_module(go, fixture, manifest, module):
    # Keep the original production source byte-for-byte, but run exactly our
    # regression against the same selected dependency versions as shipping.
    # Unrelated upstream tests are outside this negative control.
    for path in fixture.rglob('*_test.go'):
        path.unlink()
    name, _ = manifest_identity(manifest)
    requirements = sorted((item['Path'], item['Version']) for item in module['Require'] if item['Path'] not in (name, 'router-vpn'))
    text = 'module ' + name + '\n\ngo 1.26.0\n\nrequire (\n'
    text += ''.join('\t' + path + ' ' + version + '\n' for path, version in requirements)
    text += ')\n'
    (fixture / 'go.mod').write_text(text)
    (fixture / 'go.sum').write_bytes((MODULE / 'go.sum').read_bytes())


def negative_controls(go, module, archives, output):
    result = {}
    for key, package, directory, test, name, failure in (
        ('meeklite', 'meeklite', 'transports/meeklite', 'backpressure_test.go', 'TestMeekCloseDrainsBackpressuredReaderAndWriter',
         'meek Close left a backpressured application Write blocked'),
        ('meek-physical-io', 'meeklite', 'transports/meeklite', 'http_owner_test.go', 'TestMeekCloseRetainsActualTLSRead',
         'meek Close released an active physical TLS read'),
        ('httpupgrade', 'httpupgrade', 'transport/httpupgrade', 'buffering_test.go', 'TestClientPreservesApplicationBytesBufferedWithUpgradeHeaders',
         'WebTunnel discarded application bytes buffered with upgrade headers'),
        ('sfturbo', 'sfturbo', 'common/turbotunnel', 'ownership_test.go', 'TestCloseCancelsPendingDialAndJoins',
         'Snowflake Close left the pending dial context active'),
        ('sfkcp', 'sfkcp', '.', 'ownership_test.go', 'TestKCPShutdownRetainsActualPacketReader',
         'KCP shutdown released its still-running packet reader'),
        ('sfsmux', 'sfsmux', '.', 'ownership_test.go', 'TestSmuxShutdownRetainsActualStreamReader',
         'smux shutdown released its still-running stream reader'),
    ):
        source = MODULE / 'internal' / package
        manifest = json.loads((source / 'UPSTREAM.json').read_text())
        original, _ = manifest_identity(manifest)
        fixture = output / ('original-' + key)
        extract_module(archives[original], fixture)
        prepare_negative_module(go, fixture, manifest, module)
        target = fixture / directory / ('routervpn_' + test)
        target.write_bytes((source / test).read_bytes())
        log = run([go, 'test', '-mod=readonly', '-count=1', '-timeout=20s', '-run', '^' + name + '$',
                   './' + directory], fixture, output / (key + '-upstream-negative.log'), expected=1)
        if failure not in log or 'build failed' in log or 'test timed out' in log:
            raise ValueError('upstream negative control did not reproduce the required defect')
        result[key] = dict(commit=manifest['commit'], expected_failure=failure, reproduced=True)
    return result


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
    if output.is_relative_to(ROOT):
        parser.error('evidence output must be outside the source tree')
    output.mkdir(parents=True, exist_ok=False)
    before = source_snapshot()
    version = run([go, 'version'], MODULE, output / 'go-version.log').strip()
    if not version.startswith('go version go1.26.3 '):
        raise ValueError('the native PT gate requires the pinned Go 1.26.3 toolchain')
    module, archives = verify_pins(go, output)
    adaptations = verify_adaptations(archives, output)
    negative = negative_controls(go, module, archives, output) if args.upstream_negative_controls else {}
    run([go, 'test', '-mod=readonly', '-race', '-count=1', '-timeout=90s', './...'], MODULE, output / 'pt-race.log')
    after = source_snapshot()
    if before != after:
        raise ValueError('PT gate source inputs changed during verification')
    evidence = dict(
        schema=2, go=version, scope='local actual PT traffic, captured DNS and sockets, certificate verification, and owned teardown',
        public_tor_traffic_tested=False, mobile_host_packaged=False, mobile_tor_capability_enabled=False,
        race_gate_passed=True, upstream_negative_controls=negative, adapted_sources=adaptations,
        module_license_notices_verified=True, source_inputs_unchanged=True, source_sha256=after,
        boundary='HTTP physical dial/read/write operations drain before release; stdlib housekeeping goroutines may finish afterward without lower IO access.',
    )
    (output / 'pt-evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
    print('Native PT local data-path and drain gate passed:', output / 'pt-evidence.json')


if __name__ == '__main__':
    main()
