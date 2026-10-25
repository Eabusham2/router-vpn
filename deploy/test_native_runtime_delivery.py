#!/usr/bin/env python3
"""Exercise native artifact, package and signing boundaries, then real payloads."""
from pathlib import Path
import argparse
import gzip
import importlib.util
import io
import json
import os
import platform
import shutil
import struct
import subprocess
import tarfile
import tempfile
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DELIVERY = load('native_delivery', 'deploy/native-runtime-bundle.py')
SIGN = load('native_sign', 'deploy/seal-native-runtime.py')
PE_FIXTURE = load('native_pe_fixture', 'deploy/test_desktop_native_dependencies.py')
BUILD = DELIVERY.BUILD
checks = 0


def check(condition, label):
    global checks
    assert condition, label
    checks += 1


def rejected(operation, label):
    global checks
    try:
        operation()
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError):
        checks += 1
        return
    raise AssertionError('accepted '+label)


def fixture(directory, target):
    directory.mkdir(parents=True)
    for name in BUILD.expected_names(target):
        raw = (BUILD.marker(BUILD.digest()) if name == BUILD.binary_name(target) else 'fixture '+name).encode()
        if name == BUILD.PT_NOTICES:
            raw = BUILD.EXTERNAL.desktop_pt_notices()
        if target.startswith('windows/') and name in (BUILD.binary_name(target), BUILD.library_name(target)):
            raw = PE_FIXTURE.image(target)+raw
        (directory/name).write_bytes(raw)
    fixture_receipt(directory, target)


def fixture_receipt(directory, target):
    files = {name: BUILD.payload((directory/name).read_bytes()) for name in BUILD.expected_names(target)}
    receipt = {**BUILD.receipt_fields(target, BUILD.digest()), **files[BUILD.binary_name(target)], 'files': files}
    (directory/'NATIVE-RUNTIME.json').write_text(json.dumps(receipt))


def object_metadata(command, *, env):
    assert len(command) == 4 and command[:3] == ['go', 'version', '-m'], command
    return PE_FIXTURE.metadata(env['GOOS']+'/'+env['GOARCH'])


def package_archive(package, output, kind):
    if kind == 'zip':
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(package.rglob('*')):
                if path.is_file():
                    archive.write(path, package.name+'/'+path.relative_to(package).as_posix())
    else:
        with tarfile.open(output, 'w:gz') as archive:
            archive.add(package, arcname=package.name)


def checkout_bytes_test():
    """Use Git's actual checkout conversion, including a missing-attrs control."""
    inputs = {path.relative_to(BUILD.ROOT).as_posix(): path.read_bytes() for path in BUILD.inputs()}
    attributes = (ROOT/'.gitattributes').read_bytes()
    with tempfile.TemporaryDirectory(prefix='native-checkout-bytes-') as temporary:
        root = Path(temporary)
        source = root/'source'
        source.mkdir()
        for name, raw in inputs.items():
            path = source/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        (source/'.gitattributes').write_bytes(attributes)
        trace = root/'git-processes.jsonl'

        def git(*args):
            subprocess.run(['git', '-c', 'core.longpaths=true',
                            '-c', 'gc.auto=0', '-c', 'maintenance.auto=false', '-c', 'gc.autoDetach=false',
                            '-c', 'user.name=Native checkout fixture', '-c', 'user.email=native-fixture@example.invalid',
                            '-c', 'commit.gpgsign=false', *map(str, args)],
                           env={**os.environ, 'GIT_TRACE2_EVENT': str(trace)},
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)

        git('init', '-q', source)
        git('-C', source, 'config', 'core.autocrlf', 'false')
        git('-C', source, 'add', '--', '.')
        git('-C', source, 'commit', '-qm', 'Exact native input fixture')
        checkout = root/'with-attributes'
        git('clone', '--quiet', '--no-hardlinks', '--config', 'core.autocrlf=true',
            '--config', 'core.longpaths=true', source, checkout)
        for name, raw in inputs.items():
            check((checkout/name).read_bytes() == raw, 'Git checkout changed native source bytes: '+name)
        # Removing only the shipping attributes must expose the real CRLF
        # conversion. No simulated newline function or hash stub participates.
        (source/'.gitattributes').unlink()
        git('-C', source, 'add', '-u')
        git('-C', source, 'commit', '-qm', 'Missing attributes negative control')
        without = root/'without-attributes'
        git('clone', '--quiet', '--no-hardlinks', '--config', 'core.autocrlf=true',
            '--config', 'core.longpaths=true', source, without)
        changed = [name for name, raw in inputs.items() if (without/name).read_bytes() != raw]
        check(bool(changed) and any(b'\r\n' in (without/name).read_bytes() for name in changed),
              'Missing-attributes negative control did not expose actual Git CRLF drift')
        # git commit otherwise starts detached auto-maintenance, which can
        # recreate the temporary source while TemporaryDirectory removes it.
        # Inspect Git's real child launches rather than suppress cleanup errors.
        children = [event.get('argv', []) for event in
                    (json.loads(line) for line in trace.read_text(encoding='utf-8').splitlines())
                    if event.get('event') == 'child_start']
        check(not any('maintenance' in command or '--detach' in command for command in children),
              'Checkout fixture launched detached or automatic Git maintenance')
    print(f'Actual Git autocrlf=true checkout preserved all {len(inputs)} native inputs; omitted attributes exposed CRLF drift', flush=True)


def archive_boundaries(root):
    target = 'linux/amd64'
    # Header-only inputs prove rejection occurs before a declared payload is
    # skipped/read: inventory-first code instead reaches unexpected EOF.
    for label, kind, size, expected in [
        ('oversized-receipt', tarfile.REGTYPE, 32 << 20, 'payload bound'),
        ('oversized-metadata', tarfile.XHDTYPE, DELIVERY.MAX_TAR_METADATA+1, 'metadata exceeds'),
        ('sparse-header', tarfile.GNUTYPE_SPARSE, 0, 'Sparse native'),
    ]:
        path = root/(label+'.tar.gz')
        member = tarfile.TarInfo('linux-amd64/NATIVE-RUNTIME.json')
        member.type, member.size = kind, size
        with gzip.open(path, 'wb') as stream:
            stream.write(member.tobuf())
        try:
            with DELIVERY.open_tar(path, target) as archive:
                destination = root/(label+'-out'); destination.mkdir()
                try:
                    DELIVERY.unpack_payload(DELIVERY.tar_records(archive), 'linux-amd64/', target, destination)
                except ValueError as error:
                    check(expected in str(error), label+' did not reject its header bound')
                    check(archive.fileobj.tell() <= tarfile.BLOCKSIZE, label+' consumed its rejected body')
                else:
                    raise AssertionError('accepted '+label)
        except ValueError as error:
            # Metadata and sparse formats are rejected by the very first
            # TarInfo, before open_tar can return a handle.
            check(expected in str(error), label+' did not fail before opening its body')

    directory_bomb = root/'many-directories.tar.gz'
    with tarfile.open(directory_bomb, 'w:gz') as archive:
        for _ in range(len(DELIVERY.members(target))+2):
            item = tarfile.TarInfo('linux-amd64'); item.type = tarfile.DIRTYPE
            archive.addfile(item)
    rejected(lambda: DELIVERY.extract_bundle(target, directory_bomb, root/'directory-bomb-out'),
             'unbounded ignored artifact directories')

    for overridden in (False, True):
        whole_package = root/('oversized-package-pax.tar.gz' if overridden else 'oversized-package-receipt.tar.gz')
        member = tarfile.TarInfo('RouterVPN/runtime/native/NATIVE-RUNTIME.json')
        member.size = 0 if overridden else 32 << 20
        if overridden:
            member.pax_headers = {'size': str(32 << 20)}
        with gzip.open(whole_package, 'wb') as stream:
            stream.write(member.tobuf(format=tarfile.PAX_FORMAT))
        try:
            DELIVERY.verify_package(target, whole_package)
        except ValueError as error:
            check('payload bound' in str(error), 'whole-package receipt was advanced before its typed bound')
        else:
            raise AssertionError('accepted whole-package oversized native receipt')

    # A legal PAX size replacement must use the final value, not reject a zero
    # placeholder in the underlying ordinary header. Exercise both consumers.
    source = root/'sources/linux-amd64'
    for package in (False, True):
        path = root/('valid-package-pax.tar.gz' if package else 'valid-artifact-pax.tar.gz')
        prefix = 'RouterVPN/runtime/native/' if package else 'linux-amd64/'
        with gzip.open(path, 'wb') as stream:
            for filename in sorted(DELIVERY.members(target)):
                raw = (source/filename).read_bytes()
                member = tarfile.TarInfo(prefix+filename)
                member.size = len(raw)
                if filename == 'NATIVE-RUNTIME.json':
                    member.size = 0
                    member.pax_headers = {'size': str(len(raw))}
                stream.write(member.tobuf(format=tarfile.PAX_FORMAT))
                stream.write(raw)
                stream.write(b'\0'*(-len(raw) % tarfile.BLOCKSIZE))
            stream.write(b'\0'*(2*tarfile.BLOCKSIZE))
        if package:
            DELIVERY.verify_package(target, path)
            check(True, 'valid final PAX size in complete package')
        else:
            restored = root/'valid-pax-restored'
            DELIVERY.extract_bundle(target, path, restored)
            check(BUILD.reuse(restored, target) == BUILD.reuse(source, target),
                  'valid final PAX size in native artifact')

    ordinary = root/'bounded-package.tar.gz'
    with tarfile.open(ordinary, 'w:gz') as archive:
        for index in range(5):
            item = tarfile.TarInfo('RouterVPN/file'+str(index)); item.size = 3
            archive.addfile(item, io.BytesIO(b'abc'))
    def inventory():
        with DELIVERY.open_tar(ordinary) as archive:
            list(DELIVERY.tar_records(archive))
    with patch.object(DELIVERY, 'MAX_PACKAGE_MEMBERS', 4):
        rejected(inventory, 'tar member count before complete inventory')
    with patch.object(DELIVERY, 'MAX_PACKAGE_EXPANDED', 512):
        rejected(inventory, 'tar declared expanded bound before payload skip')

    sparse_pax = root/'sparse-pax.tar.gz'
    with tarfile.open(sparse_pax, 'w:gz') as archive:
        item = tarfile.TarInfo('RouterVPN/sparse')
        item.pax_headers = {'GNU.sparse.major': '1', 'GNU.sparse.minor': '0'}
        archive.addfile(item)
    rejected(lambda: DELIVERY.open_tar(sparse_pax), 'sparse PAX parser before map reads')

    zipped = root/'bounded-package.zip'
    with zipfile.ZipFile(zipped, 'w') as archive:
        for index in range(5):
            archive.writestr('RouterVPN/file'+str(index), b'abc')
    for constant, value in [('MAX_PACKAGE_MEMBERS', 4), ('MAX_ZIP_DIRECTORY', 32),
                            ('MAX_PACKAGE_MEMBER', 2), ('MAX_PACKAGE_EXPANDED', 8)]:
        with patch.object(DELIVERY, constant, value), \
                patch.object(DELIVERY.zipfile, 'ZipFile', side_effect=AssertionError('ZipInfo inventory loaded before its bound')):
            rejected(lambda: DELIVERY.verify_package(target, zipped), 'ZIP '+constant+' before inventory allocation')
    # A forged small EOCD entry count cannot hide a larger actual directory.
    raw = bytearray(zipped.read_bytes()); footer = raw.rfind(b'PK\x05\x06')
    struct.pack_into('<HH', raw, footer+8, 1, 1)
    lied = root/'lying-count.zip'; lied.write_bytes(raw)
    with patch.object(DELIVERY, 'MAX_PACKAGE_MEMBERS', 4), \
            patch.object(DELIVERY.zipfile, 'ZipFile', side_effect=AssertionError('Forged-count ZIP allocated its inventory')):
        rejected(lambda: DELIVERY.verify_package(target, lied), 'forged ZIP footer count')


def signing_promotion_boundaries(root):
    for rollback_fails in (False, True):
        directory = root/('restore-fails' if rollback_fails else 'restore-succeeds')
        fixture(directory, 'darwin/amd64')
        original = {path.name: path.read_bytes() for path in directory.iterdir()}
        real_replace, calls = SIGN.os.replace, []
        def rename(source, destination):
            calls.append((source, destination))
            if len(calls) == 2 or rollback_fails and len(calls) == 3:
                raise OSError('injected signing promotion/restore failure')
            return real_replace(source, destination)
        def codesign(command, **_):
            if '--force' in command:
                path = Path(command[-1]); path.write_bytes(path.read_bytes()+b'owned signature')
        with patch.object(SIGN.subprocess, 'run', side_effect=codesign), patch.object(SIGN.os, 'replace', side_effect=rename):
            try:
                SIGN.seal(directory, 'darwin/amd64')
            except (OSError, RuntimeError) as error:
                check(len(calls) == 3, 'failed promotion did not attempt original restoration')
                backup = Path(calls[0][1])
                if rollback_fails:
                    check('original recovery retained at '+str(backup) in str(error), 'missing explicit recovery location')
                    check(not directory.exists(), 'failed promotion exposed an unverified destination')
                    check(original == {p.name:p.read_bytes() for p in backup.iterdir()},
                          'rollback failure destroyed the only original native bundle')
                else:
                    check(original == {p.name:p.read_bytes() for p in directory.iterdir()},
                          'promotion failure did not restore original bytes')
                    check(not backup.parent.exists(), 'successful restoration left an unnecessary transaction')
            else:
                raise AssertionError('accepted failed native signing promotion')


def windows_dependency_boundaries(root):
    for target in ('windows/amd64', 'windows/arm64'):
        for name in (BUILD.binary_name(target), BUILD.library_name(target)):
            for delay in (False, True):
                label = DELIVERY.slug(target)+'-'+name+('-delay' if delay else '-ordinary')
                directory = root/('dependency-'+label)
                fixture(directory, target)
                raw = PE_FIXTURE.image(target, ('KERNEL32.dll',) if delay else ('libunwind.dll',),
                                       ('libunwind.dll',) if delay else ())
                if name == BUILD.binary_name(target):
                    raw += BUILD.marker(BUILD.digest()).encode()
                (directory/name).write_bytes(raw)
                # A receipt that faithfully hashes every byte still cannot
                # authorize an unstaged compiler dependency in either payload.
                fixture_receipt(directory, target)
                archive = root/(label+'.tar.gz')
                with tarfile.open(archive, 'w:gz') as output:
                    output.add(directory, arcname=DELIVERY.slug(target))
                restored = root/('rejected-'+label)
                rejected(lambda: DELIVERY.extract_bundle(target, archive, restored),
                         'actual PE parser ignored '+label)
                check(not restored.exists(), 'unowned DLL dependency became a published bundle')


def pt_notice_boundaries(root):
    expected = BUILD.EXTERNAL.desktop_pt_notices()
    check(256*1024 < len(expected) <= 2*1024*1024, 'real PT notices do not exercise their explicit larger bound')
    stage = root/'pt-notice-stage'
    stage.mkdir()
    BUILD.stage_pt_notices(stage)
    check((stage/'TOR-PT-NOTICES.json').read_bytes() == expected, 'builder did not stage the exact PT dependency notices')
    rejected(lambda: BUILD.stage_pt_notices(stage), 'overwrite an existing notice payload')
    empty = root/'pt-notice-overflow-stage'; empty.mkdir()
    with patch.object(BUILD.EXTERNAL, 'desktop_pt_notices', return_value=b'x'*(2*1024*1024+1)):
        rejected(lambda: BUILD.stage_pt_notices(empty), 'oversized generated PT notices')
    check(not list(empty.iterdir()), 'failed PT notice staging published a partial payload')
    for target in BUILD.TARGETS:
        check('TOR-PT-NOTICES.json' in DELIVERY.members(target), 'native package omitted mandatory PT notices')
        check(DELIVERY.bound('TOR-PT-NOTICES.json', target) == 2*1024*1024, 'PT notice archive bound differs')
        for name in BUILD.LICENSES:
            if name != 'TOR-PT-NOTICES.json':
                check(DELIVERY.bound(name, target) == 256*1024, 'ordinary license bound was widened')
        rejected(lambda: DELIVERY.bound('TOR-PT-NOTICE.json', target), 'misnamed PT notice bound')
    target = 'linux/amd64'
    for fault in ('missing', 'misnamed', 'changed', 'changed-resealed', 'oversized', 'ordinary-license-oversized'):
        directory = root/('pt-notice-'+fault)
        shutil.copytree(root/'sources/linux-amd64', directory)
        path = directory/'TOR-PT-NOTICES.json'
        if fault == 'missing':
            path.unlink()
        elif fault == 'misnamed':
            path.rename(directory/'TOR-PT-NOTICE.json')
        elif fault in ('changed', 'changed-resealed'):
            raw = bytearray(path.read_bytes()); raw[len(raw)//2] ^= 1; path.write_bytes(raw)
        elif fault == 'oversized':
            path.write_bytes(b'x'*(2*1024*1024+1))
        else:
            (directory/'XRAY-LICENSE').write_bytes(b'x'*(256*1024+1))
        if fault in ('changed-resealed', 'oversized', 'ordinary-license-oversized'):
            fixture_receipt(directory, target)
        rejected(lambda: BUILD.reuse(directory, target), 'native PT notice '+fault)
        artifact = root/('pt-notice-'+fault+'.tar.gz')
        with tarfile.open(artifact, 'w:gz') as output:
            output.add(directory, arcname='linux-amd64')
        restored = root/('pt-notice-rejected-'+fault)
        rejected(lambda: DELIVERY.extract_bundle(target, artifact, restored), 'artifact PT notice '+fault)
        check(not restored.exists(), 'invalid PT notice artifact was adopted')
        package = root/('pt-notice-'+fault+'.zip')
        with zipfile.ZipFile(package, 'w', compression=zipfile.ZIP_DEFLATED) as output:
            for child in directory.iterdir():
                output.write(child, 'RouterVPN/runtime/native/'+child.name)
        rejected(lambda: DELIVERY.verify_package(target, package), 'package PT notice '+fault)


def boundary_tests():
    # Only Go's executable build metadata and the external codesign process are
    # doubled here. The production PE parser, bounds, receipts, hashes, paths,
    # copies and atomic replacement execute. --bundle uses an actual engine.
    with tempfile.TemporaryDirectory(prefix='native-delivery-boundaries-') as temporary, \
            patch.object(BUILD, 'run', side_effect=object_metadata), \
            patch.object(SIGN.BUILD, 'run', side_effect=object_metadata):
        root = Path(temporary)
        for target in BUILD.TARGETS:
            slug = DELIVERY.slug(target)
            source = root/'sources'/slug
            fixture(source, target)
            archive = root/'artifacts'/('native-'+slug+'.tar.gz')
            DELIVERY.archive_bundle(target, source, archive)
            restored = root/'restored'/slug
            DELIVERY.extract_bundle(target, archive, restored)
            check(BUILD.reuse(source, target) == BUILD.reuse(restored, target), 'artifact altered payload')
            DELIVERY.extract_bundle(target, archive, restored)
            check((restored/'NATIVE-RUNTIME.json').read_bytes() == (source/'NATIVE-RUNTIME.json').read_bytes(), 'idempotent stage')
            with patch.object(DELIVERY, 'ROOT', root):
                prebuilt = root/'dist/native-runtime'/slug
                prebuilt.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(source, prebuilt)
                package = root/('RouterVPN-'+slug)
                package.mkdir()
                DELIVERY.package(target, package)
                for kind, suffix in [('zip', '.zip'), ('tar', '.tar.gz')]:
                    output = root/(package.name+suffix)
                    package_archive(package, output, kind)
                    DELIVERY.verify_package(target, output)
                    check(True, 'real archive membership and payload digest')
                rejected(lambda: DELIVERY.package(target, package), 'replace an existing native package')
                (prebuilt/'XRAY-LICENSE').write_text('changed')
                empty = root/('empty-'+slug); empty.mkdir()
                with patch.object(BUILD, 'build', side_effect=AssertionError('must not rebuild corrupt prebuilt')):
                    rejected(lambda: DELIVERY.package(target, empty), 'corrupt prebuilt artifact')
                check(not (empty/'runtime/native').exists(), 'failed copy became visible')

        target = 'linux/amd64'
        source = root/'sources/linux-amd64'
        for label, name, kind, size in [
            ('traversal', '../outside', tarfile.REGTYPE, 1),
            ('extra', 'linux-amd64/unowned', tarfile.REGTYPE, 1),
            ('link', 'linux-amd64/XRAY-LICENSE', tarfile.SYMTYPE, 0),
            ('hardlink', 'linux-amd64/XRAY-LICENSE', tarfile.LNKTYPE, 0),
            ('duplicate', 'linux-amd64/XRAY-LICENSE', tarfile.REGTYPE, 1),
        ]:
            archive = root/(label+'.tar.gz')
            with tarfile.open(archive, 'w:gz') as handle:
                for path in source.iterdir():
                    handle.add(path, arcname='linux-amd64/'+path.name)
                item = tarfile.TarInfo(name); item.type=kind; item.size=size; item.linkname='../outside'
                handle.addfile(item, io.BytesIO(b'x'*size) if size else None)
            rejected(lambda: DELIVERY.extract_bundle(target, archive, root/('bad-'+label)), label)
            check(not (root/('bad-'+label)).exists(), 'invalid artifact published')
        incomplete = root/'no-runtime.zip'
        with zipfile.ZipFile(incomplete, 'w') as archive:
            archive.writestr('RouterVPN/runtime/amnezia/AMNEZIA-RUNTIME.json', '{}')
        rejected(lambda: DELIVERY.verify_package(target, incomplete), 'AWG-only package')
        corrupt = root/'corrupt.zip'
        with zipfile.ZipFile(corrupt, 'w') as archive:
            for path in source.iterdir():
                archive.writestr('RouterVPN/runtime/native/'+path.name,
                                 b'changed' if path.name == 'XRAY-LICENSE' else path.read_bytes())
        rejected(lambda: DELIVERY.verify_package(target, corrupt), 'altered archived license')
        ambiguous = root/'artifacts/duplicate'; ambiguous.mkdir()
        shutil.copy2(root/'artifacts/native-linux-amd64.tar.gz', ambiguous/'native-linux-amd64.tar.gz')
        rejected(lambda: DELIVERY.stage_artifacts(root/'artifacts', root/'staged', [target]), 'ambiguous same-target artifacts')

        # The sealer must reject premodified bytes before executing codesign,
        # and signing failure must leave the original receipt and bytes intact.
        signed = root/'signed'
        shutil.copytree(root/'sources/darwin-amd64', signed)
        original = {path.name: path.read_bytes() for path in signed.iterdir()}
        with patch.object(SIGN.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'codesign')):
            rejected(lambda: SIGN.seal(signed, 'darwin/amd64'), 'failed codesign')
        check(original == {p.name:p.read_bytes() for p in signed.iterdir()}, 'sign failure changed original')
        (signed/'sing-box-routervpn').write_bytes(b'changed')
        with patch.object(SIGN.subprocess, 'run', side_effect=AssertionError('signer must not execute')):
            rejected(lambda: SIGN.seal(signed, 'darwin/amd64'), 'premodified engine before sign')
        (signed/'sing-box-routervpn').write_bytes(original['sing-box-routervpn'])

        def codesign(command, **_):
            if '--force' in command:
                path = Path(command[-1]); path.write_bytes(path.read_bytes()+b'owned signature')
        with patch.object(SIGN.subprocess, 'run', side_effect=codesign):
            SIGN.seal(signed, 'darwin/amd64')
        check(BUILD.reuse(signed, 'darwin/amd64')['sha256'] != json.loads(original['NATIVE-RUNTIME.json'])['sha256'], 'signed receipt not updated')
        check(all((signed/name).read_bytes() == raw for name,raw in original.items() if name not in ('sing-box-routervpn','NATIVE-RUNTIME.json')), 'signing changed nonbinary payload')
        rejected(lambda: SIGN.seal(signed, 'linux/amd64'), 'foreign target reseal')
        archive_boundaries(root)
        signing_promotion_boundaries(root)
        windows_dependency_boundaries(root)
        pt_notice_boundaries(root)
    checkout_bytes_test()
    print(f'{checks} native delivery/signing boundary checks passed', flush=True)


def real_bundle_tests(bundle, target):
    before = BUILD.reuse(bundle, target)
    with tempfile.TemporaryDirectory(prefix='native-real-delivery-') as temporary:
        root = Path(temporary)
        archive = root/('native-'+DELIVERY.slug(target)+'.tar.gz')
        DELIVERY.archive_bundle(target, bundle, archive)
        restored = root/'restored'
        DELIVERY.extract_bundle(target, archive, restored)
        check(BUILD.reuse(restored, target) == before, 'real artifact payload altered')
        for prefix, suffix, kind in [('RouterVPN', '.tar.gz', 'tar'), ('RouterVPNPortable', '.zip', 'zip')]:
            package = root/prefix
            native = package/('App/RouterVPN/runtime/native' if kind == 'zip' else 'runtime/native')
            shutil.copytree(restored, native)
            output = root/(prefix+suffix)
            package_archive(package, output, kind)
            DELIVERY.verify_package(target, output)
        host = {'Linux':'linux','Darwin':'darwin','Windows':'windows'}.get(platform.system())
        arch = {'x86_64':'amd64','AMD64':'amd64','aarch64':'arm64','arm64':'arm64','ARM64':'arm64'}.get(platform.machine())
        check(target == str(host)+'/'+str(arch), 'real gate ran on foreign host')
        subprocess.run([str(restored/BUILD.binary_name(target)), 'version'], check=True, timeout=20)
    print('Actual native bundle survived artifact extraction and installed/Portable archives', flush=True)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--target', choices=BUILD.TARGETS)
    args=parser.parse_args()
    if bool(args.bundle) != bool(args.target):
        parser.error('--bundle and --target are required together')
    boundary_tests()
    if args.bundle:
        real_bundle_tests(args.bundle, args.target)
