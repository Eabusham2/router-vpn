#!/usr/bin/env python3
"""Carry verified complete native engines from their host build into packages.

Foreign targets are inspected through their Go metadata and sealed payloads;
they are never executed by an unrelated packaging host. The producer executes
the full engine/relocation/graph gate on the matching architecture first.
"""
from pathlib import Path, PurePosixPath
import argparse
import importlib.util
import json
import os
import shutil
import stat
import struct
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_delivery_build', ROOT/'deploy/build-native-runtime.py')
BUILD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BUILD)
MAX_ARCHIVE = 768 << 20
MAX_PACKAGE_MEMBERS = 8192
MAX_PACKAGE_MEMBER = 512 << 20
MAX_PACKAGE_EXPANDED = 2 << 30
MAX_TAR_METADATA = 64 << 10
MAX_ZIP_DIRECTORY = 8 << 20


def slug(target):
    if target not in BUILD.TARGETS:
        raise ValueError('Unsupported native bundle target')
    return target.replace('/', '-')


def members(target):
    return BUILD.expected_names(target)|{'NATIVE-RUNTIME.json'}


def bound(name, target):
    if name == 'NATIVE-RUNTIME.json':
        return 32768
    return BUILD.payload_bound(name, target)


def unpack_payload(records, prefix, target, destination):
    """Only regular, individually bounded, unique files may cross this boundary."""
    seen = set()
    for name, size, is_file, is_directory, opener in records:
        if name == prefix.rstrip('/') and is_directory:
            continue
        if not name.startswith(prefix):
            raise ValueError('Unexpected native bundle archive member')
        relative = name[len(prefix):]
        if relative not in members(target) or relative.casefold() in seen or not is_file:
            raise ValueError('Linked, repeated or unowned native bundle archive member')
        if not 0 < size <= bound(relative, target):
            raise ValueError('Native archive member exceeds its payload bound')
        seen.add(relative.casefold())
        with opener() as stream:
            raw = stream.read(size+1)
        if len(raw) != size:
            raise ValueError('Native archive member length differs')
        path = destination/relative
        path.write_bytes(raw)
        path.chmod(0o755 if relative in (BUILD.binary_name(target), BUILD.TOR.VERIFY.binary_name(target)) else 0o644)
    if seen != {name.casefold() for name in members(target)}:
        raise ValueError('Native bundle archive is incomplete')
    return BUILD.reuse(destination, target)


def open_tar(path, target=None, *, package=False):
    """Bound headers before tarfile can skip payloads or parse large metadata.

    TarFile.getmembers() advances over every declared body before a caller can
    reject the first bad file. A lazy inventory plus a TarInfo guard also bounds
    PAX/GNU extension bodies, recursive metadata and expanded archive offsets.
    Sparse formats are unnecessary for the shipped packages and are rejected
    before their extra maps can make tarfile consume unbounded input.
    """
    artifact = target is not None and not package
    limit = len(members(target))+1 if artifact else MAX_PACKAGE_MEMBERS
    expanded = (sum(bound(name, target) for name in members(target))
                + (2*limit+8)*(MAX_TAR_METADATA+tarfile.BLOCKSIZE)
                if artifact else MAX_PACKAGE_EXPANDED)
    budget = {'headers': 0, 'members': 0, 'depth': 0}
    metadata = (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK,
                tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE)

    def native_member(item):
        if target is None:
            return
        name = item.name.rstrip('/') if item.isdir() else item.name
        if package:
            if '/runtime/native/' not in name:
                return
            relative = name.split('/runtime/native/', 1)[1]
        else:
            prefix = slug(target)+'/'
            if name == prefix.rstrip('/') and item.isdir():
                return
            if not name.startswith(prefix):
                raise ValueError('Unexpected native bundle archive member')
            relative = name[len(prefix):]
        if relative not in members(target) or not item.isfile():
            raise ValueError('Linked or unowned native archive payload')
        if not 0 < item.size <= bound(relative, target):
            raise ValueError('Native archive member exceeds its payload bound')

    class BoundedTarInfo(tarfile.TarInfo):
        def _proc_member(self, archive):
            budget['headers'] += 1
            if budget['headers'] > 2*limit+8:
                raise ValueError('Too many native archive headers')
            if self.size < 0 or self.size > MAX_PACKAGE_MEMBER:
                raise ValueError('Native archive member exceeds its declared bound')
            padded = (self.size+tarfile.BLOCKSIZE-1)//tarfile.BLOCKSIZE*tarfile.BLOCKSIZE
            if archive.fileobj.tell()+padded > expanded:
                raise ValueError('Expanded native archive exceeds its bound')
            if self.type == tarfile.GNUTYPE_SPARSE:
                raise ValueError('Sparse native package archives are unsupported')
            special = self.type in metadata
            if special:
                if self.size > MAX_TAR_METADATA:
                    raise ValueError('Native archive metadata exceeds its bound')
                budget['depth'] += 1
                if budget['depth'] > 8:
                    raise ValueError('Nested native archive metadata exceeds its bound')
                if self.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE):
                    position = archive.fileobj.tell()
                    raw = archive.fileobj.read(self.size)
                    archive.fileobj.seek(position)
                    if len(raw) != self.size:
                        raise ValueError('Truncated native archive metadata')
                    offset = 0
                    while offset < len(raw):
                        space = raw.find(b' ', offset)
                        if space < 0 or space-offset > 20 or not raw[offset:space].isdigit():
                            raise ValueError('Invalid native archive PAX record')
                        length = int(raw[offset:space])
                        end = offset+length
                        if length < 5 or end > len(raw) or raw[end-1:end] != b'\n':
                            raise ValueError('Invalid native archive PAX length')
                        key, equals, _ = raw[space+1:end-1].partition(b'=')
                        if not key or not equals or key.startswith(b'GNU.sparse'):
                            raise ValueError('Unsupported native archive PAX field')
                        offset = end
            else:
                budget['members'] += 1
                if budget['members'] > limit:
                    raise ValueError('Too many native archive members')
                if budget['depth'] == 0:
                    native_member(self)
            try:
                item = super()._proc_member(archive)
                # PAX can override a regular header's size. Validate the final
                # value before the iterator advances to its next header.
                if item.size < 0 or item.size > MAX_PACKAGE_MEMBER:
                    raise ValueError('Native archive member exceeds its declared bound')
                padded = (item.size+tarfile.BLOCKSIZE-1)//tarfile.BLOCKSIZE*tarfile.BLOCKSIZE
                if item.offset_data+padded > expanded:
                    raise ValueError('Expanded native archive exceeds its bound')
                if budget['depth'] == (1 if special else 0):
                    native_member(item)
                return item
            finally:
                if special:
                    budget['depth'] -= 1

    return tarfile.open(path, 'r:gz', tarinfo=BoundedTarInfo)


def tar_records(archive):
    for item in archive:
        yield (item.name.rstrip('/') if item.isdir() else item.name,
               item.size, item.isfile(), item.isdir(),
               lambda item=item: archive.extractfile(item))


def preflight_zip(path):
    """Inspect a bounded central directory before ZipFile builds its inventory."""
    with path.open('rb') as stream:
        # This standard-library footer reader examines at most the ZIP comment
        # plus fixed ZIP64 records; it does not load the central directory.
        footer = zipfile._EndRecData(stream)
        if not footer or footer[zipfile._ECD_DISK_NUMBER] or footer[zipfile._ECD_DISK_START]:
            raise ValueError('Missing or split native package ZIP directory')
        count, size = footer[zipfile._ECD_ENTRIES_TOTAL], footer[zipfile._ECD_SIZE]
        if (not 0 < count <= MAX_PACKAGE_MEMBERS or footer[zipfile._ECD_ENTRIES_THIS_DISK] != count
                or not 0 < size <= MAX_ZIP_DIRECTORY):
            raise ValueError('Native ZIP inventory exceeds its bound')
        # Shipping ZIPs are archives, never self-extracting executables with an
        # unaccounted prefix. ZIP64 footer decoding supplies the full offset.
        start = footer[zipfile._ECD_OFFSET]
        if start < 0 or start+size > footer[zipfile._ECD_LOCATION]:
            raise ValueError('Invalid native ZIP directory offset')
        stream.seek(start)
        raw = stream.read(size)
    if len(raw) != size:
        raise ValueError('Truncated native ZIP directory')
    offset = actual = expanded = 0
    header = struct.Struct('<4s6H3I5H2I')
    while offset < len(raw):
        if len(raw)-offset < header.size:
            raise ValueError('Truncated native ZIP entry')
        fields = header.unpack_from(raw, offset)
        if fields[0] != b'PK\x01\x02':
            raise ValueError('Invalid native ZIP directory entry')
        actual += 1
        if actual > MAX_PACKAGE_MEMBERS:
            raise ValueError('Too many native ZIP entries')
        length = header.size+fields[10]+fields[11]+fields[12]
        if offset+length > len(raw):
            raise ValueError('Truncated native ZIP entry metadata')
        size = fields[9]
        # ZIP64 sizes are checked again after the now-bounded ZipInfo parse.
        if size != 0xffffffff:
            expanded += size
            if size > MAX_PACKAGE_MEMBER or expanded > MAX_PACKAGE_EXPANDED:
                raise ValueError('Expanded native ZIP exceeds its bound')
        offset += length
    if actual != count:
        raise ValueError('Native ZIP entry count differs from its footer')


def verify_archive_path(path):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_ARCHIVE:
        raise ValueError('Missing, linked or excessive native archive')


def archive_bundle(target, bundle, output):
    BUILD.reuse(bundle, target)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or output.exists():
        raise ValueError('Native artifact output already exists')
    with tarfile.open(output, 'w:gz') as archive:
        for name in sorted(members(target)):
            archive.add(bundle/name, arcname=slug(target)+'/'+name, recursive=False)
    # Inspect the real compressed bytes before they become a workflow artifact.
    with tempfile.TemporaryDirectory(prefix='native-artifact-check-') as temporary:
        extract_bundle(target, output, Path(temporary).resolve()/slug(target))


def extract_bundle(target, archive, destination):
    slug(target)
    verify_archive_path(archive)
    if destination.is_symlink():
        raise ValueError('Linked native artifact destination')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.native-import-', dir=destination.parent) as temporary:
        stage = Path(temporary).resolve()/'bundle'
        stage.mkdir()
        with open_tar(archive, target) as handle:
            incoming = unpack_payload(tar_records(handle), slug(target)+'/', target, stage)
        if destination.exists():
            if BUILD.reuse(destination, target) != incoming:
                raise ValueError('Existing native artifact is a different payload')
            return
        os.replace(stage, destination)


def stage_artifacts(source, destination, targets):
    if source.is_symlink() or not source.is_dir():
        raise ValueError('Native artifact input directory is missing or linked')
    for target in targets:
        matches = list(source.rglob('native-'+slug(target)+'.tar.gz'))
        if len(matches) != 1 or any(parent.is_symlink() for parent in matches[0].parents):
            raise ValueError('Expected exactly one owned artifact for '+target)
        extract_bundle(target, matches[0], destination/slug(target))


def package(target, package_root):
    target_slug = slug(target)
    prebuilt = ROOT/'dist/native-runtime'/target_slug
    if prebuilt.exists() or prebuilt.is_symlink():
        # Never rebuild over a corrupt/stale prebuilt artifact to hide an error.
        BUILD.reuse(prebuilt, target)
        source = prebuilt
    else:
        source = ROOT/'dist/engines/native'/BUILD.digest()/target_slug
        BUILD.build(target, source)
    if package_root.is_symlink() or not package_root.is_dir():
        raise ValueError('Native package root must already be an owned directory')
    runtime = package_root/'runtime'
    if runtime.is_symlink():
        raise ValueError('Linked native runtime destination')
    runtime.mkdir(exist_ok=True)
    destination = runtime/'native'
    if destination.exists() or destination.is_symlink():
        raise ValueError('Native package destination already exists')
    with tempfile.TemporaryDirectory(prefix='.native-package-', dir=runtime) as temporary:
        stage = Path(temporary).resolve()/'bundle'
        shutil.copytree(source, stage, symlinks=True)
        BUILD.reuse(stage, target)
        os.replace(stage, destination)
    print('Packaged complete native runtime '+target, flush=True)


def verify_package(target, path):
    """Verify the bytes inside an installed/Portable ZIP or Unix tarball."""
    slug(target)
    verify_archive_path(path)
    with tempfile.TemporaryDirectory(prefix='native-package-check-') as temporary:
        destination = Path(temporary).resolve()
        if zipfile.is_zipfile(path):
            preflight_zip(path)
            with zipfile.ZipFile(path) as archive:
                records = []
                expanded = 0
                for item in archive.infolist():
                    expanded += item.file_size
                    if (len(records) >= MAX_PACKAGE_MEMBERS or item.file_size < 0
                            or item.file_size > MAX_PACKAGE_MEMBER or expanded > MAX_PACKAGE_EXPANDED):
                        raise ValueError('Expanded native ZIP exceeds its bound')
                    mode = item.external_attr >> 16
                    is_file = not item.is_dir() and not stat.S_ISLNK(mode) and (stat.S_IFMT(mode) in (0, stat.S_IFREG))
                    records.append((item.filename.rstrip('/') if item.is_dir() else item.filename,
                                    item.file_size, is_file, item.is_dir(),
                                    lambda item=item: archive.open(item)))
                verify_package_records(target, records, destination)
        else:
            with open_tar(path, target, package=True) as archive:
                verify_package_records(target, list(tar_records(archive)), destination)
    print('Verified archived complete native runtime '+target, flush=True)


def verify_package_records(target, records, destination):
    receipts = [name for name, _, is_file, _, _ in records
                if is_file and name.endswith('/runtime/native/NATIVE-RUNTIME.json')]
    if len(receipts) != 1:
        raise ValueError('Package must contain exactly one complete native receipt')
    prefix = receipts[0].removesuffix('NATIVE-RUNTIME.json')
    if any(part in ('..', '.', '') for part in prefix.rstrip('/').split('/')) or PurePosixPath(prefix).is_absolute():
        raise ValueError('Unsafe packaged native root')
    selected = [item for item in records if item[0] == prefix.rstrip('/') or item[0].startswith(prefix)]
    unpack_payload(selected, prefix, target, destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('archive', 'extract'):
        command = commands.add_parser(name)
        command.add_argument('target', choices=BUILD.TARGETS)
        command.add_argument('source', type=Path)
        command.add_argument('destination', type=Path)
    command = commands.add_parser('stage')
    command.add_argument('source', type=Path)
    command.add_argument('destination', type=Path)
    command.add_argument('targets', nargs='+', choices=BUILD.TARGETS)
    for name in ('package', 'verify-package', 'verify'):
        command = commands.add_parser(name)
        command.add_argument('target', choices=BUILD.TARGETS)
        command.add_argument('path', type=Path)
    args = parser.parse_args()
    if args.command == 'archive':
        archive_bundle(args.target, args.source, args.destination)
    elif args.command == 'extract':
        extract_bundle(args.target, args.source, args.destination)
    elif args.command == 'stage':
        stage_artifacts(args.source, args.destination, args.targets)
    elif args.command == 'package':
        package(args.target, args.path)
    elif args.command == 'verify':
        BUILD.reuse(args.path, args.target)
        print('Verified complete native runtime '+args.target, flush=True)
    else:
        verify_package(args.target, args.path)
