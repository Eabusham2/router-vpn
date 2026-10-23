#!/usr/bin/env python3
"""Make a source-verified packet-only Rosenpass build copy for Windows.

The pinned upstream crypto/protocol and secret-memory implementations are kept
byte-for-byte. Only unused Unix daemon exports and descriptor dependencies are
removed. Filesystem writes are deliberately unavailable inside this packet ABI;
all key material is supplied by its existing bounded C API.

The optional build-time bindgen copy backports its upstream Clang 22 definition
lookup fix. It does not alter protocol/crypto sources or disable layout checks.
"""
from pathlib import Path
import argparse
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
REVISION = '00569eb273016a10d2e75e5142236f06f7c3d4b3'
CRATES = {'rosenpass': 'rosenpass', 'rosenpass-util': 'util',
          'rosenpass-cipher-traits': 'cipher-traits', 'rosenpass-ciphers': 'ciphers',
          'rosenpass-secret-memory': 'secret-memory', 'rosenpass-constant-time': 'constant-time',
          'rosenpass-oqs': 'oqs', 'rosenpass-to': 'to'}
FILES = {
    'rosenpass/Cargo.toml': '441ad5b79693a0261a400c34f50abded593b3439',
    'rosenpass/src/lib.rs': 'b389a07aebf423187efd67731b5b6d6364d94d88',
    'rosenpass/src/config.rs': '80569db858bab5f91254f1aa6a5cf65d83f12f4a',
    'util/Cargo.toml': '7daad615fc4f542cbffbc278f6a4d4497bf8b6aa',
    'util/src/file.rs': '86d0c0103a723a2a6a42fbc8c3f9fe701e8247d4',
    'util/src/lib.rs': '69d76984f19685f5e0f5f92bd1e289b8148188d1',
}
DOCUMENT_LINKS = {'.dockerignore': '.gitignore', 'rosenpass/readme.md': 'readme.md'}
BINDGEN_VERSION = '0.71.1'
BINDGEN_SOURCE = 'registry+https://github.com/rust-lang/crates.io-index'
BINDGEN_CHECKSUM = '5f58bf3d7db68cfbac37cfc485a8d711e87e064c3d0fe0435b92f7a407f9d6b3'
BINDGEN_SIZE = 237785
BINDGEN_CLANG_SHA256 = '3bd59196c2c37fd3af4c1d59a38aa64a182c1449d1e5e93f5d754458e7ee3291'
BINDGEN_PATCHED_SHA256 = '2e1e65a56cf7434733dc87e8cc837d64add8358cb3d57f81a1424d7aea4858a5'
# https://github.com/rust-lang/rust-bindgen/pull/3278
BINDGEN_BACKPORT = '2426dd68cd12e0ac022bca18efb9c7d0acd27e12'
BINDGEN_OLD = '''    pub(crate) fn declaration(&self) -> Cursor {
        unsafe {
            Cursor {
                x: clang_getTypeDeclaration(self.x),
            }
        }
    }'''
BINDGEN_NEW = '''    pub(crate) fn declaration(&self) -> Cursor {
        let decl = Cursor {
            x: unsafe { clang_getTypeDeclaration(self.x) },
        };
        // Prior to clang 22, the declaration pointed to the definition.
        decl.definition().unwrap_or(decl)
    }'''


def blob(raw):
    return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Pinned packet-only export boundary changed')
    return text.replace(old, new, 1)


def patches(source):
    original = {}
    for name, expected in FILES.items():
        path = source/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Unsafe Rosenpass source input')
        raw = path.read_bytes()
        if blob(raw) != expected:
            raise ValueError('Pinned Rosenpass source differs: '+name)
        original[name] = raw.decode()
    output = dict(original)
    for module in ('app_server', 'cli'):
        output['rosenpass/src/lib.rs'] = once(output['rosenpass/src/lib.rs'], 'pub mod '+module+';\n', '')
    # The unchanged protocol builder references this enum, not the daemon's
    # filesystem/Unix-socket configuration API. Preserve the exact upstream
    # definition and derive behavior as its own portable configuration module.
    version = '''/// The protocol version to be used by a peer.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Copy, Clone, Default)]
#[serde(deny_unknown_fields)]
pub enum ProtocolVersion {
    #[default]
    V02,
    V03,
}'''
    if output['rosenpass/src/config.rs'].count(version) != 1:
        raise ValueError('Pinned protocol version enum changed')
    output['rosenpass/src/config.rs'] = 'use serde::{Deserialize, Serialize};\n\n'+version+'\n'
    # No Unix daemon dependency should be compiled merely because the crypto
    # crate happens to export its separate command-line application too.
    manifest = output['rosenpass/Cargo.toml']
    for name in ('mio', 'signal-hook', 'signal-hook-mio', 'rosenpass-wireguard-broker'):
        manifest = once(manifest, '\n'+name+' = { workspace = true }\n', '\n')
    manifest = once(manifest, 'experiment_memfd_secret = ["rosenpass-wireguard-broker/experiment_memfd_secret"]',
                    'experiment_memfd_secret = []')
    manifest = once(manifest, '  "rosenpass-wireguard-broker/experiment_api",\n', '')
    output['rosenpass/Cargo.toml'] = manifest
    for module in ('fd', 'mio'):
        output['util/src/lib.rs'] = once(output['util/src/lib.rs'], 'pub mod '+module+';',
                                         '#[cfg(unix)]\npub mod '+module+';')
    manifest = output['util/Cargo.toml']
    for name in ('rustix', 'mio'):
        manifest = once(manifest, '\n'+name+' = { workspace = true }\n', '\n')
    manifest += '\n[target.\'cfg(unix)\'.dependencies]\nrustix = { workspace = true }\nmio = { workspace = true }\n'
    output['util/Cargo.toml'] = manifest
    file = output['util/src/file.rs']
    file = once(file, 'use std::os::unix::fs::OpenOptionsExt;', '#[cfg(unix)]\nuse std::os::unix::fs::OpenOptionsExt;')
    original_function = '''pub fn fopen_w<P: AsRef<Path>>(path: P, visibility: Visibility) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).read(false).truncate(true);
    match visibility {
        Visibility::Public => options.mode(0o644),
        Visibility::Secret => options.mode(0o600),
    };
    options.open(path)
}'''
    replacement = '''pub fn fopen_w<P: AsRef<Path>>(path: P, visibility: Visibility) -> std::io::Result<File> {
    #[cfg(unix)] {
        let mut options = OpenOptions::new();
        options.create(true).write(true).read(false).truncate(true);
        match visibility {
            Visibility::Public => options.mode(0o644),
            Visibility::Secret => options.mode(0o600),
        };
        options.open(path)
    }
    #[cfg(not(unix))] {
        let _ = (path, visibility);
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported,
            "packet-only protocol does not own filesystem writes"))
    }
}'''
    output['util/src/file.rs'] = once(file, original_function, replacement)
    return {name: value.encode() for name, value in output.items()}


def bindgen_pin(lock):
    matches = [item for item in tomllib.loads(lock.decode('utf-8'))['package']
               if item['name'] == 'bindgen']
    if (len(matches) != 1 or matches[0]['version'] != BINDGEN_VERSION or
            matches[0].get('source') != BINDGEN_SOURCE or
            matches[0].get('checksum') != BINDGEN_CHECKSUM):
        raise ValueError('Build-time bindgen backport requires its exact locked registry crate')
    return matches[0]


def prepare_bindgen(archive, output):
    """Copy only the checksum-verified crate archive; never trust Cargo's src cache."""
    bindgen_pin((ROOT/'mobile/rosenpass/Cargo.lock').read_bytes())
    archive, output = Path(archive), Path(output)
    if (archive.is_symlink() or not archive.is_file() or archive.stat().st_size != BINDGEN_SIZE):
        raise ValueError('Invalid pinned bindgen crate archive')
    raw = archive.read_bytes()
    if hashlib.sha256(raw).hexdigest() != BINDGEN_CHECKSUM:
        raise ValueError('Bindgen crate checksum differs from Cargo.lock')
    if output.is_symlink() or output.exists():
        raise ValueError('Bindgen backport output must be a fresh owned directory')
    contents = {}
    prefix = 'bindgen-'+BINDGEN_VERSION+'/'
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as package:
        for member in package:
            if not member.name.startswith(prefix):
                raise ValueError('Foreign bindgen archive member')
            name = member.name[len(prefix):]
            parts = name.split('/')
            total += member.size
            if (not member.isfile() or not name or any(part in ('', '.', '..') for part in parts) or
                    '\\' in name or ':' in name or name in contents or len(contents) >= 256 or
                    not 0 <= member.size <= 2 << 20 or total > 4 << 20):
                raise ValueError('Unbounded or linked bindgen archive member')
            contents[name] = package.extractfile(member).read()
    original = contents.get('clang.rs', b'')
    if hashlib.sha256(original).hexdigest() != BINDGEN_CLANG_SHA256:
        raise ValueError('Pinned bindgen declaration lookup source changed')
    contents['clang.rs'] = once(original.decode('utf-8'), BINDGEN_OLD, BINDGEN_NEW).encode('utf-8')
    if hashlib.sha256(contents['clang.rs']).hexdigest() != BINDGEN_PATCHED_SHA256:
        raise ValueError('Bindgen backport differs from the exact upstream definition fix')
    manifest = tomllib.loads(contents['Cargo.toml'].decode('utf-8'))
    if manifest['package']['name'] != 'bindgen' or manifest['package']['version'] != BINDGEN_VERSION:
        raise ValueError('Pinned bindgen crate identity changed')
    output.mkdir(parents=True)
    for name, data in contents.items():
        destination = output/name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    return {'version': BINDGEN_VERSION, 'crate_sha256': BINDGEN_CHECKSUM,
            'upstream_backport': BINDGEN_BACKPORT,
            'clang_original_sha256': BINDGEN_CLANG_SHA256,
            'clang_patched_sha256': hashlib.sha256(contents['clang.rs']).hexdigest()}


def verify_lock(before, after, *, bindgen=False):
    """Local source selection may remove dependencies, never upgrade any."""
    old = tomllib.loads(before.decode())['package']
    new = tomllib.loads(after.decode())['package']
    key = lambda item: (item['name'], item['version'], item.get('source', ''))
    frozen = {key(item): item.get('checksum') for item in old if item['name'] not in CRATES}
    pinned = {item['name']: item['version'] for item in old if item['name'] in CRATES}
    seen = set()
    saw_bindgen = False
    if bindgen:
        bindgen_pin(before)
    for item in new:
        if bindgen and item['name'] == 'bindgen':
            if (saw_bindgen or item['version'] != BINDGEN_VERSION or
                    'source' in item or 'checksum' in item):
                raise ValueError('Portable protocol substituted another bindgen build tool')
            saw_bindgen = True
        elif item['name'] in CRATES:
            if item.get('source') or item['version'] != pinned[item['name']]:
                raise ValueError('Portable protocol substituted another crypto crate')
            seen.add(item['name'])
        elif key(item) not in frozen or item.get('checksum') != frozen[key(item)]:
            raise ValueError('Portable protocol changed a locked registry/Git dependency')
    if seen != set(CRATES):
        raise ValueError('Portable protocol omitted a pinned cryptographic dependency')
    if bindgen and not saw_bindgen:
        raise ValueError('Portable protocol omitted its verified bindgen backport')


def prepare(source, output, *, bindgen_archive=None):
    source, output = Path(source).resolve(), Path(output).absolute()
    if subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() != REVISION:
        raise ValueError('Packet-only Rosenpass requires the exact upstream revision')
    changed = subprocess.check_output(['git', '-C', str(source), 'diff', '--name-only', 'HEAD'], text=True)
    if changed:
        raise ValueError('Rosenpass build source contains unknown tracked changes')
    replacements = patches(source)
    if output.is_symlink() or output.exists():
        raise ValueError('Portable protocol output must be a fresh owned directory')
    records = subprocess.check_output(['git', '-C', str(source), 'ls-tree', '-rz', '--full-tree', 'HEAD'])
    hashes = {}
    contents = {}
    for record in records.split(b'\0'):
        if not record:
            continue
        header, raw_name = record.split(b'\t', 1)
        mode, kind, wanted = header.decode().split()
        name = raw_name.decode()
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or kind != 'blob':
            raise ValueError('Unbounded or linked upstream build member: '+name)
        if mode == '120000' and name in DOCUMENT_LINKS:
            # Materialize only these two pinned documentation aliases. Never
            # follow an on-disk symlink or permit links in executable sources.
            link = subprocess.check_output(['git', '-C', str(source), 'cat-file', 'blob', wanted])
            expected = '.gitignore' if name == '.dockerignore' else '../readme.md'
            if link.decode() != expected:
                raise ValueError('Pinned documentation alias changed')
            data = subprocess.check_output(['git', '-C', str(source), 'show', 'HEAD:'+DOCUMENT_LINKS[name]])
            contents[name] = data
            hashes[name] = hashlib.sha256(data).hexdigest()
            continue
        if mode not in ('100644', '100755'):
            raise ValueError('Unbounded or linked upstream build member: '+name)
        original = source/relative
        if original.is_symlink() or not original.is_file():
            raise ValueError('Unsafe pinned source member: '+name)
        data = original.read_bytes()
        if blob(data) != wanted:
            raise ValueError('Pinned upstream file changed while copying: '+name)
        contents[name] = replacements.get(name, data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    output.mkdir(parents=True)
    upstream = output/'upstream'
    upstream.mkdir()
    for name, data in contents.items():
        target = upstream/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    native = output/'native'
    shutil.copytree(ROOT/'mobile/rosenpass', native, ignore=shutil.ignore_patterns('target'))
    manifest = native/'Cargo.toml'
    text = manifest.read_text()+'\n[patch."https://github.com/rosenpass/rosenpass"]\n'
    for name, directory in CRATES.items():
        text += name+' = { path = "../upstream/'+directory+'" }\n'
    receipt = {'schema_version': 1, 'revision': REVISION,
               'upstream_files': hashes,
               'changes': {name: hashlib.sha256(data).hexdigest() for name, data in replacements.items()}}
    if bindgen_archive is not None:
        receipt['bindgen'] = prepare_bindgen(bindgen_archive, output/'build-tools/bindgen')
        text += '\n[patch.crates-io]\nbindgen = { path = "../build-tools/bindgen" }\n'
    manifest.write_bytes(text.encode('utf-8'))
    (output/'PACKET-PROTOCOL.json').write_text(json.dumps(receipt, sort_keys=True, indent=2)+'\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--bindgen-archive', type=Path)
    args = parser.parse_args()
    print(prepare(args.source, args.output, bindgen_archive=args.bindgen_archive))
