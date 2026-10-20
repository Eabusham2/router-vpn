#!/usr/bin/env python3
"""Make a source-verified packet-only Rosenpass build copy for Windows.

The pinned upstream crypto/protocol and secret-memory implementations are kept
byte-for-byte. Only unused Unix daemon exports and descriptor dependencies are
removed. Filesystem writes are deliberately unavailable inside this packet ABI;
all key material is supplied by its existing bounded C API.
"""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess
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


def verify_lock(before, after):
    """Local source selection may remove dependencies, never upgrade any."""
    old = tomllib.loads(before.decode())['package']
    new = tomllib.loads(after.decode())['package']
    key = lambda item: (item['name'], item['version'], item.get('source', ''))
    frozen = {key(item): item.get('checksum') for item in old if item['name'] not in CRATES}
    pinned = {item['name']: item['version'] for item in old if item['name'] in CRATES}
    seen = set()
    for item in new:
        if item['name'] in CRATES:
            if item.get('source') or item['version'] != pinned[item['name']]:
                raise ValueError('Portable protocol substituted another crypto crate')
            seen.add(item['name'])
        elif key(item) not in frozen or item.get('checksum') != frozen[key(item)]:
            raise ValueError('Portable protocol changed a locked registry/Git dependency')
    if seen != set(CRATES):
        raise ValueError('Portable protocol omitted a pinned cryptographic dependency')


def prepare(source, output):
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
    manifest.write_text(text)
    receipt = {'schema_version': 1, 'revision': REVISION,
               'upstream_files': hashes,
               'changes': {name: hashlib.sha256(data).hexdigest() for name, data in replacements.items()}}
    (output/'PACKET-PROTOCOL.json').write_text(json.dumps(receipt, sort_keys=True, indent=2)+'\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(prepare(args.source, args.output))
