#!/usr/bin/env python3
"""Build the exact socket-free Rosenpass C ABI for a desktop native engine.

This produces a link input, never a VPN daemon. The application and native
endpoint retain socket ownership; the protocol ABI accepts only captured keys
and bounded packets. Cross builds require the actual target C toolchain.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
import contextlib
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('desktop_mobile_pq', ROOT/'deploy/build-mobile-pq.py')
MOBILE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MOBILE)
spec = importlib.util.spec_from_file_location('desktop_packet_pq', ROOT/'deploy/prepare-desktop-rosenpass.py')
PACKET = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PACKET)
RUST = MOBILE.RUST
REVISION = '00569eb273016a10d2e75e5142236f06f7c3d4b3'
TARGETS = {
    'linux/amd64': 'x86_64-unknown-linux-gnu',
    'linux/arm64': 'aarch64-unknown-linux-gnu',
    'darwin/amd64': 'x86_64-apple-darwin',
    'darwin/arm64': 'aarch64-apple-darwin',
    'windows/amd64': 'x86_64-pc-windows-gnullvm',
    'windows/arm64': 'aarch64-pc-windows-gnullvm',
}
MAX_LIBRARY = 384 * 1024 * 1024
MAX_OQS_LIBRARY = 64 * 1024 * 1024


def run(command, *, env=None, capture=True, merge_stderr=True):
    # Cargo emits UTF-8 on every host. Keep the pipes binary so a Windows
    # locale decoder cannot discard output in subprocess's reader thread.
    # Compiler output stays combined: native-static-libs is reported on stderr.
    stderr = subprocess.STDOUT if merge_stderr else subprocess.PIPE
    result = subprocess.run([str(arg) for arg in command], env=env,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=stderr if capture else None, timeout=1800)
    if result.returncode:
        for output in (result.stdout, result.stderr):
            if output:
                print(output[-24000:].decode('utf-8', errors='replace'), flush=True)
        result.check_returncode()
    return (result.stdout or b'').decode('utf-8')


def digest():
    value = hashlib.sha256()
    for path in (Path(__file__).resolve(), ROOT/'deploy/build-mobile-pq.py', ROOT/'deploy/prepare-desktop-rosenpass.py',
                 *sorted((ROOT/'mobile/rosenpass').glob('Cargo.*')),
                 *sorted((ROOT/'mobile/rosenpass').glob('*.h')),
                 *sorted((ROOT/'mobile/rosenpass').glob('*.c')),
                 *sorted((ROOT/'mobile/rosenpass/src').rglob('*.rs'))):
        value.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+path.read_bytes())
    return value.hexdigest()


def regular(path, maximum):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError('Invalid desktop PQ input: '+str(path))
    return path.read_bytes()


def link_flags(output):
    matches = re.findall(r'^note: native-static-libs: (.+)$', output, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError('Rust did not report one exact native static dependency set')
    values = matches[0].split()
    if not values or len(values) > 80 or any(not re.fullmatch(r'-l[a-zA-Z0-9_+.]+', value) for value in values):
        raise ValueError('Unexpected native dependency flags from the pinned Rust compiler')
    return values


def oqs_identity():
    packages = tomllib.loads((ROOT/'mobile/rosenpass/Cargo.lock').read_text())['package']
    pins = [p for p in packages if p['name'] == 'oqs-sys']
    if (len(pins) != 1 or pins[0].get('source') != 'registry+https://github.com/rust-lang/crates.io-index'
            or not re.fullmatch(r'[a-f0-9]{64}', pins[0].get('checksum', ''))):
        raise ValueError('OQS dependency does not have one exact locked registry source')
    pin = pins[0]
    return {'package_id': pin['source']+'#oqs-sys@'+pin['version'], 'crate_checksum': pin['checksum']}


def static_oqs_archive(raw, target):
    """Accept target COFF code, never a thin archive or DLL import library."""
    machine = {'windows/amd64': 0x8664, 'windows/arm64': 0xaa64}.get(target)
    if machine is None or not 8 < len(raw) <= MAX_OQS_LIBRARY or raw[:8] != b'!<arch>\n':
        raise ValueError('Invalid static OQS archive for the requested Windows target')
    offset, objects, code = 8, 0, False
    while offset < len(raw):
        header = raw[offset:offset+60]
        if len(header) != 60 or header[58:] != b'`\n' or not header[48:58].strip().isdigit():
            raise ValueError('Malformed static OQS archive member')
        size = int(header[48:58])
        offset += 60
        end = offset+size
        if end > len(raw):
            raise ValueError('Truncated static OQS archive member')
        member = raw[offset:end]
        name = header[:16].rstrip()
        offset = end+(size & 1)
        if offset > len(raw):
            raise ValueError('Truncated static OQS archive alignment')
        if name in (b'/', b'//', b'/SYM64/'):
            continue
        objects += 1
        if len(member) < 20:
            raise ValueError('OQS archive contains a non-object member')
        # The short import header shares a prefix with BigObj. Only the exact
        # BigObj class identifier denotes a static COFF object in that format.
        if member[:4] == b'\0\0\xff\xff':
            if (len(member) < 56 or struct.unpack_from('<H', member, 4)[0] < 2 or
                    member[12:28] != bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8')):
                raise ValueError('OQS archive contains a DLL import object')
            actual = struct.unpack_from('<H', member, 6)[0]
            sections, symbols, count = struct.unpack_from('<III', member, 44)
            start, symbol_size = 56, 20
        else:
            actual, sections = struct.unpack_from('<HH', member)
            symbols, count = struct.unpack_from('<II', member, 8)
            if struct.unpack_from('<H', member, 16)[0] != 0:
                raise ValueError('OQS archive contains an image instead of a static object')
            start, symbol_size = 20, 18
        if actual != machine or not sections or start+40*sections > len(member):
            raise ValueError('OQS static object differs from the requested target')
        for index in range(sections):
            section = member[start+40*index:start+40*(index+1)]
            label = section[:8].rstrip(b'\0')
            if label.startswith(b'/'):
                table = symbols+count*symbol_size
                if (not label[1:].isdigit() or not symbols or table+4 > len(member)):
                    raise ValueError('Malformed OQS COFF section name')
                length = struct.unpack_from('<I', member, table)[0]
                position = int(label[1:])
                if length < 4 or table+length > len(member) or not 4 <= position < length:
                    raise ValueError('Malformed OQS COFF string table')
                strings = member[table:table+length]
                terminator = strings.find(b'\0', position)
                if terminator < 0:
                    raise ValueError('Unterminated OQS COFF section name')
                label = strings[position:terminator]
            if label.startswith((b'.idata', b'.edata')):
                raise ValueError('OQS archive contains DLL import/export sections')
            data_size, data_offset = struct.unpack_from('<II', section, 16)
            attributes = struct.unpack_from('<I', section, 36)[0]
            if data_size and not (data_offset == 0 and attributes & 0x80):
                if data_offset < start+40*sections or data_offset+data_size > len(member):
                    raise ValueError('Malformed OQS COFF section payload')
            code |= bool(attributes & 0x20 and data_size and data_offset)
    if not objects or not code:
        raise ValueError('OQS archive does not contain static target code')
    return raw


def built_oqs_archive(output, target, cache):
    """Select only this locked Cargo invocation's target-owned OQS output."""
    identity = oqs_identity()
    records = []
    for line in output.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    events = [r for r in records if r.get('reason') == 'build-script-executed'
              and r.get('package_id') == identity['package_id']]
    finished = [r for r in records if r.get('reason') == 'build-finished']
    if len(events) != 1 or len(finished) != 1 or finished[0].get('success') is not True:
        raise ValueError('OQS output is not from one successful locked Cargo build')
    event = events[0]
    # Upstream's build script selects this by its host cfg!(windows). Native
    # Windows leaves OQS external; a supported Linux cross build bundles it.
    expected_libs = ['oqs', 'advapi32'] if '-loqs' in link_flags(output) else ['static=oqs']
    if event.get('linked_libs') != expected_libs or not isinstance(event.get('out_dir'), str):
        raise ValueError('Locked OQS native dependency declaration changed')
    cache = Path(cache).resolve()
    out = Path(event['out_dir'])
    if not out.is_absolute() or '..' in out.parts:
        raise ValueError('OQS build output is not an absolute target-owned path')
    relative = out.relative_to(cache)
    if (len(relative.parts) != 5 or relative.parts[:3] != (TARGETS[target], 'release', 'build') or
            not re.fullmatch(r'oqs-sys-[a-f0-9]{16}', relative.parts[3]) or relative.parts[4] != 'out'):
        raise ValueError('OQS build output differs from the requested target cache')
    current = cache
    for part in relative.parts:
        current /= part
        if current.is_symlink() or not current.is_dir():
            raise ValueError('OQS build output contains an unowned or linked directory')
    directories = [out/'lib', out/'lib64']
    paths = event.get('linked_paths')
    if (not isinstance(paths, list) or len(paths) != 2 or
            any(not isinstance(p, str) or not p.startswith('native=') for p in paths) or
            {Path(p[7:]) for p in paths} != set(directories)):
        raise ValueError('OQS link search escapes its exact build output')
    candidates = []
    for directory in directories:
        path = directory/'liboqs.a'
        if directory.is_symlink() or path.is_symlink():
            raise ValueError('OQS archive is linked outside its owned build output')
        if path.exists():
            candidates.append(path)
    if len(candidates) != 1:
        raise ValueError('OQS build must produce one unambiguous static archive')
    return static_oqs_archive(regular(candidates[0], MAX_OQS_LIBRARY), target)


def verify(directory, target):
    if target not in TARGETS or directory.is_symlink() or not directory.is_dir():
        raise ValueError('Invalid desktop PQ target or directory')
    raw = regular(directory/'libroutervpn_rosenpass.a', MAX_LIBRARY)
    receipt = json.loads(regular(directory/'DESKTOP-PQ.json', 16384))
    required = {'schema_version': 1, 'abi': 1, 'target': target, 'rust_target': TARGETS[target],
                'rust_toolchain': RUST, 'rosenpass_revision': REVISION,
                'source_sha256': digest(), 'cargo_lock_sha256': MOBILE.validate_lock(),
                'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    flags = receipt.get('native_static_libs')
    if not isinstance(flags, list) or link_flags('note: native-static-libs: '+' '.join(flags)) != flags:
        raise ValueError('Invalid desktop PQ native dependency receipt')
    names = {'libroutervpn_rosenpass.a', 'DESKTOP-PQ.json'}
    if target.startswith('windows/'):
        imported = regular(directory/'libwindows.a', 32 << 20)
        required.update(windows_import_size=len(imported), windows_import_sha256=hashlib.sha256(imported).hexdigest())
        names.add('libwindows.a')
        oqs = static_oqs_archive(regular(directory/'liboqs.a', MAX_OQS_LIBRARY), target)
        required['oqs_archive'] = {**oqs_identity(), 'linkage': 'external' if '-loqs' in flags else 'bundled',
                                   'size': len(oqs), 'sha256': hashlib.sha256(oqs).hexdigest()}
        names.add('liboqs.a')
    if receipt != {**required, 'native_static_libs': flags}:
        raise ValueError('Desktop PQ archive differs from its exact source/target receipt')
    if set(path.name for path in directory.iterdir()) != names:
        raise ValueError('Unexpected desktop PQ bundle contents')
    return receipt


def environment(target, cache):
    if target not in TARGETS:
        raise ValueError('Unsupported desktop PQ architecture')
    env = MOBILE.base_env(cache)
    env.update(CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_DEV_DEBUG='0',
               CARGO_PROFILE_TEST_DEBUG='0')
    triple = TARGETS[target]
    if target.startswith('windows/'):
        prefix = 'x86_64' if target.endswith('/amd64') else 'aarch64'
        cc = shutil.which(prefix+'-w64-mingw32-clang')
        ar = shutil.which('llvm-ar')
        if not cc or not ar:
            raise ValueError('Windows native PQ requires the pinned LLVM-MinGW toolchain')
        env.update(CC=cc, AR=ar, CMAKE_SYSTEM_NAME='Windows',
                   BINDGEN_EXTRA_CLANG_ARGS='--target='+prefix+'-w64-windows-gnu')
        env['CC_'+triple.replace('-', '_')] = cc
        env['AR_'+triple.replace('-', '_')] = ar
        env['CARGO_TARGET_'+triple.replace('-', '_').upper()+'_LINKER'] = cc
    elif target.startswith('darwin/'):
        xcrun = shutil.which('xcrun', path=env.get('PATH', ''))
        if not xcrun:
            raise ValueError('macOS native PQ requires the selected Xcode macOS SDK')
        selected = run([xcrun, '--sdk', 'macosx', '--show-sdk-path'],
                       env=env, merge_stderr=False).strip()
        sdk = Path(selected)
        if (not selected or any(c in selected for c in '\r\n\0') or
                not sdk.is_absolute() or not sdk.is_dir() or
                not (sdk/'usr/include/stdio.h').is_file()):
            raise ValueError('The selected Xcode macOS SDK does not contain its C headers')
        # CMake can discover an SDK while libclang still searches the host root.
        # Give both OQS compilation and bindgen the same SDK and product minimum.
        arch = 'x86_64' if target.endswith('/amd64') else 'arm64'
        args = shlex.join(['-target', arch+'-apple-macosx13.0', '-isysroot', str(sdk)])
        env.update(SDKROOT=str(sdk), MACOSX_DEPLOYMENT_TARGET='13.0',
                   BINDGEN_EXTRA_CLANG_ARGS=args)
        # bindgen checks both target-specific spellings before the generic value.
        for name in (triple, triple.replace('-', '_')):
            env['BINDGEN_EXTRA_CLANG_ARGS_'+name] = args
    return env


def locked_metadata(env):
    return json.loads(run(['cargo', 'metadata', '--locked', '--format-version=1',
                           '--manifest-path', ROOT/'mobile/rosenpass/Cargo.toml'],
                          env=env, merge_stderr=False))


def windows_import(target, metadata):
    name = 'windows_'+('x86_64' if target.endswith('/amd64') else 'aarch64')+'_gnullvm'
    entries = [item for item in metadata['packages'] if item['name'] == name and item['version'] == '0.42.2']
    if len(entries) != 1 or not entries[0].get('source', '').startswith('registry+'):
        raise ValueError('Windows import archive does not have its exact locked provenance')
    package = Path(entries[0]['manifest_path']).parent
    lock = tomllib.loads((ROOT/'mobile/rosenpass/Cargo.lock').read_text())
    pins = [p for p in lock['package'] if p['name'] == name and p['version'] == '0.42.2']
    if len(pins) != 1:
        raise ValueError('Windows import archive version is ambiguous')
    archive = package.parents[2]/'cache'/package.parent.name/(package.name+'.crate')
    raw = regular(archive, 32 << 20)
    if hashlib.sha256(raw).hexdigest() != pins[0]['checksum']:
        raise ValueError('Windows import crate checksum differs from Cargo.lock')
    with tarfile.open(archive, 'r:gz') as tar:
        member = tar.getmember(package.name+'/lib/libwindows.a')
        if not member.isfile() or not 0 < member.size <= 32 << 20:
            raise ValueError('Invalid pinned Windows import archive member')
        return tar.extractfile(member).read()


def bindgen_archive(metadata):
    entries = [item for item in metadata['packages'] if item['name'] == 'bindgen']
    if (len(entries) != 1 or entries[0]['version'] != PACKET.BINDGEN_VERSION or
            entries[0].get('source') != PACKET.BINDGEN_SOURCE):
        raise ValueError('Bindgen build tool does not have its exact locked provenance')
    package = Path(entries[0]['manifest_path']).parent
    return package.parents[2]/'cache'/package.parent.name/(package.name+'.crate')


@contextlib.contextmanager
def native_manifest(target, env):
    if not target.startswith('windows/'):
        yield ROOT/'mobile/rosenpass/Cargo.toml', None
        return
    metadata = locked_metadata(env)
    entries = [item for item in metadata['packages'] if item['name'] == 'rosenpass'
               and item.get('source', '').endswith('#'+REVISION)]
    if len(entries) != 1:
        raise ValueError('Pinned packet protocol source is ambiguous')
    source = Path(entries[0]['manifest_path']).parent.parent
    with tempfile.TemporaryDirectory(prefix='routervpn-packet-protocol-') as temp:
        manifest = PACKET.prepare(source, Path(temp)/'packet', bindgen_archive=bindgen_archive(metadata))
        before = (ROOT/'mobile/rosenpass/Cargo.lock').read_bytes()
        run(['cargo', 'metadata', '--offline', '--format-version=1', '--manifest-path', manifest], env=env)
        frozen = manifest.with_name('Cargo.lock').read_bytes()
        PACKET.verify_lock(before, frozen, bindgen=True)
        yield manifest, windows_import(target, metadata)
        if manifest.with_name('Cargo.lock').read_bytes() != frozen:
            raise ValueError('Desktop compilation modified the verified portable dependency lock')


def build(target, output, cache):
    if target not in TARGETS:
        raise ValueError('Unsupported desktop PQ target')
    output = Path(output).absolute()
    if output.is_symlink():
        raise ValueError('Refusing a linked desktop PQ output')
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and any(output.iterdir()):
        verify(output, target)
        return output
    env = environment(target, cache)
    if not run(['rustc', '--version'], env=env).startswith('rustc '+RUST+' '):
        raise ValueError('Desktop PQ requires the exact Rust '+RUST+' compiler')
    if not run(['cargo', '--version'], env=env).startswith('cargo '+RUST+' '):
        raise ValueError('Desktop PQ requires the matching pinned Cargo compiler')
    lock = MOBILE.validate_lock()
    print('Building actual pinned Rosenpass ABI for '+target, flush=True)
    with native_manifest(target, env) as (manifest, imported):
        command = ['cargo', 'rustc', '--locked', '--manifest-path', manifest, '--target', TARGETS[target],
                   '--release', '--lib', '--', '--print', 'native-static-libs']
        if target.startswith('windows/'):
            command.insert(2, '--message-format=json-render-diagnostics')
        result = run(command, env=env)
        oqs = built_oqs_archive(result, target, cache) if target.startswith('windows/') else None
    flags = link_flags(result)
    if MOBILE.validate_lock() != lock:
        raise ValueError('Desktop PQ build changed the pinned dependency lock')
    library = Path(cache)/TARGETS[target]/'release/libroutervpn_rosenpass.a'
    raw = regular(library, MAX_LIBRARY)
    with tempfile.TemporaryDirectory(prefix='.desktop-pq-', dir=output.parent) as temp:
        stage = Path(temp)/'bundle'
        stage.mkdir()
        (stage/library.name).write_bytes(raw)
        receipt = {'schema_version': 1, 'abi': 1, 'target': target, 'rust_target': TARGETS[target],
                   'rust_toolchain': RUST, 'rosenpass_revision': REVISION,
                   'source_sha256': digest(), 'cargo_lock_sha256': lock,
                   'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'native_static_libs': flags}
        if imported is not None:
            (stage/'libwindows.a').write_bytes(imported)
            receipt.update(windows_import_size=len(imported), windows_import_sha256=hashlib.sha256(imported).hexdigest())
        if oqs is not None:
            (stage/'liboqs.a').write_bytes(oqs)
            receipt['oqs_archive'] = {**oqs_identity(), 'linkage': 'external' if '-loqs' in flags else 'bundled',
                                      'size': len(oqs), 'sha256': hashlib.sha256(oqs).hexdigest()}
        (stage/'DESKTOP-PQ.json').write_text(json.dumps(receipt, sort_keys=True, indent=2)+'\n')
        verify(stage, target)
        if output.exists():
            output.rmdir()
        os.replace(stage, output)
    print('Built exact desktop PQ ABI '+target, flush=True)
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', choices=TARGETS)
    parser.add_argument('output', type=Path)
    parser.add_argument('--cache', type=Path, required=True)
    args = parser.parse_args()
    build(args.target, args.output, args.cache)
