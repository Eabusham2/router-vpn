#!/usr/bin/env python3
"""Build and seal the complete pinned desktop Router VPN transport engine.

The Rust protocol has no socket owner. Its existing C ABI is linked into the
same process as WG/AWG, native Xray, Naive, authenticated Start Layers and the
TCP/UDP composite. No installed system engine is overwritten or downloaded at
connection time. A package may consume only a bundle with this exact receipt.
"""
from collections import Counter, deque
from pathlib import Path
import argparse
import ast
import base64
import errno
import hashlib
import http.client
import http.server
import importlib.util
import json
import os
import platform
import re
import shlex
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


POLICY = load('desktop_native_policy', 'prepare-relay-core.py')
PQ = load('desktop_native_pq', 'build-desktop-pq.py')
BUFFERS = load('desktop_native_buffers', 'prepare-mobile-buffers.py')
PERFORMANCE = load('desktop_native_performance', 'prepare-mobile-performance.py')
OPENVPN = load('desktop_native_openvpn', 'mobile_openvpn_close_policy.py')
EXTERNAL = load('desktop_native_external', 'prepare-desktop-external.py')
TOR = load('desktop_native_tor', 'build-desktop-tor.py')
DNSSEC = load('desktop_native_dnssec', 'desktop-dnssec-bundle.py')
BUILD_OWNER = load('desktop_windows_build_owner', 'windows_build_owner.py')
DARWIN_RACE = load('desktop_darwin_race_compiler', 'darwin_race_toolchain.py')
GO_SOCKETS = load('desktop_windows_go_sockets', 'prepare-go-windows-sockets.py')
XRAY_SERVER = load('desktop_native_xray_server', 'prepare-xray-runtime.py')
PIN, VERSION, TOOLCHAIN = POLICY.CORE, '1.14.1', 'go1.26.3'
TARGETS = tuple(PQ.TARGETS)
TAGS = ('with_wireguard', 'with_gvisor', 'with_quic', 'with_utls', 'with_openvpn',
        'with_naive_outbound', 'routervpn_native_pq')
MAX_BINARY, MAX_LIBRARY, MAX_LICENSE = 384*1024*1024, 128*1024*1024, 256*1024
PT_NOTICES, MAX_PT_NOTICES = 'TOR-PT-NOTICES.json', 2*1024*1024
CRONET_VERSION = 'v0.0.0-20260912104006-c10c03c318db'
LICENSES = ('SING-BOX-LICENSE', 'AMNEZIA-LICENSE', 'XRAY-LICENSE',
            'ROSENPASS-LICENSE-MIT', 'ROSENPASS-LICENSE-APACHE', 'CRONET-LICENSE', PT_NOTICES)
# Windows supplies these libraries and its versioned API-set contracts. Every
# other DLL must be an explicitly owned payload, never a compiler PATH entry.
WINDOWS_SYSTEM_DLLS = frozenset((
    'advapi32.dll', 'bcrypt.dll', 'bcryptprimitives.dll', 'crypt32.dll',
    'dbghelp.dll', 'iphlpapi.dll', 'kernel32.dll', 'kernelbase.dll', 'ntdll.dll',
    'ole32.dll', 'secur32.dll', 'shell32.dll', 'shlwapi.dll', 'user32.dll',
    'userenv.dll', 'winhttp.dll', 'winmm.dll', 'ws2_32.dll',
))
MAX_BUILD_DIAGNOSTIC = 64*1024
# One composed invocation preserves the original prefix and SOCKS stages
# (3000s and 4200s), including their additional bounded Local prefix cases,
# then executes the distinct HTTP/HTTPS CONNECT stage (4200s, including builds).
# The inner compiler, native case, proof and retirement deadlines are unchanged.
WINDOWS_INSTALLED_NATIVE_GATE_TIMEOUT = 3000 + 4200 + 4200
COMMAND_TEST_SELECTION = r'^TestRouterVPN(Desktop(External|MTU|DNS|Tor)|NodeMTU|NodeChain)'
COMMAND_TEST_BATCH = 8


def run(command, *, cwd=None, env=None, timeout=1800):
    # Cargo/Go metadata is UTF-8 even on Windows. Keep stdout binary until the
    # child is joined; a locale reader thread must not discard its output.
    # Python gates relay those native streams through redirected stdout. Give
    # the original child and its descendants the same UTF-8 contract instead
    # of letting a Windows code page recode a valid native diagnostic.
    child_env = {key: value for key, value in (os.environ if env is None else env).items()
                 if key.upper() != 'PYTHONIOENCODING'}
    child_env['PYTHONIOENCODING'] = 'utf-8:strict'
    command, child_env = DARWIN_RACE.command(command, cwd, child_env)
    try:
        if os.name == 'nt':
            completed = BUILD_OWNER.run(command, cwd=cwd, env=child_env, timeout=timeout)
        else:
            completed = subprocess.run([str(arg) for arg in command], cwd=cwd, env=child_env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       timeout=timeout, check=True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        # A failed or timed-out native gate must expose its actual diagnostic,
        # not only the wrapper traceback. Retain both stream tails within one
        # bound; leave the original exception and captured bytes untouched.
        stdout, stderr = error.stdout or b'', error.stderr or b''
        def diagnostic_tail(raw, limit):
            # Replacement characters must not expand malformed bytes beyond
            # the logging bound, or split a retained UTF-8 character.
            encoded = raw[-limit:].decode('utf-8', errors='replace').encode('utf-8')
            return encoded[-limit:].decode('utf-8', errors='ignore')
        stderr_tail = diagnostic_tail(stderr, MAX_BUILD_DIAGNOSTIC//2 if stdout else MAX_BUILD_DIAGNOSTIC)
        stdout_tail = diagnostic_tail(stdout, MAX_BUILD_DIAGNOSTIC-len(stderr_tail.encode('utf-8'))) if stdout else ''
        for name, value in (('stdout', stdout_tail), ('stderr', stderr_tail)):
            if value:
                sys.stderr.write('Native build failure '+name+' (bounded tail):\n')
                sys.stderr.write(value+'\n')
        sys.stderr.flush()
        raise
    # Successful metadata must remain stdout-only: a Cargo/Go warning must
    # never be concatenated into JSON or version text consumed by the builder.
    if completed.stderr:
        sys.stderr.write(completed.stderr.decode('utf-8', errors='replace'))
        sys.stderr.flush()
    output = completed.stdout.decode('utf-8')
    return output.replace('\r\n', '\n').replace('\r', '\n').strip()






def inputs():
    # Complete source fingerprints, excluding standalone regression suites.
    files = [Path(__file__).resolve(), ROOT/'deploy/build-desktop-pq.py',
             ROOT/'deploy/build-desktop-tor.py', ROOT/'deploy/build-mobile-tor.py',
             ROOT/'deploy/prepare-desktop-rosenpass.py', ROOT/'deploy/prepare-mobile-buffers.py',
             ROOT/'deploy/mobile_udp_socket_policy.py', ROOT/'deploy/seal-native-runtime.py',
             ROOT/'server/scripts/generate-xray-pq.sh', ROOT/'server/scripts/generate-advanced-profiles.sh',
             ROOT/'deploy/prepare-go-windows-sockets.py', ROOT/'deploy/windows_build_owner.py',
             ROOT/'deploy/install-desktop-windows-toolchain.py', ROOT/'deploy/darwin_race_toolchain.py',
             *POLICY.inputs(), *XRAY_SERVER.sources(), *TOR.inputs(), *DNSSEC.inputs(), *PERFORMANCE.inputs(),
             *OPENVPN.inputs(), *EXTERNAL.inputs(), ROOT/'go.mod',
             *sorted((ROOT/'cmd').rglob('*.go')), *sorted((ROOT/'internal').rglob('*.go')),
             *sorted((ROOT/'mobile').rglob('*.tmpl')), ROOT/'cmd/client/ui.html',
             ROOT/'cmd/client/logical_ui.js', ROOT/'.github/workflows/build-all.yml',
             *sorted((ROOT/'mobile/rosenpass').rglob('Cargo.*')),
             *sorted((ROOT/'mobile/rosenpass/src').rglob('*.rs'))]
    return sorted({path for path in files if not path.name.endswith(('_test.go','_test.go.tmpl')) and not path.name.startswith(('test_','test-'))}, key=lambda p:p.as_posix())


def digest():
    value = hashlib.sha256()
    for path in inputs():
        value.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+path.read_bytes())
    return value.hexdigest()


def marker(policy):
    return VERSION+'-routervpn-native.'+policy


def environment(target, *, compiler=False):
    if target not in TARGETS:
        raise ValueError('Unsupported native desktop target')
    system, arch = target.split('/')
    env = os.environ.copy()
    env.update(GOTOOLCHAIN=TOOLCHAIN, GOWORK='off', GOFLAGS='', CGO_ENABLED='1',
               GOOS=system, GOARCH=arch, GOAMD64='v1', GOARM64='v8.0', GOSUMDB='sum.golang.org')
    if system == 'windows':
        cc = shutil.which(('x86_64' if arch == 'amd64' else 'aarch64')+'-w64-mingw32-clang')
        if cc:
            env['CC'] = cc
    elif system == 'darwin' and compiler:
        # Receipt inspection also uses this environment on foreign hosts. Only
        # an actual compilation needs Xcode; metadata-only verification does not.
        xcrun = shutil.which('xcrun', path=env.get('PATH', ''))
        if not xcrun:
            raise ValueError('macOS native compilation requires the selected Xcode macOS SDK')
        env.pop('SDKROOT', None)
        selected = run([xcrun, '--sdk', 'macosx', '--show-sdk-path'], env=env).strip()
        sdk = Path(selected)
        if (not selected or any(c in selected for c in '\r\n\0') or
                not sdk.is_absolute() or not sdk.is_dir() or
                any(not (sdk/'usr/include'/name).is_file()
                    for name in ('stdio.h', 'stdlib.h', 'pthread.h'))):
            raise ValueError('The selected Xcode macOS SDK does not contain its C headers')
        machine = 'x86_64' if arch == 'amd64' else 'arm64'
        flags = ['-target', machine+'-apple-macosx13.0', '-isysroot', str(sdk)]
        # Non-Apple Clang does not infer this SDK from its executable location.
        # Keep the C/C++ compiler and the final external linker on the same SDK.
        env.update(SDKROOT=str(sdk), MACOSX_DEPLOYMENT_TARGET='13.0',
                   CGO_CFLAGS=shlex.join(['-O2', '-g', *flags]),
                   CGO_CXXFLAGS=shlex.join(['-O2', '-g', *flags]),
                   CGO_LDFLAGS=shlex.join(flags))
    return env




def tags(target):
    return TAGS+(('with_purego',) if not target.startswith('darwin/') else ())


def regular(path, maximum):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError('Unsafe or missing native runtime payload: '+str(path))
    return path.read_bytes()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate native runtime receipt key')
        result[key] = value
    return result


def payload(raw):
    return {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def expected_names(target):
    library = library_name(target)
    return set(LICENSES)|{binary_name(target)}|({library} if library else set())|TOR.VERIFY.names(target)|DNSSEC.names(target)


def payload_bound(name, target):
    if name in DNSSEC.names(target):
        return DNSSEC.bound(name, target)
    if name in TOR.VERIFY.names(target):
        return TOR.VERIFY.bound(name, target)
    if name == binary_name(target):
        return MAX_BINARY
    if name == library_name(target):
        return MAX_LIBRARY
    if name == PT_NOTICES:
        return MAX_PT_NOTICES
    if name in LICENSES:
        return MAX_LICENSE
    raise ValueError('Unowned native runtime payload name')


def library_name(target):
    return 'libcronet.dll' if target.startswith('windows/') else 'libcronet.so' if target.startswith('linux/') else ''


def binary_name(target):
    return 'sing-box-routervpn'+('.exe' if target.startswith('windows/') else '')


def pe_dependencies(raw, target):
    """Read bounded ordinary and delay imports without host tools or execution.

    This handles the PE32+ images emitted by our two pinned Windows targets.
    All directory pointers are RVAs; legacy pointer-based delay descriptors are
    rejected. Layout: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    """
    machine = {'windows/amd64': 0x8664, 'windows/arm64': 0xaa64}.get(target)
    if machine is None:
        raise ValueError('PE dependency inspection requires an exact Windows target')

    def bounded(offset, size):
        if offset < 0 or size < 0 or offset+size > len(raw):
            raise ValueError('Truncated Windows native PE structure')
        return raw[offset:offset+size]

    def fields(fmt, offset):
        return struct.unpack(fmt, bounded(offset, struct.calcsize(fmt)))

    if bounded(0, 2) != b'MZ':
        raise ValueError('Windows native payload has no DOS image signature')
    pe, = fields('<I', 0x3c)
    if pe < 64 or bounded(pe, 4) != b'PE\0\0':
        raise ValueError('Windows native payload has no PE image signature')
    actual, count, _, _, _, optional_size, characteristics = fields('<HHIIIHH', pe+4)
    if actual != machine or not characteristics & 2 or not 1 <= count <= 96:
        raise ValueError('Windows native PE target or section count differs')
    optional = pe+24
    bounded(optional, optional_size)
    if optional_size < 112 or fields('<H', optional)[0] != 0x20b:
        raise ValueError('Windows native payload is not a bounded PE32+ image')
    image_size, header_size = fields('<II', optional+56)
    directories, = fields('<I', optional+108)
    section_table = optional+optional_size
    if (not 14 <= directories <= 16 or 112+8*directories > optional_size or
            not section_table+40*count <= header_size <= len(raw) or
            not header_size < image_size <= 0x80000000):
        raise ValueError('Invalid Windows native PE directories or headers')
    sections = []
    for index in range(count):
        virtual_size, address, raw_size, offset = fields('<IIII', section_table+40*index+8)
        extent = max(virtual_size, raw_size)
        if (not extent or address < header_size or address+extent > image_size or
                (raw_size and (offset < header_size or offset+raw_size > len(raw)))):
            raise ValueError('Invalid Windows native PE section bounds')
        for other_address, other_extent, other_offset, other_size in sections:
            if (max(address, other_address) < min(address+extent, other_address+other_extent) or
                    (raw_size and other_size and
                     max(offset, other_offset) < min(offset+raw_size, other_offset+other_size))):
                raise ValueError('Overlapping Windows native PE sections')
        sections.append((address, extent, offset, raw_size))

    def location(rva, size):
        if rva > 0 and rva < header_size and rva+size <= header_size:
            return rva, header_size-rva
        for address, _, offset, raw_size in sections:
            delta = rva-address
            if delta >= 0 and delta+size <= raw_size:
                return offset+delta, raw_size-delta
        raise ValueError('Unmapped Windows native PE dependency RVA')

    def dll_name(rva):
        offset, available = location(rva, 1)
        end = raw.find(b'\0', offset, offset+min(available, 256))
        name = raw[offset:end] if end >= 0 else b''
        if not re.fullmatch(rb'[A-Za-z0-9][A-Za-z0-9_-]*\.dll', name, re.IGNORECASE):
            raise ValueError('Invalid or unterminated Windows native DLL name')
        return name.decode('ascii').lower()

    dependencies = set()
    for directory, record_size in ((1, 20), (13, 32)):
        rva, size = fields('<II', optional+112+8*directory)
        if rva == size == 0:
            continue
        if not rva or not record_size <= size <= 1024*1024:
            raise ValueError('Invalid Windows native PE dependency directory')
        offset, _ = location(rva, size)
        for index in range(min(size//record_size, 257)):
            values = fields('<'+'I'*(record_size//4), offset+index*record_size)
            if not any(values):
                break
            if index == 256:
                raise ValueError('Windows native PE has too many imported DLLs')
            if directory == 13 and values[0] != 1:
                raise ValueError('Unsupported Windows native PE delay-import attributes')
            dependencies.add(dll_name(values[3 if directory == 1 else 1]))
        else:
            raise ValueError('Unterminated Windows native PE dependency directory')
    if not dependencies:
        raise ValueError('Windows native PE dependency directories are missing or stripped')
    return dependencies


def check_windows_dependencies(directory, target):
    # Cronet is loaded explicitly rather than through the engine's import table,
    # so inspect it even when the executable has no import naming that library.
    owned = {library_name(target)}
    inspected = {}
    for name in (binary_name(target), *sorted(owned)):
        raw = regular(directory/name, MAX_BINARY if name == binary_name(target) else MAX_LIBRARY)
        dependencies = pe_dependencies(raw, target)
        for dependency in dependencies:
            api_set = re.fullmatch(r'(?:api|ext)-ms-win-[a-z0-9-]+-l\d+-\d+-\d+\.dll', dependency)
            if dependency not in WINDOWS_SYSTEM_DLLS and not api_set and dependency not in owned:
                raise ValueError('Windows native payload '+name+' imports an unowned DLL: '+dependency)
        inspected[name] = dependencies
    return inspected


def check_target(binary, target, env, metadata_reader=None):
    metadata = (metadata_reader or run)(['go', 'version', '-m', binary], env=env)
    system, arch = target.split('/')
    for value in (TOOLCHAIN, 'GOOS='+system, 'GOARCH='+arch, 'CGO_ENABLED=1',
                  'github.com/amnezia-vpn/amneziawg-go/v3\t'+POLICY.AMNEZIA.VERSION,
                  'github.com/xtls/xray-core\t'+POLICY.XRAY_VERSION):
        if value not in metadata:
            raise ValueError('Native runtime build metadata differs: '+value)
    setting = next((line.strip().removeprefix('build\t-tags=') for line in metadata.splitlines()
                    if line.strip().startswith('build\t-tags=')), '')
    if set(setting.split(',')) != set(tags(target)):
        raise ValueError('Native runtime omitted an exact required transport build tag')
    if system == 'windows':
        check_windows_dependencies(binary.parent, target)


def receipt_fields(target, policy):
    return {'schema_version': 1, 'runtime': 'sing-box-routervpn', 'version': VERSION,
            'upstream_revision': PIN, 'xray_revision': POLICY.XRAY.XRAY_PIN,
            'amnezia_version': POLICY.AMNEZIA.VERSION, 'amnezia_sum': POLICY.AMNEZIA.SUM,
            'rosenpass_revision': PQ.REVISION, 'policy_sha256': policy,
            'target': target, 'toolchain': TOOLCHAIN, 'rust_toolchain': PQ.RUST,
            'native_pq_abi': 1}


def reuse(directory, target, policy=None, env=None, metadata_reader=None):
    if target not in TARGETS or directory.is_symlink() or not directory.is_dir():
        raise ValueError('Invalid native runtime target or directory')
    policy = policy or digest()
    env = env or environment(target)
    names = expected_names(target)
    if {path.name for path in directory.iterdir()} != names|{'NATIVE-RUNTIME.json'}:
        raise ValueError('Native runtime payload set is incomplete or contains unowned files')
    files = {}
    binary = binary_name(target)
    for name in names:
        files[name] = payload(regular(directory/name, payload_bound(name, target)))
    if regular(directory/PT_NOTICES, MAX_PT_NOTICES) != EXTERNAL.desktop_pt_notices():
        raise ValueError('Native PT notices differ from the captured dependency sources')
    receipt = json.loads(regular(directory/'NATIVE-RUNTIME.json', 32768), object_pairs_hook=unique_object)
    expected = {**receipt_fields(target, policy), **files[binary], 'files': files}
    if receipt != expected:
        raise ValueError('Native runtime differs from the exact source, target or payload receipt')
    TOR.VERIFY.verify(directory, target, source_root=ROOT, exact=False)
    if target.startswith('linux/'):
        DNSSEC.verify(directory, target)
    if marker(policy).encode() not in regular(directory/binary, MAX_BINARY):
        raise ValueError('Native runtime source fingerprint is missing')
    check_target(directory/binary, target, env, metadata_reader=metadata_reader)
    return receipt


def checkout(path, repository, revision):
    run(['git', 'init', path])
    # Keep pinned upstream blobs identical on Windows too. The application's
    # attributes do not govern these separate disposable dependency repos.
    run(['git', '-C', path, 'config', 'core.autocrlf', 'false'])
    run(['git', '-C', path, 'config', 'core.eol', 'lf'])
    run(['git', '-C', path, 'remote', 'add', 'origin', repository])
    run(['git', '-C', path, 'fetch', '--depth=1', 'origin', revision])
    run(['git', '-C', path, 'checkout', '--detach', 'FETCH_HEAD'])


def pristine(path, revision):
    if path.is_symlink() or run(['git', '-C', path, 'rev-parse', 'HEAD']) != revision:
        raise ValueError('Native source must be the exact pinned disposable checkout')
    if run(['git', '-C', path, 'status', '--porcelain', '--untracked-files=all']):
        raise ValueError('Native source contains changes not owned by this fresh build')


def module(source, path, env):
    result = json.loads(run(['go', 'list', '-m', '-json', path], cwd=source, env=env))
    if result.get('Path') != path or result.get('Replace') or not result.get('Sum', '').startswith('h1:'):
        raise ValueError('Native library module has no exact checksum-verified source')
    return result


def stage_cronet(source, stage, target, env):
    system, arch = target.split('/')
    info = module(source, 'github.com/sagernet/cronet-go/lib/'+system+'_'+arch, env)
    if info['Version'] != CRONET_VERSION:
        raise ValueError('Native Naive library revision changed')
    directory = Path(info['Dir'])
    (stage/'CRONET-LICENSE').write_bytes(regular(directory/'LICENSE', MAX_LICENSE))
    library = library_name(target)
    if library:
        (stage/library).write_bytes(regular(directory/library, MAX_LIBRARY))


def stage_pq_licenses(stage, env):
    metadata = json.loads(run(['cargo', 'metadata', '--locked', '--format-version=1',
                              '--manifest-path', ROOT/'mobile/rosenpass/Cargo.toml'], env=env))
    packages = [item for item in metadata['packages'] if item['name'] == 'rosenpass'
                and item.get('source', '').endswith('#'+PQ.REVISION)]
    if len(packages) != 1:
        raise ValueError('Pinned Rosenpass license provenance is ambiguous')
    source = Path(packages[0]['manifest_path']).parent.parent
    for name in ('LICENSE-MIT', 'LICENSE-APACHE'):
        (stage/('ROSENPASS-'+name)).write_bytes(regular(source/name, MAX_LICENSE))


def stage_pt_notices(stage):
    raw = EXTERNAL.desktop_pt_notices()
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PT_NOTICES:
        raise ValueError('Native PT notices exceed their exact payload bound')
    path = stage/PT_NOTICES
    if path.exists() or path.is_symlink():
        raise ValueError('Unowned native PT notices in the build stage')
    path.write_bytes(raw)


def prepare_native_sources(source, xray, env):
    POLICY.prepare_native(source, xray, env=env)
    PERFORMANCE.prepare(source)
    OPENVPN.prepare(source)
    EXTERNAL.prepare(source, env=env)
    BUFFERS.prepare(source)
    run(['go', 'mod', 'tidy'], cwd=source, env=env)
    run(['go', 'mod', 'verify'], cwd=source, env=env)
    POLICY.AMNEZIA.verify(source)


def build_awg_smoke_peer(destination, env, source=None):
    """Compile a disposable passive peer; never add a listener to the client."""
    if run(['go', 'env', 'GOVERSION'], env=env) != TOOLCHAIN:
        raise ValueError('Passive AWG smoke requires the exact pinned Go compiler')
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('Unowned passive AWG smoke executable')
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source is None:
        # A reused bundle has no remaining prepared build tree. Reconstruct
        # the same pinned source/module graph, without rebuilding its engine
        # or any native library, rather than silently omitting this protocol.
        source, xray = destination.parent/'core', destination.parent/'xray'
        checkout(source, 'https://github.com/SagerNet/sing-box.git', PIN)
        checkout(xray, 'https://github.com/XTLS/Xray-core.git', POLICY.XRAY.XRAY_PIN)
        pristine(source, PIN)
        pristine(xray, POLICY.XRAY.XRAY_PIN)
        prepare_native_sources(source, xray, env)
    else:
        source = Path(source)
        if source.is_symlink() or run(['git', '-C', source, 'rev-parse', 'HEAD']) != PIN:
            raise ValueError('Passive AWG smoke requires the original prepared core')
    POLICY.AMNEZIA.TIMERS.verify(source, env=env)
    # Reuse the exact production raw-IP adapter, with no copied implementation
    # or dependency on the application's Box/controller import closure.
    adapter = (ROOT/'mobile/amnezia/tun.go.tmpl').read_bytes()
    package = b'package routervpnamnezia\n'
    if not adapter.startswith(package):
        raise ValueError('Native AWG adapter package boundary changed')
    with tempfile.TemporaryDirectory(prefix='routervpn-awg-smoke-', dir=source/'cmd') as generated:
        generated = Path(generated)
        (generated/'tun.go').write_bytes(b'package main\n'+adapter[len(package):])
        (generated/'main.go').write_text(AWG_SMOKE_PEER, encoding='utf-8')
        run(['go', 'build', '-mod=readonly', '-trimpath', '-buildvcs=false',
             '-tags=with_wireguard,with_gvisor', '-ldflags=-s -w -buildid= -checklinkname=0',
             '-o', destination, './cmd/'+generated.name], cwd=source, env=env)
    if not destination.is_file() or destination.is_symlink():
        raise ValueError('Passive AWG smoke executable was not produced')
    return destination


def build_xray_smoke_peer(destination, env):
    """Build the separately executed peer with the shipping server corrections."""
    if run(['go', 'env', 'GOVERSION'], env=env) != TOOLCHAIN:
        raise ValueError('Independent Xray smoke requires the exact pinned Go compiler')
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('Unowned independent Xray smoke executable')
    source = destination.parent/'xray-reference'
    checkout(source, 'https://github.com/XTLS/Xray-core.git', POLICY.XRAY.XRAY_PIN)
    pristine(source, POLICY.XRAY.XRAY_PIN)
    # The shipped server applies these same pinned transport corrections,
    # including FinalMask half-close required by REALITY. Keep both generated
    # masks; a pristine upstream server panics before authentication here.
    # No embedded-client patch or linked native library enters this peer.
    policy = XRAY_SERVER.prepare(source)
    flags = '-s -w -buildid= -checklinkname=0 -X github.com/xtls/xray-core/core.build=routervpn-'+POLICY.XRAY.XRAY_PIN+'.'+policy
    run(['go', 'build', '-mod=readonly', '-trimpath', '-buildvcs=false',
         '-ldflags='+flags, '-o', destination, './main'],
        cwd=source, env={**env, 'CGO_ENABLED': '0'})
    if not destination.is_file() or destination.is_symlink():
        raise ValueError('Independent Xray smoke executable was not produced')
    return destination


def xray_smoke_pq_keys(peer, env):
    output = run([peer, 'vlessenc'], env=env, timeout=10)
    marker = 'Authentication: ML-KEM-768'
    if output.count(marker) != 1:
        raise ValueError('Pinned Xray did not produce its ML-KEM authentication pair')
    keys = {}
    for line in output.split(marker, 1)[1].splitlines():
        if line.startswith(('"decryption":', '"encryption":')):
            keys.update(json.loads('{'+line+'}'))
    if set(keys) != {'decryption', 'encryption'} or not all(
            value.startswith('mlkem768x25519plus.') for value in keys.values()):
        raise ValueError('Pinned Xray generated no exact hybrid-PQ configuration')
    return keys


def pq_smoke_configurations(peer, env, protocol, host, target_port, upstream, proxy, cover):
    """Use the shipping generators' exact PQ/FinalMask settings and real keys."""
    pair = dict(line.split(': ', 1) for line in
                run([peer, 'x25519'], env=env, timeout=10).splitlines() if ': ' in line)
    private, password = pair.get('PrivateKey'), pair.get('Password (PublicKey)', pair.get('Password', pair.get('PublicKey')))
    if not private or not password:
        raise ValueError('Pinned Xray generated no REALITY authentication pair')
    keys = xray_smoke_pq_keys(peer, env)
    identity = run([peer, 'uuid'], env=env, timeout=10)
    if str(uuid.UUID(identity)) != identity:
        raise ValueError('Pinned Xray generated an invalid identity')
    short = os.urandom(8).hex()

    def generator(name):
        path = ROOT/'server/scripts'/name
        bodies = re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)", path.read_text(encoding='utf-8'), re.S)
        if len(bodies) != 1:
            raise ValueError('Native smoke lost the original generator boundary')
        return path, ast.parse(bodies[0], filename=str(path))

    path, tree = generator('generate-xray-pq.sh')
    definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name in ('reality', 'inbound', 'client_xray')]
    if {node.name for node in definitions} != {'reality', 'inbound', 'client_xray'} or len(definitions) != 3:
        raise ValueError('Native smoke lost the original PQ generator functions')
    scope = dict(target='localhost', tport=cover, rpriv=private, rpass=password, endpoint=host)
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(path), 'exec'), scope)
    inbound = scope['inbound']('pq-reality-in', upstream, identity, keys['decryption'], short, 'smoke')
    client = scope['client_xray'](identity, upstream, keys['encryption'], short, proxy, 'xtls-rprx-vision')
    server = {'inbounds': [inbound], 'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}
    if protocol == 'reality-xhttp':
        path, tree = generator('generate-advanced-profiles.sh')
        assignments = [node for node in tree.body if isinstance(node, ast.Assign) and
                       any(isinstance(target, ast.Name) and target.id in ('finalmask', 'outer_xray') for target in node.targets)]
        additions = [node for node in tree.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                     and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'append'
                     and any(isinstance(value, ast.Constant) and value.value == 'max-xhttp-in' for value in ast.walk(node))]
        if len(assignments) != 2 or len(additions) != 1:
            raise ValueError('Native smoke lost the original XHTTP generator settings')
        scope.update(server=server, uuid=identity, server_dec=keys['decryption'], client_enc=keys['encryption'],
                     xp=upstream, tp=cover, rpub=password, shortid=short, path='/'+os.urandom(16).hex())
        selected = sorted([*assignments, *additions], key=lambda node: node.lineno)
        exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), 'exec'), scope)
        inbound = server['inbounds'][-1]
        server['inbounds'] = [inbound]
        client = scope['outer_xray']
        client['inbounds'][0]['port'] = proxy
    # The SNI remains localhost. Only the fixture's literal bind/cover target
    # changes; the cover can never return the destination's unpredictable body.
    inbound['listen'] = host
    inbound['streamSettings']['realitySettings']['target'] = '127.0.0.1:'+str(cover)
    # The reference peer keeps the pinned private-target policy. Only this
    # fixture's exact TCP destination is admitted; every other target is denied.
    server['outbounds'][0]['settings'] = {'finalRules': [
        {'action': 'allow', 'network': 'tcp', 'ip': [host+'/32'], 'port': str(target_port)},
        {'action': 'block'}]}
    server['log'] = {'loglevel': 'error'}
    return server, client


AWG_SMOKE_PEER = r'''package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	awg "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	wg "github.com/sagernet/sing-box/transport/wireguard"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The default UDP bind batches packets on Linux. The shipping protected
// bind and its raw stack reader each use one packet; preserve that reader
// contract while permitting the genuine passive peer to use batched UDP.
type passiveTun struct { *nativeTun }
func (t *passiveTun) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	if len(buffers) == 0 || len(sizes) == 0 { return 0, errors.New("invalid passive TUN read") }
	return t.nativeTun.Read(buffers[:1], sizes[:1], offset)
}

type peerConfig struct {
	PrivateKey string `json:"private_key"`
	ClientKey string `json:"client_key"`
	ListenPort int `json:"listen_port"`
	Target string `json:"target"`
	Parameters map[string]string `json:"parameters"`
}

type targetHandler struct {
	ctx context.Context
	target netip.AddrPort
	mu sync.Mutex
	closed bool
	flows map[net.Conn]struct{}
	workers sync.WaitGroup
}

func (h *targetHandler) JudgeFlow(network uint8, _, target netip.AddrPort, _ []byte) tun.FlowVerdict {
	if network == 6 && target == h.target { return tun.FlowVerdict{Action: tun.ActionAccept} }
	return tun.FlowVerdict{Action: tun.ActionDrop}
}
func (*targetHandler) NewDNSPacket([]byte, M.Socksaddr, M.Socksaddr, N.PacketWriter) {}
func (*targetHandler) NewPacketConnectionEx(_ context.Context, c N.PacketConn, _, _ M.Socksaddr, closed N.CloseHandlerFunc) {
	_ = c.Close()
	if closed != nil { closed(net.ErrClosed) }
}
func (h *targetHandler) NewConnectionEx(_ context.Context, c net.Conn, _, target M.Socksaddr, closed N.CloseHandlerFunc) {
	defer c.Close()
	if closed != nil { defer closed(nil) }
	h.mu.Lock()
	if h.closed || target.String() != h.target.String() { h.mu.Unlock(); return }
	h.workers.Add(1)
	h.flows[c] = struct{}{}
	h.mu.Unlock()
	defer h.workers.Done()
	var upstream net.Conn
	defer func() {
		h.mu.Lock()
		delete(h.flows, c)
		if upstream != nil { delete(h.flows, upstream) }
		h.mu.Unlock()
	}()
	var err error
	upstream, err = (&net.Dialer{Timeout: 3*time.Second}).DialContext(h.ctx, "tcp", h.target.String())
	if upstream != nil { defer upstream.Close() }
	if err != nil || upstream == nil { return }
	h.mu.Lock()
	if h.closed { h.mu.Unlock(); return }
	h.flows[upstream] = struct{}{}
	h.mu.Unlock()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, c); _ = upstream.Close(); close(done) }()
	_, _ = io.Copy(c, upstream)
	_ = c.Close()
	_ = upstream.Close()
	<-done
}
func (h *targetHandler) close() {
	h.mu.Lock()
	h.closed = true
	flows := make([]net.Conn, 0, len(h.flows))
	for c := range h.flows { flows = append(flows, c) }
	h.mu.Unlock()
	for _, c := range flows { _ = c.Close() }
	h.workers.Wait()
}

func peer() error {
	if len(os.Args) != 2 { return errors.New("missing private smoke configuration") }
	raw, err := os.ReadFile(os.Args[1])
	if err != nil || len(raw) > 4096 { return errors.New("invalid private smoke configuration") }
	var config peerConfig
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF ||
		config.ListenPort < 1 || config.ListenPort > 65535 || len(config.Parameters) != 11 {
		return errors.New("invalid private smoke configuration")
	}
	private, err := base64.StdEncoding.DecodeString(config.PrivateKey)
	if err != nil || len(private) != 32 { return errors.New("invalid smoke key") }
	public, err := base64.StdEncoding.DecodeString(config.ClientKey)
	if err != nil || len(public) != 32 { return errors.New("invalid smoke key") }
	target, err := netip.ParseAddrPort(config.Target)
	if err != nil || !target.Addr().Is4() || (!target.Addr().IsGlobalUnicast() && !target.Addr().IsLinkLocalUnicast()) || target.Port() == 0 {
		return errors.New("invalid smoke target")
	}
	var parameters strings.Builder
	for _, key := range []string{"jc","jmin","jmax","s1","s2","s3","s4","h1","h2","h3","h4"} {
		value := config.Parameters[key]
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != value { return errors.New("invalid smoke padding") }
		fmt.Fprintf(&parameters, "%s=%s\n", key, value)
	}
	padding, err := strconv.Atoi(config.Parameters["s4"])
	if err != nil || padding > 1280 { return errors.New("invalid smoke padding") }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handler := &targetHandler{ctx: ctx, target: target, flows: make(map[net.Conn]struct{})}
	stack, err := wg.NewDevice(wg.DeviceOptions{Context: ctx, Logger: logger.NOP(), System: false,
		Handler: handler, UDPTimeout: 30*time.Second, ICMPTimeout: 30*time.Second,
		Name: "routervpn-passive-awg-smoke", MTU: 1280,
		Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")},
		AllowedAddress: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}})
	if err != nil { return errors.New("passive smoke stack failed") }
	wrapped := wrapTun(stack)
	device := awg.NewDevice(&passiveTun{wrapped}, awgconn.NewDefaultBind(), &awg.Logger{Verbosef: func(string,...any){}, Errorf: func(string,...any){}})
	defer func() { cancel(); handler.close(); device.Close() }()
	// A genuine passive peer has no endpoint and no periodic initiation.
	ipc := fmt.Sprintf("private_key=%x\nlisten_port=%d\n%sreplace_peers=true\npublic_key=%x\nallowed_ip=198.18.0.2/32\n",
		private, config.ListenPort, parameters.String(), public)
	if device.IpcSet(ipc) != nil || wrapped.configuredPadding(padding) != nil || stack.Start() != nil || device.Up() != nil {
		return errors.New("passive smoke peer failed")
	}
	fmt.Println("Passive AWG smoke peer ready")
	eof := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); close(eof) }()
	select {
	case <-eof:
		return nil
	case <-ctx.Done():
		// A Windows pipe read need not be interruptible by closing this handle.
		// The failed helper exits after native cleanup; the parent joins it.
		return errors.New("passive smoke peer lifetime expired")
	}
}


func cover() (result error) {
	if len(os.Args) != 5 { return errors.New("invalid smoke cover arguments") }
	address, err := netip.ParseAddrPort(os.Args[2])
	if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 { return errors.New("invalid smoke cover bind") }
	certificate, err := tls.LoadX509KeyPair(os.Args[3], os.Args[4])
	if err != nil { return errors.New("invalid smoke cover certificate") }
	pem, err := os.ReadFile(os.Args[3])
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(pem) { return errors.New("invalid smoke cover trust") }
	listener, err := net.Listen("tcp", address.String())
	if err != nil { return errors.New("smoke cover could not listen") }
	const body = "routervpn-smoke-cover"
	server := &http.Server{
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}},
		ReadHeaderTimeout: 3*time.Second, ReadTimeout: 3*time.Second, WriteTimeout: 3*time.Second, IdleTimeout: 3*time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = io.WriteString(w, body)
		}),
	}
	done := make(chan struct{})
	var serving error
	go func() { serving = server.ServeTLS(listener, "", ""); close(done) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		result = errors.Join(result, server.Shutdown(ctx))
		_ = server.Close()
		_ = listener.Close()
		<-done
		if !errors.Is(serving, http.ErrServerClosed) { result = errors.Join(result, serving) }
	}()
	// REALITY XHTTP always selects HTTP/2. Exercise the actual cover with h2
	// before readiness, instead of advertising h2 on an HTTP/1-only server.
	transport := &http.Transport{ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 3*time.Second}).Get("https://"+address.String()+"/")
	if err != nil { return errors.New("smoke cover HTTP2 handshake failed") }
	received, readErr := io.ReadAll(io.LimitReader(response.Body, 128))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.ProtoMajor != 2 || response.StatusCode != 200 || string(received) != body {
		return errors.New("smoke cover did not serve its exact HTTP2 body")
	}
	transport.CloseIdleConnections()
	input := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); close(input) }()
	fmt.Println("Native HTTP2 smoke cover ready")
	deadline := time.NewTimer(90*time.Second)
	defer deadline.Stop()
	select {
	case <-input:
		return nil
	case <-deadline.C:
		return errors.New("smoke cover ownership deadline expired")
	case <-done:
		return errors.New("smoke cover stopped before retirement")
	}
}

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "cover" { err = cover() } else { err = peer() }
	if err != nil {
		// Never emit peer-supplied IPC errors or credentials.
		fmt.Fprintln(os.Stderr, "Native smoke helper failed:", err)
		os.Exit(1)
	}
}
'''



def smoke_protocols(binary, env, *, source=None):
    """Exercise the built host engine locally, without host routes or TUN.

    One actual HTTPS exchange traverses each selected proxy. Stopping its
    server must make a fresh exchange fail while the target remains reachable.
    This is protocol data-plane evidence, not device VPN or kernel leak proof.
    """
    with tempfile.TemporaryDirectory(prefix='routervpn-protocol-smoke-') as directory:
        work = Path(directory)
        certificate, key = work/'certificate.pem', work/'key.pem'
        certificate_config = work/'certificate.cnf'
        certificate_config.write_text('[req]\ndistinguished_name=subject\nprompt=no\nx509_extensions=server\n'
                                      '[subject]\nCN=localhost\n[server]\nsubjectAltName=DNS:localhost,DNS:routervpn-smoke.invalid\n'
                                      'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyCertSign\n'
                                      'extendedKeyUsage=serverAuth\n', encoding='ascii')
        run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
             '-nodes', '-sha256', '-keyout', key, '-out', certificate, '-days', '1',
             '-config', certificate_config], env=env, timeout=20)
        key.chmod(0o600)
        token = os.urandom(32)
        target_events = deque(maxlen=32)
        awg_peer = build_awg_smoke_peer(work/'peer'/('passive-awg.exe' if os.name == 'nt' else 'passive-awg'), env, source)
        xray_peer = build_xray_smoke_peer(work/'peer'/('reference-xray.exe' if os.name == 'nt' else 'reference-xray'), env)
        print('Independent Xray smoke peer: '+POLICY.XRAY.XRAY_PIN+' server-policy '+XRAY_SERVER.digest()+' SHA256 '+hashlib.sha256(xray_peer.read_bytes()).hexdigest(), flush=True)

        class Target(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                target_events.append((time.monotonic(), 'get'))
                body = token + self.path.encode('ascii')
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                target_events.append((time.monotonic(), 'response_written'))

            def log_message(self, *_args):
                pass

        class TargetServer(http.server.ThreadingHTTPServer):
            daemon_threads = False

            def get_request(self):
                stream, address = super().get_request()
                target_events.append((time.monotonic(), 'accept'))
                stream.settimeout(3)
                return stream, address

            def finish_request(self, stream, address):
                # An abandoned native startup connection must not hold the
                # accept loop while later exchanges spend their TLS budget.
                try:
                    secured = server_tls.wrap_socket(stream, server_side=True)
                except OSError:
                    target_events.append((time.monotonic(), 'tls_failed'))
                    return
                with secured:
                    target_events.append((time.monotonic(), 'tls_complete'))
                    super().finish_request(secured, address)

        # Userspace VPN stacks reject inner loopback packets. Find this host's
        # routed address without sending a datagram; the target stays on this
        # host, and the exact same address remains reachable by the control.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
            route.connect(('192.0.2.1', 9))
            target_host = route.getsockname()[0]
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(certificate, key)
        def start_target(listen_port=0):
            server = TargetServer((target_host, listen_port), Target)
            thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
            thread.start()
            return server, thread, server.server_address[1]

        def close_target(server, thread):
            server.shutdown(); server.server_close(); thread.join(timeout=5)
            if thread.is_alive():
                raise RuntimeError('Native protocol target did not stop')

        target, worker, target_port = start_target()
        client_tls = ssl.create_default_context(cafile=str(certificate))

        def exact(stream, count):
            value = b''
            while len(value) < count:
                part = stream.recv(count-len(value))
                if not part:
                    raise ConnectionError('Native proxy closed its response')
                value += part
            return value

        def exchange(proxy_port=None):
            nonlocal client_stage
            client_stage = 'tcp_connect'
            with socket.create_connection(('127.0.0.1' if proxy_port is not None else target_host, proxy_port or target_port), timeout=3) as stream:
                if proxy_port is not None:
                    client_stage = 'socks_greeting'
                    stream.sendall(b'\x05\x01\x00')
                    if exact(stream, 2) != b'\x05\x00':
                        raise ConnectionError('Native SOCKS negotiation failed')
                    client_stage = 'socks_connect'
                    stream.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(target_host)+struct.pack('!H', target_port))
                    reply = exact(stream, 4)
                    if reply[:3] != b'\x05\x00\x00' or reply[3] not in (1, 3, 4):
                        raise ConnectionError('Selected native protocol did not connect')
                    exact(stream, (4 if reply[3] == 1 else 16 if reply[3] == 4 else exact(stream, 1)[0])+2)
                client_stage = 'tls_handshake'
                with client_tls.wrap_socket(stream, server_hostname='localhost') as secured:
                    path = '/'+os.urandom(16).hex()
                    client_stage = 'request_write'
                    secured.sendall(('GET '+path+' HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n').encode('ascii'))
                    client_stage = 'response_headers'
                    response = http.client.HTTPResponse(secured)
                    response.begin()
                    client_stage = 'response_validation'
                    if response.status != 200 or response.read(4096) != token+path.encode('ascii'):
                        raise ValueError('Native protocol returned a different target or payload')
                    client_stage = 'verified'

        allocated_ports = {target_port}

        def port(*kinds, address='127.0.0.1', dual_stack=False):
            # A TCP-only probe does not exclude Windows' UDP reservations.
            # Hold every required socket until the same port is verified for
            # the listener's complete transport/address set, without reuse.
            kinds = kinds or (socket.SOCK_STREAM,)
            bindings = [(socket.AF_INET, address)]
            if dual_stack and socket.has_ipv6:
                bindings.append((socket.AF_INET6, '::'))
            last_error = None
            for _ in range(32):
                reservations, selected = [], 0
                try:
                    for family, host in bindings:
                        for kind in kinds:
                            try:
                                reservation = socket.socket(family, kind)
                                reservations.append(reservation)
                                if family == socket.AF_INET6:
                                    reservation.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                                if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                                    reservation.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                                reservation.bind((host, selected))
                                selected = reservation.getsockname()[1]
                            except OSError as error:
                                # The pinned WG/AWG bind also permits an absent
                                # IPv6 family, while requiring its IPv4 listener.
                                if family == socket.AF_INET6 and (error.errno == errno.EAFNOSUPPORT or getattr(error, 'winerror', None) == 10047):
                                    continue
                                raise
                    if selected not in allocated_ports:
                        allocated_ports.add(selected)
                        return selected
                except OSError as error:
                    if error.errno not in (errno.EACCES, errno.EADDRINUSE) and getattr(error, 'winerror', None) not in (10013, 10048):
                        raise
                    last_error = error
                finally:
                    for reservation in reservations:
                        reservation.close()
            raise RuntimeError('No distinct native smoke listener port after 32 allocation attempts') from last_error

        def stop(process, *, clean=False):
            if process.stdin is not None:
                process.stdin.close()
            if process.poll() is None:
                if process.stdin is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if clean and process.returncode != 0:
                raise RuntimeError('Native smoke helper did not retire cleanly')

        try:
            for protocol in ('socks', 'http', 'https', 'shadowsocks', 'hysteria2', 'naive-h2', 'naive-h3', 'wireguard', 'openvpn-tcp', 'openvpn-udp', 'amneziawg', 'reality-vision', 'reality-pq-vision', 'reality-xhttp'):
                udp = protocol in ('hysteria2', 'naive-h3', 'wireguard', 'openvpn-udp', 'amneziawg')
                wildcard = protocol in ('wireguard', 'amneziawg')
                upstream_kinds = (socket.SOCK_DGRAM, socket.SOCK_STREAM) if protocol == 'shadowsocks' else (socket.SOCK_DGRAM if udp else socket.SOCK_STREAM,)
                upstream_host = '0.0.0.0' if wildcard else target_host if protocol.startswith('reality-') else '127.0.0.1'
                upstream_port, proxy_port = port(*upstream_kinds, address=upstream_host, dual_stack=wildcard), port()
                pq_case = protocol in ('reality-pq-vision', 'reality-xhttp')
                cover_port = port() if pq_case else None
                kind = 'http' if protocol == 'https' else 'naive' if protocol in ('naive-h2', 'naive-h3') else protocol
                inbound = {'type': kind, 'listen': '127.0.0.1', 'listen_port': upstream_port}
                outbound = {'type': kind, 'tag': 'selected', 'server': '127.0.0.1', 'server_port': upstream_port}
                password = base64.b64encode(os.urandom(32)).decode('ascii')
                if protocol in ('socks', 'http', 'https'):
                    inbound['users'] = [{'username': 'smoke', 'password': password}]
                    outbound.update(username='smoke', password=password)
                elif protocol in ('naive-h2', 'naive-h3'):
                    # The H3 peer has no TCP listener, so an H2 fallback cannot
                    # satisfy its payload proof. Both use original TLS trust.
                    inbound.update(network='udp' if protocol == 'naive-h3' else 'tcp',
                                   users=[{'username': 'smoke', 'password': password}])
                    outbound.update(username='smoke', password=password, quic=protocol == 'naive-h3',
                                    udp_over_tcp={'enabled': True, 'version': 2})
                elif protocol == 'shadowsocks':
                    inbound.update(method='2022-blake3-aes-256-gcm', password=password)
                    outbound.update(method=inbound['method'], password=password)
                elif protocol == 'hysteria2':
                    inbound['users'] = [{'name': 'smoke', 'password': password}]
                    outbound['password'] = password
                    inbound['obfs'] = outbound['obfs'] = {'type': 'salamander', 'password': password}
                if protocol in ('https', 'hysteria2', 'naive-h2', 'naive-h3'):
                    inbound['tls'] = {'enabled': True, 'certificate_path': str(certificate), 'key_path': str(key)}
                    # Chromium treats localhost specially. An ordinary DNS name
                    # keeps Naive's TLS identity distinct from its captured IP.
                    peer_name = 'routervpn-smoke.invalid' if kind == 'naive' else 'localhost'
                    outbound['tls'] = {'enabled': True, 'server_name': peer_name, 'certificate_path': str(certificate)}
                configurations = (
                    {'inbounds': [inbound], 'outbounds': [{'type': 'direct', 'tag': 'target'}], 'route': {'final': 'target'}},
                    {'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': proxy_port}], 'outbounds': [outbound], 'route': {'final': 'selected'}},
                )
                if protocol in ('wireguard', 'amneziawg'):
                    pairs = [dict(line.split(': ', 1) for line in run([binary, 'generate', 'wg-keypair'], env=env, timeout=10).splitlines()) for _ in range(2)]
                    for index, configuration in enumerate(configurations):
                        peer = {'public_key': pairs[1-index]['PublicKey'], 'allowed_ips': ['0.0.0.0/0', '::/0']}
                        endpoint = {'type': 'wireguard' if protocol == 'wireguard' else 'routervpn-amneziawg',
                                    'tag': 'server' if index == 0 else 'selected', 'system': False,
                                    'mtu': 1280, 'address': ['198.18.0.'+str(index+1)+'/32'],
                                    'private_key': pairs[index]['PrivateKey'], 'peers': [peer]}
                        if protocol == 'amneziawg':
                            peer.update(address=target_host, port=upstream_port, persistent_keepalive_interval=1)
                            endpoint['amnezia'] = {'jc': '2', 'jmin': '32', 'jmax': '64', 's1': '16', 's2': '32',
                                                   's3': '16', 's4': '16', 'h1': '101', 'h2': '102', 'h3': '103', 'h4': '104'}
                        elif index == 0:
                            endpoint['listen_port'] = upstream_port
                        else:
                            peer.update(address='127.0.0.1', port=upstream_port)
                        configuration.pop('inbounds' if index == 0 else 'outbounds')
                        configuration['endpoints'] = [endpoint]
                    if protocol == 'amneziawg':
                        configurations = ({'private_key': pairs[0]['PrivateKey'], 'client_key': pairs[1]['PublicKey'],
                            'listen_port': upstream_port, 'target': target_host+':'+str(target_port),
                            'parameters': configurations[1]['endpoints'][0]['amnezia']}, configurations[1])
                elif protocol.startswith('openvpn-'):
                    shared = {'system': False, 'mtu': 1280, 'network': protocol[8:], 'data_ciphers': ['AES-256-GCM']}
                    configurations[0]['endpoints'] = [{**shared, 'type': 'openvpn-server', 'tag': 'server',
                        'listen': '127.0.0.1', 'listen_port': upstream_port, 'address': ['198.18.0.1/24'], 'topology': 'subnet',
                        'users': [{'username': 'smoke', 'password': password}], 'tls': {
                            'certificate_path': str(certificate), 'key_path': str(key), 'verify_client_certificate': 'none'}}]
                    configurations[1]['endpoints'] = [{**shared, 'type': 'openvpn-client', 'tag': 'selected',
                        'server': '127.0.0.1', 'server_port': upstream_port, 'username': 'smoke', 'password': password,
                        'tls': {'certificate_path': str(certificate), 'server_name': 'localhost', 'remote_certificate_tls': 'server'}}]
                    configurations[0].pop('inbounds')
                    configurations[1].pop('outbounds')
                elif protocol == 'reality-vision':
                    pair = dict(line.split(': ', 1) for line in run([binary, 'generate', 'reality-keypair'], env=env, timeout=10).splitlines())
                    identity, short_id, flow = str(uuid.uuid4()), os.urandom(8).hex(), 'xtls-rprx-vision'
                    inbound.update(type='vless', listen=target_host, users=[{'name': 'smoke', 'uuid': identity, 'flow': flow}],
                                   tls={'enabled': True, 'server_name': 'localhost', 'reality': {'enabled': True,
                                        'handshake': {'server': target_host, 'server_port': target_port},
                                        'private_key': pair['PrivateKey'], 'short_id': [short_id]}})
                    xray = {'inbounds': [{'listen': '127.0.0.1', 'port': proxy_port, 'protocol': 'socks',
                                         'settings': {'auth': 'noauth', 'udp': True}}],
                            'outbounds': [{'tag': 'proxy', 'protocol': 'vless', 'settings': {'vnext': [{
                                'address': target_host, 'port': upstream_port,
                                'users': [{'id': identity, 'flow': flow, 'encryption': 'none'}]}]},
                                'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {
                                    'serverName': 'localhost', 'fingerprint': 'chrome',
                                    'publicKey': pair['PublicKey'], 'shortId': short_id}}}]}
                    configurations[1]['outbounds'] = [{'type': 'routervpn-xray', 'tag': 'selected',
                                                      'mode': protocol, 'config_json': json.dumps(xray)}]
                elif pq_case:
                    server, xray = pq_smoke_configurations(xray_peer, env, protocol, target_host, target_port, upstream_port, proxy_port, cover_port)
                    configurations = (server, configurations[1])
                    configurations[1]['outbounds'] = [{'type': 'routervpn-xray', 'tag': 'selected',
                                                      'mode': protocol, 'config_json': json.dumps(xray)}]
                processes, logs, log_paths = [], [], []
                cover_process, completed = None, False
                started = time.monotonic()
                phase, client_stage = 'startup', 'not_started'
                failures = Counter()

                def ready(process, path, marker, deadline):
                    while marker not in path.read_bytes().splitlines():
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError('Native '+protocol+' helper did not become ready')
                        time.sleep(0.01)
                    if process.poll() is not None:
                        raise RuntimeError('Native '+protocol+' helper exited after its readiness marker')

                def launch(role, configuration):
                    config_path, log_path = work/(protocol+'-'+role+'.json'), work/(protocol+'-'+role+'.log')
                    passive = protocol == 'amneziawg' and role == 'server'
                    reference = pq_case and role == 'server'
                    if not passive:
                        configuration['log'] = {'loglevel': 'error'} if reference else {'level': 'error', 'timestamp': False}
                    config_path.write_text(json.dumps(configuration), encoding='utf-8')
                    config_path.chmod(0o600)
                    log = log_path.open('wb'); logs.append(log); log_paths.append(log_path)
                    command = [str(awg_peer), str(config_path)] if passive else [str(xray_peer if reference else binary), 'run', '-c', str(config_path)]
                    process = subprocess.Popen(command, env=env, stdin=subprocess.PIPE if passive else None, stdout=log, stderr=log)
                    processes.append(process)
                    if passive:
                        # Readiness is charged to the same startup budget.
                        ready(process, log_path, b'Passive AWG smoke peer ready', deadline)
                    return process

                def check_processes():
                    for process in (*processes, *((cover_process,) if cover_process is not None else ())):
                        status = process.poll()
                        if status is not None:
                            raise RuntimeError('Native '+protocol+' process exited during '+phase+' with status '+str(status))

                def await_payload(deadline):
                    while True:
                        check_processes()
                        try:
                            exchange(proxy_port)
                            check_processes()
                            return
                        except (OSError, http.client.HTTPException):
                            # Preserve a dead peer's first cause rather than
                            # timing out with its client's last refused socket.
                            check_processes()
                            failures[client_stage] += 1
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.05)

                def refused(reason):
                    try:
                        exchange(proxy_port)
                    except (OSError, http.client.HTTPException):
                        return
                    raise RuntimeError('Native '+protocol+' accepted traffic '+reason)

                try:
                    deadline = time.monotonic()+15
                    if pq_case:
                        path = work/(protocol+'-cover.log')
                        log = path.open('wb'); logs.append(log); log_paths.append(path)
                        cover_process = subprocess.Popen([str(awg_peer), 'cover', '127.0.0.1:'+str(cover_port), str(certificate), str(key)],
                                                         env=env, stdin=subprocess.PIPE, stdout=log, stderr=log)
                        ready(cover_process, path, b'Native HTTP2 smoke cover ready', deadline)
                    for role, configuration in zip(('server', 'client'), configurations):
                        launch(role, configuration)
                    phase = 'positive'
                    await_payload(deadline)
                    if pq_case:
                        # Each invalid credential reaches a live native SOCKS
                        # listener. Independent ML-KEM credentials keep the UUID
                        # and REALITY trust valid, ruling out a silent PQ bypass.
                        for credential in ('uuid', 'mlkem'):
                            phase = 'wrong_'+credential
                            stop(processes[-1]); processes.pop()
                            wrong = json.loads(json.dumps(configurations[1]))
                            config = json.loads(wrong['outbounds'][0]['config_json'])
                            user = config['outbounds'][0]['settings']['vnext'][0]['users'][0]
                            if credential == 'uuid':
                                user['id'] = str(uuid.uuid4())
                            else:
                                encryption = xray_smoke_pq_keys(xray_peer, env)['encryption']
                                if encryption == user['encryption']:
                                    raise ValueError('Independent ML-KEM key generation repeated its credential')
                                user['encryption'] = encryption
                            wrong['outbounds'][0]['config_json'] = json.dumps(config)
                            invalid = launch('client-invalid-'+credential, wrong)
                            deadline = time.monotonic()+15
                            while True:
                                if invalid.poll() is not None:
                                    raise RuntimeError('Invalid-credential native client did not start')
                                try:
                                    with socket.create_connection(('127.0.0.1', proxy_port), timeout=3) as stream:
                                        stream.sendall(bytes((5, 1, 0)))
                                        if exact(stream, 2) != bytes((5, 0)):
                                            raise ValueError('Invalid-credential client has no native SOCKS ingress')
                                    break
                                except OSError:
                                    if time.monotonic() >= deadline:
                                        raise
                                    time.sleep(0.05)
                            refused('with the wrong generated '+credential+' credential')
                            if any(process.poll() is not None for process in processes):
                                raise RuntimeError('Native PQ peer exited instead of refusing its wrong credential')
                        stop(processes[-1]); processes.pop()
                        phase = 'restored_credential'
                        launch('client-restored', configurations[1])
                        await_payload(time.monotonic()+15)
                        phase = 'stopped_destination'
                        close_target(target, worker); target = None
                        refused('after its actual HTTPS destination stopped')
                        if any(process.poll() is not None for process in processes):
                            raise RuntimeError('Native PQ peer exited when the destination stopped')
                        phase = 'restored_destination'
                        target, worker, target_port = start_target(target_port)
                        await_payload(time.monotonic()+15)
                    phase = 'stopped_upstream'
                    stop(processes[0], clean=protocol == 'amneziawg')
                    refused('after its selected upstream stopped')
                    if processes[1].poll() is not None:
                        raise RuntimeError('Native client exited during upstream failure')
                    phase = 'direct_control'
                    exchange()
                    detail = '; wrong UUID and independent ML-KEM credential refused; stopped destination refused' if pq_case else ''
                    print('Native protocol traffic: '+protocol+' HTTPS payload passed; stopped upstream refused; direct control alive'+detail, flush=True)
                    completed = True
                except Exception:
                    diagnostic = {'protocol': protocol, 'phase': phase, 'client_stage': client_stage,
                                  'elapsed_ms': round((time.monotonic()-started)*1000),
                                  'positive_failures_by_stage': failures,
                                  'recent_target_events_ms': [(round((when-started)*1000), event)
                                                              for when, event in target_events.copy() if when >= started],
                                  'peer_kind': 'passive-awg' if protocol == 'amneziawg' else 'pinned-xray' if pq_case else 'project-native'}
                    print('Native protocol traffic diagnostic: '+json.dumps(diagnostic, sort_keys=True), file=sys.stderr)
                    for path in log_paths:
                        if path.exists():
                            sys.stderr.write(path.read_bytes()[-8192:].decode('utf-8', errors='replace'))
                    raise
                finally:
                    try:
                        for process in reversed(processes):
                            stop(process)
                        if cover_process is not None:
                            stop(cover_process, clean=completed)
                    finally:
                        for log in logs:
                            log.close()
        finally:
            if target is not None:
                close_target(target, worker)


def build(target, destination, *, source=None, xray=None, pq=None, cache=None, tor_compiled=None, dnssec_compiled=None):
    env, policy = environment(target, compiler=True), digest()
    host = ('darwin' if platform.system() == 'Darwin' else platform.system().lower())+'/'+{
        'x86_64': 'amd64', 'AMD64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64', 'ARM64': 'arm64'}.get(platform.machine(), '')
    if target.startswith('windows/'):
        env = GO_SOCKETS.environment(env=env)
    native_acceptance = env.get('ROUTERVPN_DARWIN_NATIVE_HOST_ACCEPTANCE', '')
    if native_acceptance not in ('', '1'):
        raise ValueError('Unknown explicit Darwin native acceptance selection')
    if native_acceptance == '1':
        host = 'darwin/'+{'x86_64': 'amd64', 'arm64': 'arm64'}.get(platform.machine(), '')
        if platform.system() != 'Darwin' or target != host:
            raise ValueError('Explicit Darwin native acceptance cannot target another build host')
    destination = Path(destination).absolute()
    if destination.is_symlink():
        raise ValueError('Refusing a linked native runtime destination')
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and any(destination.iterdir()):
        reuse(destination, target, policy, env)
        if target == host:
            smoke_protocols(destination/binary_name(target), env)
        print('Reused verified complete native runtime '+target, flush=True)
        return destination
    if run(['go', 'env', 'GOVERSION'], env=env) != TOOLCHAIN:
        raise ValueError('Incorrect pinned native Go compiler')
    with tempfile.TemporaryDirectory(prefix='.routervpn-native-', dir=destination.parent) as temp:
        temp = Path(temp)
        if source is None:
            source = temp/'core'
            checkout(source, 'https://github.com/SagerNet/sing-box.git', PIN)
        if xray is None:
            xray = temp/'xray'
            checkout(xray, 'https://github.com/XTLS/Xray-core.git', POLICY.XRAY.XRAY_PIN)
        source, xray = Path(source).resolve(), Path(xray).resolve()
        pristine(source, PIN)
        pristine(xray, POLICY.XRAY.XRAY_PIN)
        if pq is None:
            pq = temp/'pq'
            PQ.build(target, pq, cache or ROOT/'dist/.native-pq-cache')
        pq = Path(pq).absolute()
        pq_receipt = PQ.verify(pq, target)
        prepare_native_sources(source, xray, env)
        # Only the verified build-owned archive and rustc's bounded native
        # dependency names enter the linker command. No user profile does.
        platform_flags = shlex.split(env['CGO_LDFLAGS']) if target.startswith('darwin/') else []
        if target.startswith('windows/'):
            # LLVM-MinGW also ships libunwind.dll.a. Select its static compiler
            # runtime so the delivered engine cannot depend on the build PATH.
            platform_flags.append('-static')
        env['CGO_LDFLAGS'] = shlex.join([*platform_flags, '-L'+str(pq), *pq_receipt['native_static_libs']])
        stage = temp/'bundle'
        stage.mkdir()
        binary = stage/binary_name(target)
        stage_cronet(source, stage, target, env)
        if target.startswith('linux/'):
            validator = DNSSEC.build(target, temp/'dnssec-bundle', compiled=dnssec_compiled, env=env)
            for name in DNSSEC.names(target):
                shutil.copyfile(validator/name, stage/name)
        ldflags = '-s -w -buildid= -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version='+marker(policy)
        if target.startswith('linux/'):
            validator_library = payload(regular(stage/DNSSEC.LIBRARY, DNSSEC.bound(DNSSEC.LIBRARY, target)))
            ldflags += ' -X main.routerVPNDNSSECSHA='+validator_library['sha256']+' -X main.routerVPNDNSSECBytes='+str(validator_library['size'])
        if library_name(target):
            library = payload(regular(stage/library_name(target), MAX_LIBRARY))
            native_loader = source/'cmd/sing-box/routervpn_native_library.go'
            if native_loader.exists() or native_loader.is_symlink():
                raise ValueError('Unowned native library loader in the disposable core')
            native_loader.write_bytes((ROOT/'mobile/desktop/native_library.go.tmpl').read_bytes())
            ldflags += ' -X main.routerVPNCronetSHA='+library['sha256']+' -X main.routerVPNCronetBytes='+str(library['size'])
        run(['go', 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-tags='+','.join(tags(target)),
             '-ldflags='+ldflags, '-o', binary, './cmd/sing-box'], cwd=source, env=env)
        check_target(binary, target, env)
        for source_name, name in (('LICENSE', 'SING-BOX-LICENSE'),
                                  ('routervpn-amnezia-LICENSE.txt', 'AMNEZIA-LICENSE'),
                                  ('routervpn-xray-LICENSE.txt', 'XRAY-LICENSE')):
            (stage/name).write_bytes(regular(source/source_name, MAX_LICENSE))
        stage_pq_licenses(stage, env)
        stage_pt_notices(stage)
        tor = TOR.build(target, temp/'tor-bundle', compiled=tor_compiled,
                        cache=ROOT/'dist/.tor-source-cache')
        for name in TOR.VERIFY.names(target):
            shutil.copyfile(tor/name, stage/name)
        (stage/TOR.VERIFY.binary_name(target)).chmod(0o755)
        files = {name: payload(regular(stage/name, payload_bound(name, target)))
                 for name in expected_names(target)}
        receipt = {**receipt_fields(target, policy), **files[binary.name], 'files': files}
        (stage/'NATIVE-RUNTIME.json').write_text(json.dumps(receipt, sort_keys=True, indent=2)+'\n')
        binary.chmod(0o755)
        reuse(stage, target, policy, env)
        if target == host:
            output = run([binary, 'version'], env=env, timeout=20)
            if not output.startswith('sing-box version '+marker(policy)+'\n'):
                raise ValueError('Actual native engine failed the exact source version command')
            help_output = run([binary, 'routervpn-external', '--help'], env=env, timeout=20)
            if '--runtime-dir' not in help_output or '--session' not in help_output:
                raise ValueError('Actual native engine omitted its captured external owner command')
            smoke_protocols(binary, env, source=source)
        if destination.exists():
            destination.rmdir()
        os.replace(stage, destination)
    print('Built complete pinned native runtime '+target+' '+policy, flush=True)
    return destination



class AndroidConnectionQualification:
    """One original emulator, normal app controls and OS VPN Settings UI.

    The same-run APK is never rebuilt or replaced. App-private files contain
    observation phases only; neither adb settings writes nor an alternate VPN
    start/import API are used. Emergency process shutdown is containment and
    cannot replace the app's original service/descriptor join receipt.
    """
    package = 'com.eabusham.routervpn'
    serial = 'emulator-5556'
    name = 'routervpn-connect'

    def __init__(self, apk, work, evidence, run_id, command, publish, result, deadline, logs):
        self.apk, self.work, self.evidence, self.run = apk, work, evidence, run_id
        self.command, self.publish, self.result, self.deadline, self.logs = command, publish, result, deadline, logs
        self.owners, self.phases = [], {}
        self.installed = self.app_started = self.settings_changed = self.restored = False
        self.original_settings = self.before = self.final = None
        self.sdk = Path(os.environ['ANDROID_HOME']).resolve(strict=True)
        self.adb_path = self.sdk/'platform-tools/adb'
        self.emulator_path = self.sdk/'emulator/emulator'
        self.env = os.environ.copy()
        user = work/'android-user'
        user.mkdir(mode=0o700)
        (user/'avd').mkdir(mode=0o700)
        (user/'keys').mkdir(mode=0o700)
        self.env.update(ANDROID_USER_HOME=str(user), ANDROID_EMULATOR_HOME=str(user),
                        ANDROID_AVD_HOME=str(user/'avd'), ANDROID_SERIAL=self.serial,
                        ANDROID_ADB_SERVER_PORT='5038', ADB_SERVER_SOCKET='tcp:127.0.0.1:5038',
                        ADB_VENDOR_KEYS=str(user/'keys'))
        self.adb_prefix = [self.adb_path, '-H', '127.0.0.1', '-P', '5038', '-s', self.serial]
        self.emulator = self.adb_server = None

    def adb(self, *args, timeout=20, input_data=None):
        return self.command(self.adb_prefix+list(args), timeout, env=self.env, input_data=input_data)

    def spawn(self, role, argv):
        log = (self.evidence/(role+'.log')).open('xb')
        self.logs.append(log)
        child = subprocess.Popen([str(v) for v in argv], cwd=self.work, env=self.env,
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        owner = {'role': role, 'child': child, 'pidfd': None, 'pgid': child.pid}
        self.owners.append(owner)  # retain the original handle before fallible pidfd acquisition
        self.result['processes'].append({'role': role, 'pid': child.pid})
        owner['pidfd'] = os.pidfd_open(child.pid)
        return child

    def start(self):
        import xml.etree.ElementTree as ET
        if sys.platform != 'linux' or platform.machine().lower() not in ('x86_64', 'amd64') or not hasattr(os, 'pidfd_open'):
            raise ValueError('Actual x86_64 Linux emulator ownership is required')
        if not os.access('/dev/kvm', os.R_OK | os.W_OK):
            raise ValueError('Actual emulator KVM access is unavailable')
        for path in (self.adb_path, self.emulator_path, self.sdk/'cmdline-tools/latest/bin/avdmanager'):
            if not path.is_file():
                raise ValueError('An actual Android SDK prerequisite is unavailable')
        spec = importlib.util.spec_from_file_location('routervpn_android_delivery_gate', ROOT/'android/verify-delivery.py')
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        receipt = verifier.load_receipt(self.apk, os.environ['GITHUB_SHA'])
        # Verify the shipped APK again with the same delivery verifier. No
        # signing key or substitute debug build is provided to this job.
        metadata = verifier.delivery_metadata(self.apk, os.environ['GITHUB_SHA'])
        badging = self.command([self.sdk/'build-tools/36.0.0/aapt', 'dump', 'badging', self.apk], 60, env=self.env)
        signatures = self.command([self.sdk/'build-tools/36.0.0/apksigner', 'verify', '--verbose', '--print-certs', self.apk], 60, env=self.env)
        verified = verifier.verified_receipt(metadata, badging, signatures, True, metadata['variant'],
                                             metadata['version_code'], metadata['certificate_sha256'], False)
        with self.apk.open('rb') as stream:
            verified['apk_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
        verified['apk_size'] = self.apk.stat().st_size
        if verified != receipt:
            raise ValueError('Original Android delivery changed during admission')
        self.result['android_delivery'] = receipt
        raw = self.command([self.sdk/'cmdline-tools/latest/bin/apkanalyzer', 'manifest', 'print', self.apk], 30, env=self.env)
        manifest = ET.fromstring(raw)
        ns = '{http://schemas.android.com/apk/res/android}'
        app = manifest.find('application')
        if manifest.get('package') != self.package or app is None or app.get(ns+'debuggable') != 'true':
            raise ValueError('The exact APK does not expose debug-only private observation; no substitute APK is allowed')
        services = [s for s in app.findall('service') if any(a.get(ns+'name') == 'android.net.VpnService'
                    for f in s.findall('intent-filter') for a in f.findall('action'))]
        names = [s.get(ns+'name', '') for s in services]
        if not any(n in ('.LayeredVpnService', self.package+'.LayeredVpnService') for n in names):
            raise ValueError('The merged APK lacks the original native VpnService')
        if any(s.get(ns+'permission') != 'android.permission.BIND_VPN_SERVICE' or
               any(m.get(ns+'name') == 'android.net.VpnService.SUPPORTS_ALWAYS_ON' and m.get(ns+'value') == 'false'
                   for m in s.findall('meta-data')) for s in services):
            raise ValueError('The merged APK is not eligible for genuine Android Always-on VPN')
        self.result['merged_vpn_services'] = names
        self.command([self.sdk/'cmdline-tools/latest/bin/avdmanager', 'create', 'avd', '-n', self.name,
                      '-p', Path(self.env['ANDROID_AVD_HOME'])/(self.name+'.avd'),
                      '-k', 'system-images;android-35;google_apis;x86_64'], 60, env=self.env, input_data=b'no\n')
        # These fixed loopback ports must belong only to the new original
        # server/emulator. No existing adb server or emulator is adopted.
        for port in (5038, 5556, 5557):
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', port))
        self.adb_server = self.spawn('android-adb-server', [self.adb_path, '-L', 'tcp:127.0.0.1:5038', 'nodaemon', 'server'])
        end = time.monotonic()+10
        while True:
            if self.adb_server.poll() is not None:
                raise ValueError('The original adb server exited before emulator startup')
            try:
                with socket.create_connection(('127.0.0.1', 5038), 0.2):
                    break
            except OSError:
                if time.monotonic() >= end:
                    raise ValueError('The original adb server did not become available')
                time.sleep(0.05)
        self.emulator = self.spawn('android-emulator', [self.emulator_path, '-avd', self.name, '-port', '5556',
                '-no-window', '-no-audio', '-no-snapshot', '-no-boot-anim', '-gpu', 'swiftshader'])
        self.adb('wait-for-device', timeout=120)
        end = min(self.deadline-430, time.monotonic()+360)
        while self.adb('shell', 'getprop', 'sys.boot_completed', timeout=5) != '1':
            if self.emulator.poll() is not None or time.monotonic() >= end:
                raise ValueError('The original emulator did not boot within its setup budget')
            time.sleep(1)
        if self.adb('shell', 'getprop', 'ro.build.version.sdk') != '35':
            raise ValueError('The actual emulator API differs from the captured fixture')
        self.adb('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
        self.adb('shell', 'wm', 'dismiss-keyguard')
        display=self.adb('shell','wm','size')
        match=re.fullmatch(r'Physical size: ([0-9]+)x([0-9]+)',display)
        if not match or min(map(int,match.groups()))<240:
            raise ValueError('The original emulator display dimensions are unavailable')
        self.display=tuple(map(int,match.groups()))
        self.original_settings = self.settings()
        if self.original_settings != {'package': '', 'lockdown': False, 'allowlist': ''}:
            raise ValueError('The fresh original emulator already has a VPN policy owner')
        self.before = self.snapshot('before')
        if any('tun' in row['name'] for row in self.before['interfaces']):
            raise ValueError('The original emulator already has a TUN')
        self.adb('install', '--no-streaming', '-r', self.apk, timeout=90)
        self.installed = True
        uid = self.adb('exec-out', 'run-as', self.package, 'id', '-u')
        if not re.fullmatch(r'[0-9]+', uid):
            raise ValueError('The exact installed APK has no private observation owner')
        self.result['android_app_uid'] = int(uid)
        self.result['android_api'] = 35
        self.result['android_traffic_family'] = 'ipv4'
        return self.before

    def settings(self):
        raw = {key: self.adb('shell', 'settings', 'get', 'secure', key) for key in
               ('always_on_vpn_app', 'always_on_vpn_lockdown', 'always_on_vpn_lockdown_whitelist')}
        self.result.setdefault('android_settings_readbacks', []).append(raw)
        if raw['always_on_vpn_lockdown'] not in ('null', '0', '1'):
            raise ValueError('Android returned an unknown lockdown state')
        return {'package': '' if raw['always_on_vpn_app'] == 'null' else raw['always_on_vpn_app'],
                'lockdown': raw['always_on_vpn_lockdown'] == '1',
                'allowlist': '' if raw['always_on_vpn_lockdown_whitelist'] == 'null' else raw['always_on_vpn_lockdown_whitelist']}

    def snapshot(self, phase):
        links = self.adb('shell', 'ip', '-o', 'link', 'show')
        addresses = self.adb('shell', 'ip', '-o', 'addr', 'show')
        routes4 = self.adb('shell', 'ip', '-4', 'route', 'show', 'table', 'all')
        routes6 = self.adb('shell', 'ip', '-6', 'route', 'show', 'table', 'all')
        interfaces = []
        for line in links.splitlines():
            match = re.match(r'([0-9]+): ([^:@ ]+)(?:@[^: ]+)?:.*\bmtu ([0-9]+)', line)
            if not match:
                raise ValueError('Actual Android interface output is not recognized')
            interfaces.append({'index': int(match[1]), 'name': match[2], 'mtu': int(match[3])})
        prefixes = []
        for line in (routes4+'\n'+routes6).splitlines():
            words = line.split()
            if not words:
                continue
            value = words[1] if words[0] in ('local', 'broadcast', 'unreachable', 'throw', 'blackhole', 'prohibit') and len(words)>1 else words[0]
            prefixes.append({'prefix': value})
        result = {'interfaces': sorted(interfaces,key=lambda row:row['index']),
                  'addresses': [{'address': match[1]} for match in re.finditer(r'\binet ([0-9.]+)/[0-9]+', addresses)],
                  'routes': sorted(prefixes,key=lambda row:row['prefix']),
                  'link_rows': sorted(links.splitlines()), 'address_rows': sorted(addresses.splitlines()),
                  'route4_rows': sorted(routes4.splitlines()), 'route6_rows': sorted(routes6.splitlines()),
                  'settings': self.settings()}
        self.publish(self.evidence/('android-network-'+phase+'.json'),result)
        return result

    def ui(self):
        import xml.etree.ElementTree as ET
        self.adb('shell', 'uiautomator', 'dump', '--compressed', '/data/local/tmp/routervpn-connect-ui.xml', timeout=20)
        raw = self.adb('exec-out', 'cat', '/data/local/tmp/routervpn-connect-ui.xml')
        if len(raw) > 512*1024:
            raise ValueError('Actual Android UI hierarchy exceeded its bound')
        self.last_ui = raw
        return ET.fromstring(raw)

    def tap_node(self, node):
        match = re.fullmatch(r'\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]',node.get('bounds',''))
        if not match or node.get('enabled') != 'true':
            raise ValueError('The actual Android control is unavailable')
        x1,y1,x2,y2 = map(int,match.groups())
        if x2<=x1 or y2<=y1:
            raise ValueError('The actual Android control has empty bounds')
        self.adb('shell','input','tap',str((x1+x2)//2),str((y1+y2)//2))

    def find(self, text=None, description=None, resource=None, root=None):
        root = self.ui() if root is None else root
        rows = [n for n in root.iter('node') if (text is None or n.get('text')==text) and
                (description is None or n.get('content-desc')==description) and
                (resource is None or n.get('resource-id')==resource) and n.get('enabled')=='true']
        if len(rows)>1:
            raise ValueError('The actual Android control is ambiguous')
        return rows[0] if rows else None

    def tap(self, text=None, description=None, resource=None, timeout=20):
        end = min(self.deadline-100,time.monotonic()+timeout)
        while True:
            node=self.find(text,description,resource)
            if node is not None:
                self.tap_node(node)
                return
            if time.monotonic()>=end:
                raise ValueError('The required normal Android control did not appear')
            time.sleep(0.1)

    def foreground(self):
        self.adb('shell','am','start','-W','-n',self.package+'/.ProductActivity')

    def private_script(self, script):
        return self.adb('shell','run-as',self.package,'sh',input_data=('set -eu\n'+script+'\n').encode())

    def publish_device(self, phase, value):
        if phase not in ('fixture','peer-stopped','settings-restored','cancel'):
            raise ValueError('Unknown Android observation phase')
        path=self.work/('android-'+phase+'.json')
        self.publish(path,value)
        remote='/data/local/tmp/routervpn-'+self.run+'-'+phase+'.json'
        self.adb('push',path,remote)
        self.adb('shell','chmod','644',remote)  # nonsecret phase metadata; app copy is exclusively0600
        script='umask 077\n'
        if phase=='fixture':
            script+='mkdir -p -m 700 files\ntest ! -e files/android-connect\nmkdir -m 700 files/android-connect\n'
        script+=('test ! -e files/android-connect/'+phase+'.json\n'
                 'cp '+remote+' files/android-connect/.'+phase+'.tmp\n'
                 'chmod 600 files/android-connect/.'+phase+'.tmp\n'
                 'ln files/android-connect/.'+phase+'.tmp files/android-connect/'+phase+'.json\n'
                 'rm files/android-connect/.'+phase+'.tmp\n')
        self.private_script(script)
        self.adb('shell','rm',remote)

    def phase(self, phase):
        if phase not in ('armed','strict-refused','connected','loss','disconnected','result'):
            raise ValueError('Unknown actual Android result phase')
        raw=self.private_script('if test -f files/android-connect/'+phase+'.json; then cat files/android-connect/'+phase+'.json; else printf missing; fi')
        if raw=='missing':
            return None
        if len(raw.encode())>32768:
            raise ValueError('Actual Android phase exceeded its bound')
        value=json.loads(raw,object_pairs_hook=unique_object)
        if type(value.get('schema')) is not int or value.get('schema')!=1 or value.get('run_id')!=self.run or value.get('phase')!=phase:
            raise ValueError('Actual Android phase lost its original run identity')
        if phase in self.phases and self.phases[phase]!=value:
            raise ValueError('An original Android phase changed after publication')
        if phase not in self.phases:
            self.phases[phase]=value
            self.publish(self.evidence/('android-connect-'+phase+'.json'),value)
        return value

    def wait_phase(self, phase, timeout=60, cleanup=False):
        end=min(self.deadline-(15 if cleanup else 100),time.monotonic()+timeout)
        while time.monotonic()<end:
            if self.emulator is None or self.emulator.poll() is not None:
                raise ValueError('The original emulator exited before app evidence')
            value=self.phase(phase)
            if value is not None:
                return value
            if phase!='result':
                failed=self.phase('result')
                if failed is not None:
                    raise ValueError('The original Android observer failed at '+str(failed.get('failure_stage','unknown')))
            time.sleep(0.2)
        raise ValueError('Actual Android phase exceeded its original bound: '+phase)

    def settings_screen(self):
        self.adb('shell','am','start','-W','-a','android.settings.VPN_SETTINGS')
        self.tap(description='Settings')

    def set_switch(self, label, wanted):
        root=self.ui()
        label_node=self.find(text=label,root=root)
        if label_node is None:
            raise ValueError('The actual VPN Settings control is absent: '+label)
        parents={child:parent for parent in root.iter() for child in parent}
        node=label_node
        matches=[]
        while node in parents:
            node=parents[node]
            matches=[n for n in node.iter('node') if n.get('checkable')=='true']
            if matches:
                break
        if len(matches)!=1 or matches[0].get('enabled')!='true':
            raise ValueError('The actual VPN Settings switch is ambiguous or disabled')
        state=matches[0].get('checked')=='true'
        if state==wanted:
            return
        self.settings_changed=True
        self.tap_node(matches[0])
        # AOSP may present a normal confirmation dialog for enabling lockdown.
        # Only its actual positive button is clicked, never a secure-settings write.
        root=self.ui()
        positive=self.find(resource='android:id/button1',root=root)
        if positive is not None:
            words=' '.join(n.get('text','') for n in root.iter('node'))
            if 'Block connections without VPN' not in words and 'Always-on VPN' not in words:
                raise ValueError('Unexpected Android VPN policy confirmation')
            self.tap_node(positive)

    def enable_lockdown(self):
        self.settings_screen()
        self.set_switch('Always-on VPN',True)
        self.set_switch('Block connections without VPN',True)
        if self.settings()!={'package':self.package,'lockdown':True,'allowlist':''}:
            raise ValueError('The actual OS Always-on/lockdown settings were not enabled')
        self.foreground()

    def restore_settings(self):
        if self.original_settings is None:
            return
        if self.settings()!=self.original_settings:
            self.settings_screen()
            self.set_switch('Block connections without VPN',False)
            self.set_switch('Always-on VPN',False)
        if self.settings()!=self.original_settings:
            raise ValueError('Original OS VPN settings did not return')
        self.foreground()
        self.restored=True

    def arm(self,bundle,node_id,private,client,host,body_hash,control_port):
        if self.deadline-time.monotonic()<400:
            raise ValueError('Android setup left insufficient original app/cleanup budget')
        source=json.dumps(bundle,sort_keys=True,separators=(',',':')).encode()
        bundle_path=self.work/('routervpn-connect-'+self.run+'.json')
        fd=os.open(bundle_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(source);stream.flush();os.fsync(stream.fileno())
        download='/sdcard/Download/'+bundle_path.name
        self.adb('push',bundle_path,download)
        self.adb('shell','am','broadcast','-a','android.intent.action.MEDIA_SCANNER_SCAN_FILE','-d','file://'+download)
        fixture={'schema':1,'kind':'routervpn-android-connect','run_id':self.run,
                 'bundle_sha256':hashlib.sha256(source).hexdigest(),'node_proof_id':node_id,
                 'private_address':private,'client_address':client,'dns_host':host,
                 'payload_sha256':body_hash,'control_port':control_port,'logical_mode':'base-raw'}
        self.publish_device('fixture',fixture)
        self.app_started=True
        self.foreground()
        self.wait_phase('armed',30)
        # Navigate the actual in-app Add Router menu and Android's document picker.
        # There is no broadcast, intent extra or private store write for import.
        if self.find(text='Add Router') is None:
            expand=self.find(description='Expand connection controls')
            if expand is not None:
                self.tap_node(expand)
        for _ in range(4):
            button=self.find(text='Add Router')
            if button is not None:
                self.tap_node(button);break
            width,height=self.display
            self.adb('shell','input','swipe',str(width//2),str(height*4//5),str(width//2),str(height*2//5),'350')
        else:
            raise ValueError('Normal Add Router control is unavailable')
        self.tap(text='Import Router bundle file')
        self.tap(description='Show roots')
        self.tap(text='Downloads')
        self.tap(text=bundle_path.name)
        end=time.monotonic()+30
        while True:
            root=self.ui()
            spinners=[n for n in root.iter('node') if n.get('class')=='android.widget.Spinner' and
                      any(c.get('text') in ('SMART AUTO — recommended','AUTO — first proven path','Raw tunnel') for c in n.iter('node'))]
            if len(spinners)==1:
                self.tap_node(spinners[0]);break
            if time.monotonic()>=end:
                raise ValueError('Normal captured mode selector is unavailable after import')
            time.sleep(0.1)
        self.tap(text='Raw tunnel')
        self.tap(text='Connect')
        end=time.monotonic()+20
        while True:
            consent=self.ui()
            button=self.find(resource='android:id/button1',root=consent)
            if button is not None and button.get('package')=='com.android.vpndialogs':
                self.tap_node(button);break
            if time.monotonic()>=end:
                raise ValueError('The actual Android VPN consent dialog did not appear')
            time.sleep(0.1)
        self.wait_phase('strict-refused',60)
        if self.settings()!=self.original_settings:
            raise ValueError('Strict refusal changed the OS VPN settings')
        self.enable_lockdown()
        self.tap(text='Connect')
        return self.wait_phase('connected',60)

    def capture(self, phase):
        if phase not in ('connected','disconnected'):
            raise ValueError('Unknown Android capture phase')
        remote='/data/local/tmp/routervpn-connect-'+phase+'.png'
        self.adb('shell','screencap','-p',remote)
        path=self.evidence/('android-'+phase+'.png')
        self.adb('pull',remote,path)
        raw=regular(path,16*1024*1024)
        if not raw.startswith(b'\x89PNG\r\n\x1a\n'):
            raise ValueError('The original Android screenshot is not a PNG')
        self.result.setdefault('android_captures',[]).append({'phase':phase,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)})

    def close(self):
        import select
        failures=[]
        if self.app_started:
            try:
                self.final=self.phase('result')
                if self.final is None:
                    self.publish_device('cancel',{'schema':1,'run_id':self.run,'phase':'cancel'})
                    self.final=self.wait_phase('result',45,cleanup=True)
            except BaseException as failure:
                failures.append('app-original-'+type(failure).__name__)
            try:
                original_cleanup=bool(self.final and all(self.final.get(key) is True for key in
                                      ('cleanup_proved','worker_joined','supervisor_joined')))
                if self.settings()!=self.original_settings:
                    if not original_cleanup:
                        self.result['android_policy_restoration_withheld']=True
                        raise ValueError('Original service and observer retirement is unproved; retain OS lockdown')
                    self.restore_settings()
                else:
                    self.restored=True  # read-only equality; no policy change without original cleanup
                if 'android-network-after' not in self.result:
                    self.result['android-network-cleanup']=self.snapshot('cleanup')
            except BaseException as failure:
                failures.append('settings-restoration-'+type(failure).__name__)
        # Terminating the emulator is separate containment. It never supplies
        # the service/PFD/Network cleanup proof required above.
        # Every Popen is retained before pidfd acquisition or convenience-field
        # assignment. Retire those exact records even when either setup step failed.
        for owner in reversed(self.owners):
            role,child=owner['role'],owner['child']
            owner['joined']=False
            running=True
            try:running=child.poll() is None
            except BaseException as failure:failures.append(role+'-poll-'+type(failure).__name__)
            args={'android-emulator':('emu','kill'),'android-adb-server':('kill-server',)}.get(role)
            if running and args is not None:
                try:self.adb(*args,timeout=10)
                except BaseException as failure:failures.append(role+'-stop-'+type(failure).__name__)
            try:
                child.wait(10);owner['joined']=True
            except BaseException as failure:
                failures.append(role+'-join-'+type(failure).__name__)
                try:child.terminate()
                except BaseException as failure:failures.append(role+'-term-'+type(failure).__name__)
                try:
                    child.wait(5);owner['joined']=True
                except BaseException as failure:
                    failures.append(role+'-term-join-'+type(failure).__name__)
                    try:child.kill()
                    except BaseException as failure:failures.append(role+'-kill-'+type(failure).__name__)
                    try:
                        child.wait(5);owner['joined']=True
                    except BaseException as failure:failures.append(role+'-kill-join-'+type(failure).__name__)
        receipts=[]
        for owner in self.owners:
            child,fd=owner['child'],owner['pidfd']
            terminal=False
            if fd is not None:
                try:
                    poll=select.poll();poll.register(fd,select.POLLIN);terminal=bool(poll.poll(0))
                except BaseException as failure:failures.append(owner['role']+'-pidfd-'+type(failure).__name__)
            group_empty=False
            try:os.killpg(owner['pgid'],0)
            except ProcessLookupError:group_empty=True
            except BaseException as failure:failures.append(owner['role']+'-group-'+type(failure).__name__)
            joined=owner.get('joined') is True
            receipts.append({'role':owner['role'],'pid':child.pid,'joined':joined,'exit_code':child.returncode,
                             'pidfd_terminal':terminal,'original_group_empty':group_empty})
            if not joined or not terminal or not group_empty:failures.append(owner['role']+'-original-owner-retained')
            if fd is not None and terminal:
                try:os.close(fd);owner['pidfd']=None
                except BaseException as failure:failures.append(owner['role']+'-pidfd-close-'+type(failure).__name__)
        if hasattr(self,'last_ui'):
            try:
                path=self.evidence/'android-last-ui.xml'
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as stream:stream.write(self.last_ui.encode())
            except BaseException as failure:failures.append('ui-receipt-'+type(failure).__name__)
        self.result['android_process_retirement']=receipts
        self.result['android_app_result']=self.final
        self.result['android_cleanup_errors']=failures
        self.result['android_original_service_cleanup_proved']=bool(self.final and all(self.final.get(key) is True for key in ('cleanup_proved','worker_joined','supervisor_joined')))
        self.result['android_containment_proved']=not failures and bool(receipts) and all(r['joined'] and r['pidfd_terminal'] and r['original_group_empty'] for r in receipts)
        return failures


def desktop_connect(package, family, evidence, android_apk=None):
    """One real packaged App/WG/system-TUN cycle on this native desktop."""
    import ipaddress
    import socketserver
    import stat
    import signal

    windows = os.name == 'nt'
    android = family == 'android'
    if android and (sys.platform != 'linux' or android_apk is None):
        raise ValueError('The Android connection gate requires its exact APK and native Linux peer')
    if not android and ((windows and family not in ('windows', 'portable-windows')) or (
            not windows and (sys.platform != 'darwin' or family != 'macos'))):
        raise ValueError('The connection gate requires the actual native desktop')
    package = package.resolve(strict=True)
    evidence = evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    os.chmod(evidence, 0o700)
    run_id = uuid.uuid4().hex
    result = {'schema': 1, 'kind': 'routervpn-android-connect' if android else 'routervpn-desktop-connect', 'run_id': run_id,
              'family': family, 'status': 'failed', 'processes': [], 'cleanup_proved': False}
    app = peer = None
    android_session = None
    workers, servers, logs = [], [], []
    command_children = []
    workers_stop = threading.Event()
    deadline_all = time.monotonic()+(900 if android else 360)
    phase_root = None
    counts, lock = Counter(), threading.Lock()
    error = None
    stage = 'preflight'

    def publish(path, value):
        data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        if len(data) > 1 << 20:
            raise ValueError('Desktop connection JSON exceeded its bound')
        temporary = path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
        created = False
        publication_error = None
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, path)  # exclusive publication; never replace a prior phase
        except BaseException as failure:
            publication_error = failure
            raise
        finally:
            if created:
                try:
                    temporary.unlink(missing_ok=True)
                except BaseException as cleanup_error:
                    if publication_error is None:
                        raise
                    publication_error.add_note('Original publication temp retirement failed: '+type(cleanup_error).__name__)

    def read_json(path, limit=16384):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError('Desktop connection phase is not an exclusive regular file')
        if not windows and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('Desktop connection phase lost its private owner')
        with path.open('rb') as stream:
            captured = os.fstat(stream.fileno())
            if (captured.st_dev, captured.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError('Desktop connection phase identity changed')
            value = json.loads(stream.read(limit+1), object_pairs_hook=unique_object)
        current = path.lstat()
        if (current.st_dev, current.st_ino, current.st_size) != (info.st_dev, info.st_ino, info.st_size):
            raise ValueError('Desktop connection phase changed during readback')
        return value

    def command(argv, timeout=20, inspection=None, env=None, input_data=None):
        # Fixed OS inspection / package commands only. The original child is
        # retained before wait, and every timeout joins that child before error.
        if inspection not in (None, 'before', 'during', 'after', 'cleanup'):
            raise ValueError('Unknown fixed desktop network inspection')
        command_deadline = min(deadline_all, time.monotonic()+timeout)
        if inspection == 'before':
            command_deadline = min(command_deadline, deadline_all-280)
        if command_deadline <= time.monotonic():
            raise ValueError('Desktop inspection exhausted its original absolute budget')
        if input_data is not None and (not isinstance(input_data,bytes) or len(input_data)>8192):
            raise ValueError('Fixed command input exceeded its bound')
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as diagnostics, tempfile.TemporaryFile() as supplied:
            if input_data is not None:
                supplied.write(input_data);supplied.seek(0)
            child = subprocess.Popen([str(v) for v in argv], stdout=output, env=env,
                                     stdin=supplied if input_data is not None else None,
                                     stderr=diagnostics if inspection is not None else subprocess.STDOUT)
            command_children.append(child)  # original handles survive every failed wait through final readback
            primary = None
            try:
                remaining = command_deadline-time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired([str(v) for v in argv], timeout)
                code = child.wait(remaining)
                if code != 0:
                    raise ValueError('A fixed desktop inspection or installation command failed')
            except BaseException as failure:
                primary = failure
                signal_error = join_error = None
                if child.poll() is None:
                    try:
                        child.kill()
                    except BaseException as failure:
                        signal_error = failure
                try:
                    child.wait(5)
                except BaseException as failure:
                    join_error = failure
                    result.setdefault('retained_command_pids', []).append(child.pid)
                if signal_error or join_error:
                    primary.add_note('Original inspection child retirement: signal='+str(type(signal_error).__name__ if signal_error else 'ok')+' join='+str(type(join_error).__name__ if join_error else 'ok'))
                raise
            finally:
                if inspection is not None:
                    try:
                        captured = {'schema': 1, 'phase': inspection, 'pid': child.pid,
                                    'exit_code': child.returncode, 'joined': child.returncode is not None,
                                    'timeout_seconds': timeout, 'streams': {}}
                        for name, stream in (('stdout', output), ('stderr', diagnostics)):
                            size = stream.seek(0, os.SEEK_END)
                            stream.seek(0)
                            sample = stream.read(1 << 20)
                            target = evidence/('windows-network-'+inspection+'.'+name+'.log')
                            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                            with os.fdopen(fd, 'wb') as retained:
                                retained.write(sample)
                            captured['streams'][name] = {'bytes': size, 'retained_bytes': len(sample),
                                'truncated': size > len(sample), 'sha256': hashlib.sha256(sample).hexdigest()}
                        publish(evidence/('windows-network-'+inspection+'.json'), captured)
                    except BaseException as capture_error:
                        if primary is None:
                            raise
                        primary.add_note('Fixed network inspection evidence could not be retained: '+type(capture_error).__name__)
            output.seek(0)
            data = output.read((1 << 20)+1)
            diagnostic_size = diagnostics.seek(0, os.SEEK_END)
        if len(data) > 1 << 20 or diagnostic_size > 1 << 20 or code != 0:
            raise ValueError('A fixed desktop inspection or installation command failed')
        return data.decode('utf-8-sig').strip()

    powershell = (Path(os.environ.get('SystemRoot', r'C:\Windows')) /
                  'System32/WindowsPowerShell/v1.0/powershell.exe')
    def ps(script, inspection, timeout):
        script = ("$ProgressPreference='SilentlyContinue'\n"
                  "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"+script)
        encoded = base64.b64encode(script.encode('utf-16le')).decode()
        return json.loads(command([powershell, '-NoLogo', '-NoProfile', '-NonInteractive',
                                   '-OutputFormat', 'Text', '-EncodedCommand', encoded],
                                  timeout=timeout, inspection=inspection))

    def snapshot(inspection):
        if windows:
            # The first four-query CIM snapshot may initialize native modules.
            # command() caps it before the unchanged full App cleanup reserve.
            timeout = 60 if inspection == 'before' else 20
            return ps(r"""
$ErrorActionPreference='Stop'
$v=@{
 interfaces=@(Get-NetAdapter -IncludeHidden | ForEach-Object {@{index=[int]$_.ifIndex;id=$_.InterfaceGuid.ToString();name=$_.Name;status=$_.Status.ToString()}})
 addresses=@(Get-NetIPAddress | ForEach-Object {@{index=[int]$_.InterfaceIndex;address=$_.IPAddress;prefix=[int]$_.PrefixLength}})
 routes=@(Get-NetRoute | ForEach-Object {@{index=[int]$_.InterfaceIndex;prefix=$_.DestinationPrefix;gateway=$_.NextHop;metric=[int]$_.RouteMetric;interface_metric=[int]$_.InterfaceMetric}})
 dns=@(Get-DnsClientServerAddress | ForEach-Object {@{index=[int]$_.InterfaceIndex;family=$_.AddressFamily.ToString();servers=@($_.ServerAddresses)}})
}
$v | ConvertTo-Json -Depth 6 -Compress
""", inspection, timeout)
        interfaces, addresses, routes = [], [], []
        current = None
        for line in command(['/sbin/ifconfig', '-a']).splitlines():
            head = re.match(r'^(\S+): flags=\d+<([^>]*)> mtu (\d+)', line)
            if head:
                current = head[1]
                interfaces.append({'name': current, 'flags': head[2], 'mtu': int(head[3])})
            address = re.match(r'\s+inet ([0-9.]+) netmask (\S+)', line)
            if address and current:
                addresses.append({'name': current, 'address': address[1], 'netmask': address[2]})
        for version in ('inet', 'inet6'):
            for line in command(['/usr/sbin/netstat', '-rn', '-f', version]).splitlines():
                parts = line.split()
                if len(parts) >= 4 and re.fullmatch(r'[A-Za-z!]+', parts[2]) and parts[0] != 'Destination':
                    # Link-layer neighbour cache entries are not routing policy.
                    if 'L' not in parts[2] or parts[3].startswith('utun'):
                        routes.append({'family': version, 'prefix': parts[0], 'gateway': parts[1],
                                       'flags': parts[2], 'name': parts[3]})
        dns = '\n'.join(line.strip() for line in command(['/usr/sbin/scutil', '--dns']).splitlines()
                        if not line.strip().startswith('reach'))
        return {'interfaces': interfaces, 'addresses': addresses, 'routes': routes, 'dns': dns}

    def canonical(value):
        if isinstance(value, list):
            return sorted((canonical(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
        if isinstance(value, dict):
            return {k: canonical(v) for k, v in sorted(value.items())}
        return value

    def network(prefix):
        if prefix == 'default' or prefix == '0.0.0.0/0' or ':' in prefix:
            return None
        address, slash, bits = prefix.partition('/')
        if not re.fullmatch(r'[0-9.]+', address):
            return None
        fields = address.split('.')
        return ipaddress.ip_network('.'.join(fields+['0']*(4-len(fields)))+'/'+
                                    (bits if slash else str(len(fields)*8)), strict=False)

    def phase(name, expected):
        path = phase_root/name
        if not path.exists():
            return None
        if path.lstat().st_nlink == 2:  # publisher has not removed its exact temp yet
            return None
        value = read_json(path)
        if type(value.get('schema')) is not int or value.get('schema') != 1 or value.get('run_id') != run_id or value.get('phase') != expected:
            raise ValueError('Desktop connection phase does not belong to this run')
        return value

    def stop_peer():
        if peer is None:
            return
        failures = []
        if peer.poll() is None:
            try:
                peer.terminate()
            except BaseException as failure:
                failures.append(type(failure).__name__)
        try:
            code = peer.wait(8)
        except BaseException as failure:
            failures.append(type(failure).__name__)
            try:
                peer.kill()
            except BaseException as kill_failure:
                failures.append(type(kill_failure).__name__)
            try:
                code = peer.wait(5)
            except BaseException as join_failure:
                failures.append(type(join_failure).__name__)
                result['original_peer_retained'] = True
                code = None
        result['peer_exit_code'] = code
        if failures or code not in (0, -signal.SIGTERM) and not (windows and code == 1):
            result['peer_retirement_errors'] = failures
            raise ValueError('The original WG peer did not retire normally')

    try:
        target = ('linux/' if android else 'windows/' if windows else 'darwin/') + ('arm64' if platform.machine().lower() in ('arm64', 'aarch64') else 'amd64')
        payload_root = package/'App/RouterVPN' if family == 'portable-windows' else package
        if android:
            if not re.fullmatch('[0-9a-f]{40}',os.environ.get('GITHUB_SHA','')) or os.environ.get('GITHUB_REPOSITORY')!='Eabusham2/router-vpn':
                raise ValueError('The Android gate requires the exact same-run source identity')
            provenance={'source_sha':os.environ['GITHUB_SHA']}
            native=package
        else:
            provenance = json.loads(regular(package/'ROUTER-VPN-SOURCE.json', 32768))
            if provenance.get('source_sha') != os.environ.get('GITHUB_SHA') or provenance.get('repository') != os.environ.get('GITHUB_REPOSITORY'):
                raise ValueError('The connection gate requires the exact same-run package')
            native = payload_root/'runtime/native'
        native_receipt = reuse(native, target, metadata_reader=command)
        binary = native/binary_name(target)
        result.update(source_sha=provenance['source_sha'], target=target,
                      native_sha256=hashlib.sha256(regular(binary, MAX_BINARY)).hexdigest(),
                      native_policy_sha256=native_receipt['policy_sha256'])
        if android:
            phase_root=Path(tempfile.mkdtemp(prefix='routervpn-android-connect-')).resolve(strict=True)
            os.chmod(phase_root,0o700)
        elif windows:
            phase_root = package/'Data' if family == 'portable-windows' else package
            phase_root.mkdir(exist_ok=True)
            launcher = package/('RouterVPNPortable.exe' if family == 'portable-windows' else 'RouterVPN.exe')
            regular(launcher, MAX_BINARY)
        else:
            if os.getuid() == 0 or Path('/opt/router-vpn-client').exists() or Path('/opt/router-vpn-client').is_symlink():
                raise ValueError('A native Mac connection gate requires an uninstalled original desktop account')
            stage = 'install'
            command(['/bin/bash', payload_root/'client/install-macos-native.sh', payload_root], 90)
            launcher = Path('/opt/router-vpn-client/RouterVPN.app/Contents/MacOS/RouterVPN')
            regular(launcher, MAX_BINARY)
            if hashlib.sha256(launcher.read_bytes()).digest() != hashlib.sha256(
                    regular(payload_root/'RouterVPN.app/Contents/MacOS/RouterVPN', MAX_BINARY)).digest():
                raise ValueError('The installed original App differs from the verified package')
            phase_root = Path(tempfile.mkdtemp(prefix='routervpn-desktop-connect-')).resolve(strict=True)
            os.chmod(phase_root, 0o700)
        work = Path(tempfile.mkdtemp(prefix='.desktop-connect-', dir=phase_root))
        os.chmod(work, 0o700)
        for name in ('fixture', 'connected', 'peer-stopped', 'result', 'cancel'):
            if (phase_root/('desktop-connect-'+name+'.json')).exists():
                raise ValueError('The original data root already contains a connection gate')
        stage = 'network-capture'
        if android:
            android_session=AndroidConnectionQualification(android_apk.resolve(strict=True),work,evidence,run_id,command,publish,result,deadline_all,logs)
            before=android_session.start()
        else:
            before = snapshot('before')
        result['before'] = before
        if android:
            physical='original-emulator-host-alias';candidates=['10.0.2.2']
        elif windows:
            defaults = [r for r in before['routes'] if r['prefix'] == '0.0.0.0/0']
            chosen = min(defaults, key=lambda r: r['metric']+r['interface_metric'])
            physical = chosen['index']
            candidates = [a['address'] for a in before['addresses'] if a['index'] == physical and ':' not in a['address']]
            if not any(i['index'] == physical and i['status'] == 'Up' for i in before['interfaces']):
                raise ValueError('The original Windows default interface is not up')
        else:
            match = re.search(r'^\s*interface:\s*(\S+)', command(['/sbin/route', '-n', 'get', 'default']), re.M)
            physical = match[1] if match else ''
            candidates = [a['address'] for a in before['addresses'] if a['name'] == physical]
            if not any(i['name'] == physical and 'UP' in i['flags'].split(',') for i in before['interfaces']):
                raise ValueError('The original Mac default interface is not up')
        outer = next((x for x in candidates if ipaddress.ip_address(x).is_private and
                      not ipaddress.ip_address(x).is_loopback and not ipaddress.ip_address(x).is_link_local), None)
        if not outer:
            raise ValueError('The real default NIC has no captured private IPv4 address')
        occupied = [n for r in before['routes'] if (n := network(r['prefix']))]
        occupied.extend(ipaddress.ip_network(a['address']+'/32') for a in before['addresses'] if ':' not in a['address'])
        subnet = next((ipaddress.ip_network('10.253.'+str(i)+'.0/24') for i in range(240, 255)
                       if not any(ipaddress.ip_network('10.253.'+str(i)+'.0/24').overlaps(n) for n in occupied)), None)
        if subnet is None:
            raise ValueError('No non-overlapping private test subnet is available')
        private, client_address = str(subnet[1]), str(subnet[2])
        result.update(physical_interface=physical, physical_address=outer, private_address=private,
                      private_subnet=str(subnet), topology=('Android emulator 10.0.2.2 host alias; private addresses exist only inside WG' if android else 'own-NIC encrypted WG; private addresses exist only inside WG'))
        keys = []
        for _ in range(2):
            keys.append(dict(line.split(': ', 1) for line in command([binary, 'generate', 'wg-keypair']).splitlines()))
        server_key, client_key = keys
        node_id = hashlib.sha256(('router-vpn-node-proof-v1\n'+server_key['PublicKey']).encode()).hexdigest()
        host = run_id+'.desktop-smoke.invalid'
        path = '/desktop-connect/'+run_id
        body = os.urandom(32768)
        body_hash = hashlib.sha256(body).hexdigest()
        def counted(name):
            with lock:
                counts[name] += 1
        class HTTP(http.server.BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(2)
            def log_message(self, *_):
                pass
            def do_GET(self):
                if self.path == '/health':
                    data = json.dumps({'ok': True, 'node_id': node_id, 'proof': 'router-vpn-private-agent-v1'}).encode()
                    counted('health')
                elif self.path == path:
                    data = body
                    counted('payload')
                elif self.path == '/control/'+run_id:
                    data = body
                    counted('control')
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(data)
        def dns_response(data):
            if len(data) < 17 or len(data) > 4096 or data[2] & 0x80 or data[4:6] != b'\0\1':
                raise ValueError('Invalid bounded local DNS question')
            cursor, labels = 12, []
            while cursor < len(data) and data[cursor]:
                length = data[cursor]
                if length > 63 or cursor+1+length >= len(data):
                    raise ValueError('Invalid local DNS label')
                labels.append(data[cursor+1:cursor+1+length].decode('ascii').lower())
                cursor += length+1
            end = cursor+5
            if end > len(data):
                raise ValueError('Truncated local DNS question')
            name, kind, cls = '.'.join(labels), *struct.unpack('!HH', data[cursor+1:end])
            allowed = name in (host, 'example.com') and cls == 1
            answer = b''
            if allowed and kind == 1:
                # The native readiness proof requires a non-private A answer.
                # It is DNS data only: no connection to this address is made.
                address = private if name == host else '1.1.1.1'
                answer = b'\xc0\x0c'+struct.pack('!HHIH', 1, 1, 0, 4)+socket.inet_aton(address)
                counted('dns_nonce' if name == host else 'dns_readiness')
            return (data[:2]+struct.pack('!HHHHH', 0x8180 if allowed else 0x8183, 1, bool(answer), 0, 0)+data[12:end]+answer)
        class UDPDNS(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    data, channel = self.request
                    channel.sendto(dns_response(data), self.client_address)
                except (ValueError, OSError, UnicodeError):
                    counted('dns_rejected')
        class TCPDNS(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                def receive(length):
                    data = b''
                    while len(data) < length:
                        chunk = self.request.recv(length-len(data))
                        if not chunk:
                            raise ValueError('Local DNS stream closed')
                        data += chunk
                    return data
                try:
                    size = struct.unpack('!H', receive(2))[0]
                    if not 17 <= size <= 4096:
                        raise ValueError('Local DNS stream exceeded its bound')
                    answer = dns_response(receive(size))
                    self.request.sendall(struct.pack('!H', len(answer))+answer)
                except (ValueError, OSError):
                    counted('dns_rejected')
        http_server = http.server.HTTPServer(('127.0.0.1', 0), HTTP)
        servers.append(http_server)
        udp_dns = socketserver.UDPServer(('127.0.0.1', 0), UDPDNS)
        servers.append(udp_dns)
        tcp_dns = socketserver.TCPServer(('127.0.0.1', 0), TCPDNS)
        servers.append(tcp_dns)
        def serve(server):
            while not workers_stop.is_set():
                server.handle_request()
        for server in servers:
            server.timeout = 0.1
            thread = threading.Thread(target=serve, args=(server,))
            workers.append((thread, server))  # retain the pair before attempting Start
            thread.start()
        # WG opens wildcard IPv4 and IPv6 UDP on the same port. Probe that
        # exact listener set, including Windows excluded UDP ranges.
        port = None
        for _ in range(32):
            reservations, selected = [], 0
            try:
                bindings = [(socket.AF_INET, '0.0.0.0')]
                if socket.has_ipv6:
                    bindings.append((socket.AF_INET6, '::'))
                for address_family, address in bindings:
                    try:
                        reservation = socket.socket(address_family, socket.SOCK_DGRAM)
                        reservations.append(reservation)
                        if address_family == socket.AF_INET6:
                            reservation.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        if windows:
                            reservation.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                        reservation.bind((address, selected))
                        selected = reservation.getsockname()[1]
                    except OSError as failure:
                        if address_family == socket.AF_INET6 and (failure.errno == errno.EAFNOSUPPORT or getattr(failure, 'winerror', None) == 10047):
                            continue
                        raise
                port = selected
                break
            except OSError as failure:
                if failure.errno not in (errno.EACCES, errno.EADDRINUSE) and getattr(failure, 'winerror', None) not in (10013, 10048):
                    raise
            finally:
                for reservation in reservations:
                    reservation.close()
        if port is None:
            raise ValueError('No actual dual-stack UDP listener port was available')
        result['physical_peer_port'] = port
        rules = [{'ip_cidr': [private+'/32'], 'port': [8787 if protocol == 'http' else 53],
                  'network': transport, 'action': 'route', 'outbound': 'local',
                  'override_address': '127.0.0.1', 'override_port': server.server_address[1]}
                 for protocol, transport, server in (('http', 'tcp', http_server), ('dns', 'udp', udp_dns), ('dns', 'tcp', tcp_dns))]
        config = {'log': {'level': 'info'}, 'endpoints': [{'type': 'wireguard', 'tag': 'peer',
                  'system': False, 'mtu': 1280, 'address': [private+'/32'], 'private_key': server_key['PrivateKey'],
                  'listen_port': port, 'peers': [{'public_key': client_key['PublicKey'],
                  'allowed_ips': [client_address+'/32']}]}],
                  'outbounds': [{'type': 'direct', 'tag': 'local'}],
                  'route': {'rules': rules+[{'action': 'reject'}]}}
        publish(work/'peer.json', config)
        log = (work/'peer.log').open('xb')
        logs.append(log)
        peer = subprocess.Popen([str(binary), 'run', '-c', str(work/'peer.json')],
                                cwd=work, stdout=log, stderr=subprocess.STDOUT)
        result['processes'].append({'role': 'peer', 'pid': peer.pid})
        stage = 'peer-start'
        ready_deadline = time.monotonic()+5
        while True:
            if peer.poll() is not None:
                raise ValueError('The original private WG peer exited during startup')
            if 'sing-box started' in (work/'peer.log').read_text(errors='replace')[-16384:]:
                break
            if time.monotonic() >= ready_deadline:
                raise ValueError('The original private WG peer did not start')
            time.sleep(0.05)
        wg = ('[Interface]\nPrivateKey = '+client_key['PrivateKey']+'\nAddress = '+client_address+
              '/32\nDNS = '+private+'\nMTU = 1280\n[Peer]\nPublicKey = '+server_key['PublicKey']+
              '\nEndpoint = '+outer+':'+str(port)+'\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 15\n')
        profile = {'id': 'desktop-connect', 'name': 'Desktop private connection', 'node_kind': 'router-vpn',
                   'endpoint': outer, 'node_proof_id': node_id, 'api_token': os.urandom(32).hex(),
                   'router_api': 'http://'+private+':8787', 'path_probe_url': 'http://'+private+':8787/health',
                   'adguard_ipv4': private, 'dns_mode': 'home', 'dns_protocol': 'udp', 'start_layer': 'off',
                   'ipv6_mode': 'off', 'kill_switch': True, 'kill_switch_policy': 'on-connect',
                   'home_lan_access': False, 'mtu_policy': 'manual', 'manual_mtu': 1280, 'base_tunnel': 'wg'}
        bundle = {'endpoint': outer, 'nodeProofId': node_id, 'apiToken': profile['api_token'],
                  'routerAPI': profile['router_api'], 'adGuardIPv4': private, 'selectedRouterID': profile['id'],
                  'routerProfiles': [profile], 'profiles': {'wg': {'wg.conf': base64.b64encode(wg.encode()).decode()}}}
        if android:
            stage='android-app-connect'
            profile.update(name='Android private connection',base_fallback=False,auto_connect=False)
            bundle['modes']=[row for row in json.loads((ROOT/'configs/client/modes.json').read_text()) if row['id']=='wg']
            bundle['logicalModes']=[row for row in json.loads((ROOT/'configs/client/logical-modes.json').read_text()) if row['id']=='base-raw']
            if len(bundle['modes'])!=1 or len(bundle['logicalModes'])!=1:
                raise ValueError('The captured ordinary Android WG catalog changed')
            connected=android_session.arm(bundle,node_id,private,client_address,host,body_hash,http_server.server_address[1])
            if connected.get('runtime_mode')!='wg' or connected.get('payload_sha256')!=body_hash or connected.get('dns_nonce') is not True or connected.get('physical_denied') is not True:
                raise ValueError('Actual Android connected evidence changed')
            during=android_session.snapshot('during');result['during']=during
            vpn=connected.get('vpn',{})
            original_indices={row['index'] for row in before['interfaces']}
            if vpn.get('ifindex') in original_indices or not any(row['index']==vpn.get('ifindex') and row['name']==vpn.get('interface') and row['mtu']==1280 for row in during['interfaces']):
                raise ValueError('Independent Android kernel TUN readback differs from the original service')
            if during['settings']!={'package':android_session.package,'lockdown':True,'allowlist':''}:
                raise ValueError('Actual Android kernel policy changed while connected')
            with lock:
                first_counts=dict(counts)
            if first_counts.get('health',0)<1 or first_counts.get('payload',0)!=1 or first_counts.get('dns_nonce',0)<1 or first_counts.get('control',0)!=2:
                raise ValueError('The original peer did not observe the exact Android private/control traffic')
            result['connected_peer_counters']=first_counts
            android_session.capture('connected')
            def live_control():
                control=http.client.HTTPConnection('127.0.0.1',http_server.server_address[1],timeout=5)
                try:
                    control.request('GET','/control/'+run_id)
                    response=control.getresponse()
                    try:
                        value=response.read(65537)
                        if response.status!=200 or len(value)>65536 or hashlib.sha256(value).hexdigest()!=body_hash:
                            raise ValueError('The original host control did not remain live')
                    finally:response.close()
                finally:control.close()
            stage='android-peer-loss';stop_peer();live_control()
            android_session.publish_device('peer-stopped',{'schema':1,'run_id':run_id,'phase':'peer-stopped'})
            loss=android_session.wait_phase('loss',30)
            if loss.get('private_denied') is not True or loss.get('physical_denied') is not True:
                raise ValueError('Actual Android fail-closed evidence is absent')
            with lock:
                if counts['payload']!=first_counts['payload'] or counts['control']!=first_counts['control']+1:
                    raise ValueError('Android application traffic bypassed the stopped original peer')
            live_control()
            stage='android-original-disconnect'
            android_session.foreground();android_session.tap(text='Disconnect')
            disconnected=android_session.wait_phase('disconnected',45)
            if disconnected.get('owned_vpn_absent') is not True or disconnected.get('physical_still_denied') is not True:
                raise ValueError('Actual Android disconnect/remaining lockdown is unproved')
            if android_session.settings()!={'package':android_session.package,'lockdown':True,'allowlist':''}:
                raise ValueError('OS lockdown was released before the original disconnect proof')
            with lock:
                if counts['control']!=first_counts['control']+2:
                    raise ValueError('Android physical traffic escaped before OS lockdown restoration')
            android_session.capture('disconnected')
            stage='android-settings-restoration';android_session.restore_settings()
            android_session.publish_device('settings-restored',{'schema':1,'run_id':run_id,'phase':'settings-restored'})
            final=android_session.wait_phase('result',30);android_session.final=final
            if final.get('status')!='passed' or any(final.get(key) is not True for key in ('connect','traffic','loss','disconnect','worker_joined','supervisor_joined','cleanup_proved')) or final.get('connect_clicks')!=2 or final.get('disconnect_clicks')!=1:
                raise ValueError('The original Android service did not prove its complete lifecycle')
            after=android_session.snapshot('after');result['after']=after;result['android-network-after']=after
            if canonical(before)!=canonical(after):
                raise ValueError('Original emulator interfaces, routes or OS VPN settings did not return')
            with lock:
                if counts['payload']!=first_counts['payload'] or counts['control']!=first_counts['control']+3:
                    raise ValueError('Fresh physical control did not resume exactly after OS policy restoration')
            result['controller_cleanup_proved']=True;result['status']='passed'
        else:
            fixture = {'schema': 1, 'kind': 'routervpn-desktop-connect', 'run_id': run_id, 'profile_bundle': bundle,
                       'logical_mode': 'base-raw', 'runtime_mode': 'wg', 'private_address': private, 'dns_host': host,
                       'payload_url': 'http://'+host+':8787'+path, 'literal_payload_url': 'http://'+private+':8787'+path,
                       'payload_sha256': body_hash}
            publish(phase_root/'desktop-connect-fixture.json', fixture)
            stage = 'app-connect'
            app_log = (evidence/'desktop-connect-app.log').open('xb')
            logs.append(app_log)
            env = os.environ.copy()
            env['ROUTERVPN_CONNECTION_SELF_TEST'] = '1'
            if windows:
                env['ROUTERVPN_CAPTURE_SELF_TEST_LAYOUT'] = '1'
            arguments = [str(launcher), '--self-test'] if windows else [str(launcher), '--connection-self-test', str(phase_root/'desktop-connect-fixture.json')]
            # Reserve the complete original 180s watchdog + 85s checked cleanup
            # before granting the App any tunnel authority. Slow setup cannot spend
            # the shutdown budget and strand a newly admitted connection.
            if deadline_all-time.monotonic() < 280:
                raise ValueError('Desktop setup left insufficient original App cleanup budget')
            app = subprocess.Popen(arguments, cwd=phase_root, env=env, stdout=app_log, stderr=subprocess.STDOUT)
            result['processes'].append({'role': 'original-app', 'pid': app.pid})
            deadline = min(deadline_all-15, time.monotonic()+265)
            connected = None
            while time.monotonic() < deadline:
                connected = phase('desktop-connect-connected.json', 'connected')
                if connected:
                    break
                if app.poll() is not None or phase('desktop-connect-result.json', 'complete'):
                    raise ValueError('The original App did not complete its connection phase')
                time.sleep(0.1)
            if not connected:
                raise ValueError('The original App connection phase exceeded its bound')
            if (connected.get('runtime_mode') != 'wg' or connected.get('private_address') != private
                    or connected.get('payload_sha256') != body_hash or not connected.get('profile_id')):
                raise ValueError('The original App reported a different connection')
            during = snapshot('during')
            result['during'] = during
            if windows:
                original = {i['index'] for i in before['interfaces']}
                created = [i for i in during['interfaces'] if i['index'] not in original and i['status'] == 'Up']
                matching = [r for r in during['routes'] if ':' not in r['prefix'] and
                            ipaddress.ip_address(private) in ipaddress.ip_network(r['prefix'], strict=False)]
                best = min(matching, key=lambda r: (-ipaddress.ip_network(r['prefix'], strict=False).prefixlen,
                                                    r['metric']+r['interface_metric']))
                if len(created) != 1 or best['index'] != created[0]['index']:
                    raise ValueError('Fresh private traffic is not routed by the original new Windows TUN')
            else:
                original = {i['name'] for i in before['interfaces']}
                created = [i for i in during['interfaces'] if i['name'] not in original and i['name'].startswith('utun')]
                route = command(['/sbin/route', '-n', 'get', private])
                if len(created) != 1 or not re.search(r'^\s*interface:\s*'+re.escape(created[0]['name'])+r'\s*$', route, re.M):
                    raise ValueError('Fresh private traffic is not routed by the original new utun')
            if canonical(during['dns']) == canonical(before['dns']):
                raise ValueError('The original connection did not change the OS DNS configuration')
            with lock:
                first_counts = dict(counts)
            if any(first_counts.get(k, 0) < 1 for k in ('health', 'payload', 'dns_nonce', 'dns_readiness')):
                raise ValueError('The real private HTTP/DNS peer did not observe all connection proofs')
            result.update(connected=connected, tunnel_interface=created[0], connected_peer_counters=first_counts)
            stage = 'peer-loss'
            stop_peer()
            # The decrypted destination stays independently live; only the exact
            # encrypted upstream is retired before the App's fresh literal probe.
            control = http.client.HTTPConnection('127.0.0.1', http_server.server_address[1], timeout=3)
            try:
                control.request('GET', '/control/'+run_id)
                response = control.getresponse()
                if response.status != 200 or hashlib.sha256(response.read(65537)).hexdigest() != body_hash:
                    raise ValueError('The independent private destination control failed')
            finally:
                control.close()
            publish(phase_root/'desktop-connect-peer-stopped.json', {'schema': 1, 'run_id': run_id, 'phase': 'peer-stopped'})
            stage = 'app-disconnect'
            code = app.wait(max(1, deadline-time.monotonic()))
            result['app_exit_code'] = code
            final = phase('desktop-connect-result.json', 'complete')
            result['app_result'] = final
            if (code != 0 or not final or final.get('status') != 'passed' or
                    any(final.get(k) is not True for k in ('connect', 'traffic', 'loss', 'disconnect')) or
                    (not windows and final.get('cleanup_proved') is not True)):
                raise ValueError('The original App did not prove its full connection and shutdown')
            with lock:
                if counts['payload'] != first_counts['payload']:
                    raise ValueError('The stopped encrypted peer was bypassed')
            stage = 'restoration'
            after = snapshot('after')
            result['after'] = after
            if canonical(after) != canonical(before):
                raise ValueError('Original desktop interfaces, routes or DNS were not restored')
            result['controller_cleanup_proved'] = True
            result['status'] = 'passed'
    except BaseException as failure:
        error = failure
        result['failure_stage'] = stage
        if android:result['android_failure']=str(failure)[:240]
    finally:
        cleanup = []
        if android_session is not None:
            try:cleanup.extend(android_session.close())
            except BaseException as failure:cleanup.append('original-android-cleanup-'+type(failure).__name__)
        if error is not None and phase_root is not None and app is not None and app.poll() is None:
            try:
                publish(phase_root/'desktop-connect-cancel.json', {'schema': 1, 'run_id': run_id, 'phase': 'cancel'})
            except BaseException as failure:
                cleanup.append(type(failure).__name__)
            try:
                # The independent original App/session watchdog owns shutdown,
                # including when the native UI dispatcher has stalled.
                app.wait(max(1, deadline_all-time.monotonic()-10))
            except BaseException as failure:
                cleanup.append(type(failure).__name__)
                result['original_app_retained'] = app.poll() is None
        try:
            stop_peer()
        except BaseException as failure:
            cleanup.append(type(failure).__name__)
        workers_stop.set()
        retained_servers = set()
        for worker, server in workers:
            try:
                worker.join(5)
            except BaseException as failure:
                cleanup.append(type(failure).__name__)
            if worker.is_alive():
                cleanup.append('owned-worker-not-joined')
                retained_servers.add(server)
        for server in servers:
            if server in retained_servers:
                continue
            try:
                server.server_close()
            except BaseException as failure:
                cleanup.append(type(failure).__name__)
        for log in logs:
            try:
                log.close()
            except BaseException as failure:
                cleanup.append(type(failure).__name__)
        with lock:
            result['final_peer_counters'] = dict(counts)
        if app is not None and app.poll() is not None:
            result['app_exit_code'] = app.wait()
        if not android and 'before' in result and 'after' not in result and app is not None and app.poll() is not None:
            try:
                result['after'] = snapshot('cleanup')
            except BaseException as failure:
                cleanup.append(type(failure).__name__)
        result['restoration_proved'] = ('before' in result and 'after' in result and
                                        canonical(result['before']) == canonical(result['after']))
        inspections = []
        for child in command_children:
            joined, code = False, None
            try:
                code = child.wait(5)
                joined = True
            except BaseException as failure:
                cleanup.append('original-inspection-child-'+type(failure).__name__)
            inspections.append({'pid': child.pid, 'joined': joined, 'exit_code': code})
        result['inspection_children'] = inspections
        result['cleanup_errors'] = cleanup
        result['cleanup_proved'] = (not cleanup and all(child['joined'] for child in inspections) and
                                   ((android and result.get('android_original_service_cleanup_proved') is True and result.get('android_containment_proved') is True) or
                                    (not android and app is not None and app.poll() == 0)) and
                                   peer is not None and peer.poll() is not None and
                                   result.get('controller_cleanup_proved') is True and
                                   result['restoration_proved'])
        if not result['cleanup_proved']:
            result['status'] = 'failed'
        try:
            publish(evidence/('android-connect-qualification.json' if android else 'desktop-connect-qualification.json'), result)
        except BaseException as publication_error:
            if error is None:
                error = publication_error
                result['failure_stage'] = 'receipt-publication'
            else:
                error.add_note('The bounded desktop failure receipt could not be published: '+type(publication_error).__name__)
    if error is not None:
        if not android:
            # Surface the original App's own failure stage and log tail in the
            # job log, so a CI failure is diagnosable without the artifact.
            try:
                if phase_root is not None and (phase_root/'desktop-connect-result.json').exists():
                    app_final = read_json(phase_root/'desktop-connect-result.json')
                    print('Original App result:', json.dumps({k: app_final.get(k) for k in
                          ('status', 'failure_stage', 'connect', 'traffic', 'loss', 'disconnect')}), flush=True)
                app_log_path = evidence/'desktop-connect-app.log'
                if app_log_path.exists():
                    tail = app_log_path.read_bytes()[-8192:].decode('utf-8', 'replace')
                    print('Original App log tail:\n'+tail, flush=True)
            except BaseException as diagnostic_error:
                print('Original App diagnostics unavailable:', type(diagnostic_error).__name__, flush=True)
        raise ValueError('Desktop connection gate failed at '+result['failure_stage']) from error
    if result['status'] != 'passed':
        raise ValueError('Desktop connection ownership cleanup was not proved')
    print('Verified actual Android App / strict VpnService / kernel TUN / private DNS+HTTP / peer loss / lockdown / original retirement and OS restoration' if android else 'Verified real packaged App Connect / WG system TUN / private DNS+HTTP / loss / original disconnect restoration', flush=True)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--android-connect']:
        connection=argparse.ArgumentParser(description='Actual same-run Android App/VpnService/lockdown qualification')
        connection.add_argument('--android-connect',action='store_true')
        connection.add_argument('--native',type=Path,required=True)
        connection.add_argument('--apk',type=Path,required=True)
        connection.add_argument('--evidence',type=Path,required=True)
        request=connection.parse_args()
        desktop_connect(request.native,'android',request.evidence,android_apk=request.apk)
        raise SystemExit(0)
    if sys.argv[1:2] == ['--desktop-connect']:
        connection = argparse.ArgumentParser(description='Actual packaged desktop Connect/TUN connection gate')
        connection.add_argument('--desktop-connect', action='store_true')
        connection.add_argument('--package', type=Path, required=True)
        connection.add_argument('--family', choices=('windows', 'portable-windows', 'macos'), required=True)
        connection.add_argument('--evidence', type=Path, required=True)
        request = connection.parse_args()
        desktop_connect(request.package, request.family, request.evidence)
        raise SystemExit(0)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', choices=TARGETS)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--source', type=Path, help='pristine disposable exact core checkout')
    parser.add_argument('--xray', type=Path, help='pristine disposable exact Xray checkout')
    parser.add_argument('--pq', type=Path, help='verified desktop PQ link-input directory')
    parser.add_argument('--cache', type=Path, help='owned Rust incremental build cache')
    parser.add_argument('--tor-compiled', type=Path, help='exact Windows Tor compile artifact; accepted only after native tests')
    parser.add_argument('--dnssec-compiled', type=Path, help='exact native Linux pinned validator build; verified and cryptographically tested before packaging')
    args = parser.parse_args()
    build(args.target, args.destination, source=args.source, xray=args.xray, pq=args.pq, cache=args.cache, tor_compiled=args.tor_compiled, dnssec_compiled=args.dnssec_compiled)
