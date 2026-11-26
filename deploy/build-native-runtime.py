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


def check_target(binary, target, env):
    metadata = run(['go', 'version', '-m', binary], env=env)
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


def reuse(directory, target, policy=None, env=None):
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
    check_target(directory/binary, target, env)
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


if __name__ == '__main__':
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
