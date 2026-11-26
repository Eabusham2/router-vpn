#!/usr/bin/env python3
"""Build and seal the complete pinned desktop Router VPN transport engine.

The Rust protocol has no socket owner. Its existing C ABI is linked into the
same process as WG/AWG, native Xray, Naive, authenticated Start Layers and the
TCP/UDP composite. No installed system engine is overwritten or downloaded at
connection time. A package may consume only a bundle with this exact receipt.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import http.client
import http.server
import importlib.util
import json
import os
import platform
import re
import select
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
             ROOT/'deploy/prepare-go-windows-sockets.py', ROOT/'deploy/windows_build_owner.py',
             ROOT/'deploy/install-desktop-windows-toolchain.py', ROOT/'deploy/darwin_race_toolchain.py',
             *POLICY.inputs(), *TOR.inputs(), *DNSSEC.inputs(), *PERFORMANCE.inputs(),
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


STOCK_DNS_TEST = 'TestLegacyStandardDNSPinnedCore'
STOCK_DNS_CASES = tuple(STOCK_DNS_TEST+'/'+case for case in (
    'udp-uncached', 'udp-cached-negative-control', 'tcp-uncached', 'tcp-cached-negative-control'))





STANDARD_CONFIG_TEST = 'TestLinuxStandardServiceStartupStockGraphs'
STANDARD_CONFIG_PROTOCOLS = ('wireguard', 'socks5', 'http-connect', 'https-connect', 'shadowsocks', 'hysteria2')
STANDARD_CONFIG_POLICIES = ('default', 'fixed', 'ipv6-off')






IMPORTED_DESKTOP_GRAPH_TEST = 'TestDesktopImportedNativeCaptureExactGraphAndPhysicalSockets'
IMPORTED_DESKTOP_LAYER_TEST = 'TestDesktopImportedExplicitLocalPreservesSavedExecutionAndLayers'
IMPORTED_DESKTOP_LIFECYCLE_TEST = 'TestDesktopImportedDailyConnectRestoreAndOwnedTeardown'
IMPORTED_DESKTOP_DNS_ROOTS = ('TestDesktopImportedDNSReceiptAdmission',
    'TestDesktopImportedDNSCancellationWaitsForNativeJoin',
    'TestDesktopImportedDNSCannotUseSuccessfulOSLookup',
    'TestDesktopImportedDNSAtomicPublicationAndFreshHeartbeat',
    'TestDesktopImportedDNSOperationDuration')
IMPORTED_DESKTOP_DNS_CASES = ('success', 'dns-failed', 'reader', 'source', 'owner', 'old-receipt')
IMPORTED_DESKTOP_DNS_DURATION_CASES = tuple(operation+'/'+fault for operation in ('dns','observe') for fault in
    ('positive','zero','failed-zero','cancelled-zero','negative','nan','infinite','oversized','reader','foreign-operation'))
IMPORTED_NATIVE_DNS_ROOTS = ('TestRouterVPNImportedDNSMailbox',
    'TestRouterVPNImportedDNSCancellationJoins', 'TestRouterVPNImportedDNSNativeRouterIsUncached',
    'TestRouterVPNImportedDNSOperationDuration')
IMPORTED_NATIVE_DNS_DURATION_CASES = ('observe','dns','dns-error','cancelled-dns','cancelled-observe')
IMPORTED_NATIVE_DNS_CASES = ('success', 'dns-failed', 'session', 'config', 'path', 'reader',
    'deadline', 'replay', 'source-replaced', 'owner-replaced')
IMPORTED_NATIVE_DNS_PACKAGE = 'github.com/sagernet/sing-box/cmd/sing-box'
IMPORTED_DESKTOP_LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
IMPORTED_DESKTOP_PAIRS = tuple((entry, final) for entry in ('shadowsocks','hysteria2')
    for final in ('shadowsocks','reality-vision','hysteria2','wg','awg2-fast','awg2-strong')) + tuple(
    (entry, final) for entry in ('socks5','http-connect','https-connect') for final in ('shadowsocks','reality-vision'))
IMPORTED_DESKTOP_FILES = {entry+'--'+final+'.json' for entry,final in IMPORTED_DESKTOP_PAIRS
                          if (entry,final) != ('socks5','shadowsocks')} | {
    'layers-'+entry+'--'+final+'.json' for entry in IMPORTED_DESKTOP_LAYERS for final in IMPORTED_DESKTOP_LAYERS}
















IMPORTED_PACKET_PROTOCOLS = ('wireguard', 'amneziawg')
IMPORTED_PACKET_FINALS = ('shadowsocks', 'hysteria2', 'wg', 'awg2-fast', 'awg2-strong', 'reality-vision')
IMPORTED_PACKET_GRAPH_TEST = 'TestDesktopImportedPacketGraphs'
IMPORTED_PACKET_SOURCE_TEST = 'TestDesktopImportedPacketSourceOwnership'
IMPORTED_PACKET_LIMIT_TEST = 'TestDesktopImportedPacketLimits'
IMPORTED_PACKET_DNS_TEST = 'TestDesktopImportedPacketSelectedDNS'
IMPORTED_PACKET_PROFILE_TEST = 'TestDesktopImportedPacketProfiles'
IMPORTED_PACKET_PROOF_TEST = 'TestDesktopImportedPacketProof'
IMPORTED_PACKET_LIFECYCLE_TEST = 'TestDesktopImportedPacketDailyConnectRestoreAndOwnedTeardown'
IMPORTED_PACKET_SOURCE_CASES = ('private-key', 'peer-key', 'psk', 'address', 'allowed-ips', 'endpoint', 'keepalive',
    'packet-mtu', 'parameters', 'public-exit', 'final-token', 'final-dns', 'entry-layer', 'final-layer')
IMPORTED_PACKET_LIMIT_CASES = ('cancel', 'undersized-entry', 'fixed-overflow', 'missing-layer', 'server', 'auto', 'wrong-entry-mode', 'openvpn')
IMPORTED_PACKET_FILES = {protocol+'--'+mode+'--'+entry+'--'+final+'.json'
    for protocol in IMPORTED_PACKET_PROTOCOLS for mode in IMPORTED_PACKET_FINALS
    for entry in IMPORTED_DESKTOP_LAYERS for final in IMPORTED_DESKTOP_LAYERS}







IMPORTED_OPENVPN_NETWORKS = ('tcp', 'udp')
IMPORTED_OPENVPN_FILES = {network+'--'+mode+'--'+entry+'--'+final+'.json'
    for network in IMPORTED_OPENVPN_NETWORKS for mode in IMPORTED_PACKET_FINALS
    for entry in IMPORTED_DESKTOP_LAYERS for final in IMPORTED_DESKTOP_LAYERS}
IMPORTED_OPENVPN_CASES = {
    'Graphs': tuple(network+'/'+mode+'/'+entry+'/'+final
        for network in IMPORTED_OPENVPN_NETWORKS for mode in IMPORTED_PACKET_FINALS
        for entry in IMPORTED_DESKTOP_LAYERS for final in IMPORTED_DESKTOP_LAYERS),
    'Profiles': (),
    'PublicProof': ('wrong-public','cancel','replacement','success'),
    'SelectedDNS': tuple(network+'/'+mode for network in IMPORTED_OPENVPN_NETWORKS for mode in ('home','dot','doh')),
    'SourceOwnership': tuple(network+'/'+case for network in IMPORTED_OPENVPN_NETWORKS
        for case in ('username','password','certificate','remote','port','packet-mtu','public-exit','entry-layer','final-layer','final-token','final-dns')),
    'Limits': tuple(network+'/'+case for network in IMPORTED_OPENVPN_NETWORKS
        for case in ('cancel','script','multiple-remotes','hostname','undersized-entry','fixed-overflow','missing-layer','server','auto','paired-mode','third-control')),
    'ReceiptAdmission': ('success','failed','remote','port','network','capacity','missing-state','operation','reader','source','owner','old-connection','future-connection'),
    'OriginalConnectionCannotRelatch': ('generation','connected-at','capacity'),
    'CancellationJoinsNativeObservation': (),
    'ContextOwnedLocks': ('observation','mailbox','workspace'),
    'DNSOperationCannotBorrowObservation': (),
}
IMPORTED_OPENVPN_NATIVE_CASES = {
    'Constructor': ('original','digest','duplicate-entry','system','multiple-remotes','nonliteral','capacity','expired','replacement-before-ready'),
    'OriginalTuple': ('generation','remote','port','network','connected-at','capacity','too-small','pending','reader','reader-pointer','interface','index','tun-mtu','path','source','active','failure'),
    'CallerContext': ('owner-held','native-held','late-success'),
    'Mailbox': ('observe','dns','dns-failed','reconnect-during-dns','unknown-operation','foreign-observer','missing-observer'),
    'CancellationJoins': (),
    'NativeConnected': ('tcp','udp'),
}










IMPORTED_PQ_GRAPH_TEST = 'TestDesktopImportedPQRealityCapturedGraphs'
IMPORTED_PQ_ENTRIES = ('socks5', 'shadowsocks', 'hysteria2', 'http-connect', 'https-connect',
                       'wireguard', 'amneziawg', 'openvpn-tcp', 'openvpn-udp')
IMPORTED_PQ_FILES = {entry+'--reality-pq-vision--'+first+'--'+last+'.json'
    for entry in IMPORTED_PQ_ENTRIES
    for first in IMPORTED_DESKTOP_LAYERS for last in IMPORTED_DESKTOP_LAYERS}






IMPORTED_XHTTP_GRAPH_TEST = 'TestDesktopImportedXHTTPCapturedGraphs'
IMPORTED_XHTTP_ENTRIES = ('socks5', 'shadowsocks', 'hysteria2', 'http-connect', 'https-connect',
                       'wireguard', 'amneziawg', 'openvpn-tcp', 'openvpn-udp')
IMPORTED_XHTTP_FILES = {entry+'--reality-xhttp--'+first+'--'+last+'.json'
    for entry in IMPORTED_XHTTP_ENTRIES
    for first in IMPORTED_DESKTOP_LAYERS for last in IMPORTED_DESKTOP_LAYERS}






IMPORTED_NAIVE_H2_GRAPH_TEST = 'TestDesktopImportedNaiveH2CapturedGraphs'
IMPORTED_NAIVE_H2_ENTRIES = ('socks5', 'shadowsocks', 'hysteria2', 'http-connect', 'https-connect',
                       'wireguard', 'amneziawg', 'openvpn-tcp', 'openvpn-udp')
IMPORTED_NAIVE_H2_FILES = {entry+'--naive-h2--'+first+'--'+last+'.json'
    for entry in IMPORTED_NAIVE_H2_ENTRIES
    for first in IMPORTED_DESKTOP_LAYERS for last in IMPORTED_DESKTOP_LAYERS}





IMPORTED_NAIVE_H3_GRAPH_TEST = 'TestDesktopImportedNaiveH3CapturedGraphs'
IMPORTED_NAIVE_H3_ENTRIES = ('socks5', 'shadowsocks', 'hysteria2',
                       'wireguard', 'amneziawg', 'openvpn-tcp', 'openvpn-udp')
IMPORTED_NAIVE_H3_FILES = {entry+'--naive-h3--'+first+'--'+last+'.json'
    for entry in IMPORTED_NAIVE_H3_ENTRIES
    for first in IMPORTED_DESKTOP_LAYERS for last in IMPORTED_DESKTOP_LAYERS}























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


def relay_awg_smoke_datagrams(transports, host, finished):
    # Both AWG userspace endpoints dial out. Each role gets its own relay
    # socket so a native BindUpdate can change its ephemeral source port.
    peers = [None, None]
    pending = [[], []]
    while not finished.is_set():
        readable, _, _ = select.select(transports, [], [], 0.2)
        for transport in readable:
            try:
                payload, source = transport.recvfrom(65535)
            except (ConnectionResetError, ConnectionRefusedError):
                continue
            if source[0] != host:
                continue
            role = transports.index(transport)
            peers[role] = source
            for packet in pending[role]:
                transport.sendto(packet, source)
            pending[role].clear()
            other = 1 - role
            if peers[other] is not None:
                transports[other].sendto(payload, peers[other])
            elif len(pending[other]) < 129:
                # The native sender permits a 129-datagram handshake group.
                pending[other].append(payload)


def smoke_protocols(binary, env):
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

        class Target(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = token + self.path.encode('ascii')
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        class TargetServer(http.server.ThreadingHTTPServer):
            daemon_threads = False

            def get_request(self):
                stream, address = super().get_request()
                stream.settimeout(3)
                return stream, address

            def finish_request(self, stream, address):
                # An abandoned native startup connection must not hold the
                # accept loop while later exchanges spend their TLS budget.
                try:
                    secured = server_tls.wrap_socket(stream, server_side=True)
                except OSError:
                    return
                with secured:
                    super().finish_request(secured, address)

        # Userspace VPN stacks reject inner loopback packets. Find this host's
        # routed address without sending a datagram; the target stays on this
        # host, and the exact same address remains reachable by the control.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
            route.connect(('192.0.2.1', 9))
            target_host = route.getsockname()[0]
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(certificate, key)
        target = TargetServer((target_host, 0), Target)
        worker = threading.Thread(target=target.serve_forever, daemon=True)
        worker.start()
        client_tls = ssl.create_default_context(cafile=str(certificate))
        target_port = target.server_address[1]

        def exact(stream, count):
            value = b''
            while len(value) < count:
                part = stream.recv(count-len(value))
                if not part:
                    raise ConnectionError('Native proxy closed its response')
                value += part
            return value

        def exchange(proxy_port=None):
            with socket.create_connection(('127.0.0.1' if proxy_port is not None else target_host, proxy_port or target_port), timeout=3) as stream:
                if proxy_port is not None:
                    stream.sendall(b'\x05\x01\x00')
                    if exact(stream, 2) != b'\x05\x00':
                        raise ConnectionError('Native SOCKS negotiation failed')
                    stream.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(target_host)+struct.pack('!H', target_port))
                    reply = exact(stream, 4)
                    if reply[:3] != b'\x05\x00\x00' or reply[3] not in (1, 3, 4):
                        raise ConnectionError('Selected native protocol did not connect')
                    exact(stream, (4 if reply[3] == 1 else 16 if reply[3] == 4 else exact(stream, 1)[0])+2)
                with client_tls.wrap_socket(stream, server_hostname='localhost') as secured:
                    path = '/'+os.urandom(16).hex()
                    secured.sendall(('GET '+path+' HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n').encode('ascii'))
                    response = http.client.HTTPResponse(secured)
                    response.begin()
                    if response.status != 200 or response.read(4096) != token+path.encode('ascii'):
                        raise ValueError('Native protocol returned a different target or payload')

        def port(kind=socket.SOCK_STREAM):
            with socket.socket(socket.AF_INET, kind) as reservation:
                reservation.bind(('127.0.0.1', 0))
                return reservation.getsockname()[1]

        def stop(process):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

        try:
            for protocol in ('socks', 'http', 'https', 'shadowsocks', 'hysteria2', 'naive-h2', 'naive-h3', 'wireguard', 'openvpn-tcp', 'openvpn-udp', 'amneziawg', 'reality-vision'):
                upstream_port, proxy_port = port(socket.SOCK_DGRAM if protocol in ('hysteria2', 'naive-h3', 'wireguard', 'openvpn-udp', 'amneziawg') else socket.SOCK_STREAM), port()
                while upstream_port == proxy_port:
                    proxy_port = port()
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
                            peer.update(address=target_host, persistent_keepalive_interval=1)
                            endpoint['amnezia'] = {'jc': '2', 'jmin': '32', 'jmax': '64', 's1': '16', 's2': '32',
                                                   's3': '16', 's4': '16', 'h1': '101', 'h2': '102', 'h3': '103', 'h4': '104'}
                        elif index == 0:
                            endpoint['listen_port'] = upstream_port
                        else:
                            peer.update(address='127.0.0.1', port=upstream_port)
                        configuration.pop('inbounds' if index == 0 else 'outbounds')
                        configuration['endpoints'] = [endpoint]
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
                processes, logs, relay_sockets = [], [], []
                relay_done, relay_worker = threading.Event(), None
                try:
                    if protocol == 'amneziawg':
                        for configuration in configurations:
                            relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            relay_sockets.append(relay)
                            relay.bind((target_host, 0))
                            configuration['endpoints'][0]['peers'][0]['port'] = relay.getsockname()[1]
                        relay_worker = threading.Thread(target=relay_awg_smoke_datagrams,
                                                        args=(relay_sockets, target_host, relay_done), daemon=True)
                        relay_worker.start()
                    for role, configuration in zip(('server', 'client'), configurations):
                        config_path, log_path = work/(protocol+'-'+role+'.json'), work/(protocol+'-'+role+'.log')
                        configuration['log'] = {'level': 'error', 'timestamp': False}
                        config_path.write_text(json.dumps(configuration), encoding='utf-8')
                        config_path.chmod(0o600)
                        log = log_path.open('wb'); logs.append(log)
                        processes.append(subprocess.Popen([str(binary), 'run', '-c', str(config_path)], env=env, stdout=log, stderr=log))
                    deadline = time.monotonic()+15
                    while True:
                        if any(process.poll() is not None for process in processes):
                            raise RuntimeError('Native '+protocol+' process exited before its traffic check')
                        try:
                            exchange(proxy_port)
                            break
                        except (OSError, http.client.HTTPException):
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.05)
                    stop(processes[0])
                    try:
                        exchange(proxy_port)
                    except (OSError, http.client.HTTPException):
                        pass
                    else:
                        raise RuntimeError('Native '+protocol+' used a path after its selected upstream stopped')
                    if processes[1].poll() is not None:
                        raise RuntimeError('Native client exited during upstream failure')
                    exchange()
                    print('Native protocol traffic: '+protocol+' HTTPS payload passed; stopped upstream refused; direct control alive', flush=True)
                except Exception:
                    for role in ('server', 'client'):
                        path = work/(protocol+'-'+role+'.log')
                        if path.exists():
                            sys.stderr.write(path.read_bytes()[-8192:].decode('utf-8', errors='replace'))
                    raise
                finally:
                    for process in reversed(processes):
                        stop(process)
                    for log in logs:
                        log.close()
                    relay_done.set()
                    if relay_worker is not None:
                        relay_worker.join(timeout=2)
                    for relay in relay_sockets:
                        relay.close()
                    if relay_worker is not None and relay_worker.is_alive():
                        raise RuntimeError('Native AWG relay did not stop')
        finally:
            target.shutdown(); target.server_close(); worker.join(timeout=5)
            if worker.is_alive():
                raise RuntimeError('Native protocol target did not stop')


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
            smoke_protocols(binary, env)
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
