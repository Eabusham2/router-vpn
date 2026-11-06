#!/usr/bin/env python3
"""Build and seal the complete pinned desktop Router VPN transport engine.

The Rust protocol has no socket owner. Its existing C ABI is linked into the
same process as WG/AWG, native Xray, Naive, authenticated Start Layers and the
TCP/UDP composite. No installed system engine is overwritten or downloaded at
connection time. A package may consume only a bundle with this exact receipt.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile

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


def run(command, *, cwd=None, env=None, timeout=1800):
    # Cargo/Go metadata is UTF-8 even on Windows. Keep stdout binary until the
    # child is joined; a locale reader thread must not discard its output.
    try:
        if os.name == 'nt':
            completed = BUILD_OWNER.run(command, cwd=cwd, env=env, timeout=timeout)
        else:
            completed = subprocess.run([str(arg) for arg in command], cwd=cwd, env=env,
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
    files = list(dict.fromkeys([Path(__file__).resolve(), ROOT/'deploy/build-desktop-pq.py',
                             ROOT/'deploy/windows_build_owner.py',
                             ROOT/'deploy/test_windows_build_owner.py',
                             ROOT/'deploy/build-mobile-pq.py', ROOT/'deploy/prepare-desktop-rosenpass.py',
                             ROOT/'deploy/setup-desktop-native-toolchain.py',
                             ROOT/'deploy/install-desktop-windows-toolchain.py',
                             ROOT/'deploy/test_desktop_socket_uid.py',
                             ROOT/'deploy/test_desktop_windows_identity.py',
                             ROOT/'deploy/test_desktop_windows_identity_runner.py',
                             ROOT/'deploy/test_desktop_windows_wfp.py',
                             ROOT/'deploy/test_windows_protection_transfer.py',
                             ROOT/'deploy/test_windows_protection_observation.py',
                             ROOT/'deploy/test_windows_node_physical.py',
                             ROOT/'deploy/test_windows_node_physical_runner.py',
                             ROOT/'deploy/test_windows_external_provider_join.py',
                             ROOT/'deploy/test_windows_node_pq.py',
                             ROOT/'deploy/test_windows_node_pq_runner.py',
                             ROOT/'deploy/test_windows_node_max.py',
                             ROOT/'deploy/test_windows_node_max_runner.py',
                             ROOT/'deploy/test_desktop_windows_traffic.py',
                             ROOT/'deploy/test_windows_physical_bootstrap.py',
                             ROOT/'deploy/test_windows_physical_bootstrap_runner.py',
                             ROOT/'deploy/test_windows_physical_tunnel.py',
                             ROOT/'deploy/test_windows_physical_tunnel_runner.py',
                             ROOT/'deploy/test_desktop_node_physical.py',
                             ROOT/'deploy/test_mobile_imported_socks_xray.py',
                             ROOT/'deploy/test_mobile_imported_socks_xray_runner.py',
                             ROOT/'deploy/test_mobile_imported_entry.py',
                             ROOT/'deploy/test_mobile_imported_entry_runner.py',
                             ROOT/'deploy/mobile_imported_openvpn_cases.py',
                             ROOT/'deploy/test_desktop_node_routing_runner.py',
                             ROOT/'deploy/test_desktop_node_pq.py',
                             ROOT/'deploy/test_desktop_node_max.py',
                             ROOT/'deploy/test_desktop_node_max_runner.py',
                             ROOT/'deploy/build_pq_reference_fixture.py',
                             ROOT/'deploy/test_server_pq_traffic.py',
                             ROOT/'mobile/rosenpass/examples/native_keys.rs',
                             ROOT/'go.mod',
                             *([ROOT/'go.sum'] if (ROOT/'go.sum').exists() or (ROOT/'go.sum').is_symlink() else []),
                             *sorted((ROOT/'cmd/start-layer-relay').glob('*.go')),
                             *sorted((ROOT/'deploy/fixtures/windows-physical-bootstrap').glob('*.go')),
                             *sorted((ROOT/'deploy/fixtures/windows-node-physical').glob('*.go')),
                             ROOT/'deploy/test_desktop_linux_guardian.py',
                             ROOT/'deploy/test_desktop_dnssec_namespace.py',
                             ROOT/'deploy/test_desktop_dnssec_command.py',
                             ROOT/'deploy/test_desktop_command_retirement.py',
                             ROOT/'deploy/test_linux_node_child_control.py',
                             ROOT/'deploy/test_linux_node_child_control_runner.py',
                             ROOT/'deploy/test_linux_external_lifecycle.py',
                             ROOT/'deploy/test_linux_external_lifecycle_runner.py',
                             ROOT/'deploy/test_linux_external_openvpn.py',
                             ROOT/'deploy/test_linux_external_openvpn_runner.py',
                             ROOT/'deploy/test_linux_node_child_tun.py',
                             ROOT/'deploy/test_linux_node_child_tun_runner.py',
                             ROOT/'deploy/test_linux_node_host_tun.py',
                             ROOT/'deploy/test_linux_node_host_tun_runner.py',
                             ROOT/'deploy/test_linux_controller_privilege.py',
                             ROOT/'deploy/linux_standard_service_gate.py',
                             ROOT/'deploy/test_linux_standard_service_runner.py',
                             ROOT/'deploy/linux_standard_service_bundle.py',
                             ROOT/'deploy/test_linux_standard_service_bundle.py',
                             ROOT/'deploy/test_macos_external_host.py',
                             ROOT/'deploy/test_macos_external_host_runner.py',
                             ROOT/'deploy/seal-native-runtime.py',
                             *sorted((ROOT/'cmd/client').glob('*.go')),
                             ROOT/'cmd/client/ui.html', ROOT/'cmd/client/logical_ui.js',
                             *sorted((ROOT/'internal').rglob('*.go')),
                             ROOT/'deploy/test_linux_node_lifecycle.py',
                             ROOT/'deploy/test_linux_node_lifecycle_runner.py',
                             ROOT/'deploy/test_desktop_darwin_guardian.py',
                             ROOT/'deploy/test_desktop_darwin_route.py',
                             ROOT/'deploy/test_desktop_darwin_route_runner.py',
                             ROOT/'deploy/test_linux_guardian_namespace.py',
                             ROOT/'deploy/test_linux_guardian_cleanup.py',
                             *sorted((ROOT/'mobile/rosenpass').glob('Cargo.*')),
                             *sorted((ROOT/'mobile/rosenpass').glob('*.h')),
                             *sorted((ROOT/'mobile/rosenpass').glob('*.c')),
                             *sorted((ROOT/'mobile/rosenpass/src').rglob('*.rs')),
                             *POLICY.inputs(), *TOR.inputs(), *DNSSEC.inputs(),
                             *PERFORMANCE.inputs(), *OPENVPN.inputs(), *EXTERNAL.inputs(),
                             ROOT/'mobile/desktop/native_library.go.tmpl',
                             ROOT/'deploy/prepare-mobile-buffers.py',
                             ROOT/'deploy/mobile_udp_socket_policy.py']))
    # Path ordering is case-folded on Windows and case-sensitive on POSIX.
    # Nested preparers include mixed-case Java/Swift filenames, so preserving
    # their discovery order gives identical bytes different source identities.
    # Seal the complete set in one explicit, platform-independent order.
    return sorted(files, key=lambda path: path.relative_to(ROOT).as_posix())


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


def verify_linux_stock_dns_verdicts(output):
    # Keep the same exact run/pass inventory discipline as the existing native
    # forwarder and Tor importer gates. A successful Go selector can run zero
    # tests, and package success alone cannot attest these four boundaries.
    required = {STOCK_DNS_TEST, *STOCK_DNS_CASES}
    ran, passed, package_started, package_passed = set(), set(), False, False
    for line in output.splitlines():
        try:
            row = json.loads(line, object_pairs_hook=unique_object)
        except (ValueError, TypeError) as error:
            raise ValueError('Stock DNS gate emitted malformed Go verdict JSON') from error
        if not isinstance(row, dict):
            raise ValueError('Stock DNS gate emitted a non-object verdict')
        action, name = row.get('Action'), row.get('Test')
        if action in ('skip', 'fail', 'build-fail') or 'WARNING: DATA RACE' in str(row.get('Output', '')):
            raise ValueError('Stock DNS native case failed, skipped, raced or failed to build')
        if row.get('Package') != 'router-vpn/cmd/client' or package_passed:
            raise ValueError('Stock DNS verdict belongs to a foreign or completed package')
        if name is not None:
            if not isinstance(name, str) or name not in required or not package_started:
                raise ValueError('Stock DNS native case inventory changed')
            if action == 'run':
                if name in ran or STOCK_DNS_TEST in passed or name != STOCK_DNS_TEST and STOCK_DNS_TEST not in ran:
                    raise ValueError('Stock DNS native case duplicated or reordered its run')
                ran.add(name)
            elif action == 'pass':
                if name not in ran or name in passed or name == STOCK_DNS_TEST and passed != set(STOCK_DNS_CASES):
                    raise ValueError('Stock DNS native case passed without its exact preceding execution')
                passed.add(name)
            elif action not in ('output', 'pause', 'cont'):
                raise ValueError('Stock DNS native case emitted an unknown action')
        elif action == 'start':
            if package_started:
                raise ValueError('Stock DNS package duplicated its start')
            package_started = True
        elif action == 'pass':
            if ran != required or passed != required or not package_started:
                raise ValueError('Stock DNS package omitted an actual required native case')
            package_passed = True
        elif action != 'output':
            raise ValueError('Stock DNS package emitted an unknown action')
    if ran != required or passed != required or not package_passed:
        raise ValueError('Stock DNS gate omitted native parent, leaf or package completion')



STANDARD_CONFIG_TEST = 'TestLinuxStandardServiceStartupStockGraphs'
STANDARD_CONFIG_PROTOCOLS = ('wireguard', 'socks5', 'http-connect', 'https-connect', 'shadowsocks', 'hysteria2')
STANDARD_CONFIG_POLICIES = ('default', 'fixed', 'ipv6-off')


def verify_linux_standard_config_verdicts(output):
    if '--- SKIP:' in output or '--- FAIL:' in output or 'WARNING: DATA RACE' in output:
        raise ValueError('Standard engine graph preparation failed or skipped')
    expected = {STANDARD_CONFIG_TEST}
    expected.update(STANDARD_CONFIG_TEST+'/'+protocol for protocol in STANDARD_CONFIG_PROTOCOLS)
    expected.update(STANDARD_CONFIG_TEST+'/'+protocol+'/'+policy for protocol in STANDARD_CONFIG_PROTOCOLS for policy in STANDARD_CONFIG_POLICIES)
    passed = re.findall(r'(?m)^\s*--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)$', output)
    if set(passed) != expected or any(passed.count(name) != 1 for name in expected):
        raise ValueError('Standard engine graph gate omitted, renamed or duplicated a captured stock selection')


def verify_linux_standard_configs(bundle, env):
    with tempfile.TemporaryDirectory(prefix='routervpn-standard-graphs-') as directory:
        output = run(['go', 'test', '-v', '-race', './cmd/client', '-run', '^'+STANDARD_CONFIG_TEST+'$', '-count=1', '-timeout=60s'],
                     cwd=ROOT, env={**env, 'ROUTERVPN_STANDARD_CONFIG_FIXTURES':directory}, timeout=300)
        verify_linux_standard_config_verdicts(output)
        expected = {protocol+'-'+policy+'.json' for protocol in STANDARD_CONFIG_PROTOCOLS for policy in STANDARD_CONFIG_POLICIES}
        if {p.name for p in Path(directory).iterdir()} != expected:
            raise ValueError('Standard engine lost its exact exported graph inventory')
        binary = Path(bundle)/binary_name('linux/'+env['GOARCH'])
        for name in sorted(expected):
            run([binary, 'check', '-c', Path(directory)/name], env=env, timeout=20)
    print('Native retained standard engine: all eighteen captured stock protocol/device graphs accepted by the actual built core', flush=True)

def verify_linux_stock_dns(bundle, target, env):
    host = 'linux/'+{'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine(), '')
    if platform.system() != 'Linux' or target != host or env.get('GOOS') != 'linux' or env.get('GOARCH') != target.split('/')[1]:
        raise ValueError('Stock DNS native gate requires its matching completed Linux bundle')
    # The exact completed core must execute the shared mixed-inbound DNS rules
    # against real UDP/TCP responders. Cache-enabled negative controls must
    # expose stale success; the shipping uncached path must reject it.
    dns_env = {**env, 'ROUTERVPN_STOCK_DNS_CORE': str(Path(bundle).resolve()/binary_name(target)),
               'ROUTERVPN_STOCK_DNS_CORE_SHA256': hashlib.sha256((Path(bundle)/binary_name(target)).read_bytes()).hexdigest()}
    output = run(['go', 'test', '-json', '-race', '-tags=routervpn_stock_dns_native', './cmd/client',
                  '-run', '^TestLegacyStandardDNSPinnedCore$', '-count=1', '-timeout=60s'],
                 cwd=ROOT, env=dns_env, timeout=300)
    verify_linux_stock_dns_verdicts(output)
    verify_linux_standard_configs(bundle, env)
    print('Native retained stock DNS: exact parent and four UDP/TCP uncached/cache-control cases PASS', flush=True)


def verify_installed_linux_host(source, bundle, target, env):
    if target not in ('linux/amd64', 'linux/arm64') or env.get('GOOS') != 'linux' or env.get('GOARCH') != target.split('/')[1]:
        raise ValueError('Installed Linux host gate requires its matching complete native target')
    # The final installed-host gate consumes the completed bundle, including
    # native libraries and Tor, after every original payload/provenance check.
    # It runs before stage publication and uses the ordinary app verifier.
    reuse(bundle, target, env=env)
    verify_linux_stock_dns(bundle, target, env)
    run([sys.executable, ROOT/'deploy/test_linux_node_host_tun_runner.py'], cwd=ROOT, env=env, timeout=60)
    run([sys.executable, ROOT/'deploy/test_linux_node_host_tun.py', source, '--bundle', bundle], cwd=ROOT, env=env, timeout=2400)


def verify_installed_darwin_host(source, bundle, target, env):
    if env.get('ROUTERVPN_DARWIN_NATIVE_HOST_ACCEPTANCE') != '1':
        return
    host = 'darwin/'+{'x86_64': 'amd64', 'arm64': 'arm64'}.get(platform.machine(), '')
    if platform.system() != 'Darwin' or target != host or env.get('GOOS') != 'darwin' or env.get('GOARCH') != target.split('/')[1]:
        raise ValueError('Explicit Darwin native acceptance requires its matching disposable host')
    reuse(bundle, target, env=env)
    original = hashlib.sha256((Path(bundle)/'NATIVE-RUNTIME.json').read_bytes()).hexdigest()
    run([sys.executable, ROOT/'deploy/test_macos_external_host_runner.py'], cwd=ROOT, env=env, timeout=60)
    command = [sys.executable, ROOT/'deploy/test_macos_external_host.py', '--bundle', bundle]
    if source is not None:
        command += ['--source', source]
    output = run(command, cwd=ROOT, env=env, timeout=1800)
    prefix = 'Native Darwin retained external acceptance: '
    records = [line[len(prefix):] for line in output.splitlines() if line.startswith(prefix)]
    if len(records) != 1:
        raise ValueError('Explicit Darwin native acceptance omitted its unique exact receipt')
    def unique(fields):
        result = {}
        for key, value in fields:
            if key in result:
                raise ValueError('Native Darwin receipt repeated a field')
            result[key] = value
        return result
    receipt = json.loads(records[0], object_pairs_hook=unique)
    if (type(receipt.get('schema')) is not int or receipt.get('schema') != 1 or receipt.get('native') is not True or receipt.get('target') != target
            or receipt.get('source_sha256') != digest() or receipt.get('bundle_sha256') != original
            or receipt.get('cases') != ['shadowsocks', 'http-connect', 'https-connect', 'hysteria2', 'hysteria2-aes', 'hysteria2-aes-xor', 'wireguard', 'wireguard-always', 'wireguard-auto', 'socks5', 'socks5-always', 'amneziawg-fast', 'amneziawg-fast-always', 'amneziawg-strong', 'amneziawg-strong-always', 'openvpn-tcp', 'openvpn-tcp-always', 'openvpn-udp', 'openvpn-udp-always', 'openvpn-tcp-fallback', 'openvpn-tcp-fallback-always', 'openvpn-mixed-fallback', 'openvpn-mixed-fallback-always', 'wg-entry-ss', 'wg-entry-ss-always', 'awg-entry-ss-fast', 'awg-entry-ss-fast-always', 'awg-entry-ss-strong', 'awg-entry-ss-strong-always', 'wg-entry-http', 'wg-entry-http-always', 'wg-entry-https', 'wg-entry-https-always', 'awg-entry-http-fast', 'awg-entry-http-fast-always', 'awg-entry-http-strong', 'awg-entry-http-strong-always', 'awg-entry-https-fast', 'awg-entry-https-fast-always', 'awg-entry-https-strong', 'awg-entry-https-strong-always', 'wg-entry-hysteria2', 'wg-entry-hysteria2-always', 'awg-entry-hysteria2-fast', 'awg-entry-hysteria2-fast-always', 'awg-entry-hysteria2-strong', 'awg-entry-hysteria2-strong-always', 'wg-entry-socks5', 'wg-entry-socks5-always', 'awg-entry-socks5-fast', 'awg-entry-socks5-fast-always', 'awg-entry-socks5-strong', 'awg-entry-socks5-strong-always', 'wg-entry-hysteria2-aes', 'wg-entry-hysteria2-aes-always', 'wg-entry-hysteria2-aes-xor', 'wg-entry-hysteria2-aes-xor-always', 'awg-entry-hysteria2-fast-aes', 'awg-entry-hysteria2-fast-aes-always', 'awg-entry-hysteria2-fast-aes-xor', 'awg-entry-hysteria2-fast-aes-xor-always', 'awg-entry-hysteria2-strong-aes', 'awg-entry-hysteria2-strong-aes-always', 'awg-entry-hysteria2-strong-aes-xor', 'awg-entry-hysteria2-strong-aes-xor-always', 'wg-entry-wireguard', 'wg-entry-wireguard-always', 'awg-entry-wireguard-fast', 'awg-entry-wireguard-fast-always', 'awg-entry-wireguard-strong', 'awg-entry-wireguard-strong-always', 'wg-entry-amneziawg-fast', 'wg-entry-amneziawg-fast-always', 'wg-entry-amneziawg-strong', 'wg-entry-amneziawg-strong-always', 'awg-entry-fast-amneziawg-fast', 'awg-entry-fast-amneziawg-fast-always', 'awg-entry-fast-amneziawg-strong', 'awg-entry-fast-amneziawg-strong-always', 'awg-entry-strong-amneziawg-fast', 'awg-entry-strong-amneziawg-fast-always', 'awg-entry-strong-amneziawg-strong', 'awg-entry-strong-amneziawg-strong-always', 'wg-entry-openvpn-tcp', 'wg-entry-openvpn-tcp-always', 'wg-entry-openvpn-udp', 'wg-entry-openvpn-udp-always', 'wg-entry-openvpn-tcp-fallback', 'wg-entry-openvpn-tcp-fallback-always', 'wg-entry-openvpn-mixed-fallback', 'wg-entry-openvpn-mixed-fallback-always', 'awg-entry-fast-openvpn-tcp', 'awg-entry-fast-openvpn-tcp-always', 'awg-entry-fast-openvpn-udp', 'awg-entry-fast-openvpn-udp-always', 'awg-entry-fast-openvpn-tcp-fallback', 'awg-entry-fast-openvpn-tcp-fallback-always', 'awg-entry-fast-openvpn-mixed-fallback', 'awg-entry-fast-openvpn-mixed-fallback-always', 'awg-entry-strong-openvpn-tcp', 'awg-entry-strong-openvpn-tcp-always', 'awg-entry-strong-openvpn-udp', 'awg-entry-strong-openvpn-udp-always', 'awg-entry-strong-openvpn-tcp-fallback', 'awg-entry-strong-openvpn-tcp-fallback-always', 'awg-entry-strong-openvpn-mixed-fallback', 'awg-entry-strong-openvpn-mixed-fallback-always', 'ss-entry-aes128-ss-aes128', 'ss-entry-aes128-ss-aes128-always', 'ss-entry-aes128-ss-aes256', 'ss-entry-aes128-ss-aes256-always', 'ss-entry-aes128-ss-chacha', 'ss-entry-aes128-ss-chacha-always', 'ss-entry-aes256-ss-aes128', 'ss-entry-aes256-ss-aes128-always', 'ss-entry-aes256-ss-aes256', 'ss-entry-aes256-ss-aes256-always', 'ss-entry-aes256-ss-chacha', 'ss-entry-aes256-ss-chacha-always', 'ss-entry-chacha-ss-aes128', 'ss-entry-chacha-ss-aes128-always', 'ss-entry-chacha-ss-aes256', 'ss-entry-chacha-ss-aes256-always', 'ss-entry-chacha-ss-chacha', 'ss-entry-chacha-ss-chacha-always', 'ss-entry-aes128-http', 'ss-entry-aes128-http-always', 'ss-entry-aes128-https', 'ss-entry-aes128-https-always', 'ss-entry-aes256-http', 'ss-entry-aes256-http-always', 'ss-entry-aes256-https', 'ss-entry-aes256-https-always', 'ss-entry-chacha-http', 'ss-entry-chacha-http-always', 'ss-entry-chacha-https', 'ss-entry-chacha-https-always', 'ss-entry-aes128-hysteria', 'ss-entry-aes128-hysteria-always', 'ss-entry-aes256-hysteria', 'ss-entry-aes256-hysteria-always', 'ss-entry-chacha-hysteria', 'ss-entry-chacha-hysteria-always', 'ss-entry-aes256-hysteria-layers00-always', 'ss-entry-aes256-hysteria-layers01-always', 'ss-entry-aes256-hysteria-layers02-always', 'ss-entry-aes256-hysteria-layers10-always', 'ss-entry-aes256-hysteria-layers11-always', 'ss-entry-aes256-hysteria-layers12-always', 'ss-entry-aes256-hysteria-layers20-always', 'ss-entry-aes256-hysteria-layers21-always', 'ss-entry-aes256-hysteria-layers22-always', 'ss-entry-aes256-ss-chacha-layers00-always', 'ss-entry-aes256-ss-chacha-layers01-always', 'ss-entry-aes256-ss-chacha-layers02-always', 'ss-entry-aes256-ss-chacha-layers10-always', 'ss-entry-aes256-ss-chacha-layers11-always', 'ss-entry-aes256-ss-chacha-layers12-always', 'ss-entry-aes256-ss-chacha-layers20-always', 'ss-entry-aes256-ss-chacha-layers21-always', 'ss-entry-aes256-ss-chacha-layers22-always', 'hysteria2-aes-wrong-layer-key', 'hysteria2-aes-wrong-inner-key', 'hysteria2-aes-xor-wrong-layer-key', 'hysteria2-aes-xor-wrong-inner-key', 'hysteria2-aes-xor-wrong-whitening', 'wireguard-wrong-client-key', 'wireguard-wrong-psk', 'wireguard-wrong-dns', 'wireguard-wrong-trust', 'wireguard-wrong-exit', 'socks5-wrong-password', 'socks5-auth-downgrade', 'socks5-relay-domain', 'socks5-control-eof', 'socks5-wrong-dns', 'socks5-wrong-trust', 'socks5-wrong-exit', 'amneziawg-fast-wrong-client-key', 'amneziawg-strong-wrong-psk', 'amneziawg-fast-wrong-parameters', 'amneziawg-strong-wrong-parameters', 'amneziawg-strong-wrong-dns', 'amneziawg-strong-wrong-trust', 'amneziawg-strong-wrong-exit', 'openvpn-tcp-wrong-control', 'openvpn-udp-wrong-control', 'openvpn-tcp-wrong-provider-trust', 'openvpn-udp-wrong-password', 'openvpn-tcp-wrong-username', 'openvpn-udp-wrong-dns', 'openvpn-tcp-wrong-trust', 'openvpn-udp-wrong-exit', 'wg-entry-ss-wrong-entry-key', 'wg-entry-ss-wrong-entry-public', 'wg-entry-ss-wrong-exit-key', 'wg-entry-ss-wrong-dns', 'wg-entry-ss-wrong-trust', 'wg-entry-ss-wrong-exit', 'awg-entry-ss-fast-wrong-entry-key', 'awg-entry-ss-strong-wrong-entry-psk', 'awg-entry-ss-fast-wrong-entry-parameters', 'awg-entry-ss-strong-wrong-entry-parameters', 'awg-entry-ss-strong-wrong-entry-public', 'awg-entry-ss-strong-wrong-exit-key', 'awg-entry-ss-strong-wrong-dns', 'awg-entry-ss-strong-wrong-trust', 'awg-entry-ss-strong-wrong-exit', 'wg-entry-http-wrong-entry-key', 'wg-entry-http-wrong-exit-username', 'wg-entry-http-wrong-exit-key', 'wg-entry-http-wrong-dns', 'wg-entry-http-wrong-exit', 'wg-entry-https-wrong-entry-public', 'wg-entry-https-wrong-exit-server-name', 'wg-entry-https-wrong-exit-key', 'wg-entry-https-wrong-trust', 'awg-entry-http-fast-wrong-entry-parameters', 'awg-entry-https-strong-wrong-entry-parameters', 'awg-entry-https-strong-wrong-exit-key', 'wg-entry-hysteria2-wrong-entry-key', 'wg-entry-hysteria2-wrong-entry-public', 'wg-entry-hysteria2-wrong-exit-key', 'wg-entry-hysteria2-wrong-exit-server-name', 'wg-entry-hysteria2-wrong-exit-address', 'wg-entry-hysteria2-wrong-dns', 'wg-entry-hysteria2-wrong-trust', 'wg-entry-hysteria2-wrong-exit', 'awg-entry-hysteria2-fast-wrong-entry-parameters', 'awg-entry-hysteria2-strong-wrong-entry-parameters', 'awg-entry-hysteria2-strong-wrong-entry-psk', 'wg-entry-socks5-wrong-entry-key', 'wg-entry-socks5-wrong-entry-public', 'wg-entry-socks5-wrong-exit-username', 'wg-entry-socks5-wrong-exit-key', 'wg-entry-socks5-auth-downgrade', 'wg-entry-socks5-relay-domain', 'wg-entry-socks5-control-eof', 'wg-entry-socks5-relay-route', 'wg-entry-socks5-wrong-exit-address', 'wg-entry-socks5-wrong-dns', 'wg-entry-socks5-wrong-trust', 'wg-entry-socks5-wrong-exit', 'awg-entry-socks5-fast-wrong-entry-parameters', 'awg-entry-socks5-strong-wrong-entry-parameters', 'awg-entry-socks5-strong-wrong-entry-psk', 'wg-entry-hysteria2-aes-wrong-entry-key', 'wg-entry-hysteria2-aes-wrong-layer-key', 'wg-entry-hysteria2-aes-wrong-inner-key', 'wg-entry-hysteria2-aes-wrong-dns', 'wg-entry-hysteria2-aes-wrong-trust', 'wg-entry-hysteria2-aes-wrong-exit', 'wg-entry-hysteria2-aes-xor-wrong-entry-public', 'wg-entry-hysteria2-aes-xor-wrong-layer-key', 'wg-entry-hysteria2-aes-xor-wrong-inner-key', 'wg-entry-hysteria2-aes-xor-wrong-whitening', 'wg-entry-hysteria2-aes-xor-wrong-layer-route', 'awg-entry-hysteria2-fast-aes-wrong-entry-parameters', 'awg-entry-hysteria2-fast-aes-wrong-layer-key', 'awg-entry-hysteria2-strong-aes-xor-wrong-entry-psk', 'awg-entry-hysteria2-strong-aes-xor-wrong-layer-key', 'awg-entry-hysteria2-strong-aes-xor-wrong-whitening', 'wg-entry-wireguard-wrong-entry-key', 'wg-entry-wireguard-wrong-entry-psk', 'wg-entry-wireguard-wrong-entry-public', 'wg-entry-wireguard-wrong-exit-key', 'wg-entry-wireguard-wrong-exit-peer-key', 'wg-entry-wireguard-wrong-exit-psk', 'wg-entry-wireguard-wrong-exit-address', 'wg-entry-wireguard-wrong-dns', 'wg-entry-wireguard-wrong-trust', 'wg-entry-wireguard-wrong-exit', 'awg-entry-wireguard-fast-wrong-entry-parameters', 'awg-entry-wireguard-strong-wrong-entry-parameters', 'awg-entry-wireguard-strong-wrong-entry-psk', 'awg-entry-wireguard-strong-wrong-exit-key', 'awg-entry-wireguard-strong-wrong-exit-peer-key', 'awg-entry-wireguard-strong-wrong-exit-psk', 'wg-entry-amneziawg-fast-wrong-exit-key', 'wg-entry-amneziawg-fast-wrong-exit-peer-key', 'wg-entry-amneziawg-fast-wrong-exit-psk', 'wg-entry-amneziawg-fast-wrong-exit-parameters', 'wg-entry-amneziawg-fast-wrong-exit-padding', 'wg-entry-amneziawg-fast-wrong-exit-address', 'wg-entry-amneziawg-fast-wrong-dns', 'wg-entry-amneziawg-fast-wrong-trust', 'wg-entry-amneziawg-fast-wrong-exit', 'wg-entry-amneziawg-strong-wrong-exit-key', 'wg-entry-amneziawg-strong-wrong-exit-peer-key', 'wg-entry-amneziawg-strong-wrong-exit-psk', 'wg-entry-amneziawg-strong-wrong-exit-parameters', 'wg-entry-amneziawg-strong-wrong-exit-padding', 'wg-entry-amneziawg-strong-wrong-exit-address', 'wg-entry-amneziawg-strong-wrong-dns', 'wg-entry-amneziawg-strong-wrong-trust', 'wg-entry-amneziawg-strong-wrong-exit', 'awg-entry-fast-amneziawg-strong-wrong-entry-parameters', 'awg-entry-strong-amneziawg-fast-wrong-entry-parameters', 'awg-entry-strong-amneziawg-strong-wrong-entry-psk', 'wg-entry-amneziawg-strong-wrong-entry-key', 'wg-entry-amneziawg-strong-wrong-entry-psk', 'wg-entry-amneziawg-strong-wrong-entry-public', 'wg-entry-openvpn-tcp-wrong-control', 'wg-entry-openvpn-udp-wrong-control', 'wg-entry-openvpn-tcp-wrong-provider-trust', 'wg-entry-openvpn-udp-wrong-password', 'wg-entry-openvpn-tcp-wrong-username', 'wg-entry-openvpn-udp-wrong-dns', 'wg-entry-openvpn-tcp-wrong-trust', 'wg-entry-openvpn-udp-wrong-exit', 'wg-entry-openvpn-udp-wrong-exit-address', 'wg-entry-openvpn-tcp-wrong-entry-key', 'wg-entry-openvpn-udp-wrong-entry-psk', 'wg-entry-openvpn-tcp-wrong-entry-public', 'awg-entry-fast-openvpn-udp-wrong-entry-parameters', 'awg-entry-strong-openvpn-tcp-wrong-entry-parameters', 'awg-entry-strong-openvpn-udp-wrong-entry-psk', 'ss-entry-aes256-ss-aes256-wrong-entry-key', 'ss-entry-aes256-ss-aes256-wrong-entry-method', 'ss-entry-aes256-ss-aes256-wrong-entry-public', 'ss-entry-aes256-ss-aes256-wrong-exit-key', 'ss-entry-aes256-ss-aes256-wrong-exit-method', 'ss-entry-aes256-ss-aes256-wrong-exit-address', 'ss-entry-aes256-ss-aes256-wrong-dns', 'ss-entry-aes256-ss-aes256-wrong-trust', 'ss-entry-aes256-ss-aes256-wrong-exit', 'ss-entry-aes256-http-wrong-entry-key', 'ss-entry-aes256-https-wrong-entry-method', 'ss-entry-aes256-http-wrong-entry-public', 'ss-entry-aes256-http-wrong-exit-username', 'ss-entry-aes256-http-wrong-exit-key', 'ss-entry-aes256-http-wrong-exit-address', 'ss-entry-aes256-http-wrong-dns', 'ss-entry-aes256-http-wrong-exit', 'ss-entry-aes256-https-wrong-exit-username', 'ss-entry-aes256-https-wrong-exit-key', 'ss-entry-aes256-https-wrong-exit-server-name', 'ss-entry-aes256-https-wrong-trust', 'ss-entry-aes256-hysteria-wrong-entry-key', 'ss-entry-aes256-hysteria-wrong-entry-method', 'ss-entry-aes256-hysteria-wrong-entry-public', 'ss-entry-aes256-hysteria-wrong-exit-key', 'ss-entry-aes256-hysteria-wrong-exit-address', 'ss-entry-aes256-hysteria-wrong-exit-server-name', 'ss-entry-aes256-hysteria-wrong-final-trust', 'ss-entry-aes256-hysteria-wrong-dns', 'ss-entry-aes256-hysteria-wrong-exit', 'ss-entry-aes256-hysteria-layers22-wrong-entry-layer', 'ss-entry-aes256-hysteria-layers22-wrong-final-layer', 'ss-entry-aes256-hysteria-layers22-wrong-entry-whitening', 'ss-entry-aes256-hysteria-layers22-wrong-final-whitening', 'ss-entry-aes256-hysteria-layers22-wrong-entry-public', 'ss-entry-aes256-hysteria-layers22-wrong-dns', 'ss-entry-aes256-hysteria-layers22-wrong-exit', 'ss-entry-aes256-hysteria-layers22-wrong-final-trust', 'ss-entry-aes256-ss-chacha-layers22-wrong-entry-layer', 'ss-entry-aes256-ss-chacha-layers22-wrong-final-layer', 'ss-entry-aes256-ss-chacha-layers22-wrong-entry-whitening', 'ss-entry-aes256-ss-chacha-layers22-wrong-final-whitening', 'ss-entry-aes256-ss-chacha-layers22-wrong-entry-public', 'ss-entry-aes256-ss-chacha-layers22-wrong-dns', 'ss-entry-aes256-ss-chacha-layers22-wrong-exit', 'ss-entry-aes256-ss-chacha-layers22-wrong-trust']
            or not re.fullmatch('[0-9a-f]{64}', receipt.get('sealed_bundle_sha256', ''))
            or set(receipt.get('images', {})) != {'controller', 'peer'}
            or any(not re.fullmatch('[0-9a-f]{64}', value) for value in receipt['images'].values())
            or set(receipt.get('sources', {})) != {'application', 'peer'}
            or any(not group or any(not isinstance(name, str) or not name or name.startswith('/') or '..' in name.split('/')
                                    or not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value)
                                    for name, value in group.items()) for group in receipt['sources'].values())):
        raise ValueError('Native Darwin host receipt changed its exact source, bundle or protocol coverage')
    if hashlib.sha256((Path(bundle)/'NATIVE-RUNTIME.json').read_bytes()).hexdigest() != original:
        raise ValueError('Native Darwin acceptance changed its delivered bundle')
    print(output, flush=True)


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


def build(target, destination, *, source=None, xray=None, pq=None, cache=None, tor_compiled=None, dnssec_compiled=None):
    env, policy = environment(target, compiler=True), digest()
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
        if target.startswith('darwin/'):
            verify_installed_darwin_host(None, destination, target, env)
        elif platform.system() == 'Linux' and target == 'linux/'+{'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine(), ''):
            verify_linux_stock_dns(destination, target, env)
            DNSSEC.test_native_bundle(destination, target, env)
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
        POLICY.prepare_native(source, xray)
        PERFORMANCE.prepare(source)
        OPENVPN.prepare(source)
        EXTERNAL.prepare(source, env=env)
        BUFFERS.prepare(source)
        run(['go', 'mod', 'tidy'], cwd=source, env=env)
        run(['go', 'mod', 'verify'], cwd=source, env=env)
        POLICY.AMNEZIA.verify(source)
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
        host = ('darwin' if platform.system() == 'Darwin' else platform.system().lower())+'/'+{
            'x86_64': 'amd64', 'AMD64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64', 'ARM64': 'arm64'}.get(platform.machine(), '')
        if target == host:
            # These execute the actual command owner and Box proof factory.
            # Run before installing the executable-only Cronet loader, whose
            # sealed adjacent library belongs to the final package location.
            # The pinned Go toolchain supports race on all shipped native
            # desktop hosts except Windows ARM64 (internal/platform/supported.go).
            race = [] if target == 'windows/arm64' else ['-race']
            run([sys.executable, ROOT/'deploy/test_hysteria2_deadlines_pinned.py', source],
                env=env, timeout=400)
            run([sys.executable, ROOT/'deploy/test_amnezia_timers_pinned.py', source],
                env=env, timeout=200)
            run([sys.executable, ROOT/'deploy/test_gvisor_forwarder_pinned.py', source],
                env=env, timeout=200)
            run(['go', 'test', *race, '-mod=readonly', '-tags='+','.join(tags(target)),
                 '-ldflags=-checklinkname=0', './protocol/wireguard', '-run', '^TestRouterVPNWireGuard',
                 '-count=1', '-timeout=60s'], cwd=source, env=env, timeout=120)
            run(['go', 'test', *race, '-mod=readonly', '-tags='+','.join(tags(target)),
                 '-ldflags=-checklinkname=0', './cmd/sing-box', '-run', '^TestRouterVPN(Desktop(External|MTU|DNS|Tor)|NodeMTU)',
                 '-count=1', '-timeout=120s'], cwd=source, env=env, timeout=600)
            run(['go', 'test', *race, '-mod=readonly', '-tags='+','.join(tags(target)),
                 '-ldflags=-checklinkname=0', './routervpn/desktoppt', '-run', '^Test(RouterVPN(DesktopTorPT|ExternalPhysical|NodePhysicalUnix|PhysicalFactory|PhysicalTunnel|LinuxPhysicalFactory|DarwinPhysicalFactory|WindowsPhysicalFactory)|DesktopTorNetworkOwner)',
                 '-count=1', '-timeout=120s'], cwd=source, env=env, timeout=600)
            run(['go', 'test', *race, '-mod=readonly', '-tags='+','.join(tags(target)),
                 '-ldflags=-checklinkname=0', './routervpn/mobiletor', '-run', '^TestDesktopSocket',
                 '-count=1', '-timeout=60s'], cwd=source, env=env, timeout=120)
            if target.startswith(('linux/', 'windows/')):
                # Private Node startup uses its own sealed policy and eager
                # WG/AWG lower phase. The exact native command/Box tests keep
                # OS permits and TUN as explicit composition boundaries.
                # At 74bd942a both Linux architectures completed all 19
                # baseline suites, then exhausted the old 900s aggregate at
                # the first of 48 compiled controls (run 41393374409, jobs
                # 125110055580 and 125110055657). Keep serial peer execution
                # and every individual compiler/suite/control deadline; the
                # full expanded Linux workload needs its own bounded budget.
                # At f41514f7, Windows AMD64 completed all 17 baselines and
                # 16 of 34 compiled controls, then its 1200s parent stopped
                # the next compile (run 41507677662, job 125493850421).
                # Give the complete Windows workload the same aggregate
                # budget; compiler, suite and control deadlines stay intact.
                run([sys.executable, ROOT/'deploy/test_desktop_node_physical.py', source],
                    env=env, timeout=1800)
                if target.startswith('linux/'):
                    # The desktop reference owns its two native builds and
                    # exact traffic matrix. Keep it outside the existing
                    # 1200s imported-peer and 1800s node gate envelopes.
                    # The separate mobile gate owns the libbox parser.
                    run([sys.executable, ROOT/'deploy/test_mobile_imported_socks_xray.py',
                         source, '--reference-only'], env=env, timeout=3000)
                # The PQ matrix uses the same verified native archive and
                # compiler cache, fresh KEM keys, and real packet/Start Layer
                # peers. Native firewall/public admission remains separate.
                run([sys.executable, ROOT/'deploy/test_desktop_node_pq.py', source, pq,
                     '--cache', cache or ROOT/'dist/.native-pq-cache'],
                    env=env, timeout=1800)
                run([sys.executable, ROOT/'deploy/test_desktop_node_max_runner.py'],
                    cwd=ROOT, env=env, timeout=60)
                # Complete MAX retains its mandatory PQ base, middle and
                # outer transport. Prove the full encrypted graph separately
                # from the raw MAX branch and from native firewall admission.
                run([sys.executable, ROOT/'deploy/test_desktop_node_max.py', source, pq,
                     '--cache', cache or ROOT/'dist/.native-pq-cache'],
                    env=env, timeout=5400)
            if target.startswith(('linux/', 'darwin/')):
                run([sys.executable, ROOT/'deploy/test_desktop_socket_uid.py', source],
                    env=env, timeout=300)
            if target.startswith('windows/'):
                run([sys.executable, ROOT/'deploy/test_desktop_windows_identity_runner.py'], cwd=ROOT, env=env)
                run([sys.executable, ROOT/'deploy/test_desktop_windows_identity.py', source],
                    env=env, timeout=600)
                run([sys.executable, ROOT/'deploy/test_desktop_windows_wfp.py', source],
                    env=env, timeout=600)
                run([sys.executable, ROOT/'deploy/test_windows_protection_transfer.py', source],
                    env=env, timeout=600)
                run([sys.executable, ROOT/'deploy/test_windows_protection_observation.py', source],
                    env=env, timeout=600)
                run([sys.executable, ROOT/'deploy/test_windows_external_provider_join.py'], cwd=ROOT, env=env)
                run([sys.executable, ROOT/'deploy/test_windows_node_physical_runner.py'], cwd=ROOT, env=env)
                # Each actual native phase owns its original compiler/test bounds.
                # A full package requires all source-bound phase receipts.
                physical = load('desktop_windows_physical_phases', 'test_windows_node_physical.py')
                physical.execute_partitioned(source, env, run)
                run([sys.executable, ROOT/'deploy/test_windows_node_pq_runner.py'], cwd=ROOT, env=env)
                # Actual matching-host CGO/Rust, isolated sockets and BFE. Only
                # positive PQ execution keeps the shipping predicate unchanged;
                # a separate exact-family-closed control must reject admission.
                run([sys.executable, ROOT/'deploy/test_windows_node_pq.py', source, pq,
                     '--cache', cache or ROOT/'dist/.native-pq-cache'],
                    env=env, timeout=2400)
                run([sys.executable, ROOT/'deploy/test_desktop_windows_traffic.py', source],
                    env=env, timeout=600)
                # This explicit test-only admission overlay proves bootstrap
                # composition before the public Windows capability is opened.
                # Admission must remove --prospective and rerun unchanged code.
                run([sys.executable, ROOT/'deploy/test_windows_physical_bootstrap.py', source, '--prospective'],
                    env=env, timeout=900)
                run([sys.executable, ROOT/'deploy/test_windows_physical_tunnel.py', source],
                    env=env, timeout=1200)
            if target.startswith('linux/'):
                run([sys.executable, ROOT/'deploy/test_desktop_command_retirement.py',
                     '--native-core', source, '--tags='+','.join(tags(target))],
                    cwd=ROOT, env=env, timeout=180)
                run([sys.executable, ROOT/'deploy/test_desktop_linux_guardian.py', source],
                    env=env, timeout=300)
                run([sys.executable, ROOT/'deploy/test_linux_node_child_control_runner.py'],
                    cwd=ROOT, env=env, timeout=60)
                run([sys.executable, ROOT/'deploy/test_linux_node_child_control.py', source],
                    env=env, timeout=900)
                run([sys.executable, ROOT/'deploy/test_linux_external_lifecycle_runner.py'],
                    cwd=ROOT, env=env, timeout=60)
                run([sys.executable, ROOT/'deploy/test_linux_external_lifecycle.py', source],
                    env=env, timeout=900)
                run([sys.executable, ROOT/'deploy/test_linux_external_openvpn_runner.py'],
                    cwd=ROOT, env=env, timeout=60)
                run([sys.executable, ROOT/'deploy/test_linux_external_openvpn.py', source, '--pq', pq],
                    env=env, timeout=900)
                run([sys.executable, ROOT/'deploy/test_linux_node_lifecycle_runner.py'],
                    cwd=ROOT, env=env, timeout=60)
                run([sys.executable, ROOT/'deploy/test_linux_node_lifecycle.py', source],
                    env=env, timeout=600)
                run([sys.executable, ROOT/'deploy/test_linux_node_child_tun_runner.py'],
                    cwd=ROOT, env=env, timeout=60)
                run([sys.executable, ROOT/'deploy/test_linux_node_child_tun.py', source],
                    env=env, timeout=1500)
            if target.startswith('darwin/'):
                run([sys.executable, ROOT/'deploy/test_desktop_darwin_route_runner.py'],
                    cwd=ROOT, env=env, timeout=60)
                run([sys.executable, ROOT/'deploy/test_desktop_darwin_route.py', source, '--mutations'],
                    env=env, timeout=900)
                run([sys.executable, ROOT/'deploy/test_desktop_darwin_guardian.py', source, '--mutations'],
                    env=env, timeout=1800)
            run(['go', 'test', *race, '-mod=readonly', '-tags='+','.join(tags(target)),
                 '-ldflags=-checklinkname=0', './route', '-run', '^TestRouterVPNDesktopTorNetwork',
                 '-count=1', '-timeout=120s'], cwd=source, env=env, timeout=600)
            run(['go', 'test', *race, '-mod=readonly', '-tags='+','.join(tags(target)),
                 '-ldflags=-checklinkname=0', '.', '-run', '^TestRouterVPNDesktop(Tor|External)',
                 '-count=1', '-timeout=180s' if target.startswith('linux/') else '-timeout=120s'],
                cwd=source, env=env, timeout=600)
        if target.startswith('linux/'):
            validator = DNSSEC.build(target, temp/'dnssec-bundle', compiled=dnssec_compiled, env=env)
            for name in DNSSEC.names(target):
                shutil.copyfile(validator/name, stage/name)
            run([sys.executable, ROOT/'deploy/test_desktop_dnssec_namespace.py',
                 source, validator, target], cwd=ROOT, env=env, timeout=900)
            run([sys.executable, ROOT/'deploy/test_desktop_dnssec_command.py',
                 '--source', source, '--bundle', validator, '--target', target],
                cwd=ROOT, env=env, timeout=900)
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
            if target.startswith('linux/'):
                verify_installed_linux_host(source, stage, target, env)
            elif target.startswith('darwin/'):
                verify_installed_darwin_host(source, stage, target, env)
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
