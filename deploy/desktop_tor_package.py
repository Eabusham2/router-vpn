#!/usr/bin/env python3
"""Verify the pinned desktop Tor payload and exercise its offline control owner.

The outer exact-source native bundle establishes distribution trust. These
checks bind its Tor process, source licenses, padding extension and executable
architecture; a successful --version command alone never establishes support.
"""
from pathlib import Path
import hashlib
import hmac
import importlib.util
import json
import os
import platform
import re
import socket
import stat
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ('linux/amd64', 'linux/arm64', 'darwin/amd64', 'darwin/arm64', 'windows/amd64', 'windows/arm64')
VERSION = '0.4.9.14'
REVISION = '4a522a3ca491c6c04d4a44cb006b92101c42efc1'
SOURCE_SHA256 = 'ca52ffdbda44d1554c6ac0cadd7ce84bca2c1e1f46f5ca6c5aaab1d34bf0459f'
PADDING_SHA256 = '011dc1e4c3e3b60fcc3b72ec180252cff3003c37b03fbed132f2fe58e2cf8be5'
RECEIPT, SOURCE, PADDING, LICENSES = 'TOR-RUNTIME.json', 'TOR-SOURCE-LOCK.json', 'TOR-PADDING-SOURCE-LOCK.json', 'TOR-LICENSES.json'
MAX_BINARY, MAX_RECORD, MAX_LICENSES = 64 << 20, 32 << 10, 256 << 10
TEST_SELECTORS = ('routervpn_padding/..', 'routervpn_lastrelay/..', 'relaycrypt/..', 'cellqueue/..')
STATIC_LIBRARIES = frozenset(('libssl.a', 'libcrypto.a', 'libevent.a', 'libz.a'))
BUILD_INPUTS = frozenset(('deploy/build-desktop-tor.py', 'deploy/desktop_tor_package.py',
    'deploy/build-server-tor.py', 'server/scripts/server_tor_package.py',
    'deploy/build-mobile-tor-package.py', 'deploy/install-desktop-windows-toolchain.py',
    'mobile/torpack/sources.json', 'deploy/apply-tor-padding.py',
    'mobile/tor/padding-source-lock.json', 'mobile/tor/padding-integration.patch',
    'mobile/tor/routervpn_padding.c', 'mobile/tor/routervpn_padding.h', 'mobile/tor/test_routervpn_padding.c',
    'mobile/tor/routervpn_lastrelay.c', 'mobile/tor/routervpn_lastrelay.h', 'mobile/tor/test_routervpn_lastrelay.c'))
SYSTEM_DLLS = frozenset(('advapi32.dll', 'bcrypt.dll', 'crypt32.dll', 'gdi32.dll',
    'iphlpapi.dll', 'kernel32.dll', 'msvcrt.dll', 'ntdll.dll', 'secur32.dll', 'shell32.dll',
    # The pinned Tor Windows path/glob code imports PathMatchSpecA from the OS.
    'shlwapi.dll', 'user32.dll', 'userenv.dll', 'ws2_32.dll'))
APPLE_LIBRARIES = frozenset(('/usr/lib/libSystem.B.dylib', '/usr/lib/libresolv.9.dylib'))
CAPABILITY = ('250 version=1 direction=outgoing min_rate_kbps=32 max_rate_kbps=192 '
    'default_rate_kbps=192 max_ttl_ms=10000 max_pending_cells=1 accounting=tor-link-cell '
    'username_hex_lengths=32,64 password_hex_length=64 generation_highwater=0')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


SERVER = load('desktop_tor_server_format', ROOT / 'server/scripts/server_tor_package.py')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def executable_target(target):
    if target not in TARGETS:
        raise ValueError('Unsupported desktop Tor target')
    # Only this user-mode helper is emulated. The main app and TUN driver keep
    # their native ARM64 target and their separate build/acceptance gates.
    return 'windows/amd64' if target == 'windows/arm64' else target


def binary_name(target):
    executable_target(target)
    return 'tor-routervpn' + ('.exe' if target.startswith('windows/') else '')


def execution(target):
    executable_target(target)
    return 'windows11-amd64-emulation' if target == 'windows/arm64' else 'native'


def names(target):
    return {binary_name(target), RECEIPT, SOURCE, PADDING, LICENSES}


def bound(name, target):
    if name == binary_name(target):
        return MAX_BINARY
    if name in (RECEIPT, SOURCE, PADDING):
        return MAX_RECORD
    if name == LICENSES:
        return MAX_LICENSES
    raise ValueError('Unowned desktop Tor payload')


def unsafe(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def read_regular(path, maximum):
    path = Path(os.path.abspath(path))
    for parent in path.parents:
        info = parent.lstat()
        if unsafe(info) or not stat.S_ISDIR(info.st_mode):
            raise ValueError('Desktop Tor payload traverses an unowned directory')
    before = path.lstat()
    if unsafe(before) or not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
        raise ValueError('Desktop Tor payload is missing, linked or oversized')
    with path.open('rb') as source:
        opened = os.fstat(source.fileno())
        if not os.path.samestat(before, opened):
            raise ValueError('Desktop Tor payload changed before opening')
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    current = path.lstat()
    identity = lambda v: (v.st_dev, v.st_ino, v.st_mode, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
    # CPython on Windows can expose birth time through lstat's ctime and
    # metadata-change time through fstat's ctime (python/cpython#157671).
    # Compare each API's own before/after observations, retaining the strict
    # cross-API file identity and size checks instead of dropping timestamps.
    if (identity(before) != identity(current) or identity(opened) != identity(after) or
            not os.path.samestat(after, current) or unsafe(current) or not stat.S_ISREG(after.st_mode) or
            len(raw) != before.st_size or len(raw) != after.st_size):
        raise ValueError('Desktop Tor payload changed while reading')
    return raw


def payload(raw):
    return {'size': len(raw), 'sha256': digest(raw)}


def combined(inputs):
    return digest(b''.join(name.encode() + b'\0' + value.encode() + b'\0' for name, value in sorted(inputs.items())))


def host_target():
    system = {'Linux': 'linux', 'Darwin': 'darwin', 'Windows': 'windows'}.get(platform.system())
    arch = {'x86_64': 'amd64', 'AMD64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64', 'ARM64': 'arm64'}.get(platform.machine())
    target = str(system) + '/' + str(arch)
    if target not in TARGETS:
        raise ValueError('Desktop Tor requires a supported actual test host')
    return target


def require_host(target):
    if host_target() != target:
        raise ValueError('Desktop Tor acceptance must run on the exact package target')
    if target == 'windows/arm64' and (platform.version().split('.')[:2] != ['10', '0'] or
            int(platform.version().split('.')[2]) < 22000):
        raise ValueError('The x64 Tor helper requires Windows 11 on ARM64')


def macho_identity(raw, target):
    machine = {'darwin/amd64': 0x1000007, 'darwin/arm64': 0x100000c}.get(target)
    if len(raw) < 32 or struct.unpack_from('<I', raw)[0] != 0xfeedfacf:
        raise ValueError('Desktop Tor requires a thin little-endian Mach-O64 executable')
    _, cpu, _, kind, count, size, flags, _ = struct.unpack_from('<8I', raw)
    if cpu != machine or kind != 2 or not 0 < count <= 256 or not 0 < size <= len(raw) - 32 or not flags & 0x200000:
        raise ValueError('Desktop Tor Mach-O target, commands or PIE identity changed')
    offset, libraries = 32, []
    for _ in range(count):
        if offset + 8 > 32 + size:
            raise ValueError('Truncated desktop Tor Mach-O command')
        command, length = struct.unpack_from('<II', raw, offset)
        if length < 8 or length % 8 or offset + length > 32 + size:
            raise ValueError('Malformed desktop Tor Mach-O command')
        if command in (0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023):
            if length < 24:
                raise ValueError('Truncated desktop Tor Mach-O dependency')
            start = struct.unpack_from('<I', raw, offset + 8)[0]
            if not 24 <= start < length:
                raise ValueError('Malformed desktop Tor Mach-O dependency path')
            end = raw.find(b'\0', offset + start, offset + length)
            if end < 0:
                raise ValueError('Unterminated desktop Tor Mach-O dependency path')
            library = raw[offset + start:end].decode('ascii')
            if library not in APPLE_LIBRARIES:
                raise ValueError('Desktop Tor imports an unowned macOS library: ' + library)
            libraries.append(library)
        if command == 0x8000001c:
            raise ValueError('Desktop Tor must not search a runtime library path')
        offset += length
    if offset != 32 + size or '/usr/lib/libSystem.B.dylib' not in libraries:
        raise ValueError('Desktop Tor Mach-O command closure is incomplete')
    return {'format': 'Mach-O64', 'machine': cpu, 'libraries': sorted(set(libraries))}


def executable_identity(raw, target):
    target = executable_target(target)
    if target.startswith('linux/'):
        value = SERVER.elf_identity(raw, target)
        return {'format': 'ELF64', 'machine': value['elf_machine'], 'libraries': []}
    if target.startswith('darwin/'):
        return macho_identity(raw, target)
    libraries = pe_dependencies(raw, target)
    for library in libraries:
        if library not in SYSTEM_DLLS and not re.fullmatch(r'(?:api|ext)-ms-win-[a-z0-9-]+-l\d+-\d+-\d+\.dll', library):
            raise ValueError('Desktop Tor imports an unowned Windows DLL: ' + library)
    return {'format': 'PE32+', 'machine': 0x8664, 'libraries': sorted(libraries)}


def offline_receipt():
    return {**SERVER.offline_receipt(), 'scope': 'offline-disabled-network-loopback-control'}


def strict_equal(value, expected):
    return type(value) is type(expected) and (all(k in value and strict_equal(value[k], v) for k, v in expected.items())
        and len(value) == len(expected) if isinstance(expected, dict) else value == expected)


def verify(directory, target, *, source_root=None, exact=True):
    directory = Path(directory)
    if exact and {p.name for p in directory.iterdir()} != names(target):
        raise ValueError('Desktop Tor package contains missing or unowned files')
    data = {name: read_regular(directory / name, bound(name, target)) for name in names(target)}
    lock = SERVER.json_object(data[SOURCE])
    padding = SERVER.json_object(data[PADDING])
    licenses = SERVER.json_object(data[LICENSES])
    record = SERVER.json_object(data[RECEIPT])
    expected_fields = {'schema_version', 'runtime', 'version', 'upstream_revision', 'target', 'executable_target',
        'execution', 'source_lock_sha256', 'padding_lock_sha256', 'padding_version', 'build_inputs',
        'build_inputs_sha256', 'static_dependencies', 'process_source_sha256', 'native_tests',
        'offline_self_test', 'executable_identity', 'files', 'compiler'}
    if (set(record) != expected_fields or type(record.get('schema_version')) is not int or record.get('schema_version') != 1 or
            record.get('runtime') != 'tor-routervpn' or record.get('version') != VERSION or
            record.get('upstream_revision') != REVISION or record.get('target') != target or
            record.get('executable_target') != executable_target(target) or record.get('execution') != execution(target) or
            digest(data[SOURCE]) != SOURCE_SHA256 or record.get('source_lock_sha256') != SOURCE_SHA256 or
            digest(data[PADDING]) != PADDING_SHA256 or record.get('padding_lock_sha256') != PADDING_SHA256 or
            type(record.get('padding_version')) is not int or record.get('padding_version') != 1 or
            padding.get('tor_commit') != REVISION or lock.get('sources', {}).get('tor', {}).get('commit') != REVISION):
        raise ValueError('Desktop Tor source, padding or execution identity changed')
    inputs = record.get('build_inputs')
    if not isinstance(inputs, dict) or set(inputs) != BUILD_INPUTS or any(not SERVER.valid_hash(v) for v in inputs.values()) or combined(inputs) != record.get('build_inputs_sha256'):
        raise ValueError('Desktop Tor build input closure is incomplete')
    if inputs['mobile/torpack/sources.json'] != SOURCE_SHA256 or inputs['mobile/tor/padding-source-lock.json'] != PADDING_SHA256:
        raise ValueError('Desktop Tor source records do not match their build inputs')
    if inputs['mobile/tor/padding-integration.patch'] != padding['patch_sha256'] or any(inputs[name] != entry['sha256'] for name, entry in padding['copies'].items()):
        raise ValueError('Desktop Tor padding inputs differ from the compiled extension')
    if source_root is not None:
        for name, checksum in inputs.items():
            if digest(read_regular(Path(source_root) / name, 64 << 20)) != checksum:
                raise ValueError('Desktop Tor build source changed: ' + name)
    libraries = record.get('static_dependencies')
    if not isinstance(libraries, dict) or set(libraries) != STATIC_LIBRARIES or any(not SERVER.valid_hash(v) for v in libraries.values()):
        raise ValueError('Desktop Tor did not capture every static dependency')
    if record.get('process_source_sha256') != {name: item['original'] for name, item in lock['embedded_process_sha256'].items()}:
        raise ValueError('Desktop Tor must retain the upstream standalone process')
    native = record.get('native_tests')
    if not isinstance(native, dict) or set(native) != {'passed', 'selectors', 'executable_sha256'} or native.get('passed') is not True or native.get('selectors') != list(TEST_SELECTORS) or not SERVER.valid_hash(native.get('executable_sha256')):
        raise ValueError('Desktop Tor has no actual native padding/cryptography test receipt')
    if not strict_equal(record.get('offline_self_test'), offline_receipt()):
        raise ValueError('Desktop Tor has no complete offline owner/control test receipt')
    compiler = record.get('compiler')
    if not isinstance(compiler, dict) or set(compiler) != {'version', 'target'} or any(not isinstance(v, str) or not 0 < len(v) <= 256 or any(c in v for c in '\r\n\0') for v in compiler.values()):
        raise ValueError('Desktop Tor compiler identity is incomplete')
    expected_licenses = {name + '/' + path: checksum for name, entry in lock['sources'].items() for path, checksum in entry['licenses'].items()}
    if set(licenses) != set(expected_licenses) or any(not isinstance(licenses[name], str) or digest(licenses[name].encode('utf-8')) != checksum for name, checksum in expected_licenses.items()):
        raise ValueError('Desktop Tor pinned dependency licenses changed')
    files = {name: payload(raw) for name, raw in data.items() if name != RECEIPT}
    if not strict_equal(record.get('files'), files) or record.get('executable_identity') != executable_identity(data[binary_name(target)], target):
        raise ValueError('Desktop Tor executable or package payload changed')
    return record


class TCPControl(SERVER.Control):
    def __init__(self, address):
        self.socket = socket.create_connection(address, timeout=3)
        try:
            self.stream = self.socket.makefile('rwb', buffering=0)
        except BaseException:
            self.socket.close()
            raise

    def authenticate(self, cookie_path, wrong=False):
        protocol = self.success('PROTOCOLINFO 1')
        auth = next((line for line in protocol if line.startswith('250-AUTH ')), '')
        match = re.fullmatch(r'250-AUTH METHODS=([A-Z,]+) COOKIEFILE=("(?:[^"\\]|\\.)*")', auth)
        if not match or 'SAFECOOKIE' not in match[1].split(',') or os.path.normcase(os.path.normpath(json.loads(match[2]))) != os.path.normcase(str(cookie_path)):
            raise ValueError('Desktop Tor exposed a different SAFECOOKIE owner')
        raw = read_regular(cookie_path, 32)
        if len(raw) != 32 or os.name != 'nt' and cookie_path.stat().st_mode & 0o077:
            raise ValueError('Desktop Tor control cookie is not private and exact')
        nonce = os.urandom(32)
        reply = self.success('AUTHCHALLENGE SAFECOOKIE ' + nonce.hex())
        challenge = re.fullmatch(r'250 AUTHCHALLENGE SERVERHASH=([0-9A-Fa-f]{64}) SERVERNONCE=([0-9A-Fa-f]{64})', reply[0])
        if len(reply) != 1 or not challenge:
            raise ValueError('Desktop Tor SAFECOOKIE challenge is malformed')
        material = raw + nonce + bytes.fromhex(challenge[2])
        if not hmac.compare_digest(bytes.fromhex(challenge[1]), hmac.digest(SERVER.SERVER_KEY, material, 'sha256')):
            raise ValueError('Desktop Tor SAFECOOKIE server authentication failed')
        response = bytes(32) if wrong else hmac.digest(SERVER.CLIENT_KEY, material, 'sha256')
        answer = self.command('AUTHENTICATE ' + response.hex())
        if wrong and (len(answer) != 1 or not answer[0].startswith('515 ')) or not wrong and answer != ['250 OK']:
            raise ValueError('Desktop Tor accepted an incorrect control authentication or rejected its owner')


def wait_owned_process(process, target, timeout):
    code = process.wait(timeout=timeout)
    if target.startswith('windows/'):
        # CPython keeps the Windows process HANDLE after wait(), releasing it
        # only when Popen is finalized. Release this exact, already joined
        # child before verifying relocation cleanup; never close a live owner.
        handle = getattr(process, '_handle', None)
        if handle is None:
            raise ValueError('Desktop Tor joined process lost its owned Windows handle')
        handle.Close()
    return code


def offline_self_test(binary, target):
    require_host(target)
    binary = Path(binary).absolute()
    before = digest(read_regular(binary, MAX_BINARY))
    environment = {k: v for k, v in os.environ.items() if k.upper() not in (
        'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'OPENSSL_CONF', 'OPENSSL_MODULES')}
    version = subprocess.run([str(binary), '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=5, check=True, env=environment).stdout
    if not re.match(rb'^Tor version 0\.4\.9\.14(?:[. (]|$)', version):
        raise ValueError('Desktop Tor executable version differs from its pin')
    with tempfile.TemporaryDirectory(prefix='rvt-desktop-') as temporary:
        root = Path(temporary).resolve()
        root.chmod(0o700)
        data = root / 'data'
        data.mkdir(mode=0o700)
        torrc, cookie, portfile = root / 'torrc', root / 'cookie', root / 'control-port'
        torrc.write_text('')
        torrc.chmod(0o600)
        args = [str(binary), '-f', str(torrc), '--RunAsDaemon', '0', '--DisableNetwork', '1',
            '--DataDirectory', str(data), '--SocksPort', '0', '--ControlPort', '127.0.0.1:auto',
            '--ControlPortWriteToFile', str(portfile), '--CookieAuthentication', '1', '--CookieAuthFile', str(cookie),
            '--__OwningControllerProcess', str(os.getpid()), '--AvoidDiskWrites', '1', '--Log', 'notice stderr']
        owner = None
        with (root / 'tor.log').open('wb') as log:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=environment)
            try:
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise ValueError('Desktop Tor exited before offline control: ' + (root / 'tor.log').read_text(errors='replace')[-2000:])
                    if portfile.exists() and cookie.exists():
                        break
                    time.sleep(0.01)
                else:
                    raise ValueError('Desktop Tor did not publish its owned offline listener')
                match = re.fullmatch(rb'PORT=127\.0\.0\.1:([0-9]{1,5})\r?\n', read_regular(portfile, 128))
                if not match or not 1 <= int(match[1]) <= 65535:
                    raise ValueError('Desktop Tor published an unexpected control address')
                address = ('127.0.0.1', int(match[1]))
                wrong = TCPControl(address)
                try:
                    wrong.authenticate(cookie, wrong=True)
                finally:
                    wrong.close()
                owner = TCPControl(address)
                owner.authenticate(cookie)
                SERVER.lastrelay_offline_check(owner, owning=False)
                if owner.command('ROUTERVPN_PADDING INFO') != ['551 Padding requires the owning controller']:
                    raise ValueError('Desktop Tor padding accepted a non-owning controller')
                actual = owner.success('GETINFO process/pid net/listeners/control net/listeners/socks net/listeners/dns net/listeners/trans traffic/read traffic/written')
                expected = {'250-process/pid=' + str(process.pid), '250-net/listeners/control="127.0.0.1:' + str(address[1]) + '"',
                    '250-net/listeners/socks=', '250-net/listeners/dns=', '250-net/listeners/trans=', '250-traffic/read=0', '250-traffic/written=0', '250 OK'}
                if set(actual) != expected or len(actual) != len(expected):
                    raise ValueError('Desktop Tor process, listener or disabled traffic identity differs: ' + repr(actual))
                if owner.success('GETCONF DisableNetwork RunAsDaemon __OwningControllerProcess') != [
                    '250-DisableNetwork=1', '250-RunAsDaemon=0', '250 __OwningControllerProcess=' + str(os.getpid())]:
                    raise ValueError('Desktop Tor lost its disabled foreground owner')
                owner.success('SETCONF UseBridges=1 ClientTransportPlugin="obfs4 socks5 127.0.0.1:1" Bridge="obfs4 192.0.2.1:443"')
                if owner.success('GETCONF UseBridges ClientTransportPlugin Bridge DisableNetwork') != [
                    '250-UseBridges=1', '250-ClientTransportPlugin=obfs4 socks5 127.0.0.1:1', '250-Bridge=obfs4 192.0.2.1:443', '250 DisableNetwork=1']:
                    raise ValueError('Desktop Tor did not retain its owned PT socket configuration')
                owner.success('TAKEOWNERSHIP')
                SERVER.lastrelay_offline_check(owner, owning=True)
                if owner.success('ROUTERVPN_PADDING INFO') != [CAPABILITY]:
                    raise ValueError('Desktop Tor outgoing padding extension is missing or changed')
                start = 'ROUTERVPN_PADDING START ' + 'a' * 64 + ' ' + 'b' * 64 + ' 1 192 10000 ' + 'c' * 64 + ' ' + 'd' * 64
                if owner.command(start) != ['551 Padding start is stale or unavailable'] or owner.success('ROUTERVPN_PADDING INFO') != [CAPABILITY] or owner.success('GETCONF DisableNetwork') != ['250 DisableNetwork=1']:
                    raise ValueError('Desktop Tor padding altered its disabled owner')
                owner.close()
                owner = None
                if wait_owned_process(process, target, timeout=5) != 0:
                    raise ValueError('Desktop Tor did not exit with its owning controller')
            finally:
                if owner is not None:
                    owner.close()
                if process.poll() is None:
                    process.terminate()
                    try:
                        wait_owned_process(process, target, timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        wait_owned_process(process, target, timeout=5)
                elif target.startswith('windows/'):
                    # An early process exit may have been observed by poll()
                    # before the normal owner-close path reached wait().
                    wait_owned_process(process, target, timeout=5)
    if digest(read_regular(binary, MAX_BINARY)) != before:
        raise ValueError('Desktop Tor executable changed during offline verification')
    return offline_receipt()


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
