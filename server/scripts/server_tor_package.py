#!/usr/bin/env python3
"""Verify the owned standalone Tor package; optionally exercise offline control.

This is a build/image gate. The relay worker separately verifies its opened
executable and owns every live control connection, listener and session.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import hmac
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

KIND = 'standalone-server-tor'
VERSION = 'tor 0.4.9.14'
SOURCE_LOCK_SHA256 = 'ca52ffdbda44d1554c6ac0cadd7ce84bca2c1e1f46f5ca6c5aaab1d34bf0459f'
PACKAGE = 'share/router-vpn/tor'
EXECUTABLE = 'bin/routervpn-tor'
TARGETS = {'linux/amd64': 62, 'linux/arm64': 183}
BUILD_INPUTS = frozenset(('deploy/build-server-tor.py', 'deploy/build-mobile-tor-package.py',
                          'server/scripts/server_tor_package.py', 'mobile/torpack/sources.json',
                          'deploy/apply-tor-padding.py', 'mobile/tor/padding-source-lock.json',
                          'mobile/tor/padding-integration.patch', 'mobile/tor/routervpn_padding.c',
                          'mobile/tor/routervpn_padding.h', 'mobile/tor/test_routervpn_padding.c',
                          'mobile/tor/routervpn_lastrelay.c', 'mobile/tor/routervpn_lastrelay.h',
                          'mobile/tor/test_routervpn_lastrelay.c'))
STATIC_DEPENDENCIES = frozenset(('libssl.a', 'libcrypto.a', 'libevent.a', 'libz.a'))
SERVER_KEY = b'Tor safe cookie authentication server-to-controller hash'
CLIENT_KEY = b'Tor safe cookie authentication controller-to-server hash'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_object(raw):
    def pairs(items):
        value = {}
        for key, entry in items:
            if key in value:
                raise ValueError('Duplicate Tor package JSON field')
            value[key] = entry
        return value
    value = json.loads(raw, object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError('Tor package JSON must be an object')
    return value


def relative(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or str(path) != name or '..' in path.parts or '\\' in name or '\0' in name:
        raise ValueError('Invalid Tor package relative path')
    return path.parts


def read_regular(root, name, limit=64 * 1024 * 1024):
    """Read only the exact regular object through unlinked directory handles."""
    parts = relative(name)
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    try:
        if os.fstat(parent).st_mode & 0o022:
            raise ValueError('Tor package directory is not privately writable')
        for component in parts[:-1]:
            next_parent = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = next_parent
            if os.fstat(parent).st_mode & 0o022:
                raise ValueError('Tor package directory is not privately writable')
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit or before.st_mode & 0o022:
            raise ValueError('Tor package file is not bounded and privately writable')
        data = bytearray()
        while chunk := os.read(descriptor, min(1024 * 1024, limit + 1 - len(data))):
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError('Tor package file exceeded its bound')
        after = os.fstat(descriptor)
        current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode)
        if identity(before) != identity(after) or identity(after) != identity(current) or len(data) != after.st_size:
            raise ValueError('Tor package file changed while verifying')
        return bytes(data), before
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def elf_identity(data, target):
    if target not in TARGETS or len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('Standalone Tor requires its exact little-endian ELF64 target')
    kind, machine = struct.unpack_from('<HH', data, 16)
    if kind not in (2, 3) or machine != TARGETS[target]:
        raise ValueError('Standalone Tor executable architecture mismatch')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    if size != 56 or not count or offset < 64 or offset + size * count > len(data):
        raise ValueError('Standalone Tor executable program headers are incomplete')
    loads = 0
    relro = False
    stack = False
    for index in range(count):
        segment, flags, start, _, _, file_size, memory_size, _ = struct.unpack_from('<IIQQQQQQ', data, offset + size * index)
        if start + file_size > len(data) or file_size > memory_size:
            raise ValueError('Standalone Tor executable segment is truncated')
        if segment == 3:
            raise ValueError('Standalone Tor must not depend on a system ELF interpreter')
        if segment == 1:
            loads += 1
            if flags & 3 == 3:
                raise ValueError('Standalone Tor has a writable executable segment')
        elif segment == 2:
            if file_size % 16:
                raise ValueError('Standalone Tor dynamic segment is malformed')
            for item in range(start, start + file_size, 16):
                tag, _ = struct.unpack_from('<QQ', data, item)
                if tag == 1:
                    raise ValueError('Standalone Tor must statically link its dependencies')
        elif segment == 0x6474e552:
            relro = True
        elif segment == 0x6474e551:
            stack = not flags & 1
    if not loads or not relro or not stack:
        raise ValueError('Standalone Tor requires loadable segments, RELRO and a non-executable stack')
    return {'elf_machine': machine, 'elf_class': 2}


def expected_files(source_lock):
    paths = {EXECUTABLE, PACKAGE + '/sources.json', PACKAGE + '/verify.py',
             PACKAGE + '/padding-source-lock.json'}
    for name, record in source_lock['sources'].items():
        paths.update(PACKAGE + '/licenses/' + name + '-' + Path(path).name for path in record['licenses'])
    return paths


def offline_receipt():
    return {'scope': 'offline-disabled-network-control', 'version': VERSION,
            'safecookie': True, 'incorrect_authentication_rejected': True,
            'process_and_listener_identity': True, 'disabled_network_retained': True,
            'pt_socket_configuration': True, 'owning_controller_exit': True,
            'owned_padding_capability': True, 'padding_rejected_while_disabled': True,
            'padding_without_owner_rejected': True, 'owned_lastrelay_capability': True,
            'lastrelay_rejected_while_disabled': True, 'lastrelay_without_owner_rejected': True}


def lastrelay_offline_check(owner, *, owning):
    """Execute the private prerequisite with networking disabled throughout.

    The result proves a compiled owner-only capability and rejects absent
    anchors. It does not claim a public circuit, HTTP response, or latency.
    """
    capability = ('250 version=1 transport=begindir min_ttl_ms=100 '
                  'max_ttl_ms=10000 max_response_bytes=8192 generation_highwater=0')
    if not owning:
        if owner.command('ROUTERVPN_LASTRELAY INFO') != [
                '551 Last-relay probe requires its owning controller']:
            raise ValueError('Tor last-relay capability accepted a non-owning controller')
        return
    if owner.success('GETCONF DisableNetwork') != ['250 DisableNetwork=1']:
        raise ValueError('Tor last-relay offline check requires disabled networking')
    if owner.success('ROUTERVPN_LASTRELAY INFO') != [capability]:
        raise ValueError('Tor last-relay native capability is missing or changed')
    identity = 'a' * 64 + ' ' + 'b' * 64
    isolation = 'c' * 64 + ' ' + 'd' * 64
    anchor = 'ROUTERVPN_LASTRELAY ANCHOR ' + identity + ' ' + isolation + ' 127.0.0.1 41000 1.1.1.1 443'
    if owner.command(anchor) != ['551 Last-relay anchor is absent, ambiguous or retired']:
        raise ValueError('Tor last-relay discovery accepted an absent disabled anchor')
    capture = 'ROUTERVPN_LASTRELAY CAPTURE ' + identity + ' 1 10000 1 ' + isolation + ' ' + 'e' * 64
    if owner.command(capture) != ['551 Last-relay capture is not eligible or current']:
        raise ValueError('Tor last-relay capture ignored disabled networking')
    if (owner.success('ROUTERVPN_LASTRELAY INFO') != [capability] or
            owner.success('GETCONF DisableNetwork') != ['250 DisableNetwork=1']):
        raise ValueError('Tor last-relay rejection changed the disabled owner or generation')


def valid_hash(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def verify(prefix, target, source_root=None):
    if target not in TARGETS:
        raise ValueError('Unknown standalone Tor target')
    prefix = Path(prefix).absolute()
    raw_lock, _ = read_regular(prefix, PACKAGE + '/sources.json', 64 * 1024)
    if digest(raw_lock) != SOURCE_LOCK_SHA256:
        raise ValueError('Standalone Tor source lock is not the pinned product lock')
    source_lock = json_object(raw_lock)
    raw, _ = read_regular(prefix, PACKAGE + '/BUILD.json', 128 * 1024)
    record = json_object(raw)
    if (type(record.get('schema')) is not int or record.get('schema') != 1 or record.get('kind') != KIND or record.get('platform') != target or
            record.get('native_version') != VERSION or record.get('embedded_process_patches') is not False or
            record.get('source_lock_sha256') != SOURCE_LOCK_SHA256 or
            record.get('sources') != source_lock['sources'] or
            record.get('process_source_sha256') != {name: entry['original'] for name, entry in source_lock['embedded_process_sha256'].items()} or
            record.get('dependency_linkage') != 'static' or
            not valid_hash(record.get('build_inputs_sha256'))):
        raise ValueError('Standalone Tor receipt source or platform identity changed')
    inputs = record.get('build_inputs')
    if not isinstance(inputs, dict) or set(inputs) != BUILD_INPUTS or any(not valid_hash(checksum) for checksum in inputs.values()):
        raise ValueError('Standalone Tor build input receipt is incomplete')
    for name in inputs:
        relative(name)
    combined = b''.join(name.encode() + b'\0' + checksum.encode() + b'\0' for name, checksum in sorted(inputs.items()))
    if digest(combined) != record['build_inputs_sha256']:
        raise ValueError('Standalone Tor build input digest mismatch')
    raw_padding, _ = read_regular(prefix, PACKAGE + '/padding-source-lock.json', 64 * 1024)
    padding_lock = json_object(raw_padding)
    padding = record.get('padding_extension')
    expected_padding = dict(version=1, direction='outgoing',
                            tor_commit=source_lock['sources']['tor']['commit'],
                            source_lock_sha256=digest(raw_padding),
                            patch_sha256=inputs['mobile/tor/padding-integration.patch'])
    if (not isinstance(padding, dict) or type(padding.get('version')) is not int or
            padding != expected_padding or record.get('padding_native_tests') is not True or
            record.get('lastrelay_native_tests') is not True or
            inputs['mobile/tor/padding-source-lock.json'] != digest(raw_padding) or
            type(padding_lock.get('schema')) is not int or padding_lock.get('schema') != 1 or
            type(padding_lock.get('version')) is not int or padding_lock.get('version') != 1 or
            padding_lock.get('tor_commit') != expected_padding['tor_commit'] or
            padding_lock.get('patch_sha256') != expected_padding['patch_sha256'] or
            not isinstance(padding_lock.get('copies'), dict) or len(padding_lock['copies']) != 6 or
            padding_lock.get('extensions') != {'circuit_cover': 1, 'last_relay_probe': 1} or
            any(type(version) is not int for version in padding_lock['extensions'].values())):
        raise ValueError('Standalone Tor outgoing padding receipt is incomplete')
    for name in ('routervpn_padding.c', 'routervpn_padding.h', 'test_routervpn_padding.c',
                 'routervpn_lastrelay.c', 'routervpn_lastrelay.h', 'test_routervpn_lastrelay.c'):
        path = 'mobile/tor/' + name
        entry = padding_lock.get('copies', {}).get(path)
        if not isinstance(entry, dict) or entry.get('sha256') != inputs[path]:
            raise ValueError('Standalone Tor padding source receipt changed')
    dependencies = record.get('static_dependencies')
    if not isinstance(dependencies, dict) or set(dependencies) != STATIC_DEPENDENCIES or any(not valid_hash(checksum) for checksum in dependencies.values()):
        raise ValueError('Standalone Tor static dependency receipt is incomplete')
    # Booleans must remain actual JSON booleans: Python equality alone would
    # accept integer 1 as a fabricated success flag.
    offline = record.get('offline_self_test')
    expected_offline = offline_receipt()
    if not isinstance(offline, dict) or set(offline) != set(expected_offline) or any(
            type(offline[key]) is not type(value) or offline[key] != value for key, value in expected_offline.items()):
        raise ValueError('Standalone Tor offline control receipt is incomplete')
    if source_root is not None:
        for name, expected_hash in inputs.items():
            data, _ = read_regular(source_root, name)
            if digest(data) != expected_hash:
                raise ValueError('Standalone Tor build source changed: ' + name)
    paths = expected_files(source_lock)
    files = record.get('files')
    if not isinstance(files, dict) or set(files) != paths:
        raise ValueError('Standalone Tor package file set changed')
    actual = {}
    executable = None
    for name in sorted(paths):
        data, info = read_regular(prefix, name)
        actual[name] = digest(data)
        if name == EXECUTABLE:
            if info.st_mode & 0o111 != 0o111:
                raise ValueError('Standalone Tor package binary is not executable')
            executable = dict(path=name, size=len(data), sha256=digest(data), **elf_identity(data, target))
    if actual != files or record.get('executable') != executable:
        raise ValueError('Standalone Tor executable or package bytes changed')
    if inputs['mobile/torpack/sources.json'] != actual[PACKAGE + '/sources.json'] or inputs['server/scripts/server_tor_package.py'] != actual[PACKAGE + '/verify.py']:
        raise ValueError('Standalone Tor packaged verifier or source lock is not its captured build input')
    for name, source in source_lock['sources'].items():
        for original, checksum in source['licenses'].items():
            if actual[PACKAGE + '/licenses/' + name + '-' + Path(original).name] != checksum:
                raise ValueError('Standalone Tor dependency license changed')
    sums, _ = read_regular(prefix, PACKAGE + '/SHA256SUMS', 64 * 1024)
    expected = ''.join(checksum + '  ' + name + '\n' for name, checksum in sorted(files.items())).encode()
    if sums != expected:
        raise ValueError('Standalone Tor checksum list changed')
    owned = prefix / PACKAGE
    actual_paths = {str(path.relative_to(prefix)) for path in owned.rglob('*') if path.is_file()}
    if any(path.is_symlink() or not (path.is_dir() or path.is_file()) for path in owned.rglob('*')) or actual_paths != paths - {EXECUTABLE} | {PACKAGE + '/BUILD.json', PACKAGE + '/SHA256SUMS'}:
        raise ValueError('Standalone Tor receipt directory contains an unexpected file')
    return record


class Control:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(3)
        try:
            self.socket.connect(str(path))
            self.stream = self.socket.makefile('rwb', buffering=0)
        except BaseException:
            self.socket.close()
            raise

    def close(self):
        self.stream.close()
        self.socket.close()

    def command(self, command):
        if '\r' in command or '\n' in command:
            raise ValueError('Invalid offline Tor control command')
        self.stream.write(command.encode('ascii') + b'\r\n')
        lines = []
        while len(lines) < 64:
            line = self.stream.readline(16385)
            if len(line) > 16384 or not line.endswith(b'\r\n') or len(line) < 5:
                raise ValueError('Malformed or closed Tor control response')
            text = line[:-2].decode('ascii')
            if not re.match(r'\d{3}[- ]', text):
                raise ValueError('Unexpected offline Tor control response')
            lines.append(text)
            if text[3] == ' ':
                return lines
        raise ValueError('Unbounded offline Tor control response')

    def success(self, command):
        lines = self.command(command)
        if any(not line.startswith('250') for line in lines):
            raise ValueError('Offline Tor control rejected ' + command.split()[0] + ': ' + repr(lines))
        return lines

    def authenticate(self, cookie_path, wrong=False):
        protocol = self.success('PROTOCOLINFO 1')
        auth = next((line for line in protocol if line.startswith('250-AUTH ')), '')
        if 'SAFECOOKIE' not in auth or 'COOKIEFILE=' + json.dumps(str(cookie_path)) not in auth:
            raise ValueError('Standalone Tor did not expose the exact SAFECOOKIE owner')
        raw, info = read_regular(cookie_path.parent, cookie_path.name, 32)
        if len(raw) != 32 or info.st_mode & 0o077:
            raise ValueError('Standalone Tor control cookie is not private and exact')
        nonce = os.urandom(32)
        reply = self.success('AUTHCHALLENGE SAFECOOKIE ' + nonce.hex())
        match = re.fullmatch(r'250 AUTHCHALLENGE SERVERHASH=([0-9A-Fa-f]{64}) SERVERNONCE=([0-9A-Fa-f]{64})', reply[0])
        if len(reply) != 1 or not match:
            raise ValueError('Standalone Tor SAFECOOKIE challenge is malformed')
        material = raw + nonce + bytes.fromhex(match[2])
        if not hmac.compare_digest(bytes.fromhex(match[1]), hmac.digest(SERVER_KEY, material, 'sha256')):
            raise ValueError('Standalone Tor failed SAFECOOKIE server authentication')
        response = bytes(32) if wrong else hmac.digest(CLIENT_KEY, material, 'sha256')
        lines = self.command('AUTHENTICATE ' + response.hex())
        if wrong:
            if len(lines) != 1 or not lines[0].startswith('515 '):
                raise ValueError('Standalone Tor accepted an incorrect control authentication')
        elif lines != ['250 OK']:
            raise ValueError('Standalone Tor rejected its authenticated controller')


def native_platform():
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if platform.system() != 'Linux' or not arch:
        raise ValueError('Standalone Tor gate requires native Linux AMD64 or ARM64')
    return 'linux/' + arch


def offline_self_test(binary, target):
    """Actual process/control proof, always DisableNetwork=1; never bootstrap Tor."""
    if native_platform() != target:
        raise ValueError('Standalone Tor self-test must execute on the actual target')
    binary = Path(binary).absolute()
    version = subprocess.run([str(binary), '--version'], check=True, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, timeout=5).stdout
    if not re.match(r'^Tor version 0\.4\.9\.14(?:[. (]|$)', version):
        raise ValueError('Standalone Tor executable version mismatch')
    with tempfile.TemporaryDirectory(prefix='rvt-') as directory:
        runtime = Path(directory)
        runtime.chmod(0o700)
        data = runtime / 'data'
        data.mkdir(mode=0o700)
        control_path, cookie_path = runtime / 'control', runtime / 'cookie'
        config = runtime / 'torrc'
        config.write_text('')
        config.chmod(0o600)
        args = [str(binary), '-f', str(config), '--RunAsDaemon', '0', '--DisableNetwork', '1',
                '--DataDirectory', str(data), '--SocksPort', '0', '--ControlPort', '0',
                '--ControlSocket', str(control_path), '--CookieAuthentication', '1',
                '--CookieAuthFile', str(cookie_path), '--__OwningControllerProcess', str(os.getpid()),
                '--Log', 'notice stderr', '--AvoidDiskWrites', '1']
        owner = None
        with (runtime / 'stderr.log').open('wb') as log:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise ValueError('Standalone Tor exited before disabled-network control: ' + (runtime / 'stderr.log').read_text()[-2000:])
                    if control_path.exists() and cookie_path.exists():
                        break
                    time.sleep(0.01)
                else:
                    raise ValueError('Standalone Tor did not publish its owned control socket')
                wrong = Control(control_path)
                try:
                    wrong.authenticate(cookie_path, wrong=True)
                finally:
                    wrong.close()
                owner = Control(control_path)
                owner.authenticate(cookie_path)
                lastrelay_offline_check(owner, owning=False)
                if owner.command('ROUTERVPN_PADDING INFO') != ['551 Padding requires the owning controller']:
                    raise ValueError('Standalone Tor padding accepted a non-owning controller')
                info = owner.success('GETINFO process/pid net/listeners/control net/listeners/socks net/listeners/dns net/listeners/trans traffic/read traffic/written')
                expected = {'250-process/pid=' + str(process.pid), '250-net/listeners/control=' + json.dumps('unix:' + str(control_path)),
                            '250-net/listeners/socks=', '250-net/listeners/dns=', '250-net/listeners/trans=',
                            '250-traffic/read=0', '250-traffic/written=0', '250 OK'}
                if set(info) != expected or len(info) != len(expected):
                    raise ValueError('Standalone Tor offline process/listener identity mismatch: ' + repr(info))
                config_reply = owner.success('GETCONF DisableNetwork RunAsDaemon __OwningControllerProcess')
                if config_reply != ['250-DisableNetwork=1', '250-RunAsDaemon=0', '250 __OwningControllerProcess=' + str(os.getpid())]:
                    raise ValueError('Standalone Tor did not retain disabled foreground ownership')
                owner.success('SETCONF UseBridges=1 ClientTransportPlugin="obfs4 socks5 127.0.0.1:1" Bridge="obfs4 192.0.2.1:443"')
                bridge = owner.success('GETCONF UseBridges ClientTransportPlugin Bridge DisableNetwork')
                if bridge != ['250-UseBridges=1', '250-ClientTransportPlugin=obfs4 socks5 127.0.0.1:1',
                              '250-Bridge=obfs4 192.0.2.1:443', '250 DisableNetwork=1']:
                    raise ValueError('Standalone Tor did not retain the owned PT socket configuration')
                owner.success('TAKEOWNERSHIP')
                lastrelay_offline_check(owner, owning=True)
                capability = owner.success('ROUTERVPN_PADDING INFO')
                if capability != ['250 version=1 direction=outgoing min_rate_kbps=32 max_rate_kbps=192 '
                                  'default_rate_kbps=192 max_ttl_ms=10000 max_pending_cells=1 '
                                  'accounting=tor-link-cell username_hex_lengths=32,64 '
                                  'password_hex_length=64 generation_highwater=0']:
                    raise ValueError('Standalone Tor does not contain the exact owned padding capability')
                start = 'ROUTERVPN_PADDING START ' + 'a' * 64 + ' ' + 'b' * 64 + ' 1 192 10000 ' + 'c' * 64 + ' ' + 'd' * 64
                if owner.command(start) != ['551 Padding start is stale or unavailable']:
                    raise ValueError('Standalone Tor padding ignored disabled networking')
                if owner.success('ROUTERVPN_PADDING INFO') != capability or owner.success('GETCONF DisableNetwork') != ['250 DisableNetwork=1']:
                    raise ValueError('Standalone Tor padding changed the disabled owner')
                owner.close()
                owner = None
                if process.wait(timeout=5) != 0:
                    raise ValueError('Standalone Tor did not exit cleanly with its owning controller')
            finally:
                if owner is not None:
                    owner.close()
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
    return offline_receipt()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, default=Path('/usr/local'))
    parser.add_argument('--platform', choices=tuple(TARGETS), required=True)
    parser.add_argument('--source-root', type=Path,
                        help='require the exact builder/verifier/lock bytes from this checkout')
    parser.add_argument('--offline-self-test', action='store_true')
    args = parser.parse_args()
    record = verify(args.prefix, args.platform, args.source_root)
    if args.offline_self_test:
        offline_self_test(args.prefix / EXECUTABLE, args.platform)
        verify(args.prefix, args.platform, args.source_root)
    print('PASS standalone Tor package', args.platform, record['executable']['sha256'])


if __name__ == '__main__':
    main()
