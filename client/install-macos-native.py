#!/usr/bin/env python3
"""Transactional fixed-install macOS application and owned launch supervisor.

The Go installer utility validates the root-owned Python runtime before this
module executes with privilege. File copying, inode capture and installation
locks reuse the executable-tested Linux transaction primitives. Only the
macOS launchd integration below can dispatch platform commands.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import pwd
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time

SPEC = importlib.util.spec_from_file_location('routervpn_install_files', Path(__file__).with_name('install-linux-native.py'))
FILES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FILES)
ROOT = Path('/opt/router-vpn-client')
LABEL = 'com.routervpn.client'
PLIST = '/Library/LaunchDaemons/' + LABEL + '.plist'
CODE_TREES = {'client', 'modes', 'runtime', 'RouterVPN.app'}
CODE_FILES = FILES.CODE_FILES - {'router-vpn-app', 'router-vpn.desktop', 'router-vpn.png'}
REQUIRED = {'router-vpn-client', 'router-vpn-dns', 'router-vpn-start-layer-relay',
            'router-vpn-update', 'modes.json', 'logical-modes.json', 'ROUTER-VPN-SOURCE.json'}
NATIVE_MACOS = sys.platform == 'darwin'


def validate_acl_buffer(data, private):
    # Apple's ATTR_CMN_EXTENDED_SECURITY contains an attrreference followed by
    # kauth_filesec. Read-only public ACLs and deny ACEs remain compatible;
    # private data cannot acquire an extra reader through an ACL grant.
    # https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/kauth.h
    if len(data) < 12:
        raise ValueError('Short native permission readback')
    total, relative, length = struct.unpack_from('<IiI', data)
    start = 4 + relative
    if not 12 <= total <= len(data) or not 12 <= start <= total or length > total-start:
        raise ValueError('Invalid native permission bounds')
    if length == 0:
        return
    security = data[start:start+length]
    if length < 44 or struct.unpack_from('<I', security)[0] != 0x012cc16d:
        raise ValueError('Invalid native permission record')
    count = struct.unpack_from('<I', security, 36)[0]
    if count == 0xffffffff and length == 44:
        return
    if count > 128 or length != 44+24*count:
        raise ValueError('Invalid native permission entry count')
    read_only = sum(1 << bit for bit in (1, 3, 7, 9, 11, 20, 22, 24))
    for index in range(count):
        flags, rights = struct.unpack_from('<II', security, 44+24*index+16)
        kind = flags & 15
        if kind == 1:
            if rights & ~read_only or private and rights:
                raise ValueError('Privileged installation ACL grants extra mutation or private-data access')
        elif kind != 2:
            raise ValueError('Unsupported native permission entry')


class NativeAttributes(ctypes.Structure):
    _fields_ = [('count', ctypes.c_uint16), ('reserved', ctypes.c_uint16),
                ('common', ctypes.c_uint32), ('volume', ctypes.c_uint32),
                ('directory', ctypes.c_uint32), ('file', ctypes.c_uint32),
                ('fork', ctypes.c_uint32)]


def check_path_acl(path):
    if not NATIVE_MACOS:
        return
    before = path.lstat()
    library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    library.getattrlist.argtypes = [ctypes.c_char_p, ctypes.POINTER(NativeAttributes),
                                   ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
    library.getattrlist.restype = ctypes.c_int
    requested = NativeAttributes(count=5, common=0x00400000)
    buffer = ctypes.create_string_buffer(4096)
    if library.getattrlist(os.fsencode(path), ctypes.byref(requested), buffer, len(buffer), 1) != 0:
        raise OSError(ctypes.get_errno(), 'Cannot capture installed native ACL authority')
    validate_acl_buffer(buffer.raw, private=not before.st_mode & 0o077)
    after = path.lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_ctime_ns, info.st_mode,
                             info.st_uid, info.st_gid, info.st_nlink)
    if identity(before) != identity(after):
        raise ValueError('Native installation authority changed during ACL readback')


file_ordinary = FILES.ordinary


def platform_ordinary(path, *, directory=False, trusted=False):
    info = file_ordinary(path, directory=directory, trusted=trusted)
    if trusted:
        check_path_acl(path)
    return info


# The reusable file transaction calls this for protected directories, locks and
# system integration writes. User-supplied package input is copied into fresh
# files; it is never promoted merely because its original metadata looks safe.
FILES.ordinary = platform_ordinary


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate installation identity field')
        value[key] = item
    return value


def owner_uid(path, installing_uid):
    if not path.exists() and not path.is_symlink():
        return installing_uid
    info = FILES.ordinary(path, trusted=True)
    if info.st_mode & 0o077 or info.st_size > 1024:
        raise ValueError('Unsafe existing controller owner record')
    record = json.loads(path.read_text(), object_pairs_hook=unique_object)
    if not isinstance(record, dict) or set(record) != {'schema', 'caller_uid'} or record['schema'] != 1 or type(record['caller_uid']) is not int or not 0 < record['caller_uid'] < 2**32-1:
        raise ValueError('Invalid existing controller owner record')
    pwd.getpwuid(record['caller_uid'])
    return record['caller_uid']


def run(arguments, *, check=True):
    return subprocess.run(list(map(str, arguments)), check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C',
                               'HOME': '/var/root', 'PYTHONNOUSERSITE': '1'}, timeout=120)


def launch_definition():
    return plistlib.dumps({
        'Label': LABEL,
        'ProgramArguments': [str(ROOT/'router-vpn-client'), '--macos-controller-supervisor'],
        'WorkingDirectory': str(ROOT),
        'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 10,
        'ProcessType': 'Background', 'Umask': 0o077,
    }, fmt=plistlib.FMT_XML, sort_keys=True)


class LaunchIntegration(FILES.SystemIntegration):
    def __init__(self, filesystem=Path('/'), command=run):
        super().__init__(filesystem, command)
        self.loaded_before = False
        self.stopped_before = False
        self.started_new = False
        self.prepared = False

    def loaded(self):
        result = self.run(['/bin/launchctl', 'print', 'system/' + LABEL], check=False)
        if result.returncode == 0:
            return True
        # Unknown service is distinct from failed domain access or a broken
        # launchd connection. Do not interpret arbitrary errors as inactivity.
        if result.returncode == 113 and 'Could not find service' in result.stderr and LABEL in result.stderr:
            return False
        raise RuntimeError('Cannot determine the existing Router VPN launchd owner')

    def prepare(self, root):
        self.loaded_before = self.loaded()
        existing = self.path(PLIST)
        if existing.exists() or existing.is_symlink():
            FILES.ordinary(existing, trusted=True)
            definition = plistlib.loads(existing.read_bytes())
            if definition.get('Label') != LABEL or definition.get('ProgramArguments') != launch_definition_arguments():
                raise RuntimeError('Stop and remove the legacy Router VPN controller service before native installation; its live tunnel cannot be adopted by this installer.')
        elif self.loaded_before:
            raise RuntimeError('An unrecognized launchd service owns the Router VPN label')
        self.prepared = True
        if self.loaded_before:
            # The caller holds installation EX. A valid new supervisor cannot
            # have an active child without its shared lock, so this is idle.
            self.run(['/bin/launchctl', 'bootout', 'system/' + LABEL])
            self.stopped_before = True
            self.join_supervisor(root)

    def join_supervisor(self, root):
        path = root.with_name(root.name + '.supervisor.lock')
        if not path.exists():
            return
        descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            named = FILES.ordinary(path, trusted=True)
            actual = os.fstat(descriptor)
            if (named.st_dev, named.st_ino) != (actual.st_dev, actual.st_ino) or actual.st_mode & 0o077:
                raise ValueError('The supervisor lock changed or has unsafe permissions')
            deadline = time.monotonic() + 8
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('The captured idle supervisor has not finished shutdown')
                    time.sleep(0.025)
        finally:
            os.close(descriptor)

    def install(self, root):
        self.write(PLIST, launch_definition(), 0o600)
        self.run(['/usr/bin/plutil', '-lint', self.path(PLIST)])
        # Retain the existing saved Always policy before offering the new GUI
        # endpoint. OS boot-before-network acceptance is a separate live gate.
        self.run(['/usr/bin/env', '-i', 'PATH=' + str(root/'bin') + ':/usr/bin:/bin:/usr/sbin:/sbin',
                  'HOMEVPN_ROOT=' + str(root), root/'bin/python3',
                  root/'modes/kill-switch-platform.py', 'reassert'])
        self.started_new = True
        self.run(['/bin/launchctl', 'bootstrap', 'system', self.path(PLIST)])
        if not self.loaded():
            raise RuntimeError('The installed supervisor did not enter its launchd domain')

    def retire_new(self, root):
        if self.started_new and self.loaded():
            self.run(['/bin/launchctl', 'bootout', 'system/' + LABEL])
            self.join_supervisor(root)

    def restore(self):
        for target, previous in reversed(self.previous):
            if previous is None:
                target.unlink(missing_ok=True)
            else:
                data, mode = previous
                descriptor, temporary = tempfile.mkstemp(prefix='.routervpn-rollback-', dir=target.parent)
                try:
                    with os.fdopen(descriptor, 'wb') as output:
                        output.write(data); output.flush(); os.fsync(output.fileno())
                        os.fchmod(output.fileno(), mode); os.fchown(output.fileno(), 0, 0)
                    os.replace(temporary, target)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
        if self.stopped_before:
            self.run(['/bin/launchctl', 'bootstrap', 'system', self.path(PLIST)])
            if not self.loaded():
                raise RuntimeError('The previous supervisor was not restored')


def launch_definition_arguments():
    return [str(ROOT/'router-vpn-client'), '--macos-controller-supervisor']


def running_executables():
    # Apple libproc returns a PID count here (not the byte count returned by
    # proc_listpids). Paths come from the kernel, not mutable argv or ps text.
    # https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.c
    if sys.platform != 'darwin':
        raise RuntimeError('Actual macOS process identity is required')
    library = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    library.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
    library.proc_listallpids.restype = ctypes.c_int
    library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    library.proc_pidpath.restype = ctypes.c_int
    for attempt in range(4):
        count = library.proc_listallpids(None, 0)
        if not 0 < count < 1000000:
            raise RuntimeError('Cannot bound the native process inventory')
        array = (ctypes.c_int * (count + 128))()
        actual = library.proc_listallpids(array, ctypes.sizeof(array))
        if 0 < actual < len(array):
            break
    else:
        raise RuntimeError('The native process inventory kept changing during capture')
    paths = []
    for pid in array[:actual]:
        if pid <= 0:
            continue
        buffer = ctypes.create_string_buffer(4096)
        ctypes.set_errno(0)
        size = library.proc_pidpath(pid, buffer, len(buffer))
        if size <= 0:
            if ctypes.get_errno() == errno.ESRCH:
                continue
            raise RuntimeError('Cannot prove the previous native processes have exited')
        if size >= len(buffer):
            raise RuntimeError('Native executable identity was truncated')
        paths.append(os.fsdecode(buffer.raw[:size]))
    return paths


def reject_running_previous(root, process_reader=running_executables):
    for executable in process_reader():
        if executable.startswith(str(root) + '/') or executable == '/usr/local/bin/router-vpn-client':
            raise RuntimeError('Close Router VPN and its previous owned native processes before upgrading.')


def stage_application(source, root, stage, installing_uid, python):
    captured = FILES.ordinary(source, directory=True)
    if root.exists() or root.is_symlink():
        FILES.ordinary(root, directory=True, trusted=True)
    for name in CODE_TREES | REQUIRED:
        FILES.ordinary(source/name, directory=name in CODE_TREES)
    for name in sorted(CODE_TREES | CODE_FILES):
        if (source/name).exists() or (source/name).is_symlink():
            FILES.copy_checked(source/name, stage/name)
    if root.exists():
        for child in root.iterdir():
            if child.name not in CODE_TREES | CODE_FILES:
                FILES.copy_checked(child, stage/child.name, private=True)
    for name in ('client.json', 'routers.json', 'generated'):
        if not (stage/name).exists():
            FILES.copy_checked(source/name, stage/name, private=True)
    FILES.validate_config(stage/'client.json', root)
    selected_uid = owner_uid(root/'controller-owner.json', installing_uid)
    record = stage/'controller-owner.json'
    record.write_text(json.dumps({'schema': 1, 'caller_uid': selected_uid}, sort_keys=True) + '\n')
    os.chown(record, 0, 0); record.chmod(0o600)
    tools = stage/'bin'
    if not tools.exists():
        tools.mkdir(mode=0o700); os.chown(tools, 0, 0)
    wrapper = tools/'python3'
    if wrapper.exists():
        FILES.ordinary(wrapper, trusted=True)
    wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(str(python)) + ' -EsS "$@"\n')
    os.chown(wrapper, 0, 0); wrapper.chmod(0o700)
    for name in REQUIRED & {'router-vpn-client', 'router-vpn-dns', 'router-vpn-start-layer-relay', 'router-vpn-update'}:
        if not os.access(stage/name, os.X_OK):
            raise ValueError('Required native executable is not executable: ' + name)
    if not os.access(stage/'RouterVPN.app/Contents/MacOS/RouterVPN', os.X_OK):
        raise ValueError('The native AppKit executable is missing')
    # File copying must not remove an existing macOS download quarantine.
    # Codesign verifies bytes; Gatekeeper/notarization remain separate OS
    # decisions. Copy only that provenance attribute, never arbitrary ACLs or
    # extended metadata from the caller's extracted package.
    if sys.platform == 'darwin':
        absent = {errno.ENODATA, getattr(errno, 'ENOATTR', errno.ENODATA)}
        code_paths = [stage]
        for name in sorted(CODE_TREES | CODE_FILES):
            target = stage/name
            if not target.exists(): continue
            code_paths.extend([target, *target.rglob('*')] if target.is_dir() else [target])
        for path in code_paths:
            original = source/path.relative_to(stage)
            try:
                quarantine = os.getxattr(original, 'com.apple.quarantine', follow_symlinks=False)
            except OSError as error:
                if error.errno in absent: continue
                raise
            os.setxattr(path, 'com.apple.quarantine', quarantine, follow_symlinks=False)
    # New files may inherit ACLs from their parent even though copying omitted
    # source ACLs. Inspect the complete staged authority before any execution.
    for path in [stage, *stage.rglob('*')]:
        FILES.ordinary(path, directory=path.is_dir(), trusted=True)
    after = FILES.ordinary(source, directory=True)
    if (captured.st_dev, captured.st_ino, captured.st_mtime_ns, captured.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('The source package changed during installation capture')


def verify_runtimes(stage, python):
    for flag in ('--verify-native-runtime', '--verify-amnezia-runtime'):
        run([stage/'router-vpn-client', flag, stage])
    run([python, '-EsS', stage/'client/verify-bundled-xray.py', stage/'runtime/xray'])
    for path in ('RouterVPN.app', 'router-vpn-client', 'router-vpn-dns', 'router-vpn-start-layer-relay', 'router-vpn-update'):
        run(['/usr/bin/codesign', '--verify', '--deep', '--strict', stage/path])


def install(source, installing_uid, python, *, root=ROOT, integration=None, verifier=verify_runtimes,
            process_reader=running_executables):
    if os.geteuid() != 0 or type(installing_uid) is not int or not 0 < installing_uid < 2**32-1:
        raise PermissionError('Run the native installer from your normal user account and approve sudo.')
    pwd.getpwuid(installing_uid)
    integration = integration if integration is not None else LaunchIntegration()
    with FILES.installation_lock(root):
        prefix = '.' + root.name + '.install-'
        pending = list(root.parent.glob(prefix + '*'))
        if pending:
            raise RuntimeError('An interrupted native installation needs recovery; retained files: ' + ', '.join(map(str, pending)))
        temporary = Path(tempfile.mkdtemp(prefix=prefix, dir=root.parent))
        stage, previous = temporary/'new', temporary/'previous'
        stage.mkdir(mode=0o700); os.chown(stage, 0, 0)
        promoted = False
        try:
            stage_application(source, root, stage, installing_uid, python)
            verifier(stage, python)
            integration.prepare(root)
            reject_running_previous(root, process_reader)
            if root.exists():
                os.rename(root, previous)
            os.rename(stage, root)
            promoted = True
            root.chmod(0o755)
            integration.install(root)
        except BaseException:
            try:
                if promoted:
                    integration.retire_new(root)
                    os.rename(root, stage)
                if previous.exists():
                    os.rename(previous, root)
                integration.restore()
            except BaseException as rollback_error:
                raise RuntimeError('Native installation rollback needs recovery; previous bytes retained at ' + str(temporary)) from rollback_error
            shutil.rmtree(temporary)
            raise
        shutil.rmtree(temporary)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--caller-uid', type=int, required=True)
    parser.add_argument('--python', type=Path, required=True)
    arguments = parser.parse_args()
    try:
        if sys.platform != 'darwin' or Path(sys.executable).resolve() != arguments.python.resolve():
            raise ValueError('Use the native controller installer utility and its trusted macOS Python runtime.')
        FILES.ordinary(Path('/opt'), directory=True, trusted=True)
        install(arguments.source.resolve(), arguments.caller_uid, arguments.python)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print('Router VPN installation failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
    print('Router VPN installed. Its fixed native app is /opt/router-vpn-client/RouterVPN.app.')
    print('Private nodes and settings were preserved; the user-owned GUI uses its authenticated supervisor.')
