#!/usr/bin/env python3
"""Verify the shipping Go controller's fixed privileged launch in private namespaces.

Compilation runs as the build user with the selected Go toolchain. Only the
tagged executable runs with privilege, inside fresh user/PID/mount/network
namespaces. /opt and /run are private tmpfs mounts; the host installation,
services, account database, routes and firewall are never changed.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import importlib.util
import os
import platform
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('controller_privilege_toolchain', ROOT/'deploy/test_desktop_socket_uid.py')
UID = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UID)
CASES = ('FixedInstallAndPipeLifetime', 'RejectsUnsafeInstallAndConfig',
         'RejectsForeignIdentityAndInput', 'HonorsInstallAndProcessLocks', 'RequiresBoundedHandshake',
         'RejectsUnownedInstalledMainPreservesUtilities', 'NodeParentRetainsExactObjects', 'NodeParentLifetimeAndRestart')


def source_identity():
    names = sorted([ROOT/'go.mod', ROOT/'go.sum', *(ROOT/'cmd/client').glob('*'), *(ROOT/'internal').rglob('*.go')])
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in names if path.is_file() and not path.is_symlink()}


def namespace_test(binary, pattern='^TestLinuxOwnedControllerNamespace'):
    if os.geteuid() != 0 or platform.system() != 'Linux' or not binary.is_absolute() or not binary.is_file():
        raise ValueError('Controller namespace fixture requires its actual privileged Linux invocation')
    libc = ctypes.CDLL(None, use_errno=True)
    ready_read, ready_write = os.pipe()
    map_read, map_write = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(ready_read); os.close(map_write)
            if libc.unshare(0x10000000) != 0:
                raise OSError(ctypes.get_errno(), 'controller user namespace')
            os.write(ready_write, b'1')
            if os.read(map_read, 1) != b'1':
                raise RuntimeError('controller UID map was not acknowledged')
            os.close(ready_write); os.close(map_read)
            if libc.unshare(0x40000000 | 0x00020000 | 0x20000000) != 0:
                raise OSError(ctypes.get_errno(), 'controller PID/mount/network namespaces')
            init = os.fork()
            if init:
                _, status = os.waitpid(init, 0)
                os._exit(os.waitstatus_to_exitcode(status))
            subprocess.run(['mount', '--make-rprivate', '/'], check=True)
            subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/opt'], check=True)
            subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run'], check=True)
            subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
            result = subprocess.run([str(binary), '-test.run=' + pattern,
                                     '-test.count=1', '-test.timeout=120s', '-test.v'],
                                    env=dict(os.environ, ROUTERVPN_CONTROLLER_PRIVILEGE_TEST_NS='1'),
                                    timeout=135).returncode
            os._exit(result if result >= 0 else 128-result)
        except BaseException as error:
            print('Controller namespace fixture failed: '+str(error), file=sys.stderr, flush=True)
            os._exit(1)
    os.close(ready_write); os.close(map_read)
    try:
        if os.read(ready_read, 1) != b'1':
            raise RuntimeError('Controller namespace child did not start')
        Path(f'/proc/{child}/uid_map').write_text('0 0 2147483647\n')
        Path(f'/proc/{child}/gid_map').write_text('0 0 2147483647\n')
        os.write(map_write, b'1')
    finally:
        os.close(ready_read); os.close(map_write)
    _, status = os.waitpid(child, 0)
    return os.waitstatus_to_exitcode(status)


def execute(go='go'):
    if platform.system() != 'Linux':
        raise ValueError('The controller privilege gate requires a matching Linux host')
    before = source_identity()
    required = {'cmd/client/controller_local_auth.go', 'cmd/client/controller_local_auth_test.go',
                'cmd/client/controller_privilege_linux.go', 'cmd/client/controller_privilege_linux_test.go',
                'cmd/client/controller_privilege_linux_namespace_test.go', 'cmd/client/desktop_node_linux_parent.go',
                'cmd/client/desktop_node_linux_parent_native_test.go'}
    if not required.issubset(before):
        raise ValueError('The actual controller privilege source/test closure is incomplete')
    env = dict(os.environ, GOWORK='off')
    if env.get('GOOS', 'linux') != 'linux':
        raise ValueError('The controller privilege gate cannot execute a cross-compiled binary')
    sudo = UID.privilege_tool()
    compiler, env = UID.compiler_toolchain(ROOT, go, env)
    with tempfile.TemporaryDirectory(prefix='routervpn-controller-privilege-') as temporary:
        binary = Path(temporary)/'controller-privilege.test'
        UID.run([compiler, 'test', '-race', '-c', '-mod=readonly', '-tags=routervpn_controller_privileged',
                 '-o', binary, './cmd/client'], cwd=ROOT, env=env)
        if source_identity() != before:
            raise ValueError('Controller source changed during its privileged fixture compilation')
        info = binary.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size == 0:
            raise ValueError('Controller compiler did not produce its owned executable')
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        command = [sys.executable, str(Path(__file__).resolve()), '--namespace-test-binary', str(binary)]
        if sudo is not None:
            command = [sudo, '-n', '--', *command]
        output = UID.run(command, cwd=ROOT, timeout=150, sudo=sudo)
        if any('--- PASS: TestLinuxOwnedControllerNamespace'+name+' (' not in output for name in CASES) or '--- SKIP:' in output:
            raise ValueError('The controller privilege gate did not execute every required actual boundary')
        for ending in ('eof', 'second-byte'):
            if '--- PASS: TestLinuxOwnedControllerNamespaceFixedInstallAndPipeLifetime/'+ending+' (' not in output:
                raise ValueError('Controller did not execute its actual anonymous-pipe retirement case')
            if '--- PASS: TestLinuxOwnedControllerNamespaceNodeParentLifetimeAndRestart/'+ending+' (' not in output:
                raise ValueError('Node parent did not execute its actual retained GUI lifetime and restart')
        for case in ('root', 'image', 'image-descriptor', 'root-descriptor', 'network-namespace-descriptor',
                     'pid-namespace-descriptor', 'install-lock', 'process-lock', 'profile-root', 'application-owner', 'retire'):
            if '--- PASS: TestLinuxOwnedControllerNamespaceNodeParentRetainsExactObjects/'+case+' (' not in output:
                raise ValueError('Node parent omitted its captured native object substitution or retirement: '+case)
        after = binary.stat()
        if (after.st_dev, after.st_ino, after.st_size) != (info.st_dev, info.st_ino, info.st_size) or hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError('The actual controller test executable changed during verification')
        if source_identity() != before:
            raise ValueError('Controller source changed during actual privileged verification')
        print(output, end='' if output.endswith('\n') else '\n')
        print('Actual fixed-install controller, user-created stdin identity, shared transaction/process locks and EOF drain passed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--namespace-test-binary', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.namespace_test_binary is not None:
        raise SystemExit(namespace_test(args.namespace_test_binary))
    try:
        execute(args.go)
    except subprocess.CalledProcessError as error:
        if error.output:
            sys.stderr.write(error.output[-32768:].decode('utf-8', errors='replace'))
        raise
