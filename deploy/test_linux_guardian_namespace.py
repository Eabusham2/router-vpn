#!/usr/bin/env python3
"""Exercise guardian namespace teardown with a real hidden read-only /run mount.

An outer private user/mount/network namespace supplies the inherited
/run/user/1001 bind mount. The production guardian runner creates its normal
nested namespaces and real veth/peer setup. Only its Go test executable is
replaced with a small verdict process so success, failure and signals can be
checked independently. No host mount, interface, account or firewall is changed.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import importlib.util
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import types


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT/'deploy/test_desktop_linux_guardian.py'
SPEC = importlib.util.spec_from_file_location('guardian_namespace_target', TARGET)
GUARDIAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARDIAN)


def variant(before, after):
    source = TARGET.read_text()
    if source.count(before) != 1:
        raise ValueError('Guardian namespace regression lost its exact production mutation seam')
    module = types.ModuleType('guardian_namespace_negative_control')
    module.__file__ = str(TARGET)
    exec(compile(source.replace(before, after, 1), str(TARGET), 'exec'), module.__dict__)
    return module


def unchanged_mount(path, sentinel):
    if (path/'keep').read_text() != sentinel:
        raise AssertionError('Nested runner changed its inherited mount contents')
    try:
        (path/'write-must-fail').write_text('unexpected')
    except OSError as error:
        if error.errno != errno.EROFS:
            raise AssertionError('Fixture did not exercise a read-only mount') from error
    else:
        raise AssertionError('Nested runner changed its inherited read-only mount')


def cases():
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run'], check=True)
    with tempfile.TemporaryDirectory(prefix='routervpn-guardian-mount-regression-') as temporary:
        work = Path(temporary)
        source, inherited = work/'inherited', Path('/run/user/1001')
        source.mkdir()
        inherited.mkdir(parents=True)
        sentinel = 'inherited runner mount remains outside guardian ownership'
        (source/'keep').write_text(sentinel)
        subprocess.run(['mount', '--bind', str(source), str(inherited)], check=True)
        subprocess.run(['mount', '-o', 'remount,bind,ro,nosuid,nodev,noexec', str(inherited)], check=True)
        unchanged_mount(inherited, sentinel)
        mounts = Path('/proc/self/mountinfo').read_text()
        parent_identity = {name: os.readlink('/proc/self/ns/'+name) for name in ('mnt', 'net', 'user', 'pid')}

        def run_case(module, status):
            executable = work/('verdict-'+str(status)+'.py')
            executable.write_text('#!'+sys.executable+'\n' + '''
import os, pathlib, signal, sys
assert os.environ.get('ROUTERVPN_LINUX_GUARDIAN_TEST_NS') == '1'
assert os.getppid() == 1, 'the actual runner must own this test process as PID 1'
assert not pathlib.Path('/run/user/1001').exists(), 'the inherited mount was not hidden by the private /run'
assert any(line.split()[4] == '/etc' for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines())
''' + ("os.kill(os.getpid(), signal.SIGTERM)\n" if status == 143 else 'sys.exit('+str(status)+')\n'))
            executable.chmod(0o700)
            result = module.namespace_test(executable)
            unchanged_mount(inherited, sentinel)
            if Path('/proc/self/mountinfo').read_text() != mounts:
                raise AssertionError('Nested runner changed its parent mount namespace')
            if {name: os.readlink('/proc/self/ns/'+name) for name in parent_identity} != parent_identity:
                raise AssertionError('Nested runner replaced its parent namespace owner')
            return result

        for status in (0, 17, 143):
            actual = run_case(GUARDIAN, status)
            if actual != status:
                raise AssertionError('Guardian teardown changed test verdict '+str(status)+' to '+str(actual))
            print('Guardian nested mount isolation preserves test status '+str(status)+'.', flush=True)

        old_cleanup = variant(
            "                subprocess.run(['ip', 'netns', 'delete', 'rvpn-peer'], check=True)\n",
            "                subprocess.run(['ip', 'netns', 'delete', 'rvpn-peer'], check=True)\n"
            "                subprocess.run(['umount', '-R', '/run'], check=True)\n")
        if run_case(old_cleanup, 0) != 1:
            raise AssertionError('The real nested-mount reproduction accepted the old recursive teardown')
        print('Rejected recursive teardown of hidden inherited /run mounts.', flush=True)
        hidden_failure = variant('os._exit(result if result >= 0 else 128 - result)', 'os._exit(0)')
        if run_case(hidden_failure, 17) != 0:
            raise AssertionError('The verdict regression accepted an ignored failing test process')
        print('Rejected suppression of the actual test-process failure.', flush=True)
    # These /run mounts belong exclusively to the outer test namespace too.
    # Its owner exit destroys them; no host mount is explicitly unmounted.


def isolated():
    if os.geteuid() != 0 or platform.system() != 'Linux':
        raise ValueError('Guardian namespace regression requires its real privileged Linux invocation')
    libc = ctypes.CDLL(None, use_errno=True)
    ready_read, ready_write = os.pipe()
    map_read, map_write = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(ready_read)
            os.close(map_write)
            if libc.unshare(0x10000000) != 0:
                raise OSError(ctypes.get_errno(), 'guardian regression user namespace')
            os.write(ready_write, b'1')
            if os.read(map_read, 1) != b'1':
                raise RuntimeError('Guardian regression UID map was not acknowledged')
            os.close(ready_write)
            os.close(map_read)
            # Keep the existing PID/proc view for the nested runner's initial
            # /proc/PID map handshake. That runner creates and owns the fresh
            # PID namespace containing each verdict process and its helpers.
            if libc.unshare(0x40000000 | 0x00020000) != 0:
                raise OSError(ctypes.get_errno(), 'guardian regression mount/network namespaces')
            cases()
            os._exit(0)
        except BaseException as error:
            print('Guardian namespace regression failed: '+str(error), file=sys.stderr, flush=True)
            os._exit(1)
    os.close(ready_write)
    os.close(map_read)
    try:
        if os.read(ready_read, 1) != b'1':
            raise RuntimeError('Guardian regression namespace child did not start')
        Path(f'/proc/{child}/uid_map').write_text('0 0 2147483647\n')
        Path(f'/proc/{child}/gid_map').write_text('0 0 2147483647\n')
        os.write(map_write, b'1')
    finally:
        os.close(ready_read)
        os.close(map_write)
    _, status = os.waitpid(child, 0)
    return os.waitstatus_to_exitcode(status)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--isolated', action='store_true', help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.isolated:
        raise SystemExit(isolated())
    sudo = GUARDIAN.UID.privilege_tool()
    command = [sys.executable, str(Path(__file__).resolve()), '--isolated']
    if sudo is not None:
        command = [sudo, '-n', '--', *command]
    before = Path('/proc/self/mountinfo').read_text()
    output = GUARDIAN.UID.run(command, cwd=ROOT, timeout=60, sudo=sudo)
    if Path('/proc/self/mountinfo').read_text() != before:
        raise AssertionError('Guardian namespace regression changed host mounts')
    print(output, end='' if output.endswith('\n') else '\n')


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        if error.output:
            sys.stderr.write(error.output[-8192:].decode('utf-8', errors='replace'))
        raise
