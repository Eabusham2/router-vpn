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
import contextlib
import ctypes
import errno
import hashlib
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


def readonly_account_source(work):
    source, owner = work/'account-source', work/'account-owner'
    source.mkdir()
    owner.mkdir()
    original = {}
    for name in (*GUARDIAN.ACCOUNT_FILES, 'passwd-', 'shadow-', '.pwd.lock', 'passwd.lock'):
        path = source/name
        path.write_text('captured '+name+'\n')
        path.chmod(0o600 if 'shadow' in name else 0o644)
        original[name] = path.read_bytes()
    (source/'nsswitch.conf').write_text('passwd: files\ngroup: files\n')
    nested = source/'nested-config'
    nested.mkdir()
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'nodev,nosuid,noexec', 'tmpfs', str(nested)], check=True)
    try:
        (nested/'keep').write_text('nested configuration')
        with GUARDIAN.private_account_directory(source, owner) as private:
            mounts = {path: options for _, path, options in GUARDIAN.account_mounts(private)}
            if not {'ro', 'nodev', 'nosuid', 'noexec'}.issubset(mounts.get(private/'nested-config', set())):
                raise AssertionError('Private account remount lost original native security flags')
            for path in (private/'nsswitch.conf', private/'nested-config/keep'):
                try:
                    path.write_text('unexpected mutation')
                except OSError as error:
                    if error.errno != errno.EROFS:
                        raise AssertionError('Configuration did not use its read-only mount') from error
                else:
                    raise AssertionError('Private account configuration exposed a writable original mount')
            for name in (*GUARDIAN.ACCOUNT_FILES, 'passwd-', 'shadow-'):
                captured, copied = (source/name).stat(), (private/name).stat()
                if (private/name).is_symlink() or (captured.st_dev, captured.st_ino) == (copied.st_dev, copied.st_ino):
                    raise AssertionError('Private account database or backup aliases the original')
                if (captured.st_mode, captured.st_uid, captured.st_gid) != (copied.st_mode, copied.st_uid, copied.st_gid):
                    raise AssertionError('Private account copy changed credentials-file permissions')
                (private/name).write_text('private mutation\n')
            for name in ('.pwd.lock', 'passwd.lock'):
                if (private/name).exists():
                    raise AssertionError('Private account lock inherited an original owner')
                (private/name).write_text('private lock')
            if any((source/name).read_bytes() != raw for name, raw in original.items()):
                raise AssertionError('Private account writes changed the original database or lock')
            subprocess.run([sys.executable, '-c',
                "import os,pathlib,sys; os.setgroups([]); os.setgid(65534); os.setuid(65534); "
                "assert pathlib.Path(sys.argv[1]).read_text() == 'passwd: files\\ngroup: files\\n'",
                str(private/'nsswitch.conf')], check=True)
            # The original nested mount remains writable; only our captured
            # clone is read-only, including its independently mounted child.
            (nested/'keep').write_text('original remains writable')
        if GUARDIAN.account_mounts(owner):
            raise AssertionError('Private account source retained an owned mount after exit')
    finally:
        subprocess.run(['umount', str(nested)], check=True)
    print('Private account files, backups and locks are independent; NSS and nested configuration retain read-only ownership and native security flags.', flush=True)


def cases():
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run'], check=True)
    with tempfile.TemporaryDirectory(prefix='routervpn-guardian-mount-regression-') as temporary, \
            contextlib.ExitStack() as owned:
        work = Path(temporary)
        work.chmod(0o711)
        readonly_account_source(work)
        outer_workspace = work/'outer-accounts'
        outer_workspace.mkdir()
        outer_etc = owned.enter_context(GUARDIAN.private_account_directory(Path('/etc'), outer_workspace))
        owned.enter_context(GUARDIAN.bind_account_directory(outer_etc, Path('/etc')))
        # These files exist only in our outer private account namespace. Both
        # relative links escape /etc and must keep their meaning after the
        # production runner prepares and mounts its nested private directory.
        Path('/etc/routervpn-relative-config').symlink_to('../usr/lib/os-release')
        Path('/etc/routervpn-relative.d').mkdir()
        Path('/etc/routervpn-relative.d/release').symlink_to('../../usr/lib/os-release')
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
        account_hashes = {name: hashlib.sha256((Path('/etc')/name).read_bytes()).digest()
                          for name in GUARDIAN.ACCOUNT_FILES if (Path('/etc')/name).is_file()}

        def run_case(module, status):
            executable = work/('verdict-'+str(status)+'.py')
            executable.write_text('#!'+sys.executable+'\n' + '''
import os, pathlib, pwd, secrets, signal, subprocess, sys
assert os.environ.get('ROUTERVPN_LINUX_GUARDIAN_TEST_NS') == '1'
assert os.getppid() == 1, 'the actual runner must own this test process as PID 1'
assert not pathlib.Path('/run/user/1001').exists(), 'the inherited mount was not hidden by the private /run'
assert any(line.split()[4] == '/etc' for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines())
for path in ('/etc/routervpn-relative-config', '/etc/routervpn-relative.d/release', '/etc/os-release'):
    assert pathlib.Path(path).read_bytes() == pathlib.Path('/usr/lib/os-release').read_bytes(), 'relative configuration link changed meaning'
account = 'rvpnt_' + secrets.token_hex(10)
subprocess.run(['/usr/sbin/useradd', '--no-log-init', '--no-create-home', '--password', '!', '--expiredate', '1',
                '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', '--user-group', '--uid', '1073743105', account], check=True)
assert any(line.startswith(account+':') for line in pathlib.Path('/etc/passwd').read_text().splitlines())
assert any(line.startswith(account+':!') for line in pathlib.Path('/etc/shadow').read_text().splitlines())
assert pwd.getpwnam(account).pw_uid == 1073743105, 'actual NSS did not read the private account'
subprocess.run(['/usr/sbin/userdel', account], check=True)
assert not any(line.startswith(account+':') for line in pathlib.Path('/etc/passwd').read_text().splitlines())
try:
    pwd.getpwnam(account)
except KeyError:
    pass
else:
    raise AssertionError('actual NSS retained the retired private account')
''' + ("os.kill(os.getpid(), signal.SIGTERM)\n" if status == 143 else 'sys.exit('+str(status)+')\n'))
            executable.chmod(0o700)
            print('Guardian nested mount isolation starting test status '+str(status)+'.', flush=True)
            result = module.namespace_test(executable)
            unchanged_mount(inherited, sentinel)
            if Path('/proc/self/mountinfo').read_text() != mounts:
                raise AssertionError('Nested runner changed its parent mount namespace')
            if {name: os.readlink('/proc/self/ns/'+name) for name in parent_identity} != parent_identity:
                raise AssertionError('Nested runner replaced its parent namespace owner')
            if any(hashlib.sha256((Path('/etc')/name).read_bytes()).digest() != digest for name, digest in account_hashes.items()):
                raise AssertionError('Actual isolated account tools changed an original account database')
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
    from test_linux_guardian_cleanup import check as check_timeout_cleanup
    check_timeout_cleanup()
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
