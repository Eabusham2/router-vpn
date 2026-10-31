#!/usr/bin/env python3
"""Run the exact copied Unix socket creator tests under real privilege.

Compilation stays with the native build user. Only the explicit tagged fixture
executes under root/sudo -n. It forks a temporary numeric test UID, transfers
unconnected descriptors, and uses owned loopback peers; it creates no accounts,
routes or firewall state. Missing privilege is a failure, never a skipped gate.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import signal
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('desktop_socket_uid_preparation', ROOT/'deploy/prepare-desktop-external.py')
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)


def checked_sources(source):
    source = PREP.checked_vendor(source)
    expected = sorted((ROOT/'internal/mobiletor').glob('desktop_socket_*.go'))
    required = {'desktop_socket_source.go', 'desktop_socket_source_unix.go',
                'desktop_socket_source_privileged_test.go', 'desktop_socket_source_unix_test.go'}
    if not required.issubset(path.name for path in expected):
        raise ValueError('Owned Unix creator source/test closure is incomplete')
    records = {}
    for path in expected:
        target = source/'routervpn/mobiletor'/path.name
        if path.is_symlink() or target.is_symlink() or not target.is_file():
            raise ValueError('Owned Unix creator source must be an actual copied regular file: '+path.name)
        raw = path.read_bytes()
        # The preparer relocates only these declared shared-package imports.
        # Compare the actual shipping copy, not an unrelocated source file or
        # an independently simplified fixture. All other bytes remain exact.
        copied = PREP.relocated_shared_source(raw)
        if target.read_bytes() != copied:
            raise ValueError('Owned Unix creator test differs from the exact prepared source: '+path.name)
        records[path.name] = hashlib.sha256(raw).hexdigest()
    return source, records


def run(command, *, cwd=None, env=None, timeout=180, sudo=None):
    # A separate group contains the fixture and its forked helpers. On timeout
    # the same available privilege kills only that freshly owned group; no PID
    # lookup, broad process name or ambient session is used for cleanup.
    process = subprocess.Popen([str(value) for value in command], cwd=cwd, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as expired:
        try:
            if sudo is None:
                os.killpg(process.pid, signal.SIGKILL)
            else:
                # An external kill parses options independently of Bash's
                # builtin. Delimit this captured negative PGID explicitly;
                # otherwise a successful command need not signal the group.
                subprocess.run([sudo, '-n', '--', '/bin/kill', '-KILL', '--', '-'+str(process.pid)],
                               check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            output, _ = process.communicate(timeout=5)
        except (OSError, subprocess.SubprocessError) as cleanup:
            # Preserve the first timeout's progress even if the output pipe
            # remains owned by a live descendant. Never call that a join.
            partial = getattr(cleanup, 'output', None) or expired.output or b''
            raise RuntimeError('Owned socket fixture timed out and its process group could not be joined: '+
                               partial[-8192:].decode('utf-8', errors='replace')) from cleanup
        raise RuntimeError('Owned socket fixture timed out after its process group was joined: '+output[-8192:].decode('utf-8', errors='replace'))
    if process.returncode:
        raise subprocess.CalledProcessError(process.returncode, command, output=output)
    return output.decode('utf-8')


def privilege_tool():
    if os.geteuid() == 0:
        return None
    path = Path('/usr/bin/sudo')
    if path.is_symlink() or not path.is_file():
        raise ValueError('The native build requires root or /usr/bin/sudo -n for the explicit UID fixture')
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('The native UID fixture has no trusted system sudo')
    return str(path)


def compiler_toolchain(source, go, env):
    # The launcher on PATH may be older than the toolchain selected by the
    # native build. Resolve that selection before disabling Go's dispatch;
    # setting local on the launcher first silently switches back to its Go.
    identity = json.loads(run([go, 'env', '-json', 'GOROOT', 'GOVERSION'],
                              cwd=source, env=env))
    if not isinstance(identity, dict) or any(not isinstance(identity.get(key), str) or
            not identity[key] for key in ('GOROOT', 'GOVERSION')):
        raise ValueError('The UID fixture did not resolve its selected Go toolchain')
    root = Path(identity['GOROOT'])
    compiler = root/'bin/go'
    if not root.is_absolute() or not compiler.is_file() or not os.access(compiler, os.X_OK):
        raise ValueError('The UID fixture selected Go executable is unavailable')
    captured = dict(env, GOTOOLCHAIN='local', GOROOT=str(root))
    verified = json.loads(run([compiler, 'env', '-json', 'GOROOT', 'GOVERSION'],
                             cwd=source, env=captured))
    if verified != identity:
        raise ValueError('The UID fixture selected Go toolchain changed before compilation')
    return compiler, captured


def execute(source, go='go', *, env=None):
    if platform.system() not in ('Linux', 'Darwin'):
        raise ValueError('The privileged Unix creator fixture requires a matching Linux/macOS host')
    source, before = checked_sources(source)
    captured = dict(os.environ if env is None else env)
    captured['GOWORK'] = 'off'
    host = 'darwin' if platform.system() == 'Darwin' else 'linux'
    if captured.get('GOOS', host) != host:
        raise ValueError('The privileged socket fixture cannot execute a cross-compiled binary')
    sudo = privilege_tool()
    go, captured = compiler_toolchain(source, go, captured)
    with tempfile.TemporaryDirectory(prefix='routervpn-uid-gate-') as directory:
        binary = Path(directory)/'owned-socket-uid.test'
        run([go, 'test', '-c', '-race', '-mod=readonly', '-tags=routervpn_privileged',
             '-o', binary, './routervpn/mobiletor'], cwd=source, env=captured)
        if checked_sources(source)[1] != before:
            raise ValueError('Owned Unix creator source changed during fixture compilation')
        if binary.is_symlink() or not binary.is_file():
            raise ValueError('The UID fixture compiler did not produce the owned regular executable')
        info = binary.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size == 0:
            raise ValueError('The UID fixture executable ownership is invalid')
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        command = [str(binary), '-test.run=^TestDesktopSocketPrivileged', '-test.count=1',
                   '-test.timeout=45s', '-test.v']
        if sudo is not None:
            command = [sudo, '-n', '--', *command]
        output = run(command, cwd=source, timeout=60, sudo=sudo)
        required = ('TestDesktopSocketPrivilegedUIDSurvivesTransferImportAndDup',
                    'TestDesktopSocketPrivilegedWrongKernelUIDCannotGrant')
        if any('--- PASS: '+name+' (' not in output for name in required) or '--- SKIP:' in output:
            raise ValueError('The native UID fixture did not execute every required privileged test')
        for network in ('tcp4', 'udp4', 'tcp6', 'udp6'):
            if '--- PASS: '+required[0]+'/'+network+' (' not in output:
                raise ValueError('The native UID fixture omitted an actual kernel address family')
        after = binary.stat()
        if (after.st_dev, after.st_ino, after.st_size) != (info.st_dev, info.st_ino, info.st_size) or hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError('Owned UID fixture executable changed during its actual execution')
        if checked_sources(source)[1] != before:
            raise ValueError('Owned Unix creator source changed during fixture execution')
        print(output, end='' if output.endswith('\n') else '\n')
        print('Privileged UID/SCM_RIGHTS fixture passed; production UID/PF provisioning is separate.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    try:
        execute(args.source, args.go)
    except subprocess.CalledProcessError as error:
        if error.output:
            sys.stderr.write(error.output[-32768:].decode('utf-8', errors='replace'))
        raise
