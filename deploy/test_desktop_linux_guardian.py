#!/usr/bin/env python3
"""Execute the exact Linux physical-socket guardian against an isolated kernel.

The build user's selected Go compiler creates the instrumented test executable.
Root is used only for fresh user/PID/network/mount namespaces with private
account files, /run, a veth link and a separate peer network namespace. The host
account database, routes and firewall are never changed. Missing namespace or
kernel support fails the mandatory gate; no privileged cases are skipped.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('desktop_linux_guardian_uid', ROOT / 'deploy/test_desktop_socket_uid.py')
UID = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UID)

KERNEL_CASES = ('TCPAndUDP', 'RejectsWrongUIDAndPrivatePeer', 'ExpirySurvivesGuardianCrash', 'HeartbeatAdmission',
                'SocketRetirementReusesCapacity', 'RejectsChangedBaseline', 'NativeParentCrash',
                'BlockedControlRetainsSourcePort', 'RejectsStaleCaptureAndGeneration',
                'OldCleanupPreservesReplacement', 'FinishRequiresDescriptorRetirement',
                'ClosedProtectionObservations')


def namespace_test(binary: Path, case=None) -> int:
    if os.geteuid() != 0 or platform.system() != 'Linux' or not binary.is_absolute() or not binary.is_file():
        raise ValueError('The Linux guardian namespace runner requires its real root-owned invocation')
    libc = ctypes.CDLL(None, use_errno=True)
    ready_read, ready_write = os.pipe()
    map_read, map_write = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(ready_read)
            os.close(map_write)
            if libc.unshare(0x10000000) != 0:  # CLONE_NEWUSER
                raise OSError(ctypes.get_errno(), 'Linux guardian user namespace')
            os.write(ready_write, b'1')
            if os.read(map_read, 1) != b'1':
                raise RuntimeError('Linux guardian UID map was not acknowledged')
            os.close(ready_write)
            os.close(map_read)
            # PID 1 owns the entire test process tree, including deliberately
            # crashed native parents and independent guardians. Its exit ends
            # every descendant even if a negative control leaves one alive.
            if libc.unshare(0x40000000 | 0x00020000 | 0x20000000) != 0:
                raise OSError(ctypes.get_errno(), 'Linux guardian network/mount/PID namespaces')
            init = os.fork()
            if init:
                _, status = os.waitpid(init, 0)
                os._exit(os.waitstatus_to_exitcode(status))
            subprocess.run(['mount', '--make-rprivate', '/'], check=True)
            with tempfile.TemporaryDirectory(prefix='routervpn-guardian-namespace-') as temporary:
                etc = Path(temporary) / 'etc'
                shutil.copytree('/etc', etc, symlinks=True)
                subprocess.run(['mount', '--bind', str(etc), '/etc'], check=True)
                subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run'], check=True)
                for arguments in [
                    ['link', 'set', 'lo', 'up'],
                    ['netns', 'add', 'rvpn-peer'],
                    ['link', 'add', 'rvpn-test', 'type', 'veth', 'peer', 'name', 'rvpn-peer'],
                    ['link', 'set', 'rvpn-peer', 'netns', 'rvpn-peer'],
                    ['addr', 'add', '198.18.0.1/30', 'dev', 'rvpn-test'],
                    ['-6', 'addr', 'add', 'fd50::1/64', 'dev', 'rvpn-test', 'nodad'],
                    ['link', 'set', 'rvpn-test', 'up'],
                    ['netns', 'exec', 'rvpn-peer', 'ip', 'link', 'set', 'lo', 'up'],
                    ['netns', 'exec', 'rvpn-peer', 'ip', 'addr', 'add', '198.18.0.2/30', 'dev', 'rvpn-peer'],
                    ['netns', 'exec', 'rvpn-peer', 'ip', '-6', 'addr', 'add', 'fd50::2/64', 'dev', 'rvpn-peer', 'nodad'],
                    ['netns', 'exec', 'rvpn-peer', 'ip', 'link', 'set', 'rvpn-peer', 'up'],
                ]:
                    subprocess.run(['ip', *arguments], check=True)
                environment = dict(os.environ, ROUTERVPN_LINUX_GUARDIAN_TEST_NS='1')
                selector = '^TestDesktopLinuxGuardianKernel' + (case + '$' if case else '')
                result = subprocess.run([str(binary), '-test.run=' + selector,
                                         '-test.count=1', '-test.timeout=120s', '-test.v'],
                                        env=environment, timeout=135).returncode
                subprocess.run(['ip', 'netns', 'delete', 'rvpn-peer'], check=True)
                # /run is a private tmpfs owned by this PID/mount namespace.
                # Its remaining mounts disappear when this namespace exits.
                # Recursive umount also enumerates hidden inherited mounts
                # (for example a runner's /run/user/1001), which this test
                # neither created nor has authority to retire.
                subprocess.run(['umount', '/etc'], check=True)
            os._exit(result if result >= 0 else 128 - result)
        except BaseException as error:
            print('Linux guardian namespace failed: ' + str(error), file=sys.stderr, flush=True)
            os._exit(1)
    os.close(ready_write)
    os.close(map_read)
    try:
        if os.read(ready_read, 1) != b'1':
            raise RuntimeError('Linux guardian user namespace did not start')
        # The privileged parent writes the maps. No newuidmap installation or
        # host subuid/account edit is needed. A complete mapping allows the
        # production helper to drop all supplementary groups normally.
        Path(f'/proc/{child}/uid_map').write_text('0 0 2147483647\n')
        Path(f'/proc/{child}/gid_map').write_text('0 0 2147483647\n')
        os.write(map_write, b'1')
    finally:
        os.close(map_write)
        os.close(ready_read)
    _, status = os.waitpid(child, 0)
    return os.waitstatus_to_exitcode(status)


def execute(source: Path, go='go', *, env=None):
    if platform.system() != 'Linux':
        raise ValueError('The Linux guardian kernel gate requires a matching Linux host')
    source, before = UID.checked_sources(source)
    required = {'desktop_socket_linux_policy.go', 'desktop_socket_linux_helper.go',
                'desktop_socket_linux_nft.go', 'desktop_socket_linux_guardian_test.go',
                'desktop_socket_linux_protection.go', 'desktop_socket_linux_protection_record.go',
                'desktop_socket_linux_protection_native_test.go'}
    if not required.issubset(before):
        raise ValueError('The complete production guardian and actual kernel tests were not copied')
    captured = dict(os.environ if env is None else env, GOWORK='off')
    if captured.get('GOOS', 'linux') != 'linux':
        raise ValueError('The Linux guardian gate cannot run a cross-compiled executable')
    sudo = UID.privilege_tool()
    compiler, captured = UID.compiler_toolchain(source, go, captured)
    namespace_output = UID.run([sys.executable, str(ROOT/'deploy/test_linux_guardian_namespace.py')],
                               cwd=ROOT, timeout=90, sudo=sudo)
    print(namespace_output, end='' if namespace_output.endswith('\n') else '\n')
    with tempfile.TemporaryDirectory(prefix='routervpn-linux-guardian-') as directory:
        binary = Path(directory) / 'linux-guardian.test'
        UID.run([compiler, 'test', '-c', '-race', '-mod=readonly', '-tags=routervpn_linux_guardian',
                 '-o', binary, './routervpn/mobiletor'], cwd=source, env=captured)
        if UID.checked_sources(source)[1] != before:
            raise ValueError('Linux guardian source changed during compilation')
        info = binary.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size == 0:
            raise ValueError('Linux guardian compiler did not produce its owned executable')
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        command = [sys.executable, str(Path(__file__).resolve()), '--namespace-test-binary', str(binary)]
        if sudo is not None:
            command = [sudo, '-n', '--', *command]
        output = UID.run(command, cwd=source, timeout=150, sudo=sudo)
        if any('--- PASS: TestDesktopLinuxGuardianKernel' + name + ' (' not in output for name in KERNEL_CASES) or '--- SKIP:' in output:
            raise ValueError('Linux guardian kernel gate did not execute every required boundary')
        for network in ('tcp4', 'udp4', 'tcp6', 'udp6'):
            if '--- PASS: TestDesktopLinuxGuardianKernelTCPAndUDP/' + network + ' (' not in output:
                raise ValueError('Linux guardian omitted a real physical transport/address family')
        after = binary.stat()
        if (after.st_dev, after.st_ino, after.st_size) != (info.st_dev, info.st_ino, info.st_size) or hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError('Linux guardian executable changed during its actual kernel run')
        if UID.checked_sources(source)[1] != before:
            raise ValueError('Linux guardian source changed during its actual kernel run')
        print(output, end='' if output.endswith('\n') else '\n')
        print('Linux isolated UID guardian, nft tuple ownership, expiry and cleanup passed against the actual kernel.')


def execute_mutations(source: Path, go='go', *, env=None):
    """Prove specific broken production boundaries fail their real kernel cases.

    Go overlays change only the compiler's temporary inputs. Neither the working
    tree nor the exact prepared package is edited or restored by this operation.
    """
    source, before = UID.checked_sources(source)
    captured = dict(os.environ if env is None else env, GOWORK='off')
    compiler, captured = UID.compiler_toolchain(source, go, captured)
    sudo = UID.privilege_tool()
    heartbeat_witnesses = {
        'admitted heartbeat deadline': 'queued heartbeat lost its admitted readback budget',
        'failed heartbeat cannot refresh proof': 'failed or stale heartbeat refreshed captured proof',
        'cancelled heartbeat cannot enter stream': 'cancelled heartbeat entered or refreshed its captured stream',
        'prepared source activity history': 'used source was relabelled as a fresh preparation',
        'prepared native tuple emptiness': 'active native tuple was accepted as closed preparation',
        'retired native join acknowledgment': 'empty inventory substituted for native close acknowledgment',
        'retired complete native baseline': 'changed native baseline was accepted as retained protection',
    }
    mutations = (
        ('admitted heartbeat deadline', 'HeartbeatAdmission', 'desktop_socket_linux_policy.go', (
            ('p.mu.Lock()\n\tdefer p.mu.Unlock()\n\tif p.closing.Load() {\n\t\treturn false, nil\n\t}\n\tctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)\n\tdefer cancel()',
             'ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)\n\tdefer cancel()\n\tp.mu.Lock()\n\tdefer p.mu.Unlock()\n\tif p.closing.Load() {\n\t\treturn false, nil\n\t}'),
        )),
        ('failed heartbeat cannot refresh proof', 'HeartbeatAdmission', 'desktop_socket_linux_policy.go', (
            ('if err == nil {\n\t\tp.observed.Store(time.Now().UnixMilli())',
             'if true {\n\t\tp.observed.Store(time.Now().UnixMilli())'),
        )),
        ('cancelled heartbeat cannot enter stream', 'HeartbeatAdmission', 'desktop_socket_linux_policy.go', (
            ('if p.closing.Load() {\n\t\treturn false, nil\n\t}',
             'if false && p.closing.Load() {\n\t\treturn false, nil\n\t}'),
        )),
        ('kernel UID predicate', 'RejectsWrongUIDAndPrivatePeer', 'desktop_socket_linux_nft.go', (
            ('output meta skuid %d meta l4proto %s', 'output meta l4proto %s'),
            ('desktopLinuxNFTTable, uid, network, family', 'desktopLinuxNFTTable, network, family'),
            ('return []any{match(map[string]any{"meta": map[string]any{"key": "skuid"}}, float64(n.UID)), match(',
             'return []any{match('),
        )),
        ('independent kernel expiry', 'ExpirySurvivesGuardianCrash', 'desktop_socket_linux_nft.go', (
            ('timeout 9s', 'timeout 60s'),
            ('float64(9)', 'float64(60)'),
        )),
        ('complete output baseline', 'RejectsChangedBaseline', 'desktop_socket_linux_nft.go', (
            ('ok && required {', 'ok && required && false {'),
            (' || len(baselineFound) != len(n.Baseline)', ''),
        )),
        ('per-socket source retirement', 'SocketRetirementReusesCapacity', 'desktop_socket_broker.go', (
            ('ok && (s.sourceFile != nil || s.sourceNative != nil) {',
             'ok && (s.sourceFile != nil || s.sourceNative != nil) && false {'),
        )),
        ('native descriptor acknowledgment', 'FinishRequiresDescriptorRetirement', 'desktop_socket_linux_helper.go', (
            ('if release && len(g.sockets) != 0 {', 'if false && release && len(g.sockets) != 0 {'),
        )),
        ('prepared source activity history', 'ClosedProtectionObservations', 'desktop_socket_linux_policy.go', (
            ('p.socketActivity = true', 'p.socketActivity = false'),
        )),
        ('prepared native tuple emptiness', 'ClosedProtectionObservations', 'desktop_socket_linux_protection.go', (
            ('!desktopLinuxProtectionEmpty(value, "elem") || ', ''),
        )),
        ('retired native join acknowledgment', 'ClosedProtectionObservations', 'desktop_socket_linux_protection.go', (
            ('!p.closeAcknowledged.Load() || !p.closing.Load() || !desktopLinuxJoined(p.joined) || !desktopLinuxJoined(p.monitorDone)',
             'false'),
        )),
        ('retired complete native baseline', 'ClosedProtectionObservations', 'desktop_socket_linux_protection.go', (
            ('if err = p.readProtection(ctx, false); err != nil {',
             'if err = error(nil); err != nil {'),
        )),
    )
    with tempfile.TemporaryDirectory(prefix='routervpn-guardian-mutations-') as temporary:
        directory = Path(temporary)
        for index, (label, case, name, replacements) in enumerate(mutations):
            original = source/'routervpn/mobiletor'/name
            content = original.read_text()
            for old, new in replacements:
                if old not in content:
                    raise ValueError('Guardian mutation no longer matches its real production boundary: '+label)
                content = content.replace(old, new)
            changed = directory/(str(index)+'-'+name)
            changed.write_text(content)
            overlay = directory/(str(index)+'-overlay.json')
            overlay.write_text(json.dumps({'Replace': {str(original): str(changed)}}))
            binary = directory/(str(index)+'-guardian.test')
            UID.run([compiler, 'test', '-c', '-race', '-mod=readonly', '-tags=routervpn_linux_guardian',
                     '-overlay='+str(overlay), '-o', binary, './routervpn/mobiletor'], cwd=source, env=captured)
            command = [sys.executable, str(Path(__file__).resolve()), '--namespace-test-binary', str(binary),
                       '--kernel-case', case]
            if sudo is not None:
                command = [sudo, '-n', '--', *command]
            try:
                UID.run(command, cwd=source, timeout=150, sudo=sudo)
            except subprocess.CalledProcessError as error:
                output = error.output.decode('utf-8', errors='replace')
                witness = heartbeat_witnesses.get(label)
                if ('--- FAIL: TestDesktopLinuxGuardianKernel'+case+' (' not in output
                        or witness is not None and witness not in output):
                    raise ValueError('Guardian mutation failed before its intended kernel assertion: '+label+'\n'+output) from error
                print('Rejected broken '+label+' through '+case+'.', flush=True)
            else:
                raise ValueError('Guardian mutation bypassed its intended kernel assertion: '+label)
    if UID.checked_sources(source)[1] != before:
        raise ValueError('Guardian sources changed while the temporary mutation controls ran')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, nargs='?')
    parser.add_argument('--go', default='go')
    parser.add_argument('--namespace-test-binary', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--kernel-case', choices=KERNEL_CASES, help=argparse.SUPPRESS)
    parser.add_argument('--mutations', action='store_true', help='Run temporary production mutation controls against the isolated kernel')
    args = parser.parse_args()
    if args.namespace_test_binary is not None:
        raise SystemExit(namespace_test(args.namespace_test_binary, args.kernel_case))
    if args.source is None:
        parser.error('the exact prepared native source is required')
    try:
        if args.mutations:
            execute_mutations(args.source, args.go)
        else:
            execute(args.source, args.go)
    except subprocess.CalledProcessError as error:
        if error.output:
            sys.stderr.write(error.output[-32768:].decode('utf-8', errors='replace'))
        raise
