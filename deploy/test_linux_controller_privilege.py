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
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('controller_privilege_toolchain', ROOT/'deploy/test_desktop_socket_uid.py')
UID = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UID)
CONTROL_SPEC = importlib.util.spec_from_file_location('controller_node_control', ROOT/'deploy/test_linux_node_control.py')
CONTROL = importlib.util.module_from_spec(CONTROL_SPEC)
CONTROL_SPEC.loader.exec_module(CONTROL)
TRANSACTION_SPEC = importlib.util.spec_from_file_location('controller_node_transaction', ROOT/'deploy/test_linux_node_transaction.py')
TRANSACTION = importlib.util.module_from_spec(TRANSACTION_SPEC)
TRANSACTION_SPEC.loader.exec_module(TRANSACTION)
SERVICE_SPEC = importlib.util.spec_from_file_location('standard_service_gate', ROOT/'deploy/linux_standard_service_gate.py')
SERVICE = importlib.util.module_from_spec(SERVICE_SPEC)
SERVICE_SPEC.loader.exec_module(SERVICE)
BUNDLE_SPEC = importlib.util.spec_from_file_location('standard_service_bundle', ROOT/'deploy/linux_standard_service_bundle.py')
BUNDLE = importlib.util.module_from_spec(BUNDLE_SPEC)
BUNDLE_SPEC.loader.exec_module(BUNDLE)
CASES = ('FixedInstallAndPipeLifetime', 'RejectsUnsafeInstallAndConfig',
         'RejectsForeignIdentityAndInput', 'HonorsInstallAndProcessLocks', 'RequiresBoundedHandshake',
         'RejectsUnownedInstalledMainPreservesUtilities', 'NodeParentRetainsExactObjects', 'NodeParentLifetimeAndRestart',
         'JournalRetainsNativeFiles', 'JournalRequiresActualAbsence', 'JournalRetainsFailedRetirement',
         'JournalSurvivesUpgradeWithoutAdoption', 'NodeEngineLauncher', 'EmptyJournalRecovery', 'ReleaseJournalRecovery')
EMPTY_RECOVERY_CASES = ('startup', 'restart', 'cancel-retry', 'cancel-shutdown', 'live-creator',
                        'creator-drift', 'replaced-session', 'root-replaced', 'slot-replaced', 'slot-bytes', 'namespace-changed',
                        'foreign-node', 'fixed-legacy', 'unrelated-policy', 'partial-record', 'intent-record', 'nonempty-record')
RELEASE_RECOVERY_CASES = ('startup', 'restart', 'cancel-retry', 'cancel-shutdown',
    'live-controller', 'zombie-controller', 'different-birth-controller', 'live-engine', 'zombie-engine', 'different-birth-engine',
    'live-guardian', 'zombie-guardian', 'different-birth-guardian', 'native-still-present', 'foreign-node', 'fixed-legacy', 'unrelated-policy',
    'always-release', 'saved-off', 'partial-record', 'chain-mismatch', 'creator-drift', 'checkpoint-drift', 'replaced-session',
    'replacement-owner', 'root-replaced', 'slot-replaced', 'slot-bytes', 'namespace-changed')
RECOVERY_NATIVE_GROUPS = {
    'TestLinuxOwnedControllerNamespaceEmptyJournalRecovery': EMPTY_RECOVERY_CASES,
    'TestLinuxOwnedControllerNamespaceReleaseJournalRecovery': RELEASE_RECOVERY_CASES,
}
EMPTY_RECOVERY_UNITS = {
    'TestDesktopLinuxEmptyRecoveryCreatorComparison': ('distinct', 'package-upgrade', 'same-tick', 'same-capture', 'same-pid',
        'same-proc-pid', 'future-creator', 'boot', 'caller', 'anchor', 'install-lock', 'process-lock', 'network', 'pid-namespace',
        'old-invalid', 'new-invalid'),
    'TestDesktopLinuxEmptyRecoveryRequiresCapturedOwner': ('absent', 'no-session', 'no-journal', 'foreign-session'),
    'TestDesktopLinuxReleaseRecoveryCheckpointComparison': ('complete-release', 'package-upgrade', 'settled-empty', 'incomplete',
        'invalid-record', 'controller', 'always-release', 'saved-off', 'legacy-target', 'settled-target', 'missing-intent', 'missing-target',
        'engine-not-joined', 'prepare', 'successor', 'preparation', 'nonempty-candidate', 'request', 'profile', 'revision', 'result-revision',
        'guardian-boot', 'guardian-network', 'guardian-pid-namespace', 'guardian-before-parent', 'guardian-after-restart',
        'guardian-is-old-controller', 'guardian-is-current-controller', 'guardian-proc-alias-old', 'guardian-proc-alias-current',
        'engine-is-old-controller', 'engine-is-current-controller', 'engine-is-guardian'),
}
PROCESS_CASES = ('Witness', 'CreatedBootstrap', 'RejectsForeignBootstrap', 'RetainsOriginalProcView',
                 'RejectsRetiredAndReexecutedTask', 'RetainsFailedClose', 'RejectsForeignPidFD',
                 'PreservesBorrowedParent', 'ChannelBoundsAndCancellation', 'InheritedCloseOnExec',
                 'ChannelPeerClosed', 'AcknowledgedPeerClose', 'SealedImageAdmission', 'SealedBootstrap')


PROCESS_SEALED_GROUPS = {
    'SealedImageAdmission': ('original', 'unsealed', 'writable', 'non-executable', 'ordinary-file', 'closed', 'replaced', 'nil'),
    'SealedBootstrap': ('complete', 'generic-refused', 'foreign-image', 'foreign-pidfd', 'nil-image',
                        'closed-before-bind', 'closed-after-bind', 'replaced-after-bind', 'reexecuted'),
}


def check_sealed_process_verdict(output):
    if '--- SKIP:' in output or '--- FAIL:' in output:
        raise ValueError('Linux sealed process gate skipped or failed an original capability boundary')
    passed = re.findall(r'(?m)^\s*--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)$', output)
    for group, leaves in PROCESS_SEALED_GROUPS.items():
        for suffix in (group, *(group+'/'+leaf for leaf in leaves)):
            name = 'TestLinuxProcessNamespace'+suffix
            if passed.count(name) != 1:
                raise ValueError('Linux sealed process gate omitted or duplicated its exact original boundary: '+name)


def check_empty_recovery_verdict(output, *, native=False):
    if '--- SKIP:' in output or '--- FAIL:' in output:
        raise ValueError('Linux empty recovery skipped or failed an original owner boundary')
    groups = RECOVERY_NATIVE_GROUPS if native else EMPTY_RECOVERY_UNITS
    passed = re.findall(r'(?m)^\s*--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)$', output)
    for group, leaves in groups.items():
        for name in (group, *(group+'/'+leaf for leaf in leaves)):
            if passed.count(name) != 1:
                raise ValueError('Linux empty recovery omitted or duplicated its original boundary: '+name)


def source_identity():
    names = sorted(set([*BUNDLE.builder().inputs(), ROOT/'go.mod', ROOT/'go.sum', ROOT/'modes/kill-switch.py', ROOT/'modes/profile_id.py', *(ROOT/'cmd/client').glob('*'), *(ROOT/'internal').rglob('*.go'),
                    *(ROOT/'deploy'/name for name in (*CONTROL.RUNNERS, *TRANSACTION.RUNNERS, 'test_linux_controller_privilege.py',
                                                     'test_linux_empty_recovery_runner.py', 'test_linux_sealed_process_runner.py', *SERVICE.RUNNERS))]))
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in names if path.is_file() and not path.is_symlink()}


def namespace_test(binary, pattern='^TestLinuxOwnedControllerNamespace', process_sha256=None, runtime_bundle=None, runtime_manifest=None):
    if os.geteuid() != 0 or platform.system() != 'Linux' or not binary.is_absolute() or not binary.is_file():
        raise ValueError('Controller namespace fixture requires its actual privileged Linux invocation')
    if pattern.startswith('^TestLinuxProcessNamespace') and (
            not isinstance(process_sha256, str) or len(process_sha256) != 64 or
            any(c not in '0123456789abcdef' for c in process_sha256)):
        raise ValueError('Native process fixture requires its exact compiled source executable digest')
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
            executable = binary
            if process_sha256 is not None:
                # The build user may be unprivileged. Copy only this exact
                # compiled fixture into the private /opt mount so its actual
                # executable has the root-owned image identity being proved.
                directory = Path('/opt/routervpn-process-proof')
                directory.mkdir(mode=0o700)
                executable = directory/'process.test'
                with binary.open('rb') as source, executable.open('xb') as target:
                    before = os.fstat(source.fileno())
                    shutil.copyfileobj(source, target)
                    target.flush()
                    os.fchmod(target.fileno(), 0o700)
                    after = os.fstat(source.fileno())
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError('Native process fixture source changed during its private copy')
                info = executable.stat()
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_gid != 0 or
                        info.st_mode & 0o022 or hashlib.sha256(executable.read_bytes()).hexdigest() != process_sha256):
                    raise ValueError('Native process fixture did not preserve its exact compiled protected image')
            runtime_env = {}
            if runtime_bundle is not None:
                staged = BUNDLE.copy_private(runtime_bundle, Path('/opt/routervpn-runtime-proof'), runtime_manifest)
                runtime_env['ROUTERVPN_STANDARD_RUNTIME_BUNDLE'] = str(staged)
            result = subprocess.run([str(executable), '-test.run=' + pattern,
                                     '-test.count=1', '-test.timeout=120s', '-test.v'],
                                    env=dict(os.environ, ROUTERVPN_CONTROLLER_PRIVILEGE_TEST_NS='1', **runtime_env),
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


def execute(go='go', runtime_bundle=None):
    if platform.system() != 'Linux':
        raise ValueError('The controller privilege gate requires a matching Linux host')
    before = source_identity()
    SERVICE.validate_inventory(ROOT)
    required = {'cmd/client/controller_local_auth.go', 'cmd/client/controller_local_auth_test.go',
                'cmd/client/controller_privilege_linux.go', 'cmd/client/controller_privilege_linux_test.go',
                'cmd/client/controller_privilege_linux_namespace_test.go', 'cmd/client/desktop_node_linux_parent.go',
                'cmd/client/desktop_node_linux_parent_native_test.go', 'cmd/client/desktop_node_linux_journal.go',
                'cmd/client/desktop_node_linux_journal_native_test.go', 'internal/linuxprotection/record.go',
                'cmd/client/desktop_node_recovery_linux.go', 'cmd/client/desktop_node_recovery_linux_test.go',
                'cmd/client/desktop_node_recovery_linux_native_test.go', 'cmd/client/desktop_node_linux_journal_cleanup.go',
                'cmd/client/desktop_node_recovery_release_linux_test.go', 'cmd/client/desktop_node_recovery_release_linux_native_test.go',
                'internal/linuxprotection/journal_record.go', 'internal/linuxprotection/journal_header.go',
                'internal/linuxprotection/journal_record_test.go', 'internal/mobiletor/desktop_socket_linux_expectation.go',
                'internal/linuxprocess/record.go', 'internal/linuxprocess/process_linux.go',
                'internal/linuxprocess/abi_linux.go', 'internal/linuxprocess/channel_linux.go',
                'internal/linuxprocess/pidfd_linux.go', 'internal/linuxprocess/bootstrap_linux.go',
                'internal/linuxprocess/process_linux_native_test.go',
                'internal/linuxprocess/close_on_exec_linux_test.go', 'internal/linuxprocess/close_on_exec_linux_native_test.go',
                'internal/linuxprocess/channel_eof_linux_native_test.go',
                'cmd/client/desktop_node_process_linux.go', 'cmd/client/desktop_node_process_linux_native_test.go',
                'cmd/client/desktop_node_process_finish_linux.go', 'cmd/client/desktop_node_process_finish_linux_native_test.go',
                'internal/linuxprotection/command_capture.go', 'internal/linuxprotection/command_capture_test.go',
                'internal/linuxprotection/node_control_record.go', 'internal/linuxprotection/node_control_record_test.go',
                'internal/linuxprotection/node_control_linux.go', 'internal/linuxprotection/node_control_linux_native_test.go',
                'deploy/test_linux_node_control.py', 'deploy/test_linux_node_control_runner.py'}
    if not required.issubset(before):
        raise ValueError('The actual controller privilege source/test closure is incomplete')
    env = dict(os.environ, GOWORK='off')
    if env.get('GOOS', 'linux') != 'linux':
        raise ValueError('The controller privilege gate cannot execute a cross-compiled binary')
    sudo = UID.privilege_tool()
    compiler, env = UID.compiler_toolchain(ROOT, go, env)
    runtime_manifest = BUNDLE.verify(runtime_bundle, env)
    UID.run([compiler, 'test', '-race', '-mod=readonly', '-count=1', './internal/linuxprotection', './internal/linuxprocess'], cwd=ROOT, env=env)
    recovery_units = UID.run([compiler, 'test', '-race', '-mod=readonly', '-count=1', '-v',
                              '-run=^TestDesktopLinux(Empty|Release)Recovery', './cmd/client'], cwd=ROOT, env=env)
    check_empty_recovery_verdict(recovery_units)
    print(recovery_units, end='' if recovery_units.endswith('\n') else '\n')
    UID.run([sys.executable, ROOT/'deploy/test_linux_empty_recovery_runner.py'], cwd=ROOT, env=env)
    UID.run([sys.executable, ROOT/'deploy/test_linux_standard_service_runner.py'], cwd=ROOT, env=env)
    UID.run([sys.executable, ROOT/'deploy/test_linux_standard_service_bundle.py'], cwd=ROOT, env=env)
    UID.run([sys.executable, ROOT/'deploy/test_linux_node_control_runner.py'], cwd=ROOT, env=env)
    CONTROL.execute(compiler, env=env)
    UID.run([sys.executable, ROOT/'deploy/test_linux_node_transaction_runner.py'], cwd=ROOT, env=env)
    TRANSACTION.execute(compiler, env=env)
    if source_identity() != before:
        raise ValueError('Original Node control/transaction source changed during its required native gates')
    with tempfile.TemporaryDirectory(prefix='routervpn-controller-privilege-') as temporary:
        service_binary = Path(temporary)/'standard-owner-service.test'
        UID.run([compiler, 'test', '-race', '-c', '-mod=readonly',
                 '-tags=routervpn_controller_privileged,routervpn_standard_service_native',
                 '-o', service_binary, './cmd/client'], cwd=ROOT, env=env)
        service_info = service_binary.lstat()
        if not stat.S_ISREG(service_info.st_mode) or service_info.st_nlink != 1 or service_info.st_mode & 0o022 or service_info.st_size == 0:
            raise ValueError('Standard service compiler did not produce its protected executable')
        service_digest = hashlib.sha256(service_binary.read_bytes()).hexdigest()
        for group in SERVICE.GROUPS:
            service_command = [sys.executable, str(Path(__file__).resolve()), '--namespace-service-binary', str(service_binary),
                               '--namespace-service-group', group, '--namespace-service-sha256', service_digest,
                               '--runtime-bundle', str(runtime_bundle), '--runtime-manifest-sha256', runtime_manifest]
            if sudo is not None:
                service_command = [sudo, '-n', '--', *service_command]
            service_output = UID.run(service_command, cwd=ROOT, timeout=150, sudo=sudo)
            SERVICE.check_verdict(service_output, group)
            print(service_output, end='' if service_output.endswith('\n') else '\n')
        service_after = service_binary.stat()
        if (service_after.st_dev, service_after.st_ino, service_after.st_size) != (service_info.st_dev, service_info.st_ino, service_info.st_size) or hashlib.sha256(service_binary.read_bytes()).hexdigest() != service_digest or source_identity() != before:
            raise ValueError('Standard service source or native executable changed during its required gates')
        process_binary = Path(temporary)/'native-process.test'
        UID.run([compiler, 'test', '-race', '-c', '-mod=readonly', '-tags=routervpn_controller_privileged',
                 '-o', process_binary, './internal/linuxprocess'], cwd=ROOT, env=env)
        process_info = process_binary.lstat()
        if not stat.S_ISREG(process_info.st_mode) or process_info.st_nlink != 1 or process_info.st_mode & 0o022 or process_info.st_size == 0:
            raise ValueError('Native process compiler did not produce its owned executable')
        process_digest = hashlib.sha256(process_binary.read_bytes()).hexdigest()
        if source_identity() != before:
            raise ValueError('Native process source changed during compilation')
        process_command = [sys.executable, str(Path(__file__).resolve()), '--namespace-process-binary', str(process_binary),
                           '--namespace-process-sha256', process_digest]
        if sudo is not None:
            process_command = [sudo, '-n', '--', *process_command]
        process_output = UID.run(process_command, cwd=ROOT, timeout=150, sudo=sudo)
        if any('--- PASS: TestLinuxProcessNamespace'+name+' (' not in process_output for name in PROCESS_CASES) or '--- SKIP:' in process_output:
            raise ValueError('Native process gate omitted a required actual creation, authentication or retirement case')
        check_sealed_process_verdict(process_output)
        process_leaves = {
            'Witness': ('original', 'wrong-pid', 'foreign-directory', 'closed-image', 'closed-directory'),
            'RejectsForeignBootstrap': ('wrong-capture', 'wrong-pid', 'wrong-image', 'wrong-channel', 'reopened-channel', 'parent-directory', 'cancelled'),
            'RetainsOriginalProcView': ('covered-fdinfo-directory', 'rejects-bind-crossing'),
            'RejectsRetiredAndReexecutedTask': ('retired-task-directory', 'reexecuted-image'),
            'ChannelBoundsAndCancellation': ('wrong-sender', 'extra-descriptor', 'oversize', 'cancelled-receive', 'close-joins-receive'),
            'InheritedCloseOnExec': ('channel', 'directory', 'image', 'still-authenticated'),
            'ChannelPeerClosed': ('original-peer-eof', 'write-half-close', 'empty-credential-frame', 'empty-rights-frame',
                                  'disabled-credentials', 'replaced-original', 'replaced-connection', 'changed-creator',
                                  'cancelled-receive', 'local-close', 'receive-timeout', 'cancelled-completion', 'retired-completion'),
        }
        for group, leaves in process_leaves.items():
            for leaf in leaves:
                if '--- PASS: TestLinuxProcessNamespace'+group+'/'+leaf+' (' not in process_output:
                    raise ValueError('Native process gate omitted its exact actual boundary: '+group+'/'+leaf)
        process_after = process_binary.stat()
        if ((process_after.st_dev, process_after.st_ino, process_after.st_size) != (process_info.st_dev, process_info.st_ino, process_info.st_size) or
                hashlib.sha256(process_binary.read_bytes()).hexdigest() != process_digest or source_identity() != before):
            raise ValueError('Native process executable or source changed during actual verification')
        print(process_output, end='' if process_output.endswith('\n') else '\n')
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
        check_empty_recovery_verdict(output, native=True)
        for ending in ('eof', 'second-byte'):
            if '--- PASS: TestLinuxOwnedControllerNamespaceFixedInstallAndPipeLifetime/'+ending+' (' not in output:
                raise ValueError('Controller did not execute its actual anonymous-pipe retirement case')
            if '--- PASS: TestLinuxOwnedControllerNamespaceNodeParentLifetimeAndRestart/'+ending+' (' not in output:
                raise ValueError('Node parent did not execute its actual retained GUI lifetime and restart')
        for case in ('root', 'image', 'image-descriptor', 'root-descriptor', 'anchor-descriptor', 'network-namespace-descriptor',
                     'pid-namespace-descriptor', 'process-witness', 'install-lock', 'process-lock', 'profile-root', 'application-owner', 'retire'):
            if '--- PASS: TestLinuxOwnedControllerNamespaceNodeParentRetainsExactObjects/'+case+' (' not in output:
                raise ValueError('Node parent omitted its captured native object substitution or retirement: '+case)
        for case in ('roundtrip', 'partial-write', 'cancelled-append', 'parent-join', 'closed-header', 'root', 'header', 'slot',
                     'header-symlink', 'slot-hardlink', 'extra-file', 'header-bytes', 'slot-bytes'):
            if '--- PASS: TestLinuxOwnedControllerNamespaceJournalRetainsNativeFiles/'+case+' (' not in output:
                raise ValueError('Linux journal omitted its actual native storage, cancellation or parent join: '+case)
        for case in ('restart', 'new-package-inodes'):
            if '--- PASS: TestLinuxOwnedControllerNamespaceJournalSurvivesUpgradeWithoutAdoption/'+case+' (' not in output:
                raise ValueError('Linux journal omitted its stable inode/explicit creator recovery boundary: '+case)
        for case in ('live', 'engine-exit', 'parent-retirement', 'image-replacement', 'workspace-replacement',
                     'wrong-capture', 'cancelled', 'wrong-verifier', 'finish-joined', 'finish-cancelled'):
            if '--- PASS: TestLinuxOwnedControllerNamespaceNodeEngineLauncher/'+case+' (' not in output:
                raise ValueError('Linux engine launcher omitted its actual captured process boundary: '+case)
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
    parser.add_argument('--runtime-bundle', type=Path, help='Actual already prepared native runtime directory')
    parser.add_argument('--runtime-manifest-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--namespace-test-binary', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--namespace-process-binary', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--namespace-process-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--namespace-service-binary', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--namespace-service-group', choices=tuple(SERVICE.GROUPS), help=argparse.SUPPRESS)
    parser.add_argument('--namespace-service-sha256', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.namespace_test_binary is not None:
        raise SystemExit(namespace_test(args.namespace_test_binary))
    if args.namespace_process_binary is not None:
        raise SystemExit(namespace_test(args.namespace_process_binary, '^TestLinuxProcessNamespace', args.namespace_process_sha256))
    if args.namespace_service_binary is not None:
        if args.namespace_service_group is None or not re.fullmatch(r'[0-9a-f]{64}', args.namespace_service_sha256 or ''):
            raise ValueError('Standard service requires its exact native test group')
        if args.runtime_bundle is None or not args.runtime_bundle.is_absolute() or not re.fullmatch(r'[0-9a-f]{64}', args.runtime_manifest_sha256 or ''):
            raise ValueError('Standard service requires the actual staged native bundle and exact original catalog')
        raise SystemExit(namespace_test(args.namespace_service_binary, SERVICE.pattern(args.namespace_service_group), args.namespace_service_sha256, args.runtime_bundle, args.runtime_manifest_sha256))
    try:
        execute(args.go, args.runtime_bundle.resolve() if args.runtime_bundle is not None else None)
    except subprocess.CalledProcessError as error:
        if error.output:
            sys.stderr.write(error.output[-32768:].decode('utf-8', errors='replace'))
        raise
