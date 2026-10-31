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
import contextlib
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('desktop_linux_guardian_uid', ROOT / 'deploy/test_desktop_socket_uid.py')
UID = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UID)

KERNEL_CASES = ('TCPAndUDP', 'RejectsWrongUIDAndPrivatePeer', 'ExpirySurvivesGuardianCrash', 'HeartbeatAdmission',
                'SocketRetirementReusesCapacity', 'RejectsChangedBaseline', 'NativeParentCrash',
                'BlockedControlRetainsSourcePort', 'RejectsStaleCaptureAndGeneration',
                'OldCleanupPreservesReplacement', 'FinishRequiresDescriptorRetirement',
                'ClosedProtectionObservations', 'RejectsDormantTable', 'BaselineTransactions', 'RetainedBaseline', 'NodeBaselineSuccession', 'NodeProcessWitness', 'NodeCreationJournalReceipt')
ACCOUNT_FILES = ('passwd', 'group', 'shadow', 'gshadow', 'subuid', 'subgid')
BASELINE_CASES = ('RequiresCommittedBatchReceipt', 'ReplyRejectsUnrelatedDatagrams',
                  'GenerationRejectsMissingOrAmbiguousIdentity', 'EndpointRequiresRetainedOwner',
                  'SemanticFailureRetiresOriginalEndpoint', 'RetentionRequiresOriginalUnusedSource',
                  'RetentionPartialCloseOwnsOnlyOriginalDescriptors', 'RetentionCancelledWaitCannotEnterAnotherOperation',
                  'NodeCreationReceiptRequiresExactOperations', 'NodeScopeAndAbsence', 'NodePartialOwnerCannotMutate',
                  'GuardianRecordRequiresNativeRelationship', 'GuardianPartialWitnessCannotCreateProof',
                  'NodeCreationRecordBindsPreparedIdentity')


def account_mount(source, target, flags):
    # This fixture owns a private mount namespace. Do not fork one mount(8)
    # process per /etc entry: on hosted runners that overhead exceeds the
    # bounded multi-case regression despite each account operation succeeding.
    library = ctypes.CDLL(None, use_errno=True)
    mount = library.mount
    mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p)
    mount.restype = ctypes.c_int
    if mount(None if source is None else os.fsencode(source), os.fsencode(target), None, flags, None) != 0:
        failure = ctypes.get_errno()
        raise OSError(failure, os.strerror(failure), str(target))


def account_readonly_flags(options):
    # A bind remount updates VFS flags. Retain the original security/atime
    # restrictions, including inherited locked flags in nested namespaces.
    native = {'ro': 1, 'rw': 0, 'nosuid': 2, 'nodev': 4, 'noexec': 8,
              'sync': 16, 'mand': 64, 'dirsync': 128, 'nosymfollow': 256,
              'noatime': 1024, 'nodiratime': 2048, 'relatime': 1 << 21,
              'iversion': 1 << 23, 'strictatime': 1 << 24, 'lazytime': 1 << 25}
    if not options.issubset(native):
        raise ValueError('Private account source has unrecognized native mount flags')
    flags = 4096 | 32 | 1  # MS_BIND | MS_REMOUNT | MS_RDONLY
    for option in options:
        flags |= native[option]
    return flags


def account_mounts(directory):
    result = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        path = Path(re.sub(r'\\([0-7]{3})', lambda match: chr(int(match.group(1), 8)), fields[4]))
        if path == directory or path.is_relative_to(directory):
            result.append((fields[0], path, frozenset(fields[5].split(','))))
    return result


def unmount_account_mounts(mounted):
    # An rbind at /etc can hide existing /etc submounts. Retire only captured
    # new mount IDs, checking the currently visible native root first.
    # A less-privileged nested user namespace locks inherited submounts into
    # their tree. Detach our complete new bind after its test child joins;
    # do not attempt to unmount locked or hidden inherited children separately.
    # The joined namespace owner remains the final lifetime boundary.
    by_path = {}
    for identity, path, _ in mounted:
        by_path.setdefault(path, set()).add(identity)
    roots = [path for path in by_path if not any(parent in by_path for parent in path.parents)]
    for path in roots:
        descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            native = [line.split()[1] for line in Path('/proc/self/fdinfo/'+str(descriptor)).read_text().splitlines()
                      if line.startswith('mnt_id:')]
        finally:
            os.close(descriptor)
        if len(native) != 1 or native[0] not in by_path[path]:
            raise ValueError('Private account cleanup lost its original visible mount')
        captured = {identity for identity, target, _ in mounted if target == path or target.is_relative_to(path)}
        library = ctypes.CDLL(None, use_errno=True)
        unmount = library.umount2
        unmount.argtypes = (ctypes.c_char_p, ctypes.c_int)
        unmount.restype = ctypes.c_int
        if unmount(os.fsencode(path), 2 | 8) != 0:  # MNT_DETACH | UMOUNT_NOFOLLOW
            failure = ctypes.get_errno()
            raise OSError(failure, os.strerror(failure), str(path))
        if any(identity in captured for identity, _, _ in account_mounts(path)):
            raise ValueError('Private account cleanup retained its captured mount tree')


@contextlib.contextmanager
def bind_account_directory(source, target):
    before = {identity for identity, _, _ in account_mounts(target)}
    account_mount(source, target, 4096 | 16384)  # MS_BIND | MS_REC
    owned = [record for record in account_mounts(target) if record[0] not in before]
    try:
        if not any(path == target for _, path, _ in owned):
            raise ValueError('Private account directory lost its new root mount')
        yield
    finally:
        unmount_account_mounts(owned)


@contextlib.contextmanager
def private_account_directory(source, workspace):
    """Capture config read-only and copy only the account tools' mutable files.

    The caller owns a private mount namespace. Recursive read-only backing
    retains the real NSS/tool configuration without copying an unrelated
    runner's whole /etc tree. Account databases, backups and locks never alias
    that backing. Other users still need directory traversal for NSS reads.
    """
    workspace.chmod(0o711)
    backing, private = workspace/'original-etc', workspace/'etc'
    backing.mkdir()
    account_mount(source, backing, 4096 | 16384)
    mounted = account_mounts(backing)
    private_mounts = []
    try:
        if not any(path == backing for _, path, _ in mounted):
            raise ValueError('Private account source lost its captured bind mount')
        for _, path, options in sorted(mounted, key=lambda item: len(item[1].parts), reverse=True):
            account_mount(None, path, account_readonly_flags(options))
        observed = account_mounts(backing)
        expected_options = {(identity, path): (options-{'rw'}) | {'ro'} for identity, path, options in mounted}
        if ({(identity, path) for identity, path, _ in observed} !=
                {(identity, path) for identity, path, _ in mounted}
                or any(options != expected_options[(identity, path)] for identity, path, options in observed)):
            raise ValueError('Private account source is not recursively read-only')
        source_info = source.stat()
        private.mkdir(mode=stat.S_IMODE(source_info.st_mode))
        private.chmod(stat.S_IMODE(source_info.st_mode))
        os.chown(private, source_info.st_uid, source_info.st_gid)
        mutable = set(ACCOUNT_FILES) | {name+'-' for name in ACCOUNT_FILES}
        locks = {'.pwd.lock', *(name+'.lock' for name in ACCOUNT_FILES)}
        for entry in backing.iterdir():
            target = private/entry.name
            if entry.name in locks:
                continue
            if entry.name in mutable:
                info = entry.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_size > 8*1024*1024:
                    raise ValueError('Private account database is not a bounded regular file: '+entry.name)
                shutil.copy2(entry, target, follow_symlinks=False)
                os.chown(target, info.st_uid, info.st_gid, follow_symlinks=False)
            elif entry.is_symlink():
                # Relative links must resolve at their real /etc position,
                # including links escaping /etc to /usr. Indirection through
                # an unrelated /tmp backing path changes that meaning.
                target.symlink_to(os.readlink(entry))
            else:
                if entry.is_dir():
                    target.mkdir()
                    flags = 4096 | 16384
                else:
                    target.touch()
                    flags = 4096
                account_mount(entry, target, flags)
                private_mounts.extend(account_mounts(target))
        if any(not (private/name).is_file() or (private/name).is_symlink() for name in ACCOUNT_FILES[:4]):
            raise ValueError('Private account source is missing a required local database')
        yield private
    finally:
        unmount_account_mounts(private_mounts)
        unmount_account_mounts(mounted)


def namespace_progress(message):
    # Keep the exact entered phase in UID.run's bounded timeout output. A
    # native setup hang must identify its operation before process-group
    # cleanup, without extending the fixture's existing deadlines.
    print('Linux guardian namespace phase: ' + message +
          ' (pid=' + str(os.getpid()) + ', monotonic=' + format(time.monotonic(), '.3f') + ')', flush=True)


def namespace_test(binary: Path, case=None) -> int:
    if os.geteuid() != 0 or platform.system() != 'Linux' or not binary.is_absolute() or not binary.is_file():
        raise ValueError('The Linux guardian namespace runner requires its real root-owned invocation')
    libc = ctypes.CDLL(None, use_errno=True)
    ready_read, ready_write = os.pipe()
    map_read, map_write = os.pipe()
    namespace_progress('fork user-namespace child')
    child = os.fork()
    if child == 0:
        try:
            os.close(ready_read)
            os.close(map_write)
            namespace_progress('enter user namespace')
            if libc.unshare(0x10000000) != 0:  # CLONE_NEWUSER
                raise OSError(ctypes.get_errno(), 'Linux guardian user namespace')
            os.write(ready_write, b'1')
            namespace_progress('wait for original parent UID/GID mapping')
            if os.read(map_read, 1) != b'1':
                raise RuntimeError('Linux guardian UID map was not acknowledged')
            os.close(ready_write)
            os.close(map_read)
            namespace_progress('UID/GID mapping acknowledged')
            # PID 1 owns the entire test process tree, including deliberately
            # crashed native parents and independent guardians. Its exit ends
            # every descendant even if a negative control leaves one alive.
            if libc.unshare(0x40000000 | 0x00020000 | 0x20000000) != 0:
                raise OSError(ctypes.get_errno(), 'Linux guardian network/mount/PID namespaces')
            namespace_progress('fork private namespace init')
            init = os.fork()
            if init:
                namespace_progress('wait for private namespace init')
                _, status = os.waitpid(init, 0)
                os._exit(os.waitstatus_to_exitcode(status))
            namespace_progress('make inherited mounts private')
            subprocess.run(['mount', '--make-rprivate', '/'], check=True)
            namespace_progress('capture read-only configuration and private account files')
            with tempfile.TemporaryDirectory(prefix='routervpn-guardian-namespace-') as temporary, \
                    private_account_directory(Path('/etc'), Path(temporary)) as etc, \
                    bind_account_directory(etc, Path('/etc')):
                namespace_progress('bind private account directory')
                namespace_progress('mount private runtime directory')
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
                    namespace_progress('ip ' + ' '.join(arguments))
                    subprocess.run(['ip', *arguments], check=True)
                environment = dict(os.environ, ROUTERVPN_LINUX_GUARDIAN_TEST_NS='1')
                selector = '^TestDesktopLinuxGuardianKernel' + (case + '$' if case else '')
                namespace_progress('execute owned test process')
                result = subprocess.run([str(binary), '-test.run=' + selector,
                                         '-test.count=1', '-test.timeout=120s', '-test.v'],
                                        env=environment, timeout=135).returncode
                namespace_progress('retire owned peer namespace; test status ' + str(result))
                subprocess.run(['ip', 'netns', 'delete', 'rvpn-peer'], check=True)
                # /run is a private tmpfs owned by this PID/mount namespace.
                # Its remaining mounts disappear when this namespace exits.
                # Recursive umount also enumerates hidden inherited mounts
                # (for example a runner's /run/user/1001), which this test
                # neither created nor has authority to retire.
                namespace_progress('unmount private account directory')
            namespace_progress('private account workspace removed; return test status ' + str(result))
            os._exit(result if result >= 0 else 128 - result)
        except BaseException as error:
            print('Linux guardian namespace failed: ' + str(error), file=sys.stderr, flush=True)
            os._exit(1)
    os.close(ready_write)
    os.close(map_read)
    try:
        namespace_progress('wait for user-namespace child readiness')
        if os.read(ready_read, 1) != b'1':
            raise RuntimeError('Linux guardian user namespace did not start')
        # The privileged parent writes the maps. No newuidmap installation or
        # host subuid/account edit is needed. A complete mapping allows the
        # production helper to drop all supplementary groups normally.
        namespace_progress('write original child UID/GID mappings')
        Path(f'/proc/{child}/uid_map').write_text('0 0 2147483647\n')
        Path(f'/proc/{child}/gid_map').write_text('0 0 2147483647\n')
        os.write(map_write, b'1')
    finally:
        os.close(map_write)
        os.close(ready_read)
    namespace_progress('wait for original namespace child')
    _, status = os.waitpid(child, 0)
    namespace_progress('original namespace child joined')
    return os.waitstatus_to_exitcode(status)


def execute(source: Path, go='go', *, env=None):
    if platform.system() != 'Linux':
        raise ValueError('The Linux guardian kernel gate requires a matching Linux host')
    source, before = UID.checked_sources(source)
    required = {'desktop_socket_linux_policy.go', 'desktop_socket_linux_helper.go',
                'desktop_socket_linux_nft.go', 'desktop_socket_linux_guardian_test.go',
                'desktop_socket_linux_protection.go', 'desktop_socket_linux_protection_record.go',
                'desktop_socket_linux_protection_native_test.go', 'desktop_socket_linux_flags_test.go',
                'desktop_socket_linux_baseline_netlink.go', 'desktop_socket_linux_baseline_netlink_test.go',
                'desktop_socket_linux_baseline_netlink_native_test.go', 'desktop_socket_linux_baseline_owner.go',
                'desktop_socket_linux_baseline_owner_test.go', 'desktop_socket_linux_baseline_owner_native_test.go',
                'desktop_socket_linux_node_baseline.go', 'desktop_socket_linux_node_baseline_test.go',
                'desktop_socket_linux_node_baseline_native_test.go', 'desktop_socket_linux_guardian_process.go',
                'desktop_socket_linux_guardian_record.go', 'desktop_socket_linux_guardian_record_test.go',
                'desktop_socket_linux_guardian_process_test.go', 'desktop_socket_linux_guardian_process_native_test.go',
                'desktop_socket_linux_node_creation.go', 'desktop_socket_linux_node_creation_record.go',
                'desktop_socket_linux_node_creation_record_test.go', 'desktop_socket_linux_node_creation_native_test.go'}
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
        baseline_output = UID.run([str(binary), '-test.run=^TestLinuxBaseline', '-test.count=1',
                                   '-test.timeout=20s', '-test.v'], cwd=source)
        if any('--- PASS: TestLinuxBaseline' + name + ' (' not in baseline_output for name in BASELINE_CASES) or '--- SKIP:' in baseline_output:
            raise ValueError('Linux baseline receipt gate omitted an owned transaction boundary')
        print(baseline_output, end='' if baseline_output.endswith('\n') else '\n')
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
        'active table flags': 'actual heartbeat accepted the dormant native baseline',
        'conditional baseline generation': 'stale ruleset generation did not reject the actual conditional transaction',
        'original baseline table handle': 'retired handle deleted or adopted a same-name replacement',
        'committed baseline receipt': 'substituted for committed batch receipt',
        'uncertain baseline receipt': 'semantic receipt failure left its original endpoint reusable',
        'joined retained baseline source': 'live guardian authorized baseline removal',
        'retained Always selection': 'disconnect changed the captured On-connect/Always semantics',
        'retained native namespace': 'changed native namespace substituted absence for the original replacement',
        'original creation journal snapshot': 'same-name native replacement became the original creation receipt',
        'original live guardian witness': 'dead guardian passed its retained native pidfd/task witness',
        'original Node creation receipt': 'changed create receipt became original baseline ownership',
        'closed Node predecessor': 'unretired Node predecessor authorized successor deletion',
        'closed Node successor': 'rejected successor changed old deny baseline',
        'reserved Node initial absence': 'scoped Node baseline was hidden from initial journal absence',
    }
    mutations = (
        ('original creation journal snapshot', 'NodeCreationJournalReceipt', 'desktop_socket_linux_node_creation.go', (
            ('if _, err := b.observe(ctx, false); err != nil {', 'if _, err := b.observe(ctx, false); false {'),
        )),
        ('original live guardian witness', 'NodeProcessWitness', 'desktop_socket_linux_guardian_process.go', (
            ('guardian, guardianErr := w.child.Current(ctx)', 'guardian, guardianErr := w.record.Guardian, error(nil)'),
        )),
        ('original Node creation receipt', 'TestLinuxBaselineNodeCreationReceiptRequiresExactOperations', 'desktop_socket_linux_node_baseline.go', (
            ('!reflect.DeepEqual(row, request[index])', '!reflect.DeepEqual(row, row)'),
        )),
        ('closed Node predecessor', 'NodeBaselineSuccession', 'desktop_socket_linux_node_baseline.go', (
            ('\t\tif err := b.read(ctx, false); err != nil {\n\t\t\treturn err\n\t\t}\n', ''),
        )),
        ('closed Node successor', 'NodeBaselineSuccession', 'desktop_socket_linux_node_baseline.go', (
            ('\t\tif err := successor.read(ctx, true); err != nil {\n\t\t\treturn err\n\t\t}\n', ''),
        )),
        ('reserved Node initial absence', 'NodeBaselineSuccession', 'desktop_socket_linux_expectation.go', (
            ('strings.HasPrefix(name, desktopLinuxNodeTablePrefix)', 'strings.HasPrefix(name, "unowned_node_prefix_")'),
        )),
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
        ('active table flags', 'RejectsDormantTable', 'desktop_socket_linux_nft.go', (
            ('values, ok := flags.([]any)\n\treturn ok && len(values) == 0',
             '_ = flags\n\treturn true'),
        )),
        ('conditional baseline generation', 'BaselineTransactions', 'desktop_socket_linux_baseline_netlink.go', (
            ('binary.BigEndian.PutUint32(gen[:], generation)', 'binary.BigEndian.PutUint32(gen[:], 0)'),
        )),
        ('original baseline table handle', 'BaselineTransactions', 'desktop_socket_linux_baseline_netlink.go', (
            ('desktopLinuxBaselineAttribute(4, object[:])',
             'desktopLinuxBaselineAttribute(1, []byte("rvpn_baseline_transaction\\x00"))'),
        )),
        ('committed baseline receipt', 'TestLinuxBaselineRequiresCommittedBatchReceipt', 'desktop_socket_linux_baseline_netlink.go', (
            ('if index != 2 {', 'if index != 1 && index != 2 {'),
        )),
        ('uncertain baseline receipt', 'TestLinuxBaselineSemanticFailureRetiresOriginalEndpoint', 'desktop_socket_linux_baseline_netlink.go', (
            ('\t\tn.uncertain = err\n', '\t\t_ = err\n'),
        )),
        ('joined retained baseline source', 'RetainedBaseline', 'desktop_socket_linux_baseline_owner.go', (
            ('b.observe(ctx, false)', 'b.observe(ctx, true)'),
        )),
        ('retained Always selection', 'RetainedBaseline', 'desktop_socket_linux_baseline_owner.go', (
            ('if b.policy == "always" {', 'if false && b.policy == "always" {'),
            ('if b.policy != "on-connect" {', 'if b.policy != "on-connect" && b.policy != "always" {'),
        )),
        ('retained native namespace', 'RetainedBaseline', 'desktop_socket_linux_baseline_owner.go', (
            ('|| !os.SameFile(current, b.namespaceInfo)', '|| false && !os.SameFile(current, b.namespaceInfo)'),
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
            native = not case.startswith('TestLinuxBaseline')
            expected_case = 'TestDesktopLinuxGuardianKernel'+case if native else case
            if native:
                command = [sys.executable, str(Path(__file__).resolve()), '--namespace-test-binary', str(binary),
                           '--kernel-case', case]
                if sudo is not None:
                    command = [sudo, '-n', '--', *command]
            else:
                command = [str(binary), '-test.run=^'+case+'$', '-test.count=1', '-test.timeout=20s', '-test.v']
            try:
                UID.run(command, cwd=source, timeout=150, sudo=sudo)
            except subprocess.CalledProcessError as error:
                output = error.output.decode('utf-8', errors='replace')
                witness = heartbeat_witnesses.get(label)
                if ('--- FAIL: '+expected_case+' (' not in output
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
