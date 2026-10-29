#!/usr/bin/env python3
"""Run exact Darwin socket/PF ownership against a scoped native kernel fixture.

Compilation stays with the selected build-user Go toolchain. Privilege creates
only a unique root-owned test directory, four fresh loopback aliases, a private
PF anchor, one balanced PF reference, and disabled temporary socket identities.
Every deny/permit mutation stays on those aliases. No production anchor, default
route, existing account, global state table, or live Router VPN install is used.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import importlib.util
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('darwin_guardian_uid', ROOT/'deploy/test_desktop_socket_uid.py')
UID = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UID)

CASES = ('PFCompiler', 'PFSystemDispatch', 'PFAnchorPaths', 'ProtectedPathAuthority', 'IdentityRetirement', 'UIDObserver', 'TCPAndUDP', 'WrongUIDAndPrivatePeer', 'SocketRetirementReusesCapacity',
         'RetainedTunnel', 'BothOwnersCrashCannotReuseTuple', 'ForeignBlockAndLaterPass',
         'RejectsForeignStatefulDirections', 'BlockedControlRetainsSourcePort',
         'FinishRequiresDescriptorRetirement', 'FloatingStateRetirement',
         'StaleCaptureAndReplacement')


def checked_sources(source: Path):
    source = source.resolve()
    if source == ROOT:
        target, package = ROOT/'internal/mobiletor', './internal/mobiletor'
        records = {}
        for path in sorted(target.glob('desktop_socket_*.go')):
            if path.is_symlink() or not path.is_file():
                raise ValueError('The actual Darwin source must be a regular file')
            records[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        common = ROOT/'internal/common'
    else:
        source, records = UID.checked_sources(source)
        target, package = source/'routervpn/mobiletor', './routervpn/mobiletor'
        common = source/'routervpn/common'
    # The kernel ACL parser/readback is part of this ownership boundary too.
    for path in sorted((ROOT/'internal/common').glob('owned_path_acl*.go')):
        if path.name.endswith('_test.go'):
            continue
        copied = common/path.name
        expected = path.read_bytes() if source == ROOT else UID.PREP.relocated_shared_source(path.read_bytes())
        if path.is_symlink() or copied.is_symlink() or not copied.is_file() or copied.read_bytes() != expected:
            raise ValueError('Darwin guardian lost its exact shared kernel ACL source')
        records['common/'+path.name] = hashlib.sha256(expected).hexdigest()
    dispatcher = ROOT/'modes/darwin_kill_switch.py'
    if dispatcher.is_symlink() or not dispatcher.is_file():
        raise ValueError('The native PF parser proof requires the shipping dispatcher')
    records['dispatcher/darwin_kill_switch.py'] = hashlib.sha256(dispatcher.read_bytes()).hexdigest()
    for name in ('go.mod', 'go.sum'):
        path = source/name
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise ValueError('Darwin guardian module identity is not a regular file')
            records[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, package, records


def system(arguments, *, data=None, timeout=20):
    result = subprocess.run(arguments, input=data, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False,
                            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
    if result.returncode:
        raise RuntimeError('Native Darwin fixture command failed: '+repr(arguments)+': '+result.stderr[-4096:])
    return result.stdout, result.stderr


def owned_children(binary):
    """Identify the actual unique test executable, never an ambient process name."""
    proc = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    proc.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
    proc.proc_listallpids.restype = ctypes.c_int
    proc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    proc.proc_pidpath.restype = ctypes.c_int
    count = proc.proc_listallpids(None, 0)
    if count <= 0 or count > 1000000:
        raise ValueError('Native test process inventory was not bounded')
    values = (ctypes.c_int * (count + 256))()
    found = proc.proc_listallpids(values, ctypes.sizeof(values))
    if found < 0 or found >= len(values):
        raise ValueError('Native test process inventory changed beyond its bound')
    result = []
    for pid in values[:found]:
        if pid <= 1:
            continue
        path = ctypes.create_string_buffer(4096)
        size = proc.proc_pidpath(pid, path, len(path))
        if size > 0 and os.fsdecode(path.value) == str(binary):
            result.append(pid)
    return result


def stop_owned_children(binary):
    for pid in owned_children(binary):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 8
    while owned_children(binary):
        if time.monotonic() >= deadline:
            raise RuntimeError('Exact native test helpers did not exit')
        time.sleep(.02)


def dispatcher_baselines():
    """Carry exact shipping Python output into the native parse-only test."""
    spec = importlib.util.spec_from_file_location('darwin_guardian_dispatcher', ROOT/'modes/darwin_kill_switch.py')
    dispatcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dispatcher)
    capture = ('1'*32, '2'*64)
    return [dispatcher.render_owned_pf_rules(lan, owner)
            for lan in (False, True) for owner in (capture, None)]


def root_fixture(source_binary: Path, expected_digest: str, case=None):
    if platform.system() != 'Darwin' or os.geteuid() != 0:
        raise ValueError('The explicit Darwin kernel fixture requires a matching privileged host')
    source_binary = source_binary.absolute()
    info = source_binary.lstat()
    raw = source_binary.read_bytes()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022 or hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ValueError('The native fixture executable changed before its root-owned capture')
    prefix = Path('/opt')
    created_prefix = False
    try:
        prefix.mkdir(mode=0o755)
        created_prefix = True
    except FileExistsError:
        pass
    prefix_info = prefix.lstat()
    if not stat.S_ISDIR(prefix_info.st_mode) or prefix_info.st_uid != 0 or prefix_info.st_mode & 0o022:
        raise ValueError('The Darwin fixture requires the existing protected installation prefix')
    root = Path(tempfile.mkdtemp(prefix='routervpn-darwin-guardian-', dir=prefix))
    root.chmod(0o755)
    binary = root/'darwin-guardian.test'
    binary.write_bytes(raw)
    binary.chmod(0o755)
    nonce = secrets.token_hex(16)
    octet = int(nonce[:2], 16)
    addresses = [f'127.78.{octet}.10', f'127.78.{octet}.11',
                 str(ipaddress.ip_address(f'fd73:{nonce[2:6]}:{nonce[6:10]}::1')),
                 str(ipaddress.ip_address(f'fd73:{nonce[2:6]}:{nonce[6:10]}::2'))]
    (root/'fixture.json').write_text(json.dumps({'Nonce': nonce, 'Addresses': addresses,
                                               'Baselines': dispatcher_baselines()})+'\n')
    (root/'fixture.json').chmod(0o644)
    aliases, token, dispatch, started = [], None, False, False
    result, failure = None, None
    try:
        # This runs the real Go mode/ACL ancestry check before any kernel
        # fixture mutation. Do not relax /var/run's system permissions.
        system([str(binary), 'routervpn-darwin-fixture-preflight'])
        # The complete -a path has a 63-byte loader bound. These shortened
        # random fixture namespaces are captured only after proving neither
        # already belongs to another filter owner, even if its rules are empty.
        planned = {f'com.apple/{prefix}{nonce[:12]}' for prefix in ('000.t-', 'zzz.t-')}
        present, _ = system(['/sbin/pfctl', '-a', 'com.apple', '-s', 'Anchors'])
        present = {'com.apple/'+value.removeprefix('com.apple/') for value in present.split()}
        if planned & present:
            raise ValueError('A planned native PF fixture namespace already has an owner')
        for anchor in sorted(planned):
            rules, _ = system(['/sbin/pfctl', '-a', anchor, '-s', 'rules'])
            children, _ = system(['/sbin/pfctl', '-a', anchor, '-s', 'Anchors'])
            if rules.strip() or children.strip():
                raise ValueError('A planned native PF fixture namespace is not independently empty')
        before, _ = system(['/sbin/ifconfig', 'lo0'])
        existing = set()
        for field in before.split():
            try:
                existing.add(str(ipaddress.ip_address(field.split('%', 1)[0])))
            except ValueError:
                pass
        if set(addresses) & existing:
            raise ValueError('A planned loopback alias already belongs to another owner')
        for address in addresses:
            family = 'inet6' if ':' in address else 'inet'
            mask = ['prefixlen', '128'] if family == 'inet6' else ['netmask', '255.255.255.255']
            system(['/sbin/ifconfig', 'lo0', family, address, *mask, 'alias'])
            aliases.append(address)
        global_rules, _ = system(['/sbin/pfctl', '-s', 'rules'])
        if not global_rules.strip():
            all_rules, _ = system(['/sbin/pfctl', '-a', '*', '-s', 'rules'])
            if all_rules.strip():
                raise ValueError('The fixture cannot adopt populated but undispatched PF anchors')
            system(['/sbin/pfctl', '-f', '-'], data='anchor "com.apple/*" all\n')
            dispatch = True
        output, diagnostics = system(['/sbin/pfctl', '-E'])
        match = re.search(r'(?i)token\s*:\s*([0-9]+)', output+'\n'+diagnostics)
        if match is None:
            raise ValueError('PF did not return an owned enable-reference token')
        token = match[1]
        selector = '^TestDesktopDarwinGuardian' + ('Kernel'+case+'$' if case else '')
        started = True
        process = subprocess.Popen([str(binary), '-test.run='+selector, '-test.v',
                                    '-test.count=1', '-test.timeout=12m'],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True,
                                   env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C',
                                        'GORACE': 'atexit_sleep_ms=0'})
        try:
            output, _ = process.communicate(timeout=730)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate(timeout=10)
            raise RuntimeError('Darwin kernel test exceeded its bounded lifetime: '+output[-8192:].decode(errors='replace'))
        result = process.returncode
        print(output.decode(errors='replace'), end='', flush=True)
    except BaseException as error:
        failure = error
    finally:
        cleanup_errors = []
        try:
            stop_owned_children(binary)
            if started:
                system([str(binary), 'routervpn-darwin-fixture-cleanup'], timeout=60)
        except BaseException as error:
            cleanup_errors.append(error)
        for address in reversed(aliases):
            try:
                system(['/sbin/ifconfig', 'lo0', 'inet6' if ':' in address else 'inet', address, '-alias'])
            except BaseException as error:
                cleanup_errors.append(error)
        if dispatch:
            try:
                actual, _ = system(['/sbin/pfctl', '-s', 'rules'])
                if actual.strip() != 'anchor "com.apple/*" all':
                    raise RuntimeError('The fixture will not restore a changed global PF dispatch')
                system(['/sbin/pfctl', '-f', '-'], data='\n')
            except BaseException as error:
                cleanup_errors.append(error)
        if token:
            try:
                system(['/sbin/pfctl', '-X', token])
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            raise RuntimeError('Native fixture cleanup retained its recovery record at '+str(root)+': '+repr(cleanup_errors)) from failure
        shutil.rmtree(root)
        if created_prefix:
            prefix.rmdir()
    if failure is not None:
        raise failure
    return result


def reported_run(command, **kwargs):
    """Keep a failed compiler/native command's real diagnostic in the CI log."""
    try:
        return UID.run(command, **kwargs)
    except subprocess.CalledProcessError as error:
        output = error.output or b''
        if isinstance(output, bytes):
            output = output[-24*1024:].decode('utf-8', errors='replace')
        else:
            output = str(output)[-24*1024:]
        print('Darwin native command failure output (bounded tail):\n'+output, file=sys.stderr, flush=True)
        raise


def execute(source: Path, go='go', *, case=None, overlay=None):
    if platform.system() != 'Darwin':
        raise ValueError('The actual Darwin guardian gate requires a matching macOS host')
    source, package, before = checked_sources(source)
    if not {'desktop_socket_darwin_guardian_test.go', 'desktop_socket_darwin_kernel_cgo.go',
            'desktop_socket_darwin_pf.go', 'desktop_socket_darwin_state.go',
            'desktop_socket_darwin_readback.go'}.issubset(before):
        raise ValueError('The exact native PF guardian source/test closure is incomplete')
    captured = dict(os.environ, GOWORK='off', CGO_ENABLED='1')
    if captured.get('GOOS', 'darwin') != 'darwin':
        raise ValueError('The native Darwin gate cannot execute a cross-compiled package')
    compiler, captured = UID.compiler_toolchain(source, go, captured)
    sudo = UID.privilege_tool()
    with tempfile.TemporaryDirectory(prefix='routervpn-darwin-guardian-build-') as directory:
        binary = Path(directory)/'darwin-guardian.test'
        command = [compiler, 'test', '-c', '-race', '-mod=readonly',
                   '-tags=routervpn_darwin_guardian', '-o', binary, package]
        if overlay is not None:
            command.insert(2, '-overlay='+str(overlay))
        reported_run(command, cwd=source, env=captured, timeout=300)
        if checked_sources(source)[2] != before:
            raise ValueError('Darwin guardian source changed during native compilation')
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        command = [sys.executable, str(Path(__file__).resolve()), '--root-test-binary', str(binary), '--sha256', digest]
        if case is not None:
            command += ['--case', case]
        if sudo:
            command = [sudo, '-n', '--', *command]
        output = reported_run(command, cwd=source, timeout=850, sudo=sudo)
        wanted = (case,) if case else CASES
        if any('--- PASS: TestDesktopDarwinGuardianKernel'+name+' (' not in output for name in wanted) or '--- SKIP:' in output:
            raise ValueError('Darwin guardian gate did not execute every required native boundary')
        if case is None:
            for name in ('ChannelFragmentsAndDescriptorClosure', 'CurrentFreshnessAndStateScope', 'UIDAbsenceWait', 'UIDObserverProtocol'):
                if '--- PASS: TestDesktopDarwinGuardian'+name+' (' not in output:
                    raise ValueError('Darwin guardian omitted its inherited-channel or freshness boundary')
            for network in ('tcp4','udp4','tcp6','udp6'):
                if '--- PASS: TestDesktopDarwinGuardianKernelTCPAndUDP/'+network+' (' not in output:
                    raise ValueError('Darwin guardian omitted a transport/address family')
        if checked_sources(source)[2] != before or hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError('Darwin guardian source/executable changed during actual kernel execution')
        print(output, end='' if output.endswith('\n') else '\n')
        print('Darwin exact native libproc, isolated UID, scoped PF, actual utun ownership and crash cleanup passed.')


def execute_mutations(source: Path, go='go'):
    """Compile scoped, temporary broken versions and require their exact failure."""
    if platform.system() != 'Darwin':
        raise ValueError('Darwin guardian mutations require the actual native kernel')
    source, package, before = checked_sources(source)
    target = source/('internal/mobiletor' if source == ROOT else 'routervpn/mobiletor')
    captured = dict(os.environ, GOWORK='off', CGO_ENABLED='1')
    compiler, captured = UID.compiler_toolchain(source, go, captured)
    sudo = UID.privilege_tool()
    mutations = (
        ('native occupied UID observation', 'IdentityRetirement', 'fresh observer accepted an actual occupied UID',
         'desktop_socket_darwin_readback.go', (
             ('state := "occupied"', 'state := "absent"'),)),
        ('native UID observer child join', 'UIDObserver', 'unowned, unknown, malformed or unjoined UID receipt released an identity',
         'desktop_socket_darwin_readback.go', (
             ('joinErr := command.Wait()', 'joinErr := error(nil)'),)),
        ('kernel creator UID', 'WrongUIDAndPrivatePeer', 'the actual PF rule admitted the same tuple from another UID',
         'desktop_socket_darwin_pf.go', (
             (' port %d user %d%s tag ', ' port %d%s tag '),
             ('g.Remote.Port(), p.UID, flags,', 'g.Remote.Port(), flags,'))),
        ('foreign block composition', 'ForeignBlockAndLaterPass', 'owned permit bypassed a later foreign block',
         'desktop_socket_darwin_pf.go', (
             ('"pass out on %s %s proto %s', '"pass out quick on %s %s proto %s'),)),
        ('quick deny before foreign pass', 'ForeignBlockAndLaterPass', 'later foreign pass bypassed nested quick deny',
         'desktop_socket_darwin_pf.go', (
             ('block drop out quick ', 'block drop out '),)),
        ('per-socket descriptor retirement', 'SocketRetirementReusesCapacity', 'sequential owned socket 128:',
         'desktop_socket_broker.go', (
             ('ok && s.sourceFile != nil {', 'ok && s.sourceFile != nil && false {'),)),
        ('native descriptor finish acknowledgment', 'FinishRequiresDescriptorRetirement', 'finish claimed success with an unretired descriptor',
         'desktop_socket_darwin_helper.go', (
             ('if release && len(g.sockets) != 0 {', 'if false && release && len(g.sockets) != 0 {'),)),
    )
    with tempfile.TemporaryDirectory(prefix='routervpn-darwin-guardian-mutants-') as temporary:
        directory = Path(temporary)
        for index, (label, case, message, name, replacements) in enumerate(mutations):
            original = target/name
            raw = original.read_text()
            for old, new in replacements:
                if old not in raw:
                    raise ValueError('Darwin mutation no longer matches its actual boundary: '+label)
                raw = raw.replace(old, new)
            changed = directory/(str(index)+'-'+name)
            changed.write_text(raw)
            overlay = directory/(str(index)+'-overlay.json')
            overlay.write_text(json.dumps({'Replace': {str(original): str(changed)}}))
            binary = directory/(str(index)+'-guardian.test')
            reported_run([compiler, 'test', '-c', '-race', '-mod=readonly', '-tags=routervpn_darwin_guardian',
                     '-overlay='+str(overlay), '-o', binary, package], cwd=source, env=captured, timeout=300)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            command = [sys.executable, str(Path(__file__).resolve()), '--root-test-binary', str(binary),
                       '--sha256', digest, '--case', case]
            if sudo:
                command = [sudo, '-n', '--', *command]
            try:
                UID.run(command, cwd=source, timeout=850, sudo=sudo)
            except subprocess.CalledProcessError as error:
                output = error.output.decode(errors='replace') if isinstance(error.output, bytes) else str(error.output)
                if ('--- FAIL: TestDesktopDarwinGuardianKernel'+case+' (' not in output or message not in output
                        or 'Native fixture cleanup retained its recovery record' in output):
                    raise ValueError('Darwin mutation failed before its intended assertion or lost cleanup: '+label+'\n'+output) from error
                print('Rejected broken '+label+' through '+case+'.', flush=True)
            else:
                raise ValueError('Darwin mutation bypassed its required kernel assertion: '+label)
    if checked_sources(source)[2] != before:
        raise ValueError('Darwin native sources changed during the temporary production mutation controls')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('source', nargs='?', type=Path)
    parser.add_argument('--go', default='go')
    parser.add_argument('--root-test-binary', type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--case', choices=CASES)
    parser.add_argument('--mutations', action='store_true', help='Run scoped production mutation controls after the native positive suite')
    args = parser.parse_args()
    if args.root_test_binary:
        if not args.sha256 or not re.fullmatch('[0-9a-f]{64}', args.sha256):
            parser.error('root fixture requires the captured executable digest')
        raise SystemExit(root_fixture(args.root_test_binary, args.sha256, args.case))
    if args.source is None:
        parser.error('exact prepared native source is required')
    execute(args.source, args.go, case=args.case)
    if args.mutations:
        execute_mutations(args.source, args.go)
