#!/usr/bin/env python3
"""Execute exact Darwin route-conflict refusal on owned loopback host routes.

Compilation is unprivileged; only a hash-captured image is staged under a fresh
root-owned directory. The native test creates no TUN or PF rules and changes no
resolver configuration or default route. A failed cleanup retains its original
protected record. Matching-host execution is mandatory, never a skip.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import secrets
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_') + '_darwin_route', ROOT / 'deploy' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MTU = load('prepare-desktop-mtu')
NODE = load('test_desktop_node_physical')
UID = load('test_desktop_socket_uid')
PACKAGE = 'github.com/sagernet/sing-tun'
TEMPLATE = 'sing_tun_route_darwin_test.go.tmpl'
GROUPS = ('TestRouterVPNDarwinRouteConflictPreservesExisting', 'TestRouterVPNDarwinRouteOwnedAddAndRemove')
INVENTORY_CASES = {
    'TestRouterVPNDarwinRouteDump2OriginalInventory': ('ipv4', 'ipv6'),
    'TestRouterVPNDarwinRouteDump2CompactMasks': ('ipv4', 'ipv6'),
    'TestRouterVPNDarwinRouteDump2RefusesUnprovedCache': (
        'referenced', 'no-expiry', 'wrong-parent', 'foreign-interface', 'foreign-gateway',
        'missing-parent', 'duplicate-parent', 'ordinary-dump', 'truncated'),
    'TestRouterVPNDarwinRouteDump2ReadBoundary': ('native-error', 'oversized', 'empty'),
}
REQUIRED = frozenset((*GROUPS, *(root + '/' + family for root in GROUPS for family in ('ipv4', 'ipv6')),
                      *INVENTORY_CASES, *(root + '/' + case for root, cases in INVENTORY_CASES.items() for case in cases)))
WITNESS = 'Darwin route conflict took over an existing route'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_verdicts(output, *, mutant=False):
    started, verdicts = set(), {}
    required = frozenset(name for name in REQUIRED if name.startswith(GROUPS[0])) if mutant else REQUIRED
    for line in output.splitlines():
        run = re.fullmatch(r'=== RUN\s+(\S+)', line)
        if run:
            name = run.group(1)
            if name not in required or name in started:
                raise ValueError('Darwin route fixture changed or duplicated its native inventory')
            started.add(name)
        verdict = re.fullmatch(r'\s*--- (PASS|FAIL|SKIP): (\S+) \([0-9.]+s\)', line)
        if verdict:
            action, name = verdict.groups()
            if name not in required or name not in started or name in verdicts or action == 'SKIP':
                raise ValueError('Darwin route fixture reported an unproved native verdict')
            verdicts[name] = action
    if 'WARNING: DATA RACE' in output or started != required or set(verdicts) != required:
        raise ValueError('Darwin route fixture omitted, skipped or raced a required native case')
    wanted = 'FAIL' if mutant else 'PASS'
    if set(verdicts.values()) != {wanted} or output.splitlines().count(wanted) != 1:
        raise ValueError('Darwin route fixture did not complete the exact required verdicts')
    if mutant and output.count(WITNESS + ': expected original EEXIST') != 2:
        raise ValueError('Darwin route negative control missed the actual takeover boundary')


def verify_selected_module(module, source):
    replacement = module.get('Replace')
    target = Path(source).resolve() / 'routervpn-desktop-tun'
    if module.get('Path') != MTU.MODULE or module.get('Version') != MTU.VERSION or not isinstance(replacement, dict):
        raise ValueError('Darwin route gate lost its exact selected native module')
    if replacement.get('Path') != './routervpn-desktop-tun' or replacement.get('Version') or replacement.get('Sum') or replacement.get('Replace') is not None:
        raise ValueError('Darwin route gate selected a foreign native replacement')
    if Path(module.get('Dir', '')).resolve() != target or Path(replacement.get('Dir', '')).resolve() != target:
        raise ValueError('Darwin route gate selected another native source directory')


def checked_sources(source, go='go', env=None):
    source, records = NODE.checked_sources(Path(source))
    captured = dict(os.environ if env is None else env, GOWORK='off')
    module = json.loads(subprocess.check_output([go, 'list', '-mod=readonly', '-m', '-json', MTU.MODULE],
                                               cwd=source, env=captured, text=True, timeout=60))
    verify_selected_module(module, source)
    # Tidy drops the original h1 from the locally replaced graph. Preparation
    # already checked that original module; this gate independently checks the
    # complete original Darwin file against its pinned SHA and reproduces every
    # declared transformation, without turning an offline check into a fetch.
    cache = subprocess.check_output([go, 'env', 'GOMODCACHE'], cwd=source, env=captured, text=True, timeout=30).strip()
    pristine = Path(cache) / (MTU.MODULE + '@' + MTU.VERSION) / 'tun_darwin.go'
    if pristine.is_symlink() or not pristine.is_file():
        raise ValueError('Darwin route gate lost its original native source')
    expected_source = MTU.network_receipt_patch('tun_darwin.go', MTU.darwin_owned_source(pristine.read_bytes()))
    native = source / 'routervpn-desktop-tun'
    target = native / 'tun_darwin.go'
    if target.is_symlink() or not target.is_file() or target.read_bytes() != expected_source:
        raise ValueError('Darwin route gate differs from the exact prepared native operation')
    for path in sorted(native.rglob('*')):
        if path.is_symlink():
            raise ValueError('Darwin route gate contains a linked native module input')
        if path.is_file():
            records[path.relative_to(source).as_posix()] = digest(path)
    for relative in ('deploy/prepare-desktop-mtu.py', 'deploy/test_desktop_darwin_route.py',
                     'deploy/test_desktop_darwin_route_runner.py', 'mobile/desktop/' + TEMPLATE,
                     'mobile/desktop/sing_tun_network_darwin_test.go.tmpl'):
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('Darwin route gate lost an original source authority')
        records['gate/' + relative] = digest(path)
    return source, records


def restore_takeover_overlay(source, directory):
    original = source / 'routervpn-desktop-tun/tun_darwin.go'
    raw = original.read_bytes()
    before = MTU.DARWIN_ROUTE_REFUSAL
    after = MTU.DARWIN_ROUTE_TAKEOVER.replace(b'err = execRoute(', b'err = t.routervpnExecRoute(')
    if raw.count(before) != 1 or raw.count(b'import (\n') != 1 or b'"errors"' in raw:
        raise ValueError('Darwin route negative control lost its exact original seam')
    changed = raw.replace(before, after, 1).replace(b'import (\n', b'import (\n\t"errors"\n', 1)
    path = directory / 'takeover.go'
    path.write_bytes(changed)
    overlay = directory / 'takeover-overlay.json'
    overlay.write_text(json.dumps({'Replace': {str(original): str(path)}}) + '\n')
    return overlay


def captured_image(path, expected):
    if len(expected) != 64 or any(value not in '0123456789abcdef' for value in expected):
        raise ValueError('Darwin route fixture has no exact captured image hash')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        named = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_mode & 0o022 or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino):
            raise ValueError('Darwin route fixture image is not the original regular executable')
        with os.fdopen(os.dup(descriptor), 'rb') as opened:
            raw = opened.read((256 << 20) + 1)
        after = os.fstat(descriptor)
        current = os.lstat(path)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        if len(raw) > 256 << 20 or len(raw) != before.st_size or any(getattr(before, field) != getattr(after, field) or getattr(after, field) != getattr(current, field) for field in fields) or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Darwin route fixture image changed during original capture')
        return raw
    finally:
        os.close(descriptor)


def root_fixture(image, expected, mutant=False):
    if platform.system() != 'Darwin' or os.geteuid() != 0:
        raise ValueError('Darwin route fixture requires the matching privileged host')
    raw = captured_image(Path(image), expected)
    prefix = Path('/opt')
    info = prefix.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Darwin route fixture requires the existing protected prefix')
    root = prefix / ('routervpn-darwin-route-' + secrets.token_hex(16))
    root.mkdir(mode=0o700)
    binary = root / 'route.test'
    binary.write_bytes(raw)
    binary.chmod(0o500)
    return run_fixture_image(root, binary, expected, mutant)


def run_fixture_image(root, binary, expected, mutant):
    original = binary.lstat()
    arguments = [binary, '-test.v', '-test.count=1', '-test.timeout=45s',
                 '-test.run=^' + GROUPS[0] + '$' if mutant else '-test.run=^TestRouterVPNDarwinRoute']
    output, primary = '', None
    try:
        output = UID.run(arguments, cwd=root, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}, timeout=60)
    except subprocess.CalledProcessError as failure:
        # UID.run raises this only after communicate has joined the child.
        output = failure.output.decode('utf-8', errors='replace')
        primary = failure
    except BaseException:
        # An unknown completion (including an unjoined process-group timeout)
        # cannot authorize deleting routes or recovery records. Keep the exact
        # original failure; do not infer a join from diagnostic message text.
        print('Darwin route fixture completion is unproved; retained protected recovery record at ' + str(root), file=sys.stderr)
        raise
    print(output, end='' if output.endswith('\n') else '\n', flush=True)
    try:
        current = binary.lstat()
        if (current.st_dev, current.st_ino, current.st_mode) != (original.st_dev, original.st_ino, original.st_mode):
            raise ValueError('Darwin route fixture replaced its original executable')
        captured_image(binary, expected)
        UID.run([binary, 'routervpn-darwin-route-cleanup'], cwd=root,
                env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}, timeout=15)
        if digest(binary) != expected or any(path.name != 'route.test' for path in root.iterdir()):
            raise ValueError('Darwin route fixture lost its exact final image or cleanup records')
    except BaseException as cleanup:
        raise RuntimeError('Darwin route cleanup retained its protected recovery record at ' + str(root)) from cleanup
    binary.unlink()
    root.rmdir()
    if primary is not None:
        return primary.returncode
    return 0


def execute(source, go='go', mutations=False):
    if platform.system() != 'Darwin':
        raise ValueError('Darwin route operations must execute on their matching native host')
    captured = dict(os.environ, GOWORK='off', CGO_ENABLED='1')
    source, before = checked_sources(source, go, captured)
    compiler, captured = UID.compiler_toolchain(source, go, captured)
    target = subprocess.check_output([compiler, 'env', 'GOOS', 'GOARCH'], cwd=source, env=captured, text=True).split()
    host_arch = {'x86_64': 'amd64', 'arm64': 'arm64'}.get(platform.machine())
    if target != ['darwin', host_arch] or host_arch is None:
        raise ValueError('Darwin route operations cannot execute a cross-compiled image')
    sudo = UID.privilege_tool()
    with tempfile.TemporaryDirectory(prefix='routervpn-darwin-route-build-') as temporary:
        directory = Path(temporary).resolve()
        for mutant in ((False, True) if mutations else (False,)):
            binary = directory / ('takeover.test' if mutant else 'baseline.test')
            command = [compiler, 'test', '-c', '-race', '-mod=readonly', '-tags=' + ','.join(NODE.TAGS),
                       '-ldflags=-checklinkname=0', '-o', binary, PACKAGE]
            if mutant:
                command.insert(2, '-overlay=' + str(restore_takeover_overlay(source, directory)))
            print(UID.run(command, cwd=source, env=captured, timeout=300), end='', flush=True)
            if checked_sources(source, compiler, captured)[1] != before:
                raise ValueError('Darwin route source changed during native compilation')
            expected = digest(binary)
            command = [sys.executable, str(Path(__file__).resolve()), '--root-image', str(binary), '--sha256', expected]
            if mutant:
                command.append('--mutant')
            if sudo:
                command = [sudo, '-n', '--', *command]
            code, output = 0, ''
            try:
                output = UID.run(command, cwd=source, timeout=90, sudo=sudo)
            except subprocess.CalledProcessError as failure:
                code, output = failure.returncode, failure.output.decode('utf-8', errors='replace')
            print(output, end='' if output.endswith('\n') else '\n', flush=True)
            if code != (1 if mutant else 0):
                raise RuntimeError('Darwin route fixture returned an unexpected native exit status')
            check_verdicts(output, mutant=mutant)
            if digest(binary) != expected or checked_sources(source, compiler, captured)[1] != before:
                raise ValueError('Darwin route image/source changed during actual execution')
    print('Darwin route conflict refusal and original owned add/remove passed; exact source unchanged.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, nargs='?')
    parser.add_argument('--go', default='go')
    parser.add_argument('--mutations', action='store_true')
    parser.add_argument('--root-image', type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--mutant', action='store_true')
    args = parser.parse_args()
    if args.root_image is not None:
        if args.source is not None or args.mutations or not args.sha256:
            parser.error('root route fixture requires only its captured image/hash and optional mutant selector')
        raise SystemExit(root_fixture(args.root_image, args.sha256, args.mutant))
    if args.source is None or args.sha256 is not None or args.mutant:
        parser.error('native route gate requires a prepared source')
    execute(args.source, args.go, args.mutations)
