#!/usr/bin/env python3
"""Build Apple's pinned WireGuardKit with the exact verified AWG timer repair.

Keep the upstream checkout clean. An owned, content-addressed alternate modfile
selects the checksum-verified private dependency beside that checkout. The real
WireGuardKit make target consumes that modfile, including on an incremental
build whose original go.mod has not changed.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PIN = '9d5ee60edefa95b933a738dd7cda671dd18021fc'
GO_VERSION = 'go1.26.3'
MODULE_ROOT = Path('Sources/WireGuardKitGo')
WORK = 'wireguard-apple-timers'
PACKAGE = 'github.com/amnezia-vpn/amneziawg-go/v3/device'
REQUIRED = frozenset({
    'TestRouterVPNAmneziaTimerExpirationAndDeleteShareLock',
    'TestRouterVPNAmneziaTimerDelSyncJoinsEnteredExpiration',
    'TestRouterVPNAmneziaTimerCallbackCanRearmWithoutLostDuration',
})
_spec = importlib.util.spec_from_file_location('apple_awg_timer_patch', ROOT / 'deploy/prepare-amnezia-timers.py')
TIMERS = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(TIMERS)


def regular(path, maximum):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Apple timer input must be an owned regular file')
    info = path.stat()
    if info.st_nlink != 1 or not 0 < info.st_size <= maximum:
        raise ValueError('Apple timer input has another owner or invalid bounds')
    return path.read_bytes()


def directory(path):
    path = Path(path).absolute()
    if path.is_symlink() or not path.is_dir() or path.resolve() != path:
        raise ValueError('Apple timer preparation requires a canonical owned directory')
    return path


def checkout_argument(path):
    # macOS exposes ordinary temporary/workspace parents through aliases such
    # as /tmp -> /private/tmp. Resolve the parent while still rejecting a linked
    # checkout itself; every internal source/cache directory stays canonical.
    path = Path(path).absolute()
    return directory(path.parent.resolve(strict=True) / path.name)


def checkout(kit):
    kit = directory(kit)
    actual = subprocess.check_output(['git', '-C', str(kit), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != PIN:
        raise ValueError('Apple timer preparation requires the unchanged WireGuardKit pin')
    if subprocess.check_output(['git', '-C', str(kit), 'status', '--porcelain', '--untracked-files=all']):
        raise ValueError('Pinned Apple WireGuardKit source must remain clean')
    source = directory(kit / MODULE_ROOT)
    originals = {}
    for name in ('go.mod', 'go.sum'):
        data = regular(source / name, 1024 * 1024)
        expected = subprocess.check_output(['git', '-C', str(kit), 'show', PIN + ':' + (MODULE_ROOT / name).as_posix()])
        if data != expected:
            raise ValueError('Apple timer preparation lost an original pinned module input')
        originals[name] = data
    return kit, source, originals


def layout(kit):
    kit, source, originals = checkout(kit)
    digest = hashlib.sha256(b'RouterVPN Apple AWG timer dependency v1\0' + PIN.encode() + b'\0')
    inputs = [('go.mod', originals['go.mod']), ('go.sum', originals['go.sum'])]
    for path in (Path(__file__).resolve(), ROOT / 'deploy/prepare-amnezia-timers.py', TIMERS.TEMPLATE):
        inputs.append((path.relative_to(ROOT).as_posix(), regular(path, 1024 * 1024)))
    for name, data in inputs:
        digest.update(name.encode() + b'\0' + str(len(data)).encode() + b'\0' + data)
    key = digest.hexdigest()
    work = kit.parent / WORK / key
    # Go resolves relative replacements from the original module's directory,
    # even when -modfile points outside it. Keep builder paths out of metadata.
    replacement = '../../../' + WORK + '/' + key + '/' + TIMERS.COPY
    modfile = originals['go.mod'].rstrip(b'\n') + (
        '\n\nreplace ' + TIMERS.MODULE + ' ' + TIMERS.VERSION + ' => ' + replacement + '\n').encode()
    return source, work, replacement, {'go.mod': modfile, 'go.sum': originals['go.sum']}


def quoted(value):
    # Match cmd/internal/quoted.Join, not shell escaping: Go does not unescape
    # backslashes inside GOFLAGS. Spaces and either kind of quote remain valid.
    if not any(c in value for c in " \t\n\r'\""):
        return value
    if "'" not in value:
        return "'" + value + "'"
    if '"' not in value:
        return '"' + value + '"'
    raise ValueError('The Apple modfile path contains both quote types and cannot be represented in GOFLAGS')


def environment(go='go', env=None):
    captured = dict(os.environ if env is None else env)
    for name in ('GOFLAGS', 'GOROOT', 'GOOS', 'GOARCH'):
        captured.pop(name, None)
    captured.update(GOENV='off', GOTOOLCHAIN='local', GOWORK='off')
    located = shutil.which(str(go), path=captured.get('PATH'))
    if not located:
        raise ValueError('The pinned Apple Go compiler is unavailable')
    compiler = Path(located).resolve()
    captured['PATH'] = str(compiler.parent) + os.pathsep + captured.get('PATH', '')
    version = subprocess.check_output([str(compiler), 'env', 'GOVERSION'], env=captured, text=True).strip()
    if version != GO_VERSION:
        raise ValueError('Apple WireGuardKit requires the exact Go 1.26.3 toolchain')
    return str(compiler), captured


def selected_environment(work, env):
    captured = dict(env)
    captured['GOFLAGS'] = '-mod=readonly ' + quoted('-modfile=' + str(work / 'go.mod'))
    return captured


def verify_workspace(work, expected):
    directory(work.parent)
    directory(work)
    if {path.name for path in work.iterdir()} != {'go.mod', 'go.sum', TIMERS.COPY}:
        raise ValueError('Apple timer workspace contains missing or unrelated inputs')
    for name, data in expected.items():
        if regular(work / name, 1024 * 1024) != data:
            raise ValueError('Apple timer alternate module input drifted: ' + name)
    TIMERS.verify_tree(work / TIMERS.COPY)


def verify(kit, go, env):
    source, work, replacement, expected = layout(kit)
    verify_workspace(work, expected)
    selected = selected_environment(work, env)
    plan = json.loads(subprocess.check_output([go, 'mod', 'edit', '-json'], cwd=source, env=selected, text=True))
    requirements = [row for row in plan.get('Require', []) if row['Path'] == TIMERS.MODULE]
    replacements = [row for row in plan.get('Replace', []) or [] if row['Old']['Path'] == TIMERS.MODULE]
    if requirements != [{'Path': TIMERS.MODULE, 'Version': TIMERS.VERSION}] or replacements != [
            {'Old': {'Path': TIMERS.MODULE, 'Version': TIMERS.VERSION}, 'New': {'Path': replacement}}]:
        raise ValueError('Apple WireGuardKit lost its exact version-qualified AWG timer replacement')
    info = json.loads(subprocess.check_output([go, 'list', '-m', '-json', TIMERS.MODULE], cwd=source, env=selected, text=True))
    replace = info.get('Replace') or {}
    target = work / TIMERS.COPY
    if (info.get('Path') != TIMERS.MODULE or info.get('Version') != TIMERS.VERSION or info.get('Error') or
            replace.get('Path') != replacement or replace.get('Version') or
            not info.get('Dir') or Path(info['Dir']).resolve() != target or
            not replace.get('Dir') or Path(replace['Dir']).resolve() != target):
        raise ValueError('Apple WireGuardKit selected a different AWG timer dependency')
    verify_workspace(work, expected)
    return source, work, selected


def prepare(kit, go, env):
    source, work, _, expected = layout(kit)
    if work.parent.exists() or work.parent.is_symlink():
        directory(work.parent)
    else:
        work.parent.mkdir(mode=0o700)
    if work.exists() or work.is_symlink():
        verify_workspace(work, expected)
    else:
        info = json.loads(subprocess.check_output(
            [go, 'mod', 'download', '-json', TIMERS.MODULE + '@' + TIMERS.VERSION], cwd=source, env=env, text=True))
        if (info.get('Path') != TIMERS.MODULE or info.get('Version') != TIMERS.VERSION or
                info.get('Sum') != TIMERS.SUM or info.get('Error')):
            raise ValueError('Apple AWG timer archive differs from its original pinned checksum')
        with tempfile.TemporaryDirectory(prefix='.prepare-', dir=work.parent) as temporary:
            staged = Path(temporary) / 'ready'
            staged.mkdir()
            target = staged / TIMERS.COPY
            target.mkdir()
            TIMERS.extract_verified(Path(info['Zip']), target)
            for name, data in expected.items():
                with (staged / name).open('xb') as output:
                    output.write(data)
            verify_workspace(staged, expected)
            staged.rename(work)
    verify(kit, go, env)
    print('Prepared exact Apple AWG timer dependency; upstream checkout remains clean:', work.name, flush=True)


def verdicts(output):
    started, passed, package_passed = set(), set(), False
    for line in output.splitlines():
        row = json.loads(line)
        if row.get('Action') in ('skip', 'fail') or 'WARNING: DATA RACE' in row.get('Output', ''):
            raise ValueError('Apple AWG timer control skipped, raced or failed')
        name = row.get('Test')
        if name is not None:
            if row.get('Package') != PACKAGE or name not in REQUIRED:
                raise ValueError('Apple AWG timer execution changed its required case inventory')
            collection = started if row.get('Action') == 'run' else passed if row.get('Action') == 'pass' else None
            if collection is not None:
                if name in collection:
                    raise ValueError('Apple AWG timer control reported a duplicate verdict')
                collection.add(name)
        elif row.get('Package') == PACKAGE and row.get('Action') == 'pass':
            if package_passed:
                raise ValueError('Apple AWG timer package reported duplicate completion')
            package_passed = True
    if started != REQUIRED or passed != REQUIRED or not package_passed:
        raise ValueError('Apple AWG timer package omitted an actual required verdict')


def test(kit, go, env):
    source, _, selected = verify(kit, go, env)
    target = subprocess.check_output([go, 'env', 'GOOS', 'GOARCH'], cwd=source, env=selected, text=True).split()
    host = [('darwin' if platform.system() == 'Darwin' else platform.system().lower()),
            {'x86_64': 'amd64', 'AMD64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64', 'ARM64': 'arm64'}.get(platform.machine(), '')]
    if target != host or target[0] not in ('darwin', 'linux'):
        raise ValueError('Apple AWG timer controls must execute on the selected supported host')
    command = [go, 'test', '-json', '-race', PACKAGE, '-run', '^TestRouterVPNAmneziaTimer', '-count=1', '-timeout=30s']
    completed = subprocess.run(command, cwd=source, env=selected, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, check=False, timeout=180)
    output = completed.stdout.decode('utf-8')
    print(output, end='', flush=True)
    if completed.returncode:
        raise subprocess.CalledProcessError(completed.returncode, command)
    verdicts(output)
    verify(kit, go, env)
    print('All three actual Apple dependency timer controls passed with unchanged pinned source.', flush=True)


def build(kit, go, env):
    source, _, selected = verify(kit, go, env)
    if platform.system() != 'Darwin':
        raise ValueError('The real Apple WireGuardKit archive must be built on Darwin')
    # The upstream make prerequisite is the original go.mod. Its timestamp does
    # not represent our external dependency; -W forces only its archive targets
    # to rebuild while retaining the upstream GOROOT preparation and flags.
    subprocess.run(['make', '-C', str(source), '-W', 'go.mod', 'build'], env=selected, check=True)
    verify(kit, go, env)
    print('Built the real Apple WireGuardKit archive with its verified AWG timer dependency.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kit', type=Path)
    parser.add_argument('--go', default='go')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--verify', action='store_true')
    mode.add_argument('--test', action='store_true')
    mode.add_argument('--build', action='store_true')
    args = parser.parse_args()
    compiler, captured = environment(args.go)
    action = verify if args.verify else test if args.test else build if args.build else prepare
    action(checkout_argument(args.kit), compiler, captured)
