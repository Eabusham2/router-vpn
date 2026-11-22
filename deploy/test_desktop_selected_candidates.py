#!/usr/bin/env python3
"""Verify the selected desktop child mailbox, its original packet stop and joined timing."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('selected_candidate_latency_gate', ROOT/'deploy/test_desktop_selected_latency.py')
LATENCY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LATENCY)
FIXTURE = LATENCY.load('selected_candidate_component_fixture', 'prepare-desktop-selected-candidate-test.py')
MULTIPLE = LATENCY.load('selected_candidate_private_source', 'test_node_chain_multiple_imported_execution_owner.py')
PREFIX = 'TestRouterVPNDesktopSelectedPacketCandidate'
FIFTY = ('server', 'compare-server', 'compare-local', 'ordinary-entry')
REFUSALS = ('pre-metadata-cancel', 'expired-before-prepare', 'unadmitted-final', 'foreign-start-hash', 'foreign-metadata-inode',
            'foreign-source-inode', 'stale-pulse', 'foreign-revision', 'foreign-selected-capture',
            'cancel-after-metadata', 'failed-stop-retry')


def verify(core):
    identity = {'selected_latency_owner': LATENCY.verify(core)}
    sources = dict(FIXTURE.copies())
    for name in ('node_chain_execution_candidate', 'node_chain_execution_candidate_test'):
        sources['cmd/sing-box/routervpn_'+name+'.go'] = (ROOT/'mobile/desktop'/(name+'.go.tmpl')).read_bytes()
    for relative, raw in sources.items():
        target = core/relative
        if target.is_symlink() or not target.is_file() or target.read_bytes() != raw:
            raise ValueError('selected candidate lost its original projected source: '+relative)
        identity[relative] = hashlib.sha256(raw).hexdigest()
    identity['runner'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def file_identity(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('selected candidate requires a regular original file: '+path.name)
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        original = os.fstat(handle.fileno())
        if not os.path.samestat(before, original):
            raise ValueError('selected candidate original file was replaced before reading')
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
        after = os.fstat(handle.fileno())
        if (not os.path.samestat(original, path.lstat()) or original.st_size != after.st_size
                or original.st_mtime_ns != after.st_mtime_ns):
            raise ValueError('selected candidate original file changed while reading')
    return original.st_dev, original.st_ino, digest.hexdigest()


def fixture_identity(directory):
    files = sorted(directory.iterdir())
    if {path.name for path in files} != {name+'.json' for name in MULTIPLE.LAYOUTS} or any(
            path.is_symlink() or not path.is_file() for path in files):
        raise ValueError('selected candidate lost original private source inventory')
    return {path.name: file_identity(path) for path in files}


TYPED_ROOT = 'TestRouterVPNDesktopSelectedTypedEntryCandidate'
TYPED_ENTRIES = tuple(family+'-'+outcome for family in ('socks', 'connect')
                      for outcome in ('server', 'compare-local', 'compare-server', 'later-position'))


def execute_typed_entries(core, go, tags, race=True):
    source = verify(core)
    env = dict(os.environ)
    env.setdefault('GOMAXPROCS', '2')
    with tempfile.TemporaryDirectory(prefix='selected-typed-packet-entry-') as temp:
        image = Path(temp)/'typed-entry.test'
        checksum = LATENCY.compile_image(core, go, tags, race, image, env)
        compiled = file_identity(image)
        if compiled[2] != checksum:
            raise ValueError('selected typed entry original image changed')
        for name in TYPED_ENTRIES:
            selection = '^'+TYPED_ROOT+'$/^'+name+'$'
            if verify(core) != source or file_identity(image) != compiled:
                raise ValueError('selected typed entry source or image changed before test')
            result = subprocess.run(LATENCY.run_command(go, image, selection), cwd=core, env=env,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=135)
            print(result.stdout, end='', flush=True)
            records = LATENCY.ORIGINAL.CHILD.verdict(result.stdout, result.returncode, 'cmd/sing-box', {TYPED_ROOT: (name,)})
            if verify(core) != source or file_identity(image) != compiled:
                raise ValueError('selected typed entry source or image changed during test')
            print('Selected typed desktop entry PASS', name, len(records), checksum, flush=True)


def execute(core, go, tags, race=True):
    source = verify(core)
    with tempfile.TemporaryDirectory(prefix='selected-desktop-packet-candidate-') as temp:
        temp = Path(temp)
        directory = temp/'private'
        directory.mkdir(mode=0o700)
        env = dict(os.environ, ROUTERVPN_MULTIPLE_IMPORTED_EXECUTION_NATIVE_FIXTURES=str(directory))
        env.setdefault('GOMAXPROCS', '2')
        generated = MULTIPLE.NATIVE.execute([go, 'test', '-json', '-mod=readonly', '-p=1', '-count=1',
                *(['-race'] if race else []), '-timeout=160s', './internal/mobilemultihop',
                '-run', '^TestNodeChainMultipleImportedExecutionNativeFixtures$'], ROOT, env, 360)
        MULTIPLE.NATIVE.verdict(MULTIPLE.GENERATOR, generated)
        private = fixture_identity(directory)
        image = temp/'selected-candidate.test'
        checksum = LATENCY.compile_image(core, go, tags, race, image, env)
        compiled = file_identity(image)
        if compiled[2] != checksum:
            raise ValueError('selected candidate original compiled image changed')
        # Each selected trial must complete fifty individual connections inside
        # its own original deadline. Retain the existing 120s command-image bound.
        cases = [(PREFIX+'Fifty', (name,), '^'+PREFIX+'Fifty$/^'+name+'$') for name in FIFTY]
        cases.extend(((PREFIX+'Refusals', REFUSALS, '^'+PREFIX+'Refusals$'),
                      (PREFIX+'Generation', (), '^'+PREFIX+'Generation$'),
                      (PREFIX+'Publication', ('before-link', 'after-link', 'result-before-link', 'result-after-link',
                                              'result-retry', 'result-foreign-before-prepare'), '^'+PREFIX+'Publication$')))
        for root, children, selection in cases:
            if verify(core) != source or fixture_identity(directory) != private or file_identity(image) != compiled:
                raise ValueError('selected candidate image, source or private inputs changed before test')
            result = subprocess.run(LATENCY.run_command(go, image, selection), cwd=core, env=env,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=135)
            print(result.stdout, end='', flush=True)
            records = LATENCY.ORIGINAL.CHILD.verdict(result.stdout, result.returncode, 'cmd/sing-box', {root: children})
            if verify(core) != source or fixture_identity(directory) != private or file_identity(image) != compiled:
                raise ValueError('selected candidate image, source or private inputs changed during test')
            print('Selected desktop packet candidate PASS', selection, len(records), checksum, flush=True)

        # This independently compiled alteration must reach the exact assertion.
        # A timeout or compiler/fixture failure cannot stand in for that witness.
        target = core/'cmd/sing-box/routervpn_node_chain_execution_candidate.go'
        anchor = '!os.SameFile(f.info, actual.info) || '
        original = target.read_text()
        if original.count(anchor) != 1:
            raise ValueError('selected candidate original immutable file check changed')
        replacement, overlay = temp/'changed.go', temp/'overlay.json'
        replacement.write_text(original.replace(anchor, '', 1))
        overlay.write_text(json.dumps({'Replace': {str(target): str(replacement)}}))
        altered = temp/'changed.test'
        changed_hash = LATENCY.compile_image(core, go, tags, race, altered, env, overlay)
        control_image = file_identity(altered)
        if (control_image[2] != changed_hash or verify(core) != source or fixture_identity(directory) != private
                or file_identity(altered) != control_image):
            raise ValueError('selected candidate changed source, input or altered image before causal test')
        selected = '^'+PREFIX+'Refusals$/^foreign-metadata-inode$'
        result = subprocess.run(LATENCY.run_command(go, altered, selected), cwd=core, env=env,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=135)
        print(result.stdout, end='', flush=True)
        if (not LATENCY.ORIGINAL.rejected(result.stdout, result.returncode, PREFIX+'Refusals',
                'foreign-metadata-inode', 'selected candidate started with a replaced original inode')
                or file_identity(altered) != control_image
                or verify(core) != source or fixture_identity(directory) != private):
            raise ValueError('selected candidate changed-inode causal witness missing')
        print('Selected desktop packet candidate original inode causal PASS', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', required=True, type=Path)
    parser.add_argument('--go', default='go')
    parser.add_argument('--tags', default=LATENCY.ORIGINAL.CHILD.TAGS)
    parser.add_argument('--without-race', action='store_true')
    parser.add_argument('--phase', choices=('original', 'typed-entry'), default='original')
    args = parser.parse_args()
    run = execute_typed_entries if args.phase == 'typed-entry' else execute
    run(args.core.resolve(), args.go, args.tags, not args.without_race)
