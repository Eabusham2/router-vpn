#!/usr/bin/env python3
"""Join the exact native Darwin child evidence across bounded CI jobs."""
import argparse
from contextlib import contextmanager
from functools import cache
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('darwin_child_gate', ROOT/'deploy/test_darwin_node_child_tun.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)

ARCHES = ('amd64', 'arm64')
IMAGES = {
    'generated-child-test': ('child.test', './cmd/sing-box'),
    'independent-ordered-peer': ('peer.test', './protocol/routervpnamnezia'),
    'paired-node-box': ('paired-node-box.test', '.'),
}
SUITES = {
    'child-runner': 'test_darwin_node_child_tun_runner',
    'paired-runner': 'test_darwin_paired_node_child_runner',
    'ordinary-runner': 'test_darwin_ordered_mtu_reader_runner',
    'typed-runner': 'test_darwin_typed_mtu_reader_runner',
    'platform-runner': 'test_darwin_paired_node_platform',
    'phase-runner': 'test_darwin_child_phases',
}
XRAY_MODULE = 'github.com/xtls/xray-core'
XRAY_PIN = G.BUILD.POLICY.XRAY.XRAY_PIN
XRAY_REQUIRED = {'go.mod', 'go.sum', 'core/routervpn_packet.go', 'transport/internet/browser_dialer/dialer.html',
                 'common/net/find_process_darwin.s', 'transport/internet/finalmask/mkcp/original/xor_amd64.s'}
READY = 'TestDesktopNodeReadyRecordBindsDarwinOriginalSelection'
READY_FIELDS = ('session', 'source', 'config', 'selection', 'dns', 'tun', 'index', 'mtu', 'time', 'query')
READY_VERDICTS = (READY, *(f'{READY}/mtu-{mtu}/{field}' for mtu in (0, 1392) for field in READY_FIELDS))
CONTROLS = (*SUITES, 'ready-binding', 'paired-source', 'ordinary-box', 'typed-box')
PHASES = (*CONTROLS, 'images', 'preflight', 'components', 'native')
JOBS = ('controls', 'images', 'preflight', 'components', 'child')
COMPONENTS = {
    'paired_node_boundaries': G.PAIRED,
    'ordinary_mtu_boundaries': G.ORDERED_MTU,
    'typed_mtu_boundaries': G.TYPED_MTU,
}


def write_record(path, value):
    with path.open('x', encoding='utf-8') as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write('\n')


def read_file(path, maximum):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= maximum:
        raise ValueError('Missing, linked or oversized Darwin evidence: ' + path.name)
    return path.read_bytes()


def read_record(path):
    return json.loads(read_file(path, 8 << 20))


def hex_digest(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def check_sources(result):
    sources = result.get('source_files')
    if (not isinstance(sources, dict) or not sources or not all(hex_digest(v) for v in sources.values())
            or result.get('source_sha256') != G.PAIRED.source_digest(sources)):
        raise ValueError('Darwin prepared-source receipt changed')


def image_record(ids, work):
    return {role: dict(bytes=ids[work/name][2], sha256=ids[work/name][-1])
            for role, (name, _) in IMAGES.items()}


def check_image_record(record):
    if not isinstance(record, dict) or set(record) != set(IMAGES):
        raise ValueError('Darwin image inventory is incomplete')
    for row in record.values():
        if (not isinstance(row, dict) or set(row) != {'bytes', 'sha256'}
                or type(row['bytes']) is not int or not 0 < row['bytes'] <= 512 << 20 or not hex_digest(row['sha256'])):
            raise ValueError('Darwin image receipt lacks exact byte identity')


def scope(phase, arch, repo, build, run, attempt):
    if phase not in PHASES or arch not in ARCHES or not repo or not hex_digest(build):
        raise ValueError('Unknown Darwin phase, architecture or source')
    if not all(isinstance(v, str) and re.fullmatch('[1-9][0-9]*', v) for v in (run, attempt)):
        raise ValueError('Darwin phase requires its exact run and attempt')
    return dict(schema=1, phase=phase, target='darwin/'+arch, repository=repo, build_source_sha256=build,
                run_id=run, run_attempt=attempt)


def payload(record, expected):
    if (not isinstance(record, dict) or type(record.get('schema')) is not int or set(record) != set(expected) | {'result'}
            or any(record[key] != value for key, value in expected.items()) or not isinstance(record['result'], dict)):
        raise ValueError('Missing or foreign Darwin phase receipt: ' + expected['phase'])
    return record['result']


def suite_for(phase):
    name = SUITES[phase]
    module = G.load(name, name+'.py')
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    def flatten(tests):
        for item in tests:
            if isinstance(item, unittest.TestSuite):
                yield from flatten(item)
            else:
                yield item.id()
    ids = list(flatten(suite))
    parents = {
        'ordinary-runner': 'OrderedMTUBoundaries.test_actual_ordinary_parent_requires_ack_retirement_and_readback',
        'typed-runner': 'TypedMTUBoundaries.test_actual_typed_parent_requires_ack_retirement_and_readback',
    }
    if phase in parents and name+'.'+parents[phase] not in ids:
        raise ValueError('Darwin source inventory lost the original parent and its causal controls')
    if not ids or len(set(ids)) != len(ids):
        raise ValueError('Darwin runner lost its complete original unittest inventory')
    return module, suite, ids


@cache
def control_cases(phase):
    if phase in SUITES:
        return tuple(suite_for(phase)[2])
    return {'ready-binding': READY_VERDICTS, 'paired-source': ('platform', 'original-paired-reader'),
            'ordinary-box': ('ordinary-original-box-and-mutations',), 'typed-box': ('typed-original-box-and-mutations',)}[phase]


def execute_control(phase, go, environment):
    compiler, captured = G.preparation_compiler(go, ROOT, environment)
    if phase in SUITES:
        module, suite, ids = suite_for(phase)
        if phase == 'platform-runner':
            module.GO = str(compiler)
        # All original methods run, including each ordinary/typed parent and its three negative variants.
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        if (not result.wasSuccessful() or result.skipped or result.expectedFailures or result.unexpectedSuccesses
                or result.testsRun != len(ids)):
            raise ValueError('Darwin source runner omitted or failed a required original method')
        return dict(cases=ids)
    if phase == 'ready-binding':
        result = subprocess.run([compiler, 'test', '-race', '-p=1', './internal/mobilemultihop',
                                 '-run', '^'+READY+'$', '-count=1', '-v'], cwd=ROOT, env=captured,
                                capture_output=True, text=True, check=True)
        G.NODE.require_native_verdicts(result.stdout, READY_VERDICTS, 'Darwin original ready record')
    else:
        compiler, captured = G.selected_compiler(go, ROOT, environment)
        if phase == 'paired-source':
            G.PAIRED.PLATFORM.verify(go=str(compiler), environment=captured)
            G.PAIRED.READER.execute(go=str(compiler), environment=captured)
        else:
            module = {'ordinary-box': G.ORDERED_MTU, 'typed-box': G.TYPED_MTU}[phase]
            module.execute_box_source(go=str(compiler), environment=captured)
    return dict(cases=list(control_cases(phase)))


def compile_images(source, before, compiler, captured, work):
    ids = {}
    for name, package in IMAGES.values():
        path = work/name
        G.UID.run(G.native_fixture_compile(compiler, path, package), cwd=source, env=captured, timeout=600)
        G.UID.RACE.verify_image(compiler, path, source, captured)
        path.chmod(0o755)
        ids[path] = G.image_identity(path)
    if G.checked_sources(source)[1] != before or any(G.image_identity(p) != value for p, value in ids.items()):
        raise ValueError('Darwin source or race image changed during original compilation')
    return ids


def restore_images(source, before, compiler, captured, work, supplied, manifest):
    check_sources(manifest)
    check_image_record(manifest.get('artifacts'))
    if (manifest['source_files'] != before or supplied.is_symlink() or not supplied.is_dir()
            or set(p.name for p in supplied.iterdir()) != {name for name, _ in IMAGES.values()}):
        raise ValueError('Darwin transfer lost exact prepared source or original image inventory')
    ids = {}
    for role, (name, _) in IMAGES.items():
        incoming, local = supplied/name, work/name
        expected = manifest['artifacts'][role]
        info = incoming.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != expected['bytes']:
            raise ValueError('Darwin transferred image lost original bounded file')
        with incoming.open('rb') as received, local.open('xb') as owned:
            shutil.copyfileobj(received, owned, length=1 << 20)
        local.chmod(0o755)
        identity = G.image_identity(local)
        if dict(bytes=identity[2], sha256=identity[-1]) != expected:
            raise ValueError('Darwin transferred bytes differ from the original compiler receipt')
        G.UID.RACE.verify_image(compiler, local, source, captured)
        ids[local] = identity
    if G.checked_sources(source)[1] != before or any(G.image_identity(p) != v for p, v in ids.items()):
        raise ValueError('Darwin source or image changed during local adoption')
    return ids


def check_component_receipts(result, source_hash, artifacts):
    if set(result) != set(COMPONENTS):
        raise ValueError('Darwin component family is missing or foreign')
    for name, module in COMPONENTS.items():
        module.validate_receipt(result[name], source_hash, artifacts['generated-child-test']['sha256'],
                                artifacts['paired-node-box']['sha256'])


def native_workspace_parent():
    parent = Path('/private/tmp')
    info = parent.lstat()
    if (parent.resolve(strict=True) != parent or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or not info.st_mode & stat.S_ISVTX):
        raise ValueError('Darwin source workspace requires its native root-owned sticky directory')
    return parent


@contextmanager
def exclusive_source_workspace(path):
    # go.mod retains the absolute path of the pinned Xray checkout. Use the
    # same actual bytes on each disposable host, including retries of this run.
    # Atomic mkdir refuses an existing directory or symlink without removing it.
    path.mkdir(mode=0o700)
    original = path.lstat()
    try:
        yield path
    finally:
        current = path.lstat()
        if (not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid()
                or (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino)):
            raise ValueError('Darwin source workspace lost its original owner before retirement')
        shutil.rmtree(path)


def selected_xray(source, compiler, captured):
    sibling = source.parent/'xray'
    module = source/'go.mod'
    if (sibling.resolve(strict=True) != sibling or not sibling.is_dir() or module.is_symlink()):
        raise ValueError('Darwin Xray must be the exact owned local sibling')
    raw = module.read_bytes()
    selected = json.loads(G.UID.run([compiler, 'list', '-m', '-mod=readonly', '-json', XRAY_MODULE],
                                    cwd=source, env=captured, timeout=30))
    replacement = selected.get('Replace', {})
    # Bind both the compiler-selected module and the original unconditional replacement.
    # Keep the actual absolute token in go.mod and all existing core source hashes.
    lines = re.findall(rb'^replace github\.com/xtls/xray-core => ([^\r\n]+)$', raw, re.M)
    if (selected.get('Path') != XRAY_MODULE or selected.get('Dir') != str(sibling)
            or selected.get('GoMod') != str(sibling/'go.mod') or replacement.get('GoMod') != str(sibling/'go.mod')
            or replacement.get('Path') != str(sibling) or replacement.get('Dir') != str(sibling)
            or replacement.get('Version') or lines != [os.fsencode(sibling)] or module.read_bytes() != raw):
        raise ValueError('Darwin compiler did not select the exact original Xray replacement')
    return sibling


def xray_tree(sibling, *, verify_preparation):
    git_dir = sibling/'.git'
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise ValueError('Darwin Xray lost its original pinned checkout directory')
    records = G.NODE.xray_reference_sources(sibling)
    if verify_preparation:
        original = G.load('darwin_original_xray_projection','test_mobile_imported_socks_xray.py')
        if original.checked_xray(sibling) != records:
            raise ValueError('Darwin native Xray sources differ from the original prepared checkout')
    records, identities = G.NODE.complete_xray_source_tree(sibling, XRAY_PIN, records)
    if not XRAY_REQUIRED.issubset(records):
        raise ValueError('Darwin Xray source inventory omitted a required compiled input')
    return dict(pin=XRAY_PIN, files=records, sha256=G.PAIRED.source_digest(records)), identities


def check_xray_manifest(value):
    if (not isinstance(value,dict) or set(value) != {'pin','files','sha256'} or value['pin'] != XRAY_PIN
            or not isinstance(value['files'],dict) or not XRAY_REQUIRED.issubset(value['files'])
            or not all(hex_digest(row) for row in value['files'].values())
            or value['sha256'] != G.PAIRED.source_digest(value['files'])):
        raise ValueError('Darwin compiler receipt lacks the complete original Xray source')


@contextmanager
def prepared_phase_source(go, environment, repo, run):
    name = 'routervpn-darwin-child-'+repo['commit']+'-'+run
    owner = exclusive_source_workspace(native_workspace_parent()/name)
    with G.prepared_source(go, environment, workspace_owner=owner) as (source, prep, captured, workspace):
        compiler, race_env = G.selected_compiler(str(prep), source, captured)
        sibling = selected_xray(source, compiler, race_env)
        dependency, identities = xray_tree(sibling,verify_preparation=True)
        yield source, prep, captured, workspace, dependency
        if (selected_xray(source, compiler, race_env) != sibling or
                xray_tree(sibling,verify_preparation=False) != (dependency,identities)):
            raise ValueError('Darwin source phase lost its original local Xray dependency')


def latest_artifacts(root, names, max_attempt):
    if not isinstance(max_attempt, str) or not re.fullmatch('[1-9][0-9]*', max_attempt):
        raise ValueError('Darwin artifact retrieval requires a current run attempt')
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Darwin artifact download has no original directory')
    latest = {}
    for item in root.iterdir():
        stem, _, number = item.name.rpartition('-')
        if (stem not in names or not re.fullmatch('[1-9][0-9]*',number)
                or int(number)>int(max_attempt) or item.is_symlink() or not item.is_dir()):
            raise ValueError('Unexpected Darwin phase, processor, source, run or future attempt')
        if stem not in latest or int(number)>int(latest[stem][0]):
            latest[stem] = (number,item)
    if set(latest) != set(names):
        raise ValueError('Darwin phase artifact inventory is incomplete')
    return latest


def received_images(supplied, manifests, arch, repo, build, run, attempt):
    image_name = f'darwin-child-images-{arch}-{repo["commit"]}-{run}'
    receipt_name = artifact_name('images', arch, repo['commit'], run, '').rstrip('-')
    image_attempt, image_folder = latest_artifacts(supplied, {image_name}, attempt)[image_name]
    receipt_attempt, receipt_folder = latest_artifacts(manifests, {receipt_name}, attempt)[receipt_name]
    if image_attempt != receipt_attempt:
        raise ValueError('Darwin image bytes and compiler receipt came from different attempts')
    expected = scope('images',arch,repo,build,run,receipt_attempt)
    return image_folder, payload(read_record(receipt_folder/'receipt.json'), expected)


def run_phase(phase, arch, repo, build, run, attempt, output, go, supplied, manifest_path):
    environment = dict(os.environ)
    actual, uid = G.required_host(environment)
    if actual != arch:
        raise ValueError('Darwin job scheduled on wrong native processor')
    expected = scope(phase, arch, repo, build, run, attempt)
    output.mkdir(mode=0o700)
    if phase in CONTROLS:
        result = execute_control(phase, go, environment)
    elif phase == 'preflight':
        # Preserve the separate fresh signed build, in addition to the PF host's own prerequisite.
        with prepared_phase_source(go, environment, repo, run) as (source, prep, captured, workspace, dependency):
            result = G.execute(source, str(prep), environment=captured, preflight_only=True)
        if workspace.exists():
            raise ValueError('Darwin standalone handshake retained its source workspace')
        result['repository'] = repo
        result['xray_source_sha256'] = dependency['sha256']
    else:
        with prepared_phase_source(go, environment, repo, run) as (source, prep, captured, workspace, dependency):
            source, before = G.checked_sources(source)
            compiler, captured = G.selected_compiler(str(prep), source, captured)
            with tempfile.TemporaryDirectory(prefix='routervpn-darwin-phase-') as temporary:
                work = Path(temporary).resolve()
                work.chmod(0o755)
                child, peer = work/'child.test', work/'peer.test'
                if phase == 'images':
                    ids = compile_images(source, before, compiler, captured, work)
                    result = dict(artifacts=image_record(ids, work), source_files=before, xray_source=dependency,
                                  source_sha256=G.PAIRED.source_digest(before), toolchain=G.UID.RACE.TOOLCHAIN)
                    supplied.mkdir(mode=0o700)
                    for path in ids:
                        shutil.copyfile(path, supplied/path.name)
                        if G.digest(supplied/path.name) != ids[path][-1]:
                            raise ValueError('Darwin compiler changed image during transfer')
                else:
                    supplied, original = received_images(supplied, manifest_path, arch, repo, build, run, attempt)
                    if original.get('xray_source') != dependency:
                        raise ValueError('Darwin image producer and consumer used different Xray source')
                    if original.get('toolchain') != G.UID.RACE.TOOLCHAIN:
                        raise ValueError('Darwin images require original race compiler')
                    ids = restore_images(source, before, compiler, captured, work, supplied, original)
                    if phase == 'components':
                        result = {name: module.execute_images(G, source, before, captured, child, ids, work)
                                  for name, module in COMPONENTS.items()}
                        check_component_receipts(result, original['source_sha256'], original['artifacts'])
                        result = dict(boundaries=result, xray_source_sha256=dependency['sha256'])
                    elif phase == 'native':
                        args = (source, before, captured, G.UID.privilege_tool(), arch, uid, child, peer, ids)
                        handshake = G.execute_preflight_images(*args, transcript=output/'handshake.log')
                        result = G.execute_native_images(*args, transcript=output/'native.log')
                        handshake['xray_source_sha256'] = dependency['sha256']
                        result['xray_source_sha256'] = dependency['sha256']
                        result['local_preflight'] = handshake
                        result['artifacts'] = image_record(ids, work)
                    else:
                        raise ValueError('Unknown Darwin image phase')
                if G.checked_sources(source)[1] != before or any(G.image_identity(p) != val for p, val in ids.items()):
                    raise ValueError('Darwin original source or local image changed after phase')
            if work.exists():
                raise ValueError('Darwin phase retained original image workspace')
        if workspace.exists():
            raise ValueError('Darwin phase retained source workspace')
    if G.repository_identity(repo['commit']) != repo:
        raise ValueError('Darwin checkout changed during phase')
    write_record(output/'receipt.json', dict(expected, result=result))


def check_handshake(result, target, manifest, *, standalone):
    original = manifest['artifacts']
    images = result.get('artifacts', {})
    if (result.get('scope') != 'native-handshake-only' or result.get('gate') != 'generated-darwin-ordered-child-handshake'
            or result.get('native_accepted') is not False or result.get('target') != target
            or result.get('xray_source_sha256') != manifest['xray_source']['sha256']
            or result.get('schema') != 1 or result.get('toolchain') != G.UID.RACE.TOOLCHAIN
            or result.get('receipts') != list(G.PREFLIGHT_RECEIPTS) or not hex_digest(result.get('output_sha256'))
            or result.get('source_files') != manifest['source_files'] or set(images) != set(IMAGES)-{'paired-node-box'}):
        raise ValueError('Darwin signed original handshake receipt is incomplete')
    check_sources(result)
    check_image_record(dict(images, **{'paired-node-box': original['paired-node-box']}))
    if not standalone and any(images[role] != original[role] for role in images):
        raise ValueError('PF host handshake did not use the same original images')


def artifact_name(phase, arch, commit, run, attempt):
    return f'darwin-child-proof-{phase}-{arch}-{commit}-{run}-{attempt}'


def combine(arch, selected, repo, build, run):
    def location(phase):
        return selected[artifact_name(phase, arch, repo['commit'], run, '').rstrip('-')]
    def get(phase):
        attempt, folder = location(phase)
        return payload(read_record(folder/'receipt.json'), scope(phase, arch, repo, build, run, attempt))
    for phase in CONTROLS:
        if get(phase) != dict(cases=list(control_cases(phase))):
            raise ValueError('Darwin original control inventory mismatched: '+phase)
    images = get('images')
    check_sources(images)
    check_image_record(images.get('artifacts'))
    check_xray_manifest(images.get('xray_source'))
    artifacts = images['artifacts']
    if images.get('toolchain') != G.UID.RACE.TOOLCHAIN:
        raise ValueError('Darwin image build receipt has foreign compiler')
    preflight = get('preflight')
    if preflight.get('repository') != repo:
        raise ValueError('Darwin standalone handshake came from another checkout')
    target = 'darwin/'+arch
    check_handshake(preflight, target, images, standalone=True)
    component_phase = get('components')
    if set(component_phase) != {'boundaries','xray_source_sha256'} or component_phase['xray_source_sha256'] != images['xray_source']['sha256']:
        raise ValueError('Darwin component evidence came from different Xray source')
    components = component_phase['boundaries']
    check_component_receipts(components, images['source_sha256'], artifacts)
    native = get('native')
    check_sources(native)
    if (native.get('schema') != 1 or native.get('gate') != 'generated-darwin-ordered-child'
            or native.get('scope') != 'generated-command-utun' or 'native_accepted' in native or native.get('target') != target
            or native.get('xray_source_sha256') != images['xray_source']['sha256']
            or native.get('toolchain') != G.UID.RACE.TOOLCHAIN or native.get('cases') != list(G.CASES)
            or native.get('pins') != {'sing-box': G.BUILD.PIN, 'xray': G.BUILD.POLICY.XRAY.XRAY_PIN}
            or native.get('source_files') != images['source_files'] or native.get('artifacts') != artifacts):
        raise ValueError('Darwin native gate result lost original complete source, images or cases')
    check_handshake(native['local_preflight'], target, images, standalone=False)
    transcripts = {}
    for file, record, verdict in (('native.log', native, G.check_verdict),
                                  ('handshake.log', native['local_preflight'], G.check_preflight_verdict)):
        raw = read_file(location('native')[1]/file, 8 << 20)
        if hashlib.sha256(raw).hexdigest() != record.get('output_sha256'):
            raise ValueError('Darwin native transcript differs from original completed process')
        verdict(raw.decode('utf-8'))
        transcripts[file] = raw
    return dict(native, **components, repository=repo, run_id=run, xray_source=images['xray_source'],
                phase_attempts={phase: location(phase)[0] for phase in PHASES}), transcripts


def aggregate(root, out, repo, build, run, attempt, needs):
    if set(needs) != set(JOBS) or any(value.get('result') != 'success' for value in needs.values()):
        raise ValueError('Every original Darwin job must be present and successful')
    names = {artifact_name(p, arch, repo['commit'], run, '').rstrip('-') for arch in ARCHES for p in PHASES}
    selected = latest_artifacts(root, names, attempt)
    completed = {arch: combine(arch, selected, repo, build, run) for arch in ARCHES}
    if any(completed['amd64'][0][field] != completed['arm64'][0][field] for field in ('source_files','xray_source')):
        raise ValueError('The Darwin architectures used different prepared source inventories')
    out.mkdir(mode=0o700)
    for arch, (result, transcripts) in completed.items():
        write_record(out/f'darwin-node-child-{arch}.json', result)
        for name, raw in transcripts.items():
            with (out/f'{arch}-{name}').open('xb') as dest:
                dest.write(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=(*PHASES, 'aggregate'))
    parser.add_argument('--arch', choices=ARCHES)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--input', type=Path)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    repo = G.repository_identity(args.commit)
    build = G.BUILD.digest()
    run, attempt = os.environ.get('GITHUB_RUN_ID'), os.environ.get('GITHUB_RUN_ATTEMPT')
    if args.phase == 'aggregate':
        aggregate(args.input, args.output, repo, build, run, attempt, json.loads(os.environ['DARWIN_REQUIRED_JOBS']))
    else:
        run_phase(args.phase, args.arch, repo, build, run, attempt, args.output, args.go, args.input, args.manifest)


if __name__ == '__main__':
    try:
        main()
    except Exception as failure:
        try:
            G.report_native_failure(failure)
        finally:
            raise SystemExit(1) from None
