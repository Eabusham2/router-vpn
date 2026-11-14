#!/usr/bin/env python3
"""Actual installed Darwin ordered host acceptance on an explicit disposable Mac.

The signed native controller, original child, PF/utun, encrypted WG/AWG peers
and Python MTU optimizer execute without a modeled native boundary. Each case
gets its own existing 240-second native budget and strict complete verdict.
This gate does not enable the shipping public ordered capability.
"""
from pathlib import Path
from collections import Counter
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FLAG = 'ROUTERVPN_DARWIN_NODE_CHAIN_HOST_ACCEPTANCE'
TEST = 'TestMacOSRetainedNodeChainNativeHost'
AUTHORITY_TEST = 'TestDesktopDarwinInstalledImportedNodeChainFixtureKeepsOriginalSources'
AUTHORITY_CASES = (AUTHORITY_TEST, *(AUTHORITY_TEST+'/'+name for name in ('custom-wg', 'custom-awg-fast', 'custom-awg-strong')))
ORIGINAL_CASES = (
    'node-chain-3-connect', 'node-chain-4-connect', 'node-chain-3-wrong-middle-key', 'node-chain-4-wrong-middle-proof',
    'node-chain-3-final-dns-failure', 'node-chain-4-final-node-failure', 'node-chain-4-middle-source', 'node-chain-3-prefix-lost',
    'node-chain-3-awg-fast-wg-connect', 'node-chain-3-wg-awg-strong-connect', 'node-chain-3-awg-strong-awg-fast-connect',
    'node-chain-4-wg-awg-fast-awg-strong-connect', 'node-chain-4-awg-fast-awg-strong-wg-connect', 'node-chain-4-awg-strong-wg-awg-fast-connect',
    'node-chain-4-wg-awg-fast-awg-strong-wrong-middle-key', 'node-chain-4-wg-awg-fast-awg-strong-wrong-awg-parameters',
    'node-chain-4-wg-awg-fast-awg-strong-middle-source', 'node-chain-4-wg-awg-fast-awg-strong-prefix-lost',
    'node-chain-custom-wg-connect', 'node-chain-custom-awg-fast-connect', 'node-chain-custom-awg-strong-connect',
    'node-chain-custom-wg-wrong-middle-key', 'node-chain-custom-wg-wrong-middle-public', 'node-chain-custom-wg-final-dns-failure',
    'node-chain-custom-wg-middle-source', 'node-chain-custom-wg-prefix-lost',
    'node-chain-3-mtu', 'node-chain-4-wg-awg-fast-awg-strong-mtu',
)
HYSTERIA_CASES = (
    'node-chain-hy2-wg-wg-connect',
    'node-chain-hy2-awg-fast-awg-strong-connect',
    'node-chain-hy2-awg-strong-awg-fast-connect',
    'node-chain-hy2-wg-wg-final-password',
    'node-chain-hy2-wg-wg-final-trust',
    'node-chain-hy2-wg-wg-final-mask',
    'node-chain-hy2-wg-wg-final-dns-failure',
    'node-chain-hy2-wg-wg-middle-source',
    'node-chain-hy2-wg-wg-prefix-lost',
)
CASES = ORIGINAL_CASES + HYSTERIA_CASES
HYSTERIA_AUTHORITY_TEST = 'TestDesktopDarwinInstalledHysteriaNodeChainFixtureKeepsOriginalSources'
HYSTERIA_AUTHORITY_CASES = (HYSTERIA_AUTHORITY_TEST, *(HYSTERIA_AUTHORITY_TEST+'/'+name for name in
    ('wg-wg', 'awg-fast-awg-strong', 'awg-strong-awg-fast')))
HYSTERIA_AUTHORITY_SOURCE = 'cmd/client/desktop_node_chain_hysteria_darwin_native_test.go'
HYSTERIA_CONTROL_WITNESS = 'compiled installed final substituted TLS, password, Salamander or packet prefix'
MTU_CASES = ORIGINAL_CASES[-2:]
MTU_RECEIPT = 'actual sealed Darwin ordered MTU: Auto and Retest transferred final-only UDP, held Cancel joined exact rollback, original process PF and reader succession retained'
MEASUREMENT_CASES = tuple(case for case in CASES if case not in (
    'node-chain-3-wrong-middle-key', 'node-chain-4-wrong-middle-proof',
    'node-chain-3-final-dns-failure', 'node-chain-4-final-node-failure',
    'node-chain-4-wg-awg-fast-awg-strong-wrong-middle-key',
    'node-chain-4-wg-awg-fast-awg-strong-wrong-awg-parameters',
    'node-chain-custom-wg-wrong-middle-key', 'node-chain-custom-wg-wrong-middle-public', 'node-chain-custom-wg-final-dns-failure',
    'node-chain-hy2-wg-wg-final-password', 'node-chain-hy2-wg-wg-final-trust',
    'node-chain-hy2-wg-wg-final-mask', 'node-chain-hy2-wg-wg-final-dns-failure',
))
MEASUREMENT_RECEIPT = 'actual sealed Darwin ordered measurement: every original prefix transferred 8 MiB per direction with six HTTP samples, original native process PF and TUN reader retained'
SOURCE_FILES = (
    'cmd/client/desktop_node_chain_public_admission.go', 'cmd/client/desktop_node_chain_socks_admission.go',
    'cmd/client/multihop_native_routes.go', 'cmd/client/multihop_native_ordered_status.go',
    'cmd/client/telemetry_hops_ordered.go', 'cmd/client/telemetry_hops_ordered_policy.go',
    'cmd/client/profile_public_view.go',
    'deploy/test_macos_node_chain_host.py', 'deploy/test_macos_node_chain_host_runner.py',
    'cmd/client/desktop_node_chain_darwin_native_test.go',
    'cmd/client/desktop_node_chain_darwin_peer_native_test.go',
    'cmd/client/desktop_node_chain_imported_darwin_native_test.go',
    HYSTERIA_AUTHORITY_SOURCE,
    'cmd/client/controller_privilege_darwin_native_test.go',
    'modes/mtu-throughput-tuner.py', 'modes/mtu-throughput-tuner-platform.py',
    'modes/network_context.py', 'modes/private_profile_store.py', 'modes/profile_id.py',
    '.github/workflows/darwin-node-host-tun.yml', '.github/workflows/darwin-node-host-native.yml',
)


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EXTERNAL = load('ordered_native_external_boundaries', 'test_macos_external_host.py')
BUILD, CONTROLLER = EXTERNAL.BUILD, EXTERNAL.CONTROLLER
PEER_TAGS = EXTERNAL.PEER_TAGS + ',routervpn_darwin_node_chain'


def require_public_entrypoints(source):
    # Structural closure only; all actual installed cases still run below.
    audit = load('darwin_public_native_entrypoints', 'native_multihop_audit.py')
    tokens = audit._tokens(source)
    connect = audit._function(tokens, 'func macOSNodeChainNativeConnect(a *app, w http.ResponseWriter, r *http.Request, driver nativeMultihopConnectRuntime, public *atomic.Bool)')
    controller = audit._function(tokens, 'func macOSNodeChainNativeController(owned *ownedDesktopController) (bool, error)')
    case = audit._function(tokens, 'func macOSNodeChainNativeCase(t *testing.T, scenario string)')
    fragments = (
        (connect, 'if public == nil {'),
        (connect, 'public.Store(true) a.nativeMultihopConnectOwned(w, r, driver)'),
        (controller, 'if len(modes) == 2 && (modes[1] == "socks5" || modes[1] == "http-connect" || modes[1] == "https-connect") {'),
        (controller, 'macOSNodeChainNativeConnect(a, w, r, driver, &publicConnect)'),
        (controller, 'mux.HandleFunc("/api/multihop/status", func(w http.ResponseWriter, r *http.Request) { publicStatus.Store(true) a.nativeMultihopStatus(w, r) })'),
        (controller, 'value.PublicConnect, value.PublicStatus = publicConnect.Load(), publicStatus.Load()'),
        (controller, 'public := publicProfileFor(middle)'),
        (controller, 'public.External == nil || !public.External.OrderedMiddle'),
        (case, 'if !live.PublicConnect || !retired.PublicConnect || !negative && !retired.PublicStatus {'),
        (case, 't.Logf("actual sealed Darwin public ordered route verified %s: shipping Connect and original joined retirement", scenario)'),
        (case, 'if !negative { t.Logf("actual sealed Darwin public ordered status verified %s: shipping capture and retired-capture refusal", scenario) }'),
    )
    if any(body is None or len(audit._positions(body, fragment)) != 1 for body, fragment in fragments):
        raise ValueError('Installed native source lost its actual public entrypoint or typed capability boundary')
    if len(audit._positions(connect, 'a.nativeMultihopConnectOwned(w, r, driver)')) != 1 or any(
            audit._positions(body, fragment) for body in (connect, controller)
            for fragment in ('a.nativeMultihopConnectLocalOwned(', 'a.beginConnectionOperationContext(', 'privateCONNECT')):
        raise ValueError('Installed ordered source bypassed its original public dispatcher')
    return True


def case_inventory(source=None):
    require_public_entrypoints((ROOT/'cmd/client/desktop_node_chain_darwin_native_test.go').read_text())
    source = source if source is not None else (ROOT/'cmd/client/desktop_node_chain_darwin_peer_native_test.go').read_text()
    match = re.search(r'var macOSNodeChainHostCases = \[\]string\{([^}]+)\}', source)
    if match is None:
        raise ValueError('Original ordered native case inventory is absent')
    values = tuple(re.findall(r'"([a-z0-9-]+)"', match[1]))
    remainder = re.sub(r'"[a-z0-9-]+"|\s|,', '', match[1])
    if remainder or values != CASES or len(set(values)) != len(CASES):
        raise ValueError('Ordered native source inventory differs from exhaustive gate')
    return values


def receipt(case):
    if case not in CASES:
        raise ValueError('Unknown ordered native case')
    return 'actual sealed Darwin ordered host verified '+case+': original native transaction and intended proof boundary, complete captured identities, stopped acknowledgment, PF and utun retirement, controller join'


def public_route_receipt(case):
    return 'actual sealed Darwin public ordered route verified '+case+': shipping Connect and original joined retirement'


def public_status_receipt(case):
    return 'actual sealed Darwin public ordered status verified '+case+': shipping capture and retired-capture refusal'


def check_verdict(output, case, *, test=TEST, cases=CASES, mtu_cases=MTU_CASES, measurement_cases=MEASUREMENT_CASES, public_cases=CASES):
    if case not in cases or not isinstance(output, str) or re.search(
            r'(?im)^\s*(?:--- (?:FAIL|SKIP):|FAIL(?:\s|$)|SKIP(?:\s|$)|WARNING: DATA RACE|panic:|fatal error:)|\[build failed\]', output):
        raise ValueError('Native ordered host output contains unknown/failure/skip/race evidence')
    expected = {test, test+'/'+case}
    runs, passes, receipts = Counter(), Counter(), Counter()
    package_pass = 0
    for line in output.splitlines():
        run = re.fullmatch(r'=== RUN   (\S+)', line)
        passed = re.fullmatch(r'(?:    )?--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)', line)
        proof = re.fullmatch(r'\s+desktop_node_chain_darwin_native_test.go:\d+: (.*)', line)
        if run:
            name = run[1]
            if name not in expected or package_pass or runs[name] or passes[test] or name != test and runs[test] != 1:
                raise ValueError('Native ordered RUN is extra, duplicate or after completion')
            runs[name] += 1
        if passed:
            name = passed[1]
            if name not in expected or package_pass or runs[name] != 1 or passes[name]:
                raise ValueError('Native ordered PASS has no unique original RUN')
            passes[name] += 1
        if proof:
            if package_pass or runs[test+'/'+case] != 1 or passes[test]:
                raise ValueError('Native ordered ownership receipt is outside its original case')
            receipts[proof[1]] += 1
        if line == 'PASS':
            if set(passes) != expected or any(passes[name] != 1 for name in expected):
                raise ValueError('Native ordered package completed without every selected case')
            package_pass += 1
    if set(runs) != expected or set(passes) != expected or any(runs[name] != 1 or passes[name] != 1 for name in expected):
        raise ValueError('Missing unique native ordered case execution')
    if receipts[('actual sealed Darwin ordered host verified '+case+': original native transaction and intended proof boundary, complete captured identities, stopped acknowledgment, PF and utun retirement, controller join')] != 1:
        raise ValueError('Native ordered case omitted its original joined ownership receipt')
    if receipts[MTU_RECEIPT] != (1 if case in mtu_cases else 0):
        raise ValueError('Native ordered case omitted or borrowed actual MTU transfer receipt')
    if receipts[MEASUREMENT_RECEIPT] != (1 if case in measurement_cases else 0):
        raise ValueError('Native ordered case omitted or borrowed actual prefix measurement receipt')
    public = case in public_cases
    if receipts[public_route_receipt(case)] != int(public):
        raise ValueError('Native ordered case omitted or borrowed its actual public Connect route')
    if receipts[public_status_receipt(case)] != int(public and case in measurement_cases):
        raise ValueError('Native ordered case omitted or borrowed its actual public status route')
    known = {('actual sealed Darwin ordered host verified '+case+': original native transaction and intended proof boundary, complete captured identities, stopped acknowledgment, PF and utun retirement, controller join'), MTU_RECEIPT, MEASUREMENT_RECEIPT, public_route_receipt(case), public_status_receipt(case)}
    if any(value.startswith(('actual sealed Darwin ordered', 'actual sealed Darwin public ordered')) and value not in known for value in receipts):
        raise ValueError('Native ordered case borrowed another case receipt')
    if package_pass != 1 or not output.rstrip().endswith('\nPASS'):
        raise ValueError('Native ordered host did not complete one original package execution')


def source_identity(core):
    identity = EXTERNAL.source_identity(core)
    for name in SOURCE_FILES:
        identity['application'][name] = EXTERNAL.sha(ROOT/name)
    projector = getattr(BUILD.EXTERNAL, 'darwin_node_chain_peer_copies', None)
    if projector is None:
        raise ValueError('Native ordered peer source projection is not installed')
    copies = projector()
    expected = {
        'routervpn_node_chain_wg_darwin_test.go', 'routervpn_node_chain_awg_darwin_test.go',
        'routervpn_node_chain_imported_darwin_test.go', 'routervpn_node_chain_reference_darwin_test.go',
        'routervpn_node_chain_imported_middle_darwin_test.go', 'routervpn_node_chain_hysteria_final_darwin_test.go',
        'routervpn_node_chain_imported_hostname_darwin_test.go',
        'routervpn_node_chain_socks_peer_darwin_test.go', 'routervpn_node_chain_socks_process_darwin_test.go',
        'routervpn_node_chain_connect_peer_darwin_test.go', 'routervpn_node_chain_connect_reference_darwin_test.go',
    }
    if set(copies) != {'protocol/routervpnamnezia/'+name for name in expected}:
        raise ValueError('Native ordered peer lost an original or typed complete projection')
    for relative, expected in copies.items():
        path = Path(core)/relative
        actual = EXTERNAL.sha(path)
        if actual != hashlib.sha256(expected).hexdigest():
            raise ValueError('Native ordered peer projection differs from original source: '+relative)
        identity['peer'][relative] = actual
    return identity


def check_authority_verdict(output, *, hysteria=False, selected=None):
    root = HYSTERIA_AUTHORITY_TEST if hysteria else AUTHORITY_TEST
    cases = HYSTERIA_AUTHORITY_CASES if hysteria else AUTHORITY_CASES
    if selected is not None:
        root, cases = selected
    if not isinstance(output, str) or re.search(
            r'(?im)^\s*(?:--- (?:FAIL|SKIP):|FAIL(?:\s|$)|SKIP(?:\s|$)|WARNING: DATA RACE|panic:|fatal error:)|\[build failed\]', output):
        raise ValueError('Imported source authority contains failure, skip or race evidence')
    expected = set(cases)
    runs, passes = Counter(), Counter()
    complete = 0
    for line in output.splitlines():
        run = re.fullmatch(r'=== RUN   (\S+)', line)
        passed = re.fullmatch(r'(?:    )?--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)', line)
        if run:
            name = run[1]
            if name not in expected or complete or runs[name] or passes[root] or name != root and runs[root] != 1:
                raise ValueError('Imported source authority RUN is missing its original root or duplicated')
            runs[name] += 1
        if passed:
            name = passed[1]
            if name not in expected or complete or runs[name] != 1 or passes[name]:
                raise ValueError('Imported source authority PASS has no unique original RUN')
            passes[name] += 1
        if line == 'PASS':
            if set(passes) != expected:
                raise ValueError('Imported source authority omitted an exact source case')
            complete += 1
    if set(runs) != expected or set(passes) != expected or complete != 1 or not output.rstrip().endswith('\nPASS'):
        raise ValueError('Imported source authority did not complete its exact original inventory')


def execute_authority(controller, digest, environment, *, hysteria=False):
    root = HYSTERIA_AUTHORITY_TEST if hysteria else AUTHORITY_TEST
    if EXTERNAL.sha(controller) != digest:
        raise ValueError('Imported source authority lost its captured controller image')
    result = subprocess.run([str(controller), '-test.v', '-test.count=1', '-test.timeout=30s',
                             '-test.run=^'+root+'$'], cwd=ROOT, env=environment,
                            check=True, timeout=40, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end='' if result.stdout.endswith('\n') else '\n', flush=True)
    check_authority_verdict(result.stdout, hysteria=hysteria)
    if EXTERNAL.sha(controller) != digest:
        raise ValueError('Imported source authority changed its captured controller image')
    return result.stdout



def check_hysteria_control_verdict(output, returncode, *, selected=None):
    """Require the compiled original source-mask omission at all three exact leaves."""
    if returncode == 0 or not isinstance(output, str) or re.search(
            r'(?im)^\s*(?:--- (?:PASS|SKIP):|PASS(?:\s|$)|SKIP(?:\s|$)|WARNING: DATA RACE|panic:|fatal error:)|\[build failed\]', output):
        raise ValueError('Hysteria source control did not reach its original assertion')
    root, cases, witness_file, witness_text = selected or (HYSTERIA_AUTHORITY_TEST, HYSTERIA_AUTHORITY_CASES, "desktop_node_chain_hysteria_darwin_native_test.go", HYSTERIA_CONTROL_WITNESS)
    expected = set(cases)
    runs, failures, witnesses = Counter(), Counter(), Counter()
    active, complete = None, 0
    for line in output.splitlines():
        run = re.fullmatch(r'=== RUN   (\S+)', line)
        failed = re.fullmatch(r'(?:    )?--- FAIL: (\S+) \([0-9]+(?:\.[0-9]+)?s\)', line)
        witness = re.fullmatch(r'\s+'+re.escape(witness_file)+r':\d+: '+re.escape(witness_text), line)
        if run:
            name = run[1]
            if name not in expected or complete or runs[name] or failures[root] or name != root and runs[root] != 1:
                raise ValueError('Hysteria source control replaced its exact original execution')
            runs[name] += 1
            active = name
        if witness:
            if active not in expected - {root} or complete or failures[active]:
                raise ValueError('Hysteria source control borrowed a foreign assertion')
            witnesses[active] += 1
        if failed:
            name = failed[1]
            if name not in expected or complete or runs[name] != 1 or failures[name]:
                raise ValueError('Hysteria source control lacks one exact failed original run')
            failures[name] += 1
        if line == 'FAIL':
            if set(failures) != expected:
                raise ValueError('Hysteria source control ended before every required failure')
            complete += 1
    if set(runs) != expected or set(failures) != expected or complete != 1 or not output.rstrip().endswith('\nFAIL'):
        raise ValueError('Hysteria source control omitted an original verdict')
    if set(witnesses) != expected - {root} or any(value != 1 for value in witnesses.values()):
        raise ValueError('Hysteria source control omitted or duplicated its original mask assertion')


def execute_hysteria_control(compiler, work, environment):
    original = ROOT/HYSTERIA_AUTHORITY_SOURCE
    source = original.read_text()
    before = EXTERNAL.sha(original)
    needle = '"password": mask'
    if source.count(needle) != 1:
        raise ValueError('Hysteria original source-mask control seam changed')
    directory = Path(work)/'hysteria-source-control'
    directory.mkdir(mode=0o700)
    changed, overlay, image = directory/'source.go', directory/'overlay.json', directory/'controller.test'
    changed.write_text(source.replace(needle, '"password": mask + "-uncaptured"', 1))
    overlay.write_text(json.dumps({'Replace': {str(original.resolve()): str(changed.resolve())}}))
    command = [str(compiler), 'test', '-race', '-c', '-mod=readonly', '-tags=routervpn_controller_privileged',
               '-overlay='+str(overlay), '-o', str(image), './cmd/client']
    subprocess.run(command, cwd=ROOT, env=environment, check=True, timeout=300)
    digest = EXTERNAL.sha(image)
    result = subprocess.run([str(image), '-test.v', '-test.count=1', '-test.timeout=30s',
                             '-test.run=^'+HYSTERIA_AUTHORITY_TEST+'$'], cwd=ROOT, env=environment,
                            check=False, timeout=40, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end='' if result.stdout.endswith('\n') else '\n', flush=True)
    check_hysteria_control_verdict(result.stdout, result.returncode)
    if EXTERNAL.sha(image) != digest or EXTERNAL.sha(original) != before:
        raise ValueError('Hysteria source control replaced its captured image or original source')
    return dict(image_sha256=digest, output_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(),
                cases=list(HYSTERIA_AUTHORITY_CASES), witness=HYSTERIA_CONTROL_WITNESS)

def required_host(environment):
    if environment.get(FLAG) != '1' or environment.get('HOMEVPN_MTU_BENCH_FAKE'):
        raise ValueError('Ordered native host requires explicit real disposable acceptance')
    # Reuse the existing native architecture and ordinary-UID proof. This does
    # not invoke the external gate or grant its environment to the child.
    checked = dict(environment)
    checked[EXTERNAL.FLAG] = '1'
    return EXTERNAL.required_host(checked)


def repository_identity(commit):
    if commit is None:
        return None
    if not isinstance(commit, str) or re.fullmatch('[0-9a-f]{40}', commit) is None:
        raise ValueError('Native ordered receipt requires an exact original commit')
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=ROOT, text=True, timeout=30).strip()
    if git('rev-parse', 'HEAD') != commit:
        raise ValueError('Native ordered checkout differs from its required source')
    tree = git('rev-parse', 'HEAD^{tree}')
    if re.fullmatch('[0-9a-f]{40}', tree) is None:
        raise ValueError('Native ordered checkout has no exact tree')
    git('diff', '--quiet', 'HEAD', '--')
    if git('ls-files', '--others', '--exclude-standard', '--', 'mobile', 'internal', 'deploy', 'cmd', 'configs', 'modes', '.github', 'go.mod', 'go.sum'):
        raise ValueError('Native ordered receipt contains unpublished source inputs')
    return dict(repository='Eabusham2/router-vpn', commit=commit, tree=tree)


def write_receipt(path, value):
    path = Path(path).absolute()
    if path.is_symlink() or path.exists() or not path.parent.is_dir():
        raise ValueError('Native ordered receipt requires one new explicit artifact')
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(value, output, sort_keys=True, separators=(',', ':'))
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def execute(bundle, source=None, go='go', environment=None, *, required_commit=None, receipt_file=None):
    environment = dict(os.environ if environment is None else environment)
    target, uid = required_host(environment)
    repository = repository_identity(required_commit)
    if receipt_file is not None and repository is None:
        raise ValueError('Native ordered durable receipt must name its exact tested commit')
    cases = case_inventory()
    compiler, captured = CONTROLLER.UID.compiler_toolchain(ROOT, go, environment)
    captured['CGO_ENABLED'] = '1'
    bundle = Path(bundle).resolve()
    original = BUILD.reuse(bundle, target, env=captured)
    original_hash = EXTERNAL.sha(bundle/'NATIVE-RUNTIME.json')
    policy = BUILD.digest()
    python = CONTROLLER.discover_python(uid)
    sudo = CONTROLLER.UID.privilege_tool()
    with tempfile.TemporaryDirectory(prefix='routervpn-macos-node-chain-') as temporary:
        work = Path(temporary).resolve()
        work.chmod(0o755)
        core = Path(source).resolve() if source else EXTERNAL.prepared_peer_source(work, captured)
        before = source_identity(core)
        signed = work/'sealed-bundle'
        shutil.copytree(bundle, signed, symlinks=True)
        subprocess.run([os.sys.executable, str(ROOT/'deploy/seal-native-runtime.py'), str(signed), target],
                       cwd=ROOT, env=captured, check=True, timeout=300)
        BUILD.reuse(signed, target, env=captured)
        signed_hash = EXTERNAL.sha(signed/'NATIVE-RUNTIME.json')
        race_compiler, race_environment = CONTROLLER.UID.RACE.capture(core, compiler, captured)
        controller, peer = work/'controller.test', work/'peer.test'
        commands = (
            ([str(race_compiler), 'test', '-race', '-c', '-mod=readonly', '-tags=routervpn_controller_privileged',
              '-o', str(controller), './cmd/client'], ROOT),
            ([str(race_compiler), 'test', '-race', '-c', '-mod=readonly', '-tags='+PEER_TAGS,
              '-ldflags=-checklinkname=0', '-o', str(peer), './protocol/routervpnamnezia'], core),
        )
        for command, cwd in commands:
            subprocess.run(command, cwd=cwd, env=race_environment, check=True, timeout=300)
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none',
                        '--identifier', 'routervpn.fixture.ordered.controller', str(controller)], check=True, timeout=30)
        controller.chmod(0o755)
        peer.chmod(0o755)
        identities = dict(controller=EXTERNAL.sha(controller), peer=EXTERNAL.sha(peer))
        listing = subprocess.run([str(controller), '-test.list=^'+TEST+'$'], env=captured, cwd=ROOT,
                                 check=True, timeout=30, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
        if listing.strip() != TEST:
            raise ValueError('Compiled native image omitted its actual ordered host test')
        if source_identity(core) != before or BUILD.digest() != policy:
            raise ValueError('Native ordered source changed during compilation')
        authority_output = execute_authority(controller, identities['controller'], captured)
        hysteria_authority_output = execute_authority(controller, identities['controller'], captured, hysteria=True)
        hysteria_control = execute_hysteria_control(race_compiler, work, race_environment)
        completed, output_digest = [], hashlib.sha256((authority_output+hysteria_authority_output).encode())
        for case in cases:
            command = ['/usr/bin/env', 'ROUTERVPN_MACOS_CONTROLLER_PRIVILEGE_FIXTURE=1',
                       'ROUTERVPN_MACOS_FIXTURE_UID='+str(uid), 'ROUTERVPN_MACOS_FIXTURE_SOURCE='+str(ROOT),
                       'ROUTERVPN_MACOS_FIXTURE_PYTHON='+str(Path(python).absolute()),
                       'ROUTERVPN_MACOS_NODE_CHAIN_PEER='+str(peer), 'ROUTERVPN_MACOS_NODE_CHAIN_PEER_SHA256='+identities['peer'],
                       'ROUTERVPN_MACOS_EXTERNAL_BUNDLE='+str(signed), 'ROUTERVPN_MACOS_EXTERNAL_BUNDLE_SHA256='+signed_hash,
                       'GORACE=atexit_sleep_ms=0', str(controller), '-test.run=^'+TEST+'$/^'+case+'$',
                       '-test.v', '-test.count=1', '-test.timeout=240s']
            if sudo:
                command = [sudo, '-n', '--', *command]
            output = CONTROLLER.reported_run(command, cwd=ROOT, env=captured, timeout=270, sudo=sudo)
            print(output, end='', flush=True)
            check_verdict(output, case)
            completed.append(case)
            output_digest.update(output.encode())
            if EXTERNAL.sha(controller) != identities['controller'] or EXTERNAL.sha(peer) != identities['peer']:
                raise ValueError('Native ordered execution replaced an original signed image')
        if tuple(completed) != cases or source_identity(core) != before or BUILD.digest() != policy:
            raise ValueError('Native ordered acceptance omitted a case or changed original sources')
        if BUILD.reuse(bundle, target, env=captured) != original or EXTERNAL.sha(bundle/'NATIVE-RUNTIME.json') != original_hash:
            raise ValueError('Native ordered acceptance changed original delivered bundle')
        if EXTERNAL.sha(signed/'NATIVE-RUNTIME.json') != signed_hash:
            raise ValueError('Native ordered acceptance changed its captured signed copy')
        if repository_identity(required_commit) != repository:
            raise ValueError('Native ordered acceptance changed its exact source commit or tree')
        receipt_value = dict(schema=2, gate='installed-darwin-ordered-host', scope='installed-controller-public-connect-status-mtu',
                             public_darwin_admission='enabled', public_entrypoint='nativeMultihopConnectOwned', public_status_entrypoint='nativeMultihopStatus', public_cases=list(completed),
                             target=target, validation_toolchain=CONTROLLER.UID.RACE.TOOLCHAIN, repository=repository, source_sha256=policy, bundle_sha256=original_hash,
                             sealed_bundle_sha256=signed_hash, images=identities, cases=list(completed),
                             sources=before, authority_cases=list(AUTHORITY_CASES),
                             authority_output_sha256=hashlib.sha256(authority_output.encode()).hexdigest(),
                             hysteria_authority_cases=list(HYSTERIA_AUTHORITY_CASES),
                             hysteria_authority_output_sha256=hashlib.sha256(hysteria_authority_output.encode()).hexdigest(),
                             hysteria_source_control=hysteria_control,
                             output_sha256=output_digest.hexdigest(), native=True)
    if work.exists() or work.is_symlink():
        raise ValueError('Native ordered acceptance did not retire its exact compilation workspace')
    if receipt_file is not None:
        write_receipt(receipt_file, receipt_value)
    print('Native Darwin ordered host acceptance: '+json.dumps(receipt_value, sort_keys=True, separators=(',', ':')), flush=True)
    return receipt_value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--source')
    parser.add_argument('--go', default='go')
    parser.add_argument('--require-commit')
    parser.add_argument('--receipt')
    args = parser.parse_args()
    execute(args.bundle, args.source, args.go, required_commit=args.require_commit, receipt_file=args.receipt)
