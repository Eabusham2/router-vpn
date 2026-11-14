#!/usr/bin/env python3
"""Actual installed Darwin closed selected-prefix acceptance; no public admission override.

Each original case retains the existing240-second native bound. This independent
six-case gate cannot replace any of the ordinary28host/19measurement cases.
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

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('darwin_prefix_original_host',ROOT/'deploy/test_macos_node_chain_host.py')
G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)
EXTERNAL,BUILD,CONTROLLER,PEER_TAGS=G.EXTERNAL,G.BUILD,G.CONTROLLER,G.PEER_TAGS
FLAG='ROUTERVPN_DARWIN_NODE_PREFIX_HOST_ACCEPTANCE'
TEST='TestMacOSRetainedCandidatePrefixNativeHost'
AUTHORITY_TEST='TestDesktopDarwinInstalledPrefixCandidateFixtureKeepsClosedAuthority'
AUTHORITY_CASES=(AUTHORITY_TEST,*(AUTHORITY_TEST+'/'+x for x in ('wg','awg-fast','awg-strong')))
CASES=('wg-save','wg-cancel','awg-fast-save','awg-fast-cancel','awg-strong-save','awg-strong-cancel')
SOURCE_FILES=(
 'deploy/test_macos_node_candidate_prefix_host.py','deploy/test_macos_node_candidate_prefix_host_runner.py',
 'cmd/client/desktop_node_candidate_prefix_darwin_native_test.go',
 '.github/workflows/darwin-node-prefix-host-tun.yml',
 'deploy/native-artifact-workflow-parity-audit.py','deploy/test_native_artifact_aggregate.py',
 'deploy/reusable-workflow-concurrency-audit.py','.github/workflows/release-candidate.yml',
)

def case_inventory(source=None):
 source=source if source is not None else (ROOT/'cmd/client/desktop_node_candidate_prefix_darwin_native_test.go').read_text()
 match=re.search(r'var macOSCandidatePrefixHostCases = \[\]string\{([^}]+)\}',source)
 if match is None:raise ValueError('Original selected-prefix native inventory absent')
 values=tuple(re.findall(r'"([a-z0-9-]+)"',match[1]))
 if re.sub(r'"[a-z0-9-]+"|\s|,','',match[1]) or values!=CASES:raise ValueError('Selected-prefix native inventory differs from exhaustive gate')
 return values

def receipt(case):
 if case not in CASES:raise ValueError('Unknown selected-prefix native case')
 return 'actual sealed Darwin selected-prefix host verified '+case+': original encrypted private prefix, exactly fifty TCP handshakes, unopened saved final, closed application and DNS, native Stop and process join, PF and utun retirement, explicit detached decision'

def check_output(output,root,children,required_receipt=None):
 if not isinstance(output,str) or re.search(r'(?im)^\s*(?:--- (?:FAIL|SKIP):|FAIL(?:\s|$)|SKIP(?:\s|$)|WARNING: DATA RACE|panic:|fatal error:)|\[build failed\]',output):raise ValueError('Prefix output contains failure/skip/race evidence')
 expected={root,*children};runs,passes=Counter(),Counter();receipts=[];complete=0
 for line in output.splitlines():
  run=re.fullmatch(r'=== RUN   (\S+)',line)
  passed=re.fullmatch(r'(?:    )?--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)',line)
  proof=re.fullmatch(r'\s+desktop_node_candidate_prefix_darwin_native_test.go:\d+: (.*)',line)
  if run:
   name=run[1]
   if name not in expected or complete or runs[name] or passes[root] or name!=root and runs[root]!=1:raise ValueError('Prefix RUN is extra, duplicate or after completion')
   runs[name]+=1
  if passed:
   name=passed[1]
   if name not in expected or complete or runs[name]!=1 or passes[name]:raise ValueError('Prefix PASS has no original unique RUN')
   passes[name]+=1
  if proof and proof[1].startswith('actual sealed Darwin'):
   if complete or passes[root] or any(runs[child]!=1 for child in children):raise ValueError('Prefix native receipt is outside its original case')
   receipts.append(proof[1])
  if line=='PASS':
   if set(passes)!=expected:raise ValueError('Prefix package finished without exact inventory')
   complete+=1
 if set(runs)!=expected or set(passes)!=expected or complete!=1 or not output.rstrip().endswith('\nPASS'):raise ValueError('Prefix execution omitted exact original verdicts')
 if receipts != ([] if required_receipt is None else [required_receipt]):raise ValueError('Prefix native ownership receipt missing, duplicated or borrowed')

def check_verdict(output,case):
 if case not in CASES:raise ValueError('Unknown selected-prefix native verdict')
 check_output(output,TEST,(TEST+'/'+case,),receipt(case))

def check_authority_verdict(output):
 check_output(output,AUTHORITY_TEST,AUTHORITY_CASES[1:])

def source_identity(core):
 identity=G.source_identity(core)
 for name in SOURCE_FILES:identity['application'][name]=EXTERNAL.sha(ROOT/name)
 return identity

def required_host(environment):
 if environment.get(FLAG)!='1':raise ValueError('Selected-prefix acceptance requires explicit real disposable host')
 captured=dict(environment);captured[G.FLAG]='1'
 return G.required_host(captured)

repository_identity,write_receipt=G.repository_identity,G.write_receipt

def execute_authority(controller, digest, environment):
    if EXTERNAL.sha(controller) != digest:
        raise ValueError('Imported source authority lost its captured controller image')
    result = subprocess.run([str(controller), '-test.v', '-test.count=1', '-test.timeout=30s',
                             '-test.run=^'+AUTHORITY_TEST+'$'], cwd=ROOT, env=environment,
                            check=True, timeout=40, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end='' if result.stdout.endswith('\n') else '\n', flush=True)
    check_authority_verdict(result.stdout)
    if EXTERNAL.sha(controller) != digest:
        raise ValueError('Imported source authority changed its captured controller image')
    return result.stdout


def execute(bundle, source=None, go='go', environment=None, *, required_commit=None, receipt_file=None):
    environment = dict(os.environ if environment is None else environment)
    target, uid = required_host(environment)
    repository = repository_identity(required_commit)
    if receipt_file is not None and repository is None:
        raise ValueError('Native selected-prefix durable receipt must name its exact tested commit')
    cases = case_inventory()
    compiler, captured = CONTROLLER.UID.compiler_toolchain(ROOT, go, environment)
    captured['CGO_ENABLED'] = '1'
    bundle = Path(bundle).resolve()
    original = BUILD.reuse(bundle, target, env=captured)
    original_hash = EXTERNAL.sha(bundle/'NATIVE-RUNTIME.json')
    policy = BUILD.digest()
    python = CONTROLLER.discover_python(uid)
    sudo = CONTROLLER.UID.privilege_tool()
    with tempfile.TemporaryDirectory(prefix='routervpn-macos-candidate-prefix-') as temporary:
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
                        '--identifier', 'routervpn.fixture.prefix.controller', str(controller)], check=True, timeout=30)
        controller.chmod(0o755)
        peer.chmod(0o755)
        identities = dict(controller=EXTERNAL.sha(controller), peer=EXTERNAL.sha(peer))
        listing = subprocess.run([str(controller), '-test.list=^'+TEST+'$'], env=captured, cwd=ROOT,
                                 check=True, timeout=30, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
        if listing.strip() != TEST:
            raise ValueError('Compiled native image omitted its actual ordered host test')
        if source_identity(core) != before or BUILD.digest() != policy:
            raise ValueError('Native selected-prefix source changed during compilation')
        authority_output = execute_authority(controller, identities['controller'], captured)
        completed, output_digest = [], hashlib.sha256(authority_output.encode())
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
                raise ValueError('Native selected-prefix execution replaced an original signed image')
        if tuple(completed) != cases or source_identity(core) != before or BUILD.digest() != policy:
            raise ValueError('Native selected-prefix acceptance omitted a case or changed original sources')
        if BUILD.reuse(bundle, target, env=captured) != original or EXTERNAL.sha(bundle/'NATIVE-RUNTIME.json') != original_hash:
            raise ValueError('Native selected-prefix acceptance changed original delivered bundle')
        if EXTERNAL.sha(signed/'NATIVE-RUNTIME.json') != signed_hash:
            raise ValueError('Native selected-prefix acceptance changed its captured signed copy')
        if repository_identity(required_commit) != repository:
            raise ValueError('Native selected-prefix acceptance changed its exact source commit or tree')
        receipt_value = dict(schema=1, gate='installed-darwin-selected-prefix-host', scope='saved-prefix-local',
                             target=target, validation_toolchain=CONTROLLER.UID.RACE.TOOLCHAIN, repository=repository, source_sha256=policy, bundle_sha256=original_hash,
                             sealed_bundle_sha256=signed_hash, images=identities, cases=list(completed),
                             sources=before, authority_cases=list(AUTHORITY_CASES),
                             authority_output_sha256=hashlib.sha256(authority_output.encode()).hexdigest(),
                             output_sha256=output_digest.hexdigest(), native=True)
    if work.exists() or work.is_symlink():
        raise ValueError('Native selected-prefix acceptance did not retire its exact compilation workspace')
    if receipt_file is not None:
        write_receipt(receipt_file, receipt_value)
    print('Native Darwin selected-prefix host acceptance: '+json.dumps(receipt_value, sort_keys=True, separators=(',', ':')), flush=True)
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
