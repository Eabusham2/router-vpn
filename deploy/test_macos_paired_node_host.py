#!/usr/bin/env python3
"""Mandatory actual installed Darwin paired Router public host acceptance."""
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
def load(name, filename):
    spec=importlib.util.spec_from_file_location(name, ROOT/'deploy'/filename)
    value=importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
ORDERED=load('paired_native_ordered_utilities','test_macos_node_chain_host.py')
EXTERNAL,BUILD,CONTROLLER=ORDERED.EXTERNAL,ORDERED.BUILD,ORDERED.CONTROLLER
PEER_TAGS=ORDERED.PEER_TAGS
FLAG='ROUTERVPN_DARWIN_PAIRED_NODE_HOST_ACCEPTANCE'
TEST='TestMacOSRetainedPairedNodeNativePublicGraphs'
MODES=('wg','awg2-fast','awg2-strong','shadowsocks','hysteria2','ss-v2ray')
LAYERS=('off','aes-256-gcm','aes-256-gcm+xor-whitening')
POLICIES=('off','on-connect','always')
ACTIONS=('home-lan-wrong-node','resolver-failure','wrong-key','restore-sealed','mtu-rollback')
CASES=tuple('/'.join((mode,layer,policy,'connect')) for mode in MODES for layer in LAYERS for policy in POLICIES)+tuple('/'.join(('shadowsocks','off',policy,action)) for policy in POLICIES for action in ACTIONS)
PROVIDERS=('TestRouterVPNDesktopNodeLayerReferenceProcess','TestRouterVPNDesktopNodeWireGuardReferenceProcess','TestRouterVPNDesktopNodeWireGuardLayerReferenceProcess','TestRouterVPNDesktopNodeAmneziaReferenceProcess','TestRouterVPNDesktopNodeAmneziaLayerReferenceProcess')
POLICY_ROOT='TestDesktopDarwinPairedBaselineBindsOriginalCapture'
READER_ROOT='TestDesktopDarwinPairedReaderRequiresOriginalRetirement'
POLICY_CASES=(POLICY_ROOT,*(POLICY_ROOT+'/'+mode+'/'+layer+'/'+policy for mode in (*MODES, "naive-h2") for layer in LAYERS for policy in POLICIES))
READER_CASES=(READER_ROOT,*(READER_ROOT+'/'+case for case in ('pending-mutation-then-rollback','same-alias-fresh-index','same-alias-rollback','same-alias-old-reader-retained','same-alias-rollback-old-reader-retained','old-reader-retained','same-alias','same-index','stale-reader','foreign-session','foreign-config','foreign-path','kernel-name','kernel-mtu','kernel-down','kernel-absent')))
MTU_RECEIPT='actual paired Darwin MTU: Auto and Retest transferred original encrypted UDP, held Cancel joined exact rollback, original process PF and reader succession retained'
def case_inventory(source=None):
    source=source if source is not None else (ROOT/'cmd/client/desktop_node_host_darwin_native_test.go').read_text()
    audit=load('paired_native_inventory_tokens','native_multihop_audit.py')
    tokens=audit._tokens(source)
    body=audit._function(tokens,'func macOSPairedNodeNativeCases() []string')
    expected = """
 var result []string
 for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "ss-v2ray"} {
  for _, layer := range []string{"off", common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
   for _, policy := range []string{"off", "on-connect", "always"} {
    result = append(result, strings.Join([]string{mode, layer, policy, "connect"}, "/"))
   }
  }
 }
 for _, policy := range []string{"off", "on-connect", "always"} {
  for _, action := range []string{"home-lan-wrong-node", "resolver-failure", "wrong-key", "restore-sealed", "mtu-rollback"} {
   result = append(result, strings.Join([]string{"shadowsocks", "off", policy, action}, "/"))
  }
 }
 return result
 """
    if body != audit._tokens(expected): raise ValueError('Paired native finite inventory changed')
    controller=audit._function(tokens,'func macOSPairedNodeNativeController(owned *ownedDesktopController) (bool, error)')
    for fragment in ('mux.HandleFunc("/api/connect", a.connect)','mux.HandleFunc("/api/disconnect", a.disconnect)','registerMTURetestRoute(mux, a)'):
        if controller is None or len(audit._positions(controller,fragment))!=1:
            raise ValueError('Paired native fixture bypassed actual public routes')
    return CASES

def receipt(case):
    if case not in CASES: raise ValueError('Unknown paired native case')
    return 'actual paired Darwin public host verified '+case+': original encrypted proof boundary, joined native PF and utun retirement'

def check_verdict(output,case):
    if case not in CASES or not isinstance(output,str) or re.search(r'(?im)^\s*(?:--- (?:FAIL|SKIP):|FAIL(?:\s|$)|SKIP(?:\s|$)|WARNING: DATA RACE|panic:|fatal error:)|\[build failed\]',output):
        raise ValueError('Paired native execution failed, skipped or raced')
    expected={TEST,TEST+'/'+case}; runs=Counter(); passes=Counter(); receipts=Counter(); complete=0
    for line in output.splitlines():
        run=re.fullmatch(r'=== RUN   (\S+)',line)
        passed=re.fullmatch(r'(?:    )?--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)',line)
        witness=re.fullmatch(r'\s+desktop_node_host_darwin(?:_mtu)?_native_test.go:\d+: (.*)',line)
        if run:
            name=run[1]
            if name not in expected or complete or runs[name] or passes[TEST] or name!=TEST and runs[TEST]!=1: raise ValueError('Unowned or duplicate paired RUN')
            runs[name]+=1
        if passed:
            name=passed[1]
            if name not in expected or complete or runs[name]!=1 or passes[name]: raise ValueError('Unowned or duplicate paired PASS')
            passes[name]+=1
        if witness:
            text=witness[1]
            if text.startswith('actual paired Darwin'):
                if complete or runs[TEST+'/'+case]!=1 or passes[TEST]: raise ValueError('Paired receipt outside original execution')
                receipts[text]+=1
        if line=='PASS':
            if set(passes)!=expected: raise ValueError('Incomplete paired verdict')
            complete+=1
    wanted=Counter({receipt(case):1})
    if case.endswith('/mtu-rollback'): wanted[MTU_RECEIPT]=1
    if set(runs)!=expected or set(passes)!=expected or receipts!=wanted or complete!=1 or not output.rstrip().endswith('\nPASS'):
        raise ValueError('Paired native missing exact original verdict/receipts')

def source_identity(core):
    value=ORDERED.source_identity(core)
    for name in ('deploy/test_macos_paired_node_host.py','deploy/test_macos_paired_node_host_runner.py','modes/mtu-throughput-tuner.py','mobile/desktop/node_private_benchmark_test.go.tmpl','deploy/test_darwin_paired_transport_context.py'):
        value['application'][name]=EXTERNAL.sha(ROOT/name)
    return value

def required_host(environment):
    if environment.get(FLAG)!='1' or environment.get('HOMEVPN_MTU_BENCH_FAKE'): raise ValueError('Paired gate requires explicit real disposable Mac')
    checked=dict(environment); checked[EXTERNAL.FLAG]='1'; return EXTERNAL.required_host(checked)
repository_identity=ORDERED.repository_identity
write_receipt=ORDERED.write_receipt

def execute(bundle, source=None, go='go', environment=None, *, required_commit=None, receipt_file=None):
    environment = dict(os.environ if environment is None else environment)
    target, uid = required_host(environment)
    repository = repository_identity(required_commit)
    if receipt_file is not None and repository is None:
        raise ValueError('Native ordered durable receipt must name its exact tested commit')
    cases = case_inventory()
    compiler, captured = CONTROLLER.UID.compiler_toolchain(ROOT, go, environment)
    captured['CGO_ENABLED'] = '1'
    subprocess.run([os.sys.executable,str(ROOT/'deploy/test_darwin_paired_transport_context.py')],cwd=ROOT,env={**captured,'GO':str(compiler)},check=True,timeout=120)
    bundle = Path(bundle).resolve()
    original = BUILD.reuse(bundle, target, env=captured)
    original_hash = EXTERNAL.sha(bundle/'NATIVE-RUNTIME.json')
    policy = BUILD.digest()
    python = CONTROLLER.discover_python(uid)
    sudo = CONTROLLER.UID.privilege_tool()
    with tempfile.TemporaryDirectory(prefix='routervpn-macos-paired-node-') as temporary:
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
                        '--identifier', 'routervpn.fixture.paired.controller', str(controller)], check=True, timeout=30)
        controller.chmod(0o755)
        peer.chmod(0o755)
        identities = dict(controller=EXTERNAL.sha(controller), peer=EXTERNAL.sha(peer))
        listing = subprocess.run([str(controller), '-test.list=^'+TEST+'$'], env=captured, cwd=ROOT,
                                 check=True, timeout=30, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
        if listing.strip() != TEST:
            raise ValueError('Compiled native image omitted its actual ordered host test')
        if source_identity(core) != before or BUILD.digest() != policy:
            raise ValueError('Native ordered source changed during compilation')
        whitening, whitening_hash = EXTERNAL.NODE.build_layer_reference(race_compiler,work,race_environment,['-race'])
        identities['whitening']=whitening_hash
        listing=subprocess.run([str(peer),'-test.list=^('+('|'.join(PROVIDERS))+')$'],cwd=core,env=race_environment,check=True,timeout=30,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT).stdout
        if Counter(listing.splitlines())!=Counter(PROVIDERS): raise ValueError('Native peer image omitted an original encrypted provider')
        completed, output_digest=[],hashlib.sha256()
        for policy_root, policy_cases in ((POLICY_ROOT,POLICY_CASES),(READER_ROOT,READER_CASES)):
            result=subprocess.run([str(controller),'-test.run=^'+policy_root+'$','-test.v','-test.count=1','-test.timeout=30s'],cwd=ROOT,env=captured,check=True,timeout=40,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            print(result.stdout,end='',flush=True)
            ORDERED.check_authority_verdict(result.stdout,selected=(policy_root,policy_cases))
            output_digest.update(result.stdout.encode())
        for case in cases:
            command = ['/usr/bin/env', 'ROUTERVPN_MACOS_CONTROLLER_PRIVILEGE_FIXTURE=1',
                       'ROUTERVPN_MACOS_FIXTURE_UID='+str(uid), 'ROUTERVPN_MACOS_FIXTURE_SOURCE='+str(ROOT),
                       'ROUTERVPN_MACOS_FIXTURE_PYTHON='+str(Path(python).absolute()),
                       'ROUTERVPN_MACOS_PAIRED_NODE_PEER_BINARY='+str(peer), 'ROUTERVPN_MACOS_PAIRED_NODE_PEER_SHA256='+identities['peer'],
                       'ROUTERVPN_MACOS_PAIRED_NODE_WHITENING_BINARY='+str(whitening), 'ROUTERVPN_MACOS_PAIRED_NODE_WHITENING_SHA256='+whitening_hash,
                       'ROUTERVPN_MACOS_EXTERNAL_BUNDLE='+str(signed), 'ROUTERVPN_MACOS_EXTERNAL_BUNDLE_SHA256='+signed_hash,
                       'GORACE=atexit_sleep_ms=0', str(controller), '-test.run=^'+TEST+'$/'+('/'.join('^'+re.escape(part)+'$' for part in case.split('/'))),
                       '-test.v', '-test.count=1', '-test.timeout=240s']
            if sudo:
                command = [sudo, '-n', '--', *command]
            output = CONTROLLER.reported_run(command, cwd=ROOT, env=captured, timeout=270, sudo=sudo)
            print(output, end='', flush=True)
            check_verdict(output, case)
            completed.append(case)
            output_digest.update(output.encode())
            if EXTERNAL.sha(controller) != identities['controller'] or EXTERNAL.sha(peer) != identities['peer'] or EXTERNAL.sha(whitening)!=whitening_hash:
                raise ValueError('Native ordered execution replaced an original signed image')
        if tuple(completed) != cases or source_identity(core) != before or BUILD.digest() != policy:
            raise ValueError('Native ordered acceptance omitted a case or changed original sources')
        if BUILD.reuse(bundle, target, env=captured) != original or EXTERNAL.sha(bundle/'NATIVE-RUNTIME.json') != original_hash:
            raise ValueError('Native ordered acceptance changed original delivered bundle')
        if EXTERNAL.sha(signed/'NATIVE-RUNTIME.json') != signed_hash:
            raise ValueError('Native ordered acceptance changed its captured signed copy')
        if repository_identity(required_commit) != repository:
            raise ValueError('Native ordered acceptance changed its exact source commit or tree')
        receipt_value=dict(schema=1,gate='installed-darwin-paired-node-host',target=target,
            repository=repository,validation_toolchain=CONTROLLER.UID.RACE.TOOLCHAIN,
            source_sha256=policy,bundle_sha256=original_hash,sealed_bundle_sha256=signed_hash,
            images=identities,cases=completed,sources=before,providers=list(PROVIDERS),
            output_sha256=output_digest.hexdigest(),policy_cases=list(POLICY_CASES),reader_cases=list(READER_CASES),
            cancellation_evidence='actual extracted HTTP/DNS context with modeled socket boundary; native encrypted UDP cancellation',native=True)
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
