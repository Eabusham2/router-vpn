#!/usr/bin/env python3
"""Require installed Linux imported SS Server/Compare through original prefixes.

The controller, TUN, nftables, native relay image and encrypted providers are
real. Disposable namespaces and the authenticated administration adapter are
test boundaries; this gate is not private-server deployment acceptance.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('linux_imported_execution_'+name.replace('-', '_'), ROOT/'deploy'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load('test_linux_node_host_tun')
CHILD, GUARD, NODE, BUILD = BASE.CHILD, BASE.GUARD, BASE.NODE, BASE.BUILD
PROJECTOR = load('prepare-desktop-imported-execution-test')
REPOSITORY = load('test_server_node_chain_encrypted')
FLAG = 'ROUTERVPN_LINUX_IMPORTED_EXECUTION_HOST_ACCEPTANCE'
TEST = 'TestDesktopLinuxGuardianKernelImportedExecution'
CHOICES = ('server', 'auto-local', 'auto-server')
FAULTS = ('wrong-first-key', 'wrong-later-key', 'wrong-middle-key', 'wrong-final-key', 'wrong-public', 'failed-dns',
          'replaced-source', 'carrier-change', 'held-cleanup')
POSITIVE = tuple(f'ss-p{count}-{choice}' for count in range(1, 7) for choice in CHOICES)
CASES = POSITIVE + tuple('ss-p6-'+fault for fault in FAULTS)
MODES = ('wg', 'awg2-fast', 'awg2-strong')
METHODS = ('2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305')
PEER_TEMPLATE = 'mobile/desktop/node_chain_imported_execution_native_linux_test.go.tmpl'
PEER_TARGET = 'protocol/routervpnamnezia/routervpn_imported_execution_native_linux_test.go'
DRIVER = 'cmd/client/desktop_imported_execution_linux_tun_native_test.go'
SOURCES = ('deploy/test_linux_imported_execution_host.py', 'deploy/test_linux_imported_execution_host_runner.py',
           '.github/workflows/linux-imported-execution-host.yml',
           DRIVER, 'cmd/client/desktop_node_host_linux_tun_native_test.go',
           'deploy/test_desktop_linux_guardian.py', 'deploy/prepare-desktop-external.py', PEER_TEMPLATE,
           'mobile/desktop/node_chain_peer_linux_test.go.tmpl')
SOURCE_TESTS = {
    'TestRouterVPNDesktopNativeImportedSourcePositions': tuple(f'{count}-{mode}' for count in range(1, 7) for mode in MODES),
    'TestRouterVPNDesktopNativeImportedProviderPositions': tuple(str(count) for count in range(1, 7)),
    'TestRouterVPNDesktopNativeImportedSourceRefusals': ('missing-key', 'entry-key', 'import-key', 'copied-key', 'short-source',
        'missing-identity', 'moved-import', 'wrong-node', 'foreign-mode', 'changed-client'),
}
NAMESPACE_RETIREMENT_PHASES = (
    'retire owned peer namespace; test status 0',
    'unmount private account directory',
    'private account workspace removed; return test status 0',
    'original namespace child joined',
)


def scenario(case):
    if case not in CASES:
        raise ValueError('Unknown original imported execution case')
    count = int(case[4])
    variant = case[6:]
    positive = case in POSITIVE
    arm = CHOICES.index(variant) if positive else 0
    return dict(prefixes=count, requested='auto' if positive and arm else 'server',
                winner='local' if positive and arm == 1 else 'server',
                negative=not positive and variant in FAULTS[:6], restored=positive,
                cleanup_retry=variant == 'held-cleanup', carrier_required=count > 1,
                fault='' if positive else variant, arm=arm)


def case_inventory(source=None):
    source = source if source is not None else (ROOT/DRIVER).read_text()
    match = re.search(r'var linuxImportedExecutionCases = \[\]string\{([^}]+)\}', source)
    if match is None or tuple(re.findall(r'"([a-z0-9-]+)"', match[1])) != CASES or re.sub(r'"[a-z0-9-]+"|\s|,', '', match[1]):
        raise ValueError('Imported execution lost its complete original native inventory')
    for anchor in ('a.nativeMultihopConnect(w, r)', 'a.speedLabSuspendPrevious(snapshot, false)',
                   'a.speedLabRestoreTemporary(snapshot)', 'original.gate <- struct{}{}'):
        if source.count(anchor) != 1:
            raise ValueError('Imported execution lost its public/restore/retirement boundary: '+anchor)
    return CASES


def peer_inventory(source=None):
    source = source if source is not None else (ROOT/PEER_TEMPLATE).read_text()
    required = ('func nativeImportedServerSource(', 'func nativeImportedRequestValid(',
                'func TestRouterVPNDesktopNativeImportedExecutionProcess(',
                'func TestRouterVPNDesktopNativeImportedProviderProcess(',
                'policy.NativeCarrierRequired() != (n > 1)',
                'func nativeImportedNamespace(', 'func nativeImportedPrefixSnapshot(')
    for anchor in required:
        if source.count(anchor) != 1:
            raise ValueError('Imported native peer lost its original source/carrier/ownership boundary: '+anchor)
    for root in SOURCE_TESTS:
        if source.count('func '+root+'(') != 1:
            raise ValueError('Imported native peer omitted a required component root')
    return required


def receipt(case):
    values = scenario(case)
    keys = ('prefixes', 'requested', 'winner', 'negative', 'restored', 'cleanup_retry', 'carrier_required')
    rendered = lambda value: str(value).lower() if type(value) is bool else str(value)
    return ('LINUX_IMPORTED_EXECUTION_RECEIPT case='+case+' '+
            ' '.join(key+'='+rendered(values[key]) for key in keys)+
            ' native_joined=true relay_joined=true namespace_owned=true')


def exact_object(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError('Imported '+label+' changed its original fields')


def counters(value, keys, label):
    for key in keys:
        if type(value[key]) is not int or not 0 <= value[key] < 2**64:
            raise ValueError('Imported '+label+' is not a nonnegative actual integer: '+key)


def positive_values(value, keys, label):
    if any(value[key] <= 0 for key in keys):
        raise ValueError('Imported '+label+' omitted its actual traffic/proof')


def zero_values(value, keys, label):
    if any(value[key] != 0 for key in keys):
        raise ValueError('Imported '+label+' bypassed its original failed boundary')


def check_counters(value, case):
    expected = scenario(case)
    scalar = {'launches', 'restore_launches', 'comparison_trials', 'entry_proofs', 'carrier_packets', 'carrier_tcp', 'local_delayed_packets'}
    exact_object(value, {'case', 'prefixes', 'requested', 'winner', 'carrier_required', 'local_prefixes', 'server_prefixes', 'middle', 'final'} | scalar, 'counter receipt')
    if value['case'] != case or type(value['prefixes']) is not int or value['prefixes'] != expected['prefixes']:
        raise ValueError('Imported counters replaced their captured case or prefix count')
    for key in ('requested', 'winner', 'carrier_required'):
        if type(value[key]) is not type(expected[key]) or value[key] != expected[key]:
            raise ValueError('Imported counters changed original '+key)
    counters(value, scalar, 'execution counters')
    if value['comparison_trials'] != (2 if expected['requested'] == 'auto' else 0) or value['restore_launches'] != int(expected['restored'] and expected['winner'] == 'server'):
        raise ValueError('Imported execution changed its comparison or reran retained selection')
    positive_values(value, ('launches', 'entry_proofs'), 'original entry and worker')
    n, fault = expected['prefixes'], expected['fault']
    if n > 1:
        positive_values(value, ('carrier_packets',), 'native packet carrier')
        zero_values(value, ('carrier_tcp',), 'packet carrier')
    else:
        positive_values(value, ('carrier_tcp',), 'original imported transport carrier')
    local, server = value['local_prefixes'], value['server_prefixes']
    if not isinstance(local, list) or not isinstance(server, list) or len(local) != n or len(server) != n-1:
        raise ValueError('Imported counters omitted or fabricated an original packet prefix')
    packet_counts = {'raw_udp', 'tcp', 'udp', 'proof_queries', 'auth_refusals'}
    for lane, rows, first in (('Local', local, 0), ('Server', server, 1)):
        for position, row in enumerate(rows, first):
            exact_object(row, {'position', 'mode', 'parameters_sha256'} | packet_counts, lane+' packet prefix')
            mode = MODES[(position+n+expected['arm']-1) % 3] if expected['restored'] else MODES[position % 3]
            if type(row['position']) is not int or row['position'] != position or row['mode'] != mode:
                raise ValueError('Imported '+lane+' prefix lost its original position/mode')
            digest = row['parameters_sha256']
            if not isinstance(digest, str) or (digest != '' if mode == 'wg' else not re.fullmatch('[0-9a-f]{64}', digest)):
                raise ValueError('Imported '+lane+' prefix lost its actual transport parameters')
            counters(row, packet_counts, lane+' packet prefix')
            if row['auth_refusals'] != 0:
                raise ValueError('Imported private identity proof refused its original credential')
            if lane == 'Server' and digest != local[position]['parameters_sha256']:
                raise ValueError('Imported Server prefix substituted original transport parameters')
    positive_values(local[0], ('raw_udp', 'tcp'), 'original Local entry')
    if expected['requested'] == 'auto':
        for row in local[1:]:
            positive_values(row, ('raw_udp', 'tcp', 'proof_queries'), 'Local comparison prefix')
    bad_position = 1 if fault == 'wrong-first-key' else n-1 if fault == 'wrong-later-key' else None
    for row in server:
        position = row['position']
        if bad_position is None or position < bad_position:
            positive_values(row, ('raw_udp', 'tcp', 'proof_queries'), 'original Server prefix')
        elif position == bad_position:
            positive_values(row, ('raw_udp',), 'failed original packet handshake')
            zero_values(row, ('tcp', 'udp', 'proof_queries'), 'failed packet handshake')
        else:
            zero_values(row, packet_counts, 'prefix after failed handshake')
    middle, final = value['middle'], value['final']
    middle_counts = {'raw_tcp', 'raw_udp', 'tcp', 'udp', 'public_queries'}
    final_counts = {'raw_tcp', 'raw_udp', 'tcp', 'udp', 'proof_queries', 'dns_queries', 'public_queries', 'direct_queries', 'entry_public_queries'}
    exact_object(middle, middle_counts | {'method'}, 'imported transport')
    exact_object(final, final_counts, 'paired final')
    method = METHODS[(n+expected['arm']-1) % 3] if expected['restored'] else METHODS[1]
    if middle['method'] != method:
        raise ValueError('Imported middle changed its captured cipher')
    counters(middle, middle_counts, 'imported transport')
    counters(final, final_counts, 'paired final')
    zero_values(final, ('direct_queries', 'entry_public_queries'), 'final proof/DNS route')
    if bad_position is not None:
        zero_values(middle, middle_counts, 'middle after failed packet handshake')
        zero_values(final, final_counts, 'final after failed packet handshake')
    elif fault == 'wrong-middle-key':
        positive_values(middle, ('raw_tcp',), 'original encrypted middle')
        zero_values(middle, ('tcp', 'udp', 'public_queries'), 'middle authentication')
        zero_values(final, final_counts, 'final after middle authentication')
    else:
        positive_values(middle, ('raw_tcp', 'tcp', 'public_queries'), 'original imported public proof')
        if fault == 'wrong-public':
            zero_values(final, final_counts, 'final after wrong public source')
        elif fault == 'wrong-final-key':
            positive_values(final, ('raw_tcp',), 'original encrypted final')
            zero_values(final, ('tcp', 'udp', 'proof_queries', 'dns_queries', 'public_queries'), 'final authentication')
        else:
            positive_values(final, ('raw_tcp', 'tcp', 'proof_queries', 'dns_queries'), 'original final private proof and selected DNS')
            if fault != 'failed-dns':
                positive_values(final, ('public_queries',), 'proved final public path')


def check_verdict(output, case):
    if case not in CASES:
        raise ValueError('Unknown original imported execution case')
    NODE.require_native_verdicts(output, (TEST, TEST+'/'+case), 'actual installed imported prefix execution')
    lines = output.splitlines()
    terminals = [index for index, line in enumerate(lines) if line == 'PASS']
    if len(terminals) != 1:
        raise ValueError('Imported execution omitted or duplicated its terminal Go verdict')
    # GUARD emits these four records after the actual Go image exits. They are
    # the only permitted tail; a package PASS alone cannot retire its namespace.
    tail = lines[terminals[0]+1:]
    if len(tail) != len(NAMESPACE_RETIREMENT_PHASES) or any(
            re.fullmatch('Linux guardian namespace phase: '+re.escape(phase)+
                         r' \(pid=[1-9][0-9]*, monotonic=[0-9]+\.[0-9]{3}\)', line) is None
            for phase, line in zip(NAMESPACE_RETIREMENT_PHASES, tail)):
        raise ValueError('Imported execution lost its terminal original namespace retirement')
    active, completed = False, False
    records, observations = [], []

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError('Duplicated imported execution counter field')
            result[key] = value
        return result

    for line in lines:
        if line == '=== RUN   '+TEST+'/'+case:
            active = True
        if re.match(r'\s*--- PASS: ', line):
            completed = True
        for marker, target in (('LINUX_IMPORTED_EXECUTION_COUNTERS', observations), ('LINUX_IMPORTED_EXECUTION_RECEIPT', records)):
            if marker not in line:
                continue
            match = re.fullmatch(r'\s+desktop_imported_execution_linux_tun_native_test.go:\d+: ('+marker+r' .*)', line)
            if not match or not active or completed or len(line) > 1 << 20:
                raise ValueError('Imported execution evidence is outside its original running case')
            if marker.endswith('COUNTERS'):
                try:
                    value = json.loads(match[1].split(' ', 1)[1], object_pairs_hook=pairs)
                except (TypeError, json.JSONDecodeError) as error:
                    raise ValueError('Malformed imported execution counter receipt') from error
                check_counters(value, case)
                target.append(value)
            else:
                target.append(match[1])
    if records != [receipt(case)] or len(observations) != 1:
        raise ValueError('Imported execution omitted or duplicated original ownership evidence')

def source_identity(core):
 core,native=BASE.checked_sources(core)
 required={**PROJECTOR.copies(),PEER_TARGET:(ROOT/PEER_TEMPLATE).read_bytes()}
 for name,body in required.items():
  if (core/name).read_bytes()!=body:raise ValueError('Captured IMPORTED generated source changed: '+name)
 return {'native':native,'fixture':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in (*SOURCES,*PROJECTOR.SOURCES)}}
def required_host(environment):
 if platform.system()!='Linux' or environment.get(FLAG)!='1' or 'HOMEVPN_MTU_BENCH_FAKE' in environment or environment.get('GOOS','linux')!='linux' or environment.get('CGO_ENABLED','1')!='1':raise ValueError('IMPORTED execution requires opted-in real native Linux host')
 architecture={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
 if architecture is None or environment.get('GOARCH',architecture)!=architecture:raise ValueError('Unsupported or foreign native Linux architecture')
 return 'linux/'+architecture

def selected_compiler(go,environment,target):
 # Reuse the shipping Linux compiler capture. The separate Darwin race
 # selector deliberately refuses Linux and cannot authorize this fixture.
 compiler,captured,architecture=NODE.selected_compiler(go,ROOT,environment)
 if target!='linux/'+architecture or captured.get('GOOS')!='linux' or captured.get('GOARCH')!=architecture:
  raise ValueError('IMPORTED execution compiler differs from its original native host')
 captured['CGO_ENABLED']='1'
 return compiler,captured

def namespace_test(binary,peer,bundle,image_sha256,peer_sha256,bundle_sha256,case):
 if case not in CASES:raise ValueError('Uncaptured IMPORTED namespace case')
 if CHILD.image_identity(binary)[-1]!=image_sha256 or CHILD.image_identity(peer)[-1]!=peer_sha256:raise ValueError('Original IMPORTED executable changed')
 bundle=Path(bundle)
 if not bundle.is_absolute() or bundle.is_symlink() or any(parent.is_symlink() for parent in bundle.parents):raise ValueError('Foreign native bundle path')
 receipt=bundle/'NATIVE-RUNTIME.json';info=receipt.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_mode&0o6022 or not 0<info.st_size<=32768 or hashlib.sha256(receipt.read_bytes()).hexdigest()!=bundle_sha256:raise ValueError('Changed complete native bundle receipt')
 current,mount=os.stat('/proc/self/ns/net'),os.stat('/proc/self/ns/mnt')
 values=dict(zip(BASE.NAMESPACE_ENVIRONMENT,(f'{current.st_dev}:{current.st_ino}',str(bundle),bundle_sha256,str(peer),peer_sha256,'','',f'{mount.st_dev}:{mount.st_ino}')))
 values['ROUTERVPN_IMPORTED_EXECUTION_SOURCE']=str(ROOT)
 previous={key:os.environ.get(key) for key in values};os.environ.update(values)
 try:return GUARD.namespace_test(Path(binary),'ImportedExecution/'+case,image_sha256)
 finally:
  for key,value in previous.items():
   if value is None:os.environ.pop(key,None)
   else:os.environ[key]=value

def prepared_source(work,environment,compiler):
 core,xray=work/'core',work/'xray'
 BUILD.checkout(core,'https://github.com/SagerNet/sing-box.git',BUILD.PIN)
 BUILD.checkout(xray,'https://github.com/XTLS/Xray-core.git',BUILD.POLICY.XRAY.XRAY_PIN)
 BUILD.pristine(core,BUILD.PIN);BUILD.pristine(xray,BUILD.POLICY.XRAY.XRAY_PIN)
 BUILD.POLICY.prepare_native(core,xray);BUILD.PERFORMANCE.prepare(core);BUILD.OPENVPN.prepare(core);BUILD.EXTERNAL.prepare(core,env=environment);BUILD.BUFFERS.prepare(core)
 subprocess.run([str(compiler),'mod','tidy'],cwd=core,env=environment,check=True,timeout=300)
 return core

def execute(bundle,source=None,go='go',environment=None,*,required_commit=None,receipt_file=None):
 environment=dict(os.environ if environment is None else environment)
 target=required_host(environment);repository=REPOSITORY.repository_identity(required_commit)
 if receipt_file is not None and repository is None:raise ValueError('Durable native receipt requires exact published commit')
 case_inventory();peer_inventory()
 compiler,captured=selected_compiler(go,environment,target)
 bundle=Path(bundle).absolute();original,payloads=BASE.bundle_identity(bundle,target,captured);policy=BUILD.digest()
 bundle_hash=payloads['NATIVE-RUNTIME.json']['sha256'];sudo=GUARD.UID.privilege_tool();receipt_path=CHILD.new_receipt_path(receipt_file)
 with tempfile.TemporaryDirectory(prefix='routervpn-linux-imported-execution-') as temporary:
  work=Path(temporary).resolve();core=Path(source).resolve() if source else prepared_source(work,captured,compiler)
  before=source_identity(core)
  controller,peer=work/'controller.test',work/'peer.test'
  for command,cwd in (([str(compiler),'test','-race','-c','-mod=readonly','-tags=routervpn_controller_privileged','-o',str(controller),'./cmd/client'],ROOT),([str(compiler),'test','-race','-c','-mod=readonly','-tags='+','.join(NODE.TAGS),'-ldflags=-checklinkname=0','-o',str(peer),'./protocol/routervpnamnezia'],core)):
   subprocess.run(command,cwd=cwd,env=captured,check=True,timeout=300)
  for image in (controller,peer):
   version=subprocess.run([str(compiler),'version',str(image)],cwd=ROOT,env=captured,check=True,timeout=30,capture_output=True,text=True)
   if version.stdout.strip()!=str(image)+': '+BUILD.TOOLCHAIN:raise ValueError('IMPORTED execution image changed its captured native compiler')
  images={str(path):CHILD.image_identity(path) for path in (controller,peer)};source_outputs={}
  for root,leaves in SOURCE_TESTS.items():
   result=subprocess.run([str(peer),'-test.v','-test.count=1','-test.timeout=120s','-test.run=^'+root+'$'],cwd=ROOT,env=captured,check=True,timeout=135,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
   NODE.require_native_verdicts(result.stdout,(root,*(root+'/'+leaf for leaf in leaves)),'IMPORTED original product source')
   print(result.stdout,end='',flush=True);source_outputs[root]=hashlib.sha256(result.stdout.encode()).hexdigest()
  outputs={}
  for case in CASES:
   if source_identity(core)!=before or BUILD.digest()!=policy or any(CHILD.image_identity(Path(path))!=identity for path,identity in images.items()):raise ValueError('Original source/image changed before native admission')
   command=[sys.executable,str(Path(__file__).resolve()),'--namespace-test-binary',str(controller),'--peer-binary',str(peer),'--bundle',str(bundle),'--namespace-test-sha256',images[str(controller)][-1],'--peer-sha256',images[str(peer)][-1],'--bundle-sha256',bundle_hash,'--case',case]
   if sudo:command=[sudo,'-n','--',*command]
   output=GUARD.UID.run(command,cwd=ROOT,env=captured,timeout=150,sudo=sudo)
   print(output,end='',flush=True);check_verdict(output,case);outputs[case]=hashlib.sha256(output.encode()).hexdigest()
  if source_identity(core)!=before or BUILD.digest()!=policy or REPOSITORY.repository_identity(required_commit)!=repository or BASE.bundle_identity(bundle,target,captured)!=(original,payloads) or any(CHILD.image_identity(Path(path))!=identity for path,identity in images.items()):raise ValueError('Final original source/image/bundle identity changed')
  result=dict(schema=1,gate='linux-imported-prefix-execution',target=target,native=True,repository=repository,source_sha256=policy,bundle_sha256=bundle_hash,validation_toolchain=BUILD.TOOLCHAIN,images=images,sources=before,cases=list(CASES),completed=list(outputs),outputs=outputs,source_outputs=source_outputs,scope='original-public-server-compare-one-to-six-packet-prefixes-protected-controller-tun-nft-dns',administration='fixture-authenticated-private-http',worker_launch='fixture-direct-original-image',remote_private_deployment=False)
 CHILD.publish_receipt(receipt_path,result,work)
 print('Native Linux IMPORTED execution acceptance: '+json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
 return result

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--bundle',type=Path,required=True);parser.add_argument('--source',type=Path);parser.add_argument('--go',default=os.environ.get('GO','go'));parser.add_argument('--require-commit');parser.add_argument('--receipt',type=Path)
 parser.add_argument('--namespace-test-binary',type=Path,help=argparse.SUPPRESS);parser.add_argument('--peer-binary',type=Path,help=argparse.SUPPRESS);parser.add_argument('--namespace-test-sha256',help=argparse.SUPPRESS);parser.add_argument('--peer-sha256',help=argparse.SUPPRESS);parser.add_argument('--bundle-sha256',help=argparse.SUPPRESS);parser.add_argument('--case',choices=CASES,help=argparse.SUPPRESS)
 args=parser.parse_args()
 if args.namespace_test_binary is not None:
  if args.source or args.require_commit or args.receipt or not all((args.peer_binary,args.namespace_test_sha256,args.peer_sha256,args.bundle_sha256,args.case)):parser.error('Namespace requires only exact original images and case')
  return namespace_test(args.namespace_test_binary,args.peer_binary,args.bundle,args.namespace_test_sha256,args.peer_sha256,args.bundle_sha256,args.case)
 if any((args.peer_binary,args.namespace_test_sha256,args.peer_sha256,args.bundle_sha256,args.case)):parser.error('Foreign namespace arguments')
 execute(args.bundle,args.source,args.go,required_commit=args.require_commit,receipt_file=args.receipt)
 return 0
if __name__=='__main__':raise SystemExit(main())
