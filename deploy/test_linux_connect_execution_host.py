#!/usr/bin/env python3
"""Actual installed Linux CONNECT trio public Server/Compare in owned namespaces.

Real protected controller, original TUN/nft/route/DNS and encrypted HTTP/TLS
providers are mandatory. HTTP administration and direct shipping-worker launch
are bounded fixture adapters, not remote private-server deployment acceptance.
"""
from pathlib import Path
from collections import Counter
import argparse,hashlib,importlib.util,json,os,platform,re,shutil,stat,subprocess,sys,tempfile
ROOT=Path(__file__).resolve().parents[1]
def load(name):
 spec=importlib.util.spec_from_file_location('linux_connect_execution_'+name.replace('-','_'),ROOT/'deploy'/(name+'.py'))
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
BASE=load('test_linux_node_host_tun');CHILD=BASE.CHILD;GUARD=BASE.GUARD;NODE=BASE.NODE;BUILD=BASE.BUILD
PROJECTOR=load('prepare-desktop-imported-execution-test')
REPOSITORY=load('test_server_node_chain_encrypted')
FLAG='ROUTERVPN_LINUX_CONNECT_EXECUTION_HOST_ACCEPTANCE'
TEST='TestDesktopLinuxGuardianKernelCONNECTExecution'
CASES = ('http-wg-server', 'http-awg-fast-auto-local', 'http-awg-strong-auto-server', 'https-awg-strong-server', 'https-wg-auto-local', 'https-awg-fast-auto-server', 'http-wrong-auth', 'https-wrong-auth', 'https-tls-name', 'http-wrong-public', 'https-wrong-final', 'https-failed-dns', 'http-replaced-source', 'https-held-cleanup')
ENTRY_LAYERS = {case: ('aes-256-gcm' if case in ('http-awg-fast-auto-local','https-awg-strong-server') else 'aes-256-gcm+xor-whitening' if case in ('http-awg-strong-auto-server','https-wg-auto-local') else 'off') for case in CASES}
PEER_TEMPLATE = 'mobile/desktop/node_chain_connect_execution_peer_test.go.tmpl'
PEER_TARGET = 'protocol/routervpnamnezia/routervpn_connect_execution_peer_test.go'
PEER_HELPERS = {f'mobile/desktop/node_chain_connect_execution_peer_{platform}_test.go.tmpl':f'protocol/routervpnamnezia/routervpn_connect_execution_peer_{platform}_test.go' for platform in ('linux','darwin')}
SOURCES = ('deploy/test_linux_connect_execution_host.py','deploy/test_linux_connect_execution_host_runner.py',
 'cmd/client/desktop_connect_execution_linux_tun_native_test.go','cmd/client/desktop_node_host_linux_tun_native_test.go',
 'deploy/test_desktop_linux_guardian.py','deploy/prepare-desktop-external.py',PEER_TEMPLATE,*PEER_HELPERS,
 'cmd/client/desktop_node_chain_connect_execution_product_test.go','cmd/client/desktop_node_chain_connect_execution_profile_test.go')
def case_inventory(source=None):
    source = source if source is not None else (ROOT/'cmd/client/desktop_connect_execution_linux_tun_native_test.go').read_text()
    match = re.search(r'var linuxCONNECTExecutionCases = \[\]string\{([^}]+)\}', source)
    if match is None or tuple(re.findall(r'"([a-z0-9-]+)"', match[1])) != CASES or re.sub(r'"[a-z0-9-]+"|\s|,', '', match[1]):
        raise ValueError('Imported execution lost its exact native inventory')
    for anchor in ('a.nativeMultihopConnect(w, r)', 's.Current(ctx)', 'h.readReadyLocked(ctx, false)',
                   'a.speedLabSuspendPrevious(snapshot, false)', 'a.speedLabRestoreTemporary(snapshot)',
                   'reflect.DeepEqual(after.Ready.Progress.Comparison.Winner, before.Ready.Progress.Comparison.Winner)', 'if err = peer.close(ctx); err != nil' ,
                   'a.disconnect(result, request)', 'retained != owner', 'original.gate <- struct{}{}',
                   'restoreLaunches != expectedLaunches', 'len(result.Measurements) != 0',
                   'len(result.Measurements) != 2', 'math.Abs(*m.ScoreMS-(m.LastNodeMS/2+m.ExternalMS/2))'):
        if source.count(anchor) != 1:
            raise ValueError('Imported execution lost original public/proof/restore/cleanup boundary: '+anchor)
    return CASES


def peer_inventory(source=None):
    source = source if source is not None else (ROOT/PEER_TEMPLATE).read_text()
    anchors = ('mobilemultihop.NewNodeChainCONNECTSource(configure.LocalSource)',
               'mobilemultihop.NewNodeChainCONNECTServerPolicy(string(suffixRaw))',
               'peer.paired.final.streamRouter = UOT.NewRouter(',
               'desktopStartImportedCONNECTPeerAt(', 'runner := &importedExecutionRunner{',
               'request.Layers.Final != "off"', 'request.Layers.validate(request.Peer)',
               'proxyCapture.Username != request.Username', 'proxyCapture.Password != request.Password',
               'proxyCapture.TLSServerName != expectedName', 'policy.NativeCarrierRequired()',
               'layers.entryProvider(t, layerRequest, peer, local)', 'provider.awaitCertificateRefusal(ctx)',
               'router.streams.Load() != 0')
    for anchor in anchors:
        if source.count(anchor)!=1:raise ValueError('CONNECT execution lost original peer boundary: '+anchor)
    if 'mobilemultihop.NewNodeChainServerPolicy(' in source or 'mobilemultihop.NewNodeChain(configure.LocalSource)' in source:
        raise ValueError('Typed CONNECT peer borrowed generic parser authority')
    return anchors


def receipt(case):
    if case not in CASES:
        raise ValueError('Unknown CONNECT execution case')
    auto = '-auto-' in case
    negative = case in CASES[6:12]
    restored = case in CASES[:6]
    return ('LINUX_CONNECT_EXECUTION_RECEIPT case='+case+' requested='+('auto' if auto else 'server')+
            ' winner='+('local' if case.endswith('-auto-local') else 'server')+
            ' negative='+str(negative).lower()+' restored='+str(restored).lower()+
            ' cleanup_retry='+str(case=='https-held-cleanup').lower()+
            ' native_joined=true relay_joined=true namespace_owned=true')


def check_verdict(output, case):
    if case not in CASES:
        raise ValueError('Unknown imported execution case')
    NODE.require_native_verdicts(output, (TEST, TEST+'/'+case), 'actual installed CONNECT execution')
    lines = output.splitlines()
    expected = receipt(case)
    records, observations = [], []
    active, complete = False, False
    for line in lines:
        if line == '=== RUN   '+TEST+'/'+case:
            active = True
        if re.match(r'\s*--- PASS: ', line):
            complete = True
        if 'LINUX_CONNECT_EXECUTION_COUNTERS' in line:
            match = re.fullmatch(r'\s+desktop_connect_execution_linux_tun_native_test.go:\d+: LINUX_CONNECT_EXECUTION_COUNTERS (.*)', line)
            if not match or not active or complete:
                raise ValueError('Imported counters are outside the original running case')
            def pairs(values):
                result = {}
                for key, value in values:
                    if key in result:
                        raise ValueError('Duplicated imported native counter')
                    result[key] = value
                return result
            try:
                value = json.loads(match[1], object_pairs_hook=pairs)
            except (TypeError, json.JSONDecodeError) as error:
                raise ValueError('Malformed imported native counters') from error
            expected_keys = {'case','launches','entry_raw_udp','entry_tcp','entry_proofs',
                             'middle_raw_tcp','middle_tcp','middle_public','final_raw_tcp','final_tcp','final_proofs','dns',
                             'middle_raw_udp','final_raw_udp','auth_refusals','tls_refusals','open_streams','entry_layer','entry_layer_packets','entry_layer_ciphertext','entry_layer_auth','restore_launches','comparison_trials'}
            if not isinstance(value,dict) or set(value)!=expected_keys or value['case']!=case:
                raise ValueError('CONNECT native counters changed original identity')
            for key in expected_keys-{'case','entry_layer'}:
                if type(value[key]) is not int or value[key]<0:
                    raise ValueError('CONNECT counter is not a nonnegative actual integer')
            expected_trials = 2 if '-auto-' in case else 0
            expected_restore = int(case in CASES[:6] and not case.endswith('auto-local'))
            if value['comparison_trials'] != expected_trials or value['restore_launches'] != expected_restore:
                raise ValueError('CONNECT replaced original comparison or reran retained choice')
            if value['entry_layer']!=ENTRY_LAYERS[case] or value['entry_layer_auth']!=0:
                raise ValueError('CONNECT entry layer source/authentication changed')
            if ENTRY_LAYERS[case]=='off':
                if value['entry_layer_packets']!=0 or value['entry_layer_ciphertext']!=0:raise ValueError('Off borrowed native layer counters')
            elif value['entry_layer_packets']<=0 or value['entry_layer_ciphertext']<=0:
                raise ValueError('CONNECT original layered prefix omitted actual encrypted packets')
            if any(value[key]<=0 for key in ('launches','entry_raw_udp','entry_tcp','entry_proofs','middle_raw_tcp')):
                raise ValueError('CONNECT failed before its captured encrypted prefix/worker/proxy')
            if any(value[key]!=0 for key in ('middle_raw_udp','final_raw_udp','open_streams')):
                raise ValueError('CONNECT retained an open stream or acquired raw UDP authority')
            if case in ('http-wrong-auth','https-wrong-auth','https-tls-name'):
                expected_refusal='tls_refusals' if case=='https-tls-name' else 'auth_refusals'
                other_refusal='auth_refusals' if case=='https-tls-name' else 'tls_refusals'
                if value[expected_refusal]<=0 or value[other_refusal]!=0 or any(value[key]!=0 for key in ('middle_tcp','middle_public','final_proofs','dns')):
                    raise ValueError('CONNECT negative did not reach its original authentication boundary')
            else:
                if value['auth_refusals']!=0 or value['tls_refusals']!=0 or value['middle_tcp']<=0 or value['middle_public']<=0:
                    raise ValueError('CONNECT path lost authenticated public predecessor')
                if case=='http-wrong-public':
                    if value['final_proofs']!=0 or value['dns']!=0:raise ValueError('wrong public source acquired final proof')
                elif case=='https-wrong-final':
                    if value['final_raw_tcp']<=0 or value['final_tcp']!=0 or value['final_proofs']!=0 or value['dns']!=0:raise ValueError('wrong final key escaped original encrypted boundary')
                elif any(value[key]<=0 for key in ('final_raw_tcp','final_tcp','final_proofs','dns')):
                    raise ValueError('CONNECT omitted original final proof/selected DNS')
            observations.append(value)
        if 'LINUX_CONNECT_EXECUTION_RECEIPT' in line:
            match = re.fullmatch(r'\s+desktop_connect_execution_linux_tun_native_test.go:\d+: (LINUX_CONNECT_EXECUTION_RECEIPT .*)', line)
            if not match or not active or complete:
                raise ValueError('Imported execution receipt is outside its original running case')
            records.append(match[1])
    if records != [expected] or len(observations) != 1:
        raise ValueError('Imported execution lacks exact public, restoration and joined ownership receipt')



SOURCE_TESTS={
 'TestDesktopCONNECTTrioExecutionSelectionBounds':tuple(f'{protocol}/{mode}/{choice}' for protocol in ('http-connect','https-connect') for mode in ('wg','awg2-fast','awg2-strong') for choice in ('server','auto')),
 'TestDesktopCONNECTTrioExecutionSavedProfileRetainsSource':tuple(f'{protocol}/{choice}' for protocol in ('http-connect','https-connect') for choice in ('server','auto')),
}
def source_identity(core):
 core,native=BASE.checked_sources(core)
 required={**PROJECTOR.copies(),PEER_TARGET:(ROOT/PEER_TEMPLATE).read_bytes(),**{target:(ROOT/name).read_bytes() for name,target in PEER_HELPERS.items()}}
 for name,body in required.items():
  if (core/name).read_bytes()!=body:raise ValueError('Captured CONNECT generated source changed: '+name)
 return {'native':native,'fixture':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in (*SOURCES,*PROJECTOR.SOURCES)}}
def required_host(environment):
 if platform.system()!='Linux' or environment.get(FLAG)!='1' or 'HOMEVPN_MTU_BENCH_FAKE' in environment or environment.get('GOOS','linux')!='linux' or environment.get('CGO_ENABLED','1')!='1':raise ValueError('CONNECT execution requires opted-in real native Linux host')
 architecture={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
 if architecture is None or environment.get('GOARCH',architecture)!=architecture:raise ValueError('Unsupported or foreign native Linux architecture')
 return 'linux/'+architecture

def selected_compiler(go,environment,target):
 # Reuse the shipping Linux compiler capture. The separate Darwin race
 # selector deliberately refuses Linux and cannot authorize this fixture.
 compiler,captured,architecture=NODE.selected_compiler(go,ROOT,environment)
 if target!='linux/'+architecture or captured.get('GOOS')!='linux' or captured.get('GOARCH')!=architecture:
  raise ValueError('CONNECT execution compiler differs from its original native host')
 captured['CGO_ENABLED']='1'
 return compiler,captured

def namespace_test(binary,peer,bundle,image_sha256,peer_sha256,bundle_sha256,case):
 if case not in CASES:raise ValueError('Uncaptured CONNECT namespace case')
 if CHILD.image_identity(binary)[-1]!=image_sha256 or CHILD.image_identity(peer)[-1]!=peer_sha256:raise ValueError('Original CONNECT executable changed')
 bundle=Path(bundle)
 if not bundle.is_absolute() or bundle.is_symlink() or any(parent.is_symlink() for parent in bundle.parents):raise ValueError('Foreign native bundle path')
 receipt=bundle/'NATIVE-RUNTIME.json';info=receipt.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_mode&0o6022 or not 0<info.st_size<=32768 or hashlib.sha256(receipt.read_bytes()).hexdigest()!=bundle_sha256:raise ValueError('Changed complete native bundle receipt')
 current,mount=os.stat('/proc/self/ns/net'),os.stat('/proc/self/ns/mnt')
 values=dict(zip(BASE.NAMESPACE_ENVIRONMENT,(f'{current.st_dev}:{current.st_ino}',str(bundle),bundle_sha256,str(peer),peer_sha256,'','',f'{mount.st_dev}:{mount.st_ino}')))
 values['ROUTERVPN_CONNECT_EXECUTION_SOURCE']=str(ROOT)
 previous={key:os.environ.get(key) for key in values};os.environ.update(values)
 try:return GUARD.namespace_test(Path(binary),'CONNECTExecution/'+case,image_sha256)
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
 with tempfile.TemporaryDirectory(prefix='routervpn-linux-connect-execution-') as temporary:
  work=Path(temporary).resolve();core=Path(source).resolve() if source else prepared_source(work,captured,compiler)
  before=source_identity(core)
  endpoint_controls=load('test_linux_connect_execution_host_runner').execute_endpoint_controls(compiler,captured)
  controller,peer=work/'controller.test',work/'peer.test'
  for command,cwd in (([str(compiler),'test','-race','-c','-mod=readonly','-tags=routervpn_controller_privileged','-o',str(controller),'./cmd/client'],ROOT),([str(compiler),'test','-race','-c','-mod=readonly','-tags='+','.join(NODE.TAGS),'-ldflags=-checklinkname=0','-o',str(peer),'./protocol/routervpnamnezia'],core)):
   subprocess.run(command,cwd=cwd,env=captured,check=True,timeout=300)
  for image in (controller,peer):
   version=subprocess.run([str(compiler),'version',str(image)],cwd=ROOT,env=captured,check=True,timeout=30,capture_output=True,text=True)
   if version.stdout.strip()!=str(image)+': '+BUILD.TOOLCHAIN:raise ValueError('CONNECT execution image changed its captured native compiler')
  images={str(path):CHILD.image_identity(path) for path in (controller,peer)};source_outputs={}
  for root,leaves in SOURCE_TESTS.items():
   result=subprocess.run([str(controller),'-test.v','-test.count=1','-test.timeout=120s','-test.run=^'+root+'$'],cwd=ROOT,env=captured,check=True,timeout=130,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
   NODE.require_native_verdicts(result.stdout,(root,*(root+'/'+leaf for leaf in leaves)),'CONNECT original product source')
   print(result.stdout,end='',flush=True);source_outputs[root]=hashlib.sha256(result.stdout.encode()).hexdigest()
  outputs={}
  for case in CASES:
   if source_identity(core)!=before or BUILD.digest()!=policy or any(CHILD.image_identity(Path(path))!=identity for path,identity in images.items()):raise ValueError('Original source/image changed before native admission')
   command=[sys.executable,str(Path(__file__).resolve()),'--namespace-test-binary',str(controller),'--peer-binary',str(peer),'--bundle',str(bundle),'--namespace-test-sha256',images[str(controller)][-1],'--peer-sha256',images[str(peer)][-1],'--bundle-sha256',bundle_hash,'--case',case]
   if sudo:command=[sudo,'-n','--',*command]
   output=GUARD.UID.run(command,cwd=ROOT,env=captured,timeout=265,sudo=sudo)
   print(output,end='',flush=True);check_verdict(output,case);outputs[case]=hashlib.sha256(output.encode()).hexdigest()
  if source_identity(core)!=before or BUILD.digest()!=policy or REPOSITORY.repository_identity(required_commit)!=repository or BASE.bundle_identity(bundle,target,captured)!=(original,payloads) or any(CHILD.image_identity(Path(path))!=identity for path,identity in images.items()):raise ValueError('Final original source/image/bundle identity changed')
  result=dict(schema=1,gate='linux-connect-trio-execution',target=target,native=True,repository=repository,source_sha256=policy,bundle_sha256=bundle_hash,validation_toolchain=BUILD.TOOLCHAIN,images=images,sources=before,cases=list(CASES),completed=list(outputs),outputs=outputs,source_outputs=source_outputs,endpoint_controls=endpoint_controls,scope='original-public-server-compare-protected-controller-tun-nft-dns',administration='fixture-authenticated-private-http',worker_launch='fixture-direct-original-image',remote_private_deployment=False)
 CHILD.publish_receipt(receipt_path,result,work)
 print('Native Linux CONNECT execution acceptance: '+json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
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
