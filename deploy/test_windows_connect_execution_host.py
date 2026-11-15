#!/usr/bin/env python3
"""Separate installed Windows CONNECT Server/Compare acceptance, after native-runtimes.

This does not bypass or repeat the original prefix8/SOCKS11/LocalCONNECT18 gates.
Actual protected controller, inherited typed child, WFP/TUN and encrypted relay
are required. Private HTTP administration and direct counterparty worker launch
are explicit fixture adapters. The worker is a separately captured source build with only the explicit Windows
private-path adapter; the delivered bundle is preserved.
"""
from pathlib import Path
import argparse,ctypes,hashlib,importlib.util,json,os,platform,re,shutil
ROOT=Path(__file__).resolve().parents[1]
def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'deploy'/filename)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
ORIGINAL=load('windows_execution_local','test_windows_connect_node_chain_host.py')
SCOPE=load('windows_execution_projection','windows_connect_execution_overlay.py')
BUILD,CONTROLLER,NODE=ORIGINAL.BUILD,ORIGINAL.CONTROLLER,ORIGINAL.NODE
IDENTITY=load('windows_execution_identity','focused_source_identity.py')
WORKER=load('windows_execution_worker_controls','windows_connect_execution_worker_controls.py')
FLAG='ROUTERVPN_WINDOWS_CONNECT_EXECUTION_NATIVE'
TEST='TestWindowsInstalledCONNECTExecution'
CASES = ('http-wg-server', 'http-awg-fast-auto-local', 'http-awg-strong-auto-server', 'https-awg-strong-server', 'https-wg-auto-local', 'https-awg-fast-auto-server', 'http-wrong-auth', 'https-wrong-auth', 'https-tls-name', 'http-wrong-public', 'https-wrong-final', 'https-failed-dns', 'http-replaced-source', 'https-held-cleanup')
ENTRY_LAYERS = {case: ('aes-256-gcm' if case in ('http-awg-fast-auto-local','https-awg-strong-server') else 'aes-256-gcm+xor-whitening' if case in ('http-awg-strong-auto-server','https-wg-auto-local') else 'off') for case in CASES}

def receipt(case):
    if case not in CASES:
        raise ValueError('Unknown CONNECT execution case')
    auto = '-auto-' in case
    negative = case in CASES[6:12]
    restored = case in CASES[:6]
    return ('WINDOWS_CONNECT_EXECUTION_RECEIPT case='+case+' requested='+('auto' if auto else 'server')+
            ' winner='+('local' if case.endswith('-auto-local') else 'server')+
            ' negative='+str(negative).lower()+' restored='+str(restored).lower()+
            ' cleanup_retry='+str(case=='https-held-cleanup').lower()+
            ' native_joined=true relay_joined=true aliases_retired=true')


def check_verdict(output, case):
    if case not in CASES:
        raise ValueError('Unknown imported execution case')
    required=(TEST,TEST+'/'+case)
    runs=re.findall(r'^\s*=== RUN\s+(\S+)\s*$',output,re.M)
    passes=re.findall(r'^\s*--- PASS:\s+(\S+)\s+\([0-9.]+s\)$',output,re.M)
    if sorted(runs)!=sorted(required) or sorted(passes)!=sorted(required) or len(re.findall(r'^PASS\s*$',output,re.M))!=1 or any(token in output for token in ('--- FAIL:','--- SKIP:','WARNING: DATA RACE','panic:','fatal error:')):
        raise ValueError('Windows execution lost exact actual native verdicts')
    lines = output.splitlines()
    expected = receipt(case)
    records, observations = [], []
    active, complete = False, False
    for line in lines:
        if line == '=== RUN   '+TEST+'/'+case:
            active = True
        if re.match(r'\s*--- PASS: ', line):
            complete = True
        if 'WINDOWS_CONNECT_EXECUTION_COUNTERS' in line:
            match = re.fullmatch(r'\s+desktop_connect_execution_windows_native_test.go:\d+: WINDOWS_CONNECT_EXECUTION_COUNTERS (.*)', line)
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
                             'middle_raw_udp','final_raw_udp','auth_refusals','tls_refusals','open_streams','entry_layer','entry_layer_packets','entry_layer_ciphertext','entry_layer_auth','restore_launches','comparison_trials','native_joined','journal_settled','wfp_absent','tun_absent','aliases_removed'}
            if not isinstance(value,dict) or set(value)!=expected_keys or value['case']!=case:
                raise ValueError('CONNECT native counters changed original identity')
            flags={'native_joined','journal_settled','wfp_absent','tun_absent','aliases_removed'}
            if any(value[key] is not True for key in flags):
                raise ValueError('Windows execution omitted actual journal/WFP/TUN/alias retirement')
            for key in expected_keys-{'case','entry_layer'}-flags:
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
        if 'WINDOWS_CONNECT_EXECUTION_RECEIPT' in line:
            match = re.fullmatch(r'\s+desktop_connect_execution_windows_native_test.go:\d+: (WINDOWS_CONNECT_EXECUTION_RECEIPT .*)', line)
            if not match or not active or complete:
                raise ValueError('Imported execution receipt is outside its original running case')
            records.append(match[1])
    if records != [expected] or len(observations) != 1:
        raise ValueError('Imported execution lacks exact public, restoration and joined ownership receipt')


OWNED=(
 'cmd/client/desktop_connect_execution_windows_native_test.go',
 'cmd/client/desktop_connect_execution_windows_controller_test.go',
 'cmd/client/desktop_connect_execution_windows_observation_test.go',
 'cmd/client/desktop_connect_execution_windows_launcher_test.go',
 'cmd/client/desktop_connect_execution_windows_peer_test.go',
 'cmd/client/desktop_connect_execution_windows_aliases_test.go',
 'cmd/client/ordered_candidate_prefix_windows_native_test.go',
 'deploy/test_windows_connect_execution_host.py',
 'deploy/test_windows_connect_execution_host_runner.py',
 'deploy/windows_connect_execution_overlay.py',
 'deploy/windows_connect_execution_worker_controls.py',
 *SCOPE.EXTRA,*SCOPE.PLATFORM_FILES,*SCOPE.PRIVATE,*SCOPE.WORKER,*SCOPE.PROJECTOR.SOURCES,
 'mobile/desktop/node_imported_connect_entry_test.go.tmpl',
 'deploy/prepare-desktop-imported-execution-test.py',
 'cmd/client/desktop_node_chain_connect_execution_product_test.go',
 'cmd/client/desktop_node_chain_connect_execution_profile_test.go')
SOURCE_TESTS={
 'TestWindowsCONNECTExecutionAliasOriginalCreation':('original','missing-original-luid','missing-original-index','missing-original-created','foreign-luid','foreign-index','foreign-address','recreated-address','changed-prefix','changed-skip','changed-prefix-origin','changed-suffix-origin'),
 'TestDesktopCONNECTTrioExecutionSelectionBounds':tuple(f'{protocol}/{mode}/{choice}' for protocol in ('http-connect','https-connect') for mode in ('wg','awg2-fast','awg2-strong') for choice in ('server','auto')),
 'TestDesktopCONNECTTrioExecutionSavedProfileRetainsSource':tuple(f'{protocol}/{choice}' for protocol in ('http-connect','https-connect') for choice in ('server','auto'))}

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def case_inventory():
    source=(ROOT/'cmd/client/desktop_connect_execution_windows_controller_test.go').read_text()
    found=re.search(r'var windowsCONNECTExecutionCases = \[\]string\{([^}]+)\}',source)
    if not found or tuple(re.findall(r'"([a-z0-9-]+)"',found[1]))!=CASES or re.sub(r'"[a-z0-9-]+"|\s|,','',found[1]):
        raise ValueError('Windows execution lost exact fourteen native cases')
    files={name:(ROOT/name).read_text() for name in OWNED if name.startswith('cmd/client/desktop_connect_execution_windows_')}
    joined='\n'.join(files.values())
    for boundary in ('a.nativeMultihopConnect(w, r)','a.speedLabSuspendPrevious(snapshot, false)',
                     'a.speedLabRestoreTemporary(snapshot)','original.closeGate <- struct{}{}',
                     'retained != owner','process.JournalOutcome()',
                     'mobiletor.ProbeDesktopWindowsProtectionAbsent(ctx)',
                     'peer.aliases.Close(ctx, join)','process.attempt.connectChain != s.execution.original.connectPolicy'):
        if joined.count(boundary)!=1:raise ValueError('Windows execution lost original boundary: '+boundary)
    return CASES

def sources(core):
    core,records=ORIGINAL.sources(core)
    for name in OWNED:
        path=ROOT/name
        if path.is_symlink() or not path.is_file():raise ValueError('Windows execution original source missing: '+name)
        records['execution/'+name]=sha(path)
    for name,raw in SCOPE.peer_sources().items():records['execution-peer/'+name]=hashlib.sha256(raw).hexdigest()
    for name,raw in SCOPE.worker_sources(core).items():records['execution-worker/'+name]=hashlib.sha256(raw).hexdigest()
    for name,raw in WORKER.sources().items():records['execution-worker-control/'+name]=hashlib.sha256(raw).hexdigest()
    return core,records

def required_host(environment):
    if platform.system()!='Windows' or environment.get(FLAG)!='1' or not ctypes.windll.shell32.IsUserAnAdmin() or 'HOMEVPN_MTU_BENCH_FAKE' in environment:
        raise ValueError('Windows execution requires its opted-in disposable elevated native host')

def prepared_source(work,captured,compiler,owner):
    core,xray=work/'core',work/'xray'
    with owner.preparation():
        BUILD.checkout(core,'https://github.com/SagerNet/sing-box.git',BUILD.PIN)
        BUILD.checkout(xray,'https://github.com/XTLS/Xray-core.git',BUILD.POLICY.XRAY.XRAY_PIN)
        BUILD.pristine(core,BUILD.PIN);BUILD.pristine(xray,BUILD.POLICY.XRAY.XRAY_PIN)
        BUILD.POLICY.prepare_native(core,xray);BUILD.PERFORMANCE.prepare(core);BUILD.OPENVPN.prepare(core)
        BUILD.EXTERNAL.prepare(core,env=captured);BUILD.BUFFERS.prepare(core)
    status,output=owner.run([compiler,'mod','tidy'],cwd=core,env=captured,timeout=300)
    if status:raise ValueError('Original Windows prepared dependencies failed:\n'+output[-16384:])
    return core

def source_verdict(output):
    required=[name for root,leaves in SOURCE_TESTS.items() for name in (root,*(root+'/'+leaf for leaf in leaves))]
    runs=re.findall(r'^\s*=== RUN\s+(\S+)\s*$',output,re.M)
    passes=re.findall(r'^\s*--- PASS:\s+(\S+)\s+\([0-9.]+s\)$',output,re.M)
    if sorted(runs)!=sorted(required) or sorted(passes)!=sorted(required) or len(re.findall(r'^PASS\s*$',output,re.M))!=1 or any(token in output for token in ('--- FAIL:','--- SKIP:','WARNING: DATA RACE','panic:','fatal error:')):
        raise ValueError('Windows execution lost actual public and alias-ownership source verdicts')
    return required

WORKER_CASES=('private','original-posix-modes','public-input','null-input','unknown-input','public-code-writer','public-code-reader','hardlink-input','replaced-input','worker-environment')

def worker_verdict(output):
    root='TestRouterVPNWindowsExecutionPrivateWorker'
    required=[root,*(root+'/'+case for case in WORKER_CASES)]
    runs=re.findall(r'^\s*=== RUN\s+(\S+)\s*$',output,re.M)
    passes=re.findall(r'^\s*--- PASS:\s+(\S+)\s+\([0-9.]+s\)$',output,re.M)
    if sorted(runs)!=sorted(required) or sorted(passes)!=sorted(required) or len(re.findall(r'^PASS\s*$',output,re.M))!=1 or any(token in output for token in ('--- FAIL:','--- SKIP:','WARNING: DATA RACE','panic:','fatal error:')):
        raise ValueError('Windows worker lost actual private permission/source controls')
    return required


def execute(bundle,source=None,go='go',environment=None,*,required_commit=None,receipt_file=None):
    environment=dict(os.environ if environment is None else environment)
    required_host(environment)
    if not isinstance(required_commit,str) or not re.fullmatch('[0-9a-f]{40}',required_commit):raise ValueError('Windows execution requires exact published source')
    IDENTITY.original_checkout(ROOT,required_commit)
    case_inventory()
    compiler,captured,architecture=CONTROLLER.NATIVE.selected_compiler(go,ROOT,environment)
    if architecture not in ('amd64','arm64'):raise ValueError('Windows execution requires native AMD64/ARM64')
    captured['CGO_ENABLED']='1' if architecture=='amd64' else '0'
    target='windows/'+architecture
    owner=ORIGINAL.COMMAND_OWNER.MAXCommandOwner()
    with ORIGINAL.owned_bindings(ORIGINAL,owner):
        result=execute_owned(Path(bundle).resolve(),source,compiler,captured,target,owner,required_commit)
    if not owner.retired:raise ValueError('Windows native command Job did not join')
    result['command_job_joined']=True
    IDENTITY.original_checkout(ROOT,required_commit)
    if receipt_file is not None:
        path=Path(receipt_file);path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('Native Windows CONNECT execution acceptance: '+json.dumps(result,sort_keys=True),flush=True)
    return result

def execute_owned(bundle,source,compiler,captured,target,owner,commit):
    original=BUILD.reuse(bundle,target,env=captured)
    original_manifest=sha(bundle/'NATIVE-RUNTIME.json');policy=BUILD.digest()
    if original['policy_sha256']!=policy:raise ValueError('Original Windows bundle source differs')
    race=['-race'] if target=='windows/amd64' else []
    with owner.workspace(prefix='routervpn-windows-connect-execution-') as temporary:
        work=Path(temporary).resolve()
        core=Path(source).resolve() if source is not None else prepared_source(work,captured,compiler,owner)
        core,before=sources(core)
        installed=work/'installed';native=installed/'runtime/native';native.mkdir(parents=True)
        (installed/'client').mkdir();shutil.copyfile(ROOT/'client/Private-RouterVPN-Protection.ps1',installed/'client/Private-RouterVPN-Protection.ps1')
        # This separate test worker uses original protocol/IPC bodies and the
        # explicit Windows private-path projection. It must not inherit the
        # native child's test-only WFP AppID scope.
        worker_bundle=work/'original-counterparty';worker_bundle.mkdir()
        for name in original['files']:
            shutil.copyfile(bundle/name,native/name);shutil.copyfile(bundle/name,worker_bundle/name)
        shutil.copyfile(bundle/'NATIVE-RUNTIME.json',worker_bundle/'NATIVE-RUNTIME.json')
        worker=worker_bundle/BUILD.binary_name(target)
        if BUILD.reuse(worker_bundle,target,env=captured)!=original:raise ValueError('Original independent worker copy changed')
        child=native/BUILD.binary_name(target)
        native_scope,native_records=SCOPE.overlay(core/'routervpn/mobiletor',child,work/'native-scope')
        app_scope,app_records=SCOPE.overlay(ROOT/'internal/mobiletor',child,work/'controller-scope')
        if native_records!=app_records:raise ValueError('Original controller/native WFP scope diverged')
        loader=core/'cmd/sing-box/routervpn_native_library.go';raw=(ROOT/'mobile/desktop/native_library.go.tmpl').read_bytes()
        if loader.exists():
            if loader.is_symlink() or loader.read_bytes()!=raw:raise ValueError('Original native library owner changed')
        else:
            addition=work/'routervpn_native_library.go';addition.write_bytes(raw)
            overlay=work/'loader.json';overlay.write_text(json.dumps({'Replace':{str(loader):str(addition)}}))
            native_scope=ORIGINAL.merge_overlays([native_scope,overlay],work/'native-overlay.json')
        peer_overlay=SCOPE.peer_overlay(core/'protocol/routervpnamnezia',work/'peer-source')
        worker_overlay=SCOPE.worker_overlay(core,work/'worker-source')
        native_tags=(*BUILD.tags(target),SCOPE.TAG)
        flags=('-checklinkname=0 -X github.com/sagernet/sing-box/constant.Version='+BUILD.marker(original['policy_sha256'])+
               ' -X main.routerVPNCronetSHA='+original['files']['libcronet.dll']['sha256']+
               ' -X main.routerVPNCronetBytes='+str(original['files']['libcronet.dll']['size']))
        peer,controller=work/'execution-peer.test.exe',work/'execution-controller.test.exe'
        commands=(
          ([compiler,'build','-p=1','-mod=readonly','-trimpath','-buildvcs=false','-overlay='+str(native_scope),'-tags='+','.join(native_tags),'-ldflags='+flags,'-o',child,'./cmd/sing-box'],core),
          ([compiler,'build','-p=1','-mod=readonly','-trimpath','-buildvcs=false','-overlay='+str(worker_overlay),'-tags='+','.join(native_tags),'-ldflags='+flags,'-o',worker,'./cmd/sing-box'],core),
          ([compiler,'test','-c','-p=1','-mod=readonly',*race,'-overlay='+str(peer_overlay),'-tags='+','.join((*NODE.TAGS,SCOPE.TAG)),'-ldflags=-checklinkname=0','-o',peer,'./protocol/routervpnamnezia'],core),
          ([compiler,'test','-c','-p=1','-mod=readonly',*race,'-overlay='+str(app_scope),'-tags='+SCOPE.TAG,'-o',controller,'./cmd/client'],ROOT))
        for command,cwd in commands:
            status,output=owner.run(command,cwd=cwd,env=captured,timeout=600)
            if status:raise ValueError('Original Windows execution image compilation failed:\n'+output[-32768:])
        scoped=json.loads(json.dumps(original));payload=dict(size=child.stat().st_size,sha256=sha(child));scoped.update(payload);scoped['files'][child.name]=payload
        (native/'NATIVE-RUNTIME.json').write_text(json.dumps(scoped,sort_keys=True,indent=2)+'\n');BUILD.reuse(native,target,env=captured)
        worker_manifest=json.loads(json.dumps(original));payload=dict(size=worker.stat().st_size,sha256=sha(worker));worker_manifest.update(payload);worker_manifest['files'][worker.name]=payload
        (worker_bundle/'NATIVE-RUNTIME.json').write_text(json.dumps(worker_manifest,sort_keys=True,indent=2)+'\n');BUILD.reuse(worker_bundle,target,env=captured)
        worker_sha=sha(worker)
        for name in ('RouterVPN.exe','router-vpn-client.exe'):shutil.copyfile(controller,installed/name)
        paths=dict(controller=controller,peer=peer,scoped_engine=child,worker=worker,launcher=installed/'RouterVPN.exe',protected_controller=installed/'router-vpn-client.exe')
        images={key:sha(path) for key,path in paths.items()}
        if sources(core)[1]!=before or BUILD.digest()!=policy:raise ValueError('Captured Windows source changed during build')
        status,output=owner.run([controller,'-test.v','-test.count=1','-test.timeout=90s','-test.run=^('+'|'.join(SOURCE_TESTS)+')$'],cwd=ROOT,env=captured,timeout=100)
        if status:raise ValueError('Actual Windows public source controls failed:\n'+output[-32768:])
        source_records=source_verdict(output);source_log=hashlib.sha256(output.encode()).hexdigest()
        status,output=owner.run([peer,'-test.v','-test.count=1','-test.timeout=90s','-test.run=^TestRouterVPNWindowsExecutionPrivateWorker$'],cwd=ROOT,env=captured,timeout=100)
        print(output,end='' if output.endswith('\n') else '\n',flush=True)
        if status:raise ValueError('Actual Windows private worker controls failed:\n'+output[-32768:])
        worker_records=worker_verdict(output);worker_log=hashlib.sha256(output.encode()).hexdigest()
        worker_controls=WORKER.execute(compiler,captured,target,owner)
        results=[]
        child_env=dict(captured,ROUTERVPN_WINDOWS_CONNECT_EXECUTION_NATIVE='1',ROUTERVPN_WINDOWS_PREFIX_PEER=str(peer),ROUTERVPN_WINDOWS_CONNECT_EXECUTION_WORKER=str(worker),ROUTERVPN_WINDOWS_CONNECT_EXECUTION_WORKER_SHA256=worker_sha)
        for case in CASES:
            status,output=owner.run([installed/'RouterVPN.exe','-test.v','-test.count=1','-test.timeout=240s','-test.run=^'+TEST+'$','--',installed,case],cwd=ROOT,env=child_env,timeout=250)
            print(output,end='' if output.endswith('\n') else '\n',flush=True)
            if status:raise ValueError('Actual Windows CONNECT execution failed: '+case+'\n'+output[-65536:])
            check_verdict(output,case)
            results.append(dict(case=case,output_sha256=hashlib.sha256(output.encode()).hexdigest()))
            if images!={key:sha(path) for key,path in paths.items()} or sources(core)[1]!=before:raise ValueError('Original Windows source/images changed during native acceptance')
        if BUILD.reuse(bundle,target,env=captured)!=original or sha(bundle/'NATIVE-RUNTIME.json')!=original_manifest or BUILD.reuse(worker_bundle,target,env=captured)!=worker_manifest or BUILD.digest()!=policy:raise ValueError('Original delivered bundle or independent worker changed')
        return dict(schema=1,scope='windows-connect-trio-execution',native=True,target=target,commit=commit,source_sha256=policy,bundle_sha256=original_manifest,cases=list(CASES),results=results,images=images,sources=before,scope_sources=native_records,public_source_records=source_records,public_source_output_sha256=source_log,unmodified_shipping_image=False,test_scope='captured-native-child-app-id',worker_scope='separately-captured-windows-private-path-projection',worker_private_records=worker_records,worker_causal_controls=worker_controls,worker_private_output_sha256=worker_log,native_joined=True,journal_settled=True,wfp_absent=True,tun_absent=True,aliases_retired=True,remote_connect_streams_after_retirement=0,public_route='/api/multihop/connect',fixture_boundaries=['private authenticated HTTP administration','direct original counterparty worker launch','Windows private-runtime DACL and captured machine environment projection'])

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True);parser.add_argument('--source',type=Path)
    parser.add_argument('--go',default='go');parser.add_argument('--require-commit',required=True);parser.add_argument('--receipt',type=Path,required=True)
    options=parser.parse_args();execute(options.bundle,options.source,options.go,required_commit=options.require_commit,receipt_file=options.receipt)
