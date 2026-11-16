#!/usr/bin/env python3
"""Require the actual schema5 OpenVPN Server suffix with no remote packet prefix.

Private source export witnesses independent provider identities only. Native
acceptance uses the shipping worker in fresh namespaces, with a test-owned
public /32 and the original concrete endpoint. Entry leases/client UI are separate.
"""
from pathlib import Path
import argparse
import ast
import hashlib
import importlib.util
import json
import os
import platform
import re
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'deploy'/f'{name}.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
BASE=load('test_server_node_chain_encrypted')
CONNECT=load('test_server_node_chain_connect_encrypted')
TEMPLATE='mobile/server_chain_acceptance/openvpn_linux_test.go.tmpl'
TARGET='cmd/sing-box/routervpn_server_chain_openvpn_linux_test.go'
PEER_TEMPLATE='mobile/desktop/node_chain_openvpn_server_direct_peer_test.go.tmpl'
OWNER='routervpn-server-openvpn-encrypted-test-source.json'
SOURCE='TestServerChainOpenVPNDirectEncryptedSource'
NATIVE='TestServerChainOpenVPNDirectEncryptedNative'
PROVIDER='TestRouterVPNDesktopOpenVPNDirectSourceProfiles'
NETWORKS=('tcp','udp')
LAYERS=('off','aes-256-gcm','aes-256-gcm+xor-whitening')
CASES=tuple(n+'/'+l+'/original' for n in NETWORKS for l in LAYERS)+tuple(n+'/off/'+f for f in ('wrong-server-password','wrong-final-key','failed-selected-dns','joined-active-udp') for n in NETWORKS)
FIELDS={'case','capture_sha256','source_sha256','ready','selected_dns','provider_tcp','provider_udp','auth_refusals','streams','packets','unused_prefix_packets','unused_prefix_proofs','retired','worker_joined','peer_joined'}
ALIAS=('netns','exec','rvpn-peer','ip','addr','add','203.0.113.24/32','dev','lo')

def unique_object(rows):
    result={}
    for key,value in rows:
        if key in result:raise ValueError('Duplicate OpenVPN receipt field')
        result[key]=value
    return result

def check_verdict(output,case=None,*,source_only=False,provider=False):
    if source_only and provider or (source_only or provider) and case is not None or not source_only and not provider and case not in CASES:raise ValueError('Uncaptured OpenVPN selection')
    root=PROVIDER if provider else SOURCE if source_only else NATIVE
    names=NETWORKS if provider else CASES if source_only else (case,)
    expected={root,*(root+'/'+name for name in names)}
    runs=set();passes=set();receipts=[];ended=False;terminal=False
    for line in output.splitlines():
        text=line.strip()
        if not text:continue
        run=re.fullmatch(r'=== RUN\s+(\S+)',text)
        passed=re.fullmatch(r'--- PASS: (\S+) \([0-9.]+s\)',text)
        receipt=re.fullmatch(r'\S+\.go:[0-9]+: OPENVPN_DIRECT_SERVER_RECEIPT (.+)',text)
        if run:
            name=run[1]
            if ended or terminal or name not in expected or name in runs or name!=root and root not in runs:raise ValueError('Foreign/late OpenVPN run')
            runs.add(name)
        elif passed:
            name=passed[1]
            if terminal or name not in runs or name in passes:raise ValueError('Unmatched OpenVPN pass')
            if name==root:
                if runs!=expected or passes or len(receipts)!=(0 if source_only or provider else 1):raise ValueError('Premature OpenVPN root verdict')
                ended=True
            elif not ended:raise ValueError('OpenVPN leaf before parent verdict')
            passes.add(name)
        elif receipt:
            if source_only or provider or ended or terminal or root+'/'+case not in runs or receipts:raise ValueError('Foreign/late OpenVPN receipt')
            value=json.loads(receipt[1],object_pairs_hook=unique_object)
            if type(value)is not dict or set(value)!=FIELDS or value['case']!=case:raise ValueError('OpenVPN receipt selection changed')
            network,layer,fault=case.split('/');ready=fault in ('original','joined-active-udp')
            if any(value[k] is not True for k in ('retired','worker_joined','peer_joined')) or value['ready'] is not ready or value['selected_dns'] is not ready:raise ValueError('OpenVPN original readiness/join missing')
            if any(type(value[k])is not str or not re.fullmatch('[0-9a-f]{64}',value[k]) for k in ('capture_sha256','source_sha256')):raise ValueError('OpenVPN original source missing')
            counters=('provider_tcp','provider_udp','auth_refusals','streams','packets','unused_prefix_packets','unused_prefix_proofs')
            if any(type(value[k])is not int or value[k]<0 for k in counters):raise ValueError('OpenVPN malformed counters')
            if value['unused_prefix_packets'] or value['unused_prefix_proofs'] or value['provider_'+network]<=0 or value['provider_'+('udp' if network=='tcp' else 'tcp')]!=0:raise ValueError('OpenVPN original physical ownership changed')
            if fault=='wrong-server-password' and (value['auth_refusals']<=0 or value['streams'] or value['packets']):raise ValueError('OpenVPN wrong credentials delivered data')
            if ready and (value['auth_refusals'] or min(value['streams'],value['packets'])<=0):raise ValueError('OpenVPN authenticated packet/stream observation missing')
            receipts.append(value)
        elif text=='PASS':
            if terminal or not ended or passes!=expected:raise ValueError('Empty/early OpenVPN success')
            terminal=True
        else:raise ValueError('Unexpected OpenVPN output')
    if not terminal or runs!=expected or passes!=expected or len(receipts)!=(0 if source_only or provider else 1):raise ValueError('Missing exact OpenVPN inventory')
    return receipts[0] if receipts else list(names)

def install_fixture(core):
    # Retain the original pinned-core/target ownership checks verbatim through
    # the existing installer, changing only this module's explicit constants.
    core=Path(core)
    if core.is_symlink() or BASE.subprocess.check_output(['git','-C',str(core),'rev-parse','HEAD'],text=True).strip()!=BASE.BUILD.PIN:raise ValueError('OpenVPN requires original pinned core')
    source,target,record=ROOT/TEMPLATE,core/TARGET,core/OWNER
    if any(p.is_symlink() for p in (source,target,record,target.parent)):raise ValueError('Linked OpenVPN source')
    raw=source.read_bytes()
    if not raw.startswith(b'//go:build linux && !android && routervpn_server_chain_acceptance\n\npackage main\n'):raise ValueError('OpenVPN fixture target changed')
    if record.exists():
        old=json.loads(record.read_text())
        if old.get('schema')!=1 or old.get('target')!=TARGET or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest()!=old.get('sha256'):raise ValueError('Changed original OpenVPN fixture')
    elif target.exists() and target.read_bytes()!=raw:raise ValueError('Unowned OpenVPN fixture')
    target.write_bytes(raw);record.write_text(json.dumps({'schema':1,'target':TARGET,'sha256':hashlib.sha256(raw).hexdigest()},sort_keys=True)+'\n')

def checked_sources(core):
    core,records=CONNECT.checked_sources(core)
    for name in (TEMPLATE,PEER_TEMPLATE,'mobile/desktop/node_external_openvpn_installed_test.go.tmpl','deploy/test_server_node_chain_openvpn_encrypted.py','deploy/test_server_node_chain_openvpn_encrypted_runner.py'):
        p=ROOT/name
        if p.is_symlink() or not p.is_file():raise ValueError('OpenVPN source missing/linked')
        records['openvpn/'+name]=hashlib.sha256(p.read_bytes()).hexdigest()
    for source,target in ((TEMPLATE,TARGET),(PEER_TEMPLATE,BASE.NODE.PREP.PEER_TEMPLATES[Path(PEER_TEMPLATE).name])):
        if (core/target).is_symlink() or (core/target).read_bytes()!=(ROOT/source).read_bytes():raise ValueError('Original generated OpenVPN dependency changed')
    return core,records

def namespace_program(base_sha):
    tree=ast.parse(BASE.namespace_program(base_sha));changed=set()
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ('CASES','NATIVE'):
            key=node.targets[0].id;node.value=ast.parse(repr(CASES if key=='CASES' else NATIVE),mode='eval').body;changed.add(key)
    inside=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='inside_namespace')
    assignments=[n for n in ast.walk(inside) if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='commands']
    if changed!={'CASES','NATIVE'} or len(assignments)!=1 or not isinstance(assignments[0].value,ast.Tuple):raise ValueError('Original namespace program changed')
    assignments[0].value.elts.append(ast.parse(repr(ALIAS),mode='eval').body)
    return ast.unparse(ast.fix_missing_locations(tree))

def profile_sources(directory):
    if directory.is_symlink() or set(p.name for p in directory.iterdir())!={n+'.json' for n in NETWORKS}:raise ValueError('Uncaptured private provider exports')
    result={}
    for n in NETWORKS:
        p=directory/(n+'.json');s=p.lstat()
        if p.is_symlink() or not p.is_file() or s.st_mode&0o777!=0o600 or not 0<s.st_size<=1<<20:raise ValueError('Private provider export ownership changed')
        result[n]=hashlib.sha256(p.read_bytes()).hexdigest()
    return result

def execute(core,go='go',*,env=None,receipt=None,compile_only=False):
    if platform.system()!='Linux':raise ValueError('OpenVPN Server acceptance requires Linux')
    captured=dict(os.environ if env is None else env,GOWORK='off')
    if captured.get('GOOS','linux')!='linux' or captured.get('CGO_ENABLED','1')!='1':raise ValueError('OpenVPN forbids cross-host/non-race acceptance')
    captured['CGO_ENABLED']='1'
    BASE.install_fixture(core);BASE.install_imported_fixture(core);CONNECT.install_fixture(core);install_fixture(core)
    core,before=checked_sources(core);compiler,captured=BASE.UID.compiler_toolchain(core,go,captured)
    architecture=BASE.run([compiler,'env','GOARCH'],cwd=core,env=captured).strip()
    if architecture not in ('amd64','arm64'):raise ValueError('Unsupported native architecture')
    if receipt and (compile_only or Path(receipt).exists() or Path(receipt).is_symlink() or not Path(receipt).parent.is_dir()):raise ValueError('OpenVPN acceptance receipt requires unused owned path')
    with tempfile.TemporaryDirectory(prefix='routervpn-openvpn-direct-server-') as temporary:
        workspace=Path(temporary).resolve();workspace.chmod(0o755)
        profiles=workspace/'private-profiles';profiles.mkdir(mode=0o700)
        driver,peer,worker=workspace/'driver.test',workspace/'peer.test',workspace/'sing-box'
        tags=tuple(BASE.TAGS)+(() if 'with_openvpn' in BASE.TAGS else ('with_openvpn',))
        common=['-race','-mod=readonly','-p=1','-tags='+','.join(tags),'-ldflags=-checklinkname=0']
        BASE.run([compiler,'build',*common,'-o',worker,'./cmd/sing-box'],cwd=core,env=captured,timeout=600)
        BASE.run([compiler,'test','-c',*common,'-o',peer,'./protocol/routervpnamnezia'],cwd=core,env=captured,timeout=600)
        flags=[v+',routervpn_server_chain_acceptance' if v.startswith('-tags=') else v for v in common]
        BASE.run([compiler,'test','-c',*flags,'-o',driver,'./cmd/sing-box'],cwd=core,env=captured,timeout=600)
        images={role:BASE.image_identity(path) for role,path in (('driver',driver),('peer',peer),('worker',worker))}
        if checked_sources(core)[1]!=before:raise ValueError('OpenVPN source changed during compilation')
        source_env=dict(captured,ROUTERVPN_OPENVPN_DIRECT_PROFILES=str(profiles))
        provider=BASE.run([peer,'-test.run=^'+PROVIDER+'$','-test.v','-test.count=1','-test.timeout=30s'],cwd=core,env=source_env,timeout=45)
        print(provider,end='',flush=True);check_verdict(provider,provider=True);profile_hashes=profile_sources(profiles)
        source=BASE.run([driver,'-test.run=^'+SOURCE+'$','-test.v','-test.count=1','-test.timeout=60s'],cwd=core,env=source_env,timeout=75)
        check_verdict(source,source_only=True);print(source,end='',flush=True)
        original_source=BASE.run([driver,'-test.run=^'+BASE.SOURCE+'$','-test.v','-test.count=1','-test.timeout=60s'],cwd=core,env=captured,timeout=75)
        mtu=BASE.check_verdict(original_source,None,source_only=True)['carrier_mtu']
        verdicts=[]
        if not compile_only:
            sudo=BASE.UID.privilege_tool();original=os.stat('/proc/self/ns/net')
            native_env=dict(captured,TMPDIR='/tmp',ROUTERVPN_SERVER_CHAIN_CARRIER_MTU=str(mtu),ROUTERVPN_SERVER_CHAIN_OUTER_NETNS=f'{original.st_dev}:{original.st_ino}')
            program=namespace_program(before['acceptance/deploy/test_server_node_chain_encrypted.py'])
            for case in CASES:
                command=['unshare','--user','--map-root-user','--mount','--net','--pid','--fork','--mount-proc',sys.executable,'-I','-c',program,str(driver),str(peer),str(worker),images['driver'][-1],images['peer'][-1],images['worker'][-1],case]
                if sudo:command=[sudo,'-n','--preserve-env=ROUTERVPN_SERVER_CHAIN_OUTER_NETNS,ROUTERVPN_SERVER_CHAIN_CARRIER_MTU','--',*command]
                output=BASE.run(command,cwd=workspace,env=native_env,timeout=125,sudo=sudo);verdicts.append(check_verdict(output,case));print(output,end='',flush=True)
        if checked_sources(core)[1]!=before or profile_sources(profiles)!=profile_hashes or any(BASE.image_identity(path)!=images[role] for role,path in (('driver',driver),('peer',peer),('worker',worker))):raise ValueError('OpenVPN original source/image/private pair changed')
        result={'schema':1,'gate':'openvpn-direct-server-encrypted','scope':'compile-and-source-only' if compile_only else 'actual-openvpn-direct-server-suffix','target':'linux/'+architecture,'source_files':before,'source_sha256':hashlib.sha256(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'images':{role:{'sha256':v[-1],'bytes':v[2]} for role,v in images.items()},'required_cases':list(CASES),'cases':verdicts,'provider_networks':list(NETWORKS),'provider_profiles_sha256':profile_hashes,'provider_stdout_sha256':hashlib.sha256(provider.encode()).hexdigest(),'source_stdout_sha256':hashlib.sha256(source.encode()).hexdigest()}
    if workspace.exists():raise ValueError('OpenVPN joined workspace retained')
    if receipt:
        with Path(receipt).open('x') as output:json.dump(result,output,indent=2,sort_keys=True);output.write('\n')
    return result

def standalone(go='go',*,receipt=None,required_commit=None):
    repository=BASE.repository_identity(required_commit)
    compiler,captured=BASE.UID.compiler_toolchain(ROOT,go,dict(os.environ));old=dict(os.environ)
    with tempfile.TemporaryDirectory(prefix='routervpn-openvpn-direct-server-core-') as temporary:
        workspace=Path(temporary);core,xray=workspace/'core',workspace/'xray'
        try:
            os.environ.clear();os.environ.update(captured)
            BASE.BUILD.checkout(core,'https://github.com/SagerNet/sing-box.git',BASE.BUILD.PIN)
            BASE.BUILD.checkout(xray,'https://github.com/XTLS/Xray-core.git',BASE.BUILD.POLICY.XRAY.XRAY_PIN)
            BASE.BUILD.pristine(core,BASE.BUILD.PIN);BASE.BUILD.pristine(xray,BASE.BUILD.POLICY.XRAY.XRAY_PIN)
            BASE.BUILD.POLICY.prepare_native(core,xray)
            BASE.BUILD.PERFORMANCE.prepare(core);BASE.BUILD.OPENVPN.prepare(core)
            BASE.BUILD.EXTERNAL.prepare(core,go=str(compiler),env=captured);BASE.BUILD.BUFFERS.prepare(core)
            BASE.BUILD.run([compiler,'mod','tidy'],cwd=core,env=captured);BASE.BUILD.run([compiler,'mod','verify'],cwd=core,env=captured)
            BASE.BUILD.POLICY.AMNEZIA.verify(core)
            result=execute(core,str(compiler),env=captured)
        finally:
            os.environ.clear();os.environ.update(old)
    if BASE.repository_identity(required_commit)!=repository or workspace.exists():raise ValueError('OpenVPN repository/workspace ownership changed')
    result['repository']=repository
    if receipt:
        path=Path(receipt).absolute()
        if path.exists() or path.is_symlink() or not path.parent.is_dir():raise ValueError('OpenVPN native receipt requires unused owned path')
        with path.open('x') as output:json.dump(result,output,indent=2,sort_keys=True);output.write('\n')
    return result

def parse_arguments(arguments=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core',type=Path);parser.add_argument('--go',default='go');parser.add_argument('--compile-only',action='store_true');parser.add_argument('--receipt',type=Path)
    parser.add_argument('--standalone',action='store_true');parser.add_argument('--require-commit')
    args=parser.parse_args(arguments)
    if args.standalone:
        if args.core or args.compile_only or not args.require_commit:parser.error('standalone requires exact commit and native acceptance')
    elif not args.core or args.require_commit:parser.error('use standalone with required commit, or core without required commit')
    return args

if __name__=='__main__':
    args=parse_arguments()
    if args.standalone:result=standalone(args.go,receipt=args.receipt,required_commit=args.require_commit)
    else:result=execute(args.core,args.go,receipt=args.receipt,compile_only=args.compile_only)
    print(json.dumps({k:v for k,v in result.items() if k!='source_files'},sort_keys=True))
