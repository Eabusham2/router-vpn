#!/usr/bin/env python3
"""Require the distinct CONNECT Server suffix in the original isolated worker.

This gate does not model entry lease acquisition or desktop Compare. Original
paired/schema2 gates remain independently mandatory and unchanged.
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
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'deploy'/f'{name}.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
BASE=load('test_server_node_chain_encrypted')
TEMPLATE='mobile/server_chain_acceptance/connect_linux_test.go.tmpl'
TARGET='cmd/sing-box/routervpn_server_chain_connect_linux_test.go'
OWNER='routervpn-server-connect-encrypted-test-source.json'
SOURCE='TestServerChainCONNECTEncryptedSource'
NATIVE='TestServerChainCONNECTEncryptedNative'
PROTOCOLS=('http-connect','https-connect')
FAULTS=('original','wrong-middle-key','wrong-final-key','wrong-final-identity','failed-selected-dns','wrong-public-identity','joined-active-udp','admission-restrictions')
CASES=tuple(protocol+'/'+fault for protocol in PROTOCOLS for fault in FAULTS)+('https-connect/wrong-proxy-name',)
FIELDS={'case','protocol','capture_sha256','source_sha256','ready','selected_dns','middle_tcp','middle_udp','final_tcp','final_udp','retired','worker_joined','peer_joined','private_udp_refused','private_sink_packets','private_sink_replies','middle_auth','tls_refused'}

def unique_object(rows):
    result={}
    for key,value in rows:
        if key in result:raise ValueError('Duplicate CONNECT receipt key')
        result[key]=value
    return result

def check_verdict(output,case=None,*,source_only=False):
    if source_only and case is not None or not source_only and case not in CASES:raise ValueError('Uncaptured CONNECT case')
    root=SOURCE if source_only else NATIVE
    expected={root,*(root+'/'+name for name in (CASES if source_only else (case,)))}
    runs=set();passes=set();receipts=[];ended=False;terminal=False
    for line in output.splitlines():
        text=line.strip()
        if not text:continue
        if any(x in line for x in ('WARNING: DATA RACE','--- FAIL:','--- SKIP:','panic:','fatal error:')):raise ValueError('CONNECT failed, skipped or raced')
        run=re.fullmatch(r'=== RUN\s+(\S+)',text)
        passed=re.fullmatch(r'--- PASS: (\S+) \([0-9.]+s\)',text)
        receipt=re.fullmatch(r'\S+\.go:[0-9]+: CONNECT_SERVER_RECEIPT (.+)',text)
        if run:
            name=run[1]
            if ended or terminal or name not in expected or name in runs or name!=root and root not in runs:raise ValueError('Foreign/late CONNECT run')
            runs.add(name)
        elif passed:
            name=passed[1]
            if terminal or name not in runs or name in passes:raise ValueError('Unmatched CONNECT pass')
            if name==root:
                if runs!=expected or len(receipts)!=(0 if source_only else 1):raise ValueError('CONNECT root passed before original work')
                ended=True
            passes.add(name)
        elif receipt:
            if source_only or ended or terminal or root+'/'+case not in runs or root+'/'+case in passes or receipts:raise ValueError('Foreign/late CONNECT receipt')
            value=json.loads(receipt[1],object_pairs_hook=unique_object)
            protocol,fault=case.split('/')
            if type(value) is not dict or set(value)!=FIELDS or value['protocol']!=protocol or value['case']!=fault:raise ValueError('CONNECT receipt identity changed')
            ready=fault in ('original','joined-active-udp','admission-restrictions')
            if any(value[k] is not True for k in ('retired','worker_joined','peer_joined')) or value['ready'] is not ready or value['selected_dns'] is not ready:raise ValueError('CONNECT lost readiness/retirement')
            if any(type(value[k]) is not str or not re.fullmatch('[0-9a-f]{64}',value[k]) for k in ('capture_sha256','source_sha256')):raise ValueError('CONNECT source identity missing')
            counters=('middle_tcp','middle_udp','final_tcp','final_udp','middle_auth','tls_refused','private_sink_packets','private_sink_replies')
            if any(type(value[k]) is not int or value[k]<0 for k in counters) or value['middle_tcp']<=0 or value['middle_udp']!=0 or value['final_udp']!=0 or ready and value['final_tcp']<=0:raise ValueError('CONNECT actual TCP/UoT observations incomplete')
            restricted=fault=='admission-restrictions'
            if value['private_udp_refused'] is not restricted or restricted and (value['private_sink_packets'] or value['private_sink_replies']) or fault in ('original','joined-active-udp') and min(value['private_sink_packets'],value['private_sink_replies'])<=0:raise ValueError('CONNECT original LAN restriction changed')
            if fault=='wrong-middle-key' and value['middle_auth']<=0 or ready and value['middle_auth']!=0 or (fault=='wrong-proxy-name' and value['tls_refused']<=0 or fault!='wrong-proxy-name' and value['tls_refused']!=0):raise ValueError('CONNECT authentication observation changed')
            receipts.append(value)
        elif text=='PASS':
            if terminal or not ended or passes!=expected:raise ValueError('CONNECT empty/early terminal success')
            terminal=True
        else:raise ValueError('Unexpected CONNECT output')
    if not terminal or runs!=expected or passes!=expected or len(receipts)!=(0 if source_only else 1):raise ValueError('CONNECT missing exact verdict')
    return receipts[0] if receipts else {'source_cases':list(CASES)}

def install_fixture(core):
    core=Path(core)
    if core.is_symlink() or subprocess.check_output(['git','-C',str(core),'rev-parse','HEAD'],text=True).strip()!=BASE.BUILD.PIN:raise ValueError('CONNECT requires original pinned core')
    source,target,record=ROOT/TEMPLATE,core/TARGET,core/OWNER
    if any(p.is_symlink() for p in (source,target,record,target.parent)):raise ValueError('Linked CONNECT source')
    raw=source.read_bytes()
    if not raw.startswith(b'//go:build linux && !android && routervpn_server_chain_acceptance\n\npackage main\n'):raise ValueError('CONNECT fixture changed target')
    if record.exists():
        old=json.loads(record.read_text())
        if old.get('schema')!=1 or old.get('target')!=TARGET or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest()!=old.get('sha256'):raise ValueError('Changed original CONNECT fixture')
    elif target.exists() and target.read_bytes()!=raw:raise ValueError('Unowned CONNECT fixture')
    target.write_bytes(raw);record.write_text(json.dumps({'schema':1,'target':TARGET,'sha256':hashlib.sha256(raw).hexdigest()},sort_keys=True)+'\n')

def checked_sources(core):
    core,records=BASE.checked_sources(core)
    extra=(TEMPLATE,'mobile/desktop/node_chain_connect_server_peer_test.go.tmpl','mobile/desktop/node_imported_connect_entry_test.go.tmpl','mobile/chain/connect_reference_test.go.tmpl','deploy/test_server_node_chain_connect_encrypted.py','deploy/test_server_node_chain_connect_encrypted_runner.py')
    for name in extra:
        p=ROOT/name
        if p.is_symlink() or not p.is_file():raise ValueError('CONNECT dependency missing/linked')
        records['connect/'+name]=hashlib.sha256(p.read_bytes()).hexdigest()
    for name,target in ((TEMPLATE,TARGET),('mobile/desktop/node_chain_connect_server_peer_test.go.tmpl',BASE.NODE.PREP.PEER_TEMPLATES['node_chain_connect_server_peer_test.go.tmpl']),('mobile/desktop/node_imported_connect_entry_test.go.tmpl',BASE.NODE.PREP.PEER_TEMPLATES['node_imported_connect_entry_test.go.tmpl'])):
        if (core/target).is_symlink() or (core/target).read_bytes()!=(ROOT/name).read_bytes():raise ValueError('CONNECT generated original dependency changed')
    return core,records

def namespace_program(base_sha):
    # Reuse the exact original namespace/MTU/image/privilege program. Change
    # only its separately sealed typed root and finite case inventory.
    tree=ast.parse(BASE.namespace_program(base_sha))
    changed=set()
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ('CASES','NATIVE'):
            key=node.targets[0].id;node.value=ast.parse(repr(CASES if key=='CASES' else NATIVE),mode='eval').body;changed.add(key)
    if changed!={'CASES','NATIVE'}:raise ValueError('Original namespace selectors changed')
    return ast.unparse(ast.fix_missing_locations(tree))

def execute(core,go='go',*,env=None,receipt=None,compile_only=False):
    if platform.system()!='Linux':raise ValueError('CONNECT Server gate requires actual Linux')
    captured=dict(os.environ if env is None else env,GOWORK='off')
    if captured.get('GOOS','linux')!='linux' or captured.get('CGO_ENABLED','1')!='1':raise ValueError('CONNECT forbids cross-host/non-race acceptance')
    captured['CGO_ENABLED']='1'
    BASE.install_fixture(core);BASE.install_imported_fixture(core);install_fixture(core)
    core,before=checked_sources(core);compiler,captured=BASE.UID.compiler_toolchain(core,go,captured)
    architecture=BASE.run([compiler,'env','GOARCH'],cwd=core,env=captured).strip()
    if architecture not in ('amd64','arm64'):raise ValueError('Unsupported native architecture')
    if receipt and (compile_only or Path(receipt).exists() or Path(receipt).is_symlink() or not Path(receipt).parent.is_dir()):raise ValueError('CONNECT native receipt requires unused owned path')
    with tempfile.TemporaryDirectory(prefix='routervpn-connect-server-') as temporary:
        workspace=Path(temporary).resolve();workspace.chmod(0o755)
        driver,peer,worker=workspace/'driver.test',workspace/'peer.test',workspace/'sing-box'
        common=['-race','-mod=readonly','-p=1','-tags='+','.join(BASE.TAGS),'-ldflags=-checklinkname=0']
        BASE.run([compiler,'build',*common,'-o',worker,'./cmd/sing-box'],cwd=core,env=captured,timeout=600)
        BASE.run([compiler,'test','-c',*common,'-o',peer,'./protocol/routervpnamnezia'],cwd=core,env=captured,timeout=600)
        flags=[v+',routervpn_server_chain_acceptance' if v.startswith('-tags=') else v for v in common]
        BASE.run([compiler,'test','-c',*flags,'-o',driver,'./cmd/sing-box'],cwd=core,env=captured,timeout=600)
        images={role:BASE.image_identity(path) for role,path in (('driver',driver),('peer',peer),('worker',worker))}
        if checked_sources(core)[1]!=before:raise ValueError('CONNECT source changed during compilation')
        source=BASE.run([driver,'-test.run=^'+SOURCE+'$','-test.v','-test.count=1','-test.timeout=60s'],cwd=core,env=captured,timeout=75)
        check_verdict(source,source_only=True);print(source,end='')
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
                output=BASE.run(command,cwd=workspace,env=native_env,timeout=125,sudo=sudo);verdicts.append(check_verdict(output,case));print(output,end='')
        if checked_sources(core)[1]!=before or any(BASE.image_identity(path)!=images[role] for role,path in (('driver',driver),('peer',peer),('worker',worker))):raise ValueError('CONNECT original image/source changed')
        result={'schema':1,'gate':'connect-server-encrypted','scope':'compile-and-source-only' if compile_only else 'actual-connect-server-suffix','target':'linux/'+architecture,'source_files':before,'source_sha256':hashlib.sha256(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'images':{role:{'sha256':v[-1],'bytes':v[2]} for role,v in images.items()},'required_cases':list(CASES),'cases':verdicts}
    if workspace.exists():raise ValueError('CONNECT original workspace retained')
    if receipt:
        with Path(receipt).open('x') as output:json.dump(result,output,indent=2,sort_keys=True);output.write('\n')
    return result

def standalone(go='go',*,receipt=None,required_commit=None):
    repository=BASE.repository_identity(required_commit)
    compiler,captured=BASE.UID.compiler_toolchain(ROOT,go,dict(os.environ));old=dict(os.environ)
    with tempfile.TemporaryDirectory(prefix='routervpn-connect-server-core-') as temporary:
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
    if BASE.repository_identity(required_commit)!=repository or workspace.exists():raise ValueError('CONNECT repository/workspace ownership changed')
    result['repository']=repository
    if receipt:
        path=Path(receipt).absolute()
        if path.exists() or path.is_symlink() or not path.parent.is_dir():raise ValueError('CONNECT native receipt requires unused owned path')
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
