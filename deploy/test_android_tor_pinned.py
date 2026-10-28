#!/usr/bin/env python3
"""Check all captured Android Tor graphs with the exact native Libbox parser."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import itertools
import json
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);loaded=importlib.util.module_from_spec(spec);spec.loader.exec_module(loaded);return loaded
M=module('android_tor_graph_dependencies',ROOT/'deploy/test_android_multihop_pinned.py')
T=module('android_tor_owned_source',ROOT/'deploy/prepare-mobile-tor.py')
HOST=module('android_tor_graph_host',ROOT/'deploy/native_tor_graph_host.py')
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'
TEMPLATE=ROOT/'mobile/routervpn_tor_android_graph_test.go.tmpl'
PADDING_TEMPLATE=ROOT/'mobile/routervpn_tor_android_padding_graph_test.go.tmpl'
MODES=('wg','awg2-fast','awg2-strong','wg-pq','awg2-pq','shadowsocks','hysteria2','naive-h2','naive-h3','reality-vision','reality-pq-vision','reality-xhttp','ss-v2ray','split','max','max-tls-wg','max-tls-awg','max-quic-wg','max-quic-awg')
KINDS=('tor','obfs4','meek_lite','snowflake','webtunnel','custom')
LAYERS=('off','aes-256-gcm','aes-256-gcm+xor-whitening')
ORDINARY_MODES={'wireguard':'wireguard','amneziawg':'amneziawg','socks5':'socks5',
                'http':'http-connect','https':'https-connect','shadowsocks':'shadowsocks',
                'hysteria2':'hysteria2','openvpn':'openvpn'}


def inputs():
    extra=[Path(__file__).resolve(),TEMPLATE,PADDING_TEMPLATE,ROOT/'deploy/test_android_tor_pinned_contract.py',ROOT/'android/test_android_tor_profile.py',ROOT/'android/test_android_tor_server_profile.py',ROOT/'android/test_android_tor_form.py',ROOT/'android/test_android_tor_session.py',ROOT/'android/test_android_start_layer_relay_lifecycle.py',ROOT/'android/test_android_runtime_teardown.py',ROOT/'android/test_android_runtime_contract.py',ROOT/'android/test_android_standard_exit_contract.py',ROOT/'android/test_android_multihop_home_state.py',ROOT/'android/test_android_layered_service_compile.py']
    extra += [ROOT/'android'/name for name in ('max_preparation_test_boundary.py','test_android_max_dns_owner.py','test_android_max_preparation.py','test_android_max_host_paths.py','test_android_max_service.py')]
    extra += [JAVA/(name+'.java') for name in ('AndroidMAXDNSOwner','AndroidMAXProfilePreparation','AndroidTorProfile','AndroidTorSession','AndroidTorCompareRuntime','AndroidTorPaddingReceipt','AndroidStandardExitStore','AndroidStandardExitRuntime','AndroidStandardExitController','AndroidDirectStandardExitController','AndroidHomeStateStore','AndroidSessionRevalidator','LayeredVpnService','AndroidStartLayerRelay','StandardExitActivity')]
    extra += [ROOT/'android/test_android_tor_compare.py']
    return sorted(set(M.inputs()+HOST.inputs()+extra))


def digest():
    h=hashlib.sha256()
    for path in inputs():h.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes())
    return h.hexdigest()


def matrix(folder):
    if folder.is_symlink() or not folder.is_dir():raise ValueError('Android Tor matrix needs an owned directory')
    expected={f'{kind}-{mode}-{layer}.json' for kind,mode,layer in itertools.product(KINDS,MODES,LAYERS)}
    expected.update(f'{kind}-direct-off.json' for kind in KINDS)
    expected.update(f'server-{kind}-{mode}-{layer}.json' for kind,mode,layer in itertools.product(KINDS,MODES,LAYERS))
    ordinary={f'ordinary-{kind}-{mode}.json':(kind,protocol)
              for kind,(mode,protocol) in itertools.product(KINDS,ORDINARY_MODES.items())}
    expected.update(ordinary)
    actual=set()
    for path in folder.iterdir():
        if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=4*1024*1024:raise ValueError('Unsafe Android Tor graph')
        actual.add(path.name)
    if actual!=expected:raise ValueError('Android Tor matrix missing or changed: '+str(sorted(actual^expected)))
    for name,(kind,protocol) in ordinary.items():
        graph=json.loads((folder/name).read_bytes())
        if not isinstance(graph,dict) or not isinstance(graph.get('outbounds'),list):
            raise ValueError('Android ordinary Tor graph has no native outbounds: '+name)
        owners=[out for out in graph['outbounds'] if isinstance(out,dict) and out.get('type') in ('routervpn-tor','routervpn-server-tor')]
        if (len(owners)!=1 or owners[0].get('type')!='routervpn-tor'
                or owners[0].get('tag')!='routervpn-tor-exit' or owners[0].get('detour')!='custom-exit'
                or not isinstance(owners[0].get('session_id'),str) or not owners[0]['session_id']):
            raise ValueError('Android ordinary Tor graph lost its unique Local owner: '+name)
        owner=owners[0]
        fields=('external_tor_profile','external_predecessor_profile','external_predecessor_config')
        if any(not isinstance(owner.get(key),str) or not isinstance(json.loads(owner[key]),dict) for key in fields):
            raise ValueError('Android ordinary Tor graph lost its typed source inputs: '+name)
        selected,predecessor,source=(json.loads(owner[key]) for key in fields)
        external=predecessor.get('external',{})
        if (predecessor.get('node_kind')!='external' or not isinstance(external,dict)
                or external.get('protocol')!=protocol or not external.get('expected_public_ip')
                or any(predecessor.get(key) not in ('',None) for key in ('node_proof_id','router_api','api_token','agent_token'))
                or selected.get('multihop_execution')!='local' or selected.get('multihop_enabled') is not True
                or selected.get('multihop_entry_id')!=predecessor.get('id') or not predecessor.get('id')
                or selected.get('multihop_entry_mode')!=protocol
                or selected.get('multihop_exit_id')!=selected.get('id') or not selected.get('id')
                or selected.get('multihop_exit_mode')!=('tor' if kind=='tor' else 'tor-bridge')
                or not isinstance(source.get('route'),dict) or source['route'].get('final')!='custom-exit'):
            raise ValueError('Android ordinary Tor graph changed its captured role or acquired private authority: '+name)


def padding_matrix(folder):
    """Require every enabled source family/rate, independently of Off graphs."""
    if folder.is_symlink() or not folder.is_dir():raise ValueError('Android padding matrix needs an owned directory')
    expected={f'padding-{index:03d}.json' for index in range(160)}
    expected.update(f'ordinary-padding-{index:03d}.json' for index in range(8,72))
    paths=list(folder.iterdir())
    if {path.name for path in paths}!=expected:raise ValueError('Android enabled padding matrix is incomplete')
    choices=set()
    for path in paths:
        if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=4*1024*1024:
            raise ValueError('Unsafe enabled Android padding graph')
        graph=json.loads(path.read_bytes())
        owners=[row for row in graph.get('outbounds',[]) if isinstance(row,dict) and row.get('type')=='routervpn-tor']
        if len(owners)!=1 or owners[0].get('tag')!='routervpn-tor-exit' or not owners[0].get('session_id'):
            raise ValueError('Enabled Android padding lost its native Local owner')
        source=owners[0].get('padding_source')
        if not isinstance(source,dict) or not isinstance(source.get('profile'),str):
            raise ValueError('Enabled Android padding lost its captured source')
        profile=json.loads(source['profile'])
        rate=profile.get('daita_rate_kbps',0)
        if (profile.get('daita_enabled') is not True or type(rate) is not int or rate not in (0,32,64,192)
                or profile.get('multihop_execution','local')!='local'):
            raise ValueError('Enabled Android padding changed its captured policy')
        external=profile.get('external',{})
        kind='tor' if external.get('protocol')=='tor' else external.get('tor_bridge',{}).get('transport')
        ordinary=path.name.startswith('ordinary-')
        mode=profile.get('multihop_entry_mode') if profile.get('multihop_enabled') is True else 'direct'
        if mode!='direct':
            entry=json.loads(source.get('predecessor_profile','{}'))
            if not source.get('predecessor_config') or profile.get('multihop_entry_id')!=entry.get('id'):
                raise ValueError('Enabled Android padding lost its complete predecessor')
            if ordinary:
                if entry.get('node_kind')!='external' or entry.get('external',{}).get('protocol')!=mode:
                    raise ValueError('Enabled Android padding changed ordinary provider authority')
            elif entry.get('node_kind')=='external':
                raise ValueError('Enabled Android padding replaced its private entry')
        choice=('ordinary' if ordinary else 'router',mode,kind,rate)
        if choice in choices:raise ValueError('Enabled Android padding repeated a source family')
        choices.add(choice)
    expected_choices={('router',mode,kind,rate) for mode,kind,rate in itertools.product(('direct',*MODES),('tor','obfs4'),(0,32,64,192))}
    expected_choices.update(('ordinary',mode,kind,rate) for mode,kind,rate in itertools.product(ORDINARY_MODES.values(),('tor','obfs4'),(0,32,64,192)))
    if choices!=expected_choices:raise ValueError('Enabled Android padding changed its source family inventory')


def verify_prepared(vendor):
    """Require the shipping Tor source, not a same-named parser registration."""
    record=json.loads(T.destination(vendor,T.OWNER).read_text())
    expected=T.copies()
    hashes={relative:hashlib.sha256(data).hexdigest() for relative,data in expected.items()}
    if (record.get('schema')!=1 or record.get('core')!=M.PIN
            or record.get('source_sha256')!=T.digest() or record.get('files')!=hashes):
        raise ValueError('Prepared native Tor source differs from the shipping source')
    for relative,data in expected.items():
        if T.destination(vendor,relative).read_bytes()!=data:
            raise ValueError('Prepared native Tor file changed: '+relative)
    dns=(ROOT/'mobile/toroutbound/dns_adapter.go.tmpl').read_bytes()
    if (record.get('dns_adapter_sha256')!=hashlib.sha256(dns).hexdigest()
            or T.destination(vendor,'dns/transport_adapter.go').read_bytes()!=dns):
        raise ValueError('Prepared Tor bootstrap DNS owner changed')


def run(vendor,package,go,clang=None):
    vendor=vendor.resolve();package=package.resolve()
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=vendor,text=True).strip()!=M.PIN:raise ValueError('Android Tor gate needs the exact pinned core')
    T.TORPACK.PACKAGE.verify(package,'host-test')
    verify_prepared(vendor)
    library=package/'lib/libroutervpn_tor.so'
    if not library.is_file():raise ValueError('This Android runtime gate requires the verified Linux host Tor DSO')
    env=HOST.environment(go,library,clang)
    before=digest();native=hashlib.sha256(library.read_bytes()).hexdigest()
    target=vendor/'experimental/libbox/routervpn_tor_android_graph_test.go'
    padding_target=vendor/'experimental/libbox/routervpn_tor_android_padding_graph_test.go'
    data=TEMPLATE.read_bytes()
    padding_data=PADDING_TEMPLATE.read_bytes()
    if target.is_symlink() or target.exists() or padding_target.is_symlink() or padding_target.exists():raise ValueError('Android Tor native test destination must be unused')
    target.write_bytes(data)
    padding_target.write_bytes(padding_data)
    try:
        with tempfile.TemporaryDirectory(prefix='routervpn-android-tor-native-') as directory:
            work=Path(directory);graphs=work/'graphs';graphs.mkdir();padding=work/'padding';padding.mkdir()
            env['ANDROID_JSON_JAR']=str(M.android_json_dependency(work,env));env['ROUTERVPN_ANDROID_TOR_GRAPHS']=str(graphs)
            env['ROUTERVPN_ANDROID_LOCAL_PADDING_GRAPHS']=str(padding)
            env['ROUTERVPN_ANDROID_TOR_STATE']=str(work/'tor-state')
            # The Java/Go compiler fixture does not load native Tor. Passing
            # its DSO link flags into pure Go asset tools can create an unused
            # DT_NEEDED entry without the external linker's matching rpath.
            profile_env=env.copy();profile_env.pop('CGO_LDFLAGS',None)
            subprocess.run([sys.executable,str(ROOT/'android/test_android_tor_profile.py')],cwd=ROOT,env=profile_env,check=True,timeout=600)
            server_graphs=work/'server-graphs';server_graphs.mkdir()
            server_env=profile_env.copy();server_env['ROUTERVPN_ANDROID_TOR_GRAPHS']=str(server_graphs)
            server_env.pop('ROUTERVPN_ANDROID_LOCAL_PADDING_GRAPHS',None)
            subprocess.run([sys.executable,str(ROOT/'android/test_android_tor_server_profile.py')],cwd=ROOT,env=server_env,check=True,timeout=600)
            for path in server_graphs.iterdir():
                if path.is_symlink() or not path.is_file() or not path.name.startswith('server-') or (graphs/path.name).exists():
                    raise ValueError('Server graph does not have its own capture identity')
                path.rename(graphs/path.name)
            ordinary_graphs=work/'ordinary-graphs';ordinary_graphs.mkdir()
            ordinary_env=profile_env.copy();ordinary_env.pop('ROUTERVPN_ANDROID_TOR_GRAPHS',None)
            ordinary_env['ROUTERVPN_ANDROID_ORDINARY_TOR_GRAPHS']=str(ordinary_graphs)
            ordinary_padding=work/'ordinary-padding';ordinary_padding.mkdir()
            ordinary_env['ROUTERVPN_ANDROID_LOCAL_PADDING_GRAPHS']=str(ordinary_padding)
            subprocess.run([sys.executable,str(ROOT/'android/test_android_tor_form.py')],cwd=ROOT,env=ordinary_env,check=True,timeout=600)
            for path in ordinary_graphs.iterdir():
                if path.is_symlink() or not path.is_file() or not path.name.startswith('ordinary-') or (graphs/path.name).exists():
                    raise ValueError('Ordinary graph does not have its own captured source identity')
                path.rename(graphs/path.name)
            for path in ordinary_padding.iterdir():
                if path.is_symlink() or not path.is_file() or not path.name.startswith('ordinary-padding-') or (padding/path.name).exists():
                    raise ValueError('Enabled ordinary padding lacks an owned captured source')
                path.rename(padding/path.name)
            matrix(graphs)
            padding_matrix(padding)
            subprocess.run([go,'test','-mod=readonly','-ldflags=-checklinkname=0','-tags','with_quic,with_wireguard,with_gvisor,with_openvpn,with_naive_outbound,routervpn_tor_native_test','./experimental/libbox','-run','^TestRouterTorAndroidGeneratedGraphs$|^TestRouterTorAndroidLocalPaddingGraphs$','-count=1','-timeout=120s','-v'],cwd=vendor,env=env,check=True,timeout=600)
        if before!=digest() or native!=hashlib.sha256(library.read_bytes()).hexdigest():raise ValueError('Android or native Tor source changed during validation')
        T.TORPACK.PACKAGE.verify(package,'host-test')
        verify_prepared(vendor)
    finally:
        if target.exists() and target.read_bytes()==data:target.unlink()
        if padding_target.exists() and padding_target.read_bytes()==padding_data:padding_target.unlink()
    print('Android Tor: all 738 captured graphs (348 Router/direct Local, 48 ordinary Local, 342 Server) and 738 missing-engine controls passed the exact native parser; no VPN started.')
    print('Android Local Tor padding: 224 enabled direct/private/ordinary graphs and 448 missing-engine/changed-source controls passed the exact native parser; no VPN started.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('vendor',type=Path,nargs='?');parser.add_argument('--native-package',type=Path);parser.add_argument('--go',default=shutil.which('go'));parser.add_argument('--clang',help='Clang21+ with matching sibling clang++ and ld.lld');parser.add_argument('--digest',action='store_true');args=parser.parse_args()
    if args.digest:print(digest())
    elif args.vendor and args.native_package and args.go:run(args.vendor,args.native_package,args.go,args.clang)
    else:parser.error('prepared vendor, verified host package and Go are required')
