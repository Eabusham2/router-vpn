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
MODES=('wg','awg2-fast','awg2-strong','wg-pq','awg2-pq','shadowsocks','hysteria2','naive-h2','naive-h3','reality-vision','reality-pq-vision','reality-xhttp','ss-v2ray','split','max','max-tls-wg','max-tls-awg','max-quic-wg','max-quic-awg')
KINDS=('tor','obfs4','meek_lite','snowflake','webtunnel','custom')
LAYERS=('off','aes-256-gcm','aes-256-gcm+xor-whitening')


def inputs():
    extra=[Path(__file__).resolve(),TEMPLATE,ROOT/'deploy/test_android_tor_pinned_contract.py',ROOT/'android/test_android_tor_profile.py',ROOT/'android/test_android_tor_form.py',ROOT/'android/test_android_tor_session.py',ROOT/'android/test_android_start_layer_relay_lifecycle.py',ROOT/'android/test_android_runtime_teardown.py',ROOT/'android/test_android_runtime_contract.py',ROOT/'android/test_android_standard_exit_contract.py',ROOT/'android/test_android_multihop_home_state.py',ROOT/'android/test_android_layered_service_compile.py']
    extra += [ROOT/'android'/name for name in ('max_preparation_test_boundary.py','test_android_max_dns_owner.py','test_android_max_preparation.py','test_android_max_host_paths.py','test_android_max_service.py')]
    extra += [JAVA/(name+'.java') for name in ('AndroidMAXDNSOwner','AndroidMAXProfilePreparation','AndroidTorProfile','AndroidTorSession','AndroidStandardExitStore','AndroidStandardExitRuntime','AndroidStandardExitController','AndroidDirectStandardExitController','AndroidHomeStateStore','AndroidSessionRevalidator','LayeredVpnService','AndroidStartLayerRelay','StandardExitActivity')]
    return sorted(set(M.inputs()+HOST.inputs()+extra))


def digest():
    h=hashlib.sha256()
    for path in inputs():h.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes())
    return h.hexdigest()


def matrix(folder):
    if folder.is_symlink() or not folder.is_dir():raise ValueError('Android Tor matrix needs an owned directory')
    expected={f'{kind}-{mode}-{layer}.json' for kind,mode,layer in itertools.product(KINDS,MODES,LAYERS)}
    expected.update(f'{kind}-direct-off.json' for kind in KINDS)
    actual=set()
    for path in folder.iterdir():
        if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=4*1024*1024:raise ValueError('Unsafe Android Tor graph')
        actual.add(path.name)
    if actual!=expected:raise ValueError('Android Tor matrix missing or changed: '+str(sorted(actual^expected)))


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
    data=TEMPLATE.read_bytes()
    if target.is_symlink() or target.exists():raise ValueError('Android Tor native test destination must be unused')
    target.write_bytes(data)
    try:
        with tempfile.TemporaryDirectory(prefix='routervpn-android-tor-native-') as directory:
            work=Path(directory);graphs=work/'graphs';graphs.mkdir()
            env['ANDROID_JSON_JAR']=str(M.android_json_dependency(work,env));env['ROUTERVPN_ANDROID_TOR_GRAPHS']=str(graphs)
            # The Java/Go compiler fixture does not load native Tor. Passing
            # its DSO link flags into pure Go asset tools can create an unused
            # DT_NEEDED entry without the external linker's matching rpath.
            profile_env=env.copy();profile_env.pop('CGO_LDFLAGS',None)
            subprocess.run([sys.executable,str(ROOT/'android/test_android_tor_profile.py')],cwd=ROOT,env=profile_env,check=True,timeout=600)
            matrix(graphs)
            subprocess.run([go,'test','-mod=readonly','-ldflags=-checklinkname=0','-tags','with_quic,with_wireguard,with_gvisor,with_naive_outbound,routervpn_tor_native_test','./experimental/libbox','-run','^TestRouterTorAndroidGeneratedGraphs$','-count=1','-timeout=120s','-v'],cwd=vendor,env=env,check=True,timeout=600)
        if before!=digest() or native!=hashlib.sha256(library.read_bytes()).hexdigest():raise ValueError('Android or native Tor source changed during validation')
        T.TORPACK.PACKAGE.verify(package,'host-test')
        verify_prepared(vendor)
    finally:
        if target.exists() and target.read_bytes()==data:target.unlink()
    print('Android Tor: all 348 captured graphs and 348 missing-engine controls passed the exact native parser; no VPN started.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('vendor',type=Path,nargs='?');parser.add_argument('--native-package',type=Path);parser.add_argument('--go',default=shutil.which('go'));parser.add_argument('--clang',help='Clang21+ with matching sibling clang++ and ld.lld');parser.add_argument('--digest',action='store_true');args=parser.parse_args()
    if args.digest:print(digest())
    elif args.vendor and args.native_package and args.go:run(args.vendor,args.native_package,args.go,args.clang)
    else:parser.error('prepared vendor, verified host package and Go are required')
