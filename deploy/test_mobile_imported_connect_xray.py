#!/usr/bin/env python3
"""Require original HTTP/HTTPS CONNECT to paired REALITY source/native parsers.

This gate preserves separate shared, actual Android and actual Swift inventories.
Native encrypted traffic, system-tunnel and physical-device acceptance remain
separate requirements; parsing cannot establish them.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


PROXY = module('connect_reality_existing_gates', 'test_mobile_imported_proxy_xray.py')
SOCKS = PROXY.SOCKS
IMPORTED = SOCKS.IMPORTED
KINDS = ('http-connect', 'https-connect')
LAYERS = PROXY.LAYERS
FILES = {kind+'--reality-vision--'+first+'--'+final+'.json'
         for kind in KINDS for first in LAYERS for final in LAYERS}
SHARED_ENV = 'ROUTERVPN_IMPORTED_CONNECT_XRAY_FIXTURES'
ANDROID_ENV = 'ROUTERVPN_ANDROID_IMPORTED_CONNECT_XRAY_FIXTURES'
APPLE_ENV = 'ROUTERVPN_APPLE_IMPORTED_CONNECT_XRAY_FIXTURES'
REQUIRE_ENV = 'ROUTERVPN_REQUIRE_IMPORTED_CONNECT_XRAY_FIXTURES'
SHARED_PARSER = 'TestRouterImportedCONNECTRealitySourceGraphs'
ANDROID_PARSER = 'TestRouterImportedCONNECTRealityAndroidSourceGraphs'
APPLE_PARSER = 'TestRouterImportedCONNECTRealityAppleGraphs'


def kind_cases(suffix, leaves):
    return {'TestImportedCONNECTRealityVision'+suffix:
            [name for kind in KINDS for name in (kind, *(kind+'/'+leaf for leaf in leaves))]}


CORE = kind_cases('IndependentLayers', [a+'/'+b for a in LAYERS for b in LAYERS])
CORE.update(kind_cases('SelectedPolicy', ('default-home','custom-udp','custom-tcp','tls','https','h3','ipv6-off','lan-off','fixed-mtu')))
CORE.update(kind_cases('OriginalFlowsAndBootstrap', [name for flow in ('xtls-rprx-vision','xtls-rprx-vision-udp443')
    for name in (flow, *(flow+'/'+transport for transport in ('tls','https','h3')))]))
CORE.update(kind_cases('NeverBorrowsSSAuthority', ('no-service','same-node-layer-service','foreign-final-service')))
CORE.update(kind_cases('RejectsChangedAuthority', (
    'entry-password','entry-username','entry-endpoint','entry-protocol','entry-tls-source','entry-insecure',
    'entry-layer-missing','entry-layer-mode','entry-layer-foreign','entry-layer-unused','entry-route',
    'entry-paired-proof','entry-paired-api','same-node','final-not-paired','final-missing-proof',
    'final-missing-token','final-missing-xray','final-wrapper','final-plaintext','final-flow',
    'final-layer-missing','final-layer-foreign','final-layer-unused','server','compare','foreign-bootstrap')))
CORE.update(kind_cases('KeepsScope', ('hysteria2','wg','awg2-fast','awg2-strong','reality-pq-vision','reality-xhttp','split','max')))
CORE.update(kind_cases('RequiresBothProofsAndDNS', ('success','wrong-public-ip','wrong-paired-final','dns-failure',
    'cancel-during-dns','missing-dns-capability','changed-owner')))
CORE.update(kind_cases('RetainedRuntime', ('close','network-change','replacement')))


def captured_matrix(directory, prefix=''):
    expected = {prefix + name for name in FILES}
    if directory.is_symlink() or not directory.is_dir() or {p.name for p in directory.iterdir()} != expected:
        raise ValueError('CONNECT REALITY requires exactly eighteen separately owned source files')
    result = {}
    for name in sorted(expected):
        path = directory / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 1 << 20:
            raise ValueError('CONNECT REALITY source is not a bounded regular file: ' + name)
        result[name] = path.read_bytes()
    return result



def inputs():
    return sorted(set(PROXY.inputs()) | {Path(__file__).resolve(), ROOT/'deploy/test_mobile_imported_connect_xray_runner.py'})


def source_receipt():
    records = {}
    for path in inputs():
        if path.is_symlink() or not path.is_file():
            raise ValueError('CONNECT REALITY lost an original source dependency')
        records[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def checked_sources(vendor):
    records = PROXY.checked_sources(vendor, False)
    # HTTP is the actual imported transport. Bind every original protocol byte,
    # including the absence of an injected Go file, to the pinned native tree.
    tracked = subprocess.check_output(['git','-C',str(vendor),'ls-tree','-r','--name-only',SOCKS.PIN,'--','protocol/http'], text=True).splitlines()
    expected = {name for name in tracked if name.endswith('.go')}
    actual = {path.relative_to(vendor).as_posix() for path in (vendor/'protocol/http').rglob('*.go')}
    if not expected or actual != expected:
        raise ValueError('CONNECT REALITY native HTTP source inventory changed')
    for name in sorted(expected):
        original = subprocess.check_output(['git','-C',str(vendor),'show',SOCKS.PIN+':'+name])
        SOCKS.check_file(vendor/name, original, records, 'original/'+name)
    return records


def execute(command, cwd, env, expected, timeout):
    status, output = SOCKS.run_command(command, cwd, env, timeout)
    # Retain the actual failed/timed-out native output before strict rejection.
    print(output, end='' if output.endswith('\n') else '\n', flush=True)
    SOCKS.require_verdicts(output, status, expected)
    return output


def shared_sources(compiler, workspace, env):
    directory = workspace/'shared'
    directory.mkdir()
    env[SHARED_ENV] = str(directory)
    env[REQUIRE_ENV] = '1'
    execute([compiler,'test','-mod=readonly','-race','-json','./internal/mobilemultihop',
             '-run','^('+'|'.join(CORE)+')$','-count=1','-timeout=60s'],
            ROOT, env, IMPORTED.names(CORE), 240)
    return directory, captured_matrix(directory)


def android_sources(workspace, env):
    directory = workspace/'android'
    directory.mkdir()
    for kind in KINDS:
        phase = workspace/('android-'+kind)
        phase.mkdir()
        child_env = {key:value for key,value in env.items() if not key.startswith('ROUTERVPN_ANDROID_')}
        child_env[ANDROID_ENV] = str(phase)
        subprocess.run([sys.executable,str(ROOT/'android/test_android_imported_router.py'),
                        '--phase','connect-reality--'+kind], cwd=ROOT, env=child_env, check=True, timeout=240)
        expected = {'android-'+name for name in FILES if name.startswith(kind+'--')}
        IMPORTED.merge_android_exports(phase, directory, expected)
    env[ANDROID_ENV] = str(directory)
    return directory, captured_matrix(directory, 'android-')


def run(vendor, android=False):
    vendor = vendor.resolve(strict=True)
    compiler = shutil.which('go')
    if not compiler:
        raise ValueError('CONNECT REALITY requires the shipping Go compiler')
    compiler = Path(compiler).resolve(strict=True)
    env = dict(os.environ, GOTOOLCHAIN=SOCKS.TOOLCHAIN, GOWORK='off')
    for key,value in (('GOMAXPROCS','1'),('GOGC','5'),('GOMEMLIMIT','256MiB')):
        env.setdefault(key,value)
    if subprocess.check_output([compiler,'env','GOVERSION'],env=env,text=True).strip() != SOCKS.TOOLCHAIN:
        raise ValueError('CONNECT REALITY compiler differs from shipping toolchain')
    for key in ('GOOS','GOARCH'):
        env[key] = subprocess.check_output([compiler,'env','GOHOST'+key[2:]],env=env,text=True).strip()
    before = source_receipt()
    prepared = checked_sources(vendor)
    original_xray = PROXY.resolved_xray(compiler, vendor, env)
    subprocess.run([sys.executable,str(ROOT/'deploy/test_mobile_imported_connect_xray_runner.py')],
                   cwd=ROOT,env=env,check=True,timeout=30)
    receipt = {'scope':'native-source-parsers','core_pin':SOCKS.PIN,'toolchain':SOCKS.TOOLCHAIN,
               'source_sha256':SOCKS.record_digest(before),'source_count':len(before),
               'xray_version':PROXY.XRAY_VERSION,'xray_source_sha256':SOCKS.record_digest(original_xray[1]),
               'shared_verdicts':sorted(IMPORTED.names(CORE))}
    with tempfile.TemporaryDirectory(prefix='routervpn-imported-connect-reality-') as temporary:
        workspace = Path(temporary).resolve()
        shared, original_shared = shared_sources(compiler, workspace, env)
        receipt['shared'] = {name:hashlib.sha256(raw).hexdigest() for name,raw in original_shared.items()}
        groups = {SHARED_PARSER:sorted(FILES)}
        if android:
            original_android = android_sources(workspace, env)
            groups[ANDROID_PARSER] = sorted(original_android[1])
            receipt['android'] = {name:hashlib.sha256(raw).hexdigest() for name,raw in original_android[1].items()}
        execute([compiler,'test','-mod=readonly','-json','-ldflags=-checklinkname=0',
                 '-tags',SOCKS.TAGS,'./experimental/libbox','-run','^('+'|'.join(groups)+')$',
                 '-count=1','-timeout=90s'], vendor, env, IMPORTED.names(groups), 600)
        receipt['native_verdicts'] = sorted(IMPORTED.names(groups))
        if android and captured_matrix(original_android[0],'android-') != original_android[1]:
            raise ValueError('Actual Android CONNECT REALITY source changed during native parsing')
        if captured_matrix(shared) != original_shared or source_receipt() != before or checked_sources(vendor) != prepared or PROXY.resolved_xray(compiler,vendor,env) != original_xray:
            raise ValueError('CONNECT REALITY original capture or prepared source changed during verification')
    print(json.dumps(receipt,sort_keys=True),flush=True)
    print('CONNECT REALITY: eighteen separate Local captures parsed; encrypted native traffic and device acceptance remain separate.',flush=True)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor',type=Path)
    parser.add_argument('--native-parsers',action='store_true',required=True)
    parser.add_argument('--android',action='store_true')
    args = parser.parse_args()
    run(args.vendor,args.android)
