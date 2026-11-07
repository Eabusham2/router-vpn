#!/usr/bin/env python3
"""Require exact encrypted WG/AWG/OpenVPN entries to paired REALITY references.

This separate Linux gate consumes the shared source producer's original 36
captures. The mobile/Android/Apple parser gate and host/device admission remain
independent. A missing physical interface is a failure, never a skipped proof.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


CAPTURE = module('packet_reference_captured_sources', 'test_mobile_imported_packet_xray.py')
CONNECT = module('packet_reference_retained_connect', 'test_mobile_imported_connect_xray.py')
NODE = module('packet_reference_shipping_sources', 'test_desktop_node_physical.py')
SOCKS = CONNECT.SOCKS
TAGS = SOCKS.TAGS+',routervpn_openvpn_remote_test'
PEER_COPIES = (
    ('mobile/desktop/node_imported_packet_xray_test.go.tmpl', 'protocol/routervpnamnezia/routervpn_imported_packet_xray_test.go'),
    ('mobile/desktop/node_imported_packet_xray_dns_test.go.tmpl', 'protocol/routervpnamnezia/routervpn_imported_packet_xray_dns_test.go'),
)
SUPPORT = {
    'TestRouterVPNImportedPacketRealityPhysicalOwner': ['tcp','udp'],
    'TestRouterVPNImportedCONNECTRealityDoTProbeAdmission': [],
    'TestRouterVPNImportedCONNECTRealityDNSCertificateRefusal': [],
}


def cases(kind):
    children = []
    for first in CAPTURE.LAYERS:
        for final in CAPTURE.LAYERS:
            label = first+'--'+final
            faults = ['success','cancel','close-owner','replacement-owner']
            if first == final == 'off':
                faults += ['entry-route','wrong-entry-ip','final-reality-key','final-user',
                           'final-route','dns-route','final-identity','final-token']
                if kind.startswith('openvpn-'):
                    faults += ['entry-auth']
                else:
                    faults += ['entry-private-key','entry-public-key','entry-psk']
                    if kind == 'amneziawg': faults += ['entry-awg-parameter']
            if first != 'off': faults += ['entry-layer-key']
            if first == 'aes-256-gcm+xor-whitening': faults += ['entry-layer-whitening']
            if final != 'off': faults += ['final-layer-key']
            if final == 'aes-256-gcm+xor-whitening': faults += ['final-layer-whitening']
            children += [label, *(label+'/'+fault for fault in faults)]
    return children


PEERS = {'TestRouterVPNImported'+label+'RealityNativeTraffic': cases(kind)
         for kind,label in (('wireguard','WireGuard'),('amneziawg','Amnezia'),
                            ('openvpn-tcp','OpenVPNTCP'),('openvpn-udp','OpenVPNUDP'))}
DNS_PARENT = 'TestRouterVPNImportedPacketRealitySelectedDNS'
PEERS[DNS_PARENT] = [name for kind in CAPTURE.KINDS for name in
                   (kind, *(kind+'/'+leaf for leaf in CONNECT.DNS_CASES))]
GROUPS = {**SUPPORT, **PEERS}


def inputs():
    return sorted(set(CONNECT.inputs()) | set(CAPTURE.inputs()) | set(NODE.PREP.inputs()) | {
        Path(__file__).resolve(), ROOT/'deploy/test_native_imported_packet_xray_runner.py',
        ROOT/'deploy/test_desktop_node_physical.py',
        ROOT/'.github/workflows/imported-packet-reality-native.yml'})


def source_receipt():
    records = {}
    for path in inputs():
        if path.is_symlink() or not path.is_file():
            raise ValueError('Packet REALITY lost an original source dependency')
        records[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def checked_sources(vendor):
    records = CONNECT.checked_sources(vendor, True)
    checked, native = NODE.checked_sources(vendor)
    if checked != vendor:
        raise ValueError('Packet REALITY changed its original prepared directory')
    records.update({'native/'+key:value for key,value in native.items()})
    for source, target in PEER_COPIES:
        SOCKS.check_file(vendor/target, (ROOT/source).read_bytes(), records, target)
    return records


def compile_image(compiler, vendor, workspace, env):
    image = workspace/'packet-reality-peers'
    status, output = CONNECT.run_command([compiler,'test','-mod=readonly','-race','-c',
        '-ldflags=-checklinkname=0','-tags',TAGS,'-o',image,'./protocol/routervpnamnezia'], vendor, env, 600)
    CONNECT.print_output(output)
    if status or image.is_symlink() or not image.is_file():
        raise ValueError('Packet REALITY native image did not compile')
    return image, hashlib.sha256(image.read_bytes()).hexdigest()


def discover_roots(compiler, vendor, env, image, digest):
    if image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
        raise ValueError('Packet REALITY image changed before root discovery')
    status, output = CONNECT.run_command([image,'-test.list=^('+'|'.join(GROUPS)+')$'], vendor, env, 30)
    CONNECT.print_output(output)
    observed = output.splitlines()
    if status or len(observed) != len(GROUPS) or set(observed) != set(GROUPS):
        raise ValueError('Packet REALITY compiled roots are missing, duplicated or moved')
    if image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
        raise ValueError('Packet REALITY image changed during root discovery')
    return sorted(observed)


def reference_stage(compiler, vendor, workspace, env):
    xray, original, binary, digest, overlay, instrumentation = CONNECT.build_reference(compiler,vendor,workspace,env)
    image, image_digest = compile_image(compiler,vendor,workspace,env)
    roots = discover_roots(compiler,vendor,env,image,image_digest)
    result = {'compiled_roots':roots,'support':{},'peers':{}}
    for group, parents in (('support',SUPPORT),('peers',PEERS)):
        for parent, children in parents.items():
            expected = sorted(CAPTURE.IMPORTED.names({parent:children}))
            result[group][parent] = CONNECT.execute_image(compiler,vendor,env,image,image_digest,
                parent,expected,timeout=90 if group=='support' else 180)
    if binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest()!=digest or SOCKS.checked_xray(xray)!=original:
        raise ValueError('Packet REALITY original reference source or image changed')
    SOCKS.check_reference_instrumentation(xray,workspace,overlay,instrumentation)
    result['reference'] = {'sha256':digest,'source_sha256':SOCKS.record_digest(original),
        'detector_instrumentation':instrumentation,'detector_verdicts':list(SOCKS.REFERENCE_DETECTOR_TESTS)}
    return result


def run(vendor):
    if platform.system() != 'Linux':
        raise ValueError('Packet REALITY requires its original Linux encrypted reference host')
    vendor = vendor.resolve(strict=True)
    compiler = shutil.which('go')
    if not compiler:
        raise ValueError('Packet REALITY requires the shipping Go compiler')
    compiler = Path(compiler).resolve(strict=True)
    env = dict(os.environ,GOTOOLCHAIN=SOCKS.TOOLCHAIN,GOWORK='off')
    for key,value in (('GOMAXPROCS','1'),('GOGC','5'),('GOMEMLIMIT','256MiB')): env.setdefault(key,value)
    if subprocess.check_output([compiler,'env','GOVERSION'],env=env,text=True).strip() != SOCKS.TOOLCHAIN:
        raise ValueError('Packet REALITY compiler differs from the shipping toolchain')
    for key in ('GOOS','GOARCH'):
        env[key] = subprocess.check_output([compiler,'env','GOHOST'+key[2:]],env=env,text=True).strip()
    if env['GOOS'] != 'linux':
        raise ValueError('Packet REALITY requires a matching native Linux compiler')
    before, prepared = source_receipt(), checked_sources(vendor)
    original_xray = CONNECT.PROXY.resolved_xray(compiler,vendor,env)
    subprocess.run([sys.executable,str(ROOT/'deploy/test_native_imported_packet_xray_runner.py')],
                   cwd=ROOT,env=env,check=True,timeout=30)
    receipt = {'scope':'native-encrypted-packet-reference','core_pin':SOCKS.PIN,'toolchain':SOCKS.TOOLCHAIN,
               'source_sha256':SOCKS.record_digest(before),'source_count':len(before),
               'prepared_sha256':SOCKS.record_digest(prepared),'prepared_count':len(prepared),
               'xray_version':CONNECT.PROXY.XRAY_VERSION,'xray_source_sha256':SOCKS.record_digest(original_xray[1])}
    with tempfile.TemporaryDirectory(prefix='routervpn-native-packet-reality-') as temporary:
        workspace = Path(temporary).resolve()
        shared = workspace/'shared';shared.mkdir()
        env[CAPTURE.SHARED_ENV],env[CAPTURE.REQUIRE_ENV] = str(shared),'1'
        # Execute the original producer's exact inventory through the complete
        # diagnostic wrapper; no alternate capture implementation is introduced.
        expected = CAPTURE.IMPORTED.names(CAPTURE.CORE)
        CONNECT.execute([compiler,'test','-mod=readonly','-race','-json','./internal/mobilemultihop',
            '-run','^('+'|'.join(CAPTURE.CORE)+')$','-count=1','-timeout=60s'],ROOT,env,expected,240)
        original = CAPTURE.captured_matrix(shared)
        receipt['shared_verdicts'] = sorted(expected)
        receipt['shared'] = {name:hashlib.sha256(raw).hexdigest() for name,raw in original.items()}
        receipt.update(reference_stage(compiler,vendor,workspace,env))
        if CAPTURE.captured_matrix(shared)!=original or source_receipt()!=before or checked_sources(vendor)!=prepared or CONNECT.PROXY.resolved_xray(compiler,vendor,env)!=original_xray:
            raise ValueError('Packet REALITY original capture or prepared source changed during execution')
    print(json.dumps(receipt,sort_keys=True),flush=True)
    print('Packet REALITY: original 36 captures and all encrypted references passed; host/device acceptance remains separate.',flush=True)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor',type=Path)
    run(parser.parse_args().vendor)
