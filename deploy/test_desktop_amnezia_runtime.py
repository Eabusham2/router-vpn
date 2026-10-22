#!/usr/bin/env python3
"""Execute the shipped native AmneziaWG CLI against isolated encrypted peers."""
from pathlib import Path
import argparse
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('amnezia_build', ROOT/'deploy/build-amnezia-runtime.py')
BUILD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BUILD)

def prove_original_packet_race(source, env):
    patch = BUILD.POLICY.AMNEZIA.PACKET
    captured = {name: (source/patch.COPY/name).read_bytes() for name in patch.PATCHES}
    try:
        for name, fixed in captured.items():
            (source/patch.COPY/name).write_bytes(patch.transform(name, fixed, reverse=True))
        control = subprocess.run(['go', 'test', '-race', '-ldflags=-checklinkname=0', '-tags='+BUILD.TAGS,
                                  '-count=1', '-timeout=30s', './protocol/routervpnamnezia',
                                  '-run', '^TestServerPacketConcurrentEndpoint$'],
                                 cwd=source, env=env, text=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, timeout=300)
    finally:
        for name, fixed in captured.items():
            (source/patch.COPY/name).write_bytes(fixed)
    patch.verify(source)
    if control.returncode != 1 or 'WARNING: DATA RACE' not in control.stdout or 'serverPacketConn' not in control.stdout:
        print(control.stdout)
        raise RuntimeError('Original sing packet endpoint did not fail the expected race regression')
    print('Verified negative control: original pinned SOCKS UDP endpoint fails the concurrent receive/reply regression', flush=True)

def test(source=None):
    target = subprocess.check_output(['go', 'env', 'GOHOSTOS', 'GOHOSTARCH'], text=True).split()
    target = '/'.join(target)
    with tempfile.TemporaryDirectory(prefix='router-vpn-desktop-amnezia-') as temporary:
        directory = Path(temporary)
        if source is None:
            source = directory/'core'
            BUILD.fetch_source(source)
        bundle = BUILD.build(target, directory/'bundle', source)
        binary = bundle/('sing-box-amnezia.exe' if target.startswith('windows/') else 'sing-box-amnezia')
        env = BUILD.environment(target)
        env['CGO_ENABLED'] = '1'
        env['ROUTERVPN_AWG_DESKTOP_CLI'] = str(binary)
        subprocess.run(['go', 'test', '-race', '-ldflags=-checklinkname=0', '-tags='+BUILD.TAGS,
                        '-count=2', '-timeout=90s', './protocol/routervpnamnezia', '-run',
                        '^Test(DesktopAmneziaCLIEncryptedTrafficAndOwnerShutdown|BindPreservesPacketFramingAndShortWriteRejection|ActualAmneziaUnconnectedUDPReply|ServerPacketConcurrentEndpoint|ServerPacketBlockedReplyDoesNotBlockReceive)$'],
                       cwd=source, env=env, check=True, timeout=300)
        prove_original_packet_race(source, env)
        BUILD.reuse(bundle, target, BUILD.digest(), BUILD.environment(target))
        env['ROUTERVPN_AWG_DESKTOP_BUNDLE'] = str(bundle)
        env['ROUTERVPN_VIA_ENTRY_NATIVE_CLI'] = str(binary)
        subprocess.run(['go', 'test', '-race', '-count=1', '-timeout=150s',
                        './cmd/client', '-run', '^Test(DesktopAmnezia|ViaEntry)'],
                       cwd=ROOT, env=env, check=True, timeout=300)
        print('Verified actual native desktop AWG TCP/UDP, IPv4/IPv6, wrong-key and owned shutdown on '+target, flush=True)
        print('Verified shipping controller direct/multihop graphs, captured engine selection, package integrity and relocation', flush=True)
        print('Verified private candidate SOCKS upstream success/refusal timing, exact graph policy, cancellation and owned cleanup', flush=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, help='owned disposable exact-pinned test core')
    arguments = parser.parse_args()
    test(arguments.source)
