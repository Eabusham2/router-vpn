#!/usr/bin/env python3
"""Execute the exact native validator primitive in an owned private namespace.

This proves real signature validation, worker isolation and joined cancellation.
It does not authorize a resolver scope or replace the authenticated child/host
acceptance gate. The entire fixture runs in a new outer network namespace, so
enabling loopback cannot alter the build host's interfaces.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUNDLE = load('namespace_dnssec_bundle', 'deploy/desktop-dnssec-bundle.py')
UID = load('namespace_dnssec_owner', 'deploy/test_desktop_socket_uid.py')
TEMPLATES = ('standard_dnssec_linux.go.tmpl', 'standard_dnssec_native_linux_test.go.tmpl')
PARENT = 'TestRouterVPNDNSSECIsolatedNative'
CASES = (PARENT, *(PARENT+'/'+case for case in (
    'good.signed.test.', 'bogus.signed.test.', 'cancel.signed.test.',
    'unsealed-refusal', 'compiled-seal-refusal', 'anchor-length', 'anchor-total',
    'negative-domain-length')))
NAMESPACE = r'''
import fcntl,os,socket,struct,sys
before=sys.argv[1]
if os.readlink('/proc/self/ns/net')==before:
    raise RuntimeError('DNSSEC fixture did not enter its owned outer namespace')
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
request=struct.pack('16sH14s',b'lo',0,b'')
flags=struct.unpack('16sH14s',fcntl.ioctl(sock.fileno(),0x8913,request))[1]
if not flags&8:raise RuntimeError('DNSSEC fixture selected a non-loopback interface')
fcntl.ioctl(sock.fileno(),0x8914,struct.pack('16sH14s',b'lo',flags|1,b''))
sock.close()
os.execv(sys.argv[2],sys.argv[2:])
'''


def checked_sources(source):
    source = UID.PREP.checked_vendor(Path(source))
    records = {}
    for name in TEMPLATES:
        original = ROOT/'mobile/desktop'/name
        prepared = source/'cmd/sing-box'/('routervpn_'+name.removesuffix('.tmpl'))
        if original.is_symlink() or prepared.is_symlink() or prepared.read_bytes() != original.read_bytes():
            raise ValueError('DNSSEC namespace gate differs from its exact shipping template: '+name)
        records[name] = hashlib.sha256(original.read_bytes()).hexdigest()
    for package in ('common', 'linuxprocess', 'standardengine'):
        for original in sorted((ROOT/'internal'/package).glob('*.go')):
            prepared = source/'routervpn'/package/original.name
            raw = original.read_bytes()
            if original.is_symlink() or prepared.is_symlink() or prepared.read_bytes() != UID.PREP.relocated_shared_source(raw):
                raise ValueError('DNSSEC namespace foundation differs from shipping source: '+str(original))
            records[package+'/'+original.name] = hashlib.sha256(raw).hexdigest()
    return source, records


def require_verdicts(output):
    if re.search(r'^\s*--- (FAIL|SKIP):', output, re.M) or 'DATA RACE' in output:
        raise ValueError('DNSSEC namespace gate failed or skipped a required boundary')
    observed = re.findall(r'^\s*--- PASS: (\S+) \(', output, re.M)
    if sorted(observed) != sorted(CASES):
        raise ValueError('Missing, duplicate or foreign DNSSEC namespace verdict: '+repr(observed))


def execute(source, bundle, target, go='go', env=None):
    host = 'linux/'+{'x86_64':'amd64', 'aarch64':'arm64', 'arm64':'arm64'}.get(platform.machine(), '')
    if platform.system() != 'Linux' or target != host:
        raise ValueError('DNSSEC namespace gate requires its exact native Linux host')
    source, before = checked_sources(source)
    bundle = Path(bundle).resolve()
    receipt = BUNDLE.verify(bundle, target)
    captured = dict(os.environ if env is None else env, GOWORK='off')
    compiler, captured = UID.compiler_toolchain(source, go, captured)
    unshare = shutil.which('unshare', path=captured.get('PATH'))
    if unshare is None:
        raise ValueError('DNSSEC namespace fixture requires the native unshare tool')
    with tempfile.TemporaryDirectory(prefix='routervpn-dnssec-namespace-') as temporary, \
         tempfile.TemporaryDirectory(prefix='routervpn_dnssec_gate_', dir=source/'cmd') as package:
        temporary, package = Path(temporary).resolve(), Path(package).resolve()
        for name in TEMPLATES:
            shutil.copyfile(ROOT/'mobile/desktop'/name, package/name.removesuffix('.tmpl'))
        peer_source = temporary/'authority'
        peer_source.mkdir()
        for original, name in (('zone_fixture.go.tmpl','main.go'), ('fixture.go.mod','go.mod'), ('fixture.go.sum','go.sum')):
            shutil.copyfile(ROOT/'native/dnssec'/original, peer_source/name)
        peer = temporary/'signed-authority'
        UID.run([compiler, 'build', '-buildvcs=false', '-mod=readonly', '-p=1', '-o', peer, '.'],
                cwd=peer_source, env=captured, timeout=300)
        captured.update(ROUTERVPN_DNSSEC_NATIVE_LIBRARY=str(bundle/BUNDLE.LIBRARY),
                        ROUTERVPN_DNSSEC_NATIVE_PEER=str(peer))

        def compile_native(destination):
            UID.run([compiler, 'test', '-c', '-race', '-p=1', '-mod=readonly',
                     '-tags=with_purego,routervpn_dnssec_native', '-ldflags=-checklinkname=0',
                     '-o', destination, './'+package.relative_to(source).as_posix()],
                    cwd=source, env=captured, timeout=600)

        def native_run(binary, selected):
            command = [unshare, '--user', '--map-root-user', '--net', sys.executable, '-c', NAMESPACE,
                       os.readlink('/proc/self/ns/net'), binary, '-test.run', selected,
                       '-test.v', '-test.timeout=45s']
            return UID.run(command, cwd=temporary, env=captured, timeout=55)

        positive = temporary/'validator.test'
        compile_native(positive)
        if checked_sources(source)[1] != before:
            raise ValueError('DNSSEC shipping source changed during native compilation')
        output = native_run(positive, '^'+PARENT+'$')
        require_verdicts(output)
        print(output, end='' if output.endswith('\n') else '\n', flush=True)
        # Causal isolation control: creating the actual C worker only after
        # restoration must fail even when its cryptographic library is valid.
        implementation = package/'standard_dnssec_linux.go'
        raw = implementation.read_text()
        marker = '\t\tif s.api.start(s.native, spec.Name, uint32(len(spec.Name)), spec.Type) != 0 {'
        if raw.count(marker) != 1:
            raise ValueError('DNSSEC worker-start isolation mutation point changed')
        implementation.write_text(raw.replace(marker,
            '\t\tif err = unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); err != nil { return }\n'+marker))
        mutant = temporary/'validator-wrong-namespace.test'
        compile_native(mutant)
        try:
            native_run(mutant, '^'+PARENT+'$/^good[.]signed[.]test[.]$')
        except subprocess.CalledProcessError as error:
            refusal = error.output.decode('utf-8', errors='replace')
            if 'validator did not reach actual owned broker' not in refusal and 'actual validator pthread is not alone' not in refusal:
                raise ValueError('DNSSEC wrong-namespace control failed for another reason:\n'+refusal[-8192:]) from error
        else:
            raise ValueError('DNSSEC worker escaped the actual namespace control')
        if checked_sources(source)[1] != before or BUNDLE.verify(bundle, target) != receipt:
            raise ValueError('DNSSEC original source or package changed during native acceptance')
        print('Exact native DNSSEC signatures, isolated worker, joined cancellation and wrong-namespace causal passed', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('target', choices=BUNDLE.TARGETS)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    execute(args.source, args.bundle, args.target, args.go)
