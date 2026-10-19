#!/usr/bin/env python3
"""Prove native C Tor, protected PT drain, and host API linkage in pinned Libbox."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('routervpn_owned_tor', ROOT/'deploy/prepare-mobile-tor.py')
PREP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREP)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, vendor, environment, output, name, timeout=180):
    log = output/(name+'.log')
    with log.open('w') as stream:
        result = subprocess.run(command, cwd=vendor, env=environment, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(name+' failed:\n'+log.read_text(errors='replace')[-7000:])
    print('PASS native Tor outbound:', name, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--native-package', type=Path, required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    vendor, native_package = args.vendor.resolve(), args.native_package.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    package = PREP.TORPACK.PACKAGE.verify(native_package, 'host-test')
    library = native_package/'lib/libroutervpn_tor.so'
    native_hash = sha(library)
    sources = {str(path.relative_to(ROOT)): sha(path) for path in PREP.inputs()}
    environment = os.environ.copy()
    run([sys.executable, str(ROOT/'deploy/test_mobile_tor_dns_bootstrap.py'), '--vendor', str(vendor)],
        vendor, environment, args.output, 'native-dns-source-guard')
    PREP.prepare(vendor, args.go)
    first = (vendor/PREP.OWNER).read_bytes()
    PREP.prepare(vendor, args.go)
    if first != (vendor/PREP.OWNER).read_bytes():
        raise ValueError('Repeated native Tor preparation changed owned source')
    environment = os.environ.copy()
    run([args.go, 'test', '-mod=mod', '-race', '-count=1', '-timeout=90s',
         './protocol/routervpntor', './routervpn/mobiletor', './routervpn/torpt/...'],
        vendor, environment, args.output, 'single-runtime-transports')
    # Use the same compatibility option as the pinned native app build. This
    # links both the exact native CommandServer proof API and embedded notices.
    run([args.go, 'test', '-mod=readonly', '-ldflags=-checklinkname=0', '-run', '^$', './experimental/libbox'],
        vendor, environment, args.output, 'libbox-host-api')
    run([args.go, 'test', '-mod=readonly', '-race', '-count=1', '-ldflags=-checklinkname=0',
         '-run', '^TestRouterTorProof', '-timeout=60s', '.'],
        vendor, environment, args.output, 'captured-proof-request')
    environment = environment.copy()
    environment['CGO_LDFLAGS'] = '-L'+str(library.parent)+' -Wl,-rpath,'+str(library.parent)+' -lroutervpn_tor'
    for late in ('pt', 'plain'):
        environment['ROUTERVPN_TOR_TEST_LATE'] = late
        run([args.go, 'test', '-mod=readonly', '-race', '-count=1', '-timeout=120s',
             '-tags', 'routervpn_tor_native_test', '-run', '^TestNativeTorOutboundReusesResidentOnlyAfterRealPTDrain$',
             '-v', './protocol/routervpntor'],
            vendor, environment, args.output, 'real-native-'+late+'-session-drain')
    if sha(library) != native_hash or sources != {str(path.relative_to(ROOT)): sha(path) for path in PREP.inputs()}:
        raise ValueError('Native Tor source or C runtime changed during its gate')
    PREP.TORPACK.PACKAGE.verify(native_package, 'host-test')
    for name in ('go.mod', 'go.sum'):
        (args.output/name).write_bytes((vendor/name).read_bytes())
    record = dict(schema=1, core=PREP.CORE, go='go1.26.3', sources=sources,
                  native_library_sha256=native_hash, native_package=package,
                  prepared_source_sha256=PREP.digest(),
                  module_sha256={name: sha(vendor/name) for name in ('go.mod', 'go.sum')},
                  verified=dict(native_resident_invocations=2, native_resident_sessions=48, native_late_dial_quarantine=True,
                                plain_native_tls_through_captured_tcp=True, plain_late_dial_quarantine=True,
                                stable_private_state_across_runtime_roots=True, captured_cancelable_proof_requests=True,
                                actual_pt_workers=True, local_pt_application_traffic=True, captured_snowflake_dns_and_io=True,
                                bootstrap_source_guard=True,
                                libbox_host_api_linked=True, public_tor_traffic=False,
                                mobile_tor_capability_enabled=False))
    (args.output/'tor-outbound-evidence.json').write_text(json.dumps(record, indent=2, sort_keys=True)+'\n')
    print('Saved native Tor outbound evidence:', args.output/'tor-outbound-evidence.json', flush=True)


if __name__ == '__main__':
    main()
