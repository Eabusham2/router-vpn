#!/usr/bin/env python3
"""Execute captured native REALITY selected DNS over the pinned protocol peers.

This separate loopback protocol receipt does not replace physical interface,
TUN, imported composition, application or device acceptance.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import json

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


PROXY = module('udp443_proxy_receipts', 'test_mobile_imported_proxy_xray.py')
SOCKS = PROXY.SOCKS
MODES = ('reality-vision', 'reality-pq-vision')
FLOWS = ('xtls-rprx-vision', 'xtls-rprx-vision-udp443')
CASES = ('home-udp53', 'dot853', 'doh443', 'doh3-udp443', 'plain-vision-udp443',
         'wrong-dns-sni', 'wrong-dns-trust', 'wrong-dns-route', 'wrong-dns-port',
         'wrong-dns-path', 'wrong-reality-key', 'wrong-owner', 'cancel-before-query',
         'cancel-inflight', 'close-owner', 'replacement-owner')
PARENT = 'TestNativeXraySelectedDNSUDP443'
RECEIPT = 'TestNativeXrayUDP443DetectorReceipt'
NATIVE = {PARENT: [part for mode in MODES for part in (mode, *(mode + '/' + case for case in CASES))],
          RECEIPT: [], 'TestNativeXrayUDP443DoTProbeAdmission': []}
SHARED = {
    'TestVisionUDP443RetainsExplicitOriginalFlow': [mode + '/' + flow for mode in (*MODES, 'split', 'max') for flow in FLOWS],
    'TestVisionUDP443PreservesIndependentStartLayer': [mode + '/' + flow + '/' + layer for mode in MODES for flow in FLOWS for layer in ('aes-256-gcm', 'aes-256-gcm+xor-whitening')],
    'TestVisionUDP443DoesNotWidenFlowAdmission': [],
}
COPIES = {
    'mobile/applexray/outbound.go.tmpl': 'protocol/routervpnxray/outbound.go',
    'mobile/applexray/native_test.go.tmpl': 'protocol/routervpnxray/native_test.go',
    'mobile/applexray/traffic_test.go.tmpl': 'protocol/routervpnxray/traffic_test.go',
    'mobile/applexray/udp443_traffic_test.go.tmpl': 'protocol/routervpnxray/udp443_traffic_test.go',
}
GENERATION = (
    'server/scripts/generate-xray-pq.sh', 'server/scripts/preserve-generated-state.py',
    'server/init/noninteractive.sh', 'server/finalize/finalize.sh',
    'server/finalize/upgrade-safe.sh', 'server/finalize/ensure-profile-engines.sh',
    'server/install.sh', 'server/portainer-current.yaml', 'server/scripts/setup_center_guide.py',
    'server/scripts/test_ss_service_readiness.py',
    'server/scripts/create-bundle-json.py', 'server/scripts/ensure-node-proof.py',
    'server/scripts/atomic-private-batch.py', 'server/scripts/atomic-private-write.py',
    'server/scripts/private-directory.py', 'server/scripts/verified-regular-read.py',
    'server/scripts/ss_service_capability.py', 'configs/client/modes.json',
    'configs/client/logical-modes.json',
    'deploy/test_xray_udp443_generation.py',
)
TAGS = SOCKS.TAGS + ',routervpn_udp443_integration'
GENERATION_CASES = (
    'test_fresh_default_keeps_ordinary_vision',
    'test_explicit_opt_in_reaches_original_bundle_and_shared_compiler',
    'test_unset_preserves_independent_mixed_saved_choices',
    'test_legacy_original_flow_is_not_downgraded',
    'test_explicit_disable_keeps_server_identity',
    'test_missing_generated_client_recovers_only_saved_flow',
    'test_invalid_request_never_changes_authoritative_files',
    'test_malformed_or_inconsistent_originals_fail_before_adoption',
    'test_original_client_private_file_guards_remain_required',
    'test_candidate_engine_failure_keeps_previous_generation',
    'test_atomic_adoption_failure_rolls_back_client_flow_and_state',
    'test_actual_entrypoints_reject_invalid_request_or_saved_flow_before_writes',
    'test_readiness_checks_requested_flow_without_rewriting_sources',
)


def inputs():
    return sorted(set(PROXY.inputs()) | {ROOT / name for name in GENERATION} | {
        Path(__file__).resolve(), ROOT / 'deploy/test_native_xray_udp443_runner.py',
        ROOT / '.github/workflows/imported-socks-reality-native.yml',
    })


def source_receipt():
    result = {}
    for path in inputs():
        if path.is_symlink() or not path.is_file():
            raise ValueError('Native UDP443 lost an original generation or execution source: ' + str(path))
        result[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def checked_sources(vendor):
    records = SOCKS.checked_sources(vendor)
    for source, target in COPIES.items():
        SOCKS.check_file(vendor / target, (ROOT / source).read_bytes(), records, target)
    return records


def compile_image(compiler, vendor, workspace, env):
    binary = workspace / ('udp443-native.exe' if env['GOOS'] == 'windows' else 'udp443-native')
    status, output = SOCKS.run_command([
        compiler, 'test', '-mod=readonly', '-race', '-c', '-ldflags=-checklinkname=0',
        '-tags', TAGS, '-o', binary, './protocol/routervpnxray'], vendor, env, 600)
    if status or binary.is_symlink() or not binary.is_file():
        raise ValueError('Native UDP443 original pinned image did not compile:\n' + output[-24000:])
    return binary, hashlib.sha256(binary.read_bytes()).hexdigest()


def require_generation(output, status):
    records = re.findall(r'^(test_\w+) \(__main__\.VisionGeneration(?:\.[^ )]+)?\) \.\.\. (.+)$', output, re.MULTILINE)
    names = [name for name, verdict in records if verdict == 'ok']
    if status or len(records) != len(GENERATION_CASES) or len(names) != len(GENERATION_CASES) or set(names) != set(GENERATION_CASES):
        raise ValueError('Native UDP443 requires every actual generation, restoration and rollback verdict:\n' + output[-12000:])
    return sorted(names)


def generation(env):
    status, output = SOCKS.run_command([
        sys.executable, ROOT / 'deploy/test_xray_udp443_generation.py', '-v'], ROOT, env, 300)
    verdicts = require_generation(output, status)
    print(output, end='' if output.endswith('\n') else '\n', flush=True)
    return verdicts


def execute_native(compiler, vendor, env, image, digest, parent, expected):
    if image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
        raise ValueError('Native UDP443 image changed before execution')
    status, output = SOCKS.run_command([
        compiler, 'tool', 'test2json', '-t', '-p', 'routervpnxray', image,
        '-test.v', '-test.run=^' + parent + '$', '-test.count=1', '-test.timeout=90s'], vendor, env, 105)
    # Keep each original case's diagnostic even when strict verdict validation
    # rejects the matrix. A tail-only exception can omit an earlier TLS cause.
    print(output, end='' if output.endswith('\n') else '\n', flush=True)
    SOCKS.require_verdicts(output, status, expected)
    if image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
        raise ValueError('Native UDP443 image changed during execution')
    return {'sha256': digest, 'verdicts': list(expected)}


def run(vendor):
    vendor = vendor.resolve(strict=True)
    compiler = shutil.which('go')
    if not compiler:
        raise ValueError('Native UDP443 requires the pinned Go compiler')
    compiler = Path(compiler).resolve(strict=True)
    env = dict(os.environ, GOTOOLCHAIN=SOCKS.TOOLCHAIN, GOWORK='off')
    for key, value in (('GOMAXPROCS', '1'), ('GOGC', '5'), ('GOMEMLIMIT', '256MiB')):
        env.setdefault(key, value)
    if subprocess.check_output([compiler, 'env', 'GOVERSION'], env=env, text=True).strip() != SOCKS.TOOLCHAIN:
        raise ValueError('Native UDP443 compiler differs from the shipping toolchain')
    for key in ('GOOS', 'GOARCH'):
        env[key] = subprocess.check_output([compiler, 'env', 'GOHOST' + key[2:]], env=env, text=True).strip()
    original = source_receipt()
    prepared = checked_sources(vendor)
    resolved = PROXY.resolved_xray(compiler, vendor, env)
    subprocess.run([sys.executable, str(ROOT / 'deploy/test_native_xray_udp443_runner.py')], cwd=ROOT, env=env, check=True, timeout=30)
    generated = generation(env)
    status, output = SOCKS.run_command([
        compiler, 'test', '-mod=readonly', '-race', '-json', './internal/applexray',
        '-run', '^TestVisionUDP443', '-count=1', '-timeout=30s'], ROOT, env, 240)
    SOCKS.require_verdicts(output, status, SOCKS.IMPORTED.names(SHARED))
    print(output, end='' if output.endswith('\n') else '\n', flush=True)
    receipt = {'scope': 'native selected-DNS loopback protocol reference', 'core_pin': SOCKS.PIN,
               'xray_pin': SOCKS.XRAY.XRAY_PIN, 'xray_version': PROXY.XRAY_VERSION, 'toolchain': SOCKS.TOOLCHAIN,
               'source_count': len(original), 'source_sha256': SOCKS.record_digest(original),
               'core_count': len(prepared), 'core_sha256': SOCKS.record_digest(prepared),
               'shared_verdicts': sorted(SOCKS.IMPORTED.names(SHARED)),
               'generation_verdicts': generated,
               'physical_interface_proof': False, 'device_acceptance': False}
    with tempfile.TemporaryDirectory(prefix='routervpn-native-xray-udp443-') as temporary:
        workspace = Path(temporary)
        xray, xray_before, reference, reference_digest, overlay, instrumentation = SOCKS.build_reference(compiler, vendor, workspace, env)
        image, image_digest = compile_image(compiler, vendor, workspace, env)
        receipt['native'] = {}
        for parent, children in NATIVE.items():
            receipt['native'][parent] = execute_native(compiler, vendor, env, image, image_digest,
                parent, sorted(SOCKS.IMPORTED.names({parent: children})))
        if reference.is_symlink() or hashlib.sha256(reference.read_bytes()).hexdigest() != reference_digest or SOCKS.checked_xray(xray) != xray_before:
            raise ValueError('Native UDP443 original reference source or binary changed')
        SOCKS.check_reference_instrumentation(xray, workspace, overlay, instrumentation)
        if source_receipt() != original or checked_sources(vendor) != prepared or PROXY.resolved_xray(compiler, vendor, env) != resolved:
            raise ValueError('Native UDP443 lost the original source or prepared engine while executing')
        receipt['reference'] = {'sha256': reference_digest, 'xray_source_count': len(xray_before),
                                'xray_source_sha256': SOCKS.record_digest(xray_before),
                                'detector_instrumentation': instrumentation,
                                'detector_verdicts': list(SOCKS.REFERENCE_DETECTOR_TESTS)}
    print(json.dumps(receipt, sort_keys=True), flush=True)
    print('Native UDP443: exact selected DNS wire requests and responses, original captured flow and owner controls passed; physical interface and device acceptance remain separate.', flush=True)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    args = parser.parse_args()
    run(args.vendor)
