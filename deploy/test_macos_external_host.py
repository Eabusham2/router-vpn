#!/usr/bin/env python3
"""Execute retained ordinary external hosts on an explicitly disposable macOS CI host.

The actual installed supervisor/controller consumes a complete private signed
copy of the native bundle. Real independent SS2022, HTTP, HTTPS, Hysteria2,
WireGuard, AmneziaWG and authenticated SOCKS5 peers exercise selected DNS, public-exit TLS, utun MTU, captured PF reference and
joined Disconnect. This gate temporarily installs only its fingerprint-bound
peer root in the native system keychain and removes it after all clients join.
It must never be selected implicitly by an ordinary developer bundle build.
"""
from pathlib import Path
from collections import Counter
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FLAG = 'ROUTERVPN_DARWIN_NATIVE_HOST_ACCEPTANCE'
POSITIVE_CASES = ('shadowsocks', 'http-connect', 'https-connect', 'hysteria2', 'hysteria2-aes', 'hysteria2-aes-xor', 'wireguard', 'wireguard-always', 'wireguard-auto', 'socks5', 'socks5-always', 'amneziawg-fast', 'amneziawg-fast-always', 'amneziawg-strong', 'amneziawg-strong-always', 'openvpn-tcp', 'openvpn-tcp-always', 'openvpn-udp', 'openvpn-udp-always', 'openvpn-tcp-fallback', 'openvpn-tcp-fallback-always', 'openvpn-mixed-fallback', 'openvpn-mixed-fallback-always', 'wg-entry-ss', 'wg-entry-ss-always', 'awg-entry-ss-fast', 'awg-entry-ss-fast-always', 'awg-entry-ss-strong', 'awg-entry-ss-strong-always', 'wg-entry-http', 'wg-entry-http-always', 'wg-entry-https', 'wg-entry-https-always', 'awg-entry-http-fast', 'awg-entry-http-fast-always', 'awg-entry-http-strong', 'awg-entry-http-strong-always', 'awg-entry-https-fast', 'awg-entry-https-fast-always', 'awg-entry-https-strong', 'awg-entry-https-strong-always', 'wg-entry-hysteria2', 'wg-entry-hysteria2-always', 'awg-entry-hysteria2-fast', 'awg-entry-hysteria2-fast-always', 'awg-entry-hysteria2-strong', 'awg-entry-hysteria2-strong-always', 'wg-entry-socks5', 'wg-entry-socks5-always', 'awg-entry-socks5-fast', 'awg-entry-socks5-fast-always', 'awg-entry-socks5-strong', 'awg-entry-socks5-strong-always', 'wg-entry-hysteria2-aes', 'wg-entry-hysteria2-aes-always', 'wg-entry-hysteria2-aes-xor', 'wg-entry-hysteria2-aes-xor-always', 'awg-entry-hysteria2-fast-aes', 'awg-entry-hysteria2-fast-aes-always', 'awg-entry-hysteria2-fast-aes-xor', 'awg-entry-hysteria2-fast-aes-xor-always', 'awg-entry-hysteria2-strong-aes', 'awg-entry-hysteria2-strong-aes-always', 'awg-entry-hysteria2-strong-aes-xor', 'awg-entry-hysteria2-strong-aes-xor-always', 'wg-entry-wireguard', 'wg-entry-wireguard-always', 'awg-entry-wireguard-fast', 'awg-entry-wireguard-fast-always', 'awg-entry-wireguard-strong', 'awg-entry-wireguard-strong-always', 'wg-entry-amneziawg-fast', 'wg-entry-amneziawg-fast-always', 'wg-entry-amneziawg-strong', 'wg-entry-amneziawg-strong-always', 'awg-entry-fast-amneziawg-fast', 'awg-entry-fast-amneziawg-fast-always', 'awg-entry-fast-amneziawg-strong', 'awg-entry-fast-amneziawg-strong-always', 'awg-entry-strong-amneziawg-fast', 'awg-entry-strong-amneziawg-fast-always', 'awg-entry-strong-amneziawg-strong', 'awg-entry-strong-amneziawg-strong-always')
NEGATIVE_CASES = ('hysteria2-aes-wrong-layer-key', 'hysteria2-aes-wrong-inner-key', 'hysteria2-aes-xor-wrong-layer-key', 'hysteria2-aes-xor-wrong-inner-key', 'hysteria2-aes-xor-wrong-whitening', 'wireguard-wrong-client-key', 'wireguard-wrong-psk', 'wireguard-wrong-dns', 'wireguard-wrong-trust', 'wireguard-wrong-exit', 'socks5-wrong-password', 'socks5-auth-downgrade', 'socks5-relay-domain', 'socks5-control-eof', 'socks5-wrong-dns', 'socks5-wrong-trust', 'socks5-wrong-exit', 'amneziawg-fast-wrong-client-key', 'amneziawg-strong-wrong-psk', 'amneziawg-fast-wrong-parameters', 'amneziawg-strong-wrong-parameters', 'amneziawg-strong-wrong-dns', 'amneziawg-strong-wrong-trust', 'amneziawg-strong-wrong-exit', 'openvpn-tcp-wrong-control', 'openvpn-udp-wrong-control', 'openvpn-tcp-wrong-provider-trust', 'openvpn-udp-wrong-password', 'openvpn-tcp-wrong-username', 'openvpn-udp-wrong-dns', 'openvpn-tcp-wrong-trust', 'openvpn-udp-wrong-exit', 'wg-entry-ss-wrong-entry-key', 'wg-entry-ss-wrong-entry-public', 'wg-entry-ss-wrong-exit-key', 'wg-entry-ss-wrong-dns', 'wg-entry-ss-wrong-trust', 'wg-entry-ss-wrong-exit', 'awg-entry-ss-fast-wrong-entry-key', 'awg-entry-ss-strong-wrong-entry-psk', 'awg-entry-ss-fast-wrong-entry-parameters', 'awg-entry-ss-strong-wrong-entry-parameters', 'awg-entry-ss-strong-wrong-entry-public', 'awg-entry-ss-strong-wrong-exit-key', 'awg-entry-ss-strong-wrong-dns', 'awg-entry-ss-strong-wrong-trust', 'awg-entry-ss-strong-wrong-exit', 'wg-entry-http-wrong-entry-key', 'wg-entry-http-wrong-exit-username', 'wg-entry-http-wrong-exit-key', 'wg-entry-http-wrong-dns', 'wg-entry-http-wrong-exit', 'wg-entry-https-wrong-entry-public', 'wg-entry-https-wrong-exit-server-name', 'wg-entry-https-wrong-exit-key', 'wg-entry-https-wrong-trust', 'awg-entry-http-fast-wrong-entry-parameters', 'awg-entry-https-strong-wrong-entry-parameters', 'awg-entry-https-strong-wrong-exit-key', 'wg-entry-hysteria2-wrong-entry-key', 'wg-entry-hysteria2-wrong-entry-public', 'wg-entry-hysteria2-wrong-exit-key', 'wg-entry-hysteria2-wrong-exit-server-name', 'wg-entry-hysteria2-wrong-exit-address', 'wg-entry-hysteria2-wrong-dns', 'wg-entry-hysteria2-wrong-trust', 'wg-entry-hysteria2-wrong-exit', 'awg-entry-hysteria2-fast-wrong-entry-parameters', 'awg-entry-hysteria2-strong-wrong-entry-parameters', 'awg-entry-hysteria2-strong-wrong-entry-psk', 'wg-entry-socks5-wrong-entry-key', 'wg-entry-socks5-wrong-entry-public', 'wg-entry-socks5-wrong-exit-username', 'wg-entry-socks5-wrong-exit-key', 'wg-entry-socks5-auth-downgrade', 'wg-entry-socks5-relay-domain', 'wg-entry-socks5-control-eof', 'wg-entry-socks5-relay-route', 'wg-entry-socks5-wrong-exit-address', 'wg-entry-socks5-wrong-dns', 'wg-entry-socks5-wrong-trust', 'wg-entry-socks5-wrong-exit', 'awg-entry-socks5-fast-wrong-entry-parameters', 'awg-entry-socks5-strong-wrong-entry-parameters', 'awg-entry-socks5-strong-wrong-entry-psk', 'wg-entry-hysteria2-aes-wrong-entry-key', 'wg-entry-hysteria2-aes-wrong-layer-key', 'wg-entry-hysteria2-aes-wrong-inner-key', 'wg-entry-hysteria2-aes-wrong-dns', 'wg-entry-hysteria2-aes-wrong-trust', 'wg-entry-hysteria2-aes-wrong-exit', 'wg-entry-hysteria2-aes-xor-wrong-entry-public', 'wg-entry-hysteria2-aes-xor-wrong-layer-key', 'wg-entry-hysteria2-aes-xor-wrong-inner-key', 'wg-entry-hysteria2-aes-xor-wrong-whitening', 'wg-entry-hysteria2-aes-xor-wrong-layer-route', 'awg-entry-hysteria2-fast-aes-wrong-entry-parameters', 'awg-entry-hysteria2-fast-aes-wrong-layer-key', 'awg-entry-hysteria2-strong-aes-xor-wrong-entry-psk', 'awg-entry-hysteria2-strong-aes-xor-wrong-layer-key', 'awg-entry-hysteria2-strong-aes-xor-wrong-whitening', 'wg-entry-wireguard-wrong-entry-key', 'wg-entry-wireguard-wrong-entry-psk', 'wg-entry-wireguard-wrong-entry-public', 'wg-entry-wireguard-wrong-exit-key', 'wg-entry-wireguard-wrong-exit-peer-key', 'wg-entry-wireguard-wrong-exit-psk', 'wg-entry-wireguard-wrong-exit-address', 'wg-entry-wireguard-wrong-dns', 'wg-entry-wireguard-wrong-trust', 'wg-entry-wireguard-wrong-exit', 'awg-entry-wireguard-fast-wrong-entry-parameters', 'awg-entry-wireguard-strong-wrong-entry-parameters', 'awg-entry-wireguard-strong-wrong-entry-psk', 'awg-entry-wireguard-strong-wrong-exit-key', 'awg-entry-wireguard-strong-wrong-exit-peer-key', 'awg-entry-wireguard-strong-wrong-exit-psk', 'wg-entry-amneziawg-fast-wrong-exit-key', 'wg-entry-amneziawg-fast-wrong-exit-peer-key', 'wg-entry-amneziawg-fast-wrong-exit-psk', 'wg-entry-amneziawg-fast-wrong-exit-parameters', 'wg-entry-amneziawg-fast-wrong-exit-padding', 'wg-entry-amneziawg-fast-wrong-exit-address', 'wg-entry-amneziawg-fast-wrong-dns', 'wg-entry-amneziawg-fast-wrong-trust', 'wg-entry-amneziawg-fast-wrong-exit', 'wg-entry-amneziawg-strong-wrong-exit-key', 'wg-entry-amneziawg-strong-wrong-exit-peer-key', 'wg-entry-amneziawg-strong-wrong-exit-psk', 'wg-entry-amneziawg-strong-wrong-exit-parameters', 'wg-entry-amneziawg-strong-wrong-exit-padding', 'wg-entry-amneziawg-strong-wrong-exit-address', 'wg-entry-amneziawg-strong-wrong-dns', 'wg-entry-amneziawg-strong-wrong-trust', 'wg-entry-amneziawg-strong-wrong-exit', 'awg-entry-fast-amneziawg-strong-wrong-entry-parameters', 'awg-entry-strong-amneziawg-fast-wrong-entry-parameters', 'awg-entry-strong-amneziawg-strong-wrong-entry-psk', 'wg-entry-amneziawg-strong-wrong-entry-key', 'wg-entry-amneziawg-strong-wrong-entry-psk', 'wg-entry-amneziawg-strong-wrong-entry-public')
POSITIVE_CASES += ('wg-entry-openvpn-tcp', 'wg-entry-openvpn-tcp-always', 'wg-entry-openvpn-udp', 'wg-entry-openvpn-udp-always', 'wg-entry-openvpn-tcp-fallback', 'wg-entry-openvpn-tcp-fallback-always', 'wg-entry-openvpn-mixed-fallback', 'wg-entry-openvpn-mixed-fallback-always', 'awg-entry-fast-openvpn-tcp', 'awg-entry-fast-openvpn-tcp-always', 'awg-entry-fast-openvpn-udp', 'awg-entry-fast-openvpn-udp-always', 'awg-entry-fast-openvpn-tcp-fallback', 'awg-entry-fast-openvpn-tcp-fallback-always', 'awg-entry-fast-openvpn-mixed-fallback', 'awg-entry-fast-openvpn-mixed-fallback-always', 'awg-entry-strong-openvpn-tcp', 'awg-entry-strong-openvpn-tcp-always', 'awg-entry-strong-openvpn-udp', 'awg-entry-strong-openvpn-udp-always', 'awg-entry-strong-openvpn-tcp-fallback', 'awg-entry-strong-openvpn-tcp-fallback-always', 'awg-entry-strong-openvpn-mixed-fallback', 'awg-entry-strong-openvpn-mixed-fallback-always')
NEGATIVE_CASES += ('wg-entry-openvpn-tcp-wrong-control', 'wg-entry-openvpn-udp-wrong-control', 'wg-entry-openvpn-tcp-wrong-provider-trust', 'wg-entry-openvpn-udp-wrong-password', 'wg-entry-openvpn-tcp-wrong-username', 'wg-entry-openvpn-udp-wrong-dns', 'wg-entry-openvpn-tcp-wrong-trust', 'wg-entry-openvpn-udp-wrong-exit', 'wg-entry-openvpn-udp-wrong-exit-address', 'wg-entry-openvpn-tcp-wrong-entry-key', 'wg-entry-openvpn-udp-wrong-entry-psk', 'wg-entry-openvpn-tcp-wrong-entry-public', 'awg-entry-fast-openvpn-udp-wrong-entry-parameters', 'awg-entry-strong-openvpn-tcp-wrong-entry-parameters', 'awg-entry-strong-openvpn-udp-wrong-entry-psk')
CASES = POSITIVE_CASES + NEGATIVE_CASES
TEST = 'TestMacOSRetainedExternalNativeSealedProtocols'
MTU_RECEIPT = 'actual sealed Darwin WireGuard MTU accepted: automatic changed utun, transferred bytes, original Cancel rollback joined, Retest committed and original runtime PF retained'
POLICY_TESTS = ('TestSpeedLabDirectLayeredHysteriaRestoreRejectsChangedCapturedLayer', 'TestSpeedLabExternalRestoreSealRetainsOriginalOwner', 'TestDesktopExternalPacketEntryHysteriaLayersRetainBothSourcesAndMeasurementOwner', 'TestDesktopExternalPacketEntryHysteriaLayersRestoreKeepsCompleteSourceAndNewSession', 'TestDesktopExternalPacketEntryHysteriaLayersPreserveUnsupportedGraphs', 'TestDesktopMacOSHysteriaLayersRetainCompleteSavedPolicy', 'TestDesktopMacOSHysteriaLayersPreserveUnsupportedGraphBoundaries', 'TestDesktopMacOSWireGuardRetainsCapturedSourceAndGraphBoundary', 'TestDesktopMacOSSOCKSRetainsCapturedSourceAndGraphBoundary', 'TestDesktopMacOSAmneziaRetainsCapturedSourceAndGraphBoundary', 'TestDesktopMacOSOpenVPNSourceKeepsExactSavedImport', 'TestDesktopExternalWireGuardEntryRetainsBothSourcesAndMeasurementOwner', 'TestDesktopExternalWireGuardEntryRestoreKeepsCompleteSourceAndNewSession', 'TestDesktopExternalAmneziaEntryRetainsBothSourcesAndMeasurementOwner', 'TestDesktopExternalAmneziaEntryRestoreKeepsCompleteSourceAndNewSession', 'TestSpeedLabHTTPTestCancellationRestoresWholeProvedConnection', 'TestSpeedLabStaleRestoreCannotStopOrOverwriteReplacement', 'TestSpeedLabCleanupFailureRetainsOwnerAndNeverClaimsRestore', 'TestSpeedLabRestoreRequiresFreshProofAndNetwork', 'TestDesktopExternalPacketEntryCONNECTRetainsBothSourcesAndMeasurementOwner', 'TestDesktopExternalPacketEntryCONNECTRestoreKeepsCompleteSourceAndNewSession', 'TestDesktopExternalPacketEntryHysteriaRetainsBothSourcesAndMeasurementOwner', 'TestDesktopExternalPacketEntryHysteriaRestoreKeepsCompleteSourceAndNewSession', 'TestDesktopExternalPacketEntrySOCKSRetainsBothSourcesAndMeasurementOwner', 'TestDesktopExternalPacketEntrySOCKSRestoreKeepsCompleteSourceAndNewSession', 'TestDesktopExternalPacketEntryWireGuardRetainsBothSourcesAndMeasurementOwner', 'TestDesktopExternalPacketEntryWireGuardRestoreKeepsCompleteSourceAndNewSession', 'TestDesktopExternalPacketEntryWireGuardPreservesUnsupportedGraphs', 'TestDesktopExternalPacketEntryAmneziaRetainsBothSourcesAndMeasurementOwner', 'TestDesktopExternalPacketEntryAmneziaRestoreKeepsCompleteSourceAndNewSession', 'TestDesktopExternalPacketEntryAmneziaPreservesUnsupportedGraphs')
POLICY_TESTS += ('TestDesktopExternalPacketEntryOpenVPNRetainsBothSourcesAndMeasurementOwner', 'TestDesktopExternalPacketEntryOpenVPNRestoreKeepsCompleteSourceAndNewSession', 'TestDesktopExternalPacketEntryOpenVPNPreservesUnsupportedGraphs')
PEER_TAGS = 'with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego,routervpn_darwin_external_host'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONTROLLER = load('macos_external_controller_runner', 'test_macos_controller_privilege.py')
BUILD = load('macos_external_native_build', 'build-native-runtime.py')
NODE = load('macos_external_native_peer_source', 'test_desktop_node_physical.py')


def sha(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError('Native host source/image must be one regular original file')
    value = hashlib.sha256(path.read_bytes()).hexdigest()
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('Native host source/image changed while hashing')
    return value


def source_identity(core):
    core, owned = NODE.checked_sources(core)
    app = CONTROLLER.source_identity()
    for name in ('deploy/test_macos_external_host.py', 'deploy/test_macos_external_host_runner.py',
                 'deploy/seal-native-runtime.py', 'configs/client/modes.json',
                 'mobile/desktop/node_layer_peer_test.go.tmpl', 'mobile/desktop/node_darwin_external_peer_test.go.tmpl',
                 'mobile/desktop/node_external_hysteria_layer_installed_test.go.tmpl', 'mobile/desktop/node_external_wireguard_installed_test.go.tmpl', 'mobile/desktop/node_external_amnezia_installed_test.go.tmpl', 'mobile/desktop/node_external_openvpn_installed_test.go.tmpl'):
        app[name] = sha(ROOT/name)
    files = [core/'go.mod', core/'go.sum', *core.glob('*.go')]
    for directory in ('protocol/routervpnamnezia', 'routervpn', 'experimental/libbox/routervpn'):
        files.extend((core/directory).rglob('*.go'))
    return dict(application=app, peer={**owned, **{str(p.relative_to(core)): sha(p) for p in sorted(set(files))}})


def success_receipt(case):
    mtu = '1280' if case == 'wireguard-auto' or '-entry-' in case and '-openvpn-' in case else ('1328' if '-amneziawg-' in case and '-entry-' in case else ('1360' if '-entry-wireguard' in case else '1376'))
    return 'actual sealed Darwin ordinary host accepted '+case+': native child, selected DNS, exit proof, MTU'+mtu+', original PF retirement and controller join'


def refusal_receipt(case):
    if case.startswith(('wg-entry-', 'awg-entry-')):
        return 'actual sealed Darwin packet entry refused '+case+': first encrypted peer reached, expected entry or final proof boundary rejected, original physical UDP PF and utun retired, controller joined'
    if case.startswith('openvpn-'):
        return 'actual sealed Darwin OpenVPN refused '+case+': actual native encrypted provider reached, expected authentication or proof boundary rejected, original ordered PF tuples and utun retired, controller joined'
    if case.startswith('amneziawg-'):
        return 'actual sealed Darwin AmneziaWG refused '+case+': actual encrypted peer and eleven-parameter readback reached, expected proof boundary rejected, original UDP PF and utun retired, controller joined'
    if case.startswith('socks5-'):
        return 'actual sealed Darwin SOCKS refused '+case+': actual peer reached, expected association or proof boundary rejected, original control UDP PF and utun retired, controller joined'
    if case.startswith('wireguard-'):
        return 'actual sealed Darwin WireGuard refused '+case+': encrypted peer reached, expected proof boundary rejected, native PF reference and utun retired, original controller joined'
    return 'actual sealed Darwin layer refused '+case+': encrypted peer reached, no DNS or exit proof, native PF reference and utun retired, original controller joined'


def check_verdict(output):
    if not isinstance(output, str) or re.search(
            r'(?im)^\s*(?:--- (?:FAIL|SKIP):|FAIL(?:\s|$)|SKIP(?:\s|$)|WARNING: DATA RACE|panic:|fatal error:)|\[build failed\]', output):
        raise ValueError('Native Darwin host output contains failure/skip/race/incomplete evidence')
    # Count only exact anchored native lines once. Re-scanning the complete
    # output per required case made the exhaustive mutation gate exceed its
    # original bounded runner budget as the native inventory grew.
    verdicts, receipts = Counter(), Counter()
    for line in output.split('\n'):
        verdict = re.fullmatch(r'(    )?--- PASS: (.+) \([0-9]+(?:\.[0-9]+)?s\)', line)
        if verdict:
            verdicts[(verdict[1] or '', verdict[2])] += 1
        receipt = re.fullmatch(r'\s+desktop_external_darwin_native_test.go:\d+: (.*)', line)
        if receipt:
            receipts[receipt[1]] += 1
    for name in (TEST, *POLICY_TESTS, *(TEST+'/'+case for case in CASES)):
        indent = '    ' if '/' in name else ''
        if verdicts[(indent, name)] != 1:
            raise ValueError('Missing or duplicated exact native Darwin verdict: '+name)
    for case in POSITIVE_CASES:
        if receipts[success_receipt(case)] != 1:
            raise ValueError('Native Darwin protocol has no exact ownership receipt: '+case)
    for case in POSITIVE_CASES:
        receipt = 'actual sealed Darwin latency accepted '+case+': held TLS Cancel joined, foreign cancellation and replay refused, Retest50 actual responses, original session child PF and MTU retained'
        if receipts[receipt] != 1:
            raise ValueError('Native Darwin protocol has no exact retained measurement receipt: '+case)
    for case in NEGATIVE_CASES:
        if receipts[refusal_receipt(case)] != 1:
            raise ValueError('Native Darwin layer has no exact refusal and cleanup receipt: '+case)
    if receipts[MTU_RECEIPT] != 1:
        raise ValueError('Native WireGuard MTU omitted original actual transfer/rollback receipt')
    if output.splitlines().count('PASS') != 1 or not output.rstrip().endswith('\nPASS'):
        raise ValueError('Native Darwin host did not finish one complete execution')


def required_host(environment):
    if environment.get(FLAG) != '1' or platform.system() != 'Darwin':
        raise ValueError('Native PF/keychain acceptance requires its explicit disposable Darwin CI opt-in')
    architecture = {'x86_64': 'amd64', 'arm64': 'arm64'}.get(platform.machine())
    if architecture is None:
        raise ValueError('Unknown native Darwin host architecture')
    target = 'darwin/'+architecture
    if environment.get('GOOS', 'darwin') != 'darwin' or environment.get('GOARCH', architecture) != architecture:
        raise ValueError('Native Darwin acceptance cannot execute a foreign target')
    uid = int(environment.get('SUDO_UID', '0')) if os.getuid() == 0 else os.getuid()
    if uid <= 0:
        raise ValueError('Native Darwin acceptance requires its original ordinary build-user UID')
    return target, uid


def prepared_peer_source(work, environment):
    core, xray = work/'core', work/'xray'
    BUILD.checkout(core, 'https://github.com/SagerNet/sing-box.git', BUILD.PIN)
    BUILD.checkout(xray, 'https://github.com/XTLS/Xray-core.git', BUILD.POLICY.XRAY.XRAY_PIN)
    BUILD.pristine(core, BUILD.PIN)
    BUILD.pristine(xray, BUILD.POLICY.XRAY.XRAY_PIN)
    BUILD.POLICY.prepare_native(core, xray)
    BUILD.PERFORMANCE.prepare(core)
    BUILD.OPENVPN.prepare(core)
    BUILD.EXTERNAL.prepare(core, env=environment)
    BUILD.BUFFERS.prepare(core)
    subprocess.run(['go', 'mod', 'tidy'], cwd=core, env=environment, check=True, timeout=300)
    return core


def execute(bundle, source=None, go='go', environment=None):
    environment = dict(os.environ if environment is None else environment)
    target, uid = required_host(environment)
    compiler, captured = CONTROLLER.UID.compiler_toolchain(ROOT, go, environment)
    captured['CGO_ENABLED'] = '1'
    bundle = Path(bundle).resolve()
    original = BUILD.reuse(bundle, target, env=captured)
    original_hash = sha(bundle/'NATIVE-RUNTIME.json')
    policy = BUILD.digest()
    python = CONTROLLER.discover_python(uid)
    sudo = CONTROLLER.UID.privilege_tool()
    with tempfile.TemporaryDirectory(prefix='routervpn-macos-external-') as temporary:
        work = Path(temporary).resolve()
        work.chmod(0o755)
        core = Path(source).resolve() if source else prepared_peer_source(work, captured)
        before = source_identity(core)
        signed = work/'sealed-bundle'
        shutil.copytree(bundle, signed, symlinks=True)
        subprocess.run([os.sys.executable, str(ROOT/'deploy/seal-native-runtime.py'), str(signed), target],
                       cwd=ROOT, env=captured, check=True, timeout=300)
        BUILD.reuse(signed, target, env=captured)
        signed_hash = sha(signed/'NATIVE-RUNTIME.json')
        controller, peer = work/'controller.test', work/'peer.test'
        commands = (
            ([str(compiler), 'test', '-race', '-c', '-mod=readonly', '-tags=routervpn_controller_privileged',
              '-o', str(controller), './cmd/client'], ROOT),
            ([str(compiler), 'test', '-race', '-c', '-mod=readonly', '-tags='+PEER_TAGS,
              '-ldflags=-checklinkname=0', '-o', str(peer), './protocol/routervpnamnezia'], core),
        )
        for command, cwd in commands:
            subprocess.run(command, cwd=cwd, env=captured, check=True, timeout=300)
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none',
                        '--identifier', 'routervpn.fixture.external.controller', str(controller)], check=True, timeout=30)
        controller.chmod(0o755)
        peer.chmod(0o755)
        identities = dict(controller=sha(controller), peer=sha(peer))
        if source_identity(core) != before or BUILD.digest() != policy:
            raise ValueError('Native host source changed during exact image compilation')
        command = ['/usr/bin/env', 'ROUTERVPN_MACOS_CONTROLLER_PRIVILEGE_FIXTURE=1',
                   'ROUTERVPN_MACOS_FIXTURE_UID='+str(uid), 'ROUTERVPN_MACOS_FIXTURE_SOURCE='+str(ROOT),
                   'ROUTERVPN_MACOS_FIXTURE_PYTHON='+str(Path(python).absolute()),
                   'ROUTERVPN_MACOS_EXTERNAL_PEER='+str(peer), 'ROUTERVPN_MACOS_EXTERNAL_PEER_SHA256='+identities['peer'],
                   'ROUTERVPN_MACOS_EXTERNAL_BUNDLE='+str(signed), 'ROUTERVPN_MACOS_EXTERNAL_BUNDLE_SHA256='+signed_hash,
                   'GORACE=atexit_sleep_ms=0', str(controller), '-test.run=^('+('|'.join((TEST, *POLICY_TESTS)))+')$', '-test.v', '-test.count=1', '-test.timeout=900s']
        if sudo:
            command = [sudo, '-n', '--', *command]
        output = CONTROLLER.reported_run(command, cwd=ROOT, env=captured, timeout=930, sudo=sudo)
        print(output, end='')
        check_verdict(output)
        if source_identity(core) != before or sha(controller) != identities['controller'] or sha(peer) != identities['peer']:
            raise ValueError('Native acceptance lost its exact compiled source/images')
        if BUILD.reuse(bundle, target, env=captured) != original or sha(bundle/'NATIVE-RUNTIME.json') != original_hash:
            raise ValueError('Native acceptance changed the original delivered bundle')
        if sha(signed/'NATIVE-RUNTIME.json') != signed_hash:
            raise ValueError('Native acceptance changed its captured signed copy')
        receipt = dict(schema=1, target=target, source_sha256=policy, bundle_sha256=original_hash,
                       sealed_bundle_sha256=signed_hash, images=identities, cases=list(CASES),
                       sources=before, native=True)
        print('Native Darwin retained external acceptance: '+json.dumps(receipt, sort_keys=True, separators=(',', ':')), flush=True)
        return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--go', default=os.environ.get('GO', 'go'))
    options = parser.parse_args()
    execute(options.bundle, options.source, options.go)
