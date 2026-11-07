#!/usr/bin/env python3
"""Run every original desktop PT root from one exact native test image.

The ordinary roots retain their original process and 120-second test deadline.
The large Darwin capture root keeps all original leaf names and cases, with each
protocol executed in one bounded partition. This is source/composition evidence; privileged
kernel, packaged-engine, and device acceptance remain separate gates.
"""
from collections import Counter
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "github.com/sagernet/sing-box/routervpn/desktoppt"
SELECTION = r"^Test(RouterVPN(DesktopTorPT|ExternalPhysical|NodePhysicalUnix|PhysicalFactory|PhysicalTunnel|LinuxPhysicalFactory|DarwinPhysicalFactory|WindowsPhysicalFactory)|DesktopTorNetworkOwner)"
DARWIN_CAPTURE = "TestRouterVPNExternalPhysicalDarwinCapturesPolicyAndRetainsLateOwner"
TEST_TIMEOUT = "120s"
PROCESS_TIMEOUT = 600


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREP = load("desktop_pt_inventory_prepare", "prepare-desktop-external.py")
OWNER = load("desktop_pt_inventory_owner", "windows_build_owner.py")

# The compiler's list must equal this original gate inventory, including roots
# that would be silently lost by a narrower prefix, changed build tag or rename.
# Update this inventory deliberately when adding/removing an original test.
COMMON_ROOTS = ('TestDesktopTorNetworkOwnerActivatesOnlyOnceAfterStarted',
 'TestDesktopTorNetworkOwnerCloseAndParentCancellation',
 'TestDesktopTorNetworkOwnerConcurrentAdmissionAndRetirement',
 'TestDesktopTorNetworkOwnerRegistryAndValidation',
 'TestDesktopTorNetworkOwnerRetiresOnUnchangedInterfaceReset',
 'TestDesktopTorNetworkOwnersRemainIndependent',
 'TestRouterVPNDesktopTorPTAllFamiliesOwnExactPrivateListeners',
 'TestRouterVPNDesktopTorPTCloseBeforeStartIsPermanent',
 'TestRouterVPNDesktopTorPTCloseRetainsActualSnowflakeDNSWorker',
 'TestRouterVPNDesktopTorPTCloseWaitsForActualTransportDial',
 'TestRouterVPNDesktopTorPTDynamicEntryRejectsUnprovedOrWrongSources',
 'TestRouterVPNDesktopTorPTDynamicEntryRetiresDuringActualDNS',
 'TestRouterVPNDesktopTorPTEntryAddressRetriesKeepOwnerAndErrorSockets',
 'TestRouterVPNDesktopTorPTEntryCarriesRealMeekTLS',
 'TestRouterVPNDesktopTorPTEntryCarriesRealObfs4Traffic',
 'TestRouterVPNDesktopTorPTEntryCarriesRealSnowflakeTraffic',
 'TestRouterVPNDesktopTorPTEntryCarriesRealWebTunnelTLS',
 'TestRouterVPNDesktopTorPTEntryCloseWaitsForPrivateProofDrain',
 'TestRouterVPNDesktopTorPTEntryRejectsLazyForeignDetour',
 'TestRouterVPNDesktopTorPTEntryReplacementCannotRevive',
 'TestRouterVPNDesktopTorPTEntryRequiresActualPrivateProof',
 'TestRouterVPNDesktopTorPTLateSocketsRemainOwnedUntilActualClose',
 'TestRouterVPNDesktopTorPTPhysicalFixedBridgeRetainsBrokerAndNetworkOwner',
 'TestRouterVPNDesktopTorPTPhysicalNativeLowerCarriesActualSelectedDNSAndTCPUDP',
 'TestRouterVPNDesktopTorPTPhysicalRequiredCapabilityCannotFallBack',
 'TestRouterVPNDesktopTorPTPlainGuardOwnerRetainsNativeSourceAndDrain',
 'TestRouterVPNDesktopTorPTPlainPredecessorProofPrecedesGuardListener',
 'TestRouterVPNDesktopTorPTPreservesSelectedBootstrapDNS',
 'TestRouterVPNDesktopTorPTRealObfs4UsesCapturedNativeDialer',
 'TestRouterVPNDesktopTorPTRejectsUnownedBootstrapAdmission',
 'TestRouterVPNDesktopTorPTResetRejectsLateDNSAndCannotRevive',
 'TestRouterVPNExternalPhysicalActualBytesAndCapturedTuple',
 'TestRouterVPNExternalPhysicalAdmissionRetainsExactPolicy',
 'TestRouterVPNExternalPhysicalCancelBeforeStartAndAfterActivation',
 'TestRouterVPNExternalPhysicalCloseJoinsLatePartialFactory',
 'TestRouterVPNExternalPhysicalFactoryAndActivationRetainExactPolicy',
 'TestRouterVPNExternalPhysicalJournalAdmissionCapturesDurableBarrier',
 'TestRouterVPNExternalPhysicalNetworkResetRetiresOnlyCapturedOwner',
 'TestRouterVPNExternalPhysicalOutboundCloseRetiresPreparedOwner',
 'TestRouterVPNExternalPhysicalRejectsSocksUDPAndForeignTargetBeforeFactory',
 'TestRouterVPNExternalPhysicalRetirementKeepsExactJoinedSource',
 'TestRouterVPNExternalPhysicalSOCKSEntryRejectsReplacedEndpointAndPhysicalFinal',
 'TestRouterVPNExternalPhysicalSeparateRegistriesAndUnpreparedRejection',
 'TestRouterVPNExternalPhysicalStartupSocketPhase',
 'TestRouterVPNExternalPhysicalTunnelLifecycleAndRetirement',
 'TestRouterVPNPhysicalFactoryRequiresOSOwnerBeforeInitialize',
 'TestRouterVPNPhysicalFactoryRetainsPartialSourceAndLateCompletion',
 'TestRouterVPNPhysicalFactoryRunsBeforeTUNAndRetainsExactCapture',
 'TestRouterVPNPhysicalTunnelCapturesAndRetiresExactReader',
 'TestRouterVPNPhysicalTunnelCapturesExactControlFile',
 'TestRouterVPNPhysicalTunnelOriginalMutationContext',
 'TestRouterVPNPhysicalTunnelPreservesExistingOSBoundary',
 'TestRouterVPNPhysicalTunnelRejectsLateNetworkCompletion',
 'TestRouterVPNPhysicalTunnelRejectsMissingControlAdapterAndLateCapture',
 'TestRouterVPNPhysicalTunnelRejectsNativePolicyFailure',
 'TestRouterVPNPhysicalTunnelRejectsUnstartedAndInvalidReaders')
PLATFORM_ROOTS = {'linux': ('TestRouterVPNExternalPhysicalAmneziaStartupRevokesExactLower',
           'TestRouterVPNExternalPhysicalLinuxCapturesPolicyAndRetainsLateOwner',
           'TestRouterVPNExternalPhysicalLinuxLayeredEntryOwnsOnlyOriginalRoot',
           'TestRouterVPNExternalPhysicalLinuxSSCONNECTOwnsOnlyOriginalTCP',
           'TestRouterVPNExternalPhysicalLinuxSSEntryOwnsOriginalTCPAndUDP',
           'TestRouterVPNExternalPhysicalOpenVPNOrderedTupleSet',
           'TestRouterVPNExternalPhysicalOpenVPNStartupRevokesExactLower',
           'TestRouterVPNExternalPhysicalWireGuardStartupRevokesExactLower',
           'TestRouterVPNLinuxPhysicalFactoryCapturesExactInterfaceLANAndNetworkReset',
           'TestRouterVPNLinuxPhysicalFactoryRejectsFalseKernelInterface'),
 'darwin': ('TestRouterVPNDarwinPhysicalFactoryRejectsFalseKernelInterface',
            'TestRouterVPNDarwinPhysicalFactoryUsesActualDefaultAddress',
            'TestRouterVPNExternalPhysicalDarwinCapturesPolicyAndRetainsLateOwner',
            'TestRouterVPNExternalPhysicalLayeredEntryRejectsFinalPhysicalAuthority',
            'TestRouterVPNExternalPhysicalPacketFinalRejectsFinalPhysicalAuthority',
            'TestRouterVPNExternalPhysicalSSCONNECTRejectsUDPAndFinalAuthority',
            'TestRouterVPNExternalPhysicalSSEntryRejectsFinalPhysicalAuthority'),
 'windows': ('TestRouterVPNExternalPhysicalWindowsAdmissionCloseJoinsEnteredCallback',
             'TestRouterVPNExternalPhysicalWindowsAdmissionRetiresFailures',
             'TestRouterVPNExternalPhysicalWindowsCapturesPolicyAndRetainsLateOwner',
             'TestRouterVPNExternalPhysicalWindowsRetirementKeepsOriginalPredecessor',
             'TestRouterVPNWindowsPhysicalFactoryInitializesCapturedOwnerAndJoinsReplacement',
             'TestRouterVPNWindowsPhysicalFactoryRejectsFalseKernelInterface',
             'TestRouterVPNWindowsPhysicalFactoryRejectsForeignPolicyAuthority',
             'TestRouterVPNWindowsPhysicalFactoryUsesActualDefaultAddressAndMask')}
UNIX_ROOTS = ('TestRouterVPNDesktopTorPTPhysicalImportedSourceCarriesActualSelectedDNSAndTCPUDP',
 'TestRouterVPNNodePhysicalUnixCapturesPolicyAndRetainsLateOwner',
 'TestRouterVPNNodePhysicalUnixCloseJoinsLateFactoryAndRetriesSource',
 'TestRouterVPNNodePhysicalUnixRejectsUncapturedSourceBeforeConstructor')
DARWIN_PROTOCOLS = ('ss-entry-http',
 'ss-entry-https',
 'ss-entry-ss',
 'wg-entry-openvpn-tcp',
 'wg-entry-openvpn-udp',
 'wg-entry-openvpn-mixed',
 'awg-entry-fast-openvpn-tcp',
 'awg-entry-fast-openvpn-udp',
 'awg-entry-fast-openvpn-mixed',
 'awg-entry-strong-openvpn-tcp',
 'awg-entry-strong-openvpn-udp',
 'awg-entry-strong-openvpn-mixed',
 'wg-entry-amneziawg-fast',
 'wg-entry-amneziawg-strong',
 'awg-entry-fast-amneziawg-fast',
 'awg-entry-fast-amneziawg-strong',
 'awg-entry-strong-amneziawg-fast',
 'awg-entry-strong-amneziawg-strong',
 'wg-entry-wireguard',
 'awg-entry-wireguard-fast',
 'awg-entry-wireguard-strong',
 'shadowsocks',
 'hysteria2',
 'wireguard',
 'amneziawg-fast',
 'amneziawg-strong',
 'socks5',
 'openvpn-tcp',
 'openvpn-udp',
 'openvpn-mixed',
 'wg-entry-ss',
 'awg-entry-ss-fast',
 'awg-entry-ss-strong',
 'wg-entry-http',
 'wg-entry-https',
 'awg-entry-http-fast',
 'awg-entry-http-strong',
 'awg-entry-https-fast',
 'awg-entry-https-strong',
 'wg-entry-hysteria2',
 'awg-entry-hysteria2-fast',
 'awg-entry-hysteria2-strong',
 'wg-entry-socks5',
 'awg-entry-socks5-fast',
 'awg-entry-socks5-strong',
 'wg-entry-hysteria2-aes',
 'wg-entry-hysteria2-aes-xor',
 'awg-entry-hysteria2-fast-aes',
 'awg-entry-hysteria2-fast-aes-xor',
 'awg-entry-hysteria2-strong-aes',
 'awg-entry-hysteria2-strong-aes-xor')


def expected_roots(target):
    if target not in PLATFORM_ROOTS:
        raise ValueError("Unsupported desktop PT native target")
    roots = (*COMMON_ROOTS, *PLATFORM_ROOTS[target], *(UNIX_ROOTS if target != "windows" else ()))
    if len(set(roots)) != len(roots):
        raise ValueError("Duplicate original desktop PT root inventory")
    return tuple(sorted(roots))


def darwin_leaves(protocols):
    if not protocols or len(set(protocols)) != len(protocols) or not set(protocols) <= set(DARWIN_PROTOCOLS):
        raise ValueError("Changed Darwin capture protocol inventory")
    return tuple(DARWIN_CAPTURE + "/" + "/".join((protocol, lan, ipv6, kill, fault))
                 for protocol in protocols for lan in ("lan-off", "lan-on")
                 for ipv6 in ("ipv6-off", "ipv6-on") for kill in ("on-connect", "always")
                 for fault in ("live", "during-index", "during-address", "during-mask", "during-down", "partial", "cancel"))


def checked_sources(source):
    source = PREP.checked_vendor(source)
    copies = {name: raw for name, raw in PREP.pt_copies().items()
              if name.startswith(("routervpn/desktoppt/", "routervpn/torpt/"))}
    records = {}
    for relative, expected in copies.items():
        path = source / relative
        if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
            raise ValueError("Desktop PT image source differs from shipping bytes: " + relative)
        records[relative] = hashlib.sha256(expected).hexdigest()
    actual = {path.relative_to(source).as_posix() for path in (source / "routervpn/desktoppt").glob("*.go")}
    expected = {name for name in copies if name.startswith("routervpn/desktoppt/") and name.endswith(".go")}
    if actual != expected:
        raise ValueError("Desktop PT source inventory moved outside the original projection")
    for name in ("go.mod", "go.sum"):
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing original desktop PT module identity")
        records[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, records


def run(command, *, cwd, env, timeout=PROCESS_TIMEOUT):
    try:
        if os.name == "nt":
            result = OWNER.run(command, cwd=cwd, env=env, timeout=timeout)
        else:
            result = subprocess.run([str(arg) for arg in command], cwd=cwd, env=env,
                                    capture_output=True, check=True, timeout=timeout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raw = (error.stdout or b"") + (error.stderr or b"")
        # Keep the first assertion and final stack while preserving the failure.
        shown = raw if len(raw) <= 65536 else raw[:32768] + b"\n[bounded native diagnostic]\n" + raw[-32768:]
        sys.stderr.write(shown.decode("utf-8", errors="replace"))
        raise
    if result.stderr:
        sys.stderr.write(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout.decode("utf-8").replace("\r\n", "\n")


def discover(output, expected):
    roots = tuple(output.splitlines())
    if len(set(roots)) != len(roots) or any(not re.fullmatch(r"Test[A-Za-z0-9_]+", root) for root in roots):
        raise ValueError("Invalid or duplicated compiled desktop PT root inventory")
    if set(roots) != set(expected):
        raise ValueError("Compiled desktop PT inventory moved: missing=" + repr(sorted(set(expected) - set(roots))) +
                         " unexpected=" + repr(sorted(set(roots) - set(expected))))
    return tuple(sorted(roots))


def plan(roots):
    if len(set(roots)) != len(roots):
        raise ValueError("Duplicate partition root")
    ordinary = tuple(root for root in roots if root != DARWIN_CAPTURE)
    # Keep ordinary roots together in the compiler's original test order. Only
    # the observed aggregate bottleneck needs additional process boundaries.
    result = [("ordinary", "^(" + "|".join(re.escape(root) for root in ordinary) + ")$", ordinary, ())] if ordinary else []
    if DARWIN_CAPTURE in roots:
        # Six protocols per process preserve every original case. The original
        # deadline applies to each bounded partition; no fixture is relaxed.
        for start in range(0, len(DARWIN_PROTOCOLS), 6):
            protocols = DARWIN_PROTOCOLS[start:start + 6]
            selection = "^" + DARWIN_CAPTURE + "$/^(" + "|".join(re.escape(name) for name in protocols) + ")$"
            result.append((DARWIN_CAPTURE + "/" + str(start // 6 + 1), selection, (DARWIN_CAPTURE,), darwin_leaves(protocols)))
    if Counter(root for _, _, selected, _ in result for root in selected) != Counter({
            root: (len(DARWIN_PROTOCOLS) + 5) // 6 if root == DARWIN_CAPTURE else 1 for root in roots}):
        raise ValueError("Desktop PT partition lost or duplicated an original root")
    leaves = [leaf for _, _, _, required in result for leaf in required]
    if DARWIN_CAPTURE in roots and Counter(leaves) != Counter(darwin_leaves(DARWIN_PROTOCOLS)):
        raise ValueError("Desktop PT partition lost or duplicated a Darwin leaf")
    return tuple(result)


def verdicts(output, roots, required=()):
    started, passed, package_passes = Counter(), Counter(), 0
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError) as error:
            raise ValueError("Malformed native desktop PT test event") from error
        if not isinstance(event, dict) or event.get("Package") != PACKAGE:
            raise ValueError("Foreign native desktop PT test event")
        action, name = event.get("Action"), event.get("Test")
        if action in ("fail", "skip"):
            raise ValueError("Desktop PT failure or skipped original case: " + str(name))
        if name is not None and (not isinstance(name, str) or name.split("/", 1)[0] not in roots):
            raise ValueError("Desktop PT verdict moved outside its original root")
        if action == "run" and name is not None:
            started[name] += 1
        elif action == "pass":
            if name is None:
                package_passes += 1
            else:
                passed[name] += 1
        elif action not in ("start", "output", "pause", "cont"):
            raise ValueError("Unknown native desktop PT test event")
    if package_passes != 1 or not started or started != passed or any(count != 1 for count in started.values()):
        raise ValueError("Missing, duplicate or unjoined desktop PT case verdict")
    if {name for name in passed if "/" not in name} != set(roots):
        raise ValueError("Missing original desktop PT root verdict")
    if required and set(passed) != set(roots) | set(required):
        raise ValueError("Darwin capture leaf inventory moved, disappeared or duplicated")
    return set(passed)


def execute(source, tags, *, race=True):
    target = platform.system().lower()
    roots = expected_roots(target)
    source, original = checked_sources(source)
    env = dict(os.environ, PYTHONIOENCODING="utf-8:strict")
    with tempfile.TemporaryDirectory(prefix="routervpn-desktop-pt-") as directory:
        binary = Path(directory) / ("desktoppt.test.exe" if os.name == "nt" else "desktoppt.test")
        run(["go", "test", "-c", *(["-race"] if race else []), "-mod=readonly", "-tags=" + tags,
             "-ldflags=-checklinkname=0", "-o", binary, "./routervpn/desktoppt"], cwd=source, env=env)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        roots = discover(run([binary, "-test.list=" + SELECTION], cwd=source, env=env), roots)
        phases = plan(roots)
        completed, original_leaves = Counter(), set()
        for label, selection, selected, required in phases:
            if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
                raise ValueError("Original desktop PT test image changed between partitions")
            print("Desktop PT original inventory: running " + label, flush=True)
            output = run(["go", "tool", "test2json", "-t", "-p", PACKAGE, binary,
                          "-test.v=test2json", "-test.run=" + selection, "-test.count=1", "-test.timeout=" + TEST_TIMEOUT],
                         cwd=source, env=env)
            names = verdicts(output, selected, required)
            completed.update(name for name in names if "/" not in name)
            leaves = {name for name in names if "/" in name}
            if leaves & original_leaves:
                raise ValueError("Original desktop PT leaf executed in more than one partition")
            original_leaves.update(leaves)
            print("Desktop PT original inventory: " + label + " passed (" + str(len(names)) + " exact verdicts)", flush=True)
        if completed != Counter(root for _, _, selected, _ in phases for root in selected):
            raise ValueError("Incomplete original desktop PT partition inventory")
        if DARWIN_CAPTURE in roots and {leaf for leaf in original_leaves if leaf.startswith(DARWIN_CAPTURE + "/")} != set(darwin_leaves(DARWIN_PROTOCOLS)):
            raise ValueError("Incomplete original Darwin capture leaf inventory")
        _, current = checked_sources(source)
        if current != original or hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Original desktop PT source changed during execution")
        print("Desktop PT complete original inventory: " + str(len(roots)) + " roots, " + str(len(original_leaves)) +
              " distinct leaves; image_sha256=" + digest, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--tags", required=True)
    parser.add_argument("--without-race", action="store_true", help="Only supported for native Windows ARM64")
    args = parser.parse_args()
    windows_arm64 = platform.system() == "Windows" and platform.machine().lower() in ("arm64", "aarch64")
    if args.without_race != windows_arm64:
        raise ValueError("Desktop PT race instrumentation differs from the native platform contract")
    execute(args.source, args.tags, race=not args.without_race)


if __name__ == "__main__":
    main()
