"""Exact test-only scope for the installed Windows prefix controller and child.

No packet, interface, proof, process or journal operation is replaced. Every
native policy constructor and independent readback receives the same actual
native-child AppID. Missing or changed source anchors are fatal.
"""
from pathlib import Path, PureWindowsPath
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
TAG = "routervpn_windows_candidate_prefix_native"
RESOURCE = ROOT / "deploy/fixtures/windows-candidate-prefix/scope.go"

LOOPBACK_SOURCE = '''\t\tif len(p.fixtureScope) == 0 {
\t\t\trules = append(rules, p.pair("loopback", family, 60, true, true, desktopWFPCondition{Field: desktopWFPFlags, Type: 3, Match: 6, Number: 1})...)
\t\t}'''
LOOPBACK_SCOPED = LOOPBACK_SOURCE + ''' else {
\t\t\t// Keep only literal local IPC. Windows also labels same-host private
\t\t\t// interface traffic loopback; that is the encrypted reference path.
\t\t\taddress := netip.IPv6Loopback()
\t\t\tif family == 4 { address = netip.MustParseAddr("127.0.0.1") }
\t\t\trules = append(rules, p.pair("loopback-ipc", family, 60, true, true,
\t\t\t\tdesktopWFPAddress(desktopWFPLocalAddress, address),
\t\t\t\tdesktopWFPAddress(desktopWFPRemoteAddress, address))...)
\t\t}'''

REPLACEMENTS = {
    "desktop_socket_windows_policy.go": (
        ("return newDesktopWindowsSocketPolicy(ctx, capture, options, nil)",
         "return newDesktopWindowsSocketPolicy(ctx, capture, options, desktopWindowsPrefixFixtureScope())"),
        (LOOPBACK_SOURCE, LOOPBACK_SCOPED)),
    "desktop_socket_windows_transfer.go": (
        ("return newDesktopWindowsSocketPolicySuccessor(ctx, capture, options, predecessor, nil)",
         "return newDesktopWindowsSocketPolicySuccessor(ctx, capture, options, predecessor, desktopWindowsPrefixFixtureScope())"),
        ("return readDesktopWindowsRetainedProtection(ctx, target, nil)",
         "return readDesktopWindowsRetainedProtection(ctx, target, desktopWindowsPrefixFixtureScope())"),
        ("return readDesktopWindowsProtectionExpectation(ctx, target, nil)",
         "return readDesktopWindowsProtectionExpectation(ctx, target, desktopWindowsPrefixFixtureScope())"),
        ("return newDesktopWindowsProtectionTransactionTarget(ctx, nil, false, &target)",
         "return newDesktopWindowsProtectionTransactionTarget(ctx, desktopWindowsPrefixFixtureScope(), false, &target)"),
        ("return newDesktopWindowsProtectionTransactionTarget(ctx, nil, true, &target)",
         "return newDesktopWindowsProtectionTransactionTarget(ctx, desktopWindowsPrefixFixtureScope(), true, &target)")),
    "desktop_socket_windows_commit.go": (
        ("return newDesktopWindowsSocketPolicySuccessorWithBarrier(ctx, capture, options, predecessor, nil, barrier)",
         "return newDesktopWindowsSocketPolicySuccessorWithBarrier(ctx, capture, options, predecessor, desktopWindowsPrefixFixtureScope(), barrier)"),
        ("return newDesktopWindowsProtectionTransactionTargetWithBarrier(ctx, nil, false, &target, barrier)",
         "return newDesktopWindowsProtectionTransactionTargetWithBarrier(ctx, desktopWindowsPrefixFixtureScope(), false, &target, barrier)"),
        ("return newDesktopWindowsProtectionTransactionTargetWithBarrier(ctx, nil, true, &target, barrier)",
         "return newDesktopWindowsProtectionTransactionTargetWithBarrier(ctx, desktopWindowsPrefixFixtureScope(), true, &target, barrier)")),
    "desktop_socket_windows_baseline.go": (
        ("return newDesktopWindowsProtectionRecovery(ctx, nil)",
         "return newDesktopWindowsProtectionRecovery(ctx, desktopWindowsPrefixFixtureScope())"),
        ("return newDesktopWindowsProtectionTransaction(ctx, nil, false)",
         "return newDesktopWindowsProtectionTransaction(ctx, desktopWindowsPrefixFixtureScope(), false)")),
    "desktop_socket_windows_status.go": (
        ("return readDesktopWindowsProtection(ctx, nil)",
         "return readDesktopWindowsProtection(ctx, desktopWindowsPrefixFixtureScope())"),),
    "desktop_socket_windows_prepared.go": (
        ("return readDesktopWindowsPreparedProtection(ctx, capture, policy, baselineSHA256, nil)",
         "return readDesktopWindowsPreparedProtection(ctx, capture, policy, baselineSHA256, desktopWindowsPrefixFixtureScope())"),),
    "desktop_socket_windows_probe.go": (
        ("return probeDesktopWindowsProtectionAbsent(ctx, nil)",
         "return probeDesktopWindowsProtectionAbsent(ctx, desktopWindowsPrefixFixtureScope())"),),
    "desktop_socket_windows_observation.go": (
        ("return newDesktopWindowsProtectionObservationScoped(candidates, callback, nil)",
         "return newDesktopWindowsProtectionObservationScoped(candidates, callback, desktopWindowsPrefixFixtureScope())"),),
}


def replace_once(raw, before, after):
    if raw.count(before) != 1:
        raise ValueError("Installed prefix scope lost its exact original anchor: " + before)
    return raw.replace(before, after)


def scope_sources(directory, image):
    image = str(image)
    path = PureWindowsPath(image)
    if not path.is_absolute() or path.name != "sing-box-routervpn.exe" or any(value in image for value in ("\x00", "\n", "\r", '"')):
        raise ValueError("Installed prefix scope requires one captured absolute native child")
    directory = Path(directory)
    result = {}
    for name, substitutions in REPLACEMENTS.items():
        source = directory / name
        if source.is_symlink() or not source.is_file():
            raise ValueError("Installed prefix scope lost original native source: " + name)
        raw = source.read_text(encoding="utf-8")
        for before, after in substitutions:
            raw = replace_once(raw, before, after)
        result[name] = raw.encode()
    resource = RESOURCE.read_text(encoding="utf-8")
    result["routervpn_candidate_prefix_scope_windows.go"] = replace_once(
        resource, "__CAPTURED_NATIVE_IMAGE__", json.dumps(image)).encode()
    return result


def overlay(directory, image, workspace):
    directory, workspace = Path(directory).resolve(), Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=False)
    replacement = {}
    records = {}
    for name, raw in scope_sources(directory, image).items():
        target = workspace / name
        target.write_bytes(raw)
        replacement[str(directory / name)] = str(target)
        records[name] = hashlib.sha256(raw).hexdigest()
    manifest = workspace / "overlay.json"
    manifest.write_text(json.dumps({"Replace": replacement}, sort_keys=True), encoding="utf-8")
    return manifest, records


# This is the same reference family used by the installed Linux and Darwin
# gates. Extra installed helpers provide the existing WG/AWG factory types;
# none is selected by the single exact Windows reference-process test.
PEERS = (
    "node_wg_peer_test.go.tmpl", "node_awg_peer_test.go.tmpl",
    "node_imported_peer_linux_test.go.tmpl", "node_chain_peer_linux_test.go.tmpl",
    "node_chain_imported_test.go.tmpl",
    "node_external_hysteria_layer_installed_test.go.tmpl",
    "node_external_wireguard_installed_test.go.tmpl",
    "node_external_amnezia_installed_test.go.tmpl",
    "node_external_openvpn_installed_test.go.tmpl",
)


def peer_sources():
    result = {}
    for name in PEERS:
        source = ROOT / "mobile/desktop" / name
        if source.is_symlink() or not source.is_file():
            raise ValueError("Windows prefix peer lost original encrypted source: " + name)
        raw = source.read_text(encoding="utf-8")
        header, remainder = raw.split("\n", 1)
        allowed = ("//go:build linux && !android",
                   "//go:build (linux && !android) || (darwin && routervpn_darwin_external_host)")
        if header not in allowed or not remainder.startswith("\npackage routervpnamnezia\n"):
            raise ValueError("Windows prefix peer changed its explicit native selector: " + name)
        if name == "node_chain_peer_linux_test.go.tmpl":
            remainder = replace_once(remainder,
                'func desktopNodeChainReferenceAddressPair(address, client string) bool {\n',
                'func desktopNodeChainReferenceAddressPair(address, client string) bool {\n'
                '\tif runtime.GOOS == "windows" { return desktopWindowsPrefixReferenceAddressPair(address, client) }\n')
        result["routervpn_windows_prefix_" + name.removesuffix(".tmpl").replace("_linux", "")] = (
            "//go:build windows && " + TAG + "\n" + remainder).encode()
    result["routervpn_windows_prefix_reference_test.go"] = (
        ROOT / "deploy/fixtures/windows-candidate-prefix/peer.go").read_bytes()
    return result


def peer_overlay(directory, workspace):
    directory, workspace = Path(directory).resolve(), Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=False)
    replacement = {}
    for name, raw in peer_sources().items():
        path = workspace / name
        path.write_bytes(raw)
        replacement[str(directory / name)] = str(path)
    manifest = workspace / "overlay.json"
    manifest.write_text(json.dumps({"Replace": replacement}, sort_keys=True), encoding="utf-8")
    return manifest
