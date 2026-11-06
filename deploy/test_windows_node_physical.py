#!/usr/bin/env python3
"""Execute actual WFP, the shipping Node factory and real encrypted peers.

The exact compiled Box and lower use the real Windows isolated socket source
and BFE policy. Test-only AppID scope protects the CI host, and only TUN is a
harmless boundary. The distinct retained peer executable runs actual WG/AWG.
No node/DNS proof, Connected state or physical-device acceptance is fabricated.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("windows_node_source", ROOT / "deploy/test_desktop_node_physical.py")
NODE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NODE)
BOOT = NODE.BOOT
RESOURCES = ROOT / "deploy/fixtures/windows-node-physical"
TAG = b"//go:build windows && routervpn_windows_node_composition\n"
TAGS = (*NODE.TAGS, "routervpn_windows_node_composition")
REQUIRED = tuple("TestRouterVPNDesktopNodeWindowsWFP" + suffix for suffix in (
    "EncryptedTraffic", "EncryptedSuccession", "RejectsForeignPredecessor", "WrongPeerRejected", "RestorationCapture",
    "LayerTraffic", "LayerSuccession", "LayerWrongCredential", "XrayTraffic", "XraySuccession", "XrayWrongCredential",
    "NaiveTraffic", "NaiveSuccession", "NaiveWrongCredential", "CompositeTraffic", "CompositeSuccession", "CompositeWrongCredential",
    "LoopbackIPC"))
EXTERNAL_HY2_ROOT = "TestRouterVPNDesktopExternalWindowsHysteria2WFP"
EXTERNAL_HY2_CASES = (EXTERNAL_HY2_ROOT, *(EXTERNAL_HY2_ROOT + "/" + leaf for leaf in (
    "on-connect", "always", "successor-and-original-restore", "reject/password", "reject/trust",
    "reject/dns", "reject/exit", "cancelled-proof", "foreign-predecessor", "commit-refused")))
EXTERNAL_HY2_LAYER_ROOT = "TestRouterVPNDesktopExternalWindowsHysteria2LayerWFP"
EXTERNAL_HY2_LAYERS = ("aes-256-gcm", "aes-256-gcm+xor-whitening")
EXTERNAL_HY2_LAYER_CASES = {
    mode: (EXTERNAL_HY2_LAYER_ROOT, EXTERNAL_HY2_LAYER_ROOT + "/" + mode,
           *(EXTERNAL_HY2_LAYER_ROOT + "/" + mode + "/" + case.removeprefix(EXTERNAL_HY2_ROOT + "/") for case in EXTERNAL_HY2_CASES[1:]),
           EXTERNAL_HY2_LAYER_ROOT + "/" + mode + "/reject/layer-key",
           *((EXTERNAL_HY2_LAYER_ROOT + "/" + mode + "/reject/whitening",) if mode.endswith("+xor-whitening") else ()))
    for mode in EXTERNAL_HY2_LAYERS
}
EXTERNAL_SOCKS_ROOT = "TestRouterVPNDesktopExternalWindowsSOCKSWFP"
EXTERNAL_SOCKS_CASES = (EXTERNAL_SOCKS_ROOT, *(EXTERNAL_SOCKS_ROOT + "/" + leaf for leaf in (
    "refusal-receipts", "on-connect", "always", "home-lan-off", "home-lan-off/tcp-deny", "home-lan-off/udp-deny",
    "home-lan-off/tcp-retained-deny", "home-lan-off/udp-retained-deny",
    "reject/password", "reject/trust", "reject/dns", "reject/exit", "reject/auth-downgrade",
    "reject/relay-domain", "reject/relay-wildcard", "reject/relay-zero", "reject/relay-other-private", "reject/control-eof",
    "successor-and-original-restore", "cancelled-proof", "replacement-keeps-new-source",
    "foreign-predecessor", "commit-refused")))
EXTERNAL_PACKET_ROOT = "TestRouterVPNDesktopExternalWindowsPacketWFP"
EXTERNAL_PACKET_PROTOCOLS = ("wireguard", "awg2-fast", "awg2-strong")
EXTERNAL_PACKET_LEAVES = (
    "on-connect", "always", "successor-and-original-restore", "reject/private-key", "reject/psk",
    "reject/trust", "reject/dns", "reject/exit", "cancelled-proof", "foreign-predecessor", "commit-refused")
EXTERNAL_PACKET_CASES = {
    protocol: (EXTERNAL_PACKET_ROOT, EXTERNAL_PACKET_ROOT + "/" + protocol,
               *(EXTERNAL_PACKET_ROOT + "/" + protocol + "/" + leaf for leaf in
                 (*EXTERNAL_PACKET_LEAVES, *(("reject/parameters",) if protocol != "wireguard" else ()))))
    for protocol in EXTERNAL_PACKET_PROTOCOLS
}
EXTERNAL_OPENVPN_ROOT = "TestRouterVPNDesktopExternalWindowsOpenVPNWFP"
EXTERNAL_OPENVPN_NETWORKS = ("tcp", "udp", "mixed")
EXTERNAL_OPENVPN_LEAVES = ("on-connect", "always", "successor-and-original-restore", "reject/trust",
                           "reject/control-key", "reject/dns", "cancelled-proof", "foreign-predecessor", "commit-refused")
EXTERNAL_OPENVPN_CASES = {network: (EXTERNAL_OPENVPN_ROOT, EXTERNAL_OPENVPN_ROOT + "/" + network,
    *(EXTERNAL_OPENVPN_ROOT + "/" + network + "/" + leaf for leaf in EXTERNAL_OPENVPN_LEAVES)) for network in EXTERNAL_OPENVPN_NETWORKS}
EXTERNAL_OPENVPN_ALIAS = "TestRouterVPNDesktopExternalWindowsOpenVPNAlias"
EXTERNAL_OPENVPN_ALIAS_CASES = (EXTERNAL_OPENVPN_ALIAS, EXTERNAL_OPENVPN_ALIAS + "/refuse-existing-address",
    *(EXTERNAL_OPENVPN_ALIAS + "/reject-" + field for field in ("address", "luid", "index", "creation", "prefix", "skip-source", "prefix-origin", "suffix-origin")))
EXTERNAL_SS_ENTRY_ROOT = "TestRouterVPNDesktopExternalWindowsSSEntryWFP"
EXTERNAL_SS_ENTRY_NETWORKS = ("shadowsocks", "http-connect", "https-connect")
EXTERNAL_SS_ENTRY_LEAVES = ("on-connect", "always", "cipher-aes128", "cipher-chacha20", "successor-and-original-restore", "reject/entry-key", "reject/entry-exit", "reject/final-key", "reject/dns", "reject/exit", "cancelled-proof", "foreign-predecessor", "commit-refused")
EXTERNAL_SS_ENTRY_CASES = {network: (EXTERNAL_SS_ENTRY_ROOT, EXTERNAL_SS_ENTRY_ROOT + "/" + network,
    *(EXTERNAL_SS_ENTRY_ROOT + "/" + network + "/" + leaf for leaf in EXTERNAL_SS_ENTRY_LEAVES)) for network in EXTERNAL_SS_ENTRY_NETWORKS}
IPC_CASES = tuple("TestRouterVPNDesktopNodeWindowsWFPLoopbackIPC/" + network
                  for network in ("tcp4", "tcp6", "udp4", "udp6"))
LOOPBACK_SOURCE = '''\t\tif len(p.fixtureScope) == 0 {
\t\t\trules = append(rules, p.pair("loopback", family, 60, true, true, desktopWFPCondition{Field: desktopWFPFlags, Type: 3, Match: 6, Number: 1})...)
\t\t}'''
LOOPBACK_COMPOSITION = LOOPBACK_SOURCE + ''' else {
\t\t\t// Retain production's internal IPC behavior without exempting the
\t\t\t// private-interface peer used to model an off-host physical path.
\t\t\taddress := netip.IPv6Loopback()
\t\t\tif family == 4 {
\t\t\t\taddress = netip.MustParseAddr("127.0.0.1")
\t\t\t}
\t\t\trules = append(rules, p.pair("loopback-ipc", family, 60, true, true,
\t\t\t\tdesktopWFPAddress(desktopWFPLocalAddress, address),
\t\t\t\tdesktopWFPAddress(desktopWFPRemoteAddress, address))...)
\t\t}'''


def checked_sources(source):
    source, records = NODE.checked_sources(source)
    records["fixture/phase-runner"] = executable_digest(Path(__file__))
    for name in ("kernel_observer.go", "socket_peer.go", "socket_peer_test.go"):
        path = RESOURCES / name
        if path.is_symlink() or not path.is_file() or not path.read_bytes().startswith(TAG):
            raise ValueError("Windows Node observer escaped its explicit native test scope")
        records["fixture/" + name] = hashlib.sha256(path.read_bytes()).hexdigest()
    peer = ROOT / "mobile/desktop/node_peer_windows_test.go.tmpl"
    if peer.is_symlink() or not peer.read_bytes().startswith(TAG):
        raise ValueError("Windows Node encrypted peer escaped its native test tag")
    external = ROOT / "mobile/desktop/external_box_windows_hysteria2_test.go.tmpl"
    if external.is_symlink() or not external.is_file() or not external.read_bytes().startswith(TAG):
        raise ValueError("Ordinary Windows Hysteria2 escaped its explicit native test scope")
    records["external_hysteria2"] = hashlib.sha256(external.read_bytes()).hexdigest()
    layer = ROOT / "mobile/desktop/external_box_windows_hysteria2_layer_test.go.tmpl"
    if layer.is_symlink() or not layer.is_file() or not layer.read_bytes().startswith(TAG):
        raise ValueError("Ordinary Windows Hysteria2 layer escaped its explicit native test scope")
    records["external_hysteria2_layer"] = hashlib.sha256(layer.read_bytes()).hexdigest()
    peer = ROOT / "mobile/desktop/external_hysteria_layer_peer_test.go.tmpl"
    if peer.is_symlink() or not peer.is_file():
        raise ValueError("Ordinary Hysteria2 layer lost its independent encrypted peer")
    records["external_hysteria2_layer_peer"] = hashlib.sha256(peer.read_bytes()).hexdigest()
    socks = ROOT / "mobile/desktop/external_box_windows_socks_test.go.tmpl"
    if socks.is_symlink() or not socks.is_file() or not socks.read_bytes().startswith(TAG):
        raise ValueError("Ordinary Windows SOCKS escaped its explicit native test scope")
    records["external_socks"] = hashlib.sha256(socks.read_bytes()).hexdigest()
    packet = ROOT / "mobile/desktop/external_box_windows_packet_test.go.tmpl"
    if packet.is_symlink() or not packet.is_file() or not packet.read_bytes().startswith(TAG):
        raise ValueError("Ordinary Windows packet endpoint escaped its explicit native test scope")
    records["external_packet"] = hashlib.sha256(packet.read_bytes()).hexdigest()
    for name in ("alias", "openvpn"):
        native = ROOT / ("mobile/desktop/external_box_windows_" + name + "_test.go.tmpl")
        if native.is_symlink() or not native.is_file() or not native.read_bytes().startswith(TAG):
            raise ValueError("Ordinary Windows OpenVPN escaped its explicit native test scope")
        records["external_" + name] = hashlib.sha256(native.read_bytes()).hexdigest()
    records["kernel_runner"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return source, records


def overlay(source, directory, mutation=None):
    replacements = {}

    def replace(relative, raw):
        path = directory / (str(len(replacements)) + ".go")
        path.write_bytes(raw)
        replacements[str(source / relative)] = str(path)

    # Both constructors remain scoped even when the deliberate legacy-adoption
    # mutation calls the old recovery constructor. Neither ordinary binary has
    # an environment/profile switch for this fixture.
    policy = "routervpn/mobiletor/desktop_socket_windows_policy.go"
    policy_source = (source / policy).read_text(encoding="utf-8")
    policy_mutation = mutation is not None and mutation[1] == policy
    if policy_mutation:
        # Only this exact compiled action defect may share the policy overlay.
        # Both constructor replacements are still applied afterward, so the
        # deliberate permit remains confined to the actual test executable.
        if mutation not in (mutants(source)[2], mutants(source)[3]):
            raise ValueError("Node production mutation overlaps native scope ownership")
        policy_source = mutation[4]
    raw = BOOT.IDENTITY.replace_once(policy_source,
        "return newDesktopWindowsSocketPolicy(ctx, capture, options, nil)",
        "return desktopWindowsNodeCompositionConstruct(ctx, capture, options, nil, false)")
    # The general WFP unit fixture deliberately removes loopback so its local
    # peers can test ordinary-token denial. The Node fixture instead uses the
    # actual private interface for those peers and must retain narrow internal
    # IPC for Cronet's owned resolver/socket pairs. Never permit all same-host
    # traffic through WFP's broad IS_LOOPBACK flag in this composition.
    if mutation is None or mutation[0] != "missing-loopback-ipc":
        raw = BOOT.IDENTITY.replace_once(raw, LOOPBACK_SOURCE, LOOPBACK_COMPOSITION)
    replace(policy, raw.encode())
    transfer = "routervpn/mobiletor/desktop_socket_windows_transfer.go"
    raw = BOOT.IDENTITY.replace_once((source / transfer).read_text(encoding="utf-8"),
        "return newDesktopWindowsSocketPolicySuccessor(ctx, capture, options, predecessor, nil)",
        "return desktopWindowsNodeCompositionConstruct(ctx, capture, options, predecessor, true)")
    replace(transfer, raw.encode())
    for name, relative in (("kernel_observer.go", "routervpn/mobiletor/desktop_socket_windows_node_composition_overlay.go"),
                           ("socket_peer.go", "routervpn/mobiletor/desktop_socket_windows_node_peer_overlay.go")):
        if (source / relative).exists() or (source / relative).is_symlink():
            raise ValueError("Unowned Windows Node observer already occupies the native core")
        replace(relative, (RESOURCES / name).read_bytes())
    if mutation is not None:
        name, relative, test, witness, raw = mutation
        if str(source / relative) in replacements and not policy_mutation:
            raise ValueError("Node production mutation overlaps native scope ownership")
        if not policy_mutation:
            replace(relative, raw.encode())
    result = directory / "overlay.json"
    result.write_text(json.dumps({"Replace": replacements}, sort_keys=True), encoding="utf-8")
    return result


def external_overlay(source, directory, mutation=None):
    # Keep the existing exact constructor/loopback scoping, then additionally
    # scope the durable constructor used by the real external journal owner.
    # No socket, tunnel, proof, TLS or admission operation is replaced.
    scope_mutation = mutants(source)[2] if mutation == "ordinary-udp-deny" else None
    if mutation not in (None, "ordinary-udp-deny", "missing-durable-intent", "missing-socks-release", "missing-socks-readback", "missing-socks-grant-removal"):
        raise ValueError("Unknown ordinary Hysteria2 native control")
    path = overlay(source, directory, scope_mutation)
    mapping = json.loads(path.read_text(encoding="utf-8"))["Replace"]
    relative = "routervpn/mobiletor/desktop_socket_windows_commit.go"
    raw = BOOT.IDENTITY.replace_once((source / relative).read_text(encoding="utf-8"),
        "return newDesktopWindowsSocketPolicySuccessorWithBarrier(ctx, capture, options, predecessor, nil, barrier)",
        "return desktopWindowsNodeCompositionWithBarrier(ctx, capture, options, predecessor, barrier)")
    copied = directory / "external-durable-scope.go"
    copied.write_bytes(raw.encode("utf-8"))
    mapping[str(source / relative)] = str(copied)
    if mutation == "missing-durable-intent":
        relative = "routervpn/desktoppt/external_physical_windows.go"
        raw = BOOT.IDENTITY.replace_once((source / relative).read_text(encoding="utf-8"),
            "if commit != nil {", "if false && commit != nil {")
        copied = directory / "external-missing-intent.go"
        copied.write_bytes(raw.encode("utf-8"))
        mapping[str(source / relative)] = str(copied)
    if mutation in ("missing-socks-release", "missing-socks-grant-removal"):
        relative = "routervpn/mobiletor/desktop_socket_windows_policy.go"
        copied = Path(mapping[str(source / relative)])
        before, after = {
            "missing-socks-release": ("if err := p.identity.ReleaseSocket(ctx, creation); err != nil {", "if err := error(nil); err != nil {"),
            "missing-socks-grant-removal": ("return struct{}{}, p.revoke(q)", "return struct{}{}, nil"),
        }[mutation]
        copied.write_text(BOOT.IDENTITY.replace_once(copied.read_text(encoding="utf-8"), before, after), encoding="utf-8")
    if mutation == "missing-socks-readback":
        relative = "routervpn/mobiletor/desktop_socket_windows_identity.go"
        raw = BOOT.IDENTITY.replace_once((source / relative).read_text(encoding="utf-8"),
            "if record.endpoint != 0 {", "if false && record.endpoint != 0 {")
        copied = directory / "external-missing-native-retirement-readback.go"
        copied.write_text(raw, encoding="utf-8")
        mapping[str(source / relative)] = str(copied)
    path.write_text(json.dumps({"Replace": mapping}, sort_keys=True), encoding="utf-8")
    return path


def report_external_hysteria2(status, output):
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    if status or any(not exact_native_verdict(output, "PASS", case) for case in EXTERNAL_HY2_CASES) or \
            socks_native_aborted(output) or "--- FAIL:" in output or re.search(r"^FAIL(?:\s|$)", output, re.MULTILINE):
        raise ValueError("Actual ordinary Windows Hysteria2 omitted its required native result")


def report_external_hysteria2_layer(mode, status, output):
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    if mode not in EXTERNAL_HY2_LAYER_CASES or status or any(
            not exact_native_verdict(output, "PASS", case) for case in EXTERNAL_HY2_LAYER_CASES[mode]) or \
            socks_native_aborted(output) or "--- FAIL:" in output or re.search(r"^FAIL(?:\s|$)", output, re.MULTILINE):
        raise ValueError("Actual ordinary Windows Hysteria2 layer omitted its required native result")


def execute_external_hysteria2(source, workspace, build, captured):
    directory = workspace / "external-hysteria2"
    directory.mkdir()
    selected = external_overlay(source, directory)
    binary = directory / "external-hysteria2.test.exe"
    status, output = BOOT.IDENTITY.run([*build, "-overlay=" + str(selected), "-o", binary, "."],
        cwd=source, env=captured, timeout=600)
    if status:
        raise ValueError("Actual ordinary Windows Hysteria2 compilation failed:\n" + output[-32768:])
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    status, output = BOOT.IDENTITY.run([binary, "-test.run=^" + EXTERNAL_HY2_ROOT + "$", "-test.count=1", "-test.timeout=180s", "-test.v"],
        cwd=source, env=captured, timeout=195)
    report_external_hysteria2(status, output)
    for mode in EXTERNAL_HY2_LAYERS:
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Actual ordinary Hysteria2 native executable changed")
        status, output = BOOT.IDENTITY.run([binary, "-test.run=^" + EXTERNAL_HY2_LAYER_ROOT + "$/^" + re.escape(mode) + "$", "-test.count=1", "-test.timeout=180s", "-test.v"],
            cwd=source, env=captured, timeout=195)
        report_external_hysteria2_layer(mode, status, output)
    if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        raise ValueError("Actual ordinary Hysteria2 native executable changed")
    for label, leaf, witness in (
            ("ordinary-udp-deny", "always", "ordinary token bypassed actual external WFP UDP deny: independent peer marker"),
            ("missing-durable-intent", "always", "actual HY2 source skipped its durable WFP intent")):
        changed = workspace / ("external-hysteria2-" + label)
        changed.mkdir()
        selected = external_overlay(source, changed, label)
        binary = changed / "external-hysteria2.test.exe"
        status, output = BOOT.IDENTITY.run([*build, "-overlay=" + str(selected), "-o", binary, "."],
            cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError("Actual ordinary Hysteria2 control did not compile: " + label + "\n" + output[-16384:])
        control_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        status, output = BOOT.IDENTITY.run([binary, "-test.run=^" + EXTERNAL_HY2_ROOT + "$/^" + leaf + "$", "-test.count=1", "-test.timeout=60s", "-test.v"],
            cwd=source, env=captured, timeout=75)
        if status == 0 or not exact_native_verdict(output, "FAIL", EXTERNAL_HY2_ROOT + "/" + leaf) or witness not in output or \
                socks_native_aborted(output):
            raise ValueError("Actual ordinary Hysteria2 control missed its exact defect: " + label + "\n" + output[-16384:])
        if hashlib.sha256(binary.read_bytes()).hexdigest() != control_digest:
            raise ValueError("Actual ordinary Hysteria2 control executable changed")
        for mode in EXTERNAL_HY2_LAYERS:
            selected_leaf = EXTERNAL_HY2_LAYER_ROOT + "/" + mode + "/" + leaf
            status, output = BOOT.IDENTITY.run([binary, "-test.run=^" + EXTERNAL_HY2_LAYER_ROOT + "$/^" + re.escape(mode) + "$/^" + leaf + "$", "-test.count=1", "-test.timeout=60s", "-test.v"],
                cwd=source, env=captured, timeout=75)
            if status == 0 or not exact_native_verdict(output, "FAIL", selected_leaf) or witness not in output or socks_native_aborted(output):
                raise ValueError("Actual ordinary Hysteria2 layer control missed its exact defect: " + label)
            if hashlib.sha256(binary.read_bytes()).hexdigest() != control_digest:
                raise ValueError("Actual ordinary Hysteria2 layer control executable changed")
        print("Rejected actual ordinary Hysteria2 native control: " + label, flush=True)


def exact_native_verdict(output, verdict, case):
    # A diagnostic can quote an expected PASS. Only a real Go verdict line,
    # occurring exactly once, supplies evidence for this required case.
    pattern = r"^[ \t]*--- " + re.escape(verdict) + r": " + re.escape(case) + r" \("
    return len(re.findall(pattern, output, re.MULTILINE)) == 1


def socks_native_aborted(output):
    return any(value in output for value in ("--- SKIP:", "DATA RACE", "panic:", "fatal error:", "[build failed]"))


def report_external_socks(status, output):
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    if status or any(not exact_native_verdict(output, "PASS", case) for case in EXTERNAL_SOCKS_CASES) or \
            socks_native_aborted(output) or "--- FAIL:" in output or re.search(r"^FAIL(?:\s|$)", output, re.MULTILINE):
        raise ValueError("Actual ordinary Windows SOCKS omitted its required native result")


def execute_external_socks(source, workspace, build, captured):
    directory = workspace / "external-socks"
    directory.mkdir()
    selected = external_overlay(source, directory)
    binary = directory / "external-socks.test.exe"
    status, output = BOOT.IDENTITY.run([*build, "-overlay=" + str(selected), "-o", binary, "."],
        cwd=source, env=captured, timeout=600)
    if status:
        raise ValueError("Actual ordinary Windows SOCKS compilation failed:\n" + output[-32768:])
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    status, output = BOOT.IDENTITY.run([binary, "-test.run=^" + EXTERNAL_SOCKS_ROOT + "$", "-test.count=1", "-test.timeout=300s", "-test.v"],
        cwd=source, env=captured, timeout=315)
    report_external_socks(status, output)
    if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        raise ValueError("Actual ordinary SOCKS native executable changed")
    for label, mutation, leaf, witness in (
            ("ordinary-tcp-deny", "ordinary-udp-deny", "home-lan-off/tcp-deny", "ordinary token bypassed actual SOCKS WFP TCP deny: independent peer marker"),
            ("ordinary-udp-deny", "ordinary-udp-deny", "home-lan-off/udp-deny", "ordinary token bypassed actual SOCKS WFP UDP deny: independent peer marker"),
            ("missing-durable-intent", "missing-durable-intent", "always", "actual SOCKS source skipped its durable WFP intent"),
            ("missing-socket-release", "missing-socks-release", "reject/relay-other-private", "native retirement bypassed exact socket release or grant join"),
            ("missing-endpoint-readback", "missing-socks-readback", "reject/relay-other-private", "native retirement bypassed independent endpoint readback"),
            ("missing-grant-removal", "missing-socks-grant-removal", "reject/relay-other-private", "joined native I/O retained its original grant and exact WFP filters")):
        changed = workspace / ("external-socks-" + label)
        changed.mkdir()
        selected = external_overlay(source, changed, mutation)
        binary = changed / "external-socks.test.exe"
        status, output = BOOT.IDENTITY.run([*build, "-overlay=" + str(selected), "-o", binary, "."],
            cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError("Actual ordinary SOCKS control did not compile: " + label + "\n" + output[-16384:])
        expression = "^" + EXTERNAL_SOCKS_ROOT + "$/" + "/".join("^" + part + "$" for part in leaf.split("/"))
        control_digest = executable_digest(binary)
        status, output = BOOT.IDENTITY.run([binary, "-test.run=" + expression, "-test.count=1", "-test.timeout=60s", "-test.v"],
            cwd=source, env=captured, timeout=75)
        if status == 0 or not exact_native_verdict(output, "FAIL", EXTERNAL_SOCKS_ROOT + "/" + leaf) or witness not in output or \
                socks_native_aborted(output):
            raise ValueError("Actual ordinary SOCKS control missed its exact defect: " + label + "\n" + output[-16384:])
        if executable_digest(binary) != control_digest:
            raise ValueError("Ordinary native control executable changed")
        print("Rejected actual ordinary SOCKS native control: " + label, flush=True)


def report_external_packet(status, output, protocol):
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    if protocol not in EXTERNAL_PACKET_CASES or status or \
            any(not exact_native_verdict(output, "PASS", case) for case in EXTERNAL_PACKET_CASES[protocol]) or \
            socks_native_aborted(output) or "--- FAIL:" in output or re.search(r"^FAIL(?:\s|$)", output, re.MULTILINE):
        raise ValueError("Actual ordinary Windows packet endpoint omitted its required native result")


def execute_external_packet(source, workspace, build, captured):
    directory = workspace / "external-packet"
    directory.mkdir()
    selected = external_overlay(source, directory)
    binary = directory / "external-packet.test.exe"
    status, output = BOOT.IDENTITY.run([*build, "-overlay=" + str(selected), "-o", binary, "."],
        cwd=source, env=captured, timeout=600)
    if status:
        raise ValueError("Actual ordinary Windows packet compilation failed:\n" + output[-32768:])
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    reference = "TestRouterVPNDesktopExternalPacketReference"
    authority = reference + "Authority"
    status, output = BOOT.IDENTITY.run([binary, "-test.run=^(" + reference + "|" + authority + ")$", "-test.count=1", "-test.timeout=60s", "-test.v"],
        cwd=source, env=captured, timeout=75)
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    required = (authority, *(reference + "/" + protocol for protocol in EXTERNAL_PACKET_PROTOCOLS))
    # The isolated TLS-root wrapper repeats its parent verdict; only actual
    # child leaves and the independent authority test count as evidence.
    if status or any(not exact_native_verdict(output, "PASS", case) for case in required) or socks_native_aborted(output) or "--- FAIL:" in output or re.search(r"^FAIL(?:\s|$)", output, re.MULTILINE):
        raise ValueError("Independent packet reference omitted its required encrypted result")
    if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        raise ValueError("Actual ordinary packet native executable changed")
    # Each protocol has its own complete lifecycle/negative suite. Compile time
    # cannot consume its original bounded native execution window.
    for protocol in EXTERNAL_PACKET_PROTOCOLS:
        expression = "^" + EXTERNAL_PACKET_ROOT + "$/^" + protocol + "$"
        status, output = BOOT.IDENTITY.run([binary, "-test.run=" + expression, "-test.count=1", "-test.timeout=180s", "-test.v"],
            cwd=source, env=captured, timeout=195)
        report_external_packet(status, output, protocol)
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Actual ordinary packet native executable changed")
    for label, witness in (
            ("ordinary-udp-deny", "ordinary token bypassed actual external WFP UDP deny: independent peer marker"),
            ("missing-durable-intent", "actual packet source skipped its durable WFP intent")):
        changed = workspace / ("external-packet-" + label)
        changed.mkdir()
        selected = external_overlay(source, changed, label)
        binary = changed / "external-packet.test.exe"
        status, output = BOOT.IDENTITY.run([*build, "-overlay=" + str(selected), "-o", binary, "."],
            cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError("Actual ordinary packet control did not compile: " + label + "\n" + output[-16384:])
        control_digest = executable_digest(binary)
        leaf = EXTERNAL_PACKET_ROOT + "/wireguard/always"
        expression = "/".join("^" + part + "$" for part in leaf.split("/"))
        status, output = BOOT.IDENTITY.run([binary, "-test.run=" + expression, "-test.count=1", "-test.timeout=60s", "-test.v"],
            cwd=source, env=captured, timeout=75)
        if status == 0 or not exact_native_verdict(output, "FAIL", leaf) or witness not in output or socks_native_aborted(output):
            raise ValueError("Actual ordinary packet control missed its exact defect: " + label + "\n" + output[-16384:])
        if executable_digest(binary) != control_digest:
            raise ValueError("Ordinary native control executable changed")
        print("Rejected actual ordinary packet native control: " + label, flush=True)


def report_external_openvpn(status, output, network):
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    required = EXTERNAL_OPENVPN_ALIAS_CASES if network == "alias" else EXTERNAL_OPENVPN_CASES.get(network, ())
    if not required or status or any(not exact_native_verdict(output, "PASS", case) for case in required) or socks_native_aborted(output) or "--- FAIL:" in output or re.search(r"^FAIL(?:\s|$)", output, re.MULTILINE):
        raise ValueError("Ordinary Windows OpenVPN omitted its required native result: " + network)


def execute_external_openvpn(source, workspace, build, captured):
    directory = workspace / "external-openvpn"
    directory.mkdir()
    selected = external_overlay(source, directory)
    binary = directory / "external-openvpn.test.exe"
    status, output = BOOT.IDENTITY.run([*build, "-overlay=" + str(selected), "-o", binary, "."], cwd=source, env=captured, timeout=600)
    if status:
        raise ValueError("Actual ordinary Windows OpenVPN compilation failed:\n" + output[-32768:])
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    for network in ("alias", *EXTERNAL_OPENVPN_NETWORKS):
        expression = "^" + EXTERNAL_OPENVPN_ALIAS + "$" if network == "alias" else "^" + EXTERNAL_OPENVPN_ROOT + "$/^" + network + "$"
        duration = 60 if network == "alias" else 180
        status, output = BOOT.IDENTITY.run([binary, "-test.run=" + expression, "-test.count=1", "-test.timeout=" + str(duration) + "s", "-test.v"], cwd=source, env=captured, timeout=duration + 15)
        report_external_openvpn(status, output, network)
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Actual ordinary OpenVPN native executable changed")
    for label, witness in (
            ("ordinary-udp-deny", "ordinary token bypassed actual external WFP UDP deny: independent peer marker"),
            ("missing-durable-intent", "actual OpenVPN source skipped its durable WFP intent")):
        changed = workspace / ("external-openvpn-" + label)
        changed.mkdir()
        selected = external_overlay(source, changed, label)
        candidate = changed / "external-openvpn.test.exe"
        status, output = BOOT.IDENTITY.run([*build, "-overlay=" + str(selected), "-o", candidate, "."], cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError("Actual ordinary OpenVPN control did not compile: " + label + "\n" + output[-16384:])
        candidate_digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        leaf = EXTERNAL_OPENVPN_ROOT + "/udp/always"
        expression = "/".join("^" + part + "$" for part in leaf.split("/"))
        status, output = BOOT.IDENTITY.run([candidate, "-test.run=" + expression, "-test.count=1", "-test.timeout=60s", "-test.v"], cwd=source, env=captured, timeout=75)
        if status == 0 or not exact_native_verdict(output, "FAIL", leaf) or witness not in output or socks_native_aborted(output):
            raise ValueError("Actual ordinary OpenVPN control missed its exact defect: " + label + "\n" + output[-16384:])
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != candidate_digest:
            raise ValueError("Actual ordinary OpenVPN negative executable changed")
        print("Rejected actual ordinary OpenVPN native control: " + label, flush=True)


def report_external_ss_entry(status, output, network):
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    required = EXTERNAL_SS_ENTRY_CASES.get(network, ())
    if not required or status or any(not exact_native_verdict(output, "PASS", case) for case in required) or socks_native_aborted(output) or "--- FAIL:" in output or re.search(r"^FAIL(?:\s|$)", output, re.MULTILINE):
        raise ValueError("Ordinary Windows SS entry omitted its required native result: " + network)


def execute_external_ss_entry(source, workspace, build, captured):
    directory = workspace / "external-ss-entry"
    directory.mkdir()
    selected = external_overlay(source, directory)
    binary = directory / "external-ss-entry.test.exe"
    status, output = BOOT.IDENTITY.run([*build, "-overlay=" + str(selected), "-o", binary, "."], cwd=source, env=captured, timeout=600)
    if status:
        raise ValueError("Actual ordinary Windows SS entry compilation failed:\n" + output[-32768:])
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    for network in EXTERNAL_SS_ENTRY_NETWORKS:
        expression = "^" + EXTERNAL_SS_ENTRY_ROOT + "$/^" + network + "$"
        duration = 180
        status, output = BOOT.IDENTITY.run([binary, "-test.run=" + expression, "-test.count=1", "-test.timeout=" + str(duration) + "s", "-test.v"], cwd=source, env=captured, timeout=duration + 15)
        report_external_ss_entry(status, output, network)
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Actual ordinary SS entry native executable changed")
    for label, witness in (
            ("ordinary-udp-deny", "ordinary token bypassed actual external WFP UDP deny: independent peer marker"),
            ("missing-durable-intent", "actual SS entry source skipped its durable WFP intent")):
        changed = workspace / ("external-ss-entry-" + label)
        changed.mkdir()
        selected = external_overlay(source, changed, label)
        candidate = changed / "external-ss-entry.test.exe"
        status, output = BOOT.IDENTITY.run([*build, "-overlay=" + str(selected), "-o", candidate, "."], cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError("Actual ordinary SS entry control did not compile: " + label + "\n" + output[-16384:])
        candidate_digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        leaf = EXTERNAL_SS_ENTRY_ROOT + "/shadowsocks/always"
        expression = "/".join("^" + part + "$" for part in leaf.split("/"))
        status, output = BOOT.IDENTITY.run([candidate, "-test.run=" + expression, "-test.count=1", "-test.timeout=60s", "-test.v"], cwd=source, env=captured, timeout=75)
        if status == 0 or not exact_native_verdict(output, "FAIL", leaf) or witness not in output or socks_native_aborted(output):
            raise ValueError("Actual ordinary SS entry control missed its exact defect: " + label + "\n" + output[-16384:])
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != candidate_digest:
            raise ValueError("Actual ordinary SS entry negative executable changed")
        print("Rejected actual ordinary SS entry native control: " + label, flush=True)


def mutants(source):
    factory = "routervpn/desktoppt/node_physical_windows.go"
    lower = "routervpn/desktoppt/node_physical.go"
    policy = "routervpn/mobiletor/desktop_socket_windows_policy.go"
    return (
        ("legacy-adoption", factory, REQUIRED[2], "foreign predecessor reached actual encrypted startup",
         BOOT.IDENTITY.replace_once((source / factory).read_text(encoding="utf-8"),
            "owned, err := mobiletor.NewDesktopWindowsSocketPolicySuccessor(ctx, capture, options, predecessor)",
            "_ = predecessor\n\t\towned, err := mobiletor.NewDesktopWindowsSocketPolicy(ctx, capture, options)")),
        ("late-handshake", lower, REQUIRED[0], "actual WFP eager encrypted node startup failed",
         BOOT.IDENTITY.replace_once((source / lower).read_text(encoding="utf-8"), "!owner.SocketCurrent()", "!owner.Current()")),
        ("ordinary-udp-deny", policy, REQUIRED[0], "independent peer marker receipt",
         BOOT.IDENTITY.replace_once((source / policy).read_text(encoding="utf-8"),
            'p.pair("deny", family, 1, false, true)', 'p.pair("deny", family, 1, true, true)')),
        # Recompile the old scoped fixture, preserving both exact constructors
        # and every physical deny. The real IPC test must reject that omission.
        ("missing-loopback-ipc", policy, "TestRouterVPNDesktopNodeWindowsWFPLoopbackIPC",
         "captured WFP loopback IPC was denied", (source / policy).read_text(encoding="utf-8")),
    )


# Independent parent observations: every inner compiler, test and cleanup bound
# remains unchanged. The old single1200s parent could expire during its own
#1200s baseline, before the four external suites and production controls.
PHASES = ("node-baseline", "node-controls", "external-hysteria2", "external-socks", "external-packet", "external-openvpn", "external-ss-entry")
# Compiler selection has two 180s observations. Node references retain their
# 300s whitening build, 30+600s Xray build, 300s dependency verification and two
# 1800s checksum-verified Cronet module reads. These are parent sums, not new
# per-command deadlines. Include one 60s process-return/receipt margin.
_PHASE_COMMON = 2 * 180 + 90 + 60
_PHASE_REFERENCES = 300 + 30 + 600 + 300 + 2 * 1800
PHASE_TIMEOUTS = {
    "external-ss-entry": _PHASE_COMMON + 600 + 3 * 195 + 2 * (600 + 75),
    "node-baseline": _PHASE_COMMON + _PHASE_REFERENCES + 600 + 1215,
    "node-controls": _PHASE_COMMON + _PHASE_REFERENCES + 4 * (600 + 105),
    "external-hysteria2": _PHASE_COMMON + 600 + 3 * 195 + 2 * (600 + 75),
    "external-socks": _PHASE_COMMON + 600 + 315 + 6 * (600 + 75),
    "external-packet": _PHASE_COMMON + 600 + 75 + 3 * 195 + 2 * (600 + 75),
    "external-openvpn": _PHASE_COMMON + 600 + 75 + 3 * 195 + 2 * (600 + 75),
}
_PHASE_IMAGES = {
    "external-ss-entry": tuple("external-ss-entry" + suffix + "/external-ss-entry.test.exe" for suffix in ("", "-ordinary-udp-deny", "-missing-durable-intent")),
    "node-baseline": ("start-layer-relay.exe", "xray-reference.exe", "baseline/node-kernel.test.exe"),
    "node-controls": ("start-layer-relay.exe", "xray-reference.exe", *(name + "/node-negative.test.exe" for name in
                      ("legacy-adoption", "late-handshake", "ordinary-udp-deny", "missing-loopback-ipc"))),
    "external-hysteria2": tuple("external-hysteria2" + suffix + "/external-hysteria2.test.exe" for suffix in
                               ("", "-ordinary-udp-deny", "-missing-durable-intent")),
    "external-socks": tuple("external-socks" + suffix + "/external-socks.test.exe" for suffix in
                           ("", "-ordinary-tcp-deny", "-ordinary-udp-deny", "-missing-durable-intent",
                            "-missing-socket-release", "-missing-endpoint-readback", "-missing-grant-removal")),
    "external-packet": tuple("external-packet" + suffix + "/external-packet.test.exe" for suffix in
                            ("", "-ordinary-udp-deny", "-missing-durable-intent")),
    "external-openvpn": tuple("external-openvpn" + suffix + "/external-openvpn.test.exe" for suffix in
                             ("", "-ordinary-udp-deny", "-missing-durable-intent")),
}


def source_digest(records):
    return hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def executable_digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Windows physical executable is not an original regular image")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_phase_receipt(value, phase, source_sha256, architecture):
    if (phase not in PHASES or not isinstance(value, dict) or
            set(value) != {"format", "phase", "architecture", "source_sha256", "executables"} or
            value["format"] != "routervpn-windows-physical-phase-v1" or value["phase"] != phase or
            value["source_sha256"] != source_sha256 or value["architecture"] != architecture or
            architecture not in ("amd64", "arm64") or not re.fullmatch(r"[0-9a-f]{64}", source_sha256)):
        raise ValueError("Windows physical phase receipt lost its exact source/target/phase")
    images = value["executables"]
    if (not isinstance(images, dict) or set(images) != set(_PHASE_IMAGES[phase]) or
            any(not isinstance(name, str) or not name.endswith(".exe") or name.startswith("/") or
                "\\" in name or ":" in name or any(part in ("", ".", "..") for part in name.split("/")) or
                not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                for name, digest in images.items())):
        raise ValueError("Windows physical phase omitted its original executable receipts")


def validate_phase_set(results):
    if not isinstance(results, list) or len(results) != len(PHASES):
        raise ValueError("Windows physical completion requires every native phase")
    for phase, value in zip(PHASES, results):
        validate_phase_receipt(value, phase, results[0]["source_sha256"], results[0]["architecture"])


def execute_partitioned(source, env, run):
    """Packaging owns serial phase children and accepts only their complete set."""
    source, before = checked_sources(source)
    expected = source_digest(before)
    architecture = env.get("GOARCH")
    results = []
    with tempfile.TemporaryDirectory(prefix="routervpn-wfp-phase-receipts-") as temporary:
        for phase in PHASES:
            if checked_sources(source)[1] != before:
                raise ValueError("Windows physical source changed between native phases")
            path = Path(temporary) / (phase + ".json")
            output = run([sys.executable, Path(__file__).resolve(), source,
                          "--phase", phase, "--receipt", path], env=env, timeout=PHASE_TIMEOUTS[phase])
            print(output, flush=True)
            if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > 32768:
                raise ValueError("Windows physical phase has no bounded regular receipt")
            value = json.loads(path.read_text(encoding="utf-8"))
            validate_phase_receipt(value, phase, expected, architecture)
            if checked_sources(source)[1] != before:
                raise ValueError("Windows physical source changed during native phase")
            results.append(value)
    validate_phase_set(results)
    print("Actual Windows physical composition: all seven native phases and their controls passed", flush=True)
    return results


def execute(source, go="go", *, prospective=False, env=None, bootstrap_only=False, phase="complete", receipt_path=None):
    if phase not in ("complete", *PHASES):
        raise ValueError("Unknown Windows physical phase")
    if phase == "complete":
        if receipt_path is not None:
            raise ValueError("A complete Windows physical run cannot emit a partial phase receipt")
        results = [execute(source, go, prospective=prospective, env=env, bootstrap_only=bootstrap_only, phase=name) for name in PHASES]
        validate_phase_set(results)
        print("Actual Windows physical composition: all seven native phases and their controls passed", flush=True)
        return results
    if prospective or platform.system() != "Windows" or not BOOT.IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("WFP encrypted Node composition requires actual admitted Windows execution")
    source, before = checked_sources(source)
    compiler, captured, architecture = BOOT.IDENTITY.selected_compiler(go, source, dict(os.environ if env is None else env))
    race = ["-race"] if architecture == "amd64" and not bootstrap_only else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    captured.pop("ROUTERVPN_NODE_WFP_REFERENCE_CHILD", None)
    # Execute the exact test-scoped transport predicate as well as the native
    # graph. An unconnected UDP readback must not weaken connected TCP proof.
    status, output = BOOT.IDENTITY.run([compiler, "test", *race, "-count=1", "-timeout=30s", "-v",
        RESOURCES / "socket_peer.go", RESOURCES / "socket_peer_test.go"],
        cwd=source, env=captured, timeout=90)
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    if status or "--- PASS: TestWindowsNodeObserverTransportPeer (" not in output or any(value in output for value in ("--- SKIP:", "DATA RACE")):
        raise ValueError("Windows Node transport-specific observer lost its required peer checks")
    build = [compiler, "test", "-c", "-mod=readonly", "-tags=" + ",".join(TAGS), *race, "-ldflags=-checklinkname=0"]
    with tempfile.TemporaryDirectory(prefix="routervpn-node-kernel-") as temporary:
        workspace = Path(temporary)
        if phase in ("node-baseline", "node-controls"):
            relay, relay_digest = NODE.build_layer_reference(compiler, workspace, captured, race)
            xray_binary, xray_digest, xray_source, xray_records = NODE.build_xray_reference(compiler, source, workspace, captured, race)
            naive_library = NODE.stage_naive_library(compiler, source, workspace, captured)
            if phase == "node-baseline":
                base = workspace / "baseline"
                base.mkdir()
                selected = overlay(source, base)
                binary = base / "node-kernel.test.exe"
                status, output = BOOT.IDENTITY.run([*build, "-overlay=" + str(selected), "-o", binary, "./protocol/routervpnamnezia"],
                                                   cwd=source, env=captured, timeout=600)
                if status:
                    raise ValueError("Actual WFP encrypted Node compilation failed:\n" + output[-32768:])
                digest = hashlib.sha256(binary.read_bytes()).hexdigest()
                # The admitted layered graphs and cross-family reversals run in the
                # same native host with independent retained peers. This bounds the
                # complete expanded suite; individual production/fixture deadlines stay unchanged.
                # Composite adds six simultaneous two-lane graphs, twenty independently
                # authenticated failures and two reversals. Keep every per-operation
                # deadline and require each new leaf in this bounded aggregate run.
                status, output = BOOT.IDENTITY.run([binary, "-test.run=^TestRouterVPNDesktopNodeWindowsWFP", "-test.count=1", "-test.timeout=1200s", "-test.v"],
                                                   cwd=source, env=captured, timeout=1215)
                print(output, end="" if output.endswith("\n") else "\n", flush=True)
                if status or any("--- PASS: " + test + " (" not in output for test in (*REQUIRED, *IPC_CASES)) or any(value in output for value in ("--- SKIP:", "DATA RACE")):
                    raise ValueError("Actual WFP encrypted Node omitted a required native proof")
                for mode in ("wg", "awg2-fast", "awg2-strong"):
                    if "--- PASS: " + REQUIRED[0] + "/" + mode + " (" not in output:
                        raise ValueError("Actual WFP encrypted Node omitted a base protocol: " + mode)
                for case in (*NODE.LAYER_CASES, *NODE.LAYER_ALLOCATION_CASES):
                    if "--- PASS: TestRouterVPNDesktopNodeWindowsWFPLayerTraffic/" + case + " (" not in output:
                        raise ValueError("Actual WFP encrypted Node omitted an admitted graph/Start Layer: " + case)
                for mode in ("shadowsocks", "hysteria2"):
                    if "--- PASS: TestRouterVPNDesktopNodeWindowsWFPLayerSuccession/" + mode + " (" not in output:
                        raise ValueError("Actual WFP Node omitted its exact cross-family restoration: " + mode)
                for case in ("shadowsocks/aes-key", "hysteria2/hysteria-trust", "hysteria2/hysteria-password"):
                    if "--- PASS: TestRouterVPNDesktopNodeWindowsWFPLayerWrongCredential/" + case + " (" not in output:
                        raise ValueError("Actual WFP Node omitted its encrypted credential negative: " + case)
                for case in NODE.XRAY_CASES:
                    if "--- PASS: TestRouterVPNDesktopNodeWindowsWFPXrayTraffic/" + case + " (" not in output:
                        raise ValueError("Actual WFP Xray omitted an admitted graph/Start Layer: " + case)
                for mode in NODE.XRAY_MODES:
                    if "--- PASS: TestRouterVPNDesktopNodeWindowsWFPXraySuccession/" + mode + " (" not in output:
                        raise ValueError("Actual WFP Xray omitted its exact cross-family restoration: " + mode)
                for case in (*(mode + "/xray-reality-key" for mode in NODE.XRAY_MODES),
                             "reality-pq-vision/xray-pq-key", "reality-xhttp/xray-pq-key", "reality-vision/aes-key"):
                    if "--- PASS: TestRouterVPNDesktopNodeWindowsWFPXrayWrongCredential/" + case + " (" not in output:
                        raise ValueError("Actual WFP Xray omitted its encrypted credential negative: " + case)
                for case in NODE.NAIVE_CASES:
                    if "--- PASS: TestRouterVPNDesktopNodeWindowsWFPNaiveTraffic/" + case + " (" not in output:
                        raise ValueError("Actual WFP Naive omitted an admitted HTTP version/Start Layer: " + case)
                for mode in NODE.NAIVE_MODES:
                    if "--- PASS: TestRouterVPNDesktopNodeWindowsWFPNaiveSuccession/" + mode + " (" not in output:
                        raise ValueError("Actual WFP Naive omitted its exact cross-family restoration: " + mode)
                for case in (mode + "/" + fault for mode in NODE.NAIVE_MODES for fault in ("naive-user", "naive-server-name", "naive-certificate", "naive-password", "aes-key")):
                    if "--- PASS: TestRouterVPNDesktopNodeWindowsWFPNaiveWrongCredential/" + case + " (" not in output:
                        raise ValueError("Actual WFP Naive omitted its encrypted credential negative: " + case)
                for case in NODE.COMPOSITE_CASES:
                    if "--- PASS: TestRouterVPNDesktopNodeWindowsWFPCompositeTraffic/" + case + " (" not in output:
                        raise ValueError("Actual WFP composite omitted simultaneous captured TCP/UDP branches or a Start Layer: " + case)
                for mode in NODE.COMPOSITE_MODES:
                    if "--- PASS: TestRouterVPNDesktopNodeWindowsWFPCompositeSuccession/" + mode + " (" not in output:
                        raise ValueError("Actual WFP composite omitted its exact cross-family restoration: " + mode)
                for case in NODE.COMPOSITE_CREDENTIAL_CASES:
                    if "--- PASS: TestRouterVPNDesktopNodeWindowsWFPCompositeWrongCredential/" + case + " (" not in output:
                        raise ValueError("Actual WFP composite omitted an original branch or shared-layer credential negative: " + case)
                if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
                    raise ValueError("Actual WFP Node executable changed during its retained test")
            else:
                for mutation in mutants(source):
                    name, relative, test, witness, raw = mutation
                    candidate = workspace / name
                    candidate.mkdir()
                    selected = overlay(source, candidate, mutation)
                    binary = candidate / "node-negative.test.exe"
                    status, output = BOOT.IDENTITY.run([*build, "-overlay=" + str(selected), "-o", binary, "./protocol/routervpnamnezia"],
                                                       cwd=source, env=captured, timeout=600)
                    if status:
                        raise ValueError("WFP Node mutation did not compile: " + name + "\n" + output[-16384:])
                    negative_digest = executable_digest(binary)
                    status, output = BOOT.IDENTITY.run([binary, "-test.run=^" + test + "$", "-test.count=1", "-test.timeout=90s", "-test.v"],
                                                       cwd=source, env=captured, timeout=105)
                    if status == 0 or "--- FAIL: " + test + " (" not in output or witness not in output or any(value in output for value in ("--- SKIP:", "DATA RACE", "panic: test timed out")):
                        raise ValueError("WFP Node mutation missed its precise defect: " + name + "\n" + output[-16384:])
                    if executable_digest(binary) != negative_digest:
                        raise ValueError("WFP Node control executable changed during execution")
                    print("Rejected actual WFP encrypted Node production/fixture control: " + name, flush=True)
            if relay.is_symlink() or hashlib.sha256(relay.read_bytes()).hexdigest() != relay_digest:
                raise ValueError("Actual WFP whitening reference changed during execution")
            if xray_binary.is_symlink() or hashlib.sha256(xray_binary.read_bytes()).hexdigest() != xray_digest or NODE.xray_reference_sources(xray_source) != xray_records:
                raise ValueError("Actual WFP pinned Xray reference changed during execution")
            NODE.verify_naive_library(naive_library)
        else:
            external = {
                "external-hysteria2": execute_external_hysteria2,
                "external-socks": execute_external_socks,
                "external-packet": execute_external_packet,
                "external-openvpn": execute_external_openvpn,
                "external-ss-entry": execute_external_ss_entry,
            }
            external[phase](source, workspace, build, captured)
        executables = {path.relative_to(workspace).as_posix(): executable_digest(path)
                       for path in sorted(workspace.rglob("*.exe"))}
        result = {"format": "routervpn-windows-physical-phase-v1", "phase": phase,
                  "architecture": architecture, "source_sha256": source_digest(before),
                  "executables": executables}
        validate_phase_receipt(result, phase, source_digest(before), architecture)
    if checked_sources(source)[1] != before:
        raise ValueError("WFP Node source changed during actual native execution")
    if receipt_path is not None:
        with Path(receipt_path).open("x", encoding="utf-8") as stream:
            json.dump(result, stream, sort_keys=True)
            stream.write("\n")
    print("Actual Windows physical phase passed: " + phase, flush=True)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--go", default="go")
    parser.add_argument("--standalone", action="store_true")
    parser.add_argument("--phase", choices=("complete", *PHASES), default="complete")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    if args.standalone:
        if args.source is not None or args.phase != "complete" or args.receipt is not None:
            parser.error("--standalone owns its complete prepared core")
        BOOT.standalone(args.go, native_test=execute)
    elif args.source is None:
        parser.error("a prepared core or --standalone is required")
    else:
        execute(args.source, args.go, phase=args.phase, receipt_path=args.receipt)
