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
    "NaiveTraffic", "NaiveSuccession", "NaiveWrongCredential", "CompositeTraffic", "CompositeSuccession", "CompositeWrongCredential"))


def checked_sources(source):
    source, records = NODE.checked_sources(source)
    for name in ("kernel_observer.go", "socket_peer.go", "socket_peer_test.go"):
        path = RESOURCES / name
        if path.is_symlink() or not path.is_file() or not path.read_bytes().startswith(TAG):
            raise ValueError("Windows Node observer escaped its explicit native test scope")
        records["fixture/" + name] = hashlib.sha256(path.read_bytes()).hexdigest()
    peer = ROOT / "mobile/desktop/node_peer_windows_test.go.tmpl"
    if peer.is_symlink() or not peer.read_bytes().startswith(TAG):
        raise ValueError("Windows Node encrypted peer escaped its native test tag")
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
        if mutation != mutants(source)[2]:
            raise ValueError("Node production mutation overlaps native scope ownership")
        policy_source = mutation[4]
    raw = BOOT.IDENTITY.replace_once(policy_source,
        "return newDesktopWindowsSocketPolicy(ctx, capture, options, nil)",
        "return desktopWindowsNodeCompositionConstruct(ctx, capture, options, nil, false)")
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
    )


def execute(source, go="go", *, prospective=False, env=None, bootstrap_only=False):
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
        relay, relay_digest = NODE.build_layer_reference(compiler, workspace, captured, race)
        xray_binary, xray_digest, xray_source, xray_records = NODE.build_xray_reference(compiler, source, workspace, captured, race)
        naive_library = NODE.stage_naive_library(compiler, source, workspace, captured)
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
        if status or any("--- PASS: " + test + " (" not in output for test in REQUIRED) or any(value in output for value in ("--- SKIP:", "DATA RACE")):
            raise ValueError("Actual WFP encrypted Node omitted a required native proof")
        for mode in ("wg", "awg2-fast", "awg2-strong"):
            if "--- PASS: " + REQUIRED[0] + "/" + mode + " (" not in output:
                raise ValueError("Actual WFP encrypted Node omitted a base protocol: " + mode)
        for case in NODE.LAYER_CASES:
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
            status, output = BOOT.IDENTITY.run([binary, "-test.run=^" + test + "$", "-test.count=1", "-test.timeout=90s", "-test.v"],
                                               cwd=source, env=captured, timeout=105)
            if status == 0 or "--- FAIL: " + test + " (" not in output or witness not in output or any(value in output for value in ("--- SKIP:", "DATA RACE", "panic: test timed out")):
                raise ValueError("WFP Node mutation missed its precise defect: " + name + "\n" + output[-16384:])
            print("Rejected actual WFP encrypted Node production mutant: " + name, flush=True)
        if relay.is_symlink() or hashlib.sha256(relay.read_bytes()).hexdigest() != relay_digest:
            raise ValueError("Actual WFP whitening reference changed during execution")
        if xray_binary.is_symlink() or hashlib.sha256(xray_binary.read_bytes()).hexdigest() != xray_digest or NODE.xray_reference_sources(xray_source) != xray_records:
            raise ValueError("Actual WFP pinned Xray reference changed during execution")
        NODE.verify_naive_library(naive_library)
    if checked_sources(source)[1] != before:
        raise ValueError("WFP Node source changed during actual native execution")
    print("Actual Windows BFE, isolated TCP/UDP grants with exact permitted peers, WG/AWG/Shadowsocks/Hysteria2/REALITY Vision/PQ/XHTTP/Naive H2/H3/split/raw-MAX AES/XOR encrypted IPv4/IPv6 payloads, fresh selected DNS, exact cross-family forward/reverse native succession and wrong-key/ordinary-token controls passed. TUN, node identity proof, host adoption and device acceptance remain separate.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--go", default="go")
    parser.add_argument("--standalone", action="store_true")
    args = parser.parse_args()
    if args.standalone:
        if args.source is not None:
            parser.error("--standalone owns its prepared core")
        BOOT.standalone(args.go, native_test=execute)
    elif args.source is None:
        parser.error("a prepared core or --standalone is required")
    else:
        execute(args.source, args.go)
