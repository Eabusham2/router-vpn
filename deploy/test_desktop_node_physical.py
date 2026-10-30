#!/usr/bin/env python3
"""Execute the exact Node compiler, native startup, IPC and encrypted peers.

The generated Box/lower/command bytes are shipping source. Privileged permits
and TUN are explicit composition boundaries; this does not claim kernel WFP,
live node/DNS proof, legacy transfer or physical-device acceptance. Windows
factory cases still execute the actual captured interface/DHCP and handoff path.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("desktop_node_bootstrap", ROOT / "deploy/test_windows_physical_bootstrap.py")
BOOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOT)
PREP = BOOT.PREP
TAGS = tuple(value for value in BOOT.TAGS if value not in ("routervpn_native_pq", "routervpn_windows_physical_composition"))


def checked_sources(source):
    source = PREP.checked_vendor(Path(source))
    records = {}
    copies = PREP.pt_copies()
    PREP.preflight_pt_files(source, copies)
    for name, relative in PREP.PEER_TEMPLATES.items():
        copies[relative] = (ROOT / "mobile/desktop" / name).read_bytes()
    for path in sorted((ROOT / "mobile/desktop").glob("*.go.tmpl")):
        if path.name.startswith(("node", "mtu", "external")) and path.name not in PREP.PT_TEMPLATES and path.name not in PREP.BOX_TEMPLATES and path.name not in PREP.PEER_TEMPLATES:
            copies["cmd/sing-box/routervpn_" + path.name.removesuffix(".tmpl")] = path.read_bytes()
    for package in PREP.RELAY.PACKAGES:
        for path in sorted((ROOT / "internal" / package).glob("*.go")):
            if path.name.endswith("_test.go"):
                continue
            raw = path.read_bytes()
            for name in PREP.RELAY.PACKAGES:
                raw = raw.replace(('"router-vpn/internal/' + name + '"').encode(),
                    ('"github.com/sagernet/sing-box/experimental/libbox/routervpn/' + name + '"').encode())
            copies["experimental/libbox/routervpn/" + package + "/" + path.name] = raw
    for package in PREP.PURE:
        for path in sorted((ROOT / "internal" / package).glob("*.go")):
            if not path.name.endswith("_test.go"):
                copies["routervpn/" + package + "/" + path.name] = PREP.relocated_shared_source(path.read_bytes())
    for path in sorted((ROOT / "mobile/amnezia").glob("*.tmpl")):
        copies["protocol/routervpnamnezia/" + path.name.removesuffix(".tmpl")] = path.read_bytes()
    copies["service/routervpnperformance/service.go"] = (ROOT / "mobile/performance/service.go.tmpl").read_bytes()
    copies["routervpn_services.go"] = (ROOT / "mobile/performance/box.go.tmpl").read_bytes()
    for relative, expected in copies.items():
        target = source / relative
        if target.is_symlink() or not target.is_file() or target.read_bytes() != expected:
            raise ValueError("Node native source differs from shipping bytes: " + relative)
        records[relative] = hashlib.sha256(expected).hexdigest()
    box = source / "box.go"
    if box.is_symlink() or PREP.node_capture_source(box.read_text(encoding="utf-8")) != box.read_bytes():
        raise ValueError("Node source snapshot is absent or moved from actual Box construction")
    records["box.go"] = hashlib.sha256(box.read_bytes()).hexdigest()
    for name in ("go.mod", "go.sum"):
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Node native dependency record is not a retained regular file")
        records[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted((source / "protocol/routervpnamnezia").glob("*.go")):
        if path.is_symlink():
            raise ValueError("Linked encrypted peer/native implementation")
        records[path.relative_to(source).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    records["runner"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return source, records


def run(command, *, cwd, env, timeout):
    if platform.system() == "Windows":
        return BOOT.IDENTITY.run(command, cwd=cwd, env=env, timeout=timeout)
    process = subprocess.Popen([str(value) for value in command], cwd=cwd, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        raw, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        raw, _ = process.communicate(timeout=10)
        raise RuntimeError("Node test process group timed out and was joined:\n" + raw[-16384:].decode("utf-8", errors="replace"))
    return process.returncode, raw.decode("utf-8", errors="replace")


def selected_compiler(go, source, env):
    status, output = run([go, "env", "-json", "GOROOT", "GOVERSION", "GOHOSTOS", "GOHOSTARCH"], cwd=source, env=env, timeout=30)
    if status:
        raise ValueError("Node native toolchain selection failed:\n" + output[-8192:])
    identity = json.loads(output)
    system = platform.system().lower()
    if identity.get("GOVERSION") != "go1.26.3" or identity.get("GOHOSTOS") != system or system not in ("linux", "windows") or identity.get("GOHOSTARCH") not in ("amd64", "arm64"):
        raise ValueError("Node composition requires the pinned actual Linux or Windows compiler")
    arch = identity["GOHOSTARCH"]
    if env.get("GOOS", system) != system or env.get("GOARCH", arch) != arch:
        raise ValueError("Node composition cannot execute cross-compiled evidence")
    root = Path(identity["GOROOT"])
    compiler = root / "bin" / ("go.exe" if system == "windows" else "go")
    if not root.is_absolute() or not compiler.is_file():
        raise ValueError("Node composition lost its selected compiler")
    captured = dict(env, GOROOT=str(root), GOTOOLCHAIN="local", GOOS=system, GOARCH=arch, GOFLAGS="", GOWORK="off")
    status, again = run([compiler, "env", "-json", "GOROOT", "GOVERSION", "GOHOSTOS", "GOHOSTARCH"], cwd=source, env=captured, timeout=30)
    if status or json.loads(again) != identity:
        raise ValueError("Node native compiler changed during selection")
    return compiler, captured, arch


def mutants(source, windows):
    def changed(relative, before, after):
        raw = (source / relative).read_text(encoding="utf-8")
        return BOOT.IDENTITY.replace_once(raw, before, after)
    lower = "routervpn/desktoppt/node_physical.go"
    network = "routervpn/desktoppt/node_network.go"
    box = "routervpn_desktop_node_box_physical.go"
    admission = "cmd/sing-box/routervpn_node_command_admission.go"
    transfer = "cmd/sing-box/routervpn_node_command_physical.go"
    readiness = "cmd/sing-box/routervpn_node_command_ready.go"
    selected_dns = "routervpn_desktop_node_box_dns.go"
    result = [
        ("late-handshake-phase", lower, "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeEncryptedPreReadyHandshake", "awg2-fast",
         "actual eager encrypted Box startup", changed(lower, "!owner.SocketCurrent()", "!owner.Current()")),
        ("uncaptured-peer-tuple", lower, "./routervpn/desktoppt", "TestRouterVPNNodePhysicalHandshakePhaseAndExactPolicy", "",
         "node handshake admitted an uncaptured application or outer tuple", changed(lower, "closed || !allowed || owner == nil", "closed || (!allowed && false) || owner == nil")),
        ("substituted-box-source", box, ".", "TestRouterVPNDesktopNodePhysicalBoxRejectsSubstitutedGraph", "credential",
         "substituted native graph acquired a node lower factory", changed(box, "routerVPNNodeOptionsDigest(s.ctx, compiled) != s.routerVPNNodeOptions", "false && routerVPNNodeOptionsDigest(s.ctx, compiled) != s.routerVPNNodeOptions")),
        ("forgot-restored-tun-mtu", box, ".", "TestRouterVPNDesktopNodePhysicalBoxRestoresCapturedMTU", "1392",
         "actual node TUN ownership", changed(box, "expectedMTU = restored", "expectedMTU = capture.ConfiguredMTU")),
        ("equal-source-other-owner", network, "./routervpn/desktoppt", "TestRouterVPNNodePhysicalHandshakePhaseAndExactPolicy", "",
         "another compiler owner adopted this native generation", changed(network, "n.policy != policy", "false && n.policy != policy")),
        ("foreign-handoff-reply", admission, "./cmd/sing-box", "TestRouterVPNDesktopNodePhysicalCommandAdmissionRejectsForeignReplies", "source",
         "foreign handoff acknowledgement activated native sockets", changed(admission, "actual != expected", "false && actual != expected")),
        ("ignored-native-stop", admission, "./cmd/sing-box", "TestRouterVPNDesktopNodePhysicalCommandAdmissionExactStop", "after-ready",
         "exact captured stop did not retire pending native admission", changed(admission,
         "\t\tif bounded.Err() != nil || a.state.Load() != 1 || a.files.stopRequested(a.metadata.SessionID, a.metadata.ConfigSHA256) ||\n",
         "\t\tif bounded.Err() != nil || a.state.Load() != 1 || (false && a.files.stopRequested(a.metadata.SessionID, a.metadata.ConfigSHA256)) ||\n")),
        ("unbound-private-predecessor", transfer, "./cmd/sing-box", "TestRouterVPNDesktopNodePhysicalCommandTransferInput", "wrong-hash",
         "command accepted missing, changed or unbound predecessor input", changed(transfer, "hex.EncodeToString(sum[:]) != digest", "hex.EncodeToString(sum[:]) != digest && false")),
        ("unjoined-native-outcome", network, "./routervpn/desktoppt", "TestRouterVPNNodePhysicalRetirementKeepsExactJoinedSource", "partial-before-admission",
         "unjoined node acquired or queried a retained protection result", changed(network, "n.closed && n.retired", "(n.closed || true) && n.retired")),
        ("failed-cleanup-receipt", transfer, "./cmd/sing-box", "TestRouterVPNDesktopNodePhysicalCommandRetirementReceipt", "owner-failed",
         "retirement did not preserve its explicit outcome", changed(transfer, "if err != nil || ctx.Err() != nil {", "if ctx.Err() != nil {")),
        ("skipped-selected-dns", readiness, "./cmd/sing-box", "TestRouterVPNDesktopNodePhysicalCommandReadyRequiresFreshDNS", "exact",
         "actual DNS capability did not precede its exact readiness receipt", changed(readiness, "elapsed, err := owner.MeasureSelectedDNS(ctx)", "elapsed, err := time.Millisecond, error(nil)")),
        ("adopted-replaced-dns-tun", selected_dns, ".", "TestRouterVPNDesktopNodePhysicalDNSCapturedOwner", "tun-replaced",
         "Node DNS proof adopted a failed or replaced native path", changed(selected_dns, "same := owner.inbound == inbound", "same := true")),
    ]
    if windows:
        factory = "routervpn/desktoppt/node_physical_windows.go"
        result.append(("changed-prepared-baseline", factory, "./routervpn/desktoppt", "TestRouterVPNNodePhysicalWindowsAdmissionRejectsChangedOwners", "baseline-changed",
                       "failed node handoff admitted eager sockets or discarded partial source", changed(factory, "currentBaseline != baseline", "false && currentBaseline != baseline")))
        result.append(("dropped-restored-mtu-source", transfer, "./cmd/sing-box", "TestRouterVPNDesktopNodePhysicalCommandRestoredMTU", "exact",
                       "captured live MTU did not recompile the original private graph", changed(transfer,
                       "mobilemultihop.NewDesktopNodePolicyWithMTU(original, session, runtime.GOOS, restoredMTU)",
                       "mobilemultihop.NewDesktopNodePolicyWithMTU(original, session, runtime.GOOS, 0)")))
    return result


def execute(source, go="go", *, prospective=False, env=None, bootstrap_only=False):
    if prospective:
        raise ValueError("Node native source gate does not admit a prospective OS predicate")
    source, before = checked_sources(source)
    compiler, captured, arch = selected_compiler(go, source, dict(os.environ if env is None else env))
    windows = platform.system() == "Windows"
    race = [] if bootstrap_only or windows and arch == "arm64" else ["-race"]
    captured["CGO_ENABLED"] = "1" if race else "0"
    suites = [
        ("command", "./cmd/sing-box", "^TestRouterVPNDesktopNodePhysicalCommand",
         tuple("TestRouterVPNDesktopNodePhysicalCommand" + name for name in ("SourceBoundary", "RestoredMTU", "TransferInput", "RetirementReceipt", "ReadyRequiresFreshDNS", "AdmissionExactHandshake", "AdmissionRejectsForeignReplies", "AdmissionExactStop", "AdmissionRejectsForeignStop", "AdmissionCancellationAndReplacement", "AdmissionCloseRetiresEnteredCallback", "AdmissionClosePreservesFailure", "AdmissionEveryCloseJoins"))),
        ("factory", "./routervpn/desktoppt", "^TestRouterVPNNodePhysical",
         tuple("TestRouterVPNNodePhysical" + name for name in ("SeparateRegistriesAndUnpreparedRejection", "HandshakePhaseAndExactPolicy", "FactoryCancellationJoinsPartialOwner", "RetirementKeepsExactJoinedSource", "AdmissionRetainsExactPolicy", "AdmissionCapturesExactPredecessor")) +
         (tuple("TestRouterVPNNodePhysicalWindows" + name for name in ("CapturesPreparedOwner", "AdmissionRejectsChangedOwners", "CloseJoinsAdmission")) if windows else ())),
        ("box", ".", "^TestRouterVPNDesktopNodePhysical",
         tuple("TestRouterVPNDesktopNodePhysicalBox" + name for name in ("RejectsSubstitutedGraph", "RequiresPreparedOwner", "RetainsMTUAndExactRollback", "RestoresCapturedMTU")) +
         ("TestRouterVPNDesktopNodePhysicalDNSCapturedOwner", "TestRouterVPNDesktopNodePhysicalDNSRetirementCancelsQuery")),
        ("encrypted", "./protocol/routervpnamnezia", "^TestRouterVPNDesktopNodeEncrypted",
         ("TestRouterVPNDesktopNodeEncryptedPreReadyHandshake", "TestRouterVPNDesktopNodeEncryptedWrongPeerRejected", "TestRouterVPNDesktopNodeEncryptedConfiguredCoverStartup", "TestRouterVPNDesktopNodeEncryptedSelectedDNSIsFresh")),
    ]
    with tempfile.TemporaryDirectory(prefix="routervpn-node-physical-") as directory:
        workspace = Path(directory)
        build = [compiler, "test", "-c", "-mod=readonly", "-tags=" + ",".join(TAGS), *race, "-ldflags=-checklinkname=0"]
        suffix = ".exe" if windows else ""
        for name, package, selector, required in suites:
            binary = workspace / (name + ".test" + suffix)
            status, output = run([*build, "-o", binary, package], cwd=source, env=captured, timeout=600)
            if status:
                raise ValueError("Node " + name + " native compilation failed:\n" + output[-32768:])
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            status, output = run([binary, "-test.run=" + selector, "-test.count=1", "-test.timeout=90s", "-test.v"], cwd=source, env=captured, timeout=105)
            print(output, end="" if output.endswith("\n") else "\n", flush=True)
            if status or any("--- PASS: " + test + " (" not in output for test in required) or "--- SKIP:" in output or "DATA RACE" in output:
                raise ValueError("Node " + name + " omitted a required native boundary")
            if name == "encrypted" and any("--- PASS: TestRouterVPNDesktopNodeEncryptedPreReadyHandshake/" + mode + " (" not in output for mode in ("wg", "awg2-fast", "awg2-strong")):
                raise ValueError("Node encrypted gate omitted a complete base profile")
            if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
                raise ValueError("Node native executable changed during execution")
        for label, relative, package, test, subtest, witness, replacement in mutants(source, windows):
            changed = workspace / (label + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = workspace / (label + ".json")
            overlay.write_text(json.dumps({"Replace": {str(source / relative): str(changed)}}), encoding="utf-8")
            binary = workspace / (label + ".test" + suffix)
            status, output = run([*build, "-overlay=" + str(overlay), "-o", binary, package], cwd=source, env=captured, timeout=600)
            if status:
                raise ValueError("Node negative control failed to compile: " + label + "\n" + output[-16384:])
            selector = "^" + test + "$" + ("/^" + subtest + "$" if subtest else "")
            status, output = run([binary, "-test.run=" + selector, "-test.count=1", "-test.timeout=45s", "-test.v"], cwd=source, env=captured, timeout=55)
            if status == 0 or "--- FAIL: " + test + " (" not in output or witness not in output or any(value in output for value in ("--- SKIP:", "DATA RACE", "panic: test timed out")):
                raise ValueError("Node negative control missed its precise production defect: " + label + "\n" + output[-16384:])
            print("Rejected native Node production mutant: " + label, flush=True)
    if checked_sources(source)[1] != before:
        raise ValueError("Node native source changed during actual execution")
    print("Exact native Node startup, captured IPC, retained TUN/MTU rollback, real WG/AWG encrypted TCP/UDP and wrong-key controls passed. OS permits/TUN remain explicit fixtures; kernel composition and both-direction host activation remain separate.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--go", default="go")
    parser.add_argument("--standalone", action="store_true")
    args = parser.parse_args()
    if args.standalone:
        if args.source is not None:
            parser.error("--standalone owns a fresh prepared Windows core")
        BOOT.standalone(args.go, native_test=execute)
    else:
        if args.source is None:
            parser.error("a prepared native core or --standalone is required")
        execute(args.source, args.go)
