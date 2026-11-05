#!/usr/bin/env python3
"""Execute the captured ordinary Windows command, Box and native proxy proofs.

The exact prepared shipping compiler, command, generated Windows factory,
lower outbound, real proxy transports, selected DNS and proof code execute.
These composition fixtures inject the privileged OS source and TUN boundaries;
actual WFP/isolated-token/Wintun gates remain separate mandatory evidence.
No OS admission overlay, live provider, public default route or Connected
device acceptance is claimed by this local fixture runner.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "windows_external_physical_bootstrap", ROOT / "deploy/test_windows_physical_bootstrap.py")
BOOT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BOOT)
IDENTITY = BOOT.IDENTITY

HYSTERIA2_COMMAND = "TestRouterVPNDesktopExternalPhysicalCommandHysteria2SupportedTargets"
HYSTERIA2_BOX_CASES = tuple("TestRouterVPNDesktopExternalPhysicalIntegration/" + case for case in (
    "hysteria2/proof-and-mtu", "hysteria2/reject/dns", "hysteria2/reject/exit", "hysteria2/reject/credential",
    "hysteria2/reject/tls-name", "hysteria2/reject/tls-root", "hysteria2/reject/lower-denied",
    "hysteria2/reject/peer-tls-name", "hysteria2/reject/truncated", "hysteria2/cancelled-proof",
    "latency50/hysteria2", "latency50/hysteria2/source", "latency50/hysteria2/capture",
    "latency50/hysteria2/session", "latency50/hysteria2/current"))
HYSTERIA2_LAYER_PROTOCOLS = ("hysteria2-aes", "hysteria2-aes-xor")
HYSTERIA2_LAYER_BOX_CASES = tuple(case.replace("hysteria2", protocol) for protocol in HYSTERIA2_LAYER_PROTOCOLS for case in HYSTERIA2_BOX_CASES) + tuple(
    "TestRouterVPNDesktopExternalPhysicalIntegration/" + protocol + "/reject/layer-key" for protocol in HYSTERIA2_LAYER_PROTOCOLS) + (
    "TestRouterVPNDesktopExternalPhysicalIntegration/hysteria2-aes-xor/reject/whitening",)
HYSTERIA2_FACTORY_CASES = ("TestRouterVPNExternalPhysicalStartupSocketPhase/hysteria2",
    "TestRouterVPNExternalPhysicalActualBytesAndCapturedTuple/hysteria2-udp")
SOCKS_COMMAND = "TestRouterVPNDesktopExternalPhysicalCommandSOCKSSupportedTargets"
SOCKS_BOX_CASES = tuple("TestRouterVPNDesktopExternalPhysicalIntegration/" + case for case in (
    "socks5/proof-and-mtu", "socks5/reject/dns", "socks5/reject/exit", "socks5/reject/credential",
    "socks5/reject/tls-name", "socks5/reject/tls-root", "socks5/reject/lower-denied", "socks5/reject/truncated",
    "socks5/reject/auth-downgrade", "socks5/reject/relay-domain", "socks5/reject/relay-wildcard",
    "socks5/reject/relay-zero", "socks5/reject/relay-uncaptured", "socks5/reject/control-eof",
    "socks5/independent-associations-control-eof", "socks5/selected-dns-retained-control-retirement", "socks5/dns-cached-control-loss", "socks5/cancelled-proof", "socks5/replacement-keeps-new-source",
    "latency50/socks5", "latency50/socks5/source", "latency50/socks5/capture", "latency50/socks5/session", "latency50/socks5/current"))
SOCKS_FACTORY_CASES = tuple("TestRouterVPNExternalSOCKS" + name for name in (
    "RequiresExactNativeRoot", "AssociationsOwnDistinctControlAndRelaySockets",
    "CancelledAuthenticationJoinsOnlyItsOperation", "RejectsRetiredManagersAndForeignRelayCalls",
    "OwnedClosePreservesMixedFailures", "RootCloseJoinsAndRetainsOriginalFailure", "DifferentPublicRelayKeepsExactNumericTuple"))
STREAM_BOX_CASES = tuple("TestRouterVPNDesktopExternalPhysicalIntegration/" + leaf
    for protocol in ("http-connect", "https-connect", "shadowsocks")
    for leaf in (protocol + "/proof-and-mtu",
        *(protocol + "/reject/" + fault for fault in ("dns", "exit", "credential", "tls-name", "tls-root", "lower-denied")),
        "latency50/" + protocol,
        *("latency50/" + protocol + "/" + fault for fault in ("source", "capture", "session", "current"))))
PACKET_COMMANDS = ("TestRouterVPNDesktopExternalPhysicalCommandWireGuardSupportedTargets",
                   "TestRouterVPNDesktopExternalPhysicalCommandAmneziaSupportedTargets")
OPENVPN_COMMAND = "TestRouterVPNDesktopExternalPhysicalCommandOpenVPNSupportedTargets"
OPENVPN_COMMAND_CASES = (OPENVPN_COMMAND, *(OPENVPN_COMMAND + "/" + network + "/" + fault
    for network in ("tcp", "udp", "mixed")
    for fault in ("valid", "source", "credential", "username", "endpoint", "tls-name", "fingerprint", "remote-order", "remote-network", "remote-removed", "session", "original-config")))
OPENVPN_FACTORY_CASES = tuple("TestRouterVPNExternalPhysicalStartupSocketPhase/openvpn-" + network
    for network in ("tcp", "udp", "mixed"))
PACKET_PROTOCOLS = ("wireguard", "awg2-fast", "awg2-strong")
PACKET_BOX_CASES = tuple("TestRouterVPNDesktopExternalPhysicalIntegration/" + leaf
    for protocol in PACKET_PROTOCOLS
    for leaf in (protocol + "/proof-and-mtu", protocol + "/cancelled-proof",
        *(protocol + "/reject/" + fault for fault in
          ("dns", "exit", "credential", "tls-name", "tls-root", "lower-denied", "psk", "truncated")),
        *((protocol + "/reject/parameters",) if protocol != "wireguard" else ()),
        "latency50/" + protocol,
        *("latency50/" + protocol + "/" + fault for fault in ("source", "capture", "session", "current"))))
PACKET_FACTORY_CASES = tuple(parent + "/" + protocol + suffix
    for protocol in ("wireguard", "amneziawg-fast", "amneziawg-strong")
    for parent, suffix in (("TestRouterVPNExternalPhysicalStartupSocketPhase", ""),
                          ("TestRouterVPNExternalPhysicalActualBytesAndCapturedTuple", "-udp")))


LATENCY_OBSERVATION_CASES = tuple("TestRouterVPNDesktopExternalPhysicalBoxLatencyObservation/" + leaf for leaf in (
    "worker-and-drain-bounds", "blocked-drain-retains-observation", "progress-through-fifty", "complete-before-drain", "cancelled-before-drain",
    "deadline", "deadline-and-drain-failure", "late-result", "foreign-request", "malformed-status",
    "drain-failure", "unjoined", "replacement-after-drain"))

LATENCY_BOUNDARIES = ("latency-dns", "latency-tls", "latency-partial", "cancel", "network", "native-owner")


def baseline_runs(name, selection, required):
    if name != "box":
        return ((name, selection, required),)
    # Compile one captured image, then execute each independent transport under
    # the original deadlines. No added family consumes another's proof budget.
    parent = "TestRouterVPNDesktopExternalPhysicalIntegration"
    required = (*required, *LATENCY_OBSERVATION_CASES, *(case for case in STREAM_BOX_CASES if case not in required))
    ordinary = tuple(case for case in required if not case.startswith(parent))
    runs = [("box", "^TestRouterVPNDesktopExternalPhysicalBox", ordinary)]
    for protocol in ("http-connect", "https-connect", "shadowsocks", "hysteria2", *HYSTERIA2_LAYER_PROTOCOLS, "socks5", *PACKET_PROTOCOLS):
        for branch in (protocol, "latency50/" + protocol):
            prefix = parent + "/" + branch
            verdicts = tuple(case for case in required if case == prefix or case.startswith(prefix + "/"))
            runs.append(("box/" + branch, "^" + parent + "$/" + "/".join("^" + part + "$" for part in branch.split("/")),
                         verdicts))
    runs.append(("box/latency-retirement", "^" + parent + "$/^latency50$/^(" + "|".join(LATENCY_BOUNDARIES) + ")$",
                 tuple(parent + "/latency50/" + leaf for leaf in LATENCY_BOUNDARIES)))
    miscellaneous = ("delayed-accept-retains-prior-grant", "network-reset-during-mtu",
                     "network-reset-after-native-publication", "network-reset-during-real-proof")
    runs.append(("box/retirement", "^" + parent + "$/^(" + "|".join(miscellaneous) + ")$",
                 tuple(parent + "/" + leaf for leaf in miscellaneous)))
    return tuple(runs)


JOURNAL_COMMAND_CASES = tuple("TestRouterVPNDesktopExternalPhysicalCommandJournal" + name for name in (
    "BeforePrivateInputs", "PublicRequiresCompleteCapture", "WindowsHasNoFileFallback", "RetainedPipeline",
    "PartialRetirementRequiresJoin", "AdmissionCloseJoinsCallback", "TransferInput", "RetirementReceipt",
            "LegacyUnprotectedPolicy", "LegacyUnprotectedPublicStop", "ParserOwnedFlags"))
JOURNAL_FACTORY_CASES = (
    "TestRouterVPNExternalPhysicalJournalAdmissionCapturesDurableBarrier",
    "TestRouterVPNExternalPhysicalRetirementKeepsExactJoinedSource",
    "TestRouterVPNExternalPhysicalWindowsRetirementKeepsOriginalPredecessor",
)


def checked_sources(source):
    source, records = BOOT.sources(source)
    # The bootstrap gate already owns the Box, lower factory and shared socket
    # closure. This suite also executes the standalone command and its exact
    # shared external compiler, so verify those copied bytes explicitly.
    for template in sorted((ROOT / "mobile/desktop").glob("external*.go.tmpl")):
        if template.name in BOOT.PREP.PT_TEMPLATES or template.name in BOOT.PREP.BOX_TEMPLATES:
            continue
        target = source / "cmd/sing-box" / ("routervpn_" + template.name.removesuffix(".tmpl"))
        expected = template.read_bytes()
        if template.is_symlink() or target.is_symlink() or not target.is_file() or target.read_bytes() != expected:
            raise ValueError("Ordinary Windows command differs from shipping bytes: " + template.name)
        records[target.relative_to(source).as_posix()] = hashlib.sha256(expected).hexdigest()
    records.update(BOOT.PREP.RELAY.OBSERVATION.verify(source))
    for path in sorted((ROOT / "internal/mobilemultihop").glob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        expected = BOOT.PREP.RELAY.OBSERVATION.rewrite(path.read_bytes())
        for package in BOOT.PREP.RELAY.PACKAGES:
            expected = expected.replace(('"router-vpn/internal/' + package + '"').encode(),
                ('"github.com/sagernet/sing-box/experimental/libbox/routervpn/' + package + '"').encode())
        target = source / "experimental/libbox/routervpn/mobilemultihop" / path.name
        if path.is_symlink() or target.is_symlink() or not target.is_file() or target.read_bytes() != expected:
            raise ValueError("Ordinary Windows compiler differs from shipping bytes: " + path.name)
        records[target.relative_to(source).as_posix()] = hashlib.sha256(expected).hexdigest()
    records["ordinary-runner"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return source, records


def mtu_retention_mutants(source):
    engine_path = "routervpn_desktop_tor_box_mtu.go"
    manager_path = "adapter/inbound/routervpn_mtu.go"
    engine = (source / engine_path).read_text(encoding="utf-8")
    manager = (source / manager_path).read_text(encoding="utf-8")
    case = "TestRouterVPNDesktopExternalPhysicalIntegration/network-reset-after-native-publication"
    return (
        ("discarded-original-engine-candidate", engine_path, ".", case,
         "late network cancellation discarded the original engine candidate",
         IDENTITY.replace_once(engine, "\te.tun = current\n", "\te.tun = expected\n")),
        ("discarded-original-manager-candidate", manager_path, ".", case,
         "late network cancellation discarded the original manager candidate",
         IDENTITY.replace_once(manager, "\t\t\tm.inboundByTag[expected.Tag()] = value\n",
                               "\t\t\tm.inboundByTag[expected.Tag()] = expected\n")),
    )


def mutants(source):
    command = (source / "cmd/sing-box/routervpn_external.go").read_text(encoding="utf-8")
    admission = (source / "cmd/sing-box/routervpn_external_command_admission.go").read_text(encoding="utf-8")
    factory = (source / "routervpn/desktoppt/external_physical_windows.go").read_text(encoding="utf-8")
    dispatch = (source / "cmd/sing-box/routervpn_external_command_journal.go").read_text(encoding="utf-8")
    network = (source / "routervpn/desktoppt/external_network.go").read_text(encoding="utf-8")
    unjoined = IDENTITY.replace_once(admission,
        "\tif previous := a.state.Swap(2); previous != 2 {",
        "\tprevious := a.state.Swap(2)\n\tif previous == 2 { return nil }\n\tif previous != 2 {")
    return (
        ("missing-eager-endpoint-phase", "routervpn/desktoppt/external_network.go", "./routervpn/desktoppt",
         "TestRouterVPNExternalPhysicalStartupSocketPhase",
         "ordinary transport changed its separate startup socket/readiness phase",
         IDENTITY.replace_once(network, "n.sockets = meta.TargetOS == runtime.GOOS", "n.sockets = false && meta.TargetOS == runtime.GOOS")),
        ("missing-inherited-parent", "cmd/sing-box/routervpn_external_command_journal.go", "./cmd/sing-box",
         "TestRouterVPNDesktopExternalPhysicalCommandJournalWindowsHasNoFileFallback",
         "public Windows external command read private files before inherited journal admission",
         IDENTITY.replace_once(dispatch, 'if runtime.GOOS == "windows" && (source != "" || config != "" || transfer != "") || journal !=',
                               'if false && runtime.GOOS == "windows" && (source != "" || config != "" || transfer != "") || journal !=')),
        ("protected-empty-options", "cmd/sing-box/routervpn_external_command_journal.go", "./cmd/sing-box",
         "TestRouterVPNDesktopExternalPhysicalCommandJournalLegacyUnprotectedPolicy",
         "protected original policy bypassed inherited journal through empty flags",
         IDENTITY.replace_once(dispatch, 'err != nil || captured.KillSwitchPolicy != "off"',
                               'err != nil || false && captured.KillSwitchPolicy != "off"')),
        ("duplicate-owned-command-option", "cmd/sing-box/routervpn_external.go", "./cmd/sing-box",
         "TestRouterVPNDesktopExternalPhysicalCommandJournalParserOwnedFlags",
         "duplicate or empty owned option reached the external dispatcher",
         IDENTITY.replace_once(command, "\trouterVPNExternalOwnedFlags(command.Flags())",
                               "\tif false { routerVPNExternalOwnedFlags(command.Flags()) }")),
        ("private-input-before-authentication", "cmd/sing-box/routervpn_external.go", "./cmd/sing-box",
         "TestRouterVPNDesktopExternalPhysicalCommandJournalBeforePrivateInputs",
         "external private input preceded authenticated parent admission",
         IDENTITY.replace_once(command, 'if err := journal.authenticate(parent, files); err != nil {',
                               'if err := journal.authenticate(parent, files); false && err != nil {')),
        ("missing-native-handoff", "cmd/sing-box/routervpn_external.go", "./cmd/sing-box",
         "TestRouterVPNDesktopExternalPhysicalCommandAdmissionCannotSkipBarrier",
         "unacknowledged native handoff published a connected proof",
         IDENTITY.replace_once(command, "if !admission.admitted() {", "if false && !admission.admitted() {")),
        ("foreign-acknowledgement", "cmd/sing-box/routervpn_external_command_admission.go", "./cmd/sing-box",
         "TestRouterVPNDesktopExternalPhysicalCommandAdmissionRejectsForeignReplies",
         "foreign handoff acknowledgement activated native sockets",
         IDENTITY.replace_once(admission, "actual != expected", "false && actual != expected")),
        ("changed-prepared-baseline", "routervpn/desktoppt/external_physical_windows.go", "./routervpn/desktoppt",
         "TestRouterVPNExternalPhysicalWindowsAdmissionRetiresFailures",
         "failed handoff admitted sockets or discarded its partial native owner",
         IDENTITY.replace_once(factory, "currentBaseline != baseline", "false && currentBaseline != baseline")),
        ("dropped-handoff-retention", "routervpn/desktoppt/external_physical_windows.go", "./routervpn/desktoppt",
         "TestRouterVPNExternalPhysicalWindowsCapturesPolicyAndRetainsLateOwner",
         "Windows ordinary factory changed selected protection",
         IDENTITY.replace_once(factory, "RetainBaselineForHandoff: true", "RetainBaselineForHandoff: false")),
        ("forgotten-retirement-error", "cmd/sing-box/routervpn_external_command_admission.go", "./cmd/sing-box",
         "TestRouterVPNDesktopExternalPhysicalCommandAdmissionClosePreservesFailure",
         "failed admission cleanup was forgotten by repeated close", unjoined),
        ("unjoined-retirement", "cmd/sing-box/routervpn_external_command_admission.go", "./cmd/sing-box",
         "TestRouterVPNDesktopExternalPhysicalCommandAdmissionEveryCloseJoins",
         "duplicate admission close returned before the captured callback joined", unjoined),
        ("early-stopped-ack", "cmd/sing-box/routervpn_external.go", "./cmd/sing-box",
         "TestRouterVPNDesktopExternalPhysicalCommandAdmissionCleanupFailureCannotAcknowledgeStop",
         "unproved admission cleanup published a successful stopped receipt",
         IDENTITY.replace_once(command,
             '\tif admission.close() != nil {\n\t\tprogress.Stage = "cleanup-pending"',
             '\tif false && admission.close() != nil {\n\t\tprogress.Stage = "cleanup-pending"')),
    )


def report_baseline(name, required, status, output):
    # Redirected Windows Python output can default to cp1252 while the native
    # process emits UTF-8. Preserve its exact diagnostic before checking status.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    if (status or not required or
            any(len(re.findall(r"(?m)^[ \t]*--- PASS: " + re.escape(test) + r" \([^\r\n]*\)[ \t]*$", output)) != 1 for test in required) or
            any(marker in output for marker in ("--- FAIL:", "--- SKIP:", "DATA RACE", "panic:", "fatal error:", "[build failed]"))):
        raise ValueError("Ordinary Windows " + name + " did not prove its native composition"
                         + " (native exit " + str(status) + ", 0x" + format(status & 0xffffffff, "08x") + ")")


def execute(source, go="go", *, prospective=False, env=None, bootstrap_only=False):
    if prospective or platform.system() != "Windows":
        raise ValueError("Ordinary Windows composition requires its unmodified native host")
    source, before = checked_sources(source)
    compiler, captured, architecture = IDENTITY.selected_compiler(
        go, source, dict(os.environ if env is None else env))
    race = ["-race"] if architecture == "amd64" and not bootstrap_only else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    suites = (
        ("command", "./cmd/sing-box", "^TestRouterVPNDesktopExternalPhysicalCommand",
         tuple("TestRouterVPNDesktopExternalPhysicalCommand" + name for name in
             ("RequiresExactDerivedInputs", "SeparatesProofAndMailboxIdentity", "RejectsRelabeledNetworkProof", "UsesActualPreparedNativeFactory",
              "AdmissionExactHandshake", "AdmissionRejectsForeignReplies", "AdmissionCancellationAndReplacement", "AdmissionCloseRetiresEnteredCallback", "AdmissionCannotSkipBarrier",
              "AdmissionClosePreservesFailure", "AdmissionEveryCloseJoins", "AdmissionCleanupFailureCannotAcknowledgeStop")) + JOURNAL_COMMAND_CASES + (HYSTERIA2_COMMAND, SOCKS_COMMAND) + PACKET_COMMANDS + OPENVPN_COMMAND_CASES),
        ("box", ".", "^TestRouterVPNDesktopExternalPhysical",
         tuple("TestRouterVPNDesktopExternalPhysical" + name for name in
             ("BoxRejectsChangedDerivedGraph", "BoxRequiresPreparedStartedOwner", "BoxRetainsExactPolicyAndDerivedIdentity",
              "BoxRejectsTUNReadbackAndBinding", "BoxCancelAndNetworkResetRetireExactOwner", "BoxMTUReadbackKeepsGuardAndDerivedPolicy", "Integration")) + HYSTERIA2_BOX_CASES + HYSTERIA2_LAYER_BOX_CASES + SOCKS_BOX_CASES + PACKET_BOX_CASES),
        ("factory", "./routervpn/desktoppt", "^TestRouterVPNExternal(Physical(Windows|Admission|Journal|Retirement|StartupSocketPhase|ActualBytesAndCapturedTuple)|SOCKS)",
         ("TestRouterVPNExternalPhysicalWindowsCapturesPolicyAndRetainsLateOwner",
          "TestRouterVPNExternalPhysicalWindowsAdmissionRetiresFailures",
          "TestRouterVPNExternalPhysicalWindowsAdmissionCloseJoinsEnteredCallback",
          "TestRouterVPNExternalPhysicalAdmissionRetainsExactPolicy") + JOURNAL_FACTORY_CASES + HYSTERIA2_FACTORY_CASES + SOCKS_FACTORY_CASES + PACKET_FACTORY_CASES + OPENVPN_FACTORY_CASES),
    )
    with tempfile.TemporaryDirectory(prefix="routervpn-windows-external-") as directory:
        for name, package, selection, required in suites:
            binary = Path(directory) / (name + ".test.exe")
            command = [compiler, "test", "-c", "-mod=readonly", "-tags=" + ",".join(BOOT.TAGS),
                       *race, "-ldflags=-checklinkname=0", "-o", binary, package]
            status, output = IDENTITY.run(command, cwd=source, env=captured, timeout=600)
            if status:
                raise ValueError("Ordinary Windows " + name + " compilation failed:\n" + output[-32768:])
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            for run_name, run_selection, run_required in baseline_runs(name, selection, required):
                status, output = IDENTITY.run(
                    [binary, "-test.run=" + run_selection, "-test.count=1", "-test.timeout=120s", "-test.v"],
                    cwd=source, env=captured, timeout=135)
                report_baseline(run_name, run_required, status, output)
                if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
                    raise ValueError("Ordinary Windows composition binary changed during execution")
        for label, relative, package, test, witness, replacement in (*mutants(source), *mtu_retention_mutants(source)):
            changed = Path(directory) / (label + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = Path(directory) / (label + ".json")
            overlay.write_text(json.dumps({"Replace": {str(source / relative): str(changed)}}), encoding="utf-8")
            binary = Path(directory) / (label + ".test.exe")
            command = [compiler, "test", "-c", "-mod=readonly", "-tags=" + ",".join(BOOT.TAGS),
                       *race, "-overlay=" + str(overlay), "-ldflags=-checklinkname=0", "-o", binary, package]
            status, output = IDENTITY.run(command, cwd=source, env=captured, timeout=600)
            if status:
                raise ValueError("Ordinary Windows negative control did not compile: " + label + "\n" + output[-16384:])
            status, output = IDENTITY.run([binary, "-test.run=^" + test + "$", "-test.count=1", "-test.timeout=60s", "-test.v"],
                                          cwd=source, env=captured, timeout=75)
            if status == 0 or "--- FAIL: " + test + " (" not in output or witness not in output or \
                    "--- SKIP:" in output or "DATA RACE" in output or "panic: test timed out" in output:
                raise ValueError("Ordinary Windows negative control missed its exact broken behavior: " + label + "\n" + output[-16384:])
            print("Rejected actual ordinary native production mutant: " + label, flush=True)
    if checked_sources(source)[1] != before:
        raise ValueError("Ordinary Windows composition source changed during execution")
    print("Exact ordinary Windows command, generated factory, Box, HTTP/HTTPS CONNECT, Shadowsocks, Hysteria2, SOCKS5, WireGuard and AmneziaWG "
          "selected-DNS/exit proof and rejection suites passed. OS permits/TUN are explicit fixtures; "
          "the inherited journal and retirement controls passed with explicit models; actual native journal/WFP/TUN and device acceptance remain separate.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--go", default="go")
    parser.add_argument("--standalone", action="store_true")
    arguments = parser.parse_args()
    if arguments.standalone:
        if arguments.source is not None:
            parser.error("--standalone owns its newly prepared native source")
        BOOT.standalone(arguments.go, native_test=execute)
    else:
        if arguments.source is None:
            parser.error("a prepared native source or --standalone is required")
        execute(arguments.source, arguments.go)
