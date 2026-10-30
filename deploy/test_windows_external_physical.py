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
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "windows_external_physical_bootstrap", ROOT / "deploy/test_windows_physical_bootstrap.py")
BOOT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BOOT)
IDENTITY = BOOT.IDENTITY


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
    for path in sorted((ROOT / "internal/mobilemultihop").glob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        expected = path.read_bytes()
        for package in BOOT.PREP.RELAY.PACKAGES:
            expected = expected.replace(('"router-vpn/internal/' + package + '"').encode(),
                ('"github.com/sagernet/sing-box/experimental/libbox/routervpn/' + package + '"').encode())
        target = source / "experimental/libbox/routervpn/mobilemultihop" / path.name
        if path.is_symlink() or target.is_symlink() or not target.is_file() or target.read_bytes() != expected:
            raise ValueError("Ordinary Windows compiler differs from shipping bytes: " + path.name)
        records[target.relative_to(source).as_posix()] = hashlib.sha256(expected).hexdigest()
    records["ordinary-runner"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return source, records


def mutants(source):
    command = (source / "cmd/sing-box/routervpn_external.go").read_text(encoding="utf-8")
    admission = (source / "cmd/sing-box/routervpn_external_command_admission.go").read_text(encoding="utf-8")
    factory = (source / "routervpn/desktoppt/external_physical_windows.go").read_text(encoding="utf-8")
    unjoined = IDENTITY.replace_once(admission,
        "\tif previous := a.state.Swap(2); previous != 2 {",
        "\tprevious := a.state.Swap(2)\n\tif previous == 2 { return nil }\n\tif previous != 2 {")
    return (
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
              "AdmissionClosePreservesFailure", "AdmissionEveryCloseJoins", "AdmissionCleanupFailureCannotAcknowledgeStop"))),
        ("box", ".", "^TestRouterVPNDesktopExternalPhysical",
         tuple("TestRouterVPNDesktopExternalPhysical" + name for name in
             ("BoxRejectsChangedDerivedGraph", "BoxRequiresPreparedStartedOwner", "BoxRetainsExactPolicyAndDerivedIdentity",
              "BoxRejectsTUNReadbackAndBinding", "BoxCancelAndNetworkResetRetireExactOwner", "BoxMTUReadbackKeepsGuardAndDerivedPolicy", "Integration"))),
        ("factory", "./routervpn/desktoppt", "^TestRouterVPNExternalPhysical(Windows|Admission)",
         ("TestRouterVPNExternalPhysicalWindowsCapturesPolicyAndRetainsLateOwner",
          "TestRouterVPNExternalPhysicalWindowsAdmissionRetiresFailures",
          "TestRouterVPNExternalPhysicalWindowsAdmissionCloseJoinsEnteredCallback",
          "TestRouterVPNExternalPhysicalAdmissionRetainsExactPolicy")),
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
            status, output = IDENTITY.run(
                [binary, "-test.run=" + selection, "-test.count=1", "-test.timeout=120s", "-test.v"],
                cwd=source, env=captured, timeout=135)
            print(output, end="" if output.endswith("\n") else "\n", flush=True)
            if status or any("--- PASS: " + test + " (" not in output for test in required) or \
                    "--- SKIP:" in output or "DATA RACE" in output:
                raise ValueError("Ordinary Windows " + name + " did not prove its native composition")
            if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
                raise ValueError("Ordinary Windows composition binary changed during execution")
        for label, relative, package, test, witness, replacement in mutants(source):
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
    print("Exact ordinary Windows command, generated factory, Box, HTTP/HTTPS CONNECT and Shadowsocks "
          "selected-DNS/exit proof and rejection suites passed. OS permits/TUN are explicit fixtures; "
          "legacy protection handoff, production activation and device acceptance remain separate.", flush=True)


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
