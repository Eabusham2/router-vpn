#!/usr/bin/env python3
"""Execute owned Windows WFP traffic, blocked control and process-death proofs.

All firewall rules are scoped to the exact subject executable; peers execute
from a different held copy. No host Firewall profile, route or existing user
is modified. Fresh isolated socket accounts follow the shipping expiry and
disabled-account lifecycle, and every actual source must join before removal.
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
    "routervpn_windows_identity_gate", ROOT / "deploy/test_desktop_windows_identity.py")
IDENTITY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(IDENTITY)

REQUIRED = (
    "TestDesktopSocketWindowsNetworkSelectedSnapshot",
    "TestDesktopSocketWindowsNetworkRejectsLeaseSubstitution",
    "TestDesktopSocketWindowsNetworkRejectsMalformedSnapshot",
    "TestDesktopSocketWindowsNetworkActualAdapter",
    "TestDesktopSocketWindowsWFPOwnedTrafficAndRenewal",
    "TestDesktopSocketWindowsWFPBlockedControlRetainsEnteredIO",
    "TestDesktopSocketWindowsWFPActualProcessDeath",
)


def mutants(target):
    policy = (target / "desktop_socket_windows_policy.go").read_text(encoding="utf-8")
    network = (target / "desktop_socket_windows_network.go").read_text(encoding="utf-8")
    return (
        ("ordinary-socket-bypass", "desktop_socket_windows_policy.go", REQUIRED[4],
         "ordinary process socket bypassed the captured WFP baseline",
         IDENTITY.replace_once(policy,
                               'p.pair("deny", family, 1, false, true)',
                               'p.pair("deny", family, 1, true, true)')),
        ("different-adapter-lease", "desktop_socket_windows_network.go", REQUIRED[0],
         "selected physical adapter lease:",
         IDENTITY.replace_once(network,
                               'if adapter.Index != index {',
                               'if false && adapter.Index != index {')),
    )


def execute(source=ROOT, go="go", *, env=None):
    if platform.system() != "Windows":
        raise ValueError("WFP transfer proof requires actual Windows execution")
    if not IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("WFP transfer proof requires an elevated native test host")
    source, target, package, before = IDENTITY.checked_sources(source)
    for name in ("desktop_socket_windows_wfp.go", "desktop_socket_windows_policy.go",
                 "desktop_socket_windows_wfp_test.go", "desktop_socket_windows_wfp_traffic_test.go",
                 "desktop_socket_windows_network.go", "desktop_socket_windows_network_test.go"):
        if name not in before:
            raise ValueError("WFP traffic gate lost its shipping source closure: " + name)
    compiler, captured, architecture = IDENTITY.selected_compiler(
        go, source, dict(os.environ if env is None else env))
    candidates = mutants(target)
    race = ["-race"] if architecture == "amd64" else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    build = [compiler, "test", "-c", "-mod=readonly",
             "-tags=routervpn_windows_wfp,routervpn_windows_wfp_traffic", *race]
    with tempfile.TemporaryDirectory(prefix="routervpn-windows-wfp-traffic-") as directory:
        workspace = Path(directory)
        binary = workspace / "wfp-traffic.test.exe"
        status, output = IDENTITY.run([*build, "-o", binary, package], cwd=source, env=captured)
        if status:
            raise ValueError("WFP traffic compilation failed:\n" + output[-32768:])
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        selection = "^(?:" + "|".join(REQUIRED) + ")$"
        status, output = IDENTITY.run([binary, "-test.run=" + selection, "-test.count=1",
                                       "-test.timeout=180s", "-test.v"], cwd=source, env=captured, timeout=195)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if status or "--- SKIP:" in output or any("--- PASS: " + name + " (" not in output for name in REQUIRED):
            raise ValueError("WFP traffic did not execute every actual native proof")
        for network in ("tcp4", "tcp6", "udp4", "udp6"):
            if "--- PASS: " + REQUIRED[4] + "/" + network + " (" not in output:
                raise ValueError("WFP traffic omitted a required actual address/transport family: " + network)
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("WFP traffic binary changed during execution")
        for label, filename, test, witness, replacement in candidates:
            changed = workspace / (label + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = workspace / (label + ".json")
            overlay.write_text(json.dumps({"Replace": {str(target / filename): str(changed)}}), encoding="utf-8")
            candidate = workspace / (label + ".test.exe")
            status, output = IDENTITY.run([*build, "-overlay=" + str(overlay), "-o", candidate, package],
                                          cwd=source, env=captured)
            if status:
                raise ValueError("WFP traffic negative control did not compile: " + label + "\n" + output[-8192:])
            status, output = IDENTITY.run([candidate, "-test.run=^" + test + "$", "-test.count=1",
                                           "-test.timeout=90s", "-test.v"], cwd=source, env=captured, timeout=105)
            if (status == 0 or "--- FAIL: " + test + " (" not in output or witness not in output or
                    "--- SKIP:" in output or "panic: test timed out" in output or "DATA RACE" in output):
                raise ValueError("WFP traffic negative control missed its exact broken behavior: " + label + "\n" + output[-16384:])
            print("Rejected production WFP traffic mutant:", label, flush=True)
        if IDENTITY.checked_sources(source)[3] != before:
            raise ValueError("WFP traffic source changed during its actual native gate")
    print("Owned Windows WFP traffic passed all four TCP/UDP address families, connected renewal, blocked control with entered I/O and retained source ports, native-process BFE rundown, selected-adapter DHCP capture, and two production negative controls. Native factory and device acceptance remain separately gated.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", nargs="?", type=Path, default=ROOT)
    parser.add_argument("--go", default="go")
    arguments = parser.parse_args()
    execute(arguments.source, arguments.go)
