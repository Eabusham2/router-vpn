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
import os
import platform
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "windows_external_physical_bootstrap", ROOT / "deploy/test_windows_physical_bootstrap.py")
BOOT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BOOT)
IDENTITY = BOOT.IDENTITY


def execute(source, go="go", *, prospective=False, env=None, bootstrap_only=False):
    if prospective or platform.system() != "Windows":
        raise ValueError("Ordinary Windows composition requires its unmodified native host")
    source, before = BOOT.sources(source)
    compiler, captured, architecture = IDENTITY.selected_compiler(
        go, source, dict(os.environ if env is None else env))
    race = ["-race"] if architecture == "amd64" and not bootstrap_only else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    suites = (
        ("command", "./cmd/sing-box", "^TestRouterVPNDesktopExternalPhysicalCommand",
         ("RequiresExactDerivedInputs", "SeparatesProofAndMailboxIdentity", "RejectsRelabeledNetworkProof", "UsesActualPreparedNativeFactory")),
        ("box", ".", "^TestRouterVPNDesktopExternalPhysical",
         ("BoxRejectsChangedDerivedGraph", "BoxRequiresPreparedStartedOwner", "BoxRetainsExactPolicyAndDerivedIdentity",
          "BoxRejectsTUNReadbackAndBinding", "BoxCancelAndNetworkResetRetireExactOwner", "BoxMTUReadbackKeepsGuardAndDerivedPolicy", "Integration")),
        ("factory", "./routervpn/desktoppt", "^TestRouterVPNExternalPhysicalWindows",
         ("CapturesPolicyAndRetainsLateOwner",)),
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
            if status or any("--- PASS: " + selection[1:] + suffix + " (" not in output for suffix in required) or \
                    "--- SKIP:" in output or "DATA RACE" in output:
                raise ValueError("Ordinary Windows " + name + " did not prove its native composition")
            if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
                raise ValueError("Ordinary Windows composition binary changed during execution")
    if BOOT.sources(source)[1] != before:
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
