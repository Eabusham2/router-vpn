#!/usr/bin/env python3
"""Exercise the real Swift Load coordinator against the Go controller's isolated HTTP handlers on Linux."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile

from test_ios_startup_policy import member

ROOT = Path(__file__).resolve().parents[1]
MAC = ROOT / "client" / "macos"


def build_swift(directory, binary):
    profiles = (MAC / "RouterVPNConnectionProfiles.swift").read_text()
    product = (MAC / "RouterVPNMacProduct.swift").read_text()
    source = [(MAC / "RouterVPNProfileLoadTransaction.swift").read_text()]
    source.extend(member(profiles, key) for key in (
        "func macCustomPresetName(", "struct MacConnectionCustomPreset:",
        "struct RouterVPNConnectionProfileSelection:", "enum RouterVPNOrderedNodes {",
    ))
    source.extend(member(product, key) for key in (
        "enum RouterVPNNodeEntryModes {", "enum RouterVPNNodeExitModes {",
    ))
    source.extend(("final class Validator {", member(profiles, "    func validConnectionProfileToken("),
                   member(profiles, "    func validatedLoadedConnectionProfileSelection("), "}"))
    source.append((ROOT / "deploy/fixtures/appkit_profile_load_loopback.swift").read_text())
    swift = directory / "AppKitProfileLoad.swift"
    swift.write_text("\n".join(source))
    subprocess.run(["swiftc", "-swift-version", "6", "-parse-as-library", swift, "-o", binary], check=True, timeout=90)


LOOPBACK = "TestReviewProfileLoadSwiftLoopback"


def require_executions(output):
    required = {LOOPBACK, *(LOOPBACK + "/" + fault for fault in ("none", "reject", "after-prepare", "after-commit"))}
    completed = set()
    for line in output.splitlines():
        event = json.loads(line)
        name = event.get("Test")
        if name not in required:
            continue
        if event["Action"] in ("skip", "fail"):
            raise ValueError(f"AppKit/controller scenario did not pass: {name}")
        if event["Action"] == "pass":
            if name in completed:
                raise ValueError(f"AppKit/controller scenario reported a duplicate pass: {name}")
            completed.add(name)
    if missing := required - completed:
        raise ValueError(f"Missing AppKit/controller pass receipts: {sorted(missing)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-swift", type=Path, metavar="BINARY",
                        help="build the client for an independently compiled controller test")
    parser.add_argument("--race", action="store_true", help="use the complete race-enabled controller package warmed by the release job")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("this fixture exercises the Linux loopback controller test")
    with tempfile.TemporaryDirectory(prefix="routervpn-appkit-interop-") as work:
        directory = Path(work)
        binary = args.build_swift.resolve() if args.build_swift else directory / "AppKitProfileLoad"
        build_swift(directory, binary)
        if args.build_swift:
            return
        client = ROOT / "cmd/client"
        command = ["go", "test", "-p=1", "-count=1", "-json", "-run", "^" + LOOPBACK + "$"]
        if args.race:
            command.extend(("-race", "."))
        else:
            # Local runs may compile the platform's shipping source and this single
            # fixture without rebuilding every unrelated native controller test.
            package = json.loads(subprocess.check_output(["go", "list", "-json", "."], cwd=client))
            command.extend(package["GoFiles"] + package.get("CgoFiles", []))
            command.append("connection_profile_load_transaction_review_test.go")
        env = dict(os.environ, ROUTERVPN_PROFILE_LOAD_SWIFT=str(binary))
        result = subprocess.run(command, cwd=client, env=env, capture_output=True, text=True, timeout=900)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        require_executions(result.stdout)
        for line in result.stdout.splitlines():
            event = json.loads(line)
            if event["Action"] == "output" and "AppKit + live Go controller" in event.get("Output", ""):
                print(event["Output"].strip())


if __name__ == "__main__":
    main()
