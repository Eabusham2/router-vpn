#!/usr/bin/env python3
"""Verify typed Linux Router/external native protection succession.

The exact generated native services, kernel baselines and independent guardians
run in the existing disposable namespace. Physical byte-path admission and
joined protection retention are covered; encrypted exits, system TUN, parent
application journal and public connection/restoration remain separate gates.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


NODE = load("linux_external_lifecycle_sources", "test_desktop_node_physical.py")
GUARD = load("linux_external_lifecycle_namespace", "test_desktop_linux_guardian.py")
TAGS = (*NODE.TAGS, "routervpn_linux_external_lifecycle")
CASES = ("shadowsocks-succession", "http-connect-succession", "https-connect-succession",
         "refused-preserves-original", "cancelled-preserves-original", "hysteria2-succession", "wireguard-succession")
MODEL = ("KeepsTypedSourceAndJoinedOwner", "RejectsForeignOrReusedCapabilities",
         "RetainsRefusedAndCancelledSources")
RUNNERS = ("test_linux_external_lifecycle.py", "test_linux_external_lifecycle_runner.py",
           "test_desktop_node_physical.py", "test_desktop_linux_guardian.py", "test_desktop_socket_uid.py",
           "prepare-desktop-external.py", "build-native-runtime.py")


def checked_sources(source):
    source, records = NODE.checked_sources(source)
    required = {
        "routervpn/desktoppt/linux_physical_lifecycle.go",
        "routervpn/desktoppt/node_linux_lifecycle.go", "routervpn/desktoppt/node_linux_source_join.go",
        "routervpn/desktoppt/external_linux_lifecycle.go", "routervpn/desktoppt/external_network.go",
        "routervpn/desktoppt/external_linux_lifecycle_test.go",
        "routervpn/desktoppt/external_linux_lifecycle_native_test.go",
        "routervpn_desktop_external_box_linux_lifecycle.go",
        "routervpn/mobiletor/desktop_socket_linux_node_baseline.go",
        "routervpn/mobiletor/desktop_socket_linux_source_join.go",
    }
    if not required.issubset(records):
        raise ValueError("Linux typed lifecycle omits its original native source: " + ", ".join(sorted(required - records.keys())))
    for name in RUNNERS:
        path = ROOT / "deploy" / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Linux typed lifecycle lost its actual source gate: " + name)
        records["gate/" + name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, records


def require_verdict(output, names):
    if "--- FAIL:" in output or "--- SKIP:" in output or "DATA RACE" in output:
        raise ValueError("Linux typed lifecycle failed or skipped an owned boundary")
    for name in names:
        pattern = r"^[ \t]*--- PASS: " + re.escape(name) + r" \([0-9]+(?:\.[0-9]+)?s\)$"
        if len(re.findall(pattern, output, re.MULTILINE)) != 1:
            raise ValueError("Linux typed lifecycle omitted or duplicated its actual verdict: " + name)


def check_verdict(output):
    parent = "TestDesktopLinuxGuardianKernelExternalLifecycle"
    require_verdict(output, (parent, *(parent + "/" + case for case in CASES)))


def namespace_test(binary, expected_sha256):
    return GUARD.namespace_test(binary, "ExternalLifecycle", expected_sha256)


def execute(source, go="go", *, env=None):
    if platform.system() != "Linux":
        raise ValueError("Linux typed lifecycle requires its matching native Linux host")
    source, before = checked_sources(source)
    captured = dict(os.environ if env is None else env, GOWORK="off")
    if captured.get("GOOS", "linux") != "linux":
        raise ValueError("Linux typed lifecycle cannot execute a cross-compiled fixture")
    sudo = GUARD.UID.privilege_tool()
    compiler, captured = GUARD.UID.compiler_toolchain(source, go, captured)
    with tempfile.TemporaryDirectory(prefix="routervpn-linux-external-lifecycle-") as temporary:
        binary = Path(temporary).resolve() / "external-lifecycle.test"
        GUARD.UID.run([compiler, "test", "-c", "-race", "-mod=readonly", "-tags=" + ",".join(TAGS),
                       "-ldflags=-checklinkname=0", "-o", binary, "./routervpn/desktoppt"],
                      cwd=source, env=captured, timeout=600)
        if checked_sources(source)[1] != before:
            raise ValueError("Linux typed lifecycle source changed during compilation")
        original = binary.lstat()
        if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1 or original.st_mode & 0o022 or original.st_size == 0:
            raise ValueError("Linux typed lifecycle compiler lost its owned executable")
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        model = GUARD.UID.run([binary, "-test.run=^TestRouterVPNExternalLinuxLifecycle", "-test.count=1", "-test.timeout=90s", "-test.v"],
                              cwd=source, env=captured, timeout=100)
        require_verdict(model, tuple("TestRouterVPNExternalLinuxLifecycle" + name for name in MODEL))
        print(model, end="" if model.endswith("\n") else "\n", flush=True)
        command = [sys.executable, str(Path(__file__).resolve()), "--namespace-test-binary", str(binary),
                   "--namespace-test-sha256", digest]
        if sudo is not None:
            command = [sudo, "-n", "--", *command]
        output = GUARD.UID.run(command, cwd=ROOT, env=captured, timeout=150, sudo=sudo)
        check_verdict(output)
        after = binary.stat()
        if ((after.st_dev, after.st_ino, after.st_size) != (original.st_dev, original.st_ino, original.st_size) or
                hashlib.sha256(binary.read_bytes()).hexdigest() != digest or checked_sources(source)[1] != before):
            raise ValueError("Linux typed lifecycle source or executable changed during native verification")
        print(output, end="" if output.endswith("\n") else "\n")
        print("Linux typed Router/external native source, exact baseline succession, byte admission and joined retention passed; app/TUN/proof acceptance remains separate.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--go", default="go")
    parser.add_argument("--namespace-test-binary", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--namespace-test-sha256", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.namespace_test_binary is not None:
        raise SystemExit(namespace_test(args.namespace_test_binary, args.namespace_test_sha256))
    if args.namespace_test_sha256 is not None or args.source is None:
        parser.error("the prepared source is required; a compiled digest belongs only to its original namespace executable")
    try:
        execute(args.source, args.go)
    except subprocess.CalledProcessError as error:
        if error.output:
            sys.stderr.write(error.output[-32768:].decode("utf-8", errors="replace"))
        raise
