#!/usr/bin/env python3
"""Prove the original Linux Node control channel against real native owners.

The build user compiles the actual root-package sources. Only that exact
instrumented image enters the guardian runner's private user, PID, mount and
network namespaces. This gate proves the typed preparation/retirement dialogue;
application admission, durable settlement and device acceptance remain separate.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import os
import platform
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("linux_node_control_namespace", ROOT / "deploy/test_desktop_linux_guardian.py")
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
CASES = ("admitted", "refuse-creation", "refuse-admission", "before-baseline", "before-admission",
         "foreign-selection", "foreign-sequence", "foreign-engine", "foreign-network",
         "terminal-payload", "wrong-retirement-ack")
RUNNERS = ("test_linux_node_control.py", "test_linux_node_control_runner.py", "test_desktop_linux_guardian.py",
           "test_desktop_socket_uid.py", "prepare-desktop-external.py")


def checked_sources():
    paths = [ROOT / "go.mod", *(ROOT / "internal").rglob("*.go"),
             *(ROOT / "deploy" / name for name in RUNNERS)]
    if (ROOT / "go.sum").exists():
        paths.append(ROOT / "go.sum")
    records = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Linux Node control lost its actual source: " + str(path.relative_to(ROOT)))
        records[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    required = {
        "internal/linuxprotection/node_control_record.go", "internal/linuxprotection/node_control_record_test.go",
        "internal/linuxprotection/node_control_linux.go", "internal/linuxprotection/node_control_linux_native_test.go",
        "internal/linuxprocess/bootstrap_linux.go", "internal/linuxprocess/channel_linux.go",
        "internal/linuxprocess/process_linux.go", "internal/mobiletor/desktop_socket_linux_node_baseline.go",
        "internal/mobiletor/desktop_socket_linux_source_join.go",
    }
    if not required.issubset(records):
        raise ValueError("Linux Node control source closure omits an original native owner or its test")
    return records


def check_verdict(output):
    if "--- FAIL:" in output or "--- SKIP:" in output:
        raise ValueError("Linux Node control failed or skipped actual native evidence")
    prefix = "--- PASS: TestDesktopLinuxGuardianKernelNodeControl"
    for suffix in ("", *("/" + case for case in CASES)):
        if prefix + suffix + " (" not in output:
            raise ValueError("Linux Node control omitted its required native boundary: " + (suffix or "original group"))


def namespace_test(binary, expected_sha256):
    return GUARD.namespace_test(binary, "NodeControl", expected_sha256)


def execute(go="go", *, env=None):
    if platform.system() != "Linux":
        raise ValueError("Linux Node control requires its matching native Linux host")
    before = checked_sources()
    captured = dict(os.environ if env is None else env, GOWORK="off")
    if captured.get("GOOS", "linux") != "linux":
        raise ValueError("Linux Node control cannot execute a cross-compiled fixture")
    sudo = GUARD.UID.privilege_tool()
    compiler, captured = GUARD.UID.compiler_toolchain(ROOT, go, captured)
    with tempfile.TemporaryDirectory(prefix="routervpn-linux-node-control-") as temporary:
        binary = Path(temporary).resolve() / "node-control.test"
        GUARD.UID.run([compiler, "test", "-c", "-race", "-mod=readonly", "-tags=routervpn_linux_guardian",
                       "-o", binary, "./internal/linuxprotection"], cwd=ROOT, env=captured, timeout=300)
        if checked_sources() != before:
            raise ValueError("Linux Node control source changed during compilation")
        original = binary.lstat()
        if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1 or original.st_mode & 0o022 or original.st_size == 0:
            raise ValueError("Linux Node control compiler did not produce its owned executable")
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        command = [sys.executable, str(Path(__file__).resolve()), "--namespace-test-binary", str(binary),
                   "--namespace-test-sha256", digest]
        if sudo is not None:
            command = [sudo, "-n", "--", *command]
        output = GUARD.UID.run(command, cwd=ROOT, env=captured, timeout=150, sudo=sudo)
        check_verdict(output)
        after = binary.stat()
        if ((after.st_dev, after.st_ino, after.st_size) != (original.st_dev, original.st_ino, original.st_size) or
                hashlib.sha256(binary.read_bytes()).hexdigest() != digest or checked_sources() != before):
            raise ValueError("Linux Node control executable or source changed during native verification")
        print(output, end="" if output.endswith("\n") else "\n")
        print("Linux Node original-channel selection, native receipts, refusal, source join and final ACK/EOF passed; durable settlement remains separate.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--namespace-test-binary", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--namespace-test-sha256", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.namespace_test_binary is not None:
        raise SystemExit(namespace_test(args.namespace_test_binary, args.namespace_test_sha256))
    if args.namespace_test_sha256 is not None:
        parser.error("the compiled digest is only valid with its original namespace executable")
    try:
        execute(args.go)
    except subprocess.CalledProcessError as error:
        if error.output:
            sys.stderr.write(error.output[-32768:].decode("utf-8", errors="replace"))
        raise
