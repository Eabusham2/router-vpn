#!/usr/bin/env python3
"""Execute the generated Linux Node child with original native parent owners.

The exact prepared command, Box and service create/join real guardians behind
the original Bootstrap. TUN creation, selected DNS/Router proofs, durable app
settlement and device acceptance remain separate gates.
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


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


NODE = load("linux_child_control_sources", "test_desktop_node_physical.py")
GUARD = load("linux_child_control_namespace", "test_desktop_linux_guardian.py")
TAGS = (*NODE.TAGS, "routervpn_linux_node_control")
CASES = ("captured-prepare", "cancelled-after-admission", "prepared-before-start", "baseline-refused",
         "admission-refused", "before-prepare", "changed-config", "changed-selection", "bootstrap-refused", "foreign-image")
RUNNERS = ("test_linux_node_child_control.py", "test_linux_node_child_control_runner.py",
           "test_desktop_node_physical.py", "test_desktop_linux_guardian.py", "test_desktop_socket_uid.py",
           "prepare-desktop-external.py", "build-native-runtime.py")


def checked_sources(source):
    source, records = NODE.checked_sources(source)
    required = {
        "cmd/sing-box/routervpn_mtu_node.go", "cmd/sing-box/routervpn_node_command_control.go",
        "cmd/sing-box/routervpn_node_command_control_linux.go", "cmd/sing-box/routervpn_node_command_control_other.go",
        "cmd/sing-box/routervpn_node_command_run_linux.go", "cmd/sing-box/routervpn_node_command_control_linux_native_test.go",
        "cmd/sing-box/routervpn_node_command_ready.go", "routervpn_desktop_node_box_linux_lifecycle.go",
        "routervpn/desktoppt/node_linux_lifecycle.go", "routervpn/desktoppt/node_linux_source_join.go",
        "routervpn/linuxprocess/bootstrap_linux.go", "routervpn/linuxprocess/channel_linux.go",
        "routervpn/linuxprotection/node_control_linux.go", "routervpn/mobiletor/desktop_socket_linux_node_baseline.go",
    }
    if not required.issubset(records):
        raise ValueError("Generated Linux child omits its actual command, native source or original parent control")
    for name in RUNNERS:
        path = ROOT / "deploy" / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Generated Linux child lost its actual source gate: " + name)
        records["gate/" + name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, records


def check_verdict(output):
    if "--- FAIL:" in output or "--- SKIP:" in output:
        raise ValueError("Generated Linux child failed or skipped an actual native boundary")
    prefix = "--- PASS: TestDesktopLinuxGuardianKernelNodeChildControl"
    for suffix in ("", *("/" + case for case in CASES)):
        if prefix + suffix + " (" not in output:
            raise ValueError("Generated Linux child omitted its native boundary: " + (suffix or "original group"))


def namespace_test(binary, expected_sha256):
    return GUARD.namespace_test(binary, "NodeChildControl", expected_sha256)


def execute(source, go="go", *, env=None):
    if platform.system() != "Linux":
        raise ValueError("Generated Linux child requires its matching native Linux host")
    source, before = checked_sources(source)
    captured = dict(os.environ if env is None else env, GOWORK="off")
    if captured.get("GOOS", "linux") != "linux":
        raise ValueError("Generated Linux child cannot execute a cross-compiled fixture")
    sudo = GUARD.UID.privilege_tool()
    compiler, captured = GUARD.UID.compiler_toolchain(source, go, captured)
    with tempfile.TemporaryDirectory(prefix="routervpn-linux-node-child-") as temporary:
        binary = Path(temporary).resolve() / "node-child-control.test"
        GUARD.UID.run([compiler, "test", "-c", "-race", "-mod=readonly", "-tags=" + ",".join(TAGS),
                       "-ldflags=-checklinkname=0", "-o", binary, "./cmd/sing-box"],
                      cwd=source, env=captured, timeout=600)
        if checked_sources(source)[1] != before:
            raise ValueError("Generated Linux child source changed during compilation")
        original = binary.lstat()
        if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1 or original.st_mode & 0o022 or original.st_size == 0:
            raise ValueError("Generated Linux child compiler lost its owned executable")
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        command = [sys.executable, str(Path(__file__).resolve()), "--namespace-test-binary", str(binary),
                   "--namespace-test-sha256", digest]
        if sudo is not None:
            command = [sudo, "-n", "--", *command]
        output = GUARD.UID.run(command, cwd=ROOT, env=captured, timeout=150, sudo=sudo)
        check_verdict(output)
        after = binary.stat()
        if ((after.st_dev, after.st_ino, after.st_size) != (original.st_dev, original.st_ino, original.st_size) or
                hashlib.sha256(binary.read_bytes()).hexdigest() != digest or checked_sources(source)[1] != before):
            raise ValueError("Generated Linux child source or executable changed during native verification")
        print(output, end="" if output.endswith("\n") else "\n")
        print("Generated Linux Node original parent, actual Box/source join, refused admission and final ACK/EOF passed; TUN/DNS readiness remains separate.")


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
