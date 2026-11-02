#!/usr/bin/env python3
"""Execute the retained OpenVPN endpoint against its real isolated provider.

The exact shipping Box, captured lower broker, OpenVPN TLS/data transport,
selected DNS, public proof and remote-generation ownership execute in the
existing disconnected guardian namespace. OS admission and TUN construction
remain explicit fixture boundaries; actual guardian succession and installed
application/device acceptance are separate required gates.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shlex
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


NODE = load("linux_external_openvpn_sources", "test_desktop_node_physical.py")
GUARD = load("linux_external_openvpn_namespace", "test_desktop_linux_guardian.py")
BUILD = load("linux_external_openvpn_build", "build-native-runtime.py")
PARENT = "TestDesktopLinuxGuardianKernelExternalOpenVPN"
CASES = ("tcp-proof-mtu-latency50", "udp-proof-mtu-latency50", "tcp-fallback", "mixed-fallback",
         "tcp-reconnect-rejects-old-proof", "udp-reconnect-rejects-old-proof", "reconnect-during-public-proof",
         "cancelled-proof", "wrong-provider-trust", "wrong-control-key", "selected-dns-failure", "captured-tuple-set")
RUNNERS = ("test_linux_external_openvpn.py", "test_linux_external_openvpn_runner.py",
           "test_desktop_node_physical.py", "test_desktop_linux_guardian.py", "test_desktop_socket_uid.py",
           "prepare-desktop-external.py", "build-native-runtime.py", "build-desktop-pq.py")
REQUIRED = frozenset({
    "routervpn_desktop_external_box_openvpn_test.go",
    "routervpn_desktop_external_box_integration_test.go", "routervpn_desktop_external_box_physical.go",
    "routervpn/desktoppt/external_network.go", "routervpn/desktoppt/external_physical.go",
    "routervpn/desktoppt/external_linux_lifecycle.go",
    "experimental/libbox/routervpn/mobilemultihop/desktop_external_policy.go",
    "experimental/libbox/routervpn/mobilemultihop/external_openvpn_remote.go",
    "experimental/libbox/routervpn/nativeopenvpn/remote.go",
})


def checked_sources(source):
    source, records = NODE.checked_sources(source)
    if not REQUIRED.issubset(records):
        raise ValueError("Linux OpenVPN omits its original native source: " + ", ".join(sorted(REQUIRED - records.keys())))
    for name in RUNNERS:
        path = ROOT / "deploy" / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Linux OpenVPN lost its actual source gate: " + name)
        records["gate/" + name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, records


def check_verdict(output):
    if not isinstance(output, str) or "--- FAIL:" in output or "--- SKIP:" in output or "DATA RACE" in output:
        raise ValueError("Linux OpenVPN failed or skipped an owned boundary")
    expected = {PARENT, *(PARENT + "/" + case for case in CASES)}
    pattern = r"^[ \t]*--- PASS: (" + re.escape(PARENT) + r"(?:/[^\s]+)?) \([0-9]+(?:\.[0-9]+)?s\)\r?\n"
    actual = re.findall(pattern, output, re.MULTILINE)
    if len(actual) != len(expected) or set(actual) != expected:
        raise ValueError("Linux OpenVPN omitted, duplicated or substituted an actual verdict")


def namespace_test(binary, expected_sha256):
    return GUARD.namespace_test(binary, "ExternalOpenVPN", expected_sha256)


def binary_identity(binary):
    observed = binary.lstat()
    if (not stat.S_ISREG(observed.st_mode) or not observed.st_mode & stat.S_IXUSR or
            observed.st_nlink != 1 or observed.st_mode & 0o022 or
            observed.st_uid != os.geteuid() or observed.st_size == 0):
        raise ValueError("Linux OpenVPN compiler lost its owned executable")
    return (observed.st_dev, observed.st_ino, observed.st_uid, observed.st_mode, observed.st_size,
            hashlib.sha256(binary.read_bytes()).hexdigest())


def execute(source, pq, go="go", *, env=None):
    if platform.system() != "Linux":
        raise ValueError("Linux OpenVPN requires its matching native Linux host")
    source, before = checked_sources(source)
    captured = dict(os.environ if env is None else env, GOWORK="off")
    if captured.get("GOOS", "linux") != "linux":
        raise ValueError("Linux OpenVPN cannot execute a cross-compiled fixture")
    sudo = GUARD.UID.privilege_tool()
    compiler, captured = GUARD.UID.compiler_toolchain(source, go, captured)
    identity = json.loads(GUARD.UID.run([compiler, "env", "-json", "GOOS", "GOARCH", "GOHOSTOS", "GOHOSTARCH", "CGO_ENABLED"],
                                      cwd=source, env=captured, timeout=30))
    if (not isinstance(identity, dict) or identity.get("GOOS") != "linux" or identity.get("GOHOSTOS") != "linux" or
            identity.get("GOARCH") not in ("amd64", "arm64") or identity.get("GOARCH") != identity.get("GOHOSTARCH") or
            identity.get("CGO_ENABLED") != "1"):
        raise ValueError("Linux OpenVPN requires its original native architecture and CGO toolchain")
    target = "linux/" + identity["GOARCH"]
    pq = Path(pq).absolute()
    receipt = BUILD.PQ.verify(pq, target)
    captured["CGO_LDFLAGS"] = shlex.join(["-L" + str(pq), *receipt["native_static_libs"]])
    with tempfile.TemporaryDirectory(prefix="routervpn-linux-external-openvpn-") as temporary:
        binary = Path(temporary).resolve() / "external-openvpn.test"
        GUARD.UID.run([compiler, "test", "-c", "-race", "-mod=readonly", "-tags=" + ",".join(BUILD.tags(target)),
                       "-ldflags=-checklinkname=0", "-o", binary, "."],
                      cwd=source, env=captured, timeout=600)
        if checked_sources(source)[1] != before or BUILD.PQ.verify(pq, target) != receipt:
            raise ValueError("Linux OpenVPN source or native link inputs changed during compilation")
        original = binary_identity(binary)
        command = [sys.executable, str(Path(__file__).resolve()), "--namespace-test-binary", str(binary),
                   "--namespace-test-sha256", original[-1]]
        if sudo is not None:
            command = [sudo, "-n", "--", *command]
        output = GUARD.UID.run(command, cwd=ROOT, env=captured, timeout=150, sudo=sudo)
        check_verdict(output)
        if (binary_identity(binary) != original or checked_sources(source)[1] != before or
                BUILD.PQ.verify(pq, target) != receipt):
            raise ValueError("Linux OpenVPN source, executable or native link inputs changed during verification")
        print(output, end="" if output.endswith("\n") else "\n")
        print("Linux OpenVPN native encrypted TCP/UDP, ordered remotes, DNS/public proof, measurements and generation ownership passed; OS-admission/TUN and installed-device acceptance remain separate.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--pq", type=Path)
    parser.add_argument("--go", default="go")
    parser.add_argument("--namespace-test-binary", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--namespace-test-sha256", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.namespace_test_binary is not None:
        if args.source is not None or args.pq is not None or args.namespace_test_sha256 is None:
            parser.error("a namespace child requires only its original compiled executable and digest")
        raise SystemExit(namespace_test(args.namespace_test_binary, args.namespace_test_sha256))
    if args.namespace_test_sha256 is not None or args.source is None or args.pq is None:
        parser.error("the prepared source and verified PQ directory are required")
    try:
        execute(args.source, args.pq, args.go)
    except subprocess.CalledProcessError as error:
        if error.output:
            sys.stderr.write(error.output[-32768:].decode("utf-8", errors="replace"))
        raise


if __name__ == "__main__":
    main()
