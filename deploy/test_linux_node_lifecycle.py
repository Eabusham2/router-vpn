#!/usr/bin/env python3
"""Execute the exact Linux Node factory, nft guardian, TUN and encrypted peer.

Every native case runs inside the existing guardian runner's fresh user,
network, mount and PID namespaces. The retained SS2022 peer has a separate
network namespace. No host account, route, firewall or device node is changed.
This proves the generated native lifecycle; public parent/journal succession
and physical-device acceptance remain separate requirements.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import os
import platform
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NODE = load("linux_node_source", "test_desktop_node_physical.py")
GUARD = load("linux_node_namespace", "test_desktop_linux_guardian.py")
CASES = ("NodeLifecycle", "NodeFailedAdmission", "NodeFailedDNS", "NodeRestoreCaptured")
SUBCASES = {
    "NodeLifecycle": ("on-connect", "always"),
    "NodeFailedAdmission": ("cancel", "callback-error", "changed-baseline"),
    "NodeFailedDNS": ("resolver-failure", "wrong-key"),
    "NodeRestoreCaptured": ("capture", "restore"),
}


def namespace_test(binary, case=None):
    # The outer privileged parent remains alive until namespace_test joins.
    # Capture its actual namespace identity before unshare, without depending
    # on /proc/1 visibility or ptrace permission from a child user namespace.
    current = os.stat("/proc/self/ns/net")
    key = "ROUTERVPN_NODE_OUTER_NETNS_ID"
    previous = os.environ.get(key)
    os.environ[key] = str(current.st_dev) + ":" + str(current.st_ino)
    try:
        return GUARD.namespace_test(binary, case)
    finally:
        if previous is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = previous


def check_verdict(output):
    if "--- FAIL:" in output or "--- SKIP:" in output:
        raise ValueError("Linux Node lifecycle omitted or failed native acceptance")
    for name in CASES:
        if "--- PASS: TestDesktopLinuxGuardianKernel" + name + " (" not in output:
            raise ValueError("Linux Node lifecycle did not execute " + name)
    for name, children in SUBCASES.items():
        for child in children:
            if "--- PASS: TestDesktopLinuxGuardianKernel" + name + "/" + child + " (" not in output:
                raise ValueError("Linux Node lifecycle omitted a required native policy or negative: " + name + "/" + child)


def checked_sources(source):
    source, records = NODE.checked_sources(source)
    required = (
        "routervpn/desktoppt/node_linux_lifecycle.go",
        "routervpn/desktoppt/node_physical_linux.go",
        "routervpn_desktop_node_box_linux_lifecycle.go",
        "protocol/routervpnamnezia/node_linux_peer_test.go",
        "routervpn/mobiletor/desktop_socket_linux_protection.go",
        "routervpn/mobiletor/desktop_socket_linux_nft.go",
    )
    if not all(name in records for name in required):
        raise ValueError("Linux Node lifecycle lost its complete generated native ownership path")
    for relative in ("deploy/test_linux_node_lifecycle.py", "deploy/test_desktop_linux_guardian.py",
                     "deploy/test_linux_guardian_namespace.py", "deploy/test_desktop_socket_uid.py"):
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("Linux Node lifecycle lost its owned namespace runner source")
        records[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, records


def execute(source, go="go", *, env=None):
    if platform.system() != "Linux":
        raise ValueError("Linux Node lifecycle requires its matching native Linux host")
    source, before = checked_sources(source)
    captured = dict(os.environ if env is None else env)
    compiler, captured, _ = NODE.selected_compiler(go, source, captured)
    sudo = GUARD.UID.privilege_tool()
    tags = (*NODE.TAGS, "routervpn_linux_node_composition")
    with tempfile.TemporaryDirectory(prefix="routervpn-linux-node-lifecycle-") as temporary:
        binary = Path(temporary).resolve() / "linux-node-lifecycle.test"
        status, output = NODE.run([compiler, "test", "-c", "-race", "-mod=readonly", "-tags=" + ",".join(tags),
                                   "-ldflags=-checklinkname=0", "-o", binary, "./protocol/routervpnamnezia"],
                                  cwd=source, env=captured, timeout=300)
        if status:
            raise ValueError("Linux Node lifecycle native compile failed:\n" + output[-16384:])
        if checked_sources(source)[1] != before:
            raise ValueError("Linux Node lifecycle source changed during its native compile")
        identity = binary.lstat()
        if not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1 or identity.st_mode & 0o022 or identity.st_size == 0:
            raise ValueError("Linux Node lifecycle compiler did not return its owned executable")
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        command = [sys.executable, str(Path(__file__).resolve()), "--namespace-test-binary", str(binary)]
        if sudo is not None:
            command = [sudo, "-n", "--", *command]
        output = GUARD.UID.run(command, cwd=source, env=captured, timeout=150, sudo=sudo)
        check_verdict(output)
        after = binary.stat()
        if (after.st_dev, after.st_ino, after.st_size) != (identity.st_dev, identity.st_ino, identity.st_size) or hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Linux Node lifecycle executable changed during its native run")
        if checked_sources(source)[1] != before:
            raise ValueError("Linux Node lifecycle source changed during its native run")
        print(output, end="" if output.endswith("\n") else "\n")
        print("Linux Node captured admission, actual nft/TUN/SS2022/DNS and joined retirement passed; parent journal and device acceptance are separate.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--go", default="go")
    parser.add_argument("--namespace-test-binary", type=Path)
    parser.add_argument("--kernel-case", choices=CASES)
    args = parser.parse_args()
    if args.namespace_test_binary:
        raise SystemExit(namespace_test(args.namespace_test_binary, args.kernel_case))
    if args.source is None or args.kernel_case is not None:
        parser.error("an exact prepared source is required; kernel-case is only for the owned namespace invocation")
    execute(args.source, args.go)
