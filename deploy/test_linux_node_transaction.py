#!/usr/bin/env python3
"""Prove Linux Node durable transactions against actual original native owners.

The actual installed controller launches a pinned engine image, authenticates
its inherited originals, and joins real guardians and engine processes in
private namespaces. Selected DNS, TUN traffic and device acceptance are separate.
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
SPEC = importlib.util.spec_from_file_location("linux_node_transaction_namespace", ROOT / "deploy/test_desktop_linux_guardian.py")
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
CASES = ("on-connect", "request-ended", "always-successor", "cancelled-before-prepare",
         "changed-profile", "partial-prepare-write", "engine-join")
SHUTDOWN_CASES = ("shutdown-on-connect", "shutdown-request-ended", "shutdown-before-prepare", "shutdown-before-admission",
                  "shutdown-retry", "shutdown-successor-first", "shutdown-replacement", "shutdown-always")
HOST_CASES = ("complete", "restored-mtu", "wrong-package", "request-replaced", "profile-replaced", "options-replaced",
              "network-replaced", "source-replaced", "workspace-replaced", "cancelled-retirement", "entered-command")
HOST_START_CASES = ("admitted", "active-connection", "retained-workspace", "cancelled-before-start", "source-replaced",
                    "foreign-journal", "request-during-launch", "replacement-during-launch", "request-ended",
                    "replacement-after-start", "shutdown", "always-successor")
PROOF_SOCKET_CASES = ("tcp4", "tcp6", "udp-rejected", "wrong-family", "wrong-index", "wrong-name", "wrong-mtu", "cancelled", "closed-original")
GROUPS = {"NodeTransaction": CASES, "NodeShutdown": SHUTDOWN_CASES, "NodeHost": HOST_CASES,
          "NodeHostStart": HOST_START_CASES, "NodeProofSocket": PROOF_SOCKET_CASES}
UNIT_CASES = {
    "TestDesktopLinuxNodeActivationProof": ("absent", "historical-clock", "historical-start", "historical-now", "stale", "future", "before-start",
                                            "zero-elapsed", "negative-elapsed", "unbounded-elapsed", "impossible-elapsed", "unbounded-deadline",
                                            "changed-ready", "changed-live", "active-mtu", "failed-reader"),
    "TestDesktopLinuxNodeActivationRetainsCapturedLifetime": (),
    "TestDesktopLinuxNodeActivationRejectsChangedCapture": ("host", "parent", "operation", "process", "transaction", "policy", "launch", "selection",
                                                            "network", "profile", "options", "ready", "proof", "activation-time", "transaction-profile",
                                                            "transaction-network", "transaction-parent", "command", "unstarted", "retiring", "joined", "controller-ended"),
    "TestDesktopLinuxNodeConnectedCannotCreateActivation": (),
    "TestConnectionCancellationIntentPrecedesCallback": (),
    "TestConnectionCancellationIntentClearsWithOriginalFinish": (),
    "TestConnectionOperationCancellationBlocksAdoption": (),
    "TestOperationGuardSerializesConnectionAndMutationTransactions": (),
}
RUNNERS = ("test_linux_node_transaction.py", "test_linux_node_transaction_runner.py", "test_desktop_linux_guardian.py",
           "test_desktop_socket_uid.py", "prepare-desktop-external.py")


def checked_sources():
    paths = [ROOT / "go.mod", *(ROOT / "internal").rglob("*.go"), *(ROOT / "cmd/client").glob("*.go"),
             *(ROOT / "deploy" / name for name in RUNNERS)]
    if (ROOT / "go.sum").exists():
        paths.append(ROOT / "go.sum")
    records = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Linux Node transaction lost its actual source: " + str(path.relative_to(ROOT)))
        records[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    required = {
        "cmd/client/desktop_node_linux_transaction.go", "cmd/client/desktop_node_linux_transaction_retire.go",
        "cmd/client/desktop_node_linux_transaction_native_test.go", "cmd/client/desktop_node_linux_parent_native_test.go",
        "cmd/client/desktop_node_linux_journal.go", "cmd/client/desktop_node_process_linux.go",
        "cmd/client/controller_shutdown.go", "cmd/client/desktop_node_shutdown_linux.go",
        "cmd/client/desktop_node_linux_retirement.go", "cmd/client/desktop_node_linux_shutdown_native_test.go",
        "cmd/client/desktop_node_host_linux.go", "cmd/client/desktop_node_host_linux_native_test.go",
        "cmd/client/desktop_node_host_linux_start.go", "cmd/client/desktop_node_host_linux_start_native_test.go",
        "cmd/client/desktop_node_host_linux_ready.go", "cmd/client/desktop_node_host_linux_proof.go",
        "cmd/client/desktop_node_host_linux_proof_test.go", "cmd/client/desktop_node_host_linux_proof_native_test.go",
        "cmd/client/desktop_node_host_linux_active.go", "cmd/client/desktop_node_host_linux_active_test.go",
        "cmd/client/operation_guard.go", "cmd/client/operation_guard_cancellation_intent_test.go", "cmd/client/main.go",
        "internal/linuxprotection/node_control_linux.go", "internal/linuxprocess/bootstrap_linux.go",
        "internal/mobiletor/desktop_socket_linux_node_baseline.go", "internal/mobiletor/desktop_socket_linux_node_absence.go",
        "internal/mobiletor/desktop_socket_linux_node_succession_retired.go",
    }
    if not required.issubset(records):
        raise ValueError("Linux Node transaction source closure omits an original native owner or its test")
    return records


def check_unit_verdict(output):
    if "--- FAIL:" in output or "--- SKIP:" in output:
        raise ValueError("Linux Node activation failed or skipped its captured proof/cancellation checks")
    passed = re.findall(r"(?m)^\s*--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)$", output)
    for group, leaves in UNIT_CASES.items():
        for name in (group, *(group + "/" + leaf for leaf in leaves)):
            if passed.count(name) != 1:
                raise ValueError("Linux Node activation omitted or duplicated its required boundary: " + name)


def check_verdict(output, group="NodeTransaction"):
    if group not in GROUPS:
        raise ValueError("Linux Node transaction has no such captured test group")
    if "--- FAIL:" in output or "--- SKIP:" in output:
        raise ValueError("Linux Node transaction failed or skipped actual native evidence")
    prefix = "--- PASS: TestDesktopLinuxGuardianKernel" + group
    for suffix in ("", *("/" + case for case in GROUPS[group])):
        if prefix + suffix + " (" not in output:
            raise ValueError("Linux Node transaction omitted its required native boundary: " + (suffix or "original group"))


def namespace_test(binary, expected_sha256, group="NodeTransaction"):
    if group not in GROUPS:
        raise ValueError("Linux Node transaction requires its exact native group")
    return GUARD.namespace_test(binary, group, expected_sha256)


def execute(go="go", *, env=None):
    if platform.system() != "Linux":
        raise ValueError("Linux Node transaction requires its matching native Linux host")
    before = checked_sources()
    captured = dict(os.environ if env is None else env, GOWORK="off")
    if captured.get("GOOS", "linux") != "linux":
        raise ValueError("Linux Node transaction cannot execute a cross-compiled fixture")
    sudo = GUARD.UID.privilege_tool()
    compiler, captured = GUARD.UID.compiler_toolchain(ROOT, go, captured)
    output = GUARD.UID.run([compiler, "test", "-race", "-mod=readonly", "-count=1", "-timeout=45s", "-v",
                           "-run=^(" + "|".join(UNIT_CASES) + ")$", "./cmd/client"],
                          cwd=ROOT, env=captured, timeout=300)
    check_unit_verdict(output)
    if checked_sources() != before:
        raise ValueError("Linux Node activation source changed during its captured proof/cancellation checks")
    print(output, end="" if output.endswith("\n") else "\n")
    with tempfile.TemporaryDirectory(prefix="routervpn-linux-node-transaction-") as temporary:
        binary = Path(temporary).resolve() / "node-transaction.test"
        GUARD.UID.run([compiler, "test", "-c", "-race", "-mod=readonly", "-tags=routervpn_controller_privileged",
                       "-o", binary, "./cmd/client"], cwd=ROOT, env=captured, timeout=300)
        if checked_sources() != before:
            raise ValueError("Linux Node transaction source changed during compilation")
        original = binary.lstat()
        if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1 or original.st_mode & 0o022 or original.st_size == 0:
            raise ValueError("Linux Node transaction compiler did not produce its owned executable")
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        # Always intentionally survives controller exit. Give each complete
        # group its own actual network namespace; never delete that table by
        # name to pretend a new controller acquired its original capability.
        for group in GROUPS:
            command = [sys.executable, str(Path(__file__).resolve()), "--namespace-test-binary", str(binary),
                       "--namespace-test-sha256", digest, "--namespace-test-group", group]
            if sudo is not None:
                command = [sudo, "-n", "--", *command]
            output = GUARD.UID.run(command, cwd=ROOT, env=captured, timeout=150, sudo=sudo)
            check_verdict(output, group)
            after = binary.stat()
            if ((after.st_dev, after.st_ino, after.st_size) != (original.st_dev, original.st_ino, original.st_size) or
                    hashlib.sha256(binary.read_bytes()).hexdigest() != digest or checked_sources() != before):
                raise ValueError("Linux Node transaction executable or source changed during native verification")
            print(output, end="" if output.endswith("\n") else "\n")
        print("Linux Node durable transactions and actual controller shutdown passed; restart recovery and device traffic remain separate.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--namespace-test-binary", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--namespace-test-sha256", help=argparse.SUPPRESS)
    parser.add_argument("--namespace-test-group", choices=tuple(GROUPS), default="NodeTransaction", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.namespace_test_binary is not None:
        raise SystemExit(namespace_test(args.namespace_test_binary, args.namespace_test_sha256, args.namespace_test_group))
    if args.namespace_test_sha256 is not None or args.namespace_test_group != "NodeTransaction":
        parser.error("the compiled digest is only valid with its original namespace executable")
    try:
        execute(args.go)
    except subprocess.CalledProcessError as error:
        if error.output:
            sys.stderr.write(error.output[-32768:].decode("utf-8", errors="replace"))
        raise
