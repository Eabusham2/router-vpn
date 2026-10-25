#!/usr/bin/env python3
"""Exercise the shipped routervpn-node command and its real isolated Linux TUN."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
INTERFACE = "rvpn-node-test"
UPLINK = "rvpn-uplink"
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CONFIG = {
    "log": {"disabled": True},
    "inbounds": [{"type": "tun", "tag": "captured-tun", "interface_name": INTERFACE,
                  "address": ["172.29.199.1/30"], "mtu": 1420, "auto_route": False,
                  "dns_mode": "disabled", "stack": "system"}],
    "outbounds": [{"type": "direct", "tag": "retained-direct"}],
    "route": {"auto_detect_interface": True, "final": "retained-direct"},
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_json(directory, name, value):
    temporary = directory / ("." + name + ".fixture")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, separators=(",", ":"), sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, directory / name)


def private_json(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= 4096 and info.st_mode & 0o077 == 0,
            "Native receipt is not a bounded private regular file")
    return json.loads(path.read_bytes())


def validate_record(record, session, digest):
    require(type(record.get("schema")) is int and record["schema"] == 1 and record.get("session_id") == session
            and record.get("config_sha256") == digest, "Native MTU receipt belongs to a different owner")
    require(isinstance(record.get("path_id"), str) and HEX64.fullmatch(record["path_id"]),
            "Native MTU receipt has no captured physical path")
    require(record.get("interface") == INTERFACE, "Native MTU receipt names an unowned interface")
    for field in ("reader", "index", "mtu", "heartbeat_at"):
        require(type(record.get(field)) is int and record[field] > 0, "Native MTU receipt has invalid " + field)
    require(type(record.get("generation")) is int and record["generation"] >= 0
            and 1280 <= record["mtu"] <= 9000, "Native MTU generation/readback is invalid")
    require(type(record.get("active")) is bool and type(record.get("restored")) is bool,
            "Native MTU receipt has no explicit transaction state")
    require(type(record.get("expired", False)) is bool and not (record.get("expired") and record["active"]),
            "Native MTU receipt has invalid expiry state")
    require(not any(field in record for field in ("revert_token", "commit_request", "commit_generation")),
            "Native MTU receipt exposed private commit-revert authority")
    for field in ("request_id", "lease_id"):
        value = record.get(field)
        require(isinstance(value, str) and (value == "" or HEX32.fullmatch(value)),
                "Native MTU receipt has invalid " + field)
    return record


def validate_stopped(record, session, digest, interface_present):
    require(record == {"schema": 1, "session_id": session, "source_sha256": digest, "closed": True},
            "Native stopped acknowledgement does not match its captured owner")
    require(type(record["schema"]) is int and type(record["closed"]) is bool and not interface_present,
            "Native stopped acknowledgement preceded kernel TUN cleanup")


def validate_command(result, before, request, reject):
    failure = result.get("failure", "")
    require(isinstance(failure, str) and bool(failure) == reject,
            "Native MTU command success/rejection was not explicit")
    require(result["generation"] == request["generation"] and result["request_id"] == request["request_id"],
            "Native command acknowledgement belongs to another request")
    require(result["path_id"] == before["path_id"], "Native command adopted another physical path")
    if reject:
        for field in ("reader", "index", "mtu", "active", "restored", "lease_id", "interface"):
            require(result[field] == before[field], "Rejected native command changed " + field)
        require(result.get("expired", False) == before.get("expired", False),
                "Rejected native command changed expiry state")


def ip(*arguments, optional=False):
    result = subprocess.run(["ip", "-json", *arguments], capture_output=True, text=True, timeout=10)
    if optional and result.returncode != 0:
        return []
    require(result.returncode == 0, "Isolated kernel interface operation failed: " + result.stderr.strip())
    return json.loads(result.stdout or "[]")


def link(name):
    rows = ip("link", "show", "dev", name, optional=True)
    return rows[0] if rows else None


def isolated_namespace(parent):
    require(sys.platform.startswith("linux") and os.geteuid() == 0, "Kernel fixture requires isolated Linux root")
    current = os.readlink("/proc/self/ns/net")
    require(re.fullmatch(r"net:\[\d+\]", parent) and current != parent,
            "Kernel fixture must enter a new network namespace")
    require([row["ifname"] for row in ip("link", "show")] == ["lo"],
            "Kernel fixture refuses a namespace containing existing network devices")
    require(Path("/dev/net/tun").is_char_device(), "Required kernel TUN device is unavailable")
    ip("link", "set", "lo", "up")
    # This dummy uplink exists only in the fresh namespace. It gives the real
    # native network monitor a stable physical identity without external access.
    ip("link", "add", UPLINK, "type", "dummy")
    ip("address", "add", "192.0.2.1/24", "dev", UPLINK)
    ip("link", "set", UPLINK, "up")
    ip("route", "add", "default", "dev", UPLINK)
    return current


class Node:
    def __init__(self, binary, directory, pre_stopped=False):
        self.directory = directory
        self.session = uuid.uuid4().hex
        raw = json.dumps(CONFIG, separators=(",", ":"), sort_keys=True).encode()
        self.digest = hashlib.sha256(raw).hexdigest()
        path = directory / "sing-box.json"
        path.write_bytes(raw)
        path.chmod(0o600)
        self.stop_record = {"schema": 1, "session_id": self.session, "source_sha256": self.digest}
        if pre_stopped:
            atomic_json(directory, "stop.json", self.stop_record)
        self.output = open(directory / "owned-command.log", "w+b")
        os.chmod(directory / "owned-command.log", 0o600)
        self.process = subprocess.Popen([str(binary), "routervpn-node", "--runtime-dir", str(directory),
                                         "--session", self.session, "--config-sha256", self.digest],
                                        stdout=self.output, stderr=subprocess.STDOUT)

    def wait(self, predicate, message, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            if self.process.poll() is not None:
                self.output.flush()
                self.output.seek(0)
                detail = self.output.read(4096).decode("utf-8", errors="replace")
                raise AssertionError(message + "; native command exited: " + detail)
            time.sleep(0.01)
        raise AssertionError(message)

    def record(self):
        try:
            return validate_record(private_json(self.directory / "node-mtu-status.json"), self.session, self.digest)
        except FileNotFoundError:
            return None

    def readback(self, record, mtu):
        actual = link(INTERFACE)
        require(actual is not None and actual["ifindex"] == record["index"]
                and actual["mtu"] == record["mtu"] == mtu, "Native receipt differs from the actual kernel interface")

    def request(self, record, action, value=0, **changes):
        request = {"schema": 1, "session_id": self.session, "config_sha256": self.digest,
                   "path_id": record["path_id"], "generation": record["generation"] + 1,
                   "request_id": uuid.uuid4().hex, "lease_id": record["lease_id"] or uuid.uuid4().hex,
                   "action": action, "reader": record["reader"], "expected_mtu": record["mtu"]}
        if value:
            request["value"] = value
        request.update(changes)
        return request

    def command(self, record, action, value=0, reject=False, **changes):
        request = self.request(record, action, value, **changes)
        require(not (self.directory / "node-mtu-request.json").exists(), "Previous owned request was not consumed")
        atomic_json(self.directory, "node-mtu-request.json", request)

        def acknowledged():
            result = self.record()
            if (result and result["generation"] == request["generation"]
                    and result["request_id"] == request["request_id"]
                    and not (self.directory / "node-mtu-request.json").exists()):
                return result
            return None

        result = self.wait(acknowledged, "Native MTU command was not acknowledged: " + action)
        validate_command(result, record, request, reject)
        return result

    def ignored(self, record, filename, request):
        atomic_json(self.directory, filename, request)
        owned = (self.directory / filename).stat()
        result = self.wait(lambda: (current if (current := self.record())
                                   and current["heartbeat_at"] >= record["heartbeat_at"] + 500 else None),
                           "Native owner stopped publishing while rejecting a foreign request")
        require(result["generation"] == record["generation"] and result["reader"] == record["reader"]
                and result["active"] == record["active"] and result["mtu"] == record["mtu"],
                "Foreign request mutated the current owner")
        require(not (self.directory / "stopped.json").exists(), "Foreign stop retired the current owner")
        current = (self.directory / filename).stat()
        require(os.path.samestat(owned, current), "Native command removed or replaced a foreign request")
        (self.directory / filename).unlink()
        return result

    def stop(self, kernel=True):
        atomic_json(self.directory, "stop.json", self.stop_record)
        path = self.directory / "stopped.json"
        self.wait(lambda: path.exists(), "Native stopped acknowledgement never arrived")
        validate_stopped(private_json(path), self.session, self.digest, link(INTERFACE) is not None if kernel else False)
        require(self.process.wait(timeout=10) == 0, "Native command failed after checked cleanup")

    def close(self):
        try:
            if self.process.poll() is None:
                atomic_json(self.directory, "stop.json", self.stop_record)
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=5)
        finally:
            self.output.close()


def prestart(binary):
    with tempfile.TemporaryDirectory(prefix="routervpn-node-prestart-") as temporary:
        directory = Path(temporary)
        node = Node(binary, directory, pre_stopped=True)
        try:
            require(node.process.wait(timeout=10) == 0, "Captured stop-before-start did not exit successfully")
            validate_stopped(private_json(directory / "stopped.json"), node.session, node.digest, False)
            require(not (directory / "node-mtu-status.json").exists(), "Canceled startup published a live MTU owner")
            return {"prestart_stop": "passed", "kernel_executed": False, "binary_sha256": sha(binary)}
        finally:
            node.close()


def kernel(binary, parent):
    namespace = isolated_namespace(parent)
    physical = link(UPLINK)
    checks = []
    prestart(binary)
    require(link(INTERFACE) is None, "Pre-canceled startup left a native TUN")
    checks.append("captured stop before startup")
    with tempfile.TemporaryDirectory(prefix="routervpn-node-kernel-") as temporary:
        node = Node(binary, Path(temporary))
        try:
            initial = node.wait(node.record, "Real native TUN owner never published its readback")
            require(initial["generation"] == 0 and initial["reader"] == 1
                    and not initial["active"] and not initial["restored"], "Initial native owner state was not idle")
            node.readback(initial, 1420)
            checks.append("real initial kernel readback")
            current = initial
            for field, wrong in (("session_id", uuid.uuid4().hex), ("config_sha256", "f" * 64),
                                 ("generation", current["generation"] + 2)):
                request = node.request(current, "begin", **{field: wrong})
                current = node.ignored(current, "node-mtu-request.json", request)
                node.readback(current, 1420)
                checks.append("foreign " + field + " rejected")
            current = node.command(current, "begin", reject=True, path_id="f" * 64)
            require(not current["active"], "Wrong physical path acquired a lease")
            checks.append("foreign physical path rejected")
            current = node.command(current, "begin")
            require(current["active"] and not current["restored"], "Begin did not acquire its exact lease")
            before = current
            current = node.command(current, "set", 1360)
            node.readback(current, 1360)
            require(current["reader"] == before["reader"] + 1 and current["index"] != before["index"],
                    "Set did not replace the exact retained native reader")
            checks.append("begin/set with replaced native reader")
            for change in ({"reader": before["reader"]}, {"lease_id": uuid.uuid4().hex}, {"expected_mtu": 1420}):
                current = node.command(current, "set", 1280, reject=True, **change)
                node.readback(current, 1360)
                checks.append("stale " + next(iter(change)) + " rejected")
            current = node.command(current, "rollback")
            node.readback(current, 1420)
            require(not current["active"] and current["restored"], "Rollback did not explicitly acknowledge restoration")
            checks.append("exact native rollback")
            current = node.command(current, "begin", reject=True)
            require(not current["active"], "Retired lease was reused")
            checks.append("retired lease rejected")
            current = node.command(current, "begin", lease_id=uuid.uuid4().hex)
            current = node.command(current, "set", 1380)
            current = node.command(current, "commit")
            node.readback(current, 1380)
            require(not current["active"] and not current["restored"], "Commit falsely claimed rollback")
            checks.append("commit retains candidate")
            current = node.command(current, "rollback", reject=True)
            node.readback(current, 1380)
            checks.append("ordinary rollback cannot alter confirmed inactive commit")

            current = node.command(current, "begin", lease_id=uuid.uuid4().hex)
            current = node.command(current, "set", 1320)
            commit_request, revert_token = uuid.uuid4().hex, uuid.uuid4().hex
            commit_generation = current["generation"] + 1
            current = node.command(current, "commit", request_id=commit_request, revert_token=revert_token)
            node.readback(current, 1320)
            authority = {"commit_request": commit_request, "commit_generation": commit_generation,
                         "revert_token": revert_token}
            for change in ({"revert_token": uuid.uuid4().hex}, {"commit_request": uuid.uuid4().hex},
                           {"commit_generation": commit_generation - 1}, {"reader": current["reader"] - 1},
                           {"expected_mtu": 1380}, {"value": 1420}):
                altered = {**authority, **change}
                value = altered.pop("value", 1380)
                current = node.command(current, "revert-unconfirmed-commit", value, reject=True, **altered)
                node.readback(current, 1320)
                checks.append("unconfirmed commit rejects foreign " + next(iter(change)))
            candidate_reader = current["reader"]
            current = node.command(current, "revert-unconfirmed-commit", 1380, **authority)
            node.readback(current, 1380)
            require(current["restored"] and not current["active"] and not current.get("expired", False)
                    and current["reader"] == candidate_reader + 1,
                    "Commit revert did not restore the exact original through its next native reader")
            checks.append("private unconfirmed commit capability restores exact kernel original")
            current = node.command(current, "revert-unconfirmed-commit", 1380, reject=True, **authority)
            node.readback(current, 1380)
            checks.append("consumed commit-revert capability rejected")

            current = node.command(current, "begin", lease_id=uuid.uuid4().hex)
            current = node.command(current, "set", 1320)
            old_lease = current["lease_id"]
            old_authority = {"commit_request": uuid.uuid4().hex, "commit_generation": current["generation"] + 1,
                             "revert_token": uuid.uuid4().hex}
            current = node.command(current, "commit", request_id=old_authority["commit_request"],
                                   revert_token=old_authority["revert_token"])
            current = node.command(current, "begin", lease_id=uuid.uuid4().hex)
            current = node.command(current, "revert-unconfirmed-commit", 1380, reject=True,
                                   lease_id=old_lease, **old_authority)
            node.readback(current, 1320)
            checks.append("retired commit capability cannot alter a replacement lease")
            current = node.command(current, "set", 1380)
            current = node.command(current, "commit")
            node.readback(current, 1380)
            for field, wrong in (("session_id", uuid.uuid4().hex), ("source_sha256", "f" * 64)):
                current = node.ignored(current, "stop.json", {**node.stop_record, field: wrong})
                node.readback(current, 1380)
                checks.append("foreign stop " + field + " rejected")
            node.stop()
            checks.append("stopped acknowledgement follows kernel cleanup")
        finally:
            node.close()
    require(link(INTERFACE) is None and link(UPLINK)["ifindex"] == physical["ifindex"],
            "Native cleanup removed its physical uplink or retained an owned TUN")
    # A stop during a live lease must also drain the actual TUN before ack.
    with tempfile.TemporaryDirectory(prefix="routervpn-node-active-stop-") as temporary:
        node = Node(binary, Path(temporary))
        try:
            current = node.wait(node.record, "Second native owner did not start")
            current = node.command(current, "begin")
            current = node.command(current, "set", 1360)
            node.readback(current, 1360)
            node.stop()
            checks.append("active-lease stop waits for kernel cleanup")
        finally:
            node.close()
    return {"kernel_executed": True, "namespace": namespace, "parent_namespace": parent,
            "binary_sha256": sha(binary), "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choices = parser.add_mutually_exclusive_group(required=True)
    choices.add_argument("--bundle", type=Path, help="verified complete linux/amd64 runtime artifact")
    choices.add_argument("--prestart-binary", type=Path, help="only the unprivileged real CLI stop-before-start check")
    choices.add_argument("--isolated-child", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--parent-namespace", default="", help=argparse.SUPPRESS)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    if args.isolated_child:
        result = kernel(args.isolated_child.resolve(), args.parent_namespace)
        print("ROUTERVPN_NODE_KERNEL_RECEIPT=" + json.dumps(result, separators=(",", ":")))
        return
    if args.prestart_binary:
        result = prestart(args.prestart_binary.resolve())
        print("Native node stop-before-start: PASS; kernel TUN execution was not requested")
    else:
        spec = importlib.util.spec_from_file_location("routervpn_node_kernel_build", ROOT / "deploy/build-native-runtime.py")
        build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build)
        bundle = args.bundle.resolve()
        verified = build.reuse(bundle, "linux/amd64")
        require(Path("/dev/net/tun").is_char_device(), "Required kernel TUN gate cannot run: /dev/net/tun is absent")
        require(shutil.which("unshare") and shutil.which("ip"), "Required network namespace/ip utilities are absent")
        parent = os.readlink("/proc/self/ns/net")
        binary = bundle / build.binary_name("linux/amd64")
        command = ["unshare", "--net", "--", sys.executable, str(Path(__file__).resolve()),
                   "--isolated-child", str(binary), "--parent-namespace", parent]
        if os.geteuid() != 0:
            command = ["sudo", "--non-interactive", "--", *command]
        run = subprocess.run(command, capture_output=True, text=True, timeout=90)
        require(run.returncode == 0, "Actual native node kernel gate failed:\n" + (run.stdout + run.stderr)[-18000:])
        prefix = "ROUTERVPN_NODE_KERNEL_RECEIPT="
        results = [line[len(prefix):] for line in run.stdout.splitlines() if line.startswith(prefix)]
        require(len(results) == 1, "Actual native node gate did not provide one bounded receipt")
        result = json.loads(results[0])
        require(result.get("kernel_executed") is True and result.get("binary_sha256") == verified["sha256"],
                "Kernel gate did not execute the verified shipping binary")
        result["native_policy_sha256"] = verified["policy_sha256"]
        result["upstream_revision"] = verified["upstream_revision"]
        print("Actual shipping routervpn-node kernel/private-file gate: PASS")
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
