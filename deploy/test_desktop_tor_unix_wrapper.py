#!/usr/bin/env python3
"""Execute the shipping Unix Tor wrapper without a TUN, Tor, or firewall.

The selector and directory verifier are real shipping files. Only the native
controller, native executable and firewall subprocesses are controlled fixtures.
Native cryptographic admission remains covered by the actual Go CLI tests; this
suite observes the wrapper's exact inputs, failure propagation and process owner.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "modes/native-tor-bridge.sh"
DIGEST_FILES = {
    "HOMEVPN_TOR_PROFILE_SHA256": "tor-profile.json",
    "HOMEVPN_TOR_CAPTURE_SHA256": "tor-capture.json",
    "HOMEVPN_TOR_TORRC_SHA256": "torrc",
    "HOMEVPN_TOR_DEFAULTS_SHA256": "tor-defaults",
    "HOMEVPN_TOR_CONFIG_SHA256": "sing-box.json",
}
DIGEST_KEYS = ("HOMEVPN_TOR_SOURCE_SHA256", *DIGEST_FILES, "HOMEVPN_TOR_BINARY_SHA256")
OBSERVED_ENV = (
    "HOMEVPN_ROOT", "HOMEVPN_PROFILE_ID", "HOMEVPN_POLICY_PROFILE_ID",
    "HOMEVPN_ENDPOINT", "HOMEVPN_NATIVE_ENDPOINTS_JSON", "HOMEVPN_NATIVE_EGRESS_JSON", "HOMEVPN_EXTERNAL_SESSION",
    "HOMEVPN_STANDARD_ENGINE", "HOMEVPN_NATIVE_CONTROLLER", "HOMEVPN_NATIVE_PACKAGE",
    "HOMEVPN_TOR_SESSION", *DIGEST_KEYS, "ROUTERVPN_WRAPPER_LITERAL", "ROUTERVPN_WRAPPER_EMPTY",
)


BOUNDARY = r'''
import hashlib, json, os, pathlib, signal, sys
expected = json.loads(pathlib.Path(os.environ["FIXTURE_EXPECTED"]).read_text())
def event(kind):
    record = {"kind": kind, "pid": os.getpid(), "parent": os.getppid(),
              "argv": sys.argv[1:], "cwd": os.getcwd(),
              "env": {key: os.environ.get(key) for key in expected["observed_env"]}}
    with open(os.environ["FIXTURE_EVENTS"], "a", encoding="utf-8") as output:
        output.write(json.dumps(record, ensure_ascii=False) + "\n")
def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
role = pathlib.Path(sys.argv[0]).name
if role == "controller fixture":
    event("verify")
    if sys.argv[1:] != ["--verify-native-runtime", expected["package"]]: sys.exit(40)
    if os.environ.get("FIXTURE_FAIL") == "verify": sys.exit(41)
    # This is the controlled package verifier boundary, not a substitute for
    # the shipping Go receipt tests. A stale engine cannot produce a valid path.
    if digest(expected["native"]) != expected["native_sha256"]: sys.exit(42)
    print(os.environ.get("FIXTURE_VERIFIED_PATH", expected["native"]))
elif role == "kill-switch-platform.py":
    event("protect")
    if sys.argv[1:] != ["apply"]: sys.exit(43)
    for key in ("HOMEVPN_ROOT", "HOMEVPN_PROFILE_ID", "HOMEVPN_POLICY_PROFILE_ID"):
        if os.environ.get(key) != expected["env"][key]: sys.exit(44)
    if os.environ.get("HOMEVPN_ENDPOINT") != expected["endpoint"]: sys.exit(45)
    if os.environ.get("FIXTURE_FAIL") == "protect": sys.exit(46)
    if os.environ.get("FIXTURE_REMOVE_NATIVE") == "1": pathlib.Path(expected["native"]).unlink()
elif role == "standalone tor fixture":
    event("forbidden-independent-tor")
    sys.exit(47)
else:
    if sys.argv[1:] == ["routervpn-tor", "--help"]:
        event("help")
        sys.exit(48 if os.environ.get("FIXTURE_FAIL") == "help" else 0)
    if sys.argv[1:] == ["check", "-D", expected["runtime"], "-c", expected["runtime"] + "/sing-box.json"]:
        event("config")
        sys.exit(49 if os.environ.get("FIXTURE_FAIL") == "config" else 0)
    event("native-admission")
    if sys.argv[1:] != expected["native_argv"]: sys.exit(50)
    # The fixture records whether the wrapper preserves a native admission
    # rejection. It never supplies a successful proof or starts a real child.
    for key in expected["digest_keys"]:
        if os.environ.get(key) != expected["env"][key]:
            event("native-rejected"); sys.exit(51)
    for key, name in expected["digest_files"].items():
        if digest(pathlib.Path(expected["runtime"]) / name) != expected["env"][key]:
            event("native-rejected"); sys.exit(52)
    if expected["server"]:
        if "--tor-binary" in sys.argv or os.environ.get("HOMEVPN_TOR_BINARY_SHA256"):
            event("native-rejected"); sys.exit(53)
    elif digest(expected["tor"]) != expected["env"]["HOMEVPN_TOR_BINARY_SHA256"]:
        event("native-rejected"); sys.exit(53)
    event("native-started")
    if os.environ.get("FIXTURE_SIGNAL") == "term": os.kill(os.getpid(), signal.SIGTERM)
    sys.exit(int(os.environ.get("FIXTURE_NATIVE_EXIT", "0")))
'''


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(directory: Path) -> dict[str, tuple]:
    """Observe private entries without traversing a replacement symlink."""
    result: dict[str, tuple] = {}
    for parent, directories, files in os.walk(directory, followlinks=False):
        for name in [*directories, *files]:
            path = Path(parent) / name
            info = path.lstat()
            payload = os.readlink(path) if stat.S_ISLNK(info.st_mode) else sha(path) if stat.S_ISREG(info.st_mode) else ""
            result[str(path.relative_to(directory))] = (info.st_dev, info.st_ino, info.st_mode, payload)
    return result


class Fixture:
    def __init__(self, base: Path, source: str | None = None):
        base = base.resolve()
        self.base = base
        self.scripts = base / "package scripts with spaces"
        self.scripts.mkdir()
        self.wrapper = self.scripts / "native-tor-bridge.sh"
        self.wrapper.write_text(WRAPPER.read_text() if source is None else source)
        for name in ("cleanup-private-runtime.py", "select-standard-engine.sh", "tor-prelaunch-witness.py"):
            shutil.copyfile(ROOT / "modes" / name, self.scripts / name)
        self.private = base / "private state λ; literal $(ignored)"
        self.runtime = self.private / "run/tor-bridge/session-captured"
        self.runtime.mkdir(parents=True, mode=0o700)
        for directory in (self.private, self.private / "run", self.runtime.parent):
            directory.chmod(0o700)
        self.package = base / "package with spaces"
        self.package.mkdir()
        self.controller = self.package / "controller fixture"
        self.native = self.package / "native engine; literal [fixture]"
        self.tor = self.package / "standalone tor fixture"
        for path in (self.controller, self.native, self.tor, self.scripts / "kill-switch-platform.py"):
            path.write_text(f"#!{sys.executable}\n" + BOUNDARY, encoding="utf-8")
            path.chmod(0o700)
        source_sha = hashlib.sha256(b"captured source identity").hexdigest()
        self.inputs = {
            "tor-profile.json": '{"id":"captured-node","external":{"protocol":"tor-bridge"},"fixture":"private"}\n',
            "tor-capture.json": json.dumps({"schema": 1, "session_id": "a" * 32, "isolation_secret": "b" * 64,
                                           "target_os": "darwin" if sys.platform == "darwin" else "linux", "tor_binary": str(self.tor)}),
            "torrc": "DisableNetwork 1\nSocksPort 0\nUseBridges 0\n",
            "tor-defaults": "DisableNetwork 1\n",
            "sing-box.json": json.dumps({"inbounds": [], "outbounds": [], "services": [
                {"type": "routervpn-desktop-tor-network", "tag": "routervpn-tor-physical",
                 "session_id": "a" * 32, "source_sha256": source_sha}]}),
        }
        for name, content in self.inputs.items():
            path = self.runtime / name
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
        (self.runtime / "tor-data").mkdir(mode=0o700)
        self.events = base / "events.jsonl"
        self.expected_path = base / "boundary-expectations.json"
        self.endpoint = "203.0.113.44"
        self.env = dict(os.environ)
        for key in tuple(self.env):
            if key.startswith(("HOMEVPN_", "FIXTURE_", "BASH_FUNC_")) or key in {"BASH_ENV", "ENV"}:
                self.env.pop(key)
        self.env.update({
            "HOMEVPN_ROOT": str(self.private), "HOMEVPN_PROFILE_ID": "captured-node",
            "HOMEVPN_POLICY_PROFILE_ID": "captured-node", "HOMEVPN_STANDARD_ENGINE": "native",
            "HOMEVPN_ENDPOINT": self.endpoint, "HOMEVPN_NATIVE_ENDPOINTS_JSON": "", "HOMEVPN_NATIVE_EGRESS_JSON": "", "HOMEVPN_EXTERNAL_SESSION": "",
            "HOMEVPN_NATIVE_CONTROLLER": str(self.controller), "HOMEVPN_NATIVE_PACKAGE": str(self.package),
            "HOMEVPN_TOR_SESSION": "a" * 32,
            "HOMEVPN_TOR_SOURCE_SHA256": source_sha,
            "HOMEVPN_TOR_BINARY_SHA256": sha(self.tor),
            "ROUTERVPN_WRAPPER_LITERAL": "λ 中 $() & | ' \" value=exact\nsecond line",
            "ROUTERVPN_WRAPPER_EMPTY": "",
            "FIXTURE_EVENTS": str(self.events), "FIXTURE_EXPECTED": str(self.expected_path),
        })
        self.env.update({key: sha(self.runtime / name) for key, name in DIGEST_FILES.items()})
        self.native_argv = ["routervpn-tor", "--runtime-dir", str(self.runtime), "--session", "a" * 32, "--tor-binary", str(self.tor)]
        self.tor_argument = str(self.tor)
        self.expected = {
            "package": str(self.package), "native": str(self.native), "native_sha256": sha(self.native),
            "runtime": str(self.runtime), "tor": str(self.tor), "endpoint": self.endpoint,
            "native_argv": self.native_argv, "env": {key: self.env[key] for key in OBSERVED_ENV},
            "observed_env": OBSERVED_ENV, "digest_keys": DIGEST_KEYS, "digest_files": DIGEST_FILES, "server": False,
        }
        self.expected_path.write_text(json.dumps(self.expected), encoding="utf-8")

    def set_input(self, name: str, value) -> None:
        raw = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
        self.inputs[name] = raw
        (self.runtime / name).write_text(raw, encoding="utf-8")
        for variable, filename in DIGEST_FILES.items():
            if filename == name:
                self.env[variable] = sha(self.runtime / name)
        self.sync()

    def sync(self) -> None:
        self.expected["env"] = {key: self.env[key] for key in OBSERVED_ENV}
        self.expected["endpoint"] = self.env["HOMEVPN_ENDPOINT"]
        self.expected_path.write_text(json.dumps(self.expected), encoding="utf-8")

    def router_entry(self) -> None:
        egress = [{"host": "203.0.113.20", "port": 51820, "network": "udp"},
                  {"host": "2001:db8::20", "port": 51822, "network": "udp"}]
        self.env.update({"HOMEVPN_PROFILE_ID": "captured-entry", "HOMEVPN_ENDPOINT": "203.0.113.20",
                         "HOMEVPN_EXTERNAL_SESSION": self.env["HOMEVPN_TOR_SESSION"],
                         "HOMEVPN_NATIVE_ENDPOINTS_JSON": '["203.0.113.20","2001:db8::20"]',
                         "HOMEVPN_NATIVE_EGRESS_JSON": json.dumps(egress, separators=(",", ":"))})
        profile = json.loads(self.inputs["tor-profile.json"])
        profile.update({"multihop_enabled": True, "multihop_entry_id": "captured-entry", "multihop_exit_id": "captured-node",
                        "multihop_entry_mode": "wg", "multihop_exit_mode": "tor-bridge", "multihop_execution": "local",
                        "desktop_physical_egress": egress})
        capture = json.loads(self.inputs["tor-capture.json"])
        capture["predecessor"] = {"schema": 1, "entry_mode": "wg", "assets_sha256": "f" * 64,
                                  "profile": {"id": "captured-entry", "node_kind": "router-vpn"},
                                  "config": {"route": {"final": "entry-wg"}}}
        self.set_input("tor-profile.json", profile)
        self.set_input("tor-capture.json", capture)

    def fixed_obfs4(self, count=2, policy="always", transport="custom", shared=False, ipv6_first=False) -> None:
        lines, egress = [], []
        for index in range(count):
            host = f"2001:db8::{index + 40:x}" if (index % 2 == 1) != ipv6_first else f"203.0.113.{index + 40}"
            port = 8443 + index
            if shared and index == 1:
                host, port = egress[0]["host"], egress[0]["port"]
            endpoint = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            lines.append(f"obfs4 {endpoint} {index:040X} cert=Y2VydA iat-mode=0")
            row = {"host": host, "port": port, "network": "tcp"}
            if row not in egress:
                egress.append(row)
        self.endpoint = egress[0]["host"]
        profile = json.loads(self.inputs["tor-profile.json"])
        profile.update({"node_kind": "external", "endpoint": self.endpoint, "kill_switch_policy": policy,
                        "kill_switch": policy != "off", "home_lan_access": False,
                        "external": {"protocol": "tor-bridge", "tor_bridge": {
                            "transport": transport, "bridges": lines, "socks_port": 19475}},
                        "desktop_physical_egress": egress})
        self.env.update({"HOMEVPN_ENDPOINT": self.endpoint, "HOMEVPN_EXTERNAL_SESSION": self.env["HOMEVPN_TOR_SESSION"],
                         "HOMEVPN_NATIVE_ENDPOINTS_JSON": json.dumps(list(dict.fromkeys(row["host"] for row in egress)), separators=(",", ":")),
                         "HOMEVPN_NATIVE_EGRESS_JSON": json.dumps(egress, separators=(",", ":"))})
        self.set_input("tor-profile.json", profile)

    def plain_tor(self) -> None:
        profile = json.loads(self.inputs["tor-profile.json"])
        profile["external"] = {"protocol": "tor"}
        self.endpoint = ""
        if profile.get("multihop_enabled"):
            profile["multihop_exit_mode"] = "tor"
        else:
            profile["kill_switch_policy"], profile["kill_switch"] = "off", False
            self.env["HOMEVPN_ENDPOINT"] = ""
        self.set_input("tor-profile.json", profile)

    def external_entry(self, protocol: str = "shadowsocks") -> None:
        self.router_entry()
        capture = json.loads(self.inputs["tor-capture.json"])
        predecessor = capture["predecessor"]
        predecessor.update({"schema": 2, "entry_kind": "external-public-ip", "entry_mode": protocol,
                            "profile": {"id": "captured-entry", "node_kind": "external",
                                        "external": {"protocol": protocol, "expected_public_ip": "8.8.8.8"}},
                            "source_config": {"route": {"final": "external-exit"}},
                            "config": {"route": {"final": "external-exit"}}})
        profile = json.loads(self.inputs["tor-profile.json"])
        profile["multihop_entry_mode"] = protocol
        self.set_input("tor-capture.json", capture)
        self.set_input("tor-profile.json", profile)

    def server_entry(self) -> None:
        self.router_entry()
        capture = json.loads(self.inputs["tor-capture.json"])
        capture["schema"], capture["tor_binary"] = 2, ""
        profile = json.loads(self.inputs["tor-profile.json"])
        profile["multihop_execution"] = "server"
        self.env["HOMEVPN_TOR_BINARY_SHA256"] = ""
        self.tor_argument = ""
        self.native_argv = ["routervpn-tor", "--runtime-dir", str(self.runtime), "--session", "a" * 32]
        self.expected.update({"server": True, "native_argv": self.native_argv})
        self.set_input("tor-capture.json", capture)
        self.set_input("tor-profile.json", profile)
        self.set_input("torrc", "\n")
        self.set_input("tor-defaults", "\n")
        # Server must reach the native lease owner with no local Tor package.
        self.tor.unlink()

    def run(self, action: str = "up", *, updates: dict[str, str | None] | None = None,
            runtime: Path | None = None, native: Path | None = None, tor: str | None = None) -> tuple[subprocess.CompletedProcess, list[dict], int]:
        if self.events.exists():
            self.events.unlink()
        # A repeated test invocation has a new failed wrapper owner. Product
        # code never deletes or overwrites a previous wrapper's witness.
        witness = self.runtime / "prelaunch-failed.json"
        if witness.is_file() and not witness.is_symlink():
            witness.unlink()
        environment = dict(self.env)
        for key, value in (updates or {}).items():
            if value is None:
                environment.pop(key, None)
            else:
                environment[key] = value
        arguments = ["bash", str(self.wrapper), action, str(runtime or self.runtime), self.endpoint, "19475", self.tor_argument if tor is None else tor, str(native or self.native)]
        before = snapshot(self.private)
        process = subprocess.Popen(arguments, cwd=self.private, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise AssertionError("The isolated wrapper fixture did not finish.")
        observed = [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []
        after = snapshot(self.private)
        witness_key = str(witness.relative_to(self.private))
        if witness_key in after and witness_key not in before:
            record = json.loads(witness.read_text())
            expected = {"schema": 1, "session_id": environment["HOMEVPN_TOR_SESSION"],
                        "source_sha256": environment["HOMEVPN_TOR_SOURCE_SHA256"],
                        "config_sha256": environment["HOMEVPN_TOR_CONFIG_SHA256"], "no_native_process": True}
            if record != expected or witness.stat().st_mode & 0o777 != 0o600:
                raise AssertionError("The failed wrapper wrote an unbound prelaunch witness.")
            if action != "up" or not 0 < process.returncode < 128 or any(e["kind"] == "native-admission" for e in observed):
                raise AssertionError("The wrapper invented no native work after native admission.")
            del after[witness_key]
        if after != before:
            raise AssertionError("The wrapper changed or deleted controller-owned private state.")
        if any(event["kind"] == "forbidden-independent-tor" for event in observed):
            raise AssertionError("The wrapper independently launched standalone Tor.")
        return subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr), observed, process.pid


@unittest.skipIf(os.name == "nt", "Unix executable wrapper fixture")
class UnixTorWrapper(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="routervpn-unix-tor-wrapper-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.fixture = Fixture(self.base)

    def assert_success(self, fixture: Fixture | None = None):
        fixture = fixture or self.fixture
        result, events, process_id = fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([entry["kind"] for entry in events], ["verify", "help", "config", "protect", "native-admission", "native-started"],
                         "Captured protection did not precede native launch.")
        native = events[-1]
        self.assertEqual(native["pid"], process_id, "The wrapper did not exec the exact native process owner.")
        self.assertEqual(native["argv"], fixture.native_argv)
        self.assertEqual(native["env"], fixture.expected["env"], "A captured native environment value changed.")
        self.assertEqual(native["cwd"], str(fixture.private))
        self.assertEqual(events[0]["argv"], ["--verify-native-runtime", str(fixture.package)])
        self.assertEqual(events[2]["argv"], ["check", "-D", str(fixture.runtime), "-c", str(fixture.runtime / "sing-box.json")])
        self.assertEqual(events[3]["argv"], ["apply"])
        self.assertFalse((fixture.runtime / "stopped.json").exists(), "The wrapper fabricated a native receipt.")

    def test_actual_exec_inputs_order_and_private_retention(self):
        self.assert_success()

    def test_fixed_obfs4_sets_retain_all_source_tuples_before_exec(self):
        for count in range(1, 9):
            for policy in ("on-connect", "always"):
                with self.subTest(count=count, policy=policy), tempfile.TemporaryDirectory(prefix="routervpn-tor-fixed-") as directory:
                    fixture = Fixture(Path(directory))
                    fixture.fixed_obfs4(count, policy, "obfs4" if count % 2 else "custom", ipv6_first=count % 2 == 1)
                    self.assert_success(fixture)
        self.fixture.fixed_obfs4(2, shared=True)
        self.assertEqual(len(json.loads(self.fixture.inputs["tor-profile.json"])["external"]["tor_bridge"]["bridges"]), 2)
        self.assertEqual(len(json.loads(self.fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"])), 1)
        self.assert_success()

    def test_fixed_obfs4_source_cannot_be_replaced_by_matching_untrusted_tuples(self):
        for fault in ("port", "udp", "resolver", "extra", "partial", "order", "hosts-order", "missing-projection", "missing-arrays",
                      "private-source", "dynamic-source", "changed-source", "source-count", "credentials-after-capture", "session", "role"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="routervpn-tor-fixed-negative-") as directory:
                fixture = Fixture(Path(directory))
                fixture.fixed_obfs4()
                profile = json.loads(fixture.inputs["tor-profile.json"])
                rows = profile["desktop_physical_egress"]
                if fault == "port": rows[1]["port"] = 53
                elif fault == "udp": rows[1]["network"] = "udp"
                elif fault == "resolver": rows[1]["host"] = "9.9.9.9"
                elif fault == "extra": rows.append({"host": "8.8.8.8", "port": 53, "network": "tcp"})
                elif fault == "partial": rows.pop()
                elif fault == "order": rows.reverse(); fixture.endpoint = rows[0]["host"]; fixture.env["HOMEVPN_ENDPOINT"] = fixture.endpoint
                elif fault == "missing-projection": del profile["desktop_physical_egress"]
                elif fault == "private-source":
                    profile["external"]["tor_bridge"]["bridges"][1] = profile["external"]["tor_bridge"]["bridges"][1].replace("2001:db8::29", "fd00::29")
                    rows[1]["host"] = "fd00::29"
                elif fault == "dynamic-source": profile["external"]["tor_bridge"]["bridges"][1] = "meek_lite 192.0.2.2:443 url=https://front.example/ front=front.example"
                elif fault == "changed-source": profile["external"]["tor_bridge"]["bridges"][1] = profile["external"]["tor_bridge"]["bridges"][1].replace(":8444", ":9444")
                elif fault == "source-count": profile["external"]["tor_bridge"]["bridges"] *= 5
                elif fault == "session": fixture.env["HOMEVPN_EXTERNAL_SESSION"] = "f" * 32
                elif fault == "role": fixture.env["HOMEVPN_PROFILE_ID"] = "foreign-entry"
                fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"] = json.dumps(rows, separators=(",", ":"))
                hosts = list(dict.fromkeys(row["host"] for row in rows))
                if fault == "hosts-order": hosts.reverse()
                fixture.env["HOMEVPN_NATIVE_ENDPOINTS_JSON"] = json.dumps(hosts, separators=(",", ":"))
                if fault == "missing-arrays": fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"] = ""
                fixture.set_input("tor-profile.json", profile)
                if fault == "credentials-after-capture":
                    (fixture.runtime / "tor-profile.json").write_text(fixture.inputs["tor-profile.json"].replace("cert=Y2VydA", "cert=Y2hhbmdlZA", 1))
                result, events, _ = fixture.run()
                self.assertNotEqual(result.returncode, 0, fault)
                self.assertNotIn("protect", [item["kind"] for item in events], fault)
                self.assertNotIn("native-admission", [item["kind"] for item in events], fault)

    def test_fixed_source_guard_has_an_executable_negative_control(self):
        self.fixture.fixed_obfs4()
        profile = json.loads(self.fixture.inputs["tor-profile.json"])
        profile["desktop_physical_egress"][1]["port"] = 9444
        self.fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"] = json.dumps(profile["desktop_physical_egress"], separators=(",", ":"))
        self.fixture.set_input("tor-profile.json", profile)
        result, events, _ = self.fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(events, [])
        verifier = self.fixture.scripts / "tor-prelaunch-witness.py"
        source = verifier.read_text()
        guard = 'if direct is not None and (egress != direct or addresses != list(dict.fromkeys(row["host"] for row in direct))):'
        self.assertEqual(source.count(guard), 1)
        verifier.write_text(source.replace(guard, "if False:"))
        result, events, _ = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("protect", [item["kind"] for item in events], "Removed source guard did not expose the intended tuple substitution.")

    def test_plain_tor_retains_empty_guard_or_exact_predecessor(self):
        for path in ("direct", "router", "ordinary", "server"):
            with self.subTest(path=path), tempfile.TemporaryDirectory(prefix="plain-tor-wrapper-") as directory:
                fixture = Fixture(Path(directory))
                if path == "router":
                    fixture.router_entry()
                elif path == "ordinary":
                    fixture.external_entry()
                elif path == "server":
                    fixture.server_entry()
                fixture.plain_tor()
                self.assert_success(fixture)

    def test_plain_tor_rejects_invented_endpoint_bridge_and_execution(self):
        for fault in ("endpoint", "strict", "typed-kill", "bridge", "exit-mode", "unknown-protocol", "server-mode"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="plain-tor-rejection-") as directory:
                fixture = Fixture(Path(directory))
                if fault in {"exit-mode", "server-mode"}:
                    fixture.server_entry() if fault == "server-mode" else fixture.router_entry()
                fixture.plain_tor()
                profile = json.loads(fixture.inputs["tor-profile.json"])
                if fault == "endpoint": fixture.env["HOMEVPN_ENDPOINT"] = "203.0.113.44"
                elif fault == "strict": profile["kill_switch_policy"] = "always"
                elif fault == "typed-kill": profile["kill_switch"] = "false"
                elif fault == "bridge": profile["external"]["tor_bridge"] = {"bridges": ["private bridge"]}
                elif fault == "unknown-protocol": profile["external"]["protocol"] = "socks5"
                else: profile["multihop_exit_mode"] = "tor-bridge"
                fixture.set_input("tor-profile.json", profile)
                result, events, _ = fixture.run()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(e["kind"] in {"protect", "native-admission"} for e in events))

    def test_check_is_read_only_and_down_is_an_actual_noop(self):
        result, events, _ = self.fixture.run("check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([entry["kind"] for entry in events], ["verify", "help", "config"])
        for name in ("cleanup-private-runtime.py", "select-standard-engine.sh", "kill-switch-platform.py"):
            (self.fixture.scripts / name).unlink()
        result, events, _ = self.fixture.run("down", runtime=self.base / "absent-outside-runtime", native=self.base / "absent-native")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, [], "Down rediscovered or changed another process/runtime owner.")

    def test_missing_or_malformed_capture_cannot_reach_any_native_boundary(self):
        for key in DIGEST_KEYS:
            for value in (None, "", "f" * 63, "F" * 64):
                with self.subTest(key=key, value=value):
                    result, events, _ = self.fixture.run(updates={key: value})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(events, [])
        for updates in ({"HOMEVPN_TOR_SESSION": "A" * 32}, {"HOMEVPN_STANDARD_ENGINE": "stock"},
                        {"HOMEVPN_PROFILE_ID": ""}, {"HOMEVPN_POLICY_PROFILE_ID": "another-node"}):
            with self.subTest(updates=updates):
                result, events, _ = self.fixture.run(updates=updates)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(events, [])

    def test_native_package_verifier_rejection_precedes_firewall_and_launch(self):
        self.fixture.native.write_text(self.fixture.native.read_text() + "\n# changed native package bytes\n")
        result, events, _ = self.fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([entry["kind"] for entry in events], ["verify"])

    def test_changed_native_path_is_not_adopted(self):
        replacement = self.fixture.package / "another native engine"
        shutil.copyfile(self.fixture.native, replacement)
        replacement.chmod(0o700)
        for native, updates in ((replacement, {}), (None, {"FIXTURE_VERIFIED_PATH": str(replacement)}),
                                (None, {"FIXTURE_VERIFIED_PATH": str(self.fixture.native) + "\nforeign"})):
            with self.subTest(native=native, updates=updates):
                result, events, _ = self.fixture.run(native=native, updates=updates)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([entry["kind"] for entry in events], ["verify"])

    def test_each_preflight_or_protection_failure_blocks_native_launch(self):
        for failure, expected in (("verify", ["verify"]), ("help", ["verify", "help"]),
                                  ("config", ["verify", "help", "config"]),
                                  ("protect", ["verify", "help", "config", "protect"])):
            with self.subTest(failure=failure):
                result, events, _ = self.fixture.run(updates={"FIXTURE_FAIL": failure})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([entry["kind"] for entry in events], expected)
                self.assertTrue((self.fixture.runtime / "prelaunch-failed.json").is_file(),
                                "A proven pre-native wrapper failure has no recoverable witness.")

    def test_failed_exec_can_publish_only_prelaunch_failure(self):
        result, events, _ = self.fixture.run(updates={"FIXTURE_REMOVE_NATIVE": "1"})
        self.assertEqual(result.returncode, 127)
        self.assertEqual([event["kind"] for event in events], ["verify", "help", "config", "protect"])
        self.assertTrue((self.fixture.runtime / "prelaunch-failed.json").is_file())
        self.assertFalse((self.fixture.runtime / "stopped.json").exists())

    def test_no_work_writer_rejects_admission_tampering_and_other_private_owners(self):
        for mutation in ("progress", "partial-progress", "proof", "foreign", "changed-input", "used-data",
                         "linked-input", "linked-data", "foreign-stop", "linked-receipt", "prior-receipt"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="routervpn-tor-witness-") as directory:
                fixture = Fixture(Path(directory))
                runtime = fixture.runtime
                if mutation in ("progress", "partial-progress", "proof", "foreign"):
                    name = {"progress": "progress.json", "partial-progress": ".progress.json.pending",
                            "proof": "proof.json", "foreign": "foreign-owner"}[mutation]
                    (runtime / name).write_text("{}")
                elif mutation == "changed-input":
                    (runtime / "torrc").write_text("changed in place")
                elif mutation == "used-data":
                    (runtime / "tor-data/state").write_text("native already ran")
                elif mutation in ("linked-input", "linked-data"):
                    path = runtime / ("torrc" if mutation == "linked-input" else "tor-data")
                    retained = fixture.base / "another-owner"
                    path.rename(retained)
                    path.symlink_to(retained, target_is_directory=retained.is_dir())
                elif mutation == "foreign-stop":
                    path = runtime / "stop.json"
                    path.write_text(json.dumps({"schema": 1, "session_id": "f" * 32,
                                               "source_sha256": fixture.env["HOMEVPN_TOR_SOURCE_SHA256"]}))
                    path.chmod(0o600)
                elif mutation == "linked-receipt":
                    retained = fixture.base / "outside-receipt"
                    retained.write_text("retained outside")
                    (runtime / "prelaunch-failed.json").symlink_to(retained)
                else:
                    (runtime / "prelaunch-failed.json").write_text("previous witness")
                before = snapshot(fixture.private)
                result = subprocess.run([sys.executable, str(fixture.scripts / "tor-prelaunch-witness.py"), str(runtime)],
                                        env=fixture.env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(snapshot(fixture.private), before, "The witness writer changed another private owner.")

    def test_no_work_writer_accepts_only_matching_pending_controller_stop(self):
        request = {"schema": 1, "session_id": self.fixture.env["HOMEVPN_TOR_SESSION"],
                   "source_sha256": self.fixture.env["HOMEVPN_TOR_SOURCE_SHA256"], "closed": False}
        path = self.fixture.runtime / "stop.json"
        path.write_text(json.dumps(request)); path.chmod(0o600)
        result, events, _ = self.fixture.run(updates={"FIXTURE_FAIL": "protect"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(events[-1]["kind"], "protect")
        self.assertTrue((self.fixture.runtime / "prelaunch-failed.json").is_file())
        self.assertEqual(json.loads(path.read_text()), request)

    def test_missing_runtime_inputs_and_captured_controller_are_rejected(self):
        for name in self.fixture.inputs:
            with self.subTest(input=name):
                path = self.fixture.runtime / name
                retained = self.base / ("retained-" + name)
                path.rename(retained)
                try:
                    result, events, _ = self.fixture.run()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(events, [])
                    self.assertEqual(retained.read_text(), self.fixture.inputs[name])
                finally:
                    retained.rename(path)
        for key in ("HOMEVPN_NATIVE_CONTROLLER", "HOMEVPN_NATIVE_PACKAGE"):
            with self.subTest(key=key):
                result, events, _ = self.fixture.run(updates={key: None})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(events, [])

    def test_capture_rejection_precedes_protection_and_native_retains_binary_guard(self):
        for key in DIGEST_KEYS:
            with self.subTest(key=key):
                result, events, process_id = self.fixture.run(updates={key: "f" * 64})
                if key == "HOMEVPN_TOR_BINARY_SHA256":
                    self.assertEqual(result.returncode, 51)
                    self.assertEqual([entry["kind"] for entry in events], ["verify", "help", "config", "protect", "native-admission", "native-rejected"])
                    self.assertEqual(events[-1]["pid"], process_id)
                    self.assertEqual(events[-1]["env"][key], "f" * 64, "The wrapper silently replaced a stale captured digest.")
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(events, [], "Changed capture reached a native or protection boundary.")
                self.assertFalse((self.fixture.runtime / "stopped.json").exists())
        for name in DIGEST_FILES.values():
            with self.subTest(input=name):
                path = self.fixture.runtime / name
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b"changed")
                    result, events, _ = self.fixture.run()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(events, [], "Changed private bytes reached protection.")
                finally:
                    path.write_bytes(original)

    def test_router_entry_preserves_physical_endpoint_and_exact_tuples(self):
        self.fixture.router_entry()
        self.assert_success()
        self.assertNotEqual(self.fixture.env["HOMEVPN_ENDPOINT"], self.fixture.endpoint)

    def test_server_exec_uses_blank_fifth_argument_without_a_local_tor_package(self):
        self.fixture.server_entry()
        self.assertFalse(self.fixture.tor.exists())
        self.assert_success()
        result, events, _ = self.fixture.run("check")
        self.assertEqual(result.args[6], "", "Server launch shifted the native executable into the Tor argument.")
        self.assertEqual(result.args[7], str(self.fixture.native))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([entry["kind"] for entry in events], ["verify", "help", "config"])
        self.assertEqual(self.fixture.native_argv, ["routervpn-tor", "--runtime-dir", str(self.fixture.runtime), "--session", "a" * 32])

    def test_server_rejects_schema_execution_child_and_source_substitution_before_protection(self):
        faults = ("local-schema", "local-execution", "missing-execution", "compare-execution", "ordinary-entry", "direct",
                  "capture-binary", "argument-binary", "null-binary", "binary-hash", "torrc", "defaults", "empty-torrc",
                  "source", "projection", "profile-digest", "capture-digest", "graph-digest")
        for fault in faults:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="routervpn-tor-server-reject-") as directory:
                fixture = Fixture(Path(directory))
                if fault == "local-schema":
                    fixture.router_entry()
                else:
                    fixture.server_entry()
                capture = json.loads(fixture.inputs["tor-capture.json"])
                profile = json.loads(fixture.inputs["tor-profile.json"])
                profile["multihop_execution"] = "server"
                if fault == "local-execution": profile["multihop_execution"] = "local"
                elif fault == "missing-execution": del profile["multihop_execution"]
                elif fault == "compare-execution": profile["multihop_execution"] = "auto"
                elif fault == "ordinary-entry":
                    capture["predecessor"] = {"schema": 2, "entry_kind": "external-public-ip", "entry_mode": "shadowsocks",
                                              "assets_sha256": "f" * 64, "profile": {"id": "captured-entry", "node_kind": "external",
                                              "external": {"protocol": "shadowsocks", "expected_public_ip": "8.8.8.8"}},
                                              "config": {"route": {"final": "external-exit"}}, "source_config": {"route": {"final": "external-exit"}}}
                    profile["multihop_entry_mode"] = "shadowsocks"
                elif fault == "direct":
                    del capture["predecessor"]
                    for key in ("multihop_entry_id", "multihop_exit_id", "multihop_entry_mode", "multihop_exit_mode", "desktop_physical_egress"):
                        del profile[key]
                    profile["multihop_enabled"] = False
                    fixture.env.update({"HOMEVPN_PROFILE_ID": "captured-node", "HOMEVPN_ENDPOINT": fixture.endpoint,
                                        "HOMEVPN_NATIVE_ENDPOINTS_JSON": "", "HOMEVPN_NATIVE_EGRESS_JSON": "", "HOMEVPN_EXTERNAL_SESSION": ""})
                elif fault == "capture-binary": capture["tor_binary"] = str(fixture.native)
                elif fault == "null-binary": capture["tor_binary"] = None
                elif fault == "binary-hash": fixture.env["HOMEVPN_TOR_BINARY_SHA256"] = "d" * 64
                elif fault == "torrc": fixture.set_input("torrc", "DisableNetwork 1\n")
                elif fault == "defaults": fixture.set_input("tor-defaults", "DisableNetwork 1\n")
                elif fault == "empty-torrc": fixture.set_input("torrc", "")
                elif fault == "source": fixture.env["HOMEVPN_TOR_SOURCE_SHA256"] = "d" * 64
                elif fault == "projection": fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"] = fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"].replace('"port":51820', '"port":443')
                fixture.set_input("tor-capture.json", capture)
                fixture.set_input("tor-profile.json", profile)
                if fault.endswith("-digest"):
                    key = {"profile-digest": "HOMEVPN_TOR_PROFILE_SHA256", "capture-digest": "HOMEVPN_TOR_CAPTURE_SHA256", "graph-digest": "HOMEVPN_TOR_CONFIG_SHA256"}[fault]
                    fixture.env[key] = "d" * 64
                result, events, _ = fixture.run(tor=str(fixture.native) if fault == "argument-binary" else None)
                self.assertNotEqual(result.returncode, 0, fault)
                self.assertEqual(events, [], "Invalid Server capture reached verification, protection or native admission: " + fault)
                # A rejected invocation argument still leaves a valid untouched
                # capture for the EXIT trap's no-native-work witness.
                if fault != "argument-binary":
                    self.assertFalse((fixture.runtime / "prelaunch-failed.json").exists(), "Invalid Server inputs obtained no-native authority: " + fault)

    def test_server_preflight_failures_retain_inputs_and_native_exit_cannot_claim_no_work(self):
        self.fixture.server_entry()
        for failure, expected in (("verify", ["verify"]), ("help", ["verify", "help"]),
                                  ("config", ["verify", "help", "config"]), ("protect", ["verify", "help", "config", "protect"])):
            with self.subTest(failure=failure):
                result, events, _ = self.fixture.run(updates={"FIXTURE_FAIL": failure})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([entry["kind"] for entry in events], expected)
                self.assertTrue((self.fixture.runtime / "prelaunch-failed.json").is_file())
        for updates, expected in (({"FIXTURE_NATIVE_EXIT": "67"}, 67), ({"FIXTURE_SIGNAL": "term"}, -signal.SIGTERM)):
            with self.subTest(updates=updates):
                result, events, process_id = self.fixture.run(updates=updates)
                self.assertEqual(result.returncode, expected)
                self.assertEqual(events[-1]["pid"], process_id)
                self.assertFalse((self.fixture.runtime / "prelaunch-failed.json").exists())
                self.assertFalse((self.fixture.runtime / "stopped.json").exists())

    def test_external_entry_preserves_typed_proof_and_exact_physical_owner(self):
        for protocol in ("wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"):
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory(prefix="routervpn-tor-external-") as directory:
                fixture = Fixture(Path(directory))
                fixture.external_entry(protocol)
                self.assert_success(fixture)
                self.assertNotEqual(fixture.env["HOMEVPN_ENDPOINT"], fixture.endpoint)

    def test_external_entry_rejects_foreign_schema_or_proof_before_protection(self):
        faults = ("router-schema", "unknown-schema", "typed-schema", "proof-kind", "missing-kind", "null-kind", "node-kind",
                  "source-missing", "source-null", "source-array", "source-empty", "source-boolean", "config-boolean",
                  "entry-id", "protocol", "unsupported-protocol", "external-null", "external-array", "public-ip", "public-ip-mapped",
                  "router-api", "router-token", "router-id", "extra-field", "port", "network", "order", "source-digest")
        for fault in faults:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="routervpn-tor-external-reject-") as directory:
                fixture = Fixture(Path(directory))
                fixture.external_entry()
                capture = json.loads(fixture.inputs["tor-capture.json"])
                entry = capture["predecessor"]
                if fault == "router-schema": entry["schema"] = 1
                elif fault == "unknown-schema": entry["schema"] = 3
                elif fault == "typed-schema": entry["schema"] = "2"
                elif fault == "proof-kind": entry["entry_kind"] = "router-private-agent"
                elif fault == "missing-kind": del entry["entry_kind"]
                elif fault == "null-kind": entry["entry_kind"] = None
                elif fault == "node-kind": entry["profile"]["node_kind"] = "router-vpn"
                elif fault == "source-missing": del entry["source_config"]
                elif fault == "source-null": entry["source_config"] = None
                elif fault == "source-array": entry["source_config"] = []
                elif fault == "source-empty": entry["source_config"] = {}
                elif fault == "source-boolean": entry["source_config"] = True
                elif fault == "config-boolean": entry["config"] = True
                elif fault == "entry-id": entry["profile"]["id"] = "foreign-entry"
                elif fault == "protocol": entry["profile"]["external"]["protocol"] = "hysteria2"
                elif fault == "unsupported-protocol": entry["profile"]["external"]["protocol"] = entry["entry_mode"] = "foreign"
                elif fault == "external-null": entry["profile"]["external"] = None
                elif fault == "external-array": entry["profile"]["external"] = []
                elif fault == "public-ip": entry["profile"]["external"]["expected_public_ip"] = "provider.example"
                elif fault == "public-ip-mapped": entry["profile"]["external"]["expected_public_ip"] = "::ffff:8.8.8.8"
                elif fault == "router-api": entry["profile"]["router_api"] = "https://192.0.2.8"
                elif fault == "router-token": entry["profile"]["api_token"] = "foreign"
                elif fault == "router-id": entry["profile"]["node_proof_id"] = "f" * 64
                elif fault == "extra-field": entry["foreign"] = True
                elif fault == "port": fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"] = fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"].replace('"port":51820', '"port":443')
                elif fault == "network": fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"] = fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"].replace('"network":"udp"', '"network":"tcp"')
                elif fault == "order": fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"] = json.dumps(list(reversed(json.loads(fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"]))), separators=(",", ":"))
                elif fault == "source-digest": fixture.env["HOMEVPN_TOR_SOURCE_SHA256"] = "d" * 64
                fixture.set_input("tor-capture.json", capture)
                result, events, _ = fixture.run()
                self.assertNotEqual(result.returncode, 0, fault)
                self.assertEqual(events, [], "Invalid ordinary entry reached preparation or protection: " + fault)

    def test_plain_direct_policy_guard_is_required_before_firewall_handoff(self):
        self.fixture.plain_tor()
        profile = json.loads(self.fixture.inputs["tor-profile.json"])
        profile["kill_switch_policy"] = "always"
        self.fixture.set_input("tor-profile.json", profile)
        result, events, _ = self.fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(events, [])
        verifier = self.fixture.scripts / "tor-prelaunch-witness.py"
        original = verifier.read_text()
        guard = 'or profile.get("kill_switch_policy") != "off"'
        self.assertEqual(original.count(guard), 1)
        verifier.write_text(original.replace(guard, 'or False'))
        result, events, _ = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("protect", [item["kind"] for item in events], "Removed plain Direct policy guard did not expose the intended defective firewall handoff.")

    def test_external_proof_kind_guard_is_required_before_firewall_handoff(self):
        self.fixture.external_entry()
        capture = json.loads(self.fixture.inputs["tor-capture.json"])
        capture["predecessor"]["entry_kind"] = "router-private-agent"
        self.fixture.set_input("tor-capture.json", capture)
        result, events, _ = self.fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(events, [])
        verifier = self.fixture.scripts / "tor-prelaunch-witness.py"
        original = verifier.read_text()
        changed = original.replace('entry["entry_kind"] != "external-public-ip"', 'False')
        self.assertNotEqual(changed, original)
        verifier.write_text(changed)
        result, events, _ = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("protect", [item["kind"] for item in events], "Removed proof-kind guard did not expose the intended defect.")

    def test_router_entry_rejects_changed_physical_projection_before_protection(self):
        faults = ("port", "network", "extra", "missing", "order", "host", "physical-id", "policy-id", "session",
                  "entry-id", "entry-mode", "server", "projection-missing", "projection-null", "projection-unknown",
                  "projection-duplicate", "tuple-duplicate-member", "port-string", "port-bool", "source")
        for fault in faults:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="routervpn-tor-physical-") as directory:
                fixture = Fixture(Path(directory))
                fixture.router_entry()
                profile = json.loads(fixture.inputs["tor-profile.json"])
                egress = json.loads(fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"])
                if fault == "port": egress[0]["port"] = 443
                elif fault == "network": egress[0]["network"] = "tcp"
                elif fault == "extra": egress.append({"host": "203.0.113.20", "port": 443, "network": "tcp"})
                elif fault == "missing": egress.pop()
                elif fault == "order": egress.reverse()
                elif fault == "host": egress[0]["host"] = "198.51.100.99"
                elif fault == "physical-id": fixture.env["HOMEVPN_PROFILE_ID"] = "other-entry"
                elif fault == "policy-id": fixture.env["HOMEVPN_POLICY_PROFILE_ID"] = "other-exit"
                elif fault == "session": fixture.env["HOMEVPN_EXTERNAL_SESSION"] = "d" * 32
                elif fault == "entry-id": profile["multihop_entry_id"] = "other-entry"
                elif fault == "entry-mode": profile["multihop_entry_mode"] = "hysteria2"
                elif fault == "server": profile["multihop_execution"] = "server"
                elif fault == "projection-missing": del profile["desktop_physical_egress"]
                elif fault == "projection-null": profile["desktop_physical_egress"] = None
                elif fault == "projection-unknown": profile["desktop_physical_egress"][0]["allow_all"] = True
                elif fault == "port-string": egress[0]["port"] = "51820"
                elif fault == "port-bool": egress[0]["port"] = True
                elif fault == "source": fixture.env["HOMEVPN_TOR_SOURCE_SHA256"] = "d" * 64
                fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"] = json.dumps(egress, separators=(",", ":"))
                fixture.set_input("tor-profile.json", profile)
                if fault == "projection-duplicate":
                    fixture.set_input("tor-profile.json", fixture.inputs["tor-profile.json"].replace('"desktop_physical_egress":', '"desktop_physical_egress":[],"desktop_physical_egress":', 1))
                elif fault == "tuple-duplicate-member":
                    fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"] = fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"].replace('"port":51820', '"port":443,"port":51820', 1)
                result, events, _ = fixture.run()
                self.assertNotEqual(result.returncode, 0, fault)
                self.assertNotIn("protect", [item["kind"] for item in events], fault)
                self.assertNotIn("native-admission", [item["kind"] for item in events], fault)

    def test_direct_tor_cannot_borrow_an_entry_projection(self):
        for fault in ("projection", "endpoint", "arrays", "session"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="routervpn-tor-direct-") as directory:
                fixture = Fixture(Path(directory))
                if fault == "projection":
                    profile = json.loads(fixture.inputs["tor-profile.json"])
                    profile["desktop_physical_egress"] = [{"host": "203.0.113.44", "port": 443, "network": "tcp"}]
                    fixture.set_input("tor-profile.json", profile)
                elif fault == "endpoint": fixture.env["HOMEVPN_ENDPOINT"] = "203.0.113.20"
                elif fault == "arrays": fixture.env["HOMEVPN_NATIVE_ENDPOINTS_JSON"] = '["203.0.113.44"]'
                else: fixture.env["HOMEVPN_EXTERNAL_SESSION"] = fixture.env["HOMEVPN_TOR_SESSION"]
                result, events, _ = fixture.run()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(events, [])

    def test_actual_projection_guard_detects_same_host_port_mutation(self):
        self.fixture.router_entry()
        self.fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"] = self.fixture.env["HOMEVPN_NATIVE_EGRESS_JSON"].replace('"port":51820', '"port":443', 1)
        result, events, _ = self.fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(events, [])
        verifier = self.fixture.scripts / "tor-prelaunch-witness.py"
        original = verifier.read_text()
        changed = original.replace("if projected != egress:", "if False:")
        self.assertNotEqual(changed, original)
        verifier.write_text(changed)
        result, events, _ = self.fixture.run()
        self.assertEqual(result.returncode, 0, "Projection mutation did not reach its intended execution boundary.")
        self.assertIn("protect", [item["kind"] for item in events], "Removed projection guard did not permit the intended defective firewall handoff.")

    def test_native_exit_and_signal_keep_the_same_controller_process_identity(self):
        for updates, expected in (({"FIXTURE_NATIVE_EXIT": "67"}, 67), ({"FIXTURE_SIGNAL": "term"}, -signal.SIGTERM)):
            with self.subTest(updates=updates):
                result, events, process_id = self.fixture.run(updates=updates)
                self.assertEqual(result.returncode, expected)
                self.assertEqual(events[-1]["pid"], process_id)
                self.assertFalse((self.fixture.runtime / "stopped.json").exists())

    def test_links_to_inputs_binaries_helpers_and_directories_are_rejected(self):
        cases = ("input", "tor", "native", "controller", "selector", "validator", "firewall", "runtime", "category", "run", "root")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="routervpn-tor-link-") as directory:
                fixture = Fixture(Path(directory))
                paths = {
                    "input": fixture.runtime / "tor-profile.json", "tor": fixture.tor,
                    "native": fixture.native, "controller": fixture.controller,
                    "selector": fixture.scripts / "select-standard-engine.sh",
                    "validator": fixture.scripts / "cleanup-private-runtime.py",
                    "firewall": fixture.scripts / "kill-switch-platform.py",
                    "runtime": fixture.runtime, "category": fixture.runtime.parent,
                    "run": fixture.private / "run",
                }
                updates = {}
                external = None
                retained = None
                if case == "root":
                    alias = fixture.base / "linked-private-root"
                    alias.symlink_to(fixture.private, target_is_directory=True)
                    updates["HOMEVPN_ROOT"] = str(alias)
                else:
                    path = paths[case]
                    external = fixture.base / ("retained-outside-" + case)
                    path.rename(external)
                    path.symlink_to(external, target_is_directory=external.is_dir())
                    retained = snapshot(external) if external.is_dir() else external.read_bytes()
                result, events, _ = fixture.run(updates=updates)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("protect", [entry["kind"] for entry in events])
                self.assertNotIn("native-admission", [entry["kind"] for entry in events])
                if external is not None:
                    self.assertTrue(external.exists(), "A linked external owner was removed.")
                    self.assertEqual(snapshot(external) if external.is_dir() else external.read_bytes(), retained)

    def test_outside_unrelated_and_deep_runtime_paths_fail_before_verification(self):
        for target in (self.base / "outside", self.fixture.private / "run/unrelated/session-x", self.fixture.runtime / "nested"):
            with self.subTest(target=target):
                target.mkdir(parents=True, exist_ok=True)
                (target / "retain").write_text("outside owner\n")
                result, events, _ = self.fixture.run(runtime=target)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(events, [])
                self.assertEqual((target / "retain").read_text(), "outside owner\n")

    def test_generic_cleanup_stays_denied_for_verified_tor_directory(self):
        verifier = self.fixture.scripts / "cleanup-private-runtime.py"
        before = snapshot(self.fixture.private)
        verified = subprocess.run([sys.executable, str(verifier), "verify-dir", str(self.fixture.runtime)], env=self.fixture.env, capture_output=True, text=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(verified.stdout.strip(), str(self.fixture.runtime))
        for target in (self.fixture.runtime, self.fixture.runtime.parent):
            result = subprocess.run([sys.executable, str(verifier), str(target)], env=self.fixture.env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unrelated", result.stderr)
            self.assertEqual(snapshot(self.fixture.private), before)

    def test_executable_defect_controls_detect_lost_exec_and_skipped_protection(self):
        original = WRAPPER.read_text()
        mutations = {
            "exec": (original.replace('exec "$NATIVE_BIN" routervpn-tor', '"$NATIVE_BIN" routervpn-tor') + '\nnative_status=$?\nexit "$native_status"\n',
                     "The wrapper did not exec the exact native process owner"),
            "protection": (original.replace('python3 "$SCRIPT_DIR/kill-switch-platform.py" apply', ': # fixture removed protection'),
                           "Captured protection did not precede native launch"),
        }
        for name, (mutated, message) in mutations.items():
            with self.subTest(defect=name), tempfile.TemporaryDirectory(prefix="routervpn-tor-defect-") as directory:
                self.assertNotEqual(mutated, original)
                fixture = Fixture(Path(directory), mutated)
                with self.assertRaisesRegex(AssertionError, message):
                    self.assert_success(fixture)


if __name__ == "__main__":
    unittest.main(verbosity=2)
