#!/usr/bin/env python3
"""Execute the shipping optimizer against a real bounded helper subprocess."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mtu_optimizer_owner", ROOT / "modes/mtu-throughput-tuner.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
TOKEN = "a" * 32


class OwnerConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.package = tempfile.TemporaryDirectory(prefix="router-vpn-mtu-owner-binary-")
        supplied = os.environ.get("MTU_OWNER_TEST_HELPER")
        if supplied:
            cls.helper = Path(supplied).resolve()
        else:
            go = shutil.which("go")
            if not go:
                raise RuntimeError("Go is required for the actual MTU helper subprocess fixture")
            cls.helper = Path(cls.package.name) / ("owner.exe" if os.name == "nt" else "owner")
            subprocess.run([go, "build", "-o", str(cls.helper), str(ROOT / "deploy/testfixtures/mtu-owner/main.go")], check=True, cwd=ROOT)

    @classmethod
    def tearDownClass(cls):
        cls.package.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="router-vpn-mtu-owner-consumer-")
        self.path = Path(self.directory.name) / "state.json"
        self.state = {"owner_token": TOKEN, "interface": "owned-tun", "family": 4, "index": 41,
                      "mtu": 1400, "identity": "captured-reader:41", "mode": ""}
        self.save()
        self.env = mock.patch.dict(os.environ, {"HOMEVPN_MTU_OWNER_HELPER": str(self.helper),
            "HOMEVPN_MTU_OWNER_TOKEN": TOKEN, "HOMEVPN_MTU_OWNER_URL": "http://127.0.0.1:34567/mtu",
            "HOMEVPN_MTU_MINIMUM": "576", "MTU_OWNER_FIXTURE": str(self.path)}, clear=False)
        self.env.start()
        for name in MOD.MTU_GRAPH_FIELDS:
            os.environ.pop(name, None)
        self.addCleanup(self.env.stop)
        self.addCleanup(self.directory.cleanup)

    def save(self):
        self.path.write_text(json.dumps(self.state))

    def calls(self):
        path = Path(str(self.path) + ".calls")
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_read_set_rollback_and_owned_reader_replacement(self):
        self.assertEqual(MOD.interface_mtu("owned-tun", 4), 1400)
        self.state["mode"] = "change-reader"
        self.save()
        MOD.set_interface_mtu("owned-tun", 4, 1320)
        after = MOD.owner_state("owned-tun", 4)
        self.assertEqual((after["index"], after["identity"], after["mtu"]), (42, "native-owned-reader:42", 1320))
        MOD.set_interface_mtu("owned-tun", 4, 1400)
        self.assertEqual(MOD.interface_mtu("owned-tun", 4), 1400)
        self.assertEqual([row for row in self.calls() if row[0] == "--mtu-owner-set"],
                         [["--mtu-owner-set", "1320"], ["--mtu-owner-set", "1400"]])

    def test_wrong_request_cannot_reach_mutation(self):
        for alias, family, value in [("replacement", 4, 1320), ("owned-tun", 6, 1320),
                                    ("owned-tun", 4, 575), ("owned-tun", 4, 9001),
                                    ("owned-tun", 4, True), ("owned-tun", 4, 1280.0)]:
            with self.subTest(alias=alias, family=family, value=value), self.assertRaises(RuntimeError):
                MOD.set_interface_mtu(alias, family, value)
        self.assertFalse(any(row[0] == "--mtu-owner-set" for row in self.calls()))
        self.assertEqual(json.loads(self.path.read_text())["mtu"], 1400)

    def test_untrusted_reply_shapes_and_owner_changes_rejected(self):
        cases = ["wrong-token", "wrong-interface", "wrong-family", "wrong-index", "string-number",
                 "float-number", "boolean-number", "empty-identity", "control-identity", "long-identity",
                 "unknown", "null", "duplicate", "escaped-duplicate", "array", "trailing", "oversized",
                 "invalid-utf8", "stderr", "exit-failure", "retired"]
        for mode in cases:
            with self.subTest(mode=mode):
                self.state["mode"] = mode
                self.save()
                with self.assertRaises(RuntimeError):
                    MOD.interface_mtu("owned-tun", 4)

    def test_failed_set_or_inexact_readback_is_not_success(self):
        for mode in ["set-fails", "set-wrong-readback", "retire-after-set"]:
            with self.subTest(mode=mode):
                self.state["mode"] = mode
                self.save()
                with self.assertRaises(RuntimeError):
                    MOD.set_interface_mtu("owned-tun", 4, 1320)

    def test_invalid_capability_never_spawns_helper(self):
        cases = [("HOMEVPN_MTU_OWNER_TOKEN", "b" * 31), ("HOMEVPN_MTU_OWNER_TOKEN", "A" * 32),
                 ("HOMEVPN_MTU_OWNER_URL", "http://localhost:1234/mtu"),
                 ("HOMEVPN_MTU_OWNER_URL", "https://127.0.0.1:1234/mtu"),
                 ("HOMEVPN_MTU_OWNER_URL", "http://127.0.0.1:65536/mtu"),
                 ("HOMEVPN_MTU_OWNER_URL", "http://127.0.0.1:1234/mtu?x=1"),
                 ("HOMEVPN_MTU_OWNER_URL", "http://x@127.0.0.1:1234/mtu"),
                 ("HOMEVPN_MTU_OWNER_HELPER", "relative-helper"),
                 ("HOMEVPN_MTU_MINIMUM", ""), ("HOMEVPN_MTU_MINIMUM", "575"),
                 ("HOMEVPN_MTU_MINIMUM", "1281"), ("HOMEVPN_MTU_MINIMUM", "1e3")]
        for key, value in cases:
            with self.subTest(key=key, value=value), mock.patch.dict(os.environ, {key: value}), self.assertRaises(RuntimeError):
                MOD.interface_mtu("owned-tun", 4)
        self.assertEqual(self.calls(), [])

    def test_native_floor_filters_candidates_and_rejects_lower_mutation(self):
        with mock.patch.dict(os.environ, {"HOMEVPN_MTU_MINIMUM": "1280"}):
            values = MOD.candidate_mtus(1400)
            self.assertIn(1280, values)
            self.assertEqual(values[0], 1400)
            self.assertTrue(all(value >= 1280 for value in values))
            with self.assertRaises(RuntimeError):
                MOD.set_interface_mtu("owned-tun", 4, 1200)
            self.assertFalse(any(row[0] == "--mtu-owner-set" for row in self.calls()))
            self.state["mtu"] = 1200
            self.save()
            with self.assertRaises(RuntimeError):
                MOD.interface_mtu("owned-tun", 4)

    def graph_environment(self):
        return {"HOMEVPN_MTU_GRAPH_TOKEN": "b" * 64, "HOMEVPN_MTU_GRAPH_SCOPE": "multihop-exit-path",
                "HOMEVPN_MTU_CONTROL_PROFILE_ID": "control", "HOMEVPN_MTU_PHYSICAL_ENTRY_ID": "entry",
                "HOMEVPN_MTU_PHYSICAL_ENTRY_ENDPOINT": "203.0.113.8", "HOMEVPN_PROFILE_ID": "exit"}

    def test_partial_or_malformed_graph_cannot_reach_owner(self):
        good = self.graph_environment()
        for missing in MOD.MTU_GRAPH_FIELDS:
            with self.subTest(missing=missing), mock.patch.dict(os.environ, good):
                os.environ.pop(missing)
                with self.assertRaisesRegex(RuntimeError, "captured MTU graph"):
                    MOD.interface_mtu("owned-tun", 4)
        cases = {"HOMEVPN_MTU_GRAPH_TOKEN": "B" * 64, "HOMEVPN_MTU_GRAPH_SCOPE": "entry-only",
                 "HOMEVPN_MTU_CONTROL_PROFILE_ID": "../control", "HOMEVPN_MTU_PHYSICAL_ENTRY_ID": "exit",
                 "HOMEVPN_MTU_PHYSICAL_ENTRY_ENDPOINT": "entry.example.invalid"}
        for name, value in cases.items():
            with self.subTest(name=name), mock.patch.dict(os.environ, dict(good, **{name: value})), self.assertRaises(RuntimeError):
                MOD.interface_mtu("owned-tun", 4)
        self.assertEqual(self.calls(), [])

    def test_graph_fingerprint_binds_physical_entry_and_exact_winner(self):
        environment = dict(self.graph_environment(), HOMEVPN_MODE="wg", HOMEVPN_IP_FAMILY="4")
        profile = {"id": "exit", "endpoint": "198.51.100.9"}
        with mock.patch.dict(os.environ, environment), mock.patch.object(MOD, "network_fingerprint", return_value="physical") as network, mock.patch.object(MOD, "generated_profile_fingerprint", return_value="exit-source"):
            first = MOD.path_context(profile, Path(self.directory.name))
            network.assert_called_with("203.0.113.8")
            os.environ["HOMEVPN_MTU_GRAPH_TOKEN"] = "c" * 64
            second = MOD.path_context(profile, Path(self.directory.name))
        self.assertNotEqual(first[0], second[0])
        self.assertNotEqual(first[2], second[2])

    def test_guard_uses_entry_and_control_but_exit_proof_owner_is_unchanged(self):
        root = Path(self.directory.name)
        store = {"selected_id": "control", "profiles": [
            {"id": "control", "endpoint": "192.0.2.7", "kill_switch_policy": "always", "home_lan_access": False},
            {"id": "entry", "endpoint": "203.0.113.8", "kill_switch_policy": "off"},
            {"id": "exit", "endpoint": "198.51.100.9", "kill_switch_policy": "off"}]}
        (root / "routers.json").write_text(json.dumps(store))
        environment = dict(self.graph_environment(), HOMEVPN_ROOT=str(root),
            HOMEVPN_NATIVE_ENDPOINTS_JSON='["198.51.100.111"]', HOMEVPN_NATIVE_EGRESS_JSON='[{"host":"198.51.100.111"}]',
            HOMEVPN_EXTERNAL_SESSION="d" * 32, HOMEVPN_NODE_SESSION="e" * 32)
        with mock.patch.dict(os.environ, environment):
            guard = MOD.mtu_kill_switch_environment()
            self.assertEqual((guard["HOMEVPN_PROFILE_ID"], guard["HOMEVPN_POLICY_PROFILE_ID"], guard["HOMEVPN_ENDPOINT"]),
                             ("entry", "control", "203.0.113.8"))
            self.assertEqual(os.environ["HOMEVPN_PROFILE_ID"], "exit")
            self.assertFalse(any(name.startswith(("HOMEVPN_MTU_", "HOMEVPN_NATIVE_", "HOMEVPN_NODE_")) for name in guard))
            self.assertNotIn("HOMEVPN_EXTERNAL_SESSION", guard)
            store["profiles"][1]["endpoint"] = "203.0.113.99"
            (root / "routers.json").write_text(json.dumps(store))
            with self.assertRaisesRegex(RuntimeError, "physical entry changed"):
                MOD.mtu_kill_switch_environment()

    def optimize_context(self):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(mock.patch.object(MOD, "root_dir", return_value=Path(self.directory.name)))
        stack.enter_context(mock.patch.object(MOD, "load_profile", return_value=({}, {"mtu_policy": "auto", "effective_mtu": 1400})))
        stack.enter_context(mock.patch.object(MOD, "prove_node"))
        stack.enter_context(mock.patch.object(MOD, "enforce_kill_switch"))
        stack.enter_context(mock.patch.object(MOD, "route_interface", return_value="owned-tun"))
        stack.enter_context(mock.patch.object(MOD, "candidate_mtus", return_value=[1400, 1320]))
        stack.enter_context(mock.patch.object(MOD.time, "sleep"))
        stack.enter_context(mock.patch.object(MOD, "measurement_context", return_value={"path_key": "captured"}))
        return stack

    def test_measure_restores_exact_owner_and_echoes_capability(self):
        def bench(_host, _port, _family, mtu):
            return {"mtu": mtu, "working": True, "success_ratio": 1, "mbps": 100 if mtu == 1320 else 70, "median_rtt_ms": 4}
        with self.optimize_context(), mock.patch.object(MOD, "bench_candidate", side_effect=bench), mock.patch.object(MOD, "persist") as persist:
            result = MOD.optimize(defer_adopt=True)
        self.assertEqual(result["owner_token"], TOKEN)
        self.assertEqual(result["winner"]["mtu"], 1320)
        self.assertFalse(result["adopted"])
        self.assertEqual(MOD.interface_mtu("owned-tun", 4), 1400)
        persist.assert_not_called()

    def test_retired_measurement_cannot_claim_successful_rollback(self):
        def bench(*_arguments):
            state = json.loads(self.path.read_text())
            state["mode"] = "retired"
            self.path.write_text(json.dumps(state))
            raise RuntimeError("measurement canceled after owner retirement")
        with self.optimize_context(), mock.patch.object(MOD, "bench_candidate", side_effect=bench), mock.patch.object(MOD, "persist") as persist:
            with self.assertRaisesRegex(RuntimeError, "rollback was not confirmed"):
                MOD.optimize(defer_adopt=True)
        persist.assert_not_called()
        self.assertEqual([row for row in self.calls() if row[0] == "--mtu-owner-set"], [["--mtu-owner-set", "1400"]])


if __name__ == "__main__":
    unittest.main()
