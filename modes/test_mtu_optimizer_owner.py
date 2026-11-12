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
        for name in (*MOD.MTU_GRAPH_FIELDS, "HOMEVPN_MTU_ORIGINAL_INTERFACE", "HOMEVPN_MTU_INTERFACE_POLICY"):
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


    def darwin_state(self):
        self.state.update(interface="utun991", index=991, identity="captured-reader:991",
                          original_interface="utun991", interface_policy="darwin-ordered-reader-v1",
                          mode="darwin-reader", sets=0)
        self.save()
        return {"HOMEVPN_MTU_ORIGINAL_INTERFACE": "utun991",
                "HOMEVPN_MTU_INTERFACE_POLICY": "darwin-ordered-reader-v1",
                "HOMEVPN_MTU_MINIMUM": "1280"}

    def helper_state(self):
        return json.loads(self.path.read_text())

    def set_calls(self):
        return [row for row in self.calls() if row[0] == "--mtu-owner-set"]

    @staticmethod
    def successful_benchmark(_host, _port, _family, mtu):
        return {"mtu": mtu, "working": True, "success_ratio": 1,
                "mbps": 100 if mtu == 1320 else 70, "median_rtt_ms": 4}

    def test_legacy_reply_and_result_keep_exact_six_field_protocol(self):
        reply = MOD.owner_state("owned-tun", 4)
        self.assertEqual(set(reply), {"owner_token", "interface", "family", "index", "mtu", "identity"})
        with self.optimize_context(), mock.patch.object(MOD, "bench_candidate", side_effect=self.successful_benchmark), mock.patch.object(MOD, "persist"):
            result = MOD.optimize(defer_adopt=True)
        self.assertEqual(result["interface"], "owned-tun")
        self.assertNotIn("original_interface", result)
        self.assertNotIn("interface_policy", result)
        for mode in ("scope-empty-extras", "scope-empty-original", "scope-empty-policy"):
            with self.subTest(mode=mode):
                self.state["mode"] = mode
                self.save()
                with self.assertRaises(RuntimeError):
                    MOD.owner_state("owned-tun", 4)

    def test_darwin_successor_uses_original_anchor_for_every_helper_operation(self):
        with mock.patch.dict(os.environ, self.darwin_state()):
            initial = MOD.owner_state("utun991", 4)
            self.assertEqual(set(initial), {"owner_token", "interface", "family", "index", "mtu", "identity",
                                            "original_interface", "interface_policy"})
            next_state = MOD.set_interface_mtu("utun991", 4, 1320)
            self.assertEqual((next_state["interface"], next_state["index"], next_state["mtu"]), ("utun992", 992, 1320))
            self.assertEqual(next_state["original_interface"], "utun991")
            self.assertEqual(MOD.owner_state("utun991", 4), next_state)
            before = list(self.calls())
            with self.assertRaises(RuntimeError):
                MOD.set_interface_mtu("utun992", 4, 1400)
            self.assertEqual(self.calls(), before, "the replacement name became a mutation capability")
            restored = MOD.set_interface_mtu("utun991", 4, 1400)
            self.assertEqual((restored["interface"], restored["mtu"]), ("utun993", 1400))
            self.assertEqual(restored["original_interface"], "utun991")
            self.assertEqual(restored["interface_policy"], "darwin-ordered-reader-v1")
        self.assertEqual(self.set_calls(), [["--mtu-owner-set", "1320"], ["--mtu-owner-set", "1400"]])
        self.assertTrue(all(row[0] in {"--mtu-owner-read", "--mtu-owner-set"} and "utun991" not in row
                            and "utun992" not in row and "utun993" not in row for row in self.calls()))

    def test_darwin_partial_or_malformed_environment_never_spawns_helper(self):
        good = self.darwin_state()
        cases = [
            ("missing-original", "", good["HOMEVPN_MTU_INTERFACE_POLICY"]),
            ("missing-policy", "utun991", ""),
            ("wrong-policy", "utun991", "darwin-any-interface"),
            ("fixed-original", "router-vpn", good["HOMEVPN_MTU_INTERFACE_POLICY"]),
            ("empty-number", "utun", good["HOMEVPN_MTU_INTERFACE_POLICY"]),
            ("upper-case", "UTUN991", good["HOMEVPN_MTU_INTERFACE_POLICY"]),
            ("unicode-number", "utun９９１", good["HOMEVPN_MTU_INTERFACE_POLICY"]),
            ("separator", "utun-991", good["HOMEVPN_MTU_INTERFACE_POLICY"]),
            ("whitespace", "utun991 ", good["HOMEVPN_MTU_INTERFACE_POLICY"]),
        ]
        for name, original, policy in cases:
            with self.subTest(name=name), mock.patch.dict(os.environ, dict(good,
                    HOMEVPN_MTU_ORIGINAL_INTERFACE=original, HOMEVPN_MTU_INTERFACE_POLICY=policy)):
                with self.assertRaises(RuntimeError):
                    MOD.set_interface_mtu("utun991", 4, 1320)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.helper_state()["mtu"], 1400)

    def test_darwin_foreign_origin_policy_and_malformed_reply_never_reach_set(self):
        environment = self.darwin_state()
        cases = ["scope-wrong-original", "scope-wrong-policy", "scope-missing-original",
                 "scope-missing-policy", "scope-missing-core", "scope-empty-extras", "scope-empty-original",
                 "scope-empty-policy", "scope-current-fixed", "scope-current-upper", "scope-current-unicode",
                 "scope-current-separator", "scope-current-empty-number", "wrong-token", "wrong-family",
                 "wrong-index", "unknown", "duplicate", "escaped-duplicate"]
        with mock.patch.dict(os.environ, environment):
            for mode in cases:
                with self.subTest(mode=mode):
                    self.state["mode"] = mode
                    self.save()
                    with self.assertRaises(RuntimeError):
                        MOD.set_interface_mtu("utun991", 4, 1320)
        self.assertEqual(self.set_calls(), [])
        self.assertEqual(self.helper_state()["mtu"], 1400)

    def test_darwin_reply_cannot_opt_in_without_original_environment(self):
        self.darwin_state()
        with self.assertRaises(RuntimeError):
            MOD.set_interface_mtu("utun991", 4, 1320)
        self.assertEqual(self.set_calls(), [])
        self.state.pop("original_interface")
        self.state.pop("interface_policy")
        self.save()
        self.assertEqual(MOD.owner_state("utun991", 4)["interface"], "utun991")
        with self.assertRaises(RuntimeError):
            MOD.set_interface_mtu("utun991", 4, 1320)
        self.assertEqual(self.set_calls(), [["--mtu-owner-set", "1320"]])
        self.assertEqual(self.helper_state()["interface"], "utun992",
                         "fixture must expose the actual rejected rename, not silently suppress it")

    def test_darwin_measurement_restores_and_reports_actual_final_interface(self):
        with mock.patch.dict(os.environ, self.darwin_state()), self.optimize_context(), \
                mock.patch.object(MOD, "route_interface", return_value="utun991"), \
                mock.patch.object(MOD, "bench_candidate", side_effect=self.successful_benchmark), \
                mock.patch.object(MOD, "persist") as persist:
            result = MOD.optimize(defer_adopt=True)
            actual = MOD.owner_state("utun991", 4)
        self.assertEqual((result["interface"], result["original_interface"], result["interface_policy"]),
                         ("utun993", "utun991", "darwin-ordered-reader-v1"))
        self.assertEqual((actual["interface"], actual["mtu"]), ("utun993", 1400))
        self.assertEqual(result["winner"]["mtu"], 1320)
        self.assertFalse(result["adopted"])
        self.assertEqual(self.set_calls(), [["--mtu-owner-set", value] for value in ("1400", "1320", "1320", "1400")])
        persist.assert_not_called()

    def test_darwin_direct_optimizer_persists_only_confirmed_current_interface(self):
        with mock.patch.dict(os.environ, self.darwin_state()), self.optimize_context(), \
                mock.patch.object(MOD, "route_interface", return_value="utun991"), \
                mock.patch.object(MOD, "bench_candidate", side_effect=self.successful_benchmark), \
                mock.patch.object(MOD, "persist") as persist:
            result = MOD.optimize(defer_adopt=False)
        self.assertEqual((result["interface"], result["original_interface"], result["winner"]["mtu"]),
                         ("utun992", "utun991", 1320))
        self.assertTrue(result["adopted"])
        self.assertEqual((self.helper_state()["interface"], self.helper_state()["mtu"]), ("utun992", 1320))
        persist.assert_called_once()

    def test_darwin_failed_final_read_is_inside_optimizer_rollback(self):
        environment = self.darwin_state()
        self.state.update(read_fault="scope-wrong-original", read_fault_after_sets=4)
        self.save()
        with mock.patch.dict(os.environ, environment), self.optimize_context(), \
                mock.patch.object(MOD, "route_interface", return_value="utun991"), \
                mock.patch.object(MOD, "bench_candidate", side_effect=self.successful_benchmark), \
                mock.patch.object(MOD, "persist") as persist:
            with self.assertRaisesRegex(RuntimeError, "owner or exact kernel readback changed"):
                MOD.optimize(defer_adopt=True)
        self.assertEqual(self.set_calls(), [["--mtu-owner-set", value] for value in ("1400", "1320", "1320", "1400", "1400")])
        self.assertEqual((self.helper_state()["interface"], self.helper_state()["mtu"]), ("utun993", 1400))
        persist.assert_not_called()

    def test_darwin_mid_measurement_failure_restores_original_anchor(self):
        def benchmark(*arguments):
            if arguments[-1] == 1320:
                raise RuntimeError("original ordered measurement was cancelled")
            return self.successful_benchmark(*arguments)
        with mock.patch.dict(os.environ, self.darwin_state()), self.optimize_context(), \
                mock.patch.object(MOD, "route_interface", return_value="utun991"), \
                mock.patch.object(MOD, "bench_candidate", side_effect=benchmark), \
                mock.patch.object(MOD, "persist") as persist:
            with self.assertRaisesRegex(RuntimeError, "original ordered measurement was cancelled"):
                MOD.optimize(defer_adopt=True)
        self.assertEqual((self.helper_state()["interface"], self.helper_state()["mtu"]), ("utun993", 1400))
        self.assertEqual(self.set_calls(), [["--mtu-owner-set", value] for value in ("1400", "1320", "1400")])
        persist.assert_not_called()

    def measured_darwin_state(self):
        environment = self.darwin_state()
        self.state.update(interface="utun993", index=993, identity="native-owned-reader:993", sets=4)
        self.save()
        return dict(environment, HOMEVPN_MTU_APPLY_INTERFACE="utun993", HOMEVPN_MTU_APPLY_FAMILY="4",
                    HOMEVPN_MTU_APPLY_VALUE="1320", HOMEVPN_MTU_EXPECTED_PATH_KEY="captured")

    def test_darwin_apply_and_rollback_bind_measured_current_but_write_original_anchor(self):
        environment = self.measured_darwin_state()
        with mock.patch.dict(os.environ, environment), self.optimize_context(), \
                mock.patch.object(MOD, "route_interface", return_value="utun993") as route:
            applied = MOD.apply_measured_result()
            self.assertEqual((applied["interface"], applied["original_interface"], applied["applied_mtu"]),
                             ("utun994", "utun991", 1320))
            self.assertEqual(applied["interface_policy"], "darwin-ordered-reader-v1")
            self.assertFalse(applied["rollback"])
            route.assert_called_once_with("10.77.0.1")
            os.environ["HOMEVPN_MTU_APPLY_INTERFACE"] = applied["interface"]
            os.environ["HOMEVPN_MTU_APPLY_VALUE"] = "1400"
            restored = MOD.apply_measured_result(rollback=True)
        self.assertEqual((restored["interface"], restored["original_interface"], restored["applied_mtu"]),
                         ("utun995", "utun991", 1400))
        self.assertTrue(restored["rollback"])
        self.assertEqual(self.set_calls(), [["--mtu-owner-set", "1320"], ["--mtu-owner-set", "1400"]])

    def test_darwin_apply_rejects_changed_current_interface_before_mutation(self):
        for phase in ("adopt", "rollback"):
            with self.subTest(phase=phase):
                environment = self.measured_darwin_state()
                environment["HOMEVPN_MTU_APPLY_INTERFACE"] = "utun992"
                before = list(self.set_calls())
                with mock.patch.dict(os.environ, environment), self.optimize_context(), \
                        mock.patch.object(MOD, "route_interface", return_value="utun993"):
                    with self.assertRaisesRegex(RuntimeError, "measured MTU interface changed"):
                        MOD.apply_measured_result(rollback=phase == "rollback")
                self.assertEqual(self.set_calls(), before)
                self.assertEqual((self.helper_state()["interface"], self.helper_state()["mtu"]), ("utun993", 1400))

    def test_darwin_apply_route_uses_actual_current_not_original_name(self):
        with mock.patch.dict(os.environ, self.measured_darwin_state()), self.optimize_context(), \
                mock.patch.object(MOD, "route_interface", return_value="utun991"):
            with self.assertRaisesRegex(RuntimeError, "active MTU path interface changed"):
                MOD.apply_measured_result()
        self.assertEqual(self.set_calls(), [])

    def test_darwin_failed_adoption_proof_restores_via_same_original_anchor(self):
        environment = self.measured_darwin_state()
        with mock.patch.dict(os.environ, environment), self.optimize_context(), \
                mock.patch.object(MOD, "route_interface", return_value="utun993"), \
                mock.patch.object(MOD, "prove_node", side_effect=[None, RuntimeError("original proof retired after adoption")]):
            with self.assertRaisesRegex(RuntimeError, "original proof retired after adoption"):
                MOD.apply_measured_result()
        self.assertEqual((self.helper_state()["interface"], self.helper_state()["mtu"]), ("utun995", 1400))
        self.assertEqual(self.set_calls(), [["--mtu-owner-set", "1320"], ["--mtu-owner-set", "1400"]])

    def test_darwin_failed_adoption_final_read_also_restores_original_anchor(self):
        environment = self.measured_darwin_state()
        self.state.update(read_fault="scope-wrong-original", read_fault_after_sets=5)
        self.save()
        with mock.patch.dict(os.environ, environment), self.optimize_context(), \
                mock.patch.object(MOD, "route_interface", return_value="utun993"):
            with self.assertRaisesRegex(RuntimeError, "owner or exact kernel readback changed"):
                MOD.apply_measured_result()
        self.assertEqual((self.helper_state()["interface"], self.helper_state()["mtu"]), ("utun995", 1400))
        self.assertEqual(self.set_calls(), [["--mtu-owner-set", "1320"], ["--mtu-owner-set", "1400"]])


if __name__ == "__main__":
    unittest.main()
