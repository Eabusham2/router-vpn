#!/usr/bin/env python3
"""Offline checks of the actual Unix imported-entry tuple policy adapter."""
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("imported_guard", Path(__file__).with_name("kill-switch.py"))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class ImportedPhysicalPolicy(unittest.TestCase):
    def environment(self):
        return {
            "HOMEVPN_STANDARD_ENGINE": "native",
            "HOMEVPN_NODE_SESSION": "a" * 32,
            "HOMEVPN_NODE_CONFIG_SHA256": "b" * 64,
            "HOMEVPN_NODE_PHYSICAL_REQUIRED": "1",
            "HOMEVPN_NATIVE_ENDPOINTS_JSON": '["198.51.100.20"]',
            "HOMEVPN_NATIVE_EGRESS_JSON": '[{"host":"198.51.100.20","port":8389,"network":"tcp"}]',
        }

    def test_exact_outer_socket_and_retained_policy(self):
        with mock.patch.dict(os.environ, self.environment(), clear=True), mock.patch("socket.getaddrinfo") as dns:
            addresses = guard.captured_endpoint_ips("198.51.100.20")
            tuples = guard.captured_native_egress(addresses)
            rules = guard.render_rules(addresses, False, False, native_egress=tuples)
            self.assertIn("tcp dport 8389", rules)
            self.assertNotIn("ip daddr { 198.51.100.20 } accept", rules)
            self.assertNotIn("ip daddr 198.51.100.20 udp dport", rules)
            self.assertIn("policy drop", rules)
            self.assertEqual(guard.retained_native_policy({"endpoint":"198.51.100.20", "endpoint_ips":["198.51.100.20"], "native_egress":tuples}, "198.51.100.20"), (addresses, tuples))
            dns.assert_not_called()

    def test_missing_or_foreign_session_never_opens_all_ports(self):
        for key, value in (("HOMEVPN_NODE_SESSION", ""), ("HOMEVPN_NODE_SESSION", "A"*32),
                           ("HOMEVPN_NODE_CONFIG_SHA256", ""), ("HOMEVPN_NODE_CONFIG_SHA256", "f"*63),
                           ("HOMEVPN_NODE_PHYSICAL_REQUIRED", ""), ("HOMEVPN_NODE_PHYSICAL_REQUIRED", "0"),
                           ("HOMEVPN_EXTERNAL_SESSION", "c"*32), ("HOMEVPN_STANDARD_ENGINE", "sing-box")):
            with self.subTest(key=key, value=value):
                env = self.environment()
                env[key] = value
                with mock.patch.dict(os.environ, env, clear=True):
                    with self.assertRaises(RuntimeError):
                        guard.captured_endpoint_ips("198.51.100.20")

    def test_missing_endpoints_or_tuples_cannot_downgrade(self):
        for key in ("HOMEVPN_NATIVE_ENDPOINTS_JSON", "HOMEVPN_NATIVE_EGRESS_JSON"):
            with self.subTest(key=key):
                env = self.environment()
                del env[key]
                with mock.patch.dict(os.environ, env, clear=True):
                    with self.assertRaises(RuntimeError):
                        guard.captured_native_egress(guard.captured_endpoint_ips("198.51.100.20"))

    def test_inner_final_or_unbounded_tuple_is_rejected(self):
        for change in (dict(host="203.0.113.99"), dict(port=0), dict(port=True), dict(network="any")):
            with self.subTest(change=change):
                env = self.environment()
                tuple_ = dict(host="198.51.100.20", port=8389, network="tcp")
                tuple_.update(change)
                env["HOMEVPN_NATIVE_EGRESS_JSON"] = json.dumps([tuple_])
                with mock.patch.dict(os.environ, env, clear=True):
                    with self.assertRaises(RuntimeError):
                        guard.captured_native_egress(guard.captured_endpoint_ips("198.51.100.20"))


if __name__ == "__main__":
    unittest.main()
