#!/usr/bin/env python3
"""Run shipping MTU probes with explicit native-owner and socket boundaries.

HTTP parsing, proof validation and packet accounting are the real consumers.
These portable controls do not claim execution of XNU or a physical tunnel.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mtu_darwin_probes", ROOT / "modes/mtu-throughput-tuner.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class ReplyStream(io.BytesIO):
    def __init__(self, fixture, raw):
        super().__init__(raw)
        self.fixture = fixture

    def read(self, size=-1):
        value = super().read(size)
        if self.fixture.body_read:
            self.fixture.body_read()
        return value


class ProbeSocket:
    def __init__(self, fixture, family, kind):
        self.fixture, self.family, self.type = fixture, family, kind
        self.options, self.echoes, self.requests = {}, [], []
        self.connected, self.closed = False, False
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, *_error):
        self.close()

    def close(self):
        self.closed = True

    def settimeout(self, value):
        self.timeout = value

    def setsockopt(self, level, option, value):
        if self.fixture.bind_error:
            raise OSError("native interface bind refused")
        self.options[level, option] = value

    def getsockopt(self, level, option):
        return self.fixture.readback if self.fixture.readback is not None else self.options.get((level, option), 0)

    def connect(self, address):
        self.connected = True
        self.fixture.connections.append((self.family, self.type, address, dict(self.options)))
        if self.fixture.connected:
            self.fixture.connected()

    def sendall(self, data):
        if not self.connected:
            raise OSError("unconnected HTTP fixture")
        self.requests.append(bytes(data))

    def makefile(self, mode):
        if mode != "rb":
            raise AssertionError("unexpected HTTP stream mode")
        body = self.fixture.body
        raw = (f"HTTP/1.1 {self.fixture.status} fixture\r\nContent-Length: {len(body)}\r\n"
               "Location: http://192.168.50.133:8787/health\r\nConnection: close\r\n\r\n").encode() + body
        return ReplyStream(self.fixture, raw)

    def send(self, data):
        self.echoes.append(bytes(data))
        return len(data)

    def recv(self, _size):
        self.fixture.clock += 0.005
        self.fixture.receives += 1
        if self.fixture.received:
            self.fixture.received()
        if self.fixture.receive_error:
            raise OSError("native receive refused")
        if not self.echoes:
            raise socket.timeout("no queued echo")
        return self.echoes.pop(0)


class DarwinMTUProbeTests(unittest.TestCase):
    def setUp(self):
        self.state = {"owner_token": "a" * 32, "interface": "utun71", "family": 4,
                      "index": 71, "mtu": 1280, "identity": "original/path/1",
                      "original_interface": "utun70", "interface_policy": "darwin-ordered-reader-v1"}
        self.profile = {"node_proof_id": "b" * 64, "path_probe_url": "http://10.77.0.1:8787/health",
                        "daita_host": "10.77.0.1"}
        self.body = json.dumps({"ok": True, "node_id": "b" * 64, "proof": MOD.PROOF_KIND}).encode()
        self.status = 200
        self.body_read = self.received = self.connected = None
        self.receive_error = self.bind_error = False
        self.readback = None
        self.retired = False
        self.clock = 1.0
        self.receives = 0
        self.owner_reads, self.sockets, self.connections = [], [], []
        patches = [
            mock.patch.dict(os.environ, {"HOMEVPN_MTU_ORIGINAL_INTERFACE": "utun70",
                "HOMEVPN_MTU_INTERFACE_POLICY": "darwin-ordered-reader-v1", "HOMEVPN_MTU_BENCH_FAKE": ""}),
            mock.patch.object(MOD.platform, "system", return_value="Darwin"),
            mock.patch.object(MOD, "owner_state", side_effect=self.read_owner),
            mock.patch.object(MOD.socket, "socket", side_effect=self.new_socket),
            mock.patch.object(MOD.time, "monotonic", side_effect=lambda: self.clock),
            mock.patch.object(MOD, "route_interface", side_effect=AssertionError("ambient route used despite original capability")),
            mock.patch.object(MOD.urllib.request, "build_opener", side_effect=AssertionError("ambient HTTP opener reached")),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def read_owner(self, alias, family, *_value):
        self.owner_reads.append((alias, family))
        self.clock += 0.25  # Native checks must not inflate RTT or throughput.
        if self.retired:
            raise RuntimeError("captured MTU operation was rejected")
        if alias != "utun70" or family != self.state["family"]:
            raise RuntimeError("foreign operation request")
        return dict(self.state)

    def new_socket(self, family, kind, *_args, **_kwargs):
        value = ProbeSocket(self, family, kind)
        self.sockets.append(value)
        return value

    def assert_bound(self, family, kind, index=71):
        expected = {(socket.IPPROTO_IPV6, 125): index} if family == 6 else {(socket.IPPROTO_IP, 25): index}
        af = socket.AF_INET6 if family == 6 else socket.AF_INET
        self.assertEqual(len(self.connections), 1)
        self.assertEqual(self.connections[0][:2], (af, kind))
        self.assertEqual(self.connections[0][3], expected)
        self.assertTrue(all(value.closed for value in self.sockets))
        self.assertTrue(all(alias == "utun70" for alias, _family in self.owner_reads))

    def test_private_http_proof_uses_original_bound_ipv4_and_ipv6(self):
        for family, host in ((4, "10.77.0.1"), (6, "fd77::1")):
            with self.subTest(family=family):
                self.state["family"] = family
                self.profile.update(daita_host=host, path_probe_url=f"http://{'[' + host + ']' if family == 6 else host}:8787/health")
                self.connections.clear()
                MOD.prove_node(self.profile)
                self.assert_bound(family, socket.SOCK_STREAM)
                self.assertIn(b"GET /health HTTP/1.1", self.sockets[-1].requests[0])

    def test_proof_transport_family_does_not_replace_benchmark_owner_family(self):
        self.profile["path_probe_url"] = "http://[fd77::1]:8787/health"
        MOD.prove_node(self.profile)
        self.assert_bound(6, socket.SOCK_STREAM)
        self.assertTrue(all(family == 4 for _alias, family in self.owner_reads))

    def test_binding_failure_or_wrong_readback_cannot_reach_home_lan_answer(self):
        for case in ("bind", "readback"):
            for probe in ("proof", "benchmark"):
                with self.subTest(case=case, probe=probe):
                    self.bind_error = case == "bind"
                    self.readback = 19 if case == "readback" else None
                    with self.assertRaises((RuntimeError, OSError)):
                        MOD.prove_node(self.profile) if probe == "proof" else MOD.bench_candidate("10.77.0.1", 45999, 4, 1280)
                    self.assertEqual(self.connections, [])
                    self.assertTrue(all(value.closed for value in self.sockets))

    def test_foreign_or_retired_owner_cannot_open_probe_socket(self):
        for case in ("non-tunnel", "retired"):
            with self.subTest(case=case):
                self.state["interface"] = "en0" if case == "non-tunnel" else "utun71"
                self.retired = case == "retired"
                with self.assertRaises(RuntimeError):
                    MOD.prove_node(self.profile)
                self.assertEqual(self.sockets, [])

    def test_valid_http_body_from_replaced_reader_is_rejected_and_closed(self):
        for field, value in (("identity", "original/path/2"), ("index", 72), ("interface", "utun72"),
                             ("mtu", 1320), ("owner_token", "c" * 32)):
            with self.subTest(field=field):
                previous = self.state[field]
                self.body_read = lambda: self.state.update({field: value})
                with self.assertRaisesRegex(RuntimeError, "probe reader changed"):
                    MOD.prove_node(self.profile)
                self.assertTrue(self.sockets[-1].closed)
                self.state[field] = previous

    def test_redirect_wrong_identity_and_oversized_proof_are_not_success(self):
        original = self.body
        for status, body in ((302, original), (200, original.replace(b"b" * 64, b"c" * 64)),
                             (200, b"x" * (16 * 1024 + 1))):
            with self.subTest(status=status, length=len(body)):
                self.status, self.body = status, body
                before = len(self.connections)
                with self.assertRaises(RuntimeError):
                    MOD.prove_node(self.profile)
                self.assertEqual(len(self.connections), before + 1, "a redirect opened a replacement connection")
                self.assertTrue(self.sockets[-1].closed)

    def test_invalid_port_and_scoped_address_cannot_change_bound_destination(self):
        for url in ("http://10.77.0.1:0/health", "http://[fe80::1%en0]:8787/health"):
            with self.subTest(url=url), self.assertRaises(RuntimeError):
                MOD.prove_node(dict(self.profile, path_probe_url=url))
        self.assertEqual(self.connections, [])

    def test_udp_measurement_uses_exact_ipv4_and_ipv6_candidate_without_owner_time(self):
        for family, host in ((4, "10.77.0.1"), (6, "fd77::1")):
            with self.subTest(family=family):
                self.state["family"] = family
                self.connections.clear()
                result = MOD.bench_candidate(host, 45999, family, 1280)
                self.assertTrue(result["working"])
                self.assertEqual(result["success_ratio"], 1.0)
                self.assertEqual(result["median_rtt_ms"], 5.0)
                expected = round(2 * MOD.packet_payload_size(1280, family) * 8 / 0.005 / 1_000_000, 3)
                self.assertEqual(result["mbps"], expected)
                self.assert_bound(family, socket.SOCK_DGRAM)

    def test_udp_reader_change_and_retirement_even_after_receive_error_reject_whole_candidate(self):
        for phase in (1, MOD.RTT_SAMPLES + 1, MOD.RTT_SAMPLES + MOD.BURST_PACKETS * MOD.BURST_ROUNDS):
            for retire in (False, True):
                with self.subTest(phase=phase, retire=retire):
                    self.receives, self.retired, self.receive_error = 0, False, False
                    self.state["identity"] = "original/path/1"
                    def change():
                        if self.receives == phase:
                            if retire:
                                self.retired = self.receive_error = True
                            else:
                                self.state["identity"] = "original/path/2"
                    self.received = change
                    with self.assertRaises(RuntimeError):
                        MOD.bench_candidate("10.77.0.1", 45999, 4, 1280)
                    self.assertTrue(self.sockets[-1].closed)

    def test_new_candidate_can_capture_only_authenticated_successor_not_retarget_old_socket(self):
        old = MOD.capture_darwin_probe_owner("10.77.0.1", 4)
        self.state.update(interface="utun72", index=72, identity="original/path/2", mtu=1320)
        with self.assertRaisesRegex(RuntimeError, "probe reader changed"):
            old.validate()
        result = MOD.bench_candidate("10.77.0.1", 45999, 4, 1320)
        self.assertTrue(result["working"])
        self.assert_bound(4, socket.SOCK_DGRAM, index=72)

    def test_wrong_candidate_or_family_and_algorithm_fixture_cannot_return_native_measurement(self):
        for host, family, mtu in (("10.77.0.1", 4, 1320), ("fd77::1", 4, 1280), ("8.8.8.8", 4, 1280)):
            with self.subTest(host=host, family=family, mtu=mtu), self.assertRaises(RuntimeError):
                MOD.bench_candidate(host, 45999, family, mtu)
        with mock.patch.dict(os.environ, {"HOMEVPN_MTU_BENCH_FAKE": '{"1280":{"mbps":100}}'}), self.assertRaises(RuntimeError):
            MOD.bench_candidate("10.77.0.1", 45999, 4, 1280)
        self.assertEqual(self.sockets, [])


if __name__ == "__main__":
    unittest.main()
