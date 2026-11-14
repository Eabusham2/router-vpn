#!/usr/bin/env python3
"""Strict CONNECT fifty gate controls; generated JSON here tests the parser only."""
from pathlib import Path
import importlib.util
import hashlib
import types
import json
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value

V = module("connect_fifty_gate_test", ROOT / "deploy/connect_ordered_fifty_native.py")
B = module("connect_fifty_trusted_parser_test", ROOT / "deploy/test_focused_socks_bridge.py")

def rows(mode, control=None):
    root, case = V.names(mode)
    data = [dict(Action="start", Package=B.LIBBOX)]
    data.extend(dict(Action="run", Package=B.LIBBOX, Test=x) for x in (root, case))
    outputs = [control["witness"]] if control else ["CONNECT_FIFTY_CHECK " + name for name in V.LEAVES]
    data.extend(dict(Action="output", Package=B.LIBBOX, Test=case, Output=x + "\n") for x in outputs)
    action = "fail" if control else "pass"
    data.extend(dict(Action=action, Package=B.LIBBOX, Test=x) for x in (case, root))
    data.append(dict(Action=action, Package=B.LIBBOX))
    return data

def encoded(data):
    return ("\n".join(json.dumps(x) for x in data) + "\n").encode()

class CONNECTFiftyGate(unittest.TestCase):
    def test_exact_six_protocol_and_prefix_combinations(self):
        self.assertEqual(V.MODES, tuple(protocol + "-" + mode for protocol in ("http", "https") for mode in ("wg", "awg2-fast", "awg2-strong")))
        for mode in V.MODES:
            self.assertTrue(V.events(B, encoded(rows(mode)), 0, mode)["accepted"])
        for foreign in ("wg", "socks-wg", "https-awg", ""):
            with self.assertRaises(ValueError):
                V.names(foreign)

    def test_missing_duplicate_reordered_failed_or_foreign_verdict_refused(self):
        mode = V.MODES[0]
        original = rows(mode)
        for data in (original[:-1], original + original, list(reversed(original)), [r for r in original if r.get("Output") != "CONNECT_FIFTY_CHECK copied-plan\n"], original[:3] + [original[3]] + original[3:]):
            with self.subTest(data=data), self.assertRaises(ValueError):
                V.events(B, encoded(data), 0, mode)
        for status in (1, -9, 124):
            with self.assertRaises(ValueError):
                V.events(B, encoded(original), status, mode)
        for suffix in (b"panic: failed\n", b"WARNING: DATA RACE\n", b"build failed\n"):
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                V.events(B, encoded(original) + suffix, 0, mode)

    def test_all_seven_controls_require_exact_failure_witness(self):
        self.assertEqual(len(V.CONTROLS), 7)
        for control in V.CONTROLS:
            raw = encoded(rows("http-wg", control))
            self.assertTrue(V.events(B, raw, 1, "http-wg", control)["accepted"])
            for status in (0, -9, 124):
                with self.assertRaises(ValueError):
                    V.events(B, raw, status, "http-wg", control)
            for bad in (raw.replace(control["witness"].encode(), b"unrelated"), raw + b"WARNING: DATA RACE\n", raw + b"panic: unrelated\n"):
                with self.assertRaises(ValueError):
                    V.events(B, bad, 1, "http-wg", control)

    def test_control_anchors_match_actual_current_source_once(self):
        paths = {
            "experimental/libbox/routervpn_node_chain_connect_latency.go": "mobile/chain/connect_latency.go.tmpl",
            "routervpn_node_chain_connect.go": "mobile/chain/connect_box.go.tmpl",
            "experimental/libbox/routervpn/hopmeasure/ordered_latency.go": "internal/hopmeasure/ordered_latency.go",
            "experimental/libbox/routervpn_ordered_latency.go": "mobile/chain/ordered_latency_bridge.go.tmpl",
        }
        for control in V.CONTROLS:
            source = (ROOT / paths[control["path"]]).read_text()
            self.assertNotEqual(V.mutation(B, control, source), source)
            for wrong in ("absent", source + source):
                with self.assertRaises(ValueError):
                    V.mutation(B, control, wrong)

    def test_every_mode_and_control_is_required_with_original_bounds_and_images(self):
        sources = {
            "experimental/libbox/routervpn_node_chain_connect_latency.go": "mobile/chain/connect_latency.go.tmpl",
            "routervpn_node_chain_connect.go": "mobile/chain/connect_box.go.tmpl",
            "experimental/libbox/routervpn/hopmeasure/ordered_latency.go": "internal/hopmeasure/ordered_latency.go",
            "experimental/libbox/routervpn_ordered_latency.go": "mobile/chain/ordered_latency_bridge.go.tmpl",
        }
        for fault in (None, "case-missing", "control-pass", "image-changed"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                native = work / "native"
                for projected, original in sources.items():
                    path = native / projected
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes((ROOT / original).read_bytes())
                peer, client = work / "peer", work / "client"
                peer.write_bytes(b"original peer"); client.write_bytes(b"original client")
                base = types.SimpleNamespace(COMMON=types.SimpleNamespace(image_identity=lambda p: hashlib.sha256(p.read_bytes()).hexdigest()), LIBBOX=B.LIBBOX, require_events=B.require_events, mutate=B.mutate)
                calls = []
                def run(name, command, cwd, bound, env):
                    calls.append(name)
                    self.assertEqual(cwd, native)
                    self.assertEqual(env["ROUTERVPN_CONNECT_RUN_PEER"], str(peer))
                    self.assertEqual(env["GODEBUG"], "x509usefallbackroots=1")
                    if name.startswith("fifty-http-") or name.startswith("fifty-https-"):
                        mode = name.removeprefix("fifty-")
                        self.assertEqual(env["ROUTERVPN_CONNECT_FIFTY_CASE"], mode)
                        self.assertEqual(bound, 190)
                        self.assertIn("-test.timeout=180s", command)
                        data = rows(mode)
                        if fault == "case-missing": data.pop()
                        if fault == "image-changed": peer.write_bytes(b"foreign")
                        return 0, encoded(data)
                    control = next(x for x in V.CONTROLS if x["name"] == name)
                    self.assertEqual(bound, 600)
                    self.assertIn("-timeout=180s", command)
                    overlay = json.loads(Path(next(x.split("=", 1)[1] for x in command if x.startswith("-overlay="))).read_text())["Replace"]
                    original = native / control["path"]
                    self.assertEqual(list(overlay), [str(original)])
                    self.assertEqual(Path(overlay[str(original)]).read_text(), V.mutation(B, control, original.read_text()))
                    return (0 if fault == "control-pass" else 1), encoded(rows("http-wg", control))
                if fault:
                    with self.assertRaises(ValueError):
                        V.validate_compiled(base, run, "captured-go", native, peer, client, work, ["-race", "-p=1"], {})
                else:
                    result = V.validate_compiled(base, run, "captured-go", native, peer, client, work, ["-race", "-p=1"], {})
                    self.assertEqual(calls, ["fifty-" + x for x in V.MODES] + [x["name"] for x in V.CONTROLS])
                    self.assertEqual(len(result["ordered_fifty_records"]), 6)
                    self.assertEqual(len(result["ordered_fifty_controls"]), 7)
                    self.assertFalse(result["ordered_fifty_host_persistence_accepted"])

    def test_each_projection_binds_both_original_maps_bytes_and_no_symlink(self):
        for number in range(len(V.PROJECTIONS)):
            for fault in (None, "map", "bytes", "symlink"):
                with self.subTest(number=number, fault=fault), tempfile.TemporaryDirectory() as directory:
                    source, native = Path(directory) / "source", Path(directory) / "native"
                    table, shared = {}, {}
                    for template, projection in V.PROJECTIONS:
                        a, b = source / "mobile/chain" / template, native / projection
                        a.parent.mkdir(parents=True, exist_ok=True)
                        b.parent.mkdir(parents=True, exist_ok=True)
                        a.write_text("original " + template)
                        b.write_bytes(a.read_bytes())
                        (shared if template == "ordered_latency_bridge.go.tmpl" else table)[template] = projection
                    template, projection = V.PROJECTIONS[number]
                    selected = shared if template == "ordered_latency_bridge.go.tmpl" else table
                    if fault == "map": selected.pop(template)
                    if fault == "bytes": (native / projection).write_text("foreign")
                    if fault == "symlink":
                        (native / projection).unlink()
                        (native / projection).symlink_to(source / "mobile/chain" / template)
                    if fault:
                        with self.assertRaises(ValueError): V.checked_projection(source, native, table, shared)
                    else: V.checked_projection(source, native, table, shared)

if __name__ == "__main__":
    unittest.main(verbosity=2)
