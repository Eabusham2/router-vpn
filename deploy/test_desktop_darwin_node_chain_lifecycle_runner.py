#!/usr/bin/env python3
"""Required receipt and omission controls for ordered Darwin component tests."""
from pathlib import Path
import importlib.util
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("darwin_lifecycle_runner", ROOT / "deploy/test_desktop_darwin_node_chain_lifecycle.py")
RUNNER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RUNNER)


def wire(package, cases):
    name = "github.com/sagernet/sing-box" + ("/" + package if package != "." else "")
    rows = [{"Package": name, "Action": "start"}]
    for root, leaves in cases.items():
        rows.append({"Package": name, "Test": root, "Action": "run"})
        for leaf in leaves:
            for action in ("run", "pass"):
                rows.append({"Package": name, "Test": root + "/" + leaf, "Action": action})
        rows.append({"Package": name, "Test": root, "Action": "pass"})
    rows.append({"Package": name, "Action": "pass"})
    return rows


class DarwinLifecycleRunnerTests(unittest.TestCase):
    def test_exact_required_inventory_and_bounds(self):
        for package, count in (("protocol/tun", 18), ("adapter/inbound", 12), ("cmd/sing-box", 170),
                               ("experimental/libbox/routervpn/mobilemultihop", 33),
                               ("routervpn/desktoppt", 7), (".", 11)):
            validator = RUNNER.receipt(package)
            cases = RUNNER.PHASES[package]
            output = "\n".join(json.dumps(row) for row in wire(package, cases))
            self.assertEqual(validator.require_pass(output, cases), count)
            self.assertEqual(validator.TEST_TIMEOUT, RUNNER.TEST_TIMEOUT)
            self.assertEqual(validator.PROCESS_TIMEOUT, RUNNER.PROCESS_TIMEOUT)
        self.assertEqual(RUNNER.TEST_TIMEOUT, "120s")
        self.assertEqual(RUNNER.PROCESS_TIMEOUT, 600)
        self.assertEqual(len(RUNNER.MUTATIONS), 33)

    def test_each_measurement_mailbox_has_original_refusal_and_causal_omission(self):
        cases = RUNNER.PHASES["cmd/sing-box"]["TestRouterVPNNodeChainDarwinMeasurementStartup"]
        self.assertEqual(set(cases), {"absent"} | {
            name + "-" + kind for name in ("request", "cancel", "result")
            for kind in ("regular", "directory", "symlink")})
        source = (ROOT / "mobile/desktop/node_chain_control_darwin_test.go.tmpl").read_text()
        self.assertIn("err := routerVPNRunDarwinNodeChain(context.Background(), control)", source)
        selected = [control for control in RUNNER.MUTATIONS if control[0].startswith("preexisting-measurement-")]
        self.assertEqual(len(selected), 3)
        for name in ("request", "cancel", "result"):
            control, = [control for control in selected if control[0] == "preexisting-measurement-" + name]
            self.assertIn('"node-chain-measure-' + name + '.json"', control[3])
            self.assertEqual(control[5], "TestRouterVPNNodeChainDarwinMeasurementStartup/" + name + "-regular")

    def test_prefix_phase_keeps_original_lifecycle_and_distinct_native_source(self):
        cases = RUNNER.PHASES["cmd/sing-box"]
        prefix = {name: leaves for name, leaves in cases.items() if name.startswith("TestRouterVPNNodeCandidatePrefixDarwin")}
        self.assertEqual(len(prefix), 8)
        self.assertEqual(sum(1 + len(leaves) for leaves in prefix.values()), 76)
        self.assertEqual(cases["TestRouterVPNNodeChainDarwinNativeRetirementOrder"], (
            "exact-order", "proof-retry", "tun-retry", "source-retry", "ambiguous-box",
            "cancel-after-source", "missing-manager", "partial-components", "middle-before-cancel", "middle-retained", "startup-before-native"))
        self.assertEqual(prefix["TestRouterVPNNodeCandidatePrefixDarwinRuntimeClosedFifty"], ())
        for name in ("command", "dispatch", "control_darwin", "run_darwin", "retirement_darwin", "runtime", "measurement"):
            relative = "mobile/desktop/node_candidate_prefix_" + name + ".go.tmpl"
            self.assertEqual(RUNNER.COPIES[relative], "cmd/sing-box/routervpn_node_candidate_prefix_" + name + ".go")
        self.assertEqual(RUNNER.COPIES["internal/macosprocess/candidate_prefix_transfer.go"], "routervpn/macosprocess/candidate_prefix_transfer.go")

    def test_prefix_mailbox_refusals_have_causal_original_run_witnesses(self):
        cases = RUNNER.PHASES["cmd/sing-box"]["TestRouterVPNNodeCandidatePrefixDarwinMeasurementStartup"]
        self.assertEqual(set(cases), {"absent"} | {
            name + "-" + kind for name in ("request", "live", "cancel", "result")
            for kind in ("regular", "directory", "symlink")})
        source = (ROOT / "mobile/desktop/node_candidate_prefix_control_darwin_test.go.tmpl").read_text()
        self.assertIn("err := routerVPNRunDarwinNodeCandidatePrefix(context.Background(), control)", source)
        controls = [control for control in RUNNER.MUTATIONS if control[0].startswith("prefix-")]
        self.assertEqual(len(controls), 10)
        for name in ("request", "live", "cancel", "result"):
            control, = [control for control in controls if control[0] == "prefix-preexisting-" + name]
            self.assertIn('"node-candidate-prefix-' + name + '.json"', control[3])
            self.assertEqual(control[5], "TestRouterVPNNodeCandidatePrefixDarwinMeasurementStartup/" + name + "-regular")

    def test_missing_original_run_and_package_receipt(self):
        for package, cases in RUNNER.PHASES.items():
            rows = wire(package, cases)
            for changed in (rows[1:], rows[:-1], [r for r in rows if r["Action"] != "run"],
                            [*rows, rows[-1]], [*rows, {"Package": "foreign", "Action": "pass"}]):
                with self.assertRaises(ValueError):
                    RUNNER.receipt(package).require_pass("\n".join(json.dumps(r) for r in changed), cases)

    def test_phase_cannot_substitute_for_other_original(self):
        first, second = list(RUNNER.PHASES)[:2]
        output = "\n".join(json.dumps(row) for row in wire(first, RUNNER.PHASES[first]))
        with self.assertRaises(ValueError):
            RUNNER.receipt(second).require_pass(output, RUNNER.PHASES[second])
        with self.assertRaises(ValueError):
            RUNNER.receipt(first).require_pass(output, RUNNER.PHASES[second])

    def test_compiled_roots_are_exact(self):
        for cases in RUNNER.PHASES.values():
            roots = list(cases)
            RUNNER.discover("\n".join(roots), cases)
            for changed in (roots[:-1], [*roots, roots[0]], [*roots[:-1], "TestForeign"]):
                with self.assertRaises(ValueError):
                    RUNNER.discover("\n".join(changed), cases)

    def test_every_control_names_actual_shipping_boundary(self):
        original_by_target = {target: ROOT / source for source, target in RUNNER.COPIES.items()}
        for label, _, target, before, after, _, _ in RUNNER.MUTATIONS:
            self.assertIn(target, original_by_target, label)
            source = original_by_target[target].read_text()
            self.assertEqual(source.count(before), 1, label)
            self.assertNotEqual(before, after, label)

    def test_every_control_requires_exact_runtime_witness(self):
        for label, package, _, _, _, witness, message in RUNNER.MUTATIONS:
            validator = RUNNER.receipt(package)
            root = witness.split("/")[0]
            rows = [
                {"Action": "start"}, {"Action": "run", "Test": root},
                {"Action": "run", "Test": witness},
                {"Action": "output", "Test": witness, "Output": message},
                {"Action": "fail", "Test": witness}, {"Action": "fail", "Test": root},
                {"Action": "fail"},
            ]
            output = "\n".join(json.dumps({"Package": validator.PACKAGE, **row}) for row in rows)
            RUNNER.require_control(label, package, 1, output, witness, message)
            for code, changed in ((0, output), (2, output), (1, "compile failed"),
                                  (1, output.replace(message, "unrelated failure")),
                                  (1, "\n".join(output.splitlines()[:-1]))):
                with self.assertRaises(ValueError) as rejected:
                    RUNNER.require_control(label, package, code, changed, witness, message)
                self.assertIn("Darwin lifecycle causal control failed: " + label, str(rejected.exception))

    def test_wrong_witness_diagnostic_preserves_rejection_without_native_output(self):
        label, package, _, _, _, witness, message = RUNNER.MUTATIONS[0]
        validator = RUNNER.receipt(package)
        root = witness.split("/")[0]
        raw = "private-runtime-detail-must-not-be-logged"
        rows = [
            {"Action": "start"}, {"Action": "run", "Test": root},
            {"Action": "run", "Test": witness},
            {"Action": "output", "Test": witness, "Output": raw},
            {"Action": "fail", "Test": witness}, {"Action": "fail", "Test": root},
            {"Action": "fail"},
        ]
        output = "\n".join(json.dumps({"Package": validator.PACKAGE, **row}) for row in rows)
        with self.assertRaises(ValueError) as rejected:
            RUNNER.require_control(label, package, 1, output, witness, message)
        diagnostic = str(rejected.exception)
        self.assertIn("repeat-stack", diagnostic)
        self.assertIn("exact_runs=True", diagnostic)
        self.assertIn("exact_failures=True", diagnostic)
        self.assertIn("witness_message=False", diagnostic)
        self.assertNotIn(raw, diagnostic)


if __name__ == "__main__":
    unittest.main()
