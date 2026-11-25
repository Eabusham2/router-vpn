#!/usr/bin/env python3
"""Required receipt and omission controls for ordered Darwin component tests."""
from pathlib import Path
import importlib.util
import json
import contextlib
import io
import os
import tempfile
from unittest.mock import patch
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
        for package, count in (("protocol/tun", 18), ("adapter/inbound", 12), ("cmd/sing-box", 261),
                               ("experimental/libbox/routervpn/mobilemultihop", 33),
                               ("routervpn/desktoppt", 7), (".", 81)):
            validator = RUNNER.receipt(package)
            cases = RUNNER.PHASES[package]
            output = "\n".join(json.dumps(row) for row in wire(package, cases))
            self.assertEqual(validator.require_pass(output, cases), count)
            self.assertEqual(validator.TEST_TIMEOUT, RUNNER.TEST_TIMEOUT)
            self.assertEqual(validator.PROCESS_TIMEOUT, RUNNER.PROCESS_TIMEOUT)
        self.assertEqual(RUNNER.TEST_TIMEOUT, "120s")
        self.assertEqual(RUNNER.PROCESS_TIMEOUT, 600)
        self.assertEqual(len(RUNNER.MUTATIONS), 47)

    def test_hysteria_final_layers_keep_actual_darwin_owner_and_every_factory_case(self):
        physical = RUNNER.load("ordered_physical_inventory", "test_desktop_node_physical.py")
        expected = {name for name in physical.ORDERED_PHYSICAL_VERDICTS
                    if name.startswith("TestRouterVPNDesktopNodeChainPhysicalHysteria")}
        captured = {name for root, leaves in RUNNER.PHASES["."].items()
                    if root.startswith("TestRouterVPNDesktopNodeChainPhysicalHysteria")
                    for name in (root, *(root + "/" + leaf for leaf in leaves))}
        self.assertEqual(captured, expected)
        self.assertEqual(len(captured), 53)
        fixture = (ROOT / "mobile/desktop/node_chain_box_physical_test.go.tmpl").read_text()
        self.assertIn('} else if runtime.GOOS == "darwin" {\n\t\t\t\tmethod = "RouterVPNDesktopDarwinNodeChainPreparePhysicalOwned"', fixture)
        self.assertEqual(RUNNER.COPIES["mobile/desktop/node_chain_box_darwin.go.tmpl"],
                         "routervpn_desktop_node_chain_box_darwin.go")

    def test_external_final_box_verdicts_match_linux_and_windows(self):
        physical = RUNNER.load("external_final_physical_inventory", "test_desktop_node_physical.py")
        root = physical.EXTERNAL_FINAL_PHYSICAL_ROOT
        leaves = RUNNER.PHASES["."][root]
        self.assertEqual((root, *(root + "/" + leaf for leaf in leaves)), physical.EXTERNAL_FINAL_PHYSICAL_SUITE[3])
        self.assertEqual(set(leaves), {"linux-home", "windows-custom", "darwin-home", "original", "final-key", "final-detour", "home-resolver", "physical-source"} |
                         {mode + "-" + case for mode in ("awg2-fast", "awg2-strong") for case in ("linux-home", "windows-custom", "darwin-home", "foreign-mode")})
        self.assertEqual(len(leaves), 16)
        for windows in (False, True):
            self.assertIn(physical.EXTERNAL_FINAL_PHYSICAL_SUITE, physical.baseline_suites(windows))

    def test_concrete_ready_policy_control_matches_current_source_and_real_foreign_capture(self):
        control, = [value for value in RUNNER.MUTATIONS if value[0] == "ordinary-darwin-policy"]
        source = (ROOT / "internal/mobilemultihop/desktop_node_ready.go").read_text()
        fixture = (ROOT / "internal/mobilemultihop/desktop_node_ready_darwin_chain_test.go").read_text()
        self.assertEqual(source.count(control[3]), 1)
        self.assertIn("case *DesktopNodePolicy:", control[3])
        for family in ("DesktopNodeChainPolicy", "DesktopNodeChainExecutionPhysicalPolicy", "DesktopNodeChainCONNECTExecutionPhysicalPolicy", "DesktopNodeChainSOCKSExecutionPhysicalPolicy"):
            self.assertIn("case *" + family + ":", control[3])
        self.assertEqual(control[4], 'interfaceValid = desktopNodeChainReadyInterface("darwin", r.InterfaceName)')
        self.assertEqual(control[5], "TestDesktopNodeReadyDarwinRequiresExactOrderedPolicy/ordinary-policy")
        self.assertIn(control[6], fixture)
        self.assertIn('desktopSOCKSPolicyFixture(t, "wg", "", "darwin", 1392)', fixture)
        self.assertIn("ReadDesktopPhysicalPolicy(typed)", fixture)
        self.assertIn("foreign.Validate(typed, transfer)", fixture)

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

    def test_execution_phase_retains_every_original_case_and_bound(self):
        cases = RUNNER.PHASES["cmd/sing-box"]
        original, execution = RUNNER.phase_groups("cmd/sing-box", cases)
        self.assertEqual(sum(1 + len(leaves) for leaves in original.values()), 170)
        self.assertEqual(sum(1 + len(leaves) for leaves in execution.values()), 91)
        self.assertFalse(set(original) & set(execution))
        self.assertEqual(dict(original, **execution), cases)
        self.assertEqual(RUNNER.TEST_TIMEOUT, "120s")
        for package, phase in RUNNER.PHASES.items():
            if package != "cmd/sing-box":
                self.assertEqual(RUNNER.phase_groups(package, phase), (phase,))
        for phase in (original, execution, {}):
            with self.assertRaises(ValueError):
                RUNNER.phase_groups("cmd/sing-box", phase)

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
        self.assertIn(label, diagnostic)
        self.assertIn("exact_runs=True", diagnostic)
        self.assertIn("exact_failures=True", diagnostic)
        self.assertIn("witness_message=False", diagnostic)
        self.assertNotIn(raw, diagnostic)


class DarwinLifecyclePhases(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="darwin-lifecycle-phases-")
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name).resolve()
        self.digest = "a" * 64
        self.calls = []

    def phase_receipt(self, phase):
        names = RUNNER.phase_inventory()[phase]
        return {"format": "routervpn-darwin-lifecycle-phase-v1", "phase": phase,
                "source_sha256": self.digest, "architecture": "amd64", "tags": "original-tags",
                "completed": list(names), "images": {name: "b" * 64 for name in names},
                "verdicts": ({package: sum(1 + len(leaves) for leaves in cases.values())
                              for package, cases in RUNNER.PHASES.items()} if phase == "baselines" else {})}

    def orchestrate(self, fault=None, target="baselines"):
        original = self.digest
        def child(command, *, env, timeout):
            self.assertEqual(timeout, 1800)
            self.assertEqual(env, {"GOARCH": "amd64", "original": "environment"})
            self.assertEqual(command[2:4], [self.source, "--tags=original-tags"])
            phase = command[5]
            self.assertEqual(phase, RUNNER.SOURCE_PHASES[len(self.calls)])
            self.assertEqual(command[4], "--phase")
            self.assertEqual(command[6], "--receipt")
            self.calls.append(phase)
            path = command[7]
            value = self.phase_receipt(phase)
            if phase == target:
                if fault == "failed-child": raise RuntimeError("original compiler/test failed")
                if fault == "missing-receipt": return "partial native output"
                if fault == "changed-source": self.digest = "c" * 64
                if fault == "source": value["source_sha256"] = "c" * 64
                if fault == "architecture": value["architecture"] = "arm64"
                if fault == "tags": value["tags"] = "foreign-tags"
                if fault == "phase": value["phase"] = "controls" if phase == "baselines" else "baselines"
                if fault == "missing": value["completed"].pop()
                if fault == "duplicate": value["completed"].append(value["completed"][0])
                if fault == "order": value["completed"].reverse()
                if fault == "missing-image": value["images"].pop(next(iter(value["images"])))
                if fault == "foreign-image": value["images"]["foreign"] = "b" * 64
                if fault == "bad-image": value["images"][next(iter(value["images"]))] = "invalid"
                if fault == "verdicts": value["verdicts"] = {"foreign": 1}
                if fault == "extra": value["extra"] = True
                if fault == "oversized": path.write_text(" " * 65537); return ""
                if fault == "symlink":
                    alternate = self.source / "foreign-receipt.json"
                    alternate.write_text(json.dumps(value))
                    path.symlink_to(alternate)
                    return ""
            path.write_text(json.dumps(value))
            return "phase completed"
        with patch.object(RUNNER, "checked_source", side_effect=lambda source, env: self.digest), contextlib.redirect_stdout(io.StringIO()):
            try:
                return RUNNER.execute_partitioned(self.source, "original-tags", {"GOARCH": "amd64", "original": "environment"}, child)
            finally:
                self.digest = original

    def test_all_serial_phases_are_mandatory_with_original_bounds(self):
        result = self.orchestrate()
        self.assertEqual([item["phase"] for item in result], ["baselines", "controls-1", "controls-2"])
        self.assertEqual(sum(result[0]["verdicts"].values()), 412)
        self.assertEqual(len(result[0]["images"]), 6)
        self.assertEqual([len(item["images"]) for item in result[1:]], [24, 23])
        self.assertEqual(result[1]["completed"] + result[2]["completed"], [m[0] for m in RUNNER.MUTATIONS])
        self.assertEqual(RUNNER.TEST_TIMEOUT, "120s")
        self.assertEqual(RUNNER.PROCESS_TIMEOUT, 600)

    def test_duplicate_control_label_cannot_cross_phase_boundary(self):
        controls = list(RUNNER.MUTATIONS)
        controls[-1] = (controls[0][0], *controls[-1][1:])
        with patch.object(RUNNER, "MUTATIONS", controls):
            with self.assertRaisesRegex(ValueError, "unique across all phases"):
                RUNNER.phase_inventory()

    def test_bad_or_incomplete_phase_cannot_certify_complete_lifecycle(self):
        faults = ("failed-child", "missing-receipt", "changed-source", "source", "architecture", "tags", "phase",
                  "missing", "duplicate", "order", "missing-image", "foreign-image", "bad-image", "verdicts", "extra", "oversized", "symlink")
        for phase in RUNNER.SOURCE_PHASES:
            for fault in faults:
                with self.subTest(phase=phase, fault=fault):
                    self.calls = []
                    with self.assertRaises((ValueError, RuntimeError)):
                        self.orchestrate(fault, phase)
                    self.assertEqual(self.calls, list(RUNNER.SOURCE_PHASES[:RUNNER.SOURCE_PHASES.index(phase) + 1]))

    def test_partial_invocation_cannot_publish_full_completion(self):
        for phase, path in (("unknown", None), ("baselines", None), ("controls", None), ("complete", self.source / "result.json")):
            with self.subTest(phase=phase), self.assertRaisesRegex(ValueError, "partial complete"):
                RUNNER.check(self.source, phase=phase, receipt_path=path)
        path = self.source / "result.json"
        path.write_text("original receipt")
        with self.assertRaisesRegex(ValueError, "fresh owned"):
            RUNNER.check(self.source, phase="controls", receipt_path=path)
        self.assertEqual(path.read_text(), "original receipt")

    def test_phase_writer_executes_exact_original_tests_and_restores_every_mutant(self):
        # Model compiler/process boundaries only. The actual check() traversal,
        # exact native event validator, mutation application and restoration run.
        before = self.source / "target.go"
        before.write_text("original")
        cases = {"TestOriginal": ("child",)}
        phases = {"protocol/tun": cases}
        mutation = ("omitted-owner", "protocol/tun", "target.go", "original", "defective", "TestOriginal/child", "original owner omitted")
        second = ("changed-owner", *mutation[1:4], "replacement", *mutation[5:])
        for phase in (*RUNNER.SOURCE_PHASES, "controls"):
            builds, runs = [], []
            destination = self.source / (phase + ".json")
            def compile_image(source, package, image, tags, env):
                builds.append(before.read_text())
                image.write_bytes(before.read_bytes())
            def execute(source, package, image, selection, env, failure=False):
                self.assertFalse(any(path != image for path in image.parent.glob("*.test")))
                runs.append((selection, failure))
                if failure:
                    rows = wire(package, cases)
                    rows.insert(-3, {"Package": "github.com/sagernet/sing-box/" + package, "Action": "output", "Test": "TestOriginal/child", "Output": "original owner omitted"})
                    for row in rows:
                        if row["Action"] == "pass": row["Action"] = "fail"
                    return 1, "\n".join(json.dumps(row) for row in rows)
                return 0, "\n".join(json.dumps(row) for row in wire(package, cases))
            validator = RUNNER.receipt("protocol/tun")
            validator.run = lambda *args, **kwargs: (0, "TestOriginal\n")
            with patch.object(RUNNER, "PHASES", phases), patch.object(RUNNER, "MUTATIONS", (mutation, second)), \
                 patch.object(RUNNER, "checked_source", return_value=self.digest), \
                 patch.object(RUNNER, "compile_image", side_effect=compile_image), \
                 patch.object(RUNNER, "execute", side_effect=execute), \
                 patch.object(RUNNER, "receipt", return_value=validator), \
                 patch.dict(os.environ, {"GOARCH": "amd64"}), contextlib.redirect_stdout(io.StringIO()):
                result = RUNNER.check(self.source, "original-tags", phase=phase, receipt_path=destination)
            self.assertEqual(result, json.loads(destination.read_text()))
            expected = {"baselines": ["original"], "controls-1": ["defective"],
                        "controls-2": ["replacement"], "controls": ["defective", "replacement"]}
            self.assertEqual(builds, expected[phase])
            self.assertEqual([failure for _, failure in runs], [phase != "baselines"] * len(builds))
            self.assertEqual(before.read_text(), "original")


if __name__ == "__main__":
    unittest.main()
