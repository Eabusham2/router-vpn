#!/usr/bin/env python3
"""Exercise the shipping release aggregate guard against removed or bypassed gates."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "deploy/native-artifact-workflow-parity-audit.py"


def shipping_check():
    tree = ast.parse(AUDIT.read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name == "check_release_aggregate_gates"]
    if len(functions) != 1:
        raise AssertionError("shipping aggregate guard missing or duplicated")
    namespace = {}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(AUDIT), "exec"), namespace)
    return namespace["check_release_aggregate_gates"]


class NativeArtifactAggregate(unittest.TestCase):
    def setUp(self):
        self.check = shipping_check()
        self.source = (ROOT / ".github/workflows/release-candidate.yml").read_text()
        aggregate = self.source.split("\n  aggregate:\n", 1)[1]
        self.needs = next(line for line in aggregate.splitlines() if line.startswith("    needs:"))
        self.gates = [value.strip() for value in self.needs[len("    needs: ["):-1].split(",")]

    def test_actual_complete_aggregate_passes(self):
        self.check(self.source)

    def test_removing_each_original_or_imported_family_gate_fails(self):
        for gate in self.gates:
            with self.subTest(gate=gate):
                values = [value for value in self.gates if value != gate]
                changed = self.source.replace(self.needs, "    needs: [" + ", ".join(values) + "]", 1)
                with self.assertRaisesRegex(AssertionError, "complete required gate inventory"):
                    self.check(changed)

    def test_reordering_cannot_change_required_job_meaning(self):
        self.check(self.source.replace(self.needs, "    needs: [" + ", ".join(reversed(self.gates)) + "]", 1))

    def test_duplicate_and_substituted_dependencies_fail(self):
        for values in (self.gates + [self.gates[0]], self.gates[:-1] + ["unproved-pq"]):
            with self.subTest(values=values):
                with self.assertRaisesRegex(AssertionError, "complete required gate inventory"):
                    self.check(self.source.replace(self.needs, "    needs: [" + ", ".join(values) + "]", 1))

    def test_comment_or_other_job_cannot_supply_removed_needs(self):
        without = self.source.replace(self.needs, "    needs: []", 1)
        for decoy in ("\n# " + self.needs + "\n", "\n  decoy:\n" + self.needs + "\n"):
            with self.subTest(decoy=decoy):
                with self.assertRaisesRegex(AssertionError, "complete required gate inventory"):
                    self.check(without + decoy)

    def test_duplicate_aggregate_or_imported_family_job_fails(self):
        for job in ("aggregate", "imported-pq-reality", "imported-xhttp", "imported-naive-h2", "imported-naive-h3", "darwin-ordered-child"):
            with self.subTest(job=job), self.assertRaisesRegex(AssertionError, "missing or duplicate"):
                self.check(self.source + "\n  " + job + ":\n    runs-on: ubuntu-24.04\n")

    def test_removed_or_changed_pq_workflow_fails(self):
        marker = "    uses: ./.github/workflows/imported-pq-reality-native.yml"
        for replacement in ("    uses: ./.github/workflows/imported-socks-reality-native.yml", "    runs-on: ubuntu-24.04"):
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(AssertionError, "actual imported PQ"):
                    self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")

    def test_condition_or_nonblocking_gate_fails(self):
        for job in ("aggregate", "imported-pq-reality", "imported-xhttp", "imported-naive-h2", "imported-naive-h3", "darwin-ordered-child"):
            for bypass in ("    if: ${{ false }}\n", "    continue-on-error: true\n"):
                with self.subTest(job=job, bypass=bypass):
                    with self.assertRaisesRegex(AssertionError, "conditional or nonblocking"):
                        self.check(self.source.replace("  " + job + ":\n", "  " + job + ":\n" + bypass, 1))

    def test_removed_or_changed_xhttp_workflow_fails(self):
        marker = "    uses: ./.github/workflows/imported-xhttp-native.yml"
        for replacement in ("    uses: ./.github/workflows/imported-pq-reality-native.yml", "    runs-on: ubuntu-24.04"):
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(AssertionError, "actual imported XHTTP"):
                    self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")

    def test_removed_or_changed_naive_h2_workflow_fails(self):
        marker = "    uses: ./.github/workflows/imported-naive-h2-native.yml"
        for replacement in ("    uses: ./.github/workflows/imported-xhttp-native.yml", "    runs-on: ubuntu-24.04"):
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(AssertionError, "actual imported Naive H2"):
                    self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")

    def test_removed_or_changed_naive_h3_workflow_fails(self):
        marker = "    uses: ./.github/workflows/imported-naive-h3-native.yml"
        for replacement in ("    uses: ./.github/workflows/imported-xhttp-native.yml", "    runs-on: ubuntu-24.04"):
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(AssertionError, "actual imported Naive H3"):
                    self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")

    def test_authoritative_audit_executes_guard_and_controls(self):
        tree = ast.parse(AUDIT.read_text())
        calls = [node for node in tree.body if isinstance(node, ast.Expr)
                 and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                 and node.value.func.id == "check_release_aggregate_gates"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.unparse(calls[0].value), "check_release_aggregate_gates(rc)")
        caller = (ROOT / "deploy/release-orchestration-audit.py").read_text()
        self.assertEqual(caller.count('"deploy/test_native_artifact_aggregate.py"'), 1)

    def test_removed_or_changed_darwin_child_workflow_fails(self):
        marker = "    uses: ./.github/workflows/darwin-node-child-tun.yml"
        for replacement in ("    uses: ./.github/workflows/macos-native-installer-contract.yml", "    runs-on: macos-15"):
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(AssertionError, "actual ordered Darwin child"):
                    self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")


if __name__ == "__main__":
    unittest.main()
