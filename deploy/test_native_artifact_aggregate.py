#!/usr/bin/env python3
"""Exercise the shipping release aggregate guard against removed or bypassed gates."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "deploy/native-artifact-workflow-parity-audit.py"


def shipping_check(name="check_release_aggregate_gates"):
    tree = ast.parse(AUDIT.read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name == name]
    if len(functions) != 1:
        raise AssertionError("shipping aggregate guard missing or duplicated")
    namespace = {}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(AUDIT), "exec"), namespace)
    return namespace[name]


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
        for job in ("aggregate", "imported-pq-reality", "imported-xhttp", "imported-naive-h2", "imported-naive-h3", "darwin-ordered-child", "darwin-ordered-host", "native-runtimes", "server-ordered-encrypted"):
            with self.subTest(job=job), self.assertRaisesRegex(AssertionError, "missing or duplicate"):
                self.check(self.source + "\n  " + job + ":\n    runs-on: ubuntu-24.04\n")

    def test_removed_or_changed_pq_workflow_fails(self):
        marker = "    uses: ./.github/workflows/imported-pq-reality-native.yml"
        for replacement in ("    uses: ./.github/workflows/imported-socks-reality-native.yml", "    runs-on: ubuntu-24.04"):
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(AssertionError, "actual imported PQ"):
                    self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")

    def test_condition_or_nonblocking_gate_fails(self):
        for job in ("aggregate", "imported-pq-reality", "imported-xhttp", "imported-naive-h2", "imported-naive-h3", "darwin-ordered-child", "darwin-ordered-host", "native-runtimes", "server-ordered-encrypted"):
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

    def test_removed_or_changed_encrypted_server_workflow_fails(self):
        marker = "    uses: ./.github/workflows/server-node-chain-encrypted.yml"
        for replacement in ("    uses: ./.github/workflows/native-xray-exits.yml", "    runs-on: ubuntu-24.04"):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(AssertionError, "actual encrypted ordered Server"):
                self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")
        with self.assertRaisesRegex(AssertionError, "no-input same-SHA"):
            self.check(self.source.replace(marker, marker + "\n    with:\n      platform: amd64", 1))

    def test_encrypted_server_native_platform_sha_and_receipts_are_required(self):
        check = shipping_check("check_server_encrypted_workflow")
        source = (ROOT / ".github/workflows/server-node-chain-encrypted.yml").read_text()
        check(source)
        changes = (
            ("          - arch: arm64\n            runner: ubuntu-24.04-arm\n", ""),
            ("          - arch: amd64\n            runner: ubuntu-24.04\n", ""),
            ("          ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}", "          ROUTERVPN_EXPECTED_SOURCE: historical"),
            ("          persist-credentials: false", "          persist-credentials: false\n          ref: historical"),
            ("  workflow_call:\n", "  workflow_call:\n    inputs: {}\n"),
            ("  encrypted:\n", "  encrypted:\n    if: false\n"),
            ("  encrypted:\n", "  encrypted:\n    continue-on-error: true\n"),
            ("--standalone --require-commit", "--compile-only --require-commit"),
            ("          if-no-files-found: error", "          if-no-files-found: ignore"),
        )
        for old, new in changes:
            self.assertEqual(source.count(old), 1)
            with self.subTest(old=old), self.assertRaises(AssertionError):
                check(source.replace(old, new, 1))
        caller = (ROOT / "deploy/release-orchestration-audit.py").read_text()
        self.assertEqual(caller.count('"deploy/test_server_node_chain_encrypted_runner.py"'), 1)
        tree = ast.parse(AUDIT.read_text())
        calls = [node for node in tree.body if isinstance(node, ast.Expr)
                 and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                 and node.value.func.id == "check_server_encrypted_workflow"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.unparse(calls[0].value), "check_server_encrypted_workflow(read('.github/workflows/server-node-chain-encrypted.yml'))")

    def test_removed_or_changed_darwin_child_workflow_fails(self):
        marker = "    uses: ./.github/workflows/darwin-node-child-tun.yml"
        for replacement in ("    uses: ./.github/workflows/macos-native-installer-contract.yml", "    runs-on: macos-15"):
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(AssertionError, "actual ordered Darwin child"):
                    self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")

    def test_removed_or_changed_darwin_host_workflow_fails(self):
        marker = "    uses: ./.github/workflows/darwin-node-host-tun.yml"
        for replacement in ("    uses: ./.github/workflows/darwin-node-child-tun.yml", "    runs-on: macos-15"):
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(AssertionError, "actual installed ordered Darwin host"):
                    self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")

    def test_darwin_host_requires_successful_current_run_producer(self):
        marker = "    needs: native-runtimes\n    uses: ./.github/workflows/darwin-node-host-tun.yml"
        for replacement in ("    uses: ./.github/workflows/darwin-node-host-tun.yml",
                            marker.replace("needs: native-runtimes", "needs: source-audit"),
                            marker.replace("needs: native-runtimes", "needs: [native-runtimes, source-audit]")):
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(AssertionError, "successful current-run runtime producer"):
                    self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")
        producer = "    uses: ./.github/workflows/desktop-native-runtime.yml"
        for replacement in ("    uses: ./.github/workflows/desktop-native-smoke.yml", "    runs-on: macos-15"):
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(AssertionError, "complete current-run runtime producer"):
                    self.check(self.source.replace(producer, replacement, 1))


if __name__ == "__main__":
    unittest.main()
