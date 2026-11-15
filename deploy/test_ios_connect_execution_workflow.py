#!/usr/bin/env python3
"""Require actual typed Apple CONNECT contracts in the native shipping lanes."""
import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "ios/RouterVPN/test_runtime_selection_contract.py"
GUARD = "deploy/test_ios_connect_execution_workflow.py"
GATES = tuple("test_ios_connect_execution_" + name + ".py"
              for name in ("capture", "runtime", "control", "launch", "speed_lab"))
ORIGINAL = (
    'test_ios_external_policy.py',
    'test_ios_external_entry_selection.py',
    'test_ios_external_execution_owner.py',
    'test_ios_external_connection_profiles.py',
    'test_ios_tor_connection_profiles.py',
    'test_ios_external_dns_settings.py',
    'test_ios_external_device_settings.py',
    'test_ios_node_store_transactions.py',
    'test_ios_candidate_catalog.py',
    'test_ios_node_candidates.py',
    'test_ios_node_candidate_prefix_capture.py',
    'test_ios_node_candidate_prefix_provider.py',
    'test_ios_node_candidate_prefix_host.py',
    'test_ios_node_candidate_prefix_launch.py',
    'test_ios_node_candidate_prefix_flow.py',
    'test_ios_node_candidate_prefix_delivery.py',
    'test_ios_node_candidate_prefix_engine.py',
    'test_ios_node_candidate_session.py',
    'test_ios_node_candidate_transaction.py',
    'test_ios_node_candidate_preparation.py',
    'test_ios_node_candidate_preparation_flow.py',
    'test_ios_node_chain_profiles.py',
    'test_ios_node_chain_capture.py',
    'test_ios_node_chain_openvpn_capture.py',
    'test_ios_node_chain_openvpn_profiles.py',
    'test_ios_node_chain_imported_capture.py',
    'test_ios_node_chain_imported_profiles.py',
    'test_ios_node_chain_execution_capture.py',
    'test_ios_node_chain_execution_restore_last.py',
    'test_ios_node_chain_execution_host.py',
    'test_ios_node_chain_socks_host.py',
    'test_ios_ordered_latency.py',
    'test_ios_ordered_latency_callbacks.py',
    'test_ios_ordered_latency_host.py',
    'test_ios_node_chain_socks_capture.py',
    'test_ios_ordered_latency_socks_capture.py',
    'test_ios_node_chain_socks_profiles.py',
    'test_ios_node_chain_execution_registry.py',
    'test_ios_node_chain_execution_session.py',
    'test_ios_node_chain_execution_provider.py',
    'test_ios_node_chain_identity.py',
    'test_ios_node_chain_provider.py',
    'test_ios_node_chain_launch.py',
    'test_ios_node_chain_startup.py',
    'test_ios_node_chain_editor.py',
    'test_ios_node_chain_presentation.py',
)
SMOKE = ".github/workflows/ios-native-compile-smoke.yml"
LIBBOX = ".github/workflows/ios-libbox-engine.yml"
RELEASE = ".github/workflows/release-candidate.yml"
INPUTS = tuple("deploy/" + name for name in GATES) + (
    "deploy/ios_ordered_execution_control_boundary.py", GUARD, CONTRACT, SMOKE, LIBBOX)
STEP = "      - name: Require complete typed CONNECT execution contracts\n"
BASE_COMMANDS = "        run: |\n          xcrun --find swiftc\n          python3 " + GUARD + "\n"


def job(source, name):
    values = re.findall(r"(?ms)^  " + re.escape(name) + r":\n(.*?)(?=^  [A-Za-z][\w-]*:\n|\Z)", source)
    assert len(values) == 1, "missing or duplicate Apple native job: " + name
    return values[0]


def block(source, marker):
    assert source.count(marker) == 1, "missing or duplicate Apple native step"
    return source.split(marker, 1)[1].split("      - ", 1)[0]


def check(read):
    tree = ast.parse(read(CONTRACT))
    darwin = [node for node in tree.body if isinstance(node, ast.If)
              and ast.unparse(node.test) == "platform.system() == 'Darwin'"]
    assert len(darwin) == 1, "typed Apple contracts lost their actual native boundary"
    loops = [node for node in ast.walk(tree) if isinstance(node, ast.For)
             and isinstance(node.target, ast.Name) and node.target.id == "external_test"]
    assert len(loops) == 1 and loops[0] in darwin[0].body, "typed Apple gates cannot be nested, skipped or duplicated"
    names = ast.literal_eval(loops[0].iter)
    assert isinstance(names, tuple) and len(names) == len(set(names)), "duplicate Apple contract"
    assert set(names) == set(ORIGINAL) | set(GATES), "complete original and typed Apple inventory is mandatory"
    assert len(loops[0].body) == 1 and not loops[0].orelse
    assert ast.unparse(loops[0].body[0]) == "subprocess.run([sys.executable, str(root / 'deploy' / external_test)], check=True, timeout=300)", "Apple gates lost their original checked 300-second boundary"

    builder = read("deploy/build-native-runtime.py")
    for path in INPUTS:
        assert builder.count("ROOT/'" + path + "'") == 1, "missing Apple gate source identity: " + path
    for rel, name, runtime_step, runtime_command in (
            (SMOKE, "ios-native-compile", "      - name: Validate iOS runtime and DNS truth contracts\n", "python3 ios/RouterVPN/test_runtime_selection_contract.py"),
            (RELEASE, "ios", "      - name: Run iOS/iPadOS source contracts\n", "python3 test_runtime_selection_contract.py"),
            (LIBBOX, "apple-libbox", "      - name: Build exact Apple Libbox XCFramework\n", "./prepare-libbox.sh")):
        source = read(rel)
        owned = job(source, name)
        header = owned.split("    steps:\n", 1)[0]
        assert "    runs-on: macos-15\n" in header
        assert not re.search(r"(?m)^\s+(?:if|continue-on-error|[\'\"][^\n]*[\'\"])\s*:", header), "Apple native job cannot be optional"
        expected = BASE_COMMANDS
        if rel == LIBBOX:
            expected += "".join("          python3 deploy/" + gate + "\n" for gate in GATES)
        assert block(owned, STEP) == expected, "Apple typed gate is conditional, filtered or unchecked"
        assert owned.index("actions/setup-go@v5") < owned.index(STEP) < owned.index(runtime_step)
        assert "go-version: '1.26.3'" in owned
        runtime = block(owned, runtime_step)
        commands = [line.strip() for line in runtime.splitlines()]
        assert commands.count(runtime_command) == 1, "native Apple caller lost its exact original source contract"
        assert not re.search(r"(?m)^\s+(?:if|continue-on-error|[\'\"][^\n]*[\'\"])\s*:", runtime), "original Apple contract cannot become optional"

    libbox = read(LIBBOX)
    for path in ("ios/RouterVPN/App/IOS*.swift", "ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift",
                 CONTRACT, "deploy/test_ios_connect_execution_*.py", "deploy/ios_ordered_execution_control_boundary.py"):
        assert libbox.count("      - '" + path + "'\n") == 2, "Apple gate lost push or pull-request path coverage"
    aggregate = job(read(RELEASE), "aggregate")
    values = re.findall(r"(?m)^    needs: \[([^\n]+)\]$", aggregate)
    assert len(values) == 1 and [name.strip() for name in values[0].split(",")].count("ios") == 1


class AppleCONNECTWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.edits = {}

    def read(self, path):
        return self.edits[path] if path in self.edits else (ROOT / path).read_text()

    def broken(self, path, before, after):
        self.edits.clear()
        source = self.read(path)
        self.assertIn(before, source)
        self.edits[path] = source.replace(before, after, 1)
        with self.assertRaises((AssertionError, SyntaxError, ValueError)):
            check(self.read)

    def test_complete_native_closure(self):
        check(self.read)

    def test_every_original_and_new_contract_is_required_once(self):
        for name in ORIGINAL + GATES:
            with self.subTest(name=name):
                self.broken(CONTRACT, repr(name), repr("omitted.py"))
        self.broken(CONTRACT, repr(GATES[0]), repr(GATES[1]))

    def test_original_native_condition_and_checked_budget_cannot_be_bypassed(self):
        for before, after in (("if platform.system() == 'Darwin':", "if False:"),
                              ("check=True, timeout=300)\n    subprocess.run([sys.executable, str(root / 'deploy/test_ios_performance_bridge.py')", "check=False, timeout=300)\n    subprocess.run([sys.executable, str(root / 'deploy/test_ios_performance_bridge.py')"),
                              ("str(root / 'deploy' / external_test)], check=True, timeout=300)", "str(root / 'deploy' / external_test)], check=True, timeout=900)")):
            self.broken(CONTRACT, before, after)

    def test_native_callers_reject_filtered_optional_or_missing_gates(self):
        for rel in (SMOKE, RELEASE, LIBBOX):
            for before, after in ((STEP, STEP + "        if: false\n"),
                                  (STEP, STEP + "        'continue-on-error': true\n"),
                                  ("          xcrun --find swiftc\n", "          true\n"),
                                  ("          python3 " + GUARD, "          python3 " + GUARD + " || true")):
                with self.subTest(rel=rel, before=before):
                    self.broken(rel, before, after)
        for gate in GATES:
            self.broken(LIBBOX, "          python3 deploy/" + gate + "\n", "          true\n")
        self.broken(SMOKE, "python3 ios/RouterVPN/test_runtime_selection_contract.py\n", "python3 ios/RouterVPN/test_runtime_selection_contract.py || true\n")
        self.broken(RELEASE, "python3 test_runtime_selection_contract.py\n", "python3 test_runtime_selection_contract.py || true\n")

    def test_native_toolchain_source_and_release_dependency_are_required(self):
        for path in INPUTS:
            self.broken("deploy/build-native-runtime.py", "ROOT/'" + path + "'", "ROOT/'omitted.py'")
        self.broken(SMOKE, "actions/setup-go@v5", "actions/setup-python@v5")
        self.broken(RELEASE, ", ios,", ", omitted-ios,")
        self.broken(LIBBOX, "      - 'deploy/test_ios_connect_execution_*.py'\n", "")

    def test_shipping_parity_must_execute_this_guard_once(self):
        source = self.read("deploy/native-artifact-workflow-parity-audit.py")
        def calls(text):
            return [ast.unparse(node.value) for node in ast.parse(text).body
                    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == "check_ios_connect_execution_workflow"]
        marker = "check_ios_connect_execution_workflow(read)"
        self.assertEqual(calls(source), [marker])
        for changed in (source.replace(marker, "pass", 1), source.replace(marker, marker + "\n" + marker, 1),
                        source.replace(marker, "check_ios_connect_execution_workflow(other)", 1)):
            self.assertNotEqual(calls(changed), [marker])


if __name__ == "__main__":
    unittest.main()
