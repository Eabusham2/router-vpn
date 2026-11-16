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
              for name in ("capture", "prefix_controls", "runtime", "control", "launch", "speed_lab")) + tuple("test_ios_socks_execution_" + name + ".py" for name in ("capture", "runtime", "restore_last", "layered_control", "layered_launch", "layered_profiles")) + tuple("test_ios_openvpn_execution_" + name + ".py" for name in ("capture", "runtime", "restore_last", "profiles")) + ("test_ios_node_chain_connect_profiles.py",)
CAPTURE = "deploy/test_ios_connect_execution_capture.py"
PREFIX = "deploy/test_ios_connect_execution_prefix_controls.py"
ORIGINAL_CONTROLS = (
    "typed-members", "typed-identities", "final-private-source",
    "latency-original-source", "original-final-presentation", "paired-schema-presentation",
)
PREFIX_CONTROLS = (
    "original-trio-capture", "original-trio-session", "private-replay-final-layer",
    "original-trio-presentation", "later-paired-prefix",
)
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
    "deploy/test_ios_node_chain_execution_capture.py", "deploy/test_ios_node_chain_profiles.py",
    "deploy/test_ios_node_chain_openvpn_profiles.py",
    "internal/mobilemultihop/node_chain_openvpn_apple_fixture_test.go",
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


COMPLETE_PREFIX_CASES = {
    "deploy/test_ios_connect_execution_capture.py": (
        ('for count in [3,4,8] {for kind in ["http-connect","https-connect"]', 1),
        ('try completePrefixBounds()', 1),
        ('for count in 3...8 {for requested in ["server","auto"]', 1),
        ('for count in [2,9]', 1),
        ('Rejected CONNECT complete-prefix control: original-trio-capture', 1),
        ('Rejected CONNECT complete-prefix control: original-trio-session', 1),
        ('Rejected CONNECT complete-prefix control: private-replay-final-layer', 1),
        ('Rejected CONNECT complete-prefix control: original-trio-presentation', 1),
        ('Rejected CONNECT complete-prefix control: later-paired-prefix', 1),
    ),
    "deploy/test_ios_connect_execution_control.py": (
        ('for count in [3,4,8] {for kind in ["http-connect","https-connect"]', 1),
        ('for selected in requested=="auto" ? ["local","server"]:["server"]', 1),
        ('try await control.proveRestored(send:restored.send,current:{})', 5),
    ),
    "deploy/test_ios_connect_execution_launch.py": (
        ('for count in [3,4,8] {for kind in ["http-connect","https-connect"]', 2),
        ('try connectEditor()', 1),
        ('"later-prefix-token"', 3),
        ('try hostnameEditor()', 1),
        ('"hostname editor fixture keeps a real hostname"', 1),
        ('"hostname editor retains explicit original resolver without literal substitution"', 1),
    ),
    "deploy/test_ios_node_chain_connect_profiles.py": (
        ('for requested in ([3,4,8].contains(count) && mode=="wg" && host=="198.51.100.76" && authenticated ? ["local","server","auto"]:["local"]) {', 1),
        ('"typed profile Load reopens exact native source and config"', 1),
    ),
}

LAYERED_SOCKS = {
    "deploy/test_ios_socks_execution_layered_control.py": (
        ('for count in [4,8] {for finalLayer in ["aes-256-gcm","aes-256-gcm+xor-whitening"]', 1),
        ('count==8 ? "off":finalLayer=="aes-256-gcm"', 1),
        ('"layered SOCKS restoration keeps complete independent original source"', 1),
        ('"selected SOCKS final layer retains original native transport and private key"', 1),
        ('await reject("changed final layer source")', 1),
        ("C.SWIFT[C.SWIFT.index('@MainActor final class Provider'):]", 1),
    ),
    "deploy/test_ios_socks_execution_layered_launch.py": (
        ('for count in [4,8] {for finalLayer in ["aes-256-gcm","aes-256-gcm+xor-whitening"]', 2),
        ('try editor()', 1),
        ('"layered SOCKS cold Last carries original winner without Compare rerank"', 1),
        ('"layered SOCKS editor compiles every original member before saving"', 1),
        ('await reject("stale launch "+fault)', 1),
    ),
    "deploy/test_ios_socks_execution_layered_profiles.py": (
        ('for count in [4,8] {for execution in ["server","auto"] {for finalLayer in ["aes-256-gcm","aes-256-gcm+xor-whitening"]', 1),
        ('count==8 ? "off":finalLayer=="aes-256-gcm"', 1),
        ('try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:execution)', 1),
        ('"layered SOCKS profile stores independent original layers"', 1),
        ('"layered SOCKS Load retains independent original layers"', 1),
    ),
}


def check_layered_socks_consumers(read):
    for path, inventory in LAYERED_SOCKS.items():
        text = read(path)
        for marker, count in inventory:
            assert text.count(marker) == count, "required layered SOCKS consumer case changed: " + path + ": " + marker
        main = [node for node in ast.parse(text).body if isinstance(node, ast.FunctionDef) and node.name == "main"]
        assert len(main) == 1
        expected = (["C.SWIFT = SWIFT", "C.main(label='layered SOCKS')"] if path.endswith("_control.py") else
                    ["C.TESTS = TESTS", "C.main(label='layered SOCKS')"] if path.endswith("_launch.py") else
                    ["C.TYPED = TYPED", "C.main(label='layered SOCKS', roundtrip='socksRoundtrip')"])
        assert [ast.unparse(node) for node in main[0].body] == expected, "layered SOCKS must execute its original checked driver"

    # The additive cases must not replace any of the already published complete
    # source, profile or retained-choice phases, including their original bounds.
    for path in ("deploy/test_ios_socks_execution_capture.py", "deploy/test_ios_node_chain_socks_profiles.py", "deploy/test_ios_socks_execution_restore_last.py"):
        constants = [node for node in ast.parse(read(path)).body if isinstance(node, ast.Assign)
                     and [ast.unparse(target) for target in node.targets] == ["PREFIX_NODE_COUNTS"]]
        assert len(constants) == 1 and ast.literal_eval(constants[0].value) == (3, 4, 5, 6, 7, 8), "all published complete SOCKS phases remain required"
    local = read("deploy/test_ios_node_chain_socks_capture.py")
    assert local.count('SOCKS original configured nested packet capacity') == 1
    assert local.count('try socksMiddle();try socksCapacity();print(') == 1, "original configured packet-capacity refusal cannot be removed"


def check_capture_phases(read):
    """Keep both required phases finite without dropping original controls."""
    tree = ast.parse(read(CAPTURE))
    mains = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"]
    assert len(mains) == 1
    main = mains[0]
    assert ast.unparse(main.args) == "phase='original'", "original Apple capture must remain the default phase"
    assert ast.unparse(main.body[0]) == "if phase not in ('original', 'complete-prefix'):\n    raise ValueError('unknown Apple CONNECT source phase')", "unknown Apple source phases must be refused"
    contexts = [node for node in main.body if isinstance(node, ast.With)]
    assert len(contexts) == 1
    statements = contexts[0].body
    branches = [(index, node) for index, node in enumerate(statements)
                if isinstance(node, ast.If) and ast.unparse(node.test) == "phase == 'original'"]
    assert len(branches) == 1
    index, original = branches[0]
    assert not original.orelse and isinstance(original.body[-1], ast.Return) and original.body[-1].value is None
    assert ast.unparse(statements[index - 3]) == "result = run(text)"
    assert ast.unparse(statements[index - 2]) == "assert result.returncode == 0, result.stdout + result.stderr", "each capture phase must execute its positive baseline"
    prepared = [node for node in statements if isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr == "write_text"
                and ast.unparse(node.value.func.value) == "work / 'Tests.swift'"]
    assert len(prepared) == 1 and ast.unparse(prepared[0].value.args[0]) == "SWIFT if phase == 'original' else PREFIX_CONTROLS", "original matrix and focused prefix source must each execute"

    def control_names(body):
        names = []
        for statement in body:
            if isinstance(statement, ast.For) and ast.unparse(statement.target) == "(name, before, after, witness)":
                records = ast.literal_eval(statement.iter)
                assert all(len(row) == 4 and all(isinstance(value, str) for value in row) for row in records)
                emitted = [node for node in statement.body if isinstance(node, ast.Expr)
                           and isinstance(node.value, ast.Call) and ast.unparse(node.value.func) == "print"
                           and len(node.value.args) == 2 and ast.unparse(node.value.args[1]) == "name"]
                assert len(emitted) == 1
                names.extend(row[0] for row in records)
            elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call) and ast.unparse(statement.value.func) == "print":
                args = statement.value.args
                if len(args) == 1 and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str) and args[0].value.startswith("Rejected "):
                    names.append(args[0].value.rsplit(": ", 1)[-1])
        return tuple(names)

    assert control_names(original.body) == ORIGINAL_CONTROLS, "all original Apple source controls must execute in order"
    assert control_names(statements[index + 1:]) == PREFIX_CONTROLS, "all five complete-prefix controls must execute in order"
    companion = ast.parse(read(PREFIX)).body
    if companion and isinstance(companion[0], ast.Expr) and isinstance(companion[0].value, ast.Constant):
        companion = companion[1:]
    assert [ast.unparse(node) for node in companion] == [
        "from test_ios_connect_execution_capture import main",
        "if __name__ == '__main__':\n    main(phase='complete-prefix')",
    ], "required prefix companion must execute its exact phase"


def check_openvpn_profile_phases(read):
    source = read("deploy/test_ios_openvpn_execution_profiles.py")
    tree = ast.parse(source)
    counts = [node for node in tree.body if isinstance(node, ast.Assign)
              and [ast.unparse(target) for target in node.targets] == ["PROFILE_NODE_COUNTS"]]
    assert len(counts) == 1 and ast.literal_eval(counts[0].value) == (3, 4, 5, 6, 7, 8), "all six original OpenVPN profile lengths are mandatory"
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and ast.unparse(node.func) == "C.main"]
    assert len(calls) == 1 and ast.unparse(calls[0]) == "C.main(label='OpenVPN execution', roundtrip='openVPNRoundtrip', binary_cases=[(count,) for count in PROFILE_NODE_COUNTS])", "the original profile driver must execute all bounded OpenVPN phases"
    for marker in ('CommandLine.arguments.count==3', '(3...8).contains(count)',
                   'for network in ["tcp","udp"] {for requested in ["server","auto"] {for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"]',
                   'completedCases==12'):
        assert source.count(marker) == 1, "complete OpenVPN profile phase lost its original matrix: " + marker
    driver = ast.parse(read("deploy/test_ios_node_chain_connect_profiles.py"))
    calls = [node for node in ast.walk(driver) if isinstance(node, ast.Call) and ast.unparse(node.func) == "P.main"]
    assert len(calls) == 1 and [(item.arg, ast.unparse(item.value)) for item in calls[0].keywords if item.arg == "binary_cases"] == [("binary_cases", "binary_cases")], "typed profile driver must forward the complete phase inventory"


def check(read):
    check_capture_phases(read)
    check_layered_socks_consumers(read)
    check_openvpn_profile_phases(read)
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
    for path, inventory in COMPLETE_PREFIX_CASES.items():
        source = read(path)
        for marker, count in inventory:
            assert source.count(marker) == count, "Apple complete CONNECT case inventory changed: " + path + ": " + marker

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
                 CONTRACT, "deploy/test_ios_connect_execution_*.py", "deploy/test_ios_socks_execution_*.py", "deploy/test_ios_openvpn_execution_*.py", "deploy/test_ios_node_chain_connect_profiles.py", "deploy/ios_ordered_execution_control_boundary.py"):
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

    def test_complete_openvpn_profile_phases_cannot_be_omitted(self):
        path = "deploy/test_ios_openvpn_execution_profiles.py"
        for before, after in (
                ("PROFILE_NODE_COUNTS = (3, 4, 5, 6, 7, 8)", "PROFILE_NODE_COUNTS = (3, 4, 8)"),
                ("binary_cases=[(count,) for count in PROFILE_NODE_COUNTS]", "binary_cases=[(3,)]"),
                ("(3...8).contains(count)", "(3...7).contains(count)"),
                ('for network in ["tcp","udp"]', 'for network in ["tcp"]'),
                ('for requested in ["server","auto"]', 'for requested in ["server"]'),
                ("completedCases==12", "completedCases==6")):
            with self.subTest(marker=before):
                self.broken(path, before, after)
        self.broken("deploy/test_ios_node_chain_connect_profiles.py", "binary_cases=binary_cases", "binary_cases=None")

    def test_complete_connect_prefix_cases_and_controls_cannot_be_omitted(self):
        for path, inventory in COMPLETE_PREFIX_CASES.items():
            for marker, _ in inventory:
                with self.subTest(path=path, marker=marker):
                    self.broken(path, marker, "omitted-complete-prefix-case")

    def test_required_capture_phase_dispatch_and_original_inventory(self):
        for path, before, after in (
                (CAPTURE, 'def main(phase="original"):', 'def main(phase="complete-prefix"):'),
                (CAPTURE, "SWIFT if phase == 'original' else PREFIX_CONTROLS", "SWIFT"),
                (CAPTURE, "        if phase == 'original':", "        if False:"),
                (PREFIX, 'main(phase="complete-prefix")', 'main(phase="original")'),
                (PREFIX, 'main(phase="complete-prefix")', 'pass')):
            with self.subTest(path=path, before=before):
                self.broken(path, before, after)
        for name in ORIGINAL_CONTROLS:
            with self.subTest(original_control=name):
                self.broken(CAPTURE, name, "omitted-original-control")

    def test_layered_socks_cases_dispatch_and_original_phases_are_required(self):
        for path, inventory in LAYERED_SOCKS.items():
            for marker, _ in inventory:
                with self.subTest(path=path, marker=marker):
                    self.broken(path, marker, "omitted-layered-socks-consumer")
            before = 'C.main(label="layered SOCKS",roundtrip="socksRoundtrip")' if path.endswith("_profiles.py") else 'C.main(label="layered SOCKS")'
            self.broken(path, before, "pass")
        for path in ("deploy/test_ios_socks_execution_capture.py", "deploy/test_ios_node_chain_socks_profiles.py", "deploy/test_ios_socks_execution_restore_last.py"):
            self.broken(path, "PREFIX_NODE_COUNTS = (3, 4, 5, 6, 7, 8)", "PREFIX_NODE_COUNTS = (4, 8)")
        self.broken("deploy/test_ios_node_chain_socks_capture.py", "try socksMiddle();try socksCapacity();print(", "try socksMiddle();print(")

    def test_layered_socks_prepares_real_shared_consumer_bodies(self):
        # Preparing generated Swift with execution intercepted proves only
        # source composition. Actual compiled gates remain separately required.
        import test_ios_socks_execution_layered_control as control
        import test_ios_socks_execution_layered_launch as launch
        import test_ios_socks_execution_layered_profiles as profiles
        for derived, attribute in ((control, "SWIFT"), (launch, "TESTS"), (profiles, "TYPED")):
            driver = derived.C
            original, execute = getattr(driver, attribute), driver.main
            try:
                prepared = []
                driver.main = lambda **options: prepared.append((getattr(driver, attribute), options))
                derived.main()
                self.assertEqual(len(prepared), 1)
                source, options = prepared[0]
                self.assertEqual(options["label"], "layered SOCKS")
                if attribute != "TYPED":
                    self.assertEqual(source.count("@main"), 1)
                    self.assertEqual(source.count("func socksFixture("), 1)
                    self.assertEqual(source.count("func layeredSOCKSFixture("), 1)
                    self.assertEqual(source.count("enum IOSPrivateJSONStore"), 1)
                if attribute == "SWIFT":
                    self.assertIn('for selected in requested=="auto" ? ["local","server"]:["server"]', source)
                    self.assertIn('"changed restored winner"', source)
                    self.assertIn('"capture intent retained before asynchronous failure"', source)
                if attribute == "TESTS":
                    self.assertIn('"middle-password"', source)
                    self.assertIn('"layered SOCKS cold Last carries original winner without Compare rerank"', source)
                if attribute == "TYPED":
                    self.assertEqual(options["roundtrip"], "socksRoundtrip")
                    self.assertIn('IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:execution)', source)
                    self.assertNotIn('missing captured SOCKS profile phase', source)
                    self.assertIn('"typed profile Load reopens exact native source and config"', source)
            finally:
                setattr(driver, attribute, original)
                driver.main = execute

    def test_profile_derivatives_keep_their_own_local_source_scope(self):
        # Prepare the real derived Swift strings while intercepting execution.
        # This proves fixture composition only, not Swift/native acceptance.
        import test_ios_node_chain_connect_profiles as connect
        import test_ios_node_chain_imported_profiles as imported
        import test_ios_node_chain_openvpn_profiles as openvpn
        original, execute = connect.TYPED, connect.main
        try:
            for derived, name in ((imported, "importedSSRoundtrip"), (openvpn, "openVPNRoundtrip")):
                with self.subTest(source=name):
                    prepared = []
                    connect.TYPED = original
                    connect.main = lambda **options: prepared.append((connect.TYPED, options))
                    derived.main()
                    self.assertEqual(len(prepared), 1)
                    source, options = prepared[0]
                    self.assertEqual(options["roundtrip"], name)
                    self.assertEqual(source.count('for requested in ["local"] {'), 1)
                    self.assertNotIn("authenticated", source)
                    self.assertIn('"typed profile Load reopens exact native source and config"', source)
        finally:
            connect.TYPED, connect.main = original, execute

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
        self.broken(LIBBOX, "      - 'deploy/test_ios_socks_execution_*.py'\n", "")

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
