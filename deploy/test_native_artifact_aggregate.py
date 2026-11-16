#!/usr/bin/env python3
"""Exercise the shipping release aggregate guard against removed or bypassed gates."""
import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "deploy/native-artifact-workflow-parity-audit.py"
TYPED_NATIVE = ("typed-socks-native", "typed-connect-runtime", "typed-connect-source", "typed-connect-native", "typed-connect-native-mtu", "desktop-connect-child")


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
        for job in ("aggregate", "imported-pq-reality", "imported-xhttp", "imported-naive-h2", "imported-naive-h3", "darwin-ordered-child", "darwin-ordered-host", "unix-naive-h2-host", "linux-connect-execution-host", "linux-socks-execution-host", "linux-imported-execution-host", "windows-connect-execution-host", "darwin-prefix-host", "native-runtimes", "server-ordered-encrypted", "openvpn-prefix-native", "ss-prefix-native", *TYPED_NATIVE):
            with self.subTest(job=job), self.assertRaisesRegex(AssertionError, "missing or duplicate"):
                self.check(self.source + "\n  " + job + ":\n    runs-on: ubuntu-24.04\n")

    def test_removed_or_changed_pq_workflow_fails(self):
        marker = "    uses: ./.github/workflows/imported-pq-reality-native.yml"
        for replacement in ("    uses: ./.github/workflows/imported-socks-reality-native.yml", "    runs-on: ubuntu-24.04"):
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(AssertionError, "actual imported PQ"):
                    self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")

    def test_condition_or_nonblocking_gate_fails(self):
        for job in ("aggregate", "imported-pq-reality", "imported-xhttp", "imported-naive-h2", "imported-naive-h3", "darwin-ordered-child", "darwin-ordered-host", "unix-naive-h2-host", "linux-connect-execution-host", "linux-socks-execution-host", "linux-imported-execution-host", "windows-connect-execution-host", "darwin-prefix-host", "native-runtimes", "server-ordered-encrypted", "openvpn-prefix-native", "ss-prefix-native", *TYPED_NATIVE):
            for bypass in ("    if: ${{ false }}\n", "    if: ${{ always() }}\n", "    continue-on-error: true\n"):
                with self.subTest(job=job, bypass=bypass):
                    with self.assertRaisesRegex(AssertionError, "conditional or nonblocking"):
                        self.check(self.source.replace("  " + job + ":\n", "  " + job + ":\n" + bypass, 1))

    def test_each_required_typed_native_job_rejects_foreign_source_suite_or_workflow(self):
        for job in TYPED_NATIVE:
            start = self.source.index("  " + job + ":\n")
            end = start + 3 + re.search(r"\n  \S", self.source[start + 3:]).start()
            original = self.source[start:end]
            changes = (
                ("source_sha: ${{ github.sha }}", "source_sha: " + "a" * 40),
                ("source_sha: ${{ github.sha }}", "source_sha: ${{ inputs.source_sha }}"),
                ("suite: " + {"typed-socks-native": "socks-run", "typed-connect-runtime": "connect-runtime",
                             "typed-connect-source": "connect-source",
                             "typed-connect-native": "connect-run", "typed-connect-native-mtu": "connect-native-mtu", "desktop-connect-child": "desktop-connect-child"}[job],
                 "suite: socks-source"),
                ("    uses: ./.github/workflows/focused-source-validation.yml",
                 "    uses: ./.github/workflows/desktop-native-smoke.yml"),
            )
            for before, after in changes:
                with self.subTest(job=job, before=before):
                    self.assertEqual(original.count(before), 1)
                    changed = self.source[:start] + original.replace(before, after, 1) + self.source[end:]
                    with self.assertRaises(AssertionError):
                        self.check(changed + "\n# " + before + "\n")

    def test_reusable_native_suites_retain_actual_execution_and_source_guards(self):
        check = shipping_check("check_focused_native_release_workflow")
        source = (ROOT / ".github/workflows/focused-source-validation.yml").read_text()
        check(source)
        changes = [
            ("  workflow_call:\n", ""),
            ("  workflow_call:\n", "  workflow_call:\n  workflow_call:\n"),
            ("        required: true", "        required: false"),
            ("  validate:\n", "  validate:\n    continue-on-error: true\n"),
            ("    if: inputs.suite != 'darwin-socks-child' && inputs.suite != 'darwin-socks-installed'", "    if: false"),
            ('            --output "$GITHUB_WORKSPACE/validation-output/selection-after.json"', "            --output unchecked.json"),
            ("          ref: ${{ inputs.source_sha }}", "          ref: main"),
            ("          ref: ${{ github.sha }}", "          ref: main"),
            ("  cancel-in-progress: false", "  cancel-in-progress: true"),
        ]
        for suite, driver in (("socks-run", "test_focused_socks_run.py"),
                              ("connect-runtime", "test_focused_connect_runtime.py"),
                              ("connect-source", "test_focused_connect_source.py"),
                              ("connect-run", "test_focused_connect_run.py"),
                              ("connect-native-mtu", "test_focused_connect_native_mtu.py")):
            condition = "        if: inputs.suite == '" + suite + "'"
            command = "          python3 validator/deploy/" + driver + " \\\n"
            changes.extend([
                (condition, "        if: false"),
                (condition, condition + "\n        continue-on-error: true"),
                (command, "          true # " + driver + "\n"),
                (command, command.replace("python3 ", "echo ")),
            ])
        for before, after in changes:
            with self.subTest(before=before, after=after), self.assertRaises(AssertionError):
                check(source.replace(before, after, 1) + "\n# " + before + "\n")
        tree = ast.parse(AUDIT.read_text())
        calls = [node for node in tree.body if isinstance(node, ast.Expr)
                 and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                 and node.value.func.id == "check_focused_native_release_workflow"]
        self.assertEqual(len(calls), 1, "shipping release audit must execute the reusable native guard")

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

    def test_linux_connect_execution_requires_original_runtime_and_full_native_workflow(self):
        marker = "    uses: ./.github/workflows/linux-connect-execution-host.yml"
        self.assertEqual(self.source.count(marker), 1)
        for replacement in (
            "    uses: ./.github/workflows/linux-node-child-tun.yml",
            "    runs-on: ubuntu-24.04",
            marker + "\n" + marker,
        ):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(AssertionError, "actual installed Linux CONNECT"):
                self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")
        original = "    needs: native-runtimes\n" + marker
        self.assertEqual(self.source.count(original), 1)
        for needs in ("", "    needs: source-audit\n", "    needs: native-runtimes\n    needs: source-audit\n"):
            with self.subTest(needs=needs), self.assertRaisesRegex(AssertionError, "current-run runtime producer"):
                self.check(self.source.replace(original, needs + marker, 1))
        for inputs in ("      source_sha: historical", "      case: http-wg-server", "      platform: amd64"):
            with self.subTest(inputs=inputs), self.assertRaisesRegex(AssertionError, "no-input same-SHA"):
                self.check(self.source.replace(marker, marker + "\n    with:\n" + inputs, 1))

    def test_linux_socks_execution_requires_original_runtime_and_full_native_workflow(self):
        marker = "    uses: ./.github/workflows/linux-socks-execution-host.yml"
        self.assertEqual(self.source.count(marker), 1)
        for replacement in (
            "    uses: ./.github/workflows/linux-node-child-tun.yml",
            "    runs-on: ubuntu-24.04",
            marker + "\n" + marker,
        ):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(AssertionError, "actual installed Linux SOCKS"):
                self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")
        original = "    needs: native-runtimes\n" + marker
        self.assertEqual(self.source.count(original), 1)
        for needs in ("", "    needs: source-audit\n", "    needs: native-runtimes\n    needs: source-audit\n"):
            with self.subTest(needs=needs), self.assertRaisesRegex(AssertionError, "current-run runtime producer"):
                self.check(self.source.replace(original, needs + marker, 1))
        for inputs in ("      source_sha: historical", "      case: socks-wg-server", "      platform: amd64"):
            with self.subTest(inputs=inputs), self.assertRaisesRegex(AssertionError, "no-input same-SHA"):
                self.check(self.source.replace(marker, marker + "\n    with:\n" + inputs, 1))

    def test_linux_imported_execution_requires_original_runtime_and_full_native_workflow(self):
        marker = "    uses: ./.github/workflows/linux-imported-execution-host.yml"
        self.assertEqual(self.source.count(marker), 1)
        for replacement in (
            "    uses: ./.github/workflows/linux-node-child-tun.yml",
            "    runs-on: ubuntu-24.04",
            marker + "\n" + marker,
        ):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(AssertionError, "actual installed Linux imported Shadowsocks"):
                self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")
        original = "    needs: native-runtimes\n" + marker
        self.assertEqual(self.source.count(original), 1)
        for needs in ("", "    needs: source-audit\n", "    needs: native-runtimes\n    needs: source-audit\n"):
            with self.subTest(needs=needs), self.assertRaisesRegex(AssertionError, "current-run runtime producer"):
                self.check(self.source.replace(original, needs + marker, 1))
        for inputs in ("      source_sha: historical", "      case: ss-p1-server", "      platform: amd64"):
            with self.subTest(inputs=inputs), self.assertRaisesRegex(AssertionError, "no-input same-SHA"):
                self.check(self.source.replace(marker, marker + "\n    with:\n" + inputs, 1))

    def test_unix_naive_h2_requires_original_runtime_and_full_native_workflow(self):
        marker = "    uses: ./.github/workflows/unix-naive-h2-host.yml"
        self.assertEqual(self.source.count(marker), 1)
        for replacement in (
            "    uses: ./.github/workflows/imported-naive-h2-native.yml",
            "    runs-on: ubuntu-24.04",
            marker + "\n" + marker,
        ):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(AssertionError, "actual installed Unix Naive H2"):
                self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")
        original = "    needs: native-runtimes\n" + marker
        self.assertEqual(self.source.count(original), 1)
        for needs in ("", "    needs: source-audit\n", "    needs: native-runtimes\n    needs: source-audit\n"):
            with self.subTest(needs=needs), self.assertRaisesRegex(AssertionError, "current-run runtime producer"):
                self.check(self.source.replace(original, needs + marker, 1))
        for inputs in ("      source_sha: historical", "      case: naive-h2/public-connect", "      platform: amd64"):
            with self.subTest(inputs=inputs), self.assertRaisesRegex(AssertionError, "no-input same-SHA"):
                self.check(self.source.replace(marker, marker + "\n    with:\n" + inputs, 1))

    def test_windows_connect_execution_requires_original_runtime_and_full_native_workflow(self):
        marker = "    uses: ./.github/workflows/windows-connect-execution-host.yml"
        self.assertEqual(self.source.count(marker), 1)
        for replacement in (
            "    uses: ./.github/workflows/windows-native-smoke.yml",
            "    runs-on: ubuntu-24.04",
            marker + "\n" + marker,
        ):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(AssertionError, "actual installed Windows CONNECT"):
                self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")
        original = "    needs: native-runtimes\n" + marker
        self.assertEqual(self.source.count(original), 1)
        for needs in ("", "    needs: source-audit\n", "    needs: native-runtimes\n    needs: source-audit\n"):
            with self.subTest(needs=needs), self.assertRaisesRegex(AssertionError, "current-run runtime producer"):
                self.check(self.source.replace(original, needs + marker, 1))
        for inputs in ("      source_sha: historical", "      case: http-wg-server", "      platform: amd64"):
            with self.subTest(inputs=inputs), self.assertRaisesRegex(AssertionError, "no-input same-SHA"):
                self.check(self.source.replace(marker, marker + "\n    with:\n" + inputs, 1))

    def test_openvpn_prefix_requires_actual_same_sha_workflow(self):
        marker = "    uses: ./.github/workflows/openvpn-node-chain-prefix.yml"
        self.assertEqual(self.source.count(marker), 1)
        for replacement in ("    uses: ./.github/workflows/server-node-chain-encrypted.yml",
                            "    runs-on: ubuntu-24.04", marker + "\n" + marker):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(AssertionError, "actual encrypted OpenVPN prefix"):
                self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")
        for inputs in ("      source_sha: historical", "      mode: wg", "      network: tcp"):
            with self.subTest(inputs=inputs), self.assertRaisesRegex(AssertionError, "no-input same-SHA"):
                self.check(self.source.replace(marker, marker + "\n    with:\n" + inputs, 1))

    def test_ss_prefix_requires_actual_same_sha_workflow(self):
        marker = "    uses: ./.github/workflows/ss-node-chain-prefix.yml"
        self.assertEqual(self.source.count(marker), 1)
        for replacement in ("    uses: ./.github/workflows/server-node-chain-encrypted.yml",
                            "    runs-on: ubuntu-24.04", marker + "\n" + marker):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(AssertionError, "actual encrypted SS prefix"):
                self.check(self.source.replace(marker, replacement, 1) + "\n# " + marker + "\n")
        for inputs in ("      source_sha: historical", "      mode: wg", "      network: tcp"):
            with self.subTest(inputs=inputs), self.assertRaisesRegex(AssertionError, "no-input same-SHA"):
                self.check(self.source.replace(marker, marker + "\n    with:\n" + inputs, 1))

    def test_encrypted_server_native_platform_sha_and_receipts_are_required(self):
        check = shipping_check("check_server_encrypted_workflow")
        source = (ROOT / ".github/workflows/server-node-chain-encrypted.yml").read_text()
        check(source)
        changes = (
            ("          - arch: arm64\n            runner: ubuntu-24.04-arm\n", ""),
            ("          - arch: amd64\n            runner: ubuntu-24.04\n", ""),
            ("          persist-credentials: false", "          persist-credentials: false\n          ref: historical"),
            ("  workflow_call:\n", "  workflow_call:\n    inputs: {}\n"),
            ("  encrypted:\n", "  encrypted:\n    if: false\n"),
            ("  encrypted:\n", "  encrypted:\n    continue-on-error: true\n"),
            ("          if-no-files-found: error", "          if-no-files-found: ignore"),
        )
        for old, new in changes:
            self.assertEqual(source.count(old), 1)
            with self.subTest(old=old), self.assertRaises(AssertionError):
                check(source.replace(old, new, 1))
        caller = (ROOT / "deploy/release-orchestration-audit.py").read_text()
        self.assertEqual(caller.count('"deploy/test_server_node_chain_encrypted_runner.py"'), 1)
        self.assertEqual(caller.count('"deploy/test_server_node_chain_connect_encrypted_runner.py"'), 1)
        tree = ast.parse(AUDIT.read_text())
        calls = [node for node in tree.body if isinstance(node, ast.Expr)
                 and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                 and node.value.func.id == "check_server_encrypted_workflow"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.unparse(calls[0].value), "check_server_encrypted_workflow(read('.github/workflows/server-node-chain-encrypted.yml'))")

    def test_both_server_runners_precede_connect_then_original_native_and_upload(self):
        check = shipping_check("check_server_encrypted_workflow")
        source = (ROOT / ".github/workflows/server-node-chain-encrypted.yml").read_text()
        check(source)
        lines = source.splitlines(keepends=True)
        starts = [i for i, line in enumerate(lines) if line.startswith('      - ')]
        prefix = ''.join(lines[:starts[0]])
        blocks = [''.join(lines[a:b]) for a, b in zip(starts, starts[1:] + [len(lines)])]
        markers = (
            'run: python3 deploy/test_server_node_chain_encrypted_runner.py',
            'run: python3 deploy/test_server_node_chain_connect_encrypted_runner.py',
            'python3 deploy/test_server_node_chain_connect_encrypted.py --standalone',
            'python3 deploy/test_server_node_chain_encrypted.py --standalone',
            'uses: actions/upload-artifact@v4',
        )
        indices = []
        for marker in markers:
            matching = [i for i, block in enumerate(blocks) if marker in block]
            self.assertEqual(len(matching), 1, marker)
            indices.append(matching[0])
        self.assertEqual(indices, sorted(indices))
        # Every inversion of the five captured boundaries must fail, while
        # preserving each complete original step, command, receipt and budget.
        for position, first in enumerate(indices):
            for second in indices[position + 1:]:
                changed = list(blocks)
                changed[first], changed[second] = changed[second], changed[first]
                with self.subTest(first=first, second=second), self.assertRaisesRegex(AssertionError, "runners/native phases reordered"):
                    check(prefix + ''.join(changed))

    def test_each_original_and_connect_server_invocation_is_independently_required(self):
        check = shipping_check("check_server_encrypted_workflow")
        source = (ROOT / ".github/workflows/server-node-chain-encrypted.yml").read_text()
        check(source)
        for stem, variable, receipt in (
            ('test_server_node_chain_encrypted', 'ROUTERVPN_SERVER_RECEIPT', 'server-node-chain'),
            ('test_server_node_chain_connect_encrypted', 'ROUTERVPN_CONNECT_SERVER_RECEIPT', 'server-connect-node-chain'),
        ):
            command = ('          python3 deploy/' + stem + '.py --standalone --require-commit '
                       '"$ROUTERVPN_EXPECTED_SOURCE" --receipt "$' + variable + '"')
            at = source.index(command)
            start = source.rfind('      - name:', 0, at)
            end = source.index('      - ', at)
            block = source[start:end]
            changes = (
                (block, ''), (block, block + block),
                (block, block.replace('ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}', 'ROUTERVPN_EXPECTED_SOURCE: historical')),
                (block, block.replace('        env:', '        if: false\n        env:')),
                (block, block.replace('        env:', '        continue-on-error: true\n        env:')),
                (block, block.replace('        env:', '        "if": false\n        env:')),
                (block, block.replace('        env:', '        "\\x69f": false\n        env:')),
                (block, block.replace('--standalone', '--compile-only')),
                (block, block.replace(command, command + ' || true')),
                (block, block.replace('timeout-minutes: 45', 'timeout-minutes: 1')),
                (block, block.replace('--receipt "$' + variable + '"', '--receipt "$FOREIGN_RECEIPT"')),
                ('        run: python3 deploy/' + stem + '_runner.py', '        run: echo omitted-runner'),
                ('            ${{ runner.temp }}/' + receipt + '-${{ matrix.arch }}.json\n', ''),
            )
            for old, new in changes:
                self.assertEqual(source.count(old), 1)
                with self.subTest(stem=stem, mutation=new), self.assertRaises(AssertionError):
                    check(source.replace(old, new, 1))
        upload_path = '          path: |\n'
        for extra in ('            foreign.json\n',
                      '            ${{ runner.temp }}/server-node-chain-${{ matrix.arch }}.json\n'):
            with self.subTest(extra=extra), self.assertRaises(AssertionError):
                check(source.replace(upload_path, upload_path + extra, 1))
        marker = '  encrypted:\n'
        for key in ('"if"', '"\\x69f"', "'continue-on-error'"):
            with self.subTest(quoted=key), self.assertRaises(AssertionError):
                check(source.replace(marker, marker + '    ' + key + ': true\n', 1))

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

    def test_darwin_prefix_host_is_required_from_exact_successful_producer(self):
        marker = "    needs: native-runtimes\n    uses: ./.github/workflows/darwin-node-prefix-host-tun.yml"
        for changed, witness in (
            (marker.replace("darwin-node-prefix-host-tun", "darwin-node-host-tun"), "actual installed closed Darwin prefix"),
            (marker.replace("    needs: native-runtimes\n", ""), "successful current-run runtime producer"),
            (marker.replace("needs: native-runtimes", "needs: source-audit"), "successful current-run runtime producer")):
            with self.subTest(changed=changed), self.assertRaisesRegex(AssertionError, witness):
                self.check(self.source.replace(marker, changed, 1))
        with self.assertRaisesRegex(AssertionError, "complete required gate inventory"):
            self.check(self.source.replace("darwin-prefix-host, ", "", 1))


if __name__ == "__main__":
    unittest.main()
