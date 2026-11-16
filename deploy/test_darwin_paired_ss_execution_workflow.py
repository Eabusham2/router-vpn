#!/usr/bin/env python3
"""Require both installed paired-two-node hosts before authoritative publication."""
from pathlib import Path
import re
import ast
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/darwin-node-host-tun.yml"
JOB = "paired-ss-execution-host"
INPUTS = ("deploy/test_macos_paired_ss_execution_host.py",
          "deploy/test_macos_paired_ss_execution_host_runner.py",
          "deploy/test_macos_imported_execution_alias.py",
          "deploy/test_macos_imported_execution_alias_runner.py",
          "deploy/test_darwin_paired_ss_execution_workflow.py", WORKFLOW)
EXTRACT = "python3 deploy/native-runtime-bundle.py extract 'darwin/${{ matrix.arch }}' \"$RUNNER_TEMP/paired-ss-execution-host-bundle/native-darwin-${{ matrix.arch }}.tar.gz\" \"$RUNNER_TEMP/paired-ss-execution-host-verified\""
NATIVE = 'python3 deploy/test_macos_paired_ss_execution_host.py --bundle "$RUNNER_TEMP/paired-ss-execution-host-verified" --require-commit "$ROUTERVPN_EXPECTED_SOURCE" --receipt "$ROUTERVPN_PAIRED_SS_EXECUTION_RECEIPT"'


def unique_job(source, name):
    matches = re.findall(r"(?ms)^  " + re.escape(name) + r":\n(.*?)(?=^  [A-Za-z][\w-]*:\n|\Z)", source)
    if len(matches) != 1:
        raise AssertionError("missing or duplicate paired SS execution dependency: " + name)
    return matches[0]


def unique_block(source, marker):
    if source.count(marker) != 1:
        raise AssertionError("missing or duplicate paired SS execution step: " + marker.strip())
    return source.split(marker, 1)[1].split("      - ", 1)[0]



def check_parity(source):
    tree = ast.parse(source)
    name = "check_paired_ss_execution_host_workflow"
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    calls = [node for node in tree.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
             and isinstance(node.value.func, ast.Name) and node.value.func.id == name]
    if len(functions) != 1 or len(calls) != 1:
        raise AssertionError("independent publication audit omitted paired SS installed job")
    expected = ast.parse('check_paired_ss_execution_host_workflow(read(".github/workflows/darwin-node-host-tun.yml"), rc, read("deploy/build-native-runtime.py"))').body[0]
    if ast.dump(calls[0]) != ast.dump(expected) or 'deploy/test_darwin_paired_ss_execution_workflow.py' not in ast.get_source_segment(source, functions[0]):
        raise AssertionError("paired SS publication audit borrowed another workflow or guard")


def check(source, release, builder):
    check_parity((ROOT/"deploy/native-artifact-workflow-parity-audit.py").read_text())
    job = unique_job(source, JOB)
    if re.search(r"(?m)^\s+(?:(?:if|continue-on-error)\s*:|[\'\"][^\n]*[\'\"]\s*:)", job):
        raise AssertionError("paired SS execution host cannot be optional or nonblocking")
    header, steps = job.split("    steps:\n", 1)
    expected_matrix = """    runs-on: ${{ matrix.runner }}
    timeout-minutes: 120
    strategy:
      fail-fast: false
      matrix:
        include:
          - arch: amd64
            runner: macos-15-intel
          - arch: arm64
            runner: macos-15
"""
    if not header.endswith(expected_matrix) or header.count("    runs-on:") != 1:
        raise AssertionError("paired SS execution lost an original architecture or finite job budget")
    controls = unique_block(steps, "      - name: Require paired SS execution inventory, cleanup controls and authoritative workflow\n")
    if controls != """        run: |
          python3 deploy/test_macos_paired_ss_execution_host_runner.py
          python3 deploy/test_macos_imported_execution_alias_runner.py
          python3 deploy/test_darwin_paired_ss_execution_workflow.py
""":
        raise AssertionError("paired SS execution omitted exact native inventory or cleanup controls")
    download = unique_block(steps, "      - uses: actions/download-artifact@v4\n")
    if download != """        with:
          name: RouterVPN-native-runtime-darwin-${{ matrix.arch }}-${{ github.sha }}
          path: ${{ runner.temp }}/paired-ss-execution-host-bundle
""":
        raise AssertionError("paired SS execution must consume the current caller's exact native bundle")
    extract = unique_block(steps, "      - name: Verify exact-source paired SS execution runtime bundle\n")
    if extract != "        run: " + EXTRACT + "\n":
        raise AssertionError("paired SS execution lost exact native bundle verification")
    native = unique_block(steps, "      - name: Require real paired SS Server, both Compare winners and retained restoration\n")
    if native != """        timeout-minutes: 110
        env:
          ROUTERVPN_DARWIN_PAIRED_SS_EXECUTION_HOST_ACCEPTANCE: '1'
          ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}
          ROUTERVPN_PAIRED_SS_EXECUTION_RECEIPT: ${{ runner.temp }}/darwin-paired-ss-execution-host-${{ matrix.arch }}.json
          CGO_ENABLED: '1'
        run: |
          """ + NATIVE + "\n":
        raise AssertionError("paired SS execution lost unfiltered installed execution or source identity")
    upload = unique_block(steps, "      - uses: actions/upload-artifact@v4\n")
    if upload.strip() != """with:
          name: RouterVPN-Darwin-paired-ss-execution-host-${{ matrix.arch }}-${{ github.sha }}
          path: ${{ runner.temp }}/darwin-paired-ss-execution-host-${{ matrix.arch }}.json
          if-no-files-found: error
          retention-days: 14""":
        raise AssertionError("paired SS execution requires its own complete native receipt")
    caller = unique_job(release, "darwin-ordered-host")
    if "    needs: native-runtimes\n" not in caller or "    uses: ./" + WORKFLOW not in caller or re.search(r"(?m)^\s+(?:(?:if|continue-on-error)\s*:|[\'\"][^\n]*[\'\"]\s*:)", caller):
        raise AssertionError("paired SS execution lost its required current-run runtime producer")
    aggregate = unique_job(release, "aggregate")
    needs = re.search(r"(?m)^    needs: \[([^\n]+)\]$", aggregate)
    if needs is None or "darwin-ordered-host" not in [name.strip() for name in needs[1].split(",")]:
        raise AssertionError("release verification omitted installed paired SS execution")
    for path in INPUTS:
        if builder.count("ROOT/'" + path + "'") != (2 if path == "deploy/test_darwin_paired_ss_execution_workflow.py" else 1):
            raise AssertionError("paired SS execution lost exact source identity input: " + path)


class ImportedExecutionWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / WORKFLOW).read_text()
        self.release = (ROOT / ".github/workflows/release-candidate.yml").read_text()
        self.builder = (ROOT / "deploy/build-native-runtime.py").read_text()

    def test_publication_audit_cannot_drop_or_filter_installed_job(self):
        source = (ROOT/"deploy/native-artifact-workflow-parity-audit.py").read_text()
        check_parity(source)
        marker = 'check_paired_ss_execution_host_workflow(read(".github/workflows/darwin-node-host-tun.yml"), rc, read("deploy/build-native-runtime.py"))'
        for changed in (source.replace(marker, 'None', 1), source+'\n'+marker+'\n', source.replace(marker, marker.replace('rc,', '"foreign",'), 1)):
            with self.assertRaises(AssertionError): check_parity(changed)

    def test_both_original_native_targets_and_exact_receipts_are_mandatory(self):
        check(self.source, self.release, self.builder)

    def test_missing_duplicate_conditional_and_foreign_architecture_are_rejected(self):
        body = unique_job(self.source, JOB)
        for changed in (
            self.source.replace("  " + JOB + ":\n", "  omitted-host:\n", 1),
            self.source + "\n  " + JOB + ":\n" + body,
            self.source.replace("  " + JOB + ":\n", "  " + JOB + ":\n    if: false\n", 1),
            self.source.replace("  " + JOB + ":\n", "  " + JOB + ":\n    continue-on-error: true\n", 1),
            self.source.replace(body, body.replace("runner: macos-15-intel", "runner: ubuntu-latest", 1), 1),
            self.source.replace(body, body.replace("          - arch: arm64\n            runner: macos-15\n", "", 1), 1),
        ):
            with self.subTest(changed=changed[-200:]), self.assertRaises(AssertionError):
                check(changed, self.release, self.builder)

    def test_foreign_bundle_filtered_command_or_missing_owned_receipt_is_rejected(self):
        for old, new in (
            ("          path: ${{ runner.temp }}/paired-ss-execution-host-bundle", "          path: ${{ runner.temp }}/paired-ss-execution-host-bundle\n          run-id: 12345"),
            (EXTRACT, "true"), (NATIVE, "true"), (NATIVE, NATIVE + " || true"),
            (NATIVE, NATIVE + " --case wg-server"),
            ("ROUTERVPN_DARWIN_PAIRED_SS_EXECUTION_HOST_ACCEPTANCE: '1'", "ROUTERVPN_DARWIN_PAIRED_SS_EXECUTION_HOST_ACCEPTANCE: '0'"),
            ("          python3 deploy/test_macos_paired_ss_execution_host_runner.py", "          true"),
            ("          python3 deploy/test_macos_imported_execution_alias_runner.py", "          true"),
            ("          name: RouterVPN-Darwin-paired-ss-execution-host-", "          name: RouterVPN-Darwin-paired-host-"),
            ("          path: ${{ runner.temp }}/darwin-paired-ss-execution-host-${{ matrix.arch }}.json", "          path: missing.json"),
        ):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                body = unique_job(self.source, JOB)
                check(self.source.replace(body, body.replace(old, new, 1), 1), self.release, self.builder)

    def test_source_identity_and_authoritative_dependency_cannot_be_removed(self):
        for path in INPUTS:
            with self.subTest(path=path), self.assertRaises(AssertionError):
                check(self.source, self.release, self.builder.replace("ROOT/'" + path + "'", "ROOT/'omitted.py'", 1))
        marker = "    needs: native-runtimes\n    uses: ./" + WORKFLOW
        with self.assertRaises(AssertionError):
            check(self.source, self.release.replace(marker, "    uses: ./" + WORKFLOW, 1), self.builder)
        with self.assertRaises(AssertionError):
            check(self.source, self.release.replace(", darwin-ordered-host,", ", omitted-host,", 1), self.builder)

    def test_quoted_optional_keys_cannot_bypass_required_job_or_caller(self):
        # These contracts have no quoted mapping keys. Rejecting that entire
        # spelling family also catches YAML escape sequences inside keys.
        for key in ("'if'", '"continue-on-error"', '"\\x69f"'):
            with self.subTest(key=key, location="native"), self.assertRaises(AssertionError):
                check(self.source.replace("  " + JOB + ":\n", "  " + JOB + ":\n    " + key + ": false\n", 1), self.release, self.builder)
            with self.subTest(key=key, location="caller"), self.assertRaises(AssertionError):
                check(self.source, self.release.replace("  darwin-ordered-host:\n", "  darwin-ordered-host:\n    " + key + ": false\n", 1), self.builder)


if __name__ == "__main__":
    unittest.main()
