#!/usr/bin/env python3
"""Require both installed IMPORTED execution hosts before authoritative publication."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/linux-imported-execution-host.yml"
JOB = "host"
INPUTS = ("deploy/test_linux_imported_execution_host.py",
          "deploy/test_linux_imported_execution_host_runner.py",
          "deploy/test_linux_imported_execution_workflow.py", WORKFLOW)
EXTRACT = "python3 deploy/native-runtime-bundle.py extract 'linux/${{ matrix.arch }}' \"$RUNNER_TEMP/imported-execution-host-bundle/native-linux-${{ matrix.arch }}.tar.gz\" \"$RUNNER_TEMP/imported-execution-host-verified\""
NATIVE = 'python3 deploy/test_linux_imported_execution_host.py --bundle "$RUNNER_TEMP/imported-execution-host-verified" --require-commit "$ROUTERVPN_EXPECTED_SOURCE" --receipt "$ROUTERVPN_IMPORTED_EXECUTION_RECEIPT"'


def unique_job(source, name):
    matches = re.findall(r"(?ms)^  " + re.escape(name) + r":\n(.*?)(?=^  [A-Za-z][\w-]*:\n|\Z)", source)
    if len(matches) != 1:
        raise AssertionError("missing or duplicate IMPORTED execution dependency: " + name)
    return matches[0]


def unique_block(source, marker):
    if source.count(marker) != 1:
        raise AssertionError("missing or duplicate IMPORTED execution step: " + marker.strip())
    return source.split(marker, 1)[1].split("      - ", 1)[0]


def check(source, release, builder):
    job = unique_job(source, JOB)
    if re.search(r"(?m)^\s+(?:(?:if|continue-on-error)\s*:|[\'\"][^\n]*[\'\"]\s*:)", job):
        raise AssertionError("IMPORTED execution host cannot be optional or nonblocking")
    header, steps = job.split("    steps:\n", 1)
    expected_matrix = """    runs-on: ${{ matrix.runner }}
    timeout-minutes: 120
    strategy:
      fail-fast: false
      matrix:
        include:
          - arch: amd64
            runner: ubuntu-24.04
          - arch: arm64
            runner: ubuntu-24.04-arm
"""
    if not header.endswith(expected_matrix) or header.count("    runs-on:") != 1:
        raise AssertionError("IMPORTED execution lost an original architecture or finite job budget")
    checkout = unique_block(steps, "      - uses: actions/checkout@v4\n")
    if checkout != "        with:\n          persist-credentials: false\n":
        raise AssertionError("IMPORTED execution must check out the current caller's exact source")
    preparation = unique_block(steps, "      - name: Install native namespace and compilation tools\n")
    if preparation != """        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends build-essential git iproute2 nftables util-linux uidmap sudo passwd
          test -c /dev/net/tun
""":
        raise AssertionError("IMPORTED execution lost real namespace, firewall or existing TUN prerequisites")
    controls = unique_block(steps, "      - name: Require imported Shadowsocks execution inventory, cleanup controls and authoritative workflow\n")
    if controls != """        run: |
          python3 deploy/test_linux_imported_execution_host_runner.py
          python3 deploy/test_linux_imported_execution_workflow.py
""":
        raise AssertionError("IMPORTED execution omitted exact native inventory or cleanup controls")
    download = unique_block(steps, "      - uses: actions/download-artifact@v4\n")
    if download != """        with:
          name: RouterVPN-native-runtime-linux-${{ matrix.arch }}-${{ github.sha }}
          path: ${{ runner.temp }}/imported-execution-host-bundle
""":
        raise AssertionError("IMPORTED execution must consume the current caller's exact native bundle")
    extract = unique_block(steps, "      - name: Verify exact-source imported Shadowsocks execution runtime bundle\n")
    if extract != "        run: " + EXTRACT + "\n":
        raise AssertionError("IMPORTED execution lost exact native bundle verification")
    native = unique_block(steps, "      - name: Require real imported Shadowsocks Server, both Compare winners and retained restoration\n")
    if native != """        timeout-minutes: 110
        env:
          ROUTERVPN_LINUX_IMPORTED_EXECUTION_HOST_ACCEPTANCE: '1'
          ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}
          ROUTERVPN_IMPORTED_EXECUTION_RECEIPT: ${{ runner.temp }}/linux-imported-execution-host-${{ matrix.arch }}.json
          CGO_ENABLED: '1'
        run: |
          """ + NATIVE + "\n":
        raise AssertionError("IMPORTED execution lost unfiltered installed execution or source identity")
    upload = unique_block(steps, "      - uses: actions/upload-artifact@v4\n")
    if upload.strip() != """with:
          name: RouterVPN-Linux-imported-execution-host-${{ matrix.arch }}-${{ github.sha }}
          path: ${{ runner.temp }}/linux-imported-execution-host-${{ matrix.arch }}.json
          if-no-files-found: error
          retention-days: 14""":
        raise AssertionError("IMPORTED execution requires its own complete native receipt")
    caller = unique_job(release, "linux-imported-execution-host")
    if "    needs: native-runtimes\n" not in caller or "    uses: ./" + WORKFLOW not in caller or re.search(r"(?m)^\s+(?:(?:if|continue-on-error)\s*:|[\'\"][^\n]*[\'\"]\s*:)", caller):
        raise AssertionError("IMPORTED execution lost its required current-run runtime producer")
    aggregate = unique_job(release, "aggregate")
    needs = re.search(r"(?m)^    needs: \[([^\n]+)\]$", aggregate)
    if needs is None or "linux-imported-execution-host" not in [name.strip() for name in needs[1].split(",")]:
        raise AssertionError("release verification omitted installed IMPORTED execution")
    for path in INPUTS:
        if builder.count("ROOT/'" + path + "'") != 1:
            raise AssertionError("IMPORTED execution lost exact source identity input: " + path)


class IMPORTEDExecutionWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / WORKFLOW).read_text()
        self.release = (ROOT / ".github/workflows/release-candidate.yml").read_text()
        self.builder = (ROOT / "deploy/build-native-runtime.py").read_text()

    def test_both_original_native_targets_and_exact_receipts_are_mandatory(self):
        check(self.source, self.release, self.builder)

    def test_missing_duplicate_conditional_and_foreign_architecture_are_rejected(self):
        body = unique_job(self.source, JOB)
        for changed in (
            self.source.replace("  " + JOB + ":\n", "  omitted-host:\n", 1),
            self.source + "\n  " + JOB + ":\n" + body,
            self.source.replace("  " + JOB + ":\n", "  " + JOB + ":\n    if: false\n", 1),
            self.source.replace("  " + JOB + ":\n", "  " + JOB + ":\n    continue-on-error: true\n", 1),
            self.source.replace(body, body.replace("runner: ubuntu-24.04", "runner: ubuntu-latest", 1), 1),
            self.source.replace(body, body.replace("          - arch: arm64\n            runner: ubuntu-24.04-arm\n", "", 1), 1),
        ):
            with self.subTest(changed=changed[-200:]), self.assertRaises(AssertionError):
                check(changed, self.release, self.builder)

    def test_foreign_bundle_filtered_command_or_missing_owned_receipt_is_rejected(self):
        body = unique_job(self.source, JOB)
        for old, new in (
            ("          path: ${{ runner.temp }}/imported-execution-host-bundle", "          path: ${{ runner.temp }}/imported-execution-host-bundle\n          run-id: 12345"),
            (EXTRACT, "true"), (NATIVE, "true"), (NATIVE, NATIVE + " || true"),
            (NATIVE, NATIVE + " --case wg-server"),
            ("ROUTERVPN_LINUX_IMPORTED_EXECUTION_HOST_ACCEPTANCE: '1'", "ROUTERVPN_LINUX_IMPORTED_EXECUTION_HOST_ACCEPTANCE: '0'"),
            ("          python3 deploy/test_linux_imported_execution_host_runner.py", "          true"),
            ("          name: RouterVPN-Linux-imported-execution-host-", "          name: RouterVPN-Linux-paired-host-"),
            ("          path: ${{ runner.temp }}/linux-imported-execution-host-${{ matrix.arch }}.json", "          path: missing.json"),
        ):
            self.assertIn(old, body)
            with self.subTest(old=old), self.assertRaises(AssertionError):
                check(self.source.replace(body, body.replace(old, new, 1), 1), self.release, self.builder)

    def test_source_identity_and_authoritative_dependency_cannot_be_removed(self):
        for path in INPUTS:
            with self.subTest(path=path), self.assertRaises(AssertionError):
                check(self.source, self.release, self.builder.replace("ROOT/'" + path + "'", "ROOT/'omitted.py'", 1))
        marker = "    needs: native-runtimes\n    uses: ./" + WORKFLOW
        with self.assertRaises(AssertionError):
            check(self.source, self.release.replace(marker, "    uses: ./" + WORKFLOW, 1), self.builder)
        with self.assertRaises(AssertionError):
            check(self.source, self.release.replace(", linux-imported-execution-host,", ", omitted-host,", 1), self.builder)

    def test_same_source_checkout_and_real_namespace_prerequisites_are_required(self):
        for before, after in (
            ("          persist-credentials: false", "          persist-credentials: false\n          ref: historical"),
            ("          test -c /dev/net/tun", "          true"),
            ("git iproute2 nftables", "git"),
            ("      - name: Install native namespace and compilation tools\n", "      - name: Omitted namespace preparation\n"),
        ):
            self.assertEqual(self.source.count(before), 1)
            with self.subTest(before=before), self.assertRaises(AssertionError):
                check(self.source.replace(before, after, 1), self.release, self.builder)

    def test_quoted_optional_keys_cannot_bypass_required_job_or_caller(self):
        # These contracts have no quoted mapping keys. Rejecting that entire
        # spelling family also catches YAML escape sequences inside keys.
        for key in ("'if'", '"continue-on-error"', '"\\x69f"'):
            with self.subTest(key=key, location="native"), self.assertRaises(AssertionError):
                check(self.source.replace("  " + JOB + ":\n", "  " + JOB + ":\n    " + key + ": false\n", 1), self.release, self.builder)
            with self.subTest(key=key, location="caller"), self.assertRaises(AssertionError):
                check(self.source, self.release.replace("  linux-imported-execution-host:\n", "  linux-imported-execution-host:\n    " + key + ": false\n", 1), self.builder)


    def test_shipping_artifact_audit_calls_the_complete_imported_host_guard(self):
        import ast
        source = (ROOT / "deploy/native-artifact-workflow-parity-audit.py").read_text()
        def captures(value):
            tree = ast.parse(value)
            return [ast.unparse(node.value) for node in tree.body
                    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == "check_linux_imported_execution_host_workflow"]
        expected = "check_linux_imported_execution_host_workflow(read('" + WORKFLOW + "'), rc, read('deploy/build-native-runtime.py'))"
        self.assertEqual(captures(source), [expected])
        marker = 'check_linux_imported_execution_host_workflow(read("' + WORKFLOW + '"), rc, read("deploy/build-native-runtime.py"))'
        self.assertEqual(source.count(marker), 1)
        for changed in (source.replace(marker, "pass", 1), source.replace(marker, marker + "\n" + marker, 1),
                        source.replace(marker, marker.replace("rc", '"unrelated-release"'), 1)):
            self.assertNotEqual(captures(changed), [expected])


if __name__ == "__main__":
    unittest.main()
