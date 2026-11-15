#!/usr/bin/env python3
"""Require both installed paired hosts in the authoritative artifact workflow."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/darwin-node-host-tun.yml"
INPUTS = ("deploy/test_macos_paired_node_host.py", "deploy/test_macos_paired_node_host_runner.py",
          "deploy/test_darwin_paired_transport_context.py", "deploy/test_darwin_paired_host_workflow.py", WORKFLOW)
EXTRACT = "python3 deploy/native-runtime-bundle.py extract 'darwin/${{ matrix.arch }}' \"$RUNNER_TEMP/paired-host-bundle/native-darwin-${{ matrix.arch }}.tar.gz\" \"$RUNNER_TEMP/paired-host-verified\""
NATIVE = 'python3 deploy/test_macos_paired_node_host.py --bundle "$RUNNER_TEMP/paired-host-verified" --require-commit "$ROUTERVPN_EXPECTED_SOURCE" --receipt "$ROUTERVPN_PAIRED_HOST_RECEIPT"'


def unique_block(source, marker, end):
    if source.count(marker) != 1:
        raise AssertionError("missing or duplicated paired host boundary: " + marker.strip())
    return source.split(marker, 1)[1].split(end, 1)[0]


def unique_job(source, name):
    jobs = re.findall(r"(?ms)^  " + re.escape(name) + r":\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", source)
    if len(jobs) != 1:
        raise AssertionError("missing or duplicated mandatory job: " + name)
    return jobs[0]


def check(source, release, builder):
    job = unique_job(source, "paired-host")
    if re.search(r"(?m)^\s+(?:(?:if|continue-on-error)\s*:|[\'\"][^\n]*[\'\"]\s*:)", job):
        raise AssertionError("paired host cannot be conditional or nonblocking")
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
        raise AssertionError("paired host lost both original architecture runners or finite budget")
    gate = unique_block(steps, "      - name: Require complete paired host inventory and authoritative workflow\n", "      - ")
    if gate != """        run: |
          python3 deploy/test_macos_paired_node_host_runner.py
          python3 deploy/test_darwin_paired_host_workflow.py
""":
        raise AssertionError("paired host omitted its strict inventory and workflow controls")
    download = unique_block(steps, "      - uses: actions/download-artifact@v4\n", "      - ")
    if download != """        with:
          name: RouterVPN-native-runtime-darwin-${{ matrix.arch }}-${{ github.sha }}
          path: ${{ runner.temp }}/paired-host-bundle
""":
        raise AssertionError("paired host must consume only its current caller's exact native bundle")
    extract = unique_block(steps, "      - name: Verify exact-source paired runtime bundle\n", "      - ")
    if extract != "        run: " + EXTRACT + "\n":
        raise AssertionError("paired host lost exact native bundle extraction")
    native = unique_block(steps, "      - name: Require real paired graphs, protection, measurements and cancellation\n", "      - ")
    expected_native = """        timeout-minutes: 110
        env:
          ROUTERVPN_DARWIN_PAIRED_NODE_HOST_ACCEPTANCE: '1'
          ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}
          ROUTERVPN_PAIRED_HOST_RECEIPT: ${{ runner.temp }}/darwin-paired-node-host-${{ matrix.arch }}.json
          CGO_ENABLED: '1'
        run: |
          """ + NATIVE + "\n"
    if native != expected_native:
        raise AssertionError("paired host lost unfiltered actual execution or exact source receipt")
    upload = unique_block(steps, "      - uses: actions/upload-artifact@v4\n", "      - ")
    if upload.strip() != """with:
          name: RouterVPN-Darwin-paired-host-${{ matrix.arch }}-${{ github.sha }}
          path: ${{ runner.temp }}/darwin-paired-node-host-${{ matrix.arch }}.json
          if-no-files-found: error
          retention-days: 14""":
        raise AssertionError("paired host receipt must be required and distinct from ordered evidence")
    call = unique_job(release, "darwin-ordered-host")
    if "    needs: native-runtimes\n" not in call or "    uses: ./" + WORKFLOW not in call or re.search(r"(?m)^\s+(?:(?:if|continue-on-error)\s*:|[\'\"][^\n]*[\'\"]\s*:)", call):
        raise AssertionError("paired host lost its authoritative current-run producer dependency")
    aggregate = unique_job(release, "aggregate")
    needs = re.search(r"(?m)^    needs: \[([^\n]+)\]$", aggregate)
    if needs is None or "darwin-ordered-host" not in [name.strip() for name in needs[1].split(",")]:
        raise AssertionError("aggregate verification omitted the paired host workflow")
    for path in INPUTS:
        if builder.count("ROOT/'" + path + "'") != 1:
            raise AssertionError("paired host lost original source identity input: " + path)


class PairedHostWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / WORKFLOW).read_text()
        self.release = (ROOT / ".github/workflows/release-candidate.yml").read_text()
        self.builder = (ROOT / "deploy/build-native-runtime.py").read_text()

    def test_shipping_both_native_hosts_and_exact_receipts_are_required(self):
        check(self.source, self.release, self.builder)

    def test_missing_duplicate_skipped_and_single_architecture_job_are_rejected(self):
        for changed in (
            self.source.replace("  paired-host:\n", "  omitted-host:\n", 1),
            self.source + "\n  paired-host:\n    runs-on: macos-15\n",
            self.source.replace("  paired-host:\n", "  paired-host:\n    if: false\n", 1),
            self.source.replace("  paired-host:\n", "  paired-host:\n    continue-on-error: true\n", 1),
            self.source.replace("  paired-host:\n", "  paired-host:\n    runs-on: ubuntu-latest\n", 1),
            self.source.replace("  paired-host:\n" + unique_job(self.source, "paired-host"),
                "  paired-host:\n" + unique_job(self.source, "paired-host").replace(
                    "          - arch: arm64\n            runner: macos-15\n", "", 1), 1),
        ):
            with self.subTest(changed=changed[-200:]), self.assertRaises(AssertionError):
                check(changed, self.release, self.builder)

    def test_foreign_bundle_filtered_native_command_or_missing_receipt_is_rejected(self):
        for old, new in (
            ("          path: ${{ runner.temp }}/paired-host-bundle", "          path: ${{ runner.temp }}/paired-host-bundle\n          run-id: 12345"),
            (EXTRACT, "true"), (NATIVE, NATIVE + " || true"), (NATIVE, "true"),
            (NATIVE, NATIVE + " --case only-one"),
            ("ROUTERVPN_DARWIN_PAIRED_NODE_HOST_ACCEPTANCE: '1'", "ROUTERVPN_DARWIN_PAIRED_NODE_HOST_ACCEPTANCE: '0'"),
            ("          python3 deploy/test_macos_paired_node_host_runner.py", "          true"),
            ("          name: RouterVPN-Darwin-paired-host-", "          name: RouterVPN-Darwin-ordered-host-"),
            ("          path: ${{ runner.temp }}/darwin-paired-node-host-${{ matrix.arch }}.json", "          path: missing.json"),
        ):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                check(self.source.replace(old, new, 1), self.release, self.builder)

    def test_source_identity_and_release_dependency_cannot_be_removed(self):
        for path in INPUTS:
            with self.subTest(path=path), self.assertRaises(AssertionError):
                check(self.source, self.release, self.builder.replace("ROOT/'" + path + "'", "ROOT/'omitted.py'", 1))
        marker = "    needs: native-runtimes\n    uses: ./" + WORKFLOW
        with self.assertRaises(AssertionError):
            check(self.source, self.release.replace(marker, "    uses: ./" + WORKFLOW, 1), self.builder)
        with self.assertRaises(AssertionError):
            check(self.source, self.release.replace(", darwin-ordered-host,", ", omitted-host,", 1), self.builder)

    def test_quoted_optional_keys_cannot_bypass_required_paired_host(self):
        for key in ("'if'", '"continue-on-error"', '"\\x69f"'):
            with self.subTest(key=key, location="native"), self.assertRaises(AssertionError):
                check(self.source.replace("  paired-host:\n", "  paired-host:\n    " + key + ": false\n", 1), self.release, self.builder)
            with self.subTest(key=key, location="caller"), self.assertRaises(AssertionError):
                check(self.source, self.release.replace("  darwin-ordered-host:\n", "  darwin-ordered-host:\n    " + key + ": false\n", 1), self.builder)


if __name__ == "__main__":
    unittest.main()
