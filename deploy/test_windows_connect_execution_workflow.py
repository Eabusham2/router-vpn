#!/usr/bin/env python3
"""Pin the two real Windows CONNECT execution hosts and their same-run bundle."""
from pathlib import Path
import ast
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = '.github/workflows/windows-connect-execution-host.yml'
CALLER = 'windows-connect-execution-host'
INPUTS = (WORKFLOW, 'deploy/test_windows_connect_execution_host.py',
          'deploy/test_windows_connect_execution_host_runner.py',
          'deploy/test_windows_connect_execution_workflow.py',
          'deploy/windows_connect_execution_overlay.py',
          'deploy/fixtures/windows-connect-execution/peer.go',
          'deploy/fixtures/windows-connect-execution/physical.go')
PREFIX = """name: Windows installed CONNECT Server and Compare acceptance

on:
  workflow_call:

permissions:
  contents: read

concurrency:
  group: windows-connect-execution-host-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}
  cancel-in-progress: true

jobs:
"""
HEADER = """    name: Actual CONNECT trio Server and Compare on ${{ matrix.arch }}
    runs-on: ${{ matrix.runner }}
    timeout-minutes: 120
    strategy:
      fail-fast: false
      matrix:
        include:
          - arch: amd64
            runner: windows-latest
            cgo: '1'
          - arch: arm64
            runner: windows-11-arm
            cgo: '0'
    env:
      GOOS: windows
      GOARCH: ${{ matrix.arch }}
      CGO_ENABLED: ${{ matrix.cgo }}
      PYTHONDONTWRITEBYTECODE: '1'
"""
BLOCKS = (
    """      - uses: actions/checkout@v4
        with:
          persist-credentials: false
""",
    """      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
""",
    """      - uses: actions/setup-go@v5
        with:
          go-version: '1.26.3'
          cache: false
""",
    """      - uses: ./.github/actions/go-windows-sockets
""",
    """      - name: Pinned compiler for native AMD64 race checks
        if: matrix.arch == 'amd64'
        shell: pwsh
        run: |
          $ErrorActionPreference = 'Stop'
          $compilerLines = @(python deploy/install-desktop-windows-toolchain.py (Join-Path $env:RUNNER_TEMP 'routervpn-connect-execution-llvm'))
          if ($LASTEXITCODE -ne 0 -or $compilerLines.Count -ne 1) { throw 'Pinned Windows CONNECT compiler installation failed' }
          $compilerBin = [string]$compilerLines[0]
          $compiler = Join-Path $compilerBin 'x86_64-w64-mingw32-clang.exe'
          if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'Pinned Windows CONNECT C compiler is missing' }
          "CC=$compiler" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
          $compilerBin | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append
""",
    """      - name: Require CONNECT execution inventory, cleanup controls and authoritative workflow
        shell: pwsh
        run: |
          python deploy/test_windows_connect_execution_host_runner.py
          if ($LASTEXITCODE -ne 0) { throw 'Windows CONNECT execution inventory or cleanup controls failed' }
          python deploy/test_windows_connect_execution_workflow.py
          if ($LASTEXITCODE -ne 0) { throw 'Windows CONNECT execution workflow contract failed' }
""",
    """      - uses: actions/download-artifact@v4
        with:
          name: RouterVPN-native-runtime-windows-${{ matrix.arch }}-${{ github.sha }}
          path: ${{ runner.temp }}/connect-execution-host-bundle
""",
    """      - name: Verify exact-source CONNECT execution runtime bundle
        shell: pwsh
        run: |
          python deploy/native-runtime-bundle.py extract 'windows/${{ matrix.arch }}' "$env:RUNNER_TEMP/connect-execution-host-bundle/native-windows-${{ matrix.arch }}.tar.gz" "$env:RUNNER_TEMP/connect-execution-host-verified"
          if ($LASTEXITCODE -ne 0) { throw 'Windows CONNECT execution bundle verification failed' }
""",
    """      - name: Require real CONNECT Server, both Compare winners and retained restoration
        timeout-minutes: 110
        shell: pwsh
        env:
          ROUTERVPN_WINDOWS_CONNECT_EXECUTION_NATIVE: '1'
          ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}
          ROUTERVPN_CONNECT_EXECUTION_RECEIPT: ${{ runner.temp }}/windows-connect-trio-execution-${{ matrix.arch }}.json
        run: |
          python deploy/test_windows_connect_execution_host.py --bundle "$env:RUNNER_TEMP/connect-execution-host-verified" --go go --require-commit "$env:ROUTERVPN_EXPECTED_SOURCE" --receipt "$env:ROUTERVPN_CONNECT_EXECUTION_RECEIPT"
          if ($LASTEXITCODE -ne 0) { throw 'Actual Windows CONNECT Server or Compare failed' }
""",
    """      - uses: actions/upload-artifact@v4
        with:
          name: RouterVPN-Windows-connect-execution-host-${{ matrix.arch }}-${{ github.sha }}
          path: ${{ runner.temp }}/windows-connect-trio-execution-${{ matrix.arch }}.json
          if-no-files-found: error
          retention-days: 14
""",
)


def unique_job(source, name):
    matches = re.findall(r'(?ms)^  '+re.escape(name)+r':\n(.*?)(?=^  [A-Za-z][\w-]*:\n|\Z)', source)
    if len(matches) != 1:
        raise AssertionError('missing or duplicate required Windows CONNECT job: '+name)
    return matches[0]


def check(source, release, builder):
    # Exact scoped blocks allow the one architecture-specific compiler setup;
    # they do not allow conditions on native execution, ignored exit statuses,
    # foreign workflow inputs, alternate downloads or extra admission steps.
    if source.split('  host:\n', 1)[0] != PREFIX:
        raise AssertionError('Windows CONNECT lost its exact reusable workflow and source boundary')
    body = unique_job(source, 'host')
    if '    steps:\n' not in body:
        raise AssertionError('Windows CONNECT omitted native execution')
    header, steps = body.split('    steps:\n', 1)
    if header != HEADER:
        raise AssertionError('Windows CONNECT lost a native architecture, compiler split or finite budget')
    blocks = re.findall(r'(?ms)^      - .*?(?=^      - |\Z)', steps)
    if ''.join(blocks) != steps or tuple(blocks) != BLOCKS:
        raise AssertionError('Windows CONNECT changed original toolchain, controls, bundle, native command or receipt')
    if source != PREFIX+'  host:\n'+body:
        raise AssertionError('Windows CONNECT added an uncaptured workflow job')
    caller = unique_job(release, CALLER)
    if caller.strip() != 'needs: native-runtimes\n    uses: ./'+WORKFLOW:
        raise AssertionError('Windows CONNECT must require this run exact native producer without optional admission')
    aggregate = unique_job(release, 'aggregate')
    needs = re.search(r'(?m)^    needs: \[([^\n]+)\]$', aggregate)
    if needs is None or [name.strip() for name in needs[1].split(',')].count(CALLER) != 1:
        raise AssertionError('Authoritative release omitted or duplicated Windows CONNECT acceptance')
    for path in INPUTS:
        if builder.count("ROOT/'"+path+"'") != 1:
            raise AssertionError('Windows CONNECT lost exact source identity: '+path)


def check_audit(source):
    tree = ast.parse(source)
    calls = [ast.unparse(node.value) for node in tree.body
             if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
             and isinstance(node.value.func, ast.Name)
             and node.value.func.id == 'check_windows_connect_execution_host_workflow']
    expected = "check_windows_connect_execution_host_workflow(read('"+WORKFLOW+"'), rc, read('deploy/build-native-runtime.py'))"
    if calls != [expected]:
        raise AssertionError('Shipping parity audit must invoke the complete Windows CONNECT contract once')


class WindowsCONNECTExecutionWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT/WORKFLOW).read_text()
        self.release = (ROOT/'.github/workflows/release-candidate.yml').read_text()
        self.builder = (ROOT/'deploy/build-native-runtime.py').read_text()

    def test_required_native_targets_same_source_and_owned_receipts(self):
        check(self.source, self.release, self.builder)

    def test_architecture_compiler_and_budget_refusals(self):
        for before, after in (
            ('runner: windows-11-arm', 'runner: windows-latest'),
            ("cgo: '1'", "cgo: '0'"),
            ("go-version: '1.26.3'", "go-version: 'stable'"),
            ('timeout-minutes: 120', 'timeout-minutes: 240'),
            ('timeout-minutes: 110', 'timeout-minutes: 220'),
            ('      - uses: ./.github/actions/go-windows-sockets\n', ''),
            ("if: matrix.arch == 'amd64'", "if: false"),
            ('x86_64-w64-mingw32-clang.exe', 'foreign-clang.exe'),
            ("PYTHONDONTWRITEBYTECODE: '1'", "PYTHONDONTWRITEBYTECODE: '0'"),
        ):
            self.assertIn(before,self.source)
            with self.subTest(before=before), self.assertRaises(AssertionError):
                check(self.source.replace(before,after,1),self.release,self.builder)

    def test_native_or_controller_controls_cannot_be_optional(self):
        native = next(block for block in BLOCKS if 'name: Require real CONNECT' in block)
        for before, after in (
            ('        timeout-minutes: 110', '        if: false\n        timeout-minutes: 110'),
            ('        timeout-minutes: 110', "        'continue-on-error': true\n        timeout-minutes: 110"),
            (' --go go ', ' --case http-wg-server --go go '),
            ("ROUTERVPN_WINDOWS_CONNECT_EXECUTION_NATIVE: '1'", "ROUTERVPN_WINDOWS_CONNECT_EXECUTION_NATIVE: '0'"),
            ("if ($LASTEXITCODE -ne 0) { throw 'Actual Windows CONNECT Server or Compare failed' }", 'Write-Output ignored'),
        ):
            self.assertIn(before,native)
            with self.subTest(before=before),self.assertRaises(AssertionError):
                check(self.source.replace(native,native.replace(before,after,1),1),self.release,self.builder)
        for name in ('test_windows_connect_execution_host_runner.py','test_windows_connect_execution_workflow.py'):
            with self.subTest(name=name),self.assertRaises(AssertionError):
                check(self.source.replace('python deploy/'+name,'Write-Output omitted',1),self.release,self.builder)

    def test_foreign_checkout_bundle_or_receipt_is_rejected(self):
        for before, after in (
            ('persist-credentials: false', 'persist-credentials: false\n          ref: historical'),
            ('          path: ${{ runner.temp }}/connect-execution-host-bundle', '          path: ${{ runner.temp }}/connect-execution-host-bundle\n          run-id: 12345'),
            ('native-windows-${{ matrix.arch }}.tar.gz', 'native-windows-amd64.tar.gz'),
            ('ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}', 'ROUTERVPN_EXPECTED_SOURCE: historical'),
            ('if-no-files-found: error', 'if-no-files-found: warn'),
            ('name: RouterVPN-Windows-connect-execution-host-', 'name: RouterVPN-Windows-local-host-'),
        ):
            self.assertIn(before,self.source)
            with self.subTest(before=before),self.assertRaises(AssertionError):
                check(self.source.replace(before,after,1),self.release,self.builder)

    def test_missing_duplicate_extra_or_conditional_jobs_fail(self):
        body=unique_job(self.source,'host')
        for changed in (self.source.replace('  host:\n','  omitted:\n',1),
                        self.source+'\n  host:\n'+body,
                        self.source+'\n  unrelated:\n    runs-on: windows-latest\n',
                        self.source.replace('  host:\n','  host:\n    if: false\n',1)):
            with self.assertRaises(AssertionError):check(changed,self.release,self.builder)
        for key in ('if', 'continue-on-error', "'if'", '"\\x69f"'):
            with self.subTest(key=key),self.assertRaises(AssertionError):
                check(self.source,self.release.replace('  '+CALLER+':\n','  '+CALLER+':\n    '+key+': false\n',1),self.builder)

    def test_all_source_inputs_and_producer_aggregate_required(self):
        for path in INPUTS:
            with self.subTest(path=path),self.assertRaises(AssertionError):
                check(self.source,self.release,self.builder.replace("ROOT/'"+path+"'","ROOT/'omitted'",1))
        marker='    needs: native-runtimes\n    uses: ./'+WORKFLOW
        self.assertIn(marker,self.release)
        with self.assertRaises(AssertionError):
            check(self.source,self.release.replace(marker,'    uses: ./'+WORKFLOW,1),self.builder)
        aggregate=unique_job(self.release,'aggregate')
        with self.assertRaises(AssertionError):
            check(self.source,self.release.replace(aggregate,aggregate.replace(CALLER,'omitted',1),1),self.builder)

    def test_shipping_parity_requires_complete_unconditional_guard(self):
        source=(ROOT/'deploy/native-artifact-workflow-parity-audit.py').read_text()
        check_audit(source)
        marker='check_windows_connect_execution_host_workflow(read("'+WORKFLOW+'"), rc, read("deploy/build-native-runtime.py"))'
        self.assertEqual(source.count(marker),1)
        for changed in (source.replace(marker,'pass',1),source.replace(marker,marker+'\n'+marker,1),
                        source.replace(marker,'if False:\n    '+marker,1),source.replace(marker,marker.replace('rc','"foreign"'),1)):
            with self.assertRaises(AssertionError):check_audit(changed)


if __name__ == '__main__':unittest.main()
