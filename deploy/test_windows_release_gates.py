#!/usr/bin/env python3
"""Run existing device/DNS regressions against the extracted release package.

The Python harnesses remain checkout-owned. Every PowerShell source, composed
app helper and test entrypoint they read is bound to the extracted package.
With no arguments, exercise that binding and its authoritative workflow edges.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import os
from pathlib import Path
import re
import sys
import subprocess
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPOSITORY = Path(__file__).resolve().parents[1]
FULL_SOURCE_COMMAND = "python3 deploy/test_go_source_groups.py --scope all"
FULL_SOURCE_GATES = (
    ("requirements-closure.yml", "source-contract", "Compile and test Go source"),
    ("release-candidate.yml", "source-audit", "Go source contracts"),
    ("client-apps-ci.yml", "desktop-unix", "Test Go controller and shared API"),
)
HARNESSES = (
    ("test_windows_device_settings", ()),
    ("test_windows_home_dns", ()),
    ("test_desktop_dns_settings", ("--platform", "windows")),
    ("test_desktop_quick_dns", ("--platform", "windows")),
    ("test_windows_dns_measurement", ()),
)
ROOT_DEPENDENCIES = ("test_desktop_startup_settings", "test_desktop_protection_settings")
PACKAGE_FILES = (
    "client/Private-RouterVPN-State.ps1",
    "client/native-wireguard-windows.ps1",
    "client/native-windows-mode.ps1",
    "client/RouterVPN-Windows-App.ps1",
    "client/RouterVPN-Windows-ControllerTransport.psm1",
    "client/RouterVPN-Windows-ControllerTransport.cs",
    "client/RouterVPN-Windows-UIState.psm1",
    "client/RouterVPN-Windows-ProfileSettings.ps1",
    "client/RouterVPN-Windows-Product-v2.ps1",
    "client/RouterVPN-Windows-UnifiedShell.ps1",
    "client/RouterVPN-Windows-SessionMutation.ps1",
    "client/RouterVPN-Windows-DNSMeasurement.ps1",
    "client/test-windows-device-settings.ps1",
    "client/test-windows-home-dns.ps1",
    "client/test-windows-dns-measurement.ps1",
)
WORKSPACE_SCOPES = (
    ('^TestDesktopRuntimeWorkspace', ''),
    ('^TestDesktopDNS', ''),
    ('^TestDesktopImportedMTU', ''),
    ('^Test(DesktopNodePhysical|DesktopNativeStaging|NativeMultihopRetainedStage)', ''),
    ('^Test(DesktopExternalCompiledPhysical|DesktopMappedLayerPhysical|DesktopExternalFullRouterPredecessor)', ''),
    ('^TestDesktopWindowsExternalSSEntry', ''),
    ('^TestDesktopWindowsExternalRouterServer', ''),
    ('^TestDesktopWindowsExternalRouterLocal', ''),
    ('^TestDesktopWindowsExternalRouterCompare', ''),
    ('^TestDesktopTorMTU', ''),
    ('^TestDesktopTor(Comparison|Compare|PublicCompare)', ''),
    ('^TestDesktopTorOrdinary', ''),
    ('^TestDesktopTor', '^TestDesktopTor(MTU|Comparison|Compare|PublicCompare|Ordinary)'),
    ('^TestSpeedLabTor(Comparison|Compare)', ''),
    ('^TestSpeedLabTor', '^TestSpeedLabTor(Comparison|Compare)'),
    ('^TestSpeedLab', '^TestSpeedLabTor'),
)


def run_packaged(package: Path, shell: str, load=importlib.import_module) -> None:
    package = package.resolve(strict=True)
    if package == REPOSITORY or not package.is_dir():
        raise ValueError("Windows release gates require an extracted package, not checkout source")
    if shell not in ("pwsh", "powershell.exe"):
        raise ValueError("Windows release gates require PowerShell 7 or Windows PowerShell 5.1")
    for relative in PACKAGE_FILES:
        if not (package / relative).is_file():
            raise ValueError("Windows release package is missing " + relative)

    # The full/compact DNS harnesses import read() from their startup harness,
    # and load_transform() from protection. Bind those function globals too;
    # rebinding only the top-level harness would silently read checkout files.
    modules = {name: load(name) for name in (*ROOT_DEPENDENCIES, *(name for name, _ in HARNESSES))}
    saved = []
    arguments = sys.argv
    try:
        for name, module in modules.items():
            if not hasattr(module, "ROOT"):
                raise ValueError("Windows fixture lost its explicit source-root contract: " + name)
            saved.append((module, "ROOT", module.ROOT))
            module.ROOT = package
        measurement = modules["test_windows_dns_measurement"]
        for key, relative in (("HELPER", "client/RouterVPN-Windows-DNSMeasurement.ps1"), ("TEST", "client/test-windows-dns-measurement.ps1")):
            saved.append((measurement, key, getattr(measurement, key)))
            setattr(measurement, key, package / relative)
        for name, extra in HARNESSES:
            print(f"Release package gate: {name} with {shell}", flush=True)
            sys.argv = [name + ".py", "--shell", shell, *extra]
            try:
                if extra:
                    # The cross-platform harnesses expose platform functions;
                    # their CLI parser lives directly in __main__.
                    with tempfile.TemporaryDirectory(prefix="routervpn-release-fixture-") as directory:
                        modules[name].windows(Path(directory), shell)
                else:
                    modules[name].main()
            except SystemExit as error:
                # Even exit(0) here would omit every later mandatory fixture.
                raise RuntimeError("Windows fixture exited before the release gates completed: " + name) from error
    finally:
        sys.argv = arguments
        for module, key, value in reversed(saved):
            setattr(module, key, value)


def workflow_job(source: str, name: str) -> str:
    match = re.search(r"(?ms)^  " + re.escape(name) + r":\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", source)
    if match is None:
        raise AssertionError("missing authoritative job " + name)
    return match.group(1)


def check_full_source_gate(source: str, job_name: str, step_name: str) -> None:
    job = workflow_job(source, job_name)
    header = job.split("    steps:\n", 1)[0]
    if re.search(r"(?m)^    (?:if|continue-on-error):", header):
        raise AssertionError("full Go source job became conditional or nonblocking")
    marker = "      - name: " + step_name + "\n"
    if job.count(marker) != 1:
        raise AssertionError("full Go source gate is missing or duplicated")
    gate = job.split(marker, 1)[1].split("      - ", 1)[0]
    # Require the entire one-command step, not a matching substring followed
    # by a selector, ignored exit status, or a folded YAML continuation. The runner
    # discovers every package, test, example and ordinary fuzz seed in the suite.
    execution = "\n".join(line for line in gate.splitlines() if line.strip() and not line.lstrip().startswith("#"))
    if execution != "        run: " + FULL_SOURCE_COMMAND:
        raise AssertionError("full Go source gate must run the bounded unfiltered suite: " + FULL_SOURCE_COMMAND)


def check_workspace_gate(job: str) -> None:
    marker = "      - name: Native workspace deletion and captured Tor child cleanup\n"
    if job.count(marker) != 1:
        raise AssertionError("Windows captured cleanup gate is missing or duplicated")
    gate = job.split(marker, 1)[1].split("      - ", 1)[0]
    scopes = tuple(re.findall(r"@\{ Run = '([^']*)'; Skip = '([^']*)' \}", gate))
    required = (
        "shell: pwsh", "foreach ($scope in $scopes) {",
        "$arguments = @('test', '-v', '-count=1', '-timeout=180s', './cmd/client', '-run', $scope.Run)",
        "if ($scope.Skip) { $arguments += @('-skip', $scope.Skip) }", "& go @arguments",
    )
    if scopes != WORKSPACE_SCOPES or any(value not in gate for value in required):
        raise AssertionError("Windows cleanup gate omitted live-handle or captured child tests")
    if "if ($LASTEXITCODE -ne 0) { throw" not in gate or re.search(r"(?m)^        (?:if|continue-on-error):", gate):
        raise AssertionError("Windows cleanup gate no longer blocks a failed native test")


def check_node_process_caller(source: str, name: str) -> None:
    job = workflow_job(source, name)
    if (job.count("    uses: ./.github/workflows/windows-node-process-contract.yml\n") != 1 or
            re.search(r"(?m)^    (?:if|continue-on-error|with|needs):", job)):
        raise AssertionError("Windows Node process acceptance lost its unconditional same-source caller")


def check_node_process_aggregate(workflow: str) -> None:
    # The old combined twenty-minute step stopped after 54 of 66 groups in
    # 137436518780. Each shard uses the exact producer executable and deadline.
    def require(block, *markers):
        for marker in markers:
            if block.count(marker) != 1:
                raise AssertionError("Windows Node process contract lost " + marker)

    image = workflow_job(workflow, "image")
    baseline = workflow_job(workflow, "baseline")
    controls = workflow_job(workflow, "controls")
    required = workflow_job(workflow, "required")
    require(workflow.split("jobs:", 1)[0], "  workflow_call:\n",
            "  group: windows-node-process-${{ github.workflow }}-${{ github.ref }}-${{ github.run_id }}\n",
            "  cancel-in-progress: false\n")
    for job in (image, baseline, controls):
        require(job, "    runs-on: windows-latest\n", "    timeout-minutes: 25\n", "        timeout-minutes: 20\n",
                "      GOOS: windows\n", "      GOARCH: amd64\n", "      CGO_ENABLED: '1'\n",
                "          go-version: '1.26.3'\n          cache: false\n", "          python-version: '3.12'\n",
                "      - uses: ./.github/actions/go-windows-sockets\n", "python deploy/install-desktop-windows-toolchain.py ",
                "'x86_64-w64-mingw32-clang.exe'", '"CC=$compiler" | Out-File -FilePath $env:GITHUB_ENV')
    for job in (image, controls):
        require(job, "          python deploy/test_windows_node_process_runner.py\n",
                "if ($LASTEXITCODE -ne 0) { throw 'Native Node process gate lost its source or result boundary' }")
    for job in (baseline, controls):
        require(job, "      fail-fast: false\n")
    if (re.search(r"(?m)^ +(?:continue-on-error|exclude|ref):", workflow) or
            re.findall(r"(?m)^ +if: (.+)$", workflow) != ["${{ !cancelled() }}"]):
        raise AssertionError("Windows Node process acceptance became optional or selected a foreign checkout")
    artifact = "windows-node-process-image-${{ github.sha }}-${{ github.run_id }}"
    phase = "windows-node-process-baseline-${{ matrix.group }}-${{ github.sha }}-${{ github.run_id }}"
    current = '"${{ runner.temp }}/node-process-image"'
    require(image, "          python deploy/test_windows_node_process_phases.py\n",
            "if ($LASTEXITCODE -ne 0) { throw 'Native Node baseline partition contract failed' }",
            "        run: python deploy/windows_node_process_phases.py image --output " + current + "\n",
            "          name: " + artifact + "\n", "/node-process-image/node-process.test.exe\n", "/node-process-image/image.json\n")
    require(baseline, "    needs: image\n", "        group: [native-early-shared, late-shared, ordered, latency, product]\n",
            "        run: python deploy/windows_node_process_phases.py run --group '${{ matrix.group }}' --image " + current +
            ' --output "${{ runner.temp }}/node-process-phase"\n', "          name: " + phase + "\n",
            "/node-process-phase/phase.json\n", "/node-process-phase/native.log\n")
    require(controls, "        suite: [ownership-controls-1, ownership-controls-2, ownership-controls-3, ownership-controls-4, prospective-all]\n",
            "          python deploy/test_windows_node_process.py --suite '${{ matrix.suite }}'\n",
            "if ($LASTEXITCODE -ne 0) { throw 'Actual retained Windows Node process gate failed' }")
    for job in (baseline, required):
        require(job, "      - uses: actions/download-artifact@v4\n        with:\n          name: " + artifact +
                "\n          path: ${{ runner.temp }}/node-process-image\n")
    for job in (image, baseline, required):
        require(job, "      - uses: actions/upload-artifact@v4\n", "          if-no-files-found: error\n",
                "          overwrite: true\n", "          retention-days: 14\n")
    require(required, "    needs: [image, baseline, controls]\n    if: ${{ !cancelled() }}\n",
            "          pattern: windows-node-process-baseline-*-${{ github.sha }}-${{ github.run_id }}\n",
            "          path: ${{ runner.temp }}/node-process-receipts\n          merge-multiple: false\n",
            "          NATIVE_REQUIRED_JOBS: ${{ toJSON(needs) }}\n",
            "        run: python deploy/windows_node_process_phases.py aggregate --image " + current +
            ' --receipts "${{ runner.temp }}/node-process-receipts" --output "${{ runner.temp }}/node-process-accepted"\n',
            "          name: windows-node-process-accepted-${{ github.sha }}-${{ github.run_id }}\n",
            "          path: ${{ runner.temp }}/node-process-accepted/accepted.json\n")


def check_node_all_arm64(job: str) -> None:
    header = job.split("    steps:", 1)[0]
    expected = {
        r"(?m)^    runs-on: (.*)$": ["windows-11-arm"],
        r"(?m)^    timeout-minutes: (\d+)$": ["25"],
        r"(?m)^      GOOS: (.*)$": ["windows"],
        r"(?m)^      GOARCH: (.*)$": ["arm64"],
        r"(?m)^      CGO_ENABLED: (.*)$": ["'0'"],
    }
    if any(re.findall(pattern, header) != values for pattern, values in expected.items()):
        raise AssertionError("ALL omitted its matching native ARM64 host or original bound")
    if ("group: windows-node-all-arm64-${{ github.ref }}" not in header or
            "      cancel-in-progress: false\n" not in header or
            re.search(r"(?m)^    (?:if|continue-on-error):", header)):
        raise AssertionError("Native ARM64 ALL became conditional or lost its original run")
    for required in ("go-version: '1.26.3'", "python-version: '3.12'",
                     "python deploy/test_windows_node_process_runner.py", "python deploy/test_windows_release_gates.py"):
        if job.count(required) != 1:
            raise AssertionError("Native ARM64 ALL omitted its pinned compiler or required source gates")
    marker = "      - name: Execute required native ARM64 ALL and restoration\n"
    if job.count(marker) != 1:
        raise AssertionError("Native ARM64 ALL execution is missing or duplicated")
    gate = job.split(marker, 1)[1].split("      - ", 1)[0]
    if (re.findall(r"(?m)^        timeout-minutes: (\d+)$", gate) != ["20"] or
            re.findall(r"(?m)^          python deploy/test_windows_node_process\.py(.*)$", gate) != [" --suite prospective-all"] or
            "shell: pwsh" not in gate or
            "if ($LASTEXITCODE -ne 0) { throw 'Actual Windows ARM64 ALL and restoration gate failed' }" not in gate or
            re.search(r"(?m)^        (?:if|continue-on-error):", gate)):
        raise AssertionError("Native ARM64 ALL omitted complete blocking execution or its original bound")


def check_authoritative_all_workflow(workflow: str) -> None:
    if re.findall(r"(?m)^  workflow_call:$", workflow) != ["  workflow_call:"]:
        raise AssertionError("Windows ALL is not callable by the authoritative release")
    job = workflow_job(workflow, "native-all")
    header = job.split("    steps:", 1)[0]
    if re.findall(r"(?m)^          - \{arch: (\w+), runner: ([\w-]+), cgo: '([01])'\}$", header) != [
            ("amd64", "windows-latest", "1"), ("arm64", "windows-11-arm", "0")]:
        raise AssertionError("Authoritative ALL lost its two actual native Windows hosts")
    for marker in ("    runs-on: ${{ matrix.runner }}\n", "    timeout-minutes: 25\n",
                   "      fail-fast: false\n", "      GOOS: windows\n",
                   "      GOARCH: ${{ matrix.arch }}\n", "      CGO_ENABLED: ${{ matrix.cgo }}\n",
                   "group: windows-release-all-${{ github.workflow }}-${{ github.ref }}-${{ matrix.arch }}\n",
                   "      cancel-in-progress: false\n"):
        if header.count(marker) != 1:
            raise AssertionError("Authoritative ALL lost its native target, lifetime or bound")
    if re.search(r"(?m)^    (?:if|continue-on-error):", header):
        raise AssertionError("Authoritative ALL became conditional or nonblocking")
    for marker in ("go-version: '1.26.3'", "python-version: '3.12'",
                   "python deploy/test_windows_node_process_runner.py", "python deploy/test_windows_release_gates.py",
                   "        if: matrix.arch == 'amd64'\n", "python deploy/install-desktop-windows-toolchain.py",
                   "x86_64-w64-mingw32-clang.exe", '"CC=$compiler" | Out-File -FilePath $env:GITHUB_ENV'):
        if job.count(marker) != 1:
            raise AssertionError("Authoritative ALL lost its pinned compiler or source gates")
    marker = "      - name: Execute complete native ALL and restoration\n"
    if job.count(marker) != 1:
        raise AssertionError("Authoritative ALL execution is missing or duplicated")
    execution = job.split(marker, 1)[1].split("      - ", 1)[0]
    if (re.findall(r"(?m)^        timeout-minutes: (\d+)$", execution) != ["20"] or
            re.findall(r"(?m)^          python deploy/test_windows_node_process\.py(.*)$", execution) != [" --suite prospective-all"] or
            "        shell: pwsh\n" not in execution or
            "if ($LASTEXITCODE -ne 0) { throw 'Actual Windows ALL and restoration failed' }" not in execution or
            re.search(r"(?m)^        (?:if|continue-on-error):", execution)):
        raise AssertionError("Authoritative ALL lost complete blocking native execution")


def check_owned_process_gate(job: str, packaged: bool, tor_wrapper: bool = False) -> None:
    if tor_wrapper:
        name = "Execute packaged Tor wrapper lifecycle" if packaged else "Tor wrapper ownership and prelaunch failure witnesses"
        fixture = "client/test-windows-tor-wrapper-lifecycle.ps1"
    else:
        name = "Execute packaged suspended-process Job ownership" if packaged else "Windows suspended-process Job ownership"
        fixture = "client/test-windows-private-job.ps1"
    marker = "      - name: " + name + "\n"
    if job.count(marker) != 1:
        raise AssertionError("Windows suspended-process Job gate is missing or duplicated")
    gate = job.split(marker, 1)[1].split("      - ", 1)[0]
    required = ["shell: pwsh", "foreach($shell in @('pwsh','powershell.exe'))", "if($LASTEXITCODE -ne 0){throw"]
    if packaged:
        required += [
            "installed-$arch", "$roots.Count -ne 1",
            f"$test=Join-Path $roots[0].FullName '{fixture}'",
            "Test-Path -LiteralPath $test -PathType Leaf",
            "& $shell -NoProfile -ExecutionPolicy Bypass -File $test -SourceRoot $roots[0].FullName",
        ]
    else:
        required.append(f"& $shell -NoProfile -ExecutionPolicy Bypass -File {fixture} -SourceRoot $env:GITHUB_WORKSPACE")
    if any(value not in gate for value in required):
        raise AssertionError("Windows Job gate lost an actual shell or captured source boundary")
    if "-compileonly" in gate.lower() or re.search(r"(?m)^        (?:if|continue-on-error):", gate):
        raise AssertionError("Windows Job gate omitted real kernel execution or became nonblocking")


def check_wfp_gate(job: str, packaged: bool) -> None:
    name = "Execute packaged Windows WFP enforcement" if packaged else "Executable-scoped Windows WFP enforcement"
    marker = "      - name: " + name + "\n"
    if job.count(marker) != 1:
        raise AssertionError("Windows WFP kernel gate is missing or duplicated")
    gate = job.split(marker, 1)[1].split("      - ", 1)[0]
    required = ["shell: pwsh", "foreach($shell in @('pwsh','powershell.exe'))", "if($LASTEXITCODE -ne 0){throw"]
    if packaged:
        required += [
            "installed-$arch", "$roots.Count -ne 1",
            "$test=Join-Path $roots[0].FullName 'client/test-windows-wfp.ps1'",
            "Test-Path -LiteralPath $test -PathType Leaf",
            "& $shell -NoProfile -ExecutionPolicy Bypass -File $test -SourceRoot $roots[0].FullName",
        ]
    else:
        required += [
            "& $shell -NoProfile -ExecutionPolicy Bypass -File client/test-windows-wfp-endpoints.ps1 -SourceRoot $env:GITHUB_WORKSPACE",
            "& $shell -NoProfile -ExecutionPolicy Bypass -File client/test-windows-wfp.ps1 -SourceRoot $env:GITHUB_WORKSPACE",
        ]
    if any(value not in gate for value in required):
        raise AssertionError("WFP kernel gate lost a real shell or exact package boundary")
    if "-compileonly" in gate.lower() or re.search(r"(?m)^        (?:if|continue-on-error):", gate):
        raise AssertionError("WFP gate omitted native enforcement or became nonblocking")


def native_dns_test_script(workflow: str, candidate: str) -> str:
    dependency = workflow_job(candidate, "native-runtimes")
    if "uses: ./.github/workflows/desktop-native-runtime.yml" not in dependency or "platform: all" not in dependency:
        raise AssertionError("authoritative release bypasses the complete native DNS test matrix")
    job = workflow_job(workflow, "runtime")
    marker = "      - name: Native DNS proxy H3 exchanges and kernel proof\n"
    if job.count(marker) != 1:
        raise AssertionError("native nested-module DNS test gate is missing or duplicated")
    gate = job.split(marker, 1)[1].split("      - ", 1)[0]
    required = (
        "shell: bash", "ROUTER_VPN_DNS_TARGET: '${{ matrix.target }}'", "set -euo pipefail",
        "python3 deploy/test_dnsproxy_build.py", "selector['GOTOOLCHAIN'] = 'go1.26.3'",
        "['go', 'env', 'GOROOT', 'GOHOSTOS', 'GOHOSTARCH'], env=selector",
        "'/'.join(identity[1:]) != target", "'deploy/build-dnsproxy.py', 'test', '--go', str(go)",
        "if target == 'windows/arm64':\n              command.append('--without-race')",
        "subprocess.run(command, check=True)",
    )
    if any(value not in gate for value in required) or re.search(r"(?m)^        (?:if|continue-on-error):", gate):
        raise AssertionError("native DNS gate lost exact host, pinned toolchain, full tests or blocking failure")
    if job.index(marker) > job.index("uses: actions/cache/restore@v4"):
        raise AssertionError("native DNS tests must execute before runtime artifact reuse")
    for system, arch, runner in (("linux", "amd64", "ubuntu-24.04"), ("linux", "arm64", "ubuntu-24.04-arm"),
                                ("darwin", "amd64", "macos-15-intel"), ("darwin", "arm64", "macos-15"),
                                ("windows", "amd64", "windows-latest"), ("windows", "arm64", "windows-11-arm")):
        if f"('{system}', '{arch}', '{runner}')" not in workflow_job(workflow, "targets"):
            raise AssertionError("native DNS test matrix lost " + system + "/" + arch)
    return textwrap.dedent(gate.split("python3 - <<'PY'\n", 1)[1].split("\n          PY", 1)[0])


def check_workflow(candidate: str, build_all: str) -> None:
    windows = workflow_job(candidate, "windows-native-smoke")
    check_node_process_caller(candidate, "windows-node-process")
    bootstrap = workflow_job(candidate, "windows-physical-bootstrap")
    if ("    uses: ./.github/workflows/windows-physical-bootstrap-contract.yml\n" not in bootstrap or
            re.search(r"(?m)^    (?:if|continue-on-error|with|needs):", bootstrap)):
        raise AssertionError("authoritative release lost its blocking same-source Windows bootstrap workflow")
    complete_max = workflow_job(candidate, "windows-complete-max")
    if "    uses: ./.github/workflows/windows-node-max-contract.yml\n" not in complete_max or re.search(
            r"(?m)^    (?:if|continue-on-error):", complete_max):
        raise AssertionError("authoritative release lost its blocking native complete MAX workflow")
    all_controller = workflow_job(candidate, "windows-all-controller")
    if "    uses: ./.github/workflows/windows-node-all-contract.yml\n" not in all_controller or re.search(
            r"(?m)^    (?:if|continue-on-error):", all_controller):
        raise AssertionError("authoritative release lost its blocking native ALL controller workflow")
    check_workspace_gate(windows)
    check_owned_process_gate(windows, True)
    check_owned_process_gate(windows, True, True)
    check_wfp_gate(windows, True)
    check_full_source_gate(candidate, "source-audit", "Go source contracts")
    source = workflow_job(candidate, "source-audit")
    for command in ("python3 deploy/test_desktop_tor_unix_wrapper.py", "python3 modes/test_cleanup_private_runtime.py",
                    "python3 deploy/test_windows_release_gates.py"):
        if command not in source:
            raise AssertionError("authoritative source gate omitted controller or Unix ownership coverage: " + command)
    if "    needs: generic-builds\n" not in windows:
        raise AssertionError("Windows gates lost their exact run's package dependency")
    if "uses: actions/setup-python@v5" not in windows or "python-version: '3.12'" not in windows:
        raise AssertionError("Windows gate lost its native matrix Python dependency")
    for architecture, runner in (("amd64", "windows-latest"), ("arm64", "windows-11-arm")):
        if f"{{arch: {architecture}, runner: {runner}}}" not in windows:
            raise AssertionError("Windows release gate lost architecture " + architecture)
    marker = "      - name: Execute packaged device and DNS ownership gates\n"
    if windows.count(marker) != 1:
        raise AssertionError("packaged policy gate is missing or duplicated")
    gate = windows.split(marker, 1)[1].split("      - ", 1)[0]
    for value in (
        "        shell: pwsh\n",
        "installed-$arch",
        "$roots.Count -ne 1",
        "foreach($shell in @('pwsh','powershell.exe'))",
        "python deploy/test_windows_release_gates.py --package-root $roots[0].FullName --shell $shell",
        "if($LASTEXITCODE -ne 0){throw",
    ):
        if value not in gate:
            raise AssertionError("packaged policy gate lost " + value)
    if re.search(r"(?m)^    (?:if|continue-on-error):", windows) or re.search(r"(?m)^        (?:if|continue-on-error):", gate):
        raise AssertionError("Windows release policy gate became conditional or nonblocking")
    if "--unit-only" in gate or "--shipping-only" in gate:
        raise AssertionError("Windows release policy gate omitted executable negatives or live fixtures")
    aggregate = workflow_job(candidate, "aggregate")
    needs = re.search(r"(?m)^    needs: \[([^\]]+)\]$", aggregate)
    required_windows = {"windows-native-smoke", "windows-complete-max", "windows-all-controller",
                        "windows-physical-bootstrap", "windows-node-process"}
    if (needs is None or not required_windows.issubset(value.strip() for value in needs.group(1).split(",")) or
            re.search(r"(?m)^    (?:if|continue-on-error):", aggregate)):
        raise AssertionError("release aggregation bypassed Windows native gates")
    release = workflow_job(build_all, "release-candidate")
    publication = workflow_job(build_all, "publish-exact-sha-release")
    if "uses: ./.github/workflows/release-candidate.yml" not in release or "      - release-candidate\n" not in publication:
        raise AssertionError("exact-SHA publication bypassed its authoritative Windows matrix")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-root", type=Path)
    parser.add_argument("--shell", choices=("pwsh", "powershell.exe"))
    args = parser.parse_args()
    if args.package_root is not None:
        if not args.shell:
            parser.error("--shell is required with --package-root")
        run_packaged(args.package_root, args.shell)
    elif args.shell:
        parser.error("--package-root is required with --shell")
    else:
        parser.error("--package-root and --shell are required")


if __name__ == "__main__":
    main()
