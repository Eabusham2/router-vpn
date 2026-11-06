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
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPOSITORY = Path(__file__).resolve().parents[1]
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
    ('^Test(DesktopNodePhysical|DesktopNativeStaging|NativeMultihopRetainedStage)', ''),
    ('^Test(DesktopExternalCompiledPhysical|DesktopMappedLayerPhysical|DesktopExternalFullRouterPredecessor)', ''),
    ('^TestDesktopWindowsExternalSSEntry', ''),
    ('^TestDesktopWindowsExternalRouterServer', ''),
    ('^TestDesktopWindowsExternalRouterLocal', ''),
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


def check_node_process_aggregate(job: str) -> None:
    # Actual run 41553228508 passed all eight baseline groups and 46 controls
    # before its combined ALL work reached the 30-minute cap. Require all four
    # bounded suites; the driver retains every original per-case deadline.
    header = job.split("    steps:", 1)[0]
    if re.findall(r"(?m)^    timeout-minutes: (\d+)$", header) != ["25"]:
        raise AssertionError("Windows Node job lost its measured bounded aggregate")
    expected = "baseline, ownership-controls-1, ownership-controls-2, prospective-all"
    if (re.findall(r"(?m)^        suite: \[([^\]]+)\]$", header) != [expected] or
            "      fail-fast: false\n" not in header or
            re.search(r"(?m)^        (?:include|exclude):", header) or
            "windows-node-process-${{ github.ref }}-${{ matrix.suite }}" not in header):
        raise AssertionError("Windows Node aggregate lost a mandatory independent suite")
    marker = "      - name: Execute required native Node suite\n"
    if job.count(marker) != 1:
        raise AssertionError("Windows Node execution gate is missing or duplicated")
    gate = job.split(marker, 1)[1].split("      - ", 1)[0]
    if (re.findall(r"(?m)^        timeout-minutes: (\d+)$", gate) != ["20"] or
            re.findall(r"(?m)^          python deploy/test_windows_node_process\.py(.*)$", gate) != [" --suite '${{ matrix.suite }}'"] or
            "shell: pwsh" not in gate or
            "if ($LASTEXITCODE -ne 0) { throw 'Actual retained Windows Node process gate failed' }" not in gate):
        raise AssertionError("Windows Node aggregate omitted complete blocking execution or its measured bound")
    if re.search(r"(?m)^    (?:if|continue-on-error):", header) or re.search(r"(?m)^        (?:if|continue-on-error):", gate):
        raise AssertionError("Windows Node aggregate became conditional or nonblocking")


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
    source = workflow_job(candidate, "source-audit")
    for command in ("run: go test ./...", "python3 deploy/test_desktop_tor_unix_wrapper.py", "python3 modes/test_cleanup_private_runtime.py",
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
    if needs is None or not {"windows-native-smoke", "windows-complete-max", "windows-all-controller"}.issubset(
            value.strip() for value in needs.group(1).split(",")):
        raise AssertionError("release aggregation bypassed Windows native gates")
    release = workflow_job(build_all, "release-candidate")
    publication = workflow_job(build_all, "publish-exact-sha-release")
    if "uses: ./.github/workflows/release-candidate.yml" not in release or "      - release-candidate\n" not in publication:
        raise AssertionError("exact-SHA publication bypassed its authoritative Windows matrix")


class WindowsReleaseGateTests(unittest.TestCase):
    def controller_gate(self, name):
        path = REPOSITORY / ("deploy/test_windows_controller_" + name + ".py")
        spec = importlib.util.spec_from_file_location("release_controller_" + name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_controller_mutants_keep_exact_tests_when_baseline_inventory_changes(self):
        gate = self.controller_gate("foundation")
        original = gate.mutants()
        self.assertEqual(len(original), 29)
        for required in (("TestInsertedOwnershipBoundary", *gate.REQUIRED),
                         tuple(reversed(gate.REQUIRED))):
            with self.subTest(required=required[0]), patch.object(gate, "REQUIRED", required):
                self.assertEqual(gate.mutants(), original,
                                 "baseline inventory change retargeted a compiled negative control")

    def test_foundation_mutants_select_the_test_containing_their_failure_witness(self):
        declarations = {}
        for path in (REPOSITORY / "internal/windowscontroller").glob("*_test.go"):
            source = path.read_text(encoding="utf-8")
            for match in re.finditer(r"^func (Test\w+)\(t \*testing\.T\)", source, re.M):
                end = re.search(r"^func ", source[match.end():], re.M)
                body = source[match.start():match.end() + end.start() if end else len(source)]
                self.assertNotIn(match.group(1), declarations)
                declarations[match.group(1)] = body
        gate = self.controller_gate("foundation")
        for filename, mutant, selected, witness, changed in gate.mutants():
            with self.subTest(mutant=mutant):
                self.assertIn(selected, gate.REQUIRED)
                self.assertIn(selected, declarations)
                self.assertIn(witness, declarations[selected],
                              "compiled mutant selected a different semantic test")
                self.assertNotEqual(changed, (REPOSITORY / "internal/windowscontroller" / filename).read_text(encoding="utf-8"))

    def test_gui_inventory_requires_each_original_caller_source(self):
        gate = self.controller_gate("gui")
        records = gate.sources()
        required = ("context_lock.go", "context_lock_test.go",
                    "process_context_windows.go", "process_context_windows_test.go")
        for name in required:
            relative = str(Path("internal") / "windowscontroller" / name)
            self.assertEqual(records[relative], hashlib.sha256((REPOSITORY / relative).read_bytes()).hexdigest())
        with tempfile.TemporaryDirectory(prefix="controller-source-closure-") as directory:
            root = Path(directory).resolve()
            for relative in records:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((REPOSITORY / relative).read_bytes())
            package = root / "internal/windowscontroller"
            with patch.object(gate, "ROOT", root), patch.object(gate, "PACKAGE", package):
                self.assertEqual(gate.sources(), records)
                for name in required:
                    with self.subTest(missing=name):
                        path = package / name
                        original = path.read_bytes()
                        path.unlink()
                        with self.assertRaisesRegex(ValueError, "source/test closure changed"):
                            gate.sources()
                        path.write_bytes(original)
                (package / "unowned_windows.go").write_text("package windowscontroller\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "source/test closure changed"):
                    gate.sources()

    def native_dns_sources(self):
        return ((REPOSITORY / ".github/workflows/desktop-native-runtime.yml").read_text(encoding="utf-8"),
                (REPOSITORY / ".github/workflows/release-candidate.yml").read_text(encoding="utf-8"))

    def test_native_dns_gate_executes_full_module_on_each_exact_host(self):
        workflow, candidate = self.native_dns_sources()
        script = native_dns_test_script(workflow, candidate)
        for target in ("linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64", "windows/arm64"):
            with self.subTest(target=target), tempfile.TemporaryDirectory(prefix="pinned DNS Go ") as directory:
                root = Path(directory)
                calls = []
                def identity(command, **kwargs):
                    self.assertEqual(command, ['go', 'env', 'GOROOT', 'GOHOSTOS', 'GOHOSTARCH'])
                    self.assertEqual(kwargs['env']['GOTOOLCHAIN'], 'go1.26.3')
                    return str(root) + '\n' + target.replace('/', '\n') + '\n'
                def run(command, **kwargs):
                    calls.append(command)
                    self.assertIs(kwargs['check'], True)
                with patch.dict(os.environ, {'ROUTER_VPN_DNS_TARGET': target, 'GOTOOLCHAIN': 'foreign'}), \
                     patch('subprocess.check_output', side_effect=identity), patch('subprocess.run', side_effect=run):
                    exec(compile(script, '<shipping native DNS gate>', 'exec'), {})
                go = root / 'bin' / ('go.exe' if target.startswith('windows/') else 'go')
                self.assertEqual(calls, [[sys.executable, 'deploy/build-dnsproxy.py', 'test', '--go', str(go)] +
                                        (['--without-race'] if target == 'windows/arm64' else [])])

    def test_native_dns_gate_rejects_wrong_host_and_propagates_failed_tests(self):
        script = native_dns_test_script(*self.native_dns_sources())
        with patch.dict(os.environ, {'ROUTER_VPN_DNS_TARGET': 'windows/arm64'}), \
             patch('subprocess.check_output', return_value='/pinned/go\nwindows\namd64\n'), \
             patch('subprocess.run') as run:
            with self.assertRaisesRegex(RuntimeError, 'actual target architecture'):
                exec(compile(script, '<shipping native DNS gate>', 'exec'), {})
            run.assert_not_called()
        with patch.dict(os.environ, {'ROUTER_VPN_DNS_TARGET': 'linux/amd64'}), \
             patch('subprocess.check_output', return_value='/pinned/go\nlinux\namd64\n'), \
             patch('subprocess.run', side_effect=RuntimeError('captured H3 test failure')):
            with self.assertRaisesRegex(RuntimeError, 'captured H3 test failure'):
                exec(compile(script, '<shipping native DNS gate>', 'exec'), {})

    def test_native_dns_gate_rejects_omission_wrong_selector_and_disabled_race(self):
        workflow, candidate = self.native_dns_sources()
        variants = (
            ("Native DNS proxy H3 exchanges and kernel proof", "Omitted nested module"),
            ("python3 deploy/test_dnsproxy_build.py", "true # omitted dependency guard"),
            ("'deploy/build-dnsproxy.py', 'test', '--go'", "'deploy/build-dnsproxy.py', 'notices', '--go'"),
            ("env=selector, text=True", "text=True"),
            ("if target == 'windows/arm64':", "if target.startswith('windows/'):"),
            ("subprocess.run(command, check=True)", "subprocess.run(command, check=False)"),
            ("      - name: Native DNS proxy H3 exchanges and kernel proof\n", "      - name: Native DNS proxy H3 exchanges and kernel proof\n        continue-on-error: true\n"),
            ("('windows', 'arm64', 'windows-11-arm')", "('windows', 'arm64', 'windows-latest')"),
        )
        for old, new in variants:
            with self.subTest(mutation=new), self.assertRaises(AssertionError):
                native_dns_test_script(workflow.replace(old, new, 1), candidate)
        with self.assertRaises(AssertionError):
            native_dns_test_script(workflow, candidate.replace('platform: all', 'platform: windows', 1))

    def test_current_workflow_requires_both_architectures_shells_and_publication_edge(self):
        check_workflow((REPOSITORY / ".github/workflows/release-candidate.yml").read_text(encoding="utf-8"), (REPOSITORY / ".github/workflows/build-all.yml").read_text(encoding="utf-8"))

    def test_standalone_windows_runs_the_real_workspace_and_child_tests(self):
        workflow = (REPOSITORY / ".github/workflows/windows-native-contract.yml").read_text(encoding="utf-8")
        job = workflow_job(workflow, "native-windows")
        check_workspace_gate(job)
        for old, new in (("Run = '^TestDesktopRuntimeWorkspace'", "Run = '^TestDesktopTor'"),
                         ("Run = '^Test(DesktopNodePhysical|DesktopNativeStaging|NativeMultihopRetainedStage)'", "Run = '^$'"),
                         ("Run = '^Test(DesktopExternalCompiledPhysical|DesktopMappedLayerPhysical|DesktopExternalFullRouterPredecessor)'", "Run = '^$'"),
                         ("Run = '^TestDesktopWindowsExternalSSEntry'", "Run = '^$'"),
                         ("Run = '^TestDesktopWindowsExternalRouterServer'", "Run = '^$'"),
                         ("Run = '^TestDesktopWindowsExternalRouterLocal'", "Run = '^$'"),
                         ("Run = '^TestSpeedLabTor(Comparison|Compare)'", "Run = '^$'"),
                         ("Run = '^TestSpeedLabTor'", "Run = '^$'"),
                         ("Run = '^TestSpeedLab'", "Run = '^$'"),
                         ("Skip = '^TestSpeedLabTor(Comparison|Compare)'", "Skip = '^TestSpeedLabTor'"),
                         ("Skip = '^TestSpeedLabTor'", "Skip = '^TestSpeedLab'"),
                         ("Skip = '^TestDesktopTor(MTU|Comparison|Compare|PublicCompare|Ordinary)'", "Skip = '^TestDesktopTor'"),
                         ("Run = '^TestDesktopTor(Comparison|Compare|PublicCompare)'", "Run = '^$'"),
                         ("Run = '^TestDesktopTorOrdinary'", "Run = '^$'"),
                         ("'-timeout=180s'", "'-timeout=600s'"),
                         ("& go @arguments", "& go test -run '^$'")):
            with self.subTest(new=new), self.assertRaises(AssertionError):
                check_workspace_gate(job.replace(old, new, 1))

    def test_workspace_partition_preserves_every_current_native_test_once(self):
        # The former broad Tor invocation reached its 180s aggregate after
        # steady completed cases; the active leaf had run only one second.
        # Speed Lab likewise completed 69 parents before its shared budget
        # expired. Scan all declarations (including platform variants) so newly
        # added tests inherit exactly one group without a stale allowlist.
        original = (
            '^TestDesktopRuntimeWorkspace', '^TestDesktopDNS',
            '^Test(DesktopNodePhysical|DesktopNativeStaging|NativeMultihopRetainedStage)',
            '^Test(DesktopExternalCompiledPhysical|DesktopMappedLayerPhysical|DesktopExternalFullRouterPredecessor)',
            '^TestDesktopWindowsExternalSSEntry',
            '^TestDesktopWindowsExternalRouterServer',
            '^TestDesktopWindowsExternalRouterLocal',
            '^TestDesktopTor', '^TestSpeedLab',
        )
        names = set()
        for source in (REPOSITORY / 'cmd/client').glob('*_test.go'):
            names.update(re.findall(r'^func (Test\w+)\(t \*testing\.T\)', source.read_text(), re.M))
        expected = {name for name in names if any(re.search(selector, name) for selector in original)}
        selected = []
        for run, skip in WORKSPACE_SCOPES:
            group = {name for name in names if re.search(run, name) and not (skip and re.search(skip, name))}
            self.assertTrue(group, 'empty native workspace test group: ' + run)
            selected.extend(group)
        self.assertEqual(set(selected), expected)
        self.assertEqual(len(selected), len(set(selected)), 'native test selected by multiple package invocations')
        for name in (
            'TestDesktopTorComparisonRequiresStoppedReceiptAndActualProcessJoin',
            'TestDesktopTorPublicCompareHTTPCancellationDrainsOwnedTrial',
            'TestDesktopTorOrdinarySpeedLabRetainsCompiledSourceAndRestoresAfterCancel',
            'TestDesktopTorPlainSpeedLabRestoresProvedExecutionAndSource',
            'TestDesktopTorCheckedCleanupRetainsUnknownChangedAndLinkedFiles',
            'TestDesktopWindowsExternalSSEntrySources',
            'TestDesktopWindowsExternalSSEntryPublicLifecycle',
            'TestDesktopWindowsExternalSSEntryActivationCapturesBothSources',
            'TestDesktopWindowsExternalSSEntrySpeedLabRestoresBothSources',
            'TestDesktopWindowsExternalSSEntryAlwaysOffRetriesOriginalOwner',
            'TestDesktopWindowsExternalRouterServerPublicLifecycle',
            'TestDesktopWindowsExternalRouterServerRestoresOriginal',
            'TestDesktopWindowsExternalRouterServerSources',
            'TestSpeedLabTorCompareRestoresOriginalProvedExecutionWithoutReselection',
            'TestSpeedLabTorShippingPrepareStartAndRestoreExactNativePath',
            'TestSpeedLabTorPreparedTrialRejectsStaleAdmissionBeforeStop',
            'TestSpeedLabCapturedTunnelCancellationJoinsLateDial',
        ):
            self.assertIn(name, expected)

    def test_native_node_aggregate_preserves_complete_bounded_execution(self):
        workflow = (REPOSITORY / ".github/workflows/windows-controller-contract.yml").read_text(encoding="utf-8")
        job = workflow_job(workflow, "node-process")
        check_node_process_aggregate(job)
        for before, after in (
            ("    timeout-minutes: 25\n", "    timeout-minutes: 15\n"),
            ("    timeout-minutes: 25\n", "    timeout-minutes: 360\n"),
            ("    timeout-minutes: 25\n", ""),
            ("        timeout-minutes: 20\n", "        timeout-minutes: 10\n"),
            ("        timeout-minutes: 20\n", "        timeout-minutes: 360\n"),
            ("        timeout-minutes: 20\n", ""),
            ("    timeout-minutes: 25\n", "    if: false\n    timeout-minutes: 25\n"),
            ("    timeout-minutes: 25\n", "    continue-on-error: true\n    timeout-minutes: 25\n"),
            ("        timeout-minutes: 20\n", "        if: false\n        timeout-minutes: 20\n"),
            ("        timeout-minutes: 20\n", "        continue-on-error: true\n        timeout-minutes: 20\n"),
            (" --suite '${{ matrix.suite }}'", " --suite baseline"),
            ("baseline, ownership-controls-1, ownership-controls-2, prospective-all", "baseline, ownership-controls-1, ownership-controls-2"),
            ("baseline, ownership-controls-1, ownership-controls-2, prospective-all", "baseline, ownership-controls-1, ownership-controls-1, prospective-all"),
            ("      fail-fast: false", "      fail-fast: true"),
            ("${{ github.ref }}-${{ matrix.suite }}", "${{ github.ref }}"),
            ("throw 'Actual retained Windows Node process gate failed'", "Write-Host 'ignored failed native gate'"),
        ):
            self.assertEqual(job.count(before), 1, "native aggregate mutation anchor changed")
            with self.subTest(mutation=after), self.assertRaises(AssertionError):
                check_node_process_aggregate(job.replace(before, after, 1))

    def test_native_arm64_all_is_required_with_unchanged_deadlines(self):
        workflow = (REPOSITORY / ".github/workflows/windows-controller-contract.yml").read_text(encoding="utf-8")
        job = workflow_job(workflow, "node-all-arm64")
        check_node_all_arm64(job)
        check_node_process_aggregate(workflow_job(workflow, "node-process"))
        with self.assertRaisesRegex(AssertionError, "missing authoritative job"):
            workflow_job(workflow.replace("  node-all-arm64:\n", "  omitted-arm64-all:\n", 1), "node-all-arm64")
        for before, after in (
            ("runs-on: windows-11-arm", "runs-on: windows-latest"),
            ("GOARCH: arm64", "GOARCH: amd64"),
            ("GOOS: windows", "GOOS: linux"),
            ("CGO_ENABLED: '0'", "CGO_ENABLED: '1'"),
            ("    timeout-minutes: 25\n", "    timeout-minutes: 50\n"),
            ("        timeout-minutes: 20\n", "        timeout-minutes: 40\n"),
            ("    timeout-minutes: 25\n", "    if: false\n    timeout-minutes: 25\n"),
            ("    timeout-minutes: 25\n", "    continue-on-error: true\n    timeout-minutes: 25\n"),
            ("        timeout-minutes: 20\n", "        if: false\n        timeout-minutes: 20\n"),
            ("        timeout-minutes: 20\n", "        continue-on-error: true\n        timeout-minutes: 20\n"),
            ("cancel-in-progress: false", "cancel-in-progress: true"),
            (" --suite prospective-all", " --suite baseline"),
            ("throw 'Actual Windows ARM64 ALL and restoration gate failed'", "Write-Host 'ignored native failure'"),
            ("go-version: '1.26.3'", "go-version: '1.25.0'"),
        ):
            self.assertEqual(job.count(before), 1)
            with self.subTest(mutation=after), self.assertRaises(AssertionError):
                check_node_all_arm64(job.replace(before, after, 1))
        for dependency in ("internal/mobilemultihop/desktop_node_admission.go", "deploy/test_windows_node_max.py", "deploy/test_windows_release_gates.py"):
            self.assertEqual(workflow.count("      - '" + dependency + "'\n"), 2)

    def test_authoritative_all_requires_both_native_hosts_and_every_control(self):
        workflow = (REPOSITORY / ".github/workflows/windows-node-all-contract.yml").read_text(encoding="utf-8")
        check_authoritative_all_workflow(workflow)
        for old, new in (
            ("  workflow_call:\n", ""),
            ("          - {arch: arm64, runner: windows-11-arm, cgo: '0'}\n", ""),
            ("runner: windows-11-arm", "runner: windows-latest"),
            ("cgo: '0'", "cgo: '1'"),
            ("GOARCH: ${{ matrix.arch }}", "GOARCH: amd64"),
            ("    timeout-minutes: 25\n", "    timeout-minutes: 50\n"),
            ("        timeout-minutes: 20\n", "        timeout-minutes: 40\n"),
            ("    timeout-minutes: 25\n", "    if: false\n    timeout-minutes: 25\n"),
            ("        timeout-minutes: 20\n", "        continue-on-error: true\n        timeout-minutes: 20\n"),
            ("cancel-in-progress: false", "cancel-in-progress: true"),
            ("if: matrix.arch == 'amd64'", "if: matrix.arch == 'arm64'"),
            ("go-version: '1.26.3'", "go-version: '1.25.0'"),
            (" --suite prospective-all", " --suite baseline"),
            ("throw 'Actual Windows ALL and restoration failed'", "Write-Host 'ignored ALL failure'"),
        ):
            self.assertEqual(workflow.count(old), 1)
            with self.subTest(mutation=new), self.assertRaises(AssertionError):
                check_authoritative_all_workflow(workflow.replace(old, new, 1))

    def test_owned_process_gates_use_both_real_shells_and_the_captured_package(self):
        for filename, job_name, packaged in (("windows-native-contract.yml", "native-windows", False), ("release-candidate.yml", "windows-native-smoke", True)):
            workflow = (REPOSITORY / ".github/workflows" / filename).read_text(encoding="utf-8")
            job = workflow_job(workflow, job_name)
            for tor_wrapper in (False, True):
                check_owned_process_gate(job, packaged, tor_wrapper)
                source = "$roots[0].FullName" if packaged else "$env:GITHUB_WORKSPACE"
                if tor_wrapper:
                    name = "Execute packaged Tor wrapper lifecycle" if packaged else "Tor wrapper ownership and prelaunch failure witnesses"
                else:
                    name = "Execute packaged suspended-process Job ownership" if packaged else "Windows suspended-process Job ownership"
                for old, new in (
                    ("foreach($shell in @('pwsh','powershell.exe'))", "foreach($shell in @('pwsh'))"),
                    ("-SourceRoot " + source, "-CompileOnly -SourceRoot " + source),
                    ("-SourceRoot " + source, "-SourceRoot 'different source'"),
                ):
                    # Mutate only the exact owned-process step, never an
                    # earlier DNS or separate kernel-owner invocation.
                    marker = "      - name: " + name + "\n"
                    before, after = job.split(marker, 1)
                    with self.subTest(filename=filename, wrapper=tor_wrapper, mutation=new), self.assertRaises(AssertionError):
                        check_owned_process_gate(before + marker + after.replace(old, new, 1), packaged, tor_wrapper)

    def test_wfp_gates_require_both_shells_and_actual_kernel_enforcement(self):
        for filename, job_name, packaged in (("windows-native-contract.yml", "native-windows", False), ("release-candidate.yml", "windows-native-smoke", True)):
            job = workflow_job((REPOSITORY / ".github/workflows" / filename).read_text(encoding="utf-8"), job_name)
            check_wfp_gate(job, packaged)
            name = "Execute packaged Windows WFP enforcement" if packaged else "Executable-scoped Windows WFP enforcement"
            marker = "      - name: " + name + "\n"
            before, after = job.split(marker, 1)
            gate, separator, following = after.partition("      - ")
            source = "$roots[0].FullName" if packaged else "$env:GITHUB_WORKSPACE"
            for old, new in (
                ("foreach($shell in @('pwsh','powershell.exe'))", "foreach($shell in @('pwsh'))"),
                ("shell: pwsh", "continue-on-error: true\n        shell: pwsh"),
            ):
                with self.subTest(file=filename, mutation=new), self.assertRaises(AssertionError):
                    check_wfp_gate(before + marker + gate.replace(old, new, 1) + separator + following, packaged)
            fixtures = ("$test",) if packaged else (
                "client/test-windows-wfp-endpoints.ps1", "client/test-windows-wfp.ps1")
            for fixture in fixtures:
                command = "& $shell -NoProfile -ExecutionPolicy Bypass -File " + fixture + " -SourceRoot " + source
                self.assertEqual(gate.count(command), 1)
                for replacement in (
                    command.replace(" -SourceRoot ", " -CompileOnly -SourceRoot ", 1),
                    command.replace(" -SourceRoot " + source, " -SourceRoot 'unrelated source'", 1),
                    "# omitted " + fixture,
                ):
                    with self.subTest(file=filename, fixture=fixture, mutation=replacement), self.assertRaises(AssertionError):
                        check_wfp_gate(before + marker + gate.replace(command, replacement, 1) + separator + following, packaged)

    def test_broken_release_edges_and_weakened_commands_are_rejected(self):
        candidate = (REPOSITORY / ".github/workflows/release-candidate.yml").read_text(encoding="utf-8")
        build_all = (REPOSITORY / ".github/workflows/build-all.yml").read_text(encoding="utf-8")
        variants = (
            ("cleanup", "Run = '^TestDesktopRuntimeWorkspace'", "Run = '^TestDesktopTor'"),
            ("unix", "python3 deploy/test_desktop_tor_unix_wrapper.py", "true # omitted Unix ownership"),
            ("controller", "run: go test ./...", "run: go test -run '^$' ./..."),
            ("matrix", "{arch: arm64, runner: windows-11-arm}", "{arch: other, runner: windows-latest}"),
            ("shell", "foreach($shell in @('pwsh','powershell.exe')){\n            python deploy/test_windows_release_gates.py", "foreach($shell in @('pwsh')){\n            python deploy/test_windows_release_gates.py"),
            ("source", "--package-root $roots[0].FullName", "--package-root $env:GITHUB_WORKSPACE"),
            ("mutants", "--shell $shell", "--shell $shell --shipping-only"),
            ("blocking", "      - name: Execute packaged device and DNS ownership gates\n", "      - name: Execute packaged device and DNS ownership gates\n        continue-on-error: true\n"),
            ("aggregate", "generic-builds, windows-native-smoke, windows-complete-max, windows-all-controller, android", "generic-builds, windows-complete-max, windows-all-controller, android"),
            ("max-aggregate", "windows-native-smoke, windows-complete-max, windows-all-controller, android", "windows-native-smoke, windows-all-controller, android"),
            ("all-aggregate", "windows-complete-max, windows-all-controller, android", "windows-complete-max, android"),
            ("all-workflow", "uses: ./.github/workflows/windows-node-all-contract.yml", "uses: ./.github/workflows/windows-node-max-contract.yml"),
            ("all-conditional", "  windows-all-controller:\n", "  windows-all-controller:\n    if: false\n"),
            ("all-nonblocking", "  windows-all-controller:\n", "  windows-all-controller:\n    continue-on-error: true\n"),
            ("all-source-audit", "          python3 deploy/test_windows_release_gates.py\n", ""),
            ("max-workflow", "uses: ./.github/workflows/windows-node-max-contract.yml", "uses: ./.github/workflows/windows-node-pq-contract.yml"),
            ("max-conditional", "  windows-complete-max:\n", "  windows-complete-max:\n    if: false\n"),
            ("max-nonblocking", "  windows-complete-max:\n", "  windows-complete-max:\n    continue-on-error: true\n"),
        )
        for name, old, new in variants:
            with self.subTest(name=name):
                self.assertEqual(candidate.count(old), 1, "mutation anchor changed")
                with self.assertRaises(AssertionError):
                    check_workflow(candidate.replace(old, new, 1), build_all)
        with self.assertRaises(AssertionError):
            check_workflow(candidate, build_all.replace("      - release-candidate\n", "", 1))

    def fixture(self, directory):
        package = Path(directory) / "extracted-package"
        for relative in PACKAGE_FILES:
            path = package / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("owned fixture", encoding="utf-8")
        return package

    def modules(self, calls, package, fail="", exit_early=False):
        names = ("test_desktop_startup_settings", "test_desktop_protection_settings", "test_windows_device_settings", "test_windows_home_dns", "test_desktop_dns_settings", "test_desktop_quick_dns", "test_windows_dns_measurement")
        modules = {name: SimpleNamespace(ROOT=REPOSITORY) for name in names}
        modules["test_windows_dns_measurement"].HELPER = REPOSITORY / "client/RouterVPN-Windows-DNSMeasurement.ps1"
        modules["test_windows_dns_measurement"].TEST = REPOSITORY / "client/test-windows-dns-measurement.ps1"
        for name in names[2:]:
            def invoke(name=name):
                self.assertTrue(all(module.ROOT == package for module in modules.values()), "an imported fixture still reads checkout source")
                measurement = modules["test_windows_dns_measurement"]
                self.assertEqual(measurement.HELPER, package / "client/RouterVPN-Windows-DNSMeasurement.ps1")
                self.assertEqual(measurement.TEST, package / "client/test-windows-dns-measurement.ps1")
                calls.append((name, list(sys.argv)))
                if name == fail:
                    if exit_early:
                        raise SystemExit(0)
                    raise RuntimeError("actual fixture failure")
            modules[name].main = invoke
            def windows(directory, shell, invoke=invoke):
                self.assertTrue(directory.is_dir())
                self.assertIn(shell, ("pwsh", "powershell.exe"))
                invoke()
            modules[name].windows = windows
        return modules

    def test_all_existing_harnesses_use_package_sources_and_restore_bindings(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-release-gates-") as directory:
            package = self.fixture(directory).resolve()
            for shell in ("pwsh", "powershell.exe"):
                calls = []
                modules = self.modules(calls, package)
                run_packaged(package, shell, modules.__getitem__)
                self.assertEqual([name for name, _ in calls], ["test_windows_device_settings", "test_windows_home_dns", "test_desktop_dns_settings", "test_desktop_quick_dns", "test_windows_dns_measurement"])
                self.assertTrue(all(arguments[1:3] == ["--shell", shell] for _, arguments in calls))
                self.assertEqual(calls[2][1][3:], ["--platform", "windows"])
                self.assertEqual(calls[3][1][3:], ["--platform", "windows"])
                self.assertTrue(all(module.ROOT == REPOSITORY for module in modules.values()))

    def test_a_failed_or_early_exiting_fixture_blocks_later_gates(self):
        with tempfile.TemporaryDirectory(prefix="routervpn-release-gates-") as directory:
            package = self.fixture(directory).resolve()
            for exit_early in (False, True):
                calls = []
                modules = self.modules(calls, package, "test_windows_home_dns", exit_early)
                with self.assertRaises(RuntimeError):
                    run_packaged(package, "pwsh", modules.__getitem__)
                self.assertEqual(len(calls), 2)
                self.assertTrue(all(module.ROOT == REPOSITORY for module in modules.values()))

    def test_missing_package_member_and_checkout_fallback_fail_before_execution(self):
        with self.assertRaises(ValueError):
            run_packaged(REPOSITORY, "pwsh")
        with tempfile.TemporaryDirectory(prefix="routervpn-release-gates-") as directory:
            package = self.fixture(directory)
            (package / "client/test-windows-home-dns.ps1").unlink()
            with self.assertRaisesRegex(ValueError, "missing client/test-windows-home-dns.ps1"):
                run_packaged(package, "pwsh", lambda _: self.fail("missing package invoked a harness"))

    def test_missing_captured_ui_state_dependency_blocks_both_runtime_gates(self):
        # ProfileSettings and the composed App now import this actual package
        # module. A checkout copy must not satisfy an incomplete release.
        with tempfile.TemporaryDirectory(prefix="routervpn-release-state-dependency-") as directory:
            package = self.fixture(directory)
            (package / "client/RouterVPN-Windows-UIState.psm1").unlink()
            for shell in ("pwsh", "powershell.exe"):
                with self.assertRaisesRegex(ValueError, "missing client/RouterVPN-Windows-UIState.psm1"):
                    run_packaged(package, shell, lambda _: self.fail("missing UI state dependency invoked a harness"))


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
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(WindowsReleaseGateTests))
        if not result.wasSuccessful():
            raise SystemExit(1)


if __name__ == "__main__":
    main()
