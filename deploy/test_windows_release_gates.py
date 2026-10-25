#!/usr/bin/env python3
"""Run existing device/DNS regressions against the extracted release package.

The Python harnesses remain checkout-owned. Every PowerShell source, composed
app helper and test entrypoint they read is bound to the extracted package.
With no arguments, exercise that binding and its authoritative workflow edges.
"""
from __future__ import annotations

import argparse
import importlib
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest

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
    "client/RouterVPN-Windows-ProfileSettings.ps1",
    "client/RouterVPN-Windows-Product-v2.ps1",
    "client/RouterVPN-Windows-UnifiedShell.ps1",
    "client/RouterVPN-Windows-SessionMutation.ps1",
    "client/RouterVPN-Windows-DNSMeasurement.ps1",
    "client/test-windows-device-settings.ps1",
    "client/test-windows-home-dns.ps1",
    "client/test-windows-dns-measurement.ps1",
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
    if "shell: pwsh" not in gate or "& go test -v -count=1 -timeout=180s ./cmd/client -run '^Test(DesktopRuntimeWorkspace|DesktopTor|DesktopDNS|SpeedLab)'" not in gate:
        raise AssertionError("Windows cleanup gate omitted live-handle or captured child tests")
    if "if ($LASTEXITCODE -ne 0) { throw" not in gate or re.search(r"(?m)^        (?:if|continue-on-error):", gate):
        raise AssertionError("Windows cleanup gate no longer blocks a failed native test")


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


def check_workflow(candidate: str, build_all: str) -> None:
    windows = workflow_job(candidate, "windows-native-smoke")
    check_workspace_gate(windows)
    check_owned_process_gate(windows, True)
    check_owned_process_gate(windows, True, True)
    source = workflow_job(candidate, "source-audit")
    for command in ("run: go test ./...", "python3 deploy/test_desktop_tor_unix_wrapper.py", "python3 modes/test_cleanup_private_runtime.py"):
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
    if needs is None or "windows-native-smoke" not in [value.strip() for value in needs.group(1).split(",")]:
        raise AssertionError("release aggregation bypassed Windows native gates")
    release = workflow_job(build_all, "release-candidate")
    publication = workflow_job(build_all, "publish-exact-sha-release")
    if "uses: ./.github/workflows/release-candidate.yml" not in release or "      - release-candidate\n" not in publication:
        raise AssertionError("exact-SHA publication bypassed its authoritative Windows matrix")


class WindowsReleaseGateTests(unittest.TestCase):
    def test_current_workflow_requires_both_architectures_shells_and_publication_edge(self):
        check_workflow((REPOSITORY / ".github/workflows/release-candidate.yml").read_text(encoding="utf-8"), (REPOSITORY / ".github/workflows/build-all.yml").read_text(encoding="utf-8"))

    def test_standalone_windows_runs_the_real_workspace_and_child_tests(self):
        workflow = (REPOSITORY / ".github/workflows/windows-native-contract.yml").read_text(encoding="utf-8")
        job = workflow_job(workflow, "native-windows")
        check_workspace_gate(job)
        for old, new in (("DesktopRuntimeWorkspace|DesktopTor|DesktopDNS|SpeedLab", "DesktopTor"), ("DesktopRuntimeWorkspace|DesktopTor|DesktopDNS|SpeedLab", "DesktopRuntimeWorkspace"), ("& go test -v -count=1 -timeout=180s", "& go test -v -count=1 -timeout=180s -run '^$'")):
            with self.subTest(new=new), self.assertRaises(AssertionError):
                check_workspace_gate(job.replace(old, new, 1))

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

    def test_broken_release_edges_and_weakened_commands_are_rejected(self):
        candidate = (REPOSITORY / ".github/workflows/release-candidate.yml").read_text(encoding="utf-8")
        build_all = (REPOSITORY / ".github/workflows/build-all.yml").read_text(encoding="utf-8")
        variants = (
            ("cleanup", "DesktopRuntimeWorkspace|DesktopTor|DesktopDNS|SpeedLab", "DesktopTor"),
            ("unix", "python3 deploy/test_desktop_tor_unix_wrapper.py", "true # omitted Unix ownership"),
            ("controller", "run: go test ./...", "run: go test -run '^$' ./..."),
            ("matrix", "{arch: arm64, runner: windows-11-arm}", "{arch: other, runner: windows-latest}"),
            ("shell", "foreach($shell in @('pwsh','powershell.exe')){\n            python deploy/test_windows_release_gates.py", "foreach($shell in @('pwsh')){\n            python deploy/test_windows_release_gates.py"),
            ("source", "--package-root $roots[0].FullName", "--package-root $env:GITHUB_WORKSPACE"),
            ("mutants", "--shell $shell", "--shell $shell --shipping-only"),
            ("blocking", "      - name: Execute packaged device and DNS ownership gates\n", "      - name: Execute packaged device and DNS ownership gates\n        continue-on-error: true\n"),
            ("aggregate", "generic-builds, windows-native-smoke, android", "generic-builds, android"),
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
