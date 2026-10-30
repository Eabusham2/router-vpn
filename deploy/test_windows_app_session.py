#!/usr/bin/env python3
"""Run the composed Windows Session with the full shipping controller and UI.

Every child is started by the production Session through its retained native
owners. Disposable installed/Portable layouts contain the separately compiled
production cmd/client and actual App/Tray scripts; no router/node is imported
or connected. The actual elevated CI desktop exercises the explicit already
elevated launch path. Ordinary-user UAC, cross-account consent and real-device
network/visual acceptance remain separate mandatory gates.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "windows_session_native_toolchain", ROOT / "deploy/test_desktop_windows_identity.py")
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
TAG = "routervpn_windows_app_native"
TEST = "TestWindowsAppComposedSession"
CASES = ("installed-selftest", "portable-selftest", "retirement-retry",
         "foreign-launcher", "code-hardlink")


def regular_files(directory):
    """Use the shipping source closure without mutable local test state."""
    count = 0
    for parent, directories, filenames in os.walk(directory, followlinks=False):
        for name in list(directories):
            path = Path(parent) / name
            if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
                raise ValueError("Windows Session source contains a directory link: " + str(path))
            if name.casefold() in (".routervpn-state", "__pycache__"):
                directories.remove(name)
        for name in filenames:
            path = Path(parent) / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("Windows Session source is not a regular file: " + str(path))
            count += 1
            if count > 10000:
                raise ValueError("Windows Session source closure is unbounded")
            yield path


def sources():
    paths = set([*ROOT.glob("cmd/client/*.go"), *ROOT.glob("internal/**/*.go"),
                 ROOT / "go.mod", *ROOT.glob("go.sum"), Path(__file__).resolve(),
                 ROOT / "deploy/materialize-desktop-icons.py",
                 ROOT / "configs/client/modes.json", ROOT / "configs/client/logical-modes.json",
                 ROOT / ".github/workflows/windows-controller-contract.yml",
                 ROOT / ".github/workflows/windows-native-contract.yml"])
    paths.update(regular_files(ROOT / "client"))
    paths.update(regular_files(ROOT / "modes"))
    records = {}
    for path in sorted(paths):
        if path.is_symlink() or not path.is_file():
            raise ValueError("Windows Session gate lost its actual source: " + str(path))
        records[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    required = {"internal/windowsapp/session_windows.go", "internal/windowsapp/session_windows_test.go",
                "cmd/client/controller_privilege_windows.go", "cmd/client/main.go",
                "client/RouterVPN-Windows-App.ps1", "client/RouterVPN-Windows-Tray.ps1",
                "client/RouterVPN-Windows-ControllerTransport.cs",
                "client/RouterVPN-Windows-ControllerTransport.psm1"}
    if not required.issubset(records):
        raise ValueError("Windows Session gate omitted a shipping composition input")
    return records


def system_powershell():
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if length <= 0 or length >= len(buffer):
        raise ValueError("Native Session gate cannot select the actual system interpreter")
    executable = Path(buffer.value) / "WindowsPowerShell/v1.0/powershell.exe"
    if not executable.is_absolute() or not executable.is_file():
        raise ValueError("Native Session gate has no actual Windows PowerShell 5.1 host")
    return executable


def layout(workspace, fixture, shipping, scenario, env):
    root = workspace / (scenario + " layout")
    root.mkdir()
    portable = scenario == "portable-selftest"
    package = root / "App/RouterVPN" if portable else root
    data = root / "Data" if portable else root
    for path in (package, data, package / "runtime", data / "generated"):
        path.mkdir(parents=True, exist_ok=True)
    for name in ("client", "modes"):
        source = ROOT / name
        for path in regular_files(source):
            output = package / name / path.relative_to(source)
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, output)
    for name in ("modes.json", "logical-modes.json"):
        shutil.copyfile(ROOT / "configs/client" / name, package / name)
    shutil.copyfile(shipping, package / "router-vpn-client.exe")
    launcher_name = "RouterVPNPortableCore.exe" if portable else "RouterVPN.exe"
    if scenario == "foreign-launcher":
        launcher_name = "Unrelated.exe"
    launcher = root / launcher_name
    shutil.copyfile(fixture, launcher)
    config = {"listen": "127.0.0.1:8788", "health_url": "http://10.77.0.1:8787/health",
              "auto_test_seconds": 8, "modes_file": str(package / "modes.json"),
              "scripts_dir": str(package / "modes"), "state_file": str(data / "state.json"),
              "profiles_file": str(data / "routers.json")}
    (data / "client.json").write_text(json.dumps(config), encoding="utf-8")
    (data / "routers.json").write_text('{"selected_id":"","profiles":[]}', encoding="utf-8")
    # Two distinct existing stores prove that starting/closing the owned app
    # preserves a newer private Data preference as well as its migration source.
    for state, mode in ((package / "client/.routervpn-state", "wg"),
                        (data / ".routervpn-state", "awg2-fast")):
        state.mkdir(parents=True)
        (state / "windows-selected-mode-v1.txt").write_text(mode + "\n", encoding="utf-8")
        (state / "windows-onboarding-v3.json").write_text(
            '{"version":3,"done":true,"step":0}', encoding="utf-8")
        (state / "windows-custom-presets-v1.json").write_text(
            '[{"id":"owned-session-sentinel","name":"Saved preference","layers":["wireguard"]}]',
            encoding="utf-8")
    status, output = NATIVE.run(
        [sys.executable, ROOT / "deploy/materialize-desktop-icons.py",
         "--png", package / "RouterVPN.png", "--ico", package / "RouterVPN.ico"],
        cwd=ROOT, env=env, timeout=45)
    if status:
        raise ValueError("Actual shipping icon generation failed:\n" + output[-8192:])
    status, output = NATIVE.run(
        [system_powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", package / "client/Protect-RouterVPN-Windows-PrivateRoot.ps1", "-Root", root],
        cwd=root, env=env, timeout=45)
    if status:
        raise ValueError("The actual package ACL helper rejected its owned fixture:\n" + output[-8192:])
    if scenario == "code-hardlink":
        os.link(package / "client/RouterVPN-Windows-ControllerTransport.cs", root / "code-alias.cs")
    return root, launcher


def run_fixture(workspace, fixture, shipping, scenario, env):
    root, launcher = layout(workspace, fixture, shipping, scenario, env)
    digest = hashlib.sha256(launcher.read_bytes()).hexdigest()
    status, output = NATIVE.run(
        [launcher, "-test.run=^" + TEST + "$", "-test.count=1", "-test.timeout=180s",
         "-test.v", root, scenario], cwd=root, env=env, timeout=195)
    if hashlib.sha256(launcher.read_bytes()).hexdigest() != digest:
        raise ValueError("The actual native Session launcher changed during its execution")
    return status, output


def mutants():
    filename = "internal/windowsapp/session_windows.go"
    source = (ROOT / filename).read_text(encoding="utf-8")
    return (
        ("missing-ui-handoff", "native UI self-test omitted an authenticated channel",
         NATIVE.replace_once(source,
                             '\n\t\t\t"-ControllerPipe", pipe.Name(), "-ControllerParentHandle", strconv.FormatUint(parent, 10)}',
                             '}')),
        ("unacknowledged-controller", "Session released code without its authenticated receipt and independent process join",
         NATIVE.replace_once(source, "if s.authenticated && !s.receipt {",
                             "if false && s.authenticated && !s.receipt {")),
    )


def execute(go="go", *, env=None):
    if platform.system() != "Windows":
        raise ValueError("Composed Windows Session proof requires actual Windows execution")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Composed Session gate requires its actual elevated native test desktop")
    before = sources()
    compiler, captured, architecture = NATIVE.selected_compiler(
        go, ROOT, dict(os.environ if env is None else env))
    race = ["-race"] if architecture == "amd64" else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    build = [compiler, "test", "-c", "-mod=readonly", "-tags=" + TAG, *race]
    with tempfile.TemporaryDirectory(prefix="routervpn-windows-session-") as directory:
        workspace = Path(directory)
        shipping = workspace / "shipping-client.exe"
        status, output = NATIVE.run(
            [compiler, "build", "-mod=readonly", "-o", shipping, "./cmd/client"],
            cwd=ROOT, env=captured, timeout=240)
        if status:
            raise ValueError("Actual production Windows main did not compile:\n" + output[-32768:])
        shipping_digest = hashlib.sha256(shipping.read_bytes()).hexdigest()
        fixture = workspace / "session.test.exe"
        status, output = NATIVE.run(
            [*build, "-o", fixture, "./internal/windowsapp"], cwd=ROOT, env=captured, timeout=240)
        if status:
            raise ValueError("Actual native Session fixture did not compile:\n" + output[-32768:])
        fixture_digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
        for scenario in CASES:
            status, output = run_fixture(workspace, fixture, shipping, scenario, captured)
            print(output, end="" if output.endswith("\n") else "\n", flush=True)
            if (status or "--- SKIP:" in output or "DATA RACE" in output or
                    "--- PASS: " + TEST + " (" not in output):
                raise ValueError("Composed Windows Session failed its actual " + scenario + " path")
            print("Actual Windows Session passed: " + scenario, flush=True)
        for name, witness, replacement in mutants():
            changed = workspace / (name + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = workspace / (name + ".json")
            overlay.write_text(json.dumps({"Replace": {
                str(ROOT / "internal/windowsapp/session_windows.go"): str(changed)}}), encoding="utf-8")
            candidate = workspace / (name + ".test.exe")
            status, output = NATIVE.run(
                [*build, "-overlay=" + str(overlay), "-o", candidate, "./internal/windowsapp"],
                cwd=ROOT, env=captured, timeout=240)
            if status:
                raise ValueError("Windows Session negative control did not compile: " + name + "\n" + output[-8192:])
            owned = workspace / name
            owned.mkdir()
            status, output = run_fixture(owned, candidate, shipping, "installed-selftest", captured)
            if (not status or witness not in output or "--- FAIL: " + TEST + " (" not in output or
                    "--- SKIP:" in output or "panic: test timed out" in output or "DATA RACE" in output):
                raise ValueError("Native Session negative control missed its intended boundary: " + name + "\n" + output[-16384:])
            print("Native Windows Session negative control rejected: " + name, flush=True)
        if (sources() != before or hashlib.sha256(shipping.read_bytes()).hexdigest() != shipping_digest or
                hashlib.sha256(fixture.read_bytes()).hexdigest() != fixture_digest):
            raise ValueError("Actual Session source or artifacts changed during native execution")
        print(json.dumps({"schema": 1, "host": "windows/" + architecture,
                          "shipping_main": "executed", "shipping_sha256": shipping_digest,
                          "fixture_sha256": fixture_digest, "native_cases": list(CASES),
                          "installed_and_portable_app_tray": "actual-packaged-selftests-with-owned-status",
                          "native_channel_proofs": "two-per-selftest",
                          "negative_controls": len(mutants()), "source_files": len(before),
                          "source_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
                          "uac_cross_account_and_device_acceptance": "separate-required-gates"}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    execute(parser.parse_args().go)
