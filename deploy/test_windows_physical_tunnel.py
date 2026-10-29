#!/usr/bin/env python3
"""Prove actual uniquely owned Wintun readers and their exact WFP permits.

This gate uses the shipping checksum-pinned sing-tun replacement. Only test
compilation adds a real-executable WFP scope through its existing private seam.
Each new adapter remains externally configured: no address, default route or
DNS configuration is changed. The test proves retained LUID ownership,
replacement rejection and retirement; it does not prove a Tor circuit or a
full native VPN connection. No public OS-admission predicate is overlaid.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "windows_tunnel_native_bootstrap", ROOT / "deploy/test_windows_physical_bootstrap.py")
BOOT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BOOT)
IDENTITY = BOOT.IDENTITY
TEST = "TestDesktopSocketWindowsActualWintunBindingAndRetirement"
RESOURCE = ROOT / "deploy/fixtures/windows-physical-bootstrap/tunnel_test.go"
TARGET = "routervpn/mobiletor/desktop_socket_windows_actual_tunnel_test.go"
POLICY = "routervpn/mobiletor/desktop_socket_windows_tunnel.go"


def tree(directory):
    """Enumerate every regular dependency byte, including its embedded DLLs."""
    if directory.is_symlink() or getattr(directory, "is_junction", lambda: False)() or not directory.is_dir():
        raise ValueError("Actual Wintun dependency is not a regular owned directory")
    records = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            raise ValueError("Actual Wintun dependency contains a linked source")
        if path.is_file():
            records[path.relative_to(directory).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif not path.is_dir():
            raise ValueError("Actual Wintun dependency contains a non-regular source")
    if not records:
        raise ValueError("Actual Wintun dependency is empty")
    return records


def compare_tun_source(expected, source):
    reference, actual = tree(expected), tree(source)
    if actual != reference:
        changed = sorted(name for name in reference.keys() | actual.keys() if reference.get(name) != actual.get(name))
        raise ValueError("Actual Wintun dependency differs from its checksum-pinned shipping preparation: " + ", ".join(changed[:8]))
    return actual


def pinned_reference_modules(source, env):
    """Read immutable pre-replacement module authority from the core pin.

    The prepared graph replaces sing-tun locally, so its final go mod tidy may
    remove the original module checksum. Replaying that graph in a fresh
    directory cannot establish the upstream checksum. Read both original
    module files from the exact Git object, without Git replacement objects;
    never add a recovered checksum to the prepared subject.
    """
    modules = {}
    for name in ("go.mod", "go.sum"):
        status, output = IDENTITY.run(
            ["git", "--no-replace-objects", "-C", source, "show", BOOT.PREP.PIN + ":" + name],
            cwd=source, env=env, timeout=30)
        if status or not output:
            raise ValueError("Pinned Wintun reference module read failed: " + name + "\n" + output[-4096:])
        modules[name] = output.encode("utf-8")
    return modules


def verified_tun_source(source, compiler, env):
    """Recreate the shipping transformation privately; never repair the subject."""
    captured = dict(env)
    captured["PATH"] = str(compiler.parent) + os.pathsep + captured.get("PATH", "")
    status, output = IDENTITY.run([compiler, "list", "-mod=readonly", "-m", "-json", BOOT.PREP.DESKTOP_MTU.MODULE],
                                  cwd=source, env=captured, timeout=30)
    if status:
        raise ValueError("Actual Wintun module resolution failed:\n" + output[-4096:])
    selected = json.loads(output)
    replacement = selected.get("Replace", {})
    expected = (source / "routervpn-desktop-tun").resolve()
    if selected.get("Path") != BOOT.PREP.DESKTOP_MTU.MODULE or replacement.get("Path") != "./routervpn-desktop-tun" or \
            Path(replacement.get("Dir", "")).resolve() != expected or Path(selected.get("Dir", "")).resolve() != expected:
        raise ValueError("Actual Wintun compilation selected another module or source directory")
    records = {}
    for name in ("go.mod", "go.sum"):
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Actual Wintun module identity is not a regular source file")
        records[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    modules = pinned_reference_modules(source, captured)
    with tempfile.TemporaryDirectory(prefix="routervpn-wintun-source-") as directory:
        workspace = Path(directory)
        for name, raw in modules.items():
            (workspace / name).write_bytes(raw)
            records["pinned/" + name] = hashlib.sha256(raw).hexdigest()
        status, output = IDENTITY.run([sys.executable, BOOT.PREP.DESKTOP_MTU.__file__, workspace],
                                      cwd=source, env=captured, timeout=90)
        if status:
            raise ValueError("Checksum-pinned Wintun reference preparation failed:\n" + output[-8192:])
        actual = compare_tun_source(workspace / "routervpn-desktop-tun", source / "routervpn-desktop-tun")
    for name, digest in actual.items():
        records["routervpn-desktop-tun/" + name] = digest
    return records


def overlay(source, workspace, changed=None):
    if (source / TARGET).exists() or (source / TARGET).is_symlink():
        raise ValueError("Unowned actual-Wintun test file exists in the prepared source")
    raw = RESOURCE.read_bytes()
    if RESOURCE.is_symlink() or not raw.startswith(b"//go:build windows && routervpn_windows_physical_composition\n"):
        raise ValueError("Actual Wintun fixture escaped its compile-time test tag")
    fixture = workspace / "tunnel_test.go"
    fixture.write_bytes(raw)
    replacements = {str(source / TARGET): str(fixture)}
    if changed is not None:
        path = workspace / "policy.go"
        path.write_text(changed, encoding="utf-8")
        replacements[str(source / POLICY)] = str(path)
    path = workspace / "overlay.json"
    path.write_text(json.dumps({"Replace": replacements}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return path


def mutants(source):
    return (
        ("physical-interface", "actual Wintun binding authorized the captured physical interface",
         IDENTITY.replace_once(source, "if physical.Index == index || physical.LUID == luid {",
                               "if false && (physical.Index == index || physical.LUID == luid) {")),
        ("retained-luid", "actual Wintun filter does not match the exact retained LUID and test image",
         IDENTITY.replace_once(source, "desktopWFPNumber(desktopWFPInterface, 4, luid)",
                               "desktopWFPNumber(desktopWFPInterface, 4, luid^1)")),
        ("stale-reader", "actual Wintun retirement accepted another native reader",
         IDENTITY.replace_once(source, "p.tunnelName != name || p.tunnelIndex != index || ", "")),
    )


def execute(source, go="go", *, prospective=False, env=None, bootstrap_only=False):
    if prospective:
        raise ValueError("Actual Wintun gate never overlays public OS admission")
    if platform.system() != "Windows" or not IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Actual Wintun ownership requires an elevated matching Windows host")
    source, before = BOOT.sources(source)
    compiler, captured, architecture = IDENTITY.selected_compiler(go, source, dict(os.environ if env is None else env))
    race = ["-race"] if architecture == "amd64" and not bootstrap_only else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    tun_before = verified_tun_source(source, compiler, captured)
    fixture_before = hashlib.sha256(RESOURCE.read_bytes()).hexdigest()
    variants = [("baseline", None, None), *mutants((source / POLICY).read_text(encoding="utf-8"))]
    with tempfile.TemporaryDirectory(prefix="routervpn-wintun-native-") as directory:
        root = Path(directory)
        for name, failure, changed in variants:
            workspace = root / name
            workspace.mkdir()
            selected = overlay(source, workspace, changed)
            binary = workspace / "wintun.test.exe"
            command = [compiler, "test", "-c", "-mod=readonly", "-tags=" + ",".join(BOOT.TAGS), *race,
                       "-ldflags=-checklinkname=0", "-overlay=" + str(selected), "-o", binary, "./routervpn/mobiletor"]
            status, output = IDENTITY.run(command, cwd=source, env=captured, timeout=300)
            if status:
                raise ValueError("Actual Wintun " + name + " compilation failed:\n" + output[-16384:])
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            status, output = IDENTITY.run([binary, "-test.run=^" + TEST + "$", "-test.count=1", "-test.timeout=150s", "-test.v"],
                                          cwd=source, env=captured, timeout=165)
            print(output, end="" if output.endswith("\n") else "\n", flush=True)
            if "--- SKIP:" in output or "DATA RACE" in output or "panic:" in output:
                raise ValueError("Actual Wintun " + name + " did not reach its native assertion")
            if output.count("actual Wintun fixture cleanup proved") != 2:
                raise ValueError("Actual Wintun " + name + " did not prove cleanup of both family-policy fixtures")
            if failure is None:
                if status or "--- PASS: " + TEST + " (" not in output:
                    raise ValueError("Actual Wintun binding and retirement did not pass")
            elif status == 0 or failure not in output or "--- FAIL: " + TEST + " (" not in output:
                raise ValueError("Actual Wintun did not reject the intended " + name + " production defect")
            if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
                raise ValueError("Actual Wintun test binary changed during execution")
    if BOOT.sources(source)[1] != before or hashlib.sha256(RESOURCE.read_bytes()).hexdigest() != fixture_before or \
            verified_tun_source(source, compiler, captured) != tun_before:
        raise ValueError("Actual Wintun prepared source changed during native execution")
    print("Actual Wintun IPv4/IPv6 policy, retained LUID, stale-reader rejection and exact WFP/adapter retirement passed; "
          "three real production defects were rejected. No default routes, DNS or public admission changed.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--go", default="go")
    parser.add_argument("--standalone", action="store_true")
    arguments = parser.parse_args()
    if arguments.standalone:
        if arguments.source is not None:
            parser.error("--standalone owns its freshly prepared native source")
        BOOT.standalone(arguments.go, native_test=execute)
    else:
        if arguments.source is None:
            parser.error("a prepared native source or --standalone is required")
        execute(arguments.source, arguments.go)
