#!/usr/bin/env python3
"""Execute the shipping Windows child preparation and checked HTTP lifecycle.

The full production cmd/client is compiled separately. The executed test binary
uses the actual shipping preparation, token/pipe/image capture, original-user
policy, catalog capture, pinned TLS and cleanup, with disposable installed and
Portable layouts. It does not claim that ShellExecute/UAC or the complete GUI
launcher works; those remain distinct mandatory native gates.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "windows_child_native_toolchain", ROOT / "deploy/test_desktop_windows_identity.py")
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
TAG = "routervpn_controller_windows_native"
REQUIRED = (
    "TestWindowsOwnedControllerNativeEntry",
    "TestWindowsOwnedControllerCodeAndPrivateACLPolicy",
    "TestOwnedWindowsCatalogUsesImmutableSourceAndCapturedCommands",
    "TestOwnedWindowsCatalogRejectsMutableCommandAuthority",
    "TestOwnedWindowsCatalogRejectsUnboundedOrAmbiguousSource",
    "TestLocalControllerNativeOwnerRevokesWritesButRetainsPinnedDrain",
    "TestLocalControllerNativeOwnerOwnsConfigurationAndClose",
    "TestWindowsOwnedControllerPrivateRootRetainsNamespace",
    "TestWindowsOwnedControllerProtectedSelfBeforeConfiguration",
    "TestWindowsOwnedControllerProtectedSelfRetirement",
)
CASES = ("installed-eof", "portable-eof", "portable-outer-eof", "installed-extra-byte", "foreign-layout",
         "unsafe-config", "code-hardlink", "config-hardlink", "private-public-read",
         "portable-runtime-hardlink", "malformed-private", "injected-catalog")


def sources():
    # Compile the actual command package, not a copied approximation. Capturing
    # its entire local Go dependency tree also catches a missing new adapter.
    paths = sorted([*ROOT.glob("cmd/client/*.go"), *ROOT.glob("internal/**/*.go"),
                    *ROOT.glob("go.mod"), *ROOT.glob("go.sum"), ROOT / "configs/client/modes.json"])
    records = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Windows child gate requires its actual regular source: " + str(path))
        records[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    required = {"cmd/client/controller_privilege_windows.go",
                "cmd/client/controller_privilege_windows_native_test.go",
                "cmd/client/controller_windows_catalog.go", "cmd/client/private_store_owner_windows.go",
                "internal/windowsbootstrap/protocol.go"}
    if not required.issubset(records):
        raise ValueError("Windows child gate lost its shipping source closure")
    return records


def mutants():
    read = lambda name: (ROOT / name).read_text(encoding="utf-8")
    once = NATIVE.replace_once
    owner_name = "cmd/client/controller_local_auth.go"
    owner = read(owner_name)
    catalog_name = "cmd/client/controller_windows_catalog.go"
    catalog = read(catalog_name)
    capture_name = "cmd/client/controller_privilege_windows.go"
    capture = read(capture_name)
    permissions_name = "cmd/client/private_runtime_permissions_windows.go"
    permissions = read(permissions_name)
    return (
        (owner_name, "native-capture-admission", REQUIRED[5],
         "missing native capture acquired read-only authority",
         once(owner, "c.callerUID == 0 && c.nativeOwner.Captured()", "c.callerUID == 0")),
        (catalog_name, "mutable-command-authority", REQUIRED[3] + "/up",
         "writable catalog acquired elevated command or policy authority",
         once(catalog, "if !reflect.DeepEqual(operation.given, operation.before) &&",
              "if false && !reflect.DeepEqual(operation.given, operation.before) &&")),
        (capture_name, "configuration-leaf-escape", REQUIRED[0] + "/unsafe-config",
         "unsafe Windows package/configuration reached private handshake",
         once(capture, "if !matched {", "if !matched && false {")),
        (capture_name, "portable-runtime-not-retained", REQUIRED[0] + "/portable-runtime-hardlink",
         "unsafe Windows package/configuration reached private handshake",
         once(capture,
              '[]string{filepath.Join(c.packageRoot, "bin"), filepath.Join(c.dataRoot, "runtime")}',
              '[]string{filepath.Join(c.packageRoot, "bin"), filepath.Join(c.packageRoot, "runtime")}')),
        (permissions_name, "private-file-hardlink", REQUIRED[0] + "/config-hardlink",
         "unsafe Windows package/configuration reached private handshake",
         once(permissions, "info.Mode().IsRegular() && attributes.NumberOfLinks != 1",
              "false && info.Mode().IsRegular() && attributes.NumberOfLinks != 1")),
        (permissions_name, "public-code-writer", REQUIRED[1] + "/public-write",
         "immutable Windows package admitted the wrong code ACL",
         once(permissions, "readOnly := publicRead && (", "readOnly := publicRead || (")),
        (capture_name, "metadata-only-private-root", REQUIRED[7],
         "captured controller private root allowed namespace replacement",
         once(capture, "windowsRuntimeReadControl|windowsRuntimeReadAttributes|syscall.FILE_LIST_DIRECTORY",
              "windowsRuntimeReadControl|windowsRuntimeReadAttributes")),
        (capture_name, "initial-private-self-proof", REQUIRED[8],
         "private configuration bytes escaped a retired protected self capture",
         once(capture,
              "errors.Join(c.ctx.Err(), c.protectedSelf.Verify(), c.self.VerifyImage(c.selfImage), c.parent.Alive())",
              "errors.Join(c.ctx.Err(), c.self.VerifyImage(c.selfImage), c.parent.Alive())")),
        (capture_name, "protected-self-before-worker-join", REQUIRED[9],
         "protected self pins retired before the captured worker joined",
         once(capture, "\t\tc.workers.Wait()",
              "\t\tif c.protectedSelf != nil { c.closeErr = errors.Join(c.closeErr, c.protectedSelf.Close()) }\n\t\tc.workers.Wait()")),
    )


def execute(go="go", *, env=None):
    if platform.system() != "Windows":
        raise ValueError("Windows child entry proof requires actual Windows execution")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Windows child entry proof requires its actual elevated native host")
    before = sources()
    compiler, captured, architecture = NATIVE.selected_compiler(
        go, ROOT, dict(os.environ if env is None else env))
    race = ["-race"] if architecture == "amd64" else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    package = "./cmd/client"
    with tempfile.TemporaryDirectory(prefix="routervpn-windows-child-") as directory:
        workspace = Path(directory)
        shipping = workspace / "router-vpn-client.exe"
        status, output = NATIVE.run(
            [compiler, "build", "-mod=readonly", "-o", shipping, package],
            cwd=ROOT, env=captured, timeout=240)
        if status:
            raise ValueError("Actual shipping Windows controller did not compile:\n" + output[-32768:])
        shipping_digest = hashlib.sha256(shipping.read_bytes()).hexdigest()
        build = [compiler, "test", "-c", "-mod=readonly", "-tags=" + TAG, *race]
        binary = workspace / "owned-child.test.exe"
        status, output = NATIVE.run([*build, "-o", binary, package], cwd=ROOT, env=captured, timeout=240)
        if status:
            raise ValueError("Actual Windows child preparation fixture did not compile:\n" + output[-32768:])
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        expression = "^(" + "|".join(REQUIRED) + ")$"
        status, output = NATIVE.run(
            [binary, "-test.run=" + expression, "-test.count=1", "-test.timeout=180s", "-test.v"],
            cwd=ROOT / "cmd/client", env=captured, timeout=195)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        expected = (*REQUIRED, *(REQUIRED[0] + "/" + case for case in CASES))
        if (status or "--- SKIP:" in output or "DATA RACE" in output or
                any("--- PASS: " + name + " (" not in output for name in expected)):
            raise ValueError("Windows child did not execute every captured native entry boundary")
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Windows child native fixture changed during execution")
        for filename, name, test, witness, replacement in mutants():
            changed = workspace / (name + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = workspace / (name + ".json")
            overlay.write_text(json.dumps({"Replace": {str(ROOT / filename): str(changed)}}), encoding="utf-8")
            candidate = workspace / (name + ".test.exe")
            status, output = NATIVE.run(
                [*build, "-overlay=" + str(overlay), "-o", candidate, package],
                cwd=ROOT, env=captured, timeout=240)
            if status:
                raise ValueError("Windows child mutant failed to compile: " + name + "\n" + output[-8192:])
            status, output = NATIVE.run(
                [candidate, "-test.run=^" + test + "$", "-test.count=1", "-test.timeout=45s", "-test.v"],
                cwd=ROOT / "cmd/client", env=captured, timeout=55)
            if (not status or witness not in output or "--- FAIL: " + test + " (" not in output or
                    "--- SKIP:" in output or "panic: test timed out" in output or "DATA RACE" in output):
                raise ValueError("Windows child negative control missed its intended boundary: " + name + "\n" + output[-16384:])
            print("Windows child negative control rejected: " + name, flush=True)
        if sources() != before or hashlib.sha256(shipping.read_bytes()).hexdigest() != shipping_digest:
            raise ValueError("Windows controller source or shipping binary changed during the gate")
        print(json.dumps({"schema": 1, "host": "windows/" + architecture,
                          "shipping_main": "compiled", "shipping_sha256": shipping_digest,
                          "native_child_preparation": "executed", "fixture_sha256": digest,
                          "native_entry_cases": len(CASES), "negative_controls": len(mutants()),
                          "source_files": len(before), "source_sha256": hashlib.sha256(
                              json.dumps(before, sort_keys=True).encode()).hexdigest(),
                          "uac_launcher_acceptance": "separate-required-gate",
                          "cross_account_profile_acceptance": "separate-required-gate"}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    execute(parser.parse_args().go)
