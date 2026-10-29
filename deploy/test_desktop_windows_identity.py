#!/usr/bin/env python3
"""Prove the shipping Windows isolated creator against actual kernel endpoints.

This gate requires a matching elevated Windows host. It creates only fresh,
atomically expiring local test accounts and owned loopback socket/echo peers;
it installs no firewall permission or route and never touches an existing user.
The baseline and every negative control execute compiled production Go source.
An unavailable Windows capability is a failure, never a skipped proof.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = "desktop_socket_windows_identity.go"
REQUIRED = (
    "TestDesktopSocketWindowsIdentitySDKLayout",
    "TestDesktopSocketWindowsIdentityBoundKernelEndpoints",
    "TestDesktopSocketWindowsIdentityRejectsOrdinaryTokenSocket",
    "TestDesktopSocketWindowsIdentityRejectsTupleAndCaptureReplacement",
    "TestDesktopSocketWindowsIdentityRetainsTransferredSocketUntilRelease",
    "TestDesktopSocketWindowsIdentityRetainsLateCreationUntilJoin",
    "TestDesktopSocketWindowsIdentityRetainsPartialCreationError",
    "TestDesktopSocketWindowsIdentityRejectsUnjoinedDuplicate",
    "TestDesktopSocketWindowsIdentityRejectsTokenStatisticsReplacement",
    "TestDesktopSocketWindowsIdentityRejectsOtherExecutableAppID",
    "TestDesktopSocketWindowsIdentityImportedTCPAndUDP",
    "TestDesktopSocketWindowsIdentityNativeProtocolAdmission",
)


def checked_sources(source):
    source = Path(source).resolve()
    if source == ROOT:
        package = "./internal/mobiletor"
        target = source / "internal/mobiletor"
    else:
        spec = importlib.util.spec_from_file_location(
            "windows_identity_preparation", ROOT / "deploy/prepare-desktop-external.py")
        preparation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preparation)
        source = preparation.checked_vendor(source)
        target = source / "routervpn/mobiletor"
        package = "./routervpn/mobiletor"
    required = {IDENTITY, "desktop_socket_windows_identity_api.go",
                "desktop_socket_windows_identity_test.go",
                "desktop_socket_native_windows.go", "desktop_socket_source.go"}
    paths = sorted((ROOT / "internal/mobiletor").glob("desktop_socket_*.go"))
    if not required.issubset(path.name for path in paths):
        raise ValueError("Windows identity source/test closure is incomplete")
    records = {}
    for path in paths:
        copied = target / path.name
        if path.is_symlink() or copied.is_symlink() or not copied.is_file():
            raise ValueError("Windows identity source must be the actual regular copied file")
        raw = path.read_bytes()
        if copied.read_bytes() != raw:
            raise ValueError("Windows identity copy differs from shipping source: " + path.name)
        records[path.name] = hashlib.sha256(raw).hexdigest()
    return source, target, package, records


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("Windows identity negative control lost its exact production boundary")
    return text.replace(before, after, 1)


def function_mutant(text, function, before, after):
    start = text.index(function)
    end = text.find("\nfunc ", start + len(function))
    if end < 0:
        end = len(text)
    return text[:start] + replace_once(text[start:end], before, after) + text[end:]


def mutants(text):
    # Each mutant removes one real protection. A failing compile, skipped test,
    # missing capability, unrelated failure, or timeout is not a rejection.
    return (
        ("ordinary-token", REQUIRED[2], "false transfer metadata bypassed independent ordinary-token rejection",
         replace_once(text,
                      "properties.TokenModifiedID != p.statistics.ModifiedID || !bytes.Equal(appID, p.appID)",
                      "!bytes.Equal(appID, p.appID)")),
        ("other-executable", REQUIRED[9], "identical file bytes replaced the independently read process appId",
         replace_once(text,
                      "properties.TokenModifiedID != p.statistics.ModifiedID || !bytes.Equal(appID, p.appID)",
                      "properties.TokenModifiedID != p.statistics.ModifiedID")),
        ("bound-tuple", REQUIRED[3], "metadata changed the independently read bound tuple",
         replace_once(text,
                      "local.Addr() != creation.Binding.LocalAddress || local.Port() == 0",
                      "local.Port() == 0")),
        ("token-statistics", REQUIRED[8], "caller token statistics replaced actual GetTokenInformation authority",
         replace_once(text, "!bytes.Equal(sid, p.sid) || statistics != p.statistics",
                      "!bytes.Equal(sid, p.sid) || statistics.ModifiedID == 0")),
        ("open-transfer", REQUIRED[4], "source retired while the transferred socket remained open",
         function_mutant(text,
                         "func (p *DesktopWindowsSocketIdentity) ReleaseSocket(",
                         "if record.handedOut {", "if false {")),
        ("late-creation", REQUIRED[5], "late never-transferred socket was not retired after joining",
         function_mutant(text,
                         "func (p *DesktopWindowsSocketIdentity) Close(",
                         "if record.handedOut {", "if true {")),
        ("partial-creation", REQUIRED[6], "partial creation error stranded its owned resource",
         function_mutant(text,
                         "func (p *DesktopWindowsSocketIdentity) Close(",
                         "if record.handedOut {", "if true {")),
        ("duplicate-retirement", REQUIRED[7], "retirement ignored a real unjoined duplicate of the ALE endpoint",
         function_mutant(text,
                         "func (p *DesktopWindowsSocketIdentity) ReleaseSocket(",
                         "if record.endpoint != 0 {", "if false {")),
        ("atomic-expiry", REQUIRED[1], "lost its atomic bounded creation window",
         replace_once(text, "Expires: p.expires,", "Expires: ^uint32(0),")),
    )


def run(command, *, cwd, env, timeout=180):
    process = subprocess.Popen([str(value) for value in command], cwd=cwd, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    try:
        raw, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Only this newly owned process tree is terminated. The real fixture
        # creates no child helper/token process and accounts expire atomically.
        if process.poll() is None:
            subprocess.run(["taskkill.exe", "/F", "/T", "/PID", str(process.pid)],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=10)
        raw, _ = process.communicate(timeout=10)
        raise RuntimeError("Windows identity gate timed out; no proof accepted:\n" +
                           raw[-32768:].decode("utf-8", errors="replace"))
    return process.returncode, raw.decode("utf-8", errors="replace")


def selected_compiler(go, source, env):
    status, output = run([go, "env", "-json", "GOROOT", "GOVERSION", "GOHOSTOS", "GOHOSTARCH"],
                         cwd=source, env=env)
    if status:
        raise ValueError("Windows identity Go selection failed:\n" + output[-8192:])
    identity = json.loads(output)
    if (not isinstance(identity, dict) or identity.get("GOHOSTOS") != "windows" or
            identity.get("GOHOSTARCH") not in ("amd64", "arm64") or
            not identity.get("GOROOT") or not identity.get("GOVERSION")):
        raise ValueError("Windows identity gate requires the actual native Windows toolchain")
    root = Path(identity["GOROOT"])
    compiler = root / "bin/go.exe"
    if not root.is_absolute() or not compiler.is_file():
        raise ValueError("Selected Windows Go compiler is unavailable")
    if env.get("GOOS", "windows") != "windows" or env.get("GOARCH", identity["GOHOSTARCH"]) != identity["GOHOSTARCH"]:
        raise ValueError("Windows identity gate cannot execute a cross-compiled identity fixture")
    captured = dict(env, GOTOOLCHAIN="local", GOROOT=str(root), GOOS="windows",
                    GOARCH=identity["GOHOSTARCH"], GOWORK="off", GOFLAGS="")
    status, output = run([compiler, "env", "-json", "GOROOT", "GOVERSION", "GOHOSTOS", "GOHOSTARCH"],
                         cwd=source, env=captured)
    if status or json.loads(output) != identity:
        raise ValueError("Selected Windows identity compiler changed before the gate")
    return compiler, captured, identity["GOHOSTARCH"]


def execute(source=ROOT, go="go", *, env=None):
    if platform.system() != "Windows":
        raise ValueError("Windows identity proof requires actual Windows execution")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Windows identity proof requires the elevated native test host")
    source, target, package, before = checked_sources(source)
    captured = dict(os.environ if env is None else env)
    compiler, captured, architecture = selected_compiler(go, source, captured)
    changes = mutants((target / IDENTITY).read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="routervpn-windows-identity-") as directory:
        workspace = Path(directory)
        binary = workspace / "identity.test.exe"
        race = ["-race"] if architecture == "amd64" else []
        captured["CGO_ENABLED"] = "1" if race else "0"
        build = [compiler, "test", "-c", "-mod=readonly", "-tags=routervpn_windows_identity", *race]
        status, output = run([*build, "-o", binary, package], cwd=source, env=captured)
        if status:
            raise ValueError("Windows identity baseline compilation failed:\n" + output[-32768:])
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        status, output = run([binary, "-test.run=^TestDesktopSocketWindowsIdentity", "-test.count=1",
                              "-test.timeout=120s", "-test.v"], cwd=source, env=captured, timeout=135)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if (status or "--- SKIP:" in output or
                any("--- PASS: " + name + " (" not in output for name in REQUIRED)):
            raise ValueError("Windows identity baseline did not execute every actual kernel proof")
        for address in ("127.0.0.1", "::1"):
            for network in ("tcp", "udp"):
                if "--- PASS: " + REQUIRED[1] + "/" + network + "-" + address + " (" not in output:
                    raise ValueError("Windows identity baseline omitted an actual socket family")
        for family in ("4", "6"):
            for network in ("tcp", "udp"):
                if "--- PASS: " + REQUIRED[10] + "/" + network + family + " (" not in output:
                    raise ValueError("Windows identity baseline omitted native imported I/O")
                if "--- PASS: " + REQUIRED[11] + "/" + network + family + " (" not in output:
                    raise ValueError("Windows identity baseline omitted actual protocol admission")
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Windows identity binary changed during actual execution")
        for name, test, witness, replacement in changes:
            changed = workspace / (name + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = workspace / (name + ".json")
            overlay.write_text(json.dumps({"Replace": {str(target / IDENTITY): str(changed)}}), encoding="utf-8")
            candidate = workspace / (name + ".test.exe")
            status, output = run([*build, "-overlay=" + str(overlay), "-o", candidate, package],
                                 cwd=source, env=captured)
            if status:
                raise ValueError("Windows identity negative control failed to compile: " + name + "\n" + output[-8192:])
            status, output = run([candidate, "-test.run=^" + test + "$", "-test.count=1",
                                  "-test.timeout=40s", "-test.v"], cwd=source, env=captured, timeout=50)
            if (status == 0 or "--- FAIL: " + test + " (" not in output or
                    witness not in output or "--- SKIP:" in output or
                    "panic: test timed out" in output or "DATA RACE" in output):
                raise ValueError("Windows identity negative control did not reject its exact broken behavior: " + name + "\n" + output[-16384:])
            print("Rejected production Windows identity mutant:", name, flush=True)
        if checked_sources(source)[3] != before:
            raise ValueError("Windows identity source changed during its actual native gate")
    print("Windows isolated identity passed twelve kernel/lifecycle cases, all four bound/imported-I/O/protocol socket families, and nine production negative controls; WFP permit enforcement remains a separate gate.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", nargs="?", type=Path, default=ROOT)
    parser.add_argument("--go", default="go")
    arguments = parser.parse_args()
    execute(arguments.source, arguments.go)
