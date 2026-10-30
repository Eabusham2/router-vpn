#!/usr/bin/env python3
"""Exercise the pinned Windows controller transport and actual shared handler.

This prerequisite can run on the native Linux/macOS host as well as Windows.
It opens only owned loopback listeners. The shipping Windows launcher still
requires its separate native process/pipe and composed GUI acceptance gates.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "internal/controllertransport"
REQUIRED = (
    "TestControllerTransportPinnedTLSAndSharedIdentity",
    "TestControllerTransportWrongPinSendsNoPrivateRequest",
    "TestControllerTransportReauthenticatesReplacementListener",
    "TestControllerTransportNoPlaintextFallback",
    "TestControllerTransportRejectsRedirectAndForeignAddress",
    "TestControllerTransportRetiredOwnerSendsNothing",
    "TestControllerTransportCloseJoinsPendingRead",
    "TestControllerTransportCloseJoinsDetachedDial",
    "TestControllerTransportStaleResponseAndBoundedBodies",
    "TestControllerTransportRejectsFalseIdentityReceipts",
    "TestControllerTransportExactShutdownAndExitedReceipt",
    "TestControllerTransportInvalidCaptureNeverDials",
    "TestLocalControllerPinnedTLSUsesShippingIdentityAndCleanup",
    "TestControllerTransportPreservesExactBundleImportLimit",
    "TestControllerTransportDrainPinnedReadOnly",
    "TestControllerTransportDrainRejectsUnprovedPeer",
    "TestControllerTransportDrainRejectsAmbiguousReceipt",
    "TestControllerTransportDrainRevokesLateResult",
    "TestControllerTransportDrainCancellationAndDeadline",
    "TestControllerTransportDrainPublicAPIJoinsTransport",
    "TestLocalControllerPinnedDrainUsesShippingLifetime",
    "TestLocalControllerPinnedDrainRequiresActualTLSAndExactRequest",
    "TestLocalControllerPinnedDrainUtilityArguments",
    "TestLocalControllerPinnedDrainUtilityReadOnly",
    "TestLocalControllerPinnedDrainUtilityRejectsUnknownAndCancelled",
)


def run(command, env, timeout=180, *, cwd=ROOT):
    result = subprocess.run([str(value) for value in command], cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout, check=False)
    return result.returncode, result.stdout.decode("utf-8", errors="replace")


def selected_compiler(go):
    env = dict(os.environ)
    keys = ("GOROOT", "GOVERSION", "GOHOSTOS", "GOHOSTARCH")
    status, output = run([go, "env", "-json", *keys], env)
    if status:
        raise ValueError("Controller TLS compiler selection failed:\n" + output[-8192:])
    identity = json.loads(output)
    host = {"Windows": "windows", "Linux": "linux", "Darwin": "darwin"}.get(platform.system())
    architecture = identity.get("GOHOSTARCH")
    if identity.get("GOHOSTOS") != host or architecture not in ("amd64", "arm64"):
        raise ValueError("Controller TLS gate requires an actual supported native host")
    if env.get("GOOS", host) != host or env.get("GOARCH", architecture) != architecture:
        raise ValueError("Controller TLS gate refuses cross-compiled execution")
    root = Path(identity["GOROOT"])
    compiler = root / "bin" / ("go.exe" if host == "windows" else "go")
    if not root.is_absolute() or not compiler.is_file():
        raise ValueError("Controller TLS selected compiler is unavailable")
    race = [] if host == "windows" and architecture == "arm64" else ["-race"]
    env.update(GOTOOLCHAIN="local", GOROOT=str(root), GOOS=host, GOARCH=architecture,
               GOWORK="off", GOFLAGS="", CGO_ENABLED="1" if race else "0")
    status, output = run([compiler, "env", "-json", *keys], env)
    if status or json.loads(output) != identity:
        raise ValueError("Controller TLS compiler changed before execution")
    return compiler, env, race


def sources():
    names = ("internal/controllertransport/tls.go", "internal/controllertransport/client.go",
             "internal/controllertransport/client_test.go", "internal/controllertransport/drain.go",
             "internal/controllertransport/drain_test.go", "cmd/client/controller_pinned_tls_test.go",
             "cmd/client/controller_pinned_tls.go", "cmd/client/controller_local_auth.go",
             "cmd/client/controller_shutdown.go", "cmd/client/main.go",
             "cmd/client/windows_controller_drain_utility.go",
             "cmd/client/windows_controller_drain_utility_windows.go",
             "cmd/client/windows_controller_drain_utility_other.go",
             "cmd/client/windows_controller_drain_utility_test.go",
             "cmd/client/windows_controller_drain_utility_windows_test.go",
             "client/Private-RouterVPN-State.ps1")
    records = {}
    for name in names:
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Controller TLS gate requires its actual regular source: " + name)
        records[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def replace_once(value, before, after):
    if value.count(before) != 1:
        raise ValueError("Controller TLS negative control lost its production boundary")
    return value.replace(before, after, 1)


def mutants():
    client = (PACKAGE / "client.go").read_text(encoding="utf-8")
    tls = (PACKAGE / "tls.go").read_text(encoding="utf-8")
    drain = (PACKAGE / "drain.go").read_text(encoding="utf-8")
    return (
        ("tls.go", "wrong-session-certificate", REQUIRED[1],
         "wrong TLS pin admitted a private controller request",
         replace_once(tls, "subtle.ConstantTimeCompare(digest[:], expected) != 1",
                      "subtle.ConstantTimeCompare(digest[:], expected) < 0")),
        ("client.go", "late-owner-result", REQUIRED[8] + "/stale",
         "stale or oversized native result was published",
         replace_once(client, "if !acceptExitedReceipt {", "if !acceptExitedReceipt && false {")),
        ("client.go", "duplicate-identity-fields", REQUIRED[9] + "/duplicate",
         "native controller accepted a false or ambiguous identity receipt",
         replace_once(client, "!wanted[key] || seen[key]", "!wanted[key]")),
        ("client.go", "false-identity-proof", REQUIRED[9] + "/wrong-proof",
         "native controller accepted a false or ambiguous identity receipt",
         replace_once(client,
                      'mac(client.access, "routervpn-controller-identity-response\\n"+strconv.Itoa(identity.PID)+"\\n"+challenge))) != 1',
                      'mac(client.access, "routervpn-controller-identity-response\\n"+strconv.Itoa(identity.PID)+"\\n"+challenge))) < 0')),
        ("client.go", "incomplete-cleanup", REQUIRED[10] + "/not-closed",
         "false shutdown receipt closed another owner",
         replace_once(client, "receipt.PID != int(client.owner.PID()) || !receipt.Closed ||",
                      "receipt.PID != int(client.owner.PID()) ||")),
        ("client.go", "detached-dial-join", REQUIRED[7],
         "transport Close abandoned its detached native dial",
         replace_once(client,
                      "\t\t\tfinish, err := client.begin()\n\t\t\tif err != nil {\n\t\t\t\treturn nil, err\n\t\t\t}\n\t\t\tdefer finish()",
                      "\t\t\tif err := owner.Alive(); err != nil { return nil, err }")),
        ("client.go", "truncated-import-capability", REQUIRED[13],
         "existing 32 MiB bundle import did not reach the pinned controller unchanged",
         replace_once(client, "return 32 << 20", "return 8 << 20")),
        ("client.go", "import-budget-other-route", REQUIRED[13],
         "bundle import request budget escaped its exact supported operation",
         replace_once(client, 'if method == http.MethodPost && path == "/api/profile/import" {',
                      'if true {')),
        ("drain.go", "drain-wrong-process", REQUIRED[16] + "/wrong-owner",
         "ambiguous drain receipt acquired another owner's stop authority",
         replace_once(drain, "receipt.PID != client.owner.PID()", "receipt.PID == 0")),
        ("drain.go", "drain-late-process", REQUIRED[17],
         "late drain response survived its exact retained process",
         replace_once(drain, "if err := client.owner.Alive(); err != nil {", "if err := client.owner.Alive(); false && err != nil {")),
        ("drain.go", "drain-poll-deadline", REQUIRED[18],
         "native drain lost its existing bounded poll deadline",
         replace_once(drain, "const drainTimeout = 400 * time.Millisecond", "const drainTimeout = 5 * time.Second")),
        ("drain.go", "drain-transport-join", REQUIRED[19],
         "public drain abandoned its retained TLS transport after returning",
         replace_once(drain, "\tdefer client.Close()", "\t// Broken: abandon the read-only transport.")),
        ("drain.go", "drain-private-bearer", REQUIRED[14],
         "read-only drain disclosed credentials, body or another operation",
         replace_once(drain, "\tresponse, err := client.http.Do(request)",
                      '\trequest.Header.Set("Authorization", "Bearer " + client.access)\n\tresponse, err := client.http.Do(request)')),
        ("drain.go", "drain-response-bound", REQUIRED[16] + "/oversized",
         "ambiguous drain receipt acquired another owner's stop authority",
         replace_once(replace_once(replace_once(drain,
                      "response.ContentLength > drainLimit", "response.ContentLength > 1<<20"),
                      "io.LimitReader(response.Body, drainLimit+1)", "io.LimitReader(response.Body, 1<<20)"),
                      "len(raw) > drainLimit", "len(raw) > 1<<20")),
        ("drain.go", "drain-failed-http-status", REQUIRED[15] + "/failed-status",
         "failed HTTP response acquired native drain authority",
         replace_once(drain, "response.StatusCode != http.StatusOK || ", "")),
    )


def shipping_mutants():
    pinned = (ROOT / "cmd/client/controller_pinned_tls.go").read_text(encoding="utf-8")
    owner = (ROOT / "cmd/client/controller_local_auth.go").read_text(encoding="utf-8")
    utility = (ROOT / "cmd/client/windows_controller_drain_utility.go").read_text(encoding="utf-8")
    return (
        ("cmd/client/controller_pinned_tls.go", "shipping-listener-plaintext", REQUIRED[20],
         "pinned drain did not cross the actual shipping TLS admission",
         replace_once(pinned, "return tls.NewListener(listener, config), nil",
                      "if config != nil { return listener, nil }; return tls.NewListener(listener, config), nil")),
        ("cmd/client/controller_local_auth.go", "shipping-drain-without-tls", REQUIRED[21],
         "ordinary HTTP acquired pinned native drain authority",
         replace_once(owner, "c.pinnedTLS != nil && r.TLS == nil", "c.pinnedTLS != nil && false")),
        ("cmd/client/controller_pinned_tls.go", "shipping-drain-extra-query", REQUIRED[21] + "/query",
         "non-exact request acquired bounded native drain authority",
         replace_once(pinned, "r.URL.RequestURI() == controllertransport.DrainPath",
                      "(r.URL.RequestURI() == controllertransport.DrainPath || r.URL.Path == controllertransport.DrainPath)")),
        ("cmd/client/controller_local_auth.go", "shipping-drain-retired-gui", REQUIRED[20],
         "retired launcher hid the exact native drain state",
         replace_once(owner, "if c.pinnedTLS != nil && r.URL.Path == controllertransport.DrainPath {",
                      'if c.pinnedTLS != nil && r.URL.Path == controllertransport.DrainPath {\n'
                      '\t\t\tif c.retired() { http.Error(w, "retired", http.StatusServiceUnavailable); return }')),
        ("cmd/client/windows_controller_drain_utility.go", "utility-drain-unknown-result", REQUIRED[24],
         "unknown or cancelled utility observation published stop authority",
         replace_once(utility,
                      "draining, err := controllertransport.ReadDrain(ctx, owner, pin)\n\tif err != nil {",
                      "draining, err := controllertransport.ReadDrain(ctx, owner, pin)\n\tif false && err != nil {")),
    )


def execute_baseline(compiler, env, race, owned):
    outputs = []
    # The Windows shipping-utility fixture owns a 120-second build/run context
    # and narrower 5/8-second child deadlines. Its package watchdog must outlive
    # that fixture so cold compilation cannot kill a valid negative case. Keep
    # compilation separately bounded and ordinary transport execution at 90s.
    for package, selector, seconds in (
            ("./internal/controllertransport", "^TestControllerTransport", 90),
            ("./cmd/client", "^TestLocalControllerPinned", 150)):
        name = "transport" if package.startswith("./internal/") else "shipping-handler"
        binary = owned / (name + (".exe" if platform.system() == "Windows" else ".test"))
        status, output = run([compiler, "test", "-c", "-mod=readonly", "-p=1", *race,
                              "-o", binary, package], env)
        if status:
            raise ValueError("Controller TLS baseline compilation failed: " + package + "\n" + output[-16384:])
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        status, output = run([binary, "-test.run=" + selector, "-test.count=1",
                              "-test.timeout=" + str(seconds) + "s", "-test.v"], env, timeout=seconds+15,
                             cwd=ROOT / package.removeprefix("./"))
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if status:
            raise ValueError("Controller TLS baseline execution failed: " + package + "\n" + output[-32768:])
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Controller TLS baseline executable changed during execution: " + package)
        outputs.append(output)
    return "\n".join(outputs)


def execute(go="go"):
    before = sources()
    compiler, env, race = selected_compiler(go)
    with tempfile.TemporaryDirectory(prefix="routervpn-controller-tls-baseline-") as directory:
        output = execute_baseline(compiler, env, race, Path(directory))
    required = REQUIRED + (("TestLocalControllerPinnedDrainUtilityWindowsExecution",) if platform.system() == "Windows" else ())
    if ("--- SKIP:" in output or "DATA RACE" in output or
            any("--- PASS: " + name + " (" not in output for name in required)):
        raise ValueError("Controller TLS gate did not execute every real transport/handler case")
    if platform.system() == "Windows":
        for kind, cases in (("command", ("running", "draining", "wrong-pin", "wrong-owner", "timeout")),
                            ("wrapper", ("running", "draining", "captured-once", "wrong-pin", "malformed",
                                         "plaintext-fallback", "legacy", "cancelled"))):
            for case in cases:
                name = "TestLocalControllerPinnedDrainUtilityWindowsExecution/" + kind + "/" + case
                if "--- PASS: " + name + " (" not in output:
                    raise ValueError("Controller drain omitted actual Windows utility/wrapper case: " + name)
    with tempfile.TemporaryDirectory(prefix="routervpn-controller-tls-") as directory:
        owned = Path(directory)
        controls = [(PACKAGE / filename, "./internal/controllertransport", name, test, witness, replacement)
                    for filename, name, test, witness, replacement in mutants()]
        controls += [(ROOT / filename, "./cmd/client", name, test, witness, replacement)
                     for filename, name, test, witness, replacement in shipping_mutants()]
        for source, package, name, test, witness, replacement in controls:
            changed = owned / (name + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = owned / (name + ".json")
            overlay.write_text(json.dumps({"Replace": {str(source): str(changed)}}), encoding="utf-8")
            binary = owned / (name + (".exe" if platform.system() == "Windows" else ".test"))
            status, output = run([compiler, "test", "-c", "-mod=readonly", *race,
                                  "-overlay=" + str(overlay), "-o", binary, package], env)
            if status:
                raise ValueError("Controller TLS mutant did not compile: " + name + "\n" + output[-8192:])
            selector = "/".join("^" + part + "$" for part in test.split("/"))
            status, output = run([binary, "-test.run=" + selector, "-test.count=1", "-test.timeout=30s", "-test.v"], env, timeout=45)
            if (status == 0 or witness not in output or "--- FAIL: " + test.split("/")[0] + " (" not in output or
                    "--- SKIP:" in output or "panic: test timed out" in output or "DATA RACE" in output):
                raise ValueError("Controller TLS mutant missed its exact rejection: " + name + "\n" + output[-16384:])
            print("Rejected production controller TLS mutant:", name, flush=True)
    if sources() != before:
        raise ValueError("Controller TLS source changed during its execution gate")
    print("Controller TLS passed", len(required), "required real transport/handler/utility cases and twenty compiled production negative controls; Windows additionally executes the actual command and shipping wrapper with capture, plaintext, owner and cancellation negatives. Native UAC remains separate.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    execute(parser.parse_args().go)
