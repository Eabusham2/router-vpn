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
)


def run(command, env, timeout=180):
    result = subprocess.run([str(value) for value in command], cwd=ROOT, env=env,
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
             "cmd/client/controller_local_auth.go", "cmd/client/controller_shutdown.go")
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


def execute(go="go"):
    before = sources()
    compiler, env, race = selected_compiler(go)
    status, output = run(
        [compiler, "test", "-mod=readonly", *race, "./internal/controllertransport", "./cmd/client",
         "-run", "^(TestControllerTransport|TestLocalControllerPinnedTLSUsesShippingIdentityAndCleanup)",
         "-count=1", "-timeout=90s", "-v"], env)
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    if (status or "--- SKIP:" in output or "DATA RACE" in output or
            any("--- PASS: " + name + " (" not in output for name in REQUIRED)):
        raise ValueError("Controller TLS gate did not execute every real transport/handler case")
    with tempfile.TemporaryDirectory(prefix="routervpn-controller-tls-") as directory:
        owned = Path(directory)
        for filename, name, test, witness, replacement in mutants():
            changed = owned / (name + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = owned / (name + ".json")
            overlay.write_text(json.dumps({"Replace": {str(PACKAGE / filename): str(changed)}}), encoding="utf-8")
            binary = owned / (name + (".exe" if platform.system() == "Windows" else ".test"))
            status, output = run([compiler, "test", "-c", "-mod=readonly", *race,
                                  "-overlay=" + str(overlay), "-o", binary, "./internal/controllertransport"], env)
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
    print("Controller TLS passed twenty real transport/shipping-handler cases and fifteen compiled production negative controls, including the credential-free pinned drain; Windows launcher and native wrapper adoption remain separate.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    execute(parser.parse_args().go)
