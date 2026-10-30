#!/usr/bin/env python3
"""Execute the bounded native UI bridge against actual blocking streams.

This portable prerequisite runs on the selected matching Go toolchain, with the
race detector where supported. It uses net.Pipe and opens no external listener.
The Windows pipe adapter's actual peer authentication and GUI lifecycle remain
separate mandatory composition gates; framing alone never confers authority.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import platform
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "internal/controllerbridge"
SPEC = importlib.util.spec_from_file_location(
    "controller_bridge_native_compiler", ROOT / "deploy/test_windows_controller_transport.py")
TRANSPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSPORT)

REQUIRED = (
    "TestControllerBridgeIndependentHeaderEncoding",
    "TestControllerBridgeHeaderRejectsMalformedControls",
    "TestControllerBridgeTargetRejectsOtherAuthorities",
    "TestControllerBridgeForwardsExactBytesAndHTTPStatus",
    "TestControllerBridgeCompleteImportAndAggregateBound",
    "TestControllerBridgeRejectsOversizedOrdinaryBodyBeforeRead",
    "TestControllerBridgeCancellationRetainsJoinAndOtherRequest",
    "TestControllerBridgeOldCancelCannotTouchNewOwner",
    "TestControllerBridgeRejectsReplayedAndFutureIDs",
    "TestControllerBridgeBoundsSimultaneousOperations",
    "TestControllerBridgeOwnerCloseJoinsEnteredForwarder",
    "TestControllerBridgeTruncatedFrameRetiresWithoutForwarding",
    "TestControllerBridgeSuppressesNativeErrorContext",
    "TestControllerBridgeRejectsUnboundedForwarderResponse",
    "TestControllerBridgeQueuedReplyRechecksCancellation",
    "TestControllerBridgeSpeedLabCapturedDeadline",
)


def sources():
    expected = {"protocol.go", "server.go", "server_test.go"}
    paths = sorted(PACKAGE.glob("*.go"))
    if PACKAGE.is_symlink() or {path.name for path in paths} != expected:
        raise ValueError("Controller bridge production/test source closure changed")
    paths.extend(ROOT / name for name in (
        "go.mod", "internal/controllertransport/client.go",
        "internal/controllertransport/tls.go", "deploy/test_windows_controller_transport.py",
        "deploy/test_windows_controller_bridge.py"))
    checksum = ROOT / "go.sum"
    if checksum.exists() or checksum.is_symlink():
        paths.append(checksum)
    records = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Controller bridge requires actual regular source: " + str(path))
        records[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def mutants():
    protocol = (PACKAGE / "protocol.go").read_text(encoding="utf-8")
    server = (PACKAGE / "server.go").read_text(encoding="utf-8")
    once = TRANSPORT.replace_once
    return (
        ("server.go", "speed-lab-deadline-route", REQUIRED[15] + "/other",
         "another operation borrowed the Speed Lab deadline",
         once(server, " || header.TimeoutMS > RequestTimeoutLimit(method, target)", "")),
        ("server.go", "replayed-request-owner", REQUIRED[8] + "/replayed-request",
         "replayed or future request identity was admitted",
         once(server, " || h.ID != s.last+1", "")),
        ("server.go", "cancel-newest-owner", REQUIRED[7],
         "old cancellation mutated a replacement owner",
         once(server, "if request := s.pending[id]; request != nil {",
              "if request := s.pending[s.last]; request != nil {")),
        ("server.go", "cancelled-response-payload", REQUIRED[6],
         "cancelled late response published private bytes or lost its terminal join",
         once(once(server, "case request.ctx.Err() != nil:", "case false:"),
              "if request.ctx.Err() != nil {", "if false {")),
        ("server.go", "queued-cancellation-snapshot", REQUIRED[14],
         "queued cancelled response published its previous private result",
         once(server, "if request.ctx.Err() != nil {", "if false {")),
        ("server.go", "aggregate-byte-budget", REQUIRED[4],
         "aggregate UI request byte budget admitted an unbounded third owner",
         once(server, " || s.reserved > MaxReserved-charge", "")),
        ("server.go", "pending-operation-budget", REQUIRED[9],
         "UI channel exceeded its captured pending operation count",
         once(server, " || len(s.pending) >= MaxPending", "")),
        ("server.go", "entered-forwarding-join", REQUIRED[10],
         "UI channel Close abandoned an entered controller operation",
         once(server, "\ts.workers.Wait()", "\t// Broken: entered forwarding is not joined.")),
        ("protocol.go", "foreign-api-origin", REQUIRED[2],
         "UI channel admitted a foreign, aliased or launcher-only target http://127.0.0.1:8788/api/status",
         once(once(protocol, ' || !strings.HasPrefix(target, "/api/")', ""),
              'resource.IsAbs() || resource.Host != "" || ', "")),
        ("protocol.go", "launcher-only-target", REQUIRED[2],
         "UI channel admitted a foreign, aliased or launcher-only target /api/controller/shutdown",
         once(protocol,
              'strings.HasPrefix(resource.Path, "/api/controller/") || resource.Path == "/api/controller"',
              "false")),
        ("server.go", "captured-response-budget", REQUIRED[13],
         "UI channel published bytes beyond the captured response bound",
         once(server, " || uint64(len(result.Body)) > uint64(h.ResponseLimit)", "")),
        ("protocol.go", "truncated-import-capability", REQUIRED[4],
         "existing complete import failed",
         once(protocol, "return MaxImport", "return MaxBody")),
        ("server.go", "private-error-context", REQUIRED[12],
         "raw native transport error leaked through UI failure",
         once(server, '[]byte("The captured local controller request failed.")', "[]byte(err.Error())")),
        ("protocol.go", "reserved-header-fields", REQUIRED[1],
         "malformed frame header acquired a request reservation",
         once(protocol, " || value[22] != 0 || value[23] != 0", "")),
        ("server.go", "clipped-action-deadline", REQUIRED[3],
         "bridge clipped the captured long-running action deadline",
         once(server, "time.Duration(h.TimeoutMS)*time.Millisecond", "15*time.Second")),
    )


def execute(go="go"):
    before = sources()
    compiler, env, race = TRANSPORT.selected_compiler(go)
    run = TRANSPORT.run
    with tempfile.TemporaryDirectory(prefix="routervpn-controller-bridge-") as directory:
        owned = Path(directory)
        suffix = ".exe" if platform.system() == "Windows" else ".test"
        baseline = owned / ("bridge" + suffix)
        build = [compiler, "test", "-c", "-mod=readonly", *race]
        status, output = run([*build, "-o", baseline, "./internal/controllerbridge"], env)
        if status:
            raise ValueError("Controller bridge compilation failed:\n" + output[-16384:])
        identity = hashlib.sha256(baseline.read_bytes()).hexdigest()
        status, output = run([baseline, "-test.run=^TestControllerBridge", "-test.count=1",
                              "-test.timeout=60s", "-test.v"], env, timeout=75)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if (status or "--- SKIP:" in output or "DATA RACE" in output or
                any("--- PASS: " + name + " (" not in output for name in REQUIRED)):
            raise ValueError("Controller bridge did not execute every actual stream/lifecycle case")
        if hashlib.sha256(baseline.read_bytes()).hexdigest() != identity:
            raise ValueError("Controller bridge test binary changed during execution")
        for filename, name, test, witness, replacement in mutants():
            changed = owned / (name + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = owned / (name + ".json")
            overlay.write_text(json.dumps({"Replace": {str(PACKAGE / filename): str(changed)}}), encoding="utf-8")
            candidate = owned / (name + suffix)
            status, output = run([*build, "-overlay=" + str(overlay), "-o", candidate,
                                  "./internal/controllerbridge"], env)
            if status:
                raise ValueError("Controller bridge mutant did not compile: " + name + "\n" + output[-8192:])
            selector = "/".join("^" + part + "$" for part in test.split("/"))
            status, output = run([candidate, "-test.run=" + selector, "-test.count=1",
                                  "-test.timeout=20s", "-test.v"], env, timeout=30)
            if (status == 0 or witness not in output or "--- FAIL: " + test.split("/")[0] + " (" not in output or
                    "--- SKIP:" in output or "panic: test timed out" in output or "DATA RACE" in output):
                raise ValueError("Controller bridge mutant missed its exact rejection: " + name + "\n" + output[-16384:])
            print("Rejected production controller bridge mutant:", name, flush=True)
        if sources() != before:
            raise ValueError("Controller bridge source changed during its execution gate")
    print("Controller bridge passed", len(REQUIRED), "actual blocking-stream cases and", len(mutants()), "compiled production negative controls; native Windows pipe authentication and GUI composition remain separate.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    execute(parser.parse_args().go)
