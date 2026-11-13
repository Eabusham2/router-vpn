#!/usr/bin/env python3
"""Validate the dormant typed SOCKS5 shared runtime at an exact SHA."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

# Import the reviewed executor, source snapshot and strict ordered-event parser
# from this trusted checkout, never from the candidate or its working directory.
CORE_PATH = Path(__file__).resolve().with_name("test_focused_multihop_clocks.py")
_spec = importlib.util.spec_from_file_location("routervpn_focused_clock_core", CORE_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("trusted focused executor is missing")
CORE = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = CORE
_spec.loader.exec_module(CORE)
Case = CORE.Case

SUITE = "socks-runtime"
PREFIX = "TestNodeChainSOCKSRuntime"
RUNTIME = "internal/mobilemultihop/node_chain_runtime.go"
MEASUREMENT = "internal/mobilemultihop/node_chain_measurement.go"
SOURCE_PATHS = (
    "internal/mobilemultihop/node_chain_socks_runtime.go",
    "internal/mobilemultihop/node_chain_socks_runtime_test.go",
    "internal/mobilemultihop/node_chain.go",
    RUNTIME,
    MEASUREMENT,
)
ROOT_SUFFIXES = (
    "UsesOriginalProofLifecycle", "RequiresExactNativeMiddle", "RetiresChangedOwner",
    "PreservesProofRefusals", "JoinsOriginalCancellation",
    "MeasurementKeepsPublicScopeAndDrain", "KeepsGenericAdmissionClosed",
)
INITIAL_FAULTS = ("missing-interface", "source-object", "config", "metadata", "manager", "middle", "lower", "retired")
CURRENT_FAULTS = ("manager", "middle", "lower", "retired", "engine", "session", "network", "source-hash", "config-hash", "selection")
PROOF_FAULTS = ("first-private", "middle-route", "middle-public-ip", "final-private", "final-dns", "changed-source")
ORIGINAL_ROOTS = (
    "TestNodeChainRuntimeProvesEveryOriginalPrefix",
    "TestNodeChainRuntimeRejectsMiddleAndNativeChanges",
    "TestNodeChainCancellationJoinsLateOriginalCallbacks",
    "TestNodeChainImportedMiddleRequiresPublicProof",
    "TestNodeChainImportedMiddleCancellationJoinsOriginalPublicSocket",
    "TestNodeChainMeasurementsUseEveryCapturedPrivatePrefix",
    "TestNodeChainMeasurementRejectsForeignDestination",
    "TestNodeChainMeasurementRejectsInvalidCallerBeforeOwner",
)
ORIGINAL_FAULTS = ("middle-identity", "middle-death", "dns", "network-on-dns", "public-body", "tls", "source", "config", "engine", "session", "network")
SOURCE_ROOTS = ("TestNodeChainCompleteCapturedPaths", "TestNodeChainImportedMiddleSourceAndNativeProjection")
SCHEMA1_CASES = ("2/", "3/", "4/", "8/", "3/aes-256-gcm", "4/aes-256-gcm+xor-whitening")
# Inventories are taken from the actual original tests at 01950c59. The empty
# imported-public fault is Go's single unnamed child, "#00"; it is mandatory.
MUTATION_PATHS = {
    "omitted-initial-middle-observer": RUNTIME,
    "omitted-current-middle-observer": RUNTIME,
    "widened-middle-measurement-target": MEASUREMENT,
}


def cases(suite: str = SUITE) -> tuple[Case, ...]:
    if suite != SUITE:
        raise ValueError("unknown SOCKS runtime suite")
    expected = {PREFIX + suffix for suffix in ROOT_SUFFIXES}
    for suffix, children in (
        ("UsesOriginalProofLifecycle", ("wg", "awg2-fast", "awg2-strong")),
        ("RequiresExactNativeMiddle", INITIAL_FAULTS),
        ("RetiresChangedOwner", CURRENT_FAULTS),
        ("PreservesProofRefusals", PROOF_FAULTS),
        ("JoinsOriginalCancellation", ("middle-observer", "middle-dial")),
    ):
        expected.update(PREFIX + suffix + "/" + child for child in children)
    original = set(ORIGINAL_ROOTS)
    original.update(ORIGINAL_ROOTS[1] + "/" + fault for fault in ORIGINAL_FAULTS)
    original.update(ORIGINAL_ROOTS[2] + "/" + phase for phase in ("observation", "middle-dial"))
    original.update(ORIGINAL_ROOTS[3] + "/" + fault for fault in ("#00", "middle-stopped", "wrong-public-ip", "changed-source"))
    original.update(ORIGINAL_ROOTS[5] + "/" + count for count in ("3", "8"))
    source = set(SOURCE_ROOTS)
    source.update(SOURCE_ROOTS[0] + "/" + case for case in SCHEMA1_CASES)
    source.update(SOURCE_ROOTS[1] + "/" + mode + "/" + layer
                  for mode in ("wg", "awg2-fast", "awg2-strong")
                  for layer in ("", "aes-256-gcm", "aes-256-gcm+xor-whitening"))
    initial, current, measured = (PREFIX + name for name in
        ("RequiresExactNativeMiddle", "RetiresChangedOwner", "MeasurementKeepsPublicScopeAndDrain"))
    initial_leaves = frozenset(initial + "/" + fault for fault in INITIAL_FAULTS)
    current_leaves = frozenset(current + "/" + fault for fault in ("manager", "middle", "lower", "retired"))
    return (
        Case("new-socks-runtime", "^" + PREFIX, frozenset(expected), 120, 600),
        Case("preserved-original-runtime", "^(" + "|".join(ORIGINAL_ROOTS) + ")$", frozenset(original), 120, 600),
        Case("preserved-schema1-schema2", "^(" + "|".join(SOURCE_ROOTS) + ")$", frozenset(source), 120, 600),
        Case("omitted-initial-middle-observer", "^" + initial + "$", initial_leaves | {initial},
             120, 600, "omitted-initial-middle-observer",
             "missing original SOCKS owner reached native selection or proof", initial_leaves),
        Case("omitted-current-middle-observer", "^" + current + "$/^(manager|middle|lower|retired)$",
             current_leaves | {current}, 120, 600, "omitted-current-middle-observer",
             "changed original SOCKS owner remained healthy", current_leaves),
        Case("widened-middle-measurement-target", "^" + measured + "$", frozenset((measured,)),
             120, 600, "widened-middle-measurement-target",
             "foreign measurement reached the native dialer", frozenset((measured,))),
    )


def mutation_source(case: Case, source: str) -> str:
    if case.mutation == "widened-middle-measurement-target":
        old, new = "if proof.Tag == tag && address == hopmeasure.PublicAddress {", "if proof.Tag == tag {"
    elif case.mutation in ("omitted-initial-middle-observer", "omitted-current-middle-observer"):
        call = "\tif err := c.observeSOCKSMiddleContext(ctx, engine); err != nil {\n\t\treturn err\n\t}\n"
        if case.mutation == "omitted-initial-middle-observer":
            after = "\tif err := externalObservationLock(ctx, &c.runtime.mu); err != nil {\n"
        else:
            after = "\tif selected {\n"
        old, new = call + after, after
    else:
        raise ValueError("unknown SOCKS runtime control")
    if source.count(old) != 1:
        raise ValueError("SOCKS control lost its one exact original guard")
    return source.replace(old, new, 1)


def command_for(go: str, case: Case, overlay: Path | None = None) -> list[str]:
    command = [go, "test", "-race", "-p=2", "-mod=readonly", "-json", "-count=1",
               "-timeout=" + str(case.seconds) + "s", "-run", case.selection]
    if bool(case.mutation) != (overlay is not None):
        raise ValueError("each causal control requires its own compiled overlay")
    if overlay is not None:
        command += ["-overlay", str(overlay)]
    command.append("./internal/mobilemultihop")
    return command


def validate(args: argparse.Namespace) -> None:
    selected = cases(args.suite)
    source, output = Path(args.source).resolve(), Path(args.output).resolve()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        raise ValueError("--source-sha must be an exact lowercase 40-hex commit")
    if output == source or source in output.parents:
        raise ValueError("--output must be outside the candidate source checkout")
    if CORE.git(source, "rev-parse", "HEAD").decode().strip() != args.source_sha:
        raise ValueError("candidate checkout does not match requested source SHA")
    if CORE.git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("candidate checkout is not clean")
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    before = CORE.snapshot(source)
    if any(path not in before or before[path]["mode"] != "100644" for path in SOURCE_PATHS):
        raise ValueError("candidate lost one original regular SOCKS runtime file")
    serialized = json.dumps(before, sort_keys=True, separators=(",", ":")).encode()
    (output / "source-before.json").write_bytes(serialized + b"\n")
    go = shutil.which("go")
    if not go:
        raise ValueError("Go is missing from PATH")
    env = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local", GOFLAGS="", CGO_ENABLED="1",
               GOMAXPROCS="2", GOGC="100", GOMEMLIMIT="2GiB")
    version = subprocess.check_output([go, "version"], env=env, text=True, timeout=30).strip()
    if not re.fullmatch(r"go version go1\.26\.3 linux/amd64", version):
        raise ValueError("focused host gate requires pinned Go1.26.3 linux/amd64: " + version)
    go_environment = json.loads(subprocess.check_output(
        [go, "env", "-json", "GOROOT", "GOPATH", "GOCACHE"], env=env, text=True, timeout=30))
    goroot = Path(go_environment["GOROOT"]).resolve()
    if any(Path(path).resolve() == goroot for path in go_environment["GOPATH"].split(os.pathsep) if path):
        raise ValueError("GOPATH must not equal the captured GOROOT")
    manifest = {
        "schema": 1, "suite": SUITE, "requested_source_sha": args.source_sha,
        "actual_source_sha": CORE.git(source, "rev-parse", "HEAD").decode().strip(),
        "tree_sha": CORE.git(source, "rev-parse", "HEAD^{tree}").decode().strip(),
        "source_file_count": len(before), "source_closure_sha256": hashlib.sha256(serialized).hexdigest(),
        "validator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "trusted_executor_sha256": hashlib.sha256(CORE_PATH.read_bytes()).hexdigest(),
        "go": go, "go_version": version, "go_environment": go_environment,
        "resource_limits": {"parallel_packages": 2, "GOMAXPROCS": 2, "GOGC": 100, "GOMEMLIMIT": "2GiB"},
        "status": "running", "attempts": [],
        "scope": "Shared proof lifecycle with actual HTTP/TLS and explicit native owner doubles; no encrypted SOCKS, Box, TUN or UI acceptance.",
    }

    def save() -> None:
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    save()
    try:
        for case in selected:
            overlay_record, overlay = None, None
            if case.mutation:
                relative = MUTATION_PATHS[case.mutation]
                original = source / relative
                changed = output / (case.name + ".go")
                changed.write_text(mutation_source(case, original.read_text()))
                overlay = output / (case.name + ".overlay.json")
                overlay.write_text(json.dumps({"Replace": {str(original): str(changed)}}) + "\n")
                overlay_record = {"path": relative, "original_sha256": before[relative]["sha256"],
                                  "mutant_sha256": hashlib.sha256(changed.read_bytes()).hexdigest()}
            command = command_for(go, case, overlay)
            log = output / (case.name + ".jsonl")
            started = time.monotonic()
            code, timed_out, joined = CORE.execute(command, source, env, log, case.outer_seconds)
            raw = log.read_bytes()
            record = CORE.verdict(raw, case, code, timed_out, joined)
            record.update(name=case.name, command=command, seconds=round(time.monotonic() - started, 3),
                          go_test_seconds=case.seconds, outer_seconds=case.outer_seconds,
                          log=log.name, log_sha256=hashlib.sha256(raw).hexdigest(), overlay=overlay_record)
            manifest["attempts"].append(record)
            save()
            if CORE.snapshot(source) != before or CORE.git(source, "status", "--porcelain", "--untracked-files=all"):
                raise RuntimeError("candidate source changed during " + case.name)
            if not record["accepted"]:
                raise RuntimeError(case.name + ": " + record["reason"])
            print(json.dumps({"name": case.name, "accepted": True, "exit": code,
                              "passed": len(record["passed"]), "failed": len(record["failed"])}), flush=True)
        manifest["status"] = "passed"
    except BaseException as error:
        manifest["status"] = "failed"
        manifest["error"] = str(error)
        raise
    finally:
        save()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True, choices=(SUITE,))
    parser.add_argument("--source", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True)
    validate(parser.parse_args())
    return 0


if __name__ == "__main__":
    sys.exit(main())
