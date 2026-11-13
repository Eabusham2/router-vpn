#!/usr/bin/env python3
"""Validate only the dormant typed SOCKS5 ordered-source compiler at an exact SHA."""
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

SUITE = "socks-source"
PREFIX = "TestNodeChainSOCKSSource"
COMPILER = "internal/mobilemultihop/node_chain_socks_source.go"
SOURCE_PATHS = (
    "internal/mobilemultihop/node_chain_imported_socks.go",
    COMPILER,
    "internal/mobilemultihop/node_chain_socks_source_test.go",
)
PRESERVATION_ROOTS = (
    "TestNodeChainCompleteCapturedPaths",
    "TestNodeChainOrderSourceAndBounds",
    "TestNodeChainImportedMiddleSourceAndNativeProjection",
    "TestNodeChainImportedMiddleRejectsUncapturedAuthority",
)
# These lists are copied from the actual named table-driven tests at
# 06b7016a9b1700edfd3a97f9a4463a57900b0f86. The complete candidate is snapshotted;
# adding/removing/renaming a selected record is a failure, never an optional skip.
SCHEMA1_CASES = ("2/", "3/", "4/", "8/", "3/aes-256-gcm", "4/aes-256-gcm+xor-whitening")
SCHEMA1_CHANGES = ("reorder", "remove", "relabel")
SCHEMA2_FAULTS = (
    "schema1", "unknown-schema", "two", "four", "missing-identities",
    "middle-identity", "missing-first-identity", "missing-final-identity",
    "reorder", "paired-middle", "double-imported", "canonical-middle",
    "duplicate-middle-key", "fake-api", "fake-proof", "layer", "hostname",
    "wrong-credential", "legacy-method", "identity-chain", "changed-expected-ip", "extra-route",
)
MEMBER_FAULTS = (
    "member-kind", "member-schema", "noncanonical", "duplicate-field", "protocol", "profile-kind",
    "api", "proof-id", "api-token", "entry", "execution", "layer", "hostname", "mapped-ip", "zero-ip",
    "wrong-port", "wrong-user", "wrong-password", "wrong-public-ip", "socks4", "detour", "resolver",
    "udp-over-tcp", "tcp-only", "long-user", "long-password", "half-auth", "extra-outbound", "bad-mtu",
)
ORDER_FAULTS = (
    "schema1", "schema2", "schema4", "server", "auto", "two", "four", "missing-identities",
    "middle-identity", "first-identity", "final-identity", "reordered", "paired-middle", "double-middle",
    "duplicate-id", "wrong-paired-identity", "hysteria-final",
)
SEAL_FAULTS = ("source", "config", "admission", "proof", "dns", "physical", "device", "middle", "paired")
ROOT_SUFFIXES = (
    "CompilerKeepsOriginalPath", "PreservesExistingOuterLayers", "RejectsUncapturedMember",
    "RejectsInvalidOrder", "CannotAcquireNativeAuthority", "RetainsSealedCapture",
    "KeepsSelectedDNSAndPrivateImport",
)


def cases(suite: str = SUITE) -> tuple[Case, ...]:
    if suite != SUITE:
        raise ValueError("unknown SOCKS source suite")
    expected = {PREFIX + suffix for suffix in ROOT_SUFFIXES}
    expected.update(PREFIX + "CompilerKeepsOriginalPath/" + mode + "/" + auth
                    for mode in ("wg", "awg2-fast", "awg2-strong") for auth in ("password", "none"))
    expected.update(PREFIX + "PreservesExistingOuterLayers/" + layer
                    for layer in ("aes-256-gcm", "aes-256-gcm+xor-whitening"))
    for suffix, faults in (("RejectsUncapturedMember", MEMBER_FAULTS),
                           ("RejectsInvalidOrder", ORDER_FAULTS),
                           ("RetainsSealedCapture", SEAL_FAULTS)):
        expected.update(PREFIX + suffix + "/" + fault for fault in faults)
    original = set(PRESERVATION_ROOTS)
    original.update(PRESERVATION_ROOTS[0] + "/" + case for case in SCHEMA1_CASES)
    original.update(PRESERVATION_ROOTS[1] + "/" + case for case in SCHEMA1_CHANGES)
    original.update(PRESERVATION_ROOTS[2] + "/" + mode + "/" + layer
                    for mode in ("wg", "awg2-fast", "awg2-strong")
                    for layer in ("", "aes-256-gcm", "aes-256-gcm+xor-whitening"))
    original.update(PRESERVATION_ROOTS[3] + "/" + fault for fault in SCHEMA2_FAULTS)
    sealed = PREFIX + "RetainsSealedCapture"
    local = PREFIX + "RejectsInvalidOrder"
    return (
        Case("new-socks-source", "^" + PREFIX, frozenset(expected), 120, 600),
        Case("preserved-schema1-schema2", "^(" + "|".join(PRESERVATION_ROOTS) + ")$",
             frozenset(original), 120, 600),
        Case("omitted-source-seal", "^" + sealed + "$/^config$",
             frozenset((sealed, sealed + "/config")), 120, 600, "omitted-source-seal",
             "modified source result remained authoritative", frozenset((sealed + "/config",))),
        Case("omitted-local-only", "^" + local + "$/^(server|auto)$",
             frozenset((local, local + "/server", local + "/auto")), 120, 600, "omitted-local-only",
             "unsupported SOCKS composition was admitted", frozenset((local + "/server", local + "/auto"))),
    )


def mutation_source(case: Case, source: str) -> str:
    anchors = {
        "omitted-source-seal": "p.digest() != p.seal || ",
        "omitted-local-only": 'source.Execution != "local" || ',
    }
    needle = anchors.get(case.mutation)
    if needle is None or source.count(needle) != 1:
        raise ValueError("SOCKS control lost its one exact original guard")
    return source.replace(needle, "", 1)


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
        raise ValueError("candidate lost one original regular SOCKS source file")
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
        "scope": "Dormant source/compiler only; no native owner, encrypted transport, TUN or UI acceptance.",
    }

    def save() -> None:
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    save()
    try:
        for case in selected:
            overlay_record, overlay = None, None
            if case.mutation:
                original = source / COMPILER
                changed = output / (case.name + ".go")
                changed.write_text(mutation_source(case, original.read_text()))
                overlay = output / (case.name + ".overlay.json")
                overlay.write_text(json.dumps({"Replace": {str(original): str(changed)}}) + "\n")
                overlay_record = {"path": COMPILER, "original_sha256": before[COMPILER]["sha256"],
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
