#!/usr/bin/env python3
"""Validate sealed desktop SOCKS policy and original shared proof/MTU sources."""
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

SUITE = "desktop-socks-policy"
PREFIX = "TestDesktopNodeChainSOCKSPolicy"
POLICY = "internal/mobilemultihop/desktop_node_chain_socks_policy.go"
PROJECTION = "internal/mobilemultihop/node_chain_projection.go"
RUNTIME = "internal/mobilemultihop/node_chain_socks_runtime.go"
SOURCE_PATHS = (
    POLICY, "internal/mobilemultihop/desktop_node_chain_socks_policy_test.go",
    "internal/mobilemultihop/node_chain_socks_source.go", RUNTIME,
    "internal/mobilemultihop/desktop_node_chain_policy.go", PROJECTION,
    "internal/mobilemultihop/desktop_physical_policy.go", "internal/mobilemultihop/desktop_node_cover.go",
)
ROOT_SUFFIXES = ("KeepsOriginalGraph", "StrictChildReceipt", "RetainsSourceAndPhysicalBinding",
                 "RestoreRequiresOriginalFinalPolicy", "RunsOriginalProofs")
RECEIPT_FAULTS = ("session", "target", "source-hash", "config-hash", "original-hash", "root",
                  "dns-tun", "kind", "unknown", "whitespace", "schema", "source")
CANONICAL_FAULTS = tuple(x for x in RECEIPT_FAULTS if x not in ("unknown", "schema"))
BINDING_FAULTS = ("native-source", "native-graph", "native-mtu", "native-proof",
                  "physical-session", "physical-hash", "original-source", "policy-receipt")
RESTORE_CASES = ("linux", "windows", "darwin", "bad-target", "bad-session", "fixed", "projected-again")
OLD_PREFIX = "TestDesktopNodeChainPolicy"
OLD_ROOTS = ("ExactPhysicalProjection", "CombinesProtectionAndKeepsFinalDNS",
             "RejectsChangedOriginalAndPhysicalGraph", "LaunchOwnerReceiptAndClosedConstructor")
OLD_FAULTS = ("source", "physical-source", "session", "target", "restore", "control", "original-source",
              "middle-source", "replacement-proof-source", "omitted-prefix", "middle-physical",
              "selected-dns-physical", "network-service")
OLD_RECEIPTS = ("session_id", "target_os", "restored_mtu", "projection_kind", "source_sha256", "config_sha256")
MUTATION_PATHS = {"omitted-canonical-receipt": POLICY, "omitted-final-fixed-bound": PROJECTION,
                  "omitted-runtime-projection": RUNTIME}


def original_suite(filename):
    path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location("desktop_socks_preserved_" + path.stem, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("trusted original SOCKS gate is missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.cases()[0]


def cases(suite: str = SUITE) -> tuple[Case, ...]:
    if suite != SUITE:
        raise ValueError("unknown desktop SOCKS policy suite")
    expected = {PREFIX + suffix for suffix in ROOT_SUFFIXES}
    expected.update(PREFIX + "KeepsOriginalGraph/" + mode + "/" + target + "/" + layer
                    for mode in ("wg", "awg2-fast", "awg2-strong")
                    for target in ("linux", "windows", "darwin")
                    for layer in ("", "aes-256-gcm+xor-whitening"))
    for suffix, children in (("StrictChildReceipt", RECEIPT_FAULTS),
                             ("RetainsSourceAndPhysicalBinding", BINDING_FAULTS),
                             ("RestoreRequiresOriginalFinalPolicy", RESTORE_CASES),
                             ("RunsOriginalProofs", ("linux", "windows", "darwin"))):
        expected.update(PREFIX + suffix + "/" + child for child in children)
    original = {OLD_PREFIX + suffix for suffix in OLD_ROOTS}
    original.update(OLD_PREFIX + "ExactPhysicalProjection/" + target + "/" + case
                    for target in ("linux", "windows", "darwin") for case in ("3/", "4/aes-256-gcm+xor-whitening"))
    original.update(OLD_PREFIX + "RejectsChangedOriginalAndPhysicalGraph/" + name for name in OLD_FAULTS)
    original.update(OLD_PREFIX + "LaunchOwnerReceiptAndClosedConstructor/" + name for name in OLD_RECEIPTS)
    receipt, restore, run = (PREFIX + suffix for suffix in ("StrictChildReceipt", "RestoreRequiresOriginalFinalPolicy", "RunsOriginalProofs"))
    changed = frozenset(receipt + "/" + name for name in CANONICAL_FAULTS)
    fixed = frozenset((restore + "/fixed",))
    native = frozenset(run + "/" + target for target in ("linux", "windows", "darwin"))
    return (
        Case("typed-desktop-policy", "^" + PREFIX, frozenset(expected), 120, 600),
        Case("preserved-desktop-physical", "^" + OLD_PREFIX, frozenset(original), 120, 600),
        original_suite("test_focused_socks_source.py"),
        original_suite("test_focused_socks_runtime.py"),
        original_suite("test_focused_socks_mtu.py"),
        Case("omitted-canonical-receipt", "^" + receipt + "$/^(" + "|".join(CANONICAL_FAULTS) + ")$",
             changed | {receipt}, 120, 600, "omitted-canonical-receipt",
             "changed typed desktop receipt was accepted", changed),
        Case("omitted-final-fixed-bound", "^" + restore + "$/^fixed$", fixed | {restore}, 120, 600,
             "omitted-final-fixed-bound", "unsupported desktop restore acquired typed native source", fixed),
        Case("omitted-runtime-projection", "^" + run + "$", native | {run}, 120, 600,
             "omitted-runtime-projection", "original projected runtime missing", native),
    )


def mutation_source(case: Case, source: str) -> str:
    if case.mutation == "omitted-canonical-receipt":
        old, new = "if err != nil || canonical != input {", "if err != nil || false && canonical != input {"
    elif case.mutation == "omitted-final-fixed-bound":
        old, new = "fixed != 0 && restoredMTU != fixed ||", "false && fixed != 0 && restoredMTU != fixed ||"
    elif case.mutation == "omitted-runtime-projection":
        old, new = ("originalConfigSHA: source.originalConfigSHA256(), projection: source.runtimeProjection(),",
                    "originalConfigSHA: source.originalConfigSHA256(), projection: nodeChainProjection{},")
    else:
        raise ValueError("unknown desktop SOCKS policy control")
    if source.count(old) != 1:
        raise ValueError("desktop SOCKS policy control lost its one exact original guard")
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
    selection_path = output.parent / "selection.json"
    selection = json.loads(selection_path.read_text())
    if selection.get("suite") != SUITE or selection.get("source_sha") != args.source_sha or selection.get("validation_scope") != "read-only-source-candidate":
        raise ValueError("desktop policy selection differs from the trusted candidate")
    before = CORE.snapshot(source)
    if any(path not in before or before[path]["mode"] != "100644" for path in SOURCE_PATHS):
        raise ValueError("candidate lost an exact desktop SOCKS policy source")
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
        "selection": selection, "selection_sha256": hashlib.sha256(selection_path.read_bytes()).hexdigest(),
        "actual_source_sha": CORE.git(source, "rev-parse", "HEAD").decode().strip(),
        "tree_sha": CORE.git(source, "rev-parse", "HEAD^{tree}").decode().strip(),
        "source_file_count": len(before), "source_closure_sha256": hashlib.sha256(serialized).hexdigest(),
        "validator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "trusted_executor_sha256": hashlib.sha256(CORE_PATH.read_bytes()).hexdigest(),
        "go": go, "go_version": version, "go_environment": go_environment,
        "resource_limits": {"parallel_packages": 2, "GOMAXPROCS": 2, "GOGC": 100, "GOMEMLIMIT": "2GiB"},
        "status": "running", "attempts": [],
        "scope": "Typed desktop physical/TUN source projection and original shared HTTP/TLS proof/MTU lifecycle with explicit native owner doubles; no installed host, native kernel, child process or UI acceptance.",
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
