#!/usr/bin/env python3
"""Validate the typed SOCKS5 shared MTU adapter at an exact SHA."""
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

SUITE = "socks-mtu"
PREFIX = "TestNodeChainSOCKSMTU"
ADAPTER = "internal/mobilemultihop/node_chain_socks_mtu.go"
SOURCE_PATHS = (ADAPTER, "internal/mobilemultihop/node_chain_socks_mtu_test.go")
RUNTIME_PATH = Path(__file__).resolve().with_name("test_focused_socks_runtime.py")
_runtime_spec = importlib.util.spec_from_file_location("routervpn_socks_mtu_runtime_inventory", RUNTIME_PATH)
if _runtime_spec is None or _runtime_spec.loader is None:
    raise RuntimeError("trusted original runtime inventory is missing")
RUNTIME = importlib.util.module_from_spec(_runtime_spec)
sys.modules[_runtime_spec.name] = RUNTIME
_runtime_spec.loader.exec_module(RUNTIME)

ROOT_SUFFIXES = (
    "UsesOriginalPrefixPlanner", "RejectsGraphAndReadbackSubstitution",
    "ControllerRequiresFreshOwner", "DoesNotLendGenericAuthority",
)
GRAPH_FAULTS = ("middle-key", "middle-detour", "middle-relay", "dns", "route", "tun-owner", "new-setting", "readback", "ceiling")
OWNER_CASES = ("healthy", "unproved", "cancelled", "owner-change", "retired")
ORIGINAL_ROOTS = (
    "TestNodeChainMTUControllerRetainsCompleteCapturedPath",
    "TestNodeChainMTUControllerRejectsChangedMiddleAndAuthority",
    "TestNodeChainMTUControllerKeepsFixedMiddleEndpointAndFinalPolicySeparate",
    "TestNodeChainMTUControllerRetainsSealedDesktopPhysicalOwner",
)
ORIGINAL_FAULTS = ("middle-key", "middle-mtu", "dns", "route", "tun-owner", "new-setting", "readback")
MUTATION_PATHS = {name: ADAPTER for name in (
    "omitted-preproof", "omitted-postcapture-proof", "substituted-source-readback",
)}


def cases(suite: str = SUITE) -> tuple[Case, ...]:
    if suite != SUITE:
        raise ValueError("unknown SOCKS MTU suite")
    expected = {PREFIX + suffix for suffix in ROOT_SUFFIXES}
    expected.update(PREFIX + ROOT_SUFFIXES[0] + "/" + mode + "/" + policy
                    for mode in ("wg", "awg2-fast", "awg2-strong") for policy in ("auto", "fixed"))
    expected.update(PREFIX + ROOT_SUFFIXES[1] + "/" + fault for fault in GRAPH_FAULTS)
    expected.update(PREFIX + ROOT_SUFFIXES[2] + "/" + fault for fault in OWNER_CASES)
    original = set(ORIGINAL_ROOTS)
    original.update(ORIGINAL_ROOTS[0] + "/" + count for count in ("3", "4", "8"))
    original.update(ORIGINAL_ROOTS[1] + "/" + fault for fault in ORIGINAL_FAULTS)
    original.update(ORIGINAL_ROOTS[2] + "/final-fixed-" + flag for flag in ("false", "true"))
    original.update(ORIGINAL_ROOTS[3] + "/" + target for target in ("linux", "windows", "darwin"))
    controller = PREFIX + ROOT_SUFFIXES[2]
    graph = PREFIX + ROOT_SUFFIXES[1]
    graph_leaves = frozenset(graph + "/" + fault for fault in GRAPH_FAULTS)
    return (
        Case("new-socks-mtu", "^" + PREFIX, frozenset(expected), 120, 600),
        Case("preserved-original-mtu", "^(" + "|".join(ORIGINAL_ROOTS) + ")$", frozenset(original), 120, 600),
        Case("preserved-typed-runtime", RUNTIME.cases()[0].selection, RUNTIME.cases()[0].expected, 120, 600),
        Case("omitted-preproof", "^" + controller + "$/^unproved$",
             frozenset((controller, controller + "/unproved")), 120, 600, "omitted-preproof",
             "unproved or retired runtime reached MTU owner", frozenset((controller + "/unproved",))),
        Case("omitted-postcapture-proof", "^" + controller + "$/^owner-change$",
             frozenset((controller, controller + "/owner-change")), 120, 600, "omitted-postcapture-proof",
             "unproved or changed SOCKS owner acquired MTU controller", frozenset((controller + "/owner-change",))),
        Case("substituted-source-readback", "^" + graph + "$", graph_leaves | {graph}, 120, 600,
             "substituted-source-readback", "altered SOCKS graph acquired original MTU authority", graph_leaves),
    )


def mutation_source(case: Case, source: str) -> str:
    guards = {
        "omitted-preproof": (
            "\tif err := r.HealthyContext(ctx); err != nil {\n\t\treturn nil, err\n\t}\n", ""),
        "omitted-postcapture-proof": (
            "\tif err := r.HealthyContext(ctx); err != nil {\n\t\treturn nil, errors.Join(err, controller.Close())\n\t}\n", ""),
        "substituted-source-readback": (
            "return r.chain.PlanForMTU(config, actual)", "return r.chain.PlanForMTU(r.chain.config, 1280)"),
    }
    replacement = guards.get(case.mutation)
    if replacement is None or source.count(replacement[0]) != 1:
        raise ValueError("SOCKS MTU control lost its one exact original guard")
    changed = source.replace(replacement[0], replacement[1], 1)
    if case.mutation == "omitted-postcapture-proof":
        # Removing this final error join also removes the only errors use.
        # Keep the mutation a compilable guard omission, never a build failure.
        if changed.count('\t"errors"\n') != 1:
            raise ValueError("SOCKS MTU control lost its exact import")
        changed = changed.replace('\t"errors"\n', "", 1)
    return changed


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
        raise ValueError("candidate lost one original regular SOCKS MTU adapter file")
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
        "trusted_runtime_inventory_sha256": hashlib.sha256(RUNTIME_PATH.read_bytes()).hexdigest(),
        "go": go, "go_version": version, "go_environment": go_environment,
        "resource_limits": {"parallel_packages": 2, "GOMAXPROCS": 2, "GOGC": 100, "GOMEMLIMIT": "2GiB"},
        "status": "running", "attempts": [],
        "scope": "Original shared MTU planner/controller and actual HTTP/TLS proof fixtures; configured bounds are not measured PMTU. No native reader replacement/readback, encrypted SOCKS, Box, TUN or UI acceptance.",
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
