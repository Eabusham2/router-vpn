#!/usr/bin/env python3
"""Validate original desktop SOCKS source capture at an exact SHA."""
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

CORE.PACKAGE = "router-vpn/cmd/client"
SUITE = "desktop-socks-capture"
PREFIX = "TestDesktopNodeChainSOCKSCapture"
SOURCE = "cmd/client/multihop_node_chain_socks_capture.go"
SOURCE_PATHS = (SOURCE, "cmd/client/multihop_node_chain_socks_capture_test.go")
ROOT_SUFFIXES = (
    "OriginalSources", "KeepsIndependentPairedLayers", "RejectsUnsupportedSource",
    "RetiresChangedOriginal", "CatalogWaitUsesOriginalDeadline",
)
SOURCE_FAULTS = (
    "server", "auto", "first", "final", "extra", "prefix-mode", "final-mode",
    "hostname", "wrong-host", "zone", "mapped", "unspecified", "multicast",
    "paired-token", "paired-api", "paired-proof", "middle-layer", "wrong-mode",
    "partial-auth", "oversized-auth", "bad-port", "missing-source", "duplicate-catalog",
    "foreign-control", "changed-control", "final-hostname",
)
CURRENT_FAULTS = (
    "credential", "resolver", "mtu", "policy", "paired-token", "entry-asset", "final-asset",
    "order", "removed", "duplicate", "selection", "closing", "source", "config", "cancelled",
)
CATALOG_FAULTS = ("credential", "resolver", "mtu", "policy", "paired-token", "order", "removed", "duplicate")
ORIGINAL_ROOTS = (
    "TestDesktopOrderedImportedOriginalSourceCapture",
    "TestDesktopOrderedImportedPublicRequestRetainsEveryCurrentSource",
    "TestDesktopNodeChainCaptureOwnsCompleteOrderedSourceAndProjection",
    "TestDesktopNodeChainCaptureCopiesSavedSelectionBeforeProjection",
    "TestDesktopOrderedHostnameCaptureUsesSavedResolverWithoutPhysicalBootstrap",
)
MUTATION_PATHS = dict.fromkeys(("omitted-catalog-retirement", "omitted-asset-identity", "unbounded-catalog-wait"), SOURCE)


def cases(suite: str = SUITE) -> tuple[Case, ...]:
    if suite != SUITE:
        raise ValueError("unknown desktop SOCKS capture suite")
    expected = {PREFIX + suffix for suffix in ROOT_SUFFIXES}
    expected.update(PREFIX + "OriginalSources/" + mode + "/" + auth
                    for mode in ("wg", "awg2-fast", "awg2-strong") for auth in ("password", "none"))
    expected.update(PREFIX + "KeepsIndependentPairedLayers/" + layer
                    for layer in ("aes-256-gcm", "aes-256-gcm+xor-whitening"))
    expected.update(PREFIX + "RejectsUnsupportedSource/" + fault for fault in SOURCE_FAULTS)
    expected.update(PREFIX + "RetiresChangedOriginal/" + fault for fault in CURRENT_FAULTS)
    original = set(ORIGINAL_ROOTS)
    original.update(ORIGINAL_ROOTS[-1] + "/" + mode for mode in ("wg", "awg2-fast", "awg2-strong"))
    retired, waiting = PREFIX + "RetiresChangedOriginal", PREFIX + "CatalogWaitUsesOriginalDeadline"
    catalog = frozenset(retired + "/" + fault for fault in CATALOG_FAULTS)
    assets = frozenset(retired + "/" + fault for fault in ("entry-asset", "final-asset"))
    return (
        Case("typed-desktop-source", "^" + PREFIX, frozenset(expected), 120, 600),
        Case("preserved-desktop-sources", "^(" + "|".join(ORIGINAL_ROOTS) + ")$", frozenset(original), 120, 600),
        Case("omitted-catalog-retirement", "^" + retired + "$/^(" + "|".join(CATALOG_FAULTS) + ")$",
             catalog | {retired}, 120, 600, "omitted-catalog-retirement",
             "changed original SOCKS source retained desktop authority", catalog),
        Case("omitted-asset-identity", "^" + retired + "$/^(entry-asset|final-asset)$",
             assets | {retired}, 120, 600, "omitted-asset-identity",
             "changed original SOCKS source retained desktop authority", assets),
        Case("unbounded-catalog-wait", "^" + waiting + "$", frozenset((waiting,)),
             120, 600, "unbounded-catalog-wait",
             "held catalog stranded original SOCKS capture caller", frozenset((waiting,))),
    )


def mutation_source(case: Case, source: str) -> str:
    if case.mutation == "omitted-catalog-retirement":
        edits = (
            ("capture.seal != capture.digest() ||\n\t\t!original.profilesCurrent(control, profiles)",
             "capture.seal != capture.digest()"),
            ("if err != nil || !original.profilesCurrent(control, profiles) {", "if err != nil {"),
        )
    elif case.mutation == "omitted-asset-identity":
        edits = (("\t\tif !matches {\n", "\t\tif !matches && false {\n"),)
    elif case.mutation == "unbounded-catalog-wait":
        edits = (("\t\tif err := mobilemtu.LockContext(ctx, &a.mu); err != nil {\n"
                  "\t\t\treturn common.RouterProfile{}, nil, err\n\t\t}\n",
                  "\t\ta.mu.Lock()\n"),
                 ('\t"router-vpn/internal/mobilemtu"\n', ""),)
    else:
        raise ValueError("unknown desktop SOCKS source control")
    for old, new in edits:
        if source.count(old) != 1:
            raise ValueError("desktop SOCKS control lost its one exact original guard")
        source = source.replace(old, new, 1)
    return source


def command_for(go: str, case: Case, overlay: Path | None = None) -> list[str]:
    command = [go, "test", "-race", "-p=2", "-mod=readonly", "-json", "-count=1",
               "-timeout=" + str(case.seconds) + "s", "-run", case.selection]
    if bool(case.mutation) != (overlay is not None):
        raise ValueError("each causal control requires its own compiled overlay")
    if overlay is not None:
        command += ["-overlay", str(overlay)]
    command.append("./cmd/client")
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
        raise ValueError("desktop source selection does not match the trusted candidate")
    before = CORE.snapshot(source)
    if any(path not in before or before[path]["mode"] != "100644" for path in SOURCE_PATHS):
        raise ValueError("candidate lost one original regular desktop SOCKS capture file")
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
        "scope": "Actual desktop private source compiler and retained catalog/assets; no native process, physical policy, TUN, Connected or UI acceptance.",
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
